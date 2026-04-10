//! HMAC for every approved SHA variant, per FIPS 198-1.
//!
//! HMAC is the Keyed-Hash Message Authentication Code defined in
//! FIPS 198-1, built on top of any approved hash function `H` with
//! block size `B` and output size `L`:
//!
//! ```text
//!     HMAC(K, text) = H( (K0 XOR opad) || H( (K0 XOR ipad) || text ) )
//! ```
//!
//! where `K0` is the key normalized to exactly `B` bytes:
//!
//! ```text
//!     K0 = H(K) || 0x00..   if len(K) >  B
//!     K0 = K    || 0x00..   if len(K) <= B
//! ```
//!
//! and `ipad = 0x36..` and `opad = 0x5c..` are the inner/outer
//! padding strings (each `B` bytes).
//!
//! # Approved variants
//!
//! We instantiate HMAC over every FIPS 180-4 / FIPS 202 hash the
//! module already exposes:
//!
//!   - HMAC-SHA-1, HMAC-SHA-224, HMAC-SHA-256
//!   - HMAC-SHA-384, HMAC-SHA-512
//!   - HMAC-SHA-512/224, HMAC-SHA-512/256
//!   - HMAC-SHA3-224, HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512
//!
//! Each variant is a zero-overhead type alias over the generic
//! [`Hmac`] struct. Per FIPS 140-3 IG 10.3.A each one ships its own
//! power-up KAT; families do not share KATs.
//!
//! # Design
//!
//! The single implementation lives in the generic [`Hmac<H, B, L>`]
//! struct parameterized by a hash type `H` implementing the private
//! [`BlockHash`] trait. The trait is deliberately crate-private —
//! it exists only to bridge fips-sha's concrete hash types into the
//! generic HMAC core. Users always talk to the public type aliases
//! ([`HmacSha256`], etc.), never to `BlockHash` directly.
//!
//! The `new_internal` constructor on each underlying hash is
//! `#[doc(hidden)]` but public; it lets the HMAC boot-time KATs run
//! while `fips-module` is still in the `SelfTest` state, before
//! `require_operational()` would allow it.
//!
//! # FIPS 140-3 IG D.G note (March 2026)
//!
//! HMAC is an approved MAC per SP 800-107 Rev. 1 and an approved
//! PRF per SP 800-108. HMAC-SHA-1 remains approved for MAC and KDF
//! use even though SHA-1 is disallowed for digital signature
//! generation (SP 800-131A Rev. 2).
#![no_std]
#![forbid(unsafe_code)]
#![allow(
    // The HMAC padding loops walk fixed-size `[u8; B]` buffers with
    // compile-time bounds, so bounds-checked indexing is fine here
    // and mirrors the notation used in FIPS 198-1. The pedantic
    // arithmetic lint similarly objects to `+= 1` inside loops that
    // iterate over compile-time ranges.
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // `HmacSha512_224` / `HmacSha512_256` mirror the spec names.
    non_camel_case_types
)]

use fips_module::{require_operational, Error, KatEntry, SelfTestFailure};

// ----------------------------------------------------------------------
// BlockHash trait
// ----------------------------------------------------------------------

/// The hash-function abstraction used by [`Hmac`].
///
/// `B` is the hash's block size in bytes (FIPS 198-1 variable `B`)
/// and `L` is its output length in bytes (FIPS 198-1 variable `L`).
///
/// This trait is an implementation detail: it exists only to bridge
/// concrete fips-sha types into the generic HMAC core. It is
/// technically public so that the generic `Hmac<H, B, L>` struct
/// can name it as a bound, but it is `#[doc(hidden)]` and is not
/// covered by any semver commitment — downstream code must always
/// use the public type aliases ([`HmacSha256`], etc.) and never
/// name `BlockHash` directly.
#[doc(hidden)]
pub trait BlockHash<const B: usize, const L: usize>: Sized {
    /// Fresh hasher that bypasses the module state machine.
    fn block_new() -> Self;
    /// Absorb more input.
    fn block_update(&mut self, data: &[u8]);
    /// Consume self, return the `L`-byte digest.
    fn block_finalize(self) -> [u8; L];
}

// ----------------------------------------------------------------------
// Generic HMAC core
// ----------------------------------------------------------------------

/// Generic HMAC construction over any [`BlockHash`].
///
/// Holds the inner hasher (already seeded with `K0 XOR ipad`) and
/// the precomputed `K0 XOR opad` key so that [`Hmac::finalize`] can
/// run the outer hash in one pass.
pub struct Hmac<H: BlockHash<B, L>, const B: usize, const L: usize> {
    inner: H,
    outer_key: [u8; B],
}

const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5c;

impl<H: BlockHash<B, L>, const B: usize, const L: usize> Hmac<H, B, L> {
    /// Creates a new HMAC instance with the given `key`.
    ///
    /// Enforces the module boundary via
    /// [`fips_module::require_operational`]. For the boot-time KATs
    /// that must run *before* the module is operational, use
    /// [`Hmac::new_internal`].
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal(key))
    }

    /// Constructor that bypasses the module state machine.
    ///
    /// Used by the crate's power-up KATs, which run during the
    /// `SelfTest` state before `require_operational()` would permit
    /// `Hmac::new`. Not intended for application code.
    #[doc(hidden)]
    pub fn new_internal(key: &[u8]) -> Self {
        // Step 1 — normalize the key to K0 (exactly B bytes).
        let mut k0 = [0u8; B];
        if key.len() > B {
            // len(K) > B: hash the key down to L bytes, pad with zeros.
            let mut h = H::block_new();
            h.block_update(key);
            let digest = h.block_finalize();
            k0[..L].copy_from_slice(&digest);
        } else {
            // len(K) <= B: copy and zero-pad on the right.
            k0[..key.len()].copy_from_slice(key);
        }

        // Step 2 — derive the ipad and opad keys.
        let mut ipad_key = [0u8; B];
        let mut outer_key = [0u8; B];
        for i in 0..B {
            ipad_key[i] = k0[i] ^ IPAD_BYTE;
            outer_key[i] = k0[i] ^ OPAD_BYTE;
        }

        // Step 3 — seed the inner hash with the ipad key.
        let mut inner = H::block_new();
        inner.block_update(&ipad_key);

        Self { inner, outer_key }
    }

    /// Feeds `data` into the HMAC.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.block_update(data);
    }

    /// Finalizes and returns the L-byte MAC.
    pub fn finalize(self) -> [u8; L] {
        // inner_digest = H( K0 XOR ipad || text )
        let inner_digest = self.inner.block_finalize();

        // outer_digest = H( K0 XOR opad || inner_digest )
        let mut outer = H::block_new();
        outer.block_update(&self.outer_key);
        outer.block_update(&inner_digest);
        outer.block_finalize()
    }
}

// ----------------------------------------------------------------------
// BlockHash impls for each approved fips-sha type
// ----------------------------------------------------------------------

macro_rules! impl_block_hash {
    ($t:ty, $b:expr, $l:expr) => {
        impl BlockHash<$b, $l> for $t {
            fn block_new() -> Self {
                <$t>::new_internal()
            }
            fn block_update(&mut self, data: &[u8]) {
                <$t>::update(self, data);
            }
            fn block_finalize(self) -> [u8; $l] {
                <$t>::finalize(self)
            }
        }
    };
}

impl_block_hash!(fips_sha::sha1::Sha1, 64, 20);
impl_block_hash!(fips_sha::sha224::Sha224, 64, 28);
impl_block_hash!(fips_sha::sha256::Sha256, 64, 32);
impl_block_hash!(fips_sha::sha384::Sha384, 128, 48);
impl_block_hash!(fips_sha::sha512::Sha512, 128, 64);
impl_block_hash!(fips_sha::sha512_t::Sha512_224, 128, 28);
impl_block_hash!(fips_sha::sha512_t::Sha512_256, 128, 32);
impl_block_hash!(fips_sha::sha3::Sha3<144, 28>, 144, 28);
impl_block_hash!(fips_sha::sha3::Sha3<136, 32>, 136, 32);
impl_block_hash!(fips_sha::sha3::Sha3<104, 48>, 104, 48);
impl_block_hash!(fips_sha::sha3::Sha3<72, 64>, 72, 64);

// ----------------------------------------------------------------------
// Public type aliases
// ----------------------------------------------------------------------

/// HMAC-SHA-1 (B=64, L=20).
pub type HmacSha1 = Hmac<fips_sha::sha1::Sha1, 64, 20>;
/// HMAC-SHA-224 (B=64, L=28).
pub type HmacSha224 = Hmac<fips_sha::sha224::Sha224, 64, 28>;
/// HMAC-SHA-256 (B=64, L=32).
pub type HmacSha256 = Hmac<fips_sha::sha256::Sha256, 64, 32>;
/// HMAC-SHA-384 (B=128, L=48).
pub type HmacSha384 = Hmac<fips_sha::sha384::Sha384, 128, 48>;
/// HMAC-SHA-512 (B=128, L=64).
pub type HmacSha512 = Hmac<fips_sha::sha512::Sha512, 128, 64>;
/// HMAC-SHA-512/224 (B=128, L=28).
pub type HmacSha512_224 = Hmac<fips_sha::sha512_t::Sha512_224, 128, 28>;
/// HMAC-SHA-512/256 (B=128, L=32).
pub type HmacSha512_256 = Hmac<fips_sha::sha512_t::Sha512_256, 128, 32>;
/// HMAC-SHA3-224 (B=144, L=28). B is the rate, per NIST CAVP.
pub type HmacSha3_224 = Hmac<fips_sha::sha3::Sha3<144, 28>, 144, 28>;
/// HMAC-SHA3-256 (B=136, L=32).
pub type HmacSha3_256 = Hmac<fips_sha::sha3::Sha3<136, 32>, 136, 32>;
/// HMAC-SHA3-384 (B=104, L=48).
pub type HmacSha3_384 = Hmac<fips_sha::sha3::Sha3<104, 48>, 104, 48>;
/// HMAC-SHA3-512 (B=72, L=64).
pub type HmacSha3_512 = Hmac<fips_sha::sha3::Sha3<72, 64>, 72, 64>;

// ----------------------------------------------------------------------
// Power-up KATs
// ----------------------------------------------------------------------
//
// RFC 4231 §4.2 test case 1 (also applicable to SHA-1 per RFC 2202
// §3 test case 1) uses:
//
//   Key  = 0x0b repeated 20 times
//   Data = "Hi There"
//
// For the variants not covered by RFC 4231 (SHA-512/224, SHA-512/256,
// SHA-3 family) we use the same inputs and the digest computed by
// OpenSSL 3.x, which is CAVS-validated. All 11 expected values can
// be regenerated with:
//
//   printf 'Hi There' | openssl dgst -<alg> -mac HMAC \
//     -macopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b

const KAT_KEY: [u8; 20] = [0x0b; 20];
const KAT_DATA: &[u8] = b"Hi There";

/// HMAC-SHA-1 KAT from RFC 2202 §3 test case 1.
const KAT_HMAC_SHA1: [u8; 20] = [
    0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
    0xf1, 0x46, 0xbe, 0x00,
];
/// HMAC-SHA-224 KAT from RFC 4231 §4.2 test case 1.
const KAT_HMAC_SHA224: [u8; 28] = [
    0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19, 0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f,
    0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f, 0x53, 0x68, 0x4b, 0x22,
];
/// HMAC-SHA-256 KAT from RFC 4231 §4.2 test case 1.
const KAT_HMAC_SHA256: [u8; 32] = [
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
];
/// HMAC-SHA-384 KAT from RFC 4231 §4.2 test case 1.
const KAT_HMAC_SHA384: [u8; 48] = [
    0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
    0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
    0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
];
/// HMAC-SHA-512 KAT from RFC 4231 §4.2 test case 1.
const KAT_HMAC_SHA512: [u8; 64] = [
    0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
    0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
    0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
    0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
];
/// HMAC-SHA-512/224 KAT computed via OpenSSL 3.x with the RFC 4231 test 1 inputs.
const KAT_HMAC_SHA512_224: [u8; 28] = [
    0xb2, 0x44, 0xba, 0x01, 0x30, 0x7c, 0x0e, 0x7a, 0x8c, 0xca, 0xad, 0x13, 0xb1, 0x06, 0x7a, 0x4c,
    0xf6, 0xb9, 0x61, 0xfe, 0x0c, 0x6a, 0x20, 0xbd, 0xa3, 0xd9, 0x20, 0x39,
];
/// HMAC-SHA-512/256 KAT computed via OpenSSL 3.x with the RFC 4231 test 1 inputs.
const KAT_HMAC_SHA512_256: [u8; 32] = [
    0x9f, 0x91, 0x26, 0xc3, 0xd9, 0xc3, 0xc3, 0x30, 0xd7, 0x60, 0x42, 0x5c, 0xa8, 0xa2, 0x17, 0xe3,
    0x1f, 0xea, 0xe3, 0x1b, 0xfe, 0x70, 0x19, 0x6f, 0xf8, 0x16, 0x42, 0xb8, 0x68, 0x40, 0x2e, 0xab,
];
/// HMAC-SHA3-224 KAT computed via OpenSSL 3.x with the RFC 4231 test 1 inputs.
const KAT_HMAC_SHA3_224: [u8; 28] = [
    0x3b, 0x16, 0x54, 0x6b, 0xbc, 0x7b, 0xe2, 0x70, 0x6a, 0x03, 0x1d, 0xca, 0xfd, 0x56, 0x37, 0x3d,
    0x98, 0x84, 0x36, 0x76, 0x41, 0xd8, 0xc5, 0x9a, 0xf3, 0xc8, 0x60, 0xf7,
];
/// HMAC-SHA3-256 KAT computed via OpenSSL 3.x with the RFC 4231 test 1 inputs.
const KAT_HMAC_SHA3_256: [u8; 32] = [
    0xba, 0x85, 0x19, 0x23, 0x10, 0xdf, 0xfa, 0x96, 0xe2, 0xa3, 0xa4, 0x0e, 0x69, 0x77, 0x43, 0x51,
    0x14, 0x0b, 0xb7, 0x18, 0x5e, 0x12, 0x02, 0xcd, 0xcc, 0x91, 0x75, 0x89, 0xf9, 0x5e, 0x16, 0xbb,
];
/// HMAC-SHA3-384 KAT computed via OpenSSL 3.x with the RFC 4231 test 1 inputs.
const KAT_HMAC_SHA3_384: [u8; 48] = [
    0x68, 0xd2, 0xdc, 0xf7, 0xfd, 0x4d, 0xdd, 0x0a, 0x22, 0x40, 0xc8, 0xa4, 0x37, 0x30, 0x5f, 0x61,
    0xfb, 0x73, 0x34, 0xcf, 0xb5, 0xd0, 0x22, 0x6e, 0x1b, 0xc2, 0x7d, 0xc1, 0x0a, 0x2e, 0x72, 0x3a,
    0x20, 0xd3, 0x70, 0xb4, 0x77, 0x43, 0x13, 0x0e, 0x26, 0xac, 0x7e, 0x3d, 0x53, 0x28, 0x86, 0xbd,
];
/// HMAC-SHA3-512 KAT computed via OpenSSL 3.x with the RFC 4231 test 1 inputs.
const KAT_HMAC_SHA3_512: [u8; 64] = [
    0xeb, 0x3f, 0xbd, 0x4b, 0x2e, 0xaa, 0xb8, 0xf5, 0xc5, 0x04, 0xbd, 0x3a, 0x41, 0x46, 0x5a, 0xac,
    0xec, 0x15, 0x77, 0x0a, 0x7c, 0xab, 0xac, 0x53, 0x1e, 0x48, 0x2f, 0x86, 0x0b, 0x5e, 0xc7, 0xba,
    0x47, 0xcc, 0xb2, 0xc6, 0xf2, 0xaf, 0xce, 0x8f, 0x88, 0xd2, 0x2b, 0x6d, 0xc6, 0x13, 0x80, 0xf2,
    0x3a, 0x66, 0x8f, 0xd3, 0x88, 0x8b, 0xb8, 0x05, 0x37, 0xc0, 0xa0, 0xb8, 0x64, 0x07, 0x68, 0x9e,
];

macro_rules! kat_fn {
    ($name:ident, $alias:ty, $expected:ident) => {
        /// Power-up KAT for this HMAC variant. Run by
        /// `fips_module::initialize_with_tests` during `SelfTest`.
        pub fn $name() -> Result<(), SelfTestFailure> {
            let mut m = <$alias>::new_internal(&KAT_KEY);
            m.update(KAT_DATA);
            if m.finalize() == $expected {
                Ok(())
            } else {
                Err(SelfTestFailure)
            }
        }
    };
}

kat_fn!(self_test_sha1, HmacSha1, KAT_HMAC_SHA1);
kat_fn!(self_test_sha224, HmacSha224, KAT_HMAC_SHA224);
kat_fn!(self_test_sha256, HmacSha256, KAT_HMAC_SHA256);
kat_fn!(self_test_sha384, HmacSha384, KAT_HMAC_SHA384);
kat_fn!(self_test_sha512, HmacSha512, KAT_HMAC_SHA512);
kat_fn!(self_test_sha512_224, HmacSha512_224, KAT_HMAC_SHA512_224);
kat_fn!(self_test_sha512_256, HmacSha512_256, KAT_HMAC_SHA512_256);
kat_fn!(self_test_sha3_224, HmacSha3_224, KAT_HMAC_SHA3_224);
kat_fn!(self_test_sha3_256, HmacSha3_256, KAT_HMAC_SHA3_256);
kat_fn!(self_test_sha3_384, HmacSha3_384, KAT_HMAC_SHA3_384);
kat_fn!(self_test_sha3_512, HmacSha3_512, KAT_HMAC_SHA3_512);

/// Power-up KAT inventory for all HMAC variants in this crate.
///
/// Merged into the acvp-harness boot sequence via
/// `fips_module::initialize_with_tests`. Per FIPS 140-3 IG 10.3.A
/// each variant has its own KAT — families do not share.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "HMAC-SHA-1 KAT (RFC 2202 test 1)",
        run: self_test_sha1,
    },
    KatEntry {
        name: "HMAC-SHA-224 KAT (RFC 4231 test 1)",
        run: self_test_sha224,
    },
    KatEntry {
        name: "HMAC-SHA-256 KAT (RFC 4231 test 1)",
        run: self_test_sha256,
    },
    KatEntry {
        name: "HMAC-SHA-384 KAT (RFC 4231 test 1)",
        run: self_test_sha384,
    },
    KatEntry {
        name: "HMAC-SHA-512 KAT (RFC 4231 test 1)",
        run: self_test_sha512,
    },
    KatEntry {
        name: "HMAC-SHA-512/224 KAT (OpenSSL-derived, RFC 4231 inputs)",
        run: self_test_sha512_224,
    },
    KatEntry {
        name: "HMAC-SHA-512/256 KAT (OpenSSL-derived, RFC 4231 inputs)",
        run: self_test_sha512_256,
    },
    KatEntry {
        name: "HMAC-SHA3-224 KAT (OpenSSL-derived, RFC 4231 inputs)",
        run: self_test_sha3_224,
    },
    KatEntry {
        name: "HMAC-SHA3-256 KAT (OpenSSL-derived, RFC 4231 inputs)",
        run: self_test_sha3_256,
    },
    KatEntry {
        name: "HMAC-SHA3-384 KAT (OpenSSL-derived, RFC 4231 inputs)",
        run: self_test_sha3_384,
    },
    KatEntry {
        name: "HMAC-SHA3-512 KAT (OpenSSL-derived, RFC 4231 inputs)",
        run: self_test_sha3_512,
    },
];

// ----------------------------------------------------------------------
// Unit tests
// ----------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        self_test_sha1, self_test_sha224, self_test_sha256, self_test_sha384, self_test_sha3_224,
        self_test_sha3_256, self_test_sha3_384, self_test_sha3_512, self_test_sha512,
        self_test_sha512_224, self_test_sha512_256, HmacSha1, HmacSha224, HmacSha256, HmacSha384,
        HmacSha3_256, HmacSha512, HmacSha512_224, HmacSha512_256,
    };
    use fips_module::{initialize_with_tests, KatEntry};

    // Bring all the power-up KATs through the same boot the harness
    // uses. A single successful initialize flips the module into
    // Operational for all subsequent tests in this process.
    fn ensure_initialized() {
        const ALL: &[KatEntry] = super::KATS;
        let _ = initialize_with_tests(ALL);
    }

    #[test]
    fn boot_self_tests_all_pass() {
        // Direct call: the self_test functions don't require the
        // module to be operational (they run *during* SelfTest).
        assert!(self_test_sha1().is_ok());
        assert!(self_test_sha224().is_ok());
        assert!(self_test_sha256().is_ok());
        assert!(self_test_sha384().is_ok());
        assert!(self_test_sha512().is_ok());
        assert!(self_test_sha512_224().is_ok());
        assert!(self_test_sha512_256().is_ok());
        assert!(self_test_sha3_224().is_ok());
        assert!(self_test_sha3_256().is_ok());
        assert!(self_test_sha3_384().is_ok());
        assert!(self_test_sha3_512().is_ok());
    }

    #[test]
    fn hmac_sha256_streaming_matches_one_shot() {
        ensure_initialized();
        let key = [0x0b; 20];
        let data = b"Hi There";

        let mut one = HmacSha256::new(&key).unwrap();
        one.update(data);
        let a = one.finalize();

        let mut two = HmacSha256::new(&key).unwrap();
        two.update(&data[..3]);
        two.update(&data[3..]);
        let b = two.finalize();

        assert_eq!(a, b);
    }

    #[test]
    fn hmac_sha256_long_key_rfc4231_test_case_6() {
        // RFC 4231 §4.7: Key = 0xaa * 131 (> B=64 so the H(K) path
        // engages). Data = "Test Using Larger Than Block-Size Key -
        // Hash Key First". Expected MAC verified via OpenSSL.
        ensure_initialized();
        let key = [0xaa_u8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let expected: [u8; 32] = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];

        let mut m = HmacSha256::new(&key).unwrap();
        m.update(data);
        assert_eq!(m.finalize(), expected);
    }

    #[test]
    fn hmac_sha3_256_long_key() {
        // Same long-key construction exercised against SHA3-256
        // where B = 136. Expected MAC verified via OpenSSL.
        ensure_initialized();
        let key = [0xaa_u8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let expected: [u8; 32] = [
            0xed, 0x73, 0xa3, 0x74, 0xb9, 0x6c, 0x00, 0x52, 0x35, 0xf9, 0x48, 0x03, 0x2f, 0x09,
            0x67, 0x4a, 0x58, 0xc0, 0xce, 0x55, 0x5c, 0xfc, 0x1f, 0x22, 0x3b, 0x02, 0x35, 0x65,
            0x60, 0x31, 0x2c, 0x3b,
        ];

        let mut m = HmacSha3_256::new(&key).unwrap();
        m.update(data);
        assert_eq!(m.finalize(), expected);
    }

    #[test]
    fn hmac_empty_key_empty_data_is_deterministic() {
        // Edge case: empty key, empty data. Should still produce a
        // well-defined output. We cross-check by running the MAC
        // twice and asserting equality (no oracle needed).
        ensure_initialized();
        let a = {
            let mut m = HmacSha1::new(&[]).unwrap();
            m.update(&[]);
            m.finalize()
        };
        let b = {
            let mut m = HmacSha1::new(&[]).unwrap();
            m.update(&[]);
            m.finalize()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_length_checks() {
        // Sanity: every alias produces the output length its name
        // promises.
        ensure_initialized();
        let k = [0x0b; 20];
        assert_eq!(HmacSha1::new(&k).unwrap().finalize().len(), 20);
        assert_eq!(HmacSha224::new(&k).unwrap().finalize().len(), 28);
        assert_eq!(HmacSha256::new(&k).unwrap().finalize().len(), 32);
        assert_eq!(HmacSha384::new(&k).unwrap().finalize().len(), 48);
        assert_eq!(HmacSha512::new(&k).unwrap().finalize().len(), 64);
        assert_eq!(HmacSha512_224::new(&k).unwrap().finalize().len(), 28);
        assert_eq!(HmacSha512_256::new(&k).unwrap().finalize().len(), 32);
    }
}
