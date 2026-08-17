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
//! [`Hmac`] struct. Each one ships its own
//! power-up KAT; families do not share KATs.
//!
//! # Design
//!
//! The single implementation lives in the generic [`Hmac<H, B, L>`]
//! struct parameterized by a hash type `H` implementing the private
//! [`BlockHash`] trait. The trait is `#[doc(hidden)]` and carries no
//! semver commitment —
//! it exists only to bridge oxicrypt-sha's concrete hash types into the
//! generic HMAC core. Users always talk to the public type aliases
//! ([`HmacSha256`], etc.), never to `BlockHash` directly.
//!
//! The `new_internal` constructor on each underlying hash is
//! `#[doc(hidden)]` but public; it lets the HMAC boot-time KATs run
//! while `oxicrypt-module` is still in the `SelfTest` state, before
//! `require_operational()` would allow it.
//!
//! # Power-up self-tests
//!
//! [`KATS`] ships one pinned vector per HMAC variant (11 in
//! total). Each entry runs independently at module power-up
//! independently; families do not share KATs even
//! when the hash cores are related.
//!
//! # Sensitive security parameters
//!
//! - **HMAC key** — CSP. Provided by the caller as a byte slice
//!   of arbitrary length, normalized to `K0` inside the HMAC
//!   state. The caller is responsible for zeroizing the
//!   original key buffer once it hands off to HMAC; the HMAC
//!   state itself holds only the derived inner/outer hash
//!   state, which is rebuilt by `new` and goes away when
//!   the frame drops.
//!
//! # FIPS module gating
//!
//! Public `Hmac<H, B, L>` constructors gate on
//! [`oxicrypt_module::require_operational`]; the hidden
//! `*_internal` surface is used by the HMAC KAT runner itself
//! and by downstream consumers (HKDF, KBKDF, HMAC_DRBG) that
//! need to run during `SelfTest`.
//!
//! # Approval basis
//!
//! HMAC is an approved MAC per FIPS 198-1 and an
//! approved PRF per SP 800-108. HMAC-SHA-1 remains approved
//! for MAC and KDF use even though SHA-1 is disallowed for
//! digital signature generation (SP 800-131A Rev. 2).
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

use oxicrypt_module::{
    Error, KatEntry, SelfTestFailure, Service, require_allowed, require_operational,
};

// ----------------------------------------------------------------------
// BlockHash trait
// ----------------------------------------------------------------------

/// The hash-function abstraction used by [`Hmac`].
///
/// `B` is the hash's block size in bytes (FIPS 198-1 variable `B`)
/// and `L` is its output length in bytes (FIPS 198-1 variable `L`).
///
/// This trait is an implementation detail: it exists only to bridge
/// concrete oxicrypt-sha types into the generic HMAC core. It is
/// technically public so that the generic `Hmac<H, B, L>` struct
/// can name it as a bound, but it is `#[doc(hidden)]` and is not
/// covered by any semver commitment — downstream code must always
/// use the public type aliases ([`HmacSha256`], etc.) and never
/// name `BlockHash` directly.
#[doc(hidden)]
pub trait BlockHash<const B: usize, const L: usize>: Sized {
    /// The [`Service`] variant for this HMAC instantiation.
    ///
    /// Used by [`Hmac::new`] to enforce algorithm-profile restrictions.
    const HMAC_SERVICE: Service;
    /// Fresh hasher that bypasses the module state machine.
    fn block_new() -> Self;
    /// Absorb more input.
    fn block_update(&mut self, data: &[u8]);
    /// Finalize and return the `L`-byte digest.
    ///
    /// Resets internal state to a fresh hasher so subsequent calls
    /// produce the digest of an empty input. The owning struct's
    /// `Drop` zeroizes `outer_key`; the inner hash state is cleared by
    /// this reset, so a value dropped without being finalized does not
    /// have it cleared.
    fn block_finalize(&mut self) -> [u8; L];
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
    /// [`oxicrypt_module::require_operational`]. For the boot-time KATs
    /// that must run *before* the module is operational, use
    /// [`Hmac::new_internal`].
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        require_allowed(H::HMAC_SERVICE)?;
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
    pub fn finalize(&mut self) -> [u8; L] {
        // inner_digest = H( K0 XOR ipad || text )
        let inner_digest = self.inner.block_finalize();

        // outer_digest = H( K0 XOR opad || inner_digest )
        let mut outer = H::block_new();
        outer.block_update(&self.outer_key);
        outer.block_update(&inner_digest);
        outer.block_finalize()
    }
}

impl<H: BlockHash<B, L>, const B: usize, const L: usize> Drop for Hmac<H, B, L> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.outer_key);
    }
}

// ----------------------------------------------------------------------
// BlockHash impls for each approved oxicrypt-sha type
// ----------------------------------------------------------------------

macro_rules! impl_block_hash {
    ($t:ty, $b:expr, $l:expr, $service:expr) => {
        impl BlockHash<$b, $l> for $t {
            const HMAC_SERVICE: Service = $service;
            fn block_new() -> Self {
                <$t>::new_internal()
            }
            fn block_update(&mut self, data: &[u8]) {
                <$t>::update(self, data);
            }
            fn block_finalize(&mut self) -> [u8; $l] {
                // Swap out the live hasher for a blank one, then
                // finalize the taken copy. This lets the trait take
                // `&mut self` (needed for Drop on Hmac) while the
                // underlying SHA `finalize` still takes `self`.
                let taken = core::mem::replace(self, <$t>::new_internal());
                <$t>::finalize(taken)
            }
        }
    };
}

impl_block_hash!(oxicrypt_sha::sha1::Sha1, 64, 20, Service::HmacSha1);
impl_block_hash!(oxicrypt_sha::sha224::Sha224, 64, 28, Service::HmacSha224);
impl_block_hash!(oxicrypt_sha::sha256::Sha256, 64, 32, Service::HmacSha256);
impl_block_hash!(oxicrypt_sha::sha384::Sha384, 128, 48, Service::HmacSha384);
impl_block_hash!(oxicrypt_sha::sha512::Sha512, 128, 64, Service::HmacSha512);
impl_block_hash!(
    oxicrypt_sha::sha512_t::Sha512_224,
    128,
    28,
    Service::HmacSha512_224
);
impl_block_hash!(
    oxicrypt_sha::sha512_t::Sha512_256,
    128,
    32,
    Service::HmacSha512_256
);
impl_block_hash!(oxicrypt_sha::sha3::Sha3<144, 28>, 144, 28, Service::HmacSha3_224);
impl_block_hash!(oxicrypt_sha::sha3::Sha3<136, 32>, 136, 32, Service::HmacSha3_256);
impl_block_hash!(oxicrypt_sha::sha3::Sha3<104, 48>, 104, 48, Service::HmacSha3_384);
impl_block_hash!(oxicrypt_sha::sha3::Sha3<72, 64>, 72, 64, Service::HmacSha3_512);

// ----------------------------------------------------------------------
// Public type aliases
// ----------------------------------------------------------------------

/// HMAC-SHA-1 (B=64, L=20).
pub type HmacSha1 = Hmac<oxicrypt_sha::sha1::Sha1, 64, 20>;
/// HMAC-SHA-224 (B=64, L=28).
pub type HmacSha224 = Hmac<oxicrypt_sha::sha224::Sha224, 64, 28>;
/// HMAC-SHA-256 (B=64, L=32).
pub type HmacSha256 = Hmac<oxicrypt_sha::sha256::Sha256, 64, 32>;
/// HMAC-SHA-384 (B=128, L=48).
pub type HmacSha384 = Hmac<oxicrypt_sha::sha384::Sha384, 128, 48>;
/// HMAC-SHA-512 (B=128, L=64).
pub type HmacSha512 = Hmac<oxicrypt_sha::sha512::Sha512, 128, 64>;
/// HMAC-SHA-512/224 (B=128, L=28).
pub type HmacSha512_224 = Hmac<oxicrypt_sha::sha512_t::Sha512_224, 128, 28>;
/// HMAC-SHA-512/256 (B=128, L=32).
pub type HmacSha512_256 = Hmac<oxicrypt_sha::sha512_t::Sha512_256, 128, 32>;
/// HMAC-SHA3-224 (B=144, L=28). B is the rate, per NIST CAVP.
pub type HmacSha3_224 = Hmac<oxicrypt_sha::sha3::Sha3<144, 28>, 144, 28>;
/// HMAC-SHA3-256 (B=136, L=32).
pub type HmacSha3_256 = Hmac<oxicrypt_sha::sha3::Sha3<136, 32>, 136, 32>;
/// HMAC-SHA3-384 (B=104, L=48).
pub type HmacSha3_384 = Hmac<oxicrypt_sha::sha3::Sha3<104, 48>, 104, 48>;
/// HMAC-SHA3-512 (B=72, L=64).
pub type HmacSha3_512 = Hmac<oxicrypt_sha::sha3::Sha3<72, 64>, 72, 64>;

// ----------------------------------------------------------------------
// Power-up KATs
// ----------------------------------------------------------------------
//
// All HMAC power-up KATs are sourced from NIST ACVP-Server
// `HMAC-<alg>-1.0/internalProjection.json` (pinned commit + per-file
// SHA-256 recorded in `vendor/nist/MANIFEST.toml`) and re-exported via
// the `oxicrypt-test-vectors` crate.
//
// The eleven pinned ACVP cases all carry a `macLen` shorter than the
// full digest length. To validate against an unmodified NIST vector we
// therefore compute the full HMAC output and compare its leading
// `MAC_PREFIX.len()` bytes against the expected prefix constant. This
// strategy follows FIPS 140-3 IG 10.3.A, which requires a CAST for
// HMAC but does not require that the KAT be a full-length output.

macro_rules! kat_fn {
    ($name:ident, $alias:ty, $key:path, $msg:path, $prefix:path) => {
        /// Power-up KAT for this HMAC variant. Run by
        /// `oxicrypt_module::initialize_with_tests` during `SelfTest`.
        ///
        /// Sourced from NIST ACVP-Server HMAC-*-1.0; the KAT computes
        /// the full HMAC and compares its leading `MAC_PREFIX.len()`
        /// bytes against the truncated NIST expected value.
        pub fn $name() -> Result<(), SelfTestFailure> {
            let mut m = <$alias>::new_internal(&$key);
            m.update(&$msg);
            let out = m.finalize();
            let prefix = &$prefix;
            match out.get(..prefix.len()) {
                Some(head) if head == prefix => Ok(()),
                _ => Err(SelfTestFailure),
            }
        }
    };
}

kat_fn!(
    self_test_sha1,
    HmacSha1,
    oxicrypt_test_vectors::HMAC_SHA_1_KEY,
    oxicrypt_test_vectors::HMAC_SHA_1_MSG,
    oxicrypt_test_vectors::HMAC_SHA_1_MAC_PREFIX
);
kat_fn!(
    self_test_sha224,
    HmacSha224,
    oxicrypt_test_vectors::HMAC_SHA2_224_KEY,
    oxicrypt_test_vectors::HMAC_SHA2_224_MSG,
    oxicrypt_test_vectors::HMAC_SHA2_224_MAC_PREFIX
);
kat_fn!(
    self_test_sha256,
    HmacSha256,
    oxicrypt_test_vectors::HMAC_SHA2_256_KEY,
    oxicrypt_test_vectors::HMAC_SHA2_256_MSG,
    oxicrypt_test_vectors::HMAC_SHA2_256_MAC_PREFIX
);
kat_fn!(
    self_test_sha384,
    HmacSha384,
    oxicrypt_test_vectors::HMAC_SHA2_384_KEY,
    oxicrypt_test_vectors::HMAC_SHA2_384_MSG,
    oxicrypt_test_vectors::HMAC_SHA2_384_MAC_PREFIX
);
kat_fn!(
    self_test_sha512,
    HmacSha512,
    oxicrypt_test_vectors::HMAC_SHA2_512_KEY,
    oxicrypt_test_vectors::HMAC_SHA2_512_MSG,
    oxicrypt_test_vectors::HMAC_SHA2_512_MAC_PREFIX
);
kat_fn!(
    self_test_sha512_224,
    HmacSha512_224,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KEY,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_MSG,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_MAC_PREFIX
);
kat_fn!(
    self_test_sha512_256,
    HmacSha512_256,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KEY,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_MSG,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_MAC_PREFIX
);
kat_fn!(
    self_test_sha3_224,
    HmacSha3_224,
    oxicrypt_test_vectors::HMAC_SHA3_224_KEY,
    oxicrypt_test_vectors::HMAC_SHA3_224_MSG,
    oxicrypt_test_vectors::HMAC_SHA3_224_MAC_PREFIX
);
kat_fn!(
    self_test_sha3_256,
    HmacSha3_256,
    oxicrypt_test_vectors::HMAC_SHA3_256_KEY,
    oxicrypt_test_vectors::HMAC_SHA3_256_MSG,
    oxicrypt_test_vectors::HMAC_SHA3_256_MAC_PREFIX
);
kat_fn!(
    self_test_sha3_384,
    HmacSha3_384,
    oxicrypt_test_vectors::HMAC_SHA3_384_KEY,
    oxicrypt_test_vectors::HMAC_SHA3_384_MSG,
    oxicrypt_test_vectors::HMAC_SHA3_384_MAC_PREFIX
);
kat_fn!(
    self_test_sha3_512,
    HmacSha3_512,
    oxicrypt_test_vectors::HMAC_SHA3_512_KEY,
    oxicrypt_test_vectors::HMAC_SHA3_512_MSG,
    oxicrypt_test_vectors::HMAC_SHA3_512_MAC_PREFIX
);

/// Power-up KAT inventory for all HMAC variants in this crate.
///
/// Merged into the acvp-harness boot sequence via
/// `oxicrypt_module::initialize_with_tests`. Each variant has its own
/// KAT — families do not share.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "HMAC-SHA-1 KAT (NIST ACVP-Server HMAC-SHA-1-1.0, truncated)",
        run: self_test_sha1,
    },
    KatEntry {
        name: "HMAC-SHA-224 KAT (NIST ACVP-Server HMAC-SHA2-224-1.0, truncated)",
        run: self_test_sha224,
    },
    KatEntry {
        name: "HMAC-SHA-256 KAT (NIST ACVP-Server HMAC-SHA2-256-1.0, truncated)",
        run: self_test_sha256,
    },
    KatEntry {
        name: "HMAC-SHA-384 KAT (NIST ACVP-Server HMAC-SHA2-384-1.0, truncated)",
        run: self_test_sha384,
    },
    KatEntry {
        name: "HMAC-SHA-512 KAT (NIST ACVP-Server HMAC-SHA2-512-1.0, truncated)",
        run: self_test_sha512,
    },
    KatEntry {
        name: "HMAC-SHA-512/224 KAT (NIST ACVP-Server HMAC-SHA2-512/224-1.0, truncated)",
        run: self_test_sha512_224,
    },
    KatEntry {
        name: "HMAC-SHA-512/256 KAT (NIST ACVP-Server HMAC-SHA2-512/256-1.0, truncated)",
        run: self_test_sha512_256,
    },
    KatEntry {
        name: "HMAC-SHA3-224 KAT (NIST ACVP-Server HMAC-SHA3-224-1.0, truncated)",
        run: self_test_sha3_224,
    },
    KatEntry {
        name: "HMAC-SHA3-256 KAT (NIST ACVP-Server HMAC-SHA3-256-1.0, truncated)",
        run: self_test_sha3_256,
    },
    KatEntry {
        name: "HMAC-SHA3-384 KAT (NIST ACVP-Server HMAC-SHA3-384-1.0, truncated)",
        run: self_test_sha3_384,
    },
    KatEntry {
        name: "HMAC-SHA3-512 KAT (NIST ACVP-Server HMAC-SHA3-512-1.0, truncated)",
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
        HmacSha1, HmacSha3_256, HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacSha512_224,
        HmacSha512_256, self_test_sha1, self_test_sha3_224, self_test_sha3_256, self_test_sha3_384,
        self_test_sha3_512, self_test_sha224, self_test_sha256, self_test_sha384, self_test_sha512,
        self_test_sha512_224, self_test_sha512_256,
    };
    use oxicrypt_module::{KatEntry, initialize_with_tests};

    /// Stands in for the pre-operational integrity test.
    ///
    /// A `cargo test` binary is never signed, so the real integrity test
    /// cannot pass inside one. The module requires an integrity group to
    /// initialise at all, so a test that needs a gated service declares
    /// this stub — visibly, at the call site — rather than the module
    /// offering any way to skip the requirement.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    // Bring all the power-up KATs through the same boot the harness
    // uses. A single successful initialize flips the module into
    // Operational for all subsequent tests in this process.
    fn ensure_initialized() {
        const ALL: &[KatEntry] = super::KATS;
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, ALL);
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
        // Sanity: each SHA-1 / SHA-2 alias produces the output length its name
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
