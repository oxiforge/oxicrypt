//! Key derivation functions built on approved HMAC PRFs.
//!
//! # Scope (this batch)
//!
//! This crate currently ships **HKDF** per RFC 5869, as approved under
//! SP 800-56C Rev. 2 §4.1 for the Two-Step Key Derivation (extract
//! then expand) procedure. Every instantiation is parameterised by
//! one of the 11 HMAC variants that [`fips_hmac`] exposes:
//!
//!   - HKDF-SHA-1 (approved for KDF use per SP 800-131A Rev. 2 even
//!     though SHA-1 is disallowed for signatures)
//!   - HKDF-SHA-224, HKDF-SHA-256, HKDF-SHA-384, HKDF-SHA-512
//!   - HKDF-SHA-512/224, HKDF-SHA-512/256
//!   - HKDF-SHA3-224, HKDF-SHA3-256, HKDF-SHA3-384, HKDF-SHA3-512
//!
//! SP 800-108 Rev. 1 KBKDF (Counter, Feedback, Double-Pipeline) and
//! SP 800-56A Rev. 3 ConcatKDF are planned follow-on batches and do
//! not appear in this crate yet.
//!
//! # Design
//!
//! HKDF is structurally two HMAC passes: [`Hkdf::extract`] runs
//! `PRK = HMAC(salt, IKM)`, and [`Hkdf::expand`] iterates
//! `T(i) = HMAC(PRK, T(i-1) || info || i)` concatenating the outputs
//! until `okm.len()` bytes are produced. Both passes go through a
//! [`PrfHmac`] adapter trait that is blanket-implemented for every
//! [`fips_hmac::Hmac`] instantiation. Users talk to the public type
//! aliases ([`HkdfSha256`], etc.) — the adapter is `#[doc(hidden)]`
//! and not covered by semver.
//!
//! # FIPS 140-3 IG D.G note (March 2026)
//!
//! Per IG 10.3.A each KDF variant must carry its own power-up KAT;
//! KDF families do not share. The `KATS` slice exported from this
//! crate holds 11 entries — one HKDF extract+expand round-trip per
//! HMAC variant — all driven by the same RFC 5869 Test Case 1 inputs
//! for auditability.
#![no_std]
#![forbid(unsafe_code)]
#![allow(
    // KDF loops walk compile-time fixed-size buffers; bounds-checked
    // slice indexing is the clear idiom here.
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // HkdfSha512_224 / HkdfSha512_256 mirror the NIST spec names.
    non_camel_case_types
)]

use core::marker::PhantomData;

use fips_hmac::{BlockHash, Hmac};
use fips_module::{require_operational, Error, KatEntry, SelfTestFailure};

// ----------------------------------------------------------------------
// PrfHmac adapter trait
// ----------------------------------------------------------------------

/// Length-parameterised PRF view of an HMAC instantiation.
///
/// `L` is the PRF output length in bytes. HKDF does not need to know
/// the underlying hash's block size, only its MAC length, so this
/// trait erases `B` from [`fips_hmac::Hmac<H, B, L>`]. The blanket
/// impl below bridges every [`fips_hmac::Hmac`] instance into this
/// trait; callers should always use the public type aliases
/// ([`HkdfSha256`], etc.).
///
/// This trait is `#[doc(hidden)]` and is not part of the crate's
/// semver commitment.
#[doc(hidden)]
pub trait PrfHmac<const L: usize>: Sized {
    /// Construct an HMAC keyed with `key`, bypassing the module
    /// state machine (used by both the public API's already-gated
    /// callers and by boot-time KATs).
    fn prf_new(key: &[u8]) -> Self;
    /// Absorb more input.
    fn prf_update(&mut self, data: &[u8]);
    /// Finalise and return the `L`-byte MAC.
    fn prf_finalize(self) -> [u8; L];
}

impl<H, const B: usize, const L: usize> PrfHmac<L> for Hmac<H, B, L>
where
    H: BlockHash<B, L>,
{
    fn prf_new(key: &[u8]) -> Self {
        Hmac::new_internal(key)
    }
    fn prf_update(&mut self, data: &[u8]) {
        Hmac::update(self, data);
    }
    fn prf_finalize(self) -> [u8; L] {
        Hmac::finalize(self)
    }
}

// ----------------------------------------------------------------------
// Error type
// ----------------------------------------------------------------------

/// Errors surfaced by HKDF services.
///
/// `Module` wraps an [`Error`] from the module boundary (typically
/// `NotOperational`). `OutputTooLong` is returned when an expand
/// caller asks for more than `255 * L` bytes of output — the hard
/// upper bound from RFC 5869 §2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// The module rejected the call (not operational, etc.).
    Module(Error),
    /// Expand output length exceeded `255 * HashLen` bytes.
    OutputTooLong,
}

impl From<Error> for KdfError {
    fn from(value: Error) -> Self {
        Self::Module(value)
    }
}

// ----------------------------------------------------------------------
// Generic HKDF core
// ----------------------------------------------------------------------

/// HKDF instance holding a pseudorandom key produced by extract.
///
/// `L` is the HMAC output length in bytes; `P` is the HMAC
/// instantiation used for both extract and expand.
pub struct Hkdf<P: PrfHmac<L>, const L: usize> {
    prk: [u8; L],
    _m: PhantomData<fn() -> P>,
}

impl<P: PrfHmac<L>, const L: usize> Hkdf<P, L> {
    /// Runs HKDF-Extract: `PRK = HMAC(salt, IKM)`.
    ///
    /// A `None` salt is interpreted as `L` zero bytes, per RFC 5869
    /// §2.2. Enforces [`require_operational`]. For boot-time KATs,
    /// use [`Hkdf::extract_internal`].
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<Self, KdfError> {
        require_operational()?;
        Ok(Self::extract_internal(salt, ikm))
    }

    /// Gateless HKDF-Extract used by power-up KATs.
    #[doc(hidden)]
    pub fn extract_internal(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let zero_salt = [0u8; L];
        let salt_bytes: &[u8] = match salt {
            Some(s) => s,
            None => &zero_salt,
        };
        let mut mac = P::prf_new(salt_bytes);
        mac.prf_update(ikm);
        let prk = mac.prf_finalize();
        Self {
            prk,
            _m: PhantomData,
        }
    }

    /// Constructs an HKDF instance from an already-derived PRK.
    ///
    /// Intended for two-step KDF callers that ran extract in a
    /// separate operation and persisted the PRK. `prk.len()` must
    /// equal `L`; otherwise `Err(KdfError::OutputTooLong)` is
    /// returned (the length predicate is reused rather than adding
    /// a new error variant — RFC 5869 §2.3 requires `prk.len() == L`
    /// anyway).
    pub fn from_prk(prk: &[u8]) -> Result<Self, KdfError> {
        require_operational()?;
        if prk.len() != L {
            return Err(KdfError::OutputTooLong);
        }
        let mut arr = [0u8; L];
        arr.copy_from_slice(prk);
        Ok(Self {
            prk: arr,
            _m: PhantomData,
        })
    }

    /// Returns the derived PRK as a byte slice.
    pub fn prk(&self) -> &[u8; L] {
        &self.prk
    }

    /// Runs HKDF-Expand, filling `okm` with derived key material.
    ///
    /// Enforces [`require_operational`]. Returns
    /// [`KdfError::OutputTooLong`] if `okm.len() > 255 * L`.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), KdfError> {
        require_operational()?;
        self.expand_internal(info, okm)
    }

    /// Gateless HKDF-Expand used by power-up KATs.
    #[doc(hidden)]
    pub fn expand_internal(&self, info: &[u8], okm: &mut [u8]) -> Result<(), KdfError> {
        if okm.is_empty() {
            return Ok(());
        }
        // n = ceil(okm.len() / L); bounded by 255 per RFC 5869 §2.3.
        let n = okm.len().div_ceil(L);
        if n > 255 {
            return Err(KdfError::OutputTooLong);
        }

        let mut t_prev = [0u8; L];
        let mut have_prev = false;
        let mut written = 0usize;

        // n fits in u8 here because the check above rejects n > 255,
        // but we use `try_from` to satisfy clippy without a cast.
        let n_u8: u8 = match u8::try_from(n) {
            Ok(v) => v,
            Err(_) => return Err(KdfError::OutputTooLong),
        };
        let mut i: u8 = 1;
        while i <= n_u8 {
            let mut mac = P::prf_new(&self.prk);
            if have_prev {
                mac.prf_update(&t_prev);
            }
            mac.prf_update(info);
            mac.prf_update(&[i]);
            t_prev = mac.prf_finalize();
            have_prev = true;

            let remaining = okm.len() - written;
            let take = if remaining < L { remaining } else { L };
            okm[written..written + take].copy_from_slice(&t_prev[..take]);
            written += take;

            i += 1;
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Public type aliases — one HKDF per approved HMAC variant
// ----------------------------------------------------------------------

/// HKDF-SHA-1 (L=20).
pub type HkdfSha1 = Hkdf<fips_hmac::HmacSha1, 20>;
/// HKDF-SHA-224 (L=28).
pub type HkdfSha224 = Hkdf<fips_hmac::HmacSha224, 28>;
/// HKDF-SHA-256 (L=32).
pub type HkdfSha256 = Hkdf<fips_hmac::HmacSha256, 32>;
/// HKDF-SHA-384 (L=48).
pub type HkdfSha384 = Hkdf<fips_hmac::HmacSha384, 48>;
/// HKDF-SHA-512 (L=64).
pub type HkdfSha512 = Hkdf<fips_hmac::HmacSha512, 64>;
/// HKDF-SHA-512/224 (L=28).
pub type HkdfSha512_224 = Hkdf<fips_hmac::HmacSha512_224, 28>;
/// HKDF-SHA-512/256 (L=32).
pub type HkdfSha512_256 = Hkdf<fips_hmac::HmacSha512_256, 32>;
/// HKDF-SHA3-224 (L=28).
pub type HkdfSha3_224 = Hkdf<fips_hmac::HmacSha3_224, 28>;
/// HKDF-SHA3-256 (L=32).
pub type HkdfSha3_256 = Hkdf<fips_hmac::HmacSha3_256, 32>;
/// HKDF-SHA3-384 (L=48).
pub type HkdfSha3_384 = Hkdf<fips_hmac::HmacSha3_384, 48>;
/// HKDF-SHA3-512 (L=64).
pub type HkdfSha3_512 = Hkdf<fips_hmac::HmacSha3_512, 64>;

// ----------------------------------------------------------------------
// Power-up KATs
// ----------------------------------------------------------------------
//
// All 11 KATs use the RFC 5869 §A.1 Test Case 1 inputs:
//
//     IKM  = 0x0b * 22
//     salt = 0x00 0x01 0x02 ... 0x0c     (13 bytes)
//     info = 0xf0 0xf1 ... 0xf9          (10 bytes)
//     L    = 42                          (bytes of OKM)
//
// For SHA-256 the PRK and OKM are exactly the values in RFC 5869
// Appendix A.1. For the other 10 hashes the expected values were
// computed with Python's `hmac` module (which defers to OpenSSL's
// CAVS-validated primitives) against the identical inputs, so the
// entire battery is verifiable with a single line of reference
// tooling.

const KAT_IKM: [u8; 22] = [0x0b; 22];
const KAT_SALT: [u8; 13] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];
const KAT_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
const KAT_L: usize = 42;

// --- SHA-1 -----------------------------------------------------------
const KAT_PRK_SHA1: [u8; 20] = [
    0x66, 0x72, 0xe1, 0x72, 0x4a, 0xdb, 0x72, 0x79, 0x81, 0x67, 0x70, 0x3e, 0xe4, 0x4d, 0x34, 0x74,
    0x3e, 0x3b, 0x55, 0x64,
];
const KAT_OKM_SHA1: [u8; 42] = [
    0xd6, 0x00, 0x0f, 0xfb, 0x5b, 0x50, 0xbd, 0x39, 0x70, 0xb2, 0x60, 0x01, 0x77, 0x98, 0xfb, 0x9c,
    0x8d, 0xf9, 0xce, 0x2e, 0x2c, 0x16, 0xb6, 0xcd, 0x70, 0x9c, 0xca, 0x07, 0xdc, 0x3c, 0xf9, 0xcf,
    0x26, 0xd6, 0xc6, 0xd7, 0x50, 0xd0, 0xaa, 0xf5, 0xac, 0x94,
];

// --- SHA-224 ---------------------------------------------------------
const KAT_PRK_SHA224: [u8; 28] = [
    0x94, 0xf6, 0x5b, 0xed, 0x12, 0x26, 0x5c, 0x1f, 0xa2, 0x74, 0x7d, 0xb6, 0x0c, 0xad, 0xfc, 0xab,
    0xbb, 0xba, 0xed, 0xe6, 0xbe, 0x5a, 0x7a, 0x45, 0x0d, 0xe7, 0x82, 0x31,
];
const KAT_OKM_SHA224: [u8; 42] = [
    0x2f, 0x21, 0xcd, 0x7c, 0xbc, 0x81, 0x8c, 0xa5, 0xc5, 0x61, 0xb9, 0x33, 0x72, 0x8e, 0x2e, 0x08,
    0xe1, 0x54, 0xa8, 0x7e, 0x14, 0x32, 0x39, 0x9a, 0x82, 0x0d, 0xee, 0x13, 0xaa, 0x22, 0x2d, 0x0c,
    0xee, 0x61, 0x52, 0xfa, 0x53, 0x9a, 0xb7, 0x0f, 0x8e, 0x80,
];

// --- SHA-256 (RFC 5869 §A.1 reference vector) ------------------------
const KAT_PRK_SHA256: [u8; 32] = [
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
];
const KAT_OKM_SHA256: [u8; 42] = [
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
];

// --- SHA-384 ---------------------------------------------------------
const KAT_PRK_SHA384: [u8; 48] = [
    0x70, 0x4b, 0x39, 0x99, 0x07, 0x79, 0xce, 0x1d, 0xc5, 0x48, 0x05, 0x2c, 0x7d, 0xc3, 0x9f, 0x30,
    0x35, 0x70, 0xdd, 0x13, 0xfb, 0x39, 0xf7, 0xac, 0xc5, 0x64, 0x68, 0x0b, 0xef, 0x80, 0xe8, 0xde,
    0xc7, 0x0e, 0xe9, 0xa7, 0xe1, 0xf3, 0xe2, 0x93, 0xef, 0x68, 0xec, 0xeb, 0x07, 0x2a, 0x5a, 0xde,
];
const KAT_OKM_SHA384: [u8; 42] = [
    0x9b, 0x50, 0x97, 0xa8, 0x60, 0x38, 0xb8, 0x05, 0x30, 0x90, 0x76, 0xa4, 0x4b, 0x3a, 0x9f, 0x38,
    0x06, 0x3e, 0x25, 0xb5, 0x16, 0xdc, 0xbf, 0x36, 0x9f, 0x39, 0x4c, 0xfa, 0xb4, 0x36, 0x85, 0xf7,
    0x48, 0xb6, 0x45, 0x77, 0x63, 0xe4, 0xf0, 0x20, 0x4f, 0xc5,
];

// --- SHA-512 ---------------------------------------------------------
const KAT_PRK_SHA512: [u8; 64] = [
    0x66, 0x57, 0x99, 0x82, 0x37, 0x37, 0xde, 0xd0, 0x4a, 0x88, 0xe4, 0x7e, 0x54, 0xa5, 0x89, 0x0b,
    0xb2, 0xc3, 0xd2, 0x47, 0xc7, 0xa4, 0x25, 0x4a, 0x8e, 0x61, 0x35, 0x07, 0x23, 0x59, 0x0a, 0x26,
    0xc3, 0x62, 0x38, 0x12, 0x7d, 0x86, 0x61, 0xb8, 0x8c, 0xf8, 0x0e, 0xf8, 0x02, 0xd5, 0x7e, 0x2f,
    0x7c, 0xeb, 0xcf, 0x1e, 0x00, 0xe0, 0x83, 0x84, 0x8b, 0xe1, 0x99, 0x29, 0xc6, 0x1b, 0x42, 0x37,
];
const KAT_OKM_SHA512: [u8; 42] = [
    0x83, 0x23, 0x90, 0x08, 0x6c, 0xda, 0x71, 0xfb, 0x47, 0x62, 0x5b, 0xb5, 0xce, 0xb1, 0x68, 0xe4,
    0xc8, 0xe2, 0x6a, 0x1a, 0x16, 0xed, 0x34, 0xd9, 0xfc, 0x7f, 0xe9, 0x2c, 0x14, 0x81, 0x57, 0x93,
    0x38, 0xda, 0x36, 0x2c, 0xb8, 0xd9, 0xf9, 0x25, 0xd7, 0xcb,
];

// --- SHA-512/224 -----------------------------------------------------
const KAT_PRK_SHA512_224: [u8; 28] = [
    0xc0, 0xac, 0x5c, 0x0e, 0x25, 0x55, 0x62, 0x20, 0x3e, 0x0d, 0x6f, 0x74, 0x3f, 0xf2, 0xf0, 0x31,
    0x97, 0xf0, 0x95, 0xf3, 0x2e, 0xf3, 0x58, 0x9d, 0x18, 0x08, 0xf6, 0x23,
];
const KAT_OKM_SHA512_224: [u8; 42] = [
    0xf8, 0xd9, 0x56, 0xe1, 0x52, 0xb0, 0xfb, 0xa8, 0x31, 0xba, 0xc4, 0x00, 0xf1, 0xa5, 0xaf, 0x54,
    0x98, 0x2b, 0x91, 0xdb, 0x3d, 0x96, 0xae, 0x21, 0xa7, 0x56, 0x55, 0xef, 0xf1, 0x72, 0x5f, 0x92,
    0x8e, 0x49, 0x1c, 0x63, 0xf3, 0xae, 0xdb, 0x40, 0x82, 0x96,
];

// --- SHA-512/256 -----------------------------------------------------
const KAT_PRK_SHA512_256: [u8; 32] = [
    0x1b, 0x5f, 0xdf, 0xd1, 0xe8, 0x17, 0x17, 0x3b, 0x2b, 0x6f, 0xe9, 0x74, 0x99, 0xa4, 0x9e, 0xbc,
    0x45, 0xcf, 0x21, 0x6c, 0x3f, 0x94, 0x3b, 0x3a, 0xe6, 0x82, 0xab, 0xc1, 0x7f, 0xa0, 0xb0, 0x13,
];
const KAT_OKM_SHA512_256: [u8; 42] = [
    0x78, 0x9a, 0x93, 0xe5, 0x67, 0xa1, 0x86, 0x1d, 0xe4, 0x49, 0x34, 0x2b, 0x2d, 0x67, 0x4c, 0x0d,
    0xf7, 0x37, 0xfd, 0x8a, 0xdc, 0xe2, 0xa8, 0xe1, 0x84, 0x32, 0x37, 0xc1, 0x93, 0x8a, 0xc4, 0x13,
    0x04, 0x4b, 0x49, 0x6c, 0xe2, 0x67, 0xa1, 0x98, 0xeb, 0xe3,
];

// --- SHA3-224 --------------------------------------------------------
const KAT_PRK_SHA3_224: [u8; 28] = [
    0xaf, 0x44, 0x65, 0x7d, 0xfc, 0x99, 0x46, 0xf9, 0x0d, 0x9f, 0xf0, 0x07, 0xd0, 0x83, 0xfb, 0x10,
    0x6c, 0x28, 0x91, 0x71, 0x02, 0x1a, 0xad, 0x2b, 0xe4, 0x88, 0x01, 0xfb,
];
const KAT_OKM_SHA3_224: [u8; 42] = [
    0x50, 0x58, 0x86, 0x7f, 0xc7, 0xbd, 0xb1, 0x18, 0xce, 0x6a, 0x70, 0x3a, 0xdd, 0x6e, 0xdb, 0xf8,
    0xe2, 0xce, 0x21, 0xf5, 0x76, 0x6c, 0xfc, 0x2e, 0x66, 0x2e, 0x1a, 0x36, 0xff, 0x69, 0x22, 0xfa,
    0x96, 0xfc, 0x14, 0x95, 0x17, 0xcf, 0x1e, 0x45, 0x1f, 0xe6,
];

// --- SHA3-256 --------------------------------------------------------
const KAT_PRK_SHA3_256: [u8; 32] = [
    0x7d, 0x41, 0x94, 0x83, 0x6f, 0x7a, 0x11, 0x3a, 0x44, 0x67, 0x7a, 0xbc, 0x82, 0x56, 0x40, 0xad,
    0xe0, 0x7a, 0xf1, 0xc1, 0xd6, 0x9a, 0x9a, 0x4b, 0x10, 0x9b, 0x28, 0x0a, 0x8f, 0xe5, 0x4e, 0xf0,
];
const KAT_OKM_SHA3_256: [u8; 42] = [
    0x0c, 0x51, 0x60, 0x50, 0x1d, 0x65, 0x02, 0x1d, 0xea, 0xf2, 0xc1, 0x4f, 0x5a, 0xbc, 0xe0, 0x4c,
    0x5b, 0xd2, 0x63, 0x5a, 0xbc, 0xee, 0xba, 0x61, 0xc2, 0xed, 0xb6, 0xe8, 0xed, 0x72, 0x67, 0x49,
    0x00, 0x55, 0x77, 0x28, 0xf2, 0xc9, 0xf2, 0xc4, 0xc1, 0x79,
];

// --- SHA3-384 --------------------------------------------------------
const KAT_PRK_SHA3_384: [u8; 48] = [
    0x78, 0x55, 0xbc, 0x93, 0x00, 0xa4, 0xdb, 0x53, 0x2c, 0x9c, 0xab, 0x25, 0x93, 0x79, 0x6e, 0x1a,
    0x4b, 0xbb, 0x77, 0xa2, 0x4d, 0x41, 0x7e, 0x66, 0x82, 0x2b, 0xea, 0xa3, 0x6f, 0xab, 0xd4, 0x12,
    0x51, 0x5d, 0xcf, 0x38, 0x88, 0x10, 0xad, 0xf2, 0x7f, 0xa2, 0x3d, 0x3d, 0x7d, 0xef, 0x84, 0xca,
];
const KAT_OKM_SHA3_384: [u8; 42] = [
    0x13, 0x8d, 0x85, 0x21, 0xe5, 0xa3, 0x46, 0xa9, 0xcb, 0x77, 0x0f, 0x76, 0x2b, 0x9c, 0x04, 0xd9,
    0xca, 0x31, 0x74, 0x09, 0xfb, 0x6a, 0x3e, 0xf9, 0xcb, 0x90, 0x52, 0x28, 0x38, 0x55, 0x89, 0xae,
    0x88, 0x3b, 0xbe, 0x8b, 0x07, 0xb0, 0x09, 0xf0, 0xe0, 0x8b,
];

// --- SHA3-512 --------------------------------------------------------
const KAT_PRK_SHA3_512: [u8; 64] = [
    0xe1, 0xc5, 0x43, 0x09, 0x4f, 0x64, 0xf3, 0xd6, 0xc6, 0x65, 0x8a, 0x94, 0xa9, 0x4e, 0x38, 0x18,
    0xba, 0x13, 0xd0, 0xb3, 0xe7, 0x70, 0x74, 0xb8, 0x0f, 0x88, 0xf3, 0x2e, 0x6b, 0x84, 0x33, 0xb7,
    0x03, 0x53, 0x6c, 0xb5, 0x00, 0x75, 0x39, 0x67, 0xfa, 0xe2, 0xea, 0x97, 0x7e, 0x11, 0xe4, 0xdd,
    0x4f, 0x45, 0x38, 0x98, 0x07, 0xcd, 0xf2, 0x55, 0xb3, 0x95, 0xe4, 0x68, 0x07, 0xc8, 0x7d, 0x5d,
];
const KAT_OKM_SHA3_512: [u8; 42] = [
    0x40, 0xe9, 0xf1, 0x7e, 0x9b, 0xf2, 0xef, 0x99, 0x42, 0x5c, 0x2b, 0x23, 0xcc, 0xdf, 0x20, 0xa0,
    0x18, 0xea, 0x55, 0x13, 0xf9, 0xae, 0x68, 0xe1, 0xea, 0x8c, 0x62, 0x6d, 0xeb, 0x57, 0xdf, 0xa4,
    0xd5, 0x6c, 0x27, 0xcc, 0xf2, 0xa2, 0xa2, 0x44, 0x88, 0xa5,
];

macro_rules! kat_fn {
    ($name:ident, $alias:ty, $prk:ident, $okm:ident) => {
        /// Power-up KAT for this HKDF variant: extract then expand
        /// against the RFC 5869 §A.1 Test Case 1 inputs.
        pub fn $name() -> Result<(), SelfTestFailure> {
            let hk = <$alias>::extract_internal(Some(&KAT_SALT), &KAT_IKM);
            if hk.prk() != &$prk {
                return Err(SelfTestFailure);
            }
            let mut okm = [0u8; KAT_L];
            if hk.expand_internal(&KAT_INFO, &mut okm).is_err() {
                return Err(SelfTestFailure);
            }
            if okm != $okm {
                return Err(SelfTestFailure);
            }
            Ok(())
        }
    };
}

kat_fn!(self_test_sha1, HkdfSha1, KAT_PRK_SHA1, KAT_OKM_SHA1);
kat_fn!(self_test_sha224, HkdfSha224, KAT_PRK_SHA224, KAT_OKM_SHA224);
kat_fn!(self_test_sha256, HkdfSha256, KAT_PRK_SHA256, KAT_OKM_SHA256);
kat_fn!(self_test_sha384, HkdfSha384, KAT_PRK_SHA384, KAT_OKM_SHA384);
kat_fn!(self_test_sha512, HkdfSha512, KAT_PRK_SHA512, KAT_OKM_SHA512);
kat_fn!(
    self_test_sha512_224,
    HkdfSha512_224,
    KAT_PRK_SHA512_224,
    KAT_OKM_SHA512_224
);
kat_fn!(
    self_test_sha512_256,
    HkdfSha512_256,
    KAT_PRK_SHA512_256,
    KAT_OKM_SHA512_256
);
kat_fn!(
    self_test_sha3_224,
    HkdfSha3_224,
    KAT_PRK_SHA3_224,
    KAT_OKM_SHA3_224
);
kat_fn!(
    self_test_sha3_256,
    HkdfSha3_256,
    KAT_PRK_SHA3_256,
    KAT_OKM_SHA3_256
);
kat_fn!(
    self_test_sha3_384,
    HkdfSha3_384,
    KAT_PRK_SHA3_384,
    KAT_OKM_SHA3_384
);
kat_fn!(
    self_test_sha3_512,
    HkdfSha3_512,
    KAT_PRK_SHA3_512,
    KAT_OKM_SHA3_512
);

/// Power-up KAT inventory for every HKDF variant in this crate.
///
/// Merged into the acvp-harness boot sequence via
/// [`fips_module::initialize_with_tests`]. Per FIPS 140-3 IG 10.3.A
/// each KDF instantiation carries its own KAT.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "HKDF-SHA-1 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha1,
    },
    KatEntry {
        name: "HKDF-SHA-224 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha224,
    },
    KatEntry {
        name: "HKDF-SHA-256 KAT (RFC 5869 §A.1 test 1)",
        run: self_test_sha256,
    },
    KatEntry {
        name: "HKDF-SHA-384 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha384,
    },
    KatEntry {
        name: "HKDF-SHA-512 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha512,
    },
    KatEntry {
        name: "HKDF-SHA-512/224 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha512_224,
    },
    KatEntry {
        name: "HKDF-SHA-512/256 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha512_256,
    },
    KatEntry {
        name: "HKDF-SHA3-224 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha3_224,
    },
    KatEntry {
        name: "HKDF-SHA3-256 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha3_256,
    },
    KatEntry {
        name: "HKDF-SHA3-384 KAT (RFC 5869 inputs, OpenSSL-derived)",
        run: self_test_sha3_384,
    },
    KatEntry {
        name: "HKDF-SHA3-512 KAT (RFC 5869 inputs, OpenSSL-derived)",
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
        self_test_sha512_224, self_test_sha512_256, HkdfSha1, HkdfSha256, HkdfSha3_256, HkdfSha512,
        KdfError, KAT_INFO, KAT_OKM_SHA256, KAT_PRK_SHA256, KAT_SALT,
    };
    use fips_module::{initialize_with_tests, Error, KatEntry, State};

    fn ensure_initialized() {
        const ALL: &[KatEntry] = super::KATS;
        let _ = initialize_with_tests(ALL);
    }

    #[test]
    fn boot_self_tests_all_pass() {
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
    fn hkdf_sha256_rfc5869_test_case_1_public_api() {
        ensure_initialized();
        let ikm = [0x0b; 22];
        let hk = HkdfSha256::extract(Some(&KAT_SALT), &ikm).unwrap();
        assert_eq!(hk.prk(), &KAT_PRK_SHA256);
        let mut okm = [0u8; 42];
        hk.expand(&KAT_INFO, &mut okm).unwrap();
        assert_eq!(okm, KAT_OKM_SHA256);
    }

    #[test]
    fn hkdf_empty_salt_is_none_equivalent_to_zero_salt() {
        // RFC 5869 §2.2: a `None` salt MUST be treated as `HashLen`
        // zero bytes. Verify that explicit zeros and None produce
        // identical PRKs for SHA-1.
        ensure_initialized();
        let ikm = [0x0b; 22];
        let zero = [0u8; 20];
        let a = HkdfSha1::extract(None, &ikm).unwrap();
        let b = HkdfSha1::extract(Some(&zero), &ikm).unwrap();
        assert_eq!(a.prk(), b.prk());
    }

    #[test]
    fn hkdf_expand_output_too_long_is_rejected() {
        ensure_initialized();
        let ikm = [0x0b; 22];
        let hk = HkdfSha256::extract(Some(&KAT_SALT), &ikm).unwrap();
        // 256 * 32 = 8192 > 255 * 32 = 8160 — must error.
        let mut okm = [0u8; 256 * 32];
        match hk.expand(&KAT_INFO, &mut okm) {
            Err(KdfError::OutputTooLong) => {}
            Err(other) => panic!("expected OutputTooLong, got other err: {other:?}"),
            Ok(()) => panic!("expected OutputTooLong, got Ok"),
        }
    }

    #[test]
    fn hkdf_expand_empty_okm_is_noop() {
        ensure_initialized();
        let ikm = [0x0b; 22];
        let hk = HkdfSha256::extract(Some(&KAT_SALT), &ikm).unwrap();
        let mut okm: [u8; 0] = [];
        hk.expand(&KAT_INFO, &mut okm).unwrap();
    }

    #[test]
    fn hkdf_from_prk_rejects_wrong_length() {
        ensure_initialized();
        let short = [0u8; 16];
        match HkdfSha256::from_prk(&short) {
            Err(KdfError::OutputTooLong) => {}
            Err(other) => panic!("expected OutputTooLong, got other err: {other:?}"),
            Ok(_) => panic!("expected OutputTooLong, got Ok"),
        }
    }

    #[test]
    fn hkdf_from_prk_round_trips_expand() {
        ensure_initialized();
        let ikm = [0x0b; 22];
        // Produce a PRK via extract, round-trip via from_prk, and
        // verify expand still matches the RFC 5869 vector.
        let first = HkdfSha256::extract(Some(&KAT_SALT), &ikm).unwrap();
        let prk = *first.prk();
        let second = HkdfSha256::from_prk(&prk).unwrap();
        let mut okm = [0u8; 42];
        second.expand(&KAT_INFO, &mut okm).unwrap();
        assert_eq!(okm, KAT_OKM_SHA256);
    }

    #[test]
    fn hkdf_sha3_256_short_expand_deterministic() {
        // Exercise the SHA-3 PRF path with a short (< L) expand.
        ensure_initialized();
        let ikm = [0x0b; 22];
        let hk = HkdfSha3_256::extract(Some(&KAT_SALT), &ikm).unwrap();
        let mut a = [0u8; 10];
        let mut b = [0u8; 10];
        hk.expand(&KAT_INFO, &mut a).unwrap();
        hk.expand(&KAT_INFO, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_sha512_streaming_matches_one_shot_expand() {
        // HKDF-Expand has no streaming API, but back-to-back calls
        // against the same Hkdf instance must be deterministic.
        ensure_initialized();
        let ikm = [0x0b; 22];
        let hk = HkdfSha512::extract(Some(&KAT_SALT), &ikm).unwrap();
        let mut a = [0u8; 100];
        let mut b = [0u8; 100];
        hk.expand(&KAT_INFO, &mut a).unwrap();
        hk.expand(&KAT_INFO, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn kdferror_wraps_module_errors() {
        // Confirm the From impl plumbs a module error through.
        let e: KdfError = Error::NotOperational {
            current: State::PowerOff,
        }
        .into();
        assert!(matches!(e, KdfError::Module(_)));
    }
}
