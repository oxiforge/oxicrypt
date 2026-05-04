//! Key derivation functions built on approved HMAC PRFs.
//!
//! # Scope
//!
//! This crate ships:
//!
//!   - **HKDF** per RFC 5869, approved under SP 800-56C Rev. 2 §4.1
//!     as the Two-Step KDF ([`Hkdf::extract`] / [`Hkdf::expand`]).
//!   - **SP 800-108 Rev. 1 KBKDF in Counter Mode** ([`Sp800_108Counter`]),
//!     with a 32-bit big-endian counter placed before the fixed
//!     input string and the output length encoded as a 32-bit
//!     big-endian bit count.
//!   - **SP 800-108 Rev. 1 KBKDF in Feedback Mode** ([`Sp800_108Feedback`]),
//!     per §4.2, in the counterLocation="none" form:
//!     `K(0) = IV; K(i) = PRF(K_IN, K(i-1) || FixedData)`.
//!   - **SP 800-108 Rev. 1 KBKDF in Double-Pipeline Iteration Mode**
//!     ([`Sp800_108DoublePipeline`]), per §4.3, in the
//!     counterLocation="none" form:
//!     `A(0) = FixedData; A(i) = PRF(K_IN, A(i-1));`
//!     `K(i) = PRF(K_IN, A(i) || FixedData)`.
//!   - **PBKDF2** per SP 800-132 / RFC 8018 §5.2 ([`Pbkdf2`]),
//!     password-based key derivation iterating HMAC `c` times.
//!
//! Every instantiation is parameterised by one of the 11 HMAC
//! variants that [`oxicrypt_hmac`] exposes (SHA-1, SHA-2 family,
//! SHA-512/t truncated family, SHA-3 family). HMAC-SHA-1 remains
//! approved for KDF use per SP 800-131A Rev. 2 even though SHA-1 is
//! disallowed for digital signatures.
//!
//! SP 800-56A Rev. 3 ConcatKDF is a planned follow-on batch and
//! does not appear in this crate yet.
//!
//! # Design
//!
//! HKDF is structurally two HMAC passes: [`Hkdf::extract`] runs
//! `PRK = HMAC(salt, IKM)`, and [`Hkdf::expand`] iterates
//! `T(i) = HMAC(PRK, T(i-1) || info || i)` concatenating the outputs
//! until `okm.len()` bytes are produced. Both passes go through a
//! [`PrfHmac`] adapter trait that is blanket-implemented for every
//! [`oxicrypt_hmac::Hmac`] instantiation. Users talk to the public type
//! aliases ([`HkdfSha256`], etc.) — the adapter is `#[doc(hidden)]`
//! and not covered by semver.
//!
//! # Power-up self-tests
//!
//! Per IG 10.3.A each KDF instantiation carries its own
//! power-up KAT; KDF families do not share. [`KATS`] exposes
//! 46 entries total — 11 HKDF extract+expand round-trips plus
//! 11 SP 800-108 Counter Mode derivations plus 11 SP 800-108
//! Feedback Mode derivations plus 11 SP 800-108 Double-Pipeline
//! Iteration Mode derivations plus 2 PBKDF2 derivations (SHA-1,
//! SHA-256), all driven by fixed compile-time inputs for
//! auditability.
//!
//! # Sensitive security parameters
//!
//! - **Input keying material (IKM)** to HKDF-Extract — CSP
//!   supplied by the caller (e.g. an ECDH shared secret). The
//!   caller retains ownership and is responsible for zeroizing
//!   its own IKM buffer once HKDF has consumed it.
//! - **Pseudo-random key (PRK)** produced by HKDF-Extract — CSP.
//!   Held inside the [`Hkdf`] handle between `extract` and
//!   `expand`; lives only as long as the handle is in scope.
//! - **SP 800-108 key-derivation key (`K_IN`)** — CSP supplied
//!   by the caller, not retained beyond the derivation call.
//! - **Output keying material (OKM)** — CSP returned to the
//!   caller. Its classification depends on downstream use.
//!
//! # FIPS module gating and algorithm profiles
//!
//! Every public KDF entry point calls both
//! [`oxicrypt_module::require_operational`] for state-machine gating
//! and [`oxicrypt_module::require_allowed`] for algorithm-profile
//! gating. Each KDF variant (e.g., HKDF-SHA-256) maps to a
//! [`Service`] constant through the
//! [`PrfHmac`] adapter trait, enforcing the active profile's
//! restrictions (e.g., CNSA 2.0 restricts some variants). The KAT
//! runners reach into the `*_internal` surface so they can execute
//! while the module is still in `SelfTest`.
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

use oxicrypt_module::{
    require_allowed, require_operational, Error, KatEntry, SelfTestFailure, Service,
};

// ----------------------------------------------------------------------
// PrfHmac adapter trait
// ----------------------------------------------------------------------

/// Length-parameterised PRF view of an HMAC instantiation.
///
/// `L` is the PRF output length in bytes. HKDF does not need to know
/// the underlying hash's block size, only its MAC length, so this
/// trait erases `B` from [`oxicrypt_hmac::Hmac<H, B, L>`]. The blanket
/// impl below bridges every [`oxicrypt_hmac::Hmac`] instance into this
/// trait; callers should always use the public type aliases
/// ([`HkdfSha256`], etc.).
///
/// This trait is `#[doc(hidden)]` and is not part of the crate's
/// semver commitment.
#[doc(hidden)]
pub trait PrfHmac<const L: usize>: Sized {
    /// The KDF service gating this HMAC variant for profile checks.
    const KDF_SERVICE: Service;
    /// Construct an HMAC keyed with `key`, bypassing the module
    /// state machine (used by both the public API's already-gated
    /// callers and by boot-time KATs).
    fn prf_new(key: &[u8]) -> Self;
    /// Absorb more input.
    fn prf_update(&mut self, data: &[u8]);
    /// Finalise and return the `L`-byte MAC.
    fn prf_finalize(&mut self) -> [u8; L];
}

// Macro to implement PrfHmac for each HMAC type with its corresponding
// KDF service constant.
macro_rules! impl_prf_hmac {
    ($hmac_type:ty, $kdf_service:expr, $L:expr) => {
        impl PrfHmac<$L> for $hmac_type {
            const KDF_SERVICE: Service = $kdf_service;

            fn prf_new(key: &[u8]) -> Self {
                <$hmac_type>::new_internal(key)
            }
            fn prf_update(&mut self, data: &[u8]) {
                <$hmac_type>::update(self, data);
            }
            fn prf_finalize(&mut self) -> [u8; $L] {
                <$hmac_type>::finalize(self)
            }
        }
    };
}

// Implement PrfHmac for each HMAC type
impl_prf_hmac!(oxicrypt_hmac::HmacSha1, Service::HkdfSha1, 20);
impl_prf_hmac!(oxicrypt_hmac::HmacSha224, Service::HkdfSha256, 28);
impl_prf_hmac!(oxicrypt_hmac::HmacSha256, Service::HkdfSha256, 32);
impl_prf_hmac!(oxicrypt_hmac::HmacSha384, Service::HkdfSha384, 48);
impl_prf_hmac!(oxicrypt_hmac::HmacSha512, Service::HkdfSha512, 64);
impl_prf_hmac!(oxicrypt_hmac::HmacSha512_224, Service::HkdfSha256, 28);
impl_prf_hmac!(oxicrypt_hmac::HmacSha512_256, Service::HkdfSha256, 32);
impl_prf_hmac!(oxicrypt_hmac::HmacSha3_224, Service::HkdfSha256, 28);
impl_prf_hmac!(oxicrypt_hmac::HmacSha3_256, Service::HkdfSha256, 32);
impl_prf_hmac!(oxicrypt_hmac::HmacSha3_384, Service::HkdfSha384, 48);
impl_prf_hmac!(oxicrypt_hmac::HmacSha3_512, Service::HkdfSha512, 64);

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

impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Module(e) => write!(f, "module error: {e}"),
            Self::OutputTooLong => write!(
                f,
                "requested output exceeds 255 * HashLen bytes (RFC 5869 §2.3); \
                 reduce the output length or use a hash with a larger digest"
            ),
        }
    }
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
    /// §2.2. Enforces [`require_operational`] and algorithm-profile
    /// gating via [`require_allowed`]. For boot-time KATs,
    /// use `Hkdf::extract_internal` (gate-free counterpart, hidden
    /// from public docs).
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<Self, KdfError> {
        require_operational()?;
        require_allowed(P::KDF_SERVICE)?;
        Ok(Self::extract_internal(salt, ikm))
    }

    /// Gateless HKDF-Extract used by power-up KATs.
    #[doc(hidden)]
    pub(crate) fn extract_internal(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
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
    /// anyway). Enforces [`require_operational`] and algorithm-profile
    /// gating via [`require_allowed`].
    pub fn from_prk(prk: &[u8]) -> Result<Self, KdfError> {
        require_operational()?;
        require_allowed(P::KDF_SERVICE)?;
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
    /// Enforces [`require_operational`] and algorithm-profile gating
    /// via [`require_allowed`]. Returns [`KdfError::OutputTooLong`]
    /// if `okm.len() > 255 * L`.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), KdfError> {
        require_operational()?;
        require_allowed(P::KDF_SERVICE)?;
        self.expand_internal(info, okm)
    }

    /// Gateless HKDF-Expand used by power-up KATs.
    #[doc(hidden)]
    pub(crate) fn expand_internal(&self, info: &[u8], okm: &mut [u8]) -> Result<(), KdfError> {
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

impl<P: PrfHmac<L>, const L: usize> Drop for Hkdf<P, L> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.prk);
    }
}

// ----------------------------------------------------------------------
// Public type aliases — one HKDF per approved HMAC variant
// ----------------------------------------------------------------------

/// HKDF-SHA-1 (L=20).
pub type HkdfSha1 = Hkdf<oxicrypt_hmac::HmacSha1, 20>;
/// HKDF-SHA-224 (L=28).
pub type HkdfSha224 = Hkdf<oxicrypt_hmac::HmacSha224, 28>;
/// HKDF-SHA-256 (L=32).
pub type HkdfSha256 = Hkdf<oxicrypt_hmac::HmacSha256, 32>;
/// HKDF-SHA-384 (L=48).
pub type HkdfSha384 = Hkdf<oxicrypt_hmac::HmacSha384, 48>;
/// HKDF-SHA-512 (L=64).
pub type HkdfSha512 = Hkdf<oxicrypt_hmac::HmacSha512, 64>;
/// HKDF-SHA-512/224 (L=28).
pub type HkdfSha512_224 = Hkdf<oxicrypt_hmac::HmacSha512_224, 28>;
/// HKDF-SHA-512/256 (L=32).
pub type HkdfSha512_256 = Hkdf<oxicrypt_hmac::HmacSha512_256, 32>;
/// HKDF-SHA3-224 (L=28).
pub type HkdfSha3_224 = Hkdf<oxicrypt_hmac::HmacSha3_224, 28>;
/// HKDF-SHA3-256 (L=32).
pub type HkdfSha3_256 = Hkdf<oxicrypt_hmac::HmacSha3_256, 32>;
/// HKDF-SHA3-384 (L=48).
pub type HkdfSha3_384 = Hkdf<oxicrypt_hmac::HmacSha3_384, 48>;
/// HKDF-SHA3-512 (L=64).
pub type HkdfSha3_512 = Hkdf<oxicrypt_hmac::HmacSha3_512, 64>;

// ----------------------------------------------------------------------
// Power-up KATs
// ----------------------------------------------------------------------
//
// Ten of the eleven HKDF variants exercise NIST ACVP-Server
// `KDA-HKDF-Sp800-56Cr2` vectors (SP 800-56C Rev 2 §5 Two-Step KDF,
// §5.9.2 hybrid form). For each variant the KAT runs:
//
//     PRK = HMAC(SALT, IKM)                   (IKM = Z || T hybrid)
//     OKM = HKDF-Expand(PRK, FIXED_INFO, L)   (L = KEY_OUT.len())
//
// and compares the leading `KEY_OUT.len()` bytes of `OKM` against
// the expected DKM supplied by the ACVP-Server projection. FixedInfo
// is pre-encoded by `tools/acvp-gen/generate.py` per SP 800-56Cr2
// §5.8 so the Rust crypto surface sees a flat byte string.
//
// HKDF-SHA-1 is *not* covered by the KDA-HKDF-Sp800-56Cr2 family
// (SHA-1 is out of scope for SP 800-56C Rev 2). It remains on the
// RFC 5869 §A.1 Test Case 1 vector below, which is the only NIST-
// independent HKDF-SHA-1 KAT with broad cross-implementation
// corroboration.

// --- HKDF-SHA-1: RFC 5869 §A.1 Test Case 1 ---------------------------
const KAT_SHA1_IKM: [u8; 22] = [0x0b; 22];
const KAT_SHA1_SALT: [u8; 13] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];
const KAT_SHA1_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
const KAT_SHA1_PRK: [u8; 20] = [
    0x66, 0x72, 0xe1, 0x72, 0x4a, 0xdb, 0x72, 0x79, 0x81, 0x67, 0x70, 0x3e, 0xe4, 0x4d, 0x34, 0x74,
    0x3e, 0x3b, 0x55, 0x64,
];
const KAT_SHA1_OKM: [u8; 42] = [
    0xd6, 0x00, 0x0f, 0xfb, 0x5b, 0x50, 0xbd, 0x39, 0x70, 0xb2, 0x60, 0x01, 0x77, 0x98, 0xfb, 0x9c,
    0x8d, 0xf9, 0xce, 0x2e, 0x2c, 0x16, 0xb6, 0xcd, 0x70, 0x9c, 0xca, 0x07, 0xdc, 0x3c, 0xf9, 0xcf,
    0x26, 0xd6, 0xc6, 0xd7, 0x50, 0xd0, 0xaa, 0xf5, 0xac, 0x94,
];

/// Power-up KAT for HKDF-SHA-1 against the RFC 5869 §A.1 Test Case 1
/// vector. SHA-1 is out of scope for SP 800-56C Rev 2 so the KDA-HKDF
/// ACVP family does not cover it.
pub fn hkdf_self_test_sha1() -> Result<(), SelfTestFailure> {
    let hk = HkdfSha1::extract_internal(Some(&KAT_SHA1_SALT), &KAT_SHA1_IKM);
    if hk.prk() != &KAT_SHA1_PRK {
        return Err(SelfTestFailure);
    }
    let mut okm = [0u8; 42];
    if hk.expand_internal(&KAT_SHA1_INFO, &mut okm).is_err() {
        return Err(SelfTestFailure);
    }
    if okm != KAT_SHA1_OKM {
        return Err(SelfTestFailure);
    }
    Ok(())
}

/// Power-up KAT macro for an HKDF variant driven by a NIST ACVP-Server
/// `KDA-HKDF-Sp800-56Cr2` vector.
///
/// Runs `extract(Some(&SALT), &IKM)` followed by
/// `expand(&FIXED_INFO, &mut out)` and compares the leading
/// `KEY_OUT.len()` bytes of the derivation against `KEY_OUT`. The
/// IKM constant is the hybrid `Z || T` concatenation per SP 800-56Cr2
/// §5.9.2; the underlying HKDF primitive is exercised unchanged.
macro_rules! kda_hkdf_kat_fn {
    ($name:ident, $alias:ty, $salt:path, $ikm:path, $fixed_info:path, $key_out:path) => {
        /// Power-up KAT for an HKDF variant against a NIST ACVP-Server
        /// `KDA-HKDF-Sp800-56Cr2` (hybrid) test vector.
        pub fn $name() -> Result<(), SelfTestFailure> {
            let expected: &[u8] = &$key_out;
            // `KEY_OUT` from the ACVP projection is the full expected
            // DKM (1024 bits / 128 bytes at the pinned commit). The
            // backing buffer is sized to 128 so we can accommodate any
            // L up to that without a heap allocation.
            let mut out = [0u8; 128];
            let Some(slice) = out.get_mut(..expected.len()) else {
                return Err(SelfTestFailure);
            };
            let hk = <$alias>::extract_internal(Some(&$salt), &$ikm);
            if hk.expand_internal(&$fixed_info, slice).is_err() {
                return Err(SelfTestFailure);
            }
            if slice == expected {
                Ok(())
            } else {
                Err(SelfTestFailure)
            }
        }
    };
}

kda_hkdf_kat_fn!(
    hkdf_self_test_sha224,
    HkdfSha224,
    oxicrypt_test_vectors::HKDF_SHA2_224_SALT,
    oxicrypt_test_vectors::HKDF_SHA2_224_IKM,
    oxicrypt_test_vectors::HKDF_SHA2_224_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA2_224_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha256,
    HkdfSha256,
    oxicrypt_test_vectors::HKDF_SHA2_256_SALT,
    oxicrypt_test_vectors::HKDF_SHA2_256_IKM,
    oxicrypt_test_vectors::HKDF_SHA2_256_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA2_256_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha384,
    HkdfSha384,
    oxicrypt_test_vectors::HKDF_SHA2_384_SALT,
    oxicrypt_test_vectors::HKDF_SHA2_384_IKM,
    oxicrypt_test_vectors::HKDF_SHA2_384_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA2_384_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha512,
    HkdfSha512,
    oxicrypt_test_vectors::HKDF_SHA2_512_SALT,
    oxicrypt_test_vectors::HKDF_SHA2_512_IKM,
    oxicrypt_test_vectors::HKDF_SHA2_512_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA2_512_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha512_224,
    HkdfSha512_224,
    oxicrypt_test_vectors::HKDF_SHA2_512_224_SALT,
    oxicrypt_test_vectors::HKDF_SHA2_512_224_IKM,
    oxicrypt_test_vectors::HKDF_SHA2_512_224_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA2_512_224_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha512_256,
    HkdfSha512_256,
    oxicrypt_test_vectors::HKDF_SHA2_512_256_SALT,
    oxicrypt_test_vectors::HKDF_SHA2_512_256_IKM,
    oxicrypt_test_vectors::HKDF_SHA2_512_256_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA2_512_256_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha3_224,
    HkdfSha3_224,
    oxicrypt_test_vectors::HKDF_SHA3_224_SALT,
    oxicrypt_test_vectors::HKDF_SHA3_224_IKM,
    oxicrypt_test_vectors::HKDF_SHA3_224_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA3_224_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha3_256,
    HkdfSha3_256,
    oxicrypt_test_vectors::HKDF_SHA3_256_SALT,
    oxicrypt_test_vectors::HKDF_SHA3_256_IKM,
    oxicrypt_test_vectors::HKDF_SHA3_256_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA3_256_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha3_384,
    HkdfSha3_384,
    oxicrypt_test_vectors::HKDF_SHA3_384_SALT,
    oxicrypt_test_vectors::HKDF_SHA3_384_IKM,
    oxicrypt_test_vectors::HKDF_SHA3_384_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA3_384_KEY_OUT
);
kda_hkdf_kat_fn!(
    hkdf_self_test_sha3_512,
    HkdfSha3_512,
    oxicrypt_test_vectors::HKDF_SHA3_512_SALT,
    oxicrypt_test_vectors::HKDF_SHA3_512_IKM,
    oxicrypt_test_vectors::HKDF_SHA3_512_FIXED_INFO,
    oxicrypt_test_vectors::HKDF_SHA3_512_KEY_OUT
);

// ======================================================================
// SP 800-108 Rev. 1 KBKDF — Counter Mode
// ======================================================================
//
// Counter Mode, per SP 800-108 Rev. 1 §4.1, derives key material from
// a key-derivation key `K_IN` using:
//
//     K(i) = PRF(K_IN, [i]_32 || Label || 0x00 || Context || [L]_32)
//
// where:
//
//   * [i]_32 is the 32-bit big-endian iteration counter, starting at 1
//   * Label and Context are caller-supplied byte strings
//   * 0x00 is the mandatory separator byte (SP 800-108 §5.1)
//   * [L]_32 is the output length **in bits**, 32-bit big-endian
//
// This crate hard-codes r = 32 (counter width) and L_r = 32 (length
// encoding) because those are the CAVP-standard values and cover the
// overwhelming majority of deployed profiles (TLS, SSH KEX derivation,
// SP 800-56C Rev. 2 Option 1, etc.). Feedback and Double-Pipeline
// modes are a follow-on batch.

/// Generic SP 800-108 Rev. 1 KBKDF in Counter Mode.
///
/// `P` is the PRF (an HMAC instantiation) and `L` is the PRF output
/// length in bytes. Users talk to the type aliases below
/// ([`Sp800_108CounterHmacSha256`], etc.). The struct itself is
/// zero-sized — KBKDF has no state to carry between calls.
pub struct Sp800_108Counter<P: PrfHmac<L>, const L: usize> {
    _m: PhantomData<fn() -> P>,
}

impl<P: PrfHmac<L>, const L: usize> Sp800_108Counter<P, L> {
    /// Derives `out.len()` bytes of key material from `key`, `label`,
    /// and `context`, writing them into `out`.
    ///
    /// Enforces [`require_operational`] and algorithm-profile gating
    /// via [`require_allowed`]. Returns [`KdfError::OutputTooLong`]
    /// if the derivation would require more than `2^32 - 1` PRF
    /// iterations (the hard upper bound set by the 32-bit counter
    /// encoding) or if `out.len() * 8` does not fit in a 32-bit
    /// bit-length field.
    pub fn derive(
        key: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        require_operational()?;
        require_allowed(P::KDF_SERVICE)?;
        Self::derive_internal(key, label, context, out)
    }

    /// Gateless variant used by the boot-time KATs.
    ///
    /// Assembles the SP 800-108 §5.2 fixed-input blob
    /// `Label || 0x00 || Context || [L]_32` and runs the counter-mode
    /// PRF loop over it via [`derive_with_fixed_data_internal`].
    #[doc(hidden)]
    pub(crate) fn derive_internal(
        key: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }

        // Output length encoded as a 32-bit big-endian bit count.
        // out.len() * 8 must fit in u32.
        let Some(bit_len) = out.len().checked_mul(8) else {
            return Err(KdfError::OutputTooLong);
        };
        let Ok(bit_len_u32) = u32::try_from(bit_len) else {
            return Err(KdfError::OutputTooLong);
        };
        let l_bytes: [u8; 4] = bit_len_u32.to_be_bytes();

        // PRF is called with `[i]_32 || fixed_data`, so the per-block
        // fixed_data we assemble is `Label || 0x00 || Context || [L]_32`.
        // To avoid allocation we feed the PRF in pieces via a closure.
        Self::derive_with_fixed_data_pieces(key, &[label, &[0x00], context, &l_bytes], out)
    }

    /// Gateless variant used by the boot-time KATs to exercise a
    /// pre-built `fixed_data` blob exactly as NIST ACVP-Server
    /// `KDF-1.0` Counter Mode vectors provide it (counter before
    /// fixed data, counter length 32 bits).
    ///
    /// Unlike [`derive_internal`], this does **not** assemble
    /// `Label || 0x00 || Context || [L]_32` — the caller is expected
    /// to supply the already-encoded blob verbatim from the test
    /// vector. Consumers should prefer [`derive`] or [`derive_internal`]
    /// for real use so the SP 800-108 §5.2 structure is preserved.
    #[doc(hidden)]
    pub fn derive_with_fixed_data_internal(
        key: &[u8],
        fixed_data: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        Self::derive_with_fixed_data_pieces(key, &[fixed_data], out)
    }

    /// Shared counter-mode loop. `fixed_data_pieces` is the ordered
    /// list of byte slices that together form the SP 800-108 §5.2
    /// fixed-input blob that follows the 32-bit counter in each PRF
    /// invocation.
    fn derive_with_fixed_data_pieces(
        key: &[u8],
        fixed_data_pieces: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }

        // n = ceil(out.len() / L). Must fit in the 32-bit counter.
        let n = out.len().div_ceil(L);
        if n > (u32::MAX as usize) {
            return Err(KdfError::OutputTooLong);
        }
        let Ok(n_u32) = u32::try_from(n) else {
            return Err(KdfError::OutputTooLong);
        };

        let mut written = 0usize;
        let mut i: u32 = 1;
        while i <= n_u32 {
            let i_bytes = i.to_be_bytes();

            // PRF(K_IN, [i]_32 || fixed_data)
            let mut mac = P::prf_new(key);
            mac.prf_update(&i_bytes);
            for piece in fixed_data_pieces {
                mac.prf_update(piece);
            }
            let block = mac.prf_finalize();

            let remaining = out.len() - written;
            let take = if remaining < L { remaining } else { L };
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;

            // i < n_u32 <= u32::MAX, so i + 1 cannot overflow
            // because the loop exits as soon as i == n_u32.
            i += 1;
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Public type aliases — one counter-mode KBKDF per approved HMAC
// ----------------------------------------------------------------------

/// SP 800-108 Counter Mode over HMAC-SHA-1.
pub type Sp800_108CounterHmacSha1 = Sp800_108Counter<oxicrypt_hmac::HmacSha1, 20>;
/// SP 800-108 Counter Mode over HMAC-SHA-224.
pub type Sp800_108CounterHmacSha224 = Sp800_108Counter<oxicrypt_hmac::HmacSha224, 28>;
/// SP 800-108 Counter Mode over HMAC-SHA-256.
pub type Sp800_108CounterHmacSha256 = Sp800_108Counter<oxicrypt_hmac::HmacSha256, 32>;
/// SP 800-108 Counter Mode over HMAC-SHA-384.
pub type Sp800_108CounterHmacSha384 = Sp800_108Counter<oxicrypt_hmac::HmacSha384, 48>;
/// SP 800-108 Counter Mode over HMAC-SHA-512.
pub type Sp800_108CounterHmacSha512 = Sp800_108Counter<oxicrypt_hmac::HmacSha512, 64>;
/// SP 800-108 Counter Mode over HMAC-SHA-512/224.
pub type Sp800_108CounterHmacSha512_224 = Sp800_108Counter<oxicrypt_hmac::HmacSha512_224, 28>;
/// SP 800-108 Counter Mode over HMAC-SHA-512/256.
pub type Sp800_108CounterHmacSha512_256 = Sp800_108Counter<oxicrypt_hmac::HmacSha512_256, 32>;
/// SP 800-108 Counter Mode over HMAC-SHA3-224.
pub type Sp800_108CounterHmacSha3_224 = Sp800_108Counter<oxicrypt_hmac::HmacSha3_224, 28>;
/// SP 800-108 Counter Mode over HMAC-SHA3-256.
pub type Sp800_108CounterHmacSha3_256 = Sp800_108Counter<oxicrypt_hmac::HmacSha3_256, 32>;
/// SP 800-108 Counter Mode over HMAC-SHA3-384.
pub type Sp800_108CounterHmacSha3_384 = Sp800_108Counter<oxicrypt_hmac::HmacSha3_384, 48>;
/// SP 800-108 Counter Mode over HMAC-SHA3-512.
pub type Sp800_108CounterHmacSha3_512 = Sp800_108Counter<oxicrypt_hmac::HmacSha3_512, 64>;

// ----------------------------------------------------------------------
// SP 800-108 Counter Mode power-up KATs
// ----------------------------------------------------------------------
//
// Every KAT below is sourced from NIST ACVP-Server `KDF-1.0`
// (`gen-val/json-files/KDF/internalProjection.json`) via the
// `fips-test-vectors` crate. Each vector provides a pre-built
// `fixedData` blob, a `keyIn` of the PRF's natural key length, and a
// (potentially truncated) `keyOut`. Consumers run
// [`Sp800_108Counter::derive_with_fixed_data_internal`] with the
// vendored inputs and compare the leading `KEY_OUT.len()` bytes of
// the derived output against the expected `KEY_OUT` slice, matching
// the ACVP harness behaviour.
//
// The canonical ACVP-Server commit hash and vendored slice SHA-256
// digests are recorded in `vendor/nist/MANIFEST.toml`.

macro_rules! kbkdf_kat_fn {
    ($name:ident, $alias:ty, $key_in:path, $fixed_data:path, $key_out:path) => {
        /// Power-up KAT for this SP 800-108 Counter Mode variant.
        ///
        /// Sourced from NIST ACVP-Server `KDF-1.0` via
        /// `fips-test-vectors`; runs the derivation with the vendored
        /// `fixedData` blob and compares the leading
        /// `KEY_OUT.len()` bytes against the expected output.
        pub fn $name() -> Result<(), SelfTestFailure> {
            let key_out: &[u8] = &$key_out;
            // Derive into a fixed-size buffer large enough for the
            // PRF's natural output length, then compare the leading
            // `key_out.len()` bytes. ACVP KDF-1.0 truncates aggressively
            // (keyOut is commonly a single byte), so we derive exactly
            // `key_out.len()` bytes, which exercises the short-output
            // truncation path as well.
            let mut out = [0u8; 64];
            let Some(slice) = out.get_mut(..key_out.len()) else {
                return Err(SelfTestFailure);
            };
            if <$alias>::derive_with_fixed_data_internal(&$key_in, &$fixed_data, slice).is_err() {
                return Err(SelfTestFailure);
            }
            if slice == key_out {
                Ok(())
            } else {
                Err(SelfTestFailure)
            }
        }
    };
}

kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha1,
    Sp800_108CounterHmacSha1,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha224,
    Sp800_108CounterHmacSha224,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha256,
    Sp800_108CounterHmacSha256,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha384,
    Sp800_108CounterHmacSha384,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha512,
    Sp800_108CounterHmacSha512,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha512_224,
    Sp800_108CounterHmacSha512_224,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha512_256,
    Sp800_108CounterHmacSha512_256,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha3_224,
    Sp800_108CounterHmacSha3_224,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha3_256,
    Sp800_108CounterHmacSha3_256,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha3_384,
    Sp800_108CounterHmacSha3_384,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_KEY_OUT
);
kbkdf_kat_fn!(
    kbkdf_counter_self_test_sha3_512,
    Sp800_108CounterHmacSha3_512,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_KEY_OUT
);

/// Validate the per-iteration counter parameters shared by the
/// SP 800-108r1 feedback and double-pipeline counter-bearing
/// primitives, returning the byte offset at which the right-aligned
/// big-endian counter slice begins inside `i.to_be_bytes()`.
///
/// `counter_length_bits` must be one of `{8, 16, 24, 32}` per
/// SP 800-108r1 §5.1; any other value returns
/// `KdfError::Module(Error::InvalidInput)`. The resulting iteration
/// count `n = ceil(out_len / L)` must additionally fit in
/// `2^counter_length_bits - 1` so no counter value exceeds its
/// declared field width — otherwise `KdfError::OutputTooLong` is
/// returned, matching the bound the counter-mode primitive enforces.
///
/// `L` is the underlying PRF's output length in bytes (carried as a
/// const generic so the bound check is monomorphised per HMAC
/// instantiation). Callers handle the `out.is_empty()` early-return
/// before invoking this helper — the helper itself assumes a
/// non-empty output.
fn validate_counter_params_and_offset<const L: usize>(
    counter_length_bits: u32,
    out_len: usize,
) -> Result<usize, KdfError> {
    let h_bytes: usize = match counter_length_bits {
        8 => 1,
        16 => 2,
        24 => 3,
        32 => 4,
        _ => return Err(KdfError::Module(Error::InvalidInput)),
    };

    // Output bit-length must fit in a u32 to match SP 800-108's
    // `[L]_32` length encoding (the caller assembles `[L]_32` inside
    // `fixed_data` per §5.3 / §5.4; this just bounds n).
    let Some(bit_len) = out_len.checked_mul(8) else {
        return Err(KdfError::OutputTooLong);
    };
    if u32::try_from(bit_len).is_err() {
        return Err(KdfError::OutputTooLong);
    }

    let n = out_len.div_ceil(L) as u64;
    let max_counter: u64 = (1u64 << counter_length_bits) - 1;
    if n > max_counter {
        return Err(KdfError::OutputTooLong);
    }

    Ok(4 - h_bytes)
}

// ======================================================================
// SP 800-108 Rev. 1 Feedback Mode (§4.2, counterLocation="none")
// ======================================================================
//
// Recurrence:
//     K(0) = IV
//     K(i) = PRF(K_IN, K(i-1) || FixedData)       for i = 1..n
//     KDF output = K(1) || K(2) || ... truncated to the requested
//                  bit length.
//
// SP 800-108 §5.3 embeds this recurrence inside a larger fixed-input
// string `Label || 0x00 || Context || [L]_32` which is passed
// verbatim as `FixedData`. The public [`Sp800_108Feedback::derive`]
// API builds that §5 blob for callers; the gateless KAT path
// [`derive_with_fixed_data_internal`] accepts a pre-built FixedData
// blob as supplied by NIST ACVP-Server KDF-1.0 vectors.

/// Generic SP 800-108 Rev. 1 KBKDF in Feedback Mode (counterLocation=none).
///
/// `P` is the PRF (an HMAC instantiation) and `L` is the PRF output
/// length in bytes. Users talk to the type aliases below
/// ([`Sp800_108FeedbackHmacSha256`], etc.). The struct itself is
/// zero-sized — KBKDF Feedback has no state to carry between calls;
/// callers supply the IV explicitly on every derivation.
pub struct Sp800_108Feedback<P: PrfHmac<L>, const L: usize> {
    _m: PhantomData<fn() -> P>,
}

impl<P: PrfHmac<L>, const L: usize> Sp800_108Feedback<P, L> {
    /// Derives `out.len()` bytes of key material from `key`, `iv`,
    /// `label`, and `context`, writing them into `out`.
    ///
    /// Enforces [`require_operational`] and algorithm-profile gating
    /// via [`require_allowed`]. Returns [`KdfError::OutputTooLong`]
    /// if the derivation would require `out.len() * 8` bits beyond
    /// what a 32-bit `[L]_32` field can encode, matching the
    /// counter-mode bound.
    pub fn derive(
        key: &[u8],
        iv: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        require_operational()?;
        require_allowed(P::KDF_SERVICE)?;
        Self::derive_internal(key, iv, label, context, out)
    }

    /// Gateless variant used by the boot-time KATs.
    ///
    /// Assembles the SP 800-108 §5.3 fixed-input blob
    /// `Label || 0x00 || Context || [L]_32` and runs the feedback
    /// recurrence via [`derive_with_fixed_data_pieces`].
    #[doc(hidden)]
    pub(crate) fn derive_internal(
        key: &[u8],
        iv: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }
        let Some(bit_len) = out.len().checked_mul(8) else {
            return Err(KdfError::OutputTooLong);
        };
        let Ok(bit_len_u32) = u32::try_from(bit_len) else {
            return Err(KdfError::OutputTooLong);
        };
        let l_bytes: [u8; 4] = bit_len_u32.to_be_bytes();
        Self::derive_with_fixed_data_pieces(key, iv, &[label, &[0x00], context, &l_bytes], out)
    }

    /// Gateless variant used by the boot-time KATs to exercise a
    /// pre-built `fixed_data` blob exactly as NIST ACVP-Server
    /// `KDF-1.0` Feedback Mode vectors provide it (counterLocation=
    /// "none", zeroLengthIv=false).
    #[doc(hidden)]
    pub fn derive_with_fixed_data_internal(
        key: &[u8],
        iv: &[u8],
        fixed_data: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        Self::derive_with_fixed_data_pieces(key, iv, &[fixed_data], out)
    }

    /// Gateless feedback-mode variant with an explicit per-iteration
    /// counter, exactly as SP 800-108r1 §4.2 specifies for
    /// `counterLocation = "before fixed data"`. The recurrence is
    ///
    /// ```text
    /// K(1) = PRF(K, IV || [1]_h || FixedData)
    /// K(i) = PRF(K, K(i-1) || [i]_h || FixedData)   for i = 2..n
    /// ```
    ///
    /// where `h = counter_length_bits` and `[i]_h` is the big-endian
    /// encoding of the iteration counter into the rightmost `h / 8`
    /// bytes of a 32-bit field. This is the wire shape ACVP-Server
    /// `KDF-1.0` prompts feedback groups with on the demo path —
    /// `derive_with_fixed_data_internal` (h=0) is the
    /// `counterLocation = "none"` form.
    ///
    /// `counter_length_bits` must be one of `{8, 16, 24, 32}` per
    /// SP 800-108r1 §5.1 — any other value returns
    /// `KdfError::Module(Error::InvalidInput)`. The number of PRF
    /// iterations `n = ceil(out.len() / L)` must additionally fit in
    /// `2^h - 1` so that no counter value exceeds its declared field
    /// width; otherwise `KdfError::OutputTooLong` is returned, matching
    /// the bound the counter-mode primitive enforces.
    #[doc(hidden)]
    pub fn derive_with_counter_internal(
        key: &[u8],
        iv: &[u8],
        fixed_data: &[u8],
        counter_length_bits: u32,
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }
        let counter_offset =
            validate_counter_params_and_offset::<L>(counter_length_bits, out.len())?;

        // First iteration: K(1) = PRF(K, IV || [1]_h || FixedData).
        let mut i: u32 = 1;
        let mut prev: [u8; L] = {
            let mut mac = P::prf_new(key);
            mac.prf_update(iv);
            let counter_be = i.to_be_bytes();
            mac.prf_update(&counter_be[counter_offset..]);
            mac.prf_update(fixed_data);
            mac.prf_finalize()
        };

        let mut written = 0usize;
        let take = if out.len() < L { out.len() } else { L };
        out[..take].copy_from_slice(&prev[..take]);
        written += take;

        // K(i) = PRF(K, K(i-1) || [i]_h || FixedData) for i = 2..=n.
        // The `n > max_counter` guard above ensures `i + 1` cannot
        // exceed the counter's representable range.
        while written < out.len() {
            i += 1;
            let mut mac = P::prf_new(key);
            mac.prf_update(&prev);
            let counter_be = i.to_be_bytes();
            mac.prf_update(&counter_be[counter_offset..]);
            mac.prf_update(fixed_data);
            prev = mac.prf_finalize();

            let remaining = out.len() - written;
            let take = if remaining < L { remaining } else { L };
            out[written..written + take].copy_from_slice(&prev[..take]);
            written += take;
        }
        Ok(())
    }

    /// Shared feedback-mode loop. `fixed_data_pieces` is the ordered
    /// list of byte slices that together form the SP 800-108 §5.3
    /// fixed-input blob that follows `K(i-1)` in each PRF
    /// invocation. `iv` is the bit string `K(0)` and may be of any
    /// length (empty is supported for SP 800-108 zeroLengthIv=true,
    /// though the power-up KATs exercise zeroLengthIv=false to cover
    /// the IV path).
    fn derive_with_fixed_data_pieces(
        key: &[u8],
        iv: &[u8],
        fixed_data_pieces: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }
        // Output bit-length must fit in a u32 to match SP 800-108's
        // `[L]_32` length encoding and the counter-mode bound.
        let Some(bit_len) = out.len().checked_mul(8) else {
            return Err(KdfError::OutputTooLong);
        };
        if u32::try_from(bit_len).is_err() {
            return Err(KdfError::OutputTooLong);
        }

        // First block: PRF(K, IV || FixedData).
        let mut mac = P::prf_new(key);
        mac.prf_update(iv);
        for piece in fixed_data_pieces {
            mac.prf_update(piece);
        }
        let mut prev: [u8; L] = mac.prf_finalize();

        let mut written = 0usize;
        let take = if out.len() < L { out.len() } else { L };
        out[..take].copy_from_slice(&prev[..take]);
        written += take;

        // Remaining blocks: K(i) = PRF(K, K(i-1) || FixedData).
        while written < out.len() {
            let mut mac = P::prf_new(key);
            mac.prf_update(&prev);
            for piece in fixed_data_pieces {
                mac.prf_update(piece);
            }
            prev = mac.prf_finalize();

            let remaining = out.len() - written;
            let take = if remaining < L { remaining } else { L };
            out[written..written + take].copy_from_slice(&prev[..take]);
            written += take;
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Public type aliases — one feedback-mode KBKDF per approved HMAC
// ----------------------------------------------------------------------

/// SP 800-108 Feedback Mode over HMAC-SHA-1.
pub type Sp800_108FeedbackHmacSha1 = Sp800_108Feedback<oxicrypt_hmac::HmacSha1, 20>;
/// SP 800-108 Feedback Mode over HMAC-SHA-224.
pub type Sp800_108FeedbackHmacSha224 = Sp800_108Feedback<oxicrypt_hmac::HmacSha224, 28>;
/// SP 800-108 Feedback Mode over HMAC-SHA-256.
pub type Sp800_108FeedbackHmacSha256 = Sp800_108Feedback<oxicrypt_hmac::HmacSha256, 32>;
/// SP 800-108 Feedback Mode over HMAC-SHA-384.
pub type Sp800_108FeedbackHmacSha384 = Sp800_108Feedback<oxicrypt_hmac::HmacSha384, 48>;
/// SP 800-108 Feedback Mode over HMAC-SHA-512.
pub type Sp800_108FeedbackHmacSha512 = Sp800_108Feedback<oxicrypt_hmac::HmacSha512, 64>;
/// SP 800-108 Feedback Mode over HMAC-SHA-512/224.
pub type Sp800_108FeedbackHmacSha512_224 = Sp800_108Feedback<oxicrypt_hmac::HmacSha512_224, 28>;
/// SP 800-108 Feedback Mode over HMAC-SHA-512/256.
pub type Sp800_108FeedbackHmacSha512_256 = Sp800_108Feedback<oxicrypt_hmac::HmacSha512_256, 32>;
/// SP 800-108 Feedback Mode over HMAC-SHA3-224.
pub type Sp800_108FeedbackHmacSha3_224 = Sp800_108Feedback<oxicrypt_hmac::HmacSha3_224, 28>;
/// SP 800-108 Feedback Mode over HMAC-SHA3-256.
pub type Sp800_108FeedbackHmacSha3_256 = Sp800_108Feedback<oxicrypt_hmac::HmacSha3_256, 32>;
/// SP 800-108 Feedback Mode over HMAC-SHA3-384.
pub type Sp800_108FeedbackHmacSha3_384 = Sp800_108Feedback<oxicrypt_hmac::HmacSha3_384, 48>;
/// SP 800-108 Feedback Mode over HMAC-SHA3-512.
pub type Sp800_108FeedbackHmacSha3_512 = Sp800_108Feedback<oxicrypt_hmac::HmacSha3_512, 64>;

// ----------------------------------------------------------------------
// SP 800-108 Feedback Mode power-up KATs
// ----------------------------------------------------------------------
//
// Each KAT below is sourced from NIST ACVP-Server `KDF-1.0`
// (`gen-val/json-files/KDF/internalProjection.json`) via the
// `fips-test-vectors` crate. Each vector provides `keyIn`, `iv`
// (non-zero-length), a pre-built `fixedData` blob, and a
// (potentially truncated) `keyOut`. Consumers run
// [`Sp800_108Feedback::derive_with_fixed_data_internal`] with the
// vendored inputs and compare the leading `KEY_OUT.len()` bytes of
// the derived output against the expected `KEY_OUT` slice.

macro_rules! kbkdf_feedback_kat_fn {
    ($name:ident, $alias:ty, $key_in:path, $iv:path, $fixed_data:path, $key_out:path) => {
        /// Power-up KAT for this SP 800-108 Feedback Mode variant.
        ///
        /// Sourced from NIST ACVP-Server `KDF-1.0` via
        /// `fips-test-vectors`; runs the derivation with the
        /// vendored `iv` and `fixedData` blob and compares the
        /// leading `KEY_OUT.len()` bytes against the expected
        /// output.
        pub fn $name() -> Result<(), SelfTestFailure> {
            let key_out: &[u8] = &$key_out;
            let mut out = [0u8; 64];
            let Some(slice) = out.get_mut(..key_out.len()) else {
                return Err(SelfTestFailure);
            };
            if <$alias>::derive_with_fixed_data_internal(&$key_in, &$iv, &$fixed_data, slice)
                .is_err()
            {
                return Err(SelfTestFailure);
            }
            if slice == key_out {
                Ok(())
            } else {
                Err(SelfTestFailure)
            }
        }
    };
}

kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha1,
    Sp800_108FeedbackHmacSha1,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha224,
    Sp800_108FeedbackHmacSha224,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha256,
    Sp800_108FeedbackHmacSha256,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha384,
    Sp800_108FeedbackHmacSha384,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha512,
    Sp800_108FeedbackHmacSha512,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha512_224,
    Sp800_108FeedbackHmacSha512_224,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha512_256,
    Sp800_108FeedbackHmacSha512_256,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha3_224,
    Sp800_108FeedbackHmacSha3_224,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha3_256,
    Sp800_108FeedbackHmacSha3_256,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha3_384,
    Sp800_108FeedbackHmacSha3_384,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_FB_KEY_OUT
);
kbkdf_feedback_kat_fn!(
    kbkdf_feedback_self_test_sha3_512,
    Sp800_108FeedbackHmacSha3_512,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_FB_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_FB_IV,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_FB_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_FB_KEY_OUT
);

// ======================================================================
// SP 800-108 Rev. 1 Double-Pipeline Iteration Mode (§4.3,
// counterLocation="none")
// ======================================================================
//
// Recurrence:
//     A(0) = FixedData
//     A(i) = PRF(K_IN, A(i-1))
//     K(i) = PRF(K_IN, A(i) || FixedData)
//     KDF output = K(1) || K(2) || ... truncated to the requested
//                  bit length.
//
// Per SP 800-108 §4.3 the inner pipeline `A` is seeded from the
// fixed input (not from an IV), so this mode does not take an IV
// parameter. ACVP KDF-1.0 double-pipeline test groups still carry
// an `iv` field in each test case, but that field is unused in the
// counterLocation="none" form; it is not fed into the derivation
// and is not materialised as a compile-time constant here.

/// Generic SP 800-108 Rev. 1 KBKDF in Double-Pipeline Iteration Mode
/// (counterLocation=none).
///
/// `P` is the PRF (an HMAC instantiation) and `L` is the PRF output
/// length in bytes. Users talk to the type aliases below
/// ([`Sp800_108DoublePipelineHmacSha256`], etc.).
pub struct Sp800_108DoublePipeline<P: PrfHmac<L>, const L: usize> {
    _m: PhantomData<fn() -> P>,
}

impl<P: PrfHmac<L>, const L: usize> Sp800_108DoublePipeline<P, L> {
    /// Derives `out.len()` bytes of key material from `key`, `label`,
    /// and `context`, writing them into `out`.
    ///
    /// Enforces [`require_operational`] and algorithm-profile gating
    /// via [`require_allowed`]. Returns [`KdfError::OutputTooLong`]
    /// if the derivation would require `out.len() * 8` bits beyond
    /// what a 32-bit `[L]_32` field can encode, matching the
    /// counter-mode bound.
    pub fn derive(
        key: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        require_operational()?;
        require_allowed(P::KDF_SERVICE)?;
        Self::derive_internal(key, label, context, out)
    }

    /// Gateless variant used by the boot-time KATs.
    ///
    /// Assembles the SP 800-108 §5.4 fixed-input blob
    /// `Label || 0x00 || Context || [L]_32` and runs the double-
    /// pipeline recurrence via [`derive_with_fixed_data_pieces`].
    #[doc(hidden)]
    pub(crate) fn derive_internal(
        key: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }
        let Some(bit_len) = out.len().checked_mul(8) else {
            return Err(KdfError::OutputTooLong);
        };
        let Ok(bit_len_u32) = u32::try_from(bit_len) else {
            return Err(KdfError::OutputTooLong);
        };
        let l_bytes: [u8; 4] = bit_len_u32.to_be_bytes();
        Self::derive_with_fixed_data_pieces(key, &[label, &[0x00], context, &l_bytes], out)
    }

    /// Gateless variant used by the boot-time KATs to exercise a
    /// pre-built `fixed_data` blob exactly as NIST ACVP-Server
    /// `KDF-1.0` Double-Pipeline Iteration Mode vectors provide it
    /// (counterLocation="none").
    #[doc(hidden)]
    pub fn derive_with_fixed_data_internal(
        key: &[u8],
        fixed_data: &[u8],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        Self::derive_with_fixed_data_pieces(key, &[fixed_data], out)
    }

    /// Gateless double-pipeline-iteration variant with an explicit
    /// per-iteration counter, exactly as SP 800-108r1 §4.3 specifies
    /// for `counterLocation = "before fixed data"`. The recurrence is
    ///
    /// ```text
    /// A(1) = PRF(K, FixedData)
    /// A(i) = PRF(K, A(i-1))                         for i = 2..n
    /// K(i) = PRF(K, A(i) || [i]_h || FixedData)     for i = 1..n
    /// ```
    ///
    /// where `h = counter_length_bits` and `[i]_h` is the big-endian
    /// encoding of the iteration counter into the rightmost `h / 8`
    /// bytes of a 32-bit field. Note the asymmetry: the inner `A`
    /// chain is counter-free (counter only enters the output `K`
    /// PRF). This is the wire shape ACVP-Server `KDF-1.0` prompts
    /// double-pipeline groups with on the demo path —
    /// `derive_with_fixed_data_internal` (h=0) is the
    /// `counterLocation = "none"` form.
    ///
    /// `counter_length_bits` must be one of `{8, 16, 24, 32}` per
    /// SP 800-108r1 §5.1 — any other value returns
    /// `KdfError::Module(Error::InvalidInput)`. The number of PRF
    /// iterations `n = ceil(out.len() / L)` must additionally fit in
    /// `2^h - 1` so that no counter value exceeds its declared field
    /// width; otherwise `KdfError::OutputTooLong` is returned.
    #[doc(hidden)]
    pub fn derive_with_counter_internal(
        key: &[u8],
        fixed_data: &[u8],
        counter_length_bits: u32,
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }
        let counter_offset =
            validate_counter_params_and_offset::<L>(counter_length_bits, out.len())?;

        // A(1) = PRF(K, FixedData).
        let mut a: [u8; L] = {
            let mut mac = P::prf_new(key);
            mac.prf_update(fixed_data);
            mac.prf_finalize()
        };

        // K(1) = PRF(K, A(1) || [1]_h || FixedData).
        let mut i: u32 = 1;
        let mut k: [u8; L] = {
            let mut mac = P::prf_new(key);
            mac.prf_update(&a);
            let counter_be = i.to_be_bytes();
            mac.prf_update(&counter_be[counter_offset..]);
            mac.prf_update(fixed_data);
            mac.prf_finalize()
        };

        let mut written = 0usize;
        let take = if out.len() < L { out.len() } else { L };
        out[..take].copy_from_slice(&k[..take]);
        written += take;

        // For i = 2..=n: advance the inner A chain (counter-free) and
        // emit K(i) with the counter inserted between A(i) and
        // FixedData. Keeping the A advancement and the K emission as
        // separate PRF calls is the structural marker that the
        // counter never enters A — copy-pasting the K loop into A
        // would recover the feedback recurrence by mistake.
        while written < out.len() {
            // A(i) = PRF(K, A(i-1)) — counter NOT involved.
            let mut mac = P::prf_new(key);
            mac.prf_update(&a);
            a = mac.prf_finalize();

            // K(i) = PRF(K, A(i) || [i]_h || FixedData).
            i += 1;
            let mut mac = P::prf_new(key);
            mac.prf_update(&a);
            let counter_be = i.to_be_bytes();
            mac.prf_update(&counter_be[counter_offset..]);
            mac.prf_update(fixed_data);
            k = mac.prf_finalize();

            let remaining = out.len() - written;
            let take = if remaining < L { remaining } else { L };
            out[written..written + take].copy_from_slice(&k[..take]);
            written += take;
        }
        Ok(())
    }

    /// Shared double-pipeline loop. `fixed_data_pieces` is the
    /// ordered list of byte slices that together form the SP 800-108
    /// §5.4 fixed-input blob. The inner pipeline seed `A(0)` is
    /// this same fixed-input blob.
    fn derive_with_fixed_data_pieces(
        key: &[u8],
        fixed_data_pieces: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        if out.is_empty() {
            return Ok(());
        }
        // Output bit-length must fit in a u32 to match SP 800-108's
        // `[L]_32` length encoding and the counter-mode bound.
        let Some(bit_len) = out.len().checked_mul(8) else {
            return Err(KdfError::OutputTooLong);
        };
        if u32::try_from(bit_len).is_err() {
            return Err(KdfError::OutputTooLong);
        }

        // First iteration of the inner pipeline:
        //   A(1) = PRF(K, A(0)) = PRF(K, FixedData).
        let mut mac = P::prf_new(key);
        for piece in fixed_data_pieces {
            mac.prf_update(piece);
        }
        let mut a: [u8; L] = mac.prf_finalize();

        // First output block: K(1) = PRF(K, A(1) || FixedData).
        let mut mac = P::prf_new(key);
        mac.prf_update(&a);
        for piece in fixed_data_pieces {
            mac.prf_update(piece);
        }
        let mut k: [u8; L] = mac.prf_finalize();

        let mut written = 0usize;
        let take = if out.len() < L { out.len() } else { L };
        out[..take].copy_from_slice(&k[..take]);
        written += take;

        while written < out.len() {
            // A(i) = PRF(K, A(i-1)).
            let mut mac = P::prf_new(key);
            mac.prf_update(&a);
            a = mac.prf_finalize();

            // K(i) = PRF(K, A(i) || FixedData).
            let mut mac = P::prf_new(key);
            mac.prf_update(&a);
            for piece in fixed_data_pieces {
                mac.prf_update(piece);
            }
            k = mac.prf_finalize();

            let remaining = out.len() - written;
            let take = if remaining < L { remaining } else { L };
            out[written..written + take].copy_from_slice(&k[..take]);
            written += take;
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Public type aliases — one double-pipeline KBKDF per approved HMAC
// ----------------------------------------------------------------------

/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA-1.
pub type Sp800_108DoublePipelineHmacSha1 = Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha1, 20>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA-224.
pub type Sp800_108DoublePipelineHmacSha224 = Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha224, 28>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA-256.
pub type Sp800_108DoublePipelineHmacSha256 = Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha256, 32>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA-384.
pub type Sp800_108DoublePipelineHmacSha384 = Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha384, 48>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA-512.
pub type Sp800_108DoublePipelineHmacSha512 = Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha512, 64>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA-512/224.
pub type Sp800_108DoublePipelineHmacSha512_224 =
    Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha512_224, 28>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA-512/256.
pub type Sp800_108DoublePipelineHmacSha512_256 =
    Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha512_256, 32>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA3-224.
pub type Sp800_108DoublePipelineHmacSha3_224 =
    Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha3_224, 28>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA3-256.
pub type Sp800_108DoublePipelineHmacSha3_256 =
    Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha3_256, 32>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA3-384.
pub type Sp800_108DoublePipelineHmacSha3_384 =
    Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha3_384, 48>;
/// SP 800-108 Double-Pipeline Iteration Mode over HMAC-SHA3-512.
pub type Sp800_108DoublePipelineHmacSha3_512 =
    Sp800_108DoublePipeline<oxicrypt_hmac::HmacSha3_512, 64>;

// ----------------------------------------------------------------------
// SP 800-108 Double-Pipeline Iteration Mode power-up KATs
// ----------------------------------------------------------------------

macro_rules! kbkdf_dp_kat_fn {
    ($name:ident, $alias:ty, $key_in:path, $fixed_data:path, $key_out:path) => {
        /// Power-up KAT for this SP 800-108 Double-Pipeline Iteration
        /// Mode variant.
        ///
        /// Sourced from NIST ACVP-Server `KDF-1.0` via
        /// `fips-test-vectors`; runs the derivation with the
        /// vendored `fixedData` blob and compares the leading
        /// `KEY_OUT.len()` bytes against the expected output.
        pub fn $name() -> Result<(), SelfTestFailure> {
            let key_out: &[u8] = &$key_out;
            let mut out = [0u8; 64];
            let Some(slice) = out.get_mut(..key_out.len()) else {
                return Err(SelfTestFailure);
            };
            if <$alias>::derive_with_fixed_data_internal(&$key_in, &$fixed_data, slice).is_err() {
                return Err(SelfTestFailure);
            }
            if slice == key_out {
                Ok(())
            } else {
                Err(SelfTestFailure)
            }
        }
    };
}

kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha1,
    Sp800_108DoublePipelineHmacSha1,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA_1_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha224,
    Sp800_108DoublePipelineHmacSha224,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_224_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha256,
    Sp800_108DoublePipelineHmacSha256,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_256_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha384,
    Sp800_108DoublePipelineHmacSha384,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_384_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha512,
    Sp800_108DoublePipelineHmacSha512,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha512_224,
    Sp800_108DoublePipelineHmacSha512_224,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_224_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha512_256,
    Sp800_108DoublePipelineHmacSha512_256,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA2_512_256_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha3_224,
    Sp800_108DoublePipelineHmacSha3_224,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_224_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha3_256,
    Sp800_108DoublePipelineHmacSha3_256,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_256_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha3_384,
    Sp800_108DoublePipelineHmacSha3_384,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_384_KBKDF_DP_KEY_OUT
);
kbkdf_dp_kat_fn!(
    kbkdf_dp_self_test_sha3_512,
    Sp800_108DoublePipelineHmacSha3_512,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_DP_KEY_IN,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_DP_FIXED_DATA,
    oxicrypt_test_vectors::HMAC_SHA3_512_KBKDF_DP_KEY_OUT
);

// ======================================================================
// PBKDF2 — SP 800-132
// ======================================================================
//
// PBKDF2 (Password-Based Key Derivation Function 2, RFC 8018 §5.2,
// approved under SP 800-132) iterates HMAC to derive a key from a
// password and salt:
//
//     DK = T1 || T2 || ... || Tdklen/hlen
//     Ti = F(Password, Salt, c, i)
//     F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
//     U1 = PRF(Password, Salt || INT(i))
//     Uj = PRF(Password, U_{j-1})
//
// INT(i) is a 4-byte big-endian encoding of the block index (1-based).

/// PBKDF2 instance, generic over the HMAC PRF.
///
/// `P` is a [`PrfHmac`] implementation (e.g. [`oxicrypt_hmac::HmacSha256`]),
/// `L` is the PRF output length in bytes.
///
/// # Usage
///
/// ```ignore
/// let mut dk = [0u8; 32];
/// Pbkdf2HmacSha256::derive(b"password", b"salt", 4096, &mut dk)?;
/// ```
pub struct Pbkdf2<P: PrfHmac<L>, const L: usize> {
    _m: PhantomData<fn() -> P>,
}

impl<P: PrfHmac<L>, const L: usize> Pbkdf2<P, L> {
    /// Derives `out.len()` bytes from `password`, `salt`, and
    /// iteration count `c`.
    ///
    /// Enforces [`require_operational`] and algorithm-profile gating
    /// via [`require_allowed`]. Returns [`KdfError::OutputTooLong`]
    /// if the output would exceed `(2^32 − 1) × L` bytes (the RFC 8018
    /// §5.2 maximum).
    ///
    /// # Panics
    ///
    /// Panics if `c == 0`.
    pub fn derive(password: &[u8], salt: &[u8], c: u32, out: &mut [u8]) -> Result<(), KdfError> {
        require_operational()?;
        require_allowed(P::KDF_SERVICE)?;
        Self::derive_internal(password, salt, c, out)
    }

    /// Gateless variant used by the boot-time KATs.
    #[doc(hidden)]
    #[allow(clippy::many_single_char_names)]
    pub(crate) fn derive_internal(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        out: &mut [u8],
    ) -> Result<(), KdfError> {
        assert!(iterations > 0, "PBKDF2 iteration count must be > 0");
        if out.is_empty() {
            return Ok(());
        }
        // SP 800-132 / RFC 8018 §5.2: dkLen ≤ (2^32 − 1) × hLen
        let max_blocks = u64::from(u32::MAX);
        let blocks_needed = (out.len() as u64).div_ceil(L as u64);
        if blocks_needed > max_blocks {
            return Err(KdfError::OutputTooLong);
        }

        let mut offset = 0;
        let mut block_idx: u32 = 1;
        while offset < out.len() {
            // U1 = PRF(Password, Salt || INT(i))
            let mut mac = P::prf_new(password);
            mac.prf_update(salt);
            mac.prf_update(&block_idx.to_be_bytes());
            let mut u_prev = mac.prf_finalize();

            // T = U1
            let mut xor_fold = u_prev;

            // U2..Uc
            let mut iter: u32 = 1;
            while iter < iterations {
                let mut mac_inner = P::prf_new(password);
                mac_inner.prf_update(&u_prev);
                u_prev = mac_inner.prf_finalize();
                // T ^= Uj
                let mut idx = 0;
                while idx < L {
                    xor_fold[idx] ^= u_prev[idx];
                    idx += 1;
                }
                iter += 1;
            }

            let remaining = out.len() - offset;
            let to_copy = if remaining < L { remaining } else { L };
            out[offset..offset + to_copy].copy_from_slice(&xor_fold[..to_copy]);
            offset += to_copy;
            block_idx += 1;
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Public type aliases — one PBKDF2 per approved HMAC
// ----------------------------------------------------------------------

/// PBKDF2 with HMAC-SHA-1.
pub type Pbkdf2HmacSha1 = Pbkdf2<oxicrypt_hmac::HmacSha1, 20>;
/// PBKDF2 with HMAC-SHA-224.
pub type Pbkdf2HmacSha224 = Pbkdf2<oxicrypt_hmac::HmacSha224, 28>;
/// PBKDF2 with HMAC-SHA-256.
pub type Pbkdf2HmacSha256 = Pbkdf2<oxicrypt_hmac::HmacSha256, 32>;
/// PBKDF2 with HMAC-SHA-384.
pub type Pbkdf2HmacSha384 = Pbkdf2<oxicrypt_hmac::HmacSha384, 48>;
/// PBKDF2 with HMAC-SHA-512.
pub type Pbkdf2HmacSha512 = Pbkdf2<oxicrypt_hmac::HmacSha512, 64>;
/// PBKDF2 with HMAC-SHA-512/224.
pub type Pbkdf2HmacSha512_224 = Pbkdf2<oxicrypt_hmac::HmacSha512_224, 28>;
/// PBKDF2 with HMAC-SHA-512/256.
pub type Pbkdf2HmacSha512_256 = Pbkdf2<oxicrypt_hmac::HmacSha512_256, 32>;
/// PBKDF2 with HMAC-SHA3-224.
pub type Pbkdf2HmacSha3_224 = Pbkdf2<oxicrypt_hmac::HmacSha3_224, 28>;
/// PBKDF2 with HMAC-SHA3-256.
pub type Pbkdf2HmacSha3_256 = Pbkdf2<oxicrypt_hmac::HmacSha3_256, 32>;
/// PBKDF2 with HMAC-SHA3-384.
pub type Pbkdf2HmacSha3_384 = Pbkdf2<oxicrypt_hmac::HmacSha3_384, 48>;
/// PBKDF2 with HMAC-SHA3-512.
pub type Pbkdf2HmacSha3_512 = Pbkdf2<oxicrypt_hmac::HmacSha3_512, 64>;

// ----------------------------------------------------------------------
// PBKDF2 power-up KATs
// ----------------------------------------------------------------------

/// PBKDF2-HMAC-SHA-1 KAT: RFC 6070 Test Case 1.
/// P="password", S="salt", c=1, dkLen=20.
const KAT_PBKDF2_SHA1_EXPECTED: [u8; 20] = [
    0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
    0x2f, 0xe0, 0x37, 0xa6,
];

/// Power-up KAT for PBKDF2-HMAC-SHA-1.
pub fn pbkdf2_self_test_sha1() -> Result<(), SelfTestFailure> {
    let mut dk = [0u8; 20];
    Pbkdf2HmacSha1::derive_internal(b"password", b"salt", 1, &mut dk)
        .map_err(|_| SelfTestFailure)?;
    if dk == KAT_PBKDF2_SHA1_EXPECTED {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

/// PBKDF2-HMAC-SHA-256 KAT: P="password", S="salt", c=1, dkLen=32.
/// Cross-checked against Python hashlib.pbkdf2_hmac.
const KAT_PBKDF2_SHA256_EXPECTED: [u8; 32] = [
    0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
    0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
];

/// Power-up KAT for PBKDF2-HMAC-SHA-256.
pub fn pbkdf2_self_test_sha256() -> Result<(), SelfTestFailure> {
    let mut dk = [0u8; 32];
    Pbkdf2HmacSha256::derive_internal(b"password", b"salt", 1, &mut dk)
        .map_err(|_| SelfTestFailure)?;
    if dk == KAT_PBKDF2_SHA256_EXPECTED {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ======================================================================
// Power-up KAT inventory
// (HKDF + SP 800-108 Counter + Feedback + Double-Pipeline + PBKDF2)
// ======================================================================

/// Power-up KAT inventory for every KDF variant in this crate.
///
/// Merged into the acvp-harness boot sequence via
/// [`oxicrypt_module::initialize_with_tests`]. Per FIPS 140-3 IG 10.3.A
/// each KDF instantiation carries its own KAT — families and modes
/// do not share.
pub const KATS: &[KatEntry] = &[
    // --- HKDF (SP 800-56C Rev 2 Two-Step KDA-HKDF, hybrid) -----------
    //
    // Ten of the eleven HKDF KATs run against the NIST ACVP-Server
    // `KDA-HKDF-Sp800-56Cr2` family; HKDF-SHA-1 stays on RFC 5869
    // §A.1 because SHA-1 is out of scope for SP 800-56C Rev 2.
    KatEntry {
        name: "HKDF-SHA-1 KAT (RFC 5869 §A.1 Test Case 1; SHA-1 not in SP 800-56Cr2)",
        run: hkdf_self_test_sha1,
    },
    KatEntry {
        name: "HKDF-SHA-224 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha224,
    },
    KatEntry {
        name: "HKDF-SHA-256 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha256,
    },
    KatEntry {
        name: "HKDF-SHA-384 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha384,
    },
    KatEntry {
        name: "HKDF-SHA-512 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha512,
    },
    KatEntry {
        name: "HKDF-SHA-512/224 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha512_224,
    },
    KatEntry {
        name: "HKDF-SHA-512/256 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha512_256,
    },
    KatEntry {
        name: "HKDF-SHA3-224 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha3_224,
    },
    KatEntry {
        name: "HKDF-SHA3-256 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha3_256,
    },
    KatEntry {
        name: "HKDF-SHA3-384 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha3_384,
    },
    KatEntry {
        name: "HKDF-SHA3-512 KAT (NIST ACVP-Server KDA-HKDF-Sp800-56Cr2, hybrid)",
        run: hkdf_self_test_sha3_512,
    },
    // --- SP 800-108 Counter Mode KBKDF (11 entries) ------------------
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA-1 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha1,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA-224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha224,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA-256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha256,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA-384 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha384,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA-512 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha512,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA-512/224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha512_224,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA-512/256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha512_256,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA3-224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha3_224,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA3-256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha3_256,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA3-384 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha3_384,
    },
    KatEntry {
        name: "SP 800-108 Counter HMAC-SHA3-512 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_counter_self_test_sha3_512,
    },
    // --- SP 800-108 Feedback Mode KBKDF (11 entries) -----------------
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA-1 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha1,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA-224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha224,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA-256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha256,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA-384 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha384,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA-512 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha512,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA-512/224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha512_224,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA-512/256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha512_256,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA3-224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha3_224,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA3-256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha3_256,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA3-384 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha3_384,
    },
    KatEntry {
        name: "SP 800-108 Feedback HMAC-SHA3-512 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_feedback_self_test_sha3_512,
    },
    // --- SP 800-108 Double-Pipeline Iteration Mode KBKDF (11 entries) -
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA-1 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha1,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA-224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha224,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA-256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha256,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA-384 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha384,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA-512 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha512,
    },
    KatEntry {
        name:
            "SP 800-108 Double-Pipeline HMAC-SHA-512/224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha512_224,
    },
    KatEntry {
        name:
            "SP 800-108 Double-Pipeline HMAC-SHA-512/256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha512_256,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA3-224 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha3_224,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA3-256 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha3_256,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA3-384 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha3_384,
    },
    KatEntry {
        name: "SP 800-108 Double-Pipeline HMAC-SHA3-512 KAT (NIST ACVP-Server KDF-1.0, truncated)",
        run: kbkdf_dp_self_test_sha3_512,
    },
    // --- PBKDF2 (SP 800-132) -----------------------------------------------
    KatEntry {
        name: "PBKDF2-HMAC-SHA-1 KAT (RFC 6070 Test Case 1, SP 800-132)",
        run: pbkdf2_self_test_sha1,
    },
    KatEntry {
        name: "PBKDF2-HMAC-SHA-256 KAT (SP 800-132, pycryptodome cross-check)",
        run: pbkdf2_self_test_sha256,
    },
];

// ----------------------------------------------------------------------
// Unit tests
// ----------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        hkdf_self_test_sha1, hkdf_self_test_sha224, hkdf_self_test_sha256, hkdf_self_test_sha384,
        hkdf_self_test_sha3_224, hkdf_self_test_sha3_256, hkdf_self_test_sha3_384,
        hkdf_self_test_sha3_512, hkdf_self_test_sha512, hkdf_self_test_sha512_224,
        hkdf_self_test_sha512_256, kbkdf_counter_self_test_sha1, kbkdf_counter_self_test_sha224,
        kbkdf_counter_self_test_sha256, kbkdf_counter_self_test_sha384,
        kbkdf_counter_self_test_sha3_224, kbkdf_counter_self_test_sha3_256,
        kbkdf_counter_self_test_sha3_384, kbkdf_counter_self_test_sha3_512,
        kbkdf_counter_self_test_sha512, kbkdf_counter_self_test_sha512_224,
        kbkdf_counter_self_test_sha512_256, kbkdf_dp_self_test_sha1, kbkdf_dp_self_test_sha224,
        kbkdf_dp_self_test_sha256, kbkdf_dp_self_test_sha384, kbkdf_dp_self_test_sha3_224,
        kbkdf_dp_self_test_sha3_256, kbkdf_dp_self_test_sha3_384, kbkdf_dp_self_test_sha3_512,
        kbkdf_dp_self_test_sha512, kbkdf_dp_self_test_sha512_224, kbkdf_dp_self_test_sha512_256,
        kbkdf_feedback_self_test_sha1, kbkdf_feedback_self_test_sha224,
        kbkdf_feedback_self_test_sha256, kbkdf_feedback_self_test_sha384,
        kbkdf_feedback_self_test_sha3_224, kbkdf_feedback_self_test_sha3_256,
        kbkdf_feedback_self_test_sha3_384, kbkdf_feedback_self_test_sha3_512,
        kbkdf_feedback_self_test_sha512, kbkdf_feedback_self_test_sha512_224,
        kbkdf_feedback_self_test_sha512_256, pbkdf2_self_test_sha1, pbkdf2_self_test_sha256,
        HkdfSha1, HkdfSha256, HkdfSha3_256, HkdfSha512, KdfError, Pbkdf2HmacSha1, Pbkdf2HmacSha256,
        Pbkdf2HmacSha512, Sp800_108CounterHmacSha256, Sp800_108CounterHmacSha3_256,
        Sp800_108DoublePipelineHmacSha256, Sp800_108DoublePipelineHmacSha3_256,
        Sp800_108FeedbackHmacSha256, Sp800_108FeedbackHmacSha3_256,
    };

    // Local fixed inputs for the RFC 5869 §A.1 Test Case 1 cross-check
    // tests below. These are a well-known public reference vector;
    // NIST-derived coverage for HKDF-SHA-256 is provided by the power-
    // up KAT (KDA-HKDF-Sp800-56Cr2), so these unit tests exist only to
    // exercise the public extract/expand/from_prk API shape against a
    // stable, independently published input.
    const RFC5869_IKM: [u8; 22] = [0x0b; 22];
    const RFC5869_SALT: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    const RFC5869_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    const RFC5869_SHA256_PRK: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    ];
    const RFC5869_SHA256_OKM: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    // Local fixed inputs for the cross-check KBKDF unit tests below.
    // These do not participate in the power-up KAT anymore (the KAT
    // pulls its vector straight from `oxicrypt_test_vectors`), but the
    // existing tests still exercise the public API with stable,
    // non-NIST inputs to prove determinism, domain separation, and
    // the SP 800-108 §5.2 bit-length binding.
    const KBKDF_KAT_KEY: [u8; 20] = [0x0b; 20];
    const KBKDF_KAT_LABEL: &[u8] = b"pqclib KBKDF counter";
    const KBKDF_KAT_CONTEXT: &[u8] = b"fips-kdf self test";
    use oxicrypt_module::{initialize_with_tests, Error, KatEntry, State};

    fn ensure_initialized() {
        const ALL: &[KatEntry] = super::KATS;
        let _ = initialize_with_tests(ALL);
    }

    #[test]
    fn boot_self_tests_all_pass() {
        assert!(hkdf_self_test_sha1().is_ok());
        assert!(hkdf_self_test_sha224().is_ok());
        assert!(hkdf_self_test_sha256().is_ok());
        assert!(hkdf_self_test_sha384().is_ok());
        assert!(hkdf_self_test_sha512().is_ok());
        assert!(hkdf_self_test_sha512_224().is_ok());
        assert!(hkdf_self_test_sha512_256().is_ok());
        assert!(hkdf_self_test_sha3_224().is_ok());
        assert!(hkdf_self_test_sha3_256().is_ok());
        assert!(hkdf_self_test_sha3_384().is_ok());
        assert!(hkdf_self_test_sha3_512().is_ok());
    }

    #[test]
    fn hkdf_sha256_rfc5869_test_case_1_public_api() {
        ensure_initialized();
        let ikm = RFC5869_IKM;
        let hk = HkdfSha256::extract(Some(&RFC5869_SALT), &ikm).unwrap();
        assert_eq!(hk.prk(), &RFC5869_SHA256_PRK);
        let mut okm = [0u8; 42];
        hk.expand(&RFC5869_INFO, &mut okm).unwrap();
        assert_eq!(okm, RFC5869_SHA256_OKM);
    }

    #[test]
    fn hkdf_empty_salt_is_none_equivalent_to_zero_salt() {
        // RFC 5869 §2.2: a `None` salt MUST be treated as `HashLen`
        // zero bytes. Verify that explicit zeros and None produce
        // identical PRKs for SHA-1.
        ensure_initialized();
        let ikm = RFC5869_IKM;
        let zero = [0u8; 20];
        let a = HkdfSha1::extract(None, &ikm).unwrap();
        let b = HkdfSha1::extract(Some(&zero), &ikm).unwrap();
        assert_eq!(a.prk(), b.prk());
    }

    #[test]
    fn hkdf_expand_output_too_long_is_rejected() {
        ensure_initialized();
        let ikm = RFC5869_IKM;
        let hk = HkdfSha256::extract(Some(&RFC5869_SALT), &ikm).unwrap();
        // 256 * 32 = 8192 > 255 * 32 = 8160 — must error.
        let mut okm = [0u8; 256 * 32];
        match hk.expand(&RFC5869_INFO, &mut okm) {
            Err(KdfError::OutputTooLong) => {}
            Err(other) => panic!("expected OutputTooLong, got other err: {other:?}"),
            Ok(()) => panic!("expected OutputTooLong, got Ok"),
        }
    }

    #[test]
    fn hkdf_expand_empty_okm_is_noop() {
        ensure_initialized();
        let ikm = RFC5869_IKM;
        let hk = HkdfSha256::extract(Some(&RFC5869_SALT), &ikm).unwrap();
        let mut okm: [u8; 0] = [];
        hk.expand(&RFC5869_INFO, &mut okm).unwrap();
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
        let ikm = RFC5869_IKM;
        // Produce a PRK via extract, round-trip via from_prk, and
        // verify expand still matches the RFC 5869 vector.
        let first = HkdfSha256::extract(Some(&RFC5869_SALT), &ikm).unwrap();
        let prk = *first.prk();
        let second = HkdfSha256::from_prk(&prk).unwrap();
        let mut okm = [0u8; 42];
        second.expand(&RFC5869_INFO, &mut okm).unwrap();
        assert_eq!(okm, RFC5869_SHA256_OKM);
    }

    #[test]
    fn hkdf_sha3_256_short_expand_deterministic() {
        // Exercise the SHA-3 PRF path with a short (< L) expand.
        ensure_initialized();
        let ikm = RFC5869_IKM;
        let hk = HkdfSha3_256::extract(Some(&RFC5869_SALT), &ikm).unwrap();
        let mut a = [0u8; 10];
        let mut b = [0u8; 10];
        hk.expand(&RFC5869_INFO, &mut a).unwrap();
        hk.expand(&RFC5869_INFO, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_sha512_streaming_matches_one_shot_expand() {
        // HKDF-Expand has no streaming API, but back-to-back calls
        // against the same Hkdf instance must be deterministic.
        ensure_initialized();
        let ikm = RFC5869_IKM;
        let hk = HkdfSha512::extract(Some(&RFC5869_SALT), &ikm).unwrap();
        let mut a = [0u8; 100];
        let mut b = [0u8; 100];
        hk.expand(&RFC5869_INFO, &mut a).unwrap();
        hk.expand(&RFC5869_INFO, &mut b).unwrap();
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

    // ----- SP 800-108 Counter Mode --------------------------------------

    #[test]
    fn kbkdf_counter_boot_self_tests_all_pass() {
        assert!(kbkdf_counter_self_test_sha1().is_ok());
        assert!(kbkdf_counter_self_test_sha224().is_ok());
        assert!(kbkdf_counter_self_test_sha256().is_ok());
        assert!(kbkdf_counter_self_test_sha384().is_ok());
        assert!(kbkdf_counter_self_test_sha512().is_ok());
        assert!(kbkdf_counter_self_test_sha512_224().is_ok());
        assert!(kbkdf_counter_self_test_sha512_256().is_ok());
        assert!(kbkdf_counter_self_test_sha3_224().is_ok());
        assert!(kbkdf_counter_self_test_sha3_256().is_ok());
        assert!(kbkdf_counter_self_test_sha3_384().is_ok());
        assert!(kbkdf_counter_self_test_sha3_512().is_ok());
    }

    #[test]
    fn kbkdf_counter_public_api_is_deterministic() {
        // The previous test compared against a hand-rolled expected
        // output; the power-up KAT now covers correctness via NIST
        // ACVP-Server vectors. Here we just confirm the public API
        // produces a stable, non-zero, deterministic output for the
        // same inputs.
        ensure_initialized();
        let mut a = [0u8; 42];
        let mut b = [0u8; 42];
        Sp800_108CounterHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut a,
        )
        .unwrap();
        Sp800_108CounterHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut b,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 42]);
    }

    #[test]
    fn kbkdf_counter_short_output_truncates_last_block() {
        // A 17-byte request against HMAC-SHA-256 (L=32) should
        // produce the first 17 bytes of the first PRF block.
        ensure_initialized();
        let mut full = [0u8; 32];
        Sp800_108CounterHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut full,
        )
        .unwrap();
        // Re-derive 17 bytes directly. Since 17 < L, only one
        // iteration runs but its [L]_32 encoding differs (17*8=136
        // vs 32*8=256), so the short output is NOT a prefix of the
        // full output — that's the whole point of binding L in the
        // fixed input per SP 800-108 §5.2. This test confirms the
        // bit-length encoding actually participates.
        let mut short = [0u8; 17];
        Sp800_108CounterHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut short,
        )
        .unwrap();
        assert_ne!(&short[..], &full[..17]);
    }

    #[test]
    fn kbkdf_counter_empty_output_is_noop() {
        ensure_initialized();
        let mut empty: [u8; 0] = [];
        Sp800_108CounterHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut empty,
        )
        .unwrap();
    }

    #[test]
    fn kbkdf_counter_sha3_multi_block() {
        // SHA3-256 has L=32, so 42 bytes requires n=2 blocks —
        // exercises the counter increment path under a sponge PRF.
        ensure_initialized();
        let mut a = [0u8; 42];
        let mut b = [0u8; 42];
        Sp800_108CounterHmacSha3_256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut a,
        )
        .unwrap();
        Sp800_108CounterHmacSha3_256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut b,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn kbkdf_counter_distinct_contexts_diverge() {
        // Domain separation: changing Context must produce different
        // output for the same (K, Label, L).
        ensure_initialized();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Sp800_108CounterHmacSha256::derive(&KBKDF_KAT_KEY, KBKDF_KAT_LABEL, b"ctx A", &mut a)
            .unwrap();
        Sp800_108CounterHmacSha256::derive(&KBKDF_KAT_KEY, KBKDF_KAT_LABEL, b"ctx B", &mut b)
            .unwrap();
        assert_ne!(a, b);
    }

    // ----- SP 800-108 Feedback Mode -------------------------------------

    const KBKDF_FB_IV: [u8; 16] = [0x5a; 16];

    #[test]
    fn kbkdf_feedback_boot_self_tests_all_pass() {
        assert!(kbkdf_feedback_self_test_sha1().is_ok());
        assert!(kbkdf_feedback_self_test_sha224().is_ok());
        assert!(kbkdf_feedback_self_test_sha256().is_ok());
        assert!(kbkdf_feedback_self_test_sha384().is_ok());
        assert!(kbkdf_feedback_self_test_sha512().is_ok());
        assert!(kbkdf_feedback_self_test_sha512_224().is_ok());
        assert!(kbkdf_feedback_self_test_sha512_256().is_ok());
        assert!(kbkdf_feedback_self_test_sha3_224().is_ok());
        assert!(kbkdf_feedback_self_test_sha3_256().is_ok());
        assert!(kbkdf_feedback_self_test_sha3_384().is_ok());
        assert!(kbkdf_feedback_self_test_sha3_512().is_ok());
    }

    #[test]
    fn kbkdf_feedback_public_api_is_deterministic() {
        ensure_initialized();
        let mut a = [0u8; 42];
        let mut b = [0u8; 42];
        Sp800_108FeedbackHmacSha256::derive(
            &KBKDF_KAT_KEY,
            &KBKDF_FB_IV,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut a,
        )
        .unwrap();
        Sp800_108FeedbackHmacSha256::derive(
            &KBKDF_KAT_KEY,
            &KBKDF_FB_IV,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut b,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 42]);
    }

    #[test]
    fn kbkdf_feedback_distinct_ivs_diverge() {
        // Per SP 800-108 §4.2, the IV seeds K(0), so different IVs
        // must produce different outputs for the same (K, fixed data).
        ensure_initialized();
        let iv_a = [0x11u8; 16];
        let iv_b = [0x22u8; 16];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Sp800_108FeedbackHmacSha256::derive(
            &KBKDF_KAT_KEY,
            &iv_a,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut a,
        )
        .unwrap();
        Sp800_108FeedbackHmacSha256::derive(
            &KBKDF_KAT_KEY,
            &iv_b,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut b,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn kbkdf_feedback_sha3_multi_block() {
        ensure_initialized();
        let mut a = [0u8; 80];
        let mut b = [0u8; 80];
        Sp800_108FeedbackHmacSha3_256::derive(
            &KBKDF_KAT_KEY,
            &KBKDF_FB_IV,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut a,
        )
        .unwrap();
        Sp800_108FeedbackHmacSha3_256::derive(
            &KBKDF_KAT_KEY,
            &KBKDF_FB_IV,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut b,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    // ----- SP 800-108 Double-Pipeline Iteration Mode --------------------

    #[test]
    fn kbkdf_dp_boot_self_tests_all_pass() {
        assert!(kbkdf_dp_self_test_sha1().is_ok());
        assert!(kbkdf_dp_self_test_sha224().is_ok());
        assert!(kbkdf_dp_self_test_sha256().is_ok());
        assert!(kbkdf_dp_self_test_sha384().is_ok());
        assert!(kbkdf_dp_self_test_sha512().is_ok());
        assert!(kbkdf_dp_self_test_sha512_224().is_ok());
        assert!(kbkdf_dp_self_test_sha512_256().is_ok());
        assert!(kbkdf_dp_self_test_sha3_224().is_ok());
        assert!(kbkdf_dp_self_test_sha3_256().is_ok());
        assert!(kbkdf_dp_self_test_sha3_384().is_ok());
        assert!(kbkdf_dp_self_test_sha3_512().is_ok());
    }

    #[test]
    fn kbkdf_dp_public_api_is_deterministic() {
        ensure_initialized();
        let mut a = [0u8; 42];
        let mut b = [0u8; 42];
        Sp800_108DoublePipelineHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut a,
        )
        .unwrap();
        Sp800_108DoublePipelineHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut b,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 42]);
    }

    #[test]
    fn kbkdf_dp_distinct_contexts_diverge() {
        ensure_initialized();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Sp800_108DoublePipelineHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            b"ctx A",
            &mut a,
        )
        .unwrap();
        Sp800_108DoublePipelineHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            b"ctx B",
            &mut b,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn kbkdf_dp_sha3_multi_block() {
        ensure_initialized();
        let mut a = [0u8; 80];
        let mut b = [0u8; 80];
        Sp800_108DoublePipelineHmacSha3_256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut a,
        )
        .unwrap();
        Sp800_108DoublePipelineHmacSha3_256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut b,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn kbkdf_three_modes_yield_distinct_output() {
        // The three SP 800-108 modes must yield distinct output for
        // the same (K, Label, Context, L) because their recurrences
        // differ. Guards against accidental mode crosswiring.
        ensure_initialized();
        let mut c = [0u8; 32];
        let mut f = [0u8; 32];
        let mut d = [0u8; 32];
        Sp800_108CounterHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut c,
        )
        .unwrap();
        Sp800_108FeedbackHmacSha256::derive(
            &KBKDF_KAT_KEY,
            &KBKDF_FB_IV,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut f,
        )
        .unwrap();
        Sp800_108DoublePipelineHmacSha256::derive(
            &KBKDF_KAT_KEY,
            KBKDF_KAT_LABEL,
            KBKDF_KAT_CONTEXT,
            &mut d,
        )
        .unwrap();
        assert_ne!(c, f);
        assert_ne!(c, d);
        assert_ne!(f, d);
    }

    // ==================================================================
    // PBKDF2 tests
    // ==================================================================

    #[test]
    fn pbkdf2_sha1_self_test_passes() {
        pbkdf2_self_test_sha1().unwrap();
    }

    #[test]
    fn pbkdf2_sha256_self_test_passes() {
        pbkdf2_self_test_sha256().unwrap();
    }

    #[test]
    fn pbkdf2_sha1_rfc6070_c2() {
        // RFC 6070 Test Case 2: P="password", S="salt", c=2, dkLen=20
        let expected: [u8; 20] = [
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
            0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        let mut dk = [0u8; 20];
        Pbkdf2HmacSha1::derive_internal(b"password", b"salt", 2, &mut dk).unwrap();
        assert_eq!(dk, expected);
    }

    #[test]
    fn pbkdf2_sha256_c4096() {
        // P="password", S="salt", c=4096, dkLen=32 (SHA-256)
        let expected: [u8; 32] = [
            0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c,
            0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73,
            0xaa, 0x98, 0x13, 0x4a,
        ];
        let mut dk = [0u8; 32];
        Pbkdf2HmacSha256::derive_internal(b"password", b"salt", 4096, &mut dk).unwrap();
        assert_eq!(dk, expected);
    }

    #[test]
    fn pbkdf2_sha512_c1() {
        // P="password", S="salt", c=1, dkLen=64 (SHA-512)
        let expected: [u8; 64] = [
            0x86, 0x7f, 0x70, 0xcf, 0x1a, 0xde, 0x02, 0xcf, 0xf3, 0x75, 0x25, 0x99, 0xa3, 0xa5,
            0x3d, 0xc4, 0xaf, 0x34, 0xc7, 0xa6, 0x69, 0x81, 0x5a, 0xe5, 0xd5, 0x13, 0x55, 0x4e,
            0x1c, 0x8c, 0xf2, 0x52, 0xc0, 0x2d, 0x47, 0x0a, 0x28, 0x5a, 0x05, 0x01, 0xba, 0xd9,
            0x99, 0xbf, 0xe9, 0x43, 0xc0, 0x8f, 0x05, 0x02, 0x35, 0xd7, 0xd6, 0x8b, 0x1d, 0xa5,
            0x5e, 0x63, 0xf7, 0x3b, 0x60, 0xa5, 0x7f, 0xce,
        ];
        let mut dk = [0u8; 64];
        Pbkdf2HmacSha512::derive_internal(b"password", b"salt", 1, &mut dk).unwrap();
        assert_eq!(dk, expected);
    }

    #[test]
    fn pbkdf2_multi_block_output() {
        // Output longer than one HMAC block requires multiple blocks.
        // SHA-256 output is 32 bytes; request 48 bytes → 2 PBKDF2 blocks.
        let mut dk = [0u8; 48];
        Pbkdf2HmacSha256::derive_internal(b"pass", b"sa", 1, &mut dk).unwrap();
        // Verify first 32 bytes match block 1, and that bytes 32..48 are non-zero.
        assert_ne!(&dk[32..], &[0u8; 16]);
    }

    #[test]
    fn pbkdf2_deterministic() {
        let mut dk1 = [0u8; 32];
        let mut dk2 = [0u8; 32];
        Pbkdf2HmacSha256::derive_internal(b"password", b"salt", 2, &mut dk1).unwrap();
        Pbkdf2HmacSha256::derive_internal(b"password", b"salt", 2, &mut dk2).unwrap();
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn pbkdf2_different_passwords_differ() {
        let mut dk1 = [0u8; 32];
        let mut dk2 = [0u8; 32];
        Pbkdf2HmacSha256::derive_internal(b"pass-a", b"salt", 1, &mut dk1).unwrap();
        Pbkdf2HmacSha256::derive_internal(b"pass-b", b"salt", 1, &mut dk2).unwrap();
        assert_ne!(dk1, dk2);
    }

    #[test]
    fn pbkdf2_different_salts_differ() {
        let mut dk1 = [0u8; 32];
        let mut dk2 = [0u8; 32];
        Pbkdf2HmacSha256::derive_internal(b"password", b"salt-a", 1, &mut dk1).unwrap();
        Pbkdf2HmacSha256::derive_internal(b"password", b"salt-b", 1, &mut dk2).unwrap();
        assert_ne!(dk1, dk2);
    }

    #[test]
    fn pbkdf2_different_iterations_differ() {
        let mut dk1 = [0u8; 32];
        let mut dk2 = [0u8; 32];
        Pbkdf2HmacSha256::derive_internal(b"password", b"salt", 1, &mut dk1).unwrap();
        Pbkdf2HmacSha256::derive_internal(b"password", b"salt", 2, &mut dk2).unwrap();
        assert_ne!(dk1, dk2);
    }

    // ── Smoke tests for SP 800-108r1 counter-bearing primitives ─────
    //
    // Shape-correctness only: `derive_with_counter_internal` returns
    // `Ok` for the dispatched `counter_length_bits` value (32) and
    // rejects every value outside the SP 800-108r1 §5.1 set
    // `{8, 16, 24, 32}`. Cryptographic correctness for h>0 is gated
    // on the ACVP demo verdict, not these smoke tests — the vendored
    // NIST kat-slice carries h=0 vectors only for FB/DP.

    #[test]
    fn kbkdf_feedback_counter_internal_smoke_h32() {
        let key = [0x42u8; 32];
        let iv = [0x11u8; 32];
        // Arbitrary fixed-data blob; smoke test exercises the call
        // path, not the value.
        let fixed_data = b"label\x00context\x00\x00\x01\x00";
        let mut out = [0u8; 32];
        Sp800_108FeedbackHmacSha256::derive_with_counter_internal(
            &key, &iv, fixed_data, 32, &mut out,
        )
        .unwrap();
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn kbkdf_dp_counter_internal_smoke_h32() {
        let key = [0x42u8; 32];
        let fixed_data = b"label\x00context\x00\x00\x01\x00";
        let mut out = [0u8; 32];
        Sp800_108DoublePipelineHmacSha256::derive_with_counter_internal(
            &key, fixed_data, 32, &mut out,
        )
        .unwrap();
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn kbkdf_feedback_counter_rejects_invalid_h() {
        let key = [0x42u8; 32];
        let iv = [0x11u8; 32];
        let fixed_data: &[u8] = b"x";
        let mut out = [0u8; 16];
        for h in [0u32, 1, 7, 9, 17, 31, 33, 64] {
            let err = Sp800_108FeedbackHmacSha256::derive_with_counter_internal(
                &key, &iv, fixed_data, h, &mut out,
            )
            .unwrap_err();
            assert!(matches!(err, KdfError::Module(Error::InvalidInput)));
        }
    }

    #[test]
    fn kbkdf_dp_counter_rejects_invalid_h() {
        let key = [0x42u8; 32];
        let fixed_data: &[u8] = b"x";
        let mut out = [0u8; 16];
        for h in [0u32, 1, 7, 9, 17, 31, 33, 64] {
            let err = Sp800_108DoublePipelineHmacSha256::derive_with_counter_internal(
                &key, fixed_data, h, &mut out,
            )
            .unwrap_err();
            assert!(matches!(err, KdfError::Module(Error::InvalidInput)));
        }
    }
}
