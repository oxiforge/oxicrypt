//! RSA signature generation and verification per FIPS 186-5 §5.4 /
//! RFC 8017 §8.
//!
//! # Status
//!
//! Chunks R1 and R2 are live. R1 landed the fixed-width big-int
//! stack ([`bigint2048`] / [`mont2048`]) plus RSASSA-PKCS1-v1_5
//! verify with SHA-256. R2 adds the private-key side: a
//! constant-time 4-bit windowed Montgomery ladder
//! ([`mont2048::MontCtx2048::pow_secret`]), an
//! [`RsaPrivateKey2048`] handle that runs the FIPS 140-3 IG 10.3.A
//! pairwise consistency test at construction, and a gated sign
//! entry point [`RsaPrivateKey2048::sign_pkcs1_v15_sha256`]. The
//! power-up KAT is extended to cover both verify and sign against
//! a pinned `(n, e, d, msg, sig)` tuple.
//!
//! # FIPS 186-5 §5.1 modulus size
//!
//! Only `|n| = 2048` bits is accepted. Verification of legacy 1024-
//! or 1280-bit RSA signatures is outside the approved boundary and
//! this crate deliberately has no code path for it. Extension to
//! RSA-3072 and RSA-4096 will land when the corresponding
//! fixed-width big-int types are added.
//!
//! # FIPS module gating
//!
//! [`rsa_pkcs1_v15_verify_2048_sha256`] and
//! [`RsaPrivateKey2048::sign_pkcs1_v15_sha256`] call
//! [`fips_module::require_operational`] before doing any work; a
//! hidden `*_internal` pair bypasses the gate so the power-up KAT
//! in [`self_test`] can run while the module is still in `SelfTest`.
#![no_std]
#![forbid(unsafe_code)]

pub mod bigint2048;
pub mod mont2048;
pub mod pkcs1_v15;
pub mod pss;

use bigint2048::{U2048, BYTES as U2048_BYTES};
use fips_module::{require_operational, Error, SelfTestFailure};
use fips_sha::sha256::DIGEST_SIZE as SHA256_DIGEST_SIZE;
use mont2048::MontCtx2048;

/// Fixed modulus byte length for RSA-2048.
pub const RSA_2048_MODULUS_BYTES: usize = U2048_BYTES;
/// Fixed signature byte length for RSA-2048 (equal to the modulus
/// length per PKCS#1 §8.2).
pub const RSA_2048_SIGNATURE_BYTES: usize = U2048_BYTES;

// ------------------------------------------------------------------
// Core verify primitive (state-gate-free)
// ------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 verify for RSA-2048 / SHA-256, bypassing the
/// FIPS module state gate. Intended for power-up KAT use only;
/// production callers use [`rsa_pkcs1_v15_verify_2048_sha256`].
///
/// Returns `true` iff:
///   * `n` is a valid 2048-bit odd integer with the top bit set
///     (accepted by [`MontCtx2048::new`]),
///   * `s < n` where `s` is the signature integer,
///   * `RSAVP1(s) = s^e mod n = EM`, and
///   * `EM` matches the canonical EMSA-PKCS1-v1_5 encoding of
///     `SHA-256(msg)` at length 256 bytes.
#[doc(hidden)]
pub fn rsa_pkcs1_v15_verify_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> bool {
    // Decode the modulus and build a Montgomery context. `MontCtx2048::new`
    // enforces oddness and the strict-2048-bit size requirement from
    // FIPS 186-5 §5.1.
    let n = U2048::from_be_bytes(n_bytes);
    let Some(ctx) = MontCtx2048::new(n) else {
        return false;
    };

    // RFC 8017 §8.2.2 step 1: length check is implicit in the fixed
    // array sizes. Step 2a: convert signature to integer `s`.
    let s = U2048::from_be_bytes(sig_bytes);

    // RFC 8017 §5.2.2 RSAVP1 step 1: s must be in `[0, n-1]`. An
    // attacker-controlled `s ≥ n` would otherwise be accepted by the
    // Montgomery ladder (which reduces mod n and forgets the top
    // bits), letting them construct unlimited signature aliases.
    if s.ct_lt(&ctx.n) != 1 {
        return false;
    }

    // RSAVP1 / RSAEP: m = s^e mod n. `pow_public_u64` is explicitly
    // non-constant-time in `e`, which is fine here because `e` is
    // part of the public key.
    let m = ctx.pow_public_u64(&s, e);
    let em_recovered = m.to_be_bytes();

    // Build the expected EM from SHA-256(msg) and compare byte-exact.
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em_expected = [0u8; RSA_2048_MODULUS_BYTES];
    if pkcs1_v15::encode_sha256(&digest, &mut em_expected).is_none() {
        return false;
    }
    pkcs1_v15::ct_eq(&em_recovered, &em_expected) == 1
}

// ------------------------------------------------------------------
// Core sign primitive (state-gate-free)
// ------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 sign for RSA-2048 / SHA-256, bypassing the FIPS
/// module state gate and the pairwise consistency test. Intended for
/// power-up KAT use only.
///
/// Returns `None` if `n` is not a valid 2048-bit modulus accepted by
/// [`MontCtx2048::new`], if `d >= n` (which would let the ladder
/// silently wrap), or if the EMSA encoding step fails (it cannot
/// fail for an RSA-2048 SHA-256 configuration, but we plumb the
/// error anyway for symmetry with the verify path).
#[doc(hidden)]
pub fn rsa_pkcs1_v15_sign_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    msg: &[u8],
) -> Option<[u8; RSA_2048_SIGNATURE_BYTES]> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx = MontCtx2048::new(n)?;

    let d = U2048::from_be_bytes(d_bytes);
    // FIPS 186-5 §5.1 / PKCS#1 §3.2 require d ∈ [1, n−1]. Reject
    // d ≥ n here so the ladder never accepts an out-of-range secret.
    if d.ct_lt(&ctx.n) != 1 {
        return None;
    }

    // EMSA-PKCS1-v1_5 encode the message digest into an EM buffer
    // that's already one modulus-length wide.
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em = [0u8; RSA_2048_MODULUS_BYTES];
    pkcs1_v15::encode_sha256(&digest, &mut em)?;

    // RFC 8017 §9.2 step 6: convert EM → m, §5.2.1 RSASP1: s = m^d mod n.
    // The message representative always satisfies m < n because the
    // canonical EM starts with 0x00 0x01 and n has its top bit set.
    let m = U2048::from_be_bytes(&em);
    let s = ctx.pow_secret(&m, &d);
    Some(s.to_be_bytes())
}

// ------------------------------------------------------------------
// Core PSS primitives (state-gate-free)
// ------------------------------------------------------------------

/// RSASSA-PSS sign for RSA-2048 / SHA-256 with `sLen = hLen = 32`,
/// bypassing the FIPS module state gate. Intended for power-up KAT
/// and for the gated public API wrappers.
///
/// The caller supplies the salt. The KAT path passes a pinned salt;
/// production callers supply fresh randomness. Returns `None` for the
/// same structural reasons as [`rsa_pkcs1_v15_sign_2048_sha256_internal`]
/// (bad modulus, `d ≥ n`, or EMSA-PSS encode failure, which again
/// cannot happen for the pinned parameter triple but is plumbed for
/// symmetry).
#[doc(hidden)]
pub fn rsa_pss_sign_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    msg: &[u8],
    salt: &[u8; pss::SLEN],
) -> Option<[u8; RSA_2048_SIGNATURE_BYTES]> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx = MontCtx2048::new(n)?;

    let d = U2048::from_be_bytes(d_bytes);
    if d.ct_lt(&ctx.n) != 1 {
        return None;
    }

    // EMSA-PSS-ENCODE the SHA-256 digest of msg into a 256-byte EM.
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em = [0u8; pss::EM_LEN];
    pss::emsa_pss_encode(&digest, salt, &mut em)?;

    // RFC 8017 §8.1.1 step 2a/b: m = OS2IP(EM), s = RSASP1(K, m).
    // The top bit of EM is cleared (emBits = 2047 < 8·emLen = 2048),
    // so m < 2^2047 < n and the ladder never wraps.
    let m = U2048::from_be_bytes(&em);
    let s = ctx.pow_secret(&m, &d);
    Some(s.to_be_bytes())
}

/// RSASSA-PSS verify for RSA-2048 / SHA-256, bypassing the FIPS module
/// state gate. Intended for power-up KAT use only; production callers
/// use [`rsa_pss_verify_2048_sha256`].
#[doc(hidden)]
pub fn rsa_pss_verify_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> bool {
    let n = U2048::from_be_bytes(n_bytes);
    let Some(ctx) = MontCtx2048::new(n) else {
        return false;
    };

    // RFC 8017 §8.1.2 step 1: length check is implicit; step 2a: OS2IP.
    let s = U2048::from_be_bytes(sig_bytes);
    if s.ct_lt(&ctx.n) != 1 {
        return false;
    }

    // §5.2.2 RSAVP1: m = s^e mod n.
    let m = ctx.pow_public_u64(&s, e);
    let em = m.to_be_bytes();

    let digest = pkcs1_v15::sha256_internal(msg);
    pss::emsa_pss_verify(&digest, &em)
}

// ------------------------------------------------------------------
// Public verify API (gated)
// ------------------------------------------------------------------

/// Verify an RSASSA-PKCS1-v1_5 signature over `msg` under the 2048-bit
/// public key `(n_bytes, e)` using SHA-256 as the message digest.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the containing FIPS module
/// has not finished its power-up self-tests. Returns
/// [`Error::InvalidInput`] if the signature fails to verify for any
/// reason — invalid modulus, out-of-range signature integer, digest
/// mismatch, or malformed EM.
///
/// On a successful verification, returns `Ok(())`.
pub fn rsa_pkcs1_v15_verify_2048_sha256(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> Result<(), Error> {
    require_operational()?;
    if rsa_pkcs1_v15_verify_2048_sha256_internal(n_bytes, e, msg, sig_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Verify an RSASSA-PSS signature over `msg` under the 2048-bit public
/// key `(n_bytes, e)` using SHA-256 as both the message hash and the
/// MGF1 hash, with salt length fixed to `hLen = 32` bytes.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the FIPS module has not
/// finished power-up self-tests. Returns [`Error::InvalidInput`] if
/// the signature does not verify for any reason.
pub fn rsa_pss_verify_2048_sha256(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> Result<(), Error> {
    require_operational()?;
    if rsa_pss_verify_2048_sha256_internal(n_bytes, e, msg, sig_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

// ------------------------------------------------------------------
// Private-key handle + pairwise consistency test
// ------------------------------------------------------------------

/// Run a pairwise consistency test for an RSA-2048 keypair
/// `(n, e, d)`, bypassing the operational gate. Returns `true` iff
/// signing a fixed probe message with `(n, d)` produces a signature
/// that verifies under `(n, e)`.
///
/// Used both by the power-up KAT (where the KAT tuple is already
/// pinned but we still re-run the test as a structural health
/// check) and by [`RsaPrivateKey2048::from_components`] after the
/// operational gate has released.
#[doc(hidden)]
pub fn pairwise_consistency_test_2048_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
) -> bool {
    // The probe message is arbitrary but fixed; IG 10.3.A only
    // requires that the PCT cover the sign→verify roundtrip. We pick
    // a short ASCII string that is obviously not a secret.
    const PROBE: &[u8] = b"fips-rsa PCT probe / RSA-2048 / PKCS#1 v1.5 / SHA-256";
    let Some(sig) = rsa_pkcs1_v15_sign_2048_sha256_internal(n_bytes, d_bytes, PROBE) else {
        return false;
    };
    rsa_pkcs1_v15_verify_2048_sha256_internal(n_bytes, e, PROBE, &sig)
}

/// A validated RSA-2048 private key suitable for signing.
///
/// Construction runs the FIPS 140-3 IG 10.3.A pairwise consistency
/// test against the public components `(n, e)` and fails if the
/// key does not sign-and-verify a probe message. Once constructed,
/// the handle can produce signatures without re-running the PCT on
/// each call.
#[derive(Clone)]
pub struct RsaPrivateKey2048 {
    n_bytes: [u8; RSA_2048_MODULUS_BYTES],
    d_bytes: [u8; RSA_2048_MODULUS_BYTES],
    e: u64,
}

impl RsaPrivateKey2048 {
    /// Build a validated private-key handle from the raw `(n, e, d)`
    /// components.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module has not
    /// completed power-up self-tests. Returns [`Error::InvalidInput`]
    /// if the pairwise consistency test fails — which covers any of
    /// the following:
    ///
    ///   * `n` is not a strict 2048-bit odd integer;
    ///   * `d` is outside the range `[1, n − 1]`;
    ///   * `(n, e, d)` are structurally inconsistent (for example, a
    ///     `d` from a different keypair);
    ///   * any of the primitive subroutines encountered an internal
    ///     corruption.
    pub fn from_components(
        n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
        e: u64,
        d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    ) -> Result<Self, Error> {
        require_operational()?;
        if !pairwise_consistency_test_2048_internal(n_bytes, e, d_bytes) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            n_bytes: *n_bytes,
            d_bytes: *d_bytes,
            e,
        })
    }

    /// Public modulus, big-endian, 256 bytes.
    #[must_use]
    pub fn modulus_bytes(&self) -> &[u8; RSA_2048_MODULUS_BYTES] {
        &self.n_bytes
    }

    /// Public exponent.
    #[must_use]
    pub fn public_exponent(&self) -> u64 {
        self.e
    }

    /// Sign `msg` with RSASSA-PKCS1-v1_5 using SHA-256 as the message
    /// digest. Returns a 256-byte signature on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module is no
    /// longer operational at call time, or [`Error::InvalidInput`] if
    /// the internal sign primitive rejects the pinned modulus or the
    /// pinned private exponent (which should never happen for a
    /// handle successfully returned from [`Self::from_components`] —
    /// if it does, the module is corrupted).
    pub fn sign_pkcs1_v15_sha256(
        &self,
        msg: &[u8],
    ) -> Result<[u8; RSA_2048_SIGNATURE_BYTES], Error> {
        require_operational()?;
        rsa_pkcs1_v15_sign_2048_sha256_internal(&self.n_bytes, &self.d_bytes, msg)
            .ok_or(Error::InvalidInput)
    }

    /// Sign `msg` with RSASSA-PSS using SHA-256 as both the message
    /// hash and the MGF1 hash, with the caller-supplied salt. Returns
    /// a 256-byte signature on success.
    ///
    /// # Salt sourcing
    ///
    /// Exposing the salt to the caller rather than internally sampling
    /// it keeps the crate free of a randomness dependency in R3. The
    /// R4 keygen chunk will add a DRBG-backed wrapper
    /// (`sign_pss_sha256`) that samples a fresh `hLen`-byte salt and
    /// then calls this method. FIPS 186-5 §5.4 permits any
    /// `sLen ∈ [0, hLen]`; we fix it at `hLen` to keep the KAT
    /// deterministic and match the IG 10.3.A recommendation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module is no
    /// longer operational at call time, or [`Error::InvalidInput`] if
    /// the internal primitive rejects the pinned key material.
    pub fn sign_pss_sha256_with_salt(
        &self,
        msg: &[u8],
        salt: &[u8; pss::SLEN],
    ) -> Result<[u8; RSA_2048_SIGNATURE_BYTES], Error> {
        require_operational()?;
        rsa_pss_sign_2048_sha256_internal(&self.n_bytes, &self.d_bytes, msg, salt)
            .ok_or(Error::InvalidInput)
    }
}

// ------------------------------------------------------------------
// Pinned KAT material
// ------------------------------------------------------------------

/// Pinned RSA-2048 public modulus used by the power-up KAT. Generated
/// deterministically from a fixed PRNG seed.
const KAT_N_BYTES: [u8; 256] = [
    0xb1, 0xb2, 0x5f, 0x95, 0x6b, 0xa0, 0x4b, 0x22, 0xdf, 0x1c, 0x8b, 0x1f, 0xee, 0x4a, 0x47, 0x28,
    0x48, 0x92, 0xac, 0x1a, 0xe1, 0x6b, 0x62, 0x05, 0xba, 0x30, 0x2c, 0xdf, 0x03, 0x32, 0x43, 0xf3,
    0xcb, 0x96, 0x8c, 0x6d, 0x6f, 0x3b, 0xe4, 0xda, 0xb6, 0xf8, 0x61, 0x98, 0x36, 0x66, 0xfa, 0x06,
    0x9b, 0x37, 0xd0, 0x15, 0x6d, 0x61, 0x6f, 0xd8, 0x37, 0xae, 0x8a, 0x52, 0x4c, 0xf5, 0xee, 0x66,
    0x20, 0x27, 0xa0, 0xde, 0x1a, 0xf6, 0x7b, 0xb3, 0x7d, 0x5d, 0x18, 0xe3, 0x10, 0xcd, 0x37, 0xa8,
    0x67, 0x9b, 0xe3, 0x1d, 0x66, 0x19, 0xe1, 0xfa, 0x8a, 0x9b, 0xd4, 0x46, 0x8a, 0x16, 0x65, 0x72,
    0xf5, 0xa2, 0x75, 0xca, 0x23, 0x8e, 0x99, 0x98, 0xce, 0xf3, 0x1f, 0x24, 0xb3, 0x37, 0x61, 0x77,
    0xae, 0xad, 0x1f, 0x41, 0xa7, 0x0b, 0xe3, 0xd5, 0x2b, 0xb3, 0x77, 0x32, 0x51, 0x24, 0x5c, 0x2f,
    0xd0, 0x1b, 0xb6, 0x89, 0x52, 0x49, 0xa8, 0x60, 0x39, 0xf4, 0xdb, 0x74, 0xdd, 0x84, 0x24, 0x62,
    0xb7, 0xba, 0x2d, 0x8a, 0x77, 0x63, 0x41, 0x3b, 0x26, 0x18, 0x7a, 0x16, 0x18, 0x32, 0x62, 0x91,
    0x44, 0xf6, 0x1f, 0x59, 0x33, 0x39, 0x62, 0xe3, 0x3e, 0x75, 0x6c, 0xb7, 0xa2, 0xf4, 0x61, 0xf1,
    0xba, 0xd9, 0x54, 0xc2, 0x92, 0xda, 0x40, 0x5f, 0x0a, 0x07, 0x19, 0xbc, 0x73, 0xa6, 0xda, 0x88,
    0x7d, 0x13, 0x31, 0xd0, 0x91, 0x73, 0xa0, 0x19, 0x12, 0xfb, 0x3a, 0x4d, 0x27, 0xe8, 0x3d, 0xb4,
    0xd0, 0xf4, 0x8c, 0x7b, 0x0f, 0x5d, 0x13, 0xce, 0x35, 0xd4, 0x23, 0xd4, 0x2e, 0x78, 0x1a, 0xda,
    0x29, 0x95, 0x50, 0x2a, 0xb5, 0x09, 0xd7, 0x95, 0x39, 0xda, 0x50, 0x7a, 0xe2, 0xa2, 0x08, 0xbb,
    0x1c, 0xcc, 0xf0, 0x43, 0xe2, 0xfc, 0x0f, 0xcc, 0x4a, 0x05, 0xd8, 0xd4, 0xda, 0x45, 0x6c, 0x6d,
];

/// Pinned public exponent for the KAT.
const KAT_E: u64 = 65537;

/// Pinned RSA-2048 private exponent matching `(KAT_N_BYTES, KAT_E)`.
///
/// Kept inside the module so the KAT can exercise the sign path
/// alongside the verify path. The primes `p` and `q` that generated
/// this `d` are not retained: the non-CRT sign path only needs
/// `(n, d)`, and we intentionally keep the KAT tuple minimal until
/// the CRT path lands in R3.
const KAT_D_BYTES: [u8; 256] = [
    0x22, 0xc2, 0x95, 0xd8, 0x10, 0xd9, 0xa6, 0x59, 0x07, 0xf3, 0xf9, 0x73, 0x21, 0x95, 0xfe, 0x1d,
    0x6f, 0x34, 0xe1, 0xdd, 0xd0, 0x42, 0xc5, 0x46, 0x01, 0x89, 0xf2, 0xfd, 0x1d, 0x0e, 0xf4, 0x23,
    0xf8, 0xab, 0x56, 0x85, 0x01, 0xc1, 0x61, 0x9f, 0x37, 0x33, 0x97, 0x43, 0xc3, 0x40, 0x99, 0xa0,
    0x39, 0x34, 0xcd, 0xcb, 0xa3, 0x3d, 0xf0, 0x37, 0x07, 0x8d, 0x69, 0x19, 0x78, 0x5c, 0x93, 0x69,
    0xfe, 0xd8, 0x41, 0xab, 0xb0, 0xf2, 0x8e, 0x78, 0x2a, 0x09, 0xd0, 0x18, 0x7a, 0xec, 0xe9, 0xfa,
    0x53, 0x6a, 0x37, 0x1f, 0x45, 0x1d, 0xc3, 0x0a, 0xd3, 0x9a, 0x70, 0x07, 0xec, 0x73, 0x3d, 0x1d,
    0x23, 0xd7, 0xc7, 0xda, 0xe6, 0xe1, 0xba, 0x42, 0x1e, 0x19, 0x88, 0xfa, 0x10, 0xe4, 0xc0, 0x78,
    0x3c, 0xff, 0x38, 0xa2, 0x0b, 0x1f, 0x54, 0x4e, 0x1a, 0xe2, 0x5c, 0x6a, 0xc7, 0x5c, 0xa9, 0x7b,
    0x8d, 0x31, 0x7a, 0x17, 0x14, 0x91, 0xeb, 0x54, 0xdf, 0xf3, 0x2b, 0x0e, 0x5c, 0x44, 0xf2, 0xe7,
    0xed, 0x99, 0x7e, 0x27, 0x08, 0x2b, 0xb1, 0x4f, 0x90, 0x00, 0xc4, 0xc4, 0xf3, 0xc2, 0x01, 0x18,
    0xbc, 0x63, 0x16, 0x9e, 0x64, 0xdb, 0xb3, 0x1f, 0xe1, 0x84, 0x70, 0x60, 0x1d, 0xc4, 0xb7, 0x7c,
    0x1e, 0x3f, 0x3f, 0x22, 0xc3, 0xb5, 0x35, 0xfb, 0x27, 0x27, 0xcd, 0x57, 0xf0, 0x34, 0xc3, 0x32,
    0xb0, 0x71, 0xfd, 0x87, 0x59, 0x76, 0x47, 0xb2, 0x26, 0xe5, 0x06, 0xe2, 0xec, 0x5a, 0x86, 0xfa,
    0xcc, 0x51, 0xce, 0xb0, 0x0b, 0xb7, 0xc5, 0xaa, 0xb7, 0xc4, 0x0e, 0xcf, 0xf8, 0x63, 0xad, 0x40,
    0x5d, 0x27, 0x54, 0x36, 0xbf, 0xb4, 0x6d, 0x8b, 0x03, 0x6d, 0x7b, 0x1f, 0x70, 0x91, 0x17, 0x2b,
    0xe1, 0x88, 0x16, 0x4c, 0xaf, 0x14, 0xf0, 0xc2, 0x3e, 0x64, 0x4c, 0x4a, 0x1e, 0xfd, 0xc3, 0xb1,
];

/// Message covered by the KAT signature.
const KAT_MSG: &[u8] = b"pqclib FIPS RSA-2048 PKCS1v15 SHA-256 power-up KAT";

/// Pinned RSASSA-PKCS1-v1_5 signature of `KAT_MSG` under `(KAT_N, KAT_E)`.
const KAT_SIG_BYTES: [u8; 256] = [
    0x12, 0x26, 0x65, 0x1f, 0x47, 0x0b, 0xc2, 0x86, 0x25, 0x6c, 0x3a, 0x92, 0xdb, 0x77, 0xee, 0x9a,
    0xeb, 0x44, 0x7b, 0xf0, 0x26, 0x57, 0xe3, 0xb3, 0x4a, 0x9d, 0x60, 0xba, 0xfd, 0x00, 0xb2, 0xae,
    0xc7, 0x54, 0xed, 0x16, 0x3d, 0x1a, 0x9c, 0x1e, 0xe1, 0x7e, 0xa9, 0x70, 0xdd, 0xa3, 0x9c, 0x5d,
    0x04, 0xa4, 0x56, 0xc7, 0x7e, 0x0c, 0x78, 0x5a, 0x22, 0x52, 0x29, 0x73, 0x0c, 0xc9, 0xa7, 0xc6,
    0x5f, 0xc0, 0x76, 0xe9, 0xc2, 0x3d, 0xa8, 0x2c, 0xf7, 0xfb, 0xc1, 0x13, 0xea, 0x7e, 0xef, 0xb7,
    0xf0, 0x50, 0xc8, 0x3b, 0xdb, 0x08, 0xfe, 0xd2, 0x7f, 0xa2, 0xe8, 0x20, 0x39, 0x9c, 0xfe, 0x5a,
    0x45, 0x91, 0xd9, 0xde, 0xf9, 0x21, 0xe6, 0x09, 0xb6, 0xb9, 0xc5, 0x1d, 0xb6, 0x39, 0x14, 0x3f,
    0xc9, 0x46, 0x07, 0x66, 0xb2, 0xb1, 0x70, 0x2d, 0x4c, 0x27, 0x94, 0x60, 0xc1, 0x5d, 0x3b, 0x8c,
    0xfd, 0x79, 0x5a, 0xff, 0xd1, 0xa3, 0x0e, 0xc2, 0xd9, 0xa5, 0x6f, 0xd2, 0xb4, 0x90, 0xa4, 0x8b,
    0x50, 0xab, 0x69, 0xad, 0xf1, 0x9f, 0x7a, 0xf2, 0x10, 0xa6, 0x9a, 0x27, 0x50, 0xc1, 0x11, 0x7b,
    0xaf, 0x77, 0x8b, 0xdd, 0x84, 0x93, 0xa3, 0xc3, 0x25, 0x9e, 0xda, 0x69, 0xb3, 0x32, 0x85, 0xeb,
    0x00, 0x08, 0x9f, 0x9d, 0xa8, 0x6d, 0x2a, 0x21, 0xd2, 0x97, 0xf4, 0x4a, 0xeb, 0xbb, 0x3d, 0x70,
    0x18, 0x42, 0xac, 0xb9, 0x04, 0xac, 0x93, 0x95, 0x6d, 0x43, 0x01, 0x70, 0xfe, 0x91, 0xd8, 0x44,
    0x97, 0xe3, 0x77, 0x29, 0x57, 0x8c, 0xf6, 0x48, 0x02, 0x35, 0xa4, 0x7a, 0x6a, 0x02, 0x60, 0x68,
    0x12, 0x94, 0x3e, 0x5f, 0x37, 0xb0, 0x70, 0x57, 0x90, 0xed, 0x50, 0x42, 0x96, 0x85, 0x1e, 0x1c,
    0x2c, 0x27, 0xc7, 0xa1, 0x6a, 0x87, 0xa7, 0x21, 0x86, 0x89, 0xec, 0xe6, 0x73, 0x3d, 0xf4, 0xcd,
];

/// Pinned PSS salt used by the power-up KAT. Derived deterministically
/// from `SHA-256("pqclib-pss-kat-salt-v1")` and fixed at 32 bytes
/// (`sLen = hLen`). The value itself is not secret — it is the fresh
/// salt a correctly-implemented PSS signer would have sampled on the
/// one invocation that produced `KAT_PSS_SIG_BYTES`.
const KAT_PSS_SALT: [u8; 32] = [
    0x2f, 0x2f, 0x43, 0x3a, 0xbc, 0x18, 0x81, 0x24, 0x32, 0xdd, 0x17, 0xa9, 0x40, 0xb3, 0x88, 0xb6,
    0x39, 0x3b, 0x39, 0x98, 0x63, 0x5e, 0xce, 0x23, 0x89, 0xca, 0xf0, 0x7d, 0x34, 0x78, 0xb7, 0x27,
];

/// Message covered by the PSS KAT signature.
const KAT_PSS_MSG: &[u8] = b"pqclib FIPS RSA-2048 PSS SHA-256 power-up KAT";

/// Pinned RSASSA-PSS signature of `KAT_PSS_MSG` under `(KAT_N, KAT_D)`
/// with salt `KAT_PSS_SALT`.
const KAT_PSS_SIG_BYTES: [u8; 256] = [
    0x97, 0x9a, 0x30, 0xd1, 0xd9, 0x2e, 0x5b, 0x7f, 0x23, 0x5f, 0x53, 0xf0, 0xc8, 0x27, 0xbd, 0xe1,
    0xee, 0x89, 0x06, 0xc4, 0x4d, 0x80, 0xba, 0x1b, 0x8d, 0x65, 0xc9, 0x4e, 0xbd, 0x34, 0x00, 0xd9,
    0x33, 0xa3, 0xf4, 0x76, 0xe0, 0x71, 0x5d, 0xea, 0xc4, 0x56, 0x8c, 0xda, 0xcb, 0x4b, 0xee, 0xea,
    0x1b, 0xaf, 0x47, 0xbd, 0x0d, 0xcc, 0x3d, 0x40, 0x8f, 0x79, 0xc7, 0xa9, 0x6d, 0x0d, 0xe2, 0x7f,
    0x07, 0x23, 0x05, 0x10, 0x65, 0xfd, 0x38, 0xab, 0x6c, 0x6c, 0x5d, 0x1a, 0x67, 0x1d, 0xa4, 0xd9,
    0x2a, 0x61, 0x84, 0xb1, 0xbf, 0xf0, 0x7a, 0xba, 0x53, 0xf4, 0xb5, 0x50, 0x98, 0x90, 0x22, 0xcb,
    0x6a, 0xb2, 0x9e, 0x6c, 0x0d, 0xf9, 0x0b, 0x41, 0xdd, 0x4c, 0x45, 0x66, 0x13, 0x20, 0xfc, 0x77,
    0x1e, 0x49, 0x4a, 0x2b, 0xcc, 0x2f, 0xc1, 0xde, 0x86, 0x50, 0xe7, 0x47, 0x44, 0xc1, 0xf7, 0xeb,
    0x92, 0x8c, 0xbb, 0xb3, 0x48, 0xff, 0x0c, 0xdb, 0xce, 0xb7, 0x8f, 0xb4, 0x45, 0xb5, 0xad, 0xfa,
    0xd6, 0x53, 0xef, 0xd6, 0x89, 0x6a, 0x59, 0x6c, 0x3a, 0x90, 0xa9, 0x71, 0xdd, 0x15, 0x41, 0x8c,
    0x51, 0x01, 0x0a, 0xea, 0xc6, 0x30, 0x67, 0x5a, 0xec, 0x1b, 0x06, 0xbc, 0xb8, 0xf9, 0x75, 0x24,
    0x4c, 0xbc, 0x3e, 0x3d, 0x5c, 0x84, 0x8e, 0xce, 0x23, 0xe8, 0x54, 0x03, 0x64, 0xb6, 0xef, 0x30,
    0xfd, 0x9e, 0xd4, 0x6c, 0x91, 0x94, 0x9d, 0x6c, 0xb5, 0x83, 0xfa, 0xc4, 0x69, 0xb6, 0x6b, 0x62,
    0x2f, 0x91, 0x8d, 0xb7, 0x02, 0xbc, 0xbf, 0xd5, 0x8c, 0x39, 0xa6, 0xc6, 0x4e, 0xc1, 0xf3, 0x8e,
    0x1c, 0x9c, 0xb2, 0x46, 0xed, 0x07, 0xf8, 0xe1, 0xa2, 0xf2, 0x82, 0x09, 0xf5, 0xbf, 0xe2, 0x5d,
    0x56, 0xbd, 0x5d, 0xe2, 0x2c, 0x70, 0x39, 0xfe, 0xb1, 0x1b, 0xde, 0x87, 0x74, 0x2a, 0x89, 0x31,
];

// ------------------------------------------------------------------
// Power-up known-answer test
// ------------------------------------------------------------------

/// Power-up KAT for the RSA-2048 PKCS#1 v1.5 / PSS SHA-256 services.
///
/// Runs, against the pinned `(n, e, d)` keypair:
///
/// 1. PKCS#1 v1.5 verify of the pinned signature.
/// 2. PKCS#1 v1.5 tamper-rejection (flip the trailing byte).
/// 3. PKCS#1 v1.5 sign reproduces the pinned signature byte-for-byte,
///    exercising the constant-time windowed ladder and EMSA encoder.
/// 4. Pairwise consistency on `(n, e, d)` for PKCS#1 v1.5.
/// 5. PSS sign with the pinned salt reproduces the pinned PSS
///    signature byte-for-byte, exercising MGF1, EMSA-PSS-ENCODE and
///    the same ladder path.
/// 6. PSS verify of the pinned PSS signature succeeds, exercising
///    EMSA-PSS-VERIFY and the public-exponent ladder.
/// 7. PSS tamper-rejection: flipping a byte in the `maskedDB` portion
///    of the signature is rejected — this specifically catches
///    breakage in the MGF1 mask recovery path, which a tamper on the
///    trailing `0xbc` would not.
pub fn self_test() -> Result<(), SelfTestFailure> {
    // PKCS#1 v1.5 verify (positive).
    if !rsa_pkcs1_v15_verify_2048_sha256_internal(&KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_SIG_BYTES) {
        return Err(SelfTestFailure);
    }
    // PKCS#1 v1.5 verify (tamper).
    let mut tampered = KAT_SIG_BYTES;
    tampered[255] ^= 0x01;
    if rsa_pkcs1_v15_verify_2048_sha256_internal(&KAT_N_BYTES, KAT_E, KAT_MSG, &tampered) {
        return Err(SelfTestFailure);
    }
    // PKCS#1 v1.5 sign (KAT reproduction).
    let Some(produced) =
        rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_D_BYTES, KAT_MSG)
    else {
        return Err(SelfTestFailure);
    };
    if produced != KAT_SIG_BYTES {
        return Err(SelfTestFailure);
    }
    // PCT.
    if !pairwise_consistency_test_2048_internal(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES) {
        return Err(SelfTestFailure);
    }
    // PSS sign (KAT reproduction).
    let Some(pss_produced) = rsa_pss_sign_2048_sha256_internal(
        &KAT_N_BYTES,
        &KAT_D_BYTES,
        KAT_PSS_MSG,
        &KAT_PSS_SALT,
    ) else {
        return Err(SelfTestFailure);
    };
    if pss_produced != KAT_PSS_SIG_BYTES {
        return Err(SelfTestFailure);
    }
    // PSS verify (positive).
    if !rsa_pss_verify_2048_sha256_internal(
        &KAT_N_BYTES,
        KAT_E,
        KAT_PSS_MSG,
        &KAT_PSS_SIG_BYTES,
    ) {
        return Err(SelfTestFailure);
    }
    // PSS verify (tamper inside maskedDB, not the trailer).
    let mut pss_tampered = KAT_PSS_SIG_BYTES;
    pss_tampered[10] ^= 0x01;
    if rsa_pss_verify_2048_sha256_internal(
        &KAT_N_BYTES,
        KAT_E,
        KAT_PSS_MSG,
        &pss_tampered,
    ) {
        return Err(SelfTestFailure);
    }
    Ok(())
}

// Silence an otherwise-unused re-export: downstream users of the
// crate may want the hash length constant without pulling in
// `fips-sha` directly.
#[doc(hidden)]
pub const __SHA256_DIGEST_SIZE: usize = SHA256_DIGEST_SIZE;

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use fips_module::{initialize_with_tests, KatEntry};

    #[test]
    fn kat_positive_verifies() {
        assert!(rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_flipped_signature() {
        let mut bad = KAT_SIG_BYTES;
        bad[128] ^= 0x80;
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &bad
        ));
    }

    #[test]
    fn kat_rejects_wrong_message() {
        let bad_msg = b"pqclib FIPS RSA-2048 PKCS1v15 SHA-256 power-up KAT (tampered)";
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, bad_msg, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_even_modulus() {
        let mut bad_n = KAT_N_BYTES;
        bad_n[255] &= 0xfe;
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &bad_n, KAT_E, KAT_MSG, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_signature_ge_modulus() {
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_N_BYTES
        ));
    }

    #[test]
    fn sign_reproduces_pinned_signature() {
        let produced =
            rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_D_BYTES, KAT_MSG).unwrap();
        assert_eq!(produced, KAT_SIG_BYTES);
    }

    #[test]
    fn sign_then_verify_roundtrips_for_multiple_messages() {
        let messages: [&[u8]; 4] = [
            b"",
            b"a",
            b"The quick brown fox jumps over the lazy dog",
            &[0xa5u8; 256],
        ];
        for msg in messages {
            let sig =
                rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_D_BYTES, msg).unwrap();
            assert!(rsa_pkcs1_v15_verify_2048_sha256_internal(
                &KAT_N_BYTES, KAT_E, msg, &sig
            ));
        }
    }

    #[test]
    fn sign_rejects_d_equal_to_n() {
        // d must be strictly less than n; using n-as-d should be
        // rejected for the same reason signatures are.
        assert!(
            rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_N_BYTES, KAT_MSG).is_none()
        );
    }

    #[test]
    fn pct_passes_on_pinned_keypair() {
        assert!(pairwise_consistency_test_2048_internal(
            &KAT_N_BYTES, KAT_E, &KAT_D_BYTES
        ));
    }

    #[test]
    fn pct_fails_when_d_is_tampered() {
        let mut bad_d = KAT_D_BYTES;
        bad_d[0] ^= 0x01;
        assert!(!pairwise_consistency_test_2048_internal(
            &KAT_N_BYTES, KAT_E, &bad_d
        ));
    }

    #[test]
    fn pct_fails_when_e_is_wrong() {
        // Using e = 3 against a key that was generated with e = 65537
        // must fail the PCT because 3 is coprime with phi and the
        // wrong exponent will produce nonsense signatures.
        assert!(!pairwise_consistency_test_2048_internal(
            &KAT_N_BYTES, 3, &KAT_D_BYTES
        ));
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn private_key_construction_runs_pct_and_signs() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-pkcs1v15-sha256",
            run: self_test,
        }]);
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES)
            .expect("pinned keypair passes PCT");
        let sig = sk
            .sign_pkcs1_v15_sha256(KAT_MSG)
            .expect("module operational, sign succeeds");
        assert_eq!(sig, KAT_SIG_BYTES);
        rsa_pkcs1_v15_verify_2048_sha256(&KAT_N_BYTES, KAT_E, KAT_MSG, &sig)
            .expect("freshly produced signature verifies");
    }

    #[test]
    fn pss_kat_sign_reproduces_pinned_signature() {
        let produced = rsa_pss_sign_2048_sha256_internal(
            &KAT_N_BYTES,
            &KAT_D_BYTES,
            KAT_PSS_MSG,
            &KAT_PSS_SALT,
        )
        .unwrap();
        assert_eq!(produced, KAT_PSS_SIG_BYTES);
    }

    #[test]
    fn pss_kat_positive_verifies() {
        assert!(rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &KAT_PSS_SIG_BYTES
        ));
    }

    #[test]
    fn pss_rejects_flipped_trailer() {
        let mut bad = KAT_PSS_SIG_BYTES;
        bad[255] ^= 0x01;
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &bad
        ));
    }

    #[test]
    fn pss_rejects_tamper_in_masked_db() {
        // A flip inside the maskedDB half of the signature perturbs
        // the recovered DB once MGF1 unmasks it, which should fail
        // either the PS-zeroes check or the H' compare.
        let mut bad = KAT_PSS_SIG_BYTES;
        bad[0] ^= 0x40;
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &bad
        ));
    }

    #[test]
    fn pss_rejects_wrong_message() {
        let bad_msg = b"pqclib FIPS RSA-2048 PSS SHA-256 power-up KAT (tampered)";
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            bad_msg,
            &KAT_PSS_SIG_BYTES
        ));
    }

    #[test]
    fn pss_sign_verify_roundtrips_across_salts_and_messages() {
        let messages: [&[u8]; 4] = [
            b"",
            b"a",
            b"The quick brown fox jumps over the lazy dog",
            &[0x5au8; 512],
        ];
        let salts: [[u8; 32]; 2] = [[0u8; 32], [0xa5u8; 32]];
        for msg in messages {
            for salt in &salts {
                let sig = rsa_pss_sign_2048_sha256_internal(
                    &KAT_N_BYTES,
                    &KAT_D_BYTES,
                    msg,
                    salt,
                )
                .unwrap();
                assert!(rsa_pss_verify_2048_sha256_internal(
                    &KAT_N_BYTES,
                    KAT_E,
                    msg,
                    &sig
                ));
            }
        }
    }

    #[test]
    fn pss_cross_scheme_signature_does_not_verify_as_pkcs1() {
        // A PSS signature must not accidentally verify as a PKCS#1
        // v1.5 signature over the same message, and vice-versa.
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &KAT_PSS_SIG_BYTES
        ));
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_MSG,
            &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn private_key_sign_pss_then_public_verify() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-pkcs1v15-sha256",
            run: self_test,
        }]);
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES)
            .expect("pinned keypair passes PCT");
        let sig = sk
            .sign_pss_sha256_with_salt(KAT_PSS_MSG, &KAT_PSS_SALT)
            .expect("module operational, PSS sign succeeds");
        assert_eq!(sig, KAT_PSS_SIG_BYTES);
        rsa_pss_verify_2048_sha256(&KAT_N_BYTES, KAT_E, KAT_PSS_MSG, &sig)
            .expect("pinned PSS signature verifies via gated API");
    }

    #[test]
    fn private_key_construction_rejects_bad_d() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-pkcs1v15-sha256",
            run: self_test,
        }]);
        let mut bad_d = KAT_D_BYTES;
        bad_d[255] ^= 0x01;
        match RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &bad_d) {
            Err(Error::InvalidInput) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("PCT must reject a tampered d"),
        }
    }
}
