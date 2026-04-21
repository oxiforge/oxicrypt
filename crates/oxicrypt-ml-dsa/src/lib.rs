//! ML-DSA-87 (FIPS 204) — lattice-based digital signature algorithm.
//!
//! # Status
//!
//! **Implemented.**  This crate provides the full ML-DSA-87 digital
//! signature algorithm as specified in FIPS 204 (August 2024), including
//! key generation, deterministic signing (rejection sampling), and
//! signature verification.
//!
//! ML-DSA-87 is the CNSA 2.0 digital-signature algorithm, mandated for
//! software and firmware signing by the 2025 deadline.
//!
//! # Approved services
//!
//! | Service | Description |
//! |---------|-------------|
//! | `MlDsa87Keygen` | Generate an ML-DSA-87 key pair |
//! | `MlDsa87Sign`   | Sign a message with ML-DSA-87 |
//! | `MlDsa87Verify` | Verify an ML-DSA-87 signature |
//!
//! All three services are gated by
//! [`AlgorithmProfile`](oxicrypt_module::AlgorithmProfile): allowed in
//! `Unrestricted` and `Cnsa2`.
//!
//! # Parameters (FIPS 204 Table 1, ML-DSA-87)
//!
//! | Parameter | Value |
//! |-----------|-------|
//! | n         | 256   |
//! | q         | 8380417 |
//! | k         | 8     |
//! | l         | 7     |
//! | η         | 2     |
//! | τ         | 60    |
//! | β         | 120   |
//! | γ₁        | 2¹⁹  |
//! | γ₂        | (q−1)/32 = 261888 |
//! | ω         | 75    |
//! | d         | 13    |
//! | Public key  | 2592 bytes |
//! | Secret key  | 4896 bytes |
//! | Signature   | 4627 bytes |
//!
//! # Power-up self-tests
//!
//! [`KATS`] contains a deterministic round-trip test: keygen from a
//! fixed seed, sign a fixed message, verify the signature.
//!
//! # Sensitive security parameters
//!
//! | SSP | Description | Zeroization |
//! |-----|-------------|-------------|
//! | sk  | Secret key (4896 bytes) | Caller responsibility |
//! | ξ   | Keygen randomness (32 bytes) | Caller responsibility |
//! | s₁, s₂ | Secret vectors | Embedded in sk |
//! | K   | Signing key seed (32 bytes) | Embedded in sk |
//!
//! # External vs internal API
//!
//! The public [`sign`] and [`verify`] functions implement the
//! **external** ML-DSA.Sign / ML-DSA.Verify API defined in FIPS 204
//! §5.2 (Algorithms 2 and 3): they accept a `ctx` byte string and frame
//! the message as `M' = 0x00 || |ctx| || ctx || M` before invoking the
//! internal primitive.  This is the shape consumed by X.509, CMS, the
//! LAMPS profile, OpenSSL 3.5, and any other spec-conformant caller —
//! `ctx` is `b""` for those use cases.
//!
//! The `*_internal` surface ([`sign_internal`], [`verify_internal`])
//! exposes Algorithms 7 and 8 directly (`Sign_internal` /
//! `Verify_internal` in §6.2 / §6.3) — the raw-message primitive with
//! no framing.  These are `#[doc(hidden)]` and intended for FIPS 204
//! CAVP / ACVP test harnesses that exercise the internal primitive.
//!
//! # FIPS module gating
//!
//! Public entry points ([`keygen`], [`sign`], [`verify`]) gate on
//! [`oxicrypt_module::require_operational`] and
//! [`oxicrypt_module::require_allowed`].  The `*_internal` surface
//! (hidden) runs gate-free so power-up KATs can execute during
//! `SelfTest`.
//!
//! # Constant-time behaviour
//!
//! The signing rejection loop iteration count leaks information about
//! the secret key; this is a known and accepted property of Fiat-Shamir
//! with aborts signatures (NIST accepts this for ML-DSA).  Within each
//! iteration, norm checks and coefficient comparisons use
//! data-independent control flow.  NTT operations have data-independent
//! control flow.

#![no_std]
#![forbid(unsafe_code)]

mod dsa;
mod encode;
mod field;
mod ntt;
/// ML-DSA-87 parameter constants.
pub mod params;
mod poly;
mod rounding;
mod sample;

use oxicrypt_module::{Error, KatEntry, SelfTestFailure, Service};
pub use params::{PK_LEN, SIG_LEN, SK_LEN};

// ── Public API (gated) ──────────────────────────────────────────

/// Generate an ML-DSA-87 key pair.
///
/// `xi` must be 32 bytes of fresh randomness from an approved DRBG
/// (SP 800-90A).
///
/// Returns `(pk, sk)`: the public key and secret key.
pub fn keygen(xi: &[u8; 32]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlDsa87Keygen)?;
    Ok(keygen_internal(xi))
}

/// Sign a message with an ML-DSA-87 secret key (deterministic mode).
///
/// This is the **external** ML-DSA.Sign API defined in FIPS 204 §5.2
/// Algorithm 2: it frames the message as `M' = 0x00 || |ctx| || ctx || M`
/// (pure ML-DSA, empty or caller-supplied context) before applying the
/// internal signing primitive (Algorithm 7, §6.2).
///
/// `ctx` is the application-supplied context string. Pass `b""` for
/// the empty context used by X.509, CMS, and other LAMPS-conformant
/// callers.
///
/// Returns the 4627-byte signature.
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids ML-DSA-87.
/// - [`Error::InvalidInput`] if `ctx.len() > 255` (FIPS 204 §5.2 limit) or
///   signing fails after the rejection-sampling bound.
pub fn sign(
    sk: &[u8; SK_LEN],
    message: &[u8],
    ctx: &[u8],
) -> Result<[u8; SIG_LEN], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlDsa87Sign)?;
    let prefix_buf = build_external_prefix(ctx)?;
    dsa::ml_dsa_sign(sk, prefix_buf.as_slice(), message).ok_or(Error::InvalidInput)
}

/// Verify a signature with an ML-DSA-87 public key.
///
/// This is the **external** ML-DSA.Verify API defined in FIPS 204 §5.2
/// Algorithm 3: it frames the message as `M' = 0x00 || |ctx| || ctx || M`
/// (pure ML-DSA, empty or caller-supplied context) before applying the
/// internal verification primitive (Algorithm 8, §6.3).
///
/// `ctx` is the application-supplied context string. Pass `b""` for the
/// empty context used by X.509, CMS, and other LAMPS-conformant callers.
///
/// Returns `Ok(())` if the signature is valid, `Err(InvalidInput)`
/// otherwise.
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids ML-DSA-87.
/// - [`Error::InvalidInput`] if `ctx.len() > 255` (FIPS 204 §5.2 limit)
///   or the signature fails verification.
pub fn verify(
    pk: &[u8; PK_LEN],
    message: &[u8],
    ctx: &[u8],
    sig: &[u8; SIG_LEN],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlDsa87Verify)?;
    let prefix_buf = build_external_prefix(ctx)?;
    if dsa::ml_dsa_verify(pk, prefix_buf.as_slice(), message, sig) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Maximum size of the external API framing prefix: 2 header bytes
/// (`0x00` domain separator + `|ctx|` length byte) plus the 255-byte
/// ctx cap from FIPS 204 §5.2.
const EXT_PREFIX_MAX: usize = 2 + 255;

/// Stack-allocated `0x00 || |ctx| || ctx` buffer for the external
/// ML-DSA.{Sign,Verify} framing.  Keeps the crate free of any heap
/// allocation while still supporting the full FIPS 204 §5.2 ctx range.
struct ExternalPrefix {
    buf: [u8; EXT_PREFIX_MAX],
    len: usize,
}

impl ExternalPrefix {
    // Range slice is sound by construction: `len` is written exactly
    // once by `build_external_prefix` as `2 + ctx.len()` with
    // `ctx.len() ≤ 255`, so `len ≤ EXT_PREFIX_MAX`.
    #[allow(clippy::indexing_slicing)]
    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

// Arithmetic and slicing are sound by construction: the early-return
// on `ctx.len() > 255` establishes `2 + ctx.len() ≤ EXT_PREFIX_MAX`,
// so the following index operations cannot overflow or panic.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]
fn build_external_prefix(ctx: &[u8]) -> Result<ExternalPrefix, Error> {
    if ctx.len() > 255 {
        return Err(Error::InvalidInput);
    }
    let mut buf = [0u8; EXT_PREFIX_MAX];
    buf[0] = 0x00; // pure ML-DSA (HashML-DSA would use 0x01)
    buf[1] = ctx.len() as u8;
    buf[2..2 + ctx.len()].copy_from_slice(ctx);
    Ok(ExternalPrefix { buf, len: 2 + ctx.len() })
}

// ── Internal API (gate-free, for KATs) ──────────────────────────

/// Internal keygen — no module gate.
#[doc(hidden)]
pub fn keygen_internal(xi: &[u8; 32]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
    dsa::ml_dsa_keygen(xi)
}

/// Internal sign — FIPS 204 §6.2 Algorithm 7 (Sign_internal).
///
/// Operates directly on the raw message with no external-API framing,
/// matching the `ML-DSA.Sign_internal` abstraction used by FIPS 204
/// CAVP / ACVP test vectors.  Gate-free so power-up KATs can run
/// during `SelfTest`.
#[doc(hidden)]
pub fn sign_internal(sk: &[u8; SK_LEN], message: &[u8]) -> Option<[u8; SIG_LEN]> {
    dsa::ml_dsa_sign(sk, &[], message)
}

/// Internal verify — FIPS 204 §6.3 Algorithm 8 (Verify_internal).
///
/// Operates directly on the raw message with no external-API framing.
/// Gate-free so power-up KATs can run during `SelfTest`.
#[doc(hidden)]
pub fn verify_internal(pk: &[u8; PK_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    dsa::ml_dsa_verify(pk, &[], message, sig)
}

// ── Power-up KATs ───────────────────────────────────────────────

/// Power-up KATs for ML-DSA-87.
///
/// Contains a deterministic keygen → sign → verify round-trip test,
/// plus a negative test confirming that a tampered signature fails
/// verification.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "ML-DSA-87 KAT (keygen + sign + verify round-trip, FIPS 204)",
    run: self_test,
}];

/// Deterministic KAT seed for keygen.
const KAT_XI: [u8; 32] = [
    0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
    0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xaf, 0xfa, 0x28, 0x4f, 0x01,
];

/// Test message for KAT.
const KAT_MSG: &[u8] = b"ML-DSA-87 self-test message for FIPS 204 compliance";

/// Self-test: deterministic keygen → sign → verify round-trip +
/// negative (tamper) test.
fn self_test() -> Result<(), SelfTestFailure> {
    // 1. KeyGen
    let (pk, sk) = keygen_internal(&KAT_XI);

    // 2. Sign
    let Some(sig) = sign_internal(&sk, KAT_MSG) else {
        return Err(SelfTestFailure);
    };

    // 3. Verify (positive)
    if !verify_internal(&pk, KAT_MSG, &sig) {
        return Err(SelfTestFailure);
    }

    // 4. Verify with wrong message (negative)
    if verify_internal(&pk, b"wrong message", &sig) {
        return Err(SelfTestFailure);
    }

    // 5. Verify with tampered signature (negative)
    let mut sig_bad = sig;
    sig_bad[100] ^= 0x01;
    if verify_internal(&pk, KAT_MSG, &sig_bad) {
        return Err(SelfTestFailure);
    }

    Ok(())
}

// ── Unit tests ──────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn round_trip_basic() {
        let xi = [0x42u8; 32];
        let (pk, sk) = keygen_internal(&xi);
        let msg = b"hello, ML-DSA-87";
        let sig = sign_internal(&sk, msg).unwrap();
        assert!(
            verify_internal(&pk, msg, &sig),
            "round-trip failed: valid signature rejected"
        );
    }

    #[test]
    fn wrong_message_rejected() {
        let xi = [0x01u8; 32];
        let (pk, sk) = keygen_internal(&xi);
        let sig = sign_internal(&sk, b"original").unwrap();
        assert!(
            !verify_internal(&pk, b"tampered", &sig),
            "wrong message should fail verification"
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let xi = [0x55u8; 32];
        let (pk, sk) = keygen_internal(&xi);
        let msg = b"test message";
        let mut sig = sign_internal(&sk, msg).unwrap();
        sig[50] ^= 0xFF;
        assert!(
            !verify_internal(&pk, msg, &sig),
            "tampered signature should fail"
        );
    }

    #[test]
    fn deterministic_signing() {
        let xi = [0xABu8; 32];
        let (_pk, sk) = keygen_internal(&xi);
        let msg = b"deterministic test";
        let sig1 = sign_internal(&sk, msg).unwrap();
        let sig2 = sign_internal(&sk, msg).unwrap();
        assert_eq!(
            sig1, sig2,
            "deterministic signing should produce identical signatures"
        );
    }

    #[test]
    fn key_sizes_match_spec() {
        assert_eq!(PK_LEN, 2592);
        assert_eq!(SK_LEN, 4896);
        assert_eq!(SIG_LEN, 4627);
    }

    #[test]
    fn different_seeds_different_keys() {
        let (pk1, _) = keygen_internal(&[0x10u8; 32]);
        let (pk2, _) = keygen_internal(&[0x20u8; 32]);
        assert_ne!(pk1, pk2, "different seeds should produce different keys");
    }

    #[test]
    fn wrong_key_rejects() {
        let xi1 = [0x01u8; 32];
        let xi2 = [0x02u8; 32];
        let (pk1, _) = keygen_internal(&xi1);
        let (_, sk2) = keygen_internal(&xi2);
        let msg = b"cross-key test";
        let sig = sign_internal(&sk2, msg).unwrap();
        assert!(
            !verify_internal(&pk1, msg, &sig),
            "signature from different key should fail"
        );
    }
}

/// Internal test: field arithmetic, NTT roundtrips.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
mod internal_tests {
    use crate::field::{fqmul, montgomery_reduce, reduce32, to_mont};
    use crate::ntt;
    use crate::params::N;

    #[test]
    fn montgomery_to_mont_gives_r_mod_q() {
        let r_mod_q = reduce32(to_mont(1));
        assert_eq!(r_mod_q, 4193792); // R mod q = 2^32 mod 8380417
    }

    #[test]
    fn montgomery_fqmul_by_r_is_identity() {
        let r_mod_q = reduce32(to_mont(1));
        assert_eq!(reduce32(fqmul(12345, r_mod_q)), 12345);
    }

    #[test]
    fn montgomery_reduce_a_times_r() {
        let r = montgomery_reduce(42 * (1i64 << 32));
        assert_eq!(reduce32(r), 42);
    }

    #[test]
    fn ntt_pointwise_roundtrip() {
        let mut p = [0i32; N];
        for (i, coeff) in p.iter_mut().enumerate() {
            *coeff = i as i32;
        }
        let original = p;

        let mut one = [0i32; N];
        one[0] = 1;
        ntt::ntt(&mut one);

        ntt::ntt(&mut p);
        let mut result = [0i32; N];
        ntt::pointwise_mul(&mut result, &p, &one);
        ntt::inv_ntt(&mut result);

        for i in 0..N {
            assert_eq!(
                reduce32(result[i]),
                original[i],
                "roundtrip failed at index {i}"
            );
        }
    }
}
