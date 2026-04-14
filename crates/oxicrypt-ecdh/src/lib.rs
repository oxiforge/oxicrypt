//! ECDH per SP 800-56Ar3.
//!
//! # Approved services
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | P-256 ECC CDH shared secret | SP 800-56Ar3 §5.7.1.2 | [`compute_shared_secret_p256`] |
//! | P-384 ECC CDH shared secret (stub) | SP 800-56Ar3 | [`compute_shared_secret_p384`] |
//!
//! Currently supports only curve P-256 with a full implementation.
//! P-384 is present as a stub (returns `NotImplemented`) via the SP 800-56Ar3
//! §5.7.1.2 "elliptic curve Diffie-Hellman" primitive (ECC CDH):
//!
//! ```text
//!   Z = x( d_A * Q_B )
//! ```
//!
//! where `d_A` is the caller's static or ephemeral private key,
//! `Q_B` is the peer's public key, and `Z` is the 32-byte big-endian
//! x-coordinate of the resulting point. The shared secret `Z` is
//! raw; callers that need an approved key-derivation step must feed
//! `Z` into an SP 800-56C Rev. 2 extractor (HKDF, KDF in Counter
//! Mode, etc.) — this crate intentionally does not bundle a KDF.
//!
//! # Public-key validation
//!
//! Peer public keys are subject to **full** public-key validation
//! per SP 800-56Ar3 §5.6.2.3.3: canonical SEC1 uncompressed encoding
//! (`0x04 || X || Y`), coordinate canonicality (`0 ≤ X, Y < p`),
//! non-identity, and the on-curve equation
//! `y² ≡ x³ − 3x + b (mod p)`. The cofactor-1 property of P-256
//! makes the order check vacuous. A peer key that fails any of
//! these checks causes [`compute_shared_secret_p256`] to return an
//! error *without* performing the scalar multiplication.
//!
//! # Power-up self-tests
//!
//! [`self_test`] runs the RFC 5903 §8.1 ECDH-P-256 test vector in
//! both directions (`d_i * Q_r` and `d_r * Q_i`) and also checks
//! that a tampered peer key is rejected by public-key validation.
//!
//! # Conditional self-tests
//!
//! Full peer-public-key validation per SP 800-56Ar3 §5.6.2.3.3 is
//! a conditional test that runs on every ECDH call. Private-scalar
//! canonicality (`1 ≤ d < n`) is checked alongside.
//!
//! # Sensitive security parameters
//!
//! - **Private key `d`** (`[u8; 32]`) — CSP. Canonicalized to a
//!   `Scalar` in-place and not retained beyond the call.
//! - **Shared secret `Z`** (`[u8; 32]`) — CSP. Returned raw; the
//!   caller is responsible for feeding it into an SP 800-56Cr2
//!   extractor before use as keying material.
//! - **Peer public key `Q`** — public. Subject to full validation.
//!
//! # Side-channel posture
//!
//! Scalar multiplication is constant-time in `d` via the underlying
//! `fips-ecdsa::p256_point` ladder; public-key validation branches
//! only on public data. Level-1 disclosure only.
//!
//! # FIPS module gating
//!
//! The public entry point gates on
//! [`oxicrypt_module::require_operational`]; a hidden
//! `compute_shared_secret_p256_internal` primitive bypasses the
//! gate so the power-up KAT in [`self_test`] can run while the
//! module is still in `SelfTest`.
#![no_std]
#![forbid(unsafe_code)]
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use oxicrypt_ecdsa::p256_point::Point;
use oxicrypt_ecdsa::p256_scalar::Scalar;
use oxicrypt_module::{require_operational, Error, KatEntry, SelfTestFailure};

/// Length of a P-256 private-key scalar in bytes.
pub const PRIVATE_KEY_LEN: usize = 32;
/// Length of an uncompressed SEC1 public-key encoding.
pub const PUBLIC_KEY_LEN: usize = 65;
/// Length of the raw ECDH shared secret `Z` in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

// ------------------------------------------------------------------
// Core primitive (state-gate-free)
// ------------------------------------------------------------------

/// Compute the SP 800-56Ar3 §5.7.1.2 ECC CDH primitive for P-256:
/// `Z = x( d * Q )`.
///
/// Returns `None` when `d` is not a valid non-zero scalar mod `n`,
/// when `Q` fails SP 800-56Ar3 §5.6.2.3.3 public-key validation, or
/// when the scalar multiplication yields the point at infinity (the
/// "`Z` is the identity" shall-fail case in §5.7.1.2). This function
/// bypasses the FIPS module state gate so it can be called from the
/// power-up KAT runner; production callers should use
/// [`compute_shared_secret_p256`] instead.
#[doc(hidden)]
pub fn compute_shared_secret_p256_internal(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    peer_pk: &[u8; PUBLIC_KEY_LEN],
) -> Option<[u8; SHARED_SECRET_LEN]> {
    // Caller private key must be a canonical non-zero scalar in
    // [1, n-1]. The ECDH primitive itself doesn't require d != 0,
    // but Z = 0 * Q = O and we would immediately reject that below;
    // failing here lets us return early with a clearer reason.
    let d = Scalar::from_bytes(d_bytes)?;
    if d.is_zero() == 1 {
        return None;
    }

    // Peer public key: full SP 800-56Ar3 §5.6.2.3.3 validation.
    let q = Point::from_sec1_uncompressed_validated(peer_pk)?;

    // Z_point = d * Q. Our scalar-mul ladder is constant time in `d`.
    let z_point = q.mul(&d);

    // SP 800-56Ar3 §5.7.1.2 step 2: if the result is the identity,
    // output "error". For P-256 (cofactor 1, prime order), this
    // only happens when d ≡ 0 mod n, which we rejected above, or
    // when Q has order dividing d — impossible on a prime-order
    // curve with d in [1, n-1]. We still check it explicitly so
    // the code is correct for any future curve that lands here.
    let (zx, _zy) = z_point.to_affine()?;
    Some(zx.to_bytes())
}

// ------------------------------------------------------------------
// Public, gated entry point
// ------------------------------------------------------------------

/// Compute the P-256 ECDH shared secret `Z = x(d * Q)`.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the containing FIPS module
/// has not finished its power-up self-tests, or [`Error::InvalidInput`]
/// if `d` is not a valid non-zero scalar or `peer_pk` fails SP
/// 800-56Ar3 §5.6.2.3.3 public-key validation.
pub fn compute_shared_secret_p256(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    peer_pk: &[u8; PUBLIC_KEY_LEN],
) -> Result<[u8; SHARED_SECRET_LEN], Error> {
    require_operational()?;
    compute_shared_secret_p256_internal(d_bytes, peer_pk).ok_or(Error::InvalidInput)
}

// ------------------------------------------------------------------
// P-384 stub (CNSA 1.0)
// ------------------------------------------------------------------

/// Compute the P-384 ECDH shared secret.
///
/// # Status
///
/// **Stub.** The P-384 curve arithmetic has not been implemented
/// yet. This entry point is gated on the algorithm profile and
/// will return [`Error::NotImplemented`].
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn compute_shared_secret_p384(
    _d_bytes: &[u8],
    _peer_pk: &[u8],
) -> Result<(), Error> {
    require_operational()?;
    oxicrypt_module::require_allowed(oxicrypt_module::Service::EcdhP384)?;
    Err(Error::NotImplemented)
}

// ------------------------------------------------------------------
// Power-up known-answer test (RFC 5903 §8.1, ECDH P-256)
// ------------------------------------------------------------------

/// Initiator's static private key `d_i` from RFC 5903 §8.1.
const KAT_D_I: [u8; 32] = [
    0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31, 0x6d, 0xe5,
    0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33,
];

/// Initiator's uncompressed SEC1 public key `Q_i` (`0x04 || x_i || y_i`).
const KAT_Q_I: [u8; 65] = [
    0x04, //
    0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9, 0xb0, 0x51, 0xe1, 0xfe, 0xca, 0x57, 0x87, 0xd0,
    0x98, 0xdf, 0xe6, 0x37, 0xfc, 0x90, 0xb9, 0xef, 0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11, 0x80,
    0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52, 0xd6, 0x1f, 0x1c, 0x45, 0x6f, 0xa3, 0xe5, 0x9a,
    0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf, 0x5f, 0x58, 0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b, 0xb3,
];

/// Responder's static private key `d_r`.
const KAT_D_R: [u8; 32] = [
    0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97, 0xce, 0x20,
    0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53,
];

/// Responder's uncompressed SEC1 public key `Q_r`.
const KAT_Q_R: [u8; 65] = [
    0x04, //
    0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c, 0x34,
    0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63,
    0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d, 0x6a,
    0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab,
];

/// Expected shared secret `Z` (x-coordinate of `d_i * Q_r == d_r * Q_i`).
const KAT_Z: [u8; 32] = [
    0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25, 0x65, 0x20,
    0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03, 0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde,
];

/// Power-up known-answer test for ECDH P-256. Runs the RFC 5903
/// §8.1 vector in both directions and checks that flipping a byte
/// of the peer key causes rejection.
pub fn self_test() -> Result<(), SelfTestFailure> {
    // Positive 1: d_i * Q_r == Z.
    let z1 = compute_shared_secret_p256_internal(&KAT_D_I, &KAT_Q_R).ok_or(SelfTestFailure)?;
    if z1 != KAT_Z {
        return Err(SelfTestFailure);
    }

    // Positive 2: d_r * Q_i == Z (symmetry of ECDH).
    let z2 = compute_shared_secret_p256_internal(&KAT_D_R, &KAT_Q_I).ok_or(SelfTestFailure)?;
    if z2 != KAT_Z {
        return Err(SelfTestFailure);
    }

    // Negative: a tampered peer key must be rejected by public-key
    // validation before any scalar multiplication happens.
    let mut tampered = KAT_Q_R;
    tampered[64] ^= 0x01;
    if compute_shared_secret_p256_internal(&KAT_D_I, &tampered).is_some() {
        return Err(SelfTestFailure);
    }

    Ok(())
}

/// Power-up KATs exported by this crate.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "ECDH-P256 KAT (RFC 5903 §8.1 both directions + tamper, SP 800-56Ar3)",
    run: self_test,
}];

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use oxicrypt_module::{initialize_with_tests, KatEntry};

    #[test]
    fn kat_initiator_to_responder_matches_rfc5903() {
        let z = compute_shared_secret_p256_internal(&KAT_D_I, &KAT_Q_R).unwrap();
        assert_eq!(z, KAT_Z);
    }

    #[test]
    fn kat_responder_to_initiator_matches_rfc5903() {
        let z = compute_shared_secret_p256_internal(&KAT_D_R, &KAT_Q_I).unwrap();
        assert_eq!(z, KAT_Z);
    }

    #[test]
    fn rejects_tampered_peer_key_x() {
        let mut tampered = KAT_Q_R;
        tampered[1] ^= 0x01;
        assert!(compute_shared_secret_p256_internal(&KAT_D_I, &tampered).is_none());
    }

    #[test]
    fn rejects_tampered_peer_key_y() {
        let mut tampered = KAT_Q_R;
        tampered[64] ^= 0x01;
        assert!(compute_shared_secret_p256_internal(&KAT_D_I, &tampered).is_none());
    }

    #[test]
    fn rejects_peer_key_with_wrong_header() {
        let mut bad = KAT_Q_R;
        bad[0] = 0x02;
        assert!(compute_shared_secret_p256_internal(&KAT_D_I, &bad).is_none());
    }

    #[test]
    fn rejects_identity_peer_key_encoding() {
        // 0x04 || 00..00 || 00..00. Rejected by the validated decoder.
        let mut encoding = [0u8; 65];
        encoding[0] = 0x04;
        assert!(compute_shared_secret_p256_internal(&KAT_D_I, &encoding).is_none());
    }

    #[test]
    fn rejects_zero_private_key() {
        let zero = [0u8; 32];
        assert!(compute_shared_secret_p256_internal(&zero, &KAT_Q_R).is_none());
    }

    #[test]
    fn rejects_private_key_equal_to_n() {
        // n in big-endian — not a canonical scalar (>= n).
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        assert!(compute_shared_secret_p256_internal(&n_bytes, &KAT_Q_R).is_none());
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn public_api_gated_on_operational() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "ecdh-p256",
            run: self_test,
        }]);
        let z = compute_shared_secret_p256(&KAT_D_I, &KAT_Q_R).expect("module operational");
        assert_eq!(z, KAT_Z);
    }
}
