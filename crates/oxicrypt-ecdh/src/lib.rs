//! ECDH per SP 800-56Ar3.
//!
//! # Approved services
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | P-256 ECC CDH shared secret | SP 800-56Ar3 §5.7.1.2 | [`compute_shared_secret_p256`] |
//! | P-384 ECC CDH shared secret | SP 800-56Ar3 §5.7.1.2 | [`compute_shared_secret_p384`] |
//!
//! Both curves implement the SP 800-56Ar3 §5.7.1.2 "elliptic curve
//! Diffie-Hellman" primitive (ECC CDH):
//!
//! ```text
//!   Z = x( d_A * Q_B )
//! ```
//!
//! where `d_A` is the caller's static or ephemeral private key,
//! `Q_B` is the peer's public key, and `Z` is the big-endian
//! x-coordinate of the resulting point (32 bytes for P-256, 48
//! bytes for P-384). The shared secret `Z` is raw; callers that
//! need an approved key-derivation step must feed `Z` into an
//! SP 800-56C Rev. 2 extractor (HKDF, KDF in Counter Mode,
//! etc.) — this crate intentionally does not bundle a KDF.
//!
//! # Public-key validation
//!
//! Peer public keys are subject to **full** public-key validation
//! per SP 800-56Ar3 §5.6.2.3.3: canonical SEC1 uncompressed encoding
//! (`0x04 || X || Y`), coordinate canonicality (`0 ≤ X, Y < p`),
//! non-identity, and the on-curve equation
//! `y² ≡ x³ − 3x + b (mod p)`. Both P-256 and P-384 have
//! cofactor 1, making the order check vacuous. A peer key that
//! fails any of these checks causes the compute function to return
//! an error *without* performing the scalar multiplication.
//!
//! # Power-up self-tests
//!
//! [`self_test`] runs the RFC 5903 §8.1 ECDH-P-256 test vector and
//! [`self_test_p384`] runs the RFC 5903 §8.2 ECDH-P-384 test vector,
//! each in both directions (`d_i * Q_r` and `d_r * Q_i`) and also
//! checks that a tampered peer key is rejected by public-key
//! validation.
//!
//! # Conditional self-tests
//!
//! Full peer-public-key validation per SP 800-56Ar3 §5.6.2.3.3 is
//! a conditional test that runs on every ECDH call for both curves.
//! Private-scalar canonicality (`1 ≤ d < n`) is checked alongside.
//!
//! # Sensitive security parameters
//!
//! - **Private key `d`** (`[u8; 32]` for P-256, `[u8; 48]` for
//!   P-384) — CSP. Canonicalized to a `Scalar` / `Scalar384`
//!   in-place and not retained beyond the call.
//! - **Shared secret `Z`** (`[u8; 32]` for P-256, `[u8; 48]`
//!   for P-384) — CSP. Returned raw; the caller is responsible
//!   for feeding it into an SP 800-56Cr2 extractor before use
//!   as keying material.
//! - **Peer public key `Q`** — public. Subject to full validation.
//!
//! # Side-channel posture
//!
//! Scalar multiplication is constant-time in `d` via the underlying
//! `p256_point` / `p384_point` ladders; public-key validation
//! branches only on public data. Level-1 disclosure only.
//!
//! # FIPS module gating
//!
//! Public entry points gate on
//! [`oxicrypt_module::require_operational`]; hidden `*_internal`
//! primitives bypass the gate so the power-up KATs can run while
//! the module is still in `SelfTest`.
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
use oxicrypt_ecdsa::p384_point::Point384;
use oxicrypt_ecdsa::p384_scalar::Scalar384;
use oxicrypt_module::{
    require_allowed, require_operational, Error, KatEntry, SelfTestFailure, Service,
};

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
    require_allowed(Service::EcdhP256)?;
    compute_shared_secret_p256_internal(d_bytes, peer_pk).ok_or(Error::InvalidInput)
}

// ------------------------------------------------------------------
// P-384 constants
// ------------------------------------------------------------------

/// Length of a P-384 private-key scalar in bytes.
pub const P384_PRIVATE_KEY_LEN: usize = 48;
/// Length of an uncompressed SEC1 P-384 public-key encoding.
pub const P384_PUBLIC_KEY_LEN: usize = 97;
/// Length of the raw P-384 ECDH shared secret `Z` in bytes.
pub const P384_SHARED_SECRET_LEN: usize = 48;

// ------------------------------------------------------------------
// P-384 core primitive (state-gate-free)
// ------------------------------------------------------------------

/// Compute the SP 800-56Ar3 §5.7.1.2 ECC CDH primitive for P-384:
/// `Z = x( d * Q )`.
///
/// Returns `None` when `d` is not a valid non-zero scalar mod `n`,
/// when `Q` fails SP 800-56Ar3 §5.6.2.3.3 public-key validation, or
/// when the scalar multiplication yields the point at infinity.
/// Bypasses the FIPS module state gate for use from the power-up KAT
/// runner; production callers should use
/// [`compute_shared_secret_p384`] instead.
#[doc(hidden)]
pub fn compute_shared_secret_p384_internal(
    d_bytes: &[u8; P384_PRIVATE_KEY_LEN],
    peer_pk: &[u8; P384_PUBLIC_KEY_LEN],
) -> Option<[u8; P384_SHARED_SECRET_LEN]> {
    let d = Scalar384::from_bytes(d_bytes)?;
    if d.is_zero() == 1 {
        return None;
    }

    let q = Point384::from_sec1_uncompressed_validated(peer_pk)?;
    let z_point = q.mul(&d);
    let (zx, _zy) = z_point.to_affine()?;
    Some(zx.to_bytes())
}

// ------------------------------------------------------------------
// P-384 public, gated entry point
// ------------------------------------------------------------------

/// Compute the P-384 ECDH shared secret `Z = x(d * Q)`.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the containing FIPS module
/// has not finished its power-up self-tests, or [`Error::InvalidInput`]
/// if `d` is not a valid non-zero scalar or `peer_pk` fails SP
/// 800-56Ar3 §5.6.2.3.3 public-key validation.
pub fn compute_shared_secret_p384(
    d_bytes: &[u8; P384_PRIVATE_KEY_LEN],
    peer_pk: &[u8; P384_PUBLIC_KEY_LEN],
) -> Result<[u8; P384_SHARED_SECRET_LEN], Error> {
    require_operational()?;
    require_allowed(Service::EcdhP384)?;
    compute_shared_secret_p384_internal(d_bytes, peer_pk).ok_or(Error::InvalidInput)
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

// ------------------------------------------------------------------
// P-384 power-up known-answer test (RFC 5903 §8.2, ECDH P-384)
// ------------------------------------------------------------------

/// Initiator's static private key `d_i` from RFC 5903 §8.2.
const KAT_P384_D_I: [u8; 48] = [
    0x09, 0x9f, 0x3c, 0x70, 0x34, 0xd4, 0xa2, 0xc6, 0x99, 0x88, 0x4d, 0x73, 0xa3, 0x75, 0xa6, 0x7f,
    0x76, 0x24, 0xef, 0x7c, 0x6b, 0x3c, 0x0f, 0x16, 0x06, 0x47, 0xb6, 0x74, 0x14, 0xdc, 0xe6, 0x55,
    0xe3, 0x5b, 0x53, 0x80, 0x41, 0xe6, 0x49, 0xee, 0x3f, 0xae, 0xf8, 0x96, 0x78, 0x3a, 0xb1, 0x94,
];

/// Initiator's uncompressed SEC1 public key `Q_i` (`0x04 || x_i || y_i`).
const KAT_P384_Q_I: [u8; 97] = [
    0x04, 0x66, 0x78, 0x42, 0xd7, 0xd1, 0x80, 0xac, 0x2c, 0xde, 0x6f, 0x74, 0xf3, 0x75, 0x51, 0xf5,
    0x57, 0x55, 0xc7, 0x64, 0x5c, 0x20, 0xef, 0x73, 0xe3, 0x16, 0x34, 0xfe, 0x72, 0xb4, 0xc5, 0x5e,
    0xe6, 0xde, 0x3a, 0xc8, 0x08, 0xac, 0xb4, 0xbd, 0xb4, 0xc8, 0x87, 0x32, 0xae, 0xe9, 0x5f, 0x41,
    0xaa, 0x94, 0x82, 0xed, 0x1f, 0xc0, 0xee, 0xb9, 0xca, 0xfc, 0x49, 0x84, 0x62, 0x5c, 0xcf, 0xc2,
    0x3f, 0x65, 0x03, 0x21, 0x49, 0xe0, 0xe1, 0x44, 0xad, 0xa0, 0x24, 0x18, 0x15, 0x35, 0xa0, 0xf3,
    0x8e, 0xeb, 0x9f, 0xcf, 0xf3, 0xc2, 0xc9, 0x47, 0xda, 0xe6, 0x9b, 0x4c, 0x63, 0x45, 0x73, 0xa8,
    0x1c,
];

/// Responder's static private key `d_r`.
const KAT_P384_D_R: [u8; 48] = [
    0x41, 0xcb, 0x07, 0x79, 0xb4, 0xbd, 0xb8, 0x5d, 0x47, 0x84, 0x67, 0x25, 0xfb, 0xec, 0x3c, 0x94,
    0x30, 0xfa, 0xb4, 0x6c, 0xc8, 0xdc, 0x50, 0x60, 0x85, 0x5c, 0xc9, 0xbd, 0xa0, 0xaa, 0x29, 0x42,
    0xe0, 0x30, 0x83, 0x12, 0x91, 0x6b, 0x8e, 0xd2, 0x96, 0x0e, 0x4b, 0xd5, 0x5a, 0x74, 0x48, 0xfc,
];

/// Responder's uncompressed SEC1 public key `Q_r`.
const KAT_P384_Q_R: [u8; 97] = [
    0x04, 0xe5, 0x58, 0xdb, 0xef, 0x53, 0xee, 0xcd, 0xe3, 0xd3, 0xfc, 0xcf, 0xc1, 0xae, 0xa0, 0x8a,
    0x89, 0xa9, 0x87, 0x47, 0x5d, 0x12, 0xfd, 0x95, 0x0d, 0x83, 0xcf, 0xa4, 0x17, 0x32, 0xbc, 0x50,
    0x9d, 0x0d, 0x1a, 0xc4, 0x3a, 0x03, 0x36, 0xde, 0xf9, 0x6f, 0xda, 0x41, 0xd0, 0x77, 0x4a, 0x35,
    0x71, 0xdc, 0xfb, 0xec, 0x7a, 0xac, 0xf3, 0x19, 0x64, 0x72, 0x16, 0x9e, 0x83, 0x84, 0x30, 0x36,
    0x7f, 0x66, 0xee, 0xbe, 0x3c, 0x6e, 0x70, 0xc4, 0x16, 0xdd, 0x5f, 0x0c, 0x68, 0x75, 0x9d, 0xd1,
    0xff, 0xf8, 0x3f, 0xa4, 0x01, 0x42, 0x20, 0x9d, 0xff, 0x5e, 0xaa, 0xd9, 0x6d, 0xb9, 0xe6, 0x38,
    0x6c,
];

/// Expected P-384 shared secret `Z` (x-coordinate of
/// `d_i * Q_r == d_r * Q_i`).
const KAT_P384_Z: [u8; 48] = [
    0x11, 0x18, 0x73, 0x31, 0xc2, 0x79, 0x96, 0x2d, 0x93, 0xd6, 0x04, 0x24, 0x3f, 0xd5, 0x92, 0xcb,
    0x9d, 0x0a, 0x92, 0x6f, 0x42, 0x2e, 0x47, 0x18, 0x75, 0x21, 0x28, 0x7e, 0x71, 0x56, 0xc5, 0xc4,
    0xd6, 0x03, 0x13, 0x55, 0x69, 0xb9, 0xe9, 0xd0, 0x9c, 0xf5, 0xd4, 0xa2, 0x70, 0xf5, 0x97, 0x46,
];

/// Power-up known-answer test for ECDH P-384. Runs the RFC 5903
/// §8.2 vector in both directions and checks that flipping a byte
/// of the peer key causes rejection.
pub fn self_test_p384() -> Result<(), SelfTestFailure> {
    // Positive 1: d_i * Q_r == Z.
    let z1 =
        compute_shared_secret_p384_internal(&KAT_P384_D_I, &KAT_P384_Q_R).ok_or(SelfTestFailure)?;
    if z1 != KAT_P384_Z {
        return Err(SelfTestFailure);
    }

    // Positive 2: d_r * Q_i == Z (symmetry of ECDH).
    let z2 =
        compute_shared_secret_p384_internal(&KAT_P384_D_R, &KAT_P384_Q_I).ok_or(SelfTestFailure)?;
    if z2 != KAT_P384_Z {
        return Err(SelfTestFailure);
    }

    // Negative: a tampered peer key must be rejected by public-key
    // validation before any scalar multiplication happens.
    let mut tampered = KAT_P384_Q_R;
    tampered[96] ^= 0x01;
    if compute_shared_secret_p384_internal(&KAT_P384_D_I, &tampered).is_some() {
        return Err(SelfTestFailure);
    }

    Ok(())
}

// ------------------------------------------------------------------
// P-256 power-up known-answer test (RFC 5903 §8.1, ECDH P-256)
// ------------------------------------------------------------------

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
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "ECDH-P256 KAT (RFC 5903 §8.1 both directions + tamper, SP 800-56Ar3)",
        run: self_test,
    },
    KatEntry {
        name: "ECDH-P384 KAT (RFC 5903 §8.2 both directions + tamper, SP 800-56Ar3)",
        run: self_test_p384,
    },
];

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

    // ── P-384 tests ──────────────────────────────────────────────

    #[test]
    fn p384_kat_initiator_to_responder_matches_rfc5903() {
        let z = compute_shared_secret_p384_internal(&KAT_P384_D_I, &KAT_P384_Q_R).unwrap();
        assert_eq!(z, KAT_P384_Z);
    }

    #[test]
    fn p384_kat_responder_to_initiator_matches_rfc5903() {
        let z = compute_shared_secret_p384_internal(&KAT_P384_D_R, &KAT_P384_Q_I).unwrap();
        assert_eq!(z, KAT_P384_Z);
    }

    #[test]
    fn p384_rejects_tampered_peer_key_x() {
        let mut tampered = KAT_P384_Q_R;
        tampered[1] ^= 0x01;
        assert!(compute_shared_secret_p384_internal(&KAT_P384_D_I, &tampered).is_none());
    }

    #[test]
    fn p384_rejects_tampered_peer_key_y() {
        let mut tampered = KAT_P384_Q_R;
        tampered[96] ^= 0x01;
        assert!(compute_shared_secret_p384_internal(&KAT_P384_D_I, &tampered).is_none());
    }

    #[test]
    fn p384_rejects_peer_key_with_wrong_header() {
        let mut bad = KAT_P384_Q_R;
        bad[0] = 0x02;
        assert!(compute_shared_secret_p384_internal(&KAT_P384_D_I, &bad).is_none());
    }

    #[test]
    fn p384_rejects_identity_peer_key_encoding() {
        let mut encoding = [0u8; 97];
        encoding[0] = 0x04;
        assert!(compute_shared_secret_p384_internal(&KAT_P384_D_I, &encoding).is_none());
    }

    #[test]
    fn p384_rejects_zero_private_key() {
        let zero = [0u8; 48];
        assert!(compute_shared_secret_p384_internal(&zero, &KAT_P384_Q_R).is_none());
    }

    #[test]
    fn p384_self_test_passes() {
        self_test_p384().unwrap();
    }

    #[test]
    fn p384_public_api_gated_on_operational() {
        let _ = initialize_with_tests(&[
            KatEntry {
                name: "ecdh-p256",
                run: self_test,
            },
            KatEntry {
                name: "ecdh-p384",
                run: self_test_p384,
            },
        ]);
        let z =
            compute_shared_secret_p384(&KAT_P384_D_I, &KAT_P384_Q_R).expect("module operational");
        assert_eq!(z, KAT_P384_Z);
    }
}
