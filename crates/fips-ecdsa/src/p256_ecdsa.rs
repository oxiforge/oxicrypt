//! ECDSA with P-256 and SHA-256 per FIPS 186-5 §6.4.
//!
//! Three public entry points:
//!
//!   * [`derive_public_key`] — given a 32-byte private scalar `d`,
//!     compute the uncompressed SEC1 public key `[04 || X || Y]`.
//!     This is not a full FIPS keygen (which layers rejection
//!     sampling on top of an approved DRBG); it's the deterministic
//!     core that a DRBG-backed keygen will call once the DRBG lands.
//!   * [`sign_with_k`] — deterministic sign primitive taking an
//!     externally provided per-message secret `k`. This is the shape
//!     needed by KATs and by a FIPS 186-5 sign routine built on top
//!     of an approved DRBG; it is not RFC 6979 deterministic signing
//!     and must not be called with a reused `k`.
//!   * [`verify`] — verify an `(r, s)` signature against a public key
//!     per FIPS 186-5 §6.4.2.
//!
//! All three public entry points gate on
//! [`fips_module::require_operational`] so callers cannot invoke the
//! algorithm before the module has finished its power-up KATs
//! (FIPS 140-3 IG D.G, SP 800-140F). The KATs themselves go through
//! the `*_internal` helpers, which skip the gate and therefore run
//! while the module is still in `SelfTest`. SHA-256 is reached via
//! [`fips_sha::sha256::Sha256::new_internal`] for the same reason.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use fips_module::{require_operational, Error, SelfTestFailure};
use fips_sha::sha256::Sha256;

use crate::p256_point::Point;
use crate::p256_scalar::Scalar;

/// Length of a P-256 private-key scalar in bytes.
pub const PRIVATE_KEY_LEN: usize = 32;
/// Length of an uncompressed SEC1 public-key encoding
/// (`0x04 || X || Y`).
pub const PUBLIC_KEY_LEN: usize = 65;
/// Length of a serialized ECDSA signature `r || s`.
pub const SIGNATURE_LEN: usize = 64;

// ------------------------------------------------------------------
// Raw `*_internal` primitives
// ------------------------------------------------------------------

/// Derive the uncompressed SEC1 public key for a private scalar
/// `d_bytes`. Returns `None` if `d_bytes` does not encode a valid
/// non-zero scalar mod `n`.
///
/// This is the `*_internal` primitive that [`derive_public_key`]
/// wraps; it bypasses the module state gate so KATs and the
/// power-up self test can call it while the module is still in
/// `SelfTest`.
#[doc(hidden)]
pub fn derive_public_key_internal(d_bytes: &[u8; PRIVATE_KEY_LEN]) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let d = Scalar::from_bytes(d_bytes)?;
    if d.is_zero() == 1 {
        return None;
    }
    let q = Point::generator().mul(&d);
    encode_public_key(&q)
}

/// Sign `msg` under private key `d_bytes` using the explicitly
/// provided per-message secret `k_bytes`. Returns `None` if any of
/// the inputs are out of range or if the resulting `r` or `s`
/// happens to be zero (caller should retry with a fresh `k`, as
/// FIPS 186-5 §6.4.1 specifies).
///
/// `k` **must** be a fresh secret for every signature — reusing or
/// leaking `k` leaks `d`. That discipline is the caller's
/// responsibility in this layer; a DRBG-backed wrapper in a later
/// commit will own it.
#[doc(hidden)]
pub fn sign_with_k_internal(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    k_bytes: &[u8; 32],
) -> Option<[u8; SIGNATURE_LEN]> {
    let d = Scalar::from_bytes(d_bytes)?;
    if d.is_zero() == 1 {
        return None;
    }
    let k = Scalar::from_bytes(k_bytes)?;
    if k.is_zero() == 1 {
        return None;
    }

    // e = SHA-256(msg), truncated/reduced mod n.
    let e = hash_message_to_scalar(msg);

    // (x1, y1) = k * G
    let big_r = Point::generator().mul(&k);
    let (x1, _y1) = big_r.to_affine()?;
    let x1_bytes = x1.to_bytes();
    let r = Scalar::from_bytes_reduced(&x1_bytes);
    if r.is_zero() == 1 {
        return None;
    }

    // s = k^-1 * (e + r*d) mod n
    let k_inv = k.invert();
    let rd = r.mul(&d);
    let sum = e.add(&rd);
    let s = k_inv.mul(&sum);
    if s.is_zero() == 1 {
        return None;
    }

    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..32].copy_from_slice(&r.to_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    Some(sig)
}

/// Verify an ECDSA signature per FIPS 186-5 §6.4.2. Returns `true`
/// iff `sig` is a valid signature of `msg` under `pk_bytes`.
#[doc(hidden)]
pub fn verify_internal(
    pk_bytes: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> bool {
    // 1. Decode public key.
    let Some(q) = decode_public_key(pk_bytes) else {
        return false;
    };

    // 2. Parse (r, s) and enforce r, s in [1, n-1].
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    s_bytes.copy_from_slice(&sig[32..]);
    let Some(r) = Scalar::from_bytes(&r_bytes) else {
        return false;
    };
    let Some(s) = Scalar::from_bytes(&s_bytes) else {
        return false;
    };
    if r.is_zero() == 1 || s.is_zero() == 1 {
        return false;
    }

    // 3. e = SHA-256(msg) mod n.
    let e = hash_message_to_scalar(msg);

    // 4. w = s^-1 mod n ; u1 = e*w ; u2 = r*w.
    let w = s.invert();
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);

    // 5. (x1, y1) = u1*G + u2*Q. Reject if the sum is the identity.
    let p1 = Point::generator().mul(&u1);
    let p2 = q.mul(&u2);
    let sum = point_add(&p1, &p2);
    let Some((x1, _y1)) = sum.to_affine() else {
        return false;
    };

    // 6. Accept iff (x1 mod n) == r.
    let x1_bytes = x1.to_bytes();
    let x1_mod_n = Scalar::from_bytes_reduced(&x1_bytes);
    x1_mod_n.ct_eq(&r) == 1
}

// ------------------------------------------------------------------
// Public gated entry points
// ------------------------------------------------------------------

/// Derive the uncompressed SEC1 public key for private scalar `d`.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the FIPS module has
/// not completed its power-up self-tests, or
/// [`Error::InvalidInput`] if `d` is not a valid non-zero scalar.
pub fn derive_public_key(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
) -> Result<[u8; PUBLIC_KEY_LEN], Error> {
    require_operational()?;
    derive_public_key_internal(d_bytes).ok_or(Error::InvalidInput)
}

/// Sign `msg` with private key `d` and per-message secret `k`.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the module has not
/// completed its power-up self-tests, or [`Error::InvalidInput`] if
/// the scalars are out of range or the signing equation produces a
/// zero `r` or `s` (retry with a fresh `k`).
pub fn sign_with_k(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    k_bytes: &[u8; 32],
) -> Result<[u8; SIGNATURE_LEN], Error> {
    require_operational()?;
    sign_with_k_internal(d_bytes, msg, k_bytes).ok_or(Error::InvalidInput)
}

/// Verify an ECDSA signature per FIPS 186-5 §6.4.2.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the module has not
/// completed its power-up self-tests. A well-formed-but-invalid
/// signature returns `Ok(false)`.
pub fn verify(
    pk_bytes: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<bool, Error> {
    require_operational()?;
    Ok(verify_internal(pk_bytes, msg, sig))
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/// Hash `msg` with SHA-256 and reduce the resulting 32-byte digest
/// mod `n`. For P-256 the digest width and field width are both 256
/// bits, so FIPS 186-5 §6.4.1's left-truncation step is a no-op and
/// only the modular reduction remains.
fn hash_message_to_scalar(msg: &[u8]) -> Scalar {
    let mut h = Sha256::new_internal();
    h.update(msg);
    let digest = h.finalize();
    Scalar::from_bytes_reduced(&digest)
}

/// Encode a Jacobian point as the uncompressed SEC1 public-key
/// format `0x04 || X || Y`. Returns `None` if the point is the
/// identity.
fn encode_public_key(q: &Point) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let (ax, ay) = q.to_affine()?;
    let mut out = [0u8; PUBLIC_KEY_LEN];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&ax.to_bytes());
    out[33..65].copy_from_slice(&ay.to_bytes());
    Some(out)
}

/// Decode an uncompressed SEC1 public-key encoding with full SP
/// 800-56Ar3 §5.6.2.3.3 public-key validation. Delegates to
/// [`Point::from_sec1_uncompressed_validated`]; any off-curve or
/// non-canonical input returns `None` and causes `verify` to return
/// `false`.
fn decode_public_key(pk_bytes: &[u8; PUBLIC_KEY_LEN]) -> Option<Point> {
    Point::from_sec1_uncompressed_validated(pk_bytes)
}

/// Sum two Jacobian points by converting the right-hand operand to
/// affine and calling [`Point::add_mixed`]. Only used by `verify`
/// where operand-dependent timing is not a concern (both `u1` and
/// `u2` are derived from public values).
fn point_add(p1: &Point, p2: &Point) -> Point {
    if p2.is_identity() == 1 {
        return *p1;
    }
    let Some((ax, ay)) = p2.to_affine() else {
        return *p1;
    };
    p1.add_mixed(&ax, &ay)
}

// ------------------------------------------------------------------
// Power-up known-answer test
// ------------------------------------------------------------------

/// Private key `d` from RFC 6979 §A.2.5 (P-256, SHA-256).
const KAT_D: [u8; 32] = [
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];

/// Per-message secret `k` from RFC 6979 §A.2.5 (P-256, SHA-256,
/// message "sample"). Not derived via RFC 6979's HMAC construction
/// in this code — the value is pinned here and the sign primitive
/// consumes it as given.
const KAT_K: [u8; 32] = [
    0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90, 0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xdd, 0x4c,
    0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2, 0x4d, 0x61, 0x29, 0x49, 0x3d, 0x8a, 0xad, 0x60,
];

/// KAT message: the ASCII bytes of "sample", per RFC 6979 §A.2.5.
const KAT_MSG: &[u8] = b"sample";

/// Expected uncompressed SEC1 public key for [`KAT_D`]: `U` from
/// RFC 6979 §A.2.5.
const KAT_PUBLIC_KEY: [u8; 65] = [
    0x04, //
    // Ux
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    // Uy
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
];

/// Expected `r || s` signature for `(KAT_D, KAT_MSG, KAT_K)`.
const KAT_SIGNATURE: [u8; 64] = [
    // r
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
    0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
    // s
    0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
    0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
];

/// Power-up known-answer test for ECDSA P-256 / SHA-256. Runs the
/// RFC 6979 §A.2.5 "sample" vector through all three primitives
/// (public-key derivation, sign with fixed `k`, verify) and checks a
/// tampered signature is rejected. Wired into the module state
/// machine via a [`fips_module::KatEntry`].
pub fn self_test() -> Result<(), SelfTestFailure> {
    // Positive: d → Q matches, sign(d, msg, k) matches, verify accepts.
    let pk = derive_public_key_internal(&KAT_D).ok_or(SelfTestFailure)?;
    if pk != KAT_PUBLIC_KEY {
        return Err(SelfTestFailure);
    }
    let sig = sign_with_k_internal(&KAT_D, KAT_MSG, &KAT_K).ok_or(SelfTestFailure)?;
    if sig != KAT_SIGNATURE {
        return Err(SelfTestFailure);
    }
    if !verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &KAT_SIGNATURE) {
        return Err(SelfTestFailure);
    }

    // Negative: a signature with a flipped byte must be rejected.
    let mut tampered = KAT_SIGNATURE;
    tampered[0] ^= 0x01;
    if verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &tampered) {
        return Err(SelfTestFailure);
    }

    Ok(())
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use fips_module::{initialize_with_tests, KatEntry};

    #[test]
    fn kat_public_key_matches_rfc6979() {
        let pk = derive_public_key_internal(&KAT_D).unwrap();
        assert_eq!(pk, KAT_PUBLIC_KEY);
    }

    #[test]
    fn kat_signature_matches_rfc6979() {
        let sig = sign_with_k_internal(&KAT_D, KAT_MSG, &KAT_K).unwrap();
        assert_eq!(sig, KAT_SIGNATURE);
    }

    #[test]
    fn verify_accepts_valid_kat_signature() {
        assert!(verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &KAT_SIGNATURE));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut tampered = KAT_SIGNATURE;
        tampered[0] ^= 0x01;
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &tampered));

        let mut tampered2 = KAT_SIGNATURE;
        tampered2[63] ^= 0x01;
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &tampered2));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        assert!(!verify_internal(&KAT_PUBLIC_KEY, b"not sample", &KAT_SIGNATURE));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let mut wrong_pk = KAT_PUBLIC_KEY;
        wrong_pk[1] ^= 0x01;
        assert!(!verify_internal(&wrong_pk, KAT_MSG, &KAT_SIGNATURE));
    }

    #[test]
    fn verify_rejects_zero_r() {
        let mut sig = KAT_SIGNATURE;
        for b in &mut sig[..32] {
            *b = 0;
        }
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &sig));
    }

    #[test]
    fn verify_rejects_zero_s() {
        let mut sig = KAT_SIGNATURE;
        for b in &mut sig[32..] {
            *b = 0;
        }
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &sig));
    }

    #[test]
    fn verify_rejects_r_equal_to_n() {
        // n in big-endian as the `r` component — must be rejected
        // because the canonical scalar parser rejects r >= n.
        let mut sig = KAT_SIGNATURE;
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        sig[..32].copy_from_slice(&n_bytes);
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &sig));
    }

    #[test]
    fn verify_rejects_pk_with_wrong_header_byte() {
        let mut bad_pk = KAT_PUBLIC_KEY;
        bad_pk[0] = 0x02; // compressed; we only accept 0x04 here
        assert!(!verify_internal(&bad_pk, KAT_MSG, &KAT_SIGNATURE));
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn public_api_gated_on_operational() {
        // Wire up the ECDSA KAT as the only test in the module and
        // run it to completion. The public entry points must then
        // succeed; before initialization they would return
        // `Error::NotOperational`.
        let _ = initialize_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        // Regardless of whether some earlier test already initialized
        // the module, after this call it is guaranteed operational
        // (unless another test installed a failing KAT, which none do).
        let pk = derive_public_key(&KAT_D).expect("module operational");
        assert_eq!(pk, KAT_PUBLIC_KEY);
        let sig = sign_with_k(&KAT_D, KAT_MSG, &KAT_K).expect("sign ok");
        assert_eq!(sig, KAT_SIGNATURE);
        assert!(verify(&KAT_PUBLIC_KEY, KAT_MSG, &KAT_SIGNATURE).expect("verify ok"));
    }
}
