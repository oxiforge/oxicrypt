//! ECDSA with P-384 and SHA-384 per FIPS 186-5 §6.4.
//!
//! Three public entry points:
//!
//!   * [`derive_public_key`] — given a 48-byte private scalar `d`,
//!     compute the uncompressed SEC1 public key `[04 || X || Y]`.
//!   * [`sign_with_k`] — deterministic sign primitive taking an
//!     externally provided per-message secret `k`.
//!   * [`verify`] — verify an `(r, s)` signature against a public key
//!     per FIPS 186-5 §6.4.2.
//!
//! All three public entry points gate on
//! [`oxicrypt_module::require_operational`] and
//! [`oxicrypt_module::require_allowed`]. The KATs go through the
//! `*_internal` helpers, which skip the gate.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_module::{Error, SelfTestFailure, Service, require_allowed, require_operational};
use oxicrypt_sha::sha384::Sha384;

use crate::p384_keygen::{generate_p384_internal, sample_scalar_internal};
use crate::p384_point::Point384;
use crate::p384_scalar::Scalar384;

/// Length of a P-384 private-key scalar in bytes.
pub const PRIVATE_KEY_LEN: usize = 48;
/// Length of an uncompressed SEC1 public-key encoding
/// (`0x04 || X || Y`).
pub const PUBLIC_KEY_LEN: usize = 97;
/// Length of a serialized ECDSA signature `r || s`.
pub const SIGNATURE_LEN: usize = 96;

// ------------------------------------------------------------------
// Raw `*_internal` primitives
// ------------------------------------------------------------------

/// Derive the uncompressed SEC1 public key for a private scalar
/// `d_bytes`. Returns `None` if `d_bytes` does not encode a valid
/// non-zero scalar mod `n`.
#[doc(hidden)]
pub fn derive_public_key_internal(d_bytes: &[u8; PRIVATE_KEY_LEN]) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let d = Scalar384::from_bytes(d_bytes)?;
    if d.is_zero() == 1 {
        return None;
    }
    let q = Point384::generator().mul(&d);
    encode_public_key(&q)
}

/// Sign `msg` under private key `d_bytes` using the explicitly
/// provided per-message secret `k_bytes`.
#[doc(hidden)]
pub fn sign_with_k_internal(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    k_bytes: &[u8; PRIVATE_KEY_LEN],
) -> Option<[u8; SIGNATURE_LEN]> {
    let d = Scalar384::from_bytes(d_bytes)?;
    if d.is_zero() == 1 {
        return None;
    }
    let k = Scalar384::from_bytes(k_bytes)?;
    if k.is_zero() == 1 {
        return None;
    }

    // e = SHA-384(msg), reduced mod n.
    let e = hash_message_to_scalar(msg);

    // (x1, _) = k * G
    let big_r = Point384::generator().mul(&k);
    let (x1, _y1) = big_r.to_affine()?;
    let x1_bytes = x1.to_bytes();
    let r = Scalar384::from_bytes_reduced(&x1_bytes);
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
    sig[..48].copy_from_slice(&r.to_bytes());
    sig[48..].copy_from_slice(&s.to_bytes());
    Some(sig)
}

/// Verify an ECDSA signature per FIPS 186-5 §6.4.2.
#[doc(hidden)]
pub fn verify_internal(
    pk_bytes: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> bool {
    let Some(q) = decode_public_key(pk_bytes) else {
        return false;
    };

    let mut r_bytes = [0u8; 48];
    let mut s_bytes = [0u8; 48];
    r_bytes.copy_from_slice(&sig[..48]);
    s_bytes.copy_from_slice(&sig[48..]);
    let Some(r) = Scalar384::from_bytes(&r_bytes) else {
        return false;
    };
    let Some(s) = Scalar384::from_bytes(&s_bytes) else {
        return false;
    };
    if r.is_zero() == 1 || s.is_zero() == 1 {
        return false;
    }

    let e = hash_message_to_scalar(msg);

    let w = s.invert();
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);

    let p1 = Point384::generator().mul(&u1);
    let p2 = q.mul(&u2);
    let sum = point_add(&p1, &p2);
    let Some((x1, _y1)) = sum.to_affine() else {
        return false;
    };

    let x1_bytes = x1.to_bytes();
    let x1_mod_n = Scalar384::from_bytes_reduced(&x1_bytes);
    x1_mod_n.ct_eq(&r) == 1
}

// ------------------------------------------------------------------
// Public gated entry points
// ------------------------------------------------------------------

/// Derive the uncompressed SEC1 public key for private scalar `d`.
pub fn derive_public_key(d_bytes: &[u8; PRIVATE_KEY_LEN]) -> Result<[u8; PUBLIC_KEY_LEN], Error> {
    require_operational()?;
    require_allowed(Service::EcdsaP384Keygen)?;
    derive_public_key_internal(d_bytes).ok_or(Error::InvalidInput)
}

/// Sign `msg` with private key `d` and per-message secret `k`.
pub fn sign_with_k(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    k_bytes: &[u8; PRIVATE_KEY_LEN],
) -> Result<[u8; SIGNATURE_LEN], Error> {
    require_operational()?;
    require_allowed(Service::EcdsaP384Sign)?;
    sign_with_k_internal(d_bytes, msg, k_bytes).ok_or(Error::InvalidInput)
}

/// Verify an ECDSA signature per FIPS 186-5 §6.4.2.
pub fn verify(
    pk_bytes: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<bool, Error> {
    require_operational()?;
    require_allowed(Service::EcdsaP384Verify)?;
    Ok(verify_internal(pk_bytes, msg, sig))
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/// Hash `msg` with SHA-384 and reduce the 48-byte digest mod `n`.
/// For P-384 the digest width (384) matches the field width, so
/// FIPS 186-5 §6.4.1's left-truncation step is a no-op.
fn hash_message_to_scalar(msg: &[u8]) -> Scalar384 {
    let mut h = Sha384::new_internal();
    h.update(msg);
    let digest = h.finalize();
    Scalar384::from_bytes_reduced(&digest)
}

/// Encode a Jacobian point as uncompressed SEC1 `0x04 || X || Y`.
fn encode_public_key(q: &Point384) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let (ax, ay) = q.to_affine()?;
    let mut out = [0u8; PUBLIC_KEY_LEN];
    out[0] = 0x04;
    out[1..49].copy_from_slice(&ax.to_bytes());
    out[49..97].copy_from_slice(&ay.to_bytes());
    Some(out)
}

/// Decode an uncompressed SEC1 public key with SP 800-56Ar3
/// §5.6.2.3.3 public-key validation.
fn decode_public_key(pk_bytes: &[u8; PUBLIC_KEY_LEN]) -> Option<Point384> {
    Point384::from_sec1_uncompressed_validated(pk_bytes)
}

/// Sum two Jacobian points (convert right to affine, mixed-add).
fn point_add(p1: &Point384, p2: &Point384) -> Point384 {
    if p2.is_identity() == 1 {
        return *p1;
    }
    let Some((ax, ay)) = p2.to_affine() else {
        return *p1;
    };
    p1.add_mixed(&ax, &ay)
}

// ------------------------------------------------------------------
// EcdsaP384PrivateKey handle
// ------------------------------------------------------------------

/// Fixed probe message for the IG 10.3.A pairwise consistency test.
const PCT_PROBE_MSG: &[u8] = b"oxicrypt-ecdsa-p384-pct";

/// A P-384 ECDSA private key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time.
#[derive(Clone)]
pub struct EcdsaP384PrivateKey {
    d: [u8; PRIVATE_KEY_LEN],
    q: [u8; PUBLIC_KEY_LEN],
}

impl EcdsaP384PrivateKey {
    /// Import a private key from its 48-byte scalar representation,
    /// derive the public key, and run the IG 10.3.A PCT.
    pub fn from_bytes(
        drbg: &mut HmacDrbgSha256,
        d_bytes: &[u8; PRIVATE_KEY_LEN],
    ) -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::EcdsaP384Keygen)?;
        Self::from_bytes_internal(drbg, d_bytes).ok_or(Error::InvalidInput)
    }

    /// Generate a fresh P-384 private key via FIPS 186-5 §A.2.2.
    pub fn generate(drbg: &mut HmacDrbgSha256) -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::EcdsaP384Keygen)?;
        Self::generate_internal(drbg).ok_or(Error::InvalidInput)
    }

    /// Sign `msg` with SHA-384, sampling a fresh nonce from `drbg`.
    pub fn sign_sha384(
        &self,
        drbg: &mut HmacDrbgSha256,
        msg: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], Error> {
        require_operational()?;
        require_allowed(Service::EcdsaP384Sign)?;
        self.sign_sha384_internal(drbg, msg)
            .ok_or(Error::InvalidInput)
    }

    /// Return the uncompressed SEC1 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.q
    }

    /// Return a reference to the private scalar bytes.
    #[must_use]
    pub fn private_scalar(&self) -> &[u8; PRIVATE_KEY_LEN] {
        &self.d
    }

    // -- internal helpers --

    fn from_bytes_internal(
        drbg: &mut HmacDrbgSha256,
        d_bytes: &[u8; PRIVATE_KEY_LEN],
    ) -> Option<Self> {
        let pk = derive_public_key_internal(d_bytes)?;
        let handle = EcdsaP384PrivateKey { d: *d_bytes, q: pk };
        handle.run_pct(drbg)?;
        Some(handle)
    }

    fn generate_internal(drbg: &mut HmacDrbgSha256) -> Option<Self> {
        let (d, q) = generate_p384_internal(drbg)?;
        let handle = EcdsaP384PrivateKey { d, q };
        handle.run_pct(drbg)?;
        Some(handle)
    }

    fn run_pct(&self, drbg: &mut HmacDrbgSha256) -> Option<()> {
        for _ in 0..MAX_SIGN_RETRIES {
            let k = sample_scalar_internal(drbg)?;
            if let Some(sig) = sign_with_k_internal(&self.d, PCT_PROBE_MSG, &k) {
                if verify_internal(&self.q, PCT_PROBE_MSG, &sig) {
                    return Some(());
                }
                return None;
            }
        }
        None
    }

    fn sign_sha384_internal(
        &self,
        drbg: &mut HmacDrbgSha256,
        msg: &[u8],
    ) -> Option<[u8; SIGNATURE_LEN]> {
        for _ in 0..MAX_SIGN_RETRIES {
            let k = sample_scalar_internal(drbg)?;
            if let Some(sig) = sign_with_k_internal(&self.d, msg, &k) {
                return Some(sig);
            }
        }
        None
    }
}

impl Drop for EcdsaP384PrivateKey {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.d);
    }
}

const MAX_SIGN_RETRIES: usize = 8;

// ------------------------------------------------------------------
// Power-up known-answer test
// ------------------------------------------------------------------

/// KAT private key `d` — a deterministic 384-bit scalar.
const KAT_D: [u8; 48] = [
    0x0b, 0x6b, 0x19, 0xcd, 0x8e, 0x8a, 0x8b, 0x6c, 0x3a, 0xc6, 0xf3, 0xa7, 0xde, 0x1a, 0x2c, 0x5b,
    0xfa, 0x74, 0x16, 0x8e, 0xc5, 0xd5, 0x93, 0x05, 0xd9, 0xe1, 0xe7, 0xb4, 0x1b, 0x7b, 0x0a, 0xce,
    0x4f, 0xa0, 0xac, 0x7c, 0x4d, 0x84, 0xea, 0xe4, 0x48, 0x49, 0xed, 0x9d, 0x9e, 0x32, 0xd0, 0xa1,
];

/// KAT per-message secret `k`.
const KAT_K: [u8; 48] = [
    0x7a, 0x1a, 0x7e, 0x52, 0x79, 0x7f, 0xc8, 0xca, 0xaa, 0x43, 0x5d, 0x2a, 0x4d, 0xac, 0xe3, 0x91,
    0x58, 0x50, 0x4b, 0xf2, 0x04, 0xfb, 0xe1, 0x9f, 0x14, 0xdb, 0xb4, 0x27, 0xfa, 0xee, 0x50, 0xae,
    0x6a, 0xdf, 0xcf, 0x86, 0x2c, 0x1a, 0xc2, 0xf3, 0xc2, 0xc5, 0xa0, 0xbf, 0x3d, 0x53, 0xd0, 0x67,
];

/// KAT message.
const KAT_MSG: &[u8] = b"sample";

/// Expected uncompressed SEC1 public key for [`KAT_D`].
const KAT_PUBLIC_KEY: [u8; 97] = [
    0x04, // Qx
    0xb8, 0x72, 0x25, 0x2d, 0x38, 0x0c, 0x0d, 0xaf, 0x3c, 0xe4, 0x23, 0xdf, 0x1e, 0x0c, 0x4a, 0x47,
    0xd3, 0x92, 0x17, 0x82, 0xd7, 0x8b, 0x5f, 0x9c, 0xf0, 0x9e, 0xd7, 0x05, 0x30, 0xdc, 0x34, 0x2e,
    0x05, 0x09, 0x2a, 0xeb, 0x08, 0xe8, 0x5f, 0x37, 0xa3, 0x4b, 0x64, 0xf1, 0x8a, 0xac, 0x3b, 0xb1,
    // Qy
    0xce, 0x3d, 0xba, 0x74, 0x03, 0x4d, 0xdf, 0xea, 0xea, 0x4f, 0xe7, 0x91, 0xa2, 0xf4, 0xca, 0xb7,
    0x4e, 0x2f, 0x9f, 0x07, 0xeb, 0xb8, 0x74, 0x8e, 0x8a, 0x47, 0xbc, 0xef, 0xb2, 0xaa, 0x1f, 0x24,
    0x5f, 0xc8, 0xad, 0xf0, 0x2f, 0x79, 0x3d, 0x44, 0xc6, 0x9d, 0x43, 0x6a, 0xc2, 0x16, 0xa7, 0xa8,
];

/// Expected signature `r || s`.
const KAT_SIGNATURE: [u8; 96] = [
    // r
    0xf6, 0x4c, 0x88, 0x75, 0x60, 0xb7, 0xb0, 0x6e, 0x5b, 0xd3, 0xc3, 0x0c, 0x2f, 0x82, 0xa3, 0xae,
    0x01, 0xeb, 0x6d, 0x0a, 0xcf, 0x0b, 0x6a, 0xfc, 0x76, 0x20, 0x8c, 0x59, 0x9c, 0xb1, 0x0f, 0xfc,
    0xbb, 0x8c, 0x50, 0xc1, 0x7e, 0x80, 0xa7, 0xfc, 0x25, 0xd3, 0x7f, 0xf9, 0x5a, 0x4e, 0xe7, 0x7d,
    // s
    0x50, 0x96, 0x3c, 0xe4, 0xa0, 0x59, 0xfc, 0xb7, 0x91, 0xdf, 0xa2, 0xf7, 0xbc, 0xc7, 0x60, 0x20,
    0x99, 0x55, 0x53, 0x55, 0xa8, 0x10, 0xbc, 0x5e, 0xad, 0x16, 0x43, 0x66, 0xee, 0x54, 0x3c, 0xd2,
    0xbf, 0xc1, 0x8d, 0x02, 0x67, 0xde, 0xac, 0x98, 0xfb, 0xd9, 0x03, 0xe1, 0x9d, 0x23, 0x4f, 0x39,
];

/// Power-up known-answer test for ECDSA P-384 / SHA-384.
pub fn self_test() -> Result<(), SelfTestFailure> {
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
    use oxicrypt_module::{KatEntry, initialize_with_tests};

    #[test]
    fn kat_public_key_matches() {
        let pk = derive_public_key_internal(&KAT_D).unwrap();
        assert_eq!(pk, KAT_PUBLIC_KEY);
    }

    #[test]
    fn kat_signature_matches() {
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
    }

    #[test]
    fn verify_rejects_wrong_message() {
        assert!(!verify_internal(
            &KAT_PUBLIC_KEY,
            b"not sample",
            &KAT_SIGNATURE
        ));
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn public_api_gated_on_operational() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "ecdsa-p384-sha384",
            run: self_test,
        }]);
        let pk = derive_public_key(&KAT_D).expect("module operational");
        assert_eq!(pk, KAT_PUBLIC_KEY);
        let sig = sign_with_k(&KAT_D, KAT_MSG, &KAT_K).expect("sign ok");
        assert_eq!(sig, KAT_SIGNATURE);
        assert!(verify(&KAT_PUBLIC_KEY, KAT_MSG, &KAT_SIGNATURE).expect("verify ok"));
    }

    fn pct_drbg(personalization: &[u8]) -> HmacDrbgSha256 {
        let mut drbg = HmacDrbgSha256::default();
        drbg.instantiate(
            b"pqclib-p384-entropy-input",
            b"pqclib-p384-nonce",
            personalization,
        )
        .expect("drbg instantiates");
        drbg
    }

    #[test]
    fn generate_then_sign_and_verify_roundtrips() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "ecdsa-p384-sha384",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"p384-roundtrip");
        let sk = EcdsaP384PrivateKey::generate(&mut drbg).expect("generate ok");
        let msg = b"pqclib P-384: random-k sign and verify";
        let sig = sk.sign_sha384(&mut drbg, msg).expect("sign ok");
        assert!(verify(&sk.public_key(), msg, &sig).expect("verify ok"));
    }
}
