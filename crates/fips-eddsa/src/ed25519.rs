//! Ed25519 per FIPS 186-5 §7.8 / RFC 8032 §5.1.
//!
//! Three public entry points:
//!
//!   * [`keygen`] — derive a 32-byte public key from a 32-byte seed
//!     (the RFC 8032 "secret key").
//!   * [`sign`]  — produce a 64-byte signature of a byte string under
//!     the seed.
//!   * [`verify`] — strict, non-cofactored verification of an Ed25519
//!     signature, per FIPS 186-5. Matches RFC 8032 §5.1.7's "SHOULD"
//!     formulation `[S]B == R + [k]A` without multiplication by the
//!     cofactor.
//!
//! The SHA-512 calls use [`fips_sha::sha512::Sha512::new_internal`]
//! so that Ed25519 can run while the enclosing module is still in the
//! `SelfTest` state (mirrors the pattern in `fips-hmac`). The public
//! wrappers are the ones that should be called during normal operation
//! and will eventually be gated behind `require_operational` once the
//! power-up KATs for Ed25519 are wired in.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

use fips_sha::sha512::Sha512;

use crate::edwards::EdwardsPoint;
use crate::scalar::{is_canonical_encoding, muladd, reduce_wide, Scalar};

/// Length of an Ed25519 seed / "secret key" in bytes (RFC 8032 §5.1.5).
pub const SEED_LEN: usize = 32;
/// Length of an Ed25519 compressed public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// RFC 8032 §5.1.5 clamping of `h[0..32]`:
///
/// ```text
/// h[0]  &= 0xF8   // clear the low three bits
/// h[31] &= 0x7F   // clear the top bit
/// h[31] |= 0x40   // set bit 254
/// ```
fn clamp(buf: &mut [u8; 32]) {
    buf[0] &= 0xF8;
    buf[31] &= 0x7F;
    buf[31] |= 0x40;
}

/// Compute `SHA-512` of the concatenation of up to three byte slices.
/// Uses the module-internal constructor so this path is callable from
/// power-up self tests.
fn sha512_cat(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new_internal();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// Derive the Ed25519 public key (compressed A = `[s]B`) from a
/// 32-byte seed. This is RFC 8032 §5.1.5.
pub fn keygen(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let h = sha512_cat(&[seed]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&h[..32]);
    clamp(&mut s_bytes);
    let s = Scalar::from_bytes(&s_bytes);
    EdwardsPoint::BASE.mul(&s).compress()
}

/// Sign `message` under `seed` and return the 64-byte Ed25519
/// signature. This is RFC 8032 §5.1.6 (pure Ed25519, no context).
pub fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> [u8; SIGNATURE_LEN] {
    // h = SHA512(seed); split into scalar half and prefix half.
    let h = sha512_cat(&[seed]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&h[..32]);
    clamp(&mut s_bytes);
    let s = Scalar::from_bytes(&s_bytes);
    let prefix = &h[32..64];

    // A = [s]B, compressed.
    let a_bytes = EdwardsPoint::BASE.mul(&s).compress();

    // r = SHA512(prefix || M) mod L; R = [r]B
    let r_hash = sha512_cat(&[prefix, message]);
    let r = reduce_wide(&r_hash);
    let r_point_bytes = EdwardsPoint::BASE.mul(&r).compress();

    // k = SHA512(R || A || M) mod L
    let k_hash = sha512_cat(&[&r_point_bytes, &a_bytes, message]);
    let k = reduce_wide(&k_hash);

    // S = (r + k * s) mod L
    let big_s = muladd(&k, &s, &r);

    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..32].copy_from_slice(&r_point_bytes);
    sig[32..].copy_from_slice(&big_s.to_bytes());
    sig
}

/// Strict, non-cofactored Ed25519 signature verification per
/// FIPS 186-5 §7.8.2. Returns `true` iff the signature is valid.
///
/// This check:
///
///   * decodes `A` from `public_key` (RFC 8032 §5.1.3 canonical decode;
///     `decompress` already rejects non-canonical `y` encodings and
///     non-square `u/v`);
///   * decodes `R` from `signature[..32]`;
///   * requires `S = signature[32..]` to be a canonical integer in
///     `[0, L)` (RFC 8032 §5.1.7 step 2);
///   * recomputes `k = SHA512(R || A || M) mod L`;
///   * accepts iff `[S]B == R + [k]A`.
///
/// The final equality test runs on compressed encodings, so it is a
/// byte-for-byte comparison of two canonical 32-byte strings and is
/// not subject to the cofactor ambiguity that plagues batch verifiers.
#[must_use]
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    // Split the signature.
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // Step 2: reject non-canonical S.
    if !is_canonical_encoding(&s_bytes) {
        return false;
    }

    // Decode A and R.
    let Some(a_point) = EdwardsPoint::decompress(public_key) else {
        return false;
    };
    let Some(r_point) = EdwardsPoint::decompress(&r_bytes) else {
        return false;
    };

    // k = SHA512(R || A || M) mod L
    let k_hash = sha512_cat(&[&r_bytes, public_key, message]);
    let k = reduce_wide(&k_hash);

    // Compute sB and R + kA, then compare compressed encodings.
    let s_scalar = Scalar::from_bytes(&s_bytes);
    let sb = EdwardsPoint::BASE.mul(&s_scalar);
    let ka = a_point.mul(&k);
    let rhs = r_point.add(&ka);

    sb.compress() == rhs.compress()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // RFC 8032 §7.1 test vectors (pure Ed25519).
    //
    // Each vector is (secret_key, public_key, message, signature).

    struct Vec8032 {
        sk: [u8; 32],
        pk: [u8; 32],
        msg: &'static [u8],
        sig: [u8; 64],
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 64);
        for i in 0..32 {
            let hi = from_hex(bytes[2 * i]);
            let lo = from_hex(bytes[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn hex64(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 128);
        for i in 0..64 {
            let hi = from_hex(bytes[2 * i]);
            let lo = from_hex(bytes[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn from_hex(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit"),
        }
    }

    fn rfc8032_vectors() -> [Vec8032; 4] {
        [
            // TEST 1 - empty message.
            Vec8032 {
                sk: hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
                pk: hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
                msg: &[],
                sig: hex64(
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                ),
            },
            // TEST 2 - one-byte message.
            Vec8032 {
                sk: hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
                pk: hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
                msg: &[0x72],
                sig: hex64(
                    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                ),
            },
            // TEST 3 - two-byte message.
            Vec8032 {
                sk: hex32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
                pk: hex32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
                msg: &[0xaf, 0x82],
                sig: hex64(
                    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                ),
            },
            // TEST SHA(abc) - 64-byte message.
            Vec8032 {
                sk: hex32("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"),
                pk: hex32("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
                msg: &[
                    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae,
                    0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e,
                    0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1,
                    0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23,
                    0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
                ],
                sig: hex64(
                    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
                ),
            },
        ]
    }

    #[test]
    fn rfc8032_keygen_matches() {
        for v in &rfc8032_vectors() {
            assert_eq!(keygen(&v.sk), v.pk);
        }
    }

    #[test]
    fn rfc8032_sign_matches() {
        for v in &rfc8032_vectors() {
            let got = sign(&v.sk, v.msg);
            assert_eq!(got, v.sig, "signature mismatch");
        }
    }

    #[test]
    fn rfc8032_verify_accepts() {
        for v in &rfc8032_vectors() {
            assert!(verify(&v.pk, v.msg, &v.sig));
        }
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let v = &rfc8032_vectors()[1];
        let bad = [v.msg[0] ^ 0x01];
        assert!(!verify(&v.pk, &bad, &v.sig));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let v = &rfc8032_vectors()[0];
        let mut bad = v.sig;
        bad[0] ^= 0x01;
        assert!(!verify(&v.pk, v.msg, &bad));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let v0 = &rfc8032_vectors()[0];
        let v1 = &rfc8032_vectors()[1];
        assert!(!verify(&v1.pk, v0.msg, &v0.sig));
    }

    #[test]
    fn verify_rejects_non_canonical_s() {
        // Take a valid signature and replace S with L itself. L is not
        // canonical (step 2 of §5.1.7 requires S < L).
        let l_bytes: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let v = &rfc8032_vectors()[0];
        let mut bad = v.sig;
        bad[32..].copy_from_slice(&l_bytes);
        assert!(!verify(&v.pk, v.msg, &bad));
    }
}
