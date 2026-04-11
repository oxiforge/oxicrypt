//! RSASSA-PKCS1-v1_5 encoded-message (EM) construction for SHA-256.
//!
//! This module implements the EMSA-PKCS1-v1_5 encoding step from
//! RFC 8017 §9.2 for exactly one hash function, SHA-256. The EM
//! format is:
//!
//! ```text
//!   EM = 0x00 || 0x01 || PS || 0x00 || T
//! ```
//!
//! where `T` is the DER encoding of
//! `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`
//! for `id-sha256`, and `PS` is a string of `0xff` octets long enough
//! to pad the encoded message out to `emLen = k` bytes (256 for
//! RSA-2048).
//!
//! For SHA-256 the DigestInfo prefix is the 19-byte constant
//! `[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
//!   0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]` followed by the
//! 32-byte digest, for a total `tLen = 51`. With `emLen = 256` that
//! gives `PS` length `256 - 51 - 3 = 202` octets of `0xff`, then the
//! final EM is 256 bytes.
//!
//! The verify path reconstructs this fixed EM from the expected
//! message hash and does a byte-exact constant-time comparison
//! against the EM recovered from RSAVP1. No lax parsing, no
//! "parameters absent or NULL" wiggle room — we accept exactly the
//! canonical encoding RFC 8017 §9.2 step 2 specifies.

#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fips_sha::sha256::DIGEST_SIZE as SHA256_DIGEST_SIZE;

/// DER prefix for a SHA-256 DigestInfo: `SEQUENCE { AlgorithmIdentifier
/// { id-sha256, NULL }, OCTET STRING [32 bytes] }`. Does not include
/// the digest bytes themselves.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Total length of `T` (DigestInfo prefix + digest) for SHA-256.
const SHA256_T_LEN: usize = SHA256_DIGEST_INFO_PREFIX.len() + SHA256_DIGEST_SIZE;

/// Build the RFC 8017 §9.2 EMSA-PKCS1-v1_5 encoded message for a
/// SHA-256 digest into an `em_len`-byte buffer.
///
/// Returns `None` if `em_len` is too small to hold a conformant EM
/// (RFC 8017 requires at least `tLen + 11` bytes, i.e. 62 for SHA-256).
pub fn encode_sha256(digest: &[u8; SHA256_DIGEST_SIZE], em: &mut [u8]) -> Option<()> {
    let em_len = em.len();
    // RFC 8017 §9.2 step 3: if emLen < tLen + 11, output "intended
    // encoded message length too short" and stop.
    if em_len < SHA256_T_LEN + 11 {
        return None;
    }

    // RFC 8017 §9.2 step 4–5: PS is a string of (emLen - tLen - 3)
    // octets with value 0xff. EM = 0x00 || 0x01 || PS || 0x00 || T.
    em[0] = 0x00;
    em[1] = 0x01;
    let ps_end = em_len - SHA256_T_LEN - 1;
    for b in em.iter_mut().take(ps_end).skip(2) {
        *b = 0xff;
    }
    em[ps_end] = 0x00;
    em[ps_end + 1..ps_end + 1 + SHA256_DIGEST_INFO_PREFIX.len()]
        .copy_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    em[ps_end + 1 + SHA256_DIGEST_INFO_PREFIX.len()..].copy_from_slice(digest);
    Some(())
}

/// Constant-time byte-equality check over two equal-length slices.
///
/// Returns `1` if the slices are equal, `0` otherwise. The caller
/// must ensure the slices have the same length; unequal-length
/// slices trivially return `0`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    // acc==0 → result 1, else 0.
    let nz = (acc | acc.wrapping_neg()) >> 7;
    (1 ^ nz) & 1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn em_has_canonical_layout_for_256_bytes() {
        let digest = [0x42u8; SHA256_DIGEST_SIZE];
        let mut em = [0u8; 256];
        encode_sha256(&digest, &mut em).unwrap();
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        // PS occupies em[2..em_len - tLen - 1], all 0xff. For
        // em_len=256, tLen=51 → PS end at index 256 - 51 - 1 = 204.
        for (i, b) in em.iter().enumerate().skip(2).take(204 - 2) {
            assert_eq!(*b, 0xff, "PS byte at {i} should be 0xff");
        }
        assert_eq!(em[204], 0x00);
        // DigestInfo prefix.
        assert_eq!(&em[205..205 + 19], &SHA256_DIGEST_INFO_PREFIX);
        // Digest tail.
        assert_eq!(&em[205 + 19..], &digest);
    }

    #[test]
    fn em_rejects_too_short_buffer() {
        let digest = [0u8; SHA256_DIGEST_SIZE];
        let mut em = [0u8; 61]; // tLen + 11 = 62, so 61 is too small
        assert!(encode_sha256(&digest, &mut em).is_none());
    }

    #[test]
    fn ct_eq_zero_for_mismatch() {
        assert_eq!(ct_eq(b"abc", b"abd"), 0);
        assert_eq!(ct_eq(b"abc", b"abc"), 1);
        assert_eq!(ct_eq(b"abc", b"abcd"), 0);
    }
}
