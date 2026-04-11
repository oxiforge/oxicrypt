//! RSASSA-PSS message-encoding primitives (RFC 8017 §9.1) fixed to
//! SHA-256 as both the message hash and the MGF1 hash.
//!
//! # Parameter fixing
//!
//! FIPS 186-5 §5.4 permits a salt length in `[0, hLen]`. We fix
//! `sLen = hLen = 32` to track the FIPS 186-5 §5.4 recommendation
//! and keep the power-up KAT deterministic; callers that need a
//! shorter salt will drive the underlying `emsa_pss_encode` /
//! `emsa_pss_verify` routines directly when the PKCS#1 spec surface
//! eventually grows.
//!
//! # emBits / emLen
//!
//! For RSA-2048 `modBits = 2048` and therefore `emBits = 2047`,
//! `emLen = 256`. This leaves exactly one bit at the top of the
//! encoded message that RFC 8017 §9.1.1 step 11 requires be zeroed:
//! on the encode path we mask it out, and on the verify path we
//! reject any encoded message whose top bit is set.
//!
//! # Constant-time contract
//!
//! The encode and verify routines here are not strictly constant
//! time in the message bytes, because MGF1 and SHA-256 are
//! domain-public and the salt is (by construction) either fresh
//! randomness or a power-up-KAT fixed string. What matters for
//! FIPS 140-3 IG D.G is that the **private-key exponentiation**
//! (handled in [`crate::mont2048::MontCtx2048::pow_secret`]) is
//! constant time in `d`, and that the verify path does not leak
//! distinguishable information about whether a signature is valid
//! before the final `H' == H` comparison — both of which are
//! satisfied here.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::manual_div_ceil,
    clippy::cast_possible_truncation
)]

use fips_sha::sha256::{Sha256, DIGEST_SIZE as SHA256_DIGEST_SIZE};

use crate::pkcs1_v15::sha256_internal;

/// Hash output length (SHA-256).
pub const HLEN: usize = SHA256_DIGEST_SIZE;
/// Salt length, fixed to `hLen` per FIPS 186-5 §5.4 recommendation.
pub const SLEN: usize = HLEN;
/// Modulus bit length for RSA-2048.
pub const MOD_BITS: usize = 2048;
/// `emBits` per RFC 8017 §9.1.1: `modBits − 1`.
pub const EM_BITS: usize = MOD_BITS - 1;
/// `emLen` per RFC 8017 §9.1.1: `ceil(emBits / 8)`.
pub const EM_LEN: usize = (EM_BITS + 7) / 8;
/// Number of high bits to zero in the top octet of maskedDB
/// (`8·emLen − emBits`). For RSA-2048 this is `1`.
pub const TOP_BITS_TO_CLEAR: u32 = (8 * EM_LEN - EM_BITS) as u32;

/// MGF1 with SHA-256. Fills `out` with the first `out.len()` bytes
/// of the mask generated from `seed`.
///
/// Implementation of RFC 8017 §B.2.1: for `counter = 0, 1, …`,
/// concatenate `SHA-256(seed || I2OSP(counter, 4))`.
pub fn mgf1_sha256(seed: &[u8], out: &mut [u8]) {
    let mut counter: u32 = 0;
    let mut written = 0;
    while written < out.len() {
        let mut h = Sha256::new_internal();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        let block = h.finalize();
        let remaining = out.len() - written;
        let take = core::cmp::min(remaining, SHA256_DIGEST_SIZE);
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
        counter = counter.wrapping_add(1);
    }
}

/// EMSA-PSS-ENCODE for SHA-256 with `sLen = hLen = 32`, writing an
/// `EM_LEN`-byte encoded message into `em`.
///
/// Follows RFC 8017 §9.1.1 step-for-step. Returns `None` only for the
/// one failure mode RFC 8017 flags: `emLen < hLen + sLen + 2`, which
/// cannot happen for the pinned `(EM_LEN, HLEN, SLEN)` constants but
/// is checked anyway so the routine can be reused with different
/// parameter triples later.
pub fn emsa_pss_encode(
    m_hash: &[u8; HLEN],
    salt: &[u8; SLEN],
    em: &mut [u8; EM_LEN],
) -> Option<()> {
    // Step 3: check emLen is large enough.
    if EM_LEN < HLEN + SLEN + 2 {
        return None;
    }

    // Step 5: M' = (0x00)*8 || mHash || salt.
    let mut m_prime = [0u8; 8 + HLEN + SLEN];
    // Leading eight zero octets are already in place.
    m_prime[8..8 + HLEN].copy_from_slice(m_hash);
    m_prime[8 + HLEN..].copy_from_slice(salt);

    // Step 6: H = Hash(M').
    let h = sha256_internal(&m_prime);

    // Step 7–8: DB = PS || 0x01 || salt. PS is (emLen − sLen − hLen − 2)
    // zero octets, which for (256, 32, 32) is 190.
    let db_len = EM_LEN - HLEN - 1;
    let mut db = [0u8; EM_LEN];
    let ps_len = db_len - SLEN - 1;
    // PS already zero.
    db[ps_len] = 0x01;
    db[ps_len + 1..ps_len + 1 + SLEN].copy_from_slice(salt);

    // Step 9: dbMask = MGF1(H, emLen − hLen − 1).
    let mut db_mask = [0u8; EM_LEN];
    mgf1_sha256(&h, &mut db_mask[..db_len]);

    // Step 10: maskedDB = DB ⊕ dbMask.
    for i in 0..db_len {
        db[i] ^= db_mask[i];
    }

    // Step 11: zero the leftmost (8·emLen − emBits) bits of maskedDB.
    if TOP_BITS_TO_CLEAR > 0 {
        let mask = 0xffu8 >> TOP_BITS_TO_CLEAR;
        db[0] &= mask;
    }

    // Step 12: EM = maskedDB || H || 0xbc.
    em[..db_len].copy_from_slice(&db[..db_len]);
    em[db_len..db_len + HLEN].copy_from_slice(&h);
    em[EM_LEN - 1] = 0xbc;

    Some(())
}

/// EMSA-PSS-VERIFY for SHA-256 with `sLen = hLen = 32`. Returns
/// `true` iff `em` is a well-formed PSS encoding of `m_hash`.
///
/// Follows RFC 8017 §9.1.2 step-for-step. The final `H == H'`
/// comparison uses a constant-time byte compare to avoid a
/// trivially-observable "bail on first mismatch" timing side channel;
/// the earlier structural checks are allowed to short-circuit since
/// the data they operate on is public.
pub fn emsa_pss_verify(m_hash: &[u8; HLEN], em: &[u8; EM_LEN]) -> bool {
    // Step 3: check emLen is large enough.
    if EM_LEN < HLEN + SLEN + 2 {
        return false;
    }

    // Step 4: rightmost byte must be 0xbc.
    if em[EM_LEN - 1] != 0xbc {
        return false;
    }

    // Step 5: split EM into maskedDB and H.
    let db_len = EM_LEN - HLEN - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + HLEN];

    // Step 6: the leftmost (8·emLen − emBits) bits of maskedDB must be zero.
    if TOP_BITS_TO_CLEAR > 0 {
        let mask = 0xffu8 << (8 - TOP_BITS_TO_CLEAR);
        if masked_db[0] & mask != 0 {
            return false;
        }
    }

    // Step 7: dbMask = MGF1(H, emLen − hLen − 1).
    let mut db_mask = [0u8; EM_LEN];
    mgf1_sha256(h, &mut db_mask[..db_len]);

    // Step 8: DB = maskedDB ⊕ dbMask.
    let mut db = [0u8; EM_LEN];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Step 9: clear the top bits of DB[0] matching step 11 of encode.
    if TOP_BITS_TO_CLEAR > 0 {
        let mask = 0xffu8 >> TOP_BITS_TO_CLEAR;
        db[0] &= mask;
    }

    // Step 10: the leftmost (emLen − sLen − hLen − 2) bytes of DB
    // must be zero, followed by a single 0x01.
    let ps_len = db_len - SLEN - 1;
    for &b in &db[..ps_len] {
        if b != 0 {
            return false;
        }
    }
    if db[ps_len] != 0x01 {
        return false;
    }

    // Step 11: salt = last sLen bytes of DB.
    let salt = &db[ps_len + 1..ps_len + 1 + SLEN];

    // Step 12–13: M' = (0x00)*8 || mHash || salt; H' = Hash(M').
    let mut m_prime = [0u8; 8 + HLEN + SLEN];
    m_prime[8..8 + HLEN].copy_from_slice(m_hash);
    m_prime[8 + HLEN..].copy_from_slice(salt);
    let h_prime = sha256_internal(&m_prime);

    // Step 14: H == H' under a constant-time compare.
    crate::pkcs1_v15::ct_eq(&h_prime, h) == 1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn mgf1_matches_rfc8017_b2_first_block() {
        // MGF1(0x00, 32) reproduces SHA-256(0x00 || 0x00000000).
        let seed = [0u8; 1];
        let mut out = [0u8; 32];
        mgf1_sha256(&seed, &mut out);

        let mut h = Sha256::new_internal();
        h.update(&seed);
        h.update(&0u32.to_be_bytes());
        assert_eq!(out, h.finalize());
    }

    #[test]
    fn mgf1_multi_block_continues_with_counter() {
        // Produce 2*HLEN bytes; the second half must equal the hash
        // of seed || 0x00000001.
        let seed = b"abc";
        let mut out = [0u8; 2 * SHA256_DIGEST_SIZE];
        mgf1_sha256(seed, &mut out);

        let mut h0 = Sha256::new_internal();
        h0.update(seed);
        h0.update(&0u32.to_be_bytes());
        assert_eq!(&out[..SHA256_DIGEST_SIZE], &h0.finalize());

        let mut h1 = Sha256::new_internal();
        h1.update(seed);
        h1.update(&1u32.to_be_bytes());
        assert_eq!(&out[SHA256_DIGEST_SIZE..], &h1.finalize());
    }

    #[test]
    fn encode_then_verify_roundtrips() {
        let m_hash = sha256_internal(b"roundtrip-msg");
        let salt = [0x33u8; SLEN];
        let mut em = [0u8; EM_LEN];
        emsa_pss_encode(&m_hash, &salt, &mut em).unwrap();
        assert!(emsa_pss_verify(&m_hash, &em));
    }

    #[test]
    fn encode_clears_top_bit() {
        // The top bit of maskedDB must always be zero for emBits=2047.
        let m_hash = sha256_internal(b"top-bit-check");
        let salt = [0xffu8; SLEN];
        let mut em = [0u8; EM_LEN];
        emsa_pss_encode(&m_hash, &salt, &mut em).unwrap();
        assert_eq!(em[0] & 0x80, 0);
    }

    #[test]
    fn verify_rejects_missing_trailer() {
        let m_hash = sha256_internal(b"trailer-check");
        let salt = [0x00u8; SLEN];
        let mut em = [0u8; EM_LEN];
        emsa_pss_encode(&m_hash, &salt, &mut em).unwrap();
        em[EM_LEN - 1] ^= 0xff;
        assert!(!emsa_pss_verify(&m_hash, &em));
    }

    #[test]
    fn verify_rejects_nonzero_top_bit() {
        let m_hash = sha256_internal(b"top-bit-nonzero");
        let salt = [0x00u8; SLEN];
        let mut em = [0u8; EM_LEN];
        emsa_pss_encode(&m_hash, &salt, &mut em).unwrap();
        em[0] |= 0x80;
        assert!(!emsa_pss_verify(&m_hash, &em));
    }

    #[test]
    fn verify_rejects_wrong_hash() {
        let m_hash = sha256_internal(b"original-msg");
        let other_hash = sha256_internal(b"different-msg");
        let salt = [0x7bu8; SLEN];
        let mut em = [0u8; EM_LEN];
        emsa_pss_encode(&m_hash, &salt, &mut em).unwrap();
        assert!(!emsa_pss_verify(&other_hash, &em));
    }
}
