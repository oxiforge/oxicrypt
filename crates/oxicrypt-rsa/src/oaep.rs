//! RSA-OAEP encode/decode primitives (RFC 8017 §7.1) fixed to SHA-256
//! for both the label hash and the MGF1 hash, sized for RSA-2048
//! (`k = 256`).
//!
//! # Parameter fixing
//!
//! FIPS 186-5 / SP 800-56Br2 do not forbid other hash choices, but this
//! crate only exposes SHA-256 OAEP for now — the same reasoning as the
//! PSS module: a single pinned parameter triple keeps the power-up KAT
//! deterministic and avoids a combinatorial API surface. Wider OAEP
//! variants can be added behind new entry points without touching the
//! primitives here.
//!
//! # k, hLen, and the PS length cap
//!
//! For RSA-2048 SHA-256 OAEP, `k = 256` bytes and `hLen = 32`. A valid
//! plaintext `M` must satisfy `mLen ≤ k − 2·hLen − 2 = 190`, which is
//! the [`MAX_MSG_LEN`] constant. Anything larger is rejected before
//! encoding.
//!
//! # Manger-resistance contract
//!
//! The decode path in [`emsa_oaep_decode`] is written with two
//! constraints that together defeat Manger's chosen-ciphertext attack
//! on OAEP:
//!
//! 1. **No early exit on any structural check.** The leading `Y` byte,
//!    the `lHash` compare, the zero-run of `PS`, and the `0x01`
//!    delimiter are all folded into a single accumulator. The decoder
//!    runs the full MGF1 unmask regardless of where the first failure
//!    occurs, so an attacker cannot distinguish "`Y ≠ 0`" from
//!    "`lHash' ≠ lHash`" from "malformed PS" via timing or error type.
//! 2. **Single generic error at the end.** Every failure mode collapses
//!    to `None`, which the public wrapper translates into a generic
//!    `InvalidInput`. A caller cannot learn which check failed from the
//!    error value.
//!
//! The message-length extraction on success is a data-dependent copy —
//! `mLen` is not hidden from the caller once decryption succeeds, which
//! is acceptable for OAEP as a KEM (the caller already knows the
//! expected plaintext length) and consistent with the RFC 8017 API
//! shape. The copy stays inside a fixed-size stack buffer; no
//! length-dependent memory allocation or branch-on-secret-exponent
//! work happens downstream.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::cast_possible_truncation
)]

use oxicrypt_sha::sha256::DIGEST_SIZE as SHA256_DIGEST_SIZE;

use crate::pkcs1_v15::sha256_internal;
use crate::pss::mgf1_sha256;

/// SHA-256 digest length in bytes.
pub const HLEN: usize = SHA256_DIGEST_SIZE;
/// RSA-2048 modulus byte length, equal to the OAEP `k` parameter.
pub const K: usize = 256;
/// Length of the OAEP `DB` block: `k − hLen − 1 = 223`.
pub const DB_LEN: usize = K - HLEN - 1;
/// Maximum plaintext length accepted by OAEP encode: `k − 2·hLen − 2 = 190`.
pub const MAX_MSG_LEN: usize = K - 2 * HLEN - 2;

/// EME-OAEP-ENCODE for SHA-256.
///
/// Writes a `k`-byte encoded message into `em` from `(label, msg, seed)`
/// per RFC 8017 §7.1.1 step-for-step. The caller is responsible for
/// sampling a fresh `hLen`-byte `seed` from a DRBG — the encode path
/// has no randomness dependency of its own, which keeps it usable
/// from the power-up KAT with a pinned seed.
///
/// Returns `None` if `msg.len() > MAX_MSG_LEN`; there are no other
/// failure modes for the pinned `(K, HLEN)` configuration.
pub fn emsa_oaep_encode(
    label: &[u8],
    msg: &[u8],
    seed: &[u8; HLEN],
    em: &mut [u8; K],
) -> Option<()> {
    // Step 1b: mLen ≤ k − 2·hLen − 2. Step 1a (label length limit) is
    // elided because SHA-256 accepts 2^61 − 1 bytes and we would never
    // reach it in practice.
    if msg.len() > MAX_MSG_LEN {
        return None;
    }

    // Step 2a: lHash = Hash(L).
    let lhash = sha256_internal(label);

    // Step 2b: PS = (k − mLen − 2·hLen − 2) zero octets. Allocated as
    // part of DB below — PS bytes are already zero in the zero-filled
    // stack buffer.
    //
    // Step 2c: DB = lHash || PS || 0x01 || M, length k − hLen − 1.
    let mut db = [0u8; DB_LEN];
    db[..HLEN].copy_from_slice(&lhash);
    let one_idx = DB_LEN - msg.len() - 1;
    db[one_idx] = 0x01;
    db[one_idx + 1..].copy_from_slice(msg);

    // Step 2d: seed is supplied by the caller.
    // Step 2e: dbMask = MGF1(seed, k − hLen − 1).
    let mut db_mask = [0u8; DB_LEN];
    mgf1_sha256(seed, &mut db_mask);

    // Step 2f: maskedDB = DB ⊕ dbMask.
    for i in 0..DB_LEN {
        db[i] ^= db_mask[i];
    }

    // Step 2g: seedMask = MGF1(maskedDB, hLen).
    let mut seed_mask = [0u8; HLEN];
    mgf1_sha256(&db, &mut seed_mask);

    // Step 2h: maskedSeed = seed ⊕ seedMask.
    let mut masked_seed = [0u8; HLEN];
    for i in 0..HLEN {
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }

    // Step 2i: EM = 0x00 || maskedSeed || maskedDB.
    em[0] = 0x00;
    em[1..=HLEN].copy_from_slice(&masked_seed);
    em[1 + HLEN..].copy_from_slice(&db);

    Some(())
}

/// Constant-time byte equality. Returns `1` iff `a == b`, else `0`,
/// with execution time independent of the byte values.
#[inline]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let x = a ^ b;
    // x == 0 → result 1, else 0. Same trick as `pkcs1_v15::ct_eq`.
    let nz = (x | x.wrapping_neg()) >> 7;
    1 ^ nz
}

/// Constant-time `usize` select. Returns `a` if `cond == 1`, `b` if
/// `cond == 0`. `cond` must be `0` or `1`; any other value produces
/// an unspecified result.
#[inline]
fn ct_select_usize(cond: u8, a: usize, b: usize) -> usize {
    // Expand a single-bit condition into an all-ones/all-zeros mask.
    let mask = (cond as usize).wrapping_neg();
    (mask & a) | (!mask & b)
}

/// EME-OAEP-DECODE for SHA-256.
///
/// Parses a `k`-byte encoded message back into its plaintext, verifies
/// the label hash and the structural markers, and writes the message
/// into `out`. Returns `Some(mLen)` on success, `None` on any failure.
///
/// The decode is Manger-resistant: every structural check is folded
/// into a single accumulator, no branch depends on where the failure
/// occurred, and MGF1 unmasking runs to completion regardless of the
/// `Y` byte or `lHash'` state. All failure modes return the same
/// generic `None` to the caller.
pub fn emsa_oaep_decode(label: &[u8], em: &[u8; K], out: &mut [u8; MAX_MSG_LEN]) -> Option<usize> {
    // Step 3a: lHash = Hash(L).
    let lhash = sha256_internal(label);

    // Step 3b: Split EM into Y, maskedSeed, maskedDB.
    let y = em[0];
    let masked_seed = &em[1..=HLEN];
    let masked_db = &em[1 + HLEN..];
    debug_assert_eq!(masked_db.len(), DB_LEN);

    // Step 3c: seedMask = MGF1(maskedDB, hLen).
    let mut seed_mask = [0u8; HLEN];
    mgf1_sha256(masked_db, &mut seed_mask);

    // Step 3d: seed = maskedSeed ⊕ seedMask.
    let mut seed = [0u8; HLEN];
    for i in 0..HLEN {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    // Step 3e: dbMask = MGF1(seed, k − hLen − 1).
    let mut db_mask = [0u8; DB_LEN];
    mgf1_sha256(&seed, &mut db_mask);

    // Step 3f: DB = maskedDB ⊕ dbMask.
    let mut db = [0u8; DB_LEN];
    for i in 0..DB_LEN {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Step 3g: DB must have the shape `lHash' || PS || 0x01 || M`.
    //
    // We walk DB and accumulate:
    //   * `bad`: folded one-bit "something went wrong" flag
    //   * `found_one`: 1 once we've seen the 0x01 delimiter
    //   * `msg_start`: index in DB of the first byte of M (one past
    //     the 0x01), CT-selected on first-one
    //
    // Every check contributes to `bad` via bitwise OR; none of the
    // loop iterations bail out early.

    // Y byte must be 0x00. Fold any nonzero bit into `bad`.
    let mut bad: u8 = y;

    // lHash' compare. Fold the full 32-byte XOR into `bad`.
    for i in 0..HLEN {
        bad |= db[i] ^ lhash[i];
    }

    // Walk DB[HLEN..DB_LEN] looking for the 0x01 delimiter. Any byte
    // before the delimiter that is neither 0x00 nor 0x01 is a bad PS.
    // Any scan that reaches the end without finding a 0x01 is also bad.
    let mut found_one: u8 = 0;
    let mut msg_start: usize = 0;

    for (offset, &b) in db[HLEN..DB_LEN].iter().enumerate() {
        let i = HLEN + offset;
        let is_zero = ct_eq_u8(b, 0x00);
        let is_one = ct_eq_u8(b, 0x01);
        // `not_found` is 1 while we are still walking PS.
        let not_found = 1 ^ found_one;
        // In PS, b must be 0 or 1. Anything else flips `bad`.
        let bad_ps_byte = not_found & (1 ^ is_zero) & (1 ^ is_one);
        bad |= bad_ps_byte;
        // First occurrence of 0x01: mark `found_one`, record msg_start.
        let first_one = not_found & is_one;
        msg_start = ct_select_usize(first_one, i + 1, msg_start);
        found_one |= first_one;
    }

    // If we never found a 0x01 delimiter, the encoding is malformed.
    bad |= 1 ^ found_one;

    // Fold the accumulator into a boolean. Any nonzero bit means fail.
    // We only branch on `bad` after every check has run.
    let nz = (bad | bad.wrapping_neg()) >> 7;
    if nz != 0 {
        return None;
    }

    // Success path: copy the message bytes out.
    let mlen = DB_LEN - msg_start;
    out[..mlen].copy_from_slice(&db[msg_start..]);
    Some(mlen)
}

// ------------------------------------------------------------------
// Slice-based OAEP encode / decode for RSA-3072 and RSA-4096
// ------------------------------------------------------------------

/// Maximum modulus byte length (`k`) supported by the slice-based OAEP.
/// RSA-4096 → k = 512.
const MAX_K: usize = 512;
/// Maximum DB length at `MAX_K`: `k − hLen − 1 = 479`.
const MAX_DB_LEN: usize = MAX_K - HLEN - 1;
/// Maximum plaintext length at `MAX_K`: `k − 2·hLen − 2 = 446`.
pub const MAX_MSG_LEN_4096: usize = MAX_K - 2 * HLEN - 2;

/// EME-OAEP-ENCODE for SHA-256, width-generic.
///
/// `em.len()` is the modulus byte length `k` (e.g. 384 for RSA-3072,
/// 512 for RSA-4096). Returns `None` if `msg` is too long for the
/// given `k`, or if `k > MAX_K`.
pub fn emsa_oaep_encode_n(
    label: &[u8],
    msg: &[u8],
    seed: &[u8; HLEN],
    em: &mut [u8],
) -> Option<()> {
    let k = em.len();
    if !(2 * HLEN + 2..=MAX_K).contains(&k) {
        return None;
    }
    let max_msg_len = k - 2 * HLEN - 2;
    if msg.len() > max_msg_len {
        return None;
    }
    let db_len = k - HLEN - 1;

    let lhash = sha256_internal(label);

    let mut db = [0u8; MAX_DB_LEN];
    db[..HLEN].copy_from_slice(&lhash);
    let one_idx = db_len - msg.len() - 1;
    db[one_idx] = 0x01;
    db[one_idx + 1..one_idx + 1 + msg.len()].copy_from_slice(msg);

    let mut db_mask = [0u8; MAX_DB_LEN];
    mgf1_sha256(seed, &mut db_mask[..db_len]);

    for i in 0..db_len {
        db[i] ^= db_mask[i];
    }

    let mut seed_mask = [0u8; HLEN];
    mgf1_sha256(&db[..db_len], &mut seed_mask);

    let mut masked_seed = [0u8; HLEN];
    for i in 0..HLEN {
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }

    em[0] = 0x00;
    em[1..=HLEN].copy_from_slice(&masked_seed);
    em[1 + HLEN..1 + HLEN + db_len].copy_from_slice(&db[..db_len]);

    Some(())
}

/// EME-OAEP-DECODE for SHA-256, width-generic.
///
/// `em.len()` is the modulus byte length `k`. Writes the recovered
/// plaintext into `out[..mLen]` and returns `Some(mLen)` on success.
/// `out.len()` must be at least `k − 2·hLen − 2`.
///
/// Manger-resistant: single accumulator, no early exit.
pub fn emsa_oaep_decode_n(label: &[u8], em: &[u8], out: &mut [u8]) -> Option<usize> {
    let k = em.len();
    if !(2 * HLEN + 2..=MAX_K).contains(&k) {
        return None;
    }
    let db_len = k - HLEN - 1;
    let max_msg_len = k - 2 * HLEN - 2;
    if out.len() < max_msg_len {
        return None;
    }

    let lhash = sha256_internal(label);

    let y = em[0];
    let masked_seed = &em[1..=HLEN];
    let masked_db = &em[1 + HLEN..];
    debug_assert_eq!(masked_db.len(), db_len);

    let mut seed_mask = [0u8; HLEN];
    mgf1_sha256(masked_db, &mut seed_mask);

    let mut seed = [0u8; HLEN];
    for i in 0..HLEN {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    let mut db_mask = [0u8; MAX_DB_LEN];
    mgf1_sha256(&seed, &mut db_mask[..db_len]);

    let mut db = [0u8; MAX_DB_LEN];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Accumulator walk — identical to emsa_oaep_decode.
    let mut bad: u8 = y;
    for i in 0..HLEN {
        bad |= db[i] ^ lhash[i];
    }

    let mut found_one: u8 = 0;
    let mut msg_start: usize = 0;

    for (offset, &b) in db[HLEN..db_len].iter().enumerate() {
        let i = HLEN + offset;
        let is_zero = ct_eq_u8(b, 0x00);
        let is_one = ct_eq_u8(b, 0x01);
        let not_found = 1 ^ found_one;
        let bad_ps_byte = not_found & (1 ^ is_zero) & (1 ^ is_one);
        bad |= bad_ps_byte;
        let first_one = not_found & is_one;
        msg_start = ct_select_usize(first_one, i + 1, msg_start);
        found_one |= first_one;
    }

    bad |= 1 ^ found_one;

    let nz = (bad | bad.wrapping_neg()) >> 7;
    if nz != 0 {
        return None;
    }

    let mlen = db_len - msg_start;
    out[..mlen].copy_from_slice(&db[msg_start..msg_start + mlen]);
    Some(mlen)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_u8_matches_plain_equality() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected = u8::from(a == b);
                assert_eq!(ct_eq_u8(a, b), expected, "a={a} b={b}");
            }
        }
    }

    #[test]
    fn ct_select_usize_matches_branch() {
        assert_eq!(ct_select_usize(1, 17, 42), 17);
        assert_eq!(ct_select_usize(0, 17, 42), 42);
    }

    #[test]
    fn encode_then_decode_roundtrips_empty_label() {
        let label: &[u8] = b"";
        let msg = b"hello OAEP, can you hear me?";
        let seed = [0x5au8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(label, msg, &seed, &mut em).unwrap();

        let mut out = [0u8; MAX_MSG_LEN];
        let mlen = emsa_oaep_decode(label, &em, &mut out).unwrap();
        assert_eq!(mlen, msg.len());
        assert_eq!(&out[..mlen], msg);
    }

    #[test]
    fn encode_then_decode_roundtrips_with_label() {
        let label: &[u8] = b"context-2026-04";
        let msg = &[0xa5u8; 117];
        let seed = [0xc3u8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(label, msg, &seed, &mut em).unwrap();

        let mut out = [0u8; MAX_MSG_LEN];
        let mlen = emsa_oaep_decode(label, &em, &mut out).unwrap();
        assert_eq!(mlen, msg.len());
        assert_eq!(&out[..mlen], &msg[..]);
    }

    #[test]
    fn encode_rejects_oversize_message() {
        let seed = [0u8; HLEN];
        let mut em = [0u8; K];
        let msg = [0u8; MAX_MSG_LEN + 1];
        assert!(emsa_oaep_encode(b"", &msg, &seed, &mut em).is_none());
    }

    #[test]
    fn encode_accepts_max_length_message() {
        let seed = [0x11u8; HLEN];
        let mut em = [0u8; K];
        let msg = [0xeeu8; MAX_MSG_LEN];
        emsa_oaep_encode(b"", &msg, &seed, &mut em).unwrap();
        let mut out = [0u8; MAX_MSG_LEN];
        let mlen = emsa_oaep_decode(b"", &em, &mut out).unwrap();
        assert_eq!(mlen, MAX_MSG_LEN);
        assert_eq!(out, msg);
    }

    #[test]
    fn encode_accepts_empty_message() {
        let seed = [0x77u8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(b"lbl", &[], &seed, &mut em).unwrap();
        let mut out = [0u8; MAX_MSG_LEN];
        let mlen = emsa_oaep_decode(b"lbl", &em, &mut out).unwrap();
        assert_eq!(mlen, 0);
    }

    #[test]
    fn decode_rejects_wrong_label() {
        let seed = [0u8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(b"right-label", b"msg", &seed, &mut em).unwrap();
        let mut out = [0u8; MAX_MSG_LEN];
        assert!(emsa_oaep_decode(b"wrong-label", &em, &mut out).is_none());
    }

    #[test]
    fn decode_rejects_nonzero_y_byte() {
        let seed = [0u8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(b"", b"msg", &seed, &mut em).unwrap();
        em[0] = 0x01;
        let mut out = [0u8; MAX_MSG_LEN];
        assert!(emsa_oaep_decode(b"", &em, &mut out).is_none());
    }

    #[test]
    fn decode_rejects_flipped_masked_db() {
        let seed = [0u8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(b"", b"msg", &seed, &mut em).unwrap();
        // A bit-flip anywhere inside maskedDB propagates through MGF1
        // unmasking into DB; it'll either break the lHash' compare or
        // corrupt the PS zero-run, and the decoder must reject.
        em[200] ^= 0x01;
        let mut out = [0u8; MAX_MSG_LEN];
        assert!(emsa_oaep_decode(b"", &em, &mut out).is_none());
    }

    #[test]
    fn decode_rejects_flipped_masked_seed() {
        let seed = [0u8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(b"", b"msg", &seed, &mut em).unwrap();
        // A bit-flip inside maskedSeed inverts the recovered seed, which
        // through MGF1 inverts dbMask and corrupts DB entirely.
        em[5] ^= 0x80;
        let mut out = [0u8; MAX_MSG_LEN];
        assert!(emsa_oaep_decode(b"", &em, &mut out).is_none());
    }

    #[test]
    fn decode_rejects_all_zero_em() {
        let em = [0u8; K];
        let mut out = [0u8; MAX_MSG_LEN];
        assert!(emsa_oaep_decode(b"", &em, &mut out).is_none());
    }

    // --- Slice-based OAEP (for RSA-3072 / RSA-4096) ---

    #[test]
    fn encode_n_matches_fixed_for_2048() {
        let label = b"cross-check";
        let msg = b"hello fixed-vs-slice";
        let seed = [0x5au8; HLEN];
        let mut em_fixed = [0u8; K];
        emsa_oaep_encode(label, msg, &seed, &mut em_fixed).unwrap();
        let mut em_slice = [0u8; K];
        emsa_oaep_encode_n(label, msg, &seed, &mut em_slice).unwrap();
        assert_eq!(em_fixed, em_slice);
    }

    #[test]
    fn decode_n_matches_fixed_for_2048() {
        let label = b"";
        let msg = b"decode-crosscheck";
        let seed = [0x7fu8; HLEN];
        let mut em = [0u8; K];
        emsa_oaep_encode(label, msg, &seed, &mut em).unwrap();
        let mut out_fixed = [0u8; MAX_MSG_LEN];
        let mlen_fixed = emsa_oaep_decode(label, &em, &mut out_fixed).unwrap();
        let mut out_slice = [0u8; MAX_MSG_LEN];
        let mlen_slice = emsa_oaep_decode_n(label, &em, &mut out_slice).unwrap();
        assert_eq!(mlen_fixed, mlen_slice);
        assert_eq!(&out_fixed[..mlen_fixed], &out_slice[..mlen_slice]);
    }

    #[test]
    fn encode_n_roundtrip_3072() {
        // RSA-3072: k = 384, max_msg_len = 384 - 64 - 2 = 318.
        let k = 384;
        let max_msg_len = k - 2 * HLEN - 2;
        let msg = &[0xeeu8; 100];
        let seed = [0xabu8; HLEN];
        let mut em = [0u8; 384];
        emsa_oaep_encode_n(b"", msg, &seed, &mut em).unwrap();
        let mut out = [0u8; 318];
        let mlen = emsa_oaep_decode_n(b"", &em, &mut out).unwrap();
        assert_eq!(mlen, msg.len());
        assert_eq!(&out[..mlen], msg);
        // Max length message.
        let max_msg = [0xffu8; 318];
        emsa_oaep_encode_n(b"", &max_msg, &seed, &mut em).unwrap();
        let mlen = emsa_oaep_decode_n(b"", &em, &mut out).unwrap();
        assert_eq!(mlen, max_msg_len);
    }

    #[test]
    fn encode_n_roundtrip_4096() {
        // RSA-4096: k = 512, max_msg_len = 512 - 64 - 2 = 446.
        let k = 512;
        let max_msg_len = k - 2 * HLEN - 2;
        let msg = b"oaep-4096-roundtrip";
        let seed = [0xcdu8; HLEN];
        let mut em = [0u8; 512];
        emsa_oaep_encode_n(b"", msg, &seed, &mut em).unwrap();
        let mut out = [0u8; 446];
        let mlen = emsa_oaep_decode_n(b"", &em, &mut out).unwrap();
        assert_eq!(mlen, msg.len());
        assert_eq!(&out[..mlen], msg);
        // Max length message.
        let max_msg = [0x77u8; 446];
        emsa_oaep_encode_n(b"", &max_msg, &seed, &mut em).unwrap();
        let mlen = emsa_oaep_decode_n(b"", &em, &mut out).unwrap();
        assert_eq!(mlen, max_msg_len);
    }

    #[test]
    fn decode_n_rejects_wrong_label_3072() {
        let seed = [0u8; HLEN];
        let mut em = [0u8; 384];
        emsa_oaep_encode_n(b"right", b"msg", &seed, &mut em).unwrap();
        let mut out = [0u8; 318];
        assert!(emsa_oaep_decode_n(b"wrong", &em, &mut out).is_none());
    }

    #[test]
    fn encode_n_rejects_oversize() {
        let seed = [0u8; HLEN];
        let mut em = [0u8; 384];
        let msg = [0u8; 319]; // max is 318 for k=384
        assert!(emsa_oaep_encode_n(b"", &msg, &seed, &mut em).is_none());
    }
}
