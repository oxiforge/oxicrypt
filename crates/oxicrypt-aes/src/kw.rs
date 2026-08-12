//! AES Key Wrap (KW) and Key Wrap with Padding (KWP) per
//! NIST SP 800-38F / RFC 3394 / RFC 5649.
//!
//! # Scope
//!
//! Implements the two wrapping modes in SP 800-38F:
//!
//!   * **KW** (§6.2, Algorithms 3/4 "KW-AE" / "KW-AD", over the W and
//!     W^-1 functions of §6.1) — the original
//!     RFC 3394 key wrap, with the default integrity check value
//!     `A6A6A6A6A6A6A6A6`. Input length must be a positive multiple
//!     of 8 bytes and at least 16 bytes (two 8-byte semiblocks).
//!   * **KWP** (§6.3, Algorithms 5/6 "KWP-AE" / "KWP-AD") — the
//!     padded variant from RFC 5649. Accepts any plaintext of length
//!     1..=2^32 - 1 bytes, prefixes the alternative IV
//!     `A65959A6 || [mli]_32`, zero-pads to a multiple of 8 bytes,
//!     and either runs a single AES block encrypt (when the padded
//!     input fits in 16 bytes) or feeds the result into the standard
//!     KW wrapping function.
//!
//! Each mode is exposed in two cipher directions, both defined by
//! SP 800-38F §5.1 / §6.2:
//!
//!   * **Forward cipher** (the default, ACVP `kwCipher = "cipher"`):
//!     the W function uses the AES forward cipher (encrypt) for wrap
//!     and the AES inverse cipher (decrypt) for unwrap. Exposed as
//!     [`kw_wrap`] / [`kw_unwrap`] / [`kwp_wrap`] / [`kwp_unwrap`].
//!   * **Inverse cipher** (ACVP `kwCipher = "inverse"`): the W
//!     function uses the AES inverse cipher (decrypt) for wrap and
//!     the AES forward cipher (encrypt) for unwrap. Exposed as
//!     [`kw_wrap_inverse_cipher`] / [`kw_unwrap_inverse_cipher`] /
//!     [`kwp_wrap_inverse_cipher`] / [`kwp_unwrap_inverse_cipher`].
//!
//! The two directions are distinct algorithms — a wrap produced in
//! one direction is rejected by the other's ICV check with
//! overwhelming probability.
//!
//! The unwrap directions verify the published ICV: KW compares all
//! eight bytes against `A6A6A6A6A6A6A6A6`, KWP compares the four
//! `A65959A6` prefix bytes and then checks the declared length and the
//! zero padding. The wrap directions write the ICV. Any mismatch returns
//! [`ModeError::TagMismatch`]. Length mismatches and invalid inputs
//! return dedicated variants of [`ModeError`].
//!
//! # Ciphertext length
//!
//! For both KW and KWP, the wrapped output length equals the input
//! plaintext length rounded up to the next multiple of 8 **plus** 8
//! bytes for the prepended integrity-check semiblock.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::trivially_copy_pass_by_ref
)]

use crate::modes::{BlockCipher, ModeError};

/// Semiblock size in bytes. AES has a 128-bit block, so each
/// semiblock is 8 bytes (SP 800-38F §5.1).
const SEMI: usize = 8;

/// Default KW integrity check value (RFC 3394 §2.2.3.1,
/// SP 800-38F §6.2). Eight copies of the byte `0xA6`.
pub const KW_DEFAULT_IV: [u8; SEMI] = [0xA6; SEMI];

/// KWP alternative initial value prefix (RFC 5649 §3,
/// SP 800-38F §6.3). Four bytes; the remaining 4 bytes carry the
/// big-endian plaintext byte length (`mli`).
pub const KWP_IV_PREFIX: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

// ----------------------------------------------------------------------
// KW — RFC 3394 / SP 800-38F §6.2
// ----------------------------------------------------------------------

/// Core "W" wrapping function (SP 800-38F §6.1, Algorithm 1).
///
/// Takes an initial value `a` (8 bytes) and an `n`-semiblock input
/// `r` (n ≥ 2) stored as `n * 8` contiguous bytes in `r_out`, and
/// updates `r_out` in place so that the first 8 bytes become the
/// final A value and the remaining `n * 8` bytes become the wrapped
/// registers `R[1..n]`.
///
/// Laid out in this shape so both KW wrapping and the n ≥ 3 case of
/// KWP wrapping share the same core loop.
fn w_core<B: BlockCipher>(cipher: &B, a: &mut [u8; SEMI], r_out: &mut [u8]) {
    let n = r_out.len() / SEMI;
    for j in 0..6u64 {
        for i in 1..=n {
            // B_in = A || R[i]
            let mut blk = [0u8; 16];
            blk[..SEMI].copy_from_slice(a);
            blk[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.encrypt_block(&mut blk);
            // A = MSB_64(B_out) XOR t, where t = n*j + i.
            a.copy_from_slice(&blk[..SEMI]);
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            for k in 0..SEMI {
                a[k] ^= tb[k];
            }
            // R[i] = LSB_64(B_out).
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk[SEMI..]);
        }
    }
}

/// Core "W^-1" unwrapping function (SP 800-38F §6.1, Algorithm 2).
fn w_core_inv<B: BlockCipher>(cipher: &B, a: &mut [u8; SEMI], r_out: &mut [u8]) {
    let n = r_out.len() / SEMI;
    for j in (0..6u64).rev() {
        for i in (1..=n).rev() {
            // B_in = (A XOR t) || R[i]
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            let mut blk = [0u8; 16];
            for k in 0..SEMI {
                blk[k] = a[k] ^ tb[k];
            }
            blk[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.decrypt_block(&mut blk);
            a.copy_from_slice(&blk[..SEMI]);
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk[SEMI..]);
        }
    }
}

/// Constant-time equality on 8 bytes.
fn ct_eq8(a: &[u8; SEMI], b: &[u8; SEMI]) -> bool {
    let mut diff: u8 = 0;
    for k in 0..SEMI {
        diff |= a[k] ^ b[k];
    }
    diff == 0
}

/// AES-KW wrap (SP 800-38F §6.2, Algorithm 3 "KW-AE").
///
/// `plaintext` length must be a positive multiple of 8 and at least
/// 16 bytes. `ciphertext_out` must be exactly `plaintext.len() + 8`
/// bytes.
pub fn kw_wrap<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    if plaintext.len() < 2 * SEMI
        || plaintext.len() % SEMI != 0
        || ciphertext_out.len() != plaintext.len() + SEMI
    {
        return Err(ModeError::LengthMismatch);
    }
    let mut a = KW_DEFAULT_IV;
    ciphertext_out[SEMI..].copy_from_slice(plaintext);
    w_core(cipher, &mut a, &mut ciphertext_out[SEMI..]);
    ciphertext_out[..SEMI].copy_from_slice(&a);
    Ok(())
}

/// AES-KW unwrap (SP 800-38F §6.2, Algorithm 4 "KW-AD").
///
/// `ciphertext` length must be a positive multiple of 8 and at least
/// 24 bytes. `plaintext_out` must be exactly `ciphertext.len() - 8`
/// bytes. Returns [`ModeError::TagMismatch`] if the ICV did not
/// verify.
pub fn kw_unwrap<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    if ciphertext.len() < 3 * SEMI
        || ciphertext.len() % SEMI != 0
        || plaintext_out.len() != ciphertext.len() - SEMI
    {
        return Err(ModeError::LengthMismatch);
    }
    let mut a = [0u8; SEMI];
    a.copy_from_slice(&ciphertext[..SEMI]);
    plaintext_out.copy_from_slice(&ciphertext[SEMI..]);
    w_core_inv(cipher, &mut a, plaintext_out);
    if !ct_eq8(&a, &KW_DEFAULT_IV) {
        return Err(ModeError::TagMismatch);
    }
    Ok(())
}

// ----------------------------------------------------------------------
// KWP — RFC 5649 / SP 800-38F §6.3
// ----------------------------------------------------------------------

/// AES-KWP wrap (SP 800-38F §6.3, Algorithm 5 "KWP-AE").
///
/// `plaintext` may be any length from 1 to 2^32 − 1 bytes.
/// `ciphertext_out` must have length `((plaintext.len() + 7) / 8) * 8
/// + 8` bytes.
pub fn kwp_wrap<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    let mli = plaintext.len();
    if mli == 0 || mli > u32::MAX as usize {
        return Err(ModeError::LengthMismatch);
    }
    let padded_pt_len = mli.div_ceil(SEMI) * SEMI;
    let total = padded_pt_len + SEMI;
    if ciphertext_out.len() != total {
        return Err(ModeError::LengthMismatch);
    }

    // Build the alternative ICV: 0xA6 0x59 0x59 0xA6 || [mli]_32
    let mut aiv = [0u8; SEMI];
    aiv[..4].copy_from_slice(&KWP_IV_PREFIX);
    let mli_be = (mli as u32).to_be_bytes();
    aiv[4..].copy_from_slice(&mli_be);

    if padded_pt_len == SEMI {
        // Single AES block direct encrypt path (RFC 5649 §4.1 case
        // "n == 1 semiblock of plaintext padding"; SP 800-38F §6.3
        // Algorithm 5 step 5, "If len(P) <= 64, then return C = CIPHK(S)").
        // S = AIV || padded_PT.
        let mut blk = [0u8; 16];
        blk[..SEMI].copy_from_slice(&aiv);
        blk[SEMI..SEMI + mli].copy_from_slice(plaintext);
        cipher.encrypt_block(&mut blk);
        ciphertext_out.copy_from_slice(&blk);
    } else {
        // Multi-semiblock path: run W with A = AIV over the padded
        // plaintext placed in ciphertext_out[SEMI..].
        let mut a = aiv;
        ciphertext_out[SEMI..SEMI + mli].copy_from_slice(plaintext);
        for b in &mut ciphertext_out[SEMI + mli..] {
            *b = 0;
        }
        w_core(cipher, &mut a, &mut ciphertext_out[SEMI..]);
        ciphertext_out[..SEMI].copy_from_slice(&a);
    }
    Ok(())
}

/// AES-KWP unwrap (SP 800-38F §6.3, Algorithm 6 "KWP-AD").
///
/// Returns the unwrapped plaintext byte length (always ≤ the length
/// of `plaintext_out_scratch`, which must be at least
/// `ciphertext.len() - 8` bytes long — i.e. it holds the padded
/// plaintext buffer, and callers take only the first `mli` bytes of
/// it after a successful unwrap).
///
/// Returns [`ModeError::TagMismatch`] if the ICV prefix did not
/// match, the declared `mli` is inconsistent with the padded length,
/// or any of the pad bytes are non-zero.
pub fn kwp_unwrap<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out_scratch: &mut [u8],
) -> Result<usize, ModeError> {
    if ciphertext.len() < 2 * SEMI
        || ciphertext.len() % SEMI != 0
        || plaintext_out_scratch.len() != ciphertext.len() - SEMI
    {
        return Err(ModeError::LengthMismatch);
    }
    let mut aiv = [0u8; SEMI];
    if ciphertext.len() == 2 * SEMI {
        // Single AES block direct decrypt path.
        let mut blk = [0u8; 16];
        blk.copy_from_slice(ciphertext);
        cipher.decrypt_block(&mut blk);
        aiv.copy_from_slice(&blk[..SEMI]);
        plaintext_out_scratch.copy_from_slice(&blk[SEMI..]);
    } else {
        aiv.copy_from_slice(&ciphertext[..SEMI]);
        plaintext_out_scratch.copy_from_slice(&ciphertext[SEMI..]);
        w_core_inv(cipher, &mut aiv, plaintext_out_scratch);
    }

    // Check prefix constant bytes with a constant-time comparison.
    let mut diff: u8 = 0;
    for k in 0..4 {
        diff |= aiv[k] ^ KWP_IV_PREFIX[k];
    }
    // Recover declared mli and bound it.
    let mli = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]) as usize;
    // mli must satisfy: padded_pt_len - 7 ≤ mli ≤ padded_pt_len and
    // (padded_pt_len == mli's ceiling-to-8).
    let padded_pt_len = plaintext_out_scratch.len();
    let in_range = mli <= padded_pt_len && (padded_pt_len - mli) < SEMI && mli > 0;
    if diff != 0 || !in_range {
        return Err(ModeError::TagMismatch);
    }
    // Check that the trailing pad bytes are all zero.
    let mut pad_diff: u8 = 0;
    for k in mli..padded_pt_len {
        pad_diff |= plaintext_out_scratch[k];
    }
    if pad_diff != 0 {
        return Err(ModeError::TagMismatch);
    }
    Ok(mli)
}

// ----------------------------------------------------------------------
// Inverse-cipher direction (SP 800-38F §6.2 / ACVP kwCipher = "inverse")
// ----------------------------------------------------------------------
//
// Mirrors the forward-cipher KW/KWP family above. The W function and
// algorithmic structure are unchanged; only the underlying AES block
// direction inverts:
//
//   * Wrap (KW-AE / KWP-AE) drives the W function with `decrypt_block`.
//   * Unwrap (KW-AD / KWP-AD) drives the W^-1 function with
//     `encrypt_block`.
//
// The ICV (`A6A6A6A6A6A6A6A6` for KW, `A65959A6 || [mli]_32` for KWP)
// is unchanged and is checked with a constant-time comparison exactly as in the
// forward-cipher path. Cross-direction unwrap (forward-wrapped input
// fed through inverse-unwrap, or vice versa) is rejected by the ICV
// check with overwhelming probability.

/// Inverse-cipher core "W" wrapping function. Identical to [`w_core`]
/// but invokes `cipher.decrypt_block` as the underlying block primitive.
fn w_core_inverse_cipher<B: BlockCipher>(cipher: &B, a: &mut [u8; SEMI], r_out: &mut [u8]) {
    let n = r_out.len() / SEMI;
    for j in 0..6u64 {
        for i in 1..=n {
            let mut blk = [0u8; 16];
            blk[..SEMI].copy_from_slice(a);
            blk[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.decrypt_block(&mut blk);
            a.copy_from_slice(&blk[..SEMI]);
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            for k in 0..SEMI {
                a[k] ^= tb[k];
            }
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk[SEMI..]);
        }
    }
}

/// Inverse-cipher core "W^-1" unwrapping function. Identical to
/// [`w_core_inv`] but invokes `cipher.encrypt_block` as the
/// underlying block primitive.
fn w_core_inverse_cipher_inv<B: BlockCipher>(cipher: &B, a: &mut [u8; SEMI], r_out: &mut [u8]) {
    let n = r_out.len() / SEMI;
    for j in (0..6u64).rev() {
        for i in (1..=n).rev() {
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            let mut blk = [0u8; 16];
            for k in 0..SEMI {
                blk[k] = a[k] ^ tb[k];
            }
            blk[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.encrypt_block(&mut blk);
            a.copy_from_slice(&blk[..SEMI]);
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk[SEMI..]);
        }
    }
}

/// AES-KW wrap with the inverse cipher direction (SP 800-38F §6.2,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kw_wrap`].
pub fn kw_wrap_inverse_cipher<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    if plaintext.len() < 2 * SEMI
        || plaintext.len() % SEMI != 0
        || ciphertext_out.len() != plaintext.len() + SEMI
    {
        return Err(ModeError::LengthMismatch);
    }
    let mut a = KW_DEFAULT_IV;
    ciphertext_out[SEMI..].copy_from_slice(plaintext);
    w_core_inverse_cipher(cipher, &mut a, &mut ciphertext_out[SEMI..]);
    ciphertext_out[..SEMI].copy_from_slice(&a);
    Ok(())
}

/// AES-KW unwrap with the inverse cipher direction (SP 800-38F §6.2,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kw_unwrap`]. Returns
/// [`ModeError::TagMismatch`] on ICV mismatch — including the case
/// where the input was wrapped with the forward cipher direction.
pub fn kw_unwrap_inverse_cipher<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    if ciphertext.len() < 3 * SEMI
        || ciphertext.len() % SEMI != 0
        || plaintext_out.len() != ciphertext.len() - SEMI
    {
        return Err(ModeError::LengthMismatch);
    }
    let mut a = [0u8; SEMI];
    a.copy_from_slice(&ciphertext[..SEMI]);
    plaintext_out.copy_from_slice(&ciphertext[SEMI..]);
    w_core_inverse_cipher_inv(cipher, &mut a, plaintext_out);
    if !ct_eq8(&a, &KW_DEFAULT_IV) {
        return Err(ModeError::TagMismatch);
    }
    Ok(())
}

/// AES-KWP wrap with the inverse cipher direction (SP 800-38F §6.3,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kwp_wrap`].
pub fn kwp_wrap_inverse_cipher<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    let mli = plaintext.len();
    if mli == 0 || mli > u32::MAX as usize {
        return Err(ModeError::LengthMismatch);
    }
    let padded_pt_len = mli.div_ceil(SEMI) * SEMI;
    let total = padded_pt_len + SEMI;
    if ciphertext_out.len() != total {
        return Err(ModeError::LengthMismatch);
    }

    let mut aiv = [0u8; SEMI];
    aiv[..4].copy_from_slice(&KWP_IV_PREFIX);
    let mli_be = (mli as u32).to_be_bytes();
    aiv[4..].copy_from_slice(&mli_be);

    if padded_pt_len == SEMI {
        // Single AES block direct path; inverse cipher uses
        // `decrypt_block` as the wrapping primitive (SP 800-38F §6.3
        // Algorithm 5 step 5, under the inverse-cipher direction).
        let mut blk = [0u8; 16];
        blk[..SEMI].copy_from_slice(&aiv);
        blk[SEMI..SEMI + mli].copy_from_slice(plaintext);
        cipher.decrypt_block(&mut blk);
        ciphertext_out.copy_from_slice(&blk);
    } else {
        let mut a = aiv;
        ciphertext_out[SEMI..SEMI + mli].copy_from_slice(plaintext);
        for b in &mut ciphertext_out[SEMI + mli..] {
            *b = 0;
        }
        w_core_inverse_cipher(cipher, &mut a, &mut ciphertext_out[SEMI..]);
        ciphertext_out[..SEMI].copy_from_slice(&a);
    }
    Ok(())
}

/// AES-KWP unwrap with the inverse cipher direction (SP 800-38F §6.3,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kwp_unwrap`]. Returns
/// [`ModeError::TagMismatch`] on ICV-prefix mismatch, inconsistent
/// declared `mli`, non-zero pad bytes, or input wrapped with the
/// forward cipher direction.
pub fn kwp_unwrap_inverse_cipher<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out_scratch: &mut [u8],
) -> Result<usize, ModeError> {
    if ciphertext.len() < 2 * SEMI
        || ciphertext.len() % SEMI != 0
        || plaintext_out_scratch.len() != ciphertext.len() - SEMI
    {
        return Err(ModeError::LengthMismatch);
    }
    let mut aiv = [0u8; SEMI];
    if ciphertext.len() == 2 * SEMI {
        // Single AES block direct path; inverse-cipher unwrap drives
        // the AES forward cipher.
        let mut blk = [0u8; 16];
        blk.copy_from_slice(ciphertext);
        cipher.encrypt_block(&mut blk);
        aiv.copy_from_slice(&blk[..SEMI]);
        plaintext_out_scratch.copy_from_slice(&blk[SEMI..]);
    } else {
        aiv.copy_from_slice(&ciphertext[..SEMI]);
        plaintext_out_scratch.copy_from_slice(&ciphertext[SEMI..]);
        w_core_inverse_cipher_inv(cipher, &mut aiv, plaintext_out_scratch);
    }

    let mut diff: u8 = 0;
    for k in 0..4 {
        diff |= aiv[k] ^ KWP_IV_PREFIX[k];
    }
    let mli = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]) as usize;
    let padded_pt_len = plaintext_out_scratch.len();
    let in_range = mli <= padded_pt_len && (padded_pt_len - mli) < SEMI && mli > 0;
    if diff != 0 || !in_range {
        return Err(ModeError::TagMismatch);
    }
    let mut pad_diff: u8 = 0;
    for k in mli..padded_pt_len {
        pad_diff |= plaintext_out_scratch[k];
    }
    if pad_diff != 0 {
        return Err(ModeError::TagMismatch);
    }
    Ok(mli)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        kw_unwrap, kw_unwrap_inverse_cipher, kw_wrap, kw_wrap_inverse_cipher, kwp_unwrap,
        kwp_unwrap_inverse_cipher, kwp_wrap, kwp_wrap_inverse_cipher,
    };
    use crate::block::{Aes128Key, Aes192Key, Aes256Key};

    // RFC 3394 §4.1 — AES-128 wrap of 128-bit key.
    #[test]
    fn rfc3394_4_1_aes128_wrap_128() {
        let kek: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected: [u8; 24] = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        let k = Aes128Key::new_internal(&kek);
        let mut ct = [0u8; 24];
        kw_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut back = [0u8; 16];
        kw_unwrap(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    // RFC 3394 §4.6 — AES-256 wrap of 256-bit key.
    #[test]
    fn rfc3394_4_6_aes256_wrap_256() {
        let kek: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let pt: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let expected: [u8; 40] = [
            0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
            0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
            0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
        ];
        let k = Aes256Key::new_internal(&kek);
        let mut ct = [0u8; 40];
        kw_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut back = [0u8; 32];
        kw_unwrap(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    // RFC 5649 §6 — AES-192 KWP wrap of 7-byte key (single-block path).
    #[test]
    fn rfc5649_kwp_aes192_7_bytes() {
        let kek: [u8; 24] = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt: [u8; 7] = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
        let expected: [u8; 16] = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b,
            0xb2, 0x4f,
        ];
        let k = Aes192Key::new_internal(&kek);
        let mut ct = [0u8; 16];
        kwp_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut scratch = [0u8; 8];
        let mli = kwp_unwrap(&k, &ct, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);
    }

    // RFC 5649 §6 — AES-192 KWP wrap of 20-byte key (multi-semiblock path).
    #[test]
    fn rfc5649_kwp_aes192_20_bytes() {
        let kek: [u8; 24] = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt: [u8; 20] = [
            0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89,
            0x41, 0x15, 0x50, 0x68, 0xf7, 0x38,
        ];
        let expected: [u8; 32] = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];
        let k = Aes192Key::new_internal(&kek);
        let mut ct = [0u8; 32];
        kwp_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut scratch = [0u8; 24];
        let mli = kwp_unwrap(&k, &ct, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);
    }

    #[test]
    fn kw_rejects_tampered_icv() {
        let kek = [0u8; 16];
        let pt = [0xaau8; 16];
        let k = Aes128Key::new_internal(&kek);
        let mut ct = [0u8; 24];
        kw_wrap(&k, &pt, &mut ct).unwrap();
        ct[0] ^= 1;
        let mut back = [0u8; 16];
        assert!(kw_unwrap(&k, &ct, &mut back).is_err());
    }

    // ---- Inverse-cipher direction (SP 800-38F §6.2 / kwCipher = "inverse")

    // Round-trip self-consistency over the three FIPS key sizes for KW
    // and a representative payload length. Distinct from the forward
    // direction — wrapped output is verified to differ.
    #[test]
    fn kw_inverse_cipher_round_trip_aes128() {
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let k = Aes128Key::new_internal(&kek);
        let mut ct_inv = [0u8; 24];
        kw_wrap_inverse_cipher(&k, &pt, &mut ct_inv).unwrap();
        let mut back = [0u8; 16];
        kw_unwrap_inverse_cipher(&k, &ct_inv, &mut back).unwrap();
        assert_eq!(back, pt);

        // Forward-cipher wrap of the same input must produce a different
        // ciphertext — the modes are distinct algorithms.
        let mut ct_fwd = [0u8; 24];
        kw_wrap(&k, &pt, &mut ct_fwd).unwrap();
        assert_ne!(ct_inv, ct_fwd);
    }

    #[test]
    fn kw_inverse_cipher_round_trip_aes192() {
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = [0x5au8; 32];
        let k = Aes192Key::new_internal(&kek);
        let mut ct = [0u8; 40];
        kw_wrap_inverse_cipher(&k, &pt, &mut ct).unwrap();
        let mut back = [0u8; 32];
        kw_unwrap_inverse_cipher(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn kw_inverse_cipher_round_trip_aes256() {
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let k = Aes256Key::new_internal(&kek);
        let mut ct = [0u8; 40];
        kw_wrap_inverse_cipher(&k, &pt, &mut ct).unwrap();
        let mut back = [0u8; 32];
        kw_unwrap_inverse_cipher(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    // Cross-direction unwrap must reject — a forward-wrapped input fed
    // to inverse-unwrap fails the ICV check with overwhelming
    // probability, and vice versa.
    #[test]
    fn kw_cross_direction_rejects() {
        let kek = [0x42u8; 16];
        let pt = [0xa5u8; 24];
        let k = Aes128Key::new_internal(&kek);
        let mut ct_fwd = [0u8; 32];
        kw_wrap(&k, &pt, &mut ct_fwd).unwrap();
        let mut back = [0u8; 24];
        // Forward-wrapped ct fed through inverse-unwrap: ICV mismatch.
        assert!(kw_unwrap_inverse_cipher(&k, &ct_fwd, &mut back).is_err());

        let mut ct_inv = [0u8; 32];
        kw_wrap_inverse_cipher(&k, &pt, &mut ct_inv).unwrap();
        // Inverse-wrapped ct fed through forward-unwrap: ICV mismatch.
        assert!(kw_unwrap(&k, &ct_inv, &mut back).is_err());
    }

    // KWP inverse-cipher: single-block path (padded length == 8 bytes,
    // RFC 5649 §4.1 fast path) plus multi-semiblock path. Round-trip
    // both and verify divergence from the forward direction.
    #[test]
    fn kwp_inverse_cipher_round_trip_single_block() {
        let kek = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt = [0x46u8, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69]; // 7 bytes -> 1 block
        let k = Aes192Key::new_internal(&kek);
        let mut ct_inv = [0u8; 16];
        kwp_wrap_inverse_cipher(&k, &pt, &mut ct_inv).unwrap();
        let mut scratch = [0u8; 8];
        let mli = kwp_unwrap_inverse_cipher(&k, &ct_inv, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);

        // Forward-cipher KWP of the same input must differ.
        let mut ct_fwd = [0u8; 16];
        kwp_wrap(&k, &pt, &mut ct_fwd).unwrap();
        assert_ne!(ct_inv, ct_fwd);
    }

    #[test]
    fn kwp_inverse_cipher_round_trip_multi_block() {
        let kek = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt = [
            0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89,
            0x41, 0x15, 0x50, 0x68, 0xf7, 0x38,
        ]; // 20 bytes -> 24-byte padded
        let k = Aes192Key::new_internal(&kek);
        let mut ct = [0u8; 32];
        kwp_wrap_inverse_cipher(&k, &pt, &mut ct).unwrap();
        let mut scratch = [0u8; 24];
        let mli = kwp_unwrap_inverse_cipher(&k, &ct, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);
    }

    #[test]
    fn kwp_inverse_cipher_rejects_tampered_icv() {
        let kek = [0u8; 16];
        let pt = [0xc3u8; 24];
        let k = Aes128Key::new_internal(&kek);
        let mut ct = [0u8; 32];
        kwp_wrap_inverse_cipher(&k, &pt, &mut ct).unwrap();
        ct[0] ^= 1;
        let mut scratch = [0u8; 24];
        assert!(kwp_unwrap_inverse_cipher(&k, &ct, &mut scratch).is_err());
    }
}
