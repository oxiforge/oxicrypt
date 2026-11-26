//! Byte encoding/decoding, compression/decompression, and centered
//! binomial distribution (CBD) sampling per FIPS 203 §4.2.1
//! (conversion and compression) and §4.2.2 (sampling).
//!
//! Every index in this module is bounded by compile-time constants or
//! explicit loop bounds.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::integer_division,
    clippy::many_single_char_names
)]

use crate::params::{N, Q_U32};

// ========================================================================
// ByteEncode / ByteDecode — FIPS 203 Algorithms 5–6
// ========================================================================

/// `ByteEncode_d` (FIPS 203 Algorithm 5): encode 256 coefficients at `d`
/// bits each into `32 · d` bytes (LSB-first bit packing).
///
/// Coefficients must be in [0, 2^d) for d < 12, or [0, q) for d = 12.
pub(crate) fn byte_encode(d: usize, coeffs: &[i16; N], out: &mut [u8]) {
    debug_assert!(out.len() >= 32 * d);
    for b in out.iter_mut().take(32 * d) {
        *b = 0;
    }
    let mut bit_pos: usize = 0;
    for i in 0..N {
        let mut a = coeffs[i] as u16;
        for _j in 0..d {
            let byte_idx = bit_pos >> 3;
            let bit_idx = bit_pos & 7;
            out[byte_idx] |= ((a & 1) as u8) << bit_idx;
            a >>= 1;
            bit_pos += 1;
        }
    }
}

/// `ByteDecode_d` (FIPS 203 Algorithm 6): decode `32 · d` bytes into 256
/// coefficients at `d` bits each (LSB-first bit unpacking).
///
/// For d = 12 the result is reduced mod q, as Algorithm 6 specifies. Only
/// `encapsulate` and `check_encapsulation_key` refuse a key with a value at
/// or above q ([`coefficients_below_q`], FIPS 203 §7.2). The other decoders
/// of 12-bit input (the ek stored inside a dk, ŝ, the pairwise consistency
/// test and the internal forms) take unchecked bytes and rely on the
/// reduction.
pub(crate) fn byte_decode(d: usize, bytes: &[u8], coeffs: &mut [i16; N]) {
    debug_assert!(bytes.len() >= 32 * d);
    let mut bit_pos: usize = 0;
    for i in 0..N {
        let mut a: u16 = 0;
        for j in 0..d {
            let byte_idx = bit_pos >> 3;
            let bit_idx = bit_pos & 7;
            a |= (((bytes[byte_idx] >> bit_idx) & 1) as u16) << j;
            bit_pos += 1;
        }
        if d == 12 {
            coeffs[i] = (a % (Q_U32 as u16)) as i16;
        } else {
            coeffs[i] = a as i16;
        }
    }
}

/// The modulus check of FIPS 203 §7.2 on `bytes`, a sequence of
/// `ByteEncode_12` polynomials: `true` when every 12-bit value is below q.
/// `ByteDecode_12` reduces mod q and `ByteEncode_12` is injective on
/// [0, q), so this holds exactly when
/// `ByteEncode_12(ByteDecode_12(bytes)) == bytes` (equation 7.1).
///
/// Every value is read and the verdict is accumulated without a branch on
/// any value, so the running time depends only on `bytes.len()`.
pub(crate) fn coefficients_below_q(bytes: &[u8]) -> bool {
    debug_assert_eq!(bytes.len() % 384, 0);
    let mut below = 1u32;
    for group in bytes.chunks_exact(3) {
        let a = (group[0] as u32) | (((group[1] as u32) & 0x0F) << 8);
        let b = ((group[1] as u32) >> 4) | ((group[2] as u32) << 4);
        below &= a.wrapping_sub(Q_U32) >> 31;
        below &= b.wrapping_sub(Q_U32) >> 31;
    }
    below == 1
}

// ========================================================================
// Compress / Decompress — FIPS 203 §4.2.1
// ========================================================================

/// `Compress_d(x)` = ⌈(2^d / q) · x⌋ mod 2^d.
///
/// Rounds x · 2^d / q to the nearest integer (mod 2^d).
/// Input: x ∈ [0, q).  Output: y ∈ [0, 2^d).
#[inline]
pub(crate) fn compress(d: u32, x: u16) -> u16 {
    // FIPS 203 equation 4.7, with ⌈·⌋ computed as floor(· + 1/2).
    let numerator = (x as u64) * (1u64 << d) + (Q_U32 as u64 / 2);
    let result = numerator / (Q_U32 as u64);
    (result as u16) & ((1u16 << d) - 1)
}

/// `Decompress_d(y)` = ⌈(q / 2^d) · y⌋.
///
/// Input: y ∈ [0, 2^d).  Output: x ∈ [0, q).
#[inline]
pub(crate) fn decompress(d: u32, y: u16) -> u16 {
    // FIPS 203 equation 4.8, with ⌈·⌋ computed as floor(· + 1/2).
    let numerator = (y as u32) * Q_U32 + (1u32 << (d - 1));
    (numerator >> d) as u16
}

pub(crate) fn compress_poly(d: u32, coeffs: &mut [i16; N]) {
    for i in 0..N {
        coeffs[i] = compress(d, coeffs[i] as u16) as i16;
    }
}

pub(crate) fn decompress_poly(d: u32, coeffs: &mut [i16; N]) {
    for i in 0..N {
        coeffs[i] = decompress(d, coeffs[i] as u16) as i16;
    }
}

// ========================================================================
// CBD — FIPS 203 Algorithm 8 (SamplePolyCBD_η)
// ========================================================================

/// Sample a polynomial from the centered binomial distribution
/// CBD(η) using `64 · η` bytes of pseudorandom input.
///
/// For η = 2: each coefficient is in {−2, −1, 0, 1, 2}.
/// For η = 3: each coefficient is in {−3, −2, −1, 0, 1, 2, 3}.
///
/// Result coefficients are reduced to [0, q) by adding q where
/// negative.
pub(crate) fn sample_cbd(eta: usize, bytes: &[u8], coeffs: &mut [i16; N]) {
    match eta {
        2 => sample_cbd2(bytes, coeffs),
        3 => sample_cbd3(bytes, coeffs),
        _ => {}
    }
}

/// CBD(η = 2): each coefficient uses 4 bits (2 for x, 2 for y).
/// Total: 128 bytes of input → 256 coefficients.
///
/// Reference: FIPS 203 Algorithm 8, η = 2.
fn sample_cbd2(bytes: &[u8], coeffs: &mut [i16; N]) {
    debug_assert!(bytes.len() >= 128);
    for i in 0..32 {
        let t = (bytes[4 * i] as u32)
            | ((bytes[4 * i + 1] as u32) << 8)
            | ((bytes[4 * i + 2] as u32) << 16)
            | ((bytes[4 * i + 3] as u32) << 24);

        let d = t & 0x5555_5555;
        let e = (t >> 1) & 0x5555_5555;
        let f = d + e;

        // FIPS 203 Algorithm 8 steps 3–5: in each 4-bit nibble the low
        // 2 bits are x, the high 2 bits are y, and the coefficient is x − y.
        for j in 0..8 {
            let a = ((f >> (4 * j)) & 3) as i16;
            let b = ((f >> (4 * j + 2)) & 3) as i16;
            let c = a - b;
            coeffs[8 * i + j] = if c < 0 { c + 3329 } else { c };
        }
    }
}

/// CBD(η = 3): each coefficient uses 6 bits (3 for x, 3 for y).
/// Total: 192 bytes of input → 256 coefficients.
///
/// Reference: FIPS 203 Algorithm 8, η = 3.
fn sample_cbd3(bytes: &[u8], coeffs: &mut [i16; N]) {
    debug_assert!(bytes.len() >= 192);
    for i in 0..64 {
        let t = (bytes[3 * i] as u32)
            | ((bytes[3 * i + 1] as u32) << 8)
            | ((bytes[3 * i + 2] as u32) << 16);

        let d = t & 0x0024_9249;
        let e = (t >> 1) & 0x0024_9249;
        let f = (t >> 2) & 0x0024_9249;
        let g = d + e + f;

        for j in 0..4 {
            let a = ((g >> (6 * j)) & 7) as i16;
            let b = ((g >> (6 * j + 3)) & 7) as i16;
            let c = a - b;
            coeffs[4 * i + j] = if c < 0 { c + 3329 } else { c };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `ByteEncode_12` group of three bytes holding the values `a`
    /// and `b`.
    fn group(a: u16, b: u16) -> [u8; 3] {
        [a as u8, ((a >> 8) as u8) | ((b as u8) << 4), (b >> 4) as u8]
    }

    /// The predicate accepts q − 1 in either value and refuses q and
    /// 4095 in either value, wherever the group sits in the input.
    #[test]
    fn coefficients_below_q_pins_each_value_position() {
        let q = Q_U32 as u16;
        let mut bytes = [0u8; 384];
        assert!(coefficients_below_q(&bytes));
        bytes[..3].copy_from_slice(&group(q - 1, q - 1));
        bytes[381..].copy_from_slice(&group(q - 1, q - 1));
        assert!(coefficients_below_q(&bytes));
        for at in [0, 381] {
            for (a, b) in [(q, 0), (0, q), (4095, 0), (0, 4095)] {
                let mut bad = bytes;
                bad[at..at + 3].copy_from_slice(&group(a, b));
                assert!(!coefficients_below_q(&bad), "({a}, {b}) at byte {at}");
            }
        }
    }

    /// For every 12-bit value, the predicate agrees with equation 7.1
    /// computed with `byte_decode` and `byte_encode`.
    #[test]
    fn coefficients_below_q_matches_re_encoding() {
        for v in 0u16..4096 {
            for (a, b) in [(v, 0), (0, v)] {
                let mut bytes = [0u8; 384];
                bytes[189..192].copy_from_slice(&group(a, b));
                let mut coeffs = [0i16; N];
                byte_decode(12, &bytes, &mut coeffs);
                let mut test = [0u8; 384];
                byte_encode(12, &coeffs, &mut test);
                assert_eq!(coefficients_below_q(&bytes), test == bytes, "({a}, {b})");
            }
        }
    }
}
