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

/// `ByteEncode_d`: encode 256 coefficients at `d` bits each into
/// `32 · d` bytes (LSB-first bit packing).
///
/// Coefficients must be in [0, 2^d) for d < 12, or [0, q) for d = 12.
pub(crate) fn byte_encode(d: usize, coeffs: &[i16; N], out: &mut [u8]) {
    debug_assert!(out.len() >= 32 * d);
    // Zero the output
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

/// `ByteDecode_d`: decode `32 · d` bytes into 256 coefficients at
/// `d` bits each (LSB-first bit unpacking).
///
/// For d = 12 the result is reduced mod q.
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
            // Reduce mod q for the 12-bit case
            coeffs[i] = (a % (Q_U32 as u16)) as i16;
        } else {
            coeffs[i] = a as i16;
        }
    }
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
    // y = round(x · 2^d / q) = floor((x · 2^d + q/2) / q)
    let numerator = (x as u64) * (1u64 << d) + (Q_U32 as u64 / 2);
    let result = numerator / (Q_U32 as u64);
    (result as u16) & ((1u16 << d) - 1)
}

/// `Decompress_d(y)` = ⌈(q / 2^d) · y⌋.
///
/// Input: y ∈ [0, 2^d).  Output: x ∈ [0, q).
#[inline]
pub(crate) fn decompress(d: u32, y: u16) -> u16 {
    // x = round(y · q / 2^d) = floor((y · q + 2^(d-1)) / 2^d)
    let numerator = (y as u32) * Q_U32 + (1u32 << (d - 1));
    (numerator >> d) as u16
}

/// Compress an entire polynomial (in-place) at bit-width `d`.
pub(crate) fn compress_poly(d: u32, coeffs: &mut [i16; N]) {
    for i in 0..N {
        coeffs[i] = compress(d, coeffs[i] as u16) as i16;
    }
}

/// Decompress an entire polynomial (in-place) at bit-width `d`.
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
    // Process 4 bytes → 8 coefficients per iteration, 32 iterations.
    for i in 0..32 {
        let t = (bytes[4 * i] as u32)
            | ((bytes[4 * i + 1] as u32) << 8)
            | ((bytes[4 * i + 2] as u32) << 16)
            | ((bytes[4 * i + 3] as u32) << 24);

        // Popcount trick: sum adjacent bit pairs
        let d = t & 0x5555_5555;
        let e = (t >> 1) & 0x5555_5555;
        let f = d + e; // Each 2-bit field holds popcount ∈ {0, 1, 2}

        // Extract 8 coefficients: for each 4-bit nibble, low 2 bits
        // are x (sum), high 2 bits are y (sum), coefficient = x − y.
        for j in 0..8 {
            let a = ((f >> (4 * j)) & 3) as i16;
            let b = ((f >> (4 * j + 2)) & 3) as i16;
            let c = a - b;
            // Reduce to [0, q): add q if negative
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
    // Process 3 bytes → 4 coefficients per iteration, 64 iterations.
    for i in 0..64 {
        let t = (bytes[3 * i] as u32)
            | ((bytes[3 * i + 1] as u32) << 8)
            | ((bytes[3 * i + 2] as u32) << 16);

        // Popcount trick: sum 3 adjacent bits
        let d = t & 0x0024_9249;
        let e = (t >> 1) & 0x0024_9249;
        let f = (t >> 2) & 0x0024_9249;
        let g = d + e + f; // Each 3-bit field holds popcount ∈ {0,1,2,3}

        for j in 0..4 {
            let a = ((g >> (6 * j)) & 7) as i16;
            let b = ((g >> (6 * j + 3)) & 7) as i16;
            let c = a - b;
            coeffs[4 * i + j] = if c < 0 { c + 3329 } else { c };
        }
    }
}
