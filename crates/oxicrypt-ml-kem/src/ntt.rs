//! Number Theoretic Transform (NTT) over Z_q with q = 3329.
//!
//! ML-KEM uses an *incomplete* NTT: 7 layers of butterflies mapping
//! a degree-255 polynomial to 128 degree-1 quotient-ring elements.
//! The forward transform uses Cooley–Tukey butterflies; the inverse
//! uses Gentleman–Sande butterflies.
//!
//! The primitive 256th root of unity is ζ = 17.  Twiddle factors
//! (powers of ζ in bit-reversed order) are stored in Montgomery
//! domain in [`ZETAS`].
//!
//! Reference: FIPS 203 §4.3, Algorithms 9–10.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation
)]

use crate::field::{barrett_reduce, fqmul};
use crate::params::N;

/// Twiddle factors ζ^{BitRev₇(i)} in Montgomery domain (× 2¹⁶ mod q).
///
/// Sourced from the FIPS 203 / Kyber reference implementation.
/// `ZETAS[0]` (= ζ⁰ · R mod q = 2285) is unused by the NTT loop
/// which starts at index 1.
pub(crate) static ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// Forward NTT (Cooley–Tukey, in-place).
///
/// Input:  polynomial in normal domain with coefficients in (−q, q).
/// Output: polynomial in NTT domain (128 degree-1 pairs).
///
/// Corresponds to FIPS 203 Algorithm 9.
pub(crate) fn ntt(r: &mut [i16; N]) {
    let mut k: usize = 1;
    let mut len: usize = 128;
    while len >= 2 {
        let mut start: usize = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT (Gentleman–Sande, in-place).
///
/// Input:  polynomial in NTT domain.
/// Output: polynomial in normal domain, coefficients Barrett-reduced.
///
/// The final scaling by n⁻¹ = 128⁻¹ is folded into a Montgomery
/// multiply by f = R² · 128⁻¹ mod q = 1441.
///
/// Corresponds to FIPS 203 Algorithm 10.
pub(crate) fn inv_ntt(r: &mut [i16; N]) {
    /// Scaling factor: R² · 128⁻¹ mod q.
    ///
    /// Removes the accumulated R factors and applies the 1/128
    /// normalisation in a single Montgomery multiply at the end.
    const F: i16 = 1441;

    let mut k: usize = 127;
    let mut len: usize = 2;
    while len <= 128 {
        let mut start: usize = 0;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..(start + len) {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = fqmul(zeta, r[j + len] - t);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for j in 0..N {
        r[j] = fqmul(r[j], F);
    }
}

/// Base-case multiplication of two degree-1 NTT elements.
///
/// Computes (a₀ + a₁X)(b₀ + b₁X) mod (X² − γ) where γ = ζ^{2·BitRev₇(i)+1}
/// is supplied in Montgomery domain.
///
/// Output coefficients carry one extra R⁻¹ factor relative to the true
/// product, because every term goes through `fqmul`.
#[inline]
pub(crate) fn basemul(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> (i16, i16) {
    let r0 = fqmul(a1, b1);
    let r0 = fqmul(r0, zeta) + fqmul(a0, b0);
    let r1 = fqmul(a0, b1) + fqmul(a1, b0);
    (r0, r1)
}
