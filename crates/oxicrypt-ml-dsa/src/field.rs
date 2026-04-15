//! Field arithmetic modulo q = 8380417 for ML-DSA.
//!
//! ML-DSA uses 32-bit Montgomery multiplication for NTT operations.
//! Montgomery domain: â = a · R mod q where R = 2³².
//!
//! q = 8380417 = 2²³ − 2¹³ + 1, a 23-bit prime.
//! q ≡ 1 (mod 512), so a primitive 512th root of unity exists.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::integer_division
)]

use crate::params::Q;

/// q⁻¹ mod 2³² = 58728449.
///
/// q · q⁻¹ ≡ 1 (mod 2³²).  Used in Montgomery reduction:
/// t = (a mod R) · q⁻¹ mod R, then (a − t·q) / R.
const QINV: u32 = 58_728_449; // q⁻¹ mod 2³²

/// R² mod q = (2³²)² mod q = (2⁶⁴) mod q.
///
/// Used to convert normal-domain values to Montgomery domain.
/// 2⁶⁴ mod 8380417 = 2365951.
#[allow(dead_code)]
const R2: i32 = 2_365_951;

/// Montgomery reduction: given a 64-bit product, compute a · R⁻¹ mod q.
///
/// Input: a ∈ (−2⁶³, 2⁶³) (practically bounded by product of two
/// values < q·R).
/// Output: r ∈ (−q, q).
///
/// The result is not fully reduced; caller may need to add q or apply
/// further reduction.
#[inline]
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    // t = (a mod R) · q⁻¹ mod R   (low 32 bits only)
    let t = (a as u32).wrapping_mul(QINV) as i32;
    // (a − t · q) is divisible by R = 2³²; arithmetic right shift by 32
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

/// Multiply two i32 values in Montgomery domain, returning the
/// product in Montgomery domain: fqmul(â, b̂) = â · b̂ · R⁻¹ mod q.
#[inline]
pub(crate) fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce((a as i64) * (b as i64))
}

/// Convert a normal-domain value to Montgomery domain.
///
/// to_mont(a) = a · R mod q = montgomery_reduce(a · R²)
#[inline]
#[allow(dead_code)]
pub(crate) fn to_mont(a: i32) -> i32 {
    fqmul(a, R2)
}

/// Reduce a coefficient modulo q to the range [0, q).
///
/// Input: a ∈ (−2q, 2q) approximately.
/// Output: r ∈ [0, q).
#[inline]
pub(crate) fn reduce32(a: i32) -> i32 {
    // t ≈ a / q using the approximation: t = (a + (1<<22)) >> 23
    // This works because q ≈ 2²³.
    let t = (a + (1 << 22)) >> 23;
    let mut r = a - t * Q;
    // Conditional addition: if r < 0, add q
    r += (r >> 31) & Q;
    r
}

/// Fully reduce a coefficient from the Montgomery domain back to
/// normal domain in [0, q).
///
/// freeze(â) = â · R⁻¹ mod q, fully reduced.
#[inline]
#[allow(dead_code)]
pub(crate) fn freeze(a: i32) -> i32 {
    reduce32(montgomery_reduce(a as i64))
}

/// Conditional subtraction: if a >= q, subtract q.
#[inline]
#[allow(dead_code)]
pub(crate) fn cond_sub_q(a: i32) -> i32 {
    let mut r = a - Q;
    r += (r >> 31) & Q;
    r
}
