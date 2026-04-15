//! Field arithmetic modulo q = 3329.
//!
//! ML-KEM uses Montgomery multiplication for the NTT and
//! Barrett reduction for coefficient normalisation.
//! Montgomery domain: â = a · R mod q where R = 2¹⁶.
//!
//! Every index in this module is bounded by a compile-time constant
//! or a `for i in 0..N` loop, and all arithmetic intentionally wraps
//! on secret-independent intermediate values, so both lints are
//! disabled at the module level.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::integer_division
)]

use crate::params::Q_I32;

/// q⁻¹ mod 2¹⁶ (as i16, wrapping).
///
/// 3329 · 62209 ≡ 1 (mod 65536), so q⁻¹ mod R = 62209.
/// As signed i16: 62209 − 65536 = −3327.
/// We store −q⁻¹ mod R = 3327 (negation) because the Montgomery
/// reduction formula uses −q⁻¹.
const QINV: i16 = -3327; // −q⁻¹ mod 2¹⁶

/// R² mod q = (2¹⁶)² mod 3329 = 1353.
///
/// Used to convert a normal-domain value into Montgomery domain
/// via `to_mont(a) = montgomery_reduce(a as i32 * R2 as i32)`.
pub(crate) const R2: i16 = 1353;

/// Montgomery reduction: given a 32-bit product, compute
/// a · R⁻¹ mod q.
///
/// Input: a ∈ (−2³¹, 2³¹)
/// Output: r ∈ (−q, q)
///
/// The result is *not* fully reduced; the caller may need to add q
/// or apply Barrett reduction to normalise into [0, q).
#[inline]
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    // t = (a mod R) · (−q⁻¹) mod R   (low 16 bits only)
    let t = (a as i16).wrapping_mul(QINV);
    // (a − t · q) is divisible by R; arithmetic right-shift by 16
    ((a - (t as i32) * Q_I32) >> 16) as i16
}

/// Multiply two i16 values where `a` is in Montgomery domain,
/// returning the product in Montgomery domain:
///   fqmul(â, b̂) = â · b̂ · R⁻¹ mod q = (a·b·R) mod q.
#[inline]
pub(crate) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

/// Barrett reduction: reduce a ∈ (−2¹⁵, 2¹⁵) into [0, q).
///
/// Uses the approximation ⌊a/q⌋ ≈ ⌊a · v / 2²⁶⌋ with v = 20159.
#[inline]
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159; // ⌊(2²⁶ + q/2) / q⌋
    let t = ((a as i32) * V + (1 << 25)) >> 26;
    let mut r = (a as i32) - t * Q_I32;
    // Constant-time conditional subtraction: r may be in [0, 2q).
    // Arithmetic shift produces −1 (all ones) when r < q, else 0.
    let mask = (r - Q_I32) >> 31; // −1 if r < q, 0 if r ≥ q
    r -= Q_I32 & !mask;
    r as i16
}

/// Fully reduce a coefficient to [0, q).
///
/// Handles any value in the i16 range by first applying Barrett
/// reduction (which maps to approximately (−q, q)) and then a
/// single conditional addition of q.
#[inline]
pub(crate) fn reduce_full(a: i16) -> i16 {
    let r = barrett_reduce(a); // approximately in (−q, q)
    let mut s = r as i32;
    // Conditional add q if negative
    s += Q_I32 & (s >> 31);
    s as i16
}

/// Convert a normal-domain value to Montgomery domain.
///
/// to_mont(a) = a · R mod q
#[inline]
pub(crate) fn to_mont(a: i16) -> i16 {
    fqmul(a, R2)
}

/// Constant-time equality comparison of two byte slices.
///
/// Returns 0 if equal, non-zero otherwise. Timing is independent
/// of the values.
pub(crate) fn ct_bytes_eq(a: &[u8], b: &[u8]) -> u8 {
    debug_assert!(a.len() == b.len());
    let mut diff = 0u8;
    let len = if a.len() < b.len() { a.len() } else { b.len() };
    for i in 0..len {
        diff |= a[i] ^ b[i];
    }
    // Also compare lengths
    if a.len() != b.len() {
        diff |= 0xFF;
    }
    diff
}

/// Constant-time select: if `flag == 0` return `a`, else return `b`.
///
/// Timing is independent of `flag`.
pub(crate) fn ct_select_32(a: &[u8; 32], b: &[u8; 32], flag: u8) -> [u8; 32] {
    // Expand flag to a full mask: 0x00 or 0xFF
    let mask = (-(flag.wrapping_shr(0) as i8 | -(flag as i8))) as u8;
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ (mask & (a[i] ^ b[i]));
    }
    out
}
