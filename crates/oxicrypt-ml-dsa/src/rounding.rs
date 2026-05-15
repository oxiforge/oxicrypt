//! Rounding, decomposition, and hint routines for ML-DSA-87.
//!
//! Implements FIPS 204 §8.1 (Algorithms 25–28):
//! - `Power2Round`: decompose t into (t₁, t₀).
//! - `Decompose` / `HighBits` / `LowBits`: decompose w relative to 2γ₂.
//! - `MakeHint` / `UseHint`: compute and apply hint for verification.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::integer_division
)]

use crate::params::{D, GAMMA2, K, N, Q};
use crate::poly::PolyVecK;

// ========================================================================
// Power2Round — FIPS 204 Algorithm 25
// ========================================================================

/// `Power2Round(r)`: decompose r ∈ [0, q) into (r₁, r₀) such that
/// r ≡ r₁ · 2^d + r₀ (mod q) and r₀ ∈ (−2^(d−1), 2^(d−1)].
///
/// Returns (r1, r0).
#[inline]
pub(crate) fn power2round(r: i32) -> (i32, i32) {
    // r is assumed to be in [0, q)
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    let r0 = r - (r1 << D);
    (r1, r0)
}

/// Apply `Power2Round` to a polynomial vector, splitting into
/// (t₁, t₀) component-wise.
pub(crate) fn polyveck_power2round(t: &PolyVecK, t1: &mut PolyVecK, t0: &mut PolyVecK) {
    for i in 0..K {
        for j in 0..N {
            let (hi, lo) = power2round(t.polys[i].coeffs[j]);
            t1.polys[i].coeffs[j] = hi;
            t0.polys[i].coeffs[j] = lo;
        }
    }
}

// ========================================================================
// Decompose / HighBits / LowBits — FIPS 204 Algorithm 26
// ========================================================================

/// `Decompose(r)`: decompose r ∈ [0, q) into (r₁, r₀) relative to
/// 2γ₂, such that r ≡ r₁ · 2γ₂ + r₀ (mod q).
///
/// r₀ ∈ (−γ₂, γ₂] unless r₁ = (q−1)/(2γ₂) in which case r₁ is
/// set to 0 and r₀ = r − (q−1) + r₀.
///
/// Returns (r1, r0).
#[inline]
pub(crate) fn decompose(r: i32) -> (i32, i32) {
    // r must be in [0, q)
    let two_gamma2 = 2 * GAMMA2;

    // r₀ = r mod± 2γ₂ (centered)
    let mut r1 = (r + 127) >> 7; // approximate division

    // For γ₂ = (q−1)/32:
    // r₁ = ⌈r / (2γ₂)⌉ approximately, then adjust
    // 2γ₂ = 523776 = (q-1)/16
    // Actually: we compute r₁ = r mod 2γ₂ (centered), then r₁ = (r - r₀) / 2γ₂

    // Per the reference implementation (dilithium):
    // r₁ = (r + 127) >> 7
    // For γ₂ = 261888 = (q-1)/32:
    //   r₁ = (r₁ * 1025 + (1 << 21)) >> 22
    //   r₁ &= 15
    r1 = (r1 * 1025 + (1 << 21)) >> 22;
    r1 &= 15;

    let mut r0 = r - r1 * two_gamma2;

    // If r₀ overflows: r₁ was (q-1)/(2γ₂) = 15+1 = 16, set r₁ = 0
    // and subtract q-1 from r₀ to center it.
    // Detect: r₀ > γ₂ means we need to adjust.
    // Actually: when r₁ · 2γ₂ wraps mod q:
    //   if r₀ > (q-1)/2 → r₀ -= q
    // But the standard approach: check if r - r₁·2γ₂ > γ₂
    // The above computation already handles the wrap case via the mask:
    // if r₁ == 0 and original r was in [q - 2γ₂ + 1, q), r₀ could be
    // near q, which we must adjust.

    // Conditional adjust: if the original value was in the top range,
    // r₀ will be ≥ γ₂. In that case, subtract 1 from something.
    // Actually, the standard Dilithium ref impl does:
    //   r0 -= (((Q-1)/2 - r0) >> 31) & Q
    r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;

    (r1, r0)
}

/// `HighBits(r)` = the high part of `Decompose(r)`.
#[inline]
pub(crate) fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

/// `LowBits(r)` = the low part of `Decompose(r)`.
#[inline]
#[allow(dead_code)]
pub(crate) fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

/// Apply `HighBits` to every coefficient of a polynomial vector,
/// storing results in `w1`.
#[allow(dead_code)]
pub(crate) fn polyveck_high_bits(w: &PolyVecK, w1: &mut PolyVecK) {
    for i in 0..K {
        for j in 0..N {
            w1.polys[i].coeffs[j] = high_bits(w.polys[i].coeffs[j]);
        }
    }
}

/// Apply `Decompose` to every coefficient of a polynomial vector.
pub(crate) fn polyveck_decompose(w: &PolyVecK, w1: &mut PolyVecK, w0: &mut PolyVecK) {
    for i in 0..K {
        for j in 0..N {
            let (hi, lo) = decompose(w.polys[i].coeffs[j]);
            w1.polys[i].coeffs[j] = hi;
            w0.polys[i].coeffs[j] = lo;
        }
    }
}

// ========================================================================
// MakeHint / UseHint — FIPS 204 Algorithms 27–28
// ========================================================================

/// `MakeHint` per FIPS 204 Algorithm 27, expressed in pq-crystals's
/// shortcut form on centered low-bits `a0` and the corresponding
/// high-bits `a1`.
///
/// `a0` is the centered representative of `LowBits(w) − c·s₂ + c·t₀`,
/// bounded by `(−2γ₂, 2γ₂)` after the c·t₀ norm check.
/// `a1` is `w₁ = HighBits(w)` at the same coefficient position.
///
/// Returns 1 iff applying the perturbation `c·t₀` would flip the
/// high-bits bin — equivalent to `HighBits(r) ≠ HighBits(r + z)` in
/// Algorithm 27, but with the `−γ₂` fence case made explicit so the
/// `Decompose` top-bin wrap (where `r⁺ = q − γ₂` maps to `r₁ = 0,
/// r₀ = −γ₂`) is still classified as a bin flip when `w₁ ≠ 0`.
/// The spec-form `HighBits(r) ≠ HighBits(r + z)` aliases this fence
/// onto `r₁ = 0`, hiding the flip.  Matches pq-crystals/dilithium's
/// `make_hint` in `rounding.c` so ACVP-grading produces byte-identical
/// signatures across the centered/unsigned representation boundary.
#[inline]
pub(crate) fn make_hint(a0: i32, a1: i32) -> i32 {
    let outside = !(-GAMMA2..=GAMMA2).contains(&a0);
    let fence = a0 == -GAMMA2 && a1 != 0;
    i32::from(outside || fence)
}

/// `UseHint(h, r)`: if h = 0, return `HighBits(r)`. If h = 1,
/// adjust the high bits.
///
/// FIPS 204 Algorithm 28.
#[inline]
pub(crate) fn use_hint(h: i32, r: i32) -> i32 {
    let (r1, r0) = decompose(r);

    if h == 0 {
        return r1;
    }

    // For γ₂ = (q−1)/32:
    // m = (q−1) / (2γ₂) = 16 (but we use the decompose range 0..15)
    // Actually the number of possible r₁ values is (q-1)/(2γ₂) = 16
    // If r₀ > 0: r₁ + 1 mod 16
    // If r₀ ≤ 0: r₁ - 1 mod 16
    let m = 16; // (q - 1) / (2 * GAMMA2) = 16
    if r0 > 0 {
        (r1 + 1) % m
    } else {
        (r1 + m - 1) % m
    }
}

/// Compute the hint vector h coefficient-wise from `(a0, a1)` and
/// count the number of set bits.
///
/// `a0` is the polynomial-vector of centered low-bits values
/// `LowBits(w) − c·s₂ + c·t₀` (each coefficient bounded by `2γ₂`).
/// `a1` is the polynomial-vector of high-bits values `w₁`.
///
/// Returns the count of 1-bits across all k polynomials.  If the
/// count exceeds ω, the caller should reject.
pub(crate) fn polyveck_make_hint(h: &mut PolyVecK, a0: &PolyVecK, a1: &PolyVecK) -> usize {
    let mut count = 0;
    for i in 0..K {
        for j in 0..N {
            h.polys[i].coeffs[j] = make_hint(a0.polys[i].coeffs[j], a1.polys[i].coeffs[j]);
            count += h.polys[i].coeffs[j] as usize;
        }
    }
    count
}

/// Apply hints to recompute w₁' from w and h.
pub(crate) fn polyveck_use_hint(w1_prime: &mut PolyVecK, w: &PolyVecK, h: &PolyVecK) {
    for i in 0..K {
        for j in 0..N {
            w1_prime.polys[i].coeffs[j] = use_hint(h.polys[i].coeffs[j], w.polys[i].coeffs[j]);
        }
    }
}

/// Convenience: apply `LowBits` to every coefficient in a poly vector.
#[allow(dead_code)]
pub(crate) fn polyveck_low_bits(w: &PolyVecK, w0: &mut PolyVecK) {
    for i in 0..K {
        for j in 0..N {
            w0.polys[i].coeffs[j] = low_bits(w.polys[i].coeffs[j]);
        }
    }
}

/// Pack w₁ (high bits, 4 bits per coefficient for γ₂=(q-1)/32)
/// into bytes for hashing.
///
/// Each w₁ coefficient is in [0, 15], so 4 bits each.
/// Each polynomial → 128 bytes. Total: k × 128 = 1024 bytes.
pub(crate) fn pack_w1(w1: &PolyVecK, buf: &mut [u8]) {
    debug_assert!(buf.len() >= K * 128);
    let mut offset = 0;
    for i in 0..K {
        for j in (0..N).step_by(2) {
            buf[offset] = (w1.polys[i].coeffs[j] as u8) | ((w1.polys[i].coeffs[j + 1] as u8) << 4);
            offset += 1;
        }
    }
}

/// Unpack w₁ bytes back into polynomial vector (for verification).
#[allow(dead_code)]
pub(crate) fn unpack_w1(buf: &[u8], w1: &mut PolyVecK) {
    debug_assert!(buf.len() >= K * 128);
    let mut offset = 0;
    for i in 0..K {
        for j in (0..N).step_by(2) {
            w1.polys[i].coeffs[j] = i32::from(buf[offset] & 0x0F);
            w1.polys[i].coeffs[j + 1] = i32::from(buf[offset] >> 4);
            offset += 1;
        }
    }
}

/// Sub-function: used during signing to compute w - c*s₂ then check
/// lowbits. This creates a temporary reduced vector.
pub(crate) fn reduce_polyveck(v: &mut PolyVecK) {
    for p in &mut v.polys {
        for c in &mut p.coeffs {
            *c = crate::field::reduce32(*c);
        }
    }
}
