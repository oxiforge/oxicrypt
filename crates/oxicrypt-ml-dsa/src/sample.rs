//! Sampling routines for ML-DSA-87 per FIPS 204.
//!
//! - `expand_a`: expand k×l matrix A from seed ρ via SHAKE-128.
//! - `expand_s`: sample secret vectors s₁, s₂ from seed via SHAKE-256.
//! - `expand_mask`: sample mask vector y from seed + counter via SHAKE-256.
//! - `sample_in_ball`: sample challenge polynomial c via SHAKE-256.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::integer_division
)]

use crate::params::{ETA, GAMMA1, K, L, N, Q, TAU};
use crate::poly::{Poly, PolyVecK, PolyVecL};
use oxicrypt_xof::{Shake128, Shake256};

// ========================================================================
// ExpandA — FIPS 204 §8.3 (Algorithm 32: RejNTTPoly + Algorithm 30: ExpandA)
// ========================================================================

/// Rejection-sample a polynomial in NTT domain from a SHAKE-128
/// stream.
///
/// Reads 3 bytes at a time, extracting one 24-bit candidate,
/// truncated to 23 bits. Accepts if < q.
fn rej_ntt_poly(xof: &mut Shake128) -> Poly {
    let mut poly = Poly::zero();
    let mut j: usize = 0;
    let mut buf = [0u8; 3];
    while j < N {
        xof.squeeze(&mut buf);
        // Coefficient: little-endian 3 bytes, top bit masked off (23 bits)
        let t = ((buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16))
            & 0x7F_FFFF;
        if t < Q as u32 {
            poly.coeffs[j] = t as i32;
            j += 1;
        }
    }
    poly
}

/// Expand the k × l public matrix A from seed ρ.
///
/// A[i][j] = RejNTTPoly(SHAKE-128(ρ ‖ IntegerToBits(j, 8) ‖ IntegerToBits(i, 8)))
/// per FIPS 204 Algorithm 30.
pub(crate) fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
    let mut mat: [[Poly; L]; K] = core::array::from_fn(|_| {
        core::array::from_fn(|_| Poly::zero())
    });

    for i in 0..K {
        for j in 0..L {
            let mut xof = Shake128::new_internal();
            xof.update(rho);
            // FIPS 204: append (s, r) = (column index, row index) as bytes
            xof.update(&[j as u8, i as u8]);
            xof.finalize();
            mat[i][j] = rej_ntt_poly(&mut xof);
        }
    }
    mat
}

// ========================================================================
// ExpandS — FIPS 204 §8.3 (Algorithm 33: RejBoundedPoly + Algorithm 31: ExpandS)
// ========================================================================

/// Rejection-sample a polynomial with coefficients in [-η, η] from
/// SHAKE-256. For η = 2, we read one byte at a time and extract two
/// nibbles, accepting each if < 15 (so we can compute η − (t mod 5)).
///
/// FIPS 204 Algorithm 33 (CoeffFromHalfByte for η = 2).
fn rej_bounded_poly(xof: &mut Shake256) -> Poly {
    let mut poly = Poly::zero();
    let mut j: usize = 0;
    let mut buf = [0u8; 1];
    while j < N {
        xof.squeeze(&mut buf);
        let b = buf[0];

        // Low nibble
        let t0 = b & 0x0F;
        if t0 < 15 {
            // CoeffFromHalfByte: a = t0 mod 5, coefficient = η − a = 2 − a
            let a0 = t0 as i32;
            // Compute t0 mod 5 efficiently: t0 = a*5 + r, r < 5
            // Since t0 < 15, t0 mod 5 ∈ {0,1,2,3,4}
            let m0 = a0 - 5 * (a0 / 5); // a0 mod 5 when a0 >= 0
            poly.coeffs[j] = ETA - m0;
            j += 1;
        }

        if j >= N {
            break;
        }

        // High nibble
        let t1 = b >> 4;
        if t1 < 15 {
            let a1 = t1 as i32;
            let m1 = a1 - 5 * (a1 / 5);
            poly.coeffs[j] = ETA - m1;
            j += 1;
        }
    }
    poly
}

/// Expand secret vectors s₁ (length l) and s₂ (length k) from
/// seed ρ' (sigma).
///
/// FIPS 204 Algorithm 31: ExpandS.
/// s₁[r] ← RejBoundedPoly(SHAKE-256(σ ‖ r)) for r = 0..l-1
/// s₂[r] ← RejBoundedPoly(SHAKE-256(σ ‖ r)) for r = l..l+k-1
pub(crate) fn expand_s(sigma: &[u8; 64]) -> (PolyVecL, PolyVecK) {
    let mut s1 = PolyVecL::zero();
    let mut s2 = PolyVecK::zero();

    for r in 0..L {
        let mut xof = Shake256::new_internal();
        xof.update(sigma);
        // Counter as 2-byte little-endian
        xof.update(&[r as u8, (r >> 8) as u8]);
        xof.finalize();
        s1.polys[r] = rej_bounded_poly(&mut xof);
    }

    for r in 0..K {
        let mut xof = Shake256::new_internal();
        xof.update(sigma);
        let idx = L + r;
        xof.update(&[idx as u8, (idx >> 8) as u8]);
        xof.finalize();
        s2.polys[r] = rej_bounded_poly(&mut xof);
    }

    (s1, s2)
}

// ========================================================================
// ExpandMask — FIPS 204 §8.3 (Algorithm 34: ExpandMask)
// ========================================================================

/// Sample a single mask polynomial with coefficients in [−γ₁+1, γ₁]
/// from SHAKE-256(seed ‖ counter).
///
/// For ML-DSA-87: γ₁ = 2^19, so coefficients need 20 bits.
/// We read 5 bytes → 2 coefficients (20 bits each, little-endian).
fn sample_mask_poly(seed: &[u8; 64], counter: u16) -> Poly {
    let mut poly = Poly::zero();
    let mut xof = Shake256::new_internal();
    xof.update(seed);
    xof.update(&counter.to_le_bytes());
    xof.finalize();

    // 20 bits per coefficient, 256 coefficients → 640 bytes
    let mut buf = [0u8; 640];
    xof.squeeze(&mut buf);

    for i in 0..N / 4 {
        // Unpack 4 coefficients from 10 bytes (each 20 bits, little-endian)
        let off = i * 10;
        let b0 = buf[off] as u32;
        let b1 = buf[off + 1] as u32;
        let b2 = buf[off + 2] as u32;
        let b3 = buf[off + 3] as u32;
        let b4 = buf[off + 4] as u32;
        let b5 = buf[off + 5] as u32;
        let b6 = buf[off + 6] as u32;
        let b7 = buf[off + 7] as u32;
        let b8 = buf[off + 8] as u32;
        let b9 = buf[off + 9] as u32;

        let c0 = (b0 | (b1 << 8) | ((b2 & 0x0F) << 16)) & 0xFFFFF;
        let c1 = ((b2 >> 4) | (b3 << 4) | (b4 << 12)) & 0xFFFFF;
        let c2 = (b5 | (b6 << 8) | ((b7 & 0x0F) << 16)) & 0xFFFFF;
        let c3 = ((b7 >> 4) | (b8 << 4) | (b9 << 12)) & 0xFFFFF;

        // Map [0, 2γ₁) → [−γ₁+1, γ₁]: coefficient = γ₁ − c
        poly.coeffs[4 * i] = GAMMA1 - c0 as i32;
        poly.coeffs[4 * i + 1] = GAMMA1 - c1 as i32;
        poly.coeffs[4 * i + 2] = GAMMA1 - c2 as i32;
        poly.coeffs[4 * i + 3] = GAMMA1 - c3 as i32;
    }
    poly
}

/// Expand the mask vector y (length l) from seed ρ'' and counter κ.
///
/// FIPS 204 Algorithm 34: ExpandMask.
/// y[r] ← SampleMaskPoly(ρ'', κ + r) for r = 0..l-1
pub(crate) fn expand_mask(seed: &[u8; 64], kappa: u16) -> PolyVecL {
    let mut y = PolyVecL::zero();
    for r in 0..L {
        y.polys[r] = sample_mask_poly(seed, kappa + r as u16);
    }
    y
}

// ========================================================================
// SampleInBall — FIPS 204 §8.2 (Algorithm 29)
// ========================================================================

/// Sample the challenge polynomial c with exactly τ = 75 nonzero
/// coefficients, each ±1, from SHAKE-256(seed).
///
/// FIPS 204 Algorithm 29: `SampleInBall(ρ)`.
pub(crate) fn sample_in_ball(seed: &[u8]) -> Poly {
    let mut c = Poly::zero();
    let mut xof = Shake256::new_internal();
    xof.update(seed);
    xof.finalize();

    // First 8 bytes are used as sign bits (64 bits).
    let mut sign_bytes = [0u8; 8];
    xof.squeeze(&mut sign_bytes);
    let mut signs = u64::from_le_bytes(sign_bytes);

    // For i = 256−τ .. 255, pick j ∈ [0, i] and swap c[i] ↔ c[j],
    // then set c[i] = ±1.
    for i in (N - TAU)..N {
        // Sample j uniformly in [0, i]
        let j = {
            let mut buf = [0u8; 1];
            loop {
                xof.squeeze(&mut buf);
                let val = buf[0] as usize;
                if val <= i {
                    break val;
                }
            }
        };

        c.coeffs[i] = c.coeffs[j];
        // Sign bit determines ±1
        let sign = signs & 1;
        signs >>= 1;
        c.coeffs[j] = if sign == 0 { 1 } else { Q - 1 };
    }

    c
}
