//! Polynomial and polynomial-vector types for ML-DSA-87.
//!
//! A `Poly` is a degree-255 polynomial with i32 coefficients mod q.
//! `PolyVecK` and `PolyVecL` are length-k and length-l vectors of
//! polynomials (k=8, l=7 for ML-DSA-87).
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::integer_division
)]

use crate::field::{freeze, reduce32};
use crate::ntt;
use crate::params::{K, L, N, Q};

/// A polynomial with `N` = 256 coefficients in Z_q.
#[derive(Clone)]
pub(crate) struct Poly {
    pub(crate) coeffs: [i32; N],
}

impl Poly {
    /// Zero polynomial.
    pub(crate) const fn zero() -> Self {
        Self { coeffs: [0i32; N] }
    }

    /// Forward NTT (in-place).
    pub(crate) fn ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }

    /// Inverse NTT (in-place).
    pub(crate) fn inv_ntt(&mut self) {
        ntt::inv_ntt(&mut self.coeffs);
    }

    /// Reduce all coefficients modulo q to [0, q).
    pub(crate) fn reduce(&mut self) {
        ntt::poly_reduce(&mut self.coeffs);
    }

    /// Freeze: convert from Montgomery domain and fully reduce to [0, q).
    #[allow(dead_code)]
    pub(crate) fn freeze_coeffs(&mut self) {
        for c in &mut self.coeffs {
            *c = freeze(*c);
        }
    }

    /// Add `other` to `self` (coefficient-wise).
    pub(crate) fn add_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] += other.coeffs[i];
        }
    }

    /// Subtract `other` from `self` (coefficient-wise).
    pub(crate) fn sub_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] -= other.coeffs[i];
        }
    }

    /// Compute the infinity norm: max |a_i| where a_i is centered
    /// around 0 (i.e., in [−(q−1)/2, (q−1)/2]).
    ///
    /// Assumes coefficients are reduced to [0, q).
    /// Compute the infinity norm: max |a_i| where a_i is centered
    /// around 0 (i.e., in [−(q−1)/2, (q−1)/2]).
    #[allow(dead_code)]
    pub(crate) fn norm_inf(&self) -> i32 {
        let mut max = 0i32;
        for &c in &self.coeffs {
            let t = reduce32(c);
            let centered = if t > (Q - 1) / 2 { Q - t } else { t };
            if centered > max {
                max = centered;
            }
        }
        max
    }

    /// Check if the infinity norm exceeds a bound.
    ///
    /// Returns `true` if any |coeff| > bound (centered mod q).
    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        for &c in &self.coeffs {
            let t = reduce32(c);
            // Center: t ∈ [0, q) → centered ∈ [0, (q-1)/2]
            let centered = if t > (Q - 1) / 2 { Q - t } else { t };
            if centered >= bound {
                return true;
            }
        }
        false
    }
}

/// A vector of `K` (= 8) polynomials.
#[derive(Clone)]
pub(crate) struct PolyVecK {
    pub(crate) polys: [Poly; K],
}

impl PolyVecK {
    /// Zero vector.
    pub(crate) fn zero() -> Self {
        Self {
            polys: core::array::from_fn(|_| Poly::zero()),
        }
    }

    /// Forward NTT on every component.
    pub(crate) fn ntt(&mut self) {
        for p in &mut self.polys {
            p.ntt();
        }
    }

    /// Inverse NTT on every component.
    pub(crate) fn inv_ntt(&mut self) {
        for p in &mut self.polys {
            p.inv_ntt();
        }
    }

    /// Reduce all coefficients in every component.
    pub(crate) fn reduce(&mut self) {
        for p in &mut self.polys {
            p.reduce();
        }
    }

    /// Add `other` to `self` component-wise.
    pub(crate) fn add_assign(&mut self, other: &Self) {
        for i in 0..K {
            self.polys[i].add_assign(&other.polys[i]);
        }
    }

    /// Subtract `other` from `self` component-wise.
    pub(crate) fn sub_assign(&mut self, other: &Self) {
        for i in 0..K {
            self.polys[i].sub_assign(&other.polys[i]);
        }
    }

    /// Check if any polynomial's infinity norm exceeds bound.
    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        for p in &self.polys {
            if p.check_norm(bound) {
                return true;
            }
        }
        false
    }
}

/// A vector of `L` (= 7) polynomials.
#[derive(Clone)]
pub(crate) struct PolyVecL {
    pub(crate) polys: [Poly; L],
}

impl PolyVecL {
    /// Zero vector.
    pub(crate) fn zero() -> Self {
        Self {
            polys: core::array::from_fn(|_| Poly::zero()),
        }
    }

    /// Forward NTT on every component.
    pub(crate) fn ntt(&mut self) {
        for p in &mut self.polys {
            p.ntt();
        }
    }

    /// Inverse NTT on every component.
    pub(crate) fn inv_ntt(&mut self) {
        for p in &mut self.polys {
            p.inv_ntt();
        }
    }

    /// Reduce all coefficients in every component.
    pub(crate) fn reduce(&mut self) {
        for p in &mut self.polys {
            p.reduce();
        }
    }

    /// Add `other` to `self` component-wise.
    pub(crate) fn add_assign(&mut self, other: &Self) {
        for i in 0..L {
            self.polys[i].add_assign(&other.polys[i]);
        }
    }

    /// Check if any polynomial's infinity norm exceeds bound.
    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        for p in &self.polys {
            if p.check_norm(bound) {
                return true;
            }
        }
        false
    }
}

/// Multiply a k×l matrix (in NTT domain) by a length-l vector
/// (in NTT domain), producing a length-k result.
///
/// t̂ = Â · ŝ  where Â is `mat[i][j]` (row-major).
#[allow(dead_code)]
pub(crate) fn matrix_mul(mat: &[[Poly; L]; K], s: &PolyVecL) -> PolyVecK {
    let mut t = PolyVecK::zero();
    for i in 0..K {
        for j in 0..L {
            ntt::pointwise_acc(
                &mut t.polys[i].coeffs,
                &mat[i][j].coeffs,
                &s.polys[j].coeffs,
            );
        }
        t.polys[i].reduce();
    }
    t
}

/// Pointwise multiply a k×l matrix by a length-l vector, accumulating
/// into a length-k vector (in NTT domain).
pub(crate) fn matrix_pointwise_mul(t: &mut PolyVecK, mat: &[[Poly; L]; K], s: &PolyVecL) {
    for i in 0..K {
        for c in &mut t.polys[i].coeffs {
            *c = 0;
        }
        for j in 0..L {
            ntt::pointwise_acc(
                &mut t.polys[i].coeffs,
                &mat[i][j].coeffs,
                &s.polys[j].coeffs,
            );
        }
        t.polys[i].reduce();
    }
}

/// Pointwise multiply: c = a ◦ b in NTT domain (single polynomial).
pub(crate) fn poly_pointwise(c: &mut Poly, a: &Poly, b: &Poly) {
    ntt::pointwise_mul(&mut c.coeffs, &a.coeffs, &b.coeffs);
}
