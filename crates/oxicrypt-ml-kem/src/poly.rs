//! Polynomial and polynomial-vector types for ML-KEM.
//!
//! A `Poly` is a degree-255 polynomial with i16 coefficients mod q.
//! A `PolyVec` is a length-k vector of polynomials (k = 4 for
//! ML-KEM-1024).
//!
//! All indices are bounded by compile-time constants.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop
)]

use crate::field::{barrett_reduce, reduce_full, to_mont};
use crate::ntt::{self, ZETAS, basemul};
use crate::params::{K, N};

/// A polynomial with `N` = 256 coefficients in Z_q.
#[derive(Clone)]
pub(crate) struct Poly {
    /// Coefficients.  After reduction, each is in [0, q).
    pub(crate) coeffs: [i16; N],
}

impl Poly {
    /// Zero polynomial.
    pub(crate) const fn zero() -> Self {
        Self { coeffs: [0i16; N] }
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

    /// Apply Barrett reduction to every coefficient, mapping each
    /// into [0, q).
    pub(crate) fn reduce(&mut self) {
        for i in 0..N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i]);
        }
    }

    /// Fully reduce every coefficient to [0, q), handling negative
    /// values.
    pub(crate) fn reduce_full(&mut self) {
        for i in 0..N {
            self.coeffs[i] = reduce_full(self.coeffs[i]);
        }
    }

    /// Forward NTT (in-place).
    pub(crate) fn ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }

    /// Inverse NTT (in-place), including Barrett reduction.
    pub(crate) fn inv_ntt(&mut self) {
        ntt::inv_ntt(&mut self.coeffs);
    }

    /// Convert all coefficients to Montgomery domain (in-place).
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_mont(&mut self) {
        for i in 0..N {
            self.coeffs[i] = to_mont(self.coeffs[i]);
        }
    }

    /// Pointwise multiplication in NTT domain.
    ///
    /// Multiplies 128 pairs of degree-1 quotient-ring elements.
    /// Result accumulates into `self` (i.e. self += a ◦ b).
    pub(crate) fn pointwise_acc(&mut self, a: &Self, b: &Self) {
        for i in 0..64 {
            let zeta = ZETAS[64 + i];
            // Pair at (4i, 4i+1)
            let (r0, r1) = basemul(
                a.coeffs[4 * i],
                a.coeffs[4 * i + 1],
                b.coeffs[4 * i],
                b.coeffs[4 * i + 1],
                zeta,
            );
            self.coeffs[4 * i] += r0;
            self.coeffs[4 * i + 1] += r1;

            // Pair at (4i+2, 4i+3) uses −ζ
            let (r0, r1) = basemul(
                a.coeffs[4 * i + 2],
                a.coeffs[4 * i + 3],
                b.coeffs[4 * i + 2],
                b.coeffs[4 * i + 3],
                -zeta,
            );
            self.coeffs[4 * i + 2] += r0;
            self.coeffs[4 * i + 3] += r1;
        }
    }
}

/// A vector of `K` polynomials.
#[derive(Clone)]
pub(crate) struct PolyVec {
    /// The k polynomial components.
    pub(crate) polys: [Poly; K],
}

impl PolyVec {
    /// Zero vector.
    pub(crate) fn zero() -> Self {
        Self {
            polys: [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()],
        }
    }

    /// Forward NTT on every component.
    pub(crate) fn ntt(&mut self) {
        for i in 0..K {
            self.polys[i].ntt();
        }
    }

    /// Inverse NTT on every component.
    pub(crate) fn inv_ntt(&mut self) {
        for i in 0..K {
            self.polys[i].inv_ntt();
        }
    }

    /// Add `other` to `self` component-wise.
    pub(crate) fn add_assign(&mut self, other: &Self) {
        for i in 0..K {
            self.polys[i].add_assign(&other.polys[i]);
        }
    }

    /// Inner product in NTT domain: ⟨a, b⟩ = Σᵢ aᵢ ◦ bᵢ.
    pub(crate) fn inner_product_ntt(a: &Self, b: &Self) -> Poly {
        let mut r = Poly::zero();
        for i in 0..K {
            r.pointwise_acc(&a.polys[i], &b.polys[i]);
        }
        r.reduce();
        r
    }
}

/// A k × k matrix of polynomials (in NTT domain).
pub(crate) struct PolyMatrix {
    /// Row-major: `rows[i][j]` is Â[i][j].
    pub(crate) rows: [[Poly; K]; K],
}

impl PolyMatrix {
    /// Multiply matrix by column vector: t̂ = Â · ŝ.
    pub(crate) fn mul_vec(&self, s: &PolyVec) -> PolyVec {
        let mut t = PolyVec::zero();
        for i in 0..K {
            for j in 0..K {
                t.polys[i].pointwise_acc(&self.rows[i][j], &s.polys[j]);
            }
            t.polys[i].reduce();
        }
        t
    }

    /// Multiply transpose of matrix by column vector: û = Âᵀ · r̂.
    pub(crate) fn transpose_mul_vec(&self, r: &PolyVec) -> PolyVec {
        let mut u = PolyVec::zero();
        for i in 0..K {
            for j in 0..K {
                u.polys[i].pointwise_acc(&self.rows[j][i], &r.polys[j]);
            }
            u.polys[i].reduce();
        }
        u
    }
}
