//! Single-polynomial type for ML-DSA, shared across all parameter
//! sets.
//!
//! A `Poly` is a degree-255 polynomial with i32 coefficients mod q.
//! The K/L-dependent `PolyVecK`/`PolyVecL` and the K×L matrix
//! helpers are emitted per-variant inside the
//! [`ml_dsa_impl!`](crate::ml_dsa_impl::ml_dsa_impl) macro so that
//! each parameter set carries arrays of the correct fixed length.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::integer_division
)]

use crate::field::{freeze, reduce32};
use crate::ntt;
use crate::params::{N, Q};

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
    /// Returns `true` if any |coeff| ≥ bound (centered mod q).
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
