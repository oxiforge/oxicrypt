//! Sampling routines for ML-KEM.
//!
//! - `SampleNTT`: rejection-samples a polynomial in NTT domain from
//!   SHAKE-128 output (FIPS 203 Algorithm 7).
//! - `SamplePolyCBD`: samples a polynomial from the centered binomial
//!   distribution using SHAKE-256 PRF output (delegates to
//!   [`crate::encode::sample_cbd`]).
//! - `expand_a`: expands the public matrix Â from seed ρ.
//! - `sample_noise`: samples a noise polynomial from PRF(σ, N).
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_possible_wrap
)]

use crate::encode::sample_cbd;
use crate::params::{K, N, Q_U16, SEED_LEN};
use crate::poly::{Poly, PolyMatrix, PolyVec};
use oxicrypt_xof::{Shake128, Shake256};

/// Rejection-sample a polynomial in NTT domain from a SHAKE-128
/// stream (FIPS 203 Algorithm 7: `SampleNTT`).
///
/// Reads 3 bytes at a time from the XOF, extracting two 12-bit
/// candidates. Each candidate < q is accepted.
fn sample_ntt(xof: &mut Shake128) -> Poly {
    let mut poly = Poly::zero();
    let mut j: usize = 0;
    let mut buf = [0u8; 3];
    while j < N {
        xof.squeeze(&mut buf);
        let d1 = (buf[0] as u16) | (((buf[1] & 0x0F) as u16) << 8);
        let d2 = ((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4);
        if d1 < Q_U16 {
            poly.coeffs[j] = d1 as i16;
            j += 1;
        }
        if d2 < Q_U16 && j < N {
            poly.coeffs[j] = d2 as i16;
            j += 1;
        }
    }
    poly
}

/// Expand the k × k public matrix Â from seed ρ.
///
/// Â[i][j] = SampleNTT(XOF(ρ, j, i)) where XOF = SHAKE-128
/// and the input is ρ ‖ j ‖ i (column index before row index,
/// per FIPS 203 Algorithm 12 step 3).
pub(crate) fn expand_a(rho: &[u8; SEED_LEN]) -> PolyMatrix {
    let mut rows: [[Poly; K]; K] = [
        [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()],
        [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()],
        [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()],
        [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()],
    ];
    for i in 0..K {
        for j in 0..K {
            let mut xof = Shake128::new_internal();
            xof.update(rho);
            xof.update(&[j as u8, i as u8]);
            xof.finalize();
            rows[i][j] = sample_ntt(&mut xof);
        }
    }
    PolyMatrix { rows }
}

/// Sample a noise polynomial from PRF(σ, nonce) using CBD(η).
///
/// PRF_η(σ, N) = SHAKE-256(σ ‖ N), squeezed to 64 · η bytes.
pub(crate) fn sample_noise(sigma: &[u8; SEED_LEN], nonce: u8, eta: usize) -> Poly {
    let mut prf = Shake256::new_internal();
    prf.update(sigma);
    prf.update(&[nonce]);
    prf.finalize();

    let mut buf = [0u8; 192]; // max: 64 * 3 = 192 for η = 3
    let prf_len = 64 * eta;
    prf.squeeze(&mut buf[..prf_len]);

    let mut poly = Poly::zero();
    sample_cbd(eta, &buf[..prf_len], &mut poly.coeffs);
    poly
}

/// Sample a full noise vector (k polynomials) starting from
/// counter `nonce`, incrementing after each polynomial.
///
/// Returns the vector and the next nonce value.
pub(crate) fn sample_noise_vec(sigma: &[u8; SEED_LEN], mut nonce: u8, eta: usize) -> (PolyVec, u8) {
    let mut vec = PolyVec::zero();
    for i in 0..K {
        vec.polys[i] = sample_noise(sigma, nonce, eta);
        nonce = nonce.wrapping_add(1);
    }
    (vec, nonce)
}
