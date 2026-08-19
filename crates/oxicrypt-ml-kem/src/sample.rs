//! Shared (K-independent) sampling primitives for ML-KEM.
//!
//! - `SampleNTT` (FIPS 203 Algorithm 7): rejection-samples a single
//!   polynomial in NTT domain from a SHAKE-128 stream.
//! - `sample_noise` (FIPS 203 §4.2.2 / Algorithm 8 driver): samples one
//!   noise polynomial via PRF(σ, nonce) using CBD(η).
//!
//! The K-dependent helpers `expand_a` (matrix Â expansion) and
//! `sample_noise_vec` (k-component noise vector) are emitted per
//! variant by `crate::ml_kem_impl::ml_kem_impl!`.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_possible_wrap
)]

use crate::encode::sample_cbd;
use crate::params::{N, Q_U16, SEED_LEN};
use crate::poly::Poly;
use oxicrypt_xof::{Shake128, Shake256};

/// Rejection-sample a polynomial in NTT domain from a SHAKE-128
/// stream (FIPS 203 Algorithm 7: `SampleNTT`).
///
/// Reads 3 bytes at a time from the XOF, extracting two 12-bit
/// candidates. Each candidate < q is accepted.
pub(crate) fn sample_ntt(xof: &mut Shake128) -> Poly {
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
