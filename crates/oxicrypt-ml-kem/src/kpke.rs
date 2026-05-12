//! K-PKE: the inner IND-CPA public-key encryption scheme used by
//! ML-KEM (FIPS 203 §4.2, Algorithms 12–14).
//!
//! K-PKE is not directly exposed as an approved service.  It is
//! composed by the Fujisaki–Okamoto transform in [`crate::kem`] to
//! build the IND-CCA2 KEM.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::similar_names
)]

use crate::encode::{byte_decode, byte_encode, compress_poly, decompress_poly};
use crate::params::{
    CT_LEN, DU, DV, EK_LEN, ETA1, ETA2, K, POLY_COMPRESSED_DU, POLY_COMPRESSED_DV, POLY_ENCODED_12,
    SEED_LEN,
};
use crate::poly::{Poly, PolyVec};
use crate::sample::{expand_a, sample_noise, sample_noise_vec};
use oxicrypt_sha::sha3::{SHA3_512_DIGEST_SIZE, Sha3_512};

/// K-PKE key pair: (ek_PKE, dk_PKE).
///
/// FIPS 203 Algorithm 12 (`K-PKE.KeyGen`).
///
/// - `d`: 32 bytes of randomness (provided by caller from an
///   approved DRBG).
/// - `ek_pke`: output buffer for the encryption key (1568 bytes).
/// - `dk_pke`: output buffer for the decryption key (1536 bytes).
pub(crate) fn kpke_keygen(d: &[u8; SEED_LEN], ek_pke: &mut [u8], dk_pke: &mut [u8]) {
    debug_assert!(ek_pke.len() >= EK_LEN);
    debug_assert!(dk_pke.len() >= 384 * K);

    // 1. (ρ, σ) ← G(d ‖ k)  where G = SHA3-512
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = K as u8;

    let mut g = <Sha3_512>::new_internal();
    g.update(&g_input);
    let g_out: [u8; SHA3_512_DIGEST_SIZE] = g.finalize();

    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g_out[..32]);
    sigma.copy_from_slice(&g_out[32..64]);

    // 2. Expand matrix Â from ρ
    let a_hat = expand_a(&rho);

    // 3. Sample secret vector s and error vector e
    let (mut s, nonce) = sample_noise_vec(&sigma, 0, ETA1);
    let (mut e, _nonce) = sample_noise_vec(&sigma, nonce, ETA1);

    // 4. NTT(s), NTT(e)
    s.ntt();
    e.ntt();

    // 5. t̂ = Â ◦ ŝ + ê
    //    mul_vec produces results with an extra R⁻¹ Montgomery
    //    factor from basemul.  Convert back to normal form via
    //    to_mont (multiply by R) before adding ê which is in
    //    normal form.
    let mut t_hat = a_hat.mul_vec(&s);
    for i in 0..K {
        t_hat.polys[i].to_mont();
    }
    t_hat.add_assign(&e);

    // 6. Encode ek_PKE = ByteEncode_12(t̂) ‖ ρ
    for i in 0..K {
        t_hat.polys[i].reduce_full();
        byte_encode(
            12,
            &t_hat.polys[i].coeffs,
            &mut ek_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
        );
    }
    ek_pke[K * POLY_ENCODED_12..K * POLY_ENCODED_12 + 32].copy_from_slice(&rho);

    // 7. Encode dk_PKE = ByteEncode_12(ŝ)
    for i in 0..K {
        s.polys[i].reduce_full();
        byte_encode(
            12,
            &s.polys[i].coeffs,
            &mut dk_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
        );
    }
}

/// K-PKE encryption (FIPS 203 Algorithm 13: `K-PKE.Encrypt`).
///
/// - `ek_pke`: encryption key (1568 bytes).
/// - `m`: 32-byte message (the shared-secret seed).
/// - `r_seed`: 32-byte randomness for re-encryption.
/// - `ct`: output buffer for ciphertext (1568 bytes).
pub(crate) fn kpke_encrypt(ek_pke: &[u8], m: &[u8; 32], r_seed: &[u8; 32], ct: &mut [u8]) {
    debug_assert!(ek_pke.len() >= EK_LEN);
    debug_assert!(ct.len() >= CT_LEN);

    // 1. Decode t̂ from ek_PKE
    let mut t_hat = PolyVec::zero();
    for i in 0..K {
        byte_decode(
            12,
            &ek_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
            &mut t_hat.polys[i].coeffs,
        );
    }

    // 2. Extract ρ from ek_PKE
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek_pke[K * POLY_ENCODED_12..K * POLY_ENCODED_12 + 32]);

    // 3. Expand Â from ρ
    let a_hat = expand_a(&rho);

    // 4. Sample r, e₁, e₂
    let (mut r_vec, nonce) = sample_noise_vec(r_seed, 0, ETA1);
    let (e1, nonce) = sample_noise_vec(r_seed, nonce, ETA2);
    let e2 = sample_noise(r_seed, nonce, ETA2);

    // 5. NTT(r)
    r_vec.ntt();

    // 6. u = NTT⁻¹(Âᵀ ◦ r̂) + e₁
    let mut u = a_hat.transpose_mul_vec(&r_vec);
    u.inv_ntt();
    u.add_assign(&e1);

    // 7. v = NTT⁻¹(t̂ᵀ ◦ r̂) + e₂ + Decompress₁(Decode₁(m))
    let mut v = PolyVec::inner_product_ntt(&t_hat, &r_vec);
    v.inv_ntt();
    v.add_assign(&e2);

    // Decode message and add Decompress_1(m)
    let mut m_poly = Poly::zero();
    byte_decode(1, m, &mut m_poly.coeffs);
    decompress_poly(1, &mut m_poly.coeffs);
    v.add_assign(&m_poly);

    // 8. Compress and encode ciphertext
    // c₁ = ByteEncode_{dᵤ}(Compress_{dᵤ}(u))
    for i in 0..K {
        u.polys[i].reduce_full();
        compress_poly(DU as u32, &mut u.polys[i].coeffs);
        byte_encode(
            DU,
            &u.polys[i].coeffs,
            &mut ct[i * POLY_COMPRESSED_DU..(i + 1) * POLY_COMPRESSED_DU],
        );
    }

    // c₂ = ByteEncode_{dᵥ}(Compress_{dᵥ}(v))
    v.reduce_full();
    compress_poly(DV as u32, &mut v.coeffs);
    byte_encode(
        DV,
        &v.coeffs,
        &mut ct[K * POLY_COMPRESSED_DU..K * POLY_COMPRESSED_DU + POLY_COMPRESSED_DV],
    );
}

/// K-PKE decryption (FIPS 203 Algorithm 14: `K-PKE.Decrypt`).
///
/// - `dk_pke`: decryption key (1536 bytes = 384 · k).
/// - `ct`: ciphertext (1568 bytes).
/// - `m`: output 32-byte message.
pub(crate) fn kpke_decrypt(dk_pke: &[u8], ct: &[u8], m: &mut [u8; 32]) {
    debug_assert!(dk_pke.len() >= 384 * K);
    debug_assert!(ct.len() >= CT_LEN);

    // 1. Decode u from ciphertext
    let mut u = PolyVec::zero();
    for i in 0..K {
        byte_decode(
            DU,
            &ct[i * POLY_COMPRESSED_DU..(i + 1) * POLY_COMPRESSED_DU],
            &mut u.polys[i].coeffs,
        );
        decompress_poly(DU as u32, &mut u.polys[i].coeffs);
    }

    // 2. Decode v from ciphertext
    let mut v = Poly::zero();
    byte_decode(
        DV,
        &ct[K * POLY_COMPRESSED_DU..K * POLY_COMPRESSED_DU + POLY_COMPRESSED_DV],
        &mut v.coeffs,
    );
    decompress_poly(DV as u32, &mut v.coeffs);

    // 3. Decode ŝ from dk_PKE
    let mut s_hat = PolyVec::zero();
    for i in 0..K {
        byte_decode(
            12,
            &dk_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
            &mut s_hat.polys[i].coeffs,
        );
    }

    // 4. NTT(u)
    u.ntt();

    // 5. w = v − NTT⁻¹(ŝᵀ ◦ NTT(u))
    let mut w = PolyVec::inner_product_ntt(&s_hat, &u);
    w.inv_ntt();
    v.sub_assign(&w);

    // 6. m = ByteEncode₁(Compress₁(w))
    v.reduce_full();
    compress_poly(1, &mut v.coeffs);
    byte_encode(1, &v.coeffs, m);
}
