//! ML-DSA-87 keygen, sign, and verify per FIPS 204 §6.
//!
//! This module implements the three core algorithms:
//! - `ml_dsa_keygen` (Algorithm 1 / §6.1)
//! - `ml_dsa_sign` (Algorithm 2 / §6.2, deterministic variant)
//! - `ml_dsa_verify` (Algorithm 3 / §6.3)
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::too_many_lines
)]

use crate::encode;
use crate::params::{BETA, CTILDE_LEN, D, GAMMA1, GAMMA2, K, L, OMEGA, PK_LEN, SIG_LEN, SK_LEN};
use crate::poly::{PolyVecK, PolyVecL, matrix_pointwise_mul, poly_pointwise};
use crate::rounding;
use crate::sample;
use oxicrypt_xof::Shake256;

// ========================================================================
// ML-DSA.KeyGen — FIPS 204 §6.1 (Algorithm 1)
// ========================================================================

/// Generate an ML-DSA-87 key pair from 32 bytes of randomness.
///
/// Returns `(pk, sk)` as byte arrays.
pub(crate) fn ml_dsa_keygen(xi: &[u8; 32]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
    // 1. (ρ, ρ', K) ← H(ξ ‖ k ‖ l)
    //    where H = SHAKE-256, k = K, l = L
    let mut h = Shake256::new_internal();
    h.update(xi);
    h.update(&[K as u8]);
    h.update(&[L as u8]);
    h.finalize();

    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 64];
    let mut key = [0u8; 32];
    h.squeeze(&mut rho);
    h.squeeze(&mut sigma);
    h.squeeze(&mut key);

    // 2. A ← ExpandA(ρ)  (in NTT domain)
    let a_hat = sample::expand_a(&rho);

    // 3. (s₁, s₂) ← ExpandS(ρ')
    let (s1, s2) = sample::expand_s(&sigma);

    // 4. t = A · NTT(s₁) + s₂
    let mut s1_hat = s1.clone();
    s1_hat.ntt();

    let mut t = PolyVecK::zero();
    matrix_pointwise_mul(&mut t, &a_hat, &s1_hat);
    t.inv_ntt();
    t.add_assign(&s2);

    // Reduce t
    t.reduce();

    // 5. (t₁, t₀) ← Power2Round(t)
    let mut t1 = PolyVecK::zero();
    let mut t0 = PolyVecK::zero();
    rounding::polyveck_power2round(&t, &mut t1, &mut t0);

    // 6. pk = (ρ, t₁)
    let mut pk = [0u8; PK_LEN];
    encode::pack_pk(&rho, &t1, &mut pk);

    // 7. tr = H(pk) (64 bytes via SHAKE-256)
    let mut tr = [0u8; 64];
    let mut h_pk = Shake256::new_internal();
    h_pk.update(&pk);
    h_pk.finalize();
    h_pk.squeeze(&mut tr);

    // 8. sk = (ρ, K, tr, s₁, s₂, t₀)
    let mut sk = [0u8; SK_LEN];
    encode::pack_sk(&rho, &key, &tr, &s1, &s2, &t0, &mut sk);

    (pk, sk)
}

// ========================================================================
// ML-DSA.Sign — FIPS 204 §6.2 (Algorithm 2, deterministic mode)
// ========================================================================

/// Sign a message with an ML-DSA-87 secret key (deterministic mode).
///
/// `m_prefix` is absorbed into μ between `tr` and `message`. For the
/// internal primitive (FIPS 204 §6.2) pass `&[]`; for the external API
/// (FIPS 204 §5.2 Algorithm 2) pass `0x00 || |ctx| || ctx`.
///
/// Returns `Some(signature)` on success, `None` if signing fails
/// after too many iterations (should not happen in practice).
pub(crate) fn ml_dsa_sign(
    sk: &[u8; SK_LEN],
    m_prefix: &[u8],
    message: &[u8],
) -> Option<[u8; SIG_LEN]> {
    // Unpack secret key
    let mut rho = [0u8; 32];
    let mut key = [0u8; 32];
    let mut tr = [0u8; 64];
    let mut s1 = PolyVecL::zero();
    let mut s2 = PolyVecK::zero();
    let mut t0 = PolyVecK::zero();
    encode::unpack_sk(sk, &mut rho, &mut key, &mut tr, &mut s1, &mut s2, &mut t0);

    // 1. A ← ExpandA(ρ)
    let a_hat = sample::expand_a(&rho);

    // 2. μ = H(tr ‖ M')  (64 bytes via SHAKE-256)
    //    where M' = m_prefix ‖ message.  For internal callers m_prefix
    //    is empty and μ = H(tr ‖ M) exactly as FIPS 204 §6.2 specifies.
    let mut mu = [0u8; 64];
    {
        let mut h = Shake256::new_internal();
        h.update(&tr);
        h.update(m_prefix);
        h.update(message);
        h.finalize();
        h.squeeze(&mut mu);
    }

    // 3. ρ'' = H(K ‖ rnd ‖ μ)  (FIPS 204 §5.2 Algorithm 3, step 5)
    //    In deterministic mode rnd = 0^32 (32 zero bytes).
    //    (64 bytes via SHAKE-256)
    let rnd = [0u8; 32];
    let mut rho_pp = [0u8; 64];
    {
        let mut h = Shake256::new_internal();
        h.update(&key);
        h.update(&rnd);
        h.update(&mu);
        h.finalize();
        h.squeeze(&mut rho_pp);
    }

    // Pre-compute NTT of s₁, s₂, t₀
    let mut s1_hat = s1.clone();
    s1_hat.ntt();
    let mut s2_hat = s2.clone();
    s2_hat.ntt();
    let mut t0_hat = t0.clone();
    t0_hat.ntt();

    // 4. Signing loop
    let mut kappa: u16 = 0;
    let max_iters = 1000u16; // Safety bound; average ~4.5 iterations

    loop {
        if kappa >= max_iters {
            return None;
        }

        // 4a. y ← ExpandMask(ρ'', κ)
        let y = sample::expand_mask(&rho_pp, kappa * L as u16);

        // 4b. w = A · NTT(y)
        let mut y_hat = y.clone();
        y_hat.ntt();
        let mut w = PolyVecK::zero();
        matrix_pointwise_mul(&mut w, &a_hat, &y_hat);
        w.inv_ntt();
        w.reduce();

        // 4c. Decompose w into (w₁, w₀)
        let mut w1 = PolyVecK::zero();
        let mut w0 = PolyVecK::zero();
        rounding::polyveck_decompose(&w, &mut w1, &mut w0);

        // 4d. c̃ = H(μ ‖ w1Encode(w₁))
        let mut ctilde = [0u8; CTILDE_LEN];
        {
            let mut w1_packed = [0u8; K * 128];
            rounding::pack_w1(&w1, &mut w1_packed);

            let mut h = Shake256::new_internal();
            h.update(&mu);
            h.update(&w1_packed);
            h.finalize();
            h.squeeze(&mut ctilde);
        }

        // 4e. c = SampleInBall(c̃)
        let c = sample::sample_in_ball(&ctilde);
        let mut c_hat = c.clone();
        c_hat.ntt();

        // 4f. z = y + c · s₁  (in NTT domain, then inv_ntt)
        let mut z = PolyVecL::zero();
        for i in 0..L {
            poly_pointwise(&mut z.polys[i], &c_hat, &s1_hat.polys[i]);
        }
        z.inv_ntt();
        z.add_assign(&y);
        z.reduce();

        // 4g. Check ‖z‖∞ < γ₁ − β
        if z.check_norm(GAMMA1 - BETA) {
            kappa += 1;
            continue;
        }

        // 4h. Compute c · s₂ and check w₀ − c·s₂
        let mut cs2 = PolyVecK::zero();
        for i in 0..K {
            poly_pointwise(&mut cs2.polys[i], &c_hat, &s2_hat.polys[i]);
        }
        cs2.inv_ntt();

        // w₀ − c·s₂
        let mut r0 = w0.clone();
        r0.sub_assign(&cs2);
        rounding::reduce_polyveck(&mut r0);

        if r0.check_norm(GAMMA2 - BETA) {
            kappa += 1;
            continue;
        }

        // 4i. Compute c · t₀
        let mut ct0 = PolyVecK::zero();
        for i in 0..K {
            poly_pointwise(&mut ct0.polys[i], &c_hat, &t0_hat.polys[i]);
        }
        ct0.inv_ntt();
        ct0.reduce();

        // Check ‖ct₀‖∞ < γ₂
        if ct0.check_norm(GAMMA2) {
            kappa += 1;
            continue;
        }

        // 4j. Compute hint h
        // h = MakeHint(−ct₀, w − cs₂ + ct₀)
        // Which simplifies to: MakeHint(ct₀, w₀ − cs₂ + ct₀)
        // Actually per FIPS 204: h = MakeHint(−ct₀, w − c·s₂ + ct₀)
        // w − c·s₂ + ct₀ = w₀ + w₁·2γ₂ − c·s₂ + ct₀ = ...
        // Let's use the standard formulation:
        // r = w₀ − c·s₂ + ct₀ (the "recovery" value)
        // z_arg = −ct₀  (negated)
        let mut hint_z = ct0.clone();
        for p in &mut hint_z.polys {
            for c_val in &mut p.coeffs {
                *c_val = -*c_val;
            }
        }

        // r = w₀ − cs₂ + ct₀ = r0 + ct₀
        let mut hint_r = r0.clone();
        hint_r.add_assign(&ct0);
        rounding::reduce_polyveck(&mut hint_r);

        let mut h = PolyVecK::zero();
        let hint_count = rounding::polyveck_make_hint(&mut h, &hint_z, &hint_r);

        if hint_count > OMEGA {
            kappa += 1;
            continue;
        }

        // 5. Encode signature
        let mut sig = [0u8; SIG_LEN];
        if !encode::pack_sig(&ctilde, &z, &h, &mut sig) {
            kappa += 1;
            continue;
        }

        return Some(sig);
    }
}

// ========================================================================
// ML-DSA.Verify — FIPS 204 §6.3 (Algorithm 3)
// ========================================================================

/// Verify an ML-DSA-87 signature.
///
/// `m_prefix` is absorbed into μ between `tr` and `message`. For the
/// internal primitive (FIPS 204 §6.3) pass `&[]`; for the external API
/// (FIPS 204 §5.2 Algorithm 3) pass `0x00 || |ctx| || ctx`.
///
/// Returns `true` if the signature is valid.
pub(crate) fn ml_dsa_verify(
    pk: &[u8; PK_LEN],
    m_prefix: &[u8],
    message: &[u8],
    sig: &[u8; SIG_LEN],
) -> bool {
    // 1. Unpack public key
    let mut rho = [0u8; 32];
    let mut t1 = PolyVecK::zero();
    encode::unpack_pk(pk, &mut rho, &mut t1);

    // 2. Unpack signature
    let mut ctilde = [0u8; CTILDE_LEN];
    let mut z = PolyVecL::zero();
    let mut h = PolyVecK::zero();
    if !encode::unpack_sig(sig, &mut ctilde, &mut z, &mut h) {
        return false;
    }

    // 3. Check ‖z‖∞ < γ₁ − β
    if z.check_norm(GAMMA1 - BETA) {
        return false;
    }

    // 4. A ← ExpandA(ρ)
    let a_hat = sample::expand_a(&rho);

    // 5. tr = H(pk) (64 bytes)
    let mut tr = [0u8; 64];
    {
        let mut h_pk = Shake256::new_internal();
        h_pk.update(pk);
        h_pk.finalize();
        h_pk.squeeze(&mut tr);
    }

    // 6. μ = H(tr ‖ M') (64 bytes)
    //    where M' = m_prefix ‖ message.  For internal callers m_prefix
    //    is empty and μ = H(tr ‖ M) exactly as FIPS 204 §6.3 specifies.
    let mut mu = [0u8; 64];
    {
        let mut h_mu = Shake256::new_internal();
        h_mu.update(&tr);
        h_mu.update(m_prefix);
        h_mu.update(message);
        h_mu.finalize();
        h_mu.squeeze(&mut mu);
    }

    // 7. c = SampleInBall(c̃)
    let c = sample::sample_in_ball(&ctilde);
    let mut c_hat = c.clone();
    c_hat.ntt();

    // 8. Compute w' = A · NTT(z) − c · NTT(t₁ · 2^d)
    //    = A · ẑ − ĉ · t̂₁ · 2^d
    let mut z_hat = z.clone();
    z_hat.ntt();

    // A · z (in NTT domain)
    let mut w_prime = PolyVecK::zero();
    matrix_pointwise_mul(&mut w_prime, &a_hat, &z_hat);

    // t₁ · 2^d → shift each coefficient left by d, then NTT
    let mut t1_scaled = t1.clone();
    for p in &mut t1_scaled.polys {
        for coeff in &mut p.coeffs {
            *coeff <<= D;
        }
    }
    t1_scaled.ntt();

    // c · t₁_scaled (in NTT domain)
    let mut ct1 = PolyVecK::zero();
    for i in 0..K {
        poly_pointwise(&mut ct1.polys[i], &c_hat, &t1_scaled.polys[i]);
    }

    // w' = A·z − c·t₁·2^d (in NTT domain)
    w_prime.sub_assign(&ct1);
    w_prime.inv_ntt();
    w_prime.reduce();

    // 9. w₁' = UseHint(h, w')
    let mut w1_prime = PolyVecK::zero();
    rounding::polyveck_use_hint(&mut w1_prime, &w_prime, &h);

    // 10. c̃' = H(μ ‖ w1Encode(w₁'))
    let mut ctilde_prime = [0u8; CTILDE_LEN];
    {
        let mut w1_packed = [0u8; K * 128];
        rounding::pack_w1(&w1_prime, &mut w1_packed);

        let mut h_final = Shake256::new_internal();
        h_final.update(&mu);
        h_final.update(&w1_packed);
        h_final.finalize();
        h_final.squeeze(&mut ctilde_prime);
    }

    // 11. Verify c̃ == c̃'
    ctilde == ctilde_prime
}
