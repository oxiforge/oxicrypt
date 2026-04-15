//! Fujisaki–Okamoto transform: ML-KEM-1024 KEM proper
//! (FIPS 203 §4.3, Algorithms 15–17).
//!
//! The FO transform converts the IND-CPA K-PKE into an IND-CCA2
//! KEM with implicit rejection.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use crate::field::{ct_bytes_eq, ct_select_32};
use crate::kpke::{kpke_decrypt, kpke_encrypt, kpke_keygen};
use crate::params::{CT_LEN, DK_LEN, EK_LEN, K, SEED_LEN, SHARED_SECRET_LEN};
use oxicrypt_sha::sha3::{Sha3_256, Sha3_512, SHA3_256_DIGEST_SIZE, SHA3_512_DIGEST_SIZE};
use oxicrypt_xof::Shake256;

/// ML-KEM.KeyGen (FIPS 203 Algorithm 15).
///
/// - `d`: 32 bytes of randomness for K-PKE key generation.
/// - `z`: 32 bytes of randomness for implicit-rejection seed.
/// - `ek`: output encapsulation key (1568 bytes).
/// - `dk`: output decapsulation key (3168 bytes).
pub(crate) fn ml_kem_keygen(
    d: &[u8; SEED_LEN],
    z: &[u8; SEED_LEN],
    ek: &mut [u8; EK_LEN],
    dk: &mut [u8; DK_LEN],
) {
    // 1. Run K-PKE.KeyGen to get (ek_PKE, dk_PKE)
    let dk_pke_len = 384 * K; // 1536
    kpke_keygen(d, ek, &mut dk[..dk_pke_len]);

    // 2. dk = dk_PKE ‖ ek ‖ H(ek) ‖ z
    //    dk[0..1536]       = dk_PKE  (already written)
    //    dk[1536..3104]    = ek
    //    dk[3104..3136]    = H(ek) = SHA3-256(ek)
    //    dk[3136..3168]    = z
    dk[dk_pke_len..dk_pke_len + EK_LEN].copy_from_slice(ek);

    let mut h = <Sha3_256>::new_internal();
    h.update(ek);
    let h_ek: [u8; SHA3_256_DIGEST_SIZE] = h.finalize();
    dk[dk_pke_len + EK_LEN..dk_pke_len + EK_LEN + 32].copy_from_slice(&h_ek);

    dk[dk_pke_len + EK_LEN + 32..dk_pke_len + EK_LEN + 64].copy_from_slice(z);
}

/// ML-KEM.Encaps (FIPS 203 Algorithm 16).
///
/// - `ek`: encapsulation key (1568 bytes).
/// - `m`: 32 bytes of randomness for the shared secret.
/// - Returns `(K, c)` where K is the 32-byte shared secret and
///   c is the ciphertext.
///
/// Returns `None` if the encapsulation key is malformed.
pub(crate) fn ml_kem_encaps(
    ek: &[u8; EK_LEN],
    m: &[u8; SEED_LEN],
) -> ([u8; SHARED_SECRET_LEN], [u8; CT_LEN]) {
    // 1. (K, r) ← G(m ‖ H(ek))
    let mut h = <Sha3_256>::new_internal();
    h.update(ek);
    let h_ek: [u8; SHA3_256_DIGEST_SIZE] = h.finalize();

    let mut g = <Sha3_512>::new_internal();
    g.update(m);
    g.update(&h_ek);
    let g_out: [u8; SHA3_512_DIGEST_SIZE] = g.finalize();

    let mut k = [0u8; 32];
    let mut r = [0u8; 32];
    k.copy_from_slice(&g_out[..32]);
    r.copy_from_slice(&g_out[32..64]);

    // 2. c ← K-PKE.Encrypt(ek, m, r)
    let mut ct = [0u8; CT_LEN];
    kpke_encrypt(ek, m, &r, &mut ct);

    (k, ct)
}

/// ML-KEM.Decaps (FIPS 203 Algorithm 17).
///
/// - `dk`: decapsulation key (3168 bytes).
/// - `ct`: ciphertext (1568 bytes).
/// - Returns the 32-byte shared secret.
///
/// **Implicit rejection**: if the ciphertext is invalid, a
/// pseudorandom key derived from the rejection seed `z` is
/// returned (constant-time, no observable difference).
pub(crate) fn ml_kem_decaps(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> [u8; SHARED_SECRET_LEN] {
    let dk_pke_len = 384 * K; // 1536

    // Parse dk = dk_PKE ‖ ek ‖ H(ek) ‖ z
    let dk_pke = &dk[..dk_pke_len];
    let ek = &dk[dk_pke_len..dk_pke_len + EK_LEN];
    let h_ek = &dk[dk_pke_len + EK_LEN..dk_pke_len + EK_LEN + 32];
    let z = &dk[dk_pke_len + EK_LEN + 32..dk_pke_len + EK_LEN + 64];

    // 1. m' ← K-PKE.Decrypt(dk_PKE, c)
    let mut m_prime = [0u8; 32];
    kpke_decrypt(dk_pke, ct, &mut m_prime);

    // 2. (K', r') ← G(m' ‖ H(ek))
    let mut g = <Sha3_512>::new_internal();
    g.update(&m_prime);
    g.update(h_ek);
    let g_out: [u8; SHA3_512_DIGEST_SIZE] = g.finalize();

    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&g_out[..32]);
    r_prime.copy_from_slice(&g_out[32..64]);

    // 3. K̄ ← J(z ‖ c) where J = SHAKE-256, first 32 bytes
    let mut j = Shake256::new_internal();
    j.update(z);
    j.update(ct);
    j.finalize();
    let mut k_bar = [0u8; 32];
    j.squeeze(&mut k_bar);

    // 4. c' ← K-PKE.Encrypt(ek, m', r')
    let mut ct_prime = [0u8; CT_LEN];
    // We need ek as a slice of EK_LEN
    kpke_encrypt(ek, &m_prime, &r_prime, &mut ct_prime);

    // 5. Constant-time comparison: if c == c', return K'; else K̄
    let diff = ct_bytes_eq(ct, &ct_prime);
    // diff == 0 means equal → select k_prime; diff != 0 → select k_bar
    ct_select_32(&k_prime, &k_bar, diff)
}
