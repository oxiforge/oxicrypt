//! TLS 1.2 KDF per SP 800-135 Rev. 1 §4 and RFC 5246 §5.
//!
//! Implements the TLS 1.2 PRF (`P_hash` expansion) used for both
//! standard master-secret derivation (RFC 5246 §8.1) and RFC 7627
//! Extended Master Secret derivation. The `key expansion` step
//! (RFC 5246 §6.3) uses the same PRF core.
//!
//! # Algorithm
//!
//! ```text
//! PRF(secret, label, seed) = P_hash(secret, label ‖ seed)
//!
//! P_hash(secret, seed) = HMAC(secret, A(1) ‖ seed) ‖
//!                         HMAC(secret, A(2) ‖ seed) ‖ …
//! A(0) = seed
//! A(i) = HMAC(secret, A(i−1))
//! ```
//!
//! The PRF is generic over the underlying HMAC via the
//! [`fips_kdf::PrfHmac`] trait.
#![no_std]
#![forbid(unsafe_code)]

use fips_kdf::PrfHmac;

// ── Core PRF ──────────────────────────────────────────────────────

/// TLS 1.2 PRF expansion (RFC 5246 §5).
///
/// Fills `out` with `PRF(secret, label, seed)` — the `P_hash`
/// iterated-HMAC expansion. `label` and `seed` are concatenated
/// internally (no caller allocation needed).
///
/// This is the internal variant that bypasses module-state gating;
/// callers in the ACVP harness (which runs behind its own
/// `require_operational` gate) use this directly.
///
/// # Safety invariant
///
/// The `while offset < out.len()` loop guard guarantees all slice
/// accesses stay in bounds. `offset` advances by at most `L` per
/// iteration. Arithmetic is bounded by `out.len()` which fits in
/// `usize` — no wrapping.
// Allow: loop invariant guarantees in-bounds; arithmetic bounded by len.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_prf_internal<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out: &mut [u8],
) {
    // A(0) = label ‖ seed
    // A(i) = HMAC(secret, A(i−1))
    let mut a = {
        let mut mac = P::prf_new(secret);
        mac.prf_update(label);
        mac.prf_update(seed);
        mac.prf_finalize()
    };

    let mut offset = 0;
    while offset < out.len() {
        // P_i = HMAC(secret, A(i) ‖ label ‖ seed)
        let mut mac = P::prf_new(secret);
        mac.prf_update(&a);
        mac.prf_update(label);
        mac.prf_update(seed);
        let p = mac.prf_finalize();

        let remaining = out.len() - offset;
        let to_copy = if remaining < L { remaining } else { L };
        out[offset..offset + to_copy].copy_from_slice(&p[..to_copy]);
        offset += to_copy;

        // A(i+1) = HMAC(secret, A(i))
        let mut mac_a = P::prf_new(secret);
        mac_a.prf_update(&a);
        a = mac_a.prf_finalize();
    }
}

// ── RFC 7627 Extended Master Secret ───────────────────────────────

/// Master-secret length per RFC 5246 §8.1 — always 48 bytes.
pub const MASTER_SECRET_LEN: usize = 48;

/// Derive master secret and key block per TLS 1.2 with RFC 7627
/// Extended Master Secret.
///
/// 1. `master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..48]`
/// 2. `key_block = PRF(master_secret, "key expansion", server_random ‖ client_random)[0..key_block_len]`
///
/// Returns the 48-byte master secret and fills `key_block_out`.
///
/// # Panics
///
/// Panics if `server_random.len() + client_random.len() > 64`.
// Allow: seed assembly is bounded (TLS randoms are 32 bytes each).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_extended_master_secret_internal<P: PrfHmac<L>, const L: usize>(
    pre_master_secret: &[u8],
    session_hash: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_out: &mut [u8],
) -> [u8; MASTER_SECRET_LEN] {
    // Step 1: extended master secret
    let mut master_secret = [0u8; MASTER_SECRET_LEN];
    tls12_prf_internal::<P, L>(
        pre_master_secret,
        b"extended master secret",
        session_hash,
        &mut master_secret,
    );

    // Step 2: key expansion
    // seed = server_random ‖ client_random (RFC 5246 §6.3)
    let sr_len = server_random.len();
    let cr_len = client_random.len();
    assert!(sr_len + cr_len <= 64, "TLS randoms exceed 64 bytes");
    let mut seed = [0u8; 64];
    seed[..sr_len].copy_from_slice(server_random);
    seed[sr_len..sr_len + cr_len].copy_from_slice(client_random);
    tls12_prf_internal::<P, L>(
        &master_secret,
        b"key expansion",
        &seed[..sr_len + cr_len],
        key_block_out,
    );

    master_secret
}

// ── Standard (non-EMS) Master Secret ──────────────────────────────

/// Derive master secret and key block per standard TLS 1.2
/// (RFC 5246 §8.1, no EMS extension).
///
/// 1. `master_secret = PRF(pre_master_secret, "master secret", client_hello_random ‖ server_hello_random)[0..48]`
/// 2. `key_block = PRF(master_secret, "key expansion", server_random ‖ client_random)[0..key_block_len]`
///
/// # Panics
///
/// Panics if any concatenated seed pair exceeds 64 bytes.
// Allow: seed assembly is bounded (TLS randoms are 32 bytes each).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_master_secret_internal<P: PrfHmac<L>, const L: usize>(
    pre_master_secret: &[u8],
    client_hello_random: &[u8],
    server_hello_random: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_out: &mut [u8],
) -> [u8; MASTER_SECRET_LEN] {
    // Step 1: master secret — seed = clientHelloRandom ‖ serverHelloRandom
    let chr_len = client_hello_random.len();
    let shr_len = server_hello_random.len();
    assert!(chr_len + shr_len <= 64, "TLS hello randoms exceed 64 bytes");
    let mut ms_seed = [0u8; 64];
    ms_seed[..chr_len].copy_from_slice(client_hello_random);
    ms_seed[chr_len..chr_len + shr_len].copy_from_slice(server_hello_random);

    let mut master_secret = [0u8; MASTER_SECRET_LEN];
    tls12_prf_internal::<P, L>(
        pre_master_secret,
        b"master secret",
        &ms_seed[..chr_len + shr_len],
        &mut master_secret,
    );

    // Step 2: key expansion — seed = serverRandom ‖ clientRandom
    let server_len = server_random.len();
    let client_len = client_random.len();
    assert!(server_len + client_len <= 64, "TLS randoms exceed 64 bytes");
    let mut ke_seed = [0u8; 64];
    ke_seed[..server_len].copy_from_slice(server_random);
    ke_seed[server_len..server_len + client_len].copy_from_slice(client_random);
    tls12_prf_internal::<P, L>(
        &master_secret,
        b"key expansion",
        &ke_seed[..server_len + client_len],
        key_block_out,
    );

    master_secret
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use fips_hmac::HmacSha256;

    /// Smoke test: PRF produces deterministic, non-zero output.
    #[test]
    fn prf_produces_output() {
        let secret = [0x0bu8; 16];
        let label = b"test label";
        let seed = [0xaau8; 32];
        let mut out = [0u8; 64];
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out);
        assert_ne!(out, [0u8; 64]);
    }

    /// PRF is deterministic.
    #[test]
    fn prf_deterministic() {
        let secret = [0x01u8; 48];
        let label = b"key expansion";
        let seed = [0xffu8; 64];
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out1);
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out2);
        assert_eq!(out1, out2);
    }
}
