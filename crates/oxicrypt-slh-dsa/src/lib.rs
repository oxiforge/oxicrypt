//! SLH-DSA (FIPS 205) — stateless hash-based digital signature.
//!
//! # Overview
//!
//! SLH-DSA is the third NIST post-quantum signature standard. Unlike
//! LMS/XMSS it is **stateless**: the signer does not need to track
//! which leaf indices have been used.  Security rests entirely on the
//! collision resistance and preimage resistance of the underlying
//! hash function (SHA-256 for this parameter set).
//!
//! # Parameter set
//!
//! This crate implements **SLH-DSA-SHA2-256s** ("small signatures"):
//!
//! | Parameter | Value | Meaning |
//! |-----------|-------|---------|
//! | n         | 32    | Hash output / security parameter (bytes) |
//! | h         | 64    | Total hyper-tree height |
//! | d         | 8     | Number of hyper-tree layers |
//! | h'        | 8     | Tree height per layer |
//! | a         | 14    | FORS tree height |
//! | k         | 22    | Number of FORS trees |
//! | w         | 16    | Winternitz parameter |
//! | pk        | 64 B  | Public key |
//! | sk        | 128 B | Secret key |
//! | sig       | 29792 B | Signature |
//!
//! # Approved services
//!
//! | Service | Standard | Profile |
//! |---------|----------|---------|
//! | SLH-DSA keygen | FIPS 205 | Unrestricted |
//! | SLH-DSA sign   | FIPS 205 | Unrestricted |
//! | SLH-DSA verify | FIPS 205 | Unrestricted |
//!
//! # Self-tests
//!
//! Power-up KAT: deterministic keygen → sign → verify round-trip
//! with a fixed seed (FIPS 140-3 IG D.G).

#![no_std]
#![forbid(unsafe_code)]
// Cryptographic code requires pervasive index arithmetic, bitwise
// operations, and controlled truncation that are safe by construction
// (all indices are bounded by compile-time constants).  Large stack
// arrays are unavoidable for signature buffers in `no_std`.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::large_stack_arrays,
    clippy::manual_div_ceil,
    clippy::needless_range_loop,
    clippy::unnecessary_cast,
    clippy::unwrap_used
)]

mod adrs;
mod fors;
mod hypertree;
mod params;
mod thash;
mod wots;
mod xmss;

pub use params::{PK_LEN, SIG_LEN, SK_LEN};

use adrs::{Adrs, AdrsType};
use oxicrypt_module::{Error, KatEntry, Service};
use params::N;

// ── Key generation (Algorithm 17) ───────────────────────────────────

/// Generate an SLH-DSA-SHA2-256s key pair from a 96-byte seed.
///
/// `xi` must contain 3 × 32 = 96 bytes of fresh randomness:
/// `SK.seed ‖ SK.prf ‖ PK.seed`.
///
/// Returns `(public_key, secret_key)`.
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids SLH-DSA.
/// - [`Error::InvalidInput`] if `xi` is not 96 bytes.
pub fn keygen(xi: &[u8]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaKeygen)?;
    if xi.len() != 3 * N {
        return Err(Error::InvalidInput);
    }
    let mut seed = [0u8; 3 * N];
    seed.copy_from_slice(xi);
    let (pk, sk) = keygen_internal(&seed);
    Ok((pk, sk))
}

/// Gate-free key generation for self-tests.
#[doc(hidden)]
pub fn keygen_internal(xi: &[u8; 96]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
    let sk_seed: &[u8; N] = xi[..N].try_into().unwrap();
    let sk_prf: &[u8; N] = xi[N..2 * N].try_into().unwrap();
    let pk_seed: &[u8; N] = xi[2 * N..3 * N].try_into().unwrap();

    // Compute the top-level XMSS tree root at layer D-1.
    let adrs = Adrs::zero();
    let mut top_adrs = adrs;
    top_adrs.set_layer_address((params::D - 1) as u32);
    let pk_root = xmss::xmss_node(pk_seed, sk_seed, 0, params::H_PRIME as u32, &top_adrs);

    // Public key: PK.seed ‖ PK.root.
    let mut pk = [0u8; PK_LEN];
    pk[..N].copy_from_slice(pk_seed);
    pk[N..].copy_from_slice(&pk_root);

    // Secret key: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root.
    let mut sk = [0u8; SK_LEN];
    sk[..N].copy_from_slice(sk_seed);
    sk[N..2 * N].copy_from_slice(sk_prf);
    sk[2 * N..3 * N].copy_from_slice(pk_seed);
    sk[3 * N..].copy_from_slice(&pk_root);

    (pk, sk)
}

// ── Signing (Algorithm 18) ──────────────────────────────────────────

/// Sign a message with SLH-DSA-SHA2-256s (deterministic mode).
///
/// Returns the signature (29 792 bytes).
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids SLH-DSA.
/// - [`Error::InvalidInput`] if `sk` is not `SK_LEN` bytes.
pub fn sign(sk: &[u8], message: &[u8]) -> Result<[u8; SIG_LEN], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaSign)?;
    let sk_arr: &[u8; SK_LEN] = sk.try_into().map_err(|_| Error::InvalidInput)?;
    Ok(sign_internal(sk_arr, message))
}

/// Gate-free signing for self-tests.
#[doc(hidden)]
pub fn sign_internal(sk: &[u8; SK_LEN], message: &[u8]) -> [u8; SIG_LEN] {
    let sk_seed: &[u8; N] = sk[..N].try_into().unwrap();
    let sk_prf: &[u8; N] = sk[N..2 * N].try_into().unwrap();
    let pk_seed: &[u8; N] = sk[2 * N..3 * N].try_into().unwrap();
    let pk_root: &[u8; N] = sk[3 * N..4 * N].try_into().unwrap();

    let mut sig = [0u8; SIG_LEN];

    // Deterministic mode: opt_rand = PK.seed.
    let opt_rand = pk_seed;

    // R = PRF_msg(SK.prf, opt_rand, M).
    let r = thash::prf_msg(sk_prf, opt_rand, message);
    sig[..N].copy_from_slice(&r);

    // Derive FORS digest and tree/leaf indices.
    let h_out = thash::h_msg(&r, pk_seed, pk_root, message);

    // FORS signature.
    let mut fors_adrs = Adrs::zero();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(h_out.tree_idx);
    fors_adrs.set_type(AdrsType::ForsTree);
    fors_adrs.set_keypair_address(h_out.leaf_idx);

    let fors_sig = fors::fors_sign(pk_seed, sk_seed, &h_out.md, &fors_adrs);
    sig[N..N + fors::FORS_SIG_LEN].copy_from_slice(&fors_sig);

    // Compute FORS public key (the message that the hyper-tree signs).
    let fors_pk = fors::fors_pk_from_sig(pk_seed, &h_out.md, &fors_sig, &fors_adrs);

    // Hyper-tree signature.
    let ht_sig = hypertree::ht_sign(pk_seed, sk_seed, &fors_pk, h_out.tree_idx, h_out.leaf_idx);
    sig[N + fors::FORS_SIG_LEN..].copy_from_slice(&ht_sig);

    sig
}

// ── Verification (Algorithm 19) ─────────────────────────────────────

/// Verify an SLH-DSA-SHA2-256s signature.
///
/// Returns `Ok(())` if the signature is valid, `Err(InvalidInput)` otherwise.
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids SLH-DSA.
/// - [`Error::InvalidInput`] if any input has the wrong length or the
///   signature is invalid.
pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaVerify)?;
    let pk_arr: &[u8; PK_LEN] = pk.try_into().map_err(|_| Error::InvalidInput)?;
    let sig_arr: &[u8; SIG_LEN] = signature.try_into().map_err(|_| Error::InvalidInput)?;
    if verify_internal(pk_arr, message, sig_arr) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Gate-free verification for self-tests.
#[doc(hidden)]
pub fn verify_internal(pk: &[u8; PK_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    let pk_seed: &[u8; N] = pk[..N].try_into().unwrap();
    let pk_root: &[u8; N] = pk[N..2 * N].try_into().unwrap();

    // Extract R from signature.
    let r: &[u8; N] = sig[..N].try_into().unwrap();

    // Derive FORS digest and indices.
    let h_out = thash::h_msg(r, pk_seed, pk_root, message);

    // Reconstruct FORS public key.
    let mut fors_adrs = Adrs::zero();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(h_out.tree_idx);
    fors_adrs.set_type(AdrsType::ForsTree);
    fors_adrs.set_keypair_address(h_out.leaf_idx);

    let fors_sig = &sig[N..N + fors::FORS_SIG_LEN];
    let fors_pk = fors::fors_pk_from_sig(pk_seed, &h_out.md, fors_sig, &fors_adrs);

    // Verify hyper-tree signature.
    let ht_sig = &sig[N + fors::FORS_SIG_LEN..];
    hypertree::ht_verify(
        pk_seed,
        pk_root,
        &fors_pk,
        ht_sig,
        h_out.tree_idx,
        h_out.leaf_idx,
    )
}

// ── Self-tests ──────────────────────────────────────────────────────

/// Power-up KATs for SLH-DSA-SHA2-256s.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "SLH-DSA-SHA2-256s KAT (keygen + sign + verify round-trip, FIPS 205)",
    run: self_test,
}];

/// Run the SLH-DSA power-up self-test.
///
/// Uses a deterministic seed so the test is reproducible.
fn self_test() -> Result<(), oxicrypt_module::SelfTestFailure> {
    // Fixed 96-byte seed (arbitrary but deterministic).
    let mut xi = [0u8; 96];
    // Fill with a simple pattern for reproducibility.
    for (i, b) in xi.iter_mut().enumerate() {
        *b = ((i & 0xFF) as u8).wrapping_mul(37).wrapping_add(7);
    }

    let (pk, sk) = keygen_internal(&xi);

    // Sign a test message.
    let msg = b"SLH-DSA-SHA2-256s self-test message (FIPS 205)";
    let sig = sign_internal(&sk, msg);

    // Verify must succeed.
    if !verify_internal(&pk, msg, &sig) {
        return Err(oxicrypt_module::SelfTestFailure);
    }

    // Verify with a wrong message must fail.
    let bad_msg = b"tampered message";
    if verify_internal(&pk, bad_msg, &sig) {
        return Err(oxicrypt_module::SelfTestFailure);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Fill a 96-byte seed with a simple deterministic pattern.
    fn test_seed() -> [u8; 96] {
        let mut xi = [0u8; 96];
        for (i, b) in xi.iter_mut().enumerate() {
            *b = ((i & 0xFF) as u8).wrapping_mul(37).wrapping_add(7);
        }
        xi
    }

    /// Round-trip: keygen → sign → verify with the same deterministic
    /// seed as the power-up KAT.
    #[test]
    fn round_trip() {
        let xi = test_seed();
        let (pk, sk) = keygen_internal(&xi);

        assert_eq!(pk.len(), PK_LEN);
        assert_eq!(sk.len(), SK_LEN);

        let msg = b"SLH-DSA-SHA2-256s round-trip test";
        let sig = sign_internal(&sk, msg);
        assert_eq!(sig.len(), SIG_LEN);

        assert!(verify_internal(&pk, msg, &sig));
        assert!(!verify_internal(&pk, b"wrong", &sig));
    }

    /// Verify that different messages produce different signatures.
    #[test]
    fn different_messages() {
        let xi = test_seed();
        let (_pk, sk) = keygen_internal(&xi);

        let sig1 = sign_internal(&sk, b"message A");
        let sig2 = sign_internal(&sk, b"message B");
        assert_ne!(sig1[..32], sig2[..32]); // R values differ (deterministic on msg)
    }

    /// KAT function runs without panic.
    #[test]
    fn kat_passes() {
        self_test().expect("SLH-DSA KAT failed");
    }
}
