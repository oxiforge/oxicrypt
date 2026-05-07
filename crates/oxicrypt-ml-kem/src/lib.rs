//! ML-KEM-1024 (FIPS 203) — lattice-based key encapsulation mechanism.
//!
//! # Status
//!
//! **Implemented.**  This crate provides the full ML-KEM-1024 KEM as
//! specified in FIPS 203 (August 2024), including K-PKE key generation,
//! encryption, decryption, and the Fujisaki–Okamoto transform with
//! constant-time implicit rejection.
//!
//! # Approved services
//!
//! | Service | Description |
//! |---------|-------------|
//! | `MlKem1024Keygen` | Generate an ML-KEM-1024 key pair |
//! | `MlKem1024Encaps` | Encapsulate a shared secret |
//! | `MlKem1024Decaps` | Decapsulate a shared secret |
//!
//! All three services are gated by
//! [`AlgorithmProfile`](oxicrypt_module::AlgorithmProfile): allowed in
//! `Unrestricted`, `Cnsa2`, and `Cnsa1` (transition period).
//!
//! # Algorithm profile
//!
//! ML-KEM-1024 is the primary post-quantum KEM for CNSA 2.0 and is
//! mandated for key establishment by the 2027 deadline.
//!
//! # Parameters (FIPS 203 Table 2)
//!
//! | Parameter | Value |
//! |-----------|-------|
//! | n         | 256   |
//! | k         | 4     |
//! | q         | 3329  |
//! | η₁, η₂   | 2, 2  |
//! | dᵤ, dᵥ   | 11, 5 |
//! | Shared secret | 32 bytes |
//! | Encapsulation key | 1568 bytes |
//! | Decapsulation key | 3168 bytes |
//! | Ciphertext | 1568 bytes |
//!
//! # Power-up self-tests
//!
//! [`KATS`] contains a deterministic round-trip test: keygen from a
//! fixed seed, encapsulate with a fixed message, decapsulate, and
//! verify the shared secrets match.  Additionally a negative test
//! confirms that implicit rejection produces a different key when the
//! ciphertext is tampered.
//!
//! # Sensitive security parameters
//!
//! | SSP | Description | Zeroization |
//! |-----|-------------|-------------|
//! | dk  | Decapsulation key (3168 bytes) | Caller responsibility |
//! | m   | Encapsulation randomness (32 bytes) | Caller responsibility |
//! | d   | Keygen randomness (32 bytes) | Caller responsibility |
//! | z   | Implicit-rejection seed (32 bytes) | Embedded in dk |
//!
//! # FIPS module gating
//!
//! Public entry points ([`keygen`], [`encapsulate`], [`decapsulate`])
//! gate on [`oxicrypt_module::require_operational`] and
//! [`oxicrypt_module::require_allowed`].  The `*_internal` surface
//! (hidden) runs gate-free so power-up KATs can execute during
//! `SelfTest`.
//!
//! # Constant-time behaviour
//!
//! The FO transform's decapsulation uses constant-time comparison
//! and constant-time selection to implement implicit rejection.
//! NTT operations have data-independent control flow.

#![no_std]
#![forbid(unsafe_code)]

mod encode;
mod field;
mod kem;
mod kpke;
mod ntt;
/// ML-KEM-1024 parameter constants.
pub mod params;
mod poly;
mod sample;

use oxicrypt_module::{Error, KatEntry, SelfTestFailure, Service};
pub use params::{CT_LEN, DK_LEN, EK_LEN, SEED_LEN, SHARED_SECRET_LEN};

// ── Public API (gated) ──────────────────────────────────────────

/// Generate an ML-KEM-1024 key pair.
///
/// Both `d` and `z` must be 32 bytes of fresh randomness from an
/// approved DRBG (SP 800-90A).
///
/// Returns `(ek, dk)`: the encapsulation key and decapsulation key.
pub fn keygen(
    d: &[u8; SEED_LEN],
    z: &[u8; SEED_LEN],
) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlKem1024Keygen)?;
    keygen_internal(d, z).ok_or(Error::InvalidInput)
}

/// Encapsulate a shared secret against an ML-KEM-1024 encapsulation
/// key.
///
/// `m` must be 32 bytes of fresh randomness from an approved DRBG.
///
/// Returns `(shared_secret, ciphertext)`.
pub fn encapsulate(
    ek: &[u8; EK_LEN],
    m: &[u8; SEED_LEN],
) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlKem1024Encaps)?;
    Ok(encaps_internal(ek, m))
}

/// Decapsulate a shared secret from an ML-KEM-1024 ciphertext.
///
/// Uses implicit rejection: if the ciphertext is invalid, a
/// pseudorandom key is returned (constant-time, no observable
/// difference).
pub fn decapsulate(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> Result<[u8; SHARED_SECRET_LEN], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlKem1024Decaps)?;
    Ok(decaps_internal(dk, ct))
}

// ── Internal API (gate-free, for KATs) ──────────────────────────

/// Internal keygen — no module gate.
#[doc(hidden)]
pub fn keygen_internal(
    d: &[u8; SEED_LEN],
    z: &[u8; SEED_LEN],
) -> Option<([u8; EK_LEN], [u8; DK_LEN])> {
    let mut ek = [0u8; EK_LEN];
    let mut dk = [0u8; DK_LEN];
    kem::ml_kem_keygen(d, z, &mut ek, &mut dk);
    Some((ek, dk))
}

/// Internal encaps — no module gate.
#[doc(hidden)]
pub fn encaps_internal(
    ek: &[u8; EK_LEN],
    m: &[u8; SEED_LEN],
) -> ([u8; SHARED_SECRET_LEN], [u8; CT_LEN]) {
    kem::ml_kem_encaps(ek, m)
}

/// Internal decaps — no module gate.
#[doc(hidden)]
pub fn decaps_internal(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> [u8; SHARED_SECRET_LEN] {
    kem::ml_kem_decaps(dk, ct)
}

// ── Power-up KATs ───────────────────────────────────────────────

/// Power-up KATs for ML-KEM-1024.
///
/// Contains a positive round-trip test and a negative implicit-
/// rejection test, both driven by deterministic seeds.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "ML-KEM-1024 KAT (round-trip + implicit rejection, FIPS 203)",
    run: self_test,
}];

/// Deterministic KAT seed for keygen.
const KAT_D: [u8; 32] = [
    0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
    0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xaf, 0xfa, 0x28, 0x4f, 0x01,
];

/// Deterministic KAT seed for implicit-rejection randomness z.
const KAT_Z_SEED: [u8; 32] = [
    0xac, 0xcd, 0x06, 0xa5, 0x3d, 0x9b, 0x0c, 0xff, 0x59, 0xfa, 0x11, 0x68, 0x42, 0x7b, 0x31, 0x9e,
    0x2b, 0x6a, 0x9f, 0xd7, 0x04, 0xe9, 0x56, 0xd4, 0x3a, 0x08, 0xc4, 0x7e, 0x01, 0x15, 0x67, 0xbc,
];

/// Deterministic KAT seed for encapsulation.
const KAT_M: [u8; 32] = [
    0x14, 0x7c, 0x03, 0xf7, 0xa5, 0xbe, 0xbb, 0xa4, 0x06, 0xc8, 0xfa, 0xe1, 0x87, 0x4d, 0x7f, 0x13,
    0xc8, 0x0e, 0xfe, 0x79, 0xa3, 0xa9, 0xa8, 0x74, 0xcc, 0x09, 0xfe, 0x76, 0xf6, 0x99, 0x76, 0x15,
];

/// Self-test: deterministic round-trip + negative (tamper) test.
///
/// 1. KeyGen from fixed (d, z).
/// 2. Encaps with fixed m → (K, c).
/// 3. Decaps(dk, c) → K'.
/// 4. Verify K == K' (positive test).
/// 5. Tamper c, Decaps(dk, c_bad) → K''.
/// 6. Verify K'' ≠ K (implicit rejection test).
fn self_test() -> Result<(), SelfTestFailure> {
    // 1. KeyGen
    let Some((ek, dk)) = keygen_internal(&KAT_D, &KAT_Z_SEED) else {
        return Err(SelfTestFailure);
    };

    // 2. Encaps
    let (k, ct) = encaps_internal(&ek, &KAT_M);

    // 3. Decaps (positive)
    let k_prime = decaps_internal(&dk, &ct);

    // 4. K == K'
    if k != k_prime {
        return Err(SelfTestFailure);
    }

    // 5. Tamper ciphertext and decaps (negative — implicit rejection)
    let mut ct_bad = ct;
    ct_bad[0] ^= 0x01;
    let k_bad = decaps_internal(&dk, &ct_bad);

    // 6. K'' must differ from K (with overwhelming probability)
    if k_bad == k {
        return Err(SelfTestFailure);
    }

    Ok(())
}

// ── Unit tests ──────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use oxicrypt_module::{initialize_with_tests, KatEntry};

    fn ensure_initialized() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "ml-kem-1024-bootstrap",
            run: self_test,
        }]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn round_trip_basic() {
        let d = [0x42u8; 32];
        let z = [0x77u8; 32];
        let m = [0xABu8; 32];

        let (ek, dk) = keygen_internal(&d, &z).unwrap();
        let (k, ct) = encaps_internal(&ek, &m);
        let k2 = decaps_internal(&dk, &ct);
        assert_eq!(k, k2, "round-trip failed: shared secrets differ");
    }

    #[test]
    fn implicit_rejection_different_key() {
        let d = [0x01u8; 32];
        let z = [0x02u8; 32];
        let m = [0x03u8; 32];

        let (ek, dk) = keygen_internal(&d, &z).unwrap();
        let (k, mut ct) = encaps_internal(&ek, &m);
        ct[10] ^= 0xFF; // tamper
        let k_bad = decaps_internal(&dk, &ct);
        assert_ne!(
            k, k_bad,
            "implicit rejection failed: keys match after tamper"
        );
    }

    /// Tampered-ciphertext output must match the spec's `K̄ = J(z || c)`
    /// (FIPS 203 §7.3, where `J = SHAKE-256` truncated to 32 bytes)
    /// **byte-exactly** — not merely "different from the valid path".
    ///
    /// The weaker `assert_ne` guard above passes for a wide range of
    /// incorrect implementations (including a bug where `ct_select_32`
    /// only flipped LSBs of `k_prime` instead of selecting `k_bar`
    /// whole — different from `k_prime`, but also not equal to
    /// `J(z || c)`). This test pins the implicit-rejection branch
    /// against the spec-defined oracle, matching how ACVTS grades it.
    #[test]
    fn implicit_rejection_matches_j_z_c() {
        use oxicrypt_xof::Shake256;

        let d = [0x05u8; 32];
        let z = [0x06u8; 32];
        let m = [0x07u8; 32];

        let (ek, dk) = keygen_internal(&d, &z).unwrap();
        let (_k, mut ct) = encaps_internal(&ek, &m);
        ct[42] ^= 0xA5; // tamper to force implicit rejection

        // Recompute the spec's expected K̄ = J(z || c) directly:
        //   J = SHAKE-256, output truncated to 32 bytes
        //   z = decapsulation key's embedded rejection seed (matches
        //       the `z` we passed to keygen_internal above)
        let mut j = Shake256::new_internal();
        j.update(&z);
        j.update(&ct);
        j.finalize();
        let mut expected_k_bar = [0u8; 32];
        j.squeeze(&mut expected_k_bar);

        let actual = decaps_internal(&dk, &ct);
        assert_eq!(
            actual, expected_k_bar,
            "implicit rejection key must equal J(z || c) byte-exactly per FIPS 203 §7.3"
        );
    }

    #[test]
    fn different_randomness_different_keys() {
        let d1 = [0x10u8; 32];
        let z1 = [0x20u8; 32];
        let d2 = [0x30u8; 32];
        let z2 = [0x40u8; 32];

        let (ek1, _) = keygen_internal(&d1, &z1).unwrap();
        let (ek2, _) = keygen_internal(&d2, &z2).unwrap();
        assert_ne!(ek1, ek2, "different seeds should produce different keys");
    }

    #[test]
    fn key_sizes_match_spec() {
        assert_eq!(EK_LEN, 1568);
        assert_eq!(DK_LEN, 3168);
        assert_eq!(CT_LEN, 1568);
        assert_eq!(SHARED_SECRET_LEN, 32);
    }

    #[test]
    fn gated_api_requires_operational() {
        ensure_initialized();
        let d = [0u8; 32];
        let z = [0u8; 32];
        let result = keygen(&d, &z);
        // Should succeed if module is operational
        assert!(result.is_ok());
    }

    #[test]
    fn determinism() {
        // Same seeds must produce identical output
        let (ek1, dk1) = keygen_internal(&KAT_D, &KAT_Z_SEED).unwrap();
        let (ek2, dk2) = keygen_internal(&KAT_D, &KAT_Z_SEED).unwrap();
        assert_eq!(ek1, ek2);
        assert_eq!(dk1, dk2);

        let (k1, ct1) = encaps_internal(&ek1, &KAT_M);
        let (k2, ct2) = encaps_internal(&ek2, &KAT_M);
        assert_eq!(k1, k2);
        assert_eq!(ct1, ct2);
    }
}
