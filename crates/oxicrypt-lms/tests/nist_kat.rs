//! NIST ACVP Known-Answer Tests for LMS (SP 800-208, RFC 8554).
//!
//! Vectors sourced from the NIST ACVP Server repository:
//!   usnistgov/ACVP-Server @ 112690e8484dba7077709a05b1f3af58ddefdd5d
//!
//! Parameter set: LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4.
//!
//! Test cases:
//!   - keyGen  tgId=27, tcId=89:  (seed, I) → public_key
//!   - sigVer  tgId=27, tcId=107: (public_key, message, signature) → pass
#![allow(clippy::expect_used, clippy::unwrap_used)]

use oxicrypt_lms::{keygen_from_parts, verify_internal, PUBLIC_KEY_LEN, SIGNATURE_LEN};

// ── Vector helpers ──────────────────────────────────────────────────────────

fn load(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
    std::fs::read(format!("{path}{name}")).expect("test data not found")
}

fn load_arr<const N: usize>(name: &str) -> [u8; N] {
    let v = load(name);
    assert_eq!(v.len(), N, "unexpected length for {name}");
    v.try_into().unwrap()
}

// ── keyGen KAT ──────────────────────────────────────────────────────────────

/// ACVP LMS keyGen: tgId=27, tcId=89.
///
/// The ACVP keyGen test provides `seed` (32 bytes) and `I` (16-byte tree
/// identifier) directly, rather than deriving them from a master xi via
/// SHA-256.  `keygen_from_parts(seed, I)` accepts these values directly.
///
/// Note: this test hashes all 1024 leaves (LMS_SHA256_M32_H10) and may
/// take up to one second.
#[test]
fn nist_keygen_kat() {
    let seed = load_arr::<32>("lms_sha256_h10_nist_keygen_seed.bin");
    let identifier = load_arr::<16>("lms_sha256_h10_nist_keygen_i.bin");
    let expected_pk = load_arr::<PUBLIC_KEY_LEN>("lms_sha256_h10_nist_keygen_pk.bin");

    let (_sk, pk) = keygen_from_parts(&seed, &identifier);

    assert_eq!(
        pk, expected_pk,
        "LMS keyGen: public key does not match NIST ACVP vector (tgId=27, tcId=89)"
    );
}

// ── Second keyGen KAT ──────────────────────────────────────────────────────

/// ACVP LMS keyGen: tgId=27, tcId=90.
///
/// Second independent keygen test from the NIST ACVP Server projection.
#[test]
fn nist_keygen_kat_2() {
    let seed = load_arr::<32>("lms_sha256_h10_nist_keygen2_seed.bin");
    let identifier = load_arr::<16>("lms_sha256_h10_nist_keygen2_i.bin");
    let expected_pk = load_arr::<PUBLIC_KEY_LEN>("lms_sha256_h10_nist_keygen2_pk.bin");

    let (_sk, pk) = keygen_from_parts(&seed, &identifier);

    assert_eq!(
        pk, expected_pk,
        "LMS keyGen: public key does not match NIST ACVP vector (tgId=27, tcId=90)"
    );
}

// ── sigVer KAT ──────────────────────────────────────────────────────────────

/// ACVP LMS sigVer (passing): tgId=27, tcId=107.
///
/// Verifies that a valid NIST ACVP signature is accepted.
#[test]
fn nist_sigver_pass() {
    let pk = load_arr::<PUBLIC_KEY_LEN>("lms_sha256_h10_nist_sigver_pk.bin");
    let message = load("lms_sha256_h10_nist_sigver_message.bin");
    let sig = load_arr::<SIGNATURE_LEN>("lms_sha256_h10_nist_sigver_signature.bin");

    assert!(
        verify_internal(&pk, &message, &sig),
        "LMS sigVer: verify_internal rejected valid NIST ACVP signature (tgId=27, tcId=107)"
    );
}

// ── sigVer negative KAT ────────────────────────────────────────────────────

/// ACVP LMS sigVer (failing): tgId=27, tcId=105.
///
/// A modified signature must be rejected. This exercises the negative
/// path of the verification logic.
#[test]
fn nist_sigver_fail() {
    let pk = load_arr::<PUBLIC_KEY_LEN>("lms_sha256_h10_nist_sigver_fail_pk.bin");
    let message = load("lms_sha256_h10_nist_sigver_fail_message.bin");
    let sig = load_arr::<SIGNATURE_LEN>("lms_sha256_h10_nist_sigver_fail_signature.bin");

    assert!(
        !verify_internal(&pk, &message, &sig),
        "LMS sigVer: verify_internal accepted invalid NIST ACVP signature (tgId=27, tcId=105)"
    );
}
