//! NIST ACVP Known-Answer Tests for LMS (SP 800-208, RFC 8554).
//!
//! Vectors sourced from the NIST ACVP Server repository:
//!   usnistgov/ACVP-Server @ 3611942ea10c070dd8bc6afec5682d56c307de8a
//!
//! Parameter set: LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4.
//!
//! Test cases:
//!   - sigVer  tgId=27, tcId=107: (public_key, message, signature) → pass
//!   - sigVer  tgId=27, tcId=105: (public_key, message, signature) → fail
#![allow(clippy::expect_used, clippy::unwrap_used)]

use oxicrypt_lms::{PUBLIC_KEY_LEN, SIGNATURE_LEN, verify_internal};

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
