//! `oxicrypt_lms::verify_any`: verification under whichever (LMS, LM-OTS)
//! pair the public key names.
//!
//! Every one of the 80 pairs is exercised with the passing NIST ACVP sigVer
//! vector vendored for it under `tests/data/<pair>_sigver_{pk,msg,sig}.bin`
//! (source: usnistgov/ACVP-Server @ 3611942ea10c070dd8bc6afec5682d56c307de8a,
//! `gen-val/json-files/LMS-sigVer-1.0/internalProjection.json`). The pair
//! names are built here from the SP 800-208 §4 grid, independently of the
//! routing table under test.
//!
//! The refusal tests pin the two outcomes `verify_any` keeps apart: a key
//! or length that names no pair is [`VerifyAnyError::Unroutable`], and a
//! routed signature that fails is [`VerifyAnyError::VerificationFailed`].
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use oxicrypt_lms::{VerifyAnyError, verify_any};
use oxicrypt_module::{Error, KatEntry, initialize_with_tests};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary. The module requires an integrity group to
/// initialise at all.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// Brings the module to `Operational` with the LMS CASTs. A second call in
/// the same process reports `AlreadyInitialized`, which is accepted.
fn operational() {
    match initialize_with_tests(UNSIGNED_TEST_BINARY, oxicrypt_lms::KATS) {
        Ok(()) | Err(Error::AlreadyInitialized) => {}
        Err(e) => panic!("module failed to initialise: {e:?}"),
    }
    assert!(
        oxicrypt_module::is_operational(),
        "module is not operational"
    );
}

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The 80 per-pair module names of the SP 800-208 §4.1–§4.4 grid.
fn all_pairs() -> Vec<String> {
    let mut pairs = Vec::new();
    for family in ["sha256_m32", "sha256_m24", "shake_m32", "shake_m24"] {
        for h in [5, 10, 15, 20, 25] {
            for w in [1, 2, 4, 8] {
                pairs.push(format!("lms_{family}_h{h}_w{w}"));
            }
        }
    }
    pairs
}

/// The passing (public key, message, signature) vector for `pair`.
fn vector(pair: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        load(&format!("{pair}_sigver_pk.bin")),
        load(&format!("{pair}_sigver_msg.bin")),
        load(&format!("{pair}_sigver_sig.bin")),
    )
}

#[test]
fn every_pair_routes_and_verifies_its_nist_vector() {
    operational();
    let pairs = all_pairs();
    assert_eq!(pairs.len(), 80);
    for pair in &pairs {
        let (pk, msg, sig) = vector(pair);
        assert_eq!(verify_any(&pk, &msg, &sig), Ok(()), "{pair}");
    }
}

#[test]
fn typecode_pair_outside_the_grid_is_unroutable() {
    operational();
    let (mut pk, msg, sig) = vector("lms_sha256_m32_h5_w1");
    // LMS_SHA256_M32_H5 with LMOTS_SHA256_N24_W1: both typecodes are
    // assigned, but SP 800-208 approves no pair mixing N = 32 and N = 24.
    pk[4..8].copy_from_slice(&0x0000_0005u32.to_be_bytes());
    let mixed = verify_any(&pk, &msg, &sig);
    assert_eq!(mixed, Err(VerifyAnyError::Unroutable));
    assert_ne!(mixed, Err(VerifyAnyError::VerificationFailed));

    // An LMS typecode past the SP 800-208 range.
    let (mut pk, msg, sig) = vector("lms_sha256_m32_h5_w1");
    pk[0..4].copy_from_slice(&0x0000_0019u32.to_be_bytes());
    assert_eq!(verify_any(&pk, &msg, &sig), Err(VerifyAnyError::Unroutable));
}

#[test]
fn public_key_too_short_to_hold_typecodes_is_unroutable() {
    operational();
    let (pk, msg, sig) = vector("lms_sha256_m32_h5_w1");
    assert_eq!(
        verify_any(&pk[..7], &msg, &sig),
        Err(VerifyAnyError::Unroutable)
    );
    assert_eq!(verify_any(&[], &msg, &sig), Err(VerifyAnyError::Unroutable));
}

#[test]
fn routed_signature_that_fails_is_a_verification_failure() {
    operational();
    let (pk, mut msg, sig) = vector("lms_shake_m24_h5_w8");
    msg[0] ^= 0x01;
    let failed = verify_any(&pk, &msg, &sig);
    assert_eq!(failed, Err(VerifyAnyError::VerificationFailed));
    assert_ne!(failed, Err(VerifyAnyError::Unroutable));

    let (pk, msg, mut sig) = vector("lms_sha256_m24_h10_w2");
    sig[64] ^= 0x01;
    assert_eq!(
        verify_any(&pk, &msg, &sig),
        Err(VerifyAnyError::VerificationFailed)
    );
}

#[test]
fn zero_and_cross_family_typecode_pairs_are_unroutable() {
    operational();
    // (LMS typecode, LM-OTS typecode), each naming no SP 800-208 pair.
    let cases: [(u32, u32, &str); 4] = [
        (0x0000_0000, 0x0000_0001, "LMS typecode 0"),
        (
            0x0000_0005,
            0x0000_0000,
            "LMS_SHA256_M32_H5 with LM-OTS typecode 0",
        ),
        (
            0x0000_0005,
            0x0000_0009,
            "LMS_SHA256_M32_H5 with LMOTS_SHAKE_N32_W1",
        ),
        (
            0x0000_000f,
            0x0000_0001,
            "LMS_SHAKE_M32_H5 with LMOTS_SHA256_N32_W1",
        ),
    ];
    for (lms, lmots, what) in cases {
        let (mut pk, msg, sig) = vector("lms_sha256_m32_h5_w1");
        pk[0..4].copy_from_slice(&lms.to_be_bytes());
        pk[4..8].copy_from_slice(&lmots.to_be_bytes());
        assert_eq!(
            verify_any(&pk, &msg, &sig),
            Err(VerifyAnyError::Unroutable),
            "{what}"
        );
    }
}

/// The public key routes; the typecodes inside the signature disagree
/// with it. The routed verifier rejects the signature, so the refusal is a
/// verification failure, not a routing one.
#[test]
fn signature_typecode_mismatch_is_a_verification_failure() {
    use oxicrypt_lms::lms_sha256_m32_h5_w1 as pair;
    operational();

    // LM-OTS typecode at signature bytes 4..8: LMOTS_SHA256_N32_W2, not W1.
    let (pk, msg, mut sig) = vector("lms_sha256_m32_h5_w1");
    sig[4..8].copy_from_slice(&0x0000_0002u32.to_be_bytes());
    assert_eq!(
        verify_any(&pk, &msg, &sig),
        Err(VerifyAnyError::VerificationFailed)
    );

    // LMS typecode after the LM-OTS signature: LMS_SHA256_M32_H10, not H5.
    let at = 4 + pair::OTS_SIG_LEN;
    let (pk, msg, mut sig) = vector("lms_sha256_m32_h5_w1");
    sig[at..at + 4].copy_from_slice(&0x0000_0006u32.to_be_bytes());
    assert_eq!(
        verify_any(&pk, &msg, &sig),
        Err(VerifyAnyError::VerificationFailed)
    );
}

#[test]
fn length_mismatch_is_unroutable() {
    operational();
    let (pk, msg, sig) = vector("lms_sha256_m32_h10_w4");

    assert_eq!(
        verify_any(&pk, &msg, &sig[..sig.len() - 1]),
        Err(VerifyAnyError::Unroutable)
    );

    let mut long_sig = sig.clone();
    long_sig.push(0);
    assert_eq!(
        verify_any(&pk, &msg, &long_sig),
        Err(VerifyAnyError::Unroutable)
    );

    let mut long_pk = pk.clone();
    long_pk.push(0);
    assert_eq!(
        verify_any(&long_pk, &msg, &sig),
        Err(VerifyAnyError::Unroutable)
    );

    // A signature of another pair, under this pair's key.
    let (_, _, other_sig) = vector("lms_sha256_m32_h5_w4");
    assert_ne!(other_sig.len(), sig.len());
    assert_eq!(
        verify_any(&pk, &msg, &other_sig),
        Err(VerifyAnyError::Unroutable)
    );
}
