//! `oxicrypt_lms::verify_any` under the CNSA 1.0 profile, which permits no
//! LMS service: a routable key reaches the named pair's gate and is refused
//! as restricted, while an unroutable key is still refused as unroutable.
//!
//! Kept in its own test binary because the profile is process-global.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use oxicrypt_lms::{VerifyAnyError, verify_any};
use oxicrypt_module::{AlgorithmProfile, Error, KatEntry, Service, initialize_with_profile};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn routable_key_under_cnsa1_is_algorithm_restricted() {
    match initialize_with_profile(
        UNSIGNED_TEST_BINARY,
        oxicrypt_lms::KATS,
        AlgorithmProfile::Cnsa1,
    ) {
        Ok(()) | Err(Error::AlreadyInitialized) => {}
        Err(e) => panic!("module failed to initialise: {e:?}"),
    }
    assert!(oxicrypt_module::is_operational());
    assert_eq!(oxicrypt_module::active_profile(), AlgorithmProfile::Cnsa1);

    let mut pk = load("lms_sha256_m32_h5_w1_sigver_pk.bin");
    let msg = load("lms_sha256_m32_h5_w1_sigver_msg.bin");
    let sig = load("lms_sha256_m32_h5_w1_sigver_sig.bin");

    let restricted = verify_any(&pk, &msg, &sig);
    assert_eq!(
        restricted,
        Err(VerifyAnyError::Module(Error::AlgorithmRestricted {
            service: Service::LmsSha256M32H5W1Verify
        }))
    );
    assert_ne!(restricted, Err(VerifyAnyError::Unroutable));
    assert_ne!(restricted, Err(VerifyAnyError::VerificationFailed));

    // LMOTS_SHA256_N24_W1 under LMS_SHA256_M32_H5: no such pair.
    pk[4..8].copy_from_slice(&0x0000_0005u32.to_be_bytes());
    assert_eq!(verify_any(&pk, &msg, &sig), Err(VerifyAnyError::Unroutable));
}
