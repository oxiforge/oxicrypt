//! `oxicrypt_lms::verify_any` in a process that never initialises the
//! module: a routed pair reaches its gate and reports the gate's error,
//! and an unroutable key is refused without reaching any gate.
//!
//! Kept in its own test binary so that no other test can initialise the
//! module first.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use oxicrypt_lms::{VerifyAnyError, verify_any};
use oxicrypt_module::Error;

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn gate_error_passes_through_and_routing_precedes_the_gate() {
    assert!(!oxicrypt_module::is_operational());
    let mut pk = load("lms_sha256_m32_h5_w1_sigver_pk.bin");
    let msg = load("lms_sha256_m32_h5_w1_sigver_msg.bin");
    let sig = load("lms_sha256_m32_h5_w1_sigver_sig.bin");

    assert!(matches!(
        verify_any(&pk, &msg, &sig),
        Err(VerifyAnyError::Module(Error::NotOperational { .. }))
    ));

    // LMOTS_SHA256_N24_W1 under LMS_SHA256_M32_H5: no such pair.
    pk[4..8].copy_from_slice(&0x0000_0005u32.to_be_bytes());
    assert_eq!(verify_any(&pk, &msg, &sig), Err(VerifyAnyError::Unroutable));
}
