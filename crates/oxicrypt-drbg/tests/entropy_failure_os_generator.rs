//! An operating-system generator failure on the seed path is a module
//! failure. The module state is process-global and its error state is
//! terminal, so this test runs in a process of its own.

use oxicrypt_drbg::seam::{self, FaultClass};
use oxicrypt_module::{KatEntry, RbgError, initialize_with_tests, is_operational};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

#[test]
fn entropy_failure_enters_error_state() {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());
    seam::clear_all();
    seam::force_operating_system_path();
    seam::fail_next(FaultClass::OsGenerator);
    let mut out = [0xA5_u8; 32];
    assert_eq!(seam::draw(&mut out), Err(RbgError::EntropyUnavailable));
    assert_eq!(out, [0_u8; 32]);
    assert!(!is_operational());
}
