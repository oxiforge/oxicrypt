//! A failure of the second seed draw of a module-seeded instantiate is a
//! module failure, and no instance is created. The module state is
//! process-global and its error state is terminal, so this test runs in a
//! process of its own.

use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_drbg::seam::{self, FaultClass};
use oxicrypt_module::{Error, KatEntry, RbgError, initialize_with_tests, is_operational};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

#[test]
fn second_draw_failure_leaves_nothing() {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());
    seam::clear_all();
    seam::force_operating_system_path();
    seam::fail_next(FaultClass::SecondDraw);
    let result = HmacDrbgSha256::instantiate_from_module(b"");
    assert_eq!(result.err(), Some(Error::Rbg(RbgError::EntropyUnavailable)));
    assert!(!is_operational());
    assert_eq!(seam::draw_count(), 2);
}
