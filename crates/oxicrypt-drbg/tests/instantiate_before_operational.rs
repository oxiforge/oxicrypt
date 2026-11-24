//! A module-seeded instantiate of each DRBG family before the module is
//! operational is refused with `NotOperational` before the seed path is
//! decided or drawn from.
//! The module state is process-global, so this test runs in a process of
//! its own.

use oxicrypt_drbg::seam;
use oxicrypt_drbg::{CtrDrbgAes256, HashDrbgSha256, HmacDrbgSha256};
use oxicrypt_module::{Error, KatEntry, initialize_with_tests, is_operational};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

#[test]
fn instantiate_before_operational_touches_no_source() {
    seam::clear_all();
    let refusals = [
        ("HMAC", HmacDrbgSha256::instantiate_from_module(b"").err()),
        ("Hash", HashDrbgSha256::instantiate_from_module(b"").err()),
        ("CTR", CtrDrbgAes256::instantiate_from_module(b"").err()),
    ];
    for (family, refused) in refusals {
        assert!(
            matches!(refused, Some(Error::NotOperational { .. })),
            "{family}: {refused:?}"
        );
    }
    assert_eq!(seam::construction_count(), 0);
    assert_eq!(seam::draw_count(), 0);
    assert!(!is_operational());

    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());
    seam::force_operating_system_path();
    assert!(HmacDrbgSha256::instantiate_from_module(b"").is_ok());
    assert!(HashDrbgSha256::instantiate_from_module(b"").is_ok());
    assert!(CtrDrbgAes256::instantiate_from_module(b"").is_ok());
}
