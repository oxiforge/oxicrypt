//! A module failure while a CTR_DRBG `generate_df` is between its entry
//! check and its output re-check withholds the output: the generate returns
//! `NotOperational` and the caller's buffer is zeroized. The module state
//! is process-global and its error state is terminal, so this test runs in
//! a process of its own.

#![allow(clippy::unwrap_used, reason = "test assertions panic by design")]

use std::thread;
use std::time::{Duration, Instant};

use oxicrypt_drbg::seam::{self, FaultClass};
use oxicrypt_drbg::{CtrDrbgAes256, DrbgError};
use oxicrypt_module::{Error, KatEntry, RbgError, initialize_with_tests, is_operational};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// A deterministic draw, so the instance exists without constructing the
/// seed path.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the signature is the seam's draw type"
)]
fn fixed_draw(out: &mut [u8]) -> Result<(), RbgError> {
    for (byte, i) in out.iter_mut().zip((0..=u8::MAX).cycle()) {
        *byte = 0x5A ^ i;
    }
    Ok(())
}

#[test]
fn output_recheck_withholds_output_after_failure() {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());
    seam::clear_all();
    seam::set_get_entropy(fixed_draw);
    let mut instance = CtrDrbgAes256::instantiate_from_module(b"").unwrap();
    seam::clear_get_entropy();
    // Control: before the failure, the same generate writes output.
    let mut before = [0xA5_u8; 32];
    instance.generate_df(None, &mut before).unwrap();
    assert_ne!(before, [0xA5_u8; 32]);
    assert_ne!(before, [0_u8; 32]);

    let parked = thread::spawn(move || {
        seam::park_before_output(true);
        let mut buf = [0xA5_u8; 32];
        let result = instance.generate_df(None, &mut buf);
        (result, buf)
    });
    let start = Instant::now();
    while !seam::is_parked() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the generate never parked"
        );
        thread::yield_now();
    }
    seam::force_operating_system_path();
    seam::fail_next(FaultClass::OsGenerator);
    let mut drawn = [0_u8; 32];
    assert_eq!(seam::draw(&mut drawn), Err(RbgError::EntropyUnavailable));
    assert!(!is_operational());
    seam::release_parked();
    let (result, out) = parked.join().unwrap();

    assert!(
        matches!(result, Err(DrbgError::Module(Error::NotOperational { .. }))),
        "{result:?}"
    );
    assert_eq!(out, [0_u8; 32]);
}
