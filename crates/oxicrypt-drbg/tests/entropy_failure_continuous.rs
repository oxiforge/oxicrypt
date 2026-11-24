//! A continuous health-test failure of the jitter pipeline is a module
//! failure: the failing reseed returns `EntropyUnavailable` and the
//! module enters its error state. Afterwards every service returns
//! `NotOperational`, including `generate` on an instance instantiated
//! before the failure and a `generate` that was mid-operation on another
//! thread. The module state is process-global and its error state is
//! terminal, so this test runs in a process of its own.
//!
//! The jitter source reads the raw CPU counter, which exists only on the
//! architectures this file is compiled for.

#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#![allow(clippy::unwrap_used, reason = "test assertions panic by design")]

use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use oxicrypt_drbg::seam::{self, FaultClass};
use oxicrypt_drbg::{DrbgError, HmacDrbgSha256};
use oxicrypt_module::{Error, KatEntry, RbgError, initialize_with_tests, is_operational};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// A deterministic draw, so instances exist before the failure without
/// constructing the seed path.
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

/// Starts a `generate` on `instance` on another thread and waits until it
/// is parked before writing its output.
fn park_generate(mut instance: HmacDrbgSha256) -> JoinHandle<(Result<(), DrbgError>, [u8; 32])> {
    let handle = thread::spawn(move || {
        seam::park_before_output(true);
        let mut buf = [0xA5_u8; 32];
        let result = instance.generate(None, &mut buf);
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
    handle
}

#[test]
fn entropy_failure_continuous_enters_error_state() {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());
    seam::clear_all();
    seam::set_get_entropy(fixed_draw);
    let mut earlier = HmacDrbgSha256::instantiate_from_module(b"").unwrap();
    let parked = HmacDrbgSha256::instantiate_from_module(b"").unwrap();
    seam::clear_get_entropy();

    seam::force_assessed_path();
    let mut seeded = HmacDrbgSha256::instantiate_from_module(b"").unwrap();
    seam::fail_next(FaultClass::ContinuousHealth);
    let mid_operation = park_generate(parked);
    let failed = seeded.reseed_from_module(&[]).err();
    seam::release_parked();
    let (mid_result, mid_out) = mid_operation.join().unwrap();

    assert_eq!(failed, Some(Error::Rbg(RbgError::EntropyUnavailable)));
    assert!(
        matches!(
            mid_result,
            Err(DrbgError::Module(Error::NotOperational { .. }))
        ),
        "{mid_result:?}"
    );
    assert_eq!(mid_out, [0_u8; 32]);
    assert!(!is_operational());

    let mut out = [0xA5_u8; 32];
    let later = earlier.generate(None, &mut out);
    assert!(
        matches!(later, Err(DrbgError::Module(Error::NotOperational { .. }))),
        "{later:?}"
    );
    assert_eq!(out, [0_u8; 32]);
    let again = HmacDrbgSha256::instantiate_from_module(b"").err();
    assert!(
        matches!(again, Some(Error::NotOperational { .. })),
        "{again:?}"
    );
}
