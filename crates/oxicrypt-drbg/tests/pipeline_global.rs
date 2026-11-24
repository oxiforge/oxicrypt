//! The seed state is built once per process, on first use. Concurrent
//! first uses construct it once, a held cell makes other draws return
//! `Busy` after the spin bound, and a forked child whose parent held the
//! cell rebuilds its own. The seed state and the module state are
//! process-global, so this test runs in a process of its own.
//!
//! The assessed path's jitter source reads the raw CPU counter, which
//! exists only on the architectures this file is compiled for.

#![cfg(all(unix, any(target_arch = "x86_64", target_arch = "aarch64")))]
#![allow(clippy::unwrap_used, reason = "test assertions panic by design")]

use std::sync::{Arc, Barrier};
use std::thread;

use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_drbg::seam;
use oxicrypt_module::{Error, KatEntry, RbgError, initialize_with_tests, is_operational};
use oxicrypt_platform::testing::{ForkResult, fork_for_test, wait_for_child};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// The number of threads that instantiate at once.
const RACERS: usize = 16;

/// The seed-path label of the assessed path under the first assessed row.
const ASSESSED_LABEL: &str = "jitter source, assessed row OE-1";

/// The seed-path label when the forced row's timer fails the adequacy
/// check on the running machine.
const TIMER_INADEQUATE_LABEL: &str = "operating-system generator (untested operational environment, IG 9.3.A AC2); timer adequacy not met";

#[test]
#[allow(clippy::print_stderr, reason = "a skipped run reports why")]
fn seed_state_is_built_once_and_survives_fork() {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());
    seam::clear_all();
    seam::force_assessed_path();

    // Concurrent first uses: one builds the state, the rest are served by
    // it or give up with `Busy` while it is being built.
    let start = Arc::new(Barrier::new(RACERS));
    let racers: Vec<_> = (0..RACERS)
        .map(|_| {
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                HmacDrbgSha256::instantiate_from_module(b"").err()
            })
        })
        .collect();
    let results: Vec<Option<Error>> = racers.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.len(), RACERS);
    assert!(
        results
            .iter()
            .all(|r| r.is_none() || *r == Some(Error::Rbg(RbgError::Busy))),
        "{results:?}"
    );
    assert!(results.iter().any(Option::is_none), "{results:?}");
    assert_eq!(seam::construction_count(), 1);
    assert!(is_operational());

    // The forced row still runs the timer-adequacy check, and a timer that
    // fails it moves the path to the operating system's generator. The
    // rest of this test covers the assessed path only.
    let label = oxicrypt_drbg::seed_path_label();
    if label == TIMER_INADEQUATE_LABEL {
        // A run that must cover the assessed path sets this variable, and
        // a skip there is a failure.
        assert!(
            std::env::var("OXI_REQUIRE_ASSESSED_PATH").as_deref() != Ok("1"),
            "OXI_REQUIRE_ASSESSED_PATH=1, but the timer failed the adequacy check; \
             seed-path label: {label}"
        );
        eprintln!(
            "skipped: this machine's timer failed the adequacy check, so the assessed path \
             cannot be built; seed-path label: {label}"
        );
        return;
    }
    assert_eq!(label, ASSESSED_LABEL);

    // A held cell: another thread's draw spins out and returns `Busy`.
    let held = seam::hold_seed_cell();
    let blocked = thread::spawn(|| HmacDrbgSha256::instantiate_from_module(b"").err())
        .join()
        .unwrap();
    assert_eq!(blocked, Some(Error::Rbg(RbgError::Busy)));

    // Fork while the cell is held. The guard lives on this thread, which
    // the child does not run, so the child never releases it; the child's
    // first draw must rebuild the cell instead. A panic in the child does
    // not reach this process, so the child reports through its exit code.
    let child = thread::spawn(|| match fork_for_test() {
        ForkResult::Child => {
            let served = HmacDrbgSha256::instantiate_from_module(b"").is_ok();
            let rebuilt = seam::construction_count() == 2;
            std::process::exit(i32::from(!(served && rebuilt)));
        }
        ForkResult::Parent { child } => child,
    })
    .join()
    .unwrap();
    drop(held);
    assert!(child > 0, "fork failed");
    assert_eq!(wait_for_child(child), 0);

    // The parent's state is unchanged and serves again once released.
    assert!(HmacDrbgSha256::instantiate_from_module(b"").is_ok());
    assert_eq!(seam::construction_count(), 1);
}
