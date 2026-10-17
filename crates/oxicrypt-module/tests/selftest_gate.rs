//! The `SelfTest` gate across threads.
//!
//! While the power-up self-tests run, the guarded `*_internal` functions are
//! open only to the thread running them. These tests start an initialisation
//! on one thread and call a real guarded function, `Sha256::new_internal`,
//! and a real approved service, `sha256`, from others.
//!
//! The module state is process-global and each transition is one-way, so
//! every test here runs in a fresh process of its own (see [`isolated`]),
//! under `cargo nextest` and `cargo test` alike.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use oxicrypt_module::{
    Error, KatEntry, SelfTestFailure, State, enter_error_state, initialize_with_tests,
    is_operational, require_operational, require_self_test_started, state,
};
use oxicrypt_sha::sha256::{Sha256, sha256};

/// Set in the child process that runs one test on its own.
const CHILD: &str = "OXICRYPT_SELFTEST_GATE_CHILD";

/// How long any wait in these tests may take before it counts as a hang.
const DEADLINE: Duration = Duration::from_secs(30);

/// How long a child process may take, covering every wait inside it.
const CHILD_DEADLINE: Duration = Duration::from_mins(1);

/// Runs `body` in a process of its own.
///
/// Under a runner that shares one process between tests, the test
/// re-executes this binary for itself alone and checks that exactly that
/// test ran and passed there. A child that has not finished within
/// [`CHILD_DEADLINE`] is killed and the test fails, so a regression that hangs
/// is reported rather than stalling the run.
fn isolated(name: &str, body: impl FnOnce()) {
    if std::env::var_os(CHILD).is_some() {
        body();
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--test-threads=1"])
        .env(CHILD, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > CHILD_DEADLINE {
            child.kill().unwrap();
            panic!("{name} did not finish in its own process within {CHILD_DEADLINE:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{name} did not pass in its own process:\n{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// The guarded `*_internal` function every test probes.
fn internal() -> Result<(), Error> {
    Sha256::new_internal().map(|_| ())
}

/// The approved service every test probes.
fn service() -> Result<(), Error> {
    sha256(b"abc").map(|_| ())
}

/// Set by the paused self-test once it holds the module in `SelfTest`.
static PAUSED: AtomicBool = AtomicBool::new(false);
/// Set by the test to let the paused self-test finish.
static RELEASE: AtomicBool = AtomicBool::new(false);
/// Whether the initialising thread's own `*_internal` call was admitted.
static OWNER_ADMITTED: AtomicBool = AtomicBool::new(false);
/// What the initialising thread's own approved-service call,
/// `require_operational` and `is_operational` returned inside its self-test.
#[allow(clippy::type_complexity, reason = "three probe results in one slot")]
static OWNER_GATED: std::sync::Mutex<Option<(Result<(), Error>, Result<(), Error>, bool)>> =
    std::sync::Mutex::new(None);
/// How many times the counting self-test has run.
static RUNS: AtomicUsize = AtomicUsize::new(0);
/// Whether the paused self-test fails once released.
static FAIL_AFTER_PAUSE: AtomicBool = AtomicBool::new(false);
/// What a re-entrant `initialize` from inside a self-test returned.
static REENTRANT: std::sync::Mutex<Option<Result<(), Error>>> = std::sync::Mutex::new(None);

/// Waits until `flag` is set, failing the test after [`DEADLINE`].
fn wait_for(flag: &AtomicBool, what: &str) {
    let start = Instant::now();
    while !flag.load(Ordering::Acquire) {
        assert!(start.elapsed() < DEADLINE, "timed out waiting for {what}");
        std::thread::yield_now();
    }
}

/// A self-test that calls the guarded function on its own thread, then
/// holds initialisation open until [`RELEASE`] is set.
#[allow(clippy::unnecessary_wraps, reason = "a KatEntry's run signature")]
fn paused_self_test() -> Result<(), SelfTestFailure> {
    OWNER_ADMITTED.store(internal().is_ok(), Ordering::Release);
    *OWNER_GATED.lock().unwrap() = Some((service(), require_operational(), is_operational()));
    PAUSED.store(true, Ordering::Release);
    wait_for(&RELEASE, "the release of the paused self-test");
    if FAIL_AFTER_PAUSE.load(Ordering::Acquire) {
        return Err(SelfTestFailure);
    }
    Ok(())
}

/// A conditional self-test that fires while the power-up tests run: it
/// latches `Error` and then reports success.
#[allow(clippy::unnecessary_wraps, reason = "a KatEntry's run signature")]
fn latches_error_then_passes() -> Result<(), SelfTestFailure> {
    enter_error_state("a conditional self-test fired during initialisation");
    Ok(())
}

/// A self-test that calls `initialize` again on its own thread.
#[allow(clippy::unnecessary_wraps, reason = "a KatEntry's run signature")]
fn reenters_initialize() -> Result<(), SelfTestFailure> {
    let again = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    *REENTRANT.lock().unwrap() = Some(again);
    Ok(())
}

#[allow(clippy::unnecessary_wraps, reason = "a KatEntry's run signature")]
fn counting_self_test() -> Result<(), SelfTestFailure> {
    RUNS.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

fn failing_self_test() -> Result<(), SelfTestFailure> {
    Err(SelfTestFailure)
}

fn unwinding_self_test() -> Result<(), SelfTestFailure> {
    panic!("a self-test that unwinds");
}

fn refused_in(expected: State) -> Result<(), Error> {
    Err(Error::NotOperational { current: expected })
}

#[test]
fn selftest_gate_refuses_worker_while_initialisation_is_paused() {
    isolated(
        "selftest_gate_refuses_worker_while_initialisation_is_paused",
        || {
            let tests = [KatEntry {
                name: "pauses inside SelfTest",
                run: paused_self_test,
            }];
            let initialiser =
                std::thread::spawn(move || initialize_with_tests(UNSIGNED_TEST_BINARY, &tests));
            wait_for(&PAUSED, "the initialiser to pause");

            // The initialiser is parked inside its self-tests. Its own
            // `*_internal` call was admitted, but its approved-service call
            // and the operational gate refused it; this thread's calls are
            // all refused.
            assert!(OWNER_ADMITTED.load(Ordering::Acquire));
            assert_eq!(
                *OWNER_GATED.lock().unwrap(),
                Some((
                    refused_in(State::SelfTest),
                    refused_in(State::SelfTest),
                    false
                ))
            );
            assert_eq!(state(), State::SelfTest);
            assert_eq!(internal(), refused_in(State::SelfTest));
            assert_eq!(require_self_test_started(), refused_in(State::SelfTest));
            assert_eq!(service(), refused_in(State::SelfTest));

            RELEASE.store(true, Ordering::Release);
            assert_eq!(initialiser.join().unwrap(), Ok(()));
            assert_eq!(state(), State::Operational);
            assert_eq!(internal(), Ok(()));
            assert_eq!(service(), Ok(()));
        },
    );
}

#[test]
fn concurrent_initialize_has_one_winner() {
    isolated("concurrent_initialize_has_one_winner", || {
        const CALLERS: usize = 8;
        let start = Arc::new(Barrier::new(CALLERS));
        let callers: Vec<_> = (0..CALLERS)
            .map(|_| {
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    let tests = [KatEntry {
                        name: "counts its runs",
                        run: counting_self_test,
                    }];
                    start.wait();
                    initialize_with_tests(UNSIGNED_TEST_BINARY, &tests)
                })
            })
            .collect();
        let results: Vec<_> = callers.into_iter().map(|c| c.join().unwrap()).collect();

        assert_eq!(results.len(), CALLERS);
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(Error::AlreadyInitialized))
                .count(),
            CALLERS - 1
        );
        assert_eq!(RUNS.load(Ordering::Acquire), 1);
        assert_eq!(state(), State::Operational);
    });
}

#[test]
fn failed_init_is_terminal() {
    isolated("failed_init_is_terminal", || {
        let failing = [KatEntry {
            name: "fails",
            run: failing_self_test,
        }];
        assert_eq!(
            initialize_with_tests(UNSIGNED_TEST_BINARY, &failing),
            Err(Error::SelfTestFailed { test: "fails" })
        );
        assert_eq!(state(), State::Error);

        // No later call resets the state or re-runs a test, from this thread
        // or another.
        let counting = [KatEntry {
            name: "counts its runs",
            run: counting_self_test,
        }];
        assert_eq!(
            initialize_with_tests(UNSIGNED_TEST_BINARY, &counting),
            Err(Error::AlreadyFailed)
        );
        let other = std::thread::spawn(move || {
            let counting = [KatEntry {
                name: "counts its runs",
                run: counting_self_test,
            }];
            initialize_with_tests(UNSIGNED_TEST_BINARY, &counting)
        });
        assert_eq!(other.join().unwrap(), Err(Error::AlreadyFailed));
        assert_eq!(RUNS.load(Ordering::Acquire), 0);
        assert_eq!(state(), State::Error);
        assert_eq!(internal(), refused_in(State::Error));
    });
}

#[test]
fn unwinding_kat_lands_in_error() {
    isolated("unwinding_kat_lands_in_error", || {
        let unwinding = [KatEntry {
            name: "unwinds",
            run: unwinding_self_test,
        }];
        let outcome =
            std::panic::catch_unwind(|| initialize_with_tests(UNSIGNED_TEST_BINARY, &unwinding));
        assert!(outcome.is_err(), "the self-test did not unwind");

        // This thread is the one whose initialisation unwound, so it carries
        // the thread id that owned `SelfTest`. It is refused all the same.
        assert_eq!(state(), State::Error);
        assert_eq!(internal(), refused_in(State::Error));
        assert_eq!(
            std::thread::spawn(internal).join().unwrap(),
            refused_in(State::Error)
        );
        assert_eq!(
            initialize_with_tests(UNSIGNED_TEST_BINARY, &[]),
            Err(Error::AlreadyFailed)
        );
    });
}

#[test]
fn worker_thread_service_passes_after_init() {
    isolated("worker_thread_service_passes_after_init", || {
        assert_eq!(initialize_with_tests(UNSIGNED_TEST_BINARY, &[]), Ok(()));
        let worker = std::thread::spawn(|| (internal(), service()));
        assert_eq!(worker.join().unwrap(), (Ok(()), Ok(())));
    });
}

/// A success never overwrites an `Error` latched while the tests ran.
#[test]
fn an_error_latched_during_the_self_tests_survives_their_success() {
    isolated(
        "an_error_latched_during_the_self_tests_survives_their_success",
        || {
            let tests = [KatEntry {
                name: "latches Error and passes",
                run: latches_error_then_passes,
            }];
            assert_eq!(
                initialize_with_tests(UNSIGNED_TEST_BINARY, &tests),
                refused_in(State::Error)
            );
            assert_eq!(state(), State::Error);
            assert_eq!(internal(), refused_in(State::Error));
            assert_eq!(service(), refused_in(State::Error));
        },
    );
}

/// A call that loses to a winner whose self-tests then fail waits for that
/// outcome and reports `AlreadyFailed`.
#[test]
fn a_loser_of_a_failing_winner_gets_already_failed() {
    isolated("a_loser_of_a_failing_winner_gets_already_failed", || {
        FAIL_AFTER_PAUSE.store(true, Ordering::Release);
        let tests = [KatEntry {
            name: "pauses, then fails",
            run: paused_self_test,
        }];
        let winner =
            std::thread::spawn(move || initialize_with_tests(UNSIGNED_TEST_BINARY, &tests));
        wait_for(&PAUSED, "the winner to pause");
        assert_eq!(state(), State::SelfTest);

        let loser_started = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&loser_started);
        let loser = std::thread::spawn(move || {
            flag.store(true, Ordering::Release);
            initialize_with_tests(UNSIGNED_TEST_BINARY, &[])
        });
        wait_for(&loser_started, "the loser to start");
        // That the loser reaches the wait, rather than returning before it,
        // is observed by the crate's unit test
        // `loser_waits_then_gets_already_failed`; here the outcome is checked
        // end to end through the public interface.

        RELEASE.store(true, Ordering::Release);
        assert_eq!(
            winner.join().unwrap(),
            Err(Error::SelfTestFailed {
                test: "pauses, then fails"
            })
        );
        assert_eq!(loser.join().unwrap(), Err(Error::AlreadyFailed));
        assert_eq!(state(), State::Error);
    });
}

/// `initialize` called from inside a self-test, on the thread running them,
/// returns at once with `NotOperational` naming `SelfTest`, and the outer
/// initialisation completes.
#[test]
fn a_reentrant_initialize_on_the_owner_returns_without_waiting() {
    isolated(
        "a_reentrant_initialize_on_the_owner_returns_without_waiting",
        || {
            let tests = [KatEntry {
                name: "re-enters initialize",
                run: reenters_initialize,
            }];
            assert_eq!(initialize_with_tests(UNSIGNED_TEST_BINARY, &tests), Ok(()));
            assert_eq!(
                *REENTRANT.lock().unwrap(),
                Some(refused_in(State::SelfTest))
            );
            assert_eq!(state(), State::Operational);
        },
    );
}
