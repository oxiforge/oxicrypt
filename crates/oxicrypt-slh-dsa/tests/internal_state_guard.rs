//! A representative `*_internal` function of `oxicrypt-slh-dsa` refuses in every
//! module state other than `SelfTest` and `Operational`.
//!
//! The module state is process-global and each transition is one-way, so
//! every test here runs in a fresh process of its own (see [`isolated`]),
//! under `cargo nextest` and `cargo test` alike.

#![allow(clippy::unwrap_used, clippy::panic)]

use oxicrypt_module::{Error, KatEntry, SelfTestFailure, State, initialize_with_tests, state};

/// Set in the child process that runs one test on its own.
const CHILD: &str = "OXICRYPT_STATE_GUARD_CHILD";

/// Runs `body` in a process of its own.
///
/// The module state is process-global and each transition is one-way, so
/// each state needs a fresh process. Under a runner that shares one process
/// between tests, the test re-executes this binary for itself alone and
/// checks that exactly that test ran and passed there.
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
    // A child that hangs is killed and fails the test rather than stalling
    // the run.
    let start = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > std::time::Duration::from_mins(5) {
            child.kill().unwrap();
            panic!("{name} did not finish in its own process");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
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

/// Calls a representative `*_internal` function. Any outcome other than a
/// refusal, including the primitive rejecting its input, means the guard
/// admitted the call.
fn probe() -> Result<(), Error> {
    match oxicrypt_slh_dsa::slh_dsa_sha2_128f::keygen_internal(&[0u8; 48]) {
        Err(e @ Error::NotOperational { .. }) => Err(e),
        _ => Ok(()),
    }
}

fn assert_refused(expected: State) {
    assert_eq!(state(), expected);
    assert_eq!(probe(), Err(Error::NotOperational { current: expected }));
}

#[test]
fn internal_refuses_in_power_off() {
    isolated("internal_refuses_in_power_off", || {
        assert_refused(State::PowerOff);
    });
}

#[test]
fn internal_refuses_in_error_after_failed_init() {
    isolated("internal_refuses_in_error_after_failed_init", || {
        let failing = [KatEntry {
            name: "failing self-test",
            run: || Err(SelfTestFailure),
        }];
        assert!(initialize_with_tests(UNSIGNED_TEST_BINARY, &failing).is_err());
        assert_refused(State::Error);
    });
}

#[test]
fn internal_refuses_in_integrity_unverified() {
    isolated("internal_refuses_in_integrity_unverified", || {
        assert_eq!(
            initialize_with_tests(&[], &[]),
            Err(Error::IntegrityNotAttested)
        );
        assert_refused(State::IntegrityUnverified);
    });
}

/// The power-up self-tests reach the internals in `SelfTest`: the probe
/// passes there, and so does every CAST in the crate's inventory.
#[test]
fn internal_admits_self_test_and_casts_run() {
    isolated("internal_admits_self_test_and_casts_run", || {
        let probe_in_self_test = [KatEntry {
            name: "internal admits SelfTest",
            run: || {
                if state() != State::SelfTest {
                    return Err(SelfTestFailure);
                }
                probe().map_err(|_| SelfTestFailure)
            },
        }];
        let mut inventory = probe_in_self_test.to_vec();
        inventory.extend_from_slice(oxicrypt_slh_dsa::KATS);
        initialize_with_tests(UNSIGNED_TEST_BINARY, &inventory).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(state(), State::Operational);
    });
}
