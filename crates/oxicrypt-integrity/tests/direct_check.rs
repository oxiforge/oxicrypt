//! `verify_loaded_image` runs only inside the power-up self-tests. A call
//! before them, or once the module is operational, runs nothing, leaves the
//! state as it was and records nothing for `status()`: the module tests
//! itself on demand by restarting.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use oxicrypt_integrity::{IntegrityError, IntegrityStatus, status, verify_loaded_image};
use oxicrypt_module::{Error, State, state};

/// Set in the child process that runs one test on its own.
const CHILD: &str = "OXICRYPT_STATE_GUARD_CHILD";
/// Names the one case a child process runs, for a test with several.
const CASE: &str = "OXICRYPT_STATE_GUARD_CASE";

/// The entry of `oxicrypt_integrity::KATS` named `name`.
fn entry(name: &str) -> oxicrypt_module::KatEntry {
    *oxicrypt_integrity::KATS
        .iter()
        .find(|k| k.name == name)
        .unwrap_or_else(|| panic!("no {name} in the integrity group"))
}

/// Runs `body` in a process of its own.
///
/// The module state is process-global and each transition is one-way, so
/// each state needs a fresh process. Under a runner that shares one process
/// between tests, the test re-executes this binary for itself alone and
/// checks that exactly that test ran and passed there.
fn isolated(name: &str, body: impl FnOnce()) {
    isolated_case(name, "", body);
}

/// [`isolated`] for one of several cases of a test: the child runs `body`
/// only for the case it was started for.
fn isolated_case(name: &str, case: &str, body: impl FnOnce()) {
    if std::env::var_os(CHILD).is_some() {
        if std::env::var(CASE).unwrap_or_default() == case {
            body();
        }
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--test-threads=1"])
        .env(CHILD, "1")
        .env(CASE, case)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // A child that hangs is killed and fails the test rather than stalling
    // the run.
    let start = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > std::time::Duration::from_mins(1) {
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

#[test]
fn a_direct_call_before_the_self_tests_is_refused_and_changes_nothing() {
    isolated(
        "a_direct_call_before_the_self_tests_is_refused_and_changes_nothing",
        || {
            assert_eq!(state(), State::PowerOff);
            assert!(matches!(
                verify_loaded_image(),
                Err(IntegrityError::Module(Error::NotOperational {
                    current: State::PowerOff
                }))
            ));
            assert_eq!(state(), State::PowerOff);
            assert_eq!(status(), IntegrityStatus::NotRun);
        },
    );
}

/// On-demand testing is a restart: once the module is operational, a
/// direct call is refused, runs nothing and leaves the services available.
#[test]
fn a_direct_call_once_operational_is_refused_and_changes_nothing() {
    isolated(
        "a_direct_call_once_operational_is_refused_and_changes_nothing",
        || {
            use oxicrypt_module::{KatEntry, initialize_with_tests};
            let stand_in = [KatEntry {
                name: "integrity not verifiable in an unsigned test binary",
                run: || Ok(()),
            }];
            initialize_with_tests(&stand_in, &[]).unwrap();
            assert_eq!(state(), State::Operational);
            assert!(matches!(
                verify_loaded_image(),
                Err(IntegrityError::Module(Error::AlreadyInitialized))
            ));
            assert_eq!(state(), State::Operational);
            assert_eq!(status(), IntegrityStatus::NotRun);
        },
    );
}

/// A failed CAST stops the boot before the integrity test, latches `Error`,
/// and records no integrity outcome: the test was not performed.
#[test]
fn a_failed_cast_latches_error_before_the_integrity_test() {
    isolated(
        "a_failed_cast_latches_error_before_the_integrity_test",
        || {
            use oxicrypt_module::{KatEntry, initialize_with_tests};
            let failing = [
                KatEntry {
                    name: oxicrypt_integrity::ML_DSA_CAST_NAME,
                    run: || Err(oxicrypt_module::SelfTestFailure),
                },
                entry(oxicrypt_integrity::SHA256_CAST_NAME),
                entry(oxicrypt_integrity::INTEGRITY_TEST_NAME),
            ];
            assert!(matches!(
                initialize_with_tests(&failing, &[]),
                Err(Error::SelfTestFailed { .. })
            ));
            assert_eq!(state(), State::Error);
            assert_eq!(status(), IntegrityStatus::NotRun);
            assert_eq!(oxicrypt_integrity::status_detail(), None);
        },
    );
}

/// The integrity test refuses with `CastNotRun` when either CAST of its
/// group is skipped, and records that as its outcome.
#[test]
fn skipping_either_cast_makes_the_integrity_test_refuse() {
    for case in ["sha256", "ml-dsa", "both"] {
        isolated_case(
            "skipping_either_cast_makes_the_integrity_test_refuse",
            case,
            || {
                use oxicrypt_module::initialize_with_tests;
                let case = std::env::var(CASE).unwrap();
                let ml_dsa = entry(oxicrypt_integrity::ML_DSA_CAST_NAME);
                let sha256 = entry(oxicrypt_integrity::SHA256_CAST_NAME);
                let test = entry(oxicrypt_integrity::INTEGRITY_TEST_NAME);
                let group: Vec<_> = match case.as_str() {
                    // The SHA-256 CAST skipped.
                    "sha256" => vec![ml_dsa, test],
                    // The ML-DSA-87 CAST skipped.
                    "ml-dsa" => vec![sha256, test],
                    // Control: both CASTs ran, so the test runs and fails on
                    // this unsigned binary rather than refusing.
                    _ => vec![ml_dsa, sha256, test],
                };
                assert!(initialize_with_tests(&group, &[]).is_err());
                assert_eq!(state(), State::Error);
                if case == "both" {
                    // The test ran, so it reports what this build embeds:
                    // no key, or a key and the unsigned template's slot.
                    let keyed = option_env!("OXICRYPT_INTEGRITY_VERIFY_KEY").is_some()
                        || option_env!("OXICRYPT_INTEGRITY_VERIFY_KEY_HEX").is_some();
                    let want = if keyed {
                        IntegrityStatus::SlotInvalid
                    } else {
                        IntegrityStatus::NoVerifyKey
                    };
                    assert_eq!(status(), want, "keyed build: {keyed}");
                } else {
                    assert_eq!(status(), IntegrityStatus::CastNotRun, "case {case}");
                }
            },
        );
    }
}

/// A CAST call the module refuses, before initialisation, runs nothing and
/// changes nothing: the module still starts.
#[test]
fn a_refused_cast_before_initialisation_changes_nothing() {
    isolated(
        "a_refused_cast_before_initialisation_changes_nothing",
        || {
            use oxicrypt_module::{KatEntry, initialize_with_tests};
            assert!(oxicrypt_integrity::ml_dsa_cast().is_err());
            assert_eq!(state(), State::PowerOff);
            let cast = [KatEntry {
                name: oxicrypt_integrity::ML_DSA_CAST_NAME,
                run: oxicrypt_integrity::ml_dsa_cast,
            }];
            initialize_with_tests(&cast, &[]).unwrap();
            assert_eq!(state(), State::Operational);
        },
    );
}

/// Set once the owner's self-test holds the module in `SelfTest`.
static PAUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set to let the owner's self-test finish.
static RELEASE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Waits for `flag`, failing the test after 30 seconds.
fn wait_for(flag: &std::sync::atomic::AtomicBool, what: &str) {
    let start = std::time::Instant::now();
    while !flag.load(std::sync::atomic::Ordering::Acquire) {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "timed out waiting for {what}"
        );
        std::thread::yield_now();
    }
}

#[allow(clippy::unnecessary_wraps, reason = "a KatEntry's run signature")]
fn paused_self_test() -> Result<(), oxicrypt_module::SelfTestFailure> {
    PAUSED.store(true, std::sync::atomic::Ordering::Release);
    wait_for(&RELEASE, "the release of the paused self-test");
    Ok(())
}

/// A CAST call from another thread while the self-tests run is refused,
/// runs nothing and changes nothing: the owner's start still succeeds.
#[test]
fn a_cast_from_another_thread_during_the_self_tests_changes_nothing() {
    isolated(
        "a_cast_from_another_thread_during_the_self_tests_changes_nothing",
        || {
            use oxicrypt_module::{KatEntry, initialize_with_tests};
            let owner = std::thread::spawn(|| {
                let cast = [KatEntry {
                    name: oxicrypt_integrity::ML_DSA_CAST_NAME,
                    run: oxicrypt_integrity::ml_dsa_cast,
                }];
                let pause = [KatEntry {
                    name: "pauses inside SelfTest",
                    run: paused_self_test,
                }];
                initialize_with_tests(&cast, &pause)
            });
            wait_for(&PAUSED, "the owner to pause");
            assert_eq!(state(), State::SelfTest);
            assert!(oxicrypt_integrity::ml_dsa_cast().is_err());
            assert_eq!(state(), State::SelfTest);
            RELEASE.store(true, std::sync::atomic::Ordering::Release);
            assert_eq!(owner.join().unwrap(), Ok(()));
            assert_eq!(state(), State::Operational);
        },
    );
}
