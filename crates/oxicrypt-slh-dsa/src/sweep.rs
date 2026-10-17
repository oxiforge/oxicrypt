//! The pool a parallel sweep runs in.

use std::sync::OnceLock;

use oxicrypt_module::Error;
use rayon::ThreadPool;

/// A pool used only before the module is operational, that is, by the
/// power-up self-tests.
///
/// Its threads run nothing but this crate's sweeps. None of them can be a
/// thread blocked in `initialize` waiting for the self-tests to finish, so
/// the self-tests' sweeps always have threads to run on. Rayon's global
/// pool gives no such guarantee: if every global worker called
/// `initialize` while another thread ran the self-tests, a sweep queued
/// there would never start and the process would deadlock.
static SELF_TEST_POOL: OnceLock<Option<ThreadPool>> = OnceLock::new();

/// The name each [`SELF_TEST_POOL`] thread carries, followed by its index.
pub(crate) const THREAD_PREFIX: &str = "oxicrypt-slh-dsa-self-test-";

/// Runs `op`, a parallel sweep: in rayon's global pool once the module is
/// operational, and in [`SELF_TEST_POOL`] before then.
///
/// # Errors
///
/// `NotOperational`, naming the observed state, when the self-test pool
/// cannot be built. The self-test that ran the sweep then fails.
pub(crate) fn run<R: Send>(op: impl FnOnce() -> R + Send) -> Result<R, Error> {
    if oxicrypt_module::is_operational() {
        return Ok(op());
    }
    SELF_TEST_POOL
        .get_or_init(|| {
            rayon::ThreadPoolBuilder::new()
                .thread_name(|i| std::format!("{THREAD_PREFIX}{i}"))
                .build()
                .ok()
        })
        .as_ref()
        .map(|pool| pool.install(op))
        .ok_or_else(|| Error::NotOperational {
            current: oxicrypt_module::state(),
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use std::vec::Vec;

    use oxicrypt_module::{KatEntry, SelfTestFailure, State, initialize_with_tests, state};
    use oxicrypt_sha::sha256::Sha256;
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    /// Set in the child process that runs one test on its own.
    const CHILD: &str = "OXICRYPT_SLH_DSA_SWEEP_CHILD";

    /// Runs `body` in a process of its own, killed after a minute, and
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
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_mins(1) {
                child.kill().unwrap();
                panic!("{name} did not finish in its own process");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = child.wait_with_output().unwrap();
        let stdout = std::string::String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{name} did not pass in its own process:\n{stdout}{}",
            std::string::String::from_utf8_lossy(&out.stderr)
        );
    }

    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// For each sweep worker: whether it ran on a thread of the crate's
    /// self-test pool, and whether a self-guarding constructor admitted it.
    static WORKERS: Mutex<Vec<(bool, bool)>> = Mutex::new(Vec::new());
    /// Whether a real keygen, whose sweeps lend the proof, succeeded.
    static KEYGEN_OK: Mutex<Option<bool>> = Mutex::new(None);

    /// A self-test that runs a sweep whose workers call a self-guarding
    /// constructor, as a regressed worker would, and then a real keygen.
    #[allow(clippy::unnecessary_wraps, reason = "a KatEntry's run signature")]
    fn sweep_self_test() -> Result<(), SelfTestFailure> {
        let seen = super::run(|| {
            (0..8)
                .into_par_iter()
                .map(|_| {
                    (
                        std::thread::current()
                            .name()
                            .is_some_and(|n| n.starts_with(super::THREAD_PREFIX)),
                        Sha256::new_internal().is_ok(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap();
        *WORKERS.lock().unwrap() = seen;
        let xi = [7u8; 48];
        *KEYGEN_OK.lock().unwrap() = Some(crate::slh_dsa_sha2_128f::keygen_internal(&xi).is_ok());
        Ok(())
    }

    /// Control for the proof-lending sweeps: during the self-tests a sweep
    /// worker runs on a thread of the crate's own self-test pool, never on
    /// rayon's global pool or the thread running the self-tests, and a
    /// self-guarding constructor there is refused. A worker that
    /// regressed from the proof-taking form would therefore fail the
    /// parallel self-test. A keygen whose workers use the proof succeeds in
    /// the same window.
    #[test]
    fn a_worker_using_a_self_guarding_constructor_is_refused_during_the_self_tests() {
        isolated(
            "sweep::tests::a_worker_using_a_self_guarding_constructor_is_refused_during_the_self_tests",
            || {
                let tests = [KatEntry {
                    name: "sweep control",
                    run: sweep_self_test,
                }];
                initialize_with_tests(UNSIGNED_TEST_BINARY, &tests).unwrap();
                assert_eq!(state(), State::Operational);
                let workers = WORKERS.lock().unwrap();
                assert_eq!(workers.len(), 8);
                assert!(workers.iter().all(|&(on_pool, _)| on_pool));
                assert!(workers.iter().all(|&(_, admitted)| !admitted));
                assert_eq!(*KEYGEN_OK.lock().unwrap(), Some(true));
            },
        );
    }
}
