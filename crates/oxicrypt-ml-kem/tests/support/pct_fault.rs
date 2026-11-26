//! The body of the `pct_fault_ml_kem_*` tests.
//!
//! A failed pairwise consistency test puts the module in its error state,
//! which is process-global and terminal, so each fault runs in a child
//! process of its own: the test re-executes its own binary for itself alone,
//! with [`CHILD`] naming the entry point to fault.

use oxicrypt_module::{Error, KatEntry, Rbg, RbgError, initialize_with_tests, is_operational};

/// Set in the child process to the name of the entry point it faults.
const CHILD: &str = "OXICRYPT_ML_KEM_PCT_FAULT_CHILD";

/// Printed by a child once every assertion has passed.
const DONE: &str = "pct-fault child done:";

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// An RBG of the highest strength that serves a fixed byte.
pub(crate) struct FixedRbg;

impl Rbg for FixedRbg {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
        out.fill(0x5a);
        Ok(())
    }

    fn strength_bits(&self) -> u32 {
        256
    }
}

/// An entry point under test, by name, reduced to its outcome.
pub(crate) type Entry = (&'static str, fn() -> Result<(), Error>);

/// Decodes the hexadecimal `s` into `N` bytes.
#[allow(dead_code, reason = "the ML-KEM-1024 test loads its vector from files")]
pub(crate) fn hex<const N: usize>(s: &str) -> [u8; N] {
    let bytes: Vec<u8> = s
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

/// In the parent: runs `control`, then each of `entries` faulted in a child
/// process, and checks each child's exit status and stderr. In a child:
/// arms the fault, calls the entry point [`CHILD`] names, and checks that it
/// returns `ConditionalTestFailed { reason }` and that the module is no
/// longer operational.
#[allow(
    clippy::print_stderr,
    reason = "the child reports on stderr, which the parent reads"
)]
pub(crate) fn run(test: &str, reason: &'static str, control: fn(), entries: &[Entry]) {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());

    if let Ok(name) = std::env::var(CHILD) {
        let (_, call) = entries
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no entry point named {name}"));
        oxicrypt_ml_kem::seam::corrupt_next_dk();
        assert_eq!(call(), Err(Error::ConditionalTestFailed { reason }));
        assert!(!is_operational());
        eprintln!("{DONE} {name}");
        return;
    }

    control();
    assert_eq!(entries.len(), 3);
    for (name, _) in entries {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // A child that hangs is killed and fails the test rather than
        // stalling the run.
        let start = std::time::Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > std::time::Duration::from_mins(5) {
                child.kill().unwrap();
                panic!("the {name} child did not finish");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success()
                && stdout.contains("test result: ok. 1 passed")
                && stderr.contains(&format!("{DONE} {name}")),
            "the {name} child failed:\n{stdout}{stderr}"
        );
    }
    assert!(is_operational());
}
