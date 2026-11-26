//! The body of the `pct_fault_*` tests.
//!
//! A failed pairwise consistency test puts the module in its error state,
//! which is process-global and terminal, so each fault runs in a child
//! process of its own: the test re-executes its own binary for itself alone,
//! with [`CHILD`] naming the entry point to fault and a token the parent
//! generates. The token is also passed on the child's command line, so a
//! [`CHILD`] variable inherited from the environment does not make a
//! top-level run a child.
//!
//! The crates `oxicrypt-ecdh`, `oxicrypt-ecdsa`, `oxicrypt-eddsa` and
//! `oxicrypt-rsa` each hold a copy of this file. The copies are identical
//! apart from the two configuration lines that follow this header: the
//! name of [`CHILD`], set in the child process to `<entry point> <token>`,
//! and the crate's arming function. A change to the rest is pasted into
//! all four.

const CHILD: &str = "OXICRYPT_ECDH_PCT_FAULT_CHILD";
const ARM: fn() = oxicrypt_ecdh::seam::corrupt_next_pk;

use std::hash::BuildHasher;
use std::io::Read;

use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_module::{Error, KatEntry, initialize_with_tests, is_operational};

/// Printed by a child, as a line of its own, once every assertion passed.
const DONE: &str = "pct-fault child done:";

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// A DRBG the module seeds, as a production caller holds one.
pub(crate) fn module_drbg() -> HmacDrbgSha256 {
    HmacDrbgSha256::instantiate_from_module(b"pct-fault").unwrap()
}

/// An entry point under test, by name, reduced to its outcome.
pub(crate) type Entry = (&'static str, fn() -> Result<(), Error>);

/// The entry point this process faults, when it is a child its parent
/// started: [`CHILD`] holds the name and a token, and the token is also one
/// of the process's arguments.
fn child_entry() -> Option<String> {
    let value = std::env::var(CHILD).ok()?;
    let (name, token) = value.split_once(' ')?;
    std::env::args()
        .any(|arg| arg == token)
        .then(|| name.to_owned())
}

/// Runs `command` with both pipes drained, killing it after five minutes.
/// Returns its success, stdout and stderr.
fn run_child(mut command: std::process::Command) -> (bool, String, String) {
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > std::time::Duration::from_mins(5) {
            child.kill().unwrap();
            panic!("a child did not finish");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    (
        status.success(),
        stdout.join().unwrap(),
        stderr.join().unwrap(),
    )
}

/// In the parent: runs `control`, then each of `entries`, which must number
/// `expected`, faulted in a child process, and checks each child's exit
/// status and stderr. In a child: arms the fault, calls the entry point it
/// was started for, and checks that it returns
/// `ConditionalTestFailed { reason }` and that the module is no longer
/// operational.
#[allow(
    clippy::print_stderr,
    reason = "the child reports on stderr, which the parent reads"
)]
pub(crate) fn run(
    test: &str,
    reason: &'static str,
    control: fn(),
    entries: &[Entry],
    expected: usize,
) {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert!(is_operational());

    if let Some(name) = child_entry() {
        let (_, call) = entries
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no entry point named {name}"));
        ARM();
        assert_eq!(call(), Err(Error::ConditionalTestFailed { reason }));
        assert!(!is_operational());
        eprintln!("{DONE} {name}");
        return;
    }

    control();
    assert_eq!(entries.len(), expected);
    let token = format!(
        "pct-fault-token-{:016x}",
        std::collections::hash_map::RandomState::new().hash_one(std::process::id())
    );
    for (name, _) in entries {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                test,
                token.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, format!("{name} {token}"));
        let (success, stdout, stderr) = run_child(command);
        let done = format!("{DONE} {name}");
        assert!(
            success
                && stdout
                    .lines()
                    .any(|line| line.starts_with("test result: ok. 1 passed;"))
                && stderr.lines().any(|line| line == done),
            "the {name} child failed:\n{stdout}{stderr}"
        );
    }
    assert!(is_operational());
}
