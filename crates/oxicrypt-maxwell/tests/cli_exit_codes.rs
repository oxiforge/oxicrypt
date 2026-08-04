//! ISC-146: `maxwell parity` must not report success for having compared nothing.
//!
//! These drive the real `maxwell` binary rather than the library, because the
//! defect being closed lived entirely in the CLI: `Verdict::ok()` is
//! `failed == 0`, so an all-skip run was "ok" and `cmd_parity` exited zero. The
//! library predicate is [`oxicrypt_maxwell::parity::Verdict::full_strength`];
//! only running the binary proves the CLI actually exits on it.
//!
//! Every case here points `--datasets` at an empty temporary directory, so the
//! whole file runs in milliseconds and needs no EA v1.1.8 bundle — it is
//! meaningful on a CI runner that has no datasets, which is precisely the
//! environment where the defect was invisible (#153).

// Test code: `expect`/`panic` on process spawn and fixture setup are deliberate
// fatal-on-setup assertions — a harness that cannot start the binary has nothing
// to report but the failure.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

/// A directory guaranteed to contain none of the reference datasets.
///
/// Deliberately created fresh and left empty rather than reusing a temp path:
/// the whole point is an unprovisioned directory, and a stale file from another
/// test would silently turn an INCOMPLETE run into a PARTIAL one.
fn empty_datasets_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("oxicrypt-maxwell-cli-{tag}-{}", std::process::id()));
    // remove_dir_all, not a remove_file loop: the loop could not remove a
    // subdirectory, and "clear whatever is here" is the whole contract — a single
    // stale dataset would turn an INCOMPLETE run into a PARTIAL one and silently
    // invert what the test asserts.
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("clear stale dataset dir {}: {e}", dir.display()),
    }
    std::fs::create_dir_all(&dir).expect("create empty dataset dir");
    dir
}

/// Run `maxwell parity --datasets <empty dir>`, optionally with the opt-out set.
/// Returns (exit code, stdout).
fn run_parity(tag: &str, optional: bool) -> (Option<i32>, String) {
    let dir = empty_datasets_dir(tag);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_maxwell"));
    cmd.arg("parity").arg("--datasets").arg(&dir);
    // Clear it explicitly in the negative case: the developer running this suite
    // may have it exported, which would otherwise turn the failing case green.
    if optional {
        cmd.env("OXICRYPT_EA_DATA_OPTIONAL", "1");
    } else {
        cmd.env_remove("OXICRYPT_EA_DATA_OPTIONAL");
    }
    let out = cmd.output().expect("run maxwell parity");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (out.status.code(), stdout)
}

/// The defect: an all-skip run exited zero, indistinguishable from a
/// full-strength pass.
#[test]
fn parity_exits_non_zero_when_it_compared_nothing() {
    let (code, stdout) = run_parity("incomplete", false);
    assert_eq!(
        code,
        Some(1),
        "an all-skip parity run must exit non-zero; stdout:\n{stdout}"
    );
    // Positive control: assert the run really did skip everything rather than
    // failing for some unrelated reason (a bad argument also exits 1).
    assert!(
        stdout.contains("0 passed, 11 skipped, 0 failed"),
        "expected an all-skip tally, got:\n{stdout}"
    );
}

/// ISC-146 also requires the verdict to say in words that the run is not
/// evidence, so the reader never has to infer it from the skip count.
#[test]
fn parity_says_in_words_that_an_incomplete_run_is_not_evidence() {
    let (_, stdout) = run_parity("wording", false);
    assert!(
        stdout.contains("INCOMPLETE"),
        "verdict must name the run INCOMPLETE, got:\n{stdout}"
    );
    assert!(
        stdout.contains("NOT parity evidence"),
        "verdict must state the run is not evidence, got:\n{stdout}"
    );
    assert!(
        stdout.contains("OXICRYPT_EA_DATA_OPTIONAL=1"),
        "verdict must name the opt-out, got:\n{stdout}"
    );
}

/// The opt-out is per-invocation and still refuses to call the run evidence.
#[test]
fn parity_opt_out_accepts_a_partial_run_but_does_not_call_it_evidence() {
    let (code, stdout) = run_parity("optout", true);
    assert_eq!(
        code,
        Some(0),
        "OXICRYPT_EA_DATA_OPTIONAL=1 must accept a partial run; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("PARTIAL") && stdout.contains("NOT parity evidence"),
        "an opted-out run must still say it is not evidence, got:\n{stdout}"
    );
}

/// The opt-out must be exactly `1` — a truthy-looking value must not silently
/// disarm the gate.
#[test]
fn parity_opt_out_requires_the_exact_value_one() {
    let dir = empty_datasets_dir("optout-truthy");
    let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("parity")
        .arg("--datasets")
        .arg(&dir)
        .env("OXICRYPT_EA_DATA_OPTIONAL", "true")
        .output()
        .expect("run maxwell parity");
    assert_eq!(
        out.status.code(),
        Some(1),
        "only OXICRYPT_EA_DATA_OPTIONAL=1 disarms the completeness check"
    );
}

/// The FAIL branch, end-to-end and cheaply: `check_one` verifies each dataset's
/// SHA-256 provenance immediately after reading it and before any estimator runs,
/// so a single junk byte under a reference filename produces `Outcome::Fail` in
/// microseconds — no EA bundle and no multi-second estimation required.
#[test]
fn parity_exits_non_zero_and_says_fail_when_a_dataset_does_not_match() {
    let dir = empty_datasets_dir("provenance");
    std::fs::write(dir.join("rand1_short.bin"), b"not the reference dataset")
        .expect("write junk dataset");
    let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("parity")
        .arg("--datasets")
        .arg(&dir)
        // Even opted out, a dataset that actually failed must not be laundered
        // into an accepted run.
        .env("OXICRYPT_EA_DATA_OPTIONAL", "1")
        .output()
        .expect("run maxwell parity");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.status.code(),
        Some(1),
        "a failed dataset must exit non-zero even with the opt-out set; stdout:\n{stdout}"
    );
    // Positive control: prove it failed for the reason we engineered, not by
    // some unrelated path that also exits 1.
    assert!(
        stdout.contains("provenance mismatch"),
        "expected a provenance failure, got:\n{stdout}"
    );
    assert!(
        stdout.contains("0 passed, 10 skipped, 1 failed"),
        "expected exactly one failure and ten skips, got:\n{stdout}"
    );
    assert!(
        stdout.contains("verdict: FAIL") && stdout.contains("10 absent"),
        "the FAIL verdict must report the skips too, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("disagreed"),
        "nothing was numerically compared here; the verdict must not say so:\n{stdout}"
    );
}

/// A non-evidence verdict is repeated on stderr, because the opt-out is process
/// environment rather than a per-invocation act: a caller that reads only the
/// exit code can otherwise be running against a silently disarmed gate.
#[test]
fn parity_repeats_a_non_evidence_verdict_on_stderr() {
    let dir = empty_datasets_dir("stderr");
    let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("parity")
        .arg("--datasets")
        .arg(&dir)
        .env("OXICRYPT_EA_DATA_OPTIONAL", "1")
        .output()
        .expect("run maxwell parity");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "the opt-out still exits zero");
    assert!(
        stderr.contains("PARTIAL") && stderr.contains("NOT parity evidence"),
        "an accepted-but-not-evidence run must say so on stderr too, got:\n{stderr}"
    );
}

// NOT COVERED HERE, deliberately and with the reason stated: the mapping from
// `restart_verdict`'s decision to the process exit code, for a verdict produced by
// an actual analysis. Driving it needs a 1000x1000 matrix, and the run is both slow
// and strongly data-dependent — random 8-bit data measured 456s, while the
// low-entropy matrix required to *fail* the validation gate exceeded 20 minutes
// without finishing. An `#[ignore]`d test nobody can afford to run is not evidence,
// so there is no such test here rather than a green-looking one that has never
// executed.
//
// What is covered instead: the three rejection tests below and above drive the real
// binary through `cmd_restart` and prove it maps a decision to a non-zero exit;
// `restart_verdict` itself is `#[must_use]` (so discarding it is a gate failure) and
// its four branches are unit-tested in `main.rs`. The residual is the wiring for the
// post-analysis verdict specifically. See #167 for the runtime blowup.

/// A non-finite `H_I` must be rejected at parse. `nan` and `inf` both parse as
/// f64 and pass a `< 0.0` test, so without this they reached the analysis, where
/// every comparison against them is false and the gate rejects the data without
/// being able to name a cause.
#[test]
fn restart_rejects_a_non_finite_initial_entropy() {
    let dir = empty_datasets_dir("nan");
    let path = dir.join("tiny.bin");
    std::fs::write(&path, b"tiny").expect("write tiny file");
    for bad in ["nan", "inf"] {
        let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
            .arg("restart")
            .arg(&path)
            .arg("8")
            .arg(bad)
            .output()
            .expect("run maxwell restart");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "H_I={bad} must be rejected");
        // Positive control: it must be rejected for being non-finite, NOT for the
        // file being the wrong size — that check runs later and would mask this.
        assert!(
            stderr.contains("must be finite"),
            "H_I={bad} must be rejected at parse, got:\n{stderr}"
        );
    }
}

/// `restart_analysis`'s `# Panics` section states that the CLI rejects
/// single-symbol matrices before calling. It did not: a constant matrix — what a
/// stuck noise source produces — reached `simulate_bound` and tripped its debug
/// assert, exiting 101 with no verdict at all. Fast, because the rejection
/// happens before the analysis.
#[test]
fn restart_rejects_a_constant_matrix() {
    let dir = empty_datasets_dir("restart-constant");
    let path = dir.join("constant.bin");
    std::fs::write(&path, vec![0x5a_u8; 1_000_000]).expect("write constant matrix");
    let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("restart")
        .arg(&path)
        .arg("8")
        .arg("7.0")
        .output()
        .expect("run maxwell restart");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // Positive control: exit 1, the ordinary rejection — NOT 101, which is the
    // debug-assert panic this check exists to prevent.
    assert_eq!(
        out.status.code(),
        Some(1),
        "a constant matrix must be rejected, not panic; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("distinct symbol"),
        "the rejection must name the cause, got:\n{stderr}"
    );
}

/// The other half of the same precondition: `k_effective = ceil(2^H_I)` must fit
/// inside the observed alphabet, or the Monte-Carlo cutoff is drawn over symbols
/// the data never contained.
#[test]
fn restart_rejects_an_initial_entropy_wider_than_the_alphabet() {
    let dir = empty_datasets_dir("restart-narrow");
    let path = dir.join("narrow.bin");
    let mut matrix = vec![0u8; 999_999];
    matrix.push(1);
    std::fs::write(&path, &matrix).expect("write two-symbol matrix");
    let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("restart")
        .arg(&path)
        .arg("8")
        // H_I = 7.0 implies 128 equiprobable symbols; the matrix has 2.
        .arg("7.0")
        .output()
        .expect("run maxwell restart");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(1),
        "H_I wider than the alphabet must be rejected; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("128") && stderr.contains("only 2"),
        "the rejection must name both numbers, got:\n{stderr}"
    );
}
