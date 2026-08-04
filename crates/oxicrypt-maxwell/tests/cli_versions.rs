//! ISC-62: the harness output records the maxwell and EA tool versions per run.
//!
//! The line is printed by `cmd_parity` and, before this, asserted nowhere — so a
//! refactor could drop it, or stamp a literal that drifts from the crate version,
//! and every test would stay green. Provenance of an evidence run depends on it:
//! a parity table is only meaningful against the reference-tool version it was
//! generated for.
//!
//! Driven against an empty dataset directory, so it runs in milliseconds and
//! needs no EA v1.1.8 bundle.

// Test code: `expect` on process spawn is a deliberate fatal-on-setup assertion.
#![allow(clippy::expect_used, clippy::panic)]

use std::process::Command;

/// Run `maxwell parity` against a guaranteed-empty directory and return stdout.
fn parity_stdout() -> String {
    let dir =
        std::env::temp_dir().join(format!("oxicrypt-maxwell-versions-{}", std::process::id()));
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("clear {}: {e}", dir.display()),
    }
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("parity")
        .arg("--datasets")
        .arg(&dir)
        .output()
        .expect("run maxwell parity");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Both versions must appear, and must be the *live* values rather than literals
/// that could drift: the crate version comes from Cargo and the EA version from
/// the parity module, so a stamp that stopped tracking either is caught.
#[test]
fn parity_output_records_both_versions() {
    let stdout = parity_stdout();
    let expected = format!(
        "parity: oxicrypt-maxwell v{} vs EA tool v{}",
        env!("CARGO_PKG_VERSION"),
        oxicrypt_maxwell::parity::EA_TOOL_VERSION
    );
    assert!(
        stdout.contains(&expected),
        "the run must record both versions as `{expected}`, got:\n{stdout}"
    );
}

/// A positive control on the assertion above: the expected string must not be
/// trivially satisfiable. If either version were empty, `contains` would still
/// match a truncated line and the test would pass while recording nothing.
#[test]
fn version_stamps_are_non_empty() {
    assert!(
        !env!("CARGO_PKG_VERSION").is_empty(),
        "crate version must be recorded"
    );
    assert!(
        !oxicrypt_maxwell::parity::EA_TOOL_VERSION.is_empty(),
        "EA reference-tool version must be recorded"
    );
}
