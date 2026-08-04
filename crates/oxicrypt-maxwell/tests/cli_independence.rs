//! ISC-145: `maxwell independence` matches EA v1.1.8 on input validation.
//!
//! A sample wider than the declared `bits_per_symbol` is a hard error with no
//! assessment; a narrower one warns and continues. These drive the real binary,
//! because the refusal has to reach the process exit code — a library `Result`
//! that the CLI unwrapped into a report would close nothing.
//!
//! Every case here uses a few kilobytes, so the file runs in milliseconds and
//! needs no dataset bundle.

// Test code: `expect` on process spawn and fixture setup are deliberate
// fatal-on-setup assertions.
#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use oxicrypt_maxwell::independence::SIDECAR_FILE;
use std::path::PathBuf;
use std::process::{Command, Output};

/// The scratch path for a tag, without touching the filesystem — so a test can
/// name the directory a previous call created.
fn scratch_dir_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "oxicrypt-maxwell-indep-{tag}-{}",
        std::process::id()
    ))
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = scratch_dir_path(tag);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("clear {}: {e}", dir.display()),
    }
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Run `maxwell independence <file> <bits>` over `data`, sidecar into the same
/// scratch directory so nothing is written beside the source tree.
fn run_independence(tag: &str, data: &[u8], bits: u8) -> Output {
    let dir = scratch_dir(tag);
    let path = dir.join("samples.bin");
    std::fs::write(&path, data).expect("write samples");
    Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("independence")
        .arg(&path)
        .arg(bits.to_string())
        .arg("--sidecar")
        .arg(&dir)
        .output()
        .expect("run maxwell independence")
}

/// The sidecar filename is part of the evidence-artifact contract: downstream
/// readers open it by name. Every other test here builds its path from
/// `SIDECAR_FILE`, which is right for locating the file but means a rename moves
/// the assertion along with the writer and nothing notices. This pins the literal
/// once, so renaming it is a deliberate act that fails here first.
#[test]
fn sidecar_filename_is_pinned() {
    assert_eq!(
        SIDECAR_FILE, "independence-results.json",
        "renaming the evidence sidecar breaks every downstream reader"
    );
}

/// 4096 samples inside 4 bits, with one full-range byte planted. Before this
/// change the run produced a min-entropy over the retained subset while the
/// denominator counted everything, and exited zero.
#[test]
fn independence_refuses_a_sample_wider_than_the_declaration() {
    let mut data: Vec<u8> = (0..4096u32).map(|i| (i % 16) as u8).collect();
    data[100] = 0xC8;
    let out = run_independence("wide", &data, 4);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(1),
        "a wide sample must exit non-zero; stderr:\n{stderr}"
    );
    // Positive control: it must fail for the width, not for a missing file or a
    // bad argument, both of which also exit 1.
    assert!(
        stderr.contains("exceed the declared 4 bits/symbol"),
        "the refusal must name the width, got:\n{stderr}"
    );
    assert!(
        stderr.contains("index 100"),
        "the refusal must locate the sample, got:\n{stderr}"
    );
    assert!(
        stderr.contains("No assessment was performed"),
        "the refusal must say no assessment happened, got:\n{stderr}"
    );
}

/// No assessment means no evidence artifact: a refused run must not leave a
/// sidecar behind that a later reader could mistake for a result.
#[test]
fn independence_writes_no_sidecar_when_it_refuses() {
    let dir = scratch_dir("no-sidecar");
    let path = dir.join("samples.bin");
    let mut data: Vec<u8> = (0..4096u32).map(|i| (i % 16) as u8).collect();
    data[7] = 0xFF;
    std::fs::write(&path, &data).expect("write samples");
    let out = Command::new(env!("CARGO_BIN_EXE_maxwell"))
        .arg("independence")
        .arg(&path)
        .arg("4")
        .arg("--sidecar")
        .arg(&dir)
        .output()
        .expect("run maxwell independence");
    assert_eq!(out.status.code(), Some(1));
    let sidecar = dir.join(SIDECAR_FILE);
    assert!(
        !sidecar.exists(),
        "a refused run must leave no evidence artifact at {}",
        sidecar.display()
    );
}

/// The same data, declared at its true width, must be assessed normally — the
/// guard must refuse bad input without refusing good input.
#[test]
fn independence_accepts_the_same_data_at_its_true_width() {
    let mut data: Vec<u8> = (0..4096u32).map(|i| (i % 16) as u8).collect();
    data[100] = 0xC8;
    let out = run_independence("true-width", &data, 8);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "8 bits/symbol admits a full-range byte; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("exceed the declared"),
        "must not refuse valid input, got:\n{stderr}"
    );
    // Negative control for the narrow-source warning. Without this, changing the
    // CLI's `<` to `<=` makes it warn on every well-formed run — self-contradictory
    // text ("declared 8 ... needs no more than 8") that trains operators to ignore
    // the warning entirely — and every other test stays green.
    assert!(
        !stderr.contains("warning"),
        "data at its true width must not warn, got:\n{stderr}"
    );
    // Positive control for `independence_writes_no_sidecar_when_it_refuses`: that
    // test asserts a file is absent, which passes trivially forever if the filename
    // ever drifts. Assert here that an ACCEPTED run does create it, at the same
    // path, so the negative test is anchored to a path something actually writes.
    let sidecar = scratch_dir_path("true-width").join(SIDECAR_FILE);
    assert!(
        sidecar.exists(),
        "an accepted run must write the evidence sidecar at {}",
        sidecar.display()
    );
}

/// A narrower source warns and continues — EA's behaviour, and the common case
/// of a 1-bit noise source declared at a byte.
#[test]
fn independence_warns_but_continues_on_a_narrower_source() {
    let data = vec![1u8; 4096];
    let out = run_independence("narrow", &data, 8);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "a narrow source is not an error; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("warning") && stderr.contains("no sample needs more than 1"),
        "a narrow source must warn, got:\n{stderr}"
    );
}
