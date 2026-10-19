//! Control tests: the `probe` example, which has no run-time search path of
//! its own, run with the loader pointed at unsigned, modified and
//! foreign-key libraries, and in initialisation shapes a single test process
//! cannot hold. `cargo test` builds the example before running this binary.

#![cfg(all(oxicrypt_lib, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn probe() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let path = exe
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("examples")
        .join("probe");
    assert!(
        path.is_file(),
        "{} is missing; run the tests with `cargo test`, which builds the examples",
        path.display()
    );
    path
}

/// Runs the probe with the loader's search path set to `lib_dir`; returns
/// its stdout lines and whether it exited 0.
fn run(lib_dir: &Path, args: &[&str]) -> (Vec<String>, bool) {
    let out = Command::new(probe())
        .args(args)
        .env("LD_LIBRARY_PATH", lib_dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.is_empty(),
        "the probe printed nothing: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        stdout.lines().map(str::to_owned).collect(),
        out.status.success(),
    )
}

/// A scratch directory holding a copy of the signed library with `patch`
/// applied.
fn patched(name: &str, patch: impl FnOnce(&mut [u8])) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("oxicrypt-bindings-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let mut bytes = fs::read(common::lib_dir().join("liboxicrypt_ffi.so")).unwrap();
    patch(&mut bytes);
    fs::write(dir.join(common::delivered_name()), bytes).unwrap();
    dir
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let hits: Vec<usize> = bytes
        .windows(from.len())
        .enumerate()
        .filter(|(_, w)| *w == from)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected one {:?} in the library",
        String::from_utf8_lossy(from)
    );
    bytes[hits[0]..hits[0] + to.len()].copy_from_slice(to);
}

/// Builds a one-function shared object that overrides an export of the
/// library for the probe, through `LD_PRELOAD`. The library itself is the
/// signed fixture, unchanged, and its integrity test still passes: the
/// override intercepts only the crate's calls through the dynamic symbol.
fn shim(name: &str, source: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "oxicrypt-bindings-{}-shim-{name}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let c = dir.join(format!("{name}.c"));
    let so = dir.join(format!("lib{name}.so"));
    fs::write(&c, source).unwrap();
    let out = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&c)
        .output()
        .expect("run cc");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    so
}

fn run_with_shim(so: &Path, args: &[&str]) -> (Vec<String>, bool) {
    let out = Command::new(probe())
        .args(args)
        .env("LD_LIBRARY_PATH", common::lib_dir())
        .env("LD_PRELOAD", so)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    (
        stdout.lines().map(str::to_owned).collect(),
        out.status.success(),
    )
}

#[test]
fn services_without_a_shim() {
    let (lines, ok) = run(&common::lib_dir(), &["services", "1"]);
    assert_eq!(
        lines,
        [
            "init Cnsa2: ok",
            "is_operational: true",
            "encrypt: ok output=written"
        ]
    );
    assert!(ok);
}

/// `oxi_init` returns 0 but the library reports itself not operational: the
/// crate's own check after `oxi_init` must refuse.
#[test]
fn init_refuses_a_library_that_is_not_operational_after_init() {
    let so = shim("notop", "int oxi_is_operational(void) { return 0; }\n");
    let (lines, ok) = run_with_shim(&so, &["services", "1"]);
    assert_eq!(
        lines,
        ["init Cnsa2: err code=NotOperational integrity=Some(Passed) detail=none"]
    );
    assert!(!ok);
}

/// `oxi_init` returns 0 but the integrity indicator is not `Passed`: the
/// crate requires both.
#[test]
fn init_requires_the_integrity_indicator_to_read_passed() {
    let so = shim(
        "intnotrun",
        "int oxi_integrity_status(void) { return 0; }\n",
    );
    let (lines, ok) = run_with_shim(&so, &["init", "1"]);
    assert_eq!(
        lines,
        ["init Cnsa2: err code=IntegrityUnverified integrity=Some(NotRun) detail=none"]
    );
    assert!(!ok);
}

/// The library leaves its operational state after initialisation:
/// `Module::is_operational` reads it live.
#[test]
fn is_operational_reads_the_state_live() {
    let so = shim(
        "flip",
        "static int calls;\nint oxi_is_operational(void) { return calls++ == 0 ? 1 : 0; }\n",
    );
    let (lines, _) = run_with_shim(&so, &["services", "1"]);
    assert_eq!(lines[..2], ["init Cnsa2: ok", "is_operational: false"]);
}

/// An encryption the library refuses after writing into the output: the
/// crate zeroes what it wrote.
#[test]
fn a_failed_encryption_leaves_the_output_zeroed() {
    let so = shim(
        "encfail",
        "#include <stdint.h>\n#include <string.h>\n\
         int oxi_aes256_gcm_encrypt(const void *key, const uint8_t *iv, const uint8_t *aad,\n\
             uintptr_t aad_len, const uint8_t *pt, uintptr_t pt_len, uint8_t *ct, uint8_t *tag)\n\
         { memset(ct, 0x5A, pt_len); memset(tag, 0x5A, 16); return 255; }\n",
    );
    let (lines, _) = run_with_shim(&so, &["services", "1"]);
    assert_eq!(
        lines,
        [
            "init Cnsa2: ok",
            "is_operational: true",
            "encrypt: err output=zeroed",
            "encrypt error: Internal"
        ]
    );
}

#[test]
fn the_signed_library_passes_through_the_probe() {
    let (lines, ok) = run(&common::lib_dir(), &["init", "1"]);
    assert_eq!(lines, ["init Cnsa2: ok"]);
    assert!(ok);
}

#[test]
fn the_unsigned_library_is_refused() {
    let (lines, ok) = run(&common::fixture_dir().join("unsigned"), &["init", "1"]);
    assert_eq!(
        lines,
        ["init Cnsa2: err code=SelfTestFailed integrity=Some(SlotInvalid) detail=some"]
    );
    assert!(!ok);
}

#[test]
fn repeated_failure_reports_each_call_as_the_library_does() {
    let (lines, _) = run(&common::fixture_dir().join("unsigned"), &["init", "1", "1"]);
    assert_eq!(
        lines,
        [
            "init Cnsa2: err code=SelfTestFailed integrity=Some(SlotInvalid) detail=some",
            "init Cnsa2: err code=NotOperational integrity=Some(SlotInvalid) detail=some",
        ]
    );
}

#[test]
fn an_invalid_profile_does_not_initialise() {
    let (lines, ok) = run(&common::lib_dir(), &["init", "99", "1"]);
    assert_eq!(
        lines,
        [
            "init Unknown(99): err code=InvalidInput integrity=Some(NotRun) detail=none",
            "init Cnsa2: ok"
        ]
    );
    assert!(ok);
}

#[test]
fn an_unknown_spelling_of_a_known_profile_is_that_profile() {
    let (lines, ok) = run(&common::lib_dir(), &["init", "u1", "1"]);
    assert_eq!(lines, ["init Unknown(1): ok", "init Cnsa2: ok"]);
    assert!(ok);
}

#[test]
fn a_modified_library_fails_its_integrity_test() {
    // One byte of the embedded manifest text, inside the signed extent and
    // outside the version line.
    let dir = patched("tampered", |b| {
        replace_once(
            b,
            b"Pure-Rust cryptographic module targeting",
            b"Pure-Rust cryptographic module targetinG",
        );
    });
    let (lines, ok) = run(&dir, &["init", "1"]);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        lines,
        ["init Cnsa2: err code=SelfTestFailed integrity=Some(SignatureInvalid) detail=some"]
    );
    assert!(!ok);
}

/// The release version the crate was built as, which the fixture library
/// states in its manifest.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Another version of the same length: the last digit changed.
fn other_version() -> String {
    let (head, last) = VERSION.split_at(VERSION.len() - 1);
    format!("{head}{}", if last == "9" { "8" } else { "9" })
}

/// The library's version line, edited to [`other_version`]; the signature
/// then no longer holds, but the version and ABI checks run before the
/// integrity test.
fn edit_version(b: &mut [u8]) {
    let line = |v: &str| format!("library:\n  name: oxicrypt\n  version: \"{v}\"");
    replace_once(
        b,
        line(VERSION).as_bytes(),
        line(&other_version()).as_bytes(),
    );
}

/// The refusal a library at [`other_version`] without `oxi_abi_version` gets.
fn version_refusal() -> String {
    format!(
        "init Cnsa2: err code=LibraryVersion {{ library: Some({:?}), crate_: {VERSION:?} }} integrity=None detail=none",
        other_version()
    )
}

/// The `oxi_abi_version` export, renamed in the dynamic string table, as a
/// library that predates the function has none.
fn drop_abi_version(b: &mut [u8]) {
    replace_once(b, b"\0oxi_abi_version\0", b"\0oxi_abi_versioX\0");
}

/// The file offset of `symbol`'s code in the library at `lib`, from its
/// dynamic symbol table and program headers.
fn code_offset(lib: &Path, symbol: &str) -> usize {
    let nm = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(lib)
        .output()
        .unwrap();
    let nm = String::from_utf8_lossy(&nm.stdout).into_owned();
    let vaddr = nm
        .lines()
        .find_map(|l| {
            let mut f = l.split_whitespace();
            let addr = f.next()?;
            (f.nth(1)? == symbol).then(|| usize::from_str_radix(addr, 16).unwrap())
        })
        .expect("symbol in the dynamic table");
    let segs = Command::new("readelf")
        .arg("-lW")
        .arg(lib)
        .output()
        .unwrap();
    let segs = String::from_utf8_lossy(&segs.stdout).into_owned();
    segs.lines()
        .filter(|l| l.trim_start().starts_with("LOAD"))
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let hex = |s: &str| usize::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
            let (offset, seg_vaddr, filesz) = (hex(f[1]), hex(f[2]), hex(f[4]));
            (seg_vaddr <= vaddr && vaddr < seg_vaddr + filesz).then(|| vaddr - seg_vaddr + offset)
        })
        .expect("a LOAD segment holding the symbol")
}

/// The library's own `oxi_abi_version`, patched in a copy to return 2. The
/// version and ABI checks run before the integrity test, so the patch is
/// refused by the ABI check, not by the broken signature. The patch is of
/// x86_64 code, so it runs only on x86_64. The CI workflows have no macOS
/// job for this crate, so no test here exercises the macOS lookup path.
#[cfg(target_arch = "x86_64")]
#[test]
fn a_library_of_another_abi_is_refused_before_init() {
    let lib = common::lib_dir().join("liboxicrypt_ffi.so");
    let at = code_offset(&lib, "oxi_abi_version");
    let dir = patched("abi2", |b| {
        // `mov eax, 1; ret`, the whole function at ABI 1.
        assert_eq!(b[at..at + 6], [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
        b[at + 1] = 0x02;
    });
    let (lines, ok) = run(&dir, &["init", "1"]);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        lines,
        ["init Cnsa2: err code=LibraryAbi { library: 2, crate_: 1 } integrity=None detail=none"]
    );
    assert!(!ok);
}

/// Another object defining `oxi_abi_version`, loaded ahead of the library,
/// does not stand in for the library's own.
#[test]
fn a_foreign_oxi_abi_version_does_not_override_the_librarys() {
    let so = shim("abi2", "int oxi_abi_version(void) { return 2; }\n");
    let (lines, ok) = run_with_shim(&so, &["init", "1"]);
    assert_eq!(lines, ["init Cnsa2: ok"]);
    assert!(ok);
}

/// The library's own number is read even when a foreign definition comes
/// first in the lookup scope: a library of another release version with
/// ABI 1 passes the ABI check, and is then refused by its integrity test
/// because the edit broke its signature, not by the version rule.
#[test]
fn the_librarys_own_oxi_abi_version_is_read_past_a_foreign_one() {
    let dir = patched("own-past-foreign", edit_version);
    let so = shim("abi2-past", "int oxi_abi_version(void) { return 2; }\n");
    let out = Command::new(probe())
        .args(["init", "1"])
        .env("LD_LIBRARY_PATH", &dir)
        .env("LD_PRELOAD", &so)
        .output()
        .unwrap();
    fs::remove_dir_all(&dir).unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        ["init Cnsa2: err code=SelfTestFailed integrity=Some(SignatureInvalid) detail=some"]
    );
}

/// Nor does it stand in for a library that has none: the release-version
/// rule still applies.
#[test]
fn a_foreign_oxi_abi_version_does_not_stand_in_for_a_missing_one() {
    let dir = patched("foreign-noabi", |b| {
        edit_version(b);
        drop_abi_version(b);
    });
    let so = shim("abi1", "int oxi_abi_version(void) { return 1; }\n");
    let out = Command::new(probe())
        .args(["init", "1"])
        .env("LD_LIBRARY_PATH", &dir)
        .env("LD_PRELOAD", &so)
        .output()
        .unwrap();
    fs::remove_dir_all(&dir).unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().collect::<Vec<_>>(), [version_refusal()]);
}

/// A library of another release version with this crate's ABI number passes
/// the ABI check, which replaces the version rule, and then fails its
/// integrity test, because the edit invalidated its signature.
#[test]
fn the_abi_number_decides_and_not_the_release_version() {
    let dir = patched("version", edit_version);
    let (lines, ok) = run(&dir, &["init", "1"]);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        lines,
        ["init Cnsa2: err code=SelfTestFailed integrity=Some(SignatureInvalid) detail=some"]
    );
    assert!(!ok);
}

#[test]
fn without_oxi_abi_version_the_release_version_decides() {
    let dir = patched("noabi-version", |b| {
        edit_version(b);
        drop_abi_version(b);
    });
    let (lines, ok) = run(&dir, &["init", "1"]);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(lines, [version_refusal()]);
    assert!(!ok);

    // The same library at this crate's version passes the fallback, and is
    // then refused by its integrity test, since the rename changed it.
    let dir = patched("noabi", drop_abi_version);
    let (lines, _) = run(&dir, &["init", "1"]);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        lines,
        ["init Cnsa2: err code=SelfTestFailed integrity=Some(SignatureInvalid) detail=some"]
    );
}

#[test]
fn a_library_signed_with_another_key_is_refused_by_the_pin() {
    let (lines, ok) = run(&common::fixture_dir().join("second-key"), &["init", "1"]);
    if cfg!(oxicrypt_pinned) {
        let line = &lines[0];
        assert!(
            line.starts_with("init Cnsa2: err code=KeyFingerprint { found: sha256:"),
            "{line}"
        );
        let expected = common::fixture_fingerprint();
        assert!(line.contains(&format!("expected: {expected} }}")), "{line}");
        assert!(
            line.ends_with("integrity=Some(Passed) detail=none"),
            "{line}"
        );
        assert!(!ok);
    } else {
        assert_eq!(lines, ["init Cnsa2: ok"]);
    }
}

#[test]
fn a_c_caller_first_with_another_profile() {
    let (lines, ok) = run(&common::lib_dir(), &["c-first", "0", "1", "0"]);
    assert_eq!(
        lines,
        [
            "c oxi_init(0): 0",
            "init Cnsa2: err code=ProfileMismatch { active: Unrestricted, requested: Cnsa2 } integrity=Some(Passed) detail=none",
            "init Unrestricted: ok",
        ]
    );
    assert!(ok);
}

#[test]
fn a_failed_first_initialisation_by_a_c_caller() {
    let (lines, ok) = run(
        &common::fixture_dir().join("unsigned"),
        &["c-first", "1", "1"],
    );
    assert_eq!(
        lines,
        [
            "c oxi_init(1): 2",
            "init Cnsa2: err code=NotOperational integrity=Some(SlotInvalid) detail=some",
        ]
    );
    assert!(!ok);
}

#[test]
fn two_threads_with_different_profiles_one_succeeds() {
    for _ in 0..5 {
        let (lines, ok) = run(&common::lib_dir(), &["threads", "1", "0"]);
        assert!(ok, "{lines:?}");
        assert_eq!(lines.iter().filter(|l| l.ends_with(": ok")).count(), 1);
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.contains("ProfileMismatch"))
                .count(),
            1,
            "{lines:?}"
        );
    }
}
