//! The shared-object case: does the module verify the artifact that
//! contains it, or the process that loaded it?
//!
//! A design that resolves its target with `env::current_exe()` answers
//! the second question: for a shared object that call returns the **host's**
//! path, so the C ABI would verify a file that is not the module, or skip
//! the check altogether. This design locates the slot by its own runtime
//! address, which no host can substitute.
//!
//! The setup is what gives the tests their force. **The host — this test
//! binary — is never signed.** It links `oxicrypt-integrity` through the
//! signer library, so it carries its own unsigned slot. A verifier that
//! looked at the host would therefore report "never signed" and could
//! never report success, whatever we did to the library. Every pass below
//! is evidence that the library, not the host, was the thing verified.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::Command;

use oxicrypt_integrity_sign::{elf, sign_image};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

const RTLD_NOW: c_int = 2;

const OPERATIONAL: i32 = 0;
const MISMATCH: i32 = 3;
const SLOT_INVALID: i32 = 4;

/// The cdylib cargo built for this package.
///
/// Derived from the test binary's own path rather than an environment
/// variable, because cargo exposes `CARGO_BIN_EXE_*` for binaries and
/// nothing equivalent for cdylibs — measured, not assumed: no
/// `CARGO_CDYLIB_FILE_*` variable reaches this process.
///
/// Building a package's tests does not oblige cargo to produce that
/// package's cdylib artifact, so the file is built here rather than
/// inherited from whatever else the workspace happened to build. Relying
/// on the inheritance passes on a warm target directory and fails on a
/// clean one, which is the wrong way round: the machine that has never
/// built this crate is the one whose result matters.
///
/// Missing after the build is a hard failure: a skip here would read
/// exactly like a pass.
fn built_cdylib() -> PathBuf {
    static BUILT: std::sync::Once = std::sync::Once::new();

    let exe = std::env::current_exe().expect("test binary path");
    let dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/debug from target/debug/deps");

    BUILT.call_once(|| {
        // Match the profile the test itself was built under, or the build
        // lands beside a directory nothing here reads.
        let mut cmd = Command::new(env!("CARGO"));
        cmd.args(["build", "-p", "integrity-probe-so"]);
        if dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        let status = cmd.status().expect("run cargo build for the cdylib");
        assert!(status.success(), "building the cdylib under test failed");
    });

    let so = dir.join("libintegrity_probe_so.so");
    assert!(
        so.is_file(),
        "the cdylib under test is missing at {}",
        so.display()
    );
    so
}

fn scratch(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    p.push(format!(
        "oxicrypt-integrity-so-{tag}-{}-{nanos}.so",
        std::process::id()
    ));
    p
}

/// An unsigned copy of the library, at a path of its own so each test
/// gets a distinct shared object rather than the loader's cached one.
fn copy_cdylib(tag: &str) -> PathBuf {
    let dst = scratch(tag);
    std::fs::copy(built_cdylib(), &dst).expect("copy cdylib");
    dst
}

fn sign(path: &Path) {
    let mut bytes = std::fs::read(path).expect("read");
    sign_image(&mut bytes).expect("sign");
    std::fs::write(path, &bytes).expect("write");
}

fn flip(path: &Path, offset: usize) {
    let mut bytes = std::fs::read(path).expect("read");
    bytes[offset] ^= 0xff;
    std::fs::write(path, &bytes).expect("write");
}

/// A file offset inside the library's extent, in its executable segment.
fn offset_inside_extent(path: &Path) -> usize {
    let bytes = std::fs::read(path).expect("read");
    let ranges = elf::classify(&bytes).expect("classify").ranges;
    let last = ranges.last().expect("extent has ranges");
    (last.file_off + last.len / 2) as usize
}

/// Loads the library and returns `(status code, slot address, the path
/// of the mapping that address falls in)`.
///
/// The mapping is resolved **before** `dlclose`, which is not a detail:
/// after the library is unloaded its address is in no mapping at all, and
/// the lookup returns nothing rather than the wrong answer.
fn load_and_probe(path: &Path) -> (i32, usize, Option<String>) {
    let c = CString::new(path.as_os_str().to_str().expect("utf-8 path")).expect("c string");
    // SAFETY: `c` outlives the call, and the handle is used only through
    // the symbols this library is known to export.
    let handle = unsafe { dlopen(c.as_ptr(), RTLD_NOW) };
    assert!(!handle.is_null(), "dlopen failed for {}", path.display());

    let probe = unsafe { dlsym(handle, c"oxicrypt_probe_integrity".as_ptr()) };
    let addr = unsafe { dlsym(handle, c"oxicrypt_probe_slot_address".as_ptr()) };
    assert!(
        !probe.is_null() && !addr.is_null(),
        "exported symbols absent"
    );

    // SAFETY: both symbols are declared in this crate's `lib.rs` with
    // exactly these signatures and no arguments.
    let probe_fn: extern "C" fn() -> i32 = unsafe { core::mem::transmute(probe) };
    let addr_fn: extern "C" fn() -> usize = unsafe { core::mem::transmute(addr) };
    let code = probe_fn();
    let slot_addr = addr_fn();
    let mapping = mapping_path_of(slot_addr);
    unsafe { dlclose(handle) };
    (code, slot_addr, mapping)
}

/// The path of the mapping containing `addr`, per `/proc/self/maps`.
///
/// A line that will not parse is skipped rather than ending the search:
/// aborting on the first odd line would turn "not found" into a verdict
/// about the wrong thing.
fn mapping_path_of(addr: usize) -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read maps");
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else { continue };
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(s), Ok(e)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16)) else {
            continue;
        };
        if addr >= s && addr < e {
            // After the range: perms, offset, dev, inode, then the path.
            return fields.nth(4).map(ToOwned::to_owned);
        }
    }
    None
}

// ---------------------------------------------------------------------

/// The premise every other test here rests on: the host is unsigned.
///
/// Asserted rather than assumed, because if the host were signed the
/// results below would be consistent with a host-oriented verifier and
/// would prove nothing.
#[test]
fn the_host_binary_is_unsigned() {
    let exe = std::env::current_exe().expect("test binary path");
    let bytes = std::fs::read(&exe).expect("read host");
    let slot_off = elf::find_slot(&bytes).expect("the host carries a slot of its own");
    let parsed = oxicrypt_integrity::slot::parse(&bytes[slot_off..slot_off + 16384]);
    assert!(
        matches!(
            parsed,
            Err(oxicrypt_integrity::slot::SlotDefect::UnsupportedVersion(0))
        ),
        "premise failed: the host is signed, so these tests cannot distinguish \
         host from library — got {parsed:?}"
    );
}

#[test]
fn a_signed_library_verifies_itself_inside_an_unsigned_host() {
    let so = copy_cdylib("signed");
    sign(&so);
    let (code, _, _) = load_and_probe(&so);
    assert_eq!(
        code, OPERATIONAL,
        "the library must verify itself even though the host that loaded it is unsigned"
    );
    let _ = std::fs::remove_file(&so);
}

/// The direct form of the claim: the bytes verified live in the library's
/// mapping, so no host could have been substituted for it.
#[test]
fn the_verified_slot_lies_in_the_librarys_own_mapping() {
    let so = copy_cdylib("mapping");
    sign(&so);
    let (code, _slot_addr, mapping) = load_and_probe(&so);
    assert_eq!(code, OPERATIONAL);

    let mapped = mapping.expect("the slot address is in some mapping");
    assert_eq!(
        Path::new(&mapped),
        so.as_path(),
        "the slot the module verified belongs to {mapped}, not to the library under test"
    );

    let host = std::env::current_exe().expect("test binary path");
    assert_ne!(
        Path::new(&mapped),
        host.as_path(),
        "the module verified its host instead of itself — this is the original defect"
    );
    let _ = std::fs::remove_file(&so);
}

/// Tampering with the **library** must move the verdict, while the host
/// is untouched. Together with the test above this pins the direction:
/// the library's bytes are the ones under test.
#[test]
fn tampering_with_the_library_is_what_changes_the_verdict() {
    let so = copy_cdylib("tamper");
    sign(&so);
    assert_eq!(load_and_probe(&so).0, OPERATIONAL, "control: signed passes");

    let tampered = copy_cdylib("tamper-b");
    sign(&tampered);
    let off = offset_inside_extent(&tampered);
    flip(&tampered, off);
    assert_eq!(
        load_and_probe(&tampered).0,
        MISMATCH,
        "a changed byte in the library's code must fail the library's own test"
    );
    let _ = std::fs::remove_file(&so);
    let _ = std::fs::remove_file(&tampered);
}

#[test]
fn an_unsigned_library_refuses() {
    let so = copy_cdylib("unsigned");
    let (code, _, _) = load_and_probe(&so);
    assert_eq!(code, SLOT_INVALID);
    let _ = std::fs::remove_file(&so);
}
