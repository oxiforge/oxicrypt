//! The pre-operational integrity test, exercised end to end on a real
//! signed artifact.
//!
//! Every test here signs a copy of this crate's own binary, runs it, and
//! reads the status indicator off the exit code. That is deliberate:
//! the module's integrity test can only be exercised honestly by a
//! process that has actually been loaded, because the property under
//! test — that the loaded image matches what was signed — does not exist
//! until something loads it. A unit test calling the verifier in-process
//! would prove the verifier runs, not that a booting module reaches it
//! and not that memory equals file.
//!
//! **Each test asserts its own premise.** A test that flips a byte "in
//! the code" proves nothing if the offset it picked was somewhere else,
//! and the failure would look exactly like a pass. So the offset is
//! checked against the extent before it is used, in both directions.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use oxicrypt_integrity::slot::Range;
use oxicrypt_integrity_sign::{elf, image, sign_image, write_extent};

/// The probe binary cargo built for this test run.
const PROBE: &str = env!("CARGO_BIN_EXE_integrity-probe");

/// Status indicators, mirroring the probe's exit codes.
const OPERATIONAL: i32 = 0;
const MISMATCH: i32 = 3;
const SLOT_INVALID: i32 = 4;
const CAST_NOT_RUN: i32 = 7;
const INTEGRITY_UNVERIFIED: i32 = 9;
/// Status-indicator discriminants, per Security Policy §5.2.
const STATUS_PASSED: u8 = 1;
const STATUS_SLOT_INVALID: u8 = 3;
const STATUS_MISMATCH: u8 = 2;
const STATUS_CAST_NOT_RUN: u8 = 5;

fn scratch(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    p.push(format!(
        "oxicrypt-integrity-e1-{tag}-{}-{nanos}",
        std::process::id()
    ));
    p
}

/// An unsigned copy of the probe, executable.
fn copy_probe(tag: &str) -> PathBuf {
    let dst = scratch(tag);
    std::fs::copy(PROBE, &dst).expect("copy probe");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
            .expect("chmod probe");
    }
    dst
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read artifact")
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write artifact");
}

/// Signs an artifact in place, the way the build pipeline would.
fn sign(path: &Path) {
    let mut bytes = read(path);
    sign_image(&mut bytes).expect("sign");
    write(path, &bytes);
}

fn flip(path: &Path, offset: usize) {
    let mut bytes = read(path);
    bytes[offset] ^= 0xff;
    write(path, &bytes);
}

/// Runs the artifact and returns `(exit code, stdout)`.
///
/// Retries on `ETXTBSY`. These tests write an artifact and then execute
/// it, several at a time. When one thread forks to spawn its own probe,
/// the child inherits whatever write descriptors the other threads hold,
/// and a file cannot be executed while any process holds it open for
/// writing — so a sibling test's in-flight `sign` can make this exec fail
/// with "Text file busy". The window is the fork-to-exec gap in another
/// thread, so it closes on its own; nothing about the artifact is wrong.
///
/// The gate does not see this: `cargo nextest` runs each test in its own
/// process, so there are no sibling descriptors to inherit. Plain
/// `cargo test` shares one process and does.
fn run(path: &Path, args: &[&str]) -> (i32, String) {
    const ETXTBSY: i32 = 26;
    let mut waited = std::time::Duration::ZERO;
    let step = std::time::Duration::from_millis(20);
    let out = loop {
        match Command::new(path).args(args).output() {
            Ok(out) => break out,
            Err(e)
                if e.raw_os_error() == Some(ETXTBSY)
                    && waited < std::time::Duration::from_secs(5) =>
            {
                std::thread::sleep(step);
                waited += step;
            }
            Err(e) => panic!("run probe: {e}"),
        }
    };
    let code = out.status.code().unwrap_or(-1);
    (code, String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The status indicator the probe reported, per Security Policy §5.2.
fn status(stdout: &str) -> u8 {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("status: "))
        .expect("probe must print its status indicator")
        .trim()
        .parse()
        .expect("status indicator must be a number")
}

/// The slot address the probe reported, which is the ASLR observable.
fn slot_addr(stdout: &str) -> u64 {
    let line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("slot-addr: 0x"))
        .expect("probe must report its slot address");
    u64::from_str_radix(line.trim(), 16).expect("slot address is hex")
}

fn extent_of(path: &Path) -> Vec<Range> {
    elf::classify(&read(path)).expect("classify").ranges
}

fn is_in_extent(ranges: &[Range], file_off: u32) -> bool {
    ranges
        .iter()
        .any(|r| file_off >= r.file_off && file_off < r.file_off + r.len)
}

/// A file offset inside the extent — specifically in the executable
/// segment, which is the last and largest range.
fn offset_inside_extent(path: &Path) -> usize {
    let ranges = extent_of(path);
    let last = ranges.last().expect("extent has ranges");
    let off = last.file_off + last.len / 2;
    assert!(
        is_in_extent(&ranges, off),
        "premise failed: chosen offset {off:#x} is not in the extent"
    );
    off as usize
}

/// A file offset the loader rewrites — inside a writable segment, and
/// therefore outside the extent by construction.
fn offset_the_loader_rewrites(path: &Path) -> usize {
    let bytes = read(path);
    let writable = elf::writable_ranges(&bytes).expect("writable ranges");
    let first = writable.first().expect("image has a writable segment");
    // Into the segment rather than at its very edge, so the byte is a
    // relocated word rather than a boundary artefact.
    let off = first.file_off + 0x10;
    assert!(
        off < first.file_off + first.len,
        "premise failed: writable segment is too small"
    );
    assert!(
        !is_in_extent(&extent_of(path), off),
        "premise failed: chosen offset {off:#x} IS in the extent, so this is not the control it claims to be"
    );
    off as usize
}

// ---------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------

#[test]
fn an_unsigned_artifact_refuses_to_become_operational() {
    let probe = copy_probe("unsigned");
    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, SLOT_INVALID,
        "an unsigned artifact must refuse, and say so as a slot defect rather than a mismatch"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The status indicator distinguishes the failure causes the runner cannot.
///
/// `initialize_with_tests` reports every self-test failure as the same
/// payload-less `SelfTestFailure`, so a consumer reading its return value
/// cannot tell a corrupt module from an environment that could not supply
/// the module's bytes. Security Policy §5.2 requires that distinction to
/// be retrievable; this pins that it is, through a real boot rather than
/// by calling the verifier directly.
#[test]
fn the_status_indicator_distinguishes_causes_the_boot_result_cannot() {
    let signed = copy_probe("status-signed");
    sign(&signed);
    let (code, out) = run(&signed, &[]);
    assert_eq!(code, OPERATIONAL, "control: the signed artifact must boot");
    assert_eq!(
        status(&out),
        STATUS_PASSED,
        "a verified image must report Passed"
    );
    let _ = std::fs::remove_file(&signed);

    // Same binary, unsigned: the boot result is only "a self-test
    // failed", but the indicator names the cause.
    let unsigned = copy_probe("status-unsigned");
    let (code, out) = run(&unsigned, &[]);
    assert_eq!(
        code, SLOT_INVALID,
        "control: the unsigned artifact must refuse"
    );
    assert_eq!(
        status(&out),
        STATUS_SLOT_INVALID,
        "an unsigned artifact must report SlotInvalid, not Mismatch — the two send an operator to \
         different places"
    );
    let _ = std::fs::remove_file(&unsigned);
}

#[test]
fn a_signed_artifact_verifies_its_own_loaded_image_and_boots() {
    let probe = copy_probe("signed");
    sign(&probe);
    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, OPERATIONAL,
        "a signed artifact must reach Operational"
    );
    let _ = std::fs::remove_file(&probe);
}

#[test]
fn a_byte_changed_inside_the_extent_is_detected() {
    let probe = copy_probe("tamper-code");
    sign(&probe);
    let off = offset_inside_extent(&probe);
    flip(&probe, off);
    let (code, out) = run(&probe, &[]);
    assert_eq!(code, MISMATCH, "a changed code byte must fail the test");
    // The exit code comes from the probe's own match on `IntegrityError`;
    // the indicator comes from `IntegrityStatus::of`. Asserting only the
    // former leaves the mapping unpinned, so assert both.
    assert_eq!(
        status(&out),
        STATUS_MISMATCH,
        "a corrupt image must report Mismatch, not another cause"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The mirror control, and the one that carries the design.
///
/// Changing a byte the loader rewrites must **not** fail: those bytes
/// are outside the extent on purpose. Without this, the two tamper tests
/// above are equally consistent with hashing the whole file — which is
/// the scheme this design replaced.
#[test]
fn a_byte_the_loader_rewrites_is_outside_the_extent() {
    let probe = copy_probe("tamper-relro");
    sign(&probe);
    let off = offset_the_loader_rewrites(&probe);
    flip(&probe, off);
    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, OPERATIONAL,
        "a byte in a writable segment is not in the extent, so it must not affect the verdict"
    );
    let _ = std::fs::remove_file(&probe);
}

#[test]
fn a_changed_reference_mac_is_detected() {
    let probe = copy_probe("tamper-mac");
    sign(&probe);
    let bytes = read(&probe);
    let slot_off = image::find_slot(&bytes).expect("find slot");
    flip(&probe, slot_off + oxicrypt_integrity::slot::OFF_MAC);
    let (code, _) = run(&probe, &[]);
    assert_eq!(code, MISMATCH, "a changed reference MAC must fail the test");
    let _ = std::fs::remove_file(&probe);
}

/// Twenty passes mean the hashed region produced the identical MAC
/// twenty times: had any byte in it varied between runs, the comparison
/// against the fixed reference would have failed. The ASLR assertion is
/// the control — a stable verdict from an image that never moved would
/// be no evidence of relocation stability at all.
#[test]
fn the_extent_is_relocation_stable_across_twenty_runs() {
    let probe = copy_probe("stability");
    sign(&probe);
    let mut addresses = std::collections::BTreeSet::new();
    for i in 0..20 {
        let (code, stdout) = run(&probe, &[]);
        assert_eq!(code, OPERATIONAL, "run {i} did not reach Operational");
        addresses.insert(slot_addr(&stdout));
    }
    assert!(
        addresses.len() > 1,
        "control failed: the image loaded at the same address all 20 times, so a stable \
         verdict proves nothing about relocation stability (is ASLR disabled?)"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The negative control for the test above.
///
/// An extent widened to cover a writable segment must fail, because the
/// loader has rewritten those bytes and they no longer match the file the
/// signer hashed. This is what makes the twenty-run result meaningful:
/// the probe demonstrably can detect an unstable region, so a STABLE
/// verdict is a finding rather than a silent no-op.
#[test]
fn an_extent_widened_to_a_relocated_region_fails() {
    let probe = copy_probe("widened");
    let mut bytes = read(&probe);
    let layout = elf::classify(&bytes).expect("classify");
    let writable = elf::writable_ranges(&bytes).expect("writable ranges");
    let relocated = *writable.first().expect("image has a writable segment");

    let mut widened = layout.ranges.clone();
    widened.push(relocated);
    widened.sort_by_key(|r| r.rva);
    assert!(
        widened.len() > layout.ranges.len(),
        "premise failed: the extent was not actually widened"
    );

    write_extent(&mut bytes, &widened, layout.slot_rva, layout.slot_file_off)
        .expect("write widened extent");
    write(&probe, &bytes);

    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, MISMATCH,
        "an extent covering loader-written bytes must fail — if this passes, the probe cannot \
         detect an unstable region and the stability result above is worthless"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The technique's CAST must precede the integrity test.
///
/// `--skip-cast` omits it from the inventory. The refusal is what makes
/// AS10.20 ordering a checked property rather than a convention about
/// the order of a list.
#[test]
fn omitting_the_technique_cast_makes_the_integrity_test_refuse() {
    let probe = copy_probe("skip-cast");
    sign(&probe);

    let (ordinary, _) = run(&probe, &[]);
    assert_eq!(
        ordinary, OPERATIONAL,
        "control: the same artifact must boot when the CAST is present"
    );

    let (code, out) = run(&probe, &["--skip-cast"]);
    assert_eq!(
        code, CAST_NOT_RUN,
        "the integrity test must refuse to use HMAC before its CAST has passed"
    );
    assert_eq!(
        status(&out),
        STATUS_CAST_NOT_RUN,
        "a sequencing fault must report CastNotRun rather than reading as corruption"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The indicator latches on the first run and a later run cannot revise it.
///
/// `verify_loaded_image` is public and may be called again after boot. If
/// the record simply took the most recent outcome, a second run that
/// succeeds would rewrite the indicator to `Passed` while the module
/// stayed permanently latched in `Error` — the query would then
/// contradict the module state it exists to explain.
///
/// `--relatch-probe` is the only arrangement that can tell the two apart:
/// boot with the CAST omitted so the first run records `CastNotRun`, then
/// run the CAST and verify again, which on this signed artifact succeeds.
/// A latching record still reports 5; a last-write-wins record reports 1.
#[test]
fn the_indicator_latches_and_a_later_successful_run_cannot_revise_it() {
    let probe = copy_probe("relatch");
    sign(&probe);

    let (_, out) = run(&probe, &["--skip-cast", "--relatch-probe"]);
    assert!(
        out.contains("second-run-ok: true"),
        "control: the second run must actually SUCCEED, or this test cannot \
         distinguish a latch from last-write-wins — got: {out}"
    );
    assert_eq!(
        status(&out),
        STATUS_CAST_NOT_RUN,
        "the indicator must still report the first run's CastNotRun, not the second run's success"
    );
    let _ = std::fs::remove_file(&probe);
}

/// A module initialised with no integrity group must refuse to operate.
///
/// `--no-integrity` boots the way a front end that never wired the test
/// in would: an empty inventory. `initialize_with_tests` refuses it and
/// latches `IntegrityUnverified` rather than treating an empty group as
/// "nothing to check".
///
/// This is the control the probe was built to carry and, until now, the
/// only one never exercised — so deleting the `integrity.is_empty()`
/// guard broke no test. Note what it does NOT establish: the guard
/// checks that a group was supplied, never that the supplied group is
/// the real one. A caller passing a counterfeit entry still reaches
/// `Operational`, by design and by disclosure.
#[test]
fn a_module_initialised_with_no_integrity_group_refuses_to_operate() {
    let probe = copy_probe("no-integrity");
    sign(&probe);

    let (ordinary, _) = run(&probe, &[]);
    assert_eq!(
        ordinary, OPERATIONAL,
        "control: the same signed artifact must boot when the group is present"
    );

    let (code, _) = run(&probe, &["--no-integrity"]);
    assert_eq!(
        code, INTEGRITY_UNVERIFIED,
        "an empty integrity group must latch IntegrityUnverified, not become operational"
    );
    let _ = std::fs::remove_file(&probe);
}

/// Signing twice must produce the same artifact.
///
/// The slot is outside the extent, so writing the MAC cannot change the
/// bytes the MAC was computed over. Re-signing an already-signed artifact
/// is therefore a no-op — which is the circularity resolution, observable
/// from outside.
#[test]
fn signing_is_idempotent_because_the_slot_is_outside_the_extent() {
    let probe = copy_probe("idempotent");
    sign(&probe);
    let once = read(&probe);
    sign(&probe);
    let twice = read(&probe);
    assert_eq!(
        once, twice,
        "re-signing changed the artifact, so the slot is inside the hashed extent"
    );
    let (code, _) = run(&probe, &[]);
    assert_eq!(code, OPERATIONAL);
    let _ = std::fs::remove_file(&probe);
}
