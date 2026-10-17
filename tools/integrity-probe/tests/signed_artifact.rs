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

use oxicrypt_integrity::slot::{EntryKind, Range};
use oxicrypt_integrity_sign::{
    SigningKey, elf, embed_verify_key, image, sign_image, write_entries,
};

/// The probe binary cargo built for this test run.
const PROBE: &str = env!("CARGO_BIN_EXE_integrity-probe");

/// Status indicators, mirroring the probe's exit codes.
const OPERATIONAL: i32 = 0;
const SIGNATURE_INVALID: i32 = 3;
const SLOT_INVALID: i32 = 4;
const CAST_NOT_RUN: i32 = 7;
const INTEGRITY_UNVERIFIED: i32 = 9;
const NO_VERIFY_KEY: i32 = 10;
const KEY_MISMATCH: i32 = 11;
/// Status-indicator discriminants, as `IntegrityStatus` numbers them.
const STATUS_PASSED: u8 = 1;
const STATUS_SLOT_INVALID: u8 = 3;
const STATUS_SIGNATURE_INVALID: u8 = 2;
const STATUS_CAST_NOT_RUN: u8 = 5;
const STATUS_NO_VERIFY_KEY: u8 = 8;

/// The key pair these tests sign with, derived once per test process from a
/// fixed seed.
///
/// Cargo builds the probe without `OXICRYPT_INTEGRITY_VERIFY_KEY`, so each
/// copy has the test key's public half written into its key record first,
/// which is what a build with the variable set produces.
fn test_key() -> &'static SigningKey {
    static KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| SigningKey::from_seed(&[0x42; 32]).expect("derive the test key pair"))
}

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

/// An unsigned copy of the probe embedding the test key, executable.
fn copy_probe(tag: &str) -> PathBuf {
    let dst = scratch(tag);
    let mut bytes = read(Path::new(PROBE));
    embed_verify_key(&mut bytes, test_key().public_key()).expect("embed the test key");
    write(&dst, &bytes);
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

/// Signs an artifact in place with the test key, the way the build
/// pipeline would.
fn sign(path: &Path) {
    let mut bytes = read(path);
    sign_image(&mut bytes, test_key()).expect("sign");
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

/// The status indicator the probe reported.
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

/// A file offset inside the extent that nothing parses or executes before
/// the integrity test: padding between two sections.
fn offset_inside_extent(path: &Path) -> usize {
    let ranges = extent_of(path);
    let extent: Vec<(u32, u32)> = ranges.iter().map(|r| (r.file_off, r.len)).collect();
    let off = padding::padding_offset(&read(path), &extent);
    assert!(
        is_in_extent(&ranges, u32::try_from(off).expect("offset fits u32")),
        "premise failed: chosen offset {off:#x} is not in the extent"
    );
    off
}

/// Padding between sections: a hashed byte nothing executes before the
/// integrity test runs.
#[path = "../../integrity-probe-so/tests/padding/mod.rs"]
mod padding;

/// A file offset the loader overwrites without reading: a byte of a
/// relocation destination, which the extent types as a `Hole`.
fn offset_the_loader_rewrites(path: &Path) -> usize {
    let layout = elf::classify(&read(path)).expect("classify");
    let carrier = layout
        .entries
        .iter()
        .find(|e| e.hole_len() > 0)
        .expect("premise failed: the image has no relocation destination");
    let off = carrier.file_off + carrier.len + 1;
    assert!(
        !is_in_extent(&extent_of(path), off),
        "premise failed: chosen offset {off:#x} IS in the hashed extent, so this is not the control it claims to be"
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
/// the module's bytes. An operator must be able to retrieve that
/// distinction; this pins that it can, through a real boot rather than
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
        "an unsigned artifact must report SlotInvalid, not SignatureInvalid: the two send an \
         operator to different places"
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
    assert_eq!(
        code, SIGNATURE_INVALID,
        "a changed code byte must fail the test"
    );
    // The exit code and the printed indicator both come from the latched
    // `IntegrityStatus`; asserting both pins the probe's mapping as well as
    // the indicator.
    assert_eq!(
        status(&out),
        STATUS_SIGNATURE_INVALID,
        "a corrupt image must report SignatureInvalid, not another cause"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The mirror control, and the one that carries the design.
///
/// Changing a byte the loader overwrites must **not** fail: a relocation
/// destination is a `Hole`, its value covered by the relocation table.
/// Without this, the tamper tests in this file are equally consistent with
/// an extent that hashes the whole file.
#[test]
fn a_byte_the_loader_rewrites_is_outside_the_extent() {
    let probe = copy_probe("tamper-relro");
    sign(&probe);
    let off = offset_the_loader_rewrites(&probe);
    flip(&probe, off);
    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, OPERATIONAL,
        "a byte of a relocation destination is a hole, so it must not affect the verdict"
    );
    let _ = std::fs::remove_file(&probe);
}

/// A changed byte of initialised writable data, which the extent hashes
/// from the image file, is detected.
#[test]
fn a_changed_file_only_byte_is_detected() {
    let probe = copy_probe("tamper-fileonly");
    sign(&probe);
    let layout = elf::classify(&read(&probe)).expect("classify");
    let data = layout
        .entries
        .iter()
        .find(|e| e.kind == EntryKind::FileOnly)
        .expect("premise failed: the image has no FileOnly region");
    flip(&probe, (data.file_off + data.len / 2) as usize);
    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, SIGNATURE_INVALID,
        "a changed FileOnly byte must be refused"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The file offset of `.dynamic`'s `DT_PLTGOT` value: a `Relative` word
/// glibc rebases but, with every symbol bound at load, never reads, so a
/// change to it survives loading and reaches the integrity test.
fn pltgot_value_offset(bytes: &[u8]) -> usize {
    let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]) as usize;
    let u64_at = |o: usize| {
        usize::try_from(u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap())).unwrap()
    };
    let (phoff, phnum) = (u64_at(0x20), u16_at(0x38));
    let dynamic = (0..phnum)
        .map(|i| phoff + 56 * i)
        .find(|&p| u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) == 2)
        .expect("premise failed: no PT_DYNAMIC");
    let (off, len) = (u64_at(dynamic + 8), u64_at(dynamic + 32));
    (off..off + len)
        .step_by(16)
        .find(|&e| u64_at(e) == 3)
        .map(|e| e + 8)
        .expect("premise failed: no DT_PLTGOT")
}

/// A changed `Relative` word is detected: the loader adds the load bias to
/// it, and the integrity test checks it after subtracting that bias.
#[test]
fn a_changed_relative_word_is_detected() {
    let probe = copy_probe("tamper-relative");
    sign(&probe);
    let bytes = read(&probe);
    let off = pltgot_value_offset(&bytes);
    let layout = elf::classify(&bytes).expect("classify");
    assert!(
        layout.entries.iter().any(|e| e.kind == EntryKind::Relative
            && (e.file_off as usize..(e.file_off + e.len) as usize).contains(&off)),
        "premise failed: DT_PLTGOT's value at {off:#x} is not a Relative entry"
    );
    let mut tampered = bytes;
    tampered[off + 1] ^= 0x08;
    write(&probe, &tampered);
    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, SIGNATURE_INVALID,
        "a changed Relative word must be refused"
    );
    let _ = std::fs::remove_file(&probe);
}

/// A symbol table that has lost the module's state symbol, as a strip of
/// that one symbol leaves it, cannot show the state is not file-backed, so
/// signing is refused.
#[test]
fn signing_refuses_a_symbol_table_without_the_module_state() {
    let probe = copy_probe("strip-state");
    let bytes = read(&probe);
    let state = std::process::Command::new("readelf")
        .args(["-sW"])
        .arg(&probe)
        .output()
        .expect("premise failed: readelf did not run");
    let listing = String::from_utf8_lossy(&state.stdout).into_owned();
    let name = listing
        .split_whitespace()
        .find(|w| w.contains("15oxicrypt_module5STATE"))
        .expect("premise failed: the probe's symbol table names no module state")
        .to_owned();
    let stripped = scratch("strip-state-out");
    let status = std::process::Command::new("objcopy")
        .arg(format!("--strip-symbol={name}"))
        .arg(&probe)
        .arg(&stripped)
        .status()
        .expect("premise failed: objcopy did not run");
    assert!(status.success(), "premise failed: objcopy failed");
    let mut out = read(&stripped);
    let after = std::process::Command::new("readelf")
        .args(["-sW"])
        .arg(&stripped)
        .output()
        .expect("premise failed: readelf did not run");
    assert!(
        !String::from_utf8_lossy(&after.stdout).contains(&name),
        "premise failed: the state symbol survived in the symbol table"
    );
    let err = sign_image(&mut out, test_key()).expect_err("signing must be refused");
    assert!(
        err.starts_with("StaticsUnchecked") && err.contains("oxicrypt_module::STATE"),
        "{err}"
    );
    // Control: the unstripped copy signs.
    assert!(sign_image(&mut bytes.clone(), test_key()).is_ok());
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_file(&stripped);
}

#[test]
fn a_changed_signature_is_detected() {
    let probe = copy_probe("tamper-sig");
    sign(&probe);
    let bytes = read(&probe);
    let slot_off = image::find_slot(&bytes).expect("find slot");
    flip(&probe, slot_off + oxicrypt_integrity::slot::OFF_SIG);
    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, SIGNATURE_INVALID,
        "a changed signature must fail the test"
    );
    let _ = std::fs::remove_file(&probe);
}

/// The boot reports the fingerprint of the key it verified against, and it
/// is the test key's.
#[test]
fn the_module_reports_the_key_it_verified_against() {
    let probe = copy_probe("fingerprint");
    sign(&probe);
    let (code, out) = run(&probe, &[]);
    assert_eq!(code, OPERATIONAL);
    let expected = oxicrypt_integrity::format_fingerprint(
        &test_key().fingerprint().expect("fingerprint the test key"),
    );
    assert!(
        out.contains(&format!("verify-key: {expected}")),
        "the reported fingerprint must be the embedded key's, got: {out}"
    );
}

/// A module built without a verifying key never becomes operational, and
/// says why.
#[test]
fn a_module_without_a_verifying_key_reports_no_verify_key() {
    let probe = copy_probe("no-key");
    let mut bytes = read(&probe);
    embed_verify_key(&mut bytes, &[0u8; oxicrypt_integrity::key::VERIFY_KEY_LEN])
        .expect("clear the key");
    write(&probe, &bytes);
    let (code, out) = run(&probe, &[]);
    assert_eq!(
        code, NO_VERIFY_KEY,
        "a key-less build must refuse to operate"
    );
    assert_eq!(status(&out), STATUS_NO_VERIFY_KEY);
    let _ = std::fs::remove_file(&probe);
}

/// A slot signed for one key in an artifact that embeds another is a key
/// mismatch, refused before any signature is checked.
#[test]
fn an_artifact_embedding_a_different_key_reports_key_mismatch() {
    let probe = copy_probe("key-mismatch");
    sign(&probe);
    let other = SigningKey::from_seed(&[0x24; 32]).expect("derive a second key");
    let mut bytes = read(&probe);
    embed_verify_key(&mut bytes, other.public_key()).expect("swap the key");
    write(&probe, &bytes);
    let (code, _) = run(&probe, &[]);
    assert_eq!(code, KEY_MISMATCH);
    let _ = std::fs::remove_file(&probe);
}

/// Twenty passes mean the signed region read back identically twenty
/// times: had any byte in it varied between runs, the signature would have
/// failed to verify. The ASLR assertion is
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
/// An extent that hashes the relocation destinations as `Plain` must fail,
/// because the loader has rewritten those bytes and they no longer match the
/// file the signer hashed. This is what makes the twenty-run result meaningful:
/// the probe demonstrably can detect an unstable region, so a STABLE
/// verdict is a finding rather than a silent no-op.
#[test]
fn an_extent_widened_to_a_relocated_region_fails() {
    let probe = copy_probe("widened");
    let mut bytes = read(&probe);
    let layout = elf::classify(&bytes).expect("classify");
    let mut widened = layout.entries.clone();
    let mut retyped = 0;
    for e in &mut widened {
        if e.kind == EntryKind::Hole {
            e.kind = EntryKind::Plain;
            retyped += 1;
        } else if e.kind == EntryKind::Plain && e.meta > 0 {
            e.len += e.hole_len();
            e.meta = 0;
            retyped += 1;
        }
    }
    assert!(
        retyped > 0,
        "premise failed: no relocation destination was retyped"
    );

    write_entries(&mut bytes, &layout, &widened, test_key()).expect("write widened extent");
    write(&probe, &bytes);

    let (code, _) = run(&probe, &[]);
    assert_eq!(
        code, SIGNATURE_INVALID,
        "an extent covering loader-written bytes must fail; if this passes, the probe cannot \
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
        "the integrity test must refuse to use ML-DSA-87 before its CAST has passed"
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
/// the record simply took the most recent outcome, a second run would
/// rewrite the indicator while the module stayed permanently latched in
/// `Error` — the query would then contradict the module state it exists
/// to explain.
///
/// `--relatch-probe` on a tampered artifact tells the two apart: the boot's
/// run records `SignatureInvalid`, then the probe verifies again. The module
/// has latched its error state and refuses its primitives, so the second
/// run's outcome differs, and a direct call records nothing: the indicator
/// must still report 2.
#[test]
fn the_indicator_latches_and_a_later_run_cannot_revise_it() {
    let probe = copy_probe("relatch");
    sign(&probe);
    let off = offset_inside_extent(&probe);
    flip(&probe, off);

    let (code, out) = run(&probe, &["--relatch-probe"]);
    assert_eq!(
        code, SIGNATURE_INVALID,
        "control: the tampered artifact must fail its boot"
    );
    assert!(
        out.contains("second-run-refused: true"),
        "control: the second run must reach a DIFFERENT outcome, or this test cannot \
         distinguish a latch from last-write-wins — got: {out}"
    );
    assert_eq!(
        status(&out),
        STATUS_SIGNATURE_INVALID,
        "the indicator must still report the first run's SignatureInvalid, not the second run's \
         refusal"
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

/// Signing again writes only the signature field, and writes the same
/// signature.
///
/// The signature field is the one byte range the signature does not cover,
/// so writing it cannot change what was signed. ML-DSA-87 signing here is
/// deterministic, so re-signing a file whose signature field was cleared
/// restores it byte for byte, and nothing else in the file moves.
#[test]
fn re_signing_changes_only_the_signature_field() {
    let probe = copy_probe("resign");
    sign(&probe);
    let once = read(&probe);
    let slot_off = image::find_slot(&once).expect("find slot");
    let sig = slot_off + oxicrypt_integrity::slot::OFF_SIG
        ..slot_off + oxicrypt_integrity::slot::OFF_SIG + oxicrypt_integrity::slot::SIG_LEN;
    let mut cleared = once.clone();
    cleared[sig.clone()].fill(0);
    assert_ne!(cleared, once, "control: the signature field was not empty");
    write(&probe, &cleared);
    sign(&probe);
    let twice = read(&probe);
    let changed: Vec<usize> = (0..once.len())
        .filter(|&i| cleared[i] != twice[i])
        .collect();
    assert!(
        !changed.is_empty(),
        "control: re-signing wrote the cleared signature field"
    );
    assert!(
        changed.iter().all(|i| sig.contains(i)),
        "re-signing changed a byte outside the signature field"
    );
    assert_eq!(twice, once, "re-signing wrote a different signature");
    let (code, _) = run(&probe, &[]);
    assert_eq!(code, OPERATIONAL);
    let _ = std::fs::remove_file(&probe);
}
