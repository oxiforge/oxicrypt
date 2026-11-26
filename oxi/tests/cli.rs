//! The `oxi` CLI, exercised end to end on a real binary.
//!
//! Every test here copies the `oxi` cargo just built — which is unsigned,
//! because nothing signs a cargo build — runs it, and reads the outcome off
//! the exit code and the output. Cargo builds it without
//! `OXICRYPT_INTEGRITY_VERIFY_KEY`, so each copy has a test key's public half
//! written into its key record first, which is what a build with the variable
//! set produces; the tests then sign with the matching private half. That is
//! the only honest way to exercise this: the property under test is that a
//! signed binary starts and an unsigned or altered one refuses, and neither
//! can be seen until the binary is run.
//!
//! **Each test asserts its own premise.** A test that flips a byte "in the
//! code" proves nothing if the offset it picked was elsewhere, and the failure
//! would look exactly like a pass. The offset is checked against the extent
//! before it is used, and the remedy tests are paired with a case that must
//! NOT produce the remedy.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use oxicrypt_integrity::slot::Range;
use oxicrypt_integrity_sign::SigningKey;

/// The power-up inventory the binary runs, compiled from the file the binary
/// builds it from, so a count derived here is the count the binary runs.
#[path = "../src/power_up.rs"]
mod power_up;

/// The `oxi` cargo built for this test run. Unsigned: a cargo build has no
/// step after linking, which is why an installed `oxi` must be signed.
const OXI: &str = env!("CARGO_BIN_EXE_oxi");

/// The literal a person reads when an installed `oxi` refuses to start. It is
/// pinned because it is the entire remedy: a failure that names a test instead
/// of a command leaves the reader with nothing to do.
const REMEDY: &str = "oxicrypt-integrity-sign --sign";

/// The key pair these tests sign with, derived once per test process from a
/// fixed seed.
fn test_key() -> &'static SigningKey {
    static KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| SigningKey::from_seed(&[0x42; 32]).expect("derive the test key pair"))
}

/// A copy of `oxi` in a scratch directory of its own, removed with the
/// directory when the test ends, whether it passed or failed.
struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent()
            && let Err(e) = std::fs::remove_dir_all(dir)
        {
            eprintln!("could not remove {}: {e}", dir.display());
        }
    }
}

fn scratch(tag: &str) -> Scratch {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    p.push(format!("oxi-cli-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).expect("create scratch dir");
    p.push(if cfg!(windows) { "oxi.exe" } else { "oxi" });
    let mut bytes = std::fs::read(OXI).expect("read oxi");
    oxicrypt_integrity_sign::embed_verify_key(&mut bytes, test_key().public_key())
        .expect("embed the test key");
    std::fs::write(&p, &bytes).expect("copy oxi");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    Scratch(p)
}

/// Runs the artifact and returns `(exit code, stdout, stderr)`.
///
/// Retries on `ETXTBSY`: these tests write an artifact and then execute it,
/// several at a time, and a sibling test's in-flight write can be inherited
/// across another thread's fork-to-exec gap. The window closes on its own and
/// says nothing about the artifact.
fn run(path: &Path, args: &[&str]) -> (i32, String, String) {
    let dir = path.parent().expect("artifact has a parent").to_owned();
    run_in(&dir, path, args)
}

/// Runs the artifact with an explicit working directory.
///
/// Which directory the child runs in matters for exactly one test: a file whose
/// name IS a flag has to be reachable as the bare argument `--integrity`, since
/// passing a path to it would not exercise the case at all.
fn run_in(dir: &Path, path: &Path, args: &[&str]) -> (i32, String, String) {
    const ETXTBSY: i32 = 26;
    let mut waited = std::time::Duration::ZERO;
    let step = std::time::Duration::from_millis(20);
    let out = loop {
        match Command::new(path).args(args).current_dir(dir).output() {
            Ok(out) => break out,
            Err(e)
                if e.raw_os_error() == Some(ETXTBSY)
                    && waited < std::time::Duration::from_secs(5) =>
            {
                std::thread::sleep(step);
                waited += step;
            }
            Err(e) => panic!("run {}: {e}", path.display()),
        }
    };
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read artifact")
}

/// Signs an artifact in place, the way the build pipeline does.
///
/// The same library call `oxicrypt-integrity-sign --sign` makes, so a test
/// cannot diverge from the tool consumers actually run. `oxi` has no signing
/// path of its own — deliberately — so producing a signed binary is something
/// the test must do for it.
fn sign(path: &Path) {
    let mut bytes = read(path);
    oxicrypt_integrity_sign::sign_image(&mut bytes, test_key()).expect("sign");
    std::fs::write(path, &bytes).expect("write artifact");
    oxicrypt_integrity_sign::verify_image(&read(path)).expect("the signed artifact verifies");
}

fn extent_of(path: &Path) -> Vec<Range> {
    oxicrypt_integrity_sign::classify(&read(path))
        .expect("classify")
        .ranges
}

fn is_in_extent(ranges: &[Range], file_off: u32) -> bool {
    ranges
        .iter()
        .any(|r| file_off >= r.file_off && file_off < r.file_off + r.len)
}

/// A file offset inside the extent, in embedded read-only **data** rather
/// than in code.
///
/// The middle of the executable range is the wrong choice here. `oxi` embeds
/// a large binary; a byte chosen by arithmetic lands on an arbitrary
/// instruction, and corrupting one on the path the
/// process takes *before* the integrity test runs kills it in the loader or on
/// an illegal instruction. The process then exits non-zero having printed
/// nothing, which is indistinguishable from the integrity test correctly
/// refusing — the test would pass for entirely the wrong reason.
///
/// So the target is the embedded LAMA manifest: read-only data, inside the
/// extent, and reachable only from `--lama`, which these tests never call.
/// Corrupting it cannot change control flow. The offset is located by
/// searching for the manifest's own first line, so it is derived from the
/// artifact rather than guessed, and it is checked against the extent before
/// it is used.
fn offset_inside_extent(path: &Path) -> usize {
    const MARKER: &[u8] = b"lama: \"0.1\"";
    let bytes = read(path);
    let found = bytes
        .windows(MARKER.len())
        .position(|w| w == MARKER)
        .expect("premise failed: the embedded LAMA manifest is not in this binary");
    // Past the marker itself, so the flip cannot disturb the search that finds
    // it again on a later run.
    let off = u32::try_from(found + MARKER.len() + 8).expect("offset fits u32");
    let ranges = extent_of(path);
    assert!(
        is_in_extent(&ranges, off),
        "premise failed: chosen offset {off:#x} is not in the extent"
    );
    off as usize
}

fn flip(path: &Path, offset: usize) {
    let mut bytes = read(path);
    bytes[offset] ^= 0xff;
    std::fs::write(path, &bytes).expect("write artifact");
}

/// An unsigned binary tells the reader the one command that fixes it, on the
/// ordinary path — not only when asked with `--integrity`.
#[test]
fn an_unsigned_binary_names_the_command_that_fixes_it() {
    let oxi = scratch("remedy");

    let (code, _, stderr) = run(&oxi, &["hash", "sha256", OXI]);
    assert_ne!(code, 0, "an unsigned binary must refuse to run a service");
    assert!(
        stderr.contains(REMEDY),
        "the startup failure must name `{REMEDY}`, got:\n{stderr}"
    );

    // The paired control. Without it this test passes on a build that prints
    // the remedy unconditionally, which would be advice on a binary that has
    // nothing wrong with it.
    sign(&oxi);
    let (code, _, stderr) = run(&oxi, &["hash", "sha256", OXI]);
    assert_eq!(code, 0, "a signed binary must run the service");
    assert!(
        !stderr.contains(REMEDY),
        "a signed binary must not print the remedy, got:\n{stderr}"
    );
}

/// The unsigned remedy names the Apple code-signing order, after the
/// integrity signer's own line. On Apple platforms the integrity signer alone
/// leaves a binary whose code signature is stale, and the final code signature
/// is correct only in the `--reserved-against` order, so a remedy without
/// this line is incomplete there.
#[test]
fn the_unsigned_remedy_renews_the_apple_code_signature_after_signing() {
    let oxi = scratch("remedy-apple");

    let (code, _, stderr) = run(&oxi, &["hash", "sha256", OXI]);
    assert_ne!(code, 0, "an unsigned binary must refuse to run a service");
    let sign_at = stderr
        .find(REMEDY)
        .unwrap_or_else(|| panic!("the remedy must name `{REMEDY}`, got:\n{stderr}"));
    let apple_at = stderr
        .find("--reserved-against, in the order the Apple section of")
        .unwrap_or_else(|| panic!("the remedy must name the Apple order, got:\n{stderr}"));
    assert!(
        sign_at < apple_at,
        "the Apple order must come after the integrity signer, got:\n{stderr}"
    );
}

/// The claim itself: an unsigned binary refuses, a signed one is operational.
#[test]
fn signing_makes_the_next_invocation_operational() {
    let oxi = scratch("operational");

    let (code, _, _) = run(&oxi, &["--integrity"]);
    assert_ne!(
        code, 0,
        "an unsigned binary must not report integrity passed"
    );

    sign(&oxi);

    let (code, stdout, _) = run(&oxi, &["--integrity"]);
    assert_eq!(code, 0, "integrity must pass once signed: {stdout}");
    assert!(stdout.contains("passed"), "got: {stdout}");
    let fingerprint =
        oxicrypt_integrity::format_fingerprint(&test_key().fingerprint().expect("fingerprint"));
    assert!(
        stdout.contains(&format!("verify key: {fingerprint}")),
        "--integrity must report the key the binary trusts, got: {stdout}"
    );

    let (code, _, stderr) = run(&oxi, &["hash", "sha256", OXI]);
    assert_eq!(code, 0, "a service must run once signed: {stderr}");
}

/// A binary built without a verifying key says so, and says how to build one
/// that has one, rather than reporting a missing signature.
#[test]
fn a_binary_without_a_verifying_key_names_the_build_variable() {
    let oxi = scratch("no-key");
    let mut bytes = read(&oxi);
    oxicrypt_integrity_sign::embed_verify_key(
        &mut bytes,
        &[0u8; oxicrypt_integrity::key::VERIFY_KEY_LEN],
    )
    .expect("clear the key");
    std::fs::write(&oxi, &bytes).expect("write artifact");

    let (code, stdout, _) = run(&oxi, &["--integrity"]);
    assert_eq!(code, 3, "the test was not performed: {stdout}");
    assert!(
        stdout.contains("without a verifying key")
            && stdout.contains("OXICRYPT_INTEGRITY_VERIFY_KEY"),
        "got: {stdout}"
    );
}

/// Signing has not disabled the test it exists to satisfy.
///
/// This is the control on `signing_makes_the_next_invocation_operational`.
/// Without it, a signing step that
/// wrote a slot the verifier ignores would pass every other test here.
#[test]
fn a_byte_changed_inside_the_extent_after_signing_is_detected() {
    let oxi = scratch("tamper");
    sign(&oxi);
    let (code, _, _) = run(&oxi, &["hash", "sha256", OXI]);
    assert_eq!(code, 0, "premise failed: the signed binary does not run");

    flip(&oxi, offset_inside_extent(&oxi));

    let (code, _, _) = run(&oxi, &["hash", "sha256", OXI]);
    assert_ne!(code, 0, "a tampered binary must refuse to run a service");
    let (code, stdout, _) = run(&oxi, &["--integrity"]);
    assert_ne!(
        code, 0,
        "a tampered binary must not report integrity passed"
    );
    assert!(
        stdout.contains("FAILED"),
        "the tampered binary must say the image does not match, got: {stdout}"
    );
}

/// A file whose NAME is a flag is an operand, not a command.
///
/// A flag scanned across the whole of argv cannot tell itself from a file whose
/// NAME is that flag, so `oxi hash sha256 -- --integrity` would report on the
/// binary instead of hashing the file and exit 0 — a script hashing filenames it
/// did not choose would read the wrong thing as its digest. The pre-initialization
/// flags are matched at argv[1] only.
#[test]
fn a_file_operand_named_like_a_flag_is_not_a_command() {
    let oxi = scratch("operand");
    sign(&oxi);

    let dir = oxi.parent().expect("scratch has a parent").to_owned();
    let trap = dir.join("--integrity");
    std::fs::write(&trap, b"hello\n").expect("write the trap file");
    let before = read(&oxi);

    let (code, stdout, stderr) = run(&oxi, &["hash", "sha256", "--integrity"]);
    assert_eq!(code, 0, "hashing the file must succeed: {stderr}");
    // SHA-256 of "hello\n" — the file, not a report about the binary.
    assert!(
        stdout.contains("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"),
        "must print the digest of the FILE, got: {stdout}"
    );
    assert_eq!(
        before,
        read(&oxi),
        "hashing a file must not disturb the binary"
    );
}

/// Nothing signs itself unasked.
///
/// The anti-criterion. A cryptographic tool that rewrote its own binary on an
/// ordinary run would be doing the single thing this project's readers are
/// least willing to tolerate, and the saving would be one command.
#[test]
fn an_ordinary_invocation_of_an_unsigned_binary_writes_nothing() {
    let oxi = scratch("no-write");
    let dir = oxi.parent().expect("scratch has a parent").to_owned();
    let before = read(&oxi);
    let before_entries = entries(&dir);

    for args in [
        vec!["hash", "sha256", OXI],
        vec!["--integrity"],
        vec!["rand", "8"],
        vec!["--help"],
    ] {
        run(&oxi, &args);
    }

    assert_eq!(
        before,
        read(&oxi),
        "an ordinary invocation must not modify the binary"
    );
    assert_eq!(
        before_entries,
        entries(&dir),
        "an ordinary invocation must not leave files beside the binary"
    );

    // The control: the same comparison MUST see a difference when the binary
    // really is rewritten. Without it, a comparison that always succeeded
    // would read as proof of the property.
    sign(&oxi);
    assert_ne!(
        before,
        read(&oxi),
        "the comparison is vacuous: it cannot see a rewritten binary"
    );
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read scratch dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    v.sort();
    v
}

/// `oxi` has no path that writes to its own executable.
///
/// This guards an absence, not a behaviour. A binary
/// able to rewrite its own image gains nothing cryptographically — signing
/// needs a private key no shipped binary carries — and costs two real things. It would
/// link an executable-format parser into the very extent the integrity test
/// protects, and it would let a binary that has just FAILED the check re-sign
/// itself into passing.
///
/// A source scan, because the property is the absence of a capability and no
/// behavioural test can observe an absence. The signer remains a separate tool;
/// see `docs/integrity-signing.md`.
#[test]
fn oxi_never_writes_to_its_own_executable() {
    let src = strip_comments(include_str!("../src/main.rs"));
    let src = src.as_str();
    assert!(
        src.contains("fn main()"),
        "premise failed: comment stripping removed the source"
    );

    for forbidden in [
        "current_exe",
        "sign_image",
        "fs::rename",
        "File::create",
        "set_permissions",
        "fs::write",
    ] {
        assert!(
            !src.contains(forbidden),
            "`{forbidden}` appears in oxi's source — it must not be able to write its own image"
        );
    }

    // The controls: the scan reads real code, and would notice if any of the
    // above appeared. Both directions, or an empty `src` would pass.
    assert!(
        src.contains("oxicrypt_integrity::status()"),
        "premise failed: this scan is not reading oxi's main.rs"
    );
    assert!(
        format!("{src} current_exe").contains("current_exe"),
        "premise failed: the substring check cannot detect what it forbids"
    );
}

/// `src` with every `//` comment removed, so a scan reads code and not the
/// prose that explains why a capability is absent.
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => l.get(..i).unwrap_or_default(),
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `oxi` reads no operating-system entropy of its own: every random byte it
/// uses comes from a DRBG the module seeds. A source scan, for the same
/// reason as the one above.
#[test]
fn oxi_reads_no_operating_system_entropy() {
    // Each needle is assembled at run time, so this file's own source does
    // not contain the strings it forbids.
    let forbidden: Vec<String> = [
        ("uran", "dom"),
        ("getran", "dom"),
        ("OsR", "ng"),
        ("getentr", "opy"),
    ]
    .iter()
    .map(|(a, b)| format!("{a}{b}"))
    .collect();

    for (file, src) in [
        ("main.rs", include_str!("../src/main.rs")),
        ("power_up.rs", include_str!("../src/power_up.rs")),
        ("pq.rs", include_str!("../src/pq.rs")),
    ] {
        let code = strip_comments(src);
        assert!(
            code.contains("fn "),
            "premise failed: comment stripping removed {file}"
        );
        for needle in &forbidden {
            assert!(
                !code.contains(needle.as_str()),
                "`{needle}` appears in {file}: oxi must draw randomness from the module's DRBG"
            );
        }
    }
    assert!(
        format!("x {}", forbidden[0]).contains(forbidden[0].as_str()),
        "premise failed: the substring check cannot detect what it forbids"
    );
}

/// The on-demand self-test reports every test in the power-up inventory, and
/// its indicator agrees with its exit code.
#[test]
fn selftest_runs_the_whole_inventory_and_indicates_pass() {
    let oxi = scratch("selftest");
    sign(&oxi);

    let (code, stdout, stderr) = run(&oxi, &["selftest"]);
    assert_eq!(code, 0, "selftest must pass on a signed binary: {stderr}");

    // The count is read from the output and checked against the lines, so a
    // summary that said "0 of 0 passed" cannot report success. Without this the
    // whole test passes on a subcommand that ran nothing.
    let reported = stdout
        .lines()
        .find_map(|l| l.strip_suffix(" self-tests passed"))
        .and_then(|l| l.split_whitespace().next().map(str::to_owned))
        .expect("no summary line");
    let n: usize = reported.parse().expect("summary count is a number");
    let groups: Vec<(&str, usize)> = [
        ("integrity", oxicrypt_integrity::KATS.len()),
        ("entropy source", 1),
    ]
    .into_iter()
    .chain(
        power_up::inventory()
            .iter()
            .map(|(name, g)| (*name, g.len())),
    )
    .collect();
    let total: usize = groups.iter().map(|(_, len)| len).sum();
    assert_eq!(n, total, "the summary must count the whole power-up set");
    let ok_lines = stdout
        .lines()
        .filter(|l| l.trim_start().starts_with("ok    "))
        .count();
    assert_eq!(n, ok_lines, "the summary must count the lines it printed");

    // The verdict line, whose wording scripts match.
    assert!(
        stdout.contains("self-test indicator: PASS"),
        "the indicator line is required, got:\n{stdout}"
    );

    let mut after = 0;
    for (name, len) in &groups {
        let heading = format!("\n{name} ({len})\n");
        let at = stdout
            .get(after..)
            .and_then(|rest| rest.find(&heading))
            .unwrap_or_else(|| {
                panic!("`{name} ({len})` is missing or out of order in the report:\n{stdout}")
            });
        after += at + heading.len();
    }
    // And the integrity test is named, since it is the one the operator most
    // wants to see and the one that is NOT part of the flat inventory.
    assert!(
        stdout.contains("Module image integrity"),
        "the integrity test must be reported"
    );
}

/// The ML-KEM self-tests run at power-up as a group of their own, listed
/// directly after ML-DSA, and the printed total is every inventory group plus
/// the integrity group and the entropy source's line: 102 for this inventory.
#[test]
fn selftest_lists_ml_kem_group() {
    let oxi = scratch("selftest-ml-kem");
    sign(&oxi);

    let (code, stdout, stderr) = run(&oxi, &["selftest"]);
    assert_eq!(code, 0, "selftest must pass on a signed binary: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();

    let ml_dsa = lines
        .iter()
        .position(|l| l.starts_with("ml-dsa ("))
        .unwrap_or_else(|| panic!("no ml-dsa group:\n{stdout}"));
    let next = lines
        .iter()
        .skip(ml_dsa + 1)
        .find(|l| !l.starts_with("  "))
        .unwrap_or_else(|| panic!("nothing follows the ml-dsa group:\n{stdout}"));
    assert_eq!(
        *next, "ml-kem (4)",
        "the group after ml-dsa must be `ml-kem (4)`:\n{stdout}"
    );
    let ml_kem_ok = lines
        .iter()
        .skip_while(|l| **l != "ml-kem (4)")
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter(|l| l.starts_with("  ok    "))
        .count();
    assert_eq!(
        ml_kem_ok, 4,
        "the ml-kem group must pass four tests:\n{stdout}"
    );

    let expected = oxicrypt_integrity::KATS.len() + 1 + power_up::power_up_tests().len();
    assert_eq!(
        expected, 102,
        "the power-up set is {expected} self-tests, not 102; oxi/README.md's sample is stale"
    );
    let total = format!("{expected} of {expected} self-tests passed");
    assert!(
        lines.contains(&total.as_str()),
        "the total must be `{total}`:\n{stdout}"
    );

    let (code, quiet, _) = run(&oxi, &["selftest", "--quiet"]);
    assert_eq!(code, 0);
    assert_eq!(
        quiet.lines().collect::<Vec<_>>(),
        [total.as_str(), "self-test indicator: PASS"],
        "--quiet must print the total, then the indicator"
    );
}

/// The entropy source's on-demand test is reported as its own group, directly
/// after the integrity group, names the seed path, and is in the total.
#[test]
fn selftest_lists_entropy_source() {
    let oxi = scratch("selftest-entropy");
    sign(&oxi);

    let (code, stdout, stderr) = run(&oxi, &["selftest"]);
    assert_eq!(code, 0, "selftest must pass on a signed binary: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();

    let integrity = lines
        .iter()
        .position(|l| l.starts_with("integrity ("))
        .expect("no integrity group");
    let heading = lines
        .iter()
        .enumerate()
        .skip(integrity + 1)
        .find(|(_, l)| !l.starts_with("  "))
        .map(|(i, _)| i)
        .expect("nothing follows the integrity group");
    assert!(
        lines[heading].starts_with("entropy source (1)"),
        "the group after integrity must be `entropy source (1)`, got {:?}:\n{stdout}",
        lines[heading]
    );
    let line = lines
        .get(heading + 1)
        .expect("the entropy group has no line");
    assert!(
        line.starts_with("  ok    "),
        "the entropy line must pass: {line:?}"
    );
    assert!(
        line.contains("jitter source") || line.contains("operating-system generator"),
        "the entropy line must name the seed path: {line:?}"
    );
    assert!(
        !lines
            .get(heading + 2)
            .is_some_and(|l| l.starts_with("  ok    ") || l.starts_with("  FAIL  ")),
        "the entropy group holds exactly one line"
    );

    let reported: usize = stdout
        .lines()
        .find_map(|l| l.strip_suffix(" self-tests passed"))
        .and_then(|l| l.split_whitespace().next())
        .expect("no summary line")
        .parse()
        .expect("summary count is a number");
    let ok_lines = lines
        .iter()
        .filter(|l| l.trim_start().starts_with("ok    "))
        .count();
    assert_eq!(
        reported, ok_lines,
        "the summary must count the entropy line"
    );
    let total: usize = stdout
        .lines()
        .find_map(|l| l.strip_suffix(" self-tests passed"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("no total")
        .parse()
        .expect("total is a number");
    assert_eq!(total, ok_lines, "the total must include the entropy line");
}

/// `--quiet` prints the indicator and the count, and nothing per-test.
#[test]
fn selftest_quiet_still_carries_the_indicator() {
    let oxi = scratch("selftest-quiet");
    sign(&oxi);

    let (code, stdout, _) = run(&oxi, &["selftest", "--quiet"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().collect();
    let Some((count, ["self-test indicator: PASS"])) = lines.split_first() else {
        panic!("--quiet must print the count line, then the indicator, got:\n{stdout}");
    };
    let (passed, total) = count
        .strip_suffix(" self-tests passed")
        .and_then(|c| c.split_once(" of "))
        .unwrap_or_else(|| panic!("not a count line: {count}"));
    assert!(
        passed == total && passed.parse::<u32>().is_ok_and(|n| n > 0),
        "--quiet on a passing run must count every test as passed, got: {count}"
    );
    // The control: the non-quiet form DOES print each test, so the two lines
    // above are the flag working rather than the subcommand printing no
    // per-test lines either way.
    let (_, verbose, _) = run(&oxi, &["selftest"]);
    assert!(
        verbose.contains("ok    "),
        "the non-quiet form must be verbose"
    );
}

/// An unsigned binary cannot demonstrate its self-tests, because it never
/// became operational.
///
/// This is the ordering that keeps the subcommand conservative: `selftest` is
/// dispatched after `init_module`, so it can show the tests and never stand in
/// for them.
#[test]
fn selftest_is_unreachable_until_the_module_is_operational() {
    let oxi = scratch("selftest-unsigned");
    let (code, stdout, stderr) = run(&oxi, &["selftest"]);
    assert_ne!(
        code, 0,
        "an unsigned binary must not run the self-test service"
    );
    assert!(
        stderr.contains("module initialization failed"),
        "it must fail at initialization, got: {stderr}{stdout}"
    );
    assert!(
        !stdout.contains("self-test indicator"),
        "no indicator may be emitted by a module that never became operational"
    );
}

/// An unrecognised argument is refused rather than ignored.
#[test]
fn selftest_refuses_arguments_it_does_not_understand() {
    let oxi = scratch("selftest-badarg");
    sign(&oxi);
    let (code, _, stderr) = run(&oxi, &["selftest", "--verbos"]);
    assert_eq!(code, 2, "a typo must be a usage error: {stderr}");
}

/// Every HMAC variant the self-test reports is reachable from the prompt.
///
/// `oxi selftest` prints eleven HMAC known-answer tests passing. A CLI that
/// then refused any of them would be telling the operator the module can do
/// something this binary declines to do, and the inconsistency is visible on
/// one screen.
#[test]
fn every_self_tested_hmac_variant_is_reachable() {
    let oxi = scratch("hmac-parity");
    sign(&oxi);

    let (code, report, _) = run(&oxi, &["selftest"]);
    assert_eq!(code, 0);
    // Counted inside the `hmac` group only, so an HMAC entry in any other
    // group is not mistaken for a variant `oxi hmac` offers.
    let self_tested = report
        .lines()
        .skip_while(|l| !l.starts_with("hmac ("))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter(|l| l.trim_start().starts_with("ok    "))
        .count();
    assert!(
        self_tested >= 11,
        "premise failed: read {self_tested} HMAC tests from the report"
    );

    // RFC 4231 test case 1's key. The digests differ per variant; what is
    // asserted here is reachability, and the RFC vector itself is pinned by the
    // known-answer test the report just showed passing.
    let key = "0b".repeat(20);
    let variants = [
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512-224",
        "sha512-256",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
    ];
    assert_eq!(
        variants.len(),
        self_tested,
        "the report shows {self_tested} HMAC tests but this list names {}",
        variants.len()
    );
    for v in variants {
        let (code, stdout, stderr) = run(&oxi, &["hmac", v, &key, OXI]);
        assert_eq!(code, 0, "hmac {v} must be reachable: {stderr}");
        assert!(
            stdout.trim().len() >= 40,
            "hmac {v} produced no tag: {stdout}"
        );
    }

    // The control: an unknown variant is still refused, so the loop above is
    // not passing because every string is accepted.
    let (code, _, _) = run(&oxi, &["hmac", "sha3-999", &key, OXI]);
    assert_eq!(code, 2, "an unknown algorithm must still be a usage error");
}

/// `--integrity` says what was compared, not only whether it matched.
///
/// "The module verified itself" means little without the extent: the signature covers
/// a strict subset of the file by construction, so the byte count is the honest
/// measure of what the test establishes. It is read out of the slot the
/// verifier used, and reported only where a comparison happened — on an
/// unsigned binary the slot does not parse, nothing was compared, and claiming
/// an extent would read as though something had been.
#[test]
fn integrity_reports_the_extent_only_when_something_was_compared() {
    let oxi = scratch("extent");

    let (_, unsigned, _) = run(&oxi, &["--integrity"]);
    assert!(
        unsigned.contains("unsigned template"),
        "premise failed: expected an unsigned binary, got: {unsigned}"
    );
    assert!(
        !unsigned.contains("extent:"),
        "nothing was compared, so no extent may be claimed: {unsigned}"
    );

    sign(&oxi);
    let (code, signed, _) = run(&oxi, &["--integrity"]);
    assert_eq!(code, 0);
    assert!(
        signed.contains("extent:") && signed.contains("entries"),
        "a passing check must say what it covered: {signed}"
    );

    // The figure must be a real fraction of a real image, not a placeholder.
    let bytes: u64 = signed
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("extent: "))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("no extent figure");
    assert!(
        bytes > 100_000,
        "the extent should be most of a multi-megabyte binary, got {bytes}"
    );
    assert!(
        bytes < std::fs::metadata(&oxi).expect("stat").len(),
        "the extent is a strict subset of the file by construction"
    );
}

/// A failed integrity CAST stops the module before the image is examined,
/// so the image's state is unknown: every command exits 3, never 1.
///
/// The failure is injected by changing the CAST's expected signature, a
/// constant in this binary's read-only data, in the copy under test.
#[test]
fn a_failed_integrity_cast_exits_3_everywhere() {
    // The first 16 bytes of the ML-DSA-87 verification CAST's valid
    // signature, part of its commitment hash c̃.
    const KAT_SIG: [u8; 16] = [
        0x5e, 0xe7, 0x63, 0x83, 0xf8, 0xed, 0x3e, 0xcf, 0xb1, 0xe9, 0x32, 0x8f, 0x99, 0xfb, 0xc9,
        0x02,
    ];
    let oxi = scratch("cast-fails");
    let mut bytes = read(&oxi);
    let hits: Vec<usize> = bytes
        .windows(KAT_SIG.len())
        .enumerate()
        .filter(|(_, w)| *w == KAT_SIG)
        .map(|(i, _)| i)
        .collect();
    assert!(
        !hits.is_empty(),
        "premise failed: the CAST vector is not in this binary"
    );
    for at in hits {
        bytes[at + 4] ^= 0x01;
    }
    std::fs::write(&oxi, &bytes).expect("write artifact");

    let (code, _, stderr) = run(&oxi, &["hash", "sha256", OXI]);
    assert_eq!(
        code, 3,
        "a command must exit 3 when the CAST fails: {stderr}"
    );
    let (code, stdout, _) = run(&oxi, &["--integrity"]);
    assert_eq!(
        code, 3,
        "--integrity must exit 3 when the CAST fails: {stdout}"
    );
    assert!(stdout.contains("unavailable"), "{stdout}");
    assert!(
        stdout.contains(oxicrypt_integrity::ML_DSA_CAST_NAME),
        "the failing CAST is named: {stdout}"
    );
}

/// Flips one bit of every copy of `pattern` in the artifact at `path`, and
/// returns how many copies there were.
fn corrupt_every(path: &Path, pattern: &[u8]) -> usize {
    let mut bytes = read(path);
    let hits: Vec<usize> = bytes
        .windows(pattern.len())
        .enumerate()
        .filter(|(_, w)| *w == pattern)
        .map(|(i, _)| i)
        .collect();
    for &at in &hits {
        bytes[at + 4] ^= 0x01;
    }
    std::fs::write(path, &bytes).expect("write artifact");
    hits.len()
}

/// A failed SHA-256 CAST, the second test of the integrity group, stops the
/// module before the image is examined, and `--integrity` names that CAST
/// rather than the ML-DSA-87 one.
#[test]
fn a_failed_sha256_cast_is_named() {
    // The first 16 bytes of the SHA-256 KAT's expected digest.
    const SHA256_MD: [u8; 16] = [
        0x28, 0x96, 0x9c, 0xdf, 0xa7, 0x4a, 0x12, 0xc8, 0x2f, 0x3b, 0xad, 0x96, 0x0b, 0x0b, 0x00,
        0x0a,
    ];
    let oxi = scratch("sha256-cast-fails");
    assert!(
        corrupt_every(&oxi, &SHA256_MD) > 0,
        "premise failed: the SHA-256 KAT digest is not in this binary"
    );
    let (code, stdout, _) = run(&oxi, &["--integrity"]);
    assert_eq!(code, 3, "{stdout}");
    assert!(
        stdout.contains(oxicrypt_integrity::SHA256_CAST_NAME),
        "the SHA-256 CAST is named: {stdout}"
    );
    assert!(
        !stdout.contains("ML-DSA"),
        "the ML-DSA-87 CAST is not blamed: {stdout}"
    );
}

/// When the image check passes and a later algorithm self-test fails, the
/// module latches its error state, and `--integrity` exits 4 naming the
/// test rather than reporting success.
#[test]
fn a_later_self_test_failure_after_a_passing_image_exits_4() {
    // The first 16 bytes of the SHA-384 KAT's expected digest, a test of
    // the algorithm inventory that runs after the integrity group.
    const SHA384_MD: [u8; 16] = [
        0xb5, 0x2b, 0x72, 0xda, 0x75, 0xd0, 0x66, 0x63, 0x79, 0xe2, 0x0f, 0x9b, 0x4a, 0x79, 0xc3,
        0x3a,
    ];
    let oxi = scratch("later-kat-fails");
    assert!(
        corrupt_every(&oxi, &SHA384_MD) > 0,
        "premise failed: the SHA-384 KAT digest is not in this binary"
    );
    // Signed after the change, so the image check passes.
    sign(&oxi);
    let (code, stdout, _) = run(&oxi, &["--integrity"]);
    assert!(stdout.contains("integrity: passed"), "{stdout}");
    assert_eq!(code, 4, "{stdout}");
    assert!(
        stdout.contains("SHA-384 KAT"),
        "the failing test is named: {stdout}"
    );
}

/// The stderr line every seed flag prints.
const SEED_WARNING: &str = "seed supplied: protect this seed as you would the secret key\n";

/// A signed copy of `oxi`, ready to run the post-quantum commands.
fn signed(tag: &str) -> Scratch {
    let oxi = scratch(tag);
    sign(&oxi);
    oxi
}

/// The directory a scratch `oxi` runs in, where the commands' relative
/// paths land.
fn dir(oxi: &Scratch) -> PathBuf {
    oxi.parent().expect("artifact has a parent").to_owned()
}

/// Runs the artifact in its own directory with `stdin` piped in and `env`
/// set, and returns `(exit code, stdout bytes, stderr)`. Retries on
/// `ETXTBSY` as [`run_in`] does.
fn run_pq(oxi: &Path, args: &[&str], stdin: &[u8], env: &[(&str, &str)]) -> (i32, Vec<u8>, String) {
    use std::io::Write as _;
    const ETXTBSY: i32 = 26;
    let mut waited = std::time::Duration::ZERO;
    let step = std::time::Duration::from_millis(20);
    let mut child = loop {
        let spawned = Command::new(oxi)
            .args(args)
            .current_dir(oxi.parent().expect("artifact has a parent"))
            .env_remove("OXI_FAULT")
            .envs(env.iter().copied())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        match spawned {
            Ok(child) => break child,
            Err(e)
                if e.raw_os_error() == Some(ETXTBSY)
                    && waited < std::time::Duration::from_secs(5) =>
            {
                std::thread::sleep(step);
                waited += step;
            }
            Err(e) => panic!("run {}: {e}", oxi.display()),
        }
    };
    if let Some(mut input) = child.stdin.take() {
        input.write_all(stdin).expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait for oxi");
    (
        out.status.code().unwrap_or(-1),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An ACVP fixture under `tests/data/`.
fn data(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path).expect("stat").permissions().mode();
    assert_eq!(
        mode & 0o077,
        0,
        "{} must be owner-only, mode {mode:o}",
        path.display()
    );
}

#[cfg(not(unix))]
fn assert_owner_only(_: &Path) {}

/// The ACVP keyGen case `case` of ML-DSA-`set`, reproduced through
/// `--seed`; then the same seed with one byte flipped, which must not.
fn dsa_keygen_known_answer(set: &str, case: &str, pk_len: usize, sk_len: usize) {
    let oxi = signed(&format!("dsa-kat-{set}"));
    let d = dir(&oxi);
    let seed = data(&format!("ml-dsa-{set}-keygen-{case}.seed"));
    let pk = data(&format!("ml-dsa-{set}-keygen-{case}.pk"));
    let sk = data(&format!("ml-dsa-{set}-keygen-{case}.sk"));
    assert_eq!((seed.len(), pk.len(), sk.len()), (32, pk_len, sk_len));

    let (code, _, stderr) = run_pq(
        &oxi,
        &[
            "ml-dsa",
            "keygen",
            set,
            "--seed",
            &hex(&seed),
            "--pk",
            "pk",
            "--sk",
            "sk",
        ],
        b"",
        &[],
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(read(&d.join("pk")), pk, "ML-DSA-{set} pk");
    assert_eq!(read(&d.join("sk")), sk, "ML-DSA-{set} sk");

    let mut flipped = seed;
    flipped[0] ^= 0x01;
    let (code, _, stderr) = run_pq(
        &oxi,
        &[
            "ml-dsa",
            "keygen",
            set,
            "--seed",
            &hex(&flipped),
            "--pk",
            "pk2",
            "--sk",
            "sk2",
        ],
        b"",
        &[],
    );
    assert_eq!(code, 0, "{stderr}");
    assert_ne!(read(&d.join("pk2")), pk, "a flipped seed must change pk");
    assert_ne!(read(&d.join("sk2")), sk, "a flipped seed must change sk");
}

/// The ACVP keyGen case `case` of ML-KEM-`set`, reproduced through `--d`
/// and `--z`; then the same `d` with one byte flipped, which must not.
fn kem_keygen_known_answer(set: &str, case: &str, ek_len: usize, dk_len: usize) {
    let oxi = signed(&format!("kem-kat-{set}"));
    let dr = dir(&oxi);
    let d = data(&format!("ml-kem-{set}-keygen-{case}.d"));
    let z = data(&format!("ml-kem-{set}-keygen-{case}.z"));
    let ek = data(&format!("ml-kem-{set}-keygen-{case}.ek"));
    let dk = data(&format!("ml-kem-{set}-keygen-{case}.dk"));
    assert_eq!(
        (d.len(), z.len(), ek.len(), dk.len()),
        (32, 32, ek_len, dk_len)
    );

    let keygen = |d: &[u8], ek_path: &str, dk_path: &str| {
        run_pq(
            &oxi,
            &[
                "ml-kem",
                "keygen",
                set,
                "--d",
                &hex(d),
                "--z",
                &hex(&z),
                "--ek",
                ek_path,
                "--dk",
                dk_path,
            ],
            b"",
            &[],
        )
    };
    let (code, _, stderr) = keygen(&d, "ek", "dk");
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(read(&dr.join("ek")), ek, "ML-KEM-{set} ek");
    assert_eq!(read(&dr.join("dk")), dk, "ML-KEM-{set} dk");

    let mut flipped = d;
    flipped[0] ^= 0x01;
    let (code, _, stderr) = keygen(&flipped, "ek2", "dk2");
    assert_eq!(code, 0, "{stderr}");
    assert_ne!(read(&dr.join("ek2")), ek, "a flipped d must change ek");
    assert_ne!(read(&dr.join("dk2")), dk, "a flipped d must change dk");
}

#[test]
fn ml_dsa_keygen_matches_acvp_vector() {
    dsa_keygen_known_answer("87", "tg3-tc51", 2592, 4896);
}

#[test]
fn ml_kem_keygen_matches_acvp_vector() {
    kem_keygen_known_answer("1024", "tg3-tc51", 1568, 3168);
}

#[test]
fn keygen_matches_acvp_vector_ml_dsa_44() {
    dsa_keygen_known_answer("44", "tg1-tc1", 1312, 2560);
}

#[test]
fn keygen_matches_acvp_vector_ml_dsa_65() {
    dsa_keygen_known_answer("65", "tg2-tc26", 1952, 4032);
}

#[test]
fn keygen_matches_acvp_vector_ml_kem_512() {
    kem_keygen_known_answer("512", "tg1-tc1", 800, 1632);
}

#[test]
fn keygen_matches_acvp_vector_ml_kem_768() {
    kem_keygen_known_answer("768", "tg2-tc26", 1184, 2400);
}

/// For each ML-DSA set: a signature verifies, from a file operand, from
/// stdin and with a context; a flipped signature byte, a different message
/// and a missing context each exit 5.
#[test]
fn ml_dsa_round_trip_and_rejection() {
    let oxi = signed("dsa-round-trip");
    let d = dir(&oxi);
    let message = b"oxicrypt how-to message";
    std::fs::write(d.join("msg"), message).expect("write msg");
    std::fs::write(d.join("-m"), message).expect("write -m");
    std::fs::write(d.join("other"), b"a different message").expect("write other");
    let rejected = "ml-dsa verify: signature not valid\n";

    for set in ["44", "65", "87"] {
        let p = |name: &str| format!("{set}.{name}");
        let (pk, sk, sig, bad, ctx_sig) = (p("pk"), p("sk"), p("sig"), p("bad"), p("ctx-sig"));
        let ok = |args: &[&str], stdin: &[u8]| {
            let (code, stdout, stderr) = run_pq(&oxi, args, stdin, &[]);
            assert_eq!(code, 0, "{args:?}: {stderr}");
            assert!(stdout.is_empty() && stderr.is_empty(), "{args:?}: {stderr}");
        };
        let refused = |args: &[&str]| {
            let (code, _, stderr) = run_pq(&oxi, args, b"", &[]);
            assert_eq!((code, stderr.as_str()), (5, rejected), "{args:?}");
        };

        ok(&["ml-dsa", "keygen", set, "--pk", &pk, "--sk", &sk], b"");
        ok(
            &[
                "ml-dsa", "sign", set, "--sk", &sk, "--sig", &sig, "--", "-m",
            ],
            b"",
        );
        ok(
            &["ml-dsa", "verify", set, "--pk", &pk, "--sig", &sig, "msg"],
            b"",
        );
        ok(
            &["ml-dsa", "verify", set, "--pk", &pk, "--sig", &sig],
            message,
        );
        ok(
            &["ml-dsa", "verify", set, "--pk", &pk, "--sig", &sig, "-"],
            message,
        );

        let mut flipped = read(&d.join(&sig));
        flipped[0] ^= 0x01;
        std::fs::write(d.join(&bad), &flipped).expect("write flipped signature");
        refused(&["ml-dsa", "verify", set, "--pk", &pk, "--sig", &bad, "msg"]);
        refused(&["ml-dsa", "verify", set, "--pk", &pk, "--sig", &sig, "other"]);

        ok(
            &[
                "ml-dsa", "sign", set, "--sk", &sk, "--sig", &ctx_sig, "--ctx", "0102", "msg",
            ],
            b"",
        );
        ok(
            &[
                "ml-dsa", "verify", set, "--pk", &pk, "--sig", &ctx_sig, "--ctx", "0102", "msg",
            ],
            b"",
        );
        refused(&[
            "ml-dsa", "verify", set, "--pk", &pk, "--sig", &ctx_sig, "msg",
        ]);
    }
}

/// The shared secret `oxi` printed: 64 lowercase hex characters and a
/// newline, and nothing else.
fn printed_secret(stdout: &[u8]) -> String {
    let text = std::str::from_utf8(stdout).expect("stdout is text");
    let secret = text.strip_suffix('\n').expect("one line");
    assert!(
        secret.len() == 64
            && secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "stdout must be 64 lowercase hex characters: {text:?}"
    );
    secret.to_owned()
}

/// `encaps` and `decaps` agree on stdout and through `--ss`; a flipped
/// ciphertext byte decapsulates, exit 0, to a different secret; two
/// encapsulations to one key differ.
fn kem_round_trip(set: &str) {
    let oxi = signed(&format!("kem-round-trip-{set}"));
    let d = dir(&oxi);
    let ok = |args: &[&str]| {
        let (code, stdout, stderr) = run_pq(&oxi, args, b"", &[]);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        assert!(stderr.is_empty(), "{args:?}: {stderr}");
        stdout
    };

    assert!(ok(&["ml-kem", "keygen", set, "--ek", "ek", "--dk", "dk"]).is_empty());
    let encapsulated = printed_secret(&ok(&["ml-kem", "encaps", set, "--ek", "ek", "--ct", "ct"]));
    let decapsulated = printed_secret(&ok(&["ml-kem", "decaps", set, "--dk", "dk", "--ct", "ct"]));
    assert_eq!(
        encapsulated, decapsulated,
        "ML-KEM-{set}: decaps must print encaps' secret"
    );

    let mut tampered = read(&d.join("ct"));
    tampered[0] ^= 0x01;
    std::fs::write(d.join("ct.bad"), &tampered).expect("write tampered ciphertext");
    let rejected = printed_secret(&ok(&[
        "ml-kem", "decaps", set, "--dk", "dk", "--ct", "ct.bad",
    ]));
    assert_ne!(
        rejected, encapsulated,
        "implicit rejection yields a different secret"
    );

    let again = printed_secret(&ok(&["ml-kem", "encaps", set, "--ek", "ek", "--ct", "ct2"]));
    assert_ne!(again, encapsulated, "two encapsulations must differ");

    assert!(
        ok(&[
            "ml-kem", "encaps", set, "--ek", "ek", "--ct", "ct3", "--ss", "ss.sent"
        ])
        .is_empty()
    );
    assert!(
        ok(&[
            "ml-kem", "decaps", set, "--dk", "dk", "--ct", "ct3", "--ss", "ss.got"
        ])
        .is_empty()
    );
    let ss = read(&d.join("ss.sent"));
    assert_eq!(ss.len(), 32);
    assert_eq!(read(&d.join("ss.got")), ss, "--ss files must agree");
    for f in ["dk", "ss.sent", "ss.got"] {
        assert_owner_only(&d.join(f));
    }
}

#[test]
fn ml_kem_round_trip_and_implicit_rejection_512() {
    kem_round_trip("512");
}

#[test]
fn ml_kem_round_trip_and_implicit_rejection_768() {
    kem_round_trip("768");
}

#[test]
fn ml_kem_round_trip_and_implicit_rejection_1024() {
    kem_round_trip("1024");
}

/// Two key generations without a seed flag draw different seeds from the
/// module's DRBG.
#[test]
fn two_keygens_differ() {
    let oxi = signed("two-keygens");
    let d = dir(&oxi);
    for (family, set, a, b) in [
        ("ml-dsa", "87", "--pk", "--sk"),
        ("ml-kem", "1024", "--ek", "--dk"),
    ] {
        for n in ["1", "2"] {
            let (code, _, stderr) = run_pq(
                &oxi,
                &[
                    family,
                    "keygen",
                    set,
                    a,
                    &format!("pub{set}.{n}"),
                    b,
                    &format!("sec{set}.{n}"),
                ],
                b"",
                &[],
            );
            assert_eq!(code, 0, "{stderr}");
        }
        for half in ["pub", "sec"] {
            assert_ne!(
                read(&d.join(format!("{half}{set}.1"))),
                read(&d.join(format!("{half}{set}.2"))),
                "{family} {set}: two seedless keygens must differ"
            );
        }
    }
}

#[test]
fn seed_flags_warning() {
    let oxi = signed("seed-warning");
    let (code, _, stderr) = run_pq(
        &oxi,
        &[
            "ml-dsa",
            "keygen",
            "44",
            "--seed",
            &"ab".repeat(32),
            "--pk",
            "pk",
            "--sk",
            "sk",
        ],
        b"",
        &[],
    );
    assert_eq!((code, stderr.as_str()), (0, SEED_WARNING));
    let (code, _, stderr) = run_pq(
        &oxi,
        &[
            "ml-kem",
            "keygen",
            "512",
            "--d",
            &"cd".repeat(32),
            "--z",
            &"ef".repeat(32),
            "--ek",
            "ek",
            "--dk",
            "dk",
        ],
        b"",
        &[],
    );
    assert_eq!((code, stderr.as_str()), (0, SEED_WARNING));
}

/// `--seed-out` writes the module-generated seed owner-only, and expanding
/// it reproduces the pair.
#[test]
fn seed_flags_seed_out_round_trip() {
    let oxi = signed("seed-out");
    let d = dir(&oxi);
    let run_ok = |args: &[&str]| {
        let (code, _, stderr) = run_pq(&oxi, args, b"", &[]);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        stderr
    };

    let quiet = run_ok(&[
        "ml-dsa",
        "keygen",
        "65",
        "--pk",
        "pk",
        "--sk",
        "sk",
        "--seed-out",
        "xi",
    ]);
    assert!(quiet.is_empty(), "{quiet}");
    let xi = read(&d.join("xi"));
    assert_eq!(xi.len(), 32);
    assert_owner_only(&d.join("xi"));
    assert_owner_only(&d.join("sk"));
    run_ok(&[
        "ml-dsa",
        "keygen",
        "65",
        "--seed",
        &hex(&xi),
        "--pk",
        "pk2",
        "--sk",
        "sk2",
    ]);
    assert_eq!(read(&d.join("pk2")), read(&d.join("pk")));
    assert_eq!(read(&d.join("sk2")), read(&d.join("sk")));

    let quiet = run_ok(&[
        "ml-kem",
        "keygen",
        "768",
        "--ek",
        "ek",
        "--dk",
        "dk",
        "--seed-out",
        "dz",
    ]);
    assert!(quiet.is_empty(), "{quiet}");
    let dz = read(&d.join("dz"));
    assert_eq!(dz.len(), 64);
    assert_owner_only(&d.join("dz"));
    assert_owner_only(&d.join("dk"));
    run_ok(&[
        "ml-kem",
        "keygen",
        "768",
        "--d",
        &hex(&dz[..32]),
        "--z",
        &hex(&dz[32..]),
        "--ek",
        "ek2",
        "--dk",
        "dk2",
    ]);
    assert_eq!(read(&d.join("ek2")), read(&d.join("ek")));
    assert_eq!(read(&d.join("dk2")), read(&d.join("dk")));
}

#[test]
fn seed_flags_no_flag_silent() {
    let oxi = signed("seed-silent");
    for args in [
        ["ml-dsa", "keygen", "87", "--pk", "pk", "--sk", "sk"],
        ["ml-kem", "keygen", "1024", "--ek", "ek", "--dk", "dk"],
    ] {
        let (code, stdout, stderr) = run_pq(&oxi, &args, b"", &[]);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        assert!(stdout.is_empty(), "{args:?}");
        assert_eq!(stderr, "", "{args:?}: no seed flag, no warning");
    }
}

/// Every usage error exits 2, says why on stderr, and creates no output.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table: each case beside its stderr"
)]
fn pq_usage_errors_exit_2() {
    let oxi = signed("pq-usage");
    let d = dir(&oxi);
    let seed44 = hex(&data("ml-dsa-44-keygen-tg1-tc1.seed"));
    let (code, _, stderr) = run_pq(
        &oxi,
        &[
            "ml-dsa", "keygen", "44", "--seed", &seed44, "--pk", "pk", "--sk", "sk",
        ],
        b"",
        &[],
    );
    assert_eq!(code, 0, "control: a valid invocation succeeds: {stderr}");
    std::fs::write(d.join("msg"), b"message").expect("write msg");
    std::fs::write(d.join("short.sk"), [0u8; 100]).expect("write short.sk");
    std::fs::write(d.join("exists"), b"keep").expect("write exists");

    let hex32 = "11".repeat(32);
    let ctx256 = "00".repeat(256);
    let cases: &[(&[&str], &str, &[&str])] = &[
        (
            &[
                "ml-kem", "keygen", "512", "--ek", "o.ek", "--dk", "o.dk", "--d", &hex32,
            ],
            "oxi ml-kem keygen: --d and --z are required together\n",
            &["o.ek", "o.dk"],
        ),
        (
            &[
                "ml-kem", "keygen", "512", "--ek", "o.ek", "--dk", "o.dk", "--z", &hex32,
            ],
            "oxi ml-kem keygen: --d and --z are required together\n",
            &["o.ek", "o.dk"],
        ),
        (
            &[
                "ml-dsa", "sign", "44", "--sk", "sk", "--sig", "o.sig", "--ctx", &ctx256, "msg",
            ],
            "oxi ml-dsa sign: --ctx is 256 bytes; FIPS 204 §5.2 limits the context to 255 bytes\n",
            &["o.sig"],
        ),
        (
            &[
                "ml-dsa",
                "keygen",
                "44",
                "--seed",
                &"11".repeat(31),
                "--pk",
                "o.pk",
                "--sk",
                "o.sk",
            ],
            "oxi ml-dsa keygen: --seed must be 32 bytes as 64 hex characters, got 62 characters\n",
            &["o.pk", "o.sk"],
        ),
        (
            &[
                "ml-dsa",
                "keygen",
                "44",
                "--seed",
                &"zz".repeat(32),
                "--pk",
                "o.pk",
                "--sk",
                "o.sk",
            ],
            "oxi ml-dsa keygen: --seed must be 32 bytes as 64 hex characters, and it holds a \
             character that is not hex\n",
            &["o.pk", "o.sk"],
        ),
        (
            &[
                "ml-dsa", "sign", "44", "--sk", "short.sk", "--sig", "o.sig", "msg",
            ],
            "oxi ml-dsa sign: short.sk: expected 2560 bytes, got 100\n",
            &["o.sig"],
        ),
        (
            &[
                "ml-dsa",
                "sign",
                "44",
                "--sk",
                "absent.sk",
                "--sig",
                "o.sig",
                "msg",
            ],
            "oxi ml-dsa sign: absent.sk: ",
            &["o.sig"],
        ),
        (
            &[
                "ml-dsa", "keygen", "44", "--pk", "o.pk", "--sk", "o.sk", "--bogus", "1",
            ],
            "oxi ml-dsa keygen: unknown flag --bogus\n",
            &["o.pk", "o.sk"],
        ),
        (
            &[
                "ml-dsa", "keygen", "44", "--pk", "o.pk", "--pk", "o.pk2", "--sk", "o.sk",
            ],
            "oxi ml-dsa keygen: --pk given more than once\n",
            &["o.pk", "o.pk2", "o.sk"],
        ),
        (
            &["ml-dsa", "keygen", "44", "--pk", "o.pk", "--sk"],
            "oxi ml-dsa keygen: --sk needs a value\n",
            &["o.pk"],
        ),
        (
            &["ml-dsa", "keygen", "44", "--pk", "--sk", "o.sk"],
            "oxi ml-dsa keygen: --pk needs a value\n",
            &["o.sk"],
        ),
        (
            &["ml-dsa", "keygen", "44", "--pk", "o.pk"],
            "oxi ml-dsa keygen: missing required flag --sk\n",
            &["o.pk"],
        ),
        (
            &[
                "ml-dsa", "sign", "44", "--sk", "sk", "--sig", "o.sig", "msg", "msg",
            ],
            "oxi ml-dsa sign: more than one MESSAGE given\n",
            &["o.sig"],
        ),
        (
            &[
                "ml-dsa", "keygen", "44", "--pk", "o.pk", "--sk", "o.sk", "stray",
            ],
            "oxi ml-dsa keygen: unexpected argument stray\n",
            &["o.pk", "o.sk"],
        ),
        (
            &[
                "ml-dsa",
                "keygen",
                "44",
                "--pk",
                "o.pk",
                "--sk",
                "o.sk",
                "--seed",
                &hex32,
                "--seed-out",
                "o.xi",
            ],
            "oxi ml-dsa keygen: --seed-out cannot be combined with --seed\n",
            &["o.pk", "o.sk", "o.xi"],
        ),
        (
            &["ml-dsa", "keygen", "44", "--pk", "exists", "--sk", "o.sk"],
            "oxi will not overwrite exists: it already exists\n",
            &["o.sk"],
        ),
        (
            &[
                "ml-dsa", "keygen", "44", "--pk", "o.same", "--sk", "./o.same",
            ],
            "oxi ml-dsa keygen: --pk and --sk name the same file ./o.same\n",
            &["o.same"],
        ),
        (
            &["ml-dsa", "keygen", "99", "--pk", "o.pk", "--sk", "o.sk"],
            "oxi ml-dsa: usage:\n  oxi ml-dsa keygen <44|65|87>",
            &["o.pk", "o.sk"],
        ),
        (
            &["ml-kem", "frob", "512", "--ek", "o.ek", "--dk", "o.dk"],
            "oxi ml-kem: usage:\n  oxi ml-kem keygen <512|768|1024>",
            &["o.ek", "o.dk"],
        ),
    ];
    for &(args, stderr_start, outputs) in cases {
        let (code, stdout, stderr) = run_pq(&oxi, args, b"", &[]);
        assert_eq!(code, 2, "{args:?}: {stderr}");
        assert!(stdout.is_empty(), "{args:?}");
        assert!(
            stderr.starts_with(stderr_start),
            "{args:?}: stderr {stderr:?} must start with {stderr_start:?}"
        );
        for o in outputs {
            assert!(
                std::fs::symlink_metadata(d.join(o)).is_err(),
                "{args:?}: {o} must not exist"
            );
        }
    }
    assert_eq!(
        read(&d.join("exists")),
        b"keep",
        "an existing file is untouched"
    );
}

/// An ML-KEM encapsulation key with a coefficient equal to q (FIPS 203
/// §7.2) and a decapsulation key whose stored `H(ek)` is wrong (§7.3) are
/// usage errors naming the file; the canonical keys succeed.
#[test]
fn module_verdicts_mapped_invalid_key() {
    let oxi = signed("verdict-invalid-key");
    let d = dir(&oxi);
    let ek = data("ml-kem-512-keygen-tg1-tc1.ek");
    let dk = data("ml-kem-512-keygen-tg1-tc1.dk");
    std::fs::write(d.join("ek"), &ek).expect("write ek");
    std::fs::write(d.join("dk"), &dk).expect("write dk");

    // FIPS 203 Algorithm 5 (ByteEncode12): the first coefficient is
    // ek[0] | (ek[1] & 0x0f) << 8; q = 3329 = 0xd01.
    let mut noncanonical = ek;
    noncanonical[0] = 0x01;
    noncanonical[1] = (noncanonical[1] & 0xf0) | 0x0d;
    std::fs::write(d.join("bad.ek"), &noncanonical).expect("write bad.ek");
    // FIPS 203 §7.3, ML-KEM-512 (k = 2): H(ek) is stored at
    // dk[768k + 32..768k + 64].
    let mut wrong_hash = dk;
    wrong_hash[768 * 2 + 32] ^= 0x01;
    std::fs::write(d.join("bad.dk"), &wrong_hash).expect("write bad.dk");

    let (code, _, stderr) = run_pq(
        &oxi,
        &["ml-kem", "encaps", "512", "--ek", "ek", "--ct", "ct"],
        b"",
        &[],
    );
    assert_eq!(code, 0, "control: the canonical ek encapsulates: {stderr}");
    let (code, _, stderr) = run_pq(
        &oxi,
        &["ml-kem", "decaps", "512", "--dk", "dk", "--ct", "ct"],
        b"",
        &[],
    );
    assert_eq!(code, 0, "control: the canonical dk decapsulates: {stderr}");

    let (code, stdout, stderr) = run_pq(
        &oxi,
        &[
            "ml-kem", "encaps", "512", "--ek", "bad.ek", "--ct", "ct.bad",
        ],
        b"",
        &[],
    );
    assert_eq!(
        (code, stderr.as_str()),
        (2, "bad.ek: not a valid ML-KEM-512 key\n")
    );
    assert!(stdout.is_empty());
    assert!(!d.join("ct.bad").exists(), "no ciphertext is written");

    let (code, stdout, stderr) = run_pq(
        &oxi,
        &["ml-kem", "decaps", "512", "--dk", "bad.dk", "--ct", "ct"],
        b"",
        &[],
    );
    assert_eq!(
        (code, stderr.as_str()),
        (2, "bad.dk: not a valid ML-KEM-512 key\n")
    );
    assert!(stdout.is_empty(), "no secret is printed");
}

/// A key pair that fails its pairwise consistency test is reported as a
/// conditional self-test failure, exit 1, and nothing is written.
#[cfg(feature = "fault-injection")]
#[test]
fn module_verdicts_mapped_pct_failure() {
    let oxi = signed("verdict-pct");
    let d = dir(&oxi);
    let fault = [("OXI_FAULT", "corrupt-next-key")];
    let kem_seed = [
        hex(&data("ml-kem-1024-keygen-tg3-tc51.d")),
        hex(&data("ml-kem-1024-keygen-tg3-tc51.z")),
    ];
    let dsa = ["ml-dsa", "keygen", "87", "--pk", "pk", "--sk", "sk"];
    let kem = [
        "ml-kem",
        "keygen",
        "1024",
        "--d",
        &kem_seed[0],
        "--z",
        &kem_seed[1],
        "--ek",
        "ek",
        "--dk",
        "dk",
    ];

    let (code, _, stderr) = run_pq(&oxi, &dsa, b"", &fault);
    assert_eq!(
        (code, stderr.as_str()),
        (
            1,
            "oxi ml-dsa keygen: conditional self-test failed: ML-DSA-87 pairwise consistency; \
             the module is in its error state\n"
        )
    );
    let (code, _, stderr) = run_pq(&oxi, &kem, b"", &fault);
    assert_eq!(
        (code, stderr.as_str()),
        (
            1,
            "seed supplied: protect this seed as you would the secret key\n\
             oxi ml-kem keygen: conditional self-test failed: ML-KEM-1024 pairwise consistency; \
             the module is in its error state\n"
        )
    );
    for f in ["pk", "sk", "ek", "dk"] {
        assert!(!d.join(f).exists(), "{f} must not be written");
    }

    let (code, _, stderr) = run_pq(&oxi, &dsa, b"", &[]);
    assert_eq!(code, 0, "control: unfaulted ML-DSA keygen: {stderr}");
    let (code, _, stderr) = run_pq(&oxi, &kem, b"", &[]);
    assert_eq!(code, 0, "control: unfaulted ML-KEM keygen: {stderr}");
}

/// An entropy source that fails to start is reported as unavailable, exit
/// 1, and nothing is written.
#[cfg(feature = "fault-injection")]
#[test]
fn module_verdicts_mapped_entropy_unavailable() {
    const UNAVAILABLE: &str =
        "oxi: the module's entropy source is unavailable; restart the process\n";
    let oxi = signed("verdict-entropy");
    let d = dir(&oxi);
    let fault = [("OXI_FAULT", "poison-entropy")];
    let keygen = ["ml-kem", "keygen", "768", "--ek", "ek", "--dk", "dk"];

    let (code, _, stderr) = run_pq(&oxi, &keygen, b"", &fault);
    assert_eq!((code, stderr.as_str()), (1, UNAVAILABLE));
    assert!(!d.join("ek").exists() && !d.join("dk").exists());
    let (code, _, stderr) = run_pq(
        &oxi,
        &["ml-dsa", "keygen", "65", "--pk", "pk", "--sk", "sk"],
        b"",
        &fault,
    );
    assert_eq!((code, stderr.as_str()), (1, UNAVAILABLE));
    assert!(!d.join("pk").exists() && !d.join("sk").exists());

    let (code, _, stderr) = run_pq(&oxi, &keygen, b"", &[]);
    assert_eq!(code, 0, "control: an unpoisoned keygen: {stderr}");
    let (code, stdout, stderr) = run_pq(
        &oxi,
        &["ml-kem", "encaps", "768", "--ek", "ek", "--ct", "ct"],
        b"",
        &fault,
    );
    assert_eq!((code, stderr.as_str()), (1, UNAVAILABLE));
    assert!(stdout.is_empty() && !d.join("ct").exists());
}
