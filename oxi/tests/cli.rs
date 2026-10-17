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
/// passing a path to it would not reproduce the defect at all.
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
/// The obvious choice — the middle of the executable range — was tried first
/// and is wrong here. `oxi` embeds a large binary; a byte chosen by arithmetic
/// lands on an arbitrary instruction, and corrupting one on the path the
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

// ---------------------------------------------------------------------

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
/// This is the control on the test above. Without it, a signing step that
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
/// NAME is that flag, so `oxi hash sha256 -- --integrity` reported on the binary
/// instead of hashing the file and exited 0 — a script hashing filenames it did
/// not choose would read the wrong thing as its digest. The pre-initialization
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

    // Every path an ordinary user reaches, including the ones that fail.
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
/// This is an ANTI-REGRESSION guard, not a description of behaviour. A
/// self-signing subcommand was built and then deliberately removed: a binary
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
    // Comments stripped: main.rs explains in prose why this capability was
    // removed, and an unstripped scan would fail on the explanation.
    let src: String = include_str!("../src/main.rs")
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => l.get(..i).unwrap_or_default(),
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
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
            "`{forbidden}` is back in oxi — it must not be able to write its own image"
        );
    }

    // The controls: the scan reads real code, and would notice if any of the
    // above reappeared. Both directions, or an empty `src` would pass.
    assert!(
        src.contains("oxicrypt_integrity::status()"),
        "premise failed: this scan is not reading oxi's main.rs"
    );
    assert!(
        format!("{src} current_exe").contains("current_exe"),
        "premise failed: the substring check cannot detect what it forbids"
    );
}

// ── selftest ────────────────────────────────────────────────────

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
    assert!(n >= 60, "expected the full inventory, got {n}");
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

    // Each group the CLI can reach is represented, named, and non-empty.
    for group in ["integrity", "sha", "hmac", "aes", "drbg"] {
        assert!(
            stdout.contains(&format!("\n{group} (")),
            "group {group} is missing from the report"
        );
    }
    // And the integrity test is named, since it is the one the operator most
    // wants to see and the one that is NOT part of the flat inventory.
    assert!(
        stdout.contains("Module image integrity"),
        "the integrity test must be reported"
    );
}

/// `--quiet` prints the indicator and the count, and nothing per-test.
#[test]
fn selftest_quiet_still_carries_the_indicator() {
    let oxi = scratch("selftest-quiet");
    sign(&oxi);

    let (code, stdout, _) = run(&oxi, &["selftest", "--quiet"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("self-test indicator: PASS"));
    assert!(
        !stdout.contains("ok    "),
        "--quiet must not print each test, got:\n{stdout}"
    );
    // The control: the non-quiet form DOES print them, so the absence above is
    // the flag working rather than the subcommand printing nothing either way.
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
/// then refused six of them would be telling the operator the module can do
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
/// "The module verified itself" means little without the extent: the MAC covers
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
