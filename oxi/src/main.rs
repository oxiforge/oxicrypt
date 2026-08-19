//! `oxi` — command-line interface for oxicrypt.
//!
//! A thin wrapper that exposes the module's approved services to
//! the terminal. Useful for quick checks, scripting, and learning
//! the API surface without writing Rust.
//!
//! # Subcommands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `oxi hash <alg> [FILE]` | Hash a file (or stdin) with an approved algorithm |
//! | `oxi hmac <alg> <key-hex> [FILE]` | HMAC a file (or stdin) |
//! | `oxi rand <nbytes>` | Generate random bytes from HMAC_DRBG-SHA-256 |
//! | `oxi selftest` | Run the module's self-tests on demand and report each one |
//! | `oxi --lama` | Dump the LAMA manifest |
//! | `oxi --integrity` | Report the pre-operational integrity test's outcome |
//!
//! Reads from stdin when no file argument is given.
#![allow(
    // CLI binary must print to stdout/stderr.
    clippy::print_stdout,
    clippy::print_stderr,
    // Top-level error handling uses `expect` for fatal paths that
    // cannot be recovered from in a CLI context.
    clippy::expect_used,
)]

use std::fmt::Write as _;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // The pre-initialization flags are matched at argv[1] ONLY, never scanned
    // across the whole command line.
    //
    // `args.iter().any(|a| a == "--integrity")` reads naturally and is a defect:
    // it cannot tell a flag from a file whose NAME is that flag, so
    // `oxi hash sha256 -- --integrity` reported on the binary instead of
    // hashing the file, and exited 0 having printed something a script would
    // read as the digest. The subcommands below were already positional; these
    // are now too.
    let flag = args.get(1).map(String::as_str);

    // --lama: dump the LAMA manifest and exit.
    if flag == Some("--lama") {
        print!("{}", include_str!("../llm-api.yaml"));
        // The embedded manifest carries the exact build.
        // A top-level key keeps the output a single YAML document.
        // Quoted: a short SHA is often all digits (~5% of commits), and YAML
        // would then parse it as an integer — with a leading zero, as octal.
        println!("build_commit: \"{}\"", env!("OXICRYPT_COMMIT"));
        return ExitCode::SUCCESS;
    }

    // --integrity: report why the module will or will not start, and exit.
    //
    // Handled here, ahead of initialization, because its whole purpose is to be
    // reachable when initialization fails. A binary that cannot verify its own
    // image otherwise reports a self-test failure named after a test, which
    // tells the person holding it nothing about what to do next.
    if flag == Some("--integrity") {
        return report_integrity();
    }

    if args.len() < 2 {
        return usage();
    }

    // Initialize the module: the integrity group plus every algorithm group
    // this binary can reach. That the second list covers the subcommands below
    // is checked — see `power_up_tests`.
    if let Err(e) = init_module() {
        eprintln!("fatal: module initialization failed: {e}");
        // The integrity test is the failure a person holding a fresh
        // `cargo install` actually hits, and it has a one-command remedy.
        // Naming the test that failed and stopping there leaves them reading
        // a test's name, which says nothing about what to do next. The
        // diagnosis is shared with `--integrity` so the two cannot drift, and
        // it stays silent when the failure was something else.
        for line in integrity_diagnosis().remedy {
            eprintln!("  {line}");
        }
        return ExitCode::FAILURE;
    }

    let rest = args.get(2..).unwrap_or(&[]);
    match args.get(1).map(String::as_str) {
        Some("hash") => cmd_hash(rest),
        Some("hmac") => cmd_hmac(rest),
        Some("rand") => cmd_rand(rest),
        Some("selftest") => cmd_selftest(rest),
        Some("--help" | "-h") | None => usage(),
        Some(other) => {
            eprintln!("oxi: unknown command '{other}'");
            usage()
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("Usage: oxi <command> [args...]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  hash <alg> [FILE]            Hash a file or stdin");
    eprintln!("  hmac <alg> <key-hex> [FILE]  HMAC a file or stdin");
    eprintln!("  rand <nbytes>                Generate random bytes (hex)");
    eprintln!("  selftest [--quiet]           Run the module's self-tests and report each one");
    eprintln!("  --lama                       Dump LAMA manifest (YAML)");
    eprintln!("  --integrity                  Report the integrity test's outcome");
    eprintln!();
    eprintln!("Algorithms:");
    eprintln!("  sha1, sha224, sha256, sha384, sha512");
    eprintln!("  sha512-224, sha512-256");
    eprintln!("  sha3-224, sha3-256, sha3-384, sha3-512");
    ExitCode::from(2)
}

/// One sentence naming the state of the pre-operational integrity test, and
/// the lines that say what to do about it.
///
/// Read by two callers that must not disagree: `--integrity`, which a person
/// runs to ask, and the startup path, which has just failed and has to say
/// something more useful than the name of a test.
struct Diagnosis {
    line: &'static str,
    remedy: &'static [&'static str],
}

/// Interprets the latched integrity indicator.
///
/// Reads `status()` and nothing else, so it can be called after the module has
/// already run the test — the startup path — without running it a second time.
/// `report_integrity` performs the test first, because in that path nothing
/// has.
fn integrity_diagnosis() -> Diagnosis {
    let (line, remedy): (&str, &[&str]) = match oxicrypt_integrity::status() {
        oxicrypt_integrity::IntegrityStatus::Passed => (
            "passed — this binary matches the reference recorded inside it",
            &[],
        ),
        oxicrypt_integrity::IntegrityStatus::SlotInvalid => (
            "not signed — this binary carries no valid integrity slot",
            // The signer is a separate tool on purpose. A module binary able to
            // rewrite its own image is a capability nobody needs and a reviewer
            // would rightly ask about, and it buys nothing: anyone who can
            // install this crate can install that one.
            &[
                "Sign it:  cargo install oxicrypt-integrity-sign",
                "          oxicrypt-integrity-sign --sign <this binary>",
                "`cargo install` cannot do it for you — it has no step after",
                "linking in which to write the slot. See docs/integrity-signing.md.",
            ],
        ),
        oxicrypt_integrity::IntegrityStatus::Mismatch => (
            "FAILED — this binary does not match the reference recorded inside it",
            // Deliberately NOT "sign it again". Signing writes a new reference
            // over whatever the file now contains, so re-signing a modified
            // binary makes the check pass on the modification — the module
            // would be instructing someone to bless exactly what it just
            // caught.
            &[
                "Do NOT re-sign it. Signing records a new reference over whatever",
                "this file now contains, so it would make the check pass on the",
                "change rather than undo it.",
                "Replace the binary: re-download the release artifact and check it",
                "against the SHA-256 published with it, or rebuild from source.",
                "Something rewrote it after it was signed — a platform signing tool",
                "or a stripping or compression step, if not an attacker.",
            ],
        ),
        oxicrypt_integrity::IntegrityStatus::Unreadable => (
            "not performed — the module could not read its own loaded image",
            &[
                "This platform has no supported mechanism for the module to read",
                "itself. The result says nothing about whether the image is intact.",
            ],
        ),
        oxicrypt_integrity::IntegrityStatus::CastNotRun => (
            "not performed — reached before the self-test it depends on",
            &[],
        ),
        oxicrypt_integrity::IntegrityStatus::NotRun => {
            ("not performed — the test did not run", &[])
        }
        oxicrypt_integrity::IntegrityStatus::Unknown => (
            "unknown — the recorded indicator is not a value this module writes",
            &[],
        ),
        // The enum is non-exhaustive. A variant this build has never heard of is
        // reported as such rather than folded into one of the above, which would
        // put a confident wrong label on an unrecognised state.
        _ => (
            "unrecognised — this build of `oxi` does not know that indicator",
            &[],
        ),
    };
    Diagnosis { line, remedy }
}

/// Reports the pre-operational integrity test's outcome, and what to do about
/// it.
///
/// Exit codes: `0` the image matched, `1` it did not or the slot is unusable,
/// `3` the test was not performed and the image's state is unknown.
///
/// Runs the test rather than reading a stale indicator: `status()` latches on
/// the first run and reads `NotRun` before one, so calling it alone here would
/// report nothing at all. The technique's own CAST runs first because the
/// integrity test depends on it, and skipping it would turn every answer into
/// "the test was reached before the CAST it depends on".
fn report_integrity() -> ExitCode {
    if let Err(e) = oxicrypt_integrity::hmac_cast() {
        println!("integrity: unavailable — the technique's own self-test failed: {e}");
        println!("  This is the HMAC-SHA-256 implementation the test uses, not your binary.");
        return ExitCode::FAILURE;
    }

    let _ = oxicrypt_integrity::verify_loaded_image();
    let diagnosis = integrity_diagnosis();
    println!("integrity: {}", diagnosis.line);
    // Only where a comparison actually happened. On an unsigned binary nothing
    // was compared, and printing what the extent WOULD cover reads as though
    // something had been — the opposite of what this line is for.
    if matches!(
        oxicrypt_integrity::status(),
        oxicrypt_integrity::IntegrityStatus::Passed | oxicrypt_integrity::IntegrityStatus::Mismatch
    ) {
        print_extent();
    }
    for note in diagnosis.remedy {
        println!("  {note}");
    }
    // Three outcomes, three codes, because "the image is wrong" and "we could
    // not look" call for different responses and a script should not have to
    // parse prose to tell them apart. Both are non-zero: the module refuses to
    // become operational either way, so reporting success would be reporting a
    // binary as usable when every command it offers will fail.
    match oxicrypt_integrity::status() {
        oxicrypt_integrity::IntegrityStatus::Passed => ExitCode::SUCCESS,
        oxicrypt_integrity::IntegrityStatus::Mismatch
        | oxicrypt_integrity::IntegrityStatus::SlotInvalid => ExitCode::FAILURE,
        _ => ExitCode::from(3),
    }
}

/// Reports which bytes of this binary the integrity test covers.
///
/// The verdict alone says whether the image matched; it does not say what was
/// compared, and "the module verified itself" means little without that. The
/// extent is a strict subset of the file by construction — the slot holding the
/// reference is excluded, and so is everything the loader rewrites.
///
/// Read from the slot itself rather than by re-deriving the layout from the
/// file. Two reasons, and the second is why this is not merely equivalent:
/// the slot's range table is *what the verifier actually hashed*, so it cannot
/// disagree with the verdict printed beside it; and it needs only the slot
/// codec, where re-deriving would link an executable-format parser into the
/// binary — code with no cryptographic role, inside the very extent the
/// integrity test protects.
///
/// Silent when the slot does not parse, which is the unsigned case, where
/// nothing was compared and there is nothing to report.
fn print_extent() {
    let slot = &oxicrypt_integrity::FIPS_INTEGRITY_SLOT;
    let mut bytes = Vec::with_capacity(oxicrypt_integrity::SLOT_SIZE);
    bytes.extend_from_slice(&slot.hdr);
    bytes.extend_from_slice(&slot.body);
    bytes.extend_from_slice(&slot.ftr);

    let Ok(parsed) = oxicrypt_integrity::slot::parse(&bytes) else {
        return;
    };
    let Some(extent) = oxicrypt_integrity::slot::extent_len(&parsed.ranges) else {
        return;
    };
    println!(
        "  extent: {extent} bytes in {} range(s) — the loader-invariant image, \
         less the slot",
        parsed.ranges.len()
    );
    println!("  (oxicrypt-integrity-sign --show reports the full breakdown)");
}

/// Pre-operational self-tests for the services this CLI offers.
///
/// The integrity test runs first as its own, separate argument to
/// [`oxicrypt_module::initialize_with_tests`]. This inventory covers the
/// approved algorithms reachable from the subcommands: SHA for `hash`,
/// HMAC for `hmac`, and the DRBG — with the AES it is built on — for
/// `rand`.
///
/// The module refuses to become operational without an integrity group,
/// which is a separate parameter. That guarantee does not extend to this
/// inventory — a subcommand added without its KATs would start, and run an
/// algorithm that was never self-tested. So a test enforces the coverage the
/// module does not: `the_inventory_covers_every_algorithm_the_subcommands_reach`
/// derives the crates this file calls and requires each to appear here, with
/// the two exemptions named and their reasons recorded beside them.
fn power_up_tests() -> Vec<oxicrypt_module::KatEntry> {
    inventory()
        .iter()
        .flat_map(|(_, group)| group.iter().copied())
        .collect()
}

/// The power-up inventory, named by the crate that publishes each group.
///
/// One source with two readers: [`power_up_tests`] flattens it for
/// [`oxicrypt_module::initialize_with_tests`], and `cmd_selftest` walks it to
/// show an operator each test in turn. Two lists would be two opinions about
/// what this binary self-tests, and the one the operator watched would be the
/// one that could drift from the one that ran.
///
/// The integrity group is deliberately absent: it is
/// `initialize_with_tests`' separate first argument, because the module refuses
/// to become operational without it. `cmd_selftest` prepends it for display.
fn inventory() -> &'static [(&'static str, &'static [oxicrypt_module::KatEntry])] {
    &[
        ("sha", oxicrypt_sha::KATS),
        ("hmac", oxicrypt_hmac::KATS),
        ("aes", oxicrypt_aes::KATS),
        ("drbg", oxicrypt_drbg::KATS),
    ]
}

fn init_module() -> Result<(), oxicrypt_module::Error> {
    match oxicrypt_module::initialize_with_tests(oxicrypt_integrity::KATS, &power_up_tests()) {
        Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => Ok(()),
        Err(e) => Err(e),
    }
}

// ── hash ────────────────────────────────────────────────────────

fn cmd_hash(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("oxi hash: missing algorithm argument");
        return ExitCode::from(2);
    }
    let alg = args.first().map_or("", String::as_str);
    let input = match read_input(args.get(1).map(String::as_str)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("oxi hash: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = match alg {
        "sha1" => oxicrypt_sha::sha1(&input).map(|d| d.to_vec()),
        "sha224" => oxicrypt_sha::sha224(&input).map(|d| d.to_vec()),
        "sha256" => oxicrypt_sha::sha256(&input).map(|d| d.to_vec()),
        "sha384" => oxicrypt_sha::sha384(&input).map(|d| d.to_vec()),
        "sha512" => oxicrypt_sha::sha512(&input).map(|d| d.to_vec()),
        "sha512-224" => oxicrypt_sha::sha512_224(&input).map(|d| d.to_vec()),
        "sha512-256" => oxicrypt_sha::sha512_256(&input).map(|d| d.to_vec()),
        "sha3-224" => oxicrypt_sha::sha3_224(&input).map(|d| d.to_vec()),
        "sha3-256" => oxicrypt_sha::sha3_256(&input).map(|d| d.to_vec()),
        "sha3-384" => oxicrypt_sha::sha3_384(&input).map(|d| d.to_vec()),
        "sha3-512" => oxicrypt_sha::sha3_512(&input).map(|d| d.to_vec()),
        _ => {
            eprintln!("oxi hash: unknown algorithm '{alg}'");
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(digest) => {
            println!("{}  -", hex(&digest));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("oxi hash: {e}");
            ExitCode::FAILURE
        }
    }
}

// ── hmac ────────────────────────────────────────────────────────

fn cmd_hmac(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("oxi hmac: usage: oxi hmac <alg> <key-hex> [FILE]");
        return ExitCode::from(2);
    }
    let alg = args.first().map_or("", String::as_str);
    let key_hex = args.get(1).map_or("", String::as_str);
    let key = match decode_hex(key_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("oxi hmac: bad key hex: {e}");
            return ExitCode::from(2);
        }
    };
    let input = match read_input(args.get(2).map(String::as_str)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("oxi hmac: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Every variant `oxicrypt-hmac` implements `BlockHash` for, which is every
    // variant the power-up inventory self-tests. `oxi selftest` shows all
    // eleven passing, so refusing six of them at the prompt would tell the
    // operator the module can do something this CLI then declines to do.
    let result = match alg {
        "sha1" => hmac_oneshot::<oxicrypt_sha::Sha1, 64, 20>(&key, &input),
        "sha224" => hmac_oneshot::<oxicrypt_sha::Sha224, 64, 28>(&key, &input),
        "sha256" => hmac_oneshot::<oxicrypt_sha::Sha256, 64, 32>(&key, &input),
        "sha384" => hmac_oneshot::<oxicrypt_sha::Sha384, 128, 48>(&key, &input),
        "sha512" => hmac_oneshot::<oxicrypt_sha::Sha512, 128, 64>(&key, &input),
        "sha512-224" => hmac_oneshot::<oxicrypt_sha::sha512_t::Sha512_224, 128, 28>(&key, &input),
        "sha512-256" => hmac_oneshot::<oxicrypt_sha::sha512_t::Sha512_256, 128, 32>(&key, &input),
        "sha3-224" => hmac_oneshot::<oxicrypt_sha::sha3::Sha3<144, 28>, 144, 28>(&key, &input),
        "sha3-256" => hmac_oneshot::<oxicrypt_sha::sha3::Sha3<136, 32>, 136, 32>(&key, &input),
        "sha3-384" => hmac_oneshot::<oxicrypt_sha::sha3::Sha3<104, 48>, 104, 48>(&key, &input),
        "sha3-512" => hmac_oneshot::<oxicrypt_sha::sha3::Sha3<72, 64>, 72, 64>(&key, &input),
        _ => {
            eprintln!("oxi hmac: unknown algorithm '{alg}'");
            eprintln!("  supported: sha1, sha224, sha256, sha384, sha512, sha512-224, sha512-256,");
            eprintln!("             sha3-224, sha3-256, sha3-384, sha3-512");
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(tag) => {
            println!("{}  -", hex(&tag));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("oxi hmac: {e}");
            ExitCode::FAILURE
        }
    }
}

fn hmac_oneshot<H: oxicrypt_hmac::BlockHash<B, L>, const B: usize, const L: usize>(
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, oxicrypt_module::Error> {
    let mut mac = oxicrypt_hmac::Hmac::<H, B, L>::new(key)?;
    mac.update(data);
    Ok(mac.finalize().to_vec())
}

// ── rand ────────────────────────────────────────────────────────

fn cmd_rand(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("oxi rand: usage: oxi rand <nbytes>");
        return ExitCode::from(2);
    }
    let nbytes: usize = match args.first().map_or("0", String::as_str).parse() {
        Ok(n) if n > 0 => n,
        _ => {
            eprintln!("oxi rand: nbytes must be a positive integer");
            return ExitCode::from(2);
        }
    };

    // Seed HMAC_DRBG from OS entropy.
    let mut entropy = [0u8; 48]; // 32 entropy + 16 nonce
    if getrandom(&mut entropy).is_err() {
        eprintln!("oxi rand: failed to read OS entropy");
        return ExitCode::FAILURE;
    }

    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    let (ent, nonce) = entropy.split_at(32);
    if let Err(e) = drbg.instantiate(ent, nonce, b"oxi-cli") {
        eprintln!("oxi rand: DRBG instantiate failed: {e}");
        return ExitCode::FAILURE;
    }

    let mut buf = vec![0u8; nbytes];
    if let Err(e) = drbg.generate(None, &mut buf) {
        eprintln!("oxi rand: DRBG generate failed: {e}");
        return ExitCode::FAILURE;
    }

    println!("{}", hex(&buf));
    ExitCode::SUCCESS
}

// ── selftest ────────────────────────────────────────────────────

/// Runs the module's self-tests on demand and reports each one.
///
/// # Why this exists, and what it is
///
/// The module runs its full power-up battery before it becomes operational —
/// the integrity test first, then every known-answer test in the inventory —
/// and then says nothing about it. An operator holding the binary has no way to
/// see what was tested. This is that view: the same inventory, each entry run
/// again and reported by name.
///
/// **ISO/IEC 19790:2012 §7.10.1 and FIPS 140-3 IG 10.3.E**: at Security Levels 1
/// and 2, acceptable means for initiating the self-tests include *a provided
/// service*, resetting, rebooting or power cycling. This is the provided
/// service. The automatic-timer obligations (`AS10.54`, `AS10.55`) apply at
/// Levels 3 and 4 and are not claimed here.
///
/// **The indicator is required, not decoration.** IG's reading of `AS02.24`:
/// self-tests themselves need no indicator, but *a service providing on-demand
/// self-tests does*. So this prints an explicit terminal verdict line and
/// carries it in the exit code.
///
/// # What it does NOT claim
///
/// It re-runs the test functions; it does not re-establish the module's
/// pre-operational state. `initialize_with_tests` claims the `SelfTest` phase
/// with a compare-exchange from `PowerOff` and is one-shot per process, by
/// design — a second caller gets `AlreadyInitialized`. So this is reachable
/// only on a module that ALREADY passed its power-up tests, which is the
/// conservative order: it can demonstrate the tests, never substitute for them.
/// A restart remains the way to re-run the pre-operational sequence itself.
///
/// A failure here is treated as a self-test failure, not as a report: the
/// module is placed in the error state, which is what
/// ISO/IEC 19790:2012 §7.10.3 requires of a failed self-test, and every service
/// call afterwards is refused.
fn cmd_selftest(args: &[String]) -> ExitCode {
    let mut quiet = false;
    for a in args {
        if a == "--quiet" {
            quiet = true;
        } else {
            eprintln!("oxi selftest: unexpected argument '{a}'");
            eprintln!("usage: oxi selftest [--quiet]");
            return ExitCode::from(2);
        }
    }

    if !quiet {
        println!("oxi selftest — on-demand invocation of the module's self-tests");
        println!("  module state: {:?}", oxicrypt_module::state());
        println!("  these are the tests this binary runs at power-up; each is run again below");
        println!();
    }

    // The integrity group first, exactly as `initialize_with_tests` orders it:
    // everything after it depends on its verdict.
    let groups: Vec<(&str, &[oxicrypt_module::KatEntry])> =
        core::iter::once(("integrity", oxicrypt_integrity::KATS))
            .chain(inventory().iter().copied())
            .collect();

    let mut passed = 0_usize;
    let mut failed: Vec<&str> = Vec::new();
    for (group, entries) in &groups {
        if !quiet {
            println!("{group} ({})", entries.len());
        }
        for entry in *entries {
            if (entry.run)().is_err() {
                failed.push(entry.name);
                if !quiet {
                    println!("  FAIL  {}", entry.name);
                }
            } else {
                passed = passed.saturating_add(1);
                if !quiet {
                    println!("  ok    {}", entry.name);
                }
            }
        }
    }

    let total = passed.saturating_add(failed.len());
    if !quiet {
        println!();
    }
    println!("{passed} of {total} self-tests passed");

    if failed.is_empty() {
        // The indicator required of a service that provides on-demand
        // self-tests. One line, fixed wording, and the exit code agrees with
        // it so a script need not parse prose.
        println!("self-test indicator: PASS");
        ExitCode::SUCCESS
    } else {
        // A self-test that fails is not a report. The module goes to the error
        // state and refuses every service from here on, which is what a failed
        // self-test means.
        oxicrypt_module::enter_error_state("on-demand self-test failed");
        for name in &failed {
            println!("  failed: {name}");
        }
        println!("self-test indicator: FAIL");
        println!("  The module has been placed in the error state and will refuse");
        println!("  every service until it is restarted. Do not use this binary.");
        ExitCode::FAILURE
    }
}

// ── helpers ─────────────────────────────────────────────────────

/// Read from a file path or stdin.
fn read_input(path: Option<&str>) -> io::Result<Vec<u8>> {
    if let Some(p) = path {
        std::fs::read(p)
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

/// Quick hex encoder.
#[allow(clippy::arithmetic_side_effects)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

/// Decode a hex string into bytes.
#[allow(clippy::arithmetic_side_effects, clippy::integer_division)]
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(s.get(i..i + 2).ok_or_else(|| "short hex".to_string())?, 16)
                .map_err(|e| format!("invalid hex at byte {}: {e}", i / 2))
        })
        .collect()
}

/// Read random bytes from the OS. Thin wrapper over /dev/urandom.
fn getrandom(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read as _;
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;

    /// Crates whose KATs belong somewhere other than the inventory, with the
    /// reason each is exempt.
    ///
    /// `oxicrypt-module` publishes no algorithm and no `KATS`. `oxicrypt-integrity`
    /// publishes `KATS`, but they are passed as `initialize_with_tests`' *first*
    /// argument — the module refuses to become operational without them, which is
    /// a guarantee the inventory does not have and does not need to duplicate.
    const NOT_IN_THE_INVENTORY: [(&str, &str); 2] = [
        ("oxicrypt_module", "publishes no algorithm and no KATS"),
        (
            "oxicrypt_integrity",
            "its KATS are the separate integrity argument, which the module requires",
        ),
    ];

    /// The body of a named free function, from its `fn` line to the closing
    /// brace in column zero.
    ///
    /// Crude on purpose: the alternative is a parser, and the shapes it must
    /// handle are all in one file that a test asserts it can read.
    fn fn_body<'a>(src: &'a str, decl: &str) -> &'a str {
        let start = src
            .find(decl)
            .unwrap_or_else(|| panic!("{decl} is no longer declared"));
        let rest = src.get(start..).unwrap_or_default();
        let end = rest
            .find("\n}\n")
            .unwrap_or_else(|| panic!("{decl} is unterminated"));
        rest.get(..end).unwrap_or_default()
    }

    /// Every `oxicrypt_*` crate whose items `src` calls, ignoring comments.
    ///
    /// Comments are stripped because a crate path inside one is not a call, and
    /// the exemption check below turns that distinction into a live question: it
    /// requires each exempted crate to still be reached from this file, so a
    /// path surviving only in prose would keep a stale exemption alive.
    fn crates_called(src: &str) -> BTreeSet<String> {
        let stripped: String = src
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => l.get(..i).unwrap_or_default(),
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let src = stripped.as_str();
        let mut out = BTreeSet::new();
        for token in src.split("oxicrypt_").skip(1) {
            let name: String = token
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            // A path, not a word: `oxicrypt_sha::sha256` counts, prose does not.
            if !name.is_empty() && token.get(name.len()..).is_some_and(|r| r.starts_with("::")) {
                out.insert(format!("oxicrypt_{name}"));
            }
        }
        out
    }

    /// Every crate whose `KATS` the power-up inventory lists.
    ///
    /// Reads `fn inventory`, which is where the groups are named.
    /// `power_up_tests` only flattens it and mentions no crate at all, so
    /// pointing this at that function would find nothing and report a fully
    /// uncovered inventory as fully covered.
    fn crates_in_inventory(src: &str) -> BTreeSet<String> {
        let start = src
            .find("fn inventory(")
            .expect("inventory is no longer declared");
        let rest = src.get(start..).unwrap_or_default();
        let end = rest.find("\n}\n").expect("power_up_tests is unterminated");
        crates_called(rest.get(..end).unwrap_or_default())
            .into_iter()
            .filter(|c| {
                rest.get(..end)
                    .unwrap_or_default()
                    .contains(&format!("{c}::KATS"))
            })
            .collect()
    }

    /// The two scanners read paths, not prose, and each other's absence.
    ///
    /// Without this the check below is unfalsifiable: a scanner that returned
    /// nothing would report a fully covered inventory.
    #[test]
    fn the_crate_scanners_catch_what_they_must() {
        let called = crates_called("oxicrypt_sha::sha256(&x); oxicrypt_hmac::KATS");
        assert!(called.contains("oxicrypt_sha") && called.contains("oxicrypt_hmac"));
        // The mirror control: a mention that is not a path is not a call.
        assert!(
            crates_called("the oxicrypt_sha crate, and oxicrypt_drbg generally").is_empty(),
            "prose must not read as a call"
        );
        // And a real path inside a COMMENT is still not a call. This one bites
        // in practice: the exemption block below discusses
        // `oxicrypt_integrity::mac_over_file_ranges` in prose, and without this
        // the exemption's own comment would satisfy the "is it still called?"
        // guard that exists to retire stale exemptions.
        assert!(
            crates_called("// see oxicrypt_ecdsa::sign for the shape").is_empty(),
            "a crate path inside a comment is not a call"
        );
        assert!(
            crates_called("let x = oxicrypt_sha::sha256(b\"\"); // and oxicrypt_ecdsa::sign")
                == ["oxicrypt_sha".to_owned()].into_iter().collect(),
            "code before a comment still counts; the comment does not"
        );

        let listed = crates_in_inventory(
            "fn inventory() {\n    oxicrypt_sha::KATS,\n    oxicrypt_hmac::KATS,\n}\n",
        );
        assert_eq!(
            listed.len(),
            2,
            "the inventory scanner misread its own shape"
        );
        // A crate merely named inside the inventory, without its KATS, is not
        // covered by it — which is exactly the drift this guards against.
        let partial = crates_in_inventory(
            "fn inventory() {\n    oxicrypt_sha::KATS,\n    oxicrypt_aes::something_else,\n}\n",
        );
        assert_eq!(partial.len(), 1, "only a KATS reference counts as coverage");
    }

    /// A failed on-demand self-test puts the module in the error state.
    ///
    /// ISO/IEC 19790:2012 §7.10.3 requires it, and the alternative — printing
    /// FAIL and leaving the module operational — is the worst outcome available:
    /// a binary that has just demonstrated a broken algorithm and will still
    /// serve it.
    ///
    /// A scan, because the branch cannot be driven by a fixture. A KAT fails
    /// only if an algorithm is genuinely broken, and the one test that CAN be
    /// made to fail — the image integrity check — takes the module down at
    /// initialization, before `selftest` is reachable at all. Deleting the
    /// `enter_error_state` call leaves every behavioural test green, which is
    /// exactly what makes this worth asserting rather than assuming.
    #[test]
    fn a_failed_on_demand_self_test_puts_the_module_in_the_error_state() {
        let src = include_str!("main.rs");
        let body = fn_body(src, "fn cmd_selftest");
        assert!(
            body.len() > 400,
            "premise failed: read {} bytes of cmd_selftest",
            body.len()
        );

        let call = body
            .find("enter_error_state(")
            .expect("a failed self-test must place the module in the error state");
        let pass = body
            .find(r#"println!("self-test indicator: PASS")"#)
            .expect("premise failed: the PASS indicator is gone");
        assert!(
            pass < call,
            "the error state belongs on the FAILURE branch, which follows the PASS one"
        );

        // The mirror control: the extractor is not simply returning the file.
        assert!(
            !fn_body(src, "fn usage(").contains("enter_error_state("),
            "the extractor is returning more than the named function's body"
        );
    }

    /// Every algorithm crate the CLI can reach has its known-answer tests in the
    /// power-up inventory.
    ///
    /// The module requires an integrity group before it will become operational.
    /// That guarantee does not extend to this inventory, so a subcommand added
    /// without its KATs would start and run an algorithm that was never
    /// self-tested. This is the check that was missing.
    #[test]
    fn the_inventory_covers_every_algorithm_the_subcommands_reach() {
        let src = include_str!("main.rs");
        let called = crates_called(src);
        let listed = crates_in_inventory(src);

        assert!(
            called.len() >= 4,
            "read only {} oxicrypt crates from this file — the scanner is broken, not the file",
            called.len()
        );
        assert!(
            !listed.is_empty(),
            "read no crates from the inventory — the scanner is broken"
        );
        for (exempt, reason) in NOT_IN_THE_INVENTORY {
            assert!(!reason.is_empty());
            assert!(
                called.contains(exempt),
                "the exemption names {exempt}, which this file no longer calls — remove it"
            );
        }

        let exempt: BTreeSet<String> = NOT_IN_THE_INVENTORY
            .iter()
            .map(|(c, _)| (*c).to_string())
            .collect();
        let uncovered: Vec<&String> = called
            .iter()
            .filter(|c| !exempt.contains(*c) && !listed.contains(*c))
            .collect();
        assert!(
            uncovered.is_empty(),
            "these crates are reachable from a subcommand but their KATS are not in \
             power_up_tests: {uncovered:?}"
        );
    }
}
