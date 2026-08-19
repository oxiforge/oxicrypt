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
//! | `oxi --lama` | Dump the LAMA manifest |
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

    // --lama: dump the LAMA manifest and exit.
    if args.iter().any(|a| a == "--lama") {
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
    if args.iter().any(|a| a == "--integrity") {
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
        return ExitCode::FAILURE;
    }

    let rest = args.get(2..).unwrap_or(&[]);
    match args.get(1).map(String::as_str) {
        Some("hash") => cmd_hash(rest),
        Some("hmac") => cmd_hmac(rest),
        Some("rand") => cmd_rand(rest),
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
    eprintln!("  --lama                       Dump LAMA manifest (YAML)");
    eprintln!("  --integrity                  Report the integrity test's outcome");
    eprintln!();
    eprintln!("Algorithms:");
    eprintln!("  sha1, sha224, sha256, sha384, sha512");
    eprintln!("  sha512-224, sha512-256");
    eprintln!("  sha3-224, sha3-256, sha3-384, sha3-512");
    ExitCode::from(2)
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
    let status = oxicrypt_integrity::status();
    let (line, remedy): (&str, &[&str]) = match status {
        oxicrypt_integrity::IntegrityStatus::Passed => (
            "passed — this binary matches the reference recorded inside it",
            &[],
        ),
        oxicrypt_integrity::IntegrityStatus::SlotInvalid => (
            "not signed — this binary carries no valid integrity slot",
            &[
                "Sign it:  oxicrypt-integrity-sign --sign <this binary>",
                "`cargo install` cannot do this: it has no step after linking in which",
                "to write the slot. See docs/integrity-signing.md.",
            ],
        ),
        oxicrypt_integrity::IntegrityStatus::Mismatch => (
            "FAILED — this binary does not match the reference recorded inside it",
            &[
                "Something modified the binary after it was signed — stripping,",
                "compression, or a platform signing tool. Rebuild and sign again,",
                "signing last.",
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

    println!("integrity: {line}");
    for note in remedy {
        println!("  {note}");
    }
    // Three outcomes, three codes, because "the image is wrong" and "we could
    // not look" call for different responses and a script should not have to
    // parse prose to tell them apart. Both are non-zero: the module refuses to
    // become operational either way, so reporting success would be reporting a
    // binary as usable when every command it offers will fail.
    match status {
        oxicrypt_integrity::IntegrityStatus::Passed => ExitCode::SUCCESS,
        oxicrypt_integrity::IntegrityStatus::Mismatch
        | oxicrypt_integrity::IntegrityStatus::SlotInvalid => ExitCode::FAILURE,
        _ => ExitCode::from(3),
    }
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
    let groups: &[&[oxicrypt_module::KatEntry]] = &[
        oxicrypt_sha::KATS,
        oxicrypt_hmac::KATS,
        oxicrypt_aes::KATS,
        oxicrypt_drbg::KATS,
    ];
    groups.iter().flat_map(|g| g.iter().copied()).collect()
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

    let result = match alg {
        "sha256" => hmac_oneshot::<oxicrypt_sha::Sha256, 64, 32>(&key, &input),
        "sha1" => hmac_oneshot::<oxicrypt_sha::Sha1, 64, 20>(&key, &input),
        "sha224" => hmac_oneshot::<oxicrypt_sha::Sha224, 64, 28>(&key, &input),
        "sha384" => hmac_oneshot::<oxicrypt_sha::Sha384, 128, 48>(&key, &input),
        "sha512" => hmac_oneshot::<oxicrypt_sha::Sha512, 128, 64>(&key, &input),
        _ => {
            eprintln!(
                "oxi hmac: unknown algorithm '{alg}' (supported: sha1, sha224, sha256, sha384, sha512)"
            );
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

    /// Every `oxicrypt_*` crate whose items `src` calls.
    fn crates_called(src: &str) -> BTreeSet<String> {
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
    fn crates_in_inventory(src: &str) -> BTreeSet<String> {
        let start = src
            .find("fn power_up_tests()")
            .expect("power_up_tests is no longer declared");
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

        let listed = crates_in_inventory(
            "fn power_up_tests() {\n    oxicrypt_sha::KATS,\n    oxicrypt_hmac::KATS,\n}\n",
        );
        assert_eq!(
            listed.len(),
            2,
            "the inventory scanner misread its own shape"
        );
        // A crate merely named inside the inventory, without its KATS, is not
        // covered by it — which is exactly the drift this guards against.
        let partial = crates_in_inventory(
            "fn power_up_tests() {\n    oxicrypt_sha::KATS,\n    oxicrypt_aes::something_else,\n}\n",
        );
        assert_eq!(partial.len(), 1, "only a KATS reference counts as coverage");
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
