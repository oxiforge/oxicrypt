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
        print!(
            "{}",
            include_str!("../../docs/llm-api-manifest/llm-api.yaml")
        );
        return ExitCode::SUCCESS;
    }

    if args.len() < 2 {
        return usage();
    }

    // Initialize the module (skip KATs — the oxi binary isn't signed).
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
    eprintln!();
    eprintln!("Algorithms:");
    eprintln!("  sha1, sha224, sha256, sha384, sha512");
    eprintln!("  sha512-224, sha512-256");
    eprintln!("  sha3-224, sha3-256, sha3-384, sha3-512");
    ExitCode::from(2)
}

fn init_module() -> Result<(), oxicrypt_module::Error> {
    match oxicrypt_module::initialize() {
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
            eprintln!("oxi hmac: unknown algorithm '{alg}' (supported: sha1, sha224, sha256, sha384, sha512)");
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
    bytes.iter().fold(String::with_capacity(bytes.len().saturating_mul(2)), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
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
            u8::from_str_radix(
                s.get(i..i + 2).ok_or_else(|| "short hex".to_string())?,
                16,
            )
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
