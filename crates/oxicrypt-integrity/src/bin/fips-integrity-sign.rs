//! CLI front-end for the software integrity self-test.
//!
//! Usage:
//!
//! ```text
//! fips-integrity-sign --sign   <path-to-binary> [<path-to-binary> ...]
//! fips-integrity-sign --verify <path-to-binary> [<path-to-binary> ...]
//!
//! Named-flag form (equivalent — flag pairs may be mixed with positional):
//!   --target          <path>   any binary type
//!   --cdylib-target   <path>   cdylib (.so / .dylib / .dll) — semantic alias for --target
//!   --staticlib-target <path>  staticlib (.a / .lib)        — semantic alias for --target
//! ```
//!
//! `--sign` computes HMAC-SHA-256 over the given binary with the
//! fixed integrity key from the `oxicrypt-integrity` crate, locates
//! the embedded slot (`HDR | 32 zero bytes | FTR`), and writes the
//! 32-byte MAC into the slot in place. `--verify` recomputes the MAC
//! and compares against the stored slot in constant time.
//!
//! Multiple binaries may be signed (or verified) in one invocation.
//! The named-flag form (`--cdylib-target` / `--staticlib-target`)
//! makes the artifact type explicit at the call site, which is
//! reviewer-friendly when documenting the signing pipeline. The
//! flags are semantic aliases — the tool itself does not inspect
//! the binary type, only its slot contents — so any mix of plain
//! `--target` and the typed aliases is accepted.
//!
//! Exit codes:
//!
//! - `0` — success (every target signed, or every verify matched)
//! - `1` — usage error (no targets, unknown flag, etc.)
//! - `2` — signing or verification failure on at least one target.
//!   Failures are reported individually; the tool processes every
//!   target before exiting non-zero so a single bad input does not
//!   mask diagnostics for the rest.
//!
//! This tool shares `oxicrypt_integrity::sign_exe` and
//! `oxicrypt_integrity::verify_exe` with the runtime power-up KAT so
//! the signing tool and the power-up check cannot disagree about the
//! algorithm.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use oxicrypt_integrity::{encode_hmac_hex, sign_exe, verify_exe};

#[derive(Copy, Clone)]
enum Mode {
    Sign,
    Verify,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode_arg) = argv.first() else {
        usage();
        return ExitCode::from(1);
    };

    let mode = match mode_arg.as_str() {
        "--sign" => Mode::Sign,
        "--verify" => Mode::Verify,
        _ => {
            usage();
            return ExitCode::from(1);
        }
    };

    let mut targets: Vec<PathBuf> = Vec::new();
    let mut iter = argv.iter().enumerate().skip(1).peekable();
    while let Some((_, a)) = iter.next() {
        match a.as_str() {
            "--target" | "--cdylib-target" | "--staticlib-target" => {
                let Some((_, path)) = iter.next() else {
                    eprintln!("error: {a} requires a path argument");
                    usage();
                    return ExitCode::from(1);
                };
                targets.push(PathBuf::from(path));
            }
            "--" => {
                // Explicit `--` separator is rejected — every later arg
                // would be ambiguous between "literal positional path"
                // and "broken flag-pair". Reject early so the operator
                // gets a diagnostic instead of silently signing a path
                // that may be a stray flag.
                eprintln!("error: bare `--` separator not supported");
                usage();
                return ExitCode::from(1);
            }
            _ if a.starts_with("--") => {
                eprintln!("error: unknown flag {a}");
                usage();
                return ExitCode::from(1);
            }
            _ => {
                targets.push(PathBuf::from(a));
            }
        }
    }

    if targets.is_empty() {
        eprintln!("error: no targets supplied");
        usage();
        return ExitCode::from(1);
    }

    let mut had_failure = false;
    for target in &targets {
        match mode {
            Mode::Sign => match sign_exe(target) {
                Ok(mac) => {
                    let hex = encode_hmac_hex(&mac);
                    let hex_str = std::str::from_utf8(&hex).unwrap_or("<non-utf8>");
                    println!("signed {} -> {}", target.display(), hex_str);
                }
                Err(e) => {
                    eprintln!("sign failed: {} -> {e}", target.display());
                    had_failure = true;
                }
            },
            Mode::Verify => match verify_exe(target) {
                Ok(()) => {
                    println!("verify ok: {}", target.display());
                }
                Err(e) => {
                    eprintln!("verify failed: {} -> {e}", target.display());
                    had_failure = true;
                }
            },
        }
    }

    if had_failure {
        ExitCode::from(2)
    } else {
        ExitCode::from(0)
    }
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  fips-integrity-sign --sign   <path> [<path> ...]");
    eprintln!("  fips-integrity-sign --verify <path> [<path> ...]");
    eprintln!();
    eprintln!("named flag form (equivalent — may be mixed with positional):");
    eprintln!("  --target           <path>   any binary type");
    eprintln!("  --cdylib-target    <path>   cdylib (.so / .dylib / .dll)");
    eprintln!("  --staticlib-target <path>   staticlib (.a / .lib)");
}
