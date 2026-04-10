//! CLI front-end for the software integrity self-test.
//!
//! Usage:
//!
//! ```text
//! fips-integrity-sign --sign   <path-to-exe>
//! fips-integrity-sign --verify <path-to-exe>
//! ```
//!
//! `--sign` computes HMAC-SHA-256 over the given executable with the
//! fixed integrity key from the `fips-integrity` crate and writes the
//! resulting 64-char lowercase hex MAC to `<path>.fipshmac`. `--verify`
//! recomputes the MAC and compares against an existing sidecar.
//!
//! Exit codes:
//!
//! - `0` — success (signed, or verify matched)
//! - `1` — usage error
//! - `2` — signing or verification failure
//!
//! This tool shares [`fips_integrity::compute_exe_hmac`],
//! [`fips_integrity::sign_exe`], and
//! [`fips_integrity::verify_exe_against_sidecar`] with the runtime
//! power-up KAT so the signing tool and the power-up check cannot
//! disagree about the algorithm.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use fips_integrity::{encode_hmac_hex, sign_exe, verify_exe_against_sidecar};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        usage();
        return ExitCode::from(1);
    };
    let Some(target) = args.next() else {
        usage();
        return ExitCode::from(1);
    };
    let target = PathBuf::from(target);
    if args.next().is_some() {
        usage();
        return ExitCode::from(1);
    }

    match mode.as_str() {
        "--sign" => match sign_exe(&target) {
            Ok(mac) => {
                let hex = encode_hmac_hex(&mac);
                // The encoded MAC is ASCII by construction.
                let hex_str = std::str::from_utf8(&hex).unwrap_or("<non-utf8>");
                println!("signed {} -> {}", target.display(), hex_str);
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("sign failed: {e}");
                ExitCode::from(2)
            }
        },
        "--verify" => match verify_exe_against_sidecar(&target) {
            Ok(()) => {
                println!("verify ok: {}", target.display());
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("verify failed: {e}");
                ExitCode::from(2)
            }
        },
        _ => {
            usage();
            ExitCode::from(1)
        }
    }
}

fn usage() {
    eprintln!("usage: fips-integrity-sign --sign|--verify <path-to-exe>");
}
