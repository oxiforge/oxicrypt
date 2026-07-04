//! ESV harness binary.
//!
//! A thin CLI over the [`esv_harness`] library. Slice S1 wires the
//! offline ESVP §2 building blocks; the live, credentialed submission
//! run is a separate attended session (like ACVTS), so the subcommands
//! here are offline utilities that exercise the request builders without
//! any network contact:
//!
//! - `esv-harness` (no args) — print a short description and usage.
//! - `esv-harness login-body --totp-secret <base64>` — compute the
//!   current TOTP and print the `/esv/v1/login` request body.
//! - `esv-harness bulk-refresh-body --totp-secret <base64> <jwt>...` —
//!   print the `/esv/v1/login/refresh` bulk-refresh body for the given
//!   tokens.
//!
//! The live login/refresh flow (`esv_harness::login::login` and friends)
//! is generic over `EsvTransport`; wiring it to acvp-harness's
//! curl(1)/mTLS transport lands with the attended demo smoke.
//!
//! Because this is a user-facing binary it may emit to stdout/stderr.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use acvp_harness::transport::{decode_totp_secret, totp_now};
use esv_harness::login::{build_bulk_refresh_body, build_login_body};

fn usage() {
    eprintln!(
        "esv-harness — ESVP §2 offline request builders (slice S1)\n\
         \n\
         USAGE:\n  \
         esv-harness login-body --totp-secret <base64>\n  \
         esv-harness bulk-refresh-body --totp-secret <base64> <jwt>...\n\
         \n\
         The live, credentialed submission run is a separate attended session."
    );
}

/// Pull the value following `--totp-secret` out of the argument list.
fn take_totp_secret(args: &[String]) -> Result<String, String> {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--totp-secret" {
            return it
                .next()
                .cloned()
                .ok_or_else(|| "--totp-secret requires a base64 value".to_string());
        }
    }
    Err("missing --totp-secret <base64>".to_string())
}

/// The positional token arguments (everything that isn't `--totp-secret`
/// or its value).
fn positional_tokens(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--totp-secret" {
            skip_next = true;
            continue;
        }
        out.push(arg.clone());
    }
    out
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        usage();
        return Ok(());
    };
    let command = command.as_str();

    match command {
        "login-body" => {
            let secret = decode_totp_secret(&take_totp_secret(rest)?)?;
            let code = totp_now(&secret)?;
            println!("{}", build_login_body(&code));
            Ok(())
        }
        "bulk-refresh-body" => {
            let secret = decode_totp_secret(&take_totp_secret(rest)?)?;
            let code = totp_now(&secret)?;
            let tokens = positional_tokens(rest);
            if tokens.is_empty() {
                return Err("bulk-refresh-body requires at least one <jwt> token".to_string());
            }
            println!("{}", build_bulk_refresh_body(&code, &tokens));
            Ok(())
        }
        other => {
            eprintln!("unknown subcommand: {other}\n");
            usage();
            Err(format!("unknown subcommand: {other}"))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("esv-harness: {e}");
            ExitCode::FAILURE
        }
    }
}
