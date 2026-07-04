//! ESV harness binary.
//!
//! A thin CLI over the [`esv_harness`] library. Slice S1 wires the
//! offline ESVP §2 building blocks; the live, credentialed submission
//! run is a separate attended session (like ACVTS), so the subcommands
//! here are offline utilities that exercise the request builders without
//! any network contact:
//!
//! - `esv-harness` (no args) — print a short description and usage.
//! - `esv-harness login-body` — read the base64 TOTP secret from
//!   **stdin**, compute the current TOTP, and print the `/esv/v1/login`
//!   request body.
//! - `esv-harness bulk-refresh-body <jwt>...` — read the base64 TOTP
//!   secret from **stdin** and print the `/esv/v1/login/refresh`
//!   bulk-refresh body for the given tokens.
//!
//! The TOTP secret is a credential: it is read from stdin (pipe-friendly)
//! and never taken on argv (world-readable via `/proc`, and lands in shell
//! history) or from the environment.
//!
//! The live login/refresh flow (`esv_harness::login::login` and friends)
//! is generic over `EsvTransport`; wiring it to acvp-harness's
//! curl(1)/mTLS transport lands with the attended demo smoke.
//!
//! Because this is a user-facing binary it may emit to stdout/stderr.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::Read;
use std::process::ExitCode;

use acvp_harness::transport::{decode_totp_secret, totp_now};
use esv_harness::login::{build_bulk_refresh_body, build_login_body};

fn usage() {
    eprintln!(
        "esv-harness — ESVP §2 offline request builders (slice S1)\n\
         \n\
         USAGE (the base64 TOTP secret is read from stdin, never argv):\n  \
         esv-harness login-body < secret.b64\n  \
         esv-harness bulk-refresh-body <jwt>... < secret.b64\n\
         \n\
         The live, credentialed submission run is a separate attended session."
    );
}

/// Read the base64 TOTP secret from stdin and decode it to raw bytes.
///
/// The secret is a credential, so it is piped in on stdin rather than
/// passed on argv (world-readable via `/proc`, shell history) or via the
/// environment. Surrounding whitespace/newlines are trimmed.
fn read_totp_secret_from_stdin() -> Result<Vec<u8>, String> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| format!("read TOTP secret from stdin: {e}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("no TOTP secret on stdin (pipe the base64 secret in)".to_string());
    }
    decode_totp_secret(trimmed)
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
            let secret = read_totp_secret_from_stdin()?;
            let code = totp_now(&secret)?;
            println!("{}", build_login_body(&code));
            Ok(())
        }
        "bulk-refresh-body" => {
            if rest.is_empty() {
                return Err("bulk-refresh-body requires at least one <jwt> token".to_string());
            }
            let secret = read_totp_secret_from_stdin()?;
            let code = totp_now(&secret)?;
            println!("{}", build_bulk_refresh_body(&code, rest));
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
