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

use std::io::{IsTerminal, Read};
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

/// Reject any argument that looks like a flag (starts with `-`).
///
/// The harness takes **no** flags: the base64 TOTP secret is read from stdin,
/// never argv. A legacy `--totp-secret <b64> <jwt>...` invocation would
/// otherwise smuggle the secret onto argv (world-readable via `/proc`, and
/// into shell history) *and*, for `bulk-refresh-body`, straight into the
/// emitted refresh body as if the flag and the secret were both JWTs (a real
/// JWT always begins `eyJ`, never `-`, so this rejects no valid token). Fail
/// closed. Pure, so the argv contract is unit-tested directly.
fn reject_flag_args(args: &[String]) -> Result<(), String> {
    if let Some(flag) = args.iter().find(|a| a.starts_with('-')) {
        return Err(format!(
            "unexpected flag argument {flag:?}: the TOTP secret is read from stdin, \
             flags are not accepted"
        ));
    }
    Ok(())
}

/// The one-line stderr notice shown when the base64 TOTP secret is being read
/// from an interactive terminal (so an operator isn't left staring at a silent
/// block). Pure so its wording is unit-tested; the tty branch that prints it
/// is manually verified — run `esv-harness login-body` with no pipe: the
/// notice prints, then Ctrl-D at the empty prompt yields the "no TOTP secret"
/// error.
fn tty_stdin_notice() -> &'static str {
    "reading base64 TOTP secret from stdin — end with EOF (Ctrl-D)"
}

/// Read the base64 TOTP secret from stdin and decode it to raw bytes.
///
/// The secret is a credential, so it is piped in on stdin rather than
/// passed on argv (world-readable via `/proc`, shell history) or via the
/// environment. When stdin is an interactive terminal, a one-line notice is
/// printed to stderr first so the read isn't a silent block. Surrounding
/// whitespace/newlines are trimmed.
fn read_totp_secret_from_stdin() -> Result<Vec<u8>, String> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!("{}", tty_stdin_notice());
    }
    let mut raw = String::new();
    stdin
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
            reject_flag_args(rest)?;
            let secret = read_totp_secret_from_stdin()?;
            let code = totp_now(&secret)?;
            println!("{}", build_login_body(&code));
            Ok(())
        }
        "bulk-refresh-body" => {
            reject_flag_args(rest)?;
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

/// The LAMA manifest, embedded at compile time so `--lama` needs no
/// external file at runtime (SPEC.md §"Discovery", requirement 1).
const LAMA_MANIFEST: &str = include_str!("../llm-api.yaml");

fn main() -> ExitCode {
    // ── LAMA manifest ───────────────────────────────────────────────
    // `--lama` prints the compile-time-embedded YAML manifest and exits,
    // ahead of `run()` and therefore ahead of the flag-shaped-argument
    // guard, which would otherwise reject it as an unknown subcommand.
    // See https://github.com/lamaspec/lama/blob/main/SPEC.md §"Discovery".
    if std::env::args().any(|a| a == "--lama") {
        print!("{LAMA_MANIFEST}");
        // Requirement 2: the embedded manifest carries the exact build.
        // A top-level key keeps the output a single YAML document.
        // Quoted: a short SHA is often all digits (~5% of commits), and YAML
        // would then parse it as an integer — with a leading zero, as octal.
        println!("build_commit: \"{}\"", env!("OXICRYPT_COMMIT"));
        return ExitCode::SUCCESS;
    }

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("esv-harness: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    // ── Item 1: CLI argv rejection ────────────────────────────────────

    #[test]
    fn reject_flag_args_rejects_totp_secret_flag() {
        // The legacy `bulk-refresh-body --totp-secret <b64> <jwt>` regression:
        // the flag (and, without this guard, the secret behind it) would land
        // on argv and inside the emitted body.
        let err = reject_flag_args(&args(&["--totp-secret", "c2VjcmV0", "jwt-a"])).unwrap_err();
        assert!(err.contains("--totp-secret"), "{err}");
        assert!(err.contains("stdin"), "{err}");
    }

    #[test]
    fn reject_flag_args_rejects_any_dash_argument() {
        assert!(reject_flag_args(&args(&["-x"])).is_err());
        assert!(reject_flag_args(&args(&["jwt-a", "-h"])).is_err());
    }

    #[test]
    fn reject_flag_args_accepts_clean_jwt_lists() {
        assert!(reject_flag_args(&args(&[])).is_ok());
        assert!(reject_flag_args(&args(&["jwt-a"])).is_ok());
        assert!(reject_flag_args(&args(&["jwt-a", "jwt-b", "jwt-c"])).is_ok());
    }

    // ── Item 2: tty stdin notice wording ──────────────────────────────

    #[test]
    fn tty_stdin_notice_names_stdin_and_eof() {
        let n = tty_stdin_notice();
        assert!(n.contains("stdin"), "{n}");
        assert!(n.contains("Ctrl-D") || n.contains("EOF"), "{n}");
    }
}
