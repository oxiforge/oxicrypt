//! ACVP harness binary.
//!
//! The binary wraps the [`acvp_harness`] library with a tiny CLI:
//!
//! - `acvp-harness` (no args) — the Phase 1/2 default: run the
//!   power-up self-tests and print a short summary of the wired-up
//!   KAT inventory. This is what CI runs on every build to prove the
//!   module still boots end to end.
//! - `acvp-harness dispatch <prompt.json> <response.json>` — the
//!   Phase 3 ACVP vector-set dispatcher: parse an ACVP
//!   `internalProjection` slice from `<prompt.json>`, compute
//!   responses, and write them to `<response.json>`.
//! - `acvp-harness dispatch-shs <algorithm> <prompt.rsp> <response.json>`
//!   — the R12-B second envelope: parse a CAVP SHS short-message
//!   `.rsp` byte-vector file from `<prompt.rsp>`, dispatch every
//!   record through the named handler (e.g. `SHA-256`, `SHA-512/224`),
//!   and write a JSON response to `<response.json>`. CAVP SHS is the
//!   only path for plain FIPS 180-4 hashing because upstream
//!   `usnistgov/ACVP-Server` ships no top-level `SHA-*` vector
//!   directories at the pinned commit — see §11.4 of the security
//!   policy.
//! - `acvp-harness demo-run --cert <cert.pem> --key <key.pem> --totp-secret <hex>`
//!   — the ACVP transport client: connect to the NIST ACVP demo
//!   server (`demo.acvts.nist.gov`), authenticate via TOTP-signed JWT,
//!   register algorithm capabilities, fetch vector sets, process them
//!   through the local dispatcher, submit responses, and poll for
//!   verdicts. Uses `curl(1)` for HTTPS with mutual TLS, keeping the
//!   zero-third-party-dependencies policy intact. JWT signing and TOTP
//!   generation use the module's own HMAC-SHA-256. Optional
//!   `--algorithm <name>` restricts the session to a single algorithm.
//!
//! Because this is a user-facing binary it is permitted to emit
//! output to stdout/stderr — we override the workspace-wide
//! print-macro lints at the crate root.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unnecessary_wraps
)]

use oxicrypt_module::{initialize_with_tests, state, Error, KatEntry};

/// The full power-up KAT set for this binary.
///
/// Built at compile time by concatenating the `KATS` slice exported
/// by each algorithm crate. Keeping this list in source (rather than
/// assembling it via linker-section magic) means the module's test
/// inventory is trivially auditable from a single location, which is
/// exactly what a CST lab will want to see during the Security
/// Policy review.
const POWER_UP_KATS: &[KatEntry] = &concat_kats::<
    {
        oxicrypt_sha::KATS.len()
            + oxicrypt_xof::KATS.len()
            + oxicrypt_hmac::KATS.len()
            + oxicrypt_kdf::KATS.len()
            + oxicrypt_aes::KATS.len()
            + oxicrypt_cmac::KATS.len()
            + oxicrypt_drbg::KATS.len()
            + oxicrypt_integrity::KATS.len()
            + oxicrypt_ecdsa::KATS.len()
            + oxicrypt_eddsa::KATS.len()
            + oxicrypt_rsa::KATS.len()
            + oxicrypt_ecdh::KATS.len()
            + oxicrypt_tls_kdf::KATS.len()
            + oxicrypt_dh::KATS.len()
            + oxicrypt_ml_kem::KATS.len()
            + oxicrypt_ml_dsa::KATS.len()
            + oxicrypt_slh_dsa::KATS.len()
            + oxicrypt_lms::KATS.len()
            + oxicrypt_xmss::KATS.len()
    },
>(&[
    oxicrypt_sha::KATS,
    oxicrypt_xof::KATS,
    oxicrypt_hmac::KATS,
    oxicrypt_kdf::KATS,
    oxicrypt_aes::KATS,
    oxicrypt_cmac::KATS,
    oxicrypt_drbg::KATS,
    oxicrypt_integrity::KATS,
    oxicrypt_ecdsa::KATS,
    oxicrypt_eddsa::KATS,
    oxicrypt_rsa::KATS,
    oxicrypt_ecdh::KATS,
    oxicrypt_tls_kdf::KATS,
    oxicrypt_dh::KATS,
    oxicrypt_ml_kem::KATS,
    oxicrypt_ml_dsa::KATS,
    oxicrypt_slh_dsa::KATS,
    oxicrypt_lms::KATS,
    oxicrypt_xmss::KATS,
]);

/// Concatenate several `KatEntry` slices into a single fixed-size
/// array at compile time. `N` must equal the sum of the lengths of
/// the input slices; a mismatch triggers a `const` panic.
const fn concat_kats<const N: usize>(parts: &[&[KatEntry]]) -> [KatEntry; N] {
    let mut out: [KatEntry; N] = [KatEntry {
        name: "",
        run: noop_kat,
    }; N];
    let mut out_idx = 0usize;
    let mut part_idx = 0usize;
    while part_idx < parts.len() {
        let part = parts[part_idx];
        let mut i = 0usize;
        while i < part.len() {
            out[out_idx] = part[i];
            out_idx += 1;
            i += 1;
        }
        part_idx += 1;
    }
    assert!(out_idx == N, "concat_kats: length mismatch");
    out
}

/// Placeholder used only to initialize the const array before the
/// real entries are copied in. Never actually invoked because every
/// slot is overwritten in `concat_kats`.
fn noop_kat() -> Result<(), oxicrypt_module::SelfTestFailure> {
    Ok(())
}

/// Process exit codes used by this binary.
///
/// `0` — success.
/// `1` — power-up self-test failed (FIPS module integrity, KAT
///       failure, or other initialization error). The harness will
///       not perform any cryptographic work.
/// `2` — invalid CLI usage (missing required flag, unknown flag,
///       mutually-exclusive flag combination).
/// `3` — runtime failure during a subcommand (network, I/O, parse
///       error, or remote rejection).
fn main() -> std::process::ExitCode {
    // ── LAMA manifest ───────────────────────────────────────────────
    // If the caller passes `--lama`, print the compile-time-embedded
    // YAML manifest and exit immediately — before module
    // initialization, before argument parsing, before anything else.
    // This is the AI-agent equivalent of `--help` for humans.
    // See https://github.com/lamaspec/lama/blob/main/SPEC.md §"Discovery".
    if std::env::args().any(|a| a == "--lama") {
        // The YAML is embedded at compile time via include_str!.
        // The git commit is stamped by build.rs via cargo:rustc-env.
        print!(
            "{}",
            include_str!("../../docs/llm-api-manifest/llm-api.yaml")
        );
        return std::process::ExitCode::from(0);
    }

    // Self-signing has deliberately been removed: the Linux kernel
    // refuses `O_TRUNC` writes to a file that currently backs a
    // process image (`ETXTBSY`), so a running executable cannot
    // rewrite its own embedded integrity slot. The standard
    // development workflow is to build the harness, then run
    // `fips-integrity-sign --sign target/debug/acvp-harness` from a
    // separate process, and only then execute the harness.
    match initialize_with_tests(POWER_UP_KATS) {
        Ok(()) | Err(Error::AlreadyInitialized) => {}
        Err(e) => {
            eprintln!("oxicrypt acvp-harness: initialization failed: {e}");
            return std::process::ExitCode::from(1);
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "dispatch" {
        return run_dispatch_cli(&args);
    }
    if args.len() >= 2 && args[1] == "dispatch-shs" {
        return run_dispatch_shs_cli(&args);
    }
    if args.len() >= 2 && args[1] == "demo-run" {
        return run_demo_cli(&args);
    }

    print_self_test_banner();
    std::process::ExitCode::from(0)
}

// CLI parser with many flags; splitting it would add boilerplate without
// clarity. The function is a flat sequence of flag-match arms followed by
// validation and config construction.
#[allow(clippy::too_many_lines)]
fn run_demo_cli(args: &[String]) -> std::process::ExitCode {
    use acvp_harness::transport::{AcvpConfig, HttpBackend};

    // demo-run --cert <cert> --totp-secret <hex>
    //   { --key <key.pem> | --pkcs11-key 'pkcs11:object=...;type=private' }
    //   [--pkcs11-module <path>]
    //   [--http-backend curl|s_client] [--algorithm <name>]
    //   [--server <url>] [--log <path>]
    let mut cert = String::new();
    let mut key = String::new();
    let mut pkcs11_key = String::new();
    let mut pkcs11_module = String::new();
    let mut pkcs11_pin_source = String::new();
    let mut http_backend_explicit: Option<HttpBackend> = None;
    let mut totp_secret = String::new();
    let mut algorithm: Option<String> = None;
    let mut query_session: Option<String> = None;
    let mut refresh_with: Option<String> = None;
    let mut server = "https://demo.acvts.nist.gov".to_string();
    let mut log_path = "acvp-session.json".to_string();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--cert" => {
                i += 1;
                if i < args.len() {
                    cert.clone_from(&args[i]);
                }
            }
            "--key" => {
                i += 1;
                if i < args.len() {
                    key.clone_from(&args[i]);
                }
            }
            "--pkcs11-key" => {
                i += 1;
                if i < args.len() {
                    pkcs11_key.clone_from(&args[i]);
                }
            }
            "--pkcs11-module" => {
                i += 1;
                if i < args.len() {
                    pkcs11_module.clone_from(&args[i]);
                }
            }
            "--pkcs11-pin-source" => {
                i += 1;
                if i < args.len() {
                    pkcs11_pin_source.clone_from(&args[i]);
                }
            }
            "--http-backend" => {
                i += 1;
                if i < args.len() {
                    http_backend_explicit = match args[i].as_str() {
                        "curl" => Some(HttpBackend::Curl),
                        "s_client" | "openssl-s_client" => Some(HttpBackend::OpenSslSClient),
                        other => {
                            eprintln!(
                                "oxicrypt acvp-harness demo-run: unknown --http-backend value \
                                 {other:?} (valid: curl, s_client)"
                            );
                            return std::process::ExitCode::from(2);
                        }
                    };
                }
            }
            "--totp-secret" => {
                i += 1;
                if i < args.len() {
                    totp_secret.clone_from(&args[i]);
                }
            }
            "--algorithm" => {
                i += 1;
                if i < args.len() {
                    algorithm = Some(args[i].clone());
                }
            }
            "--query-session" => {
                i += 1;
                if i < args.len() {
                    query_session = Some(args[i].clone());
                }
            }
            "--refresh-with" => {
                i += 1;
                if i < args.len() {
                    refresh_with = Some(args[i].clone());
                }
            }
            "--refresh-with-file" => {
                i += 1;
                if i < args.len() {
                    match std::fs::read_to_string(&args[i]) {
                        Ok(s) => refresh_with = Some(s.trim().to_string()),
                        Err(e) => {
                            eprintln!(
                                "oxicrypt acvp-harness demo-run: cannot read --refresh-with-file {:?}: {e}",
                                &args[i]
                            );
                            return std::process::ExitCode::from(2);
                        }
                    }
                }
            }
            "--server" => {
                i += 1;
                if i < args.len() {
                    server.clone_from(&args[i]);
                }
            }
            "--log" => {
                i += 1;
                if i < args.len() {
                    log_path.clone_from(&args[i]);
                }
            }
            other => {
                eprintln!("oxicrypt acvp-harness demo-run: unknown flag {other:?}");
                print_demo_run_usage();
                return std::process::ExitCode::from(2);
            }
        }
        i += 1;
    }

    if cert.is_empty() || totp_secret.is_empty() {
        eprintln!("oxicrypt acvp-harness demo-run: --cert and --totp-secret are required");
        print_demo_run_usage();
        return std::process::ExitCode::from(2);
    }

    // Exactly one of --key or --pkcs11-key.
    let have_key = !key.is_empty();
    let have_pkcs11 = !pkcs11_key.is_empty();
    match (have_key, have_pkcs11) {
        (false, false) => {
            eprintln!(
                "oxicrypt acvp-harness demo-run: must supply either --key <file.pem> or \
                 --pkcs11-key <pkcs11:URI>"
            );
            print_demo_run_usage();
            return std::process::ExitCode::from(2);
        }
        (true, true) => {
            eprintln!(
                "oxicrypt acvp-harness demo-run: --key and --pkcs11-key are mutually exclusive"
            );
            return std::process::ExitCode::from(2);
        }
        _ => {}
    }

    // Default backend: curl for software keys, s_client for hardware keys.
    // (The NIST ACVTS demo CDN filters curl's TLS fingerprint when curl
    // signs CertVerify via PKCS#11 — observed 2026-04-26. s_client's
    // handshake is accepted.)
    let http_backend = http_backend_explicit.unwrap_or(if have_pkcs11 {
        HttpBackend::OpenSslSClient
    } else {
        HttpBackend::Curl
    });

    let config = AcvpConfig {
        server_url: server,
        cert_path: cert,
        key_path: key,
        pkcs11_uri: if pkcs11_key.is_empty() {
            None
        } else {
            Some(pkcs11_key)
        },
        pkcs11_module_path: if pkcs11_module.is_empty() {
            None
        } else {
            Some(pkcs11_module)
        },
        pkcs11_pin: if pkcs11_pin_source.is_empty() {
            String::new()
        } else {
            // Read PIN from the file once at startup. The file path comes
            // from --pkcs11-pin-source. We trim trailing whitespace
            // (newline if the file was written with `echo`).
            match std::fs::read_to_string(&pkcs11_pin_source) {
                Ok(s) => s.trim_end().to_string(),
                Err(e) => {
                    eprintln!(
                        "oxicrypt acvp-harness demo-run: cannot read PIN from {pkcs11_pin_source:?}: {e}"
                    );
                    return std::process::ExitCode::from(2);
                }
            }
        },
        http_backend,
        totp_secret,
        filter_algorithm: algorithm,
        query_session_url: query_session,
        refresh_with_token: refresh_with,
        log_path,
    };

    if let Err(msg) = acvp_harness::transport::run_demo(&config) {
        eprintln!("oxicrypt acvp-harness: demo-run failed: {msg}");
        return std::process::ExitCode::from(3);
    }
    std::process::ExitCode::from(0)
}

fn print_demo_run_usage() {
    eprintln!("usage: acvp-harness demo-run --cert <cert.pem> --totp-secret <hex>");
    eprintln!("               (--key <key.pem> | --pkcs11-key 'pkcs11:object=...;type=private')");
    eprintln!("               [--pkcs11-module <path>] [--pkcs11-pin-source <path>]");
    eprintln!("               [--http-backend curl|s_client] [--algorithm <name>]");
    eprintln!("               [--server <url>] [--log <path>]");
    eprintln!();
    eprintln!("  --key                 file-based PEM key (default backend: curl)");
    eprintln!("  --pkcs11-key          PKCS#11 URI for hardware key (default backend: s_client)");
    eprintln!("  --pkcs11-module       PKCS#11 provider module .so (default: opensc-pkcs11)");
    eprintln!("  --pkcs11-pin-source   path to a file containing the PIV PIN (avoids tty prompts;");
    eprintln!("                        place on /dev/shm with mode 0600, shred after use)");
    eprintln!("  --http-backend        override transport: curl or s_client");
    eprintln!("  --algorithm <name>    test a single algorithm (e.g. SHA2-256)");
    eprintln!(
        "  --query-session <url> fetch verdict for an existing session (skip register+submit);"
    );
    eprintln!(
        "                        URL may be relative (/acvp/v1/testSessions/...) or absolute"
    );
    eprintln!("  --refresh-with <jwt>  send existing session-bound accessToken at login;");
    eprintln!("                        server re-issues a fresh token with same tsId/vsId scope");
    eprintln!("  --refresh-with-file <path>  same as --refresh-with but read token from file");
    eprintln!("  --server <url>        ACVP server (default: https://demo.acvts.nist.gov)");
    eprintln!("  --log <path>          transcript log path (default: acvp-session.json)");
}

fn print_self_test_banner() {
    println!("oxicrypt acvp-harness: module state = {}", state());
    println!(
        "Power-up self-tests passed: {} KAT(s).",
        POWER_UP_KATS.len()
    );
    for kat in POWER_UP_KATS {
        println!("  - {}", kat.name);
    }
    let registry = acvp_harness::dispatch::with_default_handlers();
    println!("ACVP dispatch: {} handler(s) registered.", registry.len());
    let shs_registry = acvp_harness::shs::with_default_shs_handlers();
    println!(
        "CAVP SHS dispatch: {} handler(s) registered.",
        shs_registry.len()
    );
    println!("Run `acvp-harness dispatch <prompt.json> <response.json>` for an ACVP vector set,");
    println!(
        "or `acvp-harness dispatch-shs <algorithm> <prompt.rsp> <response.json>` for a CAVP SHS file,"
    );
    println!(
        "or `acvp-harness demo-run --cert <cert> --key <key> --totp-secret <hex>` for an end-to-end ACVP demo session."
    );
}

fn run_dispatch_cli(args: &[String]) -> std::process::ExitCode {
    if args.len() != 4 {
        eprintln!("usage: acvp-harness dispatch <prompt.json> <response.json>");
        return std::process::ExitCode::from(2);
    }
    let prompt_path = &args[2];
    let response_path = &args[3];
    if let Err(msg) = run_dispatch(prompt_path, response_path) {
        eprintln!("oxicrypt acvp-harness: dispatch failed: {msg}");
        return std::process::ExitCode::from(3);
    }
    std::process::ExitCode::from(0)
}

fn run_dispatch(prompt_path: &str, response_path: &str) -> Result<(), String> {
    let text =
        std::fs::read_to_string(prompt_path).map_err(|e| format!("read {prompt_path}: {e}"))?;
    let prompt =
        acvp_harness::json::parse(&text).map_err(|e| format!("parse {prompt_path}: {e}"))?;
    let registry = acvp_harness::dispatch::with_default_handlers();
    let response = acvp_harness::dispatch::process(&prompt, &registry)
        .map_err(|e| format!("dispatch: {e}"))?;
    let mut out = acvp_harness::json::to_pretty_string(&response);
    out.push('\n');
    std::fs::write(response_path, out).map_err(|e| format!("write {response_path}: {e}"))?;
    println!(
        "oxicrypt acvp-harness: wrote ACVP response to {response_path} ({} test group(s))",
        response
            .get("testGroups")
            .and_then(acvp_harness::json::JsonValue::as_array)
            .map_or(0, <[_]>::len)
    );
    Ok(())
}

fn run_dispatch_shs_cli(args: &[String]) -> std::process::ExitCode {
    if args.len() != 5 {
        eprintln!("usage: acvp-harness dispatch-shs <algorithm> <prompt.rsp> <response.json>");
        eprintln!(
            "  algorithm ∈ {{SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256}}"
        );
        return std::process::ExitCode::from(2);
    }
    let algorithm = &args[2];
    let prompt_path = &args[3];
    let response_path = &args[4];
    if let Err(msg) = run_dispatch_shs(algorithm, prompt_path, response_path) {
        eprintln!("oxicrypt acvp-harness: dispatch-shs failed: {msg}");
        return std::process::ExitCode::from(3);
    }
    std::process::ExitCode::from(0)
}

fn run_dispatch_shs(algorithm: &str, prompt_path: &str, response_path: &str) -> Result<(), String> {
    let text =
        std::fs::read_to_string(prompt_path).map_err(|e| format!("read {prompt_path}: {e}"))?;
    let doc = acvp_harness::rsp::parse(&text).map_err(|e| format!("parse {prompt_path}: {e}"))?;
    let registry = acvp_harness::shs::with_default_shs_handlers();
    let response = acvp_harness::shs::process_shs(algorithm, &doc, &registry)
        .map_err(|e| format!("dispatch-shs: {e}"))?;
    let mut out = acvp_harness::json::to_pretty_string(&response);
    out.push('\n');
    std::fs::write(response_path, out).map_err(|e| format!("write {response_path}: {e}"))?;
    println!(
        "oxicrypt acvp-harness: wrote CAVP SHS response to {response_path} ({} test case(s))",
        response
            .get("testCases")
            .and_then(acvp_harness::json::JsonValue::as_array)
            .map_or(0, <[_]>::len)
    );
    Ok(())
}
