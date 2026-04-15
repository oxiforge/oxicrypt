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

fn main() {
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
        std::process::exit(0);
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
            // Deliberately not using `std::process::exit` here so the
            // scaffold stays minimal; we will introduce a proper
            // CLI error type in a later phase.
            return;
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "dispatch" {
        run_dispatch_cli(&args);
        return;
    }
    if args.len() >= 2 && args[1] == "dispatch-shs" {
        run_dispatch_shs_cli(&args);
        return;
    }

    print_self_test_banner();
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
    println!(
        "ACVP dispatch: {} handler(s) registered.",
        registry.len()
    );
    let shs_registry = acvp_harness::shs::with_default_shs_handlers();
    println!(
        "CAVP SHS dispatch: {} handler(s) registered.",
        shs_registry.len()
    );
    println!(
        "Run `acvp-harness dispatch <prompt.json> <response.json>` for an ACVP vector set,"
    );
    println!(
        "or `acvp-harness dispatch-shs <algorithm> <prompt.rsp> <response.json>` for a CAVP SHS file."
    );
}

fn run_dispatch_cli(args: &[String]) {
    if args.len() != 4 {
        eprintln!("usage: acvp-harness dispatch <prompt.json> <response.json>");
        return;
    }
    let prompt_path = &args[2];
    let response_path = &args[3];
    if let Err(msg) = run_dispatch(prompt_path, response_path) {
        eprintln!("oxicrypt acvp-harness: dispatch failed: {msg}");
    }
}

fn run_dispatch(prompt_path: &str, response_path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(prompt_path)
        .map_err(|e| format!("read {prompt_path}: {e}"))?;
    let prompt = acvp_harness::json::parse(&text)
        .map_err(|e| format!("parse {prompt_path}: {e}"))?;
    let registry = acvp_harness::dispatch::with_default_handlers();
    let response = acvp_harness::dispatch::process(&prompt, &registry)
        .map_err(|e| format!("dispatch: {e}"))?;
    let mut out = acvp_harness::json::to_pretty_string(&response);
    out.push('\n');
    std::fs::write(response_path, out)
        .map_err(|e| format!("write {response_path}: {e}"))?;
    println!(
        "oxicrypt acvp-harness: wrote ACVP response to {response_path} ({} test group(s))",
        response
            .get("testGroups")
            .and_then(acvp_harness::json::JsonValue::as_array)
            .map_or(0, <[_]>::len)
    );
    Ok(())
}

fn run_dispatch_shs_cli(args: &[String]) {
    if args.len() != 5 {
        eprintln!(
            "usage: acvp-harness dispatch-shs <algorithm> <prompt.rsp> <response.json>"
        );
        eprintln!(
            "  algorithm ∈ {{SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256}}"
        );
        return;
    }
    let algorithm = &args[2];
    let prompt_path = &args[3];
    let response_path = &args[4];
    if let Err(msg) = run_dispatch_shs(algorithm, prompt_path, response_path) {
        eprintln!("oxicrypt acvp-harness: dispatch-shs failed: {msg}");
    }
}

fn run_dispatch_shs(
    algorithm: &str,
    prompt_path: &str,
    response_path: &str,
) -> Result<(), String> {
    let text = std::fs::read_to_string(prompt_path)
        .map_err(|e| format!("read {prompt_path}: {e}"))?;
    let doc = acvp_harness::rsp::parse(&text)
        .map_err(|e| format!("parse {prompt_path}: {e}"))?;
    let registry = acvp_harness::shs::with_default_shs_handlers();
    let response = acvp_harness::shs::process_shs(algorithm, &doc, &registry)
        .map_err(|e| format!("dispatch-shs: {e}"))?;
    let mut out = acvp_harness::json::to_pretty_string(&response);
    out.push('\n');
    std::fs::write(response_path, out)
        .map_err(|e| format!("write {response_path}: {e}"))?;
    println!(
        "oxicrypt acvp-harness: wrote CAVP SHS response to {response_path} ({} test case(s))",
        response
            .get("testCases")
            .and_then(acvp_harness::json::JsonValue::as_array)
            .map_or(0, <[_]>::len)
    );
    Ok(())
}
