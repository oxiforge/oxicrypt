//! ACVP harness binary.
//!
//! Phase 1 scaffold. Real registration, vector dispatch, and JSON
//! handling arrive in Phase 3. Today this binary only exists so the
//! workspace builds and links against `fips-module` end to end.
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

use fips_module::{initialize_with_tests, state, Error, KatEntry};

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
        fips_sha::KATS.len()
            + fips_xof::KATS.len()
            + fips_hmac::KATS.len()
            + fips_kdf::KATS.len()
            + fips_integrity::KATS.len()
    },
>(&[
    fips_sha::KATS,
    fips_xof::KATS,
    fips_hmac::KATS,
    fips_kdf::KATS,
    fips_integrity::KATS,
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
fn noop_kat() -> Result<(), fips_module::SelfTestFailure> {
    Ok(())
}

fn main() {
    // Bootstrap shortcut: when invoked with `--fips-self-sign`, write
    // the `.fipshmac` sidecar for the currently-running executable and
    // exit. This is the one flow in the module that deliberately does
    // not go through the power-up KATs — if the KATs already passed we
    // would be signing a binary that was already verified, and if they
    // did not pass we cannot reach `main` at all. Running the binary
    // once with this flag immediately after `cargo build` is the
    // intended way to prepare a freshly-compiled harness for normal
    // boot. A production module would instead embed the MAC at the
    // build server and never ship this subcommand; for Phase 1
    // development it keeps the `cargo run` loop frictionless.
    if std::env::args().any(|a| a == "--fips-self-sign") {
        match std::env::current_exe() {
            Ok(exe) => match fips_integrity::sign_exe(&exe) {
                Ok(mac) => {
                    let hex = fips_integrity::encode_hmac_hex(&mac);
                    let hex_str = std::str::from_utf8(&hex).unwrap_or("<non-utf8>");
                    println!("fips-self-sign: signed {} -> {}", exe.display(), hex_str);
                    return;
                }
                Err(e) => {
                    eprintln!("fips-self-sign failed: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("fips-self-sign: current_exe() failed: {e}");
                return;
            }
        }
    }

    match initialize_with_tests(POWER_UP_KATS) {
        Ok(()) => {
            println!("pqclib acvp-harness: module state = {}", state());
            println!(
                "Power-up self-tests passed: {} KAT(s).",
                POWER_UP_KATS.len()
            );
            for kat in POWER_UP_KATS {
                println!("  - {}", kat.name);
            }
            println!(
                "Phase 2 scaffold: SHA-1/2/3 + SHAKE + HMAC + HKDF + KBKDF + software integrity KATs run, no vectors dispatched yet."
            );
        }
        Err(Error::AlreadyInitialized) => {
            println!(
                "pqclib acvp-harness: module already initialized, state = {}",
                state()
            );
        }
        Err(e) => {
            eprintln!("pqclib acvp-harness: initialization failed: {e}");
            // Deliberately not using `std::process::exit` here so the
            // scaffold stays minimal; we will introduce a proper
            // CLI error type in Phase 3.
        }
    }
}
