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
            + fips_aes::KATS.len()
            + fips_integrity::KATS.len()
    },
>(&[
    fips_sha::KATS,
    fips_xof::KATS,
    fips_hmac::KATS,
    fips_kdf::KATS,
    fips_aes::KATS,
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
    // Self-signing has deliberately been removed: the Linux kernel
    // refuses `O_TRUNC` writes to a file that currently backs a
    // process image (`ETXTBSY`), so a running executable cannot
    // rewrite its own embedded integrity slot. The standard
    // development workflow is to build the harness, then run
    // `fips-integrity-sign --sign target/debug/acvp-harness` from a
    // separate process, and only then execute the harness.
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
                "Phase 2 scaffold: SHA-1/2/3 + SHAKE + HMAC + HKDF + KBKDF + AES (ECB/CBC/CTR/GCM) + software integrity KATs run, no vectors dispatched yet."
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
