//! ACVP harness binary.
//!
//! Phase 1 scaffold. Real registration, vector dispatch, and JSON
//! handling arrive in Phase 3. Today this binary only exists so the
//! workspace builds and links against `fips-module` end to end.
//!
//! Because this is a user-facing binary it is permitted to emit
//! output to stdout/stderr — we override the workspace-wide
//! print-macro lints at the crate root.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use fips_module::{initialize_with_tests, state, Error, KatEntry};

/// The full power-up KAT set for this binary.
///
/// Built at compile time from the `KATS` slice exported by each
/// algorithm crate. Keeping this list in source (rather than
/// assembling it via linker-section magic) means the module's test
/// inventory is trivially auditable from a single location, which is
/// exactly what a CST lab will want to see during the Security
/// Policy review.
const POWER_UP_KATS: &[KatEntry] = fips_sha::KATS;

fn main() {
    match initialize_with_tests(POWER_UP_KATS) {
        Ok(()) => {
            println!("pqclib acvp-harness: module state = {}", state());
            println!(
                "Power-up self-tests passed: {} KAT(s).",
                POWER_UP_KATS.len()
            );
            println!("Phase 2 scaffold: SHA-256 KAT runs, no vectors dispatched yet.");
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
