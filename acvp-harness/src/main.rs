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

use fips_module::{initialize, state, Error};

fn main() {
    match initialize() {
        Ok(()) => {
            println!("pqclib acvp-harness: module state = {}", state());
            println!("Phase 1 scaffold: no vectors dispatched yet.");
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
