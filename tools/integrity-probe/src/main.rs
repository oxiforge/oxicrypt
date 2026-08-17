//! A minimal front end that boots the module and reports what the
//! pre-operational integrity test decided.
//!
//! This exists so the integrity test can be exercised **through the
//! module's own entry point** rather than through a helper. The
//! distinction is the whole value of the probe: a test that calls the
//! verifier directly proves the verifier works and says nothing about
//! whether a booting module reaches it. Here the only call is
//! `oxicrypt_module::initialize_with_tests`, which runs the test while
//! the module is in `SelfTest` state — the same path every shipped front
//! end takes.
//!
//! The exit code carries the status indicator (`AS10.18`), because an
//! operator and a laboratory both need to distinguish "the module is
//! corrupt" from "this environment cannot supply the module's bytes":
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | the module became operational |
//! | 3 | `Mismatch` — the image does not match its reference MAC |
//! | 4 | `SlotInvalid` — the slot is absent, unsigned, or malformed |
//! | 5 | `Unreadable` — the test was not performed |
//! | 6 | the module refused to boot for some other reason |
//! | 7 | `CastNotRun` — the integrity test was reached before its CAST |
//! | 9 | `IntegrityUnverified` — the module was initialised with no integrity test at all |
//!
//! # `--skip-cast`
//!
//! Boots with the technique's CAST omitted from the test inventory,
//! which must make the integrity test refuse. It exists so `AS10.20`
//! ordering has a probe that can actually fail: an ordering guaranteed
//! only by the order of a list is indistinguishable, from the outside,
//! from no guarantee at all. Nothing but a test should ever pass it.
//!
//! On failure the module has already latched its error state, so the
//! second call below re-runs the same test purely to report *why*. It
//! cannot change the outcome — there is no path from `Error` back to
//! `Operational` short of a restart.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use oxicrypt_integrity::{IntegrityError, KATS, verify_loaded_image};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let skip_cast = args.iter().any(|a| a == "--skip-cast");
    // Boots the module the way a front end that never wired the
    // integrity test in would: an empty inventory. The module must
    // refuse rather than reporting itself operational, which is the
    // control proving the transition guard can fire.
    let no_integrity = args.iter().any(|a| a == "--no-integrity");
    let tests = if no_integrity {
        &[][..]
    } else if skip_cast {
        KATS.get(1..).unwrap_or(KATS)
    } else {
        KATS
    };

    // The slot's runtime address, printed unconditionally. Across runs
    // it is the ASLR control for the relocation-stability probe: a
    // stable verdict means nothing unless the image demonstrably moved.
    println!("slot-addr: {:#x}", oxicrypt_integrity::slot_address());

    // Boots with the CAST omitted so the first run records `CastNotRun`,
    // then runs the CAST and verifies again — a second run that WOULD
    // succeed. The indicator must still report the first outcome. It is
    // the only way to observe the latch from outside: every other route
    // produces the same verdict twice, which proves nothing.
    let relatch = args.iter().any(|a| a == "--relatch-probe");

    let boot = oxicrypt_module::initialize_with_tests(tests, &[]);

    if relatch {
        let _ = oxicrypt_integrity::hmac_cast();
        let second = oxicrypt_integrity::verify_loaded_image();
        println!("second-run-ok: {}", second.is_ok());
    }
    // The status indicator, printed after the boot attempt so it
    // reflects a completed run. This is the Security Policy §5.2
    // observable: it survives where the runner's SelfTestFailure does
    // not, so a test can pin `Unreadable` apart from `Mismatch`.
    println!("status: {}", oxicrypt_integrity::status() as u8);

    match boot {
        Ok(()) => {
            println!("boot: operational");
            ExitCode::from(0)
        }
        Err(module_error) => {
            eprintln!("boot: error ({module_error})");
            if oxicrypt_module::state() == oxicrypt_module::State::IntegrityUnverified {
                eprintln!("integrity: the module never checked itself at startup");
                return ExitCode::from(9);
            }
            match verify_loaded_image() {
                Ok(()) => {
                    eprintln!(
                        "integrity: ok — the module refused to boot for another reason entirely"
                    );
                    ExitCode::from(6)
                }
                Err(e @ IntegrityError::Mismatch) => {
                    eprintln!("integrity: {e}");
                    ExitCode::from(3)
                }
                Err(e @ IntegrityError::SlotInvalid(_)) => {
                    eprintln!("integrity: {e}");
                    ExitCode::from(4)
                }
                Err(e @ IntegrityError::Unreadable(_)) => {
                    eprintln!("integrity: {e}");
                    ExitCode::from(5)
                }
                Err(e @ IntegrityError::CastNotRun) => {
                    eprintln!("integrity: {e}");
                    ExitCode::from(7)
                }
            }
        }
    }
}
