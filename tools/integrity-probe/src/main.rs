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
//! | 3 | `SignatureInvalid`: the image does not match its signature |
//! | 4 | `SlotInvalid`: the slot is the unsigned template |
//! | 5 | `Unreadable`: the test was not performed |
//! | 6 | the module refused to boot for some other reason |
//! | 7 | `CastNotRun`: the integrity test was reached before its CAST |
//! | 8 | any other indicator |
//! | 9 | `IntegrityUnverified`: the module was initialised with no integrity test at all |
//! | 10 | `NoVerifyKey`: the module was built without a verifying key |
//! | 11 | `KeyMismatch`: the slot was signed for a different key |
//! | 12 | `SlotDamaged`: a signed slot, the key record or an import is damaged |
//!
//! `integrity-probe-so` numbers the same statuses differently.
//!
//! # `--skip-cast`
//!
//! Boots with the technique's CAST omitted from the test inventory,
//! which must make the integrity test refuse. It exists so `AS10.20`
//! ordering has a probe that can actually fail: an ordering guaranteed
//! only by the order of a list is indistinguishable, from the outside,
//! from no guarantee at all. Nothing but a test should ever pass it.
//!
//! On failure the module has already latched its error state and refuses
//! its primitives from then on, so the cause is read from the status
//! indicator the boot's own run latched rather than by running the test
//! again.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use oxicrypt_integrity::{IntegrityError, IntegrityStatus, KATS};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let skip_cast = args.iter().any(|a| a == "--skip-cast");
    // Boots the module the way a front end that never wired the
    // integrity test in would: an empty inventory. The module must
    // refuse rather than reporting itself operational, which is the
    // control proving the transition guard can fire.
    let no_integrity = args.iter().any(|a| a == "--no-integrity");
    // `--skip-cast` drops the ML-DSA-87 CAST, found by its name.
    let without_cast: Vec<_> = KATS
        .iter()
        .copied()
        .filter(|k| k.name != oxicrypt_integrity::ML_DSA_CAST_NAME)
        .collect();
    let tests = if no_integrity {
        &[][..]
    } else if skip_cast {
        &without_cast[..]
    } else {
        KATS
    };

    // The slot's runtime address, printed unconditionally. Across runs
    // it is the ASLR control for the relocation-stability probe: a
    // stable verdict means nothing unless the image demonstrably moved.
    println!("slot-addr: {:#x}", oxicrypt_integrity::slot_address());

    // Verifies again after the boot. On an artifact whose boot failed, the
    // module has latched its error state, so the second run is refused and
    // reaches a different outcome, `Refused`; the indicator must still
    // report the first outcome. It is the only way to observe the latch
    // from outside: every other route produces the same verdict twice,
    // which proves nothing.
    let relatch = args.iter().any(|a| a == "--relatch-probe");

    let boot = oxicrypt_module::initialize_with_tests(tests, &[]);

    if relatch {
        let second = oxicrypt_integrity::verify_loaded_image();
        println!(
            "second-run-refused: {}",
            matches!(second, Err(IntegrityError::Module(_)))
        );
    }
    // The status indicator, printed after the boot attempt so it
    // reflects a completed run. This is the observable the Security Policy
    // names (see `docs/security-policy/README.md`): it survives where the
    // runner's SelfTestFailure does not, so a test can pin `Unreadable` apart
    // from `SignatureInvalid`.
    println!("status: {}", oxicrypt_integrity::status() as u8);
    if let Some(fp) = oxicrypt_integrity::verify_key_fingerprint() {
        println!(
            "verify-key: {}",
            oxicrypt_integrity::format_fingerprint(&fp)
        );
    }

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
            // The module has latched its error state and refuses its
            // primitives from here on, so the test cannot be re-run to report
            // why; the indicator the boot's own run latched carries the cause.
            let status = oxicrypt_integrity::status();
            eprintln!("integrity: {status:?}");
            match status {
                IntegrityStatus::Passed => ExitCode::from(6),
                IntegrityStatus::SignatureInvalid => ExitCode::from(3),
                IntegrityStatus::SlotInvalid => ExitCode::from(4),
                IntegrityStatus::Unreadable => ExitCode::from(5),
                IntegrityStatus::CastNotRun => ExitCode::from(7),
                IntegrityStatus::NoVerifyKey => ExitCode::from(10),
                IntegrityStatus::KeyMismatch => ExitCode::from(11),
                IntegrityStatus::SlotDamaged => ExitCode::from(12),
                _ => ExitCode::from(8),
            }
        }
    }
}
