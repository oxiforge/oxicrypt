//! A shared object that verifies **itself**.
//!
//! It exists to prove one property: the integrity test verifies the
//! artifact that *contains* it, not whatever process happens to have
//! loaded it. A design that resolves its target with
//! `env::current_exe()` cannot — for a shared object that call returns
//! the **host** binary, so a cdylib would verify the wrong file or be
//! excluded from the check entirely.
//!
//! The current design has no such failure available to it. The slot is
//! located by its own runtime address, and the load base is that address
//! minus the slot's recorded RVA, so every range resolves inside this
//! library's mapping no matter who loaded it. There is no step at which
//! the host could be substituted.
//!
//! Loaded by `tests/self_verification.rs`, which signs this library, leaves
//! the host untouched, and checks that tampering with *this file* is what
//! moves the verdict.

/// Runs the pre-operational integrity test and returns its status
/// indicator.
///
/// The library is a test fixture outside the module boundary, so it starts
/// its copy of the module with the ML-DSA-87 and SHA-256 CASTs and then
/// its own entry that runs the image check, inside the self-tests where the
/// check runs, and keeps the check's verdict. A later call returns the
/// verdict the first one kept. The codes are this library's own:
///
/// | Code | Meaning |
/// |---|---|
/// | 0 | the image's signature verified |
/// | 3 | `SignatureInvalid` |
/// | 4 | `SlotInvalid`: the slot is the unsigned template |
/// | 5 | `Unreadable` |
/// | 7 | `CastNotRun` |
/// | 8 | the module did not start, or an error this table does not name |
/// | 10 | `Module`: the module refused a primitive the test uses |
/// | 11 | `NoVerifyKey` |
/// | 12 | `SlotInvalid(KeyMismatch)` |
/// | 13 | `SlotDamaged`: any other slot defect |
///
/// `integrity-probe` numbers the same statuses differently.
///
/// # Safety
///
/// Takes no arguments and returns a plain `i32`, so there is nothing a
/// caller can get wrong. `unsafe extern` is the C ABI's requirement, not
/// a property of this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxicrypt_probe_integrity() -> i32 {
    const START: &[oxicrypt_module::KatEntry] = &[
        oxicrypt_module::KatEntry {
            name: oxicrypt_integrity::ML_DSA_CAST_NAME,
            run: oxicrypt_integrity::ml_dsa_cast,
        },
        oxicrypt_module::KatEntry {
            name: oxicrypt_integrity::SHA256_CAST_NAME,
            run: oxicrypt_integrity::sha256_cast,
        },
        oxicrypt_module::KatEntry {
            name: "probe image check",
            run: check_image,
        },
    ];
    // A failed check has latched the module's error state; the verdict it
    // kept is the answer either way.
    let _ = oxicrypt_module::initialize_with_tests(START, &[]);
    VERDICT.get().copied().unwrap_or(8)
}

/// The image check's verdict, kept by [`check_image`].
static VERDICT: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

/// Runs the image check inside the self-tests and keeps its verdict as one
/// of the codes [`oxicrypt_probe_integrity`] documents.
#[allow(clippy::unnecessary_wraps, reason = "a KatEntry's run signature")]
fn check_image() -> Result<(), oxicrypt_module::SelfTestFailure> {
    let _ = VERDICT.set(verdict());
    Ok(())
}

/// The image check's outcome as a code.
fn verdict() -> i32 {
    match oxicrypt_integrity::verify_loaded_image() {
        Ok(()) => 0,
        Err(oxicrypt_integrity::IntegrityError::SignatureInvalid) => 3,
        Err(oxicrypt_integrity::IntegrityError::SlotInvalid(
            oxicrypt_integrity::SlotDefect::KeyMismatch,
        )) => 12,
        Err(oxicrypt_integrity::IntegrityError::SlotInvalid(d)) if d.is_unsigned() => 4,
        Err(oxicrypt_integrity::IntegrityError::SlotInvalid(_)) => 13,
        Err(oxicrypt_integrity::IntegrityError::Unreadable(_)) => 5,
        Err(oxicrypt_integrity::IntegrityError::CastNotRun) => 7,
        Err(oxicrypt_integrity::IntegrityError::Module(_)) => 10,
        Err(oxicrypt_integrity::IntegrityError::NoVerifyKey) => 11,
        Err(_) => 8,
    }
}

/// This library's slot address, so a test can confirm the mapping it
/// verified is the library's and not the host's.
///
/// # Safety
///
/// Takes no arguments and returns a plain `usize`, so there is nothing a
/// caller can get wrong. `unsafe extern` is the C ABI's requirement, not
/// a property of this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxicrypt_probe_slot_address() -> usize {
    oxicrypt_integrity::slot_address()
}
