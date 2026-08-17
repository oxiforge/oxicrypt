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
//! Loaded by `tests/shared_object.rs`, which signs this library, leaves
//! the host untouched, and checks that tampering with *this file* is what
//! moves the verdict.

/// Runs the pre-operational integrity test and returns its status
/// indicator, using the same codes as the `integrity-probe` binary.
///
/// # Safety
///
/// Takes no arguments and returns a plain `i32`, so there is nothing a
/// caller can get wrong. `unsafe extern` is the C ABI's requirement, not
/// a property of this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxicrypt_probe_integrity() -> i32 {
    if oxicrypt_integrity::hmac_cast().is_err() {
        return 8;
    }
    match oxicrypt_integrity::verify_loaded_image() {
        Ok(()) => 0,
        Err(oxicrypt_integrity::IntegrityError::Mismatch) => 3,
        Err(oxicrypt_integrity::IntegrityError::SlotInvalid(_)) => 4,
        Err(oxicrypt_integrity::IntegrityError::Unreadable(_)) => 5,
        Err(oxicrypt_integrity::IntegrityError::CastNotRun) => 7,
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
