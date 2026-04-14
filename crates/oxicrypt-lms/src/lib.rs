//! LMS (SP 800-208) — Leighton-Micali hash-based signatures.
//!
//! # Status
//!
//! **Stub crate.** This crate reserves the API surface and
//! namespace for LMS stateful hash-based signatures, used
//! primarily for firmware signing in the CNSA 2.0 suite.
//!
//! All entry points currently return
//! [`oxicrypt_module::Error::NotImplemented`].
//!
//! # Approved services (planned)
//!
//! | Service | Standard |
//! |---|---|
//! | LMS sign | SP 800-208 |
//! | LMS verify | SP 800-208 |
//!
//! # Self-tests
//!
//! No self-tests are registered until the implementation lands.

#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::{Error, KatEntry, Service};

/// Power-up KATs for LMS. Empty until implementation lands.
pub const KATS: &[KatEntry] = &[];

/// Sign a message with an LMS private key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn sign(_private_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::LmsSign)?;
    Err(Error::NotImplemented)
}

/// Verify an LMS signature.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn verify(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::LmsVerify)?;
    Err(Error::NotImplemented)
}
