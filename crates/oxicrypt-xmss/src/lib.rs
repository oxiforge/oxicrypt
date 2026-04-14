//! XMSS (SP 800-208) — eXtended Merkle Signature Scheme.
//!
//! # Status
//!
//! **Stub crate.** This crate reserves the API surface and
//! namespace for XMSS stateful hash-based signatures, used
//! primarily for firmware signing in the CNSA 2.0 suite.
//!
//! All entry points currently return
//! [`oxicrypt_module::Error::NotImplemented`].
//!
//! # Approved services (planned)
//!
//! | Service | Standard |
//! |---|---|
//! | XMSS sign | SP 800-208 |
//! | XMSS verify | SP 800-208 |
//!
//! # Self-tests
//!
//! No self-tests are registered until the implementation lands.

#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::{Error, KatEntry, Service};

/// Power-up KATs for XMSS. Empty until implementation lands.
pub const KATS: &[KatEntry] = &[];

/// Sign a message with an XMSS private key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn sign(_private_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::XmssSign)?;
    Err(Error::NotImplemented)
}

/// Verify an XMSS signature.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn verify(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::XmssVerify)?;
    Err(Error::NotImplemented)
}
