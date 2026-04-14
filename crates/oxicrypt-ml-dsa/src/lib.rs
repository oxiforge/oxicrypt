//! ML-DSA (FIPS 204) — lattice-based digital signature algorithm.
//!
//! # Status
//!
//! **Stub crate.** This crate reserves the API surface and
//! namespace for ML-DSA-87 (the CNSA 2.0 digital-signature
//! algorithm). All entry points currently return
//! [`oxicrypt_module::Error::NotImplemented`].
//!
//! # Approved services (planned)
//!
//! | Service | Standard |
//! |---|---|
//! | ML-DSA-87 keygen | FIPS 204 |
//! | ML-DSA-87 sign | FIPS 204 |
//! | ML-DSA-87 verify | FIPS 204 |
//!
//! # Self-tests
//!
//! No self-tests are registered until the implementation lands.

#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::{Error, KatEntry, Service};

/// Power-up KATs for ML-DSA. Empty until implementation lands.
pub const KATS: &[KatEntry] = &[];

/// Generate an ML-DSA-87 key pair.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn keygen() -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlDsa87Keygen)?;
    Err(Error::NotImplemented)
}

/// Sign a message with an ML-DSA-87 private key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn sign(_private_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlDsa87Sign)?;
    Err(Error::NotImplemented)
}

/// Verify a signature with an ML-DSA-87 public key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn verify(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlDsa87Verify)?;
    Err(Error::NotImplemented)
}
