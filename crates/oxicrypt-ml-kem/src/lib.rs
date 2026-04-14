//! ML-KEM (FIPS 203) — lattice-based key encapsulation mechanism.
//!
//! # Status
//!
//! **Stub crate.** This crate reserves the API surface and
//! namespace for ML-KEM-1024 (the CNSA 2.0 key-establishment
//! algorithm). All entry points currently return
//! [`oxicrypt_module::Error::NotImplemented`]. The algorithm-profile
//! gate is in place: under [`AlgorithmProfile::Cnsa2`](oxicrypt_module::AlgorithmProfile::Cnsa2) the
//! `require_allowed` check passes, but the operation itself is not
//! yet available.
//!
//! # Approved services (planned)
//!
//! | Service | Standard |
//! |---|---|
//! | ML-KEM-1024 keygen | FIPS 203 |
//! | ML-KEM-1024 encapsulate | FIPS 203 |
//! | ML-KEM-1024 decapsulate | FIPS 203 |
//!
//! # Self-tests
//!
//! No self-tests are registered until the implementation lands.
//! The `KATS` slice is empty.

#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::{Error, KatEntry, Service};

/// Power-up KATs for ML-KEM. Empty until implementation lands.
pub const KATS: &[KatEntry] = &[];

/// Generate an ML-KEM-1024 key pair.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn keygen() -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlKem1024Keygen)?;
    Err(Error::NotImplemented)
}

/// Encapsulate a shared secret using an ML-KEM-1024 public key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn encapsulate(_public_key: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlKem1024Encaps)?;
    Err(Error::NotImplemented)
}

/// Decapsulate a shared secret using an ML-KEM-1024 private key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn decapsulate(_private_key: &[u8], _ciphertext: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::MlKem1024Decaps)?;
    Err(Error::NotImplemented)
}
