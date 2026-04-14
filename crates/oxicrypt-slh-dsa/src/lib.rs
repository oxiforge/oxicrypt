//! SLH-DSA (FIPS 205) — stateless hash-based digital signature.
//!
//! # Status
//!
//! **Stub crate.** This crate reserves the API surface and
//! namespace for SLH-DSA, the third NIST post-quantum signature
//! standard. SLH-DSA is not currently part of the CNSA 2.0 suite
//! but is one of the three NIST PQC standards (alongside ML-KEM
//! and ML-DSA). Having the stub means we are ready if the NSA
//! adds it in a future update.
//!
//! All entry points currently return
//! [`oxicrypt_module::Error::NotImplemented`]. Allowed in
//! [`AlgorithmProfile::Unrestricted`](oxicrypt_module::AlgorithmProfile::Unrestricted) only.
//!
//! # Approved services (planned)
//!
//! | Service | Standard |
//! |---|---|
//! | SLH-DSA keygen | FIPS 205 |
//! | SLH-DSA sign | FIPS 205 |
//! | SLH-DSA verify | FIPS 205 |
//!
//! # Self-tests
//!
//! No self-tests are registered until the implementation lands.

#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::{Error, KatEntry, Service};

/// Power-up KATs for SLH-DSA. Empty until implementation lands.
pub const KATS: &[KatEntry] = &[];

/// Generate an SLH-DSA key pair.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn keygen() -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaKeygen)?;
    Err(Error::NotImplemented)
}

/// Sign a message with an SLH-DSA private key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn sign(_private_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaSign)?;
    Err(Error::NotImplemented)
}

/// Verify a signature with an SLH-DSA public key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn verify(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaVerify)?;
    Err(Error::NotImplemented)
}
