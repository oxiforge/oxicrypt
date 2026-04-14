//! P-384 ECDSA stubs — FIPS 186-5, CNSA 1.0.
//!
//! Placeholder entry points for P-384 ECDSA. The P-384 field,
//! scalar, and point layers have not yet been implemented; all
//! entry points return [`oxicrypt_module::Error::NotImplemented`].
//!
//! The algorithm-profile gates are wired: under CNSA 1.0,
//! `require_allowed` will pass for P-384 services.

use oxicrypt_module::{Error, Service};

/// Sign a message with an ECDSA P-384 private key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn sign(_private_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::EcdsaP384Sign)?;
    Err(Error::NotImplemented)
}

/// Verify an ECDSA P-384 signature.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn verify(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::EcdsaP384Verify)?;
    Err(Error::NotImplemented)
}

/// Generate an ECDSA P-384 key pair.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn keygen() -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::EcdsaP384Keygen)?;
    Err(Error::NotImplemented)
}
