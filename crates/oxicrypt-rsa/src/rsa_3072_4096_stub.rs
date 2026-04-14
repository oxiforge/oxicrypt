//! RSA-3072 and RSA-4096 stubs — CNSA 1.0.
//!
//! Placeholder entry points for RSA key sizes required by CNSA 1.0
//! (>= 3072 bits). The 3072- and 4096-bit big-int types and
//! Montgomery contexts have not been implemented yet; all entry
//! points return [`oxicrypt_module::Error::NotImplemented`].
//!
//! The algorithm-profile gates are wired so that under CNSA 1.0,
//! `require_allowed` passes for these services.

use oxicrypt_module::{Error, Service};

// ── RSA-3072 ──────────────────────────────────────────────────────

/// Generate an RSA-3072 key pair.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn generate_3072() -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaKeygen3072)?;
    Err(Error::NotImplemented)
}

/// RSA-PKCS1v1.5 sign with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pkcs1_v15_sign_3072(_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPkcs1v15Sign3072)?;
    Err(Error::NotImplemented)
}

/// RSA-PKCS1v1.5 verify with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pkcs1_v15_verify_3072(
    _key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPkcs1v15Verify3072)?;
    Err(Error::NotImplemented)
}

/// RSA-PSS sign with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pss_sign_3072(_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPssSign3072)?;
    Err(Error::NotImplemented)
}

/// RSA-PSS verify with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pss_verify_3072(
    _key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPssVerify3072)?;
    Err(Error::NotImplemented)
}

/// RSA-OAEP encrypt/decrypt with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn oaep_3072(_key: &[u8], _input: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaOaep3072)?;
    Err(Error::NotImplemented)
}

// ── RSA-4096 ──────────────────────────────────────────────────────

/// Generate an RSA-4096 key pair.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn generate_4096() -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaKeygen4096)?;
    Err(Error::NotImplemented)
}

/// RSA-PKCS1v1.5 sign with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pkcs1_v15_sign_4096(_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPkcs1v15Sign4096)?;
    Err(Error::NotImplemented)
}

/// RSA-PKCS1v1.5 verify with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pkcs1_v15_verify_4096(
    _key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPkcs1v15Verify4096)?;
    Err(Error::NotImplemented)
}

/// RSA-PSS sign with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pss_sign_4096(_key: &[u8], _message: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPssSign4096)?;
    Err(Error::NotImplemented)
}

/// RSA-PSS verify with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn pss_verify_4096(
    _key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPssVerify4096)?;
    Err(Error::NotImplemented)
}

/// RSA-OAEP encrypt/decrypt with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn oaep_4096(_key: &[u8], _input: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaOaep4096)?;
    Err(Error::NotImplemented)
}
