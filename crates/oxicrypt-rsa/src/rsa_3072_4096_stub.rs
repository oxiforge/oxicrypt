//! RSA-3072 and RSA-4096 public entry points — CNSA 1.0.
//!
//! These entry points were originally stubs returning `NotImplemented`.
//! They now dispatch to the real implementations in [`crate::rsa3072`]
//! and [`crate::rsa4096`]. The simple-signature entry points provided
//! here are convenience wrappers that accept raw byte-slice keys —
//! production callers should prefer the [`crate::rsa3072::RsaPrivateKey3072`]
//! and [`crate::rsa4096::RsaPrivateKey4096`] handles which run a
//! pairwise consistency test on construction and select the CRT sign
//! path when CRT material is available.

use oxicrypt_module::{Error, Service};

// ── RSA-3072 ──────────────────────────────────────────────────────

/// Generate an RSA-3072 key pair. Returns the key handle.
///
/// This is a convenience entry point; prefer
/// [`crate::rsa3072::RsaPrivateKey3072::generate`] directly.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] or [`Error::InvalidInput`].
pub fn generate_3072(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    e: u64,
) -> Result<crate::rsa3072::RsaPrivateKey3072, Error> {
    crate::rsa3072::RsaPrivateKey3072::generate(drbg, e)
}

/// RSA-PKCS1v1.5 sign with a 3072-bit key (raw byte interface).
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pkcs1_v15_sign_3072(
    n_bytes: &[u8; 384],
    d_bytes: &[u8; 384],
    msg: &[u8],
) -> Result<[u8; 384], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPkcs1v15Sign3072)?;
    crate::rsa3072::pkcs1_v15_sign_internal(n_bytes, d_bytes, msg)
        .ok_or(Error::InvalidInput)
}

/// RSA-PKCS1v1.5 verify with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pkcs1_v15_verify_3072(
    n_bytes: &[u8; 384],
    e: u64,
    msg: &[u8],
    sig: &[u8; 384],
) -> Result<(), Error> {
    crate::rsa3072::pkcs1_v15_verify(n_bytes, e, msg, sig)
}

/// RSA-PSS sign with a 3072-bit key (raw byte interface).
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pss_sign_3072(
    n_bytes: &[u8; 384],
    d_bytes: &[u8; 384],
    msg: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 384], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPssSign3072)?;
    crate::rsa3072::pss_sign_internal(n_bytes, d_bytes, msg, salt)
        .ok_or(Error::InvalidInput)
}

/// RSA-PSS verify with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pss_verify_3072(
    n_bytes: &[u8; 384],
    e: u64,
    msg: &[u8],
    sig: &[u8; 384],
) -> Result<(), Error> {
    crate::rsa3072::pss_verify(n_bytes, e, msg, sig)
}

/// RSA-OAEP encrypt with a 3072-bit key.
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn oaep_encrypt_3072(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    n_bytes: &[u8; 384],
    e: u64,
    label: &[u8],
    msg: &[u8],
) -> Result<[u8; 384], Error> {
    crate::rsa3072::oaep_encrypt(drbg, n_bytes, e, label, msg)
}

// ── RSA-4096 ──────────────────────────────────────────────────────

/// Generate an RSA-4096 key pair.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] or [`Error::InvalidInput`].
pub fn generate_4096(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    e: u64,
) -> Result<crate::rsa4096::RsaPrivateKey4096, Error> {
    crate::rsa4096::RsaPrivateKey4096::generate(drbg, e)
}

/// RSA-PKCS1v1.5 sign with a 4096-bit key (raw byte interface).
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pkcs1_v15_sign_4096(
    n_bytes: &[u8; 512],
    d_bytes: &[u8; 512],
    msg: &[u8],
) -> Result<[u8; 512], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPkcs1v15Sign4096)?;
    crate::rsa4096::pkcs1_v15_sign_internal(n_bytes, d_bytes, msg)
        .ok_or(Error::InvalidInput)
}

/// RSA-PKCS1v1.5 verify with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pkcs1_v15_verify_4096(
    n_bytes: &[u8; 512],
    e: u64,
    msg: &[u8],
    sig: &[u8; 512],
) -> Result<(), Error> {
    crate::rsa4096::pkcs1_v15_verify(n_bytes, e, msg, sig)
}

/// RSA-PSS sign with a 4096-bit key (raw byte interface).
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pss_sign_4096(
    n_bytes: &[u8; 512],
    d_bytes: &[u8; 512],
    msg: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 512], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::RsaPssSign4096)?;
    crate::rsa4096::pss_sign_internal(n_bytes, d_bytes, msg, salt)
        .ok_or(Error::InvalidInput)
}

/// RSA-PSS verify with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn pss_verify_4096(
    n_bytes: &[u8; 512],
    e: u64,
    msg: &[u8],
    sig: &[u8; 512],
) -> Result<(), Error> {
    crate::rsa4096::pss_verify(n_bytes, e, msg, sig)
}

/// RSA-OAEP encrypt with a 4096-bit key.
///
/// # Errors
///
/// Returns [`Error::NotOperational`], [`Error::AlgorithmRestricted`],
/// or [`Error::InvalidInput`].
pub fn oaep_encrypt_4096(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    n_bytes: &[u8; 512],
    e: u64,
    label: &[u8],
    msg: &[u8],
) -> Result<[u8; 512], Error> {
    crate::rsa4096::oaep_encrypt(drbg, n_bytes, e, label, msg)
}
