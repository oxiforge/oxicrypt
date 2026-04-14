//! Finite-field Diffie-Hellman key agreement (RFC 3526).
//!
//! # Status
//!
//! **Stub crate.** This crate reserves the API surface and
//! namespace for finite-field DH with >= 3072-bit groups, as
//! required by CNSA 1.0 for key agreement alongside ECDH P-384.
//!
//! All entry points currently return
//! [`oxicrypt_module::Error::NotImplemented`].
//!
//! # Approved services (planned)
//!
//! | Service | Standard |
//! |---|---|
//! | DH-3072 key agreement | RFC 3526 / SP 800-56Ar3 |
//!
//! # Self-tests
//!
//! No self-tests are registered until the implementation lands.

#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::{Error, KatEntry, Service};

/// Power-up KATs for DH. Empty until implementation lands.
pub const KATS: &[KatEntry] = &[];

/// Compute a DH shared secret using a 3072-bit group.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] — this is a stub.
pub fn compute_shared_secret_3072(
    _private_key: &[u8],
    _public_key: &[u8],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::Dh3072)?;
    Err(Error::NotImplemented)
}
