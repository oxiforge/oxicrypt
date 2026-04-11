//! CAVP SHS per-algorithm handlers — the SHA-1 / SHA-2 family.
//!
//! These handlers ride the second envelope shape landed in R12-B
//! (see [`crate::shs`]). They are trivial wrappers around the
//! byte-oriented entry points in [`fips_sha`]; the dispatcher has
//! already sliced `msg` to the declared bit length, so each handler's
//! only job is to delegate to the right primitive and box the result
//! into a `Vec<u8>` so the response emitter can hex-encode it.
//!
//! The seven handlers registered by
//! [`crate::shs::with_default_shs_handlers`] are, in order:
//!
//! - `SHA-1`        (`fips_sha::sha1::sha1`)
//! - `SHA-224`      (`fips_sha::sha224::sha224`)
//! - `SHA-256`      (`fips_sha::sha256::sha256`)
//! - `SHA-384`      (`fips_sha::sha384::sha384`)
//! - `SHA-512`      (`fips_sha::sha512::sha512`)
//! - `SHA-512/224`  (`fips_sha::sha512_t::sha512_224`)
//! - `SHA-512/256`  (`fips_sha::sha512_t::sha512_256`)
//!
//! SHA-1 is wired because the CAVP SHS zip bundles it alongside the
//! SHA-2 family, and the lab will expect all seven files to be
//! dispatchable; its status in the module's approved-service list is
//! governed by the security policy's §9 / §12 sections, not by
//! whether a handler exists here.

use crate::dispatch::DispatchError;
use crate::shs::ShsHandler;

/// SHA-1 CAVP SHS handler.
pub struct Sha1Handler;

impl ShsHandler for Sha1Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-1"
    }
    fn digest_length_bytes(&self) -> usize {
        20
    }
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError> {
        fips_sha::sha1::sha1(msg)
            .map(|d| d.to_vec())
            .map_err(|_| DispatchError::Crypto("fips_sha::sha1::sha1 returned Err"))
    }
}

/// SHA-224 CAVP SHS handler.
pub struct Sha224Handler;

impl ShsHandler for Sha224Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-224"
    }
    fn digest_length_bytes(&self) -> usize {
        28
    }
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError> {
        fips_sha::sha224::sha224(msg)
            .map(|d| d.to_vec())
            .map_err(|_| DispatchError::Crypto("fips_sha::sha224::sha224 returned Err"))
    }
}

/// SHA-256 CAVP SHS handler.
pub struct Sha256Handler;

impl ShsHandler for Sha256Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-256"
    }
    fn digest_length_bytes(&self) -> usize {
        32
    }
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError> {
        fips_sha::sha256::sha256(msg)
            .map(|d| d.to_vec())
            .map_err(|_| DispatchError::Crypto("fips_sha::sha256::sha256 returned Err"))
    }
}

/// SHA-384 CAVP SHS handler.
pub struct Sha384Handler;

impl ShsHandler for Sha384Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-384"
    }
    fn digest_length_bytes(&self) -> usize {
        48
    }
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError> {
        fips_sha::sha384::sha384(msg)
            .map(|d| d.to_vec())
            .map_err(|_| DispatchError::Crypto("fips_sha::sha384::sha384 returned Err"))
    }
}

/// SHA-512 CAVP SHS handler.
pub struct Sha512Handler;

impl ShsHandler for Sha512Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-512"
    }
    fn digest_length_bytes(&self) -> usize {
        64
    }
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError> {
        fips_sha::sha512::sha512(msg)
            .map(|d| d.to_vec())
            .map_err(|_| DispatchError::Crypto("fips_sha::sha512::sha512 returned Err"))
    }
}

/// SHA-512/224 CAVP SHS handler.
pub struct Sha512_224Handler;

impl ShsHandler for Sha512_224Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-512/224"
    }
    fn digest_length_bytes(&self) -> usize {
        28
    }
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError> {
        fips_sha::sha512_t::sha512_224(msg)
            .map(|d| d.to_vec())
            .map_err(|_| DispatchError::Crypto("fips_sha::sha512_t::sha512_224 returned Err"))
    }
}

/// SHA-512/256 CAVP SHS handler.
pub struct Sha512_256Handler;

impl ShsHandler for Sha512_256Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-512/256"
    }
    fn digest_length_bytes(&self) -> usize {
        32
    }
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError> {
        fips_sha::sha512_t::sha512_256(msg)
            .map(|d| d.to_vec())
            .map_err(|_| DispatchError::Crypto("fips_sha::sha512_t::sha512_256 returned Err"))
    }
}
