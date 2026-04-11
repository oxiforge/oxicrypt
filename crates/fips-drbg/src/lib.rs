//! Deterministic Random Bit Generators — NIST SP 800-90A Rev. 1.
//!
//! # Phase 2 scope
//!
//! * CTR_DRBG (§10.2) with AES-128/192/256, both `no df` and `use df`
//!   variants. See [`ctr`].
//! * Hash_DRBG (§10.1.1) over SHA-256/384/512. See [`hash`].
//! * HMAC_DRBG (§10.1.2) over HMAC-SHA-256/384/512. See [`hmac`].
//! * SP 800-90A §11.3 health tests. See [`health`].
//!
//! # Power-up KATs
//!
//! Per-variant known-answer tests are re-exported as [`KATS`] and
//! consumed by the workspace ACVP harness.
#![no_std]
#![forbid(unsafe_code)]

pub mod ctr;
pub mod hash;
pub mod health;
pub mod hmac;
pub mod kat;

pub use ctr::{
    Aes128Factory, Aes192Factory, Aes256Factory, CipherFactory, CtrDrbg, CtrDrbgAes128,
    CtrDrbgAes192, CtrDrbgAes256, DrbgError, MAX_DF_INPUT,
};
pub use hash::{
    HashAlg, HashDrbg, HashDrbgSha256, HashDrbgSha384, HashDrbgSha512, Sha256Alg, Sha384Alg,
    Sha512Alg, HASH_DRBG_MAX_DF_INPUT,
};
pub use hmac::{
    HmacAlg, HmacDrbg, HmacDrbgSha256, HmacDrbgSha384, HmacDrbgSha512, HmacSha256Alg,
    HmacSha384Alg, HmacSha512Alg, HMAC_DRBG_MAX_PROVIDED,
};
pub use kat::KATS;
