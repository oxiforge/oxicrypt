//! Deterministic Random Bit Generators — NIST SP 800-90A Rev. 1.
//!
//! # Phase 2 scope
//!
//! * CTR_DRBG (§10.2) with AES-128/192/256, both `no df` and `use df`
//!   variants. See [`ctr`].
//! * Hash_DRBG and HMAC_DRBG land in subsequent batches.
//!
//! # Power-up KATs
//!
//! Per-variant known-answer tests are re-exported as [`KATS`] and
//! consumed by the workspace ACVP harness.
#![no_std]
#![forbid(unsafe_code)]

pub mod ctr;
pub mod kat;

pub use ctr::{
    Aes128Factory, Aes192Factory, Aes256Factory, CipherFactory, CtrDrbg, CtrDrbgAes128,
    CtrDrbgAes192, CtrDrbgAes256, DrbgError, MAX_DF_INPUT,
};
pub use kat::KATS;
