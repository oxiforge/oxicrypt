//! AES-CMAC per NIST SP 800-38B.
//!
//! # Phase 1 scope
//!
//! Full 128-bit-tag AES-CMAC over AES-128/192/256, plus a set of
//! power-up KATs drawn from SP 800-38B Appendix D.
//!
//! # Design notes
//!
//! The implementation is layered over `fips-aes::BlockCipher`, so it
//! runs against the same AES primitive that the rest of the module
//! uses — there is no second AES core to keep in sync. The pure-Rust,
//! table-free side-channel posture is inherited from `fips-aes`; see
//! that crate's lib.rs header for the rationale.
//!
//! # Public API
//!
//! The simple entry points [`cmac_aes128`], [`cmac_aes192`], and
//! [`cmac_aes256`] take a fixed-size key and a message slice and
//! return a 16-byte tag. Callers that already hold a prepared
//! `fips_aes::Aes128Key` / `Aes192Key` / `Aes256Key` can instead use
//! the lower-level [`cmac::cmac_tag`] function, which is generic
//! over any `fips_aes::BlockCipher` implementation.

#![no_std]
#![forbid(unsafe_code)]

pub mod cmac;
pub mod kat;

pub use cmac::{cmac_aes128, cmac_aes192, cmac_aes256, cmac_tag, BLOCK_SIZE};
pub use kat::KATS;
