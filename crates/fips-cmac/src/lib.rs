//! AES-CMAC per NIST SP 800-38B.
//!
//! # Approved services
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | AES-128-CMAC tag | SP 800-38B §6.2 | [`cmac_aes128`] |
//! | AES-192-CMAC tag | SP 800-38B §6.2 | [`cmac_aes192`] |
//! | AES-256-CMAC tag | SP 800-38B §6.2 | [`cmac_aes256`] |
//!
//! All three services produce a full 128-bit tag; truncated-tag
//! variants are not exposed in Phase 1.
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
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes one KAT per AES key size (three entries total)
//! drawn from SP 800-38B Appendix D.
//!
//! # Sensitive security parameters
//!
//! - **CMAC key** — CSP. Consumed at `cmac_aesNNN` entry by the
//!   underlying AES key expansion; the `AesNNNKey` round-key
//!   schedule is the long-lived in-memory form. Subkeys K1/K2
//!   derived inside [`cmac::cmac_tag`] are ephemeral CSPs that
//!   live only for the duration of the call stack frame.
//! - **Message / tag** — public. Tag comparison is the caller's
//!   responsibility and must be constant-time.
//!
//! # FIPS module gating
//!
//! Public CMAC entry points call
//! [`fips_module::require_operational`]; the `*_internal` path is
//! used by the KAT runners so self-test can execute during
//! `SelfTest`.

#![no_std]
#![forbid(unsafe_code)]

pub mod cmac;
pub mod kat;

pub use cmac::{cmac_aes128, cmac_aes192, cmac_aes256, cmac_tag, BLOCK_SIZE};
pub use kat::KATS;
