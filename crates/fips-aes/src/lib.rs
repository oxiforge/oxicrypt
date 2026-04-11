//! AES block cipher and modes (ECB, CBC, CTR, GCM) per FIPS 197 /
//! SP 800-38A / SP 800-38D.
//!
//! # Phase 1 scope
//!
//! This crate implements:
//!
//!   * AES-128 / AES-192 / AES-256 block cipher (FIPS 197)
//!   * Electronic Codebook (ECB) — SP 800-38A §6.1
//!   * Cipher Block Chaining (CBC) — SP 800-38A §6.2
//!   * Counter (CTR) — SP 800-38A §6.5
//!   * Galois/Counter Mode (GCM) — SP 800-38D (96-bit IV, 128-bit tag)
//!
//! Additional modes (CCM, KW/KWP, CMAC) are deferred to Phase 3 per
//! the project plan.
//!
//! # Power-up KATs
//!
//! One encrypt-and-decrypt KAT per mode × key size (12 total) lives
//! in the [`kat`] module and is re-exported as [`KATS`]. Vectors are
//! sourced from FIPS 197 Appendix C, SP 800-38A Appendix F.2 / F.5,
//! and the McGrew-Viega GCM Appendix B test cases listed by NIST.
//!
//! # Side-channel posture
//!
//! Pure Rust, table-free S-box implementation. Constant-time
//! hardening (bitsliced core or AES-NI with a safe fallback) is
//! deferred to Phase 4 per the project plan. This is acceptable at
//! FIPS 140-3 Level 1, which does not mandate side-channel
//! resistance.

#![no_std]
#![forbid(unsafe_code)]

pub mod block;
pub mod kat;
pub mod modes;

pub use block::{Aes128Key, Aes192Key, Aes256Key, BLOCK_SIZE};
pub use kat::KATS;
pub use modes::{
    cbc_decrypt, cbc_encrypt, ctr_xor, ecb_decrypt, ecb_encrypt, gcm_decrypt, gcm_encrypt,
    BlockCipher, ModeError,
};
