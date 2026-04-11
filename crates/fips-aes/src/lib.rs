//! AES block cipher and modes per FIPS 197 / SP 800-38A-F.
//!
//! # Approved services
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | AES-128/192/256 block cipher | FIPS 197 | [`Aes128Key`] / [`Aes192Key`] / [`Aes256Key`] |
//! | ECB encrypt/decrypt     | SP 800-38A §6.1 | [`ecb_encrypt`] / [`ecb_decrypt`] |
//! | CBC encrypt/decrypt     | SP 800-38A §6.2 | [`cbc_encrypt`] / [`cbc_decrypt`] |
//! | CTR mode                | SP 800-38A §6.5 | [`ctr_xor`] |
//! | GCM authenticated encrypt/decrypt | SP 800-38D (96-bit IV, 128-bit tag) | [`gcm_encrypt`] / [`gcm_decrypt`] |
//! | CCM authenticated encrypt/decrypt | SP 800-38C | [`ccm_encrypt`] / [`ccm_decrypt`] |
//! | Key Wrap (KW)           | SP 800-38F §6.2 / RFC 3394 | [`kw_wrap`] / [`kw_unwrap`] |
//! | Key Wrap with Padding (KWP) | SP 800-38F §6.3 / RFC 5649 | [`kwp_wrap`] / [`kwp_unwrap`] |
//!
//! ECB is exposed because it is required as a primitive by
//! other approved services (CTR_DRBG, the KW/KWP construction,
//! AES-CMAC). It is **not** intended for direct use as a
//! confidentiality mode by application callers; the Security
//! Policy will call this out.
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes one encrypt-and-decrypt KAT per mode × key
//! size (12 entries total). Vectors are sourced from FIPS 197
//! Appendix C, SP 800-38A Appendix F.2 / F.5, and the McGrew-Viega
//! GCM Appendix B test cases listed by NIST.
//!
//! # Sensitive security parameters
//!
//! - **AES key** (`Aes128Key` / `Aes192Key` / `Aes256Key`) — CSP.
//!   The key struct stores the expanded round-key schedule; the
//!   caller's original key bytes are not retained beyond the
//!   `new(...)` call. Zeroization of the round-key schedule at
//!   drop is planned alongside the crate-wide hardening pass.
//! - **Initialization vectors / counters** — public per
//!   SP 800-38A-D. Never SSPs, but misuse (IV reuse under the
//!   same key for GCM or CCM) catastrophically breaks
//!   authenticity; callers are responsible for uniqueness.
//! - **GCM/CCM authentication tags** — public outputs; `*_decrypt`
//!   entry points compare tags in constant time and return a
//!   single error variant on any mismatch (no early-return
//!   distinguisher between "wrong tag" and "wrong ciphertext").
//!
//! # FIPS module gating
//!
//! All public entry points call
//! [`fips_module::require_operational`]; KAT runners use the
//! hidden `*_internal` surface to execute during `SelfTest`.
//!
//! # Side-channel posture
//!
//! Pure Rust, table-free S-box implementation. Constant-time
//! hardening (bitsliced core or AES-NI with a safe fallback) is
//! deferred to the Phase 4 hardening chunk per the project
//! plan. This is acceptable at FIPS 140-3 Level 1, which does
//! not mandate side-channel resistance, but the Security Policy
//! will disclose the current posture plainly.

#![no_std]
#![forbid(unsafe_code)]

pub mod block;
pub mod ccm;
pub mod kat;
pub mod kw;
pub mod modes;

pub use block::{Aes128Key, Aes192Key, Aes256Key, BLOCK_SIZE};
pub use ccm::{ccm_decrypt, ccm_encrypt};
pub use kat::KATS;
pub use kw::{kw_unwrap, kw_wrap, kwp_unwrap, kwp_wrap, KWP_IV_PREFIX, KW_DEFAULT_IV};
pub use modes::{
    cbc_decrypt, cbc_encrypt, ctr_xor, ecb_decrypt, ecb_encrypt, gcm_decrypt, gcm_encrypt,
    BlockCipher, ModeError,
};
