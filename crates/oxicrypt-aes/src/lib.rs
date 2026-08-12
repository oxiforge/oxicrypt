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
//! | Key Wrap (KW)           | SP 800-38F §6.2 / RFC 3394 | [`kw_wrap`] / [`kw_unwrap`] (forward cipher), [`kw_wrap_inverse_cipher`] / [`kw_unwrap_inverse_cipher`] (inverse cipher) |
//! | Key Wrap with Padding (KWP) | SP 800-38F §6.3 / RFC 5649 | [`kwp_wrap`] / [`kwp_unwrap`] (forward cipher), [`kwp_wrap_inverse_cipher`] / [`kwp_unwrap_inverse_cipher`] (inverse cipher) |
//!
//! ECB is exposed so the ACVP harness can drive the per-block CAVP
//! KATs. CTR_DRBG, KW/KWP and AES-CMAC do not call it — they take the
//! raw block cipher through [`BlockCipher`]. It is **not** intended
//! for direct use as a confidentiality mode by application callers.
//!
//! # Power-up self-tests
//!
//! [`KATS`] holds 23 encrypt-and-decrypt entries: three per key size
//! for ECB, CBC, CTR, GCM and CCM, six KW vectors and two KWP vectors.
//! Vectors come from the NIST AES example vectors that FIPS 197
//! Appendix C points to, SP 800-38A Appendix F.2 / F.5, and the
//! McGrew-Viega GCM Appendix B test cases.
//!
//! # Sensitive security parameters
//!
//! - **AES key** (`Aes128Key` / `Aes192Key` / `Aes256Key`) — CSP.
//!   The key struct stores the expanded round-key schedule; the
//!   caller's original key bytes are not retained beyond the
//!   `new(...)` call. The round-key schedule is zeroized via
//!   [`oxicrypt_zeroize`] when the key is dropped.
//! - **Initialization vectors / counters** — public per
//!   SP 800-38A-D. Never SSPs, but misuse (IV reuse under the
//!   same key for GCM or CCM) catastrophically breaks
//!   authenticity; callers are responsible for uniqueness.
//! - **GCM/CCM authentication tags** — public outputs; `*_decrypt`
//!   entry points return a single error variant on any mismatch (no early-return
//!   distinguisher between "wrong tag" and "wrong ciphertext").
//!
//! # FIPS module gating
//!
//! All public entry points call [`oxicrypt_module::require_operational`]
//! and [`oxicrypt_module::require_allowed`] to enforce algorithm-profile
//! restrictions. Key constructors ([`Aes128Key::new`], [`Aes192Key::new`],
//! [`Aes256Key::new`]) return `Result` and gate on the active profile
//! via [`oxicrypt_module::Service::Aes128`], `Service::Aes192`, and
//! `Service::Aes256` respectively. KAT runners use the hidden `*_internal`
//! surface to execute during `SelfTest`.
//!
//! # Side-channel posture
//!
//! Pure Rust byte-wise S-box implementation — no T-tables, but the
//! 256-byte S-box is indexed by secret data. The optional `accel-aes`
//! feature (default off) dispatches to AES-NI with a portable
//! fallback; bitsliced hardening of the portable path is not
//! implemented. This is acceptable at FIPS 140-3 Level 1, which does
//! not mandate side-channel resistance.

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
pub use kw::{
    KW_DEFAULT_IV, KWP_IV_PREFIX, kw_unwrap, kw_unwrap_inverse_cipher, kw_wrap,
    kw_wrap_inverse_cipher, kwp_unwrap, kwp_unwrap_inverse_cipher, kwp_wrap,
    kwp_wrap_inverse_cipher,
};
pub use modes::{
    BlockCipher, ModeError, cbc_decrypt, cbc_encrypt, ctr_xor, ecb_decrypt, ecb_encrypt,
    gcm_decrypt, gcm_encrypt,
};
