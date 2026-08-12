//! Deterministic Random Bit Generators — NIST SP 800-90A Rev. 1.
//!
//! # Approved services
//!
//! | Service | Standard | Module |
//! |---------|----------|--------|
//! | CTR_DRBG AES-128/192/256 (both `no df` and `use df`) | SP 800-90A §10.2 | [`ctr`] |
//! | Hash_DRBG SHA-256/384/512 | SP 800-90A §10.1.1 | [`hash`] |
//! | HMAC_DRBG SHA-256/384/512 | SP 800-90A §10.1.2 | [`hmac`] |
//! | Continuous / health tests | SP 800-90A §11.3 | [`health`] |
//!
//! Each DRBG exposes the standard `instantiate → reseed → generate`
//! life cycle; prediction-resistance requests are satisfied by a
//! caller-supplied entropy input on each `generate` call (the module
//! does not bundle an entropy source of its own — see the Security
//! Policy for the boundary).
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes 24 entries: 12 instantiate-then-generate KATs (one
//! per DRBG variant), 9 prediction-resistance KATs, and 3 error-path
//! health tests. Every vector comes from NIST CAVP DRBGVS.
//!
//! # Conditional self-tests
//!
//! - **Error-path health checks** ([`health`]): generate-before-
//!   instantiate, reseed-counter ceiling and post-uninstantiate access,
//!   run as part of the power-up KAT set; failure returns
//!   `SelfTestFailure` to `oxicrypt_module`.
//! - **Instantiate / reseed input checks**: the `no df` path requires
//!   seed material of exactly `seedlen` bytes, and the `use df` path
//!   rejects concatenated input longer than the derivation-function
//!   buffer. Minimum entropy length is the caller's obligation and is
//!   not checked here.
//!
//! # Sensitive security parameters
//!
//! - **Entropy input** (caller-supplied) — CSP. Consumed in-place
//!   by `instantiate` / `reseed` and not retained beyond the call.
//! - **Internal state** (`V`, `Key`, `reseed_counter` for CTR_DRBG;
//!   `V`, `C`, `reseed_counter` for Hash_DRBG; `K`, `V`,
//!   `reseed_counter` for HMAC_DRBG) — CSP. Lives for the lifetime
//!   of the DRBG instance. The keying material (`Key`, `V`, `C`) is
//!   zeroized on drop via volatile writes (see `oxicrypt-zeroize`);
//!   `reseed_counter` and the instantiation flag are not, and carry
//!   no secret material.
//! - **Generated output** — public once returned, but must be
//!   treated as CSP-material by the caller if used to key other
//!   services.
//!
//! # FIPS module gating
//!
//! The instantiate entry points call [`oxicrypt_module::require_operational`]
//! and [`oxicrypt_module::require_allowed`] to enforce algorithm-profile
//! restrictions; reseed and generate operate on an already-gated
//! instantiation and do not re-check. Instantiate methods
//! gate on the active profile via [`oxicrypt_module::Service::CtrDrbgAes128`],
//! `Service::CtrDrbgAes192`, `Service::CtrDrbgAes256`, `Service::HashDrbgSha256`,
//! `Service::HashDrbgSha384`, `Service::HashDrbgSha512`, `Service::HmacDrbgSha256`,
//! `Service::HmacDrbgSha384`, and `Service::HmacDrbgSha512` respectively.
//! KAT runners use the hidden `*_internal` surface to execute during `SelfTest`.
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
    HASH_DRBG_MAX_DF_INPUT, HashAlg, HashDrbg, HashDrbgSha256, HashDrbgSha384, HashDrbgSha512,
    Sha256Alg, Sha384Alg, Sha512Alg,
};
pub use hmac::{
    HMAC_DRBG_MAX_PROVIDED, HmacAlg, HmacDrbg, HmacDrbgSha256, HmacDrbgSha384, HmacDrbgSha512,
    HmacSha256Alg, HmacSha384Alg, HmacSha512Alg,
};
pub use kat::KATS;
