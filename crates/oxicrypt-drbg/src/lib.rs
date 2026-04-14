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
//! [`KATS`] exposes one instantiate-generate-reseed-generate KAT per
//! DRBG variant, sourced from NIST CAVP / ACVP-Server vectors.
//!
//! # Conditional self-tests
//!
//! - **Continuous health tests** (SP 800-90A §11.3): repetition-count
//!   and adaptive-proportion tests run on the DRBG's internal state
//!   transitions; failure transitions the state machine to the Error
//!   state via `oxicrypt_module`.
//! - **Instantiate / reseed input checks**: all entropy and nonce
//!   length bounds from the variant's SP 800-90A table are enforced
//!   at the entry points; out-of-range inputs return `DrbgError`
//!   without touching the internal state.
//!
//! # Sensitive security parameters
//!
//! - **Entropy input** (caller-supplied) — CSP. Consumed in-place
//!   by `instantiate` / `reseed` and not retained beyond the call.
//! - **Internal state** (`V`, `Key`, `reseed_counter` for CTR_DRBG;
//!   `V`, `C`, `reseed_counter` for Hash_DRBG; `K`, `V`,
//!   `reseed_counter` for HMAC_DRBG) — CSP. Lives for the lifetime
//!   of the DRBG instance. Internal state is zeroized on drop via
//!   volatile writes (see `oxicrypt-zeroize`).
//! - **Generated output** — public once returned, but must be
//!   treated as CSP-material by the caller if used to key other
//!   services.
//!
//! # FIPS module gating
//!
//! Every public DRBG entry point calls [`oxicrypt_module::require_operational`]
//! and [`oxicrypt_module::require_allowed`] to enforce algorithm-profile
//! restrictions. Instantiate and reseed methods now return `Result` and
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
    HashAlg, HashDrbg, HashDrbgSha256, HashDrbgSha384, HashDrbgSha512, Sha256Alg, Sha384Alg,
    Sha512Alg, HASH_DRBG_MAX_DF_INPUT,
};
pub use hmac::{
    HmacAlg, HmacDrbg, HmacDrbgSha256, HmacDrbgSha384, HmacDrbgSha512, HmacSha256Alg,
    HmacSha384Alg, HmacSha512Alg, HMAC_DRBG_MAX_PROVIDED,
};
pub use kat::KATS;
