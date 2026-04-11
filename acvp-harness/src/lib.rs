//! pqclib ACVP harness library.
//!
//! This crate is the library half of the `acvp-harness` package: the
//! `src/main.rs` binary is a thin CLI wrapper, while everything of
//! substance — the hand-rolled JSON parser, the typed envelope over
//! ACVP vector sets, the algorithm-handler registry, and the per-
//! algorithm AFT dispatchers — lives here so that integration tests
//! in `tests/` can exercise it directly without shelling out.
//!
//! # Dispatch scope
//!
//! Phase 3 is being landed in chunks. As of R12-B the harness carries
//! **two** envelope shapes:
//!
//! - ACVP `internalProjection.json` — the shape `usnistgov/ACVP-Server`
//!   publishes. R10 wired two handlers on it (SHA3-256, HMAC-SHA2-256);
//!   R12-A expanded that to seventeen (the entire SHA-3 hashing
//!   family, both SHAKE XOFs, HMAC-SHA-1, and every HMAC-SHA-2 /
//!   HMAC-SHA-3 variant). The dispatcher lives in [`dispatch`] and the
//!   per-algorithm handlers under [`handlers`].
//! - CAVP SHS `.rsp` byte vectors — the *second envelope shape*
//!   landed in R12-B. R11′ recorded the reason: upstream ACVP-Server
//!   ships no top-level `SHA-*`, `SHA1-*`, or `SHA2-*` vector
//!   directories at the pinned commit, so the SHA-2 family has to
//!   ride CAVP SHS instead. The parser lives in [`rsp`], the
//!   dispatcher in [`shs`], and the seven handlers
//!   (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
//!   SHA-512/256) in [`handlers::shs`].
//!
//! Everything else — HKDF, AES, DRBG, ECDSA, EdDSA, RSA, the Monte
//! Carlo and Large Data tests — is intentionally out of scope for
//! these chunks. Both dispatchers are designed so future handlers
//! slot in without touching the envelope layers; see
//! [`dispatch::with_default_handlers`] and
//! [`shs::with_default_shs_handlers`] for the extension points.
//!
//! # Module gating
//!
//! Every call to [`dispatch::process`] starts with
//! `fips_module::require_operational()`. A prompt submitted against a
//! module that hasn't passed its power-up self-tests is rejected with
//! [`dispatch::DispatchError::Module`] before any crypto primitive is
//! touched, so a failed KAT can never yield an ACVP response.
//!
//! # Zero-third-party-dependencies
//!
//! The JSON parser in [`json`] and the hex codec in [`hex`] are
//! deliberately in-tree instead of pulled from crates.io. This keeps
//! the CMVP supply-chain story on the validation binary identical to
//! the story on the module itself: no external code, period.

#![allow(
    // The harness library is test-oriented glue, not crypto core.
    // Clippy's crypto-hardened lints are relaxed here for the same
    // reasons they're relaxed in `src/main.rs` and `tools/ct-validation`.
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    // `Sha3_256Handler` / `HmacSha2_256Handler` mirror the naming
    // already in use in `fips-hmac` (e.g. `HmacSha512_224`), which is
    // itself driven by NIST's own algorithm names. This matches
    // `fips-hmac`'s crate-level allow.
    non_camel_case_types
)]

pub mod dispatch;
pub mod envelope;
pub mod handlers;
pub mod hex;
pub mod json;
pub mod rsp;
pub mod shs;

/// Convenience wrapper: run `fips_module::initialize()` and treat
/// `AlreadyInitialized` as success.
///
/// Integration tests share a single `fips_module` state machine
/// across test cases within the same test binary, so the first call
/// initializes and subsequent calls are no-ops. This helper keeps the
/// boilerplate in tests down to a single line.
pub fn ensure_initialized() -> Result<(), fips_module::Error> {
    match fips_module::initialize() {
        Ok(()) | Err(fips_module::Error::AlreadyInitialized) => Ok(()),
        Err(e) => Err(e),
    }
}
