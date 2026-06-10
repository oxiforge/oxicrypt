//! oxicrypt ACVP harness library.
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
//! Subsequent chunks expanded the handler set to 78 algorithms covering
//! AES (7 modes), DRBG (3 families), KDFs (HKDF, KBKDF, TLS, PBKDF),
//! SP 800-185 derived functions (cSHAKE, KMAC, TupleHash, ParallelHash),
//! ECDSA, EdDSA, RSA (all modes), KAS-ECC-SSC, KAS-FFC-SSC, and
//! post-quantum algorithms (ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256s,
//! LMS, XMSS).  All 78 handlers declare ACVP registration capabilities
//! via [`handlers::caps`], enabling full demo-server registration.
//!
//! # Module gating
//!
//! Every call to [`dispatch::process`] starts with
//! `oxicrypt_module::require_operational()`. A prompt submitted against a
//! module that hasn't passed its power-up self-tests is rejected with
//! [`dispatch::DispatchError::Module`] before any crypto primitive is
//! touched, so a failed KAT can never yield an ACVP response.
//!
//! # ACVP transport client
//!
//! The [`transport`] module implements the ACVP REST protocol flow for
//! end-to-end sessions against the NIST demo server
//! (`demo.acvts.nist.gov`):
//!
//! 1. Authenticate via TOTP-signed JWT (RFC 6238 / RFC 7519, using
//!    the module's own HMAC-SHA-256)
//! 2. Register algorithm capabilities derived from the handler
//!    registry via [`dispatch::AlgorithmHandler::acvp_capabilities`]
//! 3. Fetch, process, submit, and poll each vector set
//!
//! HTTPS with mutual TLS is handled by shelling out to `curl(1)`,
//! preserving the workspace's zero-third-party-dependencies policy.
//! The `demo-run` CLI subcommand in `main.rs` is the user-facing
//! entry point.
//!
//! Computed responses are persisted to a per-session directory (see
//! [`session`]) before the first submit attempt, so a transport
//! failure after a long compute costs a `resubmit` (pure replay of
//! the cached bytes) instead of a recompute.
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
pub mod mct_helpers;
pub mod rsp;
pub mod session;
pub mod shs;
pub mod transport;

/// Convenience wrapper: run `oxicrypt_module::initialize()` and treat
/// `AlreadyInitialized` as success.
///
/// Integration tests share a single `oxicrypt_module` state machine
/// across test cases within the same test binary, so the first call
/// initializes and subsequent calls are no-ops. This helper keeps the
/// boilerplate in tests down to a single line.
pub fn ensure_initialized() -> Result<(), oxicrypt_module::Error> {
    match oxicrypt_module::initialize() {
        Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => Ok(()),
        Err(e) => Err(e),
    }
}
