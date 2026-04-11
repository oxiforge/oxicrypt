//! ECDSA per FIPS 186-5.
//!
//! # Approved services
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | P-256 public-key derivation | FIPS 186-5 §6.2.1 | [`p256_ecdsa::derive_public_key`] |
//! | P-256 ECDSA sign (caller-supplied `k`) | FIPS 186-5 §6.4.1 | [`p256_ecdsa::sign_with_k`] |
//! | P-256 ECDSA verify | FIPS 186-5 §6.4.2 | [`p256_ecdsa::verify`] |
//!
//! P-384 and P-521 are deferred; they will reuse the same
//! field / point / scalar layer pattern as P-256 once the
//! current curve passes ACVP.
//!
//! # Layering
//!
//! Each curve is built bottom-up:
//!
//!   * [`p256_field`] — arithmetic in `GF(p)` with
//!     `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`. Montgomery form,
//!     four 64-bit limbs, constant-time, `no_std`.
//!   * [`p256_scalar`] — arithmetic mod the group order `n`,
//!     used for signature scalars and nonce reduction.
//!   * [`p256_point`] — Jacobian point representation, constant-
//!     time scalar multiplication, SEC1 encoding/decoding with
//!     full public-key validation (on-curve, not identity,
//!     order-n).
//!   * [`p256_ecdsa`] — FIPS 186-5 sign and verify on top of
//!     the above layers.
//!
//! # Sign API shape
//!
//! `sign_with_k` takes the per-signature nonce `k` as an explicit
//! argument; deterministic nonce generation per RFC 6979 and
//! random-k sampling through `fips-drbg` land as wrapper services
//! once both CAVP-K and hedged-signature vectors pass.
//!
//! # Power-up self-tests
//!
//! [`p256_ecdsa::self_test`] runs a sign-and-verify KAT from
//! FIPS 186-5 / NIST CAVP. The workspace test inventory wires it
//! into `fips_module::initialize_with_tests` alongside the other
//! crates' KATs.
//!
//! # Conditional self-tests
//!
//! - **Public-key validation** (FIPS 186-5 §A.2.2 / §A.4.2):
//!   all imported public keys are checked for SEC1 format, on-
//!   curve, not-identity, and order-n membership inside
//!   [`p256_point`] before verify proceeds. Failures surface as
//!   a single generic error variant.
//! - **Pairwise consistency test** (IG 10.3.A): after keygen,
//!   the derived public key must successfully verify a sample
//!   signature made with the fresh private key. Implementation
//!   lives with the future random-keygen wrapper.
//!
//! # Sensitive security parameters
//!
//! - **Private key `d`** (`[u8; 32]`) — CSP. Consumed by
//!   `derive_public_key` / `sign_with_k`; not retained beyond
//!   the call.
//! - **Per-signature nonce `k`** — CSP. Caller-supplied in the
//!   current API; must be unpredictable and single-use per
//!   FIPS 186-5 §6.4.1. Reuse under the same key reveals `d`.
//! - **Public key `Q`** — public. Subject to full validation
//!   on import.
//! - **Signature `(r, s)`** — public output.
//!
//! # Side-channel posture
//!
//! Scalar arithmetic and point operations are written to run in
//! constant time with no secret-dependent table lookups or
//! branches. Verification uses the same routines but with
//! non-secret inputs, so the constant-time properties are simply
//! a cost rather than a requirement there. FIPS 140-3 Level 1
//! does not mandate side-channel resistance; the Security Policy
//! will disclose the actual posture.
//!
//! # FIPS module gating
//!
//! Every public ECDSA entry point calls
//! [`fips_module::require_operational`]; the `*_internal` helpers
//! skip the gate so that self-tests can run during `SelfTest`.
#![no_std]
#![forbid(unsafe_code)]

pub mod p256_ecdsa;
pub mod p256_field;
pub mod p256_point;
pub mod p256_scalar;
