//! ECDSA per FIPS 186-5.
//!
//! # Approved services
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | P-256 public-key derivation | FIPS 186-5 §6.2.1 | [`p256_ecdsa::derive_public_key`] |
//! | P-256 ECDSA sign (caller-supplied `k`) | FIPS 186-5 §6.4.1 | [`p256_ecdsa::sign_with_k`] |
//! | P-256 ECDSA sign (DRBG-sampled `k`) | FIPS 186-5 §6.4.1, §A.2.2 | [`p256_ecdsa::EcdsaP256PrivateKey::sign_sha256`] |
//! | P-256 ECDSA keygen (DRBG-sampled `d`) | FIPS 186-5 §A.2.2 | [`p256_ecdsa::EcdsaP256PrivateKey::generate`] |
//! | P-256 ECDSA verify | FIPS 186-5 §6.4.2 | [`p256_ecdsa::verify`] |
//! | P-384 public-key derivation | FIPS 186-5 §6.2.1 | [`p384_ecdsa::derive_public_key`] |
//! | P-384 ECDSA sign (caller-supplied `k`) | FIPS 186-5 §6.4.1 | [`p384_ecdsa::sign_with_k`] |
//! | P-384 ECDSA sign (DRBG-sampled `k`) | FIPS 186-5 §6.4.1, §A.2.2 | [`p384_ecdsa::EcdsaP384PrivateKey::sign_sha384`] |
//! | P-384 ECDSA keygen (DRBG-sampled `d`) | FIPS 186-5 §A.2.2 | [`p384_ecdsa::EcdsaP384PrivateKey::generate`] |
//! | P-384 ECDSA verify | FIPS 186-5 §6.4.2 | [`p384_ecdsa::verify`] |
//!
//! P-521 is deferred to a future phase.
//!
//! # Layering
//!
//! Each curve is built bottom-up. P-256 uses four 64-bit limbs;
//! P-384 uses six:
//!
//!   * [`p256_field`] / [`p384_field`] — arithmetic in `GF(p)`.
//!     Montgomery form, constant-time, `no_std`.
//!   * [`p256_scalar`] / [`p384_scalar`] — arithmetic mod the
//!     group order `n`, used for signature scalars and nonce
//!     reduction.
//!   * [`p256_point`] / [`p384_point`] — Jacobian point
//!     representation, constant-time scalar multiplication,
//!     SEC1 encoding/decoding with full public-key validation
//!     (on-curve, not identity, order-n).
//!   * [`p256_ecdsa`] / [`p384_ecdsa`] — FIPS 186-5 sign and
//!     verify on top of the above layers.
//!
//! # Sign API shape
//!
//! Each curve exposes two sign entry points:
//!
//!   * `sign_with_k` — raw primitive taking the per-signature nonce
//!     `k` as an explicit argument. This is the shape used by
//!     FIPS 186-5 / CAVP KATs that pin `k`, and by internal test
//!     code; it must never be called with a reused `k`.
//!   * `EcdsaP{256,384}PrivateKey::sign_sha{256,384}` — DRBG-backed
//!     wrappers that sample a fresh `k` from an approved HMAC_DRBG
//!     on every call via the FIPS 186-5 §A.2.2 rejection sampler.
//!     This is the path production code should use.
//!
//! RFC 6979 deterministic signing is deliberately **not** offered
//! here: FIPS 186-5 §6.4 mandates an approved RBG for `k`, and
//! operator discipline around `k` reuse is enforced by the
//! DRBG-backed wrapper taking ownership of the sampler.
//!
//! # Power-up self-tests
//!
//! [`p256_ecdsa::self_test`] and [`p384_ecdsa::self_test`] each run
//! a sign-and-verify KAT from FIPS 186-5 / NIST CAVP. The
//! workspace test inventory wires them into
//! `oxicrypt_module::initialize_with_tests` alongside the other
//! crates' KATs.
//!
//! # Conditional self-tests
//!
//! - **Public-key validation** (FIPS 186-5 §A.2.2 / §A.4.2):
//!   all imported public keys are checked for SEC1 format, on-
//!   curve, not-identity, and order-n membership inside
//!   [`p256_point`] / [`p384_point`] before verify proceeds.
//!   Failures surface as a single generic error variant.
//! - **Pairwise consistency test** (IG 10.3.A): every
//!   `EcdsaP{256,384}PrivateKey` constructor (keygen or import)
//!   runs a sign-and-verify PCT against a fixed probe message
//!   using a freshly DRBG-sampled `k`; the derived public key
//!   must accept the probe signature or construction returns an
//!   error. This exercises the sampler, the sign primitive, and
//!   `verify_internal` on the same code paths that production
//!   calls will use.
//!
//! # Sensitive security parameters
//!
//! - **Private key `d`** (`[u8; 32]` for P-256, `[u8; 48]` for
//!   P-384) — CSP. Consumed by `derive_public_key` / `sign_with_k`;
//!   not retained beyond the call.
//! - **Per-signature nonce `k`** — CSP. In the DRBG-backed sign
//!   wrapper, `k` is sampled fresh on every call by the FIPS 186-5
//!   §A.2.2 rejection sampler; in `sign_with_k` the caller supplies
//!   `k` and is responsible for unpredictability and single-use
//!   discipline. Reuse under the same key reveals `d`.
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
//! [`oxicrypt_module::require_operational`]; the `*_internal` helpers
//! skip the gate so that self-tests can run during `SelfTest`.
#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::KatEntry;

pub mod p256_ecdsa;
pub mod p256_field;
pub mod p256_keygen;
pub mod p256_point;
pub mod p256_scalar;
pub mod p384_field;
pub mod p384_point;
pub mod p384_ecdsa;
pub mod p384_keygen;
pub mod p384_scalar;
pub mod p384_stub;

// ── Crate-root re-exports ────────────────────────────────────────
//
// The P-256 ECDSA public API lives in `p256_ecdsa`; re-export the
// items an agent or developer reaches for first so that
// `use oxicrypt_ecdsa::{EcdsaP256PrivateKey, verify}` works.

pub use p256_ecdsa::{
    derive_public_key, sign_with_k, verify, EcdsaP256PrivateKey, PRIVATE_KEY_LEN,
    PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

/// Power-up KATs exported by this crate.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "ECDSA-P256 KAT (sign+verify round-trip, FIPS 186-5)",
        run: p256_ecdsa::self_test,
    },
    KatEntry {
        name: "ECDSA-P384 KAT (sign+verify round-trip, FIPS 186-5)",
        run: p384_ecdsa::self_test,
    },
];
