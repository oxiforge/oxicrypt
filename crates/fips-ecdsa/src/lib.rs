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
//! Two entry points:
//!
//!   * [`p256_ecdsa::sign_with_k`] — raw primitive taking the per-
//!     signature nonce `k` as an explicit argument. This is the
//!     shape used by FIPS 186-5 / CAVP KATs that pin `k`, and by
//!     internal test code; it must never be called with a reused `k`.
//!   * [`p256_ecdsa::EcdsaP256PrivateKey::sign_sha256`] — DRBG-backed
//!     wrapper that samples a fresh `k` from an approved HMAC_DRBG
//!     on every call via the FIPS 186-5 §A.2.2 rejection sampler in
//!     [`p256_keygen`]. This is the path production code should use.
//!
//! RFC 6979 deterministic signing is deliberately **not** offered
//! here: FIPS 186-5 §6.4 mandates an approved RBG for `k`, and
//! operator discipline around `k` reuse is enforced by the
//! DRBG-backed wrapper taking ownership of the sampler.
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
//! - **Pairwise consistency test** (IG 10.3.A): every
//!   [`p256_ecdsa::EcdsaP256PrivateKey`] constructor (keygen or
//!   import) runs a sign-and-verify PCT against a fixed probe
//!   message using a freshly DRBG-sampled `k`; the derived public
//!   key must accept the probe signature or construction returns an
//!   error. This exercises the sampler, the sign primitive, and
//!   `verify_internal` on the same code paths that production calls
//!   will use.
//!
//! # Sensitive security parameters
//!
//! - **Private key `d`** (`[u8; 32]`) — CSP. Consumed by
//!   `derive_public_key` / `sign_with_k`; not retained beyond
//!   the call.
//! - **Per-signature nonce `k`** — CSP. In the DRBG-backed sign
//!   wrapper, `k` is sampled fresh on every call by the FIPS 186-5
//!   §A.2.2 rejection sampler; in [`p256_ecdsa::sign_with_k`] the
//!   caller supplies `k` and is responsible for unpredictability
//!   and single-use discipline. Reuse under the same key reveals `d`.
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
pub mod p256_keygen;
pub mod p256_point;
pub mod p256_scalar;
