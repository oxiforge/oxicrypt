//! EdDSA (Ed25519, Ed448) per FIPS 186-5.
//!
//! # Approved services
//!
//! | Service | Function | Standard |
//! |---|---|---|
//! | Ed25519 key generation | [`ed25519::Ed25519PrivateKey::generate`] | RFC 8032 §5.1.5, FIPS 186-5 §7.8 |
//! | Ed25519 key import from seed | [`ed25519::Ed25519PrivateKey::from_seed`] | RFC 8032 §5.1.5 |
//! | Ed25519 sign | [`ed25519::Ed25519PrivateKey::sign`] / [`ed25519::sign`] | RFC 8032 §5.1.6, FIPS 186-5 §7.8 |
//! | Ed25519 verify | [`ed25519::verify`] | RFC 8032 §5.1.7, FIPS 186-5 §7.8 |
//!
//! Ed25519 is deterministic: the per-signature nonce `r` is derived as
//! `SHA-512(prefix || M) mod L`, so no DRBG draw is required at sign
//! time and a whole class of randomness-reuse side channels against
//! randomized ECDSA does not apply here. The verify equation is the
//! non-cofactored `[S]B = R + [k]A`, gated by an RFC 8032 §5.1.7
//! canonical-`S` check that rejects the known signature-malleability
//! form.
//!
//! # Module layout
//!
//!   * [`field`] — arithmetic in GF(2^255 - 19), the base field of
//!     edwards25519. Five-limb radix-2^51 representation,
//!     constant-time, `no_std`.
//!   * [`scalar`] — 256-bit integers and the `Scalar` type, the
//!     RFC 8032 §5.1.7 canonical-encoding check used by signature
//!     verification, and the Barrett reduction primitives
//!     `reduce_wide` / `muladd` needed for `SHA-512(…) mod L` and
//!     for the `r + k · s` signing equation.
//!   * [`edwards`] — point arithmetic on edwards25519 in extended
//!     twisted-Edwards coordinates: point type, base point,
//!     complete addition, dedicated doubling, and fixed-window
//!     scalar multiplication.
//!   * [`ed25519`] — the RFC 8032 §5.1 keygen / sign / verify
//!     primitives and the [`ed25519::Ed25519PrivateKey`] handle.
//!
//! # Self-tests
//!
//! [`ed25519::self_test`] is called at module power-up and executes
//! the RFC 8032 §7.1 TEST 1 known-answer vector through both the
//! low-level [`ed25519::keygen`] / [`ed25519::sign`] / [`ed25519::verify`]
//! primitives and the [`ed25519::Ed25519PrivateKey`] handle path,
//! including the handle's IG 10.3.A PCT.
//!
//! # Sensitive security parameters (SSPs)
//!
//! The 32-byte Ed25519 seed is the only long-lived SSP in this crate.
//! It never leaves [`ed25519::Ed25519PrivateKey`] except through the
//! explicit [`ed25519::Ed25519PrivateKey::seed`] accessor, which is
//! provided only for key-export scenarios the caller controls.
//!
//! # Conditional self-tests
//!
//! Every [`ed25519::Ed25519PrivateKey`] — whether produced by
//! [`ed25519::Ed25519PrivateKey::generate`] or
//! [`ed25519::Ed25519PrivateKey::from_seed`] — runs an IG 10.3.A
//! pairwise consistency test before it escapes construction: a fixed
//! probe message is signed with the candidate seed and the resulting
//! signature is verified against the derived public key. Any
//! inconsistency causes construction to fail with
//! `Error::InvalidInput` and no SSP material escapes.
//!
//! # Side-channel posture
//!
//! See `docs/security-policy/security-policy.md` §12.1 for the full
//! disclosure. The secret-dependent scalar mult on the base point is
//! covered by the `eddsa_ed25519_scalar_mul` target in
//! `tools/ct-validation`; that harness holds its own measurements.
//!
//! Ed448 is deferred.
#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::KatEntry;

pub mod ed25519;
pub mod edwards;
pub mod field;
pub mod scalar;

// ── Crate-root re-exports ────────────────────────────────────────
//
// Re-export the Ed25519 public API at the crate root so agents
// can write `use oxicrypt_eddsa::{Ed25519PrivateKey, verify}`
// without navigating into the `ed25519` submodule.

pub use ed25519::{
    Ed25519PrivateKey, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN, keygen, sign, verify,
};

/// Power-up KATs exported by this crate.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "Ed25519 KAT (keygen+sign+verify round-trip, RFC 8032)",
    run: ed25519::self_test,
}];
