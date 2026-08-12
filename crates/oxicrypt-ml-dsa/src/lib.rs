//! ML-DSA (FIPS 204) — lattice-based digital signature algorithm.
//!
//! # Status
//!
//! **Implemented for all three parameter sets.** This crate provides
//! ML-DSA-44, ML-DSA-65, and ML-DSA-87 as specified in FIPS 204
//! (August 2024): key generation, deterministic signing (Fiat-Shamir
//! with aborts / rejection sampling), and signature verification.
//!
//! Every parameter set is generated from a single declarative macro
//! ([`ml_dsa_impl!`](crate::ml_dsa_impl::ml_dsa_impl)) instantiated in
//! [`ml_dsa_44`], [`ml_dsa_65`], and [`ml_dsa_87`]. The shared base
//! modules ([`field`], [`ntt`], [`poly`] (single-poly), [`params`]
//! (universal constants)) are K/L-independent; the K/L-dependent
//! `PolyVecK`/`PolyVecL` types, `Decompose`/`UseHint`/`pack_w1` rounding
//! family, byte encoders, samplers (`ExpandA`/`ExpandS`/`ExpandMask`),
//! and the FIPS 204 §6 internal primitives are emitted per-variant
//! inside each module.
//!
//! # Approved services
//!
//! | Service | Description | CNSA-1.0 | CNSA-2.0 |
//! |---------|-------------|----------|----------|
//! | `MlDsa44Keygen` / `Sign` / `Verify` | ML-DSA-44 | No | No |
//! | `MlDsa65Keygen` / `Sign` / `Verify` | ML-DSA-65 | No | No |
//! | `MlDsa87Keygen` / `Sign` / `Verify` | ML-DSA-87 | No | Yes (mandate) |
//!
//! ML-DSA-44 and ML-DSA-65 are permitted only under the
//! [`AlgorithmProfile::Unrestricted`](oxicrypt_module::AlgorithmProfile)
//! profile. ML-DSA-87 is the CNSA 2.0 digital-signature mandate
//! (CNSSP 15) and is also allowed in `Cnsa2`.
//!
//! # Parameter sets (FIPS 204 §4, Tables 1 and 2)
//!
//! | Variant | λ | τ | γ₁ | γ₂ | k | ℓ | η | β | ω | PK_LEN | SK_LEN | SIG_LEN |
//! |---------|---|---|----|----|---|---|---|---|---|--------|--------|---------|
//! | ML-DSA-44 | 128 | 39 | 2¹⁷ | (q−1)/88 | 4 | 4 | 2 | 78 | 80 | 1312 | 2560 | 2420 |
//! | ML-DSA-65 | 192 | 49 | 2¹⁹ | (q−1)/32 | 6 | 5 | 4 | 196 | 55 | 1952 | 4032 | 3309 |
//! | ML-DSA-87 | 256 | 60 | 2¹⁹ | (q−1)/32 | 8 | 7 | 2 | 120 | 75 | 2592 | 4896 | 4627 |
//!
//! Common across all variants: N = 256, q = 8 380 417, d = 13,
//! seed length = 32 B.
//!
//! # Power-up self-tests
//!
//! [`KATS`] aggregates the per-variant power-up KATs (one entry per
//! parameter set; each runs a deterministic keygen → sign → verify
//! round-trip plus a wrong-message + tampered-signature negative
//! oracle).
//!
//! # Backward compatibility
//!
//! The crate root re-exports the ML-DSA-87 surface ([`keygen`],
//! [`sign`], [`verify`], [`keygen_internal`], [`sign_internal`],
//! [`verify_internal`], [`PK_LEN`], [`SK_LEN`], [`SIG_LEN`]) so
//! existing callers (acvp-harness, oxicrypt-ffi, nist KAT tests)
//! continue to resolve `oxicrypt_ml_dsa::keygen` et al. to ML-DSA-87
//! without renames. New callers should reach for [`ml_dsa_44`],
//! [`ml_dsa_65`], or [`ml_dsa_87`] explicitly to disambiguate.
//!
//! # Sensitive security parameters
//!
//! | SSP | Description | Zeroization |
//! |-----|-------------|-------------|
//! | sk  | Secret key (per-variant length) | Caller responsibility |
//! | ξ   | Keygen randomness (32 bytes) | Caller responsibility |
//! | s₁, s₂ | Secret vectors | Embedded in sk |
//! | K   | Signing key seed (32 bytes) | Embedded in sk |
//!
//! # External vs internal API
//!
//! The public [`sign`] and [`verify`] functions of each variant
//! implement the **external** ML-DSA.Sign / ML-DSA.Verify API
//! defined in FIPS 204 §5.2 and §5.3 (Algorithms 2 and 3): they accept a
//! `ctx` byte string and frame the message as
//! `M' = 0x00 || |ctx| || ctx || M` before invoking the internal
//! primitive. This is the shape consumed by X.509, CMS, the LAMPS
//! profile, OpenSSL 3.5, and any other spec-conformant caller —
//! `ctx` is `b""` for those use cases.
//!
//! The `*_internal` surface ([`sign_internal`], [`verify_internal`])
//! exposes Algorithms 7 and 8 directly — the raw-message primitive
//! with no framing. These are `#[doc(hidden)]` and intended for
//! FIPS 204 CAVP / ACVP test harnesses that exercise the internal
//! primitive.
//!
//! # FIPS module gating
//!
//! Public entry points (`keygen`, `sign`, `verify` per variant) gate
//! on [`oxicrypt_module::require_operational`] and
//! [`oxicrypt_module::require_allowed`]. The `*_internal` surface
//! (hidden) runs gate-free so power-up KATs can execute during
//! `SelfTest`.
//!
//! # Timing properties
//!
//! The signing rejection loop iteration count leaks information
//! about the secret key; this is a known and accepted property of
//! Fiat-Shamir with aborts, which is inherent to the ML-DSA signing
//! algorithm of FIPS 204 §6.2.
//! Within each iteration, the norm checks return on the first
//! out-of-bound coefficient, so their duration depends on where the
//! bound is first exceeded. NTT operations have data-independent
//! control flow.
//!
//! # Data-parallel matrix expansion (`parallel` feature, default OFF)
//!
//! The optional `parallel` feature parallelizes the public-matrix
//! expansion `expand_a`: the k × ℓ matrix A is built by forking its
//! *rows* across a `rayon` parallel iterator. Each cell A[i][j] is a
//! pure function of ρ plus the cell's (i, j) indices — sampled from a
//! fresh local SHAKE-128 XOF with no shared mutable state — and each
//! row is written by exactly one closure, then recombined by position
//! (never by completion order). The parallel output is therefore
//! byte-identical to the sequential build, which the keygen KATs
//! (fixed ξ → fixed ρ → fixed A → fixed pk/sk) confirm with the
//! feature ON. The feature pulls in `rayon` (hence `std`), so the
//! crate is `#![no_std]` only when the feature is OFF; the default
//! build graph contains no `rayon` and is the CMVP validation-target
//! single-threaded configuration. `parallel` is a throughput option,
//! not part of that configuration.

#![cfg_attr(not(feature = "parallel"), no_std)]
#![forbid(unsafe_code)]

mod field;
pub(crate) mod ml_dsa_impl;
mod ntt;
/// Shared parameter constants common across all three ML-DSA variants.
pub mod params;
mod poly;

use oxicrypt_module::Error;

/// ML-DSA-44 instantiation (λ=128, τ=39, γ₁=2¹⁷, γ₂=(q−1)/88, k=4,
/// ℓ=4, η=2, β=78, ω=80).
pub mod ml_dsa_44;

/// ML-DSA-65 instantiation (λ=192, τ=49, γ₁=2¹⁹, γ₂=(q−1)/32, k=6,
/// ℓ=5, η=4, β=196, ω=55).
pub mod ml_dsa_65;

/// ML-DSA-87 instantiation (λ=256, τ=60, γ₁=2¹⁹, γ₂=(q−1)/32, k=8,
/// ℓ=7, η=2, β=120, ω=75).
pub mod ml_dsa_87;

// ── Backward-compat re-export of ML-DSA-87 surface ──────────────────
//
// Existing callers (acvp-harness, oxicrypt-ffi, oxicrypt-ml-dsa's own
// `tests/nist_kat.rs`) use the crate root (`oxicrypt_ml_dsa::keygen`,
// `oxicrypt_ml_dsa::SK_LEN`, etc.). Preserving the unqualified path
// keeps the ACVTS-session-727840/727841/727843 replays byte-identical
// and avoids a downstream churn cycle.
pub use ml_dsa_87::{
    PK_LEN, SIG_LEN, SK_LEN, keygen, keygen_internal, sign, sign_internal, verify, verify_internal,
};

// ── External-API ctx-framing helper (shared across all variants) ────

/// Maximum size of the external API framing prefix: 2 header bytes
/// (`0x00` domain separator + `|ctx|` length byte) plus the 255-byte
/// ctx cap from FIPS 204 §5.2.
const EXT_PREFIX_MAX: usize = 2 + 255;

/// Stack-allocated `0x00 || |ctx| || ctx` buffer for the external
/// ML-DSA.{Sign,Verify} framing. Keeps the crate free of heap
/// allocation while supporting the full FIPS 204 §5.2 ctx range.
pub(crate) struct ExternalPrefix {
    buf: [u8; EXT_PREFIX_MAX],
    len: usize,
}

impl ExternalPrefix {
    // Range slice is sound by construction: `len` is written exactly
    // once by `build_external_prefix` as `2 + ctx.len()` with
    // `ctx.len() ≤ 255`, so `len ≤ EXT_PREFIX_MAX`.
    #[allow(clippy::indexing_slicing)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

// Arithmetic and slicing are sound by construction: the early-return
// on `ctx.len() > 255` establishes `2 + ctx.len() ≤ EXT_PREFIX_MAX`,
// so the following index operations cannot overflow or panic.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]
pub(crate) fn build_external_prefix(ctx: &[u8]) -> Result<ExternalPrefix, Error> {
    if ctx.len() > 255 {
        return Err(Error::InvalidInput);
    }
    let mut buf = [0u8; EXT_PREFIX_MAX];
    buf[0] = 0x00; // pure ML-DSA (HashML-DSA would use 0x01)
    buf[1] = ctx.len() as u8;
    buf[2..2 + ctx.len()].copy_from_slice(ctx);
    Ok(ExternalPrefix {
        buf,
        len: 2 + ctx.len(),
    })
}

// ── KATS aggregate ───────────────────────────────────────────────────

use oxicrypt_module::KatEntry;

/// Power-up KATs aggregated across all three ML-DSA parameter sets.
///
/// Each entry runs a deterministic keygen → sign → verify round-trip
/// plus wrong-message + tampered-signature negative oracles for its
/// variant. The aggregated slice is what `oxicrypt-integrity`
/// registers with [`oxicrypt_module::initialize_with_tests`].
pub const KATS: &[KatEntry] = &[
    ml_dsa_44::KAT_ENTRY,
    ml_dsa_65::KAT_ENTRY,
    ml_dsa_87::KAT_ENTRY,
];

// ── Crate-internal tests (NTT roundtrip / field arithmetic) ──────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
mod internal_tests {
    use crate::field::{fqmul, montgomery_reduce, reduce32, to_mont};
    use crate::ntt;
    use crate::params::N;

    #[test]
    fn montgomery_to_mont_gives_r_mod_q() {
        let r_mod_q = reduce32(to_mont(1));
        assert_eq!(r_mod_q, 4193792); // R mod q = 2^32 mod 8380417
    }

    #[test]
    fn montgomery_fqmul_by_r_is_identity() {
        let r_mod_q = reduce32(to_mont(1));
        assert_eq!(reduce32(fqmul(12345, r_mod_q)), 12345);
    }

    #[test]
    fn montgomery_reduce_a_times_r() {
        let r = montgomery_reduce(42 * (1i64 << 32));
        assert_eq!(reduce32(r), 42);
    }

    #[test]
    fn ntt_pointwise_roundtrip() {
        let mut p = [0i32; N];
        for (i, coeff) in p.iter_mut().enumerate() {
            *coeff = i as i32;
        }
        let original = p;

        let mut one = [0i32; N];
        one[0] = 1;
        ntt::ntt(&mut one);

        ntt::ntt(&mut p);
        let mut result = [0i32; N];
        ntt::pointwise_mul(&mut result, &p, &one);
        ntt::inv_ntt(&mut result);

        for i in 0..N {
            assert_eq!(reduce32(result[i]), original[i], "roundtrip failed at {i}");
        }
    }
}
