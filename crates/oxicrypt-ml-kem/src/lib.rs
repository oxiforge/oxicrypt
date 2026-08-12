//! ML-KEM (FIPS 203) — lattice-based key encapsulation mechanism.
//!
//! # Status
//!
//! **Implemented for all three parameter sets.** This crate provides
//! ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as specified in FIPS 203
//! (August 2024), including K-PKE key generation, encryption,
//! decryption, and the Fujisaki–Okamoto transform with constant-time
//! implicit rejection.
//!
//! Every parameter set is generated from a single declarative macro
//! ([`ml_kem_impl!`](crate::ml_kem_impl::ml_kem_impl)) instantiated in
//! [`ml_kem_512`], [`ml_kem_768`], and [`ml_kem_1024`]. The shared
//! base modules ([`encode`], [`field`], [`ntt`], [`poly`], [`sample`])
//! are K-independent; the K-dependent `PolyVec` / `PolyMatrix` types
//! and the K-PKE + KEM implementations are emitted per-variant inside
//! each module.
//!
//! # Approved services
//!
//! | Service | Description | CNSA-1.0 | CNSA-2.0 |
//! |---------|-------------|----------|----------|
//! | `MlKem512Keygen` / `Encaps` / `Decaps` | ML-KEM-512 | No | No |
//! | `MlKem768Keygen` / `Encaps` / `Decaps` | ML-KEM-768 | No | No |
//! | `MlKem1024Keygen` / `Encaps` / `Decaps` | ML-KEM-1024 | Yes (transition) | Yes (core) |
//!
//! ML-KEM-512 and ML-KEM-768 are permitted only under the
//! [`AlgorithmProfile::Unrestricted`](oxicrypt_module::AlgorithmProfile)
//! profile. ML-KEM-1024 is the CNSA 2.0 baseline and is also allowed
//! in CNSA 1.0 for hybrid use during the transition period.
//!
//! # Parameter sets (FIPS 203 Tables 2 and 3)
//!
//! | Variant | k | η₁ | η₂ | dᵤ | dᵥ | EK_LEN | DK_LEN | CT_LEN |
//! |---------|---|----|----|----|----|--------|--------|--------|
//! | ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 800 | 1632 | 768 |
//! | ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 1184 | 2400 | 1088 |
//! | ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 | 3168 | 1568 |
//!
//! Common across all variants: N = 256, q = 3329, shared secret = 32 B,
//! seed length = 32 B, ByteEncode_12 polynomial = 384 B.
//!
//! # Power-up self-tests
//!
//! [`KATS`] aggregates the per-variant power-up KATs (one entry per
//! parameter set, each running a deterministic round-trip plus an
//! implicit-rejection negative test).
//!
//! # Backward compatibility
//!
//! The crate root re-exports the ML-KEM-1024 surface
//! ([`keygen`], [`encapsulate`], [`decapsulate`], [`EK_LEN`],
//! [`DK_LEN`], [`CT_LEN`], [`SEED_LEN`], [`SHARED_SECRET_LEN`],
//! [`keygen_internal`], [`encaps_internal`], [`decaps_internal`]) so
//! existing callers (acvp-harness, oxicrypt-ffi, oxicrypt-integrity
//! self-test driver) continue to resolve `oxicrypt_ml_kem::keygen`
//! et al. to ML-KEM-1024 without renames. New callers should reach
//! for [`ml_kem_512`], [`ml_kem_768`], or [`ml_kem_1024`] explicitly
//! to disambiguate.
//!
//! # Sensitive security parameters
//!
//! | SSP | Description | Zeroization |
//! |-----|-------------|-------------|
//! | dk  | Decapsulation key (per-variant length) | Caller responsibility |
//! | m   | Encapsulation randomness (32 bytes) | Caller responsibility |
//! | d   | Keygen randomness (32 bytes) | Caller responsibility |
//! | z   | Implicit-rejection seed (32 bytes) | Embedded in dk |
//! | K (encaps) | Shared secret stack local in `ml_kem_encaps` | Module — volatile zeroize on function exit |
//! | r (encaps) | Re-encryption randomness stack local in `ml_kem_encaps` | Module — volatile zeroize on function exit |
//! | m' (decaps) | Re-encryption-input random stack local in `ml_kem_decaps` | Module — volatile zeroize on function exit |
//! | K' (decaps) | Candidate shared-secret stack local in `ml_kem_decaps` | Module — volatile zeroize on function exit |
//! | K̄ (decaps) | Implicit-rejection fallback shared-secret stack local | Module — volatile zeroize on function exit |
//!
//! Intermediate-state CSPs that live in stack-locals inside the FO
//! transform are wiped via `oxicrypt_zeroize::zeroize` on function
//! exit (FIPS 140-3 IG 7.7 / SP 800-140B §7.9). Because every
//! parameter set is generated from the same `ml_kem_impl!` macro
//! body, the zeroize-completeness invariant is audited once and
//! holds uniformly across ML-KEM-512, -768, and -1024.
//!
//! # FIPS module gating
//!
//! Public entry points (`keygen`, `encapsulate`, `decapsulate` per
//! variant) gate on [`oxicrypt_module::require_operational`] and
//! [`oxicrypt_module::require_allowed`]. The `*_internal` surface
//! (hidden) runs gate-free so power-up KATs can execute during
//! `SelfTest`.
//!
//! # Constant-time behaviour
//!
//! The FO transform's decapsulation selects between the candidate and
//! the rejection key with `ct_bytes_eq` and `ct_select_32`. Both
//! are branchless masked operations, so the running time and memory
//! access pattern do not depend on the compared values.
//! NTT operations have data-independent control flow.
//!
//! # Data-parallel matrix expansion (`parallel` feature, default OFF)
//!
//! The optional `parallel` feature parallelizes the public-matrix
//! expansion `expand_a`: the k × k matrix Â is built by forking its
//! *rows* across a `rayon` parallel iterator. Each cell Â[i][j] is a
//! pure function of ρ plus the cell's (i, j) indices — sampled from a
//! fresh local SHAKE-128 XOF with no shared mutable state — and each
//! row is written by exactly one closure, then recombined by position
//! (never by completion order). The parallel output is therefore
//! byte-identical to the sequential build, which the keygen KATs
//! (fixed ρ → fixed Â → fixed ek/dk) confirm with the feature ON. The
//! feature pulls in `rayon` (hence `std`), so the crate is
//! `#![no_std]` only when the feature is OFF; the default build graph
//! contains no `rayon` and is the CMVP validation-target single-threaded
//! configuration. `parallel` is a throughput option, not part of that
//! configuration.

#![cfg_attr(not(feature = "parallel"), no_std)]
#![forbid(unsafe_code)]

mod encode;
mod field;
pub(crate) mod ml_kem_impl;
mod ntt;
/// Shared parameter constants common across all three ML-KEM variants.
pub mod params;
mod poly;
mod sample;

/// ML-KEM-512 instantiation (FIPS 203 Table 2: k=2, η₁=3, η₂=2, dᵤ=10, dᵥ=4).
pub mod ml_kem_512;

/// ML-KEM-768 instantiation (FIPS 203 Table 2: k=3, η₁=η₂=2, dᵤ=10, dᵥ=4).
pub mod ml_kem_768;

/// ML-KEM-1024 instantiation (FIPS 203 Table 2: k=4, η₁=η₂=2, dᵤ=11, dᵥ=5).
pub mod ml_kem_1024;

// ── Backward-compat re-export of ML-KEM-1024 surface ────────────────
//
// Existing callers (acvp-harness, oxicrypt-ffi) use the crate root
// (`oxicrypt_ml_kem::keygen`, `oxicrypt_ml_kem::EK_LEN`, etc.).
// Preserving the unqualified path keeps the ACVTS-session-727796
// replay byte-identical and avoids a downstream churn cycle.
pub use ml_kem_1024::{
    CT_LEN, DK_LEN, EK_LEN, SEED_LEN, SHARED_SECRET_LEN, decaps_internal, decapsulate,
    encaps_internal, encapsulate, keygen, keygen_internal,
};

use oxicrypt_module::KatEntry;

/// Power-up KATs aggregated across all three ML-KEM parameter sets.
///
/// Each entry runs a deterministic round-trip plus an implicit-
/// rejection negative test for its variant. The aggregated slice is
/// what `oxicrypt-integrity` registers with
/// [`oxicrypt_module::initialize_with_tests`].
pub const KATS: &[KatEntry] = &[
    ml_kem_512::KAT_ENTRY,
    ml_kem_768::KAT_ENTRY,
    ml_kem_1024::KAT_ENTRY,
];
