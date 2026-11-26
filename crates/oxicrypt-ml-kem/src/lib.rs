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
//! (`ml_kem_impl!`) instantiated in
//! [`ml_kem_512`], [`ml_kem_768`], and [`ml_kem_1024`]. The shared
//! base modules (`encode`, `field`, `ntt`, `poly`, `sample`)
//! are K-independent; the K-dependent `PolyVec` / `PolyMatrix` types
//! and the K-PKE + KEM implementations are emitted per-variant inside
//! each module.
//!
//! # Approved services
//!
//! | Service | Description | CNSA-1.0 | CNSA-2.0 | Migration |
//! |---------|-------------|----------|----------|-----------|
//! | `MlKem512Keygen` / `ExpandKey` / `Encaps` / `Decaps` | ML-KEM-512 | No | No | No |
//! | `MlKem768Keygen` / `ExpandKey` / `Encaps` / `Decaps` | ML-KEM-768 | No | No | No |
//! | `MlKem1024Keygen` / `ExpandKey` / `Encaps` / `Decaps` | ML-KEM-1024 | No | Yes | Yes |
//!
//! `Keygen` covers `keygen` and `keygen_with_seed`, which draw d and then z
//! from an RBG the caller passes (FIPS 203 Algorithm 19); `ExpandKey`
//! covers `expand_key`, which expands a stored `(d, z)`; `Encaps` covers
//! `encapsulate`, which draws m from an RBG the caller passes (FIPS 203
//! Algorithm 20), and `check_encapsulation_key`; `Decaps` covers
//! `decapsulate` and `check_decapsulation_key`. `keygen`,
//! `keygen_with_seed` and `encapsulate` refuse an RBG below the parameter
//! set's strength before any draw: 128 bits for ML-KEM-512, 192 for
//! ML-KEM-768, 256 for ML-KEM-1024 (FIPS 203 §3.3).
//! The three key-generation functions run a pairwise consistency test on
//! the pair before returning it (FIPS 140-3 IG 10.3.A); a failure wipes the
//! pair, returns `Error::ConditionalTestFailed` with the reason
//! `"ML-KEM-NNN pairwise consistency"`, and puts the module in its error
//! state.
//!
//! `encapsulate` runs the FIPS 203 §7.2 encapsulation key check (the length
//! by the argument's type, and every 12-bit value of the encoded vector
//! below q) before the strength check and before any draw; `decapsulate`
//! runs the FIPS 203 §7.3 decapsulation input check (the key and ciphertext
//! lengths by the arguments' types, and the stored H(ek) equal to H of the
//! stored ek) before any computation on the ciphertext. A key that fails
//! is refused with `Error::InvalidInput`; a ciphertext that does not match
//! the key is never an error. `check_encapsulation_key` and
//! `check_decapsulation_key` run the same checks on their own under the
//! `Encaps` and `Decaps` services and return `Ok(false)` for a failing key.
//!
//! ML-KEM-512 and ML-KEM-768 are permitted only under the
//! [`AlgorithmProfile::Unrestricted`](oxicrypt_module::AlgorithmProfile)
//! profile. ML-KEM-1024 is the CNSA 2.0 baseline. CNSSP-15 (October
//! 2016) names no post-quantum algorithm, so CNSA 1.0 refuses it; a
//! deployment running classical and post-quantum side by side selects
//! `Migration`.
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
//! [`KATS`] holds the power-up cryptographic algorithm self-tests
//! required by FIPS 140-3 IG 10.3.A item 14, each a known-answer test
//! against a NIST ACVP-Server vector: key generation compared to the
//! expected decapsulation key, encapsulation compared to the expected
//! ciphertext and shared secret, and decapsulation of a valid and of a
//! modified ciphertext compared to the expected shared secret, which
//! covers the implicit-rejection path. They run on ML-KEM-1024, approved
//! under the CNSA 2.0, Migration and Unrestricted profiles, so the
//! self-tested set is one that CNSA 2.0 uses; all three parameter sets
//! share one implementation through the `ml_kem_impl!` macro.
//!
//! # Crate-root re-exports
//!
//! The crate root re-exports the ML-KEM-1024 surface
//! ([`keygen`], [`keygen_with_seed`], [`expand_key`], [`encapsulate`],
//! [`decapsulate`], [`check_encapsulation_key`],
//! [`check_decapsulation_key`], [`EK_LEN`], [`DK_LEN`], [`CT_LEN`],
//! [`SEED_LEN`], [`SHARED_SECRET_LEN`], and with the `testing-interfaces`
//! feature `keygen_internal`, `encaps_internal` and `decaps_internal`), so
//! `oxicrypt_ml_kem::keygen` and the rest resolve to ML-KEM-1024. Callers
//! that need another set name [`ml_kem_512`] or [`ml_kem_768`].
//!
//! # The `testing-interfaces` feature (default OFF)
//!
//! FIPS 203 §3.3 restricts the internal key generation, encapsulation and
//! decapsulation interfaces to CAVP testing, so `keygen_internal`,
//! `encaps_internal` and `decaps_internal` of every parameter set are
//! compiled only with the `testing-interfaces` feature, which no shipped
//! build enables. Without the feature, naming any of them does not
//! compile:
//!
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_512::keygen_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_512::encaps_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_512::decaps_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_768::keygen_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_768::encaps_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_768::decaps_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_1024::keygen_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_1024::encaps_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::ml_kem_1024::decaps_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::keygen_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::encaps_internal;
//! ```
//! ```compile_fail,E0425
//! let _ = oxicrypt_ml_kem::decaps_internal;
//! ```
//!
//! # Sensitive security parameters
//!
//! | SSP | Description | Zeroization |
//! |-----|-------------|-------------|
//! | dk  | Decapsulation key (per-variant length) | Module copies wiped on every exit; the returned key is the caller's |
//! | d, z | Key-generation seeds (32 bytes each) | Drawn inside the module and wiped on every exit; returned by `keygen_with_seed` as d ‖ z in a `Zeroizing` that wipes it on drop; the caller's `expand_key` arguments are the caller's to wipe |
//! | m   | Encapsulation randomness (32 bytes) | Drawn inside the module and wiped on every exit |
//! | σ, ρ ‖ σ, d ‖ k | Key-generation intermediates | Wiped on every exit |
//! | K, r, K ‖ r (encaps) | Shared secret and encryption randomness | Wiped on every exit; the returned shared secret is the caller's |
//! | m′, K′, r′, K′ ‖ r′, K̄, c′ (decaps) | Decapsulation intermediates | Wiped on every exit |
//! | PRF output | Noise-sampling input | Wiped on every exit |
//! | s, e, t̂, Â, y, e₁, e₂, u, v, μ, u′, v′, ŝ, w | Polynomial intermediates of K-PKE | Wiped on every exit |
//!
//! Each byte buffer above is held in a wrapper that zeroizes it with
//! `oxicrypt_zeroize::zeroize` when dropped, and every polynomial is
//! zeroized with `oxicrypt_zeroize::zeroize_i16` when dropped, so an early
//! return wipes them too. A value moved out of a frame can leave a bitwise
//! copy in the dead frame. Zeroising temporary SSPs when they are no longer
//! needed is AS09.32 (ISO/IEC 19790:2012 §7.9.7), which applies at Levels 2
//! and above; this module targets Level 1 and wipes regardless.
//!
//! # The `fault-injection` feature (default OFF)
//!
//! Compiles the `seam` module, whose `corrupt_next_dk` makes the next key
//! generation's pairwise consistency test fail, for the tests of that
//! failure path. No shipped build enables it.
//!
//! # FIPS module gating
//!
//! Public entry points (`keygen`, `keygen_with_seed`, `expand_key`,
//! `encapsulate`, `decapsulate`, `check_encapsulation_key`,
//! `check_decapsulation_key` per variant) gate on
//! [`oxicrypt_module::require_operational`] and
//! [`oxicrypt_module::require_allowed`]. The `*_internal` surface
//! (hidden, `testing-interfaces` only) runs without the operational gate:
//! it calls [`oxicrypt_module::require_self_test_started`] instead, so it
//! refuses in every state other than `SelfTest` and `Operational`. The
//! power-up self-tests reach the same guarded cores without the feature.
//!
//! # Constant-time behaviour
//!
//! The FO transform's decapsulation selects between the candidate and
//! the rejection key with `ct_bytes_eq` and `ct_select_32`. Both
//! are branchless masked operations, so the running time and memory
//! access pattern do not depend on the compared values.
//! NTT operations have data-independent control flow.
//!
//! The FIPS 203 §7.2 modulus check reads every 12-bit value of the
//! encoded vector and accumulates its verdict with masks, with no branch
//! or early exit on any value. The §7.3 hash check compares the recomputed
//! and the stored H(ek) with `ct_bytes_eq` over all 32 bytes.
//!
//! # Data-parallel matrix expansion (`parallel` feature, default OFF)
//!
//! The optional `parallel` feature parallelizes the public-matrix
//! expansion `expand_a`: the k × k matrix Â is built by forking its
//! *rows* across a `rayon` parallel iterator. Each cell Â`i``j` is a
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

mod cast;
mod cast_vectors;
mod encode;
mod field;
pub(crate) mod ml_kem_impl;
mod ntt;
/// Shared parameter constants common across all three ML-KEM variants.
pub mod params;
mod poly;
mod sample;
/// Test seams for the key-generation services; available with the
/// `fault-injection` feature or in the crate's own tests.
#[cfg(any(test, feature = "fault-injection"))]
pub mod seam;
#[cfg(feature = "parallel")]
mod sweep;
mod wipe;

/// ML-KEM-512 instantiation (FIPS 203 Table 2: k=2, η₁=3, η₂=2, dᵤ=10, dᵥ=4).
pub mod ml_kem_512;

/// ML-KEM-768 instantiation (FIPS 203 Table 2: k=3, η₁=η₂=2, dᵤ=10, dᵥ=4).
pub mod ml_kem_768;

/// ML-KEM-1024 instantiation (FIPS 203 Table 2: k=4, η₁=η₂=2, dᵤ=11, dᵥ=5).
pub mod ml_kem_1024;

pub use ml_kem_1024::{
    CT_LEN, DK_LEN, EK_LEN, SEED_LEN, SHARED_SECRET_LEN, check_decapsulation_key,
    check_encapsulation_key, decapsulate, encapsulate, expand_key, keygen, keygen_with_seed,
};
#[cfg(feature = "testing-interfaces")]
pub use ml_kem_1024::{decaps_internal, encaps_internal, keygen_internal};

pub use cast::KATS;

/// What the last `Drop` of a polynomial on this thread left in its
/// coefficients, read by the drop itself while the polynomial is still
/// owned. Reading the memory after the drop would need `unsafe` and would
/// be a read of freed storage; this observes the same fact soundly.
#[cfg(test)]
mod wipe_witness {
    extern crate std;

    std::thread_local! {
        static LAST: core::cell::Cell<Option<bool>> = const { core::cell::Cell::new(None) };
        static COUNTS: core::cell::Cell<(u64, u64)> = const { core::cell::Cell::new((0, 0)) };
    }

    pub(crate) fn record(zeroed: bool) {
        LAST.with(|c| c.set(Some(zeroed)));
        COUNTS.with(|c| {
            let (drops, unzeroed) = c.get();
            c.set((
                drops.saturating_add(1),
                unzeroed.saturating_add(u64::from(!zeroed)),
            ));
        });
    }

    /// The drops recorded on this thread so far, and how many of them left
    /// a nonzero coefficient.
    #[cfg(feature = "fault-injection")]
    pub(crate) fn counts() -> (u64, u64) {
        COUNTS.with(core::cell::Cell::get)
    }

    /// `Some(true)` when the last drop left its coefficients all zero.
    pub(crate) fn take() -> Option<bool> {
        LAST.with(core::cell::Cell::take)
    }
}

#[cfg(test)]
mod wiped_tests {
    use super::wipe_witness;

    /// Dropping a polynomial that holds coefficients leaves it all zero.
    #[test]
    fn dropping_a_polynomial_zeroes_it() {
        let _ = wipe_witness::take();
        let mut p = crate::poly::Poly::zero();
        p.coeffs = [0x0123; crate::params::N];
        drop(p);
        assert_eq!(wipe_witness::take(), Some(true));
        // Control: nothing dropped, nothing recorded.
        assert_eq!(wipe_witness::take(), None);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use oxicrypt_module::{KatEntry, initialize_with_tests, require_self_test_started};

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// Brings the module out of `PowerOff` so that a test can call the
    /// `*_internal` functions, which refuse until the self-tests have
    /// started. A second call in the same process is a no-op.
    pub(crate) fn start_module() {
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
        assert_eq!(require_self_test_started(), Ok(()));
    }
}
