//! SLH-DSA (FIPS 205) — stateless hash-based digital signature.
//!
//! # Status
//!
//! **12 of 12 FIPS 205 §11 parameter sets implemented** — the full
//! SHA-2 family (`SHA2-128s`, `SHA2-128f`, `SHA2-192s`, `SHA2-192f`,
//! `SHA2-256s`, `SHA2-256f`) and the full SHAKE family (`SHAKE-128s`,
//! `SHAKE-128f`, `SHAKE-192s`, `SHAKE-192f`, `SHAKE-256s`,
//! `SHAKE-256f`). Every parameter set is emitted from a single
//! declarative macro (`slh_dsa_impl!`) with a hash-family dispatch
//! layer (`__hash_family_setup!` + seven per-construct sub-macros)
//! and an `n`-keyed SHA-2 sub-macro (`__sha2_long_setup!`) — all
//! evaluated at macro-expansion time so each variant monomorphises
//! to one path with no runtime dispatch.
//!
//! The crate is structured so that each parameter set lives in its
//! own `pub mod slh_dsa_<family>_<level><s|f>` module — mirroring the
//! ML-DSA / ML-KEM expansion pattern (PR #74, PR #75). Shared base
//! modules (ADRS, tweakable hashes, WOTS+, FORS, XMSS, hyper-tree,
//! external API, KAT) are emitted **per-variant** by the macro so
//! every byte of parameter-set divergence has a single audit site
//! inside the macro body.
//!
//! # Approved services (per FIPS 205)
//!
//! Batch 3 keeps the three generic `SlhDsaKeygen` / `SlhDsaSign` /
//! `SlhDsaVerify` Service variants in place; Batch 4 will split them
//! into 36 variant-specific entries (12 paramSets × Keygen/Sign/Verify)
//! and tighten profile gating. Today, only `SHA2-256s` is approved
//! under the CNSA 2.0 profile (CNSSP 15 mandate); the other 11
//! variants are permitted under
//! [`AlgorithmProfile::Unrestricted`](oxicrypt_module::AlgorithmProfile)
//! only.
//!
//! # Parameter sets (FIPS 205 §11 Table 2)
//!
//! | Variant | n  | h  | d  | h' | a  | k  | w  | PK | SK  | SIG    |
//! |---------|----|----|----|----|----|----|----|----|-----|--------|
//! | SLH-DSA-SHA2-128s  | 16 | 63 | 7  | 9  | 12 | 14 | 16 | 32 | 64  | 7 856  |
//! | SLH-DSA-SHA2-128f  | 16 | 66 | 22 | 3  | 6  | 33 | 16 | 32 | 64  | 17 088 |
//! | SLH-DSA-SHA2-192s  | 24 | 63 | 7  | 9  | 14 | 17 | 16 | 48 | 96  | 16 224 |
//! | SLH-DSA-SHA2-192f  | 24 | 66 | 22 | 3  | 8  | 33 | 16 | 48 | 96  | 35 664 |
//! | SLH-DSA-SHA2-256s  | 32 | 64 | 8  | 8  | 14 | 22 | 16 | 64 | 128 | 29 792 |
//! | SLH-DSA-SHA2-256f  | 32 | 68 | 17 | 4  | 9  | 35 | 16 | 64 | 128 | 49 856 |
//! | SLH-DSA-SHAKE-128s | 16 | 63 | 7  | 9  | 12 | 14 | 16 | 32 | 64  | 7 856  |
//! | SLH-DSA-SHAKE-128f | 16 | 66 | 22 | 3  | 6  | 33 | 16 | 32 | 64  | 17 088 |
//! | SLH-DSA-SHAKE-192s | 24 | 63 | 7  | 9  | 14 | 17 | 16 | 48 | 96  | 16 224 |
//! | SLH-DSA-SHAKE-192f | 24 | 66 | 22 | 3  | 8  | 33 | 16 | 48 | 96  | 35 664 |
//! | SLH-DSA-SHAKE-256s | 32 | 64 | 8  | 8  | 14 | 22 | 16 | 64 | 128 | 29 792 |
//! | SLH-DSA-SHAKE-256f | 32 | 68 | 17 | 4  | 9  | 35 | 16 | 64 | 128 | 49 856 |
//!
//! # External vs internal API
//!
//! The public [`sign`] / [`verify`] functions implement the **external**
//! `slh_sign` / `slh_verify` API defined in FIPS 205 §9.2 / §9.3
//! (Algorithms 22 and 24): they accept a `ctx` byte string and frame
//! the message as `M' = 0x00 || |ctx| || ctx || M` before invoking the
//! internal primitive. This is the shape consumed by X.509, CMS, the
//! LAMPS profile, OpenSSL 3.5, and any other spec-conformant caller —
//! `ctx` is `b""` for those use cases.
//!
//! The `*_internal` surface ([`sign_internal`], [`verify_internal`])
//! exposes Algorithms 19 and 20 directly (`slh_sign_internal` /
//! `slh_verify_internal`) — the raw-message primitive with no framing.
//! These are `#[doc(hidden)]` and intended for FIPS 205 CAVP / ACVP
//! test harnesses that exercise the internal primitive.
//!
//! # Self-tests
//!
//! Power-up KAT: deterministic keygen → sign → verify round-trip
//! with a fixed seed (FIPS 140-3 IG D.G). Aggregated via
//! [`KATS`] which currently re-exports the SHA2-256s variant's KAT.
//!
//! # Data-parallel evaluation (`parallel` feature, default OFF)
//!
//! The optional `parallel` feature swaps three embarrassingly-parallel
//! inner loops — the WOTS+ chain sweep in `wots_pkgen` / `wots_sign`
//! and the per-FORS-tree sweep in `fors_sign` — for indexed
//! disjoint-slice `rayon` `par_chunks_mut().enumerate()` loops. Each
//! closure computes one output chunk as a pure function of its index
//! plus the immutable seeds/address and writes only the chunk it
//! exclusively owns, so the parallel output is byte-identical to the
//! sequential build (security policy R77). The feature pulls in
//! `rayon` (hence `std`), so the crate is `#![no_std]` only when the
//! feature is OFF; the default build graph contains no `rayon` and is
//! the CMVP-validated single-threaded configuration. `parallel` is a
//! throughput option for tall-tree (`*s`) keygen and signing, not a
//! validated path.

#![cfg_attr(not(feature = "parallel"), no_std)]
#![forbid(unsafe_code)]
// Cryptographic code requires pervasive index arithmetic, bitwise
// operations, and controlled truncation that are safe by construction
// (all indices are bounded by compile-time constants). Large stack
// arrays are unavoidable for signature buffers in `no_std`.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::large_stack_arrays,
    clippy::manual_div_ceil,
    clippy::needless_range_loop,
    clippy::unnecessary_cast,
    clippy::unwrap_used
)]

pub(crate) mod slh_dsa_impl;

/// SLH-DSA-SHA2-128f instantiation (n=16, h=66, d=22, a=6, k=33, w=16).
pub mod slh_dsa_sha2_128f;
/// SLH-DSA-SHA2-128s instantiation (n=16, h=63, d=7, a=12, k=14, w=16).
pub mod slh_dsa_sha2_128s;
/// SLH-DSA-SHA2-192f instantiation (n=24, h=66, d=22, a=8, k=33, w=16).
pub mod slh_dsa_sha2_192f;
/// SLH-DSA-SHA2-192s instantiation (n=24, h=63, d=7, a=14, k=17, w=16).
pub mod slh_dsa_sha2_192s;
/// SLH-DSA-SHA2-256f instantiation (n=32, h=68, d=17, a=9, k=35, w=16).
pub mod slh_dsa_sha2_256f;
/// SLH-DSA-SHA2-256s instantiation (n=32, h=64, d=8, a=14, k=22, w=16).
pub mod slh_dsa_sha2_256s;
/// SLH-DSA-SHAKE-128f instantiation (n=16, h=66, d=22, a=6, k=33, w=16).
pub mod slh_dsa_shake_128f;
/// SLH-DSA-SHAKE-128s instantiation (n=16, h=63, d=7, a=12, k=14, w=16).
pub mod slh_dsa_shake_128s;
/// SLH-DSA-SHAKE-192f instantiation (n=24, h=66, d=22, a=8, k=33, w=16).
pub mod slh_dsa_shake_192f;
/// SLH-DSA-SHAKE-192s instantiation (n=24, h=63, d=7, a=14, k=17, w=16).
pub mod slh_dsa_shake_192s;
/// SLH-DSA-SHAKE-256f instantiation (n=32, h=68, d=17, a=9, k=35, w=16).
pub mod slh_dsa_shake_256f;
/// SLH-DSA-SHAKE-256s instantiation (n=32, h=64, d=8, a=14, k=22, w=16).
pub mod slh_dsa_shake_256s;

// Backwards-compat: re-export the SHA2-256s surface at crate root so
// existing callers (acvp-harness, oxicrypt-ffi, NIST KAT tests) keep
// resolving `oxicrypt_slh_dsa::keygen` et al. to SHA2-256s. New
// callers should reach for the variant module they need explicitly
// (`slh_dsa_sha2_128s`, `slh_dsa_sha2_256f`, etc.) to disambiguate.
pub use slh_dsa_sha2_256s::{
    KATS, PK_LEN, SIG_LEN, SK_LEN, keygen, keygen_internal, sign, sign_internal, verify,
    verify_internal,
};
