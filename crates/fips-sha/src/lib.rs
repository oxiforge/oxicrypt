//! SHA-1, SHA-2, SHA-3 hash functions per FIPS 180-4 / FIPS 202.
//!
//! # Status
//!
//! Phase 2 (in progress). SHA-256 is implemented and shipped with a
//! power-up KAT. SHA-1, the remaining SHA-2 variants, and the SHA-3
//! family will land incrementally in subsequent commits; each brings
//! its own registered KAT.
//!
//! # Usage
//!
//! ```ignore
//! use fips_sha::sha256;
//! use fips_module::initialize_with_tests;
//!
//! initialize_with_tests(fips_sha::KATS).unwrap();
//! let digest = sha256::sha256(b"abc").unwrap();
//! ```

#![no_std]
#![forbid(unsafe_code)]

use fips_module::KatEntry;

pub mod sha256;

/// Power-up KATs for every algorithm this crate implements.
///
/// Callers that are assembling the full module test inventory should
/// concatenate `KATS` from every algorithm crate and pass the merged
/// slice to `fips_module::initialize_with_tests`.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "SHA-256 KAT (FIPS 180-4 \"abc\")",
    run: sha256::self_test,
}];
