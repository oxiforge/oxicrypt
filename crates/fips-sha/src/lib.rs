//! SHA-1, SHA-2, SHA-3 hash functions per FIPS 180-4 / FIPS 202.
//!
//! # Status
//!
//! Phase 2 (in progress). SHA-224, SHA-256, SHA-384, SHA-512,
//! SHA-512/224, and SHA-512/256 are implemented and shipped with
//! power-up KATs. SHA-1 and the SHA-3 family will land incrementally
//! in subsequent commits; each brings its own registered KAT.
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

pub mod sha1;
pub mod sha224;
pub mod sha256;
pub mod sha384;
pub mod sha512;
pub mod sha512_t;

/// Power-up KATs for every algorithm this crate implements.
///
/// Callers that are assembling the full module test inventory should
/// concatenate `KATS` from every algorithm crate and pass the merged
/// slice to `fips_module::initialize_with_tests`.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "SHA-1 KAT (FIPS 180-4 Appendix A.1 \"abc\")",
        run: sha1::self_test,
    },
    KatEntry {
        name: "SHA-224 KAT (FIPS 180-4 Appendix A \"abc\")",
        run: sha224::self_test,
    },
    KatEntry {
        name: "SHA-256 KAT (FIPS 180-4 Appendix B \"abc\")",
        run: sha256::self_test,
    },
    KatEntry {
        name: "SHA-384 KAT (FIPS 180-4 Appendix D \"abc\")",
        run: sha384::self_test,
    },
    KatEntry {
        name: "SHA-512 KAT (FIPS 180-4 Appendix C \"abc\")",
        run: sha512::self_test,
    },
    KatEntry {
        name: "SHA-512/224 KAT (NIST CAVP \"abc\")",
        run: sha512_t::self_test_224,
    },
    KatEntry {
        name: "SHA-512/256 KAT (NIST CAVP \"abc\")",
        run: sha512_t::self_test_256,
    },
];
