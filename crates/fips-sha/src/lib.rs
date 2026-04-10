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

pub mod keccak;
pub mod sha1;
pub mod sha224;
pub mod sha256;
pub mod sha3;
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
        name: "SHA-1 KAT (NIST CAVP SHA1ShortMsg Len=8)",
        run: sha1::self_test,
    },
    KatEntry {
        name: "SHA-224 KAT (NIST CAVP SHA224ShortMsg Len=8)",
        run: sha224::self_test,
    },
    KatEntry {
        name: "SHA-256 KAT (NIST CAVP SHA256ShortMsg Len=8)",
        run: sha256::self_test,
    },
    KatEntry {
        name: "SHA-384 KAT (NIST CAVP SHA384ShortMsg Len=8)",
        run: sha384::self_test,
    },
    KatEntry {
        name: "SHA-512 KAT (NIST CAVP SHA512ShortMsg Len=8)",
        run: sha512::self_test,
    },
    KatEntry {
        name: "SHA-512/224 KAT (NIST CAVP SHA512_224ShortMsg Len=8)",
        run: sha512_t::self_test_224,
    },
    KatEntry {
        name: "SHA-512/256 KAT (NIST CAVP SHA512_256ShortMsg Len=8)",
        run: sha512_t::self_test_256,
    },
    KatEntry {
        name: "SHA3-224 KAT (NIST ACVP-Server SHA3-224-2.0)",
        run: sha3::self_test_224,
    },
    KatEntry {
        name: "SHA3-256 KAT (NIST ACVP-Server SHA3-256-2.0)",
        run: sha3::self_test_256,
    },
    KatEntry {
        name: "SHA3-384 KAT (NIST ACVP-Server SHA3-384-2.0)",
        run: sha3::self_test_384,
    },
    KatEntry {
        name: "SHA3-512 KAT (NIST ACVP-Server SHA3-512-2.0)",
        run: sha3::self_test_512,
    },
];
