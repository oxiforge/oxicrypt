//! Approved hash functions: SHA-1, the SHA-2 family, and the
//! SHA-3 family.
//!
//! # Approved algorithms
//!
//! | Algorithm | Standard | Module |
//! |-----------|----------|--------|
//! | SHA-1       | FIPS 180-4 §6.1 | [`sha1`] |
//! | SHA-224     | FIPS 180-4 §6.3 | [`sha224`] |
//! | SHA-256     | FIPS 180-4 §6.2 | [`sha256`] |
//! | SHA-384     | FIPS 180-4 §6.5 | [`sha384`] |
//! | SHA-512     | FIPS 180-4 §6.4 | [`sha512`] |
//! | SHA-512/224 | FIPS 180-4 §6.7 | [`sha512_t`] |
//! | SHA-512/256 | FIPS 180-4 §6.7 | [`sha512_t`] |
//! | SHA3-224    | FIPS 202 §6.1  | [`sha3`]    |
//! | SHA3-256    | FIPS 202 §6.1  | [`sha3`]    |
//! | SHA3-384    | FIPS 202 §6.1  | [`sha3`]    |
//! | SHA3-512    | FIPS 202 §6.1  | [`sha3`]    |
//!
//! SHA-1 is retained as an **approved hash for legacy use and
//! non-digital-signature KDF/HMAC contexts** per SP 800-131A
//! Rev. 2. It is **not** approved for new digital-signature
//! generation; `fips-rsa` and `fips-ecdsa` do not expose any
//! SHA-1 sign path.
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes one [`oxicrypt_module::KatEntry`] per algorithm,
//! driven by short-message vectors sourced from NIST CAVP
//! (SHA-1, SHA-2 family) and ACVP-Server (SHA-3 family).
//!
//! # Sensitive security parameters
//!
//! None. Hash functions are keyless public primitives; all
//! inputs and outputs are public.
//!
//! # FIPS module gating
//!
//! Hash primitives that are used directly by callers gate on
//! [`oxicrypt_module::require_operational`]. Internal consumers
//! (HMAC, KDFs, DRBGs) reach into the hidden `*_internal`
//! surface so they keep working during `SelfTest`.
//!
//! # Usage
//!
//! All one-shot hash functions and streaming hasher types are
//! re-exported at the crate root for convenience:
//!
//! ```ignore
//! use oxicrypt_sha::sha256;       // one-shot function (re-export)
//! use oxicrypt_sha::Sha256;       // streaming hasher  (re-export)
//! use oxicrypt_module::initialize_with_tests;
//!
//! initialize_with_tests(oxicrypt_sha::KATS).unwrap();
//! let digest = sha256(b"abc").unwrap();
//! ```

#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_module::KatEntry;

pub mod keccak;
pub mod sha1;
pub mod sha224;
pub mod sha256;
pub mod sha3;
pub mod sha384;
pub mod sha512;
pub mod sha512_t;

// ── Crate-root re-exports ────────────────────────────────────────
//
// Agents (and humans) expect `use oxicrypt_sha::sha256` to resolve
// to the one-shot hash function, not a submodule.  Re-exporting the
// most commonly used items at the crate root eliminates the most
// frequent first-attempt import failure.

// SHA-2 one-shot functions
pub use sha1::sha1;
pub use sha224::sha224;
pub use sha256::sha256;
pub use sha384::sha384;
pub use sha512::sha512;
pub use sha512_t::{sha512_224, sha512_256};

// SHA-3 one-shot functions
pub use sha3::{sha3_224, sha3_256, sha3_384, sha3_512};

// Streaming hasher types
pub use sha1::Sha1;
pub use sha224::Sha224;
pub use sha256::Sha256;
pub use sha384::Sha384;
pub use sha512::Sha512;
pub use sha512_t::{Sha512_224, Sha512_256};

/// Power-up KATs for every algorithm this crate implements.
///
/// Callers that are assembling the full module test inventory should
/// concatenate `KATS` from every algorithm crate and pass the merged
/// slice to `oxicrypt_module::initialize_with_tests`.
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
