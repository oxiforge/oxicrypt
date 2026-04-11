//! Per-algorithm ACVP dispatch handlers.
//!
//! Each submodule implements [`crate::dispatch::AlgorithmHandler`]
//! for one or more ACVP `(algorithm, revision)` pairs.
//!
//! # Module layout
//!
//! R10 shipped two handlers in their own files — [`sha3_256`] and
//! [`hmac_sha2_256`] — so the pre-R12-A git history stays readable.
//! R12-A adds the rest of the SHA-3 hashing family, both SHAKE XOFs,
//! and every HMAC variant other than HMAC-SHA2-256 in family modules
//! that share a private group driver per shape:
//!
//! - [`sha3`] — `SHA3-224`, `SHA3-384`, `SHA3-512`
//! - [`shake`] — `SHAKE-128`, `SHAKE-256`
//! - [`hmac`] — `HMAC-SHA-1`, the remaining five HMAC-SHA-2 variants,
//!   and all four HMAC-SHA-3 variants
//!
//! Later chunks will add AES, DRBG, ECDSA, EdDSA, RSA, plus MCT and
//! LDT test types, on the same plumbing.

pub mod hmac;
pub mod hmac_sha2_256;
pub mod sha3;
pub mod sha3_256;
pub mod shake;
