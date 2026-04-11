//! EdDSA (Ed25519, Ed448) per FIPS 186-5.
//!
//! # Status
//!
//! Phase 2, in progress. The Ed25519 implementation is being built up
//! bottom-up in pure Rust with no external dependencies beyond the
//! rest of this workspace. The current module layout:
//!
//!   * [`field`] — arithmetic in GF(2^255 - 19), the base field of
//!     edwards25519. Five-limb radix-2^51 representation,
//!     constant-time, `no_std`.
//!
//! Curve arithmetic, scalar arithmetic, keygen, sign, and verify
//! arrive in subsequent commits. Ed448 is deferred to Phase 3.
#![no_std]
#![forbid(unsafe_code)]

pub mod field;
