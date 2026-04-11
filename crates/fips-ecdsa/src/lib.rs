//! ECDSA (P-256, P-384, P-521) per FIPS 186-5.
//!
//! # Status
//!
//! Phase 2, in progress. Build order (bottom-up, per curve):
//!
//!   * [`p256_field`] — arithmetic in `GF(p)` for P-256 with
//!     `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`. Montgomery form,
//!     four 64-bit limbs, constant-time, `no_std`.
//!
//! Scalar field arithmetic mod the group order, Jacobian point
//! representation, constant-time scalar multiplication, SEC1
//! encoding, and FIPS 186-5 keygen / sign / verify land in subsequent
//! commits. P-384 and P-521 are deferred until P-256 is complete and
//! gated by power-up KATs.
#![no_std]
#![forbid(unsafe_code)]

pub mod p256_field;
pub mod p256_point;
pub mod p256_scalar;
