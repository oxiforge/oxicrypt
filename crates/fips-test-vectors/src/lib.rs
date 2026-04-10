// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # fips-test-vectors
//!
//! NIST-derived known-answer-test (KAT) constants used by pqclib
//! power-up self-tests. The constants in [`generated`] are produced
//! by `tools/acvp-gen/generate.py` from vendored NIST sources and
//! are committed verbatim for reproducibility.
//!
//! ## Sources
//!
//!   * NIST CAVP Secure Hash Standard (SHS) byte-oriented ShortMsg
//!     test vectors for SHA-1 and the SHA-2 family. Vendored under
//!     `vendor/nist/cavp-shs/shabytetestvectors/`.
//!   * NIST ACVP-Server `gen-val/json-files/<algorithm>/internalProjection.json`
//!     for SHA-3, SHAKE, HMAC and SP 800-108 Counter Mode. Slim
//!     `kat-slice.json` files are vendored under
//!     `vendor/nist/acvp-server/gen-val/json-files/<algorithm>/`
//!     so the selected `tgId`/`tcId` remain pinned even if upstream
//!     regenerates its projections.
//!
//! The canonical ACVP-Server commit hash and per-file SHA-256
//! digests are recorded in `vendor/nist/MANIFEST.toml`.
//!
//! ## Truncation-aware vectors
//!
//! NIST ACVP-Server HMAC test groups only exercise truncated MAC
//! outputs. For each variant we ship the expected truncated prefix
//! ([`generated::HMAC_SHA2_256_MAC_PREFIX`] etc.); consumers compute
//! the full HMAC output and compare its leading `prefix.len()` bytes
//! against the prefix constant. This validates the HMAC primitive
//! using an unmodified NIST vector.
//!
//! Similarly, SP 800-108 Counter Mode ACVP test groups may produce
//! truncated `keyOut` values; consumers run the full counter-mode
//! derivation using the bundled `fixedData` blob and compare the
//! leading `KEY_OUT.len()` bytes against the expected output.

#![no_std]
#![forbid(unsafe_code)]

/// NIST-derived KAT constants. This module is machine-generated;
/// regenerate it via `tools/acvp-gen/generate.py` rather than editing
/// by hand.
pub mod generated;

pub use generated::*;
