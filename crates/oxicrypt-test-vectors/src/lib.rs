// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # oxicrypt-test-vectors
//!
//! NIST-derived known-answer-test (KAT) constants used by oxicrypt
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
//!     for SHA-3, SHAKE, HMAC, SP 800-108 Rev. 1 KBKDF (Counter,
//!     Feedback and Double-Pipeline Iteration modes) and SP 800-56C
//!     Rev. 2 Two-Step KDA-HKDF. Slim
//!     `kat-slice.json` files are vendored under
//!     `vendor/nist/acvp-server/gen-val/json-files/<algorithm>/`
//!     so the selected `tgId`/`tcId` remain pinned even if upstream
//!     regenerates its projections.
//!
//! The canonical ACVP-Server commit hash is recorded in
//! `vendor/nist/MANIFEST.toml`, together with the SHA-256 of each
//! upstream `internalProjection.json` the slices were cut from. The
//! vendored slice files are not themselves digest-pinned; the CAVP
//! `.rsp` files are, being vendored byte-for-byte.
//!
//! ## Truncation-aware vectors
//!
//! The NIST ACVP-Server HMAC group selected for each variant
//! exercises a truncated MAC output. For each variant we ship the
//! expected truncated prefix
//! ([`generated::HMAC_SHA2_256_MAC_PREFIX`] etc.); consumers compute
//! the full HMAC output and compare its leading `prefix.len()` bytes
//! against the prefix constant. This validates the HMAC primitive
//! using an unmodified NIST vector.
//!
//! Similarly, the SP 800-108 KBKDF ACVP test groups — Counter,
//! Feedback and Double-Pipeline Iteration — may produce truncated
//! `keyOut` values; consumers run the full derivation using the
//! bundled `fixedData` blob and compare the
//! leading `KEY_OUT.len()` bytes against the expected output.

#![no_std]
#![forbid(unsafe_code)]

/// NIST-derived KAT constants. This module is machine-generated;
/// regenerate it via `tools/acvp-gen/generate.py` rather than editing
/// by hand.
pub mod generated;

pub use generated::*;
