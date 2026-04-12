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
//! R12-B adds a *second envelope shape* — CAVP SHS `.rsp` byte vectors
//! rather than ACVP `internalProjection.json` — with its own
//! [`crate::shs::ShsHandler`] trait. The seven handlers implementing
//! that trait live alongside the ACVP ones, in [`shs`]:
//!
//! - [`shs`] — `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`,
//!   `SHA-512/224`, `SHA-512/256` (all via the byte-oriented
//!   entry points in `fips_sha`)
//!
//! R13 adds the first KDF family handler and, with it, the first
//! use of the optional ACVP `mode` field on the dispatch key. The
//! `KDA-HKDF-Sp800-56Cr2` envelope publishes across two top-level
//! fields (`algorithm = "KDA"`, `mode = "HKDF"`), so
//! [`crate::dispatch::Registry`] now keys handlers on
//! `(algorithm, mode, revision)`; single-field families return the
//! default `mode = None` and keep their existing shape.
//!
//! - [`kda_hkdf`] — `KDA-HKDF` revision `Sp800-56Cr2`, covering
//!   `SHA2-{224,256,384,512,512/224,512/256}` and
//!   `SHA3-{224,256,384,512}` HMAC instantiations over the
//!   SP 800-56C Rev 2 §5.9.2 hybrid shared-secret form
//!
//! R14-A/R14-B landed all seven AES block-cipher / AEAD / key-wrap
//! AFT handlers in [`aes`]. R15 added the MCT engine for ECB and CBC.
//! R16 added [`cmac`] — CMAC-AES gen/ver (SP 800-38B).
//!
//! R17 adds the three DRBG family handlers — [`drbg`] — covering
//! `ctrDRBG` (AES-128/192/256, with/without DF, with/without PR),
//! `hashDRBG` (SHA2-256/384/512), and `hmacDRBG` (SHA2-256/384/512).
//!
//! R18 adds asymmetric signature-verification and key-validation
//! handlers:
//!
//! - [`ecdsa`] — `ECDSA` / `sigVer` and `keyVer`, revision `FIPS186-5`
//!   (P-256 / SHA2-256)
//! - [`eddsa`] — `EDDSA` / `sigVer` and `keyVer`, revision `1.0`
//!   (ED-25519, pure Ed25519 only — no prehash)
//! - [`rsa`] — `RSA` / `sigVer`, revision `FIPS186-5`
//!   (RSA-2048 PKCS#1 v1.5 / SHA2-256, GDT test type)
//!
//! R19 adds SigGen handlers for deterministic round-trip testing:
//!
//! - [`ecdsa`] — `ECDSA` / `sigGen` (P-256 / SHA2-256, deterministic
//!   via caller-supplied `k`)
//! - [`eddsa`] — `EDDSA` / `sigGen` (ED-25519, pure, naturally
//!   deterministic)
//!
//! R20 adds the SP 800-108r1 KBKDF handler:
//!
//! - [`kbkdf`] — `KDF` revision `1.0`, counter / feedback /
//!   double-pipeline iteration modes across all eleven HMAC
//!   instantiations
//!
//! R21 adds the RSA DecryptionPrimitive handler:
//!
//! - [`rsa_decprim`] — `RSA` / `decryptionPrimitive` revision
//!   `Sp800-56Br2`, raw RSADP with SP 800-56Br2 §7.1.2.1 range
//!   check, both `standard` (non-CRT) and `crt` (Bellcore) key
//!   modes
//!
//! R22 adds the TLS v1.2 KDF (Extended Master Secret) handler:
//!
//! - [`tls12_kdf`] — `TLS-v1.2` / `KDF` revision `RFC7627`,
//!   RFC 7627 Extended Master Secret derivation via the TLS 1.2 PRF
//!   (RFC 5246 §5) over SHA2-{256,384,512}
//!
//! R23 adds the standard (non-EMS) TLS 1.2 KDF handler:
//!
//! - [`kdf_comp_tls`] — `kdf-components` / `tls` revision `1.0`,
//!   standard TLS 1.2 master-secret + key-expansion (v1.2 groups
//!   only; v1.0/1.1 filtered — MD5 not FIPS-approved)
//!
//! R24 adds the RSA SignaturePrimitive handler:
//!
//! - [`rsa_sigprim`] — `RSA` / `signaturePrimitive` revision `2.0`,
//!   raw RSASP1 (RFC 8017 §5.2.1) with range check `0 ≤ msg < n`,
//!   both non-CRT (`d`) and CRT (Bellcore verify-after-sign) key
//!   modes
//!
//! R25 adds RSA SigGen (both padding modes):
//!
//! - [`rsa_siggen`] — `RSA` / `sigGen` revision `FIPS186-5`,
//!   PKCS#1v1.5 (non-CRT, `d`) and PSS (CRT + Bellcore,
//!   `sLen = hLen = 32`) over SHA2-256 / RSA-2048
//!
//! Later chunks will add remaining test types (MCT, LDT) and
//! additional modes (PSS, larger key sizes).

pub mod aes;
pub mod cmac;
pub mod drbg;
pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod hmac_sha2_256;
pub mod kdf_comp_tls;
pub mod kbkdf;
pub mod kda_hkdf;
pub mod rsa;
pub mod rsa_decprim;
pub mod rsa_siggen;
pub mod rsa_sigprim;
pub mod sha3;
pub mod sha3_256;
pub mod shake;
pub mod shs;
pub mod tls12_kdf;
