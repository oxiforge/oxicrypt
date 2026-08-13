//! Per-algorithm ACVP dispatch handlers.
//!
//! Each submodule implements [`crate::dispatch::AlgorithmHandler`]
//! for one or more ACVP `(algorithm, revision)` pairs.
//!
//! # Module layout
//!
//! One submodule per algorithm family, grouped below by what they
//! serve. The declarations after this block are authoritative for
//! membership; the grouping is a reading aid, not a second list to
//! keep in step.
//!
//! Hashing and XOFs: [`sha2`], [`sha3`], [`sha3_256`], [`shake`],
//! [`shs`]. Keyed hashing and MACs: [`hmac`], [`hmac_sha2_256`],
//! [`cmac`], [`kmac`]. SP 800-185 derived functions: [`cshake`],
//! [`tuplehash`], [`parallelhash`], with the shared customization-field
//! rule in [`xof_common`]. Block ciphers and AEAD: [`aes`]. Random bit
//! generation: [`drbg`]. Key derivation: [`kbkdf`], [`kda_hkdf`],
//! [`kdf_comp_tls`], [`tls12_kdf`], [`tls13_kdf`], [`pbkdf2`]. Key
//! agreement and transport: [`kas_ecc_ssc`], [`kas_ffc_ssc`],
//! [`kts_ifc`]. RSA: [`rsa`], [`rsa_keygen`], [`rsa_siggen`],
//! [`rsa_oaep`], [`rsa_decprim`], [`rsa_sigprim`]. Elliptic-curve
//! signatures: [`ecdsa`], [`eddsa`]. Post-quantum: [`ml_kem`],
//! [`ml_dsa`], [`slh_dsa`]. Stateful hash-based signatures: [`lms`],
//! [`xmss`]. Registration capabilities: [`caps`]. Shared randomness
//! bootstrap: [`os_entropy`].
//!
//! Two structural facts. Most handlers consume the ACVP
//! `internalProjection.json` envelope; the CAVP SHS handlers in
//! [`shs`] consume a second envelope shape, because upstream publishes
//! no plain FIPS 180-4 hashing vectors in the ACVP layout. And a
//! handler occupies either an `(algorithm, None, revision)` registry
//! slot or an `(algorithm, mode, revision)` one.
//!
//! The SP 800-185 and PBKDF vector files under `vendor/` are
//! self-generated.
//!
//! Handlers advertise through `acvp_capabilities()`. The offline-only
//! fixture handlers — KMAC, TupleHash, ParallelHash and RSA-OAEP —
//! return `None` and never advertise to the demo server.

pub mod aes;
pub mod caps;
pub mod cmac;
pub mod cshake;
pub mod drbg;
pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod hmac_sha2_256;
pub mod kas_ecc_ssc;
pub mod kas_ffc_ssc;
pub mod kbkdf;
pub mod kda_hkdf;
pub mod kdf_comp_tls;
pub mod kmac;
pub mod kts_ifc;
pub mod lms;
pub mod ml_dsa;
pub mod ml_kem;
pub mod os_entropy;
pub mod parallelhash;
pub mod pbkdf2;
pub mod rsa;
pub mod rsa_decprim;
pub mod rsa_keygen;
pub mod rsa_oaep;
pub mod rsa_siggen;
pub mod rsa_sigprim;
pub mod sha2;
pub mod sha3;
pub mod sha3_256;
pub mod shake;
pub mod shs;
pub mod slh_dsa;
pub mod tls12_kdf;
pub mod tls13_kdf;
pub mod tuplehash;
pub mod xmss;
pub mod xof_common;
