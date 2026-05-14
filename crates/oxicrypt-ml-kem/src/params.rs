//! Shared ML-KEM parameter constants per FIPS 203 Table 2.
//!
//! These constants are common across all three parameter sets
//! (ML-KEM-512, ML-KEM-768, ML-KEM-1024). The K-dependent constants
//! (`K`, `ETA1`, `ETA2`, `DU`, `DV`, `EK_LEN`, `DK_LEN`, `CT_LEN`,
//! `POLY_COMPRESSED_DU`, `POLY_COMPRESSED_DV`, `PRF_ETA1_BYTES`,
//! `PRF_ETA2_BYTES`) live inside each per-variant module emitted by
//! [`crate::ml_kem_impl::ml_kem_impl!`].

/// Polynomial degree (FIPS 203 Table 2).
pub const N: usize = 256;

/// Modulus.
pub const Q: i16 = 3329;

/// Modulus as `u16`.
pub const Q_U16: u16 = 3329;

/// Modulus as `i32`.
pub const Q_I32: i32 = 3329;

/// Modulus as `u32`.
pub const Q_U32: u32 = 3329;

/// Shared secret length in bytes (FIPS 203 Table 2).
pub const SHARED_SECRET_LEN: usize = 32;

/// Seed length in bytes (ρ, σ, d, z, m). Common across all variants.
pub const SEED_LEN: usize = 32;

/// Byte length of one polynomial encoded at 12 bits per coefficient.
///
/// Common across all variants — 12 · 256 / 8 = 384.
pub const POLY_ENCODED_12: usize = 384;
