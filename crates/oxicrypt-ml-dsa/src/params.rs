//! Shared parameter constants common across all three ML-DSA variants.
//!
//! Per-variant parameters (k, ℓ, η, τ, β, γ₁, γ₂, ω, λ) and their
//! derived sizes (`PK_LEN`, `SK_LEN`, `SIG_LEN`, `CTILDE_LEN`,
//! `ETA_PACKED`, `Z_PACKED`, `H_PACKED`, `W1_PACKED`) are emitted
//! inside the [`ml_dsa_impl!`](crate::ml_dsa_impl::ml_dsa_impl)
//! macro and live in [`crate::ml_dsa_44`],
//! [`crate::ml_dsa_65`], and [`crate::ml_dsa_87`].
#![allow(clippy::integer_division)]

/// Polynomial degree. FIPS 204 §4: identical across ML-DSA-44/65/87.
pub const N: usize = 256;

/// Modulus. FIPS 204 §4: identical across ML-DSA-44/65/87.
pub const Q: i32 = 8_380_417;

/// Modulus as `u32`.
pub const Q_U32: u32 = 8_380_417;

/// Modulus as `i64`.
pub const Q_I64: i64 = 8_380_417;

/// Dropped bits for rounding (Power2Round). FIPS 204 §4: d = 13 for
/// all three variants.
pub const D: u32 = 13;

/// Keygen seed length in bytes. FIPS 204 §6.1: 32 bytes for all
/// variants.
pub const SEED_LEN: usize = 32;

/// Bytes per polynomial for t₀ encoding (d=13 bits per coefficient).
/// Variant-independent: 256 * 13 / 8 = 416.
pub const T0_PACKED: usize = N * D as usize / 8;

/// Bytes per polynomial for t₁ encoding (10 bits per coefficient).
/// Variant-independent: 256 * 10 / 8 = 320.
pub const T1_PACKED: usize = N * 10 / 8;
