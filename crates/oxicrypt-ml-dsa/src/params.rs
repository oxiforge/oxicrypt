//! ML-DSA-87 parameter constants per FIPS 204 Table 1.
//!
//! All constants match the ML-DSA-87 parameter set (the CNSA 2.0
//! digital-signature algorithm).
#![allow(clippy::integer_division)]

/// Polynomial degree.
pub const N: usize = 256;

/// Module rank for public key (number of rows in A).
pub const K: usize = 8;

/// Module rank for secret key (number of columns in A).
pub const L: usize = 7;

/// Modulus.
pub const Q: i32 = 8_380_417;

/// Modulus as `u32`.
pub const Q_U32: u32 = 8_380_417;

/// Modulus as `i64`.
pub const Q_I64: i64 = 8_380_417;

/// Secret key coefficient range: s₁, s₂ ∈ [-η, η].
pub const ETA: i32 = 2;

/// Number of ±1 coefficients in challenge polynomial c.
///
/// FIPS 204 Table 1: ML-DSA-87 uses τ = 60.
pub const TAU: usize = 60;

/// Norm bound β = τ · η.
///
/// FIPS 204 Table 1: β = τ · η = 60 · 2 = 120.
pub const BETA: i32 = 120; // TAU as i32 * ETA

/// Mask range: y coefficients in [−γ₁+1, γ₁].
pub const GAMMA1: i32 = 1 << 19; // 524288

/// Decomposition parameter γ₂ = (q−1)/32.
pub const GAMMA2: i32 = 261_888; // (Q - 1) / 32

/// Max hint weight (nonzero entries in h across all k polynomials).
pub const OMEGA: usize = 75;

/// Dropped bits for rounding (Power2Round).
pub const D: u32 = 13;

/// Seed length in bytes.
pub const SEED_LEN: usize = 32;

/// Public key size in bytes: seed (32) + t₁ packed (k·n·10/8).
pub const PK_LEN: usize = SEED_LEN + K * N * 10 / 8; // 32 + 2560 = 2592

/// Secret key size in bytes.
/// ρ(32) + K(32) + tr(64) + s₁(l×n×η_packed) + s₂(k×n×η_packed) + t₀(k×n×13/8)
/// η=2 → 3 bits per coefficient → each poly = 256*3/8 = 96 bytes
/// s₁: 7×96 = 672, s₂: 8×96 = 768, t₀: 8×416 = 3328
/// Total: 32 + 32 + 64 + 672 + 768 + 3328 = 4896
pub const SK_LEN: usize = 4896;

/// Signature size in bytes.
/// c̃ (32) + z (l×n×γ₁_packed) + h (ω+k)
/// γ₁ = 2^19 → z coefficients in 20-bit encoding → each poly = 256*20/8 = 640
/// z: 7×640 = 4480, h: 75+8 = 83
/// Total: 32 + 4480 + 4 + 83 + 28 ... let's compute properly:
/// c̃: λ/4 = 32 bytes (for ML-DSA-87 λ=256 → c̃ = 32 bytes)
/// Actually FIPS 204: c̃ is 32 bytes for all ML-DSA.
/// z: l × 32·(1 + bitlen(γ₁−1)) / 8  per FIPS 204
///    bitlen(γ₁−1) = bitlen(524287) = 19, so 20 bits per coefficient
///    l × 256 × 20 / 8 = 7 × 640 = 4480
/// h: ω + k = 75 + 8 = 83
/// c̃ + z + h = 32 + 4480 + 83 = 4595
/// Wait, FIPS 204 Table 2 says 4627 for ML-DSA-87 signature.
/// Let me recompute: c̃ = 64 bytes for ML-DSA-87 (λ=256 → c̃ = 2λ/8 = 64).
/// No: FIPS 204 says c̃ ∈ {0,1}^2λ → for security category 5 (ML-DSA-87), λ=256.
/// c̃ = 2×256/8 = 64 bytes.
/// z: 7 × 640 = 4480
/// h: ω + k = 83
/// Total: 64 + 4480 + 83 = 4627 ✓
pub const SIG_LEN: usize = 4627;

/// Challenge seed size (c̃) in bytes = 2λ/8 for ML-DSA-87.
pub const CTILDE_LEN: usize = 64;

/// Bytes per polynomial for η=2 encoding (3 bits per coefficient).
pub const ETA_PACKED: usize = N * 3 / 8; // 96

/// Bytes per polynomial for t₀ encoding (d=13 bits per coefficient).
pub const T0_PACKED: usize = N * D as usize / 8; // 416

/// Bytes per polynomial for t₁ encoding (10 bits per coefficient).
pub const T1_PACKED: usize = N * 10 / 8; // 320

/// Bytes per polynomial for z encoding (20 bits per coefficient).
pub const Z_PACKED: usize = N * 20 / 8; // 640

/// Bytes for hint encoding: ω + k.
pub const H_PACKED: usize = OMEGA + K; // 83
