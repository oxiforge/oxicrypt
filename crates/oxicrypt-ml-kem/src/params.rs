//! ML-KEM-1024 parameter constants per FIPS 203 Table 2.
//!
//! All constants match the ML-KEM-1024 parameter set:
//!   n = 256, k = 4, q = 3329, η₁ = η₂ = 2, dᵤ = 11, dᵥ = 5.

/// Polynomial degree.
pub const N: usize = 256;

/// Module rank (number of polynomials per vector).
pub const K: usize = 4;

/// Modulus.
pub const Q: i16 = 3329;

/// Modulus as `u16`.
pub const Q_U16: u16 = 3329;

/// Modulus as `i32`.
pub const Q_I32: i32 = 3329;

/// Modulus as `u32`.
pub const Q_U32: u32 = 3329;

/// CBD noise parameter for secret and first error vector.
pub const ETA1: usize = 2;

/// CBD noise parameter for second error polynomial.
pub const ETA2: usize = 2;

/// Compression parameter for u (ciphertext polynomial vector).
pub const DU: usize = 11;

/// Compression parameter for v (ciphertext polynomial).
pub const DV: usize = 5;

/// Shared secret length in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// Seed length in bytes (ρ, σ, d, z, m).
pub const SEED_LEN: usize = 32;

/// Encapsulation (public) key length in bytes: 12 · k · n/8 + 32.
pub const EK_LEN: usize = 384 * K + 32; // 1568

/// Decapsulation (private) key length in bytes:
/// dk_pke (12 · k · 32) + ek (384 · k + 32) + H(ek) (32) + z (32).
pub const DK_LEN: usize = 384 * K + EK_LEN + 32 + 32; // 3168

/// Ciphertext length in bytes: dᵤ · k · n/8 + dᵥ · n/8.
pub const CT_LEN: usize = DU * K * 32 + DV * 32; // 1568

/// Byte length of one polynomial encoded at 12 bits per coefficient.
pub const POLY_ENCODED_12: usize = 384;

/// Byte length of one compressed polynomial at dᵤ = 11 bits.
pub const POLY_COMPRESSED_DU: usize = DU * 32; // 352

/// Byte length of one compressed polynomial at dᵥ = 5 bits.
pub const POLY_COMPRESSED_DV: usize = DV * 32; // 160

/// Number of bytes of PRF output needed for CBD(η) sampling:
/// 64 · η bytes.
pub const PRF_ETA1_BYTES: usize = 64 * ETA1; // 128

/// Number of bytes of PRF output needed for CBD(η₂) sampling.
pub const PRF_ETA2_BYTES: usize = 64 * ETA2; // 128
