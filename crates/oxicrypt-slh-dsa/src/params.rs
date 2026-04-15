//! SLH-DSA-SHA2-256s parameter set (FIPS 205, Table 1).
//!
//! This module defines the compile-time constants for the "small
//! signature" SHA-2 based parameter set.

/// Security parameter / hash output length in bytes.
pub(crate) const N: usize = 32;

/// Total tree height.
pub(crate) const H: usize = 64;

/// Number of hyper-tree layers.
pub(crate) const D: usize = 8;

/// Tree height per layer (`H / D`).
pub(crate) const H_PRIME: usize = H / D; // 8

/// FORS tree height (each FORS tree has 2^A leaves).
pub(crate) const A: usize = 14;

/// Number of FORS trees.
pub(crate) const K: usize = 22;

/// Winternitz parameter.
pub(crate) const W: usize = 16;

/// `lg(W)` — number of bits per Winternitz digit.
pub(crate) const LG_W: usize = 4;

/// WOTS+ chain count for message (ceil(8*N / lg(W))).
pub(crate) const LEN1: usize = 64; // 8*32/4

/// WOTS+ chain count for checksum.
pub(crate) const LEN2: usize = 3; // floor(lg(LEN1*(W-1))/lg(W)) + 1

/// Total WOTS+ chain count.
pub(crate) const LEN: usize = LEN1 + LEN2; // 67

/// Public key length in bytes (PK.seed ‖ PK.root).
pub const PK_LEN: usize = 2 * N; // 64

/// Secret key length in bytes (SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root).
pub const SK_LEN: usize = 4 * N; // 128

/// FORS signature size: k trees × (1 secret value + a auth-path nodes) × n bytes.
const FORS_SIG_LEN: usize = K * (1 + A) * N; // 10560

/// Single XMSS signature: WOTS+ sig (LEN * N) + auth path (H_PRIME * N).
const XMSS_SIG_LEN: usize = LEN * N + H_PRIME * N; // 2400

/// Hyper-tree signature: D XMSS signatures.
const HT_SIG_LEN: usize = D * XMSS_SIG_LEN; // 19200

/// Total signature length: randomness (N) + FORS sig + HT sig.
pub const SIG_LEN: usize = N + FORS_SIG_LEN + HT_SIG_LEN; // 29792

// Compile-time sanity checks.
const _: () = assert!(H_PRIME * D == H);
const _: () = assert!(LEN1 == 64);
const _: () = assert!(LEN2 == 3);
const _: () = assert!(LEN == 67);
const _: () = assert!(SIG_LEN == 29792);
const _: () = assert!(PK_LEN == 64);
const _: () = assert!(SK_LEN == 128);
