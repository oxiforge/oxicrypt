//! Tweakable hash functions — FIPS 205 §7 / §10.1 (SHA-256 instantiation).
//!
//! All SLH-DSA hash calls are domain-separated by the public seed
//! `PK.seed` and a compressed address `ADRSc`.  For the SHA-256
//! variant the first SHA-256 block is always `PK.seed ‖ zeros(32)`,
//! which can be precomputed once per key.
//!
//! Functions defined here (FIPS 205 §10.1, Table 3 for SHA-256):
//!
//! - **F** — single-block tweakable hash.
//! - **H** — two-block tweakable hash.
//! - **T** — variable-length tweakable hash.
//! - **PRF** — keyed PRF for secret-key derivation.
//! - **PRF_msg** — HMAC-based message PRF.
//! - **H_msg** — message hash (MGF1-SHA-256).

use crate::adrs::Adrs;
use crate::params::N;
use oxicrypt_sha::sha256::Sha256;

/// Padding length so that `PK.seed ‖ padding` fills one SHA-256 block.
const PAD_LEN: usize = 64 - N; // 32

// ── F: single-block tweakable hash ──────────────────────────────────

/// `F(PK.seed, ADRS, M₁)` — FIPS 205 §10.1.
///
/// Computes `Trunc_n(SHA-256(PK.seed ‖ toByte(0,32) ‖ ADRSc ‖ M₁))`.
pub(crate) fn f(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut h = Sha256::new_internal();
    h.update(pk_seed);
    h.update(&[0u8; PAD_LEN]);
    h.update(&adrsc);
    h.update(m1);
    h.finalize()
}

// ── H: two-block tweakable hash ─────────────────────────────────────

/// `H(PK.seed, ADRS, M₁, M₂)` — FIPS 205 §10.1.
///
/// Computes `Trunc_n(SHA-256(PK.seed ‖ toByte(0,32) ‖ ADRSc ‖ M₁ ‖ M₂))`.
pub(crate) fn h(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N], m2: &[u8; N]) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut hasher = Sha256::new_internal();
    hasher.update(pk_seed);
    hasher.update(&[0u8; PAD_LEN]);
    hasher.update(&adrsc);
    hasher.update(m1);
    hasher.update(m2);
    hasher.finalize()
}

// ── T: variable-length tweakable hash ───────────────────────────────

/// `T_l(PK.seed, ADRS, M)` — FIPS 205 §10.1.
///
/// `M` is `l × N` bytes.  Computes
/// `Trunc_n(SHA-256(PK.seed ‖ toByte(0,32) ‖ ADRSc ‖ M))`.
pub(crate) fn t(pk_seed: &[u8; N], adrs: &Adrs, m: &[u8]) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut hasher = Sha256::new_internal();
    hasher.update(pk_seed);
    hasher.update(&[0u8; PAD_LEN]);
    hasher.update(&adrsc);
    hasher.update(m);
    hasher.finalize()
}

// ── PRF: pseudorandom function for secret values ────────────────────

/// `PRF(PK.seed, SK.seed, ADRS)` — FIPS 205 §10.1.
///
/// Computes `Trunc_n(SHA-256(PK.seed ‖ toByte(0,32) ‖ ADRSc ‖ SK.seed))`.
pub(crate) fn prf(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut hasher = Sha256::new_internal();
    hasher.update(pk_seed);
    hasher.update(&[0u8; PAD_LEN]);
    hasher.update(&adrsc);
    hasher.update(sk_seed);
    hasher.finalize()
}

// ── PRF_msg: message randomizer ─────────────────────────────────────

/// `PRF_msg(SK.prf, opt_rand, M)` — FIPS 205 §10.1.
///
/// Computes `HMAC-SHA-256(SK.prf, opt_rand ‖ M)`, truncated to `N` bytes.
/// Since SHA-256 output is 32 bytes = `N`, no truncation is needed.
pub(crate) fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], msg: &[u8]) -> [u8; N] {
    // HMAC-SHA-256(key, data) — we inline the HMAC to avoid pulling
    // in the full oxicrypt-hmac crate as a dependency.  The HMAC
    // construction is standard (FIPS 198-1).
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Key is exactly N=32 bytes, which is ≤ block size, so K₀ = key ‖ 0^32.
    let mut ipad_key = [0u8; BLOCK_SIZE];
    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..N {
        ipad_key[i] = sk_prf[i] ^ IPAD;
        opad_key[i] = sk_prf[i] ^ OPAD;
    }
    for i in N..BLOCK_SIZE {
        ipad_key[i] = IPAD;
        opad_key[i] = OPAD;
    }

    // inner = SHA-256(ipad_key ‖ opt_rand ‖ M)
    let mut inner = Sha256::new_internal();
    inner.update(&ipad_key);
    inner.update(opt_rand);
    inner.update(msg);
    let inner_hash = inner.finalize();

    // outer = SHA-256(opad_key ‖ inner_hash)
    let mut outer = Sha256::new_internal();
    outer.update(&opad_key);
    outer.update(&inner_hash);
    outer.finalize()
}

// ── H_msg: message hash ─────────────────────────────────────────────

/// `H_msg(R, PK.seed, PK.root, M)` — FIPS 205 §10.1.
///
/// Uses MGF1-SHA-256 to produce `ceil((K*(A+1)+7)/8)` bytes of
/// pseudorandom output, which is then used to derive the FORS
/// message digest and the tree/leaf indices.
///
/// Returns `(md, tree_idx, leaf_idx)` where:
/// - `md` is the FORS message digest (K*A bits packed big-endian),
/// - `tree_idx` is the hyper-tree index (H - H/D bits),
/// - `leaf_idx` is the leaf index within the bottom XMSS tree (H/D bits).
///
/// The total output length is `ceil((K*A + K + H - H/D + H/D + 7) / 8)`
/// but we compute the three values directly from an MGF1 stream.
pub(crate) fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], msg: &[u8]) -> HMsgOutput {
    use crate::params::{A, H, H_PRIME, K};

    // Total bits needed: K*A (FORS message) + (H - H/D) (tree index)
    // + H/D (leaf index).
    //
    // K*A = 22*14 = 308 bits
    // H - H/D = 64 - 8 = 56 bits
    // H/D = 8 bits
    // Total = 308 + 56 + 8 = 372 bits = 46.5 bytes → 47 bytes
    //
    // But we compute this via MGF1 which produces 32-byte blocks.
    // We need ceil(47/32) = 2 blocks = 64 bytes.

    // Build the MGF1 seed: R ‖ PK.seed ‖ PK.root ‖ M.
    // Then run MGF1-SHA-256 over it.
    // MGF1 output block i = SHA-256(seed ‖ toByte(i, 4)).

    // We need 47 bytes → 2 MGF1 iterations.
    let mut buf = [0u8; 64]; // 2 × 32

    // MGF1 block 0.
    let mut h0 = Sha256::new_internal();
    h0.update(r);
    h0.update(pk_seed);
    h0.update(pk_root);
    h0.update(msg);
    h0.update(&0u32.to_be_bytes());
    let block0 = h0.finalize();
    buf[..32].copy_from_slice(&block0);

    // MGF1 block 1.
    let mut h1 = Sha256::new_internal();
    h1.update(r);
    h1.update(pk_seed);
    h1.update(pk_root);
    h1.update(msg);
    h1.update(&1u32.to_be_bytes());
    let block1 = h1.finalize();
    buf[32..64].copy_from_slice(&block1);

    // Extract bits from `buf`.
    // FORS message digest: K*A = 308 bits.
    let md = extract_bits(&buf, 0, K * A);

    // Tree index: (H - H/D) = 56 bits.
    let tree_bits = H - H_PRIME;
    let tree_idx = extract_bits_u64(&buf, K * A, tree_bits);

    // Leaf index: H/D = 8 bits.
    let leaf_idx = extract_bits_u32(&buf, K * A + tree_bits, H_PRIME);

    // For SLH-DSA-SHA2-256s, tree index must be mod 2^(h - h/d).
    let tree_mask = if tree_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << tree_bits) - 1
    };
    let leaf_mask = (1u32 << H_PRIME) - 1;

    HMsgOutput {
        md,
        tree_idx: tree_idx & tree_mask,
        leaf_idx: leaf_idx & leaf_mask,
    }
}

/// Output of `H_msg`: the FORS message digest and tree/leaf indices.
pub(crate) struct HMsgOutput {
    /// FORS message digest — a packed bit string from which K
    /// A-bit indices are extracted during FORS signing.
    pub md: [u8; 64],
    /// Hyper-tree index (up to `H - H/D` bits).
    pub tree_idx: u64,
    /// Leaf index within the bottom XMSS tree (up to `H/D` bits).
    pub leaf_idx: u32,
}

/// Extract `bit_len` bits starting at `bit_offset` from `buf`,
/// returning them right-aligned in a 64-byte array.
fn extract_bits(buf: &[u8; 64], bit_offset: usize, bit_len: usize) -> [u8; 64] {
    let mut out = [0u8; 64];
    // Total bytes needed to hold bit_len bits.
    let byte_len = (bit_len + 7) / 8;
    // Start writing at the end of `out` so the bits are right-aligned.
    let out_start = 64 - byte_len;

    for i in 0..bit_len {
        let src_byte = (bit_offset + i) / 8;
        let src_bit = 7 - ((bit_offset + i) % 8);
        let bit = (buf[src_byte] >> src_bit) & 1;

        let dst_bit_in_out = (byte_len * 8 - bit_len) + i;
        let dst_byte = out_start + dst_bit_in_out / 8;
        let dst_bit = 7 - (dst_bit_in_out % 8);
        out[dst_byte] |= bit << dst_bit;
    }
    out
}

/// Extract up to 64 bits from a byte buffer at an arbitrary bit offset.
fn extract_bits_u64(buf: &[u8; 64], bit_offset: usize, bit_len: usize) -> u64 {
    let mut val: u64 = 0;
    for i in 0..bit_len {
        let byte_idx = (bit_offset + i) / 8;
        let bit_idx = 7 - ((bit_offset + i) % 8);
        let bit = u64::from((buf[byte_idx] >> bit_idx) & 1);
        val = (val << 1) | bit;
    }
    val
}

/// Extract up to 32 bits from a byte buffer at an arbitrary bit offset.
fn extract_bits_u32(buf: &[u8; 64], bit_offset: usize, bit_len: usize) -> u32 {
    extract_bits_u64(buf, bit_offset, bit_len) as u32
}

/// Extract a single `A`-bit FORS index from the message digest.
///
/// Index `i` corresponds to bits `[i*A .. (i+1)*A)` of the digest
/// (stored right-aligned in the 64-byte `md` array from `H_msg`).
pub(crate) fn fors_index(md: &[u8; 64], i: usize) -> u32 {
    use crate::params::A;
    // The digest bits are stored right-aligned: the first bit of the
    // digest is at bit offset `(64*8 - K*A)` within `md`.
    let total_bits = crate::params::K * A; // 308
    let base_offset = 64 * 8 - total_bits; // 512 - 308 = 204
    let bit_offset = base_offset + i * A;
    let mut val: u32 = 0;
    for b in 0..A {
        let byte_idx = (bit_offset + b) / 8;
        let bit_idx = 7 - ((bit_offset + b) % 8);
        let bit = u32::from((md[byte_idx] >> bit_idx) & 1);
        val = (val << 1) | bit;
    }
    val
}
