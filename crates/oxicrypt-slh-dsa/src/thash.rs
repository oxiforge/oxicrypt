//! Tweakable hash functions — FIPS 205 §7 / §10.1 (SHA-256/SHA-512 instantiation).
//!
//! SLH-DSA-SHA2-256s uses **two** SHA-2 primitives (FIPS 205 §10.1):
//!
//! | Function | Primitive | Block size | Zero padding |
//! |----------|-----------|------------|--------------|
//! | F        | SHA-256   | 64 bytes   | 0^(64−n) = 0^32  |
//! | PRF      | SHA-256   | 64 bytes   | 0^(64−n) = 0^32  |
//! | H        | SHA-512   | 128 bytes  | 0^(128−n) = 0^96 |
//! | T_l      | SHA-512   | 128 bytes  | 0^(128−n) = 0^96 |
//!
//! The SHA-512 outputs are truncated to `n = 32` bytes.
//!
//! The SHA-256 functions pre-compress the first block `PK.seed ‖ 0^32`
//! before the per-call data; the SHA-512 functions do the same with
//! `PK.seed ‖ 0^96`.

use crate::adrs::Adrs;
use crate::params::N;
use oxicrypt_sha::sha256::Sha256;
use oxicrypt_sha::sha512::Sha512;

/// SHA-256 zero padding so that `PK.seed ‖ padding` fills one 64-byte block.
const PAD256: usize = 64 - N; // 32

/// SHA-512 zero padding so that `PK.seed ‖ padding` fills one 128-byte block.
const PAD512: usize = 128 - N; // 96

// ── F: single-block tweakable hash (SHA-256) ────────────────────────

/// `F(PK.seed, ADRS, M₁)` — FIPS 205 §10.1.
///
/// `F = Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64−n) ‖ ADRSc ‖ M₁))`
pub(crate) fn f(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut h = Sha256::new_internal();
    h.update(pk_seed);
    h.update(&[0u8; PAD256]);
    h.update(&adrsc);
    h.update(m1);
    h.finalize()
}

// ── H: two-input tweakable hash (SHA-512, truncated) ────────────────

/// `H(PK.seed, ADRS, M₁, M₂)` — FIPS 205 §10.1.
///
/// `H = Trunc_n(SHA-512(PK.seed ‖ toByte(0, 128−n) ‖ ADRSc ‖ M₁ ‖ M₂))`
pub(crate) fn h(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N], m2: &[u8; N]) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut hasher = Sha512::new_internal();
    hasher.update(pk_seed);
    hasher.update(&[0u8; PAD512]);
    hasher.update(&adrsc);
    hasher.update(m1);
    hasher.update(m2);
    // Truncate the 64-byte SHA-512 digest to n=32 bytes.
    let full = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

// ── T: variable-length tweakable hash (SHA-512, truncated) ──────────

/// `T_l(PK.seed, ADRS, M)` — FIPS 205 §10.1.
///
/// `M` is `l × N` bytes.
/// `T_l = Trunc_n(SHA-512(PK.seed ‖ toByte(0, 128−n) ‖ ADRSc ‖ M))`
pub(crate) fn t(pk_seed: &[u8; N], adrs: &Adrs, m: &[u8]) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut hasher = Sha512::new_internal();
    hasher.update(pk_seed);
    hasher.update(&[0u8; PAD512]);
    hasher.update(&adrsc);
    hasher.update(m);
    // Truncate the 64-byte SHA-512 digest to n=32 bytes.
    let full = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

// ── PRF: pseudorandom function for secret values (SHA-256) ──────────

/// `PRF(PK.seed, SK.seed, ADRS)` — FIPS 205 §10.1.
///
/// `PRF = Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64−n) ‖ ADRSc ‖ SK.seed))`
pub(crate) fn prf(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let adrsc = adrs.compress();
    let mut hasher = Sha256::new_internal();
    hasher.update(pk_seed);
    hasher.update(&[0u8; PAD256]);
    hasher.update(&adrsc);
    hasher.update(sk_seed);
    hasher.finalize()
}

// ── PRF_msg: message randomizer ─────────────────────────────────────

/// `PRF_msg(SK.prf, opt_rand, M)` — FIPS 205 §10.1.
///
/// Computes `Trunc_n(HMAC-SHA-512(SK.prf, opt_rand ‖ m_prefix ‖ msg))`.
/// For SLH-DSA-SHA2-256s n=32, the 64-byte SHA-512 HMAC output is truncated
/// to 32 bytes.  FIPS 205 §10.1 (SHA-2 instantiation, n=32).
///
/// `m_prefix` is absorbed between `opt_rand` and `msg` so that the
/// external API (FIPS 205 §9.2 Algorithm 22) can supply
/// `0x00 || |ctx| || ctx`.  Pass `&[]` to get the raw internal-primitive
/// behaviour (FIPS 205 §9.1 Algorithm 19).
pub(crate) fn prf_msg(
    sk_prf: &[u8; N],
    opt_rand: &[u8; N],
    m_prefix: &[u8],
    msg: &[u8],
) -> [u8; N] {
    // HMAC-SHA-512(key, data) — inlined per FIPS 198-1.
    // SHA-512 block size is 128 bytes.
    const BLOCK_SIZE: usize = 128;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Key is exactly N=32 bytes ≤ 128, so K₀ = key ‖ 0^96.
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

    // inner = SHA-512(ipad_key ‖ opt_rand ‖ m_prefix ‖ M)
    let mut inner = Sha512::new_internal();
    inner.update(&ipad_key);
    inner.update(opt_rand);
    inner.update(m_prefix);
    inner.update(msg);
    let inner_hash = inner.finalize(); // 64 bytes

    // outer = SHA-512(opad_key ‖ inner_hash)
    let mut outer = Sha512::new_internal();
    outer.update(&opad_key);
    outer.update(&inner_hash);
    let full = outer.finalize(); // 64 bytes

    // Truncate to N=32 bytes.
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

// ── H_msg: message hash ─────────────────────────────────────────────

/// `H_msg(R, PK.seed, PK.root, M)` — FIPS 205 §10.1.
///
/// Two-step construction (SHA-2-256s instantiation, n=32):
///
/// 1. `seed_inner = SHA-512(R ‖ PK.seed ‖ PK.root ‖ M)` — 64 bytes.
/// 2. `output = MGF1-SHA-512(R ‖ PK.seed ‖ seed_inner, m)` — m = 47 bytes.
///
/// This matches the SPHINCS+ / FIPS 205 SHA-2 reference implementation for
/// the "256" security level, which uses SHA-512 as the "big" hash in order
/// to produce sufficient pseudorandom output from the message.
///
/// Returns `(md, tree_idx, leaf_idx)` where:
/// - `md` is the FORS message digest (K*A bits, packed big-endian right-aligned
///   in a 64-byte buffer),
/// - `tree_idx` is the hyper-tree index (H − H/D bits),
/// - `leaf_idx` is the leaf index within the bottom XMSS tree (H/D bits).
///
/// `m_prefix` is absorbed into `seed_inner` between `pk_root` and `msg`
/// so that the external API (FIPS 205 §9.2 / §9.3 Algorithms 22 and 24)
/// can supply `0x00 || |ctx| || ctx`.  Pass `&[]` to get the raw
/// internal-primitive behaviour (FIPS 205 §9.1 Algorithms 19 and 20).
pub(crate) fn h_msg(
    r: &[u8; N],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    m_prefix: &[u8],
    msg: &[u8],
) -> HMsgOutput {
    use crate::params::{A, H, H_PRIME, K};

    // Declare constants first so they precede all statements (clippy::items_after_statements).
    const FORS_DIGEST_BYTES: usize = (K * A + 7) / 8; // 39
    const TREE_BYTES: usize = (H - H_PRIME + 7) / 8; // 7

    // ── Step 1: seed_inner = SHA-512(R ‖ PK.seed ‖ PK.root ‖ m_prefix ‖ M) ──
    let mut h_inner = Sha512::new_internal();
    h_inner.update(r);
    h_inner.update(pk_seed);
    h_inner.update(pk_root);
    h_inner.update(m_prefix);
    h_inner.update(msg);
    let seed_inner = h_inner.finalize(); // 64 bytes

    // ── Step 2: MGF1-SHA-512(R ‖ PK.seed ‖ seed_inner, 47 bytes) ──
    //
    // Total seed length = 32 + 32 + 64 = 128 bytes.
    // m = ceil(K*A/8) + ceil((H−H/D)/8) + ceil(H/D/8) = 39 + 7 + 1 = 47 bytes.
    // Each MGF1 block = SHA-512(seed ‖ toByte(i, 4)) = 64 bytes.
    // We need ceil(47/64) = 1 block (first 47 bytes of block 0).

    // MGF1 block 0 = SHA-512(R ‖ PK.seed ‖ seed_inner ‖ 0x00000000).
    let mut mgf = Sha512::new_internal();
    mgf.update(r);
    mgf.update(pk_seed);
    mgf.update(&seed_inner);
    mgf.update(&0u32.to_be_bytes());
    let block0 = mgf.finalize(); // 64 bytes; only first 47 bytes used

    // ── Extract FORS digest, tree index, leaf index ──
    //
    // The 47-byte layout follows the reference SPHINCS+ implementation:
    //   bytes  0..38  (39 bytes = 312 bits): FORS message digest.
    //                 4 leading zero bits (padding), then K × A = 308 FORS bits.
    //   bytes 39..45  (7 bytes):  hyper-tree index (56 used bits, big-endian).
    //   byte  46      (1 byte):   leaf index (8 bits).
    //
    // The FORS digest is stored right-aligned in a 64-byte array so that
    // `fors_index(md, i)` can find index i at bit offset
    //   (64*8 − ceil(K*A/8)*8) + i*A = 200 + i*14,
    // which corresponds to bit  (39*8 − K*A) + i*A = 4 + i*14  inside the
    // raw 39-byte digest — exactly the bit offset used by the C reference.

    let mut md = [0u8; 64];
    // Right-align the 39-byte FORS digest in the 64-byte md buffer.
    md[64 - FORS_DIGEST_BYTES..].copy_from_slice(&block0[..FORS_DIGEST_BYTES]);

    // Tree index: bytes [39..46] as a big-endian u64, masked to H−H/D bits.
    let mut tree_raw = 0u64;
    for b in &block0[FORS_DIGEST_BYTES..FORS_DIGEST_BYTES + TREE_BYTES] {
        tree_raw = (tree_raw << 8) | u64::from(*b);
    }
    let tree_bits = H - H_PRIME;
    let tree_mask = if tree_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << tree_bits) - 1
    };
    let tree_idx = tree_raw & tree_mask;

    // Leaf index: byte [46], masked to H/D bits.
    let leaf_mask = (1u32 << H_PRIME) - 1;
    let leaf_idx = u32::from(block0[FORS_DIGEST_BYTES + TREE_BYTES]) & leaf_mask;

    HMsgOutput {
        md,
        tree_idx,
        leaf_idx,
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

/// Extract a single `A`-bit FORS index from the message digest.
///
/// Index `i` corresponds to bits `[i*A .. (i+1)*A)` of the raw FORS
/// digest, interpreted MSB-first (FIPS 205 `base_W` / Algorithm 4).
///
/// The 39-byte FORS digest (`ceil(K*A/8) = 39` bytes, 312 bits) is
/// stored right-aligned in the 64-byte `md` array, so byte 0 of the
/// digest occupies byte 25 of `md`.  The first digest bit (MSB of
/// digest byte 0) lives at bit offset `64*8 - 39*8 = 200` in `md`.
pub(crate) fn fors_index(md: &[u8; 64], i: usize) -> u32 {
    use crate::params::A;
    // FORS_DIGEST_BYTES = ceil(K*A / 8) = ceil(308/8) = 39
    // The raw 39-byte FORS digest occupies bits [200..511] (right-aligned).
    // Extraction is MSB-first starting at bit 200 (NOT 204).
    let total_bits = crate::params::K * A; // 308
    let fors_bytes = (total_bits + 7) / 8; // 39
    let base_offset = 64 * 8 - fors_bytes * 8; // 512 - 312 = 200
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
