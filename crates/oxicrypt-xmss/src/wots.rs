//! WOTS+ one-time signature scheme per RFC 8391 section 3.
//!
//! Implements the Winternitz OTS Plus scheme for parameter set
//! XMSS-SHA2_10_256 (n=32, w=16, len=67). WOTS+ differs from
//! LM-OTS in its use of randomized hashing with bitmasks and a
//! pseudorandom key schedule derived from a public seed via PRF.
//!
//! Lints: array indexing is bounded by compile-time constants.
//! Arithmetic operates on small, bounded values (chain indices,
//! digit extraction, tree heights).
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop,
    clippy::many_single_char_names
)]

use oxicrypt_sha::sha256::Sha256;

use crate::adrs::Adrs;

/// Hash output size (n = 32).
pub(crate) const N: usize = 32;

/// Winternitz parameter (w = 16).
const W: usize = 16;

/// Number of message digits: ceil(8*n / lg(w)) = 64.
const LEN_1: usize = 64;

/// Total chains: LEN_1 + checksum digits (3).
pub(crate) const LEN: usize = 67;

/// Maximum chain value: w - 1 = 15.
const MAX_CHAIN: u8 = 15;

// ── Hash function abstractions (RFC 8391 §5.1 for SHA2-256) ────

/// toByte(x, 32): a 32-byte big-endian encoding of `x`.
const fn to_byte_32(x: u8) -> [u8; N] {
    let mut buf = [0u8; N];
    buf[N - 1] = x;
    buf
}

/// Domain separation prefix for F (chaining function).
const PAD_F: [u8; N] = to_byte_32(0);

/// Domain separation prefix for PRF.
const PAD_PRF: [u8; N] = to_byte_32(3);

/// PRF(KEY, M) = SHA-256(toByte(3,32) || KEY || M)
fn prf(key: &[u8; N], m: &[u8]) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(&PAD_PRF);
    h.update(key);
    h.update(m);
    h.finalize()
}

/// F(KEY, M) = SHA-256(toByte(0,32) || KEY || M)
fn f_hash(key: &[u8; N], m: &[u8; N]) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(&PAD_F);
    h.update(key);
    h.update(m);
    h.finalize()
}

// ── Digit extraction (base_w) ───────────────────────────────────

/// Extract the `i`-th base-w (w=16) digit from byte string `s`.
///
/// For w=16, lg(w)=4, so each byte yields 2 digits (high nibble
/// first). This is the `base_w` function from RFC 8391 §2.6.
fn base_w(s: &[u8], i: usize) -> u8 {
    let byte_idx = i / 2;
    let shift = if i.is_multiple_of(2) { 4 } else { 0 };
    (s[byte_idx] >> shift) & 0x0F
}

/// Compute the WOTS+ checksum over message digits.
///
/// csum = sum_{i=0}^{len_1-1} (w - 1 - msg_i)
fn wots_checksum(msg: &[u8; N]) -> u16 {
    let mut sum: u32 = 0;
    for i in 0..LEN_1 {
        sum += u32::from(MAX_CHAIN) - u32::from(base_w(msg, i));
    }
    sum as u16
}

/// Extract the `i`-th digit from the message hash concatenated
/// with the shifted checksum (LEN digits total).
fn msg_digit(msg: &[u8; N], i: usize) -> u8 {
    if i < LEN_1 {
        base_w(msg, i)
    } else {
        let csum = wots_checksum(msg);
        // ls = 8 - ((len_2 * lg(w)) % 8) = 8 - (12 % 8) = 4
        let csum_bytes = (csum << 4).to_be_bytes();
        base_w(&csum_bytes, i - LEN_1)
    }
}

// ── WOTS+ chain function ────────────────────────────────────────

/// One step of the WOTS+ chain.
///
/// Generates KEY and BM from pub_seed via PRF, then computes
/// F(KEY, tmp XOR BM). The ADRS is updated with the hash address
/// and key-and-mask flag per RFC 8391 §3.1.
fn chain_step(tmp: &[u8; N], j: u32, pub_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    adrs.set_hash_address(j);

    // KEY = PRF(pub_seed, ADRS with keyAndMask=0)
    adrs.set_key_and_mask(0);
    let key = prf(pub_seed, &adrs.bytes());

    // BM = PRF(pub_seed, ADRS with keyAndMask=1)
    adrs.set_key_and_mask(1);
    let bm = prf(pub_seed, &adrs.bytes());

    // F(KEY, tmp XOR BM)
    let mut xored = [0u8; N];
    for k in 0..N {
        xored[k] = tmp[k] ^ bm[k];
    }
    f_hash(&key, &xored)
}

/// Apply the WOTS+ chain from step `start` for `steps` iterations.
fn chain(x: &[u8; N], start: u32, steps: u32, pub_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut tmp = *x;
    for j in start..start + steps {
        tmp = chain_step(&tmp, j, pub_seed, adrs);
    }
    tmp
}

// ── WOTS+ key generation ────────────────────────────────────────

/// Derive WOTS+ secret key element `sk[i]` for OTS key pair at
/// leaf `ots_addr`.
///
/// sk\[i\] = PRF(sk_seed, ADRS) with ADRS encoding (ots_addr, chain=i, hash=0).
fn derive_sk_element(
    sk_seed: &[u8; N],
    _pub_seed: &[u8; N],
    ots_addr: u32,
    chain_idx: u32,
) -> [u8; N] {
    let mut adrs = Adrs::new();
    adrs.set_type(Adrs::OTS_HASH);
    adrs.set_ots_address(ots_addr);
    adrs.set_chain_address(chain_idx);
    adrs.set_hash_address(0);
    adrs.set_key_and_mask(0);
    // Use PRF with sk_seed to derive the secret key element.
    // PRF_keygen(SK_SEED, ADRS) — RFC 8391 §4.1.11
    prf(sk_seed, &adrs.bytes())
}

/// Compute the WOTS+ public key for leaf `ots_addr`.
///
/// Returns `len` chain endpoints concatenated. The result is
/// then compressed by the L-tree into a single n-byte value.
pub(crate) fn wots_pk_gen(sk_seed: &[u8; N], pub_seed: &[u8; N], ots_addr: u32) -> [[u8; N]; LEN] {
    let mut pk = [[0u8; N]; LEN];
    for i in 0..LEN {
        let sk_i = derive_sk_element(sk_seed, pub_seed, ots_addr, i as u32);
        let mut adrs = Adrs::new();
        adrs.set_type(Adrs::OTS_HASH);
        adrs.set_ots_address(ots_addr);
        adrs.set_chain_address(i as u32);
        pk[i] = chain(&sk_i, 0, W as u32 - 1, pub_seed, &mut adrs);
    }
    pk
}

// ── WOTS+ signing ───────────────────────────────────────────────

/// Create a WOTS+ signature of `msg_hash` at leaf `ots_addr`.
///
/// Returns `len` chain intermediate values.
pub(crate) fn wots_sign(
    msg_hash: &[u8; N],
    sk_seed: &[u8; N],
    pub_seed: &[u8; N],
    ots_addr: u32,
) -> [[u8; N]; LEN] {
    let mut sig = [[0u8; N]; LEN];
    for i in 0..LEN {
        let sk_i = derive_sk_element(sk_seed, pub_seed, ots_addr, i as u32);
        let a = u32::from(msg_digit(msg_hash, i));
        let mut adrs = Adrs::new();
        adrs.set_type(Adrs::OTS_HASH);
        adrs.set_ots_address(ots_addr);
        adrs.set_chain_address(i as u32);
        sig[i] = chain(&sk_i, 0, a, pub_seed, &mut adrs);
    }
    sig
}

// ── WOTS+ verification (pk from sig) ────────────────────────────

/// Compute the WOTS+ public key candidate from a signature.
///
/// Completes each chain from the signature value to the endpoint.
pub(crate) fn wots_pk_from_sig(
    msg_hash: &[u8; N],
    sig: &[[u8; N]; LEN],
    pub_seed: &[u8; N],
    ots_addr: u32,
) -> [[u8; N]; LEN] {
    let mut pk = [[0u8; N]; LEN];
    for i in 0..LEN {
        let a = u32::from(msg_digit(msg_hash, i));
        let remaining = W as u32 - 1 - a;
        let mut adrs = Adrs::new();
        adrs.set_type(Adrs::OTS_HASH);
        adrs.set_ots_address(ots_addr);
        adrs.set_chain_address(i as u32);
        pk[i] = chain(&sig[i], a, remaining, pub_seed, &mut adrs);
    }
    pk
}
