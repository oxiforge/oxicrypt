//! LM-OTS one-time signature scheme per RFC 8554 section 4.
//!
//! Implements parameter set LMOTS_SHA256_N32_W4 (type 0x0003).
//! All hash operations use `Sha256::new_internal()` so that the
//! self-test can run during the `SelfTest` module state.
//!
//! Lints: array indexing is statically bounded by constants and
//! loop ranges in this module. Arithmetic is on small, bounded
//! constants (chain indices, nibble extraction). Both lints are
//! disabled at the module level; they remain active workspace-wide.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop,
)]

use oxicrypt_sha::sha256::Sha256;

// ── Parameter set: LMOTS_SHA256_N32_W4 (RFC 8554 §4.1) ─────────

/// Hash output length in bytes (n).
pub(crate) const N: usize = 32;

/// Number of message-hash digits: ceil(8*n / w) = 64.
const U: usize = 64;

/// Total hash chains: U + V = 67.
pub(crate) const P: usize = 67;

/// Checksum left-shift: 16 - V*W = 4.
const LS: u32 = 4;

/// RFC 8554 type code for LMOTS_SHA256_N32_W4.
pub(crate) const LMOTS_TYPE: u32 = 0x0000_0003;

/// Maximum chain steps: 2^W - 1 = 15.
const MAX_CHAIN: u8 = 15;

/// Diversifier for public key generation (RFC 8554 §4.3).
const D_PBLC: u16 = 0x8080;

/// Diversifier for message hashing (RFC 8554 §4.5).
const D_MESG: u16 = 0x8181;

/// LM-OTS signature length: type(4) + C(N) + y(P*N) = 2180.
pub(crate) const OTS_SIG_LEN: usize = 4 + N + P * N;

// ── Digit extraction ────────────────────────────────────────────

/// Extract the `i`-th 4-bit (w=4) digit from byte string `s`.
///
/// High nibble is digit 0 within each byte, low nibble is digit 1.
/// RFC 8554 §4.2.
fn coef(s: &[u8], i: usize) -> u8 {
    let byte_idx = i / 2;
    let shift = if i.is_multiple_of(2) { 4 } else { 0 };
    (s[byte_idx] >> shift) & 0x0F
}

/// Compute the LM-OTS checksum over message hash `q_hash`.
///
/// Cksm(Q) = sum_{i=0}^{u-1} (2^w - 1 - coef(Q, i, w))
/// RFC 8554 §4.4.
fn checksum(q_hash: &[u8; N]) -> u16 {
    let mut sum: u32 = 0;
    for i in 0..U {
        sum += u32::from(MAX_CHAIN) - u32::from(coef(q_hash, i));
    }
    // Max sum = 64 * 15 = 960, fits u16.
    sum as u16
}

/// Build the 34-byte concatenation Q || u16str(Cksm(Q) << ls)
/// and extract digit `i` from it.
fn coef_q_cksm(q_hash: &[u8; N], i: usize) -> u8 {
    if i < U {
        coef(q_hash, i)
    } else {
        let cksm = checksum(q_hash);
        let cksm_bytes = (cksm << LS).to_be_bytes();
        coef(&cksm_bytes, i - U)
    }
}

// ── Low-level hash helpers ──────────────────────────────────────

/// Derive LM-OTS private key element x_q[chain_idx] from seed.
///
/// x_q\[i\] = H(I || u32str(q) || u16str(i) || 0xff || SEED)
/// RFC 8554 Appendix A.
fn derive_x(
    seed: &[u8; N],
    i_val: &[u8; 16],
    q: u32,
    chain_idx: u16,
) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(i_val);
    h.update(&q.to_be_bytes());
    h.update(&chain_idx.to_be_bytes());
    h.update(&[0xff]);
    h.update(seed);
    h.finalize()
}

/// One step of the hash chain.
///
/// H(I || u32str(q) || u16str(chain_idx) || u8str(j) || tmp)
fn chain_step(
    i_val: &[u8; 16],
    q: u32,
    chain_idx: u16,
    j: u8,
    tmp: &[u8; N],
) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(i_val);
    h.update(&q.to_be_bytes());
    h.update(&chain_idx.to_be_bytes());
    h.update(&[j]);
    h.update(tmp);
    h.finalize()
}

/// Iterate the hash chain from `start_val` for `count` steps
/// beginning at step index `start_j`.
fn chain(
    i_val: &[u8; 16],
    q: u32,
    chain_idx: u16,
    start_j: u8,
    count: u8,
    start_val: &[u8; N],
) -> [u8; N] {
    let mut tmp = *start_val;
    for step in 0..count {
        tmp = chain_step(i_val, q, chain_idx, start_j + step, &tmp);
    }
    tmp
}

// ── Public key computation (Algorithm 1) ────────────────────────

/// Compute the LM-OTS public key hash K for leaf `q`.
///
/// K = H(I || u32str(q) || u16str(D_PBLC) || y\[0\] || … || y\[p-1\])
/// where y\[i\] = chain(x\[i\], 0, 2^w-1).
///
/// RFC 8554 §4.3 Algorithm 1.
pub(crate) fn compute_public_key(
    seed: &[u8; N],
    i_val: &[u8; 16],
    q: u32,
) -> [u8; N] {
    let mut kc = Sha256::new_internal();
    kc.update(i_val);
    kc.update(&q.to_be_bytes());
    kc.update(&D_PBLC.to_be_bytes());

    for i in 0..P {
        let x_i = derive_x(seed, i_val, q, i as u16);
        let y_i = chain(i_val, q, i as u16, 0, MAX_CHAIN, &x_i);
        kc.update(&y_i);
    }
    kc.finalize()
}

// ── Signing (Algorithm 3) ───────────────────────────────────────

/// Deterministic randomizer C.
///
/// C = H(I || u32str(q) || u16str(0xFFFD) || SEED || message)
/// RFC 8554 §4.5 note on deterministic generation.
fn compute_c(
    seed: &[u8; N],
    i_val: &[u8; 16],
    q: u32,
    message: &[u8],
) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(i_val);
    h.update(&q.to_be_bytes());
    h.update(&0xFFFDu16.to_be_bytes());
    h.update(seed);
    h.update(message);
    h.finalize()
}

/// Compute message hash Q.
///
/// Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
fn compute_q(
    i_val: &[u8; 16],
    q: u32,
    c: &[u8; N],
    message: &[u8],
) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(i_val);
    h.update(&q.to_be_bytes());
    h.update(&D_MESG.to_be_bytes());
    h.update(c);
    h.update(message);
    h.finalize()
}

/// Create an LM-OTS signature for the given leaf `q`.
///
/// Returns the serialized OTS signature (2180 bytes).
/// RFC 8554 §4.5 Algorithm 3.
pub(crate) fn ots_sign(
    seed: &[u8; N],
    i_val: &[u8; 16],
    q: u32,
    message: &[u8],
) -> [u8; OTS_SIG_LEN] {
    let c = compute_c(seed, i_val, q, message);
    let q_hash = compute_q(i_val, q, &c, message);

    let mut sig = [0u8; OTS_SIG_LEN];
    // type code
    sig[..4].copy_from_slice(&LMOTS_TYPE.to_be_bytes());
    // randomizer C
    sig[4..4 + N].copy_from_slice(&c);
    // signature values y[0..p-1]
    for i in 0..P {
        let a = coef_q_cksm(&q_hash, i);
        let x_i = derive_x(seed, i_val, q, i as u16);
        let y_i = chain(i_val, q, i as u16, 0, a, &x_i);
        let off = 4 + N + i * N;
        sig[off..off + N].copy_from_slice(&y_i);
    }
    sig
}

// ── Verification (Algorithm 4b) ─────────────────────────────────

/// Compute the candidate public key Kc from an OTS signature.
///
/// Returns `None` if the signature format is invalid (wrong length
/// or unrecognized type code).
///
/// RFC 8554 §4.6 Algorithm 4b.
pub(crate) fn ots_verify_candidate(
    i_val: &[u8; 16],
    q: u32,
    message: &[u8],
    ots_sig: &[u8],
) -> Option<[u8; N]> {
    if ots_sig.len() != OTS_SIG_LEN {
        return None;
    }

    // Parse and validate type code.
    let sig_type = u32::from_be_bytes([
        ots_sig[0], ots_sig[1], ots_sig[2], ots_sig[3],
    ]);
    if sig_type != LMOTS_TYPE {
        return None;
    }

    // Parse randomizer C.
    let mut c = [0u8; N];
    c.copy_from_slice(&ots_sig[4..4 + N]);

    // Recompute Q.
    let q_hash = compute_q(i_val, q, &c, message);

    // Reconstruct chain endpoints z[i] and compute Kc.
    let mut kc = Sha256::new_internal();
    kc.update(i_val);
    kc.update(&q.to_be_bytes());
    kc.update(&D_PBLC.to_be_bytes());

    for i in 0..P {
        let a = coef_q_cksm(&q_hash, i);
        let remaining = MAX_CHAIN - a;
        let off = 4 + N + i * N;
        let mut y_i = [0u8; N];
        y_i.copy_from_slice(&ots_sig[off..off + N]);
        let z_i = chain(i_val, q, i as u16, a, remaining, &y_i);
        kc.update(&z_i);
    }

    Some(kc.finalize())
}
