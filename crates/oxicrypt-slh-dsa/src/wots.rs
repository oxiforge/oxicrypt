//! WOTS+ (Winternitz One-Time Signature+) — FIPS 205 §5.
//!
//! WOTS+ signs a message digest by interpreting it as a sequence of
//! base-`W` digits and chaining a secret value `d[i]` steps through
//! the tweakable hash `F`.  Verification reconstructs the public key
//! from the signature by continuing each chain to position `W − 1`.
//!
//! With `W = 16` (4-bit digits) and `N = 32`:
//! - `LEN1 = 64` message chains.
//! - `LEN2 = 3` checksum chains.
//! - `LEN = 67` total chains, each `N` bytes → WOTS+ signature is
//!   `67 × 32 = 2144` bytes, and the compressed public key is `N = 32` bytes.

use crate::adrs::{Adrs, AdrsType};
use crate::params::{LEN, LEN1, LEN2, LG_W, N, W};
use crate::thash;

/// Size of a WOTS+ signature in bytes.
pub(crate) const WOTS_SIG_LEN: usize = LEN * N; // 2144

// ── Chain function (Algorithm 4) ────────────────────────────────────

/// Iterate the tweakable hash `F` from position `start` to `start + steps - 1`.
///
/// `chain(pk_seed, adrs, x, start, steps)` — FIPS 205 Algorithm 4.
fn chain(
    pk_seed: &[u8; N],
    adrs: &mut Adrs,
    x: &[u8; N],
    start: u32,
    steps: u32,
) -> [u8; N] {
    debug_assert!(start + steps <= W as u32);
    let mut tmp = *x;
    for j in start..start + steps {
        adrs.set_hash_address(j);
        tmp = thash::f(pk_seed, adrs, &tmp);
    }
    tmp
}

// ── Base-W encoding (Algorithm 3) ───────────────────────────────────

/// Convert the N-byte message `m` into base-W digits with a checksum.
///
/// Returns `LEN` digits in `[0, W)`.
fn base_w_with_checksum(m: &[u8; N]) -> [u8; LEN] {
    let mut msg = [0u8; LEN];

    // Message digits: split each byte into two 4-bit nibbles (W=16).
    for i in 0..LEN1 {
        let byte = m[i / 2];
        // High nibble for even i, low nibble for odd i.
        if i % 2 == 0 {
            msg[i] = byte >> LG_W as u8;
        } else {
            msg[i] = byte & ((W as u8) - 1);
        }
    }

    // Checksum: sum of (W - 1 - msg[i]) for i in 0..LEN1.
    let mut csum: u32 = 0;
    for i in 0..LEN1 {
        csum += (W as u32) - 1 - u32::from(msg[i]);
    }

    // Shift checksum left by (8 - ((LEN2 * lg(W)) mod 8)) mod 8.
    // LEN2 * LG_W = 3 * 4 = 12 bits.  (8 - 12%8) % 8 = (8-4)%8 = 4.
    csum <<= 4;

    // Extract LEN2 base-W digits from the checksum (big-endian).
    // Checksum occupies ceil(12/8) = 2 bytes after the shift.
    let csum_bytes = (csum as u16).to_be_bytes();
    for i in 0..LEN2 {
        let total_idx = LEN1 + i;
        let bit_offset = i * LG_W;
        let byte_idx = bit_offset / 8;
        let shift = 8 - LG_W - (bit_offset % 8);
        msg[total_idx] = (csum_bytes[byte_idx] >> shift as u8) & ((W as u8) - 1);
    }

    msg
}

// ── WOTS+ key generation (Algorithm 5) ──────────────────────────────

/// Generate a WOTS+ public key.
///
/// `wots_pkgen(pk_seed, sk_seed, adrs)` — FIPS 205 Algorithm 5.
///
/// The address `adrs` must have `layer`, `tree`, and `keypair`
/// already set.  Returns the compressed public key (`N` bytes).
pub(crate) fn wots_pkgen(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    adrs: &Adrs,
) -> [u8; N] {
    // Buffer for the concatenation of LEN chain endpoints.
    let mut tmp = [0u8; LEN * N];

    let mut sk_adrs = *adrs;
    sk_adrs.set_type(AdrsType::WotsPrf);
    sk_adrs.set_keypair_address(adrs.keypair_address());

    let mut chain_adrs = *adrs;
    chain_adrs.set_type(AdrsType::WotsHash);
    chain_adrs.set_keypair_address(adrs.keypair_address());

    for i in 0..LEN {
        // Secret key element.
        sk_adrs.set_chain_address(i as u32);
        let sk_i = thash::prf(pk_seed, sk_seed, &sk_adrs);

        // Chain from 0 to W-1.
        chain_adrs.set_chain_address(i as u32);
        let pk_i = chain(pk_seed, &mut chain_adrs, &sk_i, 0, (W - 1) as u32);
        tmp[i * N..(i + 1) * N].copy_from_slice(&pk_i);
    }

    // Compress to a single N-byte public key using T_len.
    let mut pk_adrs = *adrs;
    pk_adrs.set_type(AdrsType::WotsPk);
    pk_adrs.set_keypair_address(adrs.keypair_address());
    thash::t(pk_seed, &pk_adrs, &tmp)
}

// ── WOTS+ signing (Algorithm 6) ─────────────────────────────────────

/// Sign an N-byte message with WOTS+.
///
/// `wots_sign(pk_seed, sk_seed, adrs, m)` — FIPS 205 Algorithm 6.
///
/// Returns a `LEN * N`-byte signature (a flat array of chain values).
pub(crate) fn wots_sign(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    adrs: &Adrs,
    m: &[u8; N],
) -> [u8; WOTS_SIG_LEN] {
    let msg = base_w_with_checksum(m);
    let mut sig = [0u8; WOTS_SIG_LEN];

    let mut sk_adrs = *adrs;
    sk_adrs.set_type(AdrsType::WotsPrf);
    sk_adrs.set_keypair_address(adrs.keypair_address());

    let mut chain_adrs = *adrs;
    chain_adrs.set_type(AdrsType::WotsHash);
    chain_adrs.set_keypair_address(adrs.keypair_address());

    for i in 0..LEN {
        sk_adrs.set_chain_address(i as u32);
        let sk_i = thash::prf(pk_seed, sk_seed, &sk_adrs);

        chain_adrs.set_chain_address(i as u32);
        let sig_i = chain(pk_seed, &mut chain_adrs, &sk_i, 0, u32::from(msg[i]));
        sig[i * N..(i + 1) * N].copy_from_slice(&sig_i);
    }

    sig
}

// ── WOTS+ public key from signature (Algorithm 7) ───────────────────

/// Reconstruct the WOTS+ public key from a signature and message.
///
/// `wots_pk_from_sig(pk_seed, adrs, sig, m)` — FIPS 205 Algorithm 7.
pub(crate) fn wots_pk_from_sig(
    pk_seed: &[u8; N],
    adrs: &Adrs,
    sig: &[u8],
    m: &[u8; N],
) -> [u8; N] {
    let msg = base_w_with_checksum(m);
    let mut tmp = [0u8; LEN * N];

    let mut chain_adrs = *adrs;
    chain_adrs.set_type(AdrsType::WotsHash);
    chain_adrs.set_keypair_address(adrs.keypair_address());

    for i in 0..LEN {
        chain_adrs.set_chain_address(i as u32);
        let mut sig_i = [0u8; N];
        sig_i.copy_from_slice(&sig[i * N..(i + 1) * N]);

        let steps = (W as u32) - 1 - u32::from(msg[i]);
        let pk_i = chain(pk_seed, &mut chain_adrs, &sig_i, u32::from(msg[i]), steps);
        tmp[i * N..(i + 1) * N].copy_from_slice(&pk_i);
    }

    let mut pk_adrs = *adrs;
    pk_adrs.set_type(AdrsType::WotsPk);
    pk_adrs.set_keypair_address(adrs.keypair_address());
    thash::t(pk_seed, &pk_adrs, &tmp)
}
