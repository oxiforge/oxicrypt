//! Keccak-f[1600] permutation and a sponge construction.
//!
//! This module implements the shared primitive used by SHA-3
//! (fixed-length) and SHAKE (XOF). The SHA-3 family is specified in
//! FIPS 202, which defines:
//!
//!   KECCAK-p[1600, 24]  — the 1600-bit permutation (a.k.a. Keccak-f)
//!   SPONGE[f, pad, r]    — the sponge construction
//!   SHA3-n, SHAKE-n      — concrete instances of SPONGE
//!
//! The sponge here is a minimal FIPS 202 implementation that covers
//! absorb → pad → squeeze with a single-shot pad (sufficient for all
//! SHA-3 and SHAKE variants we need). Per FIPS 140-3 IG 10.3.A each
//! concrete algorithm still owns its own power-up KAT; the shared
//! permutation does not get its own KAT.
//!
//! # Public visibility
//!
//! The module is `pub` so that `fips-xof` can depend on `fips-sha`
//! and reuse `Sponge` for SHAKE128/SHAKE256 rather than duplicating
//! the permutation. The types are stable inside the module's
//! public API but are not guaranteed to be stable across crate
//! versions.
//!
//! See `sha256.rs` for the rationale behind the module-level lint
//! allows.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    clippy::integer_division
)]

/// Width of the Keccak state, in lanes. Each lane is a `u64`.
pub const LANES: usize = 25;

/// Number of rounds in Keccak-f[1600].
pub const ROUNDS: usize = 24;

/// Round constants RC from FIPS 202 §3.2.5.
const RC: [u64; ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// ρ-step rotation offsets, indexed by `x + 5*y`, from FIPS 202 §3.2.2.
const RHO: [u32; LANES] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14, //
];

/// Keccak-f[1600] permutation.
///
/// In-place; operates on a state of 25 `u64` lanes. Implements the
/// θ, ρ, π, χ, ι step mapping exactly as specified in FIPS 202 §3.2.
pub fn keccak_f1600(state: &mut [u64; LANES]) {
    for round in 0..ROUNDS {
        // θ step: column parity.
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ and π steps, combined: b[y][2*x + 3*y] = rot(state[x][y], r[x][y])
        let mut b = [0u64; LANES];
        for y in 0..5 {
            for x in 0..5 {
                let idx = x + 5 * y;
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                b[new_x + 5 * new_y] = state[idx].rotate_left(RHO[idx]);
            }
        }

        // χ step: nonlinear layer.
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
            }
        }

        // ι step: inject the round constant.
        state[0] ^= RC[round];
    }
}

// ------------------------------------------------------------------------
// Sponge
// ------------------------------------------------------------------------

/// Keccak sponge with a configurable rate.
///
/// Implements SPONGE[KECCAK-p[1600,24], pad10*1, r] from FIPS 202
/// §4. The rate `RATE_BYTES` is given in bytes and must be a
/// multiple of 8 (all FIPS 202 rates are). The capacity is
/// implicitly `1600 - 8*RATE_BYTES` bits.
///
/// Sponge lifecycle:
///   new() → absorb() (repeatedly) → finalize(domain) → squeeze()
///
/// `finalize` performs the pad10*1 padding with the algorithm-specific
/// domain separation byte (0x06 for SHA-3, 0x1f for SHAKE) and runs
/// the permutation. After `finalize`, only `squeeze` is legal.
#[derive(Clone)]
pub struct Sponge<const RATE_BYTES: usize> {
    state: [u64; LANES],
    /// Byte offset within the current rate block (0..RATE_BYTES).
    /// During absorb this is the count of bytes XORed in since the
    /// last permutation. During squeeze this is the count of bytes
    /// read out of the current output block.
    offset: usize,
    /// True once `finalize` has been called.
    finalized: bool,
}

impl<const RATE_BYTES: usize> Sponge<RATE_BYTES> {
    /// Creates a fresh sponge with an all-zero state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [0u64; LANES],
            offset: 0,
            finalized: false,
        }
    }

    /// Absorbs `data` into the sponge.
    ///
    /// # Panics
    ///
    /// Panics (debug only) if called after `finalize`.
    pub fn absorb(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized, "absorb after finalize");
        for &byte in data {
            self.xor_byte(self.offset, byte);
            self.offset += 1;
            if self.offset == RATE_BYTES {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
        }
    }

    /// Pads with the pad10*1 scheme, XORs in the domain byte, and
    /// runs one permutation. After this call, `squeeze` may be used
    /// to extract output bytes.
    pub fn finalize(&mut self, domain: u8) {
        debug_assert!(!self.finalized, "double finalize");
        // pad10*1: XOR domain byte at current offset, then set MSB of
        // the final byte of the rate. FIPS 202 §B.2 describes this
        // as appending "domain || 10...01" within the rate block; in
        // byte-oriented form that is a single byte `domain` at offset,
        // zero fill, and a 0x80 XOR at the last byte of the block.
        self.xor_byte(self.offset, domain);
        self.xor_byte(RATE_BYTES - 1, 0x80);
        keccak_f1600(&mut self.state);
        self.offset = 0;
        self.finalized = true;
    }

    /// Squeezes `out.len()` bytes of output from the sponge.
    ///
    /// May be called repeatedly after `finalize` — the SHAKE XOFs
    /// rely on this. SHA-3 fixed-length hashes call `squeeze` exactly
    /// once with an output slice whose length is smaller than the
    /// rate, so no further permutation is triggered.
    ///
    /// # Panics
    ///
    /// Panics (debug only) if called before `finalize`.
    pub fn squeeze(&mut self, mut out: &mut [u8]) {
        debug_assert!(self.finalized, "squeeze before finalize");
        while !out.is_empty() {
            if self.offset == RATE_BYTES {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
            let take = core::cmp::min(RATE_BYTES - self.offset, out.len());
            for i in 0..take {
                out[i] = self.read_byte(self.offset + i);
            }
            self.offset += take;
            // Split off the filled portion.
            let (_, rest) = out.split_at_mut(take);
            out = rest;
        }
    }

    /// XORs a single byte into the state at byte position `pos`
    /// within the rate.
    #[inline]
    fn xor_byte(&mut self, pos: usize, byte: u8) {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        self.state[lane] ^= u64::from(byte) << shift;
    }

    /// Reads a single byte from the state at byte position `pos`
    /// within the rate.
    #[inline]
    fn read_byte(&self, pos: usize) -> u8 {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        ((self.state[lane] >> shift) & 0xff) as u8
    }
}

impl<const RATE_BYTES: usize> Default for Sponge<RATE_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------------------------------
// Permutation unit tests
// ------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{keccak_f1600, Sponge, LANES};

    #[test]
    fn permutation_all_zero_after_one_round_matches_known_lane0() {
        // After one Keccak-f[1600] on the all-zero state, lane 0
        // equals RC[0] = 1. Easy sanity check that the ι step is
        // wired up.
        let mut state = [0u64; LANES];
        // Run only a single round by clobbering the rest with a
        // helper.
        for round in 0..1 {
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for y in 0..5 {
                for x in 0..5 {
                    state[x + 5 * y] ^= d[x];
                }
            }
            let mut b = [0u64; LANES];
            for y in 0..5 {
                for x in 0..5 {
                    let idx = x + 5 * y;
                    let new_x = y;
                    let new_y = (2 * x + 3 * y) % 5;
                    b[new_x + 5 * new_y] = state[idx].rotate_left(super::RHO[idx]);
                }
            }
            for y in 0..5 {
                for x in 0..5 {
                    state[x + 5 * y] =
                        b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
                }
            }
            state[0] ^= super::RC[round];
        }
        assert_eq!(state[0], 1);
    }

    #[test]
    fn full_permutation_of_zero_state_is_deterministic() {
        // After 24 rounds the state is deterministic; we cross-check
        // against the higher-level SHA3 KATs rather than hand-rolling
        // a permutation vector here. The actual SHA3-256("") KAT in
        // sha3.rs is the authoritative end-to-end check.
        let mut a = [0u64; LANES];
        let mut b = [0u64; LANES];
        keccak_f1600(&mut a);
        keccak_f1600(&mut b);
        assert_eq!(a, b);
        // And the result is not all zero.
        assert!(a.iter().any(|&x| x != 0));
    }

    #[test]
    fn sponge_absorb_finalize_squeeze_roundtrip() {
        // Minimal sanity: absorb nothing, finalize with 0x1f,
        // squeeze two blocks. Must be deterministic and not panic.
        let mut sp = Sponge::<136>::new();
        sp.absorb(&[]);
        sp.finalize(0x1f);
        let mut out = [0u8; 272];
        sp.squeeze(&mut out);
        assert!(out.iter().any(|&x| x != 0));
    }
}
