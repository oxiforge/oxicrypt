//! Keccak-f\[1600\] permutation and a sponge construction.
//!
//! This module implements the shared primitive used by SHA-3
//! (fixed-length) and SHAKE (XOF). The SHA-3 family is specified in
//! FIPS 202, which defines:
//!
//!   KECCAK-p\[1600, 24\]  — the 1600-bit permutation (a.k.a. Keccak-f)
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

/// Number of rounds in Keccak-f\[1600\].
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

/// Keccak-f\[1600\] permutation.
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
/// Implements SPONGE\[KECCAK-p\[1600,24\], pad10*1, r\] from FIPS 202
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

impl<const RATE_BYTES: usize> Drop for Sponge<RATE_BYTES> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize_u64(&mut self.state);
    }
}

// ------------------------------------------------------------------------
// Batched 4-way sponge
// ------------------------------------------------------------------------

/// Four independent Keccak sponges run in lockstep.
///
/// `Sponge4` holds four independent 25-lane Keccak states and drives
/// them through the same SPONGE\[KECCAK-p\[1600,24\], pad10*1, r\]
/// lifecycle as the single-stream [`Sponge`], with one difference: the
/// permutation is applied to all four states together. When the
/// `accel-keccak` feature is enabled and the CPU supports it, that
/// batched permutation dispatches to the AVX2 4-way path in
/// `oxicrypt-keccak-accel`; otherwise (and in every default build) it
/// runs the portable [`keccak_f1600`] on each of the four states. The
/// emitted bytes are byte-for-byte identical to running four separate
/// [`Sponge`]s — only the execution unit of the permutation differs.
///
/// # Equal-length precondition
///
/// `Sponge4` batches the realistic case in which the four streams have
/// **the same input length and the same output length** (e.g. four
/// SHAKE calls with a common message length and a common output length).
/// Under that precondition all four sponges reach a rate boundary at the
/// same `offset`, so a single batched permutation advances all four in
/// lockstep — which is what makes the batching sound. The four absorb
/// slices passed to [`absorb_4`](Sponge4::absorb_4) must therefore share
/// one length, and the four squeeze slices passed to
/// [`squeeze_4`](Sponge4::squeeze_4) must share one length; both are
/// `debug_assert!`-checked. The unequal-length generalization is
/// intentionally out of scope (a caller needing it simply does not
/// batch and runs four single [`Sponge`]s instead).
///
/// Lifecycle, mirroring [`Sponge`]:
///   `new()` → `absorb_4()` (repeatedly) → `finalize_4(domain)` →
///   `squeeze_4()`
#[derive(Clone)]
pub struct Sponge4<const RATE_BYTES: usize> {
    states: [[u64; LANES]; 4],
    /// Byte offset within the current rate block (0..RATE_BYTES),
    /// shared across all four states by the equal-length precondition.
    offset: usize,
    /// True once `finalize_4` has been called.
    finalized: bool,
}

impl<const RATE_BYTES: usize> Sponge4<RATE_BYTES> {
    /// Creates four fresh sponges, each with an all-zero state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            states: [[0u64; LANES]; 4],
            offset: 0,
            finalized: false,
        }
    }

    /// Absorbs one slice into each of the four sponges.
    ///
    /// `inputs[i]` is absorbed into state `i`. All four slices must share
    /// the same length (the equal-length precondition); when they do,
    /// every state crosses a rate boundary at the same `offset`, so the
    /// single batched permutation keeps all four synchronized.
    ///
    /// # Panics
    ///
    /// Panics (debug only) if called after `finalize_4`, or if the four
    /// input slices do not all have the same length.
    pub fn absorb_4(&mut self, inputs: [&[u8]; 4]) {
        debug_assert!(!self.finalized, "absorb after finalize");
        let len = inputs[0].len();
        debug_assert!(
            inputs.iter().all(|s| s.len() == len),
            "Sponge4::absorb_4 requires equal-length inputs",
        );
        for pos in 0..len {
            for stream in 0..4 {
                Self::xor_byte(&mut self.states[stream], self.offset, inputs[stream][pos]);
            }
            self.offset += 1;
            if self.offset == RATE_BYTES {
                self.permute4();
                self.offset = 0;
            }
        }
    }

    /// Pads each of the four sponges with pad10*1, XORs in the domain
    /// byte, and runs one batched permutation. After this call,
    /// `squeeze_4` may be used to extract output bytes.
    ///
    /// The padding is byte-for-byte the single-[`Sponge`] pad10*1 applied
    /// to each state at the shared `offset` (FIPS 202 §B.2).
    ///
    /// # Panics
    ///
    /// Panics (debug only) if called more than once.
    pub fn finalize_4(&mut self, domain: u8) {
        debug_assert!(!self.finalized, "double finalize");
        for stream in 0..4 {
            Self::xor_byte(&mut self.states[stream], self.offset, domain);
            Self::xor_byte(&mut self.states[stream], RATE_BYTES - 1, 0x80);
        }
        self.permute4();
        self.offset = 0;
        self.finalized = true;
    }

    /// Squeezes `outs[i].len()` bytes of output from sponge `i`.
    ///
    /// May be called repeatedly after `finalize_4` — the SHAKE XOFs rely
    /// on this. All four output slices must share the same length (the
    /// equal-length precondition), so every state crosses a rate boundary
    /// at the same `offset` and one batched permutation refills all four.
    ///
    /// # Panics
    ///
    /// Panics (debug only) if called before `finalize_4`, or if the four
    /// output slices do not all have the same length.
    // Taken by value, not by reference: writing through each inner
    // `&mut [u8]` requires owning the array of mutable references (a
    // `&[&mut [u8]; 4]` would only grant shared access to the elements).
    #[allow(clippy::needless_pass_by_value)]
    pub fn squeeze_4(&mut self, outs: [&mut [u8]; 4]) {
        debug_assert!(self.finalized, "squeeze before finalize");
        let len = outs[0].len();
        debug_assert!(
            outs.iter().all(|o| o.len() == len),
            "Sponge4::squeeze_4 requires equal-length outputs",
        );
        let mut produced = 0;
        while produced < len {
            if self.offset == RATE_BYTES {
                self.permute4();
                self.offset = 0;
            }
            let take = core::cmp::min(RATE_BYTES - self.offset, len - produced);
            for i in 0..take {
                let pos = self.offset + i;
                for stream in 0..4 {
                    outs[stream][produced + i] = Self::read_byte(&self.states[stream], pos);
                }
            }
            self.offset += take;
            produced += take;
        }
    }

    /// The single batched-permutation point. With the `accel-keccak`
    /// feature enabled, dispatches the four states to the AVX2 4-way path
    /// when CPUID confirms support; otherwise (and always in default
    /// builds) runs the portable [`keccak_f1600`] on each of the four.
    /// Either way the result is byte-for-byte four independent
    /// permutations.
    #[inline]
    fn permute4(&mut self) {
        #[cfg(feature = "accel-keccak")]
        {
            if oxicrypt_keccak_accel::keccak_f1600_x4(&mut self.states) {
                return;
            }
        }
        for s in &mut self.states {
            keccak_f1600(s);
        }
    }

    /// XORs a single byte into one state at byte position `pos` within
    /// the rate — identical lane math to [`Sponge::xor_byte`].
    #[inline]
    fn xor_byte(state: &mut [u64; LANES], pos: usize, byte: u8) {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        state[lane] ^= u64::from(byte) << shift;
    }

    /// Reads a single byte from one state at byte position `pos` within
    /// the rate — identical lane math to [`Sponge::read_byte`].
    #[inline]
    fn read_byte(state: &[u64; LANES], pos: usize) -> u8 {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        ((state[lane] >> shift) & 0xff) as u8
    }
}

impl<const RATE_BYTES: usize> Default for Sponge4<RATE_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RATE_BYTES: usize> Drop for Sponge4<RATE_BYTES> {
    fn drop(&mut self) {
        for s in &mut self.states {
            oxicrypt_zeroize::zeroize_u64(s);
        }
    }
}

// ------------------------------------------------------------------------
// Permutation unit tests
// ------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    extern crate std;

    use super::{LANES, Sponge, Sponge4, keccak_f1600};

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

    // --------------------------------------------------------------------
    // Sponge4 batched-vs-single oracle
    // --------------------------------------------------------------------

    /// Tiny deterministic PRNG (splitmix64) so the batched-vs-single
    /// comparison is reproducible without an `rand` dependency.
    struct SplitMix64 {
        state: u64,
    }

    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = (self.next_u64() & 0xff) as u8;
            }
        }
    }

    /// Core oracle body: at a given rate `R`, for a spread of equal input
    /// lengths and equal output lengths (output spanning ≥ 3 rate blocks),
    /// assert each of the four `Sponge4<R>` outputs is byte-identical to
    /// the corresponding single `Sponge<R>`. Exercised for both the SHAKE
    /// domain byte (0x1f) and the SHA-3 domain byte (0x06).
    fn sponge4_equals_4x_single<const R: usize>(seed: u64) {
        let mut prng = SplitMix64::new(seed);
        // Input lengths chosen to straddle rate boundaries (0, partial,
        // exactly one rate, multi-rate). Output spans ≥ 3 rate blocks.
        let in_lens = [0usize, 1, R - 1, R, R + 5, 2 * R + 3];
        let out_lens = [1usize, R, 3 * R + 7];

        for &domain in &[0x1fu8, 0x06u8] {
            for &in_len in &in_lens {
                for &out_len in &out_lens {
                    // Four independent random inputs of the SAME length.
                    let mut inputs = [
                        std::vec![0u8; in_len],
                        std::vec![0u8; in_len],
                        std::vec![0u8; in_len],
                        std::vec![0u8; in_len],
                    ];
                    for inp in &mut inputs {
                        prng.fill(inp);
                    }

                    // Reference: four single sponges.
                    let mut single_outs = [
                        std::vec![0u8; out_len],
                        std::vec![0u8; out_len],
                        std::vec![0u8; out_len],
                        std::vec![0u8; out_len],
                    ];
                    for stream in 0..4 {
                        let mut sp = Sponge::<R>::new();
                        sp.absorb(&inputs[stream]);
                        sp.finalize(domain);
                        sp.squeeze(&mut single_outs[stream]);
                    }

                    // Batched: one Sponge4.
                    let mut batch_outs = [
                        std::vec![0u8; out_len],
                        std::vec![0u8; out_len],
                        std::vec![0u8; out_len],
                        std::vec![0u8; out_len],
                    ];
                    let mut sp4 = Sponge4::<R>::new();
                    sp4.absorb_4([&inputs[0], &inputs[1], &inputs[2], &inputs[3]]);
                    sp4.finalize_4(domain);
                    {
                        let [o0, o1, o2, o3] = &mut batch_outs;
                        sp4.squeeze_4([o0, o1, o2, o3]);
                    }

                    for stream in 0..4 {
                        assert_eq!(
                            batch_outs[stream], single_outs[stream],
                            "Sponge4 stream {stream} diverged at R={R} domain={domain:#x} \
                             in_len={in_len} out_len={out_len}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn sponge4_matches_4x_single_portable() {
        // Always-on portable oracle (feature OFF): the 4× scalar fallback
        // inside Sponge4 must reproduce four independent single sponges
        // byte-for-byte. Run at the SHAKE128 rate (168) and SHAKE256
        // rate (136), both domain bytes, multi-block inputs and outputs.
        sponge4_equals_4x_single::<168>(0x5301_4b45_0000_0001);
        sponge4_equals_4x_single::<136>(0x5301_4b45_0000_0002);
    }

    #[cfg(all(test, feature = "accel-keccak"))]
    #[test]
    fn sponge4_matches_4x_single_accel() {
        // Feature-ON oracle: exercises the batched AVX2 dispatch through
        // the sponge (when CPUID confirms AVX2; else the same 4× scalar
        // fallback). Multi-block inputs/outputs force multiple
        // permutations, so the batched permutation path is hit. Equality
        // with four single sponges must still hold byte-for-byte.
        sponge4_equals_4x_single::<168>(0xacce_0168_0000_0168);
        sponge4_equals_4x_single::<136>(0xacce_0136_0000_0136);
    }
}
