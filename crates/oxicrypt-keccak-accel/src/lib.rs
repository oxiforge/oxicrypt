//! CPU-intrinsic AVX2 4-way batched Keccak-f\[1600\] acceleration for
//! `oxicrypt-sha`.
//!
//! This is one of the small readily auditable in-boundary crates in the oxicrypt
//! workspace that use `unsafe` (alongside `oxicrypt-zeroize`,
//! `oxicrypt-sha-accel`, `oxicrypt-aes-accel`, and `oxicrypt-timer`). It
//! is the fifth such crate, and implements the sanctioned **CPU-intrinsic
//! acceleration** category: feature-gated, default-off, runtime-detected,
//! with equivalence to the portable permutation proven by a cross-path
//! oracle. All other in-boundary crates remain `#![forbid(unsafe_code)]`;
//! the authoritative unsafe-code accounting lives in
//! `docs/security-policy/security-policy.md` §9.2 "Isolation of `unsafe`".
//!
//! # Why a separate crate?
//!
//! Driving the AVX2 256-bit vector unit (`_mm256_xor_si256`,
//! `_mm256_andnot_si256`, the shift-pair rotates) behind a
//! `#[target_feature(enable = "avx2")]` boundary cannot be expressed in
//! safe Rust. `oxicrypt-sha` carries a literal, unconditional
//! `#![forbid(unsafe_code)]` that enters the CMVP conformance argument, so
//! the irreducible `unsafe` lives here — in a small, audit-shaped crate
//! mirroring the `oxicrypt-sha-accel` precedent. The acceleration changes
//! *where* the FIPS 202 §3.2 θ/ρ/π/χ/ι rounds execute (four independent
//! states permuted together in 256-bit lanes instead of one at a time on
//! the scalar ALU), not *what* they compute.
//!
//! # Containment
//!
//! - **Default-off.** This crate is wired into `oxicrypt-sha` only behind
//!   a feature; the portable baseline remains the shipping
//!   default and default dependency graphs are unchanged.
//! - **Runtime-detected.** One binary serves all CPUs: a hand-rolled
//!   CPUID probe (this crate is `no_std`, so `is_x86_feature_detected!`
//!   is unavailable) checks leaf 7 sub-leaf 0 EBX bit 5 (AVX2) plus the
//!   required AVX and SSE2 bits, and caches the verdict in an `AtomicU8`.
//! - **Fail-portable.** [`keccak_f1600_x4`] returns `false` — leaving the
//!   four input states **untouched** — whenever AVX2 is absent (or on any
//!   non-x86_64 target, where this crate compiles to a stub). The caller
//!   then runs the portable permutation four times; a wrong state is
//!   unreachable, and a partially-applied state is impossible.
//!
//! # Scope
//!
//! The AVX2 4-way `KeccakP1600times4` permutation only. AVX-512 8-way
//! batching is a documented follow-up under the same sanctioned category
//! (`docs/design/avx2-keccak.md`, issue #110).

#![no_std]
// This crate deliberately uses unsafe for CPU intrinsics and CPUID.
// The other in-boundary crates that use unsafe are oxicrypt-zeroize,
// oxicrypt-sha-accel, oxicrypt-aes-accel and oxicrypt-timer; every other
// in-boundary crate forbids it.
#![deny(unsafe_op_in_unsafe_fn)]

/// Returns `true` if the running CPU supports the AVX2 4-way batched
/// Keccak-f\[1600\] path (x86_64 with AVX2 + AVX + SSE2).
///
/// The first call probes CPUID; the verdict is cached in an `AtomicU8`
/// so subsequent calls are a single relaxed atomic load. On non-x86_64
/// targets this is a constant `false`.
#[must_use]
pub fn keccak_f1600_x4_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_avx2::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Apply Keccak-f\[1600\] to four independent states in parallel via AVX2.
///
/// Each `states[i]` is one 25-lane Keccak state (`[u64; 25]`, lane
/// `x + 5*y` at index `x + 5*y`, per FIPS 202 §3.1). The contract matches
/// the portable permutation `oxicrypt_sha::keccak::keccak_f1600`
/// bit-for-bit applied to each of the four states independently: same
/// lane layout, same 24-round θ/ρ/π/χ/ι mapping — only the execution unit
/// differs.
///
/// Returns `true` if the accelerated permutation ran (in which case all
/// four states have each been advanced by one full permutation), or
/// `false` if AVX2 is unavailable on this CPU or target — in which case
/// `states` is **untouched** and the caller must run its portable
/// permutation four times instead. This fail-portable contract makes a
/// silently wrong state unreachable: there is no code path that partially
/// applies the permutation.
pub fn keccak_f1600_x4(states: &mut [[u64; 25]; 4]) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_avx2::permute_x4(states)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Unreachable-by-contract stub: callers dispatch on
        // `keccak_f1600_x4_available()`, which is `false` here. Returning
        // `false` (states untouched) keeps the contract total and safe even
        // for callers that skip the availability check.
        let _ = states;
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64_avx2 {
    //! AVX2 4-way Keccak-f\[1600\] implementation.
    //!
    //! Layout: the four states are transposed on entry into 25
    //! `__m256i` lanes, where lane `i` holds state-lane `i` of all four
    //! states (state 0 in 64-bit element 0, …, state 3 in element 3). The
    //! 24-round θ/ρ/π/χ/ι mapping then runs entirely in the vector unit,
    //! and the lanes are transposed back to four `[u64; 25]` on exit.
    //!
    //! Lints: lane packing/unpacking reinterprets `u64` words as the `i64`
    //! elements the `_mm256_set_epi64x` / `_mm256_set1_epi64x` intrinsics
    //! are typed over (no numeric meaning), and every index below is
    //! statically bounded by a constant or a `for … in N..M` loop —
    //! mirroring the lint posture of `oxicrypt-sha`'s own keccak module.
    #![allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::many_single_char_names,
        clippy::needless_range_loop
    )]

    use core::arch::x86_64::{
        __cpuid_count, __m256i, _mm256_andnot_si256, _mm256_extract_epi64, _mm256_or_si256,
        _mm256_set_epi64x, _mm256_set1_epi64x, _mm256_slli_epi64, _mm256_srli_epi64,
        _mm256_xor_si256,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    /// Number of lanes in a Keccak-f\[1600\] state.
    const LANES: usize = 25;
    /// Number of rounds in Keccak-f\[1600\].
    const ROUNDS: usize = 24;

    /// Round constants RC from FIPS 202 §3.2.5 — identical to the table in
    /// `oxicrypt-sha`'s `keccak` module; the cross-path oracle would catch
    /// any drift between the two copies.
    #[rustfmt::skip]
    const RC: [u64; ROUNDS] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808a, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808b, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008a, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000a,
        0x0000_0000_8000_808b, 0x8000_0000_0000_008b, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800a, 0x8000_0000_8000_000a,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ];

    /// ρ-step rotation offsets, indexed by `x + 5*y`, from FIPS 202 §3.2.2
    /// — identical to the table in `oxicrypt-sha`'s `keccak` module; the
    /// cross-path oracle would catch any drift.
    #[rustfmt::skip]
    const RHO: [u32; LANES] = [
        0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ];

    /// Compile-time check that `PAIRS_L` — a transcription of the rotation
    /// offsets in source-index order (`idx = x + 5*y`) — matches the `RHO`
    /// reference table. It compares two tables; it does not read the
    /// `rotl::<L, 64-L>` literals in [`rho_pi`], so a drifting literal
    /// still compiles and is caught by the cross-path oracle at runtime.
    const _: () = {
        const PAIRS_L: [u32; LANES] = [
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61,
            56, 14,
        ];
        let mut i = 0;
        while i < LANES {
            assert!(
                PAIRS_L[i] == RHO[i],
                "rho_pi rotation pair drifted from RHO"
            );
            i += 1;
        }
    };

    // Detection-cache states. A single byte cannot tear, and the probe is
    // idempotent (CPUID is a pure read of fixed CPU state), so a benign
    // first-call race at worst probes twice and stores the same verdict.
    const NOT_PROBED: u8 = 0;
    const UNAVAILABLE: u8 = 1;
    const AVAILABLE: u8 = 2;

    static DETECTED: AtomicU8 = AtomicU8::new(NOT_PROBED);

    pub(crate) fn available() -> bool {
        match DETECTED.load(Ordering::Relaxed) {
            AVAILABLE => true,
            UNAVAILABLE => false,
            _ => {
                let avail = probe();
                DETECTED.store(
                    if avail { AVAILABLE } else { UNAVAILABLE },
                    Ordering::Relaxed,
                );
                avail
            }
        }
    }

    /// Hand-rolled CPUID probe for AVX2 plus the AVX and SSE2 levels the
    /// permutation relies on (`no_std`, so the std
    /// `is_x86_feature_detected!` macro is unavailable here).
    fn probe() -> bool {
        /// CPUID leaf 1 EDX bit 26 — SSE2.
        const LEAF1_EDX_SSE2: u32 = 1 << 26;
        /// CPUID leaf 1 ECX bit 28 — AVX.
        const LEAF1_ECX_AVX: u32 = 1 << 28;
        /// CPUID leaf 7 sub-leaf 0 EBX bit 5 — AVX2.
        const LEAF7_EBX_AVX2: u32 = 1 << 5;

        // `__cpuid_count` is a safe intrinsic on x86_64 (the CPUID
        // instruction is architecturally guaranteed — long mode cannot be
        // entered without it, and it only reads fixed processor
        // identification registers). Leaf 7 is only consulted after
        // leaf 0 confirms it exists.
        if __cpuid_count(0, 0).eax < 7 {
            return false;
        }
        let leaf1 = __cpuid_count(1, 0);
        let leaf7 = __cpuid_count(7, 0);
        (leaf1.edx & LEAF1_EDX_SSE2) != 0
            && (leaf1.ecx & LEAF1_ECX_AVX) != 0
            && (leaf7.ebx & LEAF7_EBX_AVX2) != 0
    }

    pub(crate) fn permute_x4(states: &mut [[u64; 25]; 4]) -> bool {
        if !available() {
            return false;
        }
        // SAFETY: `available()` has confirmed via CPUID — cached, but
        // probed on this very machine — that the CPU supports the avx2,
        // avx, and sse2 target features, which is exactly the precondition
        // for calling the `#[target_feature]` function `permute_x4_avx2`.
        // CPU features cannot be revoked at runtime.
        unsafe { permute_x4_avx2(states) };
        true
    }

    /// Pack state-lane `lane` of all four states into one `__m256i`
    /// (state 0 in 64-bit element 0, state 3 in element 3).
    #[target_feature(enable = "avx2")]
    fn pack_lane(states: &[[u64; 25]; 4], lane: usize) -> __m256i {
        // `_mm256_set_epi64x` takes elements high → low, so element 3
        // (state 3) is the first argument and element 0 (state 0) last.
        _mm256_set_epi64x(
            states[3][lane] as i64,
            states[2][lane] as i64,
            states[1][lane] as i64,
            states[0][lane] as i64,
        )
    }

    /// Rotate each 64-bit element of `v` left by a compile-time constant.
    ///
    /// The shift intrinsics require immediate counts, and stable Rust
    /// forbids const arithmetic on a single generic param in the
    /// const-generic position — so the left amount `L` and the right amount
    /// `R` are passed as two separate const generics, with `L + R == 64`
    /// computed at the call site (where both are concrete RHO-derived
    /// literals). [`rotl0`] handles the `L == 0` (identity) case, since
    /// `_mm256_srli_epi64::<64>` is an out-of-range shift count — the FIPS
    /// 202 RHO table has a zero offset at lane 0.
    #[target_feature(enable = "avx2")]
    fn rotl<const L: i32, const R: i32>(v: __m256i) -> __m256i {
        let hi = _mm256_slli_epi64::<L>(v);
        let lo = _mm256_srli_epi64::<R>(v);
        _mm256_or_si256(hi, lo)
    }

    /// Identity rotate (RHO offset 0). Kept distinct from [`rotl`] so the
    /// `srli` immediate is never the out-of-range value 64.
    #[target_feature(enable = "avx2")]
    fn rotl0(v: __m256i) -> __m256i {
        v
    }

    /// One Keccak-f\[1600\] round on the 25 vector lanes (FIPS 202 §3.2).
    ///
    /// `s` is the working state (lane `x + 5*y` at index `x + 5*y`);
    /// `round` selects the ι round constant. Mirrors the portable
    /// `keccak_f1600` body step for step.
    #[target_feature(enable = "avx2")]
    fn round(s: &mut [__m256i; LANES], round: usize) {
        // θ step: column parity.
        let mut c = [unsafe_zero(); 5];
        for x in 0..5 {
            c[x] = xor5(s[x], s[x + 5], s[x + 10], s[x + 15], s[x + 20]);
        }
        let mut d = [unsafe_zero(); 5];
        for x in 0..5 {
            d[x] = _mm256_xor_si256(c[(x + 4) % 5], rotl::<1, 63>(c[(x + 1) % 5]));
        }
        for y in 0..5 {
            for x in 0..5 {
                s[x + 5 * y] = _mm256_xor_si256(s[x + 5 * y], d[x]);
            }
        }

        // ρ and π steps, combined: b[y][2*x + 3*y] = rot(s[x][y], RHO).
        // The rotation amount is RHO[x + 5*y], a compile-time constant per
        // (x, y), so each rotate dispatches to the const-generic `rotl`
        // (or `rotl0` at the zero offset).
        let mut b = [unsafe_zero(); LANES];
        rho_pi(s, &mut b);

        // χ step: nonlinear layer. `_mm256_andnot_si256(a, b)` == (!a) & b.
        for y in 0..5 {
            for x in 0..5 {
                let n1 = b[((x + 1) % 5) + 5 * y];
                let n2 = b[((x + 2) % 5) + 5 * y];
                s[x + 5 * y] = _mm256_xor_si256(b[x + 5 * y], _mm256_andnot_si256(n1, n2));
            }
        }

        // ι step: inject the round constant into lane 0 (broadcast across
        // all four elements).
        s[0] = _mm256_xor_si256(s[0], _mm256_set1_epi64x(RC[round] as i64));
    }

    /// The ρ+π permutation with statically-resolved rotation amounts.
    ///
    /// Fully unrolled so each rotate's shift counts are compile-time
    /// immediates (the shift intrinsics require them). For source index
    /// `idx = x + 5*y` the rotation amount is `RHO[idx]`, written here as
    /// the explicit `<L, 64-L>` pair (the cross-path oracle catches any
    /// mismatch).
    /// The destination is `new_x + 5*new_y` with `new_x = y`,
    /// `new_y = (2*x + 3*y) % 5`.
    #[target_feature(enable = "avx2")]
    fn rho_pi(s: &[__m256i; LANES], b: &mut [__m256i; LANES]) {
        b[0] = rotl0(s[0]); //                 idx 0,  RHO 0,  (0,0) → 0
        b[10] = rotl::<1, 63>(s[1]); //        idx 1,  RHO 1,  (1,0) → 10
        b[20] = rotl::<62, 2>(s[2]); //        idx 2,  RHO 62, (2,0) → 20
        b[5] = rotl::<28, 36>(s[3]); //        idx 3,  RHO 28, (3,0) → 5
        b[15] = rotl::<27, 37>(s[4]); //       idx 4,  RHO 27, (4,0) → 15
        b[16] = rotl::<36, 28>(s[5]); //       idx 5,  RHO 36, (0,1) → 16
        b[1] = rotl::<44, 20>(s[6]); //        idx 6,  RHO 44, (1,1) → 1
        b[11] = rotl::<6, 58>(s[7]); //        idx 7,  RHO 6,  (2,1) → 11
        b[21] = rotl::<55, 9>(s[8]); //        idx 8,  RHO 55, (3,1) → 21
        b[6] = rotl::<20, 44>(s[9]); //        idx 9,  RHO 20, (4,1) → 6
        b[7] = rotl::<3, 61>(s[10]); //        idx 10, RHO 3,  (0,2) → 7
        b[17] = rotl::<10, 54>(s[11]); //      idx 11, RHO 10, (1,2) → 17
        b[2] = rotl::<43, 21>(s[12]); //       idx 12, RHO 43, (2,2) → 2
        b[12] = rotl::<25, 39>(s[13]); //      idx 13, RHO 25, (3,2) → 12
        b[22] = rotl::<39, 25>(s[14]); //      idx 14, RHO 39, (4,2) → 22
        b[23] = rotl::<41, 23>(s[15]); //      idx 15, RHO 41, (0,3) → 23
        b[8] = rotl::<45, 19>(s[16]); //       idx 16, RHO 45, (1,3) → 8
        b[18] = rotl::<15, 49>(s[17]); //      idx 17, RHO 15, (2,3) → 18
        b[3] = rotl::<21, 43>(s[18]); //       idx 18, RHO 21, (3,3) → 3
        b[13] = rotl::<8, 56>(s[19]); //       idx 19, RHO 8,  (4,3) → 13
        b[14] = rotl::<18, 46>(s[20]); //      idx 20, RHO 18, (0,4) → 14
        b[24] = rotl::<2, 62>(s[21]); //       idx 21, RHO 2,  (1,4) → 24
        b[9] = rotl::<61, 3>(s[22]); //        idx 22, RHO 61, (2,4) → 9
        b[19] = rotl::<56, 8>(s[23]); //       idx 23, RHO 56, (3,4) → 19
        b[4] = rotl::<14, 50>(s[24]); //       idx 24, RHO 14, (4,4) → 4
    }

    /// Five-way XOR (θ column parity).
    #[target_feature(enable = "avx2")]
    fn xor5(a: __m256i, b: __m256i, c: __m256i, d: __m256i, e: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_xor_si256(a, b), _mm256_xor_si256(c, d)),
            e,
        )
    }

    /// All-zero `__m256i` (used only to initialize fixed-size arrays before
    /// every element is overwritten).
    #[target_feature(enable = "avx2")]
    fn unsafe_zero() -> __m256i {
        _mm256_set1_epi64x(0)
    }

    /// AVX2 4-way Keccak-f\[1600\]: transpose in, 24 rounds, transpose out.
    ///
    /// Same FIPS 202 §3.2 mapping as the portable path, applied to four
    /// independent states packed element-wise into 25 256-bit lanes.
    #[target_feature(enable = "avx2")]
    fn permute_x4_avx2(states: &mut [[u64; 25]; 4]) {
        // Transpose: pack state-lane i of all four states into vector lane i.
        let mut s = [unsafe_zero(); LANES];
        for lane in 0..LANES {
            s[lane] = pack_lane(states, lane);
        }

        for r in 0..ROUNDS {
            round(&mut s, r);
        }

        // Transpose back: element j of vector lane i → states[j][i].
        for lane in 0..LANES {
            states[0][lane] = _mm256_extract_epi64::<0>(s[lane]) as u64;
            states[1][lane] = _mm256_extract_epi64::<1>(s[lane]) as u64;
            states[2][lane] = _mm256_extract_epi64::<2>(s[lane]) as u64;
            states[3][lane] = _mm256_extract_epi64::<3>(s[lane]) as u64;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;

    use super::{keccak_f1600_x4, keccak_f1600_x4_available};

    /// Tiny deterministic PRNG (splitmix64) so the cross-path fuzz is
    /// reproducible without pulling in an `rand` dependency.
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
    }

    /// Number of cross-path fuzz trials.
    const TRIALS: usize = 1000;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x4_matches_scalar_keccak_f1600_on_random_states() {
        // CRUX cross-path oracle. The scalar reference is the real
        // `oxicrypt_sha::keccak::keccak_f1600` (dev-dependency), applied to
        // each of the four states independently — never a reimplementation
        // here, so the test is non-tautological and drift-proof against the
        // RC/RHO copies in this crate. ≥1000 random 4×25-lane inputs.
        if !keccak_f1600_x4_available() {
            // No AVX2 on this host: the accelerated path is untestable here.
            return;
        }
        let mut prng = SplitMix64::new(0x5eed_1600_a2c2_0042);

        for _ in 0..TRIALS {
            let mut states = [[0u64; 25]; 4];
            for st in &mut states {
                for lane in st.iter_mut() {
                    *lane = prng.next_u64();
                }
            }

            // Expected: scalar permutation on each of the four states.
            let mut expected = states;
            for st in &mut expected {
                oxicrypt_sha::keccak::keccak_f1600(st);
            }

            // Actual: one batched AVX2 permutation.
            let mut actual = states;
            assert!(keccak_f1600_x4(&mut actual), "AVX2 path must run");

            for (i, (got, want)) in actual.iter().zip(expected.iter()).enumerate() {
                assert_eq!(got, want, "state {i} diverged from scalar keccak_f1600");
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn all_zero_state_matches_scalar() {
        // Cheap explicit ι-wiring cross-check: the all-zero state is driven
        // entirely by the round constants, so a mis-wired ι would show here.
        if !keccak_f1600_x4_available() {
            return;
        }
        let mut expected = [0u64; 25];
        oxicrypt_sha::keccak::keccak_f1600(&mut expected);

        let mut actual = [[0u64; 25]; 4];
        assert!(keccak_f1600_x4(&mut actual));
        for st in &actual {
            assert_eq!(*st, expected);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn detection_agrees_with_std_runtime_detection() {
        // Cross-path oracle for the hand-rolled CPUID probe: std's
        // is_x86_feature_detected! must agree in both directions. On an
        // AVX2 host this asserts available() == true; on older
        // x86_64 it asserts false — meaningful everywhere, skips nowhere.
        let std_says = std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("avx")
            && std::arch::is_x86_feature_detected!("sse2");
        assert_eq!(keccak_f1600_x4_available(), std_says);
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn detection_is_false_off_x86_64() {
        assert!(!keccak_f1600_x4_available());
    }

    #[test]
    fn detection_is_idempotent() {
        let first = keccak_f1600_x4_available();
        for _ in 0..1000 {
            assert_eq!(keccak_f1600_x4_available(), first);
        }
    }

    #[test]
    fn fail_portable_is_never_partial() {
        // The contract: keccak_f1600_x4 either returns true and mutates the
        // states (full permutation), or returns false and leaves them
        // byte-identical — never a partial application.
        let original = [[0x0102_0304_0506_0708u64; 25]; 4];
        let mut states = original;
        let ran = keccak_f1600_x4(&mut states);
        if ran {
            // On an AVX2 host the all-equal-lane input must change.
            assert_ne!(states, original);
        } else {
            assert_eq!(states, original);
        }
    }
}
