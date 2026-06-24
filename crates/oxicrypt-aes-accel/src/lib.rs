//! CPU-intrinsic AES block acceleration (x86_64 AES-NI) for
//! `oxicrypt-aes`.
//!
//! This is one of the small audited in-boundary crates in the oxicrypt
//! workspace that use `unsafe` (alongside `oxicrypt-zeroize` and
//! `oxicrypt-sha-accel`). It implements the sanctioned **CPU-intrinsic
//! acceleration** category established by `oxicrypt-sha-accel`:
//! feature-gated, default-off, runtime-detected, with equivalence to
//! the portable implementation proven by KAT + cross-path oracle. All
//! other in-boundary crates remain `#![forbid(unsafe_code)]`; the
//! authoritative unsafe-code accounting lives in
//! `docs/security-policy/security-policy.md` §9.2 "Isolation of
//! `unsafe`".
//!
//! # Why a separate crate?
//!
//! Invoking the AES-NI round instructions (`_mm_aesenc_si128` and
//! friends behind a `#[target_feature]` boundary) cannot be expressed
//! in safe Rust. `oxicrypt-aes` carries a literal, unconditional
//! `#![forbid(unsafe_code)]` that enters the CMVP conformance
//! argument, so the irreducible `unsafe` lives here — in a small,
//! audit-shaped crate mirroring the `oxicrypt-sha-accel` precedent.
//! The acceleration changes *where* the FIPS 197 §5.1/§5.3 rounds
//! execute (AES units instead of scalar S-box code), not *what* they
//! compute.
//!
//! # Containment
//!
//! - **Default-off.** `oxicrypt-aes` only depends on this crate behind
//!   its `accel-aes` feature; the validated portable baseline remains
//!   the shipping default and default dependency graphs are unchanged.
//! - **Runtime-detected.** One binary serves all CPUs: a hand-rolled
//!   CPUID probe (this crate is `no_std`, so
//!   `is_x86_feature_detected!` is unavailable) checks leaf 1 ECX
//!   bit 25 (AESNI) plus SSE2 and caches the verdict in an `AtomicU8`.
//! - **Fail-portable.** [`encrypt_block`] / [`decrypt_block`] return
//!   `false` — leaving `block` untouched — whenever AES-NI is absent,
//!   the target is not x86_64, or the round-key slice does not have the
//!   exact FIPS 197 shape for `nr ∈ {10, 12, 14}`. The caller then
//!   runs its portable path; a silently wrong block is unreachable.
//!
//! # Scope
//!
//! Single-block encrypt/decrypt over a caller-supplied pre-expanded
//! FIPS 197 round-key schedule — the same `(rk, nr)` contract as
//! `oxicrypt-aes`'s portable `encrypt_block_generic` /
//! `decrypt_block_generic`. The decrypt path derives the equivalent
//! inverse-cipher round keys per call via `AESIMC` (at most 13
//! single-cycle-class instructions per block — negligible against the
//! portable software path this replaces). Multi-block pipelining for
//! the CTR/GCM bulk paths is a documented follow-up under the same
//! sanctioned category. AArch64 AES intrinsics likewise.
//!
//! # Correctness oracle placement
//!
//! Unlike SHA-256 compression (whose KAT needs no key schedule), an
//! AES block KAT requires the expanded schedule, and key expansion is
//! deliberately private to `oxicrypt-aes`. The FIPS 197 Appendix C
//! KATs and the dispatch-equals-portable cross-path oracle therefore
//! live in `oxicrypt-aes`'s `accel-aes`-gated tests; this crate's own
//! tests cover the detection probe (against std's runtime detection),
//! the fail-portable contract, determinism, and cache integrity.

#![no_std]
// This crate deliberately uses unsafe for CPU intrinsics and CPUID.
// Every other in-boundary crate except oxicrypt-zeroize and
// oxicrypt-sha-accel forbids unsafe.
#![deny(unsafe_op_in_unsafe_fn)]

/// Returns `true` if the running CPU supports the AES-NI accelerated
/// block path (x86_64 with AESNI + SSE2).
///
/// The first call probes CPUID; the verdict is cached in an `AtomicU8`
/// so subsequent calls are a single relaxed atomic load. On non-x86_64
/// targets this is a constant `false`.
#[must_use]
pub fn aes_block_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_aes_ni::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Returns `true` if the running CPU supports the PCLMULQDQ-accelerated
/// GHASH multiply (x86_64 with PCLMULQDQ + SSSE3 + SSE2 — SSSE3 for the
/// `_mm_shuffle_epi8` byte-reflect).
///
/// Mirrors [`aes_block_available`] but probes a **distinct** CPU
/// feature: PCLMULQDQ (carry-less multiply) is independent of AES-NI,
/// so it is cached in its own `AtomicU8`. The first call probes CPUID;
/// subsequent calls are a single relaxed atomic load. On non-x86_64
/// targets this is a constant `false`.
#[must_use]
pub fn ghash_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_pclmul::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// GHASH single-block multiply in GF(2^128) via PCLMULQDQ, if available.
///
/// Computes the GCM field product (SP 800-38D §6.3, polynomial
/// `x^128 + x^7 + x^2 + x + 1`) of `x` and `y`, byte-for-byte identical
/// to the portable schoolbook `gf_mul` in `oxicrypt-aes`'s `modes`
/// module. The GCM bit convention (bit 7 of byte 0 is the highest
/// coefficient) is handled by byte-reflecting both operands into the
/// natural PCLMULQDQ polynomial order, multiplying, reducing, then
/// reflecting the result back.
///
/// Returns `true` if the accelerated path ran — in which case `out`
/// holds the product — or `false` if PCLMULQDQ is unavailable or the
/// target is not x86_64, in which case `out` is **untouched** and the
/// caller must run its portable path instead.
///
/// The kernel is straight-line and branch-free (no data-dependent
/// control flow, no table lookups): PCLMULQDQ is inherently
/// constant-time, so the multiply is CT by construction.
pub fn ghash_mul(x: &[u8; 16], y: &[u8; 16], out: &mut [u8; 16]) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_pclmul::mul(x, y, out)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (x, y, out);
        false
    }
}

/// Validate the `(rk, nr)` pair against the FIPS 197 schedule shape:
/// `nr ∈ {10, 12, 14}` and exactly `16 × (nr + 1)` round-key bytes.
// `nr` is matched to at most 14 before the arithmetic, so `16 * (nr + 1)`
// is bounded by 240 and cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
fn schedule_shape_ok(rk: &[u8], nr: usize) -> bool {
    matches!(nr, 10 | 12 | 14) && rk.len() == 16 * (nr + 1)
}

/// AES block encryption (FIPS 197 §5.1) via AES-NI, if available.
///
/// `rk` is the pre-expanded round-key schedule (`16 × (nr + 1)` bytes,
/// round 0 first — the exact layout `oxicrypt-aes` stores); `nr` is
/// the round count (10/12/14 for AES-128/-192/-256). The contract
/// matches the portable `encrypt_block_generic` byte-for-byte; only
/// the execution unit differs.
///
/// Returns `true` if the accelerated path ran (in which case `block`
/// holds the ciphertext), or `false` if AES-NI is unavailable or the
/// schedule shape is invalid — in which case `block` is **untouched**
/// and the caller must run its portable path instead.
pub fn encrypt_block(rk: &[u8], nr: usize, block: &mut [u8; 16]) -> bool {
    if !schedule_shape_ok(rk, nr) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_aes_ni::encrypt(rk, nr, block)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (rk, nr, block);
        false
    }
}

/// AES block decryption (FIPS 197 §5.3) via AES-NI, if available.
///
/// Same `(rk, nr)` contract as [`encrypt_block`]. The equivalent
/// inverse-cipher round keys are derived per call with `AESIMC`; the
/// output is byte-identical to the portable `decrypt_block_generic`.
///
/// Returns `true` if the accelerated path ran, else `false` with
/// `block` untouched (fail-portable).
pub fn decrypt_block(rk: &[u8], nr: usize, block: &mut [u8; 16]) -> bool {
    if !schedule_shape_ok(rk, nr) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_aes_ni::decrypt(rk, nr, block)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (rk, nr, block);
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64_aes_ni {
    //! AES-NI implementation: the canonical Intel flow — initial
    //! `AddRoundKey` as XOR, `AESENC` per middle round, `AESENCLAST`
    //! for the final round; decryption mirrors it with `AESDEC` /
    //! `AESDECLAST` over `AESIMC`-transformed middle round keys
    //! (FIPS 197 §5.3.5 equivalent inverse cipher).
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use core::arch::x86_64::{
        __cpuid_count, __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128,
        _mm_aesenclast_si128, _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    // Detection-cache states. A single byte cannot tear, and the probe
    // is idempotent (CPUID is a pure read of fixed CPU state), so a
    // benign first-call race at worst probes twice and stores the same
    // verdict.
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

    /// Hand-rolled CPUID probe for AES-NI plus SSE2 (`no_std`, so the
    /// std `is_x86_feature_detected!` macro is unavailable here).
    fn probe() -> bool {
        /// CPUID leaf 1 EDX bit 26 — SSE2.
        const LEAF1_EDX_SSE2: u32 = 1 << 26;
        /// CPUID leaf 1 ECX bit 25 — AESNI.
        const LEAF1_ECX_AESNI: u32 = 1 << 25;

        // `__cpuid_count` is a safe intrinsic on x86_64 (the CPUID
        // instruction is architecturally guaranteed in long mode and
        // only reads fixed processor identification registers).
        let leaf1 = __cpuid_count(1, 0);
        (leaf1.edx & LEAF1_EDX_SSE2) != 0 && (leaf1.ecx & LEAF1_ECX_AESNI) != 0
    }

    /// Load round key `r` from the schedule as a 128-bit lane.
    ///
    /// # Safety
    ///
    /// Caller guarantees `rk.len() >= 16 * (r + 1)` (enforced by the
    /// public wrappers' `schedule_shape_ok` and the bounded loops
    /// below) and that SSE2 is available.
    #[target_feature(enable = "sse2")]
    unsafe fn load_rk(rk: &[u8], r: usize) -> __m128i {
        // SAFETY: offset r*16 + 16 <= rk.len() per caller contract;
        // `_mm_loadu_si128` has no alignment requirement.
        unsafe { _mm_loadu_si128(rk.as_ptr().add(r * 16).cast()) }
    }

    pub(crate) fn encrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) -> bool {
        if !available() {
            return false;
        }
        // SAFETY: `available()` has confirmed via CPUID — cached, but
        // probed on this very machine — that the CPU supports the aes
        // and sse2 target features, which is exactly the precondition
        // for `encrypt_aes_ni`. CPU features cannot be revoked at
        // runtime. The schedule shape was validated by the public
        // wrapper.
        unsafe { encrypt_aes_ni(rk, nr, block) };
        true
    }

    pub(crate) fn decrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) -> bool {
        if !available() {
            return false;
        }
        // SAFETY: as in `encrypt` — CPUID-confirmed aes+sse2, shape
        // validated by the public wrapper.
        unsafe { decrypt_aes_ni(rk, nr, block) };
        true
    }

    /// One AES block, FIPS 197 §5.1 cipher over AES-NI.
    ///
    /// # Safety
    ///
    /// Requires aes+sse2 (CPUID-confirmed by the caller) and
    /// `rk.len() == 16 * (nr + 1)`.
    #[target_feature(enable = "aes,sse2")]
    unsafe fn encrypt_aes_ni(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
        // SAFETY: loads/stores are unaligned-tolerant; round indices
        // are bounded by `nr` against the wrapper-validated length.
        unsafe {
            let mut b = _mm_loadu_si128(block.as_ptr().cast());
            b = _mm_xor_si128(b, load_rk(rk, 0));
            for r in 1..nr {
                b = _mm_aesenc_si128(b, load_rk(rk, r));
            }
            b = _mm_aesenclast_si128(b, load_rk(rk, nr));
            _mm_storeu_si128(block.as_mut_ptr().cast(), b);
        }
    }

    /// One AES block, FIPS 197 §5.3.5 equivalent inverse cipher over
    /// AES-NI (`AESIMC`-transformed middle round keys, derived per
    /// call).
    ///
    /// # Safety
    ///
    /// Requires aes+sse2 (CPUID-confirmed by the caller) and
    /// `rk.len() == 16 * (nr + 1)`.
    #[target_feature(enable = "aes,sse2")]
    unsafe fn decrypt_aes_ni(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
        // SAFETY: as in `encrypt_aes_ni`.
        unsafe {
            let mut b = _mm_loadu_si128(block.as_ptr().cast());
            b = _mm_xor_si128(b, load_rk(rk, nr));
            for r in (1..nr).rev() {
                b = _mm_aesdec_si128(b, _mm_aesimc_si128(load_rk(rk, r)));
            }
            b = _mm_aesdeclast_si128(b, load_rk(rk, 0));
            _mm_storeu_si128(block.as_mut_ptr().cast(), b);
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64_pclmul {
    //! PCLMULQDQ implementation of the GCM GHASH multiply
    //! (SP 800-38D §6.3, polynomial `x^128 + x^7 + x^2 + x + 1`).
    //!
    //! The carry-less multiply `_mm_clmulepi64_si128` operates on
    //! polynomials in the natural little-endian order (bit i of the
    //! register is the coefficient of `x^i`). GCM uses the opposite
    //! bit order — bit 7 of byte 0 is the *highest* coefficient — so we
    //! byte-reflect both operands (a 16-byte `BSWAP`) into degree-rising
    //! order, do a 128×128→256 carry-less multiply (Karatsuba: three
    //! `clmul`s), reduce the 256-bit product modulo the GCM polynomial
    //! with the standard two-step shift-fold Montgomery-style reduction,
    //! and byte-reflect the 128-bit result back into GCM order.
    //!
    //! The whole sequence is straight-line and branch-free, so it is
    //! constant-time regardless of operand values.
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use core::arch::x86_64::{
        __cpuid_count, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_shuffle_epi8, _mm_slli_epi32,
        _mm_slli_si128, _mm_srli_epi32, _mm_srli_si128, _mm_storeu_si128, _mm_xor_si128,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    // Detection-cache states for the PCLMULQDQ probe. A single byte
    // cannot tear and CPUID is a pure read of fixed CPU state, so a
    // benign first-call race at worst probes twice and stores the same
    // verdict. This is a *separate* cache from the AES-NI one in
    // `x86_64_aes_ni`: PCLMULQDQ and AES-NI are distinct CPU features.
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

    /// Hand-rolled CPUID probe for PCLMULQDQ + SSSE3 + SSE2 (`no_std`, so
    /// the std `is_x86_feature_detected!` macro is unavailable here). All
    /// three are required: PCLMULQDQ for `_mm_clmulepi64_si128`, SSSE3 for
    /// the `_mm_shuffle_epi8` byte-reflect, SSE2 for the load/store/xor/shift
    /// lanes. Probing every feature the kernel uses keeps the runtime gate
    /// sound (PCLMULQDQ implies SSSE3 on every shipping CPU, but the gate
    /// asserts it rather than assuming it).
    fn probe() -> bool {
        /// CPUID leaf 1 EDX bit 26 — SSE2.
        const LEAF1_EDX_SSE2: u32 = 1 << 26;
        /// CPUID leaf 1 ECX bit 1 — PCLMULQDQ.
        const LEAF1_ECX_PCLMULQDQ: u32 = 1 << 1;
        /// CPUID leaf 1 ECX bit 9 — SSSE3 (the `_mm_shuffle_epi8` reflect).
        const LEAF1_ECX_SSSE3: u32 = 1 << 9;

        // `__cpuid_count` is a safe intrinsic on x86_64 (the CPUID
        // instruction is architecturally guaranteed in long mode and
        // only reads fixed processor identification registers).
        let leaf1 = __cpuid_count(1, 0);
        (leaf1.edx & LEAF1_EDX_SSE2) != 0
            && (leaf1.ecx & LEAF1_ECX_PCLMULQDQ) != 0
            && (leaf1.ecx & LEAF1_ECX_SSSE3) != 0
    }

    pub(crate) fn mul(x: &[u8; 16], y: &[u8; 16], out: &mut [u8; 16]) -> bool {
        if !available() {
            return false;
        }
        // SAFETY: `available()` has confirmed via CPUID — cached, but
        // probed on this very machine — that the CPU supports the
        // pclmulqdq, ssse3, and sse2 target features, the exact precondition
        // for `ghash_mul_pclmul`. CPU features cannot be revoked at runtime.
        unsafe { ghash_mul_pclmul(x, y, out) };
        true
    }

    /// GCM GHASH multiply over PCLMULQDQ.
    ///
    /// Verbatim implementation of Intel's reflected-operand `gfmul`
    /// ("Intel® Carry-Less Multiplication Instruction and its Usage for
    /// Computing the GCM Mode", Gueron & Kounavis, rev 2.02, Figure 5).
    /// We byte-reflect both 16-byte operands so polynomial degree rises
    /// with bit position (GCM's MSB-first convention is the reverse of
    /// PCLMULQDQ's natural order), run the Karatsuba 128×128 carry-less
    /// multiply, then apply the whitepaper's 32-bit-granular two-phase
    /// reduction modulo `x^128 + x^7 + x^2 + x + 1` (which folds in the
    /// reflection's one-bit shift), and byte-reflect the residue back.
    ///
    /// Straight-line and branch-free: constant time by construction.
    ///
    /// # Safety
    ///
    /// Requires pclmulqdq+ssse3+sse2 (CPUID-confirmed by the caller). SSSE3
    /// is needed for the `_mm_shuffle_epi8` byte-reflect.
    #[target_feature(enable = "pclmulqdq,ssse3,sse2")]
    unsafe fn ghash_mul_pclmul(x: &[u8; 16], y: &[u8; 16], out: &mut [u8; 16]) {
        // SAFETY: all loads/stores are unaligned-tolerant; the BSWAP
        // shuffle mask is a fixed local array; every intrinsic below
        // requires only the pclmulqdq+ssse3+sse2 features this function is
        // compiled for (ssse3 for `_mm_shuffle_epi8`).
        unsafe {
            // Byte-reverse mask: lane i <- byte (15 - i). Maps GCM's
            // MSB-first byte order onto PCLMULQDQ's degree-rising order.
            const BSWAP: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
            let bswap = _mm_loadu_si128(BSWAP.as_ptr().cast());

            let a = _mm_shuffle_epi8(_mm_loadu_si128(x.as_ptr().cast()), bswap);
            let b = _mm_shuffle_epi8(_mm_loadu_si128(y.as_ptr().cast()), bswap);

            // --- Karatsuba carry-less multiply (Figure 5, steps 1-8).
            // tmp3 = low 128 bits of the product, tmp6 = high 128 bits.
            let mut tmp3 = _mm_clmulepi64_si128(a, b, 0x00); // a0*b0
            let mut tmp6 = _mm_clmulepi64_si128(a, b, 0x11); // a1*b1
            let mut tmp4 = _mm_clmulepi64_si128(a, b, 0x10); // a1*b0
            let mut tmp5 = _mm_clmulepi64_si128(a, b, 0x01); // a0*b1
            tmp4 = _mm_xor_si128(tmp4, tmp5); // middle term
            tmp3 = _mm_xor_si128(tmp3, _mm_slli_si128(tmp4, 8));
            tmp6 = _mm_xor_si128(tmp6, _mm_srli_si128(tmp4, 8));

            // --- Phase 1 of the reduction (Figure 5, steps 9-20):
            // shift tmp3:tmp6 left by 1 (reflection adjustment) and fold
            // the three taps using 32-bit-granular shifts.
            let mut tmp7 = _mm_srli_epi32(tmp3, 31);
            let mut tmp8 = _mm_srli_epi32(tmp6, 31);
            tmp3 = _mm_slli_epi32(tmp3, 1);
            tmp6 = _mm_slli_epi32(tmp6, 1);

            let mut tmp9 = _mm_srli_si128(tmp7, 12);
            tmp8 = _mm_slli_si128(tmp8, 4);
            tmp7 = _mm_slli_si128(tmp7, 4);
            tmp3 = _mm_xor_si128(tmp3, tmp7);
            tmp6 = _mm_xor_si128(tmp6, tmp8);
            tmp6 = _mm_xor_si128(tmp6, tmp9);

            // --- Phase 2 (steps 21-37): fold tmp3 by x^1, x^2, x^7.
            tmp7 = _mm_slli_epi32(tmp3, 31);
            tmp8 = _mm_slli_epi32(tmp3, 30);
            tmp9 = _mm_slli_epi32(tmp3, 25);
            tmp7 = _mm_xor_si128(tmp7, tmp8);
            tmp7 = _mm_xor_si128(tmp7, tmp9);
            tmp8 = _mm_srli_si128(tmp7, 4);
            tmp7 = _mm_slli_si128(tmp7, 12);
            tmp3 = _mm_xor_si128(tmp3, tmp7);

            // --- Phase 3 (steps 38-end): finish the fold and combine
            // with the high half.
            let mut tmp2 = _mm_srli_epi32(tmp3, 1);
            tmp4 = _mm_srli_epi32(tmp3, 2);
            tmp5 = _mm_srli_epi32(tmp3, 7);
            tmp2 = _mm_xor_si128(tmp2, tmp4);
            tmp2 = _mm_xor_si128(tmp2, tmp5);
            tmp2 = _mm_xor_si128(tmp2, tmp8);
            tmp3 = _mm_xor_si128(tmp3, tmp2);
            tmp6 = _mm_xor_si128(tmp6, tmp3);

            // tmp6 holds the reduced 128-bit residue.
            let result = _mm_shuffle_epi8(tmp6, bswap);
            _mm_storeu_si128(out.as_mut_ptr().cast(), result);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]
mod tests {
    extern crate std;

    use super::{
        aes_block_available, decrypt_block, encrypt_block, ghash_available, ghash_mul,
        schedule_shape_ok,
    };

    #[test]
    fn schedule_shape_gate() {
        assert!(schedule_shape_ok(&[0u8; 16 * 11], 10));
        assert!(schedule_shape_ok(&[0u8; 16 * 13], 12));
        assert!(schedule_shape_ok(&[0u8; 16 * 15], 14));
        // Wrong length for the round count.
        assert!(!schedule_shape_ok(&[0u8; 16 * 11], 14));
        assert!(!schedule_shape_ok(&[0u8; 16 * 15], 10));
        // Round counts outside the FIPS 197 set.
        assert!(!schedule_shape_ok(&[0u8; 16 * 12], 11));
        assert!(!schedule_shape_ok(&[0u8; 16], 0));
    }

    #[test]
    fn invalid_shape_leaves_block_untouched() {
        let mut block = [0xAAu8; 16];
        assert!(!encrypt_block(&[0u8; 16 * 11], 14, &mut block));
        assert!(!decrypt_block(&[0u8; 16 * 11], 14, &mut block));
        assert_eq!(block, [0xAAu8; 16]);
    }

    #[test]
    fn unavailable_or_ran_contract() {
        // On AES-NI hosts the true-path must transform the block; on
        // others the false-path must leave it untouched.
        let rk = [0x5Cu8; 16 * 15];
        let original = [0x3Cu8; 16];
        let mut block = original;
        let ran = encrypt_block(&rk, 14, &mut block);
        if ran {
            assert_ne!(block, original);
        } else {
            assert_eq!(block, original);
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip_under_same_schedule() {
        // Pure contract test (any bytes form *a* valid schedule shape):
        // AES-NI decrypt over the same schedule must invert AES-NI
        // encrypt. The cross-path KAT against the portable cipher (and
        // FIPS 197 Appendix C) lives in `oxicrypt-aes`'s accel-aes
        // tests, where the real key schedule is available.
        if !aes_block_available() {
            return;
        }
        let mut rk = [0u8; 16 * 15];
        for (i, byte) in rk.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let original: [u8; 16] = *b"oxicrypt-aes-ni!";
        let mut block = original;
        assert!(encrypt_block(&rk, 14, &mut block));
        assert_ne!(block, original);
        assert!(decrypt_block(&rk, 14, &mut block));
        assert_eq!(block, original);
    }

    #[test]
    fn deterministic_across_repeated_calls() {
        let rk = [0x77u8; 16 * 11];
        let mut reference = [0x42u8; 16];
        let ran = encrypt_block(&rk, 10, &mut reference);
        for _ in 0..100 {
            let mut block = [0x42u8; 16];
            assert_eq!(encrypt_block(&rk, 10, &mut block), ran);
            assert_eq!(block, reference);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn detection_agrees_with_std_runtime_detection() {
        let std_says = std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("sse2");
        assert_eq!(aes_block_available(), std_says);
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn detection_is_false_off_x86_64() {
        assert!(!aes_block_available());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ghash_detection_agrees_with_std_runtime_detection() {
        let std_says = std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse2");
        assert_eq!(ghash_available(), std_says);
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn ghash_detection_is_false_off_x86_64() {
        assert!(!ghash_available());
    }

    #[test]
    fn ghash_unavailable_leaves_out_untouched() {
        // On non-PCLMUL hosts (or off-x86_64) the false path must leave
        // `out` exactly as supplied; on PCLMUL hosts the true path
        // overwrites it. Either way the *contract* holds.
        let x = [0x11u8; 16];
        let y = [0x22u8; 16];
        let sentinel = [0xCDu8; 16];
        let mut out = sentinel;
        let ran = ghash_mul(&x, &y, &mut out);
        if ran {
            // Accelerated: out was written (the GF product of nonzero
            // operands is itself nonzero, so it cannot equal a constant
            // sentinel by accident here — but assert the bool contract
            // rather than the value, which the oracle in oxicrypt-aes
            // pins exactly).
            assert!(ghash_available());
        } else {
            assert!(!ghash_available());
            assert_eq!(out, sentinel);
        }
    }

    #[test]
    fn ghash_zero_operand_is_zero() {
        // x * 0 == 0 in GF(2^128); a useful invariant that holds on the
        // accelerated path and is cheap to check without the portable
        // reference (which lives in oxicrypt-aes).
        if !ghash_available() {
            return;
        }
        let x = [0x9Eu8; 16];
        let zero = [0u8; 16];
        let mut out = [0xFFu8; 16];
        assert!(ghash_mul(&x, &zero, &mut out));
        assert_eq!(out, [0u8; 16]);
    }

    #[test]
    fn ghash_deterministic_across_repeated_calls() {
        if !ghash_available() {
            return;
        }
        let x = [0x3Au8; 16];
        let y = [0xC7u8; 16];
        let mut reference = [0u8; 16];
        assert!(ghash_mul(&x, &y, &mut reference));
        for _ in 0..100 {
            let mut out = [0u8; 16];
            assert!(ghash_mul(&x, &y, &mut out));
            assert_eq!(out, reference);
        }
    }

    #[test]
    fn detection_cache_has_no_torn_state_across_threads() {
        let expected = aes_block_available();
        let handles: std::vec::Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let first = aes_block_available();
                    for _ in 0..1000 {
                        assert_eq!(aes_block_available(), first);
                    }
                    first
                })
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    }
}
