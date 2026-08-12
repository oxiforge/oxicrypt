//! CPU-intrinsic SHA-256 acceleration (x86_64 SHA-NI) for `oxicrypt-sha`.
//!
//! This is one of the small audited in-boundary crates in the oxicrypt
//! workspace that use `unsafe` (alongside `oxicrypt-zeroize`,
//! `oxicrypt-aes-accel`, `oxicrypt-keccak-accel` and `oxicrypt-timer`). It
//! implements the sanctioned **CPU-intrinsic acceleration** category:
//! feature-gated, default-off, runtime-detected, with equivalence to the
//! portable implementation proven by KAT + cross-path oracle. All other
//! in-boundary crates remain `#![forbid(unsafe_code)]`; the authoritative
//! unsafe-code accounting lives in
//! `docs/security-policy/security-policy.md` §9.2 "Isolation of `unsafe`".
//!
//! # Why a separate crate?
//!
//! Invoking the SHA-NI compression path (`_mm_sha256rnds2_epu32` and
//! the message-schedule helpers behind a `#[target_feature]` boundary)
//! cannot be expressed in safe Rust. `oxicrypt-sha` carries a literal,
//! unconditional `#![forbid(unsafe_code)]` that enters the CMVP
//! conformance argument, so the irreducible `unsafe` lives here — in a
//! small, audit-shaped crate mirroring the `oxicrypt-zeroize` precedent.
//! The acceleration changes *where* the FIPS 180-4 §6.2.2 compression
//! rounds execute (SHA extension units instead of scalar ALU code), not
//! *what* they compute.
//!
//! # Containment
//!
//! - **Default-off.** `oxicrypt-sha` only depends on this crate behind
//!   its `accel-sha` feature; the validated portable baseline remains the
//!   shipping default and default dependency graphs are unchanged.
//! - **Runtime-detected.** One binary serves all CPUs: a hand-rolled
//!   CPUID probe (this crate is `no_std`, so
//!   `is_x86_feature_detected!` is unavailable) checks leaf 7
//!   sub-leaf 0 EBX bit 29 (SHA) plus the required SSE bits and caches
//!   the verdict in an `AtomicU8`.
//! - **Fail-portable.** [`sha256_compress`] returns `false` — leaving
//!   `state` untouched — whenever SHA-NI is absent (or on any
//!   non-x86_64 target, where this crate compiles to a stub). The caller
//!   then runs its portable path; a wrong digest is unreachable.
//!
//! # Scope
//!
//! SHA-256 compression only. SHA-1 acceleration is explicitly out of
//! scope (legacy-use algorithm). AArch64 SHA2 intrinsics are a
//! documented follow-up under the same sanctioned category.

#![no_std]
// This crate deliberately uses unsafe for CPU intrinsics and CPUID.
// The other in-boundary crates that use unsafe are oxicrypt-zeroize,
// oxicrypt-aes-accel, oxicrypt-keccak-accel and oxicrypt-timer; every
// other in-boundary crate forbids it.
#![deny(unsafe_op_in_unsafe_fn)]

/// Returns `true` if the running CPU supports the SHA-NI accelerated
/// SHA-256 compression path (x86_64 with SHA + SSE2 + SSSE3 + SSE4.1).
///
/// The first call probes CPUID; the verdict is cached in an `AtomicU8`
/// so subsequent calls are a single relaxed atomic load. On non-x86_64
/// targets this is a constant `false`.
#[must_use]
pub fn sha256_compress_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_sha_ni::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// SHA-256 compression of one 512-bit block via SHA-NI, if available.
///
/// `state` is the running FIPS 180-4 hash value H (eight 32-bit words,
/// `H[0]` first); `block` is one 64-byte message block. The contract
/// matches the portable compression function in `oxicrypt-sha`
/// byte-for-byte: same state layout, same big-endian word loads, same
/// §6.2.2 round logic — only the execution unit differs.
///
/// Returns `true` if the accelerated compression ran (in which case
/// `state` has been advanced by one block), or `false` if SHA-NI is
/// unavailable on this CPU or target — in which case `state` is
/// **untouched** and the caller must run its portable compression
/// instead. This fail-portable contract makes a silently wrong digest
/// unreachable: there is no code path that partially applies the block.
pub fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64_sha_ni::compress(state, block)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Unreachable-by-contract stub: callers dispatch on
        // `sha256_compress_available()`, which is `false` here. Returning
        // `false` (state untouched) keeps the contract total and safe even
        // for callers that skip the availability check.
        let _ = (state, block);
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64_sha_ni {
    //! SHA-NI implementation, structured after the canonical Intel
    //! reference flow (lane-pair ABEF/CDGH layout, four rounds per
    //! `SHA256RNDS2` pair, `SHA256MSG1`/`SHA256MSG2` schedule extension).
    //!
    //! Lints: lane packing/unpacking reinterprets `u32` words as the
    //! `i32` lanes the intrinsics are typed over (no numeric meaning),
    //! and every index below is statically bounded by a constant or a
    //! `for … in N..M` loop — mirroring the lint posture of
    //! `oxicrypt-sha`'s own compression module.
    #![allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use core::arch::x86_64::{
        __cpuid_count, __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_extract_epi32,
        _mm_set_epi32, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
        _mm_shuffle_epi32,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    /// Round constants K from FIPS 180-4 §4.2.2 — identical to the table
    /// in `oxicrypt-sha`; the KAT + cross-path oracle would catch drift.
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
        0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
        0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
        0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
        0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];

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

    /// Hand-rolled CPUID probe for SHA-NI plus the SSE levels the
    /// compression function enables (`no_std`, so the std
    /// `is_x86_feature_detected!` macro is unavailable here).
    fn probe() -> bool {
        /// CPUID leaf 1 EDX bit 26 — SSE2.
        const LEAF1_EDX_SSE2: u32 = 1 << 26;
        /// CPUID leaf 1 ECX bit 9 — SSSE3.
        const LEAF1_ECX_SSSE3: u32 = 1 << 9;
        /// CPUID leaf 1 ECX bit 19 — SSE4.1.
        const LEAF1_ECX_SSE41: u32 = 1 << 19;
        /// CPUID leaf 7 sub-leaf 0 EBX bit 29 — SHA extensions.
        const LEAF7_EBX_SHA: u32 = 1 << 29;

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
            && (leaf1.ecx & LEAF1_ECX_SSSE3) != 0
            && (leaf1.ecx & LEAF1_ECX_SSE41) != 0
            && (leaf7.ebx & LEAF7_EBX_SHA) != 0
    }

    pub(crate) fn compress(state: &mut [u32; 8], block: &[u8; 64]) -> bool {
        if !available() {
            return false;
        }
        // SAFETY: `available()` has confirmed via CPUID — cached, but
        // probed on this very machine — that the CPU supports the sha,
        // sse2, ssse3, and sse4.1 target features, which is exactly the
        // precondition for calling the `#[target_feature]` function
        // `compress_sha_ni`. CPU features cannot be revoked at runtime.
        unsafe { compress_sha_ni(state, block) };
        true
    }

    /// Pack four `u32` words into one 128-bit lane set (`w0` in lane 0).
    #[target_feature(enable = "sse2")]
    fn lanes(w3: u32, w2: u32, w1: u32, w0: u32) -> __m128i {
        _mm_set_epi32(w3 as i32, w2 as i32, w1 as i32, w0 as i32)
    }

    /// Big-endian load of message words `W[4*group .. 4*group+4]`
    /// (FIPS 180-4 §6.2.2 step 1, §3.1 word ordering).
    #[target_feature(enable = "sse2")]
    fn msg_lanes(block: &[u8; 64], group: usize) -> __m128i {
        let w = |i: usize| -> u32 {
            let off = (group * 4 + i) * 4;
            u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]])
        };
        lanes(w(3), w(2), w(1), w(0))
    }

    /// Round-constant lane set `K[4*group .. 4*group+4]` (§4.2.2).
    #[target_feature(enable = "sse2")]
    fn k_lanes(group: usize) -> __m128i {
        let base = group * 4;
        lanes(K[base + 3], K[base + 2], K[base + 1], K[base])
    }

    /// Four rounds of the §6.2.2 step-3 loop. `wk` carries
    /// `W[t]+K[t] .. W[t+3]+K[t+3]`; each `SHA256RNDS2` consumes two.
    #[target_feature(enable = "sha,sse2")]
    fn rounds4(abef: &mut __m128i, cdgh: &mut __m128i, wk: __m128i) {
        *cdgh = _mm_sha256rnds2_epu32(*cdgh, *abef, wk);
        let wk_hi = _mm_shuffle_epi32::<0x0E>(wk);
        *abef = _mm_sha256rnds2_epu32(*abef, *cdgh, wk_hi);
    }

    /// Message-schedule extension (§6.2.2 step 1, t in 16..64): derives
    /// the next four `W` words from the previous sixteen.
    #[target_feature(enable = "sha,sse2,ssse3")]
    fn schedule(w0: __m128i, w1: __m128i, w2: __m128i, w3: __m128i) -> __m128i {
        let t = _mm_sha256msg1_epu32(w0, w1);
        let t = _mm_add_epi32(t, _mm_alignr_epi8::<4>(w3, w2));
        _mm_sha256msg2_epu32(t, w3)
    }

    /// SHA-256 compression of one 512-bit block using the SHA extensions.
    ///
    /// Same FIPS 180-4 §6.2.2 logic as the portable path; the SHA
    /// extension instructions work on an ABEF/CDGH lane-pair layout, so
    /// the prologue/epilogue shuffles translate the linear `[a..h]`
    /// state in and out of that layout (canonical Intel reference flow).
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    fn compress_sha_ni(state: &mut [u32; 8], block: &[u8; 64]) {
        // Prologue: [a,b,c,d|e,f,g,h] -> ABEF / CDGH lane pairs.
        let dcba = lanes(state[3], state[2], state[1], state[0]);
        let hgfe = lanes(state[7], state[6], state[5], state[4]);
        let cdab = _mm_shuffle_epi32::<0xB1>(dcba);
        let efgh = _mm_shuffle_epi32::<0x1B>(hgfe);
        let mut abef = _mm_alignr_epi8::<8>(cdab, efgh);
        let mut cdgh = _mm_blend_epi16::<0xF0>(efgh, cdab);

        let abef_save = abef;
        let cdgh_save = cdgh;

        // Message schedule W[0..16] (step 1).
        let mut w0 = msg_lanes(block, 0);
        let mut w1 = msg_lanes(block, 1);
        let mut w2 = msg_lanes(block, 2);
        let mut w3 = msg_lanes(block, 3);

        // Rounds 0..16 consume the message words directly (step 3).
        rounds4(&mut abef, &mut cdgh, _mm_add_epi32(w0, k_lanes(0)));
        rounds4(&mut abef, &mut cdgh, _mm_add_epi32(w1, k_lanes(1)));
        rounds4(&mut abef, &mut cdgh, _mm_add_epi32(w2, k_lanes(2)));
        rounds4(&mut abef, &mut cdgh, _mm_add_epi32(w3, k_lanes(3)));

        // Rounds 16..64 extend the schedule four words at a time.
        for group in 4..16 {
            let wn = schedule(w0, w1, w2, w3);
            rounds4(&mut abef, &mut cdgh, _mm_add_epi32(wn, k_lanes(group)));
            (w0, w1, w2, w3) = (w1, w2, w3, wn);
        }

        // Step 4: fold the working variables back into H.
        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);

        // Epilogue: ABEF / CDGH -> [a,b,c,d|e,f,g,h].
        let feba = _mm_shuffle_epi32::<0x1B>(abef);
        let dchg = _mm_shuffle_epi32::<0xB1>(cdgh);
        let dcba_out = _mm_blend_epi16::<0xF0>(feba, dchg);
        let hgfe_out = _mm_alignr_epi8::<8>(dchg, feba);

        state[0] = _mm_extract_epi32::<0>(dcba_out) as u32;
        state[1] = _mm_extract_epi32::<1>(dcba_out) as u32;
        state[2] = _mm_extract_epi32::<2>(dcba_out) as u32;
        state[3] = _mm_extract_epi32::<3>(dcba_out) as u32;
        state[4] = _mm_extract_epi32::<0>(hgfe_out) as u32;
        state[5] = _mm_extract_epi32::<1>(hgfe_out) as u32;
        state[6] = _mm_extract_epi32::<2>(hgfe_out) as u32;
        state[7] = _mm_extract_epi32::<3>(hgfe_out) as u32;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;

    use super::{sha256_compress, sha256_compress_available};

    /// Initial hash value H(0) from FIPS 180-4 §5.3.3.
    const H0: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    /// SHA-256("abc") digest words — FIPS 180-4 Appendix B.1.
    const ABC_DIGEST_WORDS: [u32; 8] = [
        0xba78_16bf,
        0x8f01_cfea,
        0x4141_40de,
        0x5dae_2223,
        0xb003_61a3,
        0x9617_7a9c,
        0xb410_ff61,
        0xf200_15ad,
    ];

    /// The single padded block for the one-block message "abc"
    /// (§5.1.1 padding: 0x80, zeros, 64-bit big-endian bit length 24).
    fn abc_block() -> [u8; 64] {
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 0x18;
        block
    }

    #[test]
    fn kat_abc_matches_fips_180_4_appendix_b1() {
        if !sha256_compress_available() {
            // No SHA-NI on this host: the accelerated path is untestable
            // here; the fail-portable contract is covered below.
            return;
        }
        let mut state = H0;
        assert!(sha256_compress(&mut state, &abc_block()));
        assert_eq!(state, ABC_DIGEST_WORDS);
    }

    #[test]
    fn unavailable_leaves_state_untouched() {
        // On targets/CPUs without SHA-NI, the contract is: return false,
        // state byte-identical. On SHA-NI hosts this test still verifies
        // the true-path advances state (i.e. it is never a silent no-op).
        let mut state = H0;
        let ran = sha256_compress(&mut state, &abc_block());
        if ran {
            assert_ne!(state, H0);
        } else {
            assert_eq!(state, H0);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn detection_agrees_with_std_runtime_detection() {
        // Cross-path oracle for the hand-rolled CPUID probe: std's
        // is_x86_feature_detected! must agree in both directions. On a
        // SHA-NI host this asserts
        // available() == true; on older x86_64 it asserts false — so the
        // test is meaningful everywhere and skips nowhere on x86_64.
        let std_says = std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse2")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1");
        assert_eq!(sha256_compress_available(), std_says);
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn detection_is_false_off_x86_64() {
        assert!(!sha256_compress_available());
    }

    #[test]
    fn detection_is_idempotent() {
        let first = sha256_compress_available();
        for _ in 0..1000 {
            assert_eq!(sha256_compress_available(), first);
        }
    }

    #[test]
    fn detection_cache_has_no_torn_state_across_threads() {
        // The cache is a single AtomicU8 (cannot tear); the probe is
        // idempotent, so a first-call race stores the same verdict twice.
        // Hammer it from eight threads and require unanimity with the
        // main thread's verdict.
        let expected = sha256_compress_available();
        let handles: std::vec::Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let first = sha256_compress_available();
                    for _ in 0..1000 {
                        assert_eq!(sha256_compress_available(), first);
                    }
                    first
                })
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    }

    #[test]
    fn compress_is_deterministic_across_repeated_calls() {
        // Same block, same starting state => same result every time
        // (guards against any torn-detection path swap mid-stream).
        let block = abc_block();
        let mut reference = H0;
        let ran = sha256_compress(&mut reference, &block);
        for _ in 0..100 {
            let mut state = H0;
            assert_eq!(sha256_compress(&mut state, &block), ran);
            assert_eq!(state, reference);
        }
    }
}
