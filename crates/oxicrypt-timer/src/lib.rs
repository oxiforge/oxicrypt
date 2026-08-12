//! Raw CPU counter reads (x86_64 TSC, aarch64 CNTVCT_EL0) for the
//! oxicrypt entropy source.
//!
//! This is one of the small readily auditable in-boundary crates in the oxicrypt
//! workspace that uses `unsafe` (alongside `oxicrypt-zeroize`,
//! `oxicrypt-sha-accel`, `oxicrypt-aes-accel` and `oxicrypt-keccak-accel`). It implements the
//! sanctioned **CPU timer/counter intrinsic** category: every `unsafe`
//! block is a single side-effect-free read of an architectural
//! counter/register. All other in-boundary crates remain
//! `#![forbid(unsafe_code)]`; the authoritative unsafe-code accounting
//! lives in `docs/security-policy/security-policy.md` §9.2 "Isolation of
//! `unsafe`".
//!
//! # No cryptographic logic, no entropy claims
//!
//! This crate contains **no cryptographic logic** and makes **no entropy
//! claims**. It is a thin, auditable read of a free-running hardware
//! counter and nothing more. It does not condition, debias, accumulate,
//! or assess its output. Whether successive counter reads carry any
//! min-entropy at all — and how much — is decided entirely by
//! `oxicrypt-entropy` against SP 800-90B, which measures effective
//! timer granularity and runs the health tests. This crate is the
//! mechanical sensor; the entropy reasoning lives downstream.
//!
//! # Why a separate crate?
//!
//! Reading the time-stamp counter (`_rdtsc`) or the architectural
//! counter-timer (`MRS CNTVCT_EL0`) cannot be expressed in safe Rust:
//! both go through `core::arch` intrinsics / inline `asm!`. Isolating
//! these two tiny reads in a dedicated crate keeps the noise-source
//! collection crate, and every other in-boundary crate, literally
//! `#![forbid(unsafe_code)]` — mirroring the `oxicrypt-zeroize` and
//! `oxicrypt-sha-accel` precedent: one sanctioned category per crate,
//! each trivially auditable.
//!
//! # Scope
//!
//! Two architecture surfaces are supported: x86_64 (TSC) and aarch64
//! (CNTVCT_EL0). On any other target the crate fails to compile rather
//! than linking a silent stub — see [`read_raw_counter`].

#![no_std]
// This crate deliberately uses unsafe for CPU timer/counter intrinsics.
// Every other in-boundary crate except oxicrypt-zeroize, oxicrypt-sha-accel,
// oxicrypt-aes-accel and oxicrypt-keccak-accel forbids unsafe. The workspace lint set denies
// unsafe_op_in_unsafe_fn; each read carries its own SAFETY comment.

// Unsupported-target handling (documented design choice):
// We cfg-gate `read_raw_counter`'s body to the two supported arches and emit a
// hard `compile_error!` on any other target. We deliberately do NOT ship a
// stub that returns a constant: a silent stub would let an unsupported
// build link and feed `oxicrypt-entropy` a dead counter, which is exactly
// the failure an entropy source must never have. The `compile_error!`
// fires only when the crate is actually compiled for an unsupported
// target, so supported builds are unaffected.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "oxicrypt-timer supports only x86_64 (TSC) and aarch64 (CNTVCT_EL0); \
     no raw counter intrinsic is available on this target"
);

/// Read the architectural CPU counter as a raw 64-bit value.
///
/// What it reads, per architecture:
///
/// - **x86_64:** the time-stamp counter. An `LFENCE` is issued
///   immediately before `RDTSC` so the read is serialized against
///   prior instructions — without it, out-of-order execution lets the
///   `RDTSC` float earlier than the code being timed, blurring the
///   measurement. The lfence-before-rdtsc ordering is a
///   measurement-quality choice adopted as design provenance from the
///   published jitter-entropy design literature (Müller, *CPU Time
///   Jitter Based Non-Physical True Random Number Generator*); it is
///   cited as provenance, not transliterated.
/// - **aarch64:** the virtual count register `CNTVCT_EL0`, read with an
///   `ISB` instruction-synchronization barrier immediately before the
///   `MRS` so the counter read is ordered after preceding instructions,
///   the same serialization intent as the x86_64 `LFENCE`.
///
/// # Frequency is never trusted
///
/// The nominal counter frequency (TSC rate, `CNTFRQ_EL0`) is **never**
/// to be trusted as a measure of resolution. Callers MUST measure the
/// *effective* granularity of successive reads themselves; the
/// timer-adequacy check that decides whether this counter is usable as
/// a noise source lives in `oxicrypt-entropy`, not here. This function
/// only returns the raw bits.
///
/// The counter is free-running and wraps modulo 2^64; reason about
/// differences with `wrapping_sub`, never assume monotonic ordering
/// across a wrap.
#[inline]
#[must_use]
pub fn read_raw_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_lfence, _rdtsc};
        // SAFETY: `_mm_lfence` then `_rdtsc` is an unprivileged,
        // side-effect-free read of the time-stamp counter. RDTSC writes
        // no memory and touches no architectural state other than
        // producing the 64-bit TSC value in EDX:EAX; LFENCE only orders
        // prior loads. Both are always-available baseline x86_64
        // instructions (no target_feature gate needed). Caveat: if a
        // hypervisor or OS sets CR4.TSD to trap RDTSC from user mode,
        // the instruction faults — that surfaces as a delivered
        // signal/exception, not undefined behavior, so soundness holds.
        unsafe {
            _mm_lfence();
            _rdtsc()
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let counter: u64;
        // SAFETY: `ISB` is an unprivileged barrier with no operands;
        // `MRS x, CNTVCT_EL0` is an unprivileged, side-effect-free read
        // of the virtual count register into a general register. The asm
        // block has no memory operands (`nomem`), does not touch the
        // stack (`nostack`), and preserves the condition flags
        // (`preserves_flags`); its only effect is writing the count into
        // `counter`. Caveat: if EL1 clears CNTKCTL_EL1.EL0VCTEN the
        // read traps to EL1 — that surfaces as a delivered exception,
        // not undefined behavior, so soundness holds.
        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {c}, cntvct_el0",
                c = out(reg) counter,
                options(nomem, nostack, preserves_flags),
            );
        }
        counter
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::read_raw_counter;

    /// Across 10_000 consecutive reads, every wrapping delta is
    /// non-negative in wrapping terms: `wrapping_sub` never has its top
    /// bit set, i.e. the counter never appears to step backward by more
    /// than half its range between two adjacent reads.
    #[test]
    fn consecutive_reads_are_non_decreasing_wrapping() {
        let mut prev = read_raw_counter();
        for _ in 0..10_000u32 {
            let now = read_raw_counter();
            let delta = now.wrapping_sub(prev);
            assert_eq!(
                delta & (1u64 << 63),
                0,
                "wrapping delta {delta:#x} has top bit set (backward step)"
            );
            prev = now;
        }
    }

    /// Over the same kind of run, at least one strictly-positive delta
    /// occurs: the counter actually advances, it is not stuck.
    #[test]
    fn counter_actually_ticks() {
        let first = read_raw_counter();
        let mut saw_positive = false;
        let mut prev = first;
        for _ in 0..10_000u32 {
            let now = read_raw_counter();
            if now.wrapping_sub(prev) > 0 {
                saw_positive = true;
                break;
            }
            prev = now;
        }
        assert!(saw_positive, "counter never advanced across 10_000 reads");
    }

    /// Two reads separated by a small spin loop differ — the read is
    /// live, not a compile-time constant.
    #[test]
    fn reads_across_a_spin_differ() {
        let a = read_raw_counter();
        let mut spin = 0u64;
        for i in 0..50_000u64 {
            spin = spin.wrapping_add(i);
        }
        // Keep the spin from being optimized away.
        core::hint::black_box(spin);
        let b = read_raw_counter();
        assert_ne!(a, b, "counter did not change across a spin loop");
    }
}
