//! Vetted conditioning component: SHA-256 over health-tested raw samples.
//!
//! # The vetted claim
//!
//! The conditioning component is the **SHA-256 hash function** from
//! `oxicrypt-sha` — a vetted conditioning component per SP 800-90B
//! §3.1.5.1.1 Table 1 (hash function: `nw = n_out = 256` bits, transcribed
//! as [`VETTED_SHA256_NW_BITS`] / [`VETTED_SHA256_NOUT_BITS`]). Vetted
//! components are permitted to claim full-entropy outputs (90B
//! §3.1.5.1.2). No key is involved (hash construction, not HMAC/CMAC), so
//! no key-management surface exists.
//!
//! # Output-entropy accounting
//!
//! Full-entropy output blocks are claimed under the SP 800-90C
//! input-margin rule. (The 90B `Output_Entropy` formula transcribed in
//! [`crate::sp800_90b`] is validation-time documentation — entropy
//! estimation is an offline assessment activity, never a runtime
//! computation; the runtime obligations are the continuous health tests
//! on raw samples plus the startup KAT.) Each 256-bit output block
//! consumes raw samples carrying at least
//!
//! ```text
//! h_in ≥ n_out + 64 = 320 bits of assessed min-entropy
//! ```
//!
//! per SP 800-90C §3.2.2.2 ("the amount of entropy required for each use
//! of the conditioning function is output_len + 64 bits"), anchored on 90C
//! §2.6 item 11 — both transcribed in [`crate::sp800_90b`]
//! ([`FULL_ENTROPY_INPUT_MARGIN_BITS`]). The per-block sample count is
//! derived from the pipeline's injected min-entropy claim:
//!
//! ```text
//! samples_per_block = ⌈ (n_out + margin) / claimed_h ⌉
//! ```
//!
//! computed exactly on [`MinEntropy`]'s 1/256-bit fixed-point steps — no
//! floating-point value participates (crate doctrine). The ceiling rounds
//! the sample count **up**, so the input-entropy requirement is met or
//! exceeded for every representable claim, never approached from below.
//!
//! The block hash absorbs **exactly the drawn samples** — no length
//! fields, counters, or domain-separation constants — so the credit
//! accounting has no non-entropy input terms to exclude. The injected
//! claim is the load-bearing premise of the full-entropy argument: it
//! must be the validated SP 800-90B min-entropy lower bound for the
//! specific source on the specific operational environment (the
//! pipeline enforces the source's design ceiling structurally; binding
//! the claim to an assessment is the integrator's documented
//! obligation).
//!
//! # Statelessness
//!
//! The conditioner retains **no state across output blocks**: every block
//! is computed by a fresh SHA-256 instance over that block's samples only —
//! no hash chaining, no carried counter, no buffered samples. The
//! [`Conditioner`] struct holds a single derived configuration value (the
//! per-block sample count). Raw samples are fed to the hash one at a time
//! and never buffered; the hash state is zeroized on drop by
//! `oxicrypt-sha`'s own drop discipline.
//!
//! # Startup known-answer test
//!
//! [`Conditioner::startup_kat`] verifies the conditioning function against
//! the FIPS 180-4 Appendix B.1 one-block example (SHA-256 of the
//! three-byte message `"abc"`, vector transcribed from the workspace's
//! CAVP-tested `oxicrypt-sha` KAT material). The pipeline runs this KAT
//! before its startup health battery; a mismatch is a permanent refusal —
//! the pipeline poisons and never emits output. There is no degraded mode.
//!
//! # Pre-operational hash construction
//!
//! The hash instance is obtained via `Sha256::new_internal`, the
//! documented pre-operational bypass: this conditioner feeds the seeding
//! path that the module's operational state itself depends on, so it
//! cannot gate on that state (same bootstrap argument as the jitter
//! source's workload hash). Integrity assurance comes from the startup KAT
//! above, which exercises exactly the construction used for conditioning.

use crate::h::{H_STEPS_PER_BIT, MinEntropy};
use crate::sp800_90b::{
    FULL_ENTROPY_INPUT_MARGIN_BITS, VETTED_SHA256_NOUT_BITS, VETTED_SHA256_NW_BITS,
};
use oxicrypt_sha::Sha256;

/// Length of one conditioned output block in bytes (SHA-256 digest size).
pub const CONDITIONED_BLOCK_LEN: usize = 32;

/// FIPS 180-4 Appendix B.1 one-block example message.
const KAT_MESSAGE: &[u8] = b"abc";

/// FIPS 180-4 Appendix B.1 expected digest of [`KAT_MESSAGE`]
/// (transcribed from `oxicrypt-sha`'s CAVP-tested KAT material).
const KAT_EXPECTED: [u8; CONDITIONED_BLOCK_LEN] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, //
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, //
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, //
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad, //
];

/// The vetted SHA-256 conditioning component's derived configuration.
///
/// Holds only the per-block sample count derived from the injected claim —
/// deliberately **no** hash state, counters, or sample storage, so
/// statelessness across blocks is structural, not behavioral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conditioner {
    samples_per_block: u32,
}

impl Conditioner {
    /// Derives the conditioner configuration from the pipeline's injected
    /// min-entropy claim.
    ///
    /// Returns `None` for a zero claim (no finite sample count delivers
    /// the input-entropy requirement). Pipeline construction already
    /// refuses zero claims at health-monitor creation, so a constructed
    /// pipeline can always derive a conditioner.
    #[must_use]
    pub fn for_claim(claimed_h: MinEntropy) -> Option<Self> {
        let steps = claimed_h.steps();
        if steps == 0 {
            return None;
        }
        // (n_out + margin) bits, in 1/256-bit steps: 320 * 256 = 81 920 —
        // far below u32::MAX, no overflow possible.
        let required_steps =
            (VETTED_SHA256_NOUT_BITS + FULL_ENTROPY_INPUT_MARGIN_BITS) * H_STEPS_PER_BIT;
        Some(Self {
            samples_per_block: required_steps.div_ceil(steps),
        })
    }

    /// Raw samples consumed per 256-bit conditioned output block —
    /// `⌈(n_out + 64) / claimed_h⌉` per the module docs.
    #[must_use]
    pub const fn samples_per_block(&self) -> u32 {
        self.samples_per_block
    }

    /// Runs the startup known-answer test against the shipped FIPS 180-4
    /// vector. `false` means the conditioning function is broken and the
    /// pipeline must refuse to operate.
    #[must_use]
    pub fn startup_kat() -> bool {
        Self::kat_against(&KAT_EXPECTED)
    }

    /// KAT core, parameterized on the expected digest so tests can prove
    /// that a corrupted vector causes refusal.
    fn kat_against(expected: &[u8; CONDITIONED_BLOCK_LEN]) -> bool {
        let mut hasher = Sha256::new_internal();
        hasher.update(KAT_MESSAGE);
        hasher.finalize() == *expected
    }

    /// Begins one output block: a **fresh** hash instance, used for this
    /// block only and dropped (state zeroized) when the block completes or
    /// aborts. This is the statelessness mechanism.
    pub(crate) fn begin_block() -> Sha256 {
        Sha256::new_internal()
    }
}

// Compile-time anchors: the vetted-component geometry this module's
// accounting is written against.
const _: () = assert!(VETTED_SHA256_NOUT_BITS as usize == CONDITIONED_BLOCK_LEN * 8);
const _: () = assert!(VETTED_SHA256_NW_BITS == VETTED_SHA256_NOUT_BITS);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    // ── Oversampling derivation (ISC-22) ─────────────────────────────

    #[test]
    fn samples_per_block_varies_with_claim() {
        // H = 1 bit/sample → 320 samples per 256-bit block.
        let c = Conditioner::for_claim(MinEntropy::from_bits(1)).unwrap();
        assert_eq!(c.samples_per_block(), 320);
        // H = 0.5 → 640.
        let c = Conditioner::for_claim(MinEntropy::from_steps(128)).unwrap();
        assert_eq!(c.samples_per_block(), 640);
        // H = 4 → 80.
        let c = Conditioner::for_claim(MinEntropy::from_bits(4)).unwrap();
        assert_eq!(c.samples_per_block(), 80);
        // H = 8 (full byte) → 40.
        let c = Conditioner::for_claim(MinEntropy::from_bits(8)).unwrap();
        assert_eq!(c.samples_per_block(), 40);
    }

    #[test]
    fn samples_per_block_rounds_up_never_down() {
        // 3 steps: 81920 / 3 = 27306.67 → 27307.
        let c = Conditioner::for_claim(MinEntropy::from_steps(3)).unwrap();
        assert_eq!(c.samples_per_block(), 27307);
    }

    #[test]
    fn zero_claim_has_no_conditioner() {
        assert!(Conditioner::for_claim(MinEntropy::ZERO).is_none());
    }

    // ── Full-entropy margin enforcement (ISC-122) ────────────────────

    /// For every representable claim in a broad sweep, the derived sample
    /// count delivers `h_in ≥ n_out + 64` — and is minimal (one sample
    /// fewer would fall short). The margin is enforced exactly, never
    /// approached from below.
    #[test]
    fn margin_holds_and_is_minimal_across_claims() {
        let required =
            u64::from((VETTED_SHA256_NOUT_BITS + FULL_ENTROPY_INPUT_MARGIN_BITS) * H_STEPS_PER_BIT);
        // 1 step (1/256 bit) through 8 bits, plus odd off-grid values.
        for steps in (1u32..=2048).chain([3, 7, 100, 255, 257, 1000]) {
            let c = Conditioner::for_claim(MinEntropy::from_steps(steps)).unwrap();
            let n = u64::from(c.samples_per_block());
            assert!(
                n * u64::from(steps) >= required,
                "margin violated at {steps} steps"
            );
            assert!(
                (n - 1) * u64::from(steps) < required,
                "oversampling not minimal at {steps} steps"
            );
        }
    }

    // ── Startup KAT (ISC-23) ─────────────────────────────────────────

    #[test]
    fn startup_kat_passes_on_shipped_vector() {
        assert!(Conditioner::startup_kat());
    }

    #[test]
    fn corrupted_vector_causes_refusal() {
        let mut corrupted = KAT_EXPECTED;
        corrupted[0] ^= 0x01;
        assert!(!Conditioner::kat_against(&corrupted));
    }

    // ── Statelessness (ISC-126) ──────────────────────────────────────

    /// The same input conditioned in a fresh block yields the same output
    /// regardless of what was conditioned before — no state carries
    /// across blocks.
    #[test]
    fn blocks_are_independent_of_prior_blocks() {
        let digest = |data: &[u8]| {
            let mut h = Conditioner::begin_block();
            h.update(data);
            h.finalize()
        };
        let first = digest(b"block one input");
        // Condition something entirely different in between.
        let _ = digest(b"unrelated intervening block");
        let again = digest(b"block one input");
        assert_eq!(first, again);
    }
}
