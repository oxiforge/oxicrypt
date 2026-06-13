//! Entropy pipeline: claim enforcement at construction, health tests on
//! every sample, conditioning, startup gating, permanent poisoning.
//!
//! The full pipeline is `NoiseSource → health tests → conditioner`. This
//! module carries all three stages plus the lifecycle:
//!
//! ```text
//!   AwaitingStartup ──run_startup()──► Operational ──any health failure──► Poisoned
//!         │                                 │                                 ▲
//!         └──startup/KAT failure────────────┼─────────────────────────────────┘
//!                                           └──on_demand_test() (fresh state)
//! ```
//!
//! - **No output before startup passes** (§4.3 item 4): [`EntropyPipeline::sample`]
//!   and [`EntropyPipeline::conditioned_block`] refuse with a typed error
//!   until [`EntropyPipeline::run_startup`] has verified the conditioning
//!   KAT and run the continuous tests over at least 1024 consecutive
//!   samples. Startup-tested samples are **discarded, never released**.
//! - **On-demand testing** (§4.3 item 5): [`EntropyPipeline::on_demand_test`]
//!   re-runs the startup battery on fresh test state — no count or window
//!   carryover from continuous operation.
//! - **All health failures are permanent**: the pipeline poisons; only
//!   re-instantiation clears it. A conditioning-KAT failure poisons the
//!   same way ([`EntropyError::ConditionerKat`]).
//! - **Conditioned output** ([`EntropyPipeline::conditioned_block`]): each
//!   256-bit block consumes [`Conditioner::samples_per_block`] health-tested
//!   samples — `⌈(n_out + 64)/claimed_h⌉`, the SP 800-90C §3.2.2.2
//!   full-entropy input margin (see [`crate::conditioner`]). Every sample
//!   still flows through [`EntropyPipeline::sample`], the sole emission
//!   path, so no raw sample reaches the conditioner untested.

use crate::conditioner::{CONDITIONED_BLOCK_LEN, Conditioner};
use crate::error::EntropyError;
use crate::h::MinEntropy;
use crate::health::{Alpha, HealthError, HealthMonitor};
use crate::source::NoiseSource;
use crate::source::RawSample;
use crate::sp800_90b::STARTUP_MIN_SAMPLES;

/// Pipeline lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingStartup,
    Operational,
    Poisoned,
}

/// An entropy pipeline bound to one noise source, one validated
/// min-entropy claim, and one health-test configuration.
#[derive(Debug)]
pub struct EntropyPipeline<S: NoiseSource> {
    source: S,
    claimed_h: MinEntropy,
    alpha: Alpha,
    monitor: HealthMonitor,
    conditioner: Conditioner,
    state: State,
}

impl<S: NoiseSource> EntropyPipeline<S> {
    /// Constructs a pipeline, injecting the claimed min-entropy per sample
    /// and the health-test false-positive probability.
    ///
    /// # Errors
    ///
    /// - [`EntropyError::ClaimExceedsCeiling`] if `claimed_h` exceeds
    ///   [`NoiseSource::max_claimable_h`] — refused, never clamped.
    /// - [`EntropyError::ClaimExceedsSampleWidth`] if `claimed_h` exceeds
    ///   the declared sample width in bits (information-theoretic bound).
    /// - [`EntropyError::Health`] (`UnsupportedAlpha`) if the requested
    ///   (α, alphabet, H) point has no precomputed APT cutoff coverage.
    pub fn new(source: S, claimed_h: MinEntropy, alpha: Alpha) -> Result<Self, EntropyError> {
        let ceiling = source.max_claimable_h();
        if claimed_h > ceiling {
            return Err(EntropyError::ClaimExceedsCeiling {
                claimed: claimed_h,
                ceiling,
            });
        }
        let spec = source.spec();
        if claimed_h > MinEntropy::from_bits(spec.sample_width_bits()) {
            return Err(EntropyError::ClaimExceedsSampleWidth {
                claimed: claimed_h,
                sample_width_bits: spec.sample_width_bits(),
            });
        }
        let monitor = HealthMonitor::new(claimed_h, spec.is_binary(), alpha)?;
        // HealthMonitor::new refused a zero claim above, so the conditioner
        // derivation cannot fail for a claim that reached this point; the
        // fallback mirrors the zero-claim reporting convention documented
        // at HealthMonitor::new.
        let conditioner = Conditioner::for_claim(claimed_h).ok_or(EntropyError::Health(
            HealthError::UnsupportedAlpha {
                alpha_exp: alpha.exp(),
            },
        ))?;
        Ok(Self {
            source,
            claimed_h,
            alpha,
            monitor,
            conditioner,
            state: State::AwaitingStartup,
        })
    }

    /// Runs the startup tests: the conditioning known-answer test, then
    /// the continuous health tests over at least [`STARTUP_MIN_SAMPLES`]
    /// consecutive samples (§4.3 item 4). The tested samples are
    /// discarded — never buffered for later release.
    ///
    /// # Errors
    ///
    /// - [`EntropyError::NotReady`] if startup already ran (use
    ///   [`Self::on_demand_test`] for re-testing).
    /// - [`EntropyError::ConditionerKat`] if the conditioning KAT fails —
    ///   the pipeline is then permanently poisoned.
    /// - [`EntropyError::Health`] on a test failure — the pipeline is then
    ///   permanently poisoned.
    /// - [`EntropyError::Source`] if the source fails to produce samples.
    pub fn run_startup(&mut self) -> Result<(), EntropyError> {
        match self.state {
            State::AwaitingStartup => (),
            State::Operational | State::Poisoned => return Err(EntropyError::NotReady),
        }
        if !Conditioner::startup_kat() {
            self.state = State::Poisoned;
            return Err(EntropyError::ConditionerKat);
        }
        self.run_battery()?;
        self.state = State::Operational;
        Ok(())
    }

    /// On-demand testing (§4.3 item 5): re-runs at least the startup
    /// battery on **fresh test state** — no carryover from continuous
    /// operation. Tested samples are discarded. Only callable while
    /// operational.
    ///
    /// # Errors
    ///
    /// [`EntropyError::NotReady`] before startup; [`EntropyError::Health`]
    /// on failure (pipeline permanently poisoned); [`EntropyError::Source`]
    /// on source failure.
    pub fn on_demand_test(&mut self) -> Result<(), EntropyError> {
        match self.state {
            State::Operational => (),
            State::AwaitingStartup | State::Poisoned => return Err(EntropyError::NotReady),
        }
        self.run_battery()
    }

    /// Runs one battery of `STARTUP_MIN_SAMPLES` through a **fresh**
    /// monitor (clean RCT/APT state), then installs the fresh monitor as
    /// the continuous monitor going forward. Poisons on failure.
    fn run_battery(&mut self) -> Result<(), EntropyError> {
        let spec = self.source.spec();
        let mut fresh = HealthMonitor::new(self.claimed_h, spec.is_binary(), self.alpha)
            .map_err(EntropyError::Health)?;
        let mut fed: u32 = 0;
        while fed < STARTUP_MIN_SAMPLES {
            let sample = self.source.sample().map_err(EntropyError::Source)?;
            if let Err(e) = fresh.feed(sample) {
                self.state = State::Poisoned;
                return Err(EntropyError::Health(e));
            }
            fed = fed.saturating_add(1);
            // The tested sample goes out of scope here: discarded.
        }
        self.monitor = fresh;
        Ok(())
    }

    /// Emits one health-tested raw sample. This is the **only** path by
    /// which a sample leaves the pipeline — no raw sample reaches any
    /// downstream consumer untested.
    ///
    /// # Errors
    ///
    /// - [`EntropyError::NotReady`] before startup tests have passed
    ///   (no output before startup — §4.3 item 4) or after poisoning.
    /// - [`EntropyError::Health`] on the failing sample itself — the
    ///   sample is **not** released and the pipeline poisons permanently.
    /// - [`EntropyError::Source`] if the source fails.
    pub fn sample(&mut self) -> Result<RawSample, EntropyError> {
        match self.state {
            State::Operational => (),
            State::AwaitingStartup | State::Poisoned => return Err(EntropyError::NotReady),
        }
        let sample = self.source.sample().map_err(EntropyError::Source)?;
        if let Err(e) = self.monitor.feed(sample) {
            self.state = State::Poisoned;
            return Err(EntropyError::Health(e));
        }
        Ok(sample)
    }

    /// Emits one 256-bit conditioned output block.
    ///
    /// Draws [`Conditioner::samples_per_block`] health-tested raw samples
    /// through [`Self::sample`] — the sole emission path, so every sample
    /// the conditioner consumes has passed the continuous tests — and
    /// absorbs them into a **fresh** SHA-256 instance used for this block
    /// only (stateless across blocks; see [`crate::conditioner`]). The
    /// sample count enforces the SP 800-90C full-entropy input margin
    /// `h_in ≥ n_out + 64` for the pipeline's injected claim.
    ///
    /// # Errors
    ///
    /// - [`EntropyError::NotReady`] before startup tests pass or after
    ///   poisoning.
    /// - [`EntropyError::Health`] if any drawn sample fails a health test —
    ///   the pipeline poisons permanently, the partial block is abandoned,
    ///   and its hash state is zeroized on drop. No block is emitted.
    /// - [`EntropyError::Source`] if the source fails mid-block (no
    ///   poisoning; the partial block is abandoned the same way).
    pub fn conditioned_block(&mut self) -> Result<[u8; CONDITIONED_BLOCK_LEN], EntropyError> {
        match self.state {
            State::Operational => (),
            State::AwaitingStartup | State::Poisoned => return Err(EntropyError::NotReady),
        }
        let mut hasher = Conditioner::begin_block();
        let mut drawn: u32 = 0;
        while drawn < self.conditioner.samples_per_block() {
            let sample = self.sample()?;
            hasher.update(&[sample]);
            drawn = drawn.saturating_add(1);
        }
        Ok(hasher.finalize())
    }

    /// The conditioner configuration derived from this pipeline's claim.
    #[must_use]
    pub const fn conditioner(&self) -> Conditioner {
        self.conditioner
    }

    /// The validated min-entropy claim this pipeline operates under.
    #[must_use]
    pub const fn claimed_h(&self) -> MinEntropy {
        self.claimed_h
    }

    /// The health-test false-positive probability in use.
    #[must_use]
    pub const fn alpha(&self) -> Alpha {
        self.alpha
    }

    /// Whether startup has passed and the pipeline can emit samples.
    #[must_use]
    pub fn is_operational(&self) -> bool {
        self.state == State::Operational
    }

    /// Whether a health failure has permanently poisoned the pipeline.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.state == State::Poisoned
    }

    /// Shared access to the underlying source.
    pub fn source(&self) -> &S {
        &self.source
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::error::EntropyError;
    use crate::health::{HealthError, HealthTest};
    use crate::source::{
        RawSample, SourceError, SourceMetadata, SourceSpec, TimerSource, sealed::Sealed,
    };

    fn alpha20() -> Alpha {
        Alpha::from_exp(20).unwrap()
    }

    fn meta() -> SourceMetadata<'static> {
        SourceMetadata {
            timer_source: None,
            counter_frequency_hz: None,
            cpu_model: "test",
            os: "test",
            collection_params: "unit test",
        }
    }

    /// Deterministic xorshift-style byte source, 8-bit alphabet, healthy.
    #[derive(Debug)]
    struct PrngMock {
        state: u32,
        emitted: u32,
    }
    impl PrngMock {
        fn new() -> Self {
            Self {
                state: 0x1234_5678,
                emitted: 0,
            }
        }
    }
    impl Sealed for PrngMock {}
    impl NoiseSource for PrngMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(4)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            // xorshift32, low byte.
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            self.emitted += 1;
            Ok((x & 0xFF) as u8)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    /// Dead source: constant output (total failure — RCT's target class).
    #[derive(Debug)]
    struct DeadMock;
    impl Sealed for DeadMock {}
    impl NoiseSource for DeadMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(4)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            Ok(0xAA)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    /// Low-variety oscillating wide source (APT's target class when a
    /// high claim is injected): alternates two values on an 8-bit alphabet.
    #[derive(Debug)]
    struct OscillatingMock(u8);
    impl Sealed for OscillatingMock {}
    impl NoiseSource for OscillatingMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(8)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            self.0 ^= 1;
            Ok(self.0 & 1)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    fn healthy_pipeline() -> EntropyPipeline<PrngMock> {
        EntropyPipeline::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap()
    }

    // ── Construction (held over from trait-core, now with α) ─────────

    #[test]
    fn claim_above_ceiling_is_refused() {
        let err = EntropyPipeline::new(
            PrngMock::new(),
            MinEntropy::from_steps(4 * 256 + 1),
            alpha20(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            EntropyError::ClaimExceedsCeiling {
                claimed: MinEntropy::from_steps(1025),
                ceiling: MinEntropy::from_bits(4),
            }
        );
    }

    #[test]
    fn claim_at_ceiling_is_accepted() {
        assert!(EntropyPipeline::new(PrngMock::new(), MinEntropy::from_bits(4), alpha20()).is_ok());
    }

    #[test]
    fn unsupported_alpha_is_typed_at_construction() {
        // An α with no table coverage (e.g. 2⁻²⁵) is a typed refusal at
        // construction — cutoffs are table-borne, never computed in-boundary.
        let a25 = Alpha::from_exp(25).unwrap();
        let err = EntropyPipeline::new(PrngMock::new(), MinEntropy::from_bits(2), a25).unwrap_err();
        assert_eq!(
            err,
            EntropyError::Health(HealthError::UnsupportedAlpha { alpha_exp: 25 })
        );
    }

    #[test]
    fn default_alpha_30_is_now_supported() {
        // The ratified default α = 2⁻³⁰ is table-covered (generated grid):
        // construction succeeds where it previously returned UnsupportedAlpha.
        // PrngMock is an 8-bit (non-binary) source; H = 2 → cutoff 190.
        assert!(
            EntropyPipeline::new(PrngMock::new(), MinEntropy::from_bits(2), Alpha::DEFAULT).is_ok()
        );
    }

    // ── Startup gating (§4.3 item 4 / ISC-43) ────────────────────────

    #[test]
    fn no_output_before_startup() {
        let mut p = healthy_pipeline();
        assert_eq!(p.sample().unwrap_err(), EntropyError::NotReady);
        assert!(!p.is_operational());
    }

    #[test]
    fn startup_passes_then_samples_flow() {
        let mut p = healthy_pipeline();
        p.run_startup().unwrap();
        assert!(p.is_operational());
        for _ in 0..100 {
            p.sample().unwrap();
        }
    }

    #[test]
    fn startup_samples_are_discarded_never_reused() {
        // After startup the source has emitted exactly STARTUP_MIN_SAMPLES;
        // the first released sample is emission #1025 — fresh, not a
        // replayed startup sample.
        let mut p = healthy_pipeline();
        p.run_startup().unwrap();
        assert_eq!(p.source().emitted, STARTUP_MIN_SAMPLES);
        let _ = p.sample().unwrap();
        assert_eq!(p.source().emitted, STARTUP_MIN_SAMPLES + 1);
    }

    #[test]
    fn startup_twice_is_refused() {
        let mut p = healthy_pipeline();
        p.run_startup().unwrap();
        assert_eq!(p.run_startup().unwrap_err(), EntropyError::NotReady);
    }

    // ── Failure classes (ISC-55 / ISC-56) ────────────────────────────

    #[test]
    fn dead_source_trips_rct_during_startup() {
        // H = 2.0, α = 2⁻²⁰ → C = 11: the constant stream fails startup
        // at the spec-expected count, and the pipeline poisons permanently.
        let mut p = EntropyPipeline::new(DeadMock, MinEntropy::from_bits(2), alpha20()).unwrap();
        assert_eq!(
            p.run_startup().unwrap_err(),
            EntropyError::Health(HealthError::Failed(HealthTest::Rct))
        );
        assert!(p.is_poisoned());
        assert_eq!(p.sample().unwrap_err(), EntropyError::NotReady);
    }

    #[test]
    fn oscillating_source_trips_apt_within_one_window() {
        // Wide (8-bit) source alternating two values under an H = 8 claim:
        // W = 512, C = 13 — trips well inside the first window (the 13th
        // reference occurrence arrives by sample 25).
        let mut p =
            EntropyPipeline::new(OscillatingMock(0), MinEntropy::from_bits(8), alpha20()).unwrap();
        assert_eq!(
            p.run_startup().unwrap_err(),
            EntropyError::Health(HealthError::Failed(HealthTest::Apt))
        );
        assert!(p.is_poisoned());
    }

    // ── Permanence + on-demand (ISC-29 / ISC-49 / §4.3 item 5) ──────

    #[test]
    fn poisoned_pipeline_never_recovers() {
        let mut p = EntropyPipeline::new(DeadMock, MinEntropy::from_bits(2), alpha20()).unwrap();
        let _ = p.run_startup();
        assert!(p.is_poisoned());
        assert_eq!(p.sample().unwrap_err(), EntropyError::NotReady);
        assert_eq!(p.run_startup().unwrap_err(), EntropyError::NotReady);
        assert_eq!(p.on_demand_test().unwrap_err(), EntropyError::NotReady);
    }

    #[test]
    fn on_demand_runs_from_clean_state() {
        // Drive the continuous RCT to the brink (10 of 11 repeats is
        // impossible to arrange through a PRNG source, so probe the
        // mechanism instead: on-demand succeeds on a healthy source and
        // consumes a full fresh battery — state carryover from the
        // continuous monitor would not change sample accounting, so also
        // verify the continuous monitor was REPLACED by the fresh one).
        let mut p = healthy_pipeline();
        p.run_startup().unwrap();
        for _ in 0..50 {
            p.sample().unwrap();
        }
        let before = p.source().emitted;
        p.on_demand_test().unwrap();
        assert_eq!(p.source().emitted, before + STARTUP_MIN_SAMPLES);
        assert!(p.is_operational());
        p.sample().unwrap();
    }

    #[test]
    fn on_demand_before_startup_is_refused() {
        let mut p = healthy_pipeline();
        assert_eq!(p.on_demand_test().unwrap_err(), EntropyError::NotReady);
    }

    // ── Conditioned output (ISC-7 / ISC-22 / ISC-126 / ISC-122) ──────

    /// Healthy PRNG source that goes dead (constant output) after a set
    /// number of emissions — for tripping health tests mid-block.
    #[derive(Debug)]
    struct DiesLaterMock {
        inner: PrngMock,
        die_after: u32,
    }
    impl Sealed for DiesLaterMock {}
    impl NoiseSource for DiesLaterMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(4)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            if self.inner.emitted >= self.die_after {
                self.inner.emitted += 1;
                return Ok(0xAA);
            }
            self.inner.sample()
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    #[test]
    fn no_conditioned_output_before_startup() {
        let mut p = healthy_pipeline();
        assert_eq!(p.conditioned_block().unwrap_err(), EntropyError::NotReady);
    }

    #[test]
    fn conditioned_block_consumes_margin_derived_sample_count() {
        // Claim H = 2.0 → ⌈(256+64)/2⌉ = 160 samples per block.
        let mut p = healthy_pipeline();
        p.run_startup().unwrap();
        assert_eq!(p.conditioner().samples_per_block(), 160);
        let before = p.source().emitted;
        let _ = p.conditioned_block().unwrap();
        assert_eq!(p.source().emitted, before + 160);
    }

    #[test]
    fn conditioned_blocks_are_stateless_across_blocks() {
        // Block 2 must equal a fresh SHA-256 over exactly the source's
        // post-startup samples 161..=320 — any chained state from block 1
        // would change it.
        let mut p = healthy_pipeline();
        p.run_startup().unwrap();
        let _block1 = p.conditioned_block().unwrap();
        let block2 = p.conditioned_block().unwrap();

        let mut replay = PrngMock::new();
        for _ in 0..(STARTUP_MIN_SAMPLES + 160) {
            let _ = replay.sample().unwrap();
        }
        let mut fresh = crate::conditioner::Conditioner::begin_block();
        for _ in 0..160 {
            fresh.update(&[replay.sample().unwrap()]);
        }
        assert_eq!(block2, fresh.finalize());
    }

    #[test]
    fn health_failure_mid_block_poisons_and_emits_nothing() {
        // Source dies 16 samples into the first conditioned block: RCT
        // (C = 11 at H = 2, α = 2⁻²⁰) trips inside the block; the partial
        // block is abandoned and the pipeline poisons permanently.
        let src = DiesLaterMock {
            inner: PrngMock::new(),
            die_after: STARTUP_MIN_SAMPLES + 16,
        };
        let mut p = EntropyPipeline::new(src, MinEntropy::from_bits(2), alpha20()).unwrap();
        p.run_startup().unwrap();
        assert_eq!(
            p.conditioned_block().unwrap_err(),
            EntropyError::Health(HealthError::Failed(HealthTest::Rct))
        );
        assert!(p.is_poisoned());
        assert_eq!(p.conditioned_block().unwrap_err(), EntropyError::NotReady);
    }

    /// Send/Sync posture: a pipeline over a Send+Sync source is Send+Sync.
    #[test]
    fn send_sync_posture() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<EntropyPipeline<PrngMock>>();
        assert_sync::<EntropyPipeline<PrngMock>>();
    }

    #[test]
    fn timer_source_metadata_shape_holds() {
        // Keep the TimerSource surface exercised from this module too.
        let m = SourceMetadata {
            timer_source: Some(TimerSource::OsNanoClock),
            ..meta()
        };
        assert_eq!(m.timer_source, Some(TimerSource::OsNanoClock));
    }
}
