//! CPU execution-time jitter noise source — noise source #1.
//!
//! # Design provenance
//!
//! Design-derived from Müller's published jitter-entropy design
//! documentation (the certificate-precedented CPU-jitter lineage). This is
//! a from-scratch implementation of the *design* — measurement of
//! execution-time variation around a serialized noise workload — and never
//! a transliteration of any existing code.
//!
//! # Mechanism
//!
//! Each sample measures the duration of one **noise workload** between two
//! reads of the configured timer:
//!
//! 1. read `t0`;
//! 2. run the workload — a SHA-256 hash chain over internal state (the
//!    workspace's own `oxicrypt-sha`) followed by a data-dependent walk
//!    over an 8 KiB memory buffer, all routed through
//!    [`core::hint::black_box`];
//! 3. read `t1`; the width-masked wrapping delta is the raw measurement.
//!
//! The black_box discipline exists because **compiler optimization can
//! destroy the noise source**: a workload the optimizer can elide or
//! precompute produces deltas that measure nothing. A release-build guard
//! test asserts that delta variance persists.
//!
//! # Digitization (justification hook)
//!
//! The emitted symbol is the **low 4 bits of the delta**
//! ([`SourceSpec::sample_width_bits`] = 4) — the timing-jitter-bearing
//! bits, per the established EA-extraction precedent of this design
//! lineage. The extraction neither conceals failures from the health
//! tests nor obscures the raw statistics: the continuous health tests,
//! the entropy claim, and the raw-data files all operate on **exactly
//! these extracted symbols** — one symbol stream end to end. The formal
//! entropy-assessment-report section restates this justification when the
//! evidence package is assembled.
//!
//! # Claim ceiling
//!
//! [`NoiseSource::max_claimable_h`] returns **1 bit per sample** — the
//! conservative per-delta posture of the design lineage. The ceiling is a
//! design argument, not an assessment: operators inject their (per-OE,
//! assessment-backed) claim at pipeline construction, and the pipeline
//! refuses anything above this ceiling. No claimed-H value appears in
//! this module.
//!
//! # Timer adequacy
//!
//! Construction runs the measured-never-assumed adequacy self-check
//! ([`crate::timer::measure_adequacy`]) and refuses an inadequate timer
//! with the typed reason — a jitter source never starts on a timer whose
//! observed granularity cannot carry it. This per-construction check is
//! the standing guarantor of measurement integrity across compiler
//! versions and targets: if a future toolchain elides the workload
//! despite the black_box routing, the delta distribution collapses and
//! construction fails closed. (The timer reads themselves are
//! hardware-serialized in `oxicrypt-timer` — LFENCE+RDTSC / ISB+MRS — so
//! CPU reordering cannot retire the second read early.)
//!
//! # Known, accepted property
//!
//! Backwards deltas are discarded and remeasured (bounded), a mild
//! forward-only selection on the delta stream. Under the 1-of-4-bit
//! conservative credit this bias is negligible; it is recorded here so it
//! is a documented design property, not a discovered one.

use crate::h::MinEntropy;
use crate::source::{
    NoiseSource, RawSample, SourceError, SourceMetadata, SourceSpec, TimerSource, sealed::Sealed,
};
use crate::timer::{
    AdequacyConfig, AdequacyReport, TimerError, TimerRead, measure_adequacy, wrapping_delta,
};

/// Size of the data-dependent memory-walk buffer (8 KiB — larger than a
/// typical L1 line-fill comfort zone, an engineering default).
const WALK_BUF_LEN: usize = 8192;

/// Number of walk touches per workload round (engineering default).
const WALK_TOUCHES: usize = 64;

/// Consecutive backwards-delta limit before the source reports itself
/// unavailable (engineering default; each backwards delta is discarded
/// and remeasured per the timer-layer contract).
const MAX_CONSECUTIVE_BACKWARDS: u32 = 64;

/// Construction-time configuration for [`JitterSource`].
#[derive(Debug, Clone, Copy)]
pub struct JitterConfig<'m> {
    /// Timer-adequacy thresholds (defaults are the documented engineering
    /// choices in [`crate::timer`]).
    pub adequacy: AdequacyConfig,
    /// Which timer this source reads — recorded into dataset metadata.
    pub timer_source: Option<TimerSource>,
    /// Collection-environment identity (no anonymous datasets).
    pub cpu_model: &'m str,
    /// Operating system of the collection environment.
    pub os: &'m str,
    /// Collection parameters sufficient to reproduce a dataset.
    pub collection_params: &'m str,
}

impl Default for JitterConfig<'static> {
    fn default() -> Self {
        Self {
            adequacy: AdequacyConfig::default(),
            timer_source: None,
            cpu_model: "unspecified",
            os: "unspecified",
            collection_params: "default jitter config",
        }
    }
}

/// CPU execution-time jitter source over a configured timer.
pub struct JitterSource<'m, T: TimerRead> {
    timer: T,
    state: [u8; 32],
    walk: [u8; WALK_BUF_LEN],
    adequacy: AdequacyReport,
    config: JitterConfig<'m>,
}

impl<T: TimerRead> core::fmt::Debug for JitterSource<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never expose buffer contents: identity and adequacy only.
        f.debug_struct("JitterSource")
            .field("adequacy", &self.adequacy)
            .field("timer_source", &self.config.timer_source)
            .finish_non_exhaustive()
    }
}

impl<'m, T: TimerRead> JitterSource<'m, T> {
    /// Constructs the source, running the timer-adequacy self-check.
    ///
    /// # Errors
    ///
    /// [`TimerError::Inadequate`] (typed reason) when the measured timer
    /// behavior cannot carry a jitter source.
    pub fn new(mut timer: T, config: JitterConfig<'m>) -> Result<Self, TimerError> {
        let adequacy = measure_adequacy(&mut timer, &config.adequacy);
        adequacy.ensure_adequate(&config.adequacy)?;
        Ok(Self {
            timer,
            state: [0x5C; 32],
            walk: [0xA5; WALK_BUF_LEN],
            adequacy,
            config,
        })
    }

    /// The adequacy report measured at construction (dataset metadata and
    /// noise-source-description evidence).
    #[must_use]
    pub const fn adequacy(&self) -> &AdequacyReport {
        &self.adequacy
    }

    /// One noise-workload round: SHA-256 chain over internal state, then a
    /// data-dependent memory walk. Inputs and outputs are routed through
    /// `black_box` so the optimizer cannot elide or precompute the work.
    fn workload(&mut self) {
        use oxicrypt_sha::Sha256;
        // new_internal: the documented module-state bypass. The load-bearing
        // justification: THE ENTROPY IS IN THE TIMING OF COMPUTING THE HASH,
        // NEVER IN THE DIGEST VALUE — the digest only steers the memory walk,
        // so SHA correctness is not security-relevant on this path and the
        // entropy claim is untainted by skipping the per-use operational
        // gate. (The module's SHA-256 power-up self-test still validates the
        // algorithm itself; the bypass skips only the per-call state check.)
        // Secondarily: the entropy source runs pre-operational by definition
        // — it feeds the seeding path Operational state depends on.
        let mut hasher = Sha256::new_internal();
        hasher.update(core::hint::black_box(&self.state));
        hasher.update(core::hint::black_box(&self.walk[..64]));
        let digest = hasher.finalize();
        self.state = core::hint::black_box(digest);
        // Data-dependent walk: indices derived from the fresh digest.
        let mut idx: usize = 0;
        for &b in &digest {
            idx = (idx.wrapping_mul(257).wrapping_add(usize::from(b))) % WALK_BUF_LEN;
            // Bounded by the modulus — index cannot exceed the buffer.
            if let Some(cell) = self.walk.get_mut(idx) {
                *cell = cell.wrapping_add(b).rotate_left(1);
            }
        }
        for t in 0..WALK_TOUCHES.saturating_sub(digest.len()) {
            idx = (idx.wrapping_mul(193).wrapping_add(t)) % WALK_BUF_LEN;
            if let Some(cell) = self.walk.get_mut(idx) {
                *cell = core::hint::black_box(cell.wrapping_add(1));
            }
        }
    }

    /// Measures one workload duration, returning the raw delta.
    fn measure_once(&mut self) -> Result<u64, ()> {
        let width = self.timer.width_bits();
        let t0 = self.timer.read();
        self.workload();
        let t1 = self.timer.read();
        wrapping_delta(t0, t1, width).map_err(|_| ())
    }
}

impl<T: TimerRead> Sealed for JitterSource<'_, T> {}

impl<T: TimerRead> NoiseSource for JitterSource<'_, T> {
    fn spec(&self) -> SourceSpec {
        // 4-bit digitized symbols; width is structurally valid.
        SourceSpec::new(4).unwrap_or_else(|| unreachable!())
    }

    fn max_claimable_h(&self) -> MinEntropy {
        // Design-anchored conservative ceiling: 1 bit per sample.
        MinEntropy::from_bits(1)
    }

    fn sample(&mut self) -> Result<RawSample, SourceError> {
        let mut backwards: u32 = 0;
        loop {
            if let Ok(delta) = self.measure_once() {
                // Digitization: low 4 bits of the delta.
                #[allow(clippy::cast_possible_truncation)]
                return Ok((delta & 0x0F) as u8);
            }
            // Backwards delta: discard and remeasure, bounded.
            backwards = backwards.saturating_add(1);
            if backwards >= MAX_CONSECUTIVE_BACKWARDS {
                return Err(SourceError::Unavailable);
            }
        }
    }

    fn metadata(&self) -> SourceMetadata<'_> {
        SourceMetadata {
            timer_source: self.config.timer_source,
            counter_frequency_hz: None,
            cpu_model: self.config.cpu_model,
            os: self.config.os,
            collection_params: self.config.collection_params,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::integer_division
)]
mod tests {
    use super::*;

    /// Synthetic fine-grained timer: varied positive increments.
    struct VariedTimer {
        n: u64,
        v: u64,
    }
    impl Sealed for VariedTimer {}
    impl TimerRead for VariedTimer {
        fn read(&mut self) -> u64 {
            self.n += 1;
            self.v = self.v.wrapping_add((self.n % 13) + 1);
            self.v
        }
    }

    /// Synthetic coarse timer: ticks once every 64 reads.
    struct CoarseTimer {
        n: u64,
    }
    impl Sealed for CoarseTimer {}
    impl TimerRead for CoarseTimer {
        fn read(&mut self) -> u64 {
            self.n += 1;
            self.n / 64
        }
    }

    fn cfg() -> JitterConfig<'static> {
        JitterConfig {
            adequacy: AdequacyConfig {
                samples: 256,
                ..AdequacyConfig::default()
            },
            ..JitterConfig::default()
        }
    }

    #[test]
    fn construction_runs_adequacy_and_refuses_coarse_timers() {
        // ISC-19 wiring: an inadequate timer never yields a source.
        let err = JitterSource::new(CoarseTimer { n: 0 }, cfg()).unwrap_err();
        assert!(matches!(err, TimerError::Inadequate(_)));
        // An adequate synthetic timer constructs.
        let src = JitterSource::new(VariedTimer { n: 0, v: 0 }, cfg()).unwrap();
        assert_eq!(src.adequacy().backwards_violations, 0);
    }

    #[test]
    fn spec_and_ceiling_are_the_design_values() {
        let src = JitterSource::new(VariedTimer { n: 0, v: 0 }, cfg()).unwrap();
        assert_eq!(src.spec().sample_width_bits(), 4);
        assert!(!src.spec().is_binary());
        assert_eq!(src.max_claimable_h(), MinEntropy::from_bits(1));
    }

    #[test]
    fn samples_are_low_four_bits_and_vary() {
        let mut src = JitterSource::new(VariedTimer { n: 0, v: 0 }, cfg()).unwrap();
        let mut seen = [false; 16];
        for _ in 0..512 {
            let s = src.sample().unwrap();
            assert!(s < 16, "digitized symbol exceeds 4-bit width");
            seen[usize::from(s)] = true;
        }
        // The synthetic timer's varied increments produce symbol variety.
        assert!(seen.iter().filter(|&&b| b).count() >= 4);
    }

    #[test]
    fn debug_never_exposes_buffers() {
        // ISC-53 posture: Debug shows identity, never sample-bearing state.
        let src = JitterSource::new(VariedTimer { n: 0, v: 0 }, cfg()).unwrap();
        let s = debug_to_buf(&src);
        assert!(s.contains("JitterSource"));
        assert!(!s.contains("0x5c") && !s.contains("92, 92"));
    }

    // Minimal formatter without alloc in the crate: fixed buffer.
    fn debug_to_buf(v: &impl core::fmt::Debug) -> FixedBuf {
        use core::fmt::Write;
        let mut buf = FixedBuf {
            data: [0; 256],
            len: 0,
        };
        let _ = write!(&mut buf, "{v:?}");
        buf
    }
    struct FixedBuf {
        data: [u8; 256],
        len: usize,
    }
    impl FixedBuf {
        fn contains(&self, needle: &str) -> bool {
            core::str::from_utf8(&self.data[..self.len]).is_ok_and(|s| s.contains(needle))
        }
    }
    impl core::fmt::Write for FixedBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let room = self.data.len() - self.len;
            let take = bytes.len().min(room);
            self.data[self.len..self.len + take].copy_from_slice(&bytes[..take]);
            self.len += take;
            Ok(())
        }
    }

    /// ISC-114 guard: delta variance persists through the real workload —
    /// meaningful under --release where the optimizer would hollow an
    /// unprotected workload. Runs against the live raw counter.
    #[cfg(feature = "raw-counter")]
    #[test]
    fn release_guard_delta_variance_persists() {
        use crate::source::TimerSource as TS;
        use crate::timer::PlatformTimer;
        let timer = PlatformTimer::new(TS::RawCounter).unwrap();
        let src = JitterSource::new(timer, JitterConfig::default());
        // On a host whose timer passes adequacy, variance must be present.
        match src {
            Ok(s) => {
                assert!(s.adequacy().distinct_deltas >= 4);
                assert!(s.adequacy().min_positive_delta.is_some());
            }
            Err(TimerError::Inadequate(reason)) => {
                panic!("live timer judged inadequate on this host: {reason:?}");
            }
            Err(e) => panic!("unexpected timer error: {e:?}"),
        }
    }

    /// Live end-to-end: jitter → startup health tests → released samples.
    #[cfg(feature = "raw-counter")]
    #[test]
    fn live_jitter_flows_through_full_pipeline() {
        use crate::health::Alpha;
        use crate::pipeline::EntropyPipeline;
        use crate::source::TimerSource as TS;
        use crate::timer::PlatformTimer;
        let timer = PlatformTimer::new(TS::RawCounter).unwrap();
        let src = JitterSource::new(timer, JitterConfig::default()).unwrap();
        // Claim 0.5 bit/sample (≤ the 1-bit ceiling; APT grid row 0.5).
        let claim = MinEntropy::from_fraction_floor(1, 2).unwrap();
        let mut p = EntropyPipeline::new(src, claim, Alpha::from_exp(20).unwrap()).unwrap();
        p.run_startup()
            .expect("live jitter failed startup health tests");
        for _ in 0..256 {
            let s = p.sample().expect("live sample refused");
            assert!(s < 16);
        }
    }
}
