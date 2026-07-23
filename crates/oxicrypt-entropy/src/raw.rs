//! Raw-data collection: unconditioned sample capture for ESV submission.
//!
//! This module is the **structural counterpart** to [`crate::pipeline`]. The
//! conditioned pipeline emits 256-bit blocks; this module's [`RawCollector`]
//! emits the *unconditioned* noise stream for an Entropy Source Validation
//! (ESV) data file. The two are **distinct types constructed separately**
//! ([`RawCollector`] has **no conditioner field**) — there is no API path
//! that yields both raw and conditioned output from one instance. Raw versus
//! conditioned is a compile-time type distinction, never a runtime flag (the
//! R75/R77 compiler-checked-disjointness precedent).
//!
//! # Two postures over the same captured stream
//!
//! A collection runs in one of two [`CollectionPosture`]s; both capture the
//! complete unfiltered stream, and they differ only in the acceptance verdict:
//!
//! - **Characterization** ([`CollectionPosture::Characterization`]): the
//!   noise stream is emitted UNFILTERED after startup gating. The live RCT/APT
//!   battery runs *alongside* collection and records every trip into the
//!   dataset metadata, but **no sample is ever silently dropped, filtered, or
//!   window-stitched** — the emitted stream is the true, complete noise
//!   stream. The verdict is always
//!   [`CertVerdict::ValidForCharacterization`]. (This is the deliberate
//!   "collect unfiltered, annotate, never drop" posture: an entropy estimate
//!   must assess the *true* source distribution, and a filtered dataset would
//!   misrepresent it.)
//! - **Certification** ([`CollectionPosture::Certification`]): the same full
//!   annotated stream is captured, but the dataset submitted for a
//!   min-entropy estimate must be a clean, contiguous, **trip-free** run. If
//!   any RCT/APT trip occurred mid-run, the source declared itself unhealthy,
//!   so the run is INVALIDATED and the verdict is
//!   [`CertVerdict::InvalidReCollect`] — re-collect, never window-stitch. The
//!   unfiltered-annotated capture is retained only as characterization
//!   evidence. **No stitching code path exists.**
//!
//! The contrast with [`crate::pipeline::EntropyPipeline`] is load-bearing: in
//! the pipeline a health trip *poisons* and the sample is *not* released; in a
//! characterization capture a trip is *annotated* and the sample *is* still
//! emitted so the 1M stream is preserved. The collector therefore cannot reuse
//! [`HealthMonitor`]'s poison-and-withhold `feed`; it reconstructs the
//! lightweight trip detection (run-length for RCT, windowed-count for APT)
//! from the public [`HealthMonitor::rct_cutoff`] / [`HealthMonitor::apt_cutoff`]
//! values.
//!
//! # Wire format
//!
//! Emitted symbols are one byte per sample, each within the effective width
//! `min(sample_width_bits, 8)`; a source that ever emits a symbol wider than
//! its declared width is a typed [`EntropyError::Source`] refusal, never a
//! silent mask. A full ESV data file is exactly
//! [`crate::sp800_90b::RAW_DATA_SAMPLE_COUNT`] (1,000,000) samples.
//!
//! # std gating
//!
//! The collector's struct, sample/health hot path, and startup gating are
//! `no_std`. Metadata accumulation (the trip [`alloc::vec::Vec`]), the metadata
//! document, its JSON serializer, and the schema validator are `std`-only
//! surfaces and are gated behind the `std` feature so `cargo check
//! --no-default-features` still builds the core.

// The crate-private `RawCollector`, its `no_std` core, and the std collection
// surface (metadata + JSON serializer + schema validator) are exercised by the
// in-crate tests and, from the next milestone, by the default-off `collection`
// binary that will own the runbook-facing entry point. Until that binary lands,
// the only non-test consumer does not yet exist, so these items read as dead
// code in any non-`test` build. Suppress the dead-code lint ONLY when not under
// test — the test target uses every item, so a genuine dead-code regression in
// the tested surface is still caught; this allow simply tolerates the
// not-yet-wired-up bin consumer for one milestone.
#![cfg_attr(not(test), allow(dead_code))]

use crate::error::EntropyError;
use crate::h::MinEntropy;
use crate::health::{Alpha, HealthMonitor};
use crate::source::NoiseSource;
use crate::sp800_90b::STARTUP_MIN_SAMPLES;

#[cfg(feature = "std")]
use crate::health::{HealthError, HealthTest};
#[cfg(feature = "std")]
use crate::source::RawSample;

/// Collector lifecycle state — mirrors the pipeline's shape but is a separate
/// type (no conditioner stage, no conditioning KAT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingStartup,
    Operational,
    Poisoned,
}

/// One health-test trip observed during unfiltered characterization capture.
///
/// A trip is *annotated*, never acted on: the offending sample is still
/// emitted. These fields are health-test metadata (an index, which test, and
/// the run-length/count at the trip) — **not** raw sample values — so the type
/// safely derives [`Debug`].
///
/// Part of the std collection surface (the trip annotations live in the
/// metadata document); gated so the `no_std` core carries no dead code.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TripEvent {
    /// Zero-based index of the sample at which the test tripped.
    pub sample_index: u32,
    /// Which continuous health test tripped.
    pub test: HealthTest,
    /// The run-length (RCT) or windowed count (APT) at the trip.
    pub value: u32,
}

/// Acceptance verdict for a completed collection run.
///
/// The verdict depends on the [`CollectionPosture`] and on whether any health
/// trip occurred. There is no stitching path: a certification run that tripped
/// produces *no* submission output.
///
/// Part of the std collection surface; gated so the `no_std` core carries no
/// dead code.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertVerdict {
    /// Characterization posture: the captured stream is valid as
    /// characterization evidence regardless of trips (which are annotated).
    ValidForCharacterization,
    /// Certification posture, no trip occurred: the captured stream is a
    /// clean, contiguous, trip-free run suitable for a min-entropy estimate.
    ValidForSubmission,
    /// Certification posture, a trip occurred mid-run: the run is invalid for
    /// submission and must be re-collected. The captured stream is retained
    /// only as characterization evidence, never window-stitched.
    InvalidReCollect,
}

/// Which acceptance discipline a collection runs under (same captured stream,
/// different verdict). Modeled as an enum, not two methods, so the single
/// capture driver has exactly one implementation and no stitching branch.
///
/// Part of the std collection surface; gated so the `no_std` core carries no
/// dead code.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CollectionPosture {
    /// Emit unfiltered, annotate trips, never drop (characterization evidence).
    Characterization,
    /// Require a clean, contiguous, trip-free run (certification submission).
    Certification,
}

/// Non-withholding characterization health pass.
///
/// Reconstructs the SP 800-90B §4.4.1 (RCT, run-length) and §4.4.2 (APT,
/// windowed count) trip *detection* against the public cutoffs taken from a
/// [`HealthMonitor`], **without** that monitor's poison-and-withhold behavior:
/// every sample is still emitted, a trip is merely reported. No floating point;
/// every counter uses saturating arithmetic.
///
/// Used only by the std collection driver; gated so the `no_std` core has no
/// dead code.
#[cfg(feature = "std")]
#[derive(Debug)]
struct CharacterizationHealth {
    // RCT (run-length) state.
    rct_cutoff: u32,
    last: Option<RawSample>,
    run_len: u32,
    // APT (windowed-count) state.
    apt_cutoff: u32,
    apt_window: u32,
    reference: Option<RawSample>,
    count: u32,
    pos: u32,
}

#[cfg(feature = "std")]
impl CharacterizationHealth {
    /// Builds the pass from the cutoffs and window the equivalent
    /// [`HealthMonitor`] would use for this claim/alphabet/alpha.
    fn new(h: MinEntropy, is_binary: bool, alpha: Alpha) -> Result<Self, HealthError> {
        let monitor = HealthMonitor::new(h, is_binary, alpha)?;
        let apt_window = if is_binary {
            crate::sp800_90b::APT_WINDOW_BINARY
        } else {
            crate::sp800_90b::APT_WINDOW_NON_BINARY
        };
        Ok(Self {
            rct_cutoff: monitor.rct_cutoff(),
            last: None,
            run_len: 0,
            apt_cutoff: monitor.apt_cutoff(),
            apt_window,
            reference: None,
            count: 0,
            pos: 0,
        })
    }

    /// Observes one sample, returning a trip annotation when either test
    /// reaches its cutoff. The sample is never withheld; on a trip the run/
    /// window state continues exactly as §4.4 prescribes (RCT run resets only
    /// on a value change; APT window restarts at its boundary), so detection
    /// keeps working across the rest of the stream.
    fn observe(&mut self, sample: RawSample, index: u32) -> Option<TripEvent> {
        // ── RCT: run-length of the most recent value. ──
        if self.last == Some(sample) {
            self.run_len = self.run_len.saturating_add(1);
        } else {
            self.last = Some(sample);
            self.run_len = 1;
        }
        let rct_trip = self.run_len >= self.rct_cutoff;

        // ── APT: count of the window's reference value. ──
        match self.reference {
            None => {
                self.reference = Some(sample);
                self.count = 1;
                self.pos = 1;
            }
            Some(reference) => {
                self.pos = self.pos.saturating_add(1);
                if sample == reference {
                    self.count = self.count.saturating_add(1);
                }
            }
        }
        let apt_trip = self.count >= self.apt_cutoff;
        let apt_count_at_trip = self.count;
        if self.pos >= self.apt_window {
            // Window complete — restart per §4.4.2 step 4.
            self.reference = None;
            self.count = 0;
            self.pos = 0;
        }

        // RCT is reported first when both trip on the same sample (it is the
        // total-failure test); only one annotation per sample.
        if rct_trip {
            Some(TripEvent {
                sample_index: index,
                test: HealthTest::Rct,
                value: self.run_len,
            })
        } else if apt_trip {
            Some(TripEvent {
                sample_index: index,
                test: HealthTest::Apt,
                value: apt_count_at_trip,
            })
        } else {
            None
        }
    }
}

/// Unconditioned raw-data collector: source + full health battery, **no
/// conditioner**.
///
/// Constructed separately from [`crate::pipeline::EntropyPipeline`] and
/// structurally incapable of producing conditioned output — it holds no
/// conditioner and exposes no block-emission method. This compile-time
/// exclusion is the raw/conditioned disjointness guarantee.
///
/// Crate-private: the public collection binary (added later behind a default-off
/// feature) constructs it; it is not part of the crate's public API.
pub(crate) struct RawCollector<S: NoiseSource> {
    source: S,
    claimed_h: MinEntropy,
    alpha: Alpha,
    is_binary: bool,
    state: State,
}

// Hand-written redacting Debug: never expose the source's sample-bearing
// internals. Identity and lifecycle only.
impl<S: NoiseSource> core::fmt::Debug for RawCollector<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawCollector")
            .field("state", &self.state)
            .field("claimed_h_steps", &self.claimed_h.steps())
            .field("alpha_exp", &self.alpha.exp())
            .finish_non_exhaustive()
    }
}

impl<S: NoiseSource> RawCollector<S> {
    /// Constructs a collector, injecting the claimed min-entropy per sample
    /// and the health-test false-positive probability — the same claim-ceiling,
    /// sample-width, and health-monitor checks as
    /// [`crate::pipeline::EntropyPipeline::new`], minus the conditioner
    /// derivation (there is none).
    ///
    /// # Errors
    ///
    /// - [`EntropyError::ClaimExceedsCeiling`] if `claimed_h` exceeds the
    ///   source's design ceiling — refused, never clamped.
    /// - [`EntropyError::ClaimExceedsSampleWidth`] if `claimed_h` exceeds the
    ///   declared sample width in bits.
    /// - [`EntropyError::Health`] (`UnsupportedAlpha`) if the requested
    ///   (alpha, alphabet, H) point has no precomputed APT cutoff coverage.
    pub(crate) fn new(
        source: S,
        claimed_h: MinEntropy,
        alpha: Alpha,
    ) -> Result<Self, EntropyError> {
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
        // Construct (and immediately discard) a monitor to validate that the
        // (alpha, alphabet, H) point is table-covered, matching the pipeline's
        // construction-time refusal. The collector itself rebuilds health
        // state per posture/startup, so it does not retain this monitor.
        let _ = HealthMonitor::new(claimed_h, spec.is_binary(), alpha)?;
        Ok(Self {
            source,
            claimed_h,
            alpha,
            is_binary: spec.is_binary(),
            state: State::AwaitingStartup,
        })
    }

    /// Runs the startup continuous health battery over at least
    /// [`STARTUP_MIN_SAMPLES`] samples on a **fresh** monitor (poison-and-
    /// withhold semantics here: startup gates collection start). The tested
    /// samples are discarded. Transitions `AwaitingStartup` → `Operational`.
    /// There is no conditioning KAT — raw mode has no conditioner.
    ///
    /// # Errors
    ///
    /// - [`EntropyError::NotReady`] if startup already ran.
    /// - [`EntropyError::Health`] on a startup test failure — the collector is
    ///   then permanently poisoned.
    /// - [`EntropyError::Source`] if the source fails to produce samples.
    pub(crate) fn run_startup(&mut self) -> Result<(), EntropyError> {
        match self.state {
            State::AwaitingStartup => (),
            State::Operational | State::Poisoned => return Err(EntropyError::NotReady),
        }
        let mut fresh = HealthMonitor::new(self.claimed_h, self.is_binary, self.alpha)
            .map_err(EntropyError::Health)?;
        let mut fed: u32 = 0;
        while fed < STARTUP_MIN_SAMPLES {
            let sample = self.source.sample().map_err(EntropyError::Source)?;
            if let Err(e) = fresh.feed(sample) {
                self.state = State::Poisoned;
                return Err(EntropyError::Health(e));
            }
            fed = fed.saturating_add(1);
            // The startup sample goes out of scope here: discarded.
        }
        self.state = State::Operational;
        Ok(())
    }

    /// Whether startup has passed and the collector can emit samples.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn is_operational(&self) -> bool {
        self.state == State::Operational
    }

    /// Whether a startup health failure has permanently poisoned the collector.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.state == State::Poisoned
    }

    /// Shared access to the underlying source (metadata, adequacy, etc.).
    #[cfg(any(feature = "std", test))]
    pub(crate) fn source(&self) -> &S {
        &self.source
    }

    /// Emits the next sample, bounding it to the declared effective width.
    ///
    /// Effective width is `min(sample_width_bits, 8)`. A source that emits a
    /// symbol wider than its declared width is a typed
    /// [`EntropyError::Source`] (`SourceError::Unavailable`) refusal — never a
    /// silent mask, so an over-wide source is surfaced rather than hidden.
    ///
    /// # Errors
    ///
    /// - [`EntropyError::NotReady`] before startup or after poisoning.
    /// - [`EntropyError::Source`] on a source failure or an over-wide symbol.
    #[cfg(feature = "std")]
    fn next_bounded(&mut self) -> Result<RawSample, EntropyError> {
        match self.state {
            State::Operational => (),
            State::AwaitingStartup | State::Poisoned => return Err(EntropyError::NotReady),
        }
        let sample = self.source.sample().map_err(EntropyError::Source)?;
        let width = self.source.spec().sample_width_bits().min(8);
        // `sample >> width == 0` proves the symbol fits the effective width.
        // width is 1..=8, so the shift cannot exceed the type width (a shift
        // by 8 on a u8 is still defined here because we widen to u32 first).
        if u32::from(sample) >> u32::from(width) != 0 {
            return Err(EntropyError::Source(
                crate::source::SourceError::Unavailable,
            ));
        }
        Ok(sample)
    }
}

/// Standard-library collection surface: the full annotated capture, the
/// metadata document, its hand-rolled JSON serializer, and the purpose-built
/// subset schema validator. Pure Rust, no external crate, no C/FFI.
#[cfg(feature = "std")]
mod std_collection {
    use super::{
        CertVerdict, CharacterizationHealth, CollectionPosture, RawCollector, State, TripEvent,
    };
    use crate::error::EntropyError;
    use crate::source::{NoiseSource, RawSample, TimerSource};
    use std::string::String;
    use std::vec::Vec;

    /// A completed raw-data collection: the captured sample stream, the
    /// acceptance verdict, and the dataset metadata (with trip annotations).
    ///
    /// The sample buffer is zeroized on drop ([`Drop`] below) via
    /// `oxicrypt-zeroize`. The [`core::fmt::Debug`] impl is hand-written and
    /// **redacts the sample buffer** — it never prints sample bytes.
    pub(crate) struct CollectedDataset {
        samples: Vec<RawSample>,
        verdict: CertVerdict,
        metadata: DatasetMetadata,
    }

    impl CollectedDataset {
        /// The captured sample stream (one byte per sample). For
        /// characterization this is the complete, unfiltered stream; for a
        /// valid certification run it is the clean, contiguous, trip-free run.
        pub(crate) fn samples(&self) -> &[RawSample] {
            &self.samples
        }

        /// The acceptance verdict for this run.
        pub(crate) fn verdict(&self) -> CertVerdict {
            self.verdict
        }

        /// The dataset metadata (environment + trip annotations).
        pub(crate) fn metadata(&self) -> &DatasetMetadata {
            &self.metadata
        }

        /// Whether the run produced a submission-eligible dataset. True only
        /// for [`CertVerdict::ValidForSubmission`]; a tripped certification run
        /// ([`CertVerdict::InvalidReCollect`]) is never submission-eligible,
        /// and no stitched output is produced for it.
        pub(crate) fn is_submission(&self) -> bool {
            matches!(self.verdict, CertVerdict::ValidForSubmission)
        }
    }

    // Hand-written redacting Debug: field names + the sample COUNT, never the
    // sample bytes.
    impl core::fmt::Debug for CollectedDataset {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("CollectedDataset")
                .field("samples_collected", &self.samples.len())
                .field("verdict", &self.verdict)
                .field("trips", &self.metadata.trips.len())
                .finish_non_exhaustive()
        }
    }

    impl Drop for CollectedDataset {
        fn drop(&mut self) {
            // Zeroize the captured noise stream on drop (CSP-handling
            // discipline, consistent with the rest of the workspace).
            oxicrypt_zeroize::zeroize(&mut self.samples);
        }
    }

    /// Dataset metadata sidecar — validates against
    /// `schema/dataset-metadata.schema.v1.json`.
    ///
    /// Records the collection environment (no anonymous datasets), the
    /// **measured** counter frequency (never the nominal
    /// [`crate::source::SourceMetadata::counter_frequency_hz`]), the injected
    /// claim and health configuration, the sample count, and every health-test
    /// trip annotation. The struct holds only metadata (no sample bytes) so it
    /// safely derives [`Debug`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct DatasetMetadata {
        /// Schema version (this document is version 1).
        pub schema_version: u32,
        /// Number of one-byte samples in the accompanying raw-data file.
        pub sample_count: u32,
        /// Declared sample width in bits (1..=8).
        pub sample_width_bits: u8,
        /// Injected min-entropy claim per sample, in 1/256-bit steps.
        pub claimed_h_steps: u32,
        /// Health-test false-positive exponent a in alpha = 2^-a.
        pub alpha_exp: u32,
        /// Timer/counter the source read (or `None`).
        pub timer_source: Option<TimerSource>,
        /// MEASURED counter frequency in Hz — never the nominal value. `None`
        /// when no measurement was taken.
        pub measured_counter_frequency_hz: Option<u64>,
        /// CPU model string of the collection environment.
        pub cpu_model: String,
        /// Operating system of the collection environment.
        pub os: String,
        /// Free-form collection parameters sufficient to reproduce the dataset.
        pub collection_params: String,
        /// Health-test trip annotations (annotated during unfiltered capture;
        /// never a reason to drop a sample).
        pub trips: Vec<TripEvent>,
    }

    impl DatasetMetadata {
        /// Serializes the metadata to a canonical JSON document (hand-rolled;
        /// no serde, no external crate).
        pub(crate) fn to_json(&self) -> String {
            let mut out = String::new();
            out.push('{');
            push_u32_field(&mut out, "schema_version", self.schema_version, true);
            push_u32_field(&mut out, "sample_count", self.sample_count, false);
            push_u32_field(
                &mut out,
                "sample_width_bits",
                u32::from(self.sample_width_bits),
                false,
            );
            push_u32_field(&mut out, "claimed_h_steps", self.claimed_h_steps, false);
            push_u32_field(&mut out, "alpha_exp", self.alpha_exp, false);
            // timer_source: string or null.
            out.push(',');
            push_key(&mut out, "timer_source");
            match self.timer_source {
                Some(ts) => push_json_string(&mut out, timer_source_name(ts)),
                None => out.push_str("null"),
            }
            // measured_counter_frequency_hz: integer or null.
            out.push(',');
            push_key(&mut out, "measured_counter_frequency_hz");
            match self.measured_counter_frequency_hz {
                Some(hz) => {
                    let mut buf = itoa_u64(hz);
                    out.push_str(&buf);
                    buf.clear();
                }
                None => out.push_str("null"),
            }
            push_str_field(&mut out, "cpu_model", &self.cpu_model);
            push_str_field(&mut out, "os", &self.os);
            push_str_field(&mut out, "collection_params", &self.collection_params);
            // trips: array of objects.
            out.push(',');
            push_key(&mut out, "trips");
            out.push('[');
            for (i, trip) in self.trips.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('{');
                push_u32_field(&mut out, "sample_index", trip.sample_index, true);
                out.push(',');
                push_key(&mut out, "test");
                push_json_string(&mut out, health_test_name(trip.test));
                push_u32_field(&mut out, "value", trip.value, false);
                out.push('}');
            }
            out.push(']');
            out.push('}');
            out
        }
    }

    fn timer_source_name(ts: TimerSource) -> &'static str {
        match ts {
            TimerSource::RawCounter => "RawCounter",
            TimerSource::OsNanoClock => "OsNanoClock",
            TimerSource::InternalTimerThread => "InternalTimerThread",
        }
    }

    fn health_test_name(t: crate::health::HealthTest) -> &'static str {
        match t {
            crate::health::HealthTest::Rct => "Rct",
            crate::health::HealthTest::Apt => "Apt",
        }
    }

    fn push_key(out: &mut String, key: &str) {
        push_json_string(out, key);
        out.push(':');
    }

    fn push_u32_field(out: &mut String, key: &str, value: u32, first: bool) {
        if !first {
            out.push(',');
        }
        push_key(out, key);
        out.push_str(&itoa_u64(u64::from(value)));
    }

    fn push_str_field(out: &mut String, key: &str, value: &str) {
        out.push(',');
        push_key(out, key);
        push_json_string(out, value);
    }

    /// Appends a properly escaped JSON string literal.
    fn push_json_string(out: &mut String, s: &str) {
        out.push('"');
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str("\\u");
                    let code = c as u32;
                    for shift in [12u32, 8, 4, 0] {
                        let nibble = (code >> shift) & 0xF;
                        let hex = char::from_digit(nibble, 16).unwrap_or('0');
                        out.push(hex);
                    }
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }

    /// Minimal unsigned-integer formatter (avoids pulling format machinery
    /// where a tiny helper suffices; keeps the serializer allocation-light).
    fn itoa_u64(mut v: u64) -> String {
        if v == 0 {
            return String::from("0");
        }
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        while v > 0 {
            i = i.saturating_sub(1);
            let d = u8::try_from(v % 10).unwrap_or(0);
            if let Some(slot) = digits.get_mut(i) {
                *slot = b'0'.wrapping_add(d);
            }
            v /= 10;
        }
        match core::str::from_utf8(digits.get(i..).unwrap_or(&[])) {
            Ok(s) => String::from(s),
            Err(_) => String::from("0"),
        }
    }

    impl<S: NoiseSource> RawCollector<S> {
        /// Captures a full raw-data collection under `posture`, recording
        /// `count` samples plus the measured counter frequency.
        ///
        /// Both postures capture the complete stream; the posture only changes
        /// the verdict (see [`CollectionPosture`]). In characterization,
        /// health trips are annotated into the metadata and **every** sample is
        /// emitted (no drop, no filter, no window-stitch). In certification, a
        /// mid-run trip yields [`CertVerdict::InvalidReCollect`] and **no**
        /// trip-free submission output is produced — the captured stream is
        /// retained only as characterization evidence, never stitched.
        ///
        /// # Errors
        ///
        /// - [`EntropyError::NotReady`] before startup or after poisoning.
        /// - [`EntropyError::Source`] on a source failure or over-wide symbol.
        pub(crate) fn collect(
            &mut self,
            posture: CollectionPosture,
            count: u32,
            measured_counter_frequency_hz: Option<u64>,
        ) -> Result<CollectedDataset, EntropyError> {
            match self.state {
                State::Operational => (),
                State::AwaitingStartup | State::Poisoned => return Err(EntropyError::NotReady),
            }
            let mut health =
                CharacterizationHealth::new(self.claimed_h, self.is_binary, self.alpha)
                    .map_err(EntropyError::Health)?;
            let mut samples: Vec<RawSample> = Vec::with_capacity(count as usize);
            let mut trips: Vec<TripEvent> = Vec::new();
            let mut tripped = false;

            let mut index: u32 = 0;
            while index < count {
                let sample = self.next_bounded()?;
                // Annotate-never-drop: the sample is ALWAYS pushed, whether or
                // not a trip is observed on it.
                samples.push(sample);
                if let Some(event) = health.observe(sample, index) {
                    trips.push(event);
                    tripped = true;
                }
                index = index.saturating_add(1);
            }

            let verdict = match posture {
                CollectionPosture::Characterization => CertVerdict::ValidForCharacterization,
                CollectionPosture::Certification => {
                    if tripped {
                        // Invalidate + signal re-collect. No stitching path.
                        CertVerdict::InvalidReCollect
                    } else {
                        CertVerdict::ValidForSubmission
                    }
                }
            };

            let src_meta = self.source.metadata();
            let spec = self.source.spec();
            let metadata = DatasetMetadata {
                schema_version: SCHEMA_VERSION,
                sample_count: count,
                sample_width_bits: spec.sample_width_bits(),
                claimed_h_steps: self.claimed_h.steps(),
                alpha_exp: self.alpha.exp(),
                timer_source: src_meta.timer_source,
                measured_counter_frequency_hz,
                cpu_model: String::from(src_meta.cpu_model),
                os: String::from(src_meta.os),
                collection_params: String::from(src_meta.collection_params),
                trips,
            };

            Ok(CollectedDataset {
                samples,
                verdict,
                metadata,
            })
        }

        /// Streams a raw-data collection to `sink`, holding at most
        /// [`STREAM_CHUNK_SAMPLES`] samples in memory at any instant
        /// regardless of `count`.
        ///
        /// This is the memory-bounded path the collection tooling uses for
        /// 1M+ sample runs: samples are written to `sink` in fixed-size
        /// chunks as they are produced, the live RCT/APT battery and the
        /// certification verdict are tracked incrementally, and the chunk
        /// buffer is **zeroized** between flushes so no growing sample buffer
        /// ever exists. Only the metadata (environment + the bounded trip
        /// list) and the running verdict are retained to the end. The byte
        /// stream written to `sink` is identical to [`Self::collect`]'s
        /// `samples()` for the same source and count (one byte per sample,
        /// in order); the posture semantics are identical too — trips are
        /// annotated and never drop a sample, and a tripped certification run
        /// reports [`CertVerdict::InvalidReCollect`] without writing a
        /// stitched subset (the full unfiltered stream is what reached
        /// `sink`, retained only as characterization evidence).
        ///
        /// Returns the [`StreamSummary`] (verdict + metadata + bytes
        /// written). The caller decides, from the verdict, whether the
        /// just-written file is submission-eligible.
        ///
        /// # Errors
        ///
        /// - [`EntropyError::NotReady`] before startup or after poisoning.
        /// - [`EntropyError::Source`] on a source failure or over-wide symbol.
        /// - [`EntropyError::Io`] if `sink` returns a write error.
        pub(crate) fn stream_to<W: std::io::Write>(
            &mut self,
            posture: CollectionPosture,
            count: u32,
            measured_counter_frequency_hz: Option<u64>,
            sink: &mut W,
        ) -> Result<StreamSummary, EntropyError> {
            match self.state {
                State::Operational => (),
                State::AwaitingStartup | State::Poisoned => return Err(EntropyError::NotReady),
            }
            let mut health =
                CharacterizationHealth::new(self.claimed_h, self.is_binary, self.alpha)
                    .map_err(EntropyError::Health)?;
            // Trip annotations are bounded: `tripped` records that a trip
            // occurred, but at most `MAX_TRIP_ANNOTATIONS` events are retained,
            // so a degraded source that trips on nearly every sample of a large
            // (e.g. characterization) capture cannot grow this list without
            // limit. The trip-free vs tripped signal stays exact.
            let mut trips: Vec<TripEvent> = Vec::new();
            let mut tripped = false;
            // Bounded buffer: never grows with `count`. Capacity is the fixed
            // chunk size; it is drained (and zeroized) on every flush.
            let mut chunk: Vec<RawSample> = Vec::with_capacity(STREAM_CHUNK_SAMPLES as usize);
            let mut written: u64 = 0;

            let mut index: u32 = 0;
            while index < count {
                let sample = self.next_bounded()?;
                chunk.push(sample);
                if let Some(event) = health.observe(sample, index) {
                    tripped = true;
                    if trips.len() < MAX_TRIP_ANNOTATIONS {
                        trips.push(event);
                    }
                }
                if chunk.len() >= STREAM_CHUNK_SAMPLES as usize {
                    sink.write_all(&chunk).map_err(|_| EntropyError::Io)?;
                    written = written.saturating_add(chunk.len() as u64);
                    oxicrypt_zeroize::zeroize(&mut chunk);
                    chunk.clear();
                }
                index = index.saturating_add(1);
            }
            // Final partial chunk.
            if !chunk.is_empty() {
                sink.write_all(&chunk).map_err(|_| EntropyError::Io)?;
                written = written.saturating_add(chunk.len() as u64);
                oxicrypt_zeroize::zeroize(&mut chunk);
                chunk.clear();
            }
            sink.flush().map_err(|_| EntropyError::Io)?;

            let verdict = match posture {
                CollectionPosture::Characterization => CertVerdict::ValidForCharacterization,
                CollectionPosture::Certification => {
                    if tripped {
                        CertVerdict::InvalidReCollect
                    } else {
                        CertVerdict::ValidForSubmission
                    }
                }
            };

            let src_meta = self.source.metadata();
            let spec = self.source.spec();
            let metadata = DatasetMetadata {
                schema_version: SCHEMA_VERSION,
                sample_count: count,
                sample_width_bits: spec.sample_width_bits(),
                claimed_h_steps: self.claimed_h.steps(),
                alpha_exp: self.alpha.exp(),
                timer_source: src_meta.timer_source,
                measured_counter_frequency_hz,
                cpu_model: String::from(src_meta.cpu_model),
                os: String::from(src_meta.os),
                collection_params: String::from(src_meta.collection_params),
                trips,
            };

            Ok(StreamSummary {
                verdict,
                metadata,
                bytes_written: written,
            })
        }
    }

    /// Bounded number of samples held in memory during a streaming
    /// collection. The streaming write path drains and zeroizes this buffer
    /// on every flush, so peak memory does not grow with the total sample
    /// count — the SP 800-90B 1M+ raw datasets stream through a buffer of
    /// this fixed size, never a 1M-element buffer.
    pub(crate) const STREAM_CHUNK_SAMPLES: u32 = 8192;

    /// Maximum number of health-test trip annotations retained in a streamed
    /// dataset's metadata. Once any trip occurs the run is flagged `tripped`
    /// regardless, so the trip-free vs tripped signal is exact; only the count
    /// of *retained* annotations is capped. This keeps [`RawCollector::stream_to`]
    /// memory-bounded regardless of the sample count — a degraded source
    /// tripping on nearly every sample of a multi-hour capture cannot grow the
    /// trip list without limit.
    pub(crate) const MAX_TRIP_ANNOTATIONS: usize = 4096;

    /// Outcome of a streaming collection ([`RawCollector::stream_to`]): the
    /// acceptance verdict, the dataset metadata (with trip annotations), and
    /// the number of sample bytes written to the sink. Carries **no** sample
    /// bytes — the stream went to the caller's sink, not into memory.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct StreamSummary {
        /// Acceptance verdict for the streamed run.
        pub verdict: CertVerdict,
        /// Dataset metadata (environment + trip annotations).
        pub metadata: DatasetMetadata,
        /// Number of one-byte samples written to the sink.
        pub bytes_written: u64,
    }

    impl StreamSummary {
        /// Whether the streamed run produced a submission-eligible dataset.
        pub(crate) fn is_submission(&self) -> bool {
            matches!(self.verdict, CertVerdict::ValidForSubmission)
        }

        /// The dataset metadata JSON for this streamed run, augmented with a
        /// `restart_total` field that records `numberOfRestarts ×
        /// samplesPerRestart` for the companion restart file.
        ///
        /// The base document is the schema-validated [`DatasetMetadata`]
        /// serialization (whose `sample_count` equals the raw file's byte
        /// length — one byte per sample); `restart_total` is appended so the
        /// raw-file count and the restart-file count are both recorded in one
        /// sidecar and stay consistent with the files on disk (ISC-99). The
        /// extra key is ignored by the subset validator, which checks only
        /// the required/declared properties.
        pub(crate) fn metadata_json_with_restart(&self, restart_total: u32) -> String {
            let base = self.metadata.to_json();
            // Splice `,"restart_total":N` before the closing brace. `to_json`
            // always ends in '}', so `pop` removes exactly that brace.
            let mut out = base;
            let _ = out.pop(); // drop trailing '}'
            out.push_str(",\"restart_total\":");
            out.push_str(&itoa_u64(u64::from(restart_total)));
            out.push('}');
            out
        }

        /// The dataset metadata JSON for a **characterization** streamed run,
        /// marked with `"characterization": true`.
        ///
        /// A characterization capture is a single contiguous run collected
        /// under [`CollectionPosture::Characterization`] (health battery live,
        /// trips *annotated* into `trips`, never a reason to drop a sample).
        /// It has no companion restart file, so — unlike
        /// [`Self::metadata_json_with_restart`] — no `restart_total` is spliced;
        /// instead the `"characterization": true` marker records that this
        /// sidecar describes an unfiltered characterization dataset. The extra
        /// key is ignored by the subset validator, which checks only the
        /// required/declared properties.
        pub(crate) fn metadata_json_characterization(&self) -> String {
            let base = self.metadata.to_json();
            // Splice `,"characterization":true` before the closing brace.
            // `to_json` always ends in '}', so `pop` removes exactly that brace.
            let mut out = base;
            let _ = out.pop(); // drop trailing '}'
            out.push_str(",\"characterization\":true}");
            out
        }
    }

    /// The schema version this crate emits (`schema_version` in the document
    /// and in `schema/dataset-metadata.schema.v1.json`).
    pub(crate) const SCHEMA_VERSION: u32 = 1;

    // ── Purpose-built JSON-Schema subset validator ───────────────────────
    //
    // This is NOT a general JSON-Schema engine. It parses the vendored schema
    // (a minimal JSON parser for the object/array/string/number/bool/null
    // subset) and the produced document, then checks exactly what the metadata
    // contract needs: required keys present, declared types match, the
    // schema_version const, and the declared numeric minimum/maximum bounds.
    // It is deliberately small and is proven by both a positive test
    // (produced metadata validates) and a negative test (a missing/wrong field
    // fails), so the probe is a real machine check, not a string-equality stub.

    /// A parsed JSON value (subset: object/array/string/number/bool/null).
    #[derive(Debug, Clone, PartialEq)]
    pub(crate) enum Json {
        Null,
        Bool(bool),
        Num(f64),
        Str(String),
        Arr(Vec<Json>),
        Obj(Vec<(String, Json)>),
    }

    impl Json {
        fn get<'a>(&'a self, key: &str) -> Option<&'a Json> {
            match self {
                Json::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
    }

    /// A recursive-descent parser for the JSON subset above.
    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        fn new(s: &'a str) -> Self {
            Self {
                bytes: s.as_bytes(),
                pos: 0,
            }
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }

        fn bump(&mut self) -> Option<u8> {
            let b = self.bytes.get(self.pos).copied();
            if b.is_some() {
                self.pos = self.pos.saturating_add(1);
            }
            b
        }

        fn skip_ws(&mut self) {
            while let Some(b) = self.peek() {
                if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                    self.pos = self.pos.saturating_add(1);
                } else {
                    break;
                }
            }
        }

        fn parse(&mut self) -> Option<Json> {
            self.skip_ws();
            let v = self.parse_value()?;
            self.skip_ws();
            Some(v)
        }

        fn parse_value(&mut self) -> Option<Json> {
            self.skip_ws();
            match self.peek()? {
                b'{' => self.parse_object(),
                b'[' => self.parse_array(),
                b'"' => self.parse_string().map(Json::Str),
                b't' | b'f' => self.parse_bool(),
                b'n' => self.parse_null(),
                _ => self.parse_number(),
            }
        }

        fn parse_object(&mut self) -> Option<Json> {
            self.bump(); // '{'
            let mut entries: Vec<(String, Json)> = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.bump();
                return Some(Json::Obj(entries));
            }
            loop {
                self.skip_ws();
                if self.peek() != Some(b'"') {
                    return None;
                }
                let key = self.parse_string()?;
                self.skip_ws();
                if self.bump() != Some(b':') {
                    return None;
                }
                let value = self.parse_value()?;
                entries.push((key, value));
                self.skip_ws();
                match self.bump() {
                    Some(b',') => {}
                    Some(b'}') => break,
                    _ => return None,
                }
            }
            Some(Json::Obj(entries))
        }

        fn parse_array(&mut self) -> Option<Json> {
            self.bump(); // '['
            let mut items: Vec<Json> = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.bump();
                return Some(Json::Arr(items));
            }
            loop {
                let value = self.parse_value()?;
                items.push(value);
                self.skip_ws();
                match self.bump() {
                    Some(b',') => {}
                    Some(b']') => break,
                    _ => return None,
                }
            }
            Some(Json::Arr(items))
        }

        fn parse_string(&mut self) -> Option<String> {
            self.bump(); // opening quote
            let mut s = String::new();
            loop {
                match self.bump()? {
                    b'"' => break,
                    b'\\' => match self.bump()? {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'b' => s.push('\u{0008}'),
                        b'f' => s.push('\u{000C}'),
                        b'u' => {
                            let mut code: u32 = 0;
                            for _ in 0..4 {
                                let d = self.bump()?;
                                let nibble = (d as char).to_digit(16)?;
                                code = code.saturating_mul(16).saturating_add(nibble);
                            }
                            s.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        _ => return None,
                    },
                    b => {
                        // Collect a UTF-8 byte run for this character.
                        let start = self.pos.saturating_sub(1);
                        let mut end = self.pos;
                        // Determine the UTF-8 length from the lead byte.
                        let extra = if b < 0x80 {
                            0
                        } else if b >> 5 == 0b110 {
                            1
                        } else if b >> 4 == 0b1110 {
                            2
                        } else if b >> 3 == 0b11110 {
                            3
                        } else {
                            0
                        };
                        for _ in 0..extra {
                            self.bump();
                            end = self.pos;
                        }
                        match core::str::from_utf8(self.bytes.get(start..end).unwrap_or(&[])) {
                            Ok(chunk) => s.push_str(chunk),
                            Err(_) => return None,
                        }
                    }
                }
            }
            Some(s)
        }

        fn parse_bool(&mut self) -> Option<Json> {
            if self.bytes.get(self.pos..self.pos.saturating_add(4)) == Some(b"true") {
                self.pos = self.pos.saturating_add(4);
                Some(Json::Bool(true))
            } else if self.bytes.get(self.pos..self.pos.saturating_add(5)) == Some(b"false") {
                self.pos = self.pos.saturating_add(5);
                Some(Json::Bool(false))
            } else {
                None
            }
        }

        fn parse_null(&mut self) -> Option<Json> {
            if self.bytes.get(self.pos..self.pos.saturating_add(4)) == Some(b"null") {
                self.pos = self.pos.saturating_add(4);
                Some(Json::Null)
            } else {
                None
            }
        }

        fn parse_number(&mut self) -> Option<Json> {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b.is_ascii_digit()
                    || b == b'-'
                    || b == b'+'
                    || b == b'.'
                    || b == b'e'
                    || b == b'E'
                {
                    self.pos = self.pos.saturating_add(1);
                } else {
                    break;
                }
            }
            let slice = self.bytes.get(start..self.pos)?;
            let text = core::str::from_utf8(slice).ok()?;
            text.parse::<f64>().ok().map(Json::Num)
        }
    }

    /// Parses a JSON subset document into a [`Json`] tree.
    pub(crate) fn parse_json(s: &str) -> Option<Json> {
        Parser::new(s).parse()
    }

    /// Validates `doc` against `schema` using the purpose-built subset
    /// validator. Returns `Ok(())` on success or `Err` with a short reason.
    ///
    /// Supported schema vocabulary: `type` (string or array of strings:
    /// object/array/string/integer/number/boolean/null), `required`,
    /// `properties`, `items`, `const`, `enum`, `minimum`, `maximum`. This is a
    /// purpose-built subset, NOT a general JSON-Schema engine.
    pub(crate) fn validate(doc: &Json, schema: &Json) -> Result<(), String> {
        validate_node(doc, schema, "$")
    }

    fn type_matches(value: &Json, ty: &str) -> bool {
        match ty {
            "object" => matches!(value, Json::Obj(_)),
            "array" => matches!(value, Json::Arr(_)),
            "string" => matches!(value, Json::Str(_)),
            "boolean" => matches!(value, Json::Bool(_)),
            "null" => matches!(value, Json::Null),
            // JSON numbers are all f64 in this subset; "integer" additionally
            // requires an integral value.
            "number" => matches!(value, Json::Num(_)),
            "integer" => matches!(value, Json::Num(n) if n.fract() == 0.0),
            _ => false,
        }
    }

    fn validate_node(value: &Json, schema: &Json, path: &str) -> Result<(), String> {
        // type
        if let Some(ty) = schema.get("type") {
            let ok = match ty {
                Json::Str(s) => type_matches(value, s),
                Json::Arr(alts) => alts.iter().any(|alt| match alt {
                    Json::Str(s) => type_matches(value, s),
                    _ => false,
                }),
                _ => false,
            };
            if !ok {
                return Err(alloc_err(path, "type mismatch"));
            }
        }
        // const
        if let Some(expected) = schema.get("const")
            && value != expected
        {
            return Err(alloc_err(path, "const mismatch"));
        }
        // enum
        if let Some(Json::Arr(allowed)) = schema.get("enum")
            && !allowed.iter().any(|a| a == value)
        {
            return Err(alloc_err(path, "enum mismatch"));
        }
        // numeric bounds
        if let Json::Num(n) = value {
            if let Some(Json::Num(min)) = schema.get("minimum")
                && n < min
            {
                return Err(alloc_err(path, "below minimum"));
            }
            if let Some(Json::Num(max)) = schema.get("maximum")
                && n > max
            {
                return Err(alloc_err(path, "above maximum"));
            }
        }
        // object: required + properties
        if let Json::Obj(_) = value {
            if let Some(Json::Arr(required)) = schema.get("required") {
                for key in required {
                    if let Json::Str(k) = key
                        && value.get(k).is_none()
                    {
                        return Err(alloc_err(path, "missing required key"));
                    }
                }
            }
            if let Some(Json::Obj(props)) = schema.get("properties") {
                for (k, subschema) in props {
                    if let Some(child) = value.get(k) {
                        validate_node(child, subschema, k)?;
                    }
                }
            }
        }
        // array: items
        if let Json::Arr(items) = value
            && let Some(item_schema) = schema.get("items")
        {
            for item in items {
                validate_node(item, item_schema, path)?;
            }
        }
        Ok(())
    }

    fn alloc_err(path: &str, msg: &str) -> String {
        let mut s = String::from(path);
        s.push_str(": ");
        s.push_str(msg);
        s
    }
}

// Re-export the std collection surface the `collection` module drives, so the
// streaming writer, its summary, and the bounded-chunk constant are reachable
// in-crate without widening `std_collection` itself to `pub(crate)`. These
// items remain crate-private (no `pub` escape to the library API).
#[cfg(feature = "std")]
pub(crate) use std_collection::StreamSummary;

// The bounded-chunk constant is referenced only by the collection module's
// memory-boundedness test; gate the re-export to test builds so non-test
// builds carry no unused import.
#[cfg(all(feature = "std", test))]
pub(crate) use std_collection::{MAX_TRIP_ANNOTATIONS, STREAM_CHUNK_SAMPLES};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::health::{HealthError, HealthTest};
    use crate::source::{
        NoiseSource, RawSample, SourceError, SourceMetadata, SourceSpec, TimerSource,
        sealed::Sealed,
    };

    fn alpha20() -> Alpha {
        Alpha::from_exp(20).unwrap()
    }

    fn meta() -> SourceMetadata<'static> {
        SourceMetadata {
            timer_source: Some(TimerSource::RawCounter),
            counter_frequency_hz: Some(3_000_000_000),
            cpu_model: "test-cpu",
            os: "test-os",
            collection_params: "unit test",
        }
    }

    /// Deterministic xorshift byte source, 8-bit alphabet, healthy.
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

    /// Healthy PRNG that goes dead (constant output) after `die_after`
    /// emissions — used to trip RCT mid-run without failing startup.
    /// Consumed only by the std collection tests.
    #[cfg(feature = "std")]
    #[derive(Debug)]
    struct DiesLaterMock {
        inner: PrngMock,
        die_after: u32,
    }
    #[cfg(feature = "std")]
    impl Sealed for DiesLaterMock {}
    #[cfg(feature = "std")]
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
                return Ok(0xCC);
            }
            self.inner.sample()
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    /// Constant source — fails startup (RCT total-failure class).
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

    /// Source emitting only in-range 2-bit symbols (0..=3), varied.
    /// Consumed only by the std collection tests.
    #[cfg(feature = "std")]
    #[derive(Debug)]
    struct NarrowMock(u8);
    #[cfg(feature = "std")]
    impl Sealed for NarrowMock {}
    #[cfg(feature = "std")]
    impl NoiseSource for NarrowMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(2).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(2)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            self.0 = self.0.wrapping_add(1);
            Ok(self.0 & 0x03)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    // ── ISC-44: structural raw/conditioned exclusion ─────────────────────

    /// ISC-44: `RawCollector` is a distinct type with no conditioned-output
    /// surface — it holds no conditioner and exposes no block-emission method.
    /// This test compiles only because the raw and conditioned paths are
    /// separate types constructed separately (a runtime flag could not be
    /// type-checked this way). The pipeline's `conditioned_block` has no
    /// counterpart here, asserted by the absence of any such call.
    #[test]
    fn raw_collector_is_distinct_type_without_conditioner() {
        // RawCollector and EntropyPipeline are different types over the same S;
        // this helper accepts ONLY a RawCollector, never a pipeline.
        fn takes_raw<S: NoiseSource>(_: &RawCollector<S>) {}
        let c = RawCollector::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap();
        takes_raw(&c);
        // The collector exposes no conditioner accessor and no conditioned
        // block method (would not compile if it did): only raw collection.
        assert!(!c.is_operational());
    }

    // ── Construction parity with the pipeline ────────────────────────────

    #[test]
    fn claim_above_ceiling_is_refused() {
        let err = RawCollector::new(
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
    fn unsupported_alpha_is_typed_at_construction() {
        let a25 = Alpha::from_exp(25).unwrap();
        let err = RawCollector::new(PrngMock::new(), MinEntropy::from_bits(2), a25).unwrap_err();
        assert_eq!(
            err,
            EntropyError::Health(HealthError::UnsupportedAlpha { alpha_exp: 25 })
        );
    }

    // ── Startup gating (ISC-130: startup pass gates collection start) ────

    #[test]
    fn startup_gates_then_operational() {
        let mut c =
            RawCollector::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap();
        assert!(!c.is_operational());
        c.run_startup().unwrap();
        assert!(c.is_operational());
        assert_eq!(c.source().emitted, STARTUP_MIN_SAMPLES);
    }

    #[test]
    fn dead_source_fails_startup_and_poisons() {
        let mut c = RawCollector::new(DeadMock, MinEntropy::from_bits(2), alpha20()).unwrap();
        assert_eq!(
            c.run_startup().unwrap_err(),
            EntropyError::Health(HealthError::Failed(HealthTest::Rct))
        );
        assert!(c.is_poisoned());
    }

    #[test]
    fn startup_twice_is_refused() {
        let mut c =
            RawCollector::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap();
        c.run_startup().unwrap();
        assert_eq!(c.run_startup().unwrap_err(), EntropyError::NotReady);
    }

    // ── ISC-53: redacting Debug on the collector ─────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn collector_debug_redacts_samples() {
        use std::format;
        let c = RawCollector::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap();
        let rendered = format!("{c:?}");
        assert!(rendered.contains("RawCollector"));
        assert!(rendered.contains("state"));
        // No buffer contents: the collector holds no sample buffer to leak.
        assert!(!rendered.contains("source"));
    }

    // ── std-gated collection / metadata / JSON / schema tests ────────────

    #[cfg(feature = "std")]
    mod std_tests {
        use super::*;
        use crate::raw::std_collection::{SCHEMA_VERSION, parse_json, validate};
        use crate::raw::{CertVerdict, CollectionPosture};
        use std::format;
        use std::fs;
        use std::string::String;

        fn schema_json() -> String {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/schema/dataset-metadata.schema.v1.json"
            );
            fs::read_to_string(path).expect("vendored schema must be present")
        }

        fn started(claim_bits: u8) -> RawCollector<PrngMock> {
            let mut c = RawCollector::new(
                PrngMock::new(),
                MinEntropy::from_bits(claim_bits),
                alpha20(),
            )
            .unwrap();
            c.run_startup().unwrap();
            c
        }

        // ── ISC-130: unfiltered characterization capture ────────────────

        #[test]
        fn characterization_keeps_every_sample_and_annotates_trip() {
            // A source that dies mid-run trips RCT; in characterization the
            // sample is annotated and STILL emitted — zero dropped samples.
            let src = DiesLaterMock {
                inner: PrngMock::new(),
                die_after: STARTUP_MIN_SAMPLES + 200,
            };
            let mut c = RawCollector::new(src, MinEntropy::from_bits(2), alpha20()).unwrap();
            c.run_startup().unwrap();
            let n = 2000u32;
            let dataset = c
                .collect(CollectionPosture::Characterization, n, Some(2_500_000_000))
                .unwrap();
            // Complete buffer: exactly `n` samples, none dropped.
            assert_eq!(dataset.samples().len(), n as usize);
            assert_eq!(dataset.metadata().sample_count, n);
            // The mid-run death produced at least one annotated trip.
            assert!(!dataset.metadata().trips.is_empty());
            // Verdict: characterization always valid as evidence.
            assert_eq!(dataset.verdict(), CertVerdict::ValidForCharacterization);
            assert!(!dataset.is_submission());
            // The trip is an RCT (constant 0xCC run) at the right region.
            let trip = dataset.metadata().trips[0];
            assert_eq!(trip.test, HealthTest::Rct);
            assert!(trip.sample_index >= 200);
        }

        #[test]
        fn stream_to_bounds_retained_trip_annotations() {
            // A source that dies to a constant post-startup trips RCT on nearly
            // every subsequent sample. Over a capture far larger than the cap,
            // the retained trip list must stay bounded (no unbounded growth /
            // OOM on a large characterization run) while still flagging tripped.
            let src = DiesLaterMock {
                inner: PrngMock::new(),
                die_after: STARTUP_MIN_SAMPLES + 8,
            };
            let mut c = RawCollector::new(src, MinEntropy::from_bits(2), alpha20()).unwrap();
            c.run_startup().unwrap();
            let n = u32::try_from(MAX_TRIP_ANNOTATIONS).unwrap() + STARTUP_MIN_SAMPLES + 20_000;
            let mut sink = std::io::sink();
            let summary = c
                .stream_to(CollectionPosture::Characterization, n, None, &mut sink)
                .unwrap();
            // Every sample still streamed to the sink (never dropped).
            assert_eq!(summary.bytes_written, u64::from(n));
            // Tripped is flagged, and the retained annotations are capped.
            assert!(!summary.metadata.trips.is_empty());
            assert!(summary.metadata.trips.len() <= MAX_TRIP_ANNOTATIONS);
        }

        #[test]
        fn characterization_with_apt_trip_keeps_complete_buffer() {
            // Claim H = 2 on a wide source that, post-startup, collapses to an
            // alternating low-variety pattern → APT trips within a window.
            // Use a source dying to a constant first (RCT) is simplest, but to
            // exercise APT specifically we drive a low-variety oscillation by
            // claiming high H on an 8-bit source that emits two values.
            #[derive(Debug)]
            struct OscWide {
                emitted: u32,
                bit: u8,
            }
            impl Sealed for OscWide {}
            impl NoiseSource for OscWide {
                fn spec(&self) -> SourceSpec {
                    SourceSpec::new(8).unwrap()
                }
                fn max_claimable_h(&self) -> MinEntropy {
                    MinEntropy::from_bits(8)
                }
                fn sample(&mut self) -> Result<RawSample, SourceError> {
                    // Healthy varied bytes through startup, then alternate two
                    // values so APT (not RCT) trips.
                    self.emitted += 1;
                    if self.emitted <= STARTUP_MIN_SAMPLES {
                        // varied
                        Ok((self.emitted.wrapping_mul(2_654_435_761) >> 24) as u8)
                    } else {
                        self.bit ^= 1;
                        Ok(self.bit)
                    }
                }
                fn metadata(&self) -> SourceMetadata<'_> {
                    meta()
                }
            }
            let mut c = RawCollector::new(
                OscWide { emitted: 0, bit: 0 },
                MinEntropy::from_bits(8),
                alpha20(),
            )
            .unwrap();
            c.run_startup().unwrap();
            let n = 1500u32;
            let dataset = c
                .collect(CollectionPosture::Characterization, n, None)
                .unwrap();
            assert_eq!(dataset.samples().len(), n as usize);
            // An APT trip must have been annotated (count reaches cutoff 13 at
            // H=8 within W=512).
            assert!(
                dataset
                    .metadata()
                    .trips
                    .iter()
                    .any(|t| t.test == HealthTest::Apt)
            );
        }

        #[test]
        fn clean_characterization_has_no_trips() {
            let mut c = started(2);
            let dataset = c
                .collect(
                    CollectionPosture::Characterization,
                    4096,
                    Some(3_000_000_000),
                )
                .unwrap();
            assert_eq!(dataset.samples().len(), 4096);
            assert!(dataset.metadata().trips.is_empty());
            assert_eq!(dataset.verdict(), CertVerdict::ValidForCharacterization);
        }

        // ── ISC-132: certification invalidation ─────────────────────────

        #[test]
        fn certification_trip_invalidates_and_signals_recollect() {
            let src = DiesLaterMock {
                inner: PrngMock::new(),
                die_after: STARTUP_MIN_SAMPLES + 100,
            };
            let mut c = RawCollector::new(src, MinEntropy::from_bits(2), alpha20()).unwrap();
            c.run_startup().unwrap();
            let n = 1000u32;
            let dataset = c
                .collect(CollectionPosture::Certification, n, Some(3_000_000_000))
                .unwrap();
            // Invalidated → re-collect; NOT submission-eligible.
            assert_eq!(dataset.verdict(), CertVerdict::InvalidReCollect);
            assert!(!dataset.is_submission());
            // The full annotated capture is retained as characterization
            // evidence — same complete buffer, NOT a stitched/spliced subset.
            assert_eq!(dataset.samples().len(), n as usize);
            assert!(!dataset.metadata().trips.is_empty());
        }

        #[test]
        fn certification_clean_run_is_valid_for_submission() {
            let mut c = started(2);
            let n = 4096u32;
            let dataset = c
                .collect(CollectionPosture::Certification, n, Some(3_000_000_000))
                .unwrap();
            assert_eq!(dataset.verdict(), CertVerdict::ValidForSubmission);
            assert!(dataset.is_submission());
            // The full contiguous trip-free stream is the submission.
            assert_eq!(dataset.samples().len(), n as usize);
            assert!(dataset.metadata().trips.is_empty());
        }

        // ── ISC-97: sample count / wire format ──────────────────────────

        #[test]
        fn raw_data_sample_count_constant_is_one_million() {
            assert_eq!(crate::sp800_90b::RAW_DATA_SAMPLE_COUNT, 1_000_000);
        }

        #[test]
        fn emit_honors_requested_count_one_byte_each() {
            // Parameterized to a smaller N for speed; the constant wiring is
            // asserted separately above. One byte per sample by Vec<u8> type.
            let mut c = started(2);
            for n in [1u32, 100, 5000] {
                let dataset = c
                    .collect(CollectionPosture::Characterization, n, None)
                    .unwrap();
                assert_eq!(dataset.samples().len(), n as usize);
                assert_eq!(dataset.metadata().sample_count, n);
            }
        }

        // ── ISC-108: width bound ─────────────────────────────────────────

        #[test]
        fn in_range_narrow_symbols_are_emitted() {
            let mut c =
                RawCollector::new(NarrowMock(0), MinEntropy::from_bits(2), alpha20()).unwrap();
            c.run_startup().unwrap();
            let dataset = c
                .collect(CollectionPosture::Characterization, 1000, None)
                .unwrap();
            // Every emitted symbol is within the 2-bit effective width.
            assert!(dataset.samples().iter().all(|&s| s < 4));
        }

        #[test]
        fn over_wide_after_startup_is_refused() {
            // Healthy narrow source through startup, then emits an over-wide
            // symbol: the collector refuses with a typed Source error, never a
            // silent mask.
            #[derive(Debug)]
            struct WidensLater {
                emitted: u32,
                inner: NarrowMock,
            }
            impl Sealed for WidensLater {}
            impl NoiseSource for WidensLater {
                fn spec(&self) -> SourceSpec {
                    SourceSpec::new(2).unwrap()
                }
                fn max_claimable_h(&self) -> MinEntropy {
                    MinEntropy::from_bits(2)
                }
                fn sample(&mut self) -> Result<RawSample, SourceError> {
                    self.emitted += 1;
                    if self.emitted > STARTUP_MIN_SAMPLES {
                        Ok(0xFF) // over-wide for a 2-bit declaration
                    } else {
                        self.inner.sample()
                    }
                }
                fn metadata(&self) -> SourceMetadata<'_> {
                    meta()
                }
            }
            let mut c = RawCollector::new(
                WidensLater {
                    emitted: 0,
                    inner: NarrowMock(0),
                },
                MinEntropy::from_bits(2),
                alpha20(),
            )
            .unwrap();
            c.run_startup().unwrap();
            let err = c
                .collect(CollectionPosture::Characterization, 10, None)
                .unwrap_err();
            assert_eq!(err, EntropyError::Source(SourceError::Unavailable));
        }

        // ── ISC-53: redacting Debug on the dataset ──────────────────────

        #[test]
        fn dataset_debug_never_exposes_sample_bytes() {
            // Feed a source whose post-startup bytes contain a distinctive
            // marker and assert it never appears in the Debug rendering.
            #[derive(Debug)]
            struct MarkerMock {
                emitted: u32,
            }
            impl Sealed for MarkerMock {}
            impl NoiseSource for MarkerMock {
                fn spec(&self) -> SourceSpec {
                    SourceSpec::new(8).unwrap()
                }
                fn max_claimable_h(&self) -> MinEntropy {
                    MinEntropy::from_bits(4)
                }
                fn sample(&mut self) -> Result<RawSample, SourceError> {
                    self.emitted += 1;
                    // Varied through startup; distinctive 0xDE,0xAD cycle after.
                    if self.emitted <= STARTUP_MIN_SAMPLES {
                        Ok((self.emitted.wrapping_mul(2_654_435_761) >> 24) as u8)
                    } else if self.emitted.is_multiple_of(2) {
                        Ok(0xDE)
                    } else {
                        Ok(0xAD)
                    }
                }
                fn metadata(&self) -> SourceMetadata<'_> {
                    meta()
                }
            }
            let mut c = RawCollector::new(
                MarkerMock { emitted: 0 },
                MinEntropy::from_bits(2),
                alpha20(),
            )
            .unwrap();
            c.run_startup().unwrap();
            let dataset = c
                .collect(CollectionPosture::Characterization, 64, None)
                .unwrap();
            let rendered = format!("{dataset:?}");
            assert!(rendered.contains("CollectedDataset"));
            assert!(rendered.contains("samples_collected"));
            // The distinctive sample bytes must NOT appear in any form.
            assert!(!rendered.contains("222")); // 0xDE
            assert!(!rendered.contains("173")); // 0xAD
            assert!(!rendered.contains("0xde"));
            assert!(!rendered.contains("0xad"));
        }

        // ── ISC-14: metadata schema validation (positive + negative) ────

        #[test]
        fn metadata_validates_against_vendored_schema() {
            let mut c = started(2);
            let dataset = c
                .collect(
                    CollectionPosture::Characterization,
                    256,
                    Some(3_000_000_123),
                )
                .unwrap();
            assert_eq!(dataset.metadata().schema_version, SCHEMA_VERSION);
            // Measured frequency, not nominal: distinct from the nominal value
            // carried by SourceMetadata (3_000_000_000).
            assert_eq!(
                dataset.metadata().measured_counter_frequency_hz,
                Some(3_000_000_123)
            );
            let json = dataset.metadata().to_json();
            let doc = parse_json(&json).expect("emitted metadata must parse");
            let schema = parse_json(&schema_json()).expect("vendored schema must parse");
            validate(&doc, &schema).expect("emitted metadata must validate against the schema");
        }

        #[test]
        fn metadata_with_trips_validates() {
            let src = DiesLaterMock {
                inner: PrngMock::new(),
                die_after: STARTUP_MIN_SAMPLES + 50,
            };
            let mut c = RawCollector::new(src, MinEntropy::from_bits(2), alpha20()).unwrap();
            c.run_startup().unwrap();
            let dataset = c
                .collect(
                    CollectionPosture::Characterization,
                    500,
                    Some(2_000_000_000),
                )
                .unwrap();
            assert!(!dataset.metadata().trips.is_empty());
            let json = dataset.metadata().to_json();
            let doc = parse_json(&json).unwrap();
            let schema = parse_json(&schema_json()).unwrap();
            validate(&doc, &schema).expect("metadata with trip annotations must validate");
        }

        #[test]
        fn validator_rejects_missing_required_field() {
            // A document missing `sample_count` must FAIL — proving the
            // validator actually validates (not a string-equality stub).
            let bad = r#"{
                "schema_version": 1,
                "sample_width_bits": 8,
                "claimed_h_steps": 512,
                "alpha_exp": 20,
                "timer_source": null,
                "measured_counter_frequency_hz": null,
                "cpu_model": "x",
                "os": "y",
                "collection_params": "z",
                "trips": []
            }"#;
            let doc = parse_json(bad).unwrap();
            let schema = parse_json(&schema_json()).unwrap();
            assert!(validate(&doc, &schema).is_err());
        }

        #[test]
        fn validator_rejects_wrong_type_and_bad_version() {
            // sample_count as a string (wrong type).
            let wrong_type = r#"{
                "schema_version": 1, "sample_count": "lots", "sample_width_bits": 8,
                "claimed_h_steps": 512, "alpha_exp": 20, "timer_source": null,
                "measured_counter_frequency_hz": null, "cpu_model": "x", "os": "y",
                "collection_params": "z", "trips": []
            }"#;
            let schema = parse_json(&schema_json()).unwrap();
            assert!(validate(&parse_json(wrong_type).unwrap(), &schema).is_err());

            // schema_version const violated.
            let bad_version = r#"{
                "schema_version": 2, "sample_count": 10, "sample_width_bits": 8,
                "claimed_h_steps": 512, "alpha_exp": 20, "timer_source": null,
                "measured_counter_frequency_hz": null, "cpu_model": "x", "os": "y",
                "collection_params": "z", "trips": []
            }"#;
            assert!(validate(&parse_json(bad_version).unwrap(), &schema).is_err());

            // alpha_exp out of [20,40] range (below minimum).
            let bad_alpha = r#"{
                "schema_version": 1, "sample_count": 10, "sample_width_bits": 8,
                "claimed_h_steps": 512, "alpha_exp": 5, "timer_source": null,
                "measured_counter_frequency_hz": null, "cpu_model": "x", "os": "y",
                "collection_params": "z", "trips": []
            }"#;
            assert!(validate(&parse_json(bad_alpha).unwrap(), &schema).is_err());
        }

        #[test]
        fn json_roundtrip_string_escaping() {
            // collection_params with quotes/newlines must serialize and re-parse
            // intact (escaping correctness).
            #[derive(Debug)]
            struct QuoteMock {
                emitted: u32,
            }
            impl Sealed for QuoteMock {}
            impl NoiseSource for QuoteMock {
                fn spec(&self) -> SourceSpec {
                    SourceSpec::new(8).unwrap()
                }
                fn max_claimable_h(&self) -> MinEntropy {
                    MinEntropy::from_bits(4)
                }
                fn sample(&mut self) -> Result<RawSample, SourceError> {
                    self.emitted += 1;
                    Ok((self.emitted.wrapping_mul(2_654_435_761) >> 24) as u8)
                }
                fn metadata(&self) -> SourceMetadata<'_> {
                    SourceMetadata {
                        timer_source: None,
                        counter_frequency_hz: None,
                        cpu_model: "cpu \"x\"",
                        os: "os\nnewline",
                        collection_params: "loop=\t1",
                    }
                }
            }
            let mut c = RawCollector::new(
                QuoteMock { emitted: 0 },
                MinEntropy::from_bits(2),
                alpha20(),
            )
            .unwrap();
            c.run_startup().unwrap();
            let dataset = c
                .collect(CollectionPosture::Characterization, 16, None)
                .unwrap();
            let json = dataset.metadata().to_json();
            let doc = parse_json(&json).expect("escaped JSON must round-trip");
            let schema = parse_json(&schema_json()).unwrap();
            validate(&doc, &schema).expect("escaped metadata must validate");
        }
    }
}
