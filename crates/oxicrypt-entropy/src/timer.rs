//! Timer layer: per-architecture defaults, measured adequacy, and exact
//! delta semantics for jitter-class noise sources.
//!
//! # Per-architecture defaults (design rationale)
//!
//! - **x86_64 → [`TimerSource::RawCounter`]**: the TSC is the
//!   certificate-precedented path for CPU-jitter entropy sources and offers
//!   sub-nanosecond effective resolution on current parts. The serialized
//!   read itself lives in the audited `oxicrypt-timer` crate.
//! - **aarch64 → [`TimerSource::OsNanoClock`]**: generic-timer counters
//!   (`CNTVCT_EL0`) run at platform-defined frequencies that are often far
//!   coarser than the nominal CPU clock (pre-ARMv8.6 parts commonly tick
//!   in the tens of nanoseconds), while published 90B-passing results on
//!   ARM-class hardware ride the OS nanosecond clock. The raw counter
//!   remains admissible per operational environment **where measured
//!   granularity is adequate** — the choice is data-driven, never assumed.
//! - **[`TimerSource::InternalTimerThread`]** is reserved and
//!   **unselectable in Phase 0**: construction returns a typed
//!   [`TimerError::Unsupported`]. No validation claim references it.
//!
//! # Measured, never assumed
//!
//! Neither a nominal counter frequency nor a clock's advertised resolution
//! is trusted: an OS time source can scale a coarse hardware counter into
//! sub-tick *numerical* resolution with no *temporal* reality behind it.
//! [`measure_adequacy`] observes actual read-to-read deltas — zero-delta
//! fraction, minimum positive delta (the effective granularity), distinct
//! delta variety, monotonicity violations — and
//! [`AdequacyReport::ensure_adequate`] refuses a configuration whose
//! observed behavior is inadequate, with a typed reason.
//!
//! The adequacy thresholds are **engineering defaults, not SP 800-90B
//! values** (the spec sets no timer-granularity requirement); they are
//! deliberately conservative and documented here as design decisions so
//! they can be argued in the noise-source description.
//!
//! # Delta semantics
//!
//! Deltas are computed width-aware with wrapping arithmetic
//! ([`wrapping_delta`]): legitimate counter wraparound on a narrow counter
//! yields the correct small delta, while a masked delta with the top bit
//! of the counter width set is classified as a **backwards violation** —
//! a typed error; the affected sample is discarded by the caller. This
//! disambiguation is a conservative engineering choice: a genuine
//! wraparound observed across a sane sampling interval produces a small
//! masked delta, whereas a backwards step produces a near-maximal one.

use crate::source::TimerSource;

/// Typed timer-layer errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimerError {
    /// The requested timer source is reserved and unselectable in this
    /// phase (`InternalTimerThread`).
    Unsupported,
    /// The requested timer source was not compiled into this build
    /// (missing `raw-counter` / `std` feature).
    Unavailable,
    /// A read went backwards: the width-masked delta had the top bit of
    /// the counter width set. The affected sample must be discarded.
    Backwards,
    /// The measured timer behavior is inadequate for jitter collection.
    Inadequate(InadequacyReason),
}

/// Why [`AdequacyReport::ensure_adequate`] refused the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InadequacyReason {
    /// Too many consecutive reads were identical — the effective
    /// granularity is too coarse relative to the read cost.
    TooCoarse,
    /// Too few distinct delta values were observed — the timer shows no
    /// usable variety.
    TooUniform,
    /// One or more backwards violations occurred during measurement.
    NonMonotonic,
}

/// Width-aware wrapping delta between two raw counter reads.
///
/// `width_bits` is the counter's significant width (1..=64). Legitimate
/// wraparound yields the correct small delta; a masked delta with the top
/// bit of the width set is a backwards violation ([`TimerError::Backwards`]).
///
/// # Errors
///
/// [`TimerError::Backwards`] as described; [`TimerError::Unavailable`]
/// never occurs here (listed for the non-exhaustive enum's sake).
// Shift and decrement are bounded by the width_bits < 64 guard; the top-bit
// shift is clamped to ≤63. No overflow path exists.
#[allow(clippy::arithmetic_side_effects)]
pub fn wrapping_delta(prev: u64, now: u64, width_bits: u32) -> Result<u64, TimerError> {
    let masked = |v: u64| -> u64 {
        if width_bits >= 64 {
            v
        } else {
            v & ((1u64 << width_bits) - 1)
        }
    };
    let delta = masked(now.wrapping_sub(prev));
    let top_bit = 1u64 << width_bits.saturating_sub(1).min(63);
    if delta & top_bit != 0 {
        return Err(TimerError::Backwards);
    }
    Ok(delta)
}

/// A monotonic-intent counter read abstraction over the configured
/// [`TimerSource`].
///
/// Sealed like [`crate::source::NoiseSource`]: implementations are
/// crate-internal while the validation story matures (synthetic test
/// timers live in-crate; unsealing later is non-breaking).
pub trait TimerRead: crate::source::sealed::Sealed {
    /// Reads the counter.
    fn read(&mut self) -> u64;
    /// Significant counter width in bits (1..=64).
    fn width_bits(&self) -> u32 {
        64
    }
}

/// Adequacy-measurement configuration. Defaults are conservative
/// engineering choices (not spec values), documented at module level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdequacyConfig {
    /// Number of consecutive reads to sample (default 4096).
    pub samples: u32,
    /// Maximum tolerated zero-delta fraction, in permille (default 900:
    /// a timer where more than 90% of consecutive reads are identical is
    /// too coarse for the read cost).
    pub max_zero_delta_permille: u32,
    /// Minimum distinct positive delta values observed (default 4 —
    /// counted up to a bounded tracker capacity of 16).
    pub min_distinct_deltas: u32,
}

impl Default for AdequacyConfig {
    fn default() -> Self {
        Self {
            samples: 4096,
            max_zero_delta_permille: 900,
            min_distinct_deltas: 4,
        }
    }
}

/// Observed timer behavior over one adequacy measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdequacyReport {
    /// Deltas observed (samples − 1).
    pub deltas: u32,
    /// Deltas equal to zero.
    pub zero_deltas: u32,
    /// Smallest positive delta — the measured effective granularity.
    pub min_positive_delta: Option<u64>,
    /// Distinct positive delta values observed, saturating at the bounded
    /// tracker capacity (16).
    pub distinct_deltas: u32,
    /// Backwards violations observed.
    pub backwards_violations: u32,
}

impl AdequacyReport {
    /// Refuses an inadequate configuration with a typed reason; passes an
    /// adequate one.
    ///
    /// # Errors
    ///
    /// [`TimerError::Inadequate`] with [`InadequacyReason::NonMonotonic`]
    /// (any backwards violation), [`InadequacyReason::TooCoarse`]
    /// (zero-delta fraction above the configured permille bound), or
    /// [`InadequacyReason::TooUniform`] (insufficient delta variety).
    pub fn ensure_adequate(&self, config: &AdequacyConfig) -> Result<(), TimerError> {
        if self.backwards_violations > 0 {
            return Err(TimerError::Inadequate(InadequacyReason::NonMonotonic));
        }
        // zero_deltas / deltas > max_permille / 1000, in integers:
        let lhs = u64::from(self.zero_deltas).saturating_mul(1000);
        let rhs = u64::from(self.deltas).saturating_mul(u64::from(config.max_zero_delta_permille));
        if lhs > rhs {
            return Err(TimerError::Inadequate(InadequacyReason::TooCoarse));
        }
        if self.distinct_deltas < config.min_distinct_deltas {
            return Err(TimerError::Inadequate(InadequacyReason::TooUniform));
        }
        Ok(())
    }
}

/// Measures observed timer behavior: the startup timer-adequacy self-check.
///
/// Collects `config.samples` consecutive reads and reports zero-delta
/// fraction, minimum positive delta, bounded distinct-delta count, and
/// backwards violations. Pure observation — refusal policy lives in
/// [`AdequacyReport::ensure_adequate`].
pub fn measure_adequacy<T: TimerRead>(timer: &mut T, config: &AdequacyConfig) -> AdequacyReport {
    let width = timer.width_bits();
    let mut prev = timer.read();
    let mut report = AdequacyReport {
        deltas: 0,
        zero_deltas: 0,
        min_positive_delta: None,
        distinct_deltas: 0,
        backwards_violations: 0,
    };
    // Bounded distinct-positive-delta tracker (no_std, no alloc).
    let mut seen: [u64; 16] = [0; 16];
    let mut seen_len: usize = 0;
    let mut fed: u32 = 1;
    while fed < config.samples {
        let now = timer.read();
        match wrapping_delta(prev, now, width) {
            Err(TimerError::Backwards) => {
                report.backwards_violations = report.backwards_violations.saturating_add(1);
            }
            Err(_) | Ok(0) => {
                report.zero_deltas = report.zero_deltas.saturating_add(1);
            }
            Ok(delta) => {
                report.min_positive_delta = Some(match report.min_positive_delta {
                    Some(m) if m <= delta => m,
                    _ => delta,
                });
                let known = seen.iter().take(seen_len).any(|&s| s == delta);
                if !known && let Some(slot) = seen.get_mut(seen_len) {
                    *slot = delta;
                    seen_len = seen_len.saturating_add(1);
                }
            }
        }
        report.deltas = report.deltas.saturating_add(1);
        prev = now;
        fed = fed.saturating_add(1);
    }
    report.distinct_deltas = u32::try_from(seen_len).unwrap_or(u32::MAX);
    report
}

impl TimerSource {
    /// The per-architecture default timer source (design rationale at
    /// module level): x86_64 → `RawCounter`; aarch64 → `OsNanoClock`.
    /// Other architectures default to `OsNanoClock` pending a documented
    /// per-arch decision.
    #[must_use]
    pub const fn default_for_target() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::RawCounter
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::OsNanoClock
        }
    }
}

/// The platform timer for a configured [`TimerSource`].
#[derive(Debug)]
#[non_exhaustive]
pub enum PlatformTimer {
    /// Serialized raw CPU counter via the audited `oxicrypt-timer` crate.
    #[cfg(feature = "raw-counter")]
    RawCounter(RawCounterTimer),
    /// OS-provided monotonic nanosecond clock.
    #[cfg(feature = "std")]
    OsNanoClock(OsNanoClockTimer),
}

impl PlatformTimer {
    /// Constructs the timer for `source`.
    ///
    /// # Errors
    ///
    /// - [`TimerError::Unsupported`] for `InternalTimerThread` (reserved,
    ///   unselectable in Phase 0 — no validation claim references it).
    /// - [`TimerError::Unavailable`] when the requested source is not
    ///   compiled into this build (`raw-counter` / `std` feature off).
    pub fn new(source: TimerSource) -> Result<Self, TimerError> {
        match source {
            TimerSource::InternalTimerThread => Err(TimerError::Unsupported),
            TimerSource::RawCounter => {
                #[cfg(feature = "raw-counter")]
                {
                    Ok(Self::RawCounter(RawCounterTimer::new()))
                }
                #[cfg(not(feature = "raw-counter"))]
                {
                    Err(TimerError::Unavailable)
                }
            }
            TimerSource::OsNanoClock => {
                #[cfg(feature = "std")]
                {
                    Ok(Self::OsNanoClock(OsNanoClockTimer::new()))
                }
                #[cfg(not(feature = "std"))]
                {
                    Err(TimerError::Unavailable)
                }
            }
        }
    }
}

impl crate::source::sealed::Sealed for PlatformTimer {}
impl TimerRead for PlatformTimer {
    fn read(&mut self) -> u64 {
        match self {
            #[cfg(feature = "raw-counter")]
            Self::RawCounter(t) => t.read(),
            #[cfg(feature = "std")]
            Self::OsNanoClock(t) => t.read(),
            #[allow(unreachable_patterns)] // both features may be off
            _ => 0,
        }
    }
}

/// Serialized raw-counter timer (audited read in `oxicrypt-timer`).
#[cfg(feature = "raw-counter")]
#[derive(Debug)]
pub struct RawCounterTimer(());

#[cfg(feature = "raw-counter")]
impl RawCounterTimer {
    /// Creates the raw-counter timer.
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

#[cfg(feature = "raw-counter")]
impl Default for RawCounterTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "raw-counter")]
impl crate::source::sealed::Sealed for RawCounterTimer {}

#[cfg(feature = "raw-counter")]
impl TimerRead for RawCounterTimer {
    fn read(&mut self) -> u64 {
        oxicrypt_timer::read_raw_counter()
    }
}

/// OS monotonic nanosecond clock timer (`std`-gated).
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct OsNanoClockTimer {
    origin: std::time::Instant,
}

#[cfg(feature = "std")]
impl OsNanoClockTimer {
    /// Creates the OS-clock timer anchored at construction time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

#[cfg(feature = "std")]
impl Default for OsNanoClockTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl crate::source::sealed::Sealed for OsNanoClockTimer {}

#[cfg(feature = "std")]
impl TimerRead for OsNanoClockTimer {
    fn read(&mut self) -> u64 {
        // Truncation is fine: deltas are wrapping by design.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.origin.elapsed().as_nanos() as u64
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
    use crate::source::sealed::Sealed;

    /// Synthetic timer scripted by a closure over an internal tick count.
    struct Scripted<F: FnMut(u64) -> u64> {
        n: u64,
        f: F,
        width: u32,
    }
    impl<F: FnMut(u64) -> u64> Scripted<F> {
        fn new(width: u32, f: F) -> Self {
            Self { n: 0, f, width }
        }
    }
    impl<F: FnMut(u64) -> u64> Sealed for Scripted<F> {}
    impl<F: FnMut(u64) -> u64> TimerRead for Scripted<F> {
        fn read(&mut self) -> u64 {
            let v = (self.f)(self.n);
            self.n += 1;
            v
        }
        fn width_bits(&self) -> u32 {
            self.width
        }
    }

    // ── default_for_target (ISC-18) ──────────────────────────────────

    #[test]
    fn default_for_target_matches_arch() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(TimerSource::default_for_target(), TimerSource::RawCounter);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(TimerSource::default_for_target(), TimerSource::OsNanoClock);
    }

    // ── Phase-0 unselectability (ISC-20) ─────────────────────────────

    #[test]
    fn internal_timer_thread_is_unselectable() {
        assert_eq!(
            PlatformTimer::new(TimerSource::InternalTimerThread).unwrap_err(),
            TimerError::Unsupported
        );
    }

    // ── Delta semantics (ISC-47 / ISC-48) ────────────────────────────

    #[test]
    fn wrapping_delta_handles_wraparound_32bit() {
        // 32-bit counter wraps: prev near max, now small → small delta.
        let prev = 0xFFFF_FFF0u64;
        let now = 0x0000_0010u64;
        assert_eq!(wrapping_delta(prev, now, 32).unwrap(), 0x20);
    }

    #[test]
    fn wrapping_delta_flags_backwards() {
        // A genuine backwards step yields a near-maximal masked delta.
        assert_eq!(
            wrapping_delta(1000, 900, 64).unwrap_err(),
            TimerError::Backwards
        );
        assert_eq!(
            wrapping_delta(0x8000_0000, 0x7FFF_0000, 32).unwrap_err(),
            TimerError::Backwards
        );
    }

    #[test]
    fn wrapping_delta_full_width_normal() {
        assert_eq!(wrapping_delta(100, 175, 64).unwrap(), 75);
        assert_eq!(wrapping_delta(7, 7, 64).unwrap(), 0);
    }

    // ── Adequacy (ISC-19) ────────────────────────────────────────────

    #[test]
    fn fine_grained_timer_is_adequate() {
        // Varied positive increments: 1, 2, 3, ... cycling 1..=8.
        let mut t = Scripted::new(64, |n| (0..=n).map(|i| (i % 8) + 1).sum());
        let cfg = AdequacyConfig {
            samples: 256,
            ..AdequacyConfig::default()
        };
        let r = measure_adequacy(&mut t, &cfg);
        assert_eq!(r.backwards_violations, 0);
        assert_eq!(r.zero_deltas, 0);
        assert_eq!(r.min_positive_delta, Some(1));
        assert!(r.distinct_deltas >= 8);
        r.ensure_adequate(&cfg).unwrap();
    }

    #[test]
    fn coarse_timer_is_refused() {
        // Ticks once every 64 reads: >98% zero deltas.
        let mut t = Scripted::new(64, |n| n / 64);
        let cfg = AdequacyConfig {
            samples: 512,
            ..AdequacyConfig::default()
        };
        let r = measure_adequacy(&mut t, &cfg);
        assert_eq!(
            r.ensure_adequate(&cfg).unwrap_err(),
            TimerError::Inadequate(InadequacyReason::TooCoarse)
        );
    }

    #[test]
    fn uniform_timer_is_refused() {
        // Perfectly regular +5 ticks: exactly one distinct delta.
        let mut t = Scripted::new(64, |n| n * 5);
        let cfg = AdequacyConfig {
            samples: 256,
            ..AdequacyConfig::default()
        };
        let r = measure_adequacy(&mut t, &cfg);
        assert_eq!(r.distinct_deltas, 1);
        assert_eq!(
            r.ensure_adequate(&cfg).unwrap_err(),
            TimerError::Inadequate(InadequacyReason::TooUniform)
        );
    }

    #[test]
    fn backwards_timer_is_refused() {
        // Mostly forward with occasional backwards steps.
        let mut t = Scripted::new(64, |n| if n % 100 == 50 { n * 10 - 15 } else { n * 10 });
        let cfg = AdequacyConfig {
            samples: 512,
            ..AdequacyConfig::default()
        };
        let r = measure_adequacy(&mut t, &cfg);
        assert!(r.backwards_violations > 0);
        assert_eq!(
            r.ensure_adequate(&cfg).unwrap_err(),
            TimerError::Inadequate(InadequacyReason::NonMonotonic)
        );
    }

    #[test]
    fn raw_counter_unavailable_without_feature() {
        #[cfg(not(feature = "raw-counter"))]
        assert_eq!(
            PlatformTimer::new(TimerSource::RawCounter).unwrap_err(),
            TimerError::Unavailable
        );
        #[cfg(feature = "raw-counter")]
        {
            let mut t = PlatformTimer::new(TimerSource::RawCounter).unwrap();
            let a = t.read();
            let b = t.read();
            // Counter ticks forward in wrapping terms.
            assert!(wrapping_delta(a, b, 64).is_ok());
        }
    }
}
