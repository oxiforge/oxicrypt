//! The noise-source abstraction — stage one of the three-stage pipeline.
//!
//! Sources are **dumb emitters**: they produce digitized raw symbols and
//! declare what they are ([`SourceSpec`]), where they ran
//! ([`SourceMetadata`]), and the design-anchored ceiling on any entropy
//! claim ([`NoiseSource::max_claimable_h`]). Health testing lives *outside*
//! the trait, uniformly over every source, so a future hardware source
//! inherits the full battery without reimplementing it. No source carries a
//! claimed-H value — the claim is injected at pipeline construction.

use crate::h::MinEntropy;

pub(crate) mod sealed {
    /// Sealing supertrait for [`NoiseSource`](super::NoiseSource).
    ///
    /// Implementations are crate-internal while the validation story
    /// matures — no third-party noise source can enter the pipeline.
    /// Unsealing later (removing the supertrait) is a non-breaking
    /// widening; the reverse would be a breaking change, hence sealed
    /// from the first release.
    #[allow(unreachable_pub)] // deliberately unreachable outside the crate — that IS the seal
    pub trait Sealed {}
}

/// A digitized raw sample emitted by a noise source.
///
/// Sources emit symbols of at most 8 declared bits (the declared width lives
/// in [`SourceSpec::sample_width_bits`]); any digitization from a wider
/// internal measurement (e.g. low-bit extraction from a timer delta) happens
/// inside the source, which owns the justification that the extraction
/// neither conceals failures from the health tests nor obscures the raw
/// statistics.
pub type RawSample = u8;

/// Static description of a noise source's output alphabet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpec {
    sample_width_bits: u8,
}

impl SourceSpec {
    /// Creates a spec for samples of `sample_width_bits` declared bits.
    /// Returns `None` unless `1 ≤ sample_width_bits ≤ 8`.
    #[must_use]
    pub const fn new(sample_width_bits: u8) -> Option<Self> {
        if sample_width_bits >= 1 && sample_width_bits <= 8 {
            Some(Self { sample_width_bits })
        } else {
            None
        }
    }

    /// Declared sample width in bits (1..=8).
    #[must_use]
    pub const fn sample_width_bits(self) -> u8 {
        self.sample_width_bits
    }

    /// Whether the source is binary (alphabet of exactly two values) —
    /// selects the Adaptive Proportion Test window size downstream.
    #[must_use]
    pub const fn is_binary(self) -> bool {
        self.sample_width_bits == 1
    }
}

/// Timer/counter a jitter-class noise source reads.
///
/// This is the configuration *vocabulary* only — per-architecture
/// defaults, the startup timer-adequacy self-check, and the Phase-0
/// unselectability of [`TimerSource::InternalTimerThread`] are enforced
/// by the timer layer, not here. The enum is deliberately exhaustive:
/// the three variants are the designed set, and exhaustive matches in
/// health and collection code surface every affected site if the set
/// ever changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerSource {
    /// Raw CPU cycle counter (e.g. TSC on x86_64, CNTVCT on aarch64).
    RawCounter,
    /// OS-provided nanosecond clock.
    OsNanoClock,
    /// Internal timer thread — reserved; unimplemented and unselectable
    /// in Phase 0.
    InternalTimerThread,
}

/// Identity of one collection environment, recorded with every dataset —
/// no anonymous datasets.
///
/// Borrowed fields keep the core crate `no_std`; the collecting binary owns
/// the discovered strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceMetadata<'a> {
    /// Timer/counter the source read. `None` for sources that do not
    /// derive samples from a timer (e.g. a future hardware TRNG).
    pub timer_source: Option<TimerSource>,
    /// Nominal counter frequency in Hz, when known. Effective granularity
    /// is always measured, never assumed from this value.
    pub counter_frequency_hz: Option<u64>,
    /// CPU model string of the collection environment.
    pub cpu_model: &'a str,
    /// Operating system of the collection environment.
    pub os: &'a str,
    /// Free-form collection parameters (loop shape, oversampling, build
    /// flags) sufficient to reproduce the dataset.
    pub collection_params: &'a str,
}

/// Error from a noise source while emitting samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceError {
    /// The source cannot currently produce samples (backend unavailable,
    /// unsupported configuration, or exhausted test source).
    Unavailable,
}

/// A noise source: stage one of `NoiseSource → health tests → conditioner`.
///
/// Implementations emit digitized raw symbols and static self-description.
/// They do **not** health-test their own output and do **not** carry a
/// claimed min-entropy — only the design-anchored *ceiling* that any
/// externally injected claim must not exceed.
///
/// This trait is **sealed**: it cannot be implemented outside
/// `oxicrypt-entropy` while the validation story matures. Unsealing
/// later is a non-breaking change. The trait is object-safe by design
/// (registries may use `dyn NoiseSource`), but the pipeline is generic —
/// no vtable indirection on the sample path.
pub trait NoiseSource: sealed::Sealed {
    /// Static description of the emitted alphabet.
    fn spec(&self) -> SourceSpec;

    /// Design-anchored ceiling on claimable min-entropy per sample.
    ///
    /// Pipeline construction fails if the injected claim exceeds this
    /// ceiling. The ceiling derives from the source's documented design
    /// argument, not from any runtime assessment.
    fn max_claimable_h(&self) -> MinEntropy;

    /// Emits the next raw sample.
    fn sample(&mut self) -> Result<RawSample, SourceError>;

    /// Identity of the environment this source instance runs on.
    fn metadata(&self) -> SourceMetadata<'_>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn spec_validates_width() {
        assert!(SourceSpec::new(0).is_none());
        assert!(SourceSpec::new(9).is_none());
        let s = SourceSpec::new(1).unwrap();
        assert!(s.is_binary());
        let s = SourceSpec::new(8).unwrap();
        assert!(!s.is_binary());
        assert_eq!(s.sample_width_bits(), 8);
    }
}
