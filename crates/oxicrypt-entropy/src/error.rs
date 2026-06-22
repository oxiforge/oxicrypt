//! Typed errors for entropy-pipeline construction and operation.

use crate::h::MinEntropy;
use crate::health::HealthError;
use crate::source::SourceError;

/// Error from constructing or operating an entropy pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntropyError {
    /// The injected min-entropy claim exceeds the source's design-anchored
    /// ceiling. Construction is refused — the claim is never silently
    /// clamped.
    ClaimExceedsCeiling {
        /// The claim the caller attempted to inject.
        claimed: MinEntropy,
        /// The source's declared ceiling.
        ceiling: MinEntropy,
    },
    /// The injected min-entropy claim exceeds the information content of the
    /// declared sample width (`H > sample_width_bits`), which no source can
    /// deliver regardless of its design argument.
    ClaimExceedsSampleWidth {
        /// The claim the caller attempted to inject.
        claimed: MinEntropy,
        /// Declared sample width in bits.
        sample_width_bits: u8,
    },
    /// The underlying noise source failed.
    Source(SourceError),
    /// A health test rejected the configuration or a sample — including
    /// permanent poisoning and unsupported (α, alphabet, H) table points.
    Health(HealthError),
    /// The pipeline cannot serve this call in its current lifecycle state:
    /// output requested before startup tests passed, startup re-run after
    /// completion, or any call after permanent poisoning.
    NotReady,
    /// The startup conditioning known-answer test failed: the conditioning
    /// function did not reproduce its shipped FIPS 180-4 vector. The
    /// pipeline is permanently poisoned — refusal, never degraded
    /// operation.
    ConditionerKat,
    /// A streaming raw-data collection failed to write to its output sink.
    ///
    /// This is a tool-boundary error: it arises only on the std-gated
    /// streaming collection path (the `raw` module's `stream_to`), where
    /// samples are written to a file as they are produced. It is a unit
    /// variant (carries no `std::io::Error`) so [`EntropyError`] stays
    /// `Copy` and the `no_std` core is unaffected.
    Io,
}

impl core::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClaimExceedsCeiling { .. } => {
                f.write_str("min-entropy claim exceeds the source's design ceiling")
            }
            Self::ClaimExceedsSampleWidth { .. } => {
                f.write_str("min-entropy claim exceeds the declared sample width")
            }
            Self::Source(_) => f.write_str("noise source failure"),
            Self::Health(_) => f.write_str("health-test rejection or permanent poisoning"),
            Self::NotReady => {
                f.write_str("pipeline not ready: output before startup, re-run, or after poisoning")
            }
            Self::ConditionerKat => f.write_str("conditioning known-answer test failed"),
            Self::Io => f.write_str("raw-data collection I/O failure"),
        }
    }
}

impl From<SourceError> for EntropyError {
    fn from(e: SourceError) -> Self {
        Self::Source(e)
    }
}

impl From<HealthError> for EntropyError {
    fn from(e: HealthError) -> Self {
        Self::Health(e)
    }
}
