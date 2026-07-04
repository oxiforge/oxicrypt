//! Offline preflight validation of an entropy-source registration
//! payload — run **before any server contact** so a malformed submission
//! is caught locally, at zero credential cost.
//!
//! The constraint table below transcribes the machine-checkable rules of
//! the vendored NIST metadata schema
//! (`vendor/entropy-source-metadata-schema.json`, ESV-Server `59e0438`,
//! JSON Schema draft-07). A drift-guard test ([`tests::constraints_match_vendored_schema`])
//! re-derives every transcribed constant from that vendored file, so a
//! hand-transcription mistake fails the test rather than shipping.
//!
//! Two vetted-conditioning constraints are **not** in the metadata schema
//! and are transcribed from the NIST server-side rule scripts (same
//! pinned commit) plus the ESVP digest §3: a vetted component's
//! `description` must be a recognized ACVTS algorithm name
//! (`RuleScripts/Rules/RegisterRequest/ConditioningComponent/Vetted/description.json`),
//! and a vetted component must supply a CAVP `validationNumber`
//! (`.../Vetted/validationNumber.json`; ratified design decision **D2**).
//! The metadata schema does not carry the `validationNumber` field at all,
//! so it cannot police this — the builder ([`crate::registration`]) and
//! this preflight do.
//!
//! # Two preflights: payloads and files
//!
//! [`preflight`] validates the registration **metadata payload** (the rules
//! above). [`preflight_data_file`] validates a **data file on disk** against
//! the ESV wire constraints — exactly 1,000,000 one-byte-per-sample symbols,
//! symbol values within the effective `min(bitsPerSample, 8)` width, the
//! mandated 1000×1000 restart layout, and `DataFileSampleSize` consistency.
//! Both run **before any server contact**, at zero credential cost.
//!
//! The file constraints are checked against the module's own SP 800-90B
//! constants — [`oxicrypt_entropy::sp800_90b::RAW_DATA_SAMPLE_COUNT`] (the
//! 1,000,000-sample ESV wire format) and the §3.1.4.1 restart dimensions
//! [`RESTART_ROUNDS`](oxicrypt_entropy::sp800_90b::RESTART_ROUNDS) ×
//! [`RESTART_SAMPLES_PER_ROUND`](oxicrypt_entropy::sp800_90b::RESTART_SAMPLES_PER_ROUND)
//! — the *same* constants the module's dataset emitters produce against
//! (entropy-crate ISC-97/99/108: `oxicrypt_entropy::collection`), so the
//! validator and the emitter cannot drift. The reference client applies one
//! `VALID_FILE_SIZE = 1_000_000` byte-size check to raw-noise and restart
//! files alike (ESV-Server `59e0438`, `client/utilities/utils.py`;
//! `1000 × 1000 = 1_000_000`).
//!
//! Scope note: the NIST `validation_rules/` DSL is not *executed* here (that
//! would need a rule interpreter); the machine-checkable rules it encodes are
//! transcribed and drift-guarded (payloads) or checked against the cited
//! constants (files). Conditioned-bits data files are out of scope for the
//! vetted oxicrypt path, which uploads none (ISC-107).

use oxicrypt_entropy::sp800_90b::{
    RAW_DATA_SAMPLE_COUNT, RESTART_ROUNDS, RESTART_SAMPLES_PER_ROUND,
};

use crate::registration::{ConditioningComponent, EntropyRegistration};

// ── Schema-derived constraint table (drift-guarded below) ─────────────

/// `bitsPerSample` minimum (vendored schema).
pub const BITS_PER_SAMPLE_MIN: i64 = 1;
/// `bitsPerSample` maximum (vendored schema).
pub const BITS_PER_SAMPLE_MAX: i64 = 256;
/// `primaryNoiseSource` maximum length in characters (vendored schema).
pub const PRIMARY_NOISE_SOURCE_MAX_CHARS: usize = 64;
/// `numberOfRestarts` / `samplesPerRestart` minimum (vendored schema).
pub const RESTART_FIELD_MIN: i64 = 1;
/// Minimum for a conditioning component's `minNin` / `nw` / `nOut`
/// (vendored schema).
pub const CC_POSITIVE_INT_MIN: i64 = 1;

/// The metadata object's required fields, in schema order (vendored
/// schema, element 1 `required`).
pub const REQUIRED_METADATA_FIELDS: &[&str] = &[
    "primaryNoiseSource",
    "iidClaim",
    "bitsPerSample",
    "hminEstimate",
    "physical",
    "numberOfRestarts",
    "samplesPerRestart",
    "additionalNoiseSources",
];

/// A conditioning component's required fields, in schema order (vendored
/// schema, `conditioningComponent.items.required`). Note that
/// `validationNumber` and `bijectiveClaim` are **not** here — they are
/// governed by the vetted/non-vetted server rules, not the schema.
pub const REQUIRED_CC_FIELDS: &[&str] = &[
    "sequencePosition",
    "vetted",
    "description",
    "minNin",
    "minHin",
    "nw",
    "nOut",
    "hOut",
];

/// The exact ACVTS algorithm name for the vetted SHA2-256 conditioning
/// component. (Task requirement; ESVP digest §3.)
pub const VETTED_SHA2_256_NAME: &str = "SHA2-256";

/// Recognized ACVTS vetted-algorithm names accepted for a vetted
/// conditioning component's `description`.
///
/// These are the SP 800-90B approved-hash / XOF conditioning names whose
/// ACVP registration spellings are unambiguous (the exact `"SHA2-256"` is
/// the oxicrypt target and the one this slice exercises). The vetted MAC /
/// DRBG / derivation-function conditioning options from the ESVP digest §3
/// (HMAC, CMAC, CBC-MAC, CTR/Hash/HMAC-DRBG, Hash_DF, BlockCipher_DF) are
/// deliberately omitted until their exact ACVTS spellings are confirmed at
/// the attended demo smoke — the server-side rule is authoritative, this
/// list is a conservative local pre-check. Extend as spellings are
/// confirmed.
pub const VETTED_ALGORITHM_NAMES: &[&str] = &[
    "SHA2-224",
    "SHA2-256",
    "SHA2-384",
    "SHA2-512",
    "SHA2-512/224",
    "SHA2-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE-128",
    "SHAKE-256",
];

/// Whether `name` is a recognized ACVTS vetted-algorithm name (see
/// [`VETTED_ALGORITHM_NAMES`]).
pub fn is_vetted_algorithm_name(name: &str) -> bool {
    VETTED_ALGORITHM_NAMES.contains(&name)
}

// ── Preflight errors ──────────────────────────────────────────────────

/// A single conditioning-component preflight violation.
#[derive(Debug, Clone, PartialEq)]
pub enum CcError {
    /// `description` was empty.
    DescriptionEmpty,
    /// `minNin` was below [`CC_POSITIVE_INT_MIN`].
    MinNinTooSmall {
        /// The offending value.
        value: i64,
    },
    /// `nw` was below [`CC_POSITIVE_INT_MIN`].
    NwTooSmall {
        /// The offending value.
        value: i64,
    },
    /// `nOut` was below [`CC_POSITIVE_INT_MIN`].
    NOutTooSmall {
        /// The offending value.
        value: i64,
    },
    /// `minHin` was NaN or infinite.
    MinHinNonFinite,
    /// `minHin` was negative.
    MinHinBelowZero {
        /// The offending value.
        value: f64,
    },
    /// `hOut` was NaN or infinite.
    HOutNonFinite,
    /// `hOut` was negative.
    HOutBelowZero {
        /// The offending value.
        value: f64,
    },
    /// A vetted component's `description` is not a recognized ACVTS name.
    VettedUnknownAlgorithm {
        /// The rejected description.
        description: String,
    },
    /// A vetted component is missing its CAVP `validationNumber` (D2).
    VettedMissingValidationNumber,
    /// A vetted component carries a `bijectiveClaim` (not applicable —
    /// server rule `Vetted/bijectiveClaimIsNotApplicable.json`).
    VettedHasBijectiveClaim,
    /// A non-vetted component is missing its required `bijectiveClaim`.
    NonVettedMissingBijectiveClaim,
    /// A non-vetted component carries a `validationNumber` (not applicable
    /// — server rule `NonVetted/validationNumberIsNotApplicable.json`).
    NonVettedHasValidationNumber,
}

/// A single registration-payload preflight violation.
#[derive(Debug, Clone, PartialEq)]
pub enum PreflightError {
    /// `primaryNoiseSource` was empty or all-whitespace.
    PrimaryNoiseSourceEmpty,
    /// `primaryNoiseSource` exceeded [`PRIMARY_NOISE_SOURCE_MAX_CHARS`].
    PrimaryNoiseSourceTooLong {
        /// Actual character count.
        chars: usize,
    },
    /// `bitsPerSample` outside `1..=256`.
    BitsPerSampleOutOfRange {
        /// The offending value.
        value: i64,
    },
    /// `hminEstimate` was NaN or infinite.
    HminNonFinite,
    /// `hminEstimate` was negative.
    HminBelowZero {
        /// The offending value.
        value: f64,
    },
    /// `hminEstimate` exceeded `bitsPerSample` (schema description +
    /// server rule `hMinEstimate.json`: `0.0 <= hmin <= bitsPerSample`).
    HminAboveBitsPerSample {
        /// The offending value.
        value: f64,
        /// The `bitsPerSample` ceiling.
        bits_per_sample: i64,
    },
    /// `numberOfRestarts` below [`RESTART_FIELD_MIN`].
    NumberOfRestartsTooSmall {
        /// The offending value.
        value: i64,
    },
    /// `samplesPerRestart` below [`RESTART_FIELD_MIN`].
    SamplesPerRestartTooSmall {
        /// The offending value.
        value: i64,
    },
    /// `numberOfOEs`, when present, was below 1.
    NumberOfOesTooSmall {
        /// The offending value.
        value: i64,
    },
    /// The conditioning components' `sequencePosition`s were not exactly
    /// `1..=n` (schema: "must be 1, 2, ... n"; server rule
    /// `ConditioningComponent/sequenceNumbers.json`).
    ConditioningSequenceNotConsecutive,
    /// A conditioning component violation, with its index in the list.
    Conditioning {
        /// Index of the offending component.
        index: usize,
        /// The specific component error.
        kind: CcError,
    },
}

/// Validate a registration payload against the vendored schema's
/// machine-checkable constraints plus the vetted/non-vetted conditioning
/// rules. Returns every violation found (empty ⇒ `Ok`), so a caller can
/// report all problems at once.
///
/// # Errors
/// A non-empty `Vec<PreflightError>` listing each violation.
pub fn preflight(reg: &EntropyRegistration) -> Result<(), Vec<PreflightError>> {
    let mut errors = Vec::new();

    // primaryNoiseSource: non-whitespace, ≤64 chars.
    if reg.primary_noise_source.trim().is_empty() {
        errors.push(PreflightError::PrimaryNoiseSourceEmpty);
    }
    let chars = reg.primary_noise_source.chars().count();
    if chars > PRIMARY_NOISE_SOURCE_MAX_CHARS {
        errors.push(PreflightError::PrimaryNoiseSourceTooLong { chars });
    }

    // bitsPerSample: 1..=256.
    if reg.bits_per_sample < BITS_PER_SAMPLE_MIN || reg.bits_per_sample > BITS_PER_SAMPLE_MAX {
        errors.push(PreflightError::BitsPerSampleOutOfRange {
            value: reg.bits_per_sample,
        });
    }

    // hminEstimate: finite, 0.0..=bitsPerSample.
    if reg.hmin_estimate.is_finite() {
        if reg.hmin_estimate < 0.0 {
            errors.push(PreflightError::HminBelowZero {
                value: reg.hmin_estimate,
            });
        }
        // bitsPerSample is ≤256, so the i64→f64 conversion is exact.
        #[allow(clippy::cast_precision_loss)]
        let bits_f = reg.bits_per_sample as f64;
        if reg.hmin_estimate > bits_f {
            errors.push(PreflightError::HminAboveBitsPerSample {
                value: reg.hmin_estimate,
                bits_per_sample: reg.bits_per_sample,
            });
        }
    } else {
        errors.push(PreflightError::HminNonFinite);
    }

    // Restart fields: ≥1.
    if reg.number_of_restarts < RESTART_FIELD_MIN {
        errors.push(PreflightError::NumberOfRestartsTooSmall {
            value: reg.number_of_restarts,
        });
    }
    if reg.samples_per_restart < RESTART_FIELD_MIN {
        errors.push(PreflightError::SamplesPerRestartTooSmall {
            value: reg.samples_per_restart,
        });
    }

    // numberOfOEs (optional): ≥1 when present.
    if let Some(n) = reg.number_of_oes.filter(|&n| n < 1) {
        errors.push(PreflightError::NumberOfOesTooSmall { value: n });
    }

    // Conditioning: sequence positions must be exactly 1..=n.
    if !reg.conditioning.is_empty() && !sequence_positions_are_consecutive(&reg.conditioning) {
        errors.push(PreflightError::ConditioningSequenceNotConsecutive);
    }
    for (index, cc) in reg.conditioning.iter().enumerate() {
        for kind in conditioning_errors(cc) {
            errors.push(PreflightError::Conditioning { index, kind });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// True if the sorted `sequencePosition`s are exactly `1, 2, …, n`.
fn sequence_positions_are_consecutive(ccs: &[ConditioningComponent]) -> bool {
    let mut positions: Vec<i64> = ccs.iter().map(|c| c.sequence_position).collect();
    positions.sort_unstable();
    for (idx, pos) in positions.iter().enumerate() {
        let expected = i64::try_from(idx).ok().and_then(|v| v.checked_add(1));
        if expected != Some(*pos) {
            return false;
        }
    }
    true
}

/// Collect the preflight violations of one conditioning component.
fn conditioning_errors(cc: &ConditioningComponent) -> Vec<CcError> {
    let mut errs = Vec::new();

    if cc.description.trim().is_empty() {
        errs.push(CcError::DescriptionEmpty);
    }
    if cc.min_nin < CC_POSITIVE_INT_MIN {
        errs.push(CcError::MinNinTooSmall { value: cc.min_nin });
    }
    if cc.nw < CC_POSITIVE_INT_MIN {
        errs.push(CcError::NwTooSmall { value: cc.nw });
    }
    if cc.n_out < CC_POSITIVE_INT_MIN {
        errs.push(CcError::NOutTooSmall { value: cc.n_out });
    }
    if !cc.min_hin.is_finite() {
        errs.push(CcError::MinHinNonFinite);
    } else if cc.min_hin < 0.0 {
        errs.push(CcError::MinHinBelowZero { value: cc.min_hin });
    }
    if !cc.h_out.is_finite() {
        errs.push(CcError::HOutNonFinite);
    } else if cc.h_out < 0.0 {
        errs.push(CcError::HOutBelowZero { value: cc.h_out });
    }

    if cc.vetted {
        // Vetted: recognized name, present validationNumber (D2), no
        // bijectiveClaim.
        if !cc.description.trim().is_empty() && !is_vetted_algorithm_name(&cc.description) {
            errs.push(CcError::VettedUnknownAlgorithm {
                description: cc.description.clone(),
            });
        }
        match &cc.validation_number {
            Some(vn) if !vn.is_empty() => {}
            _ => errs.push(CcError::VettedMissingValidationNumber),
        }
        if cc.bijective_claim.is_some() {
            errs.push(CcError::VettedHasBijectiveClaim);
        }
    } else {
        // Non-vetted: required bijectiveClaim, no validationNumber.
        if cc.bijective_claim.is_none() {
            errs.push(CcError::NonVettedMissingBijectiveClaim);
        }
        if cc.validation_number.is_some() {
            errs.push(CcError::NonVettedHasValidationNumber);
        }
    }

    errs
}

// ── Data-file preflight (files half of ISC-110) ───────────────────────

/// Which data-file slot a file fills. Both carry exactly 1,000,000
/// one-byte-per-sample symbols; only the restart file adds the 1000×1000
/// dimension cross-check. (The vetted oxicrypt path uploads no conditioned
/// file — ISC-107 — so that slot has no file preflight.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFileKind {
    /// The raw-noise data file.
    RawNoise,
    /// The restart-test data file (1000 restarts × 1000 samples).
    Restart,
}

/// A single data-file preflight violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePreflightError {
    /// The file's byte length — which, at one byte per sample, is the sample
    /// count — is not the required 1,000,000
    /// ([`RAW_DATA_SAMPLE_COUNT`](oxicrypt_entropy::sp800_90b::RAW_DATA_SAMPLE_COUNT)).
    WrongSampleCount {
        /// The file's actual byte length.
        actual: usize,
        /// The required sample count (1,000,000).
        expected: u32,
    },
    /// A sample byte does not fit in the effective `min(bitsPerSample, 8)`
    /// width — reported for the first offending symbol (a byte-padded sample
    /// must never set a bit above its declared width). Entropy-crate ISC-108
    /// is the emitter side; this is the validator side.
    SampleValueTooWide {
        /// Byte offset of the first over-wide sample.
        index: usize,
        /// Its value.
        value: u8,
        /// The effective width in bits (`min(bitsPerSample, 8)`).
        width: u32,
    },
    /// A restart file whose registration `numberOfRestarts` ×
    /// `samplesPerRestart` is not the mandated 1000 × 1000 layout
    /// (SP 800-90B §3.1.4.1;
    /// [`RESTART_ROUNDS`](oxicrypt_entropy::sp800_90b::RESTART_ROUNDS) ×
    /// [`RESTART_SAMPLES_PER_ROUND`](oxicrypt_entropy::sp800_90b::RESTART_SAMPLES_PER_ROUND)).
    /// Entropy-crate ISC-99 is the emitter-side consistency; this is the
    /// validator side.
    RestartDimensionsMismatch {
        /// The registration's `numberOfRestarts`.
        number_of_restarts: i64,
        /// The registration's `samplesPerRestart`.
        samples_per_restart: i64,
        /// The required restart rounds (1000).
        expected_rounds: u32,
        /// The required samples per round (1000).
        expected_samples_per_round: u32,
    },
    /// The declared `DataFileSampleSize` disagrees with the effective width
    /// `min(bitsPerSample, 8)` derived from the registration (the server
    /// interprets the file by this width, so a mismatch mis-reads the data).
    SampleSizeInconsistent {
        /// The declared `DataFileSampleSize`.
        declared: u8,
        /// The effective width the registration implies.
        expected: u32,
    },
}

/// The effective per-sample width for a `bitsPerSample`: `min(bitsPerSample,
/// 8)`, since a byte-padded sample holds at most eight bits. Clamped into
/// `1..=8` — a `bitsPerSample` outside the schema's `1..=256` is flagged by
/// the payload [`preflight`], so run that first; here the clamp keeps the
/// width well-defined.
#[must_use]
pub fn effective_sample_width(bits_per_sample: i64) -> u32 {
    let clamped = bits_per_sample.clamp(1, 8);
    // 1..=8 after clamping, so the cast is exact and lossless.
    u32::try_from(clamped).unwrap_or(8)
}

/// Preflight a data file on disk against the ESV wire constraints, **before
/// any server contact**. Returns every violation found (empty ⇒ `Ok`).
///
/// Checks, against the module's own cited constants so validator and emitter
/// cannot drift:
///
/// 1. **Sample count / byte padding** — `bytes.len()` (one byte per sample)
///    must equal [`RAW_DATA_SAMPLE_COUNT`](oxicrypt_entropy::sp800_90b::RAW_DATA_SAMPLE_COUNT)
///    (1,000,000).
/// 2. **Symbol width** — every sample must fit in the effective
///    `min(bitsPerSample, 8)` width (the first offender is reported).
/// 3. **Restart layout** (restart files only) — the registration's
///    `numberOfRestarts` × `samplesPerRestart` must be the mandated
///    1000 × 1000 (SP 800-90B §3.1.4.1).
/// 4. **`DataFileSampleSize` consistency** — when a per-file sample width is
///    declared, it must equal the effective width the registration implies.
///
/// `declared_sample_size` is the `DataFileSampleSize` the upload would carry
/// (see [`crate::datafiles::DataFileUpload::sample_size`]); pass `None` when
/// the field is omitted.
///
/// # Errors
/// A non-empty `Vec<FilePreflightError>` listing each violation.
pub fn preflight_data_file(
    bytes: &[u8],
    kind: DataFileKind,
    reg: &EntropyRegistration,
    declared_sample_size: Option<u8>,
) -> Result<(), Vec<FilePreflightError>> {
    let mut errors = Vec::new();
    let width = effective_sample_width(reg.bits_per_sample);

    // 1. Sample count == file byte length (one byte per sample).
    if bytes.len() != RAW_DATA_SAMPLE_COUNT as usize {
        errors.push(FilePreflightError::WrongSampleCount {
            actual: bytes.len(),
            expected: RAW_DATA_SAMPLE_COUNT,
        });
    }

    // 2. Every symbol fits in the effective width (report the first offender).
    // A full byte (width 8) admits every value, so only narrower widths gate.
    if width < 8 {
        let ceiling = 1u32 << width; // width ∈ 1..=7 here → 2..=128, no overflow
        if let Some((index, &value)) = bytes
            .iter()
            .enumerate()
            .find(|&(_, &b)| u32::from(b) >= ceiling)
        {
            errors.push(FilePreflightError::SampleValueTooWide {
                index,
                value,
                width,
            });
        }
    }

    // 3. Restart files: the 1000 × 1000 layout (SP 800-90B §3.1.4.1).
    if kind == DataFileKind::Restart
        && (reg.number_of_restarts != i64::from(RESTART_ROUNDS)
            || reg.samples_per_restart != i64::from(RESTART_SAMPLES_PER_ROUND))
    {
        errors.push(FilePreflightError::RestartDimensionsMismatch {
            number_of_restarts: reg.number_of_restarts,
            samples_per_restart: reg.samples_per_restart,
            expected_rounds: RESTART_ROUNDS,
            expected_samples_per_round: RESTART_SAMPLES_PER_ROUND,
        });
    }

    // 4. Declared DataFileSampleSize must match the effective width.
    if let Some(declared) = declared_sample_size
        && u32::from(declared) != width
    {
        errors.push(FilePreflightError::SampleSizeInconsistent {
            declared,
            expected: width,
        });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::registration::ConditioningComponent;
    use acvp_harness::json::JsonValue;

    fn valid() -> EntropyRegistration {
        let mut reg = EntropyRegistration::new_non_iid(
            "cpu-jitter timing source",
            4,
            0.75,
            1000,
            1000,
            false,
        );
        reg.conditioning.push(
            ConditioningComponent::vetted_sha2_256(1, "A1234", 384, 0.5, 256, 256, 4.0).unwrap(),
        );
        reg
    }

    /// Assert that `errors` contains at least one element matching `pat`.
    macro_rules! assert_has {
        ($errors:expr, $pat:pat) => {{
            let errs = $errors;
            assert!(
                errs.iter().any(|e| matches!(e, $pat)),
                "expected a {} in {errs:?}",
                stringify!($pat)
            );
        }};
    }

    #[test]
    fn valid_payload_passes() {
        assert_eq!(preflight(&valid()), Ok(()));
    }

    #[test]
    fn missing_validation_number_on_vetted_component_is_caught() {
        // Hand-build a vetted component (bypassing the D2 constructor) to
        // prove the preflight net also catches an absent validationNumber.
        let mut reg = valid();
        reg.conditioning[0].validation_number = None;
        let errs = preflight(&reg).unwrap_err();
        assert_has!(
            &errs,
            PreflightError::Conditioning {
                kind: CcError::VettedMissingValidationNumber,
                ..
            }
        );
    }

    #[test]
    fn wrong_vetted_conditioning_name_is_caught() {
        let mut reg = valid();
        reg.conditioning[0].description = "SHA-256".to_string(); // not the ACVTS name
        let errs = preflight(&reg).unwrap_err();
        assert_has!(
            &errs,
            PreflightError::Conditioning {
                kind: CcError::VettedUnknownAlgorithm { .. },
                ..
            }
        );
    }

    #[test]
    fn bad_number_of_oes_is_caught() {
        let mut reg = valid();
        reg.number_of_oes = Some(0);
        let errs = preflight(&reg).unwrap_err();
        assert_has!(&errs, PreflightError::NumberOfOesTooSmall { value: 0 });
    }

    #[test]
    fn valid_number_of_oes_passes() {
        let mut reg = valid();
        reg.number_of_oes = Some(2);
        assert_eq!(preflight(&reg), Ok(()));
    }

    #[test]
    fn bits_per_sample_out_of_range_is_caught() {
        let mut reg = valid();
        reg.bits_per_sample = 257;
        assert_has!(
            &preflight(&reg).unwrap_err(),
            PreflightError::BitsPerSampleOutOfRange { value: 257 }
        );
        reg.bits_per_sample = 0;
        assert_has!(
            &preflight(&reg).unwrap_err(),
            PreflightError::BitsPerSampleOutOfRange { value: 0 }
        );
    }

    #[test]
    fn hmin_above_bits_per_sample_is_caught() {
        let mut reg = valid();
        reg.bits_per_sample = 4;
        reg.hmin_estimate = 5.0; // > bitsPerSample
        assert_has!(
            &preflight(&reg).unwrap_err(),
            PreflightError::HminAboveBitsPerSample { .. }
        );
    }

    #[test]
    fn hmin_non_finite_and_negative_are_caught() {
        let mut reg = valid();
        reg.hmin_estimate = f64::NAN;
        assert_has!(&preflight(&reg).unwrap_err(), PreflightError::HminNonFinite);
        reg.hmin_estimate = -0.5;
        assert_has!(
            &preflight(&reg).unwrap_err(),
            PreflightError::HminBelowZero { .. }
        );
    }

    #[test]
    fn empty_primary_noise_source_is_caught() {
        let mut reg = valid();
        reg.primary_noise_source = "   ".to_string();
        assert_has!(
            &preflight(&reg).unwrap_err(),
            PreflightError::PrimaryNoiseSourceEmpty
        );
    }

    #[test]
    fn overlong_primary_noise_source_is_caught() {
        let mut reg = valid();
        reg.primary_noise_source = "x".repeat(65);
        assert_has!(
            &preflight(&reg).unwrap_err(),
            PreflightError::PrimaryNoiseSourceTooLong { chars: 65 }
        );
    }

    #[test]
    fn non_consecutive_sequence_positions_are_caught() {
        let mut reg = valid();
        reg.conditioning.push(
            ConditioningComponent::vetted_sha2_256(3, "A1234", 384, 0.5, 256, 256, 4.0).unwrap(),
        );
        // positions {1,3} are not {1,2}
        assert_has!(
            &preflight(&reg).unwrap_err(),
            PreflightError::ConditioningSequenceNotConsecutive
        );
    }

    #[test]
    fn non_vetted_component_requires_bijective_claim_and_no_validation_number() {
        let cc = ConditioningComponent {
            sequence_position: 1,
            vetted: false,
            bijective_claim: None,
            description: "custom xor".to_string(),
            validation_number: Some("A1".to_string()),
            min_nin: 8,
            min_hin: 1.0,
            nw: 8,
            n_out: 8,
            h_out: 1.0,
        };
        let mut reg = EntropyRegistration::new_non_iid("jitter", 8, 1.0, 1000, 1000, false);
        reg.conditioning.push(cc);
        let errs = preflight(&reg).unwrap_err();
        assert_has!(
            &errs,
            PreflightError::Conditioning {
                kind: CcError::NonVettedMissingBijectiveClaim,
                ..
            }
        );
        assert_has!(
            &errs,
            PreflightError::Conditioning {
                kind: CcError::NonVettedHasValidationNumber,
                ..
            }
        );
    }

    // ── Drift guard: constants match the vendored schema ──────────────

    /// Parse the vendored schema with the shared (integer-only) codec.
    ///
    /// The codec rejects fractional literals, and the schema carries four
    /// float bounds (`hminEstimate` min `0.0` / max `256.0`, and `minHin`
    /// / `hOut` min `0.0`). This normalizes only those float *bounds* to
    /// their integer form so the tree parses; none of the nodes this
    /// drift guard asserts on is among them, so the normalization cannot
    /// mask drift in anything checked here. The vendored file itself is
    /// untouched (verbatim from ESV-Server `59e0438`).
    fn parse_vendored_schema() -> acvp_harness::json::JsonValue {
        let raw = include_str!("../vendor/entropy-source-metadata-schema.json");
        let normalized = raw.replace("256.0", "256").replace("0.0", "0");
        acvp_harness::json::parse(&normalized)
            .expect("vendored schema parses after float-bound normalization")
    }

    fn required_strings(node: &acvp_harness::json::JsonValue, key: &str) -> Vec<String> {
        node.get(key)
            .and_then(acvp_harness::json::JsonValue::as_array)
            .expect("required array present")
            .iter()
            .map(|v| v.as_str().expect("required entry is a string").to_string())
            .collect()
    }

    /// Re-derive **every** transcribed constant from a schema tree, returning
    /// `Err` on the first mismatch. Factored out of
    /// [`constraints_match_vendored_schema`] so [`seeded_drift_is_caught`] can
    /// feed it a deliberately-mutated schema and confirm the guard rejects it.
    fn verify_schema_constraints(schema: &JsonValue) -> Result<(), String> {
        let items = schema
            .get("items")
            .and_then(JsonValue::as_array)
            .ok_or("schema.items is not a tuple array")?;
        if items.len() != 2 {
            return Err(format!(
                "schema tuple has {} items, expected 2",
                items.len()
            ));
        }

        // Element 0: esvVersion const.
        let ver = items[0]
            .get("properties")
            .and_then(|p| p.get("esvVersion"))
            .and_then(|v| v.get("const"))
            .and_then(JsonValue::as_str);
        if ver != Some(crate::login::ESV_VERSION) {
            return Err(format!(
                "esvVersion const = {ver:?}, expected {:?}",
                crate::login::ESV_VERSION
            ));
        }

        // Element 1: metadata required set + property bounds.
        let meta = &items[1];
        if required_strings(meta, "required") != REQUIRED_METADATA_FIELDS {
            return Err("metadata required set drifted from REQUIRED_METADATA_FIELDS".to_string());
        }
        let props = meta.get("properties").ok_or("metadata properties absent")?;

        // Assert a numeric schema bound equals a transcribed constant.
        let want_i64 = |node: &JsonValue, name: &str, key: &str, want: i64| -> Result<(), String> {
            let got = node
                .get(name)
                .and_then(|p| p.get(key))
                .and_then(JsonValue::as_i64);
            if got == Some(want) {
                Ok(())
            } else {
                Err(format!("{name}.{key} = {got:?}, expected {want}"))
            }
        };

        want_i64(
            props,
            "primaryNoiseSource",
            "maxLength",
            i64::try_from(PRIMARY_NOISE_SOURCE_MAX_CHARS).unwrap_or(-1),
        )?;
        want_i64(props, "bitsPerSample", "minimum", BITS_PER_SAMPLE_MIN)?;
        want_i64(props, "bitsPerSample", "maximum", BITS_PER_SAMPLE_MAX)?;
        want_i64(props, "numberOfRestarts", "minimum", RESTART_FIELD_MIN)?;
        want_i64(props, "samplesPerRestart", "minimum", RESTART_FIELD_MIN)?;
        // hminEstimate float bounds (0.0 / 256.0) are normalized to 0 / 256 by
        // the float pre-pass; the preflight enforces the tighter
        // `<= bitsPerSample` upper bound (schema description + rule
        // hMinEstimate.json), but the schema-static 256 is still re-derived.
        want_i64(props, "hminEstimate", "minimum", 0)?;
        want_i64(props, "hminEstimate", "maximum", 256)?;

        // conditioningComponent item required set + every numeric bound.
        let cc_items = props
            .get("conditioningComponent")
            .and_then(|c| c.get("items"))
            .ok_or("conditioningComponent.items absent")?;
        if required_strings(cc_items, "required") != REQUIRED_CC_FIELDS {
            return Err(
                "conditioning-component required set drifted from REQUIRED_CC_FIELDS".to_string(),
            );
        }
        let cc_props = cc_items
            .get("properties")
            .ok_or("conditioningComponent.items.properties absent")?;
        // CC_POSITIVE_INT_MIN backs the `< 1` checks over sequencePosition /
        // minNin / nw / nOut (sequencePosition is schema-bounded ≥1 too).
        for name in ["sequencePosition", "minNin", "nw", "nOut"] {
            want_i64(cc_props, name, "minimum", CC_POSITIVE_INT_MIN)?;
        }
        // minHin / hOut 0.0 floors: these NEWLY-asserted nodes ARE among the
        // ones the float pre-pass normalizes (0.0 → 0), so we assert on the
        // normalized integer token (0) deliberately. The floors back the
        // `< 0.0` checks in `conditioning_errors` (MinHinBelowZero /
        // HOutBelowZero).
        want_i64(cc_props, "minHin", "minimum", 0)?;
        want_i64(cc_props, "hOut", "minimum", 0)?;

        Ok(())
    }

    #[test]
    fn constraints_match_vendored_schema() {
        verify_schema_constraints(&parse_vendored_schema())
            .expect("transcribed constants match the vendored schema");
    }

    #[test]
    fn seeded_drift_is_caught() {
        // The pristine schema verifies clean…
        assert!(verify_schema_constraints(&parse_vendored_schema()).is_ok());
        // …but a seeded drift (bitsPerSample maximum 256 → 255 — the first
        // `"maximum": 256` in the file, ahead of hminEstimate's 256.0) is
        // rejected, proving the guard actually compares rather than no-ops.
        let raw = include_str!("../vendor/entropy-source-metadata-schema.json");
        let mutated = raw.replacen("\"maximum\": 256", "\"maximum\": 255", 1);
        assert_ne!(mutated, raw, "seed replacement must change the text");
        let normalized = mutated.replace("256.0", "256").replace("0.0", "0");
        let schema = acvp_harness::json::parse(&normalized).expect("mutated schema parses");
        assert!(verify_schema_constraints(&schema).is_err());
    }

    #[test]
    fn vetted_name_constant_is_recognized() {
        assert!(is_vetted_algorithm_name(VETTED_SHA2_256_NAME));
        assert!(!is_vetted_algorithm_name("SHA-256"));
    }

    // ── Data-file preflight (files half of ISC-110) ───────────────────

    /// A registration with a 4-bit sample (the oxicrypt pilot shape), whose
    /// restart dimensions are the mandated 1000 × 1000.
    fn reg_4bit() -> EntropyRegistration {
        valid() // bits_per_sample = 4, number_of_restarts = samples_per_restart = 1000
    }

    /// A synthetic 1,000,000-byte file whose bytes all fit in 4 bits.
    fn good_4bit_file() -> Vec<u8> {
        (0..RAW_DATA_SAMPLE_COUNT as usize)
            .map(|i| u8::try_from(i % 16).unwrap()) // 0..=15 → all fit in 4 bits
            .collect()
    }

    #[test]
    fn effective_width_is_min_bits_8_clamped() {
        assert_eq!(effective_sample_width(1), 1);
        assert_eq!(effective_sample_width(4), 4);
        assert_eq!(effective_sample_width(8), 8);
        assert_eq!(effective_sample_width(256), 8); // capped at 8
        assert_eq!(effective_sample_width(0), 1); // clamped up
        assert_eq!(effective_sample_width(-5), 1);
    }

    #[test]
    fn good_raw_and_restart_files_pass() {
        let reg = reg_4bit();
        let file = good_4bit_file();
        assert_eq!(
            preflight_data_file(&file, DataFileKind::RawNoise, &reg, Some(4)),
            Ok(())
        );
        assert_eq!(
            preflight_data_file(&file, DataFileKind::Restart, &reg, Some(4)),
            Ok(())
        );
        // The DataFileSampleSize field may be omitted.
        assert_eq!(
            preflight_data_file(&file, DataFileKind::RawNoise, &reg, None),
            Ok(())
        );
    }

    #[test]
    fn wrong_sample_count_is_caught() {
        let reg = reg_4bit();
        // One byte short of the required million.
        let short = vec![0u8; RAW_DATA_SAMPLE_COUNT as usize - 1];
        let errs = preflight_data_file(&short, DataFileKind::RawNoise, &reg, None).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            FilePreflightError::WrongSampleCount {
                actual,
                expected: 1_000_000
            } if *actual == RAW_DATA_SAMPLE_COUNT as usize - 1
        )));
    }

    #[test]
    fn over_wide_symbol_is_caught_at_its_index() {
        let reg = reg_4bit(); // width 4 → ceiling 16
        let mut file = good_4bit_file();
        file[42] = 16; // 16 does not fit in 4 bits
        let errs = preflight_data_file(&file, DataFileKind::RawNoise, &reg, Some(4)).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            FilePreflightError::SampleValueTooWide {
                index: 42,
                value: 16,
                width: 4
            }
        )));
    }

    #[test]
    fn full_byte_width_admits_every_symbol() {
        // bits_per_sample 8 → width 8 → no symbol can be too wide.
        let mut reg = reg_4bit();
        reg.bits_per_sample = 8;
        let file = vec![0xFFu8; RAW_DATA_SAMPLE_COUNT as usize];
        assert_eq!(
            preflight_data_file(&file, DataFileKind::RawNoise, &reg, Some(8)),
            Ok(())
        );
    }

    #[test]
    fn restart_dimension_mismatch_is_caught() {
        let mut reg = reg_4bit();
        reg.number_of_restarts = 500;
        reg.samples_per_restart = 2000; // product is 1e6 but not the 1000×1000 layout
        let file = good_4bit_file();
        let errs = preflight_data_file(&file, DataFileKind::Restart, &reg, Some(4)).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            FilePreflightError::RestartDimensionsMismatch {
                number_of_restarts: 500,
                samples_per_restart: 2000,
                expected_rounds: 1000,
                expected_samples_per_round: 1000,
            }
        )));
        // The same off-layout dims do NOT trip a raw-noise preflight (the
        // restart layout is a restart-file constraint only).
        assert_eq!(
            preflight_data_file(&file, DataFileKind::RawNoise, &reg, Some(4)),
            Ok(())
        );
    }

    #[test]
    fn declared_sample_size_inconsistent_with_registration_is_caught() {
        let reg = reg_4bit(); // effective width 4
        let file = good_4bit_file();
        // Declaring width 8 when the registration implies 4 mis-reads the file.
        let errs = preflight_data_file(&file, DataFileKind::RawNoise, &reg, Some(8)).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            FilePreflightError::SampleSizeInconsistent {
                declared: 8,
                expected: 4
            }
        )));
    }

    #[test]
    fn all_file_violations_are_collected_together() {
        let mut reg = reg_4bit();
        reg.number_of_restarts = 7; // wrong restart layout
        // Wrong size + over-wide symbol + declared-size mismatch, on a restart file.
        let mut file = vec![0u8; 10]; // far too short
        file[0] = 200; // over-wide for 4-bit width
        let errs = preflight_data_file(&file, DataFileKind::Restart, &reg, Some(2)).unwrap_err();
        assert!(
            errs.len() >= 4,
            "expected all four violations, got {errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, FilePreflightError::WrongSampleCount { .. }))
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, FilePreflightError::SampleValueTooWide { .. }))
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, FilePreflightError::RestartDimensionsMismatch { .. }))
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, FilePreflightError::SampleSizeInconsistent { .. }))
        );
    }
}
