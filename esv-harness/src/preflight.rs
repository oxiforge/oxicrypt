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
//! Scope note: this is the **payload** preflight (registration metadata).
//! Data-file preflight (1M byte-padded samples, sample-size bounds) is a
//! later slice (S5); the NIST `validation_rules/` DSL is not executed here
//! (that would need a rule interpreter — deferred with it).

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

    #[test]
    fn constraints_match_vendored_schema() {
        let schema = parse_vendored_schema();
        let items = schema
            .get("items")
            .and_then(acvp_harness::json::JsonValue::as_array)
            .expect("schema.items is a tuple array");
        assert_eq!(
            items.len(),
            2,
            "schema tuple has version + metadata objects"
        );

        // Element 0: esvVersion const.
        assert_eq!(
            items[0]
                .get("properties")
                .and_then(|p| p.get("esvVersion"))
                .and_then(|v| v.get("const"))
                .and_then(acvp_harness::json::JsonValue::as_str),
            Some(crate::login::ESV_VERSION)
        );

        // Element 1: metadata required set + property bounds.
        let meta = &items[1];
        assert_eq!(required_strings(meta, "required"), REQUIRED_METADATA_FIELDS);

        let props = meta.get("properties").expect("metadata properties");
        let prop_i64 = |name: &str, key: &str| {
            props
                .get(name)
                .and_then(|p| p.get(key))
                .and_then(acvp_harness::json::JsonValue::as_i64)
        };
        assert_eq!(
            prop_i64("primaryNoiseSource", "maxLength"),
            i64::try_from(PRIMARY_NOISE_SOURCE_MAX_CHARS).ok()
        );
        assert_eq!(
            prop_i64("bitsPerSample", "minimum"),
            Some(BITS_PER_SAMPLE_MIN)
        );
        assert_eq!(
            prop_i64("bitsPerSample", "maximum"),
            Some(BITS_PER_SAMPLE_MAX)
        );
        assert_eq!(
            prop_i64("numberOfRestarts", "minimum"),
            Some(RESTART_FIELD_MIN)
        );
        assert_eq!(
            prop_i64("samplesPerRestart", "minimum"),
            Some(RESTART_FIELD_MIN)
        );
        // hminEstimate lower bound (0.0 → normalized 0); the upper bound is
        // schema-static 256.0 but our preflight enforces the tighter
        // `<= bitsPerSample` (schema description + rule hMinEstimate.json).
        assert_eq!(prop_i64("hminEstimate", "minimum"), Some(0));
        assert_eq!(prop_i64("hminEstimate", "maximum"), Some(256));

        // conditioningComponent item required set.
        let cc_items = props
            .get("conditioningComponent")
            .and_then(|c| c.get("items"))
            .expect("conditioningComponent.items");
        assert_eq!(required_strings(cc_items, "required"), REQUIRED_CC_FIELDS);
    }

    #[test]
    fn vetted_name_constant_is_recognized() {
        assert!(is_vetted_algorithm_name(VETTED_SHA2_256_NAME));
        assert!(!is_vetted_algorithm_name("SHA-256"));
    }
}
