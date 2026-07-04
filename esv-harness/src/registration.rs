//! ESVP §3 entropy-source registration: the metadata payload builder,
//! its wire serialization, and the multi-OE registration-response
//! parser.
//!
//! Registration is a POST of an entropy-source metadata submission to
//! `/esv/v1/entropyAssessments`; the server answers with one entropy
//! assessment object **per operating environment** (OE), each carrying
//! its own data-file URLs and a scoped JWT. The request builders and the
//! response parser here are pure functions, exercised against fixtures
//! with no network (the live, credentialed submission is a separate
//! attended session).
//!
//! # Protocol facts (cited)
//!
//! - **Metadata envelope:** `[{esvVersion:"1.0"}, {metadata}]` — the same
//!   versioned array as login (schema
//!   `entropy-source-metadata-schema.json`, vendored under `vendor/`,
//!   ESV-Server `59e0438`; ESVP digest §3).
//! - **Metadata fields + bounds** (vendored schema, element 1):
//!   `primaryNoiseSource` (string, ≤64 chars), `iidClaim` (bool),
//!   `bitsPerSample` (int 1..=256), `hminEstimate` (number,
//!   0.0..=`bitsPerSample`), `physical` (bool), `numberOfRestarts` (int
//!   ≥1), `samplesPerRestart` (int ≥1), `additionalNoiseSources` (bool),
//!   `conditioningComponent[]`. The numeric bounds are enforced (and
//!   drift-guarded against the vendored schema) in [`crate::preflight`].
//! - **Vetted conditioning entry:** for a vetted component the
//!   `description` is the **exact ACVTS algorithm name** — here
//!   `"SHA2-256"` — and `validationNumber` is the CAVP A# of that
//!   algorithm's validation. `validationNumber` is **not** part of the
//!   vendored metadata schema; it is required for a vetted component by
//!   the NIST server-side rule
//!   `RuleScripts/Rules/RegisterRequest/ConditioningComponent/Vetted/validationNumber.json`
//!   (ESV-Server `59e0438`) and by ratified design decision **D2**
//!   (required config, no default — construction fails typed when
//!   absent). (ESVP digest §3.)
//! - **`physical: false`.** The oxicrypt noise source is CPU timing
//!   jitter, a non-physical source; the *rationale* lives in the
//!   noise-source description, not here (ISC-112 — point, do not
//!   restate).
//! - **`numberOfOEs` (multi-OE).** A single registration may declare
//!   multiple operating environments; the response is then an array with
//!   one assessment object per OE. `numberOfOEs` is a register-payload
//!   field (server model `EntropyAssessmentRegisterPayload`), not part of
//!   the vendored *metadata* schema; the schema's `additionalProperties`
//!   default (true) admits it. (ESVP digest §3: "Registration creates an
//!   eaId + per-OE response objects (set `numberOfOEs`)".)
//!
//! ## Resolved-by-judgment: `numberOfOEs` on the wire
//!
//! The ESVP digest §3 says the client *sets* `numberOfOEs` on the
//! registration; the NIST reference client instead **rejects**
//! `numberOfOEs` in the payload and sends one registration per OE,
//! computing the OE count from the number of data files
//! (`client/client_actions.py:37-53`, ESV-Server `59e0438`). This module
//! carries `numberOfOEs` as an **optional** payload field
//! ([`EntropyRegistration::number_of_oes`]): `Some(n)` emits it (the
//! digest's shape), `None` omits it (the reference client's shape). The
//! divergence is flagged for empirical confirmation at the attended demo
//! smoke. The response parser ([`parse_registration_response`]) handles
//! the multi-OE array either way — the reference client confirms the
//! response is always an array, one element per OE, even for a single OE.

use acvp_harness::json::{self, JsonValue};

use crate::preflight;

/// The registration endpoint path — the **full server-relative path**;
/// the transport base is host-only (see [`crate::login::LOGIN_PATH`] for
/// the convention and the reference-config `/esv/v1` doubling trap).
/// (ESVP digest §3; ESV-Server reference client
/// `request_types/entropy_assessments.py:15`.)
pub const REGISTRATION_PATH: &str = "/esv/v1/entropyAssessments";

/// An error constructing a registration payload component.
///
/// These are the *fail-typed* construction guards — most notably D2's
/// "a vetted conditioning component must supply a `validationNumber`".
/// Broader schema/rule conformance is reported separately by
/// [`crate::preflight`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegError {
    /// A vetted conditioning component was constructed without a CAVP
    /// `validationNumber` (ratified D2 — required config, no default).
    MissingValidationNumber,
    /// A vetted conditioning component was constructed with a
    /// `description` that is not a recognized ACVTS vetted-algorithm name.
    UnknownVettedAlgorithm {
        /// The rejected description.
        description: String,
    },
    /// A floating-point metadata field was non-finite, so it cannot be
    /// serialized as a JSON number. Carries the offending field name.
    NonFiniteFloat {
        /// The metadata field whose value was NaN or infinite.
        field: &'static str,
    },
}

impl core::fmt::Display for RegError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingValidationNumber => {
                write!(
                    f,
                    "vetted conditioning component requires a CAVP validationNumber"
                )
            }
            Self::UnknownVettedAlgorithm { description } => {
                write!(
                    f,
                    "unrecognized vetted-algorithm description: {description:?}"
                )
            }
            Self::NonFiniteFloat { field } => {
                write!(f, "metadata field {field:?} is not a finite JSON number")
            }
        }
    }
}

impl std::error::Error for RegError {}

/// One conditioning component of the entropy source.
///
/// For the oxicrypt module the single conditioning component is the
/// vetted SHA2-256 hash; construct it with [`Self::vetted_sha2_256`],
/// which enforces D2. Fields are public so [`crate::preflight`] can
/// validate arbitrary (including hand-built or later-parsed) components,
/// and so seeded-violation tests can reach the preflight net.
#[derive(Debug, Clone, PartialEq)]
pub struct ConditioningComponent {
    /// 1-based position in the sequence of conditioning operations
    /// (schema: the positions of the components must be `1..=n`).
    pub sequence_position: i64,
    /// Whether the component meets the SP 800-90B definition of *vetted*.
    pub vetted: bool,
    /// For a **non-vetted** component only: whether it is claimed
    /// bijective. Must be `None` for a vetted component (server rule
    /// `Vetted/bijectiveClaimIsNotApplicable.json`).
    pub bijective_claim: Option<bool>,
    /// For a vetted component, the exact ACVTS algorithm name (e.g.
    /// `"SHA2-256"`); for a non-vetted component, a brief description.
    pub description: String,
    /// For a **vetted** component: the CAVP A# of the conditioning
    /// algorithm's validation (required — D2). `None`/absent for a
    /// non-vetted component (server rule
    /// `NonVetted/validationNumberIsNotApplicable.json`).
    pub validation_number: Option<String>,
    /// Minimum number of input bits required to run the component (≥1).
    pub min_nin: i64,
    /// Minimum input entropy required to run the component (≥0.0).
    pub min_hin: f64,
    /// Narrowest internal width of the component in bits (≥1).
    pub nw: i64,
    /// Output size of the component in bits (≥1).
    pub n_out: i64,
    /// Entropy in bits output by the component (≥0.0).
    pub h_out: f64,
}

impl ConditioningComponent {
    /// Construct a **vetted** conditioning component, enforcing D2 (a
    /// non-empty CAVP `validationNumber`) and that `algorithm_name` is a
    /// recognized ACVTS vetted-algorithm name.
    ///
    /// # Errors
    /// [`RegError::MissingValidationNumber`] if `validation_number` is
    /// empty; [`RegError::UnknownVettedAlgorithm`] if `algorithm_name` is
    /// not in [`preflight::VETTED_ALGORITHM_NAMES`].
    // The parameters map 1:1 to the vetted conditioning component's schema
    // attributes (minNin/minHin/nw/nOut/hOut); a params struct would only
    // relocate them. `min_nin`/`min_hin` mirror the NIST field names.
    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    pub fn vetted(
        sequence_position: i64,
        algorithm_name: &str,
        validation_number: &str,
        min_nin: i64,
        min_hin: f64,
        nw: i64,
        n_out: i64,
        h_out: f64,
    ) -> Result<Self, RegError> {
        if validation_number.is_empty() {
            return Err(RegError::MissingValidationNumber);
        }
        if !preflight::is_vetted_algorithm_name(algorithm_name) {
            return Err(RegError::UnknownVettedAlgorithm {
                description: algorithm_name.to_string(),
            });
        }
        Ok(Self {
            sequence_position,
            vetted: true,
            bijective_claim: None,
            description: algorithm_name.to_string(),
            validation_number: Some(validation_number.to_string()),
            min_nin,
            min_hin,
            nw,
            n_out,
            h_out,
        })
    }

    /// Convenience for the oxicrypt module's conditioning component: the
    /// vetted SHA2-256 hash. Equivalent to [`Self::vetted`] with
    /// `algorithm_name = "SHA2-256"` (the exact ACVTS name).
    ///
    /// # Errors
    /// [`RegError::MissingValidationNumber`] if `validation_number` is
    /// empty (D2).
    // `min_nin`/`min_hin` mirror the NIST schema field names.
    #[allow(clippy::similar_names)]
    pub fn vetted_sha2_256(
        sequence_position: i64,
        validation_number: &str,
        min_nin: i64,
        min_hin: f64,
        nw: i64,
        n_out: i64,
        h_out: f64,
    ) -> Result<Self, RegError> {
        Self::vetted(
            sequence_position,
            preflight::VETTED_SHA2_256_NAME,
            validation_number,
            min_nin,
            min_hin,
            nw,
            n_out,
            h_out,
        )
    }
}

/// A complete entropy-source registration metadata payload.
///
/// Construct the common oxicrypt case with [`Self::new_non_iid`] (which
/// bakes in `iidClaim = false` and `physical = false`), then attach one
/// or more [`ConditioningComponent`]s. Validate with
/// [`crate::preflight::preflight`] before serializing with
/// [`Self::to_wire_json`]. Fields are public to admit seeded-violation
/// tests and future parsed payloads.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyRegistration {
    /// Brief noise-source description (≤64 chars, non-whitespace).
    pub primary_noise_source: String,
    /// Whether an IID claim is made — `false` for the oxicrypt non-IID
    /// track.
    pub iid_claim: bool,
    /// Bits in one noise-source sample (1..=256).
    pub bits_per_sample: i64,
    /// Claimed min-entropy per sample (0.0..=`bits_per_sample`).
    pub hmin_estimate: f64,
    /// Whether the noise source is physical — `false`: the oxicrypt
    /// source is CPU timing jitter (non-physical). The rationale lives in
    /// the noise-source description, not here (ISC-112).
    pub physical: bool,
    /// Number of restarts used for the restart tests (≥1).
    pub number_of_restarts: i64,
    /// Samples generated per restart (≥1).
    pub samples_per_restart: i64,
    /// Whether the entropy source has additional noise sources
    /// (SP 800-90B §3.1.6).
    pub additional_noise_sources: bool,
    /// Optional operating-environment count for a multi-OE registration.
    /// `Some(n)` emits `numberOfOEs`; `None` omits it. See the
    /// module-level "Resolved-by-judgment" note.
    pub number_of_oes: Option<i64>,
    /// The conditioning components, in sequence order.
    pub conditioning: Vec<ConditioningComponent>,
}

impl EntropyRegistration {
    /// Build the oxicrypt-default metadata skeleton: `iidClaim = false`
    /// (non-IID track) and `physical = false` (CPU-jitter source). Attach
    /// conditioning components via [`EntropyRegistration::conditioning`].
    pub fn new_non_iid(
        primary_noise_source: &str,
        bits_per_sample: i64,
        hmin_estimate: f64,
        number_of_restarts: i64,
        samples_per_restart: i64,
        additional_noise_sources: bool,
    ) -> Self {
        Self {
            primary_noise_source: primary_noise_source.to_string(),
            iid_claim: false,
            bits_per_sample,
            hmin_estimate,
            physical: false,
            number_of_restarts,
            samples_per_restart,
            additional_noise_sources,
            number_of_oes: None,
            conditioning: Vec::new(),
        }
    }

    /// Serialize the registration to its ESVP wire body: the versioned
    /// two-element array `[{esvVersion:"1.0"}, {metadata}]`.
    ///
    /// The shared [`acvp_harness::json`] codec is integer-only (it
    /// rejects fractional literals), so the floating-point metadata
    /// fields (`hminEstimate`, and each conditioning component's `minHin`
    /// / `hOut`) are rendered by this module's contained numeric
    /// formatter. The *exactness* of `hminEstimate` against
    /// oxicrypt-entropy's fixed-point H — and its round-trip test against
    /// the schema bounds — is the separate `hmin` module (ISC-109, slice
    /// S5); here the value is rendered as a plain finite `f64`.
    ///
    /// # Errors
    /// [`RegError::NonFiniteFloat`] if any floating-point field is NaN or
    /// infinite (it would not be a valid JSON number).
    pub fn to_wire_json(&self) -> Result<String, RegError> {
        // Fail closed before rendering: a non-finite float cannot become
        // a JSON number, and the infallible renderer below assumes finite
        // inputs.
        if !self.hmin_estimate.is_finite() {
            return Err(RegError::NonFiniteFloat {
                field: "hminEstimate",
            });
        }
        for cc in &self.conditioning {
            if !cc.min_hin.is_finite() {
                return Err(RegError::NonFiniteFloat { field: "minHin" });
            }
            if !cc.h_out.is_finite() {
                return Err(RegError::NonFiniteFloat { field: "hOut" });
            }
        }

        let mut fields: Vec<(&str, Wire<'_>)> = vec![
            ("primaryNoiseSource", Wire::Str(&self.primary_noise_source)),
            ("iidClaim", Wire::Bool(self.iid_claim)),
            ("bitsPerSample", Wire::Int(self.bits_per_sample)),
            ("hminEstimate", Wire::Float(self.hmin_estimate)),
            ("physical", Wire::Bool(self.physical)),
            ("numberOfRestarts", Wire::Int(self.number_of_restarts)),
            ("samplesPerRestart", Wire::Int(self.samples_per_restart)),
            (
                "additionalNoiseSources",
                Wire::Bool(self.additional_noise_sources),
            ),
        ];
        if let Some(n) = self.number_of_oes {
            fields.push(("numberOfOEs", Wire::Int(n)));
        }
        if !self.conditioning.is_empty() {
            let items = self.conditioning.iter().map(cc_wire).collect();
            fields.push(("conditioningComponent", Wire::Arr(items)));
        }

        let envelope = Wire::Arr(vec![
            Wire::Obj(vec![("esvVersion", Wire::Str(super::login::ESV_VERSION))]),
            Wire::Obj(fields),
        ]);
        Ok(render_wire(&envelope))
    }
}

/// Render one conditioning component as a wire object, emitting the
/// vetted-only (`validationNumber`) and non-vetted-only (`bijectiveClaim`)
/// fields conditionally.
fn cc_wire(cc: &ConditioningComponent) -> Wire<'_> {
    let mut fields: Vec<(&str, Wire<'_>)> = vec![
        ("sequencePosition", Wire::Int(cc.sequence_position)),
        ("vetted", Wire::Bool(cc.vetted)),
        ("description", Wire::Str(&cc.description)),
    ];
    if let Some(vn) = &cc.validation_number {
        fields.push(("validationNumber", Wire::Str(vn)));
    }
    if let Some(bc) = cc.bijective_claim {
        fields.push(("bijectiveClaim", Wire::Bool(bc)));
    }
    fields.push(("minNin", Wire::Int(cc.min_nin)));
    fields.push(("minHin", Wire::Float(cc.min_hin)));
    fields.push(("nw", Wire::Int(cc.nw)));
    fields.push(("nOut", Wire::Int(cc.n_out)));
    fields.push(("hOut", Wire::Float(cc.h_out)));
    Wire::Obj(fields)
}

// ── Contained wire renderer (floats the shared codec cannot emit) ─────

/// A minimal JSON value for rendering the registration body. String and
/// integer scalars delegate to the proven [`acvp_harness::json`] codec
/// (so escaping and integer formatting are shared, not reimplemented);
/// only the float case, which that integer-only codec cannot represent,
/// is handled here.
enum Wire<'a> {
    Str(&'a str),
    Int(i64),
    Float(f64),
    Bool(bool),
    Obj(Vec<(&'a str, Wire<'a>)>),
    Arr(Vec<Wire<'a>>),
}

/// Render a [`Wire`] to compact JSON text. Infallible: callers guarantee
/// every [`Wire::Float`] is finite (see [`EntropyRegistration::to_wire_json`]),
/// and a finite `f64`'s `Display` form is always a valid JSON number
/// (decimal notation, never an exponent, never `NaN`/`inf`).
fn render_wire(w: &Wire<'_>) -> String {
    match w {
        Wire::Str(s) => json::to_pretty_string(&JsonValue::String((*s).to_string())),
        Wire::Int(n) => json::to_pretty_string(&JsonValue::Number(*n)),
        Wire::Bool(b) => (if *b { "true" } else { "false" }).to_string(),
        Wire::Float(f) => format!("{f}"),
        Wire::Obj(fields) => {
            let inner = fields
                .iter()
                .map(|(k, v)| {
                    let key = json::to_pretty_string(&JsonValue::String((*k).to_string()));
                    let val = render_wire(v);
                    format!("{key}:{val}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inner}}}")
        }
        Wire::Arr(items) => {
            let inner = items.iter().map(render_wire).collect::<Vec<_>>().join(",");
            format!("[{inner}]")
        }
    }
}

// ── Multi-OE registration response ────────────────────────────────────

/// A reference to one uploaded data-file slot returned by registration
/// (its URL and the trailing numeric id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFileRef {
    /// Full server URL of the data-file slot.
    pub url: String,
    /// The id — the last path segment of [`Self::url`].
    pub id: String,
}

impl DataFileRef {
    fn from_url(url: &str) -> Result<Self, String> {
        Ok(Self {
            url: url.to_string(),
            id: url_tail(url)?.to_string(),
        })
    }
}

/// A reference to a conditioned-bits data-file slot, with its sequence
/// position. (Present only for non-vetted, non-bijective conditioning —
/// the vetted oxicrypt path never receives one; see the ESVP digest §3.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionedFileRef {
    /// Full server URL of the conditioned-bits slot.
    pub url: String,
    /// The id — the last path segment of [`Self::url`].
    pub id: String,
    /// This conditioning component's sequence position.
    pub sequence_position: i64,
}

/// One operating environment's registration result: its entropy
/// assessment id, the data-file slots to upload into, and the per-OE
/// scoped JWT to authorize those uploads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OeRegistration {
    /// Full URL of the entropy assessment.
    pub url: String,
    /// The entropy assessment id — the last path segment of [`Self::url`].
    pub ea_id: String,
    /// The raw-noise data-file slot. Always `Some` when produced by
    /// [`parse_registration_response`], which requires it (the `Option` is
    /// retained for hand-built values); see [`parse_one_assessment`].
    pub raw_noise: Option<DataFileRef>,
    /// The restart-test data-file slot. `None` when the registration response
    /// carried no `restartTestBits` slot — it is tolerated-absent
    /// (DEFERRED-VERIFY at the attended smoke; see `parse_one_assessment`).
    pub restart: Option<DataFileRef>,
    /// Any conditioned-bits slots (empty for a vetted source).
    pub conditioned: Vec<ConditionedFileRef>,
    /// This OE's scoped access token (JWT).
    pub access_token: String,
}

/// The id of a resource URL: its last non-empty `/`-separated segment, after
/// trimming any trailing `/`. A URL with nothing left after trimming (all
/// slashes, or empty) is a typed error rather than a silently-empty id.
///
/// So `".../dataFiles/11/"` yields `"11"` (the trailing slash is trimmed),
/// while `"/"` / `""` yield an error. A host-only URL such as
/// `"https://host/"` trims to `"https://host"` whose last segment is the
/// non-empty `"host"` — it is *not* an empty tail, so it does not error here
/// (a real ESV resource URL always carries a `/{id}` path segment; the empty
/// case this guards is a structurally-degenerate URL).
fn url_tail(url: &str) -> Result<&str, String> {
    let trimmed = url.trim_end_matches('/');
    let tail = trimmed.rsplit('/').next().unwrap_or(trimmed);
    if tail.is_empty() {
        return Err(format!(
            "cannot derive an id from URL {url:?}: no path segment after trimming trailing '/'"
        ));
    }
    Ok(tail)
}

/// Parse a registration response into one [`OeRegistration`] per
/// operating environment.
///
/// The response is the versioned envelope `[{esvVersion}, [<ea>, …]]`
/// (reference client `request_types/entropy_assessments.py:17,25` strips
/// element 0, then iterates the array of assessments — always an array,
/// one element per OE). Each `<ea>` object carries `url`, `dataFileUrls`
/// (objects with `rawNoiseBits` / `restartTestBits` /
/// `conditionedBits`+`sequencePosition`), and `accessToken`.
///
/// The envelope itself is validated by the shared
/// [`crate::login::esv_payload_element`] — element 0 must be an
/// `{esvVersion}` object — so a version-less or error-shaped array
/// (`["error", …]`) is rejected the same way the auth parsers reject it.
///
/// # Errors
/// A `String` describing the first structural problem (parse failure,
/// missing envelope/assessment array, or a required field absent).
pub fn parse_registration_response(body: &str) -> Result<Vec<OeRegistration>, String> {
    let parsed = json::parse(body).map_err(|e| format!("parse registration response: {e}"))?;
    let payload = crate::login::esv_payload_element(&parsed)?;
    let assessments = payload
        .as_array()
        .ok_or("registration response payload (element 1) is not the assessment array")?;

    let mut out = Vec::with_capacity(assessments.len());
    for ea in assessments {
        out.push(parse_one_assessment(ea)?);
    }
    Ok(out)
}

/// Parse one entropy-assessment object from a registration response.
///
/// Fail-closed on the data-file slots: `dataFileUrls` must be present, an
/// array, and non-empty, and it must carry a `rawNoiseBits` slot. The
/// `restartTestBits` slot is **tolerated-absent** (`None` when missing): the
/// exact per-OE slot set the demo server returns is unproven, so requiring it
/// would reject a plausible server shape — **DEFERRED-VERIFY at the attended
/// smoke** whether a non-IID assessment always returns a restart slot; tighten
/// back to required only if the server confirms it. A duplicate `rawNoiseBits`
/// / `restartTestBits` slot, and a duplicate `conditionedBits`
/// `sequencePosition`, are each a typed error rather than a silent last-wins
/// overwrite. Conditioned-bits slots stay optional (absent for the vetted
/// oxicrypt path) and may repeat, one per distinct component position.
fn parse_one_assessment(ea: &JsonValue) -> Result<OeRegistration, String> {
    let url = ea
        .get("url")
        .and_then(JsonValue::as_str)
        .ok_or("assessment object missing string `url`")?;
    let access_token = ea
        .get("accessToken")
        .and_then(JsonValue::as_str)
        .ok_or("assessment object missing string `accessToken`")?;

    let slots = ea
        .get("dataFileUrls")
        .ok_or("assessment object missing `dataFileUrls`")?
        .as_array()
        .ok_or("assessment `dataFileUrls` is not an array")?;
    if slots.is_empty() {
        return Err("assessment `dataFileUrls` is empty".to_string());
    }

    let mut raw_noise = None;
    let mut restart = None;
    let mut conditioned: Vec<ConditionedFileRef> = Vec::new();
    for slot in slots {
        if let Some(u) = slot.get("rawNoiseBits").and_then(JsonValue::as_str) {
            if raw_noise.is_some() {
                return Err("assessment carries a duplicate `rawNoiseBits` slot".to_string());
            }
            raw_noise = Some(DataFileRef::from_url(u)?);
        }
        if let Some(u) = slot.get("restartTestBits").and_then(JsonValue::as_str) {
            if restart.is_some() {
                return Err("assessment carries a duplicate `restartTestBits` slot".to_string());
            }
            restart = Some(DataFileRef::from_url(u)?);
        }
        if let Some(u) = slot.get("conditionedBits").and_then(JsonValue::as_str) {
            let sequence_position = slot
                .get("sequencePosition")
                .and_then(JsonValue::as_i64)
                .ok_or("conditionedBits slot missing integer `sequencePosition`")?;
            if conditioned
                .iter()
                .any(|c| c.sequence_position == sequence_position)
            {
                return Err(format!(
                    "assessment carries a duplicate `conditionedBits` slot for sequence position {sequence_position}"
                ));
            }
            conditioned.push(ConditionedFileRef {
                url: u.to_string(),
                id: url_tail(u)?.to_string(),
                sequence_position,
            });
        }
    }

    // rawNoiseBits stays required; restartTestBits is tolerated-absent (see
    // the fn docs — DEFERRED-VERIFY at the attended smoke).
    let raw_noise = raw_noise.ok_or("assessment `dataFileUrls` has no `rawNoiseBits` slot")?;

    Ok(OeRegistration {
        ea_id: url_tail(url)?.to_string(),
        url: url.to_string(),
        raw_noise: Some(raw_noise),
        restart,
        conditioned,
        access_token: access_token.to_string(),
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    /// A valid vetted SHA2-256 registration for one OE.
    fn valid_registration() -> EntropyRegistration {
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

    // ── D2: vetted construction fails typed without a validationNumber ─

    #[test]
    fn vetted_sha2_256_sets_exact_name_and_carries_validation_number() {
        let cc =
            ConditioningComponent::vetted_sha2_256(1, "A1234", 384, 0.5, 256, 256, 4.0).unwrap();
        assert_eq!(cc.description, "SHA2-256");
        assert!(cc.vetted);
        assert_eq!(cc.validation_number.as_deref(), Some("A1234"));
        assert_eq!(cc.bijective_claim, None);
    }

    #[test]
    fn vetted_construction_without_validation_number_fails_typed() {
        let err = ConditioningComponent::vetted_sha2_256(1, "", 384, 0.5, 256, 256, 4.0);
        assert_eq!(err, Err(RegError::MissingValidationNumber));
    }

    #[test]
    fn vetted_construction_with_unknown_algorithm_name_fails_typed() {
        // "SHA-256" is not the ACVTS vetted name (that is "SHA2-256").
        let err = ConditioningComponent::vetted(1, "SHA-256", "A1234", 384, 0.5, 256, 256, 4.0);
        assert_eq!(
            err,
            Err(RegError::UnknownVettedAlgorithm {
                description: "SHA-256".to_string()
            })
        );
    }

    // ── Wire serialization ────────────────────────────────────────────

    #[test]
    fn wire_body_is_versioned_envelope_with_metadata() {
        // All-integer float values so the (integer-only) shared parser
        // can re-read the body for a structural check.
        let mut reg = EntropyRegistration::new_non_iid("jitter", 8, 0.0, 1000, 1000, false);
        reg.conditioning.push(
            ConditioningComponent::vetted_sha2_256(1, "A1234", 384, 0.0, 256, 256, 0.0).unwrap(),
        );
        let body = reg.to_wire_json().unwrap();
        let parsed = json::parse(&body).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0].get("esvVersion").and_then(JsonValue::as_str),
            Some("1.0")
        );
        let meta = &arr[1];
        assert_eq!(
            meta.get("primaryNoiseSource").and_then(JsonValue::as_str),
            Some("jitter")
        );
        assert_eq!(
            meta.get("iidClaim").and_then(JsonValue::as_bool),
            Some(false)
        );
        assert_eq!(
            meta.get("physical").and_then(JsonValue::as_bool),
            Some(false)
        );
        assert_eq!(
            meta.get("bitsPerSample").and_then(JsonValue::as_i64),
            Some(8)
        );
        // numberOfOEs omitted when None.
        assert!(meta.get("numberOfOEs").is_none());
        let ccs = meta
            .get("conditioningComponent")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(ccs.len(), 1);
        assert_eq!(
            ccs[0].get("description").and_then(JsonValue::as_str),
            Some("SHA2-256")
        );
        assert_eq!(
            ccs[0].get("validationNumber").and_then(JsonValue::as_str),
            Some("A1234")
        );
        // Vetted component omits the non-vetted-only bijectiveClaim field.
        assert!(ccs[0].get("bijectiveClaim").is_none());
    }

    #[test]
    fn wire_body_renders_fractional_hmin_as_unquoted_json_number() {
        let reg = EntropyRegistration::new_non_iid("jitter", 4, 0.7552, 1000, 1000, false);
        let body = reg.to_wire_json().unwrap();
        // Unquoted decimal number, not a string.
        assert!(body.contains("\"hminEstimate\":0.7552"), "{body}");
        assert!(!body.contains("\"hminEstimate\":\"0.7552\""), "{body}");
    }

    #[test]
    fn wire_body_emits_number_of_oes_when_set() {
        let mut reg = EntropyRegistration::new_non_iid("jitter", 4, 0.5, 1000, 1000, false);
        reg.number_of_oes = Some(2);
        let body = reg.to_wire_json().unwrap();
        assert!(body.contains("\"numberOfOEs\":2"), "{body}");
    }

    #[test]
    fn wire_body_rejects_non_finite_hmin() {
        let reg = EntropyRegistration::new_non_iid("jitter", 4, f64::NAN, 1000, 1000, false);
        assert_eq!(
            reg.to_wire_json(),
            Err(RegError::NonFiniteFloat {
                field: "hminEstimate"
            })
        );
    }

    #[test]
    fn render_finite_float_has_no_exponent_and_round_trips() {
        assert_eq!(render_wire(&Wire::Float(2.0)), "2");
        assert_eq!(render_wire(&Wire::Float(0.0)), "0");
        assert_eq!(render_wire(&Wire::Float(0.7552)), "0.7552");
        // Round-trips back to the same f64 (Display is shortest-round-trip).
        let s = render_wire(&Wire::Float(0.123_456_789));
        assert_eq!(s.parse::<f64>().unwrap(), 0.123_456_789);
    }

    // ── Multi-OE response parsing ─────────────────────────────────────

    /// A synthetic two-OE registration response.
    const TWO_OE_RESPONSE: &str = r#"[
        {"esvVersion":"1.0"},
        [
            {
                "url":"https://demo.esv.nist.gov/esv/v1/entropyAssessments/101",
                "dataFileUrls":[
                    {"rawNoiseBits":"https://demo.esv.nist.gov/esv/v1/entropyAssessments/101/dataFiles/11"},
                    {"restartTestBits":"https://demo.esv.nist.gov/esv/v1/entropyAssessments/101/dataFiles/12"}
                ],
                "accessToken":"jwt-oe1"
            },
            {
                "url":"https://demo.esv.nist.gov/esv/v1/entropyAssessments/202",
                "dataFileUrls":[
                    {"rawNoiseBits":"https://demo.esv.nist.gov/esv/v1/entropyAssessments/202/dataFiles/21"},
                    {"restartTestBits":"https://demo.esv.nist.gov/esv/v1/entropyAssessments/202/dataFiles/22"}
                ],
                "accessToken":"jwt-oe2"
            }
        ]
    ]"#;

    #[test]
    fn parse_two_oe_response_yields_per_oe_urls_and_tokens() {
        let oes = parse_registration_response(TWO_OE_RESPONSE).unwrap();
        assert_eq!(oes.len(), 2);

        assert_eq!(oes[0].ea_id, "101");
        assert_eq!(oes[0].access_token, "jwt-oe1");
        assert_eq!(oes[0].raw_noise.as_ref().unwrap().id, "11");
        assert_eq!(oes[0].restart.as_ref().unwrap().id, "12");
        assert!(oes[0].conditioned.is_empty());

        assert_eq!(oes[1].ea_id, "202");
        assert_eq!(oes[1].access_token, "jwt-oe2");
        assert_eq!(oes[1].raw_noise.as_ref().unwrap().id, "21");
        assert_eq!(oes[1].restart.as_ref().unwrap().id, "22");
    }

    #[test]
    fn parse_single_oe_response_is_still_an_array_of_one() {
        let body = r#"[{"esvVersion":"1.0"},[{"url":"x/esv/v1/entropyAssessments/7","dataFileUrls":[{"rawNoiseBits":"x/dataFiles/70"},{"restartTestBits":"x/dataFiles/71"}],"accessToken":"jwt-solo"}]]"#;
        let oes = parse_registration_response(body).unwrap();
        assert_eq!(oes.len(), 1);
        assert_eq!(oes[0].ea_id, "7");
        assert_eq!(oes[0].raw_noise.as_ref().unwrap().id, "70");
        assert_eq!(oes[0].restart.as_ref().unwrap().id, "71");
        assert!(oes[0].conditioned.is_empty());
    }

    #[test]
    fn parse_conditioned_slot_captures_sequence_position() {
        // raw-noise + restart slots are required alongside the conditioned one.
        let body = r#"[{"esvVersion":"1.0"},[{"url":"x/33","dataFileUrls":[{"rawNoiseBits":"x/dataFiles/90"},{"restartTestBits":"x/dataFiles/91"},{"conditionedBits":"x/dataFiles/92","sequencePosition":1}],"accessToken":"jwt"}]]"#;
        let oes = parse_registration_response(body).unwrap();
        assert_eq!(oes[0].conditioned.len(), 1);
        assert_eq!(oes[0].conditioned[0].id, "92");
        assert_eq!(oes[0].conditioned[0].sequence_position, 1);
    }

    #[test]
    fn parse_response_rejects_missing_assessment_array() {
        // Envelope present but element 1 is an object, not the array.
        let body = r#"[{"esvVersion":"1.0"},{"url":"x/1"}]"#;
        assert!(parse_registration_response(body).is_err());
    }

    #[test]
    fn parse_response_rejects_assessment_without_access_token() {
        let body = r#"[{"esvVersion":"1.0"},[{"url":"x/1","dataFileUrls":[]}]]"#;
        let err = parse_registration_response(body).unwrap_err();
        assert!(err.contains("accessToken"), "{err}");
    }

    // ── Item 4: envelope validation shared with the auth parsers ───────

    #[test]
    fn parse_registration_rejects_non_version_envelope() {
        // element 0 is a string, not an {esvVersion} object — rejected the
        // same way parse_access_token rejects a version-less envelope.
        let body = r#"["error",[{"url":"x/1","accessToken":"j"}]]"#;
        let err = parse_registration_response(body).unwrap_err();
        assert!(err.contains("esvVersion"), "{err}");
    }

    #[test]
    fn parse_registration_tolerates_trailing_envelope_element() {
        // A trailing third element is additive server variance (item 5).
        let body = r#"[{"esvVersion":"1.0"},[{"url":"x/7","dataFileUrls":[{"rawNoiseBits":"x/70"},{"restartTestBits":"x/71"}],"accessToken":"j"}],{"extra":true}]"#;
        let oes = parse_registration_response(body).unwrap();
        assert_eq!(oes.len(), 1);
        assert_eq!(oes[0].ea_id, "7");
    }

    // ── Item 6: fail-closed data-file slots ───────────────────────────

    /// A well-formed one-OE body with `slots` spliced in for the dataFileUrls.
    fn one_oe_with_slots(slots: &str) -> String {
        format!(
            r#"[{{"esvVersion":"1.0"}},[{{"url":"x/7","dataFileUrls":{slots},"accessToken":"j"}}]]"#
        )
    }

    #[test]
    fn parse_rejects_absent_data_file_urls() {
        let body = r#"[{"esvVersion":"1.0"},[{"url":"x/7","accessToken":"j"}]]"#;
        let err = parse_registration_response(body).unwrap_err();
        assert!(err.contains("dataFileUrls"), "{err}");
    }

    #[test]
    fn parse_rejects_object_shaped_data_file_urls() {
        let body = one_oe_with_slots(r#"{"rawNoiseBits":"x/70"}"#);
        let err = parse_registration_response(&body).unwrap_err();
        assert!(err.contains("not an array"), "{err}");
    }

    #[test]
    fn parse_rejects_empty_data_file_urls() {
        let body = one_oe_with_slots("[]");
        let err = parse_registration_response(&body).unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn parse_rejects_missing_raw_noise_slot() {
        // restart present but no raw-noise slot → fail closed.
        let body = one_oe_with_slots(r#"[{"restartTestBits":"x/71"}]"#);
        let err = parse_registration_response(&body).unwrap_err();
        assert!(err.contains("rawNoiseBits"), "{err}");
    }

    #[test]
    fn parse_rejects_duplicate_raw_noise_bits() {
        // Two rawNoiseBits slots → typed error, no last-wins.
        let body = one_oe_with_slots(
            r#"[{"rawNoiseBits":"x/70"},{"restartTestBits":"x/71"},{"rawNoiseBits":"x/72"}]"#,
        );
        let err = parse_registration_response(&body).unwrap_err();
        assert!(err.contains("duplicate `rawNoiseBits`"), "{err}");
    }

    // ── Fix 5: duplicate conditionedBits sequencePosition ─────────────

    #[test]
    fn parse_rejects_duplicate_conditioned_sequence_position() {
        // Two conditionedBits slots at the same sequence position → typed
        // error, no silent duplicate.
        let body = one_oe_with_slots(
            r#"[{"rawNoiseBits":"x/70"},{"restartTestBits":"x/71"},{"conditionedBits":"x/90","sequencePosition":1},{"conditionedBits":"x/91","sequencePosition":1}]"#,
        );
        let err = parse_registration_response(&body).unwrap_err();
        assert!(err.contains("duplicate `conditionedBits`"), "{err}");
        assert!(err.contains("sequence position 1"), "{err}");
    }

    #[test]
    fn parse_accepts_distinct_conditioned_sequence_positions() {
        // Two conditionedBits slots at DIFFERENT positions are fine.
        let body = one_oe_with_slots(
            r#"[{"rawNoiseBits":"x/70"},{"restartTestBits":"x/71"},{"conditionedBits":"x/90","sequencePosition":1},{"conditionedBits":"x/91","sequencePosition":2}]"#,
        );
        let oes = parse_registration_response(&body).unwrap();
        assert_eq!(oes[0].conditioned.len(), 2);
        assert_eq!(oes[0].conditioned[0].sequence_position, 1);
        assert_eq!(oes[0].conditioned[1].sequence_position, 2);
    }

    // ── Fix 8: restartTestBits is tolerated-absent again ──────────────

    #[test]
    fn parse_tolerates_missing_restart_slot() {
        // rawNoiseBits present, no restartTestBits → parses Ok with restart
        // = None (DEFERRED-VERIFY at the attended smoke).
        let body = one_oe_with_slots(r#"[{"rawNoiseBits":"x/70"}]"#);
        let oes = parse_registration_response(&body).unwrap();
        assert_eq!(oes.len(), 1);
        assert_eq!(oes[0].raw_noise.as_ref().unwrap().id, "70");
        assert!(oes[0].restart.is_none());
    }

    // ── Item 7: url_tail trailing-slash handling ──────────────────────

    #[test]
    fn url_tail_trims_trailing_slash_and_yields_id() {
        assert_eq!(url_tail("x/dataFiles/11/").unwrap(), "11");
        assert_eq!(url_tail("x/dataFiles/11").unwrap(), "11");
        assert_eq!(url_tail("11").unwrap(), "11");
    }

    #[test]
    fn url_tail_empty_after_trim_is_typed_error() {
        assert!(url_tail("/").is_err());
        assert!(url_tail("").is_err());
        assert!(url_tail("///").is_err());
    }

    #[test]
    fn valid_registration_serializes() {
        // Sanity: the shared valid fixture builds a wire body.
        assert!(valid_registration().to_wire_json().is_ok());
    }
}
