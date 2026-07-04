//! ESVP §7 certify request builders (ISC-103, ISC-106).
//!
//! Certify is the terminal step of an ESV submission: it binds the
//! registered entropy assessments and their supporting documents to an
//! ACVTS module / operating-environment, requesting the entropy
//! certificate. This module builds the three §7 request bodies — the full
//! submission ([`CertifyRequest`]), the staged-OE append
//! ([`AddOeRequest`], §7.2), and the Public-Use-Document swap
//! ([`UpdatePudRequest`], §7.3) — enforcing at **construction** every rule
//! the server will otherwise reject downstream:
//!
//! - **Exactly one** Entropy Assessment Report **and exactly one** Public
//!   Use Document, **at most one** Data Collection Attestation (server rule
//!   `validation_rules/…/CertifyRequest/…/supportingDocumentTypesCount.json`:
//!   `earTypeCount == 1`, `pudTypeCount == 1`, `dcaTypeCount == 0 || == 1`).
//! - A required ACVTS **`moduleId`** and, per entropy assessment, a required
//!   ACVTS **`oeId`** — a cross-server dependency (the module and OE must be
//!   registered in ACVTS first, §7.1), surfaced as typed required-config
//!   with **no defaults**, mirroring the D2 discipline for the vetted
//!   conditioning `validationNumber`.
//!
//! Because these are enforced up front, a well-formed [`CertifyRequest`]
//! cannot serialize a body the server's supporting-document rule would
//! bounce.
//!
//! # Wire shape and field order
//!
//! Bodies are the ESVP versioned envelope `[{esvVersion}, {payload}]`. The
//! payload field order follows the reference client's `cert_prep`
//! /`cert_prep_add_oe` (`client/request_types/certify_requests.py:54,76`)
//! and `send_post_update_pud`
//! (`client/request_types/supporting_documentation.py:59`), because the
//! shared JSON codec preserves object key order and matching the reference
//! keeps request diffs legible. All ids are integers, so the codec's
//! integer-only number model fits without any float handling.
//!
//! # Protocol sources
//!
//! `Entropy Source Validation Protocol.md` §7 (the property tables and the
//! full/addOE/updatePUD examples) and the reference client's
//! `request_types/certify_requests.py` + `models/entropy_certify_payload.py`.

use acvp_harness::json::{self, JsonValue};

use crate::login;
use crate::registration::OeRegistration;
use crate::supportdocs::{SdType, SupportingDoc};

/// The full-submission certify endpoint — the full server-relative path.
/// See [`crate::login::LOGIN_PATH`] for the host-only-base convention.
/// (ESVP §7.1; reference client `request_types/certify_requests.py:17`.)
pub const CERTIFY_PATH: &str = "/esv/v1/certify";

/// The AddOE certify endpoint (append operating environments to an existing
/// certificate). (ESVP §7.2; reference client
/// `request_types/certify_requests.py:33`.)
pub const CERTIFY_ADD_OE_PATH: &str = "/esv/v1/certify/addOE";

/// The UpdatePUD certify endpoint (attach a new Public Use Document to an
/// existing certificate). (ESVP §7.3; reference client
/// `request_types/supporting_documentation.py:72`.)
pub const CERTIFY_UPDATE_PUD_PATH: &str = "/esv/v1/certify/updatePUD";

/// Whether a certify payload defaults `limitEntropyAssessmentToSingleModule`
/// to true — the reference client's default (`cert_prep`,
/// `request_types/certify_requests.py:61`, "Defaulting to true for now").
pub const DEFAULT_LIMIT_TO_SINGLE_MODULE: bool = true;

// ── Errors ────────────────────────────────────────────────────────────

/// A certify-request construction violation (ISC-103).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertifyError {
    /// The submitter tracking id (`entropyId` / TID) was empty.
    MissingEntropyId,
    /// The required ACVTS `moduleId` was not supplied (non-positive — 0 is
    /// the reference client's unset sentinel). Required config, no default.
    MissingModuleId,
    /// An entropy assessment carried no ACVTS `oeId` (non-positive).
    /// Required config, no default. Carries the offending `eaId`.
    MissingOeId {
        /// The `eaId` of the assessment missing its `oeId`.
        ea_id: i64,
    },
    /// An entropy assessment carried a non-positive `eaId`.
    InvalidEaId {
        /// The rejected `eaId`.
        ea_id: i64,
    },
    /// The certify request referenced no entropy assessments (at least one
    /// is required).
    NoAssessments,
    /// The count of Entropy Assessment Report supporting documents was not
    /// exactly one.
    WrongEarCount {
        /// The observed count.
        count: usize,
    },
    /// The count of Public Use Document supporting documents was not exactly
    /// one.
    WrongPudCount {
        /// The observed count.
        count: usize,
    },
    /// More than one Data Collection Attestation supporting document was
    /// supplied (at most one is permitted).
    TooManyAttestations {
        /// The observed count.
        count: usize,
    },
    /// An AddOE / UpdatePUD request supplied no `entropyCertificate`.
    MissingEntropyCertificate,
    /// An UpdatePUD request's supporting document was not a Public Use
    /// Document.
    NotAPublicUseDocument {
        /// The wrong type actually supplied.
        sd_type: SdType,
    },
    /// An [`OeRegistration`]'s `eaId` was not a base-ten integer, so it
    /// cannot fill the integer `eaId` wire field.
    EaIdNotNumeric {
        /// The non-numeric `eaId` string.
        ea_id: String,
    },
    /// Two entropy-assessment references shared an `eaId`. Every EaID must be
    /// distinct (server rule
    /// `Rules/CertifyRequest/Entropyassessmentreference/eaIdIsDistinct.json`,
    /// imported by both `new.json` and `addOe.json`).
    DuplicateEaId {
        /// The `eaId` that appeared more than once.
        ea_id: i64,
    },
    /// A certify was built for a **non-IID** assessment with no restart-test
    /// data-file upload recorded. SP 800-90B requires restart-test data for a
    /// non-IID assessment, so a certify referencing it must have a restart
    /// upload. Carries the offending `eaId`.
    MissingRestartUpload {
        /// The `eaId` of the non-IID assessment missing its restart upload.
        ea_id: i64,
    },
}

impl core::fmt::Display for CertifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingEntropyId => f.write_str("certify request requires a non-empty entropyId"),
            Self::MissingModuleId => {
                f.write_str("certify request requires an ACVTS moduleId (positive, no default)")
            }
            Self::MissingOeId { ea_id } => write!(
                f,
                "entropy assessment eaId {ea_id} requires an ACVTS oeId (positive, no default)"
            ),
            Self::InvalidEaId { ea_id } => {
                write!(f, "entropy assessment eaId {ea_id} is not positive")
            }
            Self::NoAssessments => {
                f.write_str("certify request requires at least one entropy assessment")
            }
            Self::WrongEarCount { count } => write!(
                f,
                "certify request requires exactly one EntropyAssessmentReport, got {count}"
            ),
            Self::WrongPudCount { count } => write!(
                f,
                "certify request requires exactly one PublicUseDocument, got {count}"
            ),
            Self::TooManyAttestations { count } => write!(
                f,
                "certify request permits at most one DataCollectionAttestation, got {count}"
            ),
            Self::MissingEntropyCertificate => {
                f.write_str("request requires a non-empty entropyCertificate")
            }
            Self::NotAPublicUseDocument { sd_type } => write!(
                f,
                "updatePUD requires a PublicUseDocument, got {}",
                sd_type.wire_str()
            ),
            Self::EaIdNotNumeric { ea_id } => {
                write!(f, "registration eaId {ea_id:?} is not a base-ten integer")
            }
            Self::DuplicateEaId { ea_id } => write!(
                f,
                "certify request requires distinct eaIds; eaId {ea_id} appears more than once"
            ),
            Self::MissingRestartUpload { ea_id } => write!(
                f,
                "non-IID entropy assessment eaId {ea_id} requires a restart-test data-file upload before certify"
            ),
        }
    }
}

impl std::error::Error for CertifyError {}

// ── Entropy-assessment reference ──────────────────────────────────────

/// One entropy-assessment reference in a certify request: the ESV `eaId`,
/// the ACVTS `oeId`, and the scoped JWT authorizing the reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifyAssessment {
    /// The entropy-assessment id from registration.
    pub ea_id: i64,
    /// The ACVTS operating-environment id (cross-server; must be positive).
    pub oe_id: i64,
    /// The scoped JWT with claims to this `eaId`.
    pub access_token: String,
}

impl CertifyAssessment {
    /// A plain reference. Validation (positive `eaId`/`oeId`) is performed
    /// when the enclosing certify request is constructed, so all violations
    /// surface together.
    #[must_use]
    pub fn new(ea_id: i64, oe_id: i64, access_token: &str) -> Self {
        Self {
            ea_id,
            oe_id,
            access_token: access_token.to_string(),
        }
    }

    /// Bridge from a registration result: take the per-OE `eaId` and scoped
    /// token from an [`OeRegistration`] and pair them with the ACVTS `oeId`
    /// (which comes from ACVTS, not from the ESV registration).
    ///
    /// # Errors
    /// [`CertifyError::EaIdNotNumeric`] if the registration's `eaId` string
    /// is not a base-ten integer.
    pub fn from_registration(reg: &OeRegistration, oe_id: i64) -> Result<Self, CertifyError> {
        let ea_id = reg
            .ea_id
            .parse::<i64>()
            .map_err(|_| CertifyError::EaIdNotNumeric {
                ea_id: reg.ea_id.clone(),
            })?;
        Ok(Self::new(ea_id, oe_id, &reg.access_token))
    }

    /// This reference as a wire object `{eaId, oeId, accessToken}`.
    fn to_json(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("eaId".to_string(), JsonValue::Number(self.ea_id)),
            ("oeId".to_string(), JsonValue::Number(self.oe_id)),
            (
                "accessToken".to_string(),
                JsonValue::String(self.access_token.clone()),
            ),
        ])
    }
}

// ── Shared constraint checks ──────────────────────────────────────────

/// Enforce the entropy-assessment preconditions: at least one assessment,
/// each with a positive `eaId` and a positive ACVTS `oeId`, and all `eaId`s
/// **distinct** (server rule
/// `Rules/CertifyRequest/Entropyassessmentreference/eaIdIsDistinct.json`,
/// imported by both `new.json` and `addOe.json`).
fn check_assessments(assessments: &[CertifyAssessment]) -> Result<(), CertifyError> {
    if assessments.is_empty() {
        return Err(CertifyError::NoAssessments);
    }
    for (i, a) in assessments.iter().enumerate() {
        if a.ea_id <= 0 {
            return Err(CertifyError::InvalidEaId { ea_id: a.ea_id });
        }
        if a.oe_id <= 0 {
            return Err(CertifyError::MissingOeId { ea_id: a.ea_id });
        }
        if assessments.iter().take(i).any(|b| b.ea_id == a.ea_id) {
            return Err(CertifyError::DuplicateEaId { ea_id: a.ea_id });
        }
    }
    Ok(())
}

/// Certify precondition (SP 800-90B restart-test rule): a **non-IID**
/// assessment must have a restart-test data file uploaded before certify; an
/// IID assessment (`iid_claim == true`) has no restart requirement.
///
/// The iid claim and the restart-upload record are **not** carried by
/// [`CertifyAssessment`] (whose currency is `eaId`/`oeId`/token), so they are
/// supplied explicitly: the orchestrator reads `iid_claim` from the
/// [`crate::registration::EntropyRegistration`] and `restart_uploaded` from
/// the session's recorded uploads (a [`crate::session::Slot::Restart`]
/// [`crate::session::UploadedFile`] for this `ea_id`). This guard was
/// deliberately removed from the registration-response *parser*
/// (`restartTestBits` is tolerated-absent there, since the demo server's exact
/// slot set is unproven) and re-established here — the certify-precondition
/// layer, where both facts are known — matching the submission-lifecycle
/// "certify precondition check" step in the design.
///
/// # Errors
/// [`CertifyError::MissingRestartUpload`] when `!iid_claim && !restart_uploaded`.
pub fn check_non_iid_restart_upload(
    ea_id: i64,
    iid_claim: bool,
    restart_uploaded: bool,
) -> Result<(), CertifyError> {
    if !iid_claim && !restart_uploaded {
        return Err(CertifyError::MissingRestartUpload { ea_id });
    }
    Ok(())
}

/// Enforce the supporting-document type constraints: exactly one EAR,
/// exactly one PUD, at most one DCA (RBG-report / Other unconstrained on the
/// 90B certify path).
fn check_supporting_doc_constraints(docs: &[SupportingDoc]) -> Result<(), CertifyError> {
    let count_of = |t: SdType| docs.iter().filter(|d| d.sd_type == t).count();
    let ear = count_of(SdType::EntropyAssessmentReport);
    if ear != 1 {
        return Err(CertifyError::WrongEarCount { count: ear });
    }
    let pud = count_of(SdType::PublicUseDocument);
    if pud != 1 {
        return Err(CertifyError::WrongPudCount { count: pud });
    }
    let dca = count_of(SdType::DataCollectionAttestation);
    if dca > 1 {
        return Err(CertifyError::TooManyAttestations { count: dca });
    }
    Ok(())
}

/// A supporting-document reference as a wire object `{sdId, accessToken}`
/// (the `sdType` is used only for the constraint check, never sent here).
fn doc_to_json(doc: &SupportingDoc) -> JsonValue {
    JsonValue::Object(vec![
        ("sdId".to_string(), JsonValue::Number(doc.sd_id)),
        (
            "accessToken".to_string(),
            JsonValue::String(doc.access_token.clone()),
        ),
    ])
}

/// Wrap a payload object in the ESVP two-element versioned envelope and
/// pretty-print it (matching the login/registration builders).
fn esv_envelope(payload: Vec<(String, JsonValue)>) -> String {
    let body = JsonValue::Array(vec![
        JsonValue::Object(vec![(
            "esvVersion".to_string(),
            JsonValue::String(login::ESV_VERSION.to_string()),
        )]),
        JsonValue::Object(payload),
    ]);
    json::to_pretty_string(&body)
}

/// Build the `supportingDocumentation` and `entropyAssessments` array
/// entries shared by the full and AddOE payloads.
fn docs_and_assessments_fields(
    docs: &[SupportingDoc],
    assessments: &[CertifyAssessment],
) -> (JsonValue, JsonValue) {
    let sd = JsonValue::Array(docs.iter().map(doc_to_json).collect());
    let ea = JsonValue::Array(assessments.iter().map(CertifyAssessment::to_json).collect());
    (sd, ea)
}

// ── Full submission (§7.1) ────────────────────────────────────────────

/// A full certify submission (ESVP §7.1).
///
/// Construct with [`Self::new`], which enforces every precondition; the
/// resulting request always serializes a body the server's supporting-doc
/// rule accepts. `vendorId` is optional (see [`Self::with_vendor_id`]);
/// `limitEntropyAssessmentToSingleModule` defaults to
/// [`DEFAULT_LIMIT_TO_SINGLE_MODULE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifyRequest {
    entropy_id: String,
    module_id: i64,
    vendor_id: Option<i64>,
    limit_to_single_module: bool,
    assessments: Vec<CertifyAssessment>,
    docs: Vec<SupportingDoc>,
}

impl CertifyRequest {
    /// Build a full certify submission, enforcing all §7.1 preconditions.
    ///
    /// # Errors
    /// A [`CertifyError`] for the first violated precondition: empty
    /// `entropyId`, non-positive `moduleId`, no assessments, a non-positive
    /// `eaId`/`oeId`, or the EAR/PUD/DCA count constraints.
    pub fn new(
        entropy_id: &str,
        module_id: i64,
        assessments: Vec<CertifyAssessment>,
        docs: Vec<SupportingDoc>,
    ) -> Result<Self, CertifyError> {
        if entropy_id.is_empty() {
            return Err(CertifyError::MissingEntropyId);
        }
        if module_id <= 0 {
            return Err(CertifyError::MissingModuleId);
        }
        check_assessments(&assessments)?;
        check_supporting_doc_constraints(&docs)?;
        Ok(Self {
            entropy_id: entropy_id.to_string(),
            module_id,
            vendor_id: None,
            limit_to_single_module: DEFAULT_LIMIT_TO_SINGLE_MODULE,
            assessments,
            docs,
        })
    }

    /// Attach the ACVTS `vendorId`. The reference client always sends one
    /// (`run.example.json` carries `vendorId`), but the §7.1 property table
    /// does not document it, so it is optional here — resolve at the
    /// attended demo smoke, like the D2 `validationNumber`.
    #[must_use]
    pub fn with_vendor_id(mut self, vendor_id: i64) -> Self {
        self.vendor_id = Some(vendor_id);
        self
    }

    /// Override `limitEntropyAssessmentToSingleModule` (default
    /// [`DEFAULT_LIMIT_TO_SINGLE_MODULE`]).
    #[must_use]
    pub fn with_limit_to_single_module(mut self, limit: bool) -> Self {
        self.limit_to_single_module = limit;
        self
    }

    /// The full server-relative resource path.
    #[must_use]
    pub fn path(&self) -> &'static str {
        CERTIFY_PATH
    }

    /// Serialize the request to its wire body. Infallible: every field was
    /// validated at construction and all numbers are integers.
    #[must_use]
    pub fn to_wire_json(&self) -> String {
        let (sd, ea) = docs_and_assessments_fields(&self.docs, &self.assessments);
        let mut payload = vec![
            (
                "entropyId".to_string(),
                JsonValue::String(self.entropy_id.clone()),
            ),
            (
                "limitEntropyAssessmentToSingleModule".to_string(),
                JsonValue::Bool(self.limit_to_single_module),
            ),
            ("moduleId".to_string(), JsonValue::Number(self.module_id)),
        ];
        if let Some(v) = self.vendor_id {
            payload.push(("vendorId".to_string(), JsonValue::Number(v)));
        }
        payload.push(("supportingDocumentation".to_string(), sd));
        payload.push(("entropyAssessments".to_string(), ea));
        esv_envelope(payload)
    }
}

// ── AddOE (§7.2) ──────────────────────────────────────────────────────

/// An AddOE certify request (ESVP §7.2): append operating environments to an
/// existing certificate. Like a full submission, but `moduleId`/`vendorId`
/// are replaced by the existing `entropyCertificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOeRequest {
    entropy_id: String,
    entropy_certificate: String,
    limit_to_single_module: bool,
    assessments: Vec<CertifyAssessment>,
    docs: Vec<SupportingDoc>,
}

impl AddOeRequest {
    /// Build an AddOE request, enforcing the same assessment and
    /// supporting-doc preconditions as a full submission plus a non-empty
    /// `entropyCertificate`.
    ///
    /// # Errors
    /// A [`CertifyError`] for the first violated precondition.
    pub fn new(
        entropy_id: &str,
        entropy_certificate: &str,
        assessments: Vec<CertifyAssessment>,
        docs: Vec<SupportingDoc>,
    ) -> Result<Self, CertifyError> {
        if entropy_id.is_empty() {
            return Err(CertifyError::MissingEntropyId);
        }
        if entropy_certificate.is_empty() {
            return Err(CertifyError::MissingEntropyCertificate);
        }
        check_assessments(&assessments)?;
        check_supporting_doc_constraints(&docs)?;
        Ok(Self {
            entropy_id: entropy_id.to_string(),
            entropy_certificate: entropy_certificate.to_string(),
            limit_to_single_module: DEFAULT_LIMIT_TO_SINGLE_MODULE,
            assessments,
            docs,
        })
    }

    /// Override `limitEntropyAssessmentToSingleModule` (default
    /// [`DEFAULT_LIMIT_TO_SINGLE_MODULE`]).
    #[must_use]
    pub fn with_limit_to_single_module(mut self, limit: bool) -> Self {
        self.limit_to_single_module = limit;
        self
    }

    /// The full server-relative resource path.
    #[must_use]
    pub fn path(&self) -> &'static str {
        CERTIFY_ADD_OE_PATH
    }

    /// Serialize the request to its wire body. Infallible (see
    /// [`CertifyRequest::to_wire_json`]).
    #[must_use]
    pub fn to_wire_json(&self) -> String {
        let (sd, ea) = docs_and_assessments_fields(&self.docs, &self.assessments);
        let payload = vec![
            (
                "entropyId".to_string(),
                JsonValue::String(self.entropy_id.clone()),
            ),
            (
                "limitEntropyAssessmentToSingleModule".to_string(),
                JsonValue::Bool(self.limit_to_single_module),
            ),
            (
                "entropyCertificate".to_string(),
                JsonValue::String(self.entropy_certificate.clone()),
            ),
            ("supportingDocumentation".to_string(), sd),
            ("entropyAssessments".to_string(), ea),
        ];
        esv_envelope(payload)
    }
}

// ── UpdatePUD (§7.3) ──────────────────────────────────────────────────

/// An UpdatePUD certify request (ESVP §7.3): attach a new Public Use
/// Document to an existing certificate. Free (no cost recovery). The single
/// supporting document must be a Public Use Document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePudRequest {
    entropy_id: String,
    entropy_certificate: String,
    doc: SupportingDoc,
}

impl UpdatePudRequest {
    /// Build an UpdatePUD request.
    ///
    /// # Errors
    /// [`CertifyError::MissingEntropyId`] / [`CertifyError::MissingEntropyCertificate`]
    /// for empty ids; [`CertifyError::NotAPublicUseDocument`] if `doc` is
    /// not a Public Use Document.
    pub fn new(
        entropy_id: &str,
        entropy_certificate: &str,
        doc: SupportingDoc,
    ) -> Result<Self, CertifyError> {
        if entropy_id.is_empty() {
            return Err(CertifyError::MissingEntropyId);
        }
        if entropy_certificate.is_empty() {
            return Err(CertifyError::MissingEntropyCertificate);
        }
        if doc.sd_type != SdType::PublicUseDocument {
            return Err(CertifyError::NotAPublicUseDocument {
                sd_type: doc.sd_type,
            });
        }
        Ok(Self {
            entropy_id: entropy_id.to_string(),
            entropy_certificate: entropy_certificate.to_string(),
            doc,
        })
    }

    /// The full server-relative resource path.
    #[must_use]
    pub fn path(&self) -> &'static str {
        CERTIFY_UPDATE_PUD_PATH
    }

    /// Serialize the request to its wire body. Infallible.
    #[must_use]
    pub fn to_wire_json(&self) -> String {
        let payload = vec![
            (
                "entropyCertificate".to_string(),
                JsonValue::String(self.entropy_certificate.clone()),
            ),
            (
                "entropyId".to_string(),
                JsonValue::String(self.entropy_id.clone()),
            ),
            ("supportingDocument".to_string(), doc_to_json(&self.doc)),
        ];
        esv_envelope(payload)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::registration::{DataFileRef, OeRegistration};

    fn doc(sd_id: i64, sd_type: SdType) -> SupportingDoc {
        SupportingDoc {
            sd_id,
            sd_type,
            access_token: format!("tok-{sd_id}"),
        }
    }

    fn ear() -> SupportingDoc {
        doc(1, SdType::EntropyAssessmentReport)
    }
    fn pud() -> SupportingDoc {
        doc(2, SdType::PublicUseDocument)
    }
    fn one_assessment() -> Vec<CertifyAssessment> {
        vec![CertifyAssessment::new(11, 7, "ea-tok")]
    }
    fn valid_docs() -> Vec<SupportingDoc> {
        vec![ear(), pud()]
    }

    // ── Full submission happy path + wire shape ───────────────────────

    #[test]
    fn full_certify_builds_and_serializes() {
        let req = CertifyRequest::new("TID-0001", 3, one_assessment(), valid_docs())
            .unwrap()
            .with_vendor_id(5);
        assert_eq!(req.path(), "/esv/v1/certify");
        let body = req.to_wire_json();
        let v = json::parse(&body).unwrap();
        let payload = v.as_array().unwrap().get(1).unwrap();
        assert_eq!(payload.get("entropyId").unwrap().as_str(), Some("TID-0001"));
        assert_eq!(payload.get("moduleId").unwrap().as_i64(), Some(3));
        assert_eq!(payload.get("vendorId").unwrap().as_i64(), Some(5));
        assert_eq!(
            payload
                .get("limitEntropyAssessmentToSingleModule")
                .unwrap()
                .as_bool(),
            Some(true)
        );
        let sd = payload
            .get("supportingDocumentation")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(sd.len(), 2);
        // sdType is NOT on the wire — only sdId + accessToken.
        assert!(sd[0].get("sdType").is_none());
        assert_eq!(sd[0].get("sdId").unwrap().as_i64(), Some(1));
        let ea = payload
            .get("entropyAssessments")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(ea[0].get("eaId").unwrap().as_i64(), Some(11));
        assert_eq!(ea[0].get("oeId").unwrap().as_i64(), Some(7));
    }

    #[test]
    fn full_certify_omits_vendor_id_when_unset() {
        let req = CertifyRequest::new("T", 3, one_assessment(), valid_docs()).unwrap();
        let v = json::parse(&req.to_wire_json()).unwrap();
        let payload = &v.as_array().unwrap()[1];
        assert!(payload.get("vendorId").is_none());
    }

    // ── Required-config preconditions (moduleId + oeId) ───────────────

    #[test]
    fn full_certify_requires_module_id() {
        assert_eq!(
            CertifyRequest::new("T", 0, one_assessment(), valid_docs()),
            Err(CertifyError::MissingModuleId)
        );
        assert_eq!(
            CertifyRequest::new("T", -1, one_assessment(), valid_docs()),
            Err(CertifyError::MissingModuleId)
        );
    }

    #[test]
    fn full_certify_requires_oe_id_per_assessment() {
        let assessments = vec![CertifyAssessment::new(11, 0, "t")];
        assert_eq!(
            CertifyRequest::new("T", 3, assessments, valid_docs()),
            Err(CertifyError::MissingOeId { ea_id: 11 })
        );
    }

    #[test]
    fn full_certify_requires_entropy_id_and_assessments() {
        assert_eq!(
            CertifyRequest::new("", 3, one_assessment(), valid_docs()),
            Err(CertifyError::MissingEntropyId)
        );
        assert_eq!(
            CertifyRequest::new("T", 3, vec![], valid_docs()),
            Err(CertifyError::NoAssessments)
        );
    }

    // ── Exactly-one / at-most-one supporting-doc constraints ──────────

    #[test]
    fn full_certify_requires_exactly_one_ear() {
        // Zero EARs.
        assert_eq!(
            CertifyRequest::new("T", 3, one_assessment(), vec![pud()]),
            Err(CertifyError::WrongEarCount { count: 0 })
        );
        // Two EARs.
        assert_eq!(
            CertifyRequest::new(
                "T",
                3,
                one_assessment(),
                vec![ear(), doc(9, SdType::EntropyAssessmentReport), pud()]
            ),
            Err(CertifyError::WrongEarCount { count: 2 })
        );
    }

    #[test]
    fn full_certify_requires_exactly_one_pud() {
        assert_eq!(
            CertifyRequest::new("T", 3, one_assessment(), vec![ear()]),
            Err(CertifyError::WrongPudCount { count: 0 })
        );
        assert_eq!(
            CertifyRequest::new(
                "T",
                3,
                one_assessment(),
                vec![ear(), pud(), doc(9, SdType::PublicUseDocument)]
            ),
            Err(CertifyError::WrongPudCount { count: 2 })
        );
    }

    #[test]
    fn full_certify_allows_at_most_one_attestation() {
        // One DCA is fine.
        let ok = CertifyRequest::new(
            "T",
            3,
            one_assessment(),
            vec![ear(), pud(), doc(3, SdType::DataCollectionAttestation)],
        );
        assert!(ok.is_ok());
        // Two DCAs is a violation.
        assert_eq!(
            CertifyRequest::new(
                "T",
                3,
                one_assessment(),
                vec![
                    ear(),
                    pud(),
                    doc(3, SdType::DataCollectionAttestation),
                    doc(4, SdType::DataCollectionAttestation)
                ]
            ),
            Err(CertifyError::TooManyAttestations { count: 2 })
        );
    }

    #[test]
    fn full_certify_allows_any_number_of_other_and_rbg() {
        let ok = CertifyRequest::new(
            "T",
            3,
            one_assessment(),
            vec![
                ear(),
                pud(),
                doc(3, SdType::Other),
                doc(4, SdType::Other),
                doc(5, SdType::RandomBitGeneratorReport),
            ],
        );
        assert!(ok.is_ok(), "{ok:?}");
    }

    // ── Fix 4: distinct eaIds (eaIdIsDistinct) ────────────────────────

    #[test]
    fn full_certify_requires_distinct_ea_ids() {
        // Two assessments sharing eaId 11 → typed error at construction.
        let dup = vec![
            CertifyAssessment::new(11, 7, "t1"),
            CertifyAssessment::new(11, 8, "t2"),
        ];
        assert_eq!(
            CertifyRequest::new("T", 3, dup, valid_docs()),
            Err(CertifyError::DuplicateEaId { ea_id: 11 })
        );
        // Distinct eaIds are fine.
        let ok = vec![
            CertifyAssessment::new(11, 7, "t1"),
            CertifyAssessment::new(22, 8, "t2"),
        ];
        assert!(CertifyRequest::new("T", 3, ok, valid_docs()).is_ok());
    }

    #[test]
    fn add_oe_requires_distinct_ea_ids() {
        // The same rule applies on the AddOE path.
        let dup = vec![
            CertifyAssessment::new(5, 7, "t1"),
            CertifyAssessment::new(5, 8, "t2"),
        ];
        assert_eq!(
            AddOeRequest::new("T", "E1", dup, valid_docs()),
            Err(CertifyError::DuplicateEaId { ea_id: 5 })
        );
    }

    // ── Fix 7: non-IID restart-upload certify precondition ────────────

    #[test]
    fn non_iid_assessment_requires_a_restart_upload_before_certify() {
        // Non-IID (iid_claim = false) with no restart upload → typed error.
        assert_eq!(
            check_non_iid_restart_upload(11, false, false),
            Err(CertifyError::MissingRestartUpload { ea_id: 11 })
        );
        // Non-IID with a restart upload recorded → ok.
        assert_eq!(check_non_iid_restart_upload(11, false, true), Ok(()));
        // An IID assessment has no restart requirement, upload or not.
        assert_eq!(check_non_iid_restart_upload(11, true, false), Ok(()));
        assert_eq!(check_non_iid_restart_upload(11, true, true), Ok(()));
    }

    // ── AddOE ─────────────────────────────────────────────────────────

    #[test]
    fn add_oe_builds_with_certificate_not_module() {
        let req = AddOeRequest::new("T", "E999", one_assessment(), valid_docs()).unwrap();
        assert_eq!(req.path(), "/esv/v1/certify/addOE");
        let v = json::parse(&req.to_wire_json()).unwrap();
        let payload = &v.as_array().unwrap()[1];
        assert_eq!(
            payload.get("entropyCertificate").unwrap().as_str(),
            Some("E999")
        );
        assert!(payload.get("moduleId").is_none());
        // Same exactly-one constraints apply.
        assert!(payload.get("entropyAssessments").is_some());
    }

    #[test]
    fn add_oe_requires_certificate_and_constraints() {
        assert_eq!(
            AddOeRequest::new("T", "", one_assessment(), valid_docs()),
            Err(CertifyError::MissingEntropyCertificate)
        );
        assert_eq!(
            AddOeRequest::new("T", "E1", one_assessment(), vec![ear()]),
            Err(CertifyError::WrongPudCount { count: 0 })
        );
    }

    // ── UpdatePUD ─────────────────────────────────────────────────────

    #[test]
    fn update_pud_requires_a_pud_document() {
        let req = UpdatePudRequest::new("T", "E999", pud()).unwrap();
        assert_eq!(req.path(), "/esv/v1/certify/updatePUD");
        let v = json::parse(&req.to_wire_json()).unwrap();
        let payload = &v.as_array().unwrap()[1];
        assert_eq!(
            payload.get("entropyCertificate").unwrap().as_str(),
            Some("E999")
        );
        assert_eq!(
            payload
                .get("supportingDocument")
                .unwrap()
                .get("sdId")
                .unwrap()
                .as_i64(),
            Some(2)
        );
    }

    #[test]
    fn update_pud_rejects_non_pud() {
        assert_eq!(
            UpdatePudRequest::new("T", "E1", ear()),
            Err(CertifyError::NotAPublicUseDocument {
                sd_type: SdType::EntropyAssessmentReport
            })
        );
        assert_eq!(
            UpdatePudRequest::new("T", "", pud()),
            Err(CertifyError::MissingEntropyCertificate)
        );
    }

    // ── CertifyAssessment::from_registration bridge ───────────────────

    #[test]
    fn certify_assessment_from_registration_parses_ea_id() {
        let reg = OeRegistration {
            url: "https://h/esv/v1/entropyAssessments/11".to_string(),
            ea_id: "11".to_string(),
            raw_noise: Some(DataFileRef {
                url: "u".to_string(),
                id: "1".to_string(),
            }),
            restart: Some(DataFileRef {
                url: "u".to_string(),
                id: "2".to_string(),
            }),
            conditioned: vec![],
            access_token: "oe-tok".to_string(),
        };
        let a = CertifyAssessment::from_registration(&reg, 7).unwrap();
        assert_eq!(a.ea_id, 11);
        assert_eq!(a.oe_id, 7);
        assert_eq!(a.access_token, "oe-tok");
    }

    #[test]
    fn certify_assessment_from_registration_rejects_non_numeric_ea_id() {
        let reg = OeRegistration {
            url: "https://h/x/abc".to_string(),
            ea_id: "abc".to_string(),
            raw_noise: None,
            restart: None,
            conditioned: vec![],
            access_token: "t".to_string(),
        };
        assert_eq!(
            CertifyAssessment::from_registration(&reg, 7),
            Err(CertifyError::EaIdNotNumeric {
                ea_id: "abc".to_string()
            })
        );
    }
}
