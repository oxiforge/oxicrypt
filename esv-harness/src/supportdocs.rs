//! ESVP §6.2 supporting-documentation upload: the `sdType` classification,
//! the PDF-only construction guard, and the `multipart/form-data` request
//! builder (ISC-102).
//!
//! Supporting documents (the Entropy Assessment Report, the Public Use
//! Document, an optional Data Collection Attestation, and any number of
//! Other documents) justify the non-testable SP 800-90B requirements. The
//! harness sends **PDF only**, per ESVP §6.2, which supersedes the §1
//! "Word or PDF" mention. Nothing here exercises what the server
//! accepts; the in-tree guard proves only what this crate refuses to
//! send. The upload is `multipart/form-data`: an `sdFile` binary part,
//! an `sdType` field, and an optional `sdComments` field — the same
//! request shape as a data-file upload, serialized by the one shared
//! [`crate::datafiles::serialize_multipart`] encoder.
//!
//! # PDF enforcement — a fail-closed addition
//!
//! The NIST reference client does **not** validate PDF-ness at all: it
//! opens whatever file it is handed and hard-codes the part's content type
//! to `application/pdf` (`client/request_types/supporting_documentation.py`);
//! it checks neither the `.pdf` extension nor the file's magic bytes. This
//! harness fails closed instead — [`SupportingDocUpload::new`] refuses any
//! payload that does not begin with the PDF signature `%PDF-` (a document's
//! bytes, not its name, decide whether it is a PDF), so a non-PDF can never
//! reach the wire. (The spec's §6.2 `.pdf` extension is a naming
//! convention; the magic-byte check is the stronger, content-authoritative
//! guard.)
//!
//! # Protocol sources
//!
//! Endpoint path, part/field names, and the `sdType` wire strings are
//! transcribed from the ESV protocol specification §6.2 and the
//! reference client
//! (`client/request_types/supporting_documentation.py`,
//! `client/jsons/run.example.json`).

use acvp_harness::json::{self, JsonValue};

use crate::datafiles::{MultipartPart, serialize_multipart};

/// The supporting-documentation endpoint — the full server-relative path.
/// See [`crate::login::LOGIN_PATH`] for the host-only-base convention.
/// (reference client `request_types/supporting_documentation.py`.)
pub const SUPPORTING_DOC_PATH: &str = "/esv/v1/supportingDocumentation";

/// The multipart part name of the PDF binary payload (reference client
/// `request_types/supporting_documentation.py`).
pub const SD_FILE_PART_NAME: &str = "sdFile";

/// The multipart text-field name carrying the document classification
/// (reference client `request_types/supporting_documentation.py`).
pub const SD_TYPE_FIELD: &str = "sdType";

/// The multipart text-field name carrying the optional free-text comment
/// (reference client `request_types/supporting_documentation.py`).
pub const SD_COMMENTS_FIELD: &str = "sdComments";

/// The `Content-Type` of the `sdFile` part — PDF only (reference client
/// `request_types/supporting_documentation.py`; ESVP §6.2).
pub const SD_CONTENT_TYPE: &str = "application/pdf";

/// The PDF file signature every conformant PDF begins with (`%PDF-`), used
/// by [`SupportingDocUpload::new`] as the fail-closed content check.
pub const PDF_MAGIC: &[u8] = b"%PDF-";

// ── Document classification ───────────────────────────────────────────

/// The ESVP §6.2 supporting-document type (`sdType`).
///
/// The wire strings are transcribed from the ESV protocol
/// specification §6.2 — the authoritative list — and match the payloads
/// in the reference client's `client/jsons/run.example.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdType {
    /// The Entropy Assessment Report (`"EntropyAssessmentReport"`).
    /// Exactly one is required by a certify request.
    EntropyAssessmentReport,
    /// The Public Use Document (`"PublicUseDocument"`). Exactly one is
    /// required by a certify request; the subject of `updatePUD`.
    PublicUseDocument,
    /// The Data Collection Attestation (`"DataCollectionAttestation"`). At
    /// most one may accompany a certify request.
    DataCollectionAttestation,
    /// The Random Bit Generator Report (`"RandomBitGeneratorReport"`).
    /// Required only on the (out-of-scope) 90C RBG certify path.
    RandomBitGeneratorReport,
    /// Any other supporting document (`"Other"`). A certify request may
    /// carry any number.
    Other,
}

impl SdType {
    /// The exact ESVP wire string for this type.
    #[must_use]
    pub fn wire_str(self) -> &'static str {
        match self {
            Self::EntropyAssessmentReport => "EntropyAssessmentReport",
            Self::PublicUseDocument => "PublicUseDocument",
            Self::DataCollectionAttestation => "DataCollectionAttestation",
            Self::RandomBitGeneratorReport => "RandomBitGeneratorReport",
            Self::Other => "Other",
        }
    }

    /// Parse an `sdType` wire string back into a variant, for reconstructing
    /// a document reference from the session store. Returns `None` for an
    /// unrecognized string (fail closed rather than guess).
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "EntropyAssessmentReport" => Some(Self::EntropyAssessmentReport),
            "PublicUseDocument" => Some(Self::PublicUseDocument),
            "DataCollectionAttestation" => Some(Self::DataCollectionAttestation),
            "RandomBitGeneratorReport" => Some(Self::RandomBitGeneratorReport),
            "Other" => Some(Self::Other),
            _ => None,
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────

/// An error building a supporting-document upload (ISC-102).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportDocError {
    /// The payload does not begin with the PDF signature `%PDF-`, so it is
    /// not a PDF — refused before any request is built.
    NotPdf {
        /// The first bytes actually seen, hex-encoded (up to the signature
        /// length), to aid diagnosis without dumping the whole payload.
        leading_hex: String,
    },
    /// The payload is empty — there is nothing to upload.
    Empty,
}

impl core::fmt::Display for SupportDocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotPdf { leading_hex } => write!(
                f,
                "supporting document is not a PDF: expected leading {:?}, got bytes {leading_hex}",
                core::str::from_utf8(PDF_MAGIC).unwrap_or("%PDF-")
            ),
            Self::Empty => f.write_str("supporting document payload is empty"),
        }
    }
}

impl std::error::Error for SupportDocError {}

/// Hex-encode up to the first [`PDF_MAGIC`] bytes of a payload, for the
/// [`SupportDocError::NotPdf`] diagnostic.
fn leading_hex(bytes: &[u8]) -> String {
    let take = bytes.len().min(PDF_MAGIC.len());
    let head = bytes.get(..take).unwrap_or(bytes);
    let mut out = String::with_capacity(take.saturating_mul(2));
    for b in head {
        out.push(nibble_hex(b >> 4));
        out.push(nibble_hex(b & 0x0f));
    }
    out
}

/// Map a low nibble (0..=15) to its lowercase hex digit.
fn nibble_hex(nib: u8) -> char {
    char::from_digit(u32::from(nib), 16).unwrap_or('0')
}

// ── Upload request builder (ISC-102) ──────────────────────────────────

/// A supporting-document upload request: the classified PDF payload plus an
/// optional comment.
///
/// Build with [`Self::new`], which enforces PDF-ness (see the module docs);
/// add a comment with [`Self::with_comment`]. The request shape is
/// inspected via [`Self::parts`] or serialized to raw multipart bytes via
/// [`Self::to_multipart`] — both fixture-testable with no transport; the
/// live upload is wired at the attended smoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportingDocUpload {
    /// The document classification.
    pub sd_type: SdType,
    /// The uploaded file's name (the `filename` of the `sdFile` part).
    pub filename: String,
    /// The optional free-text comment (the `sdComments` field). `None`
    /// omits the field entirely.
    pub comment: Option<String>,
    /// The raw PDF bytes (guaranteed to begin with [`PDF_MAGIC`]). Private so
    /// the [`Self::new`] `%PDF-` magic-byte guard is the **only** way bytes
    /// enter — a struct-literal or post-construction mutation cannot bypass it.
    /// Read via [`Self::bytes`].
    bytes: Vec<u8>,
}

impl SupportingDocUpload {
    /// Build a supporting-document upload, refusing any non-PDF payload
    /// (a typed error, no request produced).
    ///
    /// # Errors
    /// [`SupportDocError::Empty`] if `bytes` is empty;
    /// [`SupportDocError::NotPdf`] if `bytes` does not begin with the PDF
    /// signature `%PDF-`.
    pub fn new(sd_type: SdType, filename: &str, bytes: Vec<u8>) -> Result<Self, SupportDocError> {
        if bytes.is_empty() {
            return Err(SupportDocError::Empty);
        }
        if !bytes.starts_with(PDF_MAGIC) {
            return Err(SupportDocError::NotPdf {
                leading_hex: leading_hex(&bytes),
            });
        }
        Ok(Self {
            sd_type,
            filename: filename.to_string(),
            comment: None,
            bytes,
        })
    }

    /// Attach a free-text comment (the `sdComments` field). Recommended
    /// especially when updating a Public Use Document (ESVP §7.3).
    #[must_use]
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    /// The raw PDF payload, guaranteed (by [`Self::new`]) to begin with the
    /// PDF signature `%PDF-`. The read-only accessor for the sealed `bytes`
    /// field.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The full server-relative resource path for this upload.
    #[must_use]
    pub fn path(&self) -> &'static str {
        SUPPORTING_DOC_PATH
    }

    /// The ordered logical parts of the multipart body: the `sdType` field,
    /// then the `sdComments` field (when present), then the `sdFile` binary
    /// part — the data-then-files order the reference client's `requests`
    /// call produces (`data=payload, files=…`,
    /// `request_types/supporting_documentation.py`).
    #[must_use]
    pub fn parts(&self) -> Vec<MultipartPart<'_>> {
        let mut out = vec![MultipartPart::Field {
            name: SD_TYPE_FIELD,
            value: self.sd_type.wire_str().to_string(),
        }];
        if let Some(comment) = &self.comment {
            out.push(MultipartPart::Field {
                name: SD_COMMENTS_FIELD,
                value: comment.clone(),
            });
        }
        out.push(MultipartPart::File {
            field_name: SD_FILE_PART_NAME,
            filename: &self.filename,
            content_type: SD_CONTENT_TYPE,
            bytes: &self.bytes,
        });
        out
    }

    /// Serialize the request to a raw `multipart/form-data` body via the
    /// shared [`serialize_multipart`] encoder, returning the `Content-Type`
    /// header value (carrying `boundary`) and the body bytes.
    ///
    /// # Errors
    /// [`crate::datafiles::MultipartError`] if `boundary` is not a valid
    /// RFC 2046 token or occurs inside a part body (see [`serialize_multipart`]).
    pub fn to_multipart(
        &self,
        boundary: &str,
    ) -> Result<(String, Vec<u8>), crate::datafiles::MultipartError> {
        serialize_multipart(&self.parts(), boundary)
    }
}

// ── Upload response ───────────────────────────────────────────────────

/// A successfully-uploaded supporting document: its server-assigned id, its
/// classification, and the scoped JWT that authorizes referencing it in a
/// certify request.
///
/// This is exactly what a certify request needs about a document (see
/// [`crate::certify`]): the `sdId` and `accessToken` go on the wire, while
/// the `sdType` drives the exactly-one/at-most-one constraint check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportingDoc {
    /// The server-assigned supporting-document id (`sdId`).
    pub sd_id: i64,
    /// The document classification. Threaded in from the upload request
    /// rather than read back from the response.
    pub sd_type: SdType,
    /// The scoped JWT with claims to this `sdId`.
    pub access_token: String,
}

/// Parse a supporting-document upload response into a [`SupportingDoc`].
///
/// The response is the versioned envelope
/// `[{esvVersion}, {sdId, status, accessToken, …}]` (ESVP §6.2). A
/// `status` other than `"success"` is a typed-as-`String` failure. The
/// `sd_type` is not echoed by the server, so it is threaded in from the
/// upload request the caller just made.
///
/// # Errors
/// A `String` describing the first structural problem (parse failure,
/// missing envelope/field, or a non-`success` status).
pub fn parse_supporting_doc_response(body: &str, sd_type: SdType) -> Result<SupportingDoc, String> {
    let parsed = json::parse(body).map_err(|e| format!("parse supporting-doc response: {e}"))?;
    let payload = crate::login::esv_payload_element(&parsed)?;

    let status = payload
        .get("status")
        .and_then(JsonValue::as_str)
        .ok_or("supporting-doc response missing string `status`")?;
    if status != "success" {
        return Err(format!(
            "supporting-doc upload did not succeed: status {status:?}"
        ));
    }

    let sd_id = payload
        .get("sdId")
        .and_then(JsonValue::as_i64)
        .ok_or("supporting-doc response missing integer `sdId`")?;
    let access_token = payload
        .get("accessToken")
        .and_then(JsonValue::as_str)
        .ok_or("supporting-doc response missing string `accessToken`")?;

    Ok(SupportingDoc {
        sd_id,
        sd_type,
        access_token: access_token.to_string(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A minimal valid PDF payload (begins with the signature).
    fn pdf_bytes() -> Vec<u8> {
        let mut b = b"%PDF-1.7\n".to_vec();
        b.extend_from_slice(b"...body...\n%%EOF\n");
        b
    }

    // ── sdType wire strings ───────────────────────────────────────────

    #[test]
    fn sd_type_wire_strings_are_exact() {
        assert_eq!(
            SdType::EntropyAssessmentReport.wire_str(),
            "EntropyAssessmentReport"
        );
        assert_eq!(SdType::PublicUseDocument.wire_str(), "PublicUseDocument");
        assert_eq!(
            SdType::DataCollectionAttestation.wire_str(),
            "DataCollectionAttestation"
        );
        assert_eq!(
            SdType::RandomBitGeneratorReport.wire_str(),
            "RandomBitGeneratorReport"
        );
        assert_eq!(SdType::Other.wire_str(), "Other");
    }

    #[test]
    fn sd_type_round_trips_through_wire() {
        for t in [
            SdType::EntropyAssessmentReport,
            SdType::PublicUseDocument,
            SdType::DataCollectionAttestation,
            SdType::RandomBitGeneratorReport,
            SdType::Other,
        ] {
            assert_eq!(SdType::from_wire(t.wire_str()), Some(t));
        }
        // The reference client's `utils.VALID_SD_TYPES` uses the short
        // "RBGReport" spelling, which is NOT the wire string — it is
        // rejected here (the authoritative wire string is the long form).
        assert_eq!(SdType::from_wire("RBGReport"), None);
        assert_eq!(SdType::from_wire("nonsense"), None);
    }

    // ── PDF-only enforcement (ISC-102) ────────────────────────────────

    #[test]
    fn new_accepts_a_pdf_payload() {
        let up =
            SupportingDocUpload::new(SdType::PublicUseDocument, "pud.pdf", pdf_bytes()).unwrap();
        assert_eq!(up.sd_type, SdType::PublicUseDocument);
        assert_eq!(up.path(), SUPPORTING_DOC_PATH);
    }

    #[test]
    fn new_refuses_a_non_pdf_payload() {
        let err = SupportingDocUpload::new(SdType::Other, "notes.txt", b"plain text".to_vec())
            .unwrap_err();
        match err {
            SupportDocError::NotPdf { leading_hex } => {
                // "pl" = 0x70 0x6c ...
                assert!(leading_hex.starts_with("706c"), "{leading_hex}");
            }
            SupportDocError::Empty => panic!("expected NotPdf, got Empty"),
        }
    }

    #[test]
    fn new_refuses_an_empty_payload() {
        let err = SupportingDocUpload::new(SdType::Other, "empty.pdf", Vec::new()).unwrap_err();
        assert_eq!(err, SupportDocError::Empty);
    }

    #[test]
    fn bytes_enter_only_through_the_guarded_constructor() {
        // The accessor returns exactly the validated bytes the constructor
        // accepted — and, since `bytes` is private and `new` is the only entry
        // point, every held payload is guaranteed to lead with `%PDF-`.
        let payload = pdf_bytes();
        let up = SupportingDocUpload::new(SdType::Other, "o.pdf", payload.clone()).unwrap();
        assert_eq!(up.bytes(), payload.as_slice());
        assert!(up.bytes().starts_with(PDF_MAGIC));
        // A non-PDF never yields an upload, so no `SupportingDocUpload` can
        // ever hold non-PDF bytes.
        assert!(matches!(
            SupportingDocUpload::new(SdType::Other, "o.pdf", b"not a pdf".to_vec()),
            Err(SupportDocError::NotPdf { .. })
        ));
    }

    #[test]
    fn new_refuses_a_pdf_signature_not_at_offset_zero() {
        // A file that only carries `%PDF-` after some prefix is not a
        // conformant PDF header (the signature must lead).
        let mut b = b"junk".to_vec();
        b.extend_from_slice(PDF_MAGIC);
        assert!(matches!(
            SupportingDocUpload::new(SdType::Other, "x.pdf", b),
            Err(SupportDocError::NotPdf { .. })
        ));
    }

    // ── Multipart shape ───────────────────────────────────────────────

    #[test]
    fn parts_order_is_type_then_comment_then_file() {
        let up = SupportingDocUpload::new(SdType::EntropyAssessmentReport, "ear.pdf", pdf_bytes())
            .unwrap()
            .with_comment("the EAR");
        let parts = up.parts();
        assert_eq!(parts.len(), 3);
        match &parts[0] {
            MultipartPart::Field { name, value } => {
                assert_eq!(*name, "sdType");
                assert_eq!(value, "EntropyAssessmentReport");
            }
            MultipartPart::File { .. } => panic!("sdType field must be first"),
        }
        match &parts[1] {
            MultipartPart::Field { name, value } => {
                assert_eq!(*name, "sdComments");
                assert_eq!(value, "the EAR");
            }
            MultipartPart::File { .. } => panic!("sdComments field must be second"),
        }
        assert!(matches!(parts[2], MultipartPart::File { .. }));
    }

    #[test]
    fn parts_omit_comment_when_absent() {
        let up = SupportingDocUpload::new(SdType::Other, "o.pdf", pdf_bytes()).unwrap();
        let parts = up.parts();
        assert_eq!(parts.len(), 2, "sdType field + sdFile only");
        assert!(
            !parts
                .iter()
                .any(|p| matches!(p, MultipartPart::Field { name, .. } if *name == "sdComments"))
        );
    }

    #[test]
    fn to_multipart_carries_type_and_content_type() {
        let up =
            SupportingDocUpload::new(SdType::PublicUseDocument, "pud.pdf", pdf_bytes()).unwrap();
        let (content_type, body) = up.to_multipart("BNDRY").unwrap();
        assert_eq!(content_type, "multipart/form-data; boundary=BNDRY");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("name=\"sdType\""), "{text}");
        assert!(text.contains("PublicUseDocument"), "{text}");
        assert!(text.contains("filename=\"pud.pdf\""), "{text}");
        assert!(text.contains("Content-Type: application/pdf"), "{text}");
        assert!(text.contains("--BNDRY--\r\n"), "closing boundary: {text}");
    }

    // ── Response parsing ──────────────────────────────────────────────

    #[test]
    fn parse_success_response() {
        let body = r#"[{"esvVersion":"1.0"},{"sdId":42,"uploadType":"UploadSupportingDocumentation","status":"success","dataLengthBytes":1234,"accessToken":"eyJ.sd.tok"}]"#;
        let doc = parse_supporting_doc_response(body, SdType::PublicUseDocument).unwrap();
        assert_eq!(doc.sd_id, 42);
        assert_eq!(doc.sd_type, SdType::PublicUseDocument);
        assert_eq!(doc.access_token, "eyJ.sd.tok");
    }

    #[test]
    fn parse_rejects_non_success_status() {
        let body = r#"[{"esvVersion":"1.0"},{"sdId":0,"status":"rejected: not a PDF"}]"#;
        let err = parse_supporting_doc_response(body, SdType::Other).unwrap_err();
        assert!(err.contains("did not succeed"), "{err}");
        assert!(err.contains("rejected"), "{err}");
    }

    #[test]
    fn parse_rejects_bare_object_envelope() {
        // Not the versioned envelope — the shared esv_payload_element rejects it.
        let body = r#"{"sdId":1,"status":"success","accessToken":"t"}"#;
        assert!(parse_supporting_doc_response(body, SdType::Other).is_err());
    }
}
