//! ESVP §6.1 data-file upload: the multipart request builder, the
//! processing-status polling state machine, and the vetted-conditioning
//! upload refusal.
//!
//! The request builder and the status decision function are pure (testable
//! against fixtures with no network); the polling loop is generic over the
//! [`EsvTransport`] trait and uses the injectable [`Sleeper`], so it is
//! driven by a canned-response stub and a recording sleeper in unit tests
//! and wired to acvp-harness's live curl(1)/mTLS transport at the attended
//! smoke.
//!
//! # Protocol facts (cited)
//!
//! - **Upload endpoint:** `POST /esv/v1/entropyAssessments/{eaId}/dataFiles/{dfId}`
//!   (reference client `request_types/data_files.py:50`; the reference
//!   `server_url` already carries the `/esv/v1` prefix, which these
//!   full-path constants reproduce — see [`crate::login::LOGIN_PATH`] for
//!   the host-only-base convention and the `/esv/v1` doubling trap).
//! - **Multipart shape:** `multipart/form-data` with a single **`dataFile`**
//!   binary part (`Content-Type: application/octet-stream`) plus, when a
//!   per-file sample width is declared, a text form field. (reference
//!   client `request_types/data_files.py:49-50`.)
//! - **`DataFileSampleSize` capitalization (v1.8 compat):** the field is
//!   sent **capitalized** — server v1.8 expects `DataFileSampleSize`; only
//!   from server v2.0 is it case-insensitive. This harness never assumes
//!   case-insensitivity. (reference client comment
//!   `request_types/data_files.py:43`; ESVP digest §6.1 "INTEROP GOTCHA".)
//!   Its value is a sample width in `1..=8` (`min(bitsPerSample, 8)` — the
//!   `bitsPerSample` cross-check is data-file preflight, slice S5; the
//!   intrinsic `1..=8` field bound is enforced here). (ESVP digest §6.1.)
//! - **Status polling:** GET the data-file resource, read `status` from the
//!   envelope payload (`[{esvVersion}, {id, status, …}]`), and loop until a
//!   terminal state. The seven documented statuses (ESVP digest §6.1) are
//!   `not-yet-processed` (wait and retry, bounded), `Uploaded` /
//!   `Run Started` (processing — wait and re-poll), and the terminal
//!   `Run Successful` (**returns NIST's computed assessment — the second
//!   maxwell oracle**), `Run Failed`, `Run Cancelled`, and `Error`.
//! - **Vetted ⇒ no conditionedBits upload:** "data file upload is only
//!   allowed on non-vetted, non-bijective conditioning components" — a
//!   conditioned-bits upload under vetted (or bijective) conditioning is a
//!   **typed refusal**, never attempted. (ESVP digest §3/§6.1;
//!   ISC-107, Anti.)
//!
//! ## Resolved-by-judgment: the retry / poll interval
//!
//! The ratified design and the ESVP digest §6.1 name a **30-second**
//! not-yet-processed retry; the NIST reference client instead sleeps
//! **10 s** on the upload not-yet-processed 400 (`data_files.py:58`) and
//! **15 s** between status polls (`data_files.py:28`). This module follows
//! the design's 30 s (the [`PollConfig`] defaults), while keeping the
//! interval a tunable field so the attended demo smoke can align it with
//! whatever the upgraded demo server actually wants. Flagged for empirical
//! confirmation at the smoke.
//!
//! ## Resolved-by-judgment: which statuses are terminal
//!
//! The reference client's poll loop treats only `error` and
//! `run successful` as terminal (`data_files.py:11`), so on `Run Failed` or
//! `Run Cancelled` it would poll forever. The ratified design (and the
//! documented status set) makes **all four** of `Run Successful` /
//! `Run Failed` / `Run Cancelled` / `Error` terminal; this module follows
//! the design and returns a typed terminal outcome for each.

use std::time::Duration;

use acvp_harness::transport::HttpResponse;

use crate::jsonlite::{self, JsonLite};
use crate::login::{EsvTransport, Sleeper};
use crate::registration::EntropyRegistration;

/// The multipart part name of the data-file binary payload
/// (reference client `request_types/data_files.py:49`).
pub const DATA_FILE_PART_NAME: &str = "dataFile";

/// The multipart text-field name declaring the file's per-sample width —
/// sent **capitalized** for server v1.8 compatibility (never assume
/// case-insensitivity). (reference client comment
/// `request_types/data_files.py:43`; ESVP digest §6.1.)
pub const DATA_FILE_SAMPLE_SIZE_FIELD: &str = "DataFileSampleSize";

/// The `Content-Type` of the `dataFile` part (reference client
/// `request_types/data_files.py:49`).
pub const DATA_FILE_CONTENT_TYPE: &str = "application/octet-stream";

/// Minimum valid `DataFileSampleSize` (ESVP digest §6.1: sample width
/// `1..=8`).
pub const DATA_FILE_SAMPLE_SIZE_MIN: u8 = 1;

/// Maximum valid `DataFileSampleSize` — never more than 8 bits, since a
/// byte-padded sample is at most one byte. (ESVP digest §6.1:
/// "never > min(bitsPerSample, 8)"; the `bitsPerSample` cross-check is
/// data-file preflight, slice S5.)
pub const DATA_FILE_SAMPLE_SIZE_MAX: u8 = 8;

// ── Errors ────────────────────────────────────────────────────────────

/// Why a conditioned-bits upload was refused (ISC-107).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionedRefusalReason {
    /// The conditioning component is **vetted** — uploads are only allowed
    /// on non-vetted components. (The oxicrypt vetted-SHA2-256 case.)
    Vetted,
    /// The conditioning component is claimed **bijective** — uploads are
    /// only allowed on non-bijective components.
    Bijective,
}

impl core::fmt::Display for ConditionedRefusalReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Vetted => f.write_str("vetted"),
            Self::Bijective => f.write_str("bijective"),
        }
    }
}

/// An error building a data-file upload request or polling its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataFileError {
    /// A `DataFileSampleSize` outside the valid `1..=8` field bound.
    SampleSizeOutOfRange {
        /// The rejected value.
        value: u8,
    },
    /// A conditioned-bits upload was attempted for a component that does not
    /// permit one (vetted or bijective) — refused before any request is
    /// built (ISC-107).
    ConditionedUploadForbidden {
        /// The conditioning component's sequence position.
        sequence_position: i64,
        /// Why the upload was refused.
        reason: ConditionedRefusalReason,
    },
    /// A conditioned-bits upload named a `sequencePosition` with no matching
    /// conditioning component in the registration.
    NoSuchConditioningComponent {
        /// The requested sequence position.
        sequence_position: i64,
    },
    /// The server reported a status string not among the seven documented
    /// states — fail closed rather than guess its meaning.
    UnrecognizedStatus {
        /// The unrecognized status string, verbatim.
        status: String,
    },
    /// The data file stayed `not-yet-processed` for more consecutive polls
    /// than [`PollConfig::max_not_yet_processed_polls`] allows.
    NotYetProcessedTimeout {
        /// The number of consecutive not-yet-processed polls tolerated
        /// before timing out.
        polls: u32,
    },
    /// The server returned an error payload (an `error` field, or a non-2xx
    /// status with neither `status` nor `error`).
    ServerError {
        /// The server's error message (or an `HTTP <code> — <body>`
        /// summary).
        message: String,
    },
    /// A status response that did not parse or lacked the expected envelope
    /// / fields.
    MalformedResponse {
        /// What was wrong.
        detail: String,
    },
    /// The data file did not reach a terminal state within
    /// [`PollConfig::max_total_polls`] total polls — bounds an
    /// alternating-status livelock (e.g. `Uploaded`/`not-yet-processed`
    /// flip-flop) that keeps resetting the consecutive-not-yet-processed
    /// counter and so never trips [`Self::NotYetProcessedTimeout`].
    PollTimeout {
        /// The total-poll cap that was reached.
        polls: u32,
    },
    /// The poll loop saw more consecutive transient failures (a transport
    /// error, or an unparseable response body such as a 502 HTML page) than
    /// [`PollConfig::max_consecutive_transient_failures`] allows; a
    /// well-formed response resets the run. Carries the last failure seen.
    TransientFailuresExhausted {
        /// The number of consecutive transient failures tolerated.
        failures: u32,
        /// The last transient failure message.
        last: String,
    },
    /// The token provider failed to yield a bearer for a poll request.
    Token(String),
    /// The underlying transport failed.
    Transport(String),
}

/// An error serializing a `multipart/form-data` body: the boundary is not a
/// valid RFC 2046 token, or it occurs inside a part body (which would
/// prematurely terminate that part on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartError {
    /// The boundary is not a valid RFC 2046 `boundary` token (empty, longer
    /// than 70 characters, a disallowed character, or a trailing space).
    InvalidBoundary {
        /// Why the boundary was rejected.
        reason: String,
    },
    /// The boundary delimiter occurs inside a part body, so serializing with
    /// it would corrupt the message. Carries the 0-based index of the
    /// colliding part.
    BoundaryCollision {
        /// The index of the colliding part.
        part_index: usize,
    },
}

impl core::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBoundary { reason } => {
                write!(f, "invalid multipart boundary: {reason}")
            }
            Self::BoundaryCollision { part_index } => write!(
                f,
                "multipart boundary occurs inside the body of part {part_index}"
            ),
        }
    }
}

impl std::error::Error for MultipartError {}

impl core::fmt::Display for DataFileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SampleSizeOutOfRange { value } => write!(
                f,
                "DataFileSampleSize {value} is outside the valid {DATA_FILE_SAMPLE_SIZE_MIN}..={DATA_FILE_SAMPLE_SIZE_MAX} range"
            ),
            Self::ConditionedUploadForbidden {
                sequence_position,
                reason,
            } => write!(
                f,
                "conditioned-bits upload refused for sequence position {sequence_position}: component is {reason}"
            ),
            Self::NoSuchConditioningComponent { sequence_position } => write!(
                f,
                "no conditioning component at sequence position {sequence_position}"
            ),
            Self::UnrecognizedStatus { status } => {
                write!(f, "unrecognized data-file status: {status:?}")
            }
            Self::NotYetProcessedTimeout { polls } => write!(
                f,
                "data file still not processed after {polls} consecutive polls"
            ),
            Self::ServerError { message } => write!(f, "ESV data-file server error: {message}"),
            Self::MalformedResponse { detail } => {
                write!(f, "malformed ESV data-file status response: {detail}")
            }
            Self::PollTimeout { polls } => write!(
                f,
                "data file did not reach a terminal state within {polls} total polls"
            ),
            Self::TransientFailuresExhausted { failures, last } => write!(
                f,
                "ESV data-file poll gave up after {failures} consecutive transient failures; last: {last}"
            ),
            Self::Token(e) => write!(f, "ESV data-file token provider error: {e}"),
            Self::Transport(e) => write!(f, "ESV data-file transport error: {e}"),
        }
    }
}

impl std::error::Error for DataFileError {}

// ── Multipart upload request builder (ISC-98, ISC-100) ────────────────

/// The full server-relative data-file resource path,
/// `/esv/v1/entropyAssessments/{ea_id}/dataFiles/{df_id}` (used for both
/// the upload POST and the status GET). See [`crate::login::LOGIN_PATH`]
/// for the host-only-base convention. (reference client
/// `request_types/data_files.py:15,50`.)
pub fn data_file_path(ea_id: &str, df_id: &str) -> String {
    format!("/esv/v1/entropyAssessments/{ea_id}/dataFiles/{df_id}")
}

/// One logical part of the multipart upload body: a text form field or the
/// binary file part. Borrows the owning [`DataFileUpload`] so the (large)
/// file bytes are never copied to inspect the request shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartPart<'a> {
    /// A text form field (e.g. `DataFileSampleSize`).
    Field {
        /// The field name.
        name: &'a str,
        /// The field value.
        value: String,
    },
    /// The binary file part.
    File {
        /// The multipart part name (`dataFile`).
        field_name: &'a str,
        /// The uploaded file's name.
        filename: &'a str,
        /// The part's declared content type.
        content_type: &'a str,
        /// The raw file bytes.
        bytes: &'a [u8],
    },
}

/// A data-file upload request: the target resource, the file bytes, and an
/// optional declared per-sample width.
///
/// Build with [`Self::new`] (raw-noise / restart uploads) or the guarded
/// [`build_conditioned_upload`] (which refuses a conditioned-bits upload
/// under vetted/bijective conditioning). The request shape is inspected via
/// [`Self::parts`] or serialized to raw multipart bytes via
/// [`Self::to_multipart`] — both fixture-testable with no transport; the
/// live upload is wired at the attended smoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFileUpload {
    /// The entropy-assessment id (path segment).
    pub ea_id: String,
    /// The data-file id (path segment).
    pub df_id: String,
    /// The declared per-sample width, when the file's sample width differs
    /// from the assessment's `bitsPerSample`. `Some(n)` emits the
    /// `DataFileSampleSize` field; `None` omits it (matching the reference
    /// client, which sends the field only when `bits_per_sample != 0`).
    pub sample_size: Option<u8>,
    /// The uploaded file's name (the `filename` of the `dataFile` part).
    pub filename: String,
    /// The raw file bytes (byte-padded 1M samples in production; the
    /// exact-size check is data-file preflight, slice S5).
    pub bytes: Vec<u8>,
}

impl DataFileUpload {
    /// Build an upload for a raw-noise or restart data-file slot (never
    /// gated). No `DataFileSampleSize` field; add one with
    /// [`Self::with_sample_size`].
    pub fn new(ea_id: &str, df_id: &str, filename: &str, bytes: Vec<u8>) -> Self {
        Self {
            ea_id: ea_id.to_string(),
            df_id: df_id.to_string(),
            sample_size: None,
            filename: filename.to_string(),
            bytes,
        }
    }

    /// Declare the file's per-sample width, emitting the capitalized
    /// `DataFileSampleSize` field.
    ///
    /// # Errors
    /// [`DataFileError::SampleSizeOutOfRange`] if `size` is outside the
    /// intrinsic `1..=8` field bound (the `min(bitsPerSample, 8)`
    /// cross-check is data-file preflight, slice S5).
    pub fn with_sample_size(mut self, size: u8) -> Result<Self, DataFileError> {
        if !(DATA_FILE_SAMPLE_SIZE_MIN..=DATA_FILE_SAMPLE_SIZE_MAX).contains(&size) {
            return Err(DataFileError::SampleSizeOutOfRange { value: size });
        }
        self.sample_size = Some(size);
        Ok(self)
    }

    /// The full server-relative resource path for this upload.
    pub fn path(&self) -> String {
        data_file_path(&self.ea_id, &self.df_id)
    }

    /// The ordered logical parts of the multipart body: the
    /// `DataFileSampleSize` field first (when present), then the `dataFile`
    /// binary part — the data-then-files order the reference client's
    /// `requests` call produces (`data=payload, files=…`,
    /// `request_types/data_files.py:50`).
    pub fn parts(&self) -> Vec<MultipartPart<'_>> {
        let mut out = Vec::new();
        if let Some(size) = self.sample_size {
            out.push(MultipartPart::Field {
                name: DATA_FILE_SAMPLE_SIZE_FIELD,
                value: size.to_string(),
            });
        }
        out.push(MultipartPart::File {
            field_name: DATA_FILE_PART_NAME,
            filename: &self.filename,
            content_type: DATA_FILE_CONTENT_TYPE,
            bytes: &self.bytes,
        });
        out
    }

    /// Serialize the request to a raw `multipart/form-data` body, returning
    /// the `Content-Type` header value (carrying `boundary`) and the body
    /// bytes.
    ///
    /// `boundary` is caller-supplied so the serialization is deterministic
    /// for fixtures; live wiring can obtain a provably non-colliding one from
    /// [`generate_boundary`]. (Filenames are module-controlled and not
    /// quote-escaped here.)
    ///
    /// # Errors
    /// [`MultipartError`] if `boundary` is not a valid RFC 2046 token or
    /// occurs inside a part body (see [`serialize_multipart`]).
    pub fn to_multipart(&self, boundary: &str) -> Result<(String, Vec<u8>), MultipartError> {
        serialize_multipart(&self.parts(), boundary)
    }
}

/// Serialize an ordered list of [`MultipartPart`]s into a raw
/// `multipart/form-data` body, returning the `Content-Type` header value
/// (carrying `boundary`) and the body bytes.
///
/// This is the single encoder both the data-file upload
/// ([`DataFileUpload::to_multipart`]) and the supporting-document upload
/// ([`crate::supportdocs::SupportingDocUpload::to_multipart`]) share, so
/// the two upload paths cannot drift on the wire format. `boundary` is
/// caller-supplied so the serialization is deterministic for fixtures; live
/// wiring can obtain a provably non-colliding one from [`generate_boundary`].
/// (Part names/filenames are module-controlled and not quote-escaped here.)
///
/// # Errors
/// [`MultipartError::InvalidBoundary`] if `boundary` is not a valid RFC 2046
/// `boundary` token (1..=70 `bchars`, no trailing space);
/// [`MultipartError::BoundaryCollision`] if the boundary delimiter occurs
/// inside a part body — either would corrupt the message, so it fails closed
/// rather than emit a body a receiver could mis-split.
pub fn serialize_multipart(
    parts: &[MultipartPart<'_>],
    boundary: &str,
) -> Result<(String, Vec<u8>), MultipartError> {
    validate_boundary(boundary)?;
    for (index, part) in parts.iter().enumerate() {
        if body_collides(part_body_bytes(part), boundary) {
            return Err(MultipartError::BoundaryCollision { part_index: index });
        }
    }
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let mut body: Vec<u8> = Vec::new();
    for part in parts {
        push_str(&mut body, &format!("--{boundary}\r\n"));
        match part {
            MultipartPart::Field { name, value } => {
                push_str(
                    &mut body,
                    &format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"),
                );
                push_str(&mut body, value);
                push_str(&mut body, "\r\n");
            }
            MultipartPart::File {
                field_name,
                filename,
                content_type: part_ct,
                bytes,
            } => {
                push_str(
                    &mut body,
                    &format!(
                        "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
                    ),
                );
                push_str(&mut body, &format!("Content-Type: {part_ct}\r\n\r\n"));
                body.extend_from_slice(bytes);
                push_str(&mut body, "\r\n");
            }
        }
    }
    push_str(&mut body, &format!("--{boundary}--\r\n"));
    Ok((content_type, body))
}

/// Append a string's bytes to a byte buffer.
fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
}

// ── Boundary validation + generation (ISC-98 hardening) ───────────────

/// True if `b` is an RFC 2046 `bchars` character (the set a multipart
/// boundary may use, including the space that a boundary must not *end*
/// with).
fn is_bchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'\''
                | b'('
                | b')'
                | b'+'
                | b'_'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?'
                | b' '
        )
}

/// Validate a multipart boundary against RFC 2046 §5.1.1: the `boundary` is
/// `1*70` `bchars` whose last character is a `bcharsnospace` (i.e. not a
/// space).
///
/// # Errors
/// [`MultipartError::InvalidBoundary`] with a reason for an empty or
/// over-long boundary, a disallowed character, or a trailing space.
pub fn validate_boundary(boundary: &str) -> Result<(), MultipartError> {
    let bytes = boundary.as_bytes();
    if bytes.is_empty() || bytes.len() > 70 {
        return Err(MultipartError::InvalidBoundary {
            reason: format!(
                "length {} is outside the RFC 2046 range 1..=70",
                bytes.len()
            ),
        });
    }
    for &b in bytes {
        if !is_bchar(b) {
            return Err(MultipartError::InvalidBoundary {
                reason: format!("byte {b:#04x} is not an RFC 2046 boundary character"),
            });
        }
    }
    if bytes.last() == Some(&b' ') {
        return Err(MultipartError::InvalidBoundary {
            reason: "boundary must not end with a space".to_string(),
        });
    }
    Ok(())
}

/// The bytes of a part a boundary delimiter could hide inside — a text
/// field's value or the binary file bytes.
fn part_body_bytes<'a>(part: &'a MultipartPart<'a>) -> &'a [u8] {
    match part {
        MultipartPart::Field { value, .. } => value.as_bytes(),
        MultipartPart::File { bytes, .. } => bytes,
    }
}

/// True if the boundary delimiter occurs inside `body`, which would
/// prematurely terminate the part on the wire. The delimiter is
/// `CRLF "--" boundary`; at the very start of a body the preceding
/// header separator (`…\r\n\r\n`) already supplies the leading CRLF, so a
/// bare leading `--boundary` is also a live delimiter.
fn body_collides(body: &[u8], boundary: &str) -> bool {
    let mut bare = Vec::with_capacity(boundary.len().saturating_add(2));
    bare.extend_from_slice(b"--");
    bare.extend_from_slice(boundary.as_bytes());
    if body.starts_with(&bare) {
        return true;
    }
    let mut crlf = Vec::with_capacity(bare.len().saturating_add(2));
    crlf.extend_from_slice(b"\r\n");
    crlf.extend_from_slice(&bare);
    body.windows(crlf.len()).any(|w| w == crlf.as_slice())
}

/// Generate a multipart boundary guaranteed not to occur inside any part
/// body of `parts`.
///
/// Deterministic and provably collision-free: it takes a fixed valid base
/// and appends an incrementing decimal suffix until a candidate collides
/// with no part body. Each body is finite, so only finitely many candidates
/// can collide, and the base is pure ASCII-alphanumeric so every candidate
/// is a valid boundary (well under 70 characters); the search therefore
/// terminates on a valid, non-colliding boundary.
#[must_use]
pub fn generate_boundary(parts: &[MultipartPart<'_>]) -> String {
    const BASE: &str = "oxicryptEsvBoundary";
    let mut n: u64 = 0;
    loop {
        let candidate = format!("{BASE}{n}");
        if parts
            .iter()
            .all(|p| !body_collides(part_body_bytes(p), &candidate))
        {
            return candidate;
        }
        n = n.saturating_add(1);
    }
}

// ── Vetted-conditioning upload refusal (ISC-107, Anti) ────────────────

/// Which data-file slot an upload targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataFileTarget {
    /// The raw-noise data-file slot (always uploadable).
    RawNoise,
    /// The restart-test data-file slot (always uploadable).
    Restart,
    /// A conditioned-bits slot for the conditioning component at this
    /// sequence position (uploadable only for a non-vetted, non-bijective
    /// component).
    ConditionedBits {
        /// The conditioning component's sequence position.
        sequence_position: i64,
    },
}

/// Check whether a data-file upload for `target` is permitted under `reg`'s
/// conditioning configuration.
///
/// Raw-noise and restart uploads are always allowed. A conditioned-bits
/// upload is allowed **only** for a non-vetted, non-bijective conditioning
/// component (ESVP digest §3/§6.1: "data file upload is only allowed on
/// non-vetted, non-bijective conditioning components"); a vetted or
/// bijective component — or a missing one — is a typed refusal.
///
/// # Errors
/// [`DataFileError::ConditionedUploadForbidden`] for a vetted/bijective
/// component; [`DataFileError::NoSuchConditioningComponent`] if no component
/// has the named sequence position.
pub fn check_conditioned_upload_allowed(
    reg: &EntropyRegistration,
    target: &DataFileTarget,
) -> Result<(), DataFileError> {
    let DataFileTarget::ConditionedBits { sequence_position } = target else {
        return Ok(());
    };
    let cc = reg
        .conditioning
        .iter()
        .find(|c| c.sequence_position == *sequence_position)
        .ok_or(DataFileError::NoSuchConditioningComponent {
            sequence_position: *sequence_position,
        })?;
    if cc.vetted {
        return Err(DataFileError::ConditionedUploadForbidden {
            sequence_position: *sequence_position,
            reason: ConditionedRefusalReason::Vetted,
        });
    }
    if cc.bijective_claim == Some(true) {
        return Err(DataFileError::ConditionedUploadForbidden {
            sequence_position: *sequence_position,
            reason: ConditionedRefusalReason::Bijective,
        });
    }
    Ok(())
}

/// Build a conditioned-bits upload, refusing (a typed error, no request
/// produced) when the target component is vetted or bijective — the ISC-107
/// anti guard, so a vetted registration can never yield a conditioned-file
/// request.
///
/// # Errors
/// Any error from [`check_conditioned_upload_allowed`].
pub fn build_conditioned_upload(
    reg: &EntropyRegistration,
    sequence_position: i64,
    ea_id: &str,
    df_id: &str,
    filename: &str,
    bytes: Vec<u8>,
) -> Result<DataFileUpload, DataFileError> {
    check_conditioned_upload_allowed(reg, &DataFileTarget::ConditionedBits { sequence_position })?;
    Ok(DataFileUpload::new(ea_id, df_id, filename, bytes))
}

// ── Status polling state machine (ISC-101) ────────────────────────────

/// A parsed data-file processing status — the seven documented states of
/// ESVP §6.1 plus a fail-closed catch-all for anything unrecognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataFileStatus {
    /// The registration is not yet processed; wait and retry (bounded).
    NotYetProcessed,
    /// The file was accepted and is queued; processing in progress.
    Uploaded,
    /// The entropy assessment run has begun; processing in progress.
    RunStarted,
    /// Terminal success — the response carries NIST's computed assessment
    /// (the second maxwell oracle).
    RunSuccessful,
    /// Terminal failure — the assessment run failed.
    RunFailed,
    /// Terminal failure — the assessment run was cancelled.
    RunCancelled,
    /// Terminal error.
    Error,
    /// A status string not among the seven documented states.
    Unrecognized(String),
}

/// A terminal data-file outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalStatus {
    /// `Run Successful` — the assessment is returned.
    RunSuccessful,
    /// `Run Failed`.
    RunFailed,
    /// `Run Cancelled`.
    RunCancelled,
    /// `Error`.
    Error,
}

/// What the polling loop should do next for a classified status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollDecision {
    /// `not-yet-processed`: wait the retry interval and poll again; this
    /// counts against the consecutive-not-yet-processed cap.
    WaitNotYetProcessed,
    /// `Uploaded` / `Run Started`: still processing — wait the poll interval
    /// and poll again (resets the not-yet-processed counter).
    WaitProcessing,
    /// A terminal state was reached.
    Terminal(TerminalStatus),
    /// The status was unrecognized — the loop surfaces a typed error.
    Unrecognized,
}

impl DataFileStatus {
    /// The next polling action for this status (pure).
    pub fn poll_decision(&self) -> PollDecision {
        match self {
            Self::NotYetProcessed => PollDecision::WaitNotYetProcessed,
            Self::Uploaded | Self::RunStarted => PollDecision::WaitProcessing,
            Self::RunSuccessful => PollDecision::Terminal(TerminalStatus::RunSuccessful),
            Self::RunFailed => PollDecision::Terminal(TerminalStatus::RunFailed),
            Self::RunCancelled => PollDecision::Terminal(TerminalStatus::RunCancelled),
            Self::Error => PollDecision::Terminal(TerminalStatus::Error),
            Self::Unrecognized(_) => PollDecision::Unrecognized,
        }
    }
}

/// Normalize a status string for matching: ASCII-lowercase, treat `-`/`_`
/// as spaces, and collapse runs of whitespace to single spaces. So
/// `"Not-Yet-Processed"`, `"not yet processed"`, and `"NOT_YET_PROCESSED"`
/// all normalize alike — robust to the case/separator drift the reference
/// client tolerates (its `.lower()` substring match) and to server v2.0's
/// case-insensitivity.
fn normalize_status(raw: &str) -> String {
    let spaced: String = raw
        .chars()
        .map(|c| match c {
            '-' | '_' => ' ',
            other => other.to_ascii_lowercase(),
        })
        .collect();
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Classify a raw status string into a [`DataFileStatus`] (pure,
/// case/separator-insensitive).
///
/// Matching is **exact** on the normalized token — an enumerated set of
/// accepted spellings — not a substring match, so a status that merely
/// *contains* a documented phrase is not misclassified: `"Rerun Successful"`
/// does not fold to `RunSuccessful`, and `"Recoverable Error - Retrying"`
/// does not fold to `Error`. Only the two documented cancelled spellings
/// (`"run cancelled"` / `"run canceled"`) fold together. Anything else
/// becomes [`DataFileStatus::Unrecognized`] carrying the original string, so
/// the poll loop fails closed rather than guess.
pub fn classify_status(raw: &str) -> DataFileStatus {
    match normalize_status(raw).as_str() {
        "not yet processed" => DataFileStatus::NotYetProcessed,
        "uploaded" => DataFileStatus::Uploaded,
        "run started" => DataFileStatus::RunStarted,
        "run successful" => DataFileStatus::RunSuccessful,
        "run failed" => DataFileStatus::RunFailed,
        "run cancelled" | "run canceled" => DataFileStatus::RunCancelled,
        "error" => DataFileStatus::Error,
        _ => DataFileStatus::Unrecognized(raw.to_string()),
    }
}

/// The pure decision function: a raw status string mapped to a typed next
/// action (`classify_status` composed with [`DataFileStatus::poll_decision`]).
pub fn decide(raw: &str) -> PollDecision {
    classify_status(raw).poll_decision()
}

/// Tunables for the polling loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollConfig {
    /// Wait between `not-yet-processed` polls (design/digest §6.1: 30 s;
    /// see the module "Resolved-by-judgment: the retry / poll interval"
    /// note).
    pub not_yet_processed_wait: Duration,
    /// Wait between `Uploaded` / `Run Started` polls.
    pub processing_wait: Duration,
    /// Maximum consecutive `not-yet-processed` polls before
    /// [`DataFileError::NotYetProcessedTimeout`] — bounds an otherwise
    /// unbounded wait on a registration that never finishes processing.
    pub max_not_yet_processed_polls: u32,
    /// Maximum **total** polls (of any status) before
    /// [`DataFileError::PollTimeout`]. This is the global ceiling the
    /// per-status caps cannot provide: an alternating status stream (e.g.
    /// `Uploaded` ↔ `not-yet-processed`) keeps resetting
    /// [`Self::max_not_yet_processed_polls`] and would otherwise loop forever.
    pub max_total_polls: u32,
    /// Maximum consecutive transient failures — a transport error or an
    /// unparseable response body (a 502 HTML page) — tolerated before
    /// [`DataFileError::TransientFailuresExhausted`]. A well-formed response
    /// resets the run, so a single blip mid-poll no longer kills the loop.
    pub max_consecutive_transient_failures: u32,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            not_yet_processed_wait: Duration::from_secs(30),
            processing_wait: Duration::from_secs(30),
            // ~20 consecutive 30 s not-yet-processed polls ≈ 10 min, a
            // generous ceiling on registration processing (~5 min typical).
            max_not_yet_processed_polls: 20,
            // 240 polls at the 30 s cadence ≈ 2 h — a generous hard ceiling
            // on total processing time, well past any real assessment run.
            max_total_polls: 240,
            // Tolerate a short run of transient blips (a dropped connection,
            // a momentary gateway error) before giving up.
            max_consecutive_transient_failures: 3,
        }
    }
}

/// The result of polling a data file to a terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFileResult {
    /// The data-file id echoed by the server, when present.
    pub id: Option<String>,
    /// The terminal status reached.
    pub status: TerminalStatus,
    /// On [`TerminalStatus::RunSuccessful`], NIST's returned assessment as
    /// the **raw response body** (the second maxwell oracle) — persist it to
    /// the session dir (slice S4) and compare it against local EA v1.1.8 with
    /// a float-capable parser downstream. `None` for the failure terminals.
    ///
    /// It is captured verbatim (never re-serialized) because the assessment
    /// carries fractional min-entropy numbers. The status envelope is read
    /// with the float-tolerant, raw-token [`crate::jsonlite`] reader, but the
    /// assessment returned here is the untouched response body, so its
    /// floating-point values are preserved exactly.
    pub assessment: Option<String>,
}

/// Adapt a fixed bearer token into the token provider [`poll_data_file`]
/// takes, for the common case where the token needs no in-flight refresh
/// across the poll (a short poll, or a caller managing refresh out of band).
///
/// ```ignore
/// poll_data_file(ea, df, &mut fixed_token("jwt"), &mut transport, &mut sleeper, &cfg)
/// ```
pub fn fixed_token(token: &str) -> impl FnMut() -> Result<String, String> + '_ {
    move || Ok(token.to_string())
}

/// Poll a data file's processing status until it reaches a terminal state.
///
/// Issues `GET`s against [`data_file_path`], classifies the `status` field,
/// and per [`DataFileStatus::poll_decision`]: waits the (bounded)
/// not-yet-processed interval, waits the processing interval, or returns the
/// terminal [`DataFileResult`] (capturing the returned assessment on success).
/// Every wait uses the injectable `sleeper`.
///
/// The bearer comes from `token_provider`, invoked **once per request** so a
/// poll that outlives the ~30-minute JWT TTL can hand back a freshly-refreshed
/// token (wire an [`crate::login::EsvSession`]-backed closure); the fixed-token
/// case is [`fixed_token`]. The loop is bounded three ways: the consecutive
/// not-yet-processed cap, a global `max_total_polls` ceiling (which also stops
/// an alternating-status livelock the per-status cap alone cannot), and a
/// consecutive-transient-failure budget so a single dropped connection or 502
/// HTML page no longer kills the poll (a well-formed response resets it;
/// transient retries count toward `max_total_polls`).
///
/// The status body is read with the float-tolerant [`crate::jsonlite`] reader
/// (a `Run Successful` assessment carries fractional min-entropy the
/// integer-only codec cannot parse); the returned assessment is the untouched
/// raw body, so its floats survive exactly.
///
/// # Errors
/// [`DataFileError::NotYetProcessedTimeout`] on the consecutive-NYP cap,
/// [`DataFileError::PollTimeout`] on the total-poll cap,
/// [`DataFileError::TransientFailuresExhausted`] on the transient-failure
/// budget, [`DataFileError::UnrecognizedStatus`] on an undocumented status,
/// [`DataFileError::ServerError`] on an error payload,
/// [`DataFileError::MalformedResponse`] on a structurally-invalid envelope,
/// or [`DataFileError::Token`] on a token-provider failure.
pub fn poll_data_file<T: EsvTransport>(
    ea_id: &str,
    df_id: &str,
    token_provider: &mut dyn FnMut() -> Result<String, String>,
    transport: &mut T,
    sleeper: &mut dyn Sleeper,
    config: &PollConfig,
) -> Result<DataFileResult, DataFileError> {
    let path = data_file_path(ea_id, df_id);
    let mut consecutive_nyp: u32 = 0;
    let mut consecutive_transient: u32 = 0;
    let mut total_polls: u32 = 0;
    loop {
        if total_polls >= config.max_total_polls {
            return Err(DataFileError::PollTimeout { polls: total_polls });
        }
        total_polls = total_polls.saturating_add(1);

        // Fresh bearer per request so a long poll can outlive the JWT TTL.
        let bearer = token_provider().map_err(DataFileError::Token)?;

        // A transport error or an unparseable body is transient (a dropped
        // connection, a 502 HTML page): tolerate a bounded consecutive run,
        // then surface typed. A well-formed body resets the run.
        let resp = match transport.request("GET", &path, None, &bearer) {
            Ok(r) => r,
            Err(e) => {
                consecutive_transient = consecutive_transient.saturating_add(1);
                if consecutive_transient > config.max_consecutive_transient_failures {
                    return Err(DataFileError::TransientFailuresExhausted {
                        failures: config.max_consecutive_transient_failures,
                        last: format!("transport error: {e}"),
                    });
                }
                sleeper.sleep(config.processing_wait);
                continue;
            }
        };
        let parsed = match parse_status_envelope(&resp.body) {
            Ok(v) => v,
            Err(e) => {
                consecutive_transient = consecutive_transient.saturating_add(1);
                if consecutive_transient > config.max_consecutive_transient_failures {
                    return Err(DataFileError::TransientFailuresExhausted {
                        failures: config.max_consecutive_transient_failures,
                        last: e.to_string(),
                    });
                }
                sleeper.sleep(config.processing_wait);
                continue;
            }
        };
        // A well-formed, parseable body ends the transient run.
        consecutive_transient = 0;

        let payload = payload_element(&parsed)?;
        let raw_status = match payload.get("status").and_then(JsonLite::as_str) {
            Some(s) => s.to_string(),
            None => return Err(status_absent_error(payload, &resp)),
        };
        let id = payload.get("id").and_then(id_to_string);

        match classify_status(&raw_status).poll_decision() {
            PollDecision::Terminal(term) => {
                let assessment = if matches!(term, TerminalStatus::RunSuccessful) {
                    // Capture the assessment losslessly from the untouched
                    // raw body (it carries fractional entropy numbers).
                    Some(resp.body.clone())
                } else {
                    None
                };
                return Ok(DataFileResult {
                    id,
                    status: term,
                    assessment,
                });
            }
            PollDecision::WaitNotYetProcessed => {
                if consecutive_nyp >= config.max_not_yet_processed_polls {
                    return Err(DataFileError::NotYetProcessedTimeout {
                        polls: consecutive_nyp,
                    });
                }
                consecutive_nyp = consecutive_nyp.saturating_add(1);
                sleeper.sleep(config.not_yet_processed_wait);
            }
            PollDecision::WaitProcessing => {
                consecutive_nyp = 0;
                sleeper.sleep(config.processing_wait);
            }
            PollDecision::Unrecognized => {
                return Err(DataFileError::UnrecognizedStatus { status: raw_status });
            }
        }
    }
}

/// Build the error for a status response whose payload carries no `status`
/// field: an explicit `error` field (reference client `data_files.py:22`),
/// else a non-2xx server error, else a malformed-response error.
fn status_absent_error(payload: &JsonLite, resp: &HttpResponse) -> DataFileError {
    if let Some(err) = payload.get("error").and_then(JsonLite::as_str) {
        return DataFileError::ServerError {
            message: err.to_string(),
        };
    }
    if !(200..300).contains(&resp.status) {
        return DataFileError::ServerError {
            message: format!("HTTP {} — {}", resp.status, resp.body),
        };
    }
    DataFileError::MalformedResponse {
        detail: "status response payload has neither `status` nor `error`".to_string(),
    }
}

/// Parse a status-response body with the float-tolerant [`crate::jsonlite`]
/// reader, which reads the `Run Successful` assessment's fractional /
/// exponent-notation min-entropy numbers losslessly (as raw tokens) where the
/// integer-only [`acvp_harness::json`] codec would reject the whole body. A
/// body that does not parse is a [`DataFileError::MalformedResponse`] — the
/// poll loop treats that (like a transport error) as a transient failure.
fn parse_status_envelope(body: &str) -> Result<JsonLite, DataFileError> {
    jsonlite::parse(body).map_err(|e| DataFileError::MalformedResponse {
        detail: format!("parse status response: {e}"),
    })
}

/// Require the ESVP versioned envelope `[{esvVersion}, {payload}, …]` and
/// return the payload element (index 1), delegating to the one shared
/// [`crate::login::esv_payload_element`] validator (which runs over both the
/// integer-only codec and the [`crate::jsonlite`] reader), so the envelope
/// contract cannot drift between the auth/registration parsers and this poll.
fn payload_element(parsed: &JsonLite) -> Result<&JsonLite, DataFileError> {
    crate::login::esv_payload_element(parsed)
        .map_err(|detail| DataFileError::MalformedResponse { detail })
}

/// Render a data-file `id` (a JSON string or number token) as a string.
fn id_to_string(v: &JsonLite) -> Option<String> {
    v.as_str()
        .map(str::to_string)
        .or_else(|| v.as_number_str().map(str::to_string))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::registration::{ConditioningComponent, EntropyRegistration};
    use std::collections::VecDeque;

    // ── Fixtures: transport stub + recording sleeper (as in login.rs) ─

    #[derive(Debug)]
    struct RecordedCall {
        method: String,
        path: String,
        bearer: String,
    }

    struct StubTransport {
        responses: VecDeque<HttpResponse>,
        calls: Vec<RecordedCall>,
    }

    impl StubTransport {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                calls: Vec::new(),
            }
        }
    }

    impl EsvTransport for StubTransport {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            _body: Option<&str>,
            bearer: &str,
        ) -> Result<HttpResponse, String> {
            self.calls.push(RecordedCall {
                method: method.to_string(),
                path: path.to_string(),
                bearer: bearer.to_string(),
            });
            self.responses
                .pop_front()
                .ok_or_else(|| "stub: no more canned responses".to_string())
        }
    }

    #[derive(Default)]
    struct RecordingSleeper {
        slept: Vec<Duration>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(&mut self, dur: Duration) {
            self.slept.push(dur);
        }
    }

    fn status_body(status: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: format!(r#"[{{"esvVersion":"1.0"}},{{"id":42,"status":"{status}"}}]"#),
        }
    }

    // ── Request-shape tests (ISC-98, ISC-100) ─────────────────────────

    #[test]
    fn path_is_full_esv_v1_data_file_path() {
        let up = DataFileUpload::new("101", "11", "raw.bin", vec![0u8; 4]);
        assert_eq!(up.path(), "/esv/v1/entropyAssessments/101/dataFiles/11");
        assert_eq!(
            data_file_path("7", "70"),
            "/esv/v1/entropyAssessments/7/dataFiles/70"
        );
    }

    #[test]
    fn parts_carry_the_data_file_part_key_and_octet_stream_content_type() {
        let up = DataFileUpload::new("1", "2", "raw.bin", vec![1, 2, 3]);
        let parts = up.parts();
        // No sample size → the file part is the only part.
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            MultipartPart::File {
                field_name,
                filename,
                content_type,
                bytes,
            } => {
                assert_eq!(*field_name, "dataFile");
                assert_eq!(*filename, "raw.bin");
                assert_eq!(*content_type, "application/octet-stream");
                assert_eq!(*bytes, &[1, 2, 3]);
            }
            MultipartPart::Field { .. } => panic!("expected the file part"),
        }
    }

    #[test]
    fn sample_size_field_is_capitalized_exactly_and_precedes_the_file() {
        let up = DataFileUpload::new("1", "2", "raw.bin", vec![9])
            .with_sample_size(4)
            .unwrap();
        let parts = up.parts();
        assert_eq!(parts.len(), 2);
        // Field first (data-then-files order), file second.
        match &parts[0] {
            MultipartPart::Field { name, value } => {
                // Exact v1.8 capitalization — never the lowercase spelling.
                assert_eq!(*name, "DataFileSampleSize");
                assert_ne!(*name, "dataFileSampleSize");
                assert_eq!(value, "4");
            }
            MultipartPart::File { .. } => panic!("field must precede the file part"),
        }
        assert!(matches!(parts[1], MultipartPart::File { .. }));
    }

    #[test]
    fn sample_size_is_omitted_when_unset() {
        let up = DataFileUpload::new("1", "2", "raw.bin", vec![0]);
        assert!(up.sample_size.is_none());
        assert!(
            !up.parts()
                .iter()
                .any(|p| matches!(p, MultipartPart::Field { .. }))
        );
    }

    #[test]
    fn sample_size_out_of_range_is_a_typed_error() {
        let base = || DataFileUpload::new("1", "2", "raw.bin", vec![0]);
        assert_eq!(
            base().with_sample_size(0),
            Err(DataFileError::SampleSizeOutOfRange { value: 0 })
        );
        assert_eq!(
            base().with_sample_size(9),
            Err(DataFileError::SampleSizeOutOfRange { value: 9 })
        );
        // The 1..=8 bounds themselves are accepted.
        assert!(base().with_sample_size(1).is_ok());
        assert!(base().with_sample_size(8).is_ok());
    }

    #[test]
    fn to_multipart_body_has_boundary_headers_part_key_and_capitalized_field() {
        let up = DataFileUpload::new("1", "2", "raw.bin", vec![0xAB, 0xCD])
            .with_sample_size(4)
            .unwrap();
        let (content_type, body) = up.to_multipart("BOUNDARY123").unwrap();
        assert_eq!(content_type, "multipart/form-data; boundary=BOUNDARY123");
        let text = String::from_utf8_lossy(&body);
        // Boundary delimiters (opening and closing).
        assert!(text.contains("--BOUNDARY123\r\n"), "{text}");
        assert!(text.contains("--BOUNDARY123--\r\n"), "{text}");
        // Capitalized sample-size field.
        assert!(
            text.contains(
                "Content-Disposition: form-data; name=\"DataFileSampleSize\"\r\n\r\n4\r\n"
            ),
            "{text}"
        );
        assert!(!text.contains("dataFileSampleSize"), "{text}");
        // File part: key, filename, content type.
        assert!(
            text.contains(
                "Content-Disposition: form-data; name=\"dataFile\"; filename=\"raw.bin\"\r\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("Content-Type: application/octet-stream\r\n\r\n"),
            "{text}"
        );
        // Raw file bytes survive verbatim.
        assert!(body.windows(2).any(|w| w == [0xAB, 0xCD]));
    }

    // ── Multipart boundary validation + generation (fix 7) ────────────

    #[test]
    fn serialize_rejects_invalid_boundaries() {
        let up = DataFileUpload::new("1", "2", "raw.bin", vec![1, 2, 3]);
        // Disallowed character.
        assert!(matches!(
            up.to_multipart("bad boundary!"),
            Err(MultipartError::InvalidBoundary { .. })
        ));
        // Empty.
        assert!(matches!(
            up.to_multipart(""),
            Err(MultipartError::InvalidBoundary { .. })
        ));
        // Over 70 characters.
        let long = "a".repeat(71);
        assert!(matches!(
            up.to_multipart(&long),
            Err(MultipartError::InvalidBoundary { .. })
        ));
        // Trailing space (a bchar, but not a valid last char).
        assert!(matches!(
            up.to_multipart("abc "),
            Err(MultipartError::InvalidBoundary { .. })
        ));
        // A valid boundary succeeds.
        assert!(up.to_multipart("abc-123").is_ok());
    }

    #[test]
    fn serialize_detects_a_seeded_boundary_collision() {
        // A file body that literally contains the boundary delimiter would be
        // mis-split by a receiver — a typed collision, no body produced.
        let colliding = b"leading\r\n--BNDRY tail".to_vec();
        let up = DataFileUpload::new("1", "2", "raw.bin", colliding);
        assert_eq!(
            up.to_multipart("BNDRY"),
            Err(MultipartError::BoundaryCollision { part_index: 0 })
        );
        // A leading (CRLF-less) `--BNDRY` at body start also collides.
        let up2 = DataFileUpload::new("1", "2", "raw.bin", b"--BNDRY at start".to_vec());
        assert!(matches!(
            up2.to_multipart("BNDRY"),
            Err(MultipartError::BoundaryCollision { .. })
        ));
    }

    #[test]
    fn generate_boundary_is_absent_from_every_part_and_serializes() {
        // A body that carries the delimiter for the base candidate
        // `oxicryptEsvBoundary0` at a real delimiter position (CRLF-prefixed),
        // forcing generate_boundary to increment past it.
        let body = b"noise\r\n--oxicryptEsvBoundary0 more noise".to_vec();
        let up = DataFileUpload::new("1", "2", "raw.bin", body)
            .with_sample_size(4)
            .unwrap();
        let parts = up.parts();
        let boundary = generate_boundary(&parts);
        // The generated boundary collides with no part body…
        assert!(
            parts
                .iter()
                .all(|p| !body_collides(part_body_bytes(p), &boundary))
        );
        // …is a valid boundary…
        assert!(validate_boundary(&boundary).is_ok());
        // …and it was forced off the colliding base candidate.
        assert_ne!(boundary, "oxicryptEsvBoundary0");
        // …so serialization succeeds with it.
        assert!(up.to_multipart(&boundary).is_ok());
    }

    // ── Status classification (ISC-101) ───────────────────────────────

    #[test]
    fn classify_all_seven_documented_statuses() {
        assert_eq!(
            classify_status("not-yet-processed"),
            DataFileStatus::NotYetProcessed
        );
        assert_eq!(classify_status("Uploaded"), DataFileStatus::Uploaded);
        assert_eq!(classify_status("Run Started"), DataFileStatus::RunStarted);
        assert_eq!(
            classify_status("Run Successful"),
            DataFileStatus::RunSuccessful
        );
        assert_eq!(classify_status("Run Failed"), DataFileStatus::RunFailed);
        assert_eq!(
            classify_status("Run Cancelled"),
            DataFileStatus::RunCancelled
        );
        assert_eq!(classify_status("Error"), DataFileStatus::Error);
    }

    #[test]
    fn classify_is_case_separator_and_spelling_insensitive() {
        // Case + separators (the reference client's `.lower()` tolerance).
        assert_eq!(
            classify_status("NOT_YET_PROCESSED"),
            DataFileStatus::NotYetProcessed
        );
        assert_eq!(
            classify_status("not yet processed"),
            DataFileStatus::NotYetProcessed
        );
        assert_eq!(
            classify_status("run  successful"),
            DataFileStatus::RunSuccessful
        );
        // American spelling of cancelled also maps to the cancelled terminal.
        assert_eq!(
            classify_status("Run Canceled"),
            DataFileStatus::RunCancelled
        );
    }

    #[test]
    fn classify_unrecognized_preserves_the_raw_string() {
        assert_eq!(
            classify_status("Frobnicated"),
            DataFileStatus::Unrecognized("Frobnicated".to_string())
        );
    }

    #[test]
    fn classify_is_exact_not_substring() {
        // "Rerun Successful" CONTAINS "run successful" but must NOT fold to
        // RunSuccessful — exact match, not substring.
        assert_eq!(
            classify_status("Rerun Successful"),
            DataFileStatus::Unrecognized("Rerun Successful".to_string())
        );
        // "Recoverable Error - Retrying" CONTAINS "error" but must NOT fold to
        // Error.
        assert_eq!(
            classify_status("Recoverable Error - Retrying"),
            DataFileStatus::Unrecognized("Recoverable Error - Retrying".to_string())
        );
    }

    // ── Decision function, one arm per status ─────────────────────────

    #[test]
    fn decision_not_yet_processed_waits_and_retries() {
        assert_eq!(
            decide("not-yet-processed"),
            PollDecision::WaitNotYetProcessed
        );
    }

    #[test]
    fn decision_uploaded_keeps_polling() {
        assert_eq!(decide("Uploaded"), PollDecision::WaitProcessing);
    }

    #[test]
    fn decision_run_started_keeps_polling() {
        assert_eq!(decide("Run Started"), PollDecision::WaitProcessing);
    }

    #[test]
    fn decision_run_successful_is_terminal_success() {
        assert_eq!(
            decide("Run Successful"),
            PollDecision::Terminal(TerminalStatus::RunSuccessful)
        );
    }

    #[test]
    fn decision_run_failed_is_terminal() {
        assert_eq!(
            decide("Run Failed"),
            PollDecision::Terminal(TerminalStatus::RunFailed)
        );
    }

    #[test]
    fn decision_run_cancelled_is_terminal() {
        assert_eq!(
            decide("Run Cancelled"),
            PollDecision::Terminal(TerminalStatus::RunCancelled)
        );
    }

    #[test]
    fn decision_error_is_terminal() {
        assert_eq!(
            decide("Error"),
            PollDecision::Terminal(TerminalStatus::Error)
        );
    }

    #[test]
    fn decision_unrecognized_status() {
        assert_eq!(decide("what is this"), PollDecision::Unrecognized);
    }

    // ── Polling loop (ISC-101) ────────────────────────────────────────

    #[test]
    fn poll_runs_through_processing_to_success_and_captures_assessment() {
        // Uploaded → Run Started → Run Successful (carrying results).
        let success = HttpResponse {
            status: 200,
            body: r#"[{"esvVersion":"1.0"},{"id":42,"status":"Run Successful","hOriginal":0.75,"minEntropy":0.7275}]"#.to_string(),
        };
        let mut t = StubTransport::new(vec![
            status_body("Uploaded"),
            status_body("Run Started"),
            success,
        ]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let res = poll_data_file(
            "101",
            "11",
            &mut fixed_token("jwt-oe1"),
            &mut t,
            &mut sl,
            &cfg,
        )
        .unwrap();

        assert_eq!(res.status, TerminalStatus::RunSuccessful);
        assert_eq!(res.id.as_deref(), Some("42"));
        // The returned assessment (second maxwell oracle) is captured as the
        // raw body — the fractional entropy numbers survive verbatim.
        let assessment = res.assessment.unwrap();
        assert!(assessment.contains("\"minEntropy\":0.7275"), "{assessment}");
        assert!(assessment.contains("\"hOriginal\":0.75"), "{assessment}");
        // Three GETs to the data-file path with the bearer; two 30 s
        // processing waits (Uploaded, Run Started), none after success.
        assert_eq!(t.calls.len(), 3);
        for call in &t.calls {
            assert_eq!(call.method, "GET");
            assert_eq!(call.path, "/esv/v1/entropyAssessments/101/dataFiles/11");
            assert_eq!(call.bearer, "jwt-oe1");
        }
        assert_eq!(
            sl.slept,
            vec![Duration::from_secs(30), Duration::from_secs(30)]
        );
    }

    // ── Fix 1: float-tolerant status reads via jsonlite ───────────────

    #[test]
    fn run_successful_body_with_e_notation_float_polls_and_captures_assessment() {
        // The review's exact good case: a Run Successful body carrying an
        // e-notation min-entropy `1.2e-05` yields RunSuccessful with the
        // assessment captured verbatim.
        let success = HttpResponse {
            status: 200,
            body:
                r#"[{"esvVersion":"1.0"},{"id":7,"status":"Run Successful","minEntropy":1.2e-05}]"#
                    .to_string(),
        };
        let mut t = StubTransport::new(vec![success]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let res = poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap();
        assert_eq!(res.status, TerminalStatus::RunSuccessful);
        assert_eq!(res.id.as_deref(), Some("7"));
        assert!(res.assessment.unwrap().contains("1.2e-05"));
    }

    #[test]
    fn malformed_number_body_is_a_malformed_response_at_the_parse_boundary() {
        // The review's exact bad case: `1.2.3` is an invalid numeral, so the
        // whole body is a MalformedResponse (the poll loop then treats a
        // MalformedResponse like a transient failure — see the transient-budget
        // tests below).
        let body = r#"[{"esvVersion":"1.0"},{"id":1.2.3,"status":"Run Successful"}]"#;
        assert!(matches!(
            parse_status_envelope(body),
            Err(DataFileError::MalformedResponse { .. })
        ));
        // A decimal inside a string is left untouched (the old pre-pass hazard).
        let ok = r#"[{"esvVersion":"1.0"},{"esvVersion":"1.0","status":"Uploaded"}]"#;
        assert!(parse_status_envelope(ok).is_ok());
    }

    #[test]
    fn poll_retries_not_yet_processed_then_succeeds() {
        let mut t = StubTransport::new(vec![
            status_body("not-yet-processed"),
            status_body("not-yet-processed"),
            status_body("Run Successful"),
        ]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let res = poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap();
        assert_eq!(res.status, TerminalStatus::RunSuccessful);
        // Two not-yet-processed waits of 30 s recorded.
        assert_eq!(
            sl.slept,
            vec![Duration::from_secs(30), Duration::from_secs(30)]
        );
    }

    #[test]
    fn poll_not_yet_processed_cap_yields_typed_timeout() {
        // cap = 2 tolerated; a 3rd consecutive not-yet-processed times out.
        let cfg = PollConfig {
            max_not_yet_processed_polls: 2,
            ..PollConfig::default()
        };
        let mut t = StubTransport::new(vec![
            status_body("not-yet-processed"),
            status_body("not-yet-processed"),
            status_body("not-yet-processed"),
        ]);
        let mut sl = RecordingSleeper::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        assert_eq!(err, DataFileError::NotYetProcessedTimeout { polls: 2 });
        // Two waits before the third poll trips the cap.
        assert_eq!(sl.slept.len(), 2);
        assert_eq!(t.calls.len(), 3);
    }

    // ── Fix 2: global total-poll bound catches an alternating livelock ─

    #[test]
    fn poll_alternating_statuses_terminate_with_a_total_poll_timeout() {
        // Uploaded ↔ not-yet-processed alternation resets the consecutive-NYP
        // counter forever; only the total-poll cap stops it.
        let cfg = PollConfig {
            max_total_polls: 4,
            ..PollConfig::default()
        };
        let mut t = StubTransport::new(vec![
            status_body("not-yet-processed"),
            status_body("Uploaded"),
            status_body("not-yet-processed"),
            status_body("Uploaded"),
        ]);
        let mut sl = RecordingSleeper::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        assert_eq!(err, DataFileError::PollTimeout { polls: 4 });
        assert_eq!(t.calls.len(), 4);
    }

    // ── Fix 4: transient-failure budget ───────────────────────────────

    #[test]
    fn poll_survives_a_single_transient_malformed_body_to_success() {
        // A 502 HTML page mid-sequence is a transient blip, not fatal.
        let html_502 = HttpResponse {
            status: 502,
            body: "<html><body>502 Bad Gateway</body></html>".to_string(),
        };
        let mut t = StubTransport::new(vec![
            status_body("Uploaded"),
            html_502,
            status_body("Run Successful"),
        ]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let res = poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap();
        assert_eq!(res.status, TerminalStatus::RunSuccessful);
        assert_eq!(t.calls.len(), 3);
    }

    #[test]
    fn poll_gives_up_after_the_transient_budget_is_exhausted() {
        // budget = 2 tolerated; a 3rd consecutive transient failure gives up.
        let cfg = PollConfig {
            max_consecutive_transient_failures: 2,
            ..PollConfig::default()
        };
        let html = || HttpResponse {
            status: 502,
            body: "<html>bad gateway</html>".to_string(),
        };
        let mut t = StubTransport::new(vec![html(), html(), html()]);
        let mut sl = RecordingSleeper::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        match err {
            DataFileError::TransientFailuresExhausted { failures, .. } => {
                assert_eq!(failures, 2);
            }
            other => panic!("expected TransientFailuresExhausted, got {other:?}"),
        }
        assert_eq!(t.calls.len(), 3);
    }

    #[test]
    fn poll_transient_failures_reset_on_a_well_formed_response() {
        // A malformed body, then a good Uploaded (resets the run), then two
        // more malformed bodies: with budget 2 this never exhausts because the
        // Uploaded broke the consecutive run — it ends on the total-poll cap.
        let cfg = PollConfig {
            max_consecutive_transient_failures: 2,
            max_total_polls: 4,
            ..PollConfig::default()
        };
        let html = || HttpResponse {
            status: 502,
            body: "<html/>".to_string(),
        };
        let mut t = StubTransport::new(vec![html(), status_body("Uploaded"), html(), html()]);
        let mut sl = RecordingSleeper::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        assert_eq!(err, DataFileError::PollTimeout { polls: 4 });
    }

    #[test]
    fn poll_run_failed_is_terminal_not_an_endless_loop() {
        // Unlike the reference client (which only treats error/run
        // successful as terminal), Run Failed terminates here.
        let mut t = StubTransport::new(vec![status_body("Run Failed")]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let res = poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap();
        assert_eq!(res.status, TerminalStatus::RunFailed);
        assert!(res.assessment.is_none());
        assert_eq!(t.calls.len(), 1);
        assert!(sl.slept.is_empty());
    }

    #[test]
    fn poll_run_cancelled_is_terminal() {
        let mut t = StubTransport::new(vec![status_body("Run Cancelled")]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let res = poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap();
        assert_eq!(res.status, TerminalStatus::RunCancelled);
        assert!(res.assessment.is_none());
    }

    #[test]
    fn poll_unrecognized_status_is_a_typed_error() {
        let mut t = StubTransport::new(vec![status_body("Frobnicated")]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        assert_eq!(
            err,
            DataFileError::UnrecognizedStatus {
                status: "Frobnicated".to_string()
            }
        );
    }

    #[test]
    fn poll_error_field_without_status_is_a_server_error() {
        let resp = HttpResponse {
            status: 400,
            body: r#"[{"esvVersion":"1.0"},{"error":"data file rejected"}]"#.to_string(),
        };
        let mut t = StubTransport::new(vec![resp]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        assert_eq!(
            err,
            DataFileError::ServerError {
                message: "data file rejected".to_string()
            }
        );
    }

    #[test]
    fn poll_tolerates_trailing_envelope_element() {
        // A third envelope element is ignored; the payload stays at index 1,
        // so a Run Successful still terminates cleanly.
        let resp = HttpResponse {
            status: 200,
            body: r#"[{"esvVersion":"1.0"},{"id":42,"status":"Run Successful"},{"extra":1}]"#
                .to_string(),
        };
        let mut t = StubTransport::new(vec![resp]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let res = poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap();
        assert_eq!(res.status, TerminalStatus::RunSuccessful);
        assert_eq!(res.id.as_deref(), Some("42"));
    }

    #[test]
    fn poll_non_envelope_response_is_malformed() {
        // A bare object parses fine but is not the versioned envelope: a
        // structural (not parse) failure, so it is fatal MalformedResponse.
        let resp = HttpResponse {
            status: 200,
            body: r#"{"status":"Uploaded"}"#.to_string(),
        };
        let mut t = StubTransport::new(vec![resp]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        assert!(matches!(err, DataFileError::MalformedResponse { .. }));
    }

    #[test]
    fn poll_persistent_transport_failure_exhausts_the_transient_budget() {
        // An empty stub errors on every request; a transport error is
        // transient, so it is retried until the budget is exhausted.
        let cfg = PollConfig {
            max_consecutive_transient_failures: 2,
            ..PollConfig::default()
        };
        let mut t = StubTransport::new(vec![]);
        let mut sl = RecordingSleeper::default();
        let err =
            poll_data_file("1", "2", &mut fixed_token("jwt"), &mut t, &mut sl, &cfg).unwrap_err();
        assert!(matches!(
            err,
            DataFileError::TransientFailuresExhausted { failures: 2, .. }
        ));
    }

    // ── Fix 6: token provider ─────────────────────────────────────────

    #[test]
    fn poll_calls_the_token_provider_once_per_request() {
        let mut t =
            StubTransport::new(vec![status_body("Uploaded"), status_body("Run Successful")]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let mut calls = 0u32;
        let mut provider = || -> Result<String, String> {
            calls = calls.saturating_add(1);
            Ok(format!("jwt-{calls}"))
        };
        let res = poll_data_file("1", "2", &mut provider, &mut t, &mut sl, &cfg).unwrap();
        assert_eq!(res.status, TerminalStatus::RunSuccessful);
        // Two requests → the provider was invoked twice, and each request
        // carried the freshly-provided bearer.
        assert_eq!(calls, 2);
        assert_eq!(t.calls[0].bearer, "jwt-1");
        assert_eq!(t.calls[1].bearer, "jwt-2");
    }

    #[test]
    fn poll_token_provider_error_surfaces_typed() {
        let mut t = StubTransport::new(vec![status_body("Run Successful")]);
        let mut sl = RecordingSleeper::default();
        let cfg = PollConfig::default();
        let mut provider = || -> Result<String, String> { Err("no token available".to_string()) };
        let err = poll_data_file("1", "2", &mut provider, &mut t, &mut sl, &cfg).unwrap_err();
        assert_eq!(err, DataFileError::Token("no token available".to_string()));
        // The provider failed before any request went out.
        assert!(t.calls.is_empty());
    }

    // ── Vetted-conditioning refusal (ISC-107, Anti) ───────────────────

    /// A vetted SHA2-256 single-component registration (the oxicrypt case).
    fn vetted_registration() -> EntropyRegistration {
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

    /// A non-vetted, non-bijective conditioning component (uploads allowed).
    fn non_vetted_component(sequence_position: i64) -> ConditioningComponent {
        ConditioningComponent {
            sequence_position,
            vetted: false,
            bijective_claim: Some(false),
            description: "custom xor".to_string(),
            validation_number: None,
            min_nin: 8,
            min_hin: 1.0,
            nw: 8,
            n_out: 8,
            h_out: 1.0,
        }
    }

    #[test]
    fn vetted_config_refuses_a_conditioned_upload_and_builds_no_request() {
        let reg = vetted_registration();
        let err =
            build_conditioned_upload(&reg, 1, "101", "91", "cond.bin", vec![0u8; 4]).unwrap_err();
        assert_eq!(
            err,
            DataFileError::ConditionedUploadForbidden {
                sequence_position: 1,
                reason: ConditionedRefusalReason::Vetted,
            }
        );
    }

    #[test]
    fn bijective_component_refuses_a_conditioned_upload() {
        let mut reg = EntropyRegistration::new_non_iid("jitter", 8, 1.0, 1000, 1000, false);
        let mut cc = non_vetted_component(1);
        cc.bijective_claim = Some(true);
        reg.conditioning.push(cc);
        let err = check_conditioned_upload_allowed(
            &reg,
            &DataFileTarget::ConditionedBits {
                sequence_position: 1,
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            DataFileError::ConditionedUploadForbidden {
                sequence_position: 1,
                reason: ConditionedRefusalReason::Bijective,
            }
        );
    }

    #[test]
    fn non_vetted_non_bijective_component_allows_a_conditioned_upload() {
        let mut reg = EntropyRegistration::new_non_iid("jitter", 8, 1.0, 1000, 1000, false);
        reg.conditioning.push(non_vetted_component(1));
        let up = build_conditioned_upload(&reg, 1, "101", "91", "cond.bin", vec![0u8; 4]).unwrap();
        assert_eq!(up.path(), "/esv/v1/entropyAssessments/101/dataFiles/91");
    }

    #[test]
    fn conditioned_upload_for_missing_component_is_typed() {
        let reg = vetted_registration();
        let err = check_conditioned_upload_allowed(
            &reg,
            &DataFileTarget::ConditionedBits {
                sequence_position: 9,
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            DataFileError::NoSuchConditioningComponent {
                sequence_position: 9
            }
        );
    }

    #[test]
    fn raw_noise_and_restart_uploads_are_always_allowed() {
        let reg = vetted_registration();
        assert_eq!(
            check_conditioned_upload_allowed(&reg, &DataFileTarget::RawNoise),
            Ok(())
        );
        assert_eq!(
            check_conditioned_upload_allowed(&reg, &DataFileTarget::Restart),
            Ok(())
        );
    }
}
