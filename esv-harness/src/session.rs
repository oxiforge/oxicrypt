//! Per-submission session directory (ISC-105 session half, ISC-111).
//!
//! An ESV submission is a multi-step, multi-object flow — register N
//! operating environments, upload two-or-more data files per OE, upload the
//! supporting documents, then certify — that an attended run may interrupt
//! (a failed submit, a dropped connection, a laptop suspend) and resume
//! later. This module makes that progress durable, mirroring the
//! `acvp-harness` `SessionDir` philosophy: a deterministic per-submission
//! directory, everything written **before** the corresponding network
//! submit, so a fresh process can reload it and know exactly where the
//! submission stands.
//!
//! Where `acvp-harness` tracks a single `(tsId, vsId)` compute, an ESV
//! submission fans out over many objects and stages, so the state model is
//! richer: an **append-only JSON-lines event log** (`events.jsonl`) is the
//! single source of truth. Each state-advancing step appends one line —
//! serialized by the shared `acvp_harness::json` codec's
//! [`to_compact_string`](acvp_harness::json::to_compact_string), one JSON
//! object per line — and only then runs the submit
//! ([`SessionDir::persist_then`]). A torn final write costs only the last
//! event; every earlier line stays intact and replayable
//! ([`SessionDir::load_state`]).
//!
//! # On-disk layout
//!
//! ```text
//! <sessions-root>/<entropyId>/
//!   events.jsonl                    append-only event log (source of truth)
//!   assessment-<eaId>-<slot>.json   NIST's "Run Successful" assessment body,
//!                                   stored verbatim (the second maxwell oracle)
//!   certify-response.json           the certify response, stored verbatim
//! ```
//!
//! `<entropyId>` is the submitter's tracking id (the TID); it is validated
//! to be a safe filename token (rejecting `.`, `..`, path separators, and
//! anything outside `[A-Za-z0-9._-]`) so it can never escape the sessions
//! root.
//!
//! # Credentials
//!
//! Per-object scoped JWTs (the OE `accessToken`s from registration, the
//! supporting-document tokens) **are** stored — the protocol requires
//! tracking them to reference each object at certify, exactly as
//! `acvp-harness` caches its session-bound token. The TOTP secret is a
//! process-lifetime credential and is **never** written here.
//!
//! # Numbers
//!
//! Every tracked field is an integer or a string, so the codec's
//! integer-only number model fits directly (no floats to encode as raw
//! strings). NIST's returned assessment bodies — the only place floats
//! appear — are stored **verbatim** as sidecar files, never round-tripped
//! through the codec, so their floating-point values are preserved exactly.

use std::path::{Path, PathBuf};

use acvp_harness::json::{self, JsonValue};

use crate::registration::OeRegistration;
use crate::supportdocs::{SdType, SupportingDoc};

/// File name of the append-only JSON-lines event log.
pub const EVENTS_FILE: &str = "events.jsonl";
/// File name of the stored-verbatim certify response.
pub const CERTIFY_RESPONSE_FILE: &str = "certify-response.json";

// ── Value types ───────────────────────────────────────────────────────

/// Which data-file slot an upload targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The raw-noise data-file slot.
    RawNoise,
    /// The restart-test data-file slot.
    Restart,
    /// A conditioned-bits slot (only on a non-vetted conditioning path;
    /// never produced by the vetted oxicrypt source).
    Conditioned,
}

impl Slot {
    /// The on-disk / log token for this slot.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RawNoise => "rawNoise",
            Self::Restart => "restart",
            Self::Conditioned => "conditioned",
        }
    }

    /// Parse a slot token back into a variant. `None` for anything else.
    #[must_use]
    pub fn from_str_token(s: &str) -> Option<Self> {
        match s {
            "rawNoise" => Some(Self::RawNoise),
            "restart" => Some(Self::Restart),
            "conditioned" => Some(Self::Conditioned),
            _ => None,
        }
    }
}

/// Which certify path completed the submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifyMode {
    /// A full §7.1 certify.
    Full,
    /// An §7.2 AddOE certify.
    AddOe,
}

impl CertifyMode {
    /// The on-disk / log token for this mode.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::AddOe => "addOE",
        }
    }

    /// Parse a mode token back into a variant. `None` for anything else.
    #[must_use]
    pub fn from_str_token(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Self::Full),
            "addOE" => Some(Self::AddOe),
            _ => None,
        }
    }
}

/// A data-file slot reference recorded from registration (its URL + id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRef {
    /// Full server URL of the slot.
    pub url: String,
    /// The slot id (last path segment).
    pub id: String,
}

/// One operating environment's registration record, as tracked in the
/// session (its eaId, data-file slots, and scoped JWT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OeRecord {
    /// The entropy-assessment id.
    pub ea_id: String,
    /// Full URL of the entropy assessment.
    pub url: String,
    /// The raw-noise slot, when registration provided one.
    pub raw_noise: Option<SlotRef>,
    /// The restart-test slot, when registration provided one.
    pub restart: Option<SlotRef>,
    /// This OE's scoped JWT.
    pub access_token: String,
}

impl OeRecord {
    /// Capture the trackable fields of an [`OeRegistration`].
    #[must_use]
    pub fn from_registration(reg: &OeRegistration) -> Self {
        let slot = |r: &Option<crate::registration::DataFileRef>| {
            r.as_ref().map(|d| SlotRef {
                url: d.url.clone(),
                id: d.id.clone(),
            })
        };
        Self {
            ea_id: reg.ea_id.clone(),
            url: reg.url.clone(),
            raw_noise: slot(&reg.raw_noise),
            restart: slot(&reg.restart),
            access_token: reg.access_token.clone(),
        }
    }
}

/// A recorded data-file upload (which OE, which slot, the assigned dfId).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedFile {
    /// The entropy-assessment id the slot belongs to.
    pub ea_id: String,
    /// Which slot was uploaded.
    pub slot: Slot,
    /// The data-file id.
    pub df_id: String,
}

/// A captured "Run Successful" assessment sidecar (the second maxwell
/// oracle) — which OE/slot it belongs to, and the file it was stored in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedAssessment {
    /// The entropy-assessment id.
    pub ea_id: String,
    /// Which slot produced it.
    pub slot: Slot,
    /// The sidecar file name (relative to the session directory).
    pub file: String,
}

// ── Events ────────────────────────────────────────────────────────────

/// One state-advancing event appended to `events.jsonl` before its submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The registration milestone: the submission's tracking id, ACVTS
    /// module, and the per-OE fan-out.
    Registered {
        /// The submitter tracking id (TID).
        entropy_id: String,
        /// The ACVTS module id (0 when not yet known).
        module_id: i64,
        /// One record per registered operating environment.
        oes: Vec<OeRecord>,
    },
    /// A data-file upload for one OE slot.
    FileUploaded {
        /// The entropy-assessment id.
        ea_id: String,
        /// Which slot.
        slot: Slot,
        /// The data-file id.
        df_id: String,
    },
    /// A "Run Successful" assessment body captured to a sidecar file.
    AssessmentCaptured {
        /// The entropy-assessment id.
        ea_id: String,
        /// Which slot.
        slot: Slot,
        /// The sidecar file name.
        file: String,
    },
    /// A supporting document upload.
    DocUploaded {
        /// The supporting-document id.
        sd_id: i64,
        /// The document type.
        sd_type: SdType,
        /// The scoped JWT for this document.
        access_token: String,
    },
    /// The terminal certify step.
    Certified {
        /// Which certify path completed.
        mode: CertifyMode,
        /// The stored-verbatim response file name.
        response_file: String,
    },
}

impl Event {
    /// Build the `registered` event from a batch of OE registrations.
    #[must_use]
    pub fn registered(entropy_id: &str, module_id: i64, regs: &[OeRegistration]) -> Self {
        Self::Registered {
            entropy_id: entropy_id.to_string(),
            module_id,
            oes: regs.iter().map(OeRecord::from_registration).collect(),
        }
    }

    /// Serialize this event to its JSON-lines value.
    fn to_json(&self) -> JsonValue {
        match self {
            Self::Registered {
                entropy_id,
                module_id,
                oes,
            } => obj(vec![
                ("kind", JsonValue::String("registered".to_string())),
                ("entropyId", JsonValue::String(entropy_id.clone())),
                ("moduleId", JsonValue::Number(*module_id)),
                (
                    "oes",
                    JsonValue::Array(oes.iter().map(oe_to_json).collect()),
                ),
            ]),
            Self::FileUploaded { ea_id, slot, df_id } => obj(vec![
                ("kind", JsonValue::String("fileUploaded".to_string())),
                ("eaId", JsonValue::String(ea_id.clone())),
                ("slot", JsonValue::String(slot.as_str().to_string())),
                ("dfId", JsonValue::String(df_id.clone())),
            ]),
            Self::AssessmentCaptured { ea_id, slot, file } => obj(vec![
                ("kind", JsonValue::String("assessmentCaptured".to_string())),
                ("eaId", JsonValue::String(ea_id.clone())),
                ("slot", JsonValue::String(slot.as_str().to_string())),
                ("file", JsonValue::String(file.clone())),
            ]),
            Self::DocUploaded {
                sd_id,
                sd_type,
                access_token,
            } => obj(vec![
                ("kind", JsonValue::String("docUploaded".to_string())),
                ("sdId", JsonValue::Number(*sd_id)),
                ("sdType", JsonValue::String(sd_type.wire_str().to_string())),
                ("accessToken", JsonValue::String(access_token.clone())),
            ]),
            Self::Certified {
                mode,
                response_file,
            } => obj(vec![
                ("kind", JsonValue::String("certified".to_string())),
                ("mode", JsonValue::String(mode.as_str().to_string())),
                ("responseFile", JsonValue::String(response_file.clone())),
            ]),
        }
    }

    /// Parse one event value back from the log.
    fn from_json(v: &JsonValue) -> Result<Self, String> {
        let kind = str_field(v, "kind")?;
        match kind {
            "registered" => {
                let oes = v
                    .get("oes")
                    .and_then(JsonValue::as_array)
                    .ok_or("registered event missing `oes` array")?;
                let mut records = Vec::with_capacity(oes.len());
                for oe in oes {
                    records.push(oe_from_json(oe)?);
                }
                Ok(Self::Registered {
                    entropy_id: str_field(v, "entropyId")?.to_string(),
                    module_id: i64_field(v, "moduleId")?,
                    oes: records,
                })
            }
            "fileUploaded" => Ok(Self::FileUploaded {
                ea_id: str_field(v, "eaId")?.to_string(),
                slot: slot_field(v)?,
                df_id: str_field(v, "dfId")?.to_string(),
            }),
            "assessmentCaptured" => Ok(Self::AssessmentCaptured {
                ea_id: str_field(v, "eaId")?.to_string(),
                slot: slot_field(v)?,
                file: str_field(v, "file")?.to_string(),
            }),
            "docUploaded" => {
                let sd_type_str = str_field(v, "sdType")?;
                let sd_type = SdType::from_wire(sd_type_str).ok_or_else(|| {
                    format!("docUploaded event has unknown sdType {sd_type_str:?}")
                })?;
                Ok(Self::DocUploaded {
                    sd_id: i64_field(v, "sdId")?,
                    sd_type,
                    access_token: str_field(v, "accessToken")?.to_string(),
                })
            }
            "certified" => {
                let mode_str = str_field(v, "mode")?;
                let mode = CertifyMode::from_str_token(mode_str)
                    .ok_or_else(|| format!("certified event has unknown mode {mode_str:?}"))?;
                Ok(Self::Certified {
                    mode,
                    response_file: str_field(v, "responseFile")?.to_string(),
                })
            }
            other => Err(format!("unknown event kind {other:?}")),
        }
    }
}

// ── Reconstructed state ───────────────────────────────────────────────

/// The coarse stage a submission has reached, derived from the events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionStage {
    /// No events yet.
    Empty,
    /// Registered (OEs known), no files uploaded.
    Registered,
    /// At least one data file uploaded.
    FilesUploaded,
    /// At least one supporting document uploaded.
    DocsUploaded,
    /// Certified (terminal).
    Certified,
}

/// The full submission state, reconstructed by replaying `events.jsonl`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubmissionState {
    /// The submitter tracking id, once a `registered` event was seen.
    pub entropy_id: Option<String>,
    /// The ACVTS module id, once known.
    pub module_id: Option<i64>,
    /// The per-OE registration records.
    pub oes: Vec<OeRecord>,
    /// Every recorded data-file upload.
    pub uploaded_files: Vec<UploadedFile>,
    /// Every captured "Run Successful" assessment sidecar.
    pub captured_assessments: Vec<CapturedAssessment>,
    /// Every uploaded supporting document.
    pub docs: Vec<SupportingDoc>,
    /// The certify mode, once the submission was certified.
    pub certified: Option<CertifyMode>,
}

impl SubmissionState {
    /// Fold one event into the state.
    fn apply(&mut self, event: Event) {
        match event {
            Event::Registered {
                entropy_id,
                module_id,
                oes,
            } => {
                self.entropy_id = Some(entropy_id);
                self.module_id = Some(module_id);
                self.oes.extend(oes);
            }
            Event::FileUploaded { ea_id, slot, df_id } => {
                self.uploaded_files
                    .push(UploadedFile { ea_id, slot, df_id });
            }
            Event::AssessmentCaptured { ea_id, slot, file } => {
                self.captured_assessments
                    .push(CapturedAssessment { ea_id, slot, file });
            }
            Event::DocUploaded {
                sd_id,
                sd_type,
                access_token,
            } => {
                self.docs.push(SupportingDoc {
                    sd_id,
                    sd_type,
                    access_token,
                });
            }
            Event::Certified { mode, .. } => {
                self.certified = Some(mode);
            }
        }
    }

    /// The coarse stage this submission has reached.
    #[must_use]
    pub fn stage(&self) -> SubmissionStage {
        if self.certified.is_some() {
            SubmissionStage::Certified
        } else if !self.docs.is_empty() {
            SubmissionStage::DocsUploaded
        } else if !self.uploaded_files.is_empty() {
            SubmissionStage::FilesUploaded
        } else if !self.oes.is_empty() {
            SubmissionStage::Registered
        } else {
            SubmissionStage::Empty
        }
    }
}

// ── Session directory ─────────────────────────────────────────────────

/// Handle to one `<sessions-root>/<entropyId>/` submission directory.
///
/// [`Self::create`] is the write path (creates the directory);
/// [`Self::open`] is the resume path (requires it to exist). The entropy
/// id is validated to be a safe filename token so it cannot escape the
/// sessions root.
#[derive(Debug)]
pub struct SessionDir {
    dir: PathBuf,
    entropy_id: String,
}

/// True when `id` is a safe single-segment directory name — non-empty, not
/// `.`/`..`, no path separators, and only `[A-Za-z0-9._-]`.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl SessionDir {
    /// Validate the entropy id and compute the session directory path.
    fn dir_for(sessions_root: &Path, entropy_id: &str) -> Result<PathBuf, String> {
        if !is_safe_id(entropy_id) {
            return Err(format!(
                "unsafe entropyId {entropy_id:?}: must be a non-empty [A-Za-z0-9._-] token \
                 (not '.', '..', or containing a path separator)"
            ));
        }
        Ok(sessions_root.join(entropy_id))
    }

    /// Create (or reuse) the session directory for `entropy_id`.
    ///
    /// # Errors
    /// An unsafe `entropy_id`, or a filesystem failure creating the dir.
    pub fn create(sessions_root: &str, entropy_id: &str) -> Result<Self, String> {
        let dir = Self::dir_for(Path::new(sessions_root), entropy_id)?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("create session dir {}: {e}", dir.display()))?;
        Ok(Self {
            dir,
            entropy_id: entropy_id.to_string(),
        })
    }

    /// Open an existing session directory for `entropy_id` (the resume
    /// path).
    ///
    /// # Errors
    /// An unsafe `entropy_id`, or a missing directory (nothing to resume).
    pub fn open(sessions_root: &str, entropy_id: &str) -> Result<Self, String> {
        let dir = Self::dir_for(Path::new(sessions_root), entropy_id)?;
        if !dir.is_dir() {
            return Err(format!(
                "no session at {}: nothing to resume (the directory is created at registration; \
                 check the entropyId and the sessions root)",
                dir.display()
            ));
        }
        Ok(Self {
            dir,
            entropy_id: entropy_id.to_string(),
        })
    }

    /// Path of the session directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The entropy id (TID) this directory belongs to.
    #[must_use]
    pub fn entropy_id(&self) -> &str {
        &self.entropy_id
    }

    /// Append one event line to `events.jsonl`, flushing it to the OS before
    /// returning. This is the durability primitive: the event is on disk
    /// before any dependent submit runs.
    ///
    /// # Errors
    /// A filesystem failure opening or writing the log.
    pub fn append_event(&self, event: &Event) -> Result<(), String> {
        use std::io::Write as _;
        let line = json::to_compact_string(&event.to_json());
        let path = self.dir.join(EVENTS_FILE);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|e| format!("append event to {}: {e}", path.display()))?;
        Ok(())
    }

    /// Persist `event`, then run `submit`. The event is durable on disk
    /// **before** `submit` executes, so a crash during submit leaves a
    /// record the resume path can act on — the persist-before-submit
    /// invariant, made a single call so ordering cannot be transposed.
    ///
    /// # Errors
    /// A persistence failure (before `submit` runs) or `submit`'s own error.
    pub fn persist_then<F, R>(&self, event: &Event, submit: F) -> Result<R, String>
    where
        F: FnOnce() -> Result<R, String>,
    {
        self.append_event(event)?;
        submit()
    }

    /// Store a "Run Successful" assessment body **verbatim** to a sidecar
    /// file `assessment-<eaId>-<slot>.json`, returning the file name. The
    /// bytes are written exactly as received (never re-encoded), so any
    /// floating-point values in NIST's assessment are preserved.
    ///
    /// # Errors
    /// A filesystem failure writing the sidecar.
    pub fn store_assessment(&self, ea_id: &str, slot: Slot, body: &str) -> Result<String, String> {
        let name = format!("assessment-{ea_id}-{}.json", slot.as_str());
        let path = self.dir.join(&name);
        std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(name)
    }

    /// Store the certify response **verbatim** to `certify-response.json`,
    /// returning the file name.
    ///
    /// # Errors
    /// A filesystem failure writing the file.
    pub fn store_certify_response(&self, body: &str) -> Result<String, String> {
        let path = self.dir.join(CERTIFY_RESPONSE_FILE);
        std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(CERTIFY_RESPONSE_FILE.to_string())
    }

    /// Read back a stored sidecar file (assessment or certify response) by
    /// name, exactly as written.
    ///
    /// # Errors
    /// A filesystem failure reading the file.
    pub fn read_sidecar(&self, name: &str) -> Result<String, String> {
        let path = self.dir.join(name);
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
    }

    /// Replay `events.jsonl` and reconstruct the submission state. A missing
    /// log yields the empty state (nothing has happened yet).
    ///
    /// # Errors
    /// A filesystem read failure, or a malformed event line (which names the
    /// offending line number).
    pub fn load_state(&self) -> Result<SubmissionState, String> {
        let path = self.dir.join(EVENTS_FILE);
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SubmissionState::default());
            }
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let mut state = SubmissionState::default();
        for (idx, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value = json::parse(line)
                .map_err(|e| format!("parse event log line {}: {e}", idx.saturating_add(1)))?;
            let event = Event::from_json(&value)
                .map_err(|e| format!("event log line {}: {e}", idx.saturating_add(1)))?;
            state.apply(event);
        }
        Ok(state)
    }
}

// ── JSON helpers ──────────────────────────────────────────────────────

/// Build an object value from `(key, value)` pairs given `&str` keys.
fn obj(pairs: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Read a required string field, or a typed error naming it.
fn str_field<'a>(v: &'a JsonValue, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("event missing string field {key:?}"))
}

/// Read a required integer field, or a typed error naming it.
fn i64_field(v: &JsonValue, key: &str) -> Result<i64, String> {
    v.get(key)
        .and_then(JsonValue::as_i64)
        .ok_or_else(|| format!("event missing integer field {key:?}"))
}

/// Read the required `slot` field and map it to a [`Slot`].
fn slot_field(v: &JsonValue) -> Result<Slot, String> {
    let s = str_field(v, "slot")?;
    Slot::from_str_token(s).ok_or_else(|| format!("event has unknown slot {s:?}"))
}

/// Serialize an [`OeRecord`] to its log object.
fn oe_to_json(oe: &OeRecord) -> JsonValue {
    let slot_ref = |r: &Option<SlotRef>| match r {
        Some(s) => obj(vec![
            ("url", JsonValue::String(s.url.clone())),
            ("id", JsonValue::String(s.id.clone())),
        ]),
        None => JsonValue::Null,
    };
    obj(vec![
        ("eaId", JsonValue::String(oe.ea_id.clone())),
        ("url", JsonValue::String(oe.url.clone())),
        ("rawNoise", slot_ref(&oe.raw_noise)),
        ("restart", slot_ref(&oe.restart)),
        ("accessToken", JsonValue::String(oe.access_token.clone())),
    ])
}

/// Parse an [`OeRecord`] from its log object.
fn oe_from_json(v: &JsonValue) -> Result<OeRecord, String> {
    let slot_ref = |key: &str| -> Result<Option<SlotRef>, String> {
        match v.get(key) {
            None | Some(JsonValue::Null) => Ok(None),
            Some(obj) => Ok(Some(SlotRef {
                url: str_field(obj, "url")?.to_string(),
                id: str_field(obj, "id")?.to_string(),
            })),
        }
    };
    Ok(OeRecord {
        ea_id: str_field(v, "eaId")?.to_string(),
        url: str_field(v, "url")?.to_string(),
        raw_noise: slot_ref("rawNoise")?,
        restart: slot_ref("restart")?,
        access_token: str_field(v, "accessToken")?.to_string(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::registration::{DataFileRef, OeRegistration};
    use std::cell::Cell;
    use std::path::PathBuf;

    /// Fresh per-test scratch root under the OS temp dir. The tag keeps
    /// parallel test threads from colliding.
    fn temp_root(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("oxicrypt-esv-session-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn root_str(root: &Path) -> &str {
        root.to_str().unwrap()
    }

    fn sample_reg(ea_id: &str) -> OeRegistration {
        OeRegistration {
            url: format!("https://h/esv/v1/entropyAssessments/{ea_id}"),
            ea_id: ea_id.to_string(),
            raw_noise: Some(DataFileRef {
                url: format!("https://h/.../dataFiles/{ea_id}0"),
                id: format!("{ea_id}0"),
            }),
            restart: Some(DataFileRef {
                url: format!("https://h/.../dataFiles/{ea_id}1"),
                id: format!("{ea_id}1"),
            }),
            conditioned: vec![],
            access_token: format!("oe-tok-{ea_id}"),
        }
    }

    // ── Safe-id guard ─────────────────────────────────────────────────

    #[test]
    fn rejects_unsafe_entropy_ids() {
        let root = temp_root("unsafe");
        for bad in ["", ".", "..", "a/b", "a\\b", "../escape", "a b"] {
            assert!(
                SessionDir::create(root_str(&root), bad).is_err(),
                "should reject {bad:?}"
            );
        }
        assert!(SessionDir::create(root_str(&root), "TID-0001.a_b").is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Directory determinism + empty state ───────────────────────────

    #[test]
    fn create_is_deterministic_and_empty_state_loads() {
        let root = temp_root("empty");
        let s = SessionDir::create(root_str(&root), "TID1").unwrap();
        assert!(s.path().ends_with("TID1"));
        assert_eq!(s.entropy_id(), "TID1");
        // No events yet → empty state, stage Empty.
        let state = s.load_state().unwrap();
        assert_eq!(state, SubmissionState::default());
        assert_eq!(state.stage(), SubmissionStage::Empty);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_missing_is_a_clear_error() {
        let root = temp_root("open-missing");
        let err = SessionDir::open(root_str(&root), "NOPE").unwrap_err();
        assert!(err.contains("NOPE"), "{err}");
        assert!(err.contains("nothing to resume"), "{err}");
    }

    // ── Full round-trip through all stages ────────────────────────────

    #[test]
    fn full_submission_round_trip_and_resume() {
        let root = temp_root("round-trip");
        let s = SessionDir::create(root_str(&root), "TID-9").unwrap();

        // Registered (two OEs).
        let regs = [sample_reg("11"), sample_reg("22")];
        s.append_event(&Event::registered("TID-9", 3, &regs))
            .unwrap();

        // A fresh handle (a new process) can see the state.
        let resumed = SessionDir::open(root_str(&root), "TID-9").unwrap();
        let st = resumed.load_state().unwrap();
        assert_eq!(st.stage(), SubmissionStage::Registered);
        assert_eq!(st.entropy_id.as_deref(), Some("TID-9"));
        assert_eq!(st.module_id, Some(3));
        assert_eq!(st.oes.len(), 2);
        assert_eq!(st.oes[0].ea_id, "11");
        assert_eq!(st.oes[0].raw_noise.as_ref().unwrap().id, "110");
        assert_eq!(st.oes[0].access_token, "oe-tok-11");

        // Files uploaded.
        s.append_event(&Event::FileUploaded {
            ea_id: "11".to_string(),
            slot: Slot::RawNoise,
            df_id: "110".to_string(),
        })
        .unwrap();
        s.append_event(&Event::FileUploaded {
            ea_id: "11".to_string(),
            slot: Slot::Restart,
            df_id: "111".to_string(),
        })
        .unwrap();
        // A captured assessment (stored verbatim, floats preserved).
        let raw_assessment = r#"[{"esvVersion":"1.0"},{"status":"Run Successful","hOriginal":0.7552,"hBitstring":0.91}]"#;
        let file = s
            .store_assessment("11", Slot::RawNoise, raw_assessment)
            .unwrap();
        s.append_event(&Event::AssessmentCaptured {
            ea_id: "11".to_string(),
            slot: Slot::RawNoise,
            file: file.clone(),
        })
        .unwrap();
        assert_eq!(s.read_sidecar(&file).unwrap(), raw_assessment);
        assert_eq!(
            s.load_state().unwrap().stage(),
            SubmissionStage::FilesUploaded
        );

        // Docs uploaded.
        s.append_event(&Event::DocUploaded {
            sd_id: 5,
            sd_type: SdType::EntropyAssessmentReport,
            access_token: "sd-tok".to_string(),
        })
        .unwrap();
        assert_eq!(
            s.load_state().unwrap().stage(),
            SubmissionStage::DocsUploaded
        );

        // Certified.
        let cert_body = r#"[{"esvVersion":"1.0"},{"entropyCertificate":"E1"}]"#;
        let cf = s.store_certify_response(cert_body).unwrap();
        s.append_event(&Event::Certified {
            mode: CertifyMode::Full,
            response_file: cf,
        })
        .unwrap();

        // Final resume from a fresh handle: identical, terminal state.
        let final_state = SessionDir::open(root_str(&root), "TID-9")
            .unwrap()
            .load_state()
            .unwrap();
        assert_eq!(final_state.stage(), SubmissionStage::Certified);
        assert_eq!(final_state.certified, Some(CertifyMode::Full));
        assert_eq!(final_state.uploaded_files.len(), 2);
        assert_eq!(final_state.captured_assessments.len(), 1);
        assert_eq!(final_state.docs.len(), 1);
        assert_eq!(final_state.docs[0].sd_type, SdType::EntropyAssessmentReport);
        // The verbatim certify body survived.
        assert_eq!(
            SessionDir::open(root_str(&root), "TID-9")
                .unwrap()
                .read_sidecar(CERTIFY_RESPONSE_FILE)
                .unwrap(),
            cert_body
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Persist-before-submit ordering (recording fake) ───────────────

    #[test]
    fn persist_then_writes_the_event_before_submit_runs() {
        let root = temp_root("persist-order");
        let s = SessionDir::create(root_str(&root), "TIDP").unwrap();

        let event = Event::FileUploaded {
            ea_id: "11".to_string(),
            slot: Slot::RawNoise,
            df_id: "110".to_string(),
        };
        let seen_on_disk_when_submit_ran = Cell::new(false);
        // The submit closure inspects the log AT THE MOMENT it runs: the
        // event must already be persisted.
        s.persist_then(&event, || {
            let st = s.load_state().unwrap();
            seen_on_disk_when_submit_ran.set(!st.uploaded_files.is_empty());
            Ok::<(), String>(())
        })
        .unwrap();
        assert!(
            seen_on_disk_when_submit_ran.get(),
            "event was durable before the submit closure ran"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn persist_then_persists_even_when_submit_fails() {
        let root = temp_root("persist-fail");
        let s = SessionDir::create(root_str(&root), "TIDF").unwrap();
        let event = Event::DocUploaded {
            sd_id: 1,
            sd_type: SdType::PublicUseDocument,
            access_token: "t".to_string(),
        };
        let out: Result<(), String> = s.persist_then(&event, || Err("network died".to_string()));
        assert!(out.is_err());
        // The event is durable despite the submit failure — resume sees it.
        let st = SessionDir::open(root_str(&root), "TIDF")
            .unwrap()
            .load_state()
            .unwrap();
        assert_eq!(st.docs.len(), 1);
        assert_eq!(st.docs[0].sd_id, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Event log is compact single lines ─────────────────────────────

    #[test]
    fn events_are_one_json_object_per_line() {
        let root = temp_root("jsonl");
        let s = SessionDir::create(root_str(&root), "TIDL").unwrap();
        s.append_event(&Event::registered("TIDL", 1, &[sample_reg("7")]))
            .unwrap();
        s.append_event(&Event::DocUploaded {
            sd_id: 2,
            sd_type: SdType::Other,
            access_token: "t".to_string(),
        })
        .unwrap();
        let raw = s.read_sidecar(EVENTS_FILE).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            // Each line is exactly one parseable JSON object.
            let v = json::parse(line).unwrap();
            assert!(v.get("kind").is_some(), "each line has a kind: {line}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Malformed line names its line number ───────────────────────────

    #[test]
    fn malformed_event_line_is_a_clear_error() {
        let root = temp_root("malformed");
        let s = SessionDir::create(root_str(&root), "TIDM").unwrap();
        s.append_event(&Event::DocUploaded {
            sd_id: 1,
            sd_type: SdType::Other,
            access_token: "t".to_string(),
        })
        .unwrap();
        // Corrupt the log with a second, bad line.
        let path = s.path().join(EVENTS_FILE);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str("{not valid json\n");
        std::fs::write(&path, content).unwrap();
        let err = s.load_state().unwrap_err();
        assert!(err.contains("line 2"), "names the line: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Event JSON round-trips ────────────────────────────────────────

    #[test]
    fn every_event_kind_round_trips_through_json() {
        let events = vec![
            Event::registered("T", 9, &[sample_reg("11")]),
            Event::FileUploaded {
                ea_id: "11".to_string(),
                slot: Slot::Restart,
                df_id: "111".to_string(),
            },
            Event::AssessmentCaptured {
                ea_id: "11".to_string(),
                slot: Slot::RawNoise,
                file: "assessment-11-rawNoise.json".to_string(),
            },
            Event::DocUploaded {
                sd_id: 3,
                sd_type: SdType::DataCollectionAttestation,
                access_token: "tok".to_string(),
            },
            Event::Certified {
                mode: CertifyMode::AddOe,
                response_file: CERTIFY_RESPONSE_FILE.to_string(),
            },
        ];
        for e in events {
            let line = json::to_compact_string(&e.to_json());
            let parsed = Event::from_json(&json::parse(&line).unwrap()).unwrap();
            assert_eq!(parsed, e);
        }
    }
}
