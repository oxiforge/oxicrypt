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
//! richer: an **append-only JSON-lines log** (`events.jsonl`) is the single
//! source of truth, one JSON object per line, serialized by the shared
//! `acvp_harness::json` codec's
//! [`to_compact_string`](acvp_harness::json::to_compact_string).
//!
//! # Intent-then-outcome durability
//!
//! Every server-facing step records **two** lines: first an [`Intent`] with
//! only locally-known data (what is about to be attempted), then — after the
//! network call — an outcome [`Event`] built from the server response
//! ([`SessionDir::persist_intent_then`] appends both in order). The intent
//! genuinely persists *before* the submit, because an outcome cannot: every
//! event carries server-assigned data (the per-OE tokens/eaIds, a dfId, an
//! sdId, the certify response) that does not exist until the response comes
//! back. Each append is written as one buffered newline-terminated record and
//! **fsync'd**, so durability holds against power loss, not just a process
//! crash.
//!
//! On resume ([`SessionDir::load_state`]) the log replays: an outcome
//! supersedes its preceding intent, so a completed step reconstructs cleanly;
//! an intent with **no** following outcome is a *dangling intent* — the action
//! may have taken effect server-side but was never confirmed — surfaced as
//! [`SubmissionStage::Interrupted`] (verify before retrying) rather than
//! silently re-submitted. A torn final write (a partial line with no trailing
//! newline, the residue of a crashed append) costs only that line: it is
//! dropped and recorded, and every earlier record stays intact and replayable.
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

// ── Intents (the pre-submit half of intent-then-outcome) ──────────────

/// The intent to perform a network side-effect, appended to the log — with
/// only **locally-known** data — *before* the submit runs.
///
/// Every [`Event`] records server-assigned data (a `Registered`'s per-OE
/// tokens and eaIds, a `FileUploaded`'s dfId, a `DocUploaded`'s sdId, a
/// `Certified`'s response), so an event cannot exist until *after* the
/// response. An intent, carrying only what is known before the call, genuinely
/// persists first. A matching outcome event appended after the submit
/// supersedes it; an intent with **no** following outcome is a *dangling
/// intent* — the action may have taken effect server-side but was never
/// confirmed, so resume surfaces it as [`SubmissionStage::Interrupted`]
/// (verify before retrying) instead of blindly re-submitting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// About to register the entropy source. The ACVTS module and the
    /// operating-environment count are known before the call; the per-OE
    /// server data (eaIds, tokens, slots) is not.
    Register {
        /// The ACVTS module id (0 when not yet known).
        module_id: i64,
        /// How many operating environments the registration declares.
        oe_count: usize,
    },
    /// About to upload a data file to an OE slot (both known before the call).
    UploadFile {
        /// The entropy-assessment id the slot belongs to.
        ea_id: String,
        /// Which slot.
        slot: Slot,
    },
    /// About to upload a supporting document (both known before the call).
    UploadDoc {
        /// The document type.
        sd_type: SdType,
        /// The uploaded file's name.
        filename: String,
    },
    /// About to run the terminal certify step.
    Certify {
        /// Which certify path is being attempted.
        mode: CertifyMode,
    },
}

impl Intent {
    /// Whether `event` is the outcome that fulfills this intent — same
    /// operation, same target. Replay clears a pending intent only on a match,
    /// so a non-matching outcome cannot silently resolve (and thereby mask) an
    /// unconfirmed action.
    fn matches_outcome(&self, event: &Event) -> bool {
        match (self, event) {
            (Self::Register { .. }, Event::Registered { .. }) => true,
            (
                Self::UploadFile { ea_id, slot },
                Event::FileUploaded {
                    ea_id: e_ea,
                    slot: e_slot,
                    ..
                },
            ) => ea_id == e_ea && slot == e_slot,
            (Self::UploadDoc { sd_type, .. }, Event::DocUploaded { sd_type: e_ty, .. }) => {
                sd_type == e_ty
            }
            (Self::Certify { mode }, Event::Certified { mode: e_mode, .. }) => mode == e_mode,
            _ => false,
        }
    }

    /// A short, operator-facing description of the pending action, for the
    /// [`SubmissionStage::Interrupted`] surface.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Register {
                module_id,
                oe_count,
            } => format!("register (moduleId {module_id}, {oe_count} OE(s))"),
            Self::UploadFile { ea_id, slot } => {
                format!("upload {} data file for eaId {ea_id}", slot.as_str())
            }
            Self::UploadDoc { sd_type, filename } => {
                format!("upload {} document {filename:?}", sd_type.wire_str())
            }
            Self::Certify { mode } => format!("certify ({})", mode.as_str()),
        }
    }

    /// Serialize this intent to its JSON-lines value.
    fn to_json(&self) -> JsonValue {
        match self {
            Self::Register {
                module_id,
                oe_count,
            } => obj(vec![
                ("kind", JsonValue::String("intentRegister".to_string())),
                ("moduleId", JsonValue::Number(*module_id)),
                ("oeCount", JsonValue::Number(i64_from_usize(*oe_count))),
            ]),
            Self::UploadFile { ea_id, slot } => obj(vec![
                ("kind", JsonValue::String("intentUploadFile".to_string())),
                ("eaId", JsonValue::String(ea_id.clone())),
                ("slot", JsonValue::String(slot.as_str().to_string())),
            ]),
            Self::UploadDoc { sd_type, filename } => obj(vec![
                ("kind", JsonValue::String("intentUploadDoc".to_string())),
                ("sdType", JsonValue::String(sd_type.wire_str().to_string())),
                ("filename", JsonValue::String(filename.clone())),
            ]),
            Self::Certify { mode } => obj(vec![
                ("kind", JsonValue::String("intentCertify".to_string())),
                ("mode", JsonValue::String(mode.as_str().to_string())),
            ]),
        }
    }

    /// Parse one intent value back from the log.
    fn from_json(v: &JsonValue) -> Result<Self, String> {
        match str_field(v, "kind")? {
            "intentRegister" => Ok(Self::Register {
                module_id: i64_field(v, "moduleId")?,
                oe_count: usize_field(v, "oeCount")?,
            }),
            "intentUploadFile" => Ok(Self::UploadFile {
                ea_id: str_field(v, "eaId")?.to_string(),
                slot: slot_field(v)?,
            }),
            "intentUploadDoc" => {
                let sd_type_str = str_field(v, "sdType")?;
                let sd_type = SdType::from_wire(sd_type_str)
                    .ok_or_else(|| format!("intentUploadDoc has unknown sdType {sd_type_str:?}"))?;
                Ok(Self::UploadDoc {
                    sd_type,
                    filename: str_field(v, "filename")?.to_string(),
                })
            }
            "intentCertify" => {
                let mode_str = str_field(v, "mode")?;
                let mode = CertifyMode::from_str_token(mode_str)
                    .ok_or_else(|| format!("intentCertify has unknown mode {mode_str:?}"))?;
                Ok(Self::Certify { mode })
            }
            other => Err(format!("unknown intent kind {other:?}")),
        }
    }
}

/// One line of the append-only log: either an [`Intent`] (pre-submit) or an
/// [`Event`] outcome (post-submit). Serialized one JSON object per line, with
/// the `kind` discriminator naming which.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LogRecord {
    /// A pre-submit intent (`kind` starting `intent…`).
    Intent(Intent),
    /// A post-submit outcome event.
    Outcome(Event),
}

impl LogRecord {
    /// Parse one log line's value into an intent or an outcome, dispatched on
    /// its `kind`.
    fn from_json(v: &JsonValue) -> Result<Self, String> {
        match str_field(v, "kind")? {
            "registered" | "fileUploaded" | "assessmentCaptured" | "docUploaded" | "certified" => {
                Event::from_json(v).map(LogRecord::Outcome)
            }
            "intentRegister" | "intentUploadFile" | "intentUploadDoc" | "intentCertify" => {
                Intent::from_json(v).map(LogRecord::Intent)
            }
            other => Err(format!("unknown log record kind {other:?}")),
        }
    }
}

// ── Reconstructed state ───────────────────────────────────────────────

/// The coarse stage a submission has reached, derived from the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionStage {
    /// No records yet.
    Empty,
    /// Registered (OEs known), no files uploaded.
    Registered,
    /// At least one data file uploaded.
    FilesUploaded,
    /// At least one supporting document uploaded.
    DocsUploaded,
    /// Certified (terminal).
    Certified,
    /// A network side-effect was begun but never confirmed — a dangling
    /// intent (an intent with no following outcome). It may have taken effect
    /// server-side, so it must be **verified before any retry** rather than
    /// blindly re-submitted. The action's description is on
    /// [`SubmissionState::interrupted`].
    Interrupted,
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
    /// A **dangling intent** — an intent with no following matching outcome.
    /// `Some(description)` means a network side-effect was begun but never
    /// confirmed (it may have taken effect server-side); it must be verified
    /// before any retry. Drives [`SubmissionStage::Interrupted`].
    pub interrupted: Option<String>,
    /// A recorded warning for a dropped torn (non-newline-terminated) final
    /// log line — a partial record from a crashed append, tolerated on load
    /// (the earlier records replay intact). `Some` carries the dropped bytes.
    pub torn_tail: Option<String>,
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
                // Dedup by eaId (field-level last-wins): a retried/duplicated
                // `registered` outcome must not double-load an OE, but the server
                // can re-issue refreshed server-assigned fields (a fresh
                // access_token / slot refs) for the same eaId on a resumed
                // registration. Adopt those mutable fields rather than pinning the
                // first — an append-only forward log never carries a
                // deliberately-older token, so last-wins is strictly safer: an
                // idempotent echo is a no-op, a genuine re-issue is applied. We
                // merge FIELDS, not swap the whole record, so a subset resume
                // response can never blank a slot ref the first registration
                // provided. A retry that created genuinely new OEs (distinct
                // eaIds) still folds those in.
                for oe in oes {
                    if let Some(existing) = self.oes.iter_mut().find(|e| e.ea_id == oe.ea_id) {
                        existing.access_token = oe.access_token;
                        existing.url = oe.url;
                        if oe.raw_noise.is_some() {
                            existing.raw_noise = oe.raw_noise;
                        }
                        if oe.restart.is_some() {
                            existing.restart = oe.restart;
                        }
                    } else {
                        self.oes.push(oe);
                    }
                }
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
    ///
    /// A dangling intent takes priority: [`SubmissionStage::Interrupted`] is
    /// returned whenever [`Self::interrupted`] is set, so a resumer never
    /// treats an unconfirmed side-effect as safely completed.
    #[must_use]
    pub fn stage(&self) -> SubmissionStage {
        if self.interrupted.is_some() {
            return SubmissionStage::Interrupted;
        }
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
        ensure_safe_component(entropy_id, "entropyId")?;
        Ok(sessions_root.join(entropy_id))
    }

    /// Create (or reuse) the session directory for `entropy_id`.
    ///
    /// # Errors
    /// An unsafe `entropy_id`, or a filesystem failure creating the dir.
    pub fn create(sessions_root: &str, entropy_id: &str) -> Result<Self, String> {
        let dir = Self::dir_for(Path::new(sessions_root), entropy_id)?;
        // Durability: `create_dir_all` makes every non-existent ancestor from
        // `dir` up to the deepest existing one. Each newly-created directory's
        // dirent lives in its parent, so record those parents (deepest first) and
        // fsync them after — fsyncing only `dir.parent()` would miss a
        // freshly-created sessions-root (and higher) on a first run, leaving the
        // whole subtree loseable on power loss despite reporting success.
        let mut new_parents: Vec<PathBuf> = Vec::new();
        let mut level = dir.as_path();
        while !level.exists() {
            match level.parent() {
                Some(parent) => {
                    new_parents.push(parent.to_path_buf());
                    level = parent;
                }
                None => break,
            }
        }
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("create session dir {}: {e}", dir.display()))?;
        for parent in &new_parents {
            Self::sync_dir(parent)?;
        }
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

    /// Append one outcome event line to `events.jsonl`, **fsync'd** to disk
    /// before returning (durable against power loss, not just process crash).
    ///
    /// The record is written as a single buffered `line + "\n"` so a crash
    /// can never separate the line from its terminating newline, and any torn
    /// (non-newline-terminated) tail left by an earlier crashed append is
    /// healed away first (see `Self::heal_torn_tail`) so a retry cannot
    /// concatenate a valid record onto an incomplete one.
    ///
    /// # Errors
    /// A filesystem failure opening, writing, or syncing the log.
    pub fn append_event(&self, event: &Event) -> Result<(), String> {
        self.append_line(&json::to_compact_string(&event.to_json()))
    }

    /// Append one pre-submit [`Intent`] line to `events.jsonl`, fsync'd before
    /// returning (same durability guarantee as [`Self::append_event`]).
    ///
    /// # Errors
    /// A filesystem failure opening, writing, or syncing the log.
    pub fn append_intent(&self, intent: &Intent) -> Result<(), String> {
        self.append_line(&json::to_compact_string(&intent.to_json()))
    }

    /// Append one already-serialized record line, newline-terminating and
    /// fsync'ing it, after healing any torn tail.
    fn append_line(&self, line: &str) -> Result<(), String> {
        use std::io::Write as _;
        let path = self.dir.join(EVENTS_FILE);
        // The session dir needs an fsync only when THIS append creates
        // events.jsonl (a new dirent); later appends grow the file, whose content
        // durability is the file `sync_all` below.
        let existed = path.exists();
        // Drop any incomplete trailing record so this one cannot merge onto it.
        Self::heal_torn_tail(&path)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        // Single buffered write: the newline can never be separated from its
        // line by a crash between two write calls.
        let mut record = String::with_capacity(line.len().saturating_add(1));
        record.push_str(line);
        record.push('\n');
        file.write_all(record.as_bytes())
            .map_err(|e| format!("append record to {}: {e}", path.display()))?;
        // Durability: the record is on disk before any dependent submit runs.
        file.sync_all()
            .map_err(|e| format!("sync {}: {e}", path.display()))?;
        // On the first append (events.jsonl just created) fsync the session dir
        // so its new dirent survives power loss too, not just a clean crash;
        // subsequent appends leave the dirent unchanged and need only the sync
        // above.
        if !existed {
            Self::sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// Remove a torn (non-newline-terminated) tail from the log, if any.
    ///
    /// A completed [`Self::append_line`] always fsyncs a newline-terminated
    /// record, so a tail lacking a trailing newline can only be the residue of
    /// an append that crashed mid-write — a dead partial record whose submit
    /// never ran. It is truncated back to the end of the last complete record
    /// so the next append starts on a clean line boundary. A missing or
    /// already-newline-terminated log is left untouched.
    fn heal_torn_tail(path: &Path) -> Result<(), String> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("open {} to heal: {e}", path.display())),
        };
        let len = file
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .len();
        if len == 0 {
            return Ok(());
        }
        // Common (untorn) case is O(1): inspect only the final byte rather than
        // re-reading the whole log on every append.
        file.seek(SeekFrom::Start(len.saturating_sub(1)))
            .map_err(|e| format!("seek {}: {e}", path.display()))?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if last[0] == b'\n' {
            return Ok(());
        }
        // Torn tail (rare — post-crash residue): find the last newline and
        // truncate the dead partial record so the next append starts clean.
        let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let keep = data
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i.saturating_add(1));
        let keep = u64::try_from(keep).map_err(|_| "session log too large to heal".to_string())?;
        file.set_len(keep)
            .map_err(|e| format!("truncate torn tail in {}: {e}", path.display()))?;
        file.sync_all()
            .map_err(|e| format!("sync {}: {e}", path.display()))?;
        // No parent-dir fsync here: truncation changes the file's size (covered
        // by the sync_all above), never its dirent.
        Ok(())
    }

    /// fsync a directory so a newly created dirent — a fresh file inside it, or
    /// the session directory itself — survives **power loss**, not just a clean
    /// process crash. A file's bytes are made durable by `fsync` on the file; its
    /// *name* is made durable only by `fsync` on the parent directory. This is
    /// the Unix idiom `open(dir, O_RDONLY)` + `fsync`.
    ///
    /// # Errors
    /// A filesystem failure opening or syncing the directory.
    fn sync_dir(dir: &Path) -> Result<(), String> {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("sync dir {}: {e}", dir.display()))
    }

    /// Durably write `bytes` to `path`: create/truncate the file, `fsync` its
    /// contents, then `fsync` the parent directory so the new dirent survives
    /// power loss too. One call gives a fresh file full power-loss durability —
    /// callers must NOT re-implement the file-then-dir fsync pairing (folding it
    /// here removes an easy-to-omit second call at each site).
    ///
    /// # Errors
    /// A filesystem failure creating, writing, or syncing the file or its dir.
    fn write_durable(path: &Path, bytes: &[u8]) -> Result<(), String> {
        use std::io::Write as _;
        let mut file =
            std::fs::File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        file.sync_all()
            .map_err(|e| format!("sync {}: {e}", path.display()))?;
        if let Some(parent) = path.parent() {
            Self::sync_dir(parent)?;
        }
        Ok(())
    }

    /// Record the *intent* to perform a network side-effect, run `submit`,
    /// then record its *outcome* — the honest intent-then-outcome primitive.
    ///
    /// The [`Intent`] (locally-known data only) is durable on disk **before**
    /// `submit` runs; `submit` returns `(Event, R)` — the outcome event (built
    /// from the server response) and the caller's value — and the outcome is
    /// appended and fsync'd after. A crash between the two leaves a *dangling
    /// intent*, which resume surfaces as [`SubmissionStage::Interrupted`] so
    /// the interrupted action is verified rather than blindly re-submitted.
    /// Both appends go through one call, so their order can never be transposed.
    ///
    /// # Errors
    /// A persistence failure before `submit` runs; `submit`'s own error (the
    /// intent stays on disk → resume sees `Interrupted`); or a failure
    /// persisting the outcome after the side-effect succeeded (also surfaced —
    /// the intent remains dangling, so resume still flags it).
    pub fn persist_intent_then<F, R>(&self, intent: &Intent, submit: F) -> Result<R, String>
    where
        F: FnOnce() -> Result<(Event, R), String>,
    {
        self.append_intent(intent)?;
        let (outcome, value) = submit()?;
        self.append_event(&outcome)?;
        Ok(value)
    }

    /// Store a "Run Successful" assessment body **verbatim** to a sidecar
    /// file `assessment-<eaId>-<slot>.json`, returning the file name. The
    /// bytes are written exactly as received (never re-encoded), so any
    /// floating-point values in NIST's assessment are preserved.
    ///
    /// The file and its parent dirent are fsync'd before returning, so the
    /// sidecar is **durable against power loss** by the time the referencing
    /// `AssessmentCaptured` event (which carries this return value) is appended.
    ///
    /// # Errors
    /// An unsafe `ea_id` (rejected the same way as the entropy id, so a
    /// crafted `ea_id` cannot escape the session dir), or a filesystem failure
    /// writing or syncing the sidecar.
    pub fn store_assessment(&self, ea_id: &str, slot: Slot, body: &str) -> Result<String, String> {
        ensure_safe_component(ea_id, "eaId")?;
        let name = format!("assessment-{ea_id}-{}.json", slot.as_str());
        let path = self.dir.join(&name);
        Self::write_durable(&path, body.as_bytes())?;
        Ok(name)
    }

    /// Store the certify response **verbatim** to `certify-response.json`,
    /// returning the file name. The file and its parent dirent are fsync'd
    /// before returning (durable against power loss before the referencing
    /// `Certified` event is appended).
    ///
    /// # Errors
    /// A filesystem failure writing or syncing the file.
    pub fn store_certify_response(&self, body: &str) -> Result<String, String> {
        let path = self.dir.join(CERTIFY_RESPONSE_FILE);
        Self::write_durable(&path, body.as_bytes())?;
        Ok(CERTIFY_RESPONSE_FILE.to_string())
    }

    /// Read back a stored sidecar file (assessment or certify response) by
    /// name, exactly as written.
    ///
    /// # Errors
    /// An unsafe `name` (rejected the same way as the entropy id, so a `../`
    /// name cannot escape the session dir), or a filesystem failure reading
    /// the file.
    pub fn read_sidecar(&self, name: &str) -> Result<String, String> {
        ensure_safe_component(name, "sidecar name")?;
        let path = self.dir.join(name);
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
    }

    /// Replay `events.jsonl` and reconstruct the submission state. A missing
    /// log yields the empty state (nothing has happened yet).
    ///
    /// Every complete (newline-terminated) line is replayed strictly — a
    /// malformed complete line is a hard error naming its line number. A torn
    /// **final** line (no trailing newline, the residue of a crashed append)
    /// is tolerated: it is dropped and recorded in
    /// [`SubmissionState::torn_tail`] rather than failing the load. An
    /// [`Intent`] with no following outcome leaves the state
    /// [`SubmissionState::interrupted`] (→ [`SubmissionStage::Interrupted`]);
    /// an outcome supersedes its preceding intent.
    ///
    /// # Errors
    /// A filesystem read failure, or a malformed **complete** log line (which
    /// names the offending line number).
    pub fn load_state(&self) -> Result<SubmissionState, String> {
        let path = self.dir.join(EVENTS_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SubmissionState::default());
            }
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };

        // Split on the last newline at the BYTE level: a torn final line (the
        // residue of a crashed append — a completed append fsyncs its newline)
        // may bisect a multibyte UTF-8 character, so decoding the whole file up
        // front would fail the load on an otherwise-recoverable session. Every
        // newline-terminated record is complete and valid UTF-8; only the tail
        // may not be, and it is never parsed — only reported.
        // split point = one past the last newline (0 if none): the complete
        // prefix is every newline-terminated record, the tail is the residue.
        let split = bytes
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i.saturating_add(1));
        let (complete_bytes, tail_bytes) = bytes.split_at(split);
        let torn_tail = {
            let tail = String::from_utf8_lossy(tail_bytes);
            if tail.trim().is_empty() {
                None
            } else {
                Some(tail.into_owned())
            }
        };
        let complete = std::str::from_utf8(complete_bytes)
            .map_err(|e| format!("event log {} is not valid UTF-8: {e}", path.display()))?;

        let mut state = SubmissionState::default();
        let mut pending: Option<Intent> = None;
        for (idx, line) in complete.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value = json::parse(line)
                .map_err(|e| format!("parse event log line {}: {e}", idx.saturating_add(1)))?;
            let record = LogRecord::from_json(&value)
                .map_err(|e| format!("event log line {}: {e}", idx.saturating_add(1)))?;
            match record {
                LogRecord::Outcome(event) => {
                    // An outcome clears the pending intent only if it *fulfills*
                    // it (same operation + target). A non-matching outcome
                    // leaves the intent dangling rather than silently resolving
                    // it — so an unrelated later step can't mask an unconfirmed
                    // action's interrupted signal.
                    let matched = pending.as_ref().is_some_and(|p| p.matches_outcome(&event));
                    state.apply(event);
                    if matched {
                        pending = None;
                    }
                }
                LogRecord::Intent(intent) => {
                    // A new intent while one is still pending means the prior
                    // intent never got its outcome — it dangled. Capture it
                    // before it is overwritten so the interrupted signal is
                    // never lost (keep the first; a genuine crash surfaces one).
                    if let Some(prev) = pending.replace(intent) {
                        state.interrupted.get_or_insert_with(|| prev.describe());
                    }
                }
            }
        }
        // A still-pending intent at end of log is the dangling operator-surface.
        if let Some(intent) = pending {
            state.interrupted.get_or_insert_with(|| intent.describe());
        }
        state.torn_tail = torn_tail;
        Ok(state)
    }
}

/// Validate a single path component (a sidecar name or an `eaId`) the same way
/// as an entropy id — a non-empty `[A-Za-z0-9._-]` token — so nothing from
/// outside can escape the session directory.
fn ensure_safe_component(value: &str, what: &str) -> Result<(), String> {
    if is_safe_id(value) {
        Ok(())
    } else {
        Err(format!(
            "unsafe {what} {value:?}: must be a non-empty [A-Za-z0-9._-] token \
             (not '.', '..', or containing a path separator)"
        ))
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

/// Read a required non-negative integer field as a `usize`.
fn usize_field(v: &JsonValue, key: &str) -> Result<usize, String> {
    let n = i64_field(v, key)?;
    usize::try_from(n).map_err(|_| format!("event field {key:?} is not a non-negative count: {n}"))
}

/// Render a `usize` count as an `i64` for the log (a session's OE count is
/// tiny, far below `i64::MAX`; a pathological overflow saturates rather than
/// wraps).
fn i64_from_usize(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
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

    // ── Intent-then-outcome ordering (recording fake) ─────────────────

    #[test]
    fn persist_intent_then_persists_the_intent_before_submit_and_the_outcome_after() {
        let root = temp_root("persist-order");
        let s = SessionDir::create(root_str(&root), "TIDP").unwrap();

        let intent = Intent::UploadFile {
            ea_id: "11".to_string(),
            slot: Slot::RawNoise,
        };
        let outcome = Event::FileUploaded {
            ea_id: "11".to_string(),
            slot: Slot::RawNoise,
            df_id: "110".to_string(),
        };
        let intent_durable_when_submit_ran = Cell::new(false);
        let outcome_absent_when_submit_ran = Cell::new(false);
        // The submit closure inspects the log AT THE MOMENT it runs: the intent
        // must already be durable (a dangling intent → Interrupted), and the
        // outcome must not be written yet.
        s.persist_intent_then(&intent, || {
            let st = s.load_state().unwrap();
            intent_durable_when_submit_ran.set(st.stage() == SubmissionStage::Interrupted);
            outcome_absent_when_submit_ran.set(st.uploaded_files.is_empty());
            Ok((outcome, ()))
        })
        .unwrap();
        assert!(
            intent_durable_when_submit_ran.get(),
            "intent was durable before the submit closure ran"
        );
        assert!(
            outcome_absent_when_submit_ran.get(),
            "outcome was not written until after the submit closure ran"
        );
        // After the call the outcome superseded the intent — a clean upload.
        let st = s.load_state().unwrap();
        assert!(st.interrupted.is_none());
        assert_eq!(st.stage(), SubmissionStage::FilesUploaded);
        assert_eq!(st.uploaded_files.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn persist_intent_then_leaves_a_dangling_intent_when_submit_fails() {
        let root = temp_root("persist-fail");
        let s = SessionDir::create(root_str(&root), "TIDF").unwrap();
        let intent = Intent::UploadDoc {
            sd_type: SdType::PublicUseDocument,
            filename: "pud.pdf".to_string(),
        };
        let out: Result<(), String> =
            s.persist_intent_then(&intent, || Err("network died".to_string()));
        assert!(out.is_err());
        // The intent is durable despite the submit failure — resume sees an
        // interrupted (unconfirmed) action, not a completed one.
        let st = SessionDir::open(root_str(&root), "TIDF")
            .unwrap()
            .load_state()
            .unwrap();
        assert_eq!(st.stage(), SubmissionStage::Interrupted);
        let desc = st.interrupted.unwrap();
        assert!(desc.contains("PublicUseDocument"), "{desc}");
        // The side-effect is NOT recorded as done — no doc folded in.
        assert!(st.docs.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dangling_intent_alone_yields_interrupted_on_resume() {
        // A crash after the intent append but before the outcome leaves only
        // the intent on disk (simulated by appending the intent alone).
        let root = temp_root("dangling");
        let s = SessionDir::create(root_str(&root), "TIDD").unwrap();
        s.append_intent(&Intent::Certify {
            mode: CertifyMode::Full,
        })
        .unwrap();
        let st = SessionDir::open(root_str(&root), "TIDD")
            .unwrap()
            .load_state()
            .unwrap();
        assert_eq!(st.stage(), SubmissionStage::Interrupted);
        assert!(st.interrupted.unwrap().contains("certify"));
        assert!(st.certified.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_completed_intent_and_outcome_yields_the_normal_stage() {
        let root = temp_root("completed");
        let s = SessionDir::create(root_str(&root), "TIDC").unwrap();
        s.append_intent(&Intent::Register {
            module_id: 3,
            oe_count: 1,
        })
        .unwrap();
        s.append_event(&Event::registered("TIDC", 3, &[sample_reg("11")]))
            .unwrap();
        let st = s.load_state().unwrap();
        // The outcome superseded the intent — no interruption.
        assert!(st.interrupted.is_none());
        assert_eq!(st.stage(), SubmissionStage::Registered);
        assert_eq!(st.oes.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── torn final line tolerated + append cannot merge ────────

    #[test]
    fn load_state_tolerates_a_truncated_final_line_and_reports_it() {
        let root = temp_root("torn");
        let s = SessionDir::create(root_str(&root), "TIDT").unwrap();
        s.append_event(&Event::registered("TIDT", 3, &[sample_reg("11")]))
            .unwrap();
        // Append a torn (non-newline-terminated) partial record, as a crashed
        // append would leave.
        let path = s.path().join(EVENTS_FILE);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(r#"{"kind":"fileUploaded","eaId":"11""#); // no newline
        std::fs::write(&path, content).unwrap();

        let st = s.load_state().unwrap();
        // The complete earlier record replayed; the torn tail was dropped and
        // recorded, not a hard error.
        assert_eq!(st.stage(), SubmissionStage::Registered);
        assert_eq!(st.oes.len(), 1);
        let torn = st.torn_tail.unwrap();
        assert!(torn.contains("fileUploaded"), "{torn}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_torn_multibyte_utf8_tail_does_not_fail_the_whole_load() {
        // A crashed append can bisect a multibyte UTF-8 char (e.g. a non-ASCII
        // filename written verbatim). Byte-level splitting must replay the
        // complete prefix and merely report the invalid-UTF-8 tail, not error.
        let root = temp_root("torn-utf8");
        let s = SessionDir::create(root_str(&root), "TIDU").unwrap();
        s.append_event(&Event::registered("TIDU", 3, &[sample_reg("11")]))
            .unwrap();
        let path = s.path().join(EVENTS_FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        // A partial record ending in the lead byte of a 2-byte UTF-8 sequence
        // (0xC3) with no continuation — invalid UTF-8, no trailing newline.
        bytes.extend_from_slice(br#"{"kind":"fileUploaded","eaId":"11","x":""#);
        bytes.push(0xC3);
        std::fs::write(&path, &bytes).unwrap();

        let st = s.load_state().unwrap(); // must not be Err(invalid utf-8)
        assert_eq!(st.stage(), SubmissionStage::Registered);
        assert_eq!(st.oes.len(), 1);
        assert!(st.torn_tail.is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dangling_intent_is_not_masked_by_a_later_unrelated_step() {
        // intentCertify dangles (no certified outcome); an unrelated doc upload
        // then completes. The interrupted signal for the unconfirmed certify
        // must survive — an outcome clears only the intent it fulfills.
        let root = temp_root("mask");
        let s = SessionDir::create(root_str(&root), "TIDM").unwrap();
        s.append_intent(&Intent::Certify {
            mode: CertifyMode::Full,
        })
        .unwrap(); // dangling — no Certified outcome follows
        s.append_intent(&Intent::UploadDoc {
            sd_type: SdType::PublicUseDocument,
            filename: "pud.pdf".to_string(),
        })
        .unwrap();
        s.append_event(&Event::DocUploaded {
            sd_id: 7,
            sd_type: SdType::PublicUseDocument,
            access_token: "tok".to_string(),
        })
        .unwrap();

        let st = SessionDir::open(root_str(&root), "TIDM")
            .unwrap()
            .load_state()
            .unwrap();
        assert_eq!(st.stage(), SubmissionStage::Interrupted);
        assert!(
            st.interrupted.as_deref().unwrap_or("").contains("certify"),
            "the unconfirmed certify must not be masked: {:?}",
            st.interrupted
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn append_after_a_torn_line_does_not_merge_two_records() {
        let root = temp_root("torn-append");
        let s = SessionDir::create(root_str(&root), "TIDA").unwrap();
        s.append_event(&Event::registered("TIDA", 3, &[sample_reg("11")]))
            .unwrap();
        // Leave a torn partial line (a crashed append).
        let path = s.path().join(EVENTS_FILE);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(r#"{"kind":"docUpl"#); // torn, no newline
        std::fs::write(&path, content).unwrap();

        // A fresh append heals the torn tail first, so the new record lands on
        // its own line and cannot concatenate onto the partial.
        s.append_event(&Event::DocUploaded {
            sd_id: 5,
            sd_type: SdType::PublicUseDocument,
            access_token: "t".to_string(),
        })
        .unwrap();

        // The log now parses cleanly: registered + docUploaded, no merged line,
        // no torn tail.
        let st = s.load_state().unwrap();
        assert!(st.torn_tail.is_none(), "torn tail healed");
        assert_eq!(st.oes.len(), 1);
        assert_eq!(st.docs.len(), 1);
        assert_eq!(st.docs[0].sd_id, 5);
        let raw = s.read_sidecar(EVENTS_FILE).unwrap();
        let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2, "{raw}");
        for line in &lines {
            assert!(json::parse(line).is_ok(), "each line parses: {line}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── a duplicate registered outcome does not double-load OEs ─

    #[test]
    fn duplicate_registered_outcome_does_not_double_load_oes() {
        let root = temp_root("dedup");
        let s = SessionDir::create(root_str(&root), "TIDR").unwrap();
        let regs = [sample_reg("11"), sample_reg("22")];
        // The same registered outcome recorded twice (a retry that re-appended
        // it) must not duplicate the OEs.
        s.append_event(&Event::registered("TIDR", 3, &regs))
            .unwrap();
        s.append_event(&Event::registered("TIDR", 3, &regs))
            .unwrap();
        let st = s.load_state().unwrap();
        assert_eq!(st.oes.len(), 2, "each OE once, not four");
        assert_eq!(st.oes[0].ea_id, "11");
        assert_eq!(st.oes[1].ea_id, "22");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn duplicate_registered_outcome_adopts_the_re_issued_token_last_wins() {
        let root = temp_root("lastwins");
        let s = SessionDir::create(root_str(&root), "TIDLW").unwrap();
        // First registration for eaId 11 with a stale token + slot ref.
        let first = OeRegistration {
            url: "https://h/esv/v1/entropyAssessments/11".to_string(),
            ea_id: "11".to_string(),
            raw_noise: Some(DataFileRef {
                url: "https://h/.../dataFiles/110".to_string(),
                id: "110".to_string(),
            }),
            restart: None,
            conditioned: vec![],
            access_token: "stale-token".to_string(),
        };
        // A resumed registration re-issues a fresh token + refreshed slot ref for
        // the SAME eaId (the interrupted-registration resume path).
        let reissued = OeRegistration {
            url: "https://h/esv/v1/entropyAssessments/11".to_string(),
            ea_id: "11".to_string(),
            raw_noise: Some(DataFileRef {
                url: "https://h/.../dataFiles/999".to_string(),
                id: "999".to_string(),
            }),
            restart: None,
            conditioned: vec![],
            access_token: "fresh-token".to_string(),
        };
        s.append_event(&Event::registered("TIDLW", 3, &[first]))
            .unwrap();
        s.append_event(&Event::registered("TIDLW", 3, &[reissued]))
            .unwrap();
        let st = s.load_state().unwrap();
        assert_eq!(st.oes.len(), 1, "one OE, not two");
        assert_eq!(st.oes[0].ea_id, "11");
        assert_eq!(
            st.oes[0].access_token, "fresh-token",
            "last-wins adopts the re-issued token, not the stale first"
        );
        assert_eq!(
            st.oes[0].raw_noise.as_ref().unwrap().id,
            "999",
            "refreshed slot ref adopted too"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn last_wins_merge_never_blanks_a_slot_the_resume_response_omits() {
        // A resume Registered record that carries a fresh token but OMITS the
        // slot refs (a subset response) must adopt the new token WITHOUT losing
        // the slot the first registration provided — field-level merge, not a
        // struct swap that would default the missing fields.
        let root = temp_root("lastwins-preserve");
        let s = SessionDir::create(root_str(&root), "TIDLP").unwrap();
        let first = OeRegistration {
            url: "https://h/esv/v1/entropyAssessments/11".to_string(),
            ea_id: "11".to_string(),
            raw_noise: Some(DataFileRef {
                url: "https://h/.../dataFiles/110".to_string(),
                id: "110".to_string(),
            }),
            restart: Some(DataFileRef {
                url: "https://h/.../dataFiles/111".to_string(),
                id: "111".to_string(),
            }),
            conditioned: vec![],
            access_token: "stale-token".to_string(),
        };
        let subset = OeRegistration {
            url: "https://h/esv/v1/entropyAssessments/11".to_string(),
            ea_id: "11".to_string(),
            raw_noise: None,
            restart: None,
            conditioned: vec![],
            access_token: "fresh-token".to_string(),
        };
        s.append_event(&Event::registered("TIDLP", 3, &[first]))
            .unwrap();
        s.append_event(&Event::registered("TIDLP", 3, &[subset]))
            .unwrap();
        let st = s.load_state().unwrap();
        assert_eq!(st.oes.len(), 1);
        assert_eq!(
            st.oes[0].access_token, "fresh-token",
            "the re-issued token is still adopted"
        );
        assert_eq!(
            st.oes[0].raw_noise.as_ref().unwrap().id,
            "110",
            "the first registration's raw-noise slot is preserved, not blanked"
        );
        assert_eq!(
            st.oes[0].restart.as_ref().unwrap().id,
            "111",
            "the first registration's restart slot is preserved, not blanked"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── sidecar name / eaId path validation ───────────────────

    #[test]
    fn read_sidecar_rejects_a_traversal_name() {
        let root = temp_root("read-traversal");
        let s = SessionDir::create(root_str(&root), "TIDX").unwrap();
        for bad in ["../escape.json", "a/b.json", "..", "sub/dir"] {
            assert!(s.read_sidecar(bad).is_err(), "should reject {bad:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn store_assessment_rejects_a_traversal_ea_id() {
        let root = temp_root("store-traversal");
        let s = SessionDir::create(root_str(&root), "TIDY").unwrap();
        let err = s
            .store_assessment("../evil", Slot::RawNoise, "{}")
            .unwrap_err();
        assert!(err.contains("eaId"), "{err}");
        // A safe eaId is fine.
        assert!(s.store_assessment("11", Slot::RawNoise, "{}").is_ok());
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

    #[test]
    fn every_intent_kind_round_trips_and_dispatches_as_an_intent() {
        let intents = vec![
            Intent::Register {
                module_id: 3,
                oe_count: 2,
            },
            Intent::UploadFile {
                ea_id: "11".to_string(),
                slot: Slot::Restart,
            },
            Intent::UploadDoc {
                sd_type: SdType::PublicUseDocument,
                filename: "pud.pdf".to_string(),
            },
            Intent::Certify {
                mode: CertifyMode::AddOe,
            },
        ];
        for i in intents {
            let line = json::to_compact_string(&i.to_json());
            let parsed = Intent::from_json(&json::parse(&line).unwrap()).unwrap();
            assert_eq!(parsed, i);
            // The shared log-record reader routes it to the intent arm, not an
            // outcome (its `kind` cannot collide with an event kind).
            assert_eq!(
                LogRecord::from_json(&json::parse(&line).unwrap()).unwrap(),
                LogRecord::Intent(i)
            );
        }
    }
}
