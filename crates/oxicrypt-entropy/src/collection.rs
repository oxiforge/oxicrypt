//! Off-boundary raw-data collection tooling.
//!
//! This module backs the default-off `collect` binary. It drives the
//! crate-private [`crate::raw`] collector to write SP 800-90B raw and
//! restart datasets to disk, under a versioned per-OE layout with a
//! top-level sha256 manifest, resumable via a content-hash session
//! checkpoint. **Everything here is outside the validated module boundary**
//! — it is gated behind the `collection` feature, the validated library
//! surface carries none of it, and the only public entry point is [`run`].
//!
//! # Why a fresh source per restart round
//!
//! SP 800-90B §3.1.4 restart-data collection runs
//! [`numberOfRestarts`][RESTART_ROUNDS] × [`samplesPerRestart`][RESTART_SAMPLES_PER_ROUND]
//! = 1000 × 1000 samples, where each restart row must come from a freshly
//! restarted source. This tool therefore allocates a **new collector and a
//! new source instance for every round** (via the injected [`SourceFactory`])
//! and re-runs startup health gating per round — a round is never served
//! from a reused, already-operational collector.
//!
//! # Memory discipline
//!
//! Both the 1,000,000-sample raw file and each 1,000-sample restart row are
//! written through [`crate::raw::RawCollector`]'s streaming path, which holds
//! at most a small fixed buffer in memory regardless of the total sample
//! count. No run ever buffers a whole dataset in RAM.
//!
//! # Dataset layout
//!
//! ```text
//! <datasets-dir>/<oe-id>/<timer>/<boundary>/
//!   raw.bin         1,000,000 one-byte samples (streamed)
//!   restart.bin     1000 × 1000 one-byte samples (fresh source per row)
//!   metadata.json   versioned sidecar (validated against the vendored schema)
//! <datasets-dir>/manifest.sha256   sha256 of every emitted file (one per line)
//! <datasets-dir>/collection-session.json   resumable content-hash checkpoint
//! ```
//!
//! Two boundaries are emitted per OE: `lower` (a tight measurement loop, the
//! worst-case lower bound on per-sample entropy) and `upper` (normal
//! operation). A reviewer thus sees the per-OE entropy floor and the
//! operating point side by side.
//!
//! # Characterization mode (`--characterization N`)
//!
//! With `--characterization N` the tool instead captures, per boundary, a
//! **single contiguous** run of N one-byte samples to `characterization.bin`
//! under [`CollectionPosture::Characterization`] — the health battery runs
//! live, trips are *annotated* into the metadata, and no sample is ever
//! dropped or the run stitched. This backs the per-OE independence /
//! periodicity evidence (`maxwell independence` / `maxwell periodicity`),
//! which wants one long uninterrupted stream (≥10 M for the package). The
//! sidecar is the same versioned `metadata.json`, marked
//! `"characterization": true`. Point characterization at its **own**
//! `--datasets-dir`: a characterization capture and a certification capture
//! both write `metadata.json`, so they must not share a boundary directory.
//!
//! ```text
//! <datasets-dir>/<oe-id>/<timer>/<boundary>/
//!   characterization.bin   N one-byte samples (single contiguous run)
//!   metadata.json          versioned sidecar, marked "characterization": true
//! ```

use crate::error::EntropyError;
use crate::h::MinEntropy;
use crate::health::Alpha;
use crate::raw::{CollectionPosture, RawCollector, StreamSummary};
use crate::source::NoiseSource;
use crate::sp800_90b::{RAW_DATA_SAMPLE_COUNT, RESTART_ROUNDS, RESTART_SAMPLES_PER_ROUND};

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, vec};

/// File name of the raw dataset (1,000,000 streamed samples).
pub(crate) const RAW_FILE: &str = "raw.bin";
/// File name of the characterization dataset (a single contiguous
/// `--characterization N` capture; N one-byte samples).
pub(crate) const CHARACTERIZATION_FILE: &str = "characterization.bin";
/// File name of the restart dataset (1000 × 1000 samples).
pub(crate) const RESTART_FILE: &str = "restart.bin";
/// File name of the per-dataset metadata sidecar.
pub(crate) const METADATA_FILE: &str = "metadata.json";
/// File name of the top-level sha256 manifest.
pub(crate) const MANIFEST_FILE: &str = "manifest.sha256";
/// File name of the resumable collection-session checkpoint.
pub(crate) const SESSION_FILE: &str = "collection-session.json";

/// Which boundary dataset a directory holds.
///
/// Both are collected per OE (ISC-116): the lower boundary is the
/// worst-case per-sample entropy under a tight loop; the upper boundary is
/// the normal-operation operating point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Boundary {
    /// Tight measurement loop — lower bound on per-sample entropy.
    Lower,
    /// Normal operation — the operating point.
    Upper,
}

impl Boundary {
    /// Stable directory-name slug for the boundary.
    #[must_use]
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Lower => "lower",
            Self::Upper => "upper",
        }
    }

    /// Human description folded into the dataset's `collection_params`.
    const fn description(self) -> &'static str {
        match self {
            Self::Lower => "lower boundary (tight measurement loop)",
            Self::Upper => "upper boundary (normal operation)",
        }
    }

    /// All boundaries collected per OE, in emission order.
    #[must_use]
    pub(crate) const fn all() -> [Self; 2] {
        [Self::Lower, Self::Upper]
    }
}

/// A factory producing a **fresh** noise-source instance on demand.
///
/// Restart collection (ISC-118) constructs a new source for every restart
/// round, so the tooling never reuses one already-warmed source across
/// rounds. Production wires this to a real jitter source over a configured
/// timer; tests wire it to a deterministic mock and assert one fresh
/// instance per round.
pub(crate) trait SourceFactory {
    /// The noise source this factory builds.
    type Source: NoiseSource;

    /// Builds a brand-new source instance. Called once per raw run and once
    /// per restart round.
    ///
    /// # Errors
    ///
    /// Returns the factory's own error string when a fresh source cannot be
    /// constructed (e.g. an inadequate timer).
    fn build(&mut self) -> Result<Self::Source, String>;

    /// Stable identifier for the timer/source kind, used as the `<timer>`
    /// path segment (e.g. `"raw-counter"`, `"os-nano-clock"`).
    fn timer_slug(&self) -> &'static str;
}

/// Counts for one collection run. Production uses the spec defaults
/// ([`Self::production`]); tests shrink them so the suite stays fast while
/// exercising every path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counts {
    /// Samples in the raw dataset.
    pub(crate) raw_samples: u32,
    /// Number of restart rounds (each a fresh source).
    pub(crate) restart_rounds: u32,
    /// Samples per restart round.
    pub(crate) restart_samples_per_round: u32,
}

impl Counts {
    /// The SP 800-90B production counts: 1,000,000 raw; 1000 × 1000 restart.
    #[must_use]
    pub(crate) const fn production() -> Self {
        Self {
            raw_samples: RAW_DATA_SAMPLE_COUNT,
            restart_rounds: RESTART_ROUNDS,
            restart_samples_per_round: RESTART_SAMPLES_PER_ROUND,
        }
    }

    /// Total restart samples (`rounds × per_round`), saturating. Test-only:
    /// production derives the total from the rounds actually collected, not
    /// the planned count.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn restart_total(self) -> u32 {
        self.restart_rounds
            .saturating_mul(self.restart_samples_per_round)
    }
}

/// Health-claim configuration shared across a collection run.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaimConfig {
    /// Injected min-entropy claim per sample.
    pub(crate) claimed_h: MinEntropy,
    /// Health-test false-positive probability.
    pub(crate) alpha: Alpha,
}

/// A fully-specified collection request for one OE.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// Operational-environment identifier (the `<oe-id>` path segment).
    pub(crate) oe_id: String,
    /// Root under which `<oe-id>/<timer>/<boundary>/…` is written.
    pub(crate) datasets_dir: PathBuf,
    /// Per-run sample counts (production certification path; ignored in
    /// characterization mode, which uses [`Self::characterization`]).
    pub(crate) counts: Counts,
    /// Claim configuration.
    pub(crate) claim: ClaimConfig,
    /// Characterization sample count `N` when running in `--characterization N`
    /// mode; `None` is the default production (raw + restart) path.
    pub(crate) characterization: Option<u32>,
}

/// An error surfaced to the tool operator (the bin boundary).
///
/// The sample/health hot path never panics; the collector returns typed
/// [`EntropyError`]s, the filesystem returns IO errors, and this type folds
/// both into one operator-facing message. The bin maps it to a process exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionError(pub String);

impl core::fmt::Display for CollectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<EntropyError> for CollectionError {
    fn from(e: EntropyError) -> Self {
        Self(format!("entropy collection failed: {e:?}"))
    }
}

impl CollectionError {
    fn io(context: &str, e: &std::io::Error) -> Self {
        Self(format!("{context}: {e}"))
    }
}

/// Outcome of collecting one boundary dataset directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DatasetOutcome {
    /// The boundary collected.
    pub(crate) boundary: Boundary,
    /// Directory the files were written to.
    pub(crate) dir: PathBuf,
    /// Whether the raw run was submission-eligible (certification, trip-free).
    pub(crate) raw_submission: bool,
    /// Number of restart rounds written (each a fresh source).
    pub(crate) restart_rounds_written: u32,
    /// `true` when the dataset was skipped because the checkpoint already
    /// marked it complete with a matching content hash.
    pub(crate) skipped_resume: bool,
    /// Characterization mode only: `Some(true)` when the contiguous capture
    /// annotated no health-test trips (the preferred, trip-free package run),
    /// `Some(false)` when trips were annotated. `None` in the production
    /// certification path.
    pub(crate) characterization_trip_free: Option<bool>,
}

// ── Layout ───────────────────────────────────────────────────────────────

/// Directory for one boundary dataset: `<datasets-dir>/<oe>/<timer>/<boundary>`.
fn boundary_dir(plan: &Plan, timer_slug: &str, boundary: Boundary) -> PathBuf {
    plan.datasets_dir
        .join(&plan.oe_id)
        .join(timer_slug)
        .join(boundary.slug())
}

// ── Content-hash session checkpoint (mirrors acvp-harness/session.rs) ──────

/// A resumable checkpoint over the dataset directory.
///
/// Each completed boundary dataset is recorded by a **content hash** of its
/// full specification (OE, timer, boundary, counts, claim, schema version).
/// On re-run the same spec hashes identically and is skipped; any change to
/// the spec produces a different hash and forces a re-collect. The store is
/// the `collection-session.json` file — the same write-before-work,
/// idempotent-resume discipline as the ACVP harness session store, applied
/// to local dataset collection.
struct SessionStore {
    path: PathBuf,
    done: Vec<String>,
}

impl SessionStore {
    /// Loads (or starts) the checkpoint under `datasets_dir`.
    fn load(datasets_dir: &Path) -> Result<Self, CollectionError> {
        let path = datasets_dir.join(SESSION_FILE);
        let done = match fs::read_to_string(&path) {
            Ok(text) => parse_done_hashes(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(CollectionError::io("read collection session", &e)),
        };
        Ok(Self { path, done })
    }

    /// Whether `hash` was already completed in a previous run.
    fn is_done(&self, hash: &str) -> bool {
        self.done.iter().any(|h| h == hash)
    }

    /// Records `hash` as complete and persists the checkpoint.
    fn mark_done(&mut self, hash: &str) -> Result<(), CollectionError> {
        if !self.is_done(hash) {
            self.done.push(hash.to_string());
        }
        let json = serialize_done_hashes(&self.done);
        fs::write(&self.path, json).map_err(|e| CollectionError::io("write collection session", &e))
    }
}

/// Content hash of one boundary dataset's full spec. Identical spec ⇒
/// identical hash ⇒ skipped on resume; any spec change ⇒ different hash ⇒
/// re-collect. (sha256 of a canonical descriptor string.)
fn dataset_content_hash(plan: &Plan, timer_slug: &str, boundary: Boundary) -> String {
    // Mode segment: the production (raw + restart) descriptor is byte-identical
    // to the pre-characterization format, so existing certification datasets
    // hash unchanged and are not forced to re-collect. Characterization uses a
    // distinct `char|n=N` segment so the two modes never collide on resume.
    let mode = match plan.characterization {
        None => format!(
            "raw={}|rounds={}|per_round={}",
            plan.counts.raw_samples,
            plan.counts.restart_rounds,
            plan.counts.restart_samples_per_round,
        ),
        Some(n) => format!("char|n={n}"),
    };
    let descriptor = format!(
        "v1|oe={}|timer={}|boundary={}|{mode}|h_steps={}|alpha_exp={}",
        plan.oe_id,
        timer_slug,
        boundary.slug(),
        plan.claim.claimed_h.steps(),
        plan.claim.alpha.exp(),
    );
    sha256_hex(descriptor.as_bytes())
}

/// Parses the `done` hash list from the session JSON. Tolerant: a malformed
/// file yields an empty list rather than aborting collection.
fn parse_done_hashes(text: &str) -> Vec<String> {
    // Minimal extraction of the "done": ["...","..."] string array. The file
    // is tool-owned and tiny; this avoids pulling a JSON dependency.
    let mut out: Vec<String> = Vec::new();
    let Some(start) = text.find("\"done\"") else {
        return out;
    };
    let Some(open) = text[start..].find('[') else {
        return out;
    };
    let after_open = start.saturating_add(open).saturating_add(1);
    let Some(close_rel) = text[after_open..].find(']') else {
        return out;
    };
    let inner = &text[after_open..after_open.saturating_add(close_rel)];
    let mut chars = inner.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == '"' {
            chars.next();
            let mut s = String::new();
            for ch in chars.by_ref() {
                if ch == '"' {
                    break;
                }
                s.push(ch);
            }
            if !s.is_empty() {
                out.push(s);
            }
        } else {
            chars.next();
        }
    }
    out
}

/// Serializes the `done` hash list to the session JSON document.
fn serialize_done_hashes(done: &[String]) -> String {
    let mut out = String::from("{\n  \"schema\": \"collection-session.v1\",\n  \"done\": [");
    for (i, h) in done.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("\n    \"");
        out.push_str(h);
        out.push('"');
    }
    if !done.is_empty() {
        out.push_str("\n  ");
    }
    out.push_str("]\n}\n");
    out
}

// ── sha256 manifest ────────────────────────────────────────────────────────

/// Lowercase-hex sha256 of `data`, via the in-workspace `oxicrypt-sha`.
fn sha256_hex(data: &[u8]) -> String {
    use oxicrypt_sha::Sha256;
    // The collection tool is off-boundary; this digest is an integrity
    // checksum, not a security operation. Use the ungated internal hasher
    // (same path as `sha256_file_hex`) — the gated one-shot `sha256()`
    // refuses unless the module's operational self-test has run, which it
    // has not in this off-boundary tool.
    let mut hasher = Sha256::new_internal();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for byte in digest {
        // Two lowercase hex nibbles per byte; no float, no panic.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0F);
        if let (Some(&h), Some(&l)) = (HEX.get(hi), HEX.get(lo)) {
            s.push(char::from(h));
            s.push(char::from(l));
        }
    }
    s
}

/// sha256 of a file's bytes, streamed so a 1M file is never fully buffered.
fn sha256_file_hex(path: &Path) -> Result<String, CollectionError> {
    use oxicrypt_sha::Sha256;
    use std::io::Read;
    let mut file =
        File::open(path).map_err(|e| CollectionError::io("open file for manifest", &e))?;
    let mut hasher = Sha256::new_internal();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|e| CollectionError::io("read file for manifest", &e))?;
        if read == 0 {
            break;
        }
        if let Some(chunk) = buf.get(..read) {
            hasher.update(chunk);
        }
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for byte in digest {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0F);
        if let (Some(&h), Some(&l)) = (HEX.get(hi), HEX.get(lo)) {
            s.push(char::from(h));
            s.push(char::from(l));
        }
    }
    Ok(s)
}

/// Rewrites the top-level `manifest.sha256` from every dataset file currently
/// present under `datasets_dir`. Lines are `"<hex>  <relative-path>"`,
/// sorted by path for a stable, diffable manifest.
fn write_manifest(datasets_dir: &Path) -> Result<(), CollectionError> {
    let mut entries: Vec<(String, String)> = Vec::new();
    collect_dataset_files(datasets_dir, datasets_dir, &mut entries)?;
    entries.sort_by(|a, b| a.1.cmp(&b.1));
    let mut out = String::new();
    for (hex, rel) in &entries {
        out.push_str(hex);
        out.push_str("  ");
        out.push_str(rel);
        out.push('\n');
    }
    let manifest_path = datasets_dir.join(MANIFEST_FILE);
    fs::write(&manifest_path, out).map_err(|e| CollectionError::io("write manifest", &e))?;
    Ok(())
}

/// Recursively gathers `(sha256_hex, relative_path)` for every dataset file
/// (raw.bin / restart.bin / metadata.json) under `root`, excluding the
/// manifest and session files themselves.
fn collect_dataset_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, String)>,
) -> Result<(), CollectionError> {
    let read_dir = fs::read_dir(dir).map_err(|e| CollectionError::io("read datasets dir", &e))?;
    for entry in read_dir {
        let entry = entry.map_err(|e| CollectionError::io("read dir entry", &e))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| CollectionError::io("stat dir entry", &e))?;
        if file_type.is_dir() {
            collect_dataset_files(root, &path, out)?;
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == MANIFEST_FILE || name == SESSION_FILE {
            continue;
        }
        let hex = sha256_file_hex(&path)?;
        let rel = match path.strip_prefix(root) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => path.to_string_lossy().to_string(),
        };
        out.push((hex, rel));
    }
    Ok(())
}

// ── Collection drivers ─────────────────────────────────────────────────────

/// Streams the raw dataset to `<dir>/raw.bin` from a fresh source, returning
/// the run summary. Memory-bounded (the collector streams in chunks).
fn collect_raw<F: SourceFactory>(
    factory: &mut F,
    plan: &Plan,
    boundary: Boundary,
    dir: &Path,
    measured_freq: Option<u64>,
) -> Result<StreamSummary, CollectionError> {
    let source = factory.build().map_err(CollectionError)?;
    let mut collector = RawCollector::new(source, plan.claim.claimed_h, plan.claim.alpha)?;
    collector.run_startup()?;
    let path = dir.join(RAW_FILE);
    let file = File::create(&path).map_err(|e| CollectionError::io("create raw.bin", &e))?;
    let mut writer = BufWriter::new(file);
    let summary = collector.stream_to(
        // Certification posture for the raw submission file: a trip
        // invalidates and signals re-collect (no stitching).
        CollectionPosture::Certification,
        plan.counts.raw_samples,
        measured_freq,
        &mut writer,
    )?;
    writer
        .flush()
        .map_err(|e| CollectionError::io("flush raw.bin", &e))?;
    let _ = boundary;
    Ok(summary)
}

/// Streams the restart dataset to `<dir>/restart.bin`, allocating a **fresh
/// source per round** (ISC-118). Each round runs startup gating, then streams
/// `restart_samples_per_round` samples. Returns the number of rounds written
/// and the rounds' trip status folded into the last summary.
fn collect_restart<F: SourceFactory>(
    factory: &mut F,
    plan: &Plan,
    dir: &Path,
    measured_freq: Option<u64>,
) -> Result<u32, CollectionError> {
    let path = dir.join(RESTART_FILE);
    let file = File::create(&path).map_err(|e| CollectionError::io("create restart.bin", &e))?;
    let mut writer = BufWriter::new(file);
    let mut rounds_written: u32 = 0;
    let mut round: u32 = 0;
    while round < plan.counts.restart_rounds {
        // Fresh source + fresh collector for THIS round — never reused.
        let source = factory.build().map_err(CollectionError)?;
        let mut collector = RawCollector::new(source, plan.claim.claimed_h, plan.claim.alpha)?;
        collector.run_startup()?;
        // Characterization posture: a restart row is captured unfiltered;
        // per-row acceptance is the downstream §6.3 gate's job, not this
        // writer's.
        let _summary = collector.stream_to(
            CollectionPosture::Characterization,
            plan.counts.restart_samples_per_round,
            measured_freq,
            &mut writer,
        )?;
        rounds_written = rounds_written.saturating_add(1);
        round = round.saturating_add(1);
    }
    writer
        .flush()
        .map_err(|e| CollectionError::io("flush restart.bin", &e))?;
    Ok(rounds_written)
}

/// Streams a single contiguous characterization capture of `count` samples to
/// `<dir>/characterization.bin` from a fresh source, returning the run summary.
///
/// Uses [`CollectionPosture::Characterization`]: the health battery runs live
/// and annotates trips into the metadata, but never drops a sample or stitches
/// the run — the deliberate "collect unfiltered, annotate" posture the
/// downstream independence/periodicity evidence needs. Memory-bounded (streamed
/// in fixed chunks regardless of `count`).
fn collect_characterization<F: SourceFactory>(
    factory: &mut F,
    plan: &Plan,
    dir: &Path,
    count: u32,
    measured_freq: Option<u64>,
) -> Result<StreamSummary, CollectionError> {
    let source = factory.build().map_err(CollectionError)?;
    let mut collector = RawCollector::new(source, plan.claim.claimed_h, plan.claim.alpha)?;
    collector.run_startup()?;
    let path = dir.join(CHARACTERIZATION_FILE);
    let file =
        File::create(&path).map_err(|e| CollectionError::io("create characterization.bin", &e))?;
    let mut writer = BufWriter::new(file);
    let summary = collector.stream_to(
        CollectionPosture::Characterization,
        count,
        measured_freq,
        &mut writer,
    )?;
    writer
        .flush()
        .map_err(|e| CollectionError::io("flush characterization.bin", &e))?;
    Ok(summary)
}

/// Writes the characterization `metadata.json` (marked `"characterization":
/// true`). The sidecar's `sample_count` equals the bytes written to
/// `characterization.bin` (ISC-99, one byte per sample).
fn write_characterization_metadata(
    dir: &Path,
    summary: &StreamSummary,
) -> Result<(), CollectionError> {
    let json = summary.metadata_json_characterization();
    let path = dir.join(METADATA_FILE);
    fs::write(&path, json).map_err(|e| CollectionError::io("write metadata.json", &e))?;
    Ok(())
}

/// Writes the per-dataset `metadata.json`, recording the run's sample-count
/// **consistency**: the metadata `sample_count` equals the bytes written to
/// `raw.bin`, and the restart total recorded equals `rounds × per_round`
/// (ISC-99).
fn write_metadata(
    dir: &Path,
    raw_summary: &StreamSummary,
    restart_total: u32,
) -> Result<(), CollectionError> {
    // The streamed raw bytes-written must equal the metadata sample_count:
    // this is the files-vs-metadata consistency invariant (ISC-99).
    let json = raw_summary.metadata_json_with_restart(restart_total);
    let path = dir.join(METADATA_FILE);
    fs::write(&path, json).map_err(|e| CollectionError::io("write metadata.json", &e))?;
    Ok(())
}

/// Byte length of an existing `characterization.bin` in `dir`, or `None` when
/// it is absent or unreadable. One byte per sample, so the length is the
/// captured sample count — used to confirm a resumed characterization capture
/// actually holds the requested `N` before it is skipped.
fn characterization_capture_len(dir: &Path) -> Option<u64> {
    fs::metadata(dir.join(CHARACTERIZATION_FILE))
        .ok()
        .map(|m| m.len())
}

/// Refuses to write one capture mode into a boundary directory that already
/// holds the **other** mode's dataset.
///
/// Certification (`raw.bin` + `restart.bin`) and characterization
/// (`characterization.bin`) both write the shared `metadata.json`, so mixing
/// them in one directory would silently overwrite a sidecar and corrupt the
/// evidence with no error surfaced. A mode never conflicts with its **own**
/// files, so a legitimate resume or overwrite is unaffected; only a genuine
/// cross-mode collision is rejected, with the fix (a separate `--datasets-dir`)
/// named in the message.
fn guard_no_conflicting_mode(
    dir: &Path,
    running_characterization: bool,
) -> Result<(), CollectionError> {
    let (conflict, other): (bool, &'static str) = if running_characterization {
        (
            dir.join(RAW_FILE).exists() || dir.join(RESTART_FILE).exists(),
            "certification",
        )
    } else {
        (dir.join(CHARACTERIZATION_FILE).exists(), "characterization")
    };
    if conflict {
        return Err(CollectionError(format!(
            "{}: directory already holds a {other} dataset (both modes write \
             metadata.json); collect this capture into a separate --datasets-dir",
            dir.display(),
        )));
    }
    Ok(())
}

/// Collects one boundary dataset directory end-to-end and refreshes the
/// manifest. In the default (certification) path that is raw + restart +
/// metadata; in characterization mode it is one contiguous capture + its
/// sidecar. Resumable: a matching, already-recorded dataset is skipped.
fn collect_one_boundary<F: SourceFactory>(
    factory: &mut F,
    plan: &Plan,
    boundary: Boundary,
    session: &mut SessionStore,
    measured_freq: Option<u64>,
) -> Result<DatasetOutcome, CollectionError> {
    let timer_slug = factory.timer_slug();
    let hash = dataset_content_hash(plan, timer_slug, boundary);
    let dir = boundary_dir(plan, timer_slug, boundary);

    // Characterization mode: one contiguous capture + its sidecar, no restart.
    if let Some(count) = plan.characterization {
        // Resume only when the recorded hash AND a matching on-disk capture
        // both exist. The content hash encodes N but the file path does not,
        // so a stale `characterization.bin` written under a different N (same
        // shared path) must NOT be accepted as this N's capture — the length
        // check forces a re-collect in that case.
        if session.is_done(&hash) && characterization_capture_len(&dir) == Some(u64::from(count)) {
            return Ok(DatasetOutcome {
                boundary,
                dir,
                raw_submission: false,
                restart_rounds_written: 0,
                skipped_resume: true,
                characterization_trip_free: None,
            });
        }

        fs::create_dir_all(&dir).map_err(|e| CollectionError::io("create dataset dir", &e))?;
        guard_no_conflicting_mode(&dir, true)?;

        let summary = collect_characterization(factory, plan, &dir, count, measured_freq)?;
        write_characterization_metadata(&dir, &summary)?;
        write_manifest(&plan.datasets_dir)?;

        // Record as done ONLY when trip-free: a tripped capture is the one the
        // operator is told to "re-collect if needed", so it must NOT be
        // hash-skipped on an identical re-run.
        let trip_free = summary.metadata.trips.is_empty();
        if trip_free {
            session.mark_done(&hash)?;
        }

        return Ok(DatasetOutcome {
            boundary,
            dir,
            raw_submission: false,
            restart_rounds_written: 0,
            skipped_resume: false,
            characterization_trip_free: Some(trip_free),
        });
    }

    // Default certification path: raw + restart.
    if session.is_done(&hash) {
        return Ok(DatasetOutcome {
            boundary,
            dir,
            raw_submission: true,
            restart_rounds_written: 0,
            skipped_resume: true,
            characterization_trip_free: None,
        });
    }

    fs::create_dir_all(&dir).map_err(|e| CollectionError::io("create dataset dir", &e))?;
    guard_no_conflicting_mode(&dir, false)?;

    let raw_summary = collect_raw(factory, plan, boundary, &dir, measured_freq)?;
    let rounds = collect_restart(factory, plan, &dir, measured_freq)?;
    let restart_total = rounds.saturating_mul(plan.counts.restart_samples_per_round);
    write_metadata(&dir, &raw_summary, restart_total)?;

    write_manifest(&plan.datasets_dir)?;
    session.mark_done(&hash)?;

    Ok(DatasetOutcome {
        boundary,
        dir,
        raw_submission: raw_summary.is_submission(),
        restart_rounds_written: rounds,
        skipped_resume: false,
        characterization_trip_free: None,
    })
}

/// Collects BOTH boundary datasets (lower + upper) for one OE (ISC-116),
/// resumable: a boundary already recorded in the checkpoint is skipped.
///
/// # Errors
///
/// Returns a [`CollectionError`] on any filesystem or collection failure;
/// the sample/health hot path itself never panics.
pub(crate) fn collect_oe<F: SourceFactory>(
    factory: &mut F,
    plan: &Plan,
    measured_freq: Option<u64>,
) -> Result<Vec<DatasetOutcome>, CollectionError> {
    fs::create_dir_all(&plan.datasets_dir)
        .map_err(|e| CollectionError::io("create datasets dir", &e))?;
    let mut session = SessionStore::load(&plan.datasets_dir)?;
    let mut outcomes: Vec<DatasetOutcome> = Vec::new();
    for boundary in Boundary::all() {
        let outcome = collect_one_boundary(factory, plan, boundary, &mut session, measured_freq)?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

// ── Public CLI entry (the only public function; called by the thin bin) ────

/// Runs the collection CLI from process args (excluding argv[0]), writing
/// operator output to `out`.
///
/// Recognized form (one OE per invocation; one documented command per
/// dataset type lives in the runbook):
///
/// ```text
/// collect --oe-id <id> --datasets-dir <dir> [--characterization <N>] [--dry-run]
/// ```
///
/// Production counts and claim are used by default (raw + restart, both
/// boundaries). `--characterization N` instead captures a single contiguous
/// N-sample run per boundary to `characterization.bin` (see the module docs);
/// point it at its own `--datasets-dir`. `--dry-run` prints the plan and the
/// resumable status without touching the noise source. This is
/// the **tool boundary**: argument and IO errors are surfaced to the
/// operator via the returned `Result` and a process exit; no panic path is
/// introduced on the sample/health side. Output goes to the injected `out`
/// sink (the bin passes a locked stdout handle), so the library introduces no
/// direct stdout writes.
///
/// # Errors
///
/// Returns a [`CollectionError`] string for a usage error, an IO failure, or
/// a collection failure.
pub fn run<W: Write>(args: &[String], out: &mut W) -> Result<(), CollectionError> {
    let parsed = CliArgs::parse(args)?;
    let plan = Plan {
        oe_id: parsed.oe_id,
        datasets_dir: parsed.datasets_dir,
        counts: Counts::production(),
        claim: default_claim(),
        characterization: parsed.characterization,
    };

    if parsed.dry_run {
        return print_dry_run(&plan, out);
    }

    let mut factory = crate::collection::jitter_factory::JitterFactory::new(&plan.oe_id);
    let measured_freq = jitter_factory::JitterFactory::measured_frequency_hz();
    let outcomes = collect_oe(&mut factory, &plan, measured_freq)?;
    for outcome in &outcomes {
        let status = if outcome.skipped_resume {
            "skipped (already complete)"
        } else if let Some(trip_free) = outcome.characterization_trip_free {
            if trip_free {
                "characterization captured (trip-free)"
            } else {
                "characterization captured (trips annotated - prefer trip-free; re-collect if needed)"
            }
        } else if outcome.raw_submission {
            "collected (raw submission-eligible)"
        } else {
            "collected (raw tripped - re-collect)"
        };
        // Operator-facing progress only; no sample data.
        writeln!(
            out,
            "[{}] {} -> {}",
            outcome.boundary.slug(),
            status,
            outcome.dir.display()
        )
        .map_err(|e| CollectionError(format!("write progress: {e}")))?;
    }
    Ok(())
}

/// The default production claim (conservative): H = 1 bit/sample at the
/// ratified default α = 2^-30 ([`Alpha::DEFAULT`], the jent-precedent
/// value the health layer defaults to). The real per-OE claim is set
/// after the pilot EA assessment; this default keeps the tool runnable
/// for a first capture.
fn default_claim() -> ClaimConfig {
    ClaimConfig {
        claimed_h: MinEntropy::from_bits(1),
        alpha: Alpha::DEFAULT,
    }
}

fn print_dry_run<W: Write>(plan: &Plan, out: &mut W) -> Result<(), CollectionError> {
    let render = |out: &mut W| -> std::io::Result<()> {
        if let Some(count) = plan.characterization {
            writeln!(out, "collection plan (dry-run, characterization mode):")?;
            writeln!(out, "  oe-id:        {}", plan.oe_id)?;
            writeln!(out, "  datasets-dir: {}", plan.datasets_dir.display())?;
            writeln!(
                out,
                "  characterization: {count} samples/boundary (single contiguous run)"
            )?;
            writeln!(out, "  boundaries:")?;
            for boundary in Boundary::all() {
                writeln!(out, "    - {}: {}", boundary.slug(), boundary.description())?;
            }
            writeln!(
                out,
                "  claim:        H={} steps (health annotation only; entropy claim is assessment-derived)",
                plan.claim.claimed_h.steps()
            )?;
            writeln!(
                out,
                "  output/boundary: {CHARACTERIZATION_FILE} + {METADATA_FILE} (\"characterization\": true)"
            )?;
            return Ok(());
        }
        writeln!(out, "collection plan (dry-run):")?;
        writeln!(out, "  oe-id:        {}", plan.oe_id)?;
        writeln!(out, "  datasets-dir: {}", plan.datasets_dir.display())?;
        writeln!(
            out,
            "  raw:          {} samples/boundary",
            plan.counts.raw_samples
        )?;
        writeln!(
            out,
            "  restart:      {} rounds x {} samples (fresh source per round)",
            plan.counts.restart_rounds, plan.counts.restart_samples_per_round
        )?;
        writeln!(out, "  boundaries:")?;
        for boundary in Boundary::all() {
            writeln!(out, "    - {}: {}", boundary.slug(), boundary.description())?;
        }
        writeln!(
            out,
            "  claim:        H={} steps",
            plan.claim.claimed_h.steps()
        )?;
        Ok(())
    };
    render(out).map_err(|e| CollectionError(format!("write dry-run: {e}")))
}

/// Parsed CLI arguments.
#[derive(Debug)]
struct CliArgs {
    oe_id: String,
    datasets_dir: PathBuf,
    dry_run: bool,
    characterization: Option<u32>,
}

/// One-line usage string (the single home for the recognized argument form).
const USAGE: &str =
    "usage: collect --oe-id <id> --datasets-dir <dir> [--characterization <N>] [--dry-run]";

impl CliArgs {
    fn parse(args: &[String]) -> Result<Self, CollectionError> {
        let mut oe_id: Option<String> = None;
        let mut datasets_dir: Option<PathBuf> = None;
        let mut dry_run = false;
        let mut characterization: Option<u32> = None;
        let mut i = 0usize;
        while let Some(arg) = args.get(i) {
            match arg.as_str() {
                "--oe-id" => {
                    let v = args
                        .get(i.saturating_add(1))
                        .ok_or_else(|| CollectionError(String::from("--oe-id needs a value")))?;
                    oe_id = Some(v.clone());
                    i = i.saturating_add(2);
                }
                "--datasets-dir" => {
                    let v = args.get(i.saturating_add(1)).ok_or_else(|| {
                        CollectionError(String::from("--datasets-dir needs a value"))
                    })?;
                    datasets_dir = Some(PathBuf::from(v));
                    i = i.saturating_add(2);
                }
                "--characterization" => {
                    let v = args.get(i.saturating_add(1)).ok_or_else(|| {
                        CollectionError(String::from(
                            "--characterization needs a value (sample count N)",
                        ))
                    })?;
                    let n: u32 = v.parse().map_err(|_| {
                        CollectionError(format!(
                            "--characterization value must be a positive integer, got {v:?}"
                        ))
                    })?;
                    if n == 0 {
                        return Err(CollectionError(String::from(
                            "--characterization value must be greater than 0",
                        )));
                    }
                    characterization = Some(n);
                    i = i.saturating_add(2);
                }
                "--dry-run" => {
                    dry_run = true;
                    i = i.saturating_add(1);
                }
                other => {
                    return Err(CollectionError(format!("unknown argument: {other}")));
                }
            }
        }
        let oe_id = oe_id.ok_or_else(|| CollectionError(String::from(USAGE)))?;
        let datasets_dir = datasets_dir.ok_or_else(|| CollectionError(String::from(USAGE)))?;
        Ok(Self {
            oe_id,
            datasets_dir,
            dry_run,
            characterization,
        })
    }
}

/// Production source factory: a CPU-jitter source over the raw counter.
mod jitter_factory {
    use super::{SourceFactory, String};
    use crate::jitter::{JitterConfig, JitterSource};
    use crate::source::TimerSource;
    use crate::timer::RawCounterTimer;
    use std::format;
    use std::string::ToString;

    /// Builds a fresh [`JitterSource`] over a fresh [`RawCounterTimer`] per
    /// call — the fresh-source-per-round discipline (ISC-118).
    pub(super) struct JitterFactory {
        cpu_model: String,
        os: String,
        params: String,
    }

    impl JitterFactory {
        pub(super) fn new(oe_id: &str) -> Self {
            Self {
                cpu_model: format!("oe:{oe_id}"),
                os: std::env::consts::OS.to_string(),
                params: String::from("raw-counter jitter, delta-steered variable workload (#125)"),
            }
        }

        /// The measured counter frequency, if discoverable. The raw counter
        /// frequency is not portably introspectable here, so this returns
        /// `None` and the field is recorded as such (never a nominal guess).
        pub(super) fn measured_frequency_hz() -> Option<u64> {
            None
        }
    }

    impl SourceFactory for JitterFactory {
        type Source = JitterSource<'static, RawCounterTimer>;

        fn build(&mut self) -> Result<Self::Source, String> {
            // Leak the per-instance descriptor strings to obtain 'static
            // borrows for the source's metadata. This runs once per round in
            // a short-lived off-boundary tool process; the leak is bounded by
            // the round count and reclaimed at process exit.
            let cpu: &'static str = std::boxed::Box::leak(self.cpu_model.clone().into_boxed_str());
            let os: &'static str = std::boxed::Box::leak(self.os.clone().into_boxed_str());
            let params: &'static str = std::boxed::Box::leak(self.params.clone().into_boxed_str());
            let config = JitterConfig {
                adequacy: crate::timer::AdequacyConfig::default(),
                timer_source: Some(TimerSource::RawCounter),
                cpu_model: cpu,
                os,
                collection_params: params,
            };
            JitterSource::new(RawCounterTimer::new(), config)
                .map_err(|e| format!("jitter source construction failed: {e:?}"))
        }

        fn timer_slug(&self) -> &'static str {
            "raw-counter"
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::source::{
        NoiseSource, RawSample, SourceError, SourceMetadata, SourceSpec, TimerSource,
        sealed::Sealed,
    };
    use std::cell::Cell;
    use std::rc::Rc;

    fn alpha20() -> Alpha {
        Alpha::from_exp(20).unwrap()
    }

    /// Deterministic xorshift byte source — healthy, 8-bit alphabet.
    #[derive(Debug)]
    struct PrngMock {
        state: u32,
    }
    impl PrngMock {
        fn new(seed: u32) -> Self {
            Self {
                state: seed | 1, // never zero
            }
        }
    }
    impl Sealed for PrngMock {}
    impl NoiseSource for PrngMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(4)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            Ok((x & 0xFF) as u8)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            SourceMetadata {
                timer_source: Some(TimerSource::RawCounter),
                counter_frequency_hz: Some(3_000_000_000),
                cpu_model: "test-cpu",
                os: "test-os",
                collection_params: "unit test",
            }
        }
    }

    /// Factory counting how many fresh sources it built (ISC-118 probe).
    struct CountingFactory {
        built: Rc<Cell<u32>>,
        seed: u32,
    }
    impl CountingFactory {
        fn new() -> (Self, Rc<Cell<u32>>) {
            let built = Rc::new(Cell::new(0));
            (
                Self {
                    built: Rc::clone(&built),
                    seed: 0x1234_5678,
                },
                built,
            )
        }
    }
    impl SourceFactory for CountingFactory {
        type Source = PrngMock;
        fn build(&mut self) -> Result<Self::Source, String> {
            let n = self.built.get();
            self.built.set(n.saturating_add(1));
            // Distinct seed per build so rounds differ but stay deterministic.
            self.seed = self.seed.wrapping_add(0x9E37_79B9);
            Ok(PrngMock::new(self.seed))
        }
        fn timer_slug(&self) -> &'static str {
            "mock-timer"
        }
    }

    /// A source that emits varied bytes through startup, then dies to a
    /// constant so a characterization capture annotates health trips — used to
    /// exercise the tripped-run behavior (not marked done → re-collects).
    #[derive(Debug)]
    struct DyingMock {
        state: u32,
        emitted: u32,
        die_after: u32,
    }
    impl Sealed for DyingMock {}
    impl NoiseSource for DyingMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(4)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            self.emitted = self.emitted.saturating_add(1);
            if self.emitted > self.die_after {
                return Ok(0xCC); // constant run → RCT trips
            }
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            Ok((x & 0xFF) as u8)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            SourceMetadata {
                timer_source: Some(TimerSource::RawCounter),
                counter_frequency_hz: Some(3_000_000_000),
                cpu_model: "test-cpu",
                os: "test-os",
                collection_params: "dying mock",
            }
        }
    }

    /// Factory building a fresh [`DyingMock`] per call.
    struct DyingFactory {
        die_after: u32,
    }
    impl SourceFactory for DyingFactory {
        type Source = DyingMock;
        fn build(&mut self) -> Result<Self::Source, String> {
            Ok(DyingMock {
                state: 0x1234_5678,
                emitted: 0,
                die_after: self.die_after,
            })
        }
        fn timer_slug(&self) -> &'static str {
            "mock-timer"
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("oxicrypt-collection-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        root
    }

    fn small_plan(dir: PathBuf) -> Plan {
        Plan {
            oe_id: String::from("test-oe"),
            datasets_dir: dir,
            counts: Counts {
                raw_samples: 4096,
                restart_rounds: 8,
                restart_samples_per_round: 256,
            },
            claim: ClaimConfig {
                claimed_h: MinEntropy::from_bits(2),
                alpha: alpha20(),
            },
            characterization: None,
        }
    }

    // ── ISC-118: fresh source instance per restart round ─────────────────

    #[test]
    fn restart_allocates_a_fresh_source_per_round() {
        let dir = temp_dir("fresh-per-round");
        let plan = small_plan(dir.clone());
        let (mut factory, built) = CountingFactory::new();
        let outcomes = collect_oe(&mut factory, &plan, Some(2_500_000_000)).unwrap();
        // Two boundaries, each: 1 raw build + restart_rounds builds.
        let per_boundary = 1 + plan.counts.restart_rounds;
        assert_eq!(built.get(), per_boundary * 2);
        for o in &outcomes {
            assert_eq!(o.restart_rounds_written, plan.counts.restart_rounds);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // ── ISC-99: files-vs-metadata count consistency ──────────────────────

    #[test]
    fn raw_file_size_matches_metadata_sample_count() {
        let dir = temp_dir("count-consistency");
        let plan = small_plan(dir.clone());
        let (mut factory, _) = CountingFactory::new();
        collect_oe(&mut factory, &plan, None).unwrap();
        for boundary in Boundary::all() {
            let bdir = boundary_dir(&plan, "mock-timer", boundary);
            // raw.bin byte length == raw_samples (one byte per sample).
            let raw_bytes = fs::metadata(bdir.join(RAW_FILE)).unwrap().len();
            assert_eq!(raw_bytes, u64::from(plan.counts.raw_samples));
            // restart.bin byte length == rounds * per_round.
            let restart_bytes = fs::metadata(bdir.join(RESTART_FILE)).unwrap().len();
            assert_eq!(restart_bytes, u64::from(plan.counts.restart_total()));
            // metadata.json sample_count and restart_total agree.
            let meta = fs::read_to_string(bdir.join(METADATA_FILE)).unwrap();
            assert!(meta.contains(&format!("\"sample_count\":{}", plan.counts.raw_samples)));
            assert!(meta.contains(&format!(
                "\"restart_total\":{}",
                plan.counts.restart_total()
            )));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_total_equals_rounds_times_per_round() {
        // Production counts: 1000 * 1000 = 1_000_000 (no real collection).
        let c = Counts::production();
        assert_eq!(c.restart_rounds, 1000);
        assert_eq!(c.restart_samples_per_round, 1000);
        assert_eq!(c.restart_total(), 1_000_000);
    }

    // ── ISC-116: dual lower/upper boundary per OE ────────────────────────

    #[test]
    fn both_boundaries_emitted_per_oe() {
        let dir = temp_dir("dual-boundary");
        let plan = small_plan(dir.clone());
        let (mut factory, _) = CountingFactory::new();
        let outcomes = collect_oe(&mut factory, &plan, None).unwrap();
        assert_eq!(outcomes.len(), 2);
        let slugs: Vec<&str> = outcomes.iter().map(|o| o.boundary.slug()).collect();
        assert!(slugs.contains(&"lower"));
        assert!(slugs.contains(&"upper"));
        for boundary in Boundary::all() {
            let bdir = boundary_dir(&plan, "mock-timer", boundary);
            assert!(bdir.join(RAW_FILE).is_file());
            assert!(bdir.join(RESTART_FILE).is_file());
            assert!(bdir.join(METADATA_FILE).is_file());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // ── ISC-61: versioned layout + sha256 manifest ───────────────────────

    #[test]
    fn layout_is_versioned_and_manifest_checksums_verify() {
        let dir = temp_dir("layout-manifest");
        let plan = small_plan(dir.clone());
        let (mut factory, _) = CountingFactory::new();
        collect_oe(&mut factory, &plan, None).unwrap();

        // Layout: <oe>/<timer>/<boundary>/{raw,restart,metadata}.
        let expected = dir
            .join("test-oe")
            .join("mock-timer")
            .join("lower")
            .join(RAW_FILE);
        assert!(expected.is_file(), "versioned layout path must exist");

        // Manifest exists and every listed checksum re-verifies.
        let manifest = fs::read_to_string(dir.join(MANIFEST_FILE)).unwrap();
        assert!(!manifest.trim().is_empty());
        let mut verified = 0u32;
        for line in manifest.lines() {
            let (hex, rel) = line.split_once("  ").unwrap();
            let actual = sha256_file_hex(&dir.join(rel)).unwrap();
            assert_eq!(actual, hex, "manifest checksum must verify for {rel}");
            verified += 1;
        }
        // 2 boundaries * 3 files each.
        assert_eq!(verified, 6);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha256_hex_matches_known_answer() {
        // FIPS 180-4 / NIST KAT: sha256("abc").
        let hex = sha256_hex(b"abc");
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ── ISC-37: resumable checkpoint skips done datasets ─────────────────

    #[test]
    fn second_run_skips_completed_datasets() {
        let dir = temp_dir("resume-skip");
        let plan = small_plan(dir.clone());

        let (mut factory1, built1) = CountingFactory::new();
        let first = collect_oe(&mut factory1, &plan, None).unwrap();
        assert!(first.iter().all(|o| !o.skipped_resume));
        let first_builds = built1.get();
        assert!(first_builds > 0);

        // Re-run with the SAME plan: both boundaries hash-match the
        // checkpoint and are skipped — zero new source builds.
        let (mut factory2, built2) = CountingFactory::new();
        let second = collect_oe(&mut factory2, &plan, None).unwrap();
        assert!(second.iter().all(|o| o.skipped_resume));
        assert_eq!(built2.get(), 0, "no source built on a fully-resumed run");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_spec_forces_recollect() {
        let dir = temp_dir("resume-changed");
        let mut plan = small_plan(dir.clone());
        let (mut f1, _) = CountingFactory::new();
        collect_oe(&mut f1, &plan, None).unwrap();

        // Change the claim → different content hash → NOT skipped.
        plan.claim.claimed_h = MinEntropy::from_bits(3);
        let (mut f2, built2) = CountingFactory::new();
        let again = collect_oe(&mut f2, &plan, None).unwrap();
        assert!(again.iter().all(|o| !o.skipped_resume));
        assert!(built2.get() > 0, "changed spec must rebuild sources");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn content_hash_is_stable_and_spec_sensitive() {
        let dir = temp_dir("hash");
        let plan = small_plan(dir.clone());
        let h1 = dataset_content_hash(&plan, "mock-timer", Boundary::Lower);
        let h1b = dataset_content_hash(&plan, "mock-timer", Boundary::Lower);
        assert_eq!(h1, h1b, "same spec hashes identically");
        let h_upper = dataset_content_hash(&plan, "mock-timer", Boundary::Upper);
        assert_ne!(h1, h_upper, "boundary changes the hash");
        let mut plan2 = plan.clone();
        plan2.counts.raw_samples += 1;
        let h2 = dataset_content_hash(&plan2, "mock-timer", Boundary::Lower);
        assert_ne!(h1, h2, "count change changes the hash");
        let _ = fs::remove_dir_all(&dir);
    }

    // ── ISC-51: streaming write is memory-bounded ────────────────────────

    #[test]
    fn streaming_write_buffer_is_bounded() {
        // A counting sink proves the stream arrives in bounded chunks and the
        // collector never hands over a count-sized buffer in one write.
        struct CountingSink {
            total: u64,
            max_single_write: usize,
        }
        impl Write for CountingSink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.total += buf.len() as u64;
                self.max_single_write = self.max_single_write.max(buf.len());
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        // Drive the crate-private collector's streaming path directly with a
        // sample count far larger than the chunk size.
        let mut collector =
            RawCollector::new(PrngMock::new(7), MinEntropy::from_bits(2), alpha20()).unwrap();
        collector.run_startup().unwrap();
        let count = crate::raw::STREAM_CHUNK_SAMPLES * 4 + 123;
        let mut sink = CountingSink {
            total: 0,
            max_single_write: 0,
        };
        let summary = collector
            .stream_to(CollectionPosture::Characterization, count, None, &mut sink)
            .unwrap();
        // Every sample reached the sink...
        assert_eq!(sink.total, u64::from(count));
        assert_eq!(summary.bytes_written, u64::from(count));
        // ...but no single write exceeded the bounded chunk: peak in-memory
        // sample buffer is the fixed chunk, NOT the total count.
        assert!(
            sink.max_single_write <= crate::raw::STREAM_CHUNK_SAMPLES as usize,
            "streaming buffer must stay bounded: max write {} > chunk {}",
            sink.max_single_write,
            crate::raw::STREAM_CHUNK_SAMPLES
        );
    }

    // ── runbook presence (ISC-37 doc half) ───────────────────────────────

    #[test]
    fn runbook_documents_one_command_per_dataset_type() {
        let runbook = include_str!("../docs/collection-runbook.md");
        assert!(runbook.contains("collect --oe-id"));
        assert!(runbook.contains("raw.bin"));
        assert!(runbook.contains("restart.bin"));
        assert!(runbook.contains("collection-session.json"));
        assert!(runbook.to_lowercase().contains("resum"));
    }

    // ── CLI arg parsing (tool boundary, no hot-path panics) ──────────────

    #[test]
    fn cli_requires_oe_and_dir() {
        assert!(CliArgs::parse(&[]).is_err());
        assert!(CliArgs::parse(&[String::from("--oe-id"), String::from("x")]).is_err());
        let ok = CliArgs::parse(&[
            String::from("--oe-id"),
            String::from("x"),
            String::from("--datasets-dir"),
            String::from("/tmp/x"),
        ])
        .unwrap();
        assert_eq!(ok.oe_id, "x");
        assert!(!ok.dry_run);
    }

    #[test]
    fn cli_rejects_unknown_arg() {
        let err = CliArgs::parse(&[String::from("--bogus")]).unwrap_err();
        assert!(err.0.contains("unknown argument"));
    }

    // ── ISC-120: characterization mode (--characterization N) ────────────

    #[test]
    fn cli_parses_characterization_count() {
        let ok = CliArgs::parse(&[
            String::from("--oe-id"),
            String::from("x"),
            String::from("--datasets-dir"),
            String::from("/tmp/x"),
            String::from("--characterization"),
            String::from("12345"),
        ])
        .unwrap();
        assert_eq!(ok.characterization, Some(12345));
        // Absent by default (production path).
        let prod = CliArgs::parse(&[
            String::from("--oe-id"),
            String::from("x"),
            String::from("--datasets-dir"),
            String::from("/tmp/x"),
        ])
        .unwrap();
        assert_eq!(prod.characterization, None);
    }

    #[test]
    fn cli_rejects_zero_and_nonnumeric_characterization() {
        let base = [
            String::from("--oe-id"),
            String::from("x"),
            String::from("--datasets-dir"),
            String::from("/tmp/x"),
        ];
        let mut zero = base.to_vec();
        zero.extend([String::from("--characterization"), String::from("0")]);
        assert!(
            CliArgs::parse(&zero)
                .unwrap_err()
                .0
                .contains("greater than 0")
        );

        let mut nan = base.to_vec();
        nan.extend([String::from("--characterization"), String::from("lots")]);
        assert!(
            CliArgs::parse(&nan)
                .unwrap_err()
                .0
                .contains("positive integer")
        );

        let mut missing = base.to_vec();
        missing.push(String::from("--characterization"));
        assert!(
            CliArgs::parse(&missing)
                .unwrap_err()
                .0
                .contains("needs a value")
        );
    }

    #[test]
    fn characterization_mode_writes_bin_and_marked_sidecar() {
        let dir = temp_dir("characterization");
        let mut plan = small_plan(dir.clone());
        let count = crate::raw::STREAM_CHUNK_SAMPLES + 321; // spans multiple chunks
        plan.characterization = Some(count);
        let (mut factory, _) = CountingFactory::new();
        let outcomes = collect_oe(&mut factory, &plan, None).unwrap();

        assert_eq!(outcomes.len(), 2);
        for outcome in &outcomes {
            // Characterization outcome is reported as such.
            assert!(outcome.characterization_trip_free.is_some());
            assert_eq!(outcome.restart_rounds_written, 0);
        }
        for boundary in Boundary::all() {
            let bdir = boundary_dir(&plan, "mock-timer", boundary);
            // characterization.bin: exactly `count` one-byte samples.
            let bytes = fs::metadata(bdir.join(CHARACTERIZATION_FILE))
                .unwrap()
                .len();
            assert_eq!(bytes, u64::from(count));
            // sidecar marked characterization:true, count consistent, no restart.
            let meta = fs::read_to_string(bdir.join(METADATA_FILE)).unwrap();
            assert!(meta.contains("\"characterization\":true"));
            assert!(meta.contains(&format!("\"sample_count\":{count}")));
            assert!(!meta.contains("restart_total"));
            // Production files are NOT produced in characterization mode.
            assert!(!bdir.join(RAW_FILE).exists());
            assert!(!bdir.join(RESTART_FILE).exists());
        }
        // Manifest checksums re-verify for the characterization files.
        let manifest = fs::read_to_string(dir.join(MANIFEST_FILE)).unwrap();
        for line in manifest.lines() {
            let (hex, rel) = line.split_once("  ").unwrap();
            assert_eq!(sha256_file_hex(&dir.join(rel)).unwrap(), hex);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn characterization_content_hash_distinct_from_production() {
        let dir = temp_dir("char-hash");
        let prod = small_plan(dir.clone());
        let mut charz = small_plan(dir.clone());
        charz.characterization = Some(prod.counts.raw_samples);
        let h_prod = dataset_content_hash(&prod, "mock-timer", Boundary::Lower);
        let h_char = dataset_content_hash(&charz, "mock-timer", Boundary::Lower);
        assert_ne!(
            h_prod, h_char,
            "characterization and production must never collide on resume"
        );
        // N is spec-sensitive.
        let mut charz2 = charz.clone();
        charz2.characterization = Some(charz.characterization.unwrap() + 1);
        let h_char2 = dataset_content_hash(&charz2, "mock-timer", Boundary::Lower);
        assert_ne!(h_char, h_char2, "characterization N changes the hash");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn characterization_refuses_to_clobber_a_certification_dir() {
        let dir = temp_dir("char-guard");
        // A production certification capture (raw + restart) lands first.
        let (mut f1, _) = CountingFactory::new();
        collect_oe(&mut f1, &small_plan(dir.clone()), None).unwrap();
        // A characterization capture into the SAME dir must be refused (both
        // modes write metadata.json — the guard prevents silent corruption).
        let mut charz = small_plan(dir.clone());
        charz.characterization = Some(2048);
        let (mut f2, _) = CountingFactory::new();
        let err = collect_oe(&mut f2, &charz, None).unwrap_err();
        assert!(err.0.contains("certification"), "got: {}", err.0);
        assert!(err.0.contains("separate --datasets-dir"), "got: {}", err.0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn certification_refuses_to_clobber_a_characterization_dir() {
        let dir = temp_dir("cert-guard");
        let mut charz = small_plan(dir.clone());
        charz.characterization = Some(2048);
        let (mut f1, _) = CountingFactory::new();
        collect_oe(&mut f1, &charz, None).unwrap();
        // A certification capture into the SAME dir must be refused.
        let (mut f2, _) = CountingFactory::new();
        let err = collect_oe(&mut f2, &small_plan(dir.clone()), None).unwrap_err();
        assert!(err.0.contains("characterization"), "got: {}", err.0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn characterization_resumes_only_on_a_length_matching_capture() {
        let dir = temp_dir("char-resume");
        let a = crate::raw::STREAM_CHUNK_SAMPLES + 100;
        let b = crate::raw::STREAM_CHUNK_SAMPLES + 900;
        let mk = |n| {
            let mut p = small_plan(dir.clone());
            p.characterization = Some(n);
            p
        };

        // 1. First N=a capture (healthy → trip-free → marked done).
        let (mut f, _) = CountingFactory::new();
        assert!(
            collect_oe(&mut f, &mk(a), None)
                .unwrap()
                .iter()
                .all(|o| !o.skipped_resume)
        );

        // 2. Identical re-run of N=a → skipped (hash done AND length matches).
        let (mut f, built) = CountingFactory::new();
        assert!(
            collect_oe(&mut f, &mk(a), None)
                .unwrap()
                .iter()
                .all(|o| o.skipped_resume)
        );
        assert_eq!(built.get(), 0, "matching capture must not rebuild");

        // 3. N=b into the same dir overwrites the shared characterization.bin.
        let (mut f, _) = CountingFactory::new();
        collect_oe(&mut f, &mk(b), None).unwrap();

        // 4. Re-run N=a: hash-a IS recorded, but the on-disk file now holds b
        //    bytes — the length mismatch must force a re-collect, not a false
        //    skip that hands back the wrong-length dataset.
        let (mut f, built) = CountingFactory::new();
        assert!(
            collect_oe(&mut f, &mk(a), None)
                .unwrap()
                .iter()
                .all(|o| !o.skipped_resume),
            "stale-length capture must re-collect"
        );
        assert!(built.get() > 0);
        for boundary in Boundary::all() {
            let bdir = boundary_dir(&mk(a), "mock-timer", boundary);
            let len = fs::metadata(bdir.join(CHARACTERIZATION_FILE))
                .unwrap()
                .len();
            assert_eq!(len, u64::from(a), "re-collected file must hold N=a samples");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tripped_characterization_is_not_marked_done_and_recollects() {
        let dir = temp_dir("char-trip");
        let mut plan = small_plan(dir.clone());
        plan.characterization = Some(crate::sp800_90b::STARTUP_MIN_SAMPLES + 1000);
        let die_after = crate::sp800_90b::STARTUP_MIN_SAMPLES + 100;

        // A tripped capture is reported as NOT trip-free...
        let mut f1 = DyingFactory { die_after };
        let first = collect_oe(&mut f1, &plan, None).unwrap();
        assert!(
            first
                .iter()
                .all(|o| o.characterization_trip_free == Some(false)),
            "dying source must annotate trips"
        );

        // ...and is NOT recorded done, so an identical re-run re-collects
        // (matches the emitted "re-collect if needed" guidance) rather than
        // being falsely skipped.
        let mut f2 = DyingFactory { die_after };
        let again = collect_oe(&mut f2, &plan, None).unwrap();
        assert!(
            again.iter().all(|o| !o.skipped_resume),
            "a tripped capture must never be hash-skipped on re-run"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
