//! On-disk persistence for ACVP demo-server sessions.
//!
//! Long IUT computes (e.g. LMS sigGen over tall trees) must survive a
//! failed submit: on 2026-05-17 an LMS sigGen vector set computed for
//! 75+ minutes and then lost everything when the submit POST died on a
//! TLS keep-alive broken pipe. This module makes the computed response
//! durable *before* the first submit attempt, so a transport failure
//! costs a resubmit instead of a recompute.
//!
//! # Session directory layout
//!
//! Every vector set processed by `demo-run` gets one directory under
//! the sessions root (default `acvts-demo/sessions`, configurable via
//! `--sessions-dir`). The directory name is deterministic — the test
//! session id and vector set id joined by a hyphen:
//!
//! ```text
//! <sessions-root>/<tsId>-<vsId>/
//!   prompt.json        vector-set prompt as fetched (pretty-printed,
//!                      ACVP envelope removed), written before compute
//!   response.json      the exact ACVP-enveloped POST body, written
//!                      after compute and BEFORE any submit attempt;
//!                      `resubmit` replays these bytes verbatim
//!   submit-status.txt  one line: PENDING → SUBMITTED → final verdict
//!                      string from the grader (e.g. passed / failed)
//!   token.txt          session-bound accessToken from registration,
//!                      cached so `resubmit` can refresh it at login
//!                      (same exposure class as the transcript log,
//!                      which already records the registration body)
//! ```
//!
//! `acvp-harness resubmit <tsId> <vsId>` opens the same directory,
//! replays `response.json` byte-for-byte, and advances
//! `submit-status.txt`. It never recomputes — the graded vectors are
//! byte-identical to what the IUT originally computed.

use std::path::{Path, PathBuf};

/// File name of the cached vector-set prompt.
pub const PROMPT_FILE: &str = "prompt.json";
/// File name of the cached, ACVP-enveloped response POST body.
pub const RESPONSE_FILE: &str = "response.json";
/// File name of the one-line submission status.
pub const STATUS_FILE: &str = "submit-status.txt";
/// File name of the cached session-bound access token.
pub const TOKEN_FILE: &str = "token.txt";

/// Status value: response computed and persisted, not yet accepted by
/// the server. A directory left in this state is exactly what
/// `resubmit` consumes.
pub const STATUS_PENDING: &str = "PENDING";
/// Status value: response accepted by the server (HTTP 2xx), verdict
/// not yet recorded. Replaced by the grader's verdict string once the
/// poll completes.
pub const STATUS_SUBMITTED: &str = "SUBMITTED";

/// Extract `(tsId, vsId)` from an ACVP vector-set URL.
///
/// Accepts both the relative form the registration response carries
/// (`/acvp/v1/testSessions/42/vectorSets/123`) and the absolute form,
/// with or without trailing segments (`.../results`). Returns `None`
/// when either id is missing or non-numeric.
pub fn parse_session_ids(vs_url: &str) -> Option<(u64, u64)> {
    let rest = vs_url.split("/testSessions/").nth(1)?;
    let ts_id: u64 = rest.split('/').next()?.parse().ok()?;
    let tail = rest.split("/vectorSets/").nth(1)?;
    let vs_id: u64 = tail.split('/').next()?.parse().ok()?;
    Some((ts_id, vs_id))
}

/// The canonical `resubmit` invocation for a session, used in error
/// messages so a failed submit names its own recovery command.
pub fn resubmit_command(ts_id: u64, vs_id: u64) -> String {
    format!(
        "acvp-harness resubmit {ts_id} {vs_id} --cert <cert.pem> --totp-secret <base64> \
         (--key <key.pem> | --pkcs11-key <pkcs11:URI>)"
    )
}

/// Handle to one `<sessions-root>/<tsId>-<vsId>/` directory.
///
/// Construction is the only place the layout is encoded: [`Self::create`]
/// for the demo-run write path (creates the directory),
/// [`Self::open`] for the resubmit read path (requires the directory
/// to already exist and fails with a clear message otherwise).
#[derive(Debug)]
pub struct SessionDir {
    dir: PathBuf,
    ts_id: u64,
    vs_id: u64,
}

impl SessionDir {
    /// Compute the deterministic directory path for a session.
    fn dir_for(sessions_root: &Path, ts_id: u64, vs_id: u64) -> PathBuf {
        sessions_root.join(format!("{ts_id}-{vs_id}"))
    }

    /// Create (or reuse) the session directory under `sessions_root`.
    ///
    /// Used by `demo-run` immediately after the prompt fetch, before
    /// any compute. Creating an already-existing directory is fine —
    /// a re-run of the same session overwrites its artifacts.
    pub fn create(sessions_root: &str, ts_id: u64, vs_id: u64) -> Result<Self, String> {
        let dir = Self::dir_for(Path::new(sessions_root), ts_id, vs_id);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("create session dir {}: {e}", dir.display()))?;
        Ok(Self { dir, ts_id, vs_id })
    }

    /// Open an existing session directory under `sessions_root`.
    ///
    /// Used by `resubmit`. Refuses cleanly when the directory does not
    /// exist — there is nothing to replay.
    pub fn open(sessions_root: &str, ts_id: u64, vs_id: u64) -> Result<Self, String> {
        let dir = Self::dir_for(Path::new(sessions_root), ts_id, vs_id);
        if !dir.is_dir() {
            return Err(format!(
                "no cached session at {}: nothing to resubmit (the directory is written by \
                 demo-run after the prompt fetch; check <tsId> <vsId> and --sessions-dir)",
                dir.display()
            ));
        }
        Ok(Self { dir, ts_id, vs_id })
    }

    /// Path of the session directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Test-session id this directory belongs to.
    pub fn ts_id(&self) -> u64 {
        self.ts_id
    }

    /// Vector-set id this directory belongs to.
    pub fn vs_id(&self) -> u64 {
        self.vs_id
    }

    /// Write one artifact file, mapping errors to a path-naming message.
    fn write_file(&self, name: &str, contents: &str) -> Result<(), String> {
        let path = self.dir.join(name);
        std::fs::write(&path, contents).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// Read one artifact file, mapping errors to a path-naming message.
    fn read_file(&self, name: &str) -> Result<String, String> {
        let path = self.dir.join(name);
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
    }

    /// Persist the fetched vector-set prompt (pretty-printed JSON).
    pub fn write_prompt(&self, prompt_json: &str) -> Result<(), String> {
        self.write_file(PROMPT_FILE, prompt_json)
    }

    /// Read back the cached prompt exactly as written.
    pub fn read_prompt(&self) -> Result<String, String> {
        self.read_file(PROMPT_FILE)
    }

    /// Persist the computed, ACVP-enveloped response POST body. Called
    /// BEFORE any submit attempt so a transport failure cannot lose
    /// the compute.
    pub fn write_response(&self, response_body: &str) -> Result<(), String> {
        self.write_file(RESPONSE_FILE, response_body)
    }

    /// Read back the cached response POST body exactly as written.
    /// `resubmit` replays these bytes verbatim; refuses cleanly when
    /// the file is missing.
    pub fn read_response(&self) -> Result<String, String> {
        self.read_file(RESPONSE_FILE).map_err(|e| {
            format!(
                "{e} — no cached response to resubmit (demo-run writes it after the IUT \
                 compute, before the first submit attempt)"
            )
        })
    }

    /// Record the submission status (one line, trailing newline).
    pub fn write_status(&self, status: &str) -> Result<(), String> {
        self.write_file(STATUS_FILE, &format!("{status}\n"))
    }

    /// Read the submission status, trimmed of surrounding whitespace.
    pub fn read_status(&self) -> Result<String, String> {
        Ok(self.read_file(STATUS_FILE)?.trim().to_string())
    }

    /// Cache the session-bound access token for later `resubmit` login
    /// refresh.
    pub fn write_token(&self, token: &str) -> Result<(), String> {
        self.write_file(TOKEN_FILE, &format!("{token}\n"))
    }

    /// Read the cached session-bound access token, if one was written.
    pub fn read_token(&self) -> Option<String> {
        self.read_file(TOKEN_FILE)
            .ok()
            .map(|s| s.trim().to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Fresh per-test scratch root under the OS temp dir. The tag keeps
    /// parallel test threads from colliding.
    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "oxicrypt-acvp-session-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn root_str(root: &Path) -> &str {
        root.to_str().unwrap()
    }

    #[test]
    fn parse_session_ids_relative_url() {
        assert_eq!(
            parse_session_ids("/acvp/v1/testSessions/42/vectorSets/123"),
            Some((42, 123))
        );
    }

    #[test]
    fn parse_session_ids_absolute_url() {
        assert_eq!(
            parse_session_ids(
                "https://demo.acvts.nist.gov/acvp/v1/testSessions/731047/vectorSets/2207110"
            ),
            Some((731_047, 2_207_110))
        );
    }

    #[test]
    fn parse_session_ids_with_trailing_results_segment() {
        assert_eq!(
            parse_session_ids("/acvp/v1/testSessions/42/vectorSets/123/results"),
            Some((42, 123))
        );
    }

    #[test]
    fn parse_session_ids_rejects_missing_or_non_numeric_ids() {
        assert_eq!(parse_session_ids("/acvp/v1/testSessions/42"), None);
        assert_eq!(parse_session_ids("/acvp/v1/vectorSets/123"), None);
        assert_eq!(
            parse_session_ids("/acvp/v1/testSessions/x/vectorSets/123"),
            None
        );
        assert_eq!(
            parse_session_ids("/acvp/v1/testSessions/42/vectorSets/y"),
            None
        );
        assert_eq!(parse_session_ids(""), None);
    }

    #[test]
    fn session_dir_path_is_deterministic() {
        let root = temp_root("layout");
        let session = SessionDir::create(root_str(&root), 42, 123).unwrap();
        assert!(session.path().ends_with("42-123"));
        assert_eq!(session.ts_id(), 42);
        assert_eq!(session.vs_id(), 123);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn round_trip_prompt_and_response_byte_identical() {
        let root = temp_root("round-trip");
        let session = SessionDir::create(root_str(&root), 7, 8).unwrap();

        let prompt = crate::json::to_pretty_string(
            &crate::json::parse(r#"{"vsId":8,"algorithm":"LMS","testGroups":[{"tgId":1}]}"#)
                .unwrap(),
        );
        let response = crate::json::to_pretty_string(
            &crate::json::parse(r#"[{"acvVersion":"1.0"},{"vsId":8,"testGroups":[]}]"#).unwrap(),
        );

        session.write_prompt(&prompt).unwrap();
        session.write_response(&response).unwrap();

        // Writer + reader produce identical bytes...
        assert_eq!(session.read_prompt().unwrap(), prompt);
        assert_eq!(session.read_response().unwrap(), response);
        // ...and the read-back text re-parses to the same JSON.
        assert_eq!(
            crate::json::to_pretty_string(
                &crate::json::parse(&session.read_response().unwrap()).unwrap()
            ),
            response
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_file_state_transitions() {
        let root = temp_root("status");
        let session = SessionDir::create(root_str(&root), 1, 2).unwrap();

        session.write_status(STATUS_PENDING).unwrap();
        assert_eq!(session.read_status().unwrap(), STATUS_PENDING);

        session.write_status(STATUS_SUBMITTED).unwrap();
        assert_eq!(session.read_status().unwrap(), STATUS_SUBMITTED);

        session.write_status("passed").unwrap();
        assert_eq!(session.read_status().unwrap(), "passed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn token_round_trip_and_absent_token_is_none() {
        let root = temp_root("token");
        let session = SessionDir::create(root_str(&root), 1, 2).unwrap();
        assert_eq!(session.read_token(), None);
        session.write_token("eyJhbGciOi.example.token").unwrap();
        assert_eq!(
            session.read_token().as_deref(),
            Some("eyJhbGciOi.example.token")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_missing_session_dir_is_a_clear_error() {
        let root = temp_root("open-missing");
        let err = SessionDir::open(root_str(&root), 99, 100).unwrap_err();
        assert!(err.contains("99-100"), "error names the directory: {err}");
        assert!(err.contains("nothing to resubmit"), "error explains: {err}");
    }

    #[test]
    fn read_response_with_missing_file_is_a_clear_error() {
        let root = temp_root("missing-response");
        // Directory exists, response.json does not.
        let created = SessionDir::create(root_str(&root), 5, 6).unwrap();
        drop(created);
        let session = SessionDir::open(root_str(&root), 5, 6).unwrap();
        let err = session.read_response().unwrap_err();
        assert!(err.contains(RESPONSE_FILE), "error names the file: {err}");
        assert!(
            err.contains("no cached response to resubmit"),
            "error explains: {err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_is_idempotent_and_preserves_existing_artifacts() {
        let root = temp_root("idempotent");
        let first = SessionDir::create(root_str(&root), 3, 4).unwrap();
        first.write_status(STATUS_PENDING).unwrap();
        let again = SessionDir::create(root_str(&root), 3, 4).unwrap();
        assert_eq!(again.read_status().unwrap(), STATUS_PENDING);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resubmit_command_names_subcommand_and_ids() {
        let cmd = resubmit_command(42, 123);
        assert!(cmd.starts_with("acvp-harness resubmit 42 123"), "{cmd}");
        assert!(cmd.contains("--cert"), "{cmd}");
        assert!(cmd.contains("--totp-secret"), "{cmd}");
    }
}
