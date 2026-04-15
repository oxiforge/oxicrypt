//! ACVP protocol transport client for the NIST demo server.
//!
//! This module implements the ACVP REST protocol flow needed to run
//! end-to-end test sessions against `demo.acvts.nist.gov`:
//!
//! 1. **Login** — POST `/acvp/v1/login` with a TOTP-signed JWT.
//! 2. **Register** — POST `/acvp/v1/testSessions` with algorithm
//!    capabilities derived from the handler registry.
//! 3. **Fetch** — GET each vector-set URL.
//! 4. **Process** — Feed each vector set through
//!    [`crate::dispatch::process`].
//! 5. **Submit** — POST responses back to each vector-set URL.
//! 6. **Poll** — GET each vector set until the verdict is in.
//!
//! # HTTP backend
//!
//! The ACVP transport shells out to `curl(1)` for HTTPS with mutual
//! TLS, preserving the workspace's zero-third-party-dependencies
//! policy. The cryptographic module boundary is unaffected: TOTP
//! generation and JWT signing use oxicrypt's own HMAC-SHA-256
//! implementation, so the only external trust boundary is the OS-
//! provided curl binary (which the lab's tested configuration already
//! includes).
//!
//! # Entry point
//!
//! [`run_demo`] is called from the `demo-run` CLI subcommand in
//! `main.rs`. It takes an [`AcvpConfig`], builds the handler
//! registry, and runs the full protocol loop.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    // Small counters (vector-set count, timestamps) fit in i64.
    clippy::cast_possible_wrap
)]

use crate::dispatch::{self, AlgorithmHandler, Registry};
use crate::json::{self, JsonValue};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Configuration ──────────────────────────────────────────────────

/// Configuration for an ACVP demo-server session.
pub struct AcvpConfig {
    /// Base URL of the ACVP server (e.g. `https://demo.acvts.nist.gov`).
    pub server_url: String,
    /// Path to the TLS client certificate (PEM).
    pub cert_path: String,
    /// Path to the TLS client private key (PEM).
    pub key_path: String,
    /// TOTP shared secret (base-32 or raw hex, depending on server).
    pub totp_secret: String,
    /// Optional: only register and test this single algorithm.
    pub filter_algorithm: Option<String>,
    /// Path to write the session transcript JSON log.
    pub log_path: String,
}

// ── TOTP (RFC 6238) ───────────────────────────────────────────────

/// Generate a 6-digit TOTP code using HMAC-SHA-256.
///
/// Uses the standard 30-second time step with T0 = 0. The secret is
/// expected as raw bytes (the caller decodes from hex/base32 before
/// calling).
fn totp_now(secret: &[u8]) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time error: {e}"))?;
    let time_step = now.as_secs() / 30;
    totp_at(secret, time_step)
}

/// Generate a TOTP code for a specific time counter value.
fn totp_at(secret: &[u8], counter: u64) -> Result<String, String> {
    let counter_bytes = counter.to_be_bytes();
    // Use oxicrypt's own HMAC-SHA-256 (internal constructor to avoid
    // module-state gating — we're in the harness, not the module).
    let mut mac = oxicrypt_hmac::HmacSha256::new_internal(secret);
    mac.update(&counter_bytes);
    let hmac_result = mac.finalize();

    // Dynamic truncation per RFC 4226 §5.4
    let offset = (hmac_result.get(31).copied().unwrap_or(0) & 0x0f) as usize;
    let code_bytes = hmac_result
        .get(offset..offset.wrapping_add(4))
        .ok_or("HMAC output too short for TOTP truncation")?;
    let code = u32::from_be_bytes([
        code_bytes.first().copied().unwrap_or(0) & 0x7f,
        code_bytes.get(1).copied().unwrap_or(0),
        code_bytes.get(2).copied().unwrap_or(0),
        code_bytes.get(3).copied().unwrap_or(0),
    ]);
    Ok(format!("{:06}", code % 1_000_000))
}

// ── JWT (RFC 7519, minimal) ───────────────────────────────────────

/// Build a minimal JWT for ACVP login, signed with HMAC-SHA-256.
///
/// The JWT carries the TOTP as the `password` claim. The ACVP demo
/// server expects the JWT in the `accessToken` field of the login
/// request body.
fn build_login_jwt(totp_secret: &[u8]) -> Result<String, String> {
    let totp_code = totp_now(totp_secret)?;

    // Header: {"alg":"HS256","typ":"JWT"}
    let header = base64url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");

    // Payload: {"password":"<TOTP>"}
    let payload_json = format!("{{\"password\":\"{totp_code}\"}}");
    let payload = base64url_encode(payload_json.as_bytes());

    let signing_input = format!("{header}.{payload}");

    // Sign with HMAC-SHA-256 using the TOTP secret as key
    let mut mac = oxicrypt_hmac::HmacSha256::new_internal(totp_secret);
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize();
    let sig_b64 = base64url_encode(&signature);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Base64url encoding (RFC 4648 §5) without padding.
fn base64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0;
    while i < input.len() {
        let b0 = input.get(i).copied().unwrap_or(0);
        let b1 = input.get(i.wrapping_add(1)).copied().unwrap_or(0);
        let b2 = input.get(i.wrapping_add(2)).copied().unwrap_or(0);
        let remaining = input.len().wrapping_sub(i);

        out.push(char::from(ALPHABET[((b0 >> 2) & 0x3f) as usize]));
        out.push(char::from(
            ALPHABET[(((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0f)) as usize],
        ));
        if remaining > 1 {
            out.push(char::from(
                ALPHABET[(((b1 & 0x0f) << 2) | ((b2 >> 6) & 0x03)) as usize],
            ));
        }
        if remaining > 2 {
            out.push(char::from(ALPHABET[(b2 & 0x3f) as usize]));
        }
        i = i.wrapping_add(3);
    }
    out
}

// ── HTTP via curl ─────────────────────────────────────────────────

/// HTTP response from a curl invocation.
struct HttpResponse {
    /// HTTP status code.
    status: u16,
    /// Response body as a string.
    body: String,
}

/// Perform an HTTP GET with mutual TLS via curl.
fn http_get(url: &str, config: &AcvpConfig, bearer: &str) -> Result<HttpResponse, String> {
    http_request("GET", url, None, config, bearer)
}

/// Perform an HTTP POST with mutual TLS via curl.
fn http_post(
    url: &str,
    body: &str,
    config: &AcvpConfig,
    bearer: &str,
) -> Result<HttpResponse, String> {
    http_request("POST", url, Some(body), config, bearer)
}

/// Core curl invocation with retry logic.
fn http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    config: &AcvpConfig,
    bearer: &str,
) -> Result<HttpResponse, String> {
    let max_attempts = 3u32;
    let mut attempt = 0u32;
    loop {
        attempt = attempt.wrapping_add(1);
        match http_request_once(method, url, body, config, bearer) {
            Ok(resp) => return Ok(resp),
            Err(e) if attempt < max_attempts => {
                let delay_ms = 1000u64.wrapping_mul(1u64 << attempt);
                eprintln!(
                    "  [transport] {method} {url} attempt {attempt}/{max_attempts} failed: {e}; \
                     retrying in {delay_ms}ms..."
                );
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
            Err(e) => {
                return Err(format!(
                    "{method} {url} failed after {max_attempts} attempts: {e}"
                ));
            }
        }
    }
}

/// Single curl invocation.
fn http_request_once(
    method: &str,
    url: &str,
    body: Option<&str>,
    config: &AcvpConfig,
    bearer: &str,
) -> Result<HttpResponse, String> {
    let mut cmd = std::process::Command::new("curl");
    cmd.arg("--silent")
        .arg("--show-error")
        // Write HTTP status code on the last line
        .arg("--write-out")
        .arg("\n%{http_code}")
        .arg("--cert")
        .arg(&config.cert_path)
        .arg("--key")
        .arg(&config.key_path)
        .arg("-X")
        .arg(method);

    if !bearer.is_empty() {
        cmd.arg("-H")
            .arg(format!("Authorization: Bearer {bearer}"));
    }
    cmd.arg("-H").arg("Content-Type: application/json");

    if let Some(b) = body {
        cmd.arg("-d").arg(b);
    }

    cmd.arg(url);
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());

    let output = cmd.output().map_err(|e| format!("curl exec: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Err(format!("curl exited with {}: {stderr}", output.status));
    }

    // Last line of stdout is the HTTP status code
    let (body_part, status_str) = match stdout.rsplit_once('\n') {
        Some((b, s)) => (b.to_string(), s.trim()),
        None => return Err("unexpected curl output format".to_string()),
    };
    let status: u16 = status_str
        .parse()
        .map_err(|_| format!("could not parse HTTP status: {status_str:?}"))?;

    Ok(HttpResponse {
        status,
        body: body_part,
    })
}

// ── Capabilities builder ──────────────────────────────────────────

/// Build the ACVP registration capabilities array from handler
/// `acvp_capabilities()` methods.
fn build_capabilities(registry: &Registry, filter: Option<&str>) -> Vec<JsonValue> {
    let mut caps = Vec::new();
    registry.for_each_handler(|h: &dyn AlgorithmHandler| {
        if let Some(filter_alg) = filter {
            if h.algorithm() != filter_alg {
                return;
            }
        }
        if let Some(cap) = h.acvp_capabilities() {
            caps.push(cap);
        }
    });
    caps
}

// ── Session transcript log ────────────────────────────────────────

/// Append an event to the transcript log.
struct TranscriptLog {
    entries: Vec<JsonValue>,
}

impl TranscriptLog {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn log(&mut self, event: &str, detail: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let entry = JsonValue::Object(vec![
            ("timestamp".to_string(), JsonValue::Number(now as i64)),
            ("event".to_string(), JsonValue::String(event.to_string())),
            ("detail".to_string(), JsonValue::String(detail.to_string())),
        ]);
        self.entries.push(entry);
    }

    fn log_json(&mut self, event: &str, data: &JsonValue) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let entry = JsonValue::Object(vec![
            ("timestamp".to_string(), JsonValue::Number(now as i64)),
            ("event".to_string(), JsonValue::String(event.to_string())),
            ("data".to_string(), data.clone()),
        ]);
        self.entries.push(entry);
    }

    fn write_to_file(&self, path: &str) -> Result<(), String> {
        let root = JsonValue::Object(vec![(
            "transcript".to_string(),
            JsonValue::Array(self.entries.clone()),
        )]);
        let text = json::to_pretty_string(&root);
        std::fs::write(path, text).map_err(|e| format!("write log {path}: {e}"))
    }
}

// ── Hex decoding for TOTP secret ──────────────────────────────────

/// Decode the TOTP secret from hex. The user provides the secret as
/// a hex string on the CLI.
fn decode_totp_secret(s: &str) -> Result<Vec<u8>, String> {
    crate::hex::decode(s).map_err(|e| format!("bad TOTP secret hex: {e}"))
}

// ── Main transport loop ───────────────────────────────────────────

/// Run a full ACVP demo-server session.
///
/// This is the top-level entry point for the `demo-run` subcommand.
pub fn run_demo(config: &AcvpConfig) -> Result<(), String> {
    let mut log = TranscriptLog::new();
    log.log("session_start", &format!("server={}", config.server_url));

    let totp_secret = decode_totp_secret(&config.totp_secret)?;

    // Build handler registry
    let registry = dispatch::with_default_handlers();
    let caps = build_capabilities(&registry, config.filter_algorithm.as_deref());
    if caps.is_empty() {
        return Err("no handlers returned ACVP capabilities".to_string());
    }
    eprintln!(
        "[transport] built {} capability registration(s)",
        caps.len()
    );
    log.log(
        "capabilities_built",
        &format!("{} registrations", caps.len()),
    );

    // ── Step 1: Login ──────────────────────────────────────────────
    eprintln!("[transport] logging in to {}...", config.server_url);
    let jwt = build_login_jwt(&totp_secret)?;
    let login_body = format!(
        "[{{\"acvVersion\":\"1.0\"}},{{\"accessToken\":\"{jwt}\"}}]"
    );
    let login_url = format!("{}/acvp/v1/login", config.server_url);
    let login_resp = http_post(&login_url, &login_body, config, "")?;
    if login_resp.status < 200 || login_resp.status >= 300 {
        log.log("login_failed", &format!("HTTP {}", login_resp.status));
        log.write_to_file(&config.log_path)?;
        return Err(format!(
            "login failed: HTTP {} — {}",
            login_resp.status, login_resp.body
        ));
    }
    // Extract the access token from the login response.
    // Response shape: [{"acvVersion":"1.0"},{"accessToken":"..."}]
    let login_json = json::parse(&login_resp.body)
        .map_err(|e| format!("parse login response: {e}"))?;
    let access_token = extract_access_token(&login_json)?;
    eprintln!("[transport] login successful, got access token");
    log.log("login_ok", "access token obtained");

    // ── Step 2: Register test session ──────────────────────────────
    eprintln!("[transport] registering test session...");
    let reg_body = build_registration_body(&caps);
    let reg_url = format!("{}/acvp/v1/testSessions", config.server_url);
    let reg_resp = http_post(&reg_url, &reg_body, config, &access_token)?;
    if reg_resp.status < 200 || reg_resp.status >= 300 {
        log.log("register_failed", &format!("HTTP {}", reg_resp.status));
        log.write_to_file(&config.log_path)?;
        return Err(format!(
            "registration failed: HTTP {} — {}",
            reg_resp.status, reg_resp.body
        ));
    }
    let reg_json = json::parse(&reg_resp.body)
        .map_err(|e| format!("parse registration response: {e}"))?;
    let vector_set_urls = extract_vector_set_urls(&reg_json)?;
    eprintln!(
        "[transport] registered: {} vector set(s)",
        vector_set_urls.len()
    );
    log.log(
        "register_ok",
        &format!("{} vector sets", vector_set_urls.len()),
    );
    log.log_json("registration_response", &reg_json);

    // ── Steps 3–5: Fetch → Process → Submit per vector set ─────────
    let results = process_vector_sets(
        &vector_set_urls,
        config,
        &access_token,
        &registry,
        &mut log,
    );

    // ── Summary ────────────────────────────────────────────────────
    write_session_summary(&results, &mut log, &config.log_path)
}

/// Fetch, process, submit, and poll each vector set in the session.
fn process_vector_sets(
    urls: &[String],
    config: &AcvpConfig,
    bearer: &str,
    registry: &Registry,
    log: &mut TranscriptLog,
) -> Vec<(String, String)> {
    let mut results: Vec<(String, String)> = Vec::new();
    for (i, vs_url) in urls.iter().enumerate() {
        let disposition = process_one_vector_set(
            vs_url,
            i.wrapping_add(1),
            urls.len(),
            config,
            bearer,
            registry,
            log,
        );
        results.push((vs_url.clone(), disposition));
    }
    results
}

/// Process a single vector set: fetch → dispatch → submit → poll.
fn process_one_vector_set(
    vs_url: &str,
    index: usize,
    total: usize,
    config: &AcvpConfig,
    bearer: &str,
    registry: &Registry,
    log: &mut TranscriptLog,
) -> String {
    let full_url = resolve_url(&config.server_url, vs_url);
    eprintln!("[transport] [{index}/{total}] fetching {vs_url}...");
    log.log("fetch_vectors", vs_url);

    // Fetch
    let vs_resp = match http_get(&full_url, config, bearer) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [transport] fetch failed: {e}");
            log.log("fetch_error", &e);
            return "FETCH_ERROR".to_string();
        }
    };
    if vs_resp.status < 200 || vs_resp.status >= 300 {
        eprintln!("  [transport] fetch returned HTTP {}", vs_resp.status);
        log.log("fetch_http_error", &format!("HTTP {}", vs_resp.status));
        return format!("HTTP_{}", vs_resp.status);
    }

    // Parse the ACVP prompt
    let prompt = match json::parse(&vs_resp.body) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  [transport] parse error: {e}");
            log.log("parse_error", &format!("{e}"));
            return "PARSE_ERROR".to_string();
        }
    };

    // The ACVP server wraps vector sets in a two-element array
    let vs_body = unwrap_acvp_array(&prompt);
    log.log_json("vector_set_prompt", vs_body);

    // Process through the dispatcher
    eprintln!("  [transport] processing...");
    let response = match dispatch::process(vs_body, registry) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [transport] dispatch error: {e}");
            log.log("dispatch_error", &format!("{e}"));
            return "DISPATCH_ERROR".to_string();
        }
    };
    log.log_json("vector_set_response", &response);

    // Submit response
    let results_url = format!("{full_url}/results");
    let response_body = build_acvp_response_body(&response);
    eprintln!("  [transport] submitting response...");
    match http_post(&results_url, &response_body, config, bearer) {
        Ok(r) if r.status >= 200 && r.status < 300 => {
            eprintln!("  [transport] submitted OK");
            log.log("submit_ok", vs_url);
        }
        Ok(r) => {
            eprintln!("  [transport] submit returned HTTP {}", r.status);
            log.log("submit_error", &format!("HTTP {}", r.status));
            return format!("SUBMIT_HTTP_{}", r.status);
        }
        Err(e) => {
            eprintln!("  [transport] submit error: {e}");
            log.log("submit_error", &e);
            return "SUBMIT_ERROR".to_string();
        }
    }

    // Poll for verdict
    eprintln!("  [transport] polling for verdict...");
    match poll_verdict(&full_url, config, bearer, log) {
        Ok(d) => {
            eprintln!("  [transport] verdict: {d}");
            log.log("verdict", &format!("{vs_url}: {d}"));
            d
        }
        Err(e) => {
            eprintln!("  [transport] poll error: {e}");
            log.log("poll_error", &e);
            "POLL_ERROR".to_string()
        }
    }
}

/// Print and log the session summary, then write the transcript file.
fn write_session_summary(
    results: &[(String, String)],
    log: &mut TranscriptLog,
    log_path: &str,
) -> Result<(), String> {
    eprintln!("\n[transport] ══════════════════════════════════════");
    eprintln!("[transport] Session complete: {} vector set(s)", results.len());
    for (url, disp) in results {
        eprintln!("  {url} → {disp}");
    }

    let summary = JsonValue::Object(vec![
        (
            "vector_sets".to_string(),
            JsonValue::Array(
                results
                    .iter()
                    .map(|(url, disp)| {
                        JsonValue::Object(vec![
                            ("url".to_string(), JsonValue::String(url.clone())),
                            (
                                "disposition".to_string(),
                                JsonValue::String(disp.clone()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "total".to_string(),
            JsonValue::Number(results.len() as i64),
        ),
    ]);
    log.log_json("session_summary", &summary);
    log.write_to_file(log_path)?;
    eprintln!("[transport] transcript written to {log_path}");
    Ok(())
}

// ── Response helpers ──────────────────────────────────────────────

/// Extract the access token from a login response.
///
/// The response is typically:
/// `[{"acvVersion":"1.0"},{"accessToken":"...","large...":...}]`
fn extract_access_token(resp: &JsonValue) -> Result<String, String> {
    // Try array-of-objects shape
    if let Some(arr) = resp.as_array() {
        for item in arr {
            if let Some(token) = item.get("accessToken").and_then(JsonValue::as_str) {
                return Ok(token.to_string());
            }
        }
    }
    // Try flat object shape
    if let Some(token) = resp.get("accessToken").and_then(JsonValue::as_str) {
        return Ok(token.to_string());
    }
    Err(format!(
        "no accessToken in login response: {}",
        json::to_pretty_string(resp)
    ))
}

/// Extract vector-set URLs from a registration response.
fn extract_vector_set_urls(resp: &JsonValue) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();
    // Try array-of-objects shape
    let obj = if let Some(arr) = resp.as_array() {
        arr.iter()
            .find(|item| item.get("vectorSetUrls").is_some())
    } else {
        Some(resp)
    };
    let obj = obj.ok_or("no vectorSetUrls in registration response")?;
    let vs_urls = obj
        .get("vectorSetUrls")
        .and_then(JsonValue::as_array)
        .ok_or("vectorSetUrls is not an array")?;
    for url_val in vs_urls {
        if let Some(s) = url_val.as_str() {
            urls.push(s.to_string());
        }
    }
    if urls.is_empty() {
        return Err("vectorSetUrls array is empty".to_string());
    }
    Ok(urls)
}

/// Build the registration request body.
fn build_registration_body(caps: &[JsonValue]) -> String {
    // [{"acvVersion":"1.0"},{"algorithms":[...]}]
    let algo_array = JsonValue::Array(caps.to_vec());
    let body = JsonValue::Array(vec![
        JsonValue::Object(vec![(
            "acvVersion".to_string(),
            JsonValue::String("1.0".to_string()),
        )]),
        JsonValue::Object(vec![(
            "algorithms".to_string(),
            algo_array,
        )]),
    ]);
    json::to_pretty_string(&body)
}

/// Wrap a response in the ACVP envelope.
fn build_acvp_response_body(response: &JsonValue) -> String {
    let body = JsonValue::Array(vec![
        JsonValue::Object(vec![(
            "acvVersion".to_string(),
            JsonValue::String("1.0".to_string()),
        )]),
        response.clone(),
    ]);
    json::to_pretty_string(&body)
}

/// Unwrap the ACVP two-element array envelope, returning the second
/// element (the actual vector set). If the input is not a two-element
/// array, return it as-is.
fn unwrap_acvp_array(val: &JsonValue) -> &JsonValue {
    if let Some(arr) = val.as_array() {
        if arr.len() == 2 {
            return arr.get(1).unwrap_or(val);
        }
    }
    val
}

/// Resolve a potentially-relative URL against the server base.
fn resolve_url(server_base: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("{server_base}{url}")
    }
}

/// Poll a vector-set URL until the status is `"complete"`, with
/// exponential backoff. Returns the disposition string.
fn poll_verdict(
    url: &str,
    config: &AcvpConfig,
    bearer: &str,
    log: &mut TranscriptLog,
) -> Result<String, String> {
    let max_polls = 20u32;
    let mut poll = 0u32;
    loop {
        poll = poll.wrapping_add(1);
        if poll > max_polls {
            return Ok("POLL_TIMEOUT".to_string());
        }
        // Wait before polling (start with 2s, cap at 30s)
        let delay = std::cmp::min(2000u64.wrapping_mul(1u64 << poll.min(4)), 30_000);
        std::thread::sleep(std::time::Duration::from_millis(delay));

        let resp = http_get(url, config, bearer)?;
        if resp.status < 200 || resp.status >= 300 {
            log.log("poll_error", &format!("HTTP {}", resp.status));
            continue;
        }
        let parsed = json::parse(&resp.body)
            .map_err(|e| format!("parse poll response: {e}"))?;
        let body = unwrap_acvp_array(&parsed);

        if let Some(status) = body.get("status").and_then(JsonValue::as_str) {
            if status == "complete" {
                let disposition = body
                    .get("disposition")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                return Ok(disposition);
            }
            eprintln!("    [poll {poll}/{max_polls}] status={status}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn base64url_encode_empty() {
        assert_eq!(base64url_encode(b""), "");
    }

    #[test]
    fn base64url_encode_hello() {
        // "Hello" → "SGVsbG8"
        assert_eq!(base64url_encode(b"Hello"), "SGVsbG8");
    }

    #[test]
    fn base64url_no_padding() {
        // Base64url should not have = padding
        let encoded = base64url_encode(b"a");
        assert!(!encoded.contains('='));
    }

    #[test]
    fn totp_deterministic() {
        let secret = b"12345678901234567890";
        // Same counter should produce the same code
        let a = totp_at(secret, 1).unwrap();
        let b = totp_at(secret, 1).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 6);
        // Different counters should (very likely) differ
        let c = totp_at(secret, 2).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn jwt_structure() {
        // A JWT should have exactly two dots separating three parts
        let secret = b"test-secret-key-1234";
        let jwt = build_login_jwt(secret).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Header and payload should be non-empty
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
        assert!(!parts[2].is_empty());
    }
}
