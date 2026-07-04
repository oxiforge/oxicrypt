//! ESVP §2 authentication: login, single-token refresh, and bulk
//! refresh.
//!
//! The request builders and response parsers are pure functions
//! (testable against fixtures with no network). The [`login`],
//! [`bulk_refresh`], and [`EsvSession`] execution paths are generic over
//! the [`EsvTransport`] trait, so the whole flow is driven by a stub in
//! unit tests and wired to acvp-harness's live curl(1)/mTLS transport at
//! the attended smoke.
//!
//! # Protocol facts (cited)
//!
//! - **Envelope:** every message is a two-element array
//!   `[{"esvVersion":"1.0"}, {payload}]` — the ACVP-style versioned
//!   envelope acvp-harness already handles. (ESVP digest §"Protocol
//!   shape"; reference client `authentication/login.py:84-85`.)
//! - **Base path `/esv/v1`, version `"1.0"`.** (reference client
//!   `jsons/config.demo.json:5-6`: `ServerURL .../esv/v1`,
//!   `EsvVersion "1.0"`.)
//! - **Login:** POST `/esv/v1/login` body `[{esvVersion},{password}]`,
//!   where `password` is the current TOTP. (login.py:66,85.)
//! - **TOTP:** RFC 6238, 30-second step, T0 = 0, **8 digits**,
//!   HMAC-SHA-256. The reference client's `totp.py` truncation is
//!   byte-identical to acvp-harness's RFC-4226 dynamic truncation
//!   (offset = low nibble of the last HMAC byte, top bit of the 32-bit
//!   window masked, mod 10^8), so [`acvp_harness::transport::totp_now`]
//!   is reused verbatim rather than reimplemented. (ESVP digest §2;
//!   `authentication/totp.py`.)
//! - **Single refresh:** re-login at `/esv/v1/login` embedding the
//!   current token, body `[{esvVersion},{password, accessToken:<old>}]`
//!   — the server re-issues a fresh same-scope token, the exact
//!   mechanism acvp-harness's own token refresh relies on. (ESVP digest
//!   §2: "refresh = POST /esv/v1/login with {password, accessToken}".)
//! - **Bulk refresh:** POST `/esv/v1/login/refresh` body
//!   `[{esvVersion},{password, accessToken:[<t1>,<t2>,…]}]` — refreshes
//!   an array of per-object JWTs in one TOTP touch. (ESVP digest §2:
//!   "NEW vs ACVP: bulk refresh … accessToken ARRAY"; the reference
//!   client's `refresh_payload` (login.py:80-81) carries the same
//!   `{password, accessToken}` object.)
//!
//! ## Resolved-by-judgment: the single-refresh endpoint
//!
//! The digest assigns the single-token refresh to `/esv/v1/login` (a
//! same-scope re-login), while the reference client's `refresh_jwt`
//! (login.py:32-48) routes *both* single- and array-token refreshes
//! through `/esv/v1/login/refresh`. This module follows the cited digest
//! — [`SINGLE_REFRESH_PATH`] = [`LOGIN_PATH`] — because it matches the
//! proven acvp-harness re-login mechanism and the task's protocol
//! source. The divergence is flagged for empirical confirmation at the
//! attended demo smoke; if the demo server rejects it, point
//! [`SINGLE_REFRESH_PATH`] at [`BULK_REFRESH_PATH`].

use acvp_harness::json::{self, JsonValue};
use acvp_harness::transport::{
    HttpResponse, extract_access_token, submit_should_refresh_retry, token_needs_refresh, totp_now,
};

/// The only ESVP version the NIST servers support.
///
/// (reference client `jsons/config.demo.json:6`: `EsvVersion "1.0"`.)
pub const ESV_VERSION: &str = "1.0";

/// Login endpoint path (relative to the server base, which already
/// carries `/esv/v1`). (reference client `authentication/login.py:66`.)
pub const LOGIN_PATH: &str = "/esv/v1/login";

/// Single-token refresh endpoint. Per the ESVP digest §2 a single
/// refresh is a same-scope re-login at [`LOGIN_PATH`]; see the module
/// docs for the reference-client divergence resolved by judgment.
pub const SINGLE_REFRESH_PATH: &str = LOGIN_PATH;

/// Bulk refresh endpoint — refreshes an array of per-object JWTs in one
/// TOTP touch. (ESVP digest §2; reference client
/// `authentication/login.py:39`.)
pub const BULK_REFRESH_PATH: &str = "/esv/v1/login/refresh";

/// A minimal ESVP HTTP transport: one call per authenticated request.
///
/// The single method mirrors the shape of acvp-harness's own transport
/// (`method`, `path`, optional `body`, `bearer`). A live implementation
/// wraps acvp-harness's curl(1)/mTLS transport; unit tests supply a stub
/// that returns canned responses and records the outgoing requests.
pub trait EsvTransport {
    /// Issue one HTTP request and return the response. `bearer` is the
    /// empty string when no `Authorization: Bearer` header applies (the
    /// login and refresh endpoints authenticate via mTLS + the TOTP in
    /// the body, not a bearer).
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
        bearer: &str,
    ) -> Result<HttpResponse, String>;
}

/// True for an HTTP 2xx status.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Wrap a payload object in the ESVP two-element versioned envelope
/// `[{"esvVersion":"1.0"}, {payload}]` and serialize it.
fn envelope(payload: Vec<(String, JsonValue)>) -> String {
    let body = JsonValue::Array(vec![
        JsonValue::Object(vec![(
            "esvVersion".to_string(),
            JsonValue::String(ESV_VERSION.to_string()),
        )]),
        JsonValue::Object(payload),
    ]);
    json::to_pretty_string(&body)
}

/// Build the login request body: `[{esvVersion},{password:<totp>}]`.
/// (reference client `authentication/login.py:85`.)
pub fn build_login_body(totp_code: &str) -> String {
    envelope(vec![(
        "password".to_string(),
        JsonValue::String(totp_code.to_string()),
    )])
}

/// Build the single-token refresh body:
/// `[{esvVersion},{password:<totp>, accessToken:<old>}]`. Field order
/// (password then accessToken) matches the reference client's
/// `refresh_payload` (`authentication/login.py:81`).
pub fn build_single_refresh_body(totp_code: &str, access_token: &str) -> String {
    envelope(vec![
        (
            "password".to_string(),
            JsonValue::String(totp_code.to_string()),
        ),
        (
            "accessToken".to_string(),
            JsonValue::String(access_token.to_string()),
        ),
    ])
}

/// Build the bulk refresh body:
/// `[{esvVersion},{password:<totp>, accessToken:[<t1>,<t2>,…]}]`. The
/// `accessToken` array preserves the caller's token order so the
/// response array maps back one-to-one. (ESVP digest §2.)
pub fn build_bulk_refresh_body(totp_code: &str, access_tokens: &[String]) -> String {
    let tokens = access_tokens
        .iter()
        .map(|t| JsonValue::String(t.clone()))
        .collect();
    envelope(vec![
        (
            "password".to_string(),
            JsonValue::String(totp_code.to_string()),
        ),
        ("accessToken".to_string(), JsonValue::Array(tokens)),
    ])
}

/// Parse a single `accessToken` string out of a login / single-refresh
/// response body. Reuses [`acvp_harness::transport::extract_access_token`],
/// which scans the versioned-array envelope for a string `accessToken`
/// — so a bulk-refresh array response is correctly rejected here.
pub fn parse_access_token(body: &str) -> Result<String, String> {
    let parsed = json::parse(body).map_err(|e| format!("parse ESV auth response: {e}"))?;
    extract_access_token(&parsed)
}

/// Parse the `accessToken` array from a bulk-refresh response body,
/// returning the refreshed tokens in order. A response carrying a single
/// string `accessToken` is accepted and wrapped in a one-element vector.
pub fn parse_bulk_refresh_tokens(body: &str) -> Result<Vec<String>, String> {
    let parsed = json::parse(body).map_err(|e| format!("parse ESV bulk-refresh response: {e}"))?;
    // The token(s) live on the payload object of the versioned array;
    // scan every array element (and the flat-object fallback) for an
    // `accessToken` field.
    let candidates: Vec<&JsonValue> = match parsed.as_array() {
        Some(items) => items.iter().collect(),
        None => vec![&parsed],
    };
    for item in candidates {
        let Some(field) = item.get("accessToken") else {
            continue;
        };
        if let Some(arr) = field.as_array() {
            let mut out = Vec::with_capacity(arr.len());
            for tok in arr {
                let s = tok
                    .as_str()
                    .ok_or("accessToken array element is not a string")?;
                out.push(s.to_string());
            }
            return Ok(out);
        }
        if let Some(s) = field.as_str() {
            return Ok(vec![s.to_string()]);
        }
    }
    Err(format!(
        "no accessToken in ESV bulk-refresh response: {}",
        json::to_pretty_string(&parsed)
    ))
}

/// POST a body to `path` and require an HTTP 2xx, returning the response
/// on success and a status-and-body error otherwise.
fn post_expect_success<T: EsvTransport>(
    transport: &mut T,
    path: &str,
    body: &str,
    bearer: &str,
) -> Result<HttpResponse, String> {
    let resp = transport.request("POST", path, Some(body), bearer)?;
    if is_success(resp.status) {
        Ok(resp)
    } else {
        Err(format!(
            "ESV POST {path} failed: HTTP {} — {}",
            resp.status, resp.body
        ))
    }
}

/// Perform an ESVP login and return the authenticated session.
///
/// Computes the current TOTP from the raw secret (reusing acvp-harness's
/// generator), POSTs the login envelope to [`LOGIN_PATH`], and parses
/// the returned access token.
pub fn login<T: EsvTransport>(totp_secret: &[u8], transport: &mut T) -> Result<EsvSession, String> {
    let code = totp_now(totp_secret)?;
    let body = build_login_body(&code);
    let resp = post_expect_success(transport, LOGIN_PATH, &body, "")?;
    let token = parse_access_token(&resp.body)?;
    Ok(EsvSession::new(token))
}

/// Bulk-refresh an array of per-object JWTs in one TOTP touch, returning
/// the refreshed tokens in the same order. Used immediately before
/// certify, when many per-object tokens must all be fresh at once.
pub fn bulk_refresh<T: EsvTransport>(
    totp_secret: &[u8],
    access_tokens: &[String],
    transport: &mut T,
) -> Result<Vec<String>, String> {
    let code = totp_now(totp_secret)?;
    let body = build_bulk_refresh_body(&code, access_tokens);
    let resp = post_expect_success(transport, BULK_REFRESH_PATH, &body, "")?;
    parse_bulk_refresh_tokens(&resp.body)
}

/// An authenticated ESV session: the current access token plus its
/// issuance instant, so a long submission can refresh the 30-minute-TTL
/// token in flight.
///
/// The proactive-margin and reactive-retry decisions reuse acvp-harness's
/// pure predicates ([`token_needs_refresh`] /
/// [`submit_should_refresh_retry`]) so the ESV and ACVP token lifecycles
/// stay in lockstep.
pub struct EsvSession {
    token: String,
    issued: std::time::Instant,
}

impl EsvSession {
    /// Wrap a freshly-issued token, stamping the issuance instant to now.
    fn new(token: String) -> Self {
        Self {
            token,
            issued: std::time::Instant::now(),
        }
    }

    /// Construct a session with a synthetic age — mocked-expiry tests
    /// only.
    #[cfg(test)]
    fn with_age(token: String, age: std::time::Duration) -> Self {
        Self {
            token,
            issued: std::time::Instant::now()
                .checked_sub(age)
                .unwrap_or_else(std::time::Instant::now),
        }
    }

    /// The current access token, for use as a bearer on non-login
    /// endpoints.
    pub fn bearer(&self) -> &str {
        &self.token
    }

    /// Seconds since the token was issued.
    pub fn elapsed_secs(&self) -> u64 {
        self.issued.elapsed().as_secs()
    }

    /// True once the token has aged past the proactive refresh margin
    /// (reuses [`token_needs_refresh`] / `TOKEN_REFRESH_MARGIN_SECS`).
    pub fn needs_refresh(&self) -> bool {
        token_needs_refresh(self.elapsed_secs())
    }

    /// Single-token refresh: re-login at [`SINGLE_REFRESH_PATH`]
    /// embedding the current token, replacing the token and resetting
    /// its age on success.
    pub fn refresh<T: EsvTransport>(
        &mut self,
        totp_secret: &[u8],
        transport: &mut T,
    ) -> Result<(), String> {
        let code = totp_now(totp_secret)?;
        let body = build_single_refresh_body(&code, &self.token);
        let resp = post_expect_success(transport, SINGLE_REFRESH_PATH, &body, "")?;
        self.token = parse_access_token(&resp.body)?;
        self.issued = std::time::Instant::now();
        Ok(())
    }

    /// Proactively refresh the token if it has aged past the margin.
    /// Returns whether a refresh was performed.
    pub fn refresh_if_stale<T: EsvTransport>(
        &mut self,
        totp_secret: &[u8],
        transport: &mut T,
    ) -> Result<bool, String> {
        if self.needs_refresh() {
            self.refresh(totp_secret, transport)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Issue an authenticated request, transparently keeping the token
    /// fresh: proactively refresh if the token is past its margin
    /// before sending, then send with the current bearer; if the server
    /// still answers 401/403, refresh once and retry exactly once
    /// (reactive backstop, gated by [`submit_should_refresh_retry`]).
    pub fn authenticated_request<T: EsvTransport>(
        &mut self,
        totp_secret: &[u8],
        method: &str,
        path: &str,
        body: Option<&str>,
        transport: &mut T,
    ) -> Result<HttpResponse, String> {
        self.refresh_if_stale(totp_secret, transport)?;
        let resp = transport.request(method, path, body, self.bearer())?;
        if submit_should_refresh_retry(resp.status, false) {
            self.refresh(totp_secret, transport)?;
            return transport.request(method, path, body, self.bearer());
        }
        Ok(resp)
    }
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
    use acvp_harness::transport::totp_at;
    use std::collections::VecDeque;

    /// One recorded outbound request.
    #[derive(Debug)]
    struct RecordedCall {
        method: String,
        path: String,
        body: Option<String>,
        bearer: String,
    }

    /// Fixture transport: replays canned responses in order and records
    /// every outgoing request for shape assertions. No network.
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
            body: Option<&str>,
            bearer: &str,
        ) -> Result<HttpResponse, String> {
            self.calls.push(RecordedCall {
                method: method.to_string(),
                path: path.to_string(),
                body: body.map(str::to_string),
                bearer: bearer.to_string(),
            });
            self.responses
                .pop_front()
                .ok_or_else(|| "stub: no more canned responses".to_string())
        }
    }

    fn ok(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: body.to_string(),
        }
    }

    fn status(code: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status: code,
            body: body.to_string(),
        }
    }

    const SECRET: &[u8] = b"12345678901234567890";

    // ── Request-shape builders ────────────────────────────────────────

    #[test]
    fn login_body_is_versioned_envelope_with_password_only() {
        let parsed = json::parse(&build_login_body("00000000")).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0].get("esvVersion").and_then(JsonValue::as_str),
            Some("1.0")
        );
        assert_eq!(
            arr[1].get("password").and_then(JsonValue::as_str),
            Some("00000000")
        );
        assert!(arr[1].get("accessToken").is_none());
    }

    #[test]
    fn single_refresh_body_carries_password_and_string_token() {
        let parsed = json::parse(&build_single_refresh_body("12345678", "jwt-old")).unwrap();
        let payload = &parsed.as_array().unwrap()[1];
        assert_eq!(
            payload.get("password").and_then(JsonValue::as_str),
            Some("12345678")
        );
        assert_eq!(
            payload.get("accessToken").and_then(JsonValue::as_str),
            Some("jwt-old")
        );
    }

    #[test]
    fn bulk_refresh_body_carries_password_and_token_array_in_order() {
        let tokens = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let parsed = json::parse(&build_bulk_refresh_body("87654321", &tokens)).unwrap();
        let payload = &parsed.as_array().unwrap()[1];
        assert_eq!(
            payload.get("password").and_then(JsonValue::as_str),
            Some("87654321")
        );
        let arr = payload
            .get("accessToken")
            .and_then(JsonValue::as_array)
            .unwrap();
        let got: Vec<&str> = arr.iter().filter_map(JsonValue::as_str).collect();
        assert_eq!(got, vec!["a", "b", "c"]);
    }

    #[test]
    fn endpoint_paths_are_esv_v1() {
        assert_eq!(LOGIN_PATH, "/esv/v1/login");
        assert_eq!(BULK_REFRESH_PATH, "/esv/v1/login/refresh");
        // Single refresh is a same-scope re-login per the ESVP digest §2.
        assert_eq!(SINGLE_REFRESH_PATH, LOGIN_PATH);
        assert_eq!(ESV_VERSION, "1.0");
    }

    // ── Response parsers ──────────────────────────────────────────────

    #[test]
    fn parse_access_token_from_versioned_envelope() {
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-123"}]"#;
        assert_eq!(parse_access_token(body).unwrap(), "jwt-123");
    }

    #[test]
    fn parse_access_token_rejects_bulk_array_response() {
        // A bulk-refresh array response must not parse as a single token.
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":["a","b"]}]"#;
        assert!(parse_access_token(body).is_err());
    }

    #[test]
    fn parse_bulk_refresh_tokens_returns_array_in_order() {
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":["t1","t2","t3"]}]"#;
        assert_eq!(
            parse_bulk_refresh_tokens(body).unwrap(),
            vec!["t1".to_string(), "t2".to_string(), "t3".to_string()]
        );
    }

    #[test]
    fn parse_bulk_refresh_tokens_wraps_single_string() {
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":"solo"}]"#;
        assert_eq!(
            parse_bulk_refresh_tokens(body).unwrap(),
            vec!["solo".to_string()]
        );
    }

    #[test]
    fn parse_bulk_refresh_tokens_errors_when_absent() {
        let body = r#"[{"esvVersion":"1.0"},{"nope":true}]"#;
        assert!(parse_bulk_refresh_tokens(body).is_err());
    }

    // ── Login flow ────────────────────────────────────────────────────

    #[test]
    fn login_posts_to_login_path_and_returns_session() {
        let mut t = StubTransport::new(vec![ok(
            r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-A"}]"#,
        )]);
        let session = login(SECRET, &mut t).unwrap();
        assert_eq!(session.bearer(), "jwt-A");
        assert_eq!(t.calls.len(), 1);
        let call = &t.calls[0];
        assert_eq!(call.method, "POST");
        assert_eq!(call.path, LOGIN_PATH);
        assert_eq!(call.bearer, "");
        // Body is a well-formed login envelope with an 8-digit password.
        let parsed = json::parse(call.body.as_ref().unwrap()).unwrap();
        let payload = &parsed.as_array().unwrap()[1];
        let code = payload.get("password").and_then(JsonValue::as_str).unwrap();
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn login_surfaces_http_error_status_and_body() {
        let mut t = StubTransport::new(vec![status(403, "forbidden")]);
        let Err(err) = login(SECRET, &mut t) else {
            panic!("expected login to fail on HTTP 403");
        };
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("forbidden"), "{err}");
    }

    // ── Single refresh ────────────────────────────────────────────────

    #[test]
    fn refresh_replaces_token_and_embeds_old_token() {
        let mut t = StubTransport::new(vec![
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-A"}]"#),
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-B"}]"#),
        ]);
        let mut session = login(SECRET, &mut t).unwrap();
        session.refresh(SECRET, &mut t).unwrap();
        assert_eq!(session.bearer(), "jwt-B");
        // The refresh POST went to the single-refresh path and embedded
        // the OLD token in the body.
        let refresh_call = &t.calls[1];
        assert_eq!(refresh_call.path, SINGLE_REFRESH_PATH);
        let parsed = json::parse(refresh_call.body.as_ref().unwrap()).unwrap();
        let payload = &parsed.as_array().unwrap()[1];
        assert_eq!(
            payload.get("accessToken").and_then(JsonValue::as_str),
            Some("jwt-A")
        );
    }

    // ── Proactive margin ──────────────────────────────────────────────

    #[test]
    fn refresh_if_stale_is_a_noop_when_fresh() {
        let mut session = EsvSession::with_age("jwt-A".to_string(), std::time::Duration::ZERO);
        let mut t = StubTransport::new(vec![]);
        assert!(!session.refresh_if_stale(SECRET, &mut t).unwrap());
        assert!(t.calls.is_empty());
        assert_eq!(session.bearer(), "jwt-A");
    }

    #[test]
    fn refresh_if_stale_refreshes_when_aged_past_margin() {
        let mut session =
            EsvSession::with_age("jwt-A".to_string(), std::time::Duration::from_mins(25));
        assert!(session.needs_refresh());
        let mut t = StubTransport::new(vec![ok(
            r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-B"}]"#,
        )]);
        assert!(session.refresh_if_stale(SECRET, &mut t).unwrap());
        assert_eq!(session.bearer(), "jwt-B");
        assert!(!session.needs_refresh());
        assert_eq!(t.calls.len(), 1);
    }

    // ── Reactive 401/403 retry ────────────────────────────────────────

    #[test]
    fn authenticated_request_refreshes_and_retries_once_on_403() {
        let mut session = EsvSession::with_age("jwt-A".to_string(), std::time::Duration::ZERO);
        let mut t = StubTransport::new(vec![
            status(403, "expired"),                                  // first attempt
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-B"}]"#), // refresh
            ok("payload-ok"),                                        // retried request
        ]);
        let resp = session
            .authenticated_request(SECRET, "POST", "/esv/v1/dataFiles", Some("x"), &mut t)
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "payload-ok");
        assert_eq!(session.bearer(), "jwt-B");
        // 3 calls: rejected request, refresh, retried request. The retry
        // carried the refreshed bearer.
        assert_eq!(t.calls.len(), 3);
        assert_eq!(t.calls[0].bearer, "jwt-A");
        assert_eq!(t.calls[1].path, SINGLE_REFRESH_PATH);
        assert_eq!(t.calls[2].bearer, "jwt-B");
    }

    #[test]
    fn authenticated_request_does_not_retry_on_success() {
        let mut session = EsvSession::with_age("jwt-A".to_string(), std::time::Duration::ZERO);
        let mut t = StubTransport::new(vec![ok("payload-ok")]);
        let resp = session
            .authenticated_request(SECRET, "GET", "/esv/v1/dataFiles/1", None, &mut t)
            .unwrap();
        assert_eq!(resp.body, "payload-ok");
        assert_eq!(t.calls.len(), 1);
        assert_eq!(t.calls[0].bearer, "jwt-A");
    }

    #[test]
    fn authenticated_request_proactively_refreshes_before_sending_when_stale() {
        let mut session =
            EsvSession::with_age("jwt-A".to_string(), std::time::Duration::from_mins(25));
        let mut t = StubTransport::new(vec![
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-B"}]"#), // proactive refresh
            ok("payload-ok"),                                        // request with fresh bearer
        ]);
        let resp = session
            .authenticated_request(SECRET, "GET", "/esv/v1/dataFiles/1", None, &mut t)
            .unwrap();
        assert_eq!(resp.body, "payload-ok");
        assert_eq!(t.calls.len(), 2);
        assert_eq!(t.calls[0].path, SINGLE_REFRESH_PATH);
        assert_eq!(t.calls[1].bearer, "jwt-B");
    }

    // ── Bulk refresh ──────────────────────────────────────────────────

    #[test]
    fn bulk_refresh_posts_token_array_and_parses_response() {
        let tokens = vec!["t1".to_string(), "t2".to_string()];
        let mut t = StubTransport::new(vec![ok(
            r#"[{"esvVersion":"1.0"},{"accessToken":["n1","n2"]}]"#,
        )]);
        let refreshed = bulk_refresh(SECRET, &tokens, &mut t).unwrap();
        assert_eq!(refreshed, vec!["n1".to_string(), "n2".to_string()]);
        assert_eq!(t.calls.len(), 1);
        assert_eq!(t.calls[0].path, BULK_REFRESH_PATH);
        let parsed = json::parse(t.calls[0].body.as_ref().unwrap()).unwrap();
        let payload = &parsed.as_array().unwrap()[1];
        let sent = payload
            .get("accessToken")
            .and_then(JsonValue::as_array)
            .unwrap();
        let sent: Vec<&str> = sent.iter().filter_map(JsonValue::as_str).collect();
        assert_eq!(sent, vec!["t1", "t2"]);
    }

    // ── TOTP reuse (byte-identical to ESV-Server totp.py) ─────────────

    #[test]
    fn reused_totp_is_deterministic_and_eight_digits() {
        // Reuse acvp-harness's generator, which produces the same code
        // as the ESV reference client's totp.py (confirmed: RFC-4226
        // dynamic truncation over HMAC-SHA-256, top bit masked, mod
        // 10^8, 8 digits).
        let a = totp_at(SECRET, 1).unwrap();
        let b = totp_at(SECRET, 1).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert!(a.bytes().all(|c| c.is_ascii_digit()));
        assert_ne!(a, totp_at(SECRET, 2).unwrap());
    }
}
