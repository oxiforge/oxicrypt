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
//! - **Endpoint paths carry the full server-relative path** (`/esv/v1/…`)
//!   and the transport base is **host-only** — see the path constants
//!   below and the reference-config trap they document.
//!   (reference client `jsons/config.demo.json:5-6`: `EsvVersion "1.0"`.)
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
//! - **TOTP-window-reuse retry:** a 403 whose body reports "TOTP Window
//!   has already been used" is transient — the reference client waits
//!   10 s and retries with a fresh TOTP (`login.py:19-29,41-44`). This
//!   module mirrors that (see [`is_totp_window_reuse`] and the
//!   [`Sleeper`]-driven retry in the flow entry points), bounded by
//!   [`TOTP_REUSE_RETRY_CAP`].
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

use std::time::Duration;

use acvp_harness::json::{self, JsonValue};
use acvp_harness::transport::{
    HttpResponse, TOKEN_REFRESH_MARGIN_SECS, submit_should_refresh_retry, totp_now,
};

/// The only ESVP version the NIST servers support.
///
/// (reference client `jsons/config.demo.json:6`: `EsvVersion "1.0"`.)
pub const ESV_VERSION: &str = "1.0";

/// Login endpoint path — the **full server-relative path**.
///
/// The transport base is **host-only** (e.g.
/// `https://demo.esvts.nist.gov:7443`), matching acvp-harness's
/// convention: its `server_url` is host-only and the paths carry
/// `/acvp/v1` (`acvp-harness/src/transport.rs` ~L904). These ESV
/// constants likewise carry the full `/esv/v1/…` path, so the base must
/// contribute the host only.
///
/// **Reference-config trap:** the reference client's
/// `jsons/config.demo.json` `ServerURL` already ends in `/esv/v1`
/// (`https://demo.esvts.nist.gov:7443/esv/v1`). It must **not** be used
/// verbatim as the transport base — doing so doubles the path to
/// `/esv/v1/esv/v1/login` (404). Strip the `/esv/v1` suffix to a
/// host-only base. (reference client `authentication/login.py:66`.)
pub const LOGIN_PATH: &str = "/esv/v1/login";

/// Single-token refresh endpoint — the full server-relative path. Per the
/// ESVP digest §2 a single refresh is a same-scope re-login at
/// [`LOGIN_PATH`]; see the module docs for the reference-client
/// divergence resolved by judgment, and [`LOGIN_PATH`] for the host-only
/// base convention and the reference-config trap.
pub const SINGLE_REFRESH_PATH: &str = LOGIN_PATH;

/// Bulk refresh endpoint — the full server-relative path; refreshes an
/// array of per-object JWTs in one TOTP touch. See [`LOGIN_PATH`] for the
/// host-only base convention and the reference-config trap. (ESVP digest
/// §2; reference client `authentication/login.py:39`.)
pub const BULK_REFRESH_PATH: &str = "/esv/v1/login/refresh";

/// Maximum TOTP-window-reuse retries before surfacing a typed error.
///
/// The reference client (`authentication/login.py:41-44`) loops
/// unbounded on the "TOTP Window has already been used" 403, waiting 10 s
/// each time. This harness caps the retries to avoid an indefinite
/// attended stall on a persistently rejected window.
pub const TOTP_REUSE_RETRY_CAP: u8 = 3;

/// The wait between TOTP-window-reuse retries (reference client
/// `authentication/login.py:44`: `time.sleep(10)`).
const TOTP_REUSE_WAIT: Duration = Duration::from_secs(10);

/// An injectable wait, so the TOTP-window-reuse retry is driven by a
/// recording no-op in unit tests and by real [`std::thread::sleep`] in
/// attended runs.
pub trait Sleeper {
    /// Block for `dur`.
    fn sleep(&mut self, dur: Duration);
}

/// The production [`Sleeper`], backed by [`std::thread::sleep`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&mut self, dur: Duration) {
        std::thread::sleep(dur);
    }
}

/// True when a response is the transient "TOTP window already used" 403
/// the NIST reference client retries.
///
/// The reference client (`authentication/login.py:19-29`, `did_totp_fail`)
/// treats a 403 whose envelope element 1 carries an `error` containing
/// "TOTP Window has already been used" as the retry trigger; a substring
/// match over the whole body is equivalent and robust to envelope shape.
pub fn is_totp_window_reuse(status: u16, body: &str) -> bool {
    status == 403 && body.contains("TOTP Window has already been used")
}

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

/// The minimal read surface an ESV versioned-array envelope is validated
/// against, so the one [`esv_payload_element`] check can run over **either**
/// JSON value model the harness parses with: the integer-only
/// [`acvp_harness::json`] codec (every float-free auth / registration /
/// supporting-doc response) and the float-tolerant [`crate::jsonlite`] reader
/// (the data-file status response, whose `Run Successful` body carries
/// fractional min-entropy numbers the integer-only codec cannot read). Keeping
/// a single envelope validator over this trait means the two readers cannot
/// drift on what a well-formed ESV envelope is.
pub(crate) trait EnvelopeValue: Sized {
    /// Borrow this value as a slice of the same value type if it is an array.
    fn env_as_array(&self) -> Option<&[Self]>;
    /// Look up an object field by key.
    fn env_get(&self, key: &str) -> Option<&Self>;
    /// Borrow this value as a `&str` if it is a string.
    fn env_as_str(&self) -> Option<&str>;
}

impl EnvelopeValue for JsonValue {
    fn env_as_array(&self) -> Option<&[Self]> {
        self.as_array()
    }
    fn env_get(&self, key: &str) -> Option<&Self> {
        self.get(key)
    }
    fn env_as_str(&self) -> Option<&str> {
        self.as_str()
    }
}

impl EnvelopeValue for crate::jsonlite::JsonLite {
    fn env_as_array(&self) -> Option<&[Self]> {
        self.as_array()
    }
    fn env_get(&self, key: &str) -> Option<&Self> {
        self.get(key)
    }
    fn env_as_str(&self) -> Option<&str> {
        self.as_str()
    }
}

/// Require the ESVP versioned envelope `[{esvVersion}, {payload}, …]` and
/// return a reference to the payload element (index 1).
///
/// ESV responses are **always** this envelope. The check is **at-least-two**
/// elements, not exactly two: element 0 must carry a string `esvVersion`,
/// element 1 is the payload, and any trailing elements are ignored — so an
/// additive server-side envelope variance is tolerated while a bare
/// `{accessToken:…}` object (or a version-less first element) is still
/// rejected. This is the fail-closed esv-side check that
/// [`parse_access_token`], [`parse_bulk_refresh_tokens`],
/// [`crate::registration::parse_registration_response`], and the data-file
/// status poll ([`crate::datafiles::poll_data_file`]) share; it deliberately
/// rejects the bare-object form that the more permissive
/// `acvp_harness::transport::extract_access_token` accepts. Generic over
/// [`EnvelopeValue`] so both the integer-only codec and the float-tolerant
/// [`crate::jsonlite`] reader reuse the identical validation. Exposed
/// `pub(crate)`.
pub(crate) fn esv_payload_element<V: EnvelopeValue>(parsed: &V) -> Result<&V, String> {
    let arr = parsed
        .env_as_array()
        .ok_or("ESV response is not a versioned-array envelope")?;
    if arr.len() < 2 {
        return Err(format!(
            "ESV response envelope must have at least two elements, got {}",
            arr.len()
        ));
    }
    let version_ok = arr
        .first()
        .and_then(|v| v.env_get("esvVersion"))
        .and_then(V::env_as_str)
        .is_some();
    if !version_ok {
        return Err("ESV response envelope element 0 is not an {esvVersion} object".to_string());
    }
    arr.get(1)
        .ok_or_else(|| "ESV response envelope is missing its payload element".to_string())
}

/// Parse a single `accessToken` string out of a login / single-refresh
/// response body.
///
/// **Fail-closed vs. the acvp helper:** this requires the ESVP two-element
/// versioned envelope `[{esvVersion}, {payload}]` and reads `accessToken`
/// from the payload element. It intentionally does **not** delegate to
/// `acvp_harness::transport::extract_access_token`, which also accepts a
/// bare `{"accessToken":"…"}` object (an ACVP-side permissiveness) — ESV
/// responses are always the envelope, so the bare-object form is rejected.
pub fn parse_access_token(body: &str) -> Result<String, String> {
    let parsed = json::parse(body).map_err(|e| format!("parse ESV auth response: {e}"))?;
    let payload = esv_payload_element(&parsed)?;
    payload
        .get("accessToken")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "no string accessToken in ESV auth payload: {}",
                json::to_pretty_string(&parsed)
            )
        })
}

/// Parse the `accessToken` array from a bulk-refresh response body,
/// returning the refreshed tokens in order.
///
/// `expected` is the number of tokens submitted. The ESVP bulk-refresh
/// response maps positionally one-to-one onto the submitted array, so the
/// returned length **must** equal `expected` — a mismatch (including an
/// empty array, or a single string when more than one token was sent) is
/// a typed error rather than a silently truncated mapping. A single-string
/// response is accepted only when exactly one token was expected.
pub fn parse_bulk_refresh_tokens(body: &str, expected: usize) -> Result<Vec<String>, String> {
    let parsed = json::parse(body).map_err(|e| format!("parse ESV bulk-refresh response: {e}"))?;
    let payload = esv_payload_element(&parsed)?;
    let field = payload.get("accessToken").ok_or_else(|| {
        format!(
            "no accessToken in ESV bulk-refresh response: {}",
            json::to_pretty_string(&parsed)
        )
    })?;

    let tokens = if let Some(arr) = field.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for tok in arr {
            let s = tok
                .as_str()
                .ok_or("accessToken array element is not a string")?;
            out.push(s.to_string());
        }
        out
    } else if let Some(s) = field.as_str() {
        vec![s.to_string()]
    } else {
        return Err("bulk-refresh accessToken is neither a string nor an array".to_string());
    };

    if tokens.len() != expected {
        return Err(format!(
            "ESV bulk-refresh returned {} token(s) for {} submitted — positional mapping broken",
            tokens.len(),
            expected
        ));
    }
    Ok(tokens)
}

/// POST a freshly-TOTP-signed body to `path`, transparently retrying a
/// "TOTP window already used" 403 after a 10 s [`Sleeper`] wait (bounded
/// by [`TOTP_REUSE_RETRY_CAP`]).
///
/// `build_body` is invoked on **each** attempt so every retry carries a
/// fresh TOTP. Returns the final response — including a non-2xx status
/// other than TOTP-window-reuse — so the caller decides how to treat it.
/// Errs only on a transport failure or when the window-reuse retry cap is
/// exhausted.
fn post_totp_signed<T, F>(
    transport: &mut T,
    sleeper: &mut dyn Sleeper,
    path: &str,
    totp_secret: &[u8],
    build_body: F,
) -> Result<HttpResponse, String>
where
    T: EsvTransport,
    F: Fn(&str) -> String,
{
    let mut retries = 0u8;
    loop {
        let code = totp_now(totp_secret)?;
        let body = build_body(&code);
        let resp = transport.request("POST", path, Some(&body), "")?;
        if is_totp_window_reuse(resp.status, &resp.body) {
            if retries >= TOTP_REUSE_RETRY_CAP {
                return Err(format!(
                    "ESV POST {path} rejected: TOTP window reuse persisted after {retries} retries"
                ));
            }
            retries = retries.saturating_add(1);
            sleeper.sleep(TOTP_REUSE_WAIT);
            continue;
        }
        return Ok(resp);
    }
}

/// [`post_totp_signed`] plus an HTTP-2xx requirement: a non-2xx status
/// (that is not TOTP-window-reuse) becomes a status-and-body error.
fn post_totp_signed_expect_success<T, F>(
    transport: &mut T,
    sleeper: &mut dyn Sleeper,
    path: &str,
    totp_secret: &[u8],
    build_body: F,
) -> Result<HttpResponse, String>
where
    T: EsvTransport,
    F: Fn(&str) -> String,
{
    let resp = post_totp_signed(transport, sleeper, path, totp_secret, build_body)?;
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
/// generator), POSTs the login envelope to [`LOGIN_PATH`] (retrying a
/// transient TOTP-window-reuse 403 via `sleeper`), and parses the
/// returned access token.
pub fn login<T: EsvTransport>(
    totp_secret: &[u8],
    transport: &mut T,
    sleeper: &mut dyn Sleeper,
) -> Result<EsvSession, String> {
    let resp =
        post_totp_signed_expect_success(transport, sleeper, LOGIN_PATH, totp_secret, |code| {
            build_login_body(code)
        })?;
    let token = parse_access_token(&resp.body)?;
    Ok(EsvSession::new(token))
}

/// Bulk-refresh an array of per-object JWTs in one TOTP touch, returning
/// the refreshed tokens in the same order. Used immediately before
/// certify, when many per-object tokens must all be fresh at once.
///
/// The response is required to carry exactly as many tokens as were
/// submitted (see [`parse_bulk_refresh_tokens`]); a transient
/// TOTP-window-reuse 403 is retried via `sleeper`.
pub fn bulk_refresh<T: EsvTransport>(
    totp_secret: &[u8],
    access_tokens: &[String],
    transport: &mut T,
    sleeper: &mut dyn Sleeper,
) -> Result<Vec<String>, String> {
    let resp = post_totp_signed_expect_success(
        transport,
        sleeper,
        BULK_REFRESH_PATH,
        totp_secret,
        |code| build_bulk_refresh_body(code, access_tokens),
    )?;
    parse_bulk_refresh_tokens(&resp.body, access_tokens.len())
}

/// An authenticated ESV session: the current access token plus its
/// issuance instant, so a long submission can refresh the 30-minute-TTL
/// token in flight.
///
/// The reactive-retry decision reuses acvp-harness's pure predicate
/// ([`submit_should_refresh_retry`]); the proactive margin is a per-session
/// field ([`EsvSession::refresh_margin_secs`]) so it can be tuned once the
/// ESV-side token TTL is measured at the attended demo smoke.
pub struct EsvSession {
    token: String,
    /// Issuance instant of [`Self::token`].
    ///
    /// **Suspend-blind:** [`std::time::Instant`] is CLOCK_MONOTONIC and
    /// does **not** advance across an OS suspend, so `elapsed()` can read
    /// "fresh" while the wall-clock token TTL has already expired (for
    /// example a laptop suspended for longer than the ~30-minute TTL). A
    /// refresh that then embeds the stale token would 401/403;
    /// [`Self::refresh`] falls back to a plain fresh login for exactly
    /// this case.
    issued: std::time::Instant,
    /// Token age (seconds) at which [`Self::needs_refresh`] fires.
    /// Defaults to acvp-harness's ACVP-measured
    /// [`TOKEN_REFRESH_MARGIN_SECS`]; tunable via
    /// [`Self::with_refresh_margin_secs`] / [`Self::set_refresh_margin_secs`].
    refresh_margin_secs: u64,
    /// Monotonic count of times [`Self::refresh`] silently fell back to a
    /// **fresh login** (a non-window 401/403 on the embedded-token refresh;
    /// see [`Self::refresh`]). Observable via [`Self::fallback_logins`].
    ///
    /// This is the caller-visible signal a fresh-login fallback happened even
    /// on the paths that discard the refresh outcome
    /// ([`Self::refresh_if_stale`], [`Self::authenticated_request`]): a fresh
    /// login obtains a new **same-scope** token, but that new authorization
    /// may not carry continuity over objects created/registered under the
    /// previous token in the same session. The attended smoke must watch this
    /// counter and re-verify in-flight object authorization if it is non-zero.
    fallback_logins: u32,
}

impl EsvSession {
    /// Wrap a freshly-issued token, stamping the issuance instant to now
    /// and the refresh margin to the ACVP-measured default.
    fn new(token: String) -> Self {
        Self {
            token,
            issued: std::time::Instant::now(),
            refresh_margin_secs: TOKEN_REFRESH_MARGIN_SECS,
            fallback_logins: 0,
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
            refresh_margin_secs: TOKEN_REFRESH_MARGIN_SECS,
            fallback_logins: 0,
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

    /// The proactive refresh margin in seconds (see
    /// [`Self::refresh_margin_secs`] field).
    pub fn refresh_margin_secs(&self) -> u64 {
        self.refresh_margin_secs
    }

    /// How many times [`Self::refresh`] has fallen back to a fresh login (see
    /// the [`Self::fallback_logins`] field). Zero on a healthy session; the
    /// attended smoke watches this to catch same-scope-continuity risk.
    pub fn fallback_logins(&self) -> u32 {
        self.fallback_logins
    }

    /// Builder: set the proactive refresh margin (seconds).
    ///
    /// The default is the ACVP-measured [`TOKEN_REFRESH_MARGIN_SECS`]
    /// (20 min, against the ACVP demo's observed `exp − iat` = 1800 s). The
    /// **ESV-side** token TTL is unmeasured until the attended demo smoke;
    /// re-measure `exp − iat` there and adjust if it differs.
    #[must_use]
    pub fn with_refresh_margin_secs(mut self, secs: u64) -> Self {
        self.refresh_margin_secs = secs;
        self
    }

    /// Setter form of [`Self::with_refresh_margin_secs`].
    pub fn set_refresh_margin_secs(&mut self, secs: u64) {
        self.refresh_margin_secs = secs;
    }

    /// True once the token has aged past the proactive refresh margin.
    pub fn needs_refresh(&self) -> bool {
        self.elapsed_secs() >= self.refresh_margin_secs
    }

    /// Single-token refresh: re-login at [`SINGLE_REFRESH_PATH`] embedding
    /// the current token, replacing the token and resetting its age on
    /// success.
    ///
    /// If the refresh is rejected 401/403 (a non-window-reuse rejection —
    /// window reuse is retried transparently by the [`Sleeper`]-driven
    /// POST), the embedded token is treated as stale (see the
    /// suspend-blind note on [`Self::issued`]) and the flow falls back to a
    /// **plain fresh login** (no embedded token) before surfacing an
    /// error.
    ///
    /// A successful fresh-login fallback increments
    /// [`Self::fallback_logins`] so the event stays observable even through
    /// the callers that discard it ([`Self::refresh_if_stale`],
    /// [`Self::authenticated_request`]). The fallback obtains a new
    /// **same-scope** token, but that new authorization may not carry
    /// continuity over objects created under the prior token in the same
    /// session — the attended smoke re-verifies in-flight objects when
    /// [`Self::fallback_logins`] is non-zero.
    pub fn refresh<T: EsvTransport>(
        &mut self,
        totp_secret: &[u8],
        transport: &mut T,
        sleeper: &mut dyn Sleeper,
    ) -> Result<(), String> {
        let old = self.token.clone();
        let resp = post_totp_signed(
            transport,
            sleeper,
            SINGLE_REFRESH_PATH,
            totp_secret,
            |code| build_single_refresh_body(code, &old),
        )?;
        if is_success(resp.status) {
            self.adopt_token(&resp.body)?;
            return Ok(());
        }
        if resp.status == 401 || resp.status == 403 {
            // Suspend-blind clock (see the `issued` field docs): the
            // embedded token may be wall-clock-expired even though the
            // monotonic age looked fresh. Fall back to a fresh login.
            let fresh = post_totp_signed(transport, sleeper, LOGIN_PATH, totp_secret, |code| {
                build_login_body(code)
            })?;
            if is_success(fresh.status) {
                self.adopt_token(&fresh.body)?;
                self.fallback_logins = self.fallback_logins.saturating_add(1);
                return Ok(());
            }
            return Err(format!(
                "ESV refresh and fresh-login fallback both failed: \
                 refresh HTTP {}, login HTTP {} — {}",
                resp.status, fresh.status, fresh.body
            ));
        }
        Err(format!(
            "ESV refresh POST {SINGLE_REFRESH_PATH} failed: HTTP {} — {}",
            resp.status, resp.body
        ))
    }

    /// Parse a fresh token out of a login/refresh response body and adopt
    /// it, resetting the issuance instant.
    fn adopt_token(&mut self, body: &str) -> Result<(), String> {
        self.token = parse_access_token(body)?;
        self.issued = std::time::Instant::now();
        Ok(())
    }

    /// Proactively refresh the token if it has aged past the margin.
    /// Returns whether a refresh was performed.
    pub fn refresh_if_stale<T: EsvTransport>(
        &mut self,
        totp_secret: &[u8],
        transport: &mut T,
        sleeper: &mut dyn Sleeper,
    ) -> Result<bool, String> {
        if self.needs_refresh() {
            self.refresh(totp_secret, transport, sleeper)?;
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
        sleeper: &mut dyn Sleeper,
    ) -> Result<HttpResponse, String> {
        self.refresh_if_stale(totp_secret, transport, sleeper)?;
        let resp = transport.request(method, path, body, self.bearer())?;
        if submit_should_refresh_retry(resp.status, false) {
            self.refresh(totp_secret, transport, sleeper)?;
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

    /// A [`Sleeper`] that records the requested waits instead of blocking.
    #[derive(Default)]
    struct RecordingSleeper {
        slept: Vec<Duration>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(&mut self, dur: Duration) {
            self.slept.push(dur);
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

    /// A 403 body reporting a reused TOTP window (reference-client shape).
    fn totp_reuse_403() -> HttpResponse {
        status(
            403,
            r#"[{"esvVersion":"1.0"},{"error":"TOTP Window has already been used"}]"#,
        )
    }

    const SECRET: &[u8] = b"12345678901234567890";

    /// The 8-digit password carried by a signed request body.
    fn password_of(body: &str) -> String {
        let parsed = json::parse(body).unwrap();
        parsed.as_array().unwrap()[1]
            .get("password")
            .and_then(JsonValue::as_str)
            .unwrap()
            .to_string()
    }

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
    fn parse_access_token_rejects_bare_object_envelope() {
        // Item 2: the acvp helper accepts a bare {accessToken}; the strict
        // esv-side parser requires the two-element versioned envelope.
        let bare = r#"{"accessToken":"jwt-bare"}"#;
        assert!(parse_access_token(bare).is_err());
        // Sanity: the same token inside a proper envelope IS accepted.
        let enveloped = r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-bare"}]"#;
        assert_eq!(parse_access_token(enveloped).unwrap(), "jwt-bare");
    }

    #[test]
    fn parse_access_token_tolerates_trailing_envelope_element() {
        // Item 5: at-least-two tolerance — a third element is additive server
        // variance and is ignored; the payload is still element 1.
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-x"},{"extra":true}]"#;
        assert_eq!(parse_access_token(body).unwrap(), "jwt-x");
    }

    #[test]
    fn parse_access_token_rejects_single_element_envelope() {
        // One element is below the at-least-two floor.
        let body = r#"[{"esvVersion":"1.0"}]"#;
        assert!(parse_access_token(body).is_err());
    }

    #[test]
    fn parse_bulk_refresh_tokens_returns_array_in_order() {
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":["t1","t2","t3"]}]"#;
        assert_eq!(
            parse_bulk_refresh_tokens(body, 3).unwrap(),
            vec!["t1".to_string(), "t2".to_string(), "t3".to_string()]
        );
    }

    #[test]
    fn parse_bulk_refresh_tokens_wraps_single_string() {
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":"solo"}]"#;
        assert_eq!(
            parse_bulk_refresh_tokens(body, 1).unwrap(),
            vec!["solo".to_string()]
        );
    }

    #[test]
    fn parse_bulk_refresh_tokens_errors_when_absent() {
        let body = r#"[{"esvVersion":"1.0"},{"nope":true}]"#;
        assert!(parse_bulk_refresh_tokens(body, 1).is_err());
    }

    // ── Item 1: bulk count integrity ──────────────────────────────────

    #[test]
    fn parse_bulk_refresh_tokens_rejects_short_count() {
        // Submitted 2, server returned 1 → positional mapping broken.
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":["only-one"]}]"#;
        let err = parse_bulk_refresh_tokens(body, 2).unwrap_err();
        assert!(err.contains("positional mapping broken"), "{err}");
    }

    #[test]
    fn parse_bulk_refresh_tokens_rejects_empty_array() {
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":[]}]"#;
        assert!(parse_bulk_refresh_tokens(body, 2).is_err());
        // Even a zero-expected empty array is a degenerate no-op we reject
        // by construction only when expected>0; expected==0 matches.
        assert_eq!(
            parse_bulk_refresh_tokens(body, 0).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn parse_bulk_refresh_tokens_exact_count_preserves_order() {
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":["x","y"]}]"#;
        assert_eq!(
            parse_bulk_refresh_tokens(body, 2).unwrap(),
            vec!["x".to_string(), "y".to_string()]
        );
    }

    #[test]
    fn parse_bulk_refresh_tokens_single_string_wrong_expected_fails() {
        // A single string when two were submitted is a count mismatch.
        let body = r#"[{"esvVersion":"1.0"},{"accessToken":"solo"}]"#;
        assert!(parse_bulk_refresh_tokens(body, 2).is_err());
    }

    // ── Login flow ────────────────────────────────────────────────────

    #[test]
    fn login_posts_to_login_path_and_returns_session() {
        let mut t = StubTransport::new(vec![ok(
            r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-A"}]"#,
        )]);
        let mut sl = RecordingSleeper::default();
        let session = login(SECRET, &mut t, &mut sl).unwrap();
        assert_eq!(session.bearer(), "jwt-A");
        assert_eq!(t.calls.len(), 1);
        let call = &t.calls[0];
        assert_eq!(call.method, "POST");
        assert_eq!(call.path, LOGIN_PATH);
        assert_eq!(call.bearer, "");
        // Body is a well-formed login envelope with an 8-digit password.
        let code = password_of(call.body.as_ref().unwrap());
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert!(sl.slept.is_empty());
    }

    #[test]
    fn login_surfaces_http_error_status_and_body() {
        let mut t = StubTransport::new(vec![status(403, "forbidden")]);
        let mut sl = RecordingSleeper::default();
        let Err(err) = login(SECRET, &mut t, &mut sl) else {
            panic!("expected login to fail on HTTP 403");
        };
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("forbidden"), "{err}");
    }

    // ── Item 3: TOTP-window-reuse retry ───────────────────────────────

    #[test]
    fn is_totp_window_reuse_matches_only_the_reuse_403() {
        let phrase = r#"[{"esvVersion":"1.0"},{"error":"TOTP Window has already been used"}]"#;
        assert!(is_totp_window_reuse(403, phrase));
        // Non-403 status with the phrase, or a 403 without it, do not match.
        assert!(!is_totp_window_reuse(200, phrase));
        assert!(!is_totp_window_reuse(401, phrase));
        assert!(!is_totp_window_reuse(403, "some other forbidden reason"));
    }

    #[test]
    fn login_retries_on_totp_window_reuse_then_succeeds() {
        let mut t = StubTransport::new(vec![
            totp_reuse_403(),
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-A"}]"#),
        ]);
        let mut sl = RecordingSleeper::default();
        let session = login(SECRET, &mut t, &mut sl).unwrap();
        assert_eq!(session.bearer(), "jwt-A");
        // Two POSTs (rejected + retried); exactly one 10 s wait.
        assert_eq!(t.calls.len(), 2);
        assert_eq!(sl.slept, vec![Duration::from_secs(10)]);
        // The retry recomputed a fresh signed body (8-digit password).
        for call in &t.calls {
            assert_eq!(call.path, LOGIN_PATH);
            assert_eq!(password_of(call.body.as_ref().unwrap()).len(), 8);
        }
    }

    #[test]
    fn login_non_window_403_is_not_retried() {
        let mut t = StubTransport::new(vec![status(403, "bad certificate")]);
        let mut sl = RecordingSleeper::default();
        assert!(login(SECRET, &mut t, &mut sl).is_err());
        assert_eq!(t.calls.len(), 1);
        assert!(sl.slept.is_empty());
    }

    #[test]
    fn totp_window_reuse_retry_cap_is_enforced() {
        // Persistent reuse: initial + CAP retries all reused → typed error.
        let mut responses = Vec::new();
        for _ in 0..=TOTP_REUSE_RETRY_CAP {
            responses.push(totp_reuse_403());
        }
        let mut t = StubTransport::new(responses);
        let mut sl = RecordingSleeper::default();
        let Err(err) = login(SECRET, &mut t, &mut sl) else {
            panic!("expected login to fail once the TOTP-reuse cap is hit");
        };
        assert!(err.contains("TOTP window reuse persisted"), "{err}");
        // CAP waits, CAP+1 POSTs.
        assert_eq!(sl.slept.len(), usize::from(TOTP_REUSE_RETRY_CAP));
        assert_eq!(t.calls.len(), usize::from(TOTP_REUSE_RETRY_CAP) + 1);
    }

    // ── Single refresh ────────────────────────────────────────────────

    #[test]
    fn refresh_replaces_token_and_embeds_old_token() {
        let mut t = StubTransport::new(vec![
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-A"}]"#),
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-B"}]"#),
        ]);
        let mut sl = RecordingSleeper::default();
        let mut session = login(SECRET, &mut t, &mut sl).unwrap();
        session.refresh(SECRET, &mut t, &mut sl).unwrap();
        assert_eq!(session.bearer(), "jwt-B");
        // A normal (2xx) refresh is not a fallback login.
        assert_eq!(session.fallback_logins(), 0);
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

    // ── Item 6: fresh-login fallback on refresh 401/403 ───────────────

    #[test]
    fn refresh_falls_back_to_fresh_login_on_401() {
        let mut session = EsvSession::with_age("jwt-A".to_string(), std::time::Duration::ZERO);
        let mut t = StubTransport::new(vec![
            status(401, "unauthorized: token expired"), // embedded-token refresh rejected
            ok(r#"[{"esvVersion":"1.0"},{"accessToken":"jwt-C"}]"#), // fresh login
        ]);
        let mut sl = RecordingSleeper::default();
        assert_eq!(session.fallback_logins(), 0);
        session.refresh(SECRET, &mut t, &mut sl).unwrap();
        assert_eq!(session.bearer(), "jwt-C");
        // Item 8: the fresh-login fallback is observable via the counter.
        assert_eq!(session.fallback_logins(), 1);
        // First call embedded the old token; the fallback carried none.
        assert_eq!(t.calls.len(), 2);
        assert_eq!(t.calls[0].path, SINGLE_REFRESH_PATH);
        let first = json::parse(t.calls[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(
            first.as_array().unwrap()[1]
                .get("accessToken")
                .and_then(JsonValue::as_str),
            Some("jwt-A")
        );
        assert_eq!(t.calls[1].path, LOGIN_PATH);
        let second = json::parse(t.calls[1].body.as_ref().unwrap()).unwrap();
        assert!(
            second.as_array().unwrap()[1].get("accessToken").is_none(),
            "fresh-login fallback must not embed a token"
        );
    }

    #[test]
    fn refresh_surfaces_typed_error_when_both_refresh_and_login_fail() {
        let mut session = EsvSession::with_age("jwt-A".to_string(), std::time::Duration::ZERO);
        let mut t = StubTransport::new(vec![
            status(403, "expired"), // refresh rejected
            status(403, "denied"),  // fresh login also rejected
        ]);
        let mut sl = RecordingSleeper::default();
        let err = session.refresh(SECRET, &mut t, &mut sl).unwrap_err();
        assert!(err.contains("both failed"), "{err}");
        assert_eq!(t.calls.len(), 2);
    }

    // ── Proactive margin ──────────────────────────────────────────────

    #[test]
    fn refresh_if_stale_is_a_noop_when_fresh() {
        let mut session = EsvSession::with_age("jwt-A".to_string(), std::time::Duration::ZERO);
        let mut t = StubTransport::new(vec![]);
        let mut sl = RecordingSleeper::default();
        assert!(!session.refresh_if_stale(SECRET, &mut t, &mut sl).unwrap());
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
        let mut sl = RecordingSleeper::default();
        assert!(session.refresh_if_stale(SECRET, &mut t, &mut sl).unwrap());
        assert_eq!(session.bearer(), "jwt-B");
        assert!(!session.needs_refresh());
        assert_eq!(t.calls.len(), 1);
    }

    // ── Item 7: tunable refresh margin ────────────────────────────────

    #[test]
    fn refresh_margin_defaults_to_acvp_measured_const() {
        let session = EsvSession::new("jwt-A".to_string());
        assert_eq!(session.refresh_margin_secs(), TOKEN_REFRESH_MARGIN_SECS);
    }

    #[test]
    fn tunable_refresh_margin_changes_needs_refresh() {
        // A 2-minute-old token is fresh under the 20-min default…
        let session = EsvSession::with_age("jwt-A".to_string(), std::time::Duration::from_mins(2));
        assert!(!session.needs_refresh());
        // …but stale once the margin is tightened to 60 s (builder + setter).
        let session = session.with_refresh_margin_secs(60);
        assert!(session.needs_refresh());
        let mut session = session;
        session.set_refresh_margin_secs(10 * 60);
        assert!(!session.needs_refresh());
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
        let mut sl = RecordingSleeper::default();
        let resp = session
            .authenticated_request(
                SECRET,
                "POST",
                "/esv/v1/dataFiles",
                Some("x"),
                &mut t,
                &mut sl,
            )
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
        let mut sl = RecordingSleeper::default();
        let resp = session
            .authenticated_request(SECRET, "GET", "/esv/v1/dataFiles/1", None, &mut t, &mut sl)
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
        let mut sl = RecordingSleeper::default();
        let resp = session
            .authenticated_request(SECRET, "GET", "/esv/v1/dataFiles/1", None, &mut t, &mut sl)
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
        let mut sl = RecordingSleeper::default();
        let refreshed = bulk_refresh(SECRET, &tokens, &mut t, &mut sl).unwrap();
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

    #[test]
    fn bulk_refresh_fails_when_server_returns_wrong_count() {
        // Submitted 2, server returned 1 → typed count-integrity error.
        let tokens = vec!["t1".to_string(), "t2".to_string()];
        let mut t = StubTransport::new(vec![ok(
            r#"[{"esvVersion":"1.0"},{"accessToken":["only-one"]}]"#,
        )]);
        let mut sl = RecordingSleeper::default();
        assert!(bulk_refresh(SECRET, &tokens, &mut t, &mut sl).is_err());
    }

    // ── Item 5: TOTP known-answer test + reuse of the ESV generator ───

    #[test]
    fn totp_matches_rfc6238_appendix_b_sha256_vector() {
        // RFC 6238 Appendix B (HMAC-SHA-256): seed = ASCII
        // "12345678901234567890123456789012", T = 59 s → counter 1 (30 s
        // step) → 8-digit TOTP "46119246". This is a real known-answer
        // check against the standard, not a self-referential determinism
        // assertion.
        let seed = b"12345678901234567890123456789012";
        assert_eq!(totp_at(seed, 1).unwrap(), "46119246");
    }

    #[test]
    fn reused_totp_is_deterministic_and_eight_digits() {
        // The generator is acvp-harness's, byte-identical to the ESV
        // reference client's totp.py (RFC-4226 dynamic truncation over
        // HMAC-SHA-256, top bit masked, mod 10^8, 8 digits).
        let a = totp_at(SECRET, 1).unwrap();
        let b = totp_at(SECRET, 1).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert!(a.bytes().all(|c| c.is_ascii_digit()));
        assert_ne!(a, totp_at(SECRET, 2).unwrap());
    }
}
