//! ACVP protocol transport client for the NIST demo server.
//!
//! This module implements the ACVP REST protocol flow needed to run
//! end-to-end test sessions against `demo.acvts.nist.gov`:
//!
//! 1. **Login** — POST `/acvp/v1/login` with a TOTP-signed JWT.
//! 2. **Register** — POST `/acvp/v1/testSessions` with algorithm
//!    capabilities derived from the handler registry.
//! 3. **Fetch** — GET each vector-set URL; persist the prompt to the
//!    per-session directory (see [`crate::session`]).
//! 4. **Process** — Feed each vector set through
//!    [`crate::dispatch::process`]; persist the computed response and
//!    a `PENDING` status BEFORE any submit attempt, so a transport
//!    failure cannot lose a long compute.
//! 5. **Submit** — POST responses back to each vector-set URL. On
//!    failure the cached `PENDING` state is left intact and the error
//!    names the `resubmit` recovery command.
//! 6. **Poll** — GET each vector set until the verdict is in; the
//!    verdict replaces the status file's `SUBMITTED` marker.
//!
//! [`run_resubmit`] (the `resubmit` CLI subcommand) replays a cached
//! `response.json` byte-for-byte against an existing test session —
//! re-login, re-fetch a session-bound token, POST, poll — without
//! recomputing anything.
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
use crate::session::{self, SessionDir};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Configuration ──────────────────────────────────────────────────

/// Which HTTP transport backend to use.
///
/// `Curl` shells out to `curl(1)` and is the default for software-key
/// mTLS. `OpenSslSClient` pipes a hand-built HTTP request through
/// `openssl s_client`; this is required against TLS-fingerprint-filtering
/// CDNs (notably the NIST ACVTS demo CDN, which silently drops curl's
/// ClientHello while accepting s_client's).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpBackend {
    /// Shell out to `curl(1)`.
    Curl,
    /// Pipe raw HTTP through `openssl s_client`.
    OpenSslSClient,
}

/// Configuration for an ACVP demo-server session.
pub struct AcvpConfig {
    /// Base URL of the ACVP server (e.g. `https://demo.acvts.nist.gov`).
    pub server_url: String,
    /// Path to the TLS client certificate (PEM).
    pub cert_path: String,
    /// Path to the TLS client private key (PEM). Used when `pkcs11_uri`
    /// is `None`.
    pub key_path: String,
    /// PKCS#11 URI for a hardware-backed private key, e.g.
    /// `pkcs11:object=PIV%20AUTH%20key;type=private`. When set, this
    /// takes precedence over `key_path` and the harness invokes its
    /// HTTP backend with the appropriate engine flags.
    pub pkcs11_uri: Option<String>,
    /// Path to the PKCS#11 provider module (e.g. `opensc-pkcs11.so`).
    /// `None` selects the platform default
    /// (`AcvpConfig::DEFAULT_PKCS11_MODULE`).
    pub pkcs11_module_path: Option<String>,
    /// Optional PIV PIN value. When non-empty, the PKCS#11 URI is
    /// augmented with `?pin-value=<URL-encoded>` so opensc-pkcs11
    /// authenticates without prompting on the terminal. Eliminates
    /// per-request PIN prompts and the associated terminal-state echo
    /// bug observed when opensc's prompt routine is interrupted by a
    /// TLS error mid-handshake.
    ///
    /// Loaded by the CLI from a file (typically on `/dev/shm` with
    /// mode 0600), so the PIN never appears in the harness's own argv.
    /// It does appear in the spawned s_client subprocess's argv as
    /// part of the PKCS#11 URI, which is visible to same-UID
    /// processes via `/proc/<pid>/cmdline`. Acceptable trade-off for
    /// development against the ACVTS demo server; production
    /// validation would use a hardened PIN-callback path.
    pub pkcs11_pin: String,
    /// Which HTTP transport backend to use for outbound requests.
    pub http_backend: HttpBackend,
    /// TOTP shared secret as base64 (NIST ACVTS demo distributes the
    /// secret in this form). Decoded once before the first login.
    pub totp_secret: String,
    /// Optional: only register and test this single algorithm.
    pub filter_algorithm: Option<String>,
    /// Optional: only register handlers whose `mode()` matches this
    /// string (in combination with `filter_algorithm`). Used for
    /// multi-mode algorithms (ECDSA, RSA, EDDSA) where a single
    /// algorithm name has multiple mode-specific handlers and ACVTS
    /// demo etiquette requires one vector set per session.
    pub filter_mode: Option<String>,
    /// Optional: when set, restrict an `acvp_capabilities_filtered`-
    /// aware handler (currently only the SLH-DSA family) to a single
    /// parameter set, producing one vector set per session per
    /// `feedback_single_algo_per_acvts_session`. Other handlers
    /// (whose default `acvp_capabilities_filtered` delegates to
    /// `acvp_capabilities`) ignore the filter and advertise their
    /// usual cap. The CLI parser validates this against the
    /// `--algorithm` it accompanies so unknown paramSet names are
    /// rejected before the session opens.
    pub filter_paramset: Option<String>,
    /// Optional: instead of registering a new test session, just GET
    /// the supplied URL (relative or absolute) and print the response.
    /// Use to fetch verdict status of an existing session that was
    /// created by a previous run, without burning another vector-set
    /// generation cycle on the demo server.
    pub query_session_url: Option<String>,
    /// Optional: an existing session-bound accessToken (potentially
    /// expired) to send alongside the TOTP at login. The ACVP server
    /// validates the JWT signature and, if it matches, issues a fresh
    /// session-bound token with the same `tsId`/`vsId` scope. Required
    /// to authorize on /testSessions/{id}/* endpoints — those reject
    /// the general login token alone.
    pub refresh_with_token: Option<String>,
    /// Path to write the session transcript JSON log.
    pub log_path: String,
    /// Root directory for per-session submission-persistence
    /// directories (see [`crate::session`] for the layout). Each
    /// vector set gets `<sessions_dir>/<tsId>-<vsId>/` holding the
    /// prompt, the computed response, and the submit status.
    pub sessions_dir: String,
}

impl AcvpConfig {
    /// Default OpenSC PKCS#11 module `.so` path on Debian/Ubuntu.
    pub const DEFAULT_PKCS11_MODULE: &'static str = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";

    /// Resolved PKCS#11 module path (config override or platform default).
    pub fn resolved_pkcs11_module(&self) -> &str {
        self.pkcs11_module_path
            .as_deref()
            .unwrap_or(Self::DEFAULT_PKCS11_MODULE)
    }

    /// PKCS#11 URI to hand to curl/s_client. If `pkcs11_pin` is set,
    /// returns `<uri>?pin-value=<URL-encoded-PIN>`. Otherwise returns
    /// `pkcs11_uri` as-is. Returns `None` when no hardware key is
    /// configured.
    fn composed_pkcs11_uri(&self) -> Option<String> {
        let base = self.pkcs11_uri.as_deref()?;
        if self.pkcs11_pin.is_empty() {
            Some(base.to_string())
        } else {
            Some(format!(
                "{base}?pin-value={}",
                urlencode_unreserved(&self.pkcs11_pin)
            ))
        }
    }
}

// ── TOTP (RFC 6238) ───────────────────────────────────────────────

/// Generate an 8-digit TOTP code using HMAC-SHA-256, matching the
/// NIST ACVTS demo server's expectation. (NIST diverges from RFC 6238
/// defaults: SHA-256 instead of SHA-1, 8 digits instead of 6.)
///
/// Uses the standard 30-second time step with T0 = 0. The secret is
/// expected as raw bytes (the caller decodes from base64 before calling).
fn totp_now(secret: &[u8]) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time error: {e}"))?;
    let time_step = now.as_secs() / 30;
    totp_at(secret, time_step)
}

/// Generate an 8-digit TOTP code for a specific time counter value.
fn totp_at(secret: &[u8], counter: u64) -> Result<String, String> {
    let counter_bytes = counter.to_be_bytes();
    // Use oxicrypt's own HMAC-SHA-256 (internal constructor to avoid
    // module-state gating — we're in the harness, not the module).
    let mut mac = oxicrypt_hmac::HmacSha256::new_internal(secret);
    mac.update(&counter_bytes);
    let hmac_result = mac.finalize();

    // Dynamic truncation per RFC 4226 §5.4.
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
    // NIST uses 8-digit codes: modulo 10^8, zero-padded.
    Ok(format!("{:08}", code % 100_000_000))
}

/// Replace any `pin-value=...` segment in a PKCS#11 URI with
/// `pin-value=<REDACTED>` for safe debug printing.
fn redact_pkcs11_pin_value(uri: &str) -> String {
    if let Some(idx) = uri.find("pin-value=") {
        let prefix_end = idx.wrapping_add("pin-value=".len());
        let prefix = uri.get(..prefix_end).unwrap_or("");
        let tail = uri.get(prefix_end..).unwrap_or("");
        // pin-value runs until the next URI delimiter (`&`, `;`, `?`)
        // or end of string.
        let stop = tail.find(['&', ';', '?']).unwrap_or(tail.len());
        let suffix = tail.get(stop..).unwrap_or("");
        format!("{prefix}<REDACTED>{suffix}")
    } else {
        uri.to_string()
    }
}

// ── URL encoding for PKCS#11 URI query values ────────────────────

/// Percent-encode a string for use as a value inside a PKCS#11 URI
/// query (RFC 7512 / RFC 3986). All bytes that aren't in the unreserved
/// set (`A-Z a-z 0-9 - _ . ~`) are percent-encoded. Conservative — we
/// only need to handle PIN values, which are realistically alphanumeric.
fn urlencode_unreserved(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            // Two-digit uppercase hex per RFC 3986 §2.1.
            out.push('%');
            out.push(
                char::from_digit(u32::from(b >> 4), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit(u32::from(b & 0x0f), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

// ── Base64 decode (RFC 4648 §4) ───────────────────────────────────

/// Decode standard base64 to bytes. Accepts both the `+/` and `-_`
/// alphabet variants (treated equivalently). Padding (`=`) is optional;
/// whitespace is ignored.
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len().wrapping_mul(3) / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        let v: u32 = match c {
            'A'..='Z' => (c as u32).wrapping_sub('A' as u32),
            'a'..='z' => (c as u32).wrapping_sub('a' as u32).wrapping_add(26),
            '0'..='9' => (c as u32).wrapping_sub('0' as u32).wrapping_add(52),
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break, // optional padding terminator
            ' ' | '\r' | '\n' | '\t' => continue,
            other => return Err(format!("invalid base64 character: {other:?}")),
        };
        buf = (buf << 6) | v;
        bits = bits.wrapping_add(6);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

// ── HTTP transport ────────────────────────────────────────────────

/// HTTP response.
struct HttpResponse {
    /// HTTP status code.
    status: u16,
    /// Response body as a string.
    body: String,
}

/// A persistent `openssl s_client` TLS tunnel for HTTP/1.1 keep-alive
/// sessions. One TLS handshake = one CertVerify signature = one
/// hardware-key touch for the entire ACVP session, regardless of how
/// many HTTP requests are made.
///
/// Ownership: holds the spawned child plus its stdin/stdout pipes.
/// Drop closes stdin (s_client sees EOF, sends TLS close_notify, exits).
struct SClientConnection {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    host: String,
    /// `true` when the previous HTTP response carried a `Connection:
    /// close` directive. The pre-request gate in [`Transport::dispatch`]
    /// reconnects before the next request when this is set.
    server_wants_close: bool,
}

impl SClientConnection {
    /// Spawn `openssl s_client`, perform the TLS handshake, and ready
    /// the pipes for HTTP/1.1 keep-alive requests. The handshake
    /// performs the one-and-only YubiKey touch for the session.
    fn open(config: &AcvpConfig) -> Result<Self, String> {
        let (host, port, _) = parse_https_url(&config.server_url)?;

        let mut cmd = std::process::Command::new("openssl");
        cmd.arg("s_client")
            .arg("-connect")
            .arg(format!("{host}:{port}"))
            .arg("-servername")
            .arg(&host)
            .arg("-cert")
            .arg(&config.cert_path);

        if let Some(uri) = config.composed_pkcs11_uri() {
            let redacted = redact_pkcs11_pin_value(&uri);
            eprintln!(
                "[transport] s_client persistent -key {redacted:?}\n  \
                 ← TOUCH YUBIKEY (one touch covers the entire session)"
            );
            cmd.arg("-engine")
                .arg("pkcs11")
                .arg("-keyform")
                .arg("engine")
                .arg("-key")
                .arg(uri);
            cmd.env("PKCS11_MODULE_PATH", config.resolved_pkcs11_module());
        } else {
            cmd.arg("-key").arg(&config.key_path);
        }

        cmd.arg("-quiet").arg("-ign_eof");
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("openssl s_client spawn: {e}"))?;
        let stdin = child.stdin.take().ok_or("missing s_client stdin")?;
        let stdout = child.stdout.take().ok_or("missing s_client stdout")?;

        Ok(SClientConnection {
            child,
            stdin,
            stdout: std::io::BufReader::new(stdout),
            host,
            server_wants_close: false,
        })
    }

    /// Send one HTTP/1.1 keep-alive request and parse the response.
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
        bearer: &str,
    ) -> Result<HttpResponse, String> {
        use std::io::Write as _;

        // Build raw HTTP/1.1 request with explicit keep-alive.
        let body_bytes: &[u8] = body.map_or(&[], str::as_bytes);
        let mut req: Vec<u8> = Vec::with_capacity(256_usize.wrapping_add(body_bytes.len()));
        req.extend_from_slice(method.as_bytes());
        req.extend_from_slice(b" ");
        req.extend_from_slice(path.as_bytes());
        req.extend_from_slice(b" HTTP/1.1\r\n");
        req.extend_from_slice(format!("Host: {}\r\n", self.host).as_bytes());
        req.extend_from_slice(b"User-Agent: oxicrypt-acvp-harness/0.1\r\n");
        if !bearer.is_empty() {
            req.extend_from_slice(format!("Authorization: Bearer {bearer}\r\n").as_bytes());
        }
        req.extend_from_slice(b"Content-Type: application/json\r\n");
        req.extend_from_slice(format!("Content-Length: {}\r\n", body_bytes.len()).as_bytes());
        req.extend_from_slice(b"Connection: keep-alive\r\n\r\n");
        if !body_bytes.is_empty() {
            req.extend_from_slice(body_bytes);
        }

        self.stdin
            .write_all(&req)
            .map_err(|e| format!("write to s_client stdin: {e}"))?;
        self.stdin
            .flush()
            .map_err(|e| format!("flush s_client stdin: {e}"))?;

        // Read response headers byte-by-byte until \r\n\r\n.
        let mut headers_buf: Vec<u8> = Vec::with_capacity(1024);
        loop {
            let mut byte = [0u8; 1];
            let n = std::io::Read::read(&mut self.stdout, &mut byte)
                .map_err(|e| format!("read response headers: {e}"))?;
            if n == 0 {
                return Err("s_client closed connection mid-response".to_string());
            }
            headers_buf.push(byte[0]);
            if headers_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        // Capture the server's keep-alive intent for the next request.
        self.server_wants_close = scan_connection_close(&headers_buf);
        let headers_end = headers_buf.len().wrapping_sub(4);
        let headers_bytes = headers_buf.get(..headers_end).unwrap_or(&[]);
        let headers_text = std::str::from_utf8(headers_bytes)
            .map_err(|e| format!("non-UTF-8 HTTP headers: {e}"))?;

        // Status line.
        let first_line = headers_text
            .split("\r\n")
            .next()
            .ok_or("empty headers section")?;
        let mut parts = first_line.splitn(3, ' ');
        let _proto = parts
            .next()
            .ok_or_else(|| format!("bad status line: {first_line}"))?;
        let code_str = parts
            .next()
            .ok_or_else(|| format!("bad status line: {first_line}"))?;
        let status: u16 = code_str
            .parse()
            .map_err(|_| format!("bad HTTP status code: {code_str}"))?;

        // Body framing: prefer Content-Length, fall back to chunked.
        let mut content_length: Option<usize> = None;
        let mut is_chunked = false;
        for line in headers_text.split("\r\n") {
            let lower = line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-length:")
                && let Ok(n) = rest.trim().parse::<usize>()
            {
                content_length = Some(n);
            }
            if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                is_chunked = true;
            }
        }

        let body_bytes_out: Vec<u8> = if is_chunked {
            self.read_chunked_body()?
        } else if let Some(n) = content_length {
            let mut buf = vec![0u8; n];
            std::io::Read::read_exact(&mut self.stdout, &mut buf)
                .map_err(|e| format!("read response body ({n} bytes): {e}"))?;
            buf
        } else {
            return Err(
                "response missing both Content-Length and chunked Transfer-Encoding".to_string(),
            );
        };

        Ok(HttpResponse {
            status,
            body: String::from_utf8_lossy(&body_bytes_out).into_owned(),
        })
    }

    /// Read an HTTP/1.1 chunked body from the connection.
    fn read_chunked_body(&mut self) -> Result<Vec<u8>, String> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            // Read chunk-size line until CRLF.
            let mut size_line: Vec<u8> = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                let n = std::io::Read::read(&mut self.stdout, &mut byte)
                    .map_err(|e| format!("read chunk size: {e}"))?;
                if n == 0 {
                    return Err("s_client closed mid-chunked-body".to_string());
                }
                size_line.push(byte[0]);
                if size_line.ends_with(b"\r\n") {
                    break;
                }
            }
            let size_line_end = size_line.len().wrapping_sub(2);
            let size_line_bytes = size_line.get(..size_line_end).unwrap_or(&[]);
            let size_str_full =
                std::str::from_utf8(size_line_bytes).map_err(|_| "non-UTF-8 chunk size line")?;
            let size_str = size_str_full
                .split(';')
                .next()
                .unwrap_or(size_str_full)
                .trim();
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|_| format!("bad chunk size: '{size_str}'"))?;
            if size == 0 {
                // Read trailer (empty line) then return.
                let mut trailer = [0u8; 2];
                let _ = std::io::Read::read_exact(&mut self.stdout, &mut trailer);
                return Ok(out);
            }
            let start = out.len();
            out.resize(start.wrapping_add(size), 0);
            let target = out.get_mut(start..).unwrap_or(&mut []);
            std::io::Read::read_exact(&mut self.stdout, target)
                .map_err(|e| format!("read chunk data ({size} bytes): {e}"))?;
            // Trailing CRLF after each chunk's data.
            let mut crlf = [0u8; 2];
            std::io::Read::read_exact(&mut self.stdout, &mut crlf)
                .map_err(|e| format!("read chunk CRLF: {e}"))?;
        }
    }

    /// Close the connection.
    ///
    /// We force-terminate the child rather than relying on stdin EOF
    /// because s_client is launched with `-ign_eof` (required so the
    /// TLS tunnel survives across multiple HTTP/1.1 keep-alive
    /// requests during the session). With `-ign_eof`, dropping stdin
    /// doesn't trigger s_client to exit — it would block until the
    /// server-side keep-alive timer fires (~60 s for typical CDNs).
    /// SIGKILL is fine here because we've already consumed the final
    /// response we care about; any in-flight server bytes are
    /// inconsequential.
    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Atomically tear down the current s_client tunnel and spawn a
    /// fresh one. Used by the pre-request gate when a prior response
    /// signaled `Connection: close`. Pre-opens the new connection
    /// before swapping, so a spawn failure leaves the old (already-
    /// doomed) connection intact and the caller sees the error.
    ///
    /// Cost: one YubiKey touch per call (the new TLS handshake
    /// performs a certificate-verify signature against the PIV slot).
    fn reopen(&mut self, config: &AcvpConfig) -> Result<(), String> {
        let new_self = Self::open(config)?;
        let old = std::mem::replace(self, new_self);
        old.close();
        Ok(())
    }
}

/// Transport handle threaded through one ACVP session. Owned by
/// [`run_demo`] for the lifetime of the session, mutably borrowed by
/// every HTTP-issuing function. For the curl backend it just borrows
/// the config (each request spawns a new process); for the s_client
/// backend it owns the persistent TLS tunnel.
enum Transport<'a> {
    Curl(&'a AcvpConfig),
    /// Persistent s_client tunnel plus a config reference so the
    /// pre-request gate in [`Transport::dispatch`] can reconnect
    /// (via [`SClientConnection::reopen`]) when the previous response
    /// signaled `Connection: close`.
    SClient(SClientConnection, &'a AcvpConfig),
}

impl<'a> Transport<'a> {
    fn open(config: &'a AcvpConfig) -> Result<Self, String> {
        match config.http_backend {
            HttpBackend::Curl => Ok(Transport::Curl(config)),
            HttpBackend::OpenSslSClient => {
                let conn = SClientConnection::open(config)?;
                Ok(Transport::SClient(conn, config))
            }
        }
    }

    fn close(self) {
        match self {
            Transport::Curl(_) => {}
            Transport::SClient(conn, _) => conn.close(),
        }
    }

    fn get(&mut self, url: &str, bearer: &str) -> Result<HttpResponse, String> {
        self.dispatch("GET", url, None, bearer)
    }

    fn post(&mut self, url: &str, body: &str, bearer: &str) -> Result<HttpResponse, String> {
        self.dispatch("POST", url, Some(body), bearer)
    }

    fn dispatch(
        &mut self,
        method: &str,
        url: &str,
        body: Option<&str>,
        bearer: &str,
    ) -> Result<HttpResponse, String> {
        match self {
            Transport::Curl(config) => {
                http_request_curl_with_retry(method, url, body, config, bearer)
            }
            Transport::SClient(conn, config) => {
                // Honor a prior Connection: close signal before
                // issuing the next request. The reconnect costs one
                // YubiKey touch; operator-visible eprintln so the
                // touch isn't surprising.
                if conn.server_wants_close {
                    eprintln!(
                        "[transport] server requested connection close on prior response; \
                         reconnecting (one YubiKey touch)"
                    );
                    conn.reopen(config)?;
                }
                let (_host, _port, path) = parse_https_url(url)?;
                conn.request(method, &path, body, bearer)
            }
        }
    }
}

/// Curl-backed HTTP request with bounded retry. Used only for the
/// `Curl` transport backend (each curl invocation is its own process,
/// so retries are inexpensive). The s_client backend has no equivalent
/// retry wrapper — a connection drop there means the persistent TLS
/// session is dead and we don't want to silently reconnect (which
/// would burn another hardware-key touch without telling the user).
fn http_request_curl_with_retry(
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
        match http_request_once_curl(method, url, body, config, bearer) {
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

/// Curl-backed HTTP request. Supports both file-PEM keys and PKCS#11
/// hardware keys via the `engine_pkcs11` engine.
fn http_request_once_curl(
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
        .arg(&config.cert_path);

    // Key source: hardware (PKCS#11 URI) takes precedence over file path.
    if let Some(uri) = config.composed_pkcs11_uri() {
        cmd.arg("--engine")
            .arg("pkcs11")
            .arg("--key-type")
            .arg("ENG")
            .arg("--key")
            .arg(uri);
        cmd.env("PKCS11_MODULE_PATH", config.resolved_pkcs11_module());
    } else {
        cmd.arg("--key").arg(&config.key_path);
    }

    cmd.arg("-X").arg(method);

    if !bearer.is_empty() {
        cmd.arg("-H").arg(format!("Authorization: Bearer {bearer}"));
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

    // Last line of stdout is the HTTP status code (from --write-out).
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

/// Parse `https://host[:port]/path` into (host, port, path).
fn parse_https_url(url: &str) -> Result<(String, u16, String), String> {
    let url = url.trim();
    let scheme_sep = url
        .find("://")
        .ok_or_else(|| format!("URL missing scheme separator: {url}"))?;
    let scheme = url.get(..scheme_sep).unwrap_or("");
    if scheme != "https" {
        return Err(format!("only https supported, got '{scheme}'"));
    }
    let rest = url
        .get(scheme_sep.wrapping_add(3)..)
        .ok_or_else(|| format!("URL has no authority: {url}"))?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("/")),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rfind(':') {
        Some(i) => {
            let h = host_port.get(..i).unwrap_or("");
            let p_str = host_port.get(i.wrapping_add(1)..).unwrap_or("");
            let p: u16 = p_str
                .parse()
                .map_err(|_| format!("bad port in URL: {p_str}"))?;
            (h.to_string(), p)
        }
        None => (host_port.to_string(), 443u16),
    };
    Ok((host, port, path.to_string()))
}

// ── Capabilities builder ──────────────────────────────────────────

/// Build the ACVP registration capabilities array from handler
/// `acvp_capabilities_filtered()` methods. When `filter_mode` is
/// supplied it is matched against `h.mode()` — handlers whose
/// `mode()` does not equal `Some(filter_mode)` are skipped, narrowing
/// the registration to a single (algorithm, mode) tuple as ACVTS
/// demo etiquette requires (one vector set per session).
///
/// `filter_paramset` is plumbed through to
/// `acvp_capabilities_filtered`; the default trait impl ignores the
/// filter, so non-SLH-DSA handlers behave identically whether or not
/// `--paramset` was supplied.
fn build_capabilities(
    registry: &Registry,
    filter_alg: Option<&str>,
    filter_mode: Option<&str>,
    filter_paramset: Option<&str>,
) -> Vec<JsonValue> {
    let mut caps = Vec::new();
    registry.for_each_handler(|h: &dyn AlgorithmHandler| {
        if let Some(name) = filter_alg
            && h.algorithm() != name
        {
            return;
        }
        if let Some(mode_name) = filter_mode
            && h.mode() != Some(mode_name)
        {
            return;
        }
        if let Some(cap) = h.acvp_capabilities_filtered(filter_paramset) {
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

/// Decode the TOTP secret from base64 (RFC 4648 §4). NIST ACVTS demo
/// distributes the shared secret in this form.
fn decode_totp_secret(s: &str) -> Result<Vec<u8>, String> {
    base64_decode(s.trim()).map_err(|e| format!("bad TOTP secret base64: {e}"))
}

// ── Main transport loop ───────────────────────────────────────────

/// POST `/acvp/v1/login` and return the access token.
///
/// The ACVP demo server expects the current 8-digit TOTP code as a
/// flat `password` field (per ACVP §10.1-10.2; verified empirically
/// 2026-04-26 against demo.acvts.nist.gov via mtls-login-sclient.sh).
/// No JWT wrapping.
///
/// When `refresh_with` carries an existing session-bound accessToken
/// (from `--refresh-with` or a cached `token.txt`), it is embedded in
/// the login body. The server validates its signature (ignoring the
/// JWT's exp) and re-issues a fresh session-bound token with the same
/// tsId/vsId scope, suitable for re-accessing /testSessions/{id}/*
/// after the original 30-minute token expiry.
///
/// On HTTP failure the transcript is flushed to `config.log_path`
/// before the error returns; on a parse failure the raw body is dumped
/// next to the transcript log so the operator can inspect it manually
/// (it may contain a still-valid JWT — shred after use).
fn login_with_totp(
    transport: &mut Transport,
    config: &AcvpConfig,
    refresh_with: Option<&str>,
    totp_secret: &[u8],
    log: &mut TranscriptLog,
) -> Result<String, String> {
    eprintln!("[transport] logging in to {}...", config.server_url);
    let totp_code = totp_now(totp_secret)?;
    let login_body = if let Some(token) = refresh_with {
        eprintln!("[transport] requesting refresh of existing session token");
        format!(
            "[{{\"acvVersion\":\"1.0\"}},{{\"password\":\"{totp_code}\",\"accessToken\":\"{token}\"}}]"
        )
    } else {
        format!("[{{\"acvVersion\":\"1.0\"}},{{\"password\":\"{totp_code}\"}}]")
    };
    let login_url = format!("{}/acvp/v1/login", config.server_url);
    let login_resp = transport.post(&login_url, &login_body, "")?;
    if login_resp.status < 200 || login_resp.status >= 300 {
        log.log("login_failed", &format!("HTTP {}", login_resp.status));
        log.write_to_file(&config.log_path)?;
        return Err(format!(
            "login failed: HTTP {} — {}",
            login_resp.status, login_resp.body
        ));
    }
    // Response shape: [{"acvVersion":"1.0"},{"accessToken":"..."}]
    let login_json = json::parse(&login_resp.body).map_err(|e| {
        let dump_path = format!("{}.login-raw.bin", config.log_path);
        let _ = std::fs::write(&dump_path, login_resp.body.as_bytes());
        let head: String = login_resp.body.chars().take(120).collect();
        format!(
            "parse login response: {e}\n  body length: {} bytes\n  body[0..120]: {head:?}\n  raw body dumped to: {dump_path}",
            login_resp.body.len()
        )
    })?;
    let access_token = extract_access_token(&login_json)?;
    eprintln!("[transport] login successful, got access token");
    log.log("login_ok", "access token obtained");
    Ok(access_token)
}

/// Run a full ACVP demo-server session.
///
/// This is the top-level entry point for the `demo-run` subcommand.
/// The function naturally exceeds clippy's pedantic line limit because
/// it linearly orchestrates: capabilities → transport open → login →
/// (query-session branch) → register → vector-set processing →
/// summary. Splitting it would scatter the protocol flow.
#[allow(clippy::too_many_lines)]
pub fn run_demo(config: &AcvpConfig) -> Result<(), String> {
    let mut log = TranscriptLog::new();
    log.log("session_start", &format!("server={}", config.server_url));

    let totp_secret = decode_totp_secret(&config.totp_secret)?;

    // Build handler registry (only needed for register-and-submit mode;
    // query-session mode bypasses the dispatcher entirely).
    let registry = dispatch::with_default_handlers();
    let caps = if config.query_session_url.is_some() {
        Vec::new()
    } else {
        let caps = build_capabilities(
            &registry,
            config.filter_algorithm.as_deref(),
            config.filter_mode.as_deref(),
            config.filter_paramset.as_deref(),
        );
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
        caps
    };

    // Open the session-wide transport. For the s_client backend this
    // performs the one-and-only TLS handshake (and YubiKey touch) for
    // the entire session; all subsequent HTTP requests are routed over
    // the persistent connection via HTTP/1.1 keep-alive. For the curl
    // backend each request still spawns its own process — that path
    // doesn't need the persistence because software keys don't require
    // hardware touches.
    let mut transport = Transport::open(config)?;

    // ── Step 1: Login ──────────────────────────────────────────────
    let access_token = login_with_totp(
        &mut transport,
        config,
        config.refresh_with_token.as_deref(),
        &totp_secret,
        &mut log,
    )?;

    // ── Branch: query-session mode skips registration + submission.
    if let Some(query_url) = config.query_session_url.clone() {
        let absolute = resolve_url(&config.server_url, &query_url);
        eprintln!("[transport] querying existing session {query_url}...");
        log.log("query_session", &absolute);
        let resp = transport.get(&absolute, &access_token)?;
        eprintln!(
            "[transport] session query: HTTP {} ({} bytes)",
            resp.status,
            resp.body.len()
        );
        log.log("query_response_status", &format!("HTTP {}", resp.status));
        // Pretty-print the body if it's parseable JSON; fall back to raw.
        if let Ok(parsed) = json::parse(&resp.body) {
            log.log_json("query_response_body", &parsed);
            println!("{}", json::to_pretty_string(&parsed));
        } else {
            log.log("query_response_body_raw", &resp.body);
            println!("{}", resp.body);
        }
        let summary_result = write_session_summary(
            &[(query_url, format!("HTTP_{}", resp.status))],
            &mut log,
            &config.log_path,
        );
        transport.close();
        return summary_result;
    }

    // ── Step 2: Register test session ──────────────────────────────
    eprintln!("[transport] registering test session...");
    let reg_body = build_registration_body(&caps);
    let reg_url = format!("{}/acvp/v1/testSessions", config.server_url);
    let reg_resp = transport.post(&reg_url, &reg_body, &access_token)?;
    if reg_resp.status < 200 || reg_resp.status >= 300 {
        log.log("register_failed", &format!("HTTP {}", reg_resp.status));
        log.write_to_file(&config.log_path)?;
        return Err(format!(
            "registration failed: HTTP {} — {}",
            reg_resp.status, reg_resp.body
        ));
    }
    let reg_json =
        json::parse(&reg_resp.body).map_err(|e| format!("parse registration response: {e}"))?;
    let vector_set_urls = extract_vector_set_urls(&reg_json)?;
    // The registration response carries a NEW, session-specific
    // accessToken bound to the test session and vector-set ids. Per the
    // ACVP demo server's authorization model, vector-set fetches and
    // submissions MUST use this session token rather than the
    // general-purpose login token, otherwise they return HTTP 403.
    let session_token = extract_access_token(&reg_json).unwrap_or_else(|_| {
        eprintln!(
            "[transport] WARN: registration returned no accessToken; falling \
             back to login token (vector-set requests may 403)"
        );
        access_token.clone()
    });
    eprintln!(
        "[transport] registered: {} vector set(s)",
        vector_set_urls.len()
    );
    log.log(
        "register_ok",
        &format!("{} vector sets", vector_set_urls.len()),
    );
    log.log_json("registration_response", &reg_json);
    // Incremental flush — the registration response carries the
    // session-bound JWT needed to fetch verdicts later. If the operator
    // Ctrl+C's mid-session, the partial transcript on disk is enough
    // to recover the token via `--refresh-with`. Flush failures are
    // non-fatal: the network workflow can still succeed and the final
    // write_session_summary will surface the disk error.
    if let Err(e) = log.write_to_file(&config.log_path) {
        eprintln!("[transport] transcript flush failed after registration (continuing): {e}");
    }

    // ── Steps 3–5: Fetch → Process → Submit per vector set ─────────
    let results = process_vector_sets(
        &vector_set_urls,
        &mut transport,
        &config.server_url,
        &session_token,
        &registry,
        &mut log,
        &config.log_path,
        &config.sessions_dir,
    );

    // ── Summary ────────────────────────────────────────────────────
    let summary_result = write_session_summary(&results, &mut log, &config.log_path);
    transport.close();
    summary_result
}

/// Replay a cached, already-computed response against an existing
/// test session — the `resubmit` CLI subcommand.
///
/// This is the recovery half of the submission-persistence layer: when
/// a `demo-run` submit fails after a long compute, the session
/// directory `<sessions_dir>/<tsId>-<vsId>/` (see [`crate::session`])
/// still holds `response.json` with `submit-status.txt` = `PENDING`.
/// `run_resubmit`:
///
/// 1. Loads the cached `response.json` — refusing cleanly, before any
///    network contact, when the directory or file is missing.
/// 2. Re-runs the existing cert/TOTP login flow, embedding the cached
///    session-bound token (`token.txt`, or `--refresh-with` when
///    supplied) so the server re-issues a fresh token scoped to the
///    same tsId/vsId.
/// 3. POSTs the cached bytes verbatim to
///    `/acvp/v1/testSessions/{tsId}/vectorSets/{vsId}/results`.
/// 4. Polls the verdict and advances `submit-status.txt`
///    (`PENDING` → `SUBMITTED` → verdict string).
///
/// It never recomputes: the graded vectors are byte-identical to what
/// the IUT computed during the original `demo-run`.
pub fn run_resubmit(config: &AcvpConfig, ts_id: u64, vs_id: u64) -> Result<(), String> {
    let mut log = TranscriptLog::new();
    log.log(
        "resubmit_start",
        &format!(
            "server={} tsId={ts_id} vsId={vs_id} sessions_dir={}",
            config.server_url, config.sessions_dir
        ),
    );

    // ── Step 0: load the cached artifacts BEFORE any network contact.
    let session = SessionDir::open(&config.sessions_dir, ts_id, vs_id)?;
    let response_body = session.read_response()?;
    let prior_status = session
        .read_status()
        .unwrap_or_else(|_| "<missing>".to_string());
    eprintln!(
        "[transport] resubmit: cached response loaded from {} ({} bytes, prior status: {prior_status})",
        session.path().display(),
        response_body.len()
    );
    log.log(
        "resubmit_cached_response",
        &format!("{} bytes, prior status {prior_status}", response_body.len()),
    );

    // Session-bound token for the login refresh: an explicit
    // --refresh-with wins, then the cached token.txt. Without either,
    // the general login token alone is likely to 403 on the
    // vector-set endpoint — warn but proceed, the server is the
    // authority.
    let refresh_with = config
        .refresh_with_token
        .clone()
        .or_else(|| session.read_token());
    if refresh_with.is_none() {
        eprintln!(
            "[transport] WARN: no cached session token ({}) and no --refresh-with; \
             vector-set requests may return HTTP 403",
            session::TOKEN_FILE
        );
    }

    let totp_secret = decode_totp_secret(&config.totp_secret)?;
    let mut transport = Transport::open(config)?;

    // ── Step 1: re-login (existing cert/TOTP flow) ─────────────────
    let access_token = match login_with_totp(
        &mut transport,
        config,
        refresh_with.as_deref(),
        &totp_secret,
        &mut log,
    ) {
        Ok(token) => token,
        Err(e) => {
            transport.close();
            return Err(e);
        }
    };

    // ── Step 2: POST the cached response verbatim ──────────────────
    let vs_path = format!("/acvp/v1/testSessions/{ts_id}/vectorSets/{vs_id}");
    let full_url = resolve_url(&config.server_url, &vs_path);
    let results_url = format!("{full_url}/results");
    eprintln!("[transport] resubmitting cached response to {vs_path}...");
    log.log("resubmit_post", &vs_path);
    let disposition = match submit_and_mark(&session, &response_body, |body| {
        transport.post(&results_url, body, &access_token)
    }) {
        SubmitOutcome::Submitted => {
            eprintln!("[transport] resubmitted OK");
            log.log("submit_ok", &vs_path);
            if let Err(e) = log.write_to_file(&config.log_path) {
                eprintln!("[transport] transcript flush failed after submit (continuing): {e}");
            }
            // ── Step 3: poll verdict, advance the status file ──────
            eprintln!("[transport] polling for verdict...");
            match poll_verdict(&full_url, &mut transport, &access_token, &mut log) {
                Ok(d) => {
                    eprintln!("[transport] verdict: {d}");
                    log.log("verdict", &format!("{vs_path}: {d}"));
                    if let Err(e) = session.write_status(&d) {
                        eprintln!("[transport] WARN: could not record verdict in status file: {e}");
                    }
                    d
                }
                Err(e) => {
                    eprintln!("[transport] poll error: {e}");
                    log.log("poll_error", &e);
                    "POLL_ERROR".to_string()
                }
            }
        }
        SubmitOutcome::HttpError(status) => {
            eprintln!("[transport] resubmit returned HTTP {status}");
            eprint_resubmit_hint(&session);
            log.log("submit_error", &format!("HTTP {status}"));
            format!("SUBMIT_HTTP_{status}")
        }
        SubmitOutcome::TransportError(e) => {
            eprintln!("[transport] resubmit error: {e}");
            eprint_resubmit_hint(&session);
            log.log("submit_error", &e);
            "SUBMIT_ERROR".to_string()
        }
    };

    let summary_result =
        write_session_summary(&[(vs_path, disposition)], &mut log, &config.log_path);
    transport.close();
    summary_result
}

/// Fetch, process, submit, and poll each vector set in the session.
#[allow(clippy::too_many_arguments)]
fn process_vector_sets(
    urls: &[String],
    transport: &mut Transport,
    server_url: &str,
    bearer: &str,
    registry: &Registry,
    log: &mut TranscriptLog,
    log_path: &str,
    sessions_dir: &str,
) -> Vec<(String, String)> {
    let mut results: Vec<(String, String)> = Vec::new();
    for (i, vs_url) in urls.iter().enumerate() {
        let disposition = process_one_vector_set(
            vs_url,
            i.wrapping_add(1),
            urls.len(),
            transport,
            server_url,
            bearer,
            registry,
            log,
            log_path,
            sessions_dir,
        );
        results.push((vs_url.clone(), disposition));
    }
    results
}

/// Process a single vector set: fetch (with retry-envelope polling)
/// → persist prompt → dispatch → persist response (`PENDING`) →
/// submit → poll verdict.
///
/// Persistence failures *before* the compute are hard errors
/// (`PERSIST_ERROR`): the compute hasn't started, failing is cheap,
/// and proceeding without durability would silently reintroduce the
/// lost-compute failure mode this layer exists to fix. Persistence
/// failures *after* the compute only warn — at that point a submit
/// attempt is strictly better than dying.
///
/// Like `run_demo`, the function linearly orchestrates one protocol
/// leg (fetch → persist → dispatch → submit → poll); splitting it
/// further would scatter the flow, hence the line-count allow.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn process_one_vector_set(
    vs_url: &str,
    index: usize,
    total: usize,
    transport: &mut Transport,
    server_url: &str,
    bearer: &str,
    registry: &Registry,
    log: &mut TranscriptLog,
    log_path: &str,
    sessions_dir: &str,
) -> String {
    let full_url = resolve_url(server_url, vs_url);
    eprintln!("[transport] [{index}/{total}] fetching {vs_url}...");
    log.log("fetch_vectors", vs_url);

    // Fetch loop. Per ACVP §11.4, when a vector set isn't yet generated
    // the server responds with `{"retry": <seconds>}` instead of the
    // vector data. The client is expected to wait the indicated seconds
    // and re-fetch. We bound the loop at `max_polls` to avoid spinning
    // forever on a wedged session.
    let max_polls = 30u32;
    let mut poll = 0u32;
    let prompt = loop {
        poll = poll.wrapping_add(1);
        if poll > max_polls {
            eprintln!("  [transport] vector set never ready after {max_polls} polls");
            log.log("retry_timeout", vs_url);
            return "RETRY_TIMEOUT".to_string();
        }

        let vs_resp = match transport.get(&full_url, bearer) {
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

        let parsed = match json::parse(&vs_resp.body) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  [transport] parse error: {e}");
                log.log("parse_error", &format!("{e}"));
                return "PARSE_ERROR".to_string();
            }
        };

        // Detect retry envelope. ACVP wraps responses in a two-element
        // array `[{"acvVersion":...},{"retry":N}]`; we unwrap before
        // checking. A non-positive retry value or absent field means
        // the body is the actual vector set. Server-supplied retry
        // seconds are routed through `clamp_retry_hint` for the same
        // defense-in-depth bound applied in `poll_verdict`.
        let body = unwrap_acvp_array(&parsed);
        if let Some(retry_secs) = body.get("retry").and_then(JsonValue::as_i64)
            && let Some(secs) = clamp_retry_hint(retry_secs)
        {
            eprintln!(
                "  [transport] vector set not ready; server says retry in {retry_secs}s, \
                     sleeping {secs}s (poll {poll}/{max_polls})"
            );
            log.log("vector_set_retry", &format!("{secs}s, poll {poll}"));
            std::thread::sleep(std::time::Duration::from_secs(secs));
            continue;
        }
        break parsed;
    };

    // The ACVP server wraps vector sets in a two-element array.
    let vs_body = unwrap_acvp_array(&prompt);
    log.log_json("vector_set_prompt", vs_body);

    // ── Submission persistence: prompt (before compute) ───────────
    // Carve the session directory out of the vector-set URL and write
    // the prompt + session token now, so even a crash mid-compute
    // leaves the operator a complete replayable record.
    let session = match open_session_store(vs_url, sessions_dir, bearer, vs_body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [transport] {e}");
            log.log("persist_error", &e);
            return "PERSIST_ERROR".to_string();
        }
    };

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
    // ACVP responses must echo back the prompt's `vsId` so the server
    // can bind the submission to its issued vector set. The dispatcher
    // produces `{algorithm, revision, testGroups}` and doesn't carry
    // `vsId` through, so we inject it here from the prompt.
    let response = inject_vs_id(&response, vs_body);
    log.log_json("vector_set_response", &response);

    // ── Submission persistence: response + PENDING (before submit) ─
    // The computed response is durable from this point on; a submit
    // failure costs a `resubmit`, never a recompute. Failures here
    // only warn — the compute is already done, so attempting the
    // submit is strictly better than dying.
    let results_url = format!("{full_url}/results");
    let response_body = build_acvp_response_body(&response);
    if let Err(e) = session
        .write_response(&response_body)
        .and_then(|()| session.write_status(session::STATUS_PENDING))
    {
        eprintln!("  [transport] WARN: response persistence failed (submitting anyway): {e}");
        log.log("persist_warning", &e);
    }

    // Submit response
    eprintln!("  [transport] submitting response...");
    match submit_and_mark(&session, &response_body, |body| {
        transport.post(&results_url, body, bearer)
    }) {
        SubmitOutcome::Submitted => {
            eprintln!("  [transport] submitted OK");
            log.log("submit_ok", vs_url);
            // Incremental flush — captures the just-submitted state so
            // an operator interruption between submit and verdict-poll
            // doesn't lose the vector-set URL needed to fetch the
            // verdict via `--query-session`.
            if let Err(e) = log.write_to_file(log_path) {
                eprintln!("  [transport] transcript flush failed after submit (continuing): {e}");
            }
        }
        SubmitOutcome::HttpError(status) => {
            eprintln!("  [transport] submit returned HTTP {status}");
            eprint_resubmit_hint(&session);
            log.log("submit_error", &format!("HTTP {status}"));
            return format!("SUBMIT_HTTP_{status}");
        }
        SubmitOutcome::TransportError(e) => {
            eprintln!("  [transport] submit error: {e}");
            eprint_resubmit_hint(&session);
            log.log("submit_error", &e);
            return "SUBMIT_ERROR".to_string();
        }
    }

    // Poll for verdict
    eprintln!("  [transport] polling for verdict...");
    match poll_verdict(&full_url, transport, bearer, log) {
        Ok(d) => {
            eprintln!("  [transport] verdict: {d}");
            log.log("verdict", &format!("{vs_url}: {d}"));
            if let Err(e) = session.write_status(&d) {
                eprintln!("  [transport] WARN: could not record verdict in status file: {e}");
            }
            d
        }
        Err(e) => {
            eprintln!("  [transport] poll error: {e}");
            log.log("poll_error", &e);
            "POLL_ERROR".to_string()
        }
    }
}

/// Resolve the session-persistence directory for a vector set and
/// write the pre-compute artifacts (prompt + session token).
///
/// Returns a hard error when the ids can't be parsed from the URL or
/// the artifacts can't be written: durability is the contract of this
/// layer, and at this point nothing has been computed yet, so failing
/// is cheap and loud beats a silent downgrade to the lossy pre-S2
/// behavior.
fn open_session_store(
    vs_url: &str,
    sessions_dir: &str,
    bearer: &str,
    vs_body: &JsonValue,
) -> Result<SessionDir, String> {
    let (ts_id, vs_id) = session::parse_session_ids(vs_url).ok_or_else(|| {
        format!("persistence setup failed: cannot parse tsId/vsId from vector-set URL {vs_url}")
    })?;
    let store = SessionDir::create(sessions_dir, ts_id, vs_id)
        .map_err(|e| format!("persistence setup failed: {e}"))?;
    let mut prompt_text = json::to_pretty_string(vs_body);
    prompt_text.push('\n');
    store
        .write_prompt(&prompt_text)
        .and_then(|()| store.write_token(bearer))
        .map_err(|e| format!("persistence setup failed: {e}"))?;
    eprintln!(
        "  [transport] session store ready at {}",
        store.path().display()
    );
    Ok(store)
}

/// Outcome of a single submit attempt (factored out of the protocol
/// loop so tests can drive the persistence state machine with a
/// stubbed transport closure — no network).
enum SubmitOutcome {
    /// HTTP 2xx — response accepted; status advanced to `SUBMITTED`.
    Submitted,
    /// Non-2xx HTTP status; the cached `PENDING` state is left intact.
    HttpError(u16),
    /// Transport-level failure (broken pipe, TLS teardown, curl exec
    /// error); the cached `PENDING` state is left intact.
    TransportError(String),
}

/// Run one submit attempt through `submit` and advance the session
/// store's status file on success.
///
/// On any failure the status file is deliberately NOT touched: it
/// stays `PENDING`, which is exactly the on-disk state
/// `acvp-harness resubmit` consumes. The caller surfaces the error and
/// the resubmit command to the operator.
fn submit_and_mark<F>(session: &SessionDir, response_body: &str, submit: F) -> SubmitOutcome
where
    F: FnOnce(&str) -> Result<HttpResponse, String>,
{
    match submit(response_body) {
        Ok(r) if r.status >= 200 && r.status < 300 => {
            if let Err(e) = session.write_status(session::STATUS_SUBMITTED) {
                eprintln!("  [transport] WARN: could not update submit status file: {e}");
            }
            SubmitOutcome::Submitted
        }
        Ok(r) => SubmitOutcome::HttpError(r.status),
        Err(e) => SubmitOutcome::TransportError(e),
    }
}

/// Tell the operator where the computed response is preserved and the
/// exact command that replays it without recomputing.
fn eprint_resubmit_hint(session: &SessionDir) {
    eprintln!(
        "  [transport] computed response preserved at {} (status {})",
        session.path().display(),
        session::STATUS_PENDING
    );
    eprintln!(
        "  [transport] resubmit WITHOUT recomputing via:\n    {}",
        session::resubmit_command(session.ts_id(), session.vs_id())
    );
}

/// Classify a vector-set disposition as a harness-level error.
///
/// Returns `true` when the disposition came from a transport, dispatch,
/// submission, or polling failure inside the harness itself — these
/// are the kinds of errors that should produce a non-zero process
/// exit so wrappers and CI can detect them. Returns `false` for the
/// ACVP grader's verdict strings (`passed` / `failed`) and any other
/// unknown disposition: a `failed` verdict is a meaningful test
/// outcome, not a harness error.
fn is_error_disposition(disp: &str) -> bool {
    disp.starts_with("DISPATCH_ERROR")
        || disp.starts_with("FETCH_ERROR")
        || disp.starts_with("PARSE_ERROR")
        || disp.starts_with("PERSIST_ERROR")
        || disp.starts_with("SUBMIT_")
        || disp.starts_with("RETRY_TIMEOUT")
        || disp.starts_with("POLL_ERROR")
        || disp.starts_with("HTTP_")
}

/// Print and log the session summary, then write the transcript file.
fn write_session_summary(
    results: &[(String, String)],
    log: &mut TranscriptLog,
    log_path: &str,
) -> Result<(), String> {
    eprintln!("\n[transport] ══════════════════════════════════════");
    eprintln!(
        "[transport] Session complete: {} vector set(s)",
        results.len()
    );
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
                            ("disposition".to_string(), JsonValue::String(disp.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("total".to_string(), JsonValue::Number(results.len() as i64)),
    ]);
    log.log_json("session_summary", &summary);
    log.write_to_file(log_path)?;
    eprintln!("[transport] transcript written to {log_path}");

    // Bubble harness-level errors to caller so main()'s ExitCode
    // propagation reflects them (exit 3 = runtime failure). The
    // transcript is fully written before this check so operators
    // always have the per-vector-set details on disk. ACVP-grader
    // verdicts ("passed"/"failed") are deliberately not errors —
    // a "failed" verdict is a real test outcome, communicated via
    // stdout and the transcript JSON.
    let errors: Vec<&(String, String)> = results
        .iter()
        .filter(|(_, disp)| is_error_disposition(disp))
        .collect();
    if !errors.is_empty() {
        let detail = errors
            .iter()
            .map(|(url, disp)| format!("{url} → {disp}"))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "{} of {} vector set(s) had harness-level errors: {detail}",
            errors.len(),
            results.len()
        ));
    }
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
        arr.iter().find(|item| item.get("vectorSetUrls").is_some())
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
        JsonValue::Object(vec![("algorithms".to_string(), algo_array)]),
    ]);
    json::to_pretty_string(&body)
}

/// Copy the `vsId` field from the prompt into the response object if
/// the response doesn't already have it. ACVP requires the response to
/// echo the prompt's `vsId` so the server can bind the submission to
/// its issued vector set; without it, submissions return HTTP 409.
fn inject_vs_id(response: &JsonValue, prompt: &JsonValue) -> JsonValue {
    let JsonValue::Object(fields) = response else {
        return response.clone();
    };
    if fields.iter().any(|(k, _)| k == "vsId") {
        return response.clone();
    }
    let Some(vs_id) = prompt.get("vsId") else {
        return response.clone();
    };
    let mut new_fields: Vec<(String, JsonValue)> = Vec::with_capacity(fields.len().wrapping_add(1));
    new_fields.push(("vsId".to_string(), vs_id.clone()));
    for (k, v) in fields {
        new_fields.push((k.clone(), v.clone()));
    }
    JsonValue::Object(new_fields)
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
    if let Some(arr) = val.as_array()
        && arr.len() == 2
    {
        return arr.get(1).unwrap_or(val);
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

/// Scan an HTTP response-headers byte buffer for a `Connection: close`
/// directive.
///
/// HTTP header names are case-insensitive (RFC 9110 §5.1) and
/// multi-value `Connection` headers carry comma-separated tokens
/// (RFC 9110 §7.6.1) — we match the literal token `close` case-
/// insensitively, with token-boundary discipline, so a value like
/// `closeAfter` does not false-positive. Operates on the raw byte
/// buffer the read-headers loop already accumulates; non-UTF-8 input
/// is treated as "no signal" (returns `false`) so a malformed header
/// can't accidentally trigger a reconnect.
fn scan_connection_close(headers: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(headers) else {
        return false;
    };
    for line in text.split("\r\n") {
        let Some(colon_idx) = line.find(':') else {
            continue;
        };
        let (name, value) = line.split_at(colon_idx);
        if !name.trim().eq_ignore_ascii_case("connection") {
            continue;
        }
        // Skip the `:` separator before splitting tokens.
        for token in value[1..].split(',') {
            if token.trim().eq_ignore_ascii_case("close") {
                return true;
            }
        }
    }
    false
}

/// Clamp a server-supplied retry hint (seconds) to `[5, 120]`, or
/// return `None` for non-positive hints so the caller falls through
/// to its own backoff schedule.
///
/// Floor prevents a server-induced retry storm if the server asks
/// for an unreasonably tight cadence; ceiling bounds the worst-case
/// total polling wall-clock at `max_polls × 120s`.
fn clamp_retry_hint(secs: i64) -> Option<u64> {
    let pos = u64::try_from(secs).ok()?;
    if pos == 0 {
        None
    } else {
        Some(pos.clamp(5, 120))
    }
}

/// Poll the vector-set's *results* endpoint until the verdict is
/// available, honoring server-supplied retry hints when present and
/// falling back to local exponential backoff otherwise. Returns the
/// disposition string. Uses the session's persistent transport, so
/// each poll is just an HTTP request over the existing TLS tunnel —
/// no per-poll touch.
///
/// **Sleep schedule:** when the server returns `{"retry": N}` on a
/// still-grading response, the next iteration sleeps for `N` seconds
/// (clamped to `[5s, 120s]` via [`clamp_retry_hint`]). When no hint
/// is available, the loop falls back to the legacy local schedule
/// `min(2s × 2^poll.min(4), 30s)`. Honoring the server's hint is the
/// politeness fix per ACVP demo etiquette — last night's session
/// (723934) showed the harness polling at 8s while the server
/// explicitly asked for 30s, which is a small retry storm on a
/// shared resource.
///
/// **URL is `<vsUrl>/results`, not `<vsUrl>` itself.** The vector-set
/// URL returns the prompt JSON regardless of grading state; the
/// `/results` sub-URL is what carries the verdict envelope. Confirmed
/// 2026-04-26 by comparing the earlier prompt fetch (`/vectorSets/{id}`
/// returned ~900KB prompt with no status field even after grading) to
/// the verdict fetch (`/vectorSets/{id}/results` returned 22KB body
/// with `disposition: passed`).
fn poll_verdict(
    vs_url: &str,
    transport: &mut Transport,
    bearer: &str,
    log: &mut TranscriptLog,
) -> Result<String, String> {
    let results_url = format!("{vs_url}/results");
    let max_polls = 20u32;
    let mut poll = 0u32;
    let mut retry_hint: Option<u64> = None;
    loop {
        poll = poll.wrapping_add(1);
        if poll > max_polls {
            return Ok("POLL_TIMEOUT".to_string());
        }
        let delay_ms = match retry_hint.take() {
            Some(secs) => secs.saturating_mul(1000),
            None => std::cmp::min(2000u64.wrapping_mul(1u64 << poll.min(4)), 30_000),
        };
        eprintln!(
            "    [poll {poll}/{max_polls}] sleeping {}s before next /results fetch",
            delay_ms / 1000
        );
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));

        let resp = transport.get(&results_url, bearer)?;
        if resp.status < 200 || resp.status >= 300 {
            eprintln!("    [poll {poll}/{max_polls}] HTTP {}", resp.status);
            log.log("poll_error", &format!("HTTP {}", resp.status));
            continue;
        }
        let parsed = json::parse(&resp.body).map_err(|e| format!("parse poll response: {e}"))?;
        let body = unwrap_acvp_array(&parsed);

        // Verdict envelope (per the SHA3-256 verdict observed 2026-04-26):
        //   {"vsId": ..., "disposition": "passed"|"failed", "tests": [...]}
        // `disposition` at top level means grading is complete. If the
        // server is still grading it returns either {"retry": N} or a
        // similar holding response — handle both by looping.
        if let Some(disposition) = body.get("disposition").and_then(JsonValue::as_str) {
            // Persist the full /results body in the transcript so an
            // operator can recover the per-tcId pass/fail cluster for a
            // failed vector set without re-fetching against ACVTS (which
            // would burn another login slot). Per
            // `project_acvts_verdict_fetch_url_pattern`, /results is the
            // only endpoint that carries the per-tcId verdict array.
            log.log("verdict_body", &resp.body);
            return Ok(disposition.to_string());
        }
        if let Some(retry_secs) = body.get("retry").and_then(JsonValue::as_i64) {
            retry_hint = clamp_retry_hint(retry_secs);
            eprintln!(
                "    [poll {poll}/{max_polls}] server says retry in {retry_secs}s (still grading; honoring on next sleep)"
            );
            continue;
        }
        let preview: String = resp.body.chars().take(120).collect();
        eprintln!(
            "    [poll {poll}/{max_polls}] HTTP 200 but no disposition/retry; body[0..120]: {preview:?}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn totp_deterministic_8_digit() {
        let secret = b"12345678901234567890";
        // Same counter should produce the same code.
        let a = totp_at(secret, 1).unwrap();
        let b = totp_at(secret, 1).unwrap();
        assert_eq!(a, b);
        // NIST ACVTS uses 8-digit codes (not the RFC 6238 default of 6).
        assert_eq!(a.len(), 8);
        // Different counters should (very likely) produce different codes.
        let c = totp_at(secret, 2).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn base64_decode_empty() {
        assert!(base64_decode("").unwrap().is_empty());
    }

    #[test]
    fn base64_decode_basic() {
        // "Hello" → "SGVsbG8=" (with padding) or "SGVsbG8" (without)
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(base64_decode("SGVsbG8").unwrap(), b"Hello");
    }

    #[test]
    fn base64_decode_url_alphabet() {
        // "?>" base64-standard = "Pz4=", base64url = "Pz4="; pick a value
        // that actually differs: byte 0xFB (rare in text) → "+w==" /
        // "-w==". This proves the decoder accepts both alphabets.
        assert_eq!(base64_decode("+w==").unwrap(), vec![0xfbu8]);
        assert_eq!(base64_decode("-w==").unwrap(), vec![0xfbu8]);
    }

    #[test]
    fn base64_decode_ignores_whitespace() {
        assert_eq!(base64_decode("SGVs\nbG8=").unwrap(), b"Hello");
        assert_eq!(base64_decode("  SGVsbG8  ").unwrap(), b"Hello");
    }

    #[test]
    fn base64_decode_rejects_invalid() {
        assert!(base64_decode("SG!Vs").is_err());
    }

    #[test]
    fn clamp_retry_hint_typical() {
        assert_eq!(clamp_retry_hint(60), Some(60));
    }

    #[test]
    fn clamp_retry_hint_below_floor() {
        assert_eq!(clamp_retry_hint(2), Some(5));
    }

    #[test]
    fn clamp_retry_hint_above_ceiling() {
        assert_eq!(clamp_retry_hint(300), Some(120));
    }

    #[test]
    fn clamp_retry_hint_zero_falls_through() {
        assert_eq!(clamp_retry_hint(0), None);
    }

    #[test]
    fn clamp_retry_hint_negative_falls_through() {
        assert_eq!(clamp_retry_hint(-1), None);
    }

    #[test]
    fn clamp_retry_hint_at_boundaries() {
        assert_eq!(clamp_retry_hint(5), Some(5));
        assert_eq!(clamp_retry_hint(120), Some(120));
    }

    #[test]
    fn is_error_disposition_dispatch() {
        assert!(is_error_disposition("DISPATCH_ERROR"));
    }

    #[test]
    fn is_error_disposition_fetch() {
        assert!(is_error_disposition("FETCH_ERROR"));
    }

    #[test]
    fn is_error_disposition_parse() {
        assert!(is_error_disposition("PARSE_ERROR"));
    }

    #[test]
    fn is_error_disposition_submit_plain() {
        assert!(is_error_disposition("SUBMIT_ERROR"));
    }

    #[test]
    fn is_error_disposition_submit_http_status() {
        assert!(is_error_disposition("SUBMIT_HTTP_500"));
        assert!(is_error_disposition("SUBMIT_HTTP_400"));
    }

    #[test]
    fn is_error_disposition_retry_timeout() {
        assert!(is_error_disposition("RETRY_TIMEOUT"));
    }

    #[test]
    fn is_error_disposition_poll_error() {
        assert!(is_error_disposition("POLL_ERROR"));
    }

    #[test]
    fn is_error_disposition_http_4xx_5xx() {
        assert!(is_error_disposition("HTTP_404"));
        assert!(is_error_disposition("HTTP_500"));
        assert!(is_error_disposition("HTTP_503"));
    }

    #[test]
    fn is_error_disposition_passed_is_not_error() {
        assert!(!is_error_disposition("passed"));
    }

    #[test]
    fn is_error_disposition_failed_verdict_is_not_harness_error() {
        // ACVP-grader test failures are a meaningful outcome, not a
        // harness-level error. Exit code stays 0; the disposition
        // string in stdout/transcript carries the signal.
        assert!(!is_error_disposition("failed"));
    }

    #[test]
    fn is_error_disposition_unknown_disposition_is_not_error() {
        assert!(!is_error_disposition("incomplete"));
        assert!(!is_error_disposition(""));
    }

    #[test]
    fn scan_connection_close_missing_header() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(!scan_connection_close(buf));
    }

    #[test]
    fn scan_connection_close_keep_alive() {
        let buf = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n";
        assert!(!scan_connection_close(buf));
    }

    #[test]
    fn scan_connection_close_lowercase() {
        let buf = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        assert!(scan_connection_close(buf));
    }

    #[test]
    fn scan_connection_close_mixed_case_value() {
        let buf_a = b"HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
        let buf_b = b"HTTP/1.1 200 OK\r\nConnection: CLOSE\r\n\r\n";
        assert!(scan_connection_close(buf_a));
        assert!(scan_connection_close(buf_b));
    }

    #[test]
    fn scan_connection_close_substring_is_not_a_token_match() {
        // "closeAfter" contains "close" as a substring but is a
        // different token. RFC 9110 Connection-header values are
        // tokens, not free-form text.
        let buf = b"HTTP/1.1 200 OK\r\nConnection: closeAfter\r\n\r\n";
        assert!(!scan_connection_close(buf));
    }

    #[test]
    fn scan_connection_close_comma_list_contains_close() {
        let buf = b"HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\n\r\n";
        assert!(scan_connection_close(buf));
    }

    #[test]
    fn scan_connection_close_comma_list_without_close() {
        let buf = b"HTTP/1.1 200 OK\r\nConnection: keep-alive, upgrade\r\n\r\n";
        assert!(!scan_connection_close(buf));
    }

    #[test]
    fn scan_connection_close_header_name_case_insensitive() {
        // RFC 9110 §5.1: header field names are case-insensitive.
        let buf = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n";
        assert!(scan_connection_close(buf));
    }

    #[test]
    fn is_error_disposition_persist_error() {
        assert!(is_error_disposition("PERSIST_ERROR"));
    }

    // ── Submission-persistence state machine ─────────────────────
    //
    // submit_and_mark takes the submit step as a closure, so these
    // tests drive the full persistence path with stubbed transports —
    // no network. The simulated-failure cases assert the on-disk
    // state is exactly what `resubmit` consumes.

    /// Fresh per-test scratch root under the OS temp dir, pre-loaded
    /// with a session dir holding a cached response + PENDING status —
    /// the state demo-run leaves just before its submit attempt.
    fn pending_session(tag: &str) -> (std::path::PathBuf, SessionDir, String) {
        let root = std::env::temp_dir().join(format!(
            "oxicrypt-acvp-transport-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let session = SessionDir::create(root.to_str().unwrap(), 42, 123).unwrap();
        let response_body =
            "[{\"acvVersion\": \"1.0\"},{\"vsId\": 123,\"testGroups\": []}]".to_string();
        session.write_response(&response_body).unwrap();
        session.write_status(session::STATUS_PENDING).unwrap();
        (root, session, response_body)
    }

    #[test]
    fn submit_and_mark_success_advances_status_to_submitted() {
        let (root, session, response_body) = pending_session("ok");
        let outcome = submit_and_mark(&session, &response_body, |body| {
            // The closure receives the exact cached bytes.
            assert_eq!(body, response_body);
            Ok(HttpResponse {
                status: 200,
                body: String::new(),
            })
        });
        assert!(matches!(outcome, SubmitOutcome::Submitted));
        assert_eq!(session.read_status().unwrap(), session::STATUS_SUBMITTED);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn submit_and_mark_transport_error_leaves_pending_state_for_resubmit() {
        let (root, session, response_body) = pending_session("broken-pipe");
        // Simulated TLS keep-alive death mid-POST (the 2026-05-17 LMS
        // B7 failure mode).
        let outcome = submit_and_mark(&session, &response_body, |_| {
            Err("write to s_client stdin: Broken pipe (os error 32)".to_string())
        });
        assert!(matches!(outcome, SubmitOutcome::TransportError(_)));
        // The on-disk state is exactly what resubmit expects: the
        // session dir opens, the response replays byte-identically,
        // and the status is still PENDING.
        let reopened = SessionDir::open(root.to_str().unwrap(), 42, 123).unwrap();
        assert_eq!(reopened.read_response().unwrap(), response_body);
        assert_eq!(reopened.read_status().unwrap(), session::STATUS_PENDING);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn submit_and_mark_http_error_leaves_pending_state() {
        let (root, session, response_body) = pending_session("http-500");
        let outcome = submit_and_mark(&session, &response_body, |_| {
            Ok(HttpResponse {
                status: 500,
                body: "server error".to_string(),
            })
        });
        assert!(matches!(outcome, SubmitOutcome::HttpError(500)));
        assert_eq!(session.read_status().unwrap(), session::STATUS_PENDING);
        assert_eq!(session.read_response().unwrap(), response_body);
        let _ = std::fs::remove_dir_all(&root);
    }
}
