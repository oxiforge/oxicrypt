//! CAVP SHS dispatch layer — the second envelope shape.
//!
//! R10 wired the first envelope shape (ACVP `internalProjection.json`)
//! with the [`crate::dispatch`] registry and trait. R11′ documented
//! that plain FIPS 180-4 hashing vectors are not shipped in that
//! layout at all: upstream `usnistgov/ACVP-Server` has never published
//! top-level `SHA-*`, `SHA1-*`, or `SHA2-*` vector directories, so the
//! SHA-2 family has to ride a different envelope. R12-B wires that
//! second envelope: parse the vendored CAVP SHS `.rsp` files via
//! [`crate::rsp`], dispatch each case to a per-algorithm
//! [`ShsHandler`], and emit a JSON response document that mirrors the
//! ACVP response shape closely enough to share the existing JSON
//! printer.
//!
//! # Envelope shape
//!
//! The in-tree model is intentionally flat — CAVP SHS short-message
//! files carry one algorithm per file and a single `[L = N]` header,
//! so there is no analogue of ACVP's `testGroups` nesting. The
//! dispatcher therefore takes:
//!
//! ```text
//! algorithm: &str     // e.g. "SHA-256", caller-supplied
//! doc: &RspDocument   // parsed .rsp: digest length + Vec<RspCase>
//! ```
//!
//! and produces:
//!
//! ```text
//! {
//!   "algorithm":  "SHA-256",
//!   "l":          32,
//!   "testCases": [
//!     { "len": 0,   "md": "E3B0C442…" },
//!     { "len": 8,   "md": "28969CDF…" },
//!      …
//!   ]
//! }
//! ```
//!
//! Identifying cases by `len` (message length in bits) works because
//! CAVP short-message files test one length per record and the
//! lengths are strictly increasing, so `len` is a unique key within
//! the file. This avoids inventing synthetic `tcId` values that would
//! have no source-of-truth in the vendored data.
//!
//! # Module gating
//!
//! [`process_shs`] re-runs `oxicrypt_module::require_operational()` on
//! every call, exactly like [`crate::dispatch::process`], so no code
//! path can reach a crypto primitive through the harness without the
//! power-up KAT set having been cleared first.
//!
//! # Algorithm coverage
//!
//! R12-B registers seven handlers, one per file vendored under
//! `[cavp_shs]` in `vendor/nist/MANIFEST.toml`:
//!
//! - `SHA-1`   (20 bytes)
//! - `SHA-224` (28 bytes)
//! - `SHA-256` (32 bytes)
//! - `SHA-384` (48 bytes)
//! - `SHA-512` (64 bytes)
//! - `SHA-512/224` (28 bytes) — truncated SHA-512 variant
//! - `SHA-512/256` (32 bytes) — truncated SHA-512 variant

use crate::dispatch::DispatchError;
use crate::handlers;
use crate::hex;
use crate::json::JsonValue;
use crate::rsp::RspDocument;

/// Trait implemented by every CAVP SHS per-algorithm handler.
///
/// Handlers are stateless: the registry stores them as
/// `Box<dyn ShsHandler>` and [`process_shs`] looks one up by
/// algorithm name. This mirrors [`crate::dispatch::AlgorithmHandler`]
/// but drops the `revision` axis, because CAVP `.rsp` files carry no
/// revision metadata — the file format is itself the revision.
pub trait ShsHandler: Send + Sync {
    /// CAVP/ACVP-style algorithm name (e.g. `"SHA-256"`,
    /// `"SHA-512/224"`).
    fn algorithm(&self) -> &'static str;

    /// Digest length in bytes (e.g. `32` for SHA-256).
    fn digest_length_bytes(&self) -> usize;

    /// Compute the digest of `msg`.
    ///
    /// `msg` is already sliced to the declared bit-length by
    /// [`process_shs`], so the handler can pass it straight to the
    /// underlying `oxicrypt_sha` primitive.
    fn compute(&self, msg: &[u8]) -> Result<Vec<u8>, DispatchError>;
}

/// Registry of CAVP SHS handlers. Separate type from
/// [`crate::dispatch::Registry`] because the handler trait is
/// different — keeping them split is cheaper than fabricating a
/// common super-trait that erases the asymmetries.
pub struct ShsRegistry {
    handlers: Vec<Box<dyn ShsHandler>>,
}

impl ShsRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register a handler. Later registrations shadow earlier ones.
    pub fn register(&mut self, h: Box<dyn ShsHandler>) {
        self.handlers.push(h);
    }

    /// Look up a handler by algorithm name.
    #[must_use]
    pub fn find(&self, algorithm: &str) -> Option<&dyn ShsHandler> {
        self.handlers
            .iter()
            .find(|h| h.algorithm() == algorithm)
            .map(AsRef::as_ref)
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether any handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl Default for ShsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Construct a [`ShsRegistry`] populated with every CAVP SHS handler
/// R12-B wires: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
/// SHA-512/224, and SHA-512/256.
#[must_use]
pub fn with_default_shs_handlers() -> ShsRegistry {
    let mut r = ShsRegistry::new();
    r.register(Box::new(handlers::shs::Sha1Handler));
    r.register(Box::new(handlers::shs::Sha224Handler));
    r.register(Box::new(handlers::shs::Sha256Handler));
    r.register(Box::new(handlers::shs::Sha384Handler));
    r.register(Box::new(handlers::shs::Sha512Handler));
    r.register(Box::new(handlers::shs::Sha512_224Handler));
    r.register(Box::new(handlers::shs::Sha512_256Handler));
    r
}

/// Dispatch a parsed CAVP SHS `.rsp` document through `registry`.
///
/// Returns a JSON response document shaped per the module rustdoc.
///
/// # Validation
///
/// - Re-runs `oxicrypt_module::require_operational()` before touching
///   anything, matching [`crate::dispatch::process`].
/// - Errors with [`DispatchError::UnsupportedAlgorithm`] if no
///   handler matches `algorithm`.
/// - Errors with [`DispatchError::Crypto`] if the document's
///   `digest_length_bytes` field disagrees with the handler's
///   advertised digest length — this catches the "fed SHA-1 vectors
///   to SHA-256" misconfiguration at dispatch time rather than only
///   at test-assertion time.
/// - Errors with [`DispatchError::Unsupported`] on non-byte-aligned
///   `Len`, matching R10's SHA-3 AFT handler. The vendored CAVP SHS
///   byte-oriented files use byte-aligned lengths exclusively, so
///   this is not a functional gap.
pub fn process_shs(
    algorithm: &str,
    doc: &RspDocument,
    registry: &ShsRegistry,
) -> Result<JsonValue, DispatchError> {
    oxicrypt_module::require_operational().map_err(DispatchError::Module)?;
    let handler = registry
        .find(algorithm)
        .ok_or_else(|| DispatchError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            mode: None,
            revision: "CAVP-SHS".to_string(),
        })?;
    if doc.digest_length_bytes != handler.digest_length_bytes() {
        return Err(DispatchError::Crypto(
            "CAVP SHS: [L = N] header disagrees with handler digest length",
        ));
    }
    let mut results: Vec<JsonValue> = Vec::with_capacity(doc.cases.len());
    for case in &doc.cases {
        if !case.len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "CAVP SHS: non-byte-aligned `Len`",
            ));
        }
        let expected_bytes: usize = (case.len_bits / 8) as usize;
        // CAVP uses a sentinel `Msg = 00` byte for `Len = 0`. Slicing
        // `msg[..0]` produces an empty slice regardless, so the same
        // `msg[..expected_bytes]` rule that R10's SHA-3 AFT handler
        // uses works here without a special case.
        if case.msg.len() < expected_bytes {
            return Err(DispatchError::Crypto(
                "CAVP SHS: `Msg` hex shorter than declared `Len`",
            ));
        }
        let used = case
            .msg
            .get(..expected_bytes)
            .ok_or(DispatchError::Crypto("CAVP SHS: slicing failed"))?;
        let md = handler.compute(used)?;
        let len_json = i64::try_from(case.len_bits).map_err(|_| {
            DispatchError::Crypto("CAVP SHS: `Len` does not fit in i64")
        })?;
        results.push(JsonValue::Object(vec![
            ("len".to_string(), JsonValue::Number(len_json)),
            ("md".to_string(), JsonValue::String(hex::encode_upper(&md))),
        ]));
    }
    let l_json = i64::try_from(doc.digest_length_bytes).map_err(|_| {
        DispatchError::Crypto("CAVP SHS: `[L = N]` does not fit in i64")
    })?;
    Ok(JsonValue::Object(vec![
        (
            "algorithm".to_string(),
            JsonValue::String(algorithm.to_string()),
        ),
        ("l".to_string(), JsonValue::Number(l_json)),
        ("testCases".to_string(), JsonValue::Array(results)),
    ]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::rsp;

    const SHA256_TWO_RECORDS: &str = "\
[L = 32]

Len = 0
Msg = 00
MD = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Len = 8
Msg = d3
MD = 28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1
";

    #[test]
    fn registry_lookup() {
        let r = with_default_shs_handlers();
        assert_eq!(r.len(), 7);
        assert!(!r.is_empty());
        assert!(r.find("SHA-1").is_some());
        assert!(r.find("SHA-224").is_some());
        assert!(r.find("SHA-256").is_some());
        assert!(r.find("SHA-384").is_some());
        assert!(r.find("SHA-512").is_some());
        assert!(r.find("SHA-512/224").is_some());
        assert!(r.find("SHA-512/256").is_some());
        assert!(r.find("SHA-3-256").is_none());
        assert!(r.find("NOPE").is_none());
    }

    #[test]
    fn dispatches_sha256_two_records() {
        let _ = crate::ensure_initialized();
        let doc = rsp::parse(SHA256_TWO_RECORDS).unwrap();
        let r = with_default_shs_handlers();
        let resp = process_shs("SHA-256", &doc, &r).unwrap();
        assert_eq!(resp.get("algorithm").and_then(JsonValue::as_str), Some("SHA-256"));
        assert_eq!(resp.get("l").and_then(JsonValue::as_i64), Some(32));
        let cases = resp.get("testCases").and_then(JsonValue::as_array).unwrap();
        assert_eq!(cases.len(), 2);
        assert_eq!(
            cases[0].get("md").and_then(JsonValue::as_str),
            Some("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
        );
        assert_eq!(cases[0].get("len").and_then(JsonValue::as_i64), Some(0));
        assert_eq!(
            cases[1].get("md").and_then(JsonValue::as_str),
            Some("28969CDFA74A12C82F3BAD960B0B000ACA2AC329DEEA5C2328EBC6F2BA9802C1")
        );
    }

    #[test]
    fn unsupported_algorithm_is_error() {
        let _ = crate::ensure_initialized();
        let doc = rsp::parse(SHA256_TWO_RECORDS).unwrap();
        let r = with_default_shs_handlers();
        let err = process_shs("NOPE", &doc, &r).unwrap_err();
        assert!(matches!(err, DispatchError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn digest_length_mismatch_is_error() {
        let _ = crate::ensure_initialized();
        // [L = 32] but ask the dispatcher for SHA-1 which claims 20
        // bytes — this should be caught at dispatch time, not at
        // test-assertion time.
        let doc = rsp::parse(SHA256_TWO_RECORDS).unwrap();
        let r = with_default_shs_handlers();
        let err = process_shs("SHA-1", &doc, &r).unwrap_err();
        assert!(matches!(err, DispatchError::Crypto(_)));
    }
}
