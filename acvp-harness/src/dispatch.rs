//! Algorithm-handler registry and the top-level [`process`] entry point.
//!
//! The dispatcher is intentionally tiny: a [`Registry`] holds a flat
//! list of [`AlgorithmHandler`] trait objects keyed on
//! `(algorithm, mode, revision)`, and [`process`] looks up the right
//! handler for the prompt's envelope and forwards each test group to
//! it. The `mode` slot is `Option<&str>` so that single-field families
//! (SHA-3, SHAKE, HMAC) key on `(algorithm, None, revision)` and
//! dual-field families (KDA-HKDF, KDA-OneStep, KDA-TwoStep) key on
//! `(algorithm, Some(mode), revision)` on the same trait object and
//! the same `find` path.
//!
//! # Module gating
//!
//! Every call to [`process`] starts with
//! `fips_module::require_operational()`. The harness binary has
//! already run the power-up KAT set by the time this code is reached,
//! but a defensive re-check here means that *any* code path leading
//! into the dispatcher — integration tests, future REST front-ends,
//! standalone fuzz harnesses — gets the same gate without having to
//! remember it.

use crate::envelope::{EnvelopeError, VectorSet};
use crate::handlers;
use crate::hex::HexError;
use crate::json::JsonValue;
use core::fmt;

/// Errors produced by [`process`] and the per-algorithm handlers.
#[derive(Debug)]
pub enum DispatchError {
    /// Failed to peel the ACVP envelope.
    Envelope(EnvelopeError),
    /// The pqclib module is not in the operational state.
    Module(fips_module::Error),
    /// A primitive returned an error or produced an unexpected shape.
    Crypto(&'static str),
    /// A hex-encoded data field could not be decoded.
    Hex(HexError),
    /// A required ACVP field is missing from a test case or group.
    MissingField(&'static str),
    /// No handler is registered for the prompt's algorithm/revision.
    UnsupportedAlgorithm {
        /// Algorithm name as it appears in the prompt.
        algorithm: String,
        /// Mode string as it appears in the prompt (if present).
        mode: Option<String>,
        /// Revision string as it appears in the prompt.
        revision: String,
    },
    /// The handler does not implement the requested `testType`.
    UnsupportedTestType(String),
    /// The handler does not yet support a feature the test exercises.
    Unsupported(&'static str),
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "envelope: {e}"),
            Self::Module(e) => write!(f, "module: {e}"),
            Self::Crypto(s) => write!(f, "crypto: {s}"),
            Self::Hex(e) => write!(f, "hex: {e}"),
            Self::MissingField(name) => write!(f, "missing field {name:?}"),
            Self::UnsupportedAlgorithm {
                algorithm,
                mode,
                revision,
            } => match mode {
                Some(m) => write!(
                    f,
                    "no handler registered for algorithm {algorithm:?} mode {m:?} revision {revision:?}"
                ),
                None => write!(
                    f,
                    "no handler registered for algorithm {algorithm:?} revision {revision:?}"
                ),
            },
            Self::UnsupportedTestType(t) => write!(f, "unsupported testType {t:?}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl From<EnvelopeError> for DispatchError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl From<HexError> for DispatchError {
    fn from(e: HexError) -> Self {
        Self::Hex(e)
    }
}

/// Trait implemented by every per-algorithm AFT dispatcher.
///
/// Handlers are stateless: the `&self` receiver lets the registry
/// store them as `Box<dyn AlgorithmHandler>` while keeping the
/// dispatch path branchless on the trait-object call.
pub trait AlgorithmHandler: Send + Sync {
    /// ACVP algorithm name (e.g. `"SHA3-256"`, `"KDA"`).
    fn algorithm(&self) -> &'static str;

    /// Optional ACVP `mode` string (e.g. `Some("HKDF")` for
    /// `KDA-HKDF-Sp800-56Cr2`). Single-field families return the
    /// default `None`.
    fn mode(&self) -> Option<&'static str> {
        None
    }

    /// ACVP revision string (e.g. `"2.0"`, `"Sp800-56Cr2"`).
    fn revision(&self) -> &'static str;

    /// Process a single test group, returning the response group.
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError>;
}

/// Mutable handler registry. Constructed with
/// [`with_default_handlers`] for normal use.
pub struct Registry {
    handlers: Vec<Box<dyn AlgorithmHandler>>,
}

impl Registry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register a handler. Last-write-wins is the caller's
    /// responsibility — `find` returns the first match.
    pub fn register(&mut self, h: Box<dyn AlgorithmHandler>) {
        self.handlers.push(h);
    }

    /// Look up a handler by algorithm/mode/revision. `mode` is
    /// `None` for single-field families (SHA-3, SHAKE, HMAC) and
    /// `Some(mode)` for dual-field families (KDA-HKDF, KDA-OneStep,
    /// KDA-TwoStep). The match is exact on all three components, so
    /// `(SHA3-256, None, 2.0)` will not collide with a future
    /// `(SHA3-256, Some("something"), 2.0)`.
    #[must_use]
    pub fn find(
        &self,
        algorithm: &str,
        mode: Option<&str>,
        revision: &str,
    ) -> Option<&dyn AlgorithmHandler> {
        self.handlers
            .iter()
            .find(|h| {
                h.algorithm() == algorithm && h.mode() == mode && h.revision() == revision
            })
            .map(AsRef::as_ref)
    }

    /// Number of registered handlers (used by the CLI banner and tests).
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

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Construct a [`Registry`] populated with every algorithm handler
/// the harness currently knows how to dispatch.
///
/// R10 wired the first two handlers — SHA3-256 AFT and HMAC-SHA2-256
/// AFT — end-to-end. R12-A expanded the SHA-3 hashing family, both
/// SHAKE XOFs, and every HMAC variant except HMAC-SHA2-256 (which
/// stays in its R10 module), bringing the total to seventeen
/// AFT handlers; R13 then added the first KDF family handler,
/// `KDA-HKDF-Sp800-56Cr2`, as the eighteenth. That is also the first
/// handler to live in a `(algorithm, mode, revision)` registry slot
/// rather than `(algorithm, None, revision)`:
///
/// - `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512` (revision `2.0`)
/// - `SHAKE-128`, `SHAKE-256` (revision `FIPS202`)
/// - `HMAC-SHA-1` (revision `1.0`)
/// - `HMAC-SHA2-{224,256,384,512}` and the two truncated
///   `HMAC-SHA2-512/{224,256}` variants (revision `1.0`)
/// - `HMAC-SHA3-{224,256,384,512}` (revision `1.0`)
/// - `KDA` mode `HKDF` revision `Sp800-56Cr2` — SP 800-56C Rev 2 §5
///   two-step KDF (hybrid form, ten HMAC instantiations)
///
/// Each new variant is a single `register` line — future chunks add
/// AES, DRBG, ECDSA, EdDSA, RSA, plus MCT/LDT test types on the same
/// plumbing.
#[must_use]
pub fn with_default_handlers() -> Registry {
    let mut r = Registry::new();
    // SHA-3 family (fixed-output hashing, revision 2.0)
    r.register(Box::new(handlers::sha3::Sha3_224Handler));
    r.register(Box::new(handlers::sha3_256::Sha3_256Handler));
    r.register(Box::new(handlers::sha3::Sha3_384Handler));
    r.register(Box::new(handlers::sha3::Sha3_512Handler));
    // SHAKE XOFs (revision FIPS202)
    r.register(Box::new(handlers::shake::Shake128Handler));
    r.register(Box::new(handlers::shake::Shake256Handler));
    // HMAC-SHA-1 (legacy, revision 1.0)
    r.register(Box::new(handlers::hmac::HmacSha1Handler));
    // HMAC-SHA-2 family (revision 1.0)
    r.register(Box::new(handlers::hmac::HmacSha2_224Handler));
    r.register(Box::new(handlers::hmac_sha2_256::HmacSha2_256Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_384Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_512Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_512_224Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_512_256Handler));
    // HMAC-SHA-3 family (revision 1.0)
    r.register(Box::new(handlers::hmac::HmacSha3_224Handler));
    r.register(Box::new(handlers::hmac::HmacSha3_256Handler));
    r.register(Box::new(handlers::hmac::HmacSha3_384Handler));
    r.register(Box::new(handlers::hmac::HmacSha3_512Handler));
    // KDA-HKDF (SP 800-56Cr2, mode-keyed)
    r.register(Box::new(handlers::kda_hkdf::KdaHkdfHandler));
    r
}

/// Top-level dispatcher: take an ACVP prompt as a `JsonValue`,
/// produce a response as a `JsonValue`.
///
/// On success, the response object preserves the prompt's `algorithm`
/// and `revision` fields and contains a `testGroups` array whose
/// shape is determined by the per-algorithm handler.
pub fn process(prompt: &JsonValue, registry: &Registry) -> Result<JsonValue, DispatchError> {
    fips_module::require_operational().map_err(DispatchError::Module)?;
    let vs = VectorSet::new(prompt)?;
    let algorithm = vs.algorithm()?;
    let mode = vs.mode()?;
    let revision = vs.revision()?;
    let handler = registry
        .find(algorithm, mode, revision)
        .ok_or_else(|| DispatchError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            mode: mode.map(str::to_string),
            revision: revision.to_string(),
        })?;
    let groups = vs.test_groups()?;
    let mut response_groups: Vec<JsonValue> = Vec::with_capacity(groups.len());
    for g in groups {
        response_groups.push(handler.handle_group(g)?);
    }
    let mut response: Vec<(String, JsonValue)> = Vec::with_capacity(4);
    response.push((
        "algorithm".to_string(),
        JsonValue::String(algorithm.to_string()),
    ));
    if let Some(m) = mode {
        response.push(("mode".to_string(), JsonValue::String(m.to_string())));
    }
    response.push((
        "revision".to_string(),
        JsonValue::String(revision.to_string()),
    ));
    response.push((
        "testGroups".to_string(),
        JsonValue::Array(response_groups),
    ));
    Ok(JsonValue::Object(response))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::json;

    #[test]
    fn registry_lookup() {
        let r = with_default_handlers();
        // R10 handlers
        assert!(r.find("SHA3-256", None, "2.0").is_some());
        assert!(r.find("HMAC-SHA2-256", None, "1.0").is_some());
        // R12-A SHA-3 family
        assert!(r.find("SHA3-224", None, "2.0").is_some());
        assert!(r.find("SHA3-384", None, "2.0").is_some());
        assert!(r.find("SHA3-512", None, "2.0").is_some());
        // R12-A SHAKE XOFs
        assert!(r.find("SHAKE-128", None, "FIPS202").is_some());
        assert!(r.find("SHAKE-256", None, "FIPS202").is_some());
        // R12-A HMAC family
        assert!(r.find("HMAC-SHA-1", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-224", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-384", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-512", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-512/224", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-512/256", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-224", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-256", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-384", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-512", None, "1.0").is_some());
        // R13 KDA-HKDF (mode-keyed)
        assert!(r.find("KDA", Some("HKDF"), "Sp800-56Cr2").is_some());
        // Negative lookups
        assert!(r.find("SHA3-256", None, "9.9").is_none());
        assert!(r.find("UNKNOWN", None, "1.0").is_none());
        assert!(r.find("KDA", None, "Sp800-56Cr2").is_none());
        assert!(r.find("KDA", Some("HKDF"), "1.0").is_none());
        assert_eq!(r.len(), 18);
        assert!(!r.is_empty());
    }

    #[test]
    fn unsupported_algorithm_error() {
        let _ = crate::ensure_initialized();
        let prompt = json::parse(r#"{"algorithm":"NOPE","revision":"1.0","testGroups":[]}"#)
            .unwrap();
        let r = with_default_handlers();
        let err = process(&prompt, &r).unwrap_err();
        assert!(matches!(
            err,
            DispatchError::UnsupportedAlgorithm { .. }
        ));
    }
}
