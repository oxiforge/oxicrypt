//! Algorithm-handler registry and the top-level [`process`] entry point.
//!
//! The dispatcher is intentionally tiny: a [`Registry`] holds a flat
//! list of [`AlgorithmHandler`] trait objects keyed on
//! `(algorithm, revision)`, and [`process`] looks up the right handler
//! for the prompt's envelope and forwards each test group to it.
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
                revision,
            } => write!(
                f,
                "no handler registered for algorithm {algorithm:?} revision {revision:?}"
            ),
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
    /// ACVP algorithm name (e.g. `"SHA3-256"`).
    fn algorithm(&self) -> &'static str;

    /// ACVP revision string (e.g. `"2.0"`).
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

    /// Look up a handler by algorithm/revision.
    #[must_use]
    pub fn find(&self, algorithm: &str, revision: &str) -> Option<&dyn AlgorithmHandler> {
        self.handlers
            .iter()
            .find(|h| h.algorithm() == algorithm && h.revision() == revision)
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
/// R10 wires up two handlers: SHA3-256 AFT and HMAC-SHA2-256 AFT.
/// Future chunks add SHA-2, SHAKE, AES, DRBG, etc. — each one a single
/// `register` line in this function.
#[must_use]
pub fn with_default_handlers() -> Registry {
    let mut r = Registry::new();
    r.register(Box::new(handlers::sha3_256::Sha3_256Handler));
    r.register(Box::new(handlers::hmac_sha2_256::HmacSha2_256Handler));
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
    let revision = vs.revision()?;
    let handler = registry
        .find(algorithm, revision)
        .ok_or_else(|| DispatchError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            revision: revision.to_string(),
        })?;
    let groups = vs.test_groups()?;
    let mut response_groups: Vec<JsonValue> = Vec::with_capacity(groups.len());
    for g in groups {
        response_groups.push(handler.handle_group(g)?);
    }
    Ok(JsonValue::Object(vec![
        (
            "algorithm".to_string(),
            JsonValue::String(algorithm.to_string()),
        ),
        (
            "revision".to_string(),
            JsonValue::String(revision.to_string()),
        ),
        (
            "testGroups".to_string(),
            JsonValue::Array(response_groups),
        ),
    ]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::json;

    #[test]
    fn registry_lookup() {
        let r = with_default_handlers();
        assert!(r.find("SHA3-256", "2.0").is_some());
        assert!(r.find("HMAC-SHA2-256", "1.0").is_some());
        assert!(r.find("SHA3-256", "9.9").is_none());
        assert!(r.find("UNKNOWN", "1.0").is_none());
        assert_eq!(r.len(), 2);
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
