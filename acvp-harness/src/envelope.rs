//! Typed views over an ACVP `internalProjection.json` document.
//!
//! The ACVP vector-set envelope is shallow:
//!
//! ```text
//! {
//!   "algorithm": "SHA3-256",
//!   "revision":  "2.0",
//!   "testGroups": [ {...}, {...} ]
//! }
//! ```
//!
//! Some ACVP families split the algorithm across two fields: an
//! `algorithm` like `"KDA"` plus a `mode` like `"HKDF"`. The KDF
//! families (`KDA-HKDF`, `KDA-OneStep`, `KDA-TwoStep`, `KDA-TLS-v1.2`,
//! `KDF`) all use this two-field form. [`VectorSet::mode`] returns
//! the mode string when present and `None` otherwise, so single-field
//! families keep their existing shape and dual-field families can
//! key their handlers on `(algorithm, mode, revision)` without any
//! top-level envelope churn.
//!
//! Per-algorithm fields inside each test group (`testType`, `tgId`,
//! `keyLen`, `msgLen`, `macLen`, `tests`, ...) are handler-specific
//! and deliberately *not* modelled here — the dispatcher hands the
//! raw `JsonValue` group straight to the handler, which reads only
//! the fields it understands. That keeps the envelope layer stable as
//! new algorithms are added in later chunks without a churn cascade.

use crate::json::JsonValue;
use core::fmt;

/// Errors produced when peeling an ACVP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The top-level value is not a JSON object.
    NotObject,
    /// A required field is missing from the top-level object.
    MissingField(&'static str),
    /// A required field has the wrong JSON shape.
    WrongType {
        /// The field name as it appears in the ACVP document.
        field: &'static str,
        /// The expected shape (`"string"`, `"array"`, ...).
        expected: &'static str,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotObject => write!(f, "ACVP prompt top-level value is not an object"),
            Self::MissingField(name) => write!(f, "ACVP prompt is missing required field {name:?}"),
            Self::WrongType { field, expected } => {
                write!(f, "ACVP prompt field {field:?} is not a {expected}")
            }
        }
    }
}

/// Typed view over the root of an ACVP vector-set prompt.
pub struct VectorSet<'a> {
    root: &'a JsonValue,
}

impl<'a> VectorSet<'a> {
    /// Construct a typed view over `root`, verifying only that the
    /// root value is a JSON object. Individual fields are decoded
    /// lazily by [`algorithm`], [`revision`], and [`test_groups`].
    ///
    /// [`algorithm`]: Self::algorithm
    /// [`revision`]: Self::revision
    /// [`test_groups`]: Self::test_groups
    pub fn new(root: &'a JsonValue) -> Result<Self, EnvelopeError> {
        if !matches!(root, JsonValue::Object(_)) {
            return Err(EnvelopeError::NotObject);
        }
        Ok(Self { root })
    }

    /// Read the `algorithm` field.
    pub fn algorithm(&self) -> Result<&'a str, EnvelopeError> {
        self.root
            .get("algorithm")
            .ok_or(EnvelopeError::MissingField("algorithm"))?
            .as_str()
            .ok_or(EnvelopeError::WrongType {
                field: "algorithm",
                expected: "string",
            })
    }

    /// Read the optional `mode` field.
    ///
    /// Returns `Ok(None)` if the field is absent (single-field
    /// families like SHA-3, SHAKE, HMAC), `Ok(Some(s))` if present and
    /// a string (KDA-HKDF, KDA-OneStep, KDA-TwoStep, KDF), or
    /// `Err(WrongType)` if present but not a string.
    pub fn mode(&self) -> Result<Option<&'a str>, EnvelopeError> {
        match self.root.get("mode") {
            None => Ok(None),
            Some(v) => v.as_str().map(Some).ok_or(EnvelopeError::WrongType {
                field: "mode",
                expected: "string",
            }),
        }
    }

    /// Read the `revision` field.
    pub fn revision(&self) -> Result<&'a str, EnvelopeError> {
        self.root
            .get("revision")
            .ok_or(EnvelopeError::MissingField("revision"))?
            .as_str()
            .ok_or(EnvelopeError::WrongType {
                field: "revision",
                expected: "string",
            })
    }

    /// Read the `testGroups` array as raw `JsonValue`s.
    pub fn test_groups(&self) -> Result<&'a [JsonValue], EnvelopeError> {
        self.root
            .get("testGroups")
            .ok_or(EnvelopeError::MissingField("testGroups"))?
            .as_array()
            .ok_or(EnvelopeError::WrongType {
                field: "testGroups",
                expected: "array",
            })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::json;

    #[test]
    fn peel_minimal_envelope() {
        let src = r#"{"algorithm":"SHA3-256","revision":"2.0","testGroups":[]}"#;
        let v = json::parse(src).unwrap();
        let vs = VectorSet::new(&v).unwrap();
        assert_eq!(vs.algorithm().unwrap(), "SHA3-256");
        assert_eq!(vs.revision().unwrap(), "2.0");
        assert!(vs.test_groups().unwrap().is_empty());
    }

    #[test]
    fn reject_non_object_root() {
        let v = json::parse("[]").unwrap();
        assert!(matches!(VectorSet::new(&v), Err(EnvelopeError::NotObject)));
    }

    #[test]
    fn missing_field_detected() {
        let v = json::parse(r#"{"algorithm":"x"}"#).unwrap();
        let vs = VectorSet::new(&v).unwrap();
        assert!(matches!(
            vs.revision(),
            Err(EnvelopeError::MissingField("revision"))
        ));
    }

    #[test]
    fn wrong_type_detected() {
        let v = json::parse(r#"{"algorithm":"x","revision":"1","testGroups":"oops"}"#).unwrap();
        let vs = VectorSet::new(&v).unwrap();
        assert!(matches!(
            vs.test_groups(),
            Err(EnvelopeError::WrongType {
                field: "testGroups",
                ..
            })
        ));
    }
}
