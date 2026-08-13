//! Shared helpers for the SP 800-185 XOF family handlers (cSHAKE,
//! KMAC, TupleHash, ParallelHash).
//!
//! Currently exposes one helper:
//!
//! - [`read_customization_field`] — reads the per-test customization
//!   string `S` from whichever JSON field the group-level
//!   `hexCustomization` boolean declares (`customizationHex` when
//!   true, `customization` when false), per `draft-celi-acvp-xof`
//!   §8.2 Table 6.
//!
//! The server emits the customization in different fields by mode:
//! `customization` when `hexCustomization: false`, `customizationHex`
//! when it is true. Reading only `customization` substitutes
//! `S = ""` for every `hexCustomization: true` test, which fails the
//! whole group on digest mismatch rather than on anything local.

use crate::dispatch::DispatchError;
use crate::hex;
use crate::json::JsonValue;

/// Read the per-test customization string `S` from the JSON field
/// declared by the group-level `hex_customization` flag:
///
/// - `hex_customization == true` → read `customizationHex`, decode
///   as hex.
/// - `hex_customization == false` → read `customization`, treat as
///   ASCII bytes.
///
/// A missing or empty field yields the empty customization
/// (`S = ""`), matching the spec's default semantics and the offline
/// fixtures.
pub fn read_customization_field(
    t: &JsonValue,
    hex_customization: bool,
) -> Result<Vec<u8>, DispatchError> {
    if hex_customization {
        match t.get("customizationHex").and_then(JsonValue::as_str) {
            None | Some("") => Ok(Vec::new()),
            Some(raw) => hex::decode(raw).map_err(Into::into),
        }
    } else {
        match t.get("customization").and_then(JsonValue::as_str) {
            None | Some("") => Ok(Vec::new()),
            Some(raw) => Ok(raw.as_bytes().to_vec()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
        JsonValue::Object(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn ascii_mode_reads_customization_field_as_bytes() {
        let t = obj(&[
            ("customization", JsonValue::String("hello".to_string())),
            (
                "customizationHex",
                JsonValue::String("DEADBEEF".to_string()),
            ),
        ]);
        let s = read_customization_field(&t, false).unwrap();
        assert_eq!(s, b"hello");
    }

    #[test]
    fn hex_mode_reads_customization_hex_field_decoded() {
        let t = obj(&[
            (
                "customization",
                JsonValue::String("ignored-ascii".to_string()),
            ),
            (
                "customizationHex",
                JsonValue::String("DEADBEEF".to_string()),
            ),
        ]);
        let s = read_customization_field(&t, true).unwrap();
        assert_eq!(s, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn ascii_mode_missing_field_yields_empty() {
        let t = obj(&[]);
        let s = read_customization_field(&t, false).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn hex_mode_missing_field_yields_empty() {
        let t = obj(&[]);
        let s = read_customization_field(&t, true).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn ascii_mode_empty_string_yields_empty() {
        let t = obj(&[("customization", JsonValue::String(String::new()))]);
        let s = read_customization_field(&t, false).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn hex_mode_empty_string_yields_empty() {
        let t = obj(&[("customizationHex", JsonValue::String(String::new()))]);
        let s = read_customization_field(&t, true).unwrap();
        assert!(s.is_empty());
    }
}
