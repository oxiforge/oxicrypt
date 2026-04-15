//! TupleHash-128 / TupleHash-256 and TupleHashXOF-128 / TupleHashXOF-256 AFT handlers.
//!
//! Targets self-generated ACVP slices with `algorithm = "TupleHash-128"`,
//! `"TupleHash-256"`, `"TupleHashXOF-128"`, or `"TupleHashXOF-256"`,
//! `revision = "1.0"`, `testType = "AFT"`.
//!
//! Each test case carries:
//!
//! - `tuple` (array of hex strings) — input tuple elements
//! - `outLen` (bits) — requested output length
//! - `hexCustomization` (hex) — customization string S
//!
//! Response field: `md` (hex).
//!
//! The XOF variants use the squeeze pattern (`finalize()` + `squeeze()`)
//! rather than `finalize_into()`, producing extendable output.
//!
//! Since the NIST ACVP-Server at the pinned commit ships no TupleHash
//! vector directories, all vectors are self-generated.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_xof::{TupleHash128, TupleHash256, TupleHashXof128, TupleHashXof256};

/// TupleHash-128 AFT handler.
pub struct TupleHash128Handler;

/// TupleHash-256 AFT handler.
pub struct TupleHash256Handler;

impl AlgorithmHandler for TupleHash128Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHash-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tuplehash_capability("TupleHash-128", false))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_tuplehash_group(group, |elements: &[Vec<u8>], s: &[u8], out: &mut [u8]| {
            let mut h = TupleHash128::new(s)
                .map_err(|_| DispatchError::Crypto("TupleHash128::new returned Err"))?;
            for elem in elements {
                h.update(elem);
            }
            h.finalize_into(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for TupleHash256Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHash-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tuplehash_capability("TupleHash-256", false))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_tuplehash_group(group, |elements: &[Vec<u8>], s: &[u8], out: &mut [u8]| {
            let mut h = TupleHash256::new(s)
                .map_err(|_| DispatchError::Crypto("TupleHash256::new returned Err"))?;
            for elem in elements {
                h.update(elem);
            }
            h.finalize_into(out);
            Ok(())
        })
    }
}

/// TupleHashXOF-128 AFT handler.
pub struct TupleHashXof128Handler;

/// TupleHashXOF-256 AFT handler.
pub struct TupleHashXof256Handler;

impl AlgorithmHandler for TupleHashXof128Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHashXOF-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tuplehash_capability("TupleHashXOF-128", true))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_tuplehash_group(group, |elements: &[Vec<u8>], s: &[u8], out: &mut [u8]| {
            let mut h = TupleHashXof128::new(s)
                .map_err(|_| DispatchError::Crypto("TupleHashXof128::new returned Err"))?;
            for elem in elements {
                h.update(elem);
            }
            h.finalize();
            h.squeeze(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for TupleHashXof256Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHashXOF-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tuplehash_capability("TupleHashXOF-256", true))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_tuplehash_group(group, |elements: &[Vec<u8>], s: &[u8], out: &mut [u8]| {
            let mut h = TupleHashXof256::new(s)
                .map_err(|_| DispatchError::Crypto("TupleHashXof256::new returned Err"))?;
            for elem in elements {
                h.update(elem);
            }
            h.finalize();
            h.squeeze(out);
            Ok(())
        })
    }
}

/// Shared group driver for TupleHash AFT.
fn handle_tuplehash_group<F>(group: &JsonValue, mut compute: F) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[Vec<u8>], &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let group_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "AFT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let tc_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let out_len_bits = t
            .get("outLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("outLen"))?;
        if !out_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "TupleHash AFT with non-byte-aligned `outLen`",
            ));
        }
        let out_bytes = (out_len_bits / 8) as usize;

        // Parse tuple elements: array of hex strings.
        let tuple_arr = t
            .get("tuple")
            .and_then(JsonValue::as_array)
            .ok_or(DispatchError::MissingField("tuple"))?;
        let mut elements: Vec<Vec<u8>> = Vec::with_capacity(tuple_arr.len());
        for elem_val in tuple_arr {
            let elem_hex = elem_val.as_str().ok_or(DispatchError::Crypto(
                "TupleHash AFT: tuple element is not a string",
            ))?;
            if elem_hex.is_empty() {
                elements.push(Vec::new());
            } else {
                elements.push(hex::decode(elem_hex)?);
            }
        }

        // Customization string S (hex-encoded).
        let s_hex = t
            .get("hexCustomization")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let s = if s_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(s_hex)?
        };

        let mut out_buf = vec![0u8; out_bytes];
        compute(&elements, &s, &mut out_buf)?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "md".to_string(),
                JsonValue::String(hex::encode_upper(&out_buf)),
            ),
        ]));
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
