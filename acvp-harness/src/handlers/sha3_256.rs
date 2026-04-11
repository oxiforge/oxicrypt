//! SHA3-256 Algorithm Functional Test (AFT) handler.
//!
//! Targets ACVP `algorithm = "SHA3-256"`, `revision = "2.0"`. The
//! handler only implements `testType = "AFT"`; Monte Carlo Test (MCT)
//! and Large Data Test (LDT) support is deferred to later chunks.
//!
//! ACVP SHA3 AFT test cases have the shape:
//!
//! ```text
//! { "tcId": 87, "len": 8, "msg": "08", "md": "..." }
//! ```
//!
//! where `len` is the message length **in bits** and `msg` is the
//! hex-encoded message padded out to the nearest byte. pqclib's
//! `fips_sha::sha3` API is byte-oriented, so this handler only
//! supports byte-aligned `len` values and errors out otherwise — the
//! ACVP vector set vendored at commit
//! `3611942ea10c070dd8bc6afec5682d56c307de8a` uses byte-aligned
//! lengths exclusively for AFT, so this is not a functional gap.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// SHA3-256 AFT dispatcher.
pub struct Sha3_256Handler;

impl AlgorithmHandler for Sha3_256Handler {
    fn algorithm(&self) -> &'static str {
        "SHA3-256"
    }

    fn revision(&self) -> &'static str {
        "2.0"
    }

    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let tg_id = group
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
            results.push(run_case(t)?);
        }
        Ok(JsonValue::Object(vec![
            ("tgId".to_string(), JsonValue::Number(tg_id)),
            ("tests".to_string(), JsonValue::Array(results)),
        ]))
    }
}

fn run_case(t: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let len_bits = t
        .get("len")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("len"))?;
    if len_bits % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "SHA3-256 AFT with non-byte-aligned `len`",
        ));
    }
    let expected_bytes: usize = (len_bits / 8) as usize;
    let msg_hex = t
        .get("msg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("msg"))?;
    let msg = hex::decode(msg_hex)?;
    if msg.len() < expected_bytes {
        return Err(DispatchError::Crypto(
            "SHA3-256 AFT: hex `msg` shorter than declared `len`",
        ));
    }
    let used = msg
        .get(..expected_bytes)
        .ok_or(DispatchError::Crypto("SHA3-256 AFT: slicing failed"))?;
    let md = fips_sha::sha3::sha3_256(used)
        .map_err(|_| DispatchError::Crypto("fips_sha::sha3::sha3_256 returned Err"))?;
    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("md".to_string(), JsonValue::String(hex::encode_upper(&md))),
    ]))
}
