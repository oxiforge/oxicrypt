//! HMAC-SHA2-256 AFT and MVT handler.
//!
//! Targets ACVP `algorithm = "HMAC-SHA2-256"`, `revision = "1.0"`.
//!
//! **AFT** (`testType = "AFT"`): ACVP HMAC test groups carry a `macLen`
//! in bits that tells us how many leading bytes of the HMAC output to
//! emit; the full 32-byte HMAC-SHA-256 tag is computed and then truncated.
//!
//! **MVT** (`testType = "MVT"`): each test case carries the same fields
//! as AFT plus a hex-encoded `mac` expected value. The handler computes
//! the HMAC, compares against the expected value, and returns a
//! `testPassed` boolean.
//!
//! A single ACVP HMAC AFT test case looks like:
//!
//! ```text
//! {
//!   "tcId":   751,
//!   "keyLen": 8,
//!   "msgLen": 128,
//!   "macLen": 80,
//!   "key":    "08",
//!   "msg":    "5F270F27C5D85262DE682546051AB767",
//!   "mac":    "B260E4E94E3E79EC2A45"
//! }
//! ```
//!
//! The `keyLen` and `msgLen` fields are informational — the `key` and
//! `msg` hex blobs are already the right length — so this handler only
//! needs to read `macLen`, `key`, and `msg`.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_hmac::HmacSha256;

/// HMAC-SHA2-256 AFT / MVT dispatcher.
pub struct HmacSha2_256Handler;

/// HMAC-SHA-256 output length in bytes.
const HMAC_SHA256_OUT: usize = 32;

/// Test type — AFT (compute and return) or MVT (verify).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestType {
    Aft,
    Mvt,
}

impl AlgorithmHandler for HmacSha2_256Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA2-256"
    }

    fn revision(&self) -> &'static str {
        "1.0"
    }

    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let tg_id = group
            .get("tgId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tgId"))?;
        let test_type_str = group
            .get("testType")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("testType"))?;
        let test_type = match test_type_str {
            "AFT" => TestType::Aft,
            "MVT" => TestType::Mvt,
            other => return Err(DispatchError::UnsupportedTestType(other.to_string())),
        };
        let tests = group
            .get("tests")
            .and_then(JsonValue::as_array)
            .ok_or(DispatchError::MissingField("tests"))?;
        let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
        for t in tests {
            results.push(run_case(t, test_type)?);
        }
        Ok(JsonValue::Object(vec![
            ("tgId".to_string(), JsonValue::Number(tg_id)),
            ("tests".to_string(), JsonValue::Array(results)),
        ]))
    }
}

fn run_case(t: &JsonValue, test_type: TestType) -> Result<JsonValue, DispatchError> {
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let mac_len_bits = t
        .get("macLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("macLen"))?;
    if mac_len_bits % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "HMAC-SHA2-256 with non-byte-aligned `macLen`",
        ));
    }
    let mac_len_bytes: usize = (mac_len_bits / 8) as usize;
    if mac_len_bytes == 0 || mac_len_bytes > HMAC_SHA256_OUT {
        return Err(DispatchError::Crypto(
            "HMAC-SHA2-256: `macLen` outside [1, 32] bytes",
        ));
    }
    let key_hex = t
        .get("key")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("key"))?;
    let msg_hex = t
        .get("msg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("msg"))?;
    let key = hex::decode(key_hex)?;
    let msg = hex::decode(msg_hex)?;
    let mut h = HmacSha256::new(&key)
        .map_err(|_| DispatchError::Crypto("HmacSha256::new returned Err"))?;
    h.update(&msg);
    let full = h.finalize();
    let truncated = full
        .get(..mac_len_bytes)
        .ok_or(DispatchError::Crypto("HMAC-SHA2-256: truncate failed"))?;
    match test_type {
        TestType::Aft => Ok(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "mac".to_string(),
                JsonValue::String(hex::encode_upper(truncated)),
            ),
        ])),
        TestType::Mvt => {
            let expected_hex = t
                .get("mac")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("mac"))?;
            let expected_mac = hex::decode(expected_hex)?;
            let passed = truncated == expected_mac.as_slice();
            Ok(JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(tc_id)),
                ("testPassed".to_string(), JsonValue::Bool(passed)),
            ]))
        }
    }
}
