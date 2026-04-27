//! HMAC-SHA2-256 AFT and MVT handler.
//!
//! Targets ACVP `algorithm = "HMAC-SHA2-256"`, `revision = "1.0"`.
//!
//! **AFT** (`testType = "AFT"`): ACVP HMAC test groups carry a `macLen`
//! in bits that tells us how many leading bytes of the HMAC output to
//! emit; the full 32-byte HMAC-SHA-256 tag is computed and then truncated.
//! The live ACVTS demo server places `macLen` on the test group; the
//! offline ACVP-server fixtures place it per-test. This handler accepts
//! either: per-test `macLen` takes precedence, with the group value as
//! fallback.
//!
//! **MVT** (`testType = "MVT"`): each test case carries the same fields
//! as AFT plus a hex-encoded `mac` expected value, and a `macLen` that
//! varies per-test (different MAC truncation lengths within one group).
//! The handler computes the HMAC, compares against the expected value,
//! and returns a `testPassed` boolean.
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

    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA2-256", 256))
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
        // ACVP places `macLen` either on the testGroup (live demo
        // server, AFT) or on each test case (offline ACVP-server
        // fixtures, especially MVT where macLen varies per test).
        // Read group-level as an optional fallback; `run_case`
        // prefers the per-test value.
        let group_mac_len_bits: Option<u64> = group.get("macLen").and_then(JsonValue::as_u64);
        let tests = group
            .get("tests")
            .and_then(JsonValue::as_array)
            .ok_or(DispatchError::MissingField("tests"))?;
        let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
        for t in tests {
            results.push(run_case(t, test_type, group_mac_len_bits)?);
        }
        Ok(JsonValue::Object(vec![
            ("tgId".to_string(), JsonValue::Number(tg_id)),
            ("tests".to_string(), JsonValue::Array(results)),
        ]))
    }
}

fn run_case(
    t: &JsonValue,
    test_type: TestType,
    group_mac_len_bits: Option<u64>,
) -> Result<JsonValue, DispatchError> {
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    // Per-test `macLen` takes precedence; group-level is the fallback
    // for the live-server AFT shape (one macLen for the whole group).
    let mac_len_bits = t
        .get("macLen")
        .and_then(JsonValue::as_u64)
        .or(group_mac_len_bits)
        .ok_or(DispatchError::MissingField("macLen"))?;
    if !mac_len_bits.is_multiple_of(8) {
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
    let mut h =
        HmacSha256::new(&key).map_err(|_| DispatchError::Crypto("HmacSha256::new returned Err"))?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::json;

    /// AFT shape from the live ACVTS demo server: `macLen` on the
    /// test group, no per-test `macLen`. Live demo prompt 2026-04-26
    /// confirmed this for HMAC-SHA2-256.
    #[test]
    fn handle_group_reads_mac_len_from_group_for_aft() {
        let group = json::parse(
            r#"{
                "tgId": 1,
                "testType": "AFT",
                "macLen": 256,
                "tests": [
                    {"tcId": 1, "key": "00", "msg": "00"}
                ]
            }"#,
        )
        .unwrap();
        let h = HmacSha2_256Handler;
        let result = h.handle_group(&group);
        assert!(
            result.is_ok(),
            "expected Ok (live AFT shape), got {:?}",
            result.err()
        );
    }

    /// MVT shape from the offline ACVP-server fixtures
    /// (`vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-256-1.0/mvt-slice.json`):
    /// `macLen` per-test-case with values varying across tests in
    /// one group.
    #[test]
    fn handle_group_reads_mac_len_per_test_for_mvt() {
        let group = json::parse(
            r#"{
                "tgId": 1,
                "testType": "MVT",
                "tests": [
                    {"tcId": 1, "macLen": 256, "key": "00", "msg": "00", "mac": "0000000000000000000000000000000000000000000000000000000000000000"},
                    {"tcId": 2, "macLen": 128, "key": "00", "msg": "00", "mac": "00000000000000000000000000000000"}
                ]
            }"#,
        )
        .unwrap();
        let h = HmacSha2_256Handler;
        let result = h.handle_group(&group);
        assert!(
            result.is_ok(),
            "expected Ok (offline MVT shape), got {:?}",
            result.err()
        );
    }

    /// Per-test `macLen` overrides group-level `macLen`.
    #[test]
    fn per_test_mac_len_overrides_group() {
        let group = json::parse(
            r#"{
                "tgId": 1,
                "testType": "AFT",
                "macLen": 256,
                "tests": [
                    {"tcId": 1, "key": "00", "msg": "00"},
                    {"tcId": 2, "macLen": 128, "key": "00", "msg": "00"}
                ]
            }"#,
        )
        .unwrap();
        let h = HmacSha2_256Handler;
        let result = h.handle_group(&group);
        assert!(
            result.is_ok(),
            "expected Ok (mixed override), got {:?}",
            result.err()
        );
    }

    /// Neither group nor per-test `macLen` → MissingField.
    #[test]
    fn missing_mac_len_errors() {
        let group = json::parse(
            r#"{
                "tgId": 1,
                "testType": "AFT",
                "tests": [
                    {"tcId": 1, "key": "00", "msg": "00"}
                ]
            }"#,
        )
        .unwrap();
        let h = HmacSha2_256Handler;
        let result = h.handle_group(&group);
        match result {
            Err(DispatchError::MissingField(name)) => assert_eq!(name, "macLen"),
            Ok(v) => panic!("expected MissingField(macLen), got Ok({v:?})"),
            Err(other) => panic!("expected MissingField(macLen), got {other:?}"),
        }
    }
}
