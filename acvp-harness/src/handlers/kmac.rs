//! KMAC-128 / KMAC-256 and KMACXOF-128 / KMACXOF-256 AFT + MVT handlers.
//!
//! Targets self-generated ACVP slices with `algorithm = "KMAC-128"`,
//! `"KMAC-256"`, `"KMACXOF-128"`, or `"KMACXOF-256"`, `revision = "1.0"`.
//!
//! Two test types are supported:
//!
//! - **AFT** (Algorithm Functional Test): compute the MAC and return it.
//! - **MVT** (MAC Verification Test): compute the MAC, compare against
//!   the supplied `mac` field, return `testPassed`.
//!
//! Each test group carries (group level):
//!
//! - `xof` (bool) — XOF variant flag (ACVP only; we dispatch by
//!   algorithm string, so this is informational here)
//! - `hexCustomization` (bool) — `true` if the per-test
//!   `customization` field is hex-encoded, `false` if it is an
//!   ASCII text string (taken byte-for-byte)
//!
//! Each test case carries:
//!
//! - `key` (hex) — KMAC key
//! - `keyLen` (bits) — key length
//! - `msg` (hex) — input message
//! - `msgLen` (bits) — message length
//! - `macLen` (bits) — requested tag length
//! - `customization` (string) — customization string S, encoding
//!   determined by the group-level `hexCustomization` flag
//! - `mac` (hex, MVT only) — expected MAC to verify against
//!
//! AFT response field: `mac` (hex).
//! MVT response field: `testPassed` (bool).
//!
//! The XOF variants use the squeeze pattern (`finalize()` + `squeeze()`)
//! rather than `finalize_into()`, producing extendable output.
//!
//! Since the NIST ACVP-Server at the pinned commit ships no KMAC
//! vector directories, all vectors are self-generated.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_xof::{Kmac128, Kmac256, KmacXof128, KmacXof256};

/// KMAC-128 AFT handler.
pub struct Kmac128Handler;

/// KMAC-256 AFT handler.
pub struct Kmac256Handler;

impl AlgorithmHandler for Kmac128Handler {
    fn algorithm(&self) -> &'static str {
        "KMAC-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kmac_capability("KMAC-128", false))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kmac_group(group, |key, msg, s, out| {
            let mut m = Kmac128::new(key, s)
                .map_err(|_| DispatchError::Crypto("Kmac128::new returned Err"))?;
            m.update(msg);
            m.finalize_into(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for Kmac256Handler {
    fn algorithm(&self) -> &'static str {
        "KMAC-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kmac_capability("KMAC-256", false))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kmac_group(group, |key, msg, s, out| {
            let mut m = Kmac256::new(key, s)
                .map_err(|_| DispatchError::Crypto("Kmac256::new returned Err"))?;
            m.update(msg);
            m.finalize_into(out);
            Ok(())
        })
    }
}

/// KMACXOF-128 AFT handler.
pub struct KmacXof128Handler;

/// KMACXOF-256 AFT handler.
pub struct KmacXof256Handler;

impl AlgorithmHandler for KmacXof128Handler {
    fn algorithm(&self) -> &'static str {
        "KMACXOF-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kmac_capability("KMACXOF-128", true))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kmac_group(group, |key, msg, s, out| {
            let mut m = KmacXof128::new(key, s)
                .map_err(|_| DispatchError::Crypto("KmacXof128::new returned Err"))?;
            m.update(msg);
            m.finalize();
            m.squeeze(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for KmacXof256Handler {
    fn algorithm(&self) -> &'static str {
        "KMACXOF-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kmac_capability("KMACXOF-256", true))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kmac_group(group, |key, msg, s, out| {
            let mut m = KmacXof256::new(key, s)
                .map_err(|_| DispatchError::Crypto("KmacXof256::new returned Err"))?;
            m.update(msg);
            m.finalize();
            m.squeeze(out);
            Ok(())
        })
    }
}

/// Whether the group is AFT (compute) or MVT (verify).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KmacTestType {
    Aft,
    Mvt,
}

/// Parsed inputs from one KMAC test case.
struct KmacTestInputs {
    key: Vec<u8>,
    msg: Vec<u8>,
    s: Vec<u8>,
    mac_bytes: usize,
}

/// Parse key, msg, customization string, and mac length from a test case.
/// `hex_customization` comes from the group-level `hexCustomization`
/// flag and determines whether the test's `customization` field is
/// hex-decoded (true) or taken as ASCII bytes (false).
fn parse_kmac_test(
    t: &JsonValue,
    hex_customization: bool,
) -> Result<KmacTestInputs, DispatchError> {
    let key_len_bits = t
        .get("keyLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("keyLen"))?;
    let msg_len_bits = t
        .get("msgLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("msgLen"))?;
    let mac_len_bits = t
        .get("macLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("macLen"))?;
    if !key_len_bits.is_multiple_of(8)
        || !msg_len_bits.is_multiple_of(8)
        || !mac_len_bits.is_multiple_of(8)
    {
        return Err(DispatchError::Unsupported(
            "KMAC with non-byte-aligned lengths",
        ));
    }
    let key_bytes = (key_len_bits / 8) as usize;
    let msg_bytes = (msg_len_bits / 8) as usize;
    let mac_bytes = (mac_len_bits / 8) as usize;

    let key_hex = t
        .get("key")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("key"))?;
    let key_full = hex::decode(key_hex)?;
    if key_full.len() < key_bytes {
        return Err(DispatchError::Crypto(
            "KMAC: hex `key` shorter than declared `keyLen`",
        ));
    }
    let key = key_full[..key_bytes].to_vec();

    let msg_hex = t
        .get("msg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("msg"))?;
    let msg_full = if msg_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(msg_hex)?
    };
    if msg_full.len() < msg_bytes {
        return Err(DispatchError::Crypto(
            "KMAC: hex `msg` shorter than declared `msgLen`",
        ));
    }
    let msg = if msg_bytes == 0 {
        Vec::new()
    } else {
        msg_full[..msg_bytes].to_vec()
    };

    // `customization` is the per-test S string. Encoding is governed
    // by the group-level `hexCustomization` boolean — `true` means
    // the field is hex; `false` means it is ASCII text taken
    // byte-for-byte (per ACVP SP 800-185 KMAC capability spec).
    // Treat a missing field as the empty customization (S = "").
    let s_field = t.get("customization").and_then(JsonValue::as_str);
    let s = match s_field {
        None | Some("") => Vec::new(),
        Some(raw) if hex_customization => hex::decode(raw)?,
        Some(raw) => raw.as_bytes().to_vec(),
    };

    Ok(KmacTestInputs {
        key,
        msg,
        s,
        mac_bytes,
    })
}

/// Shared group driver for KMAC AFT and MVT.
fn handle_kmac_group<F>(group: &JsonValue, mut compute: F) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &[u8], &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let group_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
    let test_type = match group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?
    {
        "AFT" => KmacTestType::Aft,
        "MVT" => KmacTestType::Mvt,
        other => return Err(DispatchError::UnsupportedTestType(other.to_string())),
    };
    // Group-level encoding flag for the per-test `customization`
    // field. ACVP places this at the group, not the test, because
    // every test in a group shares the encoding. Default to `false`
    // (ASCII) when the field is absent so older offline fixtures
    // without an explicit value still parse.
    let hex_customization = group
        .get("hexCustomization")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
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
        let inp = parse_kmac_test(t, hex_customization)?;

        let mut out_buf = vec![0u8; inp.mac_bytes];
        compute(&inp.key, &inp.msg, &inp.s, &mut out_buf)?;

        let resp = match test_type {
            KmacTestType::Aft => JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(tc_id)),
                (
                    "mac".to_string(),
                    JsonValue::String(hex::encode_upper(&out_buf)),
                ),
            ]),
            KmacTestType::Mvt => {
                let expected_hex = t
                    .get("mac")
                    .and_then(JsonValue::as_str)
                    .ok_or(DispatchError::MissingField("mac"))?;
                let expected_mac = hex::decode(expected_hex)?;
                // Constant-comparison isn't required here — ACVP test
                // vectors are public. Just compare computed tags.
                let passed = out_buf.as_slice() == expected_mac.as_slice();
                JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    ("testPassed".to_string(), JsonValue::Bool(passed)),
                ])
            }
        };
        results.push(resp);
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
