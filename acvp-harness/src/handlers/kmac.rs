//! KMAC-128 / KMAC-256 and KMACXOF-128 / KMACXOF-256 AFT handlers.
//!
//! Targets self-generated ACVP slices with `algorithm = "KMAC-128"`,
//! `"KMAC-256"`, `"KMACXOF-128"`, or `"KMACXOF-256"`, `revision = "1.0"`,
//! `testType = "AFT"`.
//!
//! Each test case carries:
//!
//! - `key` (hex) — KMAC key
//! - `keyLen` (bits) — key length
//! - `msg` (hex) — input message
//! - `msgLen` (bits) — message length
//! - `macLen` (bits) — requested tag length
//! - `hexCustomization` (hex) — customization string S
//!
//! Response field: `mac` (hex).
//!
//! The XOF variants use the squeeze pattern (`finalize()` + `squeeze()`)
//! rather than `finalize_into()`, producing extendable output.
//!
//! Since the NIST ACVP-Server at the pinned commit ships no KMAC
//! vector directories, all vectors are self-generated.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_xof::{Kmac128, Kmac256, KmacXof128, KmacXof256};

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

/// Shared group driver for KMAC AFT.
fn handle_kmac_group<F>(
    group: &JsonValue,
    mut compute: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &[u8], &[u8], &mut [u8]) -> Result<(), DispatchError>,
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
                "KMAC AFT with non-byte-aligned lengths",
            ));
        }
        let key_bytes = (key_len_bits / 8) as usize;
        let msg_bytes = (msg_len_bits / 8) as usize;
        let mac_bytes = (mac_len_bits / 8) as usize;

        let key_hex = t
            .get("key")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("key"))?;
        let key = hex::decode(key_hex)?;
        if key.len() < key_bytes {
            return Err(DispatchError::Crypto(
                "KMAC AFT: hex `key` shorter than declared `keyLen`",
            ));
        }
        let key_used = &key[..key_bytes];

        let msg_hex = t
            .get("msg")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("msg"))?;
        let msg = if msg_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(msg_hex)?
        };
        if msg.len() < msg_bytes {
            return Err(DispatchError::Crypto(
                "KMAC AFT: hex `msg` shorter than declared `msgLen`",
            ));
        }
        let msg_used = if msg_bytes == 0 { &[] as &[u8] } else { &msg[..msg_bytes] };

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

        let mut out_buf = vec![0u8; mac_bytes];
        compute(key_used, msg_used, &s, &mut out_buf)?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "mac".to_string(),
                JsonValue::String(hex::encode_upper(&out_buf)),
            ),
        ]));
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
