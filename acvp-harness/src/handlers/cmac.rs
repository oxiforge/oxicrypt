//! CMAC-AES AFT handler (`CMAC-AES`, revision `1.0`).
//!
//! Two directions:
//!
//! - `gen`: compute CMAC over `message` with `key`, return truncated
//!   `mac` at group-level `macLen`.
//! - `ver`: compute CMAC, compare the first `macLen` bits against the
//!   supplied `mac` field, and return `testPassed`.
//!
//! All three AES key sizes (128/192/256) are supported. The handler
//! always computes the full 128-bit CMAC tag and truncates to the
//! group-declared `macLen` (bits) for both generation and
//! verification.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_cmac::{cmac_aes128, cmac_aes192, cmac_aes256};

/// CMAC-AES AFT dispatcher.
pub struct CmacAesHandler;

impl AlgorithmHandler for CmacAesHandler {
    fn algorithm(&self) -> &'static str {
        "CMAC-AES"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::cmac_aes_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_cmac_group(group)
    }
}

/// Direction for CMAC test groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmacDirection {
    Gen,
    Ver,
}

fn handle_cmac_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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
    let direction = match group
        .get("direction")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("direction"))?
    {
        "gen" => CmacDirection::Gen,
        "ver" => CmacDirection::Ver,
        other => {
            return Err(DispatchError::Unsupported(
                if other == "encrypt" || other == "decrypt" {
                    "CMAC direction must be gen/ver, not encrypt/decrypt"
                } else {
                    "CMAC: unknown direction"
                },
            ))
        }
    };
    let key_len_bits = group
        .get("keyLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("keyLen"))?;
    let mac_len_bits = group
        .get("macLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("macLen"))?;
    if mac_len_bits == 0 || mac_len_bits > 128 || mac_len_bits % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "CMAC: macLen must be 8..128 and byte-aligned",
        ));
    }
    let mac_len_bytes = (mac_len_bits / 8) as usize;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let key_hex = t
            .get("key")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("key"))?;
        let key_bytes = hex::decode(key_hex)?;
        let msg_hex = t
            .get("message")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("message"))?;
        let msg_bytes = hex::decode(msg_hex)?;

        let full_tag = compute_cmac(key_len_bits, &key_bytes, &msg_bytes)?;
        let truncated = &full_tag[..mac_len_bytes];

        let resp = match direction {
            CmacDirection::Gen => JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(test_case_id)),
                (
                    "mac".to_string(),
                    JsonValue::String(hex::encode_upper(truncated)),
                ),
            ]),
            CmacDirection::Ver => {
                let expected_hex = t
                    .get("mac")
                    .and_then(JsonValue::as_str)
                    .ok_or(DispatchError::MissingField("mac"))?;
                let expected_mac = hex::decode(expected_hex)?;
                // Constant-comparison isn't required here — ACVP test
                // vectors are public. Just compare truncated tags.
                let passed = truncated == expected_mac.as_slice();
                JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("testPassed".to_string(), JsonValue::Bool(passed)),
                ])
            }
        };
        results.push(resp);
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

/// Compute a full 128-bit CMAC tag over `msg` using the appropriate
/// AES key size.
fn compute_cmac(
    key_len_bits: u64,
    key: &[u8],
    msg: &[u8],
) -> Result<[u8; 16], DispatchError> {
    match key_len_bits {
        128 => {
            let k: [u8; 16] = key
                .try_into()
                .map_err(|_| DispatchError::Crypto("CMAC: key length mismatch for AES-128"))?;
            cmac_aes128(&k, msg).map_err(|_e| DispatchError::Crypto("CMAC-128 error"))
        }
        192 => {
            let k: [u8; 24] = key
                .try_into()
                .map_err(|_| DispatchError::Crypto("CMAC: key length mismatch for AES-192"))?;
            cmac_aes192(&k, msg).map_err(|_e| DispatchError::Crypto("CMAC-192 error"))
        }
        256 => {
            let k: [u8; 32] = key
                .try_into()
                .map_err(|_| DispatchError::Crypto("CMAC: key length mismatch for AES-256"))?;
            cmac_aes256(&k, msg).map_err(|_e| DispatchError::Crypto("CMAC-256 error"))
        }
        _ => Err(DispatchError::Crypto("CMAC: unsupported keyLen")),
    }
}
