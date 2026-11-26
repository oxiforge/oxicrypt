//! CMAC-AES AFT handler (`CMAC-AES`, revision `1.0`).
//!
//! Two directions:
//!
//! - `gen`: compute CMAC over `message` under a key whose MAC length is
//!   the group-level `macLen`, and return that `mac`.
//! - `ver`: verify the supplied `mac` field with `cmac_verify` under a
//!   key whose MAC length is the group-level `macLen`, and return
//!   `testPassed`. The comparison runs over the key's fixed MAC length,
//!   so a `mac` of any other length fails.
//!
//! All three AES key sizes (128/192/256) are supported. `macLen` must be
//! a multiple of 8 in 64..=128 bits, the range `CmacKey` accepts
//! (SP 800-38B Appendix A); a group outside it is refused as
//! unsupported.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_aes::ModeError;
use oxicrypt_cmac::{CmacKey, cmac, cmac_verify};

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
            ));
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
    // SP 800-38B Appendix A: the module's CMAC keys take no MAC below
    // 64 bits, so a shorter `macLen` is refused, not truncated to.
    if !(64..=128).contains(&mac_len_bits) || mac_len_bits % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "CMAC: macLen must be 64..128 and byte-aligned",
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

        let resp = match direction {
            CmacDirection::Gen => {
                let k = cmac_key(key_len_bits, &key_bytes, mac_len_bytes)?;
                let mut tag = vec![0u8; mac_len_bytes];
                cmac(&k, &msg_bytes, &mut tag)
                    .map_err(|_e| DispatchError::Crypto("CMAC generation error"))?;
                JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "mac".to_string(),
                        JsonValue::String(hex::encode_upper(&tag)),
                    ),
                ])
            }
            CmacDirection::Ver => {
                let expected_hex = t
                    .get("mac")
                    .and_then(JsonValue::as_str)
                    .ok_or(DispatchError::MissingField("mac"))?;
                let expected_mac = hex::decode(expected_hex)?;
                let k = cmac_key(key_len_bits, &key_bytes, mac_len_bytes)?;
                let passed = match cmac_verify(&k, &msg_bytes, &expected_mac) {
                    Ok(()) => true,
                    Err(ModeError::TagMismatch | ModeError::InvalidTagLength) => false,
                    Err(_) => return Err(DispatchError::Crypto("CMAC verification error")),
                };
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

/// A CMAC key of the group's `keyLen` (bits) with a MAC length of
/// `mac_len` bytes.
fn cmac_key(key_len_bits: u64, key: &[u8], mac_len: usize) -> Result<CmacKey, DispatchError> {
    let (key_len, mismatch, failure) = match key_len_bits {
        128 => (
            16,
            "CMAC: key length mismatch for AES-128",
            "CMAC-128 error",
        ),
        192 => (
            24,
            "CMAC: key length mismatch for AES-192",
            "CMAC-192 error",
        ),
        256 => (
            32,
            "CMAC: key length mismatch for AES-256",
            "CMAC-256 error",
        ),
        _ => return Err(DispatchError::Crypto("CMAC: unsupported keyLen")),
    };
    if key.len() != key_len {
        return Err(DispatchError::Crypto(mismatch));
    }
    CmacKey::new(key, mac_len).map_err(|_e| DispatchError::Crypto(failure))
}
