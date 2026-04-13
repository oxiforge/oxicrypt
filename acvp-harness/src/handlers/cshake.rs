//! cSHAKE-128 / cSHAKE-256 AFT handlers.
//!
//! Targets self-generated ACVP slices with `algorithm = "cSHAKE-128"` or
//! `"cSHAKE-256"`, `revision = "1.0"`, `testType = "AFT"`.
//!
//! Each test case carries:
//!
//! - `msg` (hex) — input message
//! - `len` (bits) — message length
//! - `outLen` (bits) — requested output length
//! - `hexCustomization` (hex) — customization string S
//!
//! The function name N is always empty (the ACVP cSHAKE registration
//! does not exercise non-empty N). Response field: `md` (hex).
//!
//! Since the NIST ACVP-Server at the pinned commit ships no cSHAKE
//! vector directories, all vectors are self-generated and live in
//! `vendor/nist/acvp-server/gen-val/json-files/cSHAKE-{128,256}-1.0/`.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_xof::{CShake128, CShake256};

/// cSHAKE-128 AFT handler.
pub struct CShake128Handler;

/// cSHAKE-256 AFT handler.
pub struct CShake256Handler;

impl AlgorithmHandler for CShake128Handler {
    fn algorithm(&self) -> &'static str {
        "cSHAKE-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_cshake_group(group, |msg, s, out| {
            let mut x = CShake128::new(b"", s)
                .map_err(|_| DispatchError::Crypto("CShake128::new returned Err"))?;
            x.update(msg);
            x.finalize();
            x.squeeze(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for CShake256Handler {
    fn algorithm(&self) -> &'static str {
        "cSHAKE-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_cshake_group(group, |msg, s, out| {
            let mut x = CShake256::new(b"", s)
                .map_err(|_| DispatchError::Crypto("CShake256::new returned Err"))?;
            x.update(msg);
            x.finalize();
            x.squeeze(out);
            Ok(())
        })
    }
}

/// Shared group driver for cSHAKE AFT.
fn handle_cshake_group<F>(
    group: &JsonValue,
    mut squeeze: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &[u8], &mut [u8]) -> Result<(), DispatchError>,
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
        let len_bits = t
            .get("len")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("len"))?;
        let out_len_bits = t
            .get("outLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("outLen"))?;
        if !len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "cSHAKE AFT with non-byte-aligned `len`",
            ));
        }
        if !out_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "cSHAKE AFT with non-byte-aligned `outLen`",
            ));
        }
        let msg_bytes = (len_bits / 8) as usize;
        let out_bytes = (out_len_bits / 8) as usize;
        let msg_hex = t
            .get("msg")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("msg"))?;
        let msg = hex::decode(msg_hex)?;
        if msg.len() < msg_bytes {
            return Err(DispatchError::Crypto(
                "cSHAKE AFT: hex `msg` shorter than declared `len`",
            ));
        }
        let used = &msg[..msg_bytes];

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
        squeeze(used, &s, &mut out_buf)?;
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
