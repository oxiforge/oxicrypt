//! RSA Signature Primitive handler — `signaturePrimitive` mode,
//! revision `2.0`.
//!
//! **SignaturePrimitive** (`RSA` / `signaturePrimitive` / `2.0`):
//! Given a per-test RSA private key and message representative,
//! compute `sig = msg^d mod n` (RSASP1 per RFC 8017 §5.2.1) and
//! return `testPassed` plus the signature on success.
//!
//! Failure cases (`testPassed = false`) have `msg ≥ n`.
//!
//! Supported configuration:
//! - `modulo = 2048`

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// RSA Signature Primitive dispatcher.
pub struct RsaSigPrimHandler;

impl AlgorithmHandler for RsaSigPrimHandler {
    fn algorithm(&self) -> &'static str {
        "RSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("signaturePrimitive")
    }
    fn revision(&self) -> &'static str {
        "2.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::rsa_sigprim_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigprim_group(group)
    }
}

// ── Constants ──────────────────────────────────────────────────────

const N_BYTES: usize = oxicrypt_rsa::RSA_2048_MODULUS_BYTES;
const HALF_BYTES: usize = oxicrypt_rsa::RSA_2048_CRT_HALF_BYTES;

// ── Helpers ────────────────────────────────────────────────────────

/// Decode a hex-encoded string field from a JSON object.
fn decode_hex_field(obj: &JsonValue, name: &'static str) -> Result<Vec<u8>, DispatchError> {
    let h = obj
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(name))?;
    Ok(hex::decode(h)?)
}

/// Parse a big-endian hex field into a fixed-size array, left-padding
/// with zeroes if the decoded value is shorter than `LEN`.
fn decode_fixed<const LEN: usize>(
    obj: &JsonValue,
    name: &'static str,
) -> Result<[u8; LEN], DispatchError> {
    let raw = decode_hex_field(obj, name)?;
    if raw.len() > LEN {
        return Err(DispatchError::Crypto("RSA SigPrim: field too large"));
    }
    let mut buf = [0u8; LEN];
    buf[LEN - raw.len()..].copy_from_slice(&raw);
    Ok(buf)
}

/// Convert big-endian bytes to `u64`.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, DispatchError> {
    if bytes.len() > 8 {
        return Err(DispatchError::Crypto(
            "RSA SigPrim: e exceeds 8 bytes (u64 range)",
        ));
    }
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    Ok(val)
}

// ── Group handler ──────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn handle_sigprim_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let modulo = group
        .get("modulo")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("modulo"))?;
    if modulo != 2048 {
        return Err(DispatchError::Unsupported(
            "RSA SigPrim: only modulo 2048 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for tc in tests {
        let test_case_id = tc
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let msg: [u8; N_BYTES] = decode_fixed(tc, "message")?;
        let n: [u8; N_BYTES] = decode_fixed(tc, "n")?;

        // Detect CRT vs non-CRT: if dmp1 is absent or empty, use d.
        let has_crt = tc
            .get("dmp1")
            .and_then(JsonValue::as_str)
            .is_some_and(|s| !s.is_empty());

        let result = if has_crt {
            let p: [u8; HALF_BYTES] = decode_fixed(tc, "p")?;
            let q: [u8; HALF_BYTES] = decode_fixed(tc, "q")?;
            let dp: [u8; HALF_BYTES] = decode_fixed(tc, "dmp1")?;
            let dq: [u8; HALF_BYTES] = decode_fixed(tc, "dmq1")?;
            let qinv: [u8; HALF_BYTES] = decode_fixed(tc, "iqmp")?;
            let e_bytes = decode_hex_field(tc, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            oxicrypt_rsa::rsa_signature_primitive_2048_crt_internal(
                &n, e, &p, &q, &dp, &dq, &qinv, &msg,
            )
        } else {
            let d: [u8; N_BYTES] = decode_fixed(tc, "d")?;
            oxicrypt_rsa::rsa_signature_primitive_2048_internal(&n, &d, &msg)
        };

        match result {
            Some(sig) => {
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("testPassed".to_string(), JsonValue::Bool(true)),
                    (
                        "signature".to_string(),
                        JsonValue::String(hex::encode_upper(&sig)),
                    ),
                ]));
            }
            None => {
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("testPassed".to_string(), JsonValue::Bool(false)),
                ]));
            }
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
