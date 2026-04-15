//! RSA Decryption Primitive handler — `decryptionPrimitive` mode,
//! revision `Sp800-56Br2`.
//!
//! **DecryptionPrimitive** (`RSA` / `decryptionPrimitive` /
//! `Sp800-56Br2`): Given a per-test RSA private key and ciphertext,
//! compute `pt = ct^d mod n` (the raw RSADP) and return `testPassed`
//! plus the plaintext on success.
//!
//! Each test carries the full private key — `(n, e, d, p, q, dmp1,
//! dmq1, iqmp)` — regardless of `keyMode`. The handler always uses
//! the CRT path (with Bellcore verify-after-decrypt per IG D.G) when
//! `keyMode = "crt"`, and the non-CRT path when `keyMode = "standard"`.
//!
//! Failure cases (`testPassed = false`) are `ct ≥ n`, where the
//! primitive correctly rejects the input. The handler returns
//! `testPassed: false` with no `pt` field for these.
//!
//! Supported configuration:
//! - `modulo = 2048`

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// RSA DecryptionPrimitive dispatcher.
pub struct RsaDecPrimHandler;

impl AlgorithmHandler for RsaDecPrimHandler {
    fn algorithm(&self) -> &'static str {
        "RSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("decryptionPrimitive")
    }
    fn revision(&self) -> &'static str {
        "Sp800-56Br2"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::rsa_decprim_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_decprim_group(group)
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
        return Err(DispatchError::Crypto("RSA DecPrim: field too large"));
    }
    let mut buf = [0u8; LEN];
    buf[LEN - raw.len()..].copy_from_slice(&raw);
    Ok(buf)
}

// ── Group handler ──────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn handle_decprim_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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
            "RSA DecPrim: only modulo 2048 is supported",
        ));
    }

    let key_mode = group
        .get("keyMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("keyMode"))?;

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

        let ct: [u8; N_BYTES] = decode_fixed(tc, "ct")?;

        let result = if key_mode == "crt" {
            let n: [u8; N_BYTES] = decode_fixed(tc, "n")?;
            let p: [u8; HALF_BYTES] = decode_fixed(tc, "p")?;
            let q: [u8; HALF_BYTES] = decode_fixed(tc, "q")?;
            let dp: [u8; HALF_BYTES] = decode_fixed(tc, "dmp1")?;
            let dq: [u8; HALF_BYTES] = decode_fixed(tc, "dmq1")?;
            let qinv: [u8; HALF_BYTES] = decode_fixed(tc, "iqmp")?;

            // Parse e from hex.
            let e_bytes = decode_hex_field(tc, "e")?;
            let e = bytes_to_u64(&e_bytes)?;

            oxicrypt_rsa::rsa_decryption_primitive_2048_crt_internal(
                &n, e, &p, &q, &dp, &dq, &qinv, &ct,
            )
        } else {
            let n: [u8; N_BYTES] = decode_fixed(tc, "n")?;
            let d: [u8; N_BYTES] = decode_fixed(tc, "d")?;

            oxicrypt_rsa::rsa_decryption_primitive_2048_internal(&n, &d, &ct)
        };

        match result {
            Some(pt) => {
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("testPassed".to_string(), JsonValue::Bool(true)),
                    ("pt".to_string(), JsonValue::String(hex::encode_upper(&pt))),
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

/// Convert big-endian bytes to `u64`, rejecting values exceeding 8
/// bytes.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, DispatchError> {
    if bytes.len() > 8 {
        return Err(DispatchError::Crypto(
            "RSA DecPrim: e exceeds 8 bytes (u64 range)",
        ));
    }
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    Ok(val)
}
