//! RSA ACVP handler — `sigGen` mode, revision `FIPS186-5`.
//!
//! **SigGen** (`RSA` / `sigGen` / `FIPS186-5`): Given a private key
//! and a message, generate an RSA signature and return it.
//!
//! Supported configurations:
//! - `sigType = "pkcs1v1.5"`, `modulo = 2048`, `hashAlg = "SHA2-256"`
//!   — non-CRT path (group provides `n`, `e`, `d`), or CRT path
//!   with `keyMode = "crt"` (group provides CRT components)
//! - `sigType = "pss"`, `modulo = 2048`, `hashAlg = "SHA2-256"`,
//!   `saltLen = 32` — CRT path (group provides `n`, `e`, CRT
//!   components `p`, `q`, `dmp1`, `dmq1`, `iqmp`; each test
//!   supplies a fixed `salt`), or non-CRT path with
//!   `keyMode = "standard"` (group provides `n`, `d`)
//!
//! All four combinations of (sigType × keyMode) are supported.
//! The CRT path uses Bellcore verify-after-sign per FIPS 140-3
//! IG D.G.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// RSA SigGen dispatcher.
pub struct RsaSigGenHandler;

impl AlgorithmHandler for RsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "RSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── Constants ──────────────────────────────────────────────────────

const N_BYTES: usize = fips_rsa::RSA_2048_MODULUS_BYTES;
const HALF_BYTES: usize = fips_rsa::RSA_2048_CRT_HALF_BYTES;

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
        return Err(DispatchError::Crypto("RSA SigGen: field too large"));
    }
    let mut buf = [0u8; LEN];
    buf[LEN - raw.len()..].copy_from_slice(&raw);
    Ok(buf)
}

/// Convert big-endian bytes to `u64`.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, DispatchError> {
    if bytes.len() > 8 {
        return Err(DispatchError::Crypto(
            "RSA SigGen: e exceeds 8 bytes (u64 range)",
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
fn handle_siggen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "GDT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let sig_type = group
        .get("sigType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("sigType"))?;

    let modulo = group
        .get("modulo")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("modulo"))?;
    if modulo != 2048 {
        return Err(DispatchError::Unsupported(
            "RSA SigGen: only modulo 2048 is supported",
        ));
    }

    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;
    if hash_alg != "SHA2-256" {
        return Err(DispatchError::Unsupported(
            "RSA SigGen: only SHA2-256 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // If keyMode is absent, infer from sigType for backwards
    // compatibility with upstream vectors: pkcs1v1.5 defaults to
    // "standard" (non-CRT, d-only), pss defaults to "crt".
    let key_mode = group
        .get("keyMode")
        .and_then(JsonValue::as_str)
        .unwrap_or(match sig_type {
            "pss" => "crt",
            _ => "standard",
        });

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match (sig_type, key_mode) {
        ("pkcs1v1.5", "crt") => {
            // CRT: group carries n, e, p, q, dmp1, dmq1, iqmp.
            let n: [u8; N_BYTES] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; HALF_BYTES] = decode_fixed(group, "p")?;
            let q: [u8; HALF_BYTES] = decode_fixed(group, "q")?;
            let dp: [u8; HALF_BYTES] = decode_fixed(group, "dmp1")?;
            let dq: [u8; HALF_BYTES] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; HALF_BYTES] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let message = decode_hex_field(tc, "message")?;

                let sig = fips_rsa::rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: PKCS#1v1.5 CRT sign failed",
                ))?;

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "signature".to_string(),
                        JsonValue::String(hex::encode_upper(&sig)),
                    ),
                ]));
            }
        }
        ("pkcs1v1.5", _) => {
            // Non-CRT: group carries n, d.
            let n: [u8; N_BYTES] = decode_fixed(group, "n")?;
            let d: [u8; N_BYTES] = decode_fixed(group, "d")?;

            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let message = decode_hex_field(tc, "message")?;

                let sig = fips_rsa::rsa_pkcs1_v15_sign_2048_sha256_internal(
                    &n, &d, &message,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 sign failed"))?;

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "signature".to_string(),
                        JsonValue::String(hex::encode_upper(&sig)),
                    ),
                ]));
            }
        }
        ("pss", "crt") => {
            // CRT: group carries n, e, p, q, dmp1, dmq1, iqmp.
            let n: [u8; N_BYTES] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; HALF_BYTES] = decode_fixed(group, "p")?;
            let q: [u8; HALF_BYTES] = decode_fixed(group, "q")?;
            let dp: [u8; HALF_BYTES] = decode_fixed(group, "dmp1")?;
            let dq: [u8; HALF_BYTES] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; HALF_BYTES] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;

                let sig = fips_rsa::rsa_pss_sign_2048_sha256_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message, &salt,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PSS CRT sign failed"))?;

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "signature".to_string(),
                        JsonValue::String(hex::encode_upper(&sig)),
                    ),
                ]));
            }
        }
        ("pss", _) => {
            // Non-CRT PSS: group carries n, d; each test supplies salt.
            let n: [u8; N_BYTES] = decode_fixed(group, "n")?;
            let d: [u8; N_BYTES] = decode_fixed(group, "d")?;

            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;

                let sig = fips_rsa::rsa_pss_sign_2048_sha256_internal(
                    &n, &d, &message, &salt,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PSS sign failed"))?;

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "signature".to_string(),
                        JsonValue::String(hex::encode_upper(&sig)),
                    ),
                ]));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
            ));
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
