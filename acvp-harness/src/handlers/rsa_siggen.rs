//! RSA ACVP handler — `sigGen` mode, revision `FIPS186-5`.
//!
//! **SigGen** (`RSA` / `sigGen` / `FIPS186-5`): Given a private key
//! and a message, generate an RSA signature and return it.
//!
//! Supported configurations:
//! - `sigType = "pkcs1v1.5"`, `modulo ∈ {2048, 3072, 4096}`,
//!   `hashAlg = "SHA2-256"` — non-CRT path (group provides `n`, `d`),
//!   or CRT path with `keyMode = "crt"` (group provides CRT components)
//! - `sigType = "pss"`, `modulo ∈ {2048, 3072, 4096}`,
//!   `hashAlg = "SHA2-256"`, `saltLen = 32` — CRT path (group provides
//!   CRT components) or non-CRT path with `keyMode = "standard"`
//!
//! All four combinations of (sigType × keyMode) are supported at each
//! modulus size. The CRT path uses Bellcore verify-after-sign per
//! FIPS 140-3 IG D.G.

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

    let results = match modulo {
        2048 => handle_siggen_2048(group, tests, sig_type, key_mode)?,
        3072 => handle_siggen_3072(group, tests, sig_type, key_mode)?,
        4096 => handle_siggen_4096(group, tests, sig_type, key_mode)?,
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only modulo 2048/3072/4096 are supported",
            ));
        }
    };

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Per-modulus signing ─────────────────────────────────────────────

/// Sign with RSA-2048 keys.
#[allow(clippy::too_many_lines)]
fn handle_siggen_2048(
    group: &JsonValue,
    tests: &[JsonValue],
    sig_type: &str,
    key_mode: &str,
) -> Result<Vec<JsonValue>, DispatchError> {
    const N: usize = oxicrypt_rsa::RSA_2048_MODULUS_BYTES;
    const H: usize = oxicrypt_rsa::RSA_2048_CRT_HALF_BYTES;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match (sig_type, key_mode) {
        ("pkcs1v1.5", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 CRT sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pkcs1v1.5", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa_pkcs1_v15_sign_2048_sha256_internal(&n, &d, &message)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa_pss_sign_2048_sha256_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message, &salt,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PSS CRT sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa_pss_sign_2048_sha256_internal(&n, &d, &message, &salt)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PSS sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
            ));
        }
    }
    Ok(results)
}

/// Sign with RSA-3072 keys.
fn handle_siggen_3072(
    group: &JsonValue,
    tests: &[JsonValue],
    sig_type: &str,
    key_mode: &str,
) -> Result<Vec<JsonValue>, DispatchError> {
    const N: usize = 384;
    const H: usize = 192;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match (sig_type, key_mode) {
        ("pkcs1v1.5", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa3072::pkcs1_v15_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 CRT 3072 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pkcs1v1.5", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa3072::pkcs1_v15_sign_internal(&n, &d, &message)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 3072 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa3072::pss_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message, &salt,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PSS CRT 3072 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa3072::pss_sign_internal(&n, &d, &message, &salt)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PSS 3072 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
            ));
        }
    }
    Ok(results)
}

/// Sign with RSA-4096 keys.
fn handle_siggen_4096(
    group: &JsonValue,
    tests: &[JsonValue],
    sig_type: &str,
    key_mode: &str,
) -> Result<Vec<JsonValue>, DispatchError> {
    const N: usize = 512;
    const H: usize = 256;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match (sig_type, key_mode) {
        ("pkcs1v1.5", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa4096::pkcs1_v15_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 CRT 4096 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pkcs1v1.5", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa4096::pkcs1_v15_sign_internal(&n, &d, &message)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 4096 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa4096::pss_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message, &salt,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PSS CRT 4096 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc.get("tcId").and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa4096::pss_sign_internal(&n, &d, &message, &salt)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PSS 4096 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
            ));
        }
    }
    Ok(results)
}

// ── Result helper ──────────────────────────────────────────────────

fn sig_result(tc_id: i64, sig: &[u8]) -> JsonValue {
    JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        (
            "signature".to_string(),
            JsonValue::String(hex::encode_upper(sig)),
        ),
    ])
}
