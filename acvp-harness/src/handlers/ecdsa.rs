//! ECDSA ACVP handlers — `sigVer` and `keyVer` modes, revision
//! `FIPS186-5`.
//!
//! Two modes, each dispatched as a separate handler:
//!
//! - **SigVer** (`ECDSA` / `sigVer` / `FIPS186-5`): Given a message,
//!   public key (qx, qy), and signature (r, s), verify the ECDSA
//!   signature and return `testPassed`.
//! - **KeyVer** (`ECDSA` / `keyVer` / `FIPS186-5`): Given a public key
//!   (qx, qy), validate that it is a valid point on the curve and
//!   return `testPassed`.
//!
//! Only P-256 with SHA-256 is supported (the pqclib configuration).
//! Unsupported curves or hash algorithms produce
//! `DispatchError::Unsupported`.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── SigVer handler ──────────────────────────────────────────────────

/// ECDSA SigVer AFT dispatcher.
pub struct EcdsaSigVerHandler;

impl AlgorithmHandler for EcdsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "ECDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── KeyVer handler ──────────────────────────────────────────────────

/// ECDSA KeyVer AFT dispatcher.
pub struct EcdsaKeyVerHandler;

impl AlgorithmHandler for EcdsaKeyVerHandler {
    fn algorithm(&self) -> &'static str {
        "ECDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keyver_group(group)
    }
}

// ── SigVer group driver ─────────────────────────────────────────────

fn handle_sigver_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    // Validate curve/hash — pqclib only supports P-256 + SHA2-256.
    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    if curve != "P-256" {
        return Err(DispatchError::Unsupported("ECDSA SigVer: only P-256 is supported"));
    }
    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;
    if hash_alg != "SHA2-256" {
        return Err(DispatchError::Unsupported(
            "ECDSA SigVer: only SHA2-256 is supported",
        ));
    }

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

        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;
        let qx = hex::decode(
            t.get("qx")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qx"))?,
        )?;
        let qy = hex::decode(
            t.get("qy")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qy"))?,
        )?;
        let r_bytes = hex::decode(
            t.get("r")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("r"))?,
        )?;
        let s_bytes = hex::decode(
            t.get("s")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("s"))?,
        )?;

        let passed = ecdsa_p256_verify(&message, &qx, &qy, &r_bytes, &s_bytes);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("testPassed".to_string(), JsonValue::Bool(passed)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── KeyVer group driver ─────────────────────────────────────────────

fn handle_keyver_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    if curve != "P-256" {
        return Err(DispatchError::Unsupported("ECDSA KeyVer: only P-256 is supported"));
    }

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

        let qx = hex::decode(
            t.get("qx")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qx"))?,
        )?;
        let qy = hex::decode(
            t.get("qy")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qy"))?,
        )?;

        let passed = ecdsa_p256_key_validate(&qx, &qy);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("testPassed".to_string(), JsonValue::Bool(passed)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Crypto helpers ──────────────────────────────────────────────────

/// Build the 65-byte uncompressed SEC1 public key (0x04 || qx || qy)
/// and the 64-byte signature (r || s), then call
/// `fips_ecdsa::p256_ecdsa::verify`.
fn ecdsa_p256_verify(msg: &[u8], qx: &[u8], qy: &[u8], r: &[u8], s: &[u8]) -> bool {
    // qx and qy must each be exactly 32 bytes for P-256.
    if qx.len() != 32 || qy.len() != 32 || r.len() != 32 || s.len() != 32 {
        return false;
    }
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(qx);
    pk[33..65].copy_from_slice(qy);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(s);

    fips_ecdsa::p256_ecdsa::verify(&pk, msg, &sig).unwrap_or_default()
}

/// Build the 65-byte uncompressed SEC1 public key and validate it via
/// the full SP 800-56Ar3 §5.6.2.3.3 public-key validation.
fn ecdsa_p256_key_validate(qx: &[u8], qy: &[u8]) -> bool {
    // If qx/qy are not exactly 32 bytes each, the key is invalid.
    // ACVP KeyVer vectors may provide oversize coordinates to test
    // rejection of out-of-range values.
    if qx.len() > 32 || qy.len() > 32 {
        return false;
    }
    // Left-pad to 32 bytes (coordinates < 32 bytes are valid but
    // unusual; ACVP doesn't seem to test this, but be correct).
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    // Right-align qx into pk[1..33]
    let qx_offset = 33 - qx.len();
    pk[qx_offset..33].copy_from_slice(qx);
    // Right-align qy into pk[33..65]
    let qy_offset = 65 - qy.len();
    pk[qy_offset..65].copy_from_slice(qy);

    fips_ecdsa::p256_point::Point::from_sec1_uncompressed_validated(&pk).is_some()
}
