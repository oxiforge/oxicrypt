//! EdDSA ACVP handlers — `sigVer` and `keyVer` modes, revision `1.0`.
//!
//! Two modes, each dispatched as a separate handler:
//!
//! - **SigVer** (`EDDSA` / `sigVer` / `1.0`): Given a message, public
//!   key (`q`), and `signature`, verify the Ed25519 signature and
//!   return `testPassed`. Only `preHash = false` (pure Ed25519) is
//!   supported; prehash groups are rejected as unsupported.
//! - **KeyVer** (`EDDSA` / `keyVer` / `1.0`): Given a public key (`q`),
//!   validate that it is a valid compressed Edwards point and return
//!   `testPassed`.
//!
//! Only the `ED-25519` curve is supported. `ED-448` groups produce
//! `DispatchError::Unsupported`.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── SigVer handler ──────────────────────────────────────────────────

/// EdDSA SigVer AFT dispatcher.
pub struct EddsaSigVerHandler;

impl AlgorithmHandler for EddsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "EDDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── KeyVer handler ──────────────────────────────────────────────────

/// EdDSA KeyVer AFT dispatcher.
pub struct EddsaKeyVerHandler;

impl AlgorithmHandler for EddsaKeyVerHandler {
    fn algorithm(&self) -> &'static str {
        "EDDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
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

    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    if curve != "ED-25519" {
        return Err(DispatchError::Unsupported(
            "EdDSA SigVer: only ED-25519 is supported",
        ));
    }

    // Reject prehash (Ed25519ph) — pqclib implements pure Ed25519 only.
    let pre_hash = group
        .get("preHash")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    if pre_hash {
        return Err(DispatchError::Unsupported(
            "EdDSA SigVer: Ed25519ph (preHash=true) is not supported",
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
        let q_bytes = hex::decode(
            t.get("q")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("q"))?,
        )?;
        let sig_bytes = hex::decode(
            t.get("signature")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("signature"))?,
        )?;

        let passed = ed25519_verify(&q_bytes, &message, &sig_bytes);

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
    if curve != "ED-25519" {
        return Err(DispatchError::Unsupported(
            "EdDSA KeyVer: only ED-25519 is supported",
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

        let q_bytes = hex::decode(
            t.get("q")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("q"))?,
        )?;

        let passed = ed25519_key_validate(&q_bytes);

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

/// Verify an Ed25519 signature. Public key is 32 bytes (compressed
/// Edwards point), signature is 64 bytes (R || S).
fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let pk: &[u8; 32] = public_key.try_into().unwrap_or(&[0u8; 32]);
    let sig: &[u8; 64] = signature.try_into().unwrap_or(&[0u8; 64]);
    fips_eddsa::ed25519::verify(pk, message, sig).unwrap_or_default()
}

/// Validate an Ed25519 public key by attempting to decompress it.
fn ed25519_key_validate(public_key: &[u8]) -> bool {
    if public_key.len() != 32 {
        return false;
    }
    let pk: [u8; 32] = public_key.try_into().unwrap_or([0u8; 32]);
    fips_eddsa::edwards::EdwardsPoint::decompress(&pk).is_some()
}
