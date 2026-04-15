//! LMS ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes.
//!
//! **LMS** (`LMS` / `keyGen`, `sigGen`, `sigVer` / revision `1.0`):
//! Stateful hash-based signature scheme per SP 800-208 (RFC 8554).
//!
//! Parameter set: `LMS_SHA256_M32_H10` / `LMOTS_SHA256_N32_W4`.
//!
//! Three modes:
//! - **KeyGen**: Generate a key pair from a 32-byte seed
//! - **SigGen**: Sign a message with a private key (stateful — advances
//!   leaf index). The group provides the seed and leaf index for
//!   deterministic reconstruction of key state.
//! - **SigVer**: Verify a signature against a public key and message

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// LMS KeyGen dispatcher.
pub struct LmsKeyGenHandler;

impl AlgorithmHandler for LmsKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// LMS SigGen dispatcher.
pub struct LmsSigGenHandler;

impl AlgorithmHandler for LmsSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_siggen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── SigVer handler ──────────────────────────────────────────────────

/// LMS SigVer dispatcher.
pub struct LmsSigVerHandler;

impl AlgorithmHandler for LmsSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_sigver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── KeyGen group driver ─────────────────────────────────────────────

fn handle_keygen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

        let seed_bytes = hex::decode(
            t.get("seed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("seed"))?,
        )?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("LMS KeyGen: seed is not 32 bytes"))?;

        let (_sk, pk) = oxicrypt_lms::keygen_internal(&seed);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("pk".to_string(), JsonValue::String(hex::encode_upper(&pk))),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── SigGen group driver ─────────────────────────────────────────────

fn handle_siggen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    // Group-level seed to reconstruct key state.
    let seed_bytes = hex::decode(
        group
            .get("seed")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("seed"))?,
    )?;
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("LMS SigGen: seed is not 32 bytes"))?;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // Reconstruct the key and advance to the starting leaf index.
    let (mut sk, _pk) = oxicrypt_lms::keygen_internal(&seed);

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

        let sig = oxicrypt_lms::sign_internal(&mut sk, &message)
            .ok_or(DispatchError::Crypto("LMS SigGen: signing failed (key exhausted?)"))?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "signature".to_string(),
                JsonValue::String(hex::encode_upper(&sig)),
            ),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
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

    // Group-level public key.
    let pk_bytes = hex::decode(
        group
            .get("pk")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("pk"))?,
    )?;
    let pk: [u8; oxicrypt_lms::PUBLIC_KEY_LEN] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("LMS SigVer: pk has wrong length"))?;

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

        let sig_bytes = hex::decode(
            t.get("signature")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("signature"))?,
        )?;

        let passed = if let Ok(sig) =
            <[u8; oxicrypt_lms::SIGNATURE_LEN]>::try_from(sig_bytes.as_slice())
        {
            oxicrypt_lms::verify_internal(&pk, &message, &sig)
        } else {
            false
        };

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
