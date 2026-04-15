//! SLH-DSA-SHA2-256s ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes.
//!
//! **SLH-DSA-SHA2-256s** (`SLH-DSA-SHA2-256s` / `keyGen`, `sigGen`, `sigVer` /
//! revision `1.0`): Stateless hash-based digital signature per FIPS 205.
//!
//! Three modes for the complete signature lifecycle:
//! - **KeyGen**: Generate a (public key, secret key) pair from a 96-byte seed
//! - **SigGen**: Sign a message deterministically with a secret key
//! - **SigVer**: Verify a signature against a public key and message

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// SLH-DSA-SHA2-256s KeyGen dispatcher.
pub struct SlhDsaKeyGenHandler;

impl AlgorithmHandler for SlhDsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA-SHA2-256s"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_keygen_capability("SLH-DSA-SHA2-256s"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// SLH-DSA-SHA2-256s SigGen dispatcher.
pub struct SlhDsaSigGenHandler;

impl AlgorithmHandler for SlhDsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA-SHA2-256s"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_siggen_capability("SLH-DSA-SHA2-256s"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── SigVer handler ──────────────────────────────────────────────────

/// SLH-DSA-SHA2-256s SigVer dispatcher.
pub struct SlhDsaSigVerHandler;

impl AlgorithmHandler for SlhDsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA-SHA2-256s"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_sigver_capability("SLH-DSA-SHA2-256s"))
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

        // SLH-DSA-SHA2-256s keygen requires 96 bytes: SK.seed ‖ SK.prf ‖ PK.seed.
        let seed_bytes = hex::decode(
            t.get("seed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("seed"))?,
        )?;
        let seed: [u8; 96] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("SLH-DSA KeyGen: seed is not 96 bytes"))?;

        let (pk, sk) = oxicrypt_slh_dsa::keygen_internal(&seed);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("pk".to_string(), JsonValue::String(hex::encode_upper(&pk))),
            ("sk".to_string(), JsonValue::String(hex::encode_upper(&sk))),
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

    // Group-level secret key (128 bytes for SLH-DSA-SHA2-256s).
    let sk_bytes = hex::decode(
        group
            .get("sk")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("sk"))?,
    )?;
    let sk: [u8; oxicrypt_slh_dsa::SK_LEN] = sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("SLH-DSA SigGen: sk has wrong length"))?;

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

        let sig = oxicrypt_slh_dsa::sign_internal(&sk, &message);

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

    // Group-level public key (64 bytes for SLH-DSA-SHA2-256s).
    let pk_bytes = hex::decode(
        group
            .get("pk")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("pk"))?,
    )?;
    let pk: [u8; oxicrypt_slh_dsa::PK_LEN] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("SLH-DSA SigVer: pk has wrong length"))?;

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

        let passed =
            if let Ok(sig) = <[u8; oxicrypt_slh_dsa::SIG_LEN]>::try_from(sig_bytes.as_slice()) {
                oxicrypt_slh_dsa::verify_internal(&pk, &message, &sig)
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
