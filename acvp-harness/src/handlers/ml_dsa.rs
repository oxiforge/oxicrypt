//! ML-DSA ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes per FIPS 204.
//!
//! Three handlers, mirroring the catalog's three-mode shape
//! (see `draft-celi-acvp-ml-dsa §7.3.1`, `§7.4.1`, `§7.5.1`):
//!
//! - **`MlDsaKeyGenHandler`** — `ML-DSA` / `keyGen` / `FIPS204`,
//!   advertising `parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`.
//!   Generates a (public key, secret key) pair from a 32-byte seed.
//!   Per-group `parameterSet` field selects the variant.
//! - **`MlDsaSigGenHandler`** — `ML-DSA` / `sigGen` / `FIPS204`,
//!   advertising the same three parameter sets. Deterministic-mode
//!   signing (`externalMu: false`; internal interface). Per-group
//!   `parameterSet` field selects the variant (which fixes SK_LEN).
//! - **`MlDsaSigVerHandler`** — `ML-DSA` / `sigVer` / `FIPS204`,
//!   advertising the same three parameter sets. Per-group
//!   `parameterSet` field selects the variant (which fixes PK_LEN
//!   and SIG_LEN). The server mixes valid and tampered signatures
//!   within the same group; the IUT returns `testPassed: bool`.
//!
//! All three FIPS 204 parameter sets are supported. The `algorithm()`
//! value is the family name `"ML-DSA"`. A new parameter set needs a
//! cap entry and a match arm in each group driver, but no new handler
//! struct churn (same pattern as ML-KEM).
//!
//! Per-test field placement (`sk` for sigGen, `pk` for sigVer)
//! follows §8.2.2 Table 14 and §8.3.2 Table 16 of the draft.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// ML-DSA keyGen dispatcher
/// (`parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`).
pub struct MlDsaKeyGenHandler;

impl AlgorithmHandler for MlDsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "ML-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS204"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_dsa_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// ML-DSA sigGen dispatcher
/// (`parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`).
pub struct MlDsaSigGenHandler;

impl AlgorithmHandler for MlDsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "ML-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS204"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_dsa_siggen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── SigVer handler ──────────────────────────────────────────────────

/// ML-DSA sigVer dispatcher
/// (`parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`).
pub struct MlDsaSigVerHandler;

impl AlgorithmHandler for MlDsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "ML-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS204"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_dsa_sigver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn read_parameter_set(group: &JsonValue) -> Result<&str, DispatchError> {
    group
        .get("parameterSet")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("parameterSet"))
}

fn unsupported_parameter_set(_other: &str) -> DispatchError {
    DispatchError::Unsupported(
        "ML-DSA: parameterSet must be `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87`",
    )
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

    let parameter_set = read_parameter_set(group)?;

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

        // ML-DSA keygen takes a single 32-byte seed (xi). Same shape
        // across all three parameter sets per FIPS 204 §6.1.
        let seed_bytes = hex::decode(
            t.get("seed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("seed"))?,
        )?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-DSA KeyGen: seed is not 32 bytes"))?;

        // Per-variant dispatch: each variant emits PK/SK at the
        // sizes given in FIPS 204 §4 Table 2.
        let (pk_hex, sk_hex) = match parameter_set {
            "ML-DSA-44" => {
                let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_44::keygen_internal(&seed);
                (hex::encode_upper(&pk), hex::encode_upper(&sk))
            }
            "ML-DSA-65" => {
                let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_65::keygen_internal(&seed);
                (hex::encode_upper(&pk), hex::encode_upper(&sk))
            }
            "ML-DSA-87" => {
                let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_87::keygen_internal(&seed);
                (hex::encode_upper(&pk), hex::encode_upper(&sk))
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("pk".to_string(), JsonValue::String(pk_hex)),
            ("sk".to_string(), JsonValue::String(sk_hex)),
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

    let parameter_set = read_parameter_set(group)?;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    // `sk` is per-test per `draft-celi-acvp-ml-dsa §8.2.2` Table 14
    // (key fields live in the test case object, not the test group).
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let sk_bytes = hex::decode(
            t.get("sk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("sk"))?,
        )?;

        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;

        // Per-variant dispatch: each variant has different SK_LEN
        // and SIG_LEN per FIPS 204 §4 Table 2.
        let sig_hex = match parameter_set {
            "ML-DSA-44" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_44::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-44 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_44::sign_internal(&sk, &message)
                    .ok_or(DispatchError::Crypto("ML-DSA-44 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            "ML-DSA-65" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_65::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-65 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_65::sign_internal(&sk, &message)
                    .ok_or(DispatchError::Crypto("ML-DSA-65 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            "ML-DSA-87" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_87::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-87 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_87::sign_internal(&sk, &message)
                    .ok_or(DispatchError::Crypto("ML-DSA-87 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("signature".to_string(), JsonValue::String(sig_hex)),
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

    let parameter_set = read_parameter_set(group)?;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    // Per `draft-celi-acvp-ml-dsa §8.3.2` Table 16, `pk`, `message`,
    // and `signature` are all per-test fields. Server mixes valid
    // and tampered (key-flip) signatures within the same group; the
    // IUT returns `testPassed: bool` per case and the server grades
    // by exact-match against the expected valid/invalid disposition.
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let pk_bytes = hex::decode(
            t.get("pk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("pk"))?,
        )?;

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

        // Per-variant dispatch: each variant has different PK_LEN
        // and SIG_LEN per FIPS 204 §4 Table 2. Wrong-length pk fails
        // the test case (Crypto error); wrong-length sig grades as
        // testPassed=false (server tampers may yield short sigs;
        // upstream Verify already collapses decode-fail to false).
        let passed = match parameter_set {
            "ML-DSA-44" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_44::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-44 SigVer: pk has wrong length")
                    })?;
                if let Ok(sig) =
                    <[u8; oxicrypt_ml_dsa::ml_dsa_44::SIG_LEN]>::try_from(sig_bytes.as_slice())
                {
                    oxicrypt_ml_dsa::ml_dsa_44::verify_internal(&pk, &message, &sig)
                } else {
                    false
                }
            }
            "ML-DSA-65" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_65::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-65 SigVer: pk has wrong length")
                    })?;
                if let Ok(sig) =
                    <[u8; oxicrypt_ml_dsa::ml_dsa_65::SIG_LEN]>::try_from(sig_bytes.as_slice())
                {
                    oxicrypt_ml_dsa::ml_dsa_65::verify_internal(&pk, &message, &sig)
                } else {
                    false
                }
            }
            "ML-DSA-87" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_87::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-87 SigVer: pk has wrong length")
                    })?;
                if let Ok(sig) =
                    <[u8; oxicrypt_ml_dsa::ml_dsa_87::SIG_LEN]>::try_from(sig_bytes.as_slice())
                {
                    oxicrypt_ml_dsa::ml_dsa_87::verify_internal(&pk, &message, &sig)
                } else {
                    false
                }
            }
            other => return Err(unsupported_parameter_set(other)),
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
