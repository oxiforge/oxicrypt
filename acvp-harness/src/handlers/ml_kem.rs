//! ML-KEM-1024 ACVP handlers — `keyGen`, `encaps`, and `decaps` modes.
//!
//! **ML-KEM-1024** (`ML-KEM-1024` / `keyGen`, `encaps`, `decaps` / revision `1.0`):
//! Post-quantum key encapsulation mechanism per FIPS 203.
//!
//! Three modes for the complete encapsulation lifecycle:
//! - **KeyGen**: Generate a (public key, secret key) pair
//! - **Encaps**: Encapsulate a shared secret with a public key
//! - **Decaps**: Decapsulate a ciphertext with a secret key to recover the shared secret

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// ML-KEM-1024 KeyGen dispatcher.
pub struct MlKem1024KeyGenHandler;

impl AlgorithmHandler for MlKem1024KeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "ML-KEM-1024"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_kem_keygen_capability("ML-KEM-1024"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── Encaps handler ──────────────────────────────────────────────────

/// ML-KEM-1024 Encaps dispatcher.
pub struct MlKem1024EncapsHandler;

impl AlgorithmHandler for MlKem1024EncapsHandler {
    fn algorithm(&self) -> &'static str {
        "ML-KEM-1024"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("encaps")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_kem_encaps_capability("ML-KEM-1024"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_encaps_group(group)
    }
}

// ── Decaps handler ──────────────────────────────────────────────────

/// ML-KEM-1024 Decaps dispatcher.
pub struct MlKem1024DecapsHandler;

impl AlgorithmHandler for MlKem1024DecapsHandler {
    fn algorithm(&self) -> &'static str {
        "ML-KEM-1024"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("decaps")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_kem_decaps_capability("ML-KEM-1024"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_decaps_group(group)
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

        // ML-KEM keygen requires two 32-byte seeds: d and z.
        let d_bytes = hex::decode(
            t.get("d")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("d"))?,
        )?;
        let d: [u8; 32] = d_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 KeyGen: d is not 32 bytes"))?;

        let z_bytes = hex::decode(
            t.get("z")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("z"))?,
        )?;
        let z: [u8; 32] = z_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 KeyGen: z is not 32 bytes"))?;

        let (pk, sk) = oxicrypt_ml_kem::keygen_internal(&d, &z)
            .ok_or(DispatchError::Crypto("ML-KEM-1024 KeyGen failed"))?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("ek".to_string(), JsonValue::String(hex::encode_upper(&pk))),
            ("dk".to_string(), JsonValue::String(hex::encode_upper(&sk))),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Encaps group driver ─────────────────────────────────────────────

fn handle_encaps_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    // Group-level public key (1568 bytes for ML-KEM-1024).
    let ek_bytes = hex::decode(
        group
            .get("ek")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("ek"))?,
    )?;
    let ek: [u8; 1568] = ek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Encaps: ek is not 1568 bytes"))?;

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

        // Message/randomness for encaps (32 bytes).
        let m_bytes = hex::decode(
            t.get("m")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("m"))?,
        )?;
        let m: [u8; 32] = m_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Encaps: m is not 32 bytes"))?;

        // Encapsulate with the public key.
        let (ss, ct) = oxicrypt_ml_kem::encaps_internal(&ek, &m);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("ct".to_string(), JsonValue::String(hex::encode_upper(&ct))),
            ("ss".to_string(), JsonValue::String(hex::encode_upper(&ss))),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Decaps group driver ─────────────────────────────────────────────

fn handle_decaps_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    // Group-level secret key (3168 bytes for ML-KEM-1024).
    let dk_bytes = hex::decode(
        group
            .get("dk")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("dk"))?,
    )?;
    let dk: [u8; 3168] = dk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Decaps: dk is not 3168 bytes"))?;

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

        // Ciphertext to decapsulate (1568 bytes for ML-KEM-1024).
        let ct_bytes = hex::decode(
            t.get("ct")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("ct"))?,
        )?;
        let ct: [u8; 1568] = ct_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Decaps: ct is not 1568 bytes"))?;

        // Decapsulate.
        let ss = oxicrypt_ml_kem::decaps_internal(&dk, &ct);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("ss".to_string(), JsonValue::String(hex::encode_upper(&ss))),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
