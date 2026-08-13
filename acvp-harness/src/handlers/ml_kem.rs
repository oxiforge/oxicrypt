//! ML-KEM ACVP handlers — `keyGen` and `encapDecap` modes per FIPS 203.
//!
//! Two handlers, mirroring the catalog's two-mode shape
//! (see `draft-celi-acvp-ml-kem §7.3.1` and `§7.3.2`):
//!
//! - **`MlKemKeyGenHandler`** — `ML-KEM` / `keyGen` / `FIPS203`,
//!   advertising `parameterSets: ["ML-KEM-512", "ML-KEM-768",
//!   "ML-KEM-1024"]`. Generates a (encapsulation key, decapsulation
//!   key) pair from server-supplied `d` and `z` seeds. Per-group
//!   `parameterSet` field selects the variant (k=2/3/4).
//! - **`MlKemEncapDecapHandler`** — `ML-KEM` / `encapDecap` /
//!   `FIPS203`, advertising the same three parameter sets and
//!   `functions: ["encapsulation", "decapsulation"]`. Group-level
//!   `function` field selects encaps vs. decaps; group-level
//!   `parameterSet` field selects k.
//!
//! All three FIPS 203 parameter sets are supported. The `algorithm()`
//! value is the family name `"ML-KEM"`. A new parameter set needs a
//! cap entry and a match arm in each group driver, but no new handler
//! struct.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// ML-KEM keyGen dispatcher
/// (`parameterSets: ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]`).
pub struct MlKemKeyGenHandler;

impl AlgorithmHandler for MlKemKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "ML-KEM"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS203"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_kem_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── EncapDecap handler ──────────────────────────────────────────────

/// ML-KEM encapDecap dispatcher
/// (`parameterSets: ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]`,
/// `functions: ["encapsulation", "decapsulation"]`).
///
/// Per `draft-celi-acvp-ml-kem §8.2.1`, each prompt group within an
/// encapDecap vector set is tagged with a `function` field; this
/// handler dispatches to the encapsulation or decapsulation group
/// driver based on that tag, and then per-variant on `parameterSet`.
/// Key-check VAL functions
/// (`encapsulationKeyCheck`/`decapsulationKeyCheck`) are not
/// advertised and will be rejected with `Unsupported` if the server
/// somehow sends them under the current cap.
pub struct MlKemEncapDecapHandler;

impl AlgorithmHandler for MlKemEncapDecapHandler {
    fn algorithm(&self) -> &'static str {
        "ML-KEM"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("encapDecap")
    }
    fn revision(&self) -> &'static str {
        "FIPS203"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_kem_encapdecap_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let function = group
            .get("function")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("function"))?;
        match function {
            "encapsulation" => handle_encaps_group(group),
            "decapsulation" => handle_decaps_group(group),
            _ => Err(DispatchError::Unsupported(
                "ML-KEM encapDecap: function must be `encapsulation` or `decapsulation` \
                 under current cap (key-check VAL functions not advertised)",
            )),
        }
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
        "ML-KEM: parameterSet must be `ML-KEM-512`, `ML-KEM-768`, or `ML-KEM-1024`",
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

        // ML-KEM keygen requires two 32-byte seeds: d and z. Same
        // shape for all three parameter sets.
        let d_bytes = hex::decode(
            t.get("d")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("d"))?,
        )?;
        let d: [u8; 32] = d_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM KeyGen: d is not 32 bytes"))?;

        let z_bytes = hex::decode(
            t.get("z")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("z"))?,
        )?;
        let z: [u8; 32] = z_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM KeyGen: z is not 32 bytes"))?;

        // Per-variant dispatch: each variant has different EK/DK
        // byte counts (FIPS 203 Table 3). Match returns the hex-
        // encoded outputs for serialization.
        let (ek_hex, dk_hex) = match parameter_set {
            "ML-KEM-512" => {
                let (ek, dk) = oxicrypt_ml_kem::ml_kem_512::keygen_internal(&d, &z)
                    .ok_or(DispatchError::Crypto("ML-KEM-512 KeyGen failed"))?;
                (hex::encode_upper(&ek), hex::encode_upper(&dk))
            }
            "ML-KEM-768" => {
                let (ek, dk) = oxicrypt_ml_kem::ml_kem_768::keygen_internal(&d, &z)
                    .ok_or(DispatchError::Crypto("ML-KEM-768 KeyGen failed"))?;
                (hex::encode_upper(&ek), hex::encode_upper(&dk))
            }
            "ML-KEM-1024" => {
                let (ek, dk) = oxicrypt_ml_kem::ml_kem_1024::keygen_internal(&d, &z)
                    .ok_or(DispatchError::Crypto("ML-KEM-1024 KeyGen failed"))?;
                (hex::encode_upper(&ek), hex::encode_upper(&dk))
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("ek".to_string(), JsonValue::String(ek_hex)),
            ("dk".to_string(), JsonValue::String(dk_hex)),
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

        let ek_bytes = hex::decode(
            t.get("ek")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("ek"))?,
        )?;

        let m_bytes = hex::decode(
            t.get("m")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("m"))?,
        )?;
        let m: [u8; 32] = m_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM Encaps: m is not 32 bytes"))?;

        let (k_hex, c_hex) = match parameter_set {
            "ML-KEM-512" => {
                let ek: [u8; 800] = ek_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("ML-KEM-512 Encaps: ek is not 800 bytes"))?;
                let (ss, ct) = oxicrypt_ml_kem::ml_kem_512::encaps_internal(&ek, &m);
                (hex::encode_upper(&ss), hex::encode_upper(&ct))
            }
            "ML-KEM-768" => {
                let ek: [u8; 1184] = ek_bytes.as_slice().try_into().map_err(|_| {
                    DispatchError::Crypto("ML-KEM-768 Encaps: ek is not 1184 bytes")
                })?;
                let (ss, ct) = oxicrypt_ml_kem::ml_kem_768::encaps_internal(&ek, &m);
                (hex::encode_upper(&ss), hex::encode_upper(&ct))
            }
            "ML-KEM-1024" => {
                let ek: [u8; 1568] = ek_bytes.as_slice().try_into().map_err(|_| {
                    DispatchError::Crypto("ML-KEM-1024 Encaps: ek is not 1568 bytes")
                })?;
                let (ss, ct) = oxicrypt_ml_kem::ml_kem_1024::encaps_internal(&ek, &m);
                (hex::encode_upper(&ss), hex::encode_upper(&ct))
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("c".to_string(), JsonValue::String(c_hex)),
            ("k".to_string(), JsonValue::String(k_hex)),
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
    if test_type != "VAL" {
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

        let dk_bytes = hex::decode(
            t.get("dk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("dk"))?,
        )?;

        let c_bytes = hex::decode(
            t.get("c")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("c"))?,
        )?;

        let k_hex =
            match parameter_set {
                "ML-KEM-512" => {
                    let dk: [u8; 1632] = dk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-512 Decaps: dk is not 1632 bytes")
                    })?;
                    let c: [u8; 768] = c_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-512 Decaps: c is not 768 bytes")
                    })?;
                    let ss = oxicrypt_ml_kem::ml_kem_512::decaps_internal(&dk, &c);
                    hex::encode_upper(&ss)
                }
                "ML-KEM-768" => {
                    let dk: [u8; 2400] = dk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-768 Decaps: dk is not 2400 bytes")
                    })?;
                    let c: [u8; 1088] = c_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-768 Decaps: c is not 1088 bytes")
                    })?;
                    let ss = oxicrypt_ml_kem::ml_kem_768::decaps_internal(&dk, &c);
                    hex::encode_upper(&ss)
                }
                "ML-KEM-1024" => {
                    let dk: [u8; 3168] = dk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-1024 Decaps: dk is not 3168 bytes")
                    })?;
                    let c: [u8; 1568] = c_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-1024 Decaps: c is not 1568 bytes")
                    })?;
                    let ss = oxicrypt_ml_kem::ml_kem_1024::decaps_internal(&dk, &c);
                    hex::encode_upper(&ss)
                }
                other => return Err(unsupported_parameter_set(other)),
            };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("k".to_string(), JsonValue::String(k_hex)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
