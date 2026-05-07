//! ML-KEM ACVP handlers — `keyGen` and `encapDecap` modes per FIPS 203.
//!
//! Two handlers, mirroring the catalog's two-mode shape
//! (see `draft-celi-acvp-ml-kem §7.3.1` and `§7.3.2`):
//!
//! - **`MlKem1024KeyGenHandler`** — `ML-KEM` / `keyGen` / `FIPS203`,
//!   advertising `parameterSets: ["ML-KEM-1024"]`. Generates a
//!   (encapsulation key, decapsulation key) pair from server-supplied
//!   `d` and `z` seeds.
//! - **`MlKem1024EncapDecapHandler`** — `ML-KEM` / `encapDecap` /
//!   `FIPS203`, advertising `functions: ["encapsulation",
//!   "decapsulation"]`. Group-level `function` field selects which
//!   sub-routine drives the per-test work.
//!
//! Only `ML-KEM-1024` (CNSA 2.0 baseline) is currently advertised;
//! `ML-KEM-512` and `ML-KEM-768` are PQ-expansion-mandate items
//! (`algo-capability-matrix.md` rows 223-225) and will be added to
//! `parameterSets` when their `*_internal` + public-API surfaces ship.
//! The `algorithm()` value is the family name `"ML-KEM"` (matching
//! the live ACVP catalog) — not parameter-set-baked — so adding new
//! parameter sets is a cap-only change with no handler-name churn.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// ML-KEM keyGen dispatcher (`parameterSets: ["ML-KEM-1024"]`).
pub struct MlKem1024KeyGenHandler;

impl AlgorithmHandler for MlKem1024KeyGenHandler {
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

/// ML-KEM encapDecap dispatcher (`parameterSets: ["ML-KEM-1024"]`,
/// `functions: ["encapsulation", "decapsulation"]`).
///
/// Per `draft-celi-acvp-ml-kem §8.2.1`, each prompt group within an
/// encapDecap vector set is tagged with a `function` field; this
/// handler dispatches to the encapsulation or decapsulation group
/// driver based on that tag. Key-check VAL functions
/// (`encapsulationKeyCheck`/`decapsulationKeyCheck`) are not
/// advertised and will be rejected with `Unsupported` if the server
/// somehow sends them under the current cap.
pub struct MlKem1024EncapDecapHandler;

impl AlgorithmHandler for MlKem1024EncapDecapHandler {
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

    // AFT is the only encaps test type the live demo server emits and
    // the only one the cap advertises support for. Reject anything
    // else explicitly.
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

        // Per `draft-celi-acvp-ml-kem §8.2.2`, both `ek` and `m` are
        // per-test fields — different test cases can exercise different
        // encapsulation keys + messages within the same group.
        let ek_bytes = hex::decode(
            t.get("ek")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("ek"))?,
        )?;
        let ek: [u8; 1568] = ek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Encaps: ek is not 1568 bytes"))?;

        let m_bytes = hex::decode(
            t.get("m")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("m"))?,
        )?;
        let m: [u8; 32] = m_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Encaps: m is not 32 bytes"))?;

        let (ss, ct) = oxicrypt_ml_kem::encaps_internal(&ek, &m);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("c".to_string(), JsonValue::String(hex::encode_upper(&ct))),
            ("k".to_string(), JsonValue::String(hex::encode_upper(&ss))),
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

    // VAL is the only decaps test type the live demo server emits
    // under the current cap (key-check VAL functions are not
    // advertised). AFT semantics don't apply to decapsulation in
    // FIPS 203 — the IUT contributes nothing of its own; server
    // supplies dk + c, IUT computes ss, server grades.
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "VAL" {
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

        // Per `draft-celi-acvp-ml-kem §8.2.2`, both `dk` and `c` are
        // per-test fields. Live wire uses field name `c` for the
        // ciphertext (not `ct` as offline kat-slice format used).
        let dk_bytes = hex::decode(
            t.get("dk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("dk"))?,
        )?;
        let dk: [u8; 3168] = dk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Decaps: dk is not 3168 bytes"))?;

        let c_bytes = hex::decode(
            t.get("c")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("c"))?,
        )?;
        let c: [u8; 1568] = c_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM-1024 Decaps: c is not 1568 bytes"))?;

        let ss = oxicrypt_ml_kem::decaps_internal(&dk, &c);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("k".to_string(), JsonValue::String(hex::encode_upper(&ss))),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
