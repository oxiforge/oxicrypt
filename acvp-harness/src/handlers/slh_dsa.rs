//! SLH-DSA ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes per FIPS 205.
//!
//! Three handlers, mirroring the catalog's three-mode shape (see
//! `draft-livelsberger-acvp-slh-dsa §7.3` / `§7.4` / `§7.5`):
//!
//! - **`SlhDsaKeyGenHandler`** — `SLH-DSA` / `keyGen` / `FIPS205`,
//!   advertising `parameterSets: ["SLH-DSA-SHA2-256s"]`. Generates a
//!   (public key, secret key) pair from a 96-byte seed split into
//!   three 32-byte components (`SK.seed ‖ SK.prf ‖ PK.seed`).
//! - **`SlhDsaSigGenHandler`** — `SLH-DSA` / `sigGen` / `FIPS205`,
//!   advertising `deterministic: [true]`,
//!   `signatureInterfaces: ["internal"]`, `preHash: ["pure"]`. Signs
//!   a message deterministically (FIPS 205 §10.2 Algorithm 22 with
//!   `opt_rand = PK.seed`).
//! - **`SlhDsaSigVerHandler`** — `SLH-DSA` / `sigVer` / `FIPS205`,
//!   same interface/pre-hash advertisement as sigGen. Verifies a
//!   signature against a public key and message.
//!
//! Only `SLH-DSA-SHA2-256s` (CNSA 2.0 baseline) is currently
//! advertised; the 11 other FIPS 205 §11 Table 2 parameter sets are
//! PQ-expansion-mandate items (`algo-capability-matrix.md` rows
//! 202-213) and will be added to `parameterSets` when their
//! `*_internal` + public-API surfaces ship. The `algorithm()` value
//! is the family name `"SLH-DSA"` (matching the live ACVP catalog) —
//! not parameter-set-baked — so adding new parameter sets is a
//! cap-only change with no handler-name churn.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// SLH-DSA keyGen dispatcher (`parameterSets: ["SLH-DSA-SHA2-256s"]`).
pub struct SlhDsaKeyGenHandler;

impl AlgorithmHandler for SlhDsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS205"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// SLH-DSA sigGen dispatcher (deterministic, internal interface, pure
/// mode; `parameterSets: ["SLH-DSA-SHA2-256s"]`).
pub struct SlhDsaSigGenHandler;

impl AlgorithmHandler for SlhDsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS205"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_siggen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── SigVer handler ──────────────────────────────────────────────────

/// SLH-DSA sigVer dispatcher (internal interface, pure mode;
/// `parameterSets: ["SLH-DSA-SHA2-256s"]`).
pub struct SlhDsaSigVerHandler;

impl AlgorithmHandler for SlhDsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS205"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_sigver_capability())
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

        // Per slh-dsa §8.1.2 Table 10, the keyGen test case carries three
        // separate hex fields: skSeed, skPrf, pkSeed (each N = 32 B for
        // SLH-DSA-SHA2-256s). The primitive consumes the 96-byte
        // concatenation skSeed ‖ skPrf ‖ pkSeed; the handler assembles
        // it locally from the per-field prompt values.
        let sk_seed_bytes = hex::decode(
            t.get("skSeed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("skSeed"))?,
        )?;
        let sk_prf_bytes = hex::decode(
            t.get("skPrf")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("skPrf"))?,
        )?;
        let pk_seed_bytes = hex::decode(
            t.get("pkSeed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("pkSeed"))?,
        )?;
        if sk_seed_bytes.len() != 32 {
            return Err(DispatchError::Crypto(
                "SLH-DSA KeyGen: skSeed is not 32 bytes",
            ));
        }
        if sk_prf_bytes.len() != 32 {
            return Err(DispatchError::Crypto(
                "SLH-DSA KeyGen: skPrf is not 32 bytes",
            ));
        }
        if pk_seed_bytes.len() != 32 {
            return Err(DispatchError::Crypto(
                "SLH-DSA KeyGen: pkSeed is not 32 bytes",
            ));
        }
        let mut seed = [0u8; 96];
        seed[..32].copy_from_slice(&sk_seed_bytes);
        seed[32..64].copy_from_slice(&sk_prf_bytes);
        seed[64..].copy_from_slice(&pk_seed_bytes);

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

        // Per `draft-livelsberger-acvp-slh-dsa §8.2.2`, both `sk` and
        // `message` are per-test fields — different test cases can
        // exercise different secret keys + messages within the same
        // group.
        let sk_bytes = hex::decode(
            t.get("sk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("sk"))?,
        )?;
        let sk: [u8; oxicrypt_slh_dsa::SK_LEN] = sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("SLH-DSA SigGen: sk has wrong length"))?;

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

        // Per `draft-livelsberger-acvp-slh-dsa §8.3.2`, `pk`,
        // `message`, and `signature` are all per-test fields. Server
        // mixes valid and tampered (key-flip) signatures within the
        // same group; the IUT returns `testPassed: bool` per case
        // and the server grades by exact-match against the expected
        // valid/invalid disposition.
        let pk_bytes = hex::decode(
            t.get("pk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("pk"))?,
        )?;
        let pk: [u8; oxicrypt_slh_dsa::PK_LEN] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("SLH-DSA SigVer: pk has wrong length"))?;

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
