//! KAS-FFC-SSC ACVP handler — `Component` mode, revision `Sp800-56Ar3`.
//!
//! **KAS-FFC-SSC** (`KAS-FFC-SSC` / `Component` / `Sp800-56Ar3`):
//! Given a private key `x` and the peer's public key `y`, compute the
//! Diffie-Hellman shared secret `Z = y^x mod p` per SP 800-56Ar3 §5.7.1.3.
//!
//! Supported configurations:
//! - `domainParameterGenerationMode = "DH-3072"` — 3072-bit modulus, 384-byte values

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// KAS-FFC-SSC dispatcher.
pub struct KasFfcSscHandler;

impl AlgorithmHandler for KasFfcSscHandler {
    fn algorithm(&self) -> &'static str {
        "KAS-FFC-SSC"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("Component")
    }
    fn revision(&self) -> &'static str {
        "Sp800-56Ar3"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kas_ffc_ssc_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kas_ffc_ssc_group(group)
    }
}

fn handle_kas_ffc_ssc_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let domain = group
        .get("domainParameterGenerationMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(
            "domainParameterGenerationMode",
        ))?;
    if domain != "DH-3072" {
        return Err(DispatchError::Unsupported(
            "KAS-FFC-SSC: only DH-3072 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for tc in tests {
        let test_case_id = tc
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        // Private key x (384 bytes for 3072-bit DH).
        let x_raw = hex::decode(
            tc.get("x")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("x"))?,
        )?;
        let x: [u8; 384] = x_raw
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("KAS-FFC-SSC: x is not 384 bytes"))?;

        // Peer public key y (384 bytes for 3072-bit DH).
        let y_raw = hex::decode(
            tc.get("y")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("y"))?,
        )?;
        let y: [u8; 384] = y_raw
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("KAS-FFC-SSC: y is not 384 bytes"))?;

        let z = oxicrypt_dh::compute_shared_secret_3072_internal(&x, &y)
            .ok_or(DispatchError::Crypto("KAS-FFC-SSC: DH computation failed"))?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "z".to_string(),
                JsonValue::String(hex::encode_upper(&z)),
            ),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
