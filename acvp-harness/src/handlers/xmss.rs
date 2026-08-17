//! XMSS ACVP handler — `sigVer` mode.
//!
//! **XMSS** (`XMSS` / `sigVer` / revision `1.0`): eXtended Merkle
//! Signature Scheme per SP 800-208 (RFC 8391).
//!
//! Parameter set: `XMSS-SHA2_10_256` (OID 0x00000001).
//!
//! One mode:
//! - **SigVer**: Verify a signature against a public key and message
//!
//! Key generation and signing are not dispatched: SP 800-208 §8.1
//! confines them to hardware modules, so this module implements neither.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

// ── SigGen handler ──────────────────────────────────────────────────

// ── SigVer handler ──────────────────────────────────────────────────

/// XMSS SigVer dispatcher.
pub struct XmssSigVerHandler;

impl AlgorithmHandler for XmssSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "XMSS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::xmss_sigver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── KeyGen group driver ─────────────────────────────────────────────

// ── SigGen group driver ─────────────────────────────────────────────

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

    // Group-level public key (68 bytes for XMSS-SHA2_10_256).
    let pk_bytes = hex::decode(
        group
            .get("pk")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("pk"))?,
    )?;
    let pk: [u8; oxicrypt_xmss::PUBLIC_KEY_LEN] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("XMSS SigVer: pk has wrong length"))?;

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
            if let Ok(sig) = <[u8; oxicrypt_xmss::SIGNATURE_LEN]>::try_from(sig_bytes.as_slice()) {
                oxicrypt_xmss::verify_internal(&pk, &message, &sig)
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
