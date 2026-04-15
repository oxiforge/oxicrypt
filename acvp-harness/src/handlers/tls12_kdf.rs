//! TLS v1.2 KDF handler — `KDF` mode, revision `RFC7627`.
//!
//! **TLS-v1.2 / KDF / RFC7627**: Given pre-master secret, session hash,
//! client random, and server random, derive `masterSecret` (48 bytes)
//! and `keyBlock` (variable length) per RFC 7627 Extended Master Secret
//! using the TLS 1.2 PRF (RFC 5246 §5).
//!
//! Groups are keyed by `hashAlg` (`SHA2-256`, `SHA2-384`, `SHA2-512`)
//! and `keyBlockLength` (in bits). All groups carry
//! `tlsVersion = "v1.2_ems"` and `testType = "AFT"`.
//!
//! Supported hash algorithms: SHA2-256, SHA2-384, SHA2-512.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// TLS v1.2 KDF (RFC 7627) dispatcher.
pub struct Tls12KdfRfc7627Handler;

impl AlgorithmHandler for Tls12KdfRfc7627Handler {
    fn algorithm(&self) -> &'static str {
        "TLS-v1.2"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("KDF")
    }
    fn revision(&self) -> &'static str {
        "RFC7627"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tls12_kdf_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_tls12_kdf_group(group)
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Decode a hex-encoded string field from a JSON object.
fn decode_hex_field(obj: &JsonValue, name: &'static str) -> Result<Vec<u8>, DispatchError> {
    let h = obj
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(name))?;
    Ok(hex::decode(h)?)
}

// ── Group handler ──────────────────────────────────────────────────

fn handle_tls12_kdf_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;

    let key_block_length = group
        .get("keyBlockLength")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("keyBlockLength"))?;
    if key_block_length % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "TLS v1.2 KDF: keyBlockLength not byte-aligned",
        ));
    }
    let key_block_bytes = (key_block_length / 8) as usize;

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

        let pms = decode_hex_field(tc, "preMasterSecret")?;
        let session_hash = decode_hex_field(tc, "sessionHash")?;
        let client_random = decode_hex_field(tc, "clientRandom")?;
        let server_random = decode_hex_field(tc, "serverRandom")?;

        let mut key_block = vec![0u8; key_block_bytes];

        let master_secret = match hash_alg {
            "SHA2-256" => oxicrypt_tls_kdf::tls12_extended_master_secret_internal::<
                oxicrypt_hmac::HmacSha256,
                32,
            >(
                &pms,
                &session_hash,
                &server_random,
                &client_random,
                &mut key_block,
            ),
            "SHA2-384" => oxicrypt_tls_kdf::tls12_extended_master_secret_internal::<
                oxicrypt_hmac::HmacSha384,
                48,
            >(
                &pms,
                &session_hash,
                &server_random,
                &client_random,
                &mut key_block,
            ),
            "SHA2-512" => oxicrypt_tls_kdf::tls12_extended_master_secret_internal::<
                oxicrypt_hmac::HmacSha512,
                64,
            >(
                &pms,
                &session_hash,
                &server_random,
                &client_random,
                &mut key_block,
            ),
            _ => {
                return Err(DispatchError::Unsupported(
                    "TLS v1.2 KDF: unsupported hashAlg",
                ));
            }
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "masterSecret".to_string(),
                JsonValue::String(hex::encode_upper(&master_secret)),
            ),
            (
                "keyBlock".to_string(),
                JsonValue::String(hex::encode_upper(&key_block)),
            ),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
