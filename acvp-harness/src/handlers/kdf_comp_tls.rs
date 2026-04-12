//! kdf-components / tls handler — revision `1.0`.
//!
//! **kdf-components / tls / 1.0**: Standard TLS 1.2 KDF (non-EMS)
//! per RFC 5246 §8.1 + §6.3. Given pre-master secret, client/server
//! hello randoms, and client/server randoms, derive `masterSecret`
//! (48 bytes) and `keyBlock` (variable length).
//!
//! The slim slice includes only TLS v1.2 groups (SHA2-based PRF);
//! TLS v1.0/1.1 groups require the combined MD5+SHA-1 PRF which is
//! out of scope (MD5 is not FIPS-approved).
//!
//! Supported hash algorithms: SHA2-256, SHA2-384, SHA2-512.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// kdf-components / tls dispatcher.
pub struct KdfComponentsTlsHandler;

impl AlgorithmHandler for KdfComponentsTlsHandler {
    fn algorithm(&self) -> &'static str {
        "kdf-components"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("tls")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kdf_comp_tls_group(group)
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

#[allow(clippy::too_many_lines)]
fn handle_kdf_comp_tls_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let tls_version = group
        .get("tlsVersion")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("tlsVersion"))?;
    if tls_version != "v1.2" {
        return Err(DispatchError::Unsupported(
            "kdf-components/tls: only TLS v1.2 is supported (v1.0/1.1 needs MD5)",
        ));
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
            "kdf-components/tls: keyBlockLength not byte-aligned",
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
        let client_hello_random = decode_hex_field(tc, "clientHelloRandom")?;
        let server_hello_random = decode_hex_field(tc, "serverHelloRandom")?;
        let client_random = decode_hex_field(tc, "clientRandom")?;
        let server_random = decode_hex_field(tc, "serverRandom")?;

        let mut key_block = vec![0u8; key_block_bytes];

        let master_secret = match hash_alg {
            "SHA2-256" => {
                fips_tls_kdf::tls12_master_secret_internal::<fips_hmac::HmacSha256, 32>(
                    &pms,
                    &client_hello_random,
                    &server_hello_random,
                    &server_random,
                    &client_random,
                    &mut key_block,
                )
            }
            "SHA2-384" => {
                fips_tls_kdf::tls12_master_secret_internal::<fips_hmac::HmacSha384, 48>(
                    &pms,
                    &client_hello_random,
                    &server_hello_random,
                    &server_random,
                    &client_random,
                    &mut key_block,
                )
            }
            "SHA2-512" => {
                fips_tls_kdf::tls12_master_secret_internal::<fips_hmac::HmacSha512, 64>(
                    &pms,
                    &client_hello_random,
                    &server_hello_random,
                    &server_random,
                    &client_random,
                    &mut key_block,
                )
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "kdf-components/tls: unsupported hashAlg",
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
