//! PBKDF2 (SP 800-132 / RFC 8018 §5.2) AFT handler.
//!
//! Targets self-generated ACVP slices with `algorithm = "PBKDF"`,
//! `revision = "1.0"`, `testType = "AFT"`.
//!
//! Each test group carries `hmacAlg` selecting the HMAC instantiation
//! (e.g. `"SHA2-256"`, `"SHA-1"`). Each test case has:
//!
//! - `password` (hex) — password
//! - `salt` (hex) — salt
//! - `iterationCount` (integer) — PBKDF2 iteration count c
//! - `keyLen` (bits) — desired derived-key length
//!
//! Response field: `derivedKey` (hex).
//!
//! Since the NIST ACVP-Server at the pinned commit ships no PBKDF
//! vector directories, all vectors are self-generated.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_kdf::{
    Pbkdf2HmacSha1, Pbkdf2HmacSha224, Pbkdf2HmacSha256, Pbkdf2HmacSha384, Pbkdf2HmacSha3_224,
    Pbkdf2HmacSha3_256, Pbkdf2HmacSha3_384, Pbkdf2HmacSha3_512, Pbkdf2HmacSha512,
    Pbkdf2HmacSha512_224, Pbkdf2HmacSha512_256,
};

/// PBKDF2 AFT handler.
pub struct Pbkdf2Handler;

impl AlgorithmHandler for Pbkdf2Handler {
    fn algorithm(&self) -> &'static str {
        "PBKDF"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_pbkdf2_group(group)
    }
}

/// Dispatch PBKDF2 derivation to the correct HMAC instantiation.
fn pbkdf2_derive(
    hmac_alg: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), DispatchError> {
    match hmac_alg {
        "SHA-1" => Pbkdf2HmacSha1::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA-1 derivation failed")),
        "SHA2-224" => Pbkdf2HmacSha224::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA-224 derivation failed")),
        "SHA2-256" => Pbkdf2HmacSha256::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA-256 derivation failed")),
        "SHA2-384" => Pbkdf2HmacSha384::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA-384 derivation failed")),
        "SHA2-512" => Pbkdf2HmacSha512::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA-512 derivation failed")),
        "SHA2-512/224" => Pbkdf2HmacSha512_224::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA-512/224 derivation failed")),
        "SHA2-512/256" => Pbkdf2HmacSha512_256::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA-512/256 derivation failed")),
        "SHA3-224" => Pbkdf2HmacSha3_224::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA3-224 derivation failed")),
        "SHA3-256" => Pbkdf2HmacSha3_256::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA3-256 derivation failed")),
        "SHA3-384" => Pbkdf2HmacSha3_384::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA3-384 derivation failed")),
        "SHA3-512" => Pbkdf2HmacSha3_512::derive(password, salt, iterations, out)
            .map_err(|_| DispatchError::Crypto("PBKDF2-HMAC-SHA3-512 derivation failed")),
        _ => Err(DispatchError::Unsupported(
            "PBKDF2: unsupported hmacAlg",
        )),
    }
}

/// Group driver for PBKDF2 AFT.
fn handle_pbkdf2_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let group_id = group
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
    let hmac_alg = group
        .get("hmacAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hmacAlg"))?;
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let tc_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let key_len_bits = t
            .get("keyLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("keyLen"))?;
        let iteration_count = t
            .get("iterationCount")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("iterationCount"))?;
        if !key_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "PBKDF2 AFT with non-byte-aligned keyLen",
            ));
        }
        let key_bytes = (key_len_bits / 8) as usize;
        let iterations = u32::try_from(iteration_count)
            .map_err(|_| DispatchError::Crypto("PBKDF2: iterationCount overflows u32"))?;

        let password_hex = t
            .get("password")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("password"))?;
        let password = if password_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(password_hex)?
        };

        let salt_hex = t
            .get("salt")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("salt"))?;
        let salt = if salt_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(salt_hex)?
        };

        let mut out = vec![0u8; key_bytes];
        pbkdf2_derive(hmac_alg, &password, &salt, iterations, &mut out)?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "derivedKey".to_string(),
                JsonValue::String(hex::encode_upper(&out)),
            ),
        ]));
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
