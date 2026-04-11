//! HMAC Algorithm Functional Test (AFT) handlers for every HMAC
//! variant pqclib exposes *except* HMAC-SHA2-256, which already has
//! its own module at [`super::hmac_sha2_256`] from R10.
//!
//! Covered here:
//!
//! - `HMAC-SHA-1`      (revision `1.0`, output 20 bytes)
//! - `HMAC-SHA2-224`   (revision `1.0`, output 28 bytes)
//! - `HMAC-SHA2-384`   (revision `1.0`, output 48 bytes)
//! - `HMAC-SHA2-512`   (revision `1.0`, output 64 bytes)
//! - `HMAC-SHA2-512/224` (revision `1.0`, output 28 bytes)
//! - `HMAC-SHA2-512/256` (revision `1.0`, output 32 bytes)
//! - `HMAC-SHA3-224`   (revision `1.0`, output 28 bytes)
//! - `HMAC-SHA3-256`   (revision `1.0`, output 32 bytes)
//! - `HMAC-SHA3-384`   (revision `1.0`, output 48 bytes)
//! - `HMAC-SHA3-512`   (revision `1.0`, output 64 bytes)
//!
//! All ten share the same ACVP envelope shape: each AFT test case
//! carries `tcId`, `macLen` (in bits, byte-aligned for every vector
//! in the vendored slices at pinned commit
//! `3611942ea10c070dd8bc6afec5682d56c307de8a`), hex-encoded `key` and
//! `msg`, and produces a hex-encoded `mac` truncated to `macLen / 8`
//! leading bytes of the full HMAC output.
//!
//! Note that the SHA-512 truncated variants publish their algorithm
//! string with a slash (`HMAC-SHA2-512/224`, `HMAC-SHA2-512/256`),
//! matching the ACVP JSON exactly — not the vendored directory name
//! (`HMAC-SHA2-512-224-1.0`) which uses a hyphen.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_hmac::{
    HmacSha1, HmacSha224, HmacSha3_224, HmacSha3_256, HmacSha3_384, HmacSha3_512, HmacSha384,
    HmacSha512, HmacSha512_224, HmacSha512_256,
};

// ----------------------------------------------------------------------
// Handler structs
// ----------------------------------------------------------------------

/// HMAC-SHA-1 AFT dispatcher. Output 20 bytes.
pub struct HmacSha1Handler;

/// HMAC-SHA2-224 AFT dispatcher. Output 28 bytes.
pub struct HmacSha2_224Handler;

/// HMAC-SHA2-384 AFT dispatcher. Output 48 bytes.
pub struct HmacSha2_384Handler;

/// HMAC-SHA2-512 AFT dispatcher. Output 64 bytes.
pub struct HmacSha2_512Handler;

/// HMAC-SHA2-512/224 AFT dispatcher. Output 28 bytes.
pub struct HmacSha2_512_224Handler;

/// HMAC-SHA2-512/256 AFT dispatcher. Output 32 bytes.
pub struct HmacSha2_512_256Handler;

/// HMAC-SHA3-224 AFT dispatcher. Output 28 bytes.
pub struct HmacSha3_224Handler;

/// HMAC-SHA3-256 AFT dispatcher. Output 32 bytes.
pub struct HmacSha3_256Handler;

/// HMAC-SHA3-384 AFT dispatcher. Output 48 bytes.
pub struct HmacSha3_384Handler;

/// HMAC-SHA3-512 AFT dispatcher. Output 64 bytes.
pub struct HmacSha3_512Handler;

// ----------------------------------------------------------------------
// AlgorithmHandler impls
// ----------------------------------------------------------------------

impl AlgorithmHandler for HmacSha1Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA-1"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 20, |k, m| {
            let mut h = HmacSha1::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha1::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha2_224Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA2-224"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 28, |k, m| {
            let mut h = HmacSha224::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha224::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha2_384Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA2-384"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 48, |k, m| {
            let mut h = HmacSha384::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha384::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha2_512Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA2-512"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 64, |k, m| {
            let mut h = HmacSha512::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha512::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha2_512_224Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA2-512/224"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 28, |k, m| {
            let mut h = HmacSha512_224::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha512_224::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha2_512_256Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA2-512/256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 32, |k, m| {
            let mut h = HmacSha512_256::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha512_256::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha3_224Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA3-224"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 28, |k, m| {
            let mut h = HmacSha3_224::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha3_224::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha3_256Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA3-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 32, |k, m| {
            let mut h = HmacSha3_256::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha3_256::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha3_384Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA3-384"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 48, |k, m| {
            let mut h = HmacSha3_384::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha3_384::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

impl AlgorithmHandler for HmacSha3_512Handler {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA3-512"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hmac_group(g, 64, |k, m| {
            let mut h = HmacSha3_512::new(k)
                .map_err(|_| DispatchError::Crypto("HmacSha3_512::new returned Err"))?;
            h.update(m);
            Ok(h.finalize().to_vec())
        })
    }
}

// ----------------------------------------------------------------------
// Shared group driver
// ----------------------------------------------------------------------

/// Walks the `tests` array of an HMAC AFT group. `full_out_bytes` is
/// the untruncated HMAC output length for this algorithm in bytes;
/// `compute(key, msg)` must return exactly that many bytes. The driver
/// then truncates to `macLen / 8` leading bytes and emits the ACVP
/// response shape.
fn handle_hmac_group<F>(
    group: &JsonValue,
    full_out_bytes: usize,
    mut compute: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &[u8]) -> Result<Vec<u8>, DispatchError>,
{
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
        let mac_len_bits = t
            .get("macLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("macLen"))?;
        if !mac_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "HMAC AFT with non-byte-aligned `macLen`",
            ));
        }
        let mac_len_bytes: usize = (mac_len_bits / 8) as usize;
        if mac_len_bytes == 0 || mac_len_bytes > full_out_bytes {
            return Err(DispatchError::Crypto(
                "HMAC AFT: `macLen` outside legal range",
            ));
        }
        let key_hex = t
            .get("key")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("key"))?;
        let msg_hex = t
            .get("msg")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("msg"))?;
        let key = hex::decode(key_hex)?;
        let msg = hex::decode(msg_hex)?;
        let full = compute(&key, &msg)?;
        if full.len() != full_out_bytes {
            return Err(DispatchError::Crypto(
                "HMAC AFT: primitive returned wrong-length output",
            ));
        }
        let truncated = full
            .get(..mac_len_bytes)
            .ok_or(DispatchError::Crypto("HMAC AFT: truncate failed"))?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "mac".to_string(),
                JsonValue::String(hex::encode_upper(truncated)),
            ),
        ]));
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
