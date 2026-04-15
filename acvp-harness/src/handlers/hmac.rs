//! HMAC AFT and MVT handlers for every HMAC variant oxicrypt exposes
//! *except* HMAC-SHA2-256, which already has its own module at
//! [`super::hmac_sha2_256`] from R10.
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
//! **AFT** (Algorithm Functional Test): each test case carries `tcId`,
//! `macLen` (in bits, byte-aligned), hex-encoded `key` and `msg`, and
//! produces a hex-encoded `mac` truncated to `macLen / 8` leading bytes.
//!
//! **MVT** (MAC Verification Test): each test case carries the same
//! fields as AFT plus a hex-encoded `mac` expected value. The handler
//! computes the HMAC, compares against the expected value, and returns
//! a `testPassed` boolean.
//!
//! Note that the SHA-512 truncated variants publish their algorithm
//! string with a slash (`HMAC-SHA2-512/224`, `HMAC-SHA2-512/256`),
//! matching the ACVP JSON exactly — not the vendored directory name
//! (`HMAC-SHA2-512-224-1.0`) which uses a hyphen.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_hmac::{
    HmacSha1, HmacSha224, HmacSha384, HmacSha3_224, HmacSha3_256, HmacSha3_384, HmacSha3_512,
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA-1", 160))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA2-224", 224))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA2-384", 384))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA2-512", 512))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA2-512/224", 224))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA2-512/256", 256))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA3-224", 224))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA3-256", 256))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA3-384", 384))
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::hmac_capability("HMAC-SHA3-512", 512))
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
// Test-type enum and shared types
// ----------------------------------------------------------------------

/// HMAC test type — AFT (compute and return MAC) or MVT (verify MAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HmacTestType {
    Aft,
    Mvt,
}

/// Parsed per-test inputs shared by both AFT and MVT paths.
struct HmacTestInputs {
    key: Vec<u8>,
    msg: Vec<u8>,
    mac_bytes: usize,
}

/// Parse the common per-test fields (key, msg, macLen).
fn parse_hmac_test(
    t: &JsonValue,
    full_out_bytes: usize,
) -> Result<(i64, HmacTestInputs), DispatchError> {
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
            "HMAC with non-byte-aligned `macLen`",
        ));
    }
    let mac_bytes: usize = (mac_len_bits / 8) as usize;
    if mac_bytes == 0 || mac_bytes > full_out_bytes {
        return Err(DispatchError::Crypto("HMAC: `macLen` outside legal range"));
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
    Ok((
        tc_id,
        HmacTestInputs {
            key,
            msg,
            mac_bytes,
        },
    ))
}

// ----------------------------------------------------------------------
// Shared group driver
// ----------------------------------------------------------------------

/// Walks the `tests` array of an HMAC AFT or MVT group.
/// `full_out_bytes` is the untruncated HMAC output length for this
/// algorithm in bytes; `compute(key, msg)` must return exactly that
/// many bytes.
///
/// - **AFT**: truncates to `macLen / 8` leading bytes and returns
///   the hex-encoded `mac`.
/// - **MVT**: computes the MAC, compares against the supplied `mac`
///   field, and returns `testPassed`.
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
    let test_type_str = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    let test_type = match test_type_str {
        "AFT" => HmacTestType::Aft,
        "MVT" => HmacTestType::Mvt,
        other => return Err(DispatchError::UnsupportedTestType(other.to_string())),
    };
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let (tc_id, inputs) = parse_hmac_test(t, full_out_bytes)?;
        let full = compute(&inputs.key, &inputs.msg)?;
        if full.len() != full_out_bytes {
            return Err(DispatchError::Crypto(
                "HMAC: primitive returned wrong-length output",
            ));
        }
        let truncated = full
            .get(..inputs.mac_bytes)
            .ok_or(DispatchError::Crypto("HMAC: truncate failed"))?;
        let result = match test_type {
            HmacTestType::Aft => JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(tc_id)),
                (
                    "mac".to_string(),
                    JsonValue::String(hex::encode_upper(truncated)),
                ),
            ]),
            HmacTestType::Mvt => {
                let expected_hex = t
                    .get("mac")
                    .and_then(JsonValue::as_str)
                    .ok_or(DispatchError::MissingField("mac"))?;
                let expected_mac = hex::decode(expected_hex)?;
                let passed = truncated == expected_mac.as_slice();
                JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    ("testPassed".to_string(), JsonValue::Bool(passed)),
                ])
            }
        };
        results.push(result);
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
