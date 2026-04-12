//! SP 800-108r1 KBKDF AFT handler (`KDF`, revision `1.0`).
//!
//! A single handler struct [`KbkdfHandler`] registers on the
//! single-field dispatch key `(algorithm="KDF", revision="1.0")`.
//! Each test group carries `kdfMode` (`"counter"` /
//! `"feedback"` / `"double pipeline iteration"`) and `macMode`
//! (`"HMAC-SHA-1"`, `"HMAC-SHA2-256"`, etc.), which together
//! select the concrete `Sp800_108*Hmac*` type alias from
//! `fips_kdf`.
//!
//! Counter-mode groups use `counterLocation = "before fixed data"`
//! and `counterLength = 32` — the only layout the pqclib
//! `Sp800_108Counter` implementation supports. Feedback groups
//! carry `zeroLengthIv`; when `false`, each test supplies an `iv`
//! field. Double-pipeline groups carry no IV and no counter.
//!
//! Each AFT test case provides `keyIn` (the PRF key), `fixedData`
//! (the pre-assembled fixed-input string), and `keyOut` (the
//! expected derived key). The handler writes `keyOut` back to the
//! response (hex-encoded).

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_kdf::{
    Sp800_108CounterHmacSha1, Sp800_108CounterHmacSha224, Sp800_108CounterHmacSha256,
    Sp800_108CounterHmacSha384, Sp800_108CounterHmacSha3_224, Sp800_108CounterHmacSha3_256,
    Sp800_108CounterHmacSha3_384, Sp800_108CounterHmacSha3_512, Sp800_108CounterHmacSha512,
    Sp800_108CounterHmacSha512_224, Sp800_108CounterHmacSha512_256,
    Sp800_108DoublePipelineHmacSha1, Sp800_108DoublePipelineHmacSha224,
    Sp800_108DoublePipelineHmacSha256, Sp800_108DoublePipelineHmacSha384,
    Sp800_108DoublePipelineHmacSha3_224, Sp800_108DoublePipelineHmacSha3_256,
    Sp800_108DoublePipelineHmacSha3_384, Sp800_108DoublePipelineHmacSha3_512,
    Sp800_108DoublePipelineHmacSha512, Sp800_108DoublePipelineHmacSha512_224,
    Sp800_108DoublePipelineHmacSha512_256, Sp800_108FeedbackHmacSha1,
    Sp800_108FeedbackHmacSha224, Sp800_108FeedbackHmacSha256, Sp800_108FeedbackHmacSha384,
    Sp800_108FeedbackHmacSha3_224, Sp800_108FeedbackHmacSha3_256,
    Sp800_108FeedbackHmacSha3_384, Sp800_108FeedbackHmacSha3_512,
    Sp800_108FeedbackHmacSha512, Sp800_108FeedbackHmacSha512_224,
    Sp800_108FeedbackHmacSha512_256,
};

// ── Handler struct ──────────────────────────────────────────────────

/// SP 800-108r1 KBKDF AFT handler (counter / feedback / double pipeline,
/// eleven HMAC instantiations each).
pub struct KbkdfHandler;

impl AlgorithmHandler for KbkdfHandler {
    fn algorithm(&self) -> &'static str {
        "KDF"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kbkdf_group(group)
    }
}

// ── Internal dispatch ───────────────────────────────────────────────

/// Derive function pointer type for counter / double-pipeline modes
/// (key, fixed_data, out) → Result.
type DeriveFn = fn(&[u8], &[u8], &mut [u8]) -> Result<(), fips_kdf::KdfError>;

/// Derive function pointer type for feedback mode
/// (key, iv, fixed_data, out) → Result.
type DeriveFbFn = fn(&[u8], &[u8], &[u8], &mut [u8]) -> Result<(), fips_kdf::KdfError>;

/// Decode a hex-encoded string field from a JSON object.
fn decode_hex_field(obj: &JsonValue, name: &'static str) -> Result<Vec<u8>, DispatchError> {
    let h = obj
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(name))?;
    Ok(hex::decode(h)?)
}

#[allow(clippy::too_many_lines)]
fn handle_kbkdf_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let kdf_mode = group
        .get("kdfMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("kdfMode"))?;

    let mac_mode = group
        .get("macMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("macMode"))?;

    let key_out_bits: usize = group
        .get("keyOutLength")
        .and_then(JsonValue::as_u64)
        .and_then(|v| usize::try_from(v).ok())
        .ok_or(DispatchError::MissingField("keyOutLength"))?;
    let key_out_len = key_out_bits.div_ceil(8);

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match kdf_mode {
        "counter" => {
            // Validate counter placement assumptions.
            let counter_loc = group
                .get("counterLocation")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("counterLocation"))?;
            if counter_loc != "before fixed data" {
                return Err(DispatchError::Unsupported(
                    "KDF counter: only counterLocation=\"before fixed data\" supported",
                ));
            }
            let counter_len: usize = group
                .get("counterLength")
                .and_then(JsonValue::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .ok_or(DispatchError::MissingField("counterLength"))?;
            if counter_len != 32 {
                return Err(DispatchError::Unsupported(
                    "KDF counter: only counterLength=32 supported",
                ));
            }

            let derive_fn = counter_derive_fn(mac_mode)?;
            for tc in tests {
                results.push(run_kdf_test(tc, key_out_len, |key, fd, out| {
                    derive_fn(key, fd, out)
                })?);
            }
        }
        "feedback" => {
            let zero_length_iv = group
                .get("zeroLengthIv")
                .and_then(JsonValue::as_bool)
                .unwrap_or(true);
            let derive_fn = feedback_derive_fn(mac_mode)?;
            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let key_in = decode_hex_field(tc, "keyIn")?;
                let fixed_data = decode_hex_field(tc, "fixedData")?;
                let iv = if zero_length_iv {
                    Vec::new()
                } else {
                    decode_hex_field(tc, "iv")?
                };
                let mut key_out = vec![0u8; key_out_len];
                derive_fn(&key_in, &iv, &fixed_data, &mut key_out)
                    .map_err(|_| DispatchError::Crypto("KDF feedback derive failed"))?;
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "keyOut".to_string(),
                        JsonValue::String(hex::encode_upper(&key_out)),
                    ),
                ]));
            }
        }
        "double pipeline iteration" => {
            let derive_fn = double_pipeline_derive_fn(mac_mode)?;
            for tc in tests {
                results.push(run_kdf_test(tc, key_out_len, |key, fd, out| {
                    derive_fn(key, fd, out)
                })?);
            }
        }
        _ => {
            return Err(DispatchError::Unsupported("KDF: unknown kdfMode"));
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

/// Run a single counter-mode or double-pipeline test case — both have
/// the same `(keyIn, fixedData) → keyOut` shape.
fn run_kdf_test(
    tc: &JsonValue,
    key_out_len: usize,
    derive: impl Fn(&[u8], &[u8], &mut [u8]) -> Result<(), fips_kdf::KdfError>,
) -> Result<JsonValue, DispatchError> {
    let test_case_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let key_in = decode_hex_field(tc, "keyIn")?;
    let fixed_data = decode_hex_field(tc, "fixedData")?;
    let mut key_out = vec![0u8; key_out_len];
    derive(&key_in, &fixed_data, &mut key_out)
        .map_err(|_| DispatchError::Crypto("KDF derive failed"))?;
    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(test_case_id)),
        (
            "keyOut".to_string(),
            JsonValue::String(hex::encode_upper(&key_out)),
        ),
    ]))
}

// ── MAC-mode → derive function selectors ────────────────────────────

fn counter_derive_fn(mac_mode: &str) -> Result<DeriveFn, DispatchError> {
    match mac_mode {
        "HMAC-SHA-1" => Ok(Sp800_108CounterHmacSha1::derive_with_fixed_data_internal),
        "HMAC-SHA2-224" => Ok(Sp800_108CounterHmacSha224::derive_with_fixed_data_internal),
        "HMAC-SHA2-256" => Ok(Sp800_108CounterHmacSha256::derive_with_fixed_data_internal),
        "HMAC-SHA2-384" => Ok(Sp800_108CounterHmacSha384::derive_with_fixed_data_internal),
        "HMAC-SHA2-512" => Ok(Sp800_108CounterHmacSha512::derive_with_fixed_data_internal),
        "HMAC-SHA2-512/224" => Ok(Sp800_108CounterHmacSha512_224::derive_with_fixed_data_internal),
        "HMAC-SHA2-512/256" => Ok(Sp800_108CounterHmacSha512_256::derive_with_fixed_data_internal),
        "HMAC-SHA3-224" => Ok(Sp800_108CounterHmacSha3_224::derive_with_fixed_data_internal),
        "HMAC-SHA3-256" => Ok(Sp800_108CounterHmacSha3_256::derive_with_fixed_data_internal),
        "HMAC-SHA3-384" => Ok(Sp800_108CounterHmacSha3_384::derive_with_fixed_data_internal),
        "HMAC-SHA3-512" => Ok(Sp800_108CounterHmacSha3_512::derive_with_fixed_data_internal),
        _ => Err(DispatchError::Unsupported(
            "KDF counter: unsupported macMode",
        )),
    }
}

fn feedback_derive_fn(mac_mode: &str) -> Result<DeriveFbFn, DispatchError> {
    match mac_mode {
        "HMAC-SHA-1" => Ok(Sp800_108FeedbackHmacSha1::derive_with_fixed_data_internal),
        "HMAC-SHA2-224" => Ok(Sp800_108FeedbackHmacSha224::derive_with_fixed_data_internal),
        "HMAC-SHA2-256" => Ok(Sp800_108FeedbackHmacSha256::derive_with_fixed_data_internal),
        "HMAC-SHA2-384" => Ok(Sp800_108FeedbackHmacSha384::derive_with_fixed_data_internal),
        "HMAC-SHA2-512" => Ok(Sp800_108FeedbackHmacSha512::derive_with_fixed_data_internal),
        "HMAC-SHA2-512/224" => Ok(Sp800_108FeedbackHmacSha512_224::derive_with_fixed_data_internal),
        "HMAC-SHA2-512/256" => Ok(Sp800_108FeedbackHmacSha512_256::derive_with_fixed_data_internal),
        "HMAC-SHA3-224" => Ok(Sp800_108FeedbackHmacSha3_224::derive_with_fixed_data_internal),
        "HMAC-SHA3-256" => Ok(Sp800_108FeedbackHmacSha3_256::derive_with_fixed_data_internal),
        "HMAC-SHA3-384" => Ok(Sp800_108FeedbackHmacSha3_384::derive_with_fixed_data_internal),
        "HMAC-SHA3-512" => Ok(Sp800_108FeedbackHmacSha3_512::derive_with_fixed_data_internal),
        _ => Err(DispatchError::Unsupported(
            "KDF feedback: unsupported macMode",
        )),
    }
}

fn double_pipeline_derive_fn(mac_mode: &str) -> Result<DeriveFn, DispatchError> {
    match mac_mode {
        "HMAC-SHA-1" => Ok(Sp800_108DoublePipelineHmacSha1::derive_with_fixed_data_internal),
        "HMAC-SHA2-224" => Ok(Sp800_108DoublePipelineHmacSha224::derive_with_fixed_data_internal),
        "HMAC-SHA2-256" => Ok(Sp800_108DoublePipelineHmacSha256::derive_with_fixed_data_internal),
        "HMAC-SHA2-384" => Ok(Sp800_108DoublePipelineHmacSha384::derive_with_fixed_data_internal),
        "HMAC-SHA2-512" => Ok(Sp800_108DoublePipelineHmacSha512::derive_with_fixed_data_internal),
        "HMAC-SHA2-512/224" => {
            Ok(Sp800_108DoublePipelineHmacSha512_224::derive_with_fixed_data_internal)
        }
        "HMAC-SHA2-512/256" => {
            Ok(Sp800_108DoublePipelineHmacSha512_256::derive_with_fixed_data_internal)
        }
        "HMAC-SHA3-224" => {
            Ok(Sp800_108DoublePipelineHmacSha3_224::derive_with_fixed_data_internal)
        }
        "HMAC-SHA3-256" => {
            Ok(Sp800_108DoublePipelineHmacSha3_256::derive_with_fixed_data_internal)
        }
        "HMAC-SHA3-384" => {
            Ok(Sp800_108DoublePipelineHmacSha3_384::derive_with_fixed_data_internal)
        }
        "HMAC-SHA3-512" => {
            Ok(Sp800_108DoublePipelineHmacSha3_512::derive_with_fixed_data_internal)
        }
        _ => Err(DispatchError::Unsupported(
            "KDF double pipeline: unsupported macMode",
        )),
    }
}
