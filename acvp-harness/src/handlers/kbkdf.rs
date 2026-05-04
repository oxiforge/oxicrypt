//! SP 800-108r1 KBKDF AFT handler (`KDF`, revision `1.0`).
//!
//! A single handler struct [`KbkdfHandler`] registers on the
//! single-field dispatch key `(algorithm="KDF", revision="1.0")`.
//! Each test group carries `kdfMode` (`"counter"` /
//! `"feedback"` / `"double pipeline iteration"`) and `macMode`
//! (`"HMAC-SHA-1"`, `"HMAC-SHA2-256"`, etc.), which together
//! select the concrete `Sp800_108*Hmac*` type alias from
//! `oxicrypt_kdf`.
//!
//! Counter-mode groups use `counterLocation = "before fixed data"`
//! and `counterLength = 32` — the only layout the oxicrypt
//! `Sp800_108Counter` implementation supports. Feedback groups
//! carry `zeroLengthIv`; when `false`, the IUT samples an `iv`
//! of length equal to the PRF output and echoes it in the
//! response. Double-pipeline groups carry no IV and no counter.
//!
//! Two test shapes are supported per group:
//!
//! - **Deterministic** — each test carries `keyIn` and a pre-built
//!   `fixedData` blob (and `iv` for feedback when not zeroLengthIv).
//!   The handler dispatches the upstream
//!   `derive_with_fixed_data_internal` and echoes only `keyOut`.
//! - **Generative AFT** — each test carries only `keyIn`. The IUT
//!   samples its own Label (16 bytes) and Context (16 bytes) via
//!   [`os_entropy::read_os_entropy`], assembles
//!   `fixedData = Label || 0x00 || Context || [L]_32` per
//!   SP 800-108 §5.2, derives `keyOut`, and echoes both `keyOut`
//!   and `fixedData` (and `iv` for non-zeroLengthIv feedback).
//!
//! Detection is per-test (`fixedData` field present → deterministic;
//! absent → generative). Mixed-shape groups dispatch correctly.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::handlers::os_entropy::read_os_entropy;
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_kdf::{
    Sp800_108CounterHmacSha1, Sp800_108CounterHmacSha224, Sp800_108CounterHmacSha256,
    Sp800_108CounterHmacSha384, Sp800_108CounterHmacSha3_224, Sp800_108CounterHmacSha3_256,
    Sp800_108CounterHmacSha3_384, Sp800_108CounterHmacSha3_512, Sp800_108CounterHmacSha512,
    Sp800_108CounterHmacSha512_224, Sp800_108CounterHmacSha512_256,
    Sp800_108DoublePipelineHmacSha1, Sp800_108DoublePipelineHmacSha224,
    Sp800_108DoublePipelineHmacSha256, Sp800_108DoublePipelineHmacSha384,
    Sp800_108DoublePipelineHmacSha3_224, Sp800_108DoublePipelineHmacSha3_256,
    Sp800_108DoublePipelineHmacSha3_384, Sp800_108DoublePipelineHmacSha3_512,
    Sp800_108DoublePipelineHmacSha512, Sp800_108DoublePipelineHmacSha512_224,
    Sp800_108DoublePipelineHmacSha512_256, Sp800_108FeedbackHmacSha1, Sp800_108FeedbackHmacSha224,
    Sp800_108FeedbackHmacSha256, Sp800_108FeedbackHmacSha384, Sp800_108FeedbackHmacSha3_224,
    Sp800_108FeedbackHmacSha3_256, Sp800_108FeedbackHmacSha3_384, Sp800_108FeedbackHmacSha3_512,
    Sp800_108FeedbackHmacSha512, Sp800_108FeedbackHmacSha512_224, Sp800_108FeedbackHmacSha512_256,
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kbkdf_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kbkdf_group(group)
    }
}

// ── Internal dispatch ───────────────────────────────────────────────

/// Derive function pointer type for counter / double-pipeline modes
/// (key, fixed_data, out) → Result.
type DeriveFn = fn(&[u8], &[u8], &mut [u8]) -> Result<(), oxicrypt_kdf::KdfError>;

/// Derive function pointer type for feedback mode
/// (key, iv, fixed_data, out) → Result.
type DeriveFbFn = fn(&[u8], &[u8], &[u8], &mut [u8]) -> Result<(), oxicrypt_kdf::KdfError>;

/// Decode a hex-encoded string field from a JSON object.
fn decode_hex_field(obj: &JsonValue, name: &'static str) -> Result<Vec<u8>, DispatchError> {
    let h = obj
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(name))?;
    Ok(hex::decode(h)?)
}

/// PRF output length in bytes for the supported HMAC modes. Used to
/// size the IV the IUT samples in feedback-mode generative AFT when
/// `zeroLengthIv = false`. The match is exhaustive over the same
/// macMode strings the derive selectors handle below; reaching the
/// fallback means the selector check that runs first failed to gate
/// an unsupported macMode — surfaces as a recognisable derive failure
/// downstream rather than an out-of-bounds IV length.
fn mac_output_len(mac_mode: &str) -> Option<usize> {
    match mac_mode {
        "HMAC-SHA-1" => Some(20),
        "HMAC-SHA2-224" | "HMAC-SHA2-512/224" | "HMAC-SHA3-224" => Some(28),
        "HMAC-SHA2-256" | "HMAC-SHA2-512/256" | "HMAC-SHA3-256" => Some(32),
        "HMAC-SHA2-384" | "HMAC-SHA3-384" => Some(48),
        "HMAC-SHA2-512" | "HMAC-SHA3-512" => Some(64),
        _ => None,
    }
}

/// Sample a fresh `Label || 0x00 || Context || [L]_32` blob per
/// SP 800-108 §5.2. `key_out_bits` is the encoded `[L]_32` bit-length
/// the test group asks for. Label and context are drawn from a single
/// 32-byte `/dev/urandom` read to halve the syscall count across the
/// per-test loop.
fn sample_fixed_data(key_out_bits: u32) -> Result<Vec<u8>, DispatchError> {
    let mut buf = [0u8; 32];
    read_os_entropy(&mut buf)?;
    let label = &buf[..16];
    let context = &buf[16..];
    let mut fixed = Vec::with_capacity(label.len() + 1 + context.len() + 4);
    fixed.extend_from_slice(label);
    fixed.push(0x00);
    fixed.extend_from_slice(context);
    fixed.extend_from_slice(&key_out_bits.to_be_bytes());
    Ok(fixed)
}

/// True when the per-test prompt is the generative-AFT shape (no
/// pre-built `fixedData` field). Single decision site for both the
/// counter/double-pipeline and feedback dispatch helpers.
fn is_generative(tc: &JsonValue) -> bool {
    tc.get("fixedData").and_then(JsonValue::as_str).is_none()
}

/// Build the response object for one test. `fixed_data` and `iv` are
/// echoed only when `Some`, matching the generative-vs-deterministic
/// shape rule (deterministic responses carry only `keyOut`).
fn build_response_fields(
    tc_id: i64,
    key_out: &[u8],
    fixed_data: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> JsonValue {
    let mut fields = Vec::with_capacity(4);
    fields.push(("tcId".to_string(), JsonValue::Number(tc_id)));
    fields.push((
        "keyOut".to_string(),
        JsonValue::String(hex::encode_upper(key_out)),
    ));
    if let Some(fd) = fixed_data {
        fields.push((
            "fixedData".to_string(),
            JsonValue::String(hex::encode_upper(fd)),
        ));
    }
    if let Some(iv_bytes) = iv {
        fields.push((
            "iv".to_string(),
            JsonValue::String(hex::encode_upper(iv_bytes)),
        ));
    }
    JsonValue::Object(fields)
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

    let key_out_bits_u64: u64 = group
        .get("keyOutLength")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("keyOutLength"))?;
    let key_out_bits: u32 = u32::try_from(key_out_bits_u64)
        .map_err(|_| DispatchError::Crypto("keyOutLength > 2^32 bits"))?;
    let key_out_len = usize::try_from(key_out_bits_u64)
        .map_err(|_| DispatchError::Crypto("keyOutLength bit count exceeds usize"))?
        .div_ceil(8);

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match kdf_mode {
        "counter" => {
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
                results.push(run_kdf_counter_or_dp_test(
                    tc,
                    key_out_len,
                    key_out_bits,
                    derive_fn,
                )?);
            }
        }
        "feedback" => {
            let zero_length_iv = group
                .get("zeroLengthIv")
                .and_then(JsonValue::as_bool)
                .unwrap_or(true);
            let derive_fn = feedback_derive_fn(mac_mode)?;
            let iv_len = if zero_length_iv {
                0
            } else {
                mac_output_len(mac_mode).ok_or(DispatchError::Unsupported(
                    "KDF feedback: unsupported macMode for IV sizing",
                ))?
            };
            for tc in tests {
                results.push(run_kdf_feedback_test(
                    tc,
                    key_out_len,
                    key_out_bits,
                    iv_len,
                    derive_fn,
                )?);
            }
        }
        "double pipeline iteration" => {
            let derive_fn = double_pipeline_derive_fn(mac_mode)?;
            for tc in tests {
                results.push(run_kdf_counter_or_dp_test(
                    tc,
                    key_out_len,
                    key_out_bits,
                    derive_fn,
                )?);
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

/// Run one counter-mode or double-pipeline test. Detects deterministic
/// vs generative shape per test (not per group), so a group whose tests
/// mix the two shapes still dispatches correctly.
fn run_kdf_counter_or_dp_test(
    tc: &JsonValue,
    key_out_len: usize,
    key_out_bits: u32,
    derive: DeriveFn,
) -> Result<JsonValue, DispatchError> {
    let test_case_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let key_in = decode_hex_field(tc, "keyIn")?;

    let generative = is_generative(tc);
    let fixed_data = if generative {
        sample_fixed_data(key_out_bits)?
    } else {
        decode_hex_field(tc, "fixedData")?
    };

    let mut key_out = vec![0u8; key_out_len];
    derive(&key_in, &fixed_data, &mut key_out)
        .map_err(|_| DispatchError::Crypto("KDF derive failed"))?;

    Ok(build_response_fields(
        test_case_id,
        &key_out,
        generative.then_some(fixed_data.as_slice()),
        None,
    ))
}

/// Run one feedback-mode test. Detects deterministic vs generative
/// shape per test. When generative AND `iv_len > 0` (i.e. the group's
/// `zeroLengthIv = false`), the IV is sampled fresh and echoed in the
/// response alongside `fixedData`.
fn run_kdf_feedback_test(
    tc: &JsonValue,
    key_out_len: usize,
    key_out_bits: u32,
    iv_len: usize,
    derive: DeriveFbFn,
) -> Result<JsonValue, DispatchError> {
    let test_case_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let key_in = decode_hex_field(tc, "keyIn")?;

    let generative = is_generative(tc);
    let fixed_data = if generative {
        sample_fixed_data(key_out_bits)?
    } else {
        decode_hex_field(tc, "fixedData")?
    };

    // IV decision is anchored on shape first: deterministic prompts
    // own the IV (per-test `iv` field, or empty when zeroLengthIv);
    // generative prompts sample IV when the group requires one.
    let iv = if generative {
        if iv_len == 0 {
            Vec::new()
        } else {
            let mut v = vec![0u8; iv_len];
            read_os_entropy(&mut v)?;
            v
        }
    } else if iv_len == 0 {
        Vec::new()
    } else {
        decode_hex_field(tc, "iv")?
    };

    let mut key_out = vec![0u8; key_out_len];
    derive(&key_in, &iv, &fixed_data, &mut key_out)
        .map_err(|_| DispatchError::Crypto("KDF feedback derive failed"))?;

    let echoed_iv = if generative && iv_len > 0 {
        Some(iv.as_slice())
    } else {
        None
    };
    Ok(build_response_fields(
        test_case_id,
        &key_out,
        generative.then_some(fixed_data.as_slice()),
        echoed_iv,
    ))
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
        "HMAC-SHA3-224" => Ok(Sp800_108DoublePipelineHmacSha3_224::derive_with_fixed_data_internal),
        "HMAC-SHA3-256" => Ok(Sp800_108DoublePipelineHmacSha3_256::derive_with_fixed_data_internal),
        "HMAC-SHA3-384" => Ok(Sp800_108DoublePipelineHmacSha3_384::derive_with_fixed_data_internal),
        "HMAC-SHA3-512" => Ok(Sp800_108DoublePipelineHmacSha3_512::derive_with_fixed_data_internal),
        _ => Err(DispatchError::Unsupported(
            "KDF double pipeline: unsupported macMode",
        )),
    }
}
