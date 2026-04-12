//! SHAKE128 / SHAKE256 handlers: AFT, VOT, and MCT.
//!
//! Targets ACVP `algorithm = "SHAKE-{128,256}"`, `revision = "FIPS202"`,
//! `testType ∈ {"AFT", "VOT", "MCT"}`. Unlike the fixed-output SHA-3
//! family, each SHAKE AFT/VOT test case carries its own `outLen` (in
//! bits) — the XOF streaming API in `fips_xof` absorbs the message,
//! finalizes, and squeezes exactly `outLen / 8` bytes. Byte alignment
//! is enforced on both `len` and `outLen`.
//!
//! **VOT** (Variable Output Test) uses the same envelope as AFT — the
//! only difference is the group-level `testType` string; the handler
//! dispatches identically.
//!
//! **MCT** (Monte Carlo Test) follows the ACVP XOF MCT algorithm
//! (draft-celi-acvp-xof §6.2): 100 outer iterations × 1000 inner
//! iterations with variable output length. Each inner step feeds the
//! leftmost `minOutLen` bits of the previous output as the message,
//! squeezes `outputLen` bits, then updates `outputLen` from the
//! rightmost 16 bits of the output modulo the output-length range.
//!
//! ACVP publishes SHAKE-128 / SHAKE-256 under revision `"FIPS202"`
//! rather than `"1.0"`, matching the directory name under
//! `gen-val/json-files/` on the pinned commit.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_xof::{Shake128, Shake256};

/// SHAKE128 AFT dispatcher.
pub struct Shake128Handler;

/// SHAKE256 AFT dispatcher.
pub struct Shake256Handler;

impl AlgorithmHandler for Shake128Handler {
    fn algorithm(&self) -> &'static str {
        "SHAKE-128"
    }
    fn revision(&self) -> &'static str {
        "FIPS202"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_shake_dispatch(group, 128, |msg, out| {
            let mut x = Shake128::new()
                .map_err(|_| DispatchError::Crypto("Shake128::new returned Err"))?;
            x.update(msg);
            x.finalize();
            x.squeeze(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for Shake256Handler {
    fn algorithm(&self) -> &'static str {
        "SHAKE-256"
    }
    fn revision(&self) -> &'static str {
        "FIPS202"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_shake_dispatch(group, 256, |msg, out| {
            let mut x = Shake256::new()
                .map_err(|_| DispatchError::Crypto("Shake256::new returned Err"))?;
            x.update(msg);
            x.finalize();
            x.squeeze(out);
            Ok(())
        })
    }
}

/// Top-level dispatcher: routes to AFT/VOT or MCT based on `testType`.
fn handle_shake_dispatch<F>(
    group: &JsonValue,
    security_bits: usize,
    squeeze: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    match test_type {
        "AFT" | "VOT" => handle_shake_aft_vot(group, squeeze),
        "MCT" => handle_shake_mct(group, security_bits, squeeze),
        _ => Err(DispatchError::UnsupportedTestType(test_type.to_string())),
    }
}

/// Shared group driver for SHAKE AFT / VOT. Both test types share the
/// same per-test fields (`msg`, `len`, `outLen`) and answer field (`md`).
fn handle_shake_aft_vot<F>(
    group: &JsonValue,
    mut squeeze: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let group_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
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
        let len_bits = t
            .get("len")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("len"))?;
        let out_len_bits = t
            .get("outLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("outLen"))?;
        if !len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "SHAKE AFT/VOT with non-byte-aligned `len`",
            ));
        }
        if !out_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "SHAKE AFT/VOT with non-byte-aligned `outLen`",
            ));
        }
        let msg_bytes: usize = (len_bits / 8) as usize;
        let out_bytes: usize = (out_len_bits / 8) as usize;
        let msg_hex = t
            .get("msg")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("msg"))?;
        let msg = hex::decode(msg_hex)?;
        if msg.len() < msg_bytes {
            return Err(DispatchError::Crypto(
                "SHAKE AFT/VOT: hex `msg` shorter than declared `len`",
            ));
        }
        let used = msg
            .get(..msg_bytes)
            .ok_or(DispatchError::Crypto("SHAKE AFT/VOT: slicing failed"))?;
        let mut out_buf = vec![0u8; out_bytes];
        squeeze(used, &mut out_buf)?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "md".to_string(),
                JsonValue::String(hex::encode_upper(&out_buf)),
            ),
        ]));
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ---- MCT engine (SHAKE XOF) -------------------------------------------

/// Number of outer MCT iterations.
const MCT_OUTER: usize = 100;
/// Number of inner MCT iterations.
const MCT_INNER: usize = 1000;

/// SHAKE MCT algorithm (ACVP XOF §6.2):
///
/// ```text
/// MD = Seed (minOutLen bits)
/// outputLen = maxOutLen
/// range = maxOutLen - minOutLen + 1
///
/// For i = 0..100:
///     For j = 0..1000:
///         M = leftmost minOutLen/8 bytes of MD
///         MD = SHAKE(M, outputLen)
///         rightBits = last 2 bytes of MD as u16
///         outputLen = minOutLen + (rightBits % range)
///     resultsArray[i] = { md: MD, outLen: outputLen }
/// ```
///
/// `security_bits` is 128 for SHAKE128, 256 for SHAKE256 — this
/// equals `minOutLen` in the ACVP parameterization.
#[allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
fn handle_shake_mct<F>(
    group: &JsonValue,
    _security_bits: usize,
    mut squeeze: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let min_out_len = group
        .get("minOutLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("minOutLen"))? as usize;
    let max_out_len = group
        .get("maxOutLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("maxOutLen"))? as usize;

    if !min_out_len.is_multiple_of(8) || !max_out_len.is_multiple_of(8) {
        return Err(DispatchError::Unsupported(
            "SHAKE MCT: non-byte-aligned minOutLen/maxOutLen",
        ));
    }
    let min_out_bytes = min_out_len / 8;
    let range = max_out_len - min_out_len + 1;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    if tests.len() != 1 {
        return Err(DispatchError::Crypto(
            "SHAKE MCT: expected exactly one test",
        ));
    }
    let t = &tests[0];
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let msg_hex = t
        .get("msg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("msg"))?;
    let mut md = hex::decode(msg_hex)?;

    let mut output_len = max_out_len; // in bits

    let mut results_array: Vec<JsonValue> = Vec::with_capacity(MCT_OUTER);
    for _i in 0..MCT_OUTER {
        for _j in 0..MCT_INNER {
            // M = leftmost minOutBytes bytes of md
            let m_len = min_out_bytes.min(md.len());
            let msg_slice = &md[..m_len];

            let out_bytes = output_len / 8;
            let mut out_buf = vec![0u8; out_bytes];
            squeeze(msg_slice, &mut out_buf)?;

            // Update outputLen from rightmost 16 bits of output
            let right_bits = if out_buf.len() >= 2 {
                let hi = out_buf[out_buf.len() - 2] as usize;
                let lo = out_buf[out_buf.len() - 1] as usize;
                (hi << 8) | lo
            } else if out_buf.len() == 1 {
                out_buf[0] as usize
            } else {
                0
            };
            output_len = min_out_len + (right_bits % range);
            // Ensure byte alignment
            output_len = (output_len / 8) * 8;
            if output_len < min_out_len {
                output_len = min_out_len;
            }

            md = out_buf;
        }
        results_array.push(JsonValue::Object(vec![
            (
                "md".to_string(),
                JsonValue::String(hex::encode_upper(&md)),
            ),
            (
                "outLen".to_string(),
                JsonValue::Number(output_len as i64),
            ),
        ]));
    }

    let test_result = JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        (
            "resultsArray".to_string(),
            JsonValue::Array(results_array),
        ),
    ]);

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(vec![test_result])),
    ]))
}
