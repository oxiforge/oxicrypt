//! SHAKE128 / SHAKE256 Algorithm Functional Test (AFT) handlers.
//!
//! Targets ACVP `algorithm = "SHAKE-{128,256}"`, `revision = "FIPS202"`,
//! `testType = "AFT"`. Unlike the fixed-output SHA-3 family, each
//! SHAKE AFT test case carries its own `outLen` (in bits) — the XOF
//! streaming API in `fips_xof` absorbs the message, finalizes, and
//! squeezes exactly `outLen / 8` bytes. Byte alignment is enforced on
//! both `len` and `outLen`; the vendored ACVP slices at pinned commit
//! `3611942ea10c070dd8bc6afec5682d56c307de8a` use only byte-aligned
//! values for AFT, so this is not a functional gap.
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
        handle_shake_group(group, |msg, out| {
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
        handle_shake_group(group, |msg, out| {
            let mut x = Shake256::new()
                .map_err(|_| DispatchError::Crypto("Shake256::new returned Err"))?;
            x.update(msg);
            x.finalize();
            x.squeeze(out);
            Ok(())
        })
    }
}

/// Shared group driver for SHAKE AFT. `squeeze(msg, out)` absorbs the
/// message and writes exactly `out.len()` squeezed bytes, where
/// `out.len()` equals the per-case `outLen / 8`.
fn handle_shake_group<F>(
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
                "SHAKE AFT with non-byte-aligned `len`",
            ));
        }
        if !out_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "SHAKE AFT with non-byte-aligned `outLen`",
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
                "SHAKE AFT: hex `msg` shorter than declared `len`",
            ));
        }
        let used = msg
            .get(..msg_bytes)
            .ok_or(DispatchError::Crypto("SHAKE AFT: slicing failed"))?;
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
