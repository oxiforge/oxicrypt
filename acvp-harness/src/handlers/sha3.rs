//! SHA3-224 / SHA3-384 / SHA3-512 Algorithm Functional Test (AFT) handlers.
//!
//! Targets ACVP `algorithm = "SHA3-{224,384,512}"`, `revision = "2.0"`,
//! `testType = "AFT"`. SHA3-256 lives in its own
//! [`super::sha3_256`] module because it was wired up in R10 — this
//! module provides the other three fixed-output members of the SHA-3
//! family so R12-A can close out the SHA-3 hashing side of the
//! dispatcher without disturbing R10 code.
//!
//! All three variants share the exact envelope shape exercised by
//! [`super::sha3_256`]: each AFT test case carries a bit-length `len`
//! and a hex-encoded `msg`, and produces a hex-encoded `md`. pqclib's
//! `fips_sha::sha3` API is byte-oriented, so non-byte-aligned `len`
//! values error out — the vendored ACVP slices at pinned commit
//! `3611942ea10c070dd8bc6afec5682d56c307de8a` only use byte-aligned
//! lengths for AFT, so this is not a functional gap.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// SHA3-224 AFT dispatcher.
pub struct Sha3_224Handler;

/// SHA3-384 AFT dispatcher.
pub struct Sha3_384Handler;

/// SHA3-512 AFT dispatcher.
pub struct Sha3_512Handler;

impl AlgorithmHandler for Sha3_224Handler {
    fn algorithm(&self) -> &'static str {
        "SHA3-224"
    }
    fn revision(&self) -> &'static str {
        "2.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hash_group(group, "SHA3-224", |msg| {
            fips_sha::sha3::sha3_224(msg)
                .map(|d| d.to_vec())
                .map_err(|_| DispatchError::Crypto("fips_sha::sha3::sha3_224 returned Err"))
        })
    }
}

impl AlgorithmHandler for Sha3_384Handler {
    fn algorithm(&self) -> &'static str {
        "SHA3-384"
    }
    fn revision(&self) -> &'static str {
        "2.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hash_group(group, "SHA3-384", |msg| {
            fips_sha::sha3::sha3_384(msg)
                .map(|d| d.to_vec())
                .map_err(|_| DispatchError::Crypto("fips_sha::sha3::sha3_384 returned Err"))
        })
    }
}

impl AlgorithmHandler for Sha3_512Handler {
    fn algorithm(&self) -> &'static str {
        "SHA3-512"
    }
    fn revision(&self) -> &'static str {
        "2.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_hash_group(group, "SHA3-512", |msg| {
            fips_sha::sha3::sha3_512(msg)
                .map(|d| d.to_vec())
                .map_err(|_| DispatchError::Crypto("fips_sha::sha3::sha3_512 returned Err"))
        })
    }
}

/// Shared group driver: walks the `tests` array of a SHA-3 AFT group,
/// decoding `len` + `msg` and calling `compute(msg)` to get the digest
/// bytes. `label` is a static string used for diagnostic errors only.
fn handle_hash_group<F>(
    group: &JsonValue,
    label: &'static str,
    mut compute: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, DispatchError>,
{
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
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        results.push(run_case(t, label, &mut compute)?);
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

fn run_case<F>(
    t: &JsonValue,
    label: &'static str,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, DispatchError>,
{
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let len_bits = t
        .get("len")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("len"))?;
    if !len_bits.is_multiple_of(8) {
        let _ = label; // label kept for future diagnostic plumbing
        return Err(DispatchError::Unsupported(
            "SHA-3 AFT with non-byte-aligned `len`",
        ));
    }
    let expected_bytes: usize = (len_bits / 8) as usize;
    let msg_hex = t
        .get("msg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("msg"))?;
    let msg = hex::decode(msg_hex)?;
    if msg.len() < expected_bytes {
        return Err(DispatchError::Crypto(
            "SHA-3 AFT: hex `msg` shorter than declared `len`",
        ));
    }
    let used = msg
        .get(..expected_bytes)
        .ok_or(DispatchError::Crypto("SHA-3 AFT: slicing failed"))?;
    let md = compute(used)?;
    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("md".to_string(), JsonValue::String(hex::encode_upper(&md))),
    ]))
}
