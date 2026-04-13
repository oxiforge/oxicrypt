//! SHA3-224 / SHA3-384 / SHA3-512 AFT + MCT + LDT handlers.
//!
//! Targets ACVP `algorithm = "SHA3-{224,384,512}"`, `revision = "2.0"`,
//! `testType ∈ {"AFT", "MCT", "LDT"}`. SHA3-256 lives in its own
//! [`super::sha3_256`] module because it was wired up in R10 — this
//! module provides the other three fixed-output members of the SHA-3
//! family so R12-A can close out the SHA-3 hashing side of the
//! dispatcher without disturbing R10 code.
//!
//! All three variants share the exact envelope shape exercised by
//! [`super::sha3_256`]: each AFT test case carries a bit-length `len`
//! and a hex-encoded `msg`, and produces a hex-encoded `md`. oxicrypt's
//! `oxicrypt_sha::sha3` API is byte-oriented, so non-byte-aligned `len`
//! values error out — the vendored ACVP slices at pinned commit
//! `3611942ea10c070dd8bc6afec5682d56c307de8a` only use byte-aligned
//! lengths for AFT, so this is not a functional gap.
//!
//! SHA-3 MCT (Monte Carlo Test) implements the ACVP SHA-3 §6.2 inner
//! loop: `MD[0] = Seed; for j = 0..999: MD[j+1] = SHA3(MD[j]);
//! Output[i] = MD[1000]; MD[0] = MD[1000]` for 100 outer iterations.
//! Each MCT group has a single test carrying an initial `msg` (the
//! seed) and the response carries a `resultsArray` with one `md`
//! entry per outer iteration.
//!
//! SHA-3 LDT (Large Data Test) hashes a large message constructed by
//! repeating a short content pattern to a specified `fullLength`.
//! Uses the incremental `Sha3::update` API to stream chunks without
//! materializing the entire expanded message in memory.

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
        handle_hash_group(
            group,
            "SHA3-224",
            |msg| {
                oxicrypt_sha::sha3::sha3_224(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha3::sha3_224 returned Err"))
            },
            |content, full_bytes| {
                ldt_stream::<{ oxicrypt_sha::sha3::SHA3_224_RATE }, { oxicrypt_sha::sha3::SHA3_224_DIGEST_SIZE }>(
                    content, full_bytes,
                )
            },
        )
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
        handle_hash_group(
            group,
            "SHA3-384",
            |msg| {
                oxicrypt_sha::sha3::sha3_384(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha3::sha3_384 returned Err"))
            },
            |content, full_bytes| {
                ldt_stream::<{ oxicrypt_sha::sha3::SHA3_384_RATE }, { oxicrypt_sha::sha3::SHA3_384_DIGEST_SIZE }>(
                    content, full_bytes,
                )
            },
        )
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
        handle_hash_group(
            group,
            "SHA3-512",
            |msg| {
                oxicrypt_sha::sha3::sha3_512(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha3::sha3_512 returned Err"))
            },
            |content, full_bytes| {
                ldt_stream::<{ oxicrypt_sha::sha3::SHA3_512_RATE }, { oxicrypt_sha::sha3::SHA3_512_DIGEST_SIZE }>(
                    content, full_bytes,
                )
            },
        )
    }
}

/// Shared group driver: dispatches AFT, MCT, and LDT groups for a
/// SHA-3 variant. `label` is a static string used for diagnostic
/// errors only.
///
/// `compute` is the one-shot hash function (for AFT/MCT).
/// `ldt_compute` is the streaming LDT hash function that takes a
/// content pattern and the total message length in bytes.
pub(crate) fn handle_hash_group<F, L>(
    group: &JsonValue,
    label: &'static str,
    mut compute: F,
    mut ldt_compute: L,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, DispatchError>,
    L: FnMut(&[u8], u64) -> Result<Vec<u8>, DispatchError>,
{
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;

    match test_type {
        "AFT" => {
            let tests = group
                .get("tests")
                .and_then(JsonValue::as_array)
                .ok_or(DispatchError::MissingField("tests"))?;
            let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
            for t in tests {
                results.push(run_aft_case(t, label, &mut compute)?);
            }
            Ok(JsonValue::Object(vec![
                ("tgId".to_string(), JsonValue::Number(tg_id)),
                ("tests".to_string(), JsonValue::Array(results)),
            ]))
        }
        "MCT" => handle_mct_group(tg_id, group, &mut compute),
        "LDT" => {
            let tests = group
                .get("tests")
                .and_then(JsonValue::as_array)
                .ok_or(DispatchError::MissingField("tests"))?;
            let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
            for t in tests {
                results.push(run_ldt_case(t, &mut ldt_compute)?);
            }
            Ok(JsonValue::Object(vec![
                ("tgId".to_string(), JsonValue::Number(tg_id)),
                ("tests".to_string(), JsonValue::Array(results)),
            ]))
        }
        _ => Err(DispatchError::UnsupportedTestType(test_type.to_string())),
    }
}

fn run_aft_case<F>(
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

// ---- MCT engine (SHA-3) ------------------------------------------------

/// Number of outer iterations in a SHA-3 MCT test.
const MCT_OUTER: usize = 100;
/// Number of inner iterations per outer iteration.
const MCT_INNER: usize = 1000;

/// Handle a complete SHA-3 MCT group. Each group has exactly one test
/// carrying an initial `msg` (the seed). The handler runs the SHA-3
/// MCT algorithm and emits a `resultsArray` with `MCT_OUTER` entries.
///
/// SHA-3 MCT algorithm (ACVP SHA-3 §6.2):
/// ```text
/// MD[0] = Seed
/// For i = 0..MCT_OUTER:
///     For j = 0..MCT_INNER:
///         MD[j+1] = SHA3(MD[j])
///     Output[i] = MD[MCT_INNER]
///     MD[0] = Output[i]
/// ```
#[allow(clippy::similar_names)] // tg_id vs tc_id
fn handle_mct_group<F>(
    tg_id: i64,
    group: &JsonValue,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, DispatchError>,
{
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    if tests.len() != 1 {
        return Err(DispatchError::Crypto("SHA-3 MCT: expected exactly one test"));
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

    let mut results_array: Vec<JsonValue> = Vec::with_capacity(MCT_OUTER);
    for _i in 0..MCT_OUTER {
        for _j in 0..MCT_INNER {
            md = compute(&md)?;
        }
        results_array.push(JsonValue::Object(vec![
            ("md".to_string(), JsonValue::String(hex::encode_upper(&md))),
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

// ---- LDT engine (SHA-3) -------------------------------------------------

/// Handle a single LDT test case. Parses the `largeMsg` object to
/// extract `content`, `contentLength`, `fullLength`, and
/// `expansionTechnique`, then delegates to `ldt_compute`.
fn run_ldt_case<L>(
    t: &JsonValue,
    ldt_compute: &mut L,
) -> Result<JsonValue, DispatchError>
where
    L: FnMut(&[u8], u64) -> Result<Vec<u8>, DispatchError>,
{
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;

    let large_msg = t
        .get("largeMsg")
        .ok_or(DispatchError::MissingField("largeMsg"))?;

    let content_hex = large_msg
        .get("content")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("largeMsg.content"))?;
    let content_length_bits = large_msg
        .get("contentLength")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("largeMsg.contentLength"))?;
    let full_length_bits = large_msg
        .get("fullLength")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("largeMsg.fullLength"))?;
    let technique = large_msg
        .get("expansionTechnique")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("largeMsg.expansionTechnique"))?;

    if technique != "repeating" {
        return Err(DispatchError::Unsupported(
            "LDT: only 'repeating' expansion technique is supported",
        ));
    }
    if content_length_bits % 8 != 0 || full_length_bits % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "LDT: non-byte-aligned lengths are not supported",
        ));
    }

    let content = hex::decode(content_hex)?;
    let content_bytes = (content_length_bits / 8) as usize;
    if content.len() < content_bytes {
        return Err(DispatchError::Crypto(
            "LDT: content hex shorter than declared contentLength",
        ));
    }
    let pattern = &content[..content_bytes];

    let full_bytes = full_length_bits / 8;
    let md = ldt_compute(pattern, full_bytes)?;

    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("md".to_string(), JsonValue::String(hex::encode_upper(&md))),
    ]))
}

/// Streaming LDT hasher: feeds the repeating `pattern` into an
/// incremental `Sha3<RATE, OUT>` hasher until `full_bytes` total
/// bytes have been absorbed. Streams in chunks to avoid materializing
/// the full expanded message.
pub(crate) fn ldt_stream<const RATE: usize, const OUT: usize>(
    pattern: &[u8],
    full_bytes: u64,
) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha3::Sha3::<RATE, OUT>::new_internal();
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;

    // Feed full copies of the pattern.
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    // Feed the fractional tail (if fullLength is not a multiple of contentLength).
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }

    Ok(hasher.finalize().to_vec())
}
