//! ParallelHash-128 / ParallelHash-256 AFT + MCT handlers (with
//! offline-only ParallelHashXOF-128 / ParallelHashXOF-256 helpers).
//!
//! Targets ACVP slices with `algorithm = "ParallelHash-128"` or
//! `"ParallelHash-256"`, `revision = "1.0"`, `testType ∈ {"AFT", "MCT"}`.
//!
//! # Cap-shape unification
//!
//! Per `draft-celi-acvp-xof` §5 + §7.2 Table 3, ACVP recognises only
//! `ParallelHash-128` and `ParallelHash-256` as algorithm names; the
//! XOF mode is selected via the `xof: [true, false]` capability flag
//! and toggled per-test-group by the `xof` boolean field. There is no
//! ACVP `ParallelHashXOF-*` algorithm name. The base handlers here
//! mirror the KMAC unification pattern: they advertise the unified
//! capability and dispatch per-group on `xof` to either the XOF or
//! the non-XOF primitive. The `ParallelHashXof{128,256}Handler`
//! structs are kept around solely to serve the offline round-trip
//! fixtures under `vendor/.../ParallelHashXOF-{128,256}-1.0/` — their
//! `acvp_capabilities()` returns `None` so they do not advertise to
//! the live ACVTS server.
//!
//! # Group-level fields (per `draft-celi-acvp-xof` §8.1 Table 5)
//!
//! - `xof` (boolean) — selects XOF vs non-XOF mode for the group.
//! - `hexCustomization` (boolean, AFT) — `true` if per-test
//!   customization strings are hex-encoded, `false` if ASCII.
//!   Defaults to `false` when absent.
//! - `minOutLen`, `maxOutLen`, `outLenIncrement` (integers, MCT) —
//!   output-length domain.
//! - `minBlockSize`, `maxBlockSize` (integers, MCT) — block-size
//!   domain.
//!
//! # Per-test fields (per §8.2 Table 6)
//!
//! - `msg` (hex) — input message (AFT) or initial seed (MCT)
//! - `len` (bits) — message length
//! - `outLen` (bits, AFT only) — requested output length
//! - `blockSize` (integer, AFT only) — block size B in bytes
//! - `customization` (string, AFT only) — customization string S
//!
//! # Response
//!
//! - AFT: `md` (hex)
//! - MCT: `resultsArray` of `{md, outLen}` objects (one per outer
//!   iteration of the §6.2.2 state machine).
//!
//! # MCT — function-name handling
//!
//! SP 800-185 §6 ParallelHash takes no caller-supplied function name
//! (the internal N is hard-coded to `"ParallelHash"`). The MCT
//! pseudocode at §6.2.2 references a `FunctionName` parameter, but
//! the surrounding text never initializes it; it is a spec artefact
//! inherited from cSHAKE's pseudocode and has no effect on
//! ParallelHash output. The oxicrypt API (`ParallelHash128::new(B,
//! S)` / `ParallelHashXof128::new(B, S)`) reflects the SP 800-185
//! surface, so we ignore the spec's `FunctionName` reference.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use crate::mct_helpers::{be_u16_from_2_bytes, bits_to_string, left, right};
use oxicrypt_xof::{ParallelHash128, ParallelHash256, ParallelHashXof128, ParallelHashXof256};

/// ParallelHash-128 handler (AFT + MCT, unified XOF / non-XOF).
pub struct ParallelHash128Handler;

/// ParallelHash-256 handler (AFT + MCT, unified XOF / non-XOF).
pub struct ParallelHash256Handler;

impl AlgorithmHandler for ParallelHash128Handler {
    fn algorithm(&self) -> &'static str {
        "ParallelHash-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::parallelhash_capability("ParallelHash-128"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let xof = read_xof_flag(group);
        dispatch_parallelhash_group(group, |msg, block_size, s, out| {
            if xof {
                let mut h = ParallelHashXof128::new(block_size, s)
                    .map_err(|_| DispatchError::Crypto("ParallelHashXof128::new returned Err"))?;
                h.update(msg);
                h.finalize();
                h.squeeze(out);
            } else {
                let mut h = ParallelHash128::new(block_size, s)
                    .map_err(|_| DispatchError::Crypto("ParallelHash128::new returned Err"))?;
                h.update(msg);
                h.finalize_into(out);
            }
            Ok(())
        })
    }
}

impl AlgorithmHandler for ParallelHash256Handler {
    fn algorithm(&self) -> &'static str {
        "ParallelHash-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::parallelhash_capability("ParallelHash-256"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let xof = read_xof_flag(group);
        dispatch_parallelhash_group(group, |msg, block_size, s, out| {
            if xof {
                let mut h = ParallelHashXof256::new(block_size, s)
                    .map_err(|_| DispatchError::Crypto("ParallelHashXof256::new returned Err"))?;
                h.update(msg);
                h.finalize();
                h.squeeze(out);
            } else {
                let mut h = ParallelHash256::new(block_size, s)
                    .map_err(|_| DispatchError::Crypto("ParallelHash256::new returned Err"))?;
                h.update(msg);
                h.finalize_into(out);
            }
            Ok(())
        })
    }
}

/// Offline-only handler for `ParallelHashXOF-128` round-trip fixtures.
///
/// Returns `None` from `acvp_capabilities()` so it never advertises
/// to ACVTS. The live unified path runs through
/// [`ParallelHash128Handler`] with the per-group `xof` flag.
pub struct ParallelHashXof128Handler;

/// Offline-only handler for `ParallelHashXOF-256` round-trip fixtures.
pub struct ParallelHashXof256Handler;

impl AlgorithmHandler for ParallelHashXof128Handler {
    fn algorithm(&self) -> &'static str {
        "ParallelHashXOF-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        None
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_parallelhash_aft_group(group, &mut |msg, block_size, s, out| {
            let mut h = ParallelHashXof128::new(block_size, s)
                .map_err(|_| DispatchError::Crypto("ParallelHashXof128::new returned Err"))?;
            h.update(msg);
            h.finalize();
            h.squeeze(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for ParallelHashXof256Handler {
    fn algorithm(&self) -> &'static str {
        "ParallelHashXOF-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        None
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_parallelhash_aft_group(group, &mut |msg, block_size, s, out| {
            let mut h = ParallelHashXof256::new(block_size, s)
                .map_err(|_| DispatchError::Crypto("ParallelHashXof256::new returned Err"))?;
            h.update(msg);
            h.finalize();
            h.squeeze(out);
            Ok(())
        })
    }
}

/// Read the group-level `xof` flag (defaults to `false` when absent —
/// matches KMAC's behaviour for groups that originated before the
/// unified cap shape).
fn read_xof_flag(group: &JsonValue) -> bool {
    group
        .get("xof")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}

/// Top-level ParallelHash group dispatch — routes by `testType` to
/// the AFT or MCT driver.
fn dispatch_parallelhash_group<F>(
    group: &JsonValue,
    mut compute: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], usize, &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    match test_type {
        "AFT" => handle_parallelhash_aft_group(group, &mut compute),
        "MCT" => handle_parallelhash_mct_group(group, &mut compute),
        other => Err(DispatchError::UnsupportedTestType(other.to_string())),
    }
}

/// AFT driver — one ParallelHash call per test case.
fn handle_parallelhash_aft_group<F>(
    group: &JsonValue,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], usize, &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let group_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    // Group-level encoding flag for per-test `customization` field
    // (per `xof §8.1 Table 5`). Absent → false (ASCII).
    let hex_customization = group
        .get("hexCustomization")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);

    // Block size may be group-level or test-level.
    let group_block_size = match group.get("blockSize").and_then(JsonValue::as_u64) {
        Some(v) => Some(
            usize::try_from(v)
                .map_err(|_| DispatchError::Crypto("ParallelHash: blockSize overflows usize"))?,
        ),
        None => None,
    };

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
                "ParallelHash AFT with non-byte-aligned `len`",
            ));
        }
        if !out_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "ParallelHash AFT with non-byte-aligned `outLen`",
            ));
        }
        let msg_bytes = (len_bits / 8) as usize;
        let out_bytes = (out_len_bits / 8) as usize;

        // Test-level blockSize overrides group-level.
        let block_size = match t.get("blockSize").and_then(JsonValue::as_u64) {
            Some(v) => usize::try_from(v)
                .map_err(|_| DispatchError::Crypto("ParallelHash: blockSize overflows usize"))?,
            None => group_block_size.ok_or(DispatchError::MissingField("blockSize"))?,
        };

        let msg_hex = t
            .get("msg")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("msg"))?;
        let msg = if msg_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(msg_hex)?
        };
        if msg.len() < msg_bytes {
            return Err(DispatchError::Crypto(
                "ParallelHash AFT: hex `msg` shorter than declared `len`",
            ));
        }
        let used = if msg_bytes == 0 {
            &[] as &[u8]
        } else {
            &msg[..msg_bytes]
        };

        // Customization string S. Per-test `customization` field is
        // hex if the group-level boolean is true, ASCII otherwise.
        let s_field = t.get("customization").and_then(JsonValue::as_str);
        let s = match s_field {
            None | Some("") => Vec::new(),
            Some(raw) if hex_customization => hex::decode(raw)?,
            Some(raw) => raw.as_bytes().to_vec(),
        };

        let mut out_buf = vec![0u8; out_bytes];
        compute(used, block_size, &s, &mut out_buf)?;
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

/// MCT driver — implements the Monte Carlo Test state machine from
/// `draft-celi-acvp-xof` §6.2.2.
///
/// Pseudocode (paraphrased):
///
/// ```text
/// Output[0] = Msg
/// OutputLen = MaxOutLen
/// BlockSize = MinBlockSize
/// Customization = ""
/// for j in 0..100:
///   for i in 1..1001:
///     InnerMsg = Left(Output[i-1] || ZeroBits(128), 128)
///     Output[i] = ParallelHash(InnerMsg, OutputLen, BlockSize, Customization)
///     Rightmost = Right(Output[i], 16)
///     OutputLen = MinOutLen + floor((Rightmost % Range) / Increment) * Increment
///     BlockSize = MinBlockSize + (Right(Rightmost, 8) % BlockRange)
///     Customization = BitsToString(InnerMsg || Rightmost)
///   OutputJ[j] = Output[1000]
/// ```
///
/// `Output[0]` carries forward from one outer iteration to the next.
/// `OutputLen`, `BlockSize`, and `Customization` persist across outer
/// iterations since the spec's hard-coded initializers run only once
/// before the outer loop.
#[allow(clippy::too_many_lines)]
fn handle_parallelhash_mct_group<F>(
    group: &JsonValue,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], usize, &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let group_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
    let min_out_len = usize::try_from(
        group
            .get("minOutLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("minOutLen"))?,
    )
    .map_err(|_| DispatchError::Crypto("ParallelHash MCT: minOutLen overflows usize"))?;
    let max_out_len = usize::try_from(
        group
            .get("maxOutLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("maxOutLen"))?,
    )
    .map_err(|_| DispatchError::Crypto("ParallelHash MCT: maxOutLen overflows usize"))?;
    let out_len_increment = usize::try_from(
        group
            .get("outLenIncrement")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("outLenIncrement"))?,
    )
    .map_err(|_| DispatchError::Crypto("ParallelHash MCT: outLenIncrement overflows usize"))?;
    let min_block_size = usize::try_from(
        group
            .get("minBlockSize")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("minBlockSize"))?,
    )
    .map_err(|_| DispatchError::Crypto("ParallelHash MCT: minBlockSize overflows usize"))?;
    let max_block_size = usize::try_from(
        group
            .get("maxBlockSize")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("maxBlockSize"))?,
    )
    .map_err(|_| DispatchError::Crypto("ParallelHash MCT: maxBlockSize overflows usize"))?;
    if !min_out_len.is_multiple_of(8)
        || !max_out_len.is_multiple_of(8)
        || !out_len_increment.is_multiple_of(8)
    {
        return Err(DispatchError::Unsupported(
            "ParallelHash MCT with non-byte-aligned output length",
        ));
    }
    if min_out_len > max_out_len || out_len_increment == 0 {
        return Err(DispatchError::Crypto(
            "ParallelHash MCT: degenerate output-length domain",
        ));
    }
    if min_block_size > max_block_size {
        return Err(DispatchError::Crypto(
            "ParallelHash MCT: degenerate block-size domain",
        ));
    }
    let range = max_out_len - min_out_len + 1;
    let block_range = max_block_size - min_block_size + 1;

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
        let msg_hex = t
            .get("msg")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("msg"))?;
        let initial_msg = hex::decode(msg_hex)?;

        // Spec §6.2.2 pre-loop initial state.
        let mut output: Vec<u8> = initial_msg;
        let mut output_len_bits: usize = max_out_len;
        let mut block_size: usize = min_block_size;
        let mut customization: Vec<u8> = Vec::new();

        let mut results_array: Vec<JsonValue> = Vec::with_capacity(100);

        for _j in 0..100 {
            let mut out_len_for_this_iter = output_len_bits;

            for _i in 1..=1000 {
                out_len_for_this_iter = output_len_bits;

                // InnerMsg = Left(Output[i-1] || ZeroBits(128), 128)
                let inner_msg = left(&output, 128);

                // Output[i] = ParallelHash(InnerMsg, OutputLen, BlockSize, Customization)
                let out_bytes = output_len_bits / 8;
                let mut new_output = vec![0u8; out_bytes];
                compute(&inner_msg, block_size, &customization, &mut new_output)?;
                output = new_output;

                // Rightmost_Output_bits = Right(Output[i], 16) — 2 bytes
                let rightmost = right(&output, 16);
                let rightmost_num = usize::from(be_u16_from_2_bytes(&rightmost));

                // OutputLen update
                let modded = rightmost_num % range;
                output_len_bits = min_out_len + (modded / out_len_increment) * out_len_increment;

                // BlockSize = MinBlockSize + (Right(Rightmost, 8) % BlockRange)
                // Right(Rightmost, 8) is the rightmost byte of the 2-byte Rightmost.
                let right_byte = right(&rightmost, 8);
                block_size = min_block_size + usize::from(right_byte[0]) % block_range;

                // Customization = BitsToString(InnerMsg || Rightmost)
                let mut combo = Vec::with_capacity(inner_msg.len() + rightmost.len());
                combo.extend_from_slice(&inner_msg);
                combo.extend_from_slice(&rightmost);
                customization = bits_to_string(&combo);
            }

            let out_len_i64 = i64::try_from(out_len_for_this_iter)
                .map_err(|_| DispatchError::Crypto("ParallelHash MCT outLen overflows i64"))?;
            results_array.push(JsonValue::Object(vec![
                (
                    "md".to_string(),
                    JsonValue::String(hex::encode_upper(&output)),
                ),
                ("outLen".to_string(), JsonValue::Number(out_len_i64)),
            ]));
        }

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            ("resultsArray".to_string(), JsonValue::Array(results_array)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
