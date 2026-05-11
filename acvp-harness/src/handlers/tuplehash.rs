//! TupleHash-128 / TupleHash-256 AFT + MCT handlers (with
//! offline-only TupleHashXOF-128 / TupleHashXOF-256 helpers).
//!
//! Targets ACVP slices with `algorithm = "TupleHash-128"` or
//! `"TupleHash-256"`, `revision = "1.0"`, `testType ∈ {"AFT", "MCT"}`.
//!
//! # Cap-shape unification
//!
//! Per `draft-celi-acvp-xof` §5 + §7.2 Table 3, ACVP recognises only
//! `TupleHash-128` and `TupleHash-256` as algorithm names; the XOF
//! mode is selected via the `xof: [true, false]` capability flag and
//! toggled per-test-group by the `xof` boolean field. There is no
//! ACVP `TupleHashXOF-*` algorithm name. The base handlers here
//! mirror the KMAC unification pattern: they advertise the unified
//! capability and dispatch per-group on `xof` to either the XOF or
//! the non-XOF primitive. The `TupleHashXof{128,256}Handler` structs
//! are kept around solely to serve the offline round-trip fixtures
//! under `vendor/.../TupleHashXOF-{128,256}-1.0/` — their
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
//!
//! # Per-test fields (per §8.2 Table 6)
//!
//! - `tuple` (array of hex strings, AFT) — input tuple elements
//! - `msg` (hex, MCT) — initial single-element tuple seed
//! - `outLen` (bits, AFT only) — requested output length
//! - `customization` (string, AFT only) — customization string S
//!
//! # Response
//!
//! - AFT: `md` (hex)
//! - MCT: `resultsArray` of `{md, outLen}` objects (one per outer
//!   iteration of the §6.2.3 state machine).

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use crate::mct_helpers::{be_u16_from_2_bytes, bits_to_string, left, right};
use oxicrypt_xof::{TupleHash128, TupleHash256, TupleHashXof128, TupleHashXof256};

/// TupleHash-128 handler (AFT + MCT, unified XOF / non-XOF).
pub struct TupleHash128Handler;

/// TupleHash-256 handler (AFT + MCT, unified XOF / non-XOF).
pub struct TupleHash256Handler;

impl AlgorithmHandler for TupleHash128Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHash-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tuplehash_capability("TupleHash-128"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let xof = read_xof_flag(group);
        dispatch_tuplehash_group(group, |elements, s, out| {
            if xof {
                let mut h = TupleHashXof128::new(s)
                    .map_err(|_| DispatchError::Crypto("TupleHashXof128::new returned Err"))?;
                for elem in elements {
                    h.update(elem);
                }
                h.finalize();
                h.squeeze(out);
            } else {
                let mut h = TupleHash128::new(s)
                    .map_err(|_| DispatchError::Crypto("TupleHash128::new returned Err"))?;
                for elem in elements {
                    h.update(elem);
                }
                h.finalize_into(out);
            }
            Ok(())
        })
    }
}

impl AlgorithmHandler for TupleHash256Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHash-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tuplehash_capability("TupleHash-256"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let xof = read_xof_flag(group);
        dispatch_tuplehash_group(group, |elements, s, out| {
            if xof {
                let mut h = TupleHashXof256::new(s)
                    .map_err(|_| DispatchError::Crypto("TupleHashXof256::new returned Err"))?;
                for elem in elements {
                    h.update(elem);
                }
                h.finalize();
                h.squeeze(out);
            } else {
                let mut h = TupleHash256::new(s)
                    .map_err(|_| DispatchError::Crypto("TupleHash256::new returned Err"))?;
                for elem in elements {
                    h.update(elem);
                }
                h.finalize_into(out);
            }
            Ok(())
        })
    }
}

/// Offline-only handler for `TupleHashXOF-128` round-trip fixtures.
///
/// Returns `None` from `acvp_capabilities()` so it never advertises
/// to ACVTS. The live unified path runs through
/// [`TupleHash128Handler`] with the per-group `xof` flag.
pub struct TupleHashXof128Handler;

/// Offline-only handler for `TupleHashXOF-256` round-trip fixtures.
pub struct TupleHashXof256Handler;

impl AlgorithmHandler for TupleHashXof128Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHashXOF-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        None
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_tuplehash_aft_group(group, &mut |elements, s, out| {
            let mut h = TupleHashXof128::new(s)
                .map_err(|_| DispatchError::Crypto("TupleHashXof128::new returned Err"))?;
            for elem in elements {
                h.update(elem);
            }
            h.finalize();
            h.squeeze(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for TupleHashXof256Handler {
    fn algorithm(&self) -> &'static str {
        "TupleHashXOF-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        None
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_tuplehash_aft_group(group, &mut |elements, s, out| {
            let mut h = TupleHashXof256::new(s)
                .map_err(|_| DispatchError::Crypto("TupleHashXof256::new returned Err"))?;
            for elem in elements {
                h.update(elem);
            }
            h.finalize();
            h.squeeze(out);
            Ok(())
        })
    }
}

/// Read the group-level `xof` flag (defaults to `false` when absent).
fn read_xof_flag(group: &JsonValue) -> bool {
    group
        .get("xof")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}

/// Top-level TupleHash group dispatch — routes by `testType` to the
/// AFT or MCT driver.
fn dispatch_tuplehash_group<F>(
    group: &JsonValue,
    mut compute: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[Vec<u8>], &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    match test_type {
        "AFT" => handle_tuplehash_aft_group(group, &mut compute),
        "MCT" => handle_tuplehash_mct_group(group, &mut compute),
        other => Err(DispatchError::UnsupportedTestType(other.to_string())),
    }
}

/// AFT driver — one TupleHash call per test case, fixed `outLen` and
/// caller-supplied tuple from the prompt.
fn handle_tuplehash_aft_group<F>(
    group: &JsonValue,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[Vec<u8>], &[u8], &mut [u8]) -> Result<(), DispatchError>,
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
        let out_len_bits = t
            .get("outLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("outLen"))?;
        if !out_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "TupleHash AFT with non-byte-aligned `outLen`",
            ));
        }
        let out_bytes = (out_len_bits / 8) as usize;

        // Parse tuple elements: array of hex strings.
        let tuple_arr = t
            .get("tuple")
            .and_then(JsonValue::as_array)
            .ok_or(DispatchError::MissingField("tuple"))?;
        let mut elements: Vec<Vec<u8>> = Vec::with_capacity(tuple_arr.len());
        for elem_val in tuple_arr {
            let elem_hex = elem_val.as_str().ok_or(DispatchError::Crypto(
                "TupleHash AFT: tuple element is not a string",
            ))?;
            if elem_hex.is_empty() {
                elements.push(Vec::new());
            } else {
                elements.push(hex::decode(elem_hex)?);
            }
        }

        // Customization string S. Read whichever JSON field the
        // group-level `hexCustomization` flag declares (per
        // `draft-celi-acvp-xof` §8.2 Table 6): `customizationHex`
        // when true, `customization` when false.
        let s = super::xof_common::read_customization_field(t, hex_customization)?;

        let mut out_buf = vec![0u8; out_bytes];
        compute(&elements, &s, &mut out_buf)?;
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
/// `draft-celi-acvp-xof` §6.2.3.
///
/// Pseudocode (paraphrased):
///
/// ```text
/// T[0][0] = Tuple  (the initial single-element tuple from `msg`)
/// OutputLen = MaxOutLen
/// Customization = ""
/// for j in 0..100:
///   for i in 1..1001:
///     workingBits = Left(T[i-1][0] || ZeroBits(288), 288)
///     tupleSize = (top 3 bits of workingBits) % 4 + 1     // 1..=4
///     for k in 0..tupleSize:
///       T[i][k] = bits [k*288/tupleSize, (k+1)*288/tupleSize)
///     Output[i] = TupleHash(T[i], OutputLen, Customization)
///     Rightmost = Right(Output[i], 16)
///     OutputLen = MinOutLen + floor((Rightmost % Range) / Increment) * Increment
///     Customization = BitsToString(T[i][0] || Rightmost)
///   OutputJ[j] = Output[1000]
/// ```
///
/// `T[i][0]` carries forward as the next iteration's `T[i-1][0]`.
/// `OutputLen` and `Customization` persist across both loops since
/// the spec's hard-coded initializers run only once before the outer
/// loop. The per-iteration tuple is byte-aligned at every legal
/// `tupleSize ∈ {1, 2, 3, 4}` because 288 is divisible by each (and
/// 288/k is divisible by 8 for each), so we can partition the working
/// bytes without bit-level slicing.
///
/// The 3-bit extraction for `tupleSize` is the only sub-byte operation
/// in this driver — it's the top 3 bits of byte 0 of `workingBits`,
/// computed inline as `working_bits[0] >> 5`.
#[allow(clippy::too_many_lines)]
fn handle_tuplehash_mct_group<F>(
    group: &JsonValue,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[Vec<u8>], &[u8], &mut [u8]) -> Result<(), DispatchError>,
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
    .map_err(|_| DispatchError::Crypto("TupleHash MCT: minOutLen overflows usize"))?;
    let max_out_len = usize::try_from(
        group
            .get("maxOutLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("maxOutLen"))?,
    )
    .map_err(|_| DispatchError::Crypto("TupleHash MCT: maxOutLen overflows usize"))?;
    let out_len_increment = usize::try_from(
        group
            .get("outLenIncrement")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("outLenIncrement"))?,
    )
    .map_err(|_| DispatchError::Crypto("TupleHash MCT: outLenIncrement overflows usize"))?;
    if !min_out_len.is_multiple_of(8)
        || !max_out_len.is_multiple_of(8)
        || !out_len_increment.is_multiple_of(8)
    {
        return Err(DispatchError::Unsupported(
            "TupleHash MCT with non-byte-aligned output length",
        ));
    }
    if min_out_len > max_out_len || out_len_increment == 0 {
        return Err(DispatchError::Crypto(
            "TupleHash MCT: degenerate output-length domain",
        ));
    }
    let range = max_out_len - min_out_len + 1;

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
        let initial_tuple_elem = hex::decode(msg_hex)?;

        // Spec §6.2.3 pre-loop initial state.
        // T[0][0] is the initial single-element tuple's first element.
        let mut t_zero: Vec<u8> = initial_tuple_elem;
        let mut output_len_bits: usize = max_out_len;
        let mut customization: Vec<u8> = Vec::new();

        let mut results_array: Vec<JsonValue> = Vec::with_capacity(100);

        for _j in 0..100 {
            for i in 1..=1000 {
                // Capture the OutputLen used to drive this iteration's
                // TupleHash call, before the post-update inside this same
                // iteration replaces it.
                let out_len_for_this_iter = output_len_bits;

                // workingBits = Left(T[i-1][0] || ZeroBits(288), 288) — 36 bytes
                let working_bits = left(&t_zero, 288);

                // tupleSize = (top 3 bits of workingBits) % 4 + 1, in 1..=4.
                // The 3-bit value is the MSB-aligned top of byte 0; per spec
                // NOTE it is interpreted as a little-endian-encoded number,
                // which for a 3-bit value collapses to the raw value.
                let top_3_bits = usize::from(working_bits[0] >> 5);
                let tuple_size = (top_3_bits % 4) + 1;

                // Partition workingBits into `tuple_size` byte-aligned elements
                // of `288 / tuple_size` bits each (legal for all
                // tuple_size ∈ {1, 2, 3, 4}).
                let bits_per_elem = 288 / tuple_size;
                let bytes_per_elem = bits_per_elem / 8;
                let mut elements: Vec<Vec<u8>> = Vec::with_capacity(tuple_size);
                for k in 0..tuple_size {
                    let start = k * bytes_per_elem;
                    elements.push(working_bits[start..start + bytes_per_elem].to_vec());
                }

                // Output[i] = TupleHash(T[i], OutputLen, Customization)
                let out_bytes = output_len_bits / 8;
                let mut new_output = vec![0u8; out_bytes];
                compute(&elements, &customization, &mut new_output)?;

                // Carry T[i][0] forward as next iter's T[i-1][0].
                t_zero.clone_from(&elements[0]);

                // Rightmost_Output_bits = Right(Output[i], 16) — 2 bytes
                let rightmost = right(&new_output, 16);
                let rightmost_num = usize::from(be_u16_from_2_bytes(&rightmost));

                // OutputLen update.
                let modded = rightmost_num % range;
                output_len_bits = min_out_len + (modded / out_len_increment) * out_len_increment;

                // Customization = BitsToString(T[i][0] || Rightmost_Output_bits)
                // Uses the just-updated T[i][0] (= elements[0] = current t_zero).
                let mut combo = Vec::with_capacity(t_zero.len() + rightmost.len());
                combo.extend_from_slice(&t_zero);
                combo.extend_from_slice(&rightmost);
                customization = bits_to_string(&combo);

                if i == 1000 {
                    // Capture Output[1000] for OutputJ[j].
                    let out_len_i64 = i64::try_from(out_len_for_this_iter)
                        .map_err(|_| DispatchError::Crypto("TupleHash MCT outLen overflows i64"))?;
                    results_array.push(JsonValue::Object(vec![
                        (
                            "md".to_string(),
                            JsonValue::String(hex::encode_upper(&new_output)),
                        ),
                        ("outLen".to_string(), JsonValue::Number(out_len_i64)),
                    ]));
                }
            }
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
