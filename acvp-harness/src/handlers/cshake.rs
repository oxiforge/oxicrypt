//! cSHAKE-128 / cSHAKE-256 AFT + MCT handlers.
//!
//! Targets ACVP slices with `algorithm = "cSHAKE-128"` or
//! `"cSHAKE-256"`, `revision = "1.0"`, `testType ∈ {"AFT", "MCT"}`.
//!
//! Group-level fields (per `draft-celi-acvp-xof` §8.1 Table 5):
//!
//! - `hexCustomization` (boolean, AFT) — `true` if per-test
//!   customization strings are hex-encoded, `false` if ASCII.
//!   Defaults to `false` when absent (back-compat with offline
//!   fixtures).
//! - `minOutLen`, `maxOutLen`, `outLenIncrement` (integers, MCT)
//!   — Monte Carlo Test output-length domain.
//!
//! Per-test fields (per §8.2 Table 6):
//!
//! - `msg` (hex) — input message (AFT) or initial seed (MCT)
//! - `len` (bits) — message length
//! - `outLen` (bits, AFT only) — requested output length
//! - `customization` (string, AFT only) — customization string S,
//!   encoded per the group-level `hexCustomization` boolean
//!
//! The function name N is always empty (per `draft-celi-acvp-xof`
//! §6.2.1 the MCT hard-codes `FunctionName = ""`, and the AFT
//! registration historically does not exercise non-empty N).
//! Response fields: `md` (hex) for AFT, `resultsArray` of `{md, outLen}`
//! objects for MCT.
//!
//! Since the NIST ACVP-Server at the pinned commit ships no cSHAKE
//! vector directories, AFT vectors are self-generated and live in
//! `vendor/nist/acvp-server/gen-val/json-files/cSHAKE-{128,256}-1.0/`.
//! Self-generated fixtures emit the spec-conformant shape so the same
//! handler serves both offline round-trip and live ACVTS prompts. The
//! MCT path is exercised only against live ACVTS.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use crate::mct_helpers::{be_u16_from_2_bytes, bits_to_string, left, right};
use oxicrypt_xof::{CShake128, CShake256};

/// cSHAKE-128 handler (AFT + MCT).
pub struct CShake128Handler;

/// cSHAKE-256 handler (AFT + MCT).
pub struct CShake256Handler;

impl AlgorithmHandler for CShake128Handler {
    fn algorithm(&self) -> &'static str {
        "cSHAKE-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::cshake_capability("cSHAKE-128"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        dispatch_cshake_group(group, |msg, s, out| {
            let mut x = CShake128::new(b"", s)
                .map_err(|_| DispatchError::Crypto("CShake128::new returned Err"))?;
            x.update(msg);
            x.finalize();
            x.squeeze(out);
            Ok(())
        })
    }
}

impl AlgorithmHandler for CShake256Handler {
    fn algorithm(&self) -> &'static str {
        "cSHAKE-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::cshake_capability("cSHAKE-256"))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        dispatch_cshake_group(group, |msg, s, out| {
            let mut x = CShake256::new(b"", s)
                .map_err(|_| DispatchError::Crypto("CShake256::new returned Err"))?;
            x.update(msg);
            x.finalize();
            x.squeeze(out);
            Ok(())
        })
    }
}

/// Top-level cSHAKE group dispatch — routes by `testType` to the AFT
/// or MCT driver. The `cshake_call` closure is the cSHAKE primitive
/// for the active key size, invoked with `(msg, customization, out)`.
fn dispatch_cshake_group<F>(
    group: &JsonValue,
    mut cshake_call: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    match test_type {
        "AFT" => handle_cshake_aft_group(group, &mut cshake_call),
        "MCT" => handle_cshake_mct_group(group, &mut cshake_call),
        other => Err(DispatchError::UnsupportedTestType(other.to_string())),
    }
}

/// AFT driver — one cSHAKE call per test case, fixed `outLen` from
/// the prompt.
fn handle_cshake_aft_group<F>(
    group: &JsonValue,
    cshake_call: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &[u8], &mut [u8]) -> Result<(), DispatchError>,
{
    let group_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
    // Group-level encoding flag for the per-test `customization`
    // field (per `xof §8.1 Table 5`). Absent → false (ASCII), the
    // family pattern observed across all live KMAC sessions.
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
                "cSHAKE AFT with non-byte-aligned `len`",
            ));
        }
        if !out_len_bits.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "cSHAKE AFT with non-byte-aligned `outLen`",
            ));
        }
        let msg_bytes = (len_bits / 8) as usize;
        let out_bytes = (out_len_bits / 8) as usize;
        let msg_hex = t
            .get("msg")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("msg"))?;
        let msg = hex::decode(msg_hex)?;
        if msg.len() < msg_bytes {
            return Err(DispatchError::Crypto(
                "cSHAKE AFT: hex `msg` shorter than declared `len`",
            ));
        }
        let used = &msg[..msg_bytes];

        // Customization string S. Per-test `customization` field is
        // hex if the group-level boolean is true, ASCII otherwise.
        // Treat a missing field as the empty customization (S = "").
        let s_field = t.get("customization").and_then(JsonValue::as_str);
        let s = match s_field {
            None | Some("") => Vec::new(),
            Some(raw) if hex_customization => hex::decode(raw)?,
            Some(raw) => raw.as_bytes().to_vec(),
        };

        let mut out_buf = vec![0u8; out_bytes];
        cshake_call(used, &s, &mut out_buf)?;
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
/// `draft-celi-acvp-xof` §6.2.1.
///
/// The pseudocode there reads (paraphrased):
///
/// ```text
/// Output[0] = Msg
/// OutputLen = MaxOutLen
/// FunctionName = ""        // hard-coded
/// Customization = ""       // hard-coded
/// for j in 0..100:
///   for i in 1..1001:
///     InnerMsg = Left(Output[i-1] || ZeroBits(128), 128)
///     Output[i] = cSHAKE(InnerMsg, OutputLen, "", Customization)
///     Rightmost = Right(Output[i], 16)
///     OutputLen = MinOutLen + floor((Rightmost % Range) / Increment) * Increment
///     Customization = BitsToString(InnerMsg || Rightmost)
///   OutputJ[j] = Output[1000]
/// ```
///
/// `Output[0]` carries forward from one outer iteration to the next
/// (we keep `output` in a single mutable buffer across both loops),
/// and `OutputLen` / `Customization` persist across outer iterations
/// since the spec's hard-coded initializers run only once before the
/// outer loop. The reported `outLen` for each `OutputJ[j]` entry is
/// the `OutputLen` actually used to produce that output — captured
/// before the post-update at the same inner iteration.
fn handle_cshake_mct_group<F>(
    group: &JsonValue,
    cshake_call: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], &[u8], &mut [u8]) -> Result<(), DispatchError>,
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
    .map_err(|_| DispatchError::Crypto("cSHAKE MCT: minOutLen overflows usize"))?;
    let max_out_len = usize::try_from(
        group
            .get("maxOutLen")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("maxOutLen"))?,
    )
    .map_err(|_| DispatchError::Crypto("cSHAKE MCT: maxOutLen overflows usize"))?;
    let out_len_increment = usize::try_from(
        group
            .get("outLenIncrement")
            .and_then(JsonValue::as_u64)
            .ok_or(DispatchError::MissingField("outLenIncrement"))?,
    )
    .map_err(|_| DispatchError::Crypto("cSHAKE MCT: outLenIncrement overflows usize"))?;
    if !min_out_len.is_multiple_of(8)
        || !max_out_len.is_multiple_of(8)
        || !out_len_increment.is_multiple_of(8)
    {
        return Err(DispatchError::Unsupported(
            "cSHAKE MCT with non-byte-aligned output length",
        ));
    }
    if min_out_len > max_out_len || out_len_increment == 0 {
        return Err(DispatchError::Crypto(
            "cSHAKE MCT: degenerate output-length domain",
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
        let initial_msg = hex::decode(msg_hex)?;

        // Spec §6.2.1 pre-loop initial state.
        let mut output: Vec<u8> = initial_msg;
        let mut output_len_bits: usize = max_out_len;
        let mut customization: Vec<u8> = Vec::new();

        let mut results_array: Vec<JsonValue> = Vec::with_capacity(100);

        for _j in 0..100 {
            // `out_len_for_this_iter` records the OutputLen used to
            // produce the most recent Output[i] — needed because the
            // pseudocode mutates OutputLen *after* producing Output[i],
            // so the value reported with OutputJ[j] = Output[1000] is
            // the one that drove the i=1000 cSHAKE call, not the next
            // OutputLen derived from its rightmost bits.
            let mut out_len_for_this_iter = output_len_bits;

            for _i in 1..=1000 {
                out_len_for_this_iter = output_len_bits;

                // InnerMsg = Left(Output[i-1] || ZeroBits(128), 128) — 16 bytes
                let inner_msg = left(&output, 128);

                // Output[i] = cSHAKE(InnerMsg, OutputLen, "", Customization)
                let out_bytes = output_len_bits / 8;
                let mut new_output = vec![0u8; out_bytes];
                cshake_call(&inner_msg, &customization, &mut new_output)?;
                output = new_output;

                // Rightmost_Output_bits = Right(Output[i], 16) — 2 bytes
                let rightmost = right(&output, 16);
                let rightmost_num = usize::from(be_u16_from_2_bytes(&rightmost));

                // OutputLen = MinOutLen + floor((Rightmost % Range) / Increment) * Increment
                let modded = rightmost_num % range;
                output_len_bits = min_out_len + (modded / out_len_increment) * out_len_increment;

                // Customization = BitsToString(InnerMsg || Rightmost_Output_bits)
                let mut combo = Vec::with_capacity(inner_msg.len() + rightmost.len());
                combo.extend_from_slice(&inner_msg);
                combo.extend_from_slice(&rightmost);
                customization = bits_to_string(&combo);
            }

            // OutputJ[j] = Output[1000], at the OutputLen that produced it.
            let out_len_i64 = i64::try_from(out_len_for_this_iter)
                .map_err(|_| DispatchError::Crypto("cSHAKE MCT outLen overflows i64"))?;
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
