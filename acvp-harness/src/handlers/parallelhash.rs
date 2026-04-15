//! ParallelHash-128 / ParallelHash-256 and ParallelHashXOF-128 / ParallelHashXOF-256
//! AFT handlers.
//!
//! Targets self-generated ACVP slices with `algorithm = "ParallelHash-128"`,
//! `"ParallelHash-256"`, `"ParallelHashXOF-128"`, or `"ParallelHashXOF-256"`,
//! `revision = "1.0"`, `testType = "AFT"`.
//!
//! Each test case carries:
//!
//! - `msg` (hex) — input message
//! - `len` (bits) — message length
//! - `outLen` (bits) — requested output length
//! - `blockSize` (integer) — block size B in bytes
//! - `hexCustomization` (hex) — customization string S
//!
//! The `blockSize` field may appear at group level (shared by all tests
//! in the group) or at test level (per-test override). Test-level takes
//! precedence.
//!
//! Response field: `md` (hex).
//!
//! The XOF variants use the squeeze pattern (`finalize()` + `squeeze()`)
//! rather than `finalize_into()`, producing extendable output.
//!
//! Since the NIST ACVP-Server at the pinned commit ships no ParallelHash
//! vector directories, all vectors are self-generated.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_xof::{ParallelHash128, ParallelHash256, ParallelHashXof128, ParallelHashXof256};

/// ParallelHash-128 AFT handler.
pub struct ParallelHash128Handler;

/// ParallelHash-256 AFT handler.
pub struct ParallelHash256Handler;

impl AlgorithmHandler for ParallelHash128Handler {
    fn algorithm(&self) -> &'static str {
        "ParallelHash-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::parallelhash_capability("ParallelHash-128", false))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_parallelhash_group(group, |msg, block_size, s, out| {
            let mut h = ParallelHash128::new(block_size, s)
                .map_err(|_| DispatchError::Crypto("ParallelHash128::new returned Err"))?;
            h.update(msg);
            h.finalize_into(out);
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
        Some(super::caps::parallelhash_capability("ParallelHash-256", false))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_parallelhash_group(group, |msg, block_size, s, out| {
            let mut h = ParallelHash256::new(block_size, s)
                .map_err(|_| DispatchError::Crypto("ParallelHash256::new returned Err"))?;
            h.update(msg);
            h.finalize_into(out);
            Ok(())
        })
    }
}

/// ParallelHashXOF-128 AFT handler.
pub struct ParallelHashXof128Handler;

/// ParallelHashXOF-256 AFT handler.
pub struct ParallelHashXof256Handler;

impl AlgorithmHandler for ParallelHashXof128Handler {
    fn algorithm(&self) -> &'static str {
        "ParallelHashXOF-128"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::parallelhash_capability("ParallelHashXOF-128", true))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_parallelhash_group(group, |msg, block_size, s, out| {
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
        Some(super::caps::parallelhash_capability("ParallelHashXOF-256", true))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_parallelhash_group(group, |msg, block_size, s, out| {
            let mut h = ParallelHashXof256::new(block_size, s)
                .map_err(|_| DispatchError::Crypto("ParallelHashXof256::new returned Err"))?;
            h.update(msg);
            h.finalize();
            h.squeeze(out);
            Ok(())
        })
    }
}

/// Shared group driver for ParallelHash AFT.
fn handle_parallelhash_group<F>(
    group: &JsonValue,
    mut compute: F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8], usize, &[u8], &mut [u8]) -> Result<(), DispatchError>,
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

        // Customization string S (hex-encoded).
        let s_hex = t
            .get("hexCustomization")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let s = if s_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(s_hex)?
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
