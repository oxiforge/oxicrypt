//! AES AFT handlers for ECB / CBC / CTR (ACVP `ACVP-AES-*-1.0`).
//!
//! R14-A wires the first three symmetric-cipher families into the
//! dispatcher. Each ACVP AFT group declares a `direction`
//! (`encrypt` / `decrypt`) and a `keyLen` (128, 192, or 256 bits);
//! every test inside the group carries `key`, the plaintext/
//! ciphertext field the direction consumes, and — for CBC and CTR —
//! the 128-bit IV (or RFC 3686 initial counter block).
//!
//! The handler returns the opposite field as hex:
//!
//! - `direction = "encrypt"` → response test carries `ct`
//! - `direction = "decrypt"` → response test carries `pt`
//!
//! All three handlers live on the default dispatch key
//! `(algorithm, None, "1.0")` — ACVP-AES-* is a single-field family
//! in the R13 three-tuple `(algorithm, Option<mode>, revision)` axis.
//!
//! Phase-1 scope notes:
//!
//! - CTR only receives byte-aligned payloads. The vendored slice in
//!   `tools/acvp-gen/generate.py` filters ACVP tests to those whose
//!   `payloadLen` is a multiple of 8, matching the byte-oriented
//!   `fips_aes::ctr_xor` entry point.
//! - MCT (`testType = "MCT"`) groups are explicitly rejected as
//!   `UnsupportedTestType`; the MCT engine comes in a later chunk.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_aes::{
    cbc_decrypt, cbc_encrypt, ctr_xor, ecb_decrypt, ecb_encrypt, Aes128Key, Aes192Key, Aes256Key,
    BlockCipher, BLOCK_SIZE,
};

/// The three AES block-cipher modes the R14-A handler covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AesMode {
    Ecb,
    Cbc,
    Ctr,
}

/// AES-ECB AFT dispatcher.
pub struct AesEcbHandler;

/// AES-CBC AFT dispatcher.
pub struct AesCbcHandler;

/// AES-CTR AFT dispatcher.
pub struct AesCtrHandler;

impl AlgorithmHandler for AesEcbHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-ECB"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Ecb)
    }
}

impl AlgorithmHandler for AesCbcHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-CBC"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Cbc)
    }
}

impl AlgorithmHandler for AesCtrHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-CTR"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Ctr)
    }
}

/// Direction parsed from the group header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// Walk an AES AFT group, dispatching each test to the mode-specific
/// one-shot routine. MCT groups are rejected explicitly.
fn handle_aes_group(group: &JsonValue, mode: AesMode) -> Result<JsonValue, DispatchError> {
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
    let direction = parse_direction(group)?;
    let key_len_bits = group
        .get("keyLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("keyLen"))?;
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        results.push(run_aes_test(t, mode, direction, key_len_bits)?);
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

fn parse_direction(group: &JsonValue) -> Result<Direction, DispatchError> {
    let d = group
        .get("direction")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("direction"))?;
    match d {
        "encrypt" => Ok(Direction::Encrypt),
        "decrypt" => Ok(Direction::Decrypt),
        _ => Err(DispatchError::Crypto(
            "AES AFT: unrecognised `direction` (expected \"encrypt\" or \"decrypt\")",
        )),
    }
}

/// Execute a single AFT test case and return its response object
/// (either `{tcId, ct}` for encrypt or `{tcId, pt}` for decrypt).
fn run_aes_test(
    t: &JsonValue,
    mode: AesMode,
    direction: Direction,
    key_len_bits: u64,
) -> Result<JsonValue, DispatchError> {
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let key_hex = t
        .get("key")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("key"))?;
    let key_bytes = hex::decode(key_hex)?;
    if key_bytes.len() as u64 * 8 != key_len_bits {
        return Err(DispatchError::Crypto(
            "AES AFT: `key` byte length does not match group `keyLen`",
        ));
    }
    let (input_field, output_field) = match direction {
        Direction::Encrypt => ("pt", "ct"),
        Direction::Decrypt => ("ct", "pt"),
    };
    let input_hex = t
        .get(input_field)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(match direction {
            Direction::Encrypt => "pt",
            Direction::Decrypt => "ct",
        }))?;
    let input = hex::decode(input_hex)?;
    let output = dispatch_one_shot(mode, direction, key_len_bits, &key_bytes, t, &input)?;
    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        (
            output_field.to_string(),
            JsonValue::String(hex::encode_upper(&output)),
        ),
    ]))
}

/// Type-dispatching one-shot call into `fips_aes`. Returns the
/// resulting ciphertext or plaintext bytes.
fn dispatch_one_shot(
    mode: AesMode,
    direction: Direction,
    key_len_bits: u64,
    key_bytes: &[u8],
    t: &JsonValue,
    input: &[u8],
) -> Result<Vec<u8>, DispatchError> {
    match key_len_bits {
        128 => {
            let key_arr: [u8; 16] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES AFT: 128-bit key decoded to wrong length")
            })?;
            let cipher = Aes128Key::new(&key_arr);
            run_mode(&cipher, mode, direction, t, input)
        }
        192 => {
            let key_arr: [u8; 24] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES AFT: 192-bit key decoded to wrong length")
            })?;
            let cipher = Aes192Key::new(&key_arr);
            run_mode(&cipher, mode, direction, t, input)
        }
        256 => {
            let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES AFT: 256-bit key decoded to wrong length")
            })?;
            let cipher = Aes256Key::new(&key_arr);
            run_mode(&cipher, mode, direction, t, input)
        }
        _ => Err(DispatchError::Crypto(
            "AES AFT: unsupported keyLen (expected 128, 192, or 256)",
        )),
    }
}

/// Mode-level one-shot: takes a keyed cipher and runs ECB/CBC/CTR
/// in the requested direction. Shared by all three keyLens.
fn run_mode<B: BlockCipher>(
    cipher: &B,
    mode: AesMode,
    direction: Direction,
    t: &JsonValue,
    input: &[u8],
) -> Result<Vec<u8>, DispatchError> {
    let mut out = vec![0u8; input.len()];
    match mode {
        AesMode::Ecb => run_ecb(cipher, direction, input, &mut out)?,
        AesMode::Cbc => run_cbc(cipher, direction, t, input, &mut out)?,
        AesMode::Ctr => run_ctr(cipher, t, input, &mut out)?,
    }
    Ok(out)
}

fn run_ecb<B: BlockCipher>(
    cipher: &B,
    direction: Direction,
    input: &[u8],
    out: &mut [u8],
) -> Result<(), DispatchError> {
    if !input.len().is_multiple_of(BLOCK_SIZE) {
        return Err(DispatchError::Crypto(
            "AES-ECB AFT: input length is not a multiple of the 16-byte block size",
        ));
    }
    let r = match direction {
        Direction::Encrypt => ecb_encrypt(cipher, input, out),
        Direction::Decrypt => ecb_decrypt(cipher, input, out),
    };
    r.map_err(|_| DispatchError::Crypto("fips_aes::ecb_* returned Err"))
}

fn run_cbc<B: BlockCipher>(
    cipher: &B,
    direction: Direction,
    t: &JsonValue,
    input: &[u8],
    out: &mut [u8],
) -> Result<(), DispatchError> {
    let iv = decode_iv16(t)?;
    let r = match direction {
        Direction::Encrypt => cbc_encrypt(cipher, &iv, input, out),
        Direction::Decrypt => cbc_decrypt(cipher, &iv, input, out),
    };
    r.map_err(|_| DispatchError::Crypto("fips_aes::cbc_* returned Err"))
}

fn run_ctr<B: BlockCipher>(
    cipher: &B,
    t: &JsonValue,
    input: &[u8],
    out: &mut [u8],
) -> Result<(), DispatchError> {
    if let Some(payload_len) = t.get("payloadLen").and_then(JsonValue::as_u64) {
        if !payload_len.is_multiple_of(8) {
            return Err(DispatchError::Unsupported(
                "AES-CTR AFT with non-byte-aligned `payloadLen`",
            ));
        }
        if payload_len / 8 != input.len() as u64 {
            return Err(DispatchError::Crypto(
                "AES-CTR AFT: `payloadLen` disagrees with the decoded input byte length",
            ));
        }
    }
    let icb = decode_iv16(t)?;
    ctr_xor(cipher, &icb, input, out);
    Ok(())
}

fn decode_iv16(t: &JsonValue) -> Result<[u8; 16], DispatchError> {
    let iv_hex = t
        .get("iv")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("iv"))?;
    let iv_bytes = hex::decode(iv_hex)?;
    iv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("AES AFT: `iv` is not exactly 16 bytes"))
}
