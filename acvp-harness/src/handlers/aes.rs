//! AES AFT handlers for all seven ACVP modes (ACVP `ACVP-AES-*-1.0`).
//!
//! R14-A wired ECB / CBC / CTR. R14-B extends coverage to GCM, CCM,
//! KW, and KWP — the full FIPS 197 + SP 800-38A/C/D/F mode set.
//!
//! Each ACVP AFT group declares a `direction` (`encrypt` / `decrypt`)
//! and a `keyLen` (128, 192, or 256 bits); every test carries `key`
//! plus mode-specific fields (plaintext, ciphertext, IV/nonce, AAD,
//! tag, etc.).
//!
//! All seven handlers live on the default dispatch key
//! `(algorithm, None, "1.0")` — ACVP-AES-* is a single-field family
//! in the R13 three-tuple `(algorithm, Option<mode>, revision)` axis.
//!
//! Phase-1 scope notes:
//!
//! - CTR only receives byte-aligned payloads. The vendored slice
//!   filters tests whose `payloadLen` is a multiple of 8.
//! - GCM requires 96-bit IV and 128-bit tag (Phase-1 constraint).
//!   The vendored slice filters for these at generation time.
//! - AEAD decrypt / KW unwrap tests include `testPassed` cases
//!   where tag/ICV verification is expected to fail — the handler
//!   returns `{tcId, testPassed: false}` for those.
//! - MCT (`testType = "MCT"`) is implemented for ECB and CBC modes
//!   with the full 100×1000 iteration loop and key-schedule update.
//! - CTR (`testType = "CTR"`) is accepted for AES-CTR and processed
//!   identically to AFT — the ACVP server verifies counter properties
//!   (uniqueness, monotonic progression) server-side.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_aes::{
    cbc_decrypt, cbc_encrypt, ccm_decrypt, ccm_encrypt, ctr_xor, ecb_decrypt, ecb_encrypt,
    gcm_decrypt, gcm_encrypt, kw_unwrap, kw_wrap, kwp_unwrap, kwp_wrap, Aes128Key, Aes192Key,
    Aes256Key, BlockCipher, ModeError, BLOCK_SIZE,
};

/// AES block-cipher mode tag for dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AesMode {
    Ecb,
    Cbc,
    Ctr,
    Gcm,
    Ccm,
    Kw,
    Kwp,
}

/// AES-ECB AFT dispatcher.
pub struct AesEcbHandler;

/// AES-CBC AFT dispatcher.
pub struct AesCbcHandler;

/// AES-CTR AFT dispatcher.
pub struct AesCtrHandler;

/// AES-GCM AFT dispatcher (Phase-1: 96-bit IV, 128-bit tag only).
pub struct AesGcmHandler;

/// AES-CCM AFT dispatcher.
pub struct AesCcmHandler;

/// AES-KW AFT dispatcher (SP 800-38F key wrap).
pub struct AesKwHandler;

/// AES-KWP AFT dispatcher (SP 800-38F key wrap with padding).
pub struct AesKwpHandler;

impl AlgorithmHandler for AesEcbHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-ECB"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::aes_ecb_capability())
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::aes_cbc_capability())
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::aes_ctr_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Ctr)
    }
}

impl AlgorithmHandler for AesGcmHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-GCM"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::aes_gcm_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Gcm)
    }
}

impl AlgorithmHandler for AesCcmHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-CCM"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::aes_ccm_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Ccm)
    }
}

impl AlgorithmHandler for AesKwHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-KW"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::aes_kw_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Kw)
    }
}

impl AlgorithmHandler for AesKwpHandler {
    fn algorithm(&self) -> &'static str {
        "ACVP-AES-KWP"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::aes_kwp_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_aes_group(group, AesMode::Kwp)
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
    let direction = parse_direction(group)?;
    let key_len_bits = group
        .get("keyLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("keyLen"))?;
    if test_type == "MCT" {
        // MCT is supported for ECB and CBC only.
        match mode {
            AesMode::Ecb | AesMode::Cbc => {
                return handle_aes_mct_group(
                    group, mode, direction, tg_id, key_len_bits,
                );
            }
            _ => {
                return Err(DispatchError::UnsupportedTestType(
                    "MCT (not supported for this AES mode)".to_string(),
                ));
            }
        }
    }
    // CTR test type (counter-overflow / counter-uniqueness) is processed
    // identically to AFT from the IUT's perspective — the ACVP server
    // performs counter verification server-side. Accept it for AES-CTR.
    if test_type != "AFT" && !(test_type == "CTR" && mode == AesMode::Ctr) {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }
    // AEAD modes carry group-level tag/nonce length metadata.
    let group_meta = GroupMeta::from_group(group, mode)?;
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        results.push(run_aes_test(t, mode, direction, key_len_bits, &group_meta)?);
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

/// Group-level metadata extracted from the ACVP test-group header.
/// For ECB/CBC/CTR all fields are `None`; for AEAD/wrap modes the
/// relevant lengths are populated.
struct GroupMeta {
    /// GCM: tag size in bytes (Phase-1: always 16).
    gcm_tag: Option<usize>,
    /// CCM: nonce size in bytes (7..=13).
    ccm_nonce: Option<usize>,
    /// CCM: tag size in bytes (4,6,8,10,12,14,16).
    ccm_tag: Option<usize>,
}

impl GroupMeta {
    fn from_group(group: &JsonValue, mode: AesMode) -> Result<Self, DispatchError> {
        match mode {
            AesMode::Gcm => {
                let tag_bits = group
                    .get("tagLen")
                    .and_then(JsonValue::as_u64)
                    .ok_or(DispatchError::MissingField("tagLen"))?;
                if tag_bits % 8 != 0 {
                    return Err(DispatchError::Unsupported(
                        "AES-GCM: non-byte-aligned tagLen",
                    ));
                }
                Ok(Self {
                    gcm_tag: Some((tag_bits / 8) as usize),
                    ccm_nonce: None,
                    ccm_tag: None,
                })
            }
            AesMode::Ccm => {
                let iv_bits = group
                    .get("ivLen")
                    .and_then(JsonValue::as_u64)
                    .ok_or(DispatchError::MissingField("ivLen"))?;
                let tag_bits = group
                    .get("tagLen")
                    .and_then(JsonValue::as_u64)
                    .ok_or(DispatchError::MissingField("tagLen"))?;
                if iv_bits % 8 != 0 || tag_bits % 8 != 0 {
                    return Err(DispatchError::Unsupported(
                        "AES-CCM: non-byte-aligned ivLen or tagLen",
                    ));
                }
                Ok(Self {
                    gcm_tag: None,
                    ccm_nonce: Some((iv_bits / 8) as usize),
                    ccm_tag: Some((tag_bits / 8) as usize),
                })
            }
            _ => Ok(Self {
                gcm_tag: None,
                ccm_nonce: None,
                ccm_tag: None,
            }),
        }
    }
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

/// Execute a single AFT test case and return its response object.
///
/// For simple modes (ECB/CBC/CTR): `{tcId, ct}` or `{tcId, pt}`.
/// For GCM encrypt: `{tcId, ct, tag}`.
/// For GCM/CCM/KW/KWP decrypt: `{tcId, testPassed}` (+ `pt` if passed).
/// For CCM encrypt: `{tcId, ct}` (ct includes appended tag).
/// For KW/KWP encrypt: `{tcId, ct}`.
fn run_aes_test(
    t: &JsonValue,
    mode: AesMode,
    direction: Direction,
    key_len_bits: u64,
    meta: &GroupMeta,
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

    // AEAD / wrap modes have mode-specific response shapes.
    match mode {
        AesMode::Gcm => {
            return run_gcm_test(tc_id, &key_bytes, key_len_bits, direction, t, meta);
        }
        AesMode::Ccm => {
            return run_ccm_test(tc_id, &key_bytes, key_len_bits, direction, t, meta);
        }
        AesMode::Kw => {
            return run_kw_test(tc_id, &key_bytes, key_len_bits, direction, t, false);
        }
        AesMode::Kwp => {
            return run_kw_test(tc_id, &key_bytes, key_len_bits, direction, t, true);
        }
        _ => {}
    }

    // Simple modes: ECB / CBC / CTR.
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

/// Type-dispatching one-shot call into `oxicrypt_aes`. Returns the
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
            let cipher = Aes128Key::new_internal(&key_arr);
            run_mode(&cipher, mode, direction, t, input)
        }
        192 => {
            let key_arr: [u8; 24] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES AFT: 192-bit key decoded to wrong length")
            })?;
            let cipher = Aes192Key::new_internal(&key_arr);
            run_mode(&cipher, mode, direction, t, input)
        }
        256 => {
            let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES AFT: 256-bit key decoded to wrong length")
            })?;
            let cipher = Aes256Key::new_internal(&key_arr);
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
        // AEAD / wrap modes are dispatched directly from run_aes_test
        // and never reach run_mode.
        AesMode::Gcm | AesMode::Ccm | AesMode::Kw | AesMode::Kwp => {
            unreachable!("AEAD/wrap modes handled before run_mode")
        }
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
    r.map_err(|_| DispatchError::Crypto("oxicrypt_aes::ecb_* returned Err"))
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
    r.map_err(|_| DispatchError::Crypto("oxicrypt_aes::cbc_* returned Err"))
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

// ---- GCM -----------------------------------------------------------

fn run_gcm_test(
    tc_id: i64,
    key_bytes: &[u8],
    key_len_bits: u64,
    direction: Direction,
    t: &JsonValue,
    meta: &GroupMeta,
) -> Result<JsonValue, DispatchError> {
    let tag_len = meta
        .gcm_tag
        .ok_or(DispatchError::Crypto("AES-GCM: missing gcm_tag in meta"))?;
    let iv = decode_iv_var(t)?;
    let aad = decode_aad(t)?;

    match direction {
        Direction::Encrypt => {
            let pt = decode_hex_field(t, "pt")?;
            let ct_tag =
                dispatch_gcm_encrypt(key_len_bits, key_bytes, &iv, &aad, &pt, tag_len)?;
            let (ct_part, tag_part) = ct_tag.split_at(ct_tag.len() - tag_len);
            Ok(JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(tc_id)),
                (
                    "ct".to_string(),
                    JsonValue::String(hex::encode_upper(ct_part)),
                ),
                (
                    "tag".to_string(),
                    JsonValue::String(hex::encode_upper(tag_part)),
                ),
            ]))
        }
        Direction::Decrypt => {
            let ct = decode_hex_field(t, "ct")?;
            let tag = decode_hex_field(t, "tag")?;
            if tag.len() != tag_len {
                return Err(DispatchError::Crypto(
                    "AES-GCM: tag length doesn't match group tagLen",
                ));
            }
            match dispatch_gcm_decrypt(key_len_bits, key_bytes, &iv, &aad, &ct, &tag) {
                Ok(pt) => Ok(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    (
                        "testPassed".to_string(),
                        JsonValue::Bool(true),
                    ),
                    (
                        "pt".to_string(),
                        JsonValue::String(hex::encode_upper(&pt)),
                    ),
                ])),
                Err(DispatchError::Crypto("tag mismatch")) => Ok(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    ("testPassed".to_string(), JsonValue::Bool(false)),
                ])),
                Err(e) => Err(e),
            }
        }
    }
}

fn dispatch_gcm_encrypt(
    key_len_bits: u64,
    key_bytes: &[u8],
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, DispatchError> {
    // gcm_encrypt always produces a 16-byte tag; we truncate if tagLen < 16.
    let mut ct = vec![0u8; pt.len()];
    let mut tag_buf = [0u8; 16];
    let result = match key_len_bits {
        128 => {
            let k: [u8; 16] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES-GCM: 128-bit key wrong length")
            })?;
            let c = Aes128Key::new_internal(&k);
            gcm_encrypt(&c, iv, aad, pt, &mut ct, &mut tag_buf)
        }
        192 => {
            let k: [u8; 24] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES-GCM: 192-bit key wrong length")
            })?;
            let c = Aes192Key::new_internal(&k);
            gcm_encrypt(&c, iv, aad, pt, &mut ct, &mut tag_buf)
        }
        256 => {
            let k: [u8; 32] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES-GCM: 256-bit key wrong length")
            })?;
            let c = Aes256Key::new_internal(&k);
            gcm_encrypt(&c, iv, aad, pt, &mut ct, &mut tag_buf)
        }
        _ => return Err(DispatchError::Crypto("AES-GCM: unsupported keyLen")),
    };
    result.map_err(|_| DispatchError::Crypto("oxicrypt_aes::gcm_encrypt returned Err"))?;
    ct.extend_from_slice(&tag_buf[..tag_len]);
    Ok(ct)
}

fn dispatch_gcm_decrypt(
    key_len_bits: u64,
    key_bytes: &[u8],
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, DispatchError> {
    // Our API requires exactly 16-byte tag; pad shorter tags with zeros.
    let mut tag16 = [0u8; 16];
    tag16[..tag.len()].copy_from_slice(tag);
    let mut pt = vec![0u8; ct.len()];
    let result = match key_len_bits {
        128 => {
            let k: [u8; 16] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES-GCM: 128-bit key wrong length")
            })?;
            let c = Aes128Key::new_internal(&k);
            gcm_decrypt(&c, iv, aad, ct, &tag16, &mut pt)
        }
        192 => {
            let k: [u8; 24] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES-GCM: 192-bit key wrong length")
            })?;
            let c = Aes192Key::new_internal(&k);
            gcm_decrypt(&c, iv, aad, ct, &tag16, &mut pt)
        }
        256 => {
            let k: [u8; 32] = key_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("AES-GCM: 256-bit key wrong length")
            })?;
            let c = Aes256Key::new_internal(&k);
            gcm_decrypt(&c, iv, aad, ct, &tag16, &mut pt)
        }
        _ => return Err(DispatchError::Crypto("AES-GCM: unsupported keyLen")),
    };
    match result {
        Ok(()) => Ok(pt),
        Err(ModeError::TagMismatch) => Err(DispatchError::Crypto("tag mismatch")),
        Err(_) => Err(DispatchError::Crypto("oxicrypt_aes::gcm_decrypt returned Err")),
    }
}

// ---- CCM -----------------------------------------------------------

fn run_ccm_test(
    tc_id: i64,
    key_bytes: &[u8],
    key_len_bits: u64,
    direction: Direction,
    t: &JsonValue,
    meta: &GroupMeta,
) -> Result<JsonValue, DispatchError> {
    let nonce_len = meta
        .ccm_nonce
        .ok_or(DispatchError::Crypto("AES-CCM: missing ccm_nonce in meta"))?;
    let tag_len = meta
        .ccm_tag
        .ok_or(DispatchError::Crypto("AES-CCM: missing ccm_tag in meta"))?;
    let nonce = decode_iv_var(t)?;
    if nonce.len() != nonce_len {
        return Err(DispatchError::Crypto(
            "AES-CCM: decoded nonce length doesn't match group ivLen",
        ));
    }
    let aad = decode_aad(t)?;

    match direction {
        Direction::Encrypt => {
            let pt = decode_hex_field(t, "pt")?;
            let ct_with_tag =
                dispatch_ccm_encrypt(key_len_bits, key_bytes, &nonce, &aad, &pt, tag_len)?;
            Ok(JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(tc_id)),
                (
                    "ct".to_string(),
                    JsonValue::String(hex::encode_upper(&ct_with_tag)),
                ),
            ]))
        }
        Direction::Decrypt => {
            // CCM ct field contains ciphertext || tag.
            let ct_with_tag = decode_hex_field(t, "ct")?;
            match dispatch_ccm_decrypt(
                key_len_bits,
                key_bytes,
                &nonce,
                &aad,
                &ct_with_tag,
                tag_len,
            ) {
                Ok(pt) => Ok(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    (
                        "testPassed".to_string(),
                        JsonValue::Bool(true),
                    ),
                    (
                        "pt".to_string(),
                        JsonValue::String(hex::encode_upper(&pt)),
                    ),
                ])),
                Err(DispatchError::Crypto("tag mismatch")) => Ok(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    ("testPassed".to_string(), JsonValue::Bool(false)),
                ])),
                Err(e) => Err(e),
            }
        }
    }
}

fn dispatch_ccm_encrypt(
    key_len_bits: u64,
    key_bytes: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    tlen: usize,
) -> Result<Vec<u8>, DispatchError> {
    let mut out = vec![0u8; pt.len() + tlen];
    let result = match key_len_bits {
        128 => {
            let k: [u8; 16] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-CCM: key length"))?;
            let c = Aes128Key::new_internal(&k);
            ccm_encrypt(&c, nonce, aad, pt, tlen, &mut out)
        }
        192 => {
            let k: [u8; 24] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-CCM: key length"))?;
            let c = Aes192Key::new_internal(&k);
            ccm_encrypt(&c, nonce, aad, pt, tlen, &mut out)
        }
        256 => {
            let k: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-CCM: key length"))?;
            let c = Aes256Key::new_internal(&k);
            ccm_encrypt(&c, nonce, aad, pt, tlen, &mut out)
        }
        _ => return Err(DispatchError::Crypto("AES-CCM: unsupported keyLen")),
    };
    result.map_err(|_| DispatchError::Crypto("oxicrypt_aes::ccm_encrypt returned Err"))?;
    Ok(out)
}

fn dispatch_ccm_decrypt(
    key_len_bits: u64,
    key_bytes: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct_with_tag: &[u8],
    tlen: usize,
) -> Result<Vec<u8>, DispatchError> {
    if ct_with_tag.len() < tlen {
        return Err(DispatchError::Crypto(
            "AES-CCM: ct shorter than tagLen",
        ));
    }
    let pt_len = ct_with_tag.len() - tlen;
    let mut out = vec![0u8; pt_len];
    let result = match key_len_bits {
        128 => {
            let k: [u8; 16] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-CCM: key length"))?;
            let c = Aes128Key::new_internal(&k);
            ccm_decrypt(&c, nonce, aad, ct_with_tag, tlen, &mut out)
        }
        192 => {
            let k: [u8; 24] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-CCM: key length"))?;
            let c = Aes192Key::new_internal(&k);
            ccm_decrypt(&c, nonce, aad, ct_with_tag, tlen, &mut out)
        }
        256 => {
            let k: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-CCM: key length"))?;
            let c = Aes256Key::new_internal(&k);
            ccm_decrypt(&c, nonce, aad, ct_with_tag, tlen, &mut out)
        }
        _ => return Err(DispatchError::Crypto("AES-CCM: unsupported keyLen")),
    };
    match result {
        Ok(()) => Ok(out),
        Err(ModeError::TagMismatch) => Err(DispatchError::Crypto("tag mismatch")),
        Err(_) => Err(DispatchError::Crypto(
            "oxicrypt_aes::ccm_decrypt returned Err",
        )),
    }
}

// ---- KW / KWP ------------------------------------------------------

fn run_kw_test(
    tc_id: i64,
    key_bytes: &[u8],
    key_len_bits: u64,
    direction: Direction,
    t: &JsonValue,
    with_padding: bool,
) -> Result<JsonValue, DispatchError> {
    match direction {
        Direction::Encrypt => {
            let pt = decode_hex_field(t, "pt")?;
            let ct = dispatch_kw_wrap(key_len_bits, key_bytes, &pt, with_padding)?;
            Ok(JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(tc_id)),
                (
                    "ct".to_string(),
                    JsonValue::String(hex::encode_upper(&ct)),
                ),
            ]))
        }
        Direction::Decrypt => {
            let ct = decode_hex_field(t, "ct")?;
            match dispatch_kw_unwrap(key_len_bits, key_bytes, &ct, with_padding) {
                Ok(pt) => Ok(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    (
                        "testPassed".to_string(),
                        JsonValue::Bool(true),
                    ),
                    (
                        "pt".to_string(),
                        JsonValue::String(hex::encode_upper(&pt)),
                    ),
                ])),
                Err(DispatchError::Crypto("tag mismatch")) => Ok(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(tc_id)),
                    ("testPassed".to_string(), JsonValue::Bool(false)),
                ])),
                Err(e) => Err(e),
            }
        }
    }
}

fn dispatch_kw_wrap(
    key_len_bits: u64,
    key_bytes: &[u8],
    pt: &[u8],
    with_padding: bool,
) -> Result<Vec<u8>, DispatchError> {
    let ct_len = if with_padding {
        pt.len().div_ceil(8) * 8 + 8
    } else {
        pt.len() + 8
    };
    let mut ct = vec![0u8; ct_len];
    let result = match key_len_bits {
        128 => {
            let k: [u8; 16] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-KW: key length"))?;
            let c = Aes128Key::new_internal(&k);
            if with_padding {
                kwp_wrap(&c, pt, &mut ct)
            } else {
                kw_wrap(&c, pt, &mut ct)
            }
        }
        192 => {
            let k: [u8; 24] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-KW: key length"))?;
            let c = Aes192Key::new_internal(&k);
            if with_padding {
                kwp_wrap(&c, pt, &mut ct)
            } else {
                kw_wrap(&c, pt, &mut ct)
            }
        }
        256 => {
            let k: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-KW: key length"))?;
            let c = Aes256Key::new_internal(&k);
            if with_padding {
                kwp_wrap(&c, pt, &mut ct)
            } else {
                kw_wrap(&c, pt, &mut ct)
            }
        }
        _ => return Err(DispatchError::Crypto("AES-KW: unsupported keyLen")),
    };
    result.map_err(|_| DispatchError::Crypto("oxicrypt_aes::kw_wrap returned Err"))?;
    Ok(ct)
}

fn dispatch_kw_unwrap(
    key_len_bits: u64,
    key_bytes: &[u8],
    ct: &[u8],
    with_padding: bool,
) -> Result<Vec<u8>, DispatchError> {
    let pt_len = ct.len().saturating_sub(8);
    let mut pt = vec![0u8; pt_len];
    let result = match key_len_bits {
        128 => {
            let k: [u8; 16] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-KW: key length"))?;
            let c = Aes128Key::new_internal(&k);
            if with_padding {
                kwp_unwrap(&c, ct, &mut pt).map(|actual_len| pt.truncate(actual_len))
            } else {
                kw_unwrap(&c, ct, &mut pt)
            }
        }
        192 => {
            let k: [u8; 24] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-KW: key length"))?;
            let c = Aes192Key::new_internal(&k);
            if with_padding {
                kwp_unwrap(&c, ct, &mut pt).map(|actual_len| pt.truncate(actual_len))
            } else {
                kw_unwrap(&c, ct, &mut pt)
            }
        }
        256 => {
            let k: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("AES-KW: key length"))?;
            let c = Aes256Key::new_internal(&k);
            if with_padding {
                kwp_unwrap(&c, ct, &mut pt).map(|actual_len| pt.truncate(actual_len))
            } else {
                kw_unwrap(&c, ct, &mut pt)
            }
        }
        _ => return Err(DispatchError::Crypto("AES-KW: unsupported keyLen")),
    };
    match result {
        Ok(()) => Ok(pt),
        Err(ModeError::TagMismatch) => Err(DispatchError::Crypto("tag mismatch")),
        Err(_) => Err(DispatchError::Crypto(
            "oxicrypt_aes::kw_unwrap returned Err",
        )),
    }
}

// ---- MCT engine (ECB / CBC) ----------------------------------------

/// Number of outer iterations in an AES MCT test.
const MCT_OUTER: usize = 100;

/// Number of inner iterations per outer iteration.
const MCT_INNER: usize = 1000;

/// Handle a complete MCT group. Each group has exactly one test with
/// initial `key` and `pt` (encrypt) or `ct` (decrypt), plus `iv` for
/// CBC. The handler runs the MCT algorithm and emits a `resultsArray`
/// with `MCT_OUTER` entries.
fn handle_aes_mct_group(
    group: &JsonValue,
    mode: AesMode,
    direction: Direction,
    tg_id: i64,
    key_len_bits: u64,
) -> Result<JsonValue, DispatchError> {
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    if tests.is_empty() {
        return Err(DispatchError::MissingField("tests (empty)"));
    }
    let t = &tests[0];
    let test_case_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;

    let key_bytes = decode_hex_field(t, "key")?;
    // Encrypt uses `pt` as the initial input; decrypt uses `ct`.
    let input_field = match direction {
        Direction::Encrypt => "pt",
        Direction::Decrypt => "ct",
    };
    let input_bytes = decode_hex_field(t, input_field)?;

    let results_array = match mode {
        AesMode::Ecb => mct_ecb(direction, key_len_bits, &key_bytes, &input_bytes)?,
        AesMode::Cbc => {
            let iv_bytes = decode_hex_field(t, "iv")?;
            mct_cbc(direction, key_len_bits, &key_bytes, &iv_bytes, &input_bytes)?
        }
        _ => unreachable!(),
    };

    let test_resp = JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(test_case_id)),
        ("resultsArray".to_string(), JsonValue::Array(results_array)),
    ]);

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(vec![test_resp])),
    ]))
}

/// AES-ECB MCT algorithm (ACVP-AES-ECB §6.2).
///
/// For encrypt:
///   Key[0] = initial key; Input[0] = initial pt
///   For i = 0..MCT_OUTER:
///     For j = 0..MCT_INNER:
///       Output[j] = AES_ECB(Key[i], Input[j])
///       Input[j+1] = Output[j]
///     resultsArray[i] = {key: Key[i], pt: Input[0], ct: Output[999]}
///     Key[i+1] = key_update(Key[i], Output[998], Output[999])
///     Input[0] = Output[999]
fn mct_ecb(
    direction: Direction,
    key_len_bits: u64,
    initial_key: &[u8],
    initial_input: &[u8],
) -> Result<Vec<JsonValue>, DispatchError> {
    let key_len = initial_key.len();
    let mut key = initial_key.to_vec();
    let mut input = initial_input.to_vec();
    let mut results = Vec::with_capacity(MCT_OUTER);

    for _i in 0..MCT_OUTER {
        let (input_label, output_label) = match direction {
            Direction::Encrypt => ("pt", "ct"),
            Direction::Decrypt => ("ct", "pt"),
        };
        let saved_input = input.clone();
        let mut prev_output = vec![0u8; BLOCK_SIZE];
        let mut output = vec![0u8; BLOCK_SIZE];

        for j in 0..MCT_INNER {
            if j > 0 {
                prev_output.copy_from_slice(&output);
            }
            ecb_one_block(direction, key_len_bits, &key, &input, &mut output)?;
            input.copy_from_slice(&output);
            if j == 0 {
                prev_output.copy_from_slice(&output);
            }
        }
        // prev_output = Output[998] (for j < MCT_INNER-1, captured above)
        // Actually: after the loop, prev_output = Output[MCT_INNER-2],
        // output = Output[MCT_INNER-1]. But we need to be precise:
        // j=0: output=O[0], prev_output set to O[0] after
        // j=1: prev_output=O[0], output=O[1]
        // j=999: prev_output=O[998], output=O[999] ✓

        let mut entry = vec![
            (
                "key".to_string(),
                JsonValue::String(hex::encode_upper(&key)),
            ),
            (
                input_label.to_string(),
                JsonValue::String(hex::encode_upper(&saved_input)),
            ),
            (
                output_label.to_string(),
                JsonValue::String(hex::encode_upper(&output)),
            ),
        ];
        // CBC also has IV but ECB doesn't — this is ECB so no IV needed.
        let _ = &mut entry; // suppress unused_mut if refactored
        results.push(JsonValue::Object(entry));

        // Key update.
        mct_key_update(&mut key, key_len, &prev_output, &output);
        input.copy_from_slice(&output);
    }

    Ok(results)
}

/// AES-CBC MCT algorithm (ACVP-AES-CBC §6.2).
///
/// For encrypt:
///   Key[0] = initial key; IV[0] = initial iv; PT[0] = initial pt
///   For i = 0..MCT_OUTER:
///     For j = 0..MCT_INNER:
///       if j == 0: CT[0] = AES_CBC_Encrypt(Key[i], IV[i], PT[0])
///       else:      CT[j] = AES_CBC_Encrypt(Key[i], CT[j-1], PT[j])
///       if j == 0: PT[1] = IV[i]
///       else:      PT[j+1] = CT[j-1]
///     resultsArray[i] = {key, iv, pt, ct}
///     Key[i+1] = key_update(Key[i], CT[998], CT[999])
///     IV[i+1] = CT[999]
///     PT[0] = CT[998]
fn mct_cbc(
    direction: Direction,
    key_len_bits: u64,
    initial_key: &[u8],
    initial_iv: &[u8],
    initial_input: &[u8],
) -> Result<Vec<JsonValue>, DispatchError> {
    let key_len = initial_key.len();
    let mut key = initial_key.to_vec();
    let mut iv = initial_iv.to_vec();
    let mut input = initial_input.to_vec();
    let mut results = Vec::with_capacity(MCT_OUTER);

    for _i in 0..MCT_OUTER {
        let (input_label, output_label) = match direction {
            Direction::Encrypt => ("pt", "ct"),
            Direction::Decrypt => ("ct", "pt"),
        };
        let saved_key = key.clone();
        let saved_iv = iv.clone();
        let saved_input = input.clone();

        let mut prev_output = vec![0u8; BLOCK_SIZE];
        let mut output = vec![0u8; BLOCK_SIZE];
        let mut cur_iv = iv.clone();

        for j in 0..MCT_INNER {
            if j > 0 {
                prev_output.copy_from_slice(&output);
            }
            // Save the current input before it's overwritten —
            // decrypt needs it for the next IV (IV[j+1] = CT[j]).
            let saved_input = input.clone();
            cbc_one_block(direction, key_len_bits, &key, &cur_iv, &input, &mut output)?;

            // Update for next iteration:
            match direction {
                Direction::Encrypt => {
                    // IV for next = CT[j] (current output).
                    cur_iv.copy_from_slice(&output);
                    // Next PT = previous CT (or IV for j=0).
                    if j == 0 {
                        input.copy_from_slice(&iv);
                        prev_output.copy_from_slice(&output);
                    } else {
                        input.copy_from_slice(&prev_output);
                    }
                }
                Direction::Decrypt => {
                    // IV for next = CT[j] (current input, saved above).
                    cur_iv.copy_from_slice(&saved_input);
                    // Next CT = previous PT (or IV for j=0).
                    if j == 0 {
                        prev_output.copy_from_slice(&output);
                        input.copy_from_slice(&iv);
                    } else {
                        input.copy_from_slice(&prev_output);
                    }
                }
            }
        }
        // After loop: prev_output = Output[998], output = Output[999]

        results.push(JsonValue::Object(vec![
            (
                "key".to_string(),
                JsonValue::String(hex::encode_upper(&saved_key)),
            ),
            (
                "iv".to_string(),
                JsonValue::String(hex::encode_upper(&saved_iv)),
            ),
            (
                input_label.to_string(),
                JsonValue::String(hex::encode_upper(&saved_input)),
            ),
            (
                output_label.to_string(),
                JsonValue::String(hex::encode_upper(&output)),
            ),
        ]));

        // Key update.
        mct_key_update(&mut key, key_len, &prev_output, &output);
        iv.copy_from_slice(&output);
        input.copy_from_slice(&prev_output);
    }

    Ok(results)
}

/// Single-block ECB operation used by the MCT inner loop.
fn ecb_one_block(
    direction: Direction,
    key_len_bits: u64,
    key: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), DispatchError> {
    let r = match key_len_bits {
        128 => {
            let k: [u8; 16] = key.try_into().map_err(|_| {
                DispatchError::Crypto("MCT ECB: key length")
            })?;
            let c = Aes128Key::new_internal(&k);
            match direction {
                Direction::Encrypt => ecb_encrypt(&c, input, output),
                Direction::Decrypt => ecb_decrypt(&c, input, output),
            }
        }
        192 => {
            let k: [u8; 24] = key.try_into().map_err(|_| {
                DispatchError::Crypto("MCT ECB: key length")
            })?;
            let c = Aes192Key::new_internal(&k);
            match direction {
                Direction::Encrypt => ecb_encrypt(&c, input, output),
                Direction::Decrypt => ecb_decrypt(&c, input, output),
            }
        }
        256 => {
            let k: [u8; 32] = key.try_into().map_err(|_| {
                DispatchError::Crypto("MCT ECB: key length")
            })?;
            let c = Aes256Key::new_internal(&k);
            match direction {
                Direction::Encrypt => ecb_encrypt(&c, input, output),
                Direction::Decrypt => ecb_decrypt(&c, input, output),
            }
        }
        _ => return Err(DispatchError::Crypto("MCT: unsupported keyLen")),
    };
    r.map_err(|_| DispatchError::Crypto("MCT ECB: encrypt/decrypt failed"))
}

/// Single-block CBC operation used by the MCT inner loop.
fn cbc_one_block(
    direction: Direction,
    key_len_bits: u64,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), DispatchError> {
    let iv16: [u8; 16] = iv.try_into().map_err(|_| {
        DispatchError::Crypto("MCT CBC: IV not 16 bytes")
    })?;
    let r = match key_len_bits {
        128 => {
            let k: [u8; 16] = key.try_into().map_err(|_| {
                DispatchError::Crypto("MCT CBC: key length")
            })?;
            let c = Aes128Key::new_internal(&k);
            match direction {
                Direction::Encrypt => cbc_encrypt(&c, &iv16, input, output),
                Direction::Decrypt => cbc_decrypt(&c, &iv16, input, output),
            }
        }
        192 => {
            let k: [u8; 24] = key.try_into().map_err(|_| {
                DispatchError::Crypto("MCT CBC: key length")
            })?;
            let c = Aes192Key::new_internal(&k);
            match direction {
                Direction::Encrypt => cbc_encrypt(&c, &iv16, input, output),
                Direction::Decrypt => cbc_decrypt(&c, &iv16, input, output),
            }
        }
        256 => {
            let k: [u8; 32] = key.try_into().map_err(|_| {
                DispatchError::Crypto("MCT CBC: key length")
            })?;
            let c = Aes256Key::new_internal(&k);
            match direction {
                Direction::Encrypt => cbc_encrypt(&c, &iv16, input, output),
                Direction::Decrypt => cbc_decrypt(&c, &iv16, input, output),
            }
        }
        _ => return Err(DispatchError::Crypto("MCT: unsupported keyLen")),
    };
    r.map_err(|_| DispatchError::Crypto("MCT CBC: encrypt/decrypt failed"))
}

/// MCT key schedule update.
///
/// - 128-bit: Key[i+1] = Key[i] XOR Output[999]
/// - 192-bit: Key[i+1] = Key[i] XOR (last 8 bytes of Output[998] || Output[999])
/// - 256-bit: Key[i+1] = Key[i] XOR (Output[998] || Output[999])
fn mct_key_update(
    key: &mut [u8],
    key_len: usize,
    prev_output: &[u8],
    last_output: &[u8],
) {
    match key_len {
        16 => {
            // 128-bit: XOR with last output block
            for (k, o) in key.iter_mut().zip(last_output.iter()) {
                *k ^= o;
            }
        }
        24 => {
            // 192-bit: XOR with last 8 bytes of prev_output || last_output
            // = 24 bytes total
            let tail8 = &prev_output[BLOCK_SIZE - 8..];
            for (k, o) in key[..8].iter_mut().zip(tail8.iter()) {
                *k ^= o;
            }
            for (k, o) in key[8..].iter_mut().zip(last_output.iter()) {
                *k ^= o;
            }
        }
        32 => {
            // 256-bit: XOR with prev_output || last_output
            for (k, o) in key[..16].iter_mut().zip(prev_output.iter()) {
                *k ^= o;
            }
            for (k, o) in key[16..].iter_mut().zip(last_output.iter()) {
                *k ^= o;
            }
        }
        _ => {}
    }
}

// ---- Shared helpers ------------------------------------------------

/// Decode a variable-length IV/nonce from the `iv` field.
fn decode_iv_var(t: &JsonValue) -> Result<Vec<u8>, DispatchError> {
    let iv_hex = t
        .get("iv")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("iv"))?;
    Ok(hex::decode(iv_hex)?)
}

/// Decode the AAD field, treating missing as empty.
fn decode_aad(t: &JsonValue) -> Result<Vec<u8>, DispatchError> {
    match t.get("aad").and_then(JsonValue::as_str) {
        Some(s) if !s.is_empty() => Ok(hex::decode(s)?),
        _ => Ok(Vec::new()),
    }
}

/// Decode any hex field by name.
fn decode_hex_field(t: &JsonValue, name: &'static str) -> Result<Vec<u8>, DispatchError> {
    let h = t
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(name))?;
    Ok(hex::decode(h)?)
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
