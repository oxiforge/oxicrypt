//! RSA ACVP handler — `OAEP` mode, revision `RFC8017`.
//!
//! **OAEP encrypt** (`RSA` / `OAEP` / `RFC8017`, `direction = "encrypt"`):
//! Given the public key `(n, e)`, a message, and a 32-byte OAEP seed,
//! perform RSAES-OAEP encryption (RFC 8017 §7.1.1) and return the
//! ciphertext.
//!
//! **OAEP decrypt** (`RSA` / `OAEP` / `RFC8017`, `direction = "decrypt"`):
//! Given the private key, and a ciphertext, perform RSAES-OAEP
//! decryption (RFC 8017 §7.1.2) and return the plaintext and its
//! length. Two key modes are supported:
//!
//! - `keyMode` absent or `"standard"`: non-CRT path via `(n, d)`.
//! - `keyMode = "crt"`: CRT path via `(n, e, p, q, dP, dQ, qInv)`
//!   with Bellcore verify-after-decrypt per FIPS 140-3 IG D.G.
//!
//! Supported configurations:
//! - `modulo = 2048`, `hashAlg = "SHA2-256"`, empty label

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// RSA OAEP dispatcher.
pub struct RsaOaepHandler;

impl AlgorithmHandler for RsaOaepHandler {
    fn algorithm(&self) -> &'static str {
        "RSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("OAEP")
    }
    fn revision(&self) -> &'static str {
        "RFC8017"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::rsa_oaep_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_oaep_group(group)
    }
}

// ── Constants ──────────────────────────────────────────────────────

const N_BYTES: usize = oxicrypt_rsa::RSA_2048_MODULUS_BYTES;
const HALF_BYTES: usize = oxicrypt_rsa::RSA_2048_CRT_HALF_BYTES;
const SEED_LEN: usize = 32; // SHA-256 hash length = OAEP seed length

// ── Helpers ────────────────────────────────────────────────────────

/// Decode a hex-encoded string field from a JSON object.
fn decode_hex_field(obj: &JsonValue, name: &'static str) -> Result<Vec<u8>, DispatchError> {
    let h = obj
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(name))?;
    Ok(hex::decode(h)?)
}

/// Parse a big-endian hex field into a fixed-size array, left-padding
/// with zeroes if the decoded value is shorter than `LEN`.
fn decode_fixed<const LEN: usize>(
    obj: &JsonValue,
    name: &'static str,
) -> Result<[u8; LEN], DispatchError> {
    let raw = decode_hex_field(obj, name)?;
    if raw.len() > LEN {
        return Err(DispatchError::Crypto("RSA OAEP: field too large"));
    }
    let mut buf = [0u8; LEN];
    buf[LEN - raw.len()..].copy_from_slice(&raw);
    Ok(buf)
}

/// Convert big-endian bytes to `u64`.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, DispatchError> {
    if bytes.len() > 8 {
        return Err(DispatchError::Crypto(
            "RSA OAEP: e exceeds 8 bytes (u64 range)",
        ));
    }
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    Ok(val)
}

// ── Group handler ──────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn handle_oaep_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let direction = group
        .get("direction")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("direction"))?;

    let modulo = group
        .get("modulo")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("modulo"))?;
    if modulo != 2048 {
        return Err(DispatchError::Unsupported(
            "RSA OAEP: only modulo 2048 is supported",
        ));
    }

    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;
    if hash_alg != "SHA2-256" {
        return Err(DispatchError::Unsupported(
            "RSA OAEP: only SHA2-256 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match direction {
        "encrypt" => {
            // Public key from group: n, e.
            let n: [u8; N_BYTES] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let label = b""; // standard OAEP, empty label

            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let msg = decode_hex_field(tc, "msg")?;
                let seed: [u8; SEED_LEN] = decode_fixed(tc, "seed")?;

                let ct =
                    oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(&n, e, label, &msg, &seed)
                        .ok_or(DispatchError::Crypto("RSA OAEP: encrypt failed"))?;

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("ct".to_string(), JsonValue::String(hex::encode_upper(&ct))),
                ]));
            }
        }
        "decrypt" => {
            let key_mode = group
                .get("keyMode")
                .and_then(JsonValue::as_str)
                .unwrap_or("standard");
            let n: [u8; N_BYTES] = decode_fixed(group, "n")?;
            let label = b"";

            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let ct: [u8; N_BYTES] = decode_fixed(tc, "ct")?;
                let mut out = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];

                let pt_len = if key_mode == "crt" {
                    // CRT path: (n, e, p, q, dP, dQ, qInv) with Bellcore.
                    let e_bytes = decode_hex_field(group, "e")?;
                    let e = bytes_to_u64(&e_bytes)?;
                    let p: [u8; HALF_BYTES] = decode_fixed(group, "p")?;
                    let q: [u8; HALF_BYTES] = decode_fixed(group, "q")?;
                    let dp: [u8; HALF_BYTES] = decode_fixed(group, "dmp1")?;
                    let dq: [u8; HALF_BYTES] = decode_fixed(group, "dmq1")?;
                    let qinv: [u8; HALF_BYTES] = decode_fixed(group, "iqmp")?;
                    oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_crt_internal(
                        &n, e, &p, &q, &dp, &dq, &qinv, label, &ct, &mut out,
                    )
                    .ok_or(DispatchError::Crypto("RSA OAEP: CRT decrypt failed"))?
                } else {
                    // Non-CRT path: (n, d).
                    let d: [u8; N_BYTES] = decode_fixed(group, "d")?;
                    oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_nocrt_internal(
                        &n, &d, label, &ct, &mut out,
                    )
                    .ok_or(DispatchError::Crypto("RSA OAEP: decrypt failed"))?
                };

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "pt".to_string(),
                        JsonValue::String(hex::encode_upper(&out[..pt_len])),
                    ),
                    (
                        "ptLen".to_string(),
                        JsonValue::Number(i64::try_from(pt_len).unwrap_or(0)),
                    ),
                ]));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA OAEP: only encrypt and decrypt directions are supported",
            ));
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
