//! ECDSA ACVP handlers — `sigVer`, `keyVer`, `sigGen`, and `keyGen`
//! modes, revision `FIPS186-5`.
//!
//! Four modes, each dispatched as a separate handler:
//!
//! - **SigVer** (`ECDSA` / `sigVer` / `FIPS186-5`): Given a message,
//!   public key (qx, qy), and signature (r, s), verify the ECDSA
//!   signature and return `testPassed`.
//! - **KeyVer** (`ECDSA` / `keyVer` / `FIPS186-5`): Given a public key
//!   (qx, qy), validate that it is a valid point on the curve and
//!   return `testPassed`.
//! - **SigGen** (`ECDSA` / `sigGen` / `FIPS186-5`): Given a group-level
//!   private key `d` and per-test nonce `k` plus `message`, sign and
//!   return `(r, s)`. Deterministic because the ACVP vectors supply
//!   both `d` and `k`.
//! - **KeyGen** (`ECDSA` / `keyGen` / `FIPS186-5`): Given a per-test
//!   private scalar `d`, derive the public key `(qx, qy)` via
//!   `derive_public_key_internal`. Deterministic.
//!
//! Supported configurations:
//! - **P-256** with **SHA-256** — 32-byte coordinates, 32-byte hash
//! - **P-384** with **SHA-384** — 48-byte coordinates, 48-byte hash
//!
//! Unsupported curves or hash algorithms produce
//! `DispatchError::Unsupported`.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── SigVer handler ──────────────────────────────────────────────────

/// ECDSA SigVer AFT dispatcher.
pub struct EcdsaSigVerHandler;

impl AlgorithmHandler for EcdsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "ECDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── KeyVer handler ──────────────────────────────────────────────────

/// ECDSA KeyVer AFT dispatcher.
pub struct EcdsaKeyVerHandler;

impl AlgorithmHandler for EcdsaKeyVerHandler {
    fn algorithm(&self) -> &'static str {
        "ECDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keyver_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// ECDSA SigGen AFT dispatcher.
///
/// The ACVP SigGen vectors supply a group-level private key `d` and a
/// per-test nonce `k`, making the output fully deterministic.
pub struct EcdsaSigGenHandler;

impl AlgorithmHandler for EcdsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "ECDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── KeyGen handler ─────────────────────────────────────────────────

/// ECDSA KeyGen AFT dispatcher.
pub struct EcdsaKeyGenHandler;

impl AlgorithmHandler for EcdsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "ECDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigVer group driver ─────────────────────────────────────────────

fn handle_sigver_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    // Validate curve/hash — oxicrypt supports P-256 + SHA2-256 and P-384 + SHA2-384.
    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;

    // Validate curve-hash pairing.
    match (curve, hash_alg) {
        ("P-256", "SHA2-256") | ("P-384", "SHA2-384") => {}
        _ => {
            return Err(DispatchError::Unsupported(
                "ECDSA SigVer: only (P-256, SHA2-256) and (P-384, SHA2-384) are supported",
            ))
        }
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;
        let qx = hex::decode(
            t.get("qx")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qx"))?,
        )?;
        let qy = hex::decode(
            t.get("qy")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qy"))?,
        )?;
        let r_bytes = hex::decode(
            t.get("r")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("r"))?,
        )?;
        let s_bytes = hex::decode(
            t.get("s")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("s"))?,
        )?;

        let passed = match curve {
            "P-256" => ecdsa_p256_verify(&message, &qx, &qy, &r_bytes, &s_bytes),
            "P-384" => ecdsa_p384_verify(&message, &qx, &qy, &r_bytes, &s_bytes),
            _ => false,
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("testPassed".to_string(), JsonValue::Bool(passed)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── KeyVer group driver ─────────────────────────────────────────────

fn handle_keyver_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    if curve != "P-256" && curve != "P-384" {
        return Err(DispatchError::Unsupported(
            "ECDSA KeyVer: only P-256 and P-384 are supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let qx = hex::decode(
            t.get("qx")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qx"))?,
        )?;
        let qy = hex::decode(
            t.get("qy")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("qy"))?,
        )?;

        let passed = match curve {
            "P-256" => ecdsa_p256_key_validate(&qx, &qy),
            "P-384" => ecdsa_p384_key_validate(&qx, &qy),
            _ => false,
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("testPassed".to_string(), JsonValue::Bool(passed)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── SigGen group driver ─────────────────────────────────────────────

fn handle_siggen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;

    // Validate curve-hash pairing.
    match (curve, hash_alg) {
        ("P-256", "SHA2-256") | ("P-384", "SHA2-384") => {}
        _ => {
            return Err(DispatchError::Unsupported(
                "ECDSA SigGen: only (P-256, SHA2-256) and (P-384, SHA2-384) are supported",
            ))
        }
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match curve {
        "P-256" => {
            // Group-level private key (32 bytes for P-256).
            let d_bytes = hex::decode(
                group
                    .get("d")
                    .and_then(JsonValue::as_str)
                    .ok_or(DispatchError::MissingField("d"))?,
            )?;
            let d: [u8; 32] = d_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DispatchError::Crypto("ECDSA SigGen: d is not 32 bytes"))?;

            for t in tests {
                let test_case_id = t
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let message = hex::decode(
                    t.get("message")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("message"))?,
                )?;
                let k_bytes = hex::decode(
                    t.get("k")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("k"))?,
                )?;
                let k: [u8; 32] = k_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("ECDSA SigGen: k is not 32 bytes"))?;

                let sig = oxicrypt_ecdsa::p256_ecdsa::sign_with_k(&d, &message, &k)
                    .map_err(|_| DispatchError::Crypto("ECDSA SigGen: sign_with_k failed"))?;

                // Split 64-byte signature into r (first 32) and s (last 32).
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "r".to_string(),
                        JsonValue::String(hex::encode_upper(&sig[..32])),
                    ),
                    (
                        "s".to_string(),
                        JsonValue::String(hex::encode_upper(&sig[32..])),
                    ),
                ]));
            }
        }
        "P-384" => {
            // Group-level private key (48 bytes for P-384).
            let d_bytes = hex::decode(
                group
                    .get("d")
                    .and_then(JsonValue::as_str)
                    .ok_or(DispatchError::MissingField("d"))?,
            )?;
            let d: [u8; 48] = d_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DispatchError::Crypto("ECDSA SigGen: d is not 48 bytes"))?;

            for t in tests {
                let test_case_id = t
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let message = hex::decode(
                    t.get("message")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("message"))?,
                )?;
                let k_bytes = hex::decode(
                    t.get("k")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("k"))?,
                )?;
                let k: [u8; 48] = k_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("ECDSA SigGen: k is not 48 bytes"))?;

                let sig = oxicrypt_ecdsa::p384_ecdsa::sign_with_k_internal(&d, &message, &k)
                    .ok_or(DispatchError::Crypto("ECDSA SigGen: sign_with_k_internal failed"))?;

                // Split 96-byte signature into r (first 48) and s (last 48).
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "r".to_string(),
                        JsonValue::String(hex::encode_upper(&sig[..48])),
                    ),
                    (
                        "s".to_string(),
                        JsonValue::String(hex::encode_upper(&sig[48..])),
                    ),
                ]));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "ECDSA SigGen: unsupported curve",
            ))
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── KeyGen group driver ────────────────────────────────────────────

fn handle_keygen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    if curve != "P-256" && curve != "P-384" {
        return Err(DispatchError::Unsupported(
            "ECDSA KeyGen: only P-256 and P-384 are supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match curve {
        "P-256" => {
            for t in tests {
                let test_case_id = t
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let d_bytes = hex::decode(
                    t.get("d")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("d"))?,
                )?;
                let d: [u8; 32] = d_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("ECDSA KeyGen: d is not 32 bytes"))?;

                let pk = oxicrypt_ecdsa::p256_ecdsa::derive_public_key_internal(&d)
                    .ok_or(DispatchError::Crypto(
                        "ECDSA KeyGen: derive_public_key_internal failed",
                    ))?;

                // pk is 65 bytes: 0x04 || X(32) || Y(32)
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "qx".to_string(),
                        JsonValue::String(hex::encode_upper(&pk[1..33])),
                    ),
                    (
                        "qy".to_string(),
                        JsonValue::String(hex::encode_upper(&pk[33..65])),
                    ),
                ]));
            }
        }
        "P-384" => {
            for t in tests {
                let test_case_id = t
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                let d_bytes = hex::decode(
                    t.get("d")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("d"))?,
                )?;
                let d: [u8; 48] = d_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("ECDSA KeyGen: d is not 48 bytes"))?;

                let pk = oxicrypt_ecdsa::p384_ecdsa::derive_public_key_internal(&d)
                    .ok_or(DispatchError::Crypto(
                        "ECDSA KeyGen: derive_public_key_internal failed",
                    ))?;

                // pk is 97 bytes: 0x04 || X(48) || Y(48)
                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "qx".to_string(),
                        JsonValue::String(hex::encode_upper(&pk[1..49])),
                    ),
                    (
                        "qy".to_string(),
                        JsonValue::String(hex::encode_upper(&pk[49..97])),
                    ),
                ]));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "ECDSA KeyGen: unsupported curve",
            ))
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Crypto helpers ──────────────────────────────────────────────────

/// Build the 65-byte uncompressed SEC1 public key (0x04 || qx || qy)
/// and the 64-byte signature (r || s), then call
/// `oxicrypt_ecdsa::p256_ecdsa::verify`.
fn ecdsa_p256_verify(msg: &[u8], qx: &[u8], qy: &[u8], r: &[u8], s: &[u8]) -> bool {
    // qx and qy must each be exactly 32 bytes for P-256.
    if qx.len() != 32 || qy.len() != 32 || r.len() != 32 || s.len() != 32 {
        return false;
    }
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(qx);
    pk[33..65].copy_from_slice(qy);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(s);

    oxicrypt_ecdsa::p256_ecdsa::verify(&pk, msg, &sig).unwrap_or_default()
}

/// Build the 65-byte uncompressed SEC1 public key and validate it via
/// the full SP 800-56Ar3 §5.6.2.3.3 public-key validation.
fn ecdsa_p256_key_validate(qx: &[u8], qy: &[u8]) -> bool {
    // If qx/qy are not exactly 32 bytes each, the key is invalid.
    // ACVP KeyVer vectors may provide oversize coordinates to test
    // rejection of out-of-range values.
    if qx.len() > 32 || qy.len() > 32 {
        return false;
    }
    // Left-pad to 32 bytes (coordinates < 32 bytes are valid but
    // unusual; ACVP doesn't seem to test this, but be correct).
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    // Right-align qx into pk[1..33]
    let qx_offset = 33 - qx.len();
    pk[qx_offset..33].copy_from_slice(qx);
    // Right-align qy into pk[33..65]
    let qy_offset = 65 - qy.len();
    pk[qy_offset..65].copy_from_slice(qy);

    oxicrypt_ecdsa::p256_point::Point::from_sec1_uncompressed_validated(&pk).is_some()
}

/// Build the 97-byte uncompressed SEC1 public key (0x04 || qx || qy) and the
/// 96-byte signature (r || s), then call `oxicrypt_ecdsa::p384_ecdsa::verify_internal`.
fn ecdsa_p384_verify(msg: &[u8], qx: &[u8], qy: &[u8], r: &[u8], s: &[u8]) -> bool {
    // qx, qy, r, s must each be exactly 48 bytes for P-384.
    if qx.len() != 48 || qy.len() != 48 || r.len() != 48 || s.len() != 48 {
        return false;
    }
    let mut pk = [0u8; 97];
    pk[0] = 0x04;
    pk[1..49].copy_from_slice(qx);
    pk[49..97].copy_from_slice(qy);

    let mut sig = [0u8; 96];
    sig[..48].copy_from_slice(r);
    sig[48..].copy_from_slice(s);

    oxicrypt_ecdsa::p384_ecdsa::verify_internal(&pk, msg, &sig)
}

/// Build the 97-byte uncompressed SEC1 public key and validate it via
/// the full SP 800-56Ar3 §5.6.2.3.3 public-key validation.
fn ecdsa_p384_key_validate(qx: &[u8], qy: &[u8]) -> bool {
    // If qx/qy are not exactly 48 bytes each, the key is invalid.
    // ACVP KeyVer vectors may provide oversize coordinates to test
    // rejection of out-of-range values.
    if qx.len() > 48 || qy.len() > 48 {
        return false;
    }
    // Left-pad to 48 bytes (coordinates < 48 bytes are valid but
    // unusual; ACVP doesn't seem to test this, but be correct).
    let mut pk = [0u8; 97];
    pk[0] = 0x04;
    // Right-align qx into pk[1..49]
    let qx_offset = 49 - qx.len();
    pk[qx_offset..49].copy_from_slice(qx);
    // Right-align qy into pk[49..97]
    let qy_offset = 97 - qy.len();
    pk[qy_offset..97].copy_from_slice(qy);

    oxicrypt_ecdsa::p384_point::Point384::from_sec1_uncompressed_validated(&pk).is_some()
}
