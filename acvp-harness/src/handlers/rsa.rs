//! RSA ACVP handler — `sigVer` mode, revision `FIPS186-5`.
//!
//! **SigVer** (`RSA` / `sigVer` / `FIPS186-5`): Given a modulus `n`,
//! public exponent `e`, a message, and signature, verify the RSA
//! signature and return `testPassed`.
//!
//! Supported configurations:
//! - `sigType = "pkcs1v1.5"`, `modulo = 2048`, `hashAlg = "SHA2-256"`
//! - `sigType = "pkcs1v1.5"`, `modulo = 3072`, `hashAlg = "SHA2-256"`
//! - `sigType = "pkcs1v1.5"`, `modulo = 4096`, `hashAlg = "SHA2-256"`
//! - `sigType = "pss"`, `modulo = 2048`, `hashAlg = "SHA2-256"`
//! - `sigType = "pss"`, `modulo = 3072`, `hashAlg = "SHA2-256"`
//! - `sigType = "pss"`, `modulo = 4096`, `hashAlg = "SHA2-256"`
//!
//! The ACVP test type is `GDT` (Generated Data Test) — each group
//! carries a fixed (n, e) key pair and tests vary only in
//! message/signature content.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// RSA SigVer dispatcher.
pub struct RsaSigVerHandler;

impl AlgorithmHandler for RsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "RSA"
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

fn handle_sigver_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "GDT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let sig_type = group
        .get("sigType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("sigType"))?;
    let modulo = group
        .get("modulo")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("modulo"))?;
    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;

    // Validate supported configuration.
    if hash_alg != "SHA2-256" {
        return Err(DispatchError::Unsupported(
            "RSA SigVer: only SHA2-256 is supported",
        ));
    }

    if sig_type != "pkcs1v1.5" && sig_type != "pss" {
        return Err(DispatchError::Unsupported(
            "RSA SigVer: only pkcs1v1.5 and pss sigTypes are supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match modulo {
        2048 => {
            let n_hex = group
                .get("n")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("n"))?;
            let n_bytes = hex::decode(n_hex)?;
            let n: [u8; 256] = n_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DispatchError::Crypto("RSA SigVer: n is not 256 bytes"))?;

            let e_hex = group
                .get("e")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("e"))?;
            let e_bytes = hex::decode(e_hex)?;
            if e_bytes.len() > 8 {
                return Err(DispatchError::Crypto(
                    "RSA SigVer: e exceeds 8 bytes (u64 range)",
                ));
            }
            let mut e_val: u64 = 0;
            for &b in &e_bytes {
                e_val = (e_val << 8) | u64::from(b);
            }

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
                let signature = hex::decode(
                    t.get("signature")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("signature"))?,
                )?;

                let passed = if signature.len() == 256 {
                    let sig: &[u8; 256] = signature.as_slice().try_into().unwrap_or(&[0u8; 256]);
                    match sig_type {
                        "pkcs1v1.5" => rsa_pkcs1_verify_2048(&n, e_val, &message, sig),
                        "pss" => rsa_pss_verify_2048(&n, e_val, &message, sig),
                        _ => false,
                    }
                } else {
                    false
                };

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("testPassed".to_string(), JsonValue::Bool(passed)),
                ]));
            }
        }
        3072 => {
            let n_hex = group
                .get("n")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("n"))?;
            let n_bytes = hex::decode(n_hex)?;
            let n: [u8; 384] = n_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DispatchError::Crypto("RSA SigVer: n is not 384 bytes"))?;

            let e_hex = group
                .get("e")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("e"))?;
            let e_bytes = hex::decode(e_hex)?;
            if e_bytes.len() > 8 {
                return Err(DispatchError::Crypto(
                    "RSA SigVer: e exceeds 8 bytes (u64 range)",
                ));
            }
            let mut e_val: u64 = 0;
            for &b in &e_bytes {
                e_val = (e_val << 8) | u64::from(b);
            }

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
                let signature = hex::decode(
                    t.get("signature")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("signature"))?,
                )?;

                let passed = if signature.len() == 384 {
                    let sig: &[u8; 384] = signature.as_slice().try_into().unwrap_or(&[0u8; 384]);
                    match sig_type {
                        "pkcs1v1.5" => rsa_pkcs1_verify_3072(&n, e_val, &message, sig),
                        "pss" => rsa_pss_verify_3072(&n, e_val, &message, sig),
                        _ => false,
                    }
                } else {
                    false
                };

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("testPassed".to_string(), JsonValue::Bool(passed)),
                ]));
            }
        }
        4096 => {
            let n_hex = group
                .get("n")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("n"))?;
            let n_bytes = hex::decode(n_hex)?;
            let n: [u8; 512] = n_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DispatchError::Crypto("RSA SigVer: n is not 512 bytes"))?;

            let e_hex = group
                .get("e")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("e"))?;
            let e_bytes = hex::decode(e_hex)?;
            if e_bytes.len() > 8 {
                return Err(DispatchError::Crypto(
                    "RSA SigVer: e exceeds 8 bytes (u64 range)",
                ));
            }
            let mut e_val: u64 = 0;
            for &b in &e_bytes {
                e_val = (e_val << 8) | u64::from(b);
            }

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
                let signature = hex::decode(
                    t.get("signature")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("signature"))?,
                )?;

                let passed = if signature.len() == 512 {
                    let sig: &[u8; 512] = signature.as_slice().try_into().unwrap_or(&[0u8; 512]);
                    match sig_type {
                        "pkcs1v1.5" => rsa_pkcs1_verify_4096(&n, e_val, &message, sig),
                        "pss" => rsa_pss_verify_4096(&n, e_val, &message, sig),
                        _ => false,
                    }
                } else {
                    false
                };

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    ("testPassed".to_string(), JsonValue::Bool(passed)),
                ]));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigVer: only modulo 2048, 3072, and 4096 are supported",
            ))
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Crypto helpers ──────────────────────────────────────────────────

fn rsa_pkcs1_verify_2048(n: &[u8; 256], e: u64, msg: &[u8], sig: &[u8; 256]) -> bool {
    oxicrypt_rsa::rsa_pkcs1_v15_verify_2048_sha256(n, e, msg, sig).is_ok()
}

fn rsa_pss_verify_2048(n: &[u8; 256], e: u64, msg: &[u8], sig: &[u8; 256]) -> bool {
    oxicrypt_rsa::rsa_pss_verify_2048_sha256(n, e, msg, sig).is_ok()
}

fn rsa_pkcs1_verify_3072(n: &[u8; 384], e: u64, msg: &[u8], sig: &[u8; 384]) -> bool {
    oxicrypt_rsa::rsa3072::pkcs1_v15_verify(n, e, msg, sig).is_ok()
}

fn rsa_pss_verify_3072(n: &[u8; 384], e: u64, msg: &[u8], sig: &[u8; 384]) -> bool {
    oxicrypt_rsa::rsa3072::pss_verify(n, e, msg, sig).is_ok()
}

fn rsa_pkcs1_verify_4096(n: &[u8; 512], e: u64, msg: &[u8], sig: &[u8; 512]) -> bool {
    oxicrypt_rsa::rsa4096::pkcs1_v15_verify(n, e, msg, sig).is_ok()
}

fn rsa_pss_verify_4096(n: &[u8; 512], e: u64, msg: &[u8], sig: &[u8; 512]) -> bool {
    oxicrypt_rsa::rsa4096::pss_verify(n, e, msg, sig).is_ok()
}
