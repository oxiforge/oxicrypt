//! RSA key generation ACVP handler — `keyGen` mode, revision
//! `FIPS186-5`.
//!
//! **RSA keyGen** (`RSA` / `keyGen` / `FIPS186-5`, `testType = "AFT"`):
//! Given per-test DRBG seed material (`entropy`, `nonce`, `perso`),
//! instantiate an HMAC_DRBG-SHA256 and generate an RSA key pair
//! with `e = 65537` per FIPS 186-5 §A.1.1 / §B.3.1. Return
//! `(n, d, p, q, dP, dQ, qInv)`.
//!
//! Supported configurations:
//! - `modulo = 2048`, `fixedPubExp = "010001"` (65537)
//! - `modulo = 3072`, `fixedPubExp = "010001"` (65537)
//! - `modulo = 4096`, `fixedPubExp = "010001"` (65537)

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// RSA KeyGen dispatcher.
pub struct RsaKeyGenHandler;

impl AlgorithmHandler for RsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "RSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::rsa_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── Group handler ──────────────────────────────────────────────────

#[allow(clippy::too_many_lines, clippy::similar_names)]
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

    let modulo = group
        .get("modulo")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("modulo"))?;

    // Parse fixed public exponent from group level.
    let e_hex = group
        .get("fixedPubExp")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("fixedPubExp"))?;
    let e_bytes = hex::decode(e_hex)?;
    let e = bytes_to_u64(&e_bytes)?;
    if e != 65537 {
        return Err(DispatchError::Unsupported(
            "RSA keyGen: only e=65537 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for tc in tests {
        let test_case_id = tc
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        // Each test supplies DRBG seed material.
        let entropy = hex::decode(
            tc.get("entropy")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("entropy"))?,
        )?;
        let nonce = hex::decode(
            tc.get("nonce")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("nonce"))?,
        )?;
        let perso = hex::decode(
            tc.get("perso")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("perso"))?,
        )?;

        // Instantiate DRBG from seed material.
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(&entropy, &nonce, &perso)
            .map_err(|_| DispatchError::Crypto("RSA keyGen: DRBG instantiate failed"))?;

        match modulo {
            2048 => {
                let km = oxicrypt_rsa::keygen::generate_2048(&mut drbg, e)
                    .map_err(|_| DispatchError::Crypto("RSA keyGen: 2048 key generation failed"))?;

                let n_bytes: [u8; 256] = km.n.to_be_bytes();
                let d_bytes: [u8; 256] = km.d.to_be_bytes();
                let p_bytes: [u8; 128] = km.p.to_be_bytes();
                let q_bytes: [u8; 128] = km.q.to_be_bytes();
                let dp_bytes: [u8; 128] = km.dp.to_be_bytes();
                let dq_bytes: [u8; 128] = km.dq.to_be_bytes();
                let qinv_bytes: [u8; 128] = km.qinv.to_be_bytes();

                results.push(keygen_result(
                    test_case_id, &e_bytes,
                    &n_bytes, &d_bytes,
                    &p_bytes, &q_bytes,
                    &dp_bytes, &dq_bytes, &qinv_bytes,
                ));
            }
            3072 => {
                let km = oxicrypt_rsa::keygen3072::generate_3072(&mut drbg, e)
                    .map_err(|_| DispatchError::Crypto("RSA keyGen: 3072 key generation failed"))?;

                let n_bytes: [u8; 384] = km.n.to_be_bytes();
                let d_bytes: [u8; 384] = km.d.to_be_bytes();
                let p_bytes: [u8; 192] = km.p.to_be_bytes();
                let q_bytes: [u8; 192] = km.q.to_be_bytes();
                let dp_bytes: [u8; 192] = km.dp.to_be_bytes();
                let dq_bytes: [u8; 192] = km.dq.to_be_bytes();
                let qinv_bytes: [u8; 192] = km.qinv.to_be_bytes();

                results.push(keygen_result(
                    test_case_id, &e_bytes,
                    &n_bytes, &d_bytes,
                    &p_bytes, &q_bytes,
                    &dp_bytes, &dq_bytes, &qinv_bytes,
                ));
            }
            4096 => {
                let km = oxicrypt_rsa::keygen4096::generate_4096(&mut drbg, e)
                    .map_err(|_| DispatchError::Crypto("RSA keyGen: 4096 key generation failed"))?;

                let n_bytes: [u8; 512] = km.n.to_be_bytes();
                let d_bytes: [u8; 512] = km.d.to_be_bytes();
                let p_bytes: [u8; 256] = km.p.to_be_bytes();
                let q_bytes: [u8; 256] = km.q.to_be_bytes();
                let dp_bytes: [u8; 256] = km.dp.to_be_bytes();
                let dq_bytes: [u8; 256] = km.dq.to_be_bytes();
                let qinv_bytes: [u8; 256] = km.qinv.to_be_bytes();

                results.push(keygen_result(
                    test_case_id, &e_bytes,
                    &n_bytes, &d_bytes,
                    &p_bytes, &q_bytes,
                    &dp_bytes, &dq_bytes, &qinv_bytes,
                ));
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "RSA keyGen: only modulo 2048/3072/4096 are supported",
                ));
            }
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Helpers ────────────────────────────────────────────────────────

/// Convert big-endian bytes to `u64`.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, DispatchError> {
    if bytes.len() > 8 {
        return Err(DispatchError::Crypto(
            "RSA keyGen: e exceeds 8 bytes (u64 range)",
        ));
    }
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    Ok(val)
}

/// Build a keygen result JSON object (modulus-size-agnostic via slices).
#[allow(clippy::too_many_arguments)]
fn keygen_result(
    tc_id: i64,
    e_bytes: &[u8],
    n: &[u8],
    d: &[u8],
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    qinv: &[u8],
) -> JsonValue {
    JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("n".to_string(), JsonValue::String(hex::encode_upper(n))),
        ("d".to_string(), JsonValue::String(hex::encode_upper(d))),
        ("e".to_string(), JsonValue::String(hex::encode_upper(e_bytes))),
        ("p".to_string(), JsonValue::String(hex::encode_upper(p))),
        ("q".to_string(), JsonValue::String(hex::encode_upper(q))),
        ("dmp1".to_string(), JsonValue::String(hex::encode_upper(dp))),
        ("dmq1".to_string(), JsonValue::String(hex::encode_upper(dq))),
        ("iqmp".to_string(), JsonValue::String(hex::encode_upper(qinv))),
    ])
}
