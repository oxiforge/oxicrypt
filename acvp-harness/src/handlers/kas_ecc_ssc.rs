//! KAS-ECC-SSC ACVP handler — `Component` mode, revision `Sp800-56Ar3`.
//!
//! **KAS-ECC-SSC** (`KAS-ECC-SSC` / `Component` / `Sp800-56Ar3`):
//! Given a private key `d` and the peer's public key `(X, Y)`, compute
//! the ECDH shared secret `Z = x(d * Q)` per SP 800-56Ar3 §5.7.1.2.
//!
//! Supported configurations:
//! - `domainParameterGenerationMode = "P-256"` — 32-byte coordinates
//! - `domainParameterGenerationMode = "P-384"` — 48-byte coordinates

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// KAS-ECC-SSC dispatcher.
pub struct KasEccSscHandler;

impl AlgorithmHandler for KasEccSscHandler {
    fn algorithm(&self) -> &'static str {
        "KAS-ECC-SSC"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("Component")
    }
    fn revision(&self) -> &'static str {
        "Sp800-56Ar3"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kas_ecc_ssc_group(group)
    }
}

#[allow(clippy::too_many_lines)]
fn handle_kas_ecc_ssc_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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
        .get("domainParameterGenerationMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(
            "domainParameterGenerationMode",
        ))?;
    if curve != "P-256" && curve != "P-384" {
        return Err(DispatchError::Unsupported(
            "KAS-ECC-SSC: only P-256 and P-384 are supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match curve {
        "P-256" => {
            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                // Private key d (32 bytes for P-256).
                let d_raw = hex::decode(
                    tc.get("d")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("d"))?,
                )?;
                let d: [u8; 32] = d_raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("KAS-ECC-SSC: d is not 32 bytes"))?;

                // Peer public key X/Y (each 32 bytes for P-256).
                let pub_x = hex::decode(
                    tc.get("peerPublicKeyX")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("peerPublicKeyX"))?,
                )?;
                let pub_y = hex::decode(
                    tc.get("peerPublicKeyY")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("peerPublicKeyY"))?,
                )?;

                if pub_x.len() != 32 || pub_y.len() != 32 {
                    return Err(DispatchError::Crypto(
                        "KAS-ECC-SSC: peer public key X/Y not 32 bytes",
                    ));
                }

                // Build uncompressed SEC1 public key: 0x04 || X || Y
                let mut peer_pk = [0u8; 65];
                peer_pk[0] = 0x04;
                peer_pk[1..33].copy_from_slice(&pub_x);
                peer_pk[33..65].copy_from_slice(&pub_y);

                let z = oxicrypt_ecdh::compute_shared_secret_p256_internal(&d, &peer_pk)
                    .ok_or(DispatchError::Crypto("KAS-ECC-SSC: ECDH computation failed"))?;

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "z".to_string(),
                        JsonValue::String(hex::encode_upper(&z)),
                    ),
                ]));
            }
        }
        "P-384" => {
            for tc in tests {
                let test_case_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;

                // Private key d (48 bytes for P-384).
                let d_raw = hex::decode(
                    tc.get("d")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("d"))?,
                )?;
                let d: [u8; 48] = d_raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("KAS-ECC-SSC: d is not 48 bytes"))?;

                // Peer public key X/Y (each 48 bytes for P-384).
                let pub_x = hex::decode(
                    tc.get("peerPublicKeyX")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("peerPublicKeyX"))?,
                )?;
                let pub_y = hex::decode(
                    tc.get("peerPublicKeyY")
                        .and_then(JsonValue::as_str)
                        .ok_or(DispatchError::MissingField("peerPublicKeyY"))?,
                )?;

                if pub_x.len() != 48 || pub_y.len() != 48 {
                    return Err(DispatchError::Crypto(
                        "KAS-ECC-SSC: peer public key X/Y not 48 bytes",
                    ));
                }

                // Build uncompressed SEC1 public key: 0x04 || X || Y
                let mut peer_pk = [0u8; 97];
                peer_pk[0] = 0x04;
                peer_pk[1..49].copy_from_slice(&pub_x);
                peer_pk[49..97].copy_from_slice(&pub_y);

                let z = oxicrypt_ecdh::compute_shared_secret_p384_internal(&d, &peer_pk)
                    .ok_or(DispatchError::Crypto("KAS-ECC-SSC: ECDH computation failed"))?;

                results.push(JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(test_case_id)),
                    (
                        "z".to_string(),
                        JsonValue::String(hex::encode_upper(&z)),
                    ),
                ]));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "KAS-ECC-SSC: unsupported curve",
            ))
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
