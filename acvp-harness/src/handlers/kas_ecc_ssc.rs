//! KAS-ECC-SSC ACVP handler — revision `Sp800-56Ar3` (no mode).
//!
//! **KAS-ECC-SSC** (`KAS-ECC-SSC` / `Sp800-56Ar3`): Given a private
//! key `d` and the peer's public key `(X, Y)`, compute the ECDH
//! shared secret `Z = x(d * Q)` per SP 800-56Ar3 §5.7.1.2.
//!
//! The ACVTS demo catalog registers this algorithm with no mode
//! segment, under the lookup key `KAS-ECC-SSC-Sp800-56Ar3`. The
//! registration capability and the dispatcher's lookup tuple both
//! carry no mode; see `caps::kas_ecc_ssc_capability` for the
//! rationale.
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
        None
    }
    fn revision(&self) -> &'static str {
        "Sp800-56Ar3"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kas_ecc_ssc_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kas_ecc_ssc_group(group)
    }
}

/// AFT vs VAL.
///
/// - **AFT** (algorithm functional test): for the live demo's
///   ephemeralUnified scheme the prompt only carries the server's
///   ephemeral public key; the IUT samples its own ephemeral keypair
///   via DRBG (FIPS 186-5 §A.2.2 + IG 10.3.A PCT, reusing
///   `oxicrypt_ecdsa::EcdsaP*PrivateKey::generate` since ECDH and
///   ECDSA share scalar/point shape on each curve), reports the IUT
///   public coordinates and the computed `z`. Vendored offline kat-
///   slice fixtures use a deterministic shape — `d` and
///   `peerPublicKeyX`/`peerPublicKeyY` per test, response just `z` —
///   detected by `peerPublicKeyX` presence.
/// - **VAL** (validation): IUT computes `z` from supplied
///   `ephemeralPrivateIut` + server's ephemeral public key, compares
///   against the candidate `z` shipped with the test, and reports
///   `testPassed`.
#[derive(Debug, Clone, Copy)]
enum TestKind {
    Aft,
    Val,
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
    let kind = match test_type {
        "AFT" => TestKind::Aft,
        "VAL" => TestKind::Val,
        other => return Err(DispatchError::UnsupportedTestType(other.to_string())),
    };

    let curve = group
        .get("domainParameterGenerationMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("domainParameterGenerationMode"))?;
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

    for tc in tests {
        let resp = match (kind, curve) {
            (TestKind::Aft, "P-256") => handle_aft_p256(tc)?,
            (TestKind::Aft, "P-384") => handle_aft_p384(tc)?,
            (TestKind::Val, "P-256") => handle_val_p256(tc)?,
            (TestKind::Val, "P-384") => handle_val_p384(tc)?,
            _ => unreachable!("curve guarded above"),
        };
        results.push(resp);
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── AFT (P-256) ─────────────────────────────────────────────────────

fn handle_aft_p256(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tc_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;

    // Vendored offline kat-slice carries `peerPublicKeyX`/`peerPublicKeyY`
    // and `d` per test for deterministic round-trip; live ACVTS prompts
    // carry `ephemeralPublicServerX`/`Y` and expect the IUT to sample
    // its own ephemeral keypair via DRBG.
    if tc.get("peerPublicKeyX").is_some() {
        let d = decode_scalar_p256(tc, "d")?;
        let peer_pk = decode_uncompressed_p256(tc, "peerPublicKeyX", "peerPublicKeyY")?;
        let z = oxicrypt_ecdh::compute_shared_secret_p256_internal(&d, &peer_pk).ok_or(
            DispatchError::Crypto("KAS-ECC-SSC P-256: ECDH computation failed"),
        )?;
        Ok(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            ("z".to_string(), JsonValue::String(hex::encode_upper(&z))),
        ]))
    } else {
        let peer_pk =
            decode_uncompressed_p256(tc, "ephemeralPublicServerX", "ephemeralPublicServerY")?;
        let mut drbg = super::os_entropy::build_seeded_drbg()?;
        let sk = oxicrypt_ecdsa::p256_ecdsa::EcdsaP256PrivateKey::generate(&mut drbg)
            .map_err(|_| DispatchError::Crypto("KAS-ECC-SSC P-256: ephemeral keygen failed"))?;
        let d = *sk.private_scalar();
        let pk = sk.public_key();
        let z = oxicrypt_ecdh::compute_shared_secret_p256_internal(&d, &peer_pk).ok_or(
            DispatchError::Crypto("KAS-ECC-SSC P-256: ECDH computation failed"),
        )?;
        Ok(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "ephemeralPublicIutX".to_string(),
                JsonValue::String(hex::encode_upper(&pk[1..33])),
            ),
            (
                "ephemeralPublicIutY".to_string(),
                JsonValue::String(hex::encode_upper(&pk[33..65])),
            ),
            ("z".to_string(), JsonValue::String(hex::encode_upper(&z))),
        ]))
    }
}

// ── AFT (P-384) ─────────────────────────────────────────────────────

fn handle_aft_p384(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tc_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;

    if tc.get("peerPublicKeyX").is_some() {
        let d = decode_scalar_p384(tc, "d")?;
        let peer_pk = decode_uncompressed_p384(tc, "peerPublicKeyX", "peerPublicKeyY")?;
        let z = oxicrypt_ecdh::compute_shared_secret_p384_internal(&d, &peer_pk).ok_or(
            DispatchError::Crypto("KAS-ECC-SSC P-384: ECDH computation failed"),
        )?;
        Ok(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            ("z".to_string(), JsonValue::String(hex::encode_upper(&z))),
        ]))
    } else {
        let peer_pk =
            decode_uncompressed_p384(tc, "ephemeralPublicServerX", "ephemeralPublicServerY")?;
        let mut drbg = super::os_entropy::build_seeded_drbg()?;
        let sk = oxicrypt_ecdsa::p384_ecdsa::EcdsaP384PrivateKey::generate(&mut drbg)
            .map_err(|_| DispatchError::Crypto("KAS-ECC-SSC P-384: ephemeral keygen failed"))?;
        let d = *sk.private_scalar();
        let pk = sk.public_key();
        let z = oxicrypt_ecdh::compute_shared_secret_p384_internal(&d, &peer_pk).ok_or(
            DispatchError::Crypto("KAS-ECC-SSC P-384: ECDH computation failed"),
        )?;
        Ok(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "ephemeralPublicIutX".to_string(),
                JsonValue::String(hex::encode_upper(&pk[1..49])),
            ),
            (
                "ephemeralPublicIutY".to_string(),
                JsonValue::String(hex::encode_upper(&pk[49..97])),
            ),
            ("z".to_string(), JsonValue::String(hex::encode_upper(&z))),
        ]))
    }
}

// ── VAL (P-256) ─────────────────────────────────────────────────────

fn handle_val_p256(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tc_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let d = decode_scalar_p256(tc, "ephemeralPrivateIut")?;
    let peer_pk = decode_uncompressed_p256(tc, "ephemeralPublicServerX", "ephemeralPublicServerY")?;
    let computed = oxicrypt_ecdh::compute_shared_secret_p256_internal(&d, &peer_pk).ok_or(
        DispatchError::Crypto("KAS-ECC-SSC P-256: VAL ECDH computation failed"),
    )?;
    let candidate = hex::decode(
        tc.get("z")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("z"))?,
    )?;
    let passed = ct_eq_bytes(&computed, &candidate);
    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("testPassed".to_string(), JsonValue::Bool(passed)),
    ]))
}

// ── VAL (P-384) ─────────────────────────────────────────────────────

fn handle_val_p384(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tc_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let d = decode_scalar_p384(tc, "ephemeralPrivateIut")?;
    let peer_pk = decode_uncompressed_p384(tc, "ephemeralPublicServerX", "ephemeralPublicServerY")?;
    let computed = oxicrypt_ecdh::compute_shared_secret_p384_internal(&d, &peer_pk).ok_or(
        DispatchError::Crypto("KAS-ECC-SSC P-384: VAL ECDH computation failed"),
    )?;
    let candidate = hex::decode(
        tc.get("z")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("z"))?,
    )?;
    let passed = ct_eq_bytes(&computed, &candidate);
    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("testPassed".to_string(), JsonValue::Bool(passed)),
    ]))
}

// ── decode helpers ──────────────────────────────────────────────────

fn decode_scalar_p256(tc: &JsonValue, field: &'static str) -> Result<[u8; 32], DispatchError> {
    let raw = hex::decode(
        tc.get(field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(field))?,
    )?;
    raw.as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("KAS-ECC-SSC P-256: scalar is not 32 bytes"))
}

fn decode_scalar_p384(tc: &JsonValue, field: &'static str) -> Result<[u8; 48], DispatchError> {
    let raw = hex::decode(
        tc.get(field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(field))?,
    )?;
    raw.as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("KAS-ECC-SSC P-384: scalar is not 48 bytes"))
}

fn decode_uncompressed_p256(
    tc: &JsonValue,
    x_field: &'static str,
    y_field: &'static str,
) -> Result<[u8; 65], DispatchError> {
    let pub_x = hex::decode(
        tc.get(x_field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(x_field))?,
    )?;
    let pub_y = hex::decode(
        tc.get(y_field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(y_field))?,
    )?;
    if pub_x.len() != 32 || pub_y.len() != 32 {
        return Err(DispatchError::Crypto(
            "KAS-ECC-SSC P-256: public key X/Y not 32 bytes",
        ));
    }
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&pub_x);
    pk[33..65].copy_from_slice(&pub_y);
    Ok(pk)
}

fn decode_uncompressed_p384(
    tc: &JsonValue,
    x_field: &'static str,
    y_field: &'static str,
) -> Result<[u8; 97], DispatchError> {
    let pub_x = hex::decode(
        tc.get(x_field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(x_field))?,
    )?;
    let pub_y = hex::decode(
        tc.get(y_field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(y_field))?,
    )?;
    if pub_x.len() != 48 || pub_y.len() != 48 {
        return Err(DispatchError::Crypto(
            "KAS-ECC-SSC P-384: public key X/Y not 48 bytes",
        ));
    }
    let mut pk = [0u8; 97];
    pk[0] = 0x04;
    pk[1..49].copy_from_slice(&pub_x);
    pk[49..97].copy_from_slice(&pub_y);
    Ok(pk)
}

/// Equal-length constant-time byte-slice equality. A length mismatch
/// is reported as `false` without entering the byte loop.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
