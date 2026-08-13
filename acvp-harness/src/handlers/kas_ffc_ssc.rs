//! KAS-FFC-SSC ACVP handler — revision `Sp800-56Ar3` (no mode).
//!
//! **KAS-FFC-SSC** (`KAS-FFC-SSC` / `Sp800-56Ar3`): Given a private
//! exponent `x` and the peer's public key `y`, compute the
//! Diffie-Hellman shared secret `Z = y^x mod p` per SP 800-56Ar3
//! §5.7.1.1 over RFC 3526 Group 15 (the MODP-3072 safe-prime group).
//!
//! The ACVTS demo catalog registers this algorithm with no mode
//! segment, under the lookup key `KAS-FFC-SSC-Sp800-56Ar3`. The
//! registration capability and the dispatcher's lookup tuple both
//! carry no mode; see `caps::kas_ffc_ssc_capability` for the
//! rationale.
//!
//! Supported configurations:
//! - `domainParameterGenerationMode = "MODP-3072"` — RFC 3526 Group
//!   15 safe-prime, 384-byte exponent and shared-secret values.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// KAS-FFC-SSC dispatcher.
pub struct KasFfcSscHandler;

impl AlgorithmHandler for KasFfcSscHandler {
    fn algorithm(&self) -> &'static str {
        "KAS-FFC-SSC"
    }
    fn mode(&self) -> Option<&'static str> {
        None
    }
    fn revision(&self) -> &'static str {
        "Sp800-56Ar3"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kas_ffc_ssc_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kas_ffc_ssc_group(group)
    }
}

/// AFT vs VAL.
///
/// - **AFT** (algorithm functional test): for the live demo's
///   `dhEphem` scheme the prompt only carries the server's
///   ephemeral public key; the IUT samples its own ephemeral
///   keypair via DRBG (SP 800-56Ar3 §5.6.1.1.4 rejection sampling
///   in `oxicrypt_dh::generate_keypair_3072_internal`), reports the
///   IUT public key and the computed `z`. Vendored offline kat-
///   slice fixtures use a deterministic shape — `x` (IUT private)
///   and `y` (peer public) per test, response just `z` — detected
///   by `x` presence.
/// - **VAL** (validation): IUT computes `z` from supplied
///   `ephemeralPrivateIut` + server's `ephemeralPublicServer`,
///   compares against the candidate `z` shipped with the test, and
///   reports `testPassed`.
#[derive(Debug, Clone, Copy)]
enum TestKind {
    Aft,
    Val,
}

fn handle_kas_ffc_ssc_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    let domain = group
        .get("domainParameterGenerationMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("domainParameterGenerationMode"))?;
    if domain != "MODP-3072" {
        return Err(DispatchError::Unsupported(
            "KAS-FFC-SSC: only MODP-3072 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for tc in tests {
        let resp = match kind {
            TestKind::Aft => handle_aft(tc)?,
            TestKind::Val => handle_val(tc)?,
        };
        results.push(resp);
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── AFT ─────────────────────────────────────────────────────────────

fn handle_aft(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tc_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;

    // Offline kat-slice fixtures carry `x` per test (deterministic
    // round-trip); live ACVTS prompts carry only
    // `ephemeralPublicServer` and expect the IUT to sample its own.
    if tc.get("x").is_some() {
        let x = decode_field_3072(tc, "x")?;
        let y = decode_field_3072(tc, "y")?;
        let z = oxicrypt_dh::compute_shared_secret_3072_internal(&x, &y)
            .ok_or(DispatchError::Crypto("KAS-FFC-SSC: DH computation failed"))?;
        Ok(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            ("z".to_string(), JsonValue::String(hex::encode_upper(&z))),
        ]))
    } else {
        let peer_y = decode_field_3072(tc, "ephemeralPublicServer")?;
        let mut drbg = super::os_entropy::build_seeded_drbg()?;
        let (x_iut, y_iut) = oxicrypt_dh::generate_keypair_3072_internal(&mut drbg).ok_or(
            DispatchError::Crypto("KAS-FFC-SSC: ephemeral keygen failed"),
        )?;
        let z = oxicrypt_dh::compute_shared_secret_3072_internal(&x_iut, &peer_y)
            .ok_or(DispatchError::Crypto("KAS-FFC-SSC: DH computation failed"))?;
        Ok(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            (
                "ephemeralPublicIut".to_string(),
                JsonValue::String(hex::encode_upper(&y_iut)),
            ),
            ("z".to_string(), JsonValue::String(hex::encode_upper(&z))),
        ]))
    }
}

// ── VAL ─────────────────────────────────────────────────────────────

fn handle_val(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tc_id = tc
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let x_iut = decode_field_3072(tc, "ephemeralPrivateIut")?;
    let peer_y = decode_field_3072(tc, "ephemeralPublicServer")?;
    let computed = oxicrypt_dh::compute_shared_secret_3072_internal(&x_iut, &peer_y).ok_or(
        DispatchError::Crypto("KAS-FFC-SSC: VAL DH computation failed"),
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

/// Decode a hex-string field at MODP-3072 width (384 bytes). The
/// `ephemeralPrivateIut` field may be shorter than 384 bytes when
/// the server uses a subgroup-sized exponent; left-pad with zeros
/// so the primitive sees a 384-byte big-endian value.
fn decode_field_3072(tc: &JsonValue, field: &'static str) -> Result<[u8; 384], DispatchError> {
    let raw = hex::decode(
        tc.get(field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(field))?,
    )?;
    if raw.len() > 384 {
        return Err(DispatchError::Crypto(
            "KAS-FFC-SSC: MODP-3072 field exceeds 384 bytes",
        ));
    }
    let mut out = [0u8; 384];
    let pad = 384 - raw.len();
    out[pad..].copy_from_slice(&raw);
    Ok(out)
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
