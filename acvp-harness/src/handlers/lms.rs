//! LMS ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes.
//!
//! **LMS** (`LMS` / `keyGen`, `sigGen`, `sigVer` / revision `1.0`):
//! Stateful hash-based signature scheme per SP 800-208 (RFC 8554).
//!
//! Parameter set: `LMS_SHA256_M32_H10` / `LMOTS_SHA256_N32_W4`.
//!
//! Cap and dispatch shapes follow `draft-celi-acvp-lms` (single-pair
//! `specificCapabilities` form — see `caps::lms_specific_capabilities`).
//!
//! Three modes for the complete signature lifecycle:
//! - **KeyGen**: Generate a key pair from a server-supplied 32-byte
//!   `seed` plus a 16-byte public-key identifier `i`, both per-test
//!   per spec §8.1.2 Table 8. Returns `pk` per spec §9.1 Table 13.
//! - **SigGen**: Sign messages with an IUT-generated key. **Inverted
//!   protocol model vs ML-DSA / SLH-DSA**: per spec §8.2.1 Table 9
//!   the server prompt has no key information, and §9.2 Table 16
//!   requires the IUT to supply its own `publicKey` at group level
//!   in the response. This is structural for stateful HBS — the
//!   server can't dictate a key for a one-time-leaf scheme. The
//!   handler derives a deterministic per-group seed from `tgId` so
//!   prompt replays produce identical responses.
//! - **SigVer**: Verify a signature against a server-supplied
//!   `publicKey` (group-level per spec §8.3.1 Table 11) and per-test
//!   `message` + `signature` per spec §8.3.2 Table 12.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// LMS KeyGen dispatcher.
pub struct LmsKeyGenHandler;

impl AlgorithmHandler for LmsKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// LMS SigGen dispatcher.
pub struct LmsSigGenHandler;

impl AlgorithmHandler for LmsSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_siggen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── SigVer handler ──────────────────────────────────────────────────

/// LMS SigVer dispatcher.
pub struct LmsSigVerHandler;

impl AlgorithmHandler for LmsSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_sigver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── KeyGen group driver ─────────────────────────────────────────────

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

        // Per lms §8.1.2 Table 8 (and RFC 8554 §5.3), the LMS keyGen
        // test case carries both the OTS `seed` (32 B for SHA256
        // variants) AND the public-key identifier `i` (16 B). The
        // identifier is embedded in the resulting public key at bytes
        // 8..24 and participates in the Merkle root computation, so
        // the handler must call oxicrypt_lms::keygen_from_parts —
        // which consumes both — rather than keygen_internal, which
        // derives an identifier from the seed.
        let seed_bytes = hex::decode(
            t.get("seed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("seed"))?,
        )?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("LMS KeyGen: seed is not 32 bytes"))?;

        let i_bytes = hex::decode(
            t.get("i")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("i"))?,
        )?;
        let identifier: [u8; 16] = i_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("LMS KeyGen: i is not 16 bytes"))?;

        let (_sk, pk) = oxicrypt_lms::keygen_from_parts(&seed, &identifier);

        // Response field name is `publicKey` per spec §9.1 Table 15 —
        // NOT `pk` (ML-DSA / SLH-DSA precedent). LMS uses `publicKey`
        // consistently across all three modes' input/output.
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "publicKey".to_string(),
                JsonValue::String(hex::encode_upper(&pk)),
            ),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── SigGen group driver ─────────────────────────────────────────────

/// Derive a deterministic 32-byte seed from a test group's `tgId`.
///
/// The 28-byte ASCII prefix `b"oxicrypt-lms-acvp-handler-tg"` is a
/// self-describing marker that names the producer; the trailing 4
/// bytes carry `tgId` in big-endian. Each group gets a distinct
/// key (avoiding leaf-state collision across groups in the same
/// prompt), and identical prompts produce identical responses —
/// the harness never depends on entropy for sigGen, so a replay of
/// the same prompt JSON yields the same publicKey + signatures.
///
/// `tgId` is a positive integer in ACVP and fits comfortably in
/// `u32` (vector sets carry tens-to-hundreds of groups, far below
/// `u32::MAX`). Out-of-range inputs are a protocol violation; the
/// `Result` return surfaces them as a structured dispatch error
/// rather than silently colliding distinct invalid tgIds onto a
/// shared seed value.
fn lms_siggen_seed_from_tg_id(tg_id: i64) -> Result<[u8; 32], DispatchError> {
    const PREFIX: &[u8; 28] = b"oxicrypt-lms-acvp-handler-tg";
    let tg_u32 = u32::try_from(tg_id).map_err(|_| {
        DispatchError::Crypto("LMS SigGen: tgId is out of range for u32 seed derivation")
    })?;
    let mut seed = [0u8; 32];
    seed[..28].copy_from_slice(PREFIX);
    seed[28..32].copy_from_slice(&tg_u32.to_be_bytes());
    Ok(seed)
}

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

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // Per `draft-celi-acvp-lms §8.2.1` Table 9, the sigGen prompt
    // carries no key information at the group or test-case level —
    // only `lmsMode`, `lmOtsMode`, and per-test `message`. The IUT
    // must generate its own key and supply it back in the response
    // at group level (§9.2 Table 16). The seed is derived from
    // `tgId` for replay-stable determinism.
    let seed = lms_siggen_seed_from_tg_id(tg_id)?;
    let (mut sk, pk) = oxicrypt_lms::keygen_internal(&seed);

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

        let sig = oxicrypt_lms::sign_internal(&mut sk, &message).ok_or(DispatchError::Crypto(
            "LMS SigGen: signing failed (key exhausted?)",
        ))?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "signature".to_string(),
                JsonValue::String(hex::encode_upper(&sig)),
            ),
        ]));
    }

    // Group-level `publicKey` per spec §9.2 Table 16 — the IUT-
    // generated public key whose tree the server uses to verify
    // the per-test signatures.
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        (
            "publicKey".to_string(),
            JsonValue::String(hex::encode_upper(&pk)),
        ),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
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

    // Group-level `publicKey` per spec §8.3.1 Table 11. (Field
    // name is `publicKey`, not `pk` — different from ML-DSA / SLH-DSA
    // sigVer which use `pk`.)
    let pk_bytes = hex::decode(
        group
            .get("publicKey")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("publicKey"))?,
    )?;
    let pk: [u8; oxicrypt_lms::PUBLIC_KEY_LEN] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;

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

        let sig_bytes = hex::decode(
            t.get("signature")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("signature"))?,
        )?;

        let passed =
            if let Ok(sig) = <[u8; oxicrypt_lms::SIGNATURE_LEN]>::try_from(sig_bytes.as_slice()) {
                oxicrypt_lms::verify_internal(&pk, &message, &sig)
            } else {
                false
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
