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
//! - **SigGen** (`ECDSA` / `sigGen` / `FIPS186-5`): Dual-mode. Live
//!   ACVTS prompts are FIPS 186-5 §A.2.2 generative — the IUT samples a
//!   fresh keypair per group via `EcdsaP*PrivateKey::generate` (with
//!   IG 10.3.A PCT) and signs each per-test `message` with a fresh
//!   DRBG-sampled `k` via `sign_sha{256,384}`. Vendored offline kat-
//!   slice fixtures additionally supply `d` per group and `k` per
//!   test for deterministic round-trip assertions; the handler
//!   detects that shape and signs with the supplied scalars via
//!   `sign_with_k`. Both modes emit group-level `qx`/`qy` plus per-
//!   test `r`/`s`.
//! - **KeyGen** (`ECDSA` / `keyGen` / `FIPS186-5`): Dual-mode. Live
//!   ACVTS prompts carry no `d`; the IUT samples fresh per-test via
//!   `EcdsaP*PrivateKey::generate`. Vendored offline fixtures supply
//!   `d` per test for deterministic round-trip; the handler derives
//!   `qx`/`qy` via `derive_public_key_internal`. Group-level
//!   `secretGenerationMode` is observed (we only support
//!   `"testing candidates"` per FIPS 186-5 §A.2.2;
//!   `"extra random bits"` is rejected).
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ecdsa_sigver_capability())
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ecdsa_keyver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keyver_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// ECDSA SigGen AFT dispatcher.
///
/// Dual-mode:
/// - **Live ACVTS** (FIPS 186-5 §A.2.2 generative): prompt has no `d`
///   or `k`; the handler samples a fresh keypair per group via the
///   module's DRBG-backed `EcdsaP*PrivateKey::generate` and signs each
///   test with `sign_sha{256,384}` (DRBG-sampled `k`).
/// - **Vendored offline fixtures** (deterministic round-trip): prompt
///   carries `d` per group and `k` per test; the handler signs with
///   the supplied scalars via `sign_with_k`.
///
/// Both modes emit the same response shape: group-level `qx`/`qy` plus
/// per-test `tcId`/`r`/`s`.
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ecdsa_siggen_capability())
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
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ecdsa_keygen_capability())
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

// `qx_hex` / `qy_hex` and `tg_id` / `tc_id` are spec-mandated ACVP
// names appearing as binding pairs throughout this module; clippy's
// `similar_names` lint fires on every such pair. Suppressed at the
// function scope rather than renamed because the names match the
// JSON field names a CMVP reviewer would expect to see.
#[allow(clippy::similar_names)]
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

    // componentTest=true changes the response shape (no per-group key,
    // IUT signs a hash directly without re-hashing). The vendored slice
    // and the live demo prompt both ship componentTest=false; reject the
    // true variant rather than silently mishandle it.
    if group
        .get("componentTest")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
    {
        return Err(DispatchError::Unsupported(
            "ECDSA SigGen: componentTest=true is not supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // Dual-mode: live ACVTS prompts are FIPS 186-5 §A.2.2 generative
    // (no `d`, no `k`); the harness's vendored offline fixtures supply
    // `d` per group and `k` per test for deterministic round-trip
    // assertions. Detect the deterministic shape by `group.d`'s
    // presence — if it's there, sign with the supplied scalars; if
    // not, generate via a fresh DRBG.
    let (qx_hex, qy_hex, results) = if group.get("d").is_some() {
        match curve {
            "P-256" => sign_group_p256_deterministic(group, tests)?,
            "P-384" => sign_group_p384_deterministic(group, tests)?,
            _ => {
                return Err(DispatchError::Unsupported(
                    "ECDSA SigGen: unsupported curve",
                ))
            }
        }
    } else {
        let mut drbg = super::os_entropy::build_seeded_drbg()?;
        match curve {
            "P-256" => sign_group_p256(&mut drbg, tests)?,
            "P-384" => sign_group_p384(&mut drbg, tests)?,
            _ => {
                return Err(DispatchError::Unsupported(
                    "ECDSA SigGen: unsupported curve",
                ))
            }
        }
    };

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("qx".to_string(), JsonValue::String(qx_hex)),
        ("qy".to_string(), JsonValue::String(qy_hex)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

#[allow(clippy::similar_names)]
fn sign_group_p256(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    tests: &[JsonValue],
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    let sk = oxicrypt_ecdsa::p256_ecdsa::EcdsaP256PrivateKey::generate(drbg)
        .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-256: generate failed"))?;
    let pk = sk.public_key();
    let qx_hex = hex::encode_upper(&pk[1..33]);
    let qy_hex = hex::encode_upper(&pk[33..65]);

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let tc_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;
        let sig = sk
            .sign_sha256(drbg, &message)
            .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-256: sign_sha256 failed"))?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
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
    Ok((qx_hex, qy_hex, results))
}

#[allow(clippy::similar_names)]
fn sign_group_p384(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    tests: &[JsonValue],
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    let sk = oxicrypt_ecdsa::p384_ecdsa::EcdsaP384PrivateKey::generate(drbg)
        .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-384: generate failed"))?;
    let pk = sk.public_key();
    let qx_hex = hex::encode_upper(&pk[1..49]);
    let qy_hex = hex::encode_upper(&pk[49..97]);

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let tc_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;
        let sig = sk
            .sign_sha384(drbg, &message)
            .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-384: sign_sha384 failed"))?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
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
    Ok((qx_hex, qy_hex, results))
}

// Deterministic sigGen helpers — driven by group-level `d` and
// per-test `k`. Used by the vendored offline kat-slice round-trip
// tests; never exercised on the live demo wire.

#[allow(clippy::similar_names)]
fn sign_group_p256_deterministic(
    group: &JsonValue,
    tests: &[JsonValue],
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    let d_bytes = hex::decode(
        group
            .get("d")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("d"))?,
    )?;
    let d: [u8; 32] = d_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-256: d is not 32 bytes"))?;
    let pk = oxicrypt_ecdsa::p256_ecdsa::derive_public_key_internal(&d).ok_or(
        DispatchError::Crypto("ECDSA SigGen P-256: derive_public_key_internal failed"),
    )?;
    let qx_hex = hex::encode_upper(&pk[1..33]);
    let qy_hex = hex::encode_upper(&pk[33..65]);

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let tc_id = t
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
            .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-256: k is not 32 bytes"))?;
        let sig = oxicrypt_ecdsa::p256_ecdsa::sign_with_k(&d, &message, &k)
            .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-256: sign_with_k failed"))?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
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
    Ok((qx_hex, qy_hex, results))
}

#[allow(clippy::similar_names)]
fn sign_group_p384_deterministic(
    group: &JsonValue,
    tests: &[JsonValue],
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    let d_bytes = hex::decode(
        group
            .get("d")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("d"))?,
    )?;
    let d: [u8; 48] = d_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-384: d is not 48 bytes"))?;
    let pk = oxicrypt_ecdsa::p384_ecdsa::derive_public_key_internal(&d).ok_or(
        DispatchError::Crypto("ECDSA SigGen P-384: derive_public_key_internal failed"),
    )?;
    let qx_hex = hex::encode_upper(&pk[1..49]);
    let qy_hex = hex::encode_upper(&pk[49..97]);

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let tc_id = t
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
            .map_err(|_| DispatchError::Crypto("ECDSA SigGen P-384: k is not 48 bytes"))?;
        let sig = oxicrypt_ecdsa::p384_ecdsa::sign_with_k_internal(&d, &message, &k).ok_or(
            DispatchError::Crypto("ECDSA SigGen P-384: sign_with_k_internal failed"),
        )?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
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
    Ok((qx_hex, qy_hex, results))
}

// ── KeyGen group driver ────────────────────────────────────────────

#[allow(clippy::similar_names)]
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

    // FIPS 186-5 §A.2.2 ("testing candidates") is what
    // `EcdsaP*PrivateKey::generate` implements. The "extra random bits"
    // mode (§A.2.1) requires an N+64-bit DRBG draw and a different
    // reduction; we don't implement it. Reject it explicitly so a
    // server-side prompt change surfaces rather than silently
    // mishandles.
    if let Some(mode) = group
        .get("secretGenerationMode")
        .and_then(JsonValue::as_str)
    {
        if mode != "testing candidates" {
            return Err(DispatchError::Unsupported(
                "ECDSA KeyGen: secretGenerationMode must be \"testing candidates\"",
            ));
        }
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // Dual-mode: live ACVTS prompts are FIPS 186-5 §A.2.2 generative
    // (no `d` per-test); the harness's vendored offline fixtures supply
    // `d` per test for deterministic round-trip assertions. Detect by
    // probing the first test for `d`; if present, derive public keys
    // deterministically; if not, generate via a fresh DRBG.
    let deterministic = tests.first().is_some_and(|t| t.get("d").is_some());
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    if deterministic {
        match curve {
            "P-256" => derive_keygen_p256(tests, &mut results)?,
            "P-384" => derive_keygen_p384(tests, &mut results)?,
            _ => {
                return Err(DispatchError::Unsupported(
                    "ECDSA KeyGen: unsupported curve",
                ))
            }
        }
    } else {
        let mut drbg = super::os_entropy::build_seeded_drbg()?;
        match curve {
            "P-256" => generate_keygen_p256(&mut drbg, tests, &mut results)?,
            "P-384" => generate_keygen_p384(&mut drbg, tests, &mut results)?,
            _ => {
                return Err(DispatchError::Unsupported(
                    "ECDSA KeyGen: unsupported curve",
                ))
            }
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── KeyGen mode helpers (deterministic + generative) ───────────────

#[allow(clippy::similar_names)]
fn derive_keygen_p256(
    tests: &[JsonValue],
    results: &mut Vec<JsonValue>,
) -> Result<(), DispatchError> {
    for t in tests {
        let tc_id = t
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
            .map_err(|_| DispatchError::Crypto("ECDSA KeyGen P-256: d is not 32 bytes"))?;
        let pk = oxicrypt_ecdsa::p256_ecdsa::derive_public_key_internal(&d).ok_or(
            DispatchError::Crypto("ECDSA KeyGen P-256: derive_public_key_internal failed"),
        )?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
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
    Ok(())
}

#[allow(clippy::similar_names)]
fn derive_keygen_p384(
    tests: &[JsonValue],
    results: &mut Vec<JsonValue>,
) -> Result<(), DispatchError> {
    for t in tests {
        let tc_id = t
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
            .map_err(|_| DispatchError::Crypto("ECDSA KeyGen P-384: d is not 48 bytes"))?;
        let pk = oxicrypt_ecdsa::p384_ecdsa::derive_public_key_internal(&d).ok_or(
            DispatchError::Crypto("ECDSA KeyGen P-384: derive_public_key_internal failed"),
        )?;
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
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
    Ok(())
}

#[allow(clippy::similar_names)]
fn generate_keygen_p256(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    tests: &[JsonValue],
    results: &mut Vec<JsonValue>,
) -> Result<(), DispatchError> {
    for t in tests {
        let tc_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let sk = oxicrypt_ecdsa::p256_ecdsa::EcdsaP256PrivateKey::generate(drbg)
            .map_err(|_| DispatchError::Crypto("ECDSA KeyGen P-256: generate failed"))?;
        let d_hex = hex::encode_upper(sk.private_scalar());
        let pk = sk.public_key();
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            ("d".to_string(), JsonValue::String(d_hex)),
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
    Ok(())
}

#[allow(clippy::similar_names)]
fn generate_keygen_p384(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    tests: &[JsonValue],
    results: &mut Vec<JsonValue>,
) -> Result<(), DispatchError> {
    for t in tests {
        let tc_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let sk = oxicrypt_ecdsa::p384_ecdsa::EcdsaP384PrivateKey::generate(drbg)
            .map_err(|_| DispatchError::Crypto("ECDSA KeyGen P-384: generate failed"))?;
        let d_hex = hex::encode_upper(sk.private_scalar());
        let pk = sk.public_key();
        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(tc_id)),
            ("d".to_string(), JsonValue::String(d_hex)),
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
    Ok(())
}

// DRBG bootstrap moved to `super::os_entropy` once a second consumer
// (KAS-ECC-SSC live AFT) appeared. See that module for the rationale
// on `/dev/urandom` and the SP 800-90A §10.1 entropy/nonce split.

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
