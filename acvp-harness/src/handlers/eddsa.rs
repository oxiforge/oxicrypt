//! EdDSA ACVP handlers — `sigVer`, `keyVer`, `sigGen`, and `keyGen`
//! modes, revision `1.0`.
//!
//! Four modes, each dispatched as a separate handler:
//!
//! - **SigVer** (`EDDSA` / `sigVer` / `1.0`): Given a message, public
//!   key (`q`), and `signature`, verify the Ed25519 signature and
//!   return `testPassed`. Only `preHash = false` (pure Ed25519) is
//!   supported; prehash groups are rejected as unsupported.
//! - **KeyVer** (`EDDSA` / `keyVer` / `1.0`): Given a public key (`q`),
//!   validate that it is a valid compressed Edwards point and return
//!   `testPassed`.
//! - **SigGen** (`EDDSA` / `sigGen` / `1.0`): Dual-mode and dual-
//!   testType. Per `draft-celi-acvp-eddsa.txt` §6.1 the catalog row
//!   advertises two test types: **AFT** (Algorithm Functional Test —
//!   sign ACVP-supplied messages) and **BFT** (Bit Flip Test — sign a
//!   sequence of bit-flipped variants of one base message; the server
//!   verifies the per-message signatures are distinct and individually
//!   valid). Both testTypes share an identical per-group + per-test
//!   schema, so the handler treats them the same once the gate accepts
//!   them. Live ACVTS prompts are FIPS 186-5 §7.6 generative — group
//!   has no `d`; the IUT samples a fresh keypair per group via
//!   `Ed25519PrivateKey::generate` (with IG 10.3.A PCT) and signs each
//!   per-test `message`. Response carries group-level `q` plus per-test
//!   `signature`. Vendored offline kat-slice fixtures supply `d` at
//!   group level for deterministic round-trip; the handler signs
//!   directly with the supplied seed (Ed25519 is fully deterministic
//!   given seed + message per RFC 8032 §5.1.6).
//! - **KeyGen** (`EDDSA` / `keyGen` / `1.0`): Dual-mode. Live ACVTS
//!   prompts carry no `d` — the IUT samples fresh per-test via
//!   `Ed25519PrivateKey::generate`. Vendored offline fixtures supply
//!   `d` per test for deterministic round-trip; the handler derives
//!   `q` via `keygen_internal`.
//!
//! Only the `ED-25519` curve is supported. `ED-448` groups produce
//! `DispatchError::Unsupported`.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── SigVer handler ──────────────────────────────────────────────────

/// EdDSA SigVer AFT dispatcher.
pub struct EddsaSigVerHandler;

impl AlgorithmHandler for EddsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "EDDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::eddsa_sigver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── KeyVer handler ──────────────────────────────────────────────────

/// EdDSA KeyVer AFT dispatcher.
pub struct EddsaKeyVerHandler;

impl AlgorithmHandler for EddsaKeyVerHandler {
    fn algorithm(&self) -> &'static str {
        "EDDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::eddsa_keyver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keyver_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// EdDSA SigGen dispatcher (handles both AFT and BFT testTypes per
/// `draft-celi-acvp-eddsa.txt` §6.1).
///
/// Dual-mode:
/// - **Live ACVTS** (FIPS 186-5 §7.6 generative): group has no `d`;
///   the handler samples a fresh keypair per group via the module's
///   DRBG-backed `Ed25519PrivateKey::generate` (with IG 10.3.A PCT)
///   and signs each test message with `oxicrypt_eddsa::ed25519::sign`
///   (RFC 8032 §5.1.6 derives the per-message nonce internally, so no
///   DRBG involvement at the sign step itself). Response carries the
///   group-level `q` (so the server can verify) plus per-test
///   `signature`.
/// - **Vendored offline kat-slice** (deterministic round-trip): group
///   carries `d` per FIPS 186-5 §7.6 deterministic shape; the handler
///   signs each message with the supplied seed. Response carries
///   per-test `signature` only — the offline fixture already knows
///   `q` from `d`.
///
/// Same dual-mode pattern as [`super::ecdsa`]'s sigGen handler.
pub struct EddsaSigGenHandler;

impl AlgorithmHandler for EddsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "EDDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::eddsa_siggen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── KeyGen handler ─────────────────────────────────────────────────

/// EdDSA KeyGen AFT dispatcher.
pub struct EddsaKeyGenHandler;

impl AlgorithmHandler for EddsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "EDDSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::eddsa_keygen_capability())
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

    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    if curve != "ED-25519" {
        return Err(DispatchError::Unsupported(
            "EdDSA SigVer: only ED-25519 is supported",
        ));
    }

    // Reject prehash (Ed25519ph) — oxicrypt implements pure Ed25519 only.
    let pre_hash = group
        .get("preHash")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    if pre_hash {
        return Err(DispatchError::Unsupported(
            "EdDSA SigVer: Ed25519ph (preHash=true) is not supported",
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

        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;
        let q_bytes = hex::decode(
            t.get("q")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("q"))?,
        )?;
        let sig_bytes = hex::decode(
            t.get("signature")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("signature"))?,
        )?;

        let passed = ed25519_verify(&q_bytes, &message, &sig_bytes);

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
    if curve != "ED-25519" {
        return Err(DispatchError::Unsupported(
            "EdDSA KeyVer: only ED-25519 is supported",
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

        let q_bytes = hex::decode(
            t.get("q")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("q"))?,
        )?;

        let passed = ed25519_key_validate(&q_bytes);

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
    // EDDSA / sigGen / 1.0 has two testTypes per `draft-celi-acvp-
    // eddsa.txt` §6.1:
    //   * AFT (Algorithm Functional Test) — the IUT signs ACVP-supplied
    //     messages and the server validates each signature against the
    //     IUT's communicated curve / public key / signature.
    //   * BFT (Bit Flip Test) — the server produces a single base
    //     message and emits a sequence of bit-flipped variants; the IUT
    //     signs each one. The server validates that distinct messages
    //     produce distinct (and individually valid) signatures.
    // Both modes have structurally identical group + test schemas (per-
    // group keypair, per-test `{tcId, message}`); the only divergence
    // is in WHAT messages the server emits, which is invisible to the
    // handler. So this dispatcher's per-group key sample + per-test
    // sign loop covers both — we just need to allow BFT past the gate.
    if test_type != "AFT" && test_type != "BFT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let curve = group
        .get("curve")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("curve"))?;
    if curve != "ED-25519" {
        return Err(DispatchError::Unsupported(
            "EdDSA SigGen: only ED-25519 is supported",
        ));
    }

    let pre_hash = group
        .get("preHash")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    if pre_hash {
        return Err(DispatchError::Unsupported(
            "EdDSA SigGen: Ed25519ph (preHash=true) is not supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // Dual-mode: live ACVTS prompts are FIPS 186-5 §7.6 generative
    // (group has no `d`); the IUT samples a fresh keypair per group
    // via the module's DRBG-backed `Ed25519PrivateKey::generate` and
    // signs each test message with it. Vendored offline kat-slice
    // fixtures supply `d` at group level for deterministic round-trip
    // assertions; the handler detects that shape via `group.d` presence
    // and signs with the supplied seed directly. Same dual-mode pattern
    // as the ECDSA sigGen handler.
    let deterministic = group.get("d").is_some();

    // `seed`: the signing seed (32 bytes). Sourced from the prompt in
    // deterministic mode, sampled from DRBG in live mode.
    // `q_hex_for_group`: the public key emitted at group level only in
    // live mode — the ACVP server needs `q` to verify signatures on
    // its side. Deterministic-mode prompts already know `q` so we
    // omit it from the response (matches the ECDSA SigGen
    // convention).
    let (seed, q_hex_for_group): ([u8; 32], Option<String>) = if deterministic {
        let d_bytes = hex::decode(
            group
                .get("d")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("d"))?,
        )?;
        let seed: [u8; 32] = d_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("EdDSA SigGen: d is not 32 bytes"))?;
        (seed, None)
    } else {
        let mut drbg = super::os_entropy::build_seeded_drbg()?;
        let sk = oxicrypt_eddsa::ed25519::Ed25519PrivateKey::generate(&mut drbg)
            .map_err(|_| DispatchError::Crypto("EdDSA SigGen: generate failed"))?;
        let seed_ref: &[u8; 32] = sk.seed();
        let q = sk.public_key();
        (*seed_ref, Some(hex::encode_upper(&q)))
    };

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

        let sig = oxicrypt_eddsa::ed25519::sign(&seed, &message)
            .map_err(|_| DispatchError::Crypto("EdDSA SigGen: sign failed"))?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "signature".to_string(),
                JsonValue::String(hex::encode_upper(&sig)),
            ),
        ]));
    }

    let mut group_response: Vec<(String, JsonValue)> =
        vec![("tgId".to_string(), JsonValue::Number(tg_id))];
    if let Some(q_hex) = q_hex_for_group {
        group_response.push(("q".to_string(), JsonValue::String(q_hex)));
    }
    group_response.push(("tests".to_string(), JsonValue::Array(results)));
    Ok(JsonValue::Object(group_response))
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
    if curve != "ED-25519" {
        return Err(DispatchError::Unsupported(
            "EdDSA KeyGen: only ED-25519 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // Dual-mode: live ACVTS prompts are FIPS 186-5 §7.6 generative
    // (test carries only `tcId`); the harness's vendored offline kat-
    // slice supplies `d` per test for deterministic round-trip.
    // Detect by `d` presence on the first test — if present we take
    // the deterministic path; if absent we sample fresh seeds via the
    // module's DRBG (`Ed25519PrivateKey::generate` mirrors the ECDSA
    // keyGen DRBG-driven shape, IG 10.3.A PCT included).
    let deterministic = tests.first().is_some_and(|t| t.get("d").is_some());

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    if deterministic {
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
            let seed: [u8; 32] = d_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DispatchError::Crypto("EdDSA KeyGen: d is not 32 bytes"))?;
            let q = oxicrypt_eddsa::ed25519::keygen_internal(&seed);
            results.push(JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(test_case_id)),
                ("q".to_string(), JsonValue::String(hex::encode_upper(&q))),
            ]));
        }
    } else {
        let mut drbg = super::os_entropy::build_seeded_drbg()?;
        for t in tests {
            let test_case_id = t
                .get("tcId")
                .and_then(JsonValue::as_i64)
                .ok_or(DispatchError::MissingField("tcId"))?;
            let sk = oxicrypt_eddsa::ed25519::Ed25519PrivateKey::generate(&mut drbg)
                .map_err(|_| DispatchError::Crypto("EdDSA KeyGen: generate failed"))?;
            results.push(JsonValue::Object(vec![
                ("tcId".to_string(), JsonValue::Number(test_case_id)),
                (
                    "d".to_string(),
                    JsonValue::String(hex::encode_upper(sk.seed())),
                ),
                (
                    "q".to_string(),
                    JsonValue::String(hex::encode_upper(&sk.public_key())),
                ),
            ]));
        }
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Crypto helpers ──────────────────────────────────────────────────

/// Verify an Ed25519 signature. Public key is 32 bytes (compressed
/// Edwards point), signature is 64 bytes (R || S).
fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let pk: &[u8; 32] = public_key.try_into().unwrap_or(&[0u8; 32]);
    let sig: &[u8; 64] = signature.try_into().unwrap_or(&[0u8; 64]);
    oxicrypt_eddsa::ed25519::verify(pk, message, sig).unwrap_or_default()
}

/// Validate an Ed25519 public key by attempting to decompress it.
fn ed25519_key_validate(public_key: &[u8]) -> bool {
    if public_key.len() != 32 {
        return false;
    }
    let pk: [u8; 32] = public_key.try_into().unwrap_or([0u8; 32]);
    oxicrypt_eddsa::edwards::EdwardsPoint::decompress(&pk).is_some()
}
