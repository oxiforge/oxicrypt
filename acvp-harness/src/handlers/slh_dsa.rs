//! SLH-DSA ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes per FIPS 205.
//!
//! Three handlers, one per mode (see `draft-livelsberger-acvp-slh-dsa §7.3` /
//! `§7.4` / `§7.5`):
//!
//! - **`SlhDsaKeyGenHandler`** — `SLH-DSA` / `keyGen` / `FIPS205`, advertising
//!   all **12 parameterSets** per FIPS 205 §11 Table 2 (SHA-2 and SHAKE
//!   families × {128, 192, 256} security levels × {s, f} small/fast variants).
//!   Each test case carries `skSeed`, `skPrf`, and `pkSeed` as three separate
//!   N-byte components where `N` ∈ {16, 24, 32} per the parameterSet; the
//!   handler concatenates them into the `3N`-byte input that the per-variant
//!   `keygen_internal` consumes.
//! - **`SlhDsaSigGenHandler`** — `SLH-DSA` / `sigGen` / `FIPS205`, advertising
//!   `deterministic: [true]`, `signatureInterfaces: ["internal"]`,
//!   `preHash: ["pure"]`. Signs deterministically (FIPS 205 §10.2 Algorithm 22
//!   with `opt_rand = PK.seed`); the per-test `sk` is variant-sized
//!   (SK_LEN = 4N = 64 / 96 / 128).
//! - **`SlhDsaSigVerHandler`** — `SLH-DSA` / `sigVer` / `FIPS205`, same
//!   interface/pre-hash advertisement as sigGen. The per-test `pk` is
//!   variant-sized (PK_LEN = 2N = 32 / 48 / 64); `signature` is variant-sized
//!   per FIPS 205 §11 Table 2 (7 856 bytes for SHA2-128s up to 49 856 bytes
//!   for SHAKE-256f).
//!
//! The `algorithm()` value is the family name `"SLH-DSA"` — the per-group
//! `parameterSet` field selects the variant. This matches the live ACVP
//! catalog shape and parallels the ML-DSA handlers' three-variant dispatch
//! (12 sets for SLH-DSA in the same dispatch shape that ML-DSA uses for 3).

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// SLH-DSA keyGen dispatcher (advertises all 12 FIPS 205 §11 parameterSets).
pub struct SlhDsaKeyGenHandler;

impl AlgorithmHandler for SlhDsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS205"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_keygen_capability(None))
    }
    fn acvp_capabilities_filtered(&self, paramset: Option<&str>) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_keygen_capability(paramset))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// SLH-DSA sigGen dispatcher (deterministic, internal interface, pure mode;
/// all 12 parameterSets).
pub struct SlhDsaSigGenHandler;

impl AlgorithmHandler for SlhDsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS205"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_siggen_capability(None))
    }
    fn acvp_capabilities_filtered(&self, paramset: Option<&str>) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_siggen_capability(paramset))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── SigVer handler ──────────────────────────────────────────────────

/// SLH-DSA sigVer dispatcher (internal interface, pure mode; all 12
/// parameterSets).
pub struct SlhDsaSigVerHandler;

impl AlgorithmHandler for SlhDsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "SLH-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS205"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_sigver_capability(None))
    }
    fn acvp_capabilities_filtered(&self, paramset: Option<&str>) -> Option<JsonValue> {
        Some(super::caps::slh_dsa_sigver_capability(paramset))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn read_parameter_set(group: &JsonValue) -> Result<&str, DispatchError> {
    group
        .get("parameterSet")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("parameterSet"))
}

fn unsupported_parameter_set(_other: &str) -> DispatchError {
    DispatchError::Unsupported(
        "SLH-DSA: parameterSet must be one of SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f} (12 sets per FIPS 205 §11 Table 2)",
    )
}

// ── KeyGen group driver ─────────────────────────────────────────────

/// Match-arm body for one parameterSet's keygen.
///
/// `$keygen_fn` is the per-variant function path (e.g.
/// `oxicrypt_slh_dsa::slh_dsa_sha2_256s::keygen_internal`); `$n` is the
/// variant's `N` from FIPS 205 §11 Table 2 (16 / 24 / 32). Each of the three
/// seed components is length-checked to exactly `$n` bytes before
/// concatenation into a `[u8; 3 * $n]` array. (We pass the full function
/// path rather than the module path because Rust's `:path` metavariable does
/// not support `::`-appending inside the macro body.)
macro_rules! keygen_arm {
    ($keygen_fn:path, $n:expr, $sk_seed:expr, $sk_prf:expr, $pk_seed:expr) => {{
        if $sk_seed.len() != $n {
            return Err(DispatchError::Crypto(
                "SLH-DSA KeyGen: skSeed has wrong length for parameterSet",
            ));
        }
        if $sk_prf.len() != $n {
            return Err(DispatchError::Crypto(
                "SLH-DSA KeyGen: skPrf has wrong length for parameterSet",
            ));
        }
        if $pk_seed.len() != $n {
            return Err(DispatchError::Crypto(
                "SLH-DSA KeyGen: pkSeed has wrong length for parameterSet",
            ));
        }
        let mut seed = [0u8; 3 * $n];
        seed[..$n].copy_from_slice($sk_seed);
        seed[$n..2 * $n].copy_from_slice($sk_prf);
        seed[2 * $n..].copy_from_slice($pk_seed);
        let (pk, sk) = $keygen_fn(&seed);
        (hex::encode_upper(&pk), hex::encode_upper(&sk))
    }};
}

// Line count is driven by the 12-arm parameterSet match (SLH-DSA has 12 FIPS
// 205 §11 variants vs ML-DSA's 3). Each arm is a single macro invocation;
// the match cannot be meaningfully shortened without losing per-variant
// auditability.
#[allow(clippy::too_many_lines)]
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

    let parameter_set = read_parameter_set(group)?;

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

        // Per `draft-livelsberger-acvp-slh-dsa §8.1.2 Table 10`, the keyGen
        // test case carries three separate hex fields: skSeed, skPrf, pkSeed.
        // Each is N bytes where N varies by parameterSet (16 / 24 / 32 per
        // FIPS 205 §11 Table 2). The per-variant `keygen_internal` consumes
        // the 3N-byte concatenation `skSeed ‖ skPrf ‖ pkSeed`.
        let sk_seed_bytes = hex::decode(
            t.get("skSeed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("skSeed"))?,
        )?;
        let sk_prf_bytes = hex::decode(
            t.get("skPrf")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("skPrf"))?,
        )?;
        let pk_seed_bytes = hex::decode(
            t.get("pkSeed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("pkSeed"))?,
        )?;

        let (pk_hex, sk_hex) = match parameter_set {
            "SLH-DSA-SHA2-128s" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_128s::keygen_internal,
                16,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHA2-128f" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_128f::keygen_internal,
                16,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHA2-192s" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_192s::keygen_internal,
                24,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHA2-192f" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_192f::keygen_internal,
                24,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHA2-256s" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_256s::keygen_internal,
                32,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHA2-256f" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_256f::keygen_internal,
                32,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHAKE-128s" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_128s::keygen_internal,
                16,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHAKE-128f" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_128f::keygen_internal,
                16,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHAKE-192s" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_192s::keygen_internal,
                24,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHAKE-192f" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_192f::keygen_internal,
                24,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHAKE-256s" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_256s::keygen_internal,
                32,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            "SLH-DSA-SHAKE-256f" => keygen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_256f::keygen_internal,
                32,
                &sk_seed_bytes,
                &sk_prf_bytes,
                &pk_seed_bytes
            ),
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("pk".to_string(), JsonValue::String(pk_hex)),
            ("sk".to_string(), JsonValue::String(sk_hex)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── SigGen group driver ─────────────────────────────────────────────

/// Match-arm body for one parameterSet's sigGen.
///
/// `$sk_len` and `$sign_fn` are the per-variant `SK_LEN` const and
/// `sign_internal` function path; the macro coerces the per-test `sk` bytes
/// into `[u8; $sk_len]`, calls `$sign_fn`, and hex-encodes the variant-sized
/// signature.
macro_rules! siggen_arm {
    ($sk_len:expr, $sign_fn:path, $sk_bytes:expr, $message:expr) => {{
        let sk: [u8; $sk_len] = $sk_bytes.as_slice().try_into().map_err(|_| {
            DispatchError::Crypto("SLH-DSA SigGen: sk has wrong length for parameterSet")
        })?;
        let sig = $sign_fn(&sk, $message);
        hex::encode_upper(&sig)
    }};
}

// Line count is driven by the 12-arm parameterSet match — see comment on
// `handle_keygen_group` for the SLH-DSA-vs-ML-DSA arm-count rationale.
#[allow(clippy::too_many_lines)]
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

    let parameter_set = read_parameter_set(group)?;

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

        // Per `draft-livelsberger-acvp-slh-dsa §8.2.2`, both `sk` and
        // `message` are per-test fields — different test cases can exercise
        // different secret keys + messages within the same group. `sk` is
        // variant-sized (SK_LEN = 4N = 64 / 96 / 128).
        let sk_bytes = hex::decode(
            t.get("sk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("sk"))?,
        )?;
        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;

        let sig_hex = match parameter_set {
            "SLH-DSA-SHA2-128s" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_128s::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_128s::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHA2-128f" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_128f::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_128f::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHA2-192s" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_192s::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_192s::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHA2-192f" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_192f::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_192f::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHA2-256s" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_256s::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_256s::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHA2-256f" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_256f::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_256f::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHAKE-128s" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_128s::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_128s::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHAKE-128f" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_128f::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_128f::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHAKE-192s" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_192s::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_192s::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHAKE-192f" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_192f::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_192f::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHAKE-256s" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_256s::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_256s::sign_internal,
                sk_bytes,
                &message
            ),
            "SLH-DSA-SHAKE-256f" => siggen_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_256f::SK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_256f::sign_internal,
                sk_bytes,
                &message
            ),
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("signature".to_string(), JsonValue::String(sig_hex)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── SigVer group driver ─────────────────────────────────────────────

/// Match-arm body for one parameterSet's sigVer.
///
/// `$pk_len`, `$sig_len`, and `$verify_fn` are the per-variant const lengths
/// and function path; the macro coerces the per-test `pk` and `signature`
/// into `[u8; $pk_len]` and `[u8; $sig_len]`, calls `$verify_fn`, and
/// returns the per-case `testPassed: bool`. A wrong-length `pk` is
/// hard-failed (the server cannot produce a wrong-length valid pk per the
/// spec); a wrong-length `signature` is soft-failed to `false` so the server
/// can grade tampered cases that happen to be off-length (which the
/// per-family verify convention already collapses through `TagMismatch = 22`).
macro_rules! sigver_arm {
    ($pk_len:expr, $sig_len:expr, $verify_fn:path, $pk_bytes:expr, $message:expr, $sig_bytes:expr) => {{
        let pk: [u8; $pk_len] = $pk_bytes.as_slice().try_into().map_err(|_| {
            DispatchError::Crypto("SLH-DSA SigVer: pk has wrong length for parameterSet")
        })?;
        if let Ok(sig) = <[u8; $sig_len]>::try_from($sig_bytes.as_slice()) {
            $verify_fn(&pk, $message, &sig)
        } else {
            false
        }
    }};
}

// Line count is driven by the 12-arm parameterSet match — see comment on
// `handle_keygen_group` for the SLH-DSA-vs-ML-DSA arm-count rationale.
#[allow(clippy::too_many_lines)]
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

    let parameter_set = read_parameter_set(group)?;

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

        // Per `draft-livelsberger-acvp-slh-dsa §8.3.2`, `pk`, `message`, and
        // `signature` are all per-test fields. Server mixes valid and tampered
        // (key-flip) signatures within the same group; the IUT returns
        // `testPassed: bool` per case and the server grades by exact-match
        // against the expected valid/invalid disposition.
        let pk_bytes = hex::decode(
            t.get("pk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("pk"))?,
        )?;
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

        let passed = match parameter_set {
            "SLH-DSA-SHA2-128s" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_128s::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_128s::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_128s::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHA2-128f" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_128f::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_128f::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_128f::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHA2-192s" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_192s::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_192s::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_192s::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHA2-192f" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_192f::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_192f::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_192f::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHA2-256s" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_256s::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_256s::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_256s::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHA2-256f" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_sha2_256f::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_256f::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_sha2_256f::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHAKE-128s" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_128s::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_128s::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_128s::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHAKE-128f" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_128f::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_128f::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_128f::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHAKE-192s" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_192s::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_192s::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_192s::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHAKE-192f" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_192f::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_192f::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_192f::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHAKE-256s" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_256s::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_256s::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_256s::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            "SLH-DSA-SHAKE-256f" => sigver_arm!(
                oxicrypt_slh_dsa::slh_dsa_shake_256f::PK_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_256f::SIG_LEN,
                oxicrypt_slh_dsa::slh_dsa_shake_256f::verify_internal,
                pk_bytes,
                &message,
                sig_bytes
            ),
            other => return Err(unsupported_parameter_set(other)),
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
