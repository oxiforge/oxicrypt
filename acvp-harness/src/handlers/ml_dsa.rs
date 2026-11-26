//! ML-DSA ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes per FIPS 204.
//!
//! Three handlers, mirroring the catalog's three-mode shape
//! (see `draft-celi-acvp-ml-dsa §7.3.1`, `§7.4.1`, `§7.5.1`):
//!
//! - **`MlDsaKeyGenHandler`** — `ML-DSA` / `keyGen` / `FIPS204`,
//!   advertising `parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`.
//!   Generates a (public key, secret key) pair from a 32-byte seed.
//!   Per-group `parameterSet` field selects the variant.
//! - **`MlDsaSigGenHandler`** — `ML-DSA` / `sigGen` / `FIPS204`,
//!   advertising the same three parameter sets. Deterministic-mode
//!   signing (32 zero bytes as `rnd`, FIPS 204 §3.4). The group's
//!   `signatureInterface` selects `sign_internal` (`internal`,
//!   `externalMu: false`) or the public `sign` with the vector's
//!   context (`external`, `preHash: "pure"`). Per-group
//!   `parameterSet` field selects the variant (which fixes SK_LEN).
//! - **`MlDsaSigVerHandler`** — `ML-DSA` / `sigVer` / `FIPS204`,
//!   advertising the same three parameter sets and the same two
//!   interfaces, through `verify_internal` or the public `verify`.
//!   Per-group `parameterSet` field selects the variant (which fixes
//!   PK_LEN and SIG_LEN). The server mixes valid and tampered
//!   signatures within the same group; the IUT returns
//!   `testPassed: bool`.
//!
//! All three FIPS 204 parameter sets are supported. The `algorithm()`
//! value is the family name `"ML-DSA"`. A new parameter set needs a
//! cap entry and a match arm in each group driver, and no new handler
//! struct.
//!
//! Per-test field placement (`sk` for sigGen, `pk` for sigVer)
//! follows §8.2.2 Table 14 and §8.3.2 Table 16 of the draft.

use crate::dispatch::{AlgorithmHandler, DispatchError, primitive_err};
use crate::hex;
use crate::json::JsonValue;

/// ML-DSA keyGen dispatcher
/// (`parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`).
pub struct MlDsaKeyGenHandler;

impl AlgorithmHandler for MlDsaKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "ML-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS204"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_dsa_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

/// ML-DSA sigGen dispatcher
/// (`parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`).
pub struct MlDsaSigGenHandler;

impl AlgorithmHandler for MlDsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "ML-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS204"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_dsa_siggen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

/// ML-DSA sigVer dispatcher
/// (`parameterSets: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]`).
pub struct MlDsaSigVerHandler;

impl AlgorithmHandler for MlDsaSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "ML-DSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "FIPS204"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_dsa_sigver_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

fn read_parameter_set(group: &JsonValue) -> Result<&str, DispatchError> {
    group
        .get("parameterSet")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("parameterSet"))
}

fn unsupported_parameter_set(_other: &str) -> DispatchError {
    DispatchError::Unsupported(
        "ML-DSA: parameterSet must be `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87`",
    )
}

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

        let seed_bytes = hex::decode(
            t.get("seed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("seed"))?,
        )?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-DSA KeyGen: seed is not 32 bytes"))?;

        let (pk_hex, sk_hex) = match parameter_set {
            "ML-DSA-44" => {
                let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_44::keygen_internal(&seed)?;
                (hex::encode_upper(&pk), hex::encode_upper(&sk))
            }
            "ML-DSA-65" => {
                let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_65::keygen_internal(&seed)?;
                (hex::encode_upper(&pk), hex::encode_upper(&sk))
            }
            "ML-DSA-87" => {
                let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_87::keygen_internal(&seed)?;
                (hex::encode_upper(&pk), hex::encode_upper(&sk))
            }
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

/// The two `signatureInterface` values of `draft-celi-acvp-ml-dsa`
/// Tables 13 and 15.
enum SignatureInterface {
    Internal,
    External,
}

/// Reads the group's `signatureInterface`, refusing a group outside
/// the registration. An external group must carry `preHash: "pure"`,
/// the only value the registration lists. An internal group must
/// carry `externalMu: false`, and may carry `preHash` only as `none`:
/// `draft-celi-acvp-ml-dsa` §8.3.1 sends `preHash` on external groups
/// only, and the ACVP-Server internal projections record `none` on
/// internal ones.
fn read_signature_interface(group: &JsonValue) -> Result<SignatureInterface, DispatchError> {
    let interface = group
        .get("signatureInterface")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("signatureInterface"))?;
    match interface {
        "internal" => {
            if group
                .get("preHash")
                .is_some_and(|v| v.as_str() != Some("none"))
            {
                return Err(DispatchError::Unsupported(
                    "ML-DSA: an internal group takes no `preHash`",
                ));
            }
            let external_mu = group
                .get("externalMu")
                .and_then(JsonValue::as_bool)
                .ok_or(DispatchError::MissingField("externalMu"))?;
            if external_mu {
                return Err(DispatchError::Unsupported(
                    "ML-DSA: only `externalMu: false` is registered",
                ));
            }
            Ok(SignatureInterface::Internal)
        }
        "external" => {
            let pre_hash = group
                .get("preHash")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("preHash"))?;
            if pre_hash == "pure" {
                Ok(SignatureInterface::External)
            } else {
                Err(DispatchError::Unsupported(
                    "ML-DSA: preHash must be `pure`; HashML-DSA is not registered",
                ))
            }
        }
        _ => Err(DispatchError::Unsupported(
            "ML-DSA: signatureInterface must be `internal` or `external`",
        )),
    }
}

/// The test case's `context` (`draft-celi-acvp-ml-dsa` Tables 14 and
/// 16), hex-decoded. Every test case of an external group carries it.
/// A context over 255 bytes is outside the registered `contextLength`
/// and the FIPS 204 §5.2 bound, so it is refused like any other group
/// outside the registration.
fn read_context(t: &JsonValue) -> Result<Vec<u8>, DispatchError> {
    let context = t
        .get("context")
        .ok_or(DispatchError::MissingField("context"))?
        .as_str()
        .ok_or(DispatchError::Crypto("ML-DSA: context is not a hex string"))?;
    let context = hex::decode(context)?;
    if context.len() > 255 {
        return Err(DispatchError::Unsupported(
            "ML-DSA: context is longer than 255 bytes",
        ));
    }
    Ok(context)
}

/// Dispatches a sigGen group on its `signatureInterface`. The
/// registration lists `deterministic: [true]` only, so a group with
/// `deterministic: false`, or a test case carrying `rnd`, is refused.
/// It lists no `keyFormats`, so a group whose `keyFormat` is not
/// `expanded` is refused: the `seed` form supplies a seed in place of
/// `sk` (`draft-celi-acvp-ml-dsa` Table 14).
fn handle_siggen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let deterministic = group
        .get("deterministic")
        .and_then(JsonValue::as_bool)
        .ok_or(DispatchError::MissingField("deterministic"))?;
    if !deterministic {
        return Err(DispatchError::Unsupported(
            "ML-DSA SigGen: only `deterministic: true` is registered",
        ));
    }
    match group.get("keyFormat").map(JsonValue::as_str) {
        None | Some(Some("expanded")) => {}
        Some(Some("seed")) => {
            return Err(DispatchError::Unsupported(
                "ML-DSA SigGen: `keyFormat: seed` is not registered",
            ));
        }
        Some(_) => {
            return Err(DispatchError::Unsupported(
                "ML-DSA SigGen: `keyFormat` must be `expanded`",
            ));
        }
    }
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    if tests.iter().any(|t| t.get("rnd").is_some()) {
        return Err(DispatchError::Unsupported(
            "ML-DSA SigGen: `rnd` is not accepted; only `deterministic: true` is registered",
        ));
    }
    match read_signature_interface(group)? {
        SignatureInterface::Internal => ml_dsa_sig_gen_internal(group),
        SignatureInterface::External => ml_dsa_sig_gen_external(group),
    }
}

/// Dispatches a sigVer group on its `signatureInterface`.
fn handle_sigver_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    match read_signature_interface(group)? {
        SignatureInterface::Internal => ml_dsa_sig_ver_internal(group),
        SignatureInterface::External => ml_dsa_sig_ver_external(group),
    }
}

/// The fields every sigGen and sigVer group shares: `tgId`, an `AFT`
/// `testType`, `parameterSet` and `tests`.
fn read_aft_group(group: &JsonValue) -> Result<(i64, &str, &[JsonValue]), DispatchError> {
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
    Ok((tg_id, parameter_set, tests))
}

fn read_hex(t: &JsonValue, field: &'static str) -> Result<Vec<u8>, DispatchError> {
    Ok(hex::decode(
        t.get(field)
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField(field))?,
    )?)
}

fn read_tc_id(t: &JsonValue) -> Result<i64, DispatchError> {
    t.get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))
}

fn group_response(tg_id: i64, results: Vec<JsonValue>) -> JsonValue {
    JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ])
}

/// sigGen through the public `sign`, FIPS 204 §5.2 Algorithm 2, with
/// the vector's message and context.
fn ml_dsa_sig_gen_external(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let (tg_id, parameter_set, tests) = read_aft_group(group)?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let test_case_id = read_tc_id(t)?;
        let sk_bytes = read_hex(t, "sk")?;
        let message = read_hex(t, "message")?;
        let context = read_context(t)?;

        let sig_hex = match parameter_set {
            "ML-DSA-44" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_44::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-44 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_44::sign(&sk, &message, &context)
                    .map_err(primitive_err("ML-DSA-44 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            "ML-DSA-65" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_65::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-65 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_65::sign(&sk, &message, &context)
                    .map_err(primitive_err("ML-DSA-65 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            "ML-DSA-87" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_87::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-87 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_87::sign(&sk, &message, &context)
                    .map_err(primitive_err("ML-DSA-87 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("signature".to_string(), JsonValue::String(sig_hex)),
        ]));
    }
    Ok(group_response(tg_id, results))
}

/// The `testPassed` of the public `verify`, which reports a rejected
/// signature as `InvalidInput`. Its other `InvalidInput` cause, a
/// context over 255 bytes, is refused by [`read_context`] before the
/// call, so any other error is the module refusing the call.
fn verify_passed(result: Result<(), oxicrypt_module::Error>) -> Result<bool, DispatchError> {
    match result {
        Ok(()) => Ok(true),
        Err(oxicrypt_module::Error::InvalidInput) => Ok(false),
        Err(other) => Err(DispatchError::Module(other)),
    }
}

/// sigVer through the public `verify`, FIPS 204 §5.3 Algorithm 3,
/// with the vector's message and context. A signature of the wrong
/// length grades `testPassed: false`, as on the internal interface.
fn ml_dsa_sig_ver_external(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let (tg_id, parameter_set, tests) = read_aft_group(group)?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let test_case_id = read_tc_id(t)?;
        let pk_bytes = read_hex(t, "pk")?;
        let message = read_hex(t, "message")?;
        let sig_bytes = read_hex(t, "signature")?;
        let context = read_context(t)?;

        let passed = match parameter_set {
            "ML-DSA-44" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_44::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-44 SigVer: pk has wrong length")
                    })?;
                match <[u8; oxicrypt_ml_dsa::ml_dsa_44::SIG_LEN]>::try_from(sig_bytes.as_slice()) {
                    Ok(sig) => verify_passed(oxicrypt_ml_dsa::ml_dsa_44::verify(
                        &pk, &message, &context, &sig,
                    ))?,
                    Err(_) => false,
                }
            }
            "ML-DSA-65" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_65::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-65 SigVer: pk has wrong length")
                    })?;
                match <[u8; oxicrypt_ml_dsa::ml_dsa_65::SIG_LEN]>::try_from(sig_bytes.as_slice()) {
                    Ok(sig) => verify_passed(oxicrypt_ml_dsa::ml_dsa_65::verify(
                        &pk, &message, &context, &sig,
                    ))?,
                    Err(_) => false,
                }
            }
            "ML-DSA-87" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_87::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-87 SigVer: pk has wrong length")
                    })?;
                match <[u8; oxicrypt_ml_dsa::ml_dsa_87::SIG_LEN]>::try_from(sig_bytes.as_slice()) {
                    Ok(sig) => verify_passed(oxicrypt_ml_dsa::ml_dsa_87::verify(
                        &pk, &message, &context, &sig,
                    ))?,
                    Err(_) => false,
                }
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("testPassed".to_string(), JsonValue::Bool(passed)),
        ]));
    }
    Ok(group_response(tg_id, results))
}

/// sigGen through `sign_internal`, FIPS 204 §6.2 Algorithm 7, with
/// `M'` equal to the vector's message and `rnd` 32 zero bytes.
fn ml_dsa_sig_gen_internal(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    // `sk` is per-test per `draft-celi-acvp-ml-dsa §8.2.2` Table 14.
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

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
            "ML-DSA-44" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_44::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-44 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_44::sign_internal(&sk, &message, &[0u8; 32])
                    .map_err(primitive_err("ML-DSA-44 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            "ML-DSA-65" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_65::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-65 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_65::sign_internal(&sk, &message, &[0u8; 32])
                    .map_err(primitive_err("ML-DSA-65 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
            "ML-DSA-87" => {
                let sk: [u8; oxicrypt_ml_dsa::ml_dsa_87::SK_LEN] =
                    sk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-87 SigGen: sk has wrong length")
                    })?;
                let sig = oxicrypt_ml_dsa::ml_dsa_87::sign_internal(&sk, &message, &[0u8; 32])
                    .map_err(primitive_err("ML-DSA-87 SigGen: signing failed"))?;
                hex::encode_upper(&sig)
            }
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

/// sigVer through `verify_internal`, FIPS 204 §6.3 Algorithm 8.
fn ml_dsa_sig_ver_internal(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

    // Per `draft-celi-acvp-ml-dsa §8.3.2` Table 16, `pk`, `message`,
    // and `signature` are all per-test fields.
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

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

        // PK_LEN and SIG_LEN per FIPS 204 §4 Table 2. A wrong-length
        // pk is a harness error; a wrong-length signature is one the
        // verifier rejects, so it grades testPassed: false.
        let passed = match parameter_set {
            "ML-DSA-44" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_44::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-44 SigVer: pk has wrong length")
                    })?;
                if let Ok(sig) =
                    <[u8; oxicrypt_ml_dsa::ml_dsa_44::SIG_LEN]>::try_from(sig_bytes.as_slice())
                {
                    oxicrypt_ml_dsa::ml_dsa_44::verify_internal(&pk, &message, &sig)?
                } else {
                    false
                }
            }
            "ML-DSA-65" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_65::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-65 SigVer: pk has wrong length")
                    })?;
                if let Ok(sig) =
                    <[u8; oxicrypt_ml_dsa::ml_dsa_65::SIG_LEN]>::try_from(sig_bytes.as_slice())
                {
                    oxicrypt_ml_dsa::ml_dsa_65::verify_internal(&pk, &message, &sig)?
                } else {
                    false
                }
            }
            "ML-DSA-87" => {
                let pk: [u8; oxicrypt_ml_dsa::ml_dsa_87::PK_LEN] =
                    pk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-DSA-87 SigVer: pk has wrong length")
                    })?;
                if let Ok(sig) =
                    <[u8; oxicrypt_ml_dsa::ml_dsa_87::SIG_LEN]>::try_from(sig_bytes.as_slice())
                {
                    oxicrypt_ml_dsa::ml_dsa_87::verify_internal(&pk, &message, &sig)?
                } else {
                    false
                }
            }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::json;

    /// ACVP-Server commit 112690e8, `ML-DSA-sigGen-FIPS204`
    /// `internalProjection.json` tgId 5 tcId 73: ML-DSA-87, external
    /// interface, `preHash: "pure"`, deterministic, empty context.
    const SIG_GEN_EXTERNAL_SLICE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vendor/nist/acvp-server/gen-val/json-files/ML-DSA-sigGen-FIPS204/kat-slice.json"
    ));

    /// ACVP-Server commit 112690e8, `ML-DSA-sigVer-FIPS204`
    /// `internalProjection.json` tgId 5: ML-DSA-87, external interface,
    /// `preHash: "pure"`. tcId 62 (empty context) and tcId 72 (255-byte
    /// context) expect `false`, tcId 73 (178-byte context) `true`.
    const SIG_VER_EXTERNAL_SLICE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vendor/nist/acvp-server/gen-val/json-files/ML-DSA-sigVer-FIPS204/external-sigver-slice.json"
    ));

    /// ACVP-Server commit 3611942e, `ML-DSA-sigGen-FIPS204`
    /// `internalProjection.json` tgId 12 tcId 177: ML-DSA-87, internal
    /// interface, `externalMu: false`, deterministic.
    const SIG_GEN_INTERNAL_SLICE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vendor/nist/acvp-server/gen-val/json-files/ML-DSA-sigGen-FIPS204/cast-slice.json"
    ));

    /// ACVP-Server commit 3611942e, `ML-DSA-sigVer-FIPS204`
    /// `internalProjection.json` tgId 12 tcId 174: ML-DSA-87, internal
    /// interface, `externalMu: false`, expecting `true`.
    const SIG_VER_INTERNAL_SLICE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vendor/nist/acvp-server/gen-val/json-files/ML-DSA-sigVer-FIPS204/cast-slice.json"
    ));

    fn string(s: &str) -> JsonValue {
        JsonValue::String(s.to_string())
    }

    fn slice_group(slice: &str) -> JsonValue {
        let slice = json::parse(slice).unwrap();
        let groups = slice
            .get("testGroups")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(groups.len(), 1);
        groups[0].clone()
    }

    fn cases(v: &JsonValue) -> &[JsonValue] {
        v.get("tests").and_then(JsonValue::as_array).unwrap()
    }

    fn replay(handler: &dyn AlgorithmHandler, group: &JsonValue) -> Vec<(JsonValue, JsonValue)> {
        let response = handler.handle_group(group).unwrap();
        assert_eq!(
            response.get("tgId").and_then(JsonValue::as_i64),
            group.get("tgId").and_then(JsonValue::as_i64)
        );
        let expected = cases(group);
        let got = cases(&response);
        assert_eq!(got.len(), expected.len());
        for (g, e) in got.iter().zip(expected) {
            assert_eq!(
                g.get("tcId").and_then(JsonValue::as_i64),
                e.get("tcId").and_then(JsonValue::as_i64)
            );
        }
        expected.iter().cloned().zip(got.iter().cloned()).collect()
    }

    /// `fields` with `key` set to `value`. The key must already be
    /// present, so a fixture cannot silently add a field it meant to
    /// replace.
    fn with(
        mut fields: Vec<(&'static str, JsonValue)>,
        key: &str,
        value: JsonValue,
    ) -> Vec<(&'static str, JsonValue)> {
        let slot = fields.iter_mut().find(|(k, _)| *k == key).unwrap();
        slot.1 = value;
        fields
    }

    /// `fields` without `key`, which must be present.
    fn without(
        mut fields: Vec<(&'static str, JsonValue)>,
        key: &str,
    ) -> Vec<(&'static str, JsonValue)> {
        let before = fields.len();
        fields.retain(|(k, _)| *k != key);
        assert_eq!(fields.len(), before - 1);
        fields
    }

    fn refusal(handler: &dyn AlgorithmHandler, prompt: &JsonValue) -> String {
        match handler.handle_group(prompt) {
            Ok(_) => panic!("the group was answered, not refused"),
            Err(e) => e.to_string(),
        }
    }

    fn group(mode_fields: Vec<(&str, JsonValue)>, test: Vec<(&str, JsonValue)>) -> JsonValue {
        let mut fields = vec![
            ("tgId".to_string(), JsonValue::Number(1)),
            ("testType".to_string(), string("AFT")),
        ];
        fields.extend(mode_fields.into_iter().map(|(k, v)| (k.to_string(), v)));
        let mut case = vec![("tcId".to_string(), JsonValue::Number(1))];
        case.extend(test.into_iter().map(|(k, v)| (k.to_string(), v)));
        fields.push((
            "tests".to_string(),
            JsonValue::Array(vec![JsonValue::Object(case)]),
        ));
        JsonValue::Object(fields)
    }

    fn external_fields(parameter_set: &str) -> Vec<(&'static str, JsonValue)> {
        vec![
            ("parameterSet", string(parameter_set)),
            ("signatureInterface", string("external")),
            ("preHash", string("pure")),
            ("deterministic", JsonValue::Bool(true)),
        ]
    }

    fn internal_fields(parameter_set: &str) -> Vec<(&'static str, JsonValue)> {
        vec![
            ("parameterSet", string(parameter_set)),
            ("signatureInterface", string("internal")),
            ("externalMu", JsonValue::Bool(false)),
            ("deterministic", JsonValue::Bool(true)),
        ]
    }

    fn only_test(response: &JsonValue) -> &JsonValue {
        let tests = response.get("tests").and_then(JsonValue::as_array).unwrap();
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0].get("tcId").and_then(JsonValue::as_i64), Some(1));
        &tests[0]
    }

    fn sign_external(sk: &[u8], message: &[u8], context: &[u8]) -> String {
        let prompt = group(
            external_fields("ML-DSA-44"),
            vec![
                ("sk", string(&hex::encode_upper(sk))),
                ("message", string(&hex::encode_upper(message))),
                ("context", string(&hex::encode_upper(context))),
            ],
        );
        let response = MlDsaSigGenHandler.handle_group(&prompt).unwrap();
        only_test(&response)
            .get("signature")
            .and_then(JsonValue::as_str)
            .unwrap()
            .to_string()
    }

    fn verify_external(pk: &[u8], message: &[u8], context: &[u8], signature: &str) -> bool {
        let prompt = group(
            external_fields("ML-DSA-44"),
            vec![
                ("pk", string(&hex::encode_upper(pk))),
                ("message", string(&hex::encode_upper(message))),
                ("context", string(&hex::encode_upper(context))),
                ("signature", string(signature)),
            ],
        );
        let response = MlDsaSigVerHandler.handle_group(&prompt).unwrap();
        only_test(&response)
            .get("testPassed")
            .and_then(JsonValue::as_bool)
            .unwrap()
    }

    fn str_field<'a>(v: &'a JsonValue, name: &str) -> &'a str {
        v.get(name).and_then(JsonValue::as_str).unwrap()
    }

    #[test]
    fn sig_gen_external_reproduces_nist_vector() {
        crate::ensure_initialized().unwrap();
        let group = slice_group(SIG_GEN_EXTERNAL_SLICE);
        assert_eq!(group.get("tgId").and_then(JsonValue::as_i64), Some(5));
        assert_eq!(str_field(&group, "signatureInterface"), "external");
        let pairs = replay(&MlDsaSigGenHandler, &group);
        assert_eq!(pairs.len(), 1);
        let (expected, got) = &pairs[0];
        assert_eq!(expected.get("tcId").and_then(JsonValue::as_i64), Some(73));
        assert_eq!(str_field(expected, "context"), "");
        assert_eq!(
            str_field(got, "signature"),
            str_field(expected, "signature")
        );
    }

    #[test]
    fn sig_ver_external_reproduces_nist_vectors() {
        crate::ensure_initialized().unwrap();
        let group = slice_group(SIG_VER_EXTERNAL_SLICE);
        assert_eq!(group.get("tgId").and_then(JsonValue::as_i64), Some(5));
        assert_eq!(str_field(&group, "parameterSet"), "ML-DSA-87");
        let pairs = replay(&MlDsaSigVerHandler, &group);
        let mut verdicts = Vec::new();
        let mut context_lengths = Vec::new();
        for (expected, got) in &pairs {
            assert_eq!(
                hex::decode(str_field(expected, "signature")).unwrap().len(),
                oxicrypt_ml_dsa::ml_dsa_87::SIG_LEN
            );
            context_lengths.push(hex::decode(str_field(expected, "context")).unwrap().len());
            let want = expected
                .get("testPassed")
                .and_then(JsonValue::as_bool)
                .unwrap();
            assert_eq!(
                got.get("testPassed").and_then(JsonValue::as_bool),
                Some(want)
            );
            verdicts.push(want);
        }
        assert_eq!(context_lengths, [0, 255, 178]);
        assert_eq!(verdicts, [false, false, true]);
    }

    #[test]
    fn internal_groups_reproduce_nist_vectors() {
        crate::ensure_initialized().unwrap();
        let sig_gen = slice_group(SIG_GEN_INTERNAL_SLICE);
        assert_eq!(str_field(&sig_gen, "signatureInterface"), "internal");
        let pairs = replay(&MlDsaSigGenHandler, &sig_gen);
        assert_eq!(pairs.len(), 1);
        let (expected, got) = &pairs[0];
        assert_eq!(
            str_field(got, "signature"),
            str_field(expected, "signature")
        );

        let sig_ver = slice_group(SIG_VER_INTERNAL_SLICE);
        assert_eq!(str_field(&sig_ver, "signatureInterface"), "internal");
        let pairs = replay(&MlDsaSigVerHandler, &sig_ver);
        assert_eq!(pairs.len(), 1);
        let (expected, got) = &pairs[0];
        assert_eq!(
            expected.get("testPassed").and_then(JsonValue::as_bool),
            Some(true)
        );
        assert_eq!(
            got.get("testPassed").and_then(JsonValue::as_bool),
            Some(true)
        );
    }

    #[test]
    fn external_round_trip_verifies_and_rejects_tampering() {
        crate::ensure_initialized().unwrap();
        let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_44::keygen_internal(&[7u8; 32]).unwrap();
        let message = b"external interface round trip";
        let context = [0xA5u8; 255];

        let signature = sign_external(&sk, message, &context);
        let sig_bytes = hex::decode(&signature).unwrap();
        assert_eq!(sig_bytes.len(), oxicrypt_ml_dsa::ml_dsa_44::SIG_LEN);
        assert!(verify_external(&pk, message, &context, &signature));

        let mut flipped = sig_bytes.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_external(
            &pk,
            message,
            &context,
            &hex::encode_upper(&flipped)
        ));

        assert!(!verify_external(&pk, message, &context[..254], &signature));
        assert!(!verify_external(
            &pk,
            message,
            &context,
            &signature[..signature.len() - 2]
        ));
    }

    fn sig_gen_case(sk: &[u8]) -> Vec<(&'static str, JsonValue)> {
        vec![
            ("sk", string(&hex::encode_upper(sk))),
            ("message", string("00")),
            ("context", string("")),
        ]
    }

    fn sig_ver_case(pk: &[u8], sk: &[u8]) -> Vec<(&'static str, JsonValue)> {
        let signature =
            oxicrypt_ml_dsa::ml_dsa_44::sign(sk.try_into().unwrap(), &[0], &[]).unwrap();
        vec![
            ("pk", string(&hex::encode_upper(pk))),
            ("message", string("00")),
            ("context", string("")),
            ("signature", string(&hex::encode_upper(&signature))),
        ]
    }

    #[test]
    fn external_context_over_255_bytes_is_refused() {
        crate::ensure_initialized().unwrap();
        let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_44::keygen_internal(&[7u8; 32]).unwrap();
        let context = string(&hex::encode_upper(&[0u8; 256]));
        let refused = "unsupported: ML-DSA: context is longer than 255 bytes";
        let sign = group(
            external_fields("ML-DSA-44"),
            with(sig_gen_case(&sk), "context", context.clone()),
        );
        assert_eq!(refusal(&MlDsaSigGenHandler, &sign), refused);
        let verify = group(
            external_fields("ML-DSA-44"),
            with(sig_ver_case(&pk, &sk), "context", context),
        );
        assert_eq!(refusal(&MlDsaSigVerHandler, &verify), refused);
    }

    #[test]
    fn external_context_must_be_a_present_string() {
        crate::ensure_initialized().unwrap();
        let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_44::keygen_internal(&[7u8; 32]).unwrap();
        let fields = || external_fields("ML-DSA-44");
        for (handler, case) in [
            (
                &MlDsaSigGenHandler as &dyn AlgorithmHandler,
                sig_gen_case(&sk),
            ),
            (&MlDsaSigVerHandler, sig_ver_case(&pk, &sk)),
        ] {
            assert!(handler.handle_group(&group(fields(), case.clone())).is_ok());
            assert_eq!(
                refusal(handler, &group(fields(), without(case.clone(), "context"))),
                "missing field \"context\""
            );
            assert_eq!(
                refusal(
                    handler,
                    &group(fields(), with(case, "context", JsonValue::Null))
                ),
                "crypto: ML-DSA: context is not a hex string"
            );
        }
    }

    #[test]
    fn sig_gen_refuses_unregistered_groups() {
        crate::ensure_initialized().unwrap();
        let (_, sk) = oxicrypt_ml_dsa::ml_dsa_44::keygen_internal(&[7u8; 32]).unwrap();
        let external = || external_fields("ML-DSA-44");
        let internal = || internal_fields("ML-DSA-44");
        let mut with_rnd = sig_gen_case(&sk);
        with_rnd.push(("rnd", string(&hex::encode_upper(&[0u8; 32]))));
        let mut seed_format = external();
        seed_format.push(("keyFormat", string("seed")));
        let mut expanded_format = external();
        expanded_format.push(("keyFormat", string("expanded")));
        let mut internal_pre_hash = internal();
        internal_pre_hash.push(("preHash", string("pure")));
        let mut internal_no_pre_hash = internal();
        internal_no_pre_hash.push(("preHash", string("none")));

        for (fields, case) in [
            (external(), sig_gen_case(&sk)),
            (expanded_format, sig_gen_case(&sk)),
            (internal(), without(sig_gen_case(&sk), "context")),
            (internal_no_pre_hash, without(sig_gen_case(&sk), "context")),
        ] {
            assert!(
                MlDsaSigGenHandler
                    .handle_group(&group(fields, case))
                    .is_ok()
            );
        }

        for (fields, case, refused) in [
            (
                with(external(), "deterministic", JsonValue::Bool(false)),
                sig_gen_case(&sk),
                "unsupported: ML-DSA SigGen: only `deterministic: true` is registered",
            ),
            (
                external(),
                with_rnd,
                "unsupported: ML-DSA SigGen: `rnd` is not accepted; only `deterministic: true` is registered",
            ),
            (
                seed_format,
                sig_gen_case(&sk),
                "unsupported: ML-DSA SigGen: `keyFormat: seed` is not registered",
            ),
            (
                with(external(), "preHash", string("preHash")),
                sig_gen_case(&sk),
                "unsupported: ML-DSA: preHash must be `pure`; HashML-DSA is not registered",
            ),
            (
                without(external(), "signatureInterface"),
                sig_gen_case(&sk),
                "missing field \"signatureInterface\"",
            ),
            (
                internal_pre_hash,
                without(sig_gen_case(&sk), "context"),
                "unsupported: ML-DSA: an internal group takes no `preHash`",
            ),
            (
                with(internal(), "externalMu", JsonValue::Bool(true)),
                without(sig_gen_case(&sk), "context"),
                "unsupported: ML-DSA: only `externalMu: false` is registered",
            ),
        ] {
            assert_eq!(refusal(&MlDsaSigGenHandler, &group(fields, case)), refused);
        }
    }

    #[test]
    fn sig_ver_refuses_unregistered_groups() {
        crate::ensure_initialized().unwrap();
        let (pk, sk) = oxicrypt_ml_dsa::ml_dsa_44::keygen_internal(&[7u8; 32]).unwrap();
        let external = || without(external_fields("ML-DSA-44"), "deterministic");
        let internal = || without(internal_fields("ML-DSA-44"), "deterministic");
        let internal_case = || without(sig_ver_case(&pk, &sk), "context");
        let mut internal_pre_hash = internal();
        internal_pre_hash.push(("preHash", string("pure")));

        assert!(
            MlDsaSigVerHandler
                .handle_group(&group(external(), sig_ver_case(&pk, &sk)))
                .is_ok()
        );
        assert!(
            MlDsaSigVerHandler
                .handle_group(&group(internal(), internal_case()))
                .is_ok()
        );

        for (fields, case, refused) in [
            (
                with(external(), "preHash", string("preHash")),
                sig_ver_case(&pk, &sk),
                "unsupported: ML-DSA: preHash must be `pure`; HashML-DSA is not registered",
            ),
            (
                without(external(), "signatureInterface"),
                sig_ver_case(&pk, &sk),
                "missing field \"signatureInterface\"",
            ),
            (
                internal_pre_hash,
                internal_case(),
                "unsupported: ML-DSA: an internal group takes no `preHash`",
            ),
            (
                with(internal(), "externalMu", JsonValue::Bool(true)),
                internal_case(),
                "unsupported: ML-DSA: only `externalMu: false` is registered",
            ),
        ] {
            assert_eq!(refusal(&MlDsaSigVerHandler, &group(fields, case)), refused);
        }
    }
}
