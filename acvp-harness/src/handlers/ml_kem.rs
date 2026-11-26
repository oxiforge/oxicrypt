//! ML-KEM ACVP handlers — `keyGen` and `encapDecap` modes per FIPS 203.
//!
//! Two handlers, mirroring the catalog's two-mode shape
//! (see `draft-celi-acvp-ml-kem §7.3.1` and `§7.3.2`):
//!
//! - **`MlKemKeyGenHandler`** — `ML-KEM` / `keyGen` / `FIPS203`,
//!   advertising `parameterSets: ["ML-KEM-512", "ML-KEM-768",
//!   "ML-KEM-1024"]`. Generates a (encapsulation key, decapsulation
//!   key) pair from server-supplied `d` and `z` seeds. Per-group
//!   `parameterSet` field selects the variant (k=2/3/4).
//! - **`MlKemEncapDecapHandler`** — `ML-KEM` / `encapDecap` /
//!   `FIPS203`, advertising the same three parameter sets and
//!   `functions: ["encapsulation", "decapsulation",
//!   "encapsulationKeyCheck", "decapsulationKeyCheck"]`. Group-level
//!   `function` field selects the driver; group-level `parameterSet`
//!   field selects k.
//!
//! All three FIPS 203 parameter sets are supported. The `algorithm()`
//! value is the family name `"ML-KEM"`. A new parameter set needs a
//! cap entry and a match arm in each group driver, but no new handler
//! struct.

use crate::dispatch::{AlgorithmHandler, DispatchError, primitive_err};
use crate::hex;
use crate::json::JsonValue;

/// ML-KEM keyGen dispatcher
/// (`parameterSets: ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]`).
pub struct MlKemKeyGenHandler;

impl AlgorithmHandler for MlKemKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "ML-KEM"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS203"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_kem_keygen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

/// ML-KEM encapDecap dispatcher
/// (`parameterSets: ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]`,
/// `functions: ["encapsulation", "decapsulation",
/// "encapsulationKeyCheck", "decapsulationKeyCheck"]`).
///
/// Per `draft-celi-acvp-ml-kem §8.2.1`, each prompt group within an
/// encapDecap vector set is tagged with a `function` field; this
/// handler dispatches to the group driver for that function, and then
/// per-variant on `parameterSet`.
pub struct MlKemEncapDecapHandler;

impl AlgorithmHandler for MlKemEncapDecapHandler {
    fn algorithm(&self) -> &'static str {
        "ML-KEM"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("encapDecap")
    }
    fn revision(&self) -> &'static str {
        "FIPS203"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::ml_kem_encapdecap_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        let function = group
            .get("function")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("function"))?;
        match function {
            "encapsulation" => handle_encaps_group(group),
            "decapsulation" => handle_decaps_group(group),
            "encapsulationKeyCheck" => handle_ek_check_group(group),
            "decapsulationKeyCheck" => handle_dk_check_group(group),
            _ => Err(DispatchError::Unsupported(
                "ML-KEM encapDecap: function must be `encapsulation`, `decapsulation`, \
                 `encapsulationKeyCheck` or `decapsulationKeyCheck`",
            )),
        }
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
        "ML-KEM: parameterSet must be `ML-KEM-512`, `ML-KEM-768`, or `ML-KEM-1024`",
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

        let d_bytes = hex::decode(
            t.get("d")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("d"))?,
        )?;
        let d: [u8; 32] = d_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM KeyGen: d is not 32 bytes"))?;

        let z_bytes = hex::decode(
            t.get("z")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("z"))?,
        )?;
        let z: [u8; 32] = z_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM KeyGen: z is not 32 bytes"))?;

        let (ek_hex, dk_hex) = match parameter_set {
            "ML-KEM-512" => {
                let (ek, dk) = oxicrypt_ml_kem::ml_kem_512::keygen_internal(&d, &z)
                    .map_err(primitive_err("ML-KEM-512 KeyGen failed"))?;
                (hex::encode_upper(&ek), hex::encode_upper(&dk))
            }
            "ML-KEM-768" => {
                let (ek, dk) = oxicrypt_ml_kem::ml_kem_768::keygen_internal(&d, &z)
                    .map_err(primitive_err("ML-KEM-768 KeyGen failed"))?;
                (hex::encode_upper(&ek), hex::encode_upper(&dk))
            }
            "ML-KEM-1024" => {
                let (ek, dk) = oxicrypt_ml_kem::ml_kem_1024::keygen_internal(&d, &z)
                    .map_err(primitive_err("ML-KEM-1024 KeyGen failed"))?;
                (hex::encode_upper(&ek), hex::encode_upper(&dk))
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("ek".to_string(), JsonValue::String(ek_hex)),
            ("dk".to_string(), JsonValue::String(dk_hex)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

fn handle_encaps_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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

        let ek_bytes = hex::decode(
            t.get("ek")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("ek"))?,
        )?;

        let m_bytes = hex::decode(
            t.get("m")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("m"))?,
        )?;
        let m: [u8; 32] = m_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("ML-KEM Encaps: m is not 32 bytes"))?;

        let (k_hex, c_hex) = match parameter_set {
            "ML-KEM-512" => {
                let ek: [u8; 800] = ek_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("ML-KEM-512 Encaps: ek is not 800 bytes"))?;
                let (ss, ct) = oxicrypt_ml_kem::ml_kem_512::encaps_internal(&ek, &m)?;
                (hex::encode_upper(&ss), hex::encode_upper(&ct))
            }
            "ML-KEM-768" => {
                let ek: [u8; 1184] = ek_bytes.as_slice().try_into().map_err(|_| {
                    DispatchError::Crypto("ML-KEM-768 Encaps: ek is not 1184 bytes")
                })?;
                let (ss, ct) = oxicrypt_ml_kem::ml_kem_768::encaps_internal(&ek, &m)?;
                (hex::encode_upper(&ss), hex::encode_upper(&ct))
            }
            "ML-KEM-1024" => {
                let ek: [u8; 1568] = ek_bytes.as_slice().try_into().map_err(|_| {
                    DispatchError::Crypto("ML-KEM-1024 Encaps: ek is not 1568 bytes")
                })?;
                let (ss, ct) = oxicrypt_ml_kem::ml_kem_1024::encaps_internal(&ek, &m)?;
                (hex::encode_upper(&ss), hex::encode_upper(&ct))
            }
            other => return Err(unsupported_parameter_set(other)),
        };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("c".to_string(), JsonValue::String(c_hex)),
            ("k".to_string(), JsonValue::String(k_hex)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

fn handle_decaps_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "VAL" {
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

        let dk_bytes = hex::decode(
            t.get("dk")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("dk"))?,
        )?;

        let c_bytes = hex::decode(
            t.get("c")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("c"))?,
        )?;

        let k_hex =
            match parameter_set {
                "ML-KEM-512" => {
                    let dk: [u8; 1632] = dk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-512 Decaps: dk is not 1632 bytes")
                    })?;
                    let c: [u8; 768] = c_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-512 Decaps: c is not 768 bytes")
                    })?;
                    let ss = oxicrypt_ml_kem::ml_kem_512::decaps_internal(&dk, &c)?;
                    hex::encode_upper(&ss)
                }
                "ML-KEM-768" => {
                    let dk: [u8; 2400] = dk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-768 Decaps: dk is not 2400 bytes")
                    })?;
                    let c: [u8; 1088] = c_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-768 Decaps: c is not 1088 bytes")
                    })?;
                    let ss = oxicrypt_ml_kem::ml_kem_768::decaps_internal(&dk, &c)?;
                    hex::encode_upper(&ss)
                }
                "ML-KEM-1024" => {
                    let dk: [u8; 3168] = dk_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-1024 Decaps: dk is not 3168 bytes")
                    })?;
                    let c: [u8; 1568] = c_bytes.as_slice().try_into().map_err(|_| {
                        DispatchError::Crypto("ML-KEM-1024 Decaps: c is not 1568 bytes")
                    })?;
                    let ss = oxicrypt_ml_kem::ml_kem_1024::decaps_internal(&dk, &c)?;
                    hex::encode_upper(&ss)
                }
                other => return Err(unsupported_parameter_set(other)),
            };

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("k".to_string(), JsonValue::String(k_hex)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

/// Runs one key-check group: `testType` `VAL`, each test case
/// carrying the key under `field` and answered with `testPassed`, as
/// in the ACVP-Server `ML-KEM-encapDecap-FIPS203` vector sets.
/// `check` returns the verdict for the parameter set and the key.
fn handle_key_check_group(
    group: &JsonValue,
    field: &'static str,
    check: fn(&str, &[u8]) -> Result<bool, DispatchError>,
) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "VAL" {
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

        let key = hex::decode(
            t.get(field)
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField(field))?,
        )?;

        let passed = check(parameter_set, &key)?;

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

fn handle_ek_check_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    handle_key_check_group(group, "ek", ek_check)
}

fn handle_dk_check_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    handle_key_check_group(group, "dk", dk_check)
}

/// The FIPS 203 §7.2 encapsulation key check. A key whose length is
/// not `384k + 32` fails the §7.2 type check, so it grades
/// `testPassed: false` without a call; the ACVP-Server key-check
/// groups include such keys. Any other key goes to the public
/// `check_encapsulation_key`, whose `Err` (the module refusing the
/// call) is a harness error, never `testPassed: false`.
fn ek_check(parameter_set: &str, ek: &[u8]) -> Result<bool, DispatchError> {
    match parameter_set {
        "ML-KEM-512" => match ek.try_into() {
            Ok(ek) => Ok(oxicrypt_ml_kem::ml_kem_512::check_encapsulation_key(ek)?),
            Err(_) => Ok(false),
        },
        "ML-KEM-768" => match ek.try_into() {
            Ok(ek) => Ok(oxicrypt_ml_kem::ml_kem_768::check_encapsulation_key(ek)?),
            Err(_) => Ok(false),
        },
        "ML-KEM-1024" => match ek.try_into() {
            Ok(ek) => Ok(oxicrypt_ml_kem::ml_kem_1024::check_encapsulation_key(ek)?),
            Err(_) => Ok(false),
        },
        other => Err(unsupported_parameter_set(other)),
    }
}

/// The FIPS 203 §7.3 decapsulation key check, with the rules of
/// [`ek_check`]: a length other than `768k + 96` fails the §7.3 type
/// check, and any other key goes to the public
/// `check_decapsulation_key`.
fn dk_check(parameter_set: &str, dk: &[u8]) -> Result<bool, DispatchError> {
    match parameter_set {
        "ML-KEM-512" => match dk.try_into() {
            Ok(dk) => Ok(oxicrypt_ml_kem::ml_kem_512::check_decapsulation_key(dk)?),
            Err(_) => Ok(false),
        },
        "ML-KEM-768" => match dk.try_into() {
            Ok(dk) => Ok(oxicrypt_ml_kem::ml_kem_768::check_decapsulation_key(dk)?),
            Err(_) => Ok(false),
        },
        "ML-KEM-1024" => match dk.try_into() {
            Ok(dk) => Ok(oxicrypt_ml_kem::ml_kem_1024::check_decapsulation_key(dk)?),
            Err(_) => Ok(false),
        },
        other => Err(unsupported_parameter_set(other)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::json;

    /// ACVP-Server commit 112690e8, `ML-KEM-encapDecap-FIPS203`
    /// `internalProjection.json`: tgId 7 (decapsulationKeyCheck) tcIds
    /// 106 and 109, tgId 8 (encapsulationKeyCheck) tcIds 116 and 117,
    /// ML-KEM-512, each case with its expected `testPassed`. tcId 109
    /// fails the hash check and tcId 117 the type check (1216 bytes). No
    /// `encapsulationKeyCheck` group at that commit has a failing key of
    /// the correct length, so
    /// `ek_check_passes_canonical_key_and_fails_coefficient_equal_to_q`
    /// is the probe of the modulus check.
    const KEY_CHECK_SLICE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vendor/nist/acvp-server/gen-val/json-files/ML-KEM-encapDecap-FIPS203/keycheck-slice.json"
    ));

    fn key_check_group(function: &str, parameter_set: &str, field: &str, key: &[u8]) -> JsonValue {
        JsonValue::Object(vec![
            ("tgId".to_string(), JsonValue::Number(1)),
            ("testType".to_string(), JsonValue::String("VAL".to_string())),
            (
                "parameterSet".to_string(),
                JsonValue::String(parameter_set.to_string()),
            ),
            (
                "function".to_string(),
                JsonValue::String(function.to_string()),
            ),
            (
                "tests".to_string(),
                JsonValue::Array(vec![JsonValue::Object(vec![
                    ("tcId".to_string(), JsonValue::Number(1)),
                    (field.to_string(), JsonValue::String(hex::encode_upper(key))),
                ])]),
            ),
        ])
    }

    fn single_test_passed(response: &JsonValue) -> bool {
        let tests = response.get("tests").and_then(JsonValue::as_array).unwrap();
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0].get("tcId").and_then(JsonValue::as_i64), Some(1));
        tests[0]
            .get("testPassed")
            .and_then(JsonValue::as_bool)
            .unwrap()
    }

    fn check(function: &str, field: &str, key: &[u8]) -> bool {
        let group = key_check_group(function, "ML-KEM-768", field, key);
        single_test_passed(&MlKemEncapDecapHandler.handle_group(&group).unwrap())
    }

    fn ml_kem_768_key_pair() -> (
        [u8; oxicrypt_ml_kem::ml_kem_768::EK_LEN],
        [u8; oxicrypt_ml_kem::ml_kem_768::DK_LEN],
    ) {
        oxicrypt_ml_kem::ml_kem_768::keygen_internal(&[1u8; 32], &[2u8; 32]).unwrap()
    }

    #[test]
    fn key_check_reproduces_nist_vectors() {
        crate::ensure_initialized().unwrap();
        let slice = json::parse(KEY_CHECK_SLICE).unwrap();
        let groups = slice
            .get("testGroups")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(groups.len(), 2);
        let mut key_lengths = Vec::new();
        for group in groups {
            let key_field = match group.get("function").and_then(JsonValue::as_str) {
                Some("decapsulationKeyCheck") => "dk",
                Some("encapsulationKeyCheck") => "ek",
                other => panic!("unexpected function {other:?}"),
            };
            for e in group.get("tests").and_then(JsonValue::as_array).unwrap() {
                let key = e.get(key_field).and_then(JsonValue::as_str).unwrap();
                key_lengths.push(hex::decode(key).unwrap().len());
            }
        }
        assert_eq!(
            key_lengths,
            [
                oxicrypt_ml_kem::ml_kem_512::DK_LEN,
                oxicrypt_ml_kem::ml_kem_512::DK_LEN,
                oxicrypt_ml_kem::ml_kem_512::EK_LEN,
                1216
            ]
        );

        let mut verdicts = Vec::new();
        for group in groups {
            let expected = group.get("tests").and_then(JsonValue::as_array).unwrap();
            let response = MlKemEncapDecapHandler.handle_group(group).unwrap();
            let got = response.get("tests").and_then(JsonValue::as_array).unwrap();
            assert_eq!(got.len(), expected.len());
            for (g, e) in got.iter().zip(expected) {
                assert_eq!(
                    g.get("tcId").and_then(JsonValue::as_i64),
                    e.get("tcId").and_then(JsonValue::as_i64)
                );
                let want = e.get("testPassed").and_then(JsonValue::as_bool).unwrap();
                assert_eq!(g.get("testPassed").and_then(JsonValue::as_bool), Some(want));
                verdicts.push(want);
            }
        }
        assert_eq!(verdicts, [true, false, true, false]);
    }

    #[test]
    fn ek_check_passes_canonical_key_and_fails_coefficient_equal_to_q() {
        crate::ensure_initialized().unwrap();
        let (mut ek, _) = ml_kem_768_key_pair();
        assert!(check("encapsulationKeyCheck", "ek", &ek));

        // Coefficient 0 of `ek` is the low 12 bits of bytes 0 and 1
        // (FIPS 203 Algorithm 5, ByteEncode_12); 3329 = 0xD01 is q.
        ek[0] = 0x01;
        ek[1] = (ek[1] & 0xF0) | 0x0D;
        assert!(!check("encapsulationKeyCheck", "ek", &ek));
    }

    #[test]
    fn dk_check_fails_flipped_hash_byte() {
        crate::ensure_initialized().unwrap();
        let (_, mut dk) = ml_kem_768_key_pair();
        assert!(check("decapsulationKeyCheck", "dk", &dk));

        // FIPS 203 §7.3: `dk` is dk_PKE (384k bytes) ‖ ek ‖ H(ek) ‖ z.
        let h_offset = 384 * 3 + oxicrypt_ml_kem::ml_kem_768::EK_LEN;
        dk[h_offset] ^= 0x01;
        assert!(!check("decapsulationKeyCheck", "dk", &dk));
    }

    #[test]
    fn key_check_wrong_length_key_fails() {
        crate::ensure_initialized().unwrap();
        let (ek, dk) = ml_kem_768_key_pair();
        assert!(!check("encapsulationKeyCheck", "ek", &ek[..800]));
        assert!(!check(
            "decapsulationKeyCheck",
            "dk",
            &[&dk[..], &[0u8]].concat()
        ));
    }
}
