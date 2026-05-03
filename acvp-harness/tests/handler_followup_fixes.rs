//! Regression tests for two ACVP handler-layer follow-ups deferred from
//! the 2026-04-28 caps.rs sweep:
//!
//! 1. `ctrDRBG` no-df non-PR generate path must pad/truncate the
//!    additional_input to seed_len per SP 800-90A §10.2.1.5.1 step 2.1
//!    before calling upstream `oxicrypt_drbg::ctr::generate_no_df`,
//!    which strictly requires `additional_input.len() == F::SEED_LEN`.
//! 2. `KDA-HKDF-Sp800-56Cr2` handler must accept `testType=VAL` groups
//!    in addition to `AFT`. VAL groups carry a candidate `dkm` per test;
//!    the response shape is `{tcId, testPassed: <bool>}`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use acvp_harness::{dispatch, ensure_initialized, hex, json, json::JsonValue};

fn parse(text: &str) -> JsonValue {
    json::parse(text).unwrap_or_else(|e| panic!("parse: {e}"))
}

fn dispatch_ok(prompt: &JsonValue) -> JsonValue {
    let registry = dispatch::with_default_handlers();
    dispatch::process(prompt, &registry).unwrap_or_else(|e| panic!("dispatch: {e}"))
}

fn first_test(group: &JsonValue) -> &JsonValue {
    &group.get("tests").and_then(JsonValue::as_array).unwrap()[0]
}

// ── ctrDRBG: non-seedlen additional_input on no-df non-PR generate ──

/// SP 800-90A §10.2.1.5.1 step 2.1: `additional_input = leftmost(
/// additional_input || 0^seedlen, seedlen)`. ACVP supplies arbitrary
/// `additionalInputLen`; the handler must pad short inputs with zeros
/// and truncate long inputs before calling upstream `generate_no_df`.
///
/// Pre-fix: this prompt produces `crypto: ctrDRBG: generate_no_df failed`
/// because upstream `oxicrypt_drbg::ctr::generate_no_df` returns
/// `InvalidSeedLength` when `additional_input.len() != F::SEED_LEN`.
#[test]
fn ctrdrbg_no_df_non_pr_short_additional_input_dispatches() {
    ensure_initialized().unwrap();

    // AES-128 → seed_len 32; entropy & perso each at seed_len; addl 1 byte.
    let prompt = parse(
        r#"{
            "algorithm": "ctrDRBG",
            "revision":  "1.0",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "mode": "AES-128",
                "derFunc": false,
                "predResistance": false,
                "reSeed": false,
                "entropyInputLen": 256,
                "nonceLen": 0,
                "persoStringLen": 256,
                "additionalInputLen": 8,
                "returnedBitsLen": 256,
                "tests": [{
                    "tcId": 1,
                    "entropyInput": "C8BF102440B9FCE44C7B6314AED835D13D6BB5ABAF17358727F4FC6EBC1F6C24",
                    "nonce": "",
                    "persoString": "7602B34371D7D3F1C03ED9FE8235D5730EDFC8755EE92E88887EEF05749329FA",
                    "otherInput": [
                        {"intendedUse": "generate", "additionalInput": "21", "entropyInput": ""}
                    ]
                }]
            }]
        }"#,
    );

    let response = dispatch_ok(&prompt);
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(groups.len(), 1);
    let returned = first_test(&groups[0])
        .get("returnedBits")
        .and_then(JsonValue::as_str)
        .unwrap();
    // 256 bits = 64 hex chars
    assert_eq!(returned.len(), 64);
}

/// Same arm, additional_input *longer* than seed_len. Spec says
/// `leftmost(addl || 0^seedlen, seedlen)` — equivalent to truncation
/// when addl is already longer than seedlen.
#[test]
fn ctrdrbg_no_df_non_pr_long_additional_input_dispatches() {
    ensure_initialized().unwrap();

    // AES-128 again, addl = 64 bytes (twice seed_len).
    let addl = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899\
                AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
    let prompt_text = format!(
        r#"{{
            "algorithm": "ctrDRBG",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": 1,
                "testType": "AFT",
                "mode": "AES-128",
                "derFunc": false,
                "predResistance": false,
                "reSeed": false,
                "entropyInputLen": 256,
                "nonceLen": 0,
                "persoStringLen": 256,
                "additionalInputLen": 512,
                "returnedBitsLen": 256,
                "tests": [{{
                    "tcId": 1,
                    "entropyInput": "C8BF102440B9FCE44C7B6314AED835D13D6BB5ABAF17358727F4FC6EBC1F6C24",
                    "nonce": "",
                    "persoString": "7602B34371D7D3F1C03ED9FE8235D5730EDFC8755EE92E88887EEF05749329FA",
                    "otherInput": [
                        {{"intendedUse": "generate", "additionalInput": "{addl}", "entropyInput": ""}}
                    ]
                }}]
            }}]
        }}"#
    );
    let prompt = parse(&prompt_text);
    let response = dispatch_ok(&prompt);
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(groups.len(), 1);
}

// ── KDA-HKDF VAL ────────────────────────────────────────────────────

use oxicrypt_kdf::HkdfSha256;

/// Compute the expected OKM that the handler should produce for the
/// fixed test fixture below — the same encoding the AFT path emits as
/// `dkm`. Used to plant a correct candidate `dkm` for VAL=true cases
/// and to derive a corrupted candidate for VAL=false cases.
fn expected_okm() -> Vec<u8> {
    // Matches the test fixture: salt = AB CD EF 01, z = 11 22 33 ... 88.
    let salt = [0xAB, 0xCD, 0xEF, 0x01];
    let z = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    // fixedInfo = partyU.partyId || partyV.partyId || u32_be(l_bits)
    // partyU.partyId = "AAAA" (hex) = 0xAA 0xAA, partyV = "BBBB" = 0xBB 0xBB
    let mut fixed_info = vec![0xAA, 0xAA, 0xBB, 0xBB];
    fixed_info.extend_from_slice(&256u32.to_be_bytes());
    let prk = HkdfSha256::extract(Some(&salt), &z).unwrap();
    let mut okm = vec![0u8; 32];
    prk.expand(&fixed_info, &mut okm).unwrap();
    okm
}

fn kda_hkdf_val_prompt(candidate_dkm_hex: &str) -> JsonValue {
    let prompt_text = format!(
        r#"{{
            "algorithm": "KDA",
            "mode":      "HKDF",
            "revision":  "Sp800-56Cr2",
            "testGroups": [{{
                "tgId": 1,
                "testType": "VAL",
                "kdfConfiguration": {{
                    "kdfType":           "hkdf",
                    "fixedInfoEncoding": "concatenation",
                    "fixedInfoPattern":  "uPartyInfo||vPartyInfo||l",
                    "hmacAlg":           "SHA2-256",
                    "l":                 256
                }},
                "usesHybridSharedSecret": false,
                "tests": [{{
                    "tcId": 1,
                    "kdfParameter": {{
                        "kdfType": "hkdf",
                        "salt":    "ABCDEF01",
                        "z":       "1122334455667788",
                        "l":       256
                    }},
                    "fixedInfoPartyU": {{ "partyId": "AAAA" }},
                    "fixedInfoPartyV": {{ "partyId": "BBBB" }},
                    "dkm":             "{candidate_dkm_hex}"
                }}]
            }}]
        }}"#
    );
    parse(&prompt_text)
}

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

#[test]
fn kda_hkdf_val_correct_candidate_passes() {
    ensure_initialized().unwrap();
    let okm_hex = hex_upper(&expected_okm());
    let response = dispatch_ok(&kda_hkdf_val_prompt(&okm_hex));
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let test = first_test(&groups[0]);
    assert!(test.get("dkm").is_none(), "VAL response must not echo dkm");
    assert_eq!(
        test.get("testPassed").and_then(JsonValue::as_bool),
        Some(true)
    );
}

#[test]
fn kda_hkdf_val_corrupted_candidate_fails() {
    ensure_initialized().unwrap();
    let mut okm = expected_okm();
    okm[0] ^= 0xFF;
    let response = dispatch_ok(&kda_hkdf_val_prompt(&hex_upper(&okm)));
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let test = first_test(&groups[0]);
    assert_eq!(
        test.get("testPassed").and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn kda_hkdf_val_length_mismatched_candidate_does_not_panic() {
    // Truncate the candidate: 31 bytes instead of 32. Handler must
    // return testPassed=false cleanly, not panic.
    ensure_initialized().unwrap();
    let mut okm = expected_okm();
    okm.pop();
    let response = dispatch_ok(&kda_hkdf_val_prompt(&hex_upper(&okm)));
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let test = first_test(&groups[0]);
    assert_eq!(
        test.get("testPassed").and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn kda_hkdf_aft_response_shape_unchanged() {
    // Same fixture but testType=AFT — must emit dkm hex, not testPassed.
    ensure_initialized().unwrap();
    let prompt = parse(
        r#"{
            "algorithm": "KDA",
            "mode":      "HKDF",
            "revision":  "Sp800-56Cr2",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "kdfConfiguration": {
                    "kdfType":           "hkdf",
                    "fixedInfoEncoding": "concatenation",
                    "fixedInfoPattern":  "uPartyInfo||vPartyInfo||l",
                    "hmacAlg":           "SHA2-256",
                    "l":                 256
                },
                "usesHybridSharedSecret": false,
                "tests": [{
                    "tcId": 1,
                    "kdfParameter": {
                        "kdfType": "hkdf",
                        "salt":    "ABCDEF01",
                        "z":       "1122334455667788",
                        "l":       256
                    },
                    "fixedInfoPartyU": { "partyId": "AAAA" },
                    "fixedInfoPartyV": { "partyId": "BBBB" }
                }]
            }]
        }"#,
    );
    let response = dispatch_ok(&prompt);
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let test = first_test(&groups[0]);
    assert!(
        test.get("testPassed").is_none(),
        "AFT response must not include testPassed"
    );
    let dkm = test.get("dkm").and_then(JsonValue::as_str).unwrap();
    assert_eq!(dkm, hex_upper(&expected_okm()));
}
