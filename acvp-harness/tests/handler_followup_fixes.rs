//! Regression tests for ACVP handler-layer follow-ups:
//!
//! 1. `ctrDRBG` no-df non-PR generate pads or truncates the
//!    additional_input to seed_len before calling upstream
//!    `oxicrypt_drbg::ctr::generate_no_df`, which strictly requires
//!    `additional_input.len() == F::SEED_LEN`. The two tests below
//!    cover DISPATCH only — neither compares `returnedBits` to an
//!    expected value, so the padding direction and content are not
//!    observed here.
//! 2. `KDA-HKDF-Sp800-56Cr2` handler must accept `testType=VAL` groups
//!    in addition to `AFT`. VAL groups carry a candidate `dkm` per test;
//!    the response shape is `{tcId, testPassed: <bool>}`.
//! 3. `ECDSA` `sigGen` and `keyGen` handlers must NOT read field `d`
//!    from the prompt — both modes are FIPS 186-5 §A.2.2 generative.
//!    The IUT samples a fresh keypair via the module's DRBG-backed
//!    keygen API and reports `d` (keyGen) or `qx`/`qy` at group level
//!    plus per-test `r`/`s` (sigGen).

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
/// when addl is already longer than seedlen. This test asserts only
/// that the group dispatches; it does not read `returnedBits`, so the
/// truncation itself is not observed.
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

// ── ECDSA sigGen + keyGen "missing field d" ─────────────────────────

fn ecdsa_siggen_prompt(curve: &str, hash: &str) -> JsonValue {
    let prompt_text = format!(
        r#"{{
            "algorithm": "ECDSA",
            "mode":      "sigGen",
            "revision":  "FIPS186-5",
            "testGroups": [{{
                "tgId": 1,
                "testType":      "AFT",
                "componentTest": false,
                "curve":         "{curve}",
                "hashAlg":       "{hash}",
                "tests": [
                    {{ "tcId": 1, "message": "DEADBEEFCAFE0001" }},
                    {{ "tcId": 2, "message": "DEADBEEFCAFE0002" }}
                ]
            }}]
        }}"#
    );
    parse(&prompt_text)
}

fn ecdsa_keygen_prompt(curve: &str) -> JsonValue {
    let prompt_text = format!(
        r#"{{
            "algorithm": "ECDSA",
            "mode":      "keyGen",
            "revision":  "FIPS186-5",
            "testGroups": [{{
                "tgId": 1,
                "testType":             "AFT",
                "curve":                "{curve}",
                "secretGenerationMode": "testing candidates",
                "tests": [
                    {{ "tcId": 1 }},
                    {{ "tcId": 2 }},
                    {{ "tcId": 3 }}
                ]
            }}]
        }}"#
    );
    parse(&prompt_text)
}

#[test]
fn ecdsa_siggen_p256_dispatches_without_d_or_k() {
    ensure_initialized().unwrap();
    let response = dispatch_ok(&ecdsa_siggen_prompt("P-256", "SHA2-256"));
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(groups.len(), 1);
    let g = &groups[0];

    // Public key reported at group level (not per-test).
    let qx = g.get("qx").and_then(JsonValue::as_str).unwrap();
    let qy = g.get("qy").and_then(JsonValue::as_str).unwrap();
    assert_eq!(qx.len(), 64); // P-256 X coord = 32 bytes = 64 hex chars
    assert_eq!(qy.len(), 64);

    let tests = g.get("tests").and_then(JsonValue::as_array).unwrap();
    assert_eq!(tests.len(), 2);
    for t in tests {
        let r = t.get("r").and_then(JsonValue::as_str).unwrap();
        let s = t.get("s").and_then(JsonValue::as_str).unwrap();
        assert_eq!(r.len(), 64);
        assert_eq!(s.len(), 64);
        assert!(t.get("qx").is_none(), "sigGen must not echo qx per-test");
    }
}

#[test]
fn ecdsa_siggen_p384_dispatches_without_d_or_k() {
    ensure_initialized().unwrap();
    let response = dispatch_ok(&ecdsa_siggen_prompt("P-384", "SHA2-384"));
    let g = &response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0];
    let qx = g.get("qx").and_then(JsonValue::as_str).unwrap();
    let qy = g.get("qy").and_then(JsonValue::as_str).unwrap();
    assert_eq!(qx.len(), 96); // P-384 X coord = 48 bytes = 96 hex chars
    assert_eq!(qy.len(), 96);
}

#[test]
fn ecdsa_siggen_p256_signature_self_verifies() {
    ensure_initialized().unwrap();
    let prompt = ecdsa_siggen_prompt("P-256", "SHA2-256");
    let response = dispatch_ok(&prompt);
    let g = &response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0];

    let qx = hex::decode(g.get("qx").and_then(JsonValue::as_str).unwrap()).unwrap();
    let qy = hex::decode(g.get("qy").and_then(JsonValue::as_str).unwrap()).unwrap();
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&qx);
    pk[33..65].copy_from_slice(&qy);

    let prompt_groups = prompt
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let prompt_tests = prompt_groups[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    let response_tests = g.get("tests").and_then(JsonValue::as_array).unwrap();

    for (pt, rt) in prompt_tests.iter().zip(response_tests.iter()) {
        let msg = hex::decode(pt.get("message").and_then(JsonValue::as_str).unwrap()).unwrap();
        let r = hex::decode(rt.get("r").and_then(JsonValue::as_str).unwrap()).unwrap();
        let s = hex::decode(rt.get("s").and_then(JsonValue::as_str).unwrap()).unwrap();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&s);
        assert!(
            oxicrypt_ecdsa::p256_ecdsa::verify(&pk, &msg, &sig).unwrap(),
            "sigGen-produced signature must verify against the reported public key"
        );
    }
}

#[test]
fn ecdsa_keygen_p256_dispatches_without_d() {
    ensure_initialized().unwrap();
    let response = dispatch_ok(&ecdsa_keygen_prompt("P-256"));
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let tests = groups[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(tests.len(), 3);
    let mut seen_d = std::collections::HashSet::new();
    for t in tests {
        let d = t.get("d").and_then(JsonValue::as_str).unwrap();
        let qx = t.get("qx").and_then(JsonValue::as_str).unwrap();
        let qy = t.get("qy").and_then(JsonValue::as_str).unwrap();
        assert_eq!(d.len(), 64);
        assert_eq!(qx.len(), 64);
        assert_eq!(qy.len(), 64);
        // Each test gets a distinct keypair (vanishing collision probability).
        assert!(
            seen_d.insert(d.to_string()),
            "keyGen must produce distinct d per test"
        );
    }
}

#[test]
fn ecdsa_keygen_p384_dispatches_without_d() {
    ensure_initialized().unwrap();
    let response = dispatch_ok(&ecdsa_keygen_prompt("P-384"));
    let g = &response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0];
    let tests = g.get("tests").and_then(JsonValue::as_array).unwrap();
    for t in tests {
        let d = t.get("d").and_then(JsonValue::as_str).unwrap();
        let qx = t.get("qx").and_then(JsonValue::as_str).unwrap();
        let qy = t.get("qy").and_then(JsonValue::as_str).unwrap();
        assert_eq!(d.len(), 96);
        assert_eq!(qx.len(), 96);
        assert_eq!(qy.len(), 96);
    }
}

#[test]
fn ecdsa_siggen_unsupported_curve_hash_pair_errors() {
    ensure_initialized().unwrap();
    let prompt = ecdsa_siggen_prompt("P-256", "SHA2-384");
    let registry = dispatch::with_default_handlers();
    let r = dispatch::process(&prompt, &registry);
    assert!(r.is_err(), "(P-256, SHA2-384) must be rejected");
}

// ── KMAC unified XOF-flag dispatch ──────────────────────────────────

use oxicrypt_xof::{Kmac128, KmacXof128};

fn kmac128_prompt(xof: bool, key_hex: &str, msg_hex: &str, mac_len_bits: u64) -> JsonValue {
    let prompt_text = format!(
        r#"{{
            "algorithm": "KMAC-128",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": 1,
                "testType": "AFT",
                "xof": {xof},
                "hexCustomization": false,
                "tests": [{{
                    "tcId": 1,
                    "key":            "{key_hex}",
                    "keyLen":         {key_len},
                    "msg":            "{msg_hex}",
                    "msgLen":         {msg_len},
                    "macLen":         {mac_len_bits},
                    "customization":  ""
                }}]
            }}]
        }}"#,
        key_len = key_hex.len().saturating_mul(4),
        msg_len = msg_hex.len().saturating_mul(4),
    );
    parse(&prompt_text)
}

#[test]
fn kmac128_unified_handler_dispatches_xof_false() {
    ensure_initialized().unwrap();
    let key = "0102030405060708090A0B0C0D0E0F10";
    let msg = "DEADBEEF";
    let prompt = kmac128_prompt(false, key, msg, 256);
    let response = dispatch_ok(&prompt);
    let mac = first_test(
        &response
            .get("testGroups")
            .and_then(JsonValue::as_array)
            .unwrap()[0],
    )
    .get("mac")
    .and_then(JsonValue::as_str)
    .unwrap()
    .to_string();

    // Reference: compute via Kmac128 directly with no customization.
    let key_bytes = hex::decode(key).unwrap();
    let msg_bytes = hex::decode(msg).unwrap();
    let mut expected = vec![0u8; 32];
    let mut m = Kmac128::new(&key_bytes, &[]).unwrap();
    m.update(&msg_bytes);
    m.finalize_into(&mut expected);
    assert_eq!(mac, hex::encode_upper(&expected));
}

#[test]
fn kmac128_unified_handler_dispatches_xof_true() {
    ensure_initialized().unwrap();
    let key = "0102030405060708090A0B0C0D0E0F10";
    let msg = "DEADBEEF";
    // Pick an unusual mac length that only the XOF primitive can produce
    // cleanly to make the test diagnostic if dispatch routes wrong.
    let prompt = kmac128_prompt(true, key, msg, 320);
    let response = dispatch_ok(&prompt);
    let mac = first_test(
        &response
            .get("testGroups")
            .and_then(JsonValue::as_array)
            .unwrap()[0],
    )
    .get("mac")
    .and_then(JsonValue::as_str)
    .unwrap()
    .to_string();

    let key_bytes = hex::decode(key).unwrap();
    let msg_bytes = hex::decode(msg).unwrap();
    let mut expected = vec![0u8; 40];
    let mut m = KmacXof128::new(&key_bytes, &[]).unwrap();
    m.update(&msg_bytes);
    m.finalize();
    m.squeeze(&mut expected);
    assert_eq!(mac, hex::encode_upper(&expected));
}

#[test]
fn kmac128_unified_handler_defaults_to_non_xof_when_flag_absent() {
    // Vendored offline kat-slice format: no group-level `xof` field.
    // Handler must default to xof=false to preserve round-trip.
    ensure_initialized().unwrap();
    let key = "0102030405060708090A0B0C0D0E0F10";
    let msg = "DEADBEEF";
    let prompt_text = format!(
        r#"{{
            "algorithm": "KMAC-128",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": 1,
                "testType": "AFT",
                "hexCustomization": false,
                "tests": [{{
                    "tcId": 1,
                    "key":            "{key}",
                    "keyLen":         {kl},
                    "msg":            "{msg}",
                    "msgLen":         {ml},
                    "macLen":         256,
                    "customization":  ""
                }}]
            }}]
        }}"#,
        kl = key.len().saturating_mul(4),
        ml = msg.len().saturating_mul(4),
    );
    let prompt = parse(&prompt_text);
    let response = dispatch_ok(&prompt);
    let mac = first_test(
        &response
            .get("testGroups")
            .and_then(JsonValue::as_array)
            .unwrap()[0],
    )
    .get("mac")
    .and_then(JsonValue::as_str)
    .unwrap()
    .to_string();

    // Same as xof_false reference.
    let key_bytes = hex::decode(key).unwrap();
    let msg_bytes = hex::decode(msg).unwrap();
    let mut expected = vec![0u8; 32];
    let mut m = Kmac128::new(&key_bytes, &[]).unwrap();
    m.update(&msg_bytes);
    m.finalize_into(&mut expected);
    assert_eq!(mac, hex::encode_upper(&expected));
}

// ── KDF (SP 800-108r1) generative-AFT — handler must NOT read fixedData ──
//
// ACVP demo session 726988 returned DISPATCH_ERROR `missing field "fixedData"`
// because the live AFT prompt only supplies `keyIn` per test. The IUT samples
// its own Label + Context, assembles the fixed-input string per SP 800-108
// §5.2, derives `keyOut`, and echoes `fixedData` back. (PR #40, 2026-05-04)

fn kbkdf_counter_generative_prompt(mac_mode: &str, key_out_bits: u64) -> JsonValue {
    let prompt_text = format!(
        r#"{{
            "algorithm": "KDF",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": 1,
                "testType":        "AFT",
                "kdfMode":         "counter",
                "macMode":         "{mac_mode}",
                "counterLocation": "before fixed data",
                "counterLength":   32,
                "keyOutLength":    {key_out_bits},
                "tests": [
                    {{ "tcId": 1, "keyIn": "00112233445566778899AABBCCDDEEFF" }},
                    {{ "tcId": 2, "keyIn": "FFEEDDCCBBAA99887766554433221100" }}
                ]
            }}]
        }}"#
    );
    parse(&prompt_text)
}

fn kbkdf_feedback_generative_prompt(
    mac_mode: &str,
    key_out_bits: u64,
    zero_length_iv: bool,
) -> JsonValue {
    // Feedback groups carry `counterLength` and `counterLocation`
    // exactly as ACVTS prompts them; the handler dispatches via
    // `Sp800_108Feedback::derive_with_counter_internal` which honours
    // `[i]_h`. When zeroLengthIv=false the per-test prompt MUST carry
    // `iv` — the IUT never samples IVs because the server validates
    // its expected keyOut against the IV it sent.
    let tests = if zero_length_iv {
        r#"[
                    { "tcId": 1, "keyIn": "00112233445566778899AABBCCDDEEFF" },
                    { "tcId": 2, "keyIn": "FFEEDDCCBBAA99887766554433221100" }
                ]"#
    } else {
        // PRF-output sized IVs vary per macMode, but a 64-byte hex
        // string is the longest any of the handler's macModes asks
        // for and shorter macModes truncate via the iv_len gate; the
        // prompt-shape contract is just "iv is present and decodable".
        r#"[
                    { "tcId": 1, "keyIn": "00112233445566778899AABBCCDDEEFF",
                      "iv": "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899" },
                    { "tcId": 2, "keyIn": "FFEEDDCCBBAA99887766554433221100",
                      "iv": "9988776655443322110000FFEEDDCCBBAA99887766554433221100FFEEDDCCBB9988776655443322110000FFEEDDCCBBAA99887766554433221100FFEEDDCCBB" }
                ]"#
    };
    let prompt_text = format!(
        r#"{{
            "algorithm": "KDF",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": 1,
                "testType":        "AFT",
                "kdfMode":         "feedback",
                "macMode":         "{mac_mode}",
                "keyOutLength":    {key_out_bits},
                "counterLocation": "before fixed data",
                "counterLength":   32,
                "zeroLengthIv":    {zero_length_iv},
                "tests": {tests}
            }}]
        }}"#
    );
    parse(&prompt_text)
}

fn kbkdf_double_pipeline_generative_prompt(mac_mode: &str, key_out_bits: u64) -> JsonValue {
    // DP groups carry `counterLength` and `counterLocation` exactly
    // as ACVTS prompts them; the handler dispatches via
    // `Sp800_108DoublePipeline::derive_with_counter_internal` whose
    // inner A chain stays counter-free (counter enters only the
    // output K PRF).
    let prompt_text = format!(
        r#"{{
            "algorithm": "KDF",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": 1,
                "testType":        "AFT",
                "kdfMode":         "double pipeline iteration",
                "macMode":         "{mac_mode}",
                "keyOutLength":    {key_out_bits},
                "counterLocation": "before fixed data",
                "counterLength":   32,
                "tests": [
                    {{ "tcId": 1, "keyIn": "00112233445566778899AABBCCDDEEFF" }},
                    {{ "tcId": 2, "keyIn": "FFEEDDCCBBAA99887766554433221100" }}
                ]
            }}]
        }}"#
    );
    parse(&prompt_text)
}

#[test]
fn kbkdf_counter_generative_aft_dispatches_without_fixed_data() {
    ensure_initialized().unwrap();
    let response = dispatch_ok(&kbkdf_counter_generative_prompt("HMAC-SHA2-256", 256));
    let g = &response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0];
    let tests = g.get("tests").and_then(JsonValue::as_array).unwrap();
    assert_eq!(tests.len(), 2);
    let mut seen_fd = std::collections::HashSet::new();
    for t in tests {
        let key_out = t.get("keyOut").and_then(JsonValue::as_str).unwrap();
        let fixed_data = t.get("fixedData").and_then(JsonValue::as_str).unwrap();
        assert_eq!(key_out.len(), 64); // 256 bits / 4 = 64 hex chars
        // Each test gets distinct fixedData (Label + Context resampled).
        assert!(
            seen_fd.insert(fixed_data.to_string()),
            "counter generative-AFT must produce distinct fixedData per test"
        );
    }
}

#[test]
fn kbkdf_counter_generative_self_derives_to_same_key_out() {
    ensure_initialized().unwrap();
    let prompt = kbkdf_counter_generative_prompt("HMAC-SHA2-256", 256);
    let response = dispatch_ok(&prompt);
    let g = &response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0];
    let prompt_groups = prompt
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let prompt_tests = prompt_groups[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    let response_tests = g.get("tests").and_then(JsonValue::as_array).unwrap();

    for (pt, rt) in prompt_tests.iter().zip(response_tests.iter()) {
        let key_in = hex::decode(pt.get("keyIn").and_then(JsonValue::as_str).unwrap()).unwrap();
        let fixed_data =
            hex::decode(rt.get("fixedData").and_then(JsonValue::as_str).unwrap()).unwrap();
        let reported_key_out =
            hex::decode(rt.get("keyOut").and_then(JsonValue::as_str).unwrap()).unwrap();

        let mut recomputed = vec![0u8; reported_key_out.len()];
        oxicrypt_kdf::Sp800_108CounterHmacSha256::derive_with_fixed_data_internal(
            &key_in,
            &fixed_data,
            &mut recomputed,
        )
        .unwrap();
        assert_eq!(
            reported_key_out, recomputed,
            "reported keyOut must equal derive(keyIn, fixedData)"
        );
    }
}

#[test]
fn kbkdf_feedback_generative_aft_zero_length_iv_dispatches() {
    ensure_initialized().unwrap();
    let response = dispatch_ok(&kbkdf_feedback_generative_prompt(
        "HMAC-SHA2-256",
        256,
        true,
    ));
    let tests = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    for t in tests {
        let key_out = t.get("keyOut").and_then(JsonValue::as_str).unwrap();
        let fixed_data = t.get("fixedData").and_then(JsonValue::as_str).unwrap();
        assert_eq!(key_out.len(), 64);
        assert!(!fixed_data.is_empty());
        // Zero-length IV — the response must NOT echo a populated `iv`.
        let iv_field = t.get("iv").and_then(JsonValue::as_str);
        assert!(
            iv_field.is_none() || iv_field == Some(""),
            "zeroLengthIv=true must omit (or empty-string) iv in response"
        );
    }
}

#[test]
fn kbkdf_feedback_generative_aft_explicit_iv_dispatches() {
    // Feedback w/ zeroLengthIv=false: the IUT must consume the
    // prompt's `iv` field unconditionally (server validates its
    // expected keyOut against the IV it sent) and must NOT echo
    // `iv` in the response.
    ensure_initialized().unwrap();
    let response = dispatch_ok(&kbkdf_feedback_generative_prompt(
        "HMAC-SHA2-256",
        256,
        false,
    ));
    let tests = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    for t in tests {
        let key_out = t.get("keyOut").and_then(JsonValue::as_str).unwrap();
        let fixed_data = t.get("fixedData").and_then(JsonValue::as_str).unwrap();
        assert_eq!(key_out.len(), 64);
        assert!(!fixed_data.is_empty());
        // Response must NOT echo iv — the server already has it.
        let iv_field = t.get("iv").and_then(JsonValue::as_str);
        assert!(
            iv_field.is_none() || iv_field == Some(""),
            "feedback response must not echo iv when server provided it"
        );
    }
}

#[test]
fn kbkdf_double_pipeline_generative_aft_dispatches() {
    ensure_initialized().unwrap();
    let response = dispatch_ok(&kbkdf_double_pipeline_generative_prompt(
        "HMAC-SHA2-256",
        256,
    ));
    let tests = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap()[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    for t in tests {
        let key_out = t.get("keyOut").and_then(JsonValue::as_str).unwrap();
        let fixed_data = t.get("fixedData").and_then(JsonValue::as_str).unwrap();
        assert_eq!(key_out.len(), 64);
        assert!(!fixed_data.is_empty());
        // Double-pipeline has no IV.
        assert!(
            t.get("iv").is_none(),
            "double pipeline mode must not emit iv"
        );
    }
}

#[test]
fn kbkdf_counter_deterministic_path_still_works() {
    ensure_initialized().unwrap();
    // Pre-built fixedData supplied at test level — handler must take the
    // deterministic branch and NOT resample, returning keyOut from the
    // exact `derive_with_fixed_data_internal(keyIn, fixedData, ...)` call.
    let prompt_text = r#"{
        "algorithm": "KDF",
        "revision":  "1.0",
        "testGroups": [{
            "tgId": 1,
            "testType":        "AFT",
            "kdfMode":         "counter",
            "macMode":         "HMAC-SHA2-256",
            "counterLocation": "before fixed data",
            "counterLength":   32,
            "keyOutLength":    256,
            "tests": [
                {
                    "tcId": 1,
                    "keyIn":     "00112233445566778899AABBCCDDEEFF",
                    "fixedData": "AABBCCDDEEFF00112233445566778899"
                }
            ]
        }]
    }"#;
    let response = dispatch_ok(&parse(prompt_text));
    let t = first_test(
        &response
            .get("testGroups")
            .and_then(JsonValue::as_array)
            .unwrap()[0],
    );
    let reported_key_out =
        hex::decode(t.get("keyOut").and_then(JsonValue::as_str).unwrap()).unwrap();
    // Deterministic path must not echo the optional generative-shape fields
    // — the response shape mirrors what the handler emitted before the
    // generative branch was added (just `tcId` + `keyOut`).
    assert!(
        t.get("fixedData").is_none(),
        "deterministic path must not echo fixedData"
    );
    assert!(t.get("iv").is_none(), "deterministic path must not echo iv");
    // Re-derive offline against the prompt's exact fixedData.
    let mut expected = vec![0u8; 32];
    oxicrypt_kdf::Sp800_108CounterHmacSha256::derive_with_fixed_data_internal(
        &hex::decode("00112233445566778899AABBCCDDEEFF").unwrap(),
        &hex::decode("AABBCCDDEEFF00112233445566778899").unwrap(),
        &mut expected,
    )
    .unwrap();
    assert_eq!(reported_key_out, expected);
}

// ── SLH-DSA keyGen: read skSeed/skPrf/pkSeed as 3 separate fields ──

/// Per `slh-dsa §8.1.2 Table 10`, the SLH-DSA keyGen test case carries
/// THREE separate hex fields: `skSeed`, `skPrf`, `pkSeed` — not a
/// single pre-concatenated `seed`. Pre-fix, the handler at
/// `slh_dsa.rs:113-122` read a single `seed` field expecting 96 B
/// concat, which would fail with `MissingField("seed")` against any
/// spec-conformant prompt.
fn slh_dsa_keygen_3field_prompt(
    sk_seed_hex: &str,
    sk_prf_hex: &str,
    pk_seed_hex: &str,
) -> JsonValue {
    let prompt_text = format!(
        r#"{{
            "algorithm": "SLH-DSA",
            "mode":      "keyGen",
            "revision":  "FIPS205",
            "testGroups": [{{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "SLH-DSA-SHA2-256s",
                "tests": [
                    {{
                        "tcId":   1,
                        "skSeed": "{sk_seed_hex}",
                        "skPrf":  "{sk_prf_hex}",
                        "pkSeed": "{pk_seed_hex}"
                    }}
                ]
            }}]
        }}"#
    );
    parse(&prompt_text)
}

#[test]
fn slh_dsa_keygen_reads_separate_skseed_skprf_pkseed_fields() {
    ensure_initialized().unwrap();

    // SLH-DSA-SHA2-256s: N = 32, so each of skSeed/skPrf/pkSeed is 32 B.
    let sk_seed = [0x01u8; 32];
    let sk_prf = [0x02u8; 32];
    let pk_seed = [0x03u8; 32];

    // Reference pk: the primitive takes the 96-byte concat
    // (skSeed ‖ skPrf ‖ pkSeed). The handler must assemble it.
    let mut concat = [0u8; 96];
    concat[..32].copy_from_slice(&sk_seed);
    concat[32..64].copy_from_slice(&sk_prf);
    concat[64..].copy_from_slice(&pk_seed);
    let (expected_pk, _expected_sk) = oxicrypt_slh_dsa::keygen_internal(&concat);

    let response = dispatch_ok(&slh_dsa_keygen_3field_prompt(
        &hex::encode_upper(&sk_seed),
        &hex::encode_upper(&sk_prf),
        &hex::encode_upper(&pk_seed),
    ));

    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let tests = groups[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    let pk_hex = tests[0].get("pk").and_then(JsonValue::as_str).unwrap();
    let pk_bytes = hex::decode(pk_hex).unwrap();

    assert_eq!(
        pk_bytes,
        expected_pk.to_vec(),
        "handler must read skSeed/skPrf/pkSeed as 3 separate fields per \
         slh-dsa §8.1.2 Table 10 and concat to 96 B before calling \
         oxicrypt_slh_dsa::keygen_internal",
    );
}

// ── LMS keyGen: consume the server-supplied identifier `i` ──────────

/// Per `lms §8.1.2 Table 8` (and RFC 8554 §5.3), the LMS keyGen test
/// case carries the public-key identifier `i` (16 B) alongside the OTS
/// `seed` (32 B for SHA256 variants). Both feed the keygen — the
/// resulting public key embeds `i` at bytes 8..24 and computes the
/// Merkle root from `(seed, i)`. Pre-fix, the handler at
/// `lms.rs:118-129` consumed only `seed`, calling
/// `oxicrypt_lms::keygen_internal(&seed)` which derives an identifier
/// internally — producing a public key that does not match what the
/// server expects.
fn lms_keygen_seed_and_id_prompt(seed_hex: &str, i_hex: &str) -> JsonValue {
    let prompt_text = format!(
        r#"{{
            "algorithm": "LMS",
            "mode":      "keyGen",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": 1,
                "testType": "AFT",
                "lmsMode":   "LMS_SHA256_M32_H10",
                "lmOtsMode": "LMOTS_SHA256_N32_W4",
                "tests": [
                    {{
                        "tcId": 1,
                        "seed": "{seed_hex}",
                        "i":    "{i_hex}"
                    }}
                ]
            }}]
        }}"#
    );
    parse(&prompt_text)
}

#[test]
fn lms_keygen_consumes_server_supplied_identifier() {
    ensure_initialized().unwrap();

    let seed = [0x04u8; 32];
    let i = [0x05u8; 16];

    // Reference pk: keygen_from_parts is the ACVP-shaped primitive
    // (per its doc-comment), which takes seed AND identifier
    // separately and embeds the supplied identifier in the public key.
    let (_expected_sk, expected_pk) = oxicrypt_lms::keygen_from_parts(&seed, &i);

    let response = dispatch_ok(&lms_keygen_seed_and_id_prompt(
        &hex::encode_upper(&seed),
        &hex::encode_upper(&i),
    ));

    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let tests = groups[0]
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap();
    let pk_hex = tests[0]
        .get("publicKey")
        .and_then(JsonValue::as_str)
        .unwrap();
    let pk_bytes = hex::decode(pk_hex).unwrap();

    // Bytes 8..24 of the LMS public key are the identifier `I` per RFC
    // 8554 §5.3. If the handler ignored the supplied `i`, this slice
    // would not equal the prompt's `i`.
    assert_eq!(
        &pk_bytes[8..24],
        &i[..],
        "handler must consume the server-supplied `i` field per lms \
         §8.1.2 Table 8 / RFC 8554 §5.3 — bytes 8..24 of the public key \
         must equal the prompt's `i`",
    );
    assert_eq!(
        pk_bytes,
        expected_pk.to_vec(),
        "handler must call oxicrypt_lms::keygen_from_parts(seed, i) to \
         produce a public key whose Merkle root depends on the supplied \
         identifier",
    );
}
