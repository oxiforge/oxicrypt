//! The CMAC-AES handler at the edges of its `macLen` domain: lengths
//! outside 64..=128 bits are refused, `gen` returns a tag of the group's
//! length, and `ver` passes only the correct tag of that length.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use acvp_harness::dispatch::{AlgorithmHandler, DispatchError};
use acvp_harness::handlers::cmac::CmacAesHandler;
use acvp_harness::{ensure_initialized, hex, json, json::JsonValue};
use oxicrypt_cmac::{CmacKey, cmac};

const KEY: &str = "2B7E151628AED2A6ABF7158809CF4F3C";
const MESSAGE: &str = "6BC1BEE22E409F96E93D7E117393172A";

fn group(direction: &str, mac_len_bits: u64, mac: Option<&str>) -> JsonValue {
    let mac_field = mac.map_or(String::new(), |m| format!(r#", "mac": "{m}""#));
    json::parse(&format!(
        r#"{{
            "tgId": 1,
            "testType": "AFT",
            "direction": "{direction}",
            "keyLen": 128,
            "macLen": {mac_len_bits},
            "tests": [{{"tcId": 1, "key": "{KEY}", "message": "{MESSAGE}"{mac_field}}}]
        }}"#
    ))
    .unwrap()
}

fn first_result(response: &JsonValue) -> &JsonValue {
    &response.get("tests").and_then(JsonValue::as_array).unwrap()[0]
}

fn expected_tag(mac_len_bytes: usize) -> Vec<u8> {
    let key = CmacKey::new(&hex::decode(KEY).unwrap(), mac_len_bytes).unwrap();
    let mut tag = vec![0u8; mac_len_bytes];
    cmac(&key, &hex::decode(MESSAGE).unwrap(), &mut tag).unwrap();
    tag
}

fn ver_passed(mac: &[u8]) -> bool {
    let response = CmacAesHandler
        .handle_group(&group("ver", 64, Some(&hex::encode_upper(mac))))
        .unwrap();
    first_result(&response)
        .get("testPassed")
        .and_then(JsonValue::as_bool)
        .unwrap()
}

#[test]
fn mac_lengths_outside_the_domain_are_unsupported() {
    ensure_initialized().unwrap();
    for bits in [56, 0, 65] {
        for direction in ["gen", "ver"] {
            let result = CmacAesHandler.handle_group(&group(direction, bits, Some("00")));
            assert!(
                matches!(result, Err(DispatchError::Unsupported(_))),
                "{direction} macLen {bits}: {result:?}"
            );
        }
    }
}

#[test]
fn gen_returns_a_tag_of_the_group_mac_length() {
    ensure_initialized().unwrap();
    for bytes in [8usize, 16] {
        let bits = u64::try_from(bytes * 8).unwrap();
        let response = CmacAesHandler
            .handle_group(&group("gen", bits, None))
            .unwrap();
        let mac_hex = first_result(&response)
            .get("mac")
            .and_then(JsonValue::as_str)
            .unwrap();
        let mac = hex::decode(mac_hex).unwrap();
        assert_eq!(mac.len(), bytes, "macLen {bits}");
        assert_eq!(mac, expected_tag(bytes), "macLen {bits}");
    }
}

#[test]
fn ver_at_64_bits_passes_only_the_correct_8_byte_tag() {
    ensure_initialized().unwrap();
    let tag = expected_tag(8);
    assert!(ver_passed(&tag));

    let mut flipped = tag.clone();
    flipped[0] ^= 0x01;
    assert!(!ver_passed(&flipped));

    let full = expected_tag(16);
    assert_eq!(full[..8], tag[..]);
    assert!(!ver_passed(&full));
}
