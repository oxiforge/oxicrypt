//! The AES registrations against the module: each registered length is
//! one the module's key constructors accept, the length below the floor
//! is one they refuse, and every group in the vendored CCM slices uses
//! registered lengths.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use acvp_harness::handlers::caps::{aes_ccm_capability, aes_gcm_capability, cmac_aes_capability};
use acvp_harness::{ensure_initialized, json, json::JsonValue};

fn numbers(v: &JsonValue) -> Vec<u64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap())
        .collect()
}

#[test]
fn gcm_registers_internal_iv_generation() {
    let cap = aes_gcm_capability();
    assert_eq!(
        cap.get("ivGen").and_then(JsonValue::as_str),
        Some("internal")
    );
    assert_eq!(
        cap.get("ivGenMode").and_then(JsonValue::as_str),
        Some("8.2.2")
    );
    assert_eq!(numbers(cap.get("ivLen").unwrap()), [96]);
    assert_eq!(numbers(cap.get("tagLen").unwrap()), [128]);
}

#[test]
fn gcm_key_lengths_are_ones_gcm_key_accepts() {
    ensure_initialized().unwrap();
    let cap = aes_gcm_capability();
    let keys = numbers(cap.get("keyLen").unwrap());
    assert_eq!(keys, [128, 192, 256]);
    for bits in &keys {
        let bytes = usize::try_from(bits / 8).unwrap();
        assert!(
            oxicrypt_aes::GcmKey::new(&[0u8; 32][..bytes]).is_ok(),
            "GcmKey::new refuses registered keyLen {bits}"
        );
    }
    for bytes in [15, 17, 31, 33] {
        assert!(
            oxicrypt_aes::GcmKey::new(&[0u8; 33][..bytes]).is_err(),
            "GcmKey::new accepts an unregistered key of {bytes} bytes"
        );
    }
    assert_eq!(numbers(cap.get("ivLen").unwrap()), [96]);
    assert_eq!(numbers(cap.get("tagLen").unwrap()), [128]);
}

#[test]
fn ccm_tag_lengths_are_ones_ccm_key_accepts() {
    ensure_initialized().unwrap();
    let tags = numbers(aes_ccm_capability().get("tagLen").unwrap());
    assert_eq!(tags, [64, 80, 96, 112, 128]);
    for bits in &tags {
        let bytes = usize::try_from(bits / 8).unwrap();
        assert!(
            oxicrypt_aes::CcmKey::new(&[0u8; 16], bytes).is_ok(),
            "CcmKey::new refuses registered tagLen {bits}"
        );
    }
    assert!(oxicrypt_aes::CcmKey::new(&[0u8; 16], 6).is_err());
    assert!(oxicrypt_aes::CcmKey::new(&[0u8; 16], 7).is_err());
}

#[test]
fn cmac_mac_length_floor_is_the_cmac_key_floor() {
    ensure_initialized().unwrap();
    let cap = cmac_aes_capability();
    let caps = cap
        .get("capabilities")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(caps.len(), 1);
    let domain = caps[0].get("macLen").and_then(JsonValue::as_array).unwrap();
    assert_eq!(domain.len(), 1);
    let field = |name: &str| domain[0].get(name).and_then(JsonValue::as_u64).unwrap();
    let (min, max, inc) = (field("min"), field("max"), field("increment"));
    assert_eq!((min, max, inc), (64, 128, 8));
    let step = usize::try_from(inc).unwrap();
    let registered: Vec<u64> = (min..=max).step_by(step).collect();
    assert_eq!(registered.len(), 9);
    for bits in &registered {
        let bytes = usize::try_from(bits / 8).unwrap();
        assert!(
            oxicrypt_cmac::CmacKey::new(&[0u8; 16], bytes).is_ok(),
            "CmacKey::new refuses registered macLen {bits}"
        );
    }
    assert!(oxicrypt_cmac::CmacKey::new(&[0u8; 16], 7).is_err());
    assert!(oxicrypt_cmac::CmacKey::new(&[0u8; 16], 17).is_err());
}

#[test]
fn vendored_ccm_slices_use_registered_lengths() {
    let cap = aes_ccm_capability();
    let tags = numbers(cap.get("tagLen").unwrap());
    let ivs = numbers(cap.get("ivLen").unwrap());
    for file in ["kat-slice.json", "lifecycle-slice.json"] {
        let path = format!(
            "{}/../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CCM-1.0/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        let slice = json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
        let groups = slice
            .get("testGroups")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert!(!groups.is_empty(), "{file}: no groups");
        for g in groups {
            let tag = g.get("tagLen").and_then(JsonValue::as_u64).unwrap();
            assert!(
                tags.contains(&tag),
                "{file}: tagLen {tag} is not registered"
            );
            let iv = g.get("ivLen").and_then(JsonValue::as_u64).unwrap();
            assert!(ivs.contains(&iv), "{file}: ivLen {iv} is not registered");
        }
    }
}
