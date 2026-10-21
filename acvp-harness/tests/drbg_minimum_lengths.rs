//! ctrDRBG with a derivation function against the module's minimum
//! nonce length: the registered capability asks for nonces the module
//! accepts, the vendored NIST sample still dispatches, a df case whose
//! nonce is empty fails with an error that names the nonce, and a
//! prediction-resistance df case whose reseed entropy is empty fails
//! with an error that names the entropy input.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use acvp_harness::handlers::caps::ctr_drbg_capability;
use acvp_harness::{dispatch, ensure_initialized, json, json::JsonValue};

fn load_ctr_slice() -> JsonValue {
    let path = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files/ctrDRBG-1.0/kat-slice.json",
        env!("CARGO_MANIFEST_DIR")
    );
    json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn field<'a>(v: &'a JsonValue, name: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(kvs) => kvs.iter().find(|(k, _)| k == name).map(|(_, v)| v),
        _ => None,
    }
}

/// Replaces the nonce of every test in every `derFunc: true` group with
/// the empty string and returns how many were replaced.
fn blank_df_nonces(v: &mut JsonValue) -> usize {
    let mut n = 0;
    let JsonValue::Object(kvs) = v else { return 0 };
    let is_df = kvs
        .iter()
        .any(|(k, val)| k == "derFunc" && matches!(val, JsonValue::Bool(true)));
    for (k, val) in kvs.iter_mut() {
        match (k.as_str(), val) {
            ("testGroups", JsonValue::Array(groups)) => {
                n += groups.iter_mut().map(blank_df_nonces).sum::<usize>();
            }
            ("tests", JsonValue::Array(tests)) if is_df => {
                for t in tests.iter_mut() {
                    if let JsonValue::Object(tk) = t {
                        for (kk, vv) in tk.iter_mut() {
                            if kk == "nonce" {
                                *vv = JsonValue::String(String::new());
                                n += 1;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    n
}

/// Replaces the `entropyInput` of every `otherInput` entry of every test
/// in every `derFunc: true`, `predResistance: true` group with the empty
/// string and returns how many were replaced.
fn blank_df_pr_entropy(v: &mut JsonValue) -> usize {
    let mut n = 0;
    let JsonValue::Object(kvs) = v else { return 0 };
    let flag = |kvs: &[(String, JsonValue)], name: &str| {
        kvs.iter()
            .any(|(k, val)| k == name && matches!(val, JsonValue::Bool(true)))
    };
    let target = flag(kvs, "derFunc") && flag(kvs, "predResistance");
    for (k, val) in kvs.iter_mut() {
        match (k.as_str(), val) {
            ("testGroups", JsonValue::Array(groups)) => {
                n += groups.iter_mut().map(blank_df_pr_entropy).sum::<usize>();
            }
            ("tests", JsonValue::Array(tests)) if target => {
                for t in tests.iter_mut() {
                    let JsonValue::Object(tk) = t else { continue };
                    for (kk, vv) in tk.iter_mut() {
                        let ("otherInput", JsonValue::Array(others)) = (kk.as_str(), vv) else {
                            continue;
                        };
                        for o in others.iter_mut() {
                            let JsonValue::Object(ok) = o else { continue };
                            for (ek, ev) in ok.iter_mut() {
                                if ek == "entropyInput" {
                                    *ev = JsonValue::String(String::new());
                                    n += 1;
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    n
}

#[test]
fn ctr_drbg_df_registration_asks_for_the_minimum_nonce() {
    let cap = ctr_drbg_capability();
    let entries = field(&cap, "capabilities")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(entries.len(), 6);
    let mut registered = Vec::new();
    for entry in entries {
        let mode = field(entry, "mode").unwrap().as_str().unwrap();
        assert!(
            field(entry, "derFunc").is_none(),
            "{mode}: the registration field is derFuncEnabled; the server ignores derFunc"
        );
        let df = matches!(field(entry, "derFuncEnabled"), Some(JsonValue::Bool(true)));
        let nonce = json::to_compact_string(field(entry, "nonceLen").unwrap());
        let expected = match (mode, df) {
            ("AES-128", true) => "[64]",
            ("AES-192", true) => "[96]",
            ("AES-256", true) => "[128]",
            (_, false) => "[0]",
            other => panic!("unexpected entry {other:?}"),
        };
        assert_eq!(nonce, expected, "{mode} derFuncEnabled={df}");
        registered.push((mode.to_owned(), df));
    }
    registered.sort();
    let mut wanted: Vec<(String, bool)> = ["AES-128", "AES-192", "AES-256"]
        .iter()
        .flat_map(|mode| [(mode.to_string(), false), (mode.to_string(), true)])
        .collect();
    wanted.sort();
    assert_eq!(
        registered, wanted,
        "each AES key size is registered once with and once without the derivation function"
    );
}

#[test]
fn vendored_ctr_drbg_slice_dispatches_and_empty_df_nonce_is_named() {
    ensure_initialized().unwrap();
    let registry = dispatch::with_default_handlers();
    dispatch::process(&load_ctr_slice(), &registry).unwrap();

    let mut prompt = load_ctr_slice();
    assert!(blank_df_nonces(&mut prompt) > 0, "the slice has df groups");
    let err = dispatch::process(&prompt, &registry).unwrap_err();
    assert!(
        matches!(
            err,
            dispatch::DispatchError::InputRefused {
                cause: oxicrypt_module::Error::NonceTooShort,
                ..
            }
        ),
        "{err}"
    );
    let err = err.to_string();
    assert!(err.starts_with("crypto: "), "{err}");
    assert!(err.contains("nonce is shorter than half"), "{err}");
}

#[test]
fn empty_df_prediction_resistance_entropy_is_named() {
    ensure_initialized().unwrap();
    let registry = dispatch::with_default_handlers();
    let mut prompt = load_ctr_slice();
    assert!(
        blank_df_pr_entropy(&mut prompt) > 0,
        "the slice has df PR groups"
    );
    let err = dispatch::process(&prompt, &registry).unwrap_err();
    assert!(
        matches!(
            err,
            dispatch::DispatchError::InputRefused {
                cause: oxicrypt_module::Error::EntropyInputTooShort,
                ..
            }
        ),
        "{err}"
    );
    let err = err.to_string();
    assert!(err.starts_with("crypto: "), "{err}");
    assert!(
        err.contains("entropy input is shorter than the minimum"),
        "{err}"
    );
}
