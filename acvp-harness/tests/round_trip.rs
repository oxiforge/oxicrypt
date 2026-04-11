//! Round-trip integration tests for the ACVP dispatcher.
//!
//! For each vendored ACVP `kat-slice.json`, we:
//!
//! 1. Load the file, parse it, capture the expected answer field
//!    (`md` for SHA3-256, `mac` for HMAC-SHA2-256) from every test
//!    case.
//! 2. Strip that field from the parsed tree to simulate a prompt
//!    coming from a CAVP lab that hasn't seen the answer.
//! 3. Run the prompt through [`acvp_harness::dispatch::process`].
//! 4. Verify the response matches the expected answer, byte for byte,
//!    for every test case.
//!
//! This exercise proves three things at once: the hand-rolled JSON
//! parser round-trips the exact files NIST ships, the envelope layer
//! correctly peels off the algorithm/revision, and the per-algorithm
//! handler's output matches the reference answer. A failure on any
//! of these three layers surfaces as a single assertion diff.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use acvp_harness::{dispatch, ensure_initialized, json, json::JsonValue};

/// Load and parse a vendored ACVP slice relative to the harness
/// crate root.
fn load(relative: &str) -> JsonValue {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"));
    json::parse(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

/// Recursively remove every occurrence of `field` from every object
/// in the tree. Used to strip answer fields out of a slice so we can
/// feed it back through the dispatcher as a prompt.
fn strip_field(v: &mut JsonValue, field: &str) {
    match v {
        JsonValue::Object(kvs) => {
            kvs.retain(|(k, _)| k != field);
            for (_, val) in kvs.iter_mut() {
                strip_field(val, field);
            }
        }
        JsonValue::Array(a) => {
            for val in a.iter_mut() {
                strip_field(val, field);
            }
        }
        _ => {}
    }
}

/// For every `tests` entry in every test group, return a list of
/// `(tcId, value)` pairs for `field`.
fn collect_answers(v: &JsonValue, field: &str) -> Vec<(i64, String)> {
    let mut out = Vec::new();
    let Some(groups) = v.get("testGroups").and_then(JsonValue::as_array) else {
        return out;
    };
    for g in groups {
        let Some(tests) = g.get("tests").and_then(JsonValue::as_array) else {
            continue;
        };
        for t in tests {
            let Some(tc_id) = t.get("tcId").and_then(JsonValue::as_i64) else {
                continue;
            };
            let Some(val) = t.get(field).and_then(JsonValue::as_str) else {
                continue;
            };
            out.push((tc_id, val.to_string()));
        }
    }
    out
}

#[test]
fn sha3_256_aft_round_trip() {
    ensure_initialized().unwrap();
    let slice = load("../vendor/nist/acvp-server/gen-val/json-files/SHA3-256-2.0/kat-slice.json");
    let expected = collect_answers(&slice, "md");
    assert!(!expected.is_empty(), "SHA3-256 slice has no test cases");

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "md");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry).unwrap();
    let got = collect_answers(&response, "md");

    assert_eq!(got.len(), expected.len());
    for ((exp_tc, exp_md), (got_tc, got_md)) in expected.iter().zip(got.iter()) {
        assert_eq!(exp_tc, got_tc, "tcId mismatch");
        assert_eq!(
            exp_md.to_ascii_uppercase(),
            *got_md,
            "SHA3-256 MD mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn hmac_sha2_256_aft_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-256-1.0/kat-slice.json",
    );
    let expected = collect_answers(&slice, "mac");
    assert!(!expected.is_empty(), "HMAC slice has no test cases");

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "mac");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry).unwrap();
    let got = collect_answers(&response, "mac");

    assert_eq!(got.len(), expected.len());
    for ((exp_tc, exp_mac), (got_tc, got_mac)) in expected.iter().zip(got.iter()) {
        assert_eq!(exp_tc, got_tc, "tcId mismatch");
        assert_eq!(
            exp_mac.to_ascii_uppercase(),
            *got_mac,
            "HMAC-SHA2-256 MAC mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn envelope_preserved_in_response() {
    ensure_initialized().unwrap();
    let slice = load("../vendor/nist/acvp-server/gen-val/json-files/SHA3-256-2.0/kat-slice.json");
    let mut prompt = slice.clone();
    strip_field(&mut prompt, "md");
    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry).unwrap();
    assert_eq!(
        response.get("algorithm").and_then(JsonValue::as_str),
        Some("SHA3-256")
    );
    assert_eq!(
        response.get("revision").and_then(JsonValue::as_str),
        Some("2.0")
    );
}
