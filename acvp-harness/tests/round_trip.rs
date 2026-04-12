//! Round-trip integration tests for the ACVP dispatcher.
//!
//! For each vendored ACVP `kat-slice.json`, we:
//!
//! 1. Load the file, parse it, capture the expected answer field
//!    (`md` for hash / XOF, `mac` for HMAC) from every test case.
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
//!
//! R10 wired the first two handlers (SHA3-256, HMAC-SHA2-256). R12-A
//! expanded the set to 17 by adding SHA3-{224,384,512}, SHAKE-{128,256},
//! HMAC-SHA-1, HMAC-SHA2-{224,384,512,512/224,512/256}, and
//! HMAC-SHA3-{224,256,384,512}. The tests below are data-driven: one
//! per `(algorithm, slice)` pair, each invoking a shared round-trip
//! runner so a new handler is typically a three-line test.

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

/// Shared round-trip driver: loads `relative`, strips `answer_field`
/// from every case, dispatches, and asserts the dispatcher reproduced
/// every answer byte-for-byte (case-insensitive on the hex encoding).
fn assert_round_trip(relative: &str, answer_field: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected = collect_answers(&slice, answer_field);
    assert!(
        !expected.is_empty(),
        "{label}: slice {relative} has no test cases with field {answer_field:?}"
    );

    let mut prompt = slice.clone();
    strip_field(&mut prompt, answer_field);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));
    let got = collect_answers(&response, answer_field);

    assert_eq!(
        got.len(),
        expected.len(),
        "{label}: response has {} cases, expected {}",
        got.len(),
        expected.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected.iter().zip(got.iter()) {
        assert_eq!(exp_tc, got_tc, "{label}: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "{label}: {answer_field} mismatch for tcId {exp_tc}"
        );
    }
}

// ----------------------------------------------------------------------
// SHA-3 family (revision 2.0, answer field `md`)
// ----------------------------------------------------------------------

#[test]
fn sha3_224_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-224-2.0/kat-slice.json",
        "md",
        "SHA3-224",
    );
}

#[test]
fn sha3_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-256-2.0/kat-slice.json",
        "md",
        "SHA3-256",
    );
}

#[test]
fn sha3_384_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-384-2.0/kat-slice.json",
        "md",
        "SHA3-384",
    );
}

#[test]
fn sha3_512_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-512-2.0/kat-slice.json",
        "md",
        "SHA3-512",
    );
}

// ----------------------------------------------------------------------
// SHAKE XOFs (revision FIPS202, answer field `md`)
// ----------------------------------------------------------------------

#[test]
fn shake_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-128-FIPS202/kat-slice.json",
        "md",
        "SHAKE-128",
    );
}

#[test]
fn shake_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-256-FIPS202/kat-slice.json",
        "md",
        "SHAKE-256",
    );
}

// ----------------------------------------------------------------------
// HMAC family (revision 1.0, answer field `mac`)
// ----------------------------------------------------------------------

#[test]
fn hmac_sha1_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA-1-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA-1",
    );
}

#[test]
fn hmac_sha2_224_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-224-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA2-224",
    );
}

#[test]
fn hmac_sha2_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-256-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA2-256",
    );
}

#[test]
fn hmac_sha2_384_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-384-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA2-384",
    );
}

#[test]
fn hmac_sha2_512_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-512-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA2-512",
    );
}

#[test]
fn hmac_sha2_512_224_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-512-224-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA2-512/224",
    );
}

#[test]
fn hmac_sha2_512_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA2-512-256-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA2-512/256",
    );
}

#[test]
fn hmac_sha3_224_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA3-224-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA3-224",
    );
}

#[test]
fn hmac_sha3_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA3-256-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA3-256",
    );
}

#[test]
fn hmac_sha3_384_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA3-384-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA3-384",
    );
}

#[test]
fn hmac_sha3_512_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/HMAC-SHA3-512-1.0/kat-slice.json",
        "mac",
        "HMAC-SHA3-512",
    );
}

// ----------------------------------------------------------------------
// KDA-HKDF (revision Sp800-56Cr2, mode HKDF, answer field `dkm`)
// ----------------------------------------------------------------------

#[test]
fn kda_hkdf_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KDA-HKDF-Sp800-56Cr2/kat-slice.json",
        "dkm",
        "KDA-HKDF",
    );
}

// ----------------------------------------------------------------------
// Envelope preservation (unchanged since R10)
// ----------------------------------------------------------------------

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
