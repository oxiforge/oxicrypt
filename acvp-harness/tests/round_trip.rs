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

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::similar_names
)]

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
// AES block-cipher AFT (R14-A): ECB / CBC / CTR
//
// Each test in an AFT group carries the input for its `direction`
// (encrypt → `pt`, decrypt → `ct`) and the expected output in the
// opposite field. The shared `assert_round_trip` helper only tracks
// a single answer field, so AES uses its own direction-aware helper.
// ----------------------------------------------------------------------

/// Collect `(tcId, answer_field, answer_value)` triples from every
/// test in every group of the slice. The group's `direction` picks
/// which field (`ct` or `pt`) is the answer — AES response groups
/// intentionally omit `direction`, so this helper is only called on
/// the input slice.
fn collect_aes_expected(v: &JsonValue) -> Vec<(i64, &'static str, String)> {
    let mut out = Vec::new();
    let Some(groups) = v.get("testGroups").and_then(JsonValue::as_array) else {
        return out;
    };
    for g in groups {
        let direction = g.get("direction").and_then(JsonValue::as_str).unwrap_or("");
        let answer_field: &'static str = match direction {
            "encrypt" => "ct",
            "decrypt" => "pt",
            _ => continue,
        };
        let Some(tests) = g.get("tests").and_then(JsonValue::as_array) else {
            continue;
        };
        for t in tests {
            let Some(tc_id) = t.get("tcId").and_then(JsonValue::as_i64) else {
                continue;
            };
            let Some(val) = t.get(answer_field).and_then(JsonValue::as_str) else {
                continue;
            };
            out.push((tc_id, answer_field, val.to_string()));
        }
    }
    out
}

/// Collect every response test keyed by `tcId`, with whichever of
/// `ct` / `pt` fields is present (only one is ever present per case).
fn collect_aes_response(v: &JsonValue) -> Vec<(i64, String)> {
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
            let val = t
                .get("ct")
                .and_then(JsonValue::as_str)
                .or_else(|| t.get("pt").and_then(JsonValue::as_str));
            if let Some(v) = val {
                out.push((tc_id, v.to_string()));
            }
        }
    }
    out
}

fn assert_aes_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected = collect_aes_expected(&slice);
    assert!(
        !expected.is_empty(),
        "{label}: slice {relative} produced no expected answers"
    );

    // Strip only the group-direction answer field from each test.
    // Stripping both `ct` and `pt` would lose the input field.
    let mut prompt = slice.clone();
    strip_aes_answers_in_place(&mut prompt);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));
    let got = collect_aes_response(&response);

    assert_eq!(
        got.len(),
        expected.len(),
        "{label}: response has {} cases, expected {}",
        got.len(),
        expected.len()
    );
    for ((exp_tc, exp_field, exp_val), (got_tc, got_val)) in expected.iter().zip(got.iter()) {
        assert_eq!(exp_tc, got_tc, "{label}: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "{label}: {exp_field} mismatch for tcId {exp_tc}"
        );
    }
}

/// Remove the direction-specific answer field from each test inside
/// every `testGroups` entry, leaving the input field intact. Prompts
/// fed into the dispatcher must not contain the answer they are being
/// asked to reproduce.
fn strip_aes_answers_in_place(v: &mut JsonValue) {
    let JsonValue::Object(root_kvs) = v else {
        return;
    };
    let groups = root_kvs.iter_mut().find_map(|(k, val)| {
        if k == "testGroups" {
            if let JsonValue::Array(a) = val {
                Some(a)
            } else {
                None
            }
        } else {
            None
        }
    });
    let Some(groups) = groups else {
        return;
    };
    for g in groups.iter_mut() {
        let JsonValue::Object(g_kvs) = g else {
            continue;
        };
        // Borrow direction first (immutable) by cloning into a String.
        let direction: String = g_kvs
            .iter()
            .find_map(|(k, val)| {
                if k == "direction" {
                    val.as_str().map(str::to_string)
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let answer_field = match direction.as_str() {
            "encrypt" => "ct",
            "decrypt" => "pt",
            _ => continue,
        };
        // Now find and mutate `tests`.
        let tests = g_kvs.iter_mut().find_map(|(k, val)| {
            if k == "tests" {
                if let JsonValue::Array(a) = val {
                    Some(a)
                } else {
                    None
                }
            } else {
                None
            }
        });
        let Some(tests) = tests else {
            continue;
        };
        for t in tests.iter_mut() {
            if let JsonValue::Object(kvs) = t {
                kvs.retain(|(k, _)| k != answer_field);
            }
        }
    }
}

#[test]
fn aes_ecb_aft_round_trip() {
    assert_aes_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-ECB-1.0/kat-slice.json",
        "ACVP-AES-ECB",
    );
}

#[test]
fn aes_cbc_aft_round_trip() {
    assert_aes_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CBC-1.0/kat-slice.json",
        "ACVP-AES-CBC",
    );
}

#[test]
fn aes_ctr_aft_round_trip() {
    assert_aes_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CTR-1.0/kat-slice.json",
        "ACVP-AES-CTR",
    );
}

// ----------------------------------------------------------------------
// AES AEAD / key-wrap AFT (R14-B): GCM / CCM / KW / KWP
//
// These modes have richer response shapes than ECB/CBC/CTR:
//
// - GCM encrypt → {tcId, ct, tag}
// - GCM decrypt → {tcId, testPassed} (+ pt if testPassed)
// - CCM encrypt → {tcId, ct}  (ct includes appended tag)
// - CCM/KW/KWP decrypt → {tcId, testPassed} (+ pt if testPassed)
// - KW/KWP encrypt → {tcId, ct}
//
// The test helper collects expected answers from the vendored slice
// (which includes all fields including testPassed), strips them from
// the prompt, dispatches, and then compares the response.
// ----------------------------------------------------------------------

/// An expected answer from a single AEAD/wrap test case.
#[derive(Debug)]
enum AeadExpected {
    /// Encrypt: expected ct (and optionally tag for GCM).
    Encrypt {
        tc_id: i64,
        ct: String,
        tag: Option<String>,
    },
    /// Decrypt/unwrap: expected testPassed and (if passed) pt.
    Decrypt {
        tc_id: i64,
        test_passed: bool,
        pt: Option<String>,
    },
}

fn collect_aead_expected(v: &JsonValue) -> Vec<AeadExpected> {
    let mut out = Vec::new();
    let Some(groups) = v.get("testGroups").and_then(JsonValue::as_array) else {
        return out;
    };
    for g in groups {
        let direction = g.get("direction").and_then(JsonValue::as_str).unwrap_or("");
        let Some(tests) = g.get("tests").and_then(JsonValue::as_array) else {
            continue;
        };
        for t in tests {
            let Some(tc_id) = t.get("tcId").and_then(JsonValue::as_i64) else {
                continue;
            };
            match direction {
                "encrypt" => {
                    let ct = t
                        .get("ct")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    let tag = t.get("tag").and_then(JsonValue::as_str).map(str::to_string);
                    out.push(AeadExpected::Encrypt { tc_id, ct, tag });
                }
                "decrypt" => {
                    let test_passed = t
                        .get("testPassed")
                        .and_then(JsonValue::as_bool)
                        .unwrap_or(true);
                    let pt = if test_passed {
                        t.get("pt").and_then(JsonValue::as_str).map(str::to_string)
                    } else {
                        None
                    };
                    out.push(AeadExpected::Decrypt {
                        tc_id,
                        test_passed,
                        pt,
                    });
                }
                _ => {}
            }
        }
    }
    out
}

/// Strip AEAD answer fields from the prompt:
/// - encrypt tests: remove `ct` and `tag`
/// - decrypt tests: remove `pt` and `testPassed`
fn strip_aead_answers_in_place(v: &mut JsonValue) {
    let JsonValue::Object(root_kvs) = v else {
        return;
    };
    let groups = root_kvs.iter_mut().find_map(|(k, val)| {
        if k == "testGroups" {
            if let JsonValue::Array(a) = val {
                Some(a)
            } else {
                None
            }
        } else {
            None
        }
    });
    let Some(groups) = groups else {
        return;
    };
    for g in groups.iter_mut() {
        let JsonValue::Object(g_kvs) = g else {
            continue;
        };
        let direction: String = g_kvs
            .iter()
            .find_map(|(k, val)| {
                if k == "direction" {
                    val.as_str().map(str::to_string)
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let strip_fields: &[&str] = match direction.as_str() {
            "encrypt" => &["ct", "tag"],
            "decrypt" => &["pt", "testPassed"],
            _ => continue,
        };
        let tests = g_kvs.iter_mut().find_map(|(k, val)| {
            if k == "tests" {
                if let JsonValue::Array(a) = val {
                    Some(a)
                } else {
                    None
                }
            } else {
                None
            }
        });
        let Some(tests) = tests else {
            continue;
        };
        for t in tests.iter_mut() {
            if let JsonValue::Object(kvs) = t {
                kvs.retain(|(k, _)| !strip_fields.contains(&k.as_str()));
            }
        }
    }
}

fn assert_aead_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected = collect_aead_expected(&slice);
    assert!(
        !expected.is_empty(),
        "{label}: slice {relative} produced no expected answers"
    );

    let mut prompt = slice.clone();
    strip_aead_answers_in_place(&mut prompt);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));

    // Collect response tests keyed by tcId for comparison.
    let mut resp_tests: std::collections::HashMap<i64, &JsonValue> =
        std::collections::HashMap::new();
    if let Some(groups) = response.get("testGroups").and_then(JsonValue::as_array) {
        for g in groups {
            if let Some(tests) = g.get("tests").and_then(JsonValue::as_array) {
                for t in tests {
                    if let Some(tc_id) = t.get("tcId").and_then(JsonValue::as_i64) {
                        resp_tests.insert(tc_id, t);
                    }
                }
            }
        }
    }

    assert_eq!(
        resp_tests.len(),
        expected.len(),
        "{label}: response has {} cases, expected {}",
        resp_tests.len(),
        expected.len()
    );

    for exp in &expected {
        match exp {
            AeadExpected::Encrypt { tc_id, ct, tag } => {
                let t = resp_tests
                    .get(tc_id)
                    .unwrap_or_else(|| panic!("{label}: missing tcId {tc_id} in response"));
                let got_ct = t
                    .get("ct")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_else(|| panic!("{label}: missing ct for tcId {tc_id}"));
                assert_eq!(
                    ct.to_ascii_uppercase(),
                    got_ct,
                    "{label}: ct mismatch for tcId {tc_id}"
                );
                if let Some(exp_tag) = tag {
                    let got_tag = t
                        .get("tag")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_else(|| panic!("{label}: missing tag for tcId {tc_id}"));
                    assert_eq!(
                        exp_tag.to_ascii_uppercase(),
                        got_tag,
                        "{label}: tag mismatch for tcId {tc_id}"
                    );
                }
            }
            AeadExpected::Decrypt {
                tc_id,
                test_passed,
                pt,
            } => {
                let t = resp_tests
                    .get(tc_id)
                    .unwrap_or_else(|| panic!("{label}: missing tcId {tc_id} in response"));
                let got_passed = t
                    .get("testPassed")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or_else(|| panic!("{label}: missing testPassed for tcId {tc_id}"));
                assert_eq!(
                    *test_passed, got_passed,
                    "{label}: testPassed mismatch for tcId {tc_id}"
                );
                if let Some(exp_pt) = pt {
                    let got_pt = t
                        .get("pt")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_else(|| panic!("{label}: missing pt for tcId {tc_id}"));
                    assert_eq!(
                        exp_pt.to_ascii_uppercase(),
                        got_pt,
                        "{label}: pt mismatch for tcId {tc_id}"
                    );
                }
            }
        }
    }
}

#[test]
fn aes_gcm_aft_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-GCM-1.0/kat-slice.json",
        "ACVP-AES-GCM",
    );
}

#[test]
fn aes_ccm_aft_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CCM-1.0/kat-slice.json",
        "ACVP-AES-CCM",
    );
}

#[test]
fn aes_kw_aft_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-KW-1.0/kat-slice.json",
        "ACVP-AES-KW",
    );
}

#[test]
fn aes_kwp_aft_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-KWP-1.0/kat-slice.json",
        "ACVP-AES-KWP",
    );
}

// ----------------------------------------------------------------------
// AES lifecycle (R41): encrypt-decrypt path equivalence
//
// Each lifecycle-slice.json uses a single DRBG-generated AES-256 key
// and proves encrypt→decrypt recovers the original plaintext.  For
// authenticated/wrap modes, an additional decrypt group with a
// bit-flipped tag/ciphertext proves testPassed=false detection.
// ----------------------------------------------------------------------

#[test]
fn aes_ecb_lifecycle_round_trip() {
    assert_aes_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-ECB-1.0/lifecycle-slice.json",
        "ACVP-AES-ECB-lifecycle",
    );
}

#[test]
fn aes_cbc_lifecycle_round_trip() {
    assert_aes_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CBC-1.0/lifecycle-slice.json",
        "ACVP-AES-CBC-lifecycle",
    );
}

#[test]
fn aes_ctr_lifecycle_round_trip() {
    assert_aes_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CTR-1.0/lifecycle-slice.json",
        "ACVP-AES-CTR-lifecycle",
    );
}

#[test]
fn aes_gcm_lifecycle_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-GCM-1.0/lifecycle-slice.json",
        "ACVP-AES-GCM-lifecycle",
    );
}

#[test]
fn aes_ccm_lifecycle_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CCM-1.0/lifecycle-slice.json",
        "ACVP-AES-CCM-lifecycle",
    );
}

#[test]
fn aes_kw_lifecycle_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-KW-1.0/lifecycle-slice.json",
        "ACVP-AES-KW-lifecycle",
    );
}

#[test]
fn aes_kwp_lifecycle_round_trip() {
    assert_aead_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-KWP-1.0/lifecycle-slice.json",
        "ACVP-AES-KWP-lifecycle",
    );
}

// ----------------------------------------------------------------------
// AES MCT (R15): ECB / CBC Monte Carlo Tests
//
// Each MCT group has exactly one test with initial parameters.
// The handler runs the 100×1000 iteration loop and produces a
// `resultsArray` with 100 entries. The vendored mct-slice.json
// files contain only the first 5 entries (ra_limit=5), so we
// compare only those.
// ----------------------------------------------------------------------

/// Collect expected MCT resultsArray entries from a vendored slice.
/// Returns `(tcId, Vec<(key, value)>)` for each entry, so we can
/// compare field-by-field in a case-insensitive way.
/// One entry in a resultsArray: field name → hex value (uppercased).
type MctEntry = Vec<(String, String)>;

fn collect_mct_expected(v: &JsonValue) -> Vec<(i64, Vec<MctEntry>)> {
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
            let Some(ra) = t.get("resultsArray").and_then(JsonValue::as_array) else {
                continue;
            };
            let entries: Vec<Vec<(String, String)>> = ra
                .iter()
                .map(|entry| {
                    let JsonValue::Object(kvs) = entry else {
                        return Vec::new();
                    };
                    kvs.iter()
                        .filter_map(|(k, val)| {
                            val.as_str().map(|s| (k.clone(), s.to_ascii_uppercase()))
                        })
                        .collect()
                })
                .collect();
            out.push((tc_id, entries));
        }
    }
    out
}

fn assert_mct_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected = collect_mct_expected(&slice);
    assert!(
        !expected.is_empty(),
        "{label}: slice {relative} produced no expected MCT answers"
    );

    // Strip resultsArray from the prompt.
    let mut prompt = slice.clone();
    strip_field(&mut prompt, "resultsArray");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));

    // Collect response resultsArray entries.
    let got = collect_mct_expected(&response);

    assert_eq!(
        got.len(),
        expected.len(),
        "{label}: response has {} MCT tests, expected {}",
        got.len(),
        expected.len()
    );

    for (exp, got_entry) in expected.iter().zip(got.iter()) {
        assert_eq!(
            exp.0, got_entry.0,
            "{label}: tcId mismatch"
        );
        let exp_entries = &exp.1;
        let got_entries = &got_entry.1;
        // Only compare the first N entries (the vendored slice is trimmed).
        let compare_len = exp_entries.len();
        assert!(
            got_entries.len() >= compare_len,
            "{label}: tcId {}: response has {} resultsArray entries, expected at least {}",
            exp.0,
            got_entries.len(),
            compare_len
        );
        for (idx, (exp_ra, got_ra)) in exp_entries
            .iter()
            .zip(got_entries.iter())
            .enumerate()
        {
            for (exp_k, exp_v) in exp_ra {
                let got_v = got_ra
                    .iter()
                    .find(|(k, _)| k == exp_k)
                    .map_or_else(
                        || {
                            panic!(
                                "{label}: tcId {} resultsArray[{idx}]: missing field {exp_k:?}",
                                exp.0
                            )
                        },
                        |(_, v)| v.as_str(),
                    );
                assert_eq!(
                    exp_v, got_v,
                    "{label}: tcId {} resultsArray[{idx}] field {exp_k:?} mismatch",
                    exp.0
                );
            }
        }
    }
}

#[test]
fn aes_ecb_mct_round_trip() {
    assert_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-ECB-1.0/mct-slice.json",
        "ACVP-AES-ECB-MCT",
    );
}

#[test]
fn aes_cbc_mct_round_trip() {
    assert_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ACVP-AES-CBC-1.0/mct-slice.json",
        "ACVP-AES-CBC-MCT",
    );
}

// ----------------------------------------------------------------------
// SHA-3 MCT (R30): Monte Carlo Test for all four SHA-3 variants
// ----------------------------------------------------------------------

#[test]
fn sha3_224_mct_round_trip() {
    assert_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-224-2.0/mct-slice.json",
        "SHA3-224-MCT",
    );
}

#[test]
fn sha3_256_mct_round_trip() {
    assert_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-256-2.0/mct-slice.json",
        "SHA3-256-MCT",
    );
}

#[test]
fn sha3_384_mct_round_trip() {
    assert_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-384-2.0/mct-slice.json",
        "SHA3-384-MCT",
    );
}

#[test]
fn sha3_512_mct_round_trip() {
    assert_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-512-2.0/mct-slice.json",
        "SHA3-512-MCT",
    );
}

// ----------------------------------------------------------------------
// SHA-3 LDT (R38): Large Data Test, repeating-pattern expansion
// ----------------------------------------------------------------------

#[test]
fn sha3_224_ldt_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-224-2.0/ldt-slice.json",
        "md",
        "SHA3-224-LDT",
    );
}

#[test]
fn sha3_256_ldt_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-256-2.0/ldt-slice.json",
        "md",
        "SHA3-256-LDT",
    );
}

#[test]
fn sha3_384_ldt_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-384-2.0/ldt-slice.json",
        "md",
        "SHA3-384-LDT",
    );
}

#[test]
fn sha3_512_ldt_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHA3-512-2.0/ldt-slice.json",
        "md",
        "SHA3-512-LDT",
    );
}

// ----------------------------------------------------------------------
// CMAC-AES AFT (R16): gen + ver
//
// `gen` groups produce a `mac` answer; `ver` groups produce
// `testPassed`. The test helper strips the answer field per-direction,
// dispatches, and compares.
// ----------------------------------------------------------------------

/// Expected answer from a CMAC test case.
#[derive(Debug)]
enum CmacExpected {
    Gen { tc_id: i64, mac: String },
    Ver { tc_id: i64, test_passed: bool },
}

fn collect_cmac_expected(v: &JsonValue) -> Vec<CmacExpected> {
    let mut out = Vec::new();
    let Some(groups) = v.get("testGroups").and_then(JsonValue::as_array) else {
        return out;
    };
    for g in groups {
        let direction = g
            .get("direction")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let Some(tests) = g.get("tests").and_then(JsonValue::as_array) else {
            continue;
        };
        for t in tests {
            let Some(tc_id) = t.get("tcId").and_then(JsonValue::as_i64) else {
                continue;
            };
            match direction {
                "gen" => {
                    let mac = t
                        .get("mac")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    out.push(CmacExpected::Gen { tc_id, mac });
                }
                "ver" => {
                    let test_passed = t
                        .get("testPassed")
                        .and_then(JsonValue::as_bool)
                        .unwrap_or(true);
                    out.push(CmacExpected::Ver { tc_id, test_passed });
                }
                _ => {}
            }
        }
    }
    out
}

/// Strip CMAC answer fields from the prompt:
/// - gen: remove `mac`
/// - ver: remove `testPassed`
fn strip_cmac_answers_in_place(v: &mut JsonValue) {
    let JsonValue::Object(root_kvs) = v else {
        return;
    };
    let groups = root_kvs.iter_mut().find_map(|(k, val)| {
        if k == "testGroups" {
            if let JsonValue::Array(a) = val {
                Some(a)
            } else {
                None
            }
        } else {
            None
        }
    });
    let Some(groups) = groups else {
        return;
    };
    for g in groups.iter_mut() {
        let JsonValue::Object(g_kvs) = g else {
            continue;
        };
        let direction: String = g_kvs
            .iter()
            .find_map(|(k, val)| {
                if k == "direction" {
                    val.as_str().map(str::to_string)
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let strip_fields: &[&str] = match direction.as_str() {
            "gen" => &["mac"],
            "ver" => &["testPassed"],
            _ => continue,
        };
        let tests = g_kvs.iter_mut().find_map(|(k, val)| {
            if k == "tests" {
                if let JsonValue::Array(a) = val {
                    Some(a)
                } else {
                    None
                }
            } else {
                None
            }
        });
        let Some(tests) = tests else {
            continue;
        };
        for t in tests.iter_mut() {
            if let JsonValue::Object(kvs) = t {
                kvs.retain(|(k, _)| !strip_fields.contains(&k.as_str()));
            }
        }
    }
}

fn assert_cmac_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected = collect_cmac_expected(&slice);
    assert!(
        !expected.is_empty(),
        "{label}: slice {relative} produced no expected answers"
    );

    let mut prompt = slice.clone();
    strip_cmac_answers_in_place(&mut prompt);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));

    // Collect response tests keyed by tcId.
    let mut resp_tests: std::collections::HashMap<i64, &JsonValue> =
        std::collections::HashMap::new();
    if let Some(groups) = response.get("testGroups").and_then(JsonValue::as_array) {
        for g in groups {
            if let Some(tests) = g.get("tests").and_then(JsonValue::as_array) {
                for t in tests {
                    if let Some(tc_id) = t.get("tcId").and_then(JsonValue::as_i64) {
                        resp_tests.insert(tc_id, t);
                    }
                }
            }
        }
    }

    assert_eq!(
        resp_tests.len(),
        expected.len(),
        "{label}: response has {} cases, expected {}",
        resp_tests.len(),
        expected.len()
    );

    for exp in &expected {
        match exp {
            CmacExpected::Gen { tc_id, mac } => {
                let t = resp_tests
                    .get(tc_id)
                    .unwrap_or_else(|| panic!("{label}: missing tcId {tc_id}"));
                let got_mac = t
                    .get("mac")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_else(|| panic!("{label}: missing mac for tcId {tc_id}"));
                assert_eq!(
                    mac.to_ascii_uppercase(),
                    got_mac,
                    "{label}: mac mismatch for tcId {tc_id}"
                );
            }
            CmacExpected::Ver { tc_id, test_passed } => {
                let t = resp_tests
                    .get(tc_id)
                    .unwrap_or_else(|| panic!("{label}: missing tcId {tc_id}"));
                let got_passed = t
                    .get("testPassed")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or_else(|| {
                        panic!("{label}: missing testPassed for tcId {tc_id}")
                    });
                assert_eq!(
                    *test_passed, got_passed,
                    "{label}: testPassed mismatch for tcId {tc_id}"
                );
            }
        }
    }
}

#[test]
fn cmac_aes_aft_round_trip() {
    assert_cmac_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/CMAC-AES-1.0/kat-slice.json",
        "CMAC-AES",
    );
}

// ----------------------------------------------------------------------
// CMAC-AES lifecycle (R42): gen→ver path consistency
//
// Lifecycle slice uses a single DRBG-generated AES-256 key, proving
// that gen produces the correct MAC and ver detects both valid and
// invalid (bit-flipped) MACs.
// ----------------------------------------------------------------------

#[test]
fn cmac_aes_lifecycle_round_trip() {
    assert_cmac_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/CMAC-AES-1.0/lifecycle-slice.json",
        "CMAC-AES-lifecycle",
    );
}

// ----------------------------------------------------------------------
// DRBG families (revision 1.0, answer field `returnedBits`)
// R17 — CTR_DRBG (AES-128/192/256, ±df, ±pr),
//        Hash_DRBG (SHA2-256/384/512, ±pr),
//        HMAC_DRBG (SHA2-256/384/512, ±pr)
// ----------------------------------------------------------------------

#[test]
fn ctr_drbg_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ctrDRBG-1.0/kat-slice.json",
        "returnedBits",
        "ctrDRBG",
    );
}

#[test]
fn hash_drbg_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/hashDRBG-1.0/kat-slice.json",
        "returnedBits",
        "hashDRBG",
    );
}

#[test]
fn hmac_drbg_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/hmacDRBG-1.0/kat-slice.json",
        "returnedBits",
        "hmacDRBG",
    );
}

// ----------------------------------------------------------------------
// Verification round-trip helper
//
// For ACVP families where the answer is `testPassed` (a boolean),
// we strip the field, dispatch, and compare the boolean result for
// every test case.
// ----------------------------------------------------------------------

/// Collect `(tcId, testPassed)` pairs from every test in every group.
fn collect_bool_answers(v: &JsonValue) -> Vec<(i64, bool)> {
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
            let Some(passed) = t.get("testPassed").and_then(JsonValue::as_bool) else {
                continue;
            };
            out.push((tc_id, passed));
        }
    }
    out
}

/// Round-trip driver for verification tests where the answer field is
/// `testPassed` (a boolean). Strips `testPassed` (and optionally
/// `reason`) from the prompt, dispatches, and asserts that every
/// test case's `testPassed` matches the vendored reference.
fn assert_bool_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected = collect_bool_answers(&slice);
    assert!(
        !expected.is_empty(),
        "{label}: slice {relative} has no test cases with testPassed"
    );

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "testPassed");
    strip_field(&mut prompt, "reason");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));
    let got = collect_bool_answers(&response);

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
            exp_val, got_val,
            "{label}: testPassed mismatch for tcId {exp_tc}"
        );
    }
}

// ----------------------------------------------------------------------
// ECDSA SigVer + KeyVer (R18: P-256 / SHA2-256, FIPS186-5)
// ----------------------------------------------------------------------

#[test]
fn ecdsa_sigver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-sigVer-FIPS186-5/kat-slice.json",
        "ECDSA-sigVer",
    );
}

#[test]
fn ecdsa_keyver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-keyVer-FIPS186-5/kat-slice.json",
        "ECDSA-keyVer",
    );
}

// ----------------------------------------------------------------------
// ECDSA SigGen (R19: P-256 / SHA2-256, FIPS186-5, deterministic k)
// Answer fields: `r` and `s` (both hex strings).
// ----------------------------------------------------------------------

/// Round-trip driver for ECDSA SigGen where answers are two separate
/// hex string fields (`r` and `s`).
fn assert_ecdsa_siggen_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected_r = collect_answers(&slice, "r");
    let expected_s = collect_answers(&slice, "s");
    assert!(
        !expected_r.is_empty(),
        "{label}: no test cases with r/s fields"
    );

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "r");
    strip_field(&mut prompt, "s");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));
    let got_r = collect_answers(&response, "r");
    let got_s = collect_answers(&response, "s");

    assert_eq!(got_r.len(), expected_r.len(), "{label}: r count mismatch");
    assert_eq!(got_s.len(), expected_s.len(), "{label}: s count mismatch");

    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_r.iter().zip(got_r.iter()) {
        assert_eq!(exp_tc, got_tc, "{label}: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "{label}: r mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_s.iter().zip(got_s.iter()) {
        assert_eq!(exp_tc, got_tc, "{label}: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "{label}: s mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn ecdsa_siggen_round_trip() {
    assert_ecdsa_siggen_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-sigGen-FIPS186-5/kat-slice.json",
        "ECDSA-sigGen",
    );
}

// ----------------------------------------------------------------------
// ECDSA KeyGen (R29: P-256, FIPS186-5, deterministic derive_public_key)
// ----------------------------------------------------------------------

/// ECDSA KeyGen produces two answer fields (qx, qy).
/// Verify both independently.
#[test]
fn ecdsa_keygen_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-keyGen-FIPS186-5/kat-slice.json",
    );

    let expected_qx = collect_answers(&slice, "qx");
    let expected_qy = collect_answers(&slice, "qy");
    assert!(!expected_qx.is_empty(), "ECDSA-keyGen: no qx fields");

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "qx");
    strip_field(&mut prompt, "qy");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("ECDSA-keyGen: dispatch failed: {e}"));

    let got_qx = collect_answers(&response, "qx");
    let got_qy = collect_answers(&response, "qy");

    assert_eq!(got_qx.len(), expected_qx.len(), "ECDSA-keyGen: qx count mismatch");
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_qx.iter().zip(got_qx.iter()) {
        assert_eq!(exp_tc, got_tc, "ECDSA-keyGen: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "ECDSA-keyGen: qx mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_qy.iter().zip(got_qy.iter()) {
        assert_eq!(exp_tc, got_tc, "ECDSA-keyGen: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "ECDSA-keyGen: qy mismatch for tcId {exp_tc}"
        );
    }
}

// ----------------------------------------------------------------------
// ECDSA Lifecycle (R36: keyGen + sigGen + sigVer, shared keys)
// ----------------------------------------------------------------------

#[test]
fn ecdsa_lifecycle_keygen_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-keyGen-FIPS186-5/lifecycle-slice.json",
    );
    let expected_qx = collect_answers(&slice, "qx");
    let expected_qy = collect_answers(&slice, "qy");
    assert!(!expected_qx.is_empty(), "ECDSA-keyGen-lifecycle: no qx");

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "qx");
    strip_field(&mut prompt, "qy");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("ECDSA-keyGen-lifecycle: dispatch failed: {e}"));

    let got_qx = collect_answers(&response, "qx");
    let got_qy = collect_answers(&response, "qy");
    assert_eq!(got_qx.len(), expected_qx.len());
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_qx.iter().zip(got_qx.iter()) {
        assert_eq!(exp_tc, got_tc);
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "ECDSA-keyGen-lifecycle: qx mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_qy.iter().zip(got_qy.iter()) {
        assert_eq!(exp_tc, got_tc);
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "ECDSA-keyGen-lifecycle: qy mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn ecdsa_lifecycle_siggen_round_trip() {
    assert_ecdsa_siggen_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-sigGen-FIPS186-5/lifecycle-slice.json",
        "ECDSA-sigGen-lifecycle",
    );
}

#[test]
fn ecdsa_lifecycle_sigver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-sigVer-FIPS186-5/lifecycle-slice.json",
        "ECDSA-sigVer-lifecycle",
    );
}

// ----------------------------------------------------------------------
// EdDSA SigVer + KeyVer (R18: ED-25519, pure, 1.0)
// ----------------------------------------------------------------------

#[test]
fn eddsa_sigver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-sigVer-1.0/kat-slice.json",
        "EDDSA-sigVer",
    );
}

#[test]
fn eddsa_keyver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-keyVer-1.0/kat-slice.json",
        "EDDSA-keyVer",
    );
}

// ----------------------------------------------------------------------
// EdDSA SigGen (R19: ED-25519, pure, 1.0, deterministic)
// ----------------------------------------------------------------------

#[test]
fn eddsa_siggen_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-sigGen-1.0/kat-slice.json",
        "signature",
        "EDDSA-sigGen",
    );
}

// ----------------------------------------------------------------------
// EdDSA KeyGen (R28: ED-25519, 1.0, deterministic keygen_internal)
// ----------------------------------------------------------------------

#[test]
fn eddsa_keygen_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-keyGen-1.0/kat-slice.json",
        "q",
        "EDDSA-keyGen",
    );
}

// ----------------------------------------------------------------------
// EdDSA Lifecycle (R35: keyGen + sigGen + sigVer, shared seeds)
// ----------------------------------------------------------------------

#[test]
fn eddsa_lifecycle_keygen_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-keyGen-1.0/lifecycle-slice.json",
        "q",
        "EDDSA-keyGen-lifecycle",
    );
}

#[test]
fn eddsa_lifecycle_siggen_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-sigGen-1.0/lifecycle-slice.json",
        "signature",
        "EDDSA-sigGen-lifecycle",
    );
}

#[test]
fn eddsa_lifecycle_sigver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-sigVer-1.0/lifecycle-slice.json",
        "EDDSA-sigVer-lifecycle",
    );
}

// ----------------------------------------------------------------------
// RSA SigVer (R18: RSA-2048 / PKCS#1v1.5 / SHA2-256, FIPS186-5)
// ----------------------------------------------------------------------

#[test]
fn rsa_sigver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-sigVer-FIPS186-5/kat-slice.json",
        "RSA-sigVer",
    );
}

#[test]
fn rsa_pss_sigver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-sigVer-FIPS186-5/pss-kat-slice.json",
        "RSA-PSS-sigVer",
    );
}

// ----------------------------------------------------------------------
// SP 800-108r1 KBKDF (R20: counter / feedback / double pipeline, answer
// field `keyOut`)
// ----------------------------------------------------------------------

#[test]
fn kbkdf_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KDF-1.0/kat-slice.json",
        "keyOut",
        "KDF-KBKDF",
    );
}

// ----------------------------------------------------------------------
// RSA DecryptionPrimitive (R21: RSADP, SP 800-56Br2, modulo=2048,
// answer fields `testPassed` + `pt` on pass)
// ----------------------------------------------------------------------

/// Shared assertion for the DecryptionPrimitive shape: each test case
/// carries `testPassed` (bool) and `pt` (hex, only when `testPassed`
/// is `true`).
fn assert_decprim_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);

    // Collect expected (tcId → (testPassed, Option<pt>))
    let mut expected: Vec<(i64, bool, Option<String>)> = Vec::new();
    for g in slice.get("testGroups").unwrap().as_array().unwrap() {
        for t in g.get("tests").unwrap().as_array().unwrap() {
            let tc = t.get("tcId").unwrap().as_i64().unwrap();
            let passed = t.get("testPassed").unwrap().as_bool().unwrap();
            let pt = t.get("pt").and_then(JsonValue::as_str).map(str::to_string);
            expected.push((tc, passed, pt));
        }
    }
    assert!(!expected.is_empty(), "{label}: no test cases found");

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "testPassed");
    strip_field(&mut prompt, "pt");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));

    let mut got: Vec<(i64, bool, Option<String>)> = Vec::new();
    for g in response.get("testGroups").unwrap().as_array().unwrap() {
        for t in g.get("tests").unwrap().as_array().unwrap() {
            let tc = t.get("tcId").unwrap().as_i64().unwrap();
            let passed = t.get("testPassed").unwrap().as_bool().unwrap();
            let pt = t.get("pt").and_then(JsonValue::as_str).map(str::to_string);
            got.push((tc, passed, pt));
        }
    }

    assert_eq!(got.len(), expected.len(), "{label}: case count mismatch");
    for (e, g) in expected.iter().zip(got.iter()) {
        assert_eq!(e.0, g.0, "{label}: tcId mismatch");
        assert_eq!(e.1, g.1, "{label}: testPassed mismatch for tcId {}", e.0);
        match (&e.2, &g.2) {
            (Some(exp), Some(got_pt)) => {
                assert_eq!(
                    exp.to_ascii_uppercase(),
                    *got_pt,
                    "{label}: pt mismatch for tcId {}",
                    e.0
                );
            }
            (None, None) => {}
            _ => panic!(
                "{label}: pt presence mismatch for tcId {} (expected {:?}, got {:?})",
                e.0,
                e.2.is_some(),
                g.2.is_some()
            ),
        }
    }
}

#[test]
fn rsa_decprim_round_trip() {
    assert_decprim_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-decryptionPrimitive-Sp800-56Br2/kat-slice.json",
        "RSA-decPrim",
    );
}

// ----------------------------------------------------------------------
// RSA SignaturePrimitive (testPassed + signature)
// ----------------------------------------------------------------------

/// Like `assert_decprim_round_trip` but checks `signature` instead
/// of `pt`.
fn assert_sigprim_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);

    // Collect expected (tcId, testPassed, Option<signature>).
    let mut expected: Vec<(i64, bool, Option<String>)> = Vec::new();
    for g in slice.get("testGroups").unwrap().as_array().unwrap() {
        for t in g.get("tests").unwrap().as_array().unwrap() {
            let tc = t.get("tcId").unwrap().as_i64().unwrap();
            let passed = t.get("testPassed").unwrap().as_bool().unwrap();
            let sig = t
                .get("signature")
                .and_then(JsonValue::as_str)
                .map(str::to_string);
            expected.push((tc, passed, sig));
        }
    }
    assert!(!expected.is_empty(), "{label}: no test cases found");

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "testPassed");
    strip_field(&mut prompt, "signature");
    strip_field(&mut prompt, "deferred");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));

    let mut got: Vec<(i64, bool, Option<String>)> = Vec::new();
    for g in response.get("testGroups").unwrap().as_array().unwrap() {
        for t in g.get("tests").unwrap().as_array().unwrap() {
            let tc = t.get("tcId").unwrap().as_i64().unwrap();
            let passed = t.get("testPassed").unwrap().as_bool().unwrap();
            let sig = t
                .get("signature")
                .and_then(JsonValue::as_str)
                .map(str::to_string);
            got.push((tc, passed, sig));
        }
    }

    assert_eq!(got.len(), expected.len(), "{label}: case count mismatch");
    for (exp, actual) in expected.iter().zip(got.iter()) {
        assert_eq!(exp.0, actual.0, "{label}: tcId mismatch");
        assert_eq!(
            exp.1, actual.1,
            "{label}: testPassed mismatch for tcId {}",
            exp.0
        );
        match (&exp.2, &actual.2) {
            (Some(exp_sig), Some(got_sig)) => {
                assert_eq!(
                    exp_sig.to_ascii_uppercase(),
                    *got_sig,
                    "{label}: signature mismatch for tcId {}",
                    exp.0
                );
            }
            (None, None) => {}
            _ => panic!(
                "{label}: signature presence mismatch for tcId {} (expected {:?}, got {:?})",
                exp.0,
                exp.2.is_some(),
                actual.2.is_some()
            ),
        }
    }
}

#[test]
fn rsa_sigprim_round_trip() {
    assert_sigprim_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-SignaturePrimitive-2.0/kat-slice.json",
        "RSA-sigPrim",
    );
}

// ----------------------------------------------------------------------
// TLS v1.2 KDF (RFC 7627, answer fields `masterSecret` + `keyBlock`)
// ----------------------------------------------------------------------

/// TLS v1.2 KDF round-trip: check both `masterSecret` and `keyBlock`
/// in every test case across all groups.
fn assert_tls12_kdf_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected_ms = collect_answers(&slice, "masterSecret");
    let expected_kb = collect_answers(&slice, "keyBlock");
    assert!(
        !expected_ms.is_empty(),
        "{label}: no masterSecret answers"
    );
    assert_eq!(
        expected_ms.len(),
        expected_kb.len(),
        "{label}: masterSecret/keyBlock count mismatch"
    );

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "masterSecret");
    strip_field(&mut prompt, "keyBlock");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));
    let got_ms = collect_answers(&response, "masterSecret");
    let got_kb = collect_answers(&response, "keyBlock");

    assert_eq!(
        got_ms.len(),
        expected_ms.len(),
        "{label}: response has {} masterSecret, expected {}",
        got_ms.len(),
        expected_ms.len()
    );
    for (i, ((exp_tc, exp_ms), (got_tc, got_ms))) in
        expected_ms.iter().zip(got_ms.iter()).enumerate()
    {
        assert_eq!(exp_tc, got_tc, "{label}: tcId mismatch at {i}");
        assert_eq!(
            exp_ms.to_ascii_uppercase(),
            *got_ms,
            "{label}: masterSecret mismatch for tcId {exp_tc}"
        );
        let (_, exp_kb) = &expected_kb[i];
        let (_, got_kb_val) = &got_kb[i];
        assert_eq!(
            exp_kb.to_ascii_uppercase(),
            *got_kb_val,
            "{label}: keyBlock mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn tls12_kdf_rfc7627_round_trip() {
    assert_tls12_kdf_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/TLS-v1.2-KDF-RFC7627/kat-slice.json",
        "TLS-v1.2-KDF-RFC7627",
    );
}

// ----------------------------------------------------------------------
// kdf-components / tls (standard TLS 1.2 KDF, non-EMS)
// ----------------------------------------------------------------------

#[test]
fn kdf_comp_tls_round_trip() {
    assert_tls12_kdf_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/kdf-components-tls-1.0/kat-slice.json",
        "kdf-components-tls",
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

// ----------------------------------------------------------------------
// RSA SigGen (R25: PKCS#1v1.5 + PSS, FIPS186-5, answer = `signature`)
// ----------------------------------------------------------------------

/// Round-trip driver for RSA SigGen: the answer field is `signature`.
fn assert_rsa_siggen_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);

    let expected_sig = collect_answers(&slice, "signature");
    assert!(
        !expected_sig.is_empty(),
        "{label}: no test cases with signature field"
    );

    let mut prompt = slice.clone();
    strip_field(&mut prompt, "signature");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));

    let got_sig = collect_answers(&response, "signature");
    assert_eq!(
        got_sig.len(),
        expected_sig.len(),
        "{label}: signature count mismatch"
    );

    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_sig.iter().zip(got_sig.iter()) {
        assert_eq!(exp_tc, got_tc, "{label}: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "{label}: signature mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn rsa_siggen_round_trip() {
    assert_rsa_siggen_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-sigGen-FIPS186-5/kat-slice.json",
        "RSA-sigGen",
    );
}

#[test]
fn rsa_siggen_cross_round_trip() {
    assert_rsa_siggen_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-sigGen-FIPS186-5/cross-kat-slice.json",
        "RSA-sigGen-cross",
    );
}

// ----------------------------------------------------------------------
// RSA lifecycle cross-validation (R37/R39: keyGen→sigGen→sigVer)
// ----------------------------------------------------------------------

#[test]
fn rsa_lifecycle_keygen_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-keyGen-FIPS186-5/lifecycle-slice.json",
    );

    let expected_n = collect_answers(&slice, "n");
    let expected_d = collect_answers(&slice, "d");
    let expected_p = collect_answers(&slice, "p");
    let expected_q = collect_answers(&slice, "q");

    assert!(
        !expected_n.is_empty(),
        "RSA keyGen lifecycle: no tests with field n"
    );

    let mut prompt = slice.clone();
    for field in &["n", "d", "e", "p", "q", "dmp1", "dmq1", "iqmp"] {
        strip_field(&mut prompt, field);
    }

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("RSA keyGen lifecycle: dispatch failed: {e}"));

    let got_n = collect_answers(&response, "n");
    let got_d = collect_answers(&response, "d");
    let got_p = collect_answers(&response, "p");
    let got_q = collect_answers(&response, "q");

    assert_eq!(
        got_n.len(),
        expected_n.len(),
        "RSA keyGen lifecycle: n count mismatch"
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_n.iter().zip(got_n.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen lifecycle: tcId mismatch for n");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen lifecycle: n mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_d.iter().zip(got_d.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen lifecycle: tcId mismatch for d");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen lifecycle: d mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_p.iter().zip(got_p.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen lifecycle: tcId mismatch for p");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen lifecycle: p mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_q.iter().zip(got_q.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen lifecycle: tcId mismatch for q");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen lifecycle: q mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn rsa_lifecycle_siggen_round_trip() {
    assert_rsa_siggen_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-sigGen-FIPS186-5/lifecycle-slice.json",
        "RSA-sigGen-lifecycle",
    );
}

#[test]
fn rsa_lifecycle_sigver_round_trip() {
    assert_bool_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-sigVer-FIPS186-5/lifecycle-slice.json",
        "RSA-sigVer-lifecycle",
    );
}

// ----------------------------------------------------------------------
// KAS-ECC-SSC (R26: P-256 ECDH shared secret, answer field `z`)
// ----------------------------------------------------------------------

#[test]
fn kas_ecc_ssc_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KAS-ECC-SSC-Sp800-56Ar3/kat-slice.json",
        "z",
        "KAS-ECC-SSC",
    );
}

#[test]
fn kas_ecc_ssc_lifecycle_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KAS-ECC-SSC-Sp800-56Ar3/lifecycle-slice.json",
        "z",
        "KAS-ECC-SSC-lifecycle",
    );
}

// ----------------------------------------------------------------------
// RSA OAEP encrypt/decrypt (R27: RSA-2048 / SHA2-256, RFC8017)
// ----------------------------------------------------------------------

/// The OAEP slice contains two groups with different answer fields:
/// - encrypt (direction=encrypt) → answer field `ct`
/// - decrypt (direction=decrypt) → answer fields `pt`, `ptLen`
///
/// We strip answer fields *per-group* (encrypt: strip `ct` from its
/// tests; decrypt: strip `pt`+`ptLen` from its tests), then dispatch
/// and verify each direction's outputs.
fn strip_oaep_answers(prompt: &mut JsonValue) {
    let JsonValue::Object(top) = prompt else {
        return;
    };
    let Some((_, groups_val)) = top.iter_mut().find(|(k, _)| k == "testGroups") else {
        return;
    };
    let JsonValue::Array(groups) = groups_val else {
        return;
    };
    for g in groups.iter_mut() {
        let dir = g
            .get("direction")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let JsonValue::Object(g_kvs) = g else {
            continue;
        };
        let Some((_, tests_val)) = g_kvs.iter_mut().find(|(k, _)| k == "tests") else {
            continue;
        };
        let JsonValue::Array(tests) = tests_val else {
            continue;
        };
        for tc in tests.iter_mut() {
            match dir.as_str() {
                "encrypt" => strip_field(tc, "ct"),
                "decrypt" => {
                    strip_field(tc, "pt");
                    strip_field(tc, "ptLen");
                }
                _ => {}
            }
        }
    }
}

/// Collect `(tcId, value)` pairs for `field` only from groups whose
/// `direction` matches.
fn collect_answers_for_direction(
    v: &JsonValue,
    field: &str,
    direction: &str,
) -> Vec<(i64, String)> {
    let mut out = Vec::new();
    let Some(groups) = v.get("testGroups").and_then(JsonValue::as_array) else {
        return out;
    };
    for g in groups {
        let dir = g
            .get("direction")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if dir != direction {
            continue;
        }
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
fn rsa_oaep_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-OAEP-RFC8017/kat-slice.json",
    );

    // Collect expected answers from the correct groups only.
    let expected_ct = collect_answers_for_direction(&slice, "ct", "encrypt");
    let expected_pt = collect_answers_for_direction(&slice, "pt", "decrypt");

    assert!(
        !expected_ct.is_empty(),
        "RSA-OAEP: no encrypt tests with field ct"
    );
    assert!(
        !expected_pt.is_empty(),
        "RSA-OAEP: no decrypt tests with field pt"
    );

    // Strip answer fields per-group to create the prompt.
    let mut prompt = slice.clone();
    strip_oaep_answers(&mut prompt);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("RSA-OAEP: dispatch failed: {e}"));

    // Verify encrypt direction (ct).  The response doesn't carry
    // `direction`, but the encrypt group is first (tgId 1) and the
    // decrypt group doesn't produce `ct`, so a global collect is fine
    // for the response side.
    let got_ct = collect_answers(&response, "ct");
    assert_eq!(
        got_ct.len(),
        expected_ct.len(),
        "RSA-OAEP encrypt: response has {} cases, expected {}",
        got_ct.len(),
        expected_ct.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_ct.iter().zip(got_ct.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP encrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP encrypt: ct mismatch for tcId {exp_tc}"
        );
    }

    // Verify decrypt direction (pt).
    let got_pt = collect_answers(&response, "pt");
    assert_eq!(
        got_pt.len(),
        expected_pt.len(),
        "RSA-OAEP decrypt: response has {} cases, expected {}",
        got_pt.len(),
        expected_pt.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_pt.iter().zip(got_pt.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP decrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP decrypt: pt mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn rsa_oaep_crt_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-OAEP-RFC8017/crt-kat-slice.json",
    );

    // Collect expected answers from the correct groups only.
    let expected_ct = collect_answers_for_direction(&slice, "ct", "encrypt");
    let expected_pt = collect_answers_for_direction(&slice, "pt", "decrypt");

    assert!(
        !expected_ct.is_empty(),
        "RSA-OAEP CRT: no encrypt tests with field ct"
    );
    assert!(
        !expected_pt.is_empty(),
        "RSA-OAEP CRT: no decrypt tests with field pt"
    );

    // Strip answer fields per-group to create the prompt.
    let mut prompt = slice.clone();
    strip_oaep_answers(&mut prompt);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("RSA-OAEP CRT: dispatch failed: {e}"));

    // Verify encrypt direction (ct).
    let got_ct = collect_answers(&response, "ct");
    assert_eq!(
        got_ct.len(),
        expected_ct.len(),
        "RSA-OAEP CRT encrypt: response has {} cases, expected {}",
        got_ct.len(),
        expected_ct.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_ct.iter().zip(got_ct.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP CRT encrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP CRT encrypt: ct mismatch for tcId {exp_tc}"
        );
    }

    // Verify decrypt direction (pt) — exercises CRT path with Bellcore.
    let got_pt = collect_answers(&response, "pt");
    assert_eq!(
        got_pt.len(),
        expected_pt.len(),
        "RSA-OAEP CRT decrypt: response has {} cases, expected {}",
        got_pt.len(),
        expected_pt.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_pt.iter().zip(got_pt.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP CRT decrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP CRT decrypt: pt mismatch for tcId {exp_tc}"
        );
    }
}

/// Combined OAEP slice: one key, three groups (encrypt, CRT decrypt,
/// non-CRT decrypt).  Groups 2 and 3 decrypt the same ciphertexts,
/// proving CRT/non-CRT path equivalence.
///
/// R43 lifecycle slice follows the same shape but uses the RSA lifecycle
/// DRBG-generated key (shared with keyGen/sigGen/sigVer lifecycle slices),
/// proving keyGen→OAEP encrypt→decrypt pipeline consistency.
#[test]
fn rsa_oaep_combined_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-OAEP-RFC8017/combined-kat-slice.json",
    );

    // Collect expected answers from the correct groups only.
    let expected_ct = collect_answers_for_direction(&slice, "ct", "encrypt");
    let expected_pt = collect_answers_for_direction(&slice, "pt", "decrypt");

    assert!(
        !expected_ct.is_empty(),
        "RSA-OAEP combined: no encrypt tests with field ct"
    );
    // Both decrypt groups contribute to expected_pt (10 total).
    assert!(
        expected_pt.len() >= 10,
        "RSA-OAEP combined: expected at least 10 decrypt tests, got {}",
        expected_pt.len()
    );

    // Strip answer fields per-group to create the prompt.
    let mut prompt = slice.clone();
    strip_oaep_answers(&mut prompt);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("RSA-OAEP combined: dispatch failed: {e}"));

    // Verify encrypt direction (ct).
    let got_ct = collect_answers(&response, "ct");
    assert_eq!(
        got_ct.len(),
        expected_ct.len(),
        "RSA-OAEP combined encrypt: response has {} cases, expected {}",
        got_ct.len(),
        expected_ct.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_ct.iter().zip(got_ct.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP combined encrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP combined encrypt: ct mismatch for tcId {exp_tc}"
        );
    }

    // Verify decrypt direction (pt) — both CRT and non-CRT groups.
    let got_pt = collect_answers(&response, "pt");
    assert_eq!(
        got_pt.len(),
        expected_pt.len(),
        "RSA-OAEP combined decrypt: response has {} cases, expected {}",
        got_pt.len(),
        expected_pt.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_pt.iter().zip(got_pt.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP combined decrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP combined decrypt: pt mismatch for tcId {exp_tc}"
        );
    }
}

/// RSA OAEP lifecycle: keyGen→encrypt→decrypt with shared DRBG key.
#[test]
fn rsa_oaep_lifecycle_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-OAEP-RFC8017/lifecycle-slice.json",
    );

    let expected_ct = collect_answers_for_direction(&slice, "ct", "encrypt");
    let expected_pt = collect_answers_for_direction(&slice, "pt", "decrypt");

    assert!(
        !expected_ct.is_empty(),
        "RSA-OAEP lifecycle: no encrypt tests with field ct"
    );
    assert!(
        expected_pt.len() >= 10,
        "RSA-OAEP lifecycle: expected at least 10 decrypt tests, got {}",
        expected_pt.len()
    );

    let mut prompt = slice.clone();
    strip_oaep_answers(&mut prompt);

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("RSA-OAEP lifecycle: dispatch failed: {e}"));

    let got_ct = collect_answers(&response, "ct");
    assert_eq!(
        got_ct.len(),
        expected_ct.len(),
        "RSA-OAEP lifecycle encrypt: response has {} cases, expected {}",
        got_ct.len(),
        expected_ct.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_ct.iter().zip(got_ct.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP lifecycle encrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP lifecycle encrypt: ct mismatch for tcId {exp_tc}"
        );
    }

    let got_pt = collect_answers(&response, "pt");
    assert_eq!(
        got_pt.len(),
        expected_pt.len(),
        "RSA-OAEP lifecycle decrypt: response has {} cases, expected {}",
        got_pt.len(),
        expected_pt.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_pt.iter().zip(got_pt.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA-OAEP lifecycle decrypt: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA-OAEP lifecycle decrypt: pt mismatch for tcId {exp_tc}"
        );
    }
}

#[test]
fn rsa_keygen_round_trip() {
    ensure_initialized().unwrap();
    let slice = load(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-keyGen-FIPS186-5/kat-slice.json",
    );

    // Collect expected answers — n is the primary key component.
    let expected_n = collect_answers(&slice, "n");
    let expected_d = collect_answers(&slice, "d");
    let expected_p = collect_answers(&slice, "p");
    let expected_q = collect_answers(&slice, "q");

    assert!(
        !expected_n.is_empty(),
        "RSA keyGen: no tests with field n"
    );

    // Strip all answer fields to create the prompt.
    let mut prompt = slice.clone();
    for field in &["n", "d", "e", "p", "q", "dmp1", "dmq1", "iqmp"] {
        strip_field(&mut prompt, field);
    }

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("RSA keyGen: dispatch failed: {e}"));

    let got_n = collect_answers(&response, "n");
    let got_d = collect_answers(&response, "d");
    let got_p = collect_answers(&response, "p");
    let got_q = collect_answers(&response, "q");

    assert_eq!(
        got_n.len(),
        expected_n.len(),
        "RSA keyGen: response has {} cases, expected {}",
        got_n.len(),
        expected_n.len()
    );
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_n.iter().zip(got_n.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen: tcId mismatch");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen: n mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_d.iter().zip(got_d.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen: tcId mismatch for d");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen: d mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_p.iter().zip(got_p.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen: tcId mismatch for p");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen: p mismatch for tcId {exp_tc}"
        );
    }
    for ((exp_tc, exp_val), (got_tc, got_val)) in expected_q.iter().zip(got_q.iter()) {
        assert_eq!(exp_tc, got_tc, "RSA keyGen: tcId mismatch for q");
        assert_eq!(
            exp_val.to_ascii_uppercase(),
            *got_val,
            "RSA keyGen: q mismatch for tcId {exp_tc}"
        );
    }
}

// ----------------------------------------------------------------------
// SHAKE MCT + VOT (R45)
// ----------------------------------------------------------------------

/// SHAKE MCT resultsArray entry: md (hex) + outLen (number).
/// The existing `collect_mct_expected` only handles string fields, but
/// SHAKE MCT also has `outLen` as a JSON number, so we need a custom
/// collector.
struct ShakeMctEntry {
    md: String,
    out_len: i64,
}

fn collect_shake_mct(v: &JsonValue) -> Vec<(i64, Vec<ShakeMctEntry>)> {
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
            let Some(ra) = t.get("resultsArray").and_then(JsonValue::as_array) else {
                continue;
            };
            let entries: Vec<ShakeMctEntry> = ra
                .iter()
                .filter_map(|entry| {
                    let md = entry.get("md").and_then(JsonValue::as_str)?;
                    let out_len = entry.get("outLen").and_then(JsonValue::as_i64)?;
                    Some(ShakeMctEntry {
                        md: md.to_ascii_uppercase(),
                        out_len,
                    })
                })
                .collect();
            out.push((tc_id, entries));
        }
    }
    out
}

fn assert_shake_mct_round_trip(relative: &str, label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);
    let expected = collect_shake_mct(&slice);
    assert!(
        !expected.is_empty(),
        "{label}: slice {relative} produced no expected SHAKE MCT answers"
    );

    // Strip resultsArray from the prompt
    let mut prompt = slice.clone();
    strip_field(&mut prompt, "resultsArray");

    let registry = dispatch::with_default_handlers();
    let response = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch failed: {e}"));

    let got = collect_shake_mct(&response);

    assert_eq!(
        got.len(),
        expected.len(),
        "{label}: response has {} MCT tests, expected {}",
        got.len(),
        expected.len()
    );

    for (exp, got_entry) in expected.iter().zip(got.iter()) {
        assert_eq!(exp.0, got_entry.0, "{label}: tcId mismatch");
        let exp_entries = &exp.1;
        let got_entries = &got_entry.1;
        let compare_len = exp_entries.len();
        assert!(
            got_entries.len() >= compare_len,
            "{label}: tcId {}: response has {} resultsArray entries, expected at least {}",
            exp.0,
            got_entries.len(),
            compare_len
        );
        for (idx, (exp_ra, got_ra)) in exp_entries.iter().zip(got_entries.iter()).enumerate() {
            assert_eq!(
                exp_ra.md, got_ra.md,
                "{label}: tcId {} resultsArray[{idx}] md mismatch",
                exp.0
            );
            assert_eq!(
                exp_ra.out_len, got_ra.out_len,
                "{label}: tcId {} resultsArray[{idx}] outLen mismatch",
                exp.0
            );
        }
    }
}

#[test]
fn shake_128_mct_round_trip() {
    assert_shake_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-128-FIPS202/mct-slice.json",
        "SHAKE-128-MCT",
    );
}

#[test]
fn shake_256_mct_round_trip() {
    assert_shake_mct_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-256-FIPS202/mct-slice.json",
        "SHAKE-256-MCT",
    );
}

#[test]
fn shake_128_vot_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-128-FIPS202/vot-slice.json",
        "md",
        "SHAKE-128-VOT",
    );
}

#[test]
fn shake_256_vot_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-256-FIPS202/vot-slice.json",
        "md",
        "SHAKE-256-VOT",
    );
}

#[test]
fn shake_128_ldt_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-128-FIPS202/ldt-slice.json",
        "md",
        "SHAKE-128-LDT",
    );
}

#[test]
fn shake_256_ldt_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/SHAKE-256-FIPS202/ldt-slice.json",
        "md",
        "SHAKE-256-LDT",
    );
}

// ----------------------------------------------------------------------
// RSA primitive lifecycle (R44: sigPrim + decPrim, shared DRBG key)
// ----------------------------------------------------------------------

#[test]
fn rsa_sigprim_lifecycle_round_trip() {
    assert_sigprim_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-SignaturePrimitive-2.0/lifecycle-slice.json",
        "RSA-sigPrim-lifecycle",
    );
}

#[test]
fn rsa_decprim_lifecycle_round_trip() {
    assert_decprim_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/RSA-decryptionPrimitive-Sp800-56Br2/lifecycle-slice.json",
        "RSA-decPrim-lifecycle",
    );
}

// ----------------------------------------------------------------------
// SP 800-185 derived functions (R47: self-generated vectors)
// ----------------------------------------------------------------------

#[test]
fn cshake_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/cSHAKE-128-1.0/kat-slice.json",
        "md",
        "cSHAKE-128",
    );
}

#[test]
fn cshake_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/cSHAKE-256-1.0/kat-slice.json",
        "md",
        "cSHAKE-256",
    );
}

#[test]
fn kmac_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KMAC-128-1.0/kat-slice.json",
        "mac",
        "KMAC-128",
    );
}

#[test]
fn kmac_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KMAC-256-1.0/kat-slice.json",
        "mac",
        "KMAC-256",
    );
}

#[test]
fn tuplehash_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/TupleHash-128-1.0/kat-slice.json",
        "md",
        "TupleHash-128",
    );
}

#[test]
fn tuplehash_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/TupleHash-256-1.0/kat-slice.json",
        "md",
        "TupleHash-256",
    );
}

#[test]
fn parallelhash_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ParallelHash-128-1.0/kat-slice.json",
        "md",
        "ParallelHash-128",
    );
}

#[test]
fn parallelhash_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ParallelHash-256-1.0/kat-slice.json",
        "md",
        "ParallelHash-256",
    );
}

// ----------------------------------------------------------------------
// PBKDF2 (R55: self-generated, answer field `derivedKey`)
// ----------------------------------------------------------------------

#[test]
fn pbkdf2_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/PBKDF-1.0/kat-slice.json",
        "derivedKey",
        "PBKDF2",
    );
}

// ── R56: SP 800-185 XOF variants ───────────────────────────────────

#[test]
fn kmacxof_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KMACXOF-128-1.0/kat-slice.json",
        "mac",
        "KMACXOF-128",
    );
}

#[test]
fn kmacxof_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/KMACXOF-256-1.0/kat-slice.json",
        "mac",
        "KMACXOF-256",
    );
}

#[test]
fn tuplehashxof_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/TupleHashXOF-128-1.0/kat-slice.json",
        "md",
        "TupleHashXOF-128",
    );
}

#[test]
fn tuplehashxof_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/TupleHashXOF-256-1.0/kat-slice.json",
        "md",
        "TupleHashXOF-256",
    );
}

#[test]
fn parallelhashxof_128_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ParallelHashXOF-128-1.0/kat-slice.json",
        "md",
        "ParallelHashXOF-128",
    );
}

#[test]
fn parallelhashxof_256_aft_round_trip() {
    assert_round_trip(
        "../vendor/nist/acvp-server/gen-val/json-files/ParallelHashXOF-256-1.0/kat-slice.json",
        "md",
        "ParallelHashXOF-256",
    );
}
