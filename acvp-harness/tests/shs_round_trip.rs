//! Round-trip integration tests for the CAVP SHS dispatcher (R12-B).
//!
//! For each vendored `.rsp` short-message byte-vector file, we:
//!
//! 1. Parse the file via [`acvp_harness::rsp::parse`], capturing every
//!    expected digest (`MD = …`) alongside its `Len = …` bit length.
//! 2. Dispatch the parsed document through
//!    [`acvp_harness::shs::process_shs`] with the matching algorithm
//!    name.
//! 3. Verify the JSON response's per-case `md` field matches the
//!    vendored expected digest byte-for-byte, for every record, for
//!    every file.
//!
//! A failure on any layer (the `.rsp` parser, the envelope/dispatch
//! layer, or the per-algorithm handler) surfaces as a single assertion
//! diff.
//!
//! The tests are data-driven via [`assert_shs_round_trip`], so a new
//! handler is a one-line test.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use acvp_harness::{ensure_initialized, hex, json::JsonValue, rsp, shs};

/// Load a CAVP SHS `.rsp` file relative to the harness crate root and
/// return its parsed form.
fn load_rsp(relative: &str) -> rsp::RspDocument {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    rsp::parse(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

/// Load `relative`, dispatch it as `algorithm`, and assert every
/// produced digest matches the vendored expected digest.
///
/// `label` is the per-test name used in assertion diagnostics so a
/// single failing test binary can still tell you *which* `.rsp` file
/// misbehaved.
fn assert_shs_round_trip(relative: &str, algorithm: &str, label: &str) {
    ensure_initialized().unwrap();
    let doc = load_rsp(relative);
    assert!(
        !doc.cases.is_empty(),
        "{label}: vendored {relative} has zero records"
    );
    let registry = shs::with_default_shs_handlers();
    let response = shs::process_shs(algorithm, &doc, &registry)
        .unwrap_or_else(|e| panic!("{label}: dispatch-shs: {e}"));

    // Top-level shape: algorithm / l / testCases.
    assert_eq!(
        response.get("algorithm").and_then(JsonValue::as_str),
        Some(algorithm),
        "{label}: response algorithm mismatch"
    );
    let expected_l = i64::try_from(doc.digest_length_bytes)
        .unwrap_or_else(|_| panic!("{label}: digest length does not fit in i64"));
    assert_eq!(
        response.get("l").and_then(JsonValue::as_i64),
        Some(expected_l),
        "{label}: response `l` mismatch"
    );
    let produced_cases = response
        .get("testCases")
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{label}: response missing testCases"));
    assert_eq!(
        produced_cases.len(),
        doc.cases.len(),
        "{label}: testCase count mismatch"
    );

    // Per-case: (len, md) must match exactly.
    for (i, expected) in doc.cases.iter().enumerate() {
        let produced = &produced_cases[i];
        let produced_len = produced
            .get("len")
            .and_then(JsonValue::as_i64)
            .unwrap_or_else(|| panic!("{label}: case {i} missing `len`"));
        let expected_len = i64::try_from(expected.len_bits)
            .unwrap_or_else(|_| panic!("{label}: case {i} Len does not fit in i64"));
        assert_eq!(produced_len, expected_len, "{label}: case {i} len mismatch");
        let produced_md = produced
            .get("md")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("{label}: case {i} missing `md`"));
        // The dispatcher emits uppercase hex; the vendored file has
        // lowercase hex parsed into bytes. Compare on the decoded
        // bytes so case doesn't matter.
        let produced_md_bytes = hex::decode(produced_md)
            .unwrap_or_else(|e| panic!("{label}: case {i} produced md hex: {e}"));
        assert_eq!(
            produced_md_bytes.len(),
            doc.digest_length_bytes,
            "{label}: case {i} produced md length {} != declared {}",
            produced_md_bytes.len(),
            doc.digest_length_bytes
        );
        assert_eq!(
            produced_md_bytes, expected.md,
            "{label}: case {i} (Len={}) digest mismatch",
            expected.len_bits
        );
    }
}

#[test]
fn sha1_shortmsg_round_trip() {
    assert_shs_round_trip(
        "../vendor/nist/cavp-shs/shabytetestvectors/SHA1ShortMsg.rsp",
        "SHA-1",
        "SHA-1 ShortMsg",
    );
}

#[test]
fn sha224_shortmsg_round_trip() {
    assert_shs_round_trip(
        "../vendor/nist/cavp-shs/shabytetestvectors/SHA224ShortMsg.rsp",
        "SHA-224",
        "SHA-224 ShortMsg",
    );
}

#[test]
fn sha256_shortmsg_round_trip() {
    assert_shs_round_trip(
        "../vendor/nist/cavp-shs/shabytetestvectors/SHA256ShortMsg.rsp",
        "SHA-256",
        "SHA-256 ShortMsg",
    );
}

#[test]
fn sha384_shortmsg_round_trip() {
    assert_shs_round_trip(
        "../vendor/nist/cavp-shs/shabytetestvectors/SHA384ShortMsg.rsp",
        "SHA-384",
        "SHA-384 ShortMsg",
    );
}

#[test]
fn sha512_shortmsg_round_trip() {
    assert_shs_round_trip(
        "../vendor/nist/cavp-shs/shabytetestvectors/SHA512ShortMsg.rsp",
        "SHA-512",
        "SHA-512 ShortMsg",
    );
}

#[test]
fn sha512_224_shortmsg_round_trip() {
    assert_shs_round_trip(
        "../vendor/nist/cavp-shs/shabytetestvectors/SHA512_224ShortMsg.rsp",
        "SHA-512/224",
        "SHA-512/224 ShortMsg",
    );
}

#[test]
fn sha512_256_shortmsg_round_trip() {
    assert_shs_round_trip(
        "../vendor/nist/cavp-shs/shabytetestvectors/SHA512_256ShortMsg.rsp",
        "SHA-512/256",
        "SHA-512/256 ShortMsg",
    );
}
