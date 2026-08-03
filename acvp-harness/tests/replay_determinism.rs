//! Replay-determinism regression tests for handler-side gating logic.
//!
//! For each ACVP handler family that has IUT-side sampling on its
//! generative-AFT path (KBKDF, KAS-ECC-SSC, ECDSA, EdDSA), this file
//! asserts that running an identical *deterministic-shape* prompt
//! through `dispatch::process` twice yields byte-identical responses.
//!
//! Why this catches bugs the existing kat-slice round-trip tests
//! don't:
//!
//! - The kat-slice tests in `round_trip.rs` assert the response
//!   matches a known-good answer. They catch ANY output difference,
//!   including non-determinism, but they cannot distinguish the cause.
//! - These tests assert the response is byte-identical across two
//!   invocations of the SAME prompt. A handler that correctly takes
//!   the deterministic dispatch path is, by construction, deterministic
//!   — so a failure of this assertion isolates the bug class to
//!   *gating logic regression* (handler taking the generative-sampling
//!   path on a deterministic prompt). Other regression classes still
//!   need the kat-slice tests for detection.
//!
//! Coverage rationale: one test per family, not one per sampling site,
//! because the gating is shared within a family (KBKDF's
//! `is_generative()` predicate, ECDSA's `group.get("d").is_some()`
//! check, etc.). Per-site tests would multiply count without adding
//! gating coverage.
//!
//! Built 2026-05-04 as Method 4 of the ACVTS server-provenance audit.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use acvp_harness::{dispatch, ensure_initialized, json, json::JsonValue};

/// Load and parse a vendored ACVP slice relative to the harness crate root.
fn load(relative: &str) -> JsonValue {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    json::parse(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

/// Recursively remove every occurrence of `field` from every object in the tree.
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

/// Shared driver: load the slice, strip the answer field(s) to make it a
/// prompt, dispatch twice, assert byte-identical pretty-printed output.
fn assert_replay_stable(relative: &str, answer_fields: &[&str], label: &str) {
    ensure_initialized().unwrap();
    let slice = load(relative);

    let mut prompt = slice.clone();
    for field in answer_fields {
        strip_field(&mut prompt, field);
    }

    let registry = dispatch::with_default_handlers();
    let response_a = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: first dispatch failed: {e}"));
    let response_b = dispatch::process(&prompt, &registry)
        .unwrap_or_else(|e| panic!("{label}: second dispatch failed: {e}"));

    let a_str = json::to_pretty_string(&response_a);
    let b_str = json::to_pretty_string(&response_b);

    assert_eq!(
        a_str, b_str,
        "{label}: response differs across two invocations of identical \
         deterministic prompt — gating regression suspected (handler may \
         be taking the generative-sampling path despite deterministic \
         input fields being present)"
    );
}

// ----------------------------------------------------------------------
// KBKDF — gating: `is_generative(tc)` returns true when prompt omits
// `fixedData`. The vendored kat-slice supplies `fixedData` per test
// (and `iv` for feedback mode), so the deterministic path is taken.
// Sampling sites guarded: kbkdf.rs:119 (fixedData fabrication),
// kbkdf.rs:352 (feedback-mode IV).
// ----------------------------------------------------------------------

#[test]
fn kbkdf_deterministic_replay_stable() {
    assert_replay_stable(
        "../vendor/nist/acvp-server/gen-val/json-files/KDF-1.0/kat-slice.json",
        &["keyOut"],
        "KBKDF",
    );
}

// ----------------------------------------------------------------------
// KAS-ECC-SSC — gating: `tc.get("peerPublicKeyX").is_some()` selects
// the deterministic path. The vendored kat-slice supplies `d`,
// `peerPublicKeyX`, `peerPublicKeyY` per test.
// Sampling sites guarded: kas_ecc_ssc.rs:142 (P-256), :186 (P-384).
// ----------------------------------------------------------------------

#[test]
fn kas_ecc_ssc_deterministic_replay_stable() {
    assert_replay_stable(
        "../vendor/nist/acvp-server/gen-val/json-files/KAS-ECC-SSC-Sp800-56Ar3/kat-slice.json",
        &["z"],
        "KAS-ECC-SSC",
    );
}

// ----------------------------------------------------------------------
// ECDSA sigGen — gating: `group.get("d").is_some()` selects the
// deterministic path. Vendored kat-slice supplies `d` per group +
// `k` per test.
// Sampling sites guarded: ecdsa.rs:379, :404-405, :422, :444-445, :462.
// ----------------------------------------------------------------------

#[test]
fn ecdsa_siggen_deterministic_replay_stable() {
    assert_replay_stable(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-sigGen-FIPS186-5/kat-slice.json",
        &["r", "s"],
        "ECDSA-sigGen",
    );
}

// ----------------------------------------------------------------------
// ECDSA keyGen — gating: `tests.first().is_some_and(|t| t.get("d").
// is_some())` selects the deterministic path. Vendored kat-slice
// supplies `d`, `qx`, `qy` per test.
// Sampling sites guarded: ecdsa.rs:667, :772-773, :803-804.
// ----------------------------------------------------------------------

#[test]
fn ecdsa_keygen_deterministic_replay_stable() {
    assert_replay_stable(
        "../vendor/nist/acvp-server/gen-val/json-files/ECDSA-keyGen-FIPS186-5/kat-slice.json",
        &["qx", "qy"],
        "ECDSA-keyGen",
    );
}

// ----------------------------------------------------------------------
// EdDSA keyGen — gating: same dual-mode pattern as ECDSA keyGen.
// Vendored kat-slice supplies `d`, `q` per test.
// Sampling sites guarded: eddsa.rs:400, :406.
//
// Note: EdDSA sigGen takes server-supplied group-level `d` (Ed25519 is
// fully deterministic given the seed) and does not have a generative
// path — no gating to test, no IUT sampling. Hence keyGen is the
// relevant family endpoint here.
// ----------------------------------------------------------------------

#[test]
fn eddsa_keygen_deterministic_replay_stable() {
    // Strip ONLY `q` (the IUT-computed answer). `d` is both the gating
    // field (presence selects deterministic path) AND echoed in the
    // response. Stripping `d` would force the generative path which
    // is legitimately non-deterministic — see ECDSA-keyGen for the
    // same shape with `qx`/`qy` as answers (no overlap with gating).
    assert_replay_stable(
        "../vendor/nist/acvp-server/gen-val/json-files/EDDSA-keyGen-1.0/kat-slice.json",
        &["q"],
        "EdDSA-keyGen",
    );
}
