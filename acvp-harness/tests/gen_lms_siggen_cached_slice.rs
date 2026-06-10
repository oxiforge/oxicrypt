//! Oracle tests for the LMS `sigGen` handler after it was wired onto the
//! cached `oxicrypt_lms::<pair>::LmsSigningKey` (precomputed Merkle node
//! table) instead of the free `sign_internal` that recomputes the whole
//! 2^H-leaf tree per signature.
//!
//! Two independent oracles guard the swap:
//!
//! 1. **Equivalence** — the handler's per-case signatures must be
//!    byte-identical to the free recursive `sign_internal` path for the
//!    same key and the same sequential q-sequence (q auto-advances from
//!    0, one leaf per test case, in `tests` order). This catches wiring
//!    bugs: a wrong pair, a wrong seed, a dropped/duplicated leaf, or a
//!    desynchronised q.
//!
//! 2. **KAT-grounded** — a vendored NIST ACVP sigVer Known-Answer Test
//!    (`usnistgov/ACVP-Server @ 112690e8`, the same fixtures
//!    `oxicrypt-lms/tests/nist_kat_all_pairs.rs` consumes) is checked
//!    against `verify_internal`, grounding the verify path on an answer
//!    that does NOT come from the code under test. That externally
//!    grounded verify is then used to confirm every cached-path handler
//!    signature is a genuine LMS signature over its message under the
//!    handler-reported public key. Without this, oracle 1 alone could be
//!    tautologically green if a shared q-semantics bug corrupted both the
//!    cached and the free path identically.
//!
//! The handler derives a deterministic 32-byte seed from each group's
//! `tgId` (prefix `b"oxicrypt-lms-acvp-handler-tg"` || `tgId` as u32 BE);
//! oracle 1 replicates that derivation to drive the free reference path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::items_after_statements,
    clippy::similar_names
)]

use acvp_harness::{dispatch, ensure_initialized, hex, json, json::JsonValue};

fn parse(text: &str) -> JsonValue {
    json::parse(text).unwrap_or_else(|e| panic!("parse: {e}"))
}

fn dispatch_ok(prompt: &JsonValue) -> JsonValue {
    let registry = dispatch::with_default_handlers();
    dispatch::process(prompt, &registry).unwrap_or_else(|e| panic!("dispatch: {e}"))
}

/// Replicate the handler's `lms_siggen_seed_from_tg_id` derivation so the
/// free reference path keys off the exact same seed.
fn seed_from_tg_id(tg_id: u32) -> [u8; 32] {
    const PREFIX: &[u8; 28] = b"oxicrypt-lms-acvp-handler-tg";
    let mut seed = [0u8; 32];
    seed[..28].copy_from_slice(PREFIX);
    seed[28..32].copy_from_slice(&tg_id.to_be_bytes());
    seed
}

/// Build a single-group LMS sigGen prompt with `messages.len()` AFT test
/// cases (one leaf consumed per case, in order).
fn lms_siggen_prompt(
    tg_id: u32,
    lms_mode: &str,
    lmots_mode: &str,
    messages: &[&[u8]],
) -> JsonValue {
    let tests: Vec<String> = messages
        .iter()
        .enumerate()
        .map(|(i, m)| {
            format!(
                r#"{{ "tcId": {tc}, "message": "{msg}" }}"#,
                tc = i + 1,
                msg = hex::encode_upper(m),
            )
        })
        .collect();
    let prompt_text = format!(
        r#"{{
            "algorithm": "LMS",
            "mode":      "sigGen",
            "revision":  "1.0",
            "testGroups": [{{
                "tgId": {tg_id},
                "testType": "AFT",
                "lmsMode":   "{lms_mode}",
                "lmOtsMode": "{lmots_mode}",
                "tests": [{tests}]
            }}]
        }}"#,
        tests = tests.join(", "),
    );
    parse(&prompt_text)
}

/// Pull the group-level `publicKey` and the per-test `signature` hex
/// strings out of a sigGen response.
fn extract_group(response: &JsonValue) -> (Vec<u8>, Vec<Vec<u8>>) {
    let groups = response
        .get("testGroups")
        .and_then(JsonValue::as_array)
        .unwrap();
    let group = &groups[0];
    let pk = hex::decode(group.get("publicKey").and_then(JsonValue::as_str).unwrap()).unwrap();
    let sigs = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .unwrap()
        .iter()
        .map(|t| hex::decode(t.get("signature").and_then(JsonValue::as_str).unwrap()).unwrap())
        .collect();
    (pk, sigs)
}

// ── Oracle 1: cached handler ≡ free recursive path, same q-sequence ──

/// The cached handler path (`LmsSigningKey::new_internal` + cached
/// `sign_internal`) must produce signatures byte-identical to the free
/// recursive `sign_internal` over the plain `LmsPrivateKey` for the same
/// seed and the same sequential q-sequence. H = 5 (32 leaves) keeps the
/// reference cheap; W = 4 exercises a non-trivial LM-OTS chain layout.
#[test]
fn cached_siggen_matches_free_path_byte_for_byte() {
    ensure_initialized().unwrap();

    let tg_id: u32 = 7;
    let lms_mode = "LMS_SHA256_M32_H5";
    let lmots_mode = "LMOTS_SHA256_N32_W4";

    // Eight messages → eight leaves consumed (q = 0..8), well under the
    // 2^5 = 32-leaf budget so iteration order, not exhaustion, is tested.
    let owned: Vec<Vec<u8>> = (0u8..8)
        .map(|i| vec![i, i.wrapping_add(0x55), i.wrapping_mul(3)])
        .collect();
    let messages: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

    let response = dispatch_ok(&lms_siggen_prompt(tg_id, lms_mode, lmots_mode, &messages));
    let (handler_pk, handler_sigs) = extract_group(&response);
    assert_eq!(
        handler_sigs.len(),
        messages.len(),
        "handler must emit one signature per test case",
    );

    // Free reference path: same seed derivation, same key, q auto-advances
    // from 0 across the same message sequence.
    use oxicrypt_lms::lms_sha256_m32_h5_w4 as pair;
    let seed = seed_from_tg_id(tg_id);
    let (mut sk, free_pk) = pair::keygen_internal(&seed);

    assert_eq!(
        handler_pk,
        free_pk.to_vec(),
        "handler public key must match the free keygen for the same seed",
    );

    for (i, msg) in messages.iter().enumerate() {
        let free_sig = pair::sign_internal(&mut sk, msg)
            .expect("free path must not exhaust within budget")
            .to_vec();
        assert_eq!(
            handler_sigs[i], free_sig,
            "cached handler signature at q={i} must be byte-identical to the free path",
        );
    }
}

/// Guard against silently signing fewer leaves than requested: a handler
/// that capped at the leaf budget instead of erroring would be caught by
/// requesting a case count comfortably inside 2^H and asserting the full
/// count round-trips.
#[test]
fn cached_siggen_emits_every_requested_case_within_budget() {
    ensure_initialized().unwrap();

    let tg_id: u32 = 11;
    // 2^5 = 32 leaves available; request exactly 32 (full exhaustion) to
    // assert the handler signs the whole budget without over- or
    // under-running.
    let owned: Vec<Vec<u8>> = (0u16..32).map(|i| i.to_be_bytes().to_vec()).collect();
    let messages: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

    let response = dispatch_ok(&lms_siggen_prompt(
        tg_id,
        "LMS_SHA256_M32_H5",
        "LMOTS_SHA256_N32_W4",
        &messages,
    ));
    let (_pk, sigs) = extract_group(&response);
    assert_eq!(
        sigs.len(),
        32,
        "handler must emit one signature per case up to the full 2^H budget",
    );

    // Every signature carries its own q in the leading 4 bytes (RFC 8554
    // §5.4): they must be the consecutive sequence 0..32, proving one
    // distinct leaf per case in order.
    for (i, sig) in sigs.iter().enumerate() {
        let q = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
        assert_eq!(
            q as usize, i,
            "signature {i} must carry q={i} in its header"
        );
    }
}

// ── Oracle 2: NIST KAT grounds verify; verify grounds cached output ──

/// Vendored NIST ACVP sigVer KAT (LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W4),
/// `usnistgov/ACVP-Server @ 112690e8` — an answer external to the code
/// under test. Same fixtures `oxicrypt-lms/tests/nist_kat_all_pairs.rs`
/// consumes; included here so the harness test is self-contained.
const NIST_KAT_PK: &[u8] =
    include_bytes!("../../crates/oxicrypt-lms/tests/data/lms_sha256_m32_h5_w4_sigver_pk.bin");
const NIST_KAT_MSG: &[u8] =
    include_bytes!("../../crates/oxicrypt-lms/tests/data/lms_sha256_m32_h5_w4_sigver_msg.bin");
const NIST_KAT_SIG: &[u8] =
    include_bytes!("../../crates/oxicrypt-lms/tests/data/lms_sha256_m32_h5_w4_sigver_sig.bin");

#[test]
fn cached_siggen_output_verifies_under_nist_grounded_verify() {
    ensure_initialized().unwrap();
    use oxicrypt_lms::lms_sha256_m32_h5_w4 as pair;

    // (a) Ground the verify path on the NIST answer: a known-good
    // signature from an external source must verify. If verify is broken,
    // step (b) below would be meaningless.
    assert!(
        pair::verify_internal(
            NIST_KAT_PK.try_into().unwrap(),
            NIST_KAT_MSG,
            NIST_KAT_SIG.try_into().unwrap(),
        ),
        "NIST ACVP sigVer KAT must verify — verify path is not externally grounded",
    );
    // Negative control: the same verify must reject a flipped signature,
    // so step (b)'s acceptance is discriminating, not vacuous.
    let mut tampered = NIST_KAT_SIG.to_vec();
    tampered[0] ^= 0x01;
    assert!(
        !pair::verify_internal(
            NIST_KAT_PK.try_into().unwrap(),
            NIST_KAT_MSG,
            tampered.as_slice().try_into().unwrap(),
        ),
        "verify must reject a tampered signature",
    );

    // (b) Use that externally grounded verify to confirm the cached
    // handler emits genuine LMS signatures (not merely free-path-equal
    // bytes). A shared q-semantics bug that corrupted both paths would be
    // caught here, since the NIST-grounded verify is independent of the
    // signing code.
    let tg_id: u32 = 23;
    let owned: Vec<Vec<u8>> = (0u8..5)
        .map(|i| vec![0xA0 ^ i, 0x0B, i.wrapping_mul(7)])
        .collect();
    let messages: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

    let response = dispatch_ok(&lms_siggen_prompt(
        tg_id,
        "LMS_SHA256_M32_H5",
        "LMOTS_SHA256_N32_W4",
        &messages,
    ));
    let (pk, sigs) = extract_group(&response);
    let pk_arr: &[u8; oxicrypt_lms::lms_sha256_m32_h5_w4::PUBLIC_KEY_LEN] =
        pk.as_slice().try_into().unwrap();

    for (i, sig) in sigs.iter().enumerate() {
        let sig_arr: &[u8; oxicrypt_lms::lms_sha256_m32_h5_w4::SIGNATURE_LEN] =
            sig.as_slice().try_into().unwrap();
        assert!(
            pair::verify_internal(pk_arr, messages[i], sig_arr),
            "cached handler signature at q={i} must verify under the handler-reported public key",
        );
    }
}
