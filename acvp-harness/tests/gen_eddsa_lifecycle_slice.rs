#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::needless_range_loop,
    clippy::manual_string_new,
    clippy::uninlined_format_args,
    clippy::many_single_char_names,
    clippy::ignore_without_reason,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::items_after_statements
)]
//! One-shot helper that generates the EdDSA lifecycle vector files:
//!
//! - `EDDSA-keyGen-1.0/lifecycle-slice.json`  — keyGen
//! - `EDDSA-sigGen-1.0/lifecycle-slice.json`  — sigGen
//! - `EDDSA-sigVer-1.0/lifecycle-slice.json`  — sigVer (valid + invalid)
//!
//! All three files share the same five Ed25519 seeds, proving that
//! keyGen → sigGen → sigVer is consistent for each key.
//!
//!   cargo test -p acvp-harness --test gen_eddsa_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Five deterministic Ed25519 seeds.
const SEEDS: [[u8; 32]; 5] = [
    [0x01; 32],
    [0x42; 32],
    [0xAA; 32],
    [0xFF; 32],
    [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    ],
];

/// Five test messages.
const MESSAGES: [&[u8]; 5] = [
    b"Hello, Ed25519!",
    b"ACVP lifecycle test message two",
    b"The quick brown fox jumps over the lazy dog",
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    b"",
];

#[test]
#[ignore]
fn generate_eddsa_lifecycle_slices() {
    ensure_initialized().expect("FIPS init");

    // Derive public keys and signatures for all seeds × messages.
    let mut public_keys: Vec<[u8; 32]> = Vec::new();
    let mut signatures: Vec<Vec<[u8; 64]>> = Vec::new();

    for seed in &SEEDS {
        let q = fips_eddsa::ed25519::keygen_internal(seed);
        public_keys.push(q);

        let mut sigs_for_seed = Vec::new();
        for msg in &MESSAGES {
            let sig = fips_eddsa::ed25519::sign(seed, msg)
                .expect("Ed25519 sign failed");
            // Verify round-trips.
            assert!(
                fips_eddsa::ed25519::verify(&q, msg, &sig)
                    .unwrap_or(false),
                "Ed25519 verify failed during generation"
            );
            sigs_for_seed.push(sig);
        }
        signatures.push(sigs_for_seed);
    }

    // ── keyGen slice ──────────────────────────────────────────────
    // One group, 5 tests (one per seed).
    let keygen_tests: Vec<String> = SEEDS
        .iter()
        .zip(public_keys.iter())
        .enumerate()
        .map(|(i, (seed, q))| {
            format!(
                r#"        {{"tcId": {}, "d": "{}", "q": "{}"}}"#,
                i + 1,
                hex_upper(seed),
                hex_upper(q),
            )
        })
        .collect();

    let keygen_json = format!(
        r#"{{
  "_source": "pqclib self-generated EdDSA lifecycle vectors (keyGen)",
  "algorithm": "EDDSA",
  "mode": "keyGen",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "curve": "ED-25519",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        keygen_tests.join(",\n"),
    );

    // ── sigGen slice ──────────────────────────────────────────────
    // 5 groups (one per seed), each with 5 tests (one per message).
    let mut siggen_groups: Vec<String> = Vec::new();
    for (si, seed) in SEEDS.iter().enumerate() {
        let tests: Vec<String> = MESSAGES
            .iter()
            .zip(signatures[si].iter())
            .enumerate()
            .map(|(mi, (msg, sig))| {
                let tc_id = si * MESSAGES.len() + mi + 1;
                format!(
                    r#"        {{"tcId": {}, "message": "{}", "signature": "{}"}}"#,
                    tc_id,
                    hex_upper(msg),
                    hex_upper(sig),
                )
            })
            .collect();

        siggen_groups.push(format!(
            r#"    {{
      "tgId": {},
      "testType": "AFT",
      "curve": "ED-25519",
      "preHash": false,
      "d": "{}",
      "tests": [
{}
      ]
    }}"#,
            si + 1,
            hex_upper(seed),
            tests.join(",\n"),
        ));
    }

    let siggen_json = format!(
        r#"{{
  "_source": "pqclib self-generated EdDSA lifecycle vectors (sigGen)",
  "algorithm": "EDDSA",
  "mode": "sigGen",
  "revision": "1.0",
  "testGroups": [
{}
  ]
}}"#,
        siggen_groups.join(",\n"),
    );

    // ── sigVer slice ──────────────────────────────────────────────
    // Group 1: valid signatures (5 seeds × 5 messages = 25 tests).
    // Group 2: invalid signatures (bit-flipped, 25 tests).
    let mut valid_tests: Vec<String> = Vec::new();
    let mut invalid_tests: Vec<String> = Vec::new();
    let mut tc_valid = 1;
    let mut tc_invalid = 26;

    for (si, q) in public_keys.iter().enumerate() {
        for (mi, msg) in MESSAGES.iter().enumerate() {
            let sig = &signatures[si][mi];

            // Valid test.
            valid_tests.push(format!(
                r#"        {{"tcId": {}, "message": "{}", "q": "{}", "signature": "{}", "testPassed": true}}"#,
                tc_valid,
                hex_upper(msg),
                hex_upper(q),
                hex_upper(sig),
            ));
            tc_valid += 1;

            // Invalid test: flip the first byte of the signature.
            let mut bad_sig = *sig;
            bad_sig[0] ^= 0x01;
            invalid_tests.push(format!(
                r#"        {{"tcId": {}, "message": "{}", "q": "{}", "signature": "{}", "testPassed": false}}"#,
                tc_invalid,
                hex_upper(msg),
                hex_upper(q),
                hex_upper(&bad_sig),
            ));
            tc_invalid += 1;
        }
    }

    let sigver_json = format!(
        r#"{{
  "_source": "pqclib self-generated EdDSA lifecycle vectors (sigVer)",
  "algorithm": "EDDSA",
  "mode": "sigVer",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "curve": "ED-25519",
      "preHash": false,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "curve": "ED-25519",
      "preHash": false,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        valid_tests.join(",\n"),
        invalid_tests.join(",\n"),
    );

    // Write all three files.
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files");

    for (dir, name, json) in [
        ("EDDSA-keyGen-1.0", "lifecycle-slice.json", &keygen_json),
        ("EDDSA-sigGen-1.0", "lifecycle-slice.json", &siggen_json),
        ("EDDSA-sigVer-1.0", "lifecycle-slice.json", &sigver_json),
    ] {
        let path = base.join(dir).join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        println!("Wrote {} ({} bytes)", path.display(), json.len());
    }
}
