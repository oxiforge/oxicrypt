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
//! One-shot helper that generates the ECDSA lifecycle vector files:
//!
//! - `ECDSA-keyGen-FIPS186-5/lifecycle-slice.json`  — keyGen
//! - `ECDSA-sigGen-FIPS186-5/lifecycle-slice.json`  — sigGen
//! - `ECDSA-sigVer-FIPS186-5/lifecycle-slice.json`  — sigVer (valid + invalid)
//!
//! All three files share the same five P-256 private keys, proving
//! that keyGen → sigGen → sigVer is consistent per key.
//!
//!   cargo test -p acvp-harness --test gen_ecdsa_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Five test messages.
const MESSAGES: [&[u8]; 5] = [
    b"Hello, ECDSA P-256!",
    b"ACVP lifecycle test message two",
    b"The quick brown fox jumps over the lazy dog",
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    b"",
];

#[test]
#[ignore]
fn generate_ecdsa_lifecycle_slices() {
    ensure_initialized().expect("FIPS init");

    // Generate five deterministic P-256 private keys and nonces
    // using a DRBG so they are valid scalars in [1, n-1].
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"pqclib-ecdsa-lifecycle-gen-entropy-v1",
        b"pqclib-ecdsa-lifecycle-gen-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    let num_keys = 5;
    let mut private_keys: Vec<[u8; 32]> = Vec::new();
    let mut public_keys: Vec<[u8; 65]> = Vec::new();

    for _ in 0..num_keys {
        let mut d = [0u8; 32];
        drbg.generate(None, &mut d).expect("drbg generate");
        // Ensure d is a valid P-256 scalar by deriving the public key.
        let pk = oxicrypt_ecdsa::p256_ecdsa::derive_public_key_internal(&d)
            .expect("derive_public_key_internal failed — d may be zero or >= n");
        private_keys.push(d);
        public_keys.push(pk);
    }

    // Generate nonces (k values) for each (key, message) pair.
    let mut nonces: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut signatures: Vec<Vec<[u8; 64]>> = Vec::new();

    for (ki, d) in private_keys.iter().enumerate() {
        let pk = &public_keys[ki];
        let mut k_for_key = Vec::new();
        let mut sig_for_key = Vec::new();

        for (mi, msg) in MESSAGES.iter().enumerate() {
            let mut k = [0u8; 32];
            drbg.generate(None, &mut k).expect("drbg generate k");

            let sig = oxicrypt_ecdsa::p256_ecdsa::sign_with_k(d, msg, &k)
                .unwrap_or_else(|_| panic!("sign_with_k failed key={ki} msg={mi}"));

            // Verify round-trips.
            assert!(
                oxicrypt_ecdsa::p256_ecdsa::verify(pk, msg, &sig)
                    .unwrap_or(false),
                "verify failed during generation key={ki} msg={mi}"
            );

            k_for_key.push(k);
            sig_for_key.push(sig);
        }
        nonces.push(k_for_key);
        signatures.push(sig_for_key);
    }

    // ── keyGen slice ──────────────────────────────────────────────
    let keygen_tests: Vec<String> = private_keys
        .iter()
        .zip(public_keys.iter())
        .enumerate()
        .map(|(i, (d, pk))| {
            format!(
                r#"        {{"tcId": {}, "d": "{}", "qx": "{}", "qy": "{}"}}"#,
                i + 1,
                hex_upper(d),
                hex_upper(&pk[1..33]),
                hex_upper(&pk[33..65]),
            )
        })
        .collect();

    let keygen_json = format!(
        r#"{{
  "_source": "oxicrypt self-generated ECDSA lifecycle vectors (keyGen)",
  "algorithm": "ECDSA",
  "mode": "keyGen",
  "revision": "FIPS186-5",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "curve": "P-256",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        keygen_tests.join(",\n"),
    );

    // ── sigGen slice ──────────────────────────────────────────────
    // 5 groups (one per key), each with 5 tests (one per message).
    let mut siggen_groups: Vec<String> = Vec::new();
    for (ki, d) in private_keys.iter().enumerate() {
        let tests: Vec<String> = MESSAGES
            .iter()
            .zip(nonces[ki].iter())
            .zip(signatures[ki].iter())
            .enumerate()
            .map(|(mi, ((msg, k), sig))| {
                let tc_id = ki * MESSAGES.len() + mi + 1;
                format!(
                    r#"        {{"tcId": {}, "message": "{}", "k": "{}", "r": "{}", "s": "{}"}}"#,
                    tc_id,
                    hex_upper(msg),
                    hex_upper(k),
                    hex_upper(&sig[..32]),
                    hex_upper(&sig[32..]),
                )
            })
            .collect();

        siggen_groups.push(format!(
            r#"    {{
      "tgId": {},
      "testType": "AFT",
      "curve": "P-256",
      "hashAlg": "SHA2-256",
      "d": "{}",
      "tests": [
{}
      ]
    }}"#,
            ki + 1,
            hex_upper(d),
            tests.join(",\n"),
        ));
    }

    let siggen_json = format!(
        r#"{{
  "_source": "oxicrypt self-generated ECDSA lifecycle vectors (sigGen)",
  "algorithm": "ECDSA",
  "mode": "sigGen",
  "revision": "FIPS186-5",
  "testGroups": [
{}
  ]
}}"#,
        siggen_groups.join(",\n"),
    );

    // ── sigVer slice ──────────────────────────────────────────────
    // Group 1: valid signatures (25 tests).
    // Group 2: invalid signatures (bit-flipped r, 25 tests).
    let mut valid_tests: Vec<String> = Vec::new();
    let mut invalid_tests: Vec<String> = Vec::new();
    let mut tc_valid = 1;
    let mut tc_invalid = 26;

    for (ki, pk) in public_keys.iter().enumerate() {
        let qx_hex = hex_upper(&pk[1..33]);
        let qy_hex = hex_upper(&pk[33..65]);

        for (mi, msg) in MESSAGES.iter().enumerate() {
            let sig = &signatures[ki][mi];
            let r_hex = hex_upper(&sig[..32]);
            let s_hex = hex_upper(&sig[32..]);

            valid_tests.push(format!(
                r#"        {{"tcId": {}, "message": "{}", "qx": "{}", "qy": "{}", "r": "{}", "s": "{}", "testPassed": true}}"#,
                tc_valid,
                hex_upper(msg),
                qx_hex,
                qy_hex,
                r_hex,
                s_hex,
            ));
            tc_valid += 1;

            // Invalid: flip first byte of r.
            let mut bad_r = [0u8; 32];
            bad_r.copy_from_slice(&sig[..32]);
            bad_r[0] ^= 0x01;

            invalid_tests.push(format!(
                r#"        {{"tcId": {}, "message": "{}", "qx": "{}", "qy": "{}", "r": "{}", "s": "{}", "testPassed": false}}"#,
                tc_invalid,
                hex_upper(msg),
                qx_hex,
                qy_hex,
                hex_upper(&bad_r),
                s_hex,
            ));
            tc_invalid += 1;
        }
    }

    let sigver_json = format!(
        r#"{{
  "_source": "oxicrypt self-generated ECDSA lifecycle vectors (sigVer)",
  "algorithm": "ECDSA",
  "mode": "sigVer",
  "revision": "FIPS186-5",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "curve": "P-256",
      "hashAlg": "SHA2-256",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "curve": "P-256",
      "hashAlg": "SHA2-256",
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
        ("ECDSA-keyGen-FIPS186-5", "lifecycle-slice.json", &keygen_json),
        ("ECDSA-sigGen-FIPS186-5", "lifecycle-slice.json", &siggen_json),
        ("ECDSA-sigVer-FIPS186-5", "lifecycle-slice.json", &sigver_json),
    ] {
        let path = base.join(dir).join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        println!("Wrote {} ({} bytes)", path.display(), json.len());
    }
}
