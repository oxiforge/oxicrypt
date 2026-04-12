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
//! One-shot helper that generates the RSA lifecycle vector files:
//!
//! - `RSA-keyGen-FIPS186-5/lifecycle-slice.json`  — keyGen (1 group,
//!   1 test: DRBG seed → key material)
//! - `RSA-sigGen-FIPS186-5/lifecycle-slice.json`  — sigGen (2 groups:
//!   PKCS#1v1.5/non-CRT + PSS/CRT)
//! - `RSA-sigVer-FIPS186-5/lifecycle-slice.json`  — sigVer (4 groups:
//!   valid+invalid for each sig type)
//!
//! All three files share one DRBG-generated RSA-2048 key, proving
//! keyGen → sigGen → sigVer is consistent.
//!
//!   cargo test -p acvp-harness --test gen_rsa_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

const MESSAGES: [&[u8]; 5] = [
    b"Hello, RSA lifecycle!",
    b"ACVP lifecycle test message two",
    b"The quick brown fox jumps over the lazy dog",
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    b"Short",
];

/// Five deterministic PSS salts (32 bytes each).
const PSS_SALTS: [[u8; 32]; 5] = [
    [0x11; 32],
    [0x22; 32],
    [0x33; 32],
    [0x44; 32],
    [0x55; 32],
];

#[test]
#[ignore]
fn generate_rsa_lifecycle_slices() {
    ensure_initialized().expect("FIPS init");

    // Generate a fresh RSA-2048 key pair.
    let mut drbg = fips_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"pqclib-rsa-lifecycle-gen-entropy-v1",
        b"pqclib-rsa-lifecycle-gen-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    let km = fips_rsa::keygen::generate_2048(&mut drbg, 65537)
        .expect("RSA keygen");

    let n_bytes: [u8; 256] = km.n.to_be_bytes();
    let d_bytes: [u8; 256] = km.d.to_be_bytes();
    let p_bytes: [u8; 128] = km.p.to_be_bytes();
    let q_bytes: [u8; 128] = km.q.to_be_bytes();
    let dp_bytes: [u8; 128] = km.dp.to_be_bytes();
    let dq_bytes: [u8; 128] = km.dq.to_be_bytes();
    let qinv_bytes: [u8; 128] = km.qinv.to_be_bytes();
    let e: u64 = 65537;

    let n_hex = hex_upper(&n_bytes);
    let d_hex = hex_upper(&d_bytes);
    let e_hex = "010001";
    let p_hex = hex_upper(&p_bytes);
    let q_hex = hex_upper(&q_bytes);
    let dp_hex = hex_upper(&dp_bytes);
    let dq_hex = hex_upper(&dq_bytes);
    let qinv_hex = hex_upper(&qinv_bytes);

    // Sign all messages with both PKCS#1v1.5 (non-CRT) and PSS (CRT).
    let mut pkcs1_sigs: Vec<Vec<u8>> = Vec::new();
    let mut pss_sigs: Vec<Vec<u8>> = Vec::new();

    for (i, msg) in MESSAGES.iter().enumerate() {
        // PKCS#1v1.5 non-CRT sign
        let pkcs1_sig = fips_rsa::rsa_pkcs1_v15_sign_2048_sha256_internal(
            &n_bytes, &d_bytes, msg,
        )
        .unwrap_or_else(|| panic!("PKCS#1v1.5 sign failed msg {i}"));

        // Verify PKCS#1v1.5 signature
        assert!(
            fips_rsa::rsa_pkcs1_v15_verify_2048_sha256_internal(&n_bytes, e, msg, &pkcs1_sig),
            "PKCS#1v1.5 verify failed msg {i}"
        );
        pkcs1_sigs.push(pkcs1_sig.to_vec());

        // PSS CRT sign
        let pss_sig = fips_rsa::rsa_pss_sign_2048_sha256_crt_internal(
            &n_bytes, e, &p_bytes, &q_bytes, &dp_bytes, &dq_bytes, &qinv_bytes,
            msg, &PSS_SALTS[i],
        )
        .unwrap_or_else(|| panic!("PSS CRT sign failed msg {i}"));

        // Verify PSS signature
        assert!(
            fips_rsa::rsa_pss_verify_2048_sha256_internal(&n_bytes, e, msg, &pss_sig),
            "PSS verify failed msg {i}"
        );
        pss_sigs.push(pss_sig.to_vec());
    }

    // ── sigGen slice ──────────────────────────────────────────────
    // Group 1: PKCS#1v1.5, keyMode=standard (non-CRT, d-only)
    let pkcs1_tests: Vec<String> = MESSAGES
        .iter()
        .zip(pkcs1_sigs.iter())
        .enumerate()
        .map(|(i, (msg, sig))| {
            format!(
                r#"        {{"tcId": {}, "message": "{}", "signature": "{}"}}"#,
                i + 1,
                hex_upper(msg),
                hex_upper(sig),
            )
        })
        .collect();

    // Group 2: PSS, keyMode=crt (CRT + Bellcore)
    let pss_tests: Vec<String> = MESSAGES
        .iter()
        .zip(pss_sigs.iter())
        .enumerate()
        .map(|(i, (msg, sig))| {
            format!(
                r#"        {{"tcId": {}, "message": "{}", "salt": "{}", "signature": "{}"}}"#,
                MESSAGES.len() + i + 1,
                hex_upper(msg),
                hex_upper(&PSS_SALTS[i]),
                hex_upper(sig),
            )
        })
        .collect();

    let siggen_json = format!(
        r#"{{
  "_source": "pqclib self-generated RSA lifecycle vectors (sigGen)",
  "algorithm": "RSA",
  "mode": "sigGen",
  "revision": "FIPS186-5",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "GDT",
      "sigType": "pkcs1v1.5",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "keyMode": "standard",
      "n": "{n_hex}",
      "d": "{d_hex}",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "GDT",
      "sigType": "pss",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "saltLen": 32,
      "keyMode": "crt",
      "n": "{n_hex}",
      "e": "{e_hex}",
      "p": "{p_hex}",
      "q": "{q_hex}",
      "dmp1": "{dp_hex}",
      "dmq1": "{dq_hex}",
      "iqmp": "{qinv_hex}",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        pkcs1_tests.join(",\n"),
        pss_tests.join(",\n"),
    );

    // ── sigVer slice ──────────────────────────────────────────────
    // Group 1: PKCS#1v1.5 valid (5 tests, testPassed=true)
    // Group 2: PKCS#1v1.5 invalid (5 tests, testPassed=false)
    // Group 3: PSS valid (5 tests, testPassed=true)
    // Group 4: PSS invalid (5 tests, testPassed=false)

    let mut pkcs1_valid: Vec<String> = Vec::new();
    let mut pkcs1_invalid: Vec<String> = Vec::new();
    let mut pss_valid: Vec<String> = Vec::new();
    let mut pss_invalid: Vec<String> = Vec::new();

    for (i, msg) in MESSAGES.iter().enumerate() {
        let msg_hex = hex_upper(msg);

        // PKCS#1v1.5 valid
        pkcs1_valid.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "signature": "{}", "testPassed": true}}"#,
            i + 1,
            msg_hex,
            hex_upper(&pkcs1_sigs[i]),
        ));

        // PKCS#1v1.5 invalid (flip first byte of signature)
        let mut bad_sig = pkcs1_sigs[i].clone();
        bad_sig[0] ^= 0x01;
        pkcs1_invalid.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "signature": "{}", "testPassed": false}}"#,
            MESSAGES.len() + i + 1,
            msg_hex,
            hex_upper(&bad_sig),
        ));

        // PSS valid
        pss_valid.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "signature": "{}", "testPassed": true}}"#,
            2 * MESSAGES.len() + i + 1,
            msg_hex,
            hex_upper(&pss_sigs[i]),
        ));

        // PSS invalid (flip first byte of signature)
        let mut bad_pss = pss_sigs[i].clone();
        bad_pss[0] ^= 0x01;
        pss_invalid.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "signature": "{}", "testPassed": false}}"#,
            3 * MESSAGES.len() + i + 1,
            msg_hex,
            hex_upper(&bad_pss),
        ));
    }

    let sigver_json = format!(
        r#"{{
  "_source": "pqclib self-generated RSA lifecycle vectors (sigVer)",
  "algorithm": "RSA",
  "mode": "sigVer",
  "revision": "FIPS186-5",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "GDT",
      "sigType": "pkcs1v1.5",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "n": "{n_hex}",
      "e": "{e_hex}",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "GDT",
      "sigType": "pkcs1v1.5",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "n": "{n_hex}",
      "e": "{e_hex}",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 3,
      "testType": "GDT",
      "sigType": "pss",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "saltLen": 32,
      "n": "{n_hex}",
      "e": "{e_hex}",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 4,
      "testType": "GDT",
      "sigType": "pss",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "saltLen": 32,
      "n": "{n_hex}",
      "e": "{e_hex}",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        pkcs1_valid.join(",\n"),
        pkcs1_invalid.join(",\n"),
        pss_valid.join(",\n"),
        pss_invalid.join(",\n"),
    );

    // ── keyGen slice ─────────────────────────────────────────────
    // One group, one test: provide the same DRBG seed material so
    // the keyGen handler re-derives the identical key.
    let entropy_hex = hex_upper(b"pqclib-rsa-lifecycle-gen-entropy-v1");
    let nonce_hex = hex_upper(b"pqclib-rsa-lifecycle-gen-nonce-v1");

    let keygen_json = format!(
        r#"{{
  "_source": "pqclib self-generated RSA lifecycle vectors (keyGen)",
  "algorithm": "RSA",
  "mode": "keyGen",
  "revision": "FIPS186-5",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "modulo": 2048,
      "fixedPubExp": "{e_hex}",
      "tests": [
        {{
          "tcId": 1,
          "entropy": "{entropy_hex}",
          "nonce": "{nonce_hex}",
          "perso": "",
          "n": "{n_hex}",
          "d": "{d_hex}",
          "e": "{e_hex}",
          "p": "{p_hex}",
          "q": "{q_hex}",
          "dmp1": "{dp_hex}",
          "dmq1": "{dq_hex}",
          "iqmp": "{qinv_hex}"
        }}
      ]
    }}
  ]
}}"#,
    );

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files");

    for (dir, name, json) in [
        ("RSA-keyGen-FIPS186-5", "lifecycle-slice.json", &keygen_json),
        ("RSA-sigGen-FIPS186-5", "lifecycle-slice.json", &siggen_json),
        ("RSA-sigVer-FIPS186-5", "lifecycle-slice.json", &sigver_json),
    ] {
        let path = base.join(dir).join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        println!("Wrote {} ({} bytes)", path.display(), json.len());
    }
}
