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
//! One-shot helper that generates `RSA-sigGen-FIPS186-5/cross-kat-slice.json`.
//!
//! Creates two groups that cover the cross-product of (sigType × keyMode)
//! not exercised by the upstream `kat-slice.json`:
//!   - Group 1: `pkcs1v1.5` + `keyMode = "crt"` (Bellcore-protected)
//!   - Group 2: `pss` + `keyMode = "standard"` (non-CRT, d-only)
//!
//! Both groups use a DRBG-generated RSA-2048 key pair and verify each
//! signature via the corresponding verify function.
//!
//!   cargo test -p acvp-harness --test gen_rsa_siggen_cross_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

const MESSAGES: [&str; 5] = [
    "48656C6C6F",                                // "Hello"
    "ABCDEF0123456789",
    "00112233445566778899AABBCCDDEEFF",
    "FF",
    "0102030405060708090A0B0C0D0E0F10",
];

const SALTS: [&str; 5] = [
    "AA00BB11CC22DD33EE44FF5500112233AA00BB11CC22DD33EE44FF5500112233",
    "1122334455667788990011223344556677889900112233445566778899001122",
    "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE",
];

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
#[ignore]
fn generate_rsa_siggen_cross_slice() {
    ensure_initialized().expect("FIPS init");

    // Generate a fresh RSA-2048 key pair with CRT components.
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"pqclib-siggen-cross-entropy-v1",
        b"pqclib-siggen-cross-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    let km = oxicrypt_rsa::keygen::generate_2048(&mut drbg, 65537)
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

    // ── Group 1: pkcs1v1.5 + CRT (Bellcore) ──────────────────────
    let mut pkcs_crt_tests = Vec::new();
    for (i, msg_hex) in MESSAGES.iter().enumerate() {
        let msg = hex_decode(msg_hex);
        let sig = oxicrypt_rsa::rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
            &n_bytes, e, &p_bytes, &q_bytes, &dp_bytes, &dq_bytes, &qinv_bytes,
            &msg,
        )
        .unwrap_or_else(|| panic!("PKCS#1v1.5 CRT sign failed for test {i}"));

        // Verify the signature.
        let ok = oxicrypt_rsa::rsa_pkcs1_v15_verify_2048_sha256_internal(
            &n_bytes, e, &msg, &sig,
        );
        assert!(ok, "PKCS#1v1.5 CRT verify failed for test {i}");

        pkcs_crt_tests.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "signature": "{}"}}"#,
            i + 1,
            msg_hex,
            hex_upper(&sig),
        ));
    }

    // ── Group 2: PSS + non-CRT (standard) ────────────────────────
    let mut pss_nocrt_tests = Vec::new();
    for (i, (msg_hex, salt_hex)) in MESSAGES.iter().zip(SALTS.iter()).enumerate() {
        let msg = hex_decode(msg_hex);
        let salt = hex_decode(salt_hex);
        let salt_arr: [u8; 32] = salt.as_slice().try_into().unwrap();

        let sig = oxicrypt_rsa::rsa_pss_sign_2048_sha256_internal(
            &n_bytes, &d_bytes, &msg, &salt_arr,
        )
        .unwrap_or_else(|| panic!("PSS non-CRT sign failed for test {i}"));

        // Verify the signature.
        let ok = oxicrypt_rsa::rsa_pss_verify_2048_sha256_internal(
            &n_bytes, e, &msg, &sig,
        );
        assert!(ok, "PSS non-CRT verify failed for test {i}");

        let tc_id = MESSAGES.len() + i + 1;
        pss_nocrt_tests.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "salt": "{}", "signature": "{}"}}"#,
            tc_id,
            msg_hex,
            salt_hex,
            hex_upper(&sig),
        ));
    }

    let json = format!(
        r#"{{
  "_source": "oxicrypt self-generated RSA sigGen cross-product vectors",
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
    }},
    {{
      "tgId": 2,
      "testType": "GDT",
      "sigType": "pss",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "keyMode": "standard",
      "n": "{n_hex}",
      "d": "{d_hex}",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        pkcs_crt_tests.join(",\n"),
        pss_nocrt_tests.join(",\n"),
    );

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files/RSA-sigGen-FIPS186-5");
    let out_path = out_dir.join("cross-kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.write_all(b"\n").unwrap();
    println!("Wrote {} ({} bytes)", out_path.display(), json.len());
}
