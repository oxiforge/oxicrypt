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
    clippy::items_after_statements,
    clippy::ignore_without_reason,
    clippy::similar_names,
    // Lifecycle generators use `let mut tc_id = 1; for _ in 0..N { ...; tc_id += 1; }`
    // as a deliberate fixture-builder idiom; rewriting to `for tc_id in 1..=N` would
    // be cosmetic. Allow at file scope rather than every test-scaffold module.
    clippy::explicit_counter_loop
)]
//! One-shot helper that generates an RSA OAEP lifecycle vector file:
//!
//! - `RSA-OAEP-RFC8017/lifecycle-slice.json`
//!
//! Reuses the same DRBG seed as the RSA lifecycle slices (R37/R39) to
//! regenerate the same RSA-2048 key, then exercises OAEP encrypt→decrypt
//! (both CRT and non-CRT paths) with deterministic seeds, proving
//! keyGen→OAEP encrypt→OAEP decrypt pipeline consistency.
//!
//!   cargo test -p acvp-harness --test gen_rsa_oaep_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

const NUM_TESTS: usize = 5;

const MESSAGES: [&[u8]; NUM_TESTS] = [
    b"oxicrypt-oaep-lifecycle-msg-01",
    b"oxicrypt-oaep-lifecycle-msg-02",
    b"oxicrypt-oaep-lifecycle-msg-03",
    b"oxicrypt-oaep-lifecycle-msg-04",
    b"oxicrypt-oaep-lifecycle-msg-05",
];

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_rsa_oaep_lifecycle_slice() {
    ensure_initialized().expect("FIPS init");

    // ── Reproduce the RSA key from the lifecycle DRBG seed ───────
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"oxicrypt-rsa-lifecycle-gen-entropy-v1",
        b"oxicrypt-rsa-lifecycle-gen-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    let km = oxicrypt_rsa::keygen::generate_2048(&mut drbg, 65537).expect("RSA keygen");

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

    // ── Generate OAEP seeds deterministically ────────────────────
    let mut seed_drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    seed_drbg
        .instantiate(
            b"oxicrypt-rsa-oaep-lifecycle-seed-entropy-v1",
            b"oxicrypt-rsa-oaep-lifecycle-seed-nonce-v1",
            b"",
        )
        .expect("seed drbg instantiate");

    let mut enc_tests = Vec::new();
    let mut crt_dec_tests = Vec::new();
    let mut nocrt_dec_tests = Vec::new();
    let mut tc_id: usize = 1;

    for msg in &MESSAGES {
        let mut oaep_seed = [0u8; 32];
        seed_drbg
            .generate(None, &mut oaep_seed)
            .expect("drbg gen seed");

        let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
            &n_bytes, e, b"", // empty label
            msg, &oaep_seed,
        )
        .expect("OAEP encrypt");

        let msg_hex = hex_upper(msg);
        let seed_hex = hex_upper(&oaep_seed);
        let ct_hex = hex_upper(&ct);

        // Verify CRT decrypt works
        let mut crt_out = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
        let crt_len = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_crt_internal(
            &n_bytes,
            e,
            &p_bytes,
            &q_bytes,
            &dp_bytes,
            &dq_bytes,
            &qinv_bytes,
            b"",
            &ct,
            &mut crt_out,
        )
        .expect("OAEP CRT decrypt");
        assert_eq!(
            &crt_out[..crt_len],
            *msg,
            "CRT decrypt mismatch for msg {tc_id}"
        );

        // Verify non-CRT decrypt works
        let mut nocrt_out = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
        let nocrt_len = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_nocrt_internal(
            &n_bytes,
            &d_bytes,
            b"",
            &ct,
            &mut nocrt_out,
        )
        .expect("OAEP non-CRT decrypt");
        assert_eq!(
            &nocrt_out[..nocrt_len],
            *msg,
            "non-CRT decrypt mismatch for msg {tc_id}"
        );

        enc_tests.push(format!(
            r#"        {{"tcId": {}, "msg": "{}", "seed": "{}", "ct": "{}"}}"#,
            tc_id, msg_hex, seed_hex, ct_hex
        ));

        crt_dec_tests.push(format!(
            r#"        {{"tcId": {}, "ct": "{}", "pt": "{}", "ptLen": {}}}"#,
            tc_id + NUM_TESTS,
            ct_hex,
            msg_hex,
            msg.len()
        ));

        nocrt_dec_tests.push(format!(
            r#"        {{"tcId": {}, "ct": "{}", "pt": "{}", "ptLen": {}}}"#,
            tc_id + 2 * NUM_TESTS,
            ct_hex,
            msg_hex,
            msg.len()
        ));

        tc_id += 1;
    }

    let json = format!(
        r#"{{
  "_generator": "gen_rsa_oaep_lifecycle_slice (R43)",
  "algorithm": "RSA",
  "mode": "OAEP",
  "revision": "RFC8017",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "n": "{}",
      "e": "{}",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "keyMode": "crt",
      "n": "{}",
      "e": "{}",
      "p": "{}",
      "q": "{}",
      "dmp1": "{}",
      "dmq1": "{}",
      "iqmp": "{}",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 3,
      "testType": "AFT",
      "direction": "decrypt",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "keyMode": "standard",
      "n": "{}",
      "d": "{}",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        n_hex,
        e_hex,
        enc_tests.join(",\n"),
        n_hex,
        e_hex,
        p_hex,
        q_hex,
        dp_hex,
        dq_hex,
        qinv_hex,
        crt_dec_tests.join(",\n"),
        n_hex,
        d_hex,
        nocrt_dec_tests.join(",\n")
    );

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vendor/nist/acvp-server/gen-val/json-files");
    let path = base.join("RSA-OAEP-RFC8017/lifecycle-slice.json");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("wrote {} ({} bytes)", path.display(), json.len());
}
