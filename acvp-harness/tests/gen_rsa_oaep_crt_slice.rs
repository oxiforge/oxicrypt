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
//! One-shot helper that generates `RSA-OAEP-RFC8017/crt-kat-slice.json`.
//!
//! Creates OAEP encrypt + CRT decrypt test groups using a freshly
//! DRBG-generated RSA-2048 key pair.
//!
//!   cargo test -p acvp-harness --test gen_rsa_oaep_crt_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const MESSAGES: [&str; 5] = [
    "48656C6C6F", // "Hello"
    "ABCDEF0123456789",
    "00112233445566778899AABBCCDDEEFF",
    "FF",
    "0102030405060708090A0B0C0D0E0F10",
];

const SEEDS: [&str; 5] = [
    "AA00BB11CC22DD33EE44FF5500112233AA00BB11CC22DD33EE44FF5500112233",
    "1122334455667788990011223344556677889900112233445566778899001122",
    "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE",
];

#[test]
#[ignore]
fn generate_rsa_oaep_crt_slice() {
    ensure_initialized().expect("FIPS init");

    // Generate a fresh RSA-2048 key pair with CRT components.
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"oxicrypt-oaep-crt-gen-entropy-v1",
        b"oxicrypt-oaep-crt-gen-nonce-v1",
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

    // Verify the key works for non-CRT first.
    let label = b"";
    let test_msg = b"verify";
    let test_seed = [0x42u8; 32];
    let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
        &n_bytes, e, label, test_msg, &test_seed,
    )
    .expect("encrypt sanity check");
    let mut test_out = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
    let _tl = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_nocrt_internal(
        &n_bytes,
        &d_bytes,
        label,
        &ct,
        &mut test_out,
    )
    .expect("non-CRT decrypt sanity check");
    let _tl2 = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_crt_internal(
        &n_bytes,
        e,
        &p_bytes,
        &q_bytes,
        &dp_bytes,
        &dq_bytes,
        &qinv_bytes,
        label,
        &ct,
        &mut test_out,
    )
    .expect("CRT decrypt sanity check");

    let n_hex = hex_upper(&n_bytes);
    let e_hex = "010001"; // 65537
    let _d_hex = hex_upper(&d_bytes);
    let p_hex = hex_upper(&p_bytes);
    let q_hex = hex_upper(&q_bytes);
    let dp_hex = hex_upper(&dp_bytes);
    let dq_hex = hex_upper(&dq_bytes);
    let qinv_hex = hex_upper(&qinv_bytes);

    // Group 1: encrypt (same public key)
    let mut encrypt_tests = Vec::new();
    for (i, (msg_hex, seed_hex)) in MESSAGES.iter().zip(SEEDS.iter()).enumerate() {
        let msg = hex_decode(msg_hex);
        let seed = hex_decode(seed_hex);
        let seed_arr: [u8; 32] = seed.as_slice().try_into().unwrap();

        let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
            &n_bytes, e, label, &msg, &seed_arr,
        )
        .expect("OAEP encrypt failed");

        // Verify CRT decrypt round-trips
        let mut out = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
        let mlen = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_crt_internal(
            &n_bytes,
            e,
            &p_bytes,
            &q_bytes,
            &dp_bytes,
            &dq_bytes,
            &qinv_bytes,
            label,
            &ct,
            &mut out,
        )
        .unwrap_or_else(|| panic!("CRT decrypt failed for test {i}"));
        assert_eq!(
            &out[..mlen],
            msg.as_slice(),
            "CRT decrypt mismatch test {i}"
        );

        encrypt_tests.push(format!(
            r#"        {{"tcId": {}, "msg": "{}", "seed": "{}", "ct": "{}"}}"#,
            i + 1,
            msg_hex,
            seed_hex,
            hex_upper(&ct),
        ));
    }

    // Group 2: CRT decrypt
    let mut decrypt_tests = Vec::new();
    for (i, (msg_hex, seed_hex)) in MESSAGES.iter().zip(SEEDS.iter()).enumerate() {
        let msg = hex_decode(msg_hex);
        let seed = hex_decode(seed_hex);
        let seed_arr: [u8; 32] = seed.as_slice().try_into().unwrap();

        let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
            &n_bytes, e, label, &msg, &seed_arr,
        )
        .unwrap();

        let tc_id = MESSAGES.len() + i + 1;
        decrypt_tests.push(format!(
            r#"        {{"tcId": {}, "ct": "{}", "pt": "{}", "ptLen": {}}}"#,
            tc_id,
            hex_upper(&ct),
            msg_hex,
            msg.len(),
        ));
    }

    let json = format!(
        r#"{{
  "_source": "oxicrypt self-generated RSA OAEP CRT vectors",
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
      "keyMode": "crt",
      "n": "{n_hex}",
      "e": "{e_hex}",
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
        encrypt_tests.join(",\n"),
        decrypt_tests.join(",\n"),
    );

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files/RSA-OAEP-RFC8017");
    let out_path = out_dir.join("crt-kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.write_all(b"\n").unwrap();
    println!("Wrote {} ({} bytes)", out_path.display(), json.len());
}
