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
//! One-shot helper that generates
//! `RSA-OAEP-RFC8017/combined-kat-slice.json`.
//!
//! Creates a single RSA-2048 key and produces three test groups:
//!
//! 1. **encrypt** — public-key OAEP encrypt with deterministic seed
//! 2. **CRT decrypt** — CRT private-key OAEP decrypt (Bellcore)
//! 3. **non-CRT decrypt** — standard `(n, d)` OAEP decrypt
//!
//! Groups 2 and 3 decrypt the *same ciphertexts* produced by group 1,
//! proving that both private-key paths yield identical plaintext.
//!
//!   cargo test -p acvp-harness --test gen_rsa_oaep_combined_slice -- --ignored --nocapture

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
    "48656C6C6F",                                // "Hello"
    "ABCDEF0123456789",
    "00112233445566778899AABBCCDDEEFF",
    "FF",
    "0102030405060708090A0B0C0D0E0F10",
];

const SEEDS: [&str; 5] = [
    "BB11CC22DD33EE44FF5500112233AA00BB11CC22DD33EE44FF5500112233AA00",
    "2233445566778899001122334455667788990011223344556677889900112233",
    "EEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100FF",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
];

#[test]
#[ignore]
fn generate_rsa_oaep_combined_slice() {
    ensure_initialized().expect("FIPS init");

    // Generate a fresh RSA-2048 key pair.
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"pqclib-oaep-combined-gen-entropy-v1",
        b"pqclib-oaep-combined-gen-nonce-v1",
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
    let label = b"";

    let n_hex = hex_upper(&n_bytes);
    let d_hex = hex_upper(&d_bytes);
    let e_hex = "010001";
    let p_hex = hex_upper(&p_bytes);
    let q_hex = hex_upper(&q_bytes);
    let dp_hex = hex_upper(&dp_bytes);
    let dq_hex = hex_upper(&dq_bytes);
    let qinv_hex = hex_upper(&qinv_bytes);

    // Encrypt all messages and verify both decrypt paths agree.
    let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
    for (i, (msg_hex, seed_hex)) in MESSAGES.iter().zip(SEEDS.iter()).enumerate() {
        let msg = hex_decode(msg_hex);
        let seed = hex_decode(seed_hex);
        let seed_arr: [u8; 32] = seed.as_slice().try_into().unwrap();

        let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
            &n_bytes, e, label, &msg, &seed_arr,
        )
        .unwrap_or_else(|| panic!("encrypt failed test {i}"));

        // CRT decrypt
        let mut out_crt = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
        let len_crt = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_crt_internal(
            &n_bytes, e,
            &p_bytes, &q_bytes, &dp_bytes, &dq_bytes, &qinv_bytes,
            label, &ct, &mut out_crt,
        )
        .unwrap_or_else(|| panic!("CRT decrypt failed test {i}"));

        // Non-CRT decrypt
        let mut out_std = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
        let len_std = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_nocrt_internal(
            &n_bytes, &d_bytes, label, &ct, &mut out_std,
        )
        .unwrap_or_else(|| panic!("non-CRT decrypt failed test {i}"));

        // Path equivalence: both must produce the same plaintext.
        assert_eq!(
            &out_crt[..len_crt],
            &out_std[..len_std],
            "path equivalence failed test {i}: CRT and non-CRT differ"
        );
        assert_eq!(
            &out_crt[..len_crt],
            msg.as_slice(),
            "round-trip mismatch test {i}"
        );

        ciphertexts.push(ct.to_vec());
    }

    // Group 1: encrypt
    let encrypt_tests: Vec<String> = MESSAGES
        .iter()
        .zip(SEEDS.iter())
        .zip(ciphertexts.iter())
        .enumerate()
        .map(|(i, ((msg_hex, seed_hex), ct))| {
            format!(
                r#"        {{"tcId": {}, "msg": "{}", "seed": "{}", "ct": "{}"}}"#,
                i + 1,
                msg_hex,
                seed_hex,
                hex_upper(ct),
            )
        })
        .collect();

    // Group 2: CRT decrypt
    let crt_decrypt_tests: Vec<String> = MESSAGES
        .iter()
        .zip(ciphertexts.iter())
        .enumerate()
        .map(|(i, (msg_hex, ct))| {
            let msg = hex_decode(msg_hex);
            format!(
                r#"        {{"tcId": {}, "ct": "{}", "pt": "{}", "ptLen": {}}}"#,
                MESSAGES.len() + i + 1,
                hex_upper(ct),
                msg_hex,
                msg.len(),
            )
        })
        .collect();

    // Group 3: non-CRT decrypt (same ciphertexts, same expected pt)
    let std_decrypt_tests: Vec<String> = MESSAGES
        .iter()
        .zip(ciphertexts.iter())
        .enumerate()
        .map(|(i, (msg_hex, ct))| {
            let msg = hex_decode(msg_hex);
            format!(
                r#"        {{"tcId": {}, "ct": "{}", "pt": "{}", "ptLen": {}}}"#,
                2 * MESSAGES.len() + i + 1,
                hex_upper(ct),
                msg_hex,
                msg.len(),
            )
        })
        .collect();

    let json = format!(
        r#"{{
  "_source": "oxicrypt self-generated RSA OAEP combined vectors (path equivalence)",
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
    }},
    {{
      "tgId": 3,
      "testType": "AFT",
      "direction": "decrypt",
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
        encrypt_tests.join(",\n"),
        crt_decrypt_tests.join(",\n"),
        std_decrypt_tests.join(",\n"),
    );

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files/RSA-OAEP-RFC8017");
    let out_path = out_dir.join("combined-kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.write_all(b"\n").unwrap();
    println!("Wrote {} ({} bytes)", out_path.display(), json.len());
}
