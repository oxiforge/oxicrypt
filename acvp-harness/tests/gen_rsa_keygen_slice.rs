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
//! One-shot helper that generates `RSA-keyGen-FIPS186-5/kat-slice.json`.
//!
//! Creates RSA-2048 key generation test vectors using DRBG-seeded
//! key generation. Each test provides distinct DRBG seed material
//! (entropy, nonce, personalization) and records the resulting key
//! components.
//!
//!   cargo test -p acvp-harness --test gen_rsa_keygen_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Number of keygen tests to produce.
const NUM_TESTS: usize = 5;

/// Per-test DRBG seed material. Each entry is (entropy, nonce, perso)
/// as hex strings. The entropy and nonce values are long enough for
/// HMAC_DRBG-SHA256 (entropy ≥ 32 bytes, nonce ≥ 16 bytes).
const SEEDS: [(& str, &str, &str); NUM_TESTS] = [
    (
        "AA00BB11CC22DD33EE44FF5500112233AA00BB11CC22DD33EE44FF5500112233",
        "1122334455667788990011223344556677889900",
        "",
    ),
    (
        "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100",
        "AABBCCDDEEFF00112233445566778899AABBCCDD",
        "",
    ),
    (
        "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
        "F0E0D0C0B0A090807060504030201000F0E0D0C0",
        "70716C69622D7273612D6B657967656E2D763100",
    ),
    (
        "CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE",
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "",
    ),
    (
        "A5A5A5A5B6B6B6B6C7C7C7C7D8D8D8D8E9E9E9E9FAFAFA0A1B1B1B2C2C2C2C",
        "0000000000000000000000000000000000000001",
        "70716C69622D7273612D6B657967656E2D763200",
    ),
];

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
#[ignore]
fn generate_rsa_keygen_slice() {
    ensure_initialized().expect("FIPS init");

    let mut test_entries = Vec::new();

    for (i, (entropy_hex, nonce_hex, perso_hex)) in SEEDS.iter().enumerate() {
        let entropy = hex_decode(entropy_hex);
        let nonce = hex_decode(nonce_hex);
        let perso = hex_decode(perso_hex);

        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(&entropy, &nonce, &perso)
            .unwrap_or_else(|e| panic!("DRBG instantiate failed for test {i}: {e:?}"));

        let km = oxicrypt_rsa::keygen::generate_2048(&mut drbg, 65537)
            .unwrap_or_else(|e| panic!("RSA keygen failed for test {i}: {e:?}"));

        let n_bytes: [u8; 256] = km.n.to_be_bytes();
        let d_bytes: [u8; 256] = km.d.to_be_bytes();
        let p_bytes: [u8; 128] = km.p.to_be_bytes();
        let q_bytes: [u8; 128] = km.q.to_be_bytes();
        let dp_bytes: [u8; 128] = km.dp.to_be_bytes();
        let dq_bytes: [u8; 128] = km.dq.to_be_bytes();
        let qinv_bytes: [u8; 128] = km.qinv.to_be_bytes();

        // Sanity check: encrypt + decrypt round-trip via the generated key.
        let e: u64 = 65537;
        let label = b"";
        let test_msg = b"keygen-sanity";
        let test_seed = [0x42u8; 32];
        let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
            &n_bytes, e, label, test_msg, &test_seed,
        )
        .unwrap_or_else(|| panic!("OAEP encrypt sanity failed for test {i}"));
        let mut out = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
        let pt_len = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_crt_internal(
            &n_bytes, e, &p_bytes, &q_bytes, &dp_bytes, &dq_bytes, &qinv_bytes,
            label, &ct, &mut out,
        )
        .unwrap_or_else(|| panic!("CRT decrypt sanity failed for test {i}"));
        assert_eq!(
            &out[..pt_len], test_msg,
            "keygen sanity: round-trip mismatch for test {i}"
        );

        let tc_id = i + 1;
        test_entries.push(format!(
            r#"        {{
          "tcId": {},
          "entropy": "{}",
          "nonce": "{}",
          "perso": "{}",
          "n": "{}",
          "d": "{}",
          "e": "010001",
          "p": "{}",
          "q": "{}",
          "dmp1": "{}",
          "dmq1": "{}",
          "iqmp": "{}"
        }}"#,
            tc_id,
            entropy_hex,
            nonce_hex,
            perso_hex,
            hex_upper(&n_bytes),
            hex_upper(&d_bytes),
            hex_upper(&p_bytes),
            hex_upper(&q_bytes),
            hex_upper(&dp_bytes),
            hex_upper(&dq_bytes),
            hex_upper(&qinv_bytes),
        ));
    }

    let json = format!(
        r#"{{
  "_source": "oxicrypt self-generated RSA keyGen FIPS186-5 vectors",
  "algorithm": "RSA",
  "mode": "keyGen",
  "revision": "FIPS186-5",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "modulo": 2048,
      "fixedPubExp": "010001",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        test_entries.join(",\n"),
    );

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files/RSA-keyGen-FIPS186-5");
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("create dir {}: {e}", out_dir.display()));
    let out_path = out_dir.join("kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.write_all(b"\n").unwrap();
    println!("Wrote {} ({} bytes)", out_path.display(), json.len());
}
