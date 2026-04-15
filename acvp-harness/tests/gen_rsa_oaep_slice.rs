#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
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
    clippy::similar_names
)]
//! One-shot helper that generates `RSA-OAEP-RFC8017/kat-slice.json`.
//!
//!   cargo test -p acvp-harness --test gen_rsa_oaep_slice -- --ignored --nocapture

use std::io::Write;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

// Same key as sigGen (from sigPrim tgId=4)
const N_HEX: &str = "DAF664E04A3C85EAA67F3399FC97DE34C1F99F76AA2BE18F27FDB168C542BE883AFCD787CD902D2BF94FBB180529EF39731489F5CBDA3E25A2E1A5AE26016C42AC76AFE0904C7B86B890313CDD93129C55111719B467DDF672AD845DF86B707D386C318718BE5A346F153C79C7361BDA7759F2E99C3454DF3A9E2D7AC47B32089437B85690193BFB51CC919E796313700477491A8074F06DC8DA02437611B8DB868ACBC35C46CC7B325BC3697B3456D6C50D5FF6D4077EAC3B06C44386BACB88891BEB040CF40BBA0D501D52F305AD3D6276376AA87CFF9E5EC5EC93ED2D3A3BAF6AF3B262AAA2C14E9A2C9A3162CD0BCD9A1903DC0DE038336800513D8F53D5";
const E_HEX: &str = "010001";
const D_HEX: &str = "0D9B3F1482F874D7EA85C006A3202AD23B759017B72667EB55F0595C69D9A66E5FC00382B05EF3B7A653F28BE1124487DCE35B59575416058FB416F015F383AF36F95F1F84C803EB10C0011747AB927DFD7944E6B783B6D2D038811FB7C6B1644EA3C6861F1F010AFE16233E6C072C3EECA8BDC40F8D5EF2CA39371948696167F297C5BA344881CF6C79C432513AFE8A176FBD699ECCD9399DB35589E75D5567D41209DD384E4B7B270706CCF8D4C21525F20309BE86AF85D18B7F6EE893DA8BDECF2911CA35BACF7415595C0569EAC95C7B0268563C948C5326A0ACFD3B1EBAFDA2FB6BBE137760C978208F2B54F39803FB4C7A07A2294F62F85A50034CA261";

const MESSAGES: [&str; 5] = [
    "48656C6C6F", // "Hello"
    "ABCDEF0123456789",
    "00112233445566778899AABBCCDDEEFF",
    "FF",
    "0102030405060708090A0B0C0D0E0F10",
];

const SEEDS: [&str; 5] = [
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
    "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210",
    "AABBCCDDEEFF00110011223344556677889900AABBCCDDEEFF001122334455FF",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
];

#[test]
#[ignore]
fn generate_rsa_oaep_slice() {
    let n = hex_decode(N_HEX);
    let d = hex_decode(D_HEX);
    let e_bytes = hex_decode(E_HEX);

    let n_arr: [u8; 256] = n.as_slice().try_into().unwrap();
    let d_arr: [u8; 256] = d.as_slice().try_into().unwrap();

    let mut e_val: u64 = 0;
    for &b in &e_bytes {
        e_val = (e_val << 8) | u64::from(b);
    }

    let label = b""; // empty label, standard OAEP

    // Group 1: encrypt tests (given msg + seed → expected ct)
    let mut encrypt_tests = Vec::new();
    for (i, (msg_hex, seed_hex)) in MESSAGES.iter().zip(SEEDS.iter()).enumerate() {
        let msg = hex_decode(msg_hex);
        let seed = hex_decode(seed_hex);
        let seed_arr: [u8; 32] = seed.as_slice().try_into().unwrap();

        let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
            &n_arr, e_val, label, &msg, &seed_arr,
        )
        .expect("OAEP encrypt failed");

        // Verify decrypt round-trips
        let mut out = [0u8; 190]; // MAX_MSG_LEN
        let mlen = oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_nocrt_internal(
            &n_arr, &d_arr, label, &ct, &mut out,
        )
        .expect("OAEP decrypt failed");
        assert_eq!(
            &out[..mlen],
            msg.as_slice(),
            "decrypt mismatch for test {i}"
        );

        encrypt_tests.push(format!(
            r#"        {{"tcId": {}, "msg": "{}", "seed": "{}", "ct": "{}"}}"#,
            i + 1,
            msg_hex,
            seed_hex,
            hex_upper(&ct),
        ));
    }

    // Group 2: decrypt tests (given ct → expected pt + ptLen)
    let mut decrypt_tests = Vec::new();
    for (i, (msg_hex, seed_hex)) in MESSAGES.iter().zip(SEEDS.iter()).enumerate() {
        let msg = hex_decode(msg_hex);
        let seed = hex_decode(seed_hex);
        let seed_arr: [u8; 32] = seed.as_slice().try_into().unwrap();

        let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(
            &n_arr, e_val, label, &msg, &seed_arr,
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
  "vsId": 0,
  "algorithm": "RSA",
  "mode": "OAEP",
  "revision": "RFC8017",
  "isSample": true,
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "n": "{N_HEX}",
      "e": "{E_HEX}",
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
      "n": "{N_HEX}",
      "e": "{E_HEX}",
      "d": "{D_HEX}",
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
    std::fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("Wrote {}", out_path.display());
}
