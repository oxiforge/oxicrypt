#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::format_collect,
    clippy::needless_range_loop,
    clippy::manual_string_new,
    clippy::uninlined_format_args,
    clippy::many_single_char_names,
    clippy::ignore_without_reason,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::integer_division,
    clippy::too_many_lines
)]
//! One-shot helper that generates a PBKDF2 ACVP vector slice. Run with:
//!
//!   cargo test -p acvp-harness --test gen_pbkdf2_slice -- --ignored --nocapture
//!
//! Generates `vendor/nist/acvp-server/gen-val/json-files/PBKDF-1.0/kat-slice.json`
//! with multiple test groups, one per hmacAlg.

use acvp_harness::ensure_initialized;
use oxicrypt_kdf::{
    Pbkdf2HmacSha1, Pbkdf2HmacSha224, Pbkdf2HmacSha256, Pbkdf2HmacSha384, Pbkdf2HmacSha3_256,
    Pbkdf2HmacSha512,
};
use std::io::Write;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

struct PbCase {
    password: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
    dk_len: usize,
}

fn gen_cases() -> Vec<PbCase> {
    vec![
        PbCase {
            password: b"password".to_vec(),
            salt: b"salt".to_vec(),
            iterations: 1,
            dk_len: 20,
        },
        PbCase {
            password: b"password".to_vec(),
            salt: b"salt".to_vec(),
            iterations: 2,
            dk_len: 20,
        },
        PbCase {
            password: b"password".to_vec(),
            salt: b"salt".to_vec(),
            iterations: 1,
            dk_len: 32,
        },
        PbCase {
            password: vec![0xAA; 32],
            salt: vec![0xBB; 16],
            iterations: 10,
            dk_len: 64,
        },
        PbCase {
            password: b"longpasswordfortest".to_vec(),
            salt: b"saltyenough".to_vec(),
            iterations: 4,
            dk_len: 48,
        },
    ]
}

fn gen_group<F>(tg_id: usize, hmac_alg: &str, derive: F) -> String
where
    F: Fn(&[u8], &[u8], u32, &mut [u8]),
{
    let cases = gen_cases();
    let mut tests_json = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut dk = vec![0u8; c.dk_len];
        derive(&c.password, &c.salt, c.iterations, &mut dk);
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "password": "{}",
          "salt": "{}",
          "iterationCount": {},
          "keyLen": {},
          "derivedKey": "{}"
        }}"#,
            i + 1,
            hex(&c.password),
            hex(&c.salt),
            c.iterations,
            c.dk_len * 8,
            hex(&dk)
        ));
    }
    format!(
        r#"    {{
      "tgId": {},
      "testType": "AFT",
      "hmacAlg": "{}",
      "tests": [
{}
      ]
    }}"#,
        tg_id,
        hmac_alg,
        tests_json.join(",\n")
    )
}

#[test]
#[ignore]
fn generate_pbkdf2_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let dir = format!("{base}/PBKDF-1.0");
    std::fs::create_dir_all(&dir).unwrap();

    let groups = [
        gen_group(1, "SHA-1", |p, s, c, o| {
            Pbkdf2HmacSha1::derive(p, s, c, o).unwrap();
        }),
        gen_group(2, "SHA2-224", |p, s, c, o| {
            Pbkdf2HmacSha224::derive(p, s, c, o).unwrap();
        }),
        gen_group(3, "SHA2-256", |p, s, c, o| {
            Pbkdf2HmacSha256::derive(p, s, c, o).unwrap();
        }),
        gen_group(4, "SHA2-384", |p, s, c, o| {
            Pbkdf2HmacSha384::derive(p, s, c, o).unwrap();
        }),
        gen_group(5, "SHA2-512", |p, s, c, o| {
            Pbkdf2HmacSha512::derive(p, s, c, o).unwrap();
        }),
        gen_group(6, "SHA3-256", |p, s, c, o| {
            Pbkdf2HmacSha3_256::derive(p, s, c, o).unwrap();
        }),
    ];

    let json = format!(
        r#"{{
  "algorithm": "PBKDF",
  "revision": "1.0",
  "testGroups": [
{}
  ]
}}"#,
        groups.join(",\n")
    );

    let path = format!("{dir}/kat-slice.json");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("wrote {path}");
}
