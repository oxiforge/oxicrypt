#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::format_collect,
    clippy::needless_range_loop,
    clippy::manual_string_new,
    clippy::uninlined_format_args,
    clippy::many_single_char_names,
    clippy::ignore_without_reason
)]
//! One-shot helper that generates `EDDSA-keyGen-1.0/kat-slice.json`.
//!
//!   cargo test -p acvp-harness --test gen_eddsa_keygen_slice -- --ignored --nocapture

use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Ten deterministic seeds — each produces a known public key via
/// `keygen_internal`.
const SEEDS: [&[u8; 32]; 10] = [
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\
      \x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
    b"\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0\
      \xEF\xEE\xED\xEC\xEB\xEA\xE9\xE8\xE7\xE6\xE5\xE4\xE3\xE2\xE1\xE0",
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
      \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    b"\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\
      \xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF",
    b"\xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89\
      \xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89",
    b"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\
      \x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11",
    b"\x9C\x78\x73\x08\xE5\x4D\xCA\xB1\x2E\x5D\x63\x5D\x9F\x6C\x3E\x7B\
      \x7A\x1A\xB9\xCD\x0B\x02\x61\x6A\x74\x5C\x07\x6F\x8F\x81\x34\x01",
    b"\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\
      \x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42",
    b"\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE\
      \xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE",
    b"\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\
      \x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA",
];

#[test]
#[ignore]
fn generate_eddsa_keygen_slice() {
    let mut tests_json = Vec::new();
    for (i, seed) in SEEDS.iter().enumerate() {
        let q = fips_eddsa::ed25519::keygen_internal(seed);
        tests_json.push(format!(
            r#"        {{"tcId": {}, "d": "{}", "q": "{}"}}"#,
            i + 1,
            hex_upper(seed.as_slice()),
            hex_upper(&q),
        ));
    }

    let json = format!(
        r#"{{
  "vsId": 0,
  "algorithm": "EDDSA",
  "mode": "keyGen",
  "revision": "1.0",
  "isSample": true,
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
        tests_json.join(",\n"),
    );

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files/EDDSA-keyGen-1.0");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("Wrote {}", out_path.display());
}
