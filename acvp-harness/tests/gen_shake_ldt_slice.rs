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
    clippy::cast_possible_truncation,
    clippy::ignore_without_reason,
    clippy::integer_division
)]
//! One-shot helper that generates SHAKE-128 / SHAKE-256 LDT (Large Data
//! Test) vectors:
//!
//!   - `SHAKE-128-FIPS202/ldt-slice.json`
//!   - `SHAKE-256-FIPS202/ldt-slice.json`
//!
//! Each file has one LDT group with three test cases using different
//! content patterns, message sizes, and output lengths. The expected
//! outputs are computed using the incremental SHAKE `update` API.
//!
//!   cargo test -p acvp-harness --test gen_shake_ldt_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use oxicrypt_xof::{Shake128, Shake256};
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// LDT test parameters: (content_byte, content_bytes, full_bytes, out_bytes)
const LDT_TESTS: [(u8, usize, u64, usize); 3] = [
    // Test 1: single byte 0x61 ('a'), 1 byte content, 1MB total, 32 bytes output
    (0x61, 1, 1_048_576, 32),
    // Test 2: byte 0xDE, 1 byte content, 512KB total, 64 bytes output
    (0xDE, 1, 524_288, 64),
    // Test 3: byte 0xFF, 1 byte content, 2MB total, 128 bytes output
    (0xFF, 1, 2_097_152, 128),
];

/// Streaming SHAKE-128 LDT: absorb `full_bytes` of repeating `pattern`,
/// then squeeze `out_bytes`.
fn shake128_ldt(pattern: &[u8], full_bytes: u64, out_bytes: usize) -> Vec<u8> {
    let mut xof = Shake128::new().expect("Shake128::new");
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        xof.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        xof.update(&pattern[..remaining as usize]);
    }
    xof.finalize();
    let mut out = vec![0u8; out_bytes];
    xof.squeeze(&mut out);
    out
}

/// Streaming SHAKE-256 LDT: absorb `full_bytes` of repeating `pattern`,
/// then squeeze `out_bytes`.
fn shake256_ldt(pattern: &[u8], full_bytes: u64, out_bytes: usize) -> Vec<u8> {
    let mut xof = Shake256::new().expect("Shake256::new");
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        xof.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        xof.update(&pattern[..remaining as usize]);
    }
    xof.finalize();
    let mut out = vec![0u8; out_bytes];
    xof.squeeze(&mut out);
    out
}

struct Variant {
    algorithm: &'static str,
    dir: &'static str,
    squeeze_fn: fn(&[u8], u64, usize) -> Vec<u8>,
}

const VARIANTS: [Variant; 2] = [
    Variant {
        algorithm: "SHAKE-128",
        dir: "SHAKE-128-FIPS202",
        squeeze_fn: shake128_ldt,
    },
    Variant {
        algorithm: "SHAKE-256",
        dir: "SHAKE-256-FIPS202",
        squeeze_fn: shake256_ldt,
    },
];

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_shake_ldt_slices() {
    ensure_initialized().expect("FIPS init");

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files");

    for variant in &VARIANTS {
        let mut tests: Vec<String> = Vec::new();
        for (i, &(byte, content_bytes, full_bytes, out_bytes)) in LDT_TESTS.iter().enumerate() {
            let content_hex = hex_upper(&[byte]);
            let content_length_bits = (content_bytes as u64) * 8;
            let full_length_bits = full_bytes * 8;
            let out_len_bits = (out_bytes as u64) * 8;

            let md = (variant.squeeze_fn)(&[byte], full_bytes, out_bytes);
            let md_hex = hex_upper(&md);

            tests.push(format!(
                r#"        {{
          "tcId": {},
          "outLen": {},
          "largeMsg": {{
            "content": "{}",
            "contentLength": {},
            "fullLength": {},
            "expansionTechnique": "repeating"
          }},
          "md": "{}"
        }}"#,
                i + 1,
                out_len_bits,
                content_hex,
                content_length_bits,
                full_length_bits,
                md_hex,
            ));
        }

        let json = format!(
            r#"{{
  "_source": "oxicrypt self-generated SHAKE LDT vectors (R46)",
  "algorithm": "{}",
  "revision": "FIPS202",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "LDT",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            variant.algorithm,
            tests.join(",\n"),
        );

        let path = base.join(variant.dir).join("ldt-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        println!("Wrote {} ({} bytes)", path.display(), json.len());
    }
}
