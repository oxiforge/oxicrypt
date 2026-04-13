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
    clippy::cast_possible_truncation,
    clippy::ignore_without_reason
)]
//! One-shot helper that generates SHA-3 LDT (Large Data Test) vectors:
//!
//!   - `SHA3-224/ldt-slice.json`
//!   - `SHA3-256/ldt-slice.json`
//!   - `SHA3-384/ldt-slice.json`
//!   - `SHA3-512/ldt-slice.json`
//!
//! Each file has one LDT group with three test cases using different
//! content patterns and message sizes. The expected digests are
//! computed using the incremental `Sha3::update` API.
//!
//!   cargo test -p acvp-harness --test gen_sha3_ldt_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Content patterns for LDT tests: (content_hex, content_bytes, full_bytes)
const LDT_TESTS: [(u8, usize, u64); 3] = [
    // Test 1: single byte 0x61 ('a'), 1 byte content, 1MB total
    (0x61, 1, 1_048_576),
    // Test 2: byte 0xDE, 1 byte content, 512KB total
    (0xDE, 1, 524_288),
    // Test 3: byte 0xFF, 1 byte content, 2MB total
    (0xFF, 1, 2_097_152),
];

/// Compute SHA-3 digest over `full_bytes` of repeating `pattern` using
/// the incremental API.
fn ldt_digest<const RATE: usize, const OUT: usize>(
    pattern: &[u8],
    full_bytes: u64,
) -> [u8; OUT] {
    let mut hasher = oxicrypt_sha::sha3::Sha3::<RATE, OUT>::new_internal();
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        hasher.update(&pattern[..remaining as usize]);
    }
    hasher.finalize()
}

struct Variant {
    algorithm: &'static str,
    dir: &'static str,
    digest_fn: fn(u8, u64) -> Vec<u8>,
}

fn digest_224(byte: u8, full_bytes: u64) -> Vec<u8> {
    ldt_digest::<{ oxicrypt_sha::sha3::SHA3_224_RATE }, { oxicrypt_sha::sha3::SHA3_224_DIGEST_SIZE }>(
        &[byte], full_bytes,
    )
    .to_vec()
}

fn digest_256(byte: u8, full_bytes: u64) -> Vec<u8> {
    ldt_digest::<{ oxicrypt_sha::sha3::SHA3_256_RATE }, { oxicrypt_sha::sha3::SHA3_256_DIGEST_SIZE }>(
        &[byte], full_bytes,
    )
    .to_vec()
}

fn digest_384(byte: u8, full_bytes: u64) -> Vec<u8> {
    ldt_digest::<{ oxicrypt_sha::sha3::SHA3_384_RATE }, { oxicrypt_sha::sha3::SHA3_384_DIGEST_SIZE }>(
        &[byte], full_bytes,
    )
    .to_vec()
}

fn digest_512(byte: u8, full_bytes: u64) -> Vec<u8> {
    ldt_digest::<{ oxicrypt_sha::sha3::SHA3_512_RATE }, { oxicrypt_sha::sha3::SHA3_512_DIGEST_SIZE }>(
        &[byte], full_bytes,
    )
    .to_vec()
}

const VARIANTS: [Variant; 4] = [
    Variant {
        algorithm: "SHA3-224",
        dir: "SHA3-224-2.0",
        digest_fn: digest_224,
    },
    Variant {
        algorithm: "SHA3-256",
        dir: "SHA3-256-2.0",
        digest_fn: digest_256,
    },
    Variant {
        algorithm: "SHA3-384",
        dir: "SHA3-384-2.0",
        digest_fn: digest_384,
    },
    Variant {
        algorithm: "SHA3-512",
        dir: "SHA3-512-2.0",
        digest_fn: digest_512,
    },
];

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_sha3_ldt_slices() {
    ensure_initialized().expect("FIPS init");

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files");

    for variant in &VARIANTS {
        let mut tests: Vec<String> = Vec::new();
        for (i, &(byte, content_bytes, full_bytes)) in LDT_TESTS.iter().enumerate() {
            let content_hex = hex_upper(&[byte]);
            let content_length_bits = (content_bytes as u64) * 8;
            let full_length_bits = full_bytes * 8;

            let md = (variant.digest_fn)(byte, full_bytes);
            let md_hex = hex_upper(&md);

            tests.push(format!(
                r#"        {{
          "tcId": {},
          "largeMsg": {{
            "content": "{}",
            "contentLength": {},
            "fullLength": {},
            "expansionTechnique": "repeating"
          }},
          "md": "{}"
        }}"#,
                i + 1,
                content_hex,
                content_length_bits,
                full_length_bits,
                md_hex,
            ));
        }

        let json = format!(
            r#"{{
  "_source": "oxicrypt self-generated SHA-3 LDT vectors",
  "algorithm": "{}",
  "revision": "2.0",
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
