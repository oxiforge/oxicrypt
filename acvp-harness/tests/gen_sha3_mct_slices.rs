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
    clippy::ignore_without_reason
)]
//! One-shot helper that generates `SHA3-{224,256,384,512}-2.0/mct-slice.json`.
//!
//!   cargo test -p acvp-harness --test gen_sha3_mct_slices -- --ignored --nocapture
//!
//! SHA-3 MCT algorithm (ACVP SHA-3 §6.2):
//!
//! ```text
//! MD[0] = Seed  (random initial message, digestLen bytes)
//! For i = 0..99:
//!     For j = 0..999:
//!         MD[j+1] = SHA3(MD[j])
//!     Output[i] = MD[1000]
//!     MD[0] = MD[1000]
//! ```
//!
//! We record the first 5 outer iterations (resultsArray[0..5]) to keep
//! the vendored slice small while still exercising the full MCT engine.

use acvp_harness::ensure_initialized;
use std::io::Write;

/// Number of outer MCT iterations to run (full spec).
const MCT_OUTER: usize = 100;
/// Number of inner MCT iterations per outer iteration.
const MCT_INNER: usize = 1000;
/// Number of resultsArray entries to keep in the vendored slice.
const RESULTS_KEPT: usize = 5;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

struct Sha3Variant {
    name: &'static str,
    hash_fn: fn(&[u8]) -> Vec<u8>,
    /// Initial seed (digestLen bytes of deterministic data).
    seed: Vec<u8>,
}

fn sha3_224(data: &[u8]) -> Vec<u8> {
    oxicrypt_sha::sha3::sha3_224(data)
        .expect("sha3_224")
        .to_vec()
}
fn sha3_256(data: &[u8]) -> Vec<u8> {
    oxicrypt_sha::sha3::sha3_256(data)
        .expect("sha3_256")
        .to_vec()
}
fn sha3_384(data: &[u8]) -> Vec<u8> {
    oxicrypt_sha::sha3::sha3_384(data)
        .expect("sha3_384")
        .to_vec()
}
fn sha3_512(data: &[u8]) -> Vec<u8> {
    oxicrypt_sha::sha3::sha3_512(data)
        .expect("sha3_512")
        .to_vec()
}

fn make_seed(digest_len: usize, variant_byte: u8) -> Vec<u8> {
    // Deterministic seed: repeating pattern unique per variant
    (0..digest_len)
        .map(|i| {
            #[allow(clippy::cast_possible_truncation)]
            let b = (i as u8).wrapping_add(variant_byte);
            b ^ 0xA5
        })
        .collect()
}

fn run_mct(hash_fn: fn(&[u8]) -> Vec<u8>, seed: &[u8]) -> Vec<Vec<u8>> {
    let mut results = Vec::with_capacity(MCT_OUTER);
    let mut md = seed.to_vec();
    for _i in 0..MCT_OUTER {
        for _j in 0..MCT_INNER {
            md = hash_fn(&md);
        }
        results.push(md.clone());
    }
    results
}

fn generate_mct_slice(variant: &Sha3Variant) -> String {
    let results = run_mct(variant.hash_fn, &variant.seed);

    // Build resultsArray JSON (keep first RESULTS_KEPT entries)
    let results_json: Vec<String> = results
        .iter()
        .take(RESULTS_KEPT)
        .map(|md| format!(r#"            {{"md": "{}"}}"#, hex(md)))
        .collect();

    format!(
        r#"{{
  "_source": "oxicrypt self-generated SHA-3 MCT vectors",
  "algorithm": "{}",
  "revision": "2.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "MCT",
      "tests": [
        {{
          "tcId": 1,
          "msg": "{}",
          "resultsArray": [
{}
          ]
        }}
      ]
    }}
  ]
}}"#,
        variant.name,
        hex(&variant.seed),
        results_json.join(",\n"),
    )
}

#[test]
#[ignore]
fn generate_sha3_mct_slices() {
    ensure_initialized().expect("FIPS module init");

    let variants = [
        Sha3Variant {
            name: "SHA3-224",

            hash_fn: sha3_224,
            seed: make_seed(28, 0x01),
        },
        Sha3Variant {
            name: "SHA3-256",

            hash_fn: sha3_256,
            seed: make_seed(32, 0x02),
        },
        Sha3Variant {
            name: "SHA3-384",

            hash_fn: sha3_384,
            seed: make_seed(48, 0x03),
        },
        Sha3Variant {
            name: "SHA3-512",

            hash_fn: sha3_512,
            seed: make_seed(64, 0x04),
        },
    ];

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("vendor/nist/acvp-server/gen-val/json-files");

    for variant in &variants {
        let json = generate_mct_slice(variant);
        let dir = base.join(format!("{}-2.0", variant.name));
        // The directory should already exist (AFT slice lives there).
        let path = dir.join("mct-slice.json");
        let mut f = std::fs::File::create(&path)
            .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
        f.write_all(json.as_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        f.write_all(b"\n").expect("trailing newline");
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }
}
