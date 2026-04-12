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
    clippy::integer_division
)]
//! One-shot helper that generates SHAKE-128 / SHAKE-256 MCT and VOT vector
//! files under `vendor/nist/acvp-server/gen-val/json-files/`.
//!
//!   cargo test -p acvp-harness --test gen_shake_mct_vot_slice -- --ignored --nocapture
//!
//! **MCT** follows the ACVP XOF MCT algorithm (draft-celi-acvp-xof §6.2):
//!   100 outer × 1000 inner iterations with variable output length.
//!   We keep the first 5 resultsArray entries to keep the slice small.
//!
//! **VOT** (Variable Output Test) uses the same per-test envelope as AFT
//!   (`msg`, `len`, `outLen`, `md`) but with `testType = "VOT"` and
//!   varying output lengths. We generate 5 test cases per variant.

use acvp_harness::ensure_initialized;
use fips_xof::{Shake128, Shake256};
use std::io::Write;

/// Number of outer MCT iterations (full spec).
const MCT_OUTER: usize = 100;
/// Number of inner MCT iterations per outer iteration.
const MCT_INNER: usize = 1000;
/// Number of resultsArray entries to keep in the vendored slice.
const RESULTS_KEPT: usize = 5;
/// Number of VOT test cases per variant.
const VOT_CASES: usize = 5;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

// ---- SHAKE squeeze wrappers ----

fn shake128(msg: &[u8], out: &mut [u8]) {
    let mut x = Shake128::new().expect("Shake128::new");
    x.update(msg);
    x.finalize();
    x.squeeze(out);
}

fn shake256(msg: &[u8], out: &mut [u8]) {
    let mut x = Shake256::new().expect("Shake256::new");
    x.update(msg);
    x.finalize();
    x.squeeze(out);
}

// ---- MCT engine (mirrors the handler exactly) ----

struct MctResult {
    md: Vec<u8>,
    out_len: usize, // in bits
}

fn run_shake_mct(
    squeeze: fn(&[u8], &mut [u8]),
    seed: &[u8],
    min_out_len: usize,
    max_out_len: usize,
) -> Vec<MctResult> {
    let min_out_bytes = min_out_len / 8;
    let range = max_out_len - min_out_len + 1;
    let mut md = seed.to_vec();
    let mut output_len = max_out_len; // in bits
    let mut results = Vec::with_capacity(MCT_OUTER);

    for _i in 0..MCT_OUTER {
        for _j in 0..MCT_INNER {
            let m_len = min_out_bytes.min(md.len());
            let msg_slice = &md[..m_len];

            let out_bytes = output_len / 8;
            let mut out_buf = vec![0u8; out_bytes];
            squeeze(msg_slice, &mut out_buf);

            // Update outputLen from rightmost 16 bits
            let right_bits = if out_buf.len() >= 2 {
                let hi = out_buf[out_buf.len() - 2] as usize;
                let lo = out_buf[out_buf.len() - 1] as usize;
                (hi << 8) | lo
            } else if out_buf.len() == 1 {
                out_buf[0] as usize
            } else {
                0
            };
            output_len = min_out_len + (right_bits % range);
            // Ensure byte alignment
            output_len = (output_len / 8) * 8;
            if output_len < min_out_len {
                output_len = min_out_len;
            }

            md = out_buf;
        }
        results.push(MctResult {
            md: md.clone(),
            out_len: output_len,
        });
    }
    results
}

// ---- MCT JSON generation ----

fn generate_mct_slice(
    algorithm: &str,
    squeeze: fn(&[u8], &mut [u8]),
    seed: &[u8],
    min_out_len: usize,
    max_out_len: usize,
) -> String {
    let results = run_shake_mct(squeeze, seed, min_out_len, max_out_len);

    let results_json: Vec<String> = results
        .iter()
        .take(RESULTS_KEPT)
        .map(|r| {
            format!(
                r#"            {{"md": "{}", "outLen": {}}}"#,
                hex(&r.md),
                r.out_len
            )
        })
        .collect();

    format!(
        r#"{{
  "_source": "pqclib self-generated SHAKE MCT vectors (R45)",
  "algorithm": "{}",
  "revision": "FIPS202",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "MCT",
      "minOutLen": {},
      "maxOutLen": {},
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
        algorithm,
        min_out_len,
        max_out_len,
        hex(seed),
        results_json.join(",\n"),
    )
}

// ---- VOT JSON generation ----

fn generate_vot_slice(
    algorithm: &str,
    squeeze: fn(&[u8], &mut [u8]),
    min_out_len: usize,
) -> String {
    // Deterministic seeds for VOT messages using DRBG
    let mut drbg = fips_drbg::HmacDrbgSha256::default();
    let entropy = format!("pqclib-{}-vot-entropy-v1", algorithm);
    let nonce = format!("pqclib-{}-vot-nonce-v1", algorithm);
    drbg.instantiate(entropy.as_bytes(), nonce.as_bytes(), &[])
        .expect("drbg instantiate");

    let min_out_bytes = min_out_len / 8;
    let mut tests = Vec::with_capacity(VOT_CASES);

    for tc_id in 1..=VOT_CASES {
        // Generate a random message length: 8..256 bits (byte-aligned)
        let mut len_buf = [0u8; 2];
        drbg.generate(None, &mut len_buf).expect("drbg generate");
        let msg_bytes = 1 + (u16::from_be_bytes(len_buf) as usize % 32); // 1..32 bytes
        let msg_bits = msg_bytes * 8;

        // Generate random message
        let mut msg = vec![0u8; msg_bytes];
        drbg.generate(None, &mut msg).expect("drbg generate");

        // Generate a variable output length:
        // Range from minOutLen to minOutLen*4, byte-aligned
        let mut out_len_buf = [0u8; 2];
        drbg.generate(None, &mut out_len_buf).expect("drbg generate");
        let max_range = min_out_bytes * 4;
        let out_bytes = min_out_bytes + (u16::from_be_bytes(out_len_buf) as usize % (max_range - min_out_bytes + 1));
        let out_bits = out_bytes * 8;

        // Compute SHAKE output
        let mut out_buf = vec![0u8; out_bytes];
        squeeze(&msg, &mut out_buf);

        tests.push(format!(
            r#"        {{
          "tcId": {},
          "len": {},
          "outLen": {},
          "msg": "{}",
          "md": "{}"
        }}"#,
            tc_id,
            msg_bits,
            out_bits,
            hex(&msg),
            hex(&out_buf),
        ));
    }

    format!(
        r#"{{
  "_source": "pqclib self-generated SHAKE VOT vectors (R45)",
  "algorithm": "{}",
  "revision": "FIPS202",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "VOT",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        algorithm,
        tests.join(",\n"),
    )
}

// ---- Deterministic MCT seed (repeating-pattern, unique per variant) ----

fn make_mct_seed(out_bytes: usize, variant_byte: u8) -> Vec<u8> {
    (0..out_bytes)
        .map(|i| {
            let b = (i as u8).wrapping_add(variant_byte);
            b ^ 0xC3
        })
        .collect()
}

#[test]
#[ignore]
fn generate_shake_mct_vot_slices() {
    ensure_initialized().expect("FIPS module init");

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("vendor/nist/acvp-server/gen-val/json-files");

    // SHAKE-128: minOutLen=128, maxOutLen=4096 (standard ACVP range)
    let shake128_min = 128;
    let shake128_max = 4096;
    let shake128_seed = make_mct_seed(shake128_min / 8, 0x81);

    // SHAKE-256: minOutLen=256, maxOutLen=4096
    let shake256_min = 256;
    let shake256_max = 4096;
    let shake256_seed = make_mct_seed(shake256_min / 8, 0x82);

    // Generate MCT slices
    let shake128_mct = generate_mct_slice(
        "SHAKE-128",
        shake128,
        &shake128_seed,
        shake128_min,
        shake128_max,
    );
    let shake256_mct = generate_mct_slice(
        "SHAKE-256",
        shake256,
        &shake256_seed,
        shake256_min,
        shake256_max,
    );

    // Generate VOT slices
    let shake128_vot = generate_vot_slice("SHAKE-128", shake128, shake128_min);
    let shake256_vot = generate_vot_slice("SHAKE-256", shake256, shake256_min);

    // Write files
    let files = [
        ("SHAKE-128-FIPS202", "mct-slice.json", &shake128_mct),
        ("SHAKE-256-FIPS202", "mct-slice.json", &shake256_mct),
        ("SHAKE-128-FIPS202", "vot-slice.json", &shake128_vot),
        ("SHAKE-256-FIPS202", "vot-slice.json", &shake256_vot),
    ];

    for (dir_name, file_name, content) in &files {
        let dir = base.join(dir_name);
        let path = dir.join(file_name);
        let mut f = std::fs::File::create(&path)
            .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
        f.write_all(content.as_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        f.write_all(b"\n").expect("trailing newline");
        println!("wrote {} ({} bytes)", path.display(), content.len());
    }
}
