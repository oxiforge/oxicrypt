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
//! One-shot helper that generates KMAC / KMACXOF MVT (MAC Verification
//! Test) ACVP vector slices.  Run with:
//!
//!   cargo test -p acvp-harness --test gen_kmac_mvt_slices -- --ignored --nocapture
//!
//! Each algorithm gets two test groups:
//!
//! - Group 1 (valid):   5 tests with correct MACs → `testPassed: true`
//! - Group 2 (invalid): 5 tests with bit-flipped MACs → `testPassed: false`
//!
//! Generates:
//! - `vendor/nist/acvp-server/gen-val/json-files/KMAC-128-1.0/mvt-slice.json`
//! - `vendor/nist/acvp-server/gen-val/json-files/KMAC-256-1.0/mvt-slice.json`
//! - `vendor/nist/acvp-server/gen-val/json-files/KMACXOF-128-1.0/mvt-slice.json`
//! - `vendor/nist/acvp-server/gen-val/json-files/KMACXOF-256-1.0/mvt-slice.json`

use acvp_harness::ensure_initialized;
use oxicrypt_xof::{Kmac128, Kmac256, KmacXof128, KmacXof256};
use std::io::Write;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn write_slice(dir: &str, filename: &str, json: &str) {
    std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("mkdir {dir}: {e}"));
    let path = format!("{dir}/{filename}");
    let mut f =
        std::fs::File::create(&path).unwrap_or_else(|e| panic!("create {path}: {e}"));
    f.write_all(json.as_bytes())
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
    println!("wrote {path}");
}

// ── Shared test-case definitions ──────────────────────────────────

struct Case {
    key: Vec<u8>,
    msg: Vec<u8>,
    s: Vec<u8>,
    mac_len: usize,
}

fn test_cases(default_mac_bytes: usize) -> [Case; 5] {
    [
        Case {
            key: vec![
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            ],
            msg: vec![0x00, 0x01, 0x02, 0x03],
            s: b"My Tagged Application".to_vec(),
            mac_len: default_mac_bytes,
        },
        Case {
            key: vec![0x40; 32],
            msg: vec![],
            s: vec![],
            mac_len: default_mac_bytes,
        },
        Case {
            key: (0..48).collect(),
            msg: (0u8..200).collect(),
            s: b"".to_vec(),
            mac_len: default_mac_bytes,
        },
        Case {
            key: vec![0xAA; 16],
            msg: vec![0xBB; 64],
            s: b"Verify".to_vec(),
            mac_len: 16,
        },
        Case {
            key: vec![0x01; 64],
            msg: vec![0x02; 128],
            s: b"Test".to_vec(),
            mac_len: default_mac_bytes,
        },
    ]
}

type KmacComputeFn = fn(&[u8], &[u8], &[u8], &mut [u8]);

/// Generate an MVT slice with two groups: valid MACs and bit-flipped MACs.
fn gen_mvt_slice(
    algorithm: &str,
    compute: KmacComputeFn,
    default_mac_bytes: usize,
) -> String {
    let cases = test_cases(default_mac_bytes);

    // Group 1: valid MACs (testPassed = true)
    let mut valid_tests = Vec::new();
    let mut macs: Vec<Vec<u8>> = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut out = vec![0u8; c.mac_len];
        compute(&c.key, &c.msg, &c.s, &mut out);
        macs.push(out.clone());
        valid_tests.push(format!(
            r#"        {{
          "tcId": {},
          "keyLen": {},
          "msgLen": {},
          "macLen": {},
          "key": "{}",
          "msg": "{}",
          "hexCustomization": "{}",
          "mac": "{}",
          "testPassed": true
        }}"#,
            i + 1,
            c.key.len() * 8,
            c.msg.len() * 8,
            c.mac_len * 8,
            hex(&c.key),
            hex(&c.msg),
            hex(&c.s),
            hex(&out)
        ));
    }

    // Group 2: invalid MACs — flip the first byte of each valid MAC
    let mut invalid_tests = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut bad_mac = macs[i].clone();
        bad_mac[0] ^= 0xFF;
        invalid_tests.push(format!(
            r#"        {{
          "tcId": {},
          "keyLen": {},
          "msgLen": {},
          "macLen": {},
          "key": "{}",
          "msg": "{}",
          "hexCustomization": "{}",
          "mac": "{}",
          "testPassed": false
        }}"#,
            i + 6,
            c.key.len() * 8,
            c.msg.len() * 8,
            c.mac_len * 8,
            hex(&c.key),
            hex(&c.msg),
            hex(&c.s),
            hex(&bad_mac)
        ));
    }

    format!(
        r#"{{
  "algorithm": "{}",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "MVT",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "MVT",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        algorithm,
        valid_tests.join(",\n"),
        invalid_tests.join(",\n")
    )
}

// ── Compute functions ─────────────────────────────────────────────

fn kmac128_compute(key: &[u8], msg: &[u8], s: &[u8], out: &mut [u8]) {
    let mut m = Kmac128::new(key, s).expect("Kmac128::new");
    m.update(msg);
    m.finalize_into(out);
}

fn kmac256_compute(key: &[u8], msg: &[u8], s: &[u8], out: &mut [u8]) {
    let mut m = Kmac256::new(key, s).expect("Kmac256::new");
    m.update(msg);
    m.finalize_into(out);
}

fn kmacxof128_compute(key: &[u8], msg: &[u8], s: &[u8], out: &mut [u8]) {
    let mut m = KmacXof128::new(key, s).expect("KmacXof128::new");
    m.update(msg);
    m.finalize();
    m.squeeze(out);
}

fn kmacxof256_compute(key: &[u8], msg: &[u8], s: &[u8], out: &mut [u8]) {
    let mut m = KmacXof256::new(key, s).expect("KmacXof256::new");
    m.update(msg);
    m.finalize();
    m.squeeze(out);
}

// ── Generator tests (run with --ignored) ─────────────────────────

#[test]
#[ignore]
fn generate_kmac128_mvt_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_mvt_slice("KMAC-128", kmac128_compute, 32);
    write_slice(&format!("{base}/KMAC-128-1.0"), "mvt-slice.json", &json);
}

#[test]
#[ignore]
fn generate_kmac256_mvt_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_mvt_slice("KMAC-256", kmac256_compute, 64);
    write_slice(&format!("{base}/KMAC-256-1.0"), "mvt-slice.json", &json);
}

#[test]
#[ignore]
fn generate_kmacxof128_mvt_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_mvt_slice("KMACXOF-128", kmacxof128_compute, 32);
    write_slice(&format!("{base}/KMACXOF-128-1.0"), "mvt-slice.json", &json);
}

#[test]
#[ignore]
fn generate_kmacxof256_mvt_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_mvt_slice("KMACXOF-256", kmacxof256_compute, 64);
    write_slice(&format!("{base}/KMACXOF-256-1.0"), "mvt-slice.json", &json);
}
