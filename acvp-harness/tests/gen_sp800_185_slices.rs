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
//! One-shot helper that generates SP 800-185 derived-function ACVP vector
//! slices for cSHAKE, KMAC, TupleHash, and ParallelHash. Run with:
//!
//!   cargo test -p acvp-harness --test gen_sp800_185_slices -- --ignored --nocapture
//!
//! Generates kat-slice.json files under:
//! - `vendor/nist/acvp-server/gen-val/json-files/cSHAKE-128-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/cSHAKE-256-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/KMAC-128-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/KMAC-256-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/TupleHash-128-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/TupleHash-256-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/ParallelHash-128-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/ParallelHash-256-1.0/`

use acvp_harness::ensure_initialized;
use oxicrypt_xof::{
    CShake128, CShake256, Kmac128, Kmac256, ParallelHash128, ParallelHash256, TupleHash128,
    TupleHash256,
};
use std::io::Write;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Write a JSON string to `dir/kat-slice.json`, creating the directory if needed.
fn write_slice(dir: &str, json: &str) {
    std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("mkdir {dir}: {e}"));
    let path = format!("{dir}/kat-slice.json");
    let mut f = std::fs::File::create(&path).unwrap_or_else(|e| panic!("create {path}: {e}"));
    f.write_all(json.as_bytes())
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
    println!("wrote {path}");
}

// ── cSHAKE vector generation ────────────────────────────────────────

fn cshake128_compute(msg: &[u8], s: &[u8], out: &mut [u8]) {
    let mut x = CShake128::new(b"", s).expect("CShake128::new");
    x.update(msg);
    x.finalize();
    x.squeeze(out);
}

fn cshake256_compute(msg: &[u8], s: &[u8], out: &mut [u8]) {
    let mut x = CShake256::new(b"", s).expect("CShake256::new");
    x.update(msg);
    x.finalize();
    x.squeeze(out);
}

fn gen_cshake_slice(
    algorithm: &str,
    compute: fn(&[u8], &[u8], &mut [u8]),
    default_out_bytes: usize,
) -> String {
    // Test cases with varying message lengths and customization strings.
    struct Case {
        msg: Vec<u8>,
        s: Vec<u8>,
        out_len: usize,
    }
    let cases = [
        Case {
            msg: vec![],
            s: vec![],
            out_len: default_out_bytes,
        },
        Case {
            msg: vec![0x00, 0x01, 0x02, 0x03],
            s: b"Email Signature".to_vec(),
            out_len: default_out_bytes,
        },
        Case {
            msg: (0u8..=63).collect(),
            s: vec![],
            out_len: default_out_bytes + 16,
        },
        Case {
            msg: vec![0xAB; 200],
            s: b"My Tagged Application".to_vec(),
            out_len: default_out_bytes,
        },
        Case {
            msg: vec![0xFF; 1],
            s: vec![],
            out_len: 16,
        },
    ];

    let mut tests_json = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut out = vec![0u8; c.out_len];
        compute(&c.msg, &c.s, &mut out);
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "len": {},
          "outLen": {},
          "msg": "{}",
          "hexCustomization": "{}",
          "md": "{}"
        }}"#,
            i + 1,
            c.msg.len() * 8,
            c.out_len * 8,
            hex(&c.msg),
            hex(&c.s),
            hex(&out)
        ));
    }

    format!(
        r#"{{
  "algorithm": "{}",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        algorithm,
        tests_json.join(",\n")
    )
}

// ── KMAC vector generation ──────────────────────────────────────────

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

type KmacComputeFn = fn(&[u8], &[u8], &[u8], &mut [u8]);

fn gen_kmac_slice(algorithm: &str, compute: KmacComputeFn, default_mac_bytes: usize) -> String {
    struct Case {
        key: Vec<u8>,
        msg: Vec<u8>,
        s: Vec<u8>,
        mac_len: usize,
    }
    let cases = [
        Case {
            key: vec![
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
                0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
                0x5C, 0x5D, 0x5E, 0x5F,
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
    ];

    let mut tests_json = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut out = vec![0u8; c.mac_len];
        compute(&c.key, &c.msg, &c.s, &mut out);
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "keyLen": {},
          "msgLen": {},
          "macLen": {},
          "key": "{}",
          "msg": "{}",
          "hexCustomization": "{}",
          "mac": "{}"
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

    format!(
        r#"{{
  "algorithm": "{}",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        algorithm,
        tests_json.join(",\n")
    )
}

// ── TupleHash vector generation ─────────────────────────────────────

fn tuplehash128_compute(elems: &[&[u8]], s: &[u8], out: &mut [u8]) {
    let mut h = TupleHash128::new(s).expect("TupleHash128::new");
    for e in elems {
        h.update(e);
    }
    h.finalize_into(out);
}

fn tuplehash256_compute(elems: &[&[u8]], s: &[u8], out: &mut [u8]) {
    let mut h = TupleHash256::new(s).expect("TupleHash256::new");
    for e in elems {
        h.update(e);
    }
    h.finalize_into(out);
}

fn gen_tuplehash_slice(
    algorithm: &str,
    compute: fn(&[&[u8]], &[u8], &mut [u8]),
    default_out_bytes: usize,
) -> String {
    struct Case {
        elems: Vec<Vec<u8>>,
        s: Vec<u8>,
        out_len: usize,
    }
    let cases = [
        // SP 800-185 sample: two 3-byte elements, no customization
        Case {
            elems: vec![
                vec![0x00, 0x01, 0x02],
                vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            ],
            s: vec![],
            out_len: default_out_bytes,
        },
        // With customization
        Case {
            elems: vec![
                vec![0x00, 0x01, 0x02],
                vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            ],
            s: b"My Tuple App".to_vec(),
            out_len: default_out_bytes,
        },
        // Single element
        Case {
            elems: vec![vec![0xAB; 32]],
            s: vec![],
            out_len: default_out_bytes,
        },
        // Three elements
        Case {
            elems: vec![vec![0x01], vec![0x02, 0x03], vec![0x04, 0x05, 0x06]],
            s: b"Triple".to_vec(),
            out_len: default_out_bytes,
        },
        // Empty tuple element
        Case {
            elems: vec![vec![], vec![0xFF]],
            s: vec![],
            out_len: default_out_bytes,
        },
    ];

    let mut tests_json = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let refs: Vec<&[u8]> = c.elems.iter().map(Vec::as_slice).collect();
        let mut out = vec![0u8; c.out_len];
        compute(&refs, &c.s, &mut out);
        let tuple_json: Vec<String> = c.elems.iter().map(|e| format!(r#""{}""#, hex(e))).collect();
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "outLen": {},
          "tuple": [{}],
          "hexCustomization": "{}",
          "md": "{}"
        }}"#,
            i + 1,
            c.out_len * 8,
            tuple_json.join(", "),
            hex(&c.s),
            hex(&out)
        ));
    }

    format!(
        r#"{{
  "algorithm": "{}",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        algorithm,
        tests_json.join(",\n")
    )
}

// ── ParallelHash vector generation ──────────────────────────────────

fn parallelhash128_compute(msg: &[u8], block_size: usize, s: &[u8], out: &mut [u8]) {
    let mut h = ParallelHash128::new(block_size, s).expect("ParallelHash128::new");
    h.update(msg);
    h.finalize_into(out);
}

fn parallelhash256_compute(msg: &[u8], block_size: usize, s: &[u8], out: &mut [u8]) {
    let mut h = ParallelHash256::new(block_size, s).expect("ParallelHash256::new");
    h.update(msg);
    h.finalize_into(out);
}

fn gen_parallelhash_slice(
    algorithm: &str,
    compute: fn(&[u8], usize, &[u8], &mut [u8]),
    default_out_bytes: usize,
) -> String {
    struct Case {
        msg: Vec<u8>,
        block_size: usize,
        s: Vec<u8>,
        out_len: usize,
    }
    let cases = [
        // NIST sample-like: B=8, 24-byte message, no customization
        Case {
            msg: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            ],
            block_size: 8,
            s: vec![],
            out_len: default_out_bytes,
        },
        // With customization
        Case {
            msg: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            ],
            block_size: 8,
            s: b"Parallel Data".to_vec(),
            out_len: default_out_bytes,
        },
        // Different block size
        Case {
            msg: (0..72).collect(),
            block_size: 12,
            s: b"Parallel Data".to_vec(),
            out_len: default_out_bytes,
        },
        // Short message (less than one block)
        Case {
            msg: vec![0xAB, 0xCD],
            block_size: 8,
            s: vec![],
            out_len: default_out_bytes,
        },
        // Larger message, larger block size
        Case {
            msg: vec![0x55; 128],
            block_size: 32,
            s: b"Big Blocks".to_vec(),
            out_len: default_out_bytes,
        },
    ];

    let mut tests_json = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut out = vec![0u8; c.out_len];
        compute(&c.msg, c.block_size, &c.s, &mut out);
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "len": {},
          "outLen": {},
          "blockSize": {},
          "msg": "{}",
          "hexCustomization": "{}",
          "md": "{}"
        }}"#,
            i + 1,
            c.msg.len() * 8,
            c.out_len * 8,
            c.block_size,
            hex(&c.msg),
            hex(&c.s),
            hex(&out)
        ));
    }

    format!(
        r#"{{
  "algorithm": "{}",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "blockSize": 8,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        algorithm,
        tests_json.join(",\n")
    )
}

// ── Generator tests (run with --ignored) ─────────────────────────────

#[test]
#[ignore]
fn generate_cshake128_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_cshake_slice("cSHAKE-128", cshake128_compute, 32);
    write_slice(&format!("{base}/cSHAKE-128-1.0"), &json);
}

#[test]
#[ignore]
fn generate_cshake256_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_cshake_slice("cSHAKE-256", cshake256_compute, 64);
    write_slice(&format!("{base}/cSHAKE-256-1.0"), &json);
}

#[test]
#[ignore]
fn generate_kmac128_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_kmac_slice("KMAC-128", kmac128_compute, 32);
    write_slice(&format!("{base}/KMAC-128-1.0"), &json);
}

#[test]
#[ignore]
fn generate_kmac256_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_kmac_slice("KMAC-256", kmac256_compute, 64);
    write_slice(&format!("{base}/KMAC-256-1.0"), &json);
}

#[test]
#[ignore]
fn generate_tuplehash128_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_tuplehash_slice("TupleHash-128", tuplehash128_compute, 32);
    write_slice(&format!("{base}/TupleHash-128-1.0"), &json);
}

#[test]
#[ignore]
fn generate_tuplehash256_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_tuplehash_slice("TupleHash-256", tuplehash256_compute, 64);
    write_slice(&format!("{base}/TupleHash-256-1.0"), &json);
}

#[test]
#[ignore]
fn generate_parallelhash128_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_parallelhash_slice("ParallelHash-128", parallelhash128_compute, 32);
    write_slice(&format!("{base}/ParallelHash-128-1.0"), &json);
}

#[test]
#[ignore]
fn generate_parallelhash256_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_parallelhash_slice("ParallelHash-256", parallelhash256_compute, 64);
    write_slice(&format!("{base}/ParallelHash-256-1.0"), &json);
}
