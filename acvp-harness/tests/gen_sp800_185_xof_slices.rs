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
//! One-shot helper that generates SP 800-185 XOF variant ACVP vector
//! slices for KMACXOF, TupleHashXOF, and ParallelHashXOF. Run with:
//!
//!   cargo test -p acvp-harness --test gen_sp800_185_xof_slices -- --ignored --nocapture
//!
//! Generates kat-slice.json files under:
//! - `vendor/nist/acvp-server/gen-val/json-files/KMACXOF-128-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/KMACXOF-256-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/TupleHashXOF-128-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/TupleHashXOF-256-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/ParallelHashXOF-128-1.0/`
//! - `vendor/nist/acvp-server/gen-val/json-files/ParallelHashXOF-256-1.0/`

use acvp_harness::ensure_initialized;
use oxicrypt_xof::{
    KmacXof128, KmacXof256, ParallelHashXof128, ParallelHashXof256, TupleHashXof128,
    TupleHashXof256,
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

// ── KMACXOF vector generation ─────────────────────────────────────

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

type KmacXofComputeFn = fn(&[u8], &[u8], &[u8], &mut [u8]);

fn gen_kmacxof_slice(
    algorithm: &str,
    compute: KmacXofComputeFn,
    default_mac_bytes: usize,
) -> String {
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
        // `hexCustomization: true` is paired with the per-test
        // `customizationHex` field name (per `draft-celi-acvp-xof`
        // §8.2 Table 6) so offline fixtures match the live ACVTS
        // shape that the shared `read_customization_field` helper
        // expects.
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "keyLen": {},
          "msgLen": {},
          "macLen": {},
          "key": "{}",
          "msg": "{}",
          "customizationHex": "{}",
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
      "hexCustomization": true,
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

// ── TupleHashXOF vector generation ────────────────────────────────

fn tuplehashxof128_compute(elems: &[&[u8]], s: &[u8], out: &mut [u8]) {
    let mut h = TupleHashXof128::new(s).expect("TupleHashXof128::new");
    for e in elems {
        h.update(e);
    }
    h.finalize();
    h.squeeze(out);
}

fn tuplehashxof256_compute(elems: &[&[u8]], s: &[u8], out: &mut [u8]) {
    let mut h = TupleHashXof256::new(s).expect("TupleHashXof256::new");
    for e in elems {
        h.update(e);
    }
    h.finalize();
    h.squeeze(out);
}

fn gen_tuplehashxof_slice(
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
        Case {
            elems: vec![
                vec![0x00, 0x01, 0x02],
                vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            ],
            s: vec![],
            out_len: default_out_bytes,
        },
        Case {
            elems: vec![
                vec![0x00, 0x01, 0x02],
                vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            ],
            s: b"My Tuple App".to_vec(),
            out_len: default_out_bytes,
        },
        Case {
            elems: vec![vec![0xAB; 32]],
            s: vec![],
            out_len: default_out_bytes,
        },
        Case {
            elems: vec![vec![0x01], vec![0x02, 0x03], vec![0x04, 0x05, 0x06]],
            s: b"Triple".to_vec(),
            out_len: default_out_bytes,
        },
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
        let cust_ascii = std::str::from_utf8(&c.s).expect("customization is ASCII");
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "outLen": {},
          "tuple": [{}],
          "customization": "{}",
          "md": "{}"
        }}"#,
            i + 1,
            c.out_len * 8,
            tuple_json.join(", "),
            cust_ascii,
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
      "hexCustomization": false,
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

// ── ParallelHashXOF vector generation ─────────────────────────────

fn parallelhashxof128_compute(msg: &[u8], block_size: usize, s: &[u8], out: &mut [u8]) {
    let mut h = ParallelHashXof128::new(block_size, s).expect("ParallelHashXof128::new");
    h.update(msg);
    h.finalize();
    h.squeeze(out);
}

fn parallelhashxof256_compute(msg: &[u8], block_size: usize, s: &[u8], out: &mut [u8]) {
    let mut h = ParallelHashXof256::new(block_size, s).expect("ParallelHashXof256::new");
    h.update(msg);
    h.finalize();
    h.squeeze(out);
}

fn gen_parallelhashxof_slice(
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
        Case {
            msg: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            ],
            block_size: 8,
            s: vec![],
            out_len: default_out_bytes,
        },
        Case {
            msg: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            ],
            block_size: 8,
            s: b"Parallel Data".to_vec(),
            out_len: default_out_bytes,
        },
        Case {
            msg: (0..72).collect(),
            block_size: 12,
            s: b"Parallel Data".to_vec(),
            out_len: default_out_bytes,
        },
        Case {
            msg: vec![0xAB, 0xCD],
            block_size: 8,
            s: vec![],
            out_len: default_out_bytes,
        },
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
        let cust_ascii = std::str::from_utf8(&c.s).expect("customization is ASCII");
        tests_json.push(format!(
            r#"        {{
          "tcId": {},
          "len": {},
          "outLen": {},
          "blockSize": {},
          "msg": "{}",
          "customization": "{}",
          "md": "{}"
        }}"#,
            i + 1,
            c.msg.len() * 8,
            c.out_len * 8,
            c.block_size,
            hex(&c.msg),
            cust_ascii,
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
      "hexCustomization": false,
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

// ── Generator tests (run with --ignored) ─────────────────────────

#[test]
#[ignore]
fn generate_kmacxof128_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_kmacxof_slice("KMACXOF-128", kmacxof128_compute, 32);
    write_slice(&format!("{base}/KMACXOF-128-1.0"), &json);
}

#[test]
#[ignore]
fn generate_kmacxof256_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_kmacxof_slice("KMACXOF-256", kmacxof256_compute, 64);
    write_slice(&format!("{base}/KMACXOF-256-1.0"), &json);
}

#[test]
#[ignore]
fn generate_tuplehashxof128_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_tuplehashxof_slice("TupleHashXOF-128", tuplehashxof128_compute, 32);
    write_slice(&format!("{base}/TupleHashXOF-128-1.0"), &json);
}

#[test]
#[ignore]
fn generate_tuplehashxof256_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_tuplehashxof_slice("TupleHashXOF-256", tuplehashxof256_compute, 64);
    write_slice(&format!("{base}/TupleHashXOF-256-1.0"), &json);
}

#[test]
#[ignore]
fn generate_parallelhashxof128_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_parallelhashxof_slice("ParallelHashXOF-128", parallelhashxof128_compute, 32);
    write_slice(&format!("{base}/ParallelHashXOF-128-1.0"), &json);
}

#[test]
#[ignore]
fn generate_parallelhashxof256_slice() {
    ensure_initialized().unwrap();
    let base = format!(
        "{}/../vendor/nist/acvp-server/gen-val/json-files",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = gen_parallelhashxof_slice("ParallelHashXOF-256", parallelhashxof256_compute, 64);
    write_slice(&format!("{base}/ParallelHashXOF-256-1.0"), &json);
}
