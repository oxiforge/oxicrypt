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
    clippy::ignore_without_reason,
    clippy::similar_names
)]
//! One-shot helper that generates a CMAC-AES lifecycle vector file:
//!
//! - `CMAC-AES-1.0/lifecycle-slice.json`
//!
//! Uses a single DRBG-generated AES-256 key shared across `gen` and
//! `ver` groups.  The `ver` group contains both valid (testPassed=true)
//! and invalid (testPassed=false, bit-flipped MAC) cases.
//!
//!   cargo test -p acvp-harness --test gen_cmac_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

const NUM_TESTS: usize = 5;

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_cmac_lifecycle_slice() {
    ensure_initialized().expect("FIPS init");

    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"pqclib-cmac-lifecycle-gen-entropy-v1",
        b"pqclib-cmac-lifecycle-gen-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    // AES-256 key.
    let mut key_bytes = [0u8; 32];
    drbg.generate(None, &mut key_bytes).expect("drbg gen key");
    let key_hex = hex_upper(&key_bytes);

    let mut gen_tests = Vec::new();
    let mut ver_valid_tests = Vec::new();
    let mut ver_invalid_tests = Vec::new();
    let mut tc_id: usize = 1;

    for _ in 0..NUM_TESTS {
        let mut msg = [0u8; 64];
        drbg.generate(None, &mut msg).expect("drbg gen msg");

        let tag = oxicrypt_cmac::cmac_aes256(&key_bytes, &msg).expect("CMAC-AES256 failed");
        let msg_hex = hex_upper(&msg);
        let mac_hex = hex_upper(&tag);

        gen_tests.push(format!(
            r#"        {{
          "tcId": {},
          "key": "{}",
          "message": "{}",
          "mac": "{}"
        }}"#,
            tc_id, key_hex, msg_hex, mac_hex
        ));

        // Valid verification
        ver_valid_tests.push(format!(
            r#"        {{
          "tcId": {},
          "key": "{}",
          "message": "{}",
          "mac": "{}",
          "testPassed": true
        }}"#,
            tc_id + NUM_TESTS,
            key_hex,
            msg_hex,
            mac_hex
        ));

        // Invalid verification: flip first byte of MAC
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        ver_invalid_tests.push(format!(
            r#"        {{
          "tcId": {},
          "key": "{}",
          "message": "{}",
          "mac": "{}",
          "testPassed": false
        }}"#,
            tc_id + 2 * NUM_TESTS,
            key_hex,
            msg_hex,
            hex_upper(&bad_tag)
        ));

        tc_id += 1;
    }

    let json = format!(
        r#"{{
  "_generator": "gen_cmac_lifecycle_slice (R42)",
  "algorithm": "CMAC-AES",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "gen",
      "keyLen": 256,
      "msgLen": 512,
      "macLen": 128,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "ver",
      "keyLen": 256,
      "msgLen": 512,
      "macLen": 128,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 3,
      "testType": "AFT",
      "direction": "ver",
      "keyLen": 256,
      "msgLen": 512,
      "macLen": 128,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        gen_tests.join(",\n"),
        ver_valid_tests.join(",\n"),
        ver_invalid_tests.join(",\n")
    );

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vendor/nist/acvp-server/gen-val/json-files");
    let path = base.join("CMAC-AES-1.0/lifecycle-slice.json");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("wrote {} ({} bytes)", path.display(), json.len());
}
