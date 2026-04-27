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
    clippy::similar_names,
    clippy::integer_division,
    clippy::manual_div_ceil,
    // Lifecycle generators use `let mut tc_id = 1; for _ in 0..N { ...; tc_id += 1; }`
    // as a deliberate fixture-builder idiom; rewriting to `for tc_id in 1..=N` would
    // be cosmetic. Allow at file scope rather than every test-scaffold module.
    clippy::explicit_counter_loop
)]
//! One-shot helper that generates AES encrypt-decrypt lifecycle vector
//! files for all seven AES modes:
//!
//! - `ACVP-AES-ECB-1.0/lifecycle-slice.json`
//! - `ACVP-AES-CBC-1.0/lifecycle-slice.json`
//! - `ACVP-AES-CTR-1.0/lifecycle-slice.json`
//! - `ACVP-AES-GCM-1.0/lifecycle-slice.json`
//! - `ACVP-AES-CCM-1.0/lifecycle-slice.json`
//! - `ACVP-AES-KW-1.0/lifecycle-slice.json`
//! - `ACVP-AES-KWP-1.0/lifecycle-slice.json`
//!
//! Each file uses a single DRBG-generated AES-256 key and proves that
//! encrypt→decrypt recovers the original plaintext.  For authenticated
//! modes (GCM, CCM, KW, KWP), an additional decrypt group with a
//! bit-flipped tag/ciphertext proves that authentication failure is
//! correctly detected (testPassed = false).
//!
//!   cargo test -p acvp-harness --test gen_aes_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Flip one bit in the first byte of a hex string to create an invalid value.
fn flip_hex(hex: &str) -> String {
    let mut bytes = hex_decode(hex);
    bytes[0] ^= 0x01;
    hex_upper(&bytes)
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

const NUM_TESTS: usize = 5;

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_aes_lifecycle_slices() {
    ensure_initialized().expect("FIPS init");

    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"pqclib-aes-lifecycle-gen-entropy-v1",
        b"pqclib-aes-lifecycle-gen-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    // Generate one AES-256 key shared across all modes.
    let mut key_bytes = [0u8; 32];
    drbg.generate(None, &mut key_bytes).expect("drbg gen key");
    let key_hex = hex_upper(&key_bytes);
    let cipher = oxicrypt_aes::Aes256Key::new_internal(&key_bytes);

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vendor/nist/acvp-server/gen-val/json-files");

    // ── ECB ──────────────────────────────────────────────────────
    {
        let mut enc_tests = Vec::new();
        let mut dec_tests = Vec::new();
        let mut tc_id = 1;

        for _ in 0..NUM_TESTS {
            // 2 blocks = 32 bytes
            let mut pt = [0u8; 32];
            drbg.generate(None, &mut pt).expect("drbg gen pt");

            let mut ct = [0u8; 32];
            oxicrypt_aes::ecb_encrypt(&cipher, &pt, &mut ct).expect("ecb encrypt");

            enc_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "pt": "{}",
          "ct": "{}"
        }}"#,
                tc_id,
                key_hex,
                hex_upper(&pt),
                hex_upper(&ct)
            ));

            dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "ct": "{}",
          "pt": "{}"
        }}"#,
                tc_id + NUM_TESTS,
                key_hex,
                hex_upper(&ct),
                hex_upper(&pt)
            ));

            tc_id += 1;
        }

        let json = format!(
            r#"{{
  "_generator": "gen_aes_lifecycle_slice (R41)",
  "algorithm": "ACVP-AES-ECB",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            enc_tests.join(",\n"),
            dec_tests.join(",\n")
        );

        let dir = base.join("ACVP-AES-ECB-1.0");
        let path = dir.join("lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }

    // ── CBC ──────────────────────────────────────────────────────
    {
        let mut enc_tests = Vec::new();
        let mut dec_tests = Vec::new();
        let mut tc_id = 1;

        for _ in 0..NUM_TESTS {
            let mut iv = [0u8; 16];
            drbg.generate(None, &mut iv).expect("drbg gen iv");
            let mut pt = [0u8; 32];
            drbg.generate(None, &mut pt).expect("drbg gen pt");

            let mut ct = [0u8; 32];
            oxicrypt_aes::cbc_encrypt(&cipher, &iv, &pt, &mut ct).expect("cbc encrypt");

            enc_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "pt": "{}",
          "ct": "{}"
        }}"#,
                tc_id,
                key_hex,
                hex_upper(&iv),
                hex_upper(&pt),
                hex_upper(&ct)
            ));

            dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "ct": "{}",
          "pt": "{}"
        }}"#,
                tc_id + NUM_TESTS,
                key_hex,
                hex_upper(&iv),
                hex_upper(&ct),
                hex_upper(&pt)
            ));

            tc_id += 1;
        }

        let json = format!(
            r#"{{
  "_generator": "gen_aes_lifecycle_slice (R41)",
  "algorithm": "ACVP-AES-CBC",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            enc_tests.join(",\n"),
            dec_tests.join(",\n")
        );

        let dir = base.join("ACVP-AES-CBC-1.0");
        let path = dir.join("lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }

    // ── CTR ──────────────────────────────────────────────────────
    {
        let mut enc_tests = Vec::new();
        let mut dec_tests = Vec::new();
        let mut tc_id = 1;

        for _ in 0..NUM_TESTS {
            let mut icb = [0u8; 16];
            drbg.generate(None, &mut icb).expect("drbg gen icb");
            let mut pt = [0u8; 48]; // 3 blocks
            drbg.generate(None, &mut pt).expect("drbg gen pt");

            let mut ct = [0u8; 48];
            oxicrypt_aes::ctr_xor(&cipher, &icb, &pt, &mut ct);

            enc_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "pt": "{}",
          "ct": "{}"
        }}"#,
                tc_id,
                key_hex,
                hex_upper(&icb),
                hex_upper(&pt),
                hex_upper(&ct)
            ));

            dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "ct": "{}",
          "pt": "{}"
        }}"#,
                tc_id + NUM_TESTS,
                key_hex,
                hex_upper(&icb),
                hex_upper(&ct),
                hex_upper(&pt)
            ));

            tc_id += 1;
        }

        let json = format!(
            r#"{{
  "_generator": "gen_aes_lifecycle_slice (R41)",
  "algorithm": "ACVP-AES-CTR",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            enc_tests.join(",\n"),
            dec_tests.join(",\n")
        );

        let dir = base.join("ACVP-AES-CTR-1.0");
        let path = dir.join("lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }

    // ── GCM ──────────────────────────────────────────────────────
    {
        let mut enc_tests = Vec::new();
        let mut valid_dec_tests = Vec::new();
        let mut invalid_dec_tests = Vec::new();
        let mut tc_id = 1;

        for _ in 0..NUM_TESTS {
            let mut iv = [0u8; 12]; // 96-bit IV
            drbg.generate(None, &mut iv).expect("drbg gen iv");
            let mut aad = [0u8; 16];
            drbg.generate(None, &mut aad).expect("drbg gen aad");
            let mut pt = [0u8; 32];
            drbg.generate(None, &mut pt).expect("drbg gen pt");

            let mut ct = [0u8; 32];
            let mut tag = [0u8; 16];
            oxicrypt_aes::gcm_encrypt(&cipher, &iv, &aad, &pt, &mut ct, &mut tag)
                .expect("gcm encrypt");

            let ct_hex = hex_upper(&ct);
            let tag_hex = hex_upper(&tag);
            let pt_hex = hex_upper(&pt);
            let iv_hex = hex_upper(&iv);
            let aad_hex = hex_upper(&aad);

            enc_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "aad": "{}",
          "pt": "{}",
          "ct": "{}",
          "tag": "{}"
        }}"#,
                tc_id, key_hex, iv_hex, aad_hex, pt_hex, ct_hex, tag_hex
            ));

            // Valid decrypt: correct tag → testPassed: true
            valid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "aad": "{}",
          "ct": "{}",
          "tag": "{}",
          "testPassed": true,
          "pt": "{}"
        }}"#,
                tc_id + NUM_TESTS,
                key_hex,
                iv_hex,
                aad_hex,
                ct_hex,
                tag_hex,
                pt_hex
            ));

            // Invalid decrypt: flipped tag → testPassed: false
            invalid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "aad": "{}",
          "ct": "{}",
          "tag": "{}",
          "testPassed": false
        }}"#,
                tc_id + 2 * NUM_TESTS,
                key_hex,
                iv_hex,
                aad_hex,
                ct_hex,
                flip_hex(&tag_hex)
            ));

            tc_id += 1;
        }

        let json = format!(
            r#"{{
  "_generator": "gen_aes_lifecycle_slice (R41)",
  "algorithm": "ACVP-AES-GCM",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "keyLen": 256,
      "ivLen": 96,
      "tagLen": 128,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "ivLen": 96,
      "tagLen": 128,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 3,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "ivLen": 96,
      "tagLen": 128,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            enc_tests.join(",\n"),
            valid_dec_tests.join(",\n"),
            invalid_dec_tests.join(",\n")
        );

        let dir = base.join("ACVP-AES-GCM-1.0");
        let path = dir.join("lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }

    // ── CCM ──────────────────────────────────────────────────────
    {
        let tlen: usize = 16; // 128-bit tag
        let nonce_len: usize = 12; // 96-bit nonce
        let mut enc_tests = Vec::new();
        let mut valid_dec_tests = Vec::new();
        let mut invalid_dec_tests = Vec::new();
        let mut tc_id = 1;

        for _ in 0..NUM_TESTS {
            let mut nonce = [0u8; 12];
            drbg.generate(None, &mut nonce).expect("drbg gen nonce");
            let mut aad = [0u8; 16];
            drbg.generate(None, &mut aad).expect("drbg gen aad");
            let mut pt = [0u8; 32];
            drbg.generate(None, &mut pt).expect("drbg gen pt");

            let mut ct_with_tag = vec![0u8; pt.len() + tlen];
            oxicrypt_aes::ccm_encrypt(&cipher, &nonce, &aad, &pt, tlen, &mut ct_with_tag)
                .expect("ccm encrypt");

            let ct_hex = hex_upper(&ct_with_tag);
            let pt_hex = hex_upper(&pt);
            let nonce_hex = hex_upper(&nonce);
            let aad_hex = hex_upper(&aad);

            enc_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "aad": "{}",
          "pt": "{}",
          "ct": "{}"
        }}"#,
                tc_id, key_hex, nonce_hex, aad_hex, pt_hex, ct_hex
            ));

            // Valid decrypt
            valid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "aad": "{}",
          "ct": "{}",
          "testPassed": true,
          "pt": "{}"
        }}"#,
                tc_id + NUM_TESTS,
                key_hex,
                nonce_hex,
                aad_hex,
                ct_hex,
                pt_hex
            ));

            // Invalid decrypt: flip first byte of ct_with_tag
            invalid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "iv": "{}",
          "aad": "{}",
          "ct": "{}",
          "testPassed": false
        }}"#,
                tc_id + 2 * NUM_TESTS,
                key_hex,
                nonce_hex,
                aad_hex,
                flip_hex(&ct_hex)
            ));

            tc_id += 1;
        }

        let json = format!(
            r#"{{
  "_generator": "gen_aes_lifecycle_slice (R41)",
  "algorithm": "ACVP-AES-CCM",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "keyLen": 256,
      "ivLen": {},
      "tagLen": {},
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "ivLen": {},
      "tagLen": {},
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 3,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "ivLen": {},
      "tagLen": {},
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            nonce_len * 8,
            tlen * 8,
            enc_tests.join(",\n"),
            nonce_len * 8,
            tlen * 8,
            valid_dec_tests.join(",\n"),
            nonce_len * 8,
            tlen * 8,
            invalid_dec_tests.join(",\n")
        );

        let dir = base.join("ACVP-AES-CCM-1.0");
        let path = dir.join("lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }

    // ── KW ───────────────────────────────────────────────────────
    {
        let mut enc_tests = Vec::new();
        let mut valid_dec_tests = Vec::new();
        let mut invalid_dec_tests = Vec::new();
        let mut tc_id = 1;

        for _ in 0..NUM_TESTS {
            // KW plaintext must be multiple of 8 bytes, minimum 16.
            let mut pt = [0u8; 32]; // 4 semiblocks
            drbg.generate(None, &mut pt).expect("drbg gen pt");

            let mut ct = [0u8; 40]; // pt + 8-byte ICV
            oxicrypt_aes::kw_wrap(&cipher, &pt, &mut ct).expect("kw wrap");

            let ct_hex = hex_upper(&ct);
            let pt_hex = hex_upper(&pt);

            enc_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "pt": "{}",
          "ct": "{}"
        }}"#,
                tc_id, key_hex, pt_hex, ct_hex
            ));

            // Valid unwrap
            valid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "ct": "{}",
          "testPassed": true,
          "pt": "{}"
        }}"#,
                tc_id + NUM_TESTS,
                key_hex,
                ct_hex,
                pt_hex
            ));

            // Invalid unwrap: flip first byte of ct
            invalid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "ct": "{}",
          "testPassed": false
        }}"#,
                tc_id + 2 * NUM_TESTS,
                key_hex,
                flip_hex(&ct_hex)
            ));

            tc_id += 1;
        }

        let json = format!(
            r#"{{
  "_generator": "gen_aes_lifecycle_slice (R41)",
  "algorithm": "ACVP-AES-KW",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 3,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            enc_tests.join(",\n"),
            valid_dec_tests.join(",\n"),
            invalid_dec_tests.join(",\n")
        );

        let dir = base.join("ACVP-AES-KW-1.0");
        let path = dir.join("lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }

    // ── KWP ──────────────────────────────────────────────────────
    {
        let mut enc_tests = Vec::new();
        let mut valid_dec_tests = Vec::new();
        let mut invalid_dec_tests = Vec::new();
        let mut tc_id = 1;

        for _ in 0..NUM_TESTS {
            // KWP allows non-aligned plaintext; use 25 bytes to exercise padding.
            let mut pt = [0u8; 25];
            drbg.generate(None, &mut pt).expect("drbg gen pt");

            // KWP output: ceil(pt_len / 8) * 8 + 8 = ceil(25/8)*8 + 8 = 32 + 8 = 40
            let padded = ((pt.len() + 7) / 8) * 8;
            let ct_len = padded + 8;
            let mut ct = vec![0u8; ct_len];
            oxicrypt_aes::kwp_wrap(&cipher, &pt, &mut ct).expect("kwp wrap");

            let ct_hex = hex_upper(&ct);
            let pt_hex = hex_upper(&pt);

            enc_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "pt": "{}",
          "ct": "{}"
        }}"#,
                tc_id, key_hex, pt_hex, ct_hex
            ));

            // Valid unwrap
            valid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "ct": "{}",
          "testPassed": true,
          "pt": "{}"
        }}"#,
                tc_id + NUM_TESTS,
                key_hex,
                ct_hex,
                pt_hex
            ));

            // Invalid unwrap: flip first byte
            invalid_dec_tests.push(format!(
                r#"        {{
          "tcId": {},
          "key": "{}",
          "ct": "{}",
          "testPassed": false
        }}"#,
                tc_id + 2 * NUM_TESTS,
                key_hex,
                flip_hex(&ct_hex)
            ));

            tc_id += 1;
        }

        let json = format!(
            r#"{{
  "_generator": "gen_aes_lifecycle_slice (R41)",
  "algorithm": "ACVP-AES-KWP",
  "revision": "1.0",
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "direction": "encrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 3,
      "testType": "AFT",
      "direction": "decrypt",
      "keyLen": 256,
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            enc_tests.join(",\n"),
            valid_dec_tests.join(",\n"),
            invalid_dec_tests.join(",\n")
        );

        let dir = base.join("ACVP-AES-KWP-1.0");
        let path = dir.join("lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }

    println!("\nAll 7 AES lifecycle slices generated.");
}
