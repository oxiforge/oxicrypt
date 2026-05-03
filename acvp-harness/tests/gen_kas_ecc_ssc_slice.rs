#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::needless_range_loop,
    clippy::manual_string_new,
    clippy::uninlined_format_args,
    clippy::many_single_char_names,
    clippy::ignore_without_reason,
    clippy::similar_names
)]
//! One-shot helper that generates `KAS-ECC-SSC-Sp800-56Ar3/kat-slice.json`.
//!
//!   cargo test -p acvp-harness --test gen_kas_ecc_ssc_slice -- --ignored --nocapture

use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

// RFC 5903 §8.1 initiator key
const D_I: [u8; 32] = [
    0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31, 0x6d, 0xe5,
    0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33,
];
const Q_I: [u8; 65] = [
    0x04, 0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9, 0xb0, 0x51, 0xe1, 0xfe, 0xca, 0x57, 0x87,
    0xd0, 0x98, 0xdf, 0xe6, 0x37, 0xfc, 0x90, 0xb9, 0xef, 0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11,
    0x80, 0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52, 0xd6, 0x1f, 0x1c, 0x45, 0x6f, 0xa3, 0xe5,
    0x9a, 0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf, 0x5f, 0x58, 0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b,
    0xb3,
];

// RFC 5903 §8.1 responder key
const D_R: [u8; 32] = [
    0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97, 0xce, 0x20,
    0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53,
];
const Q_R: [u8; 65] = [
    0x04, 0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c,
    0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf,
    0x63, 0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d,
    0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72,
    0xab,
];

#[test]
#[ignore]
fn generate_kas_ecc_ssc_slice() {
    // Test 1: d_i * Q_r
    let z1 = oxicrypt_ecdh::compute_shared_secret_p256_internal(&D_I, &Q_R).expect("ECDH 1 failed");

    // Test 2: d_r * Q_i (symmetry check)
    let z2 = oxicrypt_ecdh::compute_shared_secret_p256_internal(&D_R, &Q_I).expect("ECDH 2 failed");

    assert_eq!(z1, z2, "ECDH symmetry broken");

    // Tests 3-4: use the keys as "ephemeral" parties with themselves to get different shared secrets
    // (d_i * Q_i is a self-DH which still works mathematically)
    let z3 =
        oxicrypt_ecdh::compute_shared_secret_p256_internal(&D_I, &Q_I).expect("ECDH self-i failed");
    let z4 =
        oxicrypt_ecdh::compute_shared_secret_p256_internal(&D_R, &Q_R).expect("ECDH self-r failed");

    // Build the test vectors using the ACVP KAS-ECC-SSC shape.
    // Each test provides: d (IUT private), peer public key as (X, Y), expected z.
    let tests = vec![
        (1, &D_I[..], &Q_R[1..33], &Q_R[33..65], &z1[..]),
        (2, &D_R[..], &Q_I[1..33], &Q_I[33..65], &z2[..]),
        (3, &D_I[..], &Q_I[1..33], &Q_I[33..65], &z3[..]),
        (4, &D_R[..], &Q_R[1..33], &Q_R[33..65], &z4[..]),
    ];

    let mut test_json = Vec::new();
    for (tc_id, d, pub_x, pub_y, z) in &tests {
        test_json.push(format!(
            r#"        {{"tcId": {}, "d": "{}", "peerPublicKeyX": "{}", "peerPublicKeyY": "{}", "z": "{}"}}"#,
            tc_id,
            hex_upper(d),
            hex_upper(pub_x),
            hex_upper(pub_y),
            hex_upper(z),
        ));
    }

    let json = format!(
        r#"{{
  "vsId": 0,
  "algorithm": "KAS-ECC-SSC",
  "revision": "Sp800-56Ar3",
  "isSample": true,
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "domainParameterGenerationMode": "P-256",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        test_json.join(",\n"),
    );

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files/KAS-ECC-SSC-Sp800-56Ar3");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("Wrote {}", out_path.display());
}
