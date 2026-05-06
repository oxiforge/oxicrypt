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
//! One-shot helper that generates `KAS-FFC-SSC-Sp800-56Ar3/kat-slice.json`.
//!
//! Two DRBG-driven MODP-3072 keypairs (Alice, Bob) seeded with
//! deterministic personalization strings. Four test vectors cover
//! cross-DH (Alice→Bob and the symmetric Bob→Alice) plus self-DH
//! (Alice→Alice, Bob→Bob) so the slice exercises all four combinations
//! of `(x, y)` selection while staying byte-stable across runs.
//!
//!   cargo test -p acvp-harness --test gen_kas_ffc_ssc_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_kas_ffc_ssc_slice() {
    ensure_initialized().expect("FIPS init");

    // Alice keypair from a fixed-seed DRBG.
    let mut alice_drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    alice_drbg
        .instantiate(
            b"oxicrypt-kas-ffc-ssc-kat-alice-entropy-v1",
            b"oxicrypt-kas-ffc-ssc-kat-alice-nonce-v1",
            b"",
        )
        .expect("alice drbg instantiate");
    let (x_a, y_a) =
        oxicrypt_dh::generate_keypair_3072_internal(&mut alice_drbg).expect("alice keygen");

    // Bob keypair from a separate fixed-seed DRBG.
    let mut bob_drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    bob_drbg
        .instantiate(
            b"oxicrypt-kas-ffc-ssc-kat-bob-entropy-v1",
            b"oxicrypt-kas-ffc-ssc-kat-bob-nonce-v1",
            b"",
        )
        .expect("bob drbg instantiate");
    let (x_b, y_b) =
        oxicrypt_dh::generate_keypair_3072_internal(&mut bob_drbg).expect("bob keygen");

    // Compute the four shared secrets covering AB / BA / AA / BB.
    let z_ab = oxicrypt_dh::compute_shared_secret_3072_internal(&x_a, &y_b).expect("DH AB failed");
    let z_ba = oxicrypt_dh::compute_shared_secret_3072_internal(&x_b, &y_a).expect("DH BA failed");
    assert_eq!(z_ab, z_ba, "DH symmetry broken (Z_AB != Z_BA)");
    let z_aa = oxicrypt_dh::compute_shared_secret_3072_internal(&x_a, &y_a).expect("DH AA failed");
    let z_bb = oxicrypt_dh::compute_shared_secret_3072_internal(&x_b, &y_b).expect("DH BB failed");

    // Test vectors: (tcId, x_iut, y_peer, expected_z)
    let tests = [
        (1, &x_a[..], &y_b[..], &z_ab[..]),
        (2, &x_b[..], &y_a[..], &z_ba[..]),
        (3, &x_a[..], &y_a[..], &z_aa[..]),
        (4, &x_b[..], &y_b[..], &z_bb[..]),
    ];

    let test_json: Vec<String> = tests
        .iter()
        .map(|(tc_id, x, y, z)| {
            format!(
                r#"        {{"tcId": {}, "x": "{}", "y": "{}", "z": "{}"}}"#,
                tc_id,
                hex_upper(x),
                hex_upper(y),
                hex_upper(z),
            )
        })
        .collect();

    let json = format!(
        r#"{{
  "vsId": 0,
  "algorithm": "KAS-FFC-SSC",
  "revision": "Sp800-56Ar3",
  "isSample": true,
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "AFT",
      "domainParameterGenerationMode": "MODP-3072",
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
        .join("vendor/nist/acvp-server/gen-val/json-files/KAS-FFC-SSC-Sp800-56Ar3");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("Wrote {}", out_path.display());
}
