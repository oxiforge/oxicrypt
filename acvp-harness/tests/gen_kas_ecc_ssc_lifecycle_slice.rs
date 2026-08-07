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
//! One-shot helper that generates a KAS-ECC-SSC lifecycle vector file:
//!
//! - `KAS-ECC-SSC-Sp800-56Ar3/lifecycle-slice.json`
//!
//! Reuses the same five DRBG-generated P-256 private keys from the
//! ECDSA lifecycle (R36) and pairs each with a fresh "peer" key.
//! The shared secret `z = x(d * Q_peer)` is computed for each pair,
//! proving that ECDSA-generated keys also work correctly for ECDH.
//!
//!   cargo test -p acvp-harness --test gen_kas_ecc_ssc_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_kas_ecc_ssc_lifecycle_slice() {
    ensure_initialized().expect("FIPS init");

    // Reproduce the same five ECDSA lifecycle private keys.
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"oxicrypt-ecdsa-lifecycle-gen-entropy-v1",
        b"oxicrypt-ecdsa-lifecycle-gen-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    let num_keys = 5;
    let mut private_keys: Vec<[u8; 32]> = Vec::new();

    for _ in 0..num_keys {
        let mut d = [0u8; 32];
        drbg.generate(None, &mut d).expect("drbg generate");
        private_keys.push(d);
    }

    // The ECDSA lifecycle generator also consumed 25 nonces (5 keys ×
    // 5 messages) from this same DRBG sequence. We skip those to
    // stay deterministic should anyone re-run both generators with
    // the same seed. Alternatively, we use a fresh DRBG for peer keys.
    //
    // For clarity, use a separate DRBG for peer key generation.
    let mut peer_drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    peer_drbg
        .instantiate(
            b"oxicrypt-kas-ecc-ssc-lifecycle-peer-entropy-v1",
            b"oxicrypt-kas-ecc-ssc-lifecycle-peer-nonce-v1",
            b"",
        )
        .expect("peer drbg instantiate");

    // Generate peer keys and compute shared secrets.
    let mut tests: Vec<String> = Vec::new();

    for (i, d) in private_keys.iter().enumerate() {
        // Generate peer private key.
        let mut peer_d = [0u8; 32];
        peer_drbg
            .generate(None, &mut peer_d)
            .expect("peer drbg generate");

        // Derive peer public key.
        let peer_pk = oxicrypt_ecdsa::p256_ecdsa::derive_public_key_internal(&peer_d)
            .expect("derive peer public key failed");

        // Compute shared secret: Z = x(d * Q_peer).
        let z = oxicrypt_ecdh::compute_shared_secret_p256_internal(d, &peer_pk)
            .expect("ECDH shared secret computation failed");

        // Also verify the reverse direction: Z' = x(peer_d * Q).
        let my_pk = oxicrypt_ecdsa::p256_ecdsa::derive_public_key_internal(d)
            .expect("derive own public key failed");
        let z_reverse = oxicrypt_ecdh::compute_shared_secret_p256_internal(&peer_d, &my_pk)
            .expect("ECDH reverse shared secret failed");
        assert_eq!(
            z, z_reverse,
            "Shared secret mismatch for key pair {i}: forward != reverse"
        );

        // Extract peer_pk X and Y (SEC1 uncompressed: 0x04 || X || Y).
        let peer_x_hex = hex_upper(&peer_pk[1..33]);
        let peer_y_hex = hex_upper(&peer_pk[33..65]);

        tests.push(format!(
            r#"        {{
          "tcId": {},
          "d": "{}",
          "peerPublicKeyX": "{}",
          "peerPublicKeyY": "{}",
          "z": "{}"
        }}"#,
            i + 1,
            hex_upper(d),
            peer_x_hex,
            peer_y_hex,
            hex_upper(&z),
        ));
    }

    let json = format!(
        r#"{{
  "_source": "oxicrypt self-generated KAS-ECC-SSC lifecycle vectors",
  "algorithm": "KAS-ECC-SSC",
  "revision": "Sp800-56Ar3",
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
        tests.join(",\n"),
    );

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files");

    let path = base
        .join("KAS-ECC-SSC-Sp800-56Ar3")
        .join("lifecycle-slice.json");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.write_all(b"\n").unwrap();
    println!("Wrote {} ({} bytes)", path.display(), json.len());
}
