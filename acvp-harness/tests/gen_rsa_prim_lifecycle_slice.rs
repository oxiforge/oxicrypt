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
    // Lifecycle generators use `let mut tc_id = 1; for _ in 0..N { ...; tc_id += 1; }`
    // as a deliberate fixture-builder idiom; rewriting to `for tc_id in 1..=N` would
    // be cosmetic. Allow at file scope rather than every test-scaffold module.
    clippy::explicit_counter_loop
)]
//! One-shot helper that generates RSA primitive lifecycle vector files:
//!
//! - `RSA-SignaturePrimitive-2.0/lifecycle-slice.json`
//! - `RSA-decryptionPrimitive-Sp800-56Br2/lifecycle-slice.json`
//!
//! Reuses the same DRBG seed as the RSA lifecycle slices (R37/R39/R43)
//! to regenerate the same RSA-2048 key, then exercises both primitives
//! with the same set of random message representatives across standard
//! (non-CRT, `d`) and CRT (Bellcore-protected) key modes.
//!
//! Cross-validation: `signaturePrimitive` computes `sig = msg^d mod n`
//! and `decryptionPrimitive` computes `pt = ct^d mod n`; when fed the
//! same input both must produce the same output, proving the two
//! handlers agree on the same key.
//!
//!   cargo test -p acvp-harness --test gen_rsa_prim_lifecycle_slice -- --ignored --nocapture

use acvp_harness::ensure_initialized;
use std::io::Write;

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

const NUM_TESTS: usize = 5;

#[test]
#[ignore = "one-shot generator, run manually"]
fn generate_rsa_prim_lifecycle_slices() {
    ensure_initialized().expect("FIPS init");

    // ── Reproduce the RSA key from the lifecycle DRBG seed ───────
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(
        b"pqclib-rsa-lifecycle-gen-entropy-v1",
        b"pqclib-rsa-lifecycle-gen-nonce-v1",
        b"",
    )
    .expect("drbg instantiate");

    let km = oxicrypt_rsa::keygen::generate_2048(&mut drbg, 65537).expect("RSA keygen");

    let n_bytes: [u8; 256] = km.n.to_be_bytes();
    let d_bytes: [u8; 256] = km.d.to_be_bytes();
    let p_bytes: [u8; 128] = km.p.to_be_bytes();
    let q_bytes: [u8; 128] = km.q.to_be_bytes();
    let dp_bytes: [u8; 128] = km.dp.to_be_bytes();
    let dq_bytes: [u8; 128] = km.dq.to_be_bytes();
    let qinv_bytes: [u8; 128] = km.qinv.to_be_bytes();
    let e: u64 = 65537;

    let n_hex = hex_upper(&n_bytes);
    let d_hex = hex_upper(&d_bytes);
    let e_hex = "010001";
    let p_hex = hex_upper(&p_bytes);
    let q_hex = hex_upper(&q_bytes);
    let dp_hex = hex_upper(&dp_bytes);
    let dq_hex = hex_upper(&dq_bytes);
    let qinv_hex = hex_upper(&qinv_bytes);

    // ── Generate random message representatives (< n) ───────────
    let mut msg_drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    msg_drbg
        .instantiate(
            b"pqclib-rsa-prim-lifecycle-msg-entropy-v1",
            b"pqclib-rsa-prim-lifecycle-msg-nonce-v1",
            b"",
        )
        .expect("msg drbg instantiate");

    let mut messages: Vec<[u8; 256]> = Vec::with_capacity(NUM_TESTS);
    for _ in 0..NUM_TESTS {
        let mut msg = [0u8; 256];
        msg_drbg.generate(None, &mut msg).expect("drbg gen msg");
        // Ensure msg < n by clearing the top byte.  Since n is a 2048-bit
        // RSA modulus its top byte is ≥ 0x80, so any 256-byte value with
        // a leading 0x00 is guaranteed < n.
        msg[0] = 0x00;
        messages.push(msg);
    }

    // ── Compute primitives ──────────────────────────────────────
    // Both primitives are mathematically msg^d mod n, so the output
    // is the same regardless of which handler processes the input.
    let mut results_std: Vec<[u8; 256]> = Vec::with_capacity(NUM_TESTS);
    let mut results_crt: Vec<[u8; 256]> = Vec::with_capacity(NUM_TESTS);

    for msg in &messages {
        let sig_std = oxicrypt_rsa::rsa_signature_primitive_2048_internal(&n_bytes, &d_bytes, msg)
            .expect("sigPrim standard");

        let sig_crt = oxicrypt_rsa::rsa_signature_primitive_2048_crt_internal(
            &n_bytes,
            e,
            &p_bytes,
            &q_bytes,
            &dp_bytes,
            &dq_bytes,
            &qinv_bytes,
            msg,
        )
        .expect("sigPrim CRT");

        assert_eq!(sig_std, sig_crt, "standard / CRT mismatch");

        // Cross-check: decPrim must agree.
        let pt_std = oxicrypt_rsa::rsa_decryption_primitive_2048_internal(&n_bytes, &d_bytes, msg)
            .expect("decPrim standard");
        assert_eq!(sig_std, pt_std, "sigPrim / decPrim standard mismatch");

        let pt_crt = oxicrypt_rsa::rsa_decryption_primitive_2048_crt_internal(
            &n_bytes,
            e,
            &p_bytes,
            &q_bytes,
            &dp_bytes,
            &dq_bytes,
            &qinv_bytes,
            msg,
        )
        .expect("decPrim CRT");
        assert_eq!(sig_std, pt_crt, "sigPrim / decPrim CRT mismatch");

        results_std.push(sig_std);
        results_crt.push(sig_crt);
    }

    // ── Build signaturePrimitive lifecycle JSON ──────────────────
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vendor/nist/acvp-server/gen-val/json-files");

    {
        let mut std_tests = Vec::new();
        let mut crt_tests = Vec::new();
        let mut tc_id: usize = 1;

        for i in 0..NUM_TESTS {
            let msg_hex = hex_upper(&messages[i]);
            let sig_hex = hex_upper(&results_std[i]);

            // Standard group test: dmp1/dmq1/iqmp empty, p/q present
            std_tests.push(format!(
                r#"        {{"tcId": {tc}, "testPassed": true, "deferred": false, "signature": "{sig}", "message": "{msg}", "n": "{n}", "e": "{e}", "d": "{d}", "p": "{p}", "q": "{q}", "dmp1": "", "dmq1": "", "iqmp": ""}}"#,
                tc = tc_id,
                sig = sig_hex,
                msg = msg_hex,
                n = n_hex,
                e = e_hex,
                d = d_hex,
                p = p_hex,
                q = q_hex,
            ));

            // CRT group test: all fields populated
            crt_tests.push(format!(
                r#"        {{"tcId": {tc}, "testPassed": true, "deferred": false, "signature": "{sig}", "message": "{msg}", "n": "{n}", "e": "{e}", "d": "{d}", "p": "{p}", "q": "{q}", "dmp1": "{dp}", "dmq1": "{dq}", "iqmp": "{qi}"}}"#,
                tc = tc_id + NUM_TESTS,
                sig = sig_hex,
                msg = msg_hex,
                n = n_hex,
                e = e_hex,
                d = d_hex,
                p = p_hex,
                q = q_hex,
                dp = dp_hex,
                dq = dq_hex,
                qi = qinv_hex,
            ));

            tc_id += 1;
        }

        let sigprim_json = format!(
            r#"{{
  "_generator": "gen_rsa_prim_lifecycle_slice (R44)",
  "vsId": 0,
  "algorithm": "RSA",
  "mode": "signaturePrimitive",
  "revision": "2.0",
  "isSample": false,
  "testGroups": [
    {{
      "tgId": 1,
      "modulo": 2048,
      "testType": "AFT",
      "keyMode": "standard",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "modulo": 2048,
      "testType": "AFT",
      "keyMode": "crt",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            std_tests.join(",\n"),
            crt_tests.join(",\n"),
        );

        let path = base.join("RSA-SignaturePrimitive-2.0/lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(sigprim_json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), sigprim_json.len());
    }

    // ── Build decryptionPrimitive lifecycle JSON ─────────────────
    {
        let mut std_tests = Vec::new();
        let mut crt_tests = Vec::new();
        let mut tc_id: usize = 1;

        for i in 0..NUM_TESTS {
            let ct_hex = hex_upper(&messages[i]); // same input as sigPrim
            let pt_hex = hex_upper(&results_std[i]); // same output

            // Standard group test
            std_tests.push(format!(
                r#"        {{"tcId": {tc}, "testPassed": true, "deferred": false, "ct": "{ct}", "pt": "{pt}", "n": "{n}", "e": "{e}", "d": "{d}", "p": "{p}", "q": "{q}", "dmp1": "", "dmq1": "", "iqmp": ""}}"#,
                tc = tc_id,
                ct = ct_hex,
                pt = pt_hex,
                n = n_hex,
                e = e_hex,
                d = d_hex,
                p = p_hex,
                q = q_hex,
            ));

            // CRT group test
            crt_tests.push(format!(
                r#"        {{"tcId": {tc}, "testPassed": true, "deferred": false, "ct": "{ct}", "pt": "{pt}", "n": "{n}", "e": "{e}", "d": "{d}", "p": "{p}", "q": "{q}", "dmp1": "{dp}", "dmq1": "{dq}", "iqmp": "{qi}"}}"#,
                tc = tc_id + NUM_TESTS,
                ct = ct_hex,
                pt = pt_hex,
                n = n_hex,
                e = e_hex,
                d = d_hex,
                p = p_hex,
                q = q_hex,
                dp = dp_hex,
                dq = dq_hex,
                qi = qinv_hex,
            ));

            tc_id += 1;
        }

        let decprim_json = format!(
            r#"{{
  "_generator": "gen_rsa_prim_lifecycle_slice (R44)",
  "vsId": 0,
  "algorithm": "RSA",
  "mode": "decryptionPrimitive",
  "revision": "Sp800-56Br2",
  "isSample": false,
  "testGroups": [
    {{
      "tgId": 1,
      "modulo": 2048,
      "testType": "AFT",
      "keyMode": "standard",
      "pubExpMode": "fixed",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "modulo": 2048,
      "testType": "AFT",
      "keyMode": "crt",
      "pubExpMode": "fixed",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
            std_tests.join(",\n"),
            crt_tests.join(",\n"),
        );

        let path = base.join("RSA-decryptionPrimitive-Sp800-56Br2/lifecycle-slice.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(decprim_json.as_bytes()).unwrap();
        println!("wrote {} ({} bytes)", path.display(), decprim_json.len());
    }
}
