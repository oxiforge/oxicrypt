//! Per-pair NIST ACVP sigVer Known-Answer Tests for the SP 800-208 LMS grid.
//!
//! Source: usnistgov/ACVP-Server @ 112690e8484dba7077709a05b1f3af58ddefdd5d
//!         gen-val/json-files/LMS-sigVer-1.0/internalProjection.json
//!
//! For every (lmsMode, lmOtsMode) pair instantiated in `oxicrypt-lms`,
//! one passing-verification test case (testPassed=true, tcId varies) is
//! vendored as three binary fixtures and verified against the per-pair
//! `verify_internal` function:
//!
//!   - `<pair>_sigver_pk.bin`  (publicKey from group level)
//!   - `<pair>_sigver_msg.bin` (message from chosen test)
//!   - `<pair>_sigver_sig.bin` (signature from chosen test)
//!
//! Per-pair external grounding catches parameter-table errors that a
//! self-consistent macro instantiation cannot — a wrong P / U / V / LS
//! produces a signature parse-length mismatch and verify returns false
//! before any hash chain runs. The macro shape (single-layer, `:expr`
//! numerics, hash adapter as `:path`) structurally excludes the
//! SLH-DSA B7 `:literal` hygiene bug class (see CMVP gem in
//! `docs/security-policy/security-policy.md`).
//!
//! keyGen KAT vectors are not extracted by `scripts/lms_kat_extract.py`
//! because ACVP-Server's LMS-keyGen-1.0 internalProjection.json carries
//! only the IUT-generated public-key shape (group-level `publicKey` +
//! per-test message/signature), not the (seed, I) inputs a deterministic
//! IUT-side KAT would need. The legacy baseline pair's keyGen KAT
//! (seed, I, expected_pk) lives in `tests/data/lms_sha256_h10_*` from a
//! prior arc and is exercised by `tests/nist_kat.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::similar_names,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

fn load_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

macro_rules! sigver_kat {
    ($fn_name:ident, $pair:ident) => {
        #[test]
        fn $fn_name() {
            let slug = stringify!($pair);
            let pk_bytes = load_bytes(&format!("{slug}_sigver_pk.bin"));
            let msg = load_bytes(&format!("{slug}_sigver_msg.bin"));
            let sig_bytes = load_bytes(&format!("{slug}_sigver_sig.bin"));
            let pk: [u8; oxicrypt_lms::$pair::PUBLIC_KEY_LEN] =
                pk_bytes.try_into().expect("pk length mismatch");
            let sig: [u8; oxicrypt_lms::$pair::SIGNATURE_LEN] =
                sig_bytes.try_into().expect("sig length mismatch");
            assert!(
                oxicrypt_lms::$pair::verify_internal(&pk, &msg, &sig),
                "ACVP sigVer KAT verify_internal returned false for {slug}"
            );
        }
    };
}

// 20 SHA-256 / M=32 pairs (B2).
sigver_kat!(sha256_m32_h5_w1_sigver_kat, lms_sha256_m32_h5_w1);
sigver_kat!(sha256_m32_h5_w2_sigver_kat, lms_sha256_m32_h5_w2);
sigver_kat!(sha256_m32_h5_w4_sigver_kat, lms_sha256_m32_h5_w4);
sigver_kat!(sha256_m32_h5_w8_sigver_kat, lms_sha256_m32_h5_w8);
sigver_kat!(sha256_m32_h10_w1_sigver_kat, lms_sha256_m32_h10_w1);
sigver_kat!(sha256_m32_h10_w2_sigver_kat, lms_sha256_m32_h10_w2);
sigver_kat!(sha256_m32_h10_w4_sigver_kat, lms_sha256_m32_h10_w4);
sigver_kat!(sha256_m32_h10_w8_sigver_kat, lms_sha256_m32_h10_w8);
sigver_kat!(sha256_m32_h15_w1_sigver_kat, lms_sha256_m32_h15_w1);
sigver_kat!(sha256_m32_h15_w2_sigver_kat, lms_sha256_m32_h15_w2);
sigver_kat!(sha256_m32_h15_w4_sigver_kat, lms_sha256_m32_h15_w4);
sigver_kat!(sha256_m32_h15_w8_sigver_kat, lms_sha256_m32_h15_w8);
sigver_kat!(sha256_m32_h20_w1_sigver_kat, lms_sha256_m32_h20_w1);
sigver_kat!(sha256_m32_h20_w2_sigver_kat, lms_sha256_m32_h20_w2);
sigver_kat!(sha256_m32_h20_w4_sigver_kat, lms_sha256_m32_h20_w4);
sigver_kat!(sha256_m32_h20_w8_sigver_kat, lms_sha256_m32_h20_w8);
sigver_kat!(sha256_m32_h25_w1_sigver_kat, lms_sha256_m32_h25_w1);
sigver_kat!(sha256_m32_h25_w2_sigver_kat, lms_sha256_m32_h25_w2);
sigver_kat!(sha256_m32_h25_w4_sigver_kat, lms_sha256_m32_h25_w4);
sigver_kat!(sha256_m32_h25_w8_sigver_kat, lms_sha256_m32_h25_w8);

// 20 SHA-256 / M=24 pairs (B3 — RFC 8708 §4.1).
sigver_kat!(sha256_m24_h5_w1_sigver_kat, lms_sha256_m24_h5_w1);
sigver_kat!(sha256_m24_h5_w2_sigver_kat, lms_sha256_m24_h5_w2);
sigver_kat!(sha256_m24_h5_w4_sigver_kat, lms_sha256_m24_h5_w4);
sigver_kat!(sha256_m24_h5_w8_sigver_kat, lms_sha256_m24_h5_w8);
sigver_kat!(sha256_m24_h10_w1_sigver_kat, lms_sha256_m24_h10_w1);
sigver_kat!(sha256_m24_h10_w2_sigver_kat, lms_sha256_m24_h10_w2);
sigver_kat!(sha256_m24_h10_w4_sigver_kat, lms_sha256_m24_h10_w4);
sigver_kat!(sha256_m24_h10_w8_sigver_kat, lms_sha256_m24_h10_w8);
sigver_kat!(sha256_m24_h15_w1_sigver_kat, lms_sha256_m24_h15_w1);
sigver_kat!(sha256_m24_h15_w2_sigver_kat, lms_sha256_m24_h15_w2);
sigver_kat!(sha256_m24_h15_w4_sigver_kat, lms_sha256_m24_h15_w4);
sigver_kat!(sha256_m24_h15_w8_sigver_kat, lms_sha256_m24_h15_w8);
sigver_kat!(sha256_m24_h20_w1_sigver_kat, lms_sha256_m24_h20_w1);
sigver_kat!(sha256_m24_h20_w2_sigver_kat, lms_sha256_m24_h20_w2);
sigver_kat!(sha256_m24_h20_w4_sigver_kat, lms_sha256_m24_h20_w4);
sigver_kat!(sha256_m24_h20_w8_sigver_kat, lms_sha256_m24_h20_w8);
sigver_kat!(sha256_m24_h25_w1_sigver_kat, lms_sha256_m24_h25_w1);
sigver_kat!(sha256_m24_h25_w2_sigver_kat, lms_sha256_m24_h25_w2);
sigver_kat!(sha256_m24_h25_w4_sigver_kat, lms_sha256_m24_h25_w4);
sigver_kat!(sha256_m24_h25_w8_sigver_kat, lms_sha256_m24_h25_w8);

// 20 SHAKE-256 / M=32 pairs (B3 — RFC 8708 §3.1).
sigver_kat!(shake_m32_h5_w1_sigver_kat, lms_shake_m32_h5_w1);
sigver_kat!(shake_m32_h5_w2_sigver_kat, lms_shake_m32_h5_w2);
sigver_kat!(shake_m32_h5_w4_sigver_kat, lms_shake_m32_h5_w4);
sigver_kat!(shake_m32_h5_w8_sigver_kat, lms_shake_m32_h5_w8);
sigver_kat!(shake_m32_h10_w1_sigver_kat, lms_shake_m32_h10_w1);
sigver_kat!(shake_m32_h10_w2_sigver_kat, lms_shake_m32_h10_w2);
sigver_kat!(shake_m32_h10_w4_sigver_kat, lms_shake_m32_h10_w4);
sigver_kat!(shake_m32_h10_w8_sigver_kat, lms_shake_m32_h10_w8);
sigver_kat!(shake_m32_h15_w1_sigver_kat, lms_shake_m32_h15_w1);
sigver_kat!(shake_m32_h15_w2_sigver_kat, lms_shake_m32_h15_w2);
sigver_kat!(shake_m32_h15_w4_sigver_kat, lms_shake_m32_h15_w4);
sigver_kat!(shake_m32_h15_w8_sigver_kat, lms_shake_m32_h15_w8);
sigver_kat!(shake_m32_h20_w1_sigver_kat, lms_shake_m32_h20_w1);
sigver_kat!(shake_m32_h20_w2_sigver_kat, lms_shake_m32_h20_w2);
sigver_kat!(shake_m32_h20_w4_sigver_kat, lms_shake_m32_h20_w4);
sigver_kat!(shake_m32_h20_w8_sigver_kat, lms_shake_m32_h20_w8);
sigver_kat!(shake_m32_h25_w1_sigver_kat, lms_shake_m32_h25_w1);
sigver_kat!(shake_m32_h25_w2_sigver_kat, lms_shake_m32_h25_w2);
sigver_kat!(shake_m32_h25_w4_sigver_kat, lms_shake_m32_h25_w4);
sigver_kat!(shake_m32_h25_w8_sigver_kat, lms_shake_m32_h25_w8);

// 20 SHAKE-256 / M=24 pairs (B3 — RFC 8708 §4.2).
sigver_kat!(shake_m24_h5_w1_sigver_kat, lms_shake_m24_h5_w1);
sigver_kat!(shake_m24_h5_w2_sigver_kat, lms_shake_m24_h5_w2);
sigver_kat!(shake_m24_h5_w4_sigver_kat, lms_shake_m24_h5_w4);
sigver_kat!(shake_m24_h5_w8_sigver_kat, lms_shake_m24_h5_w8);
sigver_kat!(shake_m24_h10_w1_sigver_kat, lms_shake_m24_h10_w1);
sigver_kat!(shake_m24_h10_w2_sigver_kat, lms_shake_m24_h10_w2);
sigver_kat!(shake_m24_h10_w4_sigver_kat, lms_shake_m24_h10_w4);
sigver_kat!(shake_m24_h10_w8_sigver_kat, lms_shake_m24_h10_w8);
sigver_kat!(shake_m24_h15_w1_sigver_kat, lms_shake_m24_h15_w1);
sigver_kat!(shake_m24_h15_w2_sigver_kat, lms_shake_m24_h15_w2);
sigver_kat!(shake_m24_h15_w4_sigver_kat, lms_shake_m24_h15_w4);
sigver_kat!(shake_m24_h15_w8_sigver_kat, lms_shake_m24_h15_w8);
sigver_kat!(shake_m24_h20_w1_sigver_kat, lms_shake_m24_h20_w1);
sigver_kat!(shake_m24_h20_w2_sigver_kat, lms_shake_m24_h20_w2);
sigver_kat!(shake_m24_h20_w4_sigver_kat, lms_shake_m24_h20_w4);
sigver_kat!(shake_m24_h20_w8_sigver_kat, lms_shake_m24_h20_w8);
sigver_kat!(shake_m24_h25_w1_sigver_kat, lms_shake_m24_h25_w1);
sigver_kat!(shake_m24_h25_w2_sigver_kat, lms_shake_m24_h25_w2);
sigver_kat!(shake_m24_h25_w4_sigver_kat, lms_shake_m24_h25_w4);
sigver_kat!(shake_m24_h25_w8_sigver_kat, lms_shake_m24_h25_w8);
