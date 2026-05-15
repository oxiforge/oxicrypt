//! ACVTS regression tests for ML-DSA-87 sigGen.
//!
//! Each test pins a specific ACVTS sigGen test case that previously
//! produced a wrong signature in oxicrypt, so the same input never
//! regresses again silently.
//!
//! ## ACVTS session 730469 vsId 3859350 tcId 8
//!
//! `make_hint` boundary case at `a0 == -γ_2 && w1 != 0` was missed by
//! the spec-form `HighBits(r) != HighBits(r + z)` because both sides
//! land on `HighBits = 0` via the Decompose top-bin wrap rule for
//! `r = q - γ_2` (centered −γ_2).  FIPS 204 Algorithm 27's intent —
//! and pq-crystals/dilithium's shortcut form — explicitly returns 1
//! at this fence when `w1` is non-zero.  Single coefficient at
//! (poly=3, coeff=206) differed; signature bytes diverged in the
//! hint section only.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use oxicrypt_ml_dsa::{SIG_LEN, SK_LEN, sign_internal};

fn load(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
    std::fs::read(format!("{path}{name}")).expect("test data not found")
}

fn load_arr<const N: usize>(name: &str) -> [u8; N] {
    let v = load(name);
    assert_eq!(v.len(), N, "unexpected length for {name}");
    v.try_into().unwrap()
}

/// ACVTS session 730469 vsId 3859350 tcId 8 — `make_hint` `-γ_2` boundary.
///
/// signatureInterface = "internal", so the persisted `message.bin` is M'
/// (already framed); no further `0x00 || |ctx| || ctx` wrapping is
/// applied.  Deterministic mode → `sign_internal` must produce the
/// reference signature byte-for-byte.
#[test]
fn acvts_730469_tc8_siggen_make_hint_neg_gamma2_boundary() {
    let sk = load_arr::<SK_LEN>("mldsa87_acvts_tc8_siggen_sk.bin");
    let m_prime = load("mldsa87_acvts_tc8_siggen_message.bin");
    let expected_sig = load_arr::<SIG_LEN>("mldsa87_acvts_tc8_siggen_signature.bin");

    let sig =
        sign_internal(&sk, &m_prime).expect("sign_internal returned None for ACVTS tc8 inputs");

    assert_eq!(
        sig, expected_sig,
        "ML-DSA-87 sign_internal: ACVTS session 730469 vsId 3859350 tcId 8 \
         regression — signature must match pq-crystals/dilithium FIPS 204 \
         reference signature for the persisted (sk, M'). Differs only in the \
         hint section because make_hint missed the a0 == -γ_2 && w1 != 0 \
         fence case."
    );
}
