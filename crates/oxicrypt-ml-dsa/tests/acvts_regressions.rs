//! ACVTS regression tests for ML-DSA-87 sigGen.
//!
//! Each test pins an ACVTS sigGen test case that exercises a boundary of
//! the signing path, compared byte for byte with the reference signature.
//!
//! ## ACVTS session 730469 vsId 3859350 tcId 8
//!
//! `make_hint` boundary case at `a0 == -γ_2 && w1 != 0`, which the
//! spec-form `HighBits(r) != HighBits(r + z)` misses because both sides
//! land on `HighBits = 0` via the Decompose top-bin wrap rule for
//! `r = q - γ_2` (centered −γ_2).  FIPS 204 Algorithm 39's intent —
//! and pq-crystals/dilithium's shortcut form — explicitly returns 1
//! at this fence when `w1` is non-zero.  The case turns on the single
//! coefficient at (poly=3, coeff=206), so an implementation that misses
//! it differs from the reference in the hint section only.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use oxicrypt_ml_dsa::{SIG_LEN, SK_LEN, sign_internal};

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// Brings the module out of `PowerOff` so that a test can call the
/// `*_internal` functions, which refuse until the self-tests have started.
/// A second call in the same process is a no-op.
fn start_module() {
    let _ = oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert_eq!(oxicrypt_module::require_self_test_started(), Ok(()));
}

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
/// applied.  With 32 zero bytes as `rnd`, the deterministic variant
/// (FIPS 204 §3.4), `sign_internal` must produce the reference signature
/// byte-for-byte.
#[test]
fn acvts_730469_tc8_siggen_make_hint_neg_gamma2_boundary() {
    start_module();
    let sk = load_arr::<SK_LEN>("mldsa87_acvts_tc8_siggen_sk.bin");
    let m_prime = load("mldsa87_acvts_tc8_siggen_message.bin");
    let expected_sig = load_arr::<SIG_LEN>("mldsa87_acvts_tc8_siggen_signature.bin");

    let sig = sign_internal(&sk, &m_prime, &[0u8; 32])
        .expect("sign_internal returned None for ACVTS tc8 inputs");

    assert_eq!(
        sig, expected_sig,
        "ML-DSA-87 sign_internal: ACVTS session 730469 vsId 3859350 tcId 8 \
         — signature must match the pq-crystals/dilithium FIPS 204 \
         reference signature for the persisted (sk, M'). A difference confined \
         to the hint section means make_hint misses the a0 == -γ_2 && w1 != 0 \
         fence case."
    );
}
