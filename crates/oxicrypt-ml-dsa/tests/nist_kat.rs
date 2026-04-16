//! NIST ACVP Known-Answer Tests for ML-DSA-87 (FIPS 204).
//!
//! Vectors sourced from the NIST ACVP Server repository:
//!   usnistgov/ACVP-Server @ 112690e8484dba7077709a05b1f3af58ddefdd5d
//!
//! Context wrapping: FIPS 204 §3.3 defines ML-DSA.Sign(sk, M, ctx) as:
//!   M' = 0x00 ‖ IntegerToBytes(|ctx|, 1) ‖ ctx ‖ M
//! followed by SignInternal(sk, M', rnd).  The ACVP sigGen vectors record
//! the raw message M before context wrapping.  Our `sign_internal` /
//! `verify_internal` implement SignInternal/VerifyInternal (take M'
//! directly), so the tests prepend `[0x00, 0x00]` for empty context.
//!
//! Test cases:
//!   - keyGen  tgId=3, tcId=51: seed → (pk, sk)
//!   - sigGen  tgId=5, tcId=73: (sk, M) → signature (deterministic, empty ctx)
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::similar_names)]

use oxicrypt_ml_dsa::{
    PK_LEN, SIG_LEN, SK_LEN, {keygen_internal, sign_internal, verify_internal},
};

// ── Vector helpers ──────────────────────────────────────────────────────────

fn load(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
    std::fs::read(format!("{path}{name}")).expect("test data not found")
}

fn load_arr<const N: usize>(name: &str) -> [u8; N] {
    let v = load(name);
    assert_eq!(v.len(), N, "unexpected length for {name}");
    v.try_into().unwrap()
}

// ── keyGen KAT ──────────────────────────────────────────────────────────────

/// ACVP ML-DSA-87 keyGen: tgId=3, tcId=51.
///
/// Given 32-byte xi seed, keygen must reproduce the exact public key and
/// secret key.
#[test]
fn nist_keygen_kat() {
    let xi = load_arr::<32>("mldsa87_nist_keygen_seed.bin");
    let expected_pk = load_arr::<PK_LEN>("mldsa87_nist_keygen_pk.bin");
    let expected_sk = load_arr::<SK_LEN>("mldsa87_nist_keygen_sk.bin");

    let (pk, sk) = keygen_internal(&xi);

    assert_eq!(
        pk, expected_pk,
        "ML-DSA-87 keyGen: pk does not match NIST ACVP vector (tgId=3, tcId=51)"
    );
    assert_eq!(
        sk, expected_sk,
        "ML-DSA-87 keyGen: sk does not match NIST ACVP vector (tgId=3, tcId=51)"
    );
}

// ── sigGen KAT ──────────────────────────────────────────────────────────────

/// ACVP ML-DSA-87 sigGen: tgId=5, tcId=73 (deterministic, empty context).
///
/// The ACVP `message` field is the raw M.  FIPS 204 §3.3 wraps it as
/// M' = 0x00 ‖ 0x00 ‖ M before calling SignInternal.  `sign_internal`
/// is SignInternal and receives M' directly.
#[test]
fn nist_siggen_kat() {
    let sk = load_arr::<SK_LEN>("mldsa87_nist_siggen_sk.bin");
    let raw_message = load("mldsa87_nist_siggen_message.bin");
    let expected_sig = load_arr::<SIG_LEN>("mldsa87_nist_siggen_signature.bin");

    // Wrap M with empty context: M' = 0x00 ‖ 0x00 ‖ M
    let mut m_prime = Vec::with_capacity(2 + raw_message.len());
    m_prime.push(0x00); // format byte
    m_prime.push(0x00); // |ctx| = 0
    m_prime.extend_from_slice(&raw_message);

    let sig = sign_internal(&sk, &m_prime)
        .expect("sign_internal returned None for valid NIST secret key");

    assert_eq!(
        sig, expected_sig,
        "ML-DSA-87 sigGen: signature does not match NIST ACVP vector (tgId=5, tcId=73)"
    );
}

// ── Second keyGen KAT ──────────────────────────────────────────────────────

/// ACVP ML-DSA-87 keyGen: tgId=3, tcId=52.
///
/// Second independent test case from the NIST ACVP Server projection.
#[test]
fn nist_keygen_kat_2() {
    let xi = load_arr::<32>("mldsa87_nist_keygen2_seed.bin");
    let expected_pk = load_arr::<PK_LEN>("mldsa87_nist_keygen2_pk.bin");
    let expected_sk = load_arr::<SK_LEN>("mldsa87_nist_keygen2_sk.bin");

    let (pk, sk) = keygen_internal(&xi);

    assert_eq!(
        pk, expected_pk,
        "ML-DSA-87 keyGen: pk does not match NIST ACVP vector (tgId=3, tcId=52)"
    );
    assert_eq!(
        sk, expected_sk,
        "ML-DSA-87 keyGen: sk does not match NIST ACVP vector (tgId=3, tcId=52)"
    );
}

// ── Second sigGen KAT ──────────────────────────────────────────────────────

/// ACVP ML-DSA-87 sigGen: tgId=12, tcId=166 (deterministic, internal interface).
///
/// Second independent sigGen vector using the "internal" signature
/// interface — the message field is already M' (pre-wrapped), so no
/// context prefix is added.  Different sk and message provide
/// additional assurance that the signing path is fully correct.
#[test]
fn nist_siggen_kat_2() {
    let sk = load_arr::<SK_LEN>("mldsa87_nist_siggen2_sk.bin");
    let m_prime = load("mldsa87_nist_siggen2_message.bin");
    let expected_sig = load_arr::<SIG_LEN>("mldsa87_nist_siggen2_signature.bin");

    // signatureInterface = "internal": the message IS M', no wrapping needed.
    let sig = sign_internal(&sk, &m_prime)
        .expect("sign_internal returned None for valid NIST secret key");

    assert_eq!(
        sig, expected_sig,
        "ML-DSA-87 sigGen: signature does not match NIST ACVP vector (tgId=12, tcId=166)"
    );
}

/// Round-trip: use the NIST keyGen seed to produce (pk, sk), then sign a
/// message and verify.  This exercises the full NIST-seeded key path
/// through verify_internal.
#[test]
fn nist_keygen_roundtrip() {
    let xi = load_arr::<32>("mldsa87_nist_keygen_seed.bin");
    let (pk, sk) = keygen_internal(&xi);

    // Message is arbitrary — this test exercises the keygen output path
    // not an ACVP sigGen vector.
    let raw_msg = b"nist-keygen-roundtrip test message for ML-DSA-87";
    let mut m_prime = Vec::with_capacity(2 + raw_msg.len());
    m_prime.push(0x00);
    m_prime.push(0x00);
    m_prime.extend_from_slice(raw_msg);

    let sig = sign_internal(&sk, &m_prime).expect("sign_internal failed on NIST-keygen key");

    assert!(
        verify_internal(&pk, &m_prime, &sig),
        "ML-DSA-87: verify_internal rejected valid signature from NIST-keygen key"
    );
}
