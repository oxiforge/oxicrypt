//! NIST ACVP Known-Answer Tests for SLH-DSA-SHA2-256s (FIPS 205).
//!
//! Vectors sourced from the NIST ACVP Server repository:
//!   usnistgov/ACVP-Server @ 112690e8484dba7077709a05b1f3af58ddefdd5d
//!
//! Context wrapping: FIPS 205 §9.2 defines SLH-DSA.Sign(SK, M, ctx) as:
//!   M' = toByte(0, 1) ‖ toByte(|ctx|, 1) ‖ ctx ‖ M
//! followed by SLH-DSA.SignInternal(SK, M', addrnd).  The ACVP sigGen
//! vectors record the raw message M before context wrapping.  Our
//! `sign_internal` / `verify_internal` implement SignInternal/VerifyInternal
//! (take M' directly), so the tests prepend `[0x00, 0x00]` for empty ctx.
//!
//! Test cases:
//!   - keyGen  tgId=9,  tcId=81:  (skSeed, skPrf, pkSeed) → (pk, sk)
//!   - sigGen  tgId=23, tcId=199: (sk, M) → signature (deterministic, empty ctx)
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::similar_names)]

use oxicrypt_slh_dsa::{
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

/// ACVP SLH-DSA-SHA2-256s keyGen: tgId=9, tcId=81.
///
/// xi = skSeed ‖ skPrf ‖ pkSeed (96 bytes).  keygen_internal must
/// reproduce the exact (pk, sk) values.
#[test]
fn nist_keygen_kat() {
    let sk_seed = load("slhdsa256s_nist_keygen_sk_seed.bin");
    let sk_prf = load("slhdsa256s_nist_keygen_sk_prf.bin");
    let pk_seed = load("slhdsa256s_nist_keygen_pk_seed.bin");
    let expected_pk = load_arr::<PK_LEN>("slhdsa256s_nist_keygen_pk.bin");
    let expected_sk = load_arr::<SK_LEN>("slhdsa256s_nist_keygen_sk.bin");

    // keygen_internal takes xi = SK.seed ‖ SK.prf ‖ PK.seed (96 bytes).
    let mut xi = [0u8; 96];
    xi[..32].copy_from_slice(&sk_seed);
    xi[32..64].copy_from_slice(&sk_prf);
    xi[64..96].copy_from_slice(&pk_seed);

    let (pk, sk) = keygen_internal(&xi);

    assert_eq!(
        pk, expected_pk,
        "SLH-DSA-SHA2-256s keyGen: pk does not match NIST ACVP vector (tgId=9, tcId=81)"
    );
    assert_eq!(
        sk, expected_sk,
        "SLH-DSA-SHA2-256s keyGen: sk does not match NIST ACVP vector (tgId=9, tcId=81)"
    );
}

// ── Second keyGen KAT ──────────────────────────────────────────────────────

/// ACVP SLH-DSA-SHA2-256s keyGen: tgId=9, tcId=82.
///
/// Second independent test case from the NIST ACVP Server projection.
#[test]
fn nist_keygen_kat_2() {
    let sk_seed = load("slhdsa256s_nist_keygen2_sk_seed.bin");
    let sk_prf = load("slhdsa256s_nist_keygen2_sk_prf.bin");
    let pk_seed = load("slhdsa256s_nist_keygen2_pk_seed.bin");
    let expected_pk = load_arr::<PK_LEN>("slhdsa256s_nist_keygen2_pk.bin");
    let expected_sk = load_arr::<SK_LEN>("slhdsa256s_nist_keygen2_sk.bin");

    let mut xi = [0u8; 96];
    xi[..32].copy_from_slice(&sk_seed);
    xi[32..64].copy_from_slice(&sk_prf);
    xi[64..96].copy_from_slice(&pk_seed);

    let (pk, sk) = keygen_internal(&xi);

    assert_eq!(
        pk, expected_pk,
        "SLH-DSA-SHA2-256s keyGen: pk does not match NIST ACVP vector (tgId=9, tcId=82)"
    );
    assert_eq!(
        sk, expected_sk,
        "SLH-DSA-SHA2-256s keyGen: sk does not match NIST ACVP vector (tgId=9, tcId=82)"
    );
}

// ── sigGen KAT ──────────────────────────────────────────────────────────────

/// ACVP SLH-DSA-SHA2-256s sigGen: tgId=23, tcId=199 (deterministic, empty ctx).
///
/// The ACVP `message` field is the raw M.  FIPS 205 §9.2 wraps it as
/// M' = 0x00 ‖ 0x00 ‖ M before calling SignInternal.  `sign_internal`
/// is SignInternal and receives M' directly.
#[test]
fn nist_siggen_kat() {
    let sk = load_arr::<SK_LEN>("slhdsa256s_nist_siggen_sk.bin");
    let raw_message = load("slhdsa256s_nist_siggen_message.bin");
    let expected_sig = load_arr::<SIG_LEN>("slhdsa256s_nist_siggen_signature.bin");

    // Wrap M with empty context: M' = 0x00 ‖ 0x00 ‖ M
    let mut m_prime = Vec::with_capacity(2 + raw_message.len());
    m_prime.push(0x00); // format byte
    m_prime.push(0x00); // |ctx| = 0
    m_prime.extend_from_slice(&raw_message);

    let sig = sign_internal(&sk, &m_prime);

    assert_eq!(
        sig, expected_sig,
        "SLH-DSA-SHA2-256s sigGen: signature does not match NIST ACVP vector (tgId=23, tcId=199)"
    );
}

// ── Second sigGen KAT ──────────────────────────────────────────────────────

/// ACVP SLH-DSA-SHA2-256s sigGen: tgId=33, tcId=285 (deterministic, internal interface).
///
/// Second independent sigGen vector using the "internal" signature
/// interface — the message field is already M', so no context prefix
/// is added.
#[test]
fn nist_siggen_kat_2() {
    let sk = load_arr::<SK_LEN>("slhdsa256s_nist_siggen2_sk.bin");
    let m_prime = load("slhdsa256s_nist_siggen2_message.bin");
    let expected_sig = load_arr::<SIG_LEN>("slhdsa256s_nist_siggen2_signature.bin");

    // signatureInterface = "internal": the message IS M', no wrapping needed.
    let sig = sign_internal(&sk, &m_prime);

    assert_eq!(
        sig, expected_sig,
        "SLH-DSA-SHA2-256s sigGen: signature does not match NIST ACVP vector (tgId=33, tcId=285)"
    );
}

/// Verify the NIST sigGen signature using the corresponding public key.
///
/// The sk in the sigGen vector encodes PK.seed ‖ PK.root at offsets
/// [64..96] and [96..128], so pk can be reconstructed as PK.seed ‖ PK.root.
#[test]
fn nist_siggen_verify() {
    let sk = load_arr::<SK_LEN>("slhdsa256s_nist_siggen_sk.bin");
    let raw_message = load("slhdsa256s_nist_siggen_message.bin");
    let sig = load_arr::<SIG_LEN>("slhdsa256s_nist_siggen_signature.bin");

    // SLH-DSA sk = SK.seed(32) ‖ SK.prf(32) ‖ PK.seed(32) ‖ PK.root(32)
    // pk = PK.seed(32) ‖ PK.root(32)
    let mut pk = [0u8; PK_LEN];
    pk.copy_from_slice(&sk[64..128]);

    let mut m_prime = Vec::with_capacity(2 + raw_message.len());
    m_prime.push(0x00);
    m_prime.push(0x00);
    m_prime.extend_from_slice(&raw_message);

    assert!(
        verify_internal(&pk, &m_prime, &sig),
        "SLH-DSA-SHA2-256s: verify_internal rejected valid NIST signature (tgId=23, tcId=199)"
    );
}
