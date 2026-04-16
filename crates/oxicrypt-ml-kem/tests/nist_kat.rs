//! NIST ACVP Known-Answer Tests for ML-KEM-1024 (FIPS 203).
//!
//! Vectors sourced from the NIST ACVP Server repository:
//!   usnistgov/ACVP-Server @ 112690e8484dba7077709a05b1f3af58ddefdd5d
//!
//! Test cases exercise:
//!   - keyGen: given (d, z) → verify (ek, dk) match expected values
//!   - encapDecap: given (ek, m) → verify (c, K) match expected values,
//!     then decapsulate and verify shared secret matches K
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::similar_names)]

use oxicrypt_ml_kem::{
    CT_LEN, DK_LEN, EK_LEN, SEED_LEN, SHARED_SECRET_LEN,
    {decaps_internal, encaps_internal, keygen_internal},
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

/// ACVP ML-KEM-1024 keyGen: tgId=3, tcId=51.
///
/// Given deterministic seeds (d, z), keygen must reproduce the exact
/// encapsulation key (ek) and decapsulation key (dk).
#[test]
fn nist_keygen_kat() {
    let d = load_arr::<SEED_LEN>("mlkem1024_nist_keygen_d.bin");
    let z = load_arr::<SEED_LEN>("mlkem1024_nist_keygen_z.bin");
    let expected_ek = load_arr::<EK_LEN>("mlkem1024_nist_keygen_ek.bin");
    let expected_dk = load_arr::<DK_LEN>("mlkem1024_nist_keygen_dk.bin");

    let (ek, dk) =
        keygen_internal(&d, &z).expect("keygen_internal returned None for valid NIST seeds");

    assert_eq!(
        ek, expected_ek,
        "ML-KEM-1024 keyGen: ek does not match NIST ACVP vector (tgId=3, tcId=51)"
    );
    assert_eq!(
        dk, expected_dk,
        "ML-KEM-1024 keyGen: dk does not match NIST ACVP vector (tgId=3, tcId=51)"
    );
}

// ── encapDecap KAT ──────────────────────────────────────────────────────────

/// ACVP ML-KEM-1024 encapDecap (encapsulation): tgId=3, tcId=51.
///
/// The encapDecap test uses its own key pair (separate from the keyGen
/// test).  Given ek and randomness m, encapsulation must produce the
/// expected ciphertext c and shared secret K.
#[test]
fn nist_encap_kat() {
    let ek = load_arr::<EK_LEN>("mlkem1024_nist_encap_ek.bin");
    let m = load_arr::<SEED_LEN>("mlkem1024_nist_encap_m.bin");
    let expected_c = load_arr::<CT_LEN>("mlkem1024_nist_encap_c.bin");
    let expected_k = load_arr::<SHARED_SECRET_LEN>("mlkem1024_nist_encap_k.bin");

    let (k, c) = encaps_internal(&ek, &m);

    assert_eq!(
        c, expected_c,
        "ML-KEM-1024 encaps: ciphertext does not match NIST ACVP vector (tgId=3, tcId=51)"
    );
    assert_eq!(
        k, expected_k,
        "ML-KEM-1024 encaps: shared secret does not match NIST ACVP vector (tgId=3, tcId=51)"
    );
}

/// ACVP ML-KEM-1024 encapDecap (decapsulation): tgId=3, tcId=51.
///
/// Decapsulate the NIST ciphertext with the NIST decapsulation key and
/// verify the recovered shared secret matches the expected K.
#[test]
fn nist_decap_kat() {
    let dk = load_arr::<DK_LEN>("mlkem1024_nist_encap_dk.bin");
    let c = load_arr::<CT_LEN>("mlkem1024_nist_encap_c.bin");
    let expected_k = load_arr::<SHARED_SECRET_LEN>("mlkem1024_nist_encap_k.bin");

    let k = decaps_internal(&dk, &c);

    assert_eq!(
        k, expected_k,
        "ML-KEM-1024 decaps: shared secret does not match NIST ACVP vector (tgId=3, tcId=51)"
    );
}

// ── Second keyGen KAT ──────────────────────────────────────────────────────

/// ACVP ML-KEM-1024 keyGen: tgId=3, tcId=52.
///
/// Second independent test case from the NIST ACVP Server projection,
/// providing additional assurance that keygen is fully correct.
#[test]
fn nist_keygen_kat_2() {
    let d = load_arr::<SEED_LEN>("mlkem1024_nist_keygen2_d.bin");
    let z = load_arr::<SEED_LEN>("mlkem1024_nist_keygen2_z.bin");
    let expected_ek = load_arr::<EK_LEN>("mlkem1024_nist_keygen2_ek.bin");
    let expected_dk = load_arr::<DK_LEN>("mlkem1024_nist_keygen2_dk.bin");

    let (ek, dk) =
        keygen_internal(&d, &z).expect("keygen_internal returned None for valid NIST seeds");

    assert_eq!(
        ek, expected_ek,
        "ML-KEM-1024 keyGen: ek does not match NIST ACVP vector (tgId=3, tcId=52)"
    );
    assert_eq!(
        dk, expected_dk,
        "ML-KEM-1024 keyGen: dk does not match NIST ACVP vector (tgId=3, tcId=52)"
    );
}

// ── Second encapDecap KAT ──────────────────────────────────────────────────

/// ACVP ML-KEM-1024 encapDecap (encapsulation): tgId=3, tcId=52.
#[test]
fn nist_encap_kat_2() {
    let ek = load_arr::<EK_LEN>("mlkem1024_nist_encap2_ek.bin");
    let m = load_arr::<SEED_LEN>("mlkem1024_nist_encap2_m.bin");
    let expected_c = load_arr::<CT_LEN>("mlkem1024_nist_encap2_c.bin");
    let expected_k = load_arr::<SHARED_SECRET_LEN>("mlkem1024_nist_encap2_k.bin");

    let (k, c) = encaps_internal(&ek, &m);

    assert_eq!(
        c, expected_c,
        "ML-KEM-1024 encaps: ciphertext does not match NIST ACVP vector (tgId=3, tcId=52)"
    );
    assert_eq!(
        k, expected_k,
        "ML-KEM-1024 encaps: shared secret does not match NIST ACVP vector (tgId=3, tcId=52)"
    );
}

/// ACVP ML-KEM-1024 encapDecap (decapsulation): tgId=3, tcId=52.
#[test]
fn nist_decap_kat_2() {
    let dk = load_arr::<DK_LEN>("mlkem1024_nist_encap2_dk.bin");
    let c = load_arr::<CT_LEN>("mlkem1024_nist_encap2_c.bin");
    let expected_k = load_arr::<SHARED_SECRET_LEN>("mlkem1024_nist_encap2_k.bin");

    let k = decaps_internal(&dk, &c);

    assert_eq!(
        k, expected_k,
        "ML-KEM-1024 decaps: shared secret does not match NIST ACVP vector (tgId=3, tcId=52)"
    );
}
