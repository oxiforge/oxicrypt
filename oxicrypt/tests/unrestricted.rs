//! The services the CNSA 2.0 profile does not permit, under
//! `Profile::Unrestricted`. Every test in this binary initialises with that
//! profile.

#![cfg(oxicrypt_lib)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{init, unhex};
use oxicrypt::{Error, HMAC_DRBG_MAX_REQUEST_LEN, MlDsa87KeySeed, Module, Profile};

fn module() -> Module {
    init(Profile::Unrestricted).expect("the signed fixture library initialises unrestricted")
}

// NIST CAVP HMAC_DRBG.rsp, [SHA-256], PredictionResistance = False, no
// reseed, no personalization or additional input, COUNT = 0; the same values
// are the module's HMAC_DRBG-SHA-256 self-test in crates/oxicrypt-drbg/src/kat.rs.
const ENTROPY: &str = "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488";
const NONCE: &str = "659ba96c601dc69fc902940805ec0ca8";
const EXPECTED: &str = "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89\
                        d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1\
                        07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668\
                        961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8";

#[test]
fn hmac_drbg_sha256_known_answer() {
    let m = module();
    let mut drbg = m.hmac_drbg_sha256().unwrap();
    drbg.instantiate(&unhex(ENTROPY), &unhex(NONCE), &[])
        .unwrap();
    let mut out = [0u8; 128];
    drbg.generate(&[], &mut out).unwrap();
    drbg.generate(&[], &mut out).unwrap();
    assert_eq!(out.as_slice(), unhex(EXPECTED));
}

#[test]
fn hmac_drbg_sha256_states_and_bounds() {
    let m = module();
    let mut drbg = m.hmac_drbg_sha256().unwrap();
    let mut out = [0xAAu8; 16];
    assert_eq!(drbg.generate(&[], &mut out), Err(Error::Uninstantiated));
    assert!(out.iter().all(|b| *b == 0), "output not wiped on error");
    assert_eq!(
        drbg.seed::<MlDsa87KeySeed>().unwrap_err(),
        Error::Uninstantiated
    );

    drbg.instantiate(&unhex(ENTROPY), &unhex(NONCE), b"p")
        .unwrap();
    drbg.reseed(&[3; 32], b"additional").unwrap();
    let mut big = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN + 1];
    assert_eq!(drbg.generate(&[], &mut big), Err(Error::OutputTooLong));
    assert!(big.iter().all(|b| *b == 0), "output not wiped on error");
    big.truncate(HMAC_DRBG_MAX_REQUEST_LEN);
    drbg.generate(b"more", &mut big).unwrap();

    assert_eq!(
        drbg.instantiate(&[0; 700], &[0; 69], &[]),
        Err(Error::InvalidInput),
        "769 bytes provided, over HMAC_DRBG_MAX_PROVIDED_LEN"
    );
}

/// A request over the bound is refused by the crate before the library is
/// called: on an uninstantiated handle the library would answer
/// `Uninstantiated` first.
#[test]
fn hmac_drbg_sha256_request_bound_is_checked_before_the_call() {
    let m = module();
    let mut drbg = m.hmac_drbg_sha256().unwrap();
    let mut big = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN + 1];
    assert_eq!(drbg.generate(&[], &mut big), Err(Error::OutputTooLong));
    let mut max = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN];
    assert_eq!(drbg.generate(&[], &mut max), Err(Error::Uninstantiated));
}

#[test]
fn seeds_from_the_drbg_generate_keys() {
    let m = module();
    let mut drbg = m.hmac_drbg_sha256().unwrap();
    drbg.instantiate(&unhex(ENTROPY), &unhex(NONCE), &[])
        .unwrap();
    let first: MlDsa87KeySeed = drbg.seed().unwrap();
    let second: MlDsa87KeySeed = drbg.seed().unwrap();
    assert_ne!(first.as_bytes(), second.as_bytes());

    let (pk, sk) = m.ml_dsa_87_keygen(first).unwrap();
    let sig = m.ml_dsa_87_sign(&sk, b"m", b"").unwrap();
    assert_eq!(m.ml_dsa_87_verify(&pk, b"m", b"", &sig), Ok(()));

    let (ek, dk) = m
        .ml_kem_1024_keygen(drbg.seed().unwrap(), drbg.seed().unwrap())
        .unwrap();
    let (sent, ct) = m
        .ml_kem_1024_encapsulate(&ek, drbg.seed().unwrap())
        .unwrap();
    let received = m.ml_kem_1024_decapsulate(&dk, &ct).unwrap();
    assert_eq!(sent.as_bytes(), received.as_bytes());
}

#[test]
fn a_cnsa2_request_after_unrestricted_is_a_mismatch() {
    module();
    assert_eq!(
        init(Profile::Cnsa2).unwrap_err().code,
        Error::ProfileMismatch {
            active: Profile::Unrestricted,
            requested: Profile::Cnsa2
        }
    );
}
