//! The services the CNSA 2.0 profile does not permit, under
//! `Profile::Unrestricted`. Every test in this binary initialises with that
//! profile.

#![cfg(oxicrypt_lib)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::init;
use oxicrypt::{
    DrbgKind, Error, HMAC_DRBG_MAX_PROVIDED_LEN, HMAC_DRBG_MAX_REQUEST_LEN, MlDsa87KeySeed,
    MlKem1024EncapsSeed, MlKem1024KeySeedD, MlKem1024KeySeedZ, Module, Profile,
};

fn module() -> Module {
    init(Profile::Unrestricted).expect("the signed fixture library initialises unrestricted")
}

/// Each kind with the security strength SP 800-90A gives it: 256 bits for
/// every HMAC_DRBG and Hash_DRBG here, the AES key length for CTR_DRBG.
const KINDS: [(DrbgKind, u32); 9] = [
    (DrbgKind::HmacSha256, 256),
    (DrbgKind::HmacSha384, 256),
    (DrbgKind::HmacSha512, 256),
    (DrbgKind::HashSha256, 256),
    (DrbgKind::HashSha384, 256),
    (DrbgKind::HashSha512, 256),
    (DrbgKind::CtrAes128, 128),
    (DrbgKind::CtrAes192, 192),
    (DrbgKind::CtrAes256, 256),
];

#[test]
fn drbg_generates_and_reseeds() {
    let m = module();
    for (kind, strength) in KINDS {
        let mut first = m.drbg(kind).unwrap();
        let mut second = m.drbg(kind).unwrap();
        first.instantiate(&[]).unwrap();
        second.instantiate(&[]).unwrap();
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        first.generate(&[], &mut a).unwrap();
        second.generate(&[], &mut b).unwrap();
        assert_ne!(a, [0u8; 64], "{kind:?} wrote nothing");
        assert_ne!(
            a, b,
            "two instantiations of {kind:?} produced the same output"
        );

        first.reseed(b"additional").unwrap();
        let mut c = [0u8; 64];
        first.generate(b"more", &mut c).unwrap();
        assert_ne!(a, c, "{kind:?} repeated its output after a reseed");
        assert_eq!(first.strength_bits(), Ok(strength), "{kind:?}");
        assert_eq!(second.strength_bits(), Ok(strength), "{kind:?}");
    }
}

#[test]
fn drbg_states_and_bounds() {
    let m = module();
    let mut drbg = m.drbg(DrbgKind::HmacSha256).unwrap();
    let mut out = [0xAAu8; 16];
    assert_eq!(drbg.generate(&[], &mut out), Err(Error::Uninstantiated));
    assert!(out.iter().all(|b| *b == 0), "output not wiped on error");
    assert_eq!(drbg.reseed(&[]), Err(Error::Uninstantiated));
    assert_eq!(drbg.strength_bits(), Err(Error::Uninstantiated));

    drbg.instantiate(b"p").unwrap();
    drbg.reseed(b"additional").unwrap();
    let mut big = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN + 1];
    assert_eq!(drbg.generate(&[], &mut big), Err(Error::OutputTooLong));
    assert!(big.iter().all(|b| *b == 0), "output not wiped on error");
    big.truncate(HMAC_DRBG_MAX_REQUEST_LEN);
    drbg.generate(b"more", &mut big).unwrap();

    assert_eq!(
        drbg.instantiate(&[0; HMAC_DRBG_MAX_PROVIDED_LEN]),
        Err(Error::InvalidInput),
        "a personalization string as long as everything HMAC_DRBG accepts"
    );
    assert_eq!(
        drbg.strength_bits(),
        Ok(256),
        "a refused instantiation leaves the handle as it was"
    );
}

/// A request over the bound is refused by the crate before the library is
/// called: on an uninstantiated handle the library would answer
/// `Uninstantiated` first.
#[test]
fn drbg_request_bound_is_checked_before_the_call() {
    let m = module();
    let mut drbg = m.drbg(DrbgKind::HmacSha256).unwrap();
    let mut big = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN + 1];
    assert_eq!(drbg.generate(&[], &mut big), Err(Error::OutputTooLong));
    let mut max = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN];
    assert_eq!(drbg.generate(&[], &mut max), Err(Error::Uninstantiated));
}

#[test]
fn seeds_from_the_drbg_generate_keys() {
    let m = module();
    let mut drbg = m.drbg(DrbgKind::HmacSha256).unwrap();
    drbg.instantiate(&[]).unwrap();
    let mut draw = || {
        let mut bytes = [0u8; 32];
        drbg.generate(&[], &mut bytes).unwrap();
        bytes
    };

    let (pk, sk) = m
        .ml_dsa_87_keygen(MlDsa87KeySeed::from_bytes(&draw()))
        .unwrap();
    let sig = m.ml_dsa_87_sign(&sk, b"m", b"").unwrap();
    assert_eq!(m.ml_dsa_87_verify(&pk, b"m", b"", &sig), Ok(()));

    let (ek, dk) = m
        .ml_kem_1024_keygen(
            MlKem1024KeySeedD::from_bytes(&draw()),
            MlKem1024KeySeedZ::from_bytes(&draw()),
        )
        .unwrap();
    let (sent, ct) = m
        .ml_kem_1024_encapsulate(&ek, MlKem1024EncapsSeed::from_bytes(&draw()))
        .unwrap();
    let received = m.ml_kem_1024_decapsulate(&dk, &ct).unwrap();
    assert_eq!(sent.as_bytes(), received.as_bytes());
}

#[test]
fn entropy_on_demand_test_names_the_seed_path() {
    let label = module().entropy_on_demand_test().unwrap();
    assert!(!label.is_empty());
    assert_ne!(label, "undecided");
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
