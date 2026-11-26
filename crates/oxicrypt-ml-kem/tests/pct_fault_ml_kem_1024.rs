//! A failed pairwise consistency test of ML-KEM-1024 key generation, through
//! each of `keygen`, `keygen_with_seed` and `expand_key`, returns
//! `ConditionalTestFailed` and leaves the module in its error state
//! (FIPS 140-3 IG 10.3.A).

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_ml_kem::ml_kem_1024::{DK_LEN, EK_LEN, expand_key, keygen, keygen_with_seed};
use pct_fault::FixedRbg;

fn load<const N: usize>(name: &str) -> [u8; N] {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
    std::fs::read(format!("{path}{name}"))
        .unwrap()
        .try_into()
        .unwrap()
}

/// ACVP ML-KEM-1024 keyGen, tgId 3, tcId 51.
fn control() {
    let (ek, dk) = expand_key(
        &load::<32>("mlkem1024_nist_keygen_d.bin"),
        &load::<32>("mlkem1024_nist_keygen_z.bin"),
    )
    .unwrap();
    assert_eq!(ek, load::<EK_LEN>("mlkem1024_nist_keygen_ek.bin"));
    assert_eq!(dk, load::<DK_LEN>("mlkem1024_nist_keygen_dk.bin"));
}

#[test]
fn pct_fault_ml_kem_1024() {
    pct_fault::run(
        "pct_fault_ml_kem_1024",
        "ML-KEM-1024 pairwise consistency",
        control,
        &[
            ("keygen", || keygen(&mut FixedRbg).map(drop)),
            ("keygen_with_seed", || {
                keygen_with_seed(&mut FixedRbg).map(drop)
            }),
            ("expand_key", || {
                expand_key(&[0x5a; 32], &[0x5b; 32]).map(drop)
            }),
        ],
    );
}
