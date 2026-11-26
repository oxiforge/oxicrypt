//! A failed pairwise consistency test of ML-KEM-768 key generation, through
//! each of `keygen`, `keygen_with_seed` and `expand_key`, returns
//! `ConditionalTestFailed` and leaves the module in its error state
//! (FIPS 140-3 IG 10.3.A), in which key generation, encapsulation and
//! decapsulation return `NotOperational`.

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_ml_kem::ml_kem_768::{
    CT_LEN, decapsulate, encapsulate, expand_key, keygen, keygen_with_seed,
};
use oxicrypt_ml_kem::seam::{
    ML_KEM_768_KEYGEN_D, ML_KEM_768_KEYGEN_DK, ML_KEM_768_KEYGEN_EK, ML_KEM_768_KEYGEN_Z,
};
use pct_fault::FixedRbg;

/// The ACVP key-generation case `oxicrypt_ml_kem::seam` names.
fn control() {
    let (ek, dk) = expand_key(ML_KEM_768_KEYGEN_D, ML_KEM_768_KEYGEN_Z).unwrap();
    assert_eq!(&ek, ML_KEM_768_KEYGEN_EK);
    assert_eq!(&dk, ML_KEM_768_KEYGEN_DK);
}

#[test]
fn pct_fault_ml_kem_768() {
    pct_fault::run(
        "pct_fault_ml_kem_768",
        "ML-KEM-768 pairwise consistency",
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
        &[
            ("encapsulate", || {
                encapsulate(ML_KEM_768_KEYGEN_EK, &mut FixedRbg).map(drop)
            }),
            ("decapsulate", || {
                decapsulate(ML_KEM_768_KEYGEN_DK, &[0; CT_LEN]).map(drop)
            }),
        ],
    );
}
