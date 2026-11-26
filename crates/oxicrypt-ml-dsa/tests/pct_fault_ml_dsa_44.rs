//! A failed pairwise consistency test of ML-DSA-44 key generation, through
//! each of `keygen`, `keygen_with_seed` and `expand_key`, returns
//! `ConditionalTestFailed` and leaves the module in its error state
//! (FIPS 140-3 IG 10.3.A), in which key generation and signing return
//! `NotOperational`.

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_ml_dsa::ml_dsa_44::{SK_LEN, expand_key, keygen, keygen_with_seed, sign};
use oxicrypt_ml_dsa::seam::{ML_DSA_44_ACVP_KEY_HASH, ML_DSA_44_ACVP_SEED};
use pct_fault::FixedRbg;

fn control() {
    let (pk, sk) = expand_key(&ML_DSA_44_ACVP_SEED).unwrap();
    let mut h = oxicrypt_sha::sha256::Sha256::new().unwrap();
    h.update(&pk);
    h.update(&sk);
    assert_eq!(h.finalize().unwrap(), ML_DSA_44_ACVP_KEY_HASH);
}

#[test]
fn pct_fault_ml_dsa_44() {
    pct_fault::run(
        "pct_fault_ml_dsa_44",
        "ML-DSA-44 pairwise consistency",
        control,
        &[
            ("keygen", || keygen(&mut FixedRbg).map(drop)),
            ("keygen_with_seed", || {
                keygen_with_seed(&mut FixedRbg).map(drop)
            }),
            ("expand_key", || expand_key(&[0x5a; 32]).map(drop)),
        ],
        &[("sign", || sign(&[0; SK_LEN], b"m", b"").map(drop))],
    );
}
