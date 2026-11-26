//! A failed pairwise consistency test of ML-KEM-768 key generation, through
//! each of `keygen`, `keygen_with_seed` and `expand_key`, returns
//! `ConditionalTestFailed` and leaves the module in its error state
//! (FIPS 140-3 IG 10.3.A).

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_ml_kem::ml_kem_768::{expand_key, keygen, keygen_with_seed};
use pct_fault::{FixedRbg, hex};

/// The seeds d and z, and SHA2-256(ek ‖ dk) of the expected pair, of NIST
/// ACVP-Server `ML-KEM-keyGen-FIPS203` internalProjection, tgId 2, tcId 26.
const D: &str = "A2B4BCA315A6EA4600B4A316E09A2578AA1E8BCE919C8DF3A96C71C843F5B38B";
const Z: &str = "D6BF055CB7B375E3271ED131F1BA31F83FEF533A239878A71074578B891265D1";
const KEY_HASH: &str = "1BE936A1A16581DAE59D6FC5A43A2D75FB56A07FB1A47EAD34551340B6E5E905";

fn control() {
    let (ek, dk) = expand_key(&hex(D), &hex(Z)).unwrap();
    let mut h = oxicrypt_sha::sha256::Sha256::new().unwrap();
    h.update(&ek);
    h.update(&dk);
    assert_eq!(h.finalize().unwrap(), hex::<32>(KEY_HASH));
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
    );
}
