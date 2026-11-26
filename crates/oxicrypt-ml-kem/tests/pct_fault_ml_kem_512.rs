//! A failed pairwise consistency test of ML-KEM-512 key generation, through
//! each of `keygen`, `keygen_with_seed` and `expand_key`, returns
//! `ConditionalTestFailed` and leaves the module in its error state
//! (FIPS 140-3 IG 10.3.A).

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_ml_kem::ml_kem_512::{expand_key, keygen, keygen_with_seed};
use pct_fault::{FixedRbg, hex};

/// The seeds d and z, and SHA2-256(ek ‖ dk) of the expected pair, of NIST
/// ACVP-Server `ML-KEM-keyGen-FIPS203` internalProjection, tgId 1, tcId 1.
const D: &str = "BBA3C0F5DF044CDF4D9CAA53CA15FDE26F34EB3541555CFC54CA9C31B964D0C8";
const Z: &str = "0A64FDD51A8D91B3166C4958A94EFC3166A4F5DF680980B878DB8371B7624C96";
const KEY_HASH: &str = "1C2119F3B26A3738E699857BF4F9D89711266410CB5A4C89728FB9C41C38E377";

fn control() {
    let (ek, dk) = expand_key(&hex(D), &hex(Z)).unwrap();
    let mut h = oxicrypt_sha::sha256::Sha256::new().unwrap();
    h.update(&ek);
    h.update(&dk);
    assert_eq!(h.finalize().unwrap(), hex::<32>(KEY_HASH));
}

#[test]
fn pct_fault_ml_kem_512() {
    pct_fault::run(
        "pct_fault_ml_kem_512",
        "ML-KEM-512 pairwise consistency",
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
