//! A failed pairwise consistency test of ECDSA P-256 key generation, through
//! `EcdsaP256PrivateKey::generate`, returns `ConditionalTestFailed` and
//! leaves the module in its error state (ISO/IEC 19790 §7.10.3.3, FIPS 140-3
//! IG 10.3.A).

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_ecdsa::p256_ecdsa::{EcdsaP256PrivateKey, verify};
use pct_fault::module_drbg;

/// An unfaulted pair signs, and its public key verifies the signature.
fn control() {
    let mut drbg = module_drbg();
    let key = EcdsaP256PrivateKey::generate(&mut drbg).unwrap();
    let sig = key.sign_sha256(&mut drbg, b"control").unwrap();
    assert!(verify(&key.public_key().unwrap(), b"control", &sig).unwrap());
}

#[test]
fn pct_fault_p256() {
    pct_fault::run(
        "pct_fault_p256",
        "ECDSA P-256 pairwise consistency",
        control,
        &[("EcdsaP256PrivateKey::generate", || {
            EcdsaP256PrivateKey::generate(&mut module_drbg()).map(drop)
        })],
        1,
    );
}
