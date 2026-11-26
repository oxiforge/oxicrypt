//! A failed pairwise consistency test of Ed25519 key generation, through
//! `Ed25519PrivateKey::generate`, returns `ConditionalTestFailed` and leaves
//! the module in its error state (ISO/IEC 19790 §7.10.3.3, FIPS 140-3
//! IG 10.3.A).

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_eddsa::{Ed25519PrivateKey, verify};
use pct_fault::module_drbg;

/// An unfaulted pair signs, and its public key verifies the signature.
fn control() {
    let key = Ed25519PrivateKey::generate(&mut module_drbg()).unwrap();
    let sig = key.sign(b"control").unwrap();
    assert!(verify(&key.public_key().unwrap(), b"control", &sig).unwrap());
}

#[test]
fn pct_fault_ed25519() {
    pct_fault::run(
        "pct_fault_ed25519",
        "Ed25519 pairwise consistency",
        control,
        &[("Ed25519PrivateKey::generate", || {
            Ed25519PrivateKey::generate(&mut module_drbg()).map(drop)
        })],
        1,
    );
}
