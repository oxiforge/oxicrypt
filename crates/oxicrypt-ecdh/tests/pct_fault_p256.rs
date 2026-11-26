//! A failed pairwise consistency test of ECDH P-256 key generation, through
//! `generate_keypair_p256`, returns `ConditionalTestFailed` and leaves the
//! module in its error state (ISO/IEC 19790 §7.10.3.3, FIPS 140-3 IG 10.3.A).

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_ecdh::{
    PUBLIC_KEY_LEN, SHARED_SECRET_LEN, compute_shared_secret_p256, generate_keypair_p256,
};
use pct_fault::module_drbg;

/// Two unfaulted pairs agree on their shared secret.
fn control() {
    let (d_a, q_a) = generate_keypair_p256(&mut module_drbg()).unwrap();
    let (d_b, q_b) = generate_keypair_p256(&mut module_drbg()).unwrap();
    assert_eq!(q_a.len(), PUBLIC_KEY_LEN);
    let z_ab = compute_shared_secret_p256(&d_a, &q_b).unwrap();
    let z_ba = compute_shared_secret_p256(&d_b, &q_a).unwrap();
    assert_eq!(z_ab, z_ba);
    assert_ne!(z_ab, [0; SHARED_SECRET_LEN]);
}

#[test]
fn pct_fault_p256() {
    pct_fault::run(
        "pct_fault_p256",
        "ECDH P-256 pairwise consistency",
        control,
        &[("generate_keypair_p256", || {
            generate_keypair_p256(&mut module_drbg()).map(drop)
        })],
        1,
    );
}
