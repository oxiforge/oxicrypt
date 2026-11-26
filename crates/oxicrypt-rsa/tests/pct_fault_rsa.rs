//! A failed pairwise consistency test of RSA key generation, through the
//! `generate` of RSA-2048, RSA-3072 and RSA-4096, returns
//! `ConditionalTestFailed` and leaves the module in its error state
//! (ISO/IEC 19790 §7.10.3.3, FIPS 140-3 IG 10.3.A).

#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/pct_fault.rs"]
mod pct_fault;

use oxicrypt_rsa::rsa3072::RsaPrivateKey3072;
use oxicrypt_rsa::rsa4096::RsaPrivateKey4096;
use oxicrypt_rsa::{RsaPrivateKey2048, rsa_pkcs1_v15_verify_2048_sha256, rsa3072, rsa4096};
use pct_fault::module_drbg;

/// An unfaulted key of each size signs, and its public key verifies the
/// signature. Each verification returns `Result<(), Error>`, `Ok` only for
/// a valid signature.
fn control() {
    let key = RsaPrivateKey2048::generate(&mut module_drbg(), 65537).unwrap();
    let sig = key.sign_pkcs1_v15_sha256(b"control").unwrap();
    assert_eq!(
        rsa_pkcs1_v15_verify_2048_sha256(
            key.modulus_bytes().unwrap(),
            key.public_exponent().unwrap(),
            b"control",
            &sig,
        ),
        Ok(())
    );

    let key = RsaPrivateKey3072::generate(&mut module_drbg(), 65537).unwrap();
    let sig = key.sign_pkcs1_v15_sha256(b"control").unwrap();
    assert_eq!(
        rsa3072::pkcs1_v15_verify(
            key.modulus_bytes().unwrap(),
            key.public_exponent().unwrap(),
            b"control",
            &sig,
        ),
        Ok(())
    );

    let key = RsaPrivateKey4096::generate(&mut module_drbg(), 65537).unwrap();
    let sig = key.sign_pkcs1_v15_sha256(b"control").unwrap();
    assert_eq!(
        rsa4096::pkcs1_v15_verify(
            key.modulus_bytes().unwrap(),
            key.public_exponent().unwrap(),
            b"control",
            &sig,
        ),
        Ok(())
    );
}

#[test]
fn pct_fault_rsa() {
    pct_fault::run(
        "pct_fault_rsa",
        "RSA pairwise consistency",
        control,
        &[
            ("RsaPrivateKey2048::generate", || {
                RsaPrivateKey2048::generate(&mut module_drbg(), 65537).map(drop)
            }),
            ("RsaPrivateKey3072::generate", || {
                RsaPrivateKey3072::generate(&mut module_drbg(), 65537).map(drop)
            }),
            ("RsaPrivateKey4096::generate", || {
                RsaPrivateKey4096::generate(&mut module_drbg(), 65537).map(drop)
            }),
        ],
        3,
    );
}
