//! Quickstart: Digital signatures. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_eddsa::ed25519::{Ed25519PrivateKey, verify};
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_integrity::KATS, oxicrypt_eddsa::KATS).unwrap();
    let mut rng = HmacDrbgSha256::instantiate_from_module(b"").unwrap();
    let signing_key = Ed25519PrivateKey::generate(&mut rng).unwrap();
    let signature = signing_key.sign(b"message to sign").unwrap();
    assert!(
        verify(
            &signing_key.public_key().unwrap(),
            b"message to sign",
            &signature
        )
        .unwrap()
    );
}
