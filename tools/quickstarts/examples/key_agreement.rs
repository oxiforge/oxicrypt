//! Quickstart: Key agreement. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_ecdh::{compute_shared_secret_p256, generate_keypair_p256};
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_integrity::KATS, oxicrypt_ecdh::KATS).unwrap();
    let mut rng = HmacDrbgSha256::new();
    rng.instantiate(&[0xABu8; 32], &[0xCDu8; 16], b"").unwrap();
    // Each party keeps d and publishes Q.
    let (alice_d, alice_q) = generate_keypair_p256(&mut rng).unwrap();
    let (bob_d, bob_q) = generate_keypair_p256(&mut rng).unwrap();
    let alice_shared = compute_shared_secret_p256(&alice_d, &bob_q).unwrap();
    let bob_shared = compute_shared_secret_p256(&bob_d, &alice_q).unwrap();
    assert_eq!(alice_shared, bob_shared);
}
