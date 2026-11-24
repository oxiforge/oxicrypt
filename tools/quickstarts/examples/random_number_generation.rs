//! Quickstart: Random number generation. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_integrity::KATS, oxicrypt_drbg::KATS).unwrap();
    // The module draws the entropy input and nonce from its own source.
    let mut rng = HmacDrbgSha256::instantiate_from_module(b"").unwrap();
    let mut output = [0u8; 32];
    rng.generate(None, &mut output).unwrap();
    assert_ne!(output, [0u8; 32]);
}
