//! Quickstart: Random number generation. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_integrity::KATS, oxicrypt_drbg::KATS).unwrap();
    let mut rng = HmacDrbgSha256::new();
    // Both values must come from a real entropy source in production.
    rng.instantiate(&[0xABu8; 32], &[0xCDu8; 16], b"").unwrap();
    let mut output = [0u8; 32];
    rng.generate(None, &mut output).unwrap();
    assert_ne!(output, [0u8; 32]);
}
