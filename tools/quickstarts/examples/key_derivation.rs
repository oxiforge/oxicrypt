//! Quickstart: Key derivation. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_kdf::HkdfSha256;
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_kdf::KATS).unwrap();
    // Extract concentrates the input keying material into a pseudorandom key,
    // then expand derives as many bytes as the caller asks for.
    let hkdf = HkdfSha256::extract(Some(b"optional-salt"), b"input-keying-material").unwrap();
    let mut okm = [0u8; 42];
    hkdf.expand(b"application context", &mut okm).unwrap();
    assert_ne!(okm, [0u8; 42]);
}
