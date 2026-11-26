//! Quickstart: Symmetric encryption. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_aes::{GcmKey, gcm_encrypt};
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_integrity::KATS, oxicrypt_aes::KATS).unwrap();
    let key = GcmKey::new(&[0u8; 32]).unwrap(); // use a real key
    let mut drbg = HmacDrbgSha256::instantiate_from_module(b"").unwrap();
    let plaintext = b"hello, world!   ";
    let mut ciphertext = [0u8; 16];
    // The IV is drawn from `drbg`; send it with the ciphertext and tag.
    let sealed = gcm_encrypt(&key, &mut drbg, b"", plaintext, &mut ciphertext).unwrap();
    assert_ne!(ciphertext, *plaintext);
    assert_eq!(sealed.iv.len(), 12);
}
