//! Quickstart: Symmetric encryption. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_aes::{Aes256Key, gcm_encrypt};
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_aes::KATS).unwrap();
    let key = Aes256Key::new(&[0u8; 32]).unwrap(); // use a real key
    let iv = [0u8; 12]; // a nonce must never repeat under one key
    let plaintext = b"hello, world!   ";
    let mut ciphertext = [0u8; 16];
    let mut tag = [0u8; 16];
    gcm_encrypt(&key, &iv, b"", plaintext, &mut ciphertext, &mut tag).unwrap();
    assert_ne!(ciphertext, *plaintext);
}
