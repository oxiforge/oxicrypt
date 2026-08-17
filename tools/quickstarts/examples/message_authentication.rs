//! Quickstart: Message authentication. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_hmac::HmacSha256;
use oxicrypt_module::initialize_with_tests;

fn main() {
    initialize_with_tests(oxicrypt_integrity::KATS, oxicrypt_hmac::KATS).unwrap();
    let mut mac = HmacSha256::new(b"secret-key-at-least-32-bytes-long!!").unwrap();
    mac.update(b"message to authenticate");
    let tag = mac.finalize();
    assert_eq!(tag.len(), 32);
}
