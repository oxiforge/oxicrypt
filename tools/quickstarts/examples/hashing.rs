//! Quickstart: Hashing. Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_module::initialize_with_tests;
use oxicrypt_sha::sha256;

fn main() {
    initialize_with_tests(oxicrypt_sha::KATS).unwrap();
    let digest = sha256(b"hello world").unwrap();
    assert_eq!(digest.len(), 32);
}
