//! Quickstart: Extendable-output functions (XOF). Carried in lama.yaml; this file is the canonical copy.
use oxicrypt_module::initialize_with_tests;
use oxicrypt_xof::{kmac256, shake256};

fn main() {
    initialize_with_tests(oxicrypt_xof::KATS).unwrap();
    let squeezed: [u8; 32] = shake256(b"input data").unwrap();
    let tag: [u8; 32] = kmac256(b"my-key", b"input", b"").unwrap();
    assert_eq!(squeezed.len(), 32);
    assert_eq!(tag.len(), 32);
}
