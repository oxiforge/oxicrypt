//! Compute HMAC-SHA-256 over a message.
//!
//! Run: `cargo run -p oxicrypt-hmac --example hmac_sha256`
#![allow(clippy::expect_used, clippy::print_stdout)]

use oxicrypt_sha::Sha256;
use oxicrypt_sha::sha256::{BLOCK_SIZE, DIGEST_SIZE};

fn main() {
    oxicrypt_module::initialize().expect("module init");

    let key = b"my-secret-hmac-key-for-demo!!!!"; // 31 bytes — any length works
    let message = b"Authenticate this message";

    let mut mac = oxicrypt_hmac::Hmac::<Sha256, BLOCK_SIZE, DIGEST_SIZE>::new(key)
        .expect("hmac new");
    mac.update(message);
    let tag = mac.finalize();

    println!("Key:     {:?}", std::str::from_utf8(key).expect("utf8"));
    println!("Message: {:?}", std::str::from_utf8(message).expect("utf8"));
    println!("HMAC:    {}", hex(&tag));
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
