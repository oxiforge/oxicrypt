//! Compute HMAC-SHA-256 over a message.
//!
//! Run: `cargo run -p oxicrypt-hmac --example hmac_sha256`
#![allow(clippy::expect_used, clippy::print_stdout)]

use oxicrypt_sha::Sha256;
use oxicrypt_sha::sha256::{BLOCK_SIZE, DIGEST_SIZE};

/// Stands in for the pre-operational integrity test.
///
/// A `cargo run --example` binary is never signed, so the real integrity
/// test cannot pass inside one. The module requires an integrity group to
/// initialise at all, so this example declares this stub — visibly, at
/// the call site — rather than the module offering any way to skip the
/// requirement.
const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
    name: "integrity not verifiable in an unsigned example binary",
    run: || Ok(()),
}];

fn main() {
    oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).expect("module init");

    let key = b"my-secret-hmac-key-for-demo!!!!"; // 31 bytes — any length works
    let message = b"Authenticate this message";

    let mut mac =
        oxicrypt_hmac::Hmac::<Sha256, BLOCK_SIZE, DIGEST_SIZE>::new(key).expect("hmac new");
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
