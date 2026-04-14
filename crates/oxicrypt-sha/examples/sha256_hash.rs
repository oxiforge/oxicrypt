//! Hash a message with SHA-256 using both the one-shot function and the
//! streaming API, then verify they produce the same digest.
//!
//! Run: `cargo run -p oxicrypt-sha --example sha256_hash`
#![allow(clippy::expect_used, clippy::print_stdout)]

fn main() {
    // Module must be initialized before any crypto operation.
    oxicrypt_module::initialize().expect("module init");

    let message = b"Hello, oxicrypt!";

    // One-shot convenience function:
    let digest = oxicrypt_sha::sha256(message).expect("sha256");
    println!("SHA-256 (one-shot):  {}", hex(&digest));

    // Streaming API (useful for large inputs):
    let mut hasher = oxicrypt_sha::Sha256::new().expect("sha256 new");
    hasher.update(b"Hello, ");
    hasher.update(b"oxicrypt!");
    let digest2 = hasher.finalize();
    println!("SHA-256 (streaming): {}", hex(&digest2));

    assert_eq!(digest, digest2, "one-shot and streaming must match");
    println!("Match: OK");
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
