//! Hash a message with SHA-256 using both the one-shot function and the
//! streaming API, then verify they produce the same digest.
//!
//! Run: `cargo run -p oxicrypt-sha --example sha256_hash`
#![allow(clippy::expect_used, clippy::print_stdout)]

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
    // Module must be initialized before any crypto operation.
    oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).expect("module init");

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
