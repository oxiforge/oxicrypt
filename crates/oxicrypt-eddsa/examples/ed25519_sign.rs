//! Ed25519: derive a public key from a seed, sign, and verify.
//!
//! Run: `cargo run -p oxicrypt-eddsa --example ed25519_sign`
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
    oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).expect("module init");

    // Ed25519 uses a 32-byte seed (in production, use OS entropy).
    let seed = [0x42u8; 32];

    let public_key = oxicrypt_eddsa::keygen(&seed).expect("ed25519 keygen");
    println!("Public key: {}", hex(&public_key));

    let message = b"Ed25519 is elegant";
    let signature = oxicrypt_eddsa::sign(&seed, message).expect("ed25519 sign");
    println!("Signature:  {}...", hex(&signature[..32]));

    let result = oxicrypt_eddsa::verify(&public_key, message, &signature);
    println!(
        "Verify:     {}",
        if result.is_ok() { "valid" } else { "INVALID" }
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
