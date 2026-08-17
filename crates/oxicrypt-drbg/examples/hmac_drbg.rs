//! Generate random bytes with HMAC_DRBG-SHA-256.
//!
//! Run: `cargo run -p oxicrypt-drbg --example hmac_drbg`
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

    // In production, entropy comes from the OS. For this example
    // we use a fixed seed so the output is reproducible.
    let entropy = [0xAA; 32];
    let nonce = [0xBB; 16];

    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(&entropy, &nonce, b"example-personalization")
        .expect("drbg instantiate - module gating failed");

    let mut output = [0u8; 32];
    drbg.generate(None, &mut output).expect("drbg generate");

    println!("Entropy: {}", hex(&entropy));
    println!("Nonce:   {}", hex(&nonce));
    println!("Output:  {}", hex(&output));
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
