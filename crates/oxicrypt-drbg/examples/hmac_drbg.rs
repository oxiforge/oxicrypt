//! Generate random bytes with HMAC_DRBG-SHA-256.
//!
//! Run: `cargo run -p oxicrypt-drbg --example hmac_drbg`
#![allow(clippy::expect_used, clippy::print_stdout)]

fn main() {
    oxicrypt_module::initialize().expect("module init");

    // In production, entropy comes from the OS. For this example
    // we use a fixed seed so the output is reproducible.
    let entropy = [0xAA; 32];
    let nonce = [0xBB; 16];

    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(&entropy, &nonce, b"example-personalization")
        .expect("drbg instantiate");

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
