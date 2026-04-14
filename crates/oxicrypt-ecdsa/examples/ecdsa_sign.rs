//! ECDSA P-256: generate a keypair, sign a message, and verify.
//!
//! Run: `cargo run -p oxicrypt-ecdsa --example ecdsa_sign`
#![allow(clippy::expect_used, clippy::print_stdout)]

fn main() {
    oxicrypt_module::initialize().expect("module init");

    // Set up a DRBG for key generation and signing.
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(&[0xCC; 32], &[0xDD; 16], b"ecdsa-example")
        .expect("drbg instantiate");

    // Generate a keypair:
    let private_key = oxicrypt_ecdsa::EcdsaP256PrivateKey::generate(&mut drbg)
        .expect("ecdsa keygen");
    let public_key = private_key.public_key();
    println!("Public key: {}...", hex(&public_key[..32]));

    // Sign:
    let message = b"Sign this message with ECDSA P-256";
    let signature = private_key.sign_sha256(&mut drbg, message)
        .expect("ecdsa sign");
    println!("Signature:  {}...", hex(&signature[..32]));

    // Verify:
    let result = oxicrypt_ecdsa::verify(&public_key, message, &signature);
    println!("Verify:     {}", if result.is_ok() { "valid" } else { "INVALID" });
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
