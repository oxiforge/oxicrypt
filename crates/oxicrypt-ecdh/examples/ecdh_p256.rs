//! ECDH P-256 key agreement: Alice and Bob each derive a shared secret.
//!
//! Run: `cargo run -p oxicrypt-ecdh --example ecdh_p256`
#![allow(clippy::expect_used, clippy::print_stdout)]

fn main() {
    oxicrypt_module::initialize().expect("module init");

    // Both parties need ECDSA keypairs for the P-256 curve.
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
    drbg.instantiate(&[0xEE; 32], &[0xFF; 16], b"ecdh-example")
        .expect("drbg instantiate");

    let alice = oxicrypt_ecdsa::EcdsaP256PrivateKey::generate(&mut drbg).expect("alice keygen");
    let bob = oxicrypt_ecdsa::EcdsaP256PrivateKey::generate(&mut drbg).expect("bob keygen");

    println!("Alice pub: {}...", hex(&alice.public_key()[..24]));
    println!("Bob pub:   {}...", hex(&bob.public_key()[..24]));

    // Each side computes the shared secret from their private scalar
    // and the other party's public key.
    let secret_ab =
        oxicrypt_ecdh::compute_shared_secret_p256(alice.private_scalar(), &bob.public_key())
            .expect("ecdh alice->bob");

    let secret_ba =
        oxicrypt_ecdh::compute_shared_secret_p256(bob.private_scalar(), &alice.public_key())
            .expect("ecdh bob->alice");

    assert_eq!(secret_ab, secret_ba, "shared secrets must match");
    println!("Shared:    {}", hex(&secret_ab));
    println!("Match:     OK");
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
