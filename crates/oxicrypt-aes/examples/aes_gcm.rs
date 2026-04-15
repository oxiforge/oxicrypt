//! AES-256-GCM authenticated encryption and decryption.
//!
//! Run: `cargo run -p oxicrypt-aes --example aes_gcm`
#![allow(clippy::expect_used, clippy::print_stdout)]

fn main() {
    oxicrypt_module::initialize().expect("module init");

    let key = [0x42u8; 32]; // 256-bit key (demo only!)
    let iv = [0x01u8; 12]; // 96-bit IV (use DRBG in production!)
    let aad = b"additional authenticated data";
    let plaintext = b"Secrets worth protecting";

    // Encrypt:
    let cipher = oxicrypt_aes::Aes256Key::new(&key).expect("valid key");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    oxicrypt_aes::gcm_encrypt(&cipher, &iv, aad, plaintext, &mut ciphertext, &mut tag)
        .expect("gcm encrypt");

    println!(
        "Plaintext:  {:?}",
        std::str::from_utf8(plaintext).expect("utf8")
    );
    println!("Ciphertext: {}", hex(&ciphertext));
    println!("Tag:        {}", hex(&tag));

    // Decrypt and verify:
    let mut recovered = vec![0u8; ciphertext.len()];
    oxicrypt_aes::gcm_decrypt(&cipher, &iv, aad, &ciphertext, &tag, &mut recovered)
        .expect("gcm decrypt");

    assert_eq!(plaintext.as_slice(), recovered.as_slice());
    println!(
        "Decrypted:  {:?} (verified)",
        std::str::from_utf8(&recovered).expect("utf8")
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
