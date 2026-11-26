//! AES-256-GCM authenticated encryption and decryption.
//!
//! Run: `cargo run -p oxicrypt-aes --example aes_gcm`
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

/// A demonstration generator. It is not a random bit generator and not an
/// approved source.
///
/// Its output is a counter, so the IV repeats on every run, and the 256
/// bits it reports exist only to pass the strength check. `oxicrypt-drbg`
/// depends on this crate, so this crate's examples cannot use it. A
/// program uses an `oxicrypt-drbg` type instead, such as
/// `HmacDrbgSha256::instantiate_from_module(b"")`.
struct DemoRbg(u8);

impl oxicrypt_module::Rbg for DemoRbg {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), oxicrypt_module::RbgError> {
        for b in out {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }

    fn strength_bits(&self) -> u32 {
        256
    }
}

fn main() {
    oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).expect("module init");

    let key = [0x42u8; 32]; // 256-bit key (demo only!)
    let mut drbg = DemoRbg(1);
    let aad = b"additional authenticated data";
    let plaintext = b"Secrets worth protecting";

    let cipher = oxicrypt_aes::GcmKey::new(&key).expect("valid key");
    let mut ciphertext = vec![0u8; plaintext.len()];
    // The IV is drawn from the generator passed in and returned with the tag.
    let sealed = oxicrypt_aes::gcm_encrypt(&cipher, &mut drbg, aad, plaintext, &mut ciphertext)
        .expect("gcm encrypt");

    println!(
        "Plaintext:  {:?}",
        std::str::from_utf8(plaintext).expect("utf8")
    );
    println!("Ciphertext: {}", hex(&ciphertext));
    println!("IV:         {}", hex(&sealed.iv));
    println!("Tag:        {}", hex(&sealed.tag));

    let mut recovered = vec![0u8; ciphertext.len()];
    oxicrypt_aes::gcm_decrypt(
        &cipher,
        &sealed.iv,
        aad,
        &ciphertext,
        &sealed.tag,
        &mut recovered,
    )
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
