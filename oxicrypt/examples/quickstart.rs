//! Calls every wrapped service once and prints what it returned.
//!
//! Build against a signed library (see the crate documentation) and run:
//!
//! ```text
//! OXICRYPT_LIB_DIR=<dir> OXICRYPT_LIB_FINGERPRINT=sha256:<…> \
//!     cargo run -p oxicrypt --example quickstart
//! ```
//!
//! The profile is `Unrestricted`, because the CNSA 2.0 profile does not
//! permit HMAC_DRBG-SHA-256. The DRBG's entropy here is read from the
//! operating system's generator for demonstration; an application documents
//! an entropy source meeting SP 800-90B instead.

#![allow(clippy::print_stdout)]

#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use oxicrypt::{Module, Profile};
    use std::io::Read;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[cfg(oxicrypt_pinned)]
    let module = Module::init(Profile::Unrestricted)?;
    #[cfg(not(oxicrypt_pinned))]
    let module = Module::init_unpinned(Profile::Unrestricted)?;
    println!("library: {:?}", Module::library_path());
    println!("integrity: {:?}", module.integrity_status());
    println!("verifying key: {}", module.key_fingerprint()?);

    println!("sha384(\"abc\") = {}", hex(&module.sha384(b"abc")?));

    let prk = module.hkdf_sha384_extract(Some(b"salt"), b"input key material")?;
    let okm = module.hkdf_sha384_expand(&prk, b"info", 42)?;
    println!("hkdf-sha384: {} bytes", okm.as_bytes().len());

    let key = module.aes256_key(&[7u8; 32])?;
    let nonce = [1u8; 12];
    let (ciphertext, tag) = module.aes256_gcm_encrypt_vec(&key, &nonce, b"aad", b"hello")?;
    let plaintext = module.aes256_gcm_decrypt_vec(&key, &nonce, b"aad", &ciphertext, &tag)?;
    println!("aes-256-gcm round trip: {}", plaintext == b"hello");
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let refused = module.aes256_gcm_decrypt_vec(&key, &nonce, b"aad", &ciphertext, &bad_tag);
    println!("aes-256-gcm modified tag: {:?}", refused.err());

    let mut entropy = [0u8; 48];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let mut drbg = module.hmac_drbg_sha256()?;
    drbg.instantiate(&entropy[..32], &entropy[32..], b"quickstart")?;
    let seed = drbg.seed()?;

    let (pk, sk) = module.ml_dsa_87_keygen(seed)?;
    let sig = module.ml_dsa_87_sign(&sk, b"message", b"")?;
    module.ml_dsa_87_verify(&pk, b"message", b"", &sig)?;
    println!("ml-dsa-87: signature verified");
    let wrong = module.ml_dsa_87_verify(&pk, b"other message", b"", &sig);
    println!("ml-dsa-87 other message: {:?}", wrong.err());

    let (ek, dk) = module.ml_kem_1024_keygen(drbg.seed()?, drbg.seed()?)?;
    let (sent, ct) = module.ml_kem_1024_encapsulate(&ek, drbg.seed()?)?;
    let received = module.ml_kem_1024_decapsulate(&dk, &ct)?;
    println!(
        "ml-kem-1024: shared secrets agree: {}",
        sent.as_bytes() == received.as_bytes()
    );
    Ok(())
}

#[cfg(not(any(oxicrypt_pinned, oxicrypt_unpinned)))]
fn main() {
    println!("built without a library; set OXICRYPT_LIB_DIR and a fingerprint");
}
