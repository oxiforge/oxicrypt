//! Calls one function of each wrapped service and prints what it returned.
//!
//! Build against a signed library (see the crate documentation) and run:
//!
//! ```text
//! OXICRYPT_LIB_DIR=<dir> OXICRYPT_LIB_FINGERPRINT=sha256:<…> \
//!     cargo run -p oxicrypt --example quickstart
//! ```
//!
//! The profile is `Unrestricted`, because the CNSA 2.0 profile does not
//! permit HMAC_DRBG-SHA-256. The DRBG is seeded by the module from its own
//! entropy source.

#![allow(clippy::print_stdout)]

#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use oxicrypt::{DrbgKind, Module, Profile};

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

    let key = module.aes_gcm_key(&[7u8; 32])?;
    let mut iv_drbg = module.drbg(DrbgKind::HmacSha512)?;
    iv_drbg.instantiate(b"quickstart gcm")?;
    let (ciphertext, sealed) = module.aes_gcm_seal_vec(&key, &mut iv_drbg, b"aad", b"hello")?;
    let plaintext = module.aes_gcm_open_vec(&key, &sealed.iv, b"aad", &ciphertext, &sealed.tag)?;
    println!("aes-256-gcm round trip: {}", plaintext == b"hello");
    let mut bad_tag = sealed.tag;
    bad_tag[0] ^= 1;
    let refused = module.aes_gcm_open_vec(&key, &sealed.iv, b"aad", &ciphertext, &bad_tag);
    println!("aes-256-gcm modified tag: {:?}", refused.err());
    println!("aes-gcm invocations: {}", module.aes_gcm_invocations(&key)?);

    let ccm = module.aes_ccm_key(&[8u8; 32], 16)?;
    let (mut ccm_ct, mut ccm_tag, mut ccm_opened) = ([0u8; 5], [0u8; 16], [0u8; 5]);
    module.aes_ccm_seal(
        &ccm,
        &[9u8; 13],
        b"aad",
        b"hello",
        &mut ccm_ct,
        &mut ccm_tag,
    )?;
    module.aes_ccm_open(&ccm, &[9u8; 13], b"aad", &ccm_ct, &ccm_tag, &mut ccm_opened)?;
    println!("aes-256-ccm round trip: {}", &ccm_opened == b"hello");

    let block = [3u8; 32];
    let mut out = [0u8; 32];
    module.aes_cbc_encrypt(
        &module.aes_cbc_key(&[4u8; 32])?,
        &[5u8; 16],
        &block,
        &mut out,
    )?;
    println!("aes-256-cbc: {}", hex(&out[..16]));
    module.aes_ctr(
        &module.aes_ctr_key(&[4u8; 32])?,
        &[6u8; 16],
        &block,
        &mut out,
    )?;
    println!("aes-256-ctr: {}", hex(&out[..16]));

    let kek = module.aes_kw_key(&[7u8; 32])?;
    let mut wrapped = [0u8; 40];
    module.aes_kw_wrap(&kek, &block, &mut wrapped)?;
    let mut unwrapped = [0u8; 32];
    module.aes_kw_unwrap(&kek, &wrapped, &mut unwrapped)?;
    println!("aes-256-kw round trip: {}", unwrapped == block);
    let n = module.aes_kwp_wrap(&kek, b"hello", &mut wrapped)?;
    println!("aes-256-kwp: {n} bytes wrapped");

    let cmac = module.aes_cmac_key(&[2u8; 32], 16)?;
    let mut mac = [0u8; 16];
    module.aes_cmac(&cmac, b"message", &mut mac)?;
    module.aes_cmac_verify(&cmac, b"message", &mac)?;
    println!("aes-256-cmac: {}", hex(&mac));

    println!("entropy source: {}", module.entropy_on_demand_test()?);
    let mut drbg = module.drbg(DrbgKind::HmacSha256)?;
    drbg.instantiate(b"quickstart")?;
    drbg.reseed(&[])?;
    println!("hmac_drbg-sha256: {} bits", drbg.strength_bits()?);

    let (pk, sk) = module.ml_dsa_87_keygen(&mut drbg)?;
    let sig = module.ml_dsa_87_sign(&sk, b"message", b"")?;
    module.ml_dsa_87_verify(&pk, b"message", b"", &sig)?;
    println!("ml-dsa-87: signature verified");
    let wrong = module.ml_dsa_87_verify(&pk, b"other message", b"", &sig);
    println!("ml-dsa-87 other message: {:?}", wrong.err());
    let (pk, _, seed) = module.ml_dsa_87_keygen_with_seed(&mut drbg)?;
    let (again, _) = module.ml_dsa_87_expand_key(&seed)?;
    println!("ml-dsa-87: expand_key reproduces the key: {}", again == pk);

    let (ek, dk) = module.ml_kem_1024_keygen(&mut drbg)?;
    let (sent, ct) = module.ml_kem_1024_encapsulate(&ek, &mut drbg)?;
    let received = module.ml_kem_1024_decapsulate(&dk, &ct)?;
    println!(
        "ml-kem-1024: shared secrets agree: {}",
        sent.as_bytes() == received.as_bytes()
    );
    let mut weak = module.drbg(DrbgKind::CtrAes128)?;
    weak.instantiate(b"quickstart")?;
    let refused = module.ml_kem_1024_keygen(&mut weak);
    println!("ml-kem-1024 with ctr_drbg-aes128: {:?}", refused.err());
    Ok(())
}

#[cfg(not(any(oxicrypt_pinned, oxicrypt_unpinned)))]
fn main() {
    println!("built without a library; set OXICRYPT_LIB_DIR and a fingerprint");
}
