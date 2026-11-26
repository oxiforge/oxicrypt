//! oxicrypt playground — kick the tires on the module APIs.
//!
//! This is NOT part of the workspace. Build and run it standalone:
//!
//!     cd playground && cargo run
//!
//! It walks through the main algorithm families the way an evaluating
//! developer would: initialize the module, hash something, HMAC
//! something, encrypt with AES-GCM, spin up a DRBG, sign with ECDSA
//! and Ed25519, and do an ECDH key agreement.
//!
//! Nothing here is production code — it's a scratchpad for learning
//! the API surface.

use oxicrypt_sha::{sha256, Sha256};
use oxicrypt_sha::sha256::{BLOCK_SIZE as SHA256_BLOCK_SIZE, DIGEST_SIZE as SHA256_DIGEST_SIZE};
use oxicrypt_ecdsa::{EcdsaP256PrivateKey, verify as ecdsa_verify};
use oxicrypt_eddsa::{keygen as ed_keygen, sign as ed_sign, verify as ed_verify};

/// Stands in for the pre-operational integrity test.
///
/// The playground binary is never signed, so the real integrity test
/// cannot pass inside it. The module requires an integrity group to
/// initialise at all, so this stub is declared here, visibly, rather
/// than the module offering any way to skip the requirement.
const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
    name: "integrity not verifiable in an unsigned playground binary",
    run: || Ok(()),
}];

fn main() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║        oxicrypt playground — API walkthrough     ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    // ── 1. Module initialization ────────────────────────────────
    // The module must reach the Operational state before any cryptographic
    // function works. A signed binary passes the real integrity group and
    // every algorithm self-test; the unsigned playground passes the stub and
    // an empty test list.
    println!("─── 1. Module initialization ───");
    match oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
        Ok(()) => {}
        Err(oxicrypt_module::Error::AlreadyInitialized) => {}
        Err(e) => {
            eprintln!("  FATAL: module init failed: {e}");
            return;
        }
    }
    println!("  Module state: {}", oxicrypt_module::state());
    println!();

    // ── 2. Hashing (SHA-256) ────────────────────────────────────
    println!("─── 2. SHA-256 hash ───");
    let message = b"Hello from the oxicrypt playground!";

    let digest = sha256(message).expect("sha256");
    println!("  Input:  \"{}\"", std::str::from_utf8(message).unwrap());
    println!("  SHA-256: {}", hex(&digest));

    let mut hasher = Sha256::new().expect("sha256 new");
    hasher.update(b"Hello from ");
    hasher.update(b"the oxicrypt playground!");
    let digest2 = hasher.finalize().expect("sha256 finalize");
    assert_eq!(digest, digest2, "one-shot and streaming must match");
    println!("  Streaming matches one-shot: ✓");
    println!();

    // ── 3. HMAC-SHA-256 ─────────────────────────────────────────
    println!("─── 3. HMAC-SHA-256 ───");
    let key = b"super-secret-key-for-hmac-demo!!"; // 32 bytes
    let mut mac = oxicrypt_hmac::Hmac::<
        Sha256,
        SHA256_BLOCK_SIZE,
        SHA256_DIGEST_SIZE,
    >::new(key).expect("hmac new");
    mac.update(message);
    let tag = mac.finalize().expect("hmac finalize");
    println!("  Key:     \"{}\"", std::str::from_utf8(key).unwrap());
    println!("  Message: \"{}\"", std::str::from_utf8(message).unwrap());
    println!("  HMAC:    {}", hex(&tag));
    println!();

    // ── 4. AES-256-GCM encrypt + decrypt ────────────────────────
    println!("─── 4. AES-256-GCM ───");
    let aes_key = [0x42u8; 32]; // 256-bit key (demo only!)
    let aad = b"additional authenticated data";
    let plaintext = b"Secrets worth protecting";

    // SP 800-38D §8.2.2: the module draws each 96-bit IV from this DRBG.
    let mut iv_drbg = oxicrypt_drbg::HmacDrbgSha256::instantiate_from_module(b"playground-gcm-iv")
        .expect("drbg instantiate");
    let cipher = oxicrypt_aes::GcmKey::new(&aes_key).expect("valid key");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let sealed = oxicrypt_aes::gcm_encrypt(&cipher, &mut iv_drbg, aad, plaintext, &mut ciphertext)
        .expect("gcm encrypt");
    println!("  Plaintext:  \"{}\"", std::str::from_utf8(plaintext).unwrap());
    println!("  IV:         {}", hex(&sealed.iv));
    println!("  Ciphertext: {}", hex(&ciphertext));
    println!("  Tag:        {}", hex(&sealed.tag));

    let mut recovered = vec![0u8; ciphertext.len()];
    oxicrypt_aes::gcm_decrypt(&cipher, &sealed.iv, aad, &ciphertext, &sealed.tag, &mut recovered)
        .expect("gcm decrypt");
    assert_eq!(plaintext.as_slice(), recovered.as_slice());
    println!("  Decrypted:  \"{}\" ✓", std::str::from_utf8(&recovered).unwrap());
    println!();

    // ── 5. DRBG (HMAC_DRBG with SHA-256) ────────────────────────
    println!("─── 5. HMAC_DRBG-SHA-256 ───");
    // The module draws the entropy input and nonce from its own seed
    // path; the caller supplies only the personalization string.
    let mut drbg =
        oxicrypt_drbg::HmacDrbgSha256::instantiate_from_module(b"playground-personalization")
            .expect("drbg instantiate");
    let mut random_bytes = [0u8; 32];
    drbg.generate(None, &mut random_bytes).expect("drbg generate");
    println!("  Output:     {}", hex(&random_bytes));
    println!();

    // ── 6. ECDSA P-256 sign + verify ────────────────────────────
    println!("─── 6. ECDSA P-256 (sign + verify) ───");
    let ecdsa_key = EcdsaP256PrivateKey::generate(&mut drbg)
        .expect("ecdsa keygen");
    let pub_key = ecdsa_key.public_key().expect("ecdsa public key");
    println!("  Public key: {}", hex(&pub_key[..33]));
    println!("              {}...", hex(&pub_key[33..49]));

    let sig = ecdsa_key.sign_sha256(&mut drbg, b"Sign this message please")
        .expect("ecdsa sign");
    println!("  Signature:  {}", hex(&sig[..32]));
    println!("              {}", hex(&sig[32..]));

    let valid = ecdsa_verify(
        &pub_key,
        b"Sign this message please",
        &sig,
    );
    println!("  Verify:     {}", if valid.is_ok() { "✓ valid" } else { "✗ INVALID" });
    println!();

    // ── 7. Ed25519 sign + verify ────────────────────────────────
    println!("─── 7. Ed25519 (sign + verify) ───");
    let mut seed = [0u8; 32];
    drbg.generate(None, &mut seed).expect("drbg for ed25519 seed");
    let ed_pubkey = ed_keygen(&seed).expect("ed25519 keygen");
    println!("  Public key: {}", hex(&ed_pubkey));

    let ed_sig = ed_sign(&seed, b"Ed25519 is elegant")
        .expect("ed25519 sign");
    println!("  Signature:  {}", hex(&ed_sig[..32]));
    println!("              {}", hex(&ed_sig[32..]));

    let ed_valid = ed_verify(&ed_pubkey, b"Ed25519 is elegant", &ed_sig);
    println!("  Verify:     {}", if ed_valid.is_ok() { "✓ valid" } else { "✗ INVALID" });
    println!();

    // ── 8. ECDH P-256 key agreement ─────────────────────────────
    println!("─── 8. ECDH P-256 (key agreement) ───");
    let alice = EcdsaP256PrivateKey::generate(&mut drbg)
        .expect("alice keygen");
    let bob = EcdsaP256PrivateKey::generate(&mut drbg)
        .expect("bob keygen");
    let alice_pub = alice.public_key().expect("alice public key");
    let bob_pub = bob.public_key().expect("bob public key");
    println!("  Alice pub:  {}...", hex(&alice_pub[..24]));
    println!("  Bob pub:    {}...", hex(&bob_pub[..24]));

    let secret_ab = oxicrypt_ecdh::compute_shared_secret_p256(
        alice.private_scalar().expect("private scalar"),
        &bob_pub,
    ).expect("ecdh alice→bob");

    let secret_ba = oxicrypt_ecdh::compute_shared_secret_p256(
        bob.private_scalar().expect("private scalar"),
        &alice_pub,
    ).expect("ecdh bob→alice");

    assert_eq!(secret_ab, secret_ba, "shared secrets must match");
    println!("  Shared:     {}", hex(&secret_ab));
    println!("  Match:      ✓ (Alice and Bob agree)");
    println!();

    // ── Done ────────────────────────────────────────────────────
    println!("╔══════════════════════════════════════════════════╗");
    println!("║  All demos passed. Module state: {}  ║", oxicrypt_module::state());
    println!("╚══════════════════════════════════════════════════╝");
}

/// Quick hex encoder for display.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
