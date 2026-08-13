//! Shared helpers for oxicrypt benchmarks.
//!
//! This crate ships no benches of its own. Each `[[bench]]` target
//! links it and imports what it needs.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    missing_docs
)]

/// Initialise the FIPS module with the SHA, HMAC, AES, DRBG, ECDSA,
/// EdDSA, ECDH and KDF KATs. The PQ, LMS, XMSS and RSA crates export
/// `KATS` too and are deliberately not loaded here.
///
/// Call once before any benchmark function that touches gated API.
pub fn init_module() {
    let all_kats: Vec<oxicrypt_module::KatEntry> = [
        oxicrypt_sha::KATS,
        oxicrypt_hmac::KATS,
        oxicrypt_aes::KATS,
        oxicrypt_drbg::KATS,
        oxicrypt_ecdsa::KATS,
        oxicrypt_eddsa::KATS,
        oxicrypt_ecdh::KATS,
        oxicrypt_kdf::KATS,
    ]
    .iter()
    .flat_map(|s| s.iter().copied())
    .collect();

    // Ignore AlreadyInitialized — multiple benchmark groups share
    // the same process.
    let _ = oxicrypt_module::initialize_with_tests(&all_kats);
}
