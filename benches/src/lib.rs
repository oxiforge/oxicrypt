//! Shared helpers for oxicrypt benchmarks.
//!
//! This crate is never compiled directly; each `[[bench]]` target
//! imports what it needs.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    missing_docs
)]

/// Initialise the FIPS module with KATs from every algorithm crate.
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
