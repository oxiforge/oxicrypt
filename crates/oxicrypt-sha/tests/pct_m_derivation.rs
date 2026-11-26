//! `oxicrypt_module::PCT_M` is the SHA-256 digest of the ASCII bytes of
//! `oxicrypt pairwise consistency m`, as its rustdoc states.

#![allow(clippy::unwrap_used)]

use oxicrypt_module::{KatEntry, PCT_M, initialize_with_tests};

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

#[test]
fn pct_m_is_the_sha256_of_its_domain_string() {
    initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap();
    let digest = oxicrypt_sha::sha256::sha256(b"oxicrypt pairwise consistency m").unwrap();
    assert_eq!(digest, PCT_M);
    // Control: a one-byte change to the domain string gives another digest.
    let other = oxicrypt_sha::sha256::sha256(b"oxicrypt pairwise consistency n").unwrap();
    assert_ne!(other, PCT_M);
}
