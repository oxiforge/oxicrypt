//! HKDF-Expand at its maximum length, 255 blocks (RFC 5869 §2.3).
//!
//! The block counter is a single byte, so the 255th block is the last one
//! it can number. This test requires the expansion to finish at that length
//! with the length RFC 5869 defines, to compute that last block as the RFC
//! does, and to refuse one byte more.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use oxicrypt_kdf::{HkdfSha256, KdfError};
use oxicrypt_module::{KatEntry, initialize_with_tests};

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// SHA-256 output length, `HashLen` in RFC 5869.
const L: usize = 32;

#[test]
fn hkdf_sha256_expands_to_255_blocks_and_refuses_more() {
    initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap();
    let hkdf = HkdfSha256::extract(Some(b"salt"), b"input keying material").unwrap();
    let info = b"max-length";

    let mut okm = vec![0u8; 255 * L];
    hkdf.expand(info, &mut okm).unwrap();
    assert_eq!(okm.len(), 255 * L);

    // T(255) = HMAC-Hash(PRK, T(254) || info || 0xff), from RFC 5869 §2.3.
    let mut mac = oxicrypt_hmac::HmacSha256::new(hkdf.prk().unwrap()).unwrap();
    mac.update(&okm[253 * L..254 * L]);
    mac.update(info);
    mac.update(&[0xff]);
    assert_eq!(&okm[254 * L..], &mac.finalize().unwrap()[..]);

    let mut too_long = vec![0u8; 255 * L + 1];
    assert_eq!(
        hkdf.expand(info, &mut too_long),
        Err(KdfError::OutputTooLong)
    );
}
