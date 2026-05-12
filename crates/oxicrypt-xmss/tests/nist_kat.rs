//! Implementation-derived Known-Answer Tests for XMSS-SHA2_10_256 (SP 800-208).
//!
//! NOTE: Neither RFC 8391 (XMSS) nor the NIST ACVP Server publish official
//! test vectors for XMSS.  These tests use implementation-derived vectors:
//! a fixed seed produces a deterministic key pair, which is then used to
//! sign a fixed message.  The expected public key and signature are stored
//! in `tests/data/` so any inadvertent algorithm change will be caught.
//!
//! The test was bootstrapped by running `cargo test generate_xmss_vectors`
//! (see the `generate` module below), capturing the output, and hardening
//! it into the binary files in `tests/data/`.
//!
//! Reference: SP 800-208 §5.3, RFC 8391 §4.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::similar_names)]

use oxicrypt_xmss::{
    PUBLIC_KEY_LEN, SIGNATURE_LEN, keygen_internal, sign_internal, verify_internal,
};

// ── Vector helpers ──────────────────────────────────────────────────────────

fn load(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
    std::fs::read(format!("{path}{name}")).expect("test data not found")
}

fn load_arr<const N: usize>(name: &str) -> [u8; N] {
    let v = load(name);
    assert_eq!(v.len(), N, "unexpected length for {name}");
    v.try_into().unwrap()
}

// Fixed seed for all XMSS KAT tests.
const KAT_XI: [u8; 32] = [
    0x58, 0x4d, 0x53, 0x53, 0x2d, 0x53, 0x48, 0x41, // "XMSS-SHA"
    0x32, 0x5f, 0x31, 0x30, 0x5f, 0x32, 0x35, 0x36, // "2_10_256"
    0x2d, 0x6f, 0x78, 0x69, 0x63, 0x72, 0x79, 0x70, // "-oxicryp"
    0x74, 0x2d, 0x76, 0x30, 0x2e, 0x30, 0x2e, 0x30, // "t-v0.0.0"
];

// Fixed message for signature KAT tests.
const KAT_MESSAGE: &[u8] = b"XMSS-SHA2_10_256 impl KAT: deterministic sigGen (SP 800-208)";

// ── keyGen KAT ──────────────────────────────────────────────────────────────

/// Implementation-derived XMSS keyGen KAT.
///
/// keygen_internal(KAT_XI) must reproduce the exact public key stored in
/// `tests/data/xmss_sha2_10_256_impl_keygen_pk.bin`.
#[test]
fn impl_keygen_kat() {
    let expected_pk = load_arr::<PUBLIC_KEY_LEN>("xmss_sha2_10_256_impl_keygen_pk.bin");

    let (_sk, pk) = keygen_internal(&KAT_XI);

    assert_eq!(
        pk, expected_pk,
        "XMSS-SHA2_10_256 keyGen: pk does not match implementation-derived vector"
    );
}

// ── sigGen KAT ─────────────────────────────────────────────────────────────

/// Implementation-derived XMSS sigGen KAT.
///
/// sign_internal(sk, KAT_MESSAGE) must reproduce the exact signature
/// stored in `tests/data/xmss_sha2_10_256_impl_sign_sig.bin`.
/// The signature is the first one produced by a freshly keygen'd key
/// (leaf index 0), making it fully deterministic.
#[test]
fn impl_siggen_kat() {
    let expected_sig = load_arr::<SIGNATURE_LEN>("xmss_sha2_10_256_impl_sign_sig.bin");

    let (mut sk, pk) = keygen_internal(&KAT_XI);
    let sig =
        sign_internal(&mut sk, KAT_MESSAGE).expect("sign_internal returned None (key exhausted?)");

    assert_eq!(
        sig, expected_sig,
        "XMSS-SHA2_10_256 sigGen: signature does not match implementation-derived vector"
    );

    // Also verify the stored signature as a cross-check.
    assert!(
        verify_internal(&pk, KAT_MESSAGE, &expected_sig),
        "XMSS-SHA2_10_256: verify_internal rejected stored implementation-derived signature"
    );
}

// ── Round-trip ──────────────────────────────────────────────────────────────

/// XMSS sign + verify round-trip with the KAT seed.
///
/// Confirms that a message signed with the KAT key verifies correctly, and
/// that a tampered signature fails.
#[test]
fn impl_sign_verify_roundtrip() {
    let (mut sk, pk) = keygen_internal(&KAT_XI);

    let message = b"XMSS-SHA2_10_256 impl KAT: sign+verify round-trip (SP 800-208)";

    let sig =
        sign_internal(&mut sk, message).expect("sign_internal returned None (key exhausted?)");

    assert_eq!(sig.len(), SIGNATURE_LEN);

    assert!(
        verify_internal(&pk, message, &sig),
        "XMSS round-trip: verify_internal rejected valid signature"
    );

    // Tampered message must fail.
    assert!(
        !verify_internal(&pk, b"tampered", &sig),
        "XMSS round-trip: verify_internal accepted tampered message"
    );

    // Tampered signature must fail.
    let mut bad_sig = sig;
    bad_sig[64] ^= 0x01;
    assert!(
        !verify_internal(&pk, message, &bad_sig),
        "XMSS round-trip: verify_internal accepted tampered signature"
    );
}

// ── Vector generator ────────────────────────────────────────────────────────

/// Generate the implementation-derived vectors and write them to
/// `tests/data/`.  Run once to bootstrap; not included in normal test
/// runs (marked `#[ignore]`).
#[test]
#[ignore = "one-shot vector generator, run manually to (re)create tests/data/"]
#[allow(clippy::print_stdout, clippy::use_debug)]
fn generate_xmss_vectors() {
    let (mut sk, pk) = keygen_internal(&KAT_XI);

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(format!("{path}xmss_sha2_10_256_impl_keygen_pk.bin"), pk).unwrap();

    // Also generate a signature vector for the fixed message.
    let sig =
        sign_internal(&mut sk, KAT_MESSAGE).expect("sign_internal failed on freshly generated key");
    std::fs::write(format!("{path}xmss_sha2_10_256_impl_sign_sig.bin"), sig).unwrap();

    println!("Generated XMSS vectors in {path}");
    let hex: String = pk
        .iter()
        .flat_map(|b| {
            let hi = char::from_digit(u32::from(*b) >> 4, 16).unwrap_or('?');
            let lo = char::from_digit(u32::from(*b) & 0xf, 16).unwrap_or('?');
            [hi, lo]
        })
        .collect();
    println!("pk = {hex}");
    println!("sig len = {SIGNATURE_LEN}");
}
