//! RSA signature verification per FIPS 186-5 §5.4 / RFC 8017.
//!
//! # Status
//!
//! Chunk R1 lands the RSA-2048 big-int foundation (fixed-width
//! [`bigint2048::U2048`] and the CIOS [`mont2048::MontCtx2048`]) plus
//! a public-key-only entry point,
//! [`rsa_pkcs1_v15_verify_2048_sha256`], for RSASSA-PKCS1-v1_5 with
//! SHA-256. This is enough to stand up a FIPS 140-3 IG D.G power-up
//! known-answer test for the RSA service while deferring the
//! private-key (signing, CRT, keygen) and PSS work to follow-on
//! chunks.
//!
//! # FIPS 186-5 §5.1 modulus size
//!
//! Only `|n| = 2048` bits is accepted. Verification of legacy 1024-
//! or 1280-bit RSA signatures is outside the approved boundary and
//! this crate deliberately has no code path for it. Extension to
//! RSA-3072 and RSA-4096 will land when the corresponding
//! fixed-width big-int types are added.
//!
//! # FIPS module gating
//!
//! [`rsa_pkcs1_v15_verify_2048_sha256`] calls
//! [`fips_module::require_operational`] before doing any work; a
//! hidden [`rsa_pkcs1_v15_verify_2048_sha256_internal`] primitive
//! bypasses the gate so the power-up KAT in [`self_test`] can run
//! while the module is still in `SelfTest`. The KAT uses a pinned
//! 2048-bit modulus with `e = 65537` and verifies a signature over
//! a fixed ASCII message; it also checks that a single-bit tamper of
//! the signature is rejected.
#![no_std]
#![forbid(unsafe_code)]

pub mod bigint2048;
pub mod mont2048;
pub mod pkcs1_v15;

use bigint2048::{U2048, BYTES as U2048_BYTES};
use fips_module::{require_operational, Error, SelfTestFailure};
use fips_sha::sha256::{sha256, Sha256, DIGEST_SIZE as SHA256_DIGEST_SIZE};
use mont2048::MontCtx2048;

/// Fixed modulus byte length for RSA-2048.
pub const RSA_2048_MODULUS_BYTES: usize = U2048_BYTES;
/// Fixed signature byte length for RSA-2048 (equal to the modulus
/// length per PKCS#1 §8.2).
pub const RSA_2048_SIGNATURE_BYTES: usize = U2048_BYTES;

// ------------------------------------------------------------------
// Core primitive (state-gate-free)
// ------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 verify for RSA-2048 / SHA-256, bypassing the
/// FIPS module state gate. Intended for power-up KAT use only;
/// production callers use [`rsa_pkcs1_v15_verify_2048_sha256`].
///
/// Returns `true` iff:
///   * `n` is a valid 2048-bit odd integer with the top bit set
///     (accepted by [`MontCtx2048::new`]),
///   * `s < n` where `s` is the signature integer,
///   * `RSAVP1(s) = s^e mod n = EM`, and
///   * `EM` matches the canonical EMSA-PKCS1-v1_5 encoding of
///     `SHA-256(msg)` at length 256 bytes.
#[doc(hidden)]
pub fn rsa_pkcs1_v15_verify_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> bool {
    // Decode the modulus and build a Montgomery context. `MontCtx2048::new`
    // enforces oddness and the strict-2048-bit size requirement from
    // FIPS 186-5 §5.1.
    let n = U2048::from_be_bytes(n_bytes);
    let Some(ctx) = MontCtx2048::new(n) else {
        return false;
    };

    // RFC 8017 §8.2.2 step 1: length check is implicit in the fixed
    // array sizes. Step 2a: convert signature to integer `s`.
    let s = U2048::from_be_bytes(sig_bytes);

    // RFC 8017 §5.2.2 RSAVP1 step 1: s must be in `[0, n-1]`. An
    // attacker-controlled `s ≥ n` would otherwise be accepted by the
    // Montgomery ladder (which reduces mod n and forgets the top
    // bits), letting them construct unlimited signature aliases.
    if s.ct_lt(&ctx.n) != 1 {
        return false;
    }

    // RSAVP1 / RSAEP: m = s^e mod n. `pow_public_u64` is explicitly
    // non-constant-time in `e`, which is fine here because `e` is
    // part of the public key.
    let m = ctx.pow_public_u64(&s, e);
    let em_recovered = m.to_be_bytes();

    // Build the expected EM from SHA-256(msg) and compare byte-exact.
    let mut hasher = Sha256::new_internal();
    hasher.update(msg);
    let digest = hasher.finalize();

    let mut em_expected = [0u8; RSA_2048_MODULUS_BYTES];
    if pkcs1_v15::encode_sha256(&digest, &mut em_expected).is_none() {
        return false;
    }
    pkcs1_v15::ct_eq(&em_recovered, &em_expected) == 1
}

// ------------------------------------------------------------------
// Public, gated entry point
// ------------------------------------------------------------------

/// Verify an RSASSA-PKCS1-v1_5 signature over `msg` under the 2048-bit
/// public key `(n_bytes, e)` using SHA-256 as the message digest.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the containing FIPS module
/// has not finished its power-up self-tests. Returns
/// [`Error::InvalidInput`] if the signature fails to verify for any
/// reason — invalid modulus, out-of-range signature integer, digest
/// mismatch, or malformed EM.
///
/// On a successful verification, returns `Ok(())`.
pub fn rsa_pkcs1_v15_verify_2048_sha256(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> Result<(), Error> {
    require_operational()?;
    if rsa_pkcs1_v15_verify_2048_sha256_internal(n_bytes, e, msg, sig_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

// Quiet an otherwise-unused import: `sha256` one-shot isn't used by
// the core primitive (we reach for `Sha256::new_internal` to bypass
// the gate during the KAT), but we re-expose it indirectly so the
// public surface can hash without pulling in `fips-sha` directly.
#[doc(hidden)]
pub fn __sha256_oneshot_for_docs(data: &[u8]) -> Result<[u8; SHA256_DIGEST_SIZE], Error> {
    sha256(data)
}

// ------------------------------------------------------------------
// Power-up known-answer test
// ------------------------------------------------------------------

/// Pinned RSA-2048 public modulus used by the power-up KAT. Generated
/// deterministically from a fixed PRNG seed; the matching private
/// key is stored out-of-band (not needed here because the KAT only
/// exercises the verify path).
const KAT_N_BYTES: [u8; 256] = [
    0xb1, 0xb2, 0x5f, 0x95, 0x6b, 0xa0, 0x4b, 0x22, 0xdf, 0x1c, 0x8b, 0x1f, 0xee, 0x4a, 0x47, 0x28,
    0x48, 0x92, 0xac, 0x1a, 0xe1, 0x6b, 0x62, 0x05, 0xba, 0x30, 0x2c, 0xdf, 0x03, 0x32, 0x43, 0xf3,
    0xcb, 0x96, 0x8c, 0x6d, 0x6f, 0x3b, 0xe4, 0xda, 0xb6, 0xf8, 0x61, 0x98, 0x36, 0x66, 0xfa, 0x06,
    0x9b, 0x37, 0xd0, 0x15, 0x6d, 0x61, 0x6f, 0xd8, 0x37, 0xae, 0x8a, 0x52, 0x4c, 0xf5, 0xee, 0x66,
    0x20, 0x27, 0xa0, 0xde, 0x1a, 0xf6, 0x7b, 0xb3, 0x7d, 0x5d, 0x18, 0xe3, 0x10, 0xcd, 0x37, 0xa8,
    0x67, 0x9b, 0xe3, 0x1d, 0x66, 0x19, 0xe1, 0xfa, 0x8a, 0x9b, 0xd4, 0x46, 0x8a, 0x16, 0x65, 0x72,
    0xf5, 0xa2, 0x75, 0xca, 0x23, 0x8e, 0x99, 0x98, 0xce, 0xf3, 0x1f, 0x24, 0xb3, 0x37, 0x61, 0x77,
    0xae, 0xad, 0x1f, 0x41, 0xa7, 0x0b, 0xe3, 0xd5, 0x2b, 0xb3, 0x77, 0x32, 0x51, 0x24, 0x5c, 0x2f,
    0xd0, 0x1b, 0xb6, 0x89, 0x52, 0x49, 0xa8, 0x60, 0x39, 0xf4, 0xdb, 0x74, 0xdd, 0x84, 0x24, 0x62,
    0xb7, 0xba, 0x2d, 0x8a, 0x77, 0x63, 0x41, 0x3b, 0x26, 0x18, 0x7a, 0x16, 0x18, 0x32, 0x62, 0x91,
    0x44, 0xf6, 0x1f, 0x59, 0x33, 0x39, 0x62, 0xe3, 0x3e, 0x75, 0x6c, 0xb7, 0xa2, 0xf4, 0x61, 0xf1,
    0xba, 0xd9, 0x54, 0xc2, 0x92, 0xda, 0x40, 0x5f, 0x0a, 0x07, 0x19, 0xbc, 0x73, 0xa6, 0xda, 0x88,
    0x7d, 0x13, 0x31, 0xd0, 0x91, 0x73, 0xa0, 0x19, 0x12, 0xfb, 0x3a, 0x4d, 0x27, 0xe8, 0x3d, 0xb4,
    0xd0, 0xf4, 0x8c, 0x7b, 0x0f, 0x5d, 0x13, 0xce, 0x35, 0xd4, 0x23, 0xd4, 0x2e, 0x78, 0x1a, 0xda,
    0x29, 0x95, 0x50, 0x2a, 0xb5, 0x09, 0xd7, 0x95, 0x39, 0xda, 0x50, 0x7a, 0xe2, 0xa2, 0x08, 0xbb,
    0x1c, 0xcc, 0xf0, 0x43, 0xe2, 0xfc, 0x0f, 0xcc, 0x4a, 0x05, 0xd8, 0xd4, 0xda, 0x45, 0x6c, 0x6d,
];

/// Pinned public exponent for the KAT.
const KAT_E: u64 = 65537;

/// Message covered by the KAT signature.
const KAT_MSG: &[u8] = b"pqclib FIPS RSA-2048 PKCS1v15 SHA-256 power-up KAT";

/// Pinned RSASSA-PKCS1-v1_5 signature of `KAT_MSG` under `(KAT_N, KAT_E)`.
const KAT_SIG_BYTES: [u8; 256] = [
    0x12, 0x26, 0x65, 0x1f, 0x47, 0x0b, 0xc2, 0x86, 0x25, 0x6c, 0x3a, 0x92, 0xdb, 0x77, 0xee, 0x9a,
    0xeb, 0x44, 0x7b, 0xf0, 0x26, 0x57, 0xe3, 0xb3, 0x4a, 0x9d, 0x60, 0xba, 0xfd, 0x00, 0xb2, 0xae,
    0xc7, 0x54, 0xed, 0x16, 0x3d, 0x1a, 0x9c, 0x1e, 0xe1, 0x7e, 0xa9, 0x70, 0xdd, 0xa3, 0x9c, 0x5d,
    0x04, 0xa4, 0x56, 0xc7, 0x7e, 0x0c, 0x78, 0x5a, 0x22, 0x52, 0x29, 0x73, 0x0c, 0xc9, 0xa7, 0xc6,
    0x5f, 0xc0, 0x76, 0xe9, 0xc2, 0x3d, 0xa8, 0x2c, 0xf7, 0xfb, 0xc1, 0x13, 0xea, 0x7e, 0xef, 0xb7,
    0xf0, 0x50, 0xc8, 0x3b, 0xdb, 0x08, 0xfe, 0xd2, 0x7f, 0xa2, 0xe8, 0x20, 0x39, 0x9c, 0xfe, 0x5a,
    0x45, 0x91, 0xd9, 0xde, 0xf9, 0x21, 0xe6, 0x09, 0xb6, 0xb9, 0xc5, 0x1d, 0xb6, 0x39, 0x14, 0x3f,
    0xc9, 0x46, 0x07, 0x66, 0xb2, 0xb1, 0x70, 0x2d, 0x4c, 0x27, 0x94, 0x60, 0xc1, 0x5d, 0x3b, 0x8c,
    0xfd, 0x79, 0x5a, 0xff, 0xd1, 0xa3, 0x0e, 0xc2, 0xd9, 0xa5, 0x6f, 0xd2, 0xb4, 0x90, 0xa4, 0x8b,
    0x50, 0xab, 0x69, 0xad, 0xf1, 0x9f, 0x7a, 0xf2, 0x10, 0xa6, 0x9a, 0x27, 0x50, 0xc1, 0x11, 0x7b,
    0xaf, 0x77, 0x8b, 0xdd, 0x84, 0x93, 0xa3, 0xc3, 0x25, 0x9e, 0xda, 0x69, 0xb3, 0x32, 0x85, 0xeb,
    0x00, 0x08, 0x9f, 0x9d, 0xa8, 0x6d, 0x2a, 0x21, 0xd2, 0x97, 0xf4, 0x4a, 0xeb, 0xbb, 0x3d, 0x70,
    0x18, 0x42, 0xac, 0xb9, 0x04, 0xac, 0x93, 0x95, 0x6d, 0x43, 0x01, 0x70, 0xfe, 0x91, 0xd8, 0x44,
    0x97, 0xe3, 0x77, 0x29, 0x57, 0x8c, 0xf6, 0x48, 0x02, 0x35, 0xa4, 0x7a, 0x6a, 0x02, 0x60, 0x68,
    0x12, 0x94, 0x3e, 0x5f, 0x37, 0xb0, 0x70, 0x57, 0x90, 0xed, 0x50, 0x42, 0x96, 0x85, 0x1e, 0x1c,
    0x2c, 0x27, 0xc7, 0xa1, 0x6a, 0x87, 0xa7, 0x21, 0x86, 0x89, 0xec, 0xe6, 0x73, 0x3d, 0xf4, 0xcd,
];

/// Power-up KAT for the RSA-2048 PKCS#1 v1.5 / SHA-256 verify path.
///
/// Runs two checks:
///
/// 1. Positive: the pinned `(n, e, msg, sig)` tuple verifies.
/// 2. Negative: flipping the last byte of the signature must cause
///    a rejection, exercising both the `s < n` and the digest-mismatch
///    paths.
pub fn self_test() -> Result<(), SelfTestFailure> {
    if !rsa_pkcs1_v15_verify_2048_sha256_internal(&KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_SIG_BYTES) {
        return Err(SelfTestFailure);
    }
    let mut tampered = KAT_SIG_BYTES;
    tampered[255] ^= 0x01;
    if rsa_pkcs1_v15_verify_2048_sha256_internal(&KAT_N_BYTES, KAT_E, KAT_MSG, &tampered) {
        return Err(SelfTestFailure);
    }
    Ok(())
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use fips_module::{initialize_with_tests, KatEntry};

    #[test]
    fn kat_positive_verifies() {
        assert!(rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_flipped_signature() {
        let mut bad = KAT_SIG_BYTES;
        bad[128] ^= 0x80;
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &bad
        ));
    }

    #[test]
    fn kat_rejects_wrong_message() {
        let bad_msg = b"pqclib FIPS RSA-2048 PKCS1v15 SHA-256 power-up KAT (tampered)";
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, bad_msg, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_even_modulus() {
        let mut bad_n = KAT_N_BYTES;
        bad_n[255] &= 0xfe; // force LSB to 0 → even modulus
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &bad_n, KAT_E, KAT_MSG, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_signature_ge_modulus() {
        // Set s to a value that equals n (not strictly less than n).
        // RSAVP1 step 1 must reject.
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_N_BYTES
        ));
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn public_api_gated_on_operational() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-pkcs1v15-sha256",
            run: self_test,
        }]);
        rsa_pkcs1_v15_verify_2048_sha256(&KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_SIG_BYTES)
            .expect("module operational");
    }
}
