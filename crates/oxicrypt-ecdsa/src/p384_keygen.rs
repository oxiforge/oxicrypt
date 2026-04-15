//! P-384 key generation and DRBG-backed scalar sampling, per
//! FIPS 186-5 §A.2.
//!
//! See [`crate::p256_keygen`] for the design rationale; the P-384
//! version is structurally identical with 48-byte scalars and
//! 97-byte uncompressed public keys.

#![allow(clippy::indexing_slicing)]

use oxicrypt_drbg::HmacDrbgSha256;

use crate::p384_ecdsa::{derive_public_key_internal, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN};
use crate::p384_scalar::Scalar384;

/// Maximum number of rejection-sampling attempts.
const MAX_SAMPLE_ATTEMPTS: usize = 64;

/// Draw a uniform scalar in `[1, n − 1]` from `drbg` using the
/// FIPS 186-5 §A.2.2 "Testing Candidates" method (48-byte draws).
pub(crate) fn sample_scalar_internal(drbg: &mut HmacDrbgSha256) -> Option<[u8; PRIVATE_KEY_LEN]> {
    let mut buf = [0u8; PRIVATE_KEY_LEN];
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        if drbg.generate(None, &mut buf).is_err() {
            return None;
        }
        if let Some(s) = Scalar384::from_bytes(&buf) {
            if s.is_zero() == 0 {
                return Some(buf);
            }
        }
    }
    None
}

/// Generate a fresh P-384 key pair.
pub(crate) fn generate_p384_internal(
    drbg: &mut HmacDrbgSha256,
) -> Option<([u8; PRIVATE_KEY_LEN], [u8; PUBLIC_KEY_LEN])> {
    let d = sample_scalar_internal(drbg)?;
    let pk = derive_public_key_internal(&d)?;
    Some((d, pk))
}
