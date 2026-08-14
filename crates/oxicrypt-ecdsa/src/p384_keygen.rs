//! P-384 key generation and DRBG-backed scalar sampling, per
//! FIPS 186-5 §A.2.
//!
//! See [`crate::p256_keygen`] for the design rationale; the P-384
//! version is structurally identical with 48-byte scalars and
//! 97-byte uncompressed public keys.

#![allow(clippy::indexing_slicing)]

use oxicrypt_drbg::HmacDrbgSha256;

use crate::p384_ecdsa::{PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, derive_public_key_internal};
use crate::p384_scalar::Scalar384;

/// Maximum number of rejection-sampling attempts.
const MAX_SAMPLE_ATTEMPTS: usize = 64;

/// Draw a uniform scalar in `[1, n − 1]` from `drbg` using the
/// FIPS 186-5 §A.2.2 "Testing Candidates" method (48-byte draws).
///
/// Returns `Some(d)` where `d` is a valid non-zero scalar byte
/// representation, or `None` if the DRBG fails or refuses to produce
/// an in-range value within `MAX_SAMPLE_ATTEMPTS` tries.
///
/// Visibility is `pub` rather than `pub(crate)` because
/// `oxicrypt-ecdh` reuses this primitive for ECDH P-384 keypair
/// generation. See the P-256 counterpart
/// [`crate::p256_keygen::sample_scalar_internal`] for the
/// single-implementation rationale.
#[doc(hidden)]
pub fn sample_scalar_internal(drbg: &mut HmacDrbgSha256) -> Option<[u8; PRIVATE_KEY_LEN]> {
    let mut buf = [0u8; PRIVATE_KEY_LEN];
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        if drbg.generate(None, &mut buf).is_err() {
            oxicrypt_zeroize::zeroize(&mut buf);
            return None;
        }
        if let Some(s) = Scalar384::from_bytes(&buf)
            && s.is_zero() == 0
        {
            // See P-256 counterpart for the success-path
            // copy-and-clear rationale; same pattern, 48-byte
            // scalar instead of 32.
            let result = buf;
            oxicrypt_zeroize::zeroize(&mut buf);
            return Some(result);
        }
        oxicrypt_zeroize::zeroize(&mut buf);
    }
    None
}

/// Generate a fresh P-384 key pair.
///
/// Returns `(d_bytes, pk_bytes)` where `d_bytes` is a uniform
/// scalar in `[1, n − 1]` and `pk_bytes` is the uncompressed SEC1
/// encoding of `d · G`. Returns `None` iff the DRBG fails or fails
/// to produce an in-range scalar within `MAX_SAMPLE_ATTEMPTS`
/// attempts.
///
/// This primitive does not run the IG 10.3.A pairwise consistency
/// test; callers run the PCT appropriate to their family (ECDSA
/// sign-and-verify, ECDH roundtrip).
///
/// Visibility is `pub` rather than `pub(crate)` because
/// `oxicrypt-ecdh` reuses this primitive for ECDH P-384 keypair
/// generation; see the P-256 counterpart
/// [`crate::p256_keygen::generate_p256_internal`] for the
/// single-implementation rationale.
#[doc(hidden)]
pub fn generate_p384_internal(
    drbg: &mut HmacDrbgSha256,
) -> Option<([u8; PRIVATE_KEY_LEN], [u8; PUBLIC_KEY_LEN])> {
    let d = sample_scalar_internal(drbg)?;
    let pk = derive_public_key_internal(&d)?;
    Some((d, pk))
}
