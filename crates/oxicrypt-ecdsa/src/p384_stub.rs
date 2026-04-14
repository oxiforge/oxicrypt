//! P-384 ECDSA thin wrappers — FIPS 186-5, CNSA 1.0.
//!
//! These entry points delegate to the full P-384 ECDSA
//! implementation in [`crate::p384_ecdsa`]. They exist so that
//! callers that were written against the original stub API can
//! migrate at their own pace; new code should use
//! [`crate::p384_ecdsa`] directly.

use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_module::Error;

use crate::p384_ecdsa;

/// Sign a message with an ECDSA P-384 private key, returning the
/// 96-byte `r || s` signature.
///
/// This is a thin wrapper around [`p384_ecdsa::sign_with_k`]; see
/// that function for details.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when `private_key` or `k` are
/// not valid non-zero scalars mod `n`, or when the resulting `r`
/// or `s` is zero (rejection required by FIPS 186-5).
pub fn sign(
    private_key: &[u8; p384_ecdsa::PRIVATE_KEY_LEN],
    msg: &[u8],
    k: &[u8; p384_ecdsa::PRIVATE_KEY_LEN],
) -> Result<[u8; p384_ecdsa::SIGNATURE_LEN], Error> {
    p384_ecdsa::sign_with_k(private_key, msg, k)
}

/// Verify an ECDSA P-384 signature.
///
/// Thin wrapper around [`p384_ecdsa::verify`].
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when the public key fails
/// SP 800-56Ar3 §5.6.2.3.3 validation or the signature does not
/// verify.
pub fn verify(
    public_key: &[u8; p384_ecdsa::PUBLIC_KEY_LEN],
    msg: &[u8],
    signature: &[u8; p384_ecdsa::SIGNATURE_LEN],
) -> Result<bool, Error> {
    p384_ecdsa::verify(public_key, msg, signature)
}

/// Generate an ECDSA P-384 key pair using a DRBG-backed rejection
/// sampler.
///
/// Thin wrapper around [`p384_ecdsa::EcdsaP384PrivateKey::generate`].
///
/// # Errors
///
/// Returns an error when the DRBG fails or the pairwise
/// consistency test (IG 10.3.A) rejects the new key pair.
pub fn keygen(
    drbg: &mut HmacDrbgSha256,
) -> Result<p384_ecdsa::EcdsaP384PrivateKey, Error> {
    p384_ecdsa::EcdsaP384PrivateKey::generate(drbg)
}
