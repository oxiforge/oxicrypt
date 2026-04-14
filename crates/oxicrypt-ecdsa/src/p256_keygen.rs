//! P-256 key generation and DRBG-backed scalar sampling, per
//! FIPS 186-5 §A.2.
//!
//! This module provides the private "Testing Candidates" rejection
//! sampler (`sample_scalar_internal`) that both keygen and the
//! DRBG-backed sign wrapper use to produce a uniform scalar in
//! `[1, n − 1]`, plus the keygen entry point
//! (`generate_p256_internal`) that builds a `(d, Q)` pair ready to
//! be handed to [`crate::p256_ecdsa::EcdsaP256PrivateKey`].
//!
//! # Rejection sampler (FIPS 186-5 §A.2.2)
//!
//! Appendix A.2.2 "Testing Candidates" is the simplest of the two
//! FIPS-approved scalar-generation methods: draw `nlen = 256` bits
//! from an approved DRBG, interpret them as a big-endian integer,
//! and accept iff the result lies in `[1, n − 1]`. Any out-of-range
//! draw is discarded and the loop retries with a fresh DRBG output.
//!
//! Because the P-256 group order `n` is extremely close to `2^256`
//! (the rejection probability is on the order of `2^(−128)`), the
//! loop terminates after a single iteration with overwhelming
//! probability. We still cap the retry count at a small constant so
//! a broken or empty DRBG can't wedge the caller in an infinite
//! loop — a DRBG that refuses to produce a single in-range draw in
//! 64 attempts is broken and we return `None`.
//!
//! # Why the same sampler backs both keygen and signing
//!
//! ECDSA private keys and ECDSA per-signature nonces are both
//! uniform random scalars in `[1, n − 1]`, drawn from an approved
//! DRBG (FIPS 186-5 §6.3, §A.2). The sampler is therefore the same
//! primitive in both contexts, and centralising it here lets the
//! keygen and the DRBG-backed sign wrapper share exactly one code
//! path — which means only one place needs to be constant-time,
//! only one place needs to enforce the rejection-sampling range
//! check, and the PCT that keygen runs happens to exercise the same
//! sampler the production sign path will use.

#![allow(clippy::indexing_slicing)]

use oxicrypt_drbg::HmacDrbgSha256;

use crate::p256_ecdsa::{
    derive_public_key_internal, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN,
};
use crate::p256_scalar::Scalar;

/// Maximum number of rejection-sampling attempts before we declare
/// the DRBG broken and give up. With P-256's rejection probability
/// this bound is only ever exceeded by a malfunctioning DRBG.
const MAX_SAMPLE_ATTEMPTS: usize = 64;

/// Draw a uniform scalar in `[1, n − 1]` from `drbg` using the
/// FIPS 186-5 §A.2.2 "Testing Candidates" method.
///
/// Returns `Some(d)` where `d` is a valid non-zero scalar byte
/// representation, or `None` if the DRBG fails or refuses to produce
/// an in-range value within [`MAX_SAMPLE_ATTEMPTS`] tries.
///
/// This is the `*_internal` primitive — it does not gate on module
/// state and is safe to call from KATs, PCTs, and from the
/// module-state-checked wrappers above.
pub(crate) fn sample_scalar_internal(
    drbg: &mut HmacDrbgSha256,
) -> Option<[u8; PRIVATE_KEY_LEN]> {
    let mut buf = [0u8; PRIVATE_KEY_LEN];
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        if drbg.generate(None, &mut buf).is_err() {
            return None;
        }
        // `Scalar::from_bytes` returns `None` for bytes ≥ n and
        // also silently accepts the zero encoding; we reject zero
        // explicitly afterwards to land in `[1, n − 1]`.
        if let Some(s) = Scalar::from_bytes(&buf) {
            if s.is_zero() == 0 {
                return Some(buf);
            }
        }
    }
    None
}

/// Generate a fresh P-256 key pair.
///
/// Returns `(d_bytes, pk_bytes)` where `d_bytes` is a uniform
/// scalar in `[1, n − 1]` and `pk_bytes` is the uncompressed SEC1
/// encoding of `d · G`. Returns `None` iff the DRBG fails or fails
/// to produce an in-range scalar within [`MAX_SAMPLE_ATTEMPTS`]
/// attempts — in practice, only a broken DRBG.
///
/// This primitive does not run the IG 10.3.A pairwise consistency
/// test; the PCT is the job of the handle constructor
/// [`crate::p256_ecdsa::EcdsaP256PrivateKey::generate`], which
/// composes this primitive with a sign-and-verify probe.
pub(crate) fn generate_p256_internal(
    drbg: &mut HmacDrbgSha256,
) -> Option<([u8; PRIVATE_KEY_LEN], [u8; PUBLIC_KEY_LEN])> {
    let d = sample_scalar_internal(drbg)?;
    let pk = derive_public_key_internal(&d)?;
    Some((d, pk))
}
