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
//! (`2^256 − n < 2^224`, so the rejection probability is below
//! `2^(−32)`), the loop terminates after a single iteration with
//! overwhelming probability. The retry count is still capped at a
//! small constant so a broken or empty DRBG can't wedge the caller in
//! an infinite loop — a DRBG that produces no in-range draw in 64
//! attempts is broken, and the sampler returns `Error::InvalidInput`.
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

use oxicrypt_module::{Error, Rbg, require_self_test_started};

use crate::p256_ecdsa::{PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, derive_public_key_internal};
use crate::p256_scalar::Scalar;

/// Maximum number of rejection-sampling attempts before the DRBG is
/// declared broken. With P-256's rejection probability
/// this bound is only ever exceeded by a malfunctioning DRBG.
const MAX_SAMPLE_ATTEMPTS: usize = 64;

/// Security strength, in bits, a random bit generator must report
/// through [`Rbg::strength_bits`] before a P-256 scalar is drawn from
/// it: the strength SP 800-57 Part 1 Rev. 5 Table 2 assigns to ECC
/// with `f` = 256.
pub const RBG_STRENGTH_BITS: u32 = 128;

/// Draw a uniform scalar in `[1, n − 1]` from `drbg`, a random bit
/// generator implementing [`Rbg`], using the FIPS 186-5 §A.2.2
/// "Testing Candidates" method.
///
/// Returns `d`, a valid non-zero scalar byte representation,
/// [`Error::RbgTooWeak`] before any draw if `drbg` reports less than
/// [`RBG_STRENGTH_BITS`], [`Error::Rbg`] if the random bit generator
/// produces no output, or [`Error::InvalidInput`] if it produces no
/// in-range value within `MAX_SAMPLE_ATTEMPTS` tries.
///
/// This is the `*_internal` primitive — it skips the operational
/// and profile gates, refuses unless
/// [`oxicrypt_module::require_self_test_started`] admits the call (in
/// `Operational`, or in `SelfTest` on the thread running the power-up
/// self-tests),
/// and is safe to call from KATs, PCTs, and from the
/// module-state-checked wrappers above.
///
/// Visibility is `pub` rather than `pub(crate)` because
/// `oxicrypt-ecdh` reuses this primitive for ECDH P-256 keypair
/// generation, so the same FIPS 186-5 §A.2.2 sampler serves both
/// the ECDSA keygen path and the ECDH keygen path on this curve.
/// Centralising the rejection-sampler here means a CST-lab reviewer
/// audits one range-checked sampler covering both families.
///
/// Returns [`Error::NotOperational`] when the module refuses the call,
/// which it does in every state other than `SelfTest` and `Operational`.
#[doc(hidden)]
pub fn sample_scalar_internal<R: Rbg>(drbg: &mut R) -> Result<[u8; PRIVATE_KEY_LEN], Error> {
    require_self_test_started()?;
    if drbg.strength_bits() < RBG_STRENGTH_BITS {
        return Err(Error::RbgTooWeak);
    }
    sample_scalar_internal_unguarded(drbg)?.ok_or(Error::InvalidInput)
}

/// Body of [`sample_scalar_internal`], run once its guard has passed.
fn sample_scalar_internal_unguarded<R: Rbg>(
    drbg: &mut R,
) -> Result<Option<[u8; PRIVATE_KEY_LEN]>, Error> {
    let mut buf = [0u8; PRIVATE_KEY_LEN];
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        if let Err(e) = drbg.fill(&mut buf) {
            // CSP scrub: clear any partial generator output before
            // returning, through `oxicrypt-zeroize`'s volatile store so
            // the write survives optimisation.
            oxicrypt_zeroize::zeroize(&mut buf);
            return Err(Error::Rbg(e));
        }
        // `Scalar::from_bytes` returns `None` for bytes ≥ n and
        // also silently accepts the zero encoding; zero is rejected
        // explicitly afterwards to land in `[1, n − 1]`.
        if let Some(s) = Scalar::from_bytes(&buf)
            && s.is_zero() == 0
        {
            // Success path: copy the accepted bytes out, then
            // clear the named local `buf` before returning.
            // The returned `result` carries the bytes onward;
            // the caller chain wraps it in `EcdsaP{256}PrivateKey`
            // (or, for ECDH, the `oxicrypt-ecdh` keygen wrapper),
            // both of which provide Drop-zeroize. The clear of
            // `buf` is a volatile store, so it is not elided even
            // though `buf` is dead afterwards.
            let result = buf;
            oxicrypt_zeroize::zeroize(&mut buf);
            return Ok(Some(result));
        }
        // CSP scrub: rejected candidates linger in `buf` between
        // iterations otherwise. Although a rejected scalar (≥ n or
        // zero) is by definition not a valid private key, it is DRBG
        // output and so is temporary SSP material within the meaning of
        // FIPS 140-3 IG §7.9.7 AS09.32 — zeroised when no longer needed.
        oxicrypt_zeroize::zeroize(&mut buf);
    }
    Ok(None)
}

/// Generate a fresh P-256 key pair.
///
/// Returns `(d_bytes, pk_bytes)` where `d_bytes` is a uniform
/// scalar in `[1, n − 1]` and `pk_bytes` is the uncompressed SEC1
/// encoding of `d · G`. `drbg` is a random bit generator implementing
/// [`Rbg`]. Returns [`Error::Rbg`] if it produces no output, and
/// [`Error::InvalidInput`] if it fails to produce an in-range scalar
/// within `MAX_SAMPLE_ATTEMPTS` attempts — in practice, only a broken
/// generator.
///
/// This primitive does not run the IG 10.3.A pairwise consistency
/// test; the PCT is the job of the caller. For ECDSA the PCT lives
/// inside [`crate::p256_ecdsa::EcdsaP256PrivateKey::generate`]
/// (sign-and-verify probe). For ECDH the PCT lives inside
/// `oxicrypt_ecdh::generate_keypair_p256_internal` (ECDH-roundtrip
/// against the RFC 5903 §8.1 peer keypair).
///
/// Visibility is `pub` rather than `pub(crate)` because
/// `oxicrypt-ecdh` reuses this primitive for ECDH P-256 keypair
/// generation. ECDSA private keys and ECDH private keys on the same
/// curve are uniform random scalars in the same `[1, n − 1]` range
/// drawn from the same approved DRBG; centralising the keygen
/// primitive here keeps a single FIPS 186-5 §A.2.2 implementation
/// across both families.
///
/// Returns [`Error::NotOperational`] when the module refuses the call,
/// which it does in every state other than `SelfTest` and `Operational`.
#[doc(hidden)]
pub fn generate_p256_internal<R: Rbg>(
    drbg: &mut R,
) -> Result<([u8; PRIVATE_KEY_LEN], [u8; PUBLIC_KEY_LEN]), Error> {
    require_self_test_started()?;
    let d = sample_scalar_internal(drbg)?;
    let pk = derive_public_key_internal(&d)?;
    Ok((d, pk))
}
