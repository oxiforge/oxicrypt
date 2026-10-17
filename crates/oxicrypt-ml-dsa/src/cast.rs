//! Power-up cryptographic algorithm self-tests (CASTs) for ML-DSA.
//!
//! Five CASTs, each a known-answer test against values NIST published,
//! never against this crate's own output:
//!
//! 1. key generation (FIPS 204 Algorithm 6, `ML-DSA.KeyGen_internal`) from
//!    a fixed seed ξ, compared byte for byte to the expected private key.
//!    The private key contains tr = H(pk), so the public key is not
//!    compared separately. This meets the key-generation CAST of
//!    FIPS 140-3 IG 10.3.A item 15;
//! 2. deterministic signature generation (Algorithm 7,
//!    `ML-DSA.Sign_internal`, with rnd = {0}³²) of a fixed formatted
//!    message M′ under a fixed private key, compared byte for byte to the
//!    expected signature from NIST ACVP-Server. This meets the
//!    signature-generation CAST of item 15. Its signing loop rejects
//!    candidates on the z and r0 bounds before it succeeds;
//! 3. deterministic signature generation on a vector from the list of test
//!    cases NIST gives for IG 10.3.A Note 23, whose loop rejects candidates
//!    on the z bound, the r0 bound and the number of hints, so that every
//!    rejection path that applies to ML-DSA-87 runs. For these cases NIST
//!    publishes the key-generation seed, SHA2-256(pk ‖ sk), M′ and
//!    SHA2-256(σ), not the keys or σ. The CAST therefore derives the key
//!    pair from the seed, requires SHA2-256(pk ‖ sk) to match, signs, and
//!    requires SHA2-256(σ) to match: it compares digests because the
//!    digests are what NIST publishes;
//! 4. the same on ML-DSA-44, with a listed vector whose loop also rejects a
//!    candidate on the ct0 bound, the check Note 23 names for ML-DSA-44.
//!    The check exists in the shared implementation but can reject only
//!    for ML-DSA-44 parameters;
//! 5. verification (Algorithm 8, `ML-DSA.Verify_internal`) of a fixed
//!    public key, formatted message M′ and signature that NIST publishes
//!    as valid, which must return true. This meets the verification CAST
//!    of item 15. The same signature with one bit of c̃ flipped must then
//!    return false, so a verifier that accepts every signature, or that
//!    skips the final comparison of c̃, fails.
//!
//! CASTs 1, 2, 3 and 5 run on ML-DSA-87, the parameter set approved under the
//! CNSA 2.0, Migration and Unrestricted profiles, so the self-tested set is
//! one that CNSA 2.0 uses. CNSA 1.0 admits no ML-DSA parameter set. IG 10.3.A Note 26 requires the
//! CASTs on at least one implemented parameter set; ML-DSA-44 and
//! ML-DSA-65 share every line of the implementation through the
//! `ml_dsa_impl!` macro. The external signing and verification
//! interfaces (Algorithms 2 and 3) add only the M′ framing to the
//! algorithms tested here. The vectors and their provenance are in
//! `cast_vectors`.

use oxicrypt_module::{KatEntry, SelfTestFailure};

use oxicrypt_sha::sha256::Sha256;

use crate::cast_vectors::ml_dsa_87 as v;
use crate::ml_dsa_87 as p;

fn verdict(pass: bool) -> Result<(), SelfTestFailure> {
    if pass { Ok(()) } else { Err(SelfTestFailure) }
}

/// A key-generation primitive the CASTs run, for one parameter set.
type KeygenFn<const PK: usize, const SK: usize> =
    fn(&[u8; 32]) -> Result<([u8; PK], [u8; SK]), oxicrypt_module::Error>;

/// A signing primitive the CASTs run, for one parameter set.
type SignFn<const SK: usize, const SIG: usize> =
    fn(&[u8; SK], &[u8]) -> Result<[u8; SIG], oxicrypt_module::Error>;

/// Key generation from a fixed ξ; the private key must match.
fn keygen() -> Result<(), SelfTestFailure> {
    keygen_with(p::keygen_internal)
}

/// The key-generation CAST, run on `keygen`.
fn keygen_with(keygen: KeygenFn<{ p::PK_LEN }, { p::SK_LEN }>) -> Result<(), SelfTestFailure> {
    let (_pk, sk) = keygen(&v::KEYGEN_XI).map_err(|_| SelfTestFailure)?;
    verdict(sk == v::KEYGEN_SK)
}

/// Deterministic signing of a fixed M′ under a fixed private key; the
/// signature must match byte for byte.
fn sign() -> Result<(), SelfTestFailure> {
    sign_with(p::sign_internal)
}

/// The signature-generation CAST, run on `sign`.
fn sign_with(sign: SignFn<{ p::SK_LEN }, { p::SIG_LEN }>) -> Result<(), SelfTestFailure> {
    let sig = sign(&v::SIGN_SK, &v::SIGN_MSG).map_err(|_| SelfTestFailure)?;
    verdict(sig == v::SIGN_SIG)
}

fn sha256(parts: &[&[u8]]) -> Result<[u8; 32], SelfTestFailure> {
    let mut h = Sha256::new_internal().map_err(|_| SelfTestFailure)?;
    for part in parts {
        h.update(part);
    }
    h.finalize().map_err(|_| SelfTestFailure)
}

/// Deterministic signing of a fixed M′ under the key pair from a fixed
/// seed: SHA2-256(pk ‖ sk) and SHA2-256(σ) must match NIST's values.
macro_rules! sign_cast {
    ($name:ident, $with:ident, $set:ident) => {
        fn $name() -> Result<(), SelfTestFailure> {
            $with(crate::$set::keygen_internal, crate::$set::sign_internal)
        }

        /// The CAST, run on `keygen` and `sign`.
        fn $with(
            keygen: KeygenFn<{ crate::$set::PK_LEN }, { crate::$set::SK_LEN }>,
            sign: SignFn<{ crate::$set::SK_LEN }, { crate::$set::SIG_LEN }>,
        ) -> Result<(), SelfTestFailure> {
            use crate::cast_vectors::$set as v;
            let (pk, sk) = keygen(&v::REJ_SEED).map_err(|_| SelfTestFailure)?;
            if sha256(&[&pk, &sk])? != v::REJ_KEY_HASH {
                return Err(SelfTestFailure);
            }
            let sig = sign(&sk, &v::REJ_MSG).map_err(|_| SelfTestFailure)?;
            verdict(sha256(&[&sig])? == v::REJ_SIG_HASH)
        }
    };
}

sign_cast!(sign_rejections, sign_rejections_with, ml_dsa_87);
sign_cast!(
    sign_rejections_ml_dsa_44,
    sign_rejections_ml_dsa_44_with,
    ml_dsa_44
);

/// The signature-verification primitive the verification CAST runs.
type VerifyFn =
    fn(&[u8; p::PK_LEN], &[u8], &[u8; p::SIG_LEN]) -> Result<bool, oxicrypt_module::Error>;

/// The ML-DSA-87 signature-verification CAST (FIPS 204 Algorithm 8,
/// `ML-DSA.Verify_internal`), callable on its own.
///
/// Verification of a fixed valid (pk, M′, σ) that NIST publishes must
/// return true, and of the same σ with the low bit of its first byte, part
/// of c̃, flipped must return false. It is the fifth entry of [`KATS`]; a
/// component that verifies ML-DSA-87 signatures before the rest of the
/// power-up self-tests run, such as the module's software integrity test,
/// runs it directly.
///
/// # Errors
///
/// Returns [`SelfTestFailure`] if either verdict differs from the expected
/// one, or if the module refuses the primitive because its self-tests have
/// not started.
pub fn verify_cast() -> Result<(), SelfTestFailure> {
    verify_with(p::verify_internal)
}

/// The name [`KATS`] gives [`verify_cast`].
pub const VERIFY_CAST_NAME: &str =
    "ML-DSA-87 CAST (signature verification, FIPS 204, NIST ACVP vector)";

/// The verification CAST, run on `verify`.
fn verify_with(verify: VerifyFn) -> Result<(), SelfTestFailure> {
    if !verify(&v::VERIFY_PK, &v::VERIFY_MSG, &v::VERIFY_SIG).map_err(|_| SelfTestFailure)? {
        return Err(SelfTestFailure);
    }
    let mut flipped = v::VERIFY_SIG;
    let first = flipped.first_mut().ok_or(SelfTestFailure)?;
    *first ^= 0x01;
    verdict(!verify(&v::VERIFY_PK, &v::VERIFY_MSG, &flipped).map_err(|_| SelfTestFailure)?)
}

/// Power-up cryptographic algorithm self-tests (CASTs) for ML-DSA.
///
/// Five known-answer tests against NIST vectors: on ML-DSA-87, key
/// generation, deterministic signature generation compared in full,
/// deterministic signature generation through every applicable rejection
/// path compared as digests, and signature verification, which must accept
/// the valid signature and reject it with one bit flipped; on ML-DSA-44,
/// deterministic signature generation through the ct0 rejection path,
/// compared as digests. Each is a separate entry and fails if its
/// output differs from the expected value. A module entry point passes
/// this slice to [`oxicrypt_module::initialize_with_tests`].
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "ML-DSA-87 CAST (key generation, FIPS 204, NIST ACVP vector)",
        run: keygen,
    },
    KatEntry {
        name: "ML-DSA-87 CAST (signature generation, FIPS 204, NIST ACVP vector)",
        run: sign,
    },
    KatEntry {
        name: "ML-DSA-87 CAST (signature generation, z/r0/hint rejections, FIPS 204, NIST ACVP vector)",
        run: sign_rejections,
    },
    KatEntry {
        name: "ML-DSA-44 CAST (signature generation, z/r0/ct0/hint rejections, FIPS 204, NIST ACVP vector)",
        run: sign_rejections_ml_dsa_44,
    },
    KatEntry {
        name: VERIFY_CAST_NAME,
        run: verify_cast,
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::{
        KATS, keygen_with, sign_rejections_ml_dsa_44_with, sign_rejections_with, sign_with,
        verify_with,
    };
    use crate::rejection_counts::{self, CT0, HINT, R0, Z};
    use std::vec::Vec;

    /// The verification CAST fails a verifier that accepts every signature,
    /// and one whose verdict does not depend on c̃, as a verifier that skips
    /// the final comparison of c̃ is; and it passes the real verifier.
    #[test]
    fn verify_cast_rejects_a_verifier_that_skips_its_checks() {
        use crate::cast_vectors::ml_dsa_87 as v;
        use crate::ml_dsa_87 as p;
        crate::test_support::start_module();
        assert!(verify_with(p::verify_internal).is_ok());
        assert!(
            verify_with(|_, _, _| Ok(true)).is_err(),
            "an always-true verifier passed"
        );
        let ignores_ctilde: super::VerifyFn = |pk, msg, sig| {
            let mut sig = *sig;
            for (b, want) in sig.iter_mut().zip(&v::VERIFY_SIG).take(p::CTILDE_LEN) {
                *b = *want;
            }
            p::verify_internal(pk, msg, &sig)
        };
        assert!(
            verify_with(ignores_ctilde).is_err(),
            "a verifier ignoring c̃ passed"
        );
    }

    /// The key-generation CAST fails a key generator whose private key
    /// differs by one bit, and passes the real one.
    #[test]
    fn keygen_cast_rejects_a_wrong_private_key() {
        use crate::ml_dsa_87 as p;
        crate::test_support::start_module();
        assert!(keygen_with(p::keygen_internal).is_ok());
        assert!(
            keygen_with(|xi| {
                let (pk, mut sk) = p::keygen_internal(xi)?;
                if let Some(b) = sk.first_mut() {
                    *b ^= 1;
                }
                Ok((pk, sk))
            })
            .is_err(),
            "a wrong private key passed"
        );
    }

    /// The signature-generation CAST fails a signer whose signature differs
    /// by one bit, and passes the real one.
    #[test]
    fn sign_cast_rejects_a_wrong_signature() {
        use crate::ml_dsa_87 as p;
        crate::test_support::start_module();
        assert!(sign_with(p::sign_internal).is_ok());
        assert!(
            sign_with(|sk, msg| {
                let mut sig = p::sign_internal(sk, msg)?;
                if let Some(b) = sig.first_mut() {
                    *b ^= 1;
                }
                Ok(sig)
            })
            .is_err(),
            "a wrong signature passed"
        );
    }

    /// Each rejection-path signing CAST fails when the key pair or the
    /// signature differs by one bit, so both of its digests are compared,
    /// and passes the real primitives.
    #[test]
    fn rejection_signing_casts_check_both_digests() {
        crate::test_support::start_module();
        {
            use crate::ml_dsa_87 as p;
            assert!(sign_rejections_with(p::keygen_internal, p::sign_internal).is_ok());
            assert!(
                sign_rejections_with(
                    |seed| {
                        let (mut pk, sk) = p::keygen_internal(seed)?;
                        if let Some(b) = pk.first_mut() {
                            *b ^= 1;
                        }
                        Ok((pk, sk))
                    },
                    p::sign_internal
                )
                .is_err(),
                "ML-DSA-87: a wrong key pair passed"
            );
            assert!(
                sign_rejections_with(p::keygen_internal, |sk, msg| {
                    let mut sig = p::sign_internal(sk, msg)?;
                    if let Some(b) = sig.first_mut() {
                        *b ^= 1;
                    }
                    Ok(sig)
                })
                .is_err(),
                "ML-DSA-87: a wrong signature passed"
            );
        }
        {
            use crate::ml_dsa_44 as p;
            assert!(sign_rejections_ml_dsa_44_with(p::keygen_internal, p::sign_internal).is_ok());
            assert!(
                sign_rejections_ml_dsa_44_with(
                    |seed| {
                        let (mut pk, sk) = p::keygen_internal(seed)?;
                        if let Some(b) = pk.first_mut() {
                            *b ^= 1;
                        }
                        Ok((pk, sk))
                    },
                    p::sign_internal
                )
                .is_err(),
                "ML-DSA-44: a wrong key pair passed"
            );
            assert!(
                sign_rejections_ml_dsa_44_with(p::keygen_internal, |sk, msg| {
                    let mut sig = p::sign_internal(sk, msg)?;
                    if let Some(b) = sig.first_mut() {
                        *b ^= 1;
                    }
                    Ok(sig)
                })
                .is_err(),
                "ML-DSA-44: a wrong signature passed"
            );
        }
    }

    /// Each signing CAST's loop takes the rejection paths it is chosen for.
    /// The counts are the candidates each check rejects before the loop
    /// emits the expected signature; each is pinned as a minimum.
    #[test]
    fn signing_casts_drive_the_rejection_paths() {
        use crate::cast_vectors::{ml_dsa_44, ml_dsa_87};
        crate::test_support::start_module();

        let _ = rejection_counts::take();
        let sig = crate::ml_dsa_87::sign_internal(&ml_dsa_87::SIGN_SK, &ml_dsa_87::SIGN_MSG);
        assert!(sig.is_ok_and(|s| s == ml_dsa_87::SIGN_SIG));
        let tc177 = rejection_counts::take();

        let (_, sk) = crate::ml_dsa_87::keygen_internal(&ml_dsa_87::REJ_SEED).unwrap();
        let _ = rejection_counts::take();
        assert!(crate::ml_dsa_87::sign_internal(&sk, &ml_dsa_87::REJ_MSG).is_ok());
        let row13 = rejection_counts::take();

        let (_, sk) = crate::ml_dsa_44::keygen_internal(&ml_dsa_44::REJ_SEED).unwrap();
        let _ = rejection_counts::take();
        assert!(crate::ml_dsa_44::sign_internal(&sk, &ml_dsa_44::REJ_MSG).is_ok());
        let row1 = rejection_counts::take();

        let at_least = |got: [u32; 4], min: [u32; 4], case: &str| {
            assert!(
                got.iter().zip(min).all(|(g, m)| *g >= m),
                "{case}: rejections [z, r0, ct0, hint] = {got:?}, expected at least {min:?}"
            );
        };
        // [z, r0, ct0, hint], in the order of `rejection_counts`' indices.
        assert_eq!((Z, R0, CT0, HINT), (0, 1, 2, 3));
        at_least(tc177, [3, 2, 0, 0], "ML-DSA-87 sigGen tcId 177");
        at_least(row13, [2, 3, 0, 1], "ML-DSA-87 Table 1 row 13");
        at_least(row1, [1, 1, 1, 1], "ML-DSA-44 Table 1 row 1");
    }

    #[test]
    fn every_cast_passes() {
        crate::test_support::start_module();
        assert_eq!(KATS.len(), 5, "key generation, three signing, verification");
        let failed: Vec<&str> = KATS
            .iter()
            .filter(|kat| (kat.run)().is_err())
            .map(|kat| kat.name)
            .collect();
        assert!(failed.is_empty(), "failing CASTs: {failed:?}");
    }
}
