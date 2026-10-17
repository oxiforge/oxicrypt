//! Power-up cryptographic algorithm self-tests (CASTs) for SLH-DSA.
//!
//! Three CASTs per parameter set, each a known-answer test against values
//! NIST published, never against this crate's own output:
//!
//! 1. key generation (FIPS 205 Algorithm 18) from a fixed SK.seed, SK.prf
//!    and PK.seed, compared byte for byte to the expected private and
//!    public key;
//! 2. deterministic signature generation (Algorithm 19, no additional
//!    randomness) of a fixed message under a fixed private key, compared
//!    byte for byte to the expected signature;
//! 3. verification (Algorithm 20) of a fixed public key, message and
//!    signature, which must return true; the same signature with one bit of
//!    its randomizer R flipped must then return false, so a verifier that
//!    accepts every signature, or that skips the final comparison with the
//!    public root, fails.
//!
//! They run on SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f: one parameter set
//! from each hash family, and in each family the set with the lowest-height
//! trees. The vectors and their provenance are in `cast_vectors`.

use oxicrypt_module::{KatEntry, SelfTestFailure};

fn verdict(pass: bool) -> Result<(), SelfTestFailure> {
    if pass { Ok(()) } else { Err(SelfTestFailure) }
}

/// Defines the three CASTs for one parameter set: `$set` is its module in
/// this crate and `$v` its module in `cast_vectors`.
macro_rules! slh_dsa_casts {
    (
        $keygen:ident,
        $keygen_with:ident,
        $sign:ident,
        $sign_with:ident,
        $verify:ident,
        $verify_with:ident,
        $set:ident,
        $v:ident
    ) => {
        fn $keygen() -> Result<(), SelfTestFailure> {
            $keygen_with(crate::$set::keygen_internal)
        }

        /// The key-generation CAST, run on `keygen`.
        fn $keygen_with(
            keygen: fn(
                &[u8; 3 * crate::$set::N],
            ) -> Result<
                ([u8; crate::$set::PK_LEN], [u8; crate::$set::SK_LEN]),
                oxicrypt_module::Error,
            >,
        ) -> Result<(), SelfTestFailure> {
            use crate::cast_vectors::$v as v;
            let n = v::KEYGEN_SK_SEED.len();
            let mut xi = [0u8; 3 * crate::$set::N];
            xi[..n].copy_from_slice(&v::KEYGEN_SK_SEED);
            xi[n..2 * n].copy_from_slice(&v::KEYGEN_SK_PRF);
            xi[2 * n..].copy_from_slice(&v::KEYGEN_PK_SEED);
            let (pk, sk) = keygen(&xi).map_err(|_| SelfTestFailure)?;
            verdict(sk == v::KEYGEN_SK && pk == v::KEYGEN_PK)
        }

        fn $sign() -> Result<(), SelfTestFailure> {
            $sign_with(crate::$set::sign_internal)
        }

        /// The signature-generation CAST, run on `sign`.
        fn $sign_with(
            sign: fn(
                &[u8; crate::$set::SK_LEN],
                &[u8],
            ) -> Result<[u8; crate::$set::SIG_LEN], oxicrypt_module::Error>,
        ) -> Result<(), SelfTestFailure> {
            use crate::cast_vectors::$v as v;
            verdict(sign(&v::SIG_SK, &v::SIG_MSG).map_err(|_| SelfTestFailure)? == v::SIG)
        }

        fn $verify() -> Result<(), SelfTestFailure> {
            $verify_with(crate::$set::verify_internal)
        }

        /// The verification CAST, run on `verify`.
        fn $verify_with(
            verify: fn(
                &[u8; crate::$set::PK_LEN],
                &[u8],
                &[u8; crate::$set::SIG_LEN],
            ) -> Result<bool, oxicrypt_module::Error>,
        ) -> Result<(), SelfTestFailure> {
            use crate::cast_vectors::$v as v;
            if !verify(&v::SIG_PK, &v::SIG_MSG, &v::SIG).map_err(|_| SelfTestFailure)? {
                return Err(SelfTestFailure);
            }
            // The signature opens with R, which selects the message digest
            // and so every tree the verifier walks.
            let mut flipped = v::SIG;
            let first = flipped.first_mut().ok_or(SelfTestFailure)?;
            *first ^= 0x01;
            verdict(!verify(&v::SIG_PK, &v::SIG_MSG, &flipped).map_err(|_| SelfTestFailure)?)
        }
    };
}

slh_dsa_casts!(
    keygen_sha2_128f,
    keygen_sha2_128f_with,
    sign_sha2_128f,
    sign_sha2_128f_with,
    verify_sha2_128f,
    verify_sha2_128f_with,
    slh_dsa_sha2_128f,
    sha2_128f
);
slh_dsa_casts!(
    keygen_shake_128f,
    keygen_shake_128f_with,
    sign_shake_128f,
    sign_shake_128f_with,
    verify_shake_128f,
    verify_shake_128f_with,
    slh_dsa_shake_128f,
    shake_128f
);

/// Power-up CASTs for SLH-DSA: key generation, signature generation and
/// verification, each on SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f.
/// Verification must accept the expected signature and reject it with one
/// bit flipped.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "SLH-DSA-SHA2-128f CAST (key generation, FIPS 205, NIST ACVP vector)",
        run: keygen_sha2_128f,
    },
    KatEntry {
        name: "SLH-DSA-SHA2-128f CAST (signature generation, FIPS 205, NIST ACVP vector)",
        run: sign_sha2_128f,
    },
    KatEntry {
        name: "SLH-DSA-SHA2-128f CAST (signature verification, FIPS 205, NIST ACVP vector)",
        run: verify_sha2_128f,
    },
    KatEntry {
        name: "SLH-DSA-SHAKE-128f CAST (key generation, FIPS 205, NIST ACVP vector)",
        run: keygen_shake_128f,
    },
    KatEntry {
        name: "SLH-DSA-SHAKE-128f CAST (signature generation, FIPS 205, NIST ACVP vector)",
        run: sign_shake_128f,
    },
    KatEntry {
        name: "SLH-DSA-SHAKE-128f CAST (signature verification, FIPS 205, NIST ACVP vector)",
        run: verify_shake_128f,
    },
];

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{
        KATS, keygen_sha2_128f_with, keygen_shake_128f_with, sign_sha2_128f_with,
        sign_shake_128f_with, verify_sha2_128f_with, verify_shake_128f_with,
    };
    use std::vec::Vec;

    /// The verification CASTs fail a verifier that accepts every signature,
    /// and one whose verdict does not depend on R, as a verifier that skips
    /// the final comparison with the public root is; and they pass the real
    /// verifier.
    #[test]
    fn verify_casts_reject_a_verifier_that_skips_its_checks() {
        use crate::cast_vectors::{sha2_128f, shake_128f};
        use crate::{slh_dsa_sha2_128f, slh_dsa_shake_128f};
        crate::test_support::start_module();

        assert!(verify_sha2_128f_with(slh_dsa_sha2_128f::verify_internal).is_ok());
        assert!(verify_shake_128f_with(slh_dsa_shake_128f::verify_internal).is_ok());
        assert!(verify_sha2_128f_with(|_, _, _| Ok(true)).is_err());
        assert!(verify_shake_128f_with(|_, _, _| Ok(true)).is_err());

        // R is the first N bytes of the signature.
        assert!(
            verify_sha2_128f_with(|pk, msg, sig| {
                let mut sig = *sig;
                for (b, want) in sig
                    .iter_mut()
                    .zip(&sha2_128f::SIG)
                    .take(slh_dsa_sha2_128f::N)
                {
                    *b = *want;
                }
                slh_dsa_sha2_128f::verify_internal(pk, msg, &sig)
            })
            .is_err(),
            "a SHA2-128f verifier ignoring R passed"
        );
        assert!(
            verify_shake_128f_with(|pk, msg, sig| {
                let mut sig = *sig;
                for (b, want) in sig
                    .iter_mut()
                    .zip(&shake_128f::SIG)
                    .take(slh_dsa_shake_128f::N)
                {
                    *b = *want;
                }
                slh_dsa_shake_128f::verify_internal(pk, msg, &sig)
            })
            .is_err(),
            "a SHAKE-128f verifier ignoring R passed"
        );
    }

    /// The key-generation CASTs fail a key generator whose public or
    /// private key differs by one bit, and pass the real one.
    #[test]
    fn keygen_casts_reject_a_wrong_key() {
        use crate::{slh_dsa_sha2_128f as a, slh_dsa_shake_128f as b};
        fn flip(bytes: &mut [u8]) {
            if let Some(x) = bytes.last_mut() {
                *x ^= 0x01;
            }
        }
        crate::test_support::start_module();
        assert!(keygen_sha2_128f_with(a::keygen_internal).is_ok());
        assert!(keygen_shake_128f_with(b::keygen_internal).is_ok());
        assert!(
            keygen_sha2_128f_with(|xi| {
                let (pk, mut sk) = a::keygen_internal(xi)?;
                flip(&mut sk);
                Ok((pk, sk))
            })
            .is_err(),
            "SHA2-128f: a wrong private key passed"
        );
        assert!(
            keygen_sha2_128f_with(|xi| {
                let (mut pk, sk) = a::keygen_internal(xi)?;
                flip(&mut pk);
                Ok((pk, sk))
            })
            .is_err(),
            "SHA2-128f: a wrong public key passed"
        );
        assert!(
            keygen_shake_128f_with(|xi| {
                let (pk, mut sk) = b::keygen_internal(xi)?;
                flip(&mut sk);
                Ok((pk, sk))
            })
            .is_err(),
            "SHAKE-128f: a wrong private key passed"
        );
        assert!(
            keygen_shake_128f_with(|xi| {
                let (mut pk, sk) = b::keygen_internal(xi)?;
                flip(&mut pk);
                Ok((pk, sk))
            })
            .is_err(),
            "SHAKE-128f: a wrong public key passed"
        );
    }

    /// The signature-generation CASTs fail a signer whose signature differs
    /// by one bit, and pass the real one.
    #[test]
    fn sign_casts_reject_a_wrong_signature() {
        use crate::{slh_dsa_sha2_128f as a, slh_dsa_shake_128f as b};
        crate::test_support::start_module();
        assert!(sign_sha2_128f_with(a::sign_internal).is_ok());
        assert!(sign_shake_128f_with(b::sign_internal).is_ok());
        assert!(
            sign_sha2_128f_with(|sk, msg| {
                let mut sig = a::sign_internal(sk, msg)?;
                if let Some(x) = sig.last_mut() {
                    *x ^= 0x01;
                }
                Ok(sig)
            })
            .is_err(),
            "SHA2-128f: a wrong signature passed"
        );
        assert!(
            sign_shake_128f_with(|sk, msg| {
                let mut sig = b::sign_internal(sk, msg)?;
                if let Some(x) = sig.last_mut() {
                    *x ^= 0x01;
                }
                Ok(sig)
            })
            .is_err(),
            "SHAKE-128f: a wrong signature passed"
        );
    }

    #[test]
    fn every_cast_passes() {
        crate::test_support::start_module();
        assert_eq!(KATS.len(), 6, "three CASTs on each of two parameter sets");
        let failed: Vec<&str> = KATS
            .iter()
            .filter(|kat| (kat.run)().is_err())
            .map(|kat| kat.name)
            .collect();
        assert!(failed.is_empty(), "failing CASTs: {failed:?}");
    }
}
