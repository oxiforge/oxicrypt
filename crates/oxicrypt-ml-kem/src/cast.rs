//! Power-up cryptographic algorithm self-tests (CASTs) for ML-KEM.
//!
//! Four CASTs, as FIPS 140-3 IG 10.3.A item 14 requires, each a
//! known-answer test against values NIST published rather than this
//! crate's own output:
//!
//! 1. key generation (FIPS 203 Algorithm 16, `ML-KEM.KeyGen_internal`)
//!    from fixed seeds d and z, compared byte for byte to the expected
//!    decapsulation key. The returned encapsulation key is compared to the
//!    copy of it inside the expected decapsulation key, so a fault that
//!    corrupts only the returned encapsulation key also fails;
//! 2. encapsulation (Algorithm 17, `ML-KEM.Encaps_internal`) from a fixed
//!    encapsulation key and randomness m, compared byte for byte to the
//!    expected ciphertext and shared secret;
//! 3. decapsulation (Algorithm 18, `ML-KEM.Decaps_internal`) of a fixed
//!    valid ciphertext under a fixed decapsulation key, compared to the
//!    expected shared secret;
//! 4. decapsulation of a fixed modified ciphertext, compared to the
//!    expected implicit-rejection shared secret J(z ‖ c). With CAST 3 this
//!    covers both decapsulation paths (IG 10.3.A Note 21).
//!
//! They run on ML-KEM-1024, the parameter set approved under the CNSA 2.0,
//! Migration and Unrestricted profiles, so the self-tested set is one that
//! CNSA 2.0 uses. CNSA 1.0 admits no ML-KEM parameter set. IG 10.3.A Note 22 requires the
//! CASTs on at least one implemented parameter set; ML-KEM-512 and
//! ML-KEM-768 share every line of the implementation through the
//! `ml_kem_impl!` macro. The vectors and their provenance are
//! in `cast_vectors`.

use oxicrypt_module::{KatEntry, SelfTestFailure};

use crate::cast_vectors::ml_kem_1024 as v;
use crate::ml_kem_1024 as p;

fn verdict(pass: bool) -> Result<(), SelfTestFailure> {
    if pass { Ok(()) } else { Err(SelfTestFailure) }
}

/// Key generation from fixed (d, z); the decapsulation key must match, and
/// the encapsulation key must match the copy of it the expected
/// decapsulation key holds at offset `384 · k` (FIPS 203 Algorithm 16).
fn keygen() -> Result<(), SelfTestFailure> {
    keygen_with(p::keygen_internal)
}

/// The key-generation primitive the key-generation CAST runs.
type KeygenFn = fn(
    &[u8; p::SEED_LEN],
    &[u8; p::SEED_LEN],
) -> Result<([u8; p::EK_LEN], [u8; p::DK_LEN]), oxicrypt_module::Error>;

/// The key-generation CAST, run on `keygen`.
fn keygen_with(keygen: KeygenFn) -> Result<(), SelfTestFailure> {
    let (ek, dk) = keygen(&v::KEYGEN_D, &v::KEYGEN_Z).map_err(|_| SelfTestFailure)?;
    let expected_ek = v::KEYGEN_DK
        .get(384 * p::K..384 * p::K + p::EK_LEN)
        .ok_or(SelfTestFailure)?;
    verdict(dk == v::KEYGEN_DK && ek.as_slice() == expected_ek)
}

/// Encapsulation from fixed (ek, m); the ciphertext and the shared secret
/// must both match.
fn encaps() -> Result<(), SelfTestFailure> {
    encaps_with(p::encaps_internal)
}

/// The encapsulation primitive the encapsulation CAST runs.
type EncapsFn = fn(
    &[u8; p::EK_LEN],
    &[u8; p::SEED_LEN],
)
    -> Result<([u8; p::SHARED_SECRET_LEN], [u8; p::CT_LEN]), oxicrypt_module::Error>;

/// The encapsulation CAST, run on `encaps`.
fn encaps_with(encaps: EncapsFn) -> Result<(), SelfTestFailure> {
    let (k, c) = encaps(&v::ENCAPS_EK, &v::ENCAPS_M).map_err(|_| SelfTestFailure)?;
    verdict(c == v::ENCAPS_C && k == v::ENCAPS_K)
}

/// The decapsulation primitive both decapsulation CASTs run.
type DecapsFn = fn(
    &[u8; p::DK_LEN],
    &[u8; p::CT_LEN],
) -> Result<[u8; p::SHARED_SECRET_LEN], oxicrypt_module::Error>;

/// Decapsulation of a valid ciphertext; the shared secret must match.
fn decaps() -> Result<(), SelfTestFailure> {
    decaps_with(p::decaps_internal)
}

/// The valid-ciphertext decapsulation CAST, run on `decaps`.
fn decaps_with(decaps: DecapsFn) -> Result<(), SelfTestFailure> {
    verdict(decaps(&v::DECAPS_DK, &v::DECAPS_C).map_err(|_| SelfTestFailure)? == v::DECAPS_K)
}

/// Decapsulation of a modified ciphertext; the implicit-rejection shared
/// secret must match.
fn decaps_implicit_rejection() -> Result<(), SelfTestFailure> {
    decaps_implicit_rejection_with(p::decaps_internal)
}

/// The implicit-rejection decapsulation CAST, run on `decaps`.
fn decaps_implicit_rejection_with(decaps: DecapsFn) -> Result<(), SelfTestFailure> {
    verdict(decaps(&v::REJECT_DK, &v::REJECT_C).map_err(|_| SelfTestFailure)? == v::REJECT_K)
}

/// Power-up cryptographic algorithm self-tests (CASTs) for ML-KEM.
///
/// Four known-answer tests on ML-KEM-1024 against NIST ACVP-Server
/// vectors: key generation, encapsulation, and decapsulation on the
/// valid and on the implicit-rejection path. Each is a separate entry
/// and fails if its output differs from the expected value. A module
/// entry point passes this slice to
/// [`oxicrypt_module::initialize_with_tests`].
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "ML-KEM-1024 CAST (key generation, FIPS 203, NIST ACVP vector)",
        run: keygen,
    },
    KatEntry {
        name: "ML-KEM-1024 CAST (encapsulation, FIPS 203, NIST ACVP vector)",
        run: encaps,
    },
    KatEntry {
        name: "ML-KEM-1024 CAST (decapsulation, valid ciphertext, FIPS 203, NIST ACVP vector)",
        run: decaps,
    },
    KatEntry {
        name: "ML-KEM-1024 CAST (decapsulation, implicit rejection, FIPS 203, NIST ACVP vector)",
        run: decaps_implicit_rejection,
    },
];

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{KATS, decaps_implicit_rejection_with, decaps_with, encaps_with, keygen_with};
    use std::vec::Vec;

    /// The key-generation CAST fails a key generation whose returned
    /// encapsulation key is corrupted after the decapsulation key took its
    /// copy, and passes the real one.
    #[test]
    fn keygen_cast_rejects_a_corrupted_encapsulation_key() {
        use crate::ml_kem_1024 as p;
        crate::test_support::start_module();
        assert!(keygen_with(p::keygen_internal).is_ok());
        let corrupts_ek: super::KeygenFn = |d, z| {
            let (mut ek, dk) = p::keygen_internal(d, z)?;
            if let Some(b) = ek.last_mut() {
                *b ^= 0x01;
            }
            Ok((ek, dk))
        };
        assert!(
            keygen_with(corrupts_ek).is_err(),
            "a corrupted encapsulation key passed"
        );
    }

    /// The encapsulation CAST fails an encapsulation whose shared secret
    /// or ciphertext differs by one bit, and passes the real one.
    #[test]
    fn encaps_cast_rejects_a_wrong_secret_or_ciphertext() {
        use crate::ml_kem_1024 as p;
        crate::test_support::start_module();
        assert!(encaps_with(p::encaps_internal).is_ok());
        let wrong_k: super::EncapsFn = |ek, m| {
            let (mut k, c) = p::encaps_internal(ek, m)?;
            if let Some(b) = k.first_mut() {
                *b ^= 0x01;
            }
            Ok((k, c))
        };
        let wrong_c: super::EncapsFn = |ek, m| {
            let (k, mut c) = p::encaps_internal(ek, m)?;
            if let Some(b) = c.first_mut() {
                *b ^= 0x01;
            }
            Ok((k, c))
        };
        assert!(
            encaps_with(wrong_k).is_err(),
            "a wrong shared secret passed"
        );
        assert!(encaps_with(wrong_c).is_err(), "a wrong ciphertext passed");
    }

    /// Both decapsulation CASTs fail a decapsulation whose shared secret
    /// differs by one bit, and the implicit-rejection CAST also fails one
    /// that returns a constant in place of the rejection secret; both pass
    /// the real one.
    #[test]
    fn decaps_casts_reject_a_wrong_secret() {
        use crate::ml_kem_1024 as p;
        crate::test_support::start_module();
        assert!(decaps_with(p::decaps_internal).is_ok());
        assert!(decaps_implicit_rejection_with(p::decaps_internal).is_ok());
        let wrong: super::DecapsFn = |dk, c| {
            let mut k = p::decaps_internal(dk, c)?;
            if let Some(b) = k.first_mut() {
                *b ^= 0x01;
            }
            Ok(k)
        };
        assert!(decaps_with(wrong).is_err(), "a wrong shared secret passed");
        assert!(
            decaps_implicit_rejection_with(wrong).is_err(),
            "a wrong implicit-rejection secret passed"
        );
        let no_rejection: super::DecapsFn = |_, _| Ok([0u8; p::SHARED_SECRET_LEN]);
        assert!(
            decaps_implicit_rejection_with(no_rejection).is_err(),
            "a decapsulation that skips implicit rejection passed"
        );
    }

    #[test]
    fn every_cast_passes() {
        crate::test_support::start_module();
        assert_eq!(
            KATS.len(),
            4,
            "key generation, encapsulation, two decapsulation paths"
        );
        let failed: Vec<&str> = KATS
            .iter()
            .filter(|kat| (kat.run)().is_err())
            .map(|kat| kat.name)
            .collect();
        assert!(failed.is_empty(), "failing CASTs: {failed:?}");
    }
}
