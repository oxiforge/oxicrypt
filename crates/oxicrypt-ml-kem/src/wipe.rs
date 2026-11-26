//! Zeroization of the seeds, intermediates and key copies of key
//! generation, encapsulation and decapsulation, each under its own
//! identity.
//!
//! Every byte buffer listed in [`WipedBuffer`] is held in a [`Tagged`],
//! which zeroizes it when it is dropped, and every polynomial temporary in
//! an [`Observed`], whose value `Poly`'s `Drop` zeroizes. In this crate's
//! own tests with the `fault-injection` feature each construction and each
//! wipe is also counted per identity, on the calling thread, so a test can
//! observe that a buffer was wiped on a given exit. Otherwise nothing is
//! recorded.

/// The buffer a [`Tagged`] holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WipedBuffer {
    /// The seed d drawn from the caller's RBG (FIPS 203 Algorithm 19 step 1).
    D,
    /// The seed z drawn from the caller's RBG (FIPS 203 Algorithm 19 step 2).
    Z,
    /// The randomness m drawn from the caller's RBG (FIPS 203 Algorithm 20
    /// step 1).
    M,
    /// The input d ‖ k to G (FIPS 203 Algorithm 13 step 1).
    KeygenGInput,
    /// The output ρ ‖ σ of G (FIPS 203 Algorithm 13 step 1).
    KeygenG,
    /// The public seed ρ (FIPS 203 Algorithm 13 step 1).
    KeygenRho,
    /// The noise seed σ (FIPS 203 Algorithm 13 step 1).
    KeygenSigma,
    /// The PRF output a noise polynomial is sampled from (FIPS 203
    /// Algorithm 13 steps 9 and 13, Algorithm 14 steps 10, 14 and 17).
    NoisePrf,
    /// ρ copied from the encryption key (FIPS 203 Algorithm 14 step 3).
    EncryptRho,
    /// The output K ‖ r of G (FIPS 203 Algorithm 17 step 1).
    EncapsG,
    /// The shared secret K (FIPS 203 Algorithm 17 step 1).
    EncapsK,
    /// The encryption randomness r (FIPS 203 Algorithm 17 step 1).
    EncapsR,
    /// m′ = K-PKE.Decrypt(dk_PKE, c) (FIPS 203 Algorithm 18 step 5).
    DecapsMPrime,
    /// The output K′ ‖ r′ of G (FIPS 203 Algorithm 18 step 6).
    DecapsG,
    /// The candidate shared secret K′ (FIPS 203 Algorithm 18 step 6).
    DecapsKPrime,
    /// The re-encryption randomness r′ (FIPS 203 Algorithm 18 step 6).
    DecapsRPrime,
    /// The rejection secret K̄ = J(z ‖ c) (FIPS 203 Algorithm 18 step 7).
    DecapsKBar,
    /// The re-encryption c′ (FIPS 203 Algorithm 18 step 8).
    DecapsCtPrime,
    /// The module's copy of a generated encapsulation key.
    PublicKey,
    /// The module's copy of a generated decapsulation key.
    SecretKey,
    /// The ciphertext the pairwise consistency test encapsulates.
    PctCiphertext,
    /// The shared secret the pairwise consistency test encapsulates.
    PctEncapsK,
    /// The shared secret the pairwise consistency test decapsulates.
    PctDecapsK,
    /// Â (FIPS 203 Algorithm 13 step 5).
    KeygenA,
    /// s (FIPS 203 Algorithm 13 step 9).
    KeygenS,
    /// e (FIPS 203 Algorithm 13 step 13).
    KeygenE,
    /// t̂ = Â ∘ ŝ + ê (FIPS 203 Algorithm 13 step 18).
    KeygenTHat,
    /// t̂ decoded from the encryption key (FIPS 203 Algorithm 14 step 2).
    EncryptTHat,
    /// Â (FIPS 203 Algorithm 14 step 6).
    EncryptA,
    /// y (FIPS 203 Algorithm 14 step 10).
    EncryptY,
    /// e₁ (FIPS 203 Algorithm 14 step 14).
    EncryptE1,
    /// e₂ (FIPS 203 Algorithm 14 step 17).
    EncryptE2,
    /// u (FIPS 203 Algorithm 14 step 19).
    EncryptU,
    /// v (FIPS 203 Algorithm 14 step 21).
    EncryptV,
    /// μ = Decompress₁(ByteDecode₁(m)) (FIPS 203 Algorithm 14 step 20).
    EncryptMu,
    /// u′ (FIPS 203 Algorithm 15 step 3).
    DecryptU,
    /// v′, and w once it is computed (FIPS 203 Algorithm 15 steps 4 and 6).
    DecryptV,
    /// ŝ (FIPS 203 Algorithm 15 step 5).
    DecryptSHat,
    /// NTT⁻¹(ŝᵀ ∘ NTT(u′)) (FIPS 203 Algorithm 15 step 6).
    DecryptW,
    /// The module's copy of the shared secret `encapsulate` returns.
    SharedSecret,
}

/// Every [`WipedBuffer`], for the tests that check each one.
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) const ALL: [WipedBuffer; 40] = {
    use WipedBuffer::*;
    [
        D,
        Z,
        M,
        KeygenGInput,
        KeygenG,
        KeygenRho,
        KeygenSigma,
        NoisePrf,
        EncryptRho,
        EncapsG,
        EncapsK,
        EncapsR,
        DecapsMPrime,
        DecapsG,
        DecapsKPrime,
        DecapsRPrime,
        DecapsKBar,
        DecapsCtPrime,
        PublicKey,
        SecretKey,
        PctCiphertext,
        PctEncapsK,
        PctDecapsK,
        KeygenA,
        KeygenS,
        KeygenE,
        KeygenTHat,
        EncryptTHat,
        EncryptA,
        EncryptY,
        EncryptE1,
        EncryptE2,
        EncryptU,
        EncryptV,
        EncryptMu,
        DecryptU,
        DecryptV,
        DecryptSHat,
        DecryptW,
        SharedSecret,
    ]
};

// Each identity sits at its own discriminant, so `ALL` holds every one once.
#[cfg(all(test, feature = "fault-injection"))]
#[allow(
    clippy::indexing_slicing,
    reason = "evaluated at compile time, where an index out of range fails the build"
)]
const _: () = {
    assert!(WipedBuffer::SharedSecret as usize + 1 == ALL.len());
    let mut i = 0;
    while i < ALL.len() {
        assert!(ALL[i] as usize == i);
        i += 1;
    }
};

/// A polynomial temporary of key generation, encryption or decryption,
/// which `Poly`'s `Drop` zeroizes. Outside this crate's own tests with the
/// `fault-injection` feature it is the value itself.
#[cfg(not(all(test, feature = "fault-injection")))]
pub(crate) type Observed<T> = T;

/// Wraps `value` as the temporary `buffer`.
#[cfg(not(all(test, feature = "fault-injection")))]
#[inline]
pub(crate) fn observed<T>(buffer: WipedBuffer, value: T) -> Observed<T> {
    let _ = buffer;
    value
}

/// A polynomial temporary of key generation, encryption or decryption.
/// When it is dropped it drops the value, so `Poly`'s `Drop` zeroizes every
/// coefficient, and records one wipe of `buffer` that is clean only if at
/// least one polynomial was dropped and each was left all zero.
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) struct Observed<T> {
    value: Option<T>,
    buffer: WipedBuffer,
}

/// Wraps `value` as the temporary `buffer` and records its construction.
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn observed<T>(buffer: WipedBuffer, value: T) -> Observed<T> {
    crate::seam::record_temporary(buffer);
    Observed {
        value: Some(value),
        buffer,
    }
}

#[cfg(all(test, feature = "fault-injection"))]
#[allow(clippy::unreachable, reason = "the value is taken only by drop")]
impl<T> core::ops::Deref for Observed<T> {
    type Target = T;

    fn deref(&self) -> &T {
        match &self.value {
            Some(value) => value,
            None => unreachable!(),
        }
    }
}

#[cfg(all(test, feature = "fault-injection"))]
#[allow(clippy::unreachable, reason = "the value is taken only by drop")]
impl<T> core::ops::DerefMut for Observed<T> {
    fn deref_mut(&mut self) -> &mut T {
        match &mut self.value {
            Some(value) => value,
            None => unreachable!(),
        }
    }
}

#[cfg(all(test, feature = "fault-injection"))]
impl<T> Drop for Observed<T> {
    fn drop(&mut self) {
        let (drops, unzeroed) = crate::wipe_witness::counts();
        drop(self.value.take());
        let (drops_after, unzeroed_after) = crate::wipe_witness::counts();
        crate::seam::record_wipe(
            self.buffer,
            drops_after > drops && unzeroed_after == unzeroed,
        );
    }
}

/// An `N`-byte buffer that is zeroized when it is dropped, so every exit of
/// the scope that holds it clears it.
pub(crate) struct Tagged<const N: usize> {
    pub(crate) bytes: [u8; N],
    buffer: WipedBuffer,
}

impl<const N: usize> Tagged<N> {
    pub(crate) fn new(buffer: WipedBuffer) -> Self {
        #[cfg(all(test, feature = "fault-injection"))]
        crate::seam::record_temporary(buffer);
        Self {
            bytes: [0u8; N],
            buffer,
        }
    }
}

impl<const N: usize> Drop for Tagged<N> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.bytes);
        #[cfg(all(test, feature = "fault-injection"))]
        crate::seam::record_wipe(self.buffer, self.bytes.iter().all(|&b| b == 0));
        #[cfg(not(all(test, feature = "fault-injection")))]
        let _ = self.buffer;
    }
}
