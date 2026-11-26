//! Zeroization of the seed, intermediates and key copies of the
//! key-generation services, each under its own identity.
//!
//! Every byte buffer listed in [`WipedBuffer`] is held in a [`Tagged`],
//! which zeroizes it when it is dropped, and every polynomial temporary in
//! an [`Observed`], whose value `Poly`'s `Drop` zeroizes. In this crate's
//! own tests with the
//! `fault-injection` feature each construction and each wipe is also
//! counted per identity, on the calling thread, so a test can observe that a
//! buffer was wiped on a given exit. Otherwise nothing is recorded.

/// The identity of a temporary: the byte buffer a [`Tagged`] holds, or the
/// polynomial value an [`Observed`] holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WipedBuffer {
    /// The seed ξ drawn from the caller's RBG (FIPS 204 Algorithm 1 step 1).
    Xi,
    /// The public seed ρ (FIPS 204 Algorithm 6 step 1).
    Rho,
    /// The private seed ρ′ (FIPS 204 Algorithm 6 step 1).
    RhoPrime,
    /// The private seed K (FIPS 204 Algorithm 6 step 1).
    Key,
    /// tr = H(pk, 64) (FIPS 204 Algorithm 6 step 9).
    Tr,
    /// The module's copy of a generated public key.
    PublicKey,
    /// The module's copy of a generated private key.
    SecretKey,
    /// The signature the pairwise consistency test signs and verifies.
    PctSignature,
    /// Â = ExpandA(ρ) (FIPS 204 Algorithm 6 step 3).
    KeygenA,
    /// s₁ (FIPS 204 Algorithm 6 step 4).
    KeygenS1,
    /// s₂ (FIPS 204 Algorithm 6 step 4).
    KeygenS2,
    /// NTT(s₁) (FIPS 204 Algorithm 6 step 5).
    KeygenS1Hat,
    /// t (FIPS 204 Algorithm 6 step 5).
    KeygenT,
    /// t₁ (FIPS 204 Algorithm 6 step 6).
    KeygenT1,
    /// t₀ (FIPS 204 Algorithm 6 step 6).
    KeygenT0,
    /// s₁ decoded from the private key (FIPS 204 Algorithm 7 step 1).
    SignS1,
    /// s₂ decoded from the private key (FIPS 204 Algorithm 7 step 1).
    SignS2,
    /// t₀ decoded from the private key (FIPS 204 Algorithm 7 step 1).
    SignT0,
    /// Â (FIPS 204 Algorithm 7 step 5).
    SignA,
    /// NTT(s₁) (FIPS 204 Algorithm 7 step 2).
    SignS1Hat,
    /// NTT(s₂) (FIPS 204 Algorithm 7 step 3).
    SignS2Hat,
    /// NTT(t₀) (FIPS 204 Algorithm 7 step 4).
    SignT0Hat,
    /// The mask y (FIPS 204 Algorithm 7 step 11).
    SignY,
    /// NTT(y) (FIPS 204 Algorithm 7 step 12).
    SignYHat,
    /// w (FIPS 204 Algorithm 7 step 12).
    SignW,
    /// w₁ (FIPS 204 Algorithm 7 step 13).
    SignW1,
    /// w₀, the low bits of w (FIPS 204 Algorithm 7 step 21).
    SignW0,
    /// The challenge c (FIPS 204 Algorithm 7 step 16).
    SignC,
    /// NTT(c) (FIPS 204 Algorithm 7 step 17).
    SignCHat,
    /// The response z (FIPS 204 Algorithm 7 step 20).
    SignZ,
    /// c·s₂ (FIPS 204 Algorithm 7 step 19).
    SignCs2,
    /// r₀ = LowBits(w − c·s₂) (FIPS 204 Algorithm 7 step 21).
    SignR0,
    /// c·t₀ (FIPS 204 Algorithm 7 step 25).
    SignCt0,
    /// The hint input r₀ + c·t₀, centred (FIPS 204 Algorithm 7 step 26).
    SignA0,
    /// The hint h (FIPS 204 Algorithm 7 step 26).
    SignHint,
    /// t₁ decoded from the public key (FIPS 204 Algorithm 8 step 1).
    VerifyT1,
    /// z decoded from the signature (FIPS 204 Algorithm 8 step 2).
    VerifyZ,
    /// h decoded from the signature (FIPS 204 Algorithm 8 step 2).
    VerifyHint,
    /// Â (FIPS 204 Algorithm 8 step 5).
    VerifyA,
    /// The challenge c (FIPS 204 Algorithm 8 step 8).
    VerifyC,
    /// NTT(c) (FIPS 204 Algorithm 8 step 9).
    VerifyCHat,
    /// NTT(z) (FIPS 204 Algorithm 8 step 9).
    VerifyZHat,
    /// w′_Approx (FIPS 204 Algorithm 8 step 9).
    VerifyWPrime,
    /// NTT(t₁·2ᵈ) (FIPS 204 Algorithm 8 step 9).
    VerifyT1Scaled,
    /// NTT(c)·NTT(t₁·2ᵈ) (FIPS 204 Algorithm 8 step 9).
    VerifyCt1,
    /// w₁′ = UseHint(h, w′_Approx) (FIPS 204 Algorithm 8 step 10).
    VerifyW1Prime,
    /// The private seed K decoded from the private key (FIPS 204
    /// Algorithm 7 step 1).
    SignKey,
    /// μ (FIPS 204 Algorithm 7 step 6).
    SignMu,
    /// The private random seed ρ″ (FIPS 204 Algorithm 7 step 7).
    SignRhoPrimePrime,
}

/// Every [`WipedBuffer`], in declaration order, for the tests that check
/// each one.
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) const ALL: [WipedBuffer; 49] = {
    use WipedBuffer::*;
    [
        Xi,
        Rho,
        RhoPrime,
        Key,
        Tr,
        PublicKey,
        SecretKey,
        PctSignature,
        KeygenA,
        KeygenS1,
        KeygenS2,
        KeygenS1Hat,
        KeygenT,
        KeygenT1,
        KeygenT0,
        SignS1,
        SignS2,
        SignT0,
        SignA,
        SignS1Hat,
        SignS2Hat,
        SignT0Hat,
        SignY,
        SignYHat,
        SignW,
        SignW1,
        SignW0,
        SignC,
        SignCHat,
        SignZ,
        SignCs2,
        SignR0,
        SignCt0,
        SignA0,
        SignHint,
        VerifyT1,
        VerifyZ,
        VerifyHint,
        VerifyA,
        VerifyC,
        VerifyCHat,
        VerifyZHat,
        VerifyWPrime,
        VerifyT1Scaled,
        VerifyCt1,
        VerifyW1Prime,
        SignKey,
        SignMu,
        SignRhoPrimePrime,
    ]
};

// Each variant at its own discriminant, so the list holds every variant
// exactly once.
#[cfg(all(test, feature = "fault-injection"))]
#[allow(
    clippy::indexing_slicing,
    reason = "the loop bound keeps i below ALL.len()"
)]
const _: () = {
    let mut i = 0;
    while i < ALL.len() {
        assert!(ALL[i] as usize == i);
        i += 1;
    }
    assert!(WipedBuffer::SignRhoPrimePrime as usize + 1 == ALL.len());
};

/// A polynomial temporary of key expansion, signing or verification, which
/// `Poly`'s `Drop` zeroizes. Outside this crate's own tests with the
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

/// A polynomial temporary of key expansion, signing or verification. When
/// it is dropped it drops the value, so `Poly`'s `Drop` zeroizes every
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
    #[cfg(all(test, feature = "fault-injection"))]
    buffer: WipedBuffer,
}

impl<const N: usize> Tagged<N> {
    pub(crate) fn new(buffer: WipedBuffer) -> Self {
        #[cfg(all(test, feature = "fault-injection"))]
        crate::seam::record_temporary(buffer);
        #[cfg(not(all(test, feature = "fault-injection")))]
        let _ = buffer;
        Self {
            bytes: [0u8; N],
            #[cfg(all(test, feature = "fault-injection"))]
            buffer,
        }
    }
}

impl<const N: usize> Drop for Tagged<N> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.bytes);
        #[cfg(all(test, feature = "fault-injection"))]
        crate::seam::record_wipe(self.buffer, self.bytes.iter().all(|&b| b == 0));
    }
}
