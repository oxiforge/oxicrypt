//! Zeroization of the intermediate buffers listed in [`WipedBuffer`].
//!
//! Every wipe of a listed intermediate goes through [`wipe`], which takes
//! the buffer's identity as a [`WipedBuffer`]; a [`Wiped`] guard makes
//! that call when it is dropped. With the `fault-injection`
//! feature each call is also counted per identity, so a test can observe
//! that a buffer was wiped on a given path. Without the feature [`wipe`]
//! is [`oxicrypt_zeroize::zeroize`] and nothing is recorded.

use oxicrypt_zeroize::Zeroizing;

/// The intermediate a [`wipe`] call clears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WipedBuffer {
    /// The 96-bit GCM IV, a CSP from its generation until the
    /// authenticated encryption consumes it (SP 800-38D §9.1 item 2;
    /// FIPS 140-3 IG C.H Additional Comment 10).
    GcmIv,
    /// The CBC-MAC state of a CCM decryption, which depends on the
    /// decrypted payload (SP 800-38C §6.2 step 9, Y).
    CcmMacState,
    /// A 16-byte CCM decryption local: a keystream block, a decrypted
    /// payload block, or S0 and then the recomputed tag (SP 800-38C §6.2
    /// steps 5 to 10).
    CcmBlock,
    /// The 16-byte working block of a KW or KWP unwrap, which holds a
    /// semiblock of unverified plaintext until it is dropped
    /// (SP 800-38F §6.1 Algorithm 2).
    KwBlock,
    /// The caller's output buffer of a KW or KWP unwrap, cleared on every
    /// refusal past the service gates so that no unverified plaintext is
    /// left in it (SP 800-38F §6.2 Algorithm 4 step 3, §6.3 Algorithm 6
    /// steps 4, 7 and 8).
    KwUnwrapOutput,
    /// The GHASH subkey H = CIPH_K(0^128) of a GCM encryption or
    /// decryption (SP 800-38D §7.1 step 1; secret per §5.3).
    GcmHashKey,
    /// The pre-counter block J0 (SP 800-38D §7.1 step 2; secret per §5.3).
    GcmPreCounterBlock,
    /// The running counter block of GCTR (SP 800-38D §6.5; secret per
    /// §5.3).
    GcmCounter,
    /// A GCTR keystream block CIPH_K(CB_i) (SP 800-38D §6.5; secret per
    /// §5.3).
    GcmKeystream,
    /// The GHASH accumulator, which ends as S (SP 800-38D §7.1 step 5;
    /// secret per §5.3).
    GcmGhashState,
    /// CIPH_K(J0), the mask of the tag (SP 800-38D §7.1 step 6; secret
    /// per §5.3).
    GcmTagMask,
    /// The computed tag before it is copied out or compared (SP 800-38D
    /// §7.1 step 6, §7.2 step 8; secret per §5.3 until it is output).
    GcmTag,
    /// The CBC-MAC state Y of a CCM encryption (SP 800-38C §6.1 step 3).
    CcmEncryptMacState,
    /// S0 = CIPH_K(Ctr_0), the tag mask of a CCM encryption (SP 800-38C
    /// §6.1 steps 5 to 8).
    CcmEncryptTagMask,
    /// A keystream block S_j of a CCM encryption (SP 800-38C §6.1 steps 5
    /// and 6).
    CcmEncryptKeystream,
    /// The 16-byte working block of a KW or KWP wrap, which holds a
    /// semiblock of the key being wrapped before each cipher call
    /// (SP 800-38F §6.1 Algorithm 1, §6.3 Algorithm 5 step 5).
    KwWrapBlock,
    /// The 64-bit register A of a KW or KWP wrap or unwrap, through W and
    /// W⁻¹ and every exit from them. It starts as the ICV and, during an
    /// unwrap, ends as the recovered integrity value before it is checked
    /// (SP 800-38F §6.1 Algorithm 1 step 2, Algorithm 2 step 2).
    KwRegister,
    /// The running counter block T_j of CTR mode (SP 800-38A §6.5), an
    /// intermediate of the encryption treated as secret, as
    /// [`Self::GcmCounter`] is.
    CtrCounter,
    /// A CTR output block O_j = CIPH_K(T_j) (SP 800-38A §6.5), which with
    /// the ciphertext gives the plaintext, so a secret intermediate.
    CtrKeystream,
    /// The word `temp` of the key expansion, a copy of round-key material
    /// (FIPS 197 §5.2 KeyExpansion).
    KeyExpansionWord,
    /// A working operand of one GHASH multiplication: the shifted copy of
    /// H, the partial product, or the product before it replaces the
    /// accumulator (SP 800-38D §6.3 Algorithm 1, V and Z; secret per
    /// §5.3).
    GcmGhashOperand,
    /// The caller's output buffer of a KW or KWP wrap, cleared on every
    /// error past the service gates and the length checks: it is filled
    /// with the key being wrapped before W runs, and that key is key
    /// material in transit (SP 800-38F §6.1 Algorithm 1, §6.3
    /// Algorithm 5).
    KwWrapOutput,
    /// The 16-byte block of a CCM encryption's CBC-MAC that holds a
    /// plaintext block, zero-padded, before it is absorbed (SP 800-38C
    /// §6.1 step 2, the blocks B_i of the payload).
    CcmPlaintextBlock,
    /// The 16-byte working block of an ECB encryption or decryption,
    /// which holds a plaintext block on the way in or out (SP 800-38A
    /// §6.1).
    EcbBlock,
    /// The 16-byte working block of a CBC encryption or decryption,
    /// which holds a plaintext block XORed with the chaining value, or the
    /// recovered plaintext block (SP 800-38A §6.2).
    CbcBlock,
    /// The tag of a GCM encryption between the core writing it and its
    /// copy into the returned value (SP 800-38D §7.1 step 6; secret per
    /// §5.3 until it is output).
    GcmSealTag,
    /// The expanded round-key schedule of an AES key (FIPS 197 §5.2),
    /// wiped when the key is dropped.
    RoundKeys,
}

/// An `N`-byte intermediate that is wiped through [`wipe`] when it is
/// dropped, so every exit of the function that holds it clears it.
pub(crate) struct Wiped<const N: usize> {
    pub(crate) bytes: [u8; N],
    buffer: WipedBuffer,
}

pub(crate) type WipedBlock = Wiped<16>;

/// A wiped 8-byte semiblock (SP 800-38F §5.1).
pub(crate) type WipedSemiblock = Wiped<8>;

impl<const N: usize> Wiped<N> {
    pub(crate) const fn new(buffer: WipedBuffer) -> Self {
        Self {
            bytes: [0u8; N],
            buffer,
        }
    }
}

impl<const N: usize> Drop for Wiped<N> {
    fn drop(&mut self) {
        wipe(self.buffer, &mut self.bytes);
    }
}

/// Zeroizes `bytes`, the contents of the intermediate `buffer`.
pub(crate) fn wipe(buffer: WipedBuffer, bytes: &mut [u8]) {
    oxicrypt_zeroize::zeroize(bytes);
    #[cfg(feature = "fault-injection")]
    seam::record(buffer);
    #[cfg(not(feature = "fault-injection"))]
    let _ = buffer;
}

/// Zeroizes the generated GCM IV. Its parameter type is the IV's storage
/// type, so the IV cannot be held in anything else.
pub(crate) fn wipe_gcm_iv(iv: &mut Zeroizing<[u8; 12]>) {
    wipe(WipedBuffer::GcmIv, &mut iv[..]);
}

/// Per-identity wipe counters, process-global.
#[cfg(feature = "fault-injection")]
pub(crate) mod seam {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::WipedBuffer;

    /// Counter slots; a [`WipedBuffer`] variant indexes one by its
    /// discriminant.
    const SLOTS: usize = 32;

    const _: () = assert!((WipedBuffer::RoundKeys as usize) < SLOTS);

    static WIPES: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

    pub(super) fn record(buffer: WipedBuffer) {
        if let Some(count) = WIPES.get(buffer as usize) {
            count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The number of wipes of `buffer` in this process so far.
    pub(crate) fn wipes(buffer: WipedBuffer) -> u64 {
        WIPES
            .get(buffer as usize)
            .map_or(0, |count| count.load(Ordering::SeqCst))
    }
}
