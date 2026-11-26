//! Zeroization of the generate temporaries that hold output blocks.
//!
//! Every wipe of a temporary listed in [`WipedBuffer`] goes through
//! [`wipe`], which takes the buffer's identity as a [`WipedBuffer`]; a
//! [`Wiped`] makes that call when it is dropped. In this crate's own tests
//! with the `fault-injection` feature each construction and each wipe is
//! also counted per identity, on the calling thread, so a test can observe
//! that a buffer was wiped on a given path. Otherwise [`wipe`] is [`oxicrypt_zeroize::zeroize`] and
//! nothing is recorded.

/// The temporary a [`wipe`] call clears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WipedBuffer {
    /// HMAC_DRBG's copy of V that is the HMAC input of the next output
    /// block, the previous output block from the second block on
    /// (SP 800-90A §10.1.2.5 step 4.1).
    HmacGenerateInput,
    /// HMAC_DRBG's V = HMAC(Key, V), an output block (SP 800-90A §10.1.2.5
    /// steps 4.1 and 4.2).
    HmacGenerateBlock,
    /// The tag of one HMAC call, an output block when the call is a
    /// generate step (SP 800-90A §10.1.2.5 step 4.1).
    HmacTag,
    /// HMAC_DRBG_Update's copy of V, the last output block when the update
    /// follows a generate (SP 800-90A §10.1.2.2, §10.1.2.5 step 6).
    HmacUpdateV,
    /// CTR_DRBG's output block CIPH_Key(V) (SP 800-90A §10.2.1.5.1 step
    /// 4.2, §10.2.1.5.2 step 4.2).
    CtrGenerateBlock,
}

/// An `N`-byte temporary that is wiped through [`wipe`] when it is dropped,
/// so every exit of the scope that holds it clears it.
pub(crate) struct Wiped<const N: usize> {
    pub(crate) bytes: [u8; N],
    buffer: WipedBuffer,
}

impl<const N: usize> Wiped<N> {
    pub(crate) fn new(buffer: WipedBuffer) -> Self {
        #[cfg(all(test, feature = "fault-injection"))]
        crate::seam::record_temporary(buffer);
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

/// Zeroizes `bytes`, the contents of the temporary `buffer`.
pub(crate) fn wipe(buffer: WipedBuffer, bytes: &mut [u8]) {
    oxicrypt_zeroize::zeroize(bytes);
    #[cfg(all(test, feature = "fault-injection"))]
    crate::seam::record_wipe(buffer, bytes.iter().all(|b| *b == 0));
    #[cfg(not(all(test, feature = "fault-injection")))]
    let _ = buffer;
}

#[cfg(all(test, feature = "fault-injection"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::WipedBuffer::{self, *};
    use crate::ctr::{CtrDrbg, CtrDrbgAes256, DrbgError};
    use crate::hmac::HmacDrbgSha256;
    use crate::seam::{temporaries, unwiped_temporaries, wipes};
    use crate::test_support::start_module;
    use oxicrypt_module::{Error, State};
    use std::vec::Vec;

    /// An output gate that refuses, as one does once the module has left
    /// `Operational` during the call.
    #[allow(clippy::unnecessary_wraps)]
    fn refuse() -> Result<(), Error> {
        Err(Error::NotOperational {
            current: State::Error,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn admit() -> Result<(), Error> {
        Ok(())
    }

    /// How many temporaries of each identity a path must build.
    #[derive(Clone, Copy)]
    enum Built {
        AtLeastOne,
        Nothing,
    }

    fn path(name: &str, touched: &[WipedBuffer], built: Built, body: impl FnOnce()) {
        let before: Vec<(u64, u64)> = touched
            .iter()
            .map(|b| (temporaries(*b), wipes(*b)))
            .collect();
        let unwiped = unwiped_temporaries();
        body();
        assert_eq!(before.len(), touched.len());
        for (buffer, (made, wiped)) in touched.iter().zip(before) {
            let made = temporaries(*buffer).saturating_sub(made);
            let wiped = wipes(*buffer).saturating_sub(wiped);
            match built {
                Built::AtLeastOne => assert!(made > 0, "{name}: no {buffer:?} was built"),
                Built::Nothing => assert_eq!(made, 0, "{name}: {buffer:?} built {made}"),
            }
            assert_eq!(
                wiped, made,
                "{name}: {buffer:?} built {made}, wiped {wiped}"
            );
        }
        assert_eq!(
            unwiped_temporaries(),
            unwiped,
            "{name}: a temporary read non-zero"
        );
    }

    /// HMAC_DRBG's and CTR_DRBG's generate temporaries that hold output
    /// blocks are wiped through the seam on success and on the error exit
    /// of an output gate that refuses (SP 800-90A §9.3, §10.1.2.5,
    /// §10.2.1.5). The counters are per thread, so tests running alongside
    /// do not reach them.
    #[test]
    fn generate_temporaries_zeroized() {
        start_module();
        let entropy = [0x11u8; 32];
        let nonce = [0x22u8; 16];

        let mut hmac = HmacDrbgSha256::new();
        hmac.instantiate_internal(&entropy, &nonce, b"").unwrap();
        let hmac_success = [HmacGenerateInput, HmacGenerateBlock, HmacTag, HmacUpdateV];
        path(
            "HMAC_DRBG generate",
            &hmac_success,
            Built::AtLeastOne,
            || {
                let mut out = [0u8; 80];
                hmac.generate_gated(admit, admit, None, &mut out).unwrap();
                assert_ne!(out, [0u8; 80]);
            },
        );
        let refused = "HMAC_DRBG generate, output refused";
        path(refused, &[HmacGenerateInput], Built::AtLeastOne, || {
            let mut out = [0x5au8; 80];
            let r = hmac.generate_gated(admit, refuse, None, &mut out);
            assert_eq!(r, Err(DrbgError::Module(refuse().unwrap_err())));
            assert_eq!(out, [0u8; 80]);
        });

        let mut ctr = CtrDrbgAes256::new();
        ctr.instantiate_df_internal(&entropy, &nonce, b"").unwrap();
        let body = CtrDrbg::generate_df_unwiped;
        path(
            "CTR_DRBG generate",
            &[CtrGenerateBlock],
            Built::AtLeastOne,
            || {
                let mut out = [0u8; 80];
                ctr.generate_gated(admit, admit, body, None, &mut out)
                    .unwrap();
                assert_ne!(out, [0u8; 80]);
            },
        );
        // The refusal comes before the first output block is built.
        let refused = "CTR_DRBG generate, output refused";
        path(refused, &[CtrGenerateBlock], Built::Nothing, || {
            let mut out = [0x5au8; 80];
            let r = ctr.generate_gated(admit, refuse, body, None, &mut out);
            assert_eq!(r, Err(DrbgError::Module(refuse().unwrap_err())));
            assert_eq!(out, [0u8; 80]);
        });
    }
}
