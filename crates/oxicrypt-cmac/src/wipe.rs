//! Zeroization of the crate's secret intermediates.
//!
//! Every wipe of a named intermediate goes through [`wipe`], which takes
//! the buffer's identity as a [`WipedBuffer`]; a [`WipedBlock`] makes that
//! call when it is dropped. With the `fault-injection` feature each call
//! is also counted per identity, so a test can observe that a buffer was
//! wiped on a given path. Without the feature [`wipe`] is
//! [`oxicrypt_zeroize::zeroize`] and nothing is recorded.

/// The intermediate a [`wipe`] call clears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WipedBuffer {
    /// L = CIPH_K(0^128), from which K1 and K2 are derived (SP 800-38B
    /// §6.1).
    L,
    /// The subkey K1 (SP 800-38B §6.1).
    K1,
    /// The subkey K2 (SP 800-38B §6.1).
    K2,
    /// The CBC-MAC state of a tag computation, which ends as the full
    /// 128-bit tag.
    MacState,
    /// The final message block masked with K1 or K2 (SP 800-38B §6.2).
    FinalBlock,
    /// The accumulated XOR of a computed tag with a received MAC in a
    /// verification.
    TagDiff,
}

/// A 16-byte intermediate that is wiped through [`wipe`] when it is
/// dropped, so every exit of the scope that holds it clears it.
pub(crate) struct WipedBlock {
    pub(crate) bytes: [u8; 16],
    buffer: WipedBuffer,
}

impl WipedBlock {
    pub(crate) const fn new(buffer: WipedBuffer) -> Self {
        Self {
            bytes: [0u8; 16],
            buffer,
        }
    }
}

impl Drop for WipedBlock {
    fn drop(&mut self) {
        wipe(self.buffer, &mut self.bytes);
    }
}

pub(crate) fn wipe(buffer: WipedBuffer, bytes: &mut [u8]) {
    oxicrypt_zeroize::zeroize(bytes);
    #[cfg(feature = "fault-injection")]
    seam::record(buffer);
    #[cfg(not(feature = "fault-injection"))]
    let _ = buffer;
}

/// Per-identity wipe counters, process-global.
#[cfg(feature = "fault-injection")]
pub(crate) mod seam {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::WipedBuffer;

    /// Counter slots, one per [`WipedBuffer`] variant, indexed by its
    /// discriminant: the last variant's discriminant plus one.
    const SLOTS: usize = WipedBuffer::TagDiff as usize + 1;

    static WIPES: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

    pub(super) fn record(buffer: WipedBuffer) {
        if let Some(count) = WIPES.get(buffer as usize) {
            count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The number of wipes of `buffer` in this process so far.
    #[cfg(test)]
    pub(crate) fn wipes(buffer: WipedBuffer) -> u64 {
        WIPES
            .get(buffer as usize)
            .map_or(0, |count| count.load(Ordering::SeqCst))
    }
}
