//! Observation of writes to a CCM decryption's output.
//!
//! [`ccm_decrypt`](crate::ccm_decrypt) marks the start of each decryption
//! with [`decryption_started`], reports each run of bytes it writes to the
//! caller's output with [`output_written`] and the result of its tag
//! comparison with [`tag_compared`]. The seam counts the writes the decrypt
//! path reports through it, not writes to the slice. With the
//! `fault-injection` feature it splits the reported bytes into those before
//! and after a comparison that returned equal in the same decryption, so a
//! test can observe that no output precedes verification. Without the
//! feature the calls do nothing.

pub(crate) fn decryption_started() {
    #[cfg(feature = "fault-injection")]
    seam::started();
}

pub(crate) fn output_written(len: usize) {
    #[cfg(feature = "fault-injection")]
    seam::written(len);
    #[cfg(not(feature = "fault-injection"))]
    let _ = len;
}

pub(crate) fn tag_compared(equal: bool) {
    #[cfg(feature = "fault-injection")]
    seam::compared(equal);
    #[cfg(not(feature = "fault-injection"))]
    let _ = equal;
}

/// Process-global write counters.
#[cfg(feature = "fault-injection")]
pub(crate) mod seam {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static VERIFIED: AtomicBool = AtomicBool::new(false);
    static BEFORE: AtomicU64 = AtomicU64::new(0);
    static AFTER: AtomicU64 = AtomicU64::new(0);

    pub(super) fn started() {
        VERIFIED.store(false, Ordering::SeqCst);
    }

    pub(super) fn written(len: usize) {
        let counter = if VERIFIED.load(Ordering::SeqCst) {
            &AFTER
        } else {
            &BEFORE
        };
        counter.fetch_add(len as u64, Ordering::SeqCst);
    }

    pub(super) fn compared(equal: bool) {
        if equal {
            VERIFIED.store(true, Ordering::SeqCst);
        }
    }

    /// The output bytes written in this process so far, as the count
    /// before any tag comparison returned equal and the count after.
    #[cfg(test)]
    pub(crate) fn writes() -> (u64, u64) {
        (BEFORE.load(Ordering::SeqCst), AFTER.load(Ordering::SeqCst))
    }
}

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::{decryption_started, output_written, seam::writes, tag_compared};

    /// A write that the second of two decryptions reports before its own
    /// comparison counts as before verification, though the first
    /// decryption's tag compared equal.
    #[test]
    fn verification_does_not_carry_into_the_next_decryption() {
        crate::test_support::isolated(
            "observe::tests::verification_does_not_carry_into_the_next_decryption",
            &["two decryptions"],
            |_| {
                decryption_started();
                tag_compared(true);
                output_written(3);
                decryption_started();
                output_written(2);
                assert_eq!(writes(), (2, 3));
            },
        );
    }
}
