//! The test seam for the key-generation services, compiled only with the
//! `fault-injection` feature or in this crate's own tests.
//!
//! [`corrupt_next_pk`](crate::seam::corrupt_next_pk) is process-global:
//! one flag, shared by RSA-2048, RSA-3072 and RSA-4096, read and cleared at
//! the entry of the next key generation in the process whichever size it
//! is. With the flag clear, key generation takes its production path
//! unchanged.
//!
//! The fault keeps `n` full-width and odd, so it passes the modulus shape
//! checks and reaches the arithmetic of the pairwise consistency test: the
//! CRT signature is recombined from `p` and `q`, which no longer match `n`,
//! and the Bellcore verify-after-sign check, `s^e mod n` compared with the
//! encoded message, refuses it. That check is the equation the outer
//! verification computes, so no corruption of `n` reaches the outer
//! verification without first failing it.

use core::sync::atomic::{AtomicBool, Ordering};

static CORRUPT_NEXT_PK: AtomicBool = AtomicBool::new(false);

/// Arms the next key generation in the process, through the `generate` of
/// any modulus size, to flip bit 0 of byte 0 of the big-endian modulus `n`
/// before its pairwise consistency test. The test then fails, and the
/// module enters its error state.
pub fn corrupt_next_pk() {
    CORRUPT_NEXT_PK.store(true, Ordering::SeqCst);
}

/// Disarms [`corrupt_next_pk`].
pub fn disarm() {
    CORRUPT_NEXT_PK.store(false, Ordering::SeqCst);
}

/// Whether [`corrupt_next_pk`] armed this call; clears the flag.
pub(crate) fn take_corrupt_next_pk() -> bool {
    CORRUPT_NEXT_PK.swap(false, Ordering::SeqCst)
}
