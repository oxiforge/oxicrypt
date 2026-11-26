//! The test seam for the key-generation service, compiled only with the
//! `fault-injection` feature or in this crate's own tests.
//!
//! [`corrupt_next_pk`](crate::seam::corrupt_next_pk) is process-global:
//! one flag, read and cleared at the entry of the next key generation in
//! the process. With the flag clear, key generation takes its production
//! path unchanged.
//!
//! The fault changes the encoded public key, so the pairwise consistency
//! test exercised is the path where the probe signature does not verify.

use core::sync::atomic::{AtomicBool, Ordering};

static CORRUPT_NEXT_PK: AtomicBool = AtomicBool::new(false);

/// Arms the next key generation in the process, through
/// `Ed25519PrivateKey::generate`, to flip every bit of byte 1 of the
/// encoded public key, a byte of its y-coordinate, before its pairwise
/// consistency test. The test then fails, and the module enters its error
/// state.
pub fn corrupt_next_pk() {
    CORRUPT_NEXT_PK.store(true, Ordering::SeqCst);
}

/// Disarms [`corrupt_next_pk`].
pub fn reset() {
    CORRUPT_NEXT_PK.store(false, Ordering::SeqCst);
}

/// Whether [`corrupt_next_pk`] armed this call; clears the flag.
pub(crate) fn take_corrupt_next_pk() -> bool {
    CORRUPT_NEXT_PK.swap(false, Ordering::SeqCst)
}
