//! The test seam for the key-generation services, compiled only with the
//! `fault-injection` feature or in this crate's own tests.
//!
//! [`corrupt_next_pk`](crate::seam::corrupt_next_pk) is process-global:
//! one flag, shared by P-256 and P-384, read and cleared at the entry of
//! the next key generation in the process whichever curve it is. With the
//! flag clear, key generation takes its production path unchanged.
//!
//! The fault takes the public key off the curve, so the pairwise
//! consistency test exercised is the path where public-key validation
//! refuses the new key.

use core::sync::atomic::{AtomicBool, Ordering};

static CORRUPT_NEXT_PK: AtomicBool = AtomicBool::new(false);

/// Arms the next key generation in the process, through
/// `generate_keypair_p256` or `generate_keypair_p384`, to flip every bit
/// of byte 1 of the encoded public key, the first byte of its
/// x-coordinate, before its pairwise consistency test. The test then
/// fails, and the module enters its error state.
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
