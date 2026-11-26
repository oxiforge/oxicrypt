//! Test seams for the key-generation services, compiled only with the
//! `fault-injection` feature or in this crate's own tests. In this crate's
//! own tests with the feature, it also counts the constructions and wipes of
//! the buffers of `crate::wipe` per thread.
//!
//! [`corrupt_next_pk`](crate::seam::corrupt_next_pk) is process-global: one flag, shared by the three
//! parameter sets, consumed by the next key generation in the process
//! whichever set it is. With the flag clear, key generation takes its
//! production path unchanged.
//!
//! The module also holds the ACVP key-generation vectors for ML-DSA-44 and
//! ML-DSA-65 that the crate's unit tests and its fault tests check
//! `expand_key` against.

#[cfg(all(test, feature = "fault-injection"))]
extern crate std;

use core::sync::atomic::{AtomicBool, Ordering};

static CORRUPT_NEXT_PK: AtomicBool = AtomicBool::new(false);

/// Arms the next key generation in the process, through `keygen`,
/// `keygen_with_seed` or `expand_key` of any parameter set, to flip every bit
/// of byte 1 of the encoded public key before its pairwise consistency test.
/// The test then fails, and the module enters its error state.
pub fn corrupt_next_pk() {
    CORRUPT_NEXT_PK.store(true, Ordering::SeqCst);
}

/// Whether [`corrupt_next_pk`] armed this call; clears the flag.
pub(crate) fn take_corrupt_next_pk() -> bool {
    CORRUPT_NEXT_PK.swap(false, Ordering::SeqCst)
}

/// ML-DSA-44 key-generation seed ξ, ACVP ML-DSA specification
/// (draft-celi-acvp-ml-dsa-01) §6.1.2 Table 1, row 1.
pub const ML_DSA_44_ACVP_SEED: [u8; 32] = crate::cast_vectors::ml_dsa_44::REJ_SEED;

/// SHA2-256(pk ‖ sk) of the key pair [`ML_DSA_44_ACVP_SEED`] expands to,
/// from the same row.
pub const ML_DSA_44_ACVP_KEY_HASH: [u8; 32] = crate::cast_vectors::ml_dsa_44::REJ_KEY_HASH;

/// ML-DSA-65 key-generation seed ξ, ACVP ML-DSA specification
/// (draft-celi-acvp-ml-dsa-01) §6.1.2 Table 1, row 6, as vendored in
/// `vendor/nist/acvp-ml-dsa-spec/draft-celi-acvp-ml-dsa-01.html`.
pub const ML_DSA_65_ACVP_SEED: [u8; 32] = [
    0x46, 0x47, 0x56, 0xa9, 0x85, 0xe5, 0xdf, 0x03, 0x73, 0x9d, 0x95, 0xdd, 0x30, 0x9c, 0x1e, 0xd9,
    0xc5, 0xb0, 0x42, 0x54, 0xcc, 0x29, 0x4e, 0x7e, 0x7e, 0xb9, 0xb9, 0x36, 0x5e, 0xe1, 0x51, 0x17,
];

/// SHA2-256(pk ‖ sk) of the key pair [`ML_DSA_65_ACVP_SEED`] expands to,
/// from the same row.
pub const ML_DSA_65_ACVP_KEY_HASH: [u8; 32] = [
    0xae, 0x95, 0xea, 0x0d, 0xaa, 0x80, 0x19, 0x9e, 0x7b, 0x4a, 0x74, 0xeb, 0x5a, 0x1b, 0x1d, 0xc6,
    0xc3, 0x80, 0x5b, 0xd0, 0x1d, 0x2f, 0xa7, 0x8d, 0x7c, 0x4f, 0xba, 0x8c, 0x25, 0x5a, 0xa1, 0x3d,
];

#[cfg(all(test, feature = "fault-injection"))]
const SLOTS: usize = crate::wipe::ALL.len();

// Per thread, so a test reads only the buffers of its own calls while other
// tests generate keys alongside it.
#[cfg(all(test, feature = "fault-injection"))]
std::thread_local! {
    static TEMPORARIES: [core::cell::Cell<u64>; SLOTS] =
        const { [const { core::cell::Cell::new(0) }; SLOTS] };
    static WIPES: [core::cell::Cell<u64>; SLOTS] =
        const { [const { core::cell::Cell::new(0) }; SLOTS] };
    static UNWIPED: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(all(test, feature = "fault-injection"))]
fn bump(slots: &[core::cell::Cell<u64>; SLOTS], buffer: crate::wipe::WipedBuffer) {
    if let Some(slot) = slots.get(buffer as usize) {
        slot.set(slot.get().saturating_add(1));
    }
}

#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn record_temporary(buffer: crate::wipe::WipedBuffer) {
    TEMPORARIES.with(|slots| bump(slots, buffer));
}

#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn record_wipe(buffer: crate::wipe::WipedBuffer, zero_after: bool) {
    WIPES.with(|slots| bump(slots, buffer));
    if !zero_after {
        UNWIPED.with(|c| c.set(c.get().saturating_add(1)));
    }
}

/// The number of `buffer`s constructed on this thread since [`reset`].
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn temporaries(buffer: crate::wipe::WipedBuffer) -> u64 {
    TEMPORARIES.with(|slots| slots.get(buffer as usize).map_or(0, core::cell::Cell::get))
}

/// The number of `buffer`s wiped on this thread since [`reset`].
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn wipes(buffer: crate::wipe::WipedBuffer) -> u64 {
    WIPES.with(|slots| slots.get(buffer as usize).map_or(0, core::cell::Cell::get))
}

/// The number of wipes on this thread since [`reset`] that left a nonzero
/// byte.
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn unwiped() -> u64 {
    UNWIPED.with(core::cell::Cell::get)
}

/// Zeroes this thread's counters.
#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn reset() {
    TEMPORARIES.with(|slots| slots.iter().for_each(|s| s.set(0)));
    WIPES.with(|slots| slots.iter().for_each(|s| s.set(0)));
    UNWIPED.with(|c| c.set(0));
}
