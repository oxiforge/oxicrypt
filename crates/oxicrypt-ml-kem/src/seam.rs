//! Test seams for the key-generation services, compiled only with the
//! `fault-injection` feature or in this crate's own tests. In this crate's
//! own tests with the feature, it also counts the constructions and wipes of
//! the buffers of `crate::wipe` per thread.
//!
//! [`corrupt_next_dk`](crate::seam::corrupt_next_dk) is process-global: one flag, shared by the three
//! parameter sets, consumed by the next key generation in the process
//! whichever set it is. With the flag clear, key generation takes its
//! production path unchanged.

#[cfg(all(test, feature = "fault-injection"))]
extern crate std;

use core::sync::atomic::{AtomicBool, Ordering};

static CORRUPT_NEXT_DK: AtomicBool = AtomicBool::new(false);

/// Arms the next key generation in the process, through `keygen`,
/// `keygen_with_seed` or `expand_key` of any parameter set, to flip every bit
/// of byte 0 of `dk_PKE`, the first byte of the decapsulation key, before its
/// pairwise consistency test. The decapsulated secret then differs from the
/// encapsulated one, the test fails, and the module enters its error state.
pub fn corrupt_next_dk() {
    CORRUPT_NEXT_DK.store(true, Ordering::SeqCst);
}

/// Whether [`corrupt_next_dk`] armed this call; clears the flag.
pub(crate) fn take_corrupt_next_dk() -> bool {
    CORRUPT_NEXT_DK.swap(false, Ordering::SeqCst)
}

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
