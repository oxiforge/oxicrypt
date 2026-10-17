//! Test-only counters of the candidates the signing loop rejects, per check.
//!
//! The signing loop records each rejection here under `cfg(test)`, so a test
//! can show which rejection paths a fixed signing input drives. Counts are
//! per thread, because the loop runs on the calling thread and the test
//! harness runs other signing tests in parallel.

extern crate std;

use core::cell::Cell;

/// Index of the ‖z‖∞ ≥ γ1 − β check.
pub(crate) const Z: usize = 0;
/// Index of the ‖r0‖∞ ≥ γ2 − β check.
pub(crate) const R0: usize = 1;
/// Index of the ‖ct0‖∞ ≥ γ2 check.
pub(crate) const CT0: usize = 2;
/// Index of the number-of-hints > ω check.
pub(crate) const HINT: usize = 3;

std::thread_local! {
    static COUNTS: Cell<[u32; 4]> = const { Cell::new([0; 4]) };
}

/// Count one rejection by the check at `index`.
pub(crate) fn record(index: usize) {
    COUNTS.with(|c| {
        let mut counts = c.get();
        if let Some(n) = counts.get_mut(index) {
            *n = n.saturating_add(1);
        }
        c.set(counts);
    });
}

/// This thread's counts since the last call, as `[z, r0, ct0, hint]`, and
/// reset them to zero.
pub(crate) fn take() -> [u32; 4] {
    COUNTS.with(|c| c.replace([0; 4]))
}
