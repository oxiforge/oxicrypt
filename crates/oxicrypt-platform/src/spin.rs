//! A process-aware spin cell.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(test)]
use core::sync::atomic::AtomicU32;

use crate::process::process_id;

/// The bit the recorded process id carries while a thread resets the
/// cell, combined with the id of that thread's process. Process ids are
/// below it, so a marked value never equals an id, and the low bits say
/// which process the reset belongs to.
pub(crate) const RESET_MARK: u64 = 1 << 63;

/// The number of spin iterations [`SpinCell::lock`] makes before it
/// returns [`Busy`].
const SPIN_BOUND: u32 = 1 << 24;

/// [`SpinCell::lock`] spun for its whole bound without taking the cell.
///
/// The caller retries after a pause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy;

/// A process-global cell holding an `Option<T>` behind a spin lock,
/// rebuilt when a different process uses it.
///
/// [`SpinCell::lock`] takes the lock with `Acquire` ordering and the
/// guard releases it with `Release` ordering when dropped. `lock` spins
/// with [`core::hint::spin_loop`] for at most 2^24 iterations and then
/// returns [`Busy`]; that is an iteration bound, not a time, and `lock`
/// never blocks indefinitely. `Busy` means retry after a pause.
///
/// # Fork handling
///
/// The cell records the id of the process that last used it, starting
/// from `0` at [`SpinCell::new`]. When `lock` reads a recorded id that is
/// not [`process_id`], one thread resets the cell: it marks the record
/// with its own process id and the top bit set, discards the contents
/// without running their destructors, since they belong to another
/// process's memory image, clears the lock and records the current id.
/// Every other thread of the process reads the mark and waits for the
/// current id before it contends for the lock, so no thread holds the
/// cell while it is reset. The first `lock` in a process takes the same
/// path from `0`, with nothing to discard.
///
/// A process forked while one of its parent's threads was resetting the
/// cell inherits a mark that names the parent. No thread of the child
/// will finish that reset, so `lock` treats a mark naming another process
/// as a stale reset and resets the cell again for the current process.
///
/// A descendant that reuses a parent's process id after the parent exited
/// is not detected by this check.
pub struct SpinCell<T> {
    value: UnsafeCell<Option<T>>,
    locked: AtomicBool,
    pid: AtomicU64,
    bound: u32,
    /// The number of resets this cell has made.
    #[cfg(test)]
    pub(crate) resets: AtomicU32,
    /// Set for the duration of a reset.
    #[cfg(test)]
    pub(crate) in_reset: AtomicBool,
}

// SAFETY: the contents are reached only through a `SpinGuard`, and the
// lock admits one guard at a time, so sharing the cell between threads
// moves `T` between threads but never shares it; `T: Send` suffices.
unsafe impl<T: Send> Sync for SpinCell<T> {}

/// Exclusive access to the contents of a [`SpinCell`]. Dropping it
/// releases the lock.
pub struct SpinGuard<'a, T> {
    cell: &'a SpinCell<T>,
    // The guard hands out `&mut Option<T>`, so it is `Send` and `Sync`
    // exactly when `&mut T` is.
    _contents: PhantomData<&'a mut T>,
}

impl<T> SpinCell<T> {
    /// Creates an empty, unlocked cell with no recorded process.
    // A process-global cell is built in a `static`, which needs `const
    // fn new`; a `Default` implementation would add nothing usable there.
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub const fn new() -> Self {
        Self::bounded(SPIN_BOUND)
    }

    /// Creates an empty, unlocked cell whose [`SpinCell::lock`] spins for
    /// at most `bound` iterations, so a test can reach [`Busy`] quickly.
    #[cfg(any(test, feature = "fault-injection"))]
    #[must_use]
    pub const fn with_bound(bound: u32) -> Self {
        Self::bounded(bound)
    }

    const fn bounded(bound: u32) -> Self {
        Self {
            value: UnsafeCell::new(None),
            locked: AtomicBool::new(false),
            pid: AtomicU64::new(0),
            bound,
            #[cfg(test)]
            resets: AtomicU32::new(0),
            #[cfg(test)]
            in_reset: AtomicBool::new(false),
        }
    }

    /// Takes the lock, first resetting the cell if a different process
    /// used it last.
    ///
    /// # Errors
    ///
    /// [`Busy`] when the bound passed without the cell becoming
    /// available. Waiting for another thread's reset counts toward the
    /// same bound.
    pub fn lock(&self) -> Result<SpinGuard<'_, T>, Busy> {
        let current = process_id();
        let marked = RESET_MARK | current;
        let mut spins: u32 = 0;
        loop {
            let recorded = self.pid.load(Ordering::Acquire);
            if recorded == current {
                break;
            }
            // Any other value is another process's id, 0, or a reset mark
            // naming another process, whose resetting thread does not exist
            // here. Only a mark naming this process is a reset in progress.
            if recorded != marked
                && self
                    .pid
                    .compare_exchange(recorded, marked, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                self.reset();
                self.pid.store(current, Ordering::Release);
                break;
            }
            spins = self.spin(spins)?;
        }
        loop {
            if self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(SpinGuard {
                    cell: self,
                    _contents: PhantomData,
                });
            }
            spins = self.spin(spins)?;
        }
    }

    /// Discards another process's contents and clears its lock.
    fn reset(&self) {
        #[cfg(test)]
        self.in_reset.store(true, Ordering::SeqCst);
        // SAFETY: the calling thread swapped the recorded id to
        // `RESET_MARK` combined with the current id. Every other thread of
        // this process reads that mark and spins until the current id is
        // stored, and no thread of this process can hold a guard, because
        // a guard is taken only after reading the current id. No other
        // thread touches the contents.
        let stale = unsafe { (*self.value.get()).take() };
        // The contents belong to another process's memory image; running
        // their destructors here could free or wipe memory this process
        // does not own.
        core::mem::forget(stale);
        self.locked.store(false, Ordering::Release);
        #[cfg(test)]
        {
            // Widens the reset so an overlapping guard would be seen.
            for _ in 0..64 {
                core::hint::spin_loop();
            }
            self.resets.fetch_add(1, Ordering::SeqCst);
            self.in_reset.store(false, Ordering::SeqCst);
        }
    }

    /// Sets the recorded process id, as a reset or a use in another
    /// process would have left it.
    #[cfg(test)]
    pub(crate) fn set_recorded_pid(&self, pid: u64) {
        self.pid.store(pid, Ordering::SeqCst);
    }

    /// Counts one spin, or returns [`Busy`] once the bound is reached.
    fn spin(&self, spins: u32) -> Result<u32, Busy> {
        if spins >= self.bound {
            return Err(Busy);
        }
        core::hint::spin_loop();
        Ok(spins.saturating_add(1))
    }
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = Option<T>;

    fn deref(&self) -> &Option<T> {
        // SAFETY: the guard holds the lock, so no other reference to the
        // contents exists for the guard's lifetime.
        unsafe { &*self.cell.value.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Option<T> {
        // SAFETY: the guard holds the lock, and `&mut self` makes this the
        // only reference reached through it.
        unsafe { &mut *self.cell.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.cell.locked.store(false, Ordering::Release);
    }
}
