//! Test seams for the platform calls, compiled only with the
//! `fault-injection` feature or in this crate's own tests.
//!
//! Every override is process-global. The process-id and `errno`
//! overrides live in atomics; pending generator results live in a
//! [`SpinCell`] of their own. With no override set, each call takes its
//! production path unchanged: the overrides are consulted first and fall
//! through when empty.
//!
//! - [`set_process_id_override`]: `Some(id)` makes [`process_id`] return
//!   `id` until it is cleared with `None`. Never change it while a
//!   [`SpinGuard`] is live, or a reset can run under that guard. Changing
//!   it also discards pending generator results, since their cell resets
//!   for the new id.
//! - [`set_os_random_result`]: `Some(r)` makes the next call to the
//!   platform generator return `r` instead of calling the operating
//!   system, once. Results set before any is consumed queue in order, up
//!   to four; a fifth replaces the fourth. `Ok(n)` reports `n` bytes
//!   written and leaves the buffer untouched, so `n` below the request
//!   simulates a short return and the loop continues with the next queued
//!   result or the real generator. `Err(Unavailable)` simulates a failed
//!   call. `Ok(usize::MAX)` simulates a call that returned -1, which is
//!   then classified by `errno`.
//! - [`set_errno_override`]: `Some(code)` makes every `errno` read return
//!   `code` until cleared. With `Some(4)` and `Ok(usize::MAX)` the next
//!   call simulates `EINTR`.
//! - [`SpinCell::with_bound`]: a cell with a reduced spin bound.
//! - [`fork_for_test`] and [`wait_for_child`] (Unix only): fork the
//!   process and wait for the child's exit status.
//!
//! [`process_id`]: crate::process_id

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use crate::{OsRandomError, SpinCell, SpinGuard};

static PID_SET: AtomicBool = AtomicBool::new(false);
static PID_VALUE: AtomicU64 = AtomicU64::new(0);

static ERRNO_SET: AtomicBool = AtomicBool::new(false);
static ERRNO_VALUE: AtomicI32 = AtomicI32::new(0);

/// The number of simulated generator results that can be pending.
const QUEUE_LEN: usize = 4;

/// Pending simulated generator results, oldest first.
static RESULTS: SpinCell<[Option<Result<usize, OsRandomError>>; QUEUE_LEN]> = SpinCell::new();

/// Locks the pending results, retrying while the cell is busy.
fn results() -> SpinGuard<'static, [Option<Result<usize, OsRandomError>>; QUEUE_LEN]> {
    loop {
        if let Ok(guard) = RESULTS.lock() {
            return guard;
        }
        core::hint::spin_loop();
    }
}

/// Makes [`process_id`](crate::process_id) return `id` until called with
/// `None`.
pub fn set_process_id_override(id: Option<u64>) {
    match id {
        Some(value) => {
            PID_VALUE.store(value, Ordering::SeqCst);
            PID_SET.store(true, Ordering::SeqCst);
        }
        None => PID_SET.store(false, Ordering::SeqCst),
    }
}

/// Makes every `errno` read return `code` until called with `None`.
pub fn set_errno_override(code: Option<i32>) {
    match code {
        Some(value) => {
            ERRNO_VALUE.store(value, Ordering::SeqCst);
            ERRNO_SET.store(true, Ordering::SeqCst);
        }
        None => ERRNO_SET.store(false, Ordering::SeqCst),
    }
}

/// Queues `result` as the outcome of a coming platform generator call,
/// consumed once; `None` clears every pending result. See the module
/// documentation for what each value simulates and how results queue.
pub fn set_os_random_result(result: Option<Result<usize, OsRandomError>>) {
    let mut guard = results();
    let queue = guard.get_or_insert([None; QUEUE_LEN]);
    match result {
        Some(simulated) => {
            if let Some(slot) = queue.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(simulated);
            } else if let Some(last) = queue.last_mut() {
                *last = Some(simulated);
            }
        }
        None => queue.fill(None),
    }
}

pub(crate) fn process_id_override() -> Option<u64> {
    if PID_SET.load(Ordering::SeqCst) {
        Some(PID_VALUE.load(Ordering::SeqCst))
    } else {
        None
    }
}

pub(crate) fn errno_override() -> Option<i32> {
    if ERRNO_SET.load(Ordering::SeqCst) {
        Some(ERRNO_VALUE.load(Ordering::SeqCst))
    } else {
        None
    }
}

pub(crate) fn take_os_random_result() -> Option<Result<usize, OsRandomError>> {
    let mut guard = results();
    let queue = guard.as_mut()?;
    let next = queue.first_mut()?.take();
    queue.rotate_left(1);
    next
}

/// Which side of [`fork_for_test`] the caller is on.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkResult {
    /// The original process. `child` is the child's process id, or -1
    /// when `fork` failed and there is no child.
    Parent {
        /// The child's process id, or -1.
        child: i32,
    },
    /// The new process.
    Child,
}

#[cfg(unix)]
unsafe extern "C" {
    /// Creates a child process. Returns the child's id in the parent, 0
    /// in the child, or -1 with no child created.
    fn fork() -> i32;

    /// Waits for the child `pid` to change state and stores its status.
    /// Returns `pid`, or -1 with `errno` set.
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

/// Forks the calling process.
///
/// The child runs only the forking thread. It should do no more than the
/// test needs and end with `std::process::exit`.
#[cfg(unix)]
#[must_use]
pub fn fork_for_test() -> ForkResult {
    // SAFETY: `fork` takes no arguments. The child continues with a copy
    // of the caller's memory and only the calling thread, which is the
    // documented contract of this test helper.
    match unsafe { fork() } {
        0 => ForkResult::Child,
        child if child > 0 => ForkResult::Parent { child },
        _ => ForkResult::Parent { child: -1 },
    }
}

/// Waits for the child `child` to exit and returns its exit code, or -1
/// when `child` is not positive, the wait fails or the child did not exit
/// normally.
#[cfg(unix)]
#[must_use]
pub fn wait_for_child(child: i32) -> i32 {
    if child <= 0 {
        return -1;
    }
    let mut status: i32 = 0;
    // SAFETY: `status` is a live, aligned `i32` the call may write, and
    // `child` is a positive process id.
    let ret = unsafe { waitpid(child, &raw mut status, 0) };
    if ret != child {
        return -1;
    }
    // `WIFEXITED` and `WEXITSTATUS`: the low seven bits are zero for a
    // normal exit, and the exit code is in the next eight.
    if status.trailing_zeros() >= 7 {
        (status >> 8) & 0xff
    } else {
        -1
    }
}
