// Assertions and test scaffolding panic by design.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::vec::Vec;

use crate::testing::{set_errno_override, set_os_random_result, set_process_id_override};
use crate::{Busy, OsRandomError, SpinCell, os_random, process_id};

/// The overrides are process-global, so tests that read or set them run
/// one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An id no real process has, distinct from the cell's sentinels.
const OTHER_ID: u64 = 0x5EED_0000_0001;

#[test]
#[cfg_attr(miri, ignore)]
fn os_random_fills_and_differs() {
    let _serial = serial();
    let mut a = [0_u8; 4096];
    let mut b = [0_u8; 4096];
    assert_eq!(os_random(&mut a), Ok(()));
    assert_eq!(os_random(&mut b), Ok(()));
    assert_ne!(a, b);
}

#[test]
#[cfg_attr(miri, ignore)]
fn os_random_retries_eintr() {
    let _serial = serial();
    let mut out = [0_u8; 64];
    set_errno_override(Some(4));
    set_os_random_result(Some(Ok(usize::MAX)));
    let result = os_random(&mut out);
    set_errno_override(None);
    assert_eq!(result, Ok(()));
    assert!(out.iter().any(|&byte| byte != 0));
}

#[test]
#[cfg_attr(miri, ignore)]
fn os_random_loops_on_short_return() {
    let _serial = serial();
    let mut out = [0xAA_u8; 64];
    set_os_random_result(Some(Ok(10)));
    assert_eq!(os_random(&mut out), Ok(()));
    // The simulated call wrote nothing, so the first ten bytes keep the
    // fill, and the real generator filled the rest.
    assert!(out.iter().take(10).all(|&byte| byte == 0xAA));
    assert!(out.iter().skip(10).any(|&byte| byte != 0xAA));
}

#[test]
#[cfg_attr(miri, ignore)]
fn os_random_error_is_unavailable() {
    let _serial = serial();
    let mut out = [0_u8; 64];
    set_os_random_result(Some(Err(OsRandomError::Unavailable)));
    assert_eq!(os_random(&mut out), Err(OsRandomError::Unavailable));

    set_errno_override(Some(38));
    set_os_random_result(Some(Ok(usize::MAX)));
    let result = os_random(&mut out);
    set_errno_override(None);
    assert_eq!(result, Err(OsRandomError::Unavailable));

    set_os_random_result(Some(Ok(0)));
    assert_eq!(os_random(&mut out), Err(OsRandomError::Unavailable));
}

#[test]
#[cfg_attr(miri, ignore)]
fn os_random_partial_failure_wipes() {
    let _serial = serial();
    let mut out = [0xAA_u8; 64];
    set_os_random_result(Some(Ok(10)));
    set_os_random_result(Some(Err(OsRandomError::Unavailable)));
    assert_eq!(os_random(&mut out), Err(OsRandomError::Unavailable));
    assert!(out.iter().all(|&byte| byte == 0));
}

#[test]
fn spincell_lock_and_release() {
    let _serial = serial();
    let cell: SpinCell<u32> = SpinCell::with_bound(1 << 12);
    {
        let mut guard = cell.lock().unwrap();
        assert_eq!(*guard, None);
        *guard = Some(7);
    }
    let guard = cell.lock().unwrap();
    assert_eq!(*guard, Some(7));
}

#[test]
fn spincell_busy_after_bound() {
    let _serial = serial();
    let cell: Arc<SpinCell<u32>> = Arc::new(SpinCell::with_bound(1 << 12));
    let guard = cell.lock().unwrap();
    let other = Arc::clone(&cell);
    let result = thread::spawn(move || other.lock().map(|_| ()))
        .join()
        .unwrap();
    drop(guard);
    assert_eq!(result, Err(Busy));
}

#[test]
fn spincell_first_lock_resets_from_zero() {
    let _serial = serial();
    let cell: SpinCell<u32> = SpinCell::with_bound(1 << 12);
    assert_eq!(cell.resets.load(Ordering::SeqCst), 0);
    drop(cell.lock().unwrap());
    assert_eq!(cell.resets.load(Ordering::SeqCst), 1);
    drop(cell.lock().unwrap());
    assert_eq!(cell.resets.load(Ordering::SeqCst), 1);
}

#[test]
fn spincell_reset_is_exclusive() {
    let _serial = serial();
    let cell: Arc<SpinCell<u32>> = Arc::new(SpinCell::with_bound(1 << 12));
    *cell.lock().unwrap() = Some(1);
    assert_eq!(cell.resets.load(Ordering::SeqCst), 1);

    set_process_id_override(Some(OTHER_ID));
    let overlap = Arc::new(AtomicBool::new(false));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let cell = Arc::clone(&cell);
            let overlap = Arc::clone(&overlap);
            thread::spawn(move || {
                let mut guard = loop {
                    match cell.lock() {
                        Ok(guard) => break guard,
                        Err(Busy) => thread::yield_now(),
                    }
                };
                if cell.in_reset.load(Ordering::SeqCst) {
                    overlap.store(true, Ordering::SeqCst);
                }
                *guard = Some(guard.unwrap_or(0).wrapping_add(1));
                thread::yield_now();
                if cell.in_reset.load(Ordering::SeqCst) {
                    overlap.store(true, Ordering::SeqCst);
                }
            })
        })
        .collect();
    let joined: Vec<_> = threads.into_iter().map(thread::JoinHandle::join).collect();
    // The reset discarded the earlier `Some(1)`, and each thread then
    // added one under the lock.
    let total = cell.lock().map(|guard| *guard);
    set_process_id_override(None);

    assert_eq!(joined.len(), 8);
    assert!(joined.iter().all(Result::is_ok));
    assert_eq!(cell.resets.load(Ordering::SeqCst), 2);
    assert!(!overlap.load(Ordering::SeqCst));
    assert_eq!(total, Ok(Some(8)));
}

#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore)]
fn spincell_rebuilds_in_forked_child() {
    use crate::testing::{ForkResult, fork_for_test, wait_for_child};

    let _serial = serial();
    let cell: SpinCell<u32> = SpinCell::with_bound(1 << 12);
    let mut guard = cell.lock().unwrap();
    *guard = Some(42);
    let parent = process_id();
    match fork_for_test() {
        ForkResult::Child => {
            // The guard copied into the child belongs to the parent's
            // thread; dropping it here would release the child's lock.
            core::mem::forget(guard);
            let before = cell.resets.load(Ordering::SeqCst);
            let rebuilt = match cell.lock() {
                Ok(child_guard) => child_guard.is_none() && process_id() != parent,
                Err(Busy) => false,
            };
            let after = cell.resets.load(Ordering::SeqCst);
            let passed = rebuilt && after == before.wrapping_add(1);
            std::process::exit(i32::from(!passed));
        }
        ForkResult::Parent { child } => {
            drop(guard);
            assert!(child > 0);
            assert_eq!(wait_for_child(child), 0);
        }
    }
}

#[test]
fn spincell_stale_reset_from_another_process_is_taken_over() {
    use crate::spin::RESET_MARK;

    const PARENT: u64 = 4242;
    const CHILD: u64 = 4243;
    let _serial = serial();
    let cell: SpinCell<u32> = SpinCell::with_bound(1 << 12);
    *cell.lock().unwrap() = Some(5);
    assert_eq!(cell.resets.load(Ordering::SeqCst), 1);
    set_process_id_override(Some(CHILD));
    // A thread of the parent was resetting the cell when the child was
    // forked from it.
    cell.set_recorded_pid(RESET_MARK | PARENT);
    let taken = cell.lock().map(|guard| *guard);
    let resets = cell.resets.load(Ordering::SeqCst);
    let again = cell.lock().map(|_| ());
    set_process_id_override(None);

    assert_eq!(taken, Ok(None), "the stale reset was not redone");
    assert_eq!(resets, 2);
    assert_eq!(again, Ok(()));
    assert_eq!(cell.resets.load(Ordering::SeqCst), 2);
}

#[test]
fn spincell_reset_in_this_process_spins_to_busy() {
    use crate::spin::RESET_MARK;

    const CURRENT: u64 = 4243;
    let _serial = serial();
    let cell: SpinCell<u32> = SpinCell::with_bound(1 << 12);
    set_process_id_override(Some(CURRENT));
    // A thread of this process is resetting the cell.
    cell.set_recorded_pid(RESET_MARK | CURRENT);
    let result = cell.lock().map(|_| ());
    set_process_id_override(None);

    assert_eq!(result, Err(Busy));
    assert_eq!(cell.resets.load(Ordering::SeqCst), 0);
}
