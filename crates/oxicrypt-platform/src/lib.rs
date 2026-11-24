//! The module's own platform calls: the operating-system random
//! generator, the process id, and a process-aware spin cell.
//!
//! This is one of the small readily auditable in-boundary crates in the oxicrypt
//! workspace that use `unsafe`. It implements the sanctioned
//! **platform calls: random generator, process id, and the one static
//! cell** category: every `unsafe` block is either a call into the
//! operating system declared in this crate's own `extern` blocks, or an
//! access to the contents of a [`SpinCell`]. A contents access is made
//! either under the cell's lock, or, when the cell resets for a new
//! process, outside the lock by the one thread that marked the cell with
//! `RESET_MARK` and its process id; every other thread of that process then
//! spins until the new process id is recorded, and no thread of the new
//! process can hold a guard.
//! The workspace's `AGENTS.md` names the in-boundary crates that use
//! `unsafe`, and `tools/doc-guard` checks that list against the crates.
//! Every in-boundary crate outside that list is
//! `#![forbid(unsafe_code)]`. The module's Security Policy, withheld
//! from this repository (see `docs/security-policy/README.md`), holds
//! the authoritative accounting.
//!
//! # Why a separate crate?
//!
//! The module's other crates are `#![forbid(unsafe_code)]`. Asking the
//! operating system for random bytes or for the process id is a foreign
//! function call, and a process-global cell that holds state behind a
//! lock needs interior mutability through `UnsafeCell`; neither can be
//! expressed in safe Rust. Isolating both here keeps every other crate
//! free of `unsafe` and leaves one small surface to audit, mirroring the
//! `oxicrypt-zeroize` and `oxicrypt-timer` precedent: one sanctioned
//! category per crate.
//!
//! # Fork detection and its limit
//!
//! [`SpinCell`] records the id of the process that last used it and
//! rebuilds itself when a different process locks it, which is how a
//! forked child stops using its parent's state. The check compares
//! process ids only, so a descendant that reuses a parent's process id
//! after the parent exited keeps the parent's contents. The cell's memory
//! is not wiped at fork (the crate registers no `atfork` hook and sets no
//! `MADV_WIPEONFORK`): the parent's contents stay in the child's copy of
//! memory until the child's first `lock` discards them, without running
//! their destructors.
//!
//! # Module map
//!
//! - `random`: [`os_random`] and [`OsRandomError`], per target.
//! - `process`: [`process_id`], per target.
//! - `spin`: [`SpinCell`], [`SpinGuard`] and [`Busy`].
//! - `testing`: test seams, compiled only with the `fault-injection`
//!   feature or in this crate's own tests.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod process;
mod random;
mod spin;

#[cfg(any(test, feature = "fault-injection"))]
pub mod testing;

#[cfg(test)]
mod tests;

pub use process::process_id;
pub use random::{OsRandomError, os_random};
pub use spin::{Busy, SpinCell, SpinGuard};
