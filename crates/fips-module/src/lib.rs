//! FIPS 140-3 Level 1 module boundary.
//!
//! This crate defines the **cryptographic module boundary** per FIPS 140-3
//! Section 7.2. Every approved service in the workspace routes through the
//! state machine here: no algorithm is permitted to produce output until the
//! power-up self-tests have run and the module has entered the `Operational`
//! state. On any self-test failure the module enters a terminal `Error`
//! state in which all subsequent calls are rejected.
//!
//! # State machine
//!
//! ```text
//!    ┌──────────┐  initialize() ┌───────────┐  all KATs pass  ┌──────────────┐
//!    │ PowerOff │──────────────▶│ SelfTest  │────────────────▶│ Operational  │
//!    └──────────┘               └───────────┘                 └──────────────┘
//!                                     │                              │
//!                                 KAT failure                conditional self-test
//!                                     │                            failure
//!                                     ▼                              │
//!                                ┌─────────┐◀───────────────────────┘
//!                                │  Error  │
//!                                └─────────┘
//! ```
//!
//! # Phase 1 scope
//!
//! This file defines the state machine, the `SelfTest` trait, the global
//! state accessors, and the module `Error` type. It deliberately ships
//! **no actual self-tests** yet — the test registry is empty and
//! [`initialize`] will move the module straight from `SelfTest` to
//! `Operational`. Real KATs land in later phases as each algorithm crate
//! gains an implementation.
//!
//! # Thread safety
//!
//! State is stored in a single `AtomicU8` and is safe to read from any
//! thread. `initialize` uses compare-and-swap to guarantee the self-test
//! phase runs exactly once per process lifetime even under concurrent
//! first-calls.

#![no_std]
#![forbid(unsafe_code)]

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

/// Module lifecycle state per FIPS 140-3 Section 7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// Module has not yet been initialized. No services are available.
    PowerOff = 0,
    /// Power-up self-tests are currently executing. No services are
    /// available. This state is transient.
    SelfTest = 1,
    /// All power-up self-tests have passed. Approved services are
    /// available.
    Operational = 2,
    /// A self-test has failed (either a power-up KAT or a conditional
    /// test). This state is **terminal** within a process: no further
    /// services are offered and all cached secret material must be
    /// treated as zeroized. The only recovery is to restart the
    /// containing process.
    Error = 3,
}

impl State {
    const fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::PowerOff,
            1 => Self::SelfTest,
            2 => Self::Operational,
            // Any unknown discriminant collapses to `Error` so that a
            // corrupted state byte can never be interpreted as
            // `Operational`. This is defence-in-depth: `AtomicU8`
            // should only ever hold values written through this
            // module.
            _ => Self::Error,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PowerOff => "PowerOff",
            Self::SelfTest => "SelfTest",
            Self::Operational => "Operational",
            Self::Error => "Error",
        };
        f.write_str(s)
    }
}

/// Global module state. Written only by [`initialize`] and
/// [`enter_error_state`]; read by [`state`] and [`require_operational`].
static STATE: AtomicU8 = AtomicU8::new(State::PowerOff as u8);

/// Returns the current module state.
pub fn state() -> State {
    State::from_u8(STATE.load(Ordering::Acquire))
}

/// Returns `true` iff the module has passed its power-up self-tests and is
/// currently in the `Operational` state.
pub fn is_operational() -> bool {
    state() == State::Operational
}

/// Guard used at the entry point of every approved service. Returns
/// `Ok(())` only when the module is `Operational`; otherwise returns a
/// [`Error::NotOperational`] describing the current state so callers
/// cannot accidentally ignore it.
pub fn require_operational() -> Result<(), Error> {
    let current = state();
    if current == State::Operational {
        Ok(())
    } else {
        Err(Error::NotOperational { current })
    }
}

/// Errors surfaced by the module boundary.
///
/// Every variant is constructed with a `&'static str` description so
/// that formatting is allocation-free; this lets the module report
/// failures even from `no_std` contexts and from within the self-test
/// runner itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A service was invoked while the module was not in the
    /// `Operational` state.
    NotOperational {
        /// The state the module was actually in when the call arrived.
        current: State,
    },
    /// A power-up self-test failed. The module is now in the `Error`
    /// state.
    SelfTestFailed {
        /// Name of the failing test, supplied by its
        /// [`SelfTest`] implementation.
        test: &'static str,
    },
    /// A conditional self-test (e.g. DRBG CRNGT, pairwise consistency)
    /// failed during operation. The module is now in the `Error` state.
    ConditionalTestFailed {
        /// Short description of the failing check.
        reason: &'static str,
    },
    /// [`initialize`] was called while the module was already past
    /// `PowerOff`. This is not itself a FIPS violation — it just means
    /// a second caller raced with the first. The first call's outcome
    /// is authoritative; the race loser should read [`state`] to find
    /// out.
    AlreadyInitialized,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOperational { current } => {
                write!(f, "FIPS module not operational (state = {current})")
            }
            Self::SelfTestFailed { test } => {
                write!(f, "FIPS power-up self-test failed: {test}")
            }
            Self::ConditionalTestFailed { reason } => {
                write!(f, "FIPS conditional self-test failed: {reason}")
            }
            Self::AlreadyInitialized => f.write_str("FIPS module already initialized"),
        }
    }
}

/// Marker returned by a failing [`SelfTest::run`].
///
/// Self-tests are allowed to describe *what* failed, but they are not
/// allowed to exfiltrate the intermediate values that triggered the
/// failure — including them in an error payload would potentially leak
/// information about internal state. The runner treats the mere
/// presence of this value as "test failed" and converts it into
/// [`Error::SelfTestFailed`] using the test's own [`SelfTest::NAME`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestFailure;

impl fmt::Display for SelfTestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("self-test failure")
    }
}

/// A single power-up self-test.
///
/// Each approved algorithm crate will implement this trait for at least
/// one test vector, per SP 800-140B. The [`initialize`] routine runs
/// every registered test sequentially before the module can leave the
/// `SelfTest` state.
///
/// Implementations **must** be deterministic, **must not** allocate,
/// and **must not** read from any input the caller controls: the
/// whole point of a KAT is that its inputs and expected outputs are
/// baked into the module binary.
pub trait SelfTest {
    /// Stable, human-readable identifier for this test. Appears in
    /// [`Error::SelfTestFailed`] and in audit logs.
    const NAME: &'static str;

    /// Runs the test. Returns `Ok(())` on success, `Err(SelfTestFailure)`
    /// on any mismatch. The runner converts the `Err` into
    /// [`Error::SelfTestFailed`] using [`Self::NAME`].
    fn run() -> Result<(), SelfTestFailure>;
}

/// Initializes the module.
///
/// This is the only way to move the state machine out of `PowerOff`.
/// It transitions `PowerOff -> SelfTest`, executes every registered
/// KAT, and then transitions `SelfTest -> Operational` on success or
/// `SelfTest -> Error` on the first failure.
///
/// Concurrent calls are safe: exactly one caller wins the
/// `PowerOff -> SelfTest` CAS; losers receive
/// [`Error::AlreadyInitialized`] and should consult [`state`].
///
/// # Phase 1 note
///
/// The test registry is currently empty, so this routine transitions
/// straight to `Operational`. Registration of real KATs happens in
/// Phase 2 when the first algorithm crates ship their implementations.
pub fn initialize() -> Result<(), Error> {
    // Try to claim the SelfTest phase. Only the first caller in the
    // process lifetime succeeds.
    let cas = STATE.compare_exchange(
        State::PowerOff as u8,
        State::SelfTest as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    if cas.is_err() {
        return Err(Error::AlreadyInitialized);
    }

    // --- Run power-up KATs ---
    //
    // The registry is empty in Phase 1. When algorithm crates begin
    // shipping, each will register its tests and this block will
    // iterate them. For now we keep the control-flow shape identical
    // to what the real runner will use, so that landing actual tests
    // is a mechanical change.
    let kat_result: Result<(), Error> = Ok(());

    match kat_result {
        Ok(()) => {
            STATE.store(State::Operational as u8, Ordering::Release);
            Ok(())
        }
        Err(e) => {
            STATE.store(State::Error as u8, Ordering::Release);
            Err(e)
        }
    }
}

/// Forces the module into the terminal `Error` state.
///
/// Called by conditional self-tests (DRBG CRNGT, pairwise consistency
/// on keygen, etc.) when they detect a failure. Once invoked the
/// module will reject every subsequent [`require_operational`] call
/// for the remainder of the process lifetime.
///
/// This function is intentionally irreversible: FIPS 140-3 requires
/// that a module which has entered an error condition stay there
/// until it is re-initialized, and our "re-initialization" is a
/// process restart.
pub fn enter_error_state(_reason: &'static str) {
    STATE.store(State::Error as u8, Ordering::Release);
}

// -------------------------------------------------------------------------
// Test-only utilities
// -------------------------------------------------------------------------
//
// The global `STATE` makes the normal lifecycle effectively run-once per
// process. Unit tests in this crate need to exercise multiple transitions,
// so we expose a test-only reset helper gated behind `cfg(test)`. It is
// **not** part of the public API and is not compiled into release builds.

#[cfg(test)]
fn reset_for_test() {
    STATE.store(State::PowerOff as u8, Ordering::Release);
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        enter_error_state, initialize, is_operational, require_operational, reset_for_test, state,
        Error, SelfTest, State,
    };
    use alloc::string::ToString;

    // All tests in this module share the single global `STATE`, so they
    // cannot run in parallel. `cargo test` in this crate must be invoked
    // with `--test-threads=1` — enforced by the CI workflow.

    #[test]
    fn initial_state_is_power_off() {
        reset_for_test();
        assert_eq!(state(), State::PowerOff);
        assert!(!is_operational());
    }

    #[test]
    fn initialize_transitions_to_operational() {
        reset_for_test();
        initialize().unwrap();
        assert_eq!(state(), State::Operational);
        assert!(is_operational());
        require_operational().unwrap();
    }

    #[test]
    fn second_initialize_reports_already_initialized() {
        reset_for_test();
        initialize().unwrap();
        match initialize() {
            Err(Error::AlreadyInitialized) => {}
            other => panic!("expected AlreadyInitialized, got {other:?}"),
        }
    }

    #[test]
    fn require_operational_rejects_power_off() {
        reset_for_test();
        match require_operational() {
            Err(Error::NotOperational {
                current: State::PowerOff,
            }) => {}
            other => panic!("expected NotOperational{{PowerOff}}, got {other:?}"),
        }
    }

    #[test]
    fn enter_error_state_is_terminal_for_require_operational() {
        reset_for_test();
        initialize().unwrap();
        assert!(is_operational());
        enter_error_state("unit-test forced failure");
        assert_eq!(state(), State::Error);
        match require_operational() {
            Err(Error::NotOperational {
                current: State::Error,
            }) => {}
            other => panic!("expected NotOperational{{Error}}, got {other:?}"),
        }
    }

    #[test]
    fn state_display_is_stable() {
        // The exact strings appear in log output and audit trails,
        // so pin them.
        assert_eq!(State::PowerOff.to_string(), "PowerOff");
        assert_eq!(State::SelfTest.to_string(), "SelfTest");
        assert_eq!(State::Operational.to_string(), "Operational");
        assert_eq!(State::Error.to_string(), "Error");
    }

    // A trivial SelfTest implementation just to prove the trait
    // compiles and can be named by other crates. We do not invoke
    // it through `initialize` in Phase 1 because the registry is
    // still empty; that arrives in Phase 2.
    use super::SelfTestFailure;
    struct DummyTest;
    impl SelfTest for DummyTest {
        const NAME: &'static str = "dummy-phase1-placeholder";
        fn run() -> Result<(), SelfTestFailure> {
            Ok(())
        }
    }

    #[test]
    fn dummy_self_test_trait_object_is_usable() {
        assert_eq!(DummyTest::NAME, "dummy-phase1-placeholder");
        DummyTest::run().unwrap();
    }
}
