//! FIPS 140-3 Level 1 module boundary.
//!
//! This crate defines the **cryptographic module boundary** per
//! FIPS 140-3 Section 7.2 and the service-gating plumbing every
//! other crate in the workspace depends on. No algorithm is
//! permitted to produce output until the power-up self-tests have
//! run and the module has entered the `Operational` state; on any
//! self-test failure the module latches into a terminal `Error`
//! state and rejects every subsequent call for the remainder of
//! the process lifetime.
//!
//! # State machine (FIPS 140-3 §7.2)
//!
//! ```text
//!    ┌──────────┐  initialize_with_tests()  ┌───────────┐  all KATs pass  ┌──────────────┐
//!    │ PowerOff │───────────────────────────▶│ SelfTest  │────────────────▶│ Operational  │
//!    └──────────┘                            └───────────┘                 └──────────────┘
//!                                                   │                              │
//!                                               KAT failure                conditional self-test
//!                                                   │                            failure
//!                                                   ▼                              │
//!                                              ┌─────────┐◀───────────────────────┘
//!                                              │  Error  │
//!                                              └─────────┘
//! ```
//!
//! An empty integrity group moves `SelfTest` to the terminal
//! `IntegrityUnverified` state instead of `Error`: the module was never
//! checked, rather than checked and found wrong.
//!
//! # What this crate ships
//!
//! - [`State`] and the transition machine (`PowerOff →
//!   SelfTest → Operational | Error | IntegrityUnverified`).
//! - [`initialize_with_tests`] — the canonical one-shot entry
//!   point that the top-level caller uses to run the integrity
//!   test and every approved algorithm's power-up KAT before
//!   opening the service interface.
//! - [`require_operational`] — the gate that every approved
//!   service in every other crate calls on entry. Returns
//!   [`Error::NotOperational`] (with the observed state) on any
//!   pre-`Operational` or post-`Error` call.
//! - [`require_self_test_started`] — the guard that every public
//!   `*_internal` function calls on entry. It admits `Operational`, and
//!   `SelfTest` on the thread running the power-up self-tests, so those
//!   tests can drive the internals, and refuses everything else.
//! - [`enter_error_state`] — irreversible transition into the
//!   terminal error state, called by conditional self-tests
//!   (pairwise consistency, DRBG health) when they detect a
//!   failure.
//! - [`KatEntry`] and the [`SelfTest`] trait — the registry
//!   shape that algorithm crates use to expose their power-up
//!   KATs.
//! - [`AlgorithmProfile`] — runtime selection of an algorithm
//!   restriction policy (Unrestricted, CNSA 2.0, CNSA 1.0,
//!   Migration).
//!   Set once at initialization via
//!   [`initialize_with_profile`].
//! - [`Service`] — per-algorithm-and-parameter enumeration of
//!   every approved service in the module. Used with
//!   [`require_allowed`] to enforce profile restrictions.
//!
//! The test registry is **not** assembled by linker-section
//! tricks: callers pass an explicit `&[KatEntry]` slice. That
//! means the full set of power-up tests is visible in source at
//! every call site, which makes it straightforward to audit the
//! module's power-up inventory against the Security Policy.
//!
//! # Algorithm profiles
//!
//! A single binary serves general FIPS 140-3 consumers
//! and CNSA-restricted deployments via a runtime
//! [`AlgorithmProfile`] selection. The operator passes the
//! desired profile to [`initialize_with_profile`]; subsequent
//! calls to [`require_allowed`] enforce it. Services not
//! permitted by the active profile return
//! [`Error::AlgorithmRestricted`].
//!
//! Four profiles are defined:
//!
//! - **Unrestricted** — all FIPS-approved algorithms are
//!   available. This is the default, matching the behavior of
//!   [`initialize_with_tests`].
//! - **CNSA 2.0** — CNSSP-15 (March 2025) Annex B: AES-256,
//!   SHA-384 or SHA-512, ML-KEM-1024, ML-DSA-87, and the
//!   SP 800-208 stateful hash-based signatures for software and
//!   firmware signing, together with the supporting services
//!   those need at matching strength. Every approved LMS
//!   parameter set is permitted; Annex B places no subset
//!   restriction on LMS. No Keccak-family hash or XOF is
//!   permitted: the suite names none for a software module, and
//!   the policy states that algorithms using SHA3 as a component
//!   do not thereby make SHA3 an approved hash function. No
//!   SLH-DSA parameter set is permitted — CNSSP-15 lists none.
//! - **CNSA 1.0** — CNSSP-15 (October 2016) Annex B: AES-256,
//!   ECDH and ECDSA on P-384, SHA-384, and Diffie-Hellman and
//!   RSA at a minimum 3072-bit modulus, with the supporting
//!   services those need at matching strength. SHA-256 is
//!   refused: the suite admits it only under a near-term
//!   allowance scoped to UNCLASSIFIED data, a condition the
//!   module cannot evaluate.
//! - **Migration** — both suites at once, for a deployment
//!   moving between them. It is **not** a CNSA profile and no
//!   standard defines it; it is the union of the two above, and
//!   is narrower than Unrestricted, which refuses nothing.
//!
//! **The profiles do not nest.** Neither CNSA suite contains the
//! other: CNSA 1.0 admits ECDSA, RSA and Diffie-Hellman that
//! CNSA 2.0 refuses, and CNSA 2.0 admits the post-quantum and
//! stateful hash-based algorithms that CNSA 1.0 refuses. The two
//! overlap in AES-256 and SHA-384 and their matching-strength
//! support, and nowhere else. KATs still run all algorithms
//! regardless of profile — the profile only restricts
//! post-initialization service access.
//!
//! # Sensitive security parameters (SSPs)
//!
//! This crate holds **no SSPs** of its own. It only gates
//! access to other crates that do. Secret material lives in the
//! algorithm crates that own it (e.g. `oxicrypt-rsa`'s
//! `RsaPrivateKey2048`, `oxicrypt-drbg`'s DRBG states). The error
//! latch here does not perform SSP zeroization on its own — each
//! owning crate is responsible for ensuring its SSPs are
//! dropped when the process restarts following a transition into
//! the `Error` state.
//!
//! # FIPS 140-3 / SP 800-140B mapping
//!
//! | SP 800-140B / IG clause | Implementation |
//! |-------------------------|----------------|
//! | §7.10 power-up self-tests | [`initialize_with_tests`] runs every registered [`KatEntry`] sequentially; the first failure latches [`State::Error`]. |
//! | §7.10 conditional self-tests | Algorithm crates call [`enter_error_state`] on detecting a pairwise-consistency or DRBG-health failure. |
//! | IG 9.5.A approved-mode indicator | [`is_operational`] / [`state`] — queryable at runtime. |
//! | §7.10.2.2 software integrity | Delegated to `oxicrypt-integrity` (separate crate), whose `KATS` the top-level caller runs first: the technique's own CAST, then the integrity test. |
//!
//! # Thread safety
//!
//! State is stored in a single `AtomicU64` and is safe to read
//! from any thread. Its low byte is the [`State`]; while the state is
//! `SelfTest`, the bits above it hold the operating system's id for the
//! thread running the self-tests, published in the same word so that no
//! reader sees one without the other. The id comes from
//! `oxicrypt-imageread`: `gettid` on Linux and Android,
//! `pthread_threadid_np` on Darwin, `GetCurrentThreadId` on Windows. A
//! target with none of these cannot own `SelfTest` and does not initialise.
//! A target without 64-bit atomics (`target_has_atomic = "64"`) cannot
//! hold the word, and the crate refuses to compile for it.
//!
//! [`initialize_with_tests`] uses a compare-and-swap to guarantee the
//! self-test phase runs exactly once per process lifetime even under
//! concurrent first-calls. Every self-test runs on the thread that won
//! it, and [`require_self_test_started`] admits `SelfTest` to that thread
//! alone, so another thread's `*_internal` call made while initialisation
//! is running, or paused, is refused. Racing losers wait on the state
//! word, so they do not observe the transient phase, and then receive
//! [`Error::AlreadyInitialized`] or [`Error::AlreadyFailed`]. A self-test
//! that unwinds out of initialisation leaves the module in `Error`.
//!
//! A service's check in `Operational` is one acquire load of the state
//! word and one comparison: a plain load on x86_64, `ldar` on AArch64,
//! and on a 32-bit target the platform's 64-bit atomic load. The thread id
//! is asked for only by an `*_internal` call that finds `SelfTest`.

#![no_std]
#![forbid(unsafe_code)]

// The state and the initialising thread's id are published as one 64-bit
// atomic word, so a reader never sees one without the other. A target with
// no 64-bit atomics cannot hold that word.
#[cfg(not(target_has_atomic = "64"))]
compile_error!(
    "oxicrypt-module needs 64-bit atomics: the module state and the thread running the \
     power-up self-tests are published as one AtomicU64"
);

use core::fmt;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

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
    /// The module reached the end of its pre-operational sequence
    /// without the software integrity test having been performed, so it
    /// was never verified against its integrity signature. **Terminal**, and
    /// no services are offered.
    ///
    /// Distinct from [`State::Error`] because the two are different
    /// faults with different owners. `Error` means a test ran and the
    /// module failed it: the artifact is wrong. This state means nothing
    /// checked the artifact at all — a front end initialised the module
    /// without the integrity test in its inventory. Nothing here says
    /// the module is corrupt; it says the module is unverified, and an
    /// operator told only "Error" would go looking for corruption that
    /// may not exist.
    IntegrityUnverified = 4,
}

impl State {
    const fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::PowerOff,
            1 => Self::SelfTest,
            2 => Self::Operational,
            4 => Self::IntegrityUnverified,
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
            Self::IntegrityUnverified => "IntegrityUnverified",
        };
        f.write_str(s)
    }
}

/// Global module state, packed with the owner of the `SelfTest` phase.
///
/// Bits 0–7 hold the [`State`] discriminant. Bits 8–63 hold the operating
/// system's id for the thread running the power-up self-tests while the
/// state is `SelfTest`, and are zero in every other state. One word, so no
/// reader can observe a state without its owner or an owner without its
/// state. Written only by [`initialize`] and [`enter_error_state`]; read
/// through [`state`] and the guards.
static STATE: AtomicU64 = AtomicU64::new(POWER_OFF);

/// The width of the state field; the owner occupies the bits above it.
const STATE_BITS: u32 = 8;
const POWER_OFF: u64 = State::PowerOff as u64;
/// The one word in which the approved services run. Its owner field is
/// zero, so the services' check is a single comparison.
const OPERATIONAL: u64 = State::Operational as u64;
const ERROR: u64 = State::Error as u64;
const INTEGRITY_UNVERIFIED: u64 = State::IntegrityUnverified as u64;

/// The word for `SelfTest` owned by the thread whose id is `owner`.
///
/// `owner` is non-zero and below `2^56`, as [`caller_owner_id`] returns it,
/// so the shift loses nothing.
const fn self_test_word(owner: u64) -> u64 {
    owner.wrapping_shl(STATE_BITS) | State::SelfTest as u64
}

/// The state a word encodes.
///
/// A word this module did not write reads as `Error`: an unknown
/// discriminant, `SelfTest` with no owner, or any other state with an
/// owner. None of them can therefore be taken for `Operational` or for a
/// `SelfTest` some thread owns.
const fn decode(word: u64) -> State {
    let [discriminant, ..] = word.to_le_bytes();
    let owned = word.wrapping_shr(STATE_BITS) != 0;
    match (State::from_u8(discriminant), owned) {
        (State::SelfTest, true) => State::SelfTest,
        (State::SelfTest, false) | (_, true) => State::Error,
        (state, false) => state,
    }
}

/// The calling thread's id as the owner field records it.
fn caller_owner_id() -> Option<u64> {
    owner_id(os_thread_id())
}

/// A thread id the owner field can record.
///
/// `None` when the platform offers no thread id, or offers zero or a value
/// of `2^56` or more, none of which the field can record unambiguously.
fn owner_id(raw: Option<u64>) -> Option<u64> {
    raw.filter(|&id| id != 0 && id.leading_zeros() >= STATE_BITS)
}

/// The name [`Error::SelfTestFailed`] carries when initialisation fails
/// because the platform gives the initialising thread no id the module can
/// record, so no thread could own `SelfTest`.
pub const THREAD_ID_CHECK: &str = "initialising thread id: none the module can record";

/// `gettid` on Linux and Android, `pthread_threadid_np` on Darwin,
/// `GetCurrentThreadId` on Windows.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
))]
fn os_thread_id() -> Option<u64> {
    oxicrypt_imageread::current_thread_id().ok()
}

/// No thread id on this target, so no thread can own `SelfTest` and the
/// module cannot be initialised.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
fn os_thread_id() -> Option<u64> {
    None
}

/// Returns the current module state.
pub fn state() -> State {
    decode(STATE.load(Ordering::Acquire))
}

/// Returns `true` iff the module has passed its power-up self-tests and is
/// currently in the `Operational` state.
pub fn is_operational() -> bool {
    STATE.load(Ordering::Acquire) == OPERATIONAL
}

/// Guard used at the entry point of every approved service. Returns
/// `Ok(())` only when the module is `Operational`; otherwise returns a
/// [`Error::NotOperational`] describing the current state so callers
/// cannot accidentally ignore it.
///
/// The `Operational` case costs one acquire load of the state word and one
/// comparison.
pub fn require_operational() -> Result<(), Error> {
    let word = STATE.load(Ordering::Acquire);
    if word == OPERATIONAL {
        Ok(())
    } else {
        Err(Error::NotOperational {
            current: decode(word),
        })
    }
}

/// Guard used at the entry point of every public `*_internal` function.
///
/// The `*_internal` functions perform an approved algorithm without the
/// [`require_operational`] / [`require_allowed`] gates of the approved
/// service, so that the power-up self-tests can drive them while the
/// module is still in [`State::SelfTest`]. They are not approved services.
/// This guard bounds when they run: it returns `Ok(())` in
/// [`State::Operational`] to every thread, and in [`State::SelfTest`] only
/// to the thread running the power-up self-tests. It returns
/// [`Error::NotOperational`] with the observed state to every other thread
/// in `SelfTest`, so a call that arrives while initialisation is running,
/// or paused, is refused, and to every thread in [`State::PowerOff`],
/// [`State::Error`] and [`State::IntegrityUnverified`].
///
/// The `Operational` case is the same comparison [`require_operational`]
/// makes, one acquire load and one compare, so any condition that gate
/// imposes on the approved services applies here too. Only a call that
/// finds `SelfTest` asks the operating system for its thread id.
pub fn require_self_test_started() -> Result<(), Error> {
    let word = STATE.load(Ordering::Acquire);
    if word == OPERATIONAL {
        return Ok(());
    }
    let current = decode(word);
    if current == State::SelfTest && caller_owner_id().map(self_test_word) == Some(word) {
        return Ok(());
    }
    Err(Error::NotOperational { current })
}

/// Proof that [`require_self_test_started`] passed for the holder.
///
/// Zero-sized, with no public constructor and no `Clone` or `Copy`: the only
/// way to obtain one is [`require_self_test_started_token`]. A hidden method
/// that takes `&SelfTestStarted` lets an algorithm crate do the state check
/// once at its own entry point and then run a per-block or per-squeeze loop,
/// or a region whose instructions must not change such as the entropy
/// source's timed workload, without repeating it. Each caller obtains the
/// token per call and never stores it. Holding a token across a transition
/// to `Error` does not matter, because the methods that accept one are
/// hidden and outside the module's defined service interface.
///
/// It is `Sync`, so a call that checked the state on its own thread can lend
/// `&SelfTestStarted` to the worker threads it runs in parallel. A worker
/// calling the guard itself would be refused during `SelfTest`, which admits
/// only the thread running the power-up self-tests.
#[derive(Debug)]
pub struct SelfTestStarted {
    _private: (),
}

/// Lending the proof to worker threads depends on it staying `Sync`.
const _: () = {
    const fn assert_sync<T: Sync>() {}
    assert_sync::<SelfTestStarted>();
};

/// [`require_self_test_started`], returning a [`SelfTestStarted`] proof.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] in `PowerOff`, `Error` and
/// `IntegrityUnverified`, and in `SelfTest` on any thread but the one
/// running the power-up self-tests, exactly as
/// [`require_self_test_started`] does.
pub fn require_self_test_started_token() -> Result<SelfTestStarted, Error> {
    require_self_test_started()?;
    Ok(SelfTestStarted { _private: () })
}

/// Errors surfaced by the module boundary.
///
/// Every variant is constructed with a `&'static str` description so
/// that formatting is allocation-free; this lets the module report
/// failures even from `no_std` contexts and from within the self-test
/// runner itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A service was invoked while the module was not in the
    /// `Operational` state.
    NotOperational {
        /// The state the module was actually in when the call arrived.
        current: State,
    },
    /// A power-up self-test failed. The module is now in the `Error`
    /// state.
    ///
    /// `test` is [`THREAD_ID_CHECK`] when no self-test could run because
    /// the platform gave the initialising thread no id the module can
    /// record.
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
    /// The pre-operational self-test sequence completed without the
    /// software integrity test having been performed. The module is now
    /// in the [`State::IntegrityUnverified`] state.
    ///
    /// This is an integration fault rather than a finding about the
    /// module: the test inventory handed to [`initialize_with_tests`]
    /// did not include `oxicrypt_integrity::KATS`.
    IntegrityNotAttested,
    /// [`initialize_with_tests`] or [`initialize_with_profile`] was called
    /// on a module that is already `Operational`, or that becomes
    /// `Operational` when the initialisation another thread is running
    /// completes. The module is ready; nothing was re-run.
    AlreadyInitialized,
    /// [`initialize_with_tests`] or [`initialize_with_profile`] was called
    /// on a module whose initialisation has already failed, so that it is
    /// in `Error` or `IntegrityUnverified`, including when the
    /// initialisation another thread was running fails while this call
    /// waits. A failed initialisation is terminal: no self-test is
    /// re-run, nothing resets the state, and only a process restart
    /// starts the module again.
    AlreadyFailed,
    /// A cryptographic service was called with input bytes that do not
    /// encode a valid domain element (for example, a scalar that is
    /// zero or not less than the group order, or a point that is not
    /// a canonical encoding on the curve). This is distinct from a
    /// self-test failure: the module is still operational; the caller
    /// supplied out-of-range bytes. Algorithm primitives should return
    /// this rather than silently substituting a default.
    InvalidInput,
    /// A service was invoked that is not permitted under the active
    /// [`AlgorithmProfile`]. The module is still operational — the
    /// algorithm exists but is restricted by policy. Switch to a
    /// less restrictive profile (which requires a process restart)
    /// or use an alternative algorithm that is permitted.
    AlgorithmRestricted {
        /// The specific service that was blocked.
        service: Service,
    },
    /// A service was invoked for an algorithm that exists in the
    /// [`Service`] enum but whose implementation has not yet been
    /// completed. Stub crates return this. The algorithm is
    /// recognized by the profile system and its gate will pass if
    /// the profile permits it, but the actual cryptographic
    /// operation is not yet available.
    NotImplemented,
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
            Self::IntegrityNotAttested => f.write_str(
                "this module did not check itself at startup, so it cannot tell whether this \
                 copy is the one that was built and signed. That does not mean the module is \
                 damaged: the program that started it skipped the check.",
            ),
            Self::AlreadyInitialized => f.write_str("FIPS module already initialized"),
            Self::AlreadyFailed => f.write_str(
                "FIPS module initialization already failed; restart the process to retry",
            ),
            Self::InvalidInput => f.write_str("invalid input to FIPS service"),
            Self::AlgorithmRestricted { service } => {
                write!(
                    f,
                    "algorithm {service} is not permitted under the {} profile",
                    active_profile()
                )
            }
            Self::NotImplemented => f.write_str("algorithm not yet implemented"),
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
/// one test vector, per SP 800-140B. The [`initialize_with_tests`] routine
/// runs every registered test sequentially before the module can leave the
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

/// A power-up KAT registered with the module.
///
/// Algorithm crates expose one or more `KatEntry` values that the
/// top-level caller passes into [`initialize_with_tests`] at startup.
/// The runner executes every entry sequentially before the module
/// leaves the `SelfTest` state; a single failure latches the module
/// into `Error` for the remainder of the process lifetime, per
/// FIPS 140-3 Section 7.10 and SP 800-140B.
///
/// The function pointer signature takes no inputs on purpose: a KAT
/// must run against compile-time-baked vectors only, never against
/// caller-supplied data.
#[derive(Debug, Clone, Copy)]
pub struct KatEntry {
    /// Stable identifier for the test. Surfaces in
    /// [`Error::SelfTestFailed`] and audit logs. Must match the
    /// [`SelfTest::NAME`] used for the underlying vector.
    pub name: &'static str,
    /// The test routine itself.
    pub run: fn() -> Result<(), SelfTestFailure>,
}

/// Initializes the module and runs every supplied power-up KAT.
///
/// This is the canonical entry point. It transitions
/// `PowerOff -> SelfTest`, executes every entry in `tests` in order,
/// and then transitions to `Operational` on success or to the
/// terminal `Error` state on the first failure. The returned
/// [`Error::SelfTestFailed`] carries the name of the failing test.
///
/// Concurrent calls are safe: exactly one caller wins the
/// `PowerOff -> SelfTest` CAS and runs the tests on its own thread. A
/// caller that does not win waits for the winner's outcome and receives
/// [`Error::AlreadyInitialized`] if it succeeded or [`Error::AlreadyFailed`]
/// if it failed. A call on a module that has already left `PowerOff` runs
/// no test and changes nothing: initialisation happens once per process,
/// and a failed one is terminal until the process restarts. A call made
/// from inside a self-test, on the thread running them, returns
/// [`Error::NotOperational`] naming `SelfTest`.
///
/// On a platform that gives the calling thread no id the module can
/// record, the winning call latches `Error` and returns
/// [`Error::SelfTestFailed`] naming [`THREAD_ID_CHECK`].
///
/// Note: the slice is passed **by reference**, not built up by magic.
/// This repository deliberately avoids linker-section registration
/// tricks: the full set of power-up tests is visible in source at
/// every call site, which makes it straightforward to audit the
/// module's test inventory against the Security Policy.
pub fn initialize_with_tests(integrity: &[KatEntry], tests: &[KatEntry]) -> Result<(), Error> {
    initialize(integrity, tests, AlgorithmProfile::Unrestricted)
}

/// The body of [`initialize_with_tests`] and [`initialize_with_profile`].
///
/// `profile` is stored only by the caller that wins the
/// `PowerOff -> SelfTest` CAS, and only once its self-tests pass, so a
/// later or concurrent call cannot change the profile the winning call
/// selected, and a failed initialisation leaves the default.
///
/// The winning call publishes `SelfTest` and its own thread id in one
/// word, so [`require_self_test_started`] admits only this thread while
/// the tests run. Every way out of the tests other than success moves
/// that word to a failed state, including an unwinding test, through
/// [`UnwindToError`]; none of them overwrites an `Error` that a
/// conditional self-test latched meanwhile.
fn initialize(
    integrity: &[KatEntry],
    tests: &[KatEntry],
    profile: AlgorithmProfile,
) -> Result<(), Error> {
    initialize_as(caller_owner_id(), integrity, tests, profile)
}

/// [`initialize`] for a caller whose owner id is `owner`, as
/// [`caller_owner_id`] reports it.
fn initialize_as(
    owner: Option<u64>,
    integrity: &[KatEntry],
    tests: &[KatEntry],
    profile: AlgorithmProfile,
) -> Result<(), Error> {
    // Claim the SelfTest phase. Only the first caller in the process
    // lifetime succeeds. A caller with no thread id to record cannot own
    // the phase, so on a platform without one the claim latches `Error`.
    let claim = owner.map_or(ERROR, self_test_word);
    if let Err(observed) =
        STATE.compare_exchange(POWER_OFF, claim, Ordering::AcqRel, Ordering::Acquire)
    {
        return Err(already_left_power_off(observed, claim));
    }
    if owner.is_none() {
        return Err(Error::SelfTestFailed {
            test: THREAD_ID_CHECK,
        });
    }
    let _unwind = UnwindToError { claim };

    // The integrity group runs first and cannot be OMITTED: it is a
    // separate parameter rather than an entry in `tests`, so a caller
    // cannot drop it by handing over a shorter list, and an empty group
    // is refused rather than treated as "nothing to check".
    //
    // What this does NOT establish is the group's identity. `KatEntry`
    // is a public struct, so any non-empty slice satisfies this check —
    // including one whose `run` returns `Ok(())` without verifying
    // anything. Passing a counterfeit group is an integration fault
    // that leaves the validated configuration, in the same class as
    // calling an approved algorithm with a key the operator invented;
    // the module cannot detect it and does not claim to. The Security
    // Policy states the obligation: initialise with
    // `oxicrypt_integrity::KATS`.
    if integrity.is_empty() {
        settle(claim, INTEGRITY_UNVERIFIED);
        return Err(Error::IntegrityNotAttested);
    }

    for entry in integrity.iter().chain(tests) {
        if (entry.run)().is_err() {
            // Latch the module into Error before returning. Any
            // subsequent service call will be rejected by
            // require_operational().
            settle(claim, ERROR);
            return Err(Error::SelfTestFailed { test: entry.name });
        }
    }

    // The only place in the workspace where the module becomes
    // operational. Every entry point reaches it, so the integrity
    // requirement is enforced once here rather than at the 129
    // `require_operational` call sites, and no service pays for the
    // check on its hot path.
    //
    // The profile is published here, by the call that won the CAS and
    // passed every test, before the state that makes it readable by a
    // service. A module that fails initialisation keeps the default.
    //
    // The transition is conditional on this call's own claim, so a
    // conditional self-test that latched `Error` while the tests ran is
    // never overwritten.
    PROFILE.store(profile as u8, Ordering::Release);
    if STATE
        .compare_exchange(claim, OPERATIONAL, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        PROFILE.store(AlgorithmProfile::Unrestricted as u8, Ordering::Release);
        return Err(Error::NotOperational { current: state() });
    }
    Ok(())
}

/// Moves `claim`, this call's `SelfTest` word, to the failed state `to`.
///
/// Conditional on the claim still standing, so it never overwrites an
/// `Error` latched by [`enter_error_state`] in the meantime.
fn settle(claim: u64, to: u64) {
    // A failed exchange means the word is already `Error`, which is the
    // outcome this call wants.
    let _ = STATE.compare_exchange(claim, to, Ordering::AcqRel, Ordering::Acquire);
}

/// What a call that did not win the `PowerOff` claim reports.
///
/// While another thread owns `SelfTest` the call waits for its outcome,
/// so it never reports the transient phase. A self-test that calls
/// `initialize` on the owning thread is answered at once, rather than
/// waiting on itself, with `NotOperational` naming `SelfTest`: the module
/// is not ready, and the call changes nothing.
fn already_left_power_off(mut observed: u64, claim: u64) -> Error {
    #[cfg(test)]
    if decode(observed) == State::SelfTest && observed != claim {
        WAITING_LOSERS.fetch_add(1, Ordering::AcqRel);
    }
    while decode(observed) == State::SelfTest && observed != claim {
        core::hint::spin_loop();
        observed = STATE.load(Ordering::Acquire);
    }
    match decode(observed) {
        State::Operational => Error::AlreadyInitialized,
        State::SelfTest => Error::NotOperational {
            current: State::SelfTest,
        },
        State::PowerOff | State::Error | State::IntegrityUnverified => Error::AlreadyFailed,
    }
}

/// How many calls have entered the wait in [`already_left_power_off`], so a
/// test can observe a loser waiting rather than infer it from timing.
#[cfg(test)]
static WAITING_LOSERS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Held by [`initialize`] across the self-tests.
///
/// Every return path settles the claim before this drops, so the exchange
/// below succeeds only when a self-test unwinds out of `initialize`. The
/// module then lands in `Error` rather than being left in a `SelfTest`
/// owned by a thread id that a later thread could be given.
struct UnwindToError {
    claim: u64,
}

impl Drop for UnwindToError {
    fn drop(&mut self) {
        settle(self.claim, ERROR);
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
    STATE.store(ERROR, Ordering::Release);
}

// =========================================================================
// Algorithm profile gating (CNSA 2.0 / CNSA 1.0)
// =========================================================================

/// Algorithm restriction profile selected at module initialization.
///
/// A single binary can serve general FIPS 140-3 consumers
/// (`Unrestricted`) and CNSA-restricted deployments (`Cnsa2`,
/// `Cnsa1`) by choosing the appropriate profile at init time.
///
/// The profile is immutable once set: it is stored when the module
/// becomes `Operational` and cannot be changed without restarting the
/// process (which resets the state machine). A module that fails
/// initialisation reports the default, `Unrestricted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgorithmProfile {
    /// All FIPS-approved algorithms are available. This is the
    /// default and preserves backward compatibility with callers
    /// that use [`initialize_with_tests`].
    Unrestricted = 0,
    /// CNSA 2.0 — CNSSP-15 (March 2025) Annex B: AES-256, ML-KEM-1024,
    /// ML-DSA-87, SHA-384 or SHA-512, and the SP 800-208 stateful
    /// hash-based signatures for software and firmware signing, with the
    /// supporting services those need at matching strength. The suite
    /// names no Keccak-family algorithm for a software module, so none is
    /// permitted here. Everything else returns
    /// [`Error::AlgorithmRestricted`].
    Cnsa2 = 1,
    /// CNSA 1.0 — CNSSP-15 (October 2016) Annex B: AES-256, ECDH and
    /// ECDSA on P-384, SHA-384, and Diffie-Hellman and RSA at a minimum
    /// 3072-bit modulus, with the supporting services those need at
    /// matching strength. SHA-256 and its variants are refused: the suite
    /// admits them only under a near-term condition scoped to UNCLASSIFIED
    /// data, which a module cannot evaluate.
    Cnsa1 = 2,
    /// Both suites at once — **not a CNSA profile and not defined by any
    /// standard.** This is oxicrypt's own union of CNSA 1.0 and CNSA 2.0,
    /// for a deployment migrating between them that must run classical and
    /// post-quantum algorithms side by side.
    ///
    /// It is narrower than [`Unrestricted`](Self::Unrestricted), which
    /// refuses nothing: SHA-1, AES-128, RSA-2048 and P-256 are all refused
    /// here. It admits no Keccak-family algorithm, because neither suite
    /// does.
    Migration = 3,
}

impl AlgorithmProfile {
    const fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Unrestricted,
            2 => Self::Cnsa1,
            3 => Self::Migration,
            // Unknown discriminant (including 1 = Cnsa2) defaults to
            // the most restrictive profile as defence-in-depth.
            _ => Self::Cnsa2,
        }
    }
}

impl fmt::Display for AlgorithmProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unrestricted => "Unrestricted",
            Self::Cnsa2 => "CNSA 2.0",
            Self::Cnsa1 => "CNSA 1.0",
            Self::Migration => "Migration (CNSA 1.0 + CNSA 2.0)",
        };
        f.write_str(s)
    }
}

/// Global algorithm profile. Written once by [`initialize_with_profile`];
/// read by [`require_allowed`] and [`active_profile`].
static PROFILE: AtomicU8 = AtomicU8::new(AlgorithmProfile::Unrestricted as u8);

/// Returns the active algorithm profile.
pub fn active_profile() -> AlgorithmProfile {
    AlgorithmProfile::from_u8(PROFILE.load(Ordering::Acquire))
}

/// Initializes the module with a specific algorithm profile and runs
/// every supplied power-up KAT.
///
/// This is the profile-aware entry point. The call that wins the
/// `PowerOff -> SelfTest` transition runs the KATs and, on success, stores
/// the selected profile and transitions to `Operational`. On failure the
/// module latches a terminal state and the profile stays the default. KATs
/// always run all algorithms regardless of the profile — the profile
/// only restricts post-initialization service access via
/// [`require_allowed`].
///
/// A call that does not win that transition, whether it comes later or
/// races the winner, leaves the active profile unchanged and returns
/// [`Error::AlreadyInitialized`] when the winner succeeded, or
/// [`Error::AlreadyFailed`] when it failed, as [`initialize_with_tests`]
/// describes.
///
/// See [`initialize_with_tests`] for the backward-compatible wrapper
/// that uses [`AlgorithmProfile::Unrestricted`].
///
/// # Calling context
///
/// While the self-tests run, [`require_self_test_started`] admits the
/// calling thread, so code the application runs on that thread during
/// initialisation must not call the module. Do not call module services
/// from a global allocator, panic hook or other callback that can run
/// during initialisation, and do not call this function from a task inside
/// a shared work-stealing pool, whose worker may run unrelated tasks while
/// it waits. Initialise from a dedicated thread, then use the module once
/// this function returns `Ok`.
pub fn initialize_with_profile(
    integrity: &[KatEntry],
    tests: &[KatEntry],
    profile: AlgorithmProfile,
) -> Result<(), Error> {
    initialize(integrity, tests, profile)
}

/// Enumeration of every approved service in the module, at the
/// algorithm-and-parameter level.
///
/// Each variant represents a specific algorithm instantiation (e.g.
/// `Aes128Ecb` not just `Aes`). This granularity is necessary
/// because CNSA restrictions operate at the key-size and hash-size
/// level.
///
/// Algorithm crates pass the appropriate `Service` variant to
/// [`require_allowed`] at their public entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum Service {
    // ----- oxicrypt-sha: FIPS 180-4 / FIPS 202 -----
    Sha1 = 0,
    Sha224 = 1,
    Sha256 = 2,
    Sha384 = 3,
    Sha512 = 4,
    Sha512_224 = 5,
    Sha512_256 = 6,

    Sha3_224 = 10,
    Sha3_256 = 11,
    Sha3_384 = 12,
    Sha3_512 = 13,

    // ----- oxicrypt-xof: FIPS 202 / SP 800-185 -----
    Shake128 = 20,
    Shake256 = 21,
    CShake128 = 22,
    CShake256 = 23,
    Kmac128 = 24,
    Kmac256 = 25,
    KmacXof128 = 26,
    KmacXof256 = 27,
    TupleHash128 = 28,
    TupleHash256 = 29,
    TupleHashXof128 = 30,
    TupleHashXof256 = 31,
    ParallelHash128 = 32,
    ParallelHash256 = 33,
    ParallelHashXof128 = 34,
    ParallelHashXof256 = 35,

    // ----- oxicrypt-hmac: FIPS 198-1 -----
    HmacSha1 = 40,
    HmacSha224 = 41,
    HmacSha256 = 42,
    HmacSha384 = 43,
    HmacSha512 = 44,
    HmacSha512_224 = 45,
    HmacSha512_256 = 46,
    HmacSha3_224 = 47,
    HmacSha3_256 = 48,
    HmacSha3_384 = 49,
    HmacSha3_512 = 50,

    // ----- oxicrypt-cmac: SP 800-38B -----
    CmacAes128 = 60,
    CmacAes192 = 61,
    CmacAes256 = 62,

    // ----- oxicrypt-aes: FIPS 197 / SP 800-38A/D/C/F/Fp -----
    Aes128Ecb = 70,
    Aes128Cbc = 71,
    Aes128Ctr = 72,
    Aes128Gcm = 73,
    Aes128Ccm = 74,
    Aes128Kw = 75,
    Aes128Kwp = 76,
    Aes192Ecb = 80,
    Aes192Cbc = 81,
    Aes192Ctr = 82,
    Aes192Gcm = 83,
    Aes192Ccm = 84,
    Aes192Kw = 85,
    Aes192Kwp = 86,
    Aes256Ecb = 90,
    Aes256Cbc = 91,
    Aes256Ctr = 92,
    Aes256Gcm = 93,
    Aes256Ccm = 94,
    Aes256Kw = 95,
    Aes256Kwp = 96,

    // Key-construction gates — checked when building an AES key
    // object before the caller selects a mode.  All per-mode
    // variants of the same key size share identical profile
    // permissions, so a single gate at key construction is
    // sufficient.
    /// AES-128 key construction (gates all AES-128 mode services).
    Aes128 = 97,
    /// AES-192 key construction (gates all AES-192 mode services).
    Aes192 = 98,
    /// AES-256 key construction (gates all AES-256 mode services).
    Aes256 = 99,

    // ----- oxicrypt-drbg: SP 800-90A -----
    CtrDrbgAes128 = 100,
    CtrDrbgAes192 = 101,
    CtrDrbgAes256 = 102,
    HashDrbgSha256 = 103,
    HashDrbgSha384 = 104,
    HashDrbgSha512 = 105,
    HmacDrbgSha256 = 106,
    HmacDrbgSha384 = 107,
    HmacDrbgSha512 = 108,

    // ----- oxicrypt-kdf: SP 800-56C / SP 800-108 / SP 800-132 -----
    HkdfSha1 = 120,
    HkdfSha256 = 121,
    HkdfSha384 = 122,
    HkdfSha512 = 123,
    KbkdfHmacSha256 = 130,
    KbkdfHmacSha384 = 131,
    KbkdfHmacSha512 = 132,
    KbkdfCmacAes128 = 133,
    KbkdfCmacAes192 = 134,
    KbkdfCmacAes256 = 135,
    Pbkdf2HmacSha1 = 140,
    Pbkdf2HmacSha224 = 141,
    Pbkdf2HmacSha256 = 142,
    Pbkdf2HmacSha384 = 143,
    Pbkdf2HmacSha512 = 144,

    // ----- oxicrypt-rsa: FIPS 186-5 / SP 800-56Br2 -----
    RsaKeygen2048 = 150,
    RsaPkcs1v15Sign2048 = 151,
    RsaPssSign2048 = 152,
    RsaOaep2048 = 153,
    RsaPkcs1v15Verify2048 = 154,
    RsaPssVerify2048 = 155,
    RsaKeygen3072 = 160,
    RsaPkcs1v15Sign3072 = 161,
    RsaPssSign3072 = 162,
    RsaOaep3072 = 163,
    RsaPkcs1v15Verify3072 = 164,
    RsaPssVerify3072 = 165,
    RsaKeygen4096 = 170,
    RsaPkcs1v15Sign4096 = 171,
    RsaPssSign4096 = 172,
    RsaOaep4096 = 173,
    RsaPkcs1v15Verify4096 = 174,
    RsaPssVerify4096 = 175,

    // ----- oxicrypt-ecdsa: FIPS 186-5 -----
    EcdsaP256Sign = 200,
    EcdsaP256Verify = 201,
    EcdsaP256Keygen = 202,
    EcdsaP384Sign = 210,
    EcdsaP384Verify = 211,
    EcdsaP384Keygen = 212,

    // ----- oxicrypt-ecdh: SP 800-56Ar3 -----
    EcdhP256 = 220,
    EcdhP384 = 221,

    // ----- oxicrypt-eddsa: FIPS 186-5 / RFC 8032 -----
    Ed25519Sign = 230,
    Ed25519Verify = 231,
    Ed25519Keygen = 232,

    // ----- oxicrypt-tls-kdf: SP 800-135r1 + RFC 8446 §7.1 -----
    Tls12Kdf = 240,
    Tls13Kdf = 241,

    // ----- oxicrypt-ml-kem: FIPS 203 -----
    MlKem1024Encaps = 300,
    MlKem1024Decaps = 301,
    MlKem1024Keygen = 302,
    MlKem512Encaps = 303,
    MlKem512Decaps = 304,
    MlKem512Keygen = 305,
    MlKem768Encaps = 306,
    MlKem768Decaps = 307,
    MlKem768Keygen = 308,

    // ----- oxicrypt-ml-dsa: FIPS 204 -----
    MlDsa87Sign = 310,
    MlDsa87Verify = 311,
    MlDsa87Keygen = 312,
    MlDsa44Sign = 313,
    MlDsa44Verify = 314,
    MlDsa44Keygen = 315,
    MlDsa65Sign = 316,
    MlDsa65Verify = 317,
    MlDsa65Keygen = 318,

    // ----- oxicrypt-slh-dsa: FIPS 205 (12 parameter sets × 3 ops = 36 variants) -----
    // SHA-2 256s claims 320-322 for historical reasons, then the rest of the
    // SHA-2 family (128s/f, 192s/f, 256f), then the SHAKE family. No SLH-DSA
    // parameter set is permitted under either CNSA profile.
    SlhDsaSha2256sKeygen = 320,
    SlhDsaSha2256sSign = 321,
    SlhDsaSha2256sVerify = 322,
    SlhDsaSha2128sKeygen = 323,
    SlhDsaSha2128sSign = 324,
    SlhDsaSha2128sVerify = 325,
    SlhDsaSha2128fKeygen = 326,
    SlhDsaSha2128fSign = 327,
    SlhDsaSha2128fVerify = 328,
    SlhDsaSha2192sKeygen = 329,
    SlhDsaSha2192sSign = 330,
    SlhDsaSha2192sVerify = 331,
    SlhDsaSha2192fKeygen = 332,
    SlhDsaSha2192fSign = 333,
    SlhDsaSha2192fVerify = 334,
    SlhDsaSha2256fKeygen = 335,
    SlhDsaSha2256fSign = 336,
    SlhDsaSha2256fVerify = 337,
    SlhDsaShake128sKeygen = 338,
    SlhDsaShake128sSign = 339,
    SlhDsaShake128sVerify = 340,
    SlhDsaShake128fKeygen = 341,
    SlhDsaShake128fSign = 342,
    SlhDsaShake128fVerify = 343,
    SlhDsaShake192sKeygen = 344,
    SlhDsaShake192sSign = 345,
    SlhDsaShake192sVerify = 346,
    SlhDsaShake192fKeygen = 347,
    SlhDsaShake192fSign = 348,
    SlhDsaShake192fVerify = 349,
    SlhDsaShake256sKeygen = 350,
    SlhDsaShake256sSign = 351,
    SlhDsaShake256sVerify = 352,
    SlhDsaShake256fKeygen = 353,
    SlhDsaShake256fSign = 354,
    SlhDsaShake256fVerify = 355,

    // ----- oxicrypt-lms: SP 800-208 §4.1–§4.4, verification only -----
    // 80 per-pair entries on the odd discriminants 501-659.
    // Layout: 501-539 SHA-256/M=32, 541-579 SHA-256/M=24,
    // 581-619 SHAKE/M=32, 621-659 SHAKE/M=24.
    // Within each family: (H ascending, W ascending). The even values in
    // 500-658 are unassigned: SP 800-208 §8.1 confines LMS signing to
    // hardware modules, so no signing service exists to hold them.
    // The odd values in the block hold nothing but LMS, which is what lets
    // `is_lms_service` test the block arithmetically;
    // `lms_discriminant_slots_are_complete_and_pure` and a build-time
    // assertion pin that. All 80 pairs are permitted under CNSA 2.0,
    // Migration and Unrestricted, and refused under CNSA 1.0.

    // SHA-256 / N=32 family (SP 800-208 §4.1)
    LmsSha256M32H5W1Verify = 501,
    LmsSha256M32H5W2Verify = 503,
    LmsSha256M32H5W4Verify = 505,
    LmsSha256M32H5W8Verify = 507,
    LmsSha256M32H10W1Verify = 509,
    LmsSha256M32H10W2Verify = 511,
    LmsSha256M32H10W4Verify = 513,
    LmsSha256M32H10W8Verify = 515,
    LmsSha256M32H15W1Verify = 517,
    LmsSha256M32H15W2Verify = 519,
    LmsSha256M32H15W4Verify = 521,
    LmsSha256M32H15W8Verify = 523,
    LmsSha256M32H20W1Verify = 525,
    LmsSha256M32H20W2Verify = 527,
    LmsSha256M32H20W4Verify = 529,
    LmsSha256M32H20W8Verify = 531,
    LmsSha256M32H25W1Verify = 533,
    LmsSha256M32H25W2Verify = 535,
    LmsSha256M32H25W4Verify = 537,
    LmsSha256M32H25W8Verify = 539,

    // SHA-256 / N=24 family (SP 800-208 §4.2)
    LmsSha256M24H5W1Verify = 541,
    LmsSha256M24H5W2Verify = 543,
    LmsSha256M24H5W4Verify = 545,
    LmsSha256M24H5W8Verify = 547,
    LmsSha256M24H10W1Verify = 549,
    LmsSha256M24H10W2Verify = 551,
    LmsSha256M24H10W4Verify = 553,
    LmsSha256M24H10W8Verify = 555,
    LmsSha256M24H15W1Verify = 557,
    LmsSha256M24H15W2Verify = 559,
    LmsSha256M24H15W4Verify = 561,
    LmsSha256M24H15W8Verify = 563,
    LmsSha256M24H20W1Verify = 565,
    LmsSha256M24H20W2Verify = 567,
    LmsSha256M24H20W4Verify = 569,
    LmsSha256M24H20W8Verify = 571,
    LmsSha256M24H25W1Verify = 573,
    LmsSha256M24H25W2Verify = 575,
    LmsSha256M24H25W4Verify = 577,
    LmsSha256M24H25W8Verify = 579,

    // SHAKE-256 / N=32 family (SP 800-208 §4.3)
    LmsShakeM32H5W1Verify = 581,
    LmsShakeM32H5W2Verify = 583,
    LmsShakeM32H5W4Verify = 585,
    LmsShakeM32H5W8Verify = 587,
    LmsShakeM32H10W1Verify = 589,
    LmsShakeM32H10W2Verify = 591,
    LmsShakeM32H10W4Verify = 593,
    LmsShakeM32H10W8Verify = 595,
    LmsShakeM32H15W1Verify = 597,
    LmsShakeM32H15W2Verify = 599,
    LmsShakeM32H15W4Verify = 601,
    LmsShakeM32H15W8Verify = 603,
    LmsShakeM32H20W1Verify = 605,
    LmsShakeM32H20W2Verify = 607,
    LmsShakeM32H20W4Verify = 609,
    LmsShakeM32H20W8Verify = 611,
    LmsShakeM32H25W1Verify = 613,
    LmsShakeM32H25W2Verify = 615,
    LmsShakeM32H25W4Verify = 617,
    LmsShakeM32H25W8Verify = 619,

    // SHAKE-256 / N=24 family (SP 800-208 §4.4)
    LmsShakeM24H5W1Verify = 621,
    LmsShakeM24H5W2Verify = 623,
    LmsShakeM24H5W4Verify = 625,
    LmsShakeM24H5W8Verify = 627,
    LmsShakeM24H10W1Verify = 629,
    LmsShakeM24H10W2Verify = 631,
    LmsShakeM24H10W4Verify = 633,
    LmsShakeM24H10W8Verify = 635,
    LmsShakeM24H15W1Verify = 637,
    LmsShakeM24H15W2Verify = 639,
    LmsShakeM24H15W4Verify = 641,
    LmsShakeM24H15W8Verify = 643,
    LmsShakeM24H20W1Verify = 645,
    LmsShakeM24H20W2Verify = 647,
    LmsShakeM24H20W4Verify = 649,
    LmsShakeM24H20W8Verify = 651,
    LmsShakeM24H25W1Verify = 653,
    LmsShakeM24H25W2Verify = 655,
    LmsShakeM24H25W4Verify = 657,
    LmsShakeM24H25W8Verify = 659,

    // ----- oxicrypt-xmss: SP 800-208 (stub) -----
    // Renumbered 340/341 → 370/371 to make room for the SLH-DSA block.
    XmssVerify = 371,

    // ----- oxicrypt-dh: RFC 3526 (stub) -----
    // Renumbered 350 → 380 to make room for the SLH-DSA block.
    Dh3072 = 380,
}

impl fmt::Display for Service {
    // The match arm count is proportional to the number of approved
    // services in the module; there is no natural factoring that
    // would reduce it.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_224 => "SHA-512/224",
            Self::Sha512_256 => "SHA-512/256",
            Self::Sha3_224 => "SHA3-224",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Shake128 => "SHAKE128",
            Self::Shake256 => "SHAKE256",
            Self::CShake128 => "cSHAKE128",
            Self::CShake256 => "cSHAKE256",
            Self::Kmac128 => "KMAC128",
            Self::Kmac256 => "KMAC256",
            Self::KmacXof128 => "KMACXOF128",
            Self::KmacXof256 => "KMACXOF256",
            Self::TupleHash128 => "TupleHash128",
            Self::TupleHash256 => "TupleHash256",
            Self::TupleHashXof128 => "TupleHashXOF128",
            Self::TupleHashXof256 => "TupleHashXOF256",
            Self::ParallelHash128 => "ParallelHash128",
            Self::ParallelHash256 => "ParallelHash256",
            Self::ParallelHashXof128 => "ParallelHashXOF128",
            Self::ParallelHashXof256 => "ParallelHashXOF256",
            Self::HmacSha1 => "HMAC-SHA-1",
            Self::HmacSha224 => "HMAC-SHA-224",
            Self::HmacSha256 => "HMAC-SHA-256",
            Self::HmacSha384 => "HMAC-SHA-384",
            Self::HmacSha512 => "HMAC-SHA-512",
            Self::HmacSha512_224 => "HMAC-SHA-512/224",
            Self::HmacSha512_256 => "HMAC-SHA-512/256",
            Self::HmacSha3_224 => "HMAC-SHA3-224",
            Self::HmacSha3_256 => "HMAC-SHA3-256",
            Self::HmacSha3_384 => "HMAC-SHA3-384",
            Self::HmacSha3_512 => "HMAC-SHA3-512",
            Self::CmacAes128 => "CMAC-AES-128",
            Self::CmacAes192 => "CMAC-AES-192",
            Self::CmacAes256 => "CMAC-AES-256",
            Self::Aes128Ecb => "AES-128-ECB",
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes128Ctr => "AES-128-CTR",
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes128Ccm => "AES-128-CCM",
            Self::Aes128Kw => "AES-128-KW",
            Self::Aes128Kwp => "AES-128-KWP",
            Self::Aes192Ecb => "AES-192-ECB",
            Self::Aes192Cbc => "AES-192-CBC",
            Self::Aes192Ctr => "AES-192-CTR",
            Self::Aes192Gcm => "AES-192-GCM",
            Self::Aes192Ccm => "AES-192-CCM",
            Self::Aes192Kw => "AES-192-KW",
            Self::Aes192Kwp => "AES-192-KWP",
            Self::Aes256Ecb => "AES-256-ECB",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::Aes256Ctr => "AES-256-CTR",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Aes256Ccm => "AES-256-CCM",
            Self::Aes256Kw => "AES-256-KW",
            Self::Aes256Kwp => "AES-256-KWP",
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
            Self::CtrDrbgAes128 => "CTR_DRBG-AES-128",
            Self::CtrDrbgAes192 => "CTR_DRBG-AES-192",
            Self::CtrDrbgAes256 => "CTR_DRBG-AES-256",
            Self::HashDrbgSha256 => "Hash_DRBG-SHA-256",
            Self::HashDrbgSha384 => "Hash_DRBG-SHA-384",
            Self::HashDrbgSha512 => "Hash_DRBG-SHA-512",
            Self::HmacDrbgSha256 => "HMAC_DRBG-SHA-256",
            Self::HmacDrbgSha384 => "HMAC_DRBG-SHA-384",
            Self::HmacDrbgSha512 => "HMAC_DRBG-SHA-512",
            Self::HkdfSha1 => "HKDF-SHA-1",
            Self::HkdfSha256 => "HKDF-SHA-256",
            Self::HkdfSha384 => "HKDF-SHA-384",
            Self::HkdfSha512 => "HKDF-SHA-512",
            Self::KbkdfHmacSha256 => "KBKDF-HMAC-SHA-256",
            Self::KbkdfHmacSha384 => "KBKDF-HMAC-SHA-384",
            Self::KbkdfHmacSha512 => "KBKDF-HMAC-SHA-512",
            Self::KbkdfCmacAes128 => "KBKDF-CMAC-AES-128",
            Self::KbkdfCmacAes192 => "KBKDF-CMAC-AES-192",
            Self::KbkdfCmacAes256 => "KBKDF-CMAC-AES-256",
            Self::Pbkdf2HmacSha1 => "PBKDF2-HMAC-SHA-1",
            Self::Pbkdf2HmacSha224 => "PBKDF2-HMAC-SHA-224",
            Self::Pbkdf2HmacSha256 => "PBKDF2-HMAC-SHA-256",
            Self::Pbkdf2HmacSha384 => "PBKDF2-HMAC-SHA-384",
            Self::Pbkdf2HmacSha512 => "PBKDF2-HMAC-SHA-512",
            Self::RsaKeygen2048 => "RSA-2048 keygen",
            Self::RsaPkcs1v15Sign2048 => "RSA-PKCS1v1.5-Sign-2048",
            Self::RsaPssSign2048 => "RSA-PSS-Sign-2048",
            Self::RsaOaep2048 => "RSA-OAEP-2048",
            Self::RsaPkcs1v15Verify2048 => "RSA-PKCS1v1.5-Verify-2048",
            Self::RsaPssVerify2048 => "RSA-PSS-Verify-2048",
            Self::RsaKeygen3072 => "RSA-3072 keygen",
            Self::RsaPkcs1v15Sign3072 => "RSA-PKCS1v1.5-Sign-3072",
            Self::RsaPssSign3072 => "RSA-PSS-Sign-3072",
            Self::RsaOaep3072 => "RSA-OAEP-3072",
            Self::RsaPkcs1v15Verify3072 => "RSA-PKCS1v1.5-Verify-3072",
            Self::RsaPssVerify3072 => "RSA-PSS-Verify-3072",
            Self::RsaKeygen4096 => "RSA-4096 keygen",
            Self::RsaPkcs1v15Sign4096 => "RSA-PKCS1v1.5-Sign-4096",
            Self::RsaPssSign4096 => "RSA-PSS-Sign-4096",
            Self::RsaOaep4096 => "RSA-OAEP-4096",
            Self::RsaPkcs1v15Verify4096 => "RSA-PKCS1v1.5-Verify-4096",
            Self::RsaPssVerify4096 => "RSA-PSS-Verify-4096",
            Self::EcdsaP256Sign => "ECDSA-P256 sign",
            Self::EcdsaP256Verify => "ECDSA-P256 verify",
            Self::EcdsaP256Keygen => "ECDSA-P256 keygen",
            Self::EcdsaP384Sign => "ECDSA-P384 sign",
            Self::EcdsaP384Verify => "ECDSA-P384 verify",
            Self::EcdsaP384Keygen => "ECDSA-P384 keygen",
            Self::EcdhP256 => "ECDH-P256",
            Self::EcdhP384 => "ECDH-P384",
            Self::Ed25519Sign => "Ed25519 sign",
            Self::Ed25519Verify => "Ed25519 verify",
            Self::Ed25519Keygen => "Ed25519 keygen",
            Self::Tls12Kdf => "TLS 1.2 KDF",
            Self::Tls13Kdf => "TLS 1.3 KDF",
            Self::MlKem1024Encaps => "ML-KEM-1024 encaps",
            Self::MlKem1024Decaps => "ML-KEM-1024 decaps",
            Self::MlKem1024Keygen => "ML-KEM-1024 keygen",
            Self::MlKem512Encaps => "ML-KEM-512 encaps",
            Self::MlKem512Decaps => "ML-KEM-512 decaps",
            Self::MlKem512Keygen => "ML-KEM-512 keygen",
            Self::MlKem768Encaps => "ML-KEM-768 encaps",
            Self::MlKem768Decaps => "ML-KEM-768 decaps",
            Self::MlKem768Keygen => "ML-KEM-768 keygen",
            Self::MlDsa87Sign => "ML-DSA-87 sign",
            Self::MlDsa87Verify => "ML-DSA-87 verify",
            Self::MlDsa87Keygen => "ML-DSA-87 keygen",
            Self::MlDsa44Sign => "ML-DSA-44 sign",
            Self::MlDsa44Verify => "ML-DSA-44 verify",
            Self::MlDsa44Keygen => "ML-DSA-44 keygen",
            Self::MlDsa65Sign => "ML-DSA-65 sign",
            Self::MlDsa65Verify => "ML-DSA-65 verify",
            Self::MlDsa65Keygen => "ML-DSA-65 keygen",
            Self::SlhDsaSha2256sKeygen => "SLH-DSA-SHA2-256s keygen",
            Self::SlhDsaSha2256sSign => "SLH-DSA-SHA2-256s sign",
            Self::SlhDsaSha2256sVerify => "SLH-DSA-SHA2-256s verify",
            Self::SlhDsaSha2128sKeygen => "SLH-DSA-SHA2-128s keygen",
            Self::SlhDsaSha2128sSign => "SLH-DSA-SHA2-128s sign",
            Self::SlhDsaSha2128sVerify => "SLH-DSA-SHA2-128s verify",
            Self::SlhDsaSha2128fKeygen => "SLH-DSA-SHA2-128f keygen",
            Self::SlhDsaSha2128fSign => "SLH-DSA-SHA2-128f sign",
            Self::SlhDsaSha2128fVerify => "SLH-DSA-SHA2-128f verify",
            Self::SlhDsaSha2192sKeygen => "SLH-DSA-SHA2-192s keygen",
            Self::SlhDsaSha2192sSign => "SLH-DSA-SHA2-192s sign",
            Self::SlhDsaSha2192sVerify => "SLH-DSA-SHA2-192s verify",
            Self::SlhDsaSha2192fKeygen => "SLH-DSA-SHA2-192f keygen",
            Self::SlhDsaSha2192fSign => "SLH-DSA-SHA2-192f sign",
            Self::SlhDsaSha2192fVerify => "SLH-DSA-SHA2-192f verify",
            Self::SlhDsaSha2256fKeygen => "SLH-DSA-SHA2-256f keygen",
            Self::SlhDsaSha2256fSign => "SLH-DSA-SHA2-256f sign",
            Self::SlhDsaSha2256fVerify => "SLH-DSA-SHA2-256f verify",
            Self::SlhDsaShake128sKeygen => "SLH-DSA-SHAKE-128s keygen",
            Self::SlhDsaShake128sSign => "SLH-DSA-SHAKE-128s sign",
            Self::SlhDsaShake128sVerify => "SLH-DSA-SHAKE-128s verify",
            Self::SlhDsaShake128fKeygen => "SLH-DSA-SHAKE-128f keygen",
            Self::SlhDsaShake128fSign => "SLH-DSA-SHAKE-128f sign",
            Self::SlhDsaShake128fVerify => "SLH-DSA-SHAKE-128f verify",
            Self::SlhDsaShake192sKeygen => "SLH-DSA-SHAKE-192s keygen",
            Self::SlhDsaShake192sSign => "SLH-DSA-SHAKE-192s sign",
            Self::SlhDsaShake192sVerify => "SLH-DSA-SHAKE-192s verify",
            Self::SlhDsaShake192fKeygen => "SLH-DSA-SHAKE-192f keygen",
            Self::SlhDsaShake192fSign => "SLH-DSA-SHAKE-192f sign",
            Self::SlhDsaShake192fVerify => "SLH-DSA-SHAKE-192f verify",
            Self::SlhDsaShake256sKeygen => "SLH-DSA-SHAKE-256s keygen",
            Self::SlhDsaShake256sSign => "SLH-DSA-SHAKE-256s sign",
            Self::SlhDsaShake256sVerify => "SLH-DSA-SHAKE-256s verify",
            Self::SlhDsaShake256fKeygen => "SLH-DSA-SHAKE-256f keygen",
            Self::SlhDsaShake256fSign => "SLH-DSA-SHAKE-256f sign",
            Self::SlhDsaShake256fVerify => "SLH-DSA-SHAKE-256f verify",
            Self::LmsSha256M32H5W1Verify => "LMS SHA-256 M=32 H=5 W=1 verify",
            Self::LmsSha256M32H5W2Verify => "LMS SHA-256 M=32 H=5 W=2 verify",
            Self::LmsSha256M32H5W4Verify => "LMS SHA-256 M=32 H=5 W=4 verify",
            Self::LmsSha256M32H5W8Verify => "LMS SHA-256 M=32 H=5 W=8 verify",
            Self::LmsSha256M32H10W1Verify => "LMS SHA-256 M=32 H=10 W=1 verify",
            Self::LmsSha256M32H10W2Verify => "LMS SHA-256 M=32 H=10 W=2 verify",
            Self::LmsSha256M32H10W4Verify => "LMS SHA-256 M=32 H=10 W=4 verify",
            Self::LmsSha256M32H10W8Verify => "LMS SHA-256 M=32 H=10 W=8 verify",
            Self::LmsSha256M32H15W1Verify => "LMS SHA-256 M=32 H=15 W=1 verify",
            Self::LmsSha256M32H15W2Verify => "LMS SHA-256 M=32 H=15 W=2 verify",
            Self::LmsSha256M32H15W4Verify => "LMS SHA-256 M=32 H=15 W=4 verify",
            Self::LmsSha256M32H15W8Verify => "LMS SHA-256 M=32 H=15 W=8 verify",
            Self::LmsSha256M32H20W1Verify => "LMS SHA-256 M=32 H=20 W=1 verify",
            Self::LmsSha256M32H20W2Verify => "LMS SHA-256 M=32 H=20 W=2 verify",
            Self::LmsSha256M32H20W4Verify => "LMS SHA-256 M=32 H=20 W=4 verify",
            Self::LmsSha256M32H20W8Verify => "LMS SHA-256 M=32 H=20 W=8 verify",
            Self::LmsSha256M32H25W1Verify => "LMS SHA-256 M=32 H=25 W=1 verify",
            Self::LmsSha256M32H25W2Verify => "LMS SHA-256 M=32 H=25 W=2 verify",
            Self::LmsSha256M32H25W4Verify => "LMS SHA-256 M=32 H=25 W=4 verify",
            Self::LmsSha256M32H25W8Verify => "LMS SHA-256 M=32 H=25 W=8 verify",
            Self::LmsSha256M24H5W1Verify => "LMS SHA-256 M=24 H=5 W=1 verify",
            Self::LmsSha256M24H5W2Verify => "LMS SHA-256 M=24 H=5 W=2 verify",
            Self::LmsSha256M24H5W4Verify => "LMS SHA-256 M=24 H=5 W=4 verify",
            Self::LmsSha256M24H5W8Verify => "LMS SHA-256 M=24 H=5 W=8 verify",
            Self::LmsSha256M24H10W1Verify => "LMS SHA-256 M=24 H=10 W=1 verify",
            Self::LmsSha256M24H10W2Verify => "LMS SHA-256 M=24 H=10 W=2 verify",
            Self::LmsSha256M24H10W4Verify => "LMS SHA-256 M=24 H=10 W=4 verify",
            Self::LmsSha256M24H10W8Verify => "LMS SHA-256 M=24 H=10 W=8 verify",
            Self::LmsSha256M24H15W1Verify => "LMS SHA-256 M=24 H=15 W=1 verify",
            Self::LmsSha256M24H15W2Verify => "LMS SHA-256 M=24 H=15 W=2 verify",
            Self::LmsSha256M24H15W4Verify => "LMS SHA-256 M=24 H=15 W=4 verify",
            Self::LmsSha256M24H15W8Verify => "LMS SHA-256 M=24 H=15 W=8 verify",
            Self::LmsSha256M24H20W1Verify => "LMS SHA-256 M=24 H=20 W=1 verify",
            Self::LmsSha256M24H20W2Verify => "LMS SHA-256 M=24 H=20 W=2 verify",
            Self::LmsSha256M24H20W4Verify => "LMS SHA-256 M=24 H=20 W=4 verify",
            Self::LmsSha256M24H20W8Verify => "LMS SHA-256 M=24 H=20 W=8 verify",
            Self::LmsSha256M24H25W1Verify => "LMS SHA-256 M=24 H=25 W=1 verify",
            Self::LmsSha256M24H25W2Verify => "LMS SHA-256 M=24 H=25 W=2 verify",
            Self::LmsSha256M24H25W4Verify => "LMS SHA-256 M=24 H=25 W=4 verify",
            Self::LmsSha256M24H25W8Verify => "LMS SHA-256 M=24 H=25 W=8 verify",
            Self::LmsShakeM32H5W1Verify => "LMS SHAKE M=32 H=5 W=1 verify",
            Self::LmsShakeM32H5W2Verify => "LMS SHAKE M=32 H=5 W=2 verify",
            Self::LmsShakeM32H5W4Verify => "LMS SHAKE M=32 H=5 W=4 verify",
            Self::LmsShakeM32H5W8Verify => "LMS SHAKE M=32 H=5 W=8 verify",
            Self::LmsShakeM32H10W1Verify => "LMS SHAKE M=32 H=10 W=1 verify",
            Self::LmsShakeM32H10W2Verify => "LMS SHAKE M=32 H=10 W=2 verify",
            Self::LmsShakeM32H10W4Verify => "LMS SHAKE M=32 H=10 W=4 verify",
            Self::LmsShakeM32H10W8Verify => "LMS SHAKE M=32 H=10 W=8 verify",
            Self::LmsShakeM32H15W1Verify => "LMS SHAKE M=32 H=15 W=1 verify",
            Self::LmsShakeM32H15W2Verify => "LMS SHAKE M=32 H=15 W=2 verify",
            Self::LmsShakeM32H15W4Verify => "LMS SHAKE M=32 H=15 W=4 verify",
            Self::LmsShakeM32H15W8Verify => "LMS SHAKE M=32 H=15 W=8 verify",
            Self::LmsShakeM32H20W1Verify => "LMS SHAKE M=32 H=20 W=1 verify",
            Self::LmsShakeM32H20W2Verify => "LMS SHAKE M=32 H=20 W=2 verify",
            Self::LmsShakeM32H20W4Verify => "LMS SHAKE M=32 H=20 W=4 verify",
            Self::LmsShakeM32H20W8Verify => "LMS SHAKE M=32 H=20 W=8 verify",
            Self::LmsShakeM32H25W1Verify => "LMS SHAKE M=32 H=25 W=1 verify",
            Self::LmsShakeM32H25W2Verify => "LMS SHAKE M=32 H=25 W=2 verify",
            Self::LmsShakeM32H25W4Verify => "LMS SHAKE M=32 H=25 W=4 verify",
            Self::LmsShakeM32H25W8Verify => "LMS SHAKE M=32 H=25 W=8 verify",
            Self::LmsShakeM24H5W1Verify => "LMS SHAKE M=24 H=5 W=1 verify",
            Self::LmsShakeM24H5W2Verify => "LMS SHAKE M=24 H=5 W=2 verify",
            Self::LmsShakeM24H5W4Verify => "LMS SHAKE M=24 H=5 W=4 verify",
            Self::LmsShakeM24H5W8Verify => "LMS SHAKE M=24 H=5 W=8 verify",
            Self::LmsShakeM24H10W1Verify => "LMS SHAKE M=24 H=10 W=1 verify",
            Self::LmsShakeM24H10W2Verify => "LMS SHAKE M=24 H=10 W=2 verify",
            Self::LmsShakeM24H10W4Verify => "LMS SHAKE M=24 H=10 W=4 verify",
            Self::LmsShakeM24H10W8Verify => "LMS SHAKE M=24 H=10 W=8 verify",
            Self::LmsShakeM24H15W1Verify => "LMS SHAKE M=24 H=15 W=1 verify",
            Self::LmsShakeM24H15W2Verify => "LMS SHAKE M=24 H=15 W=2 verify",
            Self::LmsShakeM24H15W4Verify => "LMS SHAKE M=24 H=15 W=4 verify",
            Self::LmsShakeM24H15W8Verify => "LMS SHAKE M=24 H=15 W=8 verify",
            Self::LmsShakeM24H20W1Verify => "LMS SHAKE M=24 H=20 W=1 verify",
            Self::LmsShakeM24H20W2Verify => "LMS SHAKE M=24 H=20 W=2 verify",
            Self::LmsShakeM24H20W4Verify => "LMS SHAKE M=24 H=20 W=4 verify",
            Self::LmsShakeM24H20W8Verify => "LMS SHAKE M=24 H=20 W=8 verify",
            Self::LmsShakeM24H25W1Verify => "LMS SHAKE M=24 H=25 W=1 verify",
            Self::LmsShakeM24H25W2Verify => "LMS SHAKE M=24 H=25 W=2 verify",
            Self::LmsShakeM24H25W4Verify => "LMS SHAKE M=24 H=25 W=4 verify",
            Self::LmsShakeM24H25W8Verify => "LMS SHAKE M=24 H=25 W=8 verify",
            Self::XmssVerify => "XMSS verify",
            Self::Dh3072 => "DH-3072",
        };
        f.write_str(name)
    }
}

/// Guard used at the entry point of every approved service, after
/// [`require_operational`], to enforce the active algorithm profile.
///
/// Returns `Ok(())` if the service is permitted under the profile
/// selected at initialization, or
/// `Err(Error::AlgorithmRestricted { .. })` otherwise.
///
/// This gate does **not** check [`State`] — callers must call
/// [`require_operational`] first. The two-gate pattern is:
///
/// ```ignore
/// require_operational()?;
/// require_allowed(Service::Sha256)?;
/// // ... perform the operation
/// ```
pub fn require_allowed(service: Service) -> Result<(), Error> {
    let profile = active_profile();
    if is_allowed(profile, service) {
        Ok(())
    } else {
        Err(Error::AlgorithmRestricted { service })
    }
}

/// Single source of truth for which services are allowed in each
/// profile.
const fn is_allowed(profile: AlgorithmProfile, service: Service) -> bool {
    match profile {
        AlgorithmProfile::Unrestricted => true,
        AlgorithmProfile::Cnsa2 => is_cnsa2_allowed(service),
        AlgorithmProfile::Cnsa1 => is_cnsa1_allowed(service),
        // Derived from the two suites rather than enumerated a third time:
        // a hand-written union is a third list that could drift from the
        // other two. `is_cnsa2_allowed` already
        // covers the LMS block, so naming it again here would be that third
        // rule in miniature.
        AlgorithmProfile::Migration => is_cnsa1_allowed(service) || is_cnsa2_allowed(service),
    }
}

/// True for every LMS service, matching on the discriminant block the
/// `Service` enum reserves for LMS.
///
/// An arithmetic test rather than 80 enumerated arms: the LMS services
/// occupy every odd value in `501..=659` and nothing else does. That is a
/// property of the enum, not of this function, so it is pinned separately
/// by `lms_discriminant_slots_are_complete_and_pure` — without which a
/// variant inserted on an odd value in the block would silently become
/// CNSA-permitted.
const fn is_lms_service(service: Service) -> bool {
    lms_block_contains(service as u16)
}

/// The arithmetic behind [`is_lms_service`], over a raw discriminant: an odd
/// value in `501..=659`.
///
/// Split out so the boundaries can be tested at all. `is_lms_service` takes a
/// `Service`, and the LMS block sits at the very top of the enum — there is no
/// variant above 659 — so a widened *upper* bound admits nothing today and no
/// `Service`-typed probe can detect it. Over a raw `u16`, both edges and the
/// parity are reachable: `lms_block_boundaries_are_exact` pins
/// 499/500/501/502/658/659/660/661, which fails if either bound moves in
/// either direction or the parity test is dropped.
const fn lms_block_contains(discriminant: u16) -> bool {
    discriminant >= Service::LmsSha256M32H5W1Verify as u16
        && discriminant <= Service::LmsShakeM24H25W8Verify as u16
        && discriminant & 1 == 1
}

/// Every LMS service, in discriminant order: one `Verify` per (LMS, LM-OTS)
/// pair of SP 800-208 §4.1–§4.4. Explicit rather than generated: CMVP
/// reviewers read this list, and a macro would hide exactly what it must
/// show.
const LMS_SERVICES: [Service; 80] = [
    // SHA-256 / N=32 family (20 pairs).
    Service::LmsSha256M32H5W1Verify,
    Service::LmsSha256M32H5W2Verify,
    Service::LmsSha256M32H5W4Verify,
    Service::LmsSha256M32H5W8Verify,
    Service::LmsSha256M32H10W1Verify,
    Service::LmsSha256M32H10W2Verify,
    Service::LmsSha256M32H10W4Verify,
    Service::LmsSha256M32H10W8Verify,
    Service::LmsSha256M32H15W1Verify,
    Service::LmsSha256M32H15W2Verify,
    Service::LmsSha256M32H15W4Verify,
    Service::LmsSha256M32H15W8Verify,
    Service::LmsSha256M32H20W1Verify,
    Service::LmsSha256M32H20W2Verify,
    Service::LmsSha256M32H20W4Verify,
    Service::LmsSha256M32H20W8Verify,
    Service::LmsSha256M32H25W1Verify,
    Service::LmsSha256M32H25W2Verify,
    Service::LmsSha256M32H25W4Verify,
    Service::LmsSha256M32H25W8Verify,
    // SHA-256 / N=24 family (20 pairs).
    Service::LmsSha256M24H5W1Verify,
    Service::LmsSha256M24H5W2Verify,
    Service::LmsSha256M24H5W4Verify,
    Service::LmsSha256M24H5W8Verify,
    Service::LmsSha256M24H10W1Verify,
    Service::LmsSha256M24H10W2Verify,
    Service::LmsSha256M24H10W4Verify,
    Service::LmsSha256M24H10W8Verify,
    Service::LmsSha256M24H15W1Verify,
    Service::LmsSha256M24H15W2Verify,
    Service::LmsSha256M24H15W4Verify,
    Service::LmsSha256M24H15W8Verify,
    Service::LmsSha256M24H20W1Verify,
    Service::LmsSha256M24H20W2Verify,
    Service::LmsSha256M24H20W4Verify,
    Service::LmsSha256M24H20W8Verify,
    Service::LmsSha256M24H25W1Verify,
    Service::LmsSha256M24H25W2Verify,
    Service::LmsSha256M24H25W4Verify,
    Service::LmsSha256M24H25W8Verify,
    // SHAKE-256 / N=32 family (20 pairs).
    Service::LmsShakeM32H5W1Verify,
    Service::LmsShakeM32H5W2Verify,
    Service::LmsShakeM32H5W4Verify,
    Service::LmsShakeM32H5W8Verify,
    Service::LmsShakeM32H10W1Verify,
    Service::LmsShakeM32H10W2Verify,
    Service::LmsShakeM32H10W4Verify,
    Service::LmsShakeM32H10W8Verify,
    Service::LmsShakeM32H15W1Verify,
    Service::LmsShakeM32H15W2Verify,
    Service::LmsShakeM32H15W4Verify,
    Service::LmsShakeM32H15W8Verify,
    Service::LmsShakeM32H20W1Verify,
    Service::LmsShakeM32H20W2Verify,
    Service::LmsShakeM32H20W4Verify,
    Service::LmsShakeM32H20W8Verify,
    Service::LmsShakeM32H25W1Verify,
    Service::LmsShakeM32H25W2Verify,
    Service::LmsShakeM32H25W4Verify,
    Service::LmsShakeM32H25W8Verify,
    // SHAKE-256 / N=24 family (20 pairs).
    Service::LmsShakeM24H5W1Verify,
    Service::LmsShakeM24H5W2Verify,
    Service::LmsShakeM24H5W4Verify,
    Service::LmsShakeM24H5W8Verify,
    Service::LmsShakeM24H10W1Verify,
    Service::LmsShakeM24H10W2Verify,
    Service::LmsShakeM24H10W4Verify,
    Service::LmsShakeM24H10W8Verify,
    Service::LmsShakeM24H15W1Verify,
    Service::LmsShakeM24H15W2Verify,
    Service::LmsShakeM24H15W4Verify,
    Service::LmsShakeM24H15W8Verify,
    Service::LmsShakeM24H20W1Verify,
    Service::LmsShakeM24H20W2Verify,
    Service::LmsShakeM24H20W4Verify,
    Service::LmsShakeM24H20W8Verify,
    Service::LmsShakeM24H25W1Verify,
    Service::LmsShakeM24H25W2Verify,
    Service::LmsShakeM24H25W4Verify,
    Service::LmsShakeM24H25W8Verify,
];

// Build-time check that the LMS services fill the odd discriminants
// 501..=659 in order, one per slot, and that `lms_block_contains` admits
// each. A missing, duplicated or moved LMS variant fails compilation.
// Whether a non-LMS variant sits on an odd slot needs the full variant
// list, so `lms_discriminant_slots_are_complete_and_pure` checks that.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const _: () = {
    let mut i = 0;
    let mut slot: u16 = 501;
    while i < LMS_SERVICES.len() {
        let d = LMS_SERVICES[i] as u16;
        assert!(d == slot, "LMS service out of its slot");
        assert!(lms_block_contains(d), "LMS service outside the LMS block");
        slot += 2;
        i += 1;
    }
    assert!(
        LMS_SERVICES[79] as u16 == 659,
        "LMS block does not end at 659"
    );
};

/// CNSA 2.0 allowed set — CNSSP-15 (March 2025) Annex B.
///
/// The suite names AES-256, ML-KEM-1024, ML-DSA-87, SHA-384 or SHA-512,
/// and the SP 800-208 stateful hash-based signatures for software and
/// firmware signing. It names no Keccak-family hash or XOF: SHA-3
/// appears only as "allowed for internal hardware functionality", and
/// the policy states that algorithms using SHA3 as a component, such as
/// LMS or ML-KEM, do not thereby make SHA3 an approved hash function.
/// This module is software, so no Keccak service is permitted here —
/// ML-KEM and ML-DSA reach Keccak through `new_internal`, which is a
/// component path and not a service.
const fn is_cnsa2_allowed(service: Service) -> bool {
    matches!(
        service,
        // AES-256 all modes
        Service::Aes256Ecb
            | Service::Aes256Cbc
            | Service::Aes256Ctr
            | Service::Aes256Gcm
            | Service::Aes256Ccm
            | Service::Aes256Kw
            | Service::Aes256Kwp
            | Service::Aes256
            // SHA-384, SHA-512
            | Service::Sha384
            | Service::Sha512
            // No Keccak-family service: Annex B allows SHA3-384/512 only
            // for internal hardware functionality, which a software module
            // cannot claim, and names no SHAKE, KMAC, TupleHash or
            // ParallelHash at all.
            // HMAC with allowed hashes
            | Service::HmacSha384
            | Service::HmacSha512
            // CMAC-AES-256
            | Service::CmacAes256
            // DRBGs backed by AES-256 or SHA-384/512
            | Service::CtrDrbgAes256
            | Service::HashDrbgSha384
            | Service::HashDrbgSha512
            | Service::HmacDrbgSha384
            | Service::HmacDrbgSha512
            // KDFs with allowed backing
            | Service::HkdfSha384
            | Service::HkdfSha512
            | Service::KbkdfHmacSha384
            | Service::KbkdfHmacSha512
            | Service::KbkdfCmacAes256
            // No TLS KDF: Annex B names no protocol-specific key derivation
            // function, and none is required in order to operate an algorithm
            // the suite does name. Both reach the fail-safe default-block.
            // Post-quantum (CNSA 2.0 core)
            | Service::MlKem1024Encaps
            | Service::MlKem1024Decaps
            | Service::MlKem1024Keygen
            | Service::MlDsa87Sign
            | Service::MlDsa87Verify
            | Service::MlDsa87Keygen
            // XMSS — SP 800-208 verification. §8.1 confines key generation and
            // signing to hardware modules, so the module offers neither.
            | Service::XmssVerify
    )
        // LMS — SP 800-208 stateful HBS for software/firmware signing.
        // CNSSP-15 Annex B states "all parameters appropriate to protect to
        // TOP SECRET", recommending LMS-SHA-256/192, so every approved
        // parameter set the module implements is permitted rather than a
        // subset. Every non-LMS service outside the arms above still reaches
        // the `matches!` fail-safe default-block.
        || is_lms_service(service)
}

/// CNSA 1.0 allowed set — CNSSP-15 (October 2016) Annex B.
///
/// Annex B names seven families with their parameters: AES with 256-bit
/// keys, ECDH on Curve P-384, ECDSA on Curve P-384, SHA-384, Diffie-Hellman
/// with a minimum 3072-bit modulus, RSA with a minimum 3072-bit modulus for
/// key establishment, and RSA with a minimum 3072-bit modulus for digital
/// signatures. It names no hash other than SHA-384 and no Keccak-family
/// algorithm at all — the policy does not cite FIPS PUB 202.
///
/// The suite names no DRBG, MAC or KDF, because it states what protects
/// information rather than every primitive a module needs in order to do
/// so. This gate therefore also admits the supporting services required to
/// operate the named algorithms **at matching strength**: the DRBGs that
/// seed their key generation, and the MAC and KDFs at the SHA-384 /
/// AES-256 security level. Anything weaker than the suite requires is
/// refused, SHA-256 and its HMAC, DRBG and KDF variants included.
///
/// Annex B's Additional Information paragraph permits RSA and Diffie-Hellman
/// at 2048, SHA-256, and P-256 "in the near term", but only for deployments
/// protecting UNCLASSIFIED NSS data or providing community-of-interest
/// separation, and it requires consulting NSA before deploying a curve other
/// than P-384. Those conditions turn on the classification of the data and on
/// an external approval, neither of which a module can evaluate, so this gate
/// refuses them and the Security Policy carries the allowance as an operator
/// obligation. [`AlgorithmProfile::Migration`] is the profile for a
/// deployment that needs both suites at once.
const fn is_cnsa1_allowed(service: Service) -> bool {
    matches!(
        service,
        // AES-256 — FIPS PUB 197, "Use 256 bit keys to protect up to TOP SECRET"
        Service::Aes256
            | Service::Aes256Ecb
            | Service::Aes256Cbc
            | Service::Aes256Ctr
            | Service::Aes256Gcm
            | Service::Aes256Ccm
            | Service::Aes256Kw
            | Service::Aes256Kwp
            // ECDH — SP 800-56A Rev 2, "Use Curve P-384 to protect up to TOP SECRET"
            | Service::EcdhP384
            // ECDSA — FIPS PUB 186-4, "Use Curve P-384 to protect up to TOP SECRET"
            | Service::EcdsaP384Keygen
            | Service::EcdsaP384Sign
            | Service::EcdsaP384Verify
            // SHA — FIPS PUB 180-4, "Use SHA-384 to protect up to TOP SECRET"
            | Service::Sha384
            // Diffie-Hellman — IETF RFC 3526, minimum 3072-bit modulus
            | Service::Dh3072
            // RSA key establishment — SP 800-56B Rev 1, minimum 3072-bit modulus
            | Service::RsaKeygen3072
            | Service::RsaKeygen4096
            | Service::RsaOaep3072
            | Service::RsaOaep4096
            // RSA digital signatures — FIPS PUB 186-4, minimum 3072-bit modulus
            | Service::RsaPkcs1v15Sign3072
            | Service::RsaPkcs1v15Sign4096
            | Service::RsaPkcs1v15Verify3072
            | Service::RsaPkcs1v15Verify4096
            | Service::RsaPssSign3072
            | Service::RsaPssSign4096
            | Service::RsaPssVerify3072
            | Service::RsaPssVerify4096
            // Supporting services at the suite's own strength: the DRBGs that
            // seed key generation for the algorithms above, and the MAC and
            // KDFs at the SHA-384 / AES-256 level.
            | Service::CtrDrbgAes256
            | Service::HashDrbgSha384
            | Service::HmacDrbgSha384
            | Service::HmacSha384
            | Service::CmacAes256
            | Service::HkdfSha384
            | Service::KbkdfHmacSha384
            | Service::KbkdfCmacAes256
    )
}

// -------------------------------------------------------------------------
// Test-only utilities
// -------------------------------------------------------------------------
//
// The global `STATE` makes the normal lifecycle effectively run-once per
// process. Unit tests in this crate need to exercise multiple transitions,
// so we expose a test-only reset helper gated behind `cfg(test)`. It is
// **not** part of the public API and is not compiled into release builds.

/// The test-only state lock, in its own module so the guard cannot be forged.
///
/// The globals are a process singleton and cargo runs unit tests on a parallel
/// thread pool, so without serialisation one test's reset lands inside
/// another's initialize-then-assert window and the second observes a profile it
/// did not install. Measured at 1 failure in 20 runs before this lock, on
/// `require_allowed_returns_restricted_error_under_cnsa2`.
///
/// Serialising is deliberate where per-test isolation would be easier: the
/// singleton is the thing under test, and giving each test private state would
/// stop exercising it.
///
/// **Why a module and not merely a private field.** `MutexGuard` carries no
/// identity tying it to a particular static, so a `StateGuard` wrapping *any*
/// mutex would satisfy the type and still reach `reset`. Confining the type
/// here — field private to this module — means the only way to obtain one is
/// [`reset_for_test`], which takes the real lock; a sibling module cannot build
/// a decoy. Editing this module still defeats it. That is the honest bound, and
/// it is a much smaller one than "every future test must remember".
#[cfg(test)]
pub(crate) mod state_lock {
    use super::{AlgorithmProfile, Ordering, PROFILE, STATE, State};

    static STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Proof that the holder owns the state lock. Constructible only by
    /// [`reset_for_test`], because the field is private to this module.
    #[must_use]
    pub(crate) struct StateGuard(
        /// Held for its `Drop`, never read: the lock releases when the guard
        /// leaves the test's scope.
        #[allow(dead_code)]
        std::sync::MutexGuard<'static, ()>,
    );

    impl StateGuard {
        /// Re-reset inside a test that already holds the lock — a loop over
        /// profiles needs fresh state per iteration without releasing it.
        // `&self` is the point: it is the proof the caller holds the lock.
        #[allow(clippy::unused_self)]
        pub(crate) fn reset(&self) {
            STATE.store(State::PowerOff as u64, Ordering::Release);
            PROFILE.store(AlgorithmProfile::Unrestricted as u8, Ordering::Release);
        }
    }

    /// Resets the module to power-off and returns the guard that makes the
    /// reset safe. The lock is not a convention a future test has to remember:
    /// this is the only way to obtain a `StateGuard`, and `StateGuard` is the
    /// only way to reach a reset.
    ///
    /// `StateGuard` is `#[must_use]`, so a bare `reset_for_test();` fails
    /// `clippy -D warnings`, which the workspace gate runs — dropping the guard
    /// early breaks the build rather than reintroducing the race quietly.
    ///
    /// Residual, stated rather than implied: `let _ = reset_for_test();` still
    /// drops the guard immediately and does not warn. That is a deliberate act,
    /// which is the most this construction can bound.
    ///
    /// A panicking test poisons the mutex. The poison carries no meaning here
    /// because the state it protects is unconditionally overwritten on the next
    /// line, so it is recovered rather than propagated.
    pub(crate) fn reset_for_test() -> StateGuard {
        let guard = StateGuard(
            STATE_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        guard.reset();
        guard
    }
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::state_lock::reset_for_test;
    use super::{
        AlgorithmProfile, Error, KatEntry, LMS_SERVICES, SelfTest, SelfTestFailure, Service, State,
        active_profile, enter_error_state, initialize_with_profile, initialize_with_tests,
        is_allowed, is_lms_service, is_operational, lms_block_contains, require_allowed,
        require_operational, require_self_test_started, state,
    };
    use alloc::string::ToString;
    use core::sync::atomic::Ordering;

    /// Stands in for the pre-operational integrity test.
    ///
    /// A `cargo test` binary is never signed, so the real integrity test
    /// cannot pass inside one. The module requires an integrity group to
    /// initialise at all, so a test that needs a gated service declares
    /// this stub — visibly, at the call site — rather than the module
    /// offering any way to skip the requirement.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    // Both of these helpers are used as `fn() -> Result<(), SelfTestFailure>`
    // function pointers in `KatEntry`, so the `Result` wrapper is mandatory
    // even though clippy sees each body as always returning the same variant.
    #[allow(clippy::unnecessary_wraps)]
    fn always_pass() -> Result<(), SelfTestFailure> {
        Ok(())
    }
    fn always_fail() -> Result<(), SelfTestFailure> {
        Err(SelfTestFailure)
    }

    /// How many times [`count_unreached`] has run.
    static UNREACHED_RUNS: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    /// A self-test that only counts its runs.
    #[allow(clippy::unnecessary_wraps)]
    fn count_unreached() -> Result<(), SelfTestFailure> {
        UNREACHED_RUNS.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    // All tests in this module share the single global `STATE`, so they
    // cannot run in parallel. `cargo test` in this crate must be invoked
    // with `--test-threads=1` — enforced by the CI workflow.

    #[test]
    fn initial_state_is_power_off() {
        let _guard = reset_for_test();
        assert_eq!(state(), State::PowerOff);
        assert!(!is_operational());
    }

    #[test]
    fn initialize_transitions_to_operational() {
        let _guard = reset_for_test();
        initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap();
        assert_eq!(state(), State::Operational);
        assert!(is_operational());
        require_operational().unwrap();
    }

    #[test]
    fn second_initialize_reports_already_initialized() {
        let _guard = reset_for_test();
        initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap();
        match initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
            Err(Error::AlreadyInitialized) => {}
            other => panic!("expected AlreadyInitialized, got {other:?}"),
        }
    }

    #[test]
    fn require_operational_rejects_power_off() {
        let _guard = reset_for_test();
        match require_operational() {
            Err(Error::NotOperational {
                current: State::PowerOff,
            }) => {}
            other => panic!("expected NotOperational{{PowerOff}}, got {other:?}"),
        }
    }

    #[test]
    fn enter_error_state_is_terminal_for_require_operational() {
        let _guard = reset_for_test();
        initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap();
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

    /// A power-up test that passes only if the guard admits the state the
    /// module is in while the self-tests run.
    fn guard_admits_self_test() -> Result<(), SelfTestFailure> {
        if state() != State::SelfTest {
            return Err(SelfTestFailure);
        }
        require_self_test_started().map_err(|_| SelfTestFailure)
    }

    #[test]
    fn require_self_test_started_rejects_power_off() {
        let _guard = reset_for_test();
        assert_eq!(
            require_self_test_started(),
            Err(Error::NotOperational {
                current: State::PowerOff
            })
        );
    }

    #[test]
    fn require_self_test_started_rejects_error_after_failed_init() {
        let _guard = reset_for_test();
        let tests = [KatEntry {
            name: "dummy-fail",
            run: always_fail,
        }];
        assert!(initialize_with_tests(UNSIGNED_TEST_BINARY, &tests).is_err());
        assert_eq!(state(), State::Error);
        assert_eq!(
            require_self_test_started(),
            Err(Error::NotOperational {
                current: State::Error
            })
        );
    }

    #[test]
    fn require_self_test_started_rejects_integrity_unverified() {
        let _guard = reset_for_test();
        assert_eq!(
            initialize_with_tests(&[], &[]),
            Err(Error::IntegrityNotAttested)
        );
        assert_eq!(state(), State::IntegrityUnverified);
        assert_eq!(
            require_self_test_started(),
            Err(Error::NotOperational {
                current: State::IntegrityUnverified
            })
        );
    }

    /// Initialising again after `IntegrityUnverified` reports
    /// `AlreadyFailed`, runs no test, and leaves the state where it was.
    #[test]
    fn initialize_after_integrity_unverified_is_already_failed() {
        let _guard = reset_for_test();
        assert_eq!(
            initialize_with_tests(&[], &[]),
            Err(Error::IntegrityNotAttested)
        );
        assert_eq!(state(), State::IntegrityUnverified);
        let counting = [KatEntry {
            name: "counts its runs",
            run: count_unreached,
        }];
        UNREACHED_RUNS.store(0, Ordering::Release);
        assert_eq!(
            initialize_with_tests(UNSIGNED_TEST_BINARY, &counting),
            Err(Error::AlreadyFailed)
        );
        assert_eq!(UNREACHED_RUNS.load(Ordering::Acquire), 0);
        assert_eq!(state(), State::IntegrityUnverified);
    }

    #[test]
    fn require_self_test_started_admits_self_test_and_operational() {
        let _guard = reset_for_test();
        let tests = [KatEntry {
            name: "guard admits SelfTest",
            run: guard_admits_self_test,
        }];
        initialize_with_tests(UNSIGNED_TEST_BINARY, &tests).unwrap();
        assert_eq!(state(), State::Operational);
        assert_eq!(require_self_test_started(), Ok(()));
    }

    /// Every word this module never writes reads as `Error`, and both guards
    /// refuse it.
    #[test]
    fn a_malformed_state_word_reads_as_error() {
        let guard = reset_for_test();
        let owner = 0x1234_u64 << super::STATE_BITS;
        let malformed = [
            // `SelfTest` with no owner.
            State::SelfTest as u64,
            // `Operational`, `PowerOff` and `IntegrityUnverified` with owner bits.
            State::Operational as u64 | owner,
            State::PowerOff as u64 | owner,
            State::IntegrityUnverified as u64 | owner,
            // Unknown discriminants, with and without owner bits.
            5,
            0xff,
            0xff | owner,
        ];
        assert_eq!(malformed.len(), 7);
        for word in malformed {
            guard.reset();
            super::STATE.store(word, Ordering::Release);
            assert_eq!(state(), State::Error, "word {word:#x}");
            assert!(!is_operational(), "word {word:#x}");
            assert_eq!(
                require_operational(),
                Err(Error::NotOperational {
                    current: State::Error
                }),
                "word {word:#x}"
            );
            assert_eq!(
                require_self_test_started(),
                Err(Error::NotOperational {
                    current: State::Error
                }),
                "word {word:#x}"
            );
        }
        // Control: the well-formed words still decode to themselves.
        guard.reset();
        assert_eq!(state(), State::PowerOff);
        super::STATE.store(State::Operational as u64, Ordering::Release);
        assert_eq!(state(), State::Operational);
    }

    /// Released by [`loser_waits_then_gets_already_failed`] once its loser is
    /// seen waiting.
    static RELEASE_FAILING_WINNER: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    /// Set by the failing winner once it holds `SelfTest`.
    static FAILING_WINNER_PAUSED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    /// Waits for `done`, failing the test after 30 seconds.
    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let start = std::time::Instant::now();
        while !done() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(30),
                "timed out waiting for {what}"
            );
            std::thread::yield_now();
        }
    }

    fn paused_then_fails() -> Result<(), SelfTestFailure> {
        FAILING_WINNER_PAUSED.store(true, Ordering::Release);
        wait_until("the release of the failing winner", || {
            RELEASE_FAILING_WINNER.load(Ordering::Acquire)
        });
        Err(SelfTestFailure)
    }

    /// A loser of a winner whose self-tests then fail is seen waiting in
    /// the loser path, and once the winner fails it reports `AlreadyFailed`.
    #[test]
    fn loser_waits_then_gets_already_failed() {
        let _guard = reset_for_test();
        FAILING_WINNER_PAUSED.store(false, Ordering::Release);
        RELEASE_FAILING_WINNER.store(false, Ordering::Release);
        let waiting_before = super::WAITING_LOSERS.load(Ordering::Acquire);
        let winner = std::thread::spawn(|| {
            let tests = [KatEntry {
                name: "pauses, then fails",
                run: paused_then_fails,
            }];
            initialize_with_tests(UNSIGNED_TEST_BINARY, &tests)
        });
        wait_until("the winner to pause", || {
            FAILING_WINNER_PAUSED.load(Ordering::Acquire)
        });
        let loser = std::thread::spawn(|| initialize_with_tests(UNSIGNED_TEST_BINARY, &[]));
        wait_until("the loser to enter its wait", || {
            super::WAITING_LOSERS.load(Ordering::Acquire) > waiting_before
        });
        assert!(!loser.is_finished());
        RELEASE_FAILING_WINNER.store(true, Ordering::Release);
        assert_eq!(
            winner.join().unwrap(),
            Err(Error::SelfTestFailed {
                test: "pauses, then fails"
            })
        );
        assert_eq!(loser.join().unwrap(), Err(Error::AlreadyFailed));
        assert_eq!(state(), State::Error);
    }

    /// The owner field records only a non-zero id below `2^56`.
    #[test]
    fn the_owner_id_filter_admits_only_recordable_ids() {
        assert_eq!(super::owner_id(None), None);
        assert_eq!(super::owner_id(Some(0)), None);
        assert_eq!(super::owner_id(Some(1)), Some(1));
        assert_eq!(super::owner_id(Some((1 << 56) - 1)), Some((1 << 56) - 1));
        assert_eq!(super::owner_id(Some(1 << 56)), None);
        assert_eq!(super::owner_id(Some(u64::MAX)), None);
    }

    /// A caller with no recordable thread id latches `Error`, names the
    /// cause, and runs no self-test.
    #[test]
    fn no_recordable_thread_id_latches_error_with_its_cause() {
        let guard = reset_for_test();
        let tests = [KatEntry {
            name: "must not run",
            run: always_fail,
        }];
        for raw in [None, Some(0), Some(1 << 56)] {
            guard.reset();
            assert_eq!(
                super::initialize_as(
                    super::owner_id(raw),
                    UNSIGNED_TEST_BINARY,
                    &tests,
                    AlgorithmProfile::Unrestricted
                ),
                Err(Error::SelfTestFailed {
                    test: super::THREAD_ID_CHECK
                }),
                "raw id {raw:?}"
            );
            assert_eq!(state(), State::Error);
            assert_eq!(
                initialize_with_tests(UNSIGNED_TEST_BINARY, &[]),
                Err(Error::AlreadyFailed)
            );
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

    #[test]
    fn registry_runs_passing_tests_and_reaches_operational() {
        let _guard = reset_for_test();
        let tests = [
            KatEntry {
                name: "dummy-pass-a",
                run: always_pass,
            },
            KatEntry {
                name: "dummy-pass-b",
                run: always_pass,
            },
        ];
        initialize_with_tests(UNSIGNED_TEST_BINARY, &tests).unwrap();
        assert_eq!(state(), State::Operational);
    }

    #[test]
    fn registry_failing_test_latches_error_and_returns_name() {
        let _guard = reset_for_test();
        let tests = [
            KatEntry {
                name: "dummy-pass",
                run: always_pass,
            },
            KatEntry {
                name: "dummy-fail",
                run: always_fail,
            },
            // The runner stops at the first failure, so this entry never runs.
            KatEntry {
                name: "dummy-unreached",
                run: count_unreached,
            },
        ];
        UNREACHED_RUNS.store(0, Ordering::Release);
        match initialize_with_tests(UNSIGNED_TEST_BINARY, &tests) {
            Err(Error::SelfTestFailed { test: "dummy-fail" }) => {}
            other => panic!("expected SelfTestFailed{{dummy-fail}}, got {other:?}"),
        }
        assert_eq!(UNREACHED_RUNS.load(Ordering::Acquire), 0);
        assert_eq!(state(), State::Error);
        // Operational-only guard must reject calls from here on.
        assert!(matches!(
            require_operational(),
            Err(Error::NotOperational {
                current: State::Error
            })
        ));
    }

    // Trivial SelfTest implementation exercised outside the registry
    // so the trait stays part of the compiled public surface.
    struct DummyTest;
    impl SelfTest for DummyTest {
        const NAME: &'static str = "dummy-trait-vector";
        fn run() -> Result<(), SelfTestFailure> {
            Ok(())
        }
    }

    #[test]
    fn dummy_self_test_trait_is_usable() {
        assert_eq!(DummyTest::NAME, "dummy-trait-vector");
        DummyTest::run().unwrap();
    }

    // =====================================================================
    // Algorithm profile gating tests
    // =====================================================================

    #[test]
    fn default_profile_is_unrestricted() {
        let _guard = reset_for_test();
        assert_eq!(active_profile(), AlgorithmProfile::Unrestricted);
    }

    #[test]
    fn initialize_with_profile_sets_cnsa2() {
        let _guard = reset_for_test();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa2).unwrap();
        assert_eq!(active_profile(), AlgorithmProfile::Cnsa2);
        assert!(is_operational());
    }

    /// A second call on an initialised module, with a different profile,
    /// leaves the first call's profile active.
    #[test]
    fn a_second_call_does_not_change_the_profile() {
        let _guard = reset_for_test();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa2).unwrap();
        match initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Unrestricted) {
            Err(Error::AlreadyInitialized) => {}
            other => panic!("expected AlreadyInitialized, got {other:?}"),
        }
        assert_eq!(active_profile(), AlgorithmProfile::Cnsa2);
        match initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
            Err(Error::AlreadyInitialized) => {}
            other => panic!("expected AlreadyInitialized, got {other:?}"),
        }
        assert_eq!(active_profile(), AlgorithmProfile::Cnsa2);
    }

    /// Holds the winning call inside its self-tests until the racing call
    /// has been made.
    static RACER_CALLED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    #[allow(clippy::unnecessary_wraps)]
    fn wait_for_racer() -> Result<(), SelfTestFailure> {
        while !RACER_CALLED.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        // The racer sets the flag immediately before it calls in; give that
        // call time to reach the CAS while this one is still in `SelfTest`.
        std::thread::sleep(std::time::Duration::from_millis(50));
        Ok(())
    }

    /// A call made while another is running its self-tests leaves the
    /// running call's profile active once both return.
    #[test]
    fn a_racing_call_does_not_change_the_profile() {
        let _guard = reset_for_test();
        RACER_CALLED.store(false, Ordering::Release);
        let tests = [KatEntry {
            name: "waits for the racing call",
            run: wait_for_racer,
        }];
        let winner = std::thread::spawn(move || {
            initialize_with_profile(UNSIGNED_TEST_BINARY, &tests, AlgorithmProfile::Cnsa2)
        });
        while state() != State::SelfTest {
            std::thread::yield_now();
        }
        RACER_CALLED.store(true, Ordering::Release);
        let racer =
            initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Unrestricted);
        let winner = winner.join().unwrap();
        assert!(winner.is_ok(), "the first call failed: {winner:?}");
        match racer {
            Err(Error::AlreadyInitialized) => {}
            other => panic!("expected AlreadyInitialized, got {other:?}"),
        }
        assert_eq!(active_profile(), AlgorithmProfile::Cnsa2);
    }

    /// A winning call whose self-tests fail leaves the default profile, so
    /// a module in `Error` does not report the profile it never served.
    #[test]
    fn a_failed_initialisation_leaves_the_default_profile() {
        let guard = reset_for_test();
        let failing = [KatEntry {
            name: "always fails",
            run: always_fail,
        }];
        match initialize_with_profile(UNSIGNED_TEST_BINARY, &failing, AlgorithmProfile::Cnsa2) {
            Err(Error::SelfTestFailed { .. }) => {}
            other => panic!("expected SelfTestFailed, got {other:?}"),
        }
        assert_eq!(state(), State::Error);
        assert_eq!(active_profile(), AlgorithmProfile::Unrestricted);

        guard.reset();
        match initialize_with_profile(&[], &[], AlgorithmProfile::Cnsa1) {
            Err(Error::IntegrityNotAttested) => {}
            other => panic!("expected IntegrityNotAttested, got {other:?}"),
        }
        assert_eq!(active_profile(), AlgorithmProfile::Unrestricted);
    }

    #[test]
    fn initialize_with_profile_sets_cnsa1() {
        let _guard = reset_for_test();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa1).unwrap();
        assert_eq!(active_profile(), AlgorithmProfile::Cnsa1);
        assert!(is_operational());
    }

    #[test]
    fn unrestricted_allows_all_services() {
        // Spot-check: every category should pass in Unrestricted.
        let spot = [
            Service::Sha1,
            Service::Sha256,
            Service::Aes128Ecb,
            Service::Aes256Gcm,
            Service::CtrDrbgAes128,
            Service::EcdsaP256Sign,
            Service::Ed25519Sign,
            Service::RsaPssSign2048,
            Service::MlKem1024Encaps,
            Service::LmsSha256M32H10W4Verify,
            Service::Dh3072,
            Service::SlhDsaSha2256sSign,
        ];
        for svc in spot {
            assert!(
                is_allowed(AlgorithmProfile::Unrestricted, svc),
                "{svc} should be allowed in Unrestricted"
            );
        }
    }

    #[test]
    fn cnsa2_allows_aes256_and_pq() {
        let allowed = [
            Service::Aes256Gcm,
            Service::Aes256Cbc,
            Service::Sha384,
            Service::Sha512,
            Service::HmacSha384,
            Service::HmacSha512,
            Service::CtrDrbgAes256,
            Service::HashDrbgSha384,
            Service::HmacDrbgSha512,
            Service::MlKem1024Encaps,
            Service::MlKem1024Decaps,
            Service::MlKem1024Keygen,
            Service::MlDsa87Sign,
            Service::MlDsa87Verify,
            Service::MlDsa87Keygen,
            Service::LmsSha256M32H10W4Verify,
            Service::XmssVerify,
        ];
        for svc in allowed {
            assert!(
                is_allowed(AlgorithmProfile::Cnsa2, svc),
                "{svc} should be allowed in CNSA 2.0"
            );
        }
    }

    /// CNSSP-15 (March 2025) Annex B names no Keccak-family hash or XOF.
    /// SHA-3 appears only as "allowed for internal hardware functionality",
    /// and the policy states outright that algorithms using SHA3 as a
    /// component — LMS and ML-KEM are its examples — do not thereby make
    /// SHA3 an approved hash function. This module is software, so the whole
    /// family is refused under CNSA 2.0. Pinned as a property because the
    /// gate permitted all twelve until 2026-08-18.
    #[test]
    fn cnsa2_refuses_the_keccak_family() {
        let refused = [
            Service::Shake256,
            Service::CShake256,
            Service::Kmac256,
            Service::KmacXof256,
            Service::TupleHash256,
            Service::TupleHashXof256,
            Service::ParallelHash256,
            Service::ParallelHashXof256,
            Service::Sha3_384,
            Service::Sha3_512,
            Service::HmacSha3_384,
            Service::HmacSha3_512,
        ];
        for svc in refused {
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa2, svc),
                "{svc} is not in CNSA 2.0 and must be refused"
            );
        }
        // Control: the suite's own hash must still pass, or this test would
        // also pass against a gate that refuses everything.
        assert!(is_allowed(AlgorithmProfile::Cnsa2, Service::Sha384));
        // Control: ML-KEM reaches Keccak internally and must be unaffected.
        assert!(is_allowed(
            AlgorithmProfile::Cnsa2,
            Service::MlKem1024Encaps
        ));
    }

    #[test]
    fn cnsa2_blocks_classical_and_small_keys() {
        let blocked = [
            Service::Sha1,
            Service::Sha224,
            Service::Sha256,
            Service::Sha512_224,
            Service::Sha512_256,
            Service::Sha3_224,
            Service::Sha3_256,
            Service::Shake128,
            Service::Kmac128,
            Service::Aes128Ecb,
            Service::Aes128Gcm,
            Service::Aes192Cbc,
            Service::CtrDrbgAes128,
            Service::CtrDrbgAes192,
            Service::HashDrbgSha256,
            Service::HmacDrbgSha256,
            Service::HmacSha1,
            Service::HmacSha256,
            Service::CmacAes128,
            Service::CmacAes192,
            Service::EcdsaP256Sign,
            Service::EcdsaP256Verify,
            Service::EcdhP256,
            Service::Ed25519Sign,
            Service::Ed25519Verify,
            Service::RsaPssSign2048,
            Service::RsaOaep2048,
            // No SLH-DSA parameter set is in CNSA 2.0 — CNSSP-15 lists none.
            Service::SlhDsaSha2128sSign,
            Service::MlDsa44Sign,
            Service::MlDsa44Verify,
            Service::MlDsa44Keygen,
            Service::MlDsa65Sign,
            Service::MlDsa65Verify,
            Service::MlDsa65Keygen,
        ];
        for svc in blocked {
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa2, svc),
                "{svc} should be BLOCKED in CNSA 2.0"
            );
        }
    }

    /// Every `Service` variant, so a profile's permitted set can be computed
    /// rather than sampled.
    ///
    /// The earlier membership test asserted only that an expected list was a
    /// SUBSET of what the gate permits, with a length assertion on the test's
    /// own array — a constant. It therefore could not see a widening: adding
    /// `RsaKeygen2048` to the CNSA 1.0 gate left it green, which is precisely
    /// the drift the test existed to catch. Enumerating the enum makes the
    /// comparison exact in both directions.
    ///
    /// The array type fixes the element count, so the compiler rejects a list
    /// of the wrong length. A variant added to `Service` but not listed here
    /// is not caught by this list; the exhaustive `Display` match is where the
    /// compiler forces every variant to be named.
    const ALL_SERVICES: [Service; 256] = [
        Service::Sha1,
        Service::Sha224,
        Service::Sha256,
        Service::Sha384,
        Service::Sha512,
        Service::Sha512_224,
        Service::Sha512_256,
        Service::Sha3_224,
        Service::Sha3_256,
        Service::Sha3_384,
        Service::Sha3_512,
        Service::Shake128,
        Service::Shake256,
        Service::CShake128,
        Service::CShake256,
        Service::Kmac128,
        Service::Kmac256,
        Service::KmacXof128,
        Service::KmacXof256,
        Service::TupleHash128,
        Service::TupleHash256,
        Service::TupleHashXof128,
        Service::TupleHashXof256,
        Service::ParallelHash128,
        Service::ParallelHash256,
        Service::ParallelHashXof128,
        Service::ParallelHashXof256,
        Service::HmacSha1,
        Service::HmacSha224,
        Service::HmacSha256,
        Service::HmacSha384,
        Service::HmacSha512,
        Service::HmacSha512_224,
        Service::HmacSha512_256,
        Service::HmacSha3_224,
        Service::HmacSha3_256,
        Service::HmacSha3_384,
        Service::HmacSha3_512,
        Service::CmacAes128,
        Service::CmacAes192,
        Service::CmacAes256,
        Service::Aes128Ecb,
        Service::Aes128Cbc,
        Service::Aes128Ctr,
        Service::Aes128Gcm,
        Service::Aes128Ccm,
        Service::Aes128Kw,
        Service::Aes128Kwp,
        Service::Aes192Ecb,
        Service::Aes192Cbc,
        Service::Aes192Ctr,
        Service::Aes192Gcm,
        Service::Aes192Ccm,
        Service::Aes192Kw,
        Service::Aes192Kwp,
        Service::Aes256Ecb,
        Service::Aes256Cbc,
        Service::Aes256Ctr,
        Service::Aes256Gcm,
        Service::Aes256Ccm,
        Service::Aes256Kw,
        Service::Aes256Kwp,
        Service::Aes128,
        Service::Aes192,
        Service::Aes256,
        Service::CtrDrbgAes128,
        Service::CtrDrbgAes192,
        Service::CtrDrbgAes256,
        Service::HashDrbgSha256,
        Service::HashDrbgSha384,
        Service::HashDrbgSha512,
        Service::HmacDrbgSha256,
        Service::HmacDrbgSha384,
        Service::HmacDrbgSha512,
        Service::HkdfSha1,
        Service::HkdfSha256,
        Service::HkdfSha384,
        Service::HkdfSha512,
        Service::KbkdfHmacSha256,
        Service::KbkdfHmacSha384,
        Service::KbkdfHmacSha512,
        Service::KbkdfCmacAes128,
        Service::KbkdfCmacAes192,
        Service::KbkdfCmacAes256,
        Service::Pbkdf2HmacSha1,
        Service::Pbkdf2HmacSha224,
        Service::Pbkdf2HmacSha256,
        Service::Pbkdf2HmacSha384,
        Service::Pbkdf2HmacSha512,
        Service::RsaKeygen2048,
        Service::RsaPkcs1v15Sign2048,
        Service::RsaPssSign2048,
        Service::RsaOaep2048,
        Service::RsaPkcs1v15Verify2048,
        Service::RsaPssVerify2048,
        Service::RsaKeygen3072,
        Service::RsaPkcs1v15Sign3072,
        Service::RsaPssSign3072,
        Service::RsaOaep3072,
        Service::RsaPkcs1v15Verify3072,
        Service::RsaPssVerify3072,
        Service::RsaKeygen4096,
        Service::RsaPkcs1v15Sign4096,
        Service::RsaPssSign4096,
        Service::RsaOaep4096,
        Service::RsaPkcs1v15Verify4096,
        Service::RsaPssVerify4096,
        Service::EcdsaP256Sign,
        Service::EcdsaP256Verify,
        Service::EcdsaP256Keygen,
        Service::EcdsaP384Sign,
        Service::EcdsaP384Verify,
        Service::EcdsaP384Keygen,
        Service::EcdhP256,
        Service::EcdhP384,
        Service::Ed25519Sign,
        Service::Ed25519Verify,
        Service::Ed25519Keygen,
        Service::Tls12Kdf,
        Service::Tls13Kdf,
        Service::MlKem1024Encaps,
        Service::MlKem1024Decaps,
        Service::MlKem1024Keygen,
        Service::MlKem512Encaps,
        Service::MlKem512Decaps,
        Service::MlKem512Keygen,
        Service::MlKem768Encaps,
        Service::MlKem768Decaps,
        Service::MlKem768Keygen,
        Service::MlDsa87Sign,
        Service::MlDsa87Verify,
        Service::MlDsa87Keygen,
        Service::MlDsa44Sign,
        Service::MlDsa44Verify,
        Service::MlDsa44Keygen,
        Service::MlDsa65Sign,
        Service::MlDsa65Verify,
        Service::MlDsa65Keygen,
        Service::SlhDsaSha2256sKeygen,
        Service::SlhDsaSha2256sSign,
        Service::SlhDsaSha2256sVerify,
        Service::SlhDsaSha2128sKeygen,
        Service::SlhDsaSha2128sSign,
        Service::SlhDsaSha2128sVerify,
        Service::SlhDsaSha2128fKeygen,
        Service::SlhDsaSha2128fSign,
        Service::SlhDsaSha2128fVerify,
        Service::SlhDsaSha2192sKeygen,
        Service::SlhDsaSha2192sSign,
        Service::SlhDsaSha2192sVerify,
        Service::SlhDsaSha2192fKeygen,
        Service::SlhDsaSha2192fSign,
        Service::SlhDsaSha2192fVerify,
        Service::SlhDsaSha2256fKeygen,
        Service::SlhDsaSha2256fSign,
        Service::SlhDsaSha2256fVerify,
        Service::SlhDsaShake128sKeygen,
        Service::SlhDsaShake128sSign,
        Service::SlhDsaShake128sVerify,
        Service::SlhDsaShake128fKeygen,
        Service::SlhDsaShake128fSign,
        Service::SlhDsaShake128fVerify,
        Service::SlhDsaShake192sKeygen,
        Service::SlhDsaShake192sSign,
        Service::SlhDsaShake192sVerify,
        Service::SlhDsaShake192fKeygen,
        Service::SlhDsaShake192fSign,
        Service::SlhDsaShake192fVerify,
        Service::SlhDsaShake256sKeygen,
        Service::SlhDsaShake256sSign,
        Service::SlhDsaShake256sVerify,
        Service::SlhDsaShake256fKeygen,
        Service::SlhDsaShake256fSign,
        Service::SlhDsaShake256fVerify,
        Service::LmsSha256M32H5W1Verify,
        Service::LmsSha256M32H5W2Verify,
        Service::LmsSha256M32H5W4Verify,
        Service::LmsSha256M32H5W8Verify,
        Service::LmsSha256M32H10W1Verify,
        Service::LmsSha256M32H10W2Verify,
        Service::LmsSha256M32H10W4Verify,
        Service::LmsSha256M32H10W8Verify,
        Service::LmsSha256M32H15W1Verify,
        Service::LmsSha256M32H15W2Verify,
        Service::LmsSha256M32H15W4Verify,
        Service::LmsSha256M32H15W8Verify,
        Service::LmsSha256M32H20W1Verify,
        Service::LmsSha256M32H20W2Verify,
        Service::LmsSha256M32H20W4Verify,
        Service::LmsSha256M32H20W8Verify,
        Service::LmsSha256M32H25W1Verify,
        Service::LmsSha256M32H25W2Verify,
        Service::LmsSha256M32H25W4Verify,
        Service::LmsSha256M32H25W8Verify,
        Service::LmsSha256M24H5W1Verify,
        Service::LmsSha256M24H5W2Verify,
        Service::LmsSha256M24H5W4Verify,
        Service::LmsSha256M24H5W8Verify,
        Service::LmsSha256M24H10W1Verify,
        Service::LmsSha256M24H10W2Verify,
        Service::LmsSha256M24H10W4Verify,
        Service::LmsSha256M24H10W8Verify,
        Service::LmsSha256M24H15W1Verify,
        Service::LmsSha256M24H15W2Verify,
        Service::LmsSha256M24H15W4Verify,
        Service::LmsSha256M24H15W8Verify,
        Service::LmsSha256M24H20W1Verify,
        Service::LmsSha256M24H20W2Verify,
        Service::LmsSha256M24H20W4Verify,
        Service::LmsSha256M24H20W8Verify,
        Service::LmsSha256M24H25W1Verify,
        Service::LmsSha256M24H25W2Verify,
        Service::LmsSha256M24H25W4Verify,
        Service::LmsSha256M24H25W8Verify,
        Service::LmsShakeM32H5W1Verify,
        Service::LmsShakeM32H5W2Verify,
        Service::LmsShakeM32H5W4Verify,
        Service::LmsShakeM32H5W8Verify,
        Service::LmsShakeM32H10W1Verify,
        Service::LmsShakeM32H10W2Verify,
        Service::LmsShakeM32H10W4Verify,
        Service::LmsShakeM32H10W8Verify,
        Service::LmsShakeM32H15W1Verify,
        Service::LmsShakeM32H15W2Verify,
        Service::LmsShakeM32H15W4Verify,
        Service::LmsShakeM32H15W8Verify,
        Service::LmsShakeM32H20W1Verify,
        Service::LmsShakeM32H20W2Verify,
        Service::LmsShakeM32H20W4Verify,
        Service::LmsShakeM32H20W8Verify,
        Service::LmsShakeM32H25W1Verify,
        Service::LmsShakeM32H25W2Verify,
        Service::LmsShakeM32H25W4Verify,
        Service::LmsShakeM32H25W8Verify,
        Service::LmsShakeM24H5W1Verify,
        Service::LmsShakeM24H5W2Verify,
        Service::LmsShakeM24H5W4Verify,
        Service::LmsShakeM24H5W8Verify,
        Service::LmsShakeM24H10W1Verify,
        Service::LmsShakeM24H10W2Verify,
        Service::LmsShakeM24H10W4Verify,
        Service::LmsShakeM24H10W8Verify,
        Service::LmsShakeM24H15W1Verify,
        Service::LmsShakeM24H15W2Verify,
        Service::LmsShakeM24H15W4Verify,
        Service::LmsShakeM24H15W8Verify,
        Service::LmsShakeM24H20W1Verify,
        Service::LmsShakeM24H20W2Verify,
        Service::LmsShakeM24H20W4Verify,
        Service::LmsShakeM24H20W8Verify,
        Service::LmsShakeM24H25W1Verify,
        Service::LmsShakeM24H25W2Verify,
        Service::LmsShakeM24H25W4Verify,
        Service::LmsShakeM24H25W8Verify,
        Service::XmssVerify,
        Service::Dh3072,
    ];

    /// CNSA 1.0 permits exactly the CNSSP-15 (October 2016) Annex B suite and
    /// the supporting services it needs at matching strength.
    const EXPECTED_CNSA1: [Service; 34] = [
        Service::Sha384,
        Service::HmacSha384,
        Service::CmacAes256,
        Service::Aes256Ecb,
        Service::Aes256Cbc,
        Service::Aes256Ctr,
        Service::Aes256Gcm,
        Service::Aes256Ccm,
        Service::Aes256Kw,
        Service::Aes256Kwp,
        Service::Aes256,
        Service::CtrDrbgAes256,
        Service::HashDrbgSha384,
        Service::HmacDrbgSha384,
        Service::HkdfSha384,
        Service::KbkdfHmacSha384,
        Service::KbkdfCmacAes256,
        Service::RsaKeygen3072,
        Service::RsaPkcs1v15Sign3072,
        Service::RsaPssSign3072,
        Service::RsaOaep3072,
        Service::RsaPkcs1v15Verify3072,
        Service::RsaPssVerify3072,
        Service::RsaKeygen4096,
        Service::RsaPkcs1v15Sign4096,
        Service::RsaPssSign4096,
        Service::RsaOaep4096,
        Service::RsaPkcs1v15Verify4096,
        Service::RsaPssVerify4096,
        Service::EcdsaP384Sign,
        Service::EcdsaP384Verify,
        Service::EcdsaP384Keygen,
        Service::EcdhP384,
        Service::Dh3072,
    ];

    /// CNSA 2.0's non-LMS membership. The 80 LMS services are asserted by
    /// count rather than listed, because `LMS_SERVICES` already enumerates them.
    const EXPECTED_CNSA2_NON_LMS: [Service; 30] = [
        Service::Sha384,
        Service::Sha512,
        Service::HmacSha384,
        Service::HmacSha512,
        Service::CmacAes256,
        Service::Aes256Ecb,
        Service::Aes256Cbc,
        Service::Aes256Ctr,
        Service::Aes256Gcm,
        Service::Aes256Ccm,
        Service::Aes256Kw,
        Service::Aes256Kwp,
        Service::Aes256,
        Service::CtrDrbgAes256,
        Service::HashDrbgSha384,
        Service::HashDrbgSha512,
        Service::HmacDrbgSha384,
        Service::HmacDrbgSha512,
        Service::HkdfSha384,
        Service::HkdfSha512,
        Service::KbkdfHmacSha384,
        Service::KbkdfHmacSha512,
        Service::KbkdfCmacAes256,
        Service::MlKem1024Encaps,
        Service::MlKem1024Decaps,
        Service::MlKem1024Keygen,
        Service::MlDsa87Sign,
        Service::MlDsa87Verify,
        Service::MlDsa87Keygen,
        Service::XmssVerify,
    ];

    /// Assert a profile permits EXACTLY `expected` (plus the LMS block when
    /// `allow_lms`), checked over every variant so a widening cannot hide.
    fn assert_exact_membership(profile: AlgorithmProfile, expected: &[Service], allow_lms: bool) {
        for svc in ALL_SERVICES {
            let want = expected.iter().any(|e| *e as u16 == svc as u16)
                || (allow_lms && is_lms_service(svc));
            assert_eq!(
                is_allowed(profile, svc),
                want,
                "{svc} under {profile}: gate says {}, suite says {want}",
                is_allowed(profile, svc)
            );
        }
    }

    /// Every profile survives the round trip through the `PROFILE` atomic.
    ///
    /// `from_u8` had no test at all, and the omission was not visible from the
    /// membership tests: those call the private `is_allowed` directly, so a
    /// mutation mapping discriminant 3 to `Cnsa2` left the suite green while
    /// every Migration deployment silently ran as CNSA 2.0 — refusing ECDSA
    /// P-384, RSA and DH — and `oxi_active_profile()` reported `1` for a module
    /// initialised with `3`. This goes through the entry point, which is the
    /// only place that mapping is exercised.
    #[test]
    fn every_profile_round_trips_through_the_active_profile() {
        for profile in [
            AlgorithmProfile::Unrestricted,
            AlgorithmProfile::Cnsa2,
            AlgorithmProfile::Cnsa1,
            AlgorithmProfile::Migration,
        ] {
            assert_eq!(
                AlgorithmProfile::from_u8(profile as u8),
                profile,
                "{profile} did not survive the round trip through its discriminant"
            );
        }

        // An unknown discriminant must not resolve to a permissive profile.
        // `Unrestricted` refuses nothing, so it is the one answer that would
        // turn a corrupted byte into an open module.
        for raw in [4u8, 9, 200, 255] {
            assert_ne!(
                AlgorithmProfile::from_u8(raw),
                AlgorithmProfile::Unrestricted,
                "unknown discriminant {raw} must not open the module"
            );
        }
    }

    /// A profile initialised through the public entry point gates as itself.
    ///
    /// The membership tests reach `is_allowed` directly; this reaches it the
    /// way a caller does, through `initialize_with_profile` and the `PROFILE`
    /// atomic that `require_allowed` reads.
    #[test]
    fn migration_gates_as_itself_through_require_allowed() {
        let guard = reset_for_test();
        guard.reset();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Migration).unwrap();
        assert_eq!(active_profile(), AlgorithmProfile::Migration);

        // Permitted by CNSA 1.0 only — refused if this silently ran as CNSA 2.0.
        assert!(
            require_allowed(Service::EcdsaP384Sign).is_ok(),
            "ECDSA P-384 is in CNSA 1.0 and must pass under Migration"
        );
        assert!(
            require_allowed(Service::Dh3072).is_ok(),
            "DH-3072 is in CNSA 1.0 and must pass under Migration"
        );
        // Permitted by CNSA 2.0 only — refused if this silently ran as CNSA 1.0.
        assert!(
            require_allowed(Service::MlKem1024Encaps).is_ok(),
            "ML-KEM-1024 is in CNSA 2.0 and must pass under Migration"
        );
        // Refused by both, so refused here: Migration is a gate, not Unrestricted.
        assert!(require_allowed(Service::Sha256).is_err());
    }

    /// Exact membership, both directions. A service added to or removed from
    /// any gate fails here.
    #[test]
    fn profile_membership_is_exact() {
        assert_exact_membership(AlgorithmProfile::Cnsa1, &EXPECTED_CNSA1, false);
        assert_exact_membership(AlgorithmProfile::Cnsa2, &EXPECTED_CNSA2_NON_LMS, true);

        // Migration is the union, so a service belongs iff either suite admits
        // it. Expressed against the two gates rather than a third list.
        for svc in ALL_SERVICES {
            let want = is_allowed(AlgorithmProfile::Cnsa1, svc)
                || is_allowed(AlgorithmProfile::Cnsa2, svc);
            assert_eq!(
                is_allowed(AlgorithmProfile::Migration, svc),
                want,
                "{svc}: Migration must permit exactly the union"
            );
        }

        // Control: Unrestricted permits everything, so a gate that refused
        // everything could not have satisfied the assertions above.
        for svc in ALL_SERVICES {
            assert!(is_allowed(AlgorithmProfile::Unrestricted, svc));
        }
    }

    /// Migration is the union of the two suites and nothing more.
    ///
    /// It is not a CNSA profile: no standard defines it, which is why it does
    /// not carry a CNSA name. Its contract is that it permits what either
    /// suite permits, refuses what both refuse, and is strictly narrower than
    /// `Unrestricted`.
    #[test]
    fn migration_is_the_union_of_both_suites() {
        // From CNSA 1.0 alone.
        for svc in [
            Service::EcdsaP384Sign,
            Service::EcdhP384,
            Service::RsaPssSign3072,
            Service::Dh3072,
        ] {
            assert!(
                is_allowed(AlgorithmProfile::Migration, svc),
                "{svc} (CNSA 1.0) must pass"
            );
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa2, svc),
                "{svc} is not CNSA 2.0"
            );
        }

        // From CNSA 2.0 alone.
        for svc in [
            Service::MlKem1024Encaps,
            Service::MlDsa87Sign,
            Service::XmssVerify,
            Service::Sha512,
            Service::LmsSha256M32H10W4Verify,
        ] {
            assert!(
                is_allowed(AlgorithmProfile::Migration, svc),
                "{svc} (CNSA 2.0) must pass"
            );
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa1, svc),
                "{svc} is not CNSA 1.0"
            );
        }

        // Shared by both — the overlap is AES-256 and SHA-384 with their
        // matching-strength support, and nothing else.
        for svc in [Service::Aes256Gcm, Service::Sha384, Service::HmacSha384] {
            assert!(is_allowed(AlgorithmProfile::Cnsa1, svc));
            assert!(is_allowed(AlgorithmProfile::Cnsa2, svc));
            assert!(is_allowed(AlgorithmProfile::Migration, svc));
        }

        // Refused by both, so refused here. This is what makes Migration a
        // gate rather than a synonym for Unrestricted.
        for svc in [
            Service::Sha1,
            Service::Sha256,
            Service::Aes128Gcm,
            Service::RsaPssSign2048,
            Service::EcdsaP256Sign,
            Service::Ed25519Sign,
            // Named by neither suite for a software module.
            Service::Sha3_384,
            Service::Shake256,
            Service::Kmac256,
        ] {
            assert!(
                !is_allowed(AlgorithmProfile::Migration, svc),
                "{svc} is in neither suite and must be refused"
            );
            // Control: Unrestricted does permit it, so the refusal above is
            // Migration's doing and not a service that is gated everywhere.
            assert!(is_allowed(AlgorithmProfile::Unrestricted, svc));
        }
    }

    #[test]
    fn cnsa1_allows_the_2016_suite() {
        let allowed = [
            Service::Aes256Gcm,
            Service::Sha384,
            Service::EcdsaP384Sign,
            Service::EcdsaP384Verify,
            Service::EcdsaP384Keygen,
            Service::EcdhP384,
            Service::RsaPssSign3072,
            Service::RsaOaep3072,
            Service::RsaPssSign4096,
            Service::Dh3072,
            // Supporting services at the suite's own strength.
            Service::HmacSha384,
            Service::CtrDrbgAes256,
            Service::HashDrbgSha384,
            Service::KbkdfHmacSha384,
        ];
        for svc in allowed {
            assert!(
                is_allowed(AlgorithmProfile::Cnsa1, svc),
                "{svc} should be allowed in CNSA 1.0"
            );
        }
    }

    #[test]
    fn cnsa1_blocks_small_keys_and_ed25519() {
        let blocked = [
            Service::Sha1,
            Service::Sha224,
            Service::Aes128Ecb,
            Service::Aes192Gcm,
            Service::CtrDrbgAes128,
            Service::EcdsaP256Sign,
            Service::EcdhP256,
            Service::Ed25519Sign,
            Service::Ed25519Verify,
            Service::RsaPssSign2048,
            Service::RsaOaep2048,
            // Weaker than the suite requires. Annex B names SHA-384 alone;
            // SHA-256 appears only in its Additional Information paragraph,
            // as a near-term allowance scoped to UNCLASSIFIED data and
            // conditioned on NSA consultation for non-P-384 curves — neither
            // of which this module can evaluate.
            Service::Sha256,
            Service::HmacSha256,
            Service::HashDrbgSha256,
            Service::HkdfSha256,
            // SHA-512 belongs to CNSA 2.0; the 2016 suite does not name it.
            Service::Sha512,
            Service::HmacSha512,
            // Named by neither suite.
            Service::Sha3_256,
            Service::Shake256,
            // Post-quantum and stateful hash-based: CNSA 2.0, not CNSA 1.0.
            Service::MlKem1024Encaps,
            Service::MlDsa87Sign,
            Service::XmssVerify,
            Service::LmsSha256M32H10W4Verify,
        ];
        for svc in blocked {
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa1, svc),
                "{svc} should be BLOCKED in CNSA 1.0"
            );
        }
    }

    #[test]
    fn lms_gating_is_exhaustive_across_all_80_variants() {
        // Enumerates every LMS Service variant (one Verify per (LMS, LM-OTS)
        // pair, 80 entries) and verifies that all 80 are gated as CNSA 2.0
        // permits them and CNSA 1.0 does not: the 2025 Annex B places no
        // subset restriction on LMS, while the 2016 suite names no stateful
        // hash-based scheme at all.
        let all_80 = LMS_SERVICES;
        assert_eq!(all_80.len(), 80, "LMS enumeration drift");

        for svc in all_80 {
            // Unrestricted: every LMS variant is permitted.
            assert!(
                is_allowed(AlgorithmProfile::Unrestricted, svc),
                "{svc} must be allowed in Unrestricted"
            );

            // CNSA 2.0: every approved SP 800-208 parameter set is permitted.
            // CNSSP-15 Annex B places no subset restriction on LMS.
            assert!(
                is_allowed(AlgorithmProfile::Cnsa2, svc),
                "{svc} must be allowed in CNSA 2.0"
            );

            // CNSA 1.0: refused. CNSSP-15 (October 2016) Annex B names no
            // stateful hash-based signature scheme; LMS arrives with CNSA 2.0.
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa1, svc),
                "{svc} is not in CNSA 1.0 and must be refused"
            );

            // Migration: permitted, because CNSA 2.0 permits it.
            assert!(
                is_allowed(AlgorithmProfile::Migration, svc),
                "{svc} must be allowed in Migration"
            );
        }
    }

    #[test]
    fn lms_discriminant_slots_are_complete_and_pure() {
        // `is_lms_service` tests "odd and in `501..=659`" instead of
        // enumerating 80 arms, which is only sound while those 80 slots hold
        // every LMS service and nothing else. Enum discriminants are unique,
        // so proving the 80 LMS variants fill the odd slots exactly also
        // proves no other variant can sit on one.
        let mut discriminants = [0u16; 80];
        for (slot, svc) in discriminants.iter_mut().zip(LMS_SERVICES) {
            *slot = svc as u16;
        }
        discriminants.sort_unstable();

        // Each step after sorting is exactly 2: all 80 are distinct, all
        // share one parity, and no odd slot between them is missing. The
        // comparison count is asserted too, so an empty or short sweep
        // cannot pass this vacuously.
        let mut compared = 0usize;
        for pair in discriminants.windows(2) {
            let [lo, hi] = pair else {
                unreachable!("windows(2) yields two-element slices")
            };
            assert_eq!(*hi, lo + 2, "LMS slot after {lo} is missing or duplicated");
            compared += 1;
        }
        assert_eq!(compared, 79, "slot sweep did not run in full");

        let (Some(&first), Some(&last)) = (discriminants.first(), discriminants.last()) else {
            unreachable!("the array holds 80 elements")
        };
        assert_eq!(first, 501, "LMS block does not start at 501");
        assert_eq!(last, 659, "LMS block does not end at 659");

        for svc in LMS_SERVICES {
            assert!(is_lms_service(svc), "{svc} must be inside the LMS block");
        }

        // No other variant anywhere in the enum is classed as LMS. This is
        // what catches a foreign variant placed on an odd slot in the block,
        // which the slot sweep above cannot see: it only reads the LMS list.
        let lms_count = ALL_SERVICES
            .iter()
            .filter(|svc| is_lms_service(**svc))
            .count();
        assert_eq!(lms_count, 80, "a non-LMS variant sits on an LMS slot");

        // Positive control on the other side of the boundary: the nearest
        // non-LMS neighbours must not be swept in by a widened range.
        for svc in [
            Service::SlhDsaShake256fVerify,
            Service::XmssVerify,
            Service::Dh3072,
        ] {
            assert!(!is_lms_service(svc), "{svc} must be outside the LMS block");
        }
    }

    #[test]
    fn slh_dsa_gating_is_exhaustive_across_all_36_variants() {
        // Enumerates every SLH-DSA Service variant (12 parameter sets ×
        // {Keygen, Sign, Verify} = 36 entries) and verifies the
        // fail-safe gating: all 36 are blocked under both CNSA profiles,
        // because CNSSP-15 lists no SLH-DSA parameter set at all; all 36
        // are permitted under Unrestricted.  If a new SLH-DSA variant is
        // added without a matching entry in this array, the assertion at
        // the end catches the gap.
        let all_36 = [
            // SHA-2 family (18 entries).
            Service::SlhDsaSha2256sKeygen,
            Service::SlhDsaSha2256sSign,
            Service::SlhDsaSha2256sVerify,
            Service::SlhDsaSha2128sKeygen,
            Service::SlhDsaSha2128sSign,
            Service::SlhDsaSha2128sVerify,
            Service::SlhDsaSha2128fKeygen,
            Service::SlhDsaSha2128fSign,
            Service::SlhDsaSha2128fVerify,
            Service::SlhDsaSha2192sKeygen,
            Service::SlhDsaSha2192sSign,
            Service::SlhDsaSha2192sVerify,
            Service::SlhDsaSha2192fKeygen,
            Service::SlhDsaSha2192fSign,
            Service::SlhDsaSha2192fVerify,
            Service::SlhDsaSha2256fKeygen,
            Service::SlhDsaSha2256fSign,
            Service::SlhDsaSha2256fVerify,
            // SHAKE family (18 entries).
            Service::SlhDsaShake128sKeygen,
            Service::SlhDsaShake128sSign,
            Service::SlhDsaShake128sVerify,
            Service::SlhDsaShake128fKeygen,
            Service::SlhDsaShake128fSign,
            Service::SlhDsaShake128fVerify,
            Service::SlhDsaShake192sKeygen,
            Service::SlhDsaShake192sSign,
            Service::SlhDsaShake192sVerify,
            Service::SlhDsaShake192fKeygen,
            Service::SlhDsaShake192fSign,
            Service::SlhDsaShake192fVerify,
            Service::SlhDsaShake256sKeygen,
            Service::SlhDsaShake256sSign,
            Service::SlhDsaShake256sVerify,
            Service::SlhDsaShake256fKeygen,
            Service::SlhDsaShake256fSign,
            Service::SlhDsaShake256fVerify,
        ];
        assert_eq!(all_36.len(), 36, "SLH-DSA enumeration drift");

        for svc in all_36 {
            // Unrestricted: every SLH-DSA variant is permitted.
            assert!(
                is_allowed(AlgorithmProfile::Unrestricted, svc),
                "{svc} must be allowed in Unrestricted"
            );

            // CNSA 1.0: no SLH-DSA variant is permitted.
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa1, svc),
                "{svc} must be BLOCKED in CNSA 1.0"
            );

            // CNSA 2.0: no SLH-DSA variant is permitted either. CNSSP-15
            // contains no SLH-DSA entry, so admitting one would be a
            // conformance claim the policy does not support.
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa2, svc),
                "{svc} must be BLOCKED in CNSA 2.0"
            );
        }
    }

    #[test]
    fn require_allowed_returns_restricted_error_under_cnsa2() {
        let _guard = reset_for_test();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa2).unwrap();
        match require_allowed(Service::Aes128Ecb) {
            Err(Error::AlgorithmRestricted {
                service: Service::Aes128Ecb,
            }) => {}
            other => panic!("expected AlgorithmRestricted(Aes128Ecb), got {other:?}"),
        }
    }

    #[test]
    fn require_allowed_passes_permitted_services() {
        let _guard = reset_for_test();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa2).unwrap();
        require_allowed(Service::Aes256Gcm).unwrap();
        require_allowed(Service::Sha384).unwrap();
        require_allowed(Service::MlKem1024Encaps).unwrap();
    }

    #[test]
    fn require_allowed_passes_everything_in_unrestricted() {
        let _guard = reset_for_test();
        initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap();
        // Spot-check a few from each end of the spectrum.
        require_allowed(Service::Sha1).unwrap();
        require_allowed(Service::Aes128Ecb).unwrap();
        require_allowed(Service::Ed25519Sign).unwrap();
        require_allowed(Service::MlKem1024Encaps).unwrap();
    }

    /// Entry-point coverage for the SLH-DSA correction. The exhaustive
    /// `slh_dsa_gating_*` test calls the private `is_allowed` helper directly,
    /// so it says nothing about whether the public gate reaches that helper.
    /// This one goes through `require_allowed`, which is what every approved
    /// service actually calls.
    #[test]
    fn require_allowed_refuses_every_slh_dsa_service_under_cnsa2() {
        let guard = reset_for_test();
        for profile in [AlgorithmProfile::Cnsa2, AlgorithmProfile::Cnsa1] {
            guard.reset();
            initialize_with_profile(UNSIGNED_TEST_BINARY, &[], profile).unwrap();
            for svc in [
                Service::SlhDsaSha2256sKeygen,
                Service::SlhDsaSha2256sSign,
                Service::SlhDsaSha2256sVerify,
                Service::SlhDsaShake128fVerify,
            ] {
                match require_allowed(svc) {
                    Err(Error::AlgorithmRestricted { service }) => assert_eq!(service, svc),
                    other => {
                        panic!("expected AlgorithmRestricted({svc}) under {profile}, got {other:?}")
                    }
                }
            }
        }
    }

    /// Entry-point coverage for the LMS correction, on the `M=24` sets.
    /// CNSSP-15 (March 2025) Annex B recommends LMS-SHA-256/192, which is
    /// `M=24`, so these are the parameter sets the policy names by name.
    ///
    /// CNSA 1.0 is absent from this list deliberately: the 2016 suite names
    /// no stateful hash-based scheme, so LMS is refused there and permitted
    /// under Migration instead.
    #[test]
    fn require_allowed_admits_lms_m24_under_cnsa2_and_migration() {
        let guard = reset_for_test();
        for profile in [AlgorithmProfile::Cnsa2, AlgorithmProfile::Migration] {
            guard.reset();
            initialize_with_profile(UNSIGNED_TEST_BINARY, &[], profile).unwrap();
            for svc in [
                Service::LmsSha256M24H5W1Verify,
                Service::LmsSha256M24H25W8Verify,
                Service::LmsShakeM24H10W4Verify,
                Service::LmsShakeM24H25W8Verify,
            ] {
                require_allowed(svc)
                    .unwrap_or_else(|e| panic!("{svc} must be allowed under {profile}: {e:?}"));
            }
        }
    }

    /// Both edges of the LMS discriminant block, over raw values.
    ///
    /// The block sits at the very top of the enum, so a widened *upper* bound
    /// admits nothing today and no `Service`-typed probe can see it — moving
    /// the bound to 709 leaves the whole suite green. Testing the arithmetic
    /// directly is what makes the upper edge checkable at all.
    #[test]
    fn lms_block_boundaries_are_exact() {
        assert!(!lms_block_contains(499), "499 is below the LMS block");
        assert!(!lms_block_contains(500), "500 is even");
        assert!(lms_block_contains(501), "501 is the first LMS discriminant");
        assert!(!lms_block_contains(502), "502 is even");
        assert!(!lms_block_contains(658), "658 is even");
        assert!(lms_block_contains(659), "659 is the last LMS discriminant");
        assert!(!lms_block_contains(660), "660 is above the LMS block");
        assert!(!lms_block_contains(661), "661 is above the LMS block");

        // ...and the block the arithmetic describes is the one the enum has.
        assert_eq!(Service::LmsSha256M32H5W1Verify as u16, 501);
        assert_eq!(Service::LmsShakeM24H25W8Verify as u16, 659);
    }

    /// The two CNSA profiles must be told apart at the entry point. Every other
    /// `require_allowed` test uses a service the profiles treat alike, so a bug
    /// wiring `Cnsa1` through as `Cnsa2` would survive them all. P-384 ECDSA is
    /// the discriminator: CNSA 1.0 permits it, CNSA 2.0 does not.
    #[test]
    fn require_allowed_distinguishes_cnsa1_from_cnsa2() {
        let guard = reset_for_test();

        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa1).unwrap();
        require_allowed(Service::EcdsaP384Sign)
            .unwrap_or_else(|e| panic!("P-384 ECDSA must be permitted under CNSA 1.0: {e:?}"));

        guard.reset();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa2).unwrap();
        match require_allowed(Service::EcdsaP384Sign) {
            Err(Error::AlgorithmRestricted {
                service: Service::EcdsaP384Sign,
            }) => {}
            other => panic!("expected P-384 ECDSA refused under CNSA 2.0, got {other:?}"),
        }
    }

    #[test]
    fn algorithm_profile_display() {
        assert_eq!(AlgorithmProfile::Unrestricted.to_string(), "Unrestricted");
        assert_eq!(AlgorithmProfile::Cnsa2.to_string(), "CNSA 2.0");
        assert_eq!(AlgorithmProfile::Cnsa1.to_string(), "CNSA 1.0");
    }

    #[test]
    fn algorithm_restricted_error_display() {
        let _guard = reset_for_test();
        initialize_with_profile(UNSIGNED_TEST_BINARY, &[], AlgorithmProfile::Cnsa2).unwrap();
        let err = Error::AlgorithmRestricted {
            service: Service::Aes128Ecb,
        };
        let msg = err.to_string();
        assert!(msg.contains("AES-128-ECB"), "got: {msg}");
        assert!(msg.contains("CNSA 2.0"), "got: {msg}");
    }

    #[test]
    fn not_implemented_error_display() {
        let err = Error::NotImplemented;
        assert_eq!(err.to_string(), "algorithm not yet implemented");
    }

    #[test]
    fn service_display_is_stable() {
        // Pin a few representative Display strings.
        assert_eq!(Service::Sha256.to_string(), "SHA-256");
        assert_eq!(Service::Aes256Gcm.to_string(), "AES-256-GCM");
        assert_eq!(Service::MlKem1024Encaps.to_string(), "ML-KEM-1024 encaps");
        assert_eq!(Service::Ed25519Sign.to_string(), "Ed25519 sign");
    }
}
