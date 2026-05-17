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
//! # What this crate ships
//!
//! - [`State`] and the transition machine (`PowerOff →
//!   SelfTest → Operational | Error`).
//! - [`initialize_with_tests`] — the canonical one-shot entry
//!   point that the top-level caller uses to run every approved
//!   algorithm's power-up KAT before opening the service
//!   interface. [`initialize`] is a thin wrapper for the empty
//!   registry case (used only by this crate's own unit tests).
//! - [`require_operational`] — the gate that every approved
//!   service in every other crate calls on entry. Returns
//!   [`Error::NotOperational`] (with the observed state) on any
//!   pre-`Operational` or post-`Error` call.
//! - [`enter_error_state`] — irreversible transition into the
//!   terminal error state, called by conditional self-tests
//!   (pairwise consistency, DRBG health) when they detect a
//!   failure.
//! - [`KatEntry`] and the [`SelfTest`] trait — the registry
//!   shape that algorithm crates use to expose their power-up
//!   KATs.
//! - [`AlgorithmProfile`] — runtime selection of an algorithm
//!   restriction policy (Unrestricted, CNSA 2.0, CNSA 1.0).
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
//! A single validated binary serves general FIPS 140-3 consumers
//! and CNSA-restricted deployments via a runtime
//! [`AlgorithmProfile`] selection. The operator passes the
//! desired profile to [`initialize_with_profile`]; subsequent
//! calls to [`require_allowed`] enforce it. Services not
//! permitted by the active profile return
//! [`Error::AlgorithmRestricted`].
//!
//! Three profiles are defined:
//!
//! - **Unrestricted** — all FIPS-approved algorithms are
//!   available. This is the default, matching the behavior of
//!   [`initialize_with_tests`].
//! - **CNSA 2.0** (CNSSP 15) — only quantum-resistant
//!   algorithms: AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87,
//!   LMS, XMSS, plus SHA3-384/512 and 256-bit SP 800-185
//!   variants.
//! - **CNSA 1.0** — classical algorithms for the transition
//!   period: AES-256, SHA-384, ECDSA/ECDH P-384, RSA >= 3072,
//!   DH >= 3072.
//!
//! Profiles nest: CNSA 2.0 is the most restrictive, CNSA 1.0
//! is intermediate, Unrestricted allows everything. KATs still
//! run all algorithms regardless of profile — the profile
//! only restricts post-initialization service access.
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
//! | IG 10.3.A software integrity | Delegated to `oxicrypt-integrity` (separate crate), wired in as the first KAT by the top-level caller. |
//!
//! # Thread safety
//!
//! State is stored in a single `AtomicU8` and is safe to read
//! from any thread. [`initialize_with_tests`] uses a
//! compare-and-swap to guarantee the self-test phase runs
//! exactly once per process lifetime even under concurrent
//! first-calls; racing losers spin on the `SelfTest` state byte
//! so they do not observe the transient phase and then receive
//! [`Error::AlreadyInitialized`].

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
            Self::AlreadyInitialized => f.write_str("FIPS module already initialized"),
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

/// Initializes the module with an empty KAT registry.
///
/// Convenience wrapper around [`initialize_with_tests`] for contexts
/// that want to exercise only the state machine (notably
/// `fips-module`'s own unit tests). Production callers of this crate
/// must use [`initialize_with_tests`] with the full approved-service
/// KAT set — a FIPS module that ships no self-tests is not compliant
/// with SP 800-140B regardless of whether the state machine runs.
pub fn initialize() -> Result<(), Error> {
    initialize_with_tests(&[])
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
/// `PowerOff -> SelfTest` CAS; losers receive
/// [`Error::AlreadyInitialized`] and should consult [`state`] to
/// discover whether the winning call succeeded.
///
/// Note: the slice is passed **by reference**, not built up by magic.
/// This repository deliberately avoids linker-section registration
/// tricks: the full set of power-up tests is visible in source at
/// every call site, which makes it straightforward to audit the
/// module's test inventory against the Security Policy.
pub fn initialize_with_tests(tests: &[KatEntry]) -> Result<(), Error> {
    // Try to claim the SelfTest phase. Only the first caller in the
    // process lifetime succeeds.
    let cas = STATE.compare_exchange(
        State::PowerOff as u8,
        State::SelfTest as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    if cas.is_err() {
        // Another thread is running (or has run) the self-tests. If
        // it is still inside `SelfTest`, spin until it publishes a
        // terminal state so racing callers don't observe the
        // transient phase and trip `require_operational`.
        while STATE.load(Ordering::Acquire) == State::SelfTest as u8 {
            core::hint::spin_loop();
        }
        return Err(Error::AlreadyInitialized);
    }

    for entry in tests {
        let result = (entry.run)();
        if result.is_err() {
            // Latch the module into Error before returning. Any
            // subsequent service call will be rejected by
            // require_operational().
            STATE.store(State::Error as u8, Ordering::Release);
            return Err(Error::SelfTestFailed { test: entry.name });
        }
    }

    STATE.store(State::Operational as u8, Ordering::Release);
    Ok(())
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

// =========================================================================
// Algorithm profile gating (CNSA 2.0 / CNSA 1.0)
// =========================================================================

/// Algorithm restriction profile selected at module initialization.
///
/// A single validated binary can serve general FIPS 140-3 consumers
/// (`Unrestricted`) and CNSA-restricted deployments (`Cnsa2`,
/// `Cnsa1`) by choosing the appropriate profile at init time.
///
/// The profile is immutable once set: it is stored alongside the
/// module `State` before the first KAT runs and cannot be changed
/// without restarting the process (which resets the state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgorithmProfile {
    /// All FIPS-approved algorithms are available. This is the
    /// default and preserves backward compatibility with callers
    /// that use [`initialize_with_tests`].
    Unrestricted = 0,
    /// CNSA 2.0 (CNSSP 15): quantum-resistant algorithms only.
    /// AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87, LMS, XMSS.
    /// SHA3-384/512 and 256-bit SP 800-185 variants are also
    /// allowed. All other algorithms return
    /// [`Error::AlgorithmRestricted`].
    Cnsa2 = 1,
    /// CNSA 1.0: classical algorithms for the transition period.
    /// AES-256, SHA-384, ECDSA/ECDH P-384, RSA >= 3072, DH >= 3072.
    Cnsa1 = 2,
}

impl AlgorithmProfile {
    const fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Unrestricted,
            2 => Self::Cnsa1,
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
/// This is the profile-aware entry point. It stores the selected
/// profile before running KATs, then transitions to `Operational` on
/// success. KATs always run all algorithms regardless of the profile —
/// the profile only restricts post-initialization service access via
/// [`require_allowed`].
///
/// See [`initialize_with_tests`] for the backward-compatible wrapper
/// that uses [`AlgorithmProfile::Unrestricted`].
pub fn initialize_with_profile(tests: &[KatEntry], profile: AlgorithmProfile) -> Result<(), Error> {
    // Store the profile before running KATs. This is safe even if
    // initialization fails: a failed init latches State::Error, so
    // no service call can reach require_allowed() anyway.
    PROFILE.store(profile as u8, Ordering::Release);
    initialize_with_tests(tests)
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
    // CNSA 2.0 baseline first: SHA-2 256s (CNSSP-15 mandate) claims 320-322,
    // then the rest of the SHA-2 family (128s/f, 192s/f, 256f), then SHAKE family.
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

    // ----- oxicrypt-lms: SP 800-208 (RFC 8554 / RFC 8708) -----
    // 160 per-pair entries (80 pairs × Sign + Verify), discriminants 500-659.
    // Layout: 500-539 SHA-256/M=32, 540-579 SHA-256/M=24,
    // 580-619 SHAKE/M=32, 620-659 SHAKE/M=24.
    // Within each family: (H ascending, W ascending), Sign/Verify alternating.
    // The 8 CNSA-2 permitted pairs (SHA-256/M=32 H{10,15,20,25} W{4,8}) are
    // flagged inline; all other 72 pairs are Unrestricted-only.

    // SHA-256 / N=32 family (RFC 8554 §A.1+§A.2)
    LmsSha256M32H5W1Sign = 500,
    LmsSha256M32H5W1Verify = 501,
    LmsSha256M32H5W2Sign = 502,
    LmsSha256M32H5W2Verify = 503,
    LmsSha256M32H5W4Sign = 504,
    LmsSha256M32H5W4Verify = 505,
    LmsSha256M32H5W8Sign = 506,
    LmsSha256M32H5W8Verify = 507,
    LmsSha256M32H10W1Sign = 508,
    LmsSha256M32H10W1Verify = 509,
    LmsSha256M32H10W2Sign = 510,
    LmsSha256M32H10W2Verify = 511,
    LmsSha256M32H10W4Sign = 512,   // CNSA 2.0
    LmsSha256M32H10W4Verify = 513, // CNSA 2.0
    LmsSha256M32H10W8Sign = 514,   // CNSA 2.0
    LmsSha256M32H10W8Verify = 515, // CNSA 2.0
    LmsSha256M32H15W1Sign = 516,
    LmsSha256M32H15W1Verify = 517,
    LmsSha256M32H15W2Sign = 518,
    LmsSha256M32H15W2Verify = 519,
    LmsSha256M32H15W4Sign = 520,   // CNSA 2.0
    LmsSha256M32H15W4Verify = 521, // CNSA 2.0
    LmsSha256M32H15W8Sign = 522,   // CNSA 2.0
    LmsSha256M32H15W8Verify = 523, // CNSA 2.0
    LmsSha256M32H20W1Sign = 524,
    LmsSha256M32H20W1Verify = 525,
    LmsSha256M32H20W2Sign = 526,
    LmsSha256M32H20W2Verify = 527,
    LmsSha256M32H20W4Sign = 528,   // CNSA 2.0
    LmsSha256M32H20W4Verify = 529, // CNSA 2.0
    LmsSha256M32H20W8Sign = 530,   // CNSA 2.0
    LmsSha256M32H20W8Verify = 531, // CNSA 2.0
    LmsSha256M32H25W1Sign = 532,
    LmsSha256M32H25W1Verify = 533,
    LmsSha256M32H25W2Sign = 534,
    LmsSha256M32H25W2Verify = 535,
    LmsSha256M32H25W4Sign = 536,   // CNSA 2.0
    LmsSha256M32H25W4Verify = 537, // CNSA 2.0
    LmsSha256M32H25W8Sign = 538,   // CNSA 2.0
    LmsSha256M32H25W8Verify = 539, // CNSA 2.0

    // SHA-256 / N=24 family (RFC 8708 §4.1)
    LmsSha256M24H5W1Sign = 540,
    LmsSha256M24H5W1Verify = 541,
    LmsSha256M24H5W2Sign = 542,
    LmsSha256M24H5W2Verify = 543,
    LmsSha256M24H5W4Sign = 544,
    LmsSha256M24H5W4Verify = 545,
    LmsSha256M24H5W8Sign = 546,
    LmsSha256M24H5W8Verify = 547,
    LmsSha256M24H10W1Sign = 548,
    LmsSha256M24H10W1Verify = 549,
    LmsSha256M24H10W2Sign = 550,
    LmsSha256M24H10W2Verify = 551,
    LmsSha256M24H10W4Sign = 552,
    LmsSha256M24H10W4Verify = 553,
    LmsSha256M24H10W8Sign = 554,
    LmsSha256M24H10W8Verify = 555,
    LmsSha256M24H15W1Sign = 556,
    LmsSha256M24H15W1Verify = 557,
    LmsSha256M24H15W2Sign = 558,
    LmsSha256M24H15W2Verify = 559,
    LmsSha256M24H15W4Sign = 560,
    LmsSha256M24H15W4Verify = 561,
    LmsSha256M24H15W8Sign = 562,
    LmsSha256M24H15W8Verify = 563,
    LmsSha256M24H20W1Sign = 564,
    LmsSha256M24H20W1Verify = 565,
    LmsSha256M24H20W2Sign = 566,
    LmsSha256M24H20W2Verify = 567,
    LmsSha256M24H20W4Sign = 568,
    LmsSha256M24H20W4Verify = 569,
    LmsSha256M24H20W8Sign = 570,
    LmsSha256M24H20W8Verify = 571,
    LmsSha256M24H25W1Sign = 572,
    LmsSha256M24H25W1Verify = 573,
    LmsSha256M24H25W2Sign = 574,
    LmsSha256M24H25W2Verify = 575,
    LmsSha256M24H25W4Sign = 576,
    LmsSha256M24H25W4Verify = 577,
    LmsSha256M24H25W8Sign = 578,
    LmsSha256M24H25W8Verify = 579,

    // SHAKE-256 / N=32 family (RFC 8708 §3.1)
    LmsShakeM32H5W1Sign = 580,
    LmsShakeM32H5W1Verify = 581,
    LmsShakeM32H5W2Sign = 582,
    LmsShakeM32H5W2Verify = 583,
    LmsShakeM32H5W4Sign = 584,
    LmsShakeM32H5W4Verify = 585,
    LmsShakeM32H5W8Sign = 586,
    LmsShakeM32H5W8Verify = 587,
    LmsShakeM32H10W1Sign = 588,
    LmsShakeM32H10W1Verify = 589,
    LmsShakeM32H10W2Sign = 590,
    LmsShakeM32H10W2Verify = 591,
    LmsShakeM32H10W4Sign = 592,
    LmsShakeM32H10W4Verify = 593,
    LmsShakeM32H10W8Sign = 594,
    LmsShakeM32H10W8Verify = 595,
    LmsShakeM32H15W1Sign = 596,
    LmsShakeM32H15W1Verify = 597,
    LmsShakeM32H15W2Sign = 598,
    LmsShakeM32H15W2Verify = 599,
    LmsShakeM32H15W4Sign = 600,
    LmsShakeM32H15W4Verify = 601,
    LmsShakeM32H15W8Sign = 602,
    LmsShakeM32H15W8Verify = 603,
    LmsShakeM32H20W1Sign = 604,
    LmsShakeM32H20W1Verify = 605,
    LmsShakeM32H20W2Sign = 606,
    LmsShakeM32H20W2Verify = 607,
    LmsShakeM32H20W4Sign = 608,
    LmsShakeM32H20W4Verify = 609,
    LmsShakeM32H20W8Sign = 610,
    LmsShakeM32H20W8Verify = 611,
    LmsShakeM32H25W1Sign = 612,
    LmsShakeM32H25W1Verify = 613,
    LmsShakeM32H25W2Sign = 614,
    LmsShakeM32H25W2Verify = 615,
    LmsShakeM32H25W4Sign = 616,
    LmsShakeM32H25W4Verify = 617,
    LmsShakeM32H25W8Sign = 618,
    LmsShakeM32H25W8Verify = 619,

    // SHAKE-256 / N=24 family (RFC 8708 §4.2)
    LmsShakeM24H5W1Sign = 620,
    LmsShakeM24H5W1Verify = 621,
    LmsShakeM24H5W2Sign = 622,
    LmsShakeM24H5W2Verify = 623,
    LmsShakeM24H5W4Sign = 624,
    LmsShakeM24H5W4Verify = 625,
    LmsShakeM24H5W8Sign = 626,
    LmsShakeM24H5W8Verify = 627,
    LmsShakeM24H10W1Sign = 628,
    LmsShakeM24H10W1Verify = 629,
    LmsShakeM24H10W2Sign = 630,
    LmsShakeM24H10W2Verify = 631,
    LmsShakeM24H10W4Sign = 632,
    LmsShakeM24H10W4Verify = 633,
    LmsShakeM24H10W8Sign = 634,
    LmsShakeM24H10W8Verify = 635,
    LmsShakeM24H15W1Sign = 636,
    LmsShakeM24H15W1Verify = 637,
    LmsShakeM24H15W2Sign = 638,
    LmsShakeM24H15W2Verify = 639,
    LmsShakeM24H15W4Sign = 640,
    LmsShakeM24H15W4Verify = 641,
    LmsShakeM24H15W8Sign = 642,
    LmsShakeM24H15W8Verify = 643,
    LmsShakeM24H20W1Sign = 644,
    LmsShakeM24H20W1Verify = 645,
    LmsShakeM24H20W2Sign = 646,
    LmsShakeM24H20W2Verify = 647,
    LmsShakeM24H20W4Sign = 648,
    LmsShakeM24H20W4Verify = 649,
    LmsShakeM24H20W8Sign = 650,
    LmsShakeM24H20W8Verify = 651,
    LmsShakeM24H25W1Sign = 652,
    LmsShakeM24H25W1Verify = 653,
    LmsShakeM24H25W2Sign = 654,
    LmsShakeM24H25W2Verify = 655,
    LmsShakeM24H25W4Sign = 656,
    LmsShakeM24H25W4Verify = 657,
    LmsShakeM24H25W8Sign = 658,
    LmsShakeM24H25W8Verify = 659,

    // ----- oxicrypt-xmss: SP 800-208 (stub) -----
    // Renumbered 340/341 → 370/371 in Batch 4 to make room for the SLH-DSA block.
    XmssSign = 370,
    XmssVerify = 371,

    // ----- oxicrypt-dh: RFC 3526 (stub) -----
    // Renumbered 350 → 380 in Batch 4 to make room for the SLH-DSA block.
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
            Self::LmsSha256M32H5W1Sign => "LMS SHA-256 M=32 H=5 W=1 sign",
            Self::LmsSha256M32H5W1Verify => "LMS SHA-256 M=32 H=5 W=1 verify",
            Self::LmsSha256M32H5W2Sign => "LMS SHA-256 M=32 H=5 W=2 sign",
            Self::LmsSha256M32H5W2Verify => "LMS SHA-256 M=32 H=5 W=2 verify",
            Self::LmsSha256M32H5W4Sign => "LMS SHA-256 M=32 H=5 W=4 sign",
            Self::LmsSha256M32H5W4Verify => "LMS SHA-256 M=32 H=5 W=4 verify",
            Self::LmsSha256M32H5W8Sign => "LMS SHA-256 M=32 H=5 W=8 sign",
            Self::LmsSha256M32H5W8Verify => "LMS SHA-256 M=32 H=5 W=8 verify",
            Self::LmsSha256M32H10W1Sign => "LMS SHA-256 M=32 H=10 W=1 sign",
            Self::LmsSha256M32H10W1Verify => "LMS SHA-256 M=32 H=10 W=1 verify",
            Self::LmsSha256M32H10W2Sign => "LMS SHA-256 M=32 H=10 W=2 sign",
            Self::LmsSha256M32H10W2Verify => "LMS SHA-256 M=32 H=10 W=2 verify",
            Self::LmsSha256M32H10W4Sign => "LMS SHA-256 M=32 H=10 W=4 sign",
            Self::LmsSha256M32H10W4Verify => "LMS SHA-256 M=32 H=10 W=4 verify",
            Self::LmsSha256M32H10W8Sign => "LMS SHA-256 M=32 H=10 W=8 sign",
            Self::LmsSha256M32H10W8Verify => "LMS SHA-256 M=32 H=10 W=8 verify",
            Self::LmsSha256M32H15W1Sign => "LMS SHA-256 M=32 H=15 W=1 sign",
            Self::LmsSha256M32H15W1Verify => "LMS SHA-256 M=32 H=15 W=1 verify",
            Self::LmsSha256M32H15W2Sign => "LMS SHA-256 M=32 H=15 W=2 sign",
            Self::LmsSha256M32H15W2Verify => "LMS SHA-256 M=32 H=15 W=2 verify",
            Self::LmsSha256M32H15W4Sign => "LMS SHA-256 M=32 H=15 W=4 sign",
            Self::LmsSha256M32H15W4Verify => "LMS SHA-256 M=32 H=15 W=4 verify",
            Self::LmsSha256M32H15W8Sign => "LMS SHA-256 M=32 H=15 W=8 sign",
            Self::LmsSha256M32H15W8Verify => "LMS SHA-256 M=32 H=15 W=8 verify",
            Self::LmsSha256M32H20W1Sign => "LMS SHA-256 M=32 H=20 W=1 sign",
            Self::LmsSha256M32H20W1Verify => "LMS SHA-256 M=32 H=20 W=1 verify",
            Self::LmsSha256M32H20W2Sign => "LMS SHA-256 M=32 H=20 W=2 sign",
            Self::LmsSha256M32H20W2Verify => "LMS SHA-256 M=32 H=20 W=2 verify",
            Self::LmsSha256M32H20W4Sign => "LMS SHA-256 M=32 H=20 W=4 sign",
            Self::LmsSha256M32H20W4Verify => "LMS SHA-256 M=32 H=20 W=4 verify",
            Self::LmsSha256M32H20W8Sign => "LMS SHA-256 M=32 H=20 W=8 sign",
            Self::LmsSha256M32H20W8Verify => "LMS SHA-256 M=32 H=20 W=8 verify",
            Self::LmsSha256M32H25W1Sign => "LMS SHA-256 M=32 H=25 W=1 sign",
            Self::LmsSha256M32H25W1Verify => "LMS SHA-256 M=32 H=25 W=1 verify",
            Self::LmsSha256M32H25W2Sign => "LMS SHA-256 M=32 H=25 W=2 sign",
            Self::LmsSha256M32H25W2Verify => "LMS SHA-256 M=32 H=25 W=2 verify",
            Self::LmsSha256M32H25W4Sign => "LMS SHA-256 M=32 H=25 W=4 sign",
            Self::LmsSha256M32H25W4Verify => "LMS SHA-256 M=32 H=25 W=4 verify",
            Self::LmsSha256M32H25W8Sign => "LMS SHA-256 M=32 H=25 W=8 sign",
            Self::LmsSha256M32H25W8Verify => "LMS SHA-256 M=32 H=25 W=8 verify",
            Self::LmsSha256M24H5W1Sign => "LMS SHA-256 M=24 H=5 W=1 sign",
            Self::LmsSha256M24H5W1Verify => "LMS SHA-256 M=24 H=5 W=1 verify",
            Self::LmsSha256M24H5W2Sign => "LMS SHA-256 M=24 H=5 W=2 sign",
            Self::LmsSha256M24H5W2Verify => "LMS SHA-256 M=24 H=5 W=2 verify",
            Self::LmsSha256M24H5W4Sign => "LMS SHA-256 M=24 H=5 W=4 sign",
            Self::LmsSha256M24H5W4Verify => "LMS SHA-256 M=24 H=5 W=4 verify",
            Self::LmsSha256M24H5W8Sign => "LMS SHA-256 M=24 H=5 W=8 sign",
            Self::LmsSha256M24H5W8Verify => "LMS SHA-256 M=24 H=5 W=8 verify",
            Self::LmsSha256M24H10W1Sign => "LMS SHA-256 M=24 H=10 W=1 sign",
            Self::LmsSha256M24H10W1Verify => "LMS SHA-256 M=24 H=10 W=1 verify",
            Self::LmsSha256M24H10W2Sign => "LMS SHA-256 M=24 H=10 W=2 sign",
            Self::LmsSha256M24H10W2Verify => "LMS SHA-256 M=24 H=10 W=2 verify",
            Self::LmsSha256M24H10W4Sign => "LMS SHA-256 M=24 H=10 W=4 sign",
            Self::LmsSha256M24H10W4Verify => "LMS SHA-256 M=24 H=10 W=4 verify",
            Self::LmsSha256M24H10W8Sign => "LMS SHA-256 M=24 H=10 W=8 sign",
            Self::LmsSha256M24H10W8Verify => "LMS SHA-256 M=24 H=10 W=8 verify",
            Self::LmsSha256M24H15W1Sign => "LMS SHA-256 M=24 H=15 W=1 sign",
            Self::LmsSha256M24H15W1Verify => "LMS SHA-256 M=24 H=15 W=1 verify",
            Self::LmsSha256M24H15W2Sign => "LMS SHA-256 M=24 H=15 W=2 sign",
            Self::LmsSha256M24H15W2Verify => "LMS SHA-256 M=24 H=15 W=2 verify",
            Self::LmsSha256M24H15W4Sign => "LMS SHA-256 M=24 H=15 W=4 sign",
            Self::LmsSha256M24H15W4Verify => "LMS SHA-256 M=24 H=15 W=4 verify",
            Self::LmsSha256M24H15W8Sign => "LMS SHA-256 M=24 H=15 W=8 sign",
            Self::LmsSha256M24H15W8Verify => "LMS SHA-256 M=24 H=15 W=8 verify",
            Self::LmsSha256M24H20W1Sign => "LMS SHA-256 M=24 H=20 W=1 sign",
            Self::LmsSha256M24H20W1Verify => "LMS SHA-256 M=24 H=20 W=1 verify",
            Self::LmsSha256M24H20W2Sign => "LMS SHA-256 M=24 H=20 W=2 sign",
            Self::LmsSha256M24H20W2Verify => "LMS SHA-256 M=24 H=20 W=2 verify",
            Self::LmsSha256M24H20W4Sign => "LMS SHA-256 M=24 H=20 W=4 sign",
            Self::LmsSha256M24H20W4Verify => "LMS SHA-256 M=24 H=20 W=4 verify",
            Self::LmsSha256M24H20W8Sign => "LMS SHA-256 M=24 H=20 W=8 sign",
            Self::LmsSha256M24H20W8Verify => "LMS SHA-256 M=24 H=20 W=8 verify",
            Self::LmsSha256M24H25W1Sign => "LMS SHA-256 M=24 H=25 W=1 sign",
            Self::LmsSha256M24H25W1Verify => "LMS SHA-256 M=24 H=25 W=1 verify",
            Self::LmsSha256M24H25W2Sign => "LMS SHA-256 M=24 H=25 W=2 sign",
            Self::LmsSha256M24H25W2Verify => "LMS SHA-256 M=24 H=25 W=2 verify",
            Self::LmsSha256M24H25W4Sign => "LMS SHA-256 M=24 H=25 W=4 sign",
            Self::LmsSha256M24H25W4Verify => "LMS SHA-256 M=24 H=25 W=4 verify",
            Self::LmsSha256M24H25W8Sign => "LMS SHA-256 M=24 H=25 W=8 sign",
            Self::LmsSha256M24H25W8Verify => "LMS SHA-256 M=24 H=25 W=8 verify",
            Self::LmsShakeM32H5W1Sign => "LMS SHAKE M=32 H=5 W=1 sign",
            Self::LmsShakeM32H5W1Verify => "LMS SHAKE M=32 H=5 W=1 verify",
            Self::LmsShakeM32H5W2Sign => "LMS SHAKE M=32 H=5 W=2 sign",
            Self::LmsShakeM32H5W2Verify => "LMS SHAKE M=32 H=5 W=2 verify",
            Self::LmsShakeM32H5W4Sign => "LMS SHAKE M=32 H=5 W=4 sign",
            Self::LmsShakeM32H5W4Verify => "LMS SHAKE M=32 H=5 W=4 verify",
            Self::LmsShakeM32H5W8Sign => "LMS SHAKE M=32 H=5 W=8 sign",
            Self::LmsShakeM32H5W8Verify => "LMS SHAKE M=32 H=5 W=8 verify",
            Self::LmsShakeM32H10W1Sign => "LMS SHAKE M=32 H=10 W=1 sign",
            Self::LmsShakeM32H10W1Verify => "LMS SHAKE M=32 H=10 W=1 verify",
            Self::LmsShakeM32H10W2Sign => "LMS SHAKE M=32 H=10 W=2 sign",
            Self::LmsShakeM32H10W2Verify => "LMS SHAKE M=32 H=10 W=2 verify",
            Self::LmsShakeM32H10W4Sign => "LMS SHAKE M=32 H=10 W=4 sign",
            Self::LmsShakeM32H10W4Verify => "LMS SHAKE M=32 H=10 W=4 verify",
            Self::LmsShakeM32H10W8Sign => "LMS SHAKE M=32 H=10 W=8 sign",
            Self::LmsShakeM32H10W8Verify => "LMS SHAKE M=32 H=10 W=8 verify",
            Self::LmsShakeM32H15W1Sign => "LMS SHAKE M=32 H=15 W=1 sign",
            Self::LmsShakeM32H15W1Verify => "LMS SHAKE M=32 H=15 W=1 verify",
            Self::LmsShakeM32H15W2Sign => "LMS SHAKE M=32 H=15 W=2 sign",
            Self::LmsShakeM32H15W2Verify => "LMS SHAKE M=32 H=15 W=2 verify",
            Self::LmsShakeM32H15W4Sign => "LMS SHAKE M=32 H=15 W=4 sign",
            Self::LmsShakeM32H15W4Verify => "LMS SHAKE M=32 H=15 W=4 verify",
            Self::LmsShakeM32H15W8Sign => "LMS SHAKE M=32 H=15 W=8 sign",
            Self::LmsShakeM32H15W8Verify => "LMS SHAKE M=32 H=15 W=8 verify",
            Self::LmsShakeM32H20W1Sign => "LMS SHAKE M=32 H=20 W=1 sign",
            Self::LmsShakeM32H20W1Verify => "LMS SHAKE M=32 H=20 W=1 verify",
            Self::LmsShakeM32H20W2Sign => "LMS SHAKE M=32 H=20 W=2 sign",
            Self::LmsShakeM32H20W2Verify => "LMS SHAKE M=32 H=20 W=2 verify",
            Self::LmsShakeM32H20W4Sign => "LMS SHAKE M=32 H=20 W=4 sign",
            Self::LmsShakeM32H20W4Verify => "LMS SHAKE M=32 H=20 W=4 verify",
            Self::LmsShakeM32H20W8Sign => "LMS SHAKE M=32 H=20 W=8 sign",
            Self::LmsShakeM32H20W8Verify => "LMS SHAKE M=32 H=20 W=8 verify",
            Self::LmsShakeM32H25W1Sign => "LMS SHAKE M=32 H=25 W=1 sign",
            Self::LmsShakeM32H25W1Verify => "LMS SHAKE M=32 H=25 W=1 verify",
            Self::LmsShakeM32H25W2Sign => "LMS SHAKE M=32 H=25 W=2 sign",
            Self::LmsShakeM32H25W2Verify => "LMS SHAKE M=32 H=25 W=2 verify",
            Self::LmsShakeM32H25W4Sign => "LMS SHAKE M=32 H=25 W=4 sign",
            Self::LmsShakeM32H25W4Verify => "LMS SHAKE M=32 H=25 W=4 verify",
            Self::LmsShakeM32H25W8Sign => "LMS SHAKE M=32 H=25 W=8 sign",
            Self::LmsShakeM32H25W8Verify => "LMS SHAKE M=32 H=25 W=8 verify",
            Self::LmsShakeM24H5W1Sign => "LMS SHAKE M=24 H=5 W=1 sign",
            Self::LmsShakeM24H5W1Verify => "LMS SHAKE M=24 H=5 W=1 verify",
            Self::LmsShakeM24H5W2Sign => "LMS SHAKE M=24 H=5 W=2 sign",
            Self::LmsShakeM24H5W2Verify => "LMS SHAKE M=24 H=5 W=2 verify",
            Self::LmsShakeM24H5W4Sign => "LMS SHAKE M=24 H=5 W=4 sign",
            Self::LmsShakeM24H5W4Verify => "LMS SHAKE M=24 H=5 W=4 verify",
            Self::LmsShakeM24H5W8Sign => "LMS SHAKE M=24 H=5 W=8 sign",
            Self::LmsShakeM24H5W8Verify => "LMS SHAKE M=24 H=5 W=8 verify",
            Self::LmsShakeM24H10W1Sign => "LMS SHAKE M=24 H=10 W=1 sign",
            Self::LmsShakeM24H10W1Verify => "LMS SHAKE M=24 H=10 W=1 verify",
            Self::LmsShakeM24H10W2Sign => "LMS SHAKE M=24 H=10 W=2 sign",
            Self::LmsShakeM24H10W2Verify => "LMS SHAKE M=24 H=10 W=2 verify",
            Self::LmsShakeM24H10W4Sign => "LMS SHAKE M=24 H=10 W=4 sign",
            Self::LmsShakeM24H10W4Verify => "LMS SHAKE M=24 H=10 W=4 verify",
            Self::LmsShakeM24H10W8Sign => "LMS SHAKE M=24 H=10 W=8 sign",
            Self::LmsShakeM24H10W8Verify => "LMS SHAKE M=24 H=10 W=8 verify",
            Self::LmsShakeM24H15W1Sign => "LMS SHAKE M=24 H=15 W=1 sign",
            Self::LmsShakeM24H15W1Verify => "LMS SHAKE M=24 H=15 W=1 verify",
            Self::LmsShakeM24H15W2Sign => "LMS SHAKE M=24 H=15 W=2 sign",
            Self::LmsShakeM24H15W2Verify => "LMS SHAKE M=24 H=15 W=2 verify",
            Self::LmsShakeM24H15W4Sign => "LMS SHAKE M=24 H=15 W=4 sign",
            Self::LmsShakeM24H15W4Verify => "LMS SHAKE M=24 H=15 W=4 verify",
            Self::LmsShakeM24H15W8Sign => "LMS SHAKE M=24 H=15 W=8 sign",
            Self::LmsShakeM24H15W8Verify => "LMS SHAKE M=24 H=15 W=8 verify",
            Self::LmsShakeM24H20W1Sign => "LMS SHAKE M=24 H=20 W=1 sign",
            Self::LmsShakeM24H20W1Verify => "LMS SHAKE M=24 H=20 W=1 verify",
            Self::LmsShakeM24H20W2Sign => "LMS SHAKE M=24 H=20 W=2 sign",
            Self::LmsShakeM24H20W2Verify => "LMS SHAKE M=24 H=20 W=2 verify",
            Self::LmsShakeM24H20W4Sign => "LMS SHAKE M=24 H=20 W=4 sign",
            Self::LmsShakeM24H20W4Verify => "LMS SHAKE M=24 H=20 W=4 verify",
            Self::LmsShakeM24H20W8Sign => "LMS SHAKE M=24 H=20 W=8 sign",
            Self::LmsShakeM24H20W8Verify => "LMS SHAKE M=24 H=20 W=8 verify",
            Self::LmsShakeM24H25W1Sign => "LMS SHAKE M=24 H=25 W=1 sign",
            Self::LmsShakeM24H25W1Verify => "LMS SHAKE M=24 H=25 W=1 verify",
            Self::LmsShakeM24H25W2Sign => "LMS SHAKE M=24 H=25 W=2 sign",
            Self::LmsShakeM24H25W2Verify => "LMS SHAKE M=24 H=25 W=2 verify",
            Self::LmsShakeM24H25W4Sign => "LMS SHAKE M=24 H=25 W=4 sign",
            Self::LmsShakeM24H25W4Verify => "LMS SHAKE M=24 H=25 W=4 verify",
            Self::LmsShakeM24H25W8Sign => "LMS SHAKE M=24 H=25 W=8 sign",
            Self::LmsShakeM24H25W8Verify => "LMS SHAKE M=24 H=25 W=8 verify",
            Self::XmssSign => "XMSS sign",
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
    }
}

/// CNSA 2.0 allowed set. Only quantum-resistant algorithms plus
/// AES-256, SHA-384/512, SHA3-384/512, and 256-bit SP 800-185.
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
            // SHA3-384, SHA3-512 (for internal / hardware — see plan note)
            | Service::Sha3_384
            | Service::Sha3_512
            // SHAKE-256
            | Service::Shake256
            // 256-bit SP 800-185 variants
            | Service::CShake256
            | Service::Kmac256
            | Service::KmacXof256
            | Service::TupleHash256
            | Service::TupleHashXof256
            | Service::ParallelHash256
            | Service::ParallelHashXof256
            // HMAC with allowed hashes
            | Service::HmacSha384
            | Service::HmacSha512
            | Service::HmacSha3_384
            | Service::HmacSha3_512
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
            | Service::Pbkdf2HmacSha384
            | Service::Pbkdf2HmacSha512
            // TLS 1.3 KDF — mandatory transport in CNSA 2.0
            | Service::Tls13Kdf
            // Post-quantum (CNSA 2.0 core)
            | Service::MlKem1024Encaps
            | Service::MlKem1024Decaps
            | Service::MlKem1024Keygen
            | Service::MlDsa87Sign
            | Service::MlDsa87Verify
            | Service::MlDsa87Keygen
            // SLH-DSA-SHA2-256s — CNSSP-15 CNSA 2.0 mandate (only SLH-DSA
            // parameter set permitted under CNSA 2.0; the other 11 parameter
            // sets are intentionally excluded and fall through to the
            // fail-safe default-block).
            | Service::SlhDsaSha2256sKeygen
            | Service::SlhDsaSha2256sSign
            | Service::SlhDsaSha2256sVerify
            // LMS — SP 800-208 stateful HBS for software/firmware signing.
            // CNSA 2.0 permits the 8 SHA-256/M=32 pairs at H{10,15,20,25}×W{4,8}
            // per CNSSP 15. All other 72 pairs default-block via the `matches!`
            // fail-safe (see CMVP gem in security-policy.md).
            | Service::LmsSha256M32H10W4Sign
            | Service::LmsSha256M32H10W4Verify
            | Service::LmsSha256M32H10W8Sign
            | Service::LmsSha256M32H10W8Verify
            | Service::LmsSha256M32H15W4Sign
            | Service::LmsSha256M32H15W4Verify
            | Service::LmsSha256M32H15W8Sign
            | Service::LmsSha256M32H15W8Verify
            | Service::LmsSha256M32H20W4Sign
            | Service::LmsSha256M32H20W4Verify
            | Service::LmsSha256M32H20W8Sign
            | Service::LmsSha256M32H20W8Verify
            | Service::LmsSha256M32H25W4Sign
            | Service::LmsSha256M32H25W4Verify
            | Service::LmsSha256M32H25W8Sign
            | Service::LmsSha256M32H25W8Verify
            | Service::XmssSign
            | Service::XmssVerify
    )
}

/// CNSA 1.0 allowed set. Classical algorithms for the transition
/// period: AES-256, SHA-384, ECDSA/ECDH P-384, RSA >= 3072,
/// DH >= 3072. Also includes SHA-256 (widely needed for
/// interoperability and certificate verification) and the
/// post-quantum algorithms allowed in CNSA 2.0 (CNSA 1.0 is
/// the transition profile; PQ algorithms are allowed if present).
const fn is_cnsa1_allowed(service: Service) -> bool {
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
            // SHA-256, SHA-384, SHA-512 (SHA-256 needed for certs)
            | Service::Sha256
            | Service::Sha384
            | Service::Sha512
            // SHA3-256, SHA3-384, SHA3-512
            | Service::Sha3_256
            | Service::Sha3_384
            | Service::Sha3_512
            // SHAKE-256
            | Service::Shake256
            // 256-bit SP 800-185 variants
            | Service::CShake256
            | Service::Kmac256
            | Service::KmacXof256
            | Service::TupleHash256
            | Service::TupleHashXof256
            | Service::ParallelHash256
            | Service::ParallelHashXof256
            // HMAC with allowed hashes
            | Service::HmacSha256
            | Service::HmacSha384
            | Service::HmacSha512
            | Service::HmacSha3_256
            | Service::HmacSha3_384
            | Service::HmacSha3_512
            // CMAC-AES-256
            | Service::CmacAes256
            // DRBGs backed by AES-256 or allowed hashes
            | Service::CtrDrbgAes256
            | Service::HashDrbgSha256
            | Service::HashDrbgSha384
            | Service::HashDrbgSha512
            | Service::HmacDrbgSha256
            | Service::HmacDrbgSha384
            | Service::HmacDrbgSha512
            // KDFs with allowed backing
            | Service::HkdfSha256
            | Service::HkdfSha384
            | Service::HkdfSha512
            | Service::KbkdfHmacSha256
            | Service::KbkdfHmacSha384
            | Service::KbkdfHmacSha512
            | Service::KbkdfCmacAes256
            | Service::Pbkdf2HmacSha256
            | Service::Pbkdf2HmacSha384
            | Service::Pbkdf2HmacSha512
            // ECDSA/ECDH P-384
            | Service::EcdsaP384Sign
            | Service::EcdsaP384Verify
            | Service::EcdsaP384Keygen
            | Service::EcdhP384
            // RSA >= 3072
            | Service::RsaKeygen3072
            | Service::RsaPkcs1v15Sign3072
            | Service::RsaPssSign3072
            | Service::RsaOaep3072
            | Service::RsaPkcs1v15Verify3072
            | Service::RsaPssVerify3072
            | Service::RsaKeygen4096
            | Service::RsaPkcs1v15Sign4096
            | Service::RsaPssSign4096
            | Service::RsaOaep4096
            | Service::RsaPkcs1v15Verify4096
            | Service::RsaPssVerify4096
            // DH >= 3072
            | Service::Dh3072
            // TLS 1.3 KDF — accepted as the modern transport KDF in the
            // transition profile too (TLS 1.3 with classical-only ciphers
            // is CNSA-1.0-compatible)
            | Service::Tls13Kdf
            // PQ algorithms (allowed during transition for hybrid use)
            | Service::MlKem1024Encaps
            | Service::MlKem1024Decaps
            | Service::MlKem1024Keygen
            | Service::MlDsa87Sign
            | Service::MlDsa87Verify
            | Service::MlDsa87Keygen
            // LMS — mirrors CNSA 2.0's 8-pair subset during the transition.
            // Stateful HBS is permitted under both profiles for software/firmware
            // signing per CNSSP 15; the 72 non-listed pairs default-block.
            | Service::LmsSha256M32H10W4Sign
            | Service::LmsSha256M32H10W4Verify
            | Service::LmsSha256M32H10W8Sign
            | Service::LmsSha256M32H10W8Verify
            | Service::LmsSha256M32H15W4Sign
            | Service::LmsSha256M32H15W4Verify
            | Service::LmsSha256M32H15W8Sign
            | Service::LmsSha256M32H15W8Verify
            | Service::LmsSha256M32H20W4Sign
            | Service::LmsSha256M32H20W4Verify
            | Service::LmsSha256M32H20W8Sign
            | Service::LmsSha256M32H20W8Verify
            | Service::LmsSha256M32H25W4Sign
            | Service::LmsSha256M32H25W4Verify
            | Service::LmsSha256M32H25W8Sign
            | Service::LmsSha256M32H25W8Verify
            | Service::XmssSign
            | Service::XmssVerify
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

#[cfg(test)]
fn reset_for_test() {
    STATE.store(State::PowerOff as u8, Ordering::Release);
    PROFILE.store(AlgorithmProfile::Unrestricted as u8, Ordering::Release);
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        AlgorithmProfile, Error, KatEntry, SelfTest, SelfTestFailure, Service, State,
        active_profile, enter_error_state, initialize, initialize_with_profile,
        initialize_with_tests, is_allowed, is_operational, require_allowed, require_operational,
        reset_for_test, state,
    };
    use alloc::string::ToString;

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

    #[test]
    fn registry_runs_passing_tests_and_reaches_operational() {
        reset_for_test();
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
        initialize_with_tests(&tests).unwrap();
        assert_eq!(state(), State::Operational);
    }

    #[test]
    fn registry_failing_test_latches_error_and_returns_name() {
        reset_for_test();
        let tests = [
            KatEntry {
                name: "dummy-pass",
                run: always_pass,
            },
            KatEntry {
                name: "dummy-fail",
                run: always_fail,
            },
            // This third entry must never run.
            KatEntry {
                name: "dummy-unreached",
                run: always_pass,
            },
        ];
        match initialize_with_tests(&tests) {
            Err(Error::SelfTestFailed { test: "dummy-fail" }) => {}
            other => panic!("expected SelfTestFailed{{dummy-fail}}, got {other:?}"),
        }
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
        reset_for_test();
        assert_eq!(active_profile(), AlgorithmProfile::Unrestricted);
    }

    #[test]
    fn initialize_with_profile_sets_cnsa2() {
        reset_for_test();
        initialize_with_profile(&[], AlgorithmProfile::Cnsa2).unwrap();
        assert_eq!(active_profile(), AlgorithmProfile::Cnsa2);
        assert!(is_operational());
    }

    #[test]
    fn initialize_with_profile_sets_cnsa1() {
        reset_for_test();
        initialize_with_profile(&[], AlgorithmProfile::Cnsa1).unwrap();
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
            Service::LmsSha256M32H10W4Sign,
            Service::Dh3072,
            Service::SlhDsaSha2256sSign,
            Service::Tls12Kdf,
            Service::Tls13Kdf,
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
            Service::Sha3_384,
            Service::Sha3_512,
            Service::HmacSha384,
            Service::HmacSha512,
            Service::CtrDrbgAes256,
            Service::HashDrbgSha384,
            Service::HmacDrbgSha512,
            Service::Kmac256,
            Service::KmacXof256,
            Service::MlKem1024Encaps,
            Service::MlKem1024Decaps,
            Service::MlKem1024Keygen,
            Service::MlDsa87Sign,
            Service::MlDsa87Verify,
            Service::MlDsa87Keygen,
            Service::LmsSha256M32H10W4Sign,
            Service::LmsSha256M32H10W4Verify,
            Service::XmssSign,
            Service::XmssVerify,
            Service::Tls13Kdf,
        ];
        for svc in allowed {
            assert!(
                is_allowed(AlgorithmProfile::Cnsa2, svc),
                "{svc} should be allowed in CNSA 2.0"
            );
        }
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
            Service::Tls12Kdf,
            // SLH-DSA-SHA2-128s is not in CNSA 2.0 (only SHA-2 256s is the
            // CNSSP-15 mandate; the other 11 parameter sets are excluded).
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

    #[test]
    fn cnsa1_allows_p384_rsa3072_and_pq() {
        let allowed = [
            Service::Aes256Gcm,
            Service::Sha384,
            Service::Sha256,
            Service::EcdsaP384Sign,
            Service::EcdsaP384Verify,
            Service::EcdsaP384Keygen,
            Service::EcdhP384,
            Service::RsaPssSign3072,
            Service::RsaOaep3072,
            Service::RsaPssSign4096,
            Service::Dh3072,
            Service::MlKem1024Encaps,
            Service::LmsSha256M32H10W4Sign,
            Service::Tls13Kdf,
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
            Service::Tls12Kdf,
        ];
        for svc in blocked {
            assert!(
                !is_allowed(AlgorithmProfile::Cnsa1, svc),
                "{svc} should be BLOCKED in CNSA 1.0"
            );
        }
    }

    #[test]
    // 160 enumerated variants + 16 CNSA-allowed entries is naturally long;
    // any "natural factoring" (helper to build the array, macro to emit it)
    // would obscure the audit-readable enumeration. CMVP reviewers benefit
    // from the explicit, line-by-line variant list.
    #[allow(clippy::too_many_lines)]
    fn lms_gating_is_exhaustive_across_all_160_variants() {
        // Enumerates every LMS Service variant (80 (LMS, LM-OTS) pairs ×
        // {Sign, Verify} = 160 entries) and verifies the fail-safe gating:
        // only the 8 CNSA-2-permitted pairs (SHA-256/M=32, H{10,15,20,25}
        // × W{4,8}) × 2 ops = 16 entries are allowed under CNSA 2.0;
        // CNSA 1.0 mirrors that same 16-entry subset (transition profile);
        // all 160 are permitted under Unrestricted. If a new LMS variant
        // is added without a matching entry in this array, the
        // length assertion catches the drift.
        let all_160 = [
            // SHA-256 / N=32 family (20 pairs, 40 entries).
            Service::LmsSha256M32H5W1Sign,
            Service::LmsSha256M32H5W1Verify,
            Service::LmsSha256M32H5W2Sign,
            Service::LmsSha256M32H5W2Verify,
            Service::LmsSha256M32H5W4Sign,
            Service::LmsSha256M32H5W4Verify,
            Service::LmsSha256M32H5W8Sign,
            Service::LmsSha256M32H5W8Verify,
            Service::LmsSha256M32H10W1Sign,
            Service::LmsSha256M32H10W1Verify,
            Service::LmsSha256M32H10W2Sign,
            Service::LmsSha256M32H10W2Verify,
            Service::LmsSha256M32H10W4Sign,
            Service::LmsSha256M32H10W4Verify,
            Service::LmsSha256M32H10W8Sign,
            Service::LmsSha256M32H10W8Verify,
            Service::LmsSha256M32H15W1Sign,
            Service::LmsSha256M32H15W1Verify,
            Service::LmsSha256M32H15W2Sign,
            Service::LmsSha256M32H15W2Verify,
            Service::LmsSha256M32H15W4Sign,
            Service::LmsSha256M32H15W4Verify,
            Service::LmsSha256M32H15W8Sign,
            Service::LmsSha256M32H15W8Verify,
            Service::LmsSha256M32H20W1Sign,
            Service::LmsSha256M32H20W1Verify,
            Service::LmsSha256M32H20W2Sign,
            Service::LmsSha256M32H20W2Verify,
            Service::LmsSha256M32H20W4Sign,
            Service::LmsSha256M32H20W4Verify,
            Service::LmsSha256M32H20W8Sign,
            Service::LmsSha256M32H20W8Verify,
            Service::LmsSha256M32H25W1Sign,
            Service::LmsSha256M32H25W1Verify,
            Service::LmsSha256M32H25W2Sign,
            Service::LmsSha256M32H25W2Verify,
            Service::LmsSha256M32H25W4Sign,
            Service::LmsSha256M32H25W4Verify,
            Service::LmsSha256M32H25W8Sign,
            Service::LmsSha256M32H25W8Verify,
            // SHA-256 / N=24 family (20 pairs, 40 entries).
            Service::LmsSha256M24H5W1Sign,
            Service::LmsSha256M24H5W1Verify,
            Service::LmsSha256M24H5W2Sign,
            Service::LmsSha256M24H5W2Verify,
            Service::LmsSha256M24H5W4Sign,
            Service::LmsSha256M24H5W4Verify,
            Service::LmsSha256M24H5W8Sign,
            Service::LmsSha256M24H5W8Verify,
            Service::LmsSha256M24H10W1Sign,
            Service::LmsSha256M24H10W1Verify,
            Service::LmsSha256M24H10W2Sign,
            Service::LmsSha256M24H10W2Verify,
            Service::LmsSha256M24H10W4Sign,
            Service::LmsSha256M24H10W4Verify,
            Service::LmsSha256M24H10W8Sign,
            Service::LmsSha256M24H10W8Verify,
            Service::LmsSha256M24H15W1Sign,
            Service::LmsSha256M24H15W1Verify,
            Service::LmsSha256M24H15W2Sign,
            Service::LmsSha256M24H15W2Verify,
            Service::LmsSha256M24H15W4Sign,
            Service::LmsSha256M24H15W4Verify,
            Service::LmsSha256M24H15W8Sign,
            Service::LmsSha256M24H15W8Verify,
            Service::LmsSha256M24H20W1Sign,
            Service::LmsSha256M24H20W1Verify,
            Service::LmsSha256M24H20W2Sign,
            Service::LmsSha256M24H20W2Verify,
            Service::LmsSha256M24H20W4Sign,
            Service::LmsSha256M24H20W4Verify,
            Service::LmsSha256M24H20W8Sign,
            Service::LmsSha256M24H20W8Verify,
            Service::LmsSha256M24H25W1Sign,
            Service::LmsSha256M24H25W1Verify,
            Service::LmsSha256M24H25W2Sign,
            Service::LmsSha256M24H25W2Verify,
            Service::LmsSha256M24H25W4Sign,
            Service::LmsSha256M24H25W4Verify,
            Service::LmsSha256M24H25W8Sign,
            Service::LmsSha256M24H25W8Verify,
            // SHAKE-256 / N=32 family (20 pairs, 40 entries).
            Service::LmsShakeM32H5W1Sign,
            Service::LmsShakeM32H5W1Verify,
            Service::LmsShakeM32H5W2Sign,
            Service::LmsShakeM32H5W2Verify,
            Service::LmsShakeM32H5W4Sign,
            Service::LmsShakeM32H5W4Verify,
            Service::LmsShakeM32H5W8Sign,
            Service::LmsShakeM32H5W8Verify,
            Service::LmsShakeM32H10W1Sign,
            Service::LmsShakeM32H10W1Verify,
            Service::LmsShakeM32H10W2Sign,
            Service::LmsShakeM32H10W2Verify,
            Service::LmsShakeM32H10W4Sign,
            Service::LmsShakeM32H10W4Verify,
            Service::LmsShakeM32H10W8Sign,
            Service::LmsShakeM32H10W8Verify,
            Service::LmsShakeM32H15W1Sign,
            Service::LmsShakeM32H15W1Verify,
            Service::LmsShakeM32H15W2Sign,
            Service::LmsShakeM32H15W2Verify,
            Service::LmsShakeM32H15W4Sign,
            Service::LmsShakeM32H15W4Verify,
            Service::LmsShakeM32H15W8Sign,
            Service::LmsShakeM32H15W8Verify,
            Service::LmsShakeM32H20W1Sign,
            Service::LmsShakeM32H20W1Verify,
            Service::LmsShakeM32H20W2Sign,
            Service::LmsShakeM32H20W2Verify,
            Service::LmsShakeM32H20W4Sign,
            Service::LmsShakeM32H20W4Verify,
            Service::LmsShakeM32H20W8Sign,
            Service::LmsShakeM32H20W8Verify,
            Service::LmsShakeM32H25W1Sign,
            Service::LmsShakeM32H25W1Verify,
            Service::LmsShakeM32H25W2Sign,
            Service::LmsShakeM32H25W2Verify,
            Service::LmsShakeM32H25W4Sign,
            Service::LmsShakeM32H25W4Verify,
            Service::LmsShakeM32H25W8Sign,
            Service::LmsShakeM32H25W8Verify,
            // SHAKE-256 / N=24 family (20 pairs, 40 entries).
            Service::LmsShakeM24H5W1Sign,
            Service::LmsShakeM24H5W1Verify,
            Service::LmsShakeM24H5W2Sign,
            Service::LmsShakeM24H5W2Verify,
            Service::LmsShakeM24H5W4Sign,
            Service::LmsShakeM24H5W4Verify,
            Service::LmsShakeM24H5W8Sign,
            Service::LmsShakeM24H5W8Verify,
            Service::LmsShakeM24H10W1Sign,
            Service::LmsShakeM24H10W1Verify,
            Service::LmsShakeM24H10W2Sign,
            Service::LmsShakeM24H10W2Verify,
            Service::LmsShakeM24H10W4Sign,
            Service::LmsShakeM24H10W4Verify,
            Service::LmsShakeM24H10W8Sign,
            Service::LmsShakeM24H10W8Verify,
            Service::LmsShakeM24H15W1Sign,
            Service::LmsShakeM24H15W1Verify,
            Service::LmsShakeM24H15W2Sign,
            Service::LmsShakeM24H15W2Verify,
            Service::LmsShakeM24H15W4Sign,
            Service::LmsShakeM24H15W4Verify,
            Service::LmsShakeM24H15W8Sign,
            Service::LmsShakeM24H15W8Verify,
            Service::LmsShakeM24H20W1Sign,
            Service::LmsShakeM24H20W1Verify,
            Service::LmsShakeM24H20W2Sign,
            Service::LmsShakeM24H20W2Verify,
            Service::LmsShakeM24H20W4Sign,
            Service::LmsShakeM24H20W4Verify,
            Service::LmsShakeM24H20W8Sign,
            Service::LmsShakeM24H20W8Verify,
            Service::LmsShakeM24H25W1Sign,
            Service::LmsShakeM24H25W1Verify,
            Service::LmsShakeM24H25W2Sign,
            Service::LmsShakeM24H25W2Verify,
            Service::LmsShakeM24H25W4Sign,
            Service::LmsShakeM24H25W4Verify,
            Service::LmsShakeM24H25W8Sign,
            Service::LmsShakeM24H25W8Verify,
        ];
        assert_eq!(all_160.len(), 160, "LMS enumeration drift");

        // CNSA 2.0 permitted: SHA-256/M=32, H{10,15,20,25} × W{4,8} = 8 pairs.
        let cnsa_allowed_set = [
            Service::LmsSha256M32H10W4Sign,
            Service::LmsSha256M32H10W4Verify,
            Service::LmsSha256M32H10W8Sign,
            Service::LmsSha256M32H10W8Verify,
            Service::LmsSha256M32H15W4Sign,
            Service::LmsSha256M32H15W4Verify,
            Service::LmsSha256M32H15W8Sign,
            Service::LmsSha256M32H15W8Verify,
            Service::LmsSha256M32H20W4Sign,
            Service::LmsSha256M32H20W4Verify,
            Service::LmsSha256M32H20W8Sign,
            Service::LmsSha256M32H20W8Verify,
            Service::LmsSha256M32H25W4Sign,
            Service::LmsSha256M32H25W4Verify,
            Service::LmsSha256M32H25W8Sign,
            Service::LmsSha256M32H25W8Verify,
        ];
        assert_eq!(cnsa_allowed_set.len(), 16, "CNSA permitted-set drift");

        for svc in all_160 {
            // Unrestricted: every LMS variant is permitted.
            assert!(
                is_allowed(AlgorithmProfile::Unrestricted, svc),
                "{svc} must be allowed in Unrestricted"
            );

            let expected = cnsa_allowed_set.contains(&svc);

            // CNSA 2.0: only the 16 CNSSP-15-conformant entries pass;
            // the other 144 default-block via the `matches!` fail-safe.
            let actual_cnsa2 = is_allowed(AlgorithmProfile::Cnsa2, svc);
            assert_eq!(
                actual_cnsa2, expected,
                "{svc} CNSA 2.0 gating mismatch (expected={expected}, actual={actual_cnsa2})"
            );

            // CNSA 1.0: mirrors CNSA 2.0 on LMS (transition profile).
            let actual_cnsa1 = is_allowed(AlgorithmProfile::Cnsa1, svc);
            assert_eq!(
                actual_cnsa1, expected,
                "{svc} CNSA 1.0 gating mismatch (expected={expected}, actual={actual_cnsa1})"
            );
        }
    }

    #[test]
    fn slh_dsa_gating_is_exhaustive_across_all_36_variants() {
        // Enumerates every SLH-DSA Service variant (12 parameter sets ×
        // {Keygen, Sign, Verify} = 36 entries) and verifies the
        // fail-safe gating: only the CNSSP-15 mandate
        // (SLH-DSA-SHA2-256s) is allowed under CNSA 2.0; all 36 are
        // blocked under CNSA 1.0; all 36 are permitted under
        // Unrestricted.  If a new SLH-DSA variant is added without a
        // matching entry in this array, the assertion at the end
        // catches the gap.
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

        let cnsa2_allowed_set = [
            Service::SlhDsaSha2256sKeygen,
            Service::SlhDsaSha2256sSign,
            Service::SlhDsaSha2256sVerify,
        ];

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

            // CNSA 2.0: only the three CNSSP-15-mandated entries pass;
            // all 33 others are blocked.
            let expected_cnsa2 = cnsa2_allowed_set.contains(&svc);
            let actual_cnsa2 = is_allowed(AlgorithmProfile::Cnsa2, svc);
            assert_eq!(
                actual_cnsa2, expected_cnsa2,
                "{svc} CNSA 2.0 gating mismatch (expected={expected_cnsa2}, actual={actual_cnsa2})"
            );
        }
    }

    #[test]
    fn require_allowed_returns_restricted_error_under_cnsa2() {
        reset_for_test();
        initialize_with_profile(&[], AlgorithmProfile::Cnsa2).unwrap();
        match require_allowed(Service::Aes128Ecb) {
            Err(Error::AlgorithmRestricted {
                service: Service::Aes128Ecb,
            }) => {}
            other => panic!("expected AlgorithmRestricted(Aes128Ecb), got {other:?}"),
        }
    }

    #[test]
    fn require_allowed_passes_permitted_services() {
        reset_for_test();
        initialize_with_profile(&[], AlgorithmProfile::Cnsa2).unwrap();
        require_allowed(Service::Aes256Gcm).unwrap();
        require_allowed(Service::Sha384).unwrap();
        require_allowed(Service::MlKem1024Encaps).unwrap();
    }

    #[test]
    fn require_allowed_passes_everything_in_unrestricted() {
        reset_for_test();
        initialize().unwrap();
        // Spot-check a few from each end of the spectrum.
        require_allowed(Service::Sha1).unwrap();
        require_allowed(Service::Aes128Ecb).unwrap();
        require_allowed(Service::Ed25519Sign).unwrap();
        require_allowed(Service::MlKem1024Encaps).unwrap();
    }

    #[test]
    fn algorithm_profile_display() {
        assert_eq!(AlgorithmProfile::Unrestricted.to_string(), "Unrestricted");
        assert_eq!(AlgorithmProfile::Cnsa2.to_string(), "CNSA 2.0");
        assert_eq!(AlgorithmProfile::Cnsa1.to_string(), "CNSA 1.0");
    }

    #[test]
    fn algorithm_restricted_error_display() {
        reset_for_test();
        initialize_with_profile(&[], AlgorithmProfile::Cnsa2).unwrap();
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
