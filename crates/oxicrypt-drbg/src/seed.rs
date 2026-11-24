//! The seed path: where the module's DRBGs draw their entropy input and
//! nonce when the module seeds them itself.
//!
//! The path is decided once per process, inside the first critical section
//! of the process-global seed cell, from the assessed environment table in
//! [`crate::seed_table`]. On the assessed path the jitter pipeline is
//! constructed and started in that same critical section and every later
//! draw reads it under the cell's lock. Any entropy failure enters the
//! module's error state.

use oxicrypt_entropy::health::Alpha;
use oxicrypt_entropy::jitter::{JitterConfig, JitterSource};
use oxicrypt_entropy::pipeline::EntropyPipeline;
use oxicrypt_entropy::source::TimerSource;
use oxicrypt_entropy::timer::{AdequacyConfig, PlatformTimer, TimerError};
use oxicrypt_module::{Error, RbgError, enter_error_state, require_operational};
use oxicrypt_platform::{SpinCell, os_random};

#[cfg(any(test, feature = "fault-injection"))]
use oxicrypt_entropy::error::EntropyError;
#[cfg(any(test, feature = "fault-injection"))]
use oxicrypt_entropy::health::{HealthError, HealthTest};

#[cfg(any(test, feature = "fault-injection"))]
use crate::seam::{self, FaultClass};
use crate::seed_table::{EnvRow, OsReason, Pipeline, ROWS, SeedChoice, SeedState};

/// A source of seed material.
pub(crate) trait SeedSource {
    /// Fills `out` with seed material.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError>;

    /// The source's name.
    #[allow(dead_code, reason = "read only by this crate's tests")]
    fn name(&self) -> &'static str;
}

/// The in-boundary jitter source, read through the process's started
/// pipeline, which the caller holds under the seed cell's lock.
pub(crate) struct AssessedJitter<'a> {
    pub(crate) pipeline: &'a mut Pipeline,
}

/// The operating system's random generator.
pub(crate) struct OperatingSystem;

/// The SP 800-90B source an assessed row draws from. A further source adds
/// a variant and a [`SeedSource`] implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceKind {
    /// The CPU execution-time jitter source in `oxicrypt-entropy`.
    Jitter,
}

/// The size of one conditioned block, in bytes.
const BLOCK_LEN: usize = 32;

/// `$op`'s result, or `Err($simulated)` in its place when a seam fault of
/// `$class` is armed, so the error arm that follows classifies a simulated
/// failure exactly as it classifies a real one.
#[cfg(any(test, feature = "fault-injection"))]
macro_rules! faulted {
    ($class:ident, $simulated:expr, $op:expr) => {
        if seam::take_fault(FaultClass::$class) {
            Err($simulated)
        } else {
            $op
        }
    };
}

/// Without the seams, `$op`'s result unchanged.
#[cfg(not(any(test, feature = "fault-injection")))]
macro_rules! faulted {
    ($class:ident, $simulated:expr, $op:expr) => {
        $op
    };
}

impl SeedSource for AssessedJitter<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
        for chunk in out.chunks_mut(BLOCK_LEN) {
            let block = faulted!(
                ContinuousHealth,
                EntropyError::Health(HealthError::Failed(HealthTest::Rct)),
                self.pipeline.conditioned_block()
            );
            let mut block = block.map_err(|_| entropy_failure())?;
            for (dst, src) in chunk.iter_mut().zip(block.iter()) {
                *dst = *src;
            }
            // Wiping the whole block also wipes the unused tail of the last.
            // Unproven: no test fails when this wipe is removed.
            oxicrypt_zeroize::zeroize(&mut block);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "jitter source"
    }
}

impl SeedSource for OperatingSystem {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
        os_random(out).map_err(|_| entropy_failure())
    }

    fn name(&self) -> &'static str {
        "operating-system generator"
    }
}

/// What the seed path reports about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedPathReport {
    /// `"assessed"` or `"operating-system"`.
    pub path: &'static str,
    /// The label every surface uses for the path, for example
    /// `jitter source, assessed row OE-1`.
    pub label: &'static str,
}

impl SeedPathReport {
    fn of(choice: SeedChoice) -> Self {
        Self {
            path: choice.path(),
            label: choice.label(),
        }
    }
}

/// The process's seed-path state, empty until the first draw decides it.
static SEED: SpinCell<SeedState> = SpinCell::new();

#[cfg(any(test, feature = "fault-injection"))]
pub(crate) fn seed_cell() -> &'static SpinCell<SeedState> {
    &SEED
}

/// Enters the module's error state and reports the entropy failure.
fn entropy_failure() -> RbgError {
    enter_error_state("entropy source");
    RbgError::EntropyUnavailable
}

/// The [`RbgError`] a module refusal maps to.
fn module_error_to_rbg(error: Error) -> RbgError {
    match error {
        Error::Rbg(inner) => inner,
        _ => RbgError::NotOperational,
    }
}

/// Why constructing the assessed pipeline did not succeed.
enum Unstarted {
    /// The timer failed the construction-time adequacy check.
    TimerInadequate,
    /// Any other failure, already classified; an entropy failure has
    /// already entered the error state.
    Failed(RbgError),
}

/// Classifies a timer error from construction.
fn timer_failure(error: TimerError) -> Unstarted {
    match error {
        TimerError::Inadequate { .. } => Unstarted::TimerInadequate,
        // The caller was not admitted, so this is not an entropy failure.
        TimerError::Module(e) => Unstarted::Failed(module_error_to_rbg(e)),
        _ => Unstarted::Failed(entropy_failure()),
    }
}

/// The jitter configuration of the operational seed path.
fn operational_config(timer: TimerSource) -> JitterConfig<'static> {
    JitterConfig {
        adequacy: AdequacyConfig::default(),
        timer_source: Some(timer),
        cpu_model: "operational",
        os: "operational",
        collection_params: "operational",
    }
}

/// Constructs and starts the jitter pipeline for `row`. The source's
/// construction runs the timer-adequacy check, and the constructed source
/// goes straight into the pipeline, so adequacy is measured once.
fn start_jitter(row: &'static EnvRow) -> Result<Pipeline, Unstarted> {
    #[cfg(any(test, feature = "fault-injection"))]
    if seam::timer_inadequate_forced() {
        return Err(Unstarted::TimerInadequate);
    }
    let timer = PlatformTimer::new(row.timer).map_err(timer_failure)?;
    let source = JitterSource::new(timer, operational_config(row.timer)).map_err(timer_failure)?;
    let mut pipeline = EntropyPipeline::new(source, row.claimed_h, Alpha::DEFAULT)
        .map_err(|_| Unstarted::Failed(entropy_failure()))?;
    let startup = faulted!(
        ConditionerKat,
        EntropyError::ConditionerKat,
        faulted!(
            StartupHealth,
            EntropyError::Health(HealthError::Failed(HealthTest::Apt)),
            pipeline.run_startup()
        )
    );
    startup.map_err(|_| Unstarted::Failed(entropy_failure()))?;
    Ok(pipeline)
}

/// Constructs the started pipeline for `row`'s source.
fn start_source(row: &'static EnvRow) -> Result<Pipeline, Unstarted> {
    match row.source {
        crate::seed::SourceKind::Jitter => start_jitter(row),
    }
}

/// The seed state for a target `row` matches.
fn from_row(row: &'static EnvRow) -> Result<SeedState, RbgError> {
    match start_source(row) {
        Ok(pipeline) => Ok(SeedState {
            choice: SeedChoice::Assessed(row),
            pipeline: Some(pipeline),
        }),
        Err(Unstarted::TimerInadequate) => Ok(SeedState {
            choice: SeedChoice::Os(OsReason::TimerInadequate),
            pipeline: None,
        }),
        Err(Unstarted::Failed(e)) => Err(e),
    }
}

/// The first row of `rows` covering `arch` and `os`.
pub(crate) fn select(rows: &'static [EnvRow], arch: &str, os: &str) -> Option<&'static EnvRow> {
    rows.iter().find(|row| row.arch == arch && row.os == os)
}

/// Decides the seed path for a target `arch`/`os` against `rows`.
pub(crate) fn decide(rows: &'static [EnvRow], arch: &str, os: &str) -> Result<SeedState, RbgError> {
    match select(rows, arch, os) {
        Some(row) => from_row(row),
        None => Ok(SeedState {
            choice: SeedChoice::Os(OsReason::NoRow),
            pipeline: None,
        }),
    }
}

/// The running target's `target_arch`, as far as the table needs it.
const fn running_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "other"
    }
}

/// The running target's `target_os`, as far as the table needs it.
const fn running_os() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "other"
    }
}

/// Decides the seed path for the running target and, on the assessed path,
/// constructs and starts its pipeline. Called once per process, inside the
/// seed cell's first critical section.
pub(crate) fn seed_path() -> Result<SeedState, RbgError> {
    #[cfg(any(test, feature = "fault-injection"))]
    let forced = seam::take_forced_choice();
    #[cfg(not(any(test, feature = "fault-injection")))]
    let forced: Option<SeedChoice> = None;

    let state = match forced {
        Some(SeedChoice::Assessed(row)) => from_row(row),
        Some(SeedChoice::Os(reason)) => Ok(SeedState {
            choice: SeedChoice::Os(reason),
            pipeline: None,
        }),
        // The raw counter every row reads exists only on these
        // architectures, so no row can construct elsewhere.
        None if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) => Ok(SeedState {
            choice: SeedChoice::Os(OsReason::NoRow),
            pipeline: None,
        }),
        None => decide(ROWS, running_arch(), running_os()),
    }?;
    #[cfg(any(test, feature = "fault-injection"))]
    seam::count_construction();
    Ok(state)
}

/// The started pipeline of an assessed state, constructed first if none
/// exists.
fn assessed_pipeline<'s>(
    row: &'static EnvRow,
    slot: &'s mut Option<Pipeline>,
) -> Result<&'s mut Pipeline, RbgError> {
    let pipeline = match slot.take() {
        Some(pipeline) => pipeline,
        None => start_source(row).map_err(|unstarted| match unstarted {
            // The path is already decided; a timer that now fails its
            // adequacy check is an entropy failure.
            Unstarted::TimerInadequate => entropy_failure(),
            Unstarted::Failed(e) => e,
        })?,
    };
    Ok(slot.insert(pipeline))
}

/// Fills `out` from the source `state` selected.
fn fill_from(state: &mut SeedState, out: &mut [u8]) -> Result<(), RbgError> {
    match state.choice {
        SeedChoice::Assessed(row) => AssessedJitter {
            pipeline: assessed_pipeline(row, &mut state.pipeline)?,
        }
        .fill(out),
        SeedChoice::Os(_) => OperatingSystem.fill(out),
    }
}

/// Draws `out` from the seed path, deciding the path first if this is the
/// process's first draw. Instantiate and reseed both draw through it. On
/// error `out` is zeroized.
pub(crate) fn get_entropy(out: &mut [u8]) -> Result<(), RbgError> {
    let result = draw(out);
    if result.is_err() {
        oxicrypt_zeroize::zeroize(out);
    }
    result
}

fn draw(out: &mut [u8]) -> Result<(), RbgError> {
    #[cfg(any(test, feature = "fault-injection"))]
    {
        seam::count_draw();
        if let Some(replacement) = seam::installed_draw() {
            return replacement(out);
        }
    }
    let mut guard = SEED.lock().map_err(|_| RbgError::Busy)?;
    let state = match guard.take() {
        Some(state) => state,
        None => seed_path()?,
    };
    fill_from(guard.insert(state), out)
}

/// The label of the decided seed path, or `"undecided"` when no draw has
/// decided it yet or the cell is busy. Never decides the path; a status
/// surface reports it beside a failure code so the caller learns which
/// path the process had taken.
pub fn seed_path_label() -> &'static str {
    SEED.lock().map_or("undecided", |guard| {
        guard
            .as_ref()
            .map_or("undecided", |state| state.choice.label())
    })
}

/// Runs the entropy source's on-demand test on the seed path and reports
/// which path it is.
///
/// On the assessed path this runs the jitter pipeline's SP 800-90B §4.3
/// on-demand health tests, constructing the pipeline first if none exists.
/// On the operating-system path it performs one 32-byte fill. The first
/// call in a process decides the seed path, as the first draw does.
///
/// # Errors
///
/// - [`Error::NotOperational`] when the module is in any state but
///   `Operational`; the entropy source is not touched.
/// - [`Error::Rbg`]`(`[`RbgError::EntropyUnavailable`]`)` when the test or
///   the fill fails. The module has then entered its error state.
/// - [`Error::Rbg`]`(`[`RbgError::Busy`]`)` when the seed path's lock spin
///   bound was exhausted; retry after a pause.
pub fn entropy_on_demand_test() -> Result<SeedPathReport, Error> {
    require_operational()?;
    on_demand().map_err(Error::Rbg)
}

fn on_demand() -> Result<SeedPathReport, RbgError> {
    #[cfg(any(test, feature = "fault-injection"))]
    if seam::take_fault(FaultClass::OnDemand) {
        return Err(entropy_failure());
    }
    let mut guard = SEED.lock().map_err(|_| RbgError::Busy)?;
    let state = match guard.take() {
        Some(state) => state,
        None => seed_path()?,
    };
    let state = guard.insert(state);
    let choice = state.choice;
    match choice {
        SeedChoice::Assessed(row) => assessed_pipeline(row, &mut state.pipeline)?
            .on_demand_test()
            .map_err(|_| entropy_failure())?,
        SeedChoice::Os(_) => {
            let mut block = [0_u8; BLOCK_LEN];
            let result = OperatingSystem.fill(&mut block);
            oxicrypt_zeroize::zeroize(&mut block);
            result?;
        }
    }
    Ok(SeedPathReport::of(choice))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions panic by design"
    )]

    use oxicrypt_entropy::h::MinEntropy;
    use oxicrypt_module::RbgError;

    use super::{
        AssessedJitter, OperatingSystem, SeedSource, SourceKind, decide, get_entropy, select,
        start_source,
    };
    use crate::seam::{self, FaultClass};
    use crate::seed_table::{EnvRow, OsReason, SeedChoice};
    use crate::test_support::serial;

    /// A row no running target names, read by the raw counter.
    static TEST_ROWS: &[EnvRow] = &[EnvRow {
        arch: "test-arch",
        os: "test-os",
        timer: oxicrypt_entropy::source::TimerSource::RawCounter,
        claimed_h: MinEntropy::from_fraction_floor_const(1, 2),
        source: SourceKind::Jitter,
        policy_ref: "TEST-1",
    }];

    fn operational_module() {
        crate::test_support::start_module();
        assert!(oxicrypt_module::is_operational());
    }

    fn assert_not_all_zero(out: &[u8]) {
        assert!(out.iter().any(|&b| b != 0), "seed output is all zero");
    }

    #[test]
    fn seed_path_selection() {
        let _serial = serial();
        seam::clear_all();

        assert!(select(TEST_ROWS, "test-arch", "other-os").is_none());
        let state = decide(TEST_ROWS, "test-arch", "other-os").unwrap();
        assert!(matches!(state.choice, SeedChoice::Os(OsReason::NoRow)));
        assert!(state.pipeline.is_none());

        seam::force_timer_inadequate(true);
        let state = decide(TEST_ROWS, "test-arch", "test-os").unwrap();
        seam::force_timer_inadequate(false);
        assert!(matches!(
            state.choice,
            SeedChoice::Os(OsReason::TimerInadequate)
        ));
        assert!(state.pipeline.is_none());

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            operational_module();
            let state = decide(TEST_ROWS, "test-arch", "test-os").unwrap();
            assert!(
                matches!(state.choice, SeedChoice::Assessed(row) if row.policy_ref == "TEST-1")
            );
            assert!(state.pipeline.is_some_and(|p| p.is_operational()));
            assert!(oxicrypt_module::is_operational());
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn seed_source_assessed_jitter_fills() {
        let _serial = serial();
        seam::clear_all();
        operational_module();
        let row = TEST_ROWS.first().unwrap();
        let Ok(mut pipeline) = start_source(row) else {
            panic!("the jitter pipeline did not start");
        };
        let mut source = AssessedJitter {
            pipeline: &mut pipeline,
        };
        assert_eq!(source.name(), "jitter source");
        let mut out = [0_u8; 48];
        assert_eq!(source.fill(&mut out), Ok(()));
        assert_not_all_zero(&out);
    }

    #[test]
    fn seed_source_operating_system_fills() {
        let _serial = serial();
        seam::clear_all();
        let mut source = OperatingSystem;
        assert_eq!(source.name(), "operating-system generator");
        let mut out = [0_u8; 48];
        assert_eq!(source.fill(&mut out), Ok(()));
        assert_not_all_zero(&out);
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the signature is the seam's draw type"
    )]
    fn fixed_fill(out: &mut [u8]) -> Result<(), RbgError> {
        out.fill(0x5A);
        Ok(())
    }

    #[test]
    fn get_entropy_zeroizes_unused_tail() {
        let _serial = serial();
        seam::clear_all();
        seam::force_seed_choice(SeedChoice::Os(OsReason::NoRow));
        let mut out = [0_u8; 40];
        assert_eq!(get_entropy(&mut out), Ok(()));
        assert_not_all_zero(&out);
        assert_eq!(seam::construction_count(), 1);

        seam::set_get_entropy(fixed_fill);
        let before = seam::draw_count();
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        assert_eq!(get_entropy(&mut first), Ok(()));
        assert_eq!(get_entropy(&mut second), Ok(()));
        assert_eq!(seam::draw_count(), before + 2);
        assert_eq!(first, [0x5A; 32]);
        seam::clear_all();
    }

    #[test]
    fn fixed_stream_seam_serves_then_refuses() {
        let _serial = serial();
        seam::clear_all();
        seam::arm_from_env(Some("seed-stream=000102030405060708090a0b0c0d0e0f")).unwrap();
        let mut out = [0_u8; 10];
        assert_eq!(get_entropy(&mut out), Ok(()));
        assert_eq!(out, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(get_entropy(&mut out), Err(RbgError::RequestTooLong));
        assert_eq!(out, [0; 10]);
        assert_eq!(
            seam::arm_from_env(Some("seed-stream=0")),
            Err(seam::ArmError::BadHex)
        );
        assert_eq!(
            seam::arm_from_env(Some("no-such-seam")),
            Err(seam::ArmError::UnknownSeam)
        );
        seam::clear_all();
    }

    #[test]
    fn draw_is_busy_while_seed_cell_held() {
        let _serial = serial();
        seam::clear_all();
        let held = seam::hold_lock();
        let result = std::thread::spawn(|| {
            let mut out = [0_u8; 32];
            get_entropy(&mut out)
        })
        .join()
        .unwrap();
        drop(held);
        assert_eq!(result, Err(RbgError::Busy));
    }

    #[test]
    fn fault_arm_is_consumed_once() {
        let _serial = serial();
        seam::clear_all();
        seam::fail_next(FaultClass::SecondDraw);
        assert!(seam::take_fault(FaultClass::SecondDraw));
        assert!(!seam::take_fault(FaultClass::SecondDraw));
        assert!(!seam::take_fault(FaultClass::OsGenerator));
    }
}
