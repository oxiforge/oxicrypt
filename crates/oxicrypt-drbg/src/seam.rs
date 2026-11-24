//! Test seams for the seed path, compiled only with the `fault-injection`
//! feature or in this crate's own tests.
//!
//! Every seam is process-global. Flags and counters live in atomics; the
//! installed draw, the forced seed choice and the fixed stream each live
//! in a [`SpinCell`] of their own. With no seam armed, the seed path takes
//! its production branch unchanged.
//!
//! An armed fault is checked where the real failure of its class is
//! classified, takes the branch that failure takes (the module enters its
//! error state and the draw returns [`RbgError::EntropyUnavailable`]), and
//! is consumed:
//!
//! - [`FaultClass::StartupHealth`]: after the pipeline's startup tests.
//! - [`FaultClass::ConditionerKat`]: after the pipeline is constructed.
//! - [`FaultClass::ContinuousHealth`]: before the next conditioned block.
//! - [`FaultClass::OnDemand`]: in [`crate::entropy_on_demand_test`].
//! - [`FaultClass::OsGenerator`]: in the operating-system fill.
//! - [`FaultClass::SecondDraw`]: at the second draw of an instantiate.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use oxicrypt_module::RbgError;
use oxicrypt_platform::{SpinCell, SpinGuard};

use crate::seed;
use crate::seed_table::{OsReason, ROWS, SeedChoice, SeedState};

/// A replacement for the seed path's draw.
pub type DrawFn = fn(&mut [u8]) -> Result<(), RbgError>;

/// A class of entropy failure [`fail_next`] can simulate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultClass {
    /// The pipeline's startup health tests fail.
    StartupHealth,
    /// The pipeline's conditioning known-answer test fails.
    ConditionerKat,
    /// A continuous health test fails while a block is drawn.
    ContinuousHealth,
    /// The on-demand test fails.
    OnDemand,
    /// The operating system's generator fails.
    OsGenerator,
    /// The second draw of an instantiate fails.
    SecondDraw,
}

impl FaultClass {
    const fn bit(self) -> u8 {
        match self {
            Self::StartupHealth => 1 << 0,
            Self::ConditionerKat => 1 << 1,
            Self::ContinuousHealth => 1 << 2,
            Self::OnDemand => 1 << 3,
            Self::OsGenerator => 1 << 4,
            Self::SecondDraw => 1 << 5,
        }
    }
}

/// Why [`arm_from_env`] refused its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmError {
    /// A comma-separated entry names no seam.
    UnknownSeam,
    /// The `seed-stream=` value is not an even-length hex string.
    BadHex,
    /// The `seed-stream=` value is longer than [`STREAM_CAPACITY`] bytes.
    StreamTooLong,
}

/// The longest stream `seed-stream=<hex>` can install, in bytes.
pub const STREAM_CAPACITY: usize = 4096;

/// The number of spins a parked service makes before it proceeds anyway.
const PARK_BOUND: u64 = 1 << 32;

static DRAWS: AtomicU64 = AtomicU64::new(0);
static CONSTRUCTIONS: AtomicU64 = AtomicU64::new(0);
static FAULTS: AtomicU8 = AtomicU8::new(0);
static TIMER_INADEQUATE: AtomicBool = AtomicBool::new(false);
static PARK_ARMED: AtomicBool = AtomicBool::new(false);
static PARKED: AtomicBool = AtomicBool::new(false);
static CORRUPT_NEXT_KEY: AtomicBool = AtomicBool::new(false);
static SLOW_WRITE: AtomicBool = AtomicBool::new(false);

static DRAW: SpinCell<DrawFn> = SpinCell::new();
static FORCED: SpinCell<SeedChoice> = SpinCell::new();

/// The bytes a `seed-stream=<hex>` draw serves, and how many it has served.
struct Stream {
    bytes: [u8; STREAM_CAPACITY],
    len: usize,
    pos: usize,
}

static STREAM: SpinCell<Stream> = SpinCell::new();

/// Locks a seam cell, retrying while it is busy.
fn locked<T>(cell: &'static SpinCell<T>) -> SpinGuard<'static, T> {
    loop {
        if let Ok(guard) = cell.lock() {
            return guard;
        }
        core::hint::spin_loop();
    }
}

/// Resets every seam, empties the seed-path cell so the next draw decides
/// the path again, and zeroes the counters. Tests call it first.
pub fn clear_all() {
    *locked(&DRAW) = None;
    *locked(&FORCED) = None;
    *locked(&STREAM) = None;
    FAULTS.store(0, Ordering::SeqCst);
    TIMER_INADEQUATE.store(false, Ordering::SeqCst);
    PARK_ARMED.store(false, Ordering::SeqCst);
    PARKED.store(false, Ordering::SeqCst);
    CORRUPT_NEXT_KEY.store(false, Ordering::SeqCst);
    SLOW_WRITE.store(false, Ordering::SeqCst);
    *locked(seed::seed_cell()) = None;
    DRAWS.store(0, Ordering::SeqCst);
    CONSTRUCTIONS.store(0, Ordering::SeqCst);
}

/// Replaces the seed path's draw with `draw` until [`clear_all`].
pub fn set_get_entropy(draw: DrawFn) {
    *locked(&DRAW) = Some(draw);
}

/// Removes the draw [`set_get_entropy`] installed, so draws take the seed
/// path again.
pub fn clear_get_entropy() {
    *locked(&DRAW) = None;
}

/// The installed replacement draw, if any.
pub(crate) fn installed_draw() -> Option<DrawFn> {
    *locked(&DRAW)
}

/// The number of seed-path draws made, replaced or not.
pub fn draw_count() -> u64 {
    DRAWS.load(Ordering::SeqCst)
}

pub(crate) fn count_draw() {
    DRAWS.fetch_add(1, Ordering::SeqCst);
}

/// The number of seed-path states constructed, whichever path they chose.
pub fn construction_count() -> u64 {
    CONSTRUCTIONS.load(Ordering::SeqCst)
}

pub(crate) fn count_construction() {
    CONSTRUCTIONS.fetch_add(1, Ordering::SeqCst);
}

/// Makes the next seed-path decision `choice`, consumed when it is made.
pub(crate) fn force_seed_choice(choice: SeedChoice) {
    *locked(&FORCED) = Some(choice);
}

/// Makes the next seed-path decision the operating system's generator, as
/// on a target no assessed row matches.
pub fn force_operating_system_path() {
    force_seed_choice(SeedChoice::Os(OsReason::NoRow));
}

/// Makes the next seed-path decision the assessed path under the first
/// assessed row, independent of the running target's own match and timer.
pub fn force_assessed_path() {
    if let Some(row) = ROWS.first() {
        force_seed_choice(SeedChoice::Assessed(row));
    }
}

pub(crate) fn take_forced_choice() -> Option<SeedChoice> {
    locked(&FORCED).take()
}

/// While `true`, a matching row's timer is treated as failing the
/// adequacy check.
pub fn force_timer_inadequate(on: bool) {
    TIMER_INADEQUATE.store(on, Ordering::SeqCst);
}

pub(crate) fn timer_inadequate_forced() -> bool {
    TIMER_INADEQUATE.load(Ordering::SeqCst)
}

/// A hold on the seed-path cell, returned by [`hold_seed_cell`]; dropping
/// it releases the cell.
pub struct HeldSeedCell {
    _guard: SpinGuard<'static, SeedState>,
}

/// Holds the seed-path cell, so that another thread's draw spins and then
/// returns [`RbgError::Busy`].
pub fn hold_seed_cell() -> HeldSeedCell {
    HeldSeedCell {
        _guard: locked(seed::seed_cell()),
    }
}

/// [`hold_seed_cell`], under the name this crate's own tests use.
#[cfg(test)]
pub(crate) fn hold_lock() -> HeldSeedCell {
    hold_seed_cell()
}

/// Arms one failure of `class`, consumed by the next point that checks it.
pub fn fail_next(class: FaultClass) {
    FAULTS.fetch_or(class.bit(), Ordering::SeqCst);
}

/// Consumes an armed failure of `class`, returning whether it was armed.
pub(crate) fn take_fault(class: FaultClass) -> bool {
    FAULTS.fetch_and(!class.bit(), Ordering::SeqCst) & class.bit() != 0
}

/// Consumes an armed [`FaultClass::SecondDraw`] failure.
#[allow(
    dead_code,
    reason = "called by the per-type instantiate path at its second draw"
)]
pub(crate) fn take_second_draw_fault() -> bool {
    take_fault(FaultClass::SecondDraw)
}

/// Poisons the seed path: arms [`FaultClass::StartupHealth`] and draws, so
/// a pipeline constructed by that draw fails its startup tests. Returns the
/// draw's result.
pub fn poison_pipeline() -> Result<(), RbgError> {
    fail_next(FaultClass::StartupHealth);
    let mut out = [0_u8; 32];
    let result = seed::get_entropy(&mut out);
    oxicrypt_zeroize::zeroize(&mut out);
    result
}

/// Draws `out` through the seed path, as instantiate and reseed do.
pub fn draw(out: &mut [u8]) -> Result<(), RbgError> {
    seed::get_entropy(out)
}

/// While `true`, the next service to reach its output re-check parks there
/// until [`release_parked`].
pub fn park_before_output(on: bool) {
    PARK_ARMED.store(on, Ordering::SeqCst);
}

/// Releases a service parked at its output re-check.
pub fn release_parked() {
    PARK_ARMED.store(false, Ordering::SeqCst);
    PARKED.store(false, Ordering::SeqCst);
}

/// Whether a service is parked at its output re-check.
pub fn is_parked() -> bool {
    PARKED.load(Ordering::SeqCst)
}

/// The output re-check point: parks while [`park_before_output`] is armed,
/// for at most a large spin bound, then proceeds.
#[allow(dead_code, reason = "called by `generate` at its output re-check")]
pub(crate) fn output_checkpoint() {
    if !PARK_ARMED.swap(false, Ordering::SeqCst) {
        return;
    }
    PARKED.store(true, Ordering::SeqCst);
    let mut spins: u64 = 0;
    while PARKED.load(Ordering::SeqCst) && spins < PARK_BOUND {
        core::hint::spin_loop();
        spins = spins.saturating_add(1);
    }
    PARKED.store(false, Ordering::SeqCst);
}

/// Whether `corrupt-next-key` was armed through [`arm_from_env`].
pub fn corrupt_next_key_armed() -> bool {
    CORRUPT_NEXT_KEY.load(Ordering::SeqCst)
}

/// Whether `slow-write` was armed through [`arm_from_env`].
pub fn slow_write_armed() -> bool {
    SLOW_WRITE.load(Ordering::SeqCst)
}

/// Arms the seams named in the value of the `OXI_FAULT` environment
/// variable, which a binary with `std` reads and passes in.
///
/// The value is a comma-separated list of:
///
/// - `seed-stream=<hex>`: the seed path serves the hex bytes in order and
///   returns [`RbgError::RequestTooLong`] once they are exhausted.
/// - `poison-entropy`: [`poison_pipeline`].
/// - `corrupt-next-key`: sets [`corrupt_next_key_armed`].
/// - `slow-write`: sets [`slow_write_armed`].
///
/// `None` and an empty value arm nothing.
///
/// # Errors
///
/// An [`ArmError`] for the first entry that cannot be armed; entries
/// before it stay armed.
pub fn arm_from_env(value: Option<&str>) -> Result<(), ArmError> {
    let Some(value) = value else {
        return Ok(());
    };
    for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Some(hex) = entry.strip_prefix("seed-stream=") {
            install_stream(hex)?;
        } else {
            match entry {
                "poison-entropy" => {
                    // The draw's failure is the armed effect.
                    let _ = poison_pipeline();
                }
                "corrupt-next-key" => CORRUPT_NEXT_KEY.store(true, Ordering::SeqCst),
                "slow-write" => SLOW_WRITE.store(true, Ordering::SeqCst),
                _ => return Err(ArmError::UnknownSeam),
            }
        }
    }
    Ok(())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

fn install_stream(hex: &str) -> Result<(), ArmError> {
    let (pairs, odd) = hex.as_bytes().as_chunks::<2>();
    if !odd.is_empty() {
        return Err(ArmError::BadHex);
    }
    if pairs.len() > STREAM_CAPACITY {
        return Err(ArmError::StreamTooLong);
    }
    let mut stream = Stream {
        bytes: [0; STREAM_CAPACITY],
        len: pairs.len(),
        pos: 0,
    };
    for (slot, &[hi, lo]) in stream.bytes.iter_mut().zip(pairs) {
        let (Some(hi), Some(lo)) = (hex_digit(hi), hex_digit(lo)) else {
            return Err(ArmError::BadHex);
        };
        *slot = (hi << 4) | lo;
    }
    *locked(&STREAM) = Some(stream);
    set_get_entropy(stream_draw);
    Ok(())
}

/// Serves the installed stream in order, refusing a request it cannot
/// serve in full.
fn stream_draw(out: &mut [u8]) -> Result<(), RbgError> {
    let mut guard = locked(&STREAM);
    let served = guard.as_mut().and_then(|stream| {
        let end = stream.pos.checked_add(out.len())?;
        let source = stream.bytes.get(stream.pos..end.min(stream.len))?;
        if source.len() != out.len() {
            return None;
        }
        out.copy_from_slice(source);
        stream.pos = end;
        Some(())
    });
    served.ok_or_else(|| {
        oxicrypt_zeroize::zeroize(out);
        RbgError::RequestTooLong
    })
}
