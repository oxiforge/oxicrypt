//! C ABI for the shared DRBG handle: one opaque type, `OxiDrbg`, for all
//! nine SP 800-90A DRBGs, seeded from the module's own seed path.
//!
//! A handle is constructed by one of the nine `_new_rbg` functions, which
//! fixes its DRBG for its lifetime, and is then driven through the shared
//! `oxi_drbg_*` functions. The caller supplies no entropy: instantiate,
//! reseed and the automatic reseed at the SP 800-90A interval all draw from
//! the module's seed path.
//!
//! # Check order
//!
//! Every operation on a handle checks, in order, and returns the first
//! failure:
//!
//! 1. A required pointer that is NULL returns `NullPointer = 10`. An
//!    optional pointer that is NULL with a non-zero length, a length above
//!    `isize::MAX`, or a caller range that overlaps an output or the handle
//!    returns `InvalidInput = 5`.
//! 2. A module that is not operational returns `NotOperational = 1`.
//! 3. A DRBG the active profile does not allow returns
//!    `AlgorithmRestricted = 6`.
//! 4. A handle inherited from another process returns `InvalidInput = 5`,
//!    except from `oxi_drbg_instantiate`, which takes such a handle over
//!    and instantiates it afresh. A handle is inherited when it was
//!    instantiated by another process, or when a thread of another process
//!    held it at the fork, whether or not it was ever instantiated.
//! 5. A handle in use by another call of this process, or being taken over
//!    by another thread, returns `Busy = 32`. A hold by a thread of another
//!    process, inherited across fork, is never `Busy`: it is step 4, and
//!    `oxi_drbg_instantiate` recovers the handle in every case.
//! 6. An input the DRBG would refuse returns `InvalidInput = 5`.
//! 7. The operation itself returns the DRBG's own codes:
//!    `Uninstantiated = 8`, `OutputTooLong = 12`, `Busy = 32` (the seed path
//!    was held too long) or `EntropyUnavailable = 33`. A handle seeded by
//!    the module reseeds itself, so `ReseedRequired = 9` never occurs.
//!
//! Outputs are written only on success.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int};
use core::sync::atomic::{AtomicU64, Ordering};
use std::alloc::{Layout, alloc, dealloc};

use oxicrypt_drbg::{
    Aes128Factory, Aes192Factory, Aes256Factory, CipherFactory, CtrDrbgAes128, CtrDrbgAes192,
    CtrDrbgAes256, DrbgError, HashAlg, HashDrbgSha256, HashDrbgSha384, HashDrbgSha512, HmacAlg,
    HmacDrbgSha256, HmacDrbgSha384, HmacDrbgSha512, HmacSha256Alg, HmacSha384Alg, HmacSha512Alg,
    Sha256Alg, Sha384Alg, Sha512Alg,
};
use oxicrypt_module::{Error, Rbg, RbgError, Service};

use crate::error::OxiResult as R;

/// The largest request, in bytes, any of the nine DRBGs serves in one
/// generate call (SP 800-90A Rev. 1 Tables 2 and 3, `max_number_of_bits_per_request`
/// of 2^19 bits).
pub(crate) const MAX_REQUEST_BYTES: usize = 1 << 16;

macro_rules! drbg_kinds {
    ($($variant:ident($ty:ident, $alg:ident, $generate:ident)),* $(,)?) => {
        /// The DRBG an [`OxiDrbg`] holds. The variant is fixed when the
        /// handle is constructed; every operation dispatches on it.
        pub(crate) enum DrbgKind {
            $($variant($ty),)*
        }

        impl DrbgKind {
            /// The service the active profile is checked against.
            fn service(&self) -> Service {
                match self {
                    $(Self::$variant(_) => $alg::DRBG_SERVICE,)*
                }
            }

            /// The longest additional input the DRBG accepts from a module
            /// reseed, which bounds generate's additional input too.
            fn max_additional_input(&self) -> usize {
                match self {
                    $(Self::$variant(_) => $ty::MAX_MODULE_ADDITIONAL_INPUT,)*
                }
            }

            /// Instantiates from the module's seed path and replaces the
            /// held DRBG. On failure the held DRBG is unchanged.
            fn instantiate(&mut self, personalization: &[u8]) -> Result<(), Error> {
                match self {
                    $(Self::$variant(d) => *d = $ty::instantiate_from_module(personalization)?,)*
                }
                Ok(())
            }

            /// Replaces the held DRBG with an uninstantiated one, so a
            /// generate afterwards returns `Uninstantiated = 8`.
            fn reset(&mut self) {
                match self {
                    $(Self::$variant(d) => *d = $ty::new(),)*
                }
            }

            /// Reseeds from the module's seed path.
            fn reseed(&mut self, additional_input: &[u8]) -> Result<(), Error> {
                match self {
                    $(Self::$variant(d) => d.reseed_from_module(additional_input),)*
                }
            }

            /// Generates into `out`; CTR_DRBG uses its derivation function.
            fn generate(
                &mut self,
                additional_input: Option<&[u8]>,
                out: &mut [u8],
            ) -> Result<(), DrbgError> {
                match self {
                    $(Self::$variant(d) => d.$generate(additional_input, out),)*
                }
            }
        }

        impl Rbg for DrbgKind {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
                match self {
                    $(Self::$variant(d) => d.fill(out),)*
                }
            }

            fn strength_bits(&self) -> u32 {
                match self {
                    $(Self::$variant(d) => d.strength_bits(),)*
                }
            }
        }
    };
}

drbg_kinds!(
    HmacSha256(HmacDrbgSha256, HmacSha256Alg, generate),
    HmacSha384(HmacDrbgSha384, HmacSha384Alg, generate),
    HmacSha512(HmacDrbgSha512, HmacSha512Alg, generate),
    HashSha256(HashDrbgSha256, Sha256Alg, generate),
    HashSha384(HashDrbgSha384, Sha384Alg, generate),
    HashSha512(HashDrbgSha512, Sha512Alg, generate),
    CtrAes128(CtrDrbgAes128, Aes128Factory, generate_df),
    CtrAes192(CtrDrbgAes192, Aes192Factory, generate_df),
    CtrAes256(CtrDrbgAes256, Aes256Factory, generate_df),
);

/// Opaque handle to one of the nine SP 800-90A DRBGs, seeded by the module.
///
/// After fork, the child inherits a copy of every handle. The copy is refused in the child with
/// `InvalidInput = 5` until the child either constructs a new handle or re-instantiates the
/// inherited one with `oxi_drbg_instantiate`, so parent and child never produce the same output.
/// One thread of the child takes the inherited handle over; another thread calling on it
/// meanwhile receives `Busy = 32`. If the re-instantiation fails, the handle holds no state
/// from the parent and returns `Uninstantiated = 8` until it is instantiated. The check
/// compares the caller's process id with the one recorded at instantiation and with the one
/// recorded by the call holding the handle, so a handle a parent thread was instantiating
/// for the first time at the fork is inherited too. A process id reused after the parent
/// exits is not detected.
///
/// A call that finds the handle in use by another call of this process returns `Busy = 32` and
/// changes nothing: retry after a pause. A hold inherited from a thread of the parent is not
/// `Busy`: `oxi_drbg_instantiate` takes the handle over in every case. Calls on one handle from
/// several threads are otherwise safe.
///
/// Calling `oxi_drbg_free` on a handle another thread is using is undefined behaviour, as for
/// every handle.
///
/// cbindgen:opaque
pub struct OxiDrbg {
    /// 0 while no call holds the handle, otherwise the id of the process
    /// whose call holds it. One compare-exchange from 0 takes the hold, so
    /// a fork at any instant leaves the child either a free handle or one
    /// held by the parent's id, which `oxi_drbg_instantiate` takes over. A
    /// value other than 0 and the caller's own process id means the holder
    /// is a thread of another process and the handle was inherited across
    /// fork.
    pub(crate) holder: AtomicU64,
    /// The process that instantiated the handle, or 0 if it never was, or
    /// [`RESETTING`] combined with the id of the process whose thread is
    /// taking over a handle inherited across fork.
    pub(crate) pid: AtomicU64,
    /// The held DRBG's service, fixed at construction so the profile check
    /// runs before the handle is held.
    service: Service,
    /// The held DRBG, reached only by the call that holds `holder`.
    inner: UnsafeCell<Option<DrbgKind>>,
}

/// A hold on a handle, released when dropped.
struct Held<'a> {
    drbg: &'a OxiDrbg,
}

impl Held<'_> {
    /// The held DRBG. The reference lives no longer than this hold.
    fn kind(&mut self) -> Result<&mut DrbgKind, R> {
        // SAFETY: this hold was taken by a successful compare-exchange,
        // either of `holder` from 0 or, on a take-over, of `pid` or of a
        // foreign `holder`, so no other reference into `inner` exists until
        // it is dropped, and the returned borrow is tied to `&mut self`.
        unsafe { &mut *self.drbg.inner.get() }
            .as_mut()
            .ok_or(R::Internal)
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.drbg.holder.store(0, Ordering::Release);
    }
}

/// Takes the hold on a free handle for this process, or returns `Busy` when
/// another call has it.
fn acquire(drbg: &OxiDrbg) -> Result<Held<'_>, R> {
    drbg.holder
        .compare_exchange(0, current_process(), Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| R::Busy)?;
    Ok(Held { drbg })
}

/// Whether a thread of another process holds the handle: the hold was taken
/// before a fork and the holder does not exist in this process.
fn held_by_other_process(drbg: &OxiDrbg, current: u64) -> bool {
    let holder = drbg.holder.load(Ordering::Acquire);
    holder != 0 && holder != current
}

/// The calling process's id as a handle records it. It is never 0, so a
/// recorded 0 always means the handle was never instantiated, including on
/// a target without process ids.
pub(crate) fn current_process() -> u64 {
    oxicrypt_platform::process_id().max(1)
}

/// The bit a handle's recorded process id carries while a thread of that
/// process takes over a handle inherited across fork. Process ids are far
/// below it, so the combined value never equals an id.
const RESETTING: u64 = 1 << 63;

/// Steps 2 to 5 of the check order: the module state, the profile, the
/// process id and the hold.
fn enter(drbg: &OxiDrbg) -> Result<Held<'_>, R> {
    oxicrypt_module::require_operational().map_err(R::from)?;
    oxicrypt_module::require_allowed(drbg.service).map_err(R::from)?;
    let current = current_process();
    let recorded = drbg.pid.load(Ordering::Acquire);
    if recorded == RESETTING | current {
        return Err(R::Busy);
    }
    if (recorded != 0 && recorded != current) || held_by_other_process(drbg, current) {
        return Err(R::InvalidInput);
    }
    acquire(drbg)
}

/// Runs `f` on the DRBG a handle holds, for a service that draws from a
/// caller's handle, after steps 2 to 5 of the check order as
/// `oxi_drbg_generate` performs them. The hold is released when `f`
/// returns.
///
/// # Safety
///
/// `h` must be a non-NULL live handle from a `_new_rbg` function.
pub(crate) unsafe fn with_held<T>(
    h: *mut OxiDrbg,
    f: impl FnOnce(&mut DrbgKind) -> T,
) -> Result<T, R> {
    // SAFETY: `h` is a live handle by contract; only atomics and the
    // `UnsafeCell` are reached through this shared reference.
    let drbg = unsafe { &*h };
    let mut held = enter(drbg)?;
    Ok(f(held.kind()?))
}

/// Takes over a handle inherited across fork, after this thread's
/// compare-and-swap claimed it for this process, either by marking its
/// recorded id [`RESETTING`] or by replacing a holder of another process
/// with this one: records this process as the holder in place of any
/// holder the claim found, which can only be a thread of another process;
/// resets the parent's DRBG instance, so a generate afterwards returns
/// `Uninstantiated = 8`; and records the handle as never instantiated.
/// Another thread that calls on the handle meanwhile reads the mark or the
/// hold of this process and returns `Busy`.
fn take_over(drbg: &OxiDrbg, current: u64) -> Result<Held<'_>, R> {
    drbg.holder.store(current, Ordering::Release);
    let mut held = Held { drbg };
    let reset = held.kind().map(DrbgKind::reset);
    // Published after the holder, so a thread that reads 0 also reads the
    // handle held.
    drbg.pid.store(0, Ordering::Release);
    reset.map(|()| held)
}

/// Whether `len` exceeds the largest length a Rust slice can have.
fn too_long(len: usize) -> bool {
    len > isize::MAX.unsigned_abs()
}

/// Whether two non-empty address ranges share a byte.
fn overlaps(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let (a, b) = (a.addr(), b.addr());
    a < b.saturating_add(b_len) && b < a.saturating_add(a_len)
}

/// Whether a caller range overlaps the handle's own memory.
fn overlaps_handle(ptr: *const u8, len: usize, drbg: *const OxiDrbg) -> bool {
    overlaps(ptr, len, drbg.cast::<u8>(), size_of::<OxiDrbg>())
}

/// Borrows an optional caller input, which may be NULL only with length 0.
///
/// # Safety
///
/// A non-NULL `ptr` must be valid for reads of `len` bytes for `'a`.
unsafe fn optional_input<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], R> {
    if too_long(len) || (ptr.is_null() && len > 0) {
        return Err(R::InvalidInput);
    }
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: `ptr` is non-NULL here and the caller guarantees it is valid
    // for `len` bytes; `len` is at most `isize::MAX`.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

#[cfg(test)]
thread_local! {
    /// In a unit test, how many further [`write_out`] calls on this thread
    /// succeed before one returns `NotOperational`, as a failed re-check
    /// does; `None` places no refusal. The refusal clears it.
    pub(crate) static WRITES_BEFORE_REFUSAL: core::cell::Cell<Option<u32>> =
        const { core::cell::Cell::new(None) };
}

/// Copies `src` to the caller's buffer at `dst`, after re-checking that the
/// module is operational immediately before the write. A module that
/// entered its error state meanwhile receives nothing: the result is
/// `NotOperational`.
///
/// # Safety
///
/// `dst` must be valid for writes of `src.len()` bytes and must not
/// overlap `src`.
pub(crate) unsafe fn write_out(dst: *mut u8, src: &[u8]) -> Result<(), R> {
    #[cfg(test)]
    if let Some(n) = WRITES_BEFORE_REFUSAL.get() {
        WRITES_BEFORE_REFUSAL.set(n.checked_sub(1));
        if n == 0 {
            return Err(R::NotOperational);
        }
    }
    // Delays the call 250 ms before the re-check when the slow-write seam
    // is armed.
    #[cfg(feature = "fault-injection")]
    if oxicrypt_drbg::seam::slow_write_armed() {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    oxicrypt_module::require_operational_for_output().map_err(R::from)?;
    if !src.is_empty() {
        // SAFETY: the caller guarantees `dst` is valid for `src.len()`
        // bytes and does not overlap `src`.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
    }
    Ok(())
}

#[cfg(feature = "fault-injection")]
static FAIL_NEXT_ALLOC: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether the last allocation `wipe_and_free` released read as all zero
/// after its wipe: 1 yes, 0 no, -1 when none has been released since the
/// last read.
#[cfg(feature = "fault-injection")]
static LAST_FREED_ZERO: core::sync::atomic::AtomicI8 = core::sync::atomic::AtomicI8::new(-1);

/// Makes the next `_new_rbg` call return `Internal` without allocating.
#[cfg(feature = "fault-injection")]
pub(crate) fn fail_next_alloc() {
    FAIL_NEXT_ALLOC.store(true, Ordering::SeqCst);
}

/// 1 when the last allocation `wipe_and_free` released read as all zero
/// after its wipe, 0 when it did not, -1 when none has been released since
/// the last read. Reading clears the record, so each release is observed on
/// its own.
#[cfg(feature = "fault-injection")]
pub(crate) fn last_freed_bytes_zero() -> c_int {
    c_int::from(LAST_FREED_ZERO.swap(-1, Ordering::SeqCst))
}

/// Allocates a handle holding `kind`, uninstantiated, and writes it to `out`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
unsafe fn construct(out: *mut *mut OxiDrbg, kind: DrbgKind) -> c_int {
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    #[cfg(feature = "fault-injection")]
    if FAIL_NEXT_ALLOC.swap(false, Ordering::SeqCst) {
        return R::Internal as c_int;
    }
    let layout = Layout::new::<OxiDrbg>();
    // SAFETY: `OxiDrbg` is not zero-sized, so the layout has a non-zero size.
    let raw = unsafe { alloc(layout) };
    if raw.is_null() {
        return R::Internal as c_int;
    }
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the allocation was made with the layout of `OxiDrbg`"
    )]
    let handle = raw.cast::<OxiDrbg>();
    let drbg = OxiDrbg {
        holder: AtomicU64::new(0),
        pid: AtomicU64::new(0),
        service: kind.service(),
        inner: UnsafeCell::new(Some(kind)),
    };
    // SAFETY: `handle` is a fresh, non-NULL allocation with the size and
    // alignment of `OxiDrbg`; `out` is non-NULL and the caller guarantees it
    // is writable.
    unsafe {
        handle.write(drbg);
        *out = handle;
    }
    R::Ok as c_int
}

/// Construct an uninstantiated handle holding HMAC_DRBG with SHA-256.
///
/// Writes the handle to `*out` and returns `Ok = 0`. The caller owns it and
/// releases it with `oxi_drbg_free`. Instantiate it with
/// `oxi_drbg_instantiate` before generating: until then `oxi_drbg_generate`,
/// `oxi_drbg_reseed` and `oxi_drbg_strength_bits` return
/// `Uninstantiated = 8`.
///
/// Returns `NullPointer = 10` when `out` is NULL, and `Internal = 255`
/// when the allocation fails, leaving `*out` unchanged in both cases.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::HmacSha256(HmacDrbgSha256::new())) }
}

/// Construct an uninstantiated handle holding HMAC_DRBG with SHA-384.
/// Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::HmacSha384(HmacDrbgSha384::new())) }
}

/// Construct an uninstantiated handle holding HMAC_DRBG with SHA-512.
/// Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::HmacSha512(HmacDrbgSha512::new())) }
}

/// Construct an uninstantiated handle holding Hash_DRBG with SHA-256.
/// Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::HashSha256(HashDrbgSha256::new())) }
}

/// Construct an uninstantiated handle holding Hash_DRBG with SHA-384.
/// Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::HashSha384(HashDrbgSha384::new())) }
}

/// Construct an uninstantiated handle holding Hash_DRBG with SHA-512.
/// Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::HashSha512(HashDrbgSha512::new())) }
}

/// Construct an uninstantiated handle holding CTR_DRBG with AES-128 and the
/// derivation function. Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::CtrAes128(CtrDrbgAes128::new())) }
}

/// Construct an uninstantiated handle holding CTR_DRBG with AES-192 and the
/// derivation function. Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::CtrAes192(CtrDrbgAes192::new())) }
}

/// Construct an uninstantiated handle holding CTR_DRBG with AES-256 and the
/// derivation function. Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.
///
/// # Safety
///
/// `out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_new_rbg(out: *mut *mut OxiDrbg) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe { construct(out, DrbgKind::CtrAes256(CtrDrbgAes256::new())) }
}

/// Instantiate the handle's DRBG from the module's seed path, with an
/// optional personalization string, replacing any earlier instantiation.
///
/// `perso` may be NULL when `perso_len` is 0. A personalization string
/// longer than the DRBG accepts returns `InvalidInput = 5` before any draw.
/// A failed draw returns `Busy = 32` (retry after a pause) or
/// `EntropyUnavailable = 33`; the handle keeps its earlier instantiation,
/// except on a take-over (below), where the parent's instance is already
/// reset and the handle is uninstantiated.
///
/// On a handle inherited across fork, this is the call that makes it usable
/// in the child, including a handle a thread of the parent was instantiating
/// for the first time at the fork. Exactly one thread of the child takes the
/// handle over: it takes the hold, which a thread of the parent may have
/// held at the fork, resets the parent's DRBG instance, instantiates afresh
/// and records the child's process id. Every other thread calling on the handle meanwhile
/// returns `Busy = 32`. If that instantiation fails, the handle holds no
/// state from the parent and returns `Uninstantiated = 8` until it is
/// instantiated.
///
/// # Safety
///
/// `h` must be NULL or a live handle from a `_new_rbg` function. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_drbg_instantiate(
    h: *mut OxiDrbg,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    if h.is_null() {
        return R::NullPointer as c_int;
    }
    if overlaps_handle(perso, perso_len, h) {
        return R::InvalidInput as c_int;
    }
    // SAFETY: a non-NULL `perso` is valid for `perso_len` bytes by contract.
    let perso = match unsafe { optional_input(perso, perso_len) } {
        Ok(p) => p,
        Err(e) => return e as c_int,
    };
    // SAFETY: `h` is a live handle by contract; only atomics and the
    // `UnsafeCell` are reached through this shared reference.
    let drbg = unsafe { &*h };
    if let Err(e) = oxicrypt_module::require_operational() {
        return R::from(e) as c_int;
    }
    if let Err(e) = oxicrypt_module::require_allowed(drbg.service) {
        return R::from(e) as c_int;
    }
    let current = current_process();
    let recorded = drbg.pid.load(Ordering::Acquire);
    let held = if recorded == RESETTING | current {
        Err(R::Busy)
    } else if recorded != 0 && recorded != current {
        // Only the thread whose swap succeeds takes the handle over; a
        // failed swap means another thread of this process already has.
        match drbg.pid.compare_exchange(
            recorded,
            RESETTING | current,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => take_over(drbg, current),
            Err(_) => Err(R::Busy),
        }
    } else if let holder @ 1.. = drbg.holder.load(Ordering::Acquire)
        && holder != current
    {
        // A thread of another process held the handle at the fork, before
        // it recorded an id. No thread of this process can hold the handle
        // while the holder is foreign, so the swap that replaces the holder
        // claims the hold, and only one thread's swap succeeds.
        match drbg
            .holder
            .compare_exchange(holder, current, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => take_over(drbg, current),
            Err(_) => Err(R::Busy),
        }
    } else {
        acquire(drbg)
    };
    let mut held = match held {
        Ok(held) => held,
        Err(e) => return e as c_int,
    };
    let kind = match held.kind() {
        Ok(kind) => kind,
        Err(e) => return e as c_int,
    };
    match kind.instantiate(perso) {
        Ok(()) => {
            drbg.pid.store(current, Ordering::Release);
            R::Ok as c_int
        }
        Err(e) => R::from(e) as c_int,
    }
}

/// Reseed the handle's DRBG from the module's seed path, with optional
/// additional input.
///
/// `additional` may be NULL when `additional_len` is 0. Additional input
/// longer than the DRBG accepts returns `InvalidInput = 5` before any draw.
/// A failed draw returns `Busy = 32` (retry after a pause) or
/// `EntropyUnavailable = 33`.
///
/// # Safety
///
/// `h` must be NULL or a live handle from a `_new_rbg` function. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_drbg_reseed(
    h: *mut OxiDrbg,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    if h.is_null() {
        return R::NullPointer as c_int;
    }
    if overlaps_handle(additional, additional_len, h) {
        return R::InvalidInput as c_int;
    }
    // SAFETY: a non-NULL `additional` is valid for `additional_len` bytes by
    // contract.
    let additional = match unsafe { optional_input(additional, additional_len) } {
        Ok(a) => a,
        Err(e) => return e as c_int,
    };
    // SAFETY: `h` is a live handle by contract; only atomics and the
    // `UnsafeCell` are reached through this shared reference.
    let drbg = unsafe { &*h };
    let mut held = match enter(drbg) {
        Ok(held) => held,
        Err(e) => return e as c_int,
    };
    let kind = match held.kind() {
        Ok(kind) => kind,
        Err(e) => return e as c_int,
    };
    if additional.len() > kind.max_additional_input() {
        return R::InvalidInput as c_int;
    }
    match kind.reseed(additional) {
        Ok(()) => R::Ok as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Fill `out` with `out_len` bytes from the handle's DRBG, with optional
/// additional input.
///
/// `additional` may be NULL when `additional_len` is 0; additional input
/// longer than the DRBG accepts from a reseed returns `InvalidInput = 5`.
/// A request above 65536 bytes returns `OutputTooLong = 12`. A handle that
/// reaches its reseed interval reseeds itself from the seed path first, and
/// a failed draw then returns `Busy = 32` or `EntropyUnavailable = 33`.
/// `out` is written only on success, and must not overlap `additional`.
///
/// # Safety
///
/// `h` must be NULL or a live handle from a `_new_rbg` function. `out` must
/// be valid for writes of `out_len` bytes. A non-NULL `additional` must be
/// valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_drbg_generate(
    h: *mut OxiDrbg,
    additional: *const u8,
    additional_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if h.is_null() || out.is_null() {
        return R::NullPointer as c_int;
    }
    if too_long(out_len)
        || overlaps(out, out_len, additional, additional_len)
        || overlaps_handle(out, out_len, h)
        || overlaps_handle(additional, additional_len, h)
    {
        return R::InvalidInput as c_int;
    }
    // SAFETY: a non-NULL `additional` is valid for `additional_len` bytes by
    // contract.
    let additional = match unsafe { optional_input(additional, additional_len) } {
        Ok(a) => a,
        Err(e) => return e as c_int,
    };
    // SAFETY: `h` is a live handle by contract; only atomics and the
    // `UnsafeCell` are reached through this shared reference.
    let drbg = unsafe { &*h };
    let mut held = match enter(drbg) {
        Ok(held) => held,
        Err(e) => return e as c_int,
    };
    let kind = match held.kind() {
        Ok(kind) => kind,
        Err(e) => return e as c_int,
    };
    if additional.len() > kind.max_additional_input() {
        return R::InvalidInput as c_int;
    }
    let additional = (!additional.is_empty()).then_some(additional);
    // A request above the largest any DRBG serves is staged at one byte over
    // that bound, so the DRBG returns the code it returns for the request
    // without the full length being allocated.
    let mut staged = vec![0u8; out_len.min(MAX_REQUEST_BYTES.saturating_add(1))];
    let result = kind.generate(additional, &mut staged).map_err(R::from);
    let result = result.and_then(|()| {
        // SAFETY: `out` is valid for `out_len` bytes by contract, the DRBG
        // succeeded only for `staged.len() == out_len`, and `staged` is this
        // function's own allocation.
        unsafe { write_out(out, &staged) }
    });
    oxicrypt_zeroize::zeroize(&mut staged);
    match result {
        Ok(()) => R::Ok as c_int,
        Err(e) => e as c_int,
    }
}

/// Write the security strength, in bits, of the handle's DRBG to `*out`.
///
/// Returns `Uninstantiated = 8` for a handle never instantiated.
///
/// # Safety
///
/// `h` must be NULL or a live handle from a `_new_rbg` function. `out` must
/// be NULL or valid for a write of one `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_drbg_strength_bits(h: *const OxiDrbg, out: *mut u32) -> c_int {
    if h.is_null() || out.is_null() {
        return R::NullPointer as c_int;
    }
    if overlaps_handle(out.cast::<u8>(), size_of::<u32>(), h) {
        return R::InvalidInput as c_int;
    }
    // SAFETY: `h` is a live handle by contract; only atomics and the
    // `UnsafeCell` are reached through this shared reference.
    let drbg = unsafe { &*h };
    let mut held = match enter(drbg) {
        Ok(held) => held,
        Err(e) => return e as c_int,
    };
    if drbg.pid.load(Ordering::Acquire) == 0 {
        return R::Uninstantiated as c_int;
    }
    let bits = match held.kind() {
        Ok(kind) => kind.strength_bits(),
        Err(e) => return e as c_int,
    };
    // SAFETY: `out` is valid for a `uint32_t` by contract, written bytewise
    // so its alignment does not matter, and does not overlap the local.
    match unsafe { write_out(out.cast::<u8>(), &bits.to_ne_bytes()) } {
        Ok(()) => R::Ok as c_int,
        Err(e) => e as c_int,
    }
}

/// Free a handle. NULL is a no-op.
///
/// The held DRBG's key material is wiped, then every byte of the handle,
/// before its memory is released. Freeing a handle another thread is using,
/// or freeing one twice, is undefined behaviour.
///
/// # Safety
///
/// `h` must be NULL or a live handle from a `_new_rbg` function that no
/// other thread is using.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_drbg_free(h: *mut OxiDrbg) {
    if h.is_null() {
        return;
    }
    // SAFETY: `h` is a live handle from `construct`, which allocates with
    // the layout of `OxiDrbg`, and no other thread is using it, by
    // contract.
    unsafe { wipe_and_free(h) };
}

/// The byte the free path writes over a dropped handle before its volatile
/// wipe, so that every byte, padding included, is initialised. A
/// fault-injection build writes a non-zero byte, so the handle reads as all
/// zero afterwards only if `oxicrypt_zeroize::zeroize` ran.
#[cfg(not(feature = "fault-injection"))]
const FREE_FILL: u8 = 0;
#[cfg(feature = "fault-injection")]
const FREE_FILL: u8 = 0xA5;

/// Drops the handle at `h` in place, which wipes the held DRBG's key
/// material, then wipes every byte of its allocation and releases it.
///
/// # Safety
///
/// `h` must be non-NULL and point to a live `T` in an allocation the global
/// allocator made with the layout of `T` (a `Box<T>`, `construct`, or the
/// AES `key_new`), which no other thread is using and which is released
/// once.
pub(crate) unsafe fn wipe_and_free<T>(h: *mut T) {
    let layout = Layout::new::<T>();
    let bytes = h.cast::<u8>();
    // SAFETY: `h` is a live `T` no other thread is using, by contract, so
    // its value may be dropped in place. Writing `FREE_FILL` then
    // initialises every byte, padding included, so the whole allocation may
    // be viewed as `[u8]`.
    let all = unsafe {
        core::ptr::drop_in_place(h);
        core::ptr::write_bytes(bytes, FREE_FILL, layout.size());
        core::slice::from_raw_parts_mut(bytes, layout.size())
    };
    oxicrypt_zeroize::zeroize(all);
    #[cfg(feature = "fault-injection")]
    LAST_FREED_ZERO.store(i8::from(all.iter().all(|&b| b == 0)), Ordering::SeqCst);
    // SAFETY: the allocation was made by the global allocator with this
    // layout, by contract, and is released once.
    unsafe { dealloc(bytes, layout) };
    #[cfg(test)]
    WIPED_AND_FREED.set(WIPED_AND_FREED.get().saturating_add(1));
}

#[cfg(test)]
thread_local! {
    /// In a unit test, the allocations [`wipe_and_free`] has wiped and
    /// released on this thread.
    pub(crate) static WIPED_AND_FREED: core::cell::Cell<usize> =
        const { core::cell::Cell::new(0) };
}

static LABEL_UNDECIDED: &CStr = c"undecided";

/// The seed-path labels, as NUL-terminated strings. Index 0 is
/// `undecided`.
static LABELS: [&CStr; 4] = [
    LABEL_UNDECIDED,
    c"operating-system generator (untested operational environment, IG 9.3.A AC2)",
    c"operating-system generator (untested operational environment, IG 9.3.A AC2); timer adequacy not met",
    c"jitter source, assessed row OE-1",
];

/// The index into [`LABELS`] of `label`, or 0 (`undecided`) for a label
/// this library does not know.
fn label_index(label: &str) -> u8 {
    LABELS
        .iter()
        .position(|l| l.to_bytes() == label.as_bytes())
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(0)
}

fn label_at(index: u8) -> &'static CStr {
    LABELS
        .get(usize::from(index))
        .copied()
        .unwrap_or(LABEL_UNDECIDED)
}

/// Run the entropy source's on-demand test on the module's seed path.
///
/// On the jitter path this runs the source's SP 800-90B on-demand health
/// tests; on the operating-system path it performs one fill. The first call
/// in a process decides the seed path, as the first draw does.
///
/// Returns `Ok = 0`, `NotOperational = 1`, `Busy = 32` (retry after a
/// pause) or `EntropyUnavailable = 33` (the test failed and the module has
/// entered its error state). When `label_out` is not NULL, on `0` and `33`
/// it is set to a static NUL-terminated label naming the seed path: on `0`
/// the path just tested; on `33` the path the process has decided, or
/// `undecided` when no draw has decided it. The string must not be freed.
///
/// # Safety
///
/// `label_out` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_entropy_on_demand_test(label_out: *mut *const c_char) -> c_int {
    let (code, label) = match oxicrypt_drbg::entropy_on_demand_test() {
        Ok(report) => (R::Ok, Some(label_at(label_index(report.label)))),
        Err(Error::Rbg(RbgError::EntropyUnavailable)) => (
            R::EntropyUnavailable,
            Some(label_at(label_index(oxicrypt_drbg::seed_path_label()))),
        ),
        Err(e) => (R::from(e), None),
    };
    if let Some(label) = label
        && !label_out.is_null()
    {
        // SAFETY: `label_out` is non-NULL and writable by contract.
        unsafe { *label_out = label.as_ptr() };
    }
    code as c_int
}

#[cfg(test)]
#[allow(clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use core::ptr;

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// A deterministic stand-in for the seed path's draw: each call serves a
    /// different byte pattern.
    #[cfg(feature = "fault-injection")]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the seam's draw signature returns a result"
    )]
    fn fixed_draw(out: &mut [u8]) -> Result<(), RbgError> {
        static CALLS: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
        let mut x = CALLS.fetch_add(1, Ordering::SeqCst);
        for b in out {
            x = x.wrapping_mul(29).wrapping_add(113);
            *b = x;
        }
        Ok(())
    }

    /// Makes the module operational and, with the fault-injection feature,
    /// replaces the seed path's draw with [`fixed_draw`]. Initialising the
    /// module is process-global, so these tests rely on the test runner,
    /// nextest, running each test in its own process.
    fn setup() {
        #[cfg(feature = "fault-injection")]
        {
            oxicrypt_drbg::seam::clear_all();
            oxicrypt_drbg::seam::set_get_entropy(fixed_draw);
        }
        match oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
            Ok(()) | Err(Error::AlreadyInitialized) => {}
            Err(e) => panic!("module failed to initialise: {e:?}"),
        }
    }

    type New = unsafe extern "C" fn(*mut *mut OxiDrbg) -> c_int;

    fn instantiated(new: New) -> *mut OxiDrbg {
        let mut h = ptr::null_mut();
        // SAFETY: `h` is a writable local; the handle is live after `new`.
        unsafe {
            assert_eq!(new(&raw mut h), 0);
            assert_eq!(oxi_drbg_instantiate(h, b"app".as_ptr(), 3), 0);
        }
        h
    }

    fn generate(h: *mut OxiDrbg, additional: &[u8], out: &mut [u8]) -> c_int {
        // SAFETY: `h` is live; both slices are valid locals.
        unsafe {
            oxi_drbg_generate(
                h,
                additional.as_ptr(),
                additional.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        }
    }

    fn round_trip(new: New, strength: u32) {
        setup();
        let h = instantiated(new);
        let mut out = [0u8; 64];
        assert_eq!(generate(h, &[], &mut out), 0);
        assert!(out.iter().any(|&b| b != 0));
        let mut bits = 0u32;
        // SAFETY: `h` is live and `bits` is a writable local.
        unsafe {
            assert_eq!(oxi_drbg_strength_bits(h, &raw mut bits), 0);
            oxi_drbg_free(h);
        }
        assert_eq!(bits, strength);
    }

    #[test]
    fn oxi_drbg_handle_round_trip() {
        round_trip(oxi_hmac_drbg_sha256_new_rbg, 256);
        round_trip(oxi_hash_drbg_sha256_new_rbg, 256);
        round_trip(oxi_ctr_drbg_aes128_new_rbg, 128);
    }

    #[test]
    fn oxi_drbg_generate_on_never_instantiated_returns_8() {
        setup();
        let mut h = ptr::null_mut();
        let mut out = [0xa5u8; 16];
        let mut bits = 7u32;
        // SAFETY: `h` is a writable local and live after construction.
        unsafe {
            assert_eq!(oxi_hmac_drbg_sha256_new_rbg(&raw mut h), 0);
            assert_eq!(generate(h, &[], &mut out), R::Uninstantiated as c_int);
            assert_eq!(
                oxi_drbg_strength_bits(h, &raw mut bits),
                R::Uninstantiated as c_int
            );
            assert_eq!(
                oxi_drbg_reseed(h, ptr::null(), 0),
                R::Uninstantiated as c_int
            );
            oxi_drbg_free(h);
        }
        assert_eq!(out, [0xa5u8; 16], "a failed call wrote output");
        assert_eq!(bits, 7);
    }

    #[test]
    fn oxi_drbg_null_handle_returns_10() {
        setup();
        let null = ptr::null_mut();
        let mut out = [0u8; 16];
        let mut bits = 0u32;
        // SAFETY: every handle argument is NULL, which each function refuses
        // before any dereference.
        unsafe {
            assert_eq!(oxi_hmac_drbg_sha256_new_rbg(ptr::null_mut()), 10);
            assert_eq!(oxi_ctr_drbg_aes256_new_rbg(ptr::null_mut()), 10);
            assert_eq!(oxi_drbg_instantiate(null, ptr::null(), 0), 10);
            assert_eq!(oxi_drbg_reseed(null, ptr::null(), 0), 10);
            assert_eq!(generate(null, &[], &mut out), 10);
            assert_eq!(oxi_drbg_strength_bits(null, &raw mut bits), 10);
            oxi_drbg_free(null);
        }
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        // SAFETY: `h` is live; the NULL outputs are refused before any write.
        unsafe {
            assert_eq!(oxi_drbg_generate(h, ptr::null(), 0, ptr::null_mut(), 0), 10);
            assert_eq!(oxi_drbg_strength_bits(h, ptr::null_mut()), 10);
            // An optional input that is NULL with a length is invalid input.
            assert_eq!(oxi_drbg_reseed(h, ptr::null(), 1), 5);
            oxi_drbg_free(h);
        }
    }

    #[test]
    fn oxi_drbg_additional_input_over_limit_returns_5() {
        setup();
        assert_eq!(HmacDrbgSha256::MAX_MODULE_ADDITIONAL_INPUT, 736);
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        #[cfg(feature = "fault-injection")]
        let draws = oxicrypt_drbg::seam::draw_count();
        let over = [0x11u8; 737];
        let mut out = [0u8; 32];
        // SAFETY: `h` is live and `over` is a valid local.
        unsafe {
            assert_eq!(oxi_drbg_reseed(h, over.as_ptr(), over.len()), 5);
        }
        assert_eq!(generate(h, &over, &mut out), 5);
        assert_eq!(out, [0u8; 32]);
        #[cfg(feature = "fault-injection")]
        assert_eq!(oxicrypt_drbg::seam::draw_count(), draws, "a refusal drew");
        assert_eq!(generate(h, &over[..736], &mut out), 0);
        // SAFETY: `h` is live.
        unsafe { oxi_drbg_free(h) };
    }

    #[test]
    fn oxi_drbg_busy_returns_32() {
        setup();
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        let mut out = [0u8; 16];
        // SAFETY: `h` is live.
        unsafe { &*h }
            .holder
            .store(current_process(), Ordering::SeqCst);
        assert_eq!(generate(h, &[], &mut out), R::Busy as c_int);
        assert_eq!(R::Busy as c_int, 32);
        assert_eq!(out, [0u8; 16]);
        // SAFETY: `h` is live.
        unsafe { &*h }.holder.store(0, Ordering::SeqCst);
        assert_eq!(generate(h, &[], &mut out), 0);
        // SAFETY: `h` is live.
        unsafe { oxi_drbg_free(h) };
    }

    #[test]
    fn oxi_drbg_pid_mismatch_returns_5_and_instantiate_recovers() {
        setup();
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        // SAFETY: `h` is live.
        let drbg = unsafe { &*h };
        let own = drbg.pid.load(Ordering::SeqCst);
        assert_eq!(own, oxicrypt_platform::process_id());
        // A handle inherited from another process, whose thread held it at
        // the fork.
        drbg.pid.store(own.wrapping_add(1), Ordering::SeqCst);
        drbg.holder.store(own.wrapping_add(1), Ordering::SeqCst);
        let mut out = [0u8; 16];
        assert_eq!(generate(h, &[], &mut out), 5);
        // SAFETY: `h` is live.
        unsafe {
            assert_eq!(oxi_drbg_reseed(h, ptr::null(), 0), 5);
            assert_eq!(oxi_drbg_instantiate(h, ptr::null(), 0), 0);
        }
        assert_eq!(drbg.pid.load(Ordering::SeqCst), own);
        assert_eq!(drbg.holder.load(Ordering::SeqCst), 0);
        assert_eq!(generate(h, &[], &mut out), 0);
        // SAFETY: `h` is live.
        unsafe { oxi_drbg_free(h) };
    }

    #[test]
    fn oxi_drbg_output_overlapping_input_returns_5() {
        setup();
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        let mut buf = [0u8; 32];
        let p = buf.as_mut_ptr();
        // SAFETY: `h` is live; both ranges lie in `buf`.
        unsafe {
            assert_eq!(oxi_drbg_generate(h, p.cast_const(), 8, p.add(4), 8), 5);
            assert_eq!(oxi_drbg_generate(h, p.cast_const(), 8, p.add(8), 8), 0);
            assert_eq!(oxi_drbg_generate(h, ptr::null(), 0, h.cast::<u8>(), 8), 5);
            oxi_drbg_free(h);
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn oxi_drbg_free_zeroizes() {
        setup();
        assert_eq!(crate::test_api::oxi_test_last_freed_bytes_zero(), -1);
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        let mut out = [0u8; 16];
        assert_eq!(generate(h, &[], &mut out), 0);
        // SAFETY: `h` is live.
        unsafe { oxi_drbg_free(h) };
        assert_eq!(crate::test_api::oxi_test_last_freed_bytes_zero(), 1);
        assert_eq!(crate::test_api::oxi_test_last_freed_bytes_zero(), -1);

        let mut typed = ptr::null_mut();
        // SAFETY: `typed` is a writable local, live after `_new`.
        unsafe {
            assert_eq!(crate::drbg::oxi_hash_drbg_sha256_new(&raw mut typed), 0);
            crate::drbg::oxi_hash_drbg_sha256_free(typed);
        }
        assert_eq!(crate::test_api::oxi_test_last_freed_bytes_zero(), 1);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn new_rbg_alloc_failure_returns_255() {
        let sentinel = ptr::dangling_mut::<OxiDrbg>();
        let mut h = sentinel;
        crate::test_api::oxi_test_fail_next_alloc();
        // SAFETY: `h` is a writable local.
        unsafe {
            assert_eq!(oxi_hash_drbg_sha512_new_rbg(&raw mut h), 255);
            assert_eq!(h, sentinel, "a failed construction wrote the handle");
            assert_eq!(oxi_hash_drbg_sha512_new_rbg(&raw mut h), 0);
            assert_ne!(h, sentinel);
            oxi_drbg_free(h);
        }
    }

    #[test]
    fn entropy_on_demand_test_reports_label() {
        #[cfg(feature = "fault-injection")]
        {
            oxicrypt_drbg::seam::clear_all();
            oxicrypt_drbg::seam::force_operating_system_path();
        }
        setup_module_only();
        let mut label: *const c_char = ptr::null();
        // SAFETY: `label` is a writable local; the label is a static string.
        let text = unsafe {
            assert_eq!(oxi_entropy_on_demand_test(&raw mut label), 0);
            assert!(!label.is_null());
            assert_eq!(oxi_entropy_on_demand_test(ptr::null_mut()), 0);
            CStr::from_ptr(label)
                .to_str()
                .unwrap_or_default()
                .to_owned()
        };
        assert!(
            text.starts_with("jitter source") || text.starts_with("operating-system generator"),
            "{text}"
        );
        #[cfg(feature = "fault-injection")]
        {
            assert!(text.starts_with("operating-system generator"), "{text}");
            oxicrypt_drbg::seam::fail_next(oxicrypt_drbg::seam::FaultClass::OnDemand);
            let mut failed: *const c_char = ptr::null();
            // SAFETY: `failed` is a writable local.
            assert_eq!(unsafe { oxi_entropy_on_demand_test(&raw mut failed) }, 33);
            assert_eq!(
                failed, label,
                "the failure reports the decided path's label"
            );
        }
    }

    /// Makes the module operational without touching the seams.
    fn setup_module_only() {
        match oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
            Ok(()) | Err(Error::AlreadyInitialized) => {}
            Err(e) => panic!("module failed to initialise: {e:?}"),
        }
    }

    /// A handle inherited across fork, held by a thread of the parent, is
    /// taken over by exactly one thread: while that
    /// thread's draw waits on the held seed cell, a second instantiate and
    /// a generate on the handle return `Busy`. The draw then fails with
    /// `Busy`, and the handle holds none of the parent's state: it returns
    /// `Uninstantiated` until it is instantiated again.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn inherited_handle_is_taken_over_by_one_thread() {
        oxicrypt_drbg::seam::clear_all();
        setup_module_only();
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        // SAFETY: `h` is live until it is freed at the end of this test.
        let drbg = unsafe { &*h };
        let foreign = current_process().wrapping_add(1);
        drbg.pid.store(foreign, Ordering::SeqCst);
        drbg.holder.store(foreign, Ordering::SeqCst);
        let mut out = [0u8; 32];
        assert_eq!(generate(h, &[], &mut out), R::InvalidInput as c_int);

        let hold = oxicrypt_drbg::seam::hold_seed_cell();
        let addr = h.expose_provenance();
        let winner = std::thread::spawn(move || {
            let h = core::ptr::with_exposed_provenance_mut::<OxiDrbg>(addr);
            // SAFETY: the handle outlives the thread, which is joined below.
            unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) }
        });
        let mut spins: u64 = 0;
        // The takeover records 0 once it has wiped the parent's state, and
        // the winner then waits in its draw.
        while drbg.pid.load(Ordering::SeqCst) != 0 {
            assert!(spins < 1 << 32, "no thread took the handle over");
            spins = spins.saturating_add(1);
            core::hint::spin_loop();
        }
        let started = std::time::Instant::now();
        // SAFETY: `h` is live.
        let second = unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) };
        // A refusal by the handle is immediate; a call that reached the
        // held seed cell would spin there for its whole bound.
        let second_took = started.elapsed();
        let during = generate(h, &[], &mut out);
        let first = winner
            .join()
            .unwrap_or_else(|_| panic!("the winner panicked"));
        drop(hold);
        assert_eq!(
            second,
            R::Busy as c_int,
            "a second thread took the handle too"
        );
        assert!(
            second_took < std::time::Duration::from_millis(50),
            "the second instantiate reached the seed path ({second_took:?})"
        );
        assert_eq!(
            during,
            R::Busy as c_int,
            "a generate reached the handle mid-takeover"
        );
        assert_eq!(
            first,
            R::Busy as c_int,
            "the held seed cell did not fail the draw"
        );
        assert_eq!(drbg.pid.load(Ordering::SeqCst), 0);
        assert_eq!(generate(h, &[], &mut out), R::Uninstantiated as c_int);
        let mut bits = 0u32;
        // SAFETY: `h` is live and `bits` is a writable local.
        unsafe {
            assert_eq!(
                oxi_drbg_strength_bits(h, &raw mut bits),
                R::Uninstantiated as c_int
            );
            assert_eq!(oxi_drbg_instantiate(h, ptr::null(), 0), 0);
        }
        assert_eq!(generate(h, &[], &mut out), 0);
        // SAFETY: `h` is live and no other thread uses it.
        unsafe { oxi_drbg_free(h) };
    }

    /// A handle a thread of another process was instantiating for the first
    /// time at a fork: its holder is that process and its recorded id is
    /// still 0. Every operation but instantiate refuses it
    /// with `InvalidInput`; instantiate takes it over, and a generate then
    /// succeeds.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn first_instantiate_held_at_fork_is_taken_over() {
        setup();
        let mut h = ptr::null_mut();
        // SAFETY: `h` is a writable local.
        assert_eq!(unsafe { oxi_hmac_drbg_sha256_new_rbg(&raw mut h) }, 0);
        // SAFETY: `h` is live until it is freed at the end of this test.
        let drbg = unsafe { &*h };
        let foreign = current_process().wrapping_add(1);
        drbg.holder.store(foreign, Ordering::SeqCst);
        assert_eq!(drbg.pid.load(Ordering::SeqCst), 0);
        let mut out = [0u8; 32];
        let mut bits = 0u32;
        assert_eq!(generate(h, &[], &mut out), R::InvalidInput as c_int);
        // SAFETY: `h` is live and `bits` is a writable local.
        unsafe {
            assert_eq!(oxi_drbg_reseed(h, ptr::null(), 0), R::InvalidInput as c_int);
            assert_eq!(
                oxi_drbg_strength_bits(h, &raw mut bits),
                R::InvalidInput as c_int
            );
            assert_eq!(oxi_drbg_instantiate(h, ptr::null(), 0), 0);
        }
        assert_eq!(drbg.pid.load(Ordering::SeqCst), current_process());
        assert_eq!(drbg.holder.load(Ordering::SeqCst), 0);
        assert_eq!(generate(h, &[], &mut out), 0);
        assert_ne!(out, [0u8; 32]);

        // Control: the same hold recorded by this process is a call in
        // progress here, so it is `Busy`, not inherited.
        drbg.holder.store(current_process(), Ordering::SeqCst);
        // SAFETY: `h` is live.
        assert_eq!(
            unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) },
            R::Busy as c_int
        );
        assert_eq!(generate(h, &[], &mut out), R::Busy as c_int);
        drbg.holder.store(0, Ordering::SeqCst);
        // SAFETY: `h` is live and no other thread uses it.
        unsafe { oxi_drbg_free(h) };
    }

    /// A fork at any instant of a parent's first instantiate leaves the
    /// child one of two states, because the hold is one word taken by one
    /// compare-exchange: free, or held by the parent's id with no id
    /// recorded. In each, instantiate succeeds and a generate then succeeds.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn every_state_a_fork_leaves_is_recovered() {
        setup();
        let foreign = current_process().wrapping_add(1);
        for holder in [0, foreign] {
            let mut h = ptr::null_mut();
            // SAFETY: `h` is a writable local.
            assert_eq!(unsafe { oxi_hmac_drbg_sha256_new_rbg(&raw mut h) }, 0);
            // SAFETY: `h` is live until it is freed below.
            let drbg = unsafe { &*h };
            drbg.holder.store(holder, Ordering::SeqCst);
            assert_eq!(drbg.pid.load(Ordering::SeqCst), 0);
            // SAFETY: `h` is live.
            assert_eq!(
                unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) },
                0,
                "holder {holder}"
            );
            assert_eq!(drbg.pid.load(Ordering::SeqCst), current_process());
            assert_eq!(drbg.holder.load(Ordering::SeqCst), 0);
            let mut out = [0u8; 32];
            assert_eq!(generate(h, &[], &mut out), 0, "holder {holder}");
            assert_ne!(out, [0u8; 32]);
            // SAFETY: `h` is live and no other thread uses it.
            unsafe { oxi_drbg_free(h) };
        }
    }

    /// A draw that fails as a seed path held past its wait bound does: the
    /// module stays operational and a later draw can succeed.
    #[cfg(feature = "fault-injection")]
    fn failed_draw(_: &mut [u8]) -> Result<(), RbgError> {
        Err(RbgError::Busy)
    }

    /// A fork while a thread of the parent takes a handle over leaves the
    /// child the parent's reset mark: [`RESETTING`] with the parent's id,
    /// and a hold that is free or foreign. A fork during the parent's first
    /// instantiate leaves no recorded id and a foreign hold. Neither mark
    /// nor hold is this process's, so neither is `Busy` here. Every
    /// operation but instantiate refuses the handle with `InvalidInput`.
    /// Instantiate takes it over and resets the parent's instance even when
    /// its draw fails, so the handle is then uninstantiated rather than
    /// refused. A later instantiate succeeds, records this process, and a
    /// generate then succeeds.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn reset_mark_of_the_parent_is_recovered() {
        setup();
        let current = current_process();
        let parent = current.wrapping_add(1);
        for (pid, holder) in [
            (RESETTING | parent, 0),
            (RESETTING | parent, parent),
            (0, parent),
        ] {
            let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
            // SAFETY: `h` is live until it is freed below.
            let drbg = unsafe { &*h };
            drbg.pid.store(pid, Ordering::SeqCst);
            drbg.holder.store(holder, Ordering::SeqCst);
            let case = format!("pid {pid:#x}, holder {holder}");
            let mut out = [0u8; 32];
            assert_eq!(
                generate(h, &[], &mut out),
                R::InvalidInput as c_int,
                "{case}: generate before the take-over"
            );

            oxicrypt_drbg::seam::set_get_entropy(failed_draw);
            // SAFETY: `h` is live.
            let failed = unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) };
            oxicrypt_drbg::seam::set_get_entropy(fixed_draw);
            assert_eq!(
                failed,
                R::Busy as c_int,
                "{case}: instantiate with a failing draw"
            );
            assert_eq!(drbg.pid.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(drbg.holder.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(
                generate(h, &[], &mut out),
                R::Uninstantiated as c_int,
                "{case}: the parent's instance survived the take-over"
            );

            // SAFETY: `h` is live.
            assert_eq!(
                unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) },
                0,
                "{case}: instantiate"
            );
            assert_eq!(drbg.pid.load(Ordering::SeqCst), current, "{case}");
            assert_eq!(drbg.holder.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(generate(h, &[], &mut out), 0, "{case}: generate");
            assert_ne!(out, [0u8; 32]);
            // SAFETY: `h` is live and no other thread uses it.
            unsafe { oxi_drbg_free(h) };
        }
    }

    /// While a thread of this process takes a handle over, its recorded id
    /// carries [`RESETTING`]: instantiate and generate both return `Busy`
    /// without touching the handle, and once the mark is gone both succeed.
    #[test]
    fn reset_mark_of_this_process_returns_32() {
        setup();
        let h = instantiated(oxi_hmac_drbg_sha256_new_rbg);
        // SAFETY: `h` is live until it is freed below.
        let drbg = unsafe { &*h };
        let current = current_process();
        drbg.pid.store(RESETTING | current, Ordering::SeqCst);
        let mut out = [0u8; 32];
        // SAFETY: `h` is live.
        let during = unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) };
        assert_eq!(during, R::Busy as c_int, "instantiate under the mark");
        assert_eq!(
            generate(h, &[], &mut out),
            R::Busy as c_int,
            "generate under the mark"
        );
        assert_eq!(out, [0u8; 32]);
        assert_eq!(drbg.pid.load(Ordering::SeqCst), RESETTING | current);
        assert_eq!(drbg.holder.load(Ordering::SeqCst), 0);
        drbg.pid.store(current, Ordering::SeqCst);
        assert_eq!(generate(h, &[], &mut out), 0);
        // SAFETY: `h` is live.
        assert_eq!(unsafe { oxi_drbg_instantiate(h, ptr::null(), 0) }, 0);
        // SAFETY: `h` is live and no other thread uses it.
        unsafe { oxi_drbg_free(h) };
    }

    /// Decides the seed path through the DRBG crate's on-demand test and
    /// checks that the label it reports, and the label
    /// `oxicrypt_drbg::seed_path_label` then returns, are an entry of
    /// [`LABELS`] other than `undecided`, byte for byte.
    fn assert_reported_label_known() {
        setup_module_only();
        let report = oxicrypt_drbg::entropy_on_demand_test()
            .unwrap_or_else(|e| panic!("on-demand test failed: {e:?}"));
        let index = label_index(report.label);
        assert_ne!(index, 0, "{:?} is not in LABELS", report.label);
        assert_eq!(label_at(index).to_bytes(), report.label.as_bytes());
        assert_eq!(oxicrypt_drbg::seed_path_label(), report.label);
    }

    #[test]
    fn label_index_knows_the_undecided_label() {
        let undecided = oxicrypt_drbg::seed_path_label();
        assert_eq!(label_index(undecided), 0);
        assert_eq!(label_at(0).to_bytes(), undecided.as_bytes());
        assert_eq!(label_index("a label this library does not know"), 0);
    }

    #[test]
    fn label_index_knows_the_reported_label() {
        #[cfg(feature = "fault-injection")]
        oxicrypt_drbg::seam::clear_all();
        assert_reported_label_known();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn label_index_knows_the_operating_system_label() {
        oxicrypt_drbg::seam::clear_all();
        oxicrypt_drbg::seam::force_operating_system_path();
        assert_reported_label_known();
    }

    /// On a target an assessed row matches, the forced adequacy failure
    /// selects the operating-system path with its timer suffix; elsewhere
    /// no row matches and the plain operating-system label is reported.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn label_index_knows_the_timer_inadequate_label() {
        oxicrypt_drbg::seam::clear_all();
        oxicrypt_drbg::seam::force_timer_inadequate(true);
        assert_reported_label_known();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn label_index_knows_the_assessed_label() {
        oxicrypt_drbg::seam::clear_all();
        oxicrypt_drbg::seam::force_assessed_path();
        assert_reported_label_known();
    }

    /// The C header's documentation of `OxiDrbg` states what a forked
    /// child must do, the limit of the process-id check, what `Busy` asks
    /// of the caller, and that freeing a handle in use is undefined.
    #[test]
    fn drbg_header_statements() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/include/oxicrypt.h");
        let header = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let decl = header
            .find("typedef struct OxiDrbg OxiDrbg;")
            .unwrap_or_else(|| panic!("no OxiDrbg declaration"));
        let before = header[..decl].trim_end();
        assert!(
            before.ends_with("*/"),
            "no comment block precedes the declaration"
        );
        let start = before
            .rfind("/*")
            .unwrap_or_else(|| panic!("unterminated comment"));
        let block = &before[start..];
        for needle in ["fork", "process id", "retry", "undefined behaviour"] {
            assert!(
                block.contains(needle),
                "the OxiDrbg comment lacks {needle:?}"
            );
        }
    }

    /// The functions whose bodies may copy into a caller buffer without
    /// [`write_out`]: `write_out` itself, and the two status outputs a
    /// caller reads after the module has entered its error state, which
    /// `write_out`'s re-check would refuse.
    const DIRECT_COPY_ALLOWED: &[&str] = &[
        "write_out",
        "oxi_integrity_key_fingerprint",
        "oxi_integrity_status_detail",
    ];

    /// The functions whose bodies may call `write_bytes`, with the reason
    /// for each: `zero_out` clears a caller's output buffer when a call is
    /// refused, writing no module data, and must work in the error state,
    /// where `write_out` refuses; `wipe_and_free` overwrites the allocation
    /// of a handle the module is releasing, which is not an output buffer.
    const WRITE_BYTES_ALLOWED: &[&str] = &["zero_out", "wipe_and_free"];

    /// The functions that may hand a slice bound from `from_raw_parts_mut`
    /// to a call: `wipe_and_free`'s slice views the allocation of the
    /// handle it releases, not a caller buffer, and goes only to the
    /// volatile wipe.
    const HANDED_ON_ALLOWED: &[&str] = &["wipe_and_free"];

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "offsets into a source file, far below usize::MAX"
    )]
    mod output_copy_scan {
        fn is_ident(c: Option<&char>) -> bool {
            c.is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
        }

        fn find(s: &[char], from: usize, pat: &[char]) -> Option<usize> {
            (from..s.len()).find(|&k| s[k..].starts_with(pat))
        }

        fn blank(out: &mut [char], from: usize, to: usize) {
            let to = to.min(out.len());
            for c in out.iter_mut().take(to).skip(from) {
                if *c != '\n' {
                    *c = ' ';
                }
            }
        }

        /// `src` with its comments and string, byte-string and char literals
        /// blanked to spaces. Newlines are kept, so offsets and line numbers
        /// are those of `src`.
        pub(super) fn code_only(src: &str) -> Vec<char> {
            let text: Vec<char> = src.chars().collect();
            let mut out = text.clone();
            let at = |k: usize| text.get(k).copied();
            let mut i = 0;
            while i < text.len() {
                let ch = text[i];
                let next = at(i + 1);
                let after_ident = i > 0 && is_ident(text.get(i - 1));
                if ch == '/' && next == Some('/') {
                    let stop = find(&text, i, &['\n']).unwrap_or(text.len());
                    blank(&mut out, i, stop);
                    i = stop;
                } else if ch == '/' && next == Some('*') {
                    let mut depth = 1;
                    let mut k = i + 2;
                    while k < text.len() && depth > 0 {
                        if text[k] == '/' && at(k + 1) == Some('*') {
                            depth += 1;
                            k += 2;
                        } else if text[k] == '*' && at(k + 1) == Some('/') {
                            depth -= 1;
                            k += 2;
                        } else {
                            k += 1;
                        }
                    }
                    blank(&mut out, i, k);
                    i = k;
                } else if (ch == 'r' || ((ch == 'b' || ch == 'c') && next == Some('r')))
                    && !after_ident
                {
                    // A raw string: `r`, an optional `b` or `c` before it,
                    // then any number of `#`, then `"`.
                    let mut k = if ch == 'r' { i + 1 } else { i + 2 };
                    let mut close = vec!['"'];
                    while at(k) == Some('#') {
                        close.push('#');
                        k += 1;
                    }
                    if at(k) == Some('"') {
                        let stop =
                            find(&text, k + 1, &close).map_or(text.len(), |end| end + close.len());
                        blank(&mut out, i, stop);
                        i = stop;
                    } else {
                        i += 1;
                    }
                } else if ch == '"'
                    || ((ch == 'b' || ch == 'c') && next == Some('"') && !after_ident)
                {
                    let mut k = if ch == '"' { i + 1 } else { i + 2 };
                    while k < text.len() && text[k] != '"' {
                        k += if text[k] == '\\' { 2 } else { 1 };
                    }
                    blank(&mut out, i, k + 1);
                    i = k + 1;
                } else if ch == '\'' || (ch == 'b' && next == Some('\'') && !after_ident) {
                    // A char literal closes within a few characters; a
                    // lifetime does not.
                    let quote = if ch == 'b' { i + 1 } else { i };
                    let close = if at(quote + 1) == Some('\\') {
                        find(&text, quote + 3, &['\'']).filter(|&end| end - quote <= 12)
                    } else if at(quote + 2) == Some('\'') {
                        Some(quote + 2)
                    } else {
                        None
                    };
                    if let Some(end) = close {
                        blank(&mut out, i, end + 1);
                        i = end + 1;
                    } else {
                        i = quote + 1;
                    }
                } else {
                    i += 1;
                }
            }
            out
        }

        /// The offset of the bracket that closes the one at `open`.
        fn closing(code: &[char], open: usize, pair: (char, char)) -> Option<usize> {
            let mut depth = 0usize;
            for (k, &c) in code.iter().enumerate().skip(open) {
                if c == pair.0 {
                    depth += 1;
                } else if c == pair.1 {
                    depth -= 1;
                    if depth == 0 {
                        return Some(k);
                    }
                }
            }
            None
        }

        /// The offset of the bracket that opens the one at `close`.
        fn opening(code: &[char], close: usize, pair: (char, char)) -> Option<usize> {
            let mut depth = 0usize;
            for k in (0..=close).rev() {
                if code[k] == pair.1 {
                    depth += 1;
                } else if code[k] == pair.0 {
                    depth -= 1;
                    if depth == 0 {
                        return Some(k);
                    }
                }
            }
            None
        }

        /// Every offset at which `needle` starts and is not the tail of a
        /// longer identifier.
        fn occurrences(code: &[char], needle: &str) -> Vec<usize> {
            occurrences_in(code, needle, 0, code.len())
        }

        /// As [`occurrences`], within `code[from..to]`.
        fn occurrences_in(code: &[char], needle: &str, from: usize, to: usize) -> Vec<usize> {
            let pat: Vec<char> = needle.chars().collect();
            (from..to)
                .filter(|&k| code[k..].starts_with(&pat))
                .filter(|&k| !(is_ident(pat.first()) && k > 0 && is_ident(code.get(k - 1))))
                .collect()
        }

        /// Every function with a body, as its name and the offsets of the
        /// braces around its body.
        fn fn_bodies(code: &[char]) -> Vec<(String, usize, usize)> {
            let mut found = Vec::new();
            for start in occurrences(code, "fn ") {
                let mut k = start + 3;
                while code.get(k).is_some_and(|c| c.is_whitespace()) {
                    k += 1;
                }
                let name_at = k;
                while is_ident(code.get(k)) {
                    k += 1;
                }
                let name: String = code[name_at..k].iter().collect();
                if name.is_empty() && code.get(k) == Some(&'(') {
                    // A function pointer type.
                    continue;
                }
                // The body opens at the first `{` outside parentheses and
                // brackets; a `;` there first means the function has none.
                let (mut paren, mut bracket) = (0i32, 0i32);
                let mut open = None;
                while k < code.len() {
                    match code[k] {
                        '(' => paren += 1,
                        ')' => paren -= 1,
                        '[' => bracket += 1,
                        ']' => bracket -= 1,
                        '{' if paren == 0 && bracket == 0 => {
                            open = Some(k);
                            break;
                        }
                        ';' if paren == 0 && bracket == 0 => break,
                        _ => {}
                    }
                    k += 1;
                }
                if let Some(open) = open
                    && let Some(close) = closing(code, open, ('{', '}'))
                {
                    found.push((name, open, close));
                }
            }
            found
        }

        /// The names a `let` in `code[open..close]` binds to a value whose
        /// initializer calls `slice_from_raw_mut` or `from_raw_parts_mut`.
        fn raw_bound(code: &[char], open: usize, close: usize) -> Vec<String> {
            raw_bindings(code, open, close)
                .into_iter()
                .map(|(name, _)| name)
                .collect()
        }

        /// As [`raw_bound`], each name with the offset of the `;` that ends
        /// its `let` statement.
        fn raw_bindings(code: &[char], open: usize, close: usize) -> Vec<(String, usize)> {
            let mut names = Vec::new();
            for start in occurrences_in(code, "let ", open, close) {
                if start <= open || start >= close {
                    continue;
                }
                let Some(eq) = (start..close).find(|&k| {
                    code[k] == '='
                        && !matches!(code.get(k + 1), Some('=' | '>'))
                        && !matches!(code.get(k - 1), Some('=' | '!' | '<' | '>'))
                }) else {
                    continue;
                };
                let mut depth = 0i32;
                let mut end = close;
                for (k, &c) in code.iter().enumerate().take(close).skip(eq) {
                    match c {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => depth -= 1,
                        ';' if depth == 0 => {
                            end = k;
                            break;
                        }
                        _ => {}
                    }
                }
                let init: String = code[eq..end].iter().collect();
                if !init.contains("slice_from_raw_mut(") && !init.contains("from_raw_parts_mut(") {
                    continue;
                }
                // The pattern ends at a type annotation's lone `:`, so the
                // type's words are not taken for bound names.
                let pattern_end = (start + 4..eq)
                    .find(|&k| {
                        code[k] == ':' && code.get(k + 1) != Some(&':') && code[k - 1] != ':'
                    })
                    .unwrap_or(eq);
                let pattern: String = code[start + 4..pattern_end].iter().collect();
                for word in pattern.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                    if !word.is_empty() && word != "mut" && word != "ref" {
                        names.push((word.to_owned(), end));
                    }
                }
            }
            names
        }

        /// Whether the identifier at `pos` sits directly inside the
        /// parentheses of a call: a function, method or macro call, or a
        /// call with a turbofish.
        fn is_call_argument(code: &[char], pos: usize) -> bool {
            let mut depth = 0usize;
            for k in (0..pos).rev() {
                match code[k] {
                    ')' | ']' | '}' => depth += 1,
                    '[' | '{' if depth == 0 => return false,
                    '(' if depth == 0 => {
                        let before = (0..k).rev().find(|&b| !code[b].is_whitespace());
                        return before.is_some_and(|b| {
                            is_ident(code.get(b)) || matches!(code[b], '>' | '!')
                        });
                    }
                    '(' | '[' | '{' => depth -= 1,
                    _ => {}
                }
            }
            false
        }

        /// The 1-based lines at which a name bound from
        /// `slice_from_raw_mut` or `from_raw_parts_mut` is passed as an
        /// argument to a call after its binding, in the same function.
        fn raw_slices_handed_on(
            code: &[char],
            bodies: &[(String, usize, usize)],
            allowed: &[&str],
        ) -> Vec<usize> {
            let line = |pos: usize| code[..pos].iter().filter(|&&c| c == '\n').count() + 1;
            let mut flagged = Vec::new();
            for (fn_name, open, close) in bodies {
                if allowed.contains(&fn_name.as_str()) {
                    continue;
                }
                for (name, after) in raw_bindings(code, *open, *close) {
                    for pos in occurrences_in(code, &name, after, *close) {
                        let whole = !is_ident(code.get(pos + name.chars().count()));
                        if pos > after && pos < *close && whole && is_call_argument(code, pos) {
                            flagged.push(line(pos));
                        }
                    }
                }
            }
            flagged
        }

        /// The receiver expression that ends at `dot`.
        fn receiver_expr(code: &[char], dot: usize) -> String {
            let mut k = dot;
            while k > 0 {
                let c = code[k - 1];
                if is_ident(Some(&c)) || c == '.' {
                    k -= 1;
                } else if c == ']' || c == ')' {
                    let pair = if c == ']' { ('[', ']') } else { ('(', ')') };
                    match opening(code, k - 1, pair) {
                        Some(o) => k = o,
                        None => break,
                    }
                } else {
                    break;
                }
            }
            code[k..dot].iter().collect()
        }

        /// The offset at which the receiver expression that ends at `dot`
        /// begins.
        fn receiver_start(code: &[char], dot: usize) -> usize {
            dot - receiver_expr(code, dot).chars().count()
        }

        /// Whether the receiver expression that ends at `dot` offsets a
        /// pointer, with one of [`POINTER_OFFSETS`].
        fn offsets_pointer(code: &[char], dot: usize) -> bool {
            let expr = receiver_expr(code, dot);
            POINTER_OFFSETS.iter().any(|m| expr.contains(m))
        }

        /// The methods that form a pointer at an offset from another.
        const POINTER_OFFSETS: &[&str] = &[
            ".add(",
            ".offset(",
            ".wrapping_add(",
            ".sub(",
            ".wrapping_sub(",
            ".wrapping_offset(",
            ".byte_add(",
            ".byte_sub(",
            ".byte_offset(",
        ];

        /// The offsets of every assignment through a dereferenced pointer
        /// formed at an offset, as in `*p.add(i) = v` or `*p.add(i) |= v`: a
        /// `*`, past any opening parentheses, before a receiver that ends in a call to one of
        /// [`POINTER_OFFSETS`], followed by `=` and not `==`, or by a
        /// compound assignment operator.
        fn offset_deref_assignments(code: &[char]) -> Vec<usize> {
            let mut found = Vec::new();
            for method in POINTER_OFFSETS {
                for pos in occurrences(code, method) {
                    let Some(close) = closing(code, pos + method.len() - 1, ('(', ')')) else {
                        continue;
                    };
                    let start = receiver_start(code, pos);
                    // Parentheses around the pointer, as in `*(p.add(i)) = v`,
                    // are skipped on both sides.
                    let deref = (0..start)
                        .rev()
                        .find(|&b| !(code[b].is_whitespace() || code[b] == '('))
                        .is_some_and(|b| code[b] == '*');
                    let after = (close + 1..code.len())
                        .find(|&k| !(code[k].is_whitespace() || code[k] == ')'));
                    let assigns = after.is_some_and(|k| match code[k] {
                        '=' => code.get(k + 1) != Some(&'='),
                        '+' | '-' | '*' | '/' | '%' | '|' | '&' | '^' => {
                            code.get(k + 1) == Some(&'=')
                        }
                        _ => false,
                    });
                    if deref && assigns {
                        found.push(pos);
                    }
                }
            }
            found
        }

        /// The root name of the receiver expression that ends at `dot`.
        fn receiver_root(code: &[char], dot: usize) -> String {
            receiver_expr(code, dot)
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .find(|w| !w.is_empty())
                .unwrap_or_default()
                .to_owned()
        }

        /// The 1-based lines of `src` that copy into a caller buffer other
        /// than inside a function named in `allowed`: any
        /// `copy_nonoverlapping(`, `copy_from_nonoverlapping(`,
        /// `copy_to_nonoverlapping(`, `ptr::copy(`, `.copy_from(`,
        /// `.copy_to(`, `ptr::write(`, `ptr::write_unaligned(`,
        /// `ptr::write_volatile(`, `.write_unaligned(` or `.write_volatile(`
        /// call; any `.write(` whose receiver offsets a pointer with one of
        /// [`POINTER_OFFSETS`]; any assignment through such a
        /// pointer, as in `*p.add(i) = v`; any `write_bytes(`
        /// outside [`super::WRITE_BYTES_ALLOWED`]; and any `.copy_from_slice(` or
        /// `.clone_from_slice(` whose receiver is a name the enclosing
        /// function binds from `slice_from_raw_mut` or `from_raw_parts_mut`.
        /// With `slices_handed_on`, also any such name passed as an argument
        /// to a call outside [`super::HANDED_ON_ALLOWED`]: the caller's buffer
        /// handed to a library call that may write into it.
        pub(super) fn raw_output_copies(
            src: &str,
            allowed: &[&str],
            slices_handed_on: bool,
        ) -> Vec<usize> {
            let code = code_only(src);
            let bodies = fn_bodies(&code);
            let enclosing = |pos: usize| {
                bodies
                    .iter()
                    .filter(|(_, open, close)| *open < pos && pos < *close)
                    .max_by_key(|(_, open, _)| *open)
            };
            let line = |pos: usize| code[..pos].iter().filter(|&&c| c == '\n').count() + 1;
            let mut flagged = Vec::new();
            let in_allowed = |pos: usize, extra: &[&str]| {
                enclosing(pos).is_some_and(|(name, _, _)| {
                    allowed.contains(&name.as_str()) || extra.contains(&name.as_str())
                })
            };
            let copies = occurrences(&code, "copy_nonoverlapping(")
                .into_iter()
                .chain(occurrences(&code, "copy_from_nonoverlapping("))
                .chain(occurrences(&code, "copy_to_nonoverlapping("))
                .chain(occurrences(&code, "ptr::copy("))
                .chain(occurrences(&code, ".copy_from("))
                .chain(occurrences(&code, ".copy_to("))
                .chain(occurrences(&code, "ptr::write("))
                .chain(occurrences(&code, "ptr::write_unaligned("))
                .chain(occurrences(&code, "ptr::write_volatile("))
                .chain(occurrences(&code, ".write_unaligned("))
                .chain(occurrences(&code, ".write_volatile("))
                .chain(offset_deref_assignments(&code));
            for pos in copies {
                if !in_allowed(pos, &[]) {
                    flagged.push(line(pos));
                }
            }
            for pos in occurrences(&code, ".write(") {
                if offsets_pointer(&code, pos) && !in_allowed(pos, &[]) {
                    flagged.push(line(pos));
                }
            }
            for pos in occurrences(&code, "write_bytes(") {
                if !in_allowed(pos, super::WRITE_BYTES_ALLOWED) {
                    flagged.push(line(pos));
                }
            }
            let slice_copies = occurrences(&code, ".copy_from_slice(")
                .into_iter()
                .chain(occurrences(&code, ".clone_from_slice("));
            for pos in slice_copies {
                let Some((name, open, close)) = enclosing(pos) else {
                    continue;
                };
                if allowed.contains(&name.as_str()) {
                    continue;
                }
                if raw_bound(&code, *open, *close).contains(&receiver_root(&code, pos)) {
                    flagged.push(line(pos));
                }
            }
            if slices_handed_on {
                let handed_on_allowed: Vec<&str> = allowed
                    .iter()
                    .chain(super::HANDED_ON_ALLOWED)
                    .copied()
                    .collect();
                flagged.extend(raw_slices_handed_on(&code, &bodies, &handed_on_allowed));
            }
            flagged.sort_unstable();
            flagged.dedup();
            flagged
        }
    }

    /// The scan behind [`no_raw_output_copies`] flags each pattern it
    /// names, and nothing in code that copies only into its own memory.
    #[test]
    fn raw_output_copy_scan_flags_each_pattern() {
        use output_copy_scan::raw_output_copies;

        let raw = r"
fn into_slice(p: *mut u8, n: usize) -> c_int {
    let buf = [0u8; 4];
    let out = unsafe { slice_from_raw_mut(p, n)? };
    out.copy_from_slice(&buf);
    0
}
fn into_pointer(a: *const u8, b: *mut u8, n: usize) {
    unsafe { core::ptr::copy_nonoverlapping(a, b, n) };
}
";
        assert_eq!(
            raw_output_copies(raw, DIRECT_COPY_ALLOWED, true),
            vec![5, 9]
        );
        let local = r"
fn into_local(b: &[u8]) {
    let mut a = [0u8; 4];
    a.copy_from_slice(b);
}
";
        assert_eq!(
            raw_output_copies(local, DIRECT_COPY_ALLOWED, true),
            Vec::<usize>::new()
        );
        // A caller-derived slice passed to any call is flagged, whether the
        // callee writes into it or only reads it: the scan cannot tell the
        // two apart, so any argument use counts.
        let handed_on = r"
fn into_kdf(p: *mut u8, n: usize) -> c_int {
    let out = unsafe { slice_from_raw_mut(p, n)? };
    kdf(&mut key, out);
    0
}
fn into_reader(p: *mut u8, n: usize) {
    let out = unsafe { slice_from_raw_mut(p, n)? };
    checksum(out);
}
";
        assert_eq!(
            raw_output_copies(handed_on, DIRECT_COPY_ALLOWED, true),
            vec![4, 9]
        );
        assert_eq!(
            raw_output_copies(handed_on, DIRECT_COPY_ALLOWED, false),
            Vec::<usize>::new()
        );
        // One positive fixture per further pattern, each a write into a
        // caller pointer or slice outside `write_out`.
        let widened = r"
fn from_pointer(a: *const u8, b: *mut u8, n: usize) {
    unsafe { b.copy_from_nonoverlapping(a, n) };
}
fn to_pointer(a: *const u8, b: *mut u8, n: usize) {
    unsafe { a.copy_to_nonoverlapping(b, n) };
}
fn at_offset(b: *mut u8, i: usize) {
    unsafe { b.add(i).write(7) };
}
fn by_clone(p: *mut u8, n: usize) {
    let out = unsafe { slice_from_raw_mut(p, n)? };
    out.clone_from_slice(&[0u8; 4]);
}
fn by_fill(b: *mut u8, n: usize) {
    unsafe { core::ptr::write_bytes(b, 0, n) };
}
fn zero_out(b: *mut u8, n: usize) {
    unsafe { core::ptr::write_bytes(b, 0, n) };
}
fn plain_write(b: *mut u8) {
    unsafe { b.write(7) };
}
";
        assert_eq!(
            raw_output_copies(widened, DIRECT_COPY_ALLOWED, false),
            vec![3, 6, 9, 13, 16]
        );
        // The handed-on exemption covers `wipe_and_free` by name only.
        let wipe = r"
fn wipe_and_free(h: *mut u8, n: usize) {
    let all = unsafe { core::slice::from_raw_parts_mut(h, n) };
    zeroize(all);
}
fn wipe_other(h: *mut u8, n: usize) {
    let all = unsafe { core::slice::from_raw_parts_mut(h, n) };
    zeroize(all);
}
";
        assert_eq!(raw_output_copies(wipe, DIRECT_COPY_ALLOWED, true), vec![8]);
    }

    /// The scan behind [`no_raw_output_copies`] flags each pointer write it
    /// names, and no read, comparison or offset arithmetic.
    #[test]
    fn raw_output_copy_scan_flags_pointer_writes() {
        use output_copy_scan::raw_output_copies;

        // One positive fixture per pointer write, then reads, comparisons and
        // offset arithmetic that write nothing.
        let pointer_writes = r"
fn deref_add(b: *mut u8, i: usize) {
    unsafe { *b.add(i) = 7 };
}
fn deref_offset_paren(b: *mut u8, i: isize) {
    unsafe { *(b.offset(i)) = 7 };
}
fn deref_wrapping_or(b: *mut u8, i: usize) {
    unsafe { *b.wrapping_add(i) |= 7 };
}
fn free_write(b: *mut u8) {
    unsafe { core::ptr::write(b, 7) };
}
fn method_unaligned(b: *mut u32) {
    unsafe { b.write_unaligned(7) };
}
fn method_volatile(b: *mut u8) {
    unsafe { b.write_volatile(7) };
}
fn method_copy_from(a: *const u8, b: *mut u8, n: usize) {
    unsafe { b.copy_from(a, n) };
}
fn method_copy_to(a: *const u8, b: *mut u8, n: usize) {
    unsafe { a.copy_to(b, n) };
}
fn write_at_offset(b: *mut u8, i: isize) {
    unsafe { b.offset(i).write(7) };
}
fn write_at_wrapping(b: *mut u8, i: usize) {
    unsafe { b.wrapping_add(i).write(7) };
}
fn free_unaligned(b: *mut u32) {
    unsafe { core::ptr::write_unaligned(b, 7) };
}
fn free_volatile(b: *mut u8) {
    unsafe { core::ptr::write_volatile(b, 7) };
}
fn deref_sub(b: *mut u8, i: usize) {
    unsafe { *b.sub(i) = 7 };
}
fn write_at_wrapping_sub(b: *mut u8, i: usize) {
    unsafe { b.wrapping_sub(i).write(7) };
}
fn deref_wrapping_offset(b: *mut u8, i: isize) {
    unsafe { *b.wrapping_offset(i) = 7 };
}
fn write_at_byte_add(b: *mut u8, i: usize) {
    unsafe { b.byte_add(i).write(7) };
}
fn deref_byte_sub_xor(b: *mut u8, i: usize) {
    unsafe { *b.byte_sub(i) ^= 7 };
}
fn write_at_byte_offset(b: *mut u8, i: isize) {
    unsafe { b.byte_offset(i).write(7) };
}
fn reads_only(a: *const u8, i: usize, own: u64) -> bool {
    let v = unsafe { *a.add(i) };
    let w = unsafe { *a.byte_sub(i) };
    let next = own.wrapping_add(1);
    let prev = own.wrapping_sub(1);
    unsafe { *a.add(i) == v && *a.sub(i) != w && next > prev }
}
";
        assert_eq!(
            raw_output_copies(pointer_writes, DIRECT_COPY_ALLOWED, false),
            vec![
                3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48, 51, 54
            ]
        );
    }

    /// Every copy into a caller buffer in this crate goes through
    /// [`write_out`], so the module's operational state is re-checked
    /// immediately before any output leaves it.
    #[test]
    fn no_raw_output_copies() {
        use output_copy_scan::raw_output_copies;

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
            .map(|entry| entry.unwrap_or_else(|e| panic!("{e}")).path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .collect();
        files.sort();
        let mut flagged = Vec::new();
        let mut unexempted = 0;
        let mut handed_on = Vec::new();
        for path in &files {
            let src = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            // The handed-on rule covers the AES mode symbols in `aes.rs`, the
            // algorithm symbols in `lib.rs` and the DRBG symbols in
            // `drbg.rs` and `rbg.rs`.
            let slices_handed_on = path.ends_with("aes.rs")
                || path.ends_with("lib.rs")
                || path.ends_with("drbg.rs")
                || path.ends_with("rbg.rs");
            unexempted += raw_output_copies(&src, &[], false).len();
            let file = path.file_name().unwrap_or_default().to_string_lossy();
            if slices_handed_on {
                handed_on.push((
                    file.to_string(),
                    raw_output_copies(&src, DIRECT_COPY_ALLOWED, true),
                ));
            }
            for line in raw_output_copies(&src, DIRECT_COPY_ALLOWED, slices_handed_on) {
                flagged.push(format!("src/{file}:{line}"));
            }
        }
        assert!(
            files.iter().any(|p| p.ends_with("lib.rs"))
                && files.iter().any(|p| p.ends_with("rbg.rs")),
            "the scan did not reach lib.rs and rbg.rs"
        );
        assert!(
            flagged.is_empty(),
            "copies into a caller buffer outside write_out:\n{}",
            flagged.join("\n")
        );
        let held: Vec<&str> = handed_on.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(
            held,
            ["aes.rs", "drbg.rs", "lib.rs", "rbg.rs"],
            "the handed-on rule did not reach exactly its four files"
        );
        for (file, lines) in &handed_on {
            assert!(
                lines.is_empty(),
                "src/{file} copies into or hands on a caller-derived slice at lines {lines:?}"
            );
        }
        // `write_out` and the two status outputs each copy once, and the
        // status detail writes its terminator at an offset.
        assert_eq!(
            unexempted, 4,
            "the scan no longer sees the permitted copies"
        );
    }
}
