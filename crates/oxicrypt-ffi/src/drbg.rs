//! C ABI for the nine SP 800-90A DRBGs as typed handles, seeded by the
//! module.
//!
//! Each DRBG has its own handle type and functions: HMAC_DRBG with
//! SHA-256, SHA-384 and SHA-512, Hash_DRBG with the same three hashes, and
//! CTR_DRBG with AES-128, AES-192 and AES-256. The HMAC_DRBG-SHA-256 handle
//! is the one the rest of the C ABI takes as a parameter (ECDSA, ECDH, RSA
//! and DH key generation and signing).
//!
//! # Lifecycle
//!
//! ```text
//!   oxi_hmac_drbg_sha256_new(&handle)
//!     → an uninstantiated handle
//!
//!   oxi_hmac_drbg_sha256_instantiate_from_module(handle, perso, perso_len)
//!     → instantiates from the module's seed path and records the
//!       calling process's id
//!
//!   oxi_hmac_drbg_sha256_generate(handle, additional, additional_len, out, out_len)
//!     → output; the DRBG reseeds itself from the seed path when it
//!       reaches the SP 800-90A reseed interval
//!
//!   oxi_hmac_drbg_sha256_reseed_from_module(handle, additional, additional_len)
//!     → an explicit reseed from the seed path
//!
//!   oxi_hmac_drbg_sha256_free(handle)
//!     → NULL-safe; the DRBG state is zeroized as it is dropped
//! ```
//!
//! The caller supplies no entropy. A CTR_DRBG handle is always instantiated
//! through the derivation function, so its generate function is
//! `_generate_df`.
//!
//! # Check order
//!
//! `_instantiate_from_module`, `_reseed_from_module` and `_generate` check
//! in the order the shared `OxiDrbg` handle uses, and return the first
//! failure:
//!
//! 1. A NULL handle returns `NullPointer = 10`. An optional input of
//!    `_instantiate_from_module` or `_reseed_from_module` that is NULL with
//!    a non-zero length, or longer than `isize::MAX`, returns
//!    `InvalidInput = 5`. `_generate` returns `NullPointer = 10` for a NULL
//!    output or additional input with a non-zero length, and
//!    `InvalidInput = 5` for additional input longer than `isize::MAX`.
//! 2. A module that is not operational returns `NotOperational = 1`.
//! 3. A DRBG the active profile does not allow returns
//!    `AlgorithmRestricted = 6`.
//! 4. A handle instantiated by another process returns `InvalidInput = 5`.
//!    `_instantiate_from_module` skips this check and the next: it takes
//!    over a handle inherited across fork and replaces its state.
//! 5. A handle never instantiated with `_instantiate_from_module` returns
//!    `Uninstantiated = 8`.
//! 6. An input the DRBG would refuse returns `InvalidInput = 5`.
//! 7. The operation itself returns the DRBG's own codes, among them
//!    `OutputTooLong = 12` (`_generate` refuses a request above 65536 bytes
//!    before allocating it), `Busy = 32` (the seed path was held too long)
//!    and `EntropyUnavailable = 33`. A handle seeded by the module reseeds
//!    itself, so `ReseedRequired = 9` never occurs.
//!
//! Output is written only on success.
//!
//! # Thread-safety contract
//!
//! Every call on a typed handle advances its DRBG's state, and the handle
//! has no busy flag: two C threads calling into the same handle at once is
//! a data race and undefined behaviour. **Callers MUST serialise all calls
//! on one handle** (a mutex, single-threaded ownership, or an equivalent
//! discipline). The shared `OxiDrbg` handle detects concurrent use instead.
//!
//! # Fork
//!
//! A handle records the id of the process that instantiated it. After fork,
//! the child's copy returns `InvalidInput = 5` from every call that reaches
//! the DRBG until the child calls `_instantiate_from_module` on it, so
//! parent and child never produce the same output. A process id reused
//! after the parent exits is not detected.
//!
//! # Handle lifecycle invariant
//!
//! `OxiHmacDrbgSha256` follows the same opaque-handle pattern as
//! `OxiAes256Key` (see `aes.rs`). The internal state lives on the
//! heap; the caller holds a `*mut OxiHmacDrbgSha256` and MUST pair
//! every `_new` with a `_free`.

use crate::error::{OxiResult as R, status_module};
use crate::handle::OxiHandle;
use crate::rbg::{MAX_REQUEST_BYTES, write_out};
use core::ffi::c_int;
use core::sync::atomic::Ordering;
use oxicrypt_drbg::{
    CtrDrbgAes128, CtrDrbgAes192, CtrDrbgAes256, DrbgError, HashDrbgSha256, HashDrbgSha384,
    HashDrbgSha512, HmacDrbgSha256, HmacDrbgSha384, HmacDrbgSha512,
};
use oxicrypt_module::{Error, Service};

/// The calling process's id as a handle records it. It is never 0, so a
/// recorded 0 always means the handle was never instantiated, including on
/// a target without process ids.
fn current_process() -> u64 {
    oxicrypt_platform::process_id().max(1)
}

/// One of the nine typed DRBG handles, each holding its DRBG in an
/// [`OxiHandle`].
pub(crate) trait TypedDrbg {
    /// The DRBG the handle holds.
    type Inner;
    /// The handle's state: the DRBG and the process id recorded when it was
    /// instantiated.
    fn handle(&mut self) -> &mut OxiHandle<Self::Inner>;
}

/// Reaches the DRBG a typed handle holds, the one path every function that
/// uses a typed handle's DRBG takes.
///
/// It returns, in this order, `NullPointer` for a NULL `h`, `InvalidInput`
/// for a handle instantiated by another process (a copy inherited across
/// fork), and `Uninstantiated` for a handle never instantiated with
/// `_instantiate_from_module`.
///
/// Its callers place the module checks in one of two ways:
///
/// - `_reseed_from_module` and `_generate` check their pointers, then run
///   `require_operational` and `require_allowed`, then call this. A module
///   that is not operational returns `NotOperational = 1` from them
///   whatever the handle's state.
/// - The key generation, signing and encryption functions that take a
///   typed handle (ECDH, ECDSA, RSA and DH) check their pointers, call
///   this, and then call the service, which runs `require_operational`
///   and `require_allowed` itself before it draws from the DRBG. A module
///   that is not operational returns `NotOperational = 1` from them only
///   for a handle this process instantiated; a handle from another process
///   returns `InvalidInput = 5` and one never instantiated returns
///   `Uninstantiated = 8` first.
///
/// # Safety
///
/// `h` must be NULL or a live handle that nothing else reaches while the
/// returned borrow is used. The `'static` lifetime is not a promise: the
/// caller must not use the borrow after the C call it serves returns.
pub(crate) unsafe fn typed_drbg_access<H: TypedDrbg>(
    h: *mut H,
) -> Result<&'static mut H::Inner, R> {
    if h.is_null() {
        return Err(R::NullPointer);
    }
    // SAFETY: `h` is non-NULL and, by contract, a live handle nothing else
    // reaches during the call.
    let handle: *mut OxiHandle<H::Inner> = unsafe { (*h).handle() };
    // SAFETY: as above; the caller confines the borrow to the call it serves.
    let handle = unsafe { &mut *handle };
    let recorded = handle.pid.load(Ordering::Acquire);
    if recorded != 0 && recorded != current_process() {
        return Err(R::InvalidInput);
    }
    if recorded == 0 {
        return Err(R::Uninstantiated);
    }
    handle.as_mut().ok_or(R::Internal)
}

/// Borrows an optional caller input, which may be NULL only with length 0.
/// A NULL pointer with a non-zero length, or a length above `isize::MAX`,
/// returns `InvalidInput`.
///
/// # Safety
///
/// A non-NULL `ptr` must be valid for reads of `len` bytes for `'a`.
unsafe fn optional_input<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], R> {
    if len > isize::MAX.unsigned_abs() || (ptr.is_null() && len > 0) {
        return Err(R::InvalidInput);
    }
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: `ptr` is non-NULL here and the caller guarantees it is valid
    // for `len` bytes; `len` is at most `isize::MAX`.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// The body of every `_instantiate_from_module` function. Checks the handle,
/// the personalization string, the module state and the profile, then builds
/// a new instance with `instantiate`. On success it replaces the handle's
/// DRBG and records the calling process's id; on failure the handle is
/// unchanged.
///
/// # Safety
///
/// `h` must be NULL or a live handle nothing else reaches during the call.
/// A non-NULL `perso` must be valid for reads of `perso_len` bytes.
unsafe fn instantiate_typed<H: TypedDrbg>(
    h: *mut H,
    perso: *const u8,
    perso_len: usize,
    service: Service,
    instantiate: impl FnOnce(&[u8]) -> Result<H::Inner, Error>,
) -> c_int {
    if h.is_null() {
        return R::NullPointer as c_int;
    }
    // SAFETY: a non-NULL `perso` is valid for `perso_len` bytes by contract.
    let perso = match unsafe { optional_input(perso, perso_len) } {
        Ok(p) => p,
        Err(e) => return e as c_int,
    };
    if let Err(e) = oxicrypt_module::require_operational() {
        return R::from(e) as c_int;
    }
    if let Err(e) = oxicrypt_module::require_allowed(service) {
        return R::from(e) as c_int;
    }
    let drbg = match instantiate(perso) {
        Ok(d) => d,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `h` is non-NULL and, by contract, a live handle nothing else
    // reaches during the call.
    let handle = unsafe { (*h).handle() };
    handle.inner = Some(drbg);
    handle.pid.store(current_process(), Ordering::Release);
    R::Ok as c_int
}

/// The body of every `_reseed_from_module` function. Checks the handle, the
/// additional input, the module state and the profile, reaches the DRBG
/// through [`typed_drbg_access`], then reseeds it with `reseed`.
///
/// # Safety
///
/// `h` must be NULL or a live handle nothing else reaches during the call.
/// A non-NULL `additional` must be valid for reads of `additional_len`
/// bytes.
unsafe fn reseed_typed<H: TypedDrbg>(
    h: *mut H,
    additional: *const u8,
    additional_len: usize,
    service: Service,
    reseed: impl FnOnce(&mut H::Inner, &[u8]) -> Result<(), Error>,
) -> c_int
where
    H::Inner: 'static,
{
    if h.is_null() {
        return R::NullPointer as c_int;
    }
    // SAFETY: a non-NULL `additional` is valid for `additional_len` bytes by
    // contract.
    let additional = match unsafe { optional_input(additional, additional_len) } {
        Ok(a) => a,
        Err(e) => return e as c_int,
    };
    if let Err(e) = oxicrypt_module::require_operational() {
        return R::from(e) as c_int;
    }
    if let Err(e) = oxicrypt_module::require_allowed(service) {
        return R::from(e) as c_int;
    }
    // SAFETY: `h` is a live handle nothing else reaches during the call, by
    // contract; the borrow ends with this function.
    let drbg = match unsafe { typed_drbg_access(h) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    status_module(reseed(drbg, additional))
}

/// The body of every `_generate` function. Checks the handle and the output
/// and additional-input pointers, the module state and the profile, reaches
/// the DRBG through [`typed_drbg_access`], refuses additional input longer
/// than `max_additional`, then generates through [`staged`].
///
/// # Safety
///
/// `h` must be NULL or a live handle nothing else reaches during the call.
/// `out` must be valid for writes of `out_len` bytes. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[allow(
    clippy::too_many_arguments,
    reason = "the five C arguments plus the DRBG's service, bound and generate function"
)]
unsafe fn generate_typed<H: TypedDrbg>(
    h: *mut H,
    additional: *const u8,
    additional_len: usize,
    out: *mut u8,
    out_len: usize,
    service: Service,
    max_additional: usize,
    generate: impl FnOnce(&mut H::Inner, Option<&[u8]>, &mut [u8]) -> Result<(), DrbgError>,
) -> c_int
where
    H::Inner: 'static,
{
    if h.is_null() || (out.is_null() && out_len > 0) {
        return R::NullPointer as c_int;
    }
    // NULL with a non-zero length is refused by slice_from_raw with NullPointer.
    let additional: Option<&[u8]> = if additional.is_null() && additional_len == 0 {
        None
    } else {
        // SAFETY: a non-NULL `additional` is valid for `additional_len`
        // bytes by contract.
        match unsafe { crate::slice_from_raw(additional, additional_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    if let Err(e) = oxicrypt_module::require_operational() {
        return R::from(e) as c_int;
    }
    if let Err(e) = oxicrypt_module::require_allowed(service) {
        return R::from(e) as c_int;
    }
    // SAFETY: `h` is a live handle nothing else reaches during the call, by
    // contract; the borrow ends with this function.
    let drbg = match unsafe { typed_drbg_access(h) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    if additional_len > max_additional {
        return R::InvalidInput as c_int;
    }
    // Refused before the private buffer is allocated, so a request of any
    // length costs no allocation of that length.
    if out_len > MAX_REQUEST_BYTES {
        return R::OutputTooLong as c_int;
    }
    // SAFETY: `out` is valid for writes of `out_len` bytes by contract.
    unsafe { staged(out, out_len, |buf| generate(drbg, additional, buf)) }
}

/// Runs a generate call into a private buffer and copies the bytes to the
/// caller's buffer at `out` through [`write_out`] only once the call has
/// succeeded, so a failed call, or a module that entered its error state
/// meanwhile, never writes generated bytes there. The private buffer is
/// wiped either way; no test observes that wipe, so it is unproven.
///
/// # Safety
///
/// `out` must be valid for writes of `out_len` bytes; it may be NULL only
/// when `out_len` is 0.
unsafe fn staged(
    out: *mut u8,
    out_len: usize,
    generate: impl FnOnce(&mut [u8]) -> Result<(), DrbgError>,
) -> c_int {
    let mut buf = vec![0u8; out_len];
    let result = generate(&mut buf).map_err(R::from).and_then(|()| {
        // SAFETY: `out` is valid for `out_len` bytes by contract, the
        // generate call filled all `out_len` bytes of `buf`, and `buf` is this
        // function's own allocation, so the two do not overlap.
        unsafe { write_out(out, &buf) }
    });
    oxicrypt_zeroize::zeroize(&mut buf);
    match result {
        Ok(()) => R::Ok as c_int,
        Err(e) => e as c_int,
    }
}

/// Opaque HMAC_DRBG-SHA-256 handle. The internal layout
/// (`OxiHandle<HmacDrbgSha256>`) is implementation detail and not
/// part of the C ABI; cbindgen renders this as an opaque struct.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiHmacDrbgSha256 {
    inner: OxiHandle<HmacDrbgSha256>,
}

impl TypedDrbg for OxiHmacDrbgSha256 {
    type Inner = HmacDrbgSha256;
    fn handle(&mut self) -> &mut OxiHandle<HmacDrbgSha256> {
        &mut self.inner
    }
}

/// Allocate a new, **uninstantiated** HMAC_DRBG-SHA-256 handle.
///
/// On success, writes a heap-allocated handle pointer through
/// `out_handle` and returns `OxiResult::Ok = 0`. The caller owns
/// the handle and MUST release it with [`oxi_hmac_drbg_sha256_free`].
///
/// The newly-allocated handle is uninstantiated — calling
/// [`oxi_hmac_drbg_sha256_generate`] or
/// [`oxi_hmac_drbg_sha256_reseed_from_module`] before
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`] returns
/// `OxiResult::Uninstantiated = 8`.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHmacDrbgSha256`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_new(
    out_handle: *mut *mut OxiHmacDrbgSha256,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHmacDrbgSha256 {
        inner: OxiHandle::new(HmacDrbgSha256::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an HMAC_DRBG-SHA-256 handle. NULL-safe.
///
/// After this call the caller's pointer is dangling; the caller
/// SHOULD set their pointer to NULL to avoid use-after-free. A
/// double-free of the same non-NULL pointer is undefined behaviour
/// (matches malloc/free semantics — the shim cannot detect it).
///
/// Drop on the upstream `HmacDrbgSha256` zeroizes the internal
/// `(K, V)` state via the workspace-wide `oxicrypt-zeroize`
/// volatile-write convention, and every byte of the handle is then wiped
/// before its memory is released; no caller-side scrubbing is required.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hmac_drbg_sha256_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_free(handle: *mut OxiHmacDrbgSha256) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// HMAC_DRBG-SHA-256 Instantiate from the module's seed path
/// (SP 800-90A §10.1.2.3), with an optional personalization string.
///
/// Draws the entropy input and nonce from the module's seed path,
/// replaces any earlier instantiation of the handle and records the
/// calling process's id. In a forked child this is the call that makes
/// an inherited handle usable again.
///
/// `perso` may be NULL when `perso_len` is 0; NULL with a non-zero length
/// returns `OxiResult::InvalidInput = 5`. A personalization string longer
/// than the DRBG accepts returns `InvalidInput = 5` before any draw. A
/// failed draw returns `OxiResult::Busy = 32` (retry after a pause) or
/// `OxiResult::EntropyUnavailable = 33`. Every refusal leaves the handle
/// as it was.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha256_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_instantiate_from_module(
    handle: *mut OxiHmacDrbgSha256,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::HmacDrbgSha256,
            HmacDrbgSha256::instantiate_from_module,
        )
    }
}

/// HMAC_DRBG-SHA-256 Reseed from the module's seed path
/// (SP 800-90A §10.1.2.4), with optional additional input.
///
/// `additional` may be NULL when `additional_len` is 0; NULL with a
/// non-zero length returns `OxiResult::InvalidInput = 5`. A handle never
/// instantiated with [`oxi_hmac_drbg_sha256_instantiate_from_module`]
/// returns `OxiResult::Uninstantiated = 8`, and a handle instantiated by
/// another process returns `InvalidInput = 5`. Additional input longer
/// than the DRBG accepts returns `InvalidInput = 5` before any draw. A
/// failed draw returns `OxiResult::Busy = 32` or
/// `OxiResult::EntropyUnavailable = 33`.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha256_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_reseed_from_module(
    handle: *mut OxiHmacDrbgSha256,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::HmacDrbgSha256,
            HmacDrbgSha256::reseed_from_module,
        )
    }
}

/// HMAC_DRBG-SHA-256 Generate (SP 800-90A §10.1.2.5).
///
/// Produces `out_len` pseudorandom bytes into `out`. The DRBG reseeds
/// itself from the module's seed path when it reaches the SP 800-90A
/// reseed interval, so `OxiResult::ReseedRequired = 9` never occurs.
///
/// `additional_input` may be NULL when `additional_input_len` is 0
/// (mapped to upstream `additional_input = None`); a NULL with
/// non-zero length returns `OxiResult::NullPointer = 10`.
///
/// Returns `OxiResult::Uninstantiated = 8` if the handle was never
/// instantiated with [`oxi_hmac_drbg_sha256_instantiate_from_module`],
/// and `OxiResult::InvalidInput = 5` if it was instantiated by another
/// process or `additional_input_len` exceeds the additional input the
/// DRBG accepts from a module reseed. Returns
/// `OxiResult::OutputTooLong = 12` if `out_len` exceeds the
/// SP 800-90A Table 3 `max_number_of_bits_per_request` ceiling
/// (`2^19` bits = 65 536 bytes). `out` is written only on success.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha256_new`], not in use by another call.
/// `out` must point to ≥ `out_len` writable bytes (or `out_len == 0`).
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_generate(
    handle: *mut OxiHmacDrbgSha256,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::HmacDrbgSha256,
            HmacDrbgSha256::MAX_MODULE_ADDITIONAL_INPUT,
            HmacDrbgSha256::generate,
        )
    }
}

// ── HMAC-DRBG-SHA-384 / -SHA-512 ─────────────────────────────────
//
// The `OxiHmacDrbgSha256` shape for the wider HMAC-DRBG hashes
// (SP 800-90A §10.1.2), over the upstream `HmacDrbg<H: HmacAlg>` type
// aliases `HmacDrbgSha384` and `HmacDrbgSha512`. Output lengths are
// wider; both are instantiated at 256-bit security strength (SP 800-57
// Part 1, SP 800-90A Table 2); the
// `instantiate_from_module / reseed_from_module / generate` shape is
// identical. Same per-call-mutating thread-safety contract, same
// `(K, V, reseed_counter)` Drop-zeroize, same check order; see the
// SHA-256 rustdocs above for the full contract — comments here cite only
// hash-specific deltas.

/// Opaque HMAC_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiHmacDrbgSha384 {
    inner: OxiHandle<HmacDrbgSha384>,
}

impl TypedDrbg for OxiHmacDrbgSha384 {
    type Inner = HmacDrbgSha384;
    fn handle(&mut self) -> &mut OxiHandle<HmacDrbgSha384> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated HMAC_DRBG-SHA-384 handle. See
/// [`oxi_hmac_drbg_sha256_new`] for full contract.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHmacDrbgSha384`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_new(
    out_handle: *mut *mut OxiHmacDrbgSha384,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHmacDrbgSha384 {
        inner: OxiHandle::new(HmacDrbgSha384::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an HMAC_DRBG-SHA-384 handle. NULL-safe. See
/// [`oxi_hmac_drbg_sha256_free`] for zeroization semantics.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hmac_drbg_sha384_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_free(handle: *mut OxiHmacDrbgSha384) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// HMAC_DRBG-SHA-384 Instantiate from the module's seed path
/// (SP 800-90A §10.1.2.3). See
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
/// The instantiated security strength is 256 bits (SP 800-57 Part 1).
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha384_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_instantiate_from_module(
    handle: *mut OxiHmacDrbgSha384,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::HmacDrbgSha384,
            HmacDrbgSha384::instantiate_from_module,
        )
    }
}

/// HMAC_DRBG-SHA-384 Reseed from the module's seed path
/// (SP 800-90A §10.1.2.4). See
/// [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha384_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_reseed_from_module(
    handle: *mut OxiHmacDrbgSha384,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::HmacDrbgSha384,
            HmacDrbgSha384::reseed_from_module,
        )
    }
}

/// HMAC_DRBG-SHA-384 Generate (SP 800-90A §10.1.2.5). See
/// [`oxi_hmac_drbg_sha256_generate`] for full contract; the
/// `out_len` ceiling is the alg-independent
/// `max_number_of_bits_per_request` = `2^19` bits = 65 536 bytes.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha384_new`], not in use by another call.
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_generate(
    handle: *mut OxiHmacDrbgSha384,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::HmacDrbgSha384,
            HmacDrbgSha384::MAX_MODULE_ADDITIONAL_INPUT,
            HmacDrbgSha384::generate,
        )
    }
}

/// Opaque HMAC_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiHmacDrbgSha512 {
    inner: OxiHandle<HmacDrbgSha512>,
}

impl TypedDrbg for OxiHmacDrbgSha512 {
    type Inner = HmacDrbgSha512;
    fn handle(&mut self) -> &mut OxiHandle<HmacDrbgSha512> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated HMAC_DRBG-SHA-512 handle. See
/// [`oxi_hmac_drbg_sha256_new`] for full contract.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHmacDrbgSha512`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_new(
    out_handle: *mut *mut OxiHmacDrbgSha512,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHmacDrbgSha512 {
        inner: OxiHandle::new(HmacDrbgSha512::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an HMAC_DRBG-SHA-512 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hmac_drbg_sha512_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_free(handle: *mut OxiHmacDrbgSha512) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// HMAC_DRBG-SHA-512 Instantiate from the module's seed path
/// (SP 800-90A §10.1.2.3). See
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
/// The instantiated security strength is 256 bits, with a wider internal
/// `(K, V)` of 64 bytes each.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha512_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_instantiate_from_module(
    handle: *mut OxiHmacDrbgSha512,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::HmacDrbgSha512,
            HmacDrbgSha512::instantiate_from_module,
        )
    }
}

/// HMAC_DRBG-SHA-512 Reseed from the module's seed path
/// (SP 800-90A §10.1.2.4). See
/// [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha512_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_reseed_from_module(
    handle: *mut OxiHmacDrbgSha512,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::HmacDrbgSha512,
            HmacDrbgSha512::reseed_from_module,
        )
    }
}

/// HMAC_DRBG-SHA-512 Generate (SP 800-90A §10.1.2.5). See
/// [`oxi_hmac_drbg_sha256_generate`].
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hmac_drbg_sha512_new`], not in use by another call.
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_generate(
    handle: *mut OxiHmacDrbgSha512,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::HmacDrbgSha512,
            HmacDrbgSha512::MAX_MODULE_ADDITIONAL_INPUT,
            HmacDrbgSha512::generate,
        )
    }
}

// ── Hash-DRBG-SHA-256 / -SHA-384 / -SHA-512 ──────────────────────
//
// SP 800-90A §10.1.1 Hash_DRBG family, in the shape of
// `OxiHmacDrbgSha{256,384,512}` above, over the upstream
// `HashDrbg<H: HashAlg>` type aliases `HashDrbgSha{256,384,512}`. The
// `instantiate_from_module / reseed_from_module / generate` signatures
// are identical to the HMAC-DRBG family. Per SP 800-90A Table 2,
// security strengths match HMAC: 256 bits for SHA-256, SHA-384 and
// SHA-512 (SP 800-57 Part 1).

/// Opaque Hash_DRBG-SHA-256 handle. See `OxiHmacDrbgSha256`.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiHashDrbgSha256 {
    inner: OxiHandle<HashDrbgSha256>,
}

impl TypedDrbg for OxiHashDrbgSha256 {
    type Inner = HashDrbgSha256;
    fn handle(&mut self) -> &mut OxiHandle<HashDrbgSha256> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated Hash_DRBG-SHA-256 handle. See
/// [`oxi_hmac_drbg_sha256_new`] for full contract.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHashDrbgSha256`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_new(
    out_handle: *mut *mut OxiHashDrbgSha256,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHashDrbgSha256 {
        inner: OxiHandle::new(HashDrbgSha256::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a Hash_DRBG-SHA-256 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hash_drbg_sha256_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_free(handle: *mut OxiHashDrbgSha256) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// Hash_DRBG-SHA-256 Instantiate from the module's seed path
/// (SP 800-90A §10.1.1.2). See
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha256_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_instantiate_from_module(
    handle: *mut OxiHashDrbgSha256,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::HashDrbgSha256,
            HashDrbgSha256::instantiate_from_module,
        )
    }
}

/// Hash_DRBG-SHA-256 Reseed from the module's seed path
/// (SP 800-90A §10.1.1.3). See
/// [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha256_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_reseed_from_module(
    handle: *mut OxiHashDrbgSha256,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::HashDrbgSha256,
            HashDrbgSha256::reseed_from_module,
        )
    }
}

/// Hash_DRBG-SHA-256 Generate (SP 800-90A §10.1.1.4). See
/// [`oxi_hmac_drbg_sha256_generate`].
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha256_new`], not in use by another call.
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_generate(
    handle: *mut OxiHashDrbgSha256,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::HashDrbgSha256,
            HashDrbgSha256::MAX_MODULE_ADDITIONAL_INPUT,
            HashDrbgSha256::generate,
        )
    }
}

/// Opaque Hash_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiHashDrbgSha384 {
    inner: OxiHandle<HashDrbgSha384>,
}

impl TypedDrbg for OxiHashDrbgSha384 {
    type Inner = HashDrbgSha384;
    fn handle(&mut self) -> &mut OxiHandle<HashDrbgSha384> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated Hash_DRBG-SHA-384 handle.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHashDrbgSha384`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_new(
    out_handle: *mut *mut OxiHashDrbgSha384,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHashDrbgSha384 {
        inner: OxiHandle::new(HashDrbgSha384::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a Hash_DRBG-SHA-384 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hash_drbg_sha384_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_free(handle: *mut OxiHashDrbgSha384) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// Hash_DRBG-SHA-384 Instantiate from the module's seed path. The
/// instantiated security strength is 256 bits (SP 800-57 Part 1). See
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha384_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_instantiate_from_module(
    handle: *mut OxiHashDrbgSha384,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::HashDrbgSha384,
            HashDrbgSha384::instantiate_from_module,
        )
    }
}

/// Hash_DRBG-SHA-384 Reseed from the module's seed path. See
/// [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha384_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_reseed_from_module(
    handle: *mut OxiHashDrbgSha384,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::HashDrbgSha384,
            HashDrbgSha384::reseed_from_module,
        )
    }
}

/// Hash_DRBG-SHA-384 Generate. See [`oxi_hmac_drbg_sha256_generate`].
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha384_new`], not in use by another call.
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_generate(
    handle: *mut OxiHashDrbgSha384,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::HashDrbgSha384,
            HashDrbgSha384::MAX_MODULE_ADDITIONAL_INPUT,
            HashDrbgSha384::generate,
        )
    }
}

/// Opaque Hash_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiHashDrbgSha512 {
    inner: OxiHandle<HashDrbgSha512>,
}

impl TypedDrbg for OxiHashDrbgSha512 {
    type Inner = HashDrbgSha512;
    fn handle(&mut self) -> &mut OxiHandle<HashDrbgSha512> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated Hash_DRBG-SHA-512 handle.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHashDrbgSha512`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_new(
    out_handle: *mut *mut OxiHashDrbgSha512,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHashDrbgSha512 {
        inner: OxiHandle::new(HashDrbgSha512::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a Hash_DRBG-SHA-512 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hash_drbg_sha512_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_free(handle: *mut OxiHashDrbgSha512) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// Hash_DRBG-SHA-512 Instantiate from the module's seed path. The
/// instantiated security strength is 256 bits. See
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha512_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_instantiate_from_module(
    handle: *mut OxiHashDrbgSha512,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::HashDrbgSha512,
            HashDrbgSha512::instantiate_from_module,
        )
    }
}

/// Hash_DRBG-SHA-512 Reseed from the module's seed path. See
/// [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha512_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_reseed_from_module(
    handle: *mut OxiHashDrbgSha512,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::HashDrbgSha512,
            HashDrbgSha512::reseed_from_module,
        )
    }
}

/// Hash_DRBG-SHA-512 Generate. See [`oxi_hmac_drbg_sha256_generate`].
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_hash_drbg_sha512_new`], not in use by another call.
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_generate(
    handle: *mut OxiHashDrbgSha512,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::HashDrbgSha512,
            HashDrbgSha512::MAX_MODULE_ADDITIONAL_INPUT,
            HashDrbgSha512::generate,
        )
    }
}

// ── CTR-DRBG-AES-128 / -192 / -256 ───────────────────────────────
//
// SP 800-90A §10.2 CTR_DRBG family. Same opaque-handle / `OxiHandle<T>`
// / Drop-zeroize / per-call-mutating contract as the HMAC-DRBG and
// Hash-DRBG families above; differs in upstream construction (block
// cipher CTR mode per §10.2 vs hash-based per §10.1.1/§10.1.2). Every
// CTR_DRBG handle is instantiated from the module's seed path through
// the derivation function (`Block_Cipher_df`, SP 800-90A §10.3.2), so
// the generate entry point is `_generate_df`.
//
// Per SP 800-90A Table 3, security strength is 128 / 192 / 256 bits
// for CTR-AES-128 / -192 / -256 (matches the underlying block-cipher
// key length). `max_number_of_bits_per_request` is `2^19` bits —
// alg-independent across all DRBG families. CTR_DRBG needs no
// `OxiResult` discriminant of its own: its errors map through
// `From<oxicrypt_module::Error>` + `From<DrbgError>` in `error.rs`.

/// Opaque CTR_DRBG-AES-128 handle. See `OxiHmacDrbgSha256` for the
/// per-call-mutating thread-safety and Drop-zeroize contract.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiCtrDrbgAes128 {
    inner: OxiHandle<CtrDrbgAes128>,
}

impl TypedDrbg for OxiCtrDrbgAes128 {
    type Inner = CtrDrbgAes128;
    fn handle(&mut self) -> &mut OxiHandle<CtrDrbgAes128> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated CTR_DRBG-AES-128 handle. Caller
/// must subsequently call
/// [`oxi_ctr_drbg_aes128_instantiate_from_module`] before generate /
/// reseed becomes operational.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiCtrDrbgAes128`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_new(out_handle: *mut *mut OxiCtrDrbgAes128) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiCtrDrbgAes128 {
        inner: OxiHandle::new(CtrDrbgAes128::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a CTR_DRBG-AES-128 handle. NULL-safe. Drop on the upstream
/// `CtrDrbgAes128` zeroizes the internal `(Key, V, reseed_counter)`
/// state via `oxicrypt-zeroize`, and every byte of the handle is then wiped
/// before its memory is released.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_ctr_drbg_aes128_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_free(handle: *mut OxiCtrDrbgAes128) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// CTR_DRBG-AES-128 Instantiate from the module's seed path, through the
/// derivation function (SP 800-90A §10.2.1.3.2). The instantiated security
/// strength is 128 bits. See
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes128_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_instantiate_from_module(
    handle: *mut OxiCtrDrbgAes128,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::CtrDrbgAes128,
            CtrDrbgAes128::instantiate_from_module,
        )
    }
}

/// CTR_DRBG-AES-128 Reseed from the module's seed path, through the
/// derivation function (SP 800-90A §10.2.1.4.2). See
/// [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes128_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_reseed_from_module(
    handle: *mut OxiCtrDrbgAes128,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::CtrDrbgAes128,
            CtrDrbgAes128::reseed_from_module,
        )
    }
}

/// CTR_DRBG-AES-128 Generate, **df** variant (SP 800-90A
/// §10.2.1.5.2). `additional_input` is passed through
/// `Block_Cipher_df` before being mixed in, and is bounded by the
/// additional input the DRBG accepts from a module reseed; longer
/// returns `OxiResult::InvalidInput = 5`. NULL+0 is the no-AI call;
/// NULL with non-zero length returns `OxiResult::NullPointer = 10`.
/// `out_len` is bounded by `2^16` bytes. See
/// [`oxi_hmac_drbg_sha256_generate`] for the rest of the contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes128_new`], not in use by another call. `out` must
/// point to ≥ `out_len` writable bytes. `additional_input` must point
/// to ≥ `additional_input_len` readable bytes when
/// `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_generate_df(
    handle: *mut OxiCtrDrbgAes128,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::CtrDrbgAes128,
            CtrDrbgAes128::MAX_MODULE_ADDITIONAL_INPUT,
            CtrDrbgAes128::generate_df,
        )
    }
}

/// Opaque CTR_DRBG-AES-192 handle. See `OxiCtrDrbgAes128`.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiCtrDrbgAes192 {
    inner: OxiHandle<CtrDrbgAes192>,
}

impl TypedDrbg for OxiCtrDrbgAes192 {
    type Inner = CtrDrbgAes192;
    fn handle(&mut self) -> &mut OxiHandle<CtrDrbgAes192> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated CTR_DRBG-AES-192 handle. See
/// [`oxi_ctr_drbg_aes128_new`].
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiCtrDrbgAes192`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_new(out_handle: *mut *mut OxiCtrDrbgAes192) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiCtrDrbgAes192 {
        inner: OxiHandle::new(CtrDrbgAes192::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a CTR_DRBG-AES-192 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_ctr_drbg_aes192_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_free(handle: *mut OxiCtrDrbgAes192) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// CTR_DRBG-AES-192 Instantiate from the module's seed path, through the
/// derivation function. The instantiated security strength is 192 bits.
/// See [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full
/// contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes192_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_instantiate_from_module(
    handle: *mut OxiCtrDrbgAes192,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::CtrDrbgAes192,
            CtrDrbgAes192::instantiate_from_module,
        )
    }
}

/// CTR_DRBG-AES-192 Reseed from the module's seed path, through the
/// derivation function. See [`oxi_hmac_drbg_sha256_reseed_from_module`]
/// for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes192_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_reseed_from_module(
    handle: *mut OxiCtrDrbgAes192,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::CtrDrbgAes192,
            CtrDrbgAes192::reseed_from_module,
        )
    }
}

/// CTR_DRBG-AES-192 Generate, df. See [`oxi_ctr_drbg_aes128_generate_df`].
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes192_new`], not in use by another call. `out` must
/// point to ≥ `out_len` writable bytes. `additional_input` must point
/// to ≥ `additional_input_len` readable bytes when
/// `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_generate_df(
    handle: *mut OxiCtrDrbgAes192,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::CtrDrbgAes192,
            CtrDrbgAes192::MAX_MODULE_ADDITIONAL_INPUT,
            CtrDrbgAes192::generate_df,
        )
    }
}

/// Opaque CTR_DRBG-AES-256 handle. See `OxiCtrDrbgAes128`.
///
/// The handle is seeded by the module: `_instantiate_from_module` draws its
/// entropy input and nonce from the module's seed path, and the DRBG reseeds
/// itself from the same path at the SP 800-90A reseed interval. A forked
/// child inherits a copy that returns `InvalidInput = 5` until the child
/// re-instantiates it with `_instantiate_from_module`. The handle has no
/// busy flag: callers serialise all calls on one handle.
///
/// cbindgen:opaque
pub struct OxiCtrDrbgAes256 {
    inner: OxiHandle<CtrDrbgAes256>,
}

impl TypedDrbg for OxiCtrDrbgAes256 {
    type Inner = CtrDrbgAes256;
    fn handle(&mut self) -> &mut OxiHandle<CtrDrbgAes256> {
        &mut self.inner
    }
}

/// Allocate a new, uninstantiated CTR_DRBG-AES-256 handle.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiCtrDrbgAes256`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_new(out_handle: *mut *mut OxiCtrDrbgAes256) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiCtrDrbgAes256 {
        inner: OxiHandle::new(CtrDrbgAes256::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a CTR_DRBG-AES-256 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_ctr_drbg_aes256_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_free(handle: *mut OxiCtrDrbgAes256) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is a live `Box` from the matching `_new` that has not
    // been freed, by contract.
    unsafe { crate::rbg::wipe_and_free(handle) };
}

/// CTR_DRBG-AES-256 Instantiate from the module's seed path, through the
/// derivation function. The instantiated security strength is 256 bits.
/// See [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full
/// contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes256_new`], not in use by another call. A non-NULL
/// `perso` must be valid for reads of `perso_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_instantiate_from_module(
    handle: *mut OxiCtrDrbgAes256,
    perso: *const u8,
    perso_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `instantiate_typed`'s.
    unsafe {
        instantiate_typed(
            handle,
            perso,
            perso_len,
            Service::CtrDrbgAes256,
            CtrDrbgAes256::instantiate_from_module,
        )
    }
}

/// CTR_DRBG-AES-256 Reseed from the module's seed path, through the
/// derivation function. See [`oxi_hmac_drbg_sha256_reseed_from_module`]
/// for the full contract.
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes256_new`], not in use by another call. A non-NULL
/// `additional` must be valid for reads of `additional_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_reseed_from_module(
    handle: *mut OxiCtrDrbgAes256,
    additional: *const u8,
    additional_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `reseed_typed`'s.
    unsafe {
        reseed_typed(
            handle,
            additional,
            additional_len,
            Service::CtrDrbgAes256,
            CtrDrbgAes256::reseed_from_module,
        )
    }
}

/// CTR_DRBG-AES-256 Generate, df. See [`oxi_ctr_drbg_aes128_generate_df`].
///
/// # Safety
///
/// `handle` must be NULL or a live handle from
/// [`oxi_ctr_drbg_aes256_new`], not in use by another call. `out` must
/// point to ≥ `out_len` writable bytes. `additional_input` must point
/// to ≥ `additional_input_len` readable bytes when
/// `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_generate_df(
    handle: *mut OxiCtrDrbgAes256,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: this function's contract is `generate_typed`'s.
    unsafe {
        generate_typed(
            handle,
            additional_input,
            additional_input_len,
            out,
            out_len,
            Service::CtrDrbgAes256,
            CtrDrbgAes256::MAX_MODULE_ADDITIONAL_INPUT,
            CtrDrbgAes256::generate_df,
        )
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use core::ptr;

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// Initialising the module is process-global and other tests in this
    /// crate assert it is uninitialised, so these tests rely on the
    /// workspace's test runner, nextest, running each test in its own
    /// process.
    fn operational() {
        match oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
            Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => {}
            Err(e) => panic!("module failed to initialise: {e:?}"),
        }
    }

    /// Drives one handle family through its C entry points: generate and
    /// reseed on a never-instantiated handle return `Uninstantiated = 8`;
    /// instantiate, generate and reseed then succeed; an optional input that
    /// is NULL with a length, and additional input over the module-reseed
    /// bound, return `InvalidInput = 5`; a handle whose recorded process id
    /// is another process's returns `InvalidInput = 5` until it is
    /// instantiated again; and a NULL handle returns `NullPointer = 10`.
    macro_rules! module_seeded_codes {
        ($test:ident, $new:ident, $free:ident, $inst:ident, $reseed:ident, $generate:ident, $ty:ty, $inner:ty) => {
            #[test]
            fn $test() {
                operational();
                let mut h: *mut $ty = ptr::null_mut();
                let mut out = [0xa5u8; 32];
                let (o, n) = (out.as_mut_ptr(), out.len());
                let over = vec![0x11u8; <$inner>::MAX_MODULE_ADDITIONAL_INPUT + 1];
                // SAFETY: `h` is a writable local and a live handle after
                // `$new` until `$free`; every buffer is a valid local; the NULL
                // handles are refused before any dereference.
                unsafe {
                    assert_eq!($new(&raw mut h), R::Ok as c_int);
                    assert_eq!(
                        $generate(h, ptr::null(), 0, o, n),
                        R::Uninstantiated as c_int
                    );
                    assert_eq!($reseed(h, ptr::null(), 0), R::Uninstantiated as c_int);
                    assert_eq!(out, [0xa5u8; 32], "a failed call wrote output");

                    assert_eq!($inst(h, b"app".as_ptr(), 3), R::Ok as c_int);
                    assert_eq!($generate(h, ptr::null(), 0, o, n), R::Ok as c_int);
                    assert_ne!(out, [0xa5u8; 32]);
                    assert_eq!($reseed(h, b"more".as_ptr(), 4), R::Ok as c_int);
                    assert_eq!($inst(h, ptr::null(), 1), R::InvalidInput as c_int);
                    assert_eq!($reseed(h, ptr::null(), 1), R::InvalidInput as c_int);
                    assert_eq!(
                        $generate(h, over.as_ptr(), over.len(), o, n),
                        R::InvalidInput as c_int
                    );
                    assert_eq!(
                        $generate(h, over.as_ptr(), over.len() - 1, o, n),
                        R::Ok as c_int
                    );

                    // A copy inherited from another process.
                    let pid = &raw const (*h).inner.pid;
                    let own = (*pid).load(Ordering::SeqCst);
                    assert_eq!(own, current_process());
                    (*pid).store(own.wrapping_add(1), Ordering::SeqCst);
                    assert_eq!($generate(h, ptr::null(), 0, o, n), R::InvalidInput as c_int);
                    assert_eq!($reseed(h, ptr::null(), 0), R::InvalidInput as c_int);
                    assert_eq!($inst(h, ptr::null(), 0), R::Ok as c_int);
                    assert_eq!((*pid).load(Ordering::SeqCst), own);
                    assert_eq!($generate(h, ptr::null(), 0, o, n), R::Ok as c_int);
                    $free(h);

                    assert_eq!(
                        $inst(ptr::null_mut(), ptr::null(), 0),
                        R::NullPointer as c_int
                    );
                    assert_eq!(
                        $reseed(ptr::null_mut(), ptr::null(), 0),
                        R::NullPointer as c_int
                    );
                    assert_eq!(
                        $generate(ptr::null_mut(), ptr::null(), 0, o, n),
                        R::NullPointer as c_int
                    );
                }
                assert_eq!(R::Uninstantiated as c_int, 8);
            }
        };
    }

    module_seeded_codes!(
        hmac_drbg_sha256_module_seeded_codes,
        oxi_hmac_drbg_sha256_new,
        oxi_hmac_drbg_sha256_free,
        oxi_hmac_drbg_sha256_instantiate_from_module,
        oxi_hmac_drbg_sha256_reseed_from_module,
        oxi_hmac_drbg_sha256_generate,
        OxiHmacDrbgSha256,
        HmacDrbgSha256
    );
    module_seeded_codes!(
        hmac_drbg_sha384_module_seeded_codes,
        oxi_hmac_drbg_sha384_new,
        oxi_hmac_drbg_sha384_free,
        oxi_hmac_drbg_sha384_instantiate_from_module,
        oxi_hmac_drbg_sha384_reseed_from_module,
        oxi_hmac_drbg_sha384_generate,
        OxiHmacDrbgSha384,
        HmacDrbgSha384
    );
    module_seeded_codes!(
        hmac_drbg_sha512_module_seeded_codes,
        oxi_hmac_drbg_sha512_new,
        oxi_hmac_drbg_sha512_free,
        oxi_hmac_drbg_sha512_instantiate_from_module,
        oxi_hmac_drbg_sha512_reseed_from_module,
        oxi_hmac_drbg_sha512_generate,
        OxiHmacDrbgSha512,
        HmacDrbgSha512
    );
    module_seeded_codes!(
        hash_drbg_sha256_module_seeded_codes,
        oxi_hash_drbg_sha256_new,
        oxi_hash_drbg_sha256_free,
        oxi_hash_drbg_sha256_instantiate_from_module,
        oxi_hash_drbg_sha256_reseed_from_module,
        oxi_hash_drbg_sha256_generate,
        OxiHashDrbgSha256,
        HashDrbgSha256
    );
    module_seeded_codes!(
        hash_drbg_sha384_module_seeded_codes,
        oxi_hash_drbg_sha384_new,
        oxi_hash_drbg_sha384_free,
        oxi_hash_drbg_sha384_instantiate_from_module,
        oxi_hash_drbg_sha384_reseed_from_module,
        oxi_hash_drbg_sha384_generate,
        OxiHashDrbgSha384,
        HashDrbgSha384
    );
    module_seeded_codes!(
        hash_drbg_sha512_module_seeded_codes,
        oxi_hash_drbg_sha512_new,
        oxi_hash_drbg_sha512_free,
        oxi_hash_drbg_sha512_instantiate_from_module,
        oxi_hash_drbg_sha512_reseed_from_module,
        oxi_hash_drbg_sha512_generate,
        OxiHashDrbgSha512,
        HashDrbgSha512
    );
    module_seeded_codes!(
        ctr_drbg_aes128_module_seeded_codes,
        oxi_ctr_drbg_aes128_new,
        oxi_ctr_drbg_aes128_free,
        oxi_ctr_drbg_aes128_instantiate_from_module,
        oxi_ctr_drbg_aes128_reseed_from_module,
        oxi_ctr_drbg_aes128_generate_df,
        OxiCtrDrbgAes128,
        CtrDrbgAes128
    );
    module_seeded_codes!(
        ctr_drbg_aes192_module_seeded_codes,
        oxi_ctr_drbg_aes192_new,
        oxi_ctr_drbg_aes192_free,
        oxi_ctr_drbg_aes192_instantiate_from_module,
        oxi_ctr_drbg_aes192_reseed_from_module,
        oxi_ctr_drbg_aes192_generate_df,
        OxiCtrDrbgAes192,
        CtrDrbgAes192
    );
    module_seeded_codes!(
        ctr_drbg_aes256_module_seeded_codes,
        oxi_ctr_drbg_aes256_new,
        oxi_ctr_drbg_aes256_free,
        oxi_ctr_drbg_aes256_instantiate_from_module,
        oxi_ctr_drbg_aes256_reseed_from_module,
        oxi_ctr_drbg_aes256_generate_df,
        OxiCtrDrbgAes256,
        CtrDrbgAes256
    );
}
