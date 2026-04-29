//! C ABI wrappers for oxicrypt approved services.
//!
//! This crate provides `extern "C"` entry points that language
//! bindings (Python, Go, Node, etc.) can call via their FFI
//! mechanisms. The underlying Rust implementations remain pure-
//! Rust, `no_std`-friendly, and inside the FIPS 140-3 cryptographic
//! boundary; this crate is a thin translation layer that sits
//! outside that boundary.
//!
//! # Symbol prefix
//!
//! Every function exported by this crate uses the `oxi_` prefix
//! (e.g. `oxi_init`, `oxi_sha256`). The prefix is short, namespaced,
//! and consistent — see `docs/c-api-design.md` for the design
//! rationale.
//!
//! # Status codes
//!
//! Every function returns a `c_int` whose value is an [`OxiResult`]
//! discriminant. `OxiResult::Ok = 0` is success; non-zero values are
//! distinct failure modes banded by source crate. See
//! [`crate::error`] for the full mapping.
//!
//! # Output buffers
//!
//! Output buffers are caller-allocated. The caller must ensure
//! they are at least as large as the documented minimum size.
//!
//! # Safety
//!
//! All functions in this crate that take pointers are `unsafe`
//! because they accept raw pointers from C callers. Every function
//! performs null checks and length validation before dereferencing
//! any pointer.
//!
//! # Initialisation
//!
//! The module must be initialised by calling [`oxi_init`] before
//! any cryptographic function. This runs all power-up KATs.
//! Calling a cryptographic function before init returns
//! [`OxiResult::NotOperational`].
//!
//! # Algorithm profiles
//!
//! [`oxi_init`] accepts a profile selector:
//!
//! | Value | Profile |
//! |-------|---------|
//! | `0`   | Unrestricted (all approved algorithms) |
//! | `1`   | CNSA 2.0 (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87, LMS, XMSS) |
//! | `2`   | CNSA 1.0 (AES-256, SHA-256+, P-384, RSA ≥ 3072, DH ≥ 3072) |
//!
//! Unknown profile codes return [`OxiResult::InvalidInput`].
//! Once a profile is active, calling a restricted algorithm returns
//! [`OxiResult::AlgorithmRestricted`].
//! [`oxi_active_profile`] queries the current profile;
//! [`oxi_is_operational`] queries the module state.

// This crate is the FFI boundary — unsafe is required by definition.
#![allow(unsafe_code, clippy::missing_safety_doc)]

mod aes;
mod error;
mod handle;
pub use aes::{
    oxi_aes256_free, oxi_aes256_gcm_decrypt, oxi_aes256_gcm_encrypt, oxi_aes256_new, OxiAes256Key,
};
pub use error::OxiResult;

use crate::error::{status_module, OxiResult as R};
use core::ffi::c_int;

// ── Helpers ──────────────────────────────────────────────────────

/// Build a `&[u8]` from a raw pointer and length, returning
/// [`OxiResult::NullPointer`] on null with non-zero length.
///
/// The returned slice is borrowed for the unbounded lifetime `'a`,
/// chosen by the caller. Sound usage requires the caller to confine
/// `'a` to the FFI call's stack frame so the slice can never escape
/// the underlying C-side buffer's lifetime. The bound is unbounded
/// rather than `'static` so a misuse that stashes the slice into a
/// `static`/`OnceCell`/return value is rejected by the borrow checker.
///
/// # Safety
///
/// The caller must ensure the pointer is valid for `len` bytes.
unsafe fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], c_int> {
    if ptr.is_null() && len > 0 {
        return Err(R::NullPointer as c_int);
    }
    if len == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Build a `&mut [u8]` from a raw pointer and length.
///
/// Unbounded lifetime per the same convention as [`slice_from_raw`].
///
/// # Safety
///
/// The caller must ensure the pointer is valid for `len` bytes.
unsafe fn slice_from_raw_mut<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], c_int> {
    if ptr.is_null() && len > 0 {
        return Err(R::NullPointer as c_int);
    }
    if len == 0 {
        // Return a valid empty slice even for null ptr with len=0.
        return Ok(&mut []);
    }
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

// ── Module lifecycle ─────────────────────────────────────────────

/// Collect every KAT entry from every algorithm crate into a single
/// flat `Vec`.
///
/// The integrity self-test KAT (`oxicrypt_integrity::KATS`) is
/// deliberately NOT bundled here. `integrity_self_test` resolves the
/// current binary via `env::current_exe()`, which for a cdylib
/// loaded into a host process returns the host's path, not the
/// `liboxicrypt_ffi.so` path. Wiring the existing KAT into `oxi_init`
/// would cause every C-ABI consumer to fail with
/// `OxiResult::SelfTestFailed` because the slot scanner would scan
/// the wrong binary.
///
/// The integrity slot still ships in the cdylib/staticlib (forced via
/// the `_SLOT_REF` static below) and is sign-able via
/// `fips-integrity-sign --cdylib-target …`. Runtime verification for
/// the cdylib path requires a `dladdr`-based "find this .so's own
/// path" helper, which is tracked as a future-work item in the
/// security policy.
fn collect_kats() -> Vec<oxicrypt_module::KatEntry> {
    let all_kats: &[&[oxicrypt_module::KatEntry]] = &[
        oxicrypt_sha::KATS,
        oxicrypt_hmac::KATS,
        oxicrypt_aes::KATS,
        oxicrypt_drbg::KATS,
        oxicrypt_ecdsa::KATS,
        oxicrypt_eddsa::KATS,
        oxicrypt_ecdh::KATS,
    ];
    let mut merged = Vec::new();
    for group in all_kats {
        for kat in *group {
            merged.push(*kat);
        }
    }
    merged
}

/// Force the integrity slot into the cdylib/staticlib output.
///
/// `oxicrypt_integrity::FIPS_INTEGRITY_SLOT` is `#[used]` in its own
/// crate, but the rlib-to-cdylib linker may still drop unreferenced
/// symbols during dead-code elimination. The explicit `&'static`
/// reference here creates an actual code-level pointer to the slot,
/// guaranteeing its 64 bytes (header magic + 32-byte MAC + footer
/// magic) land contiguously in the output binary's `.rodata` so
/// `fips-integrity-sign` can locate and update them.
#[used]
static _SLOT_REF: &oxicrypt_integrity::IntegritySlot = &oxicrypt_integrity::FIPS_INTEGRITY_SLOT;

/// Initialise the FIPS module with the given algorithm profile,
/// running all power-up KATs.
///
/// `profile` selects the algorithm-restriction level:
///
/// - `0` — Unrestricted (all approved algorithms available)
/// - `1` — CNSA 2.0 (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87,
///   LMS, XMSS)
/// - `2` — CNSA 1.0 (AES-256, SHA-256+, P-384, RSA ≥ 3072, DH ≥ 3072)
///
/// Any other value returns [`OxiResult::InvalidInput`] without
/// performing initialisation. This is per F4 reviewer-framing —
/// distinct error variants per failure mode rather than silently
/// defaulting unknown codes to a profile.
///
/// Idempotent: calling `oxi_init` more than once returns
/// [`OxiResult::Ok`] on the second call. **The first init's outcome
/// is authoritative** — both the success/failure state AND the
/// active profile are determined by the first successful call. A
/// second call passing a *different* profile selector is silently
/// accepted and the *original* profile remains active. Callers that
/// need to verify which profile is in effect must call
/// [`oxi_active_profile`] after `oxi_init` returns.
///
/// Must be called exactly once before any other `oxi_*` function.
/// Returns `0` on success or a non-zero `OxiResult` discriminant.
///
/// # Safety
///
/// No pointers; always safe to call.
#[no_mangle]
pub extern "C" fn oxi_init(profile: c_int) -> c_int {
    let p = match profile {
        0 => oxicrypt_module::AlgorithmProfile::Unrestricted,
        1 => oxicrypt_module::AlgorithmProfile::Cnsa2,
        2 => oxicrypt_module::AlgorithmProfile::Cnsa1,
        _ => return R::InvalidInput as c_int,
    };
    // Idempotent fast-path: skip KAT collection on already-operational
    // re-init. `collect_kats` aggregates ~13 crate slices into a fresh
    // `Vec` and `initialize_with_profile` would discard them via
    // `AlreadyInitialized` regardless. One atomic load saves the
    // allocation on every subsequent call.
    if oxicrypt_module::is_operational() {
        return R::Ok as c_int;
    }
    let kats = collect_kats();
    match oxicrypt_module::initialize_with_profile(&kats, p) {
        Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => R::Ok as c_int,
        Err(e) => status_module(Err(e)),
    }
}

/// Query the active algorithm profile.
///
/// Returns:
/// - `0` — Unrestricted
/// - `1` — CNSA 2.0
/// - `2` — CNSA 1.0
///
/// # Safety
///
/// No pointers; always safe to call.
#[no_mangle]
pub extern "C" fn oxi_active_profile() -> c_int {
    match oxicrypt_module::active_profile() {
        oxicrypt_module::AlgorithmProfile::Unrestricted => 0,
        oxicrypt_module::AlgorithmProfile::Cnsa2 => 1,
        oxicrypt_module::AlgorithmProfile::Cnsa1 => 2,
    }
}

/// Query whether the module is in the `Operational` state.
///
/// Returns `1` if the module has completed power-up self-tests
/// without failure and is currently servicing approved cryptographic
/// requests, `0` otherwise (any other state: `PowerOff`, `SelfTest`,
/// `Error`).
///
/// This is a query, not a gate — operational-only entry points
/// already gate themselves via `oxicrypt_module::require_operational`
/// and return [`OxiResult::NotOperational`] when called outside the
/// operational state. The query exists so C callers can present a
/// clear "module ready" signal without needing to make a
/// cryptographic call to discover the state.
///
/// # Safety
///
/// No pointers; always safe to call.
#[no_mangle]
pub extern "C" fn oxi_is_operational() -> c_int {
    c_int::from(oxicrypt_module::is_operational())
}

// ── SHA-256 ──────────────────────────────────────────────────────

/// Compute SHA-256 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 32 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha256(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha256(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-512 ──────────────────────────────────────────────────────

/// Compute SHA-512 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 64 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha512(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha512(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 64) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-3 family ─────────────────────────────────────────────────
//
// SHA-3 (FIPS 202) is a separate primitive family from SHA-2 with a
// different (sponge) construction; it is exposed as one-shot entry
// points only, mirroring the existing `oxi_sha256` / `oxi_sha512`
// shape. Streaming exposure is deferred until the underlying
// `oxicrypt_sha` Rust API exposes streaming SHA-3 publicly — exposing
// a caller-managed streaming surface ahead of the Rust API would
// invert the dependency direction (same rationale as PRD foundation
// Decision D1 for AES-GCM streaming).

/// Compute SHA3-224 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 28 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 28 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha3_224(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha3_224(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 28) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

/// Compute SHA3-256 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 32 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha3_256(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha3_256(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

/// Compute SHA3-384 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 48 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 48 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha3_384(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha3_384(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 48) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

/// Compute SHA3-512 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 64 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha3_512(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha3_512(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 64) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── HMAC-SHA-256 ─────────────────────────────────────────────────

/// Compute HMAC-SHA-256 over `data_len` bytes with the given key.
///
/// `out` must point to a buffer of at least 32 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha256(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    let mut mac = match oxicrypt_hmac::HmacSha256::new(key) {
        Ok(m) => m,
        Err(e) => return status_module(Err(e)),
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 32) };
    R::Ok as c_int
}

// ── HMAC-SHA-384 ─────────────────────────────────────────────────

/// Compute HMAC-SHA-384 over `data_len` bytes with the given key.
///
/// `out` must point to a buffer of at least 48 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha384(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    let mut mac = match oxicrypt_hmac::HmacSha384::new(key) {
        Ok(m) => m,
        Err(e) => return status_module(Err(e)),
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 48) };
    R::Ok as c_int
}

// ── HMAC-SHA-512 ─────────────────────────────────────────────────

/// Compute HMAC-SHA-512 over `data_len` bytes with the given key.
///
/// `out` must point to a buffer of at least 64 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    let mut mac = match oxicrypt_hmac::HmacSha512::new(key) {
        Ok(m) => m,
        Err(e) => return status_module(Err(e)),
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 64) };
    R::Ok as c_int
}

// ── HMAC-SHA3-224 ────────────────────────────────────────────────

/// Compute HMAC-SHA3-224 over `data_len` bytes with the given key.
///
/// `out` must point to a buffer of at least 28 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha3_224(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    let mut mac = match oxicrypt_hmac::HmacSha3_224::new(key) {
        Ok(m) => m,
        Err(e) => return status_module(Err(e)),
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 28) };
    R::Ok as c_int
}

// ── HMAC-SHA3-256 ────────────────────────────────────────────────

/// Compute HMAC-SHA3-256 over `data_len` bytes with the given key.
///
/// `out` must point to a buffer of at least 32 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha3_256(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    let mut mac = match oxicrypt_hmac::HmacSha3_256::new(key) {
        Ok(m) => m,
        Err(e) => return status_module(Err(e)),
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 32) };
    R::Ok as c_int
}

// ── HMAC-SHA3-384 ────────────────────────────────────────────────

/// Compute HMAC-SHA3-384 over `data_len` bytes with the given key.
///
/// `out` must point to a buffer of at least 48 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha3_384(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    let mut mac = match oxicrypt_hmac::HmacSha3_384::new(key) {
        Ok(m) => m,
        Err(e) => return status_module(Err(e)),
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 48) };
    R::Ok as c_int
}

// ── HMAC-SHA3-512 ────────────────────────────────────────────────

/// Compute HMAC-SHA3-512 over `data_len` bytes with the given key.
///
/// `out` must point to a buffer of at least 64 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha3_512(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    let mut mac = match oxicrypt_hmac::HmacSha3_512::new(key) {
        Ok(m) => m,
        Err(e) => return status_module(Err(e)),
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 64) };
    R::Ok as c_int
}
