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
    oxi_aes256_cbc_decrypt, oxi_aes256_cbc_encrypt, oxi_aes256_ccm_decrypt, oxi_aes256_ccm_encrypt,
    oxi_aes256_cmac, oxi_aes256_ctr, oxi_aes256_free, oxi_aes256_gcm_decrypt,
    oxi_aes256_gcm_encrypt, oxi_aes256_kw_unwrap, oxi_aes256_kw_wrap, oxi_aes256_kwp_unwrap,
    oxi_aes256_kwp_wrap, oxi_aes256_new, OxiAes256Key,
};
pub use error::OxiResult;

use crate::error::{status_kdf, status_module, OxiResult as R};
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
        oxicrypt_dh::KATS,
        oxicrypt_rsa::KATS,
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

// ── SHA-224 ──────────────────────────────────────────────────────

/// Compute SHA-224 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 28 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 28 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha224(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha224(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 28) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-384 ──────────────────────────────────────────────────────

/// Compute SHA-384 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 48 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 48 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha384(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha384(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 48) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-512/224 ──────────────────────────────────────────────────
//
// SHA-512/224 (FIPS 180-4 §6.6) is the truncated SHA-512 variant
// using its own distinct IV per FIPS 180-4 §5.3.6.1; it is NOT a
// post-hoc truncation of SHA-512 output. The Rust API
// `oxicrypt_sha::sha512_224` enforces this distinction internally.

/// Compute SHA-512/224 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 28 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 28 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224(
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha512_224(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 28) };
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-512/256 ──────────────────────────────────────────────────
//
// SHA-512/256 (FIPS 180-4 §6.7) likewise uses its own distinct IV
// per FIPS 180-4 §5.3.6.2 — not a post-hoc truncation of SHA-512.

/// Compute SHA-512/256 over `data_len` bytes at `data_ptr`.
///
/// `out` must point to a buffer of at least 32 bytes.
///
/// # Safety
///
/// Caller must ensure `data_ptr` is valid for `data_len` bytes
/// and `out` is valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256(
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> c_int {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    match oxicrypt_sha::sha512_256(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
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

// ── ECDSA (FIPS 186-5) — stateless surface ───────────────────────
//
// Three pure-functional entry points per curve: derive_public_key,
// sign_with_k (caller supplies per-message secret `k`), verify. The
// stateful surface — DRBG-sampled keygen and DRBG-sampled signing —
// lands in a follow-up PR after the DRBG family C ABI ships.
//
// Byte layouts (per curve):
//   P-256: d=32, public_key=65 (SEC1 §2.3.3 uncompressed: 0x04||X||Y),
//          k=32, signature=64 (r||s).
//   P-384: d=48, public_key=97, k=48, signature=96.
//
// Verify returns OxiResult::TagMismatch = 22 for well-formed-but-
// invalid signatures (Ok(false) upstream), generalizing the AEAD
// tag-mismatch semantic to the signature-verification family.

// ── ECDSA P-256 ──────────────────────────────────────────────────

/// Derive the uncompressed SEC1 public key for an ECDSA P-256 private
/// scalar (FIPS 186-5 §6.2.1).
///
/// `d_ptr` must point to exactly 32 bytes (the private scalar). On
/// success, writes 65 bytes (`0x04 || X(32) || Y(32)`) into
/// `public_key_out`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `public_key_out` must be a
/// non-NULL writable pointer to ≥65 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdsa_p256_derive_public_key(
    d_ptr: *const u8,
    public_key_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if public_key_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 32]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let pk = match oxicrypt_ecdsa::p256_ecdsa::derive_public_key(d_arr) {
        Ok(p) => p,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), public_key_out, 65) };
    R::Ok as c_int
}

/// Sign `msg` with ECDSA P-256 using a caller-supplied per-message
/// secret `k` (FIPS 186-5 §6.4.1).
///
/// `d_ptr` and `k_ptr` must each point to exactly 32 bytes; `k` must
/// be uniformly random in `[1, n-1]` per FIPS 186-5 §A.2.2 — the FFI
/// cannot enforce uniformity, only document the requirement. On
/// success, writes 64 bytes (`r(32) || s(32)`) into `sig_out`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must be a
/// non-NULL writable pointer to ≥64 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdsa_p256_sign_with_k(
    d_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    k_ptr: *const u8,
    sig_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let k = match unsafe { slice_from_raw(k_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 32]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let Ok(k_arr) = <&[u8; 32]>::try_from(k) else {
        return R::Internal as c_int;
    };
    let sig = match oxicrypt_ecdsa::p256_ecdsa::sign_with_k(d_arr, msg, k_arr) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 64) };
    R::Ok as c_int
}

/// Verify an ECDSA P-256 signature over `msg` against the public key
/// `pk` (FIPS 186-5 §6.4.2).
///
/// `public_key_ptr` must point to exactly 65 bytes (uncompressed SEC1)
/// and `sig_ptr` to exactly 64 bytes (`r || s`).
///
/// Returns `OxiResult::Ok = 0` for valid, `OxiResult::TagMismatch = 22`
/// for well-formed-but-invalid (the upstream `Ok(false)`), or a module
/// error variant on `Err`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdsa_p256_verify(
    public_key_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(public_key_ptr, 65) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk_arr) = <&[u8; 65]>::try_from(pk) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 64]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_ecdsa::p256_ecdsa::verify(pk_arr, msg, sig_arr) {
        Ok(true) => R::Ok as c_int,
        Ok(false) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── ECDSA P-384 ──────────────────────────────────────────────────

/// Derive the uncompressed SEC1 public key for an ECDSA P-384 private
/// scalar (FIPS 186-5 §6.2.1).
///
/// `d_ptr` must point to exactly 48 bytes. On success, writes 97
/// bytes (`0x04 || X(48) || Y(48)`) into `public_key_out`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `public_key_out` must be a
/// non-NULL writable pointer to ≥97 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdsa_p384_derive_public_key(
    d_ptr: *const u8,
    public_key_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if public_key_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 48]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let pk = match oxicrypt_ecdsa::p384_ecdsa::derive_public_key(d_arr) {
        Ok(p) => p,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), public_key_out, 97) };
    R::Ok as c_int
}

/// Sign `msg` with ECDSA P-384 using a caller-supplied per-message
/// secret `k` (FIPS 186-5 §6.4.1).
///
/// `d_ptr` and `k_ptr` must each point to exactly 48 bytes; `k` must
/// be uniformly random in `[1, n-1]` per FIPS 186-5 §A.2.2. On
/// success, writes 96 bytes (`r(48) || s(48)`) into `sig_out`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must be a
/// non-NULL writable pointer to ≥96 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdsa_p384_sign_with_k(
    d_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    k_ptr: *const u8,
    sig_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let k = match unsafe { slice_from_raw(k_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 48]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let Ok(k_arr) = <&[u8; 48]>::try_from(k) else {
        return R::Internal as c_int;
    };
    let sig = match oxicrypt_ecdsa::p384_ecdsa::sign_with_k(d_arr, msg, k_arr) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 96) };
    R::Ok as c_int
}

/// Verify an ECDSA P-384 signature over `msg` against the public key
/// `pk` (FIPS 186-5 §6.4.2).
///
/// `public_key_ptr` must point to exactly 97 bytes (uncompressed SEC1)
/// and `sig_ptr` to exactly 96 bytes (`r || s`).
///
/// Returns `OxiResult::Ok = 0` for valid, `OxiResult::TagMismatch = 22`
/// for well-formed-but-invalid, or a module error on `Err`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdsa_p384_verify(
    public_key_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(public_key_ptr, 97) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk_arr) = <&[u8; 97]>::try_from(pk) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 96]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_ecdsa::p384_ecdsa::verify(pk_arr, msg, sig_arr) {
        Ok(true) => R::Ok as c_int,
        Ok(false) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── HKDF (RFC 5869, SP 800-56C Rev. 2 §4.1) ──────────────────────
//
// Two-step extract/expand surface — RFC 5869 §2's pure-function
// abstract. The PRK is `L` bytes (32/48/64 for SHA-256/384/512) and
// is the entire HKDF state, so we expose it as raw bytes between
// `extract` and `expand` rather than wrapping it in an opaque
// handle. Caller decides PRK storage (RAM, KMS, file). Profile
// gating routes through `P::KDF_SERVICE` per CMVP gem D5 — same
// KDF mechanism with a different PRF is a different approved
// service per SP 800-56C Rev. 2.

// ── HKDF-SHA-256 ─────────────────────────────────────────────────

/// Run HKDF-Extract per RFC 5869 §2.2 with HMAC-SHA-256.
///
/// Computes `PRK = HMAC-SHA-256(salt, IKM)` and writes the 32-byte
/// PRK into `prk_out`. A NULL or zero-length salt is interpreted as
/// 32 zero bytes per RFC 5869 §2.2.
///
/// `prk_out` must point to a buffer of at least 32 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `prk_out` must be a
/// non-NULL writable pointer to ≥32 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_hkdf_sha256_extract(
    salt_ptr: *const u8,
    salt_len: usize,
    ikm_ptr: *const u8,
    ikm_len: usize,
    prk_out: *mut u8,
) -> c_int {
    let salt = match unsafe { slice_from_raw(salt_ptr, salt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ikm = match unsafe { slice_from_raw(ikm_ptr, ikm_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if prk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = match oxicrypt_kdf::HkdfSha256::extract(salt_opt, ikm) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(hk.prk().as_ptr(), prk_out, 32) };
    R::Ok as c_int
}

/// Run HKDF-Expand per RFC 5869 §2.3 with HMAC-SHA-256.
///
/// Reconstructs HKDF state from a 32-byte PRK and fills `okm_out`
/// with `okm_len` bytes of derived key material. Returns
/// `OxiResult::OutputTooLong` when `okm_len > 255 * 32 = 8160`.
///
/// `prk_ptr` must point to exactly 32 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `okm_out` must be a
/// writable pointer to at least `okm_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_hkdf_sha256_expand(
    prk_ptr: *const u8,
    info_ptr: *const u8,
    info_len: usize,
    okm_out: *mut u8,
    okm_len: usize,
) -> c_int {
    let prk = match unsafe { slice_from_raw(prk_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let info = match unsafe { slice_from_raw(info_ptr, info_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let okm = match unsafe { slice_from_raw_mut(okm_out, okm_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let hk = match oxicrypt_kdf::HkdfSha256::from_prk(prk) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    status_kdf(hk.expand(info, okm))
}

// ── HKDF-SHA-384 ─────────────────────────────────────────────────

/// Run HKDF-Extract per RFC 5869 §2.2 with HMAC-SHA-384.
///
/// Computes `PRK = HMAC-SHA-384(salt, IKM)` and writes the 48-byte
/// PRK into `prk_out`. A NULL or zero-length salt is interpreted as
/// 48 zero bytes per RFC 5869 §2.2.
///
/// `prk_out` must point to a buffer of at least 48 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `prk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_hkdf_sha384_extract(
    salt_ptr: *const u8,
    salt_len: usize,
    ikm_ptr: *const u8,
    ikm_len: usize,
    prk_out: *mut u8,
) -> c_int {
    let salt = match unsafe { slice_from_raw(salt_ptr, salt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ikm = match unsafe { slice_from_raw(ikm_ptr, ikm_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if prk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = match oxicrypt_kdf::HkdfSha384::extract(salt_opt, ikm) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(hk.prk().as_ptr(), prk_out, 48) };
    R::Ok as c_int
}

/// Run HKDF-Expand per RFC 5869 §2.3 with HMAC-SHA-384.
///
/// Reconstructs HKDF state from a 48-byte PRK and fills `okm_out`
/// with `okm_len` bytes of derived key material. Returns
/// `OxiResult::OutputTooLong` when `okm_len > 255 * 48 = 12240`.
///
/// `prk_ptr` must point to exactly 48 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `okm_out` must be a
/// writable pointer to at least `okm_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_hkdf_sha384_expand(
    prk_ptr: *const u8,
    info_ptr: *const u8,
    info_len: usize,
    okm_out: *mut u8,
    okm_len: usize,
) -> c_int {
    let prk = match unsafe { slice_from_raw(prk_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let info = match unsafe { slice_from_raw(info_ptr, info_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let okm = match unsafe { slice_from_raw_mut(okm_out, okm_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let hk = match oxicrypt_kdf::HkdfSha384::from_prk(prk) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    status_kdf(hk.expand(info, okm))
}

// ── HKDF-SHA-512 ─────────────────────────────────────────────────

/// Run HKDF-Extract per RFC 5869 §2.2 with HMAC-SHA-512.
///
/// Computes `PRK = HMAC-SHA-512(salt, IKM)` and writes the 64-byte
/// PRK into `prk_out`. A NULL or zero-length salt is interpreted as
/// 64 zero bytes per RFC 5869 §2.2.
///
/// `prk_out` must point to a buffer of at least 64 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `prk_out` must be a
/// non-NULL writable pointer to ≥64 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_hkdf_sha512_extract(
    salt_ptr: *const u8,
    salt_len: usize,
    ikm_ptr: *const u8,
    ikm_len: usize,
    prk_out: *mut u8,
) -> c_int {
    let salt = match unsafe { slice_from_raw(salt_ptr, salt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ikm = match unsafe { slice_from_raw(ikm_ptr, ikm_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if prk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = match oxicrypt_kdf::HkdfSha512::extract(salt_opt, ikm) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(hk.prk().as_ptr(), prk_out, 64) };
    R::Ok as c_int
}

/// Run HKDF-Expand per RFC 5869 §2.3 with HMAC-SHA-512.
///
/// Reconstructs HKDF state from a 64-byte PRK and fills `okm_out`
/// with `okm_len` bytes of derived key material. Returns
/// `OxiResult::OutputTooLong` when `okm_len > 255 * 64 = 16320`.
///
/// `prk_ptr` must point to exactly 64 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `okm_out` must be a
/// writable pointer to at least `okm_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_hkdf_sha512_expand(
    prk_ptr: *const u8,
    info_ptr: *const u8,
    info_len: usize,
    okm_out: *mut u8,
    okm_len: usize,
) -> c_int {
    let prk = match unsafe { slice_from_raw(prk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let info = match unsafe { slice_from_raw(info_ptr, info_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let okm = match unsafe { slice_from_raw_mut(okm_out, okm_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let hk = match oxicrypt_kdf::HkdfSha512::from_prk(prk) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    status_kdf(hk.expand(info, okm))
}

// ── TLS 1.3 KDF (RFC 8446 §7.1) ──────────────────────────────────
//
// HKDF-Expand-Label and Derive-Secret over the TLS 1.3 ciphersuite
// hashes. RFC 8446 §B.4 pins TLS 1.3 to SHA-256
// (TLS_AES_128_GCM_SHA256 / TLS_CHACHA20_POLY1305_SHA256) or
// SHA-384 (TLS_AES_256_GCM_SHA384) — SHA-512 is not in the IANA
// TLS 1.3 ciphersuite registry, so it is intentionally not exposed.
// Profile gating: `Service::Tls13Kdf` (one service for both hash
// instantiations, matching the upstream TLS-KDF crate's gating).

// ── TLS 1.3 HKDF-Expand-Label ────────────────────────────────────

/// Run HKDF-Expand-Label per RFC 8446 §7.1 with HMAC-SHA-256.
///
/// Builds the HkdfLabel wire structure
/// `length || "tls13 " + label || context` and runs HKDF-Expand
/// (RFC 5869 §2.3) to fill `out` with `out_len` bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `out` must be a writable
/// pointer to at least `out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_tls13_hkdf_expand_label_sha256(
    secret_ptr: *const u8,
    secret_len: usize,
    label_ptr: *const u8,
    label_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let secret = match unsafe { slice_from_raw(secret_ptr, secret_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let context = match unsafe { slice_from_raw(context_ptr, context_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_module(oxicrypt_tls_kdf::tls13_hkdf_expand_label::<
        oxicrypt_hmac::HmacSha256,
        32,
    >(secret, label, context, out_slice))
}

/// Run HKDF-Expand-Label per RFC 8446 §7.1 with HMAC-SHA-384.
///
/// Builds the HkdfLabel wire structure
/// `length || "tls13 " + label || context` and runs HKDF-Expand
/// (RFC 5869 §2.3) to fill `out` with `out_len` bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `out` must be a writable
/// pointer to at least `out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_tls13_hkdf_expand_label_sha384(
    secret_ptr: *const u8,
    secret_len: usize,
    label_ptr: *const u8,
    label_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let secret = match unsafe { slice_from_raw(secret_ptr, secret_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let context = match unsafe { slice_from_raw(context_ptr, context_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_module(oxicrypt_tls_kdf::tls13_hkdf_expand_label::<
        oxicrypt_hmac::HmacSha384,
        48,
    >(secret, label, context, out_slice))
}

// ── TLS 1.3 Derive-Secret ────────────────────────────────────────

/// Run Derive-Secret per RFC 8446 §7.1 with HMAC-SHA-256.
///
/// Equivalent to `HKDF-Expand-Label(secret, label, transcript_hash,
/// out_len)`. The caller computes `Hash(messages)` (the running
/// transcript hash) and passes it as `transcript_hash`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `out` must be a writable
/// pointer to at least `out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_tls13_derive_secret_sha256(
    secret_ptr: *const u8,
    secret_len: usize,
    label_ptr: *const u8,
    label_len: usize,
    transcript_hash_ptr: *const u8,
    transcript_hash_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let secret = match unsafe { slice_from_raw(secret_ptr, secret_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let transcript_hash = match unsafe { slice_from_raw(transcript_hash_ptr, transcript_hash_len) }
    {
        Ok(s) => s,
        Err(e) => return e,
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_module(oxicrypt_tls_kdf::tls13_derive_secret::<
        oxicrypt_hmac::HmacSha256,
        32,
    >(secret, label, transcript_hash, out_slice))
}

/// Run Derive-Secret per RFC 8446 §7.1 with HMAC-SHA-384.
///
/// Equivalent to `HKDF-Expand-Label(secret, label, transcript_hash,
/// out_len)`. The caller computes `Hash(messages)` (the running
/// transcript hash) and passes it as `transcript_hash`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `out` must be a writable
/// pointer to at least `out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_tls13_derive_secret_sha384(
    secret_ptr: *const u8,
    secret_len: usize,
    label_ptr: *const u8,
    label_len: usize,
    transcript_hash_ptr: *const u8,
    transcript_hash_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let secret = match unsafe { slice_from_raw(secret_ptr, secret_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let transcript_hash = match unsafe { slice_from_raw(transcript_hash_ptr, transcript_hash_len) }
    {
        Ok(s) => s,
        Err(e) => return e,
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_module(oxicrypt_tls_kdf::tls13_derive_secret::<
        oxicrypt_hmac::HmacSha384,
        48,
    >(secret, label, transcript_hash, out_slice))
}

// ── EdDSA Ed25519 (RFC 8032, FIPS 186-5 §7.8) ────────────────────
//
// Three pure-deterministic entry points: keygen, sign, verify.
// Unlike ECDSA, EVERY operation is deterministic by construction:
//   - keygen(seed) → public_key  per RFC 8032 §5.1.5 — given the
//     same seed, the same public key. NO DRBG involved (the
//     `Service::Ed25519Keygen` gate is "is the curve allowed?",
//     NOT "do we have entropy?").
//   - sign(seed, msg) → signature  per RFC 8032 §5.1.6 — the
//     per-message nonce is derived via HMAC-SHA512 over a prefix
//     of the secret and the message. Bit-identical signatures for
//     the same `(seed, msg)` pair. NO `sign_with_k` variant
//     because there is no `k` to supply.
//   - verify(pk, msg, sig) → bool  per RFC 8032 §5.1.7 — returns
//     `Ok(false)` for well-formed-but-invalid; we map that to
//     `OxiResult::TagMismatch = 22` per the cross-family
//     verify-mismatch generalization (security-policy §4.7).
//
// Byte layout: seed = 32 bytes; public_key = 32 bytes (compressed
// twisted Edwards point per RFC 8032 §5.1.2 — Y-coord plus 1 sign
// bit packed into the high bit of the last byte; NOT SEC1
// uncompressed); signature = 64 bytes (R(32) || S(32)).

/// Derive the Ed25519 public key from a 32-byte seed (RFC 8032 §5.1.5).
///
/// Reads exactly 32 bytes from `seed_ptr`. Writes the 32-byte
/// compressed-Edwards-point public key into `public_key_out`. This
/// operation is **deterministic**: given the same seed, the same
/// public key. Distinct from ECDSA's DRBG-sampled key generation —
/// the `Service::Ed25519Keygen` gate fires for profile-restriction
/// purposes, NOT because randomness is consumed.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `public_key_out` must be a
/// non-NULL writable pointer to ≥32 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ed25519_keygen(seed_ptr: *const u8, public_key_out: *mut u8) -> c_int {
    let seed = match unsafe { slice_from_raw(seed_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if public_key_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(seed_arr) = <&[u8; 32]>::try_from(seed) else {
        return R::Internal as c_int;
    };
    let pk = match oxicrypt_eddsa::ed25519::keygen(seed_arr) {
        Ok(p) => p,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), public_key_out, 32) };
    R::Ok as c_int
}

/// Sign `msg` with Ed25519 using the 32-byte seed (RFC 8032 §5.1.6).
///
/// Reads exactly 32 bytes from `seed_ptr`. Writes 64 bytes
/// (`R(32) || S(32)`) into `sig_out`. Signing is **deterministic** —
/// the per-message nonce is derived via HMAC-SHA512 over a prefix of
/// the secret and the message, so signatures are bit-identical for
/// the same `(seed, msg)` pair. There is NO `sign_with_k` variant
/// because RFC 8032 supplies the `k` internally.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must be a
/// non-NULL writable pointer to ≥64 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ed25519_sign(
    seed_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let seed = match unsafe { slice_from_raw(seed_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(seed_arr) = <&[u8; 32]>::try_from(seed) else {
        return R::Internal as c_int;
    };
    let sig = match oxicrypt_eddsa::ed25519::sign(seed_arr, msg) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 64) };
    R::Ok as c_int
}

/// Verify an Ed25519 signature over `msg` (RFC 8032 §5.1.7).
///
/// Reads exactly 32 bytes from `public_key_ptr` and exactly 64 bytes
/// from `sig_ptr`. Returns `OxiResult::Ok = 0` for valid,
/// `OxiResult::TagMismatch = 22` for well-formed-but-invalid (the
/// upstream `Ok(false)` — same cross-family verify-mismatch code as
/// AEAD AES-GCM/CCM/KW/KWP and ECDSA verify), or a module error
/// variant on `Err`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_ed25519_verify(
    public_key_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(public_key_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk_arr) = <&[u8; 32]>::try_from(pk) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 64]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_eddsa::ed25519::verify(pk_arr, msg, sig_arr) {
        Ok(true) => R::Ok as c_int,
        Ok(false) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── ECDH (SP 800-56Ar3 §5.7.1.2) — stateless surface ─────────────
//
// Two pure entry points, one per curve, computing the SP 800-56Ar3
// §5.7.1.2 ECC CDH primitive `Z = x(d * Q)`. No `derive_public_key`
// in this round — ECDH and ECDSA share the same scalar-multiplication
// primitive on each curve, so callers needing the public key from a
// stored private scalar should reuse `oxi_ecdsa_p{256,384}_derive_
// public_key` from the ECDSA family.
//
// Byte layout: private scalar `d` = 32 bytes (P-256) or 48 bytes
// (P-384); peer public key = 65 bytes (P-256) or 97 bytes (P-384),
// SEC1 uncompressed encoding `0x04 || X || Y` (same shape as ECDSA);
// shared secret `Z` = 32 bytes (P-256) or 48 bytes (P-384), the raw
// big-endian x-coordinate of `d * Q`. `Z` is the **raw** ECDH output
// per SP 800-56Ar3 — callers MUST run an SP 800-56C Rev. 2 extractor
// (HKDF, KBKDF) over `Z` before using it as keying material; the FFI
// intentionally does not bundle a KDF (see paragraph in
// `docs/security-policy/security-policy.md` §4.8).
//
// Errors: `InvalidInput = 5` covers BOTH a non-canonical private
// scalar `d` AND a peer public key that fails SP 800-56Ar3 §5.6.2.3.3
// public-key validation (canonical SEC1, coordinate canonicality,
// non-identity, on-curve `y² ≡ x³ − 3x + b (mod p)`). There is NO
// `TagMismatch = 22` mapping here — ECDH compute is `Result<bytes,
// Error>`, never `Ok(false)`, so the cross-family verify-mismatch
// code does not apply.

// ── ECDH P-256 ───────────────────────────────────────────────────

/// Compute the SP 800-56Ar3 §5.7.1.2 ECC CDH shared secret for
/// P-256: `Z = x(d * Q)`.
///
/// Reads exactly 32 bytes from `d_ptr` (the caller's private scalar)
/// and exactly 65 bytes from `peer_public_key_ptr` (the peer's
/// uncompressed SEC1 public key, `0x04 || X(32) || Y(32)`). Writes
/// 32 bytes (the raw big-endian x-coordinate of `d * Q`) into
/// `shared_secret_out`. The shared secret is the **raw** ECDH output
/// per SP 800-56Ar3; the caller MUST run an SP 800-56C Rev. 2
/// extractor (HKDF, KBKDF) over `Z` before using it as keying
/// material.
///
/// Peer public key undergoes full SP 800-56Ar3 §5.6.2.3.3 validation
/// (canonical encoding, coordinate canonicality, non-identity,
/// on-curve) before any scalar multiplication; a peer key failing
/// any check causes the call to return `OxiResult::InvalidInput = 5`
/// without performing the scalar-mul.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `shared_secret_out` must
/// be a non-NULL writable pointer to ≥32 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdh_p256_compute_shared_secret(
    d_ptr: *const u8,
    peer_public_key_ptr: *const u8,
    shared_secret_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let peer_pk = match unsafe { slice_from_raw(peer_public_key_ptr, 65) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if shared_secret_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 32]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let Ok(peer_pk_arr) = <&[u8; 65]>::try_from(peer_pk) else {
        return R::Internal as c_int;
    };
    let z = match oxicrypt_ecdh::compute_shared_secret_p256(d_arr, peer_pk_arr) {
        Ok(z) => z,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(z.as_ptr(), shared_secret_out, 32) };
    R::Ok as c_int
}

// ── ECDH P-384 ───────────────────────────────────────────────────

/// Compute the SP 800-56Ar3 §5.7.1.2 ECC CDH shared secret for
/// P-384: `Z = x(d * Q)`.
///
/// Reads exactly 48 bytes from `d_ptr` and exactly 97 bytes from
/// `peer_public_key_ptr` (uncompressed SEC1, `0x04 || X(48) || Y(48)`).
/// Writes 48 bytes (raw big-endian x-coordinate) into
/// `shared_secret_out`. The shared secret is the raw ECDH output;
/// the caller MUST run an SP 800-56C Rev. 2 extractor before use as
/// keying material.
///
/// Peer public key undergoes full SP 800-56Ar3 §5.6.2.3.3 validation
/// before scalar multiplication.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `shared_secret_out` must
/// be a non-NULL writable pointer to ≥48 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_ecdh_p384_compute_shared_secret(
    d_ptr: *const u8,
    peer_public_key_ptr: *const u8,
    shared_secret_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let peer_pk = match unsafe { slice_from_raw(peer_public_key_ptr, 97) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if shared_secret_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 48]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let Ok(peer_pk_arr) = <&[u8; 97]>::try_from(peer_pk) else {
        return R::Internal as c_int;
    };
    let z = match oxicrypt_ecdh::compute_shared_secret_p384(d_arr, peer_pk_arr) {
        Ok(z) => z,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(z.as_ptr(), shared_secret_out, 48) };
    R::Ok as c_int
}

// ── DH-3072 (RFC 3526 Group 15, SP 800-56Ar3 §5.7.1.1) ───────────
//
// One stateless entry point computing the SP 800-56Ar3 §5.7.1.1
// finite-field DH (FFC) primitive `Z = y^x mod p` over the RFC 3526
// Group 15 safe prime (3072-bit `p`, generator `g = 2`). All three
// values — private key `x`, peer public key `y`, and shared secret
// `Z` — are exactly 384 bytes (the byte-length of `p`), big-endian.
//
// Peer public-key validation follows SP 800-56Ar3 §5.6.2.3.1 (FFC
// **partial** validation: `2 ≤ y ≤ p − 2`), distinct from ECDH's
// §5.6.2.3.3 (ECC **full** validation). This is upstream-mandated:
// safe-prime FFC groups have cofactor `h = 2`, so `[2, p − 2]`
// excludes the only small-subgroup element `p − 1` of order 2 —
// see security-policy §4.8 paragraph on FFC vs ECC validation
// differential.
//
// `Z` is the **raw** FFC-DH output per SP 800-56Ar3 — callers MUST
// run an SP 800-56C Rev. 2 extractor (HKDF, KBKDF) over `Z` before
// using it as keying material; same composition discipline as ECDH.
//
// Errors: `InvalidInput = 5` covers a non-canonical private key
// `x` (outside `[1, q − 1]`), peer-key validation failure, OR the
// degenerate result `Z == 1` (the §5.7.1.1 "shall fail" condition,
// which can only occur for adversarially-chosen peer keys that
// passed partial validation but happened to lie in the order-2
// subgroup mod the cofactor — `[2, p − 2]` already excludes the
// trivial case but the upstream check is defence-in-depth).
//
// DRBG-driven keygen (`oxicrypt_dh::generate_keypair_3072`)
// deferred to a post-DRBG follow-up per stabilized arc pattern #1,
// same as ECDSA's `generate(drbg)` and ECDH's eventual `generate`.

/// Compute the SP 800-56Ar3 §5.7.1.1 finite-field DH shared secret
/// over RFC 3526 Group 15 (3072-bit safe prime): `Z = y^x mod p`.
///
/// Reads exactly 384 bytes from `x_ptr` (the caller's private key,
/// big-endian, in `[1, q − 1]` where `q = (p − 1) / 2`) and exactly
/// 384 bytes from `peer_public_key_ptr` (the peer's public key, big-
/// endian, in `[2, p − 2]`). Writes 384 bytes (the raw shared
/// secret `Z`) into `shared_secret_out`.
///
/// The shared secret is the **raw** FFC-DH output; the caller MUST
/// run an SP 800-56C Rev. 2 extractor over `Z` before using it as
/// keying material — same discipline as ECDH (see security-policy
/// §4.8 ECDH raw-Z paragraph).
///
/// Peer public key undergoes SP 800-56Ar3 §5.6.2.3.1 partial
/// validation (`2 ≤ y ≤ p − 2`) before any modular exponentiation;
/// a peer key failing the bound check causes the call to return
/// `OxiResult::InvalidInput = 5` without performing the exponent.
/// The post-exponent `Z != 1` check guards against the degenerate
/// SP 800-56Ar3 §5.7.1.1 "shall fail" outcome.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `shared_secret_out` must
/// be a non-NULL writable pointer to ≥384 bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_dh3072_compute_shared_secret(
    x_ptr: *const u8,
    peer_public_key_ptr: *const u8,
    shared_secret_out: *mut u8,
) -> c_int {
    let x = match unsafe { slice_from_raw(x_ptr, 384) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let y = match unsafe { slice_from_raw(peer_public_key_ptr, 384) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if shared_secret_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(x_arr) = <&[u8; 384]>::try_from(x) else {
        return R::Internal as c_int;
    };
    let Ok(y_arr) = <&[u8; 384]>::try_from(y) else {
        return R::Internal as c_int;
    };
    let z = match oxicrypt_dh::compute_shared_secret_3072(x_arr, y_arr) {
        Ok(z) => z,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(z.as_ptr(), shared_secret_out, 384) };
    R::Ok as c_int
}

// ── RSA verify (FIPS 186-5 §5.4, RFC 8017 §8) — stateless surface ─
//
// Six stateless entry points for RSA signature verification, mirroring
// the upstream `oxicrypt-rsa` Rust public API:
//
//   {2048, 3072, 4096} × {PKCS#1-v1.5, PSS}
//
// Hash variant is fixed at SHA-256 for all six — the only hash the
// upstream RSA crate currently exposes for the 3072 and 4096 sizes.
// All six fns take the public modulus `n` as a raw byte array
// (256 / 384 / 512 bytes big-endian), the public exponent `e` as a
// u64 (covers RFC-mandated common values 3, 17, 65537 = F4 with
// 32-bit headroom), the message bytes, and the signature as a raw
// byte array (same length as the modulus).
//
// **TagMismatch=22 mapping** (CMVP gem in security-policy §4.8): the
// upstream RSA verify fns return `Result<(), Error>` rather than
// `Result<bool, Error>` — they collapse signature-invalid AND
// input-decode-fail into a single `Err(Error::InvalidInput)`. The
// FFI maps any non-NotOperational, non-AlgorithmRestricted Err to
// `OxiResult::TagMismatch = 22` to maintain the cross-family
// verify-mismatch convention established for ECDSA / EdDSA / AEAD.
// This is a deliberate boundary choice: we lose the upstream
// distinction between "your modulus parsed wrong" and "this signature
// doesn't verify" but gain a uniform reviewer-facing semantic across
// all verify families.
//
// DRBG-driven sign + OAEP encrypt + keygen surfaces are deferred to
// post-DRBG follow-up rounds per stabilized arc pattern #1.

// ── RSA-2048 PKCS#1 v1.5 verify ──────────────────────────────────

/// Verify an RSASSA-PKCS#1-v1.5 signature with a 2048-bit RSA public
/// key, SHA-256 hash (FIPS 186-5 §5.4 / RFC 8017 §8.2).
///
/// Reads exactly 256 bytes from `n_ptr` (modulus, big-endian), takes
/// the public exponent `e` as a `uint64_t`, reads `msg_len` bytes
/// from `msg_ptr`, and reads exactly 256 bytes from `sig_ptr`.
///
/// Returns `OxiResult::Ok = 0` on a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (invalid modulus, malformed signature, digest mismatch — upstream
/// collapses these into a single Err), or a module error variant on
/// `NotOperational` / `AlgorithmRestricted`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_rsa_pkcs1_v15_verify_2048_sha256(
    n_ptr: *const u8,
    e: u64,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let n = match unsafe { slice_from_raw(n_ptr, 256) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 256) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(n_arr) = <&[u8; 256]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 256]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_rsa::rsa_pkcs1_v15_verify_2048_sha256(n_arr, e, msg, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── RSA-2048 PSS verify ──────────────────────────────────────────

/// Verify an RSASSA-PSS signature with a 2048-bit RSA public key,
/// SHA-256 as both message hash and MGF1 hash, salt length 32 bytes
/// (FIPS 186-5 §5.4 / RFC 8017 §8.1).
///
/// Reads exactly 256 bytes from `n_ptr`, takes `e` as `uint64_t`,
/// reads `msg_len` bytes from `msg_ptr`, and reads exactly 256 bytes
/// from `sig_ptr`. Returns `Ok = 0` on a valid signature,
/// `TagMismatch = 22` on any verification failure (see TagMismatch
/// paragraph in security-policy §4.8 for upstream-Err mapping
/// rationale), or a module error variant.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_rsa_pss_verify_2048_sha256(
    n_ptr: *const u8,
    e: u64,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let n = match unsafe { slice_from_raw(n_ptr, 256) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 256) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(n_arr) = <&[u8; 256]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 256]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_rsa::rsa_pss_verify_2048_sha256(n_arr, e, msg, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── RSA-3072 PKCS#1 v1.5 verify ──────────────────────────────────

/// Verify an RSASSA-PKCS#1-v1.5 signature with a 3072-bit RSA public
/// key, SHA-256 hash (FIPS 186-5 §5.4 / RFC 8017 §8.2).
///
/// Reads exactly 384 bytes from `n_ptr` and 384 bytes from `sig_ptr`.
/// See the `oxi_rsa_pkcs1_v15_verify_2048_sha256` rustdoc for return
/// semantics — identical except for byte sizes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_rsa_pkcs1_v15_verify_3072_sha256(
    n_ptr: *const u8,
    e: u64,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let n = match unsafe { slice_from_raw(n_ptr, 384) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 384) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(n_arr) = <&[u8; 384]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 384]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_rsa::rsa_3072_4096_stub::pkcs1_v15_verify_3072(n_arr, e, msg, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── RSA-3072 PSS verify ──────────────────────────────────────────

/// Verify an RSASSA-PSS signature with a 3072-bit RSA public key,
/// SHA-256 as both message hash and MGF1 hash (FIPS 186-5 §5.4 /
/// RFC 8017 §8.1).
///
/// Reads exactly 384 bytes from `n_ptr` and 384 bytes from `sig_ptr`.
/// PSS parameters per `oxicrypt_rsa::rsa3072` rustdoc:
/// `emBits = 3071`, `emLen = 384`, `sLen = hLen = 32`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_rsa_pss_verify_3072_sha256(
    n_ptr: *const u8,
    e: u64,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let n = match unsafe { slice_from_raw(n_ptr, 384) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 384) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(n_arr) = <&[u8; 384]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 384]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_rsa::rsa_3072_4096_stub::pss_verify_3072(n_arr, e, msg, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── RSA-4096 PKCS#1 v1.5 verify ──────────────────────────────────

/// Verify an RSASSA-PKCS#1-v1.5 signature with a 4096-bit RSA public
/// key, SHA-256 hash (FIPS 186-5 §5.4 / RFC 8017 §8.2).
///
/// Reads exactly 512 bytes from `n_ptr` and 512 bytes from `sig_ptr`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_rsa_pkcs1_v15_verify_4096_sha256(
    n_ptr: *const u8,
    e: u64,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let n = match unsafe { slice_from_raw(n_ptr, 512) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 512) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(n_arr) = <&[u8; 512]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 512]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_rsa::rsa_3072_4096_stub::pkcs1_v15_verify_4096(n_arr, e, msg, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── RSA-4096 PSS verify ──────────────────────────────────────────

/// Verify an RSASSA-PSS signature with a 4096-bit RSA public key,
/// SHA-256 as both message hash and MGF1 hash (FIPS 186-5 §5.4 /
/// RFC 8017 §8.1).
///
/// Reads exactly 512 bytes from `n_ptr` and 512 bytes from `sig_ptr`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxi_rsa_pss_verify_4096_sha256(
    n_ptr: *const u8,
    e: u64,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let n = match unsafe { slice_from_raw(n_ptr, 512) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 512) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(n_arr) = <&[u8; 512]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 512]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_rsa::rsa_3072_4096_stub::pss_verify_4096(n_arr, e, msg, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}
