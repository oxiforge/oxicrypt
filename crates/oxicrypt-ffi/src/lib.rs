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
//! (e.g. `oxi_init`, `oxi_sha256`), with one deliberate exception:
//! [`lama_manifest`], whose name and signature are fixed by the LAMA
//! specification so a consuming agent can resolve it without guessing.
//! It performs no cryptographic work. The prefix is short, namespaced,
//! and consistent — see `docs/c-api-design.md` for the design
//! rationale.
//!
//! # Status codes
//!
//! Every function returns a `c_int` whose value is an [`OxiResult`]
//! discriminant. `OxiResult::Ok = 0` is success; non-zero values are
//! distinct failure modes banded by source crate. See [`OxiResult`]
//! for the full mapping.
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
mod drbg;
mod error;
mod handle;
pub use aes::{
    OxiAes256Key, oxi_aes256_cbc_decrypt, oxi_aes256_cbc_encrypt, oxi_aes256_ccm_decrypt,
    oxi_aes256_ccm_encrypt, oxi_aes256_cmac, oxi_aes256_ctr, oxi_aes256_free,
    oxi_aes256_gcm_decrypt, oxi_aes256_gcm_encrypt, oxi_aes256_kw_unwrap, oxi_aes256_kw_wrap,
    oxi_aes256_kwp_unwrap, oxi_aes256_kwp_wrap, oxi_aes256_new,
};
pub use drbg::{
    OxiCtrDrbgAes128, OxiCtrDrbgAes192, OxiCtrDrbgAes256, OxiHashDrbgSha256, OxiHashDrbgSha384,
    OxiHashDrbgSha512, OxiHmacDrbgSha256, OxiHmacDrbgSha384, OxiHmacDrbgSha512,
    oxi_ctr_drbg_aes128_free, oxi_ctr_drbg_aes128_generate_df, oxi_ctr_drbg_aes128_generate_no_df,
    oxi_ctr_drbg_aes128_instantiate_df, oxi_ctr_drbg_aes128_instantiate_no_df,
    oxi_ctr_drbg_aes128_new, oxi_ctr_drbg_aes128_reseed_df, oxi_ctr_drbg_aes128_reseed_no_df,
    oxi_ctr_drbg_aes192_free, oxi_ctr_drbg_aes192_generate_df, oxi_ctr_drbg_aes192_generate_no_df,
    oxi_ctr_drbg_aes192_instantiate_df, oxi_ctr_drbg_aes192_instantiate_no_df,
    oxi_ctr_drbg_aes192_new, oxi_ctr_drbg_aes192_reseed_df, oxi_ctr_drbg_aes192_reseed_no_df,
    oxi_ctr_drbg_aes256_free, oxi_ctr_drbg_aes256_generate_df, oxi_ctr_drbg_aes256_generate_no_df,
    oxi_ctr_drbg_aes256_instantiate_df, oxi_ctr_drbg_aes256_instantiate_no_df,
    oxi_ctr_drbg_aes256_new, oxi_ctr_drbg_aes256_reseed_df, oxi_ctr_drbg_aes256_reseed_no_df,
    oxi_hash_drbg_sha256_free, oxi_hash_drbg_sha256_generate, oxi_hash_drbg_sha256_instantiate,
    oxi_hash_drbg_sha256_new, oxi_hash_drbg_sha256_reseed, oxi_hash_drbg_sha384_free,
    oxi_hash_drbg_sha384_generate, oxi_hash_drbg_sha384_instantiate, oxi_hash_drbg_sha384_new,
    oxi_hash_drbg_sha384_reseed, oxi_hash_drbg_sha512_free, oxi_hash_drbg_sha512_generate,
    oxi_hash_drbg_sha512_instantiate, oxi_hash_drbg_sha512_new, oxi_hash_drbg_sha512_reseed,
    oxi_hmac_drbg_sha256_free, oxi_hmac_drbg_sha256_generate, oxi_hmac_drbg_sha256_instantiate,
    oxi_hmac_drbg_sha256_new, oxi_hmac_drbg_sha256_reseed, oxi_hmac_drbg_sha384_free,
    oxi_hmac_drbg_sha384_generate, oxi_hmac_drbg_sha384_instantiate, oxi_hmac_drbg_sha384_new,
    oxi_hmac_drbg_sha384_reseed, oxi_hmac_drbg_sha512_free, oxi_hmac_drbg_sha512_generate,
    oxi_hmac_drbg_sha512_instantiate, oxi_hmac_drbg_sha512_new, oxi_hmac_drbg_sha512_reseed,
};
pub use error::OxiResult;

use crate::error::{OxiResult as R, status_kdf, status_module};
use crate::handle::OxiHandle;
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

/// Collect every algorithm KAT entry from every algorithm crate into a
/// single flat `Vec`.
///
/// The integrity self-test KAT (`oxicrypt_integrity::KATS`) is not
/// collected here: [`oxi_init`] passes it separately, as the required
/// integrity argument to `initialize_with_profile`. `oxicrypt_integrity`
/// verifies the artifact that contains it — it locates its slot by that
/// slot's own runtime address, so a cdylib verifies itself rather than
/// its host.
///
/// The integrity slot ships in the cdylib and staticlib (forced via
/// the `_SLOT_REF` static below) and the shared library is sign-able
/// with `oxicrypt-integrity-sign --cdylib-target …`.
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
/// guaranteeing its `oxicrypt_integrity::SLOT_SIZE` bytes land
/// contiguously in the output binary's `.rodata` so
/// `oxicrypt-integrity-sign` can locate and populate them.
#[used]
static _SLOT_REF: &oxicrypt_integrity::IntegritySlot = &oxicrypt_integrity::FIPS_INTEGRITY_SLOT;

/// The LAMA manifest, embedded at compile time and NUL-terminated so it
/// can be handed to C without an allocation or a runtime file read.
static LAMA_MANIFEST: &str = concat!(include_str!("../llm-api.yaml"), "\0");

/// Return the LAMA API manifest as a NUL-terminated UTF-8 string with
/// static lifetime.
///
/// This is the shared-library half of LAMA discovery: an agent that has
/// loaded the `.so` / `.dylib` / `.dll` resolves this symbol and reads the
/// manifest describing every `oxi_*` entry point, rather than inferring
/// the API from the header. The specification fixes both the name and the
/// signature — `const char *lama_manifest(void)` — so this is the one
/// exported symbol in this crate that does **not** carry the `oxi_`
/// prefix: a name an agent has to guess would defeat the purpose.
///
/// See <https://github.com/lamaspec/lama/blob/main/SPEC.md> §"Discovery".
///
/// The returned pointer is valid for the lifetime of the loaded library
/// and must not be freed. The manifest is metadata about the binary, not
/// a service it provides, so this requires no initialisation and is
/// callable before [`oxi_init`] and regardless of module state.
///
/// # Safety
///
/// No pointers in; always safe to call. The caller must treat the result
/// as read-only and must not free it.
#[unsafe(no_mangle)]
pub extern "C" fn lama_manifest() -> *const core::ffi::c_char {
    LAMA_MANIFEST.as_ptr().cast::<core::ffi::c_char>()
}

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
#[unsafe(no_mangle)]
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
    match oxicrypt_module::initialize_with_profile(oxicrypt_integrity::KATS, &kats, p) {
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub extern "C" fn oxi_is_operational() -> c_int {
    c_int::from(oxicrypt_module::is_operational())
}

/// Returns the pre-operational integrity test's status indicator.
///
/// | Value | Meaning |
/// |---|---|
/// | 0 | `NotRun` — the test has not run in this process |
/// | 1 | `Passed` — the image matched its reference MAC |
/// | 2 | `Mismatch` — the image does not match its reference MAC |
/// | 3 | `SlotInvalid` — the slot is absent, malformed, or impossible |
/// | 4 | `Unreadable` — the test was **not performed** |
/// | 5 | `CastNotRun` — the test was reached before its CAST |
/// | 6 | `Unknown` — the record held a value this module never writes |
///
/// This exists because `oxi_init` cannot carry the distinction: a
/// failing self-test returns [`OxiResult::SelfTestFailed`] whatever the
/// cause, so `Mismatch` and `Unreadable` are indistinguishable from its
/// return value alone. Security Policy §5.2 requires an operator and a
/// test laboratory to be able to tell those two apart — a corrupt module
/// from an environment that could not supply the module's own bytes —
/// and this query is how that is retrieved.
///
/// The value latches on the first run and nothing is re-run here, so a
/// later call cannot revise it and this is safe to call from the error
/// state. A value of 6 means the record held something this module never
/// writes.
///
/// # Safety
///
/// No pointers; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_integrity_status() -> c_int {
    oxicrypt_integrity::status() as c_int
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

// ── ECDH (SP 800-56Ar3 §5.7.1.2) ─────────────────────────────────
//
// Four entry points, two per curve. Per curve: one stateless
// `compute_shared_secret` computing the SP 800-56Ar3 §5.7.1.2 ECC
// CDH primitive `Z = x(d * Q)`, and one DRBG-driven
// `generate_keypair` that samples a fresh `(d, Q)` pair via the
// FIPS 186-5 §A.2.2 rejection sampler and runs the IG 10.3.A
// pairwise consistency test before returning. No
// `derive_public_key` entry point — ECDH and ECDSA share the same
// scalar-multiplication primitive on each curve, so callers
// needing the public key from a stored private scalar should
// reuse `oxi_ecdsa_p{256,384}_derive_public_key` from the ECDSA
// family.
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

// ── ECDH P-256 — DRBG-driven keypair generation ──────────────────

/// Generate a fresh ECDH P-256 key pair via the FIPS 186-5 §A.2.2
/// rejection sampler driven by `drbg`, run the IG 10.3.A pairwise
/// consistency test, and write the private/public key bytes to the
/// caller-provided buffers.
///
/// On success, writes 32 bytes (the private scalar `d` in canonical
/// big-endian encoding, in `[1, n − 1]`) into `private_out` and
/// 65 bytes (the SEC1 uncompressed public key `0x04 || X(32) || Y(32)`
/// of `Q = d · G`) into `public_out`. The IG 10.3.A PCT runs as an
/// ECDH roundtrip against the RFC 5903 §8.1 responder keypair: a
/// faulted scalar-mul during keygen produces a `Q` that fails the
/// roundtrip equality and the call returns
/// `OxiResult::InvalidInput = 5` without writing the buffers.
///
/// Applies the per-call-mutating-handle thread-safety contract:
/// callers MUST serialise concurrent calls on the same `drbg`
/// pointer (the FFI projects `*mut OxiHmacDrbgSha256` to
/// `&mut HmacDrbgSha256` for the duration of this call, which
/// Rust's exclusivity rule enforces internally but cannot enforce
/// across the C boundary). See the per-call-mutating-handle
/// paragraph in `docs/security-policy/security-policy.md` §4.8.
///
/// Returns `OxiResult::Ok = 0` on success;
/// `OxiResult::NullPointer = 10` if any pointer is NULL;
/// `OxiResult::NotOperational = 1` if the FIPS module is not in
/// the `Operational` state OR the DRBG handle has been finalised;
/// `OxiResult::AlgorithmRestricted = 6` if the active profile does
/// not allow ECDH-P-256;
/// `OxiResult::InvalidInput = 5` if the DRBG faults during sampling,
/// rejection-sampling exhausts without an in-range scalar (in
/// practice only a broken DRBG), or the IG 10.3.A PCT mismatches.
///
/// # Safety
///
/// `drbg` must be a live, instantiated handle from
/// [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate`]. `private_out` must be a
/// non-NULL writable pointer to ≥32 bytes. `public_out` must be a
/// non-NULL writable pointer to ≥65 bytes. The caller MUST
/// serialise concurrent calls on the same `drbg` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdh_p256_generate_keypair(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    private_out: *mut u8,
    public_out: *mut u8,
) -> c_int {
    if drbg.is_null() || private_out.is_null() || public_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let (d, q) = match oxicrypt_ecdh::generate_keypair_p256(drbg_ref) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), private_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(q.as_ptr(), public_out, 65) };
    R::Ok as c_int
}

// ── ECDH P-384 — DRBG-driven keypair generation ──────────────────

/// Generate a fresh ECDH P-384 key pair via the FIPS 186-5 §A.2.2
/// rejection sampler driven by `drbg`, run the IG 10.3.A pairwise
/// consistency test, and write the private/public key bytes to the
/// caller-provided buffers.
///
/// Mirrors [`oxi_ecdh_p256_generate_keypair`] for the P-384 curve:
/// 48-byte private scalar, 97-byte SEC1 uncompressed public key,
/// RFC 5903 §8.2 responder keypair drives the IG 10.3.A PCT.
/// Same error mapping and thread-safety contract.
///
/// # Safety
///
/// `drbg` must be a live, instantiated handle. `private_out` must be
/// a non-NULL writable pointer to ≥48 bytes. `public_out` must be a
/// non-NULL writable pointer to ≥97 bytes. Callers MUST serialise
/// concurrent calls on the same `drbg` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdh_p384_generate_keypair(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    private_out: *mut u8,
    public_out: *mut u8,
) -> c_int {
    if drbg.is_null() || private_out.is_null() || public_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let (d, q) = match oxicrypt_ecdh::generate_keypair_p384(drbg_ref) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), private_out, 48) };
    unsafe { core::ptr::copy_nonoverlapping(q.as_ptr(), public_out, 97) };
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
#[unsafe(no_mangle)]
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

/// Generate a DH-3072 key pair `(private_key, public_key)` from the
/// caller-supplied DRBG handle (RFC 3526 Group 15, SP 800-56Ar3
/// §5.7.1.1).
///
/// The private key `x` is sampled from `[1, q − 1]` via HMAC-DRBG-
/// SHA-256 rejection sampling. The public key is `y = 2^x mod p`. On
/// success, writes the 384-byte big-endian `x` into `private_out` and
/// the 384-byte big-endian `y` into `public_out`. The DRBG handle is
/// advanced (its `(K, V, reseed_counter)` state mutates) by the
/// rejection-sampling loop.
///
/// **First C ABI surface to consume an opaque DRBG handle.** The
/// caller is responsible for: (a) allocating the handle via
/// [`oxi_hmac_drbg_sha256_new`]; (b) instantiating it via
/// [`oxi_hmac_drbg_sha256_instantiate`] with caller-sourced entropy
/// before this call; (c) freeing it via [`oxi_hmac_drbg_sha256_free`]
/// after use; and (d) serializing all calls on the same handle
/// pointer per the per-call-mutating-handle thread-safety contract.
///
/// Returns `OxiResult::Ok = 0` on success; `OxiResult::InvalidInput
/// = 5` if the DRBG is uninstantiated, exhausts its rejection-
/// sampling attempts, or fails to produce output (the upstream
/// `Option` is collapsed to `Err(InvalidInput)` by the gated public
/// API); `OxiResult::NotOperational = 1` if the FIPS module is not
/// operational; or `OxiResult::AlgorithmRestricted = 6` if the
/// active profile blocks DH-3072.
///
/// # Safety
///
/// `drbg` must be a live handle from [`oxi_hmac_drbg_sha256_new`]
/// that has been instantiated. `private_out` must be a non-NULL
/// writable pointer to ≥384 bytes. `public_out` must be a non-NULL
/// writable pointer to ≥384 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_dh3072_generate_keypair(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    private_out: *mut u8,
    public_out: *mut u8,
) -> c_int {
    if drbg.is_null() || private_out.is_null() || public_out.is_null() {
        return R::NullPointer as c_int;
    }
    // Project to `&mut HmacDrbgSha256` via the `inner_mut` accessor
    // on `OxiHmacDrbgSha256` (added alongside this round). The
    // `&mut self` borrow upholds Rust's exclusivity rule for the
    // duration of this FFI call; C-side concurrent calls on the same
    // handle pointer are a serialization-contract violation per the
    // per-call-mutating-handle thread-safety contract documented in
    // `drbg.rs` and security-policy.md.
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let (x, y) = match oxicrypt_dh::generate_keypair_3072(drbg_ref) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(x.as_ptr(), private_out, 384) };
    unsafe { core::ptr::copy_nonoverlapping(y.as_ptr(), public_out, 384) };
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

// ── ML-DSA-87 (FIPS 204) — stateless surface ─────────────────────
//
// Three pure entry points: keygen, sign, verify. ML-DSA-87 is the
// CNSA 2.0 digital-signature algorithm (lattice-based, post-quantum).
// All three operations are deterministic on the byte-array surface:
//
//   - keygen(xi) → (pk, sk)  per FIPS 204 §6.1 — `xi` is a 32-byte
//     caller-supplied seed. NO DRBG is consumed inside the FFI; the
//     caller is responsible for sourcing `xi` from an SP 800-90A
//     DRBG (or any approved entropy source). Mirrors the EdDSA
//     pattern: the `Service::MlDsa87Keygen` gate is "is the algorithm
//     allowed?", NOT "do we have entropy?".
//   - sign(sk, msg, ctx) → sig  per FIPS 204 §5.2 Algorithm 2 — the
//     external pure-ML-DSA Sign API. Signing is **deterministic**:
//     the rejection-sampling iteration count varies with the secret
//     key, but for any given `(sk, msg, ctx)` the signature is
//     bit-identical across calls. NO randomized variant is exposed
//     (FIPS 204 §5.2.1 randomized mode is intentionally omitted).
//   - verify(pk, msg, ctx, sig) → bool  per FIPS 204 §5.2 Algorithm 3.
//     Upstream returns `Result<(), Error>` collapsing decode-fail and
//     verify-fail into `Err(Error::InvalidInput)`; the FFI maps that
//     to `OxiResult::TagMismatch = 22` per the cross-family
//     verify-mismatch convention (security-policy §4.8). Same shape
//     as RSA verify (PR #17).
//
// Byte layout: xi = 32 bytes; pk = 2592 bytes; sk = 4896 bytes;
// sig = 4627 bytes; ctx = 0..=255 bytes (FIPS 204 §5.2 limit,
// enforced upstream as `Error::InvalidInput`). Pass `ctx_len = 0`
// for the empty context used by X.509, CMS, and other LAMPS-
// conformant callers.
//
// Per-variant naming: this is `ml_dsa_87` (not `ml_dsa(param: int)`)
// per stabilized arc pattern #8 — when ML-DSA-44 / ML-DSA-65 ship,
// they will be added as new fns (`oxi_ml_dsa_44_*`, `oxi_ml_dsa_65_*`)
// rather than as enum-dispatched parameters on these. Existing C
// callers do not recompile when new variants ship.

/// Generate an ML-DSA-87 key pair from a 32-byte seed (FIPS 204 §6.1).
///
/// Reads exactly 32 bytes from `seed_ptr` (the keygen randomness
/// `xi`). Writes the 2592-byte public key into `pk_out` and the
/// 4896-byte secret key into `sk_out`. The caller is responsible for
/// sourcing `seed_ptr` from an approved DRBG (SP 800-90A); the FFI
/// performs no entropy generation.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `pk_out` and `sk_out` must
/// each be non-NULL writable pointers to ≥2592 and ≥4896 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_87_keygen(
    seed_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let seed = match unsafe { slice_from_raw(seed_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(seed_arr) = <&[u8; 32]>::try_from(seed) else {
        return R::Internal as c_int;
    };
    let (pk, sk) = match oxicrypt_ml_dsa::keygen(seed_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 2592) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 4896) };
    R::Ok as c_int
}

/// Sign a message with ML-DSA-87 (FIPS 204 §5.2 Algorithm 2).
///
/// Reads exactly 4896 bytes from `sk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
/// 4627-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
/// `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.
///
/// Signing is deterministic: bit-identical signature across calls
/// for the same `(sk, msg, ctx)` triple. NO randomized-mode variant
/// is exposed.
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
/// `ctx_len > 255` (FIPS 204 §5.2 limit) or rejection sampling fails
/// after the upstream bound, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must be a
/// non-NULL writable pointer to ≥4627 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_87_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 4896) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(sk_arr) = <&[u8; 4896]>::try_from(sk) else {
        return R::Internal as c_int;
    };
    let sig = match oxicrypt_ml_dsa::sign(sk_arr, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 4627) };
    R::Ok as c_int
}

/// Verify an ML-DSA-87 signature (FIPS 204 §5.2 Algorithm 3).
///
/// Reads exactly 2592 bytes from `pk_ptr`, `msg_len` bytes from
/// `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 4627 bytes from
/// `sig_ptr`. Pass `ctx_len = 0` for the empty context used by
/// X.509 / CMS / LAMPS.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (decode-fail OR signature-invalid — upstream collapses these into
/// a single `Err(InvalidInput)`; same shape as RSA verify), or a
/// module error variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_87_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 2592) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 4627) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk_arr) = <&[u8; 2592]>::try_from(pk) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 4627]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_ml_dsa::verify(pk_arr, msg, ctx, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── ML-DSA-44 (FIPS 204) — stateless surface ─────────────────────
//
// Per-variant additive expansion of the ML-DSA-87 surface above.
// Same three-entry-point shape (keygen, sign, verify), same
// deterministic-signing semantics, same `Err(InvalidInput)` →
// `TagMismatch = 22` collapse on verify — only the byte counts
// differ per FIPS 204 §4 Table 1 (k=4, ℓ=4 parameter set): pk = 1312
// bytes, sk = 2560 bytes, sig = 2420 bytes. The 32-byte seed `xi`
// and the 0..=255-byte ctx are parameter-set-invariant per
// FIPS 204 §5.2 / §6.1.
//
// CNSA gating: ML-DSA-44 is **not** part of CNSA 2.0 (which
// mandates ML-DSA-87) and is **not** in the CNSA 1.0 transition
// allow-list either. The underlying `Service::MlDsa44Keygen /
// Sign / Verify` variants are permitted only under
// `AlgorithmProfile::Unrestricted`; calls under either CNSA profile
// return `OxiResult::AlgorithmRestricted = 6` via the existing
// `require_allowed` gate in `oxicrypt_module`.

/// Generate an ML-DSA-44 key pair from a 32-byte seed (FIPS 204 §6.1).
///
/// Reads exactly 32 bytes from `seed_ptr` (the keygen randomness
/// `xi`). Writes the 1312-byte public key into `pk_out` and the
/// 2560-byte secret key into `sk_out`. The caller is responsible for
/// sourcing `seed_ptr` from an approved DRBG (SP 800-90A); the FFI
/// performs no entropy generation.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `pk_out` and `sk_out` must
/// each be non-NULL writable pointers to ≥1312 and ≥2560 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_44_keygen(
    seed_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let seed = match unsafe { slice_from_raw(seed_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(seed_arr) = <&[u8; 32]>::try_from(seed) else {
        return R::Internal as c_int;
    };
    let (pk, sk) = match oxicrypt_ml_dsa::ml_dsa_44::keygen(seed_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 1312) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 2560) };
    R::Ok as c_int
}

/// Sign a message with ML-DSA-44 (FIPS 204 §5.2 Algorithm 2).
///
/// Reads exactly 2560 bytes from `sk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
/// 2420-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
/// `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.
///
/// Signing is deterministic: bit-identical signature across calls
/// for the same `(sk, msg, ctx)` triple. NO randomized-mode variant
/// is exposed.
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
/// `ctx_len > 255` (FIPS 204 §5.2 limit) or rejection sampling fails
/// after the upstream bound, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must be a
/// non-NULL writable pointer to ≥2420 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_44_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 2560) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(sk_arr) = <&[u8; 2560]>::try_from(sk) else {
        return R::Internal as c_int;
    };
    let sig = match oxicrypt_ml_dsa::ml_dsa_44::sign(sk_arr, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 2420) };
    R::Ok as c_int
}

/// Verify an ML-DSA-44 signature (FIPS 204 §5.2 Algorithm 3).
///
/// Reads exactly 1312 bytes from `pk_ptr`, `msg_len` bytes from
/// `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 2420 bytes from
/// `sig_ptr`. Pass `ctx_len = 0` for the empty context used by
/// X.509 / CMS / LAMPS.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (decode-fail OR signature-invalid — upstream collapses these into
/// a single `Err(InvalidInput)`; same shape as RSA verify), or a
/// module error variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_44_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 1312) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 2420) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk_arr) = <&[u8; 1312]>::try_from(pk) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 2420]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_ml_dsa::ml_dsa_44::verify(pk_arr, msg, ctx, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── ML-DSA-65 (FIPS 204) — stateless surface ─────────────────────
//
// Per-variant additive expansion of the ML-DSA-87 surface above.
// Same three-entry-point shape (keygen, sign, verify), same
// deterministic-signing semantics, same `Err(InvalidInput)` →
// `TagMismatch = 22` collapse on verify — only the byte counts
// differ per FIPS 204 §4 Table 1 (k=6, ℓ=5 parameter set): pk = 1952
// bytes, sk = 4032 bytes, sig = 3309 bytes. The 32-byte seed `xi`
// and the 0..=255-byte ctx are parameter-set-invariant per
// FIPS 204 §5.2 / §6.1.
//
// CNSA gating: ML-DSA-65 is **not** part of CNSA 2.0 (which
// mandates ML-DSA-87) and is **not** in the CNSA 1.0 transition
// allow-list either. The underlying `Service::MlDsa65Keygen /
// Sign / Verify` variants are permitted only under
// `AlgorithmProfile::Unrestricted`; calls under either CNSA profile
// return `OxiResult::AlgorithmRestricted = 6` via the existing
// `require_allowed` gate in `oxicrypt_module`.

/// Generate an ML-DSA-65 key pair from a 32-byte seed (FIPS 204 §6.1).
///
/// Reads exactly 32 bytes from `seed_ptr` (the keygen randomness
/// `xi`). Writes the 1952-byte public key into `pk_out` and the
/// 4032-byte secret key into `sk_out`. The caller is responsible for
/// sourcing `seed_ptr` from an approved DRBG (SP 800-90A); the FFI
/// performs no entropy generation.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `pk_out` and `sk_out` must
/// each be non-NULL writable pointers to ≥1952 and ≥4032 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_65_keygen(
    seed_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let seed = match unsafe { slice_from_raw(seed_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(seed_arr) = <&[u8; 32]>::try_from(seed) else {
        return R::Internal as c_int;
    };
    let (pk, sk) = match oxicrypt_ml_dsa::ml_dsa_65::keygen(seed_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 1952) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 4032) };
    R::Ok as c_int
}

/// Sign a message with ML-DSA-65 (FIPS 204 §5.2 Algorithm 2).
///
/// Reads exactly 4032 bytes from `sk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
/// 3309-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
/// `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.
///
/// Signing is deterministic: bit-identical signature across calls
/// for the same `(sk, msg, ctx)` triple. NO randomized-mode variant
/// is exposed.
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
/// `ctx_len > 255` (FIPS 204 §5.2 limit) or rejection sampling fails
/// after the upstream bound, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must be a
/// non-NULL writable pointer to ≥3309 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_65_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 4032) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(sk_arr) = <&[u8; 4032]>::try_from(sk) else {
        return R::Internal as c_int;
    };
    let sig = match oxicrypt_ml_dsa::ml_dsa_65::sign(sk_arr, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 3309) };
    R::Ok as c_int
}

/// Verify an ML-DSA-65 signature (FIPS 204 §5.2 Algorithm 3).
///
/// Reads exactly 1952 bytes from `pk_ptr`, `msg_len` bytes from
/// `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 3309 bytes from
/// `sig_ptr`. Pass `ctx_len = 0` for the empty context used by
/// X.509 / CMS / LAMPS.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (decode-fail OR signature-invalid — upstream collapses these into
/// a single `Err(InvalidInput)`; same shape as RSA verify), or a
/// module error variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_65_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 1952) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 3309) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk_arr) = <&[u8; 1952]>::try_from(pk) else {
        return R::Internal as c_int;
    };
    let Ok(sig_arr) = <&[u8; 3309]>::try_from(sig) else {
        return R::Internal as c_int;
    };
    match oxicrypt_ml_dsa::ml_dsa_65::verify(pk_arr, msg, ctx, sig_arr) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── ML-KEM-1024 (FIPS 203) — stateless surface ───────────────────
//
// Three pure entry points: keygen, encapsulate, decapsulate.
// ML-KEM-1024 is the CNSA 2.0 post-quantum KEM (key encapsulation
// mechanism), mandated for key establishment by the 2027 deadline.
// All three operations are exposed at a stateless byte-array surface
// with NO DRBG plumbing at the FFI boundary:
//
//   - keygen(d, z) → (ek, dk)  per FIPS 203 §6.1 (ML-KEM.KeyGen).
//     `d` is the K-PKE keygen randomness (32 bytes); `z` is the
//     implicit-rejection seed embedded in `dk` (32 bytes). BOTH are
//     caller-supplied — the caller is responsible for sourcing each
//     from an SP 800-90A DRBG. They are NOT interchangeable: `d`
//     drives the K-PKE matrix expansion and secret sampling; `z` is
//     written into `dk` for use in the FO transform's deterministic
//     implicit-rejection branch. Mixing them would produce a
//     well-formed but adversarially-distinguishable key pair.
//   - encapsulate(ek, m) → (ss, ct)  per FIPS 203 §6.2. `m` is the
//     32-byte encapsulation randomness; caller-supplied (SP 800-90A
//     DRBG responsibility). Returns the 32-byte shared secret and
//     1568-byte ciphertext.
//   - decapsulate(dk, ct) → ss  per FIPS 203 §6.3. **Fully
//     deterministic**: no caller-supplied randomness. The FO
//     transform's implicit-rejection branch absorbs tampered
//     ciphertext into a deterministic-but-pseudorandom shared secret
//     in constant time. Tampered ct does NOT surface as a discrete
//     error code — it produces a useless-but-uniform shared secret.
//     This is the deliberate FIPS 203 §6.3 design (see
//     decapsulate-implicit-rejection paragraph in security-policy
//     §4.9). Distinct from RSA verify / ML-DSA verify / EdDSA verify
//     — there is NO `OxiResult::TagMismatch = 22` mapping for
//     ML-KEM decapsulate.
//
// Byte layout: d = z = m = 32 bytes; ek = 1568 bytes; dk = 3168
// bytes; ct = 1568 bytes; ss = 32 bytes (FIPS 203 Table 2,
// ML-KEM-1024 parameter set k=4).
//
// Per-variant naming: this is `ml_kem_1024` (not
// `ml_kem(param: int)`) per stabilized arc pattern #8 — when
// ML-KEM-512 / ML-KEM-768 ship, they will be added as new fns
// (`oxi_ml_kem_512_*`, `oxi_ml_kem_768_*`) rather than as
// enum-dispatched parameters on these. Existing C callers do not
// recompile when new variants ship.

/// Generate an ML-KEM-1024 key pair from two 32-byte caller-supplied
/// seeds (FIPS 203 §6.1 ML-KEM.KeyGen).
///
/// Reads exactly 32 bytes from `d_ptr` (K-PKE keygen randomness) and
/// exactly 32 bytes from `z_ptr` (implicit-rejection seed). Writes
/// the 1568-byte encapsulation key into `ek_out` and the 3168-byte
/// decapsulation key into `dk_out`. Both seeds are caller-supplied;
/// the caller MUST source each independently from an approved DRBG
/// (SP 800-90A). `d` and `z` are NOT interchangeable — see the
/// section comment above for the semantic distinction.
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if a
/// rare K-PKE NTT decode failure occurs during keygen, or a module
/// error variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ek_out` and `dk_out`
/// must each be non-NULL writable pointers to ≥1568 and ≥3168 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_1024_keygen(
    d_ptr: *const u8,
    z_ptr: *const u8,
    ek_out: *mut u8,
    dk_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let z = match unsafe { slice_from_raw(z_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ek_out.is_null() || dk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 32]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let Ok(z_arr) = <&[u8; 32]>::try_from(z) else {
        return R::Internal as c_int;
    };
    let (ek, dk) = match oxicrypt_ml_kem::keygen(d_arr, z_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ek.as_ptr(), ek_out, 1568) };
    unsafe { core::ptr::copy_nonoverlapping(dk.as_ptr(), dk_out, 3168) };
    R::Ok as c_int
}

/// Encapsulate a shared secret against an ML-KEM-1024 encapsulation
/// key (FIPS 203 §6.2 ML-KEM.Encaps).
///
/// Reads exactly 1568 bytes from `ek_ptr` and exactly 32 bytes from
/// `m_ptr` (encapsulation randomness, caller-supplied from an
/// SP 800-90A DRBG). Writes the 32-byte shared secret into `ss_out`
/// and the 1568-byte ciphertext into `ct_out`.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ss_out` and `ct_out`
/// must each be non-NULL writable pointers to ≥32 and ≥1568 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_1024_encapsulate(
    ek_ptr: *const u8,
    m_ptr: *const u8,
    ss_out: *mut u8,
    ct_out: *mut u8,
) -> c_int {
    let ek = match unsafe { slice_from_raw(ek_ptr, 1568) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let m = match unsafe { slice_from_raw(m_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ss_out.is_null() || ct_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(ek_arr) = <&[u8; 1568]>::try_from(ek) else {
        return R::Internal as c_int;
    };
    let Ok(m_arr) = <&[u8; 32]>::try_from(m) else {
        return R::Internal as c_int;
    };
    let (ss, ct) = match oxicrypt_ml_kem::encapsulate(ek_arr, m_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, 1568) };
    R::Ok as c_int
}

/// Decapsulate a shared secret from an ML-KEM-1024 ciphertext
/// (FIPS 203 §6.3 ML-KEM.Decaps).
///
/// Reads exactly 3168 bytes from `dk_ptr` and exactly 1568 bytes
/// from `ct_ptr`. Writes the 32-byte shared secret into `ss_out`.
/// **Fully deterministic** — no caller randomness, no `Ok(false)`
/// shape, no `TagMismatch = 22` mapping. The FO transform's
/// implicit-rejection branch absorbs tampered ciphertext into a
/// deterministic-but-pseudorandom shared secret in constant time;
/// tamper does NOT surface as a discriminant. See the
/// decapsulate-implicit-rejection paragraph in security-policy §4.9.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error
/// variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ss_out` must be a
/// non-NULL writable pointer to ≥32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_1024_decapsulate(
    dk_ptr: *const u8,
    ct_ptr: *const u8,
    ss_out: *mut u8,
) -> c_int {
    let dk = match unsafe { slice_from_raw(dk_ptr, 3168) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct = match unsafe { slice_from_raw(ct_ptr, 1568) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ss_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(dk_arr) = <&[u8; 3168]>::try_from(dk) else {
        return R::Internal as c_int;
    };
    let Ok(ct_arr) = <&[u8; 1568]>::try_from(ct) else {
        return R::Internal as c_int;
    };
    let ss = match oxicrypt_ml_kem::decapsulate(dk_arr, ct_arr) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32) };
    R::Ok as c_int
}

// ── ML-KEM-512 (FIPS 203) — stateless surface ────────────────────
//
// Per-variant additive expansion of the ML-KEM-1024 surface above.
// Same three-entry-point shape (keygen, encapsulate, decapsulate),
// same caller-seeded `(d, z)` + `m` randomness contracts, same
// implicit-rejection semantics on decapsulate — only the byte
// counts differ per FIPS 203 Table 2 (k=2 parameter set): ek = 800
// bytes, dk = 1632 bytes, ct = 768 bytes. The 32-byte seeds and
// the 32-byte shared secret are parameter-set-invariant per
// FIPS 203 §6.1–§6.3.
//
// CNSA gating: ML-KEM-512 is **not** part of CNSA 2.0 (which
// mandates ML-KEM-1024) and is **not** in the CNSA 1.0 transition
// allow-list either. The underlying `Service::MlKem512Keygen /
// Encaps / Decaps` variants are permitted only under
// `AlgorithmProfile::Unrestricted`; calls under either CNSA profile
// return `OxiResult::AlgorithmRestricted = 6` via the existing
// `require_allowed` gate in `oxicrypt_module`.

/// Generate an ML-KEM-512 key pair from two 32-byte caller-supplied
/// seeds (FIPS 203 §6.1 ML-KEM.KeyGen, k=2 parameter set).
///
/// Reads exactly 32 bytes from `d_ptr` (K-PKE keygen randomness) and
/// exactly 32 bytes from `z_ptr` (implicit-rejection seed). Writes
/// the 800-byte encapsulation key into `ek_out` and the 1632-byte
/// decapsulation key into `dk_out`. Both seeds are caller-supplied;
/// the caller MUST source each independently from an approved DRBG
/// (SP 800-90A). `d` and `z` are NOT interchangeable — see the
/// ML-KEM-1024 section comment above for the semantic distinction
/// (identical across all three parameter sets).
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if a
/// rare K-PKE NTT decode failure occurs during keygen, or a module
/// error variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ek_out` and `dk_out`
/// must each be non-NULL writable pointers to ≥800 and ≥1632 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_512_keygen(
    d_ptr: *const u8,
    z_ptr: *const u8,
    ek_out: *mut u8,
    dk_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let z = match unsafe { slice_from_raw(z_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ek_out.is_null() || dk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 32]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let Ok(z_arr) = <&[u8; 32]>::try_from(z) else {
        return R::Internal as c_int;
    };
    let (ek, dk) = match oxicrypt_ml_kem::ml_kem_512::keygen(d_arr, z_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ek.as_ptr(), ek_out, 800) };
    unsafe { core::ptr::copy_nonoverlapping(dk.as_ptr(), dk_out, 1632) };
    R::Ok as c_int
}

/// Encapsulate a shared secret against an ML-KEM-512 encapsulation
/// key (FIPS 203 §6.2 ML-KEM.Encaps, k=2 parameter set).
///
/// Reads exactly 800 bytes from `ek_ptr` and exactly 32 bytes from
/// `m_ptr` (encapsulation randomness, caller-supplied from an
/// SP 800-90A DRBG). Writes the 32-byte shared secret into `ss_out`
/// and the 768-byte ciphertext into `ct_out`.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ss_out` and `ct_out`
/// must each be non-NULL writable pointers to ≥32 and ≥768 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_512_encapsulate(
    ek_ptr: *const u8,
    m_ptr: *const u8,
    ss_out: *mut u8,
    ct_out: *mut u8,
) -> c_int {
    let ek = match unsafe { slice_from_raw(ek_ptr, 800) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let m = match unsafe { slice_from_raw(m_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ss_out.is_null() || ct_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(ek_arr) = <&[u8; 800]>::try_from(ek) else {
        return R::Internal as c_int;
    };
    let Ok(m_arr) = <&[u8; 32]>::try_from(m) else {
        return R::Internal as c_int;
    };
    let (ss, ct) = match oxicrypt_ml_kem::ml_kem_512::encapsulate(ek_arr, m_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, 768) };
    R::Ok as c_int
}

/// Decapsulate a shared secret from an ML-KEM-512 ciphertext
/// (FIPS 203 §6.3 ML-KEM.Decaps, k=2 parameter set).
///
/// Reads exactly 1632 bytes from `dk_ptr` and exactly 768 bytes
/// from `ct_ptr`. Writes the 32-byte shared secret into `ss_out`.
/// **Fully deterministic** — no caller randomness, no `Ok(false)`
/// shape, no `TagMismatch = 22` mapping. The FO transform's
/// implicit-rejection branch absorbs tampered ciphertext into a
/// deterministic-but-pseudorandom shared secret in constant time;
/// tamper does NOT surface as a discriminant. See the
/// decapsulate-implicit-rejection paragraph in security-policy §4.9.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error
/// variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ss_out` must be a
/// non-NULL writable pointer to ≥32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_512_decapsulate(
    dk_ptr: *const u8,
    ct_ptr: *const u8,
    ss_out: *mut u8,
) -> c_int {
    let dk = match unsafe { slice_from_raw(dk_ptr, 1632) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct = match unsafe { slice_from_raw(ct_ptr, 768) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ss_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(dk_arr) = <&[u8; 1632]>::try_from(dk) else {
        return R::Internal as c_int;
    };
    let Ok(ct_arr) = <&[u8; 768]>::try_from(ct) else {
        return R::Internal as c_int;
    };
    let ss = match oxicrypt_ml_kem::ml_kem_512::decapsulate(dk_arr, ct_arr) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32) };
    R::Ok as c_int
}

// ── ML-KEM-768 (FIPS 203) — stateless surface ────────────────────
//
// Per-variant additive expansion of the ML-KEM-1024 surface above.
// Same three-entry-point shape (keygen, encapsulate, decapsulate),
// same caller-seeded `(d, z)` + `m` randomness contracts, same
// implicit-rejection semantics on decapsulate — only the byte
// counts differ per FIPS 203 Table 2 (k=3 parameter set): ek = 1184
// bytes, dk = 2400 bytes, ct = 1088 bytes. The 32-byte seeds and
// the 32-byte shared secret are parameter-set-invariant per
// FIPS 203 §6.1–§6.3.
//
// CNSA gating: ML-KEM-768 is **not** part of CNSA 2.0 (which
// mandates ML-KEM-1024) and is **not** in the CNSA 1.0 transition
// allow-list either. The underlying `Service::MlKem768Keygen /
// Encaps / Decaps` variants are permitted only under
// `AlgorithmProfile::Unrestricted`; calls under either CNSA profile
// return `OxiResult::AlgorithmRestricted = 6` via the existing
// `require_allowed` gate in `oxicrypt_module`.

/// Generate an ML-KEM-768 key pair from two 32-byte caller-supplied
/// seeds (FIPS 203 §6.1 ML-KEM.KeyGen, k=3 parameter set).
///
/// Reads exactly 32 bytes from `d_ptr` (K-PKE keygen randomness) and
/// exactly 32 bytes from `z_ptr` (implicit-rejection seed). Writes
/// the 1184-byte encapsulation key into `ek_out` and the 2400-byte
/// decapsulation key into `dk_out`. Both seeds are caller-supplied;
/// the caller MUST source each independently from an approved DRBG
/// (SP 800-90A). `d` and `z` are NOT interchangeable — see the
/// ML-KEM-1024 section comment above for the semantic distinction
/// (identical across all three parameter sets).
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if a
/// rare K-PKE NTT decode failure occurs during keygen, or a module
/// error variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ek_out` and `dk_out`
/// must each be non-NULL writable pointers to ≥1184 and ≥2400 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_768_keygen(
    d_ptr: *const u8,
    z_ptr: *const u8,
    ek_out: *mut u8,
    dk_out: *mut u8,
) -> c_int {
    let d = match unsafe { slice_from_raw(d_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let z = match unsafe { slice_from_raw(z_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ek_out.is_null() || dk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(d_arr) = <&[u8; 32]>::try_from(d) else {
        return R::Internal as c_int;
    };
    let Ok(z_arr) = <&[u8; 32]>::try_from(z) else {
        return R::Internal as c_int;
    };
    let (ek, dk) = match oxicrypt_ml_kem::ml_kem_768::keygen(d_arr, z_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ek.as_ptr(), ek_out, 1184) };
    unsafe { core::ptr::copy_nonoverlapping(dk.as_ptr(), dk_out, 2400) };
    R::Ok as c_int
}

/// Encapsulate a shared secret against an ML-KEM-768 encapsulation
/// key (FIPS 203 §6.2 ML-KEM.Encaps, k=3 parameter set).
///
/// Reads exactly 1184 bytes from `ek_ptr` and exactly 32 bytes from
/// `m_ptr` (encapsulation randomness, caller-supplied from an
/// SP 800-90A DRBG). Writes the 32-byte shared secret into `ss_out`
/// and the 1088-byte ciphertext into `ct_out`.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ss_out` and `ct_out`
/// must each be non-NULL writable pointers to ≥32 and ≥1088 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_768_encapsulate(
    ek_ptr: *const u8,
    m_ptr: *const u8,
    ss_out: *mut u8,
    ct_out: *mut u8,
) -> c_int {
    let ek = match unsafe { slice_from_raw(ek_ptr, 1184) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let m = match unsafe { slice_from_raw(m_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ss_out.is_null() || ct_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(ek_arr) = <&[u8; 1184]>::try_from(ek) else {
        return R::Internal as c_int;
    };
    let Ok(m_arr) = <&[u8; 32]>::try_from(m) else {
        return R::Internal as c_int;
    };
    let (ss, ct) = match oxicrypt_ml_kem::ml_kem_768::encapsulate(ek_arr, m_arr) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, 1088) };
    R::Ok as c_int
}

/// Decapsulate a shared secret from an ML-KEM-768 ciphertext
/// (FIPS 203 §6.3 ML-KEM.Decaps, k=3 parameter set).
///
/// Reads exactly 2400 bytes from `dk_ptr` and exactly 1088 bytes
/// from `ct_ptr`. Writes the 32-byte shared secret into `ss_out`.
/// **Fully deterministic** — no caller randomness, no `Ok(false)`
/// shape, no `TagMismatch = 22` mapping. The FO transform's
/// implicit-rejection branch absorbs tampered ciphertext into a
/// deterministic-but-pseudorandom shared secret in constant time;
/// tamper does NOT surface as a discriminant. See the
/// decapsulate-implicit-rejection paragraph in security-policy §4.9.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error
/// variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `ss_out` must be a
/// non-NULL writable pointer to ≥32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_768_decapsulate(
    dk_ptr: *const u8,
    ct_ptr: *const u8,
    ss_out: *mut u8,
) -> c_int {
    let dk = match unsafe { slice_from_raw(dk_ptr, 2400) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct = match unsafe { slice_from_raw(ct_ptr, 1088) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if ss_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(dk_arr) = <&[u8; 2400]>::try_from(dk) else {
        return R::Internal as c_int;
    };
    let Ok(ct_arr) = <&[u8; 1088]>::try_from(ct) else {
        return R::Internal as c_int;
    };
    let ss = match oxicrypt_ml_kem::ml_kem_768::decapsulate(dk_arr, ct_arr) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32) };
    R::Ok as c_int
}

// ── SLH-DSA-SHA2-256s (FIPS 205) — stateless surface ─────────────
//
// Three pure entry points: keygen, sign, verify. SLH-DSA is the
// third NIST-standardized post-quantum signature scheme — pure
// hash-based, stateless, with security resting on the collision /
// preimage resistance of SHA-2 alone. The SHA2-256s parameter set
// ("small signatures") is the slow-sign / fast-verify, smallest-key
// profile per FIPS 205 §10.1.
//
// All three operations are exposed at a stateless byte-array surface
// with NO DRBG plumbing at the FFI boundary:
//
//   - keygen(xi) → (pk, sk)  per FIPS 205 §9.1 Algorithm 17.
//     `xi` is 96 bytes (3 × 32) of caller-supplied randomness,
//     internally split as `SK.seed ‖ SK.prf ‖ PK.seed`. The three
//     32-byte components are NOT interchangeable: SK.seed drives
//     WOTS+ / FORS secret derivation, SK.prf is the PRF key for
//     deterministic message-randomness in sign, and PK.seed is the
//     domain-separation tweak baked into every hash call. Mixing
//     them would put PRF key material into the secret-derivation
//     slot or vice-versa, breaking the FIPS 205 §10.2 security
//     argument. Caller is responsible for sourcing each independently
//     from an SP 800-90A DRBG.
//   - sign(sk, msg, ctx) → sig  per FIPS 205 §9.2 Algorithm 22
//     (external `slh_sign`). Signing is **deterministic** in this
//     crate (opt_rand = PK.seed): bit-identical signature for the
//     same `(sk, msg, ctx)` triple. Pass `ctx_len = 0` (with any
//     `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.
//   - verify(pk, msg, ctx, sig)  per FIPS 205 §9.3 Algorithm 24
//     (external `slh_verify`). Upstream returns `Result<(), Error>`
//     where `Err(InvalidInput)` collapses decode-fail and
//     verify-fail into a single discriminant. The FFI maps that to
//     `OxiResult::TagMismatch = 22` per the cross-family
//     verify-mismatch convention established by RSA verify
//     (PR #17) and ML-DSA verify (PR #18). Third PQ family with
//     this mapping; the `Result<()>` upstream shape is the load-
//     bearing structural property here.
//
// Byte layout (FIPS 205 §10.1, SHA2-256s parameter set):
//   xi  = 96 bytes (3 × 32: SK.seed ‖ SK.prf ‖ PK.seed)
//   pk  = 64 bytes
//   sk  = 128 bytes
//   sig = 29 792 bytes (fixed — no length-out pointer)
//   ctx ≤ 255 bytes (FIPS 205 §9.2 limit)
//
// Per-variant naming: this is `slh_dsa_sha2_256s` (not
// `slh_dsa(param_set: int)` and not `slh_dsa_256s` collapsing the
// hash family) per stabilized arc pattern #8. The other 11 FIPS 205
// §11 parameter sets — SHA2-{128s,128f,192s,192f,256f} and
// SHAKE-{128s,128f,192s,192f,256s,256f} — are exposed as additive
// per-variant fns below; existing C callers do not recompile when
// new variants ship. Each fn forwards to its variant-specific
// `oxicrypt_slh_dsa::slh_dsa_<family>_<level><sf>::{keygen,sign,
// verify}` submodule (Batch 3 expansion); the crate-root re-export
// of `oxicrypt_slh_dsa::keygen` continues to resolve to SHA2-256s
// for backwards-compat with non-FFI callers.

/// Generate an SLH-DSA-SHA2-256s key pair from a 96-byte
/// caller-supplied seed (FIPS 205 §9.1 Algorithm 17).
///
/// Reads exactly 96 bytes from `xi_ptr`, internally framed as
/// `SK.seed ‖ SK.prf ‖ PK.seed`. Writes the 64-byte public key
/// into `pk_out` and the 128-byte secret key into `sk_out`. The
/// caller MUST source the 96 bytes from an approved DRBG
/// (SP 800-90A); the FFI performs no entropy generation. The three
/// 32-byte components are NOT interchangeable — see the section
/// comment above for the semantic distinction.
///
/// Returns `OxiResult::Ok = 0` on success, or a module error
/// variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `pk_out` and `sk_out`
/// must each be non-NULL writable pointers to ≥64 and ≥128 bytes
/// respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_256s_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_sha2_256s::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 64) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 128) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHA2-256s (FIPS 205 §9.2
/// Algorithm 22, external `slh_sign`).
///
/// Reads exactly 128 bytes from `sk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
/// 29 792-byte signature into `sig_out`. Pass `ctx_len = 0` (with
/// any `ctx_ptr`) for the empty context used by X.509 / CMS /
/// LAMPS.
///
/// Signing is **deterministic** (opt_rand = PK.seed): bit-identical
/// signature across calls for the same `(sk, msg, ctx)` triple.
/// NO randomized-mode variant is exposed.
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
/// `ctx_len > 255` (FIPS 205 §9.2 limit), or a module error
/// variant (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must be a
/// non-NULL writable pointer to ≥29 792 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_256s_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 128) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_sha2_256s::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 29_792) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHA2-256s signature (FIPS 205 §9.3
/// Algorithm 24, external `slh_verify`).
///
/// Reads exactly 64 bytes from `pk_ptr`, `msg_len` bytes from
/// `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 29 792 bytes
/// from `sig_ptr`. Pass `ctx_len = 0` for the empty context used
/// by X.509 / CMS / LAMPS.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (decode-fail OR signature-invalid — upstream collapses these
/// into a single `Err(InvalidInput)`; same shape as RSA verify and
/// ML-DSA verify), or a module error variant (`NotOperational`,
/// `AlgorithmRestricted`).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_256s_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 29_792) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_sha2_256s::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── SLH-DSA — SHA-2 family, 5 additional variants ───────────────
//
// Per-variant additive expansion of the SHA2-256s surface above.
// Same three-entry-point shape (keygen, sign, verify), same
// deterministic-signing semantics, same `Err(InvalidInput)` →
// `TagMismatch = 22` collapse on verify — only the byte counts
// differ per FIPS 205 §11 Table 2:
//
//   n=16 (128-bit category): xi=48, pk=32, sk=64, sig-s=7 856,
//                            sig-f=17 088
//   n=24 (192-bit category): xi=72, pk=48, sk=96, sig-s=16 224,
//                            sig-f=35 664
//   n=32 (256-bit category): xi=96, pk=64, sk=128, sig-s=29 792,
//                            sig-f=49 856
//
// xi continues to frame as `SK.seed ‖ SK.prf ‖ PK.seed` (three
// `n`-byte components, role-segregated and NOT interchangeable —
// SK.seed drives WOTS+/FORS secret derivation, SK.prf is the PRF
// key for deterministic message randomness, PK.seed is the
// domain-separation tweak baked into every hash call; mixing them
// would put PRF key material into the secret-derivation slot or
// vice-versa, breaking the FIPS 205 §10 security argument).
//
// CNSA gating: CNSSP-15 lists no SLH-DSA parameter set, so all 12
// variants — every entry in this block plus the SHAKE block
// below — are permitted only under
// `AlgorithmProfile::Unrestricted`; calls under either CNSA
// profile return `OxiResult::AlgorithmRestricted = 6` via the
// existing `require_allowed` gate in `oxicrypt_module` against
// the per-parameter-set `Service::SlhDsa<Family><Level><SF><Op>`
// discriminants (320-355, contiguous block; Batch 4).

/// Generate an SLH-DSA-SHA2-128s key pair from a 48-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=16; xi=48, pk=32, sk=64).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_128s_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_sha2_128s::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 64) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHA2-128s (FIPS 205 §9.2 Algorithm
/// 22). Deterministic. Reads 64-byte sk, writes 7 856-byte
/// signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_128s_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_sha2_128s::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 7_856) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHA2-128s signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 32-byte pk + 7 856-byte sig. `Err(InvalidInput) →
/// TagMismatch = 22` collapse.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_128s_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 7_856) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_sha2_128s::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHA2-128f key pair from a 48-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=16, fast variant; xi=48, pk=32,
/// sk=64).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_128f_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_sha2_128f::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 64) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHA2-128f (FIPS 205 §9.2 Algorithm
/// 22). Deterministic. Reads 64-byte sk, writes 17 088-byte
/// signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_128f_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_sha2_128f::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 17_088) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHA2-128f signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 32-byte pk + 17 088-byte sig. `Err(InvalidInput) →
/// TagMismatch = 22` collapse.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_128f_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 17_088) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_sha2_128f::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHA2-192s key pair from a 72-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=24).
///
/// Reads 72 bytes from `xi_ptr` (`SK.seed ‖ SK.prf ‖ PK.seed`,
/// 3 × 24 bytes). Writes the 48-byte pk into `pk_out` and the
/// 96-byte sk into `sk_out`.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_192s_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 72) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_sha2_192s::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 48) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 96) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHA2-192s (FIPS 205 §9.2 Algorithm
/// 22). Reads 96-byte sk, writes 16 224-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must point to
/// ≥16 224 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_192s_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_sha2_192s::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 16_224) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHA2-192s signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 48-byte pk, 16 224-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_192s_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 16_224) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_sha2_192s::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHA2-192f key pair from a 72-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=24, fast variant).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_192f_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 72) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_sha2_192f::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 48) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 96) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHA2-192f (FIPS 205 §9.2 Algorithm
/// 22). Reads 96-byte sk, writes 35 664-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must point to
/// ≥35 664 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_192f_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_sha2_192f::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 35_664) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHA2-192f signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 48-byte pk, 35 664-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_192f_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 35_664) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_sha2_192f::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHA2-256f key pair from a 96-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=32, fast variant).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_256f_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_sha2_256f::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 64) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 128) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHA2-256f (FIPS 205 §9.2 Algorithm
/// 22). Reads 128-byte sk, writes 49 856-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `sig_out` must point to
/// ≥49 856 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_256f_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 128) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_sha2_256f::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 49_856) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHA2-256f signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 64-byte pk, 49 856-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_sha2_256f_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 49_856) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_sha2_256f::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── SLH-DSA — SHAKE family, all 6 variants ──────────────────────
//
// FIPS 205 §10.2 SHAKE family. Parameter (n, h, d, a, k, w) tuples
// match the SHA-2 family per FIPS 205 §11 Table 2 — so byte counts
// (xi / pk / sk / sig) are identical across SHA-2 and SHAKE at the
// same level + s/f. The functions below mirror their SHA-2
// counterparts byte-for-byte at the FFI boundary; the only
// difference is internal: SHAKE-256 (one-shot XOF) replaces every
// SHA-256 / SHA-512 tweakable-hash call, PRF_msg is plain
// concatenation (SHAKE provides native domain separation, no HMAC
// needed), and H_msg is a single-shot squeeze (no MGF1 loop). All
// 6 SHAKE variants share `AlgorithmProfile::Unrestricted` gating —
// CNSSP-15 lists no SLH-DSA parameter set at all.

/// Generate an SLH-DSA-SHAKE-128s key pair from a 48-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=16).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_128s_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_shake_128s::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 64) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHAKE-128s (FIPS 205 §9.2 Algorithm
/// 22). Reads 64-byte sk, writes 7 856-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_128s_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_shake_128s::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 7_856) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHAKE-128s signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 32-byte pk, 7 856-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_128s_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 7_856) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_shake_128s::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHAKE-128f key pair from a 48-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=16, fast variant).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_128f_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_shake_128f::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 32) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 64) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHAKE-128f (FIPS 205 §9.2 Algorithm
/// 22). Reads 64-byte sk, writes 17 088-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_128f_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_shake_128f::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 17_088) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHAKE-128f signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 32-byte pk, 17 088-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_128f_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 17_088) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_shake_128f::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHAKE-192s key pair from a 72-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=24).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_192s_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 72) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_shake_192s::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 48) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 96) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHAKE-192s (FIPS 205 §9.2 Algorithm
/// 22). Reads 96-byte sk, writes 16 224-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_192s_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_shake_192s::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 16_224) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHAKE-192s signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 48-byte pk, 16 224-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_192s_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 16_224) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_shake_192s::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHAKE-192f key pair from a 72-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=24, fast variant).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_192f_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 72) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_shake_192f::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 48) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 96) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHAKE-192f (FIPS 205 §9.2 Algorithm
/// 22). Reads 96-byte sk, writes 35 664-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_192f_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_shake_192f::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 35_664) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHAKE-192f signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 48-byte pk, 35 664-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_192f_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 48) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 35_664) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_shake_192f::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHAKE-256s key pair from a 96-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=32).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_256s_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_shake_256s::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 64) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 128) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHAKE-256s (FIPS 205 §9.2 Algorithm
/// 22). Reads 128-byte sk, writes 29 792-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_256s_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 128) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_shake_256s::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 29_792) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHAKE-256s signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 64-byte pk, 29 792-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_256s_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 29_792) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_shake_256s::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an SLH-DSA-SHAKE-256f key pair from a 96-byte seed
/// (FIPS 205 §9.1 Algorithm 17; n=32, fast variant).
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_256f_keygen(
    xi_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    let xi = match unsafe { slice_from_raw(xi_ptr, 96) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if pk_out.is_null() || sk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let (pk, sk) = match oxicrypt_slh_dsa::slh_dsa_shake_256f::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, 64) };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, 128) };
    R::Ok as c_int
}

/// Sign a message with SLH-DSA-SHAKE-256f (FIPS 205 §9.2 Algorithm
/// 22). Reads 128-byte sk, writes 49 856-byte signature.
/// Deterministic.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_256f_sign(
    sk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let sk = match unsafe { slice_from_raw(sk_ptr, 128) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let sig = match oxicrypt_slh_dsa::slh_dsa_shake_256f::sign(sk, msg, ctx) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 49_856) };
    R::Ok as c_int
}

/// Verify an SLH-DSA-SHAKE-256f signature (FIPS 205 §9.3 Algorithm
/// 24). Reads 64-byte pk, 49 856-byte signature.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_slh_dsa_shake_256f_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, 64) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = match unsafe { slice_from_raw(ctx_ptr, ctx_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, 49_856) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_slh_dsa::slh_dsa_shake_256f::verify(pk, msg, ctx, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── LMS / XMSS — SP 800-208 stateful hash-based signatures ──────
//
// LMS (Leighton-Micali, RFC 8554) and XMSS (RFC 8391) are stateful
// hash-based signature schemes approved by SP 800-208 for FIPS use,
// and named in CNSA 2.0 for firmware signing. Both are wired to the
// same parameter set per upstream:
//
//   LMS  — LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4 (1024 sigs/key)
//   XMSS — XMSS-SHA2_10_256, OID 0x00000001        (1024 sigs/key)
//
// Stateful means each leaf of the Merkle tree may sign exactly one
// message; reusing a leaf is a catastrophic break of the scheme. The
// caller is the SOLE custodian of the private-key state, and MUST
// persist the updated `sk_out` after every sign before using the
// signature. This C ABI surface encodes that obligation in its
// signature shape: every sign call takes both an `sk_in` (pre-state)
// and writes an `sk_out` (post-state, leaf index advanced by one).
// There is no opaque handle, by design, so a caller cannot escape
// the persistence contract by holding a long-lived in-memory state
// and forgetting to write it down. See the FFI design note in the
// PR body and `docs/security-policy/security-policy.md` §4 for the
// rationale.
//
// Mapping of upstream `Result` shapes to `OxiResult`:
//
//   keygen → Result<(SK, [u8; PK_LEN]), Error>
//     Ok                   → OxiResult::Ok = 0
//     Err(NotOperational)  → OxiResult::NotOperational = 1
//     Err(AlgorithmRestricted) → OxiResult::AlgorithmRestricted = 6
//
//   sign → Result<[u8; SIG_LEN], Error>
//     Ok                   → OxiResult::Ok = 0; sk_out written
//     Err(InvalidInput)    → OxiResult::InvalidInput = 5 (key
//                            exhausted: leaf_index ≥ MAX_SIGNATURES)
//     Err(NotOperational | AlgorithmRestricted) → as above
//
//   verify → Result<(), Error>
//     Ok                   → OxiResult::Ok = 0
//     Err(InvalidInput)    → OxiResult::TagMismatch = 22
//                            (verify-fail collapses parse, structural,
//                            and cryptographic mismatch into a single
//                            discriminant — same upstream shape as
//                            RSA verify, ML-DSA verify, SLH-DSA
//                            verify; verify-mismatch convention
//                            stabilized as arc pattern #7)
//
// Byte layouts:
//
//   LMS  pk = 56 bytes   (lms_type(4) || ots_type(4) || I(16) || root(32))
//   LMS  sk = 52 bytes   (seed(32) || I(16) || leaf_index(4)) — opaque,
//        treat as a binary blob; produced by upstream `to_bytes()`
//   LMS  sig = 2508 bytes (q(4) || ots_sig(2180) || lms_type(4)
//        || auth_path(10×32))
//
//   XMSS pk = 68 bytes   (OID(4) || root(32) || PUB_SEED(32))
//   XMSS sk = 132 bytes  (sk_seed(32) || sk_prf(32) || pub_seed(32)
//        || root(32) || idx(4)) — opaque, treat as a binary blob
//   XMSS sig = 2500 bytes (idx(4) || r(32) || wots_sig(67×32)
//        || auth_path(10×32))
//
// Per-variant naming: this is `lms` / `xmss` (not `lms_sha256_m32_h10`
// or `xmss_sha2_10_256`) because each upstream crate currently exposes
// exactly one parameter set. Future parameter sets, if added upstream,
// will land as new functions under qualified names per stabilized arc
// pattern #8 (per-variant naming, no enum dispatch). Existing C
// callers do not recompile when new variants ship.

/// Length of an LMS public key in bytes (56).
pub const OXI_LMS_PUBLIC_KEY_LEN: usize = 56;

/// Length of an LMS opaque private-key blob in bytes (52).
///
/// This matches the upstream `LmsPrivateKey::to_bytes()` /
/// `from_bytes()` round-trip layout: `seed(32) || I(16) ||
/// leaf_index(4)`. Treat the blob as opaque; the C ABI never
/// reaches inside it.
pub const OXI_LMS_PRIVATE_KEY_LEN: usize = 52;

/// Length of an LMS signature in bytes (2508).
pub const OXI_LMS_SIGNATURE_LEN: usize = 2508;

/// Length of an XMSS public key in bytes (68).
pub const OXI_XMSS_PUBLIC_KEY_LEN: usize = 68;

/// Length of an XMSS opaque private-key blob in bytes (132).
///
/// Matches upstream `XmssPrivateKey::to_bytes()` / `from_bytes()`
/// layout: `sk_seed(32) || sk_prf(32) || pub_seed(32) || root(32)
/// || idx(4)`. Treat as opaque.
pub const OXI_XMSS_PRIVATE_KEY_LEN: usize = 132;

/// Length of an XMSS signature in bytes (2500).
pub const OXI_XMSS_SIGNATURE_LEN: usize = 2500;

/// Generate an LMS key pair from a 32-byte caller-supplied seed.
///
/// Reads exactly 32 bytes from `xi_ptr`, deterministically derives
/// the tree seed and 16-byte identifier `I` via SHA-256, and writes
/// the 52-byte opaque private-key blob into `sk_out` and the
/// 56-byte public key into `pk_out`. The caller MUST source the 32
/// seed bytes from an approved DRBG (SP 800-90A); the FFI performs
/// no entropy generation.
///
/// `sk_out` is the persistence-of-record format. Treat it as an
/// opaque blob and pass it back unchanged to [`oxi_lms_sign`].
///
/// Returns `OxiResult::Ok = 0` on success or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a non-NULL
/// writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    // Unreachable: slice_from_raw verified length == 32.
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h10_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe { core::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk_out, OXI_LMS_PRIVATE_KEY_LEN) };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, OXI_LMS_PUBLIC_KEY_LEN) };
    R::Ok as c_int
}

/// Sign a message with an LMS private key.
///
/// Reads the 52-byte opaque private-key blob from `sk_in_ptr`,
/// `msg_len` bytes from `msg_ptr`, signs the message, advances the
/// internal leaf index by one, writes the **updated** 52-byte blob
/// into `sk_out`, and writes the 2508-byte signature into `sig_out`.
///
/// **Persistence contract:** the caller MUST persist `sk_out` (the
/// post-state) before using `sig_out`. Failure to persist before a
/// crash, followed by a restart that re-signs from the pre-state,
/// reuses the same one-time key — a catastrophic break of LMS.
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if the
/// key is exhausted (1024 signatures already issued), or a module
/// error variant.
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr` must be valid
/// for `msg_len` bytes (NULL with len=0 is permitted). `sk_out`
/// must be a non-NULL writable pointer to ≥52 bytes. `sig_out`
/// must be a non-NULL writable pointer to ≥2508 bytes. `sk_in_ptr`
/// and `sk_out` may alias (in-place advance is supported).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe { slice_from_raw(sk_in_ptr, OXI_LMS_PRIVATE_KEY_LEN) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    // Unreachable: slice_from_raw verified length == 52.
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h10_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h10_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe { core::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk_out, OXI_LMS_PRIVATE_KEY_LEN) };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, OXI_LMS_SIGNATURE_LEN) };
    R::Ok as c_int
}

/// Verify an LMS signature.
///
/// Reads the 56-byte public key from `pk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and the 2508-byte signature from `sig_ptr`.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (parse, structural mismatch, or cryptographic mismatch — upstream
/// collapses these into a single `Err(InvalidInput)`; same shape
/// as RSA verify, ML-DSA verify, SLH-DSA verify), or a module error
/// variant.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must be valid for
/// `msg_len` bytes (NULL with len=0 is permitted). `sig_ptr` must
/// be valid for 2508 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe { slice_from_raw(pk_ptr, OXI_LMS_PUBLIC_KEY_LEN) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe { slice_from_raw(sig_ptr, OXI_LMS_SIGNATURE_LEN) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    // Unreachable: slice_from_raw verified each input's length.
    let Ok(pk) = <&[u8; OXI_LMS_PUBLIC_KEY_LEN]>::try_from(pk_slice) else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; OXI_LMS_SIGNATURE_LEN]>::try_from(sig_slice) else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h10_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── SHA-256 / M=32 family (RFC 8554 §A.1+§A.2) — 20 pairs × 3 ops = 60 fns ──

/// Generate an LMS key pair for SHA-256 M=32 H=5 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h5_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=5 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 8684-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥8684 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h5_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h5_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h5_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h5_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8684-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 8684 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h5_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h5_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h5_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=5 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h5_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=5 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4460-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4460 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h5_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h5_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h5_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h5_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4460-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4460 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h5_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h5_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h5_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=5 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h5_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=5 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2348-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2348 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h5_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h5_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h5_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h5_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2348-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2348 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h5_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h5_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h5_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=5 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h5_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=5 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1292-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1292 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h5_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h5_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h5_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h5_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1292-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1292 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h5_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h5_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h5_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h5_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h5_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=10 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h10_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=10 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 8844-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥8844 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h10_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h10_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h10_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h10_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8844-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 8844 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h10_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h10_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h10_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=10 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h10_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=10 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4620-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4620 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h10_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h10_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h10_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h10_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4620-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4620 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h10_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h10_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h10_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=10 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h10_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=10 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2508-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2508 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h10_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h10_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h10_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h10_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2508-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2508 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h10_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h10_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h10_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=10 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h10_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=10 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1452-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1452 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h10_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h10_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h10_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h10_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1452-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1452 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h10_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h10_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h10_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h10_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h10_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=15 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h15_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=15 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 9004-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥9004 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h15_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h15_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h15_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h15_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9004-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 9004 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h15_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h15_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h15_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=15 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h15_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=15 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4780-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4780 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h15_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h15_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h15_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h15_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4780-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4780 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h15_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h15_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h15_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=15 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h15_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=15 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2668-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2668 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h15_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h15_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h15_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h15_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2668-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2668 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h15_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h15_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h15_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=15 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h15_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=15 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1612-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1612 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h15_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h15_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h15_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h15_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1612-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1612 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h15_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h15_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h15_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h15_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h15_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=20 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h20_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=20 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 9164-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥9164 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h20_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h20_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h20_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h20_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9164-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 9164 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h20_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h20_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h20_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=20 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h20_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=20 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4940-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4940 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h20_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h20_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h20_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h20_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4940-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4940 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h20_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h20_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h20_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=20 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h20_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=20 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2828-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2828 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h20_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h20_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h20_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h20_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2828-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2828 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h20_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h20_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h20_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=20 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h20_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=20 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1772-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1772 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h20_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h20_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h20_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h20_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1772-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1772 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h20_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h20_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h20_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h20_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h20_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=25 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h25_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=25 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 9324-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥9324 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h25_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h25_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h25_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h25_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9324-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 9324 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h25_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h25_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h25_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=25 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h25_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=25 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5100-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥5100 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h25_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h25_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h25_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h25_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 5100-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5100 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h25_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h25_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h25_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=25 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h25_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=25 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2988-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2988 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h25_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h25_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h25_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h25_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2988-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2988 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h25_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h25_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h25_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=32 H=25 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m32_h25_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=32 H=25 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1932-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1932 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m32_h25_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m32_h25_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m32_h25_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m32_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m32_h25_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1932-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1932 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m32_h25_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m32_h25_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m32_h25_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m32_h25_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m32_h25_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── SHA-256 / M=24 family (RFC 8708 §4.1) — 20 pairs × 3 ops = 60 fns ──

/// Generate an LMS key pair for SHA-256 M=24 H=5 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h5_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=5 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4956-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥4956 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h5_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h5_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h5_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h5_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 4956-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4956 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h5_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h5_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h5_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=5 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h5_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=5 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2580-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2580 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h5_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h5_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h5_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h5_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2580-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2580 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h5_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h5_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h5_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=5 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h5_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=5 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1380-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1380 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h5_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h5_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h5_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h5_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1380-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1380 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h5_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h5_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h5_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=5 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h5_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=5 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 780-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥780 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h5_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h5_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h5_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h5_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 780-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 780 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h5_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h5_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h5_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h5_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h5_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=10 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h10_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=10 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5076-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5076 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h10_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h10_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h10_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h10_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5076-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5076 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h10_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h10_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h10_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=10 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h10_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=10 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2700-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2700 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h10_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h10_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h10_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h10_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2700-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2700 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h10_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h10_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h10_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=10 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h10_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=10 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1500-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1500 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h10_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h10_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h10_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h10_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1500-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1500 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h10_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h10_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h10_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=10 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h10_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=10 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 900-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥900 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h10_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h10_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h10_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h10_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 900-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 900 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h10_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h10_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h10_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h10_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h10_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=15 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h15_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=15 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5196-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5196 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h15_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h15_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h15_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h15_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5196-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5196 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h15_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h15_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h15_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=15 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h15_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=15 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2820-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2820 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h15_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h15_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h15_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h15_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2820-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2820 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h15_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h15_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h15_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=15 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h15_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=15 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1620-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1620 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h15_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h15_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h15_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h15_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1620-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1620 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h15_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h15_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h15_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=15 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h15_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=15 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1020-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1020 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h15_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h15_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h15_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h15_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1020-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1020 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h15_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h15_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h15_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h15_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h15_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=20 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h20_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=20 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5316-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5316 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h20_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h20_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h20_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h20_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5316-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5316 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h20_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h20_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h20_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=20 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h20_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=20 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2940-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2940 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h20_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h20_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h20_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h20_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2940-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2940 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h20_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h20_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h20_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=20 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h20_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=20 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1740-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1740 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h20_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h20_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h20_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h20_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1740-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1740 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h20_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h20_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h20_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=20 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h20_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=20 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1140-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1140 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h20_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h20_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h20_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h20_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1140-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1140 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h20_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h20_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h20_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h20_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h20_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=25 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h25_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=25 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5436-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5436 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h25_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h25_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h25_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h25_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5436-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5436 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h25_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h25_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h25_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=25 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h25_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=25 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 3060-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥3060 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h25_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h25_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h25_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h25_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 3060-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 3060 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h25_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h25_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h25_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=25 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h25_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=25 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1860-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1860 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h25_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h25_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h25_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h25_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1860-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1860 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h25_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h25_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h25_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHA-256 M=24 H=25 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_sha256_m24_h25_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHA-256 M=24 H=25 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1260-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1260 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_sha256_m24_h25_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_sha256_m24_h25_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_sha256_m24_h25_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_sha256_m24_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_sha256_m24_h25_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1260-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1260 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_sha256_m24_h25_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_sha256_m24_h25_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_sha256_m24_h25_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_sha256_m24_h25_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_sha256_m24_h25_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── SHAKE-256 / M=32 family (RFC 8708 §3.1) — 20 pairs × 3 ops = 60 fns ──

/// Generate an LMS key pair for SHAKE-256 M=32 H=5 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h5_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h5_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=5 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 8684-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥8684 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h5_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h5_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h5_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h5_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8684-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 8684 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h5_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h5_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h5_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=5 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h5_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h5_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=5 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4460-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4460 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h5_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h5_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h5_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h5_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4460-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4460 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h5_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h5_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h5_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=5 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h5_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h5_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=5 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2348-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2348 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h5_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h5_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h5_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h5_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2348-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2348 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h5_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h5_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h5_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=5 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h5_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h5_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=5 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1292-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1292 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h5_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h5_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h5_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h5_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1292-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1292 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h5_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h5_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h5_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h5_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h5_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=10 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h10_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h10_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=10 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 8844-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥8844 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h10_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h10_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h10_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h10_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8844-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 8844 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h10_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h10_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h10_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=10 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h10_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h10_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=10 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4620-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4620 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h10_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h10_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h10_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h10_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4620-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4620 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h10_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h10_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h10_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=10 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h10_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h10_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=10 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2508-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2508 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h10_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h10_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h10_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h10_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2508-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2508 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h10_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h10_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h10_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=10 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h10_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h10_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=10 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1452-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1452 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h10_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h10_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h10_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h10_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1452-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1452 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h10_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h10_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h10_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h10_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h10_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=15 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h15_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h15_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=15 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 9004-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥9004 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h15_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h15_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h15_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h15_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9004-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 9004 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h15_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h15_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h15_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=15 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h15_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h15_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=15 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4780-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4780 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h15_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h15_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h15_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h15_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4780-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4780 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h15_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h15_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h15_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=15 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h15_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h15_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=15 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2668-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2668 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h15_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h15_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h15_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h15_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2668-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2668 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h15_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h15_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h15_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=15 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h15_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h15_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=15 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1612-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1612 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h15_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h15_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h15_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h15_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1612-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1612 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h15_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h15_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h15_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h15_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h15_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=20 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h20_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h20_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=20 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 9164-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥9164 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h20_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h20_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h20_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h20_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9164-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 9164 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h20_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h20_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h20_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=20 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h20_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h20_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=20 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4940-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥4940 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h20_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h20_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h20_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h20_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4940-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4940 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h20_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h20_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h20_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=20 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h20_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h20_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=20 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2828-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2828 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h20_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h20_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h20_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h20_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2828-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2828 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h20_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h20_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h20_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=20 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h20_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h20_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=20 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1772-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1772 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h20_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h20_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h20_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h20_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1772-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1772 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h20_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h20_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h20_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h20_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h20_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=25 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h25_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h25_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=25 W=1 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 9324-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥9324 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h25_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h25_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h25_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h25_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9324-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 9324 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h25_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h25_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h25_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=25 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h25_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h25_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=25 W=2 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5100-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥5100 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h25_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h25_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h25_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h25_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 5100-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5100 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h25_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h25_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h25_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=25 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h25_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h25_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=25 W=4 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2988-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥2988 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h25_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h25_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h25_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h25_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2988-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2988 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h25_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h25_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h25_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=32 H=25 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
/// private-key blob into `sk_out` and a 56-byte public key
/// into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥52 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥56 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m32_h25_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m32_h25_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=32 H=25 W=8 variant.
///
/// Reads the 52-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1932-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥52 bytes, `sig_out` ≥1932 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m32_h25_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m32_h25_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m32_h25_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m32_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m32_h25_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1932-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.
///
/// # Safety
///
/// `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1932 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m32_h25_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m32_h25_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m32_h25_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m32_h25_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m32_h25_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── SHAKE-256 / M=24 family (RFC 8708 §4.2) — 20 pairs × 3 ops = 60 fns ──

/// Generate an LMS key pair for SHAKE-256 M=24 H=5 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h5_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h5_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=5 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 4956-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥4956 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h5_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h5_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h5_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h5_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 4956-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 4956 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h5_w1::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h5_w1::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h5_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=5 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h5_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h5_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=5 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2580-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2580 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h5_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h5_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h5_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h5_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2580-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2580 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h5_w2::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h5_w2::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h5_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=5 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h5_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h5_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=5 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1380-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1380 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h5_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h5_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h5_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h5_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1380-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1380 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h5_w4::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h5_w4::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h5_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=5 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h5_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h5_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=5 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 780-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥780 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h5_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h5_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h5_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h5_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h5_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 780-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 780 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h5_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe {
        slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h5_w8::PUBLIC_KEY_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe {
        slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h5_w8::SIGNATURE_LEN)
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h5_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h5_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=10 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h10_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h10_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=10 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5076-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5076 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h10_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h10_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h10_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h10_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5076-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5076 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h10_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h10_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h10_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=10 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h10_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h10_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=10 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2700-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2700 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h10_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h10_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h10_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h10_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2700-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2700 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h10_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h10_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h10_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=10 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h10_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h10_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=10 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1500-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1500 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h10_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h10_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h10_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h10_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1500-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1500 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h10_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h10_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h10_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=10 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h10_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h10_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=10 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 900-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥900 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h10_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h10_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h10_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h10_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h10_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 900-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 900 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h10_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h10_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h10_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h10_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h10_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=15 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h15_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h15_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=15 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5196-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5196 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h15_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h15_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h15_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h15_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5196-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5196 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h15_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h15_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h15_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=15 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h15_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h15_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=15 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2820-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2820 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h15_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h15_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h15_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h15_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2820-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2820 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h15_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h15_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h15_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=15 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h15_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h15_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=15 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1620-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1620 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h15_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h15_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h15_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h15_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1620-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1620 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h15_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h15_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h15_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=15 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h15_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h15_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=15 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1020-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1020 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h15_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h15_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h15_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h15_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h15_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1020-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1020 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h15_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h15_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h15_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h15_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h15_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=20 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h20_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h20_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=20 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5316-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5316 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h20_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h20_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h20_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h20_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5316-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5316 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h20_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h20_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h20_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=20 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h20_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h20_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=20 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 2940-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥2940 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h20_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h20_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h20_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h20_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2940-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 2940 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h20_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h20_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h20_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=20 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h20_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h20_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=20 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1740-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1740 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h20_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h20_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h20_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h20_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1740-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1740 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h20_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h20_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h20_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=20 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h20_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h20_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=20 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1140-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1140 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h20_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h20_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h20_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h20_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h20_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1140-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1140 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h20_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h20_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h20_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h20_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h20_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=25 W=1.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w1_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h25_w1::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h25_w1::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=25 W=1 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 5436-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥5436 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w1_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h25_w1::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h25_w1::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h25_w1::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w1::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h25_w1::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5436-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 5436 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w1_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h25_w1::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h25_w1::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w1::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w1::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h25_w1::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=25 W=2.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w2_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h25_w2::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h25_w2::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=25 W=2 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 3060-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥3060 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w2_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h25_w2::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h25_w2::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h25_w2::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w2::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h25_w2::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 3060-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 3060 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w2_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h25_w2::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h25_w2::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w2::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w2::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h25_w2::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=25 W=4.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w4_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h25_w4::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h25_w4::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=25 W=4 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1860-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1860 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w4_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h25_w4::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h25_w4::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h25_w4::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w4::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h25_w4::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1860-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1860 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w4_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h25_w4::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h25_w4::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w4::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w4::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h25_w4::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an LMS key pair for SHAKE-256 M=24 H=25 W=8.
///
/// Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
/// private-key blob into `sk_out` and a 48-byte public key
/// into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥44 bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w8_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_lms::lms_shake_m24_h25_w8::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::lms_shake_m24_h25_w8::PUBLIC_KEY_LEN,
        );
    };
    R::Ok as c_int
}

/// Sign a message with the LMS SHAKE-256 M=24 H=25 W=8 variant.
///
/// Reads the 44-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// 1260-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥44 bytes, `sig_out` ≥1260 bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w8_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe {
        slice_from_raw(
            sk_in_ptr,
            oxicrypt_lms::lms_shake_m24_h25_w8::PRIVATE_KEY_LEN,
        )
    } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(mut sk) = oxicrypt_lms::lms_shake_m24_h25_w8::LmsPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_lms::lms_shake_m24_h25_w8::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::lms_shake_m24_h25_w8::PRIVATE_KEY_LEN,
        );
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::lms_shake_m24_h25_w8::SIGNATURE_LEN,
        );
    };
    R::Ok as c_int
}

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1260-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.
///
/// # Safety
///
/// `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for 1260 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_shake_m24_h25_w8_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice =
        match unsafe { slice_from_raw(pk_ptr, oxicrypt_lms::lms_shake_m24_h25_w8::PUBLIC_KEY_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice =
        match unsafe { slice_from_raw(sig_ptr, oxicrypt_lms::lms_shake_m24_h25_w8::SIGNATURE_LEN) }
        {
            Ok(s) => s,
            Err(e) => return e,
        };
    let Ok(pk) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w8::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; oxicrypt_lms::lms_shake_m24_h25_w8::SIGNATURE_LEN]>::try_from(sig_slice)
    else {
        return R::Internal as c_int;
    };
    match oxicrypt_lms::lms_shake_m24_h25_w8::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

/// Generate an XMSS key pair from a 32-byte caller-supplied seed.
///
/// Reads exactly 32 bytes from `xi_ptr`, deterministically derives
/// `SK_SEED`, `SK_PRF`, and `PUB_SEED` via SHA-256 over `(xi || tag)`
/// for tags 0x00, 0x01, 0x02 respectively, computes the Merkle tree
/// root, and writes the 132-byte opaque private-key blob into
/// `sk_out` and the 68-byte public key into `pk_out`. The caller
/// MUST source the 32 seed bytes from an approved DRBG.
///
/// `sk_out` is the persistence-of-record format. Treat it as opaque.
///
/// Returns `OxiResult::Ok = 0` on success or a module error variant.
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥132 bytes. `pk_out` must be a non-NULL
/// writable pointer to ≥68 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_xmss_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {
    let xi_slice = match unsafe { slice_from_raw(xi_ptr, 32) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || pk_out.is_null() {
        return R::NullPointer as c_int;
    }
    // Unreachable: slice_from_raw verified length == 32.
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {
        return R::Internal as c_int;
    };
    let (sk, pk) = match oxicrypt_xmss::keygen(xi) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe { core::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk_out, OXI_XMSS_PRIVATE_KEY_LEN) };
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, OXI_XMSS_PUBLIC_KEY_LEN) };
    R::Ok as c_int
}

/// Sign a message with an XMSS private key.
///
/// Reads the 132-byte opaque private-key blob from `sk_in_ptr`,
/// `msg_len` bytes from `msg_ptr`, signs the message, advances the
/// internal leaf index by one, writes the **updated** 132-byte blob
/// into `sk_out`, and writes the 2500-byte signature into `sig_out`.
///
/// **Persistence contract:** identical to LMS — the caller MUST
/// persist `sk_out` before using `sig_out`. See [`oxi_lms_sign`] for
/// the rationale.
///
/// Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if the
/// key is exhausted (1024 signatures already issued), or a module
/// error variant.
///
/// # Safety
///
/// `sk_in_ptr` must be valid for 132 bytes. `msg_ptr` must be valid
/// for `msg_len` bytes. `sk_out` must be a non-NULL writable pointer
/// to ≥132 bytes. `sig_out` must be a non-NULL writable pointer to
/// ≥2500 bytes. `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_xmss_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {
    let sk_in = match unsafe { slice_from_raw(sk_in_ptr, OXI_XMSS_PRIVATE_KEY_LEN) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if sk_out.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    // Unreachable: slice_from_raw verified length == 132.
    let Some(mut sk) = oxicrypt_xmss::XmssPrivateKey::from_bytes(sk_in) else {
        return R::InvalidInput as c_int;
    };
    let sig = match oxicrypt_xmss::sign(&mut sk, msg) {
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    };
    let sk_bytes = sk.to_bytes();
    unsafe { core::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk_out, OXI_XMSS_PRIVATE_KEY_LEN) };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, OXI_XMSS_SIGNATURE_LEN) };
    R::Ok as c_int
}

/// Verify an XMSS signature.
///
/// Reads the 68-byte public key from `pk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and the 2500-byte signature from `sig_ptr`.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (parse / structural / cryptographic), or a module error variant.
///
/// # Safety
///
/// `pk_ptr` must be valid for 68 bytes. `msg_ptr` must be valid for
/// `msg_len` bytes. `sig_ptr` must be valid for 2500 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_xmss_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {
    let pk_slice = match unsafe { slice_from_raw(pk_ptr, OXI_XMSS_PUBLIC_KEY_LEN) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_slice = match unsafe { slice_from_raw(sig_ptr, OXI_XMSS_SIGNATURE_LEN) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    // Unreachable: slice_from_raw verified each input's length.
    let Ok(pk) = <&[u8; OXI_XMSS_PUBLIC_KEY_LEN]>::try_from(pk_slice) else {
        return R::Internal as c_int;
    };
    let Ok(sig) = <&[u8; OXI_XMSS_SIGNATURE_LEN]>::try_from(sig_slice) else {
        return R::Internal as c_int;
    };
    match oxicrypt_xmss::verify(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }
}

// ── ECDSA DRBG-driven (FIPS 186-5 §A.2.2 + IG 10.3.A) — handle surface ───
//
// Eight C ABI entry points + two opaque types extending the existing
// stateless ECDSA family (above, lib.rs §"ECDSA (FIPS 186-5) — stateless
// surface") with the FIPS 186-5 §A.2.2 rejection-sampler-driven keygen
// and SHA-{256,384}-based signing. DRBG-handle-as-parameter pattern,
// extending the seam validated by `oxi_dh3072_generate_keypair`
// (PR #30).
//
// Per-curve set:
//   - OxiEcdsaP{256,384}PrivateKey — opaque handle that has passed an
//     IG 10.3.A pairwise consistency test at construction time. Carries
//     both the private scalar `d` and the derived uncompressed SEC1
//     public key `Q`. Drop chain calls upstream
//     `oxicrypt_zeroize::zeroize(&mut self.d)`.
//
//   - oxi_ecdsa_p{256,384}_private_key_new_generate(drbg, **out_key) —
//     allocates a heap handle, generates `d` via FIPS 186-5 §A.2.2
//     rejection sampling on `drbg`, derives `Q`, and runs the
//     IG 10.3.A PCT before returning. Allocation succeeds only on PCT
//     pass; PCT-fail collapses to `OxiResult::InvalidInput = 5`.
//
//   - oxi_ecdsa_p{256,384}_private_key_free(key) — NULL-safe; releases
//     the heap handle and runs Drop, which zeroises `d`.
//
//   - oxi_ecdsa_p{256,384}_private_key_public_key(key, out_pk) — copies
//     the SEC1 uncompressed public key (65 / 97 bytes) into the
//     caller buffer.
//
//   - oxi_ecdsa_p{256,384}_private_key_sign_sha{256,384}(key, drbg,
//     msg, msg_len, out_sig) — signs `msg`, sampling a fresh
//     per-signature nonce `k` from `drbg` via FIPS 186-5 §A.2.2.
//     Both handles must be live; `drbg` is borrowed mutably for the
//     duration of the call (per-call-mutating-handle thread-safety
//     contract — caller MUST serialise concurrent calls on the same
//     `drbg` pointer). Returns `OxiResult::InvalidInput = 5` if the
//     DRBG faults or the bounded retry chain (8 draws) fails to produce
//     a non-zero `(r, s)` (astronomically improbable; signals a faulted
//     primitive, not bad input).
//
// **PCT-at-construction handle invariant** (CMVP gem in security-policy
// §4.8): the C ABI surface preserves the upstream IG 10.3.A invariant
// that no `EcdsaP{256,384}PrivateKey` exists without having passed a
// sign-and-verify PCT against a fixed probe message under a fresh
// DRBG-sampled `k`. Because the handle wraps the upstream type
// directly (via `OxiHandle<EcdsaP{256,384}PrivateKey>`) and only the
// DRBG-driven `_new_generate` constructor exists this round, every
// reachable `OxiEcdsaP{256,384}PrivateKey` pointer in C land
// corresponds to a Rust-side handle whose construction succeeded —
// PCT-fail aborts allocation, never produces a half-initialised
// pointer. Stateless `from_bytes(d, drbg)` import constructor and
// `private_scalar(&self)` exfil accessor are deliberately deferred to
// future additive rounds (no API break to add either later).

/// Opaque ECDSA P-256 private-key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time.
///
/// The internal layout (`OxiHandle<EcdsaP256PrivateKey>`) is
/// implementation detail and not part of the C ABI; cbindgen renders
/// this as an opaque struct.
///
/// cbindgen:opaque
pub struct OxiEcdsaP256PrivateKey {
    inner: OxiHandle<oxicrypt_ecdsa::p256_ecdsa::EcdsaP256PrivateKey>,
}

impl OxiEcdsaP256PrivateKey {
    /// Crate-internal accessor for the underlying read-only
    /// `EcdsaP256PrivateKey`. Returns `None` if the handle has been
    /// finalised (today: never — this handle has no `_finalize` entry
    /// point, only `_free` via Drop).
    pub(crate) fn inner_ref(&self) -> Option<&oxicrypt_ecdsa::p256_ecdsa::EcdsaP256PrivateKey> {
        self.inner.as_ref()
    }
}

/// Opaque ECDSA P-384 private-key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time.
///
/// cbindgen:opaque
pub struct OxiEcdsaP384PrivateKey {
    inner: OxiHandle<oxicrypt_ecdsa::p384_ecdsa::EcdsaP384PrivateKey>,
}

impl OxiEcdsaP384PrivateKey {
    pub(crate) fn inner_ref(&self) -> Option<&oxicrypt_ecdsa::p384_ecdsa::EcdsaP384PrivateKey> {
        self.inner.as_ref()
    }
}

// ── ECDSA P-256 — DRBG-driven keygen + sign ──────────────────────

/// Allocate a new ECDSA P-256 private-key handle, generating its
/// private scalar via the FIPS 186-5 §A.2.2 rejection sampler on
/// `drbg`, deriving its public key, and running the IG 10.3.A
/// pairwise consistency test against a fixed probe message before
/// returning.
///
/// On success, writes a heap-allocated handle pointer through
/// `out_key` and returns `OxiResult::Ok = 0`. The caller owns the
/// handle and MUST release it with
/// [`oxi_ecdsa_p256_private_key_free`].
///
/// Returns `OxiResult::InvalidInput = 5` if the DRBG faults during
/// scalar / nonce sampling, or if the IG 10.3.A PCT sign-and-verify
/// round-trip on the freshly-generated key fails (the latter would
/// indicate a faulted sign or verify primitive). Returns
/// `OxiResult::NotOperational = 1` if the FIPS module is not in the
/// `Operational` state. Returns `OxiResult::AlgorithmRestricted = 6`
/// if the active algorithm profile blocks ECDSA-P256 keygen.
///
/// # Safety
///
/// `drbg` must be a live, instantiated handle from
/// [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate`]. `out_key` must be a non-NULL
/// writable pointer to a `*mut OxiEcdsaP256PrivateKey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p256_private_key_new_generate(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    out_key: *mut *mut OxiEcdsaP256PrivateKey,
) -> c_int {
    if drbg.is_null() || out_key.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let key = match oxicrypt_ecdsa::p256_ecdsa::EcdsaP256PrivateKey::generate(drbg_ref) {
        Ok(k) => k,
        Err(e) => return R::from(e) as c_int,
    };
    let boxed = Box::new(OxiEcdsaP256PrivateKey {
        inner: OxiHandle::new(key),
    });
    unsafe { *out_key = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an ECDSA P-256 private-key handle. NULL-safe.
///
/// After this call the caller's pointer is dangling; the caller
/// SHOULD set their pointer to NULL to avoid use-after-free. Drop
/// on the upstream `EcdsaP256PrivateKey` zeroises the private
/// scalar `d` via the workspace-wide `oxicrypt-zeroize` volatile-
/// write convention; no caller-side scrubbing is required.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by
/// [`oxi_ecdsa_p256_private_key_new_generate`] that has not yet
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p256_private_key_free(key: *mut OxiEcdsaP256PrivateKey) {
    if key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(key) });
}

/// Copy the uncompressed SEC1 public key (`0x04 || X(32) || Y(32)`,
/// 65 bytes) from an ECDSA P-256 private-key handle into the caller
/// buffer.
///
/// Returns `OxiResult::Ok = 0` on success;
/// `OxiResult::NullPointer = 10` if either pointer is NULL;
/// `OxiResult::NotOperational = 1` if the handle has been
/// finalised (today: never — no `_finalize` exists for this handle).
///
/// # Safety
///
/// `key` must be a live handle from
/// [`oxi_ecdsa_p256_private_key_new_generate`]. `public_key_out`
/// must be a non-NULL writable pointer to ≥65 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p256_private_key_public_key(
    key: *const OxiEcdsaP256PrivateKey,
    public_key_out: *mut u8,
) -> c_int {
    if key.is_null() || public_key_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let pk = key_ref.public_key();
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), public_key_out, 65) };
    R::Ok as c_int
}

/// Sign `msg` with ECDSA P-256 + SHA-256 under the private-key
/// handle, sampling a fresh per-signature nonce `k` from `drbg` via
/// the FIPS 186-5 §A.2.2 rejection sampler. If the sampled `k`
/// produces `r == 0` or `s == 0` (mathematically possible but
/// astronomically unlikely; on the order of `2^(-256)` per draw),
/// the call retries with a fresh draw up to 8 times before returning
/// `OxiResult::InvalidInput = 5`.
///
/// On success, writes 64 bytes (`r(32) || s(32)`) into `sig_out`.
///
/// Returns `OxiResult::InvalidInput = 5` if the DRBG faults during
/// nonce sampling or the bounded retry chain exhausts without a
/// non-zero `(r, s)` (a faulted primitive, not bad input). Returns
/// `OxiResult::NotOperational = 1` if the FIPS module is not in the
/// `Operational` state. Returns `OxiResult::AlgorithmRestricted = 6`
/// if the active algorithm profile blocks ECDSA-P256 sign (a profile
/// MAY allow `EcdsaP256Keygen` but block `EcdsaP256Sign`, in which
/// case `_new_generate` succeeds but this fn returns 6).
///
/// # Safety
///
/// `key` must be a live handle from
/// [`oxi_ecdsa_p256_private_key_new_generate`]. `drbg` must be a
/// live, instantiated handle from [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate`]; the caller MUST serialise
/// concurrent calls on the same `drbg` pointer per the
/// per-call-mutating-handle thread-safety contract documented in
/// security-policy §4.8. `msg_ptr` must be valid for `msg_len` bytes.
/// `sig_out` must be a non-NULL writable pointer to ≥64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p256_private_key_sign_sha256(
    key: *const OxiEcdsaP256PrivateKey,
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || drbg.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 64) };
    R::Ok as c_int
}

// ── ECDSA P-384 — DRBG-driven keygen + sign ──────────────────────

/// Allocate a new ECDSA P-384 private-key handle, generating its
/// private scalar via the FIPS 186-5 §A.2.2 rejection sampler on
/// `drbg`, deriving its public key, and running the IG 10.3.A
/// pairwise consistency test before returning. Mirrors
/// [`oxi_ecdsa_p256_private_key_new_generate`].
///
/// # Safety
///
/// `drbg` must be a live, instantiated DRBG handle. `out_key` must
/// be a non-NULL writable pointer to a `*mut OxiEcdsaP384PrivateKey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p384_private_key_new_generate(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    out_key: *mut *mut OxiEcdsaP384PrivateKey,
) -> c_int {
    if drbg.is_null() || out_key.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let key = match oxicrypt_ecdsa::p384_ecdsa::EcdsaP384PrivateKey::generate(drbg_ref) {
        Ok(k) => k,
        Err(e) => return R::from(e) as c_int,
    };
    let boxed = Box::new(OxiEcdsaP384PrivateKey {
        inner: OxiHandle::new(key),
    });
    unsafe { *out_key = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an ECDSA P-384 private-key handle. NULL-safe. Mirrors
/// [`oxi_ecdsa_p256_private_key_free`].
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by
/// [`oxi_ecdsa_p384_private_key_new_generate`] that has not yet
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p384_private_key_free(key: *mut OxiEcdsaP384PrivateKey) {
    if key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(key) });
}

/// Copy the uncompressed SEC1 public key (`0x04 || X(48) || Y(48)`,
/// 97 bytes) from an ECDSA P-384 private-key handle into the caller
/// buffer.
///
/// # Safety
///
/// `key` must be a live handle from
/// [`oxi_ecdsa_p384_private_key_new_generate`]. `public_key_out`
/// must be a non-NULL writable pointer to ≥97 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p384_private_key_public_key(
    key: *const OxiEcdsaP384PrivateKey,
    public_key_out: *mut u8,
) -> c_int {
    if key.is_null() || public_key_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let pk = key_ref.public_key();
    unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), public_key_out, 97) };
    R::Ok as c_int
}

/// Sign `msg` with ECDSA P-384 + SHA-384 under the private-key
/// handle, sampling a fresh per-signature nonce `k` from `drbg` via
/// the FIPS 186-5 §A.2.2 rejection sampler. Mirrors
/// [`oxi_ecdsa_p256_private_key_sign_sha256`] with `[u8; 96]`
/// signature output.
///
/// Returns `OxiResult::InvalidInput = 5` if the DRBG faults or the
/// bounded retry chain exhausts. Returns `OxiResult::NotOperational
/// = 1` if the FIPS module is not in the `Operational` state.
/// Returns `OxiResult::AlgorithmRestricted = 6` if the active
/// algorithm profile blocks ECDSA-P384 sign (a profile MAY allow
/// `EcdsaP384Keygen` but block `EcdsaP384Sign`, in which case
/// `_new_generate` succeeds but this fn returns 6).
///
/// # Safety
///
/// `key` must be a live handle from
/// [`oxi_ecdsa_p384_private_key_new_generate`]. `drbg` must be a
/// live, instantiated DRBG handle; serialise concurrent calls per
/// the per-call-mutating-handle thread-safety contract.
/// `msg_ptr` must be valid for `msg_len` bytes. `sig_out` must be a
/// non-NULL writable pointer to ≥96 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p384_private_key_sign_sha384(
    key: *const OxiEcdsaP384PrivateKey,
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || drbg.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_sha384(drbg_ref, msg) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 96) };
    R::Ok as c_int
}

// ── RSA DRBG-driven (FIPS 186-5 / RFC 8017 §8) — handle surface ──
//
// 24 entry points + 3 opaque types completing the RSA family. Verify-
// only stateless surface shipped earlier (six fns: PKCS#1 v1.5 verify
// and PSS verify across 2048/3072/4096); this round adds DRBG-driven
// keygen with PCT-at-construction, deterministic PKCS#1 v1.5 sign,
// DRBG-driven PSS sign, public-key DRBG-driven OAEP encrypt,
// handle-mediated OAEP decrypt, plus modulus and public-exponent
// accessors per size.
//
// Per-size pattern (×3: 2048, 3072, 4096):
//
//   1. _new_generate(drbg, e, **out_key)        DRBG-driven, PCT-at-construction
//   2. _free(key)                               Opaque-handle cleanup
//   3. _modulus(key, out)                       Public n accessor
//   4. _public_exponent(key, *out_e)            Public e accessor
//   5. _sign_pkcs1_v15_sha256(key, msg, sig)    Deterministic
//   6. _sign_pss_sha256(key, drbg, msg, sig)    DRBG-driven re-borrow for fresh salt
//   7. _oaep_encrypt_sha256(drbg, n, e, ...)    Stateless public-key, DRBG seed
//   8. _oaep_decrypt_sha256(key, label, ct, ...)Handle-mediated, length-out-pointer
//
// **CRT-secret-exfil safe by API shape:** the handle exposes only `n`
// (modulus) and `e` (public exponent) via accessors. The CRT
// components — `p`, `q`, `dP`, `dQ`, `qInv` — remain encapsulated
// inside the upstream `RsaPrivateKey{N}` struct and are zeroized by
// its `Drop` impl on handle release. There is no FFI accessor that
// can extract the secret half-moduli or private exponent: the C API
// does not surface them and the underlying Rust struct's CRT field is
// `pub(crate)`-private to `oxicrypt-rsa`.
//
// **PCT-at-construction handle invariant** (extends ECDSA gem from
// security-policy §4.8): `_new_generate` is the sole construction
// path exposed via FFI; it routes through `RsaPrivateKey{N}::generate`,
// which runs the IG 10.3.A pairwise consistency test on the CRT path
// (sign a fixed probe with `_crt_internal`, verify with the public
// exponent) before returning the handle. Every handle a C caller can
// observe has therefore already produced a valid sign/verify pair on
// the same code path the caller will exercise.
//
// **DRBG-handle-as-parameter** (per `OxiHmacDrbgSha256::inner_mut`):
// keygen takes the DRBG by mutable pointer; sign-PSS re-borrows the
// same DRBG for per-signature salt sampling; OAEP encrypt borrows the
// DRBG for seed sampling. Three sites per size = nine DRBG re-borrows
// total for this round — single-threaded callers are unaffected;
// concurrent C callers must serialize DRBG access per the per-call-
// mutating-handle thread-safety contract documented in
// security-policy.md.
//
// **TagMismatch=22 mapping (verify-only)** continues to apply to the
// previously-shipped verify functions; sign / decrypt / keygen on
// this surface use the generic `R::from(Error)` mapping (Error
// coverage already complete; no new `OxiResult` discriminants).

// ── Opaque RSA private-key handles ───────────────────────────────

/// Opaque RSA-2048 private-key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time. Mirrors the
/// `OxiEcdsaP256PrivateKey` pattern and inherits the same PCT-at-
/// construction structural argument from security-policy §4.8.
///
/// cbindgen:opaque
pub struct OxiRsaPrivateKey2048 {
    inner: OxiHandle<oxicrypt_rsa::RsaPrivateKey2048>,
}

impl OxiRsaPrivateKey2048 {
    /// Crate-internal accessor for the underlying read-only
    /// `RsaPrivateKey2048`. Returns `None` if the handle has been
    /// finalised (today: never — this handle has no `_finalize`
    /// entry point, only `_free` via Drop).
    pub(crate) fn inner_ref(&self) -> Option<&oxicrypt_rsa::RsaPrivateKey2048> {
        self.inner.as_ref()
    }
}

/// Opaque RSA-3072 private-key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time.
///
/// cbindgen:opaque
pub struct OxiRsaPrivateKey3072 {
    inner: OxiHandle<oxicrypt_rsa::rsa3072::RsaPrivateKey3072>,
}

impl OxiRsaPrivateKey3072 {
    pub(crate) fn inner_ref(&self) -> Option<&oxicrypt_rsa::rsa3072::RsaPrivateKey3072> {
        self.inner.as_ref()
    }
}

/// Opaque RSA-4096 private-key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time.
///
/// cbindgen:opaque
pub struct OxiRsaPrivateKey4096 {
    inner: OxiHandle<oxicrypt_rsa::rsa4096::RsaPrivateKey4096>,
}

impl OxiRsaPrivateKey4096 {
    pub(crate) fn inner_ref(&self) -> Option<&oxicrypt_rsa::rsa4096::RsaPrivateKey4096> {
        self.inner.as_ref()
    }
}

// ── RSA-2048 — DRBG-driven keygen + sign + OAEP ──────────────────

/// Allocate a new RSA-2048 private-key handle, generating a fresh
/// keypair via FIPS 186-5 §A.1.1 / §B.3.1 prime sampling on `drbg`,
/// then running the IG 10.3.A pairwise consistency test on the CRT
/// path (sign a fixed probe, verify with the public exponent) before
/// returning. `e` must be an odd prime in `[65537, 2^64)` — in
/// practice, pass `65537` (F4).
///
/// On success, writes a heap-allocated handle pointer through
/// `out_key` and returns `OxiResult::Ok = 0`. The caller owns the
/// handle and MUST release it with [`oxi_rsa_2048_private_key_free`].
///
/// Returns `OxiResult::InvalidInput = 5` if the DRBG faults during
/// prime sampling, the prime-candidate retry budget is exceeded,
/// `e` fails the structural check, or the resulting keypair fails
/// the pairwise consistency test (the latter would indicate internal
/// corruption). Returns `OxiResult::NotOperational = 1` if the FIPS
/// module is not in the `Operational` state. Returns
/// `OxiResult::AlgorithmRestricted = 6` if the active algorithm
/// profile blocks RSA-2048 keygen.
///
/// # Safety
///
/// `drbg` must be a live, instantiated handle from
/// [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate`]. `out_key` must be a non-NULL
/// writable pointer to a `*mut OxiRsaPrivateKey2048`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_private_key_new_generate(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    e: u64,
    out_key: *mut *mut OxiRsaPrivateKey2048,
) -> c_int {
    if drbg.is_null() || out_key.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let key = match oxicrypt_rsa::RsaPrivateKey2048::generate(drbg_ref, e) {
        Ok(k) => k,
        Err(err) => return R::from(err) as c_int,
    };
    let boxed = Box::new(OxiRsaPrivateKey2048 {
        inner: OxiHandle::new(key),
    });
    unsafe { *out_key = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an RSA-2048 private-key handle. NULL-safe.
///
/// After this call the caller's pointer is dangling. Drop on the
/// upstream `RsaPrivateKey2048` zeroises the private exponent `d`
/// and (when present) the CRT components `p, q, dP, dQ, qInv` via
/// the workspace-wide `oxicrypt-zeroize` volatile-write convention.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by
/// [`oxi_rsa_2048_private_key_new_generate`] that has not yet been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_private_key_free(key: *mut OxiRsaPrivateKey2048) {
    if key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(key) });
}

/// Copy the public modulus `n` (256 bytes, big-endian) from an
/// RSA-2048 private-key handle into the caller buffer.
///
/// Returns `OxiResult::Ok = 0` on success;
/// `OxiResult::NullPointer = 10` if either pointer is NULL.
///
/// # Safety
///
/// `key` must be a live handle. `modulus_out` must be a non-NULL
/// writable pointer to ≥256 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_modulus(
    key: *const OxiRsaPrivateKey2048,
    modulus_out: *mut u8,
) -> c_int {
    if key.is_null() || modulus_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let n = key_ref.modulus_bytes();
    unsafe { core::ptr::copy_nonoverlapping(n.as_ptr(), modulus_out, 256) };
    R::Ok as c_int
}

/// Copy the public exponent `e` from an RSA-2048 private-key handle
/// into the caller-supplied `uint64_t*`.
///
/// Returns `OxiResult::Ok = 0` on success;
/// `OxiResult::NullPointer = 10` if either pointer is NULL.
///
/// # Safety
///
/// `key` must be a live handle. `e_out` must be a non-NULL writable
/// pointer to a `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_public_exponent(
    key: *const OxiRsaPrivateKey2048,
    e_out: *mut u64,
) -> c_int {
    if key.is_null() || e_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    unsafe { *e_out = key_ref.public_exponent() };
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PKCS#1-v1.5 SHA-256 under the RSA-2048
/// private-key handle (FIPS 186-5 §5.4 / RFC 8017 §8.2).
/// Deterministic — signing the same `(key, msg)` twice produces
/// byte-identical signatures.
///
/// On success, writes 256 bytes into `sig_out` and returns `Ok = 0`.
///
/// # Safety
///
/// `key` must be a live handle. `msg_ptr` must be valid for
/// `msg_len` bytes. `sig_out` must be a non-NULL writable pointer
/// to ≥256 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_sign_pkcs1_v15_sha256(
    key: *const OxiRsaPrivateKey2048,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_pkcs1_v15_sha256(msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 256) };
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PSS SHA-256 under the RSA-2048 private-
/// key handle, sampling a fresh 32-byte salt from `drbg` per call
/// (FIPS 186-5 §5.4 / RFC 8017 §8.1). Signing the same `(key, msg)`
/// twice produces two distinct signatures.
///
/// On success, writes 256 bytes into `sig_out` and returns `Ok = 0`.
///
/// # Safety
///
/// `key` must be a live handle. `drbg` must be a live, instantiated
/// DRBG handle; the caller MUST serialise concurrent calls on the
/// same `drbg` pointer per the per-call-mutating-handle thread-
/// safety contract documented in security-policy.md. `msg_ptr` must
/// be valid for `msg_len` bytes. `sig_out` must be a non-NULL
/// writable pointer to ≥256 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_sign_pss_sha256(
    key: *const OxiRsaPrivateKey2048,
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || drbg.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_pss_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 256) };
    R::Ok as c_int
}

/// Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-2048
/// public key `(n, e)`, sampling a fresh 32-byte seed from `drbg`
/// per call (RFC 8017 §7.1). The ciphertext is fixed at 256 bytes
/// regardless of message length. Maximum plaintext length is 190
/// bytes (`k − 2·hLen − 2` with `k = 256`, `hLen = 32`).
///
/// On success, writes 256 bytes into `ct_out` and returns `Ok = 0`.
///
/// # Safety
///
/// `drbg` must be a live, instantiated DRBG handle. `n_ptr` must
/// point to a 256-byte big-endian modulus. `label_ptr` must be valid
/// for `label_len` bytes (use `NULL`/`0` for the empty label).
/// `msg_ptr` must be valid for `msg_len` bytes; `msg_len` must be
/// ≤ 190. `ct_out` must be a non-NULL writable pointer to ≥256 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_oaep_encrypt_sha256(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    n_ptr: *const u8,
    e: u64,
    label_ptr: *const u8,
    label_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    ct_out: *mut u8,
) -> c_int {
    if drbg.is_null() || n_ptr.is_null() || ct_out.is_null() {
        return R::NullPointer as c_int;
    }
    let n = match unsafe { slice_from_raw(n_ptr, 256) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let Ok(n_arr) = <&[u8; 256]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let ct = match oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256(drbg_ref, n_arr, e, label, msg) {
        Ok(c) => c,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, 256) };
    R::Ok as c_int
}

/// Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-2048
/// private-key handle (RFC 8017 §7.1). The ciphertext is fixed at
/// 256 bytes; the recovered plaintext length is variable in
/// `[0, 190]` and reported through `out_actual_len`.
///
/// `out_max_len` must be ≥ 190 (the maximum possible plaintext for
/// RSA-2048 OAEP-SHA-256). On success, the recovered plaintext is
/// written into `out_ptr[0..*out_actual_len]`.
///
/// All OAEP decode failures (bad `Y` byte, `lHash'` mismatch,
/// malformed `PS`, missing `0x01` delimiter, wrong label) collapse
/// to `OxiResult::InvalidInput = 5` without revealing which check
/// failed (Manger-resistance contract). When the handle was built
/// with CRT material (the only path exposed via `_new_generate`), a
/// single CRT-half fault is caught by the Bellcore verify-after-
/// decrypt step in the upstream primitive.
///
/// # Safety
///
/// `key` must be a live handle. `label_ptr` must be valid for
/// `label_len` bytes. `ct_ptr` must point to exactly 256 bytes.
/// `out_ptr` must be a non-NULL writable pointer to ≥`out_max_len`
/// bytes; `out_max_len` must be ≥ 190. `out_actual_len` must be a
/// non-NULL writable pointer to a `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_2048_oaep_decrypt_sha256(
    key: *const OxiRsaPrivateKey2048,
    label_ptr: *const u8,
    label_len: usize,
    ct_ptr: *const u8,
    out_ptr: *mut u8,
    out_max_len: usize,
    out_actual_len: *mut usize,
) -> c_int {
    if key.is_null() || ct_ptr.is_null() || out_ptr.is_null() || out_actual_len.is_null() {
        return R::NullPointer as c_int;
    }
    if out_max_len < oxicrypt_rsa::oaep::MAX_MSG_LEN {
        return R::InvalidInput as c_int;
    }
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let ct = match unsafe { slice_from_raw(ct_ptr, 256) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let Ok(ct_arr) = <&[u8; 256]>::try_from(ct) else {
        return R::Internal as c_int;
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let mut buf = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
    let actual = match key_ref.decrypt_oaep_sha256(label, ct_arr, &mut buf) {
        Ok(n) => n,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr, actual) };
    unsafe { *out_actual_len = actual };
    R::Ok as c_int
}

// ── RSA-3072 — DRBG-driven keygen + sign + OAEP ──────────────────

/// Allocate a new RSA-3072 private-key handle. Mirrors
/// [`oxi_rsa_2048_private_key_new_generate`] for the 3072-bit
/// modulus; PCT-at-construction runs on the CRT path with Bellcore
/// verify-after-sign.
///
/// # Safety
///
/// See [`oxi_rsa_2048_private_key_new_generate`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_private_key_new_generate(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    e: u64,
    out_key: *mut *mut OxiRsaPrivateKey3072,
) -> c_int {
    if drbg.is_null() || out_key.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let key = match oxicrypt_rsa::rsa3072::RsaPrivateKey3072::generate(drbg_ref, e) {
        Ok(k) => k,
        Err(err) => return R::from(err) as c_int,
    };
    let boxed = Box::new(OxiRsaPrivateKey3072 {
        inner: OxiHandle::new(key),
    });
    unsafe { *out_key = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an RSA-3072 private-key handle. NULL-safe. See
/// [`oxi_rsa_2048_private_key_free`] for zeroization semantics.
///
/// # Safety
///
/// See [`oxi_rsa_2048_private_key_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_private_key_free(key: *mut OxiRsaPrivateKey3072) {
    if key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(key) });
}

/// Copy the 384-byte big-endian public modulus `n` from an RSA-3072
/// handle. See [`oxi_rsa_2048_modulus`].
///
/// # Safety
///
/// `key` must be a live handle. `modulus_out` must be a non-NULL
/// writable pointer to ≥384 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_modulus(
    key: *const OxiRsaPrivateKey3072,
    modulus_out: *mut u8,
) -> c_int {
    if key.is_null() || modulus_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let n = key_ref.modulus_bytes();
    unsafe { core::ptr::copy_nonoverlapping(n.as_ptr(), modulus_out, 384) };
    R::Ok as c_int
}

/// Copy the public exponent `e` from an RSA-3072 handle. See
/// [`oxi_rsa_2048_public_exponent`].
///
/// # Safety
///
/// `key` must be a live handle. `e_out` must be a non-NULL writable
/// pointer to a `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_public_exponent(
    key: *const OxiRsaPrivateKey3072,
    e_out: *mut u64,
) -> c_int {
    if key.is_null() || e_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    unsafe { *e_out = key_ref.public_exponent() };
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PKCS#1-v1.5 SHA-256 under the RSA-3072
/// handle. Deterministic; produces a 384-byte signature.
///
/// # Safety
///
/// See [`oxi_rsa_2048_sign_pkcs1_v15_sha256`]. `sig_out` must be a
/// non-NULL writable pointer to ≥384 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_sign_pkcs1_v15_sha256(
    key: *const OxiRsaPrivateKey3072,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_pkcs1_v15_sha256(msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 384) };
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PSS SHA-256 under the RSA-3072 handle,
/// DRBG-sampled salt. Produces a 384-byte signature.
///
/// # Safety
///
/// See [`oxi_rsa_2048_sign_pss_sha256`]. `sig_out` must be a
/// non-NULL writable pointer to ≥384 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_sign_pss_sha256(
    key: *const OxiRsaPrivateKey3072,
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || drbg.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_pss_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 384) };
    R::Ok as c_int
}

/// Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-3072
/// public key `(n, e)`, DRBG-sampled seed. Maximum plaintext length
/// is 318 bytes (`k − 2·hLen − 2` with `k = 384`, `hLen = 32`).
/// Ciphertext is fixed at 384 bytes.
///
/// # Safety
///
/// See [`oxi_rsa_2048_oaep_encrypt_sha256`]. `n_ptr` must point to
/// 384 bytes; `msg_len` must be ≤ 318; `ct_out` must be a non-NULL
/// writable pointer to ≥384 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_oaep_encrypt_sha256(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    n_ptr: *const u8,
    e: u64,
    label_ptr: *const u8,
    label_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    ct_out: *mut u8,
) -> c_int {
    if drbg.is_null() || n_ptr.is_null() || ct_out.is_null() {
        return R::NullPointer as c_int;
    }
    let n = match unsafe { slice_from_raw(n_ptr, 384) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let Ok(n_arr) = <&[u8; 384]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let ct = match oxicrypt_rsa::rsa3072::oaep_encrypt(drbg_ref, n_arr, e, label, msg) {
        Ok(c) => c,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, 384) };
    R::Ok as c_int
}

/// Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-3072
/// handle. `out_max_len` must be ≥ 318. Mirrors the Manger-
/// resistance and Bellcore-on-CRT contracts of
/// [`oxi_rsa_2048_oaep_decrypt_sha256`].
///
/// # Safety
///
/// See [`oxi_rsa_2048_oaep_decrypt_sha256`]. `ct_ptr` must point to
/// exactly 384 bytes; `out_max_len` must be ≥ 318.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_3072_oaep_decrypt_sha256(
    key: *const OxiRsaPrivateKey3072,
    label_ptr: *const u8,
    label_len: usize,
    ct_ptr: *const u8,
    out_ptr: *mut u8,
    out_max_len: usize,
    out_actual_len: *mut usize,
) -> c_int {
    if key.is_null() || ct_ptr.is_null() || out_ptr.is_null() || out_actual_len.is_null() {
        return R::NullPointer as c_int;
    }
    if out_max_len < oxicrypt_rsa::rsa3072::OAEP_MAX_MSG_LEN {
        return R::InvalidInput as c_int;
    }
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let ct = match unsafe { slice_from_raw(ct_ptr, 384) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let Ok(ct_arr) = <&[u8; 384]>::try_from(ct) else {
        return R::Internal as c_int;
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    // Pass the caller's buffer directly — upstream `decrypt_oaep_sha256`
    // (macro-generated, `&mut [u8]` slice variant) writes to `out` only
    // on the success path of `emsa_oaep_decode_n` (after the
    // constant-time accumulator check passes); failure returns `None`
    // before any write, so the caller's buffer is left untouched on
    // error. No intermediate stack copy needed.
    let out_slice = unsafe { core::slice::from_raw_parts_mut(out_ptr, out_max_len) };
    let actual = match key_ref.decrypt_oaep_sha256(label, ct_arr, out_slice) {
        Ok(n) => n,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { *out_actual_len = actual };
    R::Ok as c_int
}

// ── RSA-4096 — DRBG-driven keygen + sign + OAEP ──────────────────

/// Allocate a new RSA-4096 private-key handle. Mirrors
/// [`oxi_rsa_2048_private_key_new_generate`] for the 4096-bit
/// modulus.
///
/// # Safety
///
/// See [`oxi_rsa_2048_private_key_new_generate`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_private_key_new_generate(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    e: u64,
    out_key: *mut *mut OxiRsaPrivateKey4096,
) -> c_int {
    if drbg.is_null() || out_key.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let key = match oxicrypt_rsa::rsa4096::RsaPrivateKey4096::generate(drbg_ref, e) {
        Ok(k) => k,
        Err(err) => return R::from(err) as c_int,
    };
    let boxed = Box::new(OxiRsaPrivateKey4096 {
        inner: OxiHandle::new(key),
    });
    unsafe { *out_key = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an RSA-4096 private-key handle. NULL-safe.
///
/// # Safety
///
/// See [`oxi_rsa_2048_private_key_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_private_key_free(key: *mut OxiRsaPrivateKey4096) {
    if key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(key) });
}

/// Copy the 512-byte big-endian public modulus `n` from an RSA-4096
/// handle.
///
/// # Safety
///
/// `key` must be a live handle. `modulus_out` must be a non-NULL
/// writable pointer to ≥512 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_modulus(
    key: *const OxiRsaPrivateKey4096,
    modulus_out: *mut u8,
) -> c_int {
    if key.is_null() || modulus_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let n = key_ref.modulus_bytes();
    unsafe { core::ptr::copy_nonoverlapping(n.as_ptr(), modulus_out, 512) };
    R::Ok as c_int
}

/// Copy the public exponent `e` from an RSA-4096 handle.
///
/// # Safety
///
/// `key` must be a live handle. `e_out` must be a non-NULL writable
/// pointer to a `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_public_exponent(
    key: *const OxiRsaPrivateKey4096,
    e_out: *mut u64,
) -> c_int {
    if key.is_null() || e_out.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    unsafe { *e_out = key_ref.public_exponent() };
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PKCS#1-v1.5 SHA-256 under the RSA-4096
/// handle. Deterministic; produces a 512-byte signature.
///
/// # Safety
///
/// See [`oxi_rsa_2048_sign_pkcs1_v15_sha256`]. `sig_out` must be a
/// non-NULL writable pointer to ≥512 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_sign_pkcs1_v15_sha256(
    key: *const OxiRsaPrivateKey4096,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_pkcs1_v15_sha256(msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 512) };
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PSS SHA-256 under the RSA-4096 handle,
/// DRBG-sampled salt. Produces a 512-byte signature.
///
/// # Safety
///
/// See [`oxi_rsa_2048_sign_pss_sha256`]. `sig_out` must be a
/// non-NULL writable pointer to ≥512 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_sign_pss_sha256(
    key: *const OxiRsaPrivateKey4096,
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || drbg.is_null() || sig_out.is_null() {
        return R::NullPointer as c_int;
    }
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let sig = match key_ref.sign_pss_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 512) };
    R::Ok as c_int
}

/// Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-4096
/// public key `(n, e)`, DRBG-sampled seed. Maximum plaintext length
/// is 446 bytes; ciphertext is 512 bytes.
///
/// # Safety
///
/// See [`oxi_rsa_2048_oaep_encrypt_sha256`]. `n_ptr` must point to
/// 512 bytes; `msg_len` must be ≤ 446; `ct_out` must be a non-NULL
/// writable pointer to ≥512 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_oaep_encrypt_sha256(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    n_ptr: *const u8,
    e: u64,
    label_ptr: *const u8,
    label_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    ct_out: *mut u8,
) -> c_int {
    if drbg.is_null() || n_ptr.is_null() || ct_out.is_null() {
        return R::NullPointer as c_int;
    }
    let n = match unsafe { slice_from_raw(n_ptr, 512) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let Ok(n_arr) = <&[u8; 512]>::try_from(n) else {
        return R::Internal as c_int;
    };
    let Some(drbg_ref) = (unsafe { (*drbg).inner_mut() }) else {
        return R::NotOperational as c_int;
    };
    let ct = match oxicrypt_rsa::rsa4096::oaep_encrypt(drbg_ref, n_arr, e, label, msg) {
        Ok(c) => c,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { core::ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, 512) };
    R::Ok as c_int
}

/// Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-4096
/// handle. `out_max_len` must be ≥ 446. Manger-resistant and
/// Bellcore-protected on the CRT path.
///
/// # Safety
///
/// See [`oxi_rsa_2048_oaep_decrypt_sha256`]. `ct_ptr` must point to
/// exactly 512 bytes; `out_max_len` must be ≥ 446.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_rsa_4096_oaep_decrypt_sha256(
    key: *const OxiRsaPrivateKey4096,
    label_ptr: *const u8,
    label_len: usize,
    ct_ptr: *const u8,
    out_ptr: *mut u8,
    out_max_len: usize,
    out_actual_len: *mut usize,
) -> c_int {
    if key.is_null() || ct_ptr.is_null() || out_ptr.is_null() || out_actual_len.is_null() {
        return R::NullPointer as c_int;
    }
    if out_max_len < oxicrypt_rsa::rsa4096::OAEP_MAX_MSG_LEN {
        return R::InvalidInput as c_int;
    }
    let label = match unsafe { slice_from_raw(label_ptr, label_len) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let ct = match unsafe { slice_from_raw(ct_ptr, 512) } {
        Ok(s) => s,
        Err(err) => return err,
    };
    let Ok(ct_arr) = <&[u8; 512]>::try_from(ct) else {
        return R::Internal as c_int;
    };
    let Some(key_ref) = (unsafe { (*key).inner_ref() }) else {
        return R::NotOperational as c_int;
    };
    // Direct caller-buffer write — see `oxi_rsa_3072_oaep_decrypt_sha256`
    // for the Manger-resistance + write-on-success-only argument.
    let out_slice = unsafe { core::slice::from_raw_parts_mut(out_ptr, out_max_len) };
    let actual = match key_ref.decrypt_oaep_sha256(label, ct_arr, out_slice) {
        Ok(n) => n,
        Err(err) => return R::from(err) as c_int,
    };
    unsafe { *out_actual_len = actual };
    R::Ok as c_int
}

#[cfg(test)]
mod lama_tests {
    use super::LAMA_MANIFEST;

    /// The embedded manifest must not contain either integrity-slot magic.
    ///
    /// This crate now carries a ~500 KB document inside an artifact whose
    /// integrity slot is located by scanning the on-disk bytes for a
    /// header/footer magic pair. A second match anywhere in the file makes
    /// the signer refuse the artifact as ambiguous, a hard failure — so an
    /// arbitrary embedded document is a surface worth guarding rather than
    /// assuming away.
    ///
    /// It holds structurally today: both magics lead with `0xfc` / `0xfd`,
    /// which are not legal UTF-8 lead bytes, and the manifest is valid UTF-8.
    /// The test exists so a future change to either the magics or the
    /// embedding says so out loud.
    #[test]
    fn embedded_manifest_carries_neither_integrity_magic() {
        let bytes = LAMA_MANIFEST.as_bytes();
        let hdr = &oxicrypt_integrity::SLOT_HEADER_MAGIC;
        let ftr = &oxicrypt_integrity::SLOT_FOOTER_MAGIC;
        assert!(
            !bytes.windows(hdr.len()).any(|w| w == hdr),
            "embedded LAMA manifest contains SLOT_HEADER_MAGIC"
        );
        assert!(
            !bytes.windows(ftr.len()).any(|w| w == ftr),
            "embedded LAMA manifest contains SLOT_FOOTER_MAGIC"
        );

        // Positive control: the same scan finds a sequence that IS present, so
        // a silently broken search cannot pass as a clean result.
        let present = b"lama: ";
        assert!(
            bytes.windows(present.len()).any(|w| w == present),
            "the scan found nothing at all — the probe is broken, not the manifest"
        );
    }

    /// The manifest is NUL-terminated exactly once, at the end.
    #[test]
    fn embedded_manifest_is_nul_terminated_once() {
        let bytes = LAMA_MANIFEST.as_bytes();
        // The first NUL must be the last byte: an interior one would truncate
        // the document silently for any C consumer calling strlen.
        assert_eq!(bytes.iter().position(|b| *b == 0), Some(bytes.len() - 1));
        assert_eq!(bytes.last(), Some(&0u8));
    }
}
