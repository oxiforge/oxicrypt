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
//! because they accept raw pointers from C callers. A caller must
//! pass each pointer either null or valid for reads, or writes, of
//! the length it supplies beside it. A null pointer with a non-zero
//! length is refused with `NullPointer = 10`; a null pointer with
//! length 0 is an empty input where the function's documentation says
//! so. A length outside the documented bounds is refused with the code
//! the function's own documentation names.
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
//! | `2`   | CNSA 1.0 (AES-256, SHA-384, P-384, RSA ≥ 3072, DH ≥ 3072) |
//! | `3`   | Migration — both suites at once; not a CNSA profile |
//!
//! Unknown profile codes return [`OxiResult::InvalidInput`].
//! Once a profile is active, calling a restricted algorithm returns
//! [`OxiResult::AlgorithmRestricted`].
//! [`oxi_active_profile`] queries the current profile;
//! [`oxi_is_operational`] queries the module state.

// This crate is the FFI boundary — unsafe is required by definition.
#![allow(unsafe_code, clippy::missing_safety_doc)]

#[cfg(test)]
mod abi_tests;
mod aes;
mod drbg;
mod error;
mod handle;
mod power_up;
mod pq;
#[cfg(test)]
mod pq_tests;
mod rbg;
#[cfg(feature = "fault-injection")]
mod test_api;

include!("abi_version.rs");
pub use aes::{
    OxiAesCbcKey, OxiAesCcmKey, OxiAesCmacKey, OxiAesCtrKey, OxiAesGcmKey, OxiAesKwKey,
    oxi_aes_cbc_decrypt, oxi_aes_cbc_encrypt, oxi_aes_cbc_key_free, oxi_aes_cbc_key_new,
    oxi_aes_ccm_key_free, oxi_aes_ccm_key_invocations, oxi_aes_ccm_key_new,
    oxi_aes_ccm_key_new_with_count, oxi_aes_ccm_open, oxi_aes_ccm_seal, oxi_aes_cmac,
    oxi_aes_cmac_key_free, oxi_aes_cmac_key_new, oxi_aes_cmac_verify, oxi_aes_ctr,
    oxi_aes_ctr_key_free, oxi_aes_ctr_key_new, oxi_aes_gcm_key_free, oxi_aes_gcm_key_invocations,
    oxi_aes_gcm_key_new, oxi_aes_gcm_key_new_with_count, oxi_aes_gcm_key_new_with_limit,
    oxi_aes_gcm_open, oxi_aes_gcm_seal, oxi_aes_kw_key_free, oxi_aes_kw_key_new, oxi_aes_kw_unwrap,
    oxi_aes_kw_unwrap_inverse, oxi_aes_kw_wrap, oxi_aes_kw_wrap_inverse, oxi_aes_kwp_unwrap,
    oxi_aes_kwp_unwrap_inverse, oxi_aes_kwp_wrap, oxi_aes_kwp_wrap_inverse,
};
pub use drbg::{
    OxiCtrDrbgAes128, OxiCtrDrbgAes192, OxiCtrDrbgAes256, OxiHashDrbgSha256, OxiHashDrbgSha384,
    OxiHashDrbgSha512, OxiHmacDrbgSha256, OxiHmacDrbgSha384, OxiHmacDrbgSha512,
    oxi_ctr_drbg_aes128_free, oxi_ctr_drbg_aes128_generate_df,
    oxi_ctr_drbg_aes128_instantiate_from_module, oxi_ctr_drbg_aes128_new,
    oxi_ctr_drbg_aes128_reseed_from_module, oxi_ctr_drbg_aes192_free,
    oxi_ctr_drbg_aes192_generate_df, oxi_ctr_drbg_aes192_instantiate_from_module,
    oxi_ctr_drbg_aes192_new, oxi_ctr_drbg_aes192_reseed_from_module, oxi_ctr_drbg_aes256_free,
    oxi_ctr_drbg_aes256_generate_df, oxi_ctr_drbg_aes256_instantiate_from_module,
    oxi_ctr_drbg_aes256_new, oxi_ctr_drbg_aes256_reseed_from_module, oxi_hash_drbg_sha256_free,
    oxi_hash_drbg_sha256_generate, oxi_hash_drbg_sha256_instantiate_from_module,
    oxi_hash_drbg_sha256_new, oxi_hash_drbg_sha256_reseed_from_module, oxi_hash_drbg_sha384_free,
    oxi_hash_drbg_sha384_generate, oxi_hash_drbg_sha384_instantiate_from_module,
    oxi_hash_drbg_sha384_new, oxi_hash_drbg_sha384_reseed_from_module, oxi_hash_drbg_sha512_free,
    oxi_hash_drbg_sha512_generate, oxi_hash_drbg_sha512_instantiate_from_module,
    oxi_hash_drbg_sha512_new, oxi_hash_drbg_sha512_reseed_from_module, oxi_hmac_drbg_sha256_free,
    oxi_hmac_drbg_sha256_generate, oxi_hmac_drbg_sha256_instantiate_from_module,
    oxi_hmac_drbg_sha256_new, oxi_hmac_drbg_sha256_reseed_from_module, oxi_hmac_drbg_sha384_free,
    oxi_hmac_drbg_sha384_generate, oxi_hmac_drbg_sha384_instantiate_from_module,
    oxi_hmac_drbg_sha384_new, oxi_hmac_drbg_sha384_reseed_from_module, oxi_hmac_drbg_sha512_free,
    oxi_hmac_drbg_sha512_generate, oxi_hmac_drbg_sha512_instantiate_from_module,
    oxi_hmac_drbg_sha512_new, oxi_hmac_drbg_sha512_reseed_from_module,
};
pub use error::OxiResult;
pub use rbg::{
    OxiDrbg, oxi_ctr_drbg_aes128_new_rbg, oxi_ctr_drbg_aes192_new_rbg, oxi_ctr_drbg_aes256_new_rbg,
    oxi_drbg_free, oxi_drbg_generate, oxi_drbg_instantiate, oxi_drbg_reseed,
    oxi_drbg_strength_bits, oxi_entropy_on_demand_test, oxi_hash_drbg_sha256_new_rbg,
    oxi_hash_drbg_sha384_new_rbg, oxi_hash_drbg_sha512_new_rbg, oxi_hmac_drbg_sha256_new_rbg,
    oxi_hmac_drbg_sha384_new_rbg, oxi_hmac_drbg_sha512_new_rbg,
};
#[cfg(feature = "fault-injection")]
pub use test_api::{
    oxi_test_corrupt_next_dk_ml_kem, oxi_test_corrupt_next_key, oxi_test_corrupt_next_pk_ecdh,
    oxi_test_corrupt_next_pk_ecdsa, oxi_test_corrupt_next_pk_ml_dsa, oxi_test_corrupt_next_pk_rsa,
    oxi_test_fail_next_alloc, oxi_test_fail_next_on_demand, oxi_test_hold_busy, oxi_test_is_parked,
    oxi_test_last_freed_bytes_zero, oxi_test_park_before_output, oxi_test_poison_entropy,
    oxi_test_release_parked, oxi_test_set_seed_stream,
};

use crate::error::{OxiResult as R, status_kdf, status_module};
use crate::handle::OxiHandle;
use crate::rbg::{DrbgKind, write_out};
use core::ffi::c_int;
#[cfg(test)]
use kat_tests::initialize_with_profile;
#[cfg(not(test))]
use oxicrypt_module::initialize_with_profile;

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
    // A slice cannot span more than `isize::MAX` bytes; refusing the length
    // here keeps `from_raw_parts` within its contract for every caller.
    if len > isize::MAX.unsigned_abs() {
        return Err(R::InvalidInput as c_int);
    }
    if len == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// One byte over the longest HKDF-Expand output with a 32-byte hash,
/// 255 blocks (RFC 5869 §2.3).
const STAGE_CAP_SHA256: usize = 255 * 32 + 1;
/// One byte over the longest HKDF-Expand output with a 48-byte hash.
const STAGE_CAP_SHA384: usize = 255 * 48 + 1;
/// One byte over the longest HKDF-Expand output with a 64-byte hash.
const STAGE_CAP_SHA512: usize = 255 * 64 + 1;

/// Overwrites the caller's `len` bytes at `out` with zeros. A function that
/// fails calls it on a caller buffer, so no partial or earlier result
/// survives the failure. Zeroing writes no output, so it does not go
/// through [`write_out`]'s re-check and runs in every module state.
///
/// # Safety
///
/// `out` must be valid for writes of `len` bytes. It may be NULL only when
/// `len` is 0.
unsafe fn zero_out(out: *mut u8, len: usize) {
    if len > 0 && !out.is_null() {
        // SAFETY: `out` is non-NULL and valid for writes of `len` bytes by
        // contract.
        unsafe { core::ptr::write_bytes(out, 0, len) };
    }
}

/// Runs `fill` on a module-owned buffer of `len` bytes, then writes the
/// buffer to the caller's `out` through [`write_out`] and wipes it.
///
/// `fill` returns a status code, and any code but `Ok` is returned
/// unchanged. `cap` is one byte over the longest output `fill` serves, so a
/// `len` of `cap` or more is a request refused for its length: it is staged
/// at `cap` bytes, `fill` refuses the staged request with the code it
/// returns for the full one without the full length being allocated, and
/// nothing is written to `out`. A shorter request that fails, in `fill` or
/// in the write, leaves `out` zeroized for `len` bytes.
///
/// # Safety
///
/// `out` must be valid for writes of `len` bytes. It may be NULL only when
/// `len` is 0.
unsafe fn staged_output(
    out: *mut u8,
    len: usize,
    cap: usize,
    fill: impl FnOnce(&mut [u8]) -> c_int,
) -> c_int {
    let mut buf = vec![0u8; len.min(cap)];
    let mut code = fill(&mut buf);
    if code == R::Ok as c_int {
        code = if buf.len() == len {
            // SAFETY: `out` is valid for writes of `len` bytes by contract,
            // `buf` holds `len` bytes, and `buf` is this function's own
            // allocation, so the two do not overlap.
            match unsafe { write_out(out, &buf) } {
                Ok(()) => R::Ok as c_int,
                Err(e) => e as c_int,
            }
        } else {
            R::Internal as c_int
        };
    }
    oxicrypt_zeroize::zeroize(&mut buf);
    if code != R::Ok as c_int && len < cap {
        // SAFETY: `out` is valid for writes of `len` bytes, or `len` is 0,
        // by contract.
        unsafe { zero_out(out, len) };
    }
    code
}

// ── Module lifecycle ─────────────────────────────────────────────

/// The integrity self-test and the algorithm self-tests [`oxi_init`] passes
/// to `initialize_with_profile`, in that order.
///
/// The algorithm self-tests are the `KATS` of every approved algorithm crate
/// this library links, 18 crates, listed in `power_up.rs`. `kat_tests` reads
/// the library's resolved dependency graph and fails if a linked algorithm
/// crate is missing, and checks that `oxi_init` passes exactly this pair.
///
/// The integrity self-test (`oxicrypt_integrity::KATS`) is the required
/// integrity argument to `initialize_with_profile`. `oxicrypt_integrity`
/// verifies the artifact that contains it — it locates its slot by that
/// slot's own runtime address, so a cdylib verifies itself rather than
/// its host.
///
/// The integrity slot ships in the cdylib and staticlib (forced via
/// the `_SLOT_REF` static below) and the shared library is sign-able
/// with `oxicrypt-integrity-sign --cdylib-target …`.
fn power_up_set() -> (
    &'static [oxicrypt_module::KatEntry],
    Vec<oxicrypt_module::KatEntry>,
) {
    (oxicrypt_integrity::KATS, power_up::algorithm_self_tests())
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

/// Return the ABI number of this C interface.
///
/// The number is independent of the release version. It changes only when
/// the interface breaks compatibility (a function removed, a parameter or
/// return type changed, or an output size changed) and never when functions
/// are added. Compatibility within a number runs one way: a library returning
/// N serves a caller built against an earlier release of ABI N, but a caller
/// that uses a function added later in ABI N cannot load an older library of
/// the same number, which lacks it. The library's `SONAME` on Linux
/// (`liboxicrypt_ffi.so.<N>`) and its macOS install name follow the number;
/// Android keeps the plain `liboxicrypt_ffi.so`.
///
/// A query about the interface, not a service: it requires no
/// initialisation and is callable before [`oxi_init`] and in any module
/// state. A library that predates this function does not export it.
///
/// # Safety
///
/// No pointers; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_abi_version() -> c_int {
    OXI_ABI_VERSION
}

/// Initialise the FIPS module with the given algorithm profile,
/// running all power-up KATs.
///
/// `profile` selects the algorithm-restriction level:
///
/// - `0` — Unrestricted (all approved algorithms available)
/// - `1` — CNSA 2.0 (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87,
///   LMS, XMSS)
/// - `2` — CNSA 1.0 (AES-256, SHA-384, P-384, RSA ≥ 3072, DH ≥ 3072)
/// - `3` — Migration (both suites at once; not a CNSA profile)
///
/// Any other value returns [`OxiResult::InvalidInput`] without
/// performing initialisation, rather than silently defaulting an unknown
/// code to a profile.
///
/// Initialisation happens once per process, and **the first init's
/// outcome is authoritative**. A later call runs no self-test and
/// returns that outcome: [`OxiResult::Ok`] if the first call succeeded,
/// and [`OxiResult::NotOperational`] if it failed, because a failed
/// initialisation is terminal until the process restarts. The active
/// profile is the one the first successful call selected; a later call
/// passing a *different* profile selector is accepted and the
/// *original* profile remains active. Callers that need to verify which
/// profile is in effect must call [`oxi_active_profile`] after
/// `oxi_init` returns.
///
/// Must be called before any other `oxi_*` function.
/// Returns `0` on success or a non-zero `OxiResult` discriminant.
///
/// # Safety
///
/// No pointers; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_init(profile: c_int) -> c_int {
    // A library built for fault-injection testing arms the seams named in
    // `OXI_FAULT`; a value it cannot arm is ignored.
    #[cfg(feature = "fault-injection")]
    let _ = oxicrypt_drbg::seam::arm_from_env(std::env::var("OXI_FAULT").ok().as_deref());
    let p = match profile {
        0 => oxicrypt_module::AlgorithmProfile::Unrestricted,
        1 => oxicrypt_module::AlgorithmProfile::Cnsa2,
        2 => oxicrypt_module::AlgorithmProfile::Cnsa1,
        3 => oxicrypt_module::AlgorithmProfile::Migration,
        _ => return R::InvalidInput as c_int,
    };
    // A second call on an operational module returns before
    // `power_up_set` allocates a list `initialize_with_profile` would
    // discard.
    if oxicrypt_module::is_operational() {
        return R::Ok as c_int;
    }
    let (integrity, tests) = power_up_set();
    match initialize_with_profile(integrity, &tests, p) {
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
/// - `3` — Migration (CNSA 1.0 + CNSA 2.0)
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
        oxicrypt_module::AlgorithmProfile::Migration => 3,
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
/// | 1 | `Passed` — the signature over the image verified |
/// | 2 | `SignatureInvalid` — the image does not match its signature |
/// | 3 | `SlotInvalid` — the slot is the unsigned template, as in an unsigned build or a signed one whose slot was overwritten; not on its own a reason to sign (see the remedies below) |
/// | 4 | `Unreadable` — the test was **not performed**; do not sign, and obtain a fresh copy if it persists |
/// | 5 | `CastNotRun` — the test was reached before its CASTs passed |
/// | 6 | `Unknown` — the record held a value this module never writes |
/// | 7 | `Refused` — the module refused a primitive, so the test was **not performed** |
/// | 8 | `NoVerifyKey` — the library carries no verifying key, as in a key-less build or a signed one whose key was zeroed; as for 3 |
/// | 9 | `KeyMismatch` — the slot was signed for a different key than the library embeds |
/// | 10 | `SlotDamaged` — the slot, the key record or a bound import is damaged; do not re-sign |
///
/// Remedies: no value is on its own a reason to sign the library. If you
/// built it from source yourself and have not signed it yet, sign it with
/// your own key; if you received it from anyone else, do not sign it and
/// obtain a fresh copy from its publisher. For 2, 9 and 10, never sign it
/// again.
///
/// This exists because `oxi_init` cannot carry the distinction: a
/// failing self-test returns [`OxiResult::SelfTestFailed`] whatever the
/// cause, so `SignatureInvalid` and `Unreadable` are indistinguishable from
/// its return value alone. An operator and a test laboratory must be able
/// to tell those apart — a corrupt module from
/// one signed for another key, one built without a key, and an environment
/// that could not supply the module's own bytes — and this query is how
/// that is retrieved.
///
/// The value latches on the first run and nothing is re-run here, so a
/// later call cannot revise it and this is safe to call from the error
/// state.
///
/// # Safety
///
/// No pointers; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_integrity_status() -> c_int {
    oxicrypt_integrity::status() as c_int
}

/// Writes the fingerprint of the verifying key this library embeds: the
/// SHA-256 of the encoded ML-DSA-87 public key, 32 bytes, to `out`.
///
/// The fingerprint names the signer this build trusts: a project release
/// embeds the project key, a source build the builder's own. It is recorded
/// when the integrity test reads the key, so it is available after
/// [`oxi_init`] whether or not the test passed, and it equals the
/// fingerprint `oxicrypt-integrity-sign --show` prints for the file.
///
/// Returns:
/// - [`OxiResult::Ok`] — the fingerprint was written to `out[0..32]`.
/// - [`OxiResult::NullPointer`] — `out` is null.
/// - [`OxiResult::BufferTooSmall`] — `out_len` is less than 32. Nothing is
///   written.
/// - [`OxiResult::NotOperational`] — no fingerprint is known, and nothing
///   is written. The integrity test has not read a key: `oxi_init` has not
///   run it, its CAST failed first, the key record could not be read or
///   is malformed, or the library embeds no key. `oxi_integrity_status`
///   tells these apart (`NotRun`, `CastNotRun`, `Unreadable`,
///   `SlotDamaged`, `NoVerifyKey`).
///
/// # Safety
///
/// `out` must be valid for writes of `out_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_integrity_key_fingerprint(out: *mut u8, out_len: usize) -> c_int {
    if out.is_null() {
        return R::NullPointer as c_int;
    }
    if out_len < 32 {
        return R::BufferTooSmall as c_int;
    }
    match oxicrypt_integrity::verify_key_fingerprint() {
        Some(fp) => {
            // SAFETY: `out` is non-null and the caller guarantees it is valid
            // for `out_len` >= 32 bytes; `fp` is a local 32-byte array.
            unsafe { core::ptr::copy_nonoverlapping(fp.as_ptr(), out, fp.len()) };
            R::Ok as c_int
        }
        None => R::NotOperational as c_int,
    }
}

/// Writes the integrity test's failure in words, NUL-terminated UTF-8, to
/// `out`: the cause the status value cannot carry, such as which slot
/// defect, which memory route's error, or which lengths disagreed.
///
/// `*written` always receives the number of bytes the text needs including
/// its NUL, or 0 when there is none, so a caller can pass `out_len` 0 to
/// size the buffer first.
///
/// Returns:
/// - [`OxiResult::Ok`] — the text and its NUL were written.
/// - [`OxiResult::NullPointer`] — `written` is null, or `out` is null with a
///   non-zero `out_len`; in the second case `*written` still receives the
///   size.
/// - [`OxiResult::BufferTooSmall`] — `out_len` is less than `*written`.
///   Nothing is written to `out`.
/// - [`OxiResult::NotOperational`] — the boot sequence's integrity test has
///   not failed in this process, so there is no text; `*written` is 0.
///
/// # Safety
///
/// `out` must be valid for writes of `out_len` bytes and `written` for one
/// `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_integrity_status_detail(
    out: *mut u8,
    out_len: usize,
    written: *mut usize,
) -> c_int {
    if written.is_null() {
        return R::NullPointer as c_int;
    }
    let Some(detail) = oxicrypt_integrity::status_detail() else {
        // SAFETY: `written` is non-null and valid for one `usize`.
        unsafe { written.write(0) };
        return R::NotOperational as c_int;
    };
    let needed = detail.len().saturating_add(1);
    // SAFETY: as above. Written before any other refusal, so a caller
    // always learns the size it needs.
    unsafe { written.write(needed) };
    if out.is_null() && out_len != 0 {
        return R::NullPointer as c_int;
    }
    if out_len < needed {
        return R::BufferTooSmall as c_int;
    }
    // SAFETY: `out` is non-null (out_len >= needed > 0) and valid for
    // `out_len` >= `needed` bytes; the text and its NUL fit.
    unsafe {
        core::ptr::copy_nonoverlapping(detail.as_ptr(), out, detail.len());
        out.add(detail.len()).write(0);
    }
    R::Ok as c_int
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
            // SAFETY: `out` is valid for writes of 32 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..32]) } {
                return e as c_int;
            }
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
            // SAFETY: `out` is valid for writes of 64 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..64]) } {
                return e as c_int;
            }
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
            // SAFETY: `out` is valid for writes of 28 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..28]) } {
                return e as c_int;
            }
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
            // SAFETY: `out` is valid for writes of 48 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..48]) } {
                return e as c_int;
            }
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-512/224 (FIPS 180-4 §6.6, IV §5.3.6.1) ───────────────────

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
            // SAFETY: `out` is valid for writes of 28 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..28]) } {
                return e as c_int;
            }
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-512/256 (FIPS 180-4 §6.7, IV §5.3.6.2) ───────────────────

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
            // SAFETY: `out` is valid for writes of 32 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..32]) } {
                return e as c_int;
            }
            R::Ok as c_int
        }
        Err(e) => status_module(Err(e)),
    }
}

// ── SHA-3 (FIPS 202) ─────────────────────────────────────────────

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
            // SAFETY: `out` is valid for writes of 28 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..28]) } {
                return e as c_int;
            }
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
            // SAFETY: `out` is valid for writes of 32 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..32]) } {
                return e as c_int;
            }
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
            // SAFETY: `out` is valid for writes of 48 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..48]) } {
                return e as c_int;
            }
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
            // SAFETY: `out` is valid for writes of 64 bytes by contract,
            // and the local `digest` does not overlap it.
            if let Err(e) = unsafe { write_out(out, &digest[..64]) } {
                return e as c_int;
            }
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
    let tag = match mac.finalize() {
        Ok(t) => t,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `out` is valid for writes of 32 bytes by contract,
    // and the local `tag` does not overlap it.
    if let Err(e) = unsafe { write_out(out, &tag[..32]) } {
        return e as c_int;
    }
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
    let tag = match mac.finalize() {
        Ok(t) => t,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `out` is valid for writes of 48 bytes by contract,
    // and the local `tag` does not overlap it.
    if let Err(e) = unsafe { write_out(out, &tag[..48]) } {
        return e as c_int;
    }
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
    let tag = match mac.finalize() {
        Ok(t) => t,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `out` is valid for writes of 64 bytes by contract,
    // and the local `tag` does not overlap it.
    if let Err(e) = unsafe { write_out(out, &tag[..64]) } {
        return e as c_int;
    }
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
    let tag = match mac.finalize() {
        Ok(t) => t,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `out` is valid for writes of 28 bytes by contract,
    // and the local `tag` does not overlap it.
    if let Err(e) = unsafe { write_out(out, &tag[..28]) } {
        return e as c_int;
    }
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
    let tag = match mac.finalize() {
        Ok(t) => t,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `out` is valid for writes of 32 bytes by contract,
    // and the local `tag` does not overlap it.
    if let Err(e) = unsafe { write_out(out, &tag[..32]) } {
        return e as c_int;
    }
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
    let tag = match mac.finalize() {
        Ok(t) => t,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `out` is valid for writes of 48 bytes by contract,
    // and the local `tag` does not overlap it.
    if let Err(e) = unsafe { write_out(out, &tag[..48]) } {
        return e as c_int;
    }
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
    let tag = match mac.finalize() {
        Ok(t) => t,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `out` is valid for writes of 64 bytes by contract,
    // and the local `tag` does not overlap it.
    if let Err(e) = unsafe { write_out(out, &tag[..64]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

// ── ECDSA (FIPS 186-5) ───────────────────────────────────────────

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
    // SAFETY: `public_key_out` is valid for writes of 65 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(public_key_out, &pk[..65]) } {
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 64 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..64]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Verify an ECDSA P-256 signature over `msg` against the public key
/// `pk` (FIPS 186-5 §6.4.2).
///
/// `public_key_ptr` must point to exactly 65 bytes (uncompressed SEC1)
/// and `sig_ptr` to exactly 64 bytes (`r || s`).
///
/// Returns `OxiResult::Ok = 0` for valid, `OxiResult::TagMismatch = 22`
/// for a well-formed signature that does not verify, or a module error
/// variant.
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
    // SAFETY: `public_key_out` is valid for writes of 97 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(public_key_out, &pk[..97]) } {
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 96 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..96]) } {
        return e as c_int;
    }
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
// The PRK is the whole HKDF state between extract and expand
// (RFC 5869 §2), so it crosses the interface as bytes, not a handle.

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
    let prk = match hk.prk() {
        Ok(p) => p,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `prk_out` is valid for writes of 32 bytes by contract,
    // and the local `prk` does not overlap it.
    if let Err(e) = unsafe { write_out(prk_out, &prk[..32]) } {
        return e as c_int;
    }
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
    if okm_out.is_null() && okm_len > 0 {
        return R::NullPointer as c_int;
    }
    let hk = match oxicrypt_kdf::HkdfSha256::from_prk(prk) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `okm_out` is valid for writes of `okm_len` bytes by contract
    // and is non-NULL unless `okm_len` is 0.
    unsafe {
        staged_output(okm_out, okm_len, STAGE_CAP_SHA256, |okm| {
            status_kdf(hk.expand(info, okm))
        })
    }
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
    let prk = match hk.prk() {
        Ok(p) => p,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `prk_out` is valid for writes of 48 bytes by contract,
    // and the local `prk` does not overlap it.
    if let Err(e) = unsafe { write_out(prk_out, &prk[..48]) } {
        return e as c_int;
    }
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
    if okm_out.is_null() && okm_len > 0 {
        return R::NullPointer as c_int;
    }
    let hk = match oxicrypt_kdf::HkdfSha384::from_prk(prk) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `okm_out` is valid for writes of `okm_len` bytes by contract
    // and is non-NULL unless `okm_len` is 0.
    unsafe {
        staged_output(okm_out, okm_len, STAGE_CAP_SHA384, |okm| {
            status_kdf(hk.expand(info, okm))
        })
    }
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
    let prk = match hk.prk() {
        Ok(p) => p,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `prk_out` is valid for writes of 64 bytes by contract,
    // and the local `prk` does not overlap it.
    if let Err(e) = unsafe { write_out(prk_out, &prk[..64]) } {
        return e as c_int;
    }
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
    if okm_out.is_null() && okm_len > 0 {
        return R::NullPointer as c_int;
    }
    let hk = match oxicrypt_kdf::HkdfSha512::from_prk(prk) {
        Ok(h) => h,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `okm_out` is valid for writes of `okm_len` bytes by contract
    // and is non-NULL unless `okm_len` is 0.
    unsafe {
        staged_output(okm_out, okm_len, STAGE_CAP_SHA512, |okm| {
            status_kdf(hk.expand(info, okm))
        })
    }
}

// ── TLS 1.3 KDF (RFC 8446 §7.1) ──────────────────────────────────
//
// SHA-256 and SHA-384 only: no TLS 1.3 cipher suite of RFC 8446 §B.4
// uses SHA-512.

// ── TLS 1.3 HKDF-Expand-Label ────────────────────────────────────

/// Run HKDF-Expand-Label per RFC 8446 §7.1 with HMAC-SHA-256.
///
/// Builds the HkdfLabel wire structure
/// `length || "tls13 " + label || context` and runs HKDF-Expand
/// (RFC 5869 §2.3) to fill `out` with `out_len` bytes.
///
/// Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
/// hash blocks, if the label is empty or longer than 249 bytes, or if the
/// context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
/// 255 hash blocks is refused for its length and writes nothing to `out`.
/// Otherwise a failure once the derivation has started, a refused label or
/// context or a refused write, leaves `out` zeroized for `out_len` bytes.
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
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    // SAFETY: `out` is valid for writes of `out_len` bytes by contract and
    // is non-NULL unless `out_len` is 0.
    unsafe {
        staged_output(out, out_len, STAGE_CAP_SHA256, |okm| {
            status_module(oxicrypt_tls_kdf::tls13_hkdf_expand_label::<
                oxicrypt_hmac::HmacSha256,
                32,
            >(secret, label, context, okm))
        })
    }
}

/// Run HKDF-Expand-Label per RFC 8446 §7.1 with HMAC-SHA-384.
///
/// Builds the HkdfLabel wire structure
/// `length || "tls13 " + label || context` and runs HKDF-Expand
/// (RFC 5869 §2.3) to fill `out` with `out_len` bytes.
///
/// Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
/// hash blocks, if the label is empty or longer than 249 bytes, or if the
/// context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
/// 255 hash blocks is refused for its length and writes nothing to `out`.
/// Otherwise a failure once the derivation has started, a refused label or
/// context or a refused write, leaves `out` zeroized for `out_len` bytes.
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
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    // SAFETY: `out` is valid for writes of `out_len` bytes by contract and
    // is non-NULL unless `out_len` is 0.
    unsafe {
        staged_output(out, out_len, STAGE_CAP_SHA384, |okm| {
            status_module(oxicrypt_tls_kdf::tls13_hkdf_expand_label::<
                oxicrypt_hmac::HmacSha384,
                48,
            >(secret, label, context, okm))
        })
    }
}

// ── TLS 1.3 Derive-Secret ────────────────────────────────────────

/// Run Derive-Secret per RFC 8446 §7.1 with HMAC-SHA-256.
///
/// Equivalent to `HKDF-Expand-Label(secret, label, transcript_hash,
/// out_len)`. The caller computes `Hash(messages)` (the running
/// transcript hash) and passes it as `transcript_hash`.
///
/// Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
/// hash blocks, if the label is empty or longer than 249 bytes, or if the
/// context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
/// 255 hash blocks is refused for its length and writes nothing to `out`.
/// Otherwise a failure once the derivation has started, a refused label or
/// context or a refused write, leaves `out` zeroized for `out_len` bytes.
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
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    // SAFETY: `out` is valid for writes of `out_len` bytes by contract and
    // is non-NULL unless `out_len` is 0.
    unsafe {
        staged_output(out, out_len, STAGE_CAP_SHA256, |okm| {
            status_module(oxicrypt_tls_kdf::tls13_derive_secret::<
                oxicrypt_hmac::HmacSha256,
                32,
            >(secret, label, transcript_hash, okm))
        })
    }
}

/// Run Derive-Secret per RFC 8446 §7.1 with HMAC-SHA-384.
///
/// Equivalent to `HKDF-Expand-Label(secret, label, transcript_hash,
/// out_len)`. The caller computes `Hash(messages)` (the running
/// transcript hash) and passes it as `transcript_hash`.
///
/// Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
/// hash blocks, if the label is empty or longer than 249 bytes, or if the
/// context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
/// 255 hash blocks is refused for its length and writes nothing to `out`.
/// Otherwise a failure once the derivation has started, a refused label or
/// context or a refused write, leaves `out` zeroized for `out_len` bytes.
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
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    // SAFETY: `out` is valid for writes of `out_len` bytes by contract and
    // is non-NULL unless `out_len` is 0.
    unsafe {
        staged_output(out, out_len, STAGE_CAP_SHA384, |okm| {
            status_module(oxicrypt_tls_kdf::tls13_derive_secret::<
                oxicrypt_hmac::HmacSha384,
                48,
            >(secret, label, transcript_hash, okm))
        })
    }
}

// ── EdDSA Ed25519 (RFC 8032, FIPS 186-5 §7.8) ────────────────────

/// Derive the Ed25519 public key from a 32-byte seed (RFC 8032 §5.1.5).
///
/// Reads exactly 32 bytes from `seed_ptr`. Writes the 32-byte
/// compressed-Edwards-point public key into `public_key_out`. The same
/// seed gives the same public key; nothing is drawn. Returns
/// `AlgorithmRestricted = 6` when the active profile does not admit
/// Ed25519 key generation.
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
    // SAFETY: `public_key_out` is valid for writes of 32 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(public_key_out, &pk[..32]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Sign `msg` with Ed25519 using the 32-byte seed (RFC 8032 §5.1.6).
///
/// Reads exactly 32 bytes from `seed_ptr`. Writes 64 bytes
/// (`R(32) || S(32)`) into `sig_out`. Signing is deterministic: the
/// nonce is derived from the secret and the message (RFC 8032 §5.1.6), so
/// the same `(seed, msg)` gives the same signature.
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
    // SAFETY: `sig_out` is valid for writes of 64 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..64]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Verify an Ed25519 signature over `msg` (RFC 8032 §5.1.7).
///
/// Reads exactly 32 bytes from `public_key_ptr` and exactly 64 bytes
/// from `sig_ptr`. Returns `OxiResult::Ok = 0` for valid,
/// `OxiResult::TagMismatch = 22` for a well-formed signature that does
/// not verify, or a module error variant.
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
    // SAFETY: `shared_secret_out` is valid for writes of 32 bytes by
    // contract, and the local `z` does not overlap it.
    if let Err(e) = unsafe { write_out(shared_secret_out, &z[..32]) } {
        return e as c_int;
    }
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
    // SAFETY: `shared_secret_out` is valid for writes of 48 bytes by
    // contract, and the local `z` does not overlap it.
    if let Err(e) = unsafe { write_out(shared_secret_out, &z[..48]) } {
        return e as c_int;
    }
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
/// of `Q = d · G`) into `public_out`. Callers must serialise concurrent
/// calls on the same `drbg`.
///
/// Returns `Ok = 0` on success, otherwise, in this order:
/// `NullPointer = 10` if any pointer is NULL; `InvalidInput = 5` for a
/// DRBG handle instantiated by another process and `Uninstantiated = 8`
/// for one never instantiated, both checked before the module state;
/// `NotOperational = 1` if the module is not operational;
/// `AlgorithmRestricted = 6` if the active profile does not admit ECDH
/// P-256 key generation; the DRBG's codes when it produces no output;
/// `InvalidInput = 5` when scalar sampling exhausts its retries; and
/// `ConditionalTestFailed = 3` when the pairwise consistency test fails,
/// after which the module is in its error state and every later call
/// returns `NotOperational = 1`. On a failure nothing is written, except
/// that a refused second copy zeroes the private key already copied.
///
/// # Safety
///
/// `drbg` must be a live, instantiated handle from
/// [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`]. `private_out` must be a
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let (d, q) = match oxicrypt_ecdh::generate_keypair_p256(drbg_ref) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `private_out` is valid for writes of 32 bytes by contract,
    // and the local `d` does not overlap it.
    if let Err(e) = unsafe { write_out(private_out, &d[..32]) } {
        return e as c_int;
    }
    // SAFETY: `public_out` is valid for writes of 65 bytes by contract,
    // and the local `q` does not overlap it.
    if let Err(e) = unsafe { write_out(public_out, &q[..65]) } {
        // SAFETY: `private_out` is valid for writes of 32 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(private_out, 32) };
        return e as c_int;
    }
    R::Ok as c_int
}

// ── ECDH P-384 — DRBG-driven keypair generation ──────────────────

/// Generate a fresh ECDH P-384 key pair via the FIPS 186-5 §A.2.2
/// rejection sampler driven by `drbg`, run the IG 10.3.A pairwise
/// consistency test, and write the private/public key bytes to the
/// caller-provided buffers.
///
/// As [`oxi_ecdh_p256_generate_keypair`] for P-384: a 48-byte private
/// scalar and a 97-byte SEC1 uncompressed public key, with the same codes
/// in the same order, `ConditionalTestFailed = 3` and then
/// `NotOperational = 1` on every later call included, and the same
/// serialisation requirement.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let (d, q) = match oxicrypt_ecdh::generate_keypair_p384(drbg_ref) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `private_out` is valid for writes of 48 bytes by contract,
    // and the local `d` does not overlap it.
    if let Err(e) = unsafe { write_out(private_out, &d[..48]) } {
        return e as c_int;
    }
    // SAFETY: `public_out` is valid for writes of 97 bytes by contract,
    // and the local `q` does not overlap it.
    if let Err(e) = unsafe { write_out(public_out, &q[..97]) } {
        // SAFETY: `private_out` is valid for writes of 48 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(private_out, 48) };
        return e as c_int;
    }
    R::Ok as c_int
}

// ── DH-3072 (RFC 3526 Group 15, SP 800-56Ar3 §5.7.1.1) ───────────

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
/// keying material — same discipline as ECDH.
///
/// Peer public key undergoes SP 800-56Ar3 §5.6.2.3.2 partial
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
    // SAFETY: `shared_secret_out` is valid for writes of 384 bytes by
    // contract, and the local `z` does not overlap it.
    if let Err(e) = unsafe { write_out(shared_secret_out, &z[..384]) } {
        return e as c_int;
    }
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
/// The caller is responsible for: (a) allocating the handle via
/// [`oxi_hmac_drbg_sha256_new`]; (b) having the handle instantiated
/// with [`oxi_hmac_drbg_sha256_instantiate_from_module`], which seeds
/// it from the module's seed path, before this call; (c) freeing it via
/// [`oxi_hmac_drbg_sha256_free`] after use; and (d) serializing all
/// calls on the same handle pointer per the per-call-mutating-handle
/// thread-safety contract.
///
/// Returns `OxiResult::Ok = 0` on success;
/// `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated with `_instantiate_from_module`;
/// `OxiResult::InvalidInput = 5` if the handle was instantiated by
/// another process, or the DRBG exhausts its rejection-sampling
/// attempts or fails to produce output;
/// `OxiResult::NotOperational = 1` if the FIPS module is not
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let (x, y) = match oxicrypt_dh::generate_keypair_3072(drbg_ref) {
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `private_out` is valid for writes of 384 bytes by contract,
    // and the local `x` does not overlap it.
    if let Err(e) = unsafe { write_out(private_out, &x[..384]) } {
        return e as c_int;
    }
    // SAFETY: `public_out` is valid for writes of 384 bytes by contract,
    // and the local `y` does not overlap it.
    if let Err(e) = unsafe { write_out(public_out, &y[..384]) } {
        // SAFETY: `private_out` is valid for writes of 384 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(private_out, 384) };
        return e as c_int;
    }
    R::Ok as c_int
}

// ── RSA verify (FIPS 186-5 §5.4, RFC 8017 §8) ────────────────────

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
/// (an invalid modulus or a malformed signature included), or a
/// module error variant on `NotOperational` / `AlgorithmRestricted`.
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
/// `TagMismatch = 22` on any verification failure (a malformed input
/// included), or a module error variant.
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

// ── ML-DSA-87 (FIPS 204) ─────────────────────────────────────────

/// ML-DSA-87 key generation (FIPS 204 Algorithm 1): draws the seed ξ from
/// the caller's DRBG handle, expands the key pair and runs the pairwise
/// consistency test on it (FIPS 140-3 IG 10.3.A) before anything is
/// written.
///
/// Buffers: `pk_out`, 2592 writable bytes; `sk_out`, 4896 writable bytes;
/// `seed_out`, 32 writable bytes or NULL. With `seed_out` NULL the module
/// wipes ξ and returns only the pair. Otherwise ξ is written to
/// `seed_out`, and [`oxi_ml_dsa_87_expand_key`] reproduces the pair from
/// it; ξ computes the secret key and needs the same protection (FIPS 204
/// §3.6.3).
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when `rbg`,
///   `pk_out` or `sk_out` is NULL, `InvalidInput = 5` when a range runs
///   past the top of the address space.
/// - `InvalidInput = 5`: an output shares a byte with another output or
///   with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit ML-DSA-87
///   key generation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `RbgTooWeak = 31`: the DRBG's security strength is below 256 bits;
///   nothing is drawn.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for writes of its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_87_keygen_rbg(
    rbg: *mut OxiDrbg,
    pk_out: *mut u8,
    sk_out: *mut u8,
    seed_out: *mut u8,
) -> c_int {
    use oxicrypt_ml_dsa::ml_dsa_87 as set;
    // SAFETY: every pointer meets `keygen_rbg`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::keygen_rbg(
            rbg,
            pk_out,
            sk_out,
            seed_out,
            oxicrypt_module::Service::MlDsa87Keygen,
            set::keygen::<DrbgKind>,
            set::keygen_with_seed::<DrbgKind>,
        )
    })
}

/// ML-DSA-87 key expansion from a stored seed ξ (FIPS 204 Algorithm 6),
/// with the pairwise consistency test run on the pair before anything is
/// written (FIPS 140-3 IG 10.3.A). A seed that did not come from
/// [`oxi_ml_dsa_87_keygen_rbg`] is a private key imported into the module.
///
/// Buffers: `seed_ptr`, 32 bytes; `pk_out`, 2592 writable bytes; `sk_out`,
/// 4896 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with the seed or with the
///   other output.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit ML-DSA-87
///   key expansion.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success, as for
/// [`oxi_ml_dsa_87_keygen_rbg`].
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_87_expand_key(
    seed_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `expand_key`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::expand_key::<32, 0, _, _>(
            seed_ptr,
            core::ptr::null(),
            pk_out,
            sk_out,
            oxicrypt_module::Service::MlDsa87ExpandKey,
            |xi, _| oxicrypt_ml_dsa::ml_dsa_87::expand_key(xi),
        )
    })
}

/// Sign a message with ML-DSA-87 (FIPS 204 §5.2 Algorithm 2).
///
/// Reads exactly 4896 bytes from `sk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
/// 4627-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
/// `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.
///
/// Signing is the deterministic variant (FIPS 204 §3.4): the same
/// `(sk, msg, ctx)` gives the same signature on every call. The hedged
/// variant is a planned addition.
///
/// Returns `Ok = 0` on success, `NullPointer = 10` for a NULL `sk_ptr` or
/// `sig_out` or a NULL pointer with a non-zero length, `NotOperational = 1`
/// when the module is not operational, `AlgorithmRestricted = 6` when the
/// active profile does not admit the parameter set's signing, and
/// `InvalidInput = 5` when `ctx_len` exceeds 255 (FIPS 204 §5.2) or the
/// signing loop reaches its iteration bound.
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
    // SAFETY: `sig_out` is valid for writes of 4627 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..4627]) } {
        return e as c_int;
    }
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
/// (a malformed signature included), `NullPointer = 10` for a NULL
/// pointer, `NotOperational = 1` when the module is not operational, or
/// `AlgorithmRestricted = 6` when the active profile does not admit the
/// parameter set's verification.
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

// ── ML-DSA-44 (FIPS 204) ─────────────────────────────────────────

/// ML-DSA-44 key generation (FIPS 204 Algorithm 1): draws the seed ξ from
/// the caller's DRBG handle, expands the key pair and runs the pairwise
/// consistency test on it (FIPS 140-3 IG 10.3.A) before anything is
/// written.
///
/// Buffers: `pk_out`, 1312 writable bytes; `sk_out`, 2560 writable bytes;
/// `seed_out`, 32 writable bytes or NULL. With `seed_out` NULL the module
/// wipes ξ and returns only the pair. Otherwise ξ is written to
/// `seed_out`, and [`oxi_ml_dsa_44_expand_key`] reproduces the pair from
/// it; ξ computes the secret key and needs the same protection (FIPS 204
/// §3.6.3).
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when `rbg`,
///   `pk_out` or `sk_out` is NULL, `InvalidInput = 5` when a range runs
///   past the top of the address space.
/// - `InvalidInput = 5`: an output shares a byte with another output or
///   with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit ML-DSA-44
///   key generation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `RbgTooWeak = 31`: the DRBG's security strength is below 192 bits;
///   nothing is drawn.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for writes of its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_44_keygen_rbg(
    rbg: *mut OxiDrbg,
    pk_out: *mut u8,
    sk_out: *mut u8,
    seed_out: *mut u8,
) -> c_int {
    use oxicrypt_ml_dsa::ml_dsa_44 as set;
    // SAFETY: every pointer meets `keygen_rbg`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::keygen_rbg(
            rbg,
            pk_out,
            sk_out,
            seed_out,
            oxicrypt_module::Service::MlDsa44Keygen,
            set::keygen::<DrbgKind>,
            set::keygen_with_seed::<DrbgKind>,
        )
    })
}

/// ML-DSA-44 key expansion from a stored seed ξ (FIPS 204 Algorithm 6),
/// with the pairwise consistency test run on the pair before anything is
/// written (FIPS 140-3 IG 10.3.A). A seed that did not come from
/// [`oxi_ml_dsa_44_keygen_rbg`] is a private key imported into the module.
///
/// Buffers: `seed_ptr`, 32 bytes; `pk_out`, 1312 writable bytes; `sk_out`,
/// 2560 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with the seed or with the
///   other output.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit ML-DSA-44
///   key expansion.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success, as for
/// [`oxi_ml_dsa_44_keygen_rbg`].
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_44_expand_key(
    seed_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `expand_key`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::expand_key::<32, 0, _, _>(
            seed_ptr,
            core::ptr::null(),
            pk_out,
            sk_out,
            oxicrypt_module::Service::MlDsa44ExpandKey,
            |xi, _| oxicrypt_ml_dsa::ml_dsa_44::expand_key(xi),
        )
    })
}

/// Sign a message with ML-DSA-44 (FIPS 204 §5.2 Algorithm 2).
///
/// Reads exactly 2560 bytes from `sk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
/// 2420-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
/// `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.
///
/// Signing is the deterministic variant (FIPS 204 §3.4): the same
/// `(sk, msg, ctx)` gives the same signature on every call. The hedged
/// variant is a planned addition.
///
/// Returns `Ok = 0` on success, `NullPointer = 10` for a NULL `sk_ptr` or
/// `sig_out` or a NULL pointer with a non-zero length, `NotOperational = 1`
/// when the module is not operational, `AlgorithmRestricted = 6` when the
/// active profile does not admit the parameter set's signing, and
/// `InvalidInput = 5` when `ctx_len` exceeds 255 (FIPS 204 §5.2) or the
/// signing loop reaches its iteration bound.
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
    // SAFETY: `sig_out` is valid for writes of 2420 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..2420]) } {
        return e as c_int;
    }
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
/// (a malformed signature included), `NullPointer = 10` for a NULL
/// pointer, `NotOperational = 1` when the module is not operational, or
/// `AlgorithmRestricted = 6` when the active profile does not admit the
/// parameter set's verification.
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

// ── ML-DSA-65 (FIPS 204) ─────────────────────────────────────────

/// ML-DSA-65 key generation (FIPS 204 Algorithm 1): draws the seed ξ from
/// the caller's DRBG handle, expands the key pair and runs the pairwise
/// consistency test on it (FIPS 140-3 IG 10.3.A) before anything is
/// written.
///
/// Buffers: `pk_out`, 1952 writable bytes; `sk_out`, 4032 writable bytes;
/// `seed_out`, 32 writable bytes or NULL. With `seed_out` NULL the module
/// wipes ξ and returns only the pair. Otherwise ξ is written to
/// `seed_out`, and [`oxi_ml_dsa_65_expand_key`] reproduces the pair from
/// it; ξ computes the secret key and needs the same protection (FIPS 204
/// §3.6.3).
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when `rbg`,
///   `pk_out` or `sk_out` is NULL, `InvalidInput = 5` when a range runs
///   past the top of the address space.
/// - `InvalidInput = 5`: an output shares a byte with another output or
///   with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit ML-DSA-65
///   key generation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `RbgTooWeak = 31`: the DRBG's security strength is below 192 bits;
///   nothing is drawn.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for writes of its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_65_keygen_rbg(
    rbg: *mut OxiDrbg,
    pk_out: *mut u8,
    sk_out: *mut u8,
    seed_out: *mut u8,
) -> c_int {
    use oxicrypt_ml_dsa::ml_dsa_65 as set;
    // SAFETY: every pointer meets `keygen_rbg`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::keygen_rbg(
            rbg,
            pk_out,
            sk_out,
            seed_out,
            oxicrypt_module::Service::MlDsa65Keygen,
            set::keygen::<DrbgKind>,
            set::keygen_with_seed::<DrbgKind>,
        )
    })
}

/// ML-DSA-65 key expansion from a stored seed ξ (FIPS 204 Algorithm 6),
/// with the pairwise consistency test run on the pair before anything is
/// written (FIPS 140-3 IG 10.3.A). A seed that did not come from
/// [`oxi_ml_dsa_65_keygen_rbg`] is a private key imported into the module.
///
/// Buffers: `seed_ptr`, 32 bytes; `pk_out`, 1952 writable bytes; `sk_out`,
/// 4032 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with the seed or with the
///   other output.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit ML-DSA-65
///   key expansion.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success, as for
/// [`oxi_ml_dsa_65_keygen_rbg`].
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_dsa_65_expand_key(
    seed_ptr: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `expand_key`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::expand_key::<32, 0, _, _>(
            seed_ptr,
            core::ptr::null(),
            pk_out,
            sk_out,
            oxicrypt_module::Service::MlDsa65ExpandKey,
            |xi, _| oxicrypt_ml_dsa::ml_dsa_65::expand_key(xi),
        )
    })
}

/// Sign a message with ML-DSA-65 (FIPS 204 §5.2 Algorithm 2).
///
/// Reads exactly 4032 bytes from `sk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
/// 3309-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
/// `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.
///
/// Signing is the deterministic variant (FIPS 204 §3.4): the same
/// `(sk, msg, ctx)` gives the same signature on every call. The hedged
/// variant is a planned addition.
///
/// Returns `Ok = 0` on success, `NullPointer = 10` for a NULL `sk_ptr` or
/// `sig_out` or a NULL pointer with a non-zero length, `NotOperational = 1`
/// when the module is not operational, `AlgorithmRestricted = 6` when the
/// active profile does not admit the parameter set's signing, and
/// `InvalidInput = 5` when `ctx_len` exceeds 255 (FIPS 204 §5.2) or the
/// signing loop reaches its iteration bound.
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
    // SAFETY: `sig_out` is valid for writes of 3309 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..3309]) } {
        return e as c_int;
    }
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
/// (a malformed signature included), `NullPointer = 10` for a NULL
/// pointer, `NotOperational = 1` when the module is not operational, or
/// `AlgorithmRestricted = 6` when the active profile does not admit the
/// parameter set's verification.
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

// ── ML-KEM-1024 (FIPS 203) ───────────────────────────────────────

/// ML-KEM-1024 key generation (FIPS 203 Algorithm 19): draws the seeds d
/// and z from the caller's DRBG handle, expands the key pair and runs the
/// pairwise consistency test on it (FIPS 140-3 IG 10.3.A) before anything
/// is written.
///
/// Buffers: `ek_out`, 1568 writable bytes; `dk_out`, 3168 writable bytes;
/// `seed_out`, 64 writable bytes or NULL. With `seed_out` NULL the module
/// wipes d and z and returns only the pair. Otherwise `d ‖ z` is written
/// to `seed_out`, d first, and [`oxi_ml_kem_1024_expand_key`] reproduces
/// the pair from it; the seed computes the decapsulation key and needs the
/// same protection.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when `rbg`,
///   `ek_out` or `dk_out` is NULL, `InvalidInput = 5` when a range runs
///   past the top of the address space.
/// - `InvalidInput = 5`: an output shares a byte with another output or
///   with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-1024 key generation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `RbgTooWeak = 31`: the DRBG's security strength is below 256 bits;
///   nothing is drawn.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for writes of its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_1024_keygen_rbg(
    rbg: *mut OxiDrbg,
    ek_out: *mut u8,
    dk_out: *mut u8,
    seed_out: *mut u8,
) -> c_int {
    use oxicrypt_ml_kem::ml_kem_1024 as set;
    // SAFETY: every pointer meets `keygen_rbg`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::keygen_rbg(
            rbg,
            ek_out,
            dk_out,
            seed_out,
            oxicrypt_module::Service::MlKem1024Keygen,
            set::keygen::<DrbgKind>,
            set::keygen_with_seed::<DrbgKind>,
        )
    })
}

/// ML-KEM-1024 key expansion from a stored seed (FIPS 203 Algorithm 16),
/// with the pairwise consistency test run on the pair before anything is
/// written (FIPS 140-3 IG 10.3.A). `d` is the K-PKE seed and `z` the
/// implicit-rejection seed; the two are not interchangeable. A seed that
/// did not come from [`oxi_ml_kem_1024_keygen_rbg`] is a private key
/// imported into the module.
///
/// Buffers: `d_ptr` and `z_ptr`, 32 bytes each; `ek_out`, 1568 writable
/// bytes; `dk_out`, 3168 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with a seed or with the
///   other output.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-1024 key expansion.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success, as for
/// [`oxi_ml_kem_1024_keygen_rbg`].
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_1024_expand_key(
    d_ptr: *const u8,
    z_ptr: *const u8,
    ek_out: *mut u8,
    dk_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `expand_key`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::expand_key(
            d_ptr,
            z_ptr,
            ek_out,
            dk_out,
            oxicrypt_module::Service::MlKem1024ExpandKey,
            oxicrypt_ml_kem::ml_kem_1024::expand_key,
        )
    })
}

/// ML-KEM-1024 encapsulation (FIPS 203 Algorithm 20): checks `ek` (FIPS 203
/// §7.2), draws m from the caller's DRBG handle and encapsulates against
/// `ek`.
///
/// Buffers: `ek_ptr`, 1568 bytes; `ss_out`, 32 writable bytes; `ct_out`,
/// 1568 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with `ek`, with the other
///   output or with the handle, or `ek` shares a byte with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-1024 encapsulation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `InvalidInput = 5`: `ek` fails the §7.2 modulus check; nothing is
///   drawn.
/// - `RbgTooWeak = 31`: the DRBG's security strength is below 256 bits;
///   nothing is drawn.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_1024_encapsulate_rbg(
    ek_ptr: *const u8,
    rbg: *mut OxiDrbg,
    ss_out: *mut u8,
    ct_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `encapsulate_rbg`'s contract, which is
    // this function's.
    aes::code(unsafe {
        pq::encapsulate_rbg(
            ek_ptr,
            rbg,
            ss_out,
            ct_out,
            oxicrypt_module::Service::MlKem1024Encaps,
            oxicrypt_ml_kem::ml_kem_1024::encapsulate::<DrbgKind>,
        )
    })
}

/// ML-KEM-1024 decapsulation (FIPS 203 Algorithm 21): checks `dk` (FIPS 203
/// §7.3) and decapsulates `ct` under it.
///
/// Buffers: `dk_ptr`, 3168 bytes; `ct_ptr`, 1568 bytes; `ss_out`, 32
/// writable bytes. A ciphertext that does not match `dk` is not an error:
/// implicit rejection (FIPS 203 §6.3) returns `Ok = 0` with a pseudorandom
/// shared secret derived from `z` and `ct`.
///
/// Returns `Ok = 0` on success, `NullPointer = 10` for a NULL pointer,
/// `InvalidInput = 5` when `ss_out` shares a byte with `dk` or `ct` or a
/// range runs past the top of the address space,
/// `NotOperational = 1` when the module is not operational,
/// `AlgorithmRestricted = 6` when the active profile does not admit
/// ML-KEM-1024 decapsulation, and `InvalidInput = 5` when `dk` fails the
/// §7.3 hash check. The shared secret is written only on success.
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_1024_decapsulate(
    dk_ptr: *const u8,
    ct_ptr: *const u8,
    ss_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `decapsulate`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::decapsulate(
            dk_ptr,
            ct_ptr,
            ss_out,
            oxicrypt_module::Service::MlKem1024Decaps,
            oxicrypt_ml_kem::ml_kem_1024::decapsulate,
        )
    })
}

// ── ML-KEM-512 (FIPS 203) ────────────────────────────────────────

/// ML-KEM-512 key generation (FIPS 203 Algorithm 19): draws the seeds d
/// and z from the caller's DRBG handle, expands the key pair and runs the
/// pairwise consistency test on it (FIPS 140-3 IG 10.3.A) before anything
/// is written.
///
/// Buffers: `ek_out`, 800 writable bytes; `dk_out`, 1632 writable bytes;
/// `seed_out`, 64 writable bytes or NULL. With `seed_out` NULL the module
/// wipes d and z and returns only the pair. Otherwise `d ‖ z` is written
/// to `seed_out`, d first, and [`oxi_ml_kem_512_expand_key`] reproduces
/// the pair from it; the seed computes the decapsulation key and needs the
/// same protection.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when `rbg`,
///   `ek_out` or `dk_out` is NULL, `InvalidInput = 5` when a range runs
///   past the top of the address space.
/// - `InvalidInput = 5`: an output shares a byte with another output or
///   with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-512 key generation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `RbgTooWeak = 31` is not returned: it would need a DRBG below 128
///   bits of security strength, and no `OxiDrbg` is.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for writes of its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_512_keygen_rbg(
    rbg: *mut OxiDrbg,
    ek_out: *mut u8,
    dk_out: *mut u8,
    seed_out: *mut u8,
) -> c_int {
    use oxicrypt_ml_kem::ml_kem_512 as set;
    // SAFETY: every pointer meets `keygen_rbg`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::keygen_rbg(
            rbg,
            ek_out,
            dk_out,
            seed_out,
            oxicrypt_module::Service::MlKem512Keygen,
            set::keygen::<DrbgKind>,
            set::keygen_with_seed::<DrbgKind>,
        )
    })
}

/// ML-KEM-512 key expansion from a stored seed (FIPS 203 Algorithm 16),
/// with the pairwise consistency test run on the pair before anything is
/// written (FIPS 140-3 IG 10.3.A). `d` is the K-PKE seed and `z` the
/// implicit-rejection seed; the two are not interchangeable. A seed that
/// did not come from [`oxi_ml_kem_512_keygen_rbg`] is a private key
/// imported into the module.
///
/// Buffers: `d_ptr` and `z_ptr`, 32 bytes each; `ek_out`, 800 writable
/// bytes; `dk_out`, 1632 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with a seed or with the
///   other output.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-512 key expansion.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success, as for
/// [`oxi_ml_kem_512_keygen_rbg`].
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_512_expand_key(
    d_ptr: *const u8,
    z_ptr: *const u8,
    ek_out: *mut u8,
    dk_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `expand_key`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::expand_key(
            d_ptr,
            z_ptr,
            ek_out,
            dk_out,
            oxicrypt_module::Service::MlKem512ExpandKey,
            oxicrypt_ml_kem::ml_kem_512::expand_key,
        )
    })
}

/// ML-KEM-512 encapsulation (FIPS 203 Algorithm 20): checks `ek` (FIPS 203
/// §7.2), draws m from the caller's DRBG handle and encapsulates against
/// `ek`.
///
/// Buffers: `ek_ptr`, 800 bytes; `ss_out`, 32 writable bytes; `ct_out`,
/// 768 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with `ek`, with the other
///   output or with the handle, or `ek` shares a byte with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-512 encapsulation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `InvalidInput = 5`: `ek` fails the §7.2 modulus check; nothing is
///   drawn.
/// - `RbgTooWeak = 31` is not returned: it would need a DRBG below 128
///   bits of security strength, and no `OxiDrbg` is.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_512_encapsulate_rbg(
    ek_ptr: *const u8,
    rbg: *mut OxiDrbg,
    ss_out: *mut u8,
    ct_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `encapsulate_rbg`'s contract, which is
    // this function's.
    aes::code(unsafe {
        pq::encapsulate_rbg(
            ek_ptr,
            rbg,
            ss_out,
            ct_out,
            oxicrypt_module::Service::MlKem512Encaps,
            oxicrypt_ml_kem::ml_kem_512::encapsulate::<DrbgKind>,
        )
    })
}

/// ML-KEM-512 decapsulation (FIPS 203 Algorithm 21): checks `dk` (FIPS 203
/// §7.3) and decapsulates `ct` under it.
///
/// Buffers: `dk_ptr`, 1632 bytes; `ct_ptr`, 768 bytes; `ss_out`, 32
/// writable bytes. A ciphertext that does not match `dk` is not an error:
/// implicit rejection (FIPS 203 §6.3) returns `Ok = 0` with a pseudorandom
/// shared secret derived from `z` and `ct`.
///
/// Returns `Ok = 0` on success, `NullPointer = 10` for a NULL pointer,
/// `InvalidInput = 5` when `ss_out` shares a byte with `dk` or `ct` or a
/// range runs past the top of the address space,
/// `NotOperational = 1` when the module is not operational,
/// `AlgorithmRestricted = 6` when the active profile does not admit
/// ML-KEM-512 decapsulation, and `InvalidInput = 5` when `dk` fails the
/// §7.3 hash check. The shared secret is written only on success.
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_512_decapsulate(
    dk_ptr: *const u8,
    ct_ptr: *const u8,
    ss_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `decapsulate`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::decapsulate(
            dk_ptr,
            ct_ptr,
            ss_out,
            oxicrypt_module::Service::MlKem512Decaps,
            oxicrypt_ml_kem::ml_kem_512::decapsulate,
        )
    })
}

// ── ML-KEM-768 (FIPS 203) ────────────────────────────────────────

/// ML-KEM-768 key generation (FIPS 203 Algorithm 19): draws the seeds d
/// and z from the caller's DRBG handle, expands the key pair and runs the
/// pairwise consistency test on it (FIPS 140-3 IG 10.3.A) before anything
/// is written.
///
/// Buffers: `ek_out`, 1184 writable bytes; `dk_out`, 2400 writable bytes;
/// `seed_out`, 64 writable bytes or NULL. With `seed_out` NULL the module
/// wipes d and z and returns only the pair. Otherwise `d ‖ z` is written
/// to `seed_out`, d first, and [`oxi_ml_kem_768_expand_key`] reproduces
/// the pair from it; the seed computes the decapsulation key and needs the
/// same protection.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when `rbg`,
///   `ek_out` or `dk_out` is NULL, `InvalidInput = 5` when a range runs
///   past the top of the address space.
/// - `InvalidInput = 5`: an output shares a byte with another output or
///   with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-768 key generation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `RbgTooWeak = 31`: the DRBG's security strength is below 192 bits;
///   nothing is drawn.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for writes of its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_768_keygen_rbg(
    rbg: *mut OxiDrbg,
    ek_out: *mut u8,
    dk_out: *mut u8,
    seed_out: *mut u8,
) -> c_int {
    use oxicrypt_ml_kem::ml_kem_768 as set;
    // SAFETY: every pointer meets `keygen_rbg`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::keygen_rbg(
            rbg,
            ek_out,
            dk_out,
            seed_out,
            oxicrypt_module::Service::MlKem768Keygen,
            set::keygen::<DrbgKind>,
            set::keygen_with_seed::<DrbgKind>,
        )
    })
}

/// ML-KEM-768 key expansion from a stored seed (FIPS 203 Algorithm 16),
/// with the pairwise consistency test run on the pair before anything is
/// written (FIPS 140-3 IG 10.3.A). `d` is the K-PKE seed and `z` the
/// implicit-rejection seed; the two are not interchangeable. A seed that
/// did not come from [`oxi_ml_kem_768_keygen_rbg`] is a private key
/// imported into the module.
///
/// Buffers: `d_ptr` and `z_ptr`, 32 bytes each; `ek_out`, 1184 writable
/// bytes; `dk_out`, 2400 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with a seed or with the
///   other output.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-768 key expansion.
/// - `ConditionalTestFailed = 3`: the pairwise consistency test failed.
///   The module has entered its error state, and every later call returns
///   `NotOperational = 1`.
///
/// Outputs are written only on success, as for
/// [`oxi_ml_kem_768_keygen_rbg`].
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_768_expand_key(
    d_ptr: *const u8,
    z_ptr: *const u8,
    ek_out: *mut u8,
    dk_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `expand_key`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::expand_key(
            d_ptr,
            z_ptr,
            ek_out,
            dk_out,
            oxicrypt_module::Service::MlKem768ExpandKey,
            oxicrypt_ml_kem::ml_kem_768::expand_key,
        )
    })
}

/// ML-KEM-768 encapsulation (FIPS 203 Algorithm 20): checks `ek` (FIPS 203
/// §7.2), draws m from the caller's DRBG handle and encapsulates against
/// `ek`.
///
/// Buffers: `ek_ptr`, 1184 bytes; `ss_out`, 32 writable bytes; `ct_out`,
/// 1088 writable bytes.
///
/// Returns `Ok = 0` on success, otherwise the first of, in this order:
/// - Each pointer, in parameter order: `NullPointer = 10` when it is NULL,
///   `InvalidInput = 5` when its range runs past the top of the address
///   space.
/// - `InvalidInput = 5`: an output shares a byte with `ek`, with the other
///   output or with the handle, or `ek` shares a byte with the handle.
/// - `NotOperational = 1`: the module is not operational.
/// - `AlgorithmRestricted = 6`: the active profile does not admit
///   ML-KEM-768 encapsulation, or the handle's DRBG.
/// - `InvalidInput = 5`: the handle was instantiated by another process.
/// - `Busy = 32`: the handle is in use by another call.
/// - `InvalidInput = 5`: `ek` fails the §7.2 modulus check; nothing is
///   drawn.
/// - `RbgTooWeak = 31`: the DRBG's security strength is below 192 bits;
///   nothing is drawn.
/// - The DRBG's codes: `Uninstantiated = 8` for a handle never
///   instantiated; `Busy = 32` when its reseed waits too long on a seed
///   path another thread holds; `EntropyUnavailable = 33` when the entropy
///   source fails during that reseed.
///
/// Outputs are written only on success. A module that enters its error
/// state between the copies zeroes the outputs already copied and returns
/// `NotOperational = 1`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function, and
/// every non-NULL buffer valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_768_encapsulate_rbg(
    ek_ptr: *const u8,
    rbg: *mut OxiDrbg,
    ss_out: *mut u8,
    ct_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `encapsulate_rbg`'s contract, which is
    // this function's.
    aes::code(unsafe {
        pq::encapsulate_rbg(
            ek_ptr,
            rbg,
            ss_out,
            ct_out,
            oxicrypt_module::Service::MlKem768Encaps,
            oxicrypt_ml_kem::ml_kem_768::encapsulate::<DrbgKind>,
        )
    })
}

/// ML-KEM-768 decapsulation (FIPS 203 Algorithm 21): checks `dk` (FIPS 203
/// §7.3) and decapsulates `ct` under it.
///
/// Buffers: `dk_ptr`, 2400 bytes; `ct_ptr`, 1088 bytes; `ss_out`, 32
/// writable bytes. A ciphertext that does not match `dk` is not an error:
/// implicit rejection (FIPS 203 §6.3) returns `Ok = 0` with a pseudorandom
/// shared secret derived from `z` and `ct`.
///
/// Returns `Ok = 0` on success, `NullPointer = 10` for a NULL pointer,
/// `InvalidInput = 5` when `ss_out` shares a byte with `dk` or `ct` or a
/// range runs past the top of the address space,
/// `NotOperational = 1` when the module is not operational,
/// `AlgorithmRestricted = 6` when the active profile does not admit
/// ML-KEM-768 decapsulation, and `InvalidInput = 5` when `dk` fails the
/// §7.3 hash check. The shared secret is written only on success.
///
/// # Safety
///
/// Every non-NULL buffer must be valid for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ml_kem_768_decapsulate(
    dk_ptr: *const u8,
    ct_ptr: *const u8,
    ss_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `decapsulate`'s contract, which is this
    // function's.
    aes::code(unsafe {
        pq::decapsulate(
            dk_ptr,
            ct_ptr,
            ss_out,
            oxicrypt_module::Service::MlKem768Decaps,
            oxicrypt_ml_kem::ml_kem_768::decapsulate,
        )
    })
}

// ── SLH-DSA-SHA2-256s (FIPS 205) ─────────────────────────────────

/// Generate an SLH-DSA-SHA2-256s key pair from a 96-byte
/// caller-supplied seed (FIPS 205 §9.1 Algorithm 17).
///
/// Reads exactly 96 bytes from `xi_ptr`, internally framed as
/// `SK.seed ‖ SK.prf ‖ PK.seed`. Writes the 64-byte public key
/// into `pk_out` and the 128-byte secret key into `sk_out`. The
/// caller MUST source the 96 bytes from an approved DRBG
/// (SP 800-90A); the module draws nothing. The three 32-byte
/// components have distinct roles and are not interchangeable:
/// SK.seed derives the secret values, SK.prf keys the message
/// randomizer, and PK.seed separates the hash calls of one key pair
/// from another's (FIPS 205 §9.1).
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
    // SAFETY: `pk_out` is valid for writes of 64 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..64]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 128 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..128]) } {
        // SAFETY: `pk_out` is valid for writes of 64 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 64) };
        return e as c_int;
    }
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
/// Signing is the deterministic variant (opt_rand = PK.seed, FIPS 205
/// Algorithm 22): the same `(sk, msg, ctx)` gives the same signature on every
/// call.
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
    // SAFETY: `sig_out` is valid for writes of 29_792 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..29_792]) } {
        return e as c_int;
    }
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
/// (a malformed signature included), or a module error variant
/// (`NotOperational`, `AlgorithmRestricted`).
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

// ── SLH-DSA — the other SHA-2 parameter sets (FIPS 205) ──────────

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
    // SAFETY: `pk_out` is valid for writes of 32 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..32]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 64 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..64]) } {
        // SAFETY: `pk_out` is valid for writes of 32 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 32) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 7_856 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..7_856]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 32 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..32]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 64 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..64]) } {
        // SAFETY: `pk_out` is valid for writes of 32 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 32) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 17_088 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..17_088]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 48 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..48]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 96 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..96]) } {
        // SAFETY: `pk_out` is valid for writes of 48 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 48) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 16_224 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..16_224]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 48 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..48]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 96 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..96]) } {
        // SAFETY: `pk_out` is valid for writes of 48 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 48) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 35_664 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..35_664]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 64 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..64]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 128 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..128]) } {
        // SAFETY: `pk_out` is valid for writes of 64 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 64) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 49_856 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..49_856]) } {
        return e as c_int;
    }
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

// ── SLH-DSA — the SHAKE parameter sets (FIPS 205) ────────────────

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
    // SAFETY: `pk_out` is valid for writes of 32 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..32]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 64 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..64]) } {
        // SAFETY: `pk_out` is valid for writes of 32 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 32) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 7_856 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..7_856]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 32 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..32]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 64 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..64]) } {
        // SAFETY: `pk_out` is valid for writes of 32 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 32) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 17_088 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..17_088]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 48 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..48]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 96 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..96]) } {
        // SAFETY: `pk_out` is valid for writes of 48 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 48) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 16_224 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..16_224]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 48 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..48]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 96 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..96]) } {
        // SAFETY: `pk_out` is valid for writes of 48 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 48) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 35_664 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..35_664]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 64 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..64]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 128 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..128]) } {
        // SAFETY: `pk_out` is valid for writes of 64 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 64) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 29_792 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..29_792]) } {
        return e as c_int;
    }
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
    // SAFETY: `pk_out` is valid for writes of 64 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(pk_out, &pk[..64]) } {
        return e as c_int;
    }
    // SAFETY: `sk_out` is valid for writes of 128 bytes by contract,
    // and the local `sk` does not overlap it.
    if let Err(e) = unsafe { write_out(sk_out, &sk[..128]) } {
        // SAFETY: `pk_out` is valid for writes of 64 bytes by contract;
        // the output already written there does not survive the failure.
        unsafe { zero_out(pk_out, 64) };
        return e as c_int;
    }
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
    // SAFETY: `sig_out` is valid for writes of 49_856 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..49_856]) } {
        return e as c_int;
    }
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
// Verification only: SP 800-208 §8.1 confines key generation and
// signing to hardware modules.

/// Length of an LMS public key in bytes (56).
pub const OXI_LMS_PUBLIC_KEY_LEN: usize = 56;

/// Length of an LMS signature in bytes (2508).
pub const OXI_LMS_SIGNATURE_LEN: usize = 2508;

/// Length of an XMSS public key in bytes (68).
pub const OXI_XMSS_PUBLIC_KEY_LEN: usize = 68;

/// Length of an XMSS signature in bytes (2500).
pub const OXI_XMSS_SIGNATURE_LEN: usize = 2500;

/// Verify an LMS signature.
///
/// Reads the 56-byte public key from `pk_ptr`, `msg_len` bytes from
/// `msg_ptr`, and the 2508-byte signature from `sig_ptr`.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::TagMismatch = 22` for any verification failure
/// (a malformed key or signature included), or a module error variant.
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

/// Verify an LMS signature under whichever of the 80 SP 800-208
/// §4.1–§4.4 parameter pairs its public key names.
///
/// Reads the LMS and LM-OTS typecodes from the first 8 bytes of the
/// `pk_len`-byte public key and verifies through that pair's gated
/// `verify`, as `oxicrypt_lms::verify_any` does.
///
/// Returns `OxiResult::Ok = 0` for a valid signature,
/// `OxiResult::InvalidInput = 5` when the input names no pair (fewer than
/// 8 public-key bytes, a typecode pair outside the 80, or a `pk_len` or
/// `sig_len` that is not the named pair's), `OxiResult::TagMismatch = 22`
/// when the named pair's verifier rejects the signature, or a module
/// error variant from the named pair's gate.
///
/// # Safety
///
/// `pk_ptr` must be valid for `pk_len` bytes, `msg_ptr` for `msg_len`
/// bytes and `sig_ptr` for `sig_len` bytes. Each may be NULL only when
/// its length is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_lms_verify_any(
    pk_ptr: *const u8,
    pk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> c_int {
    let pk = match unsafe { slice_from_raw(pk_ptr, pk_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let msg = match unsafe { slice_from_raw(msg_ptr, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig = match unsafe { slice_from_raw(sig_ptr, sig_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match oxicrypt_lms::verify_any(pk, msg, sig) {
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_lms::VerifyAnyError::Unroutable) => R::InvalidInput as c_int,
        Err(oxicrypt_lms::VerifyAnyError::VerificationFailed) => R::TagMismatch as c_int,
        Err(oxicrypt_lms::VerifyAnyError::Module(e)) => R::from(e) as c_int,
    }
}

// ── SHA-256 / M=32 family (SP 800-208 §4.1) — 20 pairs, verify only ──

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8684-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4460-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2348-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=5 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1292-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8844-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4620-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2508-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=10 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1452-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9004-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4780-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2668-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=15 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1612-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9164-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4940-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2828-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=20 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1772-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9324-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 5100-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2988-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

/// Verify an LMS signature for the SHA-256 M=32 H=25 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1932-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.1.
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

// ── SHA-256 / M=24 family (SP 800-208 §4.2) — 20 pairs, verify only ──

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 4956-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2580-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1380-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=5 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 780-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5076-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2700-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1500-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=10 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 900-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5196-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2820-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1620-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=15 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1020-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5316-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2940-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1740-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=20 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1140-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5436-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 3060-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1860-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

/// Verify an LMS signature for the SHA-256 M=24 H=25 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1260-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.2.
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

// ── SHAKE-256 / M=32 family (SP 800-208 §4.3) — 20 pairs, verify only ──

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8684-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4460-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2348-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=5 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1292-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 8844-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4620-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2508-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=10 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1452-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9004-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4780-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2668-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=15 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1612-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9164-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 4940-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2828-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=20 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1772-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=1 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 9324-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=2 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 5100-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=4 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 2988-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

/// Verify an LMS signature for the SHAKE-256 M=32 H=25 W=8 variant.
///
/// Reads 56-byte pk, `msg_len`-byte message, and
/// 1932-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.3.
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

// ── SHAKE-256 / M=24 family (SP 800-208 §4.4) — 20 pairs, verify only ──

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 4956-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2580-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1380-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=5 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 780-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5076-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2700-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1500-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=10 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 900-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5196-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2820-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1620-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=15 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1020-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5316-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 2940-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1740-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=20 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1140-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=1 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 5436-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=2 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 3060-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=4 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1860-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

/// Verify an LMS signature for the SHAKE-256 M=24 H=25 W=8 variant.
///
/// Reads 48-byte pk, `msg_len`-byte message, and
/// 1260-byte signature. Returns `TagMismatch=22` on any
/// verification failure, a malformed key or signature included.
/// Spec: SP 800-208 §4.4.
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

// ── ECDSA private-key handles (FIPS 186-5 §A.2.2, IG 10.3.A) ─────
//
// `_new_generate` is the only constructor, so every handle holds a key
// that passed its pairwise consistency test.

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
    /// `EcdsaP256PrivateKey`. Returns `None` only for a finalised
    /// handle, and this handle has no `_finalize` entry point, only
    /// `_free` via Drop.
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

// ── ECDSA P-256 private key ──────────────────────────────────────

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
/// Returns, in this order: `NullPointer = 10` for a NULL `drbg` or
/// `out_key`; `InvalidInput = 5` for a DRBG handle instantiated by
/// another process and `Uninstantiated = 8` for one never instantiated,
/// both checked before the module state; `NotOperational = 1` when the
/// module is not operational; `AlgorithmRestricted = 6` when the active
/// profile does not admit ECDSA P-256 key generation; the DRBG's codes
/// when it produces no output; `InvalidInput = 5` when scalar sampling
/// exhausts its retries; and `ConditionalTestFailed = 3` when the
/// pairwise consistency test fails, after which the module is in its
/// error state and every later call returns `NotOperational = 1`. On any
/// failure `*out_key` is unchanged.
///
/// # Safety
///
/// `drbg` must be a live, instantiated handle from
/// [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`]. `out_key` must be a non-NULL
/// writable pointer to a `*mut OxiEcdsaP256PrivateKey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ecdsa_p256_private_key_new_generate(
    drbg: *mut crate::drbg::OxiHmacDrbgSha256,
    out_key: *mut *mut OxiEcdsaP256PrivateKey,
) -> c_int {
    if drbg.is_null() || out_key.is_null() {
        return R::NullPointer as c_int;
    }
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
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
/// SHOULD set their pointer to NULL to avoid use-after-free.
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
/// finalised, which cannot happen: this handle has no `_finalize`.
///
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let pk = match key_ref.public_key() {
        Ok(v) => v,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `public_key_out` is valid for writes of 65 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(public_key_out, &pk[..65]) } {
        return e as c_int;
    }
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
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
///
/// # Safety
///
/// `key` must be a live handle from
/// [`oxi_ecdsa_p256_private_key_new_generate`]. `drbg` must be a
/// live, instantiated handle from [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`]; the caller MUST serialise
/// concurrent calls on the same `drbg` pointer, because every call
/// mutates the DRBG's state. `msg_ptr` must be valid for `msg_len` bytes.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let sig = match key_ref.sign_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `sig_out` is valid for writes of 64 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..64]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

// ── ECDSA P-384 private key ──────────────────────────────────────

/// Allocate a new ECDSA P-384 private-key handle, generating its
/// private scalar via the FIPS 186-5 §A.2.2 rejection sampler on
/// `drbg`, deriving its public key, and running the IG 10.3.A
/// pairwise consistency test before returning.
///
/// Returns the codes of [`oxi_ecdsa_p256_private_key_new_generate`] in
/// the same order, for ECDSA P-384 key generation: `NullPointer = 10`,
/// `InvalidInput = 5` and `Uninstantiated = 8` for the DRBG handle,
/// `NotOperational = 1`, `AlgorithmRestricted = 6`, the DRBG's codes,
/// `InvalidInput = 5` on sampling exhaustion, and
/// `ConditionalTestFailed = 3` when the pairwise consistency test fails,
/// after which every call returns `NotOperational = 1`.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
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

/// Free an ECDSA P-384 private-key handle, as
/// [`oxi_ecdsa_p256_private_key_free`] does. NULL is a no-op.
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
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let pk = match key_ref.public_key() {
        Ok(v) => v,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `public_key_out` is valid for writes of 97 bytes by contract,
    // and the local `pk` does not overlap it.
    if let Err(e) = unsafe { write_out(public_key_out, &pk[..97]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Sign `msg` with ECDSA P-384 + SHA-384 under the private-key
/// handle, sampling a fresh per-signature nonce `k` from `drbg` via
/// the FIPS 186-5 §A.2.2 rejection sampler, as
/// [`oxi_ecdsa_p256_private_key_sign_sha256`] does, with a 96-byte
/// signature.
///
/// Returns `OxiResult::InvalidInput = 5` if the DRBG faults or the
/// bounded retry chain exhausts. Returns `OxiResult::NotOperational
/// = 1` if the FIPS module is not in the `Operational` state.
/// Returns `OxiResult::AlgorithmRestricted = 6` if the active
/// algorithm profile blocks ECDSA-P384 sign (a profile MAY allow
/// `EcdsaP384Keygen` but block `EcdsaP384Sign`, in which case
/// `_new_generate` succeeds but this fn returns 6).
///
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let sig = match key_ref.sign_sha384(drbg_ref, msg) {
        Ok(s) => s,
        Err(e) => return R::from(e) as c_int,
    };
    // SAFETY: `sig_out` is valid for writes of 96 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..96]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

// ── RSA private-key handles (FIPS 186-5, RFC 8017 §8, IG 10.3.A) ─
//
// `_new_generate` is the only constructor, so every handle holds a key
// that passed its pairwise consistency test. The handle exposes `n` and
// `e` and no private component.

/// Opaque RSA-2048 private-key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time: its only constructor
/// runs the test, so no handle exists that has not passed it.
///
/// cbindgen:opaque
pub struct OxiRsaPrivateKey2048 {
    inner: OxiHandle<oxicrypt_rsa::RsaPrivateKey2048>,
}

impl OxiRsaPrivateKey2048 {
    /// Crate-internal accessor for the underlying read-only
    /// `RsaPrivateKey2048`. Returns `None` only for a finalised
    /// handle, and this handle has no `_finalize` entry point, only
    /// `_free` via Drop.
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

// ── RSA-2048 ─────────────────────────────────────────────────────

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
/// Returns, in this order: `NullPointer = 10` for a NULL `drbg` or
/// `out_key`; `InvalidInput = 5` for a DRBG handle instantiated by
/// another process and `Uninstantiated = 8` for one never instantiated,
/// both checked before the module state; `NotOperational = 1` when the
/// module is not operational; `AlgorithmRestricted = 6` when the active
/// profile does not admit RSA-2048 key generation; the DRBG's codes when
/// it produces no output; `InvalidInput = 5` when `e` fails its check or
/// prime sampling exceeds its retry budget; and
/// `ConditionalTestFailed = 3` when the pairwise consistency test fails,
/// after which the module is in its error state and every later call
/// returns `NotOperational = 1`. On any failure `*out_key` is unchanged.
///
/// # Safety
///
/// `drbg` must be a live, instantiated handle from
/// [`oxi_hmac_drbg_sha256_new`] +
/// [`oxi_hmac_drbg_sha256_instantiate_from_module`]. `out_key` must be a non-NULL
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
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
/// After this call the caller's pointer is dangling.
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
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let n = match key_ref.modulus_bytes() {
        Ok(v) => v,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `modulus_out` is valid for writes of 256 bytes by contract,
    // and the local `n` does not overlap it.
    if let Err(e) = unsafe { write_out(modulus_out, &n[..256]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Copy the public exponent `e` from an RSA-2048 private-key handle
/// into the caller-supplied `uint64_t*`.
///
/// Returns `OxiResult::Ok = 0` on success;
/// `OxiResult::NullPointer = 10` if either pointer is NULL.
///
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let e = match key_ref.public_exponent() {
        Ok(e) => e,
        Err(err) => return status_module(Err(err)),
    };
    unsafe { *e_out = e };
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
    // SAFETY: `sig_out` is valid for writes of 256 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..256]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PSS SHA-256 under the RSA-2048 private-
/// key handle, sampling a fresh 32-byte salt from `drbg` per call
/// (FIPS 186-5 §5.4 / RFC 8017 §8.1). Signing the same `(key, msg)`
/// twice produces two distinct signatures.
///
/// On success, writes 256 bytes into `sig_out` and returns `Ok = 0`.
///
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
///
/// # Safety
///
/// `key` must be a live handle. `drbg` must be a live, instantiated
/// DRBG handle; the caller MUST serialise concurrent calls on the
/// same `drbg` pointer, because every call mutates the DRBG's
/// state. `msg_ptr` must
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let sig = match key_ref.sign_pss_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    // SAFETY: `sig_out` is valid for writes of 256 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..256]) } {
        return e as c_int;
    }
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
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let ct = match oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256(drbg_ref, n_arr, e, label, msg) {
        Ok(c) => c,
        Err(err) => return R::from(err) as c_int,
    };
    // SAFETY: `ct_out` is valid for writes of 256 bytes by contract,
    // and the local `ct` does not overlap it.
    if let Err(e) = unsafe { write_out(ct_out, &ct[..256]) } {
        return e as c_int;
    }
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
/// failed (Manger-resistance contract).
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
    let code = match key_ref.decrypt_oaep_sha256(label, ct_arr, &mut buf) {
        Ok(actual) => match buf.get(..actual) {
            // SAFETY: `out_ptr` is valid for writes of `out_max_len` bytes
            // by contract, `out_max_len` is at least `buf.len()` >=
            // `plain.len()`, and the local `buf` does not overlap it.
            Some(plain) => match unsafe { write_out(out_ptr, plain) } {
                Ok(()) => {
                    // SAFETY: `out_actual_len` is non-NULL and valid for
                    // one `size_t` by contract.
                    unsafe { *out_actual_len = actual };
                    R::Ok as c_int
                }
                Err(e) => e as c_int,
            },
            None => R::Internal as c_int,
        },
        Err(err) => R::from(err) as c_int,
    };
    oxicrypt_zeroize::zeroize(&mut buf);
    code
}

// ── RSA-3072 ─────────────────────────────────────────────────────

/// Allocate a new RSA-3072 private-key handle, as
/// [`oxi_rsa_2048_private_key_new_generate`] does for a 2048-bit modulus,
/// with the same codes in the same order: `ConditionalTestFailed = 3`
/// when the pairwise consistency test fails, and `NotOperational = 1` on
/// every later call.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
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
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let n = match key_ref.modulus_bytes() {
        Ok(v) => v,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `modulus_out` is valid for writes of 384 bytes by contract,
    // and the local `n` does not overlap it.
    if let Err(e) = unsafe { write_out(modulus_out, &n[..384]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Copy the public exponent `e` from an RSA-3072 handle. See
/// [`oxi_rsa_2048_public_exponent`].
///
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let e = match key_ref.public_exponent() {
        Ok(e) => e,
        Err(err) => return status_module(Err(err)),
    };
    unsafe { *e_out = e };
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
    // SAFETY: `sig_out` is valid for writes of 384 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..384]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PSS SHA-256 under the RSA-3072 handle,
/// DRBG-sampled salt. Produces a 384-byte signature.
///
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let sig = match key_ref.sign_pss_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    // SAFETY: `sig_out` is valid for writes of 384 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..384]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-3072
/// public key `(n, e)`, DRBG-sampled seed. Maximum plaintext length
/// is 318 bytes (`k − 2·hLen − 2` with `k = 384`, `hLen = 32`).
/// Ciphertext is fixed at 384 bytes.
///
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let ct = match oxicrypt_rsa::rsa3072::oaep_encrypt(drbg_ref, n_arr, e, label, msg) {
        Ok(c) => c,
        Err(err) => return R::from(err) as c_int,
    };
    // SAFETY: `ct_out` is valid for writes of 384 bytes by contract,
    // and the local `ct` does not overlap it.
    if let Err(e) = unsafe { write_out(ct_out, &ct[..384]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-3072
/// handle. `out_max_len` must be ≥ 318. Every decode failure returns
/// `InvalidInput = 5`, as for [`oxi_rsa_2048_oaep_decrypt_sha256`].
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
    // The message is decoded into a module-owned buffer and reaches the
    // caller only through `write_out`. A failed decode writes nothing to
    // the caller's buffer.
    let mut buf = [0u8; oxicrypt_rsa::rsa3072::OAEP_MAX_MSG_LEN];
    let code = match key_ref.decrypt_oaep_sha256(label, ct_arr, &mut buf) {
        Ok(actual) => match buf.get(..actual) {
            // SAFETY: `out_ptr` is valid for writes of `out_max_len` bytes
            // by contract, `out_max_len` is at least `buf.len()` >=
            // `plain.len()`, and the local `buf` does not overlap it.
            Some(plain) => match unsafe { write_out(out_ptr, plain) } {
                Ok(()) => {
                    // SAFETY: `out_actual_len` is non-NULL and valid for
                    // one `size_t` by contract.
                    unsafe { *out_actual_len = actual };
                    R::Ok as c_int
                }
                Err(e) => e as c_int,
            },
            None => R::Internal as c_int,
        },
        Err(err) => R::from(err) as c_int,
    };
    oxicrypt_zeroize::zeroize(&mut buf);
    code
}

// ── RSA-4096 ─────────────────────────────────────────────────────

/// Allocate a new RSA-4096 private-key handle, as
/// [`oxi_rsa_2048_private_key_new_generate`] does for a 2048-bit modulus,
/// with the same codes in the same order: `ConditionalTestFailed = 3`
/// when the pairwise consistency test fails, and `NotOperational = 1` on
/// every later call.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
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
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let n = match key_ref.modulus_bytes() {
        Ok(v) => v,
        Err(e) => return status_module(Err(e)),
    };
    // SAFETY: `modulus_out` is valid for writes of 512 bytes by contract,
    // and the local `n` does not overlap it.
    if let Err(e) = unsafe { write_out(modulus_out, &n[..512]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Copy the public exponent `e` from an RSA-4096 handle.
///
/// Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
/// `Operational` states, including for a handle created before the module
/// entered `Error`.
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
    let e = match key_ref.public_exponent() {
        Ok(e) => e,
        Err(err) => return status_module(Err(err)),
    };
    unsafe { *e_out = e };
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
    // SAFETY: `sig_out` is valid for writes of 512 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..512]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Sign `msg` with RSASSA-PSS SHA-256 under the RSA-4096 handle,
/// DRBG-sampled salt. Produces a 512-byte signature.
///
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let sig = match key_ref.sign_pss_sha256(drbg_ref, msg) {
        Ok(s) => s,
        Err(err) => return R::from(err) as c_int,
    };
    // SAFETY: `sig_out` is valid for writes of 512 bytes by contract,
    // and the local `sig` does not overlap it.
    if let Err(e) = unsafe { write_out(sig_out, &sig[..512]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-4096
/// public key `(n, e)`, DRBG-sampled seed. Maximum plaintext length
/// is 446 bytes; ciphertext is 512 bytes.
///
/// Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
/// instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
/// by another process; both are checked before the module state.
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
    // SAFETY: `drbg` is a live handle nothing else reaches during this
    // call, by contract; the borrow ends with this function.
    let drbg_ref = match unsafe { crate::drbg::typed_drbg_access(drbg) } {
        Ok(d) => d,
        Err(e) => return e as c_int,
    };
    let ct = match oxicrypt_rsa::rsa4096::oaep_encrypt(drbg_ref, n_arr, e, label, msg) {
        Ok(c) => c,
        Err(err) => return R::from(err) as c_int,
    };
    // SAFETY: `ct_out` is valid for writes of 512 bytes by contract,
    // and the local `ct` does not overlap it.
    if let Err(e) = unsafe { write_out(ct_out, &ct[..512]) } {
        return e as c_int;
    }
    R::Ok as c_int
}

/// Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-4096
/// handle. `out_max_len` must be ≥ 446. Every decode failure returns
/// `InvalidInput = 5`, as for [`oxi_rsa_2048_oaep_decrypt_sha256`].
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
    // Staged as in `oxi_rsa_3072_oaep_decrypt_sha256`.
    let mut buf = [0u8; oxicrypt_rsa::rsa4096::OAEP_MAX_MSG_LEN];
    let code = match key_ref.decrypt_oaep_sha256(label, ct_arr, &mut buf) {
        Ok(actual) => match buf.get(..actual) {
            // SAFETY: `out_ptr` is valid for writes of `out_max_len` bytes
            // by contract, `out_max_len` is at least `buf.len()` >=
            // `plain.len()`, and the local `buf` does not overlap it.
            Some(plain) => match unsafe { write_out(out_ptr, plain) } {
                Ok(()) => {
                    // SAFETY: `out_actual_len` is non-NULL and valid for
                    // one `size_t` by contract.
                    unsafe { *out_actual_len = actual };
                    R::Ok as c_int
                }
                Err(e) => e as c_int,
            },
            None => R::Internal as c_int,
        },
        Err(err) => R::from(err) as c_int,
    };
    oxicrypt_zeroize::zeroize(&mut buf);
    code
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod lms_verify_any_tests {
    use super::{R, oxi_lms_verify_any};
    use core::ffi::c_int;
    use oxicrypt_lms::lms_sha256_m32_h5_w1 as pair;

    /// A public key naming LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W1, with
    /// the LM-OTS typecode replaced by `lmots`.
    fn pk(lmots: u32) -> [u8; pair::PUBLIC_KEY_LEN] {
        let mut pk = [0u8; pair::PUBLIC_KEY_LEN];
        pk[..4].copy_from_slice(&pair::LMS_TYPE.to_be_bytes());
        pk[4..8].copy_from_slice(&lmots.to_be_bytes());
        pk
    }

    fn call(pk: &[u8], sig: &[u8]) -> c_int {
        unsafe {
            oxi_lms_verify_any(
                pk.as_ptr(),
                pk.len(),
                core::ptr::null(),
                0,
                sig.as_ptr(),
                sig.len(),
            )
        }
    }

    /// The module is never initialised in this test binary, so a routed
    /// pair reaches its gate and returns `NotOperational`. Input naming no
    /// pair returns `InvalidInput` without reaching any gate.
    #[test]
    fn unroutable_input_is_invalid_input_and_routed_input_reaches_the_gate() {
        let sig = [0u8; pair::SIGNATURE_LEN];
        assert_eq!(
            call(&pk(pair::LMOTS_TYPE), &sig),
            R::NotOperational as c_int
        );
        // LMOTS_SHA256_N24_W1 under an N = 32 LMS typecode: no such pair.
        assert_eq!(call(&pk(0x0000_0005), &sig), R::InvalidInput as c_int);
        assert_eq!(
            call(&pk(pair::LMOTS_TYPE), &sig[..sig.len() - 1]),
            R::InvalidInput as c_int
        );
        assert_eq!(
            call(&pk(pair::LMOTS_TYPE)[..7], &sig),
            R::InvalidInput as c_int
        );
    }

    #[test]
    fn null_buffer_with_nonzero_length_is_null_pointer() {
        let pk = pk(pair::LMOTS_TYPE);
        let msg = [0u8; 16];
        let sig = [0u8; pair::SIGNATURE_LEN];
        let null = core::ptr::null();
        let rc = |pk: *const u8, msg: *const u8, sig: *const u8| unsafe {
            oxi_lms_verify_any(pk, pair::PUBLIC_KEY_LEN, msg, 16, sig, pair::SIGNATURE_LEN)
        };
        assert_eq!(
            rc(null, msg.as_ptr(), sig.as_ptr()),
            R::NullPointer as c_int
        );
        assert_eq!(rc(pk.as_ptr(), null, sig.as_ptr()), R::NullPointer as c_int);
        assert_eq!(rc(pk.as_ptr(), msg.as_ptr(), null), R::NullPointer as c_int);
        // Positive control: the same buffers, none NULL, reach the gate.
        assert_eq!(
            rc(pk.as_ptr(), msg.as_ptr(), sig.as_ptr()),
            R::NotOperational as c_int
        );
    }

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// CNSA 1.0 permits no LMS service, so a routable key reaches the
    /// named pair's gate and returns `AlgorithmRestricted`, while input
    /// naming no pair still returns `InvalidInput`.
    ///
    /// Initialising the module is process-global and the other tests in
    /// this module assert it is uninitialised, so this relies on the
    /// workspace's test runner, nextest, running each test in its own
    /// process.
    #[test]
    fn routable_key_under_cnsa1_is_algorithm_restricted() {
        match oxicrypt_module::initialize_with_profile(
            UNSIGNED_TEST_BINARY,
            oxicrypt_lms::KATS,
            oxicrypt_module::AlgorithmProfile::Cnsa1,
        ) {
            Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => {}
            Err(e) => panic!("module failed to initialise: {e:?}"),
        }
        assert!(oxicrypt_module::is_operational());
        let sig = [0u8; pair::SIGNATURE_LEN];
        assert_eq!(
            call(&pk(pair::LMOTS_TYPE), &sig),
            R::AlgorithmRestricted as c_int
        );
        assert_eq!(call(&pk(0x0000_0005), &sig), R::InvalidInput as c_int);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod kat_tests {
    use super::{oxi_init, power_up_set};
    use oxicrypt_module::{AlgorithmProfile, Error, KatEntry};
    use std::collections::BTreeSet;
    use std::sync::{Mutex, PoisonError};

    /// Linked `oxicrypt-*` crates that publish no algorithm KATs, each
    /// with the reason it is not in the power-up set.
    const NOT_ALGORITHM_CRATES: &[(&str, &str)] = &[
        (
            "oxicrypt_module",
            "the self-test runner and state machine; it implements no algorithm",
        ),
        (
            "oxicrypt_integrity",
            "its KAT is the separate integrity argument to initialize_with_profile",
        ),
        (
            "oxicrypt_imageread",
            "reads the module's own image for the integrity test; it implements no algorithm",
        ),
        (
            "oxicrypt_zeroize",
            "zeroizes secret buffers; it implements no algorithm",
        ),
        (
            "oxicrypt_test_vectors",
            "vector data that algorithm crates' KATs read; it implements no algorithm",
        ),
        (
            "oxicrypt_entropy",
            "the SP 800-90B entropy source behind the DRBG seed path; its start-up health \
             tests and conditioner known-answer test run when the seed path first starts the \
             source (SP 800-90B section 4.3), a failure is a module failure, and its \
             conditioning function's algorithm test is oxicrypt_sha's",
        ),
        (
            "oxicrypt_timer",
            "reads the CPU counter for the entropy source; it implements no algorithm",
        ),
        (
            "oxicrypt_platform",
            "the module's own platform calls for the seed path; it implements no algorithm",
        ),
    ];

    /// Each algorithm crate's own `KATS` slice, keyed by the crate's path
    /// as written. `stringify!` takes the key from the same path the slice
    /// is read through, so a key cannot name a different crate's slice.
    macro_rules! kats_by_crate {
        ($($krate:ident),* $(,)?) => {
            &[$((stringify!($krate), $krate::KATS)),*]
        };
    }

    const KATS_BY_CRATE: &[(&str, &[KatEntry])] = kats_by_crate![
        oxicrypt_sha,
        oxicrypt_xof,
        oxicrypt_hmac,
        oxicrypt_kdf,
        oxicrypt_aes,
        oxicrypt_cmac,
        oxicrypt_drbg,
        oxicrypt_ecdsa,
        oxicrypt_eddsa,
        oxicrypt_ecdh,
        oxicrypt_tls_kdf,
        oxicrypt_dh,
        oxicrypt_rsa,
        oxicrypt_ml_kem,
        oxicrypt_ml_dsa,
        oxicrypt_slh_dsa,
        oxicrypt_lms,
        oxicrypt_xmss,
    ];

    /// The names of the integrity and algorithm self-tests the most recent
    /// `oxi_init` passed to the module.
    static PASSED: Mutex<Option<(Vec<&'static str>, Vec<&'static str>)>> = Mutex::new(None);

    fn names(kats: &[KatEntry]) -> Vec<&'static str> {
        kats.iter().map(|k| k.name).collect()
    }

    /// `oxi_init` calls this in place of
    /// `oxicrypt_module::initialize_with_profile` in this crate's tests. It
    /// records what it was given, then forwards the call unchanged.
    pub(super) fn initialize_with_profile(
        integrity: &[KatEntry],
        tests: &[KatEntry],
        profile: AlgorithmProfile,
    ) -> Result<(), Error> {
        *PASSED.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((names(integrity), names(tests)));
        oxicrypt_module::initialize_with_profile(integrity, tests, profile)
    }

    /// Every workspace package in this crate's normal-dependency closure with
    /// default features, on every target platform, except this crate
    /// itself, with hyphens mapped to underscores so they compare against
    /// crate paths. A dependency enabled only by a non-default feature is not
    /// read; the entry points have no features. A package from outside the
    /// workspace is not an `oxicrypt` crate and is not returned.
    ///
    /// Read from Cargo's resolved dependency graph, so a dependency declared
    /// in a sub-table, under `[target.*]` or under another name, and a crate
    /// linked only through another dependency, are all included. The `cargo`
    /// that built this test runs it, offline and against the committed
    /// `Cargo.lock`.
    fn linked_packages() -> BTreeSet<String> {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| env!("CARGO").into());
        let out = std::process::Command::new(cargo)
            .args([
                "tree",
                "--offline",
                "--locked",
                "--manifest-path",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                "-p",
                env!("CARGO_PKG_NAME"),
                "-e",
                "normal",
                "--target",
                "all",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ])
            .output()
            .expect("cargo tree could not be run");
        assert!(
            out.status.success(),
            "cargo tree failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
            .canonicalize()
            .expect("the workspace root is readable");
        String::from_utf8(out.stdout)
            .expect("cargo tree printed non-UTF-8")
            .lines()
            .filter(|l| {
                // `name vX.Y.Z (/path/to/package)`; a registry or git
                // package prints no path and is not a workspace crate.
                l.split_once(" (")
                    .and_then(|(_, rest)| rest.split_once(')'))
                    .and_then(|(dir, _)| std::path::Path::new(dir).canonicalize().ok())
                    .is_some_and(|dir| dir.starts_with(&root))
            })
            .filter_map(|l| l.split_whitespace().next())
            .filter(|p| *p != env!("CARGO_PKG_NAME"))
            .map(|p| p.replace('-', "_"))
            .collect()
    }

    /// `oxi_init` runs what `power_up_set` returns. Every approved
    /// algorithm crate this library links must have all of its KATs in
    /// that set, each exactly once, and nothing else may be in it.
    ///
    /// The linked set is the library's resolved dependency graph, so
    /// linking an algorithm crate, directly or through another
    /// dependency, without adding its `KATS` to `power_up.rs` fails here.
    /// Entries are attributed to a crate by membership in that crate's
    /// own `KATS` slice, matched by name; names are checked unique across
    /// all slices first so that one crate's entry cannot stand in for
    /// another's.
    #[test]
    fn power_up_set_covers_every_linked_algorithm_crate() {
        let linked = linked_packages();
        assert!(
            linked.contains("oxicrypt_module") && linked.len() >= 10,
            "read {linked:?} from cargo tree; the dependency reader is broken"
        );

        let mut all_names = BTreeSet::new();
        for (krate, slice) in KATS_BY_CRATE {
            assert!(!slice.is_empty(), "{krate} publishes an empty KATS slice");
            for kat in *slice {
                assert!(
                    all_names.insert(kat.name),
                    "KAT name {} is not unique across crates",
                    kat.name
                );
            }
        }

        let (integrity, kats) = power_up_set();
        assert_eq!(names(integrity), names(oxicrypt_integrity::KATS));
        let mut run = BTreeSet::new();
        for kat in &kats {
            assert!(run.insert(kat.name), "{} runs twice at oxi_init", kat.name);
        }

        for (krate, reason) in NOT_ALGORITHM_CRATES {
            assert!(!reason.is_empty());
            assert!(
                linked.contains(*krate),
                "the exemption names {krate}, which this library no longer links; remove it"
            );
        }

        let exempt: BTreeSet<&str> = NOT_ALGORITHM_CRATES.iter().map(|(c, _)| *c).collect();
        let mut expected = 0usize;
        let mut not_self_tested = Vec::new();
        for krate in linked.iter().filter(|c| !exempt.contains(c.as_str())) {
            let Some((_, slice)) = KATS_BY_CRATE.iter().find(|(k, _)| k == krate) else {
                panic!(
                    "{krate} is linked but KATS_BY_CRATE has no entry for it; \
                     add its KATS here and to power_up.rs"
                );
            };
            expected += slice.len();
            if slice.iter().any(|k| !run.contains(k.name)) {
                not_self_tested.push(krate.as_str());
            }
        }
        assert!(
            not_self_tested.is_empty(),
            "linked but missing from oxi_init's power-up set: {not_self_tested:?}"
        );
        assert_eq!(
            kats.len(),
            expected,
            "oxi_init runs KATs from a crate that is not a linked algorithm crate"
        );
    }

    /// `oxi_init` hands the module exactly the pair `power_up_set` returns.
    ///
    /// The module is process-global, so this relies on the workspace's test
    /// runner, nextest, running each test in its own process: an `oxi_init`
    /// that found the module already operational would not call it.
    #[test]
    fn oxi_init_passes_its_power_up_set_to_the_module() {
        // The integrity test fails in an unsigned test binary, so the call
        // itself fails; what it passed is recorded first.
        let _ = oxi_init(0);
        let (integrity, tests) = PASSED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("oxi_init did not call initialize_with_profile");
        let (want_integrity, want_tests) = power_up_set();
        assert_eq!(integrity, names(want_integrity));
        assert_eq!(tests, names(&want_tests));
        assert!(!tests.is_empty());
    }
}

#[cfg(test)]
mod lama_tests {
    use super::LAMA_MANIFEST;

    /// The fingerprint query checks its buffer before anything else, and
    /// writes nothing when no fingerprint is known. Its value against a real
    /// key is checked by the C refusal test.
    #[test]
    fn the_fingerprint_query_checks_its_buffer() {
        // SAFETY: a null pointer is refused before any write.
        assert_eq!(
            unsafe { crate::oxi_integrity_key_fingerprint(core::ptr::null_mut(), 32) },
            crate::OxiResult::NullPointer as core::ffi::c_int
        );
        let mut short = [0xaau8; 31];
        // SAFETY: `short` is valid for 31 bytes, the length passed.
        assert_eq!(
            unsafe { crate::oxi_integrity_key_fingerprint(short.as_mut_ptr(), short.len()) },
            crate::OxiResult::BufferTooSmall as core::ffi::c_int
        );
        assert_eq!(short, [0xaa; 31], "a short buffer is not written");
        if oxicrypt_integrity::verify_key_fingerprint().is_none() {
            let mut exact = [0xaau8; 32];
            // SAFETY: `exact` is valid for 32 bytes.
            assert_eq!(
                unsafe { crate::oxi_integrity_key_fingerprint(exact.as_mut_ptr(), exact.len()) },
                crate::OxiResult::NotOperational as core::ffi::c_int
            );
            assert_eq!(exact, [0xaa; 32]);
        }
    }

    /// The detail query sizes its output and refuses a short buffer.
    #[test]
    fn the_detail_query_reports_its_size() {
        let mut written = usize::MAX;
        // SAFETY: a null `written` is refused before any write.
        assert_eq!(
            unsafe {
                crate::oxi_integrity_status_detail(core::ptr::null_mut(), 0, core::ptr::null_mut())
            },
            crate::OxiResult::NullPointer as core::ffi::c_int
        );
        // SAFETY: `out` is null with length 0, `written` is a live local.
        let rc = unsafe {
            crate::oxi_integrity_status_detail(core::ptr::null_mut(), 0, &raw mut written)
        };
        match oxicrypt_integrity::status_detail() {
            None => {
                assert_eq!(rc, crate::OxiResult::NotOperational as core::ffi::c_int);
                assert_eq!(written, 0);
            }
            Some(text) => {
                assert_eq!(rc, crate::OxiResult::BufferTooSmall as core::ffi::c_int);
                assert_eq!(written, text.len() + 1);
            }
        }
    }

    /// The embedded manifest must not contain either integrity-slot magic.
    ///
    /// The artifact's integrity slot is located by scanning its on-disk
    /// bytes for a header/footer magic pair, and a second match anywhere in
    /// the file makes the signer refuse the artifact as ambiguous, a hard
    /// failure.
    ///
    /// Both magics lead with `0xfc` / `0xfd`, which are not legal UTF-8 lead
    /// bytes, and the manifest is valid UTF-8, so the manifest cannot
    /// contain either. This test fails if a change to the magics or to the
    /// embedding breaks that.
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

#[cfg(test)]
#[allow(clippy::panic)]
mod partial_output_tests {
    use super::*;
    use crate::rbg::WRITES_BEFORE_REFUSAL;
    use core::ptr;

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// Makes the module operational.
    fn setup() {
        match oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
            Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => {}
            Err(e) => panic!("module failed to initialise: {e:?}"),
        }
    }

    /// A two-output key generation whose second write is refused zeroizes
    /// the first output: no private key survives a failed call.
    #[test]
    fn second_write_refused_zeroizes_first_output() {
        setup();
        let mut drbg = ptr::null_mut();
        let mut private = [0xA5_u8; 32];
        let mut public = [0x5A_u8; 65];
        // SAFETY: `drbg` is a writable local and the handle is live from
        // `_new` to `_free`; both key buffers are writable locals of the
        // sizes the function writes.
        let (healthy, refused) = unsafe {
            assert_eq!(crate::drbg::oxi_hmac_drbg_sha256_new(&raw mut drbg), 0);
            assert_eq!(
                crate::drbg::oxi_hmac_drbg_sha256_instantiate_from_module(drbg, ptr::null(), 0),
                0
            );
            let healthy =
                oxi_ecdh_p256_generate_keypair(drbg, private.as_mut_ptr(), public.as_mut_ptr());
            let written = private.iter().any(|&b| b != 0xA5 && b != 0);
            assert!(written, "the healthy call wrote no private key");
            private = [0xA5_u8; 32];
            WRITES_BEFORE_REFUSAL.set(Some(1));
            let refused =
                oxi_ecdh_p256_generate_keypair(drbg, private.as_mut_ptr(), public.as_mut_ptr());
            crate::drbg::oxi_hmac_drbg_sha256_free(drbg);
            (healthy, refused)
        };
        assert_eq!(healthy, R::Ok as c_int);
        assert_eq!(refused, R::NotOperational as c_int);
        assert_eq!(
            WRITES_BEFORE_REFUSAL.get(),
            None,
            "the refusal was not reached"
        );
        assert!(
            private.iter().all(|&b| b == 0),
            "the first output survived the failed second write"
        );
    }

    /// A staged single output whose write is refused zeroizes the caller's
    /// buffer.
    #[test]
    fn staged_output_refused_zeroizes_out() {
        setup();
        let mut out = [0xA5_u8; 16];
        WRITES_BEFORE_REFUSAL.set(Some(0));
        // SAFETY: `out` is a writable local of 16 bytes.
        let code = unsafe {
            staged_output(out.as_mut_ptr(), out.len(), 17, |buf| {
                buf.fill(7);
                R::Ok as c_int
            })
        };
        assert_eq!(code, R::NotOperational as c_int);
        assert!(out.iter().all(|&b| b == 0), "{out:?}");
        out = [0xA5_u8; 16];
        // SAFETY: as above.
        let code = unsafe {
            staged_output(out.as_mut_ptr(), out.len(), 17, |buf| {
                buf.fill(7);
                R::InvalidInput as c_int
            })
        };
        assert_eq!(code, R::InvalidInput as c_int);
        assert!(out.iter().all(|&b| b == 0), "{out:?}");
        // SAFETY: as above.
        let code = unsafe {
            staged_output(out.as_mut_ptr(), out.len(), 17, |buf| {
                buf.fill(7);
                R::Ok as c_int
            })
        };
        assert_eq!(code, R::Ok as c_int);
        assert!(out.iter().all(|&b| b == 7), "{out:?}");
    }

    /// A request of `cap` bytes or more is refused for its length and writes
    /// nothing to the caller's buffer: at `cap`, where `fill` refuses the
    /// length, and above it, where the request is staged at `cap` and even a
    /// `fill` that accepts the staged buffer is refused.
    #[test]
    fn staged_output_length_refusal_writes_nothing() {
        setup();
        let cases = [
            (17, R::OutputTooLong as c_int),
            (32, R::OutputTooLong as c_int),
            (32, R::Ok as c_int),
        ];
        for (len, fill_code) in cases {
            let mut out = [0xA5_u8; 32];
            // SAFETY: `out` is a writable local of at least `len` bytes.
            let code = unsafe {
                staged_output(out.as_mut_ptr(), len, 17, |buf| {
                    assert_eq!(buf.len(), 17, "the request was not staged at cap");
                    buf.fill(7);
                    fill_code
                })
            };
            assert_ne!(code, R::Ok as c_int, "len {len}");
            assert!(out.iter().all(|&b| b == 0xA5), "len {len}: {out:?}");
        }
    }

    /// A request below `cap` whose `fill` fails leaves the caller's buffer
    /// zeroized for its length and no further.
    #[test]
    fn staged_output_failed_fill_zeroizes_len_bytes() {
        setup();
        let mut out = [0xA5_u8; 32];
        // SAFETY: `out` is a writable local of 32 bytes.
        let code = unsafe {
            staged_output(out.as_mut_ptr(), 16, 17, |buf| {
                buf.fill(7);
                R::InvalidInput as c_int
            })
        };
        assert_eq!(code, R::InvalidInput as c_int);
        assert!(out[..16].iter().all(|&b| b == 0), "{out:?}");
        assert!(out[16..].iter().all(|&b| b == 0xA5), "{out:?}");
    }
}
