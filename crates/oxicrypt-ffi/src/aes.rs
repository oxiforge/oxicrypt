//! AES-256-GCM C ABI exposure with opaque key handle.
//!
//! One-shot encryption / decryption only — streaming AES-GCM exposure
//! is deferred per PRD Decision D1 (the underlying `oxicrypt-aes`
//! public API does not expose streaming GCM yet, and exposing a
//! caller-managed streaming surface ahead of the Rust API would
//! invert the dependency direction).
//!
//! # Lifecycle
//!
//! ```c
//! OxiAes256Key *key = NULL;
//! if (oxi_aes256_new(&key, key_bytes_32) != 0) { /* handle error */ }
//! oxi_aes256_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len, ct, tag);
//! oxi_aes256_free(key);
//! ```
//!
//! `oxi_aes256_free(NULL)` is a safe no-op. The caller should NULL
//! their pointer after free; the shim cannot detect a double-free
//! across the heap and a true double-free is undefined behaviour
//! (matches malloc/free semantics).
//!
//! # Reviewer-framing
//!
//! - F4 — distinct error variants per failure mode: AAD-NULL-with-zero-len
//!   is `Ok` (AAD is logically defined by length per SP 800-38D);
//!   tag mismatch returns `OxiResult::TagMismatch = 22`, not a generic
//!   "operation failed".
//! - F5 — safe-no-op-after-free: NULL-safe `_free` plus `OxiHandle<T>`
//!   consumed-sentinel pattern (handle.rs §4.8 in the security policy).
//! - F9 — NULL-AAD-with-len-0 allowed: SP 800-38D defines AAD logically
//!   by length, not by pointer presence. The shim mirrors the Rust
//!   `slice_from_raw` helper, which returns an empty slice for the
//!   `(null, 0)` case.

use crate::error::{status_aes, OxiResult as R};
use crate::handle::OxiHandle;
use crate::{slice_from_raw, slice_from_raw_mut};
use core::ffi::c_int;
use oxicrypt_aes::{gcm_decrypt, gcm_encrypt, Aes256Key};
use oxicrypt_module::{require_allowed, Service};

/// Opaque AES-256 key handle. The internal layout
/// (`OxiHandle<Aes256Key>`) is implementation detail and not part
/// of the C ABI; cbindgen renders this as an opaque struct.
///
/// cbindgen:opaque
pub struct OxiAes256Key {
    inner: OxiHandle<Aes256Key>,
}

/// Allocate a new AES-256 key handle from raw 32-byte key material.
///
/// On success, writes a heap-allocated handle pointer through
/// `out_handle` and returns `OxiResult::Ok = 0`. The caller owns the
/// handle and MUST release it with [`oxi_aes256_free`].
///
/// # Safety
///
/// - `out_handle` must be a valid pointer to a writable
///   `*mut OxiAes256Key`.
/// - `key` must point to at least 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_new(
    out_handle: *mut *mut OxiAes256Key,
    key: *const u8,
) -> c_int {
    if out_handle.is_null() || key.is_null() {
        return R::NullPointer as c_int;
    }
    let key_bytes: &[u8; 32] = unsafe { &*(key.cast::<[u8; 32]>()) };
    match Aes256Key::new(key_bytes) {
        Ok(k) => {
            let boxed = Box::new(OxiAes256Key {
                inner: OxiHandle::new(k),
            });
            unsafe { *out_handle = Box::into_raw(boxed) };
            R::Ok as c_int
        }
        Err(e) => crate::error::status_module(Err(e)),
    }
}

/// Free an AES-256 key handle. NULL-safe.
///
/// After this call the caller's pointer is dangling; the caller
/// SHOULD set their pointer to NULL to avoid use-after-free. A
/// double-free of the same non-NULL pointer is undefined behaviour
/// (matches malloc/free semantics — the shim cannot detect it).
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_aes256_new`] that has not yet been freed.
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_free(handle: *mut OxiAes256Key) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// AES-256-GCM authenticated encryption (one-shot).
///
/// Buffer requirements:
/// - `iv` — exactly 12 readable bytes (96-bit nonce).
/// - `aad` — `aad_len` readable bytes if `aad_len > 0`; may be NULL
///   when `aad_len == 0` (per F9).
/// - `plaintext` — `pt_len` readable bytes; may be NULL when
///   `pt_len == 0`.
/// - `ciphertext` — `pt_len` writable bytes.
/// - `tag` — exactly 16 writable bytes (128-bit authentication tag).
///
/// Returns `OxiResult::Ok = 0` on success or a non-zero discriminant
/// per the [`OxiResult`] mapping. `OxiResult::AlgorithmRestricted = 6`
/// is returned when AES-256-GCM is blocked by the active profile.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_gcm_encrypt(
    key: *const OxiAes256Key,
    iv: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    ciphertext: *mut u8,
    tag: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || tag.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Gcm) {
        return crate::error::status_module(Err(e));
    }
    // SAFETY: per the handle lifecycle contract documented in security
    // policy §4.8, the caller MUST not race `_free` against an in-flight
    // `_gcm_*` call on the same handle. AES-GCM is one-shot so the
    // `&self`-only `as_ref` projection cannot witness a torn `Option`,
    // but a future streaming/finalize-bearing handle will need stronger
    // synchronization between the consumed flag and the inner read.
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let iv_slice: &[u8; 12] = unsafe { &*(iv.cast::<[u8; 12]>()) };
    let aad_slice = match unsafe { slice_from_raw(aad, aad_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let pt_slice = match unsafe { slice_from_raw(plaintext, pt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct_slice = match unsafe { slice_from_raw_mut(ciphertext, pt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let tag_arr: &mut [u8; 16] = unsafe { &mut *(tag.cast::<[u8; 16]>()) };
    status_aes(gcm_encrypt(
        key_ref, iv_slice, aad_slice, pt_slice, ct_slice, tag_arr,
    ))
}

/// AES-256-GCM authenticated decryption (one-shot).
///
/// Returns `OxiResult::TagMismatch = 22` on authentication failure.
/// On tag mismatch the `plaintext` buffer contents are UNDEFINED —
/// the caller MUST NOT use them. (FIPS 140-3 expects the
/// implementation to release the plaintext only after successful
/// tag verification, but operating-system buffers may have been
/// touched during the constant-time tag check; treat the buffer as
/// untrusted on any non-Ok return.)
///
/// Buffer requirements identical to [`oxi_aes256_gcm_encrypt`] with
/// `ciphertext`/`plaintext` directions swapped and `tag` as input.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_gcm_decrypt(
    key: *const OxiAes256Key,
    iv: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ct_len: usize,
    plaintext: *mut u8,
    tag: *const u8,
) -> c_int {
    if key.is_null() || iv.is_null() || tag.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Gcm) {
        return crate::error::status_module(Err(e));
    }
    // SAFETY: see corresponding note in `oxi_aes256_gcm_encrypt`.
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let iv_slice: &[u8; 12] = unsafe { &*(iv.cast::<[u8; 12]>()) };
    let aad_slice = match unsafe { slice_from_raw(aad, aad_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct_slice = match unsafe { slice_from_raw(ciphertext, ct_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let pt_slice = match unsafe { slice_from_raw_mut(plaintext, ct_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let tag_arr: &[u8; 16] = unsafe { &*(tag.cast::<[u8; 16]>()) };
    status_aes(gcm_decrypt(
        key_ref, iv_slice, aad_slice, ct_slice, tag_arr, pt_slice,
    ))
}
