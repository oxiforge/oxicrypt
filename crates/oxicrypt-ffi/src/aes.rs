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
use oxicrypt_aes::{
    cbc_decrypt, cbc_encrypt, ccm_decrypt, ccm_encrypt, ctr_xor, gcm_decrypt, gcm_encrypt,
    kw_unwrap, kw_wrap, kwp_unwrap, kwp_wrap, Aes256Key,
};
use oxicrypt_cmac::cmac_tag;
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
/// per the [`crate::OxiResult`] mapping. `OxiResult::AlgorithmRestricted = 6`
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

// ── AES-256-CBC ──────────────────────────────────────────────────
//
// Confidentiality-only mode (no authentication). Inputs and outputs
// must be block-aligned (multiples of 16 bytes); padding is the
// caller's responsibility. SP 800-38A §6.2.

/// AES-256-CBC encryption (one-shot).
///
/// Buffer requirements:
/// - `iv` — exactly 16 readable bytes.
/// - `input` — `input_len` readable bytes; must be a positive multiple of 16.
/// - `output` — `input_len` writable bytes.
///
/// Returns `OxiResult::NotBlockAligned = 20` when `input_len` is not
/// a multiple of 16, `OxiResult::LengthMismatch = 23` when the output
/// buffer length doesn't match.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_cbc_encrypt(
    key: *const OxiAes256Key,
    iv: *const u8,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Cbc) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let iv_slice: &[u8; 16] = unsafe { &*(iv.cast::<[u8; 16]>()) };
    let pt_slice = match unsafe { slice_from_raw(input, input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct_slice = match unsafe { slice_from_raw_mut(output, input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_aes(cbc_encrypt(key_ref, iv_slice, pt_slice, ct_slice))
}

/// AES-256-CBC decryption (one-shot).
///
/// Buffer requirements identical to [`oxi_aes256_cbc_encrypt`] with
/// input/output directions reversed.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_cbc_decrypt(
    key: *const OxiAes256Key,
    iv: *const u8,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Cbc) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let iv_slice: &[u8; 16] = unsafe { &*(iv.cast::<[u8; 16]>()) };
    let ct_slice = match unsafe { slice_from_raw(input, input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let pt_slice = match unsafe { slice_from_raw_mut(output, input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_aes(cbc_decrypt(key_ref, iv_slice, ct_slice, pt_slice))
}

// ── AES-256-CTR ──────────────────────────────────────────────────
//
// Confidentiality-only stream-cipher mode (block cipher used as
// keystream generator). The XOR operation is symmetric: a single
// entry point handles both encrypt and decrypt directions. Caller
// supplies the full 16-byte initial counter block (ICB) — the FFI
// does not impose a particular nonce/counter split, mirroring SP
// 800-38A §6.5's Appendix B which leaves that to the caller.

/// AES-256-CTR XOR (one-shot).
///
/// Buffer requirements:
/// - `icb` — exactly 16 readable bytes (initial counter block).
/// - `input` — `len` readable bytes (any length).
/// - `output` — `len` writable bytes.
///
/// CTR is symmetric: encrypt and decrypt are the same operation.
/// Same `(key, icb)` pair MUST NOT be reused — the caller is
/// responsible for nonce uniqueness within a key (SP 800-38A
/// Appendix B).
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_ctr(
    key: *const OxiAes256Key,
    icb: *const u8,
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || icb.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Ctr) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let icb_slice: &[u8; 16] = unsafe { &*(icb.cast::<[u8; 16]>()) };
    let in_slice = match unsafe { slice_from_raw(input, len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let out_slice = match unsafe { slice_from_raw_mut(output, len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    ctr_xor(key_ref, icb_slice, in_slice, out_slice);
    R::Ok as c_int
}

// ── AES-256-CCM ──────────────────────────────────────────────────
//
// Authenticated-encryption mode (SP 800-38C). Like GCM but with
// caller-chosen tag length and nonce length. The encrypt output is
// `ciphertext || tag` packed into a single buffer of length
// `pt_len + tlen`; decrypt input mirrors that layout.

/// AES-256-CCM authenticated encryption (one-shot).
///
/// Buffer requirements:
/// - `nonce` — `nonce_len` readable bytes; valid range 7..=13 per SP 800-38C.
/// - `aad` — `aad_len` readable bytes if `aad_len > 0`; may be NULL
///   when `aad_len == 0` (per F9, AAD logically defined by length).
/// - `plaintext` — `pt_len` readable bytes; may be NULL when `pt_len == 0`.
/// - `tlen` — tag length in bytes; valid set {4, 6, 8, 10, 12, 14, 16}.
/// - `out` — exactly `pt_len + tlen` writable bytes; layout `C || T`.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_ccm_encrypt(
    key: *const OxiAes256Key,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    tlen: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Ccm) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let nonce_slice = match unsafe { slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let aad_slice = match unsafe { slice_from_raw(aad, aad_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let pt_slice = match unsafe { slice_from_raw(plaintext, pt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(out_total) = pt_len.checked_add(tlen) else {
        return R::LengthMismatch as c_int;
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, out_total) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_aes(ccm_encrypt(
        key_ref,
        nonce_slice,
        aad_slice,
        pt_slice,
        tlen,
        out_slice,
    ))
}

/// AES-256-CCM authenticated decryption (one-shot).
///
/// `ciphertext` is the full `C || T` buffer of length
/// `ct_len = pt_len + tlen`. On success writes the recovered plaintext
/// (length `ct_len - tlen`) into `out`.
///
/// On tag-verification failure returns `OxiResult::TagMismatch = 22`
/// and the upstream zeroises the output buffer so unverified plaintext
/// is never exposed.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_ccm_decrypt(
    key: *const OxiAes256Key,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ct_len: usize,
    tlen: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Ccm) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    if ct_len < tlen {
        return R::LengthMismatch as c_int;
    }
    let nonce_slice = match unsafe { slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let aad_slice = match unsafe { slice_from_raw(aad, aad_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct_slice = match unsafe { slice_from_raw(ciphertext, ct_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    // ct_len >= tlen verified above; checked_sub is belt-and-braces.
    let Some(pt_total) = ct_len.checked_sub(tlen) else {
        return R::LengthMismatch as c_int;
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, pt_total) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_aes(ccm_decrypt(
        key_ref,
        nonce_slice,
        aad_slice,
        ct_slice,
        tlen,
        out_slice,
    ))
}

// ── CMAC-AES-256 ─────────────────────────────────────────────────
//
// MAC over arbitrary-length message under an AES-256 block cipher
// (SP 800-38B). Tag is always 16 bytes (full BLOCK_SIZE); callers
// that need a truncated MAC must truncate at the application layer
// per SP 800-38B §4. CMAC is gated on `Service::CmacAes256` (60-band)
// distinct from the cipher-mode `Aes256*` services (90-band).

/// CMAC-AES-256 (one-shot).
///
/// Buffer requirements:
/// - `msg` — `msg_len` readable bytes; may be NULL when `msg_len == 0`.
/// - `tag` — exactly 16 writable bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_cmac(
    key: *const OxiAes256Key,
    msg: *const u8,
    msg_len: usize,
    tag: *mut u8,
) -> c_int {
    if key.is_null() || tag.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::CmacAes256) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let msg_slice = match unsafe { slice_from_raw(msg, msg_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let t = cmac_tag(key_ref, msg_slice);
    unsafe { core::ptr::copy_nonoverlapping(t.as_ptr(), tag, 16) };
    R::Ok as c_int
}

// ── AES-256-KW / AES-256-KWP ─────────────────────────────────────
//
// SP 800-38F key-wrap modes. KW (§6.2) requires plaintext to be a
// positive multiple of 8 bytes and at least 16 bytes; KWP (§6.3)
// accepts any length from 1 to 2^32 − 1 bytes. Both produce
// `padded_pt_len + 8` bytes of ciphertext. KWP unwrap returns the
// recovered plaintext byte length through `out_len` because the
// padded buffer length is not the message length.

/// AES-256-KW wrap (SP 800-38F §6.2 KW-AE).
///
/// Buffer requirements:
/// - `plaintext` — `pt_len` readable bytes; must be a positive
///   multiple of 8 and at least 16.
/// - `out` — exactly `pt_len + 8` writable bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_kw_wrap(
    key: *const OxiAes256Key,
    plaintext: *const u8,
    pt_len: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Kw) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    let pt_slice = match unsafe { slice_from_raw(plaintext, pt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(out_total) = pt_len.checked_add(8) else {
        return R::LengthMismatch as c_int;
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, out_total) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_aes(kw_wrap(key_ref, pt_slice, out_slice))
}

/// AES-256-KW unwrap (SP 800-38F §6.2 KW-AD).
///
/// Buffer requirements:
/// - `ciphertext` — `ct_len` readable bytes; must be a positive
///   multiple of 8 and at least 24.
/// - `out` — exactly `ct_len - 8` writable bytes.
///
/// Returns `OxiResult::TagMismatch = 22` if the integrity check
/// value did not verify.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_kw_unwrap(
    key: *const OxiAes256Key,
    ciphertext: *const u8,
    ct_len: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Kw) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    if ct_len < 8 {
        return R::LengthMismatch as c_int;
    }
    let ct_slice = match unsafe { slice_from_raw(ciphertext, ct_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    // ct_len >= 8 verified above; checked_sub is belt-and-braces.
    let Some(pt_total) = ct_len.checked_sub(8) else {
        return R::LengthMismatch as c_int;
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, pt_total) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_aes(kw_unwrap(key_ref, ct_slice, out_slice))
}

/// AES-256-KWP wrap (SP 800-38F §6.3 KWP-AE / RFC 5649).
///
/// Buffer requirements:
/// - `plaintext` — `pt_len` readable bytes; must be `1..=2^32-1`.
/// - `out` — exactly `((pt_len + 7) / 8) * 8 + 8` writable bytes
///   (padded plaintext + 8-byte AIV).
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_kwp_wrap(
    key: *const OxiAes256Key,
    plaintext: *const u8,
    pt_len: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Kwp) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    // padded_pt_len = round-up(pt_len, 8); total = padded + 8-byte AIV.
    // Use checked_* so a usize::MAX-class pt_len returns LengthMismatch
    // rather than wrapping (per workspace lint policy).
    let Some(padded_pt_len) = pt_len.div_ceil(8).checked_mul(8) else {
        return R::LengthMismatch as c_int;
    };
    let Some(total) = padded_pt_len.checked_add(8) else {
        return R::LengthMismatch as c_int;
    };
    let pt_slice = match unsafe { slice_from_raw(plaintext, pt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let out_slice = match unsafe { slice_from_raw_mut(out, total) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    status_aes(kwp_wrap(key_ref, pt_slice, out_slice))
}

/// AES-256-KWP unwrap (SP 800-38F §6.3 KWP-AD / RFC 5649).
///
/// Buffer requirements:
/// - `ciphertext` — `ct_len` readable bytes; must be a positive
///   multiple of 8 and at least 16.
/// - `out_scratch` — exactly `ct_len - 8` writable bytes (padded
///   plaintext buffer; only the first `*out_len` bytes are the
///   recovered message after success).
/// - `out_len` — pointer to a `size_t` that receives the recovered
///   plaintext length (≤ `ct_len - 8`) on success.
///
/// Returns `OxiResult::TagMismatch = 22` on AIV / padding mismatch.
/// `*out_len` is unmodified on any non-Ok return.
///
/// # Safety
///
/// All pointer/length pairs must be valid as documented above.
/// `key` must be a live handle from [`oxi_aes256_new`].
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_kwp_unwrap(
    key: *const OxiAes256Key,
    ciphertext: *const u8,
    ct_len: usize,
    out_scratch: *mut u8,
    out_len: *mut usize,
) -> c_int {
    if key.is_null() || out_len.is_null() {
        return R::NullPointer as c_int;
    }
    if let Err(e) = require_allowed(Service::Aes256Kwp) {
        return crate::error::status_module(Err(e));
    }
    let Some(key_ref) = (unsafe { (*key).inner.as_ref() }) else {
        return R::NotOperational as c_int;
    };
    if ct_len < 8 {
        return R::LengthMismatch as c_int;
    }
    let ct_slice = match unsafe { slice_from_raw(ciphertext, ct_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    // ct_len >= 8 verified above; checked_sub is belt-and-braces.
    let Some(scratch_len) = ct_len.checked_sub(8) else {
        return R::LengthMismatch as c_int;
    };
    let scratch = match unsafe { slice_from_raw_mut(out_scratch, scratch_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match kwp_unwrap(key_ref, ct_slice, scratch) {
        Ok(mli) => {
            unsafe { *out_len = mli };
            R::Ok as c_int
        }
        Err(e) => crate::error::OxiResult::from(e) as c_int,
    }
}
