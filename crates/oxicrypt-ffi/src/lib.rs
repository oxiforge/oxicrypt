//! C ABI wrappers for oxicrypt approved services.
//!
//! This crate provides `extern "C"` entry points that language
//! bindings (Python, Go, Node, etc.) can call via their FFI
//! mechanisms. The underlying Rust implementations remain pure-
//! Rust, `no_std`-friendly, and inside the FIPS 140-3 cryptographic
//! boundary; this crate is a thin translation layer that sits
//! outside that boundary.
//!
//! # Conventions
//!
//! Every function returns an `i32` status code:
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | Success |
//! | `-1` | Module not operational (power-up self-tests not run) |
//! | `-2` | Invalid input (null pointer, wrong length, etc.) |
//! | `-3` | Cryptographic operation failed |
//!
//! Output buffers are caller-allocated. The caller must ensure
//! they are at least as large as the documented minimum size.
//!
//! # Safety
//!
//! All functions in this crate are `unsafe` because they accept
//! raw pointers from C callers. Every function performs null checks
//! and length validation before dereferencing any pointer.
//!
//! # Initialisation
//!
//! The module must be initialised by calling [`oxicrypt_init`]
//! before any cryptographic function. This runs all power-up
//! KATs. Calling a cryptographic function before init returns
//! status code `-1`.

// This crate is the FFI boundary — unsafe is required by definition.
#![allow(unsafe_code, clippy::missing_safety_doc)]

// ── Status codes ─────────────────────────────────────────────────

/// Operation succeeded.
const OK: i32 = 0;
/// Module not operational.
const ERR_NOT_OPERATIONAL: i32 = -1;
/// Invalid input (null pointer, wrong length, bad key, etc.).
const ERR_INVALID_INPUT: i32 = -2;
/// Cryptographic operation failed.
#[allow(dead_code)]
const ERR_CRYPTO_FAILED: i32 = -3;

// ── Helpers ──────────────────────────────────────────────────────

/// Convert a module `Error` to an FFI status code.
fn status(r: Result<(), oxicrypt_module::Error>) -> i32 {
    match r {
        Ok(()) => OK,
        Err(oxicrypt_module::Error::NotOperational { .. }) => ERR_NOT_OPERATIONAL,
        _ => ERR_INVALID_INPUT,
    }
}

/// Build a `&[u8]` from a raw pointer and length, returning
/// `ERR_INVALID_INPUT` on null.
///
/// # Safety
///
/// The caller must ensure the pointer is valid for `len` bytes.
unsafe fn slice_from_raw(ptr: *const u8, len: usize) -> Result<&'static [u8], i32> {
    if ptr.is_null() && len > 0 {
        return Err(ERR_INVALID_INPUT);
    }
    if len == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Build a `&mut [u8]` from a raw pointer and length.
///
/// # Safety
///
/// The caller must ensure the pointer is valid for `len` bytes.
unsafe fn slice_from_raw_mut(ptr: *mut u8, len: usize) -> Result<&'static mut [u8], i32> {
    if ptr.is_null() && len > 0 {
        return Err(ERR_INVALID_INPUT);
    }
    if len == 0 {
        // Return a valid empty slice even for null ptr with len=0.
        return Ok(&mut []);
    }
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

// ── Module lifecycle ─────────────────────────────────────────────

/// Initialise the FIPS module, running all power-up KATs.
///
/// Must be called exactly once before any other `oxicrypt_*`
/// function. Returns `0` on success or a negative error code.
///
/// # Safety
///
/// No pointers; always safe to call.
#[no_mangle]
pub extern "C" fn oxicrypt_init() -> i32 {
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
    match oxicrypt_module::initialize_with_tests(&merged) {
        Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => OK,
        Err(e) => status(Err(e)),
    }
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
pub unsafe extern "C" fn oxicrypt_sha256(
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return ERR_INVALID_INPUT;
    }
    match oxicrypt_sha::sha256(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
            OK
        }
        Err(oxicrypt_module::Error::NotOperational { .. }) => ERR_NOT_OPERATIONAL,
        Err(_) => ERR_INVALID_INPUT,
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
pub unsafe extern "C" fn oxicrypt_sha512(
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return ERR_INVALID_INPUT;
    }
    match oxicrypt_sha::sha512(data) {
        Ok(digest) => {
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 64) };
            OK
        }
        Err(oxicrypt_module::Error::NotOperational { .. }) => ERR_NOT_OPERATIONAL,
        Err(_) => ERR_INVALID_INPUT,
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
pub unsafe extern "C" fn oxicrypt_hmac_sha256(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    let key = match unsafe { slice_from_raw(key_ptr, key_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match unsafe { slice_from_raw(data_ptr, data_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if out.is_null() {
        return ERR_INVALID_INPUT;
    }
    let mut mac = match oxicrypt_hmac::HmacSha256::new(key) {
        Ok(m) => m,
        Err(oxicrypt_module::Error::NotOperational { .. }) => return ERR_NOT_OPERATIONAL,
        Err(_) => return ERR_INVALID_INPUT,
    };
    mac.update(data);
    let tag = mac.finalize();
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out, 32) };
    OK
}

// ── AES-256-GCM ──────────────────────────────────────────────────

/// Encrypt with AES-256-GCM (96-bit IV, 128-bit tag).
///
/// `ct_out` must be at least `pt_len` bytes; `tag_out` at least 16.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxicrypt_aes256_gcm_encrypt(
    key_ptr: *const u8,          // 32 bytes
    iv_ptr: *const u8,           // 12 bytes
    aad_ptr: *const u8,
    aad_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    ct_out: *mut u8,             // pt_len bytes
    tag_out: *mut u8,            // 16 bytes
) -> i32 {
    if key_ptr.is_null() || iv_ptr.is_null() || ct_out.is_null() || tag_out.is_null() {
        return ERR_INVALID_INPUT;
    }
    let key_bytes: &[u8; 32] = unsafe { &*(key_ptr.cast::<[u8; 32]>()) };
    let iv: &[u8; 12] = unsafe { &*(iv_ptr.cast::<[u8; 12]>()) };
    let aad = match unsafe { slice_from_raw(aad_ptr, aad_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let pt = match unsafe { slice_from_raw(pt_ptr, pt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct = match unsafe { slice_from_raw_mut(ct_out, pt_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let tag: &mut [u8; 16] = unsafe { &mut *(tag_out.cast::<[u8; 16]>()) };

    let key = oxicrypt_aes::Aes256Key::new(key_bytes);
    match oxicrypt_aes::gcm_encrypt(&key, iv, aad, pt, ct, tag) {
        Ok(()) => OK,
        Err(_) => ERR_INVALID_INPUT,
    }
}

/// Decrypt with AES-256-GCM (96-bit IV, 128-bit tag).
///
/// Returns `0` on success (tag valid) or `-3` on tag mismatch.
/// `pt_out` must be at least `ct_len` bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn oxicrypt_aes256_gcm_decrypt(
    key_ptr: *const u8,          // 32 bytes
    iv_ptr: *const u8,           // 12 bytes
    aad_ptr: *const u8,
    aad_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    tag_ptr: *const u8,          // 16 bytes
    pt_out: *mut u8,             // ct_len bytes
) -> i32 {
    if key_ptr.is_null() || iv_ptr.is_null() || tag_ptr.is_null() || pt_out.is_null() {
        return ERR_INVALID_INPUT;
    }
    let key_bytes: &[u8; 32] = unsafe { &*(key_ptr.cast::<[u8; 32]>()) };
    let iv: &[u8; 12] = unsafe { &*(iv_ptr.cast::<[u8; 12]>()) };
    let aad = match unsafe { slice_from_raw(aad_ptr, aad_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ct = match unsafe { slice_from_raw(ct_ptr, ct_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let tag: &[u8; 16] = unsafe { &*(tag_ptr.cast::<[u8; 16]>()) };
    let pt = match unsafe { slice_from_raw_mut(pt_out, ct_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let key = oxicrypt_aes::Aes256Key::new(key_bytes);
    match oxicrypt_aes::gcm_decrypt(&key, iv, aad, ct, tag, pt) {
        Ok(()) => OK,
        Err(_) => ERR_CRYPTO_FAILED,
    }
}
