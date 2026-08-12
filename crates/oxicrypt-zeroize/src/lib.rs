//! Volatile zeroization for sensitive security parameters.
//!
//! This is one of the in-boundary crates in the oxicrypt
//! workspace that use `unsafe` (the others are `oxicrypt-sha-accel`,
//! `oxicrypt-aes-accel`, `oxicrypt-keccak-accel` and `oxicrypt-timer`).
//! It provides three functions — [`zeroize`], [`zeroize_u32`] and
//! [`zeroize_u64`] — that write zeroes through volatile stores. All other in-boundary
//! crates remain `#![forbid(unsafe_code)]`; the authoritative
//! unsafe-code accounting lives in
//! `docs/security-policy/security-policy.md` §9.2.
//!
//! # Why a separate crate?
//!
//! FIPS 140-3 requires a module to provide methods to zeroise
//! unprotected SSPs at every level (AS09.28, ISO/IEC 19790:2012
//! §7.9.7). Zeroising temporary SSPs when they are no longer
//! needed is AS09.32, which applies at Levels 2 and above; this
//! module targets Level 1 and zeroises on drop regardless. The
//! standard Rust `Drop` path
//! can be optimised away by LLVM if the dead-store eliminator
//! determines the memory is never read. `write_volatile` is the
//! portable, stable mechanism to prevent that.
//!
//! Isolating the `unsafe` in three small loops makes
//! the security-relevant code trivially auditable: there are
//! exactly three `unsafe` blocks in the entire module, each a
//! `write_volatile` of a zero, and the soundness argument for each
//! is that it writes to owned, aligned, valid
//! memory — the same memory the caller already has a mutable
//! reference to.
//!
//! # Constant-time note
//!
//! `write_volatile` issues a store to every byte unconditionally;
//! the store width and order are implementation-defined. This is
//! adequate for zeroization but is **not** a constant-time
//! comparison or copy.

#![no_std]
// This crate deliberately uses unsafe for volatile writes.
// Every other in-boundary crate except oxicrypt-sha-accel,
// oxicrypt-aes-accel, oxicrypt-keccak-accel and oxicrypt-timer forbids
// unsafe.
#![deny(unsafe_op_in_unsafe_fn)]

/// Overwrite `buf` with zeroes using a volatile store.
///
/// `core::ptr::write_volatile` documents volatile operations as
/// externally observable events that are guaranteed not to be elided
/// or reordered by the compiler, so the write survives dead-store
/// elimination even when the buffer is about to be deallocated. That
/// guarantee is the language's, not this crate's — nothing here
/// establishes it and no test can observe it.
/// The `zeroize*` functions in this crate are what `Drop`
/// implementations on CSP-holding types call across the workspace.
///
/// # Examples
///
/// ```
/// let mut secret = [0xFFu8; 32];
/// oxicrypt_zeroize::zeroize(&mut secret);
/// assert!(secret.iter().all(|&b| b == 0));
/// ```
#[inline]
pub fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, dereferenceable pointer
        // to a byte within `buf` — we have `&mut` access. The volatile
        // write prevents dead-store elimination.
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

/// Overwrite a `[u32]` slice with zeroes using volatile stores.
///
/// Used by SHA-1 and SHA-2 (32-bit) types whose internal state is
/// `[u32; N]` word arrays.
#[inline]
pub fn zeroize_u32(buf: &mut [u32]) {
    for word in buf.iter_mut() {
        // SAFETY: same argument as `zeroize` — valid, aligned, owned.
        unsafe {
            core::ptr::write_volatile(word, 0);
        }
    }
}

/// Overwrite a `[u64]` slice with zeroes using volatile stores.
///
/// Used by SHA-512 and the Keccak sponge state, and by RSA bigint
/// types whose internal representation is `[u64; N]` limb arrays.
#[inline]
pub fn zeroize_u64(buf: &mut [u64]) {
    for limb in buf.iter_mut() {
        // SAFETY: same argument as `zeroize` — valid, aligned, owned.
        unsafe {
            core::ptr::write_volatile(limb, 0);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_clears_bytes() {
        let mut buf = [0xAA_u8; 64];
        zeroize(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_u64_clears_limbs() {
        let mut buf = [0xDEAD_BEEF_u64; 16];
        zeroize_u64(&mut buf);
        assert!(buf.iter().all(|&l| l == 0));
    }

    #[test]
    fn zeroize_empty_slice_is_noop() {
        let mut buf: [u8; 0] = [];
        zeroize(&mut buf);
        // No panic, no UB.
    }
}
