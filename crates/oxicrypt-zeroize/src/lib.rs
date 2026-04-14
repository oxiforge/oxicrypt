//! Volatile zeroization for sensitive security parameters.
//!
//! This is the **only** crate in the oxicrypt workspace that uses
//! `unsafe`. It provides a single function, [`zeroize`], that
//! writes zeroes through a volatile store so the compiler cannot
//! elide the write even if it can prove the buffer is never read
//! again. All other crates remain `#![forbid(unsafe_code)]`.
//!
//! # Why a separate crate?
//!
//! FIPS 140-3 Level 1 requires that CSPs are zeroized when they
//! are no longer needed (IG 7.7). The standard Rust `Drop` path
//! can be optimised away by LLVM if the dead-store eliminator
//! determines the memory is never read. `write_volatile` is the
//! portable, stable mechanism to prevent that.
//!
//! Isolating the `unsafe` in a single three-line function makes
//! the security-relevant code trivially auditable: there is
//! exactly one `unsafe` block in the entire module, and its
//! soundness argument is that it writes to owned, aligned, valid
//! memory — the same memory the caller already has a mutable
//! reference to.
//!
//! # Constant-time note
//!
//! `write_volatile` issues a store to every byte unconditionally;
//! the store width and order are implementation-defined but
//! there is no data-dependent branching. This is adequate for
//! zeroization but is **not** a constant-time comparison or copy.

#![no_std]
// This crate deliberately uses unsafe for volatile writes.
// Every other crate in the workspace forbids unsafe.
#![deny(unsafe_op_in_unsafe_fn)]

/// Overwrite `buf` with zeroes using a volatile store.
///
/// The volatile semantics prevent the compiler from eliding
/// the write even if the buffer is about to be deallocated.
/// This is the primitive used by every `Drop` implementation
/// on CSP-holding types across the workspace.
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

/// Overwrite a `[u64]` slice with zeroes using volatile stores.
///
/// Used by RSA bigint types whose internal representation is
/// `[u64; N]` limb arrays.
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
