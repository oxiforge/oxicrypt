//! Volatile zeroization for sensitive security parameters.
//!
//! This is one of the in-boundary crates in the oxicrypt workspace that
//! use `unsafe`. It provides five functions — [`zeroize`],
//! [`zeroize_u32`], [`zeroize_i16`], [`zeroize_i32`] and [`zeroize_u64`] —
//! that write zeroes through volatile stores, and one type, the wrapper [`Zeroizing`], whose
//! `Drop` calls [`zeroize`] on the byte buffer it holds.
//! The workspace's `AGENTS.md` names the in-boundary crates that use
//! `unsafe`, and `tools/doc-guard` checks that list against the crates.
//! Every in-boundary crate outside that list is
//! `#![forbid(unsafe_code)]`. The module's Security Policy, withheld
//! from this repository (see `docs/security-policy/README.md`), holds
//! the authoritative accounting.
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
//! Outside its tests the crate has five `unsafe` blocks, one in each
//! of the five loops, each a `write_volatile` of a zero, and the
//! soundness argument for each is that it writes to owned, aligned,
//! valid memory — the same memory the caller already has a mutable
//! reference to.
//!
//! # Constant-time note
//!
//! `write_volatile` issues a store to every byte unconditionally;
//! the store width and order are implementation-defined. This is
//! adequate for zeroization but is **not** a constant-time
//! comparison or copy.

#![no_std]
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

/// Overwrite an `[i16]` slice with zeroes using volatile stores.
///
/// Used by ML-KEM, whose polynomial coefficients are `i16`.
#[inline]
pub fn zeroize_i16(buf: &mut [i16]) {
    for coeff in buf.iter_mut() {
        // SAFETY: same argument as `zeroize` — valid, aligned, owned.
        unsafe {
            core::ptr::write_volatile(coeff, 0);
        }
    }
}

/// Overwrite an `[i32]` slice with zeroes using volatile stores.
///
/// Used by ML-DSA, whose polynomial coefficients are `i32`.
#[inline]
pub fn zeroize_i32(buf: &mut [i32]) {
    for coeff in buf.iter_mut() {
        // SAFETY: same argument as `zeroize` — valid, aligned, owned.
        unsafe {
            core::ptr::write_volatile(coeff, 0);
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

/// A byte buffer whose contents are a critical security parameter,
/// wiped with a volatile store when dropped.
///
/// The wrapper dereferences to the buffer it holds, and its `Drop`
/// implementation passes `as_mut()` to [`zeroize`].
///
/// # Examples
///
/// ```
/// use oxicrypt_zeroize::Zeroizing;
///
/// let mut key = Zeroizing::new([0u8; 32]);
/// key[0] = 0x42;
/// assert_eq!(key[0], 0x42);
/// // The 32 bytes are zeroed when `key` goes out of scope.
/// ```
pub struct Zeroizing<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> Zeroizing<T> {
    /// Wraps `value`, a byte buffer whose contents are a critical
    /// security parameter, so that its bytes are wiped with a volatile
    /// store when the wrapper is dropped.
    #[inline]
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: AsMut<[u8]>> core::ops::Deref for Zeroizing<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: AsMut<[u8]>> core::ops::DerefMut for Zeroizing<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: AsMut<[u8]>> Drop for Zeroizing<T> {
    #[inline]
    fn drop(&mut self) {
        zeroize(self.0.as_mut());
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
    fn zeroize_i16_clears_coefficients() {
        let mut buf = [-0x0123_i16; 256];
        zeroize_i16(&mut buf);
        assert!(buf.iter().all(|&c| c == 0));
    }

    #[test]
    fn zeroize_i32_clears_coefficients() {
        let mut buf = [-0x0123_4567_i32; 256];
        zeroize_i32(&mut buf);
        assert!(buf.iter().all(|&c| c == 0));
    }

    #[test]
    fn zeroizing_wipes_on_drop() {
        let mut z = Zeroizing::new([0xAA_u8; 32]);
        let p: *const u8 = z.as_ptr();
        // SAFETY: `z` is a live local, properly aligned and initialised;
        // `drop_in_place` runs its destructor without releasing the
        // storage, and `z` is forgotten below so it is never dropped again.
        unsafe { core::ptr::drop_in_place(&raw mut z) };
        // SAFETY: `p` points at the 32 bytes inside `z`, which is still in
        // scope, so the storage remains allocated and initialised.
        let after = unsafe { core::slice::from_raw_parts(p, 32) };
        assert!(after.iter().all(|&b| b == 0));
        core::mem::forget(z);

        // Control: a plain array has no destructor, so the same sequence
        // must leave its bytes untouched.
        let mut plain = [0xAA_u8; 32];
        let q: *const u8 = plain.as_ptr();
        // SAFETY: as above; dropping a `[u8; 32]` in place is a no-op.
        unsafe { core::ptr::drop_in_place(&raw mut plain) };
        // SAFETY: `plain` is still in scope, so its storage is live.
        let untouched = unsafe { core::slice::from_raw_parts(q, 32) };
        assert!(untouched.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn zeroize_empty_slice_is_noop() {
        let mut buf: [u8; 0] = [];
        zeroize(&mut buf);
        // Reaching this line is the assertion: the call must not panic
        // on a zero-length slice.
    }
}
