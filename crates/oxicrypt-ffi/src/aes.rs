//! C ABI for the AES modes: one opaque key handle type per mode, each built
//! once from 16, 24 or 32 key bytes and holding that mode's Rust key, so the
//! key's profile gate, its fixed tag or MAC length and its invocation count
//! apply to every call on the handle.
//!
//! # Lifecycle
//!
//! ```c
//! OxiAesGcmKey *key = NULL;
//! OxiDrbg *drbg = NULL;
//! if (oxi_aes_gcm_key_new(key_bytes, 32, &key) != 0) { /* handle error */ }
//! if (oxi_hmac_drbg_sha256_new_rbg(&drbg) != 0
//!     || oxi_drbg_instantiate(drbg, NULL, 0) != 0) { /* handle error */ }
//! uint8_t iv[12], tag[16];
//! oxi_aes_gcm_seal(key, drbg, aad, aad_len, pt, pt_len, ct, iv, tag);
//! oxi_aes_gcm_open(key, iv, aad, aad_len, ct, pt_len, tag, pt_out);
//! oxi_drbg_free(drbg);
//! oxi_aes_gcm_key_free(key);
//! ```
//!
//! Every `_key_free` accepts NULL as a no-op. Freeing a handle twice, or
//! while another thread uses it, is undefined behaviour.
//!
//! # Handles
//!
//! A handle is a module allocation whose first field is an
//! [`OxiKeyHeader`]: a kind naming the mode and a fixed magic, both written
//! by the module at construction. Every symbol reads the header through a
//! `*const OxiKeyHeader` before it forms a reference of the handle's type,
//! and returns `InvalidInput = 5` when the kind is not the symbol's mode or
//! the magic is wrong, so a handle of one mode passed to a symbol of another
//! is refused at run time as the distinct C types refuse it at compile time.
//! A `_key_free` given a handle of another mode frees nothing, and the
//! handle stays live to be freed by its own mode's `_key_free`. Freeing a
//! handle drops its Rust key, which zeroizes the key schedule, then wipes
//! every byte of the allocation.
//!
//! # Check order
//!
//! Every operation checks, in order, before any work, and returns the first
//! failure:
//!
//! 1. A NULL key handle, or a NULL `out` on a `_key_new`, returns
//!    `NullPointer = 10`.
//! 2. A module that is not operational returns `NotOperational = 1`.
//! 3. A handle whose header names another mode, or whose magic is wrong,
//!    returns `InvalidInput = 5`.
//! 4. Each pointer and length pair, in parameter order: a NULL pointer with a
//!    non-zero length, or a NULL fixed-size pointer (an IV, counter, tag,
//!    MAC, `written`, or the DRBG handle), returns `NullPointer = 10`; a
//!    length above `isize::MAX`, or a range that ends past the top of the
//!    address space, returns `InvalidInput = 5`.
//! 5. A writable range (`ct`, `pt`, `out`, `iv_out`, `tag_out`, the tag of
//!    `oxi_aes_ccm_seal`, the MAC of `oxi_aes_cmac`, `written`, or the `out`
//!    of a `_key_new` or `_key_invocations`) that shares a byte with any other
//!    range, input or output, returns `InvalidInput = 5`. The key handle and
//!    the DRBG handle count as writable ranges, since a call updates the
//!    key's count and the DRBG's hold, so an input that shares a byte with
//!    either handle, and a DRBG handle that is the key handle, return
//!    `InvalidInput = 5` too. In-place operation is therefore refused.
//! 6. `oxi_aes_gcm_seal` then takes the DRBG handle as `oxi_drbg_generate`
//!    does: a DRBG the active profile does not allow returns
//!    `AlgorithmRestricted = 6`, a handle inherited from another process
//!    `InvalidInput = 5`, and a handle in use `Busy = 32`.
//! 7. `oxi_aes_kwp_wrap` and its inverse return `BufferTooSmall = 11` when
//!    `out_cap` is below the wrapped length of a plaintext of a length KWP
//!    accepts.
//! 8. Before any module buffer is allocated, a length above the mode's own
//!    bound returns the code the mode's Rust function returns for it: a
//!    GCM text above 2^36 − 32 bytes `InvalidPayloadLength = 26`; under a
//!    CCM nonce of 7 to 13 bytes, a payload its length field cannot
//!    represent `InvalidPayloadLength = 26` on `oxi_aes_ccm_seal` and
//!    `TagMismatch = 22` on `oxi_aes_ccm_open`; a KW input past 2^54
//!    semiblocks, or a KWP unwrap input longer than the wrap of 2^32 − 1
//!    bytes, `LengthMismatch = 23` when its length is not a multiple of 8
//!    and otherwise `InvalidPayloadLength = 26` for KW and
//!    `TagMismatch = 22` for KWP. These refusals come before the profile
//!    check and the invocation count, so they charge no count.
//!
//! The Rust key type performs the rest, in its own functions: the module
//! state again, the profile check for the mode at the key's size
//! (`AlgorithmRestricted = 6`), the key-length and tag- or MAC-length
//! checks at construction (`InvalidInput = 5`), the mode's length and
//! parameter checks, the invocation count (`KeyExhausted = 34`), the
//! DRBG's own codes on a GCM seal (`Uninstantiated = 8` for a handle never
//! instantiated), and the cryptographic result.
//!
//! # Outputs
//!
//! Each operation writes its result into a buffer the module owns and
//! copies it to the caller's memory through raw pointers only once the
//! operation has succeeded. The module state is re-checked before each
//! copy: a module that enters its error state between the copies of one
//! call zeroes every output it has already copied, leaves the later ones
//! unwritten and returns `NotOperational = 1`. On any failure, a tag or ICV
//! that does not verify included, nothing of the call's output survives in
//! the caller's buffers. The module buffer is wiped when the call returns.

use self::handle::{ModeKey, enter, handle_span, key_free, key_new};
use crate::error::OxiResult as R;
use crate::rbg::{OxiDrbg, with_held, write_out};
use core::ffi::c_int;
use oxicrypt_aes::{
    CbcKey, CcmKey, CtrKey, GcmKey, KwKey, ModeError, cbc_decrypt, cbc_encrypt, ccm_decrypt,
    ccm_encrypt, ctr, gcm_decrypt, gcm_encrypt, kw_unwrap, kw_unwrap_inverse, kw_wrap,
    kw_wrap_inverse, kwp_unwrap, kwp_unwrap_inverse, kwp_wrap, kwp_wrap_inverse,
};
use oxicrypt_cmac::{CmacKey, cmac, cmac_verify};
use oxicrypt_zeroize::Zeroizing;

/// Opaque AES-GCM key handle: a key of 16, 24 or 32 bytes and its count of
/// encryptions. Built by the `oxi_aes_gcm_key_new` functions, released by
/// [`oxi_aes_gcm_key_free`], and refused with `InvalidInput = 5` by the
/// symbols of every other mode, which read the allocation's leading
/// `OxiKeyHeader` (a mode kind and a magic the module writes at
/// construction) before any typed access.
///
/// Any number of threads may call the mode's functions with the same handle
/// at the same time: every function takes the handle shared, and the only
/// state a call changes through it is the GCM invocation count, which is
/// atomic. [`oxi_aes_gcm_key_free`] alone requires that no other thread is
/// using the handle.
pub struct OxiAesGcmKey {
    _opaque: [u8; 0],
}

/// Opaque AES-CCM key handle: a key of 16, 24 or 32 bytes, its tag length
/// and its count of block-cipher invocations. Built by the
/// `oxi_aes_ccm_key_new` functions, released by [`oxi_aes_ccm_key_free`],
/// and refused with `InvalidInput = 5` by the symbols of every other mode,
/// which read the allocation's leading `OxiKeyHeader` (a mode kind and a
/// magic the module writes at construction) before any typed access.
///
/// Any number of threads may call the mode's functions with the same handle
/// at the same time: every function takes the handle shared, and the only
/// state a call changes through it is the CCM invocation count, which is
/// atomic. [`oxi_aes_ccm_key_free`] alone requires that no other thread is
/// using the handle.
pub struct OxiAesCcmKey {
    _opaque: [u8; 0],
}

/// Opaque AES-CBC key handle: a key of 16, 24 or 32 bytes. Built by
/// [`oxi_aes_cbc_key_new`], released by [`oxi_aes_cbc_key_free`], and
/// refused with `InvalidInput = 5` by the symbols of every other mode,
/// which read the allocation's leading `OxiKeyHeader` (a mode kind and a
/// magic the module writes at construction) before any typed access.
///
/// Any number of threads may call the mode's functions with the same handle
/// at the same time: every function takes the handle shared, and no call
/// changes any state through it. [`oxi_aes_cbc_key_free`] alone requires
/// that no other thread is using the handle.
pub struct OxiAesCbcKey {
    _opaque: [u8; 0],
}

/// Opaque AES-CTR key handle: a key of 16, 24 or 32 bytes. Built by
/// [`oxi_aes_ctr_key_new`], released by [`oxi_aes_ctr_key_free`], and
/// refused with `InvalidInput = 5` by the symbols of every other mode,
/// which read the allocation's leading `OxiKeyHeader` (a mode kind and a
/// magic the module writes at construction) before any typed access.
///
/// Any number of threads may call the mode's functions with the same handle
/// at the same time: every function takes the handle shared, and no call
/// changes any state through it. [`oxi_aes_ctr_key_free`] alone requires
/// that no other thread is using the handle.
pub struct OxiAesCtrKey {
    _opaque: [u8; 0],
}

/// Opaque AES key-wrap key handle: a key of 16, 24 or 32 bytes for KW and
/// KWP, in both the forward and the inverse-cipher variants. Built by
/// [`oxi_aes_kw_key_new`], released by [`oxi_aes_kw_key_free`], and refused
/// with `InvalidInput = 5` by the symbols of every other mode, which read
/// the allocation's leading `OxiKeyHeader` (a mode kind and a magic the
/// module writes at construction) before any typed access.
///
/// Any number of threads may call the mode's functions with the same handle
/// at the same time: every function takes the handle shared, and no call
/// changes any state through it. [`oxi_aes_kw_key_free`] alone requires
/// that no other thread is using the handle.
pub struct OxiAesKwKey {
    _opaque: [u8; 0],
}

/// Opaque CMAC key handle: a key of 16, 24 or 32 bytes and its MAC length.
/// Built by [`oxi_aes_cmac_key_new`], released by [`oxi_aes_cmac_key_free`],
/// and refused with `InvalidInput = 5` by the symbols of every other mode,
/// which read the allocation's leading `OxiKeyHeader` (a mode kind and a
/// magic the module writes at construction) before any typed access.
///
/// Any number of threads may call the mode's functions with the same handle
/// at the same time: every function takes the handle shared, and no call
/// changes any state through it. [`oxi_aes_cmac_key_free`] alone requires
/// that no other thread is using the handle.
pub struct OxiAesCmacKey {
    _opaque: [u8; 0],
}

/// The key handles: their header, their allocation, and the functions that
/// build, check and free them. A mode function reaches a handle's Rust key
/// only through [`handle::enter`], once the header has matched.
mod handle {
    use super::{
        OxiAesCbcKey, OxiAesCcmKey, OxiAesCmacKey, OxiAesCtrKey, OxiAesGcmKey, OxiAesKwKey, R,
        Span, disjoint, input, span,
    };
    use crate::rbg::wipe_and_free;
    use core::mem::MaybeUninit;
    use core::ptr::addr_of_mut;
    use oxicrypt_aes::{CbcKey, CcmKey, CtrKey, GcmKey, KwKey};
    use oxicrypt_cmac::CmacKey;
    use oxicrypt_module::{Error, require_operational};
    use std::alloc::{Layout, alloc};

    /// The first field of every key handle, written by the module at
    /// construction and read before any typed access.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct OxiKeyHeader {
        kind: u32,
        magic: u32,
    }

    /// The magic every live key handle carries.
    const KEY_MAGIC: u32 = 0x4F58_4B48;

    const _: () = assert!(size_of::<OxiKeyHeader>() == 8);

    /// A key handle's allocation: the header, then the mode's Rust key.
    #[repr(C)]
    struct KeyHandle<K> {
        header: OxiKeyHeader,
        key: K,
    }

    /// A mode's Rust key type, its header kind and its C handle type.
    pub(super) trait ModeKey: Sized {
        const KIND: u32;
        type Handle;
    }

    /// Whether no two of `kinds` are equal.
    const fn distinct(kinds: &[u32]) -> bool {
        let mut rest = kinds;
        while let [first, tail @ ..] = rest {
            let mut others = tail;
            while let [other, more @ ..] = others {
                if *first == *other {
                    return false;
                }
                others = more;
            }
            rest = tail;
        }
        true
    }

    macro_rules! mode_keys {
        ($($key:ident => $handle:ident, $kind:literal;)*) => {
            $(
                impl ModeKey for $key {
                    const KIND: u32 = $kind;
                    type Handle = $handle;
                }
                const _: () = assert!(core::mem::offset_of!(KeyHandle<$key>, header) == 0);
            )*
            const _: () = assert!(distinct(&[$($kind),*]), "two modes share a header kind");
        };
    }

    mode_keys! {
        GcmKey => OxiAesGcmKey, 1;
        CcmKey => OxiAesCcmKey, 2;
        CbcKey => OxiAesCbcKey, 3;
        CtrKey => OxiAesCtrKey, 4;
        KwKey => OxiAesKwKey, 5;
        CmacKey => OxiAesCmacKey, 6;
    }

    /// The header a live handle of `K`'s mode carries.
    const fn header_of<K: ModeKey>() -> OxiKeyHeader {
        OxiKeyHeader {
            kind: K::KIND,
            magic: KEY_MAGIC,
        }
    }

    /// Steps 1 to 3 of the check order: the NULL handle, the module state
    /// and the handle's header. The reference to the Rust key is formed only
    /// after the header matches.
    ///
    /// # Safety
    ///
    /// `key` must be NULL or a live key handle of any mode.
    pub(super) unsafe fn enter<'a, K: ModeKey>(key: *const K::Handle) -> Result<&'a K, R> {
        if key.is_null() {
            return Err(R::NullPointer);
        }
        require_operational().map_err(R::from)?;
        // SAFETY: `key` was checked non-NULL above and is a live handle by
        // contract. Every live handle of every mode is a `KeyHandle` whose
        // 8-byte `OxiKeyHeader` sits at offset 0, as the assertions above
        // pin, so the read stays inside the allocation.
        let header = unsafe { key.cast::<OxiKeyHeader>().read() };
        if header != header_of::<K>() {
            return Err(R::InvalidInput);
        }
        // SAFETY: the header read above names `K`'s mode and carries the
        // magic. Only `key_new::<K>` writes that header, at offset 0 of a
        // `KeyHandle<K>` allocation, so `key` points to a live one.
        Ok(unsafe { &(*key.cast::<KeyHandle<K>>()).key })
    }

    /// The memory of a key handle the call takes. It counts as writable,
    /// since a GCM or CCM call updates the key's count through it, so no
    /// caller range may share a byte with it.
    pub(super) fn handle_span<K: ModeKey>(h: *const K::Handle) -> Span {
        Span {
            start: h.addr(),
            len: size_of::<KeyHandle<K>>(),
            writable: true,
        }
    }

    #[cfg(test)]
    thread_local! {
        /// In a unit test, whether the next [`key_new`] on this thread
        /// returns `Internal` as a failed allocation does, without
        /// allocating. The refusal clears it.
        pub(super) static FAIL_NEXT_KEY_ALLOC: core::cell::Cell<bool> =
            const { core::cell::Cell::new(false) };

        /// In a unit test, the key handle allocations this thread has made
        /// and not yet released.
        pub(super) static LIVE_KEY_ALLOCS: core::cell::Cell<isize> =
            const { core::cell::Cell::new(0) };
    }

    /// Allocates a `KeyHandle<K>`, writes its header, has `build` construct
    /// the key in the allocation's `key` field, and writes the handle to
    /// `out`. The key is expanded in the allocation and is not moved by the
    /// module's code. On an error the allocation is zeroed and released,
    /// and `*out` is not written.
    ///
    /// # Safety
    ///
    /// `out` must be NULL or valid for a write of one pointer. A non-NULL
    /// `key` must be valid for reads of `key_len` bytes.
    pub(super) unsafe fn key_new<K: ModeKey>(
        key: *const u8,
        key_len: usize,
        out: *mut *mut K::Handle,
        build: impl for<'s> FnOnce(&'s mut MaybeUninit<K>, &[u8]) -> Result<&'s mut K, Error>,
    ) -> Result<(), R> {
        if out.is_null() {
            return Err(R::NullPointer);
        }
        require_operational().map_err(R::from)?;
        disjoint(&[
            span(key, key_len, false)?,
            span(out, size_of::<*mut K::Handle>(), true)?,
        ])?;
        #[cfg(test)]
        if FAIL_NEXT_KEY_ALLOC.replace(false) {
            return Err(R::Internal);
        }
        let layout = Layout::new::<KeyHandle<K>>();
        // SAFETY: `KeyHandle<K>` holds an 8-byte header, so the layout's
        // size is not zero.
        let raw = unsafe { alloc(layout) };
        if raw.is_null() {
            return Err(R::Internal);
        }
        #[cfg(test)]
        LIVE_KEY_ALLOCS.set(LIVE_KEY_ALLOCS.get().saturating_add(1));
        #[allow(
            clippy::cast_ptr_alignment,
            reason = "the allocation was made with the layout of `KeyHandle<K>`"
        )]
        let handle = raw.cast::<KeyHandle<K>>();
        // SAFETY: `handle` is the fresh non-NULL allocation made above with
        // the size and alignment of `KeyHandle<K>`, so both field pointers
        // are in bounds and aligned. `MaybeUninit<K>` has the layout of `K`,
        // and the field is not read until `build` has initialised it.
        // `key` passed `span` and `disjoint` above, so it is non-NULL or has
        // a length of 0 and shares no byte with `out`; it is valid for
        // `key_len` bytes by contract, and the allocation is fresh, so it
        // shares no byte with `key` either.
        let constructed = unsafe {
            addr_of_mut!((*handle).header).write(header_of::<K>());
            let slot = &mut *addr_of_mut!((*handle).key).cast::<MaybeUninit<K>>();
            build(slot, input(key, key_len)).map(|_| ())
        };
        if let Err(e) = constructed {
            // SAFETY: on an error the key field holds either nothing or a
            // zeroed key with no key material, so no destructor needs to run
            // before the allocation is wiped and freed. Viewed as a
            // `MaybeUninit<KeyHandle<K>>`, which has the layout of
            // `KeyHandle<K>` and is valid whatever its bytes, it is a live
            // value whose drop does nothing, in the allocation made with
            // that layout above; no other thread has seen it, and it is
            // released once.
            unsafe { wipe_and_free(handle.cast::<MaybeUninit<KeyHandle<K>>>()) };
            #[cfg(test)]
            LIVE_KEY_ALLOCS.set(LIVE_KEY_ALLOCS.get().saturating_sub(1));
            return Err(R::from(e));
        }
        // SAFETY: `out` was checked non-NULL and disjoint from `key` above,
        // and is valid for a write of one pointer by contract.
        unsafe { *out = handle.cast::<K::Handle>() };
        Ok(())
    }

    /// Frees a handle of `K`'s mode. NULL, or a handle of another mode,
    /// frees nothing, and a handle of another mode stays live.
    ///
    /// # Safety
    ///
    /// `key` must be NULL or a live key handle that no other thread is
    /// using.
    pub(super) unsafe fn key_free<K: ModeKey>(key: *mut K::Handle) {
        if key.is_null() {
            return;
        }
        // SAFETY: `key` was checked non-NULL above and is a live handle by
        // contract, which begins with an 8-byte `OxiKeyHeader` at offset 0
        // whatever its mode.
        if unsafe { key.cast::<OxiKeyHeader>().read() } != header_of::<K>() {
            return;
        }
        // SAFETY: the header names `K`'s mode, so `key` is the
        // `KeyHandle<K>` allocation `key_new::<K>` made with the layout of
        // `KeyHandle<K>`; no other thread uses it, by contract, and this
        // call releases it once.
        unsafe { wipe_and_free(key.cast::<KeyHandle<K>>()) };
        #[cfg(test)]
        LIVE_KEY_ALLOCS.set(LIVE_KEY_ALLOCS.get().saturating_sub(1));
    }
}

/// One caller range, after step 4 of the check order.
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    len: usize,
    writable: bool,
}

/// Step 4 for one pointer and length pair. A fixed-size pointer is passed
/// with its size, so a NULL one is refused as a NULL with a length.
fn span<T>(ptr: *const T, len: usize, writable: bool) -> Result<Span, R> {
    if ptr.is_null() && len > 0 {
        return Err(R::NullPointer);
    }
    if len > isize::MAX.unsigned_abs() || ptr.addr().checked_add(len).is_none() {
        return Err(R::InvalidInput);
    }
    Ok(Span {
        start: ptr.addr(),
        len,
        writable,
    })
}

/// Step 5: no writable range shares a byte with any other range.
fn disjoint(spans: &[Span]) -> Result<(), R> {
    for (i, a) in spans.iter().enumerate() {
        for b in spans.iter().skip(i.saturating_add(1)) {
            let shared = a.len > 0
                && b.len > 0
                && a.start < b.start.saturating_add(b.len)
                && b.start < a.start.saturating_add(a.len);
            if shared && (a.writable || b.writable) {
                return Err(R::InvalidInput);
            }
        }
    }
    Ok(())
}

/// Borrows a caller input that passed steps 4 and 5.
///
/// # Safety
///
/// A non-NULL `ptr` must be valid for reads of `len` bytes for `'a`, and no
/// writable range of the call may overlap it.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: `ptr` is non-NULL for a non-zero length after step 4, valid
    // for `len` bytes by contract, and `len` is at most `isize::MAX`.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// A fixed-size caller input that passed steps 4 and 5.
///
/// # Safety
///
/// `ptr` must be non-NULL and valid for reads of `N` bytes.
unsafe fn input_array<const N: usize>(ptr: *const u8) -> [u8; N] {
    // SAFETY: `ptr` is valid for reads of `N` bytes by contract; an array of
    // bytes has no alignment requirement beyond 1.
    unsafe { ptr.cast::<[u8; N]>().read() }
}

/// A module buffer of `len` zero bytes for an operation's output, wiped when
/// dropped.
fn staged(len: usize) -> Result<Zeroizing<Vec<u8>>, R> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| R::Internal)?;
    v.resize(len, 0);
    Ok(Zeroizing::new(v))
}

/// The C status of a shim result.
fn code(r: Result<(), R>) -> c_int {
    match r {
        Ok(()) => R::Ok as c_int,
        Err(e) => e as c_int,
    }
}

/// Copies each staged output to its caller buffer, in order, through
/// [`write_out`]. When a copy is refused, every buffer already written is
/// zeroed through [`crate::zero_out`], which runs in every module state, so
/// no part of the call's output survives the failure.
///
/// # Safety
///
/// Each destination must be valid for writes of its source's length and
/// must overlap no source and no other destination.
unsafe fn write_all(outputs: &[(*mut u8, &[u8])]) -> Result<(), R> {
    for (copied, &(dst, src)) in outputs.iter().enumerate() {
        // SAFETY: `dst` is valid for `src.len()` bytes and overlaps no
        // source, by contract.
        if let Err(e) = unsafe { write_out(dst, src) } {
            for &(done, done_src) in outputs.iter().take(copied) {
                // SAFETY: `done` is valid for writes of `done_src.len()`
                // bytes, by contract, as for its copy above.
                unsafe { crate::zero_out(done, done_src.len()) };
            }
            return Err(e);
        }
    }
    Ok(())
}

/// The length a step 8 bound is compared in.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Longest GCM plaintext or ciphertext, in bytes: 2^39 − 256 bits
/// (SP 800-38D §5.2.1.1), the bound `gcm_encrypt` and `gcm_decrypt` apply.
const GCM_MAX_TEXT_LEN: u64 = (1 << 36) - 32;

/// Step 8 for GCM.
fn gcm_text_bound(len: usize) -> Result<(), R> {
    if len_u64(len) > GCM_MAX_TEXT_LEN {
        return Err(R::from(ModeError::InvalidPayloadLength));
    }
    Ok(())
}

/// Whether a CCM payload of `len` bytes is one the length field of
/// `15 − nonce_len` bytes cannot represent (SP 800-38C Appendix A.1). A
/// nonce of 7 bytes leaves an 8-byte field, which represents every length;
/// an invalid nonce length is left to the Rust function to refuse.
fn ccm_payload_over(nonce_len: usize, len: usize) -> bool {
    let field_bits = match nonce_len {
        8 => 56,
        9 => 48,
        10 => 40,
        11 => 32,
        12 => 24,
        13 => 16,
        _ => return false,
    };
    len_u64(len) >> field_bits != 0
}

/// Longest KW plaintext, in bytes: 2^54 − 1 semiblocks (SP 800-38F §5.3.1
/// Table 1).
const KW_MAX_PLAINTEXT_LEN: u64 = ((1 << 54) - 1) * 8;

/// Longest KW ciphertext, in bytes: 2^54 semiblocks (SP 800-38F §5.3.1
/// Table 1).
const KW_MAX_CIPHERTEXT_LEN: u64 = (1 << 54) * 8;

/// Longest KWP ciphertext, in bytes: the wrap of a plaintext of 2^32 − 1
/// bytes (SP 800-38F §5.3.1 Table 1).
const KWP_MAX_CIPHERTEXT_LEN: u64 = (1 << 32) + 8;

/// Step 8 for KW and KWP: a `len` above `max` returns `LengthMismatch` when
/// it is not a multiple of 8, as the Rust function checks that first, and
/// `over` otherwise.
fn kw_bound(len: usize, max: u64, over: ModeError) -> Result<(), R> {
    if len_u64(len) <= max {
        return Ok(());
    }
    if len & 7 != 0 {
        return Err(R::from(ModeError::LengthMismatch));
    }
    Err(R::from(over))
}

/// Writes a count read from a handle to `out`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle; `out` must be NULL or valid for
/// writes of 8 bytes.
unsafe fn key_invocations<K: ModeKey>(
    key: *const K::Handle,
    out: *mut u64,
    count: impl FnOnce(&K) -> u64,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<K>(key) }?;
    disjoint(&[handle_span::<K>(key), span(out, size_of::<u64>(), true)?])?;
    let n = count(k).to_ne_bytes();
    // SAFETY: `out` was checked non-NULL by `span` and disjoint from the
    // handle by `disjoint` above, and is valid for 8 bytes by contract; it
    // is written bytewise, so its alignment does not matter.
    unsafe { write_out(out.cast::<u8>(), &n) }
}

// ── GCM ──────────────────────────────────────────────────────────────

/// Construct an AES-GCM key handle from `key_len` bytes of key material,
/// with a count of 0 and a limit of 2^32 encryptions (SP 800-38D §8.3).
///
/// `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
/// success the handle is written to `*out`; release it with
/// [`oxi_aes_gcm_key_free`]. `out` must not overlap `key`. A NULL `out`, or
/// a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
/// operational returns 1. A failed allocation returns `Internal = 255`. On
/// any failure `*out` is unchanged. The buffer contract of every
/// `oxi_aes_*` function, this one included, is stated at the top of this
/// header.
///
/// # Safety
///
/// `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
/// NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_gcm_key_new(
    key: *const u8,
    key_len: usize,
    out: *mut *mut OxiAesGcmKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe { key_new(key, key_len, out, GcmKey::new_in_place) })
}

/// Construct an AES-GCM key handle as [`oxi_aes_gcm_key_new`] does, with
/// its count preloaded to `used`: the encryptions earlier instances of the
/// same key bytes performed, as read from [`oxi_aes_gcm_key_invocations`].
///
/// A `used` above 2^32 returns `InvalidInput = 5`; a `used` of 2^32 builds
/// a key that is already exhausted. The operator sums the counts of every
/// instance of one key and establishes a new key before the sum reaches
/// 2^32; the module sees one instance only. A NULL `out`, or a NULL `key`
/// with a non-zero `key_len`, returns 10; a module that is not operational
/// returns 1. A failed allocation returns `Internal = 255`. On any failure
/// `*out` is unchanged.
///
/// # Safety
///
/// As for [`oxi_aes_gcm_key_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_gcm_key_new_with_count(
    key: *const u8,
    key_len: usize,
    used: u64,
    out: *mut *mut OxiAesGcmKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe {
        key_new(key, key_len, out, |s, k| {
            GcmKey::new_with_count_in_place(s, k, used)
        })
    })
}

/// Construct an AES-GCM key handle as [`oxi_aes_gcm_key_new`] does, with
/// a count of 0 and a limit of `limit` encryptions: this instance's share
/// of the 2^32 permitted under the key bytes.
///
/// A `limit` of 0 or above 2^32 returns `InvalidInput = 5`. The operator
/// keeps the sum of the shares of one key at or below 2^32; the module does
/// not see the other instances. A NULL `out`, or a NULL `key` with a
/// non-zero `key_len`, returns 10; a module that is not operational
/// returns 1. A failed allocation returns `Internal = 255`. On any failure
/// `*out` is unchanged.
///
/// # Safety
///
/// As for [`oxi_aes_gcm_key_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_gcm_key_new_with_limit(
    key: *const u8,
    key_len: usize,
    limit: u64,
    out: *mut *mut OxiAesGcmKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe {
        key_new(key, key_len, out, |s, k| {
            GcmKey::new_with_limit_in_place(s, k, limit)
        })
    })
}

/// Write to `*out` the number of encryptions reserved under the handle,
/// including any preloaded by [`oxi_aes_gcm_key_new_with_count`].
///
/// A handle of another mode returns `InvalidInput = 5`. `out` must not
/// overlap the handle. A NULL `key` returns 10; a module that is not
/// operational returns 1.
///
/// # Safety
///
/// `key` must be NULL or a live key handle; `out` must be NULL or valid for
/// a write of one `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_gcm_key_invocations(
    key: *const OxiAesGcmKey,
    out: *mut u64,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_invocations`'s contract by this
    // function's.
    code(unsafe { key_invocations(key, out, GcmKey::invocations) })
}

/// Free an AES-GCM key handle, zeroizing its key schedule. NULL frees
/// nothing. A handle of another mode frees nothing and stays live, to be
/// freed by its own mode's `_key_free`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle that no other thread is using.
/// An AES-GCM handle is dangling once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_gcm_key_free(key: *mut OxiAesGcmKey) {
    // SAFETY: `key` is NULL or a live handle no other thread uses, by
    // contract, as `key_free` requires.
    unsafe { key_free::<GcmKey>(key) };
}

/// AES-GCM authenticated encryption (SP 800-38D §7.1) under a 96-bit IV the
/// module draws from the caller's DRBG handle (SP 800-38D §8.2.2).
///
/// Buffers: `aad`, `aad_len` bytes; `plaintext`, `pt_len` bytes;
/// `ciphertext`, `pt_len` writable bytes; `iv_out`, 12 writable bytes;
/// `tag_out`, 16 writable bytes. `aad` and `plaintext` may be NULL with a
/// length of 0. No range may overlap a writable range or either handle,
/// and the DRBG handle may not be the key handle: an overlap, in-place
/// encryption included, returns `InvalidInput = 5`. A handle of another
/// mode returns `InvalidInput = 5`. A NULL `key` returns 10; a module that
/// is not operational returns 1.
///
/// The DRBG handle is taken as `oxi_drbg_generate` takes it, with its codes:
/// `Uninstantiated = 8` for a handle never instantiated, `Busy = 32` for one
/// in use, `InvalidInput = 5` for one inherited from another process.
/// Plaintext longer than 2^36 − 32 bytes returns
/// `InvalidPayloadLength = 26`, AAD longer than 2^61 − 1 bytes
/// `InvalidAadLength = 27`. A key that has reached its limit returns
/// `KeyExhausted = 34` before any IV is drawn, and stays exhausted; an
/// encryption whose IV draw fails still spends one invocation. On success
/// the ciphertext, the IV and the tag are written. On any failure nothing
/// of them survives in the caller's buffers: an output copied before a
/// later copy is refused is zeroed.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, `drbg` NULL or a live handle
/// from a `_new_rbg` function, and every non-NULL buffer valid for its
/// stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_gcm_seal(
    key: *const OxiAesGcmKey,
    drbg: *mut OxiDrbg,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    ciphertext: *mut u8,
    iv_out: *mut u8,
    tag_out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `gcm_seal`'s contract, which is this
    // function's.
    code(unsafe {
        gcm_seal(
            key, drbg, aad, aad_len, plaintext, pt_len, ciphertext, iv_out, tag_out,
        )
    })
}

/// [`oxi_aes_gcm_seal`] as a shim result.
///
/// # Safety
///
/// As for [`oxi_aes_gcm_seal`].
#[allow(clippy::too_many_arguments, reason = "the C signature's parameters")]
unsafe fn gcm_seal(
    key: *const OxiAesGcmKey,
    drbg: *mut OxiDrbg,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    ciphertext: *mut u8,
    iv_out: *mut u8,
    tag_out: *mut u8,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<GcmKey>(key) }?;
    disjoint(&[
        handle_span::<GcmKey>(key),
        span(drbg, size_of::<OxiDrbg>(), true)?,
        span(aad, aad_len, false)?,
        span(plaintext, pt_len, false)?,
        span(ciphertext, pt_len, true)?,
        span(iv_out, 12, true)?,
        span(tag_out, 16, true)?,
    ])?;
    gcm_text_bound(pt_len)?;
    // SAFETY: `aad` and `plaintext` passed `span` and `disjoint` above, so
    // each is non-NULL or empty and shares no byte with an output or a
    // handle; each is valid for its length by contract.
    let (aad, pt) = unsafe { (input(aad, aad_len), input(plaintext, pt_len)) };
    let mut ct = staged(pt_len)?;
    // SAFETY: `drbg` was checked non-NULL by `span` and shares no byte with
    // the key handle or any range, by `disjoint` above, and is a live
    // `_new_rbg` handle by contract.
    let sealed = unsafe { with_held(drbg, |rbg| gcm_encrypt(k, rbg, aad, pt, &mut ct)) }?
        .map_err(R::from)?;
    // SAFETY: `ciphertext`, `iv_out` and `tag_out` were checked non-NULL by
    // `span` and disjoint from every other range by `disjoint` above, are
    // valid for `pt_len`, 12 and 16 bytes by contract, and overlap none of
    // the module's buffers.
    unsafe {
        write_all(&[
            (ciphertext, ct.as_slice()),
            (iv_out, sealed.iv.as_slice()),
            (tag_out, sealed.tag.as_slice()),
        ])
    }
}

/// AES-GCM authenticated decryption (SP 800-38D §7.2).
///
/// Buffers: `iv`, 12 bytes; `aad`, `aad_len` bytes; `ciphertext`, `ct_len`
/// bytes; `tag`, 16 bytes; `plaintext`, `ct_len` writable bytes. `aad` and
/// `ciphertext` may be NULL with a length of 0. No range may overlap
/// `plaintext` or the handle: an overlap returns `InvalidInput = 5`. A
/// handle of another mode returns `InvalidInput = 5`. A NULL `key` returns
/// 10; a module that is not operational returns 1.
///
/// A tag that does not verify returns `TagMismatch = 22`. The length bounds
/// of [`oxi_aes_gcm_seal`] apply to `ct_len` and `aad_len`. Decryption
/// does not count against the key's limit. The plaintext is written only on
/// success; on any failure nothing is.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_gcm_open(
    key: *const OxiAesGcmKey,
    iv: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ct_len: usize,
    tag: *const u8,
    plaintext: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `gcm_open`'s contract, which is this
    // function's.
    code(unsafe { gcm_open(key, iv, aad, aad_len, ciphertext, ct_len, tag, plaintext) })
}

/// [`oxi_aes_gcm_open`] as a shim result.
///
/// # Safety
///
/// As for [`oxi_aes_gcm_open`].
#[allow(clippy::too_many_arguments, reason = "the C signature's parameters")]
unsafe fn gcm_open(
    key: *const OxiAesGcmKey,
    iv: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ct_len: usize,
    tag: *const u8,
    plaintext: *mut u8,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<GcmKey>(key) }?;
    disjoint(&[
        handle_span::<GcmKey>(key),
        span(iv, 12, false)?,
        span(aad, aad_len, false)?,
        span(ciphertext, ct_len, false)?,
        span(tag, 16, false)?,
        span(plaintext, ct_len, true)?,
    ])?;
    gcm_text_bound(ct_len)?;
    // SAFETY: `iv`, `aad`, `ciphertext` and `tag` passed `span` and
    // `disjoint` above, so each is non-NULL or empty (`iv` and `tag` are
    // non-NULL) and shares no byte with `plaintext` or the handle; each is
    // valid for its length by contract.
    let (iv, aad, ct, tag) = unsafe {
        (
            input(iv, 12),
            input(aad, aad_len),
            input(ciphertext, ct_len),
            input_array::<16>(tag),
        )
    };
    let mut pt = staged(ct_len)?;
    gcm_decrypt(k, iv, aad, ct, &tag, &mut pt).map_err(R::from)?;
    // SAFETY: `plaintext` was checked by `span` and `disjoint` above, is
    // valid for `ct_len` bytes by contract, and does not overlap the module
    // buffer.
    unsafe { write_out(plaintext, &pt) }
}

// ── CCM ──────────────────────────────────────────────────────────────

/// Construct an AES-CCM key handle from `key_len` bytes of key material
/// with a tag length of `tag_len` bytes, fixed for the key (SP 800-38C
/// §5.3), and an invocation count of 0.
///
/// `key_len` is 16, 24 or 32 and `tag_len` one of 8, 10, 12, 14 or 16; any
/// other returns `InvalidInput = 5`. On success the handle is written to
/// `*out`; release it with [`oxi_aes_ccm_key_free`]. `out` must not overlap
/// `key`. A NULL `out`, or a NULL `key` with a non-zero `key_len`, returns
/// 10; a module that is not operational returns 1. A failed allocation
/// returns `Internal = 255`. On any failure `*out` is unchanged.
///
/// # Safety
///
/// `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
/// NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ccm_key_new(
    key: *const u8,
    key_len: usize,
    tag_len: usize,
    out: *mut *mut OxiAesCcmKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe {
        key_new(key, key_len, out, |s, k| {
            CcmKey::new_in_place(s, k, tag_len)
        })
    })
}

/// Construct an AES-CCM key handle as [`oxi_aes_ccm_key_new`] does, with
/// its count preloaded to `used`: the block-cipher invocations earlier
/// instances of the same key bytes performed, as read from
/// [`oxi_aes_ccm_key_invocations`].
///
/// A `used` above 2^61 returns `InvalidInput = 5`. A NULL `out`, or a NULL
/// `key` with a non-zero `key_len`, returns 10; a module that is not
/// operational returns 1. A failed allocation returns `Internal = 255`. On
/// any failure `*out` is unchanged.
///
/// # Safety
///
/// As for [`oxi_aes_ccm_key_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ccm_key_new_with_count(
    key: *const u8,
    key_len: usize,
    tag_len: usize,
    used: u64,
    out: *mut *mut OxiAesCcmKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe {
        key_new(key, key_len, out, |s, k| {
            CcmKey::new_with_count_in_place(s, k, tag_len, used)
        })
    })
}

/// Write to `*out` the number of block-cipher invocations reserved under the
/// handle, including any preloaded by [`oxi_aes_ccm_key_new_with_count`].
///
/// A handle of another mode returns `InvalidInput = 5`. `out` must not
/// overlap the handle. A NULL `key` returns 10; a module that is not
/// operational returns 1.
///
/// # Safety
///
/// `key` must be NULL or a live key handle; `out` must be NULL or valid for
/// a write of one `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ccm_key_invocations(
    key: *const OxiAesCcmKey,
    out: *mut u64,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_invocations`'s contract by this
    // function's.
    code(unsafe { key_invocations(key, out, CcmKey::invocations) })
}

/// Free an AES-CCM key handle, zeroizing its key schedule. NULL frees
/// nothing. A handle of another mode frees nothing and stays live, to be
/// freed by its own mode's `_key_free`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle that no other thread is using.
/// An AES-CCM handle is dangling once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ccm_key_free(key: *mut OxiAesCcmKey) {
    // SAFETY: `key` is NULL or a live handle no other thread uses, by
    // contract, as `key_free` requires.
    unsafe { key_free::<CcmKey>(key) };
}

/// AES-CCM authenticated encryption (SP 800-38C §6.1) under a caller's
/// nonce, which must be unique under the key.
///
/// Buffers: `nonce`, `nonce_len` bytes, 7 to 13; `aad`, `aad_len` bytes;
/// `pt`, `pt_len` bytes; `ct`, `pt_len` writable bytes; `tag`, the key's
/// tag length in writable bytes. `aad` and `pt` may be NULL with a length
/// of 0. No range may overlap a writable range or the handle: an overlap,
/// in-place encryption included, returns `InvalidInput = 5`. A handle of
/// another mode returns `InvalidInput = 5`. A NULL `key` returns 10; a
/// module that is not operational returns 1.
///
/// A nonce length outside 7 to 13 returns `InvalidNonceLength = 24`, a
/// payload the nonce's length field cannot represent
/// `InvalidPayloadLength = 26`, AAD above the SP 800-38C bound
/// `InvalidAadLength = 27`, and an encryption that would take the key's
/// count past 2^61 block-cipher invocations `KeyExhausted = 34`. A payload
/// the length field cannot represent is refused before the key's count is
/// charged. The ciphertext and tag are written only on success. On any
/// failure nothing of them survives in the caller's buffers: a ciphertext
/// copied before the tag's copy is refused is zeroed.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ccm_seal(
    key: *const OxiAesCcmKey,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    ct: *mut u8,
    tag: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `ccm_seal`'s contract, which is this
    // function's.
    code(unsafe { ccm_seal(key, nonce, nonce_len, aad, aad_len, pt, pt_len, ct, tag) })
}

/// [`oxi_aes_ccm_seal`] as a shim result.
///
/// # Safety
///
/// As for [`oxi_aes_ccm_seal`].
#[allow(clippy::too_many_arguments, reason = "the C signature's parameters")]
unsafe fn ccm_seal(
    key: *const OxiAesCcmKey,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    ct: *mut u8,
    tag: *mut u8,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<CcmKey>(key) }?;
    disjoint(&[
        handle_span::<CcmKey>(key),
        span(nonce, nonce_len, false)?,
        span(aad, aad_len, false)?,
        span(pt, pt_len, false)?,
        span(ct, pt_len, true)?,
        span(tag, k.tag_len(), true)?,
    ])?;
    if ccm_payload_over(nonce_len, pt_len) {
        return Err(R::from(ModeError::InvalidPayloadLength));
    }
    // SAFETY: `nonce`, `aad` and `pt` passed `span` and `disjoint` above,
    // so each is non-NULL or empty and shares no byte with an output or the
    // handle; each is valid for its length by contract.
    let (nonce, aad, pt) = unsafe {
        (
            input(nonce, nonce_len),
            input(aad, aad_len),
            input(pt, pt_len),
        )
    };
    let mut staged_ct = staged(pt_len)?;
    let mut staged_tag = staged(k.tag_len())?;
    ccm_encrypt(k, nonce, aad, pt, &mut staged_ct, &mut staged_tag).map_err(R::from)?;
    // SAFETY: `ct` and `tag` were checked by `span` and are disjoint from
    // each other and every range by `disjoint` above; they are valid for
    // `pt_len` bytes and the key's tag length by contract, and overlap
    // neither module buffer.
    unsafe { write_all(&[(ct, staged_ct.as_slice()), (tag, staged_tag.as_slice())]) }
}

/// AES-CCM authenticated decryption (SP 800-38C §6.2).
///
/// Buffers: `nonce`, `nonce_len` bytes; `aad`, `aad_len` bytes; `ct`,
/// `ct_len` bytes, the ciphertext without its tag; `tag`, the key's tag
/// length in bytes; `pt`, `ct_len` writable bytes. `nonce`, `aad` and `ct`
/// may be NULL with a length of 0. No range may overlap `pt` or the
/// handle: an overlap returns `InvalidInput = 5`. A handle of another mode
/// returns `InvalidInput = 5`. A NULL `key` returns 10; a module that is
/// not operational returns 1.
///
/// Every invalid input returns `TagMismatch = 22`: a nonce length outside 7
/// to 13, a payload length the nonce's length field cannot represent, and a
/// tag that does not verify. The tag is verified before any plaintext
/// exists outside the module, and `pt` is written only on success. A
/// decryption that would take the key's count past 2^61 returns
/// `KeyExhausted = 34`. A failed decryption is counted in full, except a
/// `ct_len` the nonce's length field cannot represent, which is refused
/// before the count is charged.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ccm_open(
    key: *const OxiAesCcmKey,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ct: *const u8,
    ct_len: usize,
    tag: *const u8,
    pt: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `ccm_open`'s contract, which is this
    // function's.
    code(unsafe { ccm_open(key, nonce, nonce_len, aad, aad_len, ct, ct_len, tag, pt) })
}

/// [`oxi_aes_ccm_open`] as a shim result.
///
/// # Safety
///
/// As for [`oxi_aes_ccm_open`].
#[allow(clippy::too_many_arguments, reason = "the C signature's parameters")]
unsafe fn ccm_open(
    key: *const OxiAesCcmKey,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ct: *const u8,
    ct_len: usize,
    tag: *const u8,
    pt: *mut u8,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<CcmKey>(key) }?;
    disjoint(&[
        handle_span::<CcmKey>(key),
        span(nonce, nonce_len, false)?,
        span(aad, aad_len, false)?,
        span(ct, ct_len, false)?,
        span(tag, k.tag_len(), false)?,
        span(pt, ct_len, true)?,
    ])?;
    if ccm_payload_over(nonce_len, ct_len) {
        return Err(R::from(ModeError::TagMismatch));
    }
    // SAFETY: `nonce`, `aad`, `ct` and `tag` passed `span` and `disjoint`
    // above, so each is non-NULL or empty and shares no byte with `pt` or
    // the handle; each is valid for its length by contract.
    let (nonce, aad, ct, tag) = unsafe {
        (
            input(nonce, nonce_len),
            input(aad, aad_len),
            input(ct, ct_len),
            input(tag, k.tag_len()),
        )
    };
    let mut staged_pt = staged(ct_len)?;
    ccm_decrypt(k, nonce, aad, ct, tag, &mut staged_pt).map_err(R::from)?;
    // SAFETY: `pt` was checked by `span` and `disjoint` above, is valid for
    // `ct_len` bytes by contract, and does not overlap the module buffer.
    unsafe { write_out(pt, &staged_pt) }
}

// ── CBC and CTR ──────────────────────────────────────────────────────

/// A CBC or CTR operation: a 16-byte IV or counter block, an input and an
/// output of the input's length.
type BlockMode<K> = fn(&K, &[u8; 16], &[u8], &mut [u8]) -> Result<(), ModeError>;

/// Runs a CBC or CTR operation through the check order and the staged
/// output.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
unsafe fn block_mode<K: ModeKey>(
    key: *const K::Handle,
    iv: *const u8,
    input_ptr: *const u8,
    len: usize,
    out: *mut u8,
    op: BlockMode<K>,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<K>(key) }?;
    disjoint(&[
        handle_span::<K>(key),
        span(iv, 16, false)?,
        span(input_ptr, len, false)?,
        span(out, len, true)?,
    ])?;
    // SAFETY: `iv` was checked non-NULL and `input_ptr` non-NULL or empty by
    // `span` above, and neither shares a byte with `out` or the handle, by
    // `disjoint`; each is valid for its length by contract.
    let (iv, data) = unsafe { (input_array::<16>(iv), input(input_ptr, len)) };
    let mut staged_out = staged(len)?;
    op(k, &iv, data, &mut staged_out).map_err(R::from)?;
    // SAFETY: `out` was checked by `span` and `disjoint` above, is valid for
    // `len` bytes by contract, and does not overlap the module buffer.
    unsafe { write_out(out, &staged_out) }
}

/// Construct an AES-CBC key handle from `key_len` bytes of key material.
///
/// `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
/// success the handle is written to `*out`; release it with
/// [`oxi_aes_cbc_key_free`]. `out` must not overlap `key`. A NULL `out`, or
/// a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
/// operational returns 1. A failed allocation returns `Internal = 255`. On
/// any failure `*out` is unchanged.
///
/// # Safety
///
/// `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
/// NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cbc_key_new(
    key: *const u8,
    key_len: usize,
    out: *mut *mut OxiAesCbcKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe { key_new(key, key_len, out, CbcKey::new_in_place) })
}

/// Free an AES-CBC key handle, zeroizing its key schedule. NULL frees
/// nothing. A handle of another mode frees nothing and stays live, to be
/// freed by its own mode's `_key_free`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle that no other thread is using.
/// An AES-CBC handle is dangling once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cbc_key_free(key: *mut OxiAesCbcKey) {
    // SAFETY: `key` is NULL or a live handle no other thread uses, by
    // contract, as `key_free` requires.
    unsafe { key_free::<CbcKey>(key) };
}

/// AES-CBC encryption (SP 800-38A §6.2), confidentiality only.
///
/// Buffers: `iv`, 16 bytes, which must be unpredictable (SP 800-38A
/// Appendix C); `in`, `len` bytes, a positive multiple of 16; `out`, `len`
/// writable bytes. No range may overlap `out` or the handle: an overlap,
/// in-place encryption included, returns `InvalidInput = 5`. A handle of
/// another mode returns `InvalidInput = 5`. A NULL `key` returns 10; a
/// module that is not operational returns 1.
///
/// A `len` that is not a multiple of 16 returns `NotBlockAligned = 20`, a
/// `len` of 0 `InvalidPayloadLength = 26`. `out` is written only on success.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cbc_encrypt(
    key: *const OxiAesCbcKey,
    iv: *const u8,
    r#in: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `block_mode`'s contract, which is this
    // function's.
    code(unsafe { block_mode(key, iv, r#in, len, out, cbc_encrypt) })
}

/// AES-CBC decryption (SP 800-38A §6.2).
///
/// The buffers and codes of [`oxi_aes_cbc_encrypt`], with `in` the
/// ciphertext and `out` the plaintext. A NULL `key` returns 10; a module
/// that is not operational returns 1.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cbc_decrypt(
    key: *const OxiAesCbcKey,
    iv: *const u8,
    r#in: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `block_mode`'s contract, which is this
    // function's.
    code(unsafe { block_mode(key, iv, r#in, len, out, cbc_decrypt) })
}

/// Construct an AES-CTR key handle from `key_len` bytes of key material.
///
/// `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
/// success the handle is written to `*out`; release it with
/// [`oxi_aes_ctr_key_free`]. `out` must not overlap `key`. A NULL `out`, or
/// a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
/// operational returns 1. A failed allocation returns `Internal = 255`. On
/// any failure `*out` is unchanged.
///
/// # Safety
///
/// `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
/// NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ctr_key_new(
    key: *const u8,
    key_len: usize,
    out: *mut *mut OxiAesCtrKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe { key_new(key, key_len, out, CtrKey::new_in_place) })
}

/// Free an AES-CTR key handle, zeroizing its key schedule. NULL frees
/// nothing. A handle of another mode frees nothing and stays live, to be
/// freed by its own mode's `_key_free`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle that no other thread is using.
/// An AES-CTR handle is dangling once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ctr_key_free(key: *mut OxiAesCtrKey) {
    // SAFETY: `key` is NULL or a live handle no other thread uses, by
    // contract, as `key_free` requires.
    unsafe { key_free::<CtrKey>(key) };
}

/// AES-CTR (SP 800-38A §6.5): XORs `in` with the keystream from the
/// 16-byte initial counter block `counter`, which the module increments as
/// one 128-bit big-endian integer. Encryption and decryption are the same
/// operation.
///
/// Buffers: `counter`, 16 bytes; `in`, `len` bytes, any length; `out`, `len`
/// writable bytes. No range may overlap `out` or the handle: an overlap,
/// in-place operation included, returns `InvalidInput = 5`. A handle of
/// another mode returns `InvalidInput = 5`. A NULL `key` returns 10; a
/// module that is not operational returns 1. No counter block may repeat
/// under one key (SP 800-38A Appendix B); that is the caller's duty. `out`
/// is written only on success.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_ctr(
    key: *const OxiAesCtrKey,
    counter: *const u8,
    r#in: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `block_mode`'s contract, which is this
    // function's.
    code(unsafe { block_mode(key, counter, r#in, len, out, ctr) })
}

// ── KW and KWP ───────────────────────────────────────────────────────

/// A KW operation: its output is the input's length plus or minus 8.
type KwOp = fn(&KwKey, &[u8], &mut [u8]) -> Result<(), ModeError>;

/// A KWP operation, returning the length it wrote.
type KwpOp = fn(&KwKey, &[u8], &mut [u8]) -> Result<usize, ModeError>;

/// Whether a KW operation wraps (output 8 bytes longer) or unwraps (8
/// bytes shorter).
#[derive(Clone, Copy)]
enum Direction {
    Wrap,
    Unwrap,
}

/// Runs a KW wrap or unwrap through the check order. The output is staged
/// in a module buffer and copied to `out` only on success, so a failed
/// unwrap leaves `out` as it was (SP 800-38F §6.2 Algorithm 4 step 3).
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
unsafe fn kw(
    key: *const OxiAesKwKey,
    data: *const u8,
    len: usize,
    out: *mut u8,
    direction: Direction,
    op: KwOp,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<KwKey>(key) }?;
    let data_span = span(data, len, false)?;
    let (out_len, max) = match direction {
        Direction::Wrap => (
            len.checked_add(8).ok_or(R::InvalidInput)?,
            KW_MAX_PLAINTEXT_LEN,
        ),
        Direction::Unwrap => (len.saturating_sub(8), KW_MAX_CIPHERTEXT_LEN),
    };
    disjoint(&[
        handle_span::<KwKey>(key),
        data_span,
        span(out, out_len, true)?,
    ])?;
    kw_bound(len, max, ModeError::InvalidPayloadLength)?;
    // SAFETY: `data` passed `span` and `disjoint` above, so it is non-NULL
    // or empty and shares no byte with `out` or the handle; it is valid for
    // `len` bytes by contract.
    let data = unsafe { input(data, len) };
    let mut staged_out = staged(out_len)?;
    op(k, data, &mut staged_out).map_err(R::from)?;
    // SAFETY: `out` was checked by `span` and `disjoint` above, is valid for
    // `out_len` bytes by contract, and does not overlap the module buffer.
    unsafe { write_out(out, &staged_out) }
}

/// The length KWP wraps a plaintext of `pt_len` bytes to, or 0 for a length
/// KWP does not accept, which the Rust layer then refuses.
fn kwp_wrapped_len(pt_len: usize) -> usize {
    if pt_len == 0 || u32::try_from(pt_len).is_err() {
        return 0;
    }
    pt_len
        .div_ceil(8)
        .checked_mul(8)
        .and_then(|n| n.checked_add(8))
        .unwrap_or(0)
}

/// Runs a KWP wrap or unwrap through the check order. The output is staged
/// in a module buffer; `out` and `written` are written only on success, so a
/// failed unwrap leaves both as they were (SP 800-38F §6.3 Algorithm 6
/// steps 4, 7 and 8), and an `out_cap` below the result returns
/// `BufferTooSmall` with nothing written. A refused copy of `written`
/// zeroes `out`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, every non-NULL buffer valid for
/// its stated length, and `written` NULL or valid for a write of one
/// `uintptr_t`.
#[allow(
    clippy::too_many_arguments,
    reason = "the C signature's parameters, the direction and the operation"
)]
unsafe fn kwp(
    key: *const OxiAesKwKey,
    data: *const u8,
    len: usize,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
    direction: Direction,
    op: KwpOp,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<KwKey>(key) }?;
    disjoint(&[
        handle_span::<KwKey>(key),
        span(data, len, false)?,
        span(out, out_cap, true)?,
        span(written, size_of::<usize>(), true)?,
    ])?;
    let staged_len = match direction {
        Direction::Wrap => {
            let wrapped = kwp_wrapped_len(len);
            if wrapped > out_cap {
                return Err(R::BufferTooSmall);
            }
            wrapped
        }
        Direction::Unwrap => {
            kw_bound(len, KWP_MAX_CIPHERTEXT_LEN, ModeError::TagMismatch)?;
            len.saturating_sub(8)
        }
    };
    // SAFETY: `data` passed `span` and `disjoint` above, so it is non-NULL
    // or empty and shares no byte with an output or the handle; it is valid
    // for `len` bytes by contract.
    let data = unsafe { input(data, len) };
    let mut staged_out = staged(staged_len)?;
    let n = op(k, data, &mut staged_out).map_err(R::from)?;
    let result = staged_out.get(..n).ok_or(R::Internal)?;
    if n > out_cap {
        return Err(R::BufferTooSmall);
    }
    let n_bytes = n.to_ne_bytes();
    // SAFETY: `written` was checked non-NULL, and `out` non-NULL or empty,
    // by `span`, and both are disjoint from every range by `disjoint` above;
    // `out`
    // is valid for `out_cap >= n` bytes and `written` for one `uintptr_t`
    // by contract, written bytewise so its alignment does not matter, and
    // neither overlaps the module buffer or `n_bytes`.
    unsafe { write_all(&[(out, result), (written.cast::<u8>(), n_bytes.as_slice())]) }
}

/// Construct an AES key-wrap key handle from `key_len` bytes of key
/// material, for KW and KWP (SP 800-38F) in both the forward and the
/// inverse-cipher variants.
///
/// `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
/// success the handle is written to `*out`; release it with
/// [`oxi_aes_kw_key_free`]. `out` must not overlap `key`. A NULL `out`, or
/// a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
/// operational returns 1. A failed allocation returns `Internal = 255`. On
/// any failure `*out` is unchanged.
///
/// # Safety
///
/// `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
/// NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kw_key_new(
    key: *const u8,
    key_len: usize,
    out: *mut *mut OxiAesKwKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe { key_new(key, key_len, out, KwKey::new_in_place) })
}

/// Free an AES key-wrap key handle, zeroizing its key schedule. NULL frees
/// nothing. A handle of another mode frees nothing and stays live, to be
/// freed by its own mode's `_key_free`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle that no other thread is using.
/// An AES key-wrap handle is dangling once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kw_key_free(key: *mut OxiAesKwKey) {
    // SAFETY: `key` is NULL or a live handle no other thread uses, by
    // contract, as `key_free` requires.
    unsafe { key_free::<KwKey>(key) };
}

/// AES-KW wrap (SP 800-38F §6.2 Algorithm 3, KW-AE).
///
/// Buffers: `pt`, `pt_len` bytes, a multiple of 8 of at least 16 and fewer
/// than 2^54 semiblocks; `out`, `pt_len + 8` writable bytes. No range may
/// overlap `out` or the handle: an overlap, in-place wrapping included,
/// returns `InvalidInput = 5`. A handle of another mode returns
/// `InvalidInput = 5`. A NULL `key` returns 10; a module that is not
/// operational returns 1. A length KW does not accept returns
/// `LengthMismatch = 23` or `InvalidPayloadLength = 26`. `out` is written
/// only on success.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kw_wrap(
    key: *const OxiAesKwKey,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `kw`'s contract, which is this function's.
    code(unsafe { kw(key, pt, pt_len, out, Direction::Wrap, kw_wrap) })
}

/// AES-KW unwrap (SP 800-38F §6.2 Algorithm 4, KW-AD).
///
/// Buffers: `ct`, `ct_len` bytes, a multiple of 8 of at least 24; `out`,
/// `ct_len - 8` writable bytes. No range may overlap `out` or the handle:
/// an overlap returns `InvalidInput = 5`. A handle of another mode returns
/// `InvalidInput = 5`. A NULL `key` returns 10; a module that is not
/// operational returns 1. An integrity check value that does not verify
/// returns `TagMismatch = 22`, a length KW does not accept
/// `LengthMismatch = 23` or `InvalidPayloadLength = 26`. On any failure
/// nothing is written to `out`: the unwrapped key is copied out only once
/// it has verified.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kw_unwrap(
    key: *const OxiAesKwKey,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `kw`'s contract, which is this function's.
    code(unsafe { kw(key, ct, ct_len, out, Direction::Unwrap, kw_unwrap) })
}

/// AES-KWP wrap (SP 800-38F §6.3 Algorithm 5, KWP-AE).
///
/// Buffers: `pt`, `pt_len` bytes, 1 to 2^32 − 1; `out`, `out_cap` writable
/// bytes, at least the wrapped length `((pt_len + 7) / 8) * 8 + 8`;
/// `written`, one writable `uintptr_t`, set to the wrapped length on
/// success. No range may overlap `out`, `written` or the handle: an
/// overlap returns `InvalidInput = 5`. A handle of another mode returns
/// `InvalidInput = 5`. A NULL `key` or `written` returns 10; a module that
/// is not operational returns 1. An `out_cap` below the wrapped length
/// returns `BufferTooSmall = 11`, and a `pt_len` KWP does not accept
/// `LengthMismatch = 23`. `out` and `written` are written only on success.
/// On any failure nothing of them survives in the caller's buffers: an
/// `out` copied before the copy of `written` is refused is zeroed.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, every non-NULL buffer valid for
/// its stated length, and `written` NULL or valid for a write of one
/// `uintptr_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kwp_wrap(
    key: *const OxiAesKwKey,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    // SAFETY: every pointer meets `kwp`'s contract, which is this
    // function's.
    code(unsafe {
        kwp(
            key,
            pt,
            pt_len,
            out,
            out_cap,
            written,
            Direction::Wrap,
            kwp_wrap,
        )
    })
}

/// AES-KWP unwrap (SP 800-38F §6.3 Algorithm 6, KWP-AD).
///
/// Buffers: `ct`, `ct_len` bytes, a multiple of 8 of at least 16; `out`,
/// `out_cap` writable bytes, at least the unwrapped length; `written`, one
/// writable `uintptr_t`, set to the unwrapped length on success. No range
/// may overlap `out`, `written` or the handle: an overlap returns
/// `InvalidInput = 5`. A handle of another mode returns
/// `InvalidInput = 5`. A NULL `key` or `written` returns 10; a module that
/// is not operational returns 1. An integrity check value or padding that
/// does not verify returns `TagMismatch = 22`, a length KWP does not
/// accept `LengthMismatch = 23`, and an `out_cap` below the unwrapped
/// length `BufferTooSmall = 11`. `out_cap` is compared with the unwrapped
/// length only after verification, so `TagMismatch = 22` takes precedence
/// over `BufferTooSmall = 11`. The unwrapped key is copied out only once it
/// has verified, and on any failure nothing of `out` or `written` survives
/// in the caller's buffers: an `out` copied before the copy of `written`
/// is refused is zeroed.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, every non-NULL buffer valid for
/// its stated length, and `written` NULL or valid for a write of one
/// `uintptr_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kwp_unwrap(
    key: *const OxiAesKwKey,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    // SAFETY: every pointer meets `kwp`'s contract, which is this
    // function's.
    code(unsafe {
        kwp(
            key,
            ct,
            ct_len,
            out,
            out_cap,
            written,
            Direction::Unwrap,
            kwp_unwrap,
        )
    })
}

/// AES-KW wrap with the inverse cipher (SP 800-38F §6.4, KW-AE with
/// CIPH⁻¹). The buffers and codes of [`oxi_aes_kw_wrap`]. A NULL `key`
/// returns 10; a module that is not operational returns 1.
///
/// # Safety
///
/// As for [`oxi_aes_kw_wrap`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kw_wrap_inverse(
    key: *const OxiAesKwKey,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `kw`'s contract, which is this function's.
    code(unsafe { kw(key, pt, pt_len, out, Direction::Wrap, kw_wrap_inverse) })
}

/// AES-KW unwrap with the forward cipher (SP 800-38F §6.4, the inverse of
/// [`oxi_aes_kw_wrap_inverse`]). The buffers and codes of
/// [`oxi_aes_kw_unwrap`]; on any failure nothing is written to `out`. A
/// NULL `key` returns 10; a module that is not operational returns 1.
///
/// # Safety
///
/// As for [`oxi_aes_kw_unwrap`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kw_unwrap_inverse(
    key: *const OxiAesKwKey,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `kw`'s contract, which is this function's.
    code(unsafe { kw(key, ct, ct_len, out, Direction::Unwrap, kw_unwrap_inverse) })
}

/// AES-KWP wrap with the inverse cipher (SP 800-38F §6.4, KWP-AE with
/// CIPH⁻¹). The buffers and codes of [`oxi_aes_kwp_wrap`]. A NULL `key`
/// returns 10; a module that is not operational returns 1.
///
/// # Safety
///
/// As for [`oxi_aes_kwp_wrap`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kwp_wrap_inverse(
    key: *const OxiAesKwKey,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    // SAFETY: every pointer meets `kwp`'s contract, which is this
    // function's.
    code(unsafe {
        kwp(
            key,
            pt,
            pt_len,
            out,
            out_cap,
            written,
            Direction::Wrap,
            kwp_wrap_inverse,
        )
    })
}

/// AES-KWP unwrap with the forward cipher (SP 800-38F §6.4, the inverse of
/// [`oxi_aes_kwp_wrap_inverse`]). The buffers and codes of
/// [`oxi_aes_kwp_unwrap`], including its precedence of `TagMismatch = 22`
/// over `BufferTooSmall = 11`; on any failure nothing of `out` or `written`
/// survives in the caller's buffers. A NULL `key` returns 10; a module that
/// is not operational returns 1.
///
/// # Safety
///
/// As for [`oxi_aes_kwp_unwrap`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_kwp_unwrap_inverse(
    key: *const OxiAesKwKey,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    // SAFETY: every pointer meets `kwp`'s contract, which is this
    // function's.
    code(unsafe {
        kwp(
            key,
            ct,
            ct_len,
            out,
            out_cap,
            written,
            Direction::Unwrap,
            kwp_unwrap_inverse,
        )
    })
}

// ── CMAC ─────────────────────────────────────────────────────────────

/// Construct a CMAC key handle (SP 800-38B) from `key_len` bytes of key
/// material with a MAC length of `mac_len` bytes, fixed for the key.
///
/// `key_len` is 16, 24 or 32 and `mac_len` 8 to 16; any other returns
/// `InvalidInput = 5`. On success the handle is written to `*out`; release
/// it with [`oxi_aes_cmac_key_free`]. `out` must not overlap `key`. A NULL
/// `out`, or a NULL `key` with a non-zero `key_len`, returns 10; a module
/// that is not operational returns 1. A failed allocation returns
/// `Internal = 255`. On any failure `*out` is unchanged. SP 800-38B
/// Appendix B recommends at most 2^48 messages under one key.
///
/// # Safety
///
/// `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
/// NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cmac_key_new(
    key: *const u8,
    key_len: usize,
    mac_len: usize,
    out: *mut *mut OxiAesCmacKey,
) -> c_int {
    // SAFETY: `key` and `out` meet `key_new`'s contract by this function's.
    code(unsafe {
        key_new(key, key_len, out, |s, k| {
            CmacKey::new_in_place(s, k, mac_len)
        })
    })
}

/// Free a CMAC key handle, zeroizing its key schedule and subkeys. NULL
/// frees nothing. A handle of another mode frees nothing and stays live, to
/// be freed by its own mode's `_key_free`.
///
/// # Safety
///
/// `key` must be NULL or a live key handle that no other thread is using.
/// A CMAC handle is dangling once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cmac_key_free(key: *mut OxiAesCmacKey) {
    // SAFETY: `key` is NULL or a live handle no other thread uses, by
    // contract, as `key_free` requires.
    unsafe { key_free::<CmacKey>(key) };
}

/// Compute the CMAC (SP 800-38B §6.2) of `msg` into `mac`.
///
/// Buffers: `msg`, `msg_len` bytes, NULL with a length of 0 allowed; `mac`,
/// the key's MAC length in writable bytes. No range may overlap `mac` or
/// the handle: an overlap returns `InvalidInput = 5`. A handle of another
/// mode returns `InvalidInput = 5`. A NULL `key` returns 10; a module that
/// is not operational returns 1. `mac` is written only on success.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cmac(
    key: *const OxiAesCmacKey,
    msg: *const u8,
    msg_len: usize,
    mac: *mut u8,
) -> c_int {
    // SAFETY: every pointer meets `cmac_compute`'s contract, which is this
    // function's.
    code(unsafe { cmac_compute(key, msg, msg_len, mac) })
}

/// [`oxi_aes_cmac`] as a shim result.
///
/// # Safety
///
/// As for [`oxi_aes_cmac`].
unsafe fn cmac_compute(
    key: *const OxiAesCmacKey,
    msg: *const u8,
    msg_len: usize,
    mac: *mut u8,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<CmacKey>(key) }?;
    disjoint(&[
        handle_span::<CmacKey>(key),
        span(msg, msg_len, false)?,
        span(mac, k.mac_len(), true)?,
    ])?;
    // SAFETY: `msg` passed `span` and `disjoint` above, so it is non-NULL or
    // empty and shares no byte with `mac` or the handle; it is valid for
    // `msg_len` bytes by contract.
    let msg = unsafe { input(msg, msg_len) };
    let mut staged_mac = staged(k.mac_len())?;
    cmac(k, msg, &mut staged_mac).map_err(R::from)?;
    // SAFETY: `mac` was checked by `span` and `disjoint` above, is valid for
    // the key's MAC length by contract, and does not overlap the module
    // buffer.
    unsafe { write_out(mac, &staged_mac) }
}

/// Verify `mac` as the CMAC of `msg` (SP 800-38B §6.3), comparing every
/// byte of the key's MAC length without an early exit.
///
/// Buffers: `msg`, `msg_len` bytes, NULL with a length of 0 allowed; `mac`,
/// the key's MAC length in bytes. No range may overlap the handle: an
/// overlap returns `InvalidInput = 5`. A handle of another mode returns
/// `InvalidInput = 5`. A NULL `key` returns 10; a module that is not
/// operational returns 1. A MAC that does not verify returns
/// `TagMismatch = 22`. Nothing is written.
///
/// # Safety
///
/// `key` must be NULL or a live key handle, and every non-NULL buffer valid
/// for its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_aes_cmac_verify(
    key: *const OxiAesCmacKey,
    msg: *const u8,
    msg_len: usize,
    mac: *const u8,
) -> c_int {
    // SAFETY: every pointer meets `cmac_check`'s contract, which is this
    // function's.
    code(unsafe { cmac_check(key, msg, msg_len, mac) })
}

/// [`oxi_aes_cmac_verify`] as a shim result.
///
/// # Safety
///
/// As for [`oxi_aes_cmac_verify`].
unsafe fn cmac_check(
    key: *const OxiAesCmacKey,
    msg: *const u8,
    msg_len: usize,
    mac: *const u8,
) -> Result<(), R> {
    // SAFETY: `key` is NULL or a live handle by contract, as `enter`
    // requires.
    let k = unsafe { enter::<CmacKey>(key) }?;
    disjoint(&[
        handle_span::<CmacKey>(key),
        span(msg, msg_len, false)?,
        span(mac, k.mac_len(), false)?,
    ])?;
    // SAFETY: `msg` and `mac` passed `span` and `disjoint` above, so each
    // is non-NULL or empty and shares no byte with the handle; each is valid
    // for its length by contract.
    let (msg, mac) = unsafe { (input(msg, msg_len), input(mac, k.mac_len())) };
    cmac_verify(k, msg, mac).map_err(R::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::rbg::{
        WRITES_BEFORE_REFUSAL, oxi_drbg_free, oxi_drbg_instantiate, oxi_hmac_drbg_sha256_new_rbg,
    };
    use core::ptr;
    use oxicrypt_module::{Error, KatEntry, State, initialize_with_tests, state};

    /// Set in the child process that runs one test on its own.
    const CHILD: &str = "OXICRYPT_STATE_GUARD_CHILD";

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    const KEY: [u8; 32] = [0x0b; 32];
    const OK: c_int = R::Ok as c_int;
    const INVALID: c_int = R::InvalidInput as c_int;

    /// Makes the module operational. Initialisation is process-global and
    /// idempotent here, so tests sharing a process each call it.
    fn setup() {
        match initialize_with_tests(UNSIGNED_TEST_BINARY, &[]) {
            Ok(()) | Err(Error::AlreadyInitialized) => {}
            Err(e) => panic!("module failed to initialise: {e:?}"),
        }
    }

    /// Runs `body` in a process of its own, because the module state is
    /// process-global and entering the error state is one-way.
    fn isolated(name: &str, body: impl FnOnce()) {
        if std::env::var_os(CHILD).is_some() {
            body();
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{name} did not pass in its own process:\n{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn gcm_key() -> *mut OxiAesGcmKey {
        let mut h = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_gcm_key_new(KEY.as_ptr(), 32, &raw mut h) },
            OK
        );
        h
    }

    fn ccm_key() -> *mut OxiAesCcmKey {
        let mut h = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_ccm_key_new(KEY.as_ptr(), 32, 16, &raw mut h) },
            OK
        );
        h
    }

    fn cbc_key() -> *mut OxiAesCbcKey {
        let mut h = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_cbc_key_new(KEY.as_ptr(), 32, &raw mut h) },
            OK
        );
        h
    }

    fn kw_key() -> *mut OxiAesKwKey {
        let mut h = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_kw_key_new(KEY.as_ptr(), 32, &raw mut h) },
            OK
        );
        h
    }

    fn cmac_key() -> *mut OxiAesCmacKey {
        let mut h = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_cmac_key_new(KEY.as_ptr(), 32, 16, &raw mut h) },
            OK
        );
        h
    }

    fn drbg() -> *mut OxiDrbg {
        let mut d = ptr::null_mut();
        unsafe {
            assert_eq!(oxi_hmac_drbg_sha256_new_rbg(&raw mut d), OK);
            assert_eq!(oxi_drbg_instantiate(d, ptr::null(), 0), OK);
        }
        d
    }

    fn seal(key: *const OxiAesGcmKey, d: *mut OxiDrbg, pt: &[u8], ct: &mut [u8]) -> c_int {
        let (mut iv, mut tag) = ([0u8; 12], [0u8; 16]);
        unsafe {
            oxi_aes_gcm_seal(
                key,
                d,
                ptr::null(),
                0,
                pt.as_ptr(),
                pt.len(),
                ct.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        }
    }

    fn ccm_open(key: *const OxiAesCcmKey, nonce: &[u8], ct: &[u8], tag: &[u8]) -> (c_int, bool) {
        let mut pt = [0xA5_u8; 20];
        let rc = unsafe {
            oxi_aes_ccm_open(
                key,
                nonce.as_ptr(),
                nonce.len(),
                ptr::null(),
                0,
                ct.as_ptr(),
                ct.len(),
                tag.as_ptr(),
                pt.as_mut_ptr(),
            )
        };
        (rc, pt == [0xA5_u8; 20])
    }

    /// Each handle's kind is checked: a handle of the matching mode is
    /// accepted, a handle of another mode is refused with 5 before any typed
    /// access, and a free of the wrong kind frees nothing.
    #[test]
    fn key_handle_kind_checked() {
        setup();
        let gcm = gcm_key();
        let ccm = ccm_key();
        let nonce = [0x1c_u8; 13];
        let pt = [0x42_u8; 20];
        let (mut ct, mut tag) = ([0u8; 20], [0u8; 16]);
        let ccm_seal = |key: *const OxiAesCcmKey, ct: &mut [u8; 20], tag: &mut [u8; 16]| unsafe {
            oxi_aes_ccm_seal(
                key,
                nonce.as_ptr(),
                13,
                ptr::null(),
                0,
                pt.as_ptr(),
                pt.len(),
                ct.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(ccm_seal(gcm.cast(), &mut ct, &mut tag), INVALID);
        assert_eq!((ct, tag), ([0u8; 20], [0u8; 16]), "a refused call writes");
        assert_eq!(ccm_seal(ccm, &mut ct, &mut tag), OK);
        assert_eq!(ccm_open(ccm, &nonce, &ct, &tag), (OK, false));

        let mut count = 7u64;
        assert_eq!(
            unsafe { oxi_aes_gcm_key_invocations(ccm.cast(), &raw mut count) },
            INVALID
        );
        assert_eq!(count, 7);
        assert_eq!(
            unsafe { oxi_aes_ccm_key_invocations(ccm, &raw mut count) },
            OK
        );
        assert!(count > 0);

        let (cbc, kw, cmac) = (cbc_key(), kw_key(), cmac_key());
        let block = [0u8; 16];
        let mut out = [0u8; 16];
        let cbc_rc = |key: *const OxiAesCbcKey, out: &mut [u8; 16]| unsafe {
            oxi_aes_cbc_encrypt(key, block.as_ptr(), block.as_ptr(), 16, out.as_mut_ptr())
        };
        assert_eq!(cbc_rc(kw.cast(), &mut out), INVALID);
        assert_eq!(cbc_rc(cbc, &mut out), OK);
        let mut mac = [0u8; 16];
        assert_eq!(
            unsafe { oxi_aes_cmac(cbc.cast(), block.as_ptr(), 16, mac.as_mut_ptr()) },
            INVALID
        );
        assert_eq!(
            unsafe { oxi_aes_cmac(cmac, block.as_ptr(), 16, mac.as_mut_ptr()) },
            OK
        );

        // A free of the wrong kind frees nothing: the handle still works.
        unsafe { oxi_aes_ccm_key_free(gcm.cast()) };
        let d = drbg();
        assert_eq!(seal(gcm, d, &pt, &mut ct), OK);
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
            oxi_aes_ccm_key_free(ccm);
            oxi_aes_cbc_key_free(cbc);
            oxi_aes_kw_key_free(kw);
            oxi_aes_cmac_key_free(cmac);
            oxi_aes_gcm_key_free(ptr::null_mut());
        }
    }

    /// Encryption in place is an overlap of the output with the input, and
    /// is refused with 5 with nothing written.
    #[test]
    fn cbc_encrypt_in_place_is_refused() {
        setup();
        let cbc = cbc_key();
        let iv = [0u8; 16];
        let mut buf = [0x33_u8; 32];
        let rc =
            unsafe { oxi_aes_cbc_encrypt(cbc, iv.as_ptr(), buf.as_ptr(), 32, buf.as_mut_ptr()) };
        assert_eq!(rc, INVALID);
        assert_eq!(buf, [0x33; 32]);
        let mut out = [0u8; 32];
        let rc =
            unsafe { oxi_aes_cbc_encrypt(cbc, iv.as_ptr(), buf.as_ptr(), 32, out.as_mut_ptr()) };
        assert_eq!(rc, OK, "the control: disjoint buffers encrypt");
        unsafe { oxi_aes_cbc_key_free(cbc) };
    }

    /// A `tag_out` inside `ciphertext` is refused with 5 before the DRBG is
    /// drawn from or the count is spent.
    #[test]
    fn gcm_seal_tag_inside_ciphertext_is_refused() {
        setup();
        let gcm = gcm_key();
        let d = drbg();
        let pt = [0x42_u8; 32];
        let mut ct = [0u8; 32];
        let mut iv = [0u8; 12];
        let seal_with_tag = |ct: &mut [u8; 32], iv: &mut [u8; 12], tag: *mut u8| unsafe {
            oxi_aes_gcm_seal(
                gcm,
                d,
                ptr::null(),
                0,
                pt.as_ptr(),
                32,
                ct.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag,
            )
        };
        let inside = unsafe { ct.as_mut_ptr().add(8) };
        assert_eq!(seal_with_tag(&mut ct, &mut iv, inside), INVALID);
        assert_eq!((ct, iv), ([0u8; 32], [0u8; 12]));
        let mut count = 1u64;
        assert_eq!(
            unsafe { oxi_aes_gcm_key_invocations(gcm, &raw mut count) },
            OK
        );
        assert_eq!(count, 0, "a refused call spends no invocation");
        let mut tag = [0u8; 16];
        assert_eq!(seal_with_tag(&mut ct, &mut iv, tag.as_mut_ptr()), OK);
        let mut back = [0u8; 32];
        let rc = unsafe {
            oxi_aes_gcm_open(
                gcm,
                iv.as_ptr(),
                ptr::null(),
                0,
                ct.as_ptr(),
                32,
                tag.as_ptr(),
                back.as_mut_ptr(),
            )
        };
        assert_eq!((rc, back), (OK, pt));
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
        }
    }

    /// A NULL pointer with a non-zero length returns 10; NULL with a length
    /// of 0 is an empty input.
    #[test]
    fn null_with_length_returns_10() {
        setup();
        let cmac = cmac_key();
        let mut mac = [0u8; 16];
        assert_eq!(
            unsafe { oxi_aes_cmac(cmac, ptr::null(), 1, mac.as_mut_ptr()) },
            R::NullPointer as c_int
        );
        assert_eq!(
            unsafe { oxi_aes_cmac(cmac, ptr::null(), 0, mac.as_mut_ptr()) },
            OK
        );
        assert_eq!(
            unsafe { oxi_aes_cmac(cmac, ptr::null(), 0, ptr::null_mut()) },
            R::NullPointer as c_int
        );
        assert_eq!(
            unsafe { oxi_aes_cmac(ptr::null(), ptr::null(), 0, mac.as_mut_ptr()) },
            R::NullPointer as c_int
        );
        assert_eq!(
            unsafe { oxi_aes_cmac(cmac, mac.as_ptr(), usize::MAX, ptr::null_mut()) },
            INVALID,
            "a length above isize::MAX"
        );
        unsafe { oxi_aes_cmac_key_free(cmac) };
    }

    /// A KW unwrap whose integrity check value does not verify leaves the
    /// sentinel in `out`; a verifying one fills it.
    #[test]
    fn kw_unwrap_failure_writes_nothing() {
        setup();
        let kw = kw_key();
        let secret = [0x5c_u8; 32];
        let mut wrapped = [0u8; 40];
        assert_eq!(
            unsafe { oxi_aes_kw_wrap(kw, secret.as_ptr(), 32, wrapped.as_mut_ptr()) },
            OK
        );
        let unwrap = |ct: &[u8; 40], out: &mut [u8; 32]| unsafe {
            oxi_aes_kw_unwrap(kw, ct.as_ptr(), 40, out.as_mut_ptr())
        };
        let mut bad = wrapped;
        bad[0] ^= 1;
        let mut out = [0xA5_u8; 32];
        assert_eq!(unwrap(&bad, &mut out), R::TagMismatch as c_int);
        assert_eq!(out, [0xA5; 32], "a failed unwrap wrote to out");
        assert_eq!(unwrap(&wrapped, &mut out), OK);
        assert_eq!(out, secret, "the control: a verifying unwrap fills out");
        unsafe { oxi_aes_kw_key_free(kw) };
    }

    /// A KWP unwrap that does not verify leaves `out` and `written` as they
    /// were.
    #[test]
    fn kwp_unwrap_failure_writes_nothing() {
        setup();
        let kw = kw_key();
        let secret = [0x5c_u8; 20];
        let (mut wrapped, mut n) = ([0u8; 32], 0usize);
        let rc = unsafe {
            oxi_aes_kwp_wrap(
                kw,
                secret.as_ptr(),
                20,
                wrapped.as_mut_ptr(),
                32,
                &raw mut n,
            )
        };
        assert_eq!((rc, n), (OK, 32));
        let mut bad = wrapped;
        bad[3] ^= 0x80;
        let (mut out, mut written) = ([0xA5_u8; 24], 99usize);
        let rc = unsafe {
            oxi_aes_kwp_unwrap(kw, bad.as_ptr(), 32, out.as_mut_ptr(), 24, &raw mut written)
        };
        assert_eq!(rc, R::TagMismatch as c_int);
        assert_eq!((out, written), ([0xA5; 24], 99));
        let rc = unsafe {
            oxi_aes_kwp_unwrap(
                kw,
                wrapped.as_ptr(),
                32,
                out.as_mut_ptr(),
                24,
                &raw mut written,
            )
        };
        assert_eq!((rc, written), (OK, 20));
        assert_eq!(out[..20], secret);
        unsafe { oxi_aes_kw_key_free(kw) };
    }

    /// An `out_cap` one byte short of the wrapped length returns 11 with
    /// nothing written.
    #[test]
    fn kwp_wrap_out_cap_one_short_returns_11() {
        setup();
        let kw = kw_key();
        let secret = [0x5c_u8; 20];
        let (mut out, mut written) = ([0xA5_u8; 32], 99usize);
        let rc = unsafe {
            oxi_aes_kwp_wrap(
                kw,
                secret.as_ptr(),
                20,
                out.as_mut_ptr(),
                31,
                &raw mut written,
            )
        };
        assert_eq!(rc, R::BufferTooSmall as c_int);
        assert_eq!((out, written), ([0xA5; 32], 99));
        let rc = unsafe {
            oxi_aes_kwp_wrap(
                kw,
                secret.as_ptr(),
                20,
                out.as_mut_ptr(),
                32,
                &raw mut written,
            )
        };
        assert_eq!((rc, written), (OK, 32));
        unsafe { oxi_aes_kw_key_free(kw) };
    }

    /// Every validity fault of a CCM decryption's input returns 22 with
    /// nothing written; a NULL nonce with a non-zero length returns 10.
    #[test]
    fn ccm_open_validity_faults_return_22() {
        setup();
        let ccm = ccm_key();
        let nonce = [0x1c_u8; 14];
        let pt = [0x42_u8; 20];
        let (mut ct, mut tag) = ([0u8; 20], [0u8; 16]);
        let rc = unsafe {
            oxi_aes_ccm_seal(
                ccm,
                nonce.as_ptr(),
                13,
                ptr::null(),
                0,
                pt.as_ptr(),
                20,
                ct.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(rc, OK);
        let mismatch = (R::TagMismatch as c_int, true);
        assert_eq!(ccm_open(ccm, &nonce[..6], &ct, &tag), mismatch);
        assert_eq!(ccm_open(ccm, &nonce[..14], &ct, &tag), mismatch);
        let mut flipped = tag;
        flipped[15] ^= 1;
        assert_eq!(ccm_open(ccm, &nonce[..13], &ct, &flipped), mismatch);
        assert_eq!(ccm_open(ccm, &nonce[..13], &ct, &tag), (OK, false));
        let mut out = [0xA5_u8; 20];
        let rc = unsafe {
            oxi_aes_ccm_open(
                ccm,
                ptr::null(),
                13,
                ptr::null(),
                0,
                ct.as_ptr(),
                20,
                tag.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        assert_eq!((rc, out), (R::NullPointer as c_int, [0xA5; 20]));
        unsafe { oxi_aes_ccm_key_free(ccm) };
    }

    /// A key built with a limit of one encryption seals once and then
    /// returns 34 with nothing written; the count reads back.
    ///
    /// That the exhausted call draws nothing from the DRBG is not observed
    /// here: the C interface exposes no DRBG counter, and each handle's
    /// instantiation draws fresh entropy, so no output can be compared
    /// across the call.
    #[test]
    fn gcm_seal_past_limit_returns_34() {
        setup();
        let mut gcm = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_gcm_key_new_with_limit(KEY.as_ptr(), 16, 1, &raw mut gcm) },
            OK
        );
        let mut refused = ptr::null_mut();
        for limit in [0, (1 << 32) + 1] {
            assert_eq!(
                unsafe {
                    oxi_aes_gcm_key_new_with_limit(KEY.as_ptr(), 16, limit, &raw mut refused)
                },
                INVALID,
                "limit {limit}"
            );
        }
        assert_eq!(
            unsafe {
                oxi_aes_gcm_key_new_with_count(KEY.as_ptr(), 16, (1 << 32) + 1, &raw mut refused)
            },
            INVALID
        );
        assert!(refused.is_null());
        let d = drbg();
        let pt = [0x42_u8; 16];
        let mut ct = [0u8; 16];
        assert_eq!(seal(gcm, d, &pt, &mut ct), OK);
        let (mut second, mut iv, mut tag) = ([0xA5_u8; 16], [0xA5_u8; 12], [0xA5_u8; 16]);
        let rc = unsafe {
            oxi_aes_gcm_seal(
                gcm,
                d,
                ptr::null(),
                0,
                pt.as_ptr(),
                16,
                second.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(rc, R::KeyExhausted as c_int);
        assert_eq!((second, iv, tag), ([0xA5; 16], [0xA5; 12], [0xA5; 16]));
        let mut count = 0u64;
        assert_eq!(
            unsafe { oxi_aes_gcm_key_invocations(gcm, &raw mut count) },
            OK
        );
        assert_eq!(count, 1);
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
        }
    }

    /// A CCM key whose count is preloaded to its limit returns 34 with
    /// nothing written.
    #[test]
    fn ccm_seal_at_limit_returns_34() {
        setup();
        let mut ccm = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_ccm_key_new_with_count(KEY.as_ptr(), 16, 8, 1 << 61, &raw mut ccm) },
            OK
        );
        let nonce = [0u8; 13];
        let (mut ct, mut tag) = ([0xA5_u8; 4], [0xA5_u8; 8]);
        let rc = unsafe {
            oxi_aes_ccm_seal(
                ccm,
                nonce.as_ptr(),
                13,
                ptr::null(),
                0,
                nonce.as_ptr(),
                4,
                ct.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(rc, R::KeyExhausted as c_int);
        assert_eq!((ct, tag), ([0xA5; 4], [0xA5; 8]));
        unsafe { oxi_aes_ccm_key_free(ccm) };
    }

    /// `oxi_aes_cmac_verify` accepts the MAC `oxi_aes_cmac` computed and
    /// refuses it with one bit flipped.
    #[test]
    fn cmac_verify_accepts_and_refuses_one_bit_flip() {
        setup();
        let cmac = cmac_key();
        let msg = b"a message of some length";
        let mut mac = [0u8; 16];
        assert_eq!(
            unsafe { oxi_aes_cmac(cmac, msg.as_ptr(), msg.len(), mac.as_mut_ptr()) },
            OK
        );
        let verify = |mac: &[u8; 16]| unsafe {
            oxi_aes_cmac_verify(cmac, msg.as_ptr(), msg.len(), mac.as_ptr())
        };
        assert_eq!(verify(&mac), OK);
        let mut flipped = mac;
        flipped[9] ^= 0x04;
        assert_eq!(verify(&flipped), R::TagMismatch as c_int);
        unsafe { oxi_aes_cmac_key_free(cmac) };
    }

    /// Every key constructor accepts 16, 24 and 32 key bytes and refuses
    /// every other length with 5.
    #[test]
    fn key_lengths_accepted() {
        setup();
        for len in [15, 16, 17, 24, 31, 32, 33] {
            let want = if matches!(len, 16 | 24 | 32) {
                OK
            } else {
                INVALID
            };
            let bytes = [0x11_u8; 33];
            let key = bytes.as_ptr();
            unsafe {
                let mut gcm = ptr::null_mut();
                assert_eq!(
                    oxi_aes_gcm_key_new(key, len, &raw mut gcm),
                    want,
                    "gcm {len}"
                );
                oxi_aes_gcm_key_free(gcm);
                let mut ccm = ptr::null_mut();
                assert_eq!(
                    oxi_aes_ccm_key_new(key, len, 16, &raw mut ccm),
                    want,
                    "ccm {len}"
                );
                oxi_aes_ccm_key_free(ccm);
                let mut cbc = ptr::null_mut();
                assert_eq!(
                    oxi_aes_cbc_key_new(key, len, &raw mut cbc),
                    want,
                    "cbc {len}"
                );
                oxi_aes_cbc_key_free(cbc);
                let mut ctr = ptr::null_mut();
                assert_eq!(
                    oxi_aes_ctr_key_new(key, len, &raw mut ctr),
                    want,
                    "ctr {len}"
                );
                oxi_aes_ctr_key_free(ctr);
                let mut kw = ptr::null_mut();
                assert_eq!(oxi_aes_kw_key_new(key, len, &raw mut kw), want, "kw {len}");
                oxi_aes_kw_key_free(kw);
                let mut cmac = ptr::null_mut();
                assert_eq!(
                    oxi_aes_cmac_key_new(key, len, 16, &raw mut cmac),
                    want,
                    "cmac {len}"
                );
                oxi_aes_cmac_key_free(cmac);
            }
        }
    }

    /// A key handle created while the module is operational produces no
    /// output through the C interface once the module has entered the error
    /// state.
    #[test]
    fn handle_refuses_output_after_error() {
        isolated("aes::tests::handle_refuses_output_after_error", || {
            initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(state(), State::Operational);
            let (ctr_key, cmac) = {
                let mut t = ptr::null_mut();
                assert_eq!(
                    unsafe { oxi_aes_ctr_key_new(KEY.as_ptr(), 32, &raw mut t) },
                    OK
                );
                (t, cmac_key())
            };
            oxicrypt_module::enter_error_state("live-handle refusal test");
            let refused = R::NotOperational as c_int;
            let counter = [0u8; 16];
            let pt = [1u8; 16];
            let (mut ct, mut mac) = ([0u8; 16], [0u8; 16]);
            let rc =
                unsafe { oxi_aes_ctr(ctr_key, counter.as_ptr(), pt.as_ptr(), 16, ct.as_mut_ptr()) };
            assert_eq!(rc, refused);
            let rc = unsafe { oxi_aes_cmac(cmac, pt.as_ptr(), 16, mac.as_mut_ptr()) };
            assert_eq!(rc, refused);
            assert_eq!((ct, mac), ([0u8; 16], [0u8; 16]));
            unsafe {
                oxi_aes_ctr_key_free(ctr_key);
                oxi_aes_cmac_key_free(cmac);
            }
        });
    }

    const NULL: c_int = R::NullPointer as c_int;
    const MISMATCH: c_int = R::TagMismatch as c_int;

    fn gcm_count(key: *const OxiAesGcmKey) -> u64 {
        let mut n = u64::MAX;
        assert_eq!(unsafe { oxi_aes_gcm_key_invocations(key, &raw mut n) }, OK);
        n
    }

    fn ccm_count(key: *const OxiAesCcmKey) -> u64 {
        let mut n = u64::MAX;
        assert_eq!(unsafe { oxi_aes_ccm_key_invocations(key, &raw mut n) }, OK);
        n
    }

    /// An input inside the key handle, and a DRBG handle that is the key
    /// handle, are refused with 5 before the DRBG is taken or the count is
    /// spent.
    #[test]
    fn handle_aliasing_refused() {
        setup();
        let gcm = gcm_key();
        let d = drbg();
        let pt = [0x42_u8; 16];
        let aad = [7u8; 1];
        let (mut ct, mut iv, mut tag) = ([0u8; 16], [0u8; 12], [0u8; 16]);
        let mut seal_with = |aad: *const u8, d: *mut OxiDrbg, ct: &mut [u8; 16]| unsafe {
            oxi_aes_gcm_seal(
                gcm,
                d,
                aad,
                1,
                pt.as_ptr(),
                16,
                ct.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(
            seal_with(gcm.cast::<u8>(), d, &mut ct),
            INVALID,
            "aad in the key"
        );
        assert_eq!(
            seal_with(aad.as_ptr(), gcm.cast::<OxiDrbg>(), &mut ct),
            INVALID,
            "the key handle as the DRBG"
        );
        assert_eq!(ct, [0u8; 16]);
        assert_eq!(gcm_count(gcm), 0);
        assert_eq!(seal_with(aad.as_ptr(), d, &mut ct), OK, "the control");
        assert_eq!(gcm_count(gcm), 1);
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
        }
    }

    /// A GCM seal whose second copy is refused, as when the module leaves
    /// the operational state between copies, zeroes the ciphertext it
    /// copied and leaves the IV and the tag unwritten.
    #[test]
    fn gcm_seal_refused_copy_zeroes_earlier_output() {
        setup();
        let gcm = gcm_key();
        let d = drbg();
        let pt = [0x42_u8; 32];
        let (mut ct, mut iv, mut tag) = ([0xA5_u8; 32], [0xA5_u8; 12], [0xA5_u8; 16]);
        let mut seal_all = || unsafe {
            oxi_aes_gcm_seal(
                gcm,
                d,
                ptr::null(),
                0,
                pt.as_ptr(),
                32,
                ct.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        WRITES_BEFORE_REFUSAL.set(Some(1));
        assert_eq!(seal_all(), R::NotOperational as c_int);
        assert_eq!(
            WRITES_BEFORE_REFUSAL.get(),
            None,
            "the refusal was not reached"
        );
        assert_eq!(ct, [0u8; 32], "the copied ciphertext survived");
        assert_eq!((iv, tag), ([0xA5; 12], [0xA5; 16]));
        let mut seal_all = || unsafe {
            oxi_aes_gcm_seal(
                gcm,
                d,
                ptr::null(),
                0,
                pt.as_ptr(),
                32,
                ct.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(seal_all(), OK, "the control: an unrefused seal");
        assert_ne!(ct, [0u8; 32]);
        assert_ne!((iv, tag), ([0xA5; 12], [0xA5; 16]));
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
        }
    }

    /// A key construction whose allocation fails returns 255 and leaves
    /// `*out` unchanged.
    #[test]
    fn key_new_alloc_failure_returns_255() {
        setup();
        let sentinel = ptr::dangling_mut::<OxiAesGcmKey>();
        let mut h = sentinel;
        handle::FAIL_NEXT_KEY_ALLOC.set(true);
        let rc = unsafe { oxi_aes_gcm_key_new(KEY.as_ptr(), 32, &raw mut h) };
        assert_eq!(rc, R::Internal as c_int);
        assert!(
            !handle::FAIL_NEXT_KEY_ALLOC.get(),
            "the seam was not reached"
        );
        assert_eq!(h, sentinel, "a failed construction wrote the handle");
        assert_eq!(
            unsafe { oxi_aes_gcm_key_new(KEY.as_ptr(), 32, &raw mut h) },
            OK
        );
        assert_ne!(h, sentinel);
        unsafe { oxi_aes_gcm_key_free(h) };
    }

    /// A key of a length no mode accepts returns 5 from every `_key_new`,
    /// wipes and releases the allocation the key was to be built in, and
    /// leaves `*out` unchanged, so no handle is written and none is freed.
    /// The release is counted inside the free path itself, and with the
    /// `fault-injection` feature each released allocation reads as all zero
    /// after its wipe. None of these constructors writes the key field
    /// before refusing a length; the CMAC derivation failure, which does,
    /// is `cmac_key_new_derive_failure_wipes_and_releases`.
    #[test]
    fn key_new_wrong_length_returns_5_and_releases_its_allocation() {
        setup();
        let bytes = [0x11_u8; 17];
        let key = bytes.as_ptr();
        let before = handle::LIVE_KEY_ALLOCS.get();
        let freed_before = crate::rbg::WIPED_AND_FREED.get();
        let released = |rc: c_int, name: &str| {
            assert_eq!(rc, INVALID, "{name}");
            #[cfg(feature = "fault-injection")]
            assert_eq!(crate::rbg::last_freed_bytes_zero(), 1, "{name}");
        };
        let mut gcm = ptr::dangling_mut::<OxiAesGcmKey>();
        let mut gcm_count = ptr::dangling_mut::<OxiAesGcmKey>();
        let mut gcm_limit = ptr::dangling_mut::<OxiAesGcmKey>();
        let mut ccm = ptr::dangling_mut::<OxiAesCcmKey>();
        let mut ccm_count = ptr::dangling_mut::<OxiAesCcmKey>();
        let mut cbc = ptr::dangling_mut::<OxiAesCbcKey>();
        let mut ctr = ptr::dangling_mut::<OxiAesCtrKey>();
        let mut kw = ptr::dangling_mut::<OxiAesKwKey>();
        let mut cmac = ptr::dangling_mut::<OxiAesCmacKey>();
        unsafe {
            released(oxi_aes_gcm_key_new(key, 17, &raw mut gcm), "gcm");
            released(
                oxi_aes_gcm_key_new_with_count(key, 17, 1, &raw mut gcm_count),
                "gcm with count",
            );
            released(
                oxi_aes_gcm_key_new_with_limit(key, 17, 1, &raw mut gcm_limit),
                "gcm with limit",
            );
            released(oxi_aes_ccm_key_new(key, 17, 16, &raw mut ccm), "ccm");
            released(
                oxi_aes_ccm_key_new_with_count(key, 17, 16, 1, &raw mut ccm_count),
                "ccm with count",
            );
            released(oxi_aes_cbc_key_new(key, 17, &raw mut cbc), "cbc");
            released(oxi_aes_ctr_key_new(key, 17, &raw mut ctr), "ctr");
            released(oxi_aes_kw_key_new(key, 17, &raw mut kw), "kw");
            released(oxi_aes_cmac_key_new(key, 17, 16, &raw mut cmac), "cmac");
        }
        assert_eq!(crate::rbg::WIPED_AND_FREED.get() - freed_before, 9);
        assert_eq!(gcm, ptr::dangling_mut());
        assert_eq!(gcm_count, ptr::dangling_mut());
        assert_eq!(gcm_limit, ptr::dangling_mut());
        assert_eq!(ccm, ptr::dangling_mut());
        assert_eq!(ccm_count, ptr::dangling_mut());
        assert_eq!(cbc, ptr::dangling_mut());
        assert_eq!(ctr, ptr::dangling_mut());
        assert_eq!(kw, ptr::dangling_mut());
        assert_eq!(cmac, ptr::dangling_mut());
        assert_eq!(
            handle::LIVE_KEY_ALLOCS.get(),
            before,
            "an allocation leaked"
        );

        // The control: a key the mode accepts holds its allocation until the
        // handle is freed.
        let mut ok = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_gcm_key_new(KEY.as_ptr(), 32, &raw mut ok) },
            OK
        );
        assert_eq!(handle::LIVE_KEY_ALLOCS.get(), before + 1);
        unsafe { oxi_aes_gcm_key_free(ok) };
        assert_eq!(handle::LIVE_KEY_ALLOCS.get(), before);
    }

    /// Builds a handle through `new`, runs `check` on it and frees it
    /// through `free`, and requires that construction wiped no round-key
    /// schedule and the free wiped exactly one: the free runs the
    /// destructor of the key built in place in the allocation.
    #[cfg(feature = "fault-injection")]
    fn pin_free_wipes_schedule<H>(
        name: &str,
        new: impl FnOnce(*mut *mut H) -> c_int,
        check: impl FnOnce(*mut H),
        free: impl FnOnce(*mut H),
    ) {
        use oxicrypt_aes::seam::schedule_wipes;
        let before = schedule_wipes();
        let mut h = ptr::null_mut();
        assert_eq!(new(&raw mut h), OK, "{name}");
        assert!(!h.is_null(), "{name}");
        check(h);
        assert_eq!(schedule_wipes(), before, "{name}: construction");
        free(h);
        assert_eq!(
            schedule_wipes().checked_sub(before),
            Some(1),
            "{name}: free"
        );
    }

    /// Every kind of key handle, from each of its `_key_new` functions,
    /// has its round-key schedule wiped once when its `_key_free` runs,
    /// and the handles built with a preloaded count report it. The wipe
    /// counter is process-global, so the test runs in a process of its own.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn every_key_handle_free_wipes_its_schedule_once() {
        isolated(
            "aes::tests::every_key_handle_free_wipes_its_schedule_once",
            || {
                setup();
                let k = KEY.as_ptr();
                pin_free_wipes_schedule(
                    "gcm",
                    |o| unsafe { oxi_aes_gcm_key_new(k, 32, o) },
                    |h| assert_eq!(gcm_count(h), 0),
                    |h| unsafe { oxi_aes_gcm_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "gcm with count",
                    |o| unsafe { oxi_aes_gcm_key_new_with_count(k, 32, 7, o) },
                    |h| assert_eq!(gcm_count(h), 7),
                    |h| unsafe { oxi_aes_gcm_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "gcm with limit",
                    |o| unsafe { oxi_aes_gcm_key_new_with_limit(k, 32, 3, o) },
                    |_| {},
                    |h| unsafe { oxi_aes_gcm_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "ccm",
                    |o| unsafe { oxi_aes_ccm_key_new(k, 32, 16, o) },
                    |h| assert_eq!(ccm_count(h), 0),
                    |h| unsafe { oxi_aes_ccm_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "ccm with count",
                    |o| unsafe { oxi_aes_ccm_key_new_with_count(k, 32, 16, 9, o) },
                    |h| assert_eq!(ccm_count(h), 9),
                    |h| unsafe { oxi_aes_ccm_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "cbc",
                    |o| unsafe { oxi_aes_cbc_key_new(k, 32, o) },
                    |_| {},
                    |h| unsafe { oxi_aes_cbc_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "ctr",
                    |o| unsafe { oxi_aes_ctr_key_new(k, 32, o) },
                    |_| {},
                    |h| unsafe { oxi_aes_ctr_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "kw",
                    |o| unsafe { oxi_aes_kw_key_new(k, 32, o) },
                    |_| {},
                    |h| unsafe { oxi_aes_kw_key_free(h) },
                );
                pin_free_wipes_schedule(
                    "cmac",
                    |o| unsafe { oxi_aes_cmac_key_new(k, 32, 16, o) },
                    |_| {},
                    |h| unsafe { oxi_aes_cmac_key_free(h) },
                );
            },
        );
    }

    /// A CMAC derivation that fails after the schedule is expanded, here a
    /// module error injected between the expansion and the subkey
    /// derivation, returns 1 after writing the key field: the partly
    /// derived key's schedule is wiped once when the constructor replaces
    /// it with a zeroed key, the allocation is wiped to zero and released,
    /// and `*out` is unchanged. The error state is permanent, so the test
    /// runs in a process of its own.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn cmac_key_new_derive_failure_wipes_and_releases() {
        isolated(
            "aes::tests::cmac_key_new_derive_failure_wipes_and_releases",
            || {
                use oxicrypt_aes::seam::schedule_wipes;
                setup();
                let (allocs, freed, wiped) = (
                    handle::LIVE_KEY_ALLOCS.get(),
                    crate::rbg::WIPED_AND_FREED.get(),
                    schedule_wipes(),
                );
                let mut out = ptr::dangling_mut::<OxiAesCmacKey>();
                oxicrypt_cmac::seam::error_after_next_expansion();
                let rc = unsafe { oxi_aes_cmac_key_new(KEY.as_ptr(), 32, 16, &raw mut out) };
                assert_eq!(rc, R::NotOperational as c_int);
                assert_eq!(out, ptr::dangling_mut());
                assert_eq!(schedule_wipes() - wiped, 1);
                assert_eq!(crate::rbg::WIPED_AND_FREED.get() - freed, 1);
                assert_eq!(crate::rbg::last_freed_bytes_zero(), 1);
                assert_eq!(handle::LIVE_KEY_ALLOCS.get(), allocs);
            },
        );
    }

    /// A CCM open whose `ct_len` the nonce's length field cannot represent
    /// returns 22 before the Rust function runs, so no module buffer is
    /// staged and no count is charged; one byte shorter reaches the Rust
    /// function, which charges the count.
    #[test]
    fn ccm_open_unrepresentable_length_returns_22_uncharged() {
        setup();
        let ccm = ccm_key();
        let nonce = [0x1c_u8; 13];
        let tag = [0u8; 16];
        let ct = vec![0u8; 0x1_0000];
        let mut pt = vec![0xA5_u8; 0x1_0000];
        let mut open = |len: usize| unsafe {
            oxi_aes_ccm_open(
                ccm,
                nonce.as_ptr(),
                13,
                ptr::null(),
                0,
                ct.as_ptr(),
                len,
                tag.as_ptr(),
                pt.as_mut_ptr(),
            )
        };
        let before = ccm_count(ccm);
        assert_eq!(open(0x1_0000), MISMATCH);
        assert_eq!(ccm_count(ccm), before, "the Rust function ran");
        assert_eq!(
            open(0xFFFF),
            MISMATCH,
            "the control: a representable length"
        );
        assert!(ccm_count(ccm) > before);
        assert!(pt.iter().all(|&b| b == 0xA5));
        unsafe { oxi_aes_ccm_key_free(ccm) };
    }

    /// A handle of another mode is refused with 5 by a symbol of each mode
    /// not covered by `key_handle_kind_checked`, and the symbol's own
    /// handle is accepted.
    #[test]
    fn foreign_kind_refused_by_every_mode() {
        setup();
        let (gcm, ccm, cbc, kw, cmac) = (gcm_key(), ccm_key(), cbc_key(), kw_key(), cmac_key());
        let mut ctr = ptr::null_mut();
        assert_eq!(
            unsafe { oxi_aes_ctr_key_new(KEY.as_ptr(), 32, &raw mut ctr) },
            OK
        );
        let block = [0x11_u8; 32];
        let mut out = [0u8; 40];
        let ctr_rc = |key: *const OxiAesCtrKey, out: &mut [u8; 40]| unsafe {
            oxi_aes_ctr(key, block.as_ptr(), block.as_ptr(), 16, out.as_mut_ptr())
        };
        assert_eq!(ctr_rc(cbc.cast(), &mut out), INVALID, "ctr");
        assert_eq!(ctr_rc(ctr, &mut out), OK);
        let kw_rc = |key: *const OxiAesKwKey, out: &mut [u8; 40]| unsafe {
            oxi_aes_kw_wrap(key, block.as_ptr(), 32, out.as_mut_ptr())
        };
        assert_eq!(kw_rc(ctr.cast(), &mut out), INVALID, "kw");
        assert_eq!(kw_rc(kw, &mut out), OK);
        let mut n = 0usize;
        let padded_wrap = |key: *const OxiAesKwKey, out: &mut [u8; 40], n: &mut usize| unsafe {
            oxi_aes_kwp_wrap(key, block.as_ptr(), 20, out.as_mut_ptr(), 40, n)
        };
        assert_eq!(padded_wrap(cmac.cast(), &mut out, &mut n), INVALID, "kwp");
        assert_eq!(padded_wrap(kw, &mut out, &mut n), OK);
        let d = drbg();
        let mut ct = [0u8; 16];
        assert_eq!(seal(ccm.cast(), d, &block[..16], &mut ct), INVALID, "gcm");
        assert_eq!(seal(gcm, d, &block[..16], &mut ct), OK);
        let mut pt = [0xA5_u8; 20];
        let ccm_rc = |key: *const OxiAesCcmKey, pt: &mut [u8; 20]| unsafe {
            oxi_aes_ccm_open(
                key,
                block.as_ptr(),
                13,
                ptr::null(),
                0,
                block.as_ptr(),
                20,
                block.as_ptr(),
                pt.as_mut_ptr(),
            )
        };
        assert_eq!(ccm_rc(gcm.cast(), &mut pt), INVALID, "ccm");
        assert_eq!(
            ccm_rc(ccm, &mut pt),
            MISMATCH,
            "the control reaches the tag check"
        );
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
            oxi_aes_ccm_key_free(ccm);
            oxi_aes_cbc_key_free(cbc);
            oxi_aes_ctr_key_free(ctr);
            oxi_aes_kw_key_free(kw);
            oxi_aes_cmac_key_free(cmac);
        }
    }

    /// CBC in either direction refuses `out = in + 16` and an `out` over
    /// `iv` with 5 and nothing written; disjoint buffers succeed.
    #[test]
    fn cbc_overlaps_refused() {
        type CbcOp = unsafe extern "C" fn(
            *const OxiAesCbcKey,
            *const u8,
            *const u8,
            usize,
            *mut u8,
        ) -> c_int;
        setup();
        let cbc = cbc_key();
        let ops: [(CbcOp, &str); 2] = [
            (oxi_aes_cbc_encrypt, "encrypt"),
            (oxi_aes_cbc_decrypt, "decrypt"),
        ];
        let iv = [0u8; 16];
        let input = [0x44_u8; 32];
        for (op, name) in ops {
            let mut buf = [0x33_u8; 64];
            let base = buf.as_mut_ptr();
            let rc = unsafe { op(cbc, iv.as_ptr(), base, 32, base.add(16)) };
            assert_eq!(rc, INVALID, "{name}: out = in + 16");
            let rc = unsafe { op(cbc, base, input.as_ptr(), 32, base.add(8)) };
            assert_eq!(rc, INVALID, "{name}: out over iv");
            assert_eq!(buf, [0x33; 64]);
            let mut out = [0u8; 32];
            let rc = unsafe { op(cbc, iv.as_ptr(), input.as_ptr(), 32, out.as_mut_ptr()) };
            assert_eq!(rc, OK, "{name}: the control");
        }
        unsafe { oxi_aes_cbc_key_free(cbc) };
    }

    /// A GCM seal refuses with 5 each overlapping output pair named below,
    /// before the count is spent; disjoint buffers succeed.
    #[test]
    fn gcm_seal_output_overlaps_refused() {
        setup();
        let gcm = gcm_key();
        let d = drbg();
        let pt = [0x42_u8; 16];
        let mut buf = [0u8; 64];
        let base = buf.as_mut_ptr();
        let (mut ct, mut iv, mut tag) = ([0u8; 16], [0u8; 12], [0u8; 16]);
        let seal_at = |pt: *const u8, ct: *mut u8, iv: *mut u8, tag: *mut u8| unsafe {
            oxi_aes_gcm_seal(gcm, d, ptr::null(), 0, pt, 16, ct, iv, tag)
        };
        unsafe {
            let rc = seal_at(pt.as_ptr(), ct.as_mut_ptr(), base, base.add(8));
            assert_eq!(rc, INVALID, "tag_out over iv_out");
            let rc = seal_at(pt.as_ptr(), base, base.add(10), tag.as_mut_ptr());
            assert_eq!(rc, INVALID, "iv_out over ct");
            let rc = seal_at(base, base.add(8), iv.as_mut_ptr(), tag.as_mut_ptr());
            assert_eq!(rc, INVALID, "ct over pt");
        }
        assert_eq!(buf, [0u8; 64]);
        assert_eq!(gcm_count(gcm), 0);
        let rc = seal_at(
            pt.as_ptr(),
            ct.as_mut_ptr(),
            iv.as_mut_ptr(),
            tag.as_mut_ptr(),
        );
        assert_eq!(rc, OK, "the control");
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
        }
    }

    /// A NULL `aad` with an `aad_len` of 1 on a GCM seal, and a NULL
    /// `written` on a KWP wrap, return 10.
    #[test]
    fn null_aad_and_null_written_return_10() {
        setup();
        let gcm = gcm_key();
        let d = drbg();
        let pt = [0x42_u8; 16];
        let (mut ct, mut iv, mut tag) = ([0u8; 16], [0u8; 12], [0u8; 16]);
        let aad = [1u8; 1];
        let mut seal_aad = |aad: *const u8, ct: &mut [u8; 16]| unsafe {
            oxi_aes_gcm_seal(
                gcm,
                d,
                aad,
                1,
                pt.as_ptr(),
                16,
                ct.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(seal_aad(ptr::null(), &mut ct), NULL);
        assert_eq!(seal_aad(aad.as_ptr(), &mut ct), OK, "the control");
        let kw = kw_key();
        let mut out = [0u8; 32];
        let mut n = 0usize;
        let wrap = |written: *mut usize, out: &mut [u8; 32]| unsafe {
            oxi_aes_kwp_wrap(kw, pt.as_ptr(), 16, out.as_mut_ptr(), 32, written)
        };
        assert_eq!(wrap(ptr::null_mut(), &mut out), NULL);
        assert_eq!(out, [0u8; 32]);
        assert_eq!(wrap(&raw mut n, &mut out), OK, "the control");
        assert_eq!(n, 24);
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
            oxi_aes_kw_key_free(kw);
        }
    }

    /// A KW wrap in place, `out` sharing bytes with `pt`, is refused with
    /// 5 with nothing written; disjoint buffers succeed.
    #[test]
    fn kw_wrap_in_place_is_refused() {
        setup();
        let kw = kw_key();
        let mut buf = [0x5c_u8; 48];
        let base = buf.as_mut_ptr();
        let rc = unsafe { oxi_aes_kw_wrap(kw, base.add(8), 32, base) };
        assert_eq!(rc, INVALID);
        assert_eq!(buf, [0x5c; 48]);
        let mut out = [0u8; 40];
        let rc = unsafe { oxi_aes_kw_wrap(kw, buf.as_ptr(), 32, out.as_mut_ptr()) };
        assert_eq!(rc, OK, "the control");
        unsafe { oxi_aes_kw_key_free(kw) };
    }

    /// A KWP unwrap of a valid wrap with `out_cap` one byte short of the
    /// unwrapped length returns 11 with `out` and `written` untouched.
    #[test]
    fn kwp_unwrap_out_cap_one_short_returns_11() {
        setup();
        let kw = kw_key();
        let secret = [0x5c_u8; 20];
        let (mut wrapped, mut n) = ([0u8; 32], 0usize);
        let rc = unsafe {
            oxi_aes_kwp_wrap(
                kw,
                secret.as_ptr(),
                20,
                wrapped.as_mut_ptr(),
                32,
                &raw mut n,
            )
        };
        assert_eq!((rc, n), (OK, 32));
        let (mut out, mut written) = ([0xA5_u8; 24], 99usize);
        let mut unwrap = |cap: usize| unsafe {
            oxi_aes_kwp_unwrap(
                kw,
                wrapped.as_ptr(),
                32,
                out.as_mut_ptr(),
                cap,
                &raw mut written,
            )
        };
        assert_eq!(unwrap(19), R::BufferTooSmall as c_int);
        assert_eq!((out, written), ([0xA5; 24], 99));
        let rc = unsafe {
            oxi_aes_kwp_unwrap(
                kw,
                wrapped.as_ptr(),
                32,
                out.as_mut_ptr(),
                20,
                &raw mut written,
            )
        };
        assert_eq!((rc, written), (OK, 20), "the control");
        assert_eq!(out[..20], secret);
        unsafe { oxi_aes_kw_key_free(kw) };
    }

    /// A GCM open whose tag has one bit flipped returns 22 and leaves the
    /// plaintext buffer at its sentinel; the unflipped tag opens.
    #[test]
    fn gcm_open_flipped_tag_writes_nothing() {
        setup();
        let gcm = gcm_key();
        let d = drbg();
        let pt = [0x42_u8; 24];
        let (mut ct, mut iv, mut tag) = ([0u8; 24], [0u8; 12], [0u8; 16]);
        let rc = unsafe {
            oxi_aes_gcm_seal(
                gcm,
                d,
                ptr::null(),
                0,
                pt.as_ptr(),
                24,
                ct.as_mut_ptr(),
                iv.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(rc, OK);
        let mut back = [0xA5_u8; 24];
        let mut open = |tag: &[u8; 16]| unsafe {
            oxi_aes_gcm_open(
                gcm,
                iv.as_ptr(),
                ptr::null(),
                0,
                ct.as_ptr(),
                24,
                tag.as_ptr(),
                back.as_mut_ptr(),
            )
        };
        let mut flipped = tag;
        flipped[0] ^= 0x01;
        assert_eq!(open(&flipped), MISMATCH);
        assert_eq!(open(&tag), OK, "the control");
        let mut refused = [0xA5_u8; 24];
        let rc = unsafe {
            oxi_aes_gcm_open(
                gcm,
                iv.as_ptr(),
                ptr::null(),
                0,
                ct.as_ptr(),
                24,
                flipped.as_ptr(),
                refused.as_mut_ptr(),
            )
        };
        assert_eq!((rc, refused), (MISMATCH, [0xA5; 24]));
        assert_eq!(back, pt);
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(gcm);
        }
    }

    /// A CCM open whose tag does not verify charges the key's count.
    #[test]
    fn ccm_open_failed_decryption_charges_count() {
        setup();
        let ccm = ccm_key();
        let nonce = [0x1c_u8; 13];
        let ct = [0u8; 20];
        let tag = [0u8; 16];
        let before = ccm_count(ccm);
        assert_eq!(before, 0);
        assert_eq!(ccm_open(ccm, &nonce, &ct, &tag), (MISMATCH, true));
        assert!(
            ccm_count(ccm) > before,
            "a failed decryption was not counted"
        );
        unsafe { oxi_aes_ccm_key_free(ccm) };
    }

    /// A GCM limit of 2^32 is accepted and 2^32 + 1 refused; a count of
    /// 2^32 is accepted as an exhausted key, which seals nothing.
    #[test]
    fn gcm_limit_and_count_boundaries() {
        setup();
        let mut h = ptr::null_mut();
        let new_with_limit = |limit: u64, h: &mut *mut OxiAesGcmKey| unsafe {
            oxi_aes_gcm_key_new_with_limit(KEY.as_ptr(), 32, limit, h)
        };
        assert_eq!(new_with_limit(1 << 32, &mut h), OK);
        unsafe { oxi_aes_gcm_key_free(h) };
        h = ptr::null_mut();
        assert_eq!(new_with_limit((1 << 32) + 1, &mut h), INVALID);
        assert!(h.is_null());
        assert_eq!(
            unsafe { oxi_aes_gcm_key_new_with_count(KEY.as_ptr(), 32, 1 << 32, &raw mut h) },
            OK
        );
        assert_eq!(gcm_count(h), 1 << 32);
        let d = drbg();
        let mut ct = [0xA5_u8; 16];
        assert_eq!(seal(h, d, &[0x42; 16], &mut ct), R::KeyExhausted as c_int);
        assert_eq!(ct, [0xA5; 16]);
        unsafe {
            oxi_drbg_free(d);
            oxi_aes_gcm_key_free(h);
        }
    }
}
