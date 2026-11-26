//! Opaque handle pattern.
//!
//! Lifecycle:
//!   `_new(...)` returns a heap-allocated handle via double-pointer.
//!   `_free(handle)` deallocates; safe to call on NULL.

use core::sync::atomic::AtomicU64;

/// Container for handle state.
///
/// `T` is the inner Rust type (e.g. a DRBG instance).
pub(crate) struct OxiHandle<T> {
    pub(crate) inner: Option<T>,
    /// The process that instantiated the handle's DRBG from the module's
    /// seed path, or 0 if it never was. Set by the typed DRBG handles'
    /// `_instantiate_from_module` and read on every call that reaches
    /// their DRBG; other handles leave it 0.
    pub(crate) pid: AtomicU64,
}

impl<T> OxiHandle<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner: Some(inner),
            pid: AtomicU64::new(0),
        }
    }

    /// Borrow the inner state.
    ///
    /// Read-only accessor that hides the `Option<T>` representation
    /// from callers.
    pub(crate) fn as_ref(&self) -> Option<&T> {
        self.inner.as_ref()
    }

    /// Mutably borrow the inner state.
    ///
    /// Required by handle types that mutate per-call state (e.g.
    /// `OxiHmacDrbgSha256`, where `instantiate` / `reseed` / `generate`
    /// each advance the DRBG's internal `(K, V, reseed_counter)`
    /// tuple).
    pub(crate) fn as_mut(&mut self) -> Option<&mut T> {
        self.inner.as_mut()
    }
}
