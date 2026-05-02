//! Opaque handle pattern with consumed-sentinel for safe-no-op-after-finalize.
//!
//! Lifecycle:
//!   `_new(...)` returns a heap-allocated handle via double-pointer.
//!   `_free(handle)` deallocates; safe to call on NULL or on a consumed handle.
//!   `_finalize(handle, out)` consumes the inner state, sets the sentinel,
//!     and is safe to follow with `_free`.
//!
//! Zeroize-on-Drop is preserved: when `_free` runs, Drop fires on the
//! still-present-but-sentinel-tagged inner; if zeroize already ran during
//! `_finalize`, the second pass is idempotent (zeroizing zeroes is a no-op).
//!
//! Per `feedback_cmvp_reviewer_framing` F5: safe-no-op over UB. The CMVP
//! reviewer expects every handle-bearing API to define behaviour after
//! finalize/free, not leave it as undefined.

use core::sync::atomic::{AtomicBool, Ordering};

/// Container for handle state with a consumed flag.
///
/// `T` is the inner Rust type (e.g. `Aes256Key`, `Sha256`). `consumed`
/// flips to `true` when `_finalize` runs. Subsequent `_free` calls
/// observe the flag and skip operations that would be unsound on
/// consumed state.
pub(crate) struct OxiHandle<T> {
    pub(crate) inner: Option<T>,
    // First call site for the consumed flag is the first
    // finalize-bearing handle (e.g. an SHA streaming context where
    // `_finalize(handle, out)` consumes the inner state to release
    // the digest). AES-GCM uses one-shot semantics and only exercises
    // `OxiHandle::new` + Drop. Allow the unused warning until the
    // first such handle lands.
    #[allow(dead_code)]
    pub(crate) consumed: AtomicBool,
}

impl<T> OxiHandle<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner: Some(inner),
            consumed: AtomicBool::new(false),
        }
    }

    /// Take inner state, mark consumed. Idempotent: subsequent calls
    /// return `None` even if `inner` is still `Some`. The `AcqRel`
    /// ordering on the swap ensures the consumed flag becomes visible
    /// to any concurrent `_free` before the inner is taken.
    #[allow(dead_code)] // first call site lands with the first finalize-bearing handle
    pub(crate) fn consume(&mut self) -> Option<T> {
        if self.consumed.swap(true, Ordering::AcqRel) {
            None
        } else {
            self.inner.take()
        }
    }

    #[allow(dead_code)] // first call site lands with the first finalize-bearing handle
    pub(crate) fn is_consumed(&self) -> bool {
        self.consumed.load(Ordering::Acquire)
    }

    /// Borrow the inner state, if not yet consumed.
    ///
    /// Read-only accessor that hides the `Option<T>` representation
    /// from callers. Returns `None` once the handle has been finalized.
    pub(crate) fn as_ref(&self) -> Option<&T> {
        self.inner.as_ref()
    }

    /// Mutably borrow the inner state, if not yet consumed.
    ///
    /// Required by handle types that mutate per-call state (e.g.
    /// `OxiHmacDrbgSha256`, where `instantiate` / `reseed` / `generate`
    /// each advance the DRBG's internal `(K, V, reseed_counter)`
    /// tuple). AES handles use `as_ref` because their per-call mode
    /// implementations are pure functions over `&Aes256Key`.
    pub(crate) fn as_mut(&mut self) -> Option<&mut T> {
        self.inner.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// Test-only inner type whose Drop increments a shared counter so
    /// `handle_drop_after_consume_is_idempotent` can verify the inner
    /// is dropped exactly once, not twice.
    struct InnerWithCounter(Arc<AtomicUsize>);

    impl Drop for InnerWithCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn handle_consume_returns_inner_first_call_only() {
        let mut h = OxiHandle::new(42u32);
        assert_eq!(h.consume(), Some(42));
        assert_eq!(h.consume(), None);
        assert!(h.is_consumed());
    }

    #[test]
    fn handle_drop_after_consume_is_idempotent() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut h = OxiHandle::new(InnerWithCounter(counter.clone()));
        let consumed = h.consume();
        assert!(consumed.is_some(), "first consume returns Some");
        drop(consumed); // Option<InnerWithCounter>::drop fires InnerWithCounter::drop, counter += 1
        drop(h); // should NOT increment counter (handle's inner is already None)
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "consumed inner dropped exactly once"
        );
    }
}
