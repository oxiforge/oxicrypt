//! A request over an output bound is refused before the crate allocates for
//! it. This binary's allocator records the largest block requested.

#![cfg(oxicrypt_lib)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use oxicrypt::{Error, HKDF_SHA384_MAX_OKM_LEN, Profile};

struct Largest;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call to `System` unchanged and only records sizes.
unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::SeqCst);
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::SeqCst);
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Largest = Largest;

#[test]
fn hkdf_expand_over_the_bound_allocates_nothing_for_it() {
    let m = common::init(Profile::Cnsa2).unwrap();
    let prk = m.hkdf_sha384_extract(None, b"ikm").unwrap();

    // Positive control: a request at the bound allocates its output.
    LARGEST.store(0, Ordering::SeqCst);
    let okm = m
        .hkdf_sha384_expand(&prk, b"", HKDF_SHA384_MAX_OKM_LEN)
        .unwrap();
    assert_eq!(okm.as_bytes().len(), HKDF_SHA384_MAX_OKM_LEN);
    assert!(LARGEST.load(Ordering::SeqCst) >= HKDF_SHA384_MAX_OKM_LEN);
    drop(okm);

    for len in [HKDF_SHA384_MAX_OKM_LEN + 1, 2 * HKDF_SHA384_MAX_OKM_LEN] {
        LARGEST.store(0, Ordering::SeqCst);
        assert_eq!(
            m.hkdf_sha384_expand(&prk, b"", len).unwrap_err(),
            Error::OutputTooLong
        );
        let largest = LARGEST.load(Ordering::SeqCst);
        assert!(
            largest < len,
            "allocated {largest} bytes for a refused {len}"
        );
    }
}
