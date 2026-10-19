//! Each handle is freed when dropped, and only once.
//!
//! The library allocates a handle with the process's C allocator, which this
//! test reads through glibc's `mallinfo2` (glibc 2.33 and later). Handles
//! that are kept alive must show up in the count (the positive control);
//! handles that are dropped must not remain in it. A handle freed twice
//! aborts in glibc's allocator, which fails the test binary.
//!
//! `mallinfo2` is looked up at run time, so on an older glibc, and on every
//! other target, the test prints why it did not run instead of failing to
//! link.

#![cfg(oxicrypt_lib)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_wrap)]
#![allow(clippy::print_stderr)]

mod common;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod census {
    use core::ffi::{c_char, c_void};

    /// `struct mallinfo2` from `<malloc.h>`.
    #[repr(C)]
    #[allow(clippy::struct_field_names, dead_code)]
    pub(crate) struct Mallinfo2 {
        arena: usize,
        ordblks: usize,
        smblks: usize,
        hblks: usize,
        pub(crate) hblkhd: usize,
        usmblks: usize,
        fsmblks: usize,
        pub(crate) uordblks: usize,
        fordblks: usize,
        keepcost: usize,
    }

    pub(crate) type Mallinfo2Fn = unsafe extern "C" fn() -> Mallinfo2;

    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }

    unsafe extern "C" {
        fn gnu_get_libc_version() -> *const c_char;
    }

    /// Whether this glibc is 2.33 or later, and so must have `mallinfo2`.
    pub(crate) fn has_mallinfo2() -> bool {
        // SAFETY: glibc returns a static NUL-terminated version string.
        let version = unsafe { core::ffi::CStr::from_ptr(gnu_get_libc_version()) };
        let mut parts = version.to_str().unwrap_or("0.0").split('.');
        let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        (major, minor) >= (2, 33)
    }

    /// The process's definition of `name`, if it has one. `RTLD_DEFAULT` is
    /// the null handle on glibc.
    pub(crate) fn lookup(name: &core::ffi::CStr) -> Option<Mallinfo2Fn> {
        // SAFETY: `dlsym` with `RTLD_DEFAULT` and a NUL-terminated name.
        let ptr = unsafe { dlsym(core::ptr::null_mut(), name.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            // SAFETY: the symbol is glibc's `mallinfo2`, whose type this is.
            Some(unsafe { core::mem::transmute::<*mut c_void, Mallinfo2Fn>(ptr) })
        }
    }

    /// Bytes the C allocator has handed out and not taken back, in every
    /// arena.
    pub(crate) fn in_use(mallinfo2: Mallinfo2Fn) -> isize {
        // SAFETY: glibc's `mallinfo2` takes no arguments and returns the
        // structure by value.
        let info = unsafe { mallinfo2() };
        (info.uordblks + info.hblkhd) as isize
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn the_census_lookup_reports_a_missing_function() {
    assert!(census::lookup(c"oxicrypt_no_such_function").is_none());
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[test]
fn handles_are_freed_when_dropped() {
    eprintln!("skipped: the handle census needs glibc's mallinfo2, which this target lacks");
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const N: usize = 2_000;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn handles_are_freed_when_dropped() {
    let Some(mallinfo2) = census::lookup(c"mallinfo2") else {
        assert!(
            !census::has_mallinfo2(),
            "glibc 2.33 or later, but mallinfo2 was not found"
        );
        eprintln!("skipped: this glibc has no mallinfo2 (glibc 2.33 and later have it)");
        return;
    };
    let in_use = || census::in_use(mallinfo2);
    let m = common::init(oxicrypt::Profile::Cnsa2).unwrap();
    // Warm up anything allocated once per process.
    drop(m.aes256_key(&[1; 32]).unwrap());
    drop(m.hmac_drbg_sha256().unwrap());

    let before = in_use();
    let kept: Vec<_> = (0..N)
        .map(|_| {
            (
                m.aes256_key(&[2; 32]).unwrap(),
                m.hmac_drbg_sha256().unwrap(),
            )
        })
        .collect();
    let alive = in_use() - before;
    // Positive control: N live pairs hold at least the AES key schedules,
    // 240 bytes each.
    assert!(
        alive >= (N * 240) as isize,
        "the census does not see the library's handles: {alive} bytes for {N} pairs"
    );

    drop(kept);
    for _ in 0..N {
        drop(m.aes256_key(&[3; 32]).unwrap());
        drop(m.hmac_drbg_sha256().unwrap());
    }
    let leaked = in_use() - before;
    assert!(
        leaked < (N * 16) as isize,
        "{leaked} bytes still allocated after dropping every handle (alive: {alive})"
    );
}
