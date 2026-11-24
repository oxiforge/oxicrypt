//! The operating-system random generator, per target.

/// Why [`os_random`] could not fill its output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsRandomError {
    /// The generator could not be used: the platform is not one the crate
    /// reaches, the call failed, or it returned nothing.
    Unavailable,
}

/// Fills `out` with bytes from the operating system's random generator.
///
/// Per target:
///
/// - **Linux:** the `getrandom` system call, made through
///   `syscall(SYS_getrandom, buf, len, 0)` with the per-architecture
///   number (318 on x86_64, 278 on aarch64; any other Linux architecture
///   returns [`OsRandomError::Unavailable`]). The raw system call is used
///   because the libc wrapper appears only in glibc 2.25, above the glibc
///   floor this crate supports (2.17). The system call needs Linux 3.17.
/// - **Android:** the same system call, because the libc wrapper appears
///   only at API level 28.
/// - **macOS:** `getentropy`, in pieces of at most 256 bytes.
/// - **Windows:** `ProcessPrng` from `bcryptprimitives.dll`, present
///   since Windows 10.
/// - **Any other target:** [`OsRandomError::Unavailable`].
///
/// A short return continues with the rest of the buffer, and an
/// interrupted call (`EINTR`) is retried. With flags `0`, `getrandom`
/// blocks until the kernel's pool has been initialised, which happens
/// once, early in boot.
///
/// An empty `out` succeeds without calling the operating system.
///
/// # Errors
///
/// [`OsRandomError::Unavailable`] when the target has no generator this
/// crate reaches, the call reports any error other than `EINTR`
/// (including `ENOSYS`), or it returns zero bytes. On failure every byte
/// of `out` is zeroized, so bytes written before the failure never reach
/// the caller.
pub fn os_random(out: &mut [u8]) -> Result<(), OsRandomError> {
    let result = fill(out);
    if result.is_err() {
        oxicrypt_zeroize::zeroize(out);
    }
    result
}

/// The outcome of one call to the platform generator.
enum Step {
    /// The call wrote this many bytes to the front of the buffer.
    Wrote(usize),
    /// The call was interrupted before writing anything.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        test,
        feature = "fault-injection"
    ))]
    Interrupted,
    /// The call failed.
    Failed,
}

/// `EINTR` on every target that reports errors through `errno` here.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    test,
    feature = "fault-injection"
))]
const EINTR: i32 = 4;

fn fill(out: &mut [u8]) -> Result<(), OsRandomError> {
    let mut filled: usize = 0;
    loop {
        let Some(rest) = out.get_mut(filled..) else {
            return Err(OsRandomError::Unavailable);
        };
        if rest.is_empty() {
            return Ok(());
        }
        match step(rest) {
            Step::Wrote(0) | Step::Failed => return Err(OsRandomError::Unavailable),
            Step::Wrote(written) => filled = filled.saturating_add(written.min(rest.len())),
            #[cfg(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                test,
                feature = "fault-injection"
            ))]
            Step::Interrupted => {}
        }
    }
}

fn step(buf: &mut [u8]) -> Step {
    #[cfg(any(test, feature = "fault-injection"))]
    if let Some(simulated) = crate::testing::take_os_random_result() {
        return match simulated {
            Err(OsRandomError::Unavailable) => Step::Failed,
            Ok(usize::MAX) => after_failed_call(),
            Ok(written) => Step::Wrote(written),
        };
    }
    platform_step(buf)
}

/// Classifies a call that returned -1 by the `errno` it left.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    test,
    feature = "fault-injection"
))]
fn after_failed_call() -> Step {
    if errno() == EINTR {
        Step::Interrupted
    } else {
        Step::Failed
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    test,
    feature = "fault-injection"
))]
fn errno() -> i32 {
    #[cfg(any(test, feature = "fault-injection"))]
    if let Some(code) = crate::testing::errno_override() {
        return code;
    }
    platform_errno()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    unsafe extern "C" {
        /// Makes the system call `number`. `getrandom` is reached through
        /// it because its libc wrapper is newer than the supported floors.
        pub(super) fn syscall(number: core::ffi::c_long, ...) -> core::ffi::c_long;

        /// The address of the calling thread's `errno` (glibc).
        #[cfg(target_os = "linux")]
        pub(super) fn __errno_location() -> *mut core::ffi::c_int;

        /// The address of the calling thread's `errno` (Bionic).
        #[cfg(target_os = "android")]
        pub(super) fn __errno() -> *mut core::ffi::c_int;
    }
}

/// The `getrandom` system call number.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "x86_64"
))]
const SYS_GETRANDOM: core::ffi::c_long = 318;

/// The `getrandom` system call number.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
const SYS_GETRANDOM: core::ffi::c_long = 278;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn platform_step(buf: &mut [u8]) -> Step {
    // SAFETY: `getrandom(buf, len, 0)` writes at most `len` bytes to
    // `buf`, which is a live, exclusively borrowed buffer of exactly
    // `len` bytes. The flags argument is 0.
    let ret = unsafe { sys::syscall(SYS_GETRANDOM, buf.as_mut_ptr(), buf.len(), 0_u32) };
    if ret < 0 {
        return after_failed_call();
    }
    usize::try_from(ret).map_or(Step::Failed, Step::Wrote)
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn platform_step(_buf: &mut [u8]) -> Step {
    Step::Failed
}

#[cfg(target_os = "linux")]
fn platform_errno() -> i32 {
    // SAFETY: `__errno_location` returns a valid, aligned pointer to the
    // calling thread's `errno`, live for the thread's lifetime.
    unsafe { *sys::__errno_location() }
}

#[cfg(target_os = "android")]
fn platform_errno() -> i32 {
    // SAFETY: `__errno` returns a valid, aligned pointer to the calling
    // thread's `errno`, live for the thread's lifetime.
    unsafe { *sys::__errno() }
}

#[cfg(target_os = "macos")]
mod sys {
    unsafe extern "C" {
        /// Fills `buf` with `len` random bytes, `len` at most 256. Zero on
        /// success, -1 with `errno` set.
        pub(super) fn getentropy(buf: *mut core::ffi::c_void, len: usize) -> core::ffi::c_int;

        /// The address of the calling thread's `errno`.
        pub(super) fn __error() -> *mut core::ffi::c_int;
    }
}

/// The largest request `getentropy` accepts.
#[cfg(target_os = "macos")]
const GETENTROPY_MAX: usize = 256;

#[cfg(target_os = "macos")]
fn platform_step(buf: &mut [u8]) -> Step {
    let len = buf.len().min(GETENTROPY_MAX);
    // SAFETY: `getentropy` writes exactly `len` bytes to `buf`, and `len`
    // is at most the length of the live, exclusively borrowed buffer.
    let ret = unsafe { sys::getentropy(buf.as_mut_ptr().cast::<core::ffi::c_void>(), len) };
    if ret == 0 {
        Step::Wrote(len)
    } else {
        after_failed_call()
    }
}

#[cfg(target_os = "macos")]
fn platform_errno() -> i32 {
    // SAFETY: `__error` returns a valid, aligned pointer to the calling
    // thread's `errno`, live for the thread's lifetime.
    unsafe { *sys::__error() }
}

#[cfg(windows)]
mod sys {
    // `bcryptprimitives.dll` ships no import library, so the symbol is
    // bound with `raw-dylib`, as the Rust standard library binds it.
    #[link(name = "bcryptprimitives", kind = "raw-dylib")]
    unsafe extern "system" {
        /// Fills `data` with `len` random bytes. Documented always to
        /// return non-zero.
        pub(super) fn ProcessPrng(data: *mut u8, len: usize) -> i32;
    }
}

#[cfg(windows)]
fn platform_step(buf: &mut [u8]) -> Step {
    // SAFETY: `ProcessPrng` writes exactly `len` bytes to `data`, which is
    // a live, exclusively borrowed buffer of exactly `len` bytes.
    let ret = unsafe { sys::ProcessPrng(buf.as_mut_ptr(), buf.len()) };
    if ret == 0 {
        Step::Failed
    } else {
        Step::Wrote(buf.len())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn platform_step(_buf: &mut [u8]) -> Step {
    Step::Failed
}

#[cfg(all(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    any(test, feature = "fault-injection")
))]
fn platform_errno() -> i32 {
    0
}
