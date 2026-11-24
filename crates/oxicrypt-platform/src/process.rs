//! The calling process's id.

/// Returns the calling process's id.
///
/// `getpid` on Unix-like targets, `GetCurrentProcessId` on Windows, and
/// `0` on any other target. The call cannot fail.
#[must_use]
pub fn process_id() -> u64 {
    #[cfg(any(test, feature = "fault-injection"))]
    if let Some(id) = crate::testing::process_id_override() {
        return id;
    }
    platform_process_id()
}

#[cfg(unix)]
fn platform_process_id() -> u64 {
    unsafe extern "C" {
        /// The calling process's id. Always succeeds.
        fn getpid() -> i32;
    }
    // SAFETY: `getpid` takes no arguments, touches no memory the caller
    // owns and always succeeds.
    let id = unsafe { getpid() };
    u64::from(id.unsigned_abs())
}

#[cfg(windows)]
fn platform_process_id() -> u64 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        /// The calling process's id. Always succeeds.
        fn GetCurrentProcessId() -> u32;
    }
    // SAFETY: `GetCurrentProcessId` takes no arguments, touches no
    // memory the caller owns and always succeeds.
    u64::from(unsafe { GetCurrentProcessId() })
}

#[cfg(not(any(unix, windows)))]
fn platform_process_id() -> u64 {
    0
}
