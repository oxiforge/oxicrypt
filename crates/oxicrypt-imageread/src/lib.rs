//! Kernel-mediated access to the module's own loaded image.
//!
//! # Why this crate exists at all
//!
//! `oxicrypt-integrity` keeps `#![forbid(unsafe_code)]`, because the
//! failure mode of a raw pointer read, in the crate whose whole job is
//! integrity, is the one failure mode worth spending effort to avoid.
//! Everything the integrity test needs from the operating system that is
//! not an ordinary file read needs an `extern` declaration, so those
//! declarations live here, in a crate that does nothing else, rather than
//! eroding the guarantee in the crate that performs the test.
//!
//! This is one of the in-boundary crates in the oxicrypt workspace that
//! use `unsafe`.
//! The workspace's `AGENTS.md` names the in-boundary crates that use
//! `unsafe`, and `tools/doc-guard` checks that list against the crates.
//! Every in-boundary crate outside that list is
//! `#![forbid(unsafe_code)]`. The module's Security Policy, withheld
//! from this repository (see `docs/security-policy/README.md`), holds
//! the authoritative accounting.
//!
//! This crate provides seven interfaces:
//!
//! | Interface | Linux, Android | Darwin | Windows |
//! |---|---|---|---|
//! | [`read_self`] | `process_vm_readv(getpid(), …)` | `mach_vm_read_overwrite` | `ReadProcessMemory` |
//! | [`image_path`] | `dladdr` (used where `/proc/self/maps` cannot be read) | `dladdr` | `GetModuleHandleExW` + `GetModuleFileNameW` |
//! | [`page_size`] | `getauxval(AT_PAGESZ)` | not provided | not provided |
//! | [`resolve_symbol`] | not provided | `dlopen(RTLD_NOLOAD)` + `dlsym` | `GetModuleHandleExW` + `GetProcAddress` |
//! | [`loaded_image`] | not provided | `_dyld_image_count` + `_dyld_get_image_name` + `_dyld_get_image_header` | not provided |
//! | [`range_in_image`] | not provided | not provided | `VirtualQuery` |
//! | [`current_thread_id`] | `gettid` | `pthread_threadid_np` | `GetCurrentThreadId` |
//!
//! [`available`] reports whether the target has a [`read_self`] mechanism
//! at all.
//!
//! Every other target compiles each interface to a stub returning
//! [`ReadError::NoMechanism`].
//!
//! # Why a system call rather than a pointer read
//!
//! The memory reads are *kernel-mediated copies*, and that is the point
//! of choosing them. The addresses this crate is asked to read come from a
//! table inside the artifact; a corrupt or hostile table can name an
//! address that is not mapped. Dereferencing it would fault and take the
//! process down, a denial of service triggered by exactly the malformed
//! input the integrity test exists to detect. Each mechanism below returns
//! a status instead, so an unreadable address becomes an error return and
//! the module enters its error state, which is the required outcome.
//!
//! The `unsafe` here is confined to *calling* documented system
//! interfaces with buffers this crate owns. It performs no pointer
//! arithmetic on the addresses it is given, parses no executable format,
//! and never dereferences them.

use std::path::PathBuf;

/// Why a request to the operating system did not complete.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadError {
    /// This target has no implemented mechanism for the request.
    NoMechanism,
    /// The operating system refused the request and reported this status.
    ///
    /// `errno` on Linux and Android, the `kern_return_t` or `errno` on
    /// Darwin, the value of `GetLastError()` on Windows. Carried rather
    /// than collapsed to a boolean because "the address is not mapped" and
    /// "the process lacks the right" are different findings for whoever is
    /// holding a module that will not start.
    Os(i64),
    /// The mechanism succeeded but returned fewer bytes than asked for.
    ///
    /// Distinguished from [`ReadError::Os`] because a short read with a
    /// success status means the request straddled the end of a mapping,
    /// which is a statement about the table that named the address rather
    /// than about permissions.
    Short {
        /// Bytes requested.
        wanted: usize,
        /// Bytes the mechanism actually supplied.
        got: usize,
    },
    /// A library or symbol name could not be passed to the operating
    /// system: it holds an interior NUL, or is not valid for the platform's
    /// string encoding.
    InvalidName,
    /// The loader names no image file for the address: it lies in no
    /// loaded object, or the object's recorded name is empty.
    NoImage,
}

impl core::fmt::Display for ReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMechanism => f.write_str("no mechanism for this request on this target"),
            Self::Os(status) => write!(
                f,
                "the operating system refused the request: status {status}"
            ),
            Self::Short { wanted, got } => {
                write!(f, "short self-image read: wanted {wanted} bytes, got {got}")
            }
            Self::InvalidName => {
                f.write_str("a library or symbol name cannot be passed to the system")
            }
            Self::NoImage => f.write_str("the loader names no image file for the address"),
        }
    }
}

impl std::error::Error for ReadError {}

/// One import a loader binds: the symbol, by name or by ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbol<'a> {
    /// An export named by its symbol name, without any platform prefix.
    Name(&'a str),
    /// A PE export named by its ordinal.
    Ordinal(u16),
}

/// Whether this target has a [`read_self`] mechanism at all.
///
/// Exposed so a caller can tell "the test was not performed because this
/// platform has no mechanism" from "the test was performed and failed",
/// without provoking a read to find out.
#[must_use]
pub const fn available() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        windows
    ))
}

/// Copies `out.len()` bytes beginning at `addr` in this process's own
/// loaded image into `out`.
///
/// On Linux and Android this is `process_vm_readv` on the calling
/// process, the second memory route after `/proc/self/mem`: it is governed
/// by the same ptrace access check as a read of another process, which a
/// process always passes against itself, so it still works where a
/// non-dumpable process finds `/proc/self/mem` owned by root.
///
/// # Errors
///
/// Returns [`ReadError::NoMechanism`] on a target with no implementation,
/// [`ReadError::Os`] when the operating system refuses, and
/// [`ReadError::Short`] when fewer bytes arrive than were asked for.
///
/// An empty `out` is a successful no-op: the mechanisms below are not
/// specified for a zero-length request, and asking one for zero bytes
/// would make the outcome depend on a platform detail rather than on the
/// module's state.
pub fn read_self(addr: usize, out: &mut [u8]) -> Result<(), ReadError> {
    if out.is_empty() {
        return Ok(());
    }
    imp::read_self(addr, out)
}

/// The path of the image file the loader mapped the code at `addr` from.
///
/// On Linux and Android the integrity crate reads the same answer from the
/// `/proc/self/maps` line containing `addr`, and asks this function only
/// when `/proc` cannot be read. For the main executable glibc reports the
/// path the program was started with, which may be relative.
///
/// # Errors
///
/// [`ReadError::NoMechanism`] on a target with no implementation. On
/// Linux, Android and Darwin, [`ReadError::NoImage`] when the loader names
/// no image file for `addr`. On Windows, [`ReadError::Os`] when the
/// operating system refuses the request, including for an address in no
/// loaded module.
pub fn image_path(addr: usize) -> Result<PathBuf, ReadError> {
    imp::image_path(addr)
}

/// The kernel's page size, the granularity the loader maps a segment at.
///
/// Linux and Android only, from the auxiliary vector (`AT_PAGESZ`); every
/// other target returns [`ReadError::NoMechanism`].
///
/// # Errors
///
/// [`ReadError::NoMechanism`] off Linux and Android, or when the auxiliary
/// vector carries no page size.
pub fn page_size() -> Result<u64, ReadError> {
    imp::page_size()
}

/// Resolves `symbol` in the already-loaded `library` the way the loader
/// bound it, without loading anything.
///
/// Darwin: `dlopen(library, RTLD_NOLOAD | RTLD_LAZY | RTLD_FIRST)`, then
/// `dlsym`. Windows: `GetModuleHandleExW` with an unchanged reference
/// count, then `GetProcAddress`.
///
/// `Ok(None)` means resolution failed: the library is not loaded, or it
/// exports no such symbol. The caller decides what a failure means; for
/// a weak import it is not an error. An import by ordinal on Darwin, whose
/// loader binds by name only, is [`ReadError::NoMechanism`].
///
/// # Errors
///
/// [`ReadError::NoMechanism`] on a target with no implementation, and
/// [`ReadError::InvalidName`] when a name cannot be passed to the system.
pub fn resolve_symbol(library: &str, symbol: Symbol<'_>) -> Result<Option<usize>, ReadError> {
    imp::resolve_symbol(library, symbol)
}

/// The address of the Mach header of the loaded image whose path is
/// exactly `path`, or `None` when no loaded image has that path.
///
/// Darwin only: walks dyld's image list (`_dyld_image_count`,
/// `_dyld_get_image_name`, `_dyld_get_image_header`) and compares each
/// image's path with `path`. Every other target returns
/// [`ReadError::NoMechanism`].
///
/// The integrity test reads the export tries of the libraries an x86_64
/// import is resolved through from there, to confirm a resolver stub.
///
/// # Errors
///
/// [`ReadError::NoMechanism`] off Darwin.
pub fn loaded_image(path: &[u8]) -> Result<Option<usize>, ReadError> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Ok(imp::loaded_image(path))
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = path;
        Err(ReadError::NoMechanism)
    }
}

/// Whether `[addr, addr + len)` lies wholly in committed, readable memory
/// of the module whose image contains `image_addr`.
///
/// Windows only: walks `VirtualQuery`'s regions across the range and
/// requires each to be committed, readable (neither `PAGE_NOACCESS` nor
/// `PAGE_GUARD`) and part of the allocation the loader made for that
/// module. Every other target returns [`ReadError::NoMechanism`].
///
/// # Errors
///
/// [`ReadError::NoMechanism`] off Windows, and [`ReadError::Os`] when a
/// query fails.
pub fn range_in_image(image_addr: usize, addr: usize, len: usize) -> Result<bool, ReadError> {
    imp::range_in_image(image_addr, addr, len)
}

/// The operating system's identifier for the calling thread.
///
/// `gettid` on Linux and Android, `pthread_threadid_np` on Darwin,
/// `GetCurrentThreadId` on Windows. Unlike `std::thread::ThreadId`, the
/// value is the kernel's, so it is meaningful for a thread the Rust
/// runtime did not create, such as a C caller's.
///
/// # Errors
///
/// [`ReadError::NoMechanism`] on a target with no implementation, including
/// a Linux or Android architecture other than x86-64, AArch64, RISC-V 64,
/// LoongArch 64, x86 and Arm, whose `gettid` number this crate does not
/// carry (the memory route of [`available`] is unaffected), and
/// [`ReadError::Os`] when the operating system refuses.
pub fn current_thread_id() -> Result<u64, ReadError> {
    imp::current_thread_id()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    #![allow(unsafe_code)]

    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    use super::{ReadError, Symbol};

    /// `Dl_info`.
    #[repr(C)]
    struct DlInfo {
        fname: *const core::ffi::c_char,
        fbase: *mut core::ffi::c_void,
        sname: *const core::ffi::c_char,
        saddr: *mut core::ffi::c_void,
    }

    /// `struct iovec`.
    #[repr(C)]
    struct IoVec {
        base: *mut core::ffi::c_void,
        len: usize,
    }

    unsafe extern "C" {
        /// The calling process's id. Always succeeds.
        fn getpid() -> i32;

        /// Makes the system call `number`. The thread id is read through it
        /// because the `gettid` wrapper exists only from glibc 2.30.
        fn syscall(number: core::ffi::c_long, ...) -> core::ffi::c_long;

        /// Copies memory from the process `pid` into local buffers.
        /// Returns the number of bytes copied, or -1 with `errno` set.
        fn process_vm_readv(
            pid: i32,
            local_iov: *const IoVec,
            liovcnt: core::ffi::c_ulong,
            remote_iov: *const IoVec,
            riovcnt: core::ffi::c_ulong,
            flags: core::ffi::c_ulong,
        ) -> isize;

        /// Describes the image containing `addr`. Non-zero on success.
        fn dladdr(addr: *const core::ffi::c_void, info: *mut DlInfo) -> i32;

        /// Returns the auxiliary-vector value for `kind`, or zero.
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }

    pub(super) fn read_self(addr: usize, out: &mut [u8]) -> Result<(), ReadError> {
        let wanted = out.len();
        let local = IoVec {
            base: out.as_mut_ptr().cast::<core::ffi::c_void>(),
            len: wanted,
        };
        let remote = IoVec {
            base: addr as *mut core::ffi::c_void,
            len: wanted,
        };
        // SAFETY: `local` describes `out`, a live, uniquely borrowed slice
        // of exactly `wanted` bytes, so the kernel writes only into memory
        // this function owns. `remote` is never dereferenced here: the
        // kernel validates it against this process's mappings and returns
        // -1 with `EFAULT` rather than faulting when it is not mapped. Both
        // vectors are live locals for the duration of the call, and the
        // counts are one each. `getpid` takes no arguments.
        let copied =
            unsafe { process_vm_readv(getpid(), &raw const local, 1, &raw const remote, 1, 0) };
        if copied < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(ReadError::Os(i64::from(errno)));
        }
        let got = usize::try_from(copied).unwrap_or(0);
        if got != wanted {
            return Err(ReadError::Short { wanted, got });
        }
        Ok(())
    }

    pub(super) fn image_path(addr: usize) -> Result<PathBuf, ReadError> {
        let mut info = DlInfo {
            fname: core::ptr::null(),
            fbase: core::ptr::null_mut(),
            sname: core::ptr::null(),
            saddr: core::ptr::null_mut(),
        };
        // SAFETY: `dladdr` reads no memory at `addr`; it looks the address
        // up in the loader's list of loaded objects. `info` is a live,
        // writable local of the declared layout.
        let found = unsafe { dladdr(addr as *const core::ffi::c_void, &raw mut info) };
        if found == 0 || info.fname.is_null() {
            return Err(ReadError::NoImage);
        }
        // SAFETY: on success `dli_fname` points to a NUL-terminated path
        // owned by the loader, valid while the object stays loaded, which it
        // does for as long as this code runs from it.
        let name = unsafe { CStr::from_ptr(info.fname) };
        if name.is_empty() {
            return Err(ReadError::NoImage);
        }
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes())))
    }

    /// `AT_PAGESZ`: the kernel's page size, the same number on every
    /// Linux libc.
    const AT_PAGESZ: core::ffi::c_ulong = 6;

    #[allow(
        clippy::useless_conversion,
        reason = "`c_ulong` is `u64` here but `u32` on the 32-bit targets"
    )]
    pub(super) fn page_size() -> Result<u64, ReadError> {
        // SAFETY: `getauxval` reads the process's auxiliary vector, takes a
        // plain integer and returns one; it passes no pointer.
        match u64::from(unsafe { getauxval(AT_PAGESZ) }) {
            0 => Err(ReadError::NoMechanism),
            size => Ok(size),
        }
    }

    pub(super) fn resolve_symbol(
        _library: &str,
        _symbol: Symbol<'_>,
    ) -> Result<Option<usize>, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn range_in_image(
        _image_addr: usize,
        _addr: usize,
        _len: usize,
    ) -> Result<bool, ReadError> {
        Err(ReadError::NoMechanism)
    }

    /// The `gettid` system call's number.
    #[cfg(target_arch = "x86_64")]
    const SYS_GETTID: core::ffi::c_long = 186;
    /// The `gettid` system call's number.
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))]
    const SYS_GETTID: core::ffi::c_long = 178;
    /// The `gettid` system call's number.
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    const SYS_GETTID: core::ffi::c_long = 224;

    #[allow(
        clippy::useless_conversion,
        reason = "`c_long` is `i64` here but `i32` on the 32-bit targets"
    )]
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "x86",
        target_arch = "arm"
    ))]
    pub(super) fn current_thread_id() -> Result<u64, ReadError> {
        // SAFETY: `gettid` takes no arguments, cannot fail, and returns the
        // calling thread's id as a plain integer; the call passes no pointer.
        let tid = unsafe { syscall(SYS_GETTID) };
        u64::try_from(tid).map_err(|_| ReadError::Os(i64::from(tid)))
    }

    /// An architecture whose `gettid` number this crate does not carry: no
    /// mechanism, which the module turns into a failed initialisation rather
    /// than a guessed system call.
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "x86",
        target_arch = "arm"
    )))]
    pub(super) fn current_thread_id() -> Result<u64, ReadError> {
        Err(ReadError::NoMechanism)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    #![allow(unsafe_code)]

    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    use super::{ReadError, Symbol};

    /// `mach_port_t`.
    type MachPortT = u32;
    /// `kern_return_t`.
    type KernReturnT = i32;
    /// `mach_vm_address_t` and `mach_vm_size_t` are both 64-bit on every
    /// Darwin target this module builds for.
    type MachVmAddressT = u64;
    /// See [`MachVmAddressT`].
    type MachVmSizeT = u64;

    /// `KERN_SUCCESS`.
    const KERN_SUCCESS: KernReturnT = 0;
    /// `RTLD_LAZY`.
    const RTLD_LAZY: i32 = 0x1;
    /// `RTLD_NOLOAD`: return a handle only if the image is already loaded.
    const RTLD_NOLOAD: i32 = 0x10;
    /// `RTLD_FIRST`: `dlsym` on the handle searches that image alone.
    const RTLD_FIRST: i32 = 0x100;

    /// `Dl_info`.
    #[repr(C)]
    struct DlInfo {
        fname: *const core::ffi::c_char,
        fbase: *mut core::ffi::c_void,
        sname: *const core::ffi::c_char,
        saddr: *mut core::ffi::c_void,
    }

    unsafe extern "C" {
        /// `mach_task_self()` is a macro over this global in
        /// `<mach/mach_init.h>`, not a function. Declaring it as a
        /// function would link against a symbol that does not exist.
        static mach_task_self_: MachPortT;

        /// Copies memory from `target_task` into a buffer the caller
        /// already owns. Returns `KERN_SUCCESS` or a `kern_return_t`
        /// describing why not.
        fn mach_vm_read_overwrite(
            target_task: MachPortT,
            address: MachVmAddressT,
            size: MachVmSizeT,
            data: MachVmAddressT,
            out_size: *mut MachVmSizeT,
        ) -> KernReturnT;

        /// Describes the image containing `addr`. Non-zero on success.
        fn dladdr(addr: *const core::ffi::c_void, info: *mut DlInfo) -> i32;

        /// Opens an image by path; with `RTLD_NOLOAD`, only one already
        /// loaded. Null on failure.
        fn dlopen(path: *const core::ffi::c_char, mode: i32) -> *mut core::ffi::c_void;

        /// Looks up `symbol` in `handle`. Null when absent.
        fn dlsym(
            handle: *mut core::ffi::c_void,
            symbol: *const core::ffi::c_char,
        ) -> *mut core::ffi::c_void;

        /// Releases a reference taken by `dlopen`.
        fn dlclose(handle: *mut core::ffi::c_void) -> i32;

        /// Writes the kernel id of `thread` (null for the caller) to `out`.
        /// Zero on success.
        fn pthread_threadid_np(thread: *mut core::ffi::c_void, out: *mut u64) -> i32;

    }

    unsafe extern "C" {
        /// The number of images dyld has loaded.
        fn _dyld_image_count() -> u32;
        /// The path of image `index`, or null past the end.
        fn _dyld_get_image_name(index: u32) -> *const core::ffi::c_char;
        /// The Mach header of image `index`, or null past the end.
        fn _dyld_get_image_header(index: u32) -> *const core::ffi::c_void;
    }

    pub(super) fn loaded_image(path: &[u8]) -> Option<usize> {
        // SAFETY: takes no arguments and returns a count.
        let count = unsafe { _dyld_image_count() };
        for index in 0..count {
            // SAFETY: an index below the count dyld reported; a concurrent
            // unload makes either call return null, which is checked.
            let (name, header) =
                unsafe { (_dyld_get_image_name(index), _dyld_get_image_header(index)) };
            if name.is_null() || header.is_null() {
                continue;
            }
            // SAFETY: a non-null name is a NUL-terminated path owned by dyld.
            if unsafe { CStr::from_ptr(name) }.to_bytes() == path {
                return Some(header as usize);
            }
        }
        None
    }

    pub(super) fn read_self(addr: usize, out: &mut [u8]) -> Result<(), ReadError> {
        let wanted = out.len();
        let mut got: MachVmSizeT = 0;
        // SAFETY: `out` is a live, uniquely borrowed slice of `wanted`
        // bytes, so the destination the kernel is given is valid for
        // writes of exactly the size declared. `addr` is not
        // dereferenced here: it is passed to the kernel, which validates
        // it and reports `KERN_INVALID_ADDRESS` rather than faulting if it
        // is not mapped. `got` is a live local. `mach_task_self_` is the
        // current task port.
        let status = unsafe {
            mach_vm_read_overwrite(
                mach_task_self_,
                addr as MachVmAddressT,
                wanted as MachVmSizeT,
                out.as_mut_ptr() as MachVmAddressT,
                &raw mut got,
            )
        };
        if status != KERN_SUCCESS {
            return Err(ReadError::Os(i64::from(status)));
        }
        let got = usize::try_from(got).unwrap_or(0);
        if got != wanted {
            return Err(ReadError::Short { wanted, got });
        }
        Ok(())
    }

    pub(super) fn image_path(addr: usize) -> Result<PathBuf, ReadError> {
        let mut info = DlInfo {
            fname: core::ptr::null(),
            fbase: core::ptr::null_mut(),
            sname: core::ptr::null(),
            saddr: core::ptr::null_mut(),
        };
        // SAFETY: `dladdr` reads no memory at `addr`; it looks the address
        // up in the loader's image list. `info` is a live, writable local of
        // the declared layout.
        let found = unsafe { dladdr(addr as *const core::ffi::c_void, &raw mut info) };
        if found == 0 || info.fname.is_null() {
            return Err(ReadError::NoImage);
        }
        // SAFETY: on success `dli_fname` points to a NUL-terminated path
        // owned by the loader, valid while the image stays loaded, which it
        // does for as long as this code runs from it.
        let name = unsafe { CStr::from_ptr(info.fname) };
        if name.is_empty() {
            return Err(ReadError::NoImage);
        }
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes())))
    }

    pub(super) fn page_size() -> Result<u64, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn resolve_symbol(
        library: &str,
        symbol: Symbol<'_>,
    ) -> Result<Option<usize>, ReadError> {
        let Symbol::Name(name) = symbol else {
            // Darwin binds by name only. An ordinal record is not one this
            // loader could have produced, so there is no mechanism to
            // resolve it; reporting it as unresolved would let a weak
            // ordinal record pass on a zero word.
            return Err(ReadError::NoMechanism);
        };
        let path = CString::new(library).map_err(|_| ReadError::InvalidName)?;
        let name = CString::new(name).map_err(|_| ReadError::InvalidName)?;
        // SAFETY: `path` is a live NUL-terminated string. `RTLD_NOLOAD`
        // makes this a lookup of an image already loaded, so no initialiser
        // runs.
        let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOLOAD | RTLD_LAZY | RTLD_FIRST) };
        if handle.is_null() {
            return Ok(None);
        }
        // SAFETY: `handle` was just returned non-null by `dlopen`, and
        // `name` is a live NUL-terminated string.
        let sym = unsafe { dlsym(handle, name.as_ptr()) };
        // SAFETY: releases the reference the successful `dlopen` above
        // took; the image stays loaded because it was loaded before.
        unsafe { dlclose(handle) };
        if sym.is_null() {
            Ok(None)
        } else {
            Ok(Some(sym as usize))
        }
    }

    pub(super) fn range_in_image(
        _image_addr: usize,
        _addr: usize,
        _len: usize,
    ) -> Result<bool, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn current_thread_id() -> Result<u64, ReadError> {
        let mut tid: u64 = 0;
        // SAFETY: a null thread means the calling thread, and `tid` is a
        // live, writable local.
        let status = unsafe { pthread_threadid_np(core::ptr::null_mut(), &raw mut tid) };
        if status != 0 {
            return Err(ReadError::Os(i64::from(status)));
        }
        Ok(tid)
    }
}

#[cfg(windows)]
mod imp {
    #![allow(unsafe_code)]

    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    use super::{ReadError, Symbol};

    /// `HANDLE` and `HMODULE`.
    type Handle = *mut core::ffi::c_void;

    /// `GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT`.
    const UNCHANGED_REFCOUNT: u32 = 0x2;
    /// `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS`.
    const FROM_ADDRESS: u32 = 0x4;
    /// The longest path `GetModuleFileNameW` can return.
    const MAX_WIDE_PATH: usize = 32_768;

    unsafe extern "system" {
        /// A pseudo-handle to the current process. It needs no closing.
        fn GetCurrentProcess() -> Handle;

        /// Copies memory from a process, here this one. Zero on failure,
        /// with the reason in `GetLastError`.
        fn ReadProcessMemory(
            process: Handle,
            base: *const core::ffi::c_void,
            buffer: *mut core::ffi::c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;

        /// The calling thread's last error code.
        fn GetLastError() -> u32;

        /// A handle to a loaded module, by name or by an address inside it.
        fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut Handle) -> i32;

        /// The path of a loaded module. Returns the length written.
        fn GetModuleFileNameW(module: Handle, filename: *mut u16, size: u32) -> u32;

        /// An export of a loaded module, by name or by ordinal.
        fn GetProcAddress(module: Handle, name: *const u8) -> *mut core::ffi::c_void;

        /// The calling thread's id.
        fn GetCurrentThreadId() -> u32;

        /// Describes the region containing `address`. Returns the bytes
        /// written to `buffer`, zero on failure.
        fn VirtualQuery(
            address: *const core::ffi::c_void,
            buffer: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
    }

    /// `MEMORY_BASIC_INFORMATION` on 64-bit Windows.
    #[cfg(target_pointer_width = "64")]
    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut core::ffi::c_void,
        allocation_base: *mut core::ffi::c_void,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    /// `MEMORY_BASIC_INFORMATION` on 32-bit Windows, which has no
    /// `PartitionId`.
    #[cfg(target_pointer_width = "32")]
    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut core::ffi::c_void,
        allocation_base: *mut core::ffi::c_void,
        allocation_protect: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    /// `MEM_COMMIT`.
    const MEM_COMMIT: u32 = 0x1000;
    /// `PAGE_NOACCESS`.
    const PAGE_NOACCESS: u32 = 0x01;
    /// `PAGE_GUARD`.
    const PAGE_GUARD: u32 = 0x100;

    /// The region containing `addr`.
    fn query(addr: usize) -> Result<MemoryBasicInformation, ReadError> {
        // SAFETY: an all-zero `MEMORY_BASIC_INFORMATION` is a valid value of
        // a plain C struct of pointers and integers.
        let mut info: MemoryBasicInformation = unsafe { core::mem::zeroed() };
        // SAFETY: `VirtualQuery` reads no memory at `addr`; it looks the
        // address up in the process's address-space map. `info` is a live,
        // writable local of the declared size.
        let written = unsafe {
            VirtualQuery(
                addr as *const core::ffi::c_void,
                &raw mut info,
                core::mem::size_of::<MemoryBasicInformation>(),
            )
        };
        if written == 0 {
            return Err(last_error());
        }
        Ok(info)
    }

    pub(super) fn range_in_image(
        image_addr: usize,
        addr: usize,
        len: usize,
    ) -> Result<bool, ReadError> {
        let image = query(image_addr)?.allocation_base as usize;
        let Some(end) = addr.checked_add(len) else {
            return Ok(false);
        };
        let mut at = addr;
        while at < end {
            let info = query(at)?;
            let readable = info.state == MEM_COMMIT
                && info.protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
                && info.allocation_base as usize == image;
            if !readable {
                return Ok(false);
            }
            let next = (info.base_address as usize).saturating_add(info.region_size);
            if next <= at {
                return Ok(false);
            }
            at = next;
        }
        Ok(true)
    }

    /// The last error as a [`ReadError`].
    fn last_error() -> ReadError {
        // SAFETY: reads a thread-local error code; it takes no arguments and
        // returns a plain integer.
        ReadError::Os(i64::from(unsafe { GetLastError() }))
    }

    pub(super) fn read_self(addr: usize, out: &mut [u8]) -> Result<(), ReadError> {
        let wanted = out.len();
        let mut got: usize = 0;
        // SAFETY: `out` is a live, uniquely borrowed slice of `wanted`
        // bytes, so the destination buffer is valid for writes of the
        // declared size. `addr` is passed to the kernel as an opaque
        // address and never dereferenced here; an unmapped address makes
        // `ReadProcessMemory` return zero rather than fault.
        // `GetCurrentProcess` yields a pseudo-handle that requires no
        // release, and `got` points to a live local.
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                addr as *const core::ffi::c_void,
                out.as_mut_ptr().cast::<core::ffi::c_void>(),
                wanted,
                &raw mut got,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        if got != wanted {
            return Err(ReadError::Short { wanted, got });
        }
        Ok(())
    }

    pub(super) fn image_path(addr: usize) -> Result<PathBuf, ReadError> {
        let mut module: Handle = core::ptr::null_mut();
        // SAFETY: with `FROM_ADDRESS` the name argument is an address the
        // loader looks up, never a string it reads; `UNCHANGED_REFCOUNT`
        // takes no reference that would need releasing. `module` is a live
        // local.
        let ok = unsafe {
            GetModuleHandleExW(
                FROM_ADDRESS | UNCHANGED_REFCOUNT,
                addr as *const u16,
                &raw mut module,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        let mut buf = vec![0u16; MAX_WIDE_PATH];
        let size = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is a live, writable buffer of `size` UTF-16 units,
        // and `module` was just returned by the loader.
        let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), size) };
        let len = usize::try_from(len).unwrap_or(0);
        if len == 0 || len >= buf.len() {
            return Err(last_error());
        }
        buf.truncate(len);
        Ok(PathBuf::from(OsString::from_wide(&buf)))
    }

    pub(super) fn page_size() -> Result<u64, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn resolve_symbol(
        library: &str,
        symbol: Symbol<'_>,
    ) -> Result<Option<usize>, ReadError> {
        let wide: Vec<u16> = std::ffi::OsStr::new(library)
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        if wide
            .iter()
            .take(wide.len().saturating_sub(1))
            .any(|&u| u == 0)
        {
            return Err(ReadError::InvalidName);
        }
        let mut module: Handle = core::ptr::null_mut();
        // SAFETY: `wide` is a live NUL-terminated UTF-16 string, the flag
        // takes no reference, and `module` is a live local.
        let ok = unsafe { GetModuleHandleExW(UNCHANGED_REFCOUNT, wide.as_ptr(), &raw mut module) };
        if ok == 0 {
            return Ok(None);
        }
        let proc = match symbol {
            Symbol::Name(name) => {
                let name = std::ffi::CString::new(name).map_err(|_| ReadError::InvalidName)?;
                // SAFETY: `module` is a loaded module and `name` a live
                // NUL-terminated string.
                unsafe { GetProcAddress(module, name.as_ptr().cast::<u8>()) }
            }
            Symbol::Ordinal(ordinal) => {
                // SAFETY: an ordinal is passed as a pointer-sized integer
                // below 0x10000, which `GetProcAddress` interprets as an
                // ordinal and never dereferences (`MAKEINTRESOURCEA`).
                unsafe { GetProcAddress(module, usize::from(ordinal) as *const u8) }
            }
        };
        if proc.is_null() {
            Ok(None)
        } else {
            Ok(Some(proc as usize))
        }
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "one signature across targets; other targets can fail"
    )]
    pub(super) fn current_thread_id() -> Result<u64, ReadError> {
        // SAFETY: takes no arguments and returns a plain integer.
        Ok(u64::from(unsafe { GetCurrentThreadId() }))
    }
}

/// Every target this module has not been ported to.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
mod imp {
    use std::path::PathBuf;

    use super::{ReadError, Symbol};

    pub(super) fn read_self(_addr: usize, _out: &mut [u8]) -> Result<(), ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn image_path(_addr: usize) -> Result<PathBuf, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn page_size() -> Result<u64, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn resolve_symbol(
        _library: &str,
        _symbol: Symbol<'_>,
    ) -> Result<Option<usize>, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn range_in_image(
        _image_addr: usize,
        _addr: usize,
        _len: usize,
    ) -> Result<bool, ReadError> {
        Err(ReadError::NoMechanism)
    }

    pub(super) fn current_thread_id() -> Result<u64, ReadError> {
        Err(ReadError::NoMechanism)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    use super::ReadError;
    use super::read_self;

    /// The memory route reads this process's own bytes back exactly.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn process_vm_readv_reads_this_process_back() {
        let source: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap() ^ 0x5a);
        let mut out = [0u8; 64];
        read_self(core::ptr::from_ref(&source) as usize, &mut out).unwrap();
        assert_eq!(out, source);
    }

    /// An unmapped address is a status, never a fault.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn an_unmapped_address_is_an_error_return() {
        let mut out = [0u8; 16];
        match read_self(8, &mut out) {
            Err(ReadError::Os(_)) => {}
            other => panic!("expected Os, got {other:?}"),
        }
    }

    /// `dladdr` names the file this test binary was loaded from, and an
    /// address in no loaded object names none.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    #[test]
    fn the_image_path_names_this_binary() {
        static IN_THIS_BINARY: u8 = 1;
        let here = super::image_path(core::ptr::from_ref(&IN_THIS_BINARY) as usize).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            std::fs::canonicalize(here).unwrap(),
            std::fs::canonicalize(exe).unwrap()
        );
        assert!(matches!(super::image_path(8), Err(ReadError::NoImage)));
    }

    /// The page size is a power of two of at least 4 KiB.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_page_size_is_a_page() {
        let size = super::page_size().unwrap();
        assert!(size >= 4096 && size.is_power_of_two(), "{size}");
    }

    /// An empty request succeeds without asking the system anything.
    #[test]
    fn an_empty_read_is_a_no_op() {
        assert!(read_self(0, &mut []).is_ok());
    }

    /// Off Darwin the image lookup has no mechanism.
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn the_image_lookup_is_darwin_only() {
        assert!(matches!(
            super::loaded_image(b"/usr/lib/libSystem.B.dylib"),
            Err(super::ReadError::NoMechanism)
        ));
    }

    /// libSystem is loaded, at an address holding a 64-bit Mach header; a
    /// path nothing loaded has is not.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn a_loaded_library_is_found_by_its_path() {
        use super::{loaded_image, read_self};
        let Some(base) = loaded_image(b"/usr/lib/libSystem.B.dylib").unwrap() else {
            panic!("libSystem is not loaded");
        };
        let mut magic = [0u8; 4];
        read_self(base, &mut magic).unwrap();
        assert_eq!(u32::from_le_bytes(magic), 0xfeed_facf);
        assert_eq!(loaded_image(b"/usr/lib/libnothing.dylib").unwrap(), None);
    }

    /// The kernel's thread id is available and differs between threads.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn thread_ids_differ_between_threads() {
        let here = super::current_thread_id().unwrap();
        let there = std::thread::spawn(|| super::current_thread_id().unwrap())
            .join()
            .unwrap();
        assert_ne!(here, there);
    }
}
