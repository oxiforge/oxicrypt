//! Kernel-mediated reads of the module's own loaded image.
//!
//! # Why this crate exists at all
//!
//! [`oxicrypt-integrity`] keeps `#![forbid(unsafe_code)]`, because the
//! failure mode of a raw pointer read, in the crate whose whole job is
//! integrity, is the one failure mode worth spending effort to avoid.
//! On Linux and Android it can hold that line completely: the loaded
//! image is readable through `/proc/self/mem` or through the backing
//! file, so every acquisition is an ordinary positioned file read and a
//! wrong offset produces a short read rather than undefined behaviour.
//!
//! Darwin and Windows offer no file-shaped route to a process's own
//! memory. Reading the image there needs a system call, and a system
//! call needs an `extern` declaration — so the declarations live here,
//! in a crate that does nothing else, rather than eroding the guarantee
//! in the crate that performs the test.
//!
//! # Why a system call rather than a pointer read
//!
//! Both mechanisms below are *kernel-mediated copies*, and that is the
//! point of choosing them. The addresses this crate is asked to read
//! come from a range table inside the artifact; a corrupt or hostile
//! table can name an address that is not mapped. Dereferencing it would
//! fault and take the process down — a denial of service triggered by
//! exactly the malformed input the integrity test exists to detect.
//! `mach_vm_read_overwrite` and `ReadProcessMemory` return a status
//! instead, so an unreadable range becomes an error return and the
//! module enters its error state, which is the required outcome.
//!
//! The `unsafe` here is therefore confined to *calling* two documented
//! system interfaces with a buffer this crate owns. It performs no
//! pointer arithmetic on the addresses it is given, parses no executable
//! format, and never dereferences them.

/// Why a self-image read did not complete.
#[derive(Debug)]
pub enum ReadError {
    /// This target has no implemented mechanism.
    NoMechanism,
    /// The operating system refused the read and reported this status.
    ///
    /// `mach_vm_read_overwrite`'s `kern_return_t` on Darwin, the value
    /// of `GetLastError()` on Windows. Carried rather than collapsed to
    /// a boolean because "the address is not mapped" and "the process
    /// lacks the right" are different findings for whoever is holding
    /// a module that will not start.
    Os(i64),
    /// The mechanism succeeded but returned fewer bytes than asked for.
    ///
    /// Distinguished from [`ReadError::Os`] because a short read with a
    /// success status means the request straddled the end of a mapping,
    /// which is a statement about the range table rather than about
    /// permissions.
    Short {
        /// Bytes requested.
        wanted: usize,
        /// Bytes the mechanism actually supplied.
        got: usize,
    },
}

impl core::fmt::Display for ReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMechanism => f.write_str("no self-image read mechanism on this target"),
            Self::Os(status) => write!(f, "the operating system refused the read: status {status}"),
            Self::Short { wanted, got } => {
                write!(f, "short self-image read: wanted {wanted} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for ReadError {}

/// Whether this target has a mechanism at all.
///
/// Exposed so a caller can tell "the test was not performed because this
/// platform has no mechanism" from "the test was performed and failed",
/// without provoking a read to find out.
#[must_use]
pub const fn available() -> bool {
    cfg!(any(target_os = "macos", target_os = "ios", windows))
}

/// Copies `out.len()` bytes beginning at `addr` in this process's own
/// loaded image into `out`.
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

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    #![allow(unsafe_code)]

    use super::ReadError;

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

    unsafe extern "C" {
        /// `mach_task_self()` is a macro over this global in
        /// `<mach/mach_init.h>`, not a function — declaring it as a
        /// function would link against a symbol that does not exist.
        static mach_task_self_: MachPortT;

        /// Copies memory from `target_task` into a buffer the caller
        /// already owns, rather than allocating a new one as
        /// `mach_vm_read` does. Returns `KERN_SUCCESS` or a
        /// `kern_return_t` describing why not.
        fn mach_vm_read_overwrite(
            target_task: MachPortT,
            address: MachVmAddressT,
            size: MachVmSizeT,
            data: MachVmAddressT,
            out_size: *mut MachVmSizeT,
        ) -> KernReturnT;
    }

    pub(super) fn read_self(addr: usize, out: &mut [u8]) -> Result<(), ReadError> {
        let wanted = out.len();
        let mut got: MachVmSizeT = 0;
        // SAFETY: `out` is a live, uniquely borrowed slice of `wanted`
        // bytes, so the destination the kernel is given is valid for
        // writes of exactly the size declared. `addr` is not
        // dereferenced here — it is passed to the kernel, which
        // validates it and reports `KERN_INVALID_ADDRESS` rather than
        // faulting if it is not mapped. `out_size` points to a live
        // local. `mach_task_self_` is the current task port.
        let status = unsafe {
            mach_vm_read_overwrite(
                mach_task_self_,
                addr as MachVmAddressT,
                wanted as MachVmSizeT,
                out.as_mut_ptr() as MachVmAddressT,
                &mut got,
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
}

#[cfg(windows)]
mod imp {
    #![allow(unsafe_code)]

    use super::ReadError;

    /// `HANDLE`.
    type Handle = *mut core::ffi::c_void;

    unsafe extern "system" {
        /// A pseudo-handle to the current process. It needs no closing.
        fn GetCurrentProcess() -> Handle;

        /// Copies memory from another process — or, as here, from this
        /// one. Returns zero on failure, with the reason in
        /// `GetLastError`.
        fn ReadProcessMemory(
            process: Handle,
            base: *const core::ffi::c_void,
            buffer: *mut core::ffi::c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;

        /// The calling thread's last error code.
        fn GetLastError() -> u32;
    }

    pub(super) fn read_self(addr: usize, out: &mut [u8]) -> Result<(), ReadError> {
        let wanted = out.len();
        let mut got: usize = 0;
        // SAFETY: `out` is a live, uniquely borrowed slice of `wanted`
        // bytes, so the destination buffer is valid for writes of the
        // declared size. `addr` is passed to the kernel as an opaque
        // address and is never dereferenced here; an unmapped address
        // makes `ReadProcessMemory` return zero rather than fault.
        // `GetCurrentProcess` yields a pseudo-handle that requires no
        // release, and `got` points to a live local.
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                addr as *const core::ffi::c_void,
                out.as_mut_ptr().cast::<core::ffi::c_void>(),
                wanted,
                &mut got,
            )
        };
        if ok == 0 {
            // SAFETY: reads a thread-local error code set by the call
            // above; it takes no arguments and returns a plain integer.
            let code = unsafe { GetLastError() };
            return Err(ReadError::Os(i64::from(code)));
        }
        if got != wanted {
            return Err(ReadError::Short { wanted, got });
        }
        Ok(())
    }
}

/// Every target with a file-shaped route to its own image, plus every
/// target this module has not been ported to.
///
/// Linux and Android are deliberately here rather than given a
/// mechanism: they read through `/proc/self/mem` or the backing file,
/// which needs no `unsafe` at all, so compiling one for them would add
/// an exception the boundary does not need.
#[cfg(not(any(target_os = "macos", target_os = "ios", windows)))]
mod imp {
    use super::ReadError;

    pub(super) fn read_self(_addr: usize, _out: &mut [u8]) -> Result<(), ReadError> {
        Err(ReadError::NoMechanism)
    }
}
