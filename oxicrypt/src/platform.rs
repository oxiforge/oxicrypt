//! Which file the loader bound the library to, for a diagnostic, and the
//! library's ABI number, looked up at run time.
//!
//! The address looked up is the manifest string `lama_manifest` returns,
//! which lies in the library's own image. The address of an imported
//! function would not do: in a program that is not position-independent it
//! is the program's own PLT entry.

use std::path::PathBuf;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) fn library_path() -> Option<PathBuf> {
    use core::ffi::{CStr, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;

    /// `Dl_info` from `<dlfcn.h>`, with its field names.
    #[repr(C)]
    #[allow(clippy::struct_field_names)]
    struct DlInfo {
        dli_fname: *const c_char,
        dli_fbase: *mut c_void,
        dli_sname: *const c_char,
        dli_saddr: *mut c_void,
    }

    #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "dl"))]
    unsafe extern "C" {
        fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
    }

    let mut info = DlInfo {
        dli_fname: core::ptr::null(),
        dli_fbase: core::ptr::null_mut(),
        dli_sname: core::ptr::null(),
        dli_saddr: core::ptr::null_mut(),
    };
    // SAFETY: U1; no pointers in. U5, the result is a static string of the
    // library.
    let addr = unsafe { crate::sys::lama_manifest() }.cast::<c_void>();
    if addr.is_null() {
        return None;
    }
    // SAFETY: U10, `addr` lies in the library's image and `info` is a
    // zero-initialised local of the documented layout.
    if unsafe { dladdr(addr, &raw mut info) } == 0 || info.dli_fname.is_null() {
        return None;
    }
    // SAFETY: U10, on success `dli_fname` is a NUL-terminated path owned by
    // the loader; it is copied at once.
    let name = unsafe { CStr::from_ptr(info.dli_fname) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes())))
}

#[cfg(windows)]
pub(crate) fn library_path() -> Option<PathBuf> {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStringExt;

    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x4;
    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x2;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut *mut c_void) -> i32;
        fn GetModuleFileNameW(module: *mut c_void, name: *mut u16, size: u32) -> u32;
    }

    let mut module: *mut c_void = core::ptr::null_mut();
    // SAFETY: U1; no pointers in. U5, the result is a static string of the
    // library.
    let addr = unsafe { crate::sys::lama_manifest() }.cast::<c_void>();
    if addr.is_null() {
        return None;
    }
    // SAFETY: U10, with FROM_ADDRESS the name argument is read as an address
    // inside the module, here the library's manifest string; `module` is a
    // local.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            addr.cast(),
            &raw mut module,
        )
    };
    if found == 0 {
        return None;
    }
    let mut buf = vec![0u16; 32 * 1024];
    let size = u32::try_from(buf.len()).ok()?;
    // SAFETY: U10, `buf` holds `size` writable UTF-16 units.
    let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), size) };
    let len = usize::try_from(len).ok()?;
    if len == 0 || len >= buf.len() {
        return None;
    }
    buf.truncate(len);
    Some(PathBuf::from(std::ffi::OsString::from_wide(&buf)))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
pub(crate) fn library_path() -> Option<PathBuf> {
    None
}

/// Calls the library's `oxi_abi_version`, found at run time rather than by a
/// link-time reference, so a library that predates the function still loads;
/// `None` when the library does not define it.
///
/// The symbol is taken only from the image that holds `lama_manifest()`'s
/// string, the library this program is bound to: the image is opened by its
/// own path without loading anything (`RTLD_NOLOAD`), the symbol is looked
/// up in that handle, and a result `dladdr` places in any other image is
/// ignored. The answer is thereby confined to the image the program's own
/// `lama_manifest` reference bound to: an object loaded later, such as a
/// plugin, or one that defines `oxi_abi_version` alone, neither overrides the
/// library's number nor stands in for a library that has none.
///
/// It does not resist a preloaded object that defines `lama_manifest` as
/// well: such an object becomes the image the program binds to, for that
/// function and for every other `oxi_*` function it defines, at load, before
/// any code of the crate runs. No check inside the crate can resist someone
/// who controls the program's launch, which the module's threat model
/// excludes, as it excludes an adversary who controls both the file and the
/// launch.
///
/// The tests exercise this on Linux only. The macOS path (`dladdr`, then
/// `dlopen` with `RTLD_NOLOAD`) has no test: the CI workflows have no macOS
/// job for this crate.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) fn abi_version() -> Option<i32> {
    use core::ffi::{c_char, c_int, c_void};

    /// `Dl_info` from `<dlfcn.h>`, with its field names.
    #[repr(C)]
    #[allow(clippy::struct_field_names)]
    struct DlInfo {
        dli_fname: *const c_char,
        dli_fbase: *mut c_void,
        dli_sname: *const c_char,
        dli_saddr: *mut c_void,
    }

    #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "dl"))]
    unsafe extern "C" {
        fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
    }

    const RTLD_NOW: c_int = 2;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const RTLD_NOLOAD: c_int = 0x10;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    const RTLD_NOLOAD: c_int = 4;

    /// The image holding `addr`: its path and load base.
    fn image_of(addr: *const c_void) -> Option<(*const c_char, *mut c_void)> {
        let mut info = DlInfo {
            dli_fname: core::ptr::null(),
            dli_fbase: core::ptr::null_mut(),
            dli_sname: core::ptr::null(),
            dli_saddr: core::ptr::null_mut(),
        };
        // SAFETY: U10, `info` is a zero-initialised local of the documented
        // layout; `dladdr` only reads `addr` as an address.
        let found = unsafe { dladdr(addr, &raw mut info) } != 0;
        (found && !info.dli_fname.is_null()).then_some((info.dli_fname, info.dli_fbase))
    }

    // SAFETY: U1; no pointers in. U5, the result is a static string of the
    // library.
    let manifest = unsafe { crate::sys::lama_manifest() }.cast::<c_void>();
    if manifest.is_null() {
        return None;
    }
    let (path, base) = image_of(manifest)?;
    // SAFETY: U10, `path` is the loader's NUL-terminated name for an image
    // already loaded; `RTLD_NOLOAD` opens nothing new.
    let handle = unsafe { dlopen(path, RTLD_NOW | RTLD_NOLOAD) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: U10, a handle from `dlopen` and a NUL-terminated name.
    let ptr = unsafe { dlsym(handle, c"oxi_abi_version".as_ptr()) };
    let own = !ptr.is_null() && image_of(ptr).is_some_and(|(_, b)| b == base);
    let value = own.then(|| {
        // SAFETY: U1, the symbol is the library's own `int oxi_abi_version(void)`,
        // which the header declares and the header-pinning test checks.
        let function =
            unsafe { core::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> c_int>(ptr) };
        // SAFETY: U1; no pointers, callable in any module state.
        unsafe { function() }
    });
    // SAFETY: U10, releases the reference `dlopen` took; the library stays
    // loaded through the program's own reference.
    unsafe { dlclose(handle) };
    value
}

#[cfg(windows)]
pub(crate) fn abi_version() -> Option<i32> {
    use core::ffi::{c_char, c_int, c_void};

    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x4;
    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x2;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut *mut c_void) -> i32;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }

    let mut module: *mut c_void = core::ptr::null_mut();
    // SAFETY: U1; no pointers in. U5, the result is a static string of the
    // library.
    let addr = unsafe { crate::sys::lama_manifest() }.cast::<c_void>();
    // SAFETY: U10, as in `library_path`.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            addr.cast(),
            &raw mut module,
        )
    };
    if found == 0 {
        return None;
    }
    // SAFETY: U10, a module handle and a NUL-terminated export name.
    let ptr = unsafe { GetProcAddress(module, c"oxi_abi_version".as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: U1, as on the other platforms.
    let function =
        unsafe { core::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> c_int>(ptr) };
    // SAFETY: U1; no pointers, callable in any module state.
    Some(unsafe { function() })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
pub(crate) fn abi_version() -> Option<i32> {
    None
}
