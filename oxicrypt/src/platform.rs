//! Which file the loader bound the library to, for a diagnostic.
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
