//! Byte acquisition: reading the module's own image.
//!
//! Two routes, used for different entry kinds.
//!
//! **The memory route** reads the image as loaded, for every `Plain`,
//! `Relative` and `Bind` entry, the slot and the key record. On Linux and
//! Android it is `pread` on `/proc/self/mem`, then `process_vm_readv` on
//! the calling process when that fails (a non-dumpable process finds
//! `/proc/self/mem` owned by root, while `process_vm_readv` passes the same
//! ptrace check against itself). On Darwin it is `mach_vm_read_overwrite`,
//! on Windows `ReadProcessMemory`. Both routes failing is
//! [`Unreadable`]: the test was not performed. There is no fallback to the
//! image file for these entries, because the file is not the loaded
//! image.
//!
//! **The file route** reads the image file the loader reports, for
//! `FileOnly` entries alone: initialised writable data the loader or the
//! module may rewrite before the test runs, whose signed value is the
//! file's. Linux and Android take the path and mapping offset from the
//! `/proc/self/maps` line containing the slot; Darwin asks `dladdr`, and
//! reads at the slice whose header and slot are the loaded image's when
//! that file is universal;
//! Windows asks `GetModuleFileNameW`. The file is opened only when the
//! slot lists a `FileOnly` entry.
//!
//! Every system call that is not a file read lives in `oxicrypt-imageread`,
//! which is what lets this crate keep `#![forbid(unsafe_code)]`.

use std::fs::File;
use std::path::{Path, PathBuf};

use oxicrypt_imageread::ReadError;

use crate::slot::{BindRecord, SlotFields};
use crate::verify::{self, Located, Process};
use crate::{IntegrityError, Unreadable};

/// The page granularity mapping offsets and addresses agree modulo. Every
/// supported page size is a multiple of it.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the maps reader serves Linux and Android; its tests run everywhere"
    )
)]
const PAGE: u64 = 4096;

/// Runs the integrity test in this process.
pub(crate) fn verify_at(
    slot_addr: usize,
    key_addr: usize,
    fingerprint: &mut Option<[u8; 32]>,
) -> Result<(), IntegrityError> {
    let mut process = ThisProcess::new(Routes::SYSTEM);
    verify::verify(&mut process, slot_addr as u64, key_addr as u64, fingerprint)
}

/// The memory routes, in the order they are tried. Function pointers so a
/// test can make either fail; production uses [`Routes::SYSTEM`].
#[derive(Clone, Copy)]
pub(crate) struct Routes {
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(
            dead_code,
            reason = "the Linux and Android route and maps reader; their tests run everywhere"
        )
    )]
    /// Linux and Android: open `/proc/self/mem` and read `out` at `addr`.
    pub(crate) proc_self_mem: fn(u64, &mut [u8]) -> std::io::Result<File>,
    /// The kernel-mediated copy: `process_vm_readv`, `mach_vm_read_overwrite`
    /// or `ReadProcessMemory`.
    pub(crate) read_self: fn(usize, &mut [u8]) -> Result<(), ReadError>,
}

impl Routes {
    /// The real routes.
    pub(crate) const SYSTEM: Self = Self {
        proc_self_mem: open_proc_self_mem,
        read_self: oxicrypt_imageread::read_self,
    };
}

/// Opens `/proc/self/mem` and reads `out` at `addr` through it.
fn open_proc_self_mem(addr: u64, out: &mut [u8]) -> std::io::Result<File> {
    let file = File::open("/proc/self/mem")?;
    read_exact_at(&file, out, addr)?;
    Ok(file)
}

/// Which memory route served the first read; later reads use it.
#[derive(Debug)]
pub(crate) enum Route {
    /// No read has succeeded yet.
    Unchosen,
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(
            dead_code,
            reason = "the Linux and Android route and maps reader; their tests run everywhere"
        )
    )]
    /// `/proc/self/mem`, kept open.
    ProcSelfMem(File),
    /// The kernel-mediated copy.
    SystemCall,
}

/// This process, read through the platform's routes.
pub(crate) struct ThisProcess {
    routes: Routes,
    pub(crate) route: Route,
    file: Option<(PathBuf, File)>,
}

impl ThisProcess {
    pub(crate) fn new(routes: Routes) -> Self {
        Self {
            routes,
            route: Route::Unchosen,
            file: None,
        }
    }

    /// The open image file, opened on first use.
    fn image_file(&mut self, path: &Path) -> Result<&File, Unreadable> {
        let reopen = self.file.as_ref().is_none_or(|(p, _)| p != path);
        if reopen {
            let file = File::open(path).map_err(Unreadable::FileOpen)?;
            self.file = Some((path.to_owned(), file));
        }
        self.file
            .as_ref()
            .map(|(_, f)| f)
            .ok_or(Unreadable::NoBackingFile)
    }
}

impl Process for ThisProcess {
    fn read(&mut self, addr: u64, out: &mut [u8]) -> Result<(), Unreadable> {
        let addr_usize = usize::try_from(addr).map_err(|_| Unreadable::SlotUnmapped)?;
        match &self.route {
            Route::ProcSelfMem(file) => {
                return read_exact_at(file, out, addr).map_err(Unreadable::MemoryRead);
            }
            Route::SystemCall => {
                return (self.routes.read_self)(addr_usize, out)
                    .map_err(Unreadable::SelfReadFailed);
            }
            Route::Unchosen => {}
        }
        let (route, outcome) = choose_route(self.routes, addr, out);
        if outcome.is_ok() {
            self.route = route;
        }
        outcome
    }

    fn locate_file(
        &mut self,
        slot: &SlotFields,
        slot_addr: u64,
        base: u64,
        span: u64,
    ) -> Result<Located, Unreadable> {
        locate_this_image(slot, slot_addr, base, span)
    }

    fn file_size(&mut self, path: &Path) -> Result<u64, Unreadable> {
        Ok(self
            .image_file(path)?
            .metadata()
            .map_err(Unreadable::FileOpen)?
            .len())
    }

    fn read_file(&mut self, path: &Path, pos: u64, out: &mut [u8]) -> Result<(), Unreadable> {
        let file = self.image_file(path)?;
        read_exact_at(file, out, pos).map_err(Unreadable::FileRead)
    }

    fn resolve(&mut self, record: &BindRecord) -> Result<Option<u64>, Option<Unreadable>> {
        match oxicrypt_imageread::resolve_symbol(&record.library, verify::symbol_of(record)) {
            Ok(found) => Ok(found.map(|a| a as u64)),
            Err(ReadError::NoMechanism) => Err(None),
            Err(e) => Err(Some(Unreadable::Resolver(e))),
        }
    }

    fn loaded_image(&mut self, path: &[u8]) -> Result<Option<u64>, Unreadable> {
        match oxicrypt_imageread::loaded_image(path) {
            Ok(base) => Ok(base.map(|b| b as u64)),
            Err(ReadError::NoMechanism) => Ok(None),
            Err(e) => Err(Unreadable::Resolver(e)),
        }
    }

    fn indirect_stubs(&self) -> bool {
        cfg!(all(
            target_arch = "x86_64",
            any(target_os = "macos", target_os = "ios")
        ))
    }

    fn mapped(&mut self, addr: u64, len: u64, slot_addr: u64) -> Option<bool> {
        if let Some(maps) = this_maps() {
            return range_mapped(&maps, addr, len);
        }
        // Windows: inside the image is committed, readable memory of the
        // allocation the loader made for the module the slot lies in, across
        // every region of the range.
        oxicrypt_imageread::range_in_image(
            usize::try_from(slot_addr).ok()?,
            usize::try_from(addr).ok()?,
            usize::try_from(len).ok()?,
        )
        .ok()
    }

    fn payload_cap(
        &mut self,
        slot_addr: u64,
        base: u64,
        span: u64,
        file_len: u64,
    ) -> Result<u64, Unreadable> {
        this_payload_cap(slot_addr, base, span, file_len)
    }
}

/// Linux and Android: the bytes of the slot's image file mapped readable or
/// executable inside the range the slot's entries describe. Where
/// `/proc/self/maps` does not exist, the size of the file the loader names
/// for the slot's address by an absolute path; where neither can be
/// measured, the test is not performed.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn this_payload_cap(
    slot_addr: u64,
    base: u64,
    span: u64,
    file_len: u64,
) -> Result<u64, Unreadable> {
    payload_cap_from(
        std::fs::read_to_string("/proc/self/maps"),
        slot_addr,
        base,
        span,
        file_len,
        oxicrypt_imageread::image_path,
    )
}

/// [`this_payload_cap`] over a maps read and a path lookup, so a test can
/// make either fail.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the maps reader serves Linux and Android; its tests run everywhere"
    )
)]
///
/// Only a missing `/proc/self/maps` falls back to the loader's name for the
/// image, which bounds the allocation and nothing else: the bytes compared
/// never come from it. A relative name is refused, since it resolves against
/// whatever the working directory has become, and a file shorter than the
/// slot's `file_len` is the environment's, never damage.
pub(crate) fn payload_cap_from(
    maps: std::io::Result<String>,
    slot_addr: u64,
    base: u64,
    span: u64,
    file_len: u64,
    image_path: fn(usize) -> Result<PathBuf, ReadError>,
) -> Result<u64, Unreadable> {
    let maps = match maps {
        Ok(maps) => maps,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let addr = usize::try_from(slot_addr).map_err(|_| Unreadable::SlotUnmapped)?;
            let path = image_path(addr).map_err(|image_path| Unreadable::ImagePathWithoutMaps {
                maps: e,
                image_path,
            })?;
            if !path.is_absolute() {
                return Err(Unreadable::ImagePathRelative(path));
            }
            return image_file_cap(&path, file_len);
        }
        Err(e) => return Err(Unreadable::MapsUnavailable(e)),
    };
    match mapped_bytes_in(&maps, slot_addr, base, span) {
        // No mapping of a named file holds the slot: nothing measured the
        // image, so nothing bounds the allocation.
        0 => Err(Unreadable::NoBackingFile),
        cap => Ok(cap),
    }
}

/// Darwin and Windows: the image file's physical size. A slot cannot
/// describe more bytes than the file the image came from holds, and a size
/// that cannot be measured is refused rather than skipped.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn this_payload_cap(
    slot_addr: u64,
    _base: u64,
    _span: u64,
    file_len: u64,
) -> Result<u64, Unreadable> {
    let addr = usize::try_from(slot_addr).map_err(|_| Unreadable::SlotUnmapped)?;
    let path = oxicrypt_imageread::image_path(addr).map_err(Unreadable::ImagePath)?;
    image_file_cap(&path, file_len)
}

/// The size of the image file at `path`, as a bound on the payload. A file
/// shorter than the slot's `file_len` is [`Unreadable::FileLength`]: the
/// environment named a file that is not the image, which says nothing
/// about the slot.
fn image_file_cap(path: &std::path::Path, file_len: u64) -> Result<u64, Unreadable> {
    let size = std::fs::metadata(path).map_err(Unreadable::FileOpen)?.len();
    if size < file_len {
        return Err(Unreadable::FileLength {
            expected: file_len,
            actual: size,
        });
    }
    Ok(size)
}

/// This process's `/proc/self/maps`, where the platform has one.
fn this_maps() -> Option<String> {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        std::fs::read_to_string("/proc/self/maps").ok()
    } else {
        None
    }
}

/// Whether `[addr, addr + len)` is covered by contiguous readable or
/// executable mappings; `None` when a line of the maps does not parse, so
/// the answer cannot be trusted either way.
pub(crate) fn range_mapped(maps: &str, addr: u64, len: u64) -> Option<bool> {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for line in maps.lines() {
        let m = parse_mapping(line)?.ok()?;
        if m.readable || m.executable {
            ranges.push((m.start, m.end));
        }
    }
    ranges.sort_unstable();
    let end = addr.saturating_add(len);
    let mut covered = addr;
    for (start, stop) in ranges {
        if start <= covered && stop > covered {
            covered = stop;
        }
        if covered >= end {
            return Some(true);
        }
    }
    Some(false)
}

/// The bytes of the slot's image file mapped readable or executable inside
/// `[base, base + span)`, the address range the slot's own entries describe.
/// An execute-only text mapping counts: `/proc/self/mem` reads it. Mappings
/// of the same file elsewhere (a second load, a crash reporter's view) are
/// outside that range and do not count, and no gap between mappings is
/// bridged, so a layout aligned to large pages is measured as it is.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the maps reader serves Linux and Android; its tests run everywhere"
    )
)]
pub(crate) fn mapped_bytes_in(maps: &str, slot_addr: u64, base: u64, span: u64) -> u64 {
    let mappings: Vec<Mapping> = maps
        .lines()
        .filter_map(parse_mapping)
        .filter_map(Result::ok)
        .collect();
    let Some(path) = mappings
        .iter()
        .find(|m| slot_addr >= m.start && slot_addr < m.end)
        .and_then(|m| m.path.clone())
    else {
        return 0;
    };
    let end = base.saturating_add(span);
    mappings
        .iter()
        .filter(|m| (m.readable || m.executable) && m.path.as_deref() == Some(path.as_str()))
        .map(|m| m.end.min(end).saturating_sub(m.start.max(base)))
        .fold(0u64, u64::saturating_add)
}

/// Positioned read of a whole buffer.
fn read_exact_at(file: &File, out: &mut [u8], pos: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(out, pos)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < out.len() {
            let window = out
                .get_mut(done..)
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            let at = pos
                .checked_add(done as u64)
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            let n = file.seek_read(window, at)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            done = done.saturating_add(n);
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, out, pos);
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// Tries the memory routes in order for the first read: `/proc/self/mem`,
/// then the kernel-mediated copy. Both failing is reported with both
/// errors. Nothing else is tried: the image file is not the loaded image.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn choose_route(
    routes: Routes,
    addr: u64,
    out: &mut [u8],
) -> (Route, Result<(), Unreadable>) {
    let addr_usize = usize::try_from(addr).unwrap_or(usize::MAX);
    match (routes.proc_self_mem)(addr, out) {
        Ok(file) => (Route::ProcSelfMem(file), Ok(())),
        Err(proc_self_mem) => match (routes.read_self)(addr_usize, out) {
            Ok(()) => (Route::SystemCall, Ok(())),
            Err(process_vm_readv) => (
                Route::Unchosen,
                Err(Unreadable::MemoryRoutesFailed {
                    proc_self_mem,
                    process_vm_readv,
                }),
            ),
        },
    }
}

/// Darwin and Windows have one memory route.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn choose_route(
    routes: Routes,
    addr: u64,
    out: &mut [u8],
) -> (Route, Result<(), Unreadable>) {
    let addr_usize = usize::try_from(addr).unwrap_or(usize::MAX);
    match (routes.read_self)(addr_usize, out) {
        Ok(()) => (Route::SystemCall, Ok(())),
        Err(ReadError::NoMechanism) => (Route::Unchosen, Err(Unreadable::NoMechanism)),
        Err(e) => (Route::Unchosen, Err(Unreadable::SelfReadFailed(e))),
    }
}

/// Linux and Android: the image file is named by `/proc/self/maps`. Without
/// the maps the file route is not performed: nothing else names the file the
/// loader mapped, or where in it the image starts.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn locate_this_image(
    slot: &SlotFields,
    slot_addr: u64,
    base: u64,
    span: u64,
) -> Result<Located, Unreadable> {
    locate_from(
        std::fs::read_to_string("/proc/self/maps"),
        slot,
        slot_addr,
        base,
        span,
        oxicrypt_imageread::page_size().unwrap_or(PAGE).max(PAGE),
    )
}

/// [`locate_this_image`] over a maps read and the page size, so a test can
/// supply either.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the maps reader serves Linux and Android; its tests run everywhere"
    )
)]
pub(crate) fn locate_from(
    maps: std::io::Result<String>,
    slot: &SlotFields,
    slot_addr: u64,
    base: u64,
    span: u64,
    page: u64,
) -> Result<Located, Unreadable> {
    let maps = maps.map_err(Unreadable::MapsUnavailable)?;
    locate_image_paged(&maps, slot, slot_addr, base, span, page)
}

/// Windows, and any other target: the operating system names the image
/// file, which may carry its code-signature envelope after the signed
/// image.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn locate_this_image(
    _slot: &SlotFields,
    slot_addr: u64,
    _base: u64,
    _span: u64,
) -> Result<Located, Unreadable> {
    let addr = usize::try_from(slot_addr).map_err(|_| Unreadable::SlotUnmapped)?;
    let path = oxicrypt_imageread::image_path(addr).map_err(Unreadable::ImagePath)?;
    Ok(Located {
        path,
        base: 0,
        envelope: true,
    })
}

/// Darwin: `dladdr` names the image file, which is either the signed image
/// followed by its code-signature envelope, or a universal file holding it
/// as one architecture slice. The image's place in the file is the one
/// candidate whose Mach header and integrity slot equal the loaded image's
/// (see [`locate_slice`]).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn locate_this_image(
    slot: &SlotFields,
    slot_addr: u64,
    base: u64,
    _span: u64,
) -> Result<Located, Unreadable> {
    let addr = usize::try_from(slot_addr).map_err(|_| Unreadable::SlotUnmapped)?;
    let path = oxicrypt_imageread::image_path(addr).map_err(Unreadable::ImagePath)?;
    let mut header = [0u8; MACH_HEADER_LEN];
    oxicrypt_imageread::read_self(
        usize::try_from(base).map_err(|_| Unreadable::SlotUnmapped)?,
        &mut header,
    )
    .map_err(Unreadable::SelfReadFailed)?;
    let mut loaded_slot = vec![0u8; crate::SLOT_SIZE];
    oxicrypt_imageread::read_self(addr, &mut loaded_slot).map_err(Unreadable::SelfReadFailed)?;
    let file = File::open(&path).map_err(Unreadable::FileOpen)?;
    let size = file.metadata().map_err(Unreadable::FileOpen)?.len();
    let mut read =
        |pos: u64, out: &mut [u8]| read_exact_at(&file, out, pos).map_err(Unreadable::FileRead);
    let offset = locate_slice(&mut read, size, &header, &loaded_slot, slot.slot_file_off)?;
    Ok(Located {
        path,
        base: offset,
        envelope: true,
    })
}

/// A read of `out.len()` bytes of the image file at a position.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "ios")),
    allow(dead_code, reason = "the Darwin file route; its tests run everywhere")
)]
pub(crate) type ReadAt<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), Unreadable> + 'a;

/// Length of a 64-bit Mach header.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "ios")),
    allow(dead_code, reason = "the Darwin file route; its tests run everywhere")
)]
const MACH_HEADER_LEN: usize = 32;

/// Where in an image file the loaded image lies: the offset whose Mach
/// header equals `header` and whose integrity slot, `slot_file_off` past
/// it, equals `slot`, both as loaded.
///
/// A thin image file has one candidate, offset zero. A universal file
/// (`FAT_MAGIC` or `FAT_MAGIC_64`, big-endian) proposes one per slice from
/// its architecture table. The table only proposes: a candidate is taken
/// when its bytes equal the loaded image's, so nothing read from the table
/// decides what is hashed. Exactly one candidate must match.
///
/// The table is read whole, within the limits dyld's universal-file parser
/// sets: the header and every declared entry inside the first 4 KiB and
/// inside the file. A table past them, or a 32-bit table followed by the
/// arm64 entry dyld also loads although `nfat_arch` does not count it, is
/// refused rather than shortened.
///
/// # Errors
///
/// [`Unreadable::SliceNotFound`] when no candidate, or more than one,
/// matches; [`Unreadable::UniversalTable`] for a table outside those
/// limits or with that hidden entry; a read failure as `read` reports it.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "ios")),
    allow(dead_code, reason = "the Darwin file route; its tests run everywhere")
)]
pub(crate) fn locate_slice(
    read: &mut ReadAt<'_>,
    size: u64,
    header: &[u8],
    slot: &[u8],
    slot_file_off: u32,
) -> Result<u64, Unreadable> {
    /// The universal-file magics, as the big-endian file holds them.
    const FAT_MAGIC: u32 = 0xcafe_babe;
    const FAT_MAGIC_64: u32 = 0xcafe_babf;
    /// The bytes of a universal file's header and table dyld reads.
    const TABLE_LIMIT: u64 = 4096;
    /// `CPU_TYPE_ARM64`.
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;

    let mut candidates: Vec<u64> = Vec::new();
    let mut head = [0u8; 8];
    if size >= 8 {
        read(0, &mut head)?;
    }
    let [m0, m1, m2, m3, n0, n1, n2, n3] = head;
    let magic = u32::from_be_bytes([m0, m1, m2, m3]);
    if size >= 8 && (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
        let count = u64::from(u32::from_be_bytes([n0, n1, n2, n3]));
        let (width, at): (u64, u64) = if magic == FAT_MAGIC { (20, 8) } else { (32, 8) };
        let table_end = count
            .checked_mul(width)
            .and_then(|t| t.checked_add(8))
            .filter(|&end| end <= TABLE_LIMIT && end <= size)
            .ok_or(Unreadable::UniversalTable)?;
        if magic == FAT_MAGIC && table_end.saturating_add(width) <= size.min(TABLE_LIMIT) {
            let mut cputype = [0u8; 4];
            read(table_end, &mut cputype)?;
            if u32::from_be_bytes(cputype) == CPU_TYPE_ARM64 {
                return Err(Unreadable::UniversalTable);
            }
        }
        for i in 0..count {
            let entry = 8u64.saturating_add(i.saturating_mul(width));
            let offset = if magic == FAT_MAGIC {
                let mut field = [0u8; 4];
                read(entry.saturating_add(at), &mut field)?;
                u64::from(u32::from_be_bytes(field))
            } else {
                let mut field = [0u8; 8];
                read(entry.saturating_add(at), &mut field)?;
                u64::from_be_bytes(field)
            };
            candidates.push(offset);
        }
    } else {
        candidates.push(0);
    }

    let mut found: Option<u64> = None;
    let mut buf = vec![0u8; slot.len()];
    for offset in candidates {
        let slot_at = offset.checked_add(u64::from(slot_file_off));
        let fits = slot_at
            .and_then(|s| s.checked_add(slot.len() as u64))
            .is_some_and(|end| end <= size)
            && offset.saturating_add(header.len() as u64) <= size;
        let Some(slot_at) = slot_at.filter(|_| fits) else {
            continue;
        };
        let mut file_header = vec![0u8; header.len()];
        read(offset, &mut file_header)?;
        if file_header != header {
            continue;
        }
        read(slot_at, &mut buf)?;
        if buf != slot {
            continue;
        }
        if found.replace(offset).is_some() {
            return Err(Unreadable::SliceNotFound);
        }
    }
    found.ok_or(Unreadable::SliceNotFound)
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the Linux and Android route and maps reader; their tests run everywhere"
    )
)]
/// One line of `/proc/self/maps`, reduced to what is needed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mapping {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) offset: u64,
    pub(crate) path: Option<String>,
    /// Whether the mapping is readable. glibc reserves the gaps between a
    /// library's segments with `---p` mappings of the same file, which map
    /// nothing the image uses.
    pub(crate) readable: bool,
    /// Whether the mapping is executable. An execute-only text segment
    /// (`--xp`) maps the image although it is not readable.
    pub(crate) executable: bool,
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the Linux and Android route and maps reader; their tests run everywhere"
    )
)]
/// Parses one `/proc/self/maps` line.
fn parse_mapping(line: &str) -> Option<Result<Mapping, Unreadable>> {
    let mut fields = line.split_whitespace();
    let (start, end) = fields.next()?.split_once('-')?;
    let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
    else {
        return None;
    };
    let perms = fields.next().unwrap_or("");
    let readable = perms.starts_with('r');
    let executable = perms.get(2..3) == Some("x");
    // A mapping whose offset will not parse is refused rather than
    // defaulted: substituting zero would read the wrong bytes.
    let Some(Ok(offset)) = fields.next().map(|o| u64::from_str_radix(o, 16)) else {
        return Some(Err(Unreadable::MapsUnparseable));
    };
    let _dev = fields.next();
    let _inode = fields.next();
    let rest = fields.collect::<Vec<_>>().join(" ");
    let path = if rest.is_empty() || rest.starts_with('[') {
        None
    } else {
        Some(rest)
    };
    Some(Ok(Mapping {
        start,
        end,
        offset,
        path,
        readable,
        executable,
    }))
}

/// The largest page size a Linux or Android loader maps a segment with (64
/// KiB on aarch64 kernels built for 64 KiB pages): a segment's mapping
/// rounds its file range out to this at most.
const SEGMENT_PAGE: u64 = 0x1_0000;

/// Whether a mapping of `len` bytes, starting `rel_file` into the image's
/// file and `rel_mem` past its load base, is placed the way this image's
/// loader places that file range: it overlaps the file range of an entry
/// (or of the slot) and moves it by exactly that entry's `rva - file_off`.
/// A different archive entry mapped inside the image's span does not.
fn places_like_the_image(slot: &SlotFields, rel_mem: u64, rel_file: u64, len: u64) -> bool {
    let file_end = rel_file.saturating_add(len);
    let delta = i128::from(rel_mem).wrapping_sub(i128::from(rel_file));
    // The file runs this image places at `delta`: the slot and every entry
    // moved by exactly that much, merged where they lie within a page of
    // each other, as one mapping covers them.
    let slot_run = (
        u64::from(slot.slot_file_off),
        u64::from(slot.slot_file_off).saturating_add(crate::SLOT_SIZE as u64),
        i128::from(slot.slot_rva).wrapping_sub(i128::from(slot.slot_file_off)),
    );
    let mut runs: Vec<(u64, u64)> = core::iter::once(slot_run)
        .chain(slot.entries.iter().map(|e| {
            (
                u64::from(e.file_off),
                e.file_end().map_or(u64::MAX, u64::from),
                i128::from(e.rva).wrapping_sub(i128::from(e.file_off)),
            )
        }))
        .filter(|&(_, _, run_delta)| run_delta == delta)
        .map(|(start, end, _)| (start, end))
        .collect();
    runs.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in runs {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(SEGMENT_PAGE) => {
                last.1 = last.1.max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    // The mapping must lie within one such run, widened only by the page
    // rounding a loader applies to a segment's ends.
    merged.iter().any(|&(start, end)| {
        let low = start & !SEGMENT_PAGE.wrapping_sub(1);
        let high = end
            .checked_next_multiple_of(SEGMENT_PAGE)
            .unwrap_or(u64::MAX);
        rel_file >= low && file_end <= high
    })
}

/// [`locate_image_paged`] at the runtime page size.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the Linux and Android route and maps reader; their tests run everywhere"
    )
)]
#[cfg(test)]
pub(crate) fn locate_image(
    maps: &str,
    slot: &SlotFields,
    slot_addr: u64,
    base: u64,
    span: u64,
) -> Result<Located, Unreadable> {
    locate_image_paged(maps, slot, slot_addr, base, span, PAGE)
}

/// Finds the image file and the image's offset inside it from the text of
/// `/proc/self/maps`.
///
/// The image's offset inside that file is
/// `image_base = map.offset + slot_address - map.start - slot_file_off`,
/// from the mapping containing the slot: zero for a library loaded from
/// its own file, the entry's offset when bionic maps the library straight
/// out of an APK. It must be page-aligned.
///
/// Every readable or executable mapping of the same file whose file range
/// overlaps `[image_base, image_base + file_len)` and whose addresses meet
/// the image's range `[base, base + span)` (`span` being the end of the
/// highest RVA the slot names, rounded up to `page`) must be one this
/// image's loader could have made: it lies wholly inside that range, and
/// it moves the file range it maps by exactly the `rva - file_off` of an
/// entry, or the slot, covering that range. A segment whose address and
/// file offset differ by whole pages, which is ordinary in ELF, passes; a
/// different archive entry or a foreign mapping of the file inside the
/// image's range is refused.
///
/// A mapping of the file wholly outside the image's range is another load of
/// it (`dlmopen`, a second Android linker namespace) or another view of the
/// archive, and bears on nothing this test reads: the file route reads at
/// `image_base`, derived from the slot's own mapping. `---p` reservations are
/// not mappings of image bytes and are skipped.
///
/// `page` is the process's page size: the last segment's mapping ends on
/// that boundary, so the image's range does too.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "the Linux and Android route and maps reader; their tests run everywhere"
    )
)]
pub(crate) fn locate_image_paged(
    maps: &str,
    slot: &SlotFields,
    slot_addr: u64,
    base: u64,
    span: u64,
    page: u64,
) -> Result<Located, Unreadable> {
    let mut mappings = Vec::new();
    for line in maps.lines() {
        if let Some(parsed) = parse_mapping(line) {
            mappings.push(parsed?);
        }
    }
    let own = mappings
        .iter()
        .find(|m| slot_addr >= m.start && slot_addr < m.end)
        .ok_or(Unreadable::SlotUnmapped)?;
    let path = own.path.clone().ok_or(Unreadable::NoBackingFile)?;
    let image_base = own
        .offset
        .checked_add(slot_addr.saturating_sub(own.start))
        .and_then(|v| v.checked_sub(u64::from(slot.slot_file_off)))
        .ok_or(Unreadable::SlotUnmapped)?;
    if image_base % PAGE != 0 {
        return Err(Unreadable::ArchiveBaseUnaligned(image_base));
    }
    let image_end = image_base
        .checked_add(u64::from(slot.file_len))
        .ok_or(Unreadable::SlotUnmapped)?;
    let range_end = base.saturating_add(span.checked_next_multiple_of(page).unwrap_or(u64::MAX));
    for m in &mappings {
        if m.path.as_deref() != Some(path.as_str()) || !(m.readable || m.executable) {
            continue;
        }
        let len = m.end.saturating_sub(m.start);
        let overlaps = m.offset < image_end && m.offset.saturating_add(len) > image_base;
        if !overlaps || m.end <= base || m.start >= range_end {
            continue;
        }
        let rel_file = m.offset.saturating_sub(image_base);
        let rel_mem = m.start.saturating_sub(base);
        // A mapping of the image's file bytes reaching outside the address
        // range the slot's entries describe, or one inside it that moves its
        // bytes unlike the slot's entry for them, contradicts the slot.
        let in_range = m.offset >= image_base && m.start >= base && m.end <= range_end;
        if !in_range {
            return Err(Unreadable::ForeignArchiveMapping);
        }
        if !places_like_the_image(slot, rel_mem, rel_file, len) {
            return Err(Unreadable::MappingMisplaced);
        }
    }
    Ok(Located {
        path: PathBuf::from(path),
        base: image_base,
        envelope: false,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        unused_imports,
        dead_code,
        reason = "the route tests run on Linux and Android"
    )
)]
mod tests {
    use super::{Route, Routes, ThisProcess, locate_image};

    /// The image-file bound every platform's file fallback uses: a file at
    /// least `file_len` long bounds the payload by its size, and a shorter
    /// one is the environment's, reported as `FileLength`, never damage.
    #[test]
    fn a_named_file_shorter_than_file_len_is_unreadable() {
        let exe = std::env::current_exe().unwrap();
        let size = std::fs::metadata(&exe).unwrap().len();
        assert_eq!(super::image_file_cap(&exe, size).unwrap(), size);
        assert!(matches!(
            super::image_file_cap(&exe, size + 1),
            Err(crate::Unreadable::FileLength { expected, actual })
                if expected == size + 1 && actual == size
        ));
    }
    use crate::Unreadable;
    use crate::slot::SlotFields;
    use crate::verify::{Located, Process, check_file_length};

    fn fields(slot_file_off: u32, file_len: u32) -> SlotFields {
        SlotFields {
            flags: 0,
            slot_rva: slot_file_off,
            key_id: [0; 32],
            link_base: 0,
            slot_file_off,
            file_len,
            entries: Vec::new(),
            records: Vec::new(),
        }
    }

    /// A `Plain` run at `rva` from file offset `file_off`.
    fn run(rva: u32, file_off: u32, len: u32) -> crate::slot::Entry {
        crate::slot::Entry {
            rva,
            file_off,
            len,
            kind: crate::slot::EntryKind::Plain,
            meta: 0,
        }
    }

    /// A library loaded from its own file has `image_base` zero.
    #[test]
    fn a_plain_library_has_a_zero_image_base() {
        let maps = "\
7f0000000000-7f0000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000002000-7f0000006000 r-xp 00002000 08:01 42 /usr/lib/libx.so
";
        let base = 0x7f00_0000_0000;
        let mut f = fields(0x2100, 0x6000);
        f.entries = vec![run(0, 0, 0x2000), run(0x2000, 0x2000, 0x100)];
        let located = locate_image(maps, &f, base + 0x2100, base, 0x6000).unwrap();
        assert_eq!(located.base, 0);
        assert_eq!(located.path, std::path::Path::new("/usr/lib/libx.so"));
        assert!(!located.envelope);
    }

    /// The shape of a real ELF artifact: the executable and writable
    /// segments sit one or more pages higher in memory than in the file
    /// (`p_vaddr - p_offset` of 0x1000 and 0x3000), and the slot lives in
    /// the shifted executable segment. It must locate, at `image_base` zero.
    #[test]
    fn segments_shifted_from_their_file_offsets_locate() {
        let maps = "\
7f0000000000-7f00000c9000 r--p 00000000 08:01 42 /usr/lib/liby.so
7f00000ca000-7f0000141000 r-xp 000c9000 08:01 42 /usr/lib/liby.so
7f0000142000-7f0000145000 rw-p 00140000 08:01 42 /usr/lib/liby.so
7f0000147000-7f0000148000 rw-p 00144000 08:01 42 /usr/lib/liby.so
";
        let base = 0x7f00_0000_0000;
        // The slot at file offset 0xd0010, which this image maps at RVA
        // 0xd1010.
        let mut f = fields(0xd_0010, 0x14_5000);
        f.slot_rva = 0xd_1010;
        f.entries = vec![
            run(0, 0, 0xc_9000),
            run(0xca_000, 0xc9_000, 0x7_7000),
            run(0x14_2000, 0x14_0000, 0x3000),
            run(0x14_7000, 0x14_4000, 0x800),
        ];
        let located = locate_image(maps, &f, base + 0xd_1010, base, 0x14_8000).unwrap();
        assert_eq!(
            located.base, 0,
            "a shifted plain library has image_base zero"
        );
    }

    /// An aarch64 library linked for 64 KiB pages, loaded by glibc: the
    /// writable segment sits 64 KiB higher in memory than in the file, and
    /// the loader reserves the gap between the segments with a `---p`
    /// mapping of the same file. The intact image locates, the hole is not
    /// readable memory, and the cap counts only the readable bytes.
    #[test]
    fn a_64k_page_layout_with_a_reserved_hole_locates() {
        let maps = "\
7f0000000000-7f0000020000 r-xp 00000000 08:01 42 /usr/lib/libz.so
7f0000020000-7f0000030000 ---p 00020000 08:01 42 /usr/lib/libz.so
7f0000030000-7f0000040000 rw-p 00020000 08:01 42 /usr/lib/libz.so
";
        let base = 0x7f00_0000_0000;
        let mut f = fields(0x1000, 0x2_2440);
        f.entries = vec![
            run(0, 0, 0x1000),
            run(0x1_1000, 0x1_1000, 0x1340),
            run(0x3_2340, 0x2_2340, 0x100),
        ];
        let span = 0x3_2440;
        let located =
            super::locate_image_paged(maps, &f, base + 0x1000, base, span, 0x1_0000).unwrap();
        assert_eq!(located.base, 0);
        assert_eq!(
            super::range_mapped(maps, base + 0x2_0000, 0x10),
            Some(false)
        );
        assert_eq!(
            super::range_mapped(maps, base + 0x3_2340, 0x100),
            Some(true)
        );
        assert_eq!(
            super::mapped_bytes_in(maps, base + 0x1000, base, span),
            0x2_2440,
            "the hole is not counted"
        );
        // Control: the same hole mapped readable is a mapping the slot does
        // not place there.
        let readable_hole = maps.replace("---p", "r--p");
        match super::locate_image_paged(&readable_hole, &f, base + 0x1000, base, span, 0x1_0000) {
            Err(Unreadable::MappingMisplaced) => {}
            other => panic!("expected MappingMisplaced, got {other:?}"),
        }
    }

    /// A library mapped out of an APK has `image_base` equal to its entry's
    /// offset in the archive, and a decoy entry of the same archive mapped
    /// below the subject, outside its range, does not disturb that.
    #[test]
    fn an_apk_mapped_library_finds_its_entry_past_a_decoy() {
        let maps = "\
7a0000000000-7a0000004000 r-xp 00010000 fd:01 9 /data/app/base.apk
7b0000000000-7b0000002000 r--p 00040000 fd:01 9 /data/app/base.apk
7b0000003000-7b0000008000 r-xp 00042000 fd:01 9 /data/app/base.apk
";
        let base = 0x7b00_0000_0000;
        let slot_addr = base + 0x4000;
        // The executable segment is shifted by a page: file 0x2000 maps at
        // RVA 0x3000, so the slot at RVA 0x4000 is at file offset 0x3000.
        let mut f = fields(0x3000, 0x8000);
        f.slot_rva = 0x4000;
        f.entries = vec![run(0, 0, 0x2000), run(0x3000, 0x2000, 0x1000)];
        let located = locate_image(maps, &f, slot_addr, base, 0x8000).unwrap();
        assert_eq!(
            located.base, 0x40000,
            "image_base is the subject entry's offset"
        );

        // Bytes of the subject's entry mapped again at another address,
        // below the image or above its span, are another view of the
        // archive: they do not move `image_base` and are not refused.
        for elsewhere in [
            "7a0000000000-7a0000001000 r--p 00044000 fd:01 9 /data/app/base.apk\n",
            "7b0000100000-7b0000101000 r--p 00045000 fd:01 9 /data/app/base.apk\n",
        ] {
            let maps = format!(
                "{elsewhere}\
7b0000000000-7b0000002000 r--p 00040000 fd:01 9 /data/app/base.apk
7b0000003000-7b0000008000 r-xp 00042000 fd:01 9 /data/app/base.apk
"
            );
            assert_eq!(
                locate_image(&maps, &f, slot_addr, base, 0x8000)
                    .unwrap()
                    .base,
                0x40000
            );
        }

        // Control: a mapping of the subject's bytes that runs out of the
        // image's address range is refused, and so is one inside the range
        // that maps archive bytes from before the subject's entry.
        for hostile in [
            "7b0000007000-7b0000009000 r--p 00045000 fd:01 9 /data/app/base.apk\n",
            "7b0000005000-7b0000007000 r--p 0003f000 fd:01 9 /data/app/base.apk\n",
        ] {
            let maps = format!(
                "\
7b0000000000-7b0000002000 r--p 00040000 fd:01 9 /data/app/base.apk
7b0000003000-7b0000008000 r-xp 00042000 fd:01 9 /data/app/base.apk
{hostile}"
            );
            match locate_image(&maps, &f, slot_addr, base, 0x8000) {
                Err(Unreadable::ForeignArchiveMapping) => {}
                other => panic!("expected ForeignArchiveMapping, got {other:?}"),
            }
        }
    }

    /// A second load of the same library (`dlmopen`, another Android
    /// linker namespace) maps the same file bytes at another base. The first
    /// load still locates, and its cap counts only its own mappings.
    #[test]
    fn a_second_load_of_the_same_file_is_not_damage() {
        let one = "\
7f0000000000-7f0000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000002000-7f0000006000 r-xp 00002000 08:01 42 /usr/lib/libx.so
";
        let two = "\
7f4000000000-7f4000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f4000002000-7f4000006000 r-xp 00002000 08:01 42 /usr/lib/libx.so
";
        let base = 0x7f00_0000_0000;
        let mut f = fields(0x2100, 0x6000);
        f.entries = vec![run(0, 0, 0x2000), run(0x2000, 0x2000, 0x100)];
        for maps in [format!("{one}{two}"), format!("{two}{one}")] {
            assert_eq!(
                locate_image(&maps, &f, base + 0x2100, base, 0x6000)
                    .unwrap()
                    .base,
                0
            );
            assert_eq!(
                super::mapped_bytes_in(&maps, base + 0x2100, base, 0x6000),
                0x6000
            );
        }
    }

    /// An execute-only text mapping (`--xp`) maps image bytes: it counts
    /// toward the cap, and it is placed like any other mapping.
    #[test]
    fn an_execute_only_mapping_counts_and_is_placed() {
        let maps = "\
7f0000000000-7f0000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000002000-7f0000006000 --xp 00002000 08:01 42 /usr/lib/libx.so
";
        let base = 0x7f00_0000_0000;
        let mut f = fields(0x100, 0x6000);
        f.entries = vec![run(0x1_0100, 0x1_0100, 0x100), run(0x2000, 0x2000, 0x4000)];
        f.entries.sort_by_key(|e| e.rva);
        assert_eq!(
            super::mapped_bytes_in(maps, base + 0x100, base, 0x6000),
            0x6000
        );
        assert!(locate_image(maps, &f, base + 0x100, base, 0x1_0200).is_ok());
        // Control: the same mapping one page from where its entry places it.
        let moved = maps.replace("7f0000002000-7f0000006000", "7f0000003000-7f0000007000");
        match locate_image(&moved, &f, base + 0x100, base, 0x1_0200) {
            Err(Unreadable::MappingMisplaced) => {}
            other => panic!("expected MappingMisplaced, got {other:?}"),
        }
    }

    fn no_maps() -> std::io::Result<String> {
        Err(std::io::ErrorKind::NotFound.into())
    }

    fn this_exe(_: usize) -> Result<std::path::PathBuf, oxicrypt_imageread::ReadError> {
        std::env::current_exe().map_err(|_| oxicrypt_imageread::ReadError::Os(2))
    }

    fn no_path(_: usize) -> Result<std::path::PathBuf, oxicrypt_imageread::ReadError> {
        Err(oxicrypt_imageread::ReadError::NoImage)
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the signature of an image-path lookup"
    )]
    fn relative(_: usize) -> Result<std::path::PathBuf, oxicrypt_imageread::ReadError> {
        Ok(std::path::PathBuf::from("./liboxicrypt_ffi.so"))
    }

    /// Without `/proc/self/maps` the loader's name for the image only bounds
    /// the allocation, and only when it is absolute and at least the signed
    /// length; the file route is not performed at all. Every such case is
    /// `Unreadable`, never a pass and never damage.
    #[test]
    fn without_proc_the_file_route_is_unreadable_and_the_cap_needs_an_absolute_path() {
        let exe_len = std::fs::metadata(std::env::current_exe().unwrap())
            .unwrap()
            .len();
        assert_eq!(
            super::payload_cap_from(no_maps(), 0x1000, 0, 0x2000, exe_len, this_exe).unwrap(),
            exe_len
        );
        match super::payload_cap_from(no_maps(), 0x1000, 0, 0x2000, exe_len + 1, this_exe) {
            Err(Unreadable::FileLength { expected, actual }) => {
                assert_eq!((expected, actual), (exe_len + 1, exe_len));
            }
            other => panic!("expected FileLength, got {other:?}"),
        }
        match super::payload_cap_from(no_maps(), 0x1000, 0, 0x2000, 1, relative) {
            Err(Unreadable::ImagePathRelative(_)) => {}
            other => panic!("expected ImagePathRelative, got {other:?}"),
        }
        match super::payload_cap_from(no_maps(), 0x1000, 0, 0x2000, 1, no_path) {
            Err(Unreadable::ImagePathWithoutMaps { maps, .. }) => {
                assert_eq!(maps.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected ImagePathWithoutMaps, got {other:?}"),
        }
        // Any other failure to read the maps is reported as it is, without
        // consulting the loader's name.
        let denied = || Err(std::io::ErrorKind::PermissionDenied.into());
        match super::payload_cap_from(denied(), 0x1000, 0, 0x2000, 1, this_exe) {
            Err(Unreadable::MapsUnavailable(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected MapsUnavailable, got {other:?}"),
        }
        // The file route never falls back: a FileOnly entry without the maps
        // is not read from any file.
        for maps in [no_maps(), denied()] {
            match super::locate_from(maps, &fields(0, 0x1_0000), 0x1000, 0, 0x2000, 0x1000) {
                Err(Unreadable::MapsUnavailable(_)) => {}
                other => panic!("expected MapsUnavailable, got {other:?}"),
            }
        }
    }

    /// An unrelated view of the image file mapped just past the image, inside
    /// a 64 KiB rounding of its span but past its last page, is not the
    /// image's and is not refused; one that reaches into the image's last
    /// page is.
    #[test]
    fn a_view_past_the_image_end_is_not_refused() {
        let image = "\
7f0000000000-7f0000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000002000-7f0000006000 r-xp 00002000 08:01 42 /usr/lib/libx.so
";
        let base = 0x7f00_0000_0000;
        let mut f = fields(0x2100, 0x6000);
        f.entries = vec![run(0, 0, 0x2000), run(0x2000, 0x2000, 0x100)];
        let past =
            format!("{image}7f0000007000-7f0000008000 r--p 00000000 08:01 42 /usr/lib/libx.so\n");
        assert!(super::locate_image_paged(&past, &f, base + 0x2100, base, 0x5c58, 0x1000).is_ok());
        let into =
            format!("{image}7f0000005000-7f0000008000 r--p 00000000 08:01 42 /usr/lib/libx.so\n");
        match super::locate_image_paged(&into, &f, base + 0x2100, base, 0x5c58, 0x1000) {
            Err(Unreadable::ForeignArchiveMapping) => {}
            other => panic!("expected ForeignArchiveMapping, got {other:?}"),
        }
    }

    /// Maps that hold no mapping of a file at the slot measure nothing, which
    /// is `Unreadable` rather than a cap of zero.
    #[test]
    fn a_cap_of_nothing_is_unreadable() {
        let maps = "7f0000000000-7f0000002000 r--p 00000000 00:00 0\n".to_owned();
        match super::payload_cap_from(
            Ok(maps),
            0x7f00_0000_0100,
            0x7f00_0000_0000,
            0x2000,
            1,
            no_path,
        ) {
            Err(Unreadable::NoBackingFile) => {}
            other => panic!("expected NoBackingFile, got {other:?}"),
        }
    }

    /// A mapping inside the image's span that moves its file range by a
    /// different amount than the entry covering that range is refused. Page
    /// congruence alone cannot see this: both sides are page-aligned.
    #[test]
    fn a_mapping_placed_unlike_its_entry_is_refused() {
        let base = 0x7f00_0000_0000;
        let mut f = fields(0x2100, 0x6000);
        f.entries = vec![run(0, 0, 0x2000), run(0x2000, 0x2000, 0x100)];
        let good = "\
7f0000000000-7f0000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000002000-7f0000006000 r-xp 00002000 08:01 42 /usr/lib/libx.so
";
        assert!(locate_image(good, &f, base + 0x2100, base, 0x6000).is_ok());
        // The first segment mapped one page higher than its entry places it.
        let moved = "\
7f0000001000-7f0000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000002000-7f0000006000 r-xp 00002000 08:01 42 /usr/lib/libx.so
";
        match locate_image(moved, &f, base + 0x2100, base, 0x6000) {
            Err(Unreadable::MappingMisplaced) => {}
            other => panic!("expected MappingMisplaced, got {other:?}"),
        }
        // A mapping that runs on past its entry's file range into bytes the
        // slot places elsewhere is refused too, though it starts in place.
        let mut short = fields(0x2_0100, 0x4_0000);
        short.entries = vec![run(0, 0, 0x800)];
        short.slot_rva = 0x3_0100;
        let overlong = "\
7f0000000000-7f0000021000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000030000-7f0000040000 r--p 00020000 08:01 42 /usr/lib/libx.so
";
        match locate_image(overlong, &short, base + 0x3_0100, base, 0x4_0100) {
            Err(Unreadable::MappingMisplaced) => {}
            other => panic!("expected MappingMisplaced, got {other:?}"),
        }
    }

    #[test]
    fn mapped_ranges_and_spans_are_read_from_maps() {
        let maps = "\
7f0000000000-7f0000002000 r--p 00000000 08:01 42 /usr/lib/libx.so
7f0000002000-7f0000006000 r-xp 00002000 08:01 42 /usr/lib/libx.so
7f0000008000-7f0000009000 rw-p 00000000 00:00 0
";
        assert_eq!(
            super::range_mapped(maps, 0x7f00_0000_1000, 0x2000),
            Some(true)
        );
        assert_eq!(
            super::range_mapped(maps, 0x7f00_0000_5000, 0x2000),
            Some(false)
        );
        // An execute-only mapping is mapped; an unparseable line makes the
        // answer unknown rather than false.
        let xom = "7f0000000000-7f0000002000 --xp 00000000 08:01 42 /usr/lib/libx.so\n";
        assert_eq!(
            super::range_mapped(xom, 0x7f00_0000_0000, 0x1000),
            Some(true)
        );
        let broken = format!("{maps}7f0000009000-7f000000a000 r--p zz 08:01 42 /x\n");
        assert_eq!(super::range_mapped(&broken, 0x7f00_0000_5000, 0x2000), None);
        let base = 0x7f00_0000_0000;
        assert_eq!(
            super::mapped_bytes_in(maps, base + 0x3000, base, 0x6000),
            0x6000
        );
        // A distant mapping of the same file does not count.
        let far =
            format!("{maps}7f8000000000-7f8000001000 r--p 00000000 08:01 42 /usr/lib/libx.so\n");
        assert_eq!(
            super::mapped_bytes_in(&far, base + 0x3000, base, 0x6000),
            0x6000
        );
    }

    /// An archive base that is not page-aligned cannot be a mapped entry.
    #[test]
    fn an_unaligned_image_base_is_refused() {
        let maps = "7b0000000000-7b0000004000 r--p 00040000 fd:01 9 /data/app/base.apk\n";
        let base = 0x7b00_0000_0000;
        match locate_image(maps, &fields(0x10, 0x4000), base + 0x20, base, 0x4000) {
            Err(Unreadable::ArchiveBaseUnaligned(_)) => {}
            other => panic!("expected ArchiveBaseUnaligned, got {other:?}"),
        }
    }

    fn fail_proc_self_mem(_: u64, _: &mut [u8]) -> std::io::Result<std::fs::File> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }

    fn fail_read_self(_: usize, _: &mut [u8]) -> Result<(), oxicrypt_imageread::ReadError> {
        Err(oxicrypt_imageread::ReadError::Os(1))
    }

    /// `/proc/self/mem` is tried first and kept when it works.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn proc_self_mem_is_the_first_route() {
        let source = [0x5au8; 16];
        let mut process = ThisProcess::new(Routes::SYSTEM);
        let mut out = [0u8; 16];
        process
            .read(core::ptr::from_ref(&source) as u64, &mut out)
            .unwrap();
        assert_eq!(out, source);
        assert!(matches!(process.route, Route::ProcSelfMem(_)));
    }

    /// When `/proc/self/mem` fails, as it does for a non-dumpable process,
    /// `process_vm_readv` serves the read and is kept.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn process_vm_readv_serves_when_proc_self_mem_fails() {
        let source = [0xa5u8; 16];
        let mut process = ThisProcess::new(Routes {
            proc_self_mem: fail_proc_self_mem,
            read_self: Routes::SYSTEM.read_self,
        });
        let mut out = [0u8; 16];
        process
            .read(core::ptr::from_ref(&source) as u64, &mut out)
            .unwrap();
        assert_eq!(out, source);
        assert!(matches!(process.route, Route::SystemCall));
    }

    /// Both memory routes failing is `MemoryRoutesFailed`, even for an
    /// address whose bytes the image file holds: a writable static's
    /// initial value is in the file, and a file fallback would return it.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn no_file_fallback_when_both_memory_routes_fail() {
        static INITIALISED: [u8; 16] = [0x3c; 16];
        let mut process = ThisProcess::new(Routes {
            proc_self_mem: fail_proc_self_mem,
            read_self: fail_read_self,
        });
        let mut out = [0u8; 16];
        match process.read(core::ptr::from_ref(&INITIALISED) as u64, &mut out) {
            Err(Unreadable::MemoryRoutesFailed { .. }) => {}
            other => panic!("expected MemoryRoutesFailed, got {other:?}"),
        }
        assert_eq!(out, [0u8; 16], "nothing may be read from anywhere else");
        assert!(matches!(process.route, Route::Unchosen));
    }

    /// The real routes both fail on an unmapped address.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn both_real_routes_fail_on_an_unmapped_address() {
        let mut out = [0u8; 16];
        match ThisProcess::new(Routes::SYSTEM).read(8, &mut out) {
            Err(Unreadable::MemoryRoutesFailed { .. }) => {}
            other => panic!("expected MemoryRoutesFailed, got {other:?}"),
        }
    }

    /// A plain file must be exactly the signed length; an archive must hold
    /// the image; a file with an operating-system signature envelope may be
    /// longer than the signed image, never shorter.
    #[test]
    fn the_file_route_checks_the_length() {
        let at = |base, envelope| Located {
            path: "x".into(),
            base,
            envelope,
        };
        assert!(check_file_length(&at(0, false), 100, 100).is_ok());
        assert!(matches!(
            check_file_length(&at(0, false), 100, 101),
            Err(Unreadable::FileLength {
                expected: 100,
                actual: 101
            })
        ));
        assert!(check_file_length(&at(4096, false), 100, 4196).is_ok());
        assert!(check_file_length(&at(4096, false), 100, 4195).is_err());
        assert!(check_file_length(&at(0, true), 100, 100).is_ok());
        assert!(check_file_length(&at(0, true), 100, 9000).is_ok());
        assert!(check_file_length(&at(0, true), 100, 99).is_err());
    }

    /// The Darwin file route finds the loaded image in a thin file at offset
    /// zero and in a universal file at its slice, by the loaded header and
    /// slot; a file holding neither, or two matching slices, is refused.
    #[test]
    #[allow(
        clippy::indexing_slicing,
        reason = "fixture bytes laid out by literals in this test"
    )]
    fn the_loaded_slice_is_found_by_its_header_and_slot() {
        use super::locate_slice;
        const SLOT_AT: u32 = 0x40;
        let header = [0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1];
        let slot = [0x5au8; 16];
        let thin = |h: &[u8], s: &[u8]| {
            let mut f = vec![0u8; 0x80];
            f[..h.len()].copy_from_slice(h);
            f[SLOT_AT as usize..SLOT_AT as usize + s.len()].copy_from_slice(s);
            f
        };
        let run = |file: &[u8]| {
            let mut read = |pos: u64, out: &mut [u8]| {
                let pos = usize::try_from(pos).unwrap();
                out.copy_from_slice(file.get(pos..pos + out.len()).ok_or_else(|| {
                    Unreadable::FileRead(std::io::ErrorKind::UnexpectedEof.into())
                })?);
                Ok(())
            };
            locate_slice(&mut read, file.len() as u64, &header, &slot, SLOT_AT)
        };
        assert_eq!(run(&thin(&header, &slot)).unwrap(), 0);
        let mut other = header;
        other[4] = 0x0c;
        assert!(matches!(
            run(&thin(&other, &slot)),
            Err(Unreadable::SliceNotFound)
        ));
        assert!(matches!(
            run(&thin(&header, &[0x5b; 16])),
            Err(Unreadable::SliceNotFound)
        ));

        // A universal file: a foreign slice at 0x100, ours at 0x200.
        let fat = |magic: u32, wide: bool, ours: &[u8]| {
            let mut f = vec![0u8; 0x300];
            f[..4].copy_from_slice(&magic.to_be_bytes());
            f[4..8].copy_from_slice(&2u32.to_be_bytes());
            for (i, off) in [0x100u64, 0x200].iter().enumerate() {
                let entry = 8 + i * if wide { 32 } else { 20 };
                if wide {
                    f[entry + 8..entry + 16].copy_from_slice(&off.to_be_bytes());
                } else {
                    f[entry + 8..entry + 12]
                        .copy_from_slice(&u32::try_from(*off).unwrap().to_be_bytes());
                }
            }
            f[0x100..0x180].copy_from_slice(&thin(&other, &slot));
            f[0x200..0x280].copy_from_slice(&thin(ours, &slot));
            f
        };
        assert_eq!(run(&fat(0xcafe_babe, false, &header)).unwrap(), 0x200);
        assert_eq!(run(&fat(0xcafe_babf, true, &header)).unwrap(), 0x200);
        // Control: neither slice is the loaded image.
        assert!(matches!(
            run(&fat(0xcafe_babe, false, &other)),
            Err(Unreadable::SliceNotFound)
        ));
        // Two slices that both match leave the image's place undecided.
        let mut twice = fat(0xcafe_babe, false, &header);
        let ours = twice[0x200..0x280].to_vec();
        twice[0x100..0x180].copy_from_slice(&ours);
        assert!(matches!(run(&twice), Err(Unreadable::SliceNotFound)));
    }

    /// The whole declared table is read: a match at index 65 of 70 is found,
    /// a second match at index 66 is refused, and a table past dyld's 4 KiB
    /// limit or a hidden arm64 entry after it is refused rather than
    /// shortened.
    #[test]
    #[allow(
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        reason = "fixture bytes and offsets laid out by literals in this test"
    )]
    fn the_whole_universal_table_is_read_within_dyld_limits() {
        use super::locate_slice;
        const SLOT_AT: usize = 0x40;
        const SLICE: usize = 0x80;
        let header = [0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1];
        let slot = [0x5au8; 16];
        // `count` 32-bit entries, the slices named by `ours` holding the
        // loaded image, every other entry pointing at an empty slice.
        let fat = |count: u32, ours: &[usize], hidden: bool| {
            let base = 0x2000;
            let mut f = vec![0u8; base + (count as usize + 1) * SLICE];
            f[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
            f[4..8].copy_from_slice(&count.to_be_bytes());
            for i in 0..count as usize {
                let entry = 8 + i * 20;
                let off = base + i * SLICE;
                if entry + 20 <= 0x2000 {
                    f[entry + 8..entry + 12].copy_from_slice(&(off as u32).to_be_bytes());
                }
                if ours.contains(&i) {
                    f[off..off + header.len()].copy_from_slice(&header);
                    f[off + SLOT_AT..off + SLOT_AT + slot.len()].copy_from_slice(&slot);
                }
            }
            if hidden {
                let entry = 8 + count as usize * 20;
                f[entry..entry + 4].copy_from_slice(&0x0100_000cu32.to_be_bytes());
            }
            f
        };
        let run = |file: &[u8]| {
            let mut read = |pos: u64, out: &mut [u8]| {
                let pos = usize::try_from(pos).unwrap();
                out.copy_from_slice(file.get(pos..pos + out.len()).ok_or_else(|| {
                    Unreadable::FileRead(std::io::ErrorKind::UnexpectedEof.into())
                })?);
                Ok(())
            };
            locate_slice(&mut read, file.len() as u64, &header, &slot, SLOT_AT as u32)
        };
        assert_eq!(
            run(&fat(70, &[65], false)).unwrap(),
            0x2000 + 65 * SLICE as u64
        );
        assert!(matches!(
            run(&fat(70, &[3, 66], false)),
            Err(Unreadable::SliceNotFound)
        ));
        // 8 + 204 * 20 = 4088 fits the first 4 KiB; 205 entries do not.
        assert!(run(&fat(204, &[200], false)).is_ok());
        assert!(matches!(
            run(&fat(205, &[200], false)),
            Err(Unreadable::UniversalTable)
        ));
        assert!(matches!(
            run(&fat(2, &[1], true)),
            Err(Unreadable::UniversalTable)
        ));
        // Control: the same table without the hidden entry is found.
        assert!(run(&fat(2, &[1], false)).is_ok());
    }
}
