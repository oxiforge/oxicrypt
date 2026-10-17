//! PE32+ classification: the typed extent of an x86_64 DLL or EXE.
//!
//! The signer's half of the design for Windows, outside the cryptographic
//! boundary like the rest of this crate. Every byte the loader maps from the
//! file is typed, from the loader's own structures:
//!
//! | Region | Kind |
//! |---|---|
//! | Headers, `[0, SizeOfHeaders)` | `Plain`; `ImageBase` `Relative`; `CheckSum` and the Security directory entry holes when measured to vary |
//! | Every section mapped read-only (`.text`, `.rdata`, `.pdata`, `.reloc`, ...) | `Plain` |
//! | A `DIR64` base-relocation destination in `Plain` bytes, Load Config pointers among them | `Relative` |
//! | An IAT thunk the import directory enumerates | `Bind` |
//! | Each storage word the load configuration names for the loader to write (CFG, XFG, CastGuard, GuardMemcpy) | `FileOnly` |
//! | File alignment padding past a section's `VirtualSize` | `FileOnly` |
//! | The TLS template inside a writable section | `Plain`, `DIR64` words `Relative` |
//! | Every other file-backed byte of a writable section (`.data`) | `FileOnly` |
//!
//! A section's file-backed bytes are its raw data; memory past
//! `SizeOfRawData` is zero-fill. Whether a loader writes a storage word, or
//! maps a padding byte, depends on the host, so both are signed from the
//! file, which is what an edit at rest changes. A `Relative` word's file value is its
//! address at `ImageBase`, which the slot records as its link base; the
//! module subtracts the load delta from the loaded word. The Windows loader
//! rewrites the mapped `ImageBase` field with the address it chose, so that
//! field is `Relative` too. A `Bind` word contributes nothing to the
//! signature; its record (the DLL as the descriptor names it, and the symbol
//! or ordinal its lookup table entry names) is in the slot's string table,
//! and the module checks the loaded thunk against `GetProcAddress`. The
//! slot's `file_len` is the certificate table's file offset when the image
//! has one: Authenticode appends its signature there.
//!
//! # Envelope holes
//!
//! `signtool` writes two fields inside the headers: the optional header's
//! `CheckSum` and the Security directory entry, which locates the
//! certificate table. Which of them a signing run changes is measured: given
//! a reference, the same build as linked (two signing runs of the same bytes
//! write the same `CheckSum`, so the unsigned image is the reference that
//! shows it), and this artifact after `signtool` with the final certificate
//! and options ([`classify_with`]), each of the two fields that differs
//! becomes a `Hole`, each that does not stays `Plain`, and any other
//! difference before the certificate table is refused. Without a reference
//! both are `Plain`.
//!
//! # Imports
//!
//! Each descriptor must carry a `TimeDateStamp` of zero and a lookup table
//! (`OriginalFirstThunk`), so every thunk the loader writes is named by a
//! lookup-table entry the signature covers; the lookup table, the hint/name
//! entries and the descriptors lie in `Plain` bytes and overlap no thunk or
//! typed word. A thunk edited on disk is overwritten at load and changes
//! nothing; an edit of what names it is a change to signed bytes.
//!
//! # Refused by name
//!
//! `Machine` (anything but x86_64), `Alignment` (a `SectionAlignment` below
//! the page size, or a `FileAlignment` that does not fit it), `Geometry`
//! (an `ImageBase`, `SizeOfImage`, `SizeOfHeaders`, section RVA or raw
//! extent off the format's alignment, raw data without an offset, or raw
//! extents out of order or overlapping), `RelocationBlock` (a relocation
//! block not a 4-byte multiple or not for one 4 KiB page),
//! `RelocationType` (`HIGHLOW`, `HIGH`,
//! `LOW` or any other base relocation but `DIR64` and padding),
//! `RelocTarget` (a `DIR64` destination outside the file-backed bytes or
//! straddling them), `BoundImports` (a bound import directory or a
//! descriptor with a non-zero `TimeDateStamp`), `MissingLookupTable`,
//! `ImportTable` (an import table outside `Plain` bytes, overlapping
//! another, or malformed), `DelayLoadIat` (a delay-load IAT in `Plain`
//! bytes), `DelayLoadDescriptor` (a delay-load descriptor that is not
//! RVA-based, or a directory with no terminator inside it), `Xfg` (an
//! XFG-enabled image),
//! `UncheckedRelocation` (relocated words only in `FileOnly` bytes, so none
//! is checked as loaded), `TlsTemplate`, `TlsIndex` (the TLS index slot in
//! `Plain` bytes), `DelayLoadHandle` (a delay-load module handle in `Plain`
//! bytes), `TableNotCovered`, `WordOverlap`,
//! `CertificateTable`, `TooManyImports` (more than 65,536 imports) and
//! `ReservationDiff`.
//!
//! # Module statics
//!
//! A PE image carries no symbol table the signer can trust to name the
//! module's statics, so [`module_statics`] reads them from the program
//! database the linker wrote, accepted only when its GUID and age are the
//! ones the image's CodeView debug record names. The linker places
//! zero-initialised data after `.data`'s initialised bytes, and the section's
//! raw data is rounded up to the file alignment, so a zero-initialised static
//! that falls inside that rounding is a byte of the file. The signer refuses
//! while any module static is.

mod pdb;

use oxicrypt_integrity::SLOT_SIZE;
use oxicrypt_integrity::slot::{self, BindRecord, EntryKind, Range, SlotFields};

use crate::elf::{REQUIRED_STATICS, StaticRow, Statics, links_boot_test};
use crate::image::{
    Layout, Placed, Region, RelativeEncoding, ensure_disjoint, ensure_non_empty, entries_of,
    file_len_of, find_slot, slot_fits, subtract_slot, u16_at, u32_at, u64_at,
};

/// Offset of `e_lfanew` in the DOS header.
const E_LFANEW_OFF: usize = 0x3c;
/// `IMAGE_NT_SIGNATURE`.
const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
const PE32_PLUS_MAGIC: u16 = 0x20b;
/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`, recognised only so the refusal can name it.
const PE32_MAGIC: u16 = 0x10b;
/// `IMAGE_FILE_MACHINE_AMD64`.
const MACHINE_AMD64: u16 = 0x8664;
/// Bytes from the PE signature to the optional header.
const COFF_HEADER_SIZE: usize = 24;
/// `IMAGE_SECTION_HEADER` size.
const SECTION_HEADER_SIZE: usize = 40;
/// `IMAGE_SCN_MEM_WRITE`.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// `IMAGE_SCN_MEM_EXECUTE`.
#[cfg(test)]
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Offsets in the PE32+ optional header.
const OPT_IMAGE_BASE: usize = 24;
const OPT_SECTION_ALIGNMENT: usize = 32;
const OPT_FILE_ALIGNMENT: usize = 36;
/// The page size of every x86_64 Windows host.
const PAGE: u32 = 0x1000;
const OPT_SIZE_OF_IMAGE: usize = 56;
const OPT_SIZE_OF_HEADERS: usize = 60;
const OPT_CHECKSUM: usize = 64;
const OPT_RVA_COUNT: usize = 108;
const OPT_DIRECTORIES: usize = 112;

/// Data directory indices.
const DIR_IMPORT: usize = 1;
const DIR_SECURITY: usize = 4;
const DIR_BASERELOC: usize = 5;
const DIR_DEBUG: usize = 6;
const DIR_TLS: usize = 9;
const DIR_LOAD_CONFIG: usize = 10;
const DIR_BOUND_IMPORT: usize = 11;
const DIR_DELAY_IMPORT: usize = 13;

/// Base relocation types.
const REL_ABSOLUTE: u16 = 0;
const REL_HIGH: u16 = 1;
const REL_LOW: u16 = 2;
const REL_HIGHLOW: u16 = 3;
const REL_DIR64: u16 = 10;

/// Load Config offsets (`IMAGE_LOAD_CONFIG_DIRECTORY64`).
const LC_GUARD_FLAGS: usize = 0x90;
/// The Load Config fields that point at storage the loader may write:
/// `GuardCFCheckFunctionPointer`, `GuardCFDispatchFunctionPointer`,
/// `GuardRFFailureRoutineFunctionPointer`,
/// `GuardRFVerifyStackPointerFunctionPointer`, the three XFG function
/// pointers, `CastGuardOsDeterminedFailureMode` and
/// `GuardMemcpyFunctionPointer`.
const LC_LOADER_STORAGE: [usize; 9] = [0x70, 0x78, 0xd8, 0xe8, 0x118, 0x120, 0x128, 0x130, 0x138];
/// `IMAGE_GUARD_CF_INSTRUMENTED`.
#[cfg(test)]
const GUARD_CF_INSTRUMENTED: u32 = 0x100;
/// A delay-load descriptor's `dlattrRva`: its fields are RVAs.
const DELAY_ATTR_RVA: u32 = 1;
/// `IMAGE_GUARD_XFG_ENABLED`.
const GUARD_XFG_ENABLED: u32 = 0x0080_0000;

/// `IMAGE_DEBUG_TYPE_CODEVIEW`.
const DEBUG_TYPE_CODEVIEW: u32 = 2;
/// Size of an `IMAGE_DEBUG_DIRECTORY` entry.
const DEBUG_ENTRY_SIZE: usize = 28;

/// Width of a thunk, a lookup-table entry and a `DIR64` word.
const WORD: u64 = 8;

/// The file offset of the PE signature, if `bytes` carries a DOS stub pointing
/// at one.
fn pe_header_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..2) != Some(b"MZ".as_slice()) {
        return None;
    }
    let e_lfanew = u32_at(bytes, E_LFANEW_OFF)?;
    let off = usize::try_from(e_lfanew).ok()?;
    (bytes.get(off..off.checked_add(4)?)? == PE_SIGNATURE).then_some(off)
}

/// True when `bytes` looks like a PE32+ image.
#[must_use]
pub fn is_pe32plus(bytes: &[u8]) -> bool {
    pe_header_offset(bytes)
        .and_then(|pe| u16_at(bytes, pe.checked_add(COFF_HEADER_SIZE)?))
        .is_some_and(|magic| magic == PE32_PLUS_MAGIC)
}

/// Why `bytes` is a PE this signer will not classify, if it is one.
#[must_use]
pub fn unsupported_reason(bytes: &[u8]) -> Option<&'static str> {
    let pe = pe_header_offset(bytes)?;
    match u16_at(bytes, pe.checked_add(COFF_HEADER_SIZE)?) {
        Some(PE32_MAGIC) => Some("32-bit PE images are not supported; the module is 64-bit only"),
        Some(PE32_PLUS_MAGIC) => None,
        _ => Some("the PE optional header carries an unrecognised magic"),
    }
}

/// One section header, reduced to what classification needs.
#[derive(Debug, Clone)]
struct Section {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
}

impl Section {
    /// The loader maps this section writable.
    const fn writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// The section's own file-backed bytes: the raw data, capped at the
    /// virtual size, the file alignment padding after it being typed
    /// apart. A section declaring no virtual size maps its raw data whole.
    const fn mapped_len(&self) -> u32 {
        if self.raw_offset == 0 {
            0
        } else if self.virtual_size == 0 || self.virtual_size > self.raw_size {
            self.raw_size
        } else {
            self.virtual_size
        }
    }
}

/// What classification reads from the headers.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_field_names,
    reason = "`image_base` is the format's own term, used under that name across the crate"
)]
struct Image {
    /// File offset of the optional header.
    opt: usize,
    /// The optional header's `ImageBase`: the link base.
    image_base: u64,
    size_of_headers: u32,
    sections: Vec<Section>,
    /// Every data directory, padded to sixteen with empty ones.
    dirs: [(u32, u32); 16],
    /// The image declares a Security directory entry.
    has_security_entry: bool,
}

impl Image {
    fn dir(&self, index: usize) -> (u32, u32) {
        self.dirs.get(index).copied().unwrap_or((0, 0))
    }

    /// The file offset of `[rva, rva + len)`, when the headers or one
    /// section's file-backed bytes hold all of it.
    fn file_of(&self, rva: u32, len: u32) -> Option<usize> {
        let end = rva.checked_add(len)?;
        if end <= self.size_of_headers {
            return usize::try_from(rva).ok();
        }
        self.sections.iter().find_map(|s| {
            let off = rva.checked_sub(s.virtual_address)?;
            (off.checked_add(len)? <= s.mapped_len())
                .then(|| usize::try_from(s.raw_offset.checked_add(off)?).ok())
                .flatten()
        })
    }
}

/// Parses the headers and the section table.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the headers; each field's refusal sits beside the field"
)]
fn parse(bytes: &[u8]) -> Result<Image, String> {
    let pe = pe_header_offset(bytes).ok_or("not a PE image")?;
    if !is_pe32plus(bytes) {
        return Err("not a PE32+ image".to_owned());
    }
    let machine = u16_at(bytes, pe.checked_add(4).ok_or("PE header overflows")?)
        .ok_or("truncated COFF header")?;
    if machine != MACHINE_AMD64 {
        return Err(format!(
            "Machine: the image is for machine {machine:#06x}, not x86_64"
        ));
    }
    let nsections = u16_at(bytes, pe.checked_add(6).ok_or("PE header overflows")?)
        .ok_or("truncated COFF header")?;
    let opt_size = u16_at(bytes, pe.checked_add(20).ok_or("PE header overflows")?)
        .ok_or("truncated COFF header")?;
    let opt = pe
        .checked_add(COFF_HEADER_SIZE)
        .ok_or("optional header offset overflows")?;
    let field = |d: usize| -> Result<usize, String> {
        opt.checked_add(d)
            .ok_or_else(|| "optional header field overflows".to_owned())
    };
    let image_base = u64_at(bytes, field(OPT_IMAGE_BASE)?).ok_or("truncated optional header")?;
    let section_alignment =
        u32_at(bytes, field(OPT_SECTION_ALIGNMENT)?).ok_or("truncated optional header")?;
    let file_alignment =
        u32_at(bytes, field(OPT_FILE_ALIGNMENT)?).ok_or("truncated optional header")?;
    // Below a page, the loader maps the file one to one rather than by
    // section, which this typing does not describe.
    if section_alignment < PAGE
        || !section_alignment.is_power_of_two()
        || !file_alignment.is_power_of_two()
        || !(512..=0x1_0000).contains(&file_alignment)
        || file_alignment > section_alignment
    {
        return Err(format!(
            "Alignment: SectionAlignment {section_alignment:#x} and FileAlignment \
             {file_alignment:#x} are not a page-aligned image the loader maps by section"
        ));
    }
    let size_of_image =
        u32_at(bytes, field(OPT_SIZE_OF_IMAGE)?).ok_or("truncated optional header")?;
    let size_of_headers =
        u32_at(bytes, field(OPT_SIZE_OF_HEADERS)?).ok_or("truncated optional header")?;
    // The loader's own alignment rules for the image as a whole.
    if !image_base.is_multiple_of(0x1_0000)
        || !size_of_image.is_multiple_of(section_alignment)
        || !size_of_headers.is_multiple_of(file_alignment)
    {
        return Err(format!(
            "Geometry: ImageBase {image_base:#x} must be 64 KiB aligned, SizeOfImage \
             {size_of_image:#x} a multiple of SectionAlignment and SizeOfHeaders \
             {size_of_headers:#x} a multiple of FileAlignment"
        ));
    }
    let count = u32_at(bytes, field(OPT_RVA_COUNT)?).ok_or("truncated optional header")?;
    let count = usize::try_from(count).map_err(|_| "data directory count overflows")?;
    if count > 16
        || count
            .checked_mul(8)
            .and_then(|n| n.checked_add(OPT_DIRECTORIES))
            .is_none_or(|n| n > usize::from(opt_size))
    {
        return Err(format!(
            "{count} data directories do not fit the optional header"
        ));
    }
    let mut dirs = [(0u32, 0u32); 16];
    for (i, d) in dirs.iter_mut().enumerate().take(count) {
        let at = field(OPT_DIRECTORIES.saturating_add(i.saturating_mul(8)))?;
        *d = (
            u32_at(bytes, at).ok_or("truncated data directory")?,
            u32_at(bytes, at.saturating_add(4)).ok_or("truncated data directory")?,
        );
    }
    let table = opt
        .checked_add(usize::from(opt_size))
        .ok_or("section table offset overflows")?;
    let table_end = usize::from(nsections)
        .checked_mul(SECTION_HEADER_SIZE)
        .and_then(|n| n.checked_add(table))
        .ok_or("section table overflows")?;
    if table_end > usize::try_from(size_of_headers).unwrap_or(usize::MAX)
        || usize::try_from(size_of_headers).is_ok_and(|h| h > bytes.len())
    {
        return Err("the headers do not hold the section table, or run past the file".to_owned());
    }

    let mut sections: Vec<Section> = Vec::with_capacity(usize::from(nsections));
    let mut raw_floor = size_of_headers;
    for i in 0..usize::from(nsections) {
        let off = table.saturating_add(i.saturating_mul(SECTION_HEADER_SIZE));
        let at = |d: usize| off.saturating_add(d);
        let s = Section {
            virtual_size: u32_at(bytes, at(8)).ok_or("truncated section header")?,
            virtual_address: u32_at(bytes, at(12)).ok_or("truncated section header")?,
            raw_size: u32_at(bytes, at(16)).ok_or("truncated section header")?,
            raw_offset: u32_at(bytes, at(20)).ok_or("truncated section header")?,
            characteristics: u32_at(bytes, at(36)).ok_or("truncated section header")?,
        };
        let span = s.virtual_size.max(s.raw_size);
        if s.virtual_address < size_of_headers
            || s.virtual_address
                .checked_add(span)
                .is_none_or(|end| end > size_of_image)
        {
            return Err(format!(
                "section {i} at RVA {:#x} lies inside the headers or past SizeOfImage",
                s.virtual_address
            ));
        }
        if !s.virtual_address.is_multiple_of(section_alignment)
            || !s.raw_offset.is_multiple_of(file_alignment)
            || !s.raw_size.is_multiple_of(file_alignment)
            || (s.raw_size != 0 && s.raw_offset == 0)
        {
            return Err(format!(
                "Geometry: section {i} at RVA {:#x} has raw data {:#x}+{:#x}; its RVA must be \
                 a multiple of SectionAlignment, its raw offset and size of FileAlignment, and \
                 raw data must have an offset",
                s.virtual_address, s.raw_offset, s.raw_size
            ));
        }
        if s.raw_size != 0 {
            let end = s
                .raw_offset
                .checked_add(s.raw_size)
                .filter(|&e| usize::try_from(e).is_ok_and(|e| e <= bytes.len()))
                .ok_or("a section's file extent runs past the end of the file")?;
            // Raw data follows the headers and each earlier section's, in
            // table order, without overlap.
            if s.raw_offset < raw_floor {
                return Err(format!(
                    "Geometry: section {i}'s raw data at {:#x} overlaps or precedes the headers \
                     or an earlier section's",
                    s.raw_offset
                ));
            }
            raw_floor = end;
        }
        if let Some(prev) = sections.last()
            && prev
                .virtual_address
                .saturating_add(prev.virtual_size.max(prev.raw_size))
                > s.virtual_address
        {
            return Err("the sections are not in ascending, disjoint address order".to_owned());
        }
        sections.push(s);
    }
    Ok(Image {
        opt,
        image_base,
        size_of_headers,
        sections,
        dirs,
        has_security_entry: count > DIR_SECURITY,
    })
}

/// One of the two header fields `signtool` may rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReservedField {
    /// The optional header's `CheckSum`.
    CheckSum,
    /// The Security directory entry: the certificate table's file offset
    /// and size.
    SecurityDirectory,
}

impl ReservedField {
    /// The field's name, as a refusal or a report spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CheckSum => "CheckSum",
            Self::SecurityDirectory => "Security directory entry",
        }
    }
}

/// Where each reserved field lies in the file, and its width.
fn reserved_fields(img: &Image) -> Vec<(ReservedField, usize, usize)> {
    let mut out = vec![(
        ReservedField::CheckSum,
        img.opt.saturating_add(OPT_CHECKSUM),
        4,
    )];
    if img.has_security_entry {
        out.push((
            ReservedField::SecurityDirectory,
            img.opt
                .saturating_add(OPT_DIRECTORIES)
                .saturating_add(DIR_SECURITY.saturating_mul(8)),
            8,
        ));
    }
    out
}

/// Whether `bytes` is a PE32+ image whose Security directory names a
/// certificate table, which `signtool` has signed and must sign again.
pub(crate) fn has_certificate_table(bytes: &[u8]) -> bool {
    parse(bytes).is_ok_and(|img| img.dir(DIR_SECURITY).1 != 0)
}

/// Where the signed image ends: the certificate table's file offset when
/// the image has one, else the file's length.
fn signed_end(bytes: &[u8], img: &Image) -> Result<u64, String> {
    let (offset, size) = img.dir(DIR_SECURITY);
    if size == 0 {
        return Ok(bytes.len() as u64);
    }
    let offset = u64::from(offset);
    let sections_end = img
        .sections
        .iter()
        .map(|s| u64::from(s.raw_offset).saturating_add(u64::from(s.raw_size)))
        .chain(std::iter::once(u64::from(img.size_of_headers)))
        .max()
        .unwrap_or(0);
    if offset < sections_end || offset.saturating_add(u64::from(size)) > bytes.len() as u64 {
        return Err(format!(
            "CertificateTable: the certificate table at file offset {offset:#x} does not lie \
             after every section's raw data and inside the file"
        ));
    }
    Ok(offset)
}

/// The reserved fields `signtool` rewrote between `reference`, the same
/// build before the last signing run (the image as linked shows `CheckSum`),
/// and `bytes`, the artifact after it.
///
/// # Errors
///
/// `ReservationDiff` when any other byte before the certificate table
/// differs, or the two are laid out differently; a description when either
/// is malformed.
pub fn reservation_holes(reference: &[u8], bytes: &[u8]) -> Result<Vec<ReservedField>, String> {
    let a = parse(reference).map_err(|e| format!("the reference: {e}"))?;
    let b = parse(bytes)?;
    let (fa, fb) = (reserved_fields(&a), reserved_fields(&b));
    if a.opt != b.opt || a.size_of_headers != b.size_of_headers || fa != fb {
        return Err(
            "ReservationDiff: the reference's headers are not laid out like this artifact's; it \
             must be the same build"
                .to_owned(),
        );
    }
    let end_a = usize::try_from(signed_end(reference, &a)?).map_err(|_| "offset overflows")?;
    let end_b = usize::try_from(signed_end(bytes, &b)?).map_err(|_| "offset overflows")?;
    let common = end_a.min(end_b);
    // Authenticode pads the image to eight bytes before the certificate
    // table; what one image holds past the other's end must be that padding.
    let longer = if end_a > end_b {
        reference.get(common..end_a)
    } else {
        bytes.get(common..end_b)
    };
    if longer.is_none_or(|tail| tail.len() >= 8 || tail.iter().any(|&x| x != 0)) {
        return Err(format!(
            "ReservationDiff: the reference's signed image is {end_a:#x} bytes and this \
             artifact's {end_b:#x}; they must be the same build"
        ));
    }
    let ra = reference
        .get(..common)
        .ok_or("the reference is truncated")?;
    let rb = bytes.get(..common).ok_or("the artifact is truncated")?;
    let mut changed: Vec<ReservedField> = Vec::new();
    for (i, (x, y)) in ra.iter().zip(rb).enumerate() {
        if x == y {
            continue;
        }
        let field = fb
            .iter()
            .find(|(_, at, len)| i >= *at && i < at.saturating_add(*len))
            .map(|(f, _, _)| *f)
            .ok_or_else(|| {
                format!(
                    "ReservationDiff: byte {i:#x} differs from the reference outside CheckSum \
                     and the Security directory entry"
                )
            })?;
        if !changed.contains(&field) {
            changed.push(field);
        }
    }
    changed.sort();
    Ok(changed)
}

/// Derives the typed extent of a PE32+ image, with `CheckSum` and the
/// Security directory entry `Plain`.
///
/// # Errors
///
/// Returns a description, beginning with the refusal's name where one
/// applies, when the image is malformed, uses a structure the typing does
/// not describe, or the slot is missing or ambiguous.
pub fn classify(bytes: &[u8]) -> Result<Layout, String> {
    classify_with(bytes, None)
}

/// [`classify`], with each reserved field that differs between
/// `reserved_against` and `bytes` typed as a hole (see
/// [`reservation_holes`]).
///
/// # Errors
///
/// As [`classify`] and [`reservation_holes`].
pub fn classify_with(bytes: &[u8], reserved_against: Option<&[u8]>) -> Result<Layout, String> {
    let holes = match reserved_against {
        Some(reference) => reservation_holes(reference, bytes)?,
        None => Vec::new(),
    };
    typed(bytes, &holes)
}

/// The regions every file-backed byte of `img` falls in, ascending by RVA.
fn regions(bytes: &[u8], img: &Image) -> Result<Vec<Region>, String> {
    let mut out = vec![Region {
        va: 0,
        len: u64::from(img.size_of_headers),
        file_off: 0,
        kind: EntryKind::Plain,
        writable: false,
    }];
    // The TLS template the loader copies for each thread, which the module
    // never writes in place.
    let (tls_rva, tls_size) = img.dir(DIR_TLS);
    let template = if tls_size == 0 {
        None
    } else {
        let at = img
            .file_of(tls_rva, 16)
            .ok_or("TlsTemplate: the TLS directory lies outside the file-backed bytes")?;
        let start = u64_at(bytes, at).ok_or("truncated TLS directory")?;
        let end = u64_at(bytes, at.saturating_add(8)).ok_or("truncated TLS directory")?;
        let (start, end) = (
            start.wrapping_sub(img.image_base),
            end.wrapping_sub(img.image_base),
        );
        if end < start {
            return Err("TlsTemplate: the TLS template ends before it begins".to_owned());
        }
        Some((start, end))
    };
    for s in img.sections.iter().filter(|s| s.mapped_len() > 0) {
        let va = u64::from(s.virtual_address);
        let end = va.saturating_add(u64::from(s.mapped_len()));
        let mut push = |from: u64, to: u64, kind: EntryKind| {
            if to > from {
                out.push(Region {
                    va: from,
                    len: to.saturating_sub(from),
                    file_off: u64::from(s.raw_offset).saturating_add(from.saturating_sub(va)),
                    kind,
                    writable: s.writable(),
                });
            }
        };
        // File alignment padding past VirtualSize: a byte of the file the
        // loader may map, whatever the section, checked from the file.
        push(
            end,
            va.saturating_add(u64::from(s.raw_size)),
            EntryKind::FileOnly,
        );
        if !s.writable() {
            push(va, end, EntryKind::Plain);
            continue;
        }
        match template {
            Some((t0, t1)) if t1 > t0 && t0 >= va && t0 < end => {
                if t1 > end {
                    return Err(
                        "TlsTemplate: the TLS template runs past its section's file-backed bytes"
                            .to_owned(),
                    );
                }
                push(va, t0, EntryKind::FileOnly);
                push(t0, t1, EntryKind::Plain);
                push(t1, end, EntryKind::FileOnly);
            }
            _ => push(va, end, EntryKind::FileOnly),
        }
    }
    if let Some((t0, t1)) = template
        && t1 > t0
        && !out
            .iter()
            .any(|r| t0 >= r.va && t1 <= r.end() && r.kind == EntryKind::Plain)
    {
        return Err(
            "TlsTemplate: the TLS template does not lie in one section's file-backed bytes"
                .to_owned(),
        );
    }
    out.sort_by_key(|r| r.va);
    file_only_words(out, &loader_storage(bytes, img)?)
}

/// The region holding all of `[rva, rva + len)`, if one does.
fn region_of(regions: &[Region], rva: u64, len: u64) -> Option<&Region> {
    let end = rva.checked_add(len)?;
    regions.iter().find(|r| rva >= r.va && end <= r.end())
}

/// Whether `[rva, rva + len)` lies in `Plain` bytes.
fn in_plain(regions: &[Region], rva: u64, len: u64) -> bool {
    region_of(regions, rva, len).is_some_and(|r| r.kind == EntryKind::Plain)
}

/// Every `DIR64` destination, by RVA.
fn base_relocations(bytes: &[u8], img: &Image, regions: &[Region]) -> Result<Vec<u64>, String> {
    let (rva, size) = img.dir(DIR_BASERELOC);
    if size == 0 {
        return Ok(Vec::new());
    }
    if !in_plain(regions, u64::from(rva), u64::from(size)) {
        return Err(
            "TableNotCovered: the base relocation table does not lie in Plain bytes".to_owned(),
        );
    }
    let start = img
        .file_of(rva, size)
        .ok_or("the base relocation table lies outside the file")?;
    let table = start
        .checked_add(usize::try_from(size).map_err(|_| "relocation table overflows")?)
        .and_then(|end| bytes.get(start..end))
        .ok_or("the base relocation table runs past the file")?;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < table.len() {
        let page = u32_at(table, at).ok_or("truncated base relocation block")?;
        let block = u32_at(table, at.saturating_add(4)).ok_or("truncated base relocation block")?;
        let block = usize::try_from(block).map_err(|_| "relocation block overflows")?;
        let end = at.checked_add(block).ok_or("relocation block overflows")?;
        // Blocks start on a 32-bit boundary and cover one 4 KiB page each.
        if block < 8
            || !block.is_multiple_of(4)
            || !at.is_multiple_of(4)
            || !page.is_multiple_of(PAGE)
            || end > table.len()
        {
            return Err(format!(
                "RelocationBlock: the base relocation block at offset {at:#x} has page RVA \
                 {page:#x} and size {block}; a block is a 4-byte multiple covering one 4 KiB page"
            ));
        }
        let mut e = at.saturating_add(8);
        while e < end {
            let entry = u16_at(table, e).ok_or("truncated base relocation entry")?;
            let target = u64::from(page).saturating_add(u64::from(entry & 0xfff));
            match entry >> 12 {
                REL_ABSOLUTE => {}
                REL_DIR64 => out.push(target),
                t => {
                    let name = match t {
                        REL_HIGHLOW => "HIGHLOW",
                        REL_HIGH => "HIGH",
                        REL_LOW => "LOW",
                        _ => "an unrecognised",
                    };
                    return Err(format!(
                        "RelocationType: {name} base relocation (type {t}) at RVA {target:#x}; \
                         only DIR64 is typed"
                    ));
                }
            }
            e = e.saturating_add(2);
        }
        at = end;
    }
    out.sort_unstable();
    Ok(out)
}

/// The NUL-terminated string at `rva`, which must lie in `Plain` bytes.
fn string_at(bytes: &[u8], img: &Image, regions: &[Region], rva: u32) -> Result<String, String> {
    let at = img
        .file_of(rva, 1)
        .ok_or_else(|| format!("ImportTable: a name at RVA {rva:#x} lies outside the file"))?;
    let tail = bytes.get(at..).ok_or("a name lies past the file")?;
    let len = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or("ImportTable: a name is not terminated")?;
    let len32 = u32::try_from(len).map_err(|_| "a name overflows")?;
    if !in_plain(regions, u64::from(rva), u64::from(len32).saturating_add(1)) {
        return Err(format!(
            "ImportTable: the name at RVA {rva:#x} does not lie in Plain bytes"
        ));
    }
    let raw = tail.get(..len).ok_or("a name lies past the file")?;
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| "ImportTable: a name is not UTF-8".to_owned())
}

/// What the import directory names: each thunk with its record, and every
/// table the thunks are named by.
struct Imports {
    /// `(thunk RVA, record)`, in table order.
    thunks: Vec<(u64, BindRecord)>,
    /// `(rva, len)` of each lookup table, terminator included.
    lookups: Vec<(u64, u64)>,
    /// `(rva, len)` of each thunk array, terminator included.
    arrays: Vec<(u64, u64)>,
}

/// Walks the import directory.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the descriptors; each refusal sits beside the field it reads"
)]
fn imports(bytes: &[u8], img: &Image, regions: &[Region]) -> Result<Imports, String> {
    let mut out = Imports {
        thunks: Vec::new(),
        lookups: Vec::new(),
        arrays: Vec::new(),
    };
    if img.dir(DIR_BOUND_IMPORT).1 != 0 {
        return Err(
            "BoundImports: the image has a bound import directory; the loader may then keep \
             thunk values the linker wrote"
                .to_owned(),
        );
    }
    let (rva, size) = img.dir(DIR_IMPORT);
    if size == 0 {
        return Ok(out);
    }
    if !in_plain(regions, u64::from(rva), u64::from(size)) {
        return Err("ImportTable: the import directory does not lie in Plain bytes".to_owned());
    }
    let start = img
        .file_of(rva, size)
        .ok_or("ImportTable: the import directory lies outside the file")?;
    let end = start.saturating_add(usize::try_from(size).map_err(|_| "import table overflows")?);
    let mut d = start;
    loop {
        if d.saturating_add(20) > end {
            return Err(
                "ImportTable: the import directory ends before its terminating descriptor"
                    .to_owned(),
            );
        }
        let f = |k: usize| u32_at(bytes, d.saturating_add(k)).ok_or("truncated import descriptor");
        let (lookup, stamp, forwarder, name, thunks) = (f(0)?, f(4)?, f(8)?, f(12)?, f(16)?);
        if lookup == 0 && stamp == 0 && forwarder == 0 && name == 0 && thunks == 0 {
            break;
        }
        let dll = string_at(bytes, img, regions, name)?;
        if stamp != 0 {
            return Err(format!(
                "BoundImports: the descriptor for {dll} carries TimeDateStamp {stamp:#x}; its \
                 thunks may hold values bound at link time"
            ));
        }
        if lookup == 0 {
            return Err(format!(
                "MissingLookupTable: the descriptor for {dll} has no lookup table, so nothing \
                 the signature covers names its thunks"
            ));
        }
        let mut i: u64 = 0;
        loop {
            let at = u64::from(lookup)
                .checked_add(i.saturating_mul(WORD))
                .ok_or("ImportTable: a lookup table overflows")?;
            let at32 = u32::try_from(at).map_err(|_| "ImportTable: a lookup table overflows")?;
            let off = img.file_of(at32, 8).ok_or_else(|| {
                format!("ImportTable: the lookup table for {dll} runs past the file-backed bytes")
            })?;
            let entry = u64_at(bytes, off).ok_or("truncated lookup table")?;
            if entry == 0 {
                break;
            }
            let record = if entry >> 63 == 1 {
                let ordinal = u16::try_from(entry & 0xffff).unwrap_or(0);
                if entry & 0x7fff_ffff_ffff_0000 != 0 || ordinal == 0 {
                    return Err(format!(
                        "ImportTable: an ordinal entry for {dll} is malformed ({entry:#x})"
                    ));
                }
                BindRecord {
                    library: dll.clone(),
                    symbol: String::new(),
                    ordinal,
                    addend: 0,
                    weak: false,
                }
            } else {
                if entry > 0x7fff_ffff {
                    return Err(format!(
                        "ImportTable: a name entry for {dll} is malformed ({entry:#x})"
                    ));
                }
                let hint_name = u32::try_from(entry).map_err(|_| "a hint/name RVA overflows")?;
                if !in_plain(regions, u64::from(hint_name), 2) {
                    return Err(format!(
                        "ImportTable: a hint/name entry for {dll} does not lie in Plain bytes"
                    ));
                }
                let symbol = string_at(bytes, img, regions, hint_name.saturating_add(2))?;
                if symbol.is_empty() {
                    return Err(format!(
                        "ImportTable: an import from {dll} has an empty name"
                    ));
                }
                BindRecord {
                    library: dll.clone(),
                    symbol,
                    ordinal: 0,
                    addend: 0,
                    weak: false,
                }
            };
            let thunk = u64::from(thunks)
                .checked_add(i.saturating_mul(WORD))
                .ok_or("ImportTable: a thunk array overflows")?;
            out.thunks.push((thunk, record));
            i = i.saturating_add(1);
        }
        let len = i.saturating_add(1).saturating_mul(WORD);
        let (lookup, thunks) = (u64::from(lookup), u64::from(thunks));
        if !in_plain(regions, lookup, len) {
            return Err(format!(
                "ImportTable: the lookup table for {dll} does not lie in Plain bytes"
            ));
        }
        if !in_plain(regions, thunks, len) {
            return Err(format!(
                "ImportTable: the thunks for {dll} do not lie in Plain bytes"
            ));
        }
        out.lookups.push((lookup, len));
        out.arrays.push((thunks, len));
        d = d.saturating_add(20);
    }
    // No lookup table may share a byte with any thunk array.
    for &(l, ln) in &out.lookups {
        for &(t, tn) in &out.arrays {
            if l < t.saturating_add(tn) && t < l.saturating_add(ln) {
                return Err(format!(
                    "ImportTable: the lookup table at RVA {l:#x} overlaps the thunks at {t:#x}"
                ));
            }
        }
    }
    Ok(out)
}

/// Whether any byte of `[rva, rva + len)` lies in `Plain` bytes.
fn touches_plain(regions: &[Region], rva: u64, len: u64) -> bool {
    regions
        .iter()
        .any(|r| r.kind == EntryKind::Plain && rva < r.end() && r.va < rva.saturating_add(len))
}

/// Refuses a TLS index slot in `Plain` bytes: the loader stores the index
/// through `AddressOfIndex` at load, so the signed value never survives.
fn check_tls_index(bytes: &[u8], img: &Image, regions: &[Region]) -> Result<(), String> {
    let (rva, size) = img.dir(DIR_TLS);
    if size == 0 {
        return Ok(());
    }
    let at = img
        .file_of(rva, 24)
        .ok_or("TlsTemplate: the TLS directory lies outside the file-backed bytes")?;
    let index = u64_at(bytes, at.saturating_add(16))
        .ok_or("truncated TLS directory")?
        .wrapping_sub(img.image_base);
    if touches_plain(regions, index, 4) {
        return Err(format!(
            "TlsIndex: the TLS index at RVA {index:#x} lies in Plain bytes, which the loader \
             writes at load; link it into writable data"
        ));
    }
    Ok(())
}

/// Refuses a delay-load IAT or module handle in `Plain` bytes: the loader's
/// helper writes both on first call, after the test may have run.
fn check_delay_load(bytes: &[u8], img: &Image, regions: &[Region]) -> Result<(), String> {
    let (rva, size) = img.dir(DIR_DELAY_IMPORT);
    if size == 0 {
        return Ok(());
    }
    let end = rva
        .checked_add(size)
        .ok_or("DelayLoadDescriptor: the delay-load directory overflows")?;
    let mut d = rva;
    loop {
        // Every descriptor, the terminator included, inside the directory.
        if d.checked_add(32).is_none_or(|e| e > end) {
            return Err(
                "DelayLoadDescriptor: the delay-load directory ends before its terminating \
                 descriptor"
                    .to_owned(),
            );
        }
        let off = img
            .file_of(d, 32)
            .ok_or("DelayLoadIat: the delay-load directory lies outside the file-backed bytes")?;
        let f = |k: usize| u32_at(bytes, off.saturating_add(k)).ok_or("truncated delay descriptor");
        let (attributes, handle, iat, names) = (f(0)?, f(8)?, f(12)?, f(16)?);
        if (0..8).all(|k: usize| f(k.saturating_mul(4)) == Ok(0)) {
            return Ok(());
        }
        // `dlattrRva` alone: a legacy descriptor holds addresses, not RVAs,
        // and every other bit is reserved.
        if attributes != DELAY_ATTR_RVA {
            return Err(format!(
                "DelayLoadDescriptor: the delay-load descriptor at RVA {d:#x} has attributes \
                 {attributes:#x}; only RVA-based descriptors (1) are read"
            ));
        }
        let mut n: u32 = 0;
        loop {
            let at = names
                .checked_add(n.saturating_mul(8))
                .and_then(|a| img.file_of(a, 8))
                .ok_or("DelayLoadIat: a delay-load name table runs past the file")?;
            if u64_at(bytes, at) == Some(0) {
                break;
            }
            n = n.saturating_add(1);
        }
        let len = u64::from(n).saturating_mul(WORD);
        if touches_plain(regions, u64::from(iat), len) {
            return Err(format!(
                "DelayLoadIat: the delay-load IAT at RVA {iat:#x} lies in Plain bytes, which \
                 the loader's helper rewrites on first call"
            ));
        }
        if touches_plain(regions, u64::from(handle), WORD) {
            return Err(format!(
                "DelayLoadHandle: the delay-load module handle at RVA {handle:#x} lies in Plain \
                 bytes, which the loader's helper writes on first call; link it into writable \
                 data"
            ));
        }
        d = d.saturating_add(32);
    }
}

/// The RVA of every storage word the load configuration names for the
/// loader to write, whatever the image's guard flags say, since whether a
/// loader writes each depends on the host and its version; refuses an
/// XFG-enabled image.
fn loader_storage(bytes: &[u8], img: &Image) -> Result<Vec<u64>, String> {
    let (rva, size) = img.dir(DIR_LOAD_CONFIG);
    if size == 0 {
        return Ok(Vec::new());
    }
    let lc = img
        .file_of(rva, 4)
        .ok_or("TableNotCovered: the load configuration lies outside the file-backed bytes")?;
    let struct_size = u32_at(bytes, lc).ok_or("truncated load configuration")?;
    if struct_size > size || img.file_of(rva, struct_size).is_none() {
        return Err(format!(
            "TableNotCovered: the load configuration's Size {struct_size:#x} does not fit its \
             directory or the file"
        ));
    }
    let struct_size = usize::try_from(struct_size).map_err(|_| "load configuration overflows")?;
    // A field the structure's Size does not reach is absent for its
    // version: None, never a zero that would read as "no storage".
    let word = |off: usize| {
        (off.saturating_add(8) <= struct_size)
            .then(|| u64_at(bytes, lc.saturating_add(off)))
            .flatten()
    };
    let flags = (LC_GUARD_FLAGS.saturating_add(4) <= struct_size)
        .then(|| u32_at(bytes, lc.saturating_add(LC_GUARD_FLAGS)))
        .flatten();
    if flags.is_some_and(|f| f & GUARD_XFG_ENABLED != 0) {
        return Err(
            "Xfg: the image is XFG-enabled; the loader rewrites XFG storage, and its check \
             functions' type hashes are not typed"
                .to_owned(),
        );
    }
    let mut out: Vec<u64> = LC_LOADER_STORAGE
        .iter()
        .filter_map(|&off| word(off))
        .filter(|&va| va != 0)
        .map(|va| va.wrapping_sub(img.image_base))
        .collect();
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// `regions` with each 8-byte word at `words` that lies in `Plain` bytes
/// made `FileOnly`: the file's value is signed, so the result does not
/// depend on whether the loader writes the word.
fn file_only_words(regions: Vec<Region>, words: &[u64]) -> Result<Vec<Region>, String> {
    let mut out = regions;
    for &w in words {
        let end = w.checked_add(WORD).ok_or("a storage word overflows")?;
        let Some(i) = out.iter().position(|r| w >= r.va && end <= r.end()) else {
            return Err(format!(
                "TableNotCovered: the load configuration names storage at RVA {w:#x}, outside \
                 one region of the image's file-backed bytes"
            ));
        };
        let r = out.remove(i);
        if r.kind != EntryKind::Plain {
            out.insert(i, r);
            continue;
        }
        let at = |from: u64, to: u64, kind: EntryKind| Region {
            va: from,
            len: to.saturating_sub(from),
            file_off: r.file_off.saturating_add(from.saturating_sub(r.va)),
            kind,
            writable: r.writable,
        };
        let parts = [
            at(r.va, w, EntryKind::Plain),
            at(w, end, EntryKind::FileOnly),
            at(end, r.end(), EntryKind::Plain),
        ];
        for (k, p) in parts.into_iter().filter(|p| p.len > 0).enumerate() {
            out.insert(i.saturating_add(k), p);
        }
    }
    Ok(out)
}

/// The typed extent, with `holes` among the reserved fields.
#[allow(
    clippy::too_many_lines,
    reason = "one linear derivation; each refusal sits beside the structure it reads"
)]
fn typed(bytes: &[u8], holes: &[ReservedField]) -> Result<Layout, String> {
    let img = parse(bytes)?;
    let end = signed_end(bytes, &img)?;
    let regions = regions(bytes, &img)?;
    if let Some(r) = regions
        .iter()
        .find(|r| r.file_off.saturating_add(r.len) > end)
    {
        return Err(format!(
            "CertificateTable: mapped bytes at file offset {:#x} lie past the signed image's \
             end {end:#x}",
            r.file_off
        ));
    }
    let mut placed: Vec<Placed> = Vec::new();

    // ImageBase: the loader writes the address it chose.
    placed.push(Placed {
        va: img.opt.saturating_add(OPT_IMAGE_BASE) as u64,
        len: WORD,
        kind: EntryKind::Relative,
        meta: 0,
    });
    // DIR64 destinations: Relative in Plain bytes, nothing in FileOnly.
    let (mut relative, mut file_only) = (0usize, 0usize);
    for rva in base_relocations(bytes, &img, &regions)? {
        let region = region_of(&regions, rva, WORD).ok_or_else(|| {
            format!(
                "RelocTarget: the DIR64 destination at RVA {rva:#x} does not lie wholly in \
                 the image's file-backed bytes"
            )
        })?;
        if region.kind == EntryKind::FileOnly {
            file_only = file_only.saturating_add(1);
            continue;
        }
        relative = relative.saturating_add(1);
        placed.push(Placed {
            va: rva,
            len: WORD,
            kind: EntryKind::Relative,
            meta: 0,
        });
    }
    // A FileOnly word is checked against the file, not against where the
    // loader moved it: an edit of `ImageBase` moves every relocated word
    // while the file's bytes stay the same, and only a Relative word,
    // checked by its loaded value, sees that. (The `ImageBase` field
    // itself does not: the loader rewrites it.)
    if file_only > 0 && relative == 0 {
        return Err(format!(
            "UncheckedRelocation: {file_only} DIR64 destination(s) lie in FileOnly bytes and none \
             in Plain bytes, so no relocated word is checked as loaded and an edited ImageBase \
             would go unseen"
        ));
    }
    check_tls_index(bytes, &img, &regions)?;
    check_delay_load(bytes, &img, &regions)?;
    // Thunks: Bind, records in order of first use in the table, which is
    // address order; the linker need not lay the thunk arrays out in the
    // order of their descriptors.
    let mut imports = imports(bytes, &img, &regions)?;
    imports.thunks.sort_by_key(|(rva, _)| *rva);
    let mut records: Vec<BindRecord> = Vec::new();
    for (rva, record) in imports.thunks {
        let index = if let Some(i) = records.iter().position(|r| *r == record) {
            i
        } else {
            records.push(record);
            records.len().saturating_sub(1)
        };
        placed.push(Placed {
            va: rva,
            len: WORD,
            kind: EntryKind::Bind,
            meta: u16::try_from(index).map_err(|_| "TooManyImports: more than 65,536 imports")?,
        });
    }
    // The reserved fields measured to vary.
    for (field, at, len) in reserved_fields(&img) {
        if holes.contains(&field) {
            placed.push(Placed {
                va: at as u64,
                len: len as u64,
                kind: EntryKind::Hole,
                meta: 0,
            });
        }
    }
    placed.sort_by_key(|p| p.va);
    for (a, b) in placed.iter().zip(placed.iter().skip(1)) {
        if a.va.saturating_add(a.len) > b.va {
            return Err(format!(
                "WordOverlap: the typed words at RVA {:#x} ({:?}) and {:#x} ({:?}) overlap",
                a.va, a.kind, b.va, b.kind
            ));
        }
    }
    for p in &placed {
        if region_of(&regions, p.va, p.len).is_none_or(|r| r.kind != EntryKind::Plain) {
            return Err(format!(
                "WordOverlap: the {:?} word at RVA {:#x} does not lie in Plain bytes",
                p.kind, p.va
            ));
        }
    }
    // No typed word inside a lookup table.
    for &(l, ln) in &imports.lookups {
        if let Some(p) = placed
            .iter()
            .find(|p| p.va < l.saturating_add(ln) && l < p.va.saturating_add(p.len))
        {
            return Err(format!(
                "ImportTable: the lookup table at RVA {l:#x} overlaps a {:?} word at {:#x}",
                p.kind, p.va
            ));
        }
    }

    let entries = entries_of(&regions, &placed, 0)?;
    let typed_len: u64 = regions.iter().map(|r| r.len).sum();
    let covered: u64 = entries.iter().map(|e| u64::from(e.len)).sum();
    if covered != typed_len {
        return Err(format!(
            "the typed entries cover {covered} of {typed_len} file-backed bytes"
        ));
    }
    let ranges: Vec<Range> = regions
        .iter()
        .map(|r| -> Result<Range, String> {
            Ok(Range {
                rva: u32::try_from(r.va).map_err(|_| "an RVA exceeds 32 bits")?,
                file_off: u32::try_from(r.file_off).map_err(|_| "a file offset exceeds 32 bits")?,
                len: u32::try_from(r.len).map_err(|_| "a region exceeds 32 bits")?,
            })
        })
        .collect::<Result<_, _>>()?;
    ensure_disjoint(&ranges)?;

    // The slot must sit in a read-only section's Plain bytes.
    let slot_file_off = find_slot(bytes)?;
    let slot_sec = img
        .sections
        .iter()
        .find(|s| {
            let start = usize::try_from(s.raw_offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(s.mapped_len()).unwrap_or(0));
            s.mapped_len() > 0 && slot_fits(slot_file_off, start, end)
        })
        .ok_or("no single mapped section contains the whole integrity slot")?;
    if slot_sec.writable() {
        return Err(
            "the integrity slot is in a writable section; the loader may modify it".to_owned(),
        );
    }
    let slot_rva = u32::try_from(slot_file_off)
        .map_err(|_| "slot file offset exceeds 32 bits")?
        .checked_sub(slot_sec.raw_offset)
        .and_then(|d| slot_sec.virtual_address.checked_add(d))
        .ok_or("slot RVA overflows")?;
    let entries = slot::merge(&subtract_slot(&entries, slot_rva)?);
    let covered = slot::extent_len(&entries).ok_or("an entry overflows")?;
    if covered.saturating_add(SLOT_SIZE as u64) != typed_len {
        return Err(format!(
            "the typed entries and the slot cover {} of {typed_len} file-backed bytes",
            covered.saturating_add(SLOT_SIZE as u64)
        ));
    }
    let plain: Vec<Range> = entries
        .iter()
        .filter(|e| e.kind == EntryKind::Plain)
        .map(|e| Range {
            rva: e.rva,
            file_off: e.file_off,
            len: e.len,
        })
        .collect();
    ensure_non_empty(&plain)?;
    let file_len = if end == bytes.len() as u64 {
        file_len_of(bytes)?
    } else {
        u32::try_from(end).map_err(|_| "the certificate table offset exceeds 32 bits")?
    };
    Ok(Layout {
        ranges: plain,
        entries,
        flags: 0,
        slot_file_off,
        slot_rva,
        invariant_len: typed_len,
        mapped_len: typed_len,
        link_base: img.image_base,
        file_len,
        relative: RelativeEncoding::FileWord,
        records,
    })
}

/// Checks a signed image's slot against the image's own structures: the
/// table and records it holds must be exactly the typing of this file, with
/// the reserved fields the slot types as holes.
///
/// This is the offline check of the import typing. A thunk's file value is
/// not signature input, and the records name what the loader binds; here
/// the lookup tables, the names and the descriptors are decoded again and
/// the records they give must be the signed ones.
///
/// # Errors
///
/// `ImportMismatch` when the records differ, `FixupMismatch` naming the
/// first entry that differs, or the refusal the classifier gives the file.
pub fn check_signed(bytes: &[u8], fields: &SlotFields) -> Result<(), String> {
    let img = parse(bytes)?;
    let holes: Vec<ReservedField> = reserved_fields(&img)
        .into_iter()
        .filter(|&(_, at, len)| {
            (at..at.saturating_add(len)).all(|byte| {
                let byte = byte as u64;
                fields.entries.iter().any(|e| {
                    let start = match e.kind {
                        EntryKind::Hole => e.file_off,
                        EntryKind::Plain => e.file_off.saturating_add(e.len),
                        _ => return false,
                    };
                    e.file_end()
                        .is_some_and(|end| byte >= u64::from(start) && byte < u64::from(end))
                })
            })
        })
        .map(|(f, _, _)| f)
        .collect();
    let layout = typed(bytes, &holes)?;
    if layout.records != fields.records {
        return Err(
            "ImportMismatch: the slot's bound imports are not the ones the file's lookup tables, \
             names and descriptors give"
                .to_owned(),
        );
    }
    if layout.entries.len() != fields.entries.len() {
        return Err(format!(
            "FixupMismatch: the slot records {} entries, the file's structures give {}",
            fields.entries.len(),
            layout.entries.len()
        ));
    }
    if let Some((i, (want, got))) = fields
        .entries
        .iter()
        .zip(&layout.entries)
        .enumerate()
        .find(|(_, (a, b))| a != b)
    {
        return Err(format!(
            "FixupMismatch: entry {i} is {:?} at RVA {:#x} in the slot, {:?} at RVA {:#x} in \
             the file's structures",
            want.kind, want.rva, got.kind, got.rva
        ));
    }
    if layout.link_base != fields.link_base || layout.file_len != fields.file_len {
        return Err(
            "FixupMismatch: the slot's link base or file length is not this file's".to_owned(),
        );
    }
    Ok(())
}

/// The CodeView record an image's debug directory carries: the identity of
/// the program database the linker wrote with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeView {
    /// The PDB's GUID.
    pub guid: [u8; 16],
    /// The PDB's age.
    pub age: u32,
    /// The PDB's path as the linker recorded it.
    pub path: String,
}

/// The image's CodeView (`RSDS`) record, when its debug directory has one.
///
/// # Errors
///
/// A description when the image or its debug directory is malformed.
pub fn codeview(bytes: &[u8]) -> Result<Option<CodeView>, String> {
    let img = parse(bytes)?;
    let (rva, size) = img.dir(DIR_DEBUG);
    let start = match img.file_of(rva, size) {
        Some(s) if size > 0 => s,
        _ => return Ok(None),
    };
    let size = usize::try_from(size).map_err(|_| "debug directory overflows")?;
    let end = start.saturating_add(size);
    let mut next = start;
    while next.saturating_add(DEBUG_ENTRY_SIZE) <= end {
        let e = next;
        next = next.saturating_add(DEBUG_ENTRY_SIZE);
        if u32_at(bytes, e.saturating_add(12)) != Some(DEBUG_TYPE_CODEVIEW) {
            continue;
        }
        let len = u32_at(bytes, e.saturating_add(16)).ok_or("truncated debug directory")?;
        let at = u32_at(bytes, e.saturating_add(24)).ok_or("truncated debug directory")?;
        let at = usize::try_from(at).map_err(|_| "debug data overflows")?;
        let record = at
            .checked_add(usize::try_from(len).map_err(|_| "debug data overflows")?)
            .and_then(|end| bytes.get(at..end))
            .ok_or("the CodeView record lies past the end of the file")?;
        if record.get(..4) != Some(b"RSDS".as_slice()) || record.len() < 25 {
            continue;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(record.get(4..20).ok_or("truncated CodeView record")?);
        let age = u32_at(record, 20).ok_or("truncated CodeView record")?;
        let tail = record.get(24..).unwrap_or(&[]);
        let n = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        let path = String::from_utf8_lossy(tail.get(..n).unwrap_or(&[])).into_owned();
        return Ok(Some(CodeView { guid, age, path }));
    }
    Ok(None)
}

/// Parses `pdb`, required to be the program database the image's CodeView
/// record names: the same GUID and age.
///
/// # Errors
///
/// `StaticsUnchecked` when the image names no PDB, `pdb` is not one, or it
/// is another build's.
pub(crate) fn matching_pdb(bytes: &[u8], pdb: &[u8]) -> Result<pdb::Pdb, String> {
    let cv = codeview(bytes)?.ok_or(
        "StaticsUnchecked: the image has no CodeView debug record naming its program database",
    )?;
    let pdb = pdb::parse(pdb).map_err(|e| format!("StaticsUnchecked: the PDB: {e}"))?;
    if pdb.guid != cv.guid || pdb.age != cv.age {
        return Err(
            "StaticsUnchecked: the PDB's GUID and age are not the ones the image's CodeView \
             record names, so its symbols describe another build"
                .to_owned(),
        );
    }
    Ok(pdb)
}

/// Names every zero-initialised module static the image's file holds.
///
/// The pre-operational tests run inside module initialisation, which the
/// service gates skip once the module state says the tests have run. A
/// zero-initialised static that the loader maps from the file rather than
/// from zero-fill could be preset by an edit of the file, so an image with
/// one must not be signed.
///
/// The symbols come from `pdb`, the program database whose GUID and age are
/// the ones the image's CodeView record names. A module static is a data or
/// public symbol whose name contains `oxicrypt`, in a writable section. A
/// symbol extends to the next symbol in its section, or to the section's
/// end. It is file-backed when any of its bytes lie inside the section's
/// raw data, and zero-initialised when every such byte is zero and no
/// `DIR64` relocation writes into it. The statics [`REQUIRED_STATICS`] pins,
/// matched by their mangled path or their qualified name, are rows whenever
/// any byte is file-backed.
///
/// # Errors
///
/// `StaticsUnchecked` when no PDB is given or it is not this image's, or a
/// description when either is malformed.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the symbols; each condition sits beside the field it reads"
)]
pub fn module_statics(bytes: &[u8], pdb: Option<&[u8]>) -> Result<Statics, String> {
    let img = parse(bytes)?;
    let Some(pdb) = pdb else {
        let named = codeview(bytes)?.map_or_else(
            || "no program database: the image has no CodeView debug record".to_owned(),
            |cv| {
                format!(
                    "the program database {} was not found beside the artifact",
                    cv.path
                )
            },
        );
        return Err(format!(
            "StaticsUnchecked: {named}; link with full debug information and keep the PDB the \
             linker wrote beside the artifact"
        ));
    };
    let pdb = matching_pdb(bytes, pdb)?;
    let regions = regions(bytes, &img)?;
    let relocated = base_relocations(bytes, &img, &regions)?;
    let mut syms: Vec<(u64, usize, String)> = Vec::new();
    for s in &pdb.symbols {
        let Some(index) = usize::from(s.segment).checked_sub(1) else {
            continue;
        };
        let Some(sec) = img.sections.get(index) else {
            continue;
        };
        // A symbol outside its section names no byte the check could read,
        // so it neither counts nor finds a pinned static.
        if s.offset >= sec.virtual_size.max(sec.raw_size) {
            continue;
        }
        let rva = u64::from(sec.virtual_address).saturating_add(u64::from(s.offset));
        syms.push((rva, index, s.name.clone()));
    }
    syms.sort_by(|a, b| (a.0, &a.2).cmp(&(b.0, &b.2)));
    syms.dedup_by(|a, b| a.0 == b.0 && a.2 == b.2);

    let mut matched = 0usize;
    let mut initialised = 0usize;
    let mut rows = Vec::new();
    let mut found = [false; REQUIRED_STATICS.len()];
    for (idx, (rva, index, name)) in syms.iter().enumerate() {
        if !name.contains("oxicrypt") {
            continue;
        }
        let Some(sec) = img.sections.get(*index) else {
            continue;
        };
        if !sec.writable() {
            continue;
        }
        matched = matched.saturating_add(1);
        let mut pinned = false;
        for (seen, (path, ident, _)) in found.iter_mut().zip(REQUIRED_STATICS) {
            let is = name.contains(ident) || name == path;
            *seen |= is;
            pinned |= is;
        }
        let va = u64::from(sec.virtual_address);
        let sec_end = va.saturating_add(u64::from(sec.virtual_size.max(sec.raw_size)));
        let next = syms
            .iter()
            .skip(idx.saturating_add(1))
            .find(|(v, s, _)| s == index && v > rva)
            .map_or(sec_end, |(v, _, _)| *v);
        let size = next.saturating_sub(*rva).max(1);
        let file_end = va.saturating_add(u64::from(sec.mapped_len()));
        let backed = rva.saturating_add(size).min(file_end).saturating_sub(*rva);
        if backed == 0 {
            continue;
        }
        let off = u64::from(sec.raw_offset).saturating_add(rva.saturating_sub(va));
        let file = usize::try_from(off)
            .ok()
            .zip(usize::try_from(backed).ok())
            .and_then(|(o, n)| bytes.get(o..o.checked_add(n)?))
            .ok_or("a module static's file bytes lie past the end of the file")?;
        let written = relocated
            .iter()
            .any(|&w| w < rva.saturating_add(size) && w.saturating_add(WORD) > *rva);
        if !pinned && (written || file.iter().any(|&b| b != 0)) {
            initialised = initialised.saturating_add(1);
            continue;
        }
        rows.push(StaticRow {
            name: name.clone(),
            addr: img.image_base.saturating_add(*rva),
            size,
            file_backed: backed,
        });
    }
    let boot = links_boot_test(bytes);
    let missing = REQUIRED_STATICS
        .iter()
        .zip(found)
        .filter(|((_, _, boot_owned), seen)| !seen && (boot || !boot_owned))
        .map(|((path, _, _), _)| *path)
        .collect();
    Ok(Statics {
        matched,
        initialised,
        rows,
        missing,
    })
}

/// The ranges the loader may write to: every writable section's file-backed
/// bytes.
///
/// # Errors
///
/// Returns a description when the image is malformed.
pub fn writable_ranges(bytes: &[u8]) -> Result<Vec<Range>, String> {
    let img = parse(bytes)?;
    img.sections
        .iter()
        .filter(|s| s.writable() && s.mapped_len() > 0)
        .map(|s| {
            Ok(Range {
                rva: s.virtual_address,
                file_off: s.raw_offset,
                len: s.mapped_len(),
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // Fixture builders compute header offsets from literals chosen in this
    // same file; a wrong one fails the test it feeds rather than shipping.
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]
mod tests;
