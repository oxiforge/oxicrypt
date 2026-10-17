//! Mach-O 64-bit classification: the typed extent of a `.dylib`.
//!
//! The signer's half of the design for Darwin, outside the cryptographic
//! boundary like the rest of this crate. Every byte of every segment's file
//! extent is typed, from the loader's own structures:
//!
//! | Region | Kind |
//! |---|---|
//! | `mach_header_64`, the load-command table and its pad | `Plain`, less the envelope locator holes |
//! | `__TEXT`, and every other segment mapped read-only | `Plain` |
//! | `__DATA_CONST`, or a writable segment flagged `SG_READ_ONLY` | `Plain`; chained rebases `Relative`, chained binds `Bind` |
//! | `__LINKEDIT` up to `LC_CODE_SIGNATURE`'s `dataoff` | `Plain` |
//! | `__DATA,__thread_data` | `Plain`, fixups typed as above |
//! | `__DATA`, every other file-backed byte | `FileOnly` |
//! | `[dataoff, end of __LINKEDIT)` | the code-signature envelope, outside the signed image |
//!
//! A `Relative` word contributes its unslid value: `target`, with `high8`
//! restored in the top byte, plus the link base for
//! `DYLD_CHAINED_PTR_64_OFFSET`. A `Bind` word contributes nothing to the
//! signature; its record (the library its ordinal names, the symbol with one
//! leading `_` removed, the import's addend plus the word's, and the weak
//! flag) is in the slot's string table, which the signature covers, and the
//! module checks the loaded word against the resolver. The slot's
//! `file_len` is `dataoff`: `codesign` rewrites or grows only what lies at
//! or beyond it.
//!
//! # Envelope locator holes
//!
//! `codesign` also rewrites four fields inside the load-command table:
//! `LC_CODE_SIGNATURE`'s `dataoff` and `datasize`, and `__LINKEDIT`'s
//! `vmsize` and `filesize`. Which of them a re-sign with the final identity
//! and options changes is measured, not assumed: given the artifact `A`
//! from one such `codesign`, and this artifact from the next
//! ([`classify_with`] with `reserved_against`), each of the four fields
//! that differs becomes a `Hole`, each that does not stays `Plain`, and any
//! other difference in the header and load commands is refused. Without a
//! reference all four are `Plain`.
//!
//! # Refused by name
//!
//! `CpuType` (a CPU type other than arm64 and x86_64), `OpcodeFixups`
//! (`LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY`: the image must be
//! linked with chained fixups), `LazyPointers` (`__la_symbol_ptr`,
//! `__nl_symbol_ptr` or a lazy pointer section), `Arm64e` (the `arm64e`
//! subtype or a pointer-authenticated chain format), `PointerFormat` (any
//! chain format but `DYLD_CHAINED_PTR_64` and `DYLD_CHAINED_PTR_64_OFFSET`),
//! `SpecialOrdinal` (a bind through the image itself, the main executable,
//! flat or weak lookup), `ChainInvalid` (a chain that leaves its page or
//! segment, revisits or overlaps a word, or carries reserved bits),
//! `FixupTarget` (a fixup outside a writable segment), `ClassicRelocations`,
//! `WritableSegment` (a writable segment other than `__DATA_CONST` and
//! `__DATA`), `TableNotCovered` (a table `__LINKEDIT` holds outside its
//! `Plain` bytes), `TooManyImports` (more than 65,536 imports) and
//! `ReservationDiff`.
//!
//! # Module statics
//!
//! [`module_statics`] reads the image's own symbol table, or its dSYM's, and
//! names every module static the module must start from zero-fill whose
//! bytes the file holds; the signer refuses while that row is non-empty.
//! The linker rounds `__DATA`'s file extent up to a page, so a zero-fill
//! section that follows the last initialised byte inside that page is
//! file-backed. Placing the zero-fill sections in a segment of their own,
//! which has no file bytes at all, empties the row (see
//! `docs/integrity-signing.md`).

use oxicrypt_integrity::SLOT_SIZE;
use oxicrypt_integrity::slot::{self, BindRecord, EntryKind, Range, SlotFields};

use crate::elf::{REQUIRED_STATICS, StaticRow, Statics, links_boot_test};
use crate::image::{
    Layout, Placed, Region, RelativeEncoding, ensure_disjoint, ensure_non_empty, entries_of,
    file_len_of, find_slot, slot_fits, subtract_slot, u16_at, u32_at, u64_at,
};

/// 64-bit Mach-O, little-endian.
const MH_MAGIC_64: u32 = 0xfeed_facf;
/// 64-bit Mach-O with the opposite byte order. Recognised only so the
/// refusal can name it; a big-endian image is not classified.
const MH_CIGAM_64: u32 = 0xcffa_edfe;
/// A universal ("fat") file, as a little-endian read sees its big-endian
/// magic, and the same byte-swapped.
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_CIGAM: u32 = 0xbeba_feca;
/// The 64-bit universal file magics, read both ways.
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM_64: u32 = 0xbfba_feca;

/// `CPU_TYPE_ARM64`.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// `CPU_TYPE_X86_64`.
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// `CPU_SUBTYPE_MASK`: the capability bits above the subtype.
const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
/// `CPU_SUBTYPE_ARM64E`.
const CPU_SUBTYPE_ARM64E: u32 = 2;

/// `LC_REQ_DYLD`.
const LC_REQ_DYLD: u32 = 0x8000_0000;
/// `LC_SEGMENT`, the 32-bit segment command.
const LC_SEGMENT: u32 = 0x1;
/// `LC_SYMTAB`.
const LC_SYMTAB: u32 = 0x2;
/// `LC_DYSYMTAB`.
const LC_DYSYMTAB: u32 = 0xb;
/// `LC_LOAD_DYLIB`.
const LC_LOAD_DYLIB: u32 = 0xc;
/// `LC_LOAD_WEAK_DYLIB`.
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
/// `LC_SEGMENT_64`.
const LC_SEGMENT_64: u32 = 0x19;
/// `LC_CODE_SIGNATURE`.
const LC_CODE_SIGNATURE: u32 = 0x1d;
/// `LC_SEGMENT_SPLIT_INFO`.
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
/// `LC_REEXPORT_DYLIB`.
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
/// `LC_LAZY_LOAD_DYLIB`.
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// `LC_DYLD_INFO`.
const LC_DYLD_INFO: u32 = 0x22;
/// `LC_DYLD_INFO_ONLY`.
const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
/// `LC_LOAD_UPWARD_DYLIB`.
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
/// `LC_FUNCTION_STARTS`.
const LC_FUNCTION_STARTS: u32 = 0x26;
/// `LC_DATA_IN_CODE`.
const LC_DATA_IN_CODE: u32 = 0x29;
/// `LC_DYLIB_CODE_SIGN_DRS`.
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
/// `LC_LINKER_OPTIMIZATION_HINT`.
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
/// `LC_DYLD_EXPORTS_TRIE`.
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
/// `LC_DYLD_CHAINED_FIXUPS`.
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
/// `LC_ATOM_INFO`.
const LC_ATOM_INFO: u32 = 0x36;

/// Size of the fixed part of a `segment_command_64`, before its sections.
const SEGMENT_COMMAND_64_SIZE: usize = 72;
/// `mach_header_64` size.
const MACH_HEADER_64_SIZE: usize = 32;
/// `section_64` size.
const SECTION_64_SIZE: usize = 80;
/// `nlist_64` size.
const NLIST_64_SIZE: usize = 16;
/// `VM_PROT_WRITE`.
const VM_PROT_WRITE: u32 = 0x2;
/// `SG_READ_ONLY`: the loader makes the segment read-only after fixups.
const SG_READ_ONLY: u32 = 0x10;

/// Section types (`flags & SECTION_TYPE`).
const SECTION_TYPE: u32 = 0xff;
const S_ZEROFILL: u32 = 0x1;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_GB_ZEROFILL: u32 = 0xc;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;

/// `nlist_64.n_type` masks.
const N_STAB: u8 = 0xe0;
/// `N_STSYM`: the debug map's entry for a static symbol.
const N_STSYM: u8 = 0x26;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;

/// `DYLD_CHAINED_PTR_64`: `target` is the unslid address.
const DYLD_CHAINED_PTR_64: u16 = 2;
/// `DYLD_CHAINED_PTR_64_OFFSET`: `target` is an offset from the link base.
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// The pointer-authenticated chain formats: `ARM64E`, `ARM64E_KERNEL`,
/// `ARM64E_USERLAND`, `ARM64E_FIRMWARE`, `ARM64E_USERLAND24`,
/// `ARM64E_SHARED_CACHE`, `ARM64E_SEGMENTED`.
const ARM64E_FORMATS: [u16; 7] = [1, 7, 9, 10, 12, 13, 14];
/// `DYLD_CHAINED_PTR_START_NONE`: the page has no fixups.
const PTR_START_NONE: u16 = 0xffff;
/// `DYLD_CHAINED_PTR_START_MULTI`: a 32-bit format's multi-start page.
const PTR_START_MULTI: u16 = 0x8000;
/// The chain stride of both accepted formats, in bytes.
const CHAIN_STRIDE: u64 = 4;
/// `DYLD_CHAINED_IMPORT`, `_ADDEND`, `_ADDEND64`.
const IMPORT: u32 = 1;
const IMPORT_ADDEND: u32 = 2;
const IMPORT_ADDEND64: u32 = 3;
/// Width of a fixup word.
const WORD: u64 = 8;

/// True when `bytes` looks like a little-endian 64-bit Mach-O image.
#[must_use]
pub fn is_macho64_le(bytes: &[u8]) -> bool {
    u32_at(bytes, 0) == Some(MH_MAGIC_64)
}

/// Why `bytes` is a Mach-O this signer will not classify, if it is one.
///
/// Separated from [`is_macho64_le`] so the caller can tell "not a Mach-O at
/// all" from "a Mach-O whose shape is out of scope", and say which.
#[must_use]
pub fn unsupported_reason(bytes: &[u8]) -> Option<&'static str> {
    match u32_at(bytes, 0) {
        Some(MH_CIGAM_64) => Some("big-endian Mach-O images are not supported"),
        Some(FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64) => Some(
            "Mach-O universal files are not signed whole: sign each thin slice, then join them \
             with lipo; the module finds its own slice when it runs",
        ),
        _ => None,
    }
}

/// One `section_64`, reduced to what classification needs.
#[derive(Debug, Clone)]
struct Section {
    name: String,
    addr: u64,
    size: u64,
    kind: u32,
}

impl Section {
    /// The loader fills the section rather than reading it from the file.
    const fn zero_fill(&self) -> bool {
        matches!(
            self.kind,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }
}

/// One `LC_SEGMENT_64`, reduced to what classification needs.
#[derive(Debug, Clone)]
struct Segment {
    name: String,
    /// File offset of the load command.
    cmd_off: usize,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u32,
    flags: u32,
    sections: Vec<Section>,
}

impl Segment {
    /// The loader maps this segment writable.
    const fn writable(&self) -> bool {
        self.initprot & VM_PROT_WRITE != 0
    }

    /// A writable segment no byte of which changes after the loader's
    /// fixups: `__DATA_CONST`, or any segment the loader makes read-only
    /// once they are applied.
    fn constant(&self) -> bool {
        self.name == "__DATA_CONST" || self.flags & SG_READ_ONLY != 0
    }

    fn file_end(&self) -> Option<u64> {
        self.fileoff.checked_add(self.filesize)
    }
}

/// A `linkedit_data_command`: where in the file its table lies.
#[derive(Debug, Clone, Copy)]
struct LinkeditData {
    cmd_off: usize,
    dataoff: u64,
    datasize: u64,
}

/// A library an ordinal names.
#[derive(Debug, Clone)]
struct Dylib {
    path: String,
    /// Loaded with `LC_LOAD_WEAK_DYLIB`: a missing library binds to zero.
    weak: bool,
}

/// `LC_SYMTAB`'s tables.
#[derive(Debug, Clone, Copy)]
struct Symtab {
    symoff: u64,
    nsyms: u64,
    stroff: u64,
    strsize: u64,
}

/// What classification reads from the header and load commands.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_field_names,
    reason = "`image_base` is the format's own term, used under that name across the crate"
)]
struct Image {
    /// One past the load-command table.
    cmds_end: usize,
    /// Every `LC_SEGMENT_64`, in load-command order.
    segments: Vec<Segment>,
    /// The libraries ordinals name, in load-command order.
    dylibs: Vec<Dylib>,
    code_signature: Option<LinkeditData>,
    chained: Option<LinkeditData>,
    symtab: Option<Symtab>,
    /// Every table the loader or the module's tools read from
    /// `__LINKEDIT`, by name, offset and length.
    tables: Vec<(&'static str, u64, u64)>,
    /// The address of the segment that maps the file's start.
    image_base: u64,
}

/// The fixed-width name field at `off`, up to its first NUL.
fn name16(bytes: &[u8], off: usize) -> Result<String, String> {
    let end = off.checked_add(16).ok_or("name field overflows")?;
    let raw = bytes.get(off..end).ok_or("truncated name field")?;
    let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(raw.get(..len).unwrap_or(&[])).into_owned())
}

/// The NUL-terminated string at `off`, which must end before `end`.
fn c_string(bytes: &[u8], off: usize, end: usize) -> Result<String, String> {
    let tail = bytes
        .get(off..end)
        .ok_or("a string lies outside its table")?;
    let len = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or("a string is not terminated inside its table")?;
    let raw = tail.get(..len).ok_or("a string lies outside its table")?;
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| "a string is not UTF-8".to_owned())
}

fn usize_of(v: u64) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| "an offset exceeds usize".to_owned())
}

/// Parses the header and load commands.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the load commands; each command's refusal sits beside it"
)]
fn parse(bytes: &[u8]) -> Result<Image, String> {
    if !is_macho64_le(bytes) {
        return Err("not a little-endian 64-bit Mach-O image".to_owned());
    }
    let cputype = u32_at(bytes, 4).ok_or("truncated Mach-O header")?;
    let cpusubtype = u32_at(bytes, 8).ok_or("truncated Mach-O header")?;
    let ncmds = u32_at(bytes, 16).ok_or("truncated Mach-O header")?;
    let sizeofcmds = u32_at(bytes, 20).ok_or("truncated Mach-O header")?;
    if cputype == CPU_TYPE_ARM64 && cpusubtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E {
        return Err(
            "Arm64e: the image is arm64e; its pointers carry authentication codes that are a \
             function of where they load, so no unslid value of them can be signed"
                .to_owned(),
        );
    }
    if cputype != CPU_TYPE_ARM64 && cputype != CPU_TYPE_X86_64 {
        return Err(format!(
            "CpuType: cputype {cputype:#x} is neither arm64 nor x86_64"
        ));
    }
    let cmds_end = MACH_HEADER_64_SIZE
        .checked_add(usize::try_from(sizeofcmds).map_err(|_| "load commands exceed usize")?)
        .ok_or("load command region overflows")?;
    if cmds_end > bytes.len() {
        return Err("load commands extend past the end of the file".to_owned());
    }

    let mut img = Image {
        cmds_end,
        segments: Vec::new(),
        dylibs: Vec::new(),
        code_signature: None,
        chained: None,
        symtab: None,
        tables: Vec::new(),
        image_base: 0,
    };
    let mut off = MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        let cmd = u32_at(bytes, off).ok_or("truncated load command")?;
        let cmdsize = u32_at(bytes, off.checked_add(4).ok_or("load command overflows")?)
            .ok_or("truncated load command")?;
        let cmdsize = usize::try_from(cmdsize).map_err(|_| "load command size exceeds usize")?;
        // A zero or unaligned size would loop forever or walk off the end.
        if cmdsize < 8 || cmdsize % 8 != 0 {
            return Err(format!("load command has an implausible size of {cmdsize}"));
        }
        let next = off.checked_add(cmdsize).ok_or("load command overflows")?;
        if next > cmds_end {
            return Err("a load command extends past the load command region".to_owned());
        }
        let at = |d: usize| -> Result<usize, String> {
            off.checked_add(d)
                .ok_or_else(|| "load command field overflows".to_owned())
        };
        let field32 = |d: usize| -> Result<u64, String> {
            if d.saturating_add(4) > cmdsize {
                return Err(format!("load command {cmd:#x} is too short"));
            }
            u32_at(bytes, at(d)?)
                .map(u64::from)
                .ok_or_else(|| "truncated load command".to_owned())
        };
        match cmd {
            LC_SEGMENT => {
                return Err("a 32-bit LC_SEGMENT is not a 64-bit image's".to_owned());
            }
            LC_SEGMENT_64 => img.segments.push(segment(bytes, off, cmdsize)?),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                return Err(
                    "OpcodeFixups: the image records its fixups as dyld opcodes \
                     (LC_DYLD_INFO_ONLY); link it with -Wl,-fixup_chains so every rebase and \
                     bind is a typed chain word"
                        .to_owned(),
                );
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                let name_off = usize_of(field32(8)?)?;
                let path = c_string(bytes, at(name_off)?, next)?;
                img.dylibs.push(Dylib {
                    path,
                    weak: cmd == LC_LOAD_WEAK_DYLIB,
                });
            }
            LC_CODE_SIGNATURE
            | LC_SEGMENT_SPLIT_INFO
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_ATOM_INFO => {
                let data = LinkeditData {
                    cmd_off: off,
                    dataoff: field32(8)?,
                    datasize: field32(12)?,
                };
                let holder = match cmd {
                    LC_CODE_SIGNATURE => Some(&mut img.code_signature),
                    LC_DYLD_CHAINED_FIXUPS => Some(&mut img.chained),
                    _ => None,
                };
                if let Some(holder) = holder
                    && holder.replace(data).is_some()
                {
                    return Err(format!("load command {cmd:#x} appears twice"));
                }
                if cmd != LC_CODE_SIGNATURE {
                    img.tables
                        .push((command_name(cmd), data.dataoff, data.datasize));
                }
            }
            LC_SYMTAB => {
                let symtab = Symtab {
                    symoff: field32(8)?,
                    nsyms: field32(12)?,
                    stroff: field32(16)?,
                    strsize: field32(20)?,
                };
                if img.symtab.replace(symtab).is_some() {
                    return Err("LC_SYMTAB appears twice".to_owned());
                }
                let syms = symtab
                    .nsyms
                    .checked_mul(NLIST_64_SIZE as u64)
                    .ok_or("the symbol table overflows")?;
                img.tables.push(("LC_SYMTAB symbols", symtab.symoff, syms));
                img.tables
                    .push(("LC_SYMTAB strings", symtab.stroff, symtab.strsize));
            }
            LC_DYSYMTAB => {
                // tocoff, modtaboff, extrefsymoff, indirectsymoff,
                // extreloff, locreloff, each with its count and entry size.
                if field32(64)? != 0 || field32(72)? != 0 {
                    return Err(
                        "ClassicRelocations: LC_DYSYMTAB lists external or local relocations, \
                         which a chained-fixup image does not carry"
                            .to_owned(),
                    );
                }
                for (name, at_off, at_count, width) in [
                    ("LC_DYSYMTAB table of contents", 32, 36, 8u64),
                    ("LC_DYSYMTAB module table", 40, 44, 56),
                    ("LC_DYSYMTAB external references", 48, 52, 4),
                    ("LC_DYSYMTAB indirect symbols", 56, 60, 4),
                ] {
                    let len = field32(at_count)?
                        .checked_mul(width)
                        .ok_or("an LC_DYSYMTAB table overflows")?;
                    img.tables.push((name, field32(at_off)?, len));
                }
            }
            _ => {}
        }
        off = next;
    }

    // The image base is the address of the segment that maps the file's
    // start, the one carrying the Mach header.
    img.image_base = img
        .segments
        .iter()
        .find(|s| s.fileoff == 0 && s.filesize > 0)
        .map(|s| s.vmaddr)
        .ok_or("no file-backed segment maps the start of the file, so there is no image base")?;
    Ok(img)
}

/// The name of a `linkedit_data_command`, for a refusal.
const fn command_name(cmd: u32) -> &'static str {
    match cmd {
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS",
        LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT",
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        LC_ATOM_INFO => "LC_ATOM_INFO",
        _ => "a linkedit data command",
    }
}

/// Parses the `LC_SEGMENT_64` at `off` and its sections.
fn segment(bytes: &[u8], off: usize, cmdsize: usize) -> Result<Segment, String> {
    if cmdsize < SEGMENT_COMMAND_64_SIZE {
        return Err("LC_SEGMENT_64 is shorter than its fixed fields".to_owned());
    }
    let at = |d: usize| -> Result<usize, String> {
        off.checked_add(d)
            .ok_or_else(|| "segment field overflows".to_owned())
    };
    let nsects = u32_at(bytes, at(64)?).ok_or("truncated segment command")?;
    let nsects = usize::try_from(nsects).map_err(|_| "section count exceeds usize")?;
    let needed = nsects
        .checked_mul(SECTION_64_SIZE)
        .and_then(|t| t.checked_add(SEGMENT_COMMAND_64_SIZE))
        .ok_or("section table overflows")?;
    if needed > cmdsize {
        return Err(format!(
            "LC_SEGMENT_64 declares {nsects} sections but is only {cmdsize} bytes"
        ));
    }
    let mut sections = Vec::with_capacity(nsects);
    for i in 0..nsects {
        let base = i
            .checked_mul(SECTION_64_SIZE)
            .and_then(|s| s.checked_add(SEGMENT_COMMAND_64_SIZE))
            .and_then(|s| off.checked_add(s))
            .ok_or("section offset overflows")?;
        let field = |d: usize| base.checked_add(d).ok_or("section field overflows");
        sections.push(Section {
            name: name16(bytes, base)?,
            addr: u64_at(bytes, field(32)?).ok_or("truncated section")?,
            size: u64_at(bytes, field(40)?).ok_or("truncated section")?,
            kind: u32_at(bytes, field(64)?).ok_or("truncated section")? & SECTION_TYPE,
        });
    }
    Ok(Segment {
        name: name16(bytes, at(8)?)?,
        cmd_off: off,
        vmaddr: u64_at(bytes, at(24)?).ok_or("truncated segment command")?,
        vmsize: u64_at(bytes, at(32)?).ok_or("truncated segment command")?,
        fileoff: u64_at(bytes, at(40)?).ok_or("truncated segment command")?,
        filesize: u64_at(bytes, at(48)?).ok_or("truncated segment command")?,
        initprot: u32_at(bytes, at(60)?).ok_or("truncated segment command")?,
        flags: u32_at(bytes, at(68)?).ok_or("truncated segment command")?,
        sections,
    })
}

/// One of the four header fields `codesign` may rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LocatorField {
    /// `LC_CODE_SIGNATURE`'s `dataoff`.
    DataOff,
    /// `LC_CODE_SIGNATURE`'s `datasize`.
    DataSize,
    /// `__LINKEDIT`'s `vmsize`.
    VmSize,
    /// `__LINKEDIT`'s `filesize`.
    FileSize,
}

impl LocatorField {
    /// The field's name, as a refusal or a report spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DataOff => "LC_CODE_SIGNATURE.dataoff",
            Self::DataSize => "LC_CODE_SIGNATURE.datasize",
            Self::VmSize => "__LINKEDIT.vmsize",
            Self::FileSize => "__LINKEDIT.filesize",
        }
    }
}

/// Where each locator field the image has lies in the file, and its width.
fn locator_fields(img: &Image) -> Vec<(LocatorField, usize, usize)> {
    let mut out = Vec::new();
    if let Some(cs) = img.code_signature {
        out.push((LocatorField::DataOff, cs.cmd_off.saturating_add(8), 4));
        out.push((LocatorField::DataSize, cs.cmd_off.saturating_add(12), 4));
    }
    if let Some(le) = img.segments.iter().find(|s| s.name == "__LINKEDIT") {
        out.push((LocatorField::VmSize, le.cmd_off.saturating_add(32), 8));
        out.push((LocatorField::FileSize, le.cmd_off.saturating_add(48), 8));
    }
    out
}

/// The locator fields `codesign` rewrote between `reference`, the artifact
/// one `codesign` with the final identity and options produced, and
/// `bytes`, the artifact the next such `codesign` produced.
///
/// # Errors
///
/// `ReservationDiff` when any byte of the header and load commands outside
/// the four fields differs, or the two lay the fields out differently; a
/// description when either is malformed.
pub fn reservation_holes(reference: &[u8], bytes: &[u8]) -> Result<Vec<LocatorField>, String> {
    let a = parse(reference).map_err(|e| format!("the reference: {e}"))?;
    let b = parse(bytes)?;
    let (fa, fb) = (locator_fields(&a), locator_fields(&b));
    if a.cmds_end != b.cmds_end || fa != fb {
        return Err(
            "ReservationDiff: the reference's header and load commands are not laid out like \
             this artifact's; it must be the same build, code-signed with the final identity \
             and options"
                .to_owned(),
        );
    }
    let ra = reference
        .get(..a.cmds_end)
        .ok_or("the reference is truncated")?;
    let rb = bytes.get(..b.cmds_end).ok_or("the artifact is truncated")?;
    let mut changed: Vec<LocatorField> = Vec::new();
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
                    "ReservationDiff: byte {i:#x} of the header and load commands differs from \
                     the reference outside the four envelope locator fields"
                )
            })?;
        if !changed.contains(&field) {
            changed.push(field);
        }
    }
    changed.sort();
    Ok(changed)
}

/// One chained fixup: where it is, and the import a bind names.
#[derive(Debug, Clone)]
struct Fixup {
    va: u64,
    bind: Option<BindRecord>,
}

/// The chain format the image uses, and its fixups, without classifying.
///
/// # Errors
///
/// A description, beginning with the refusal's name, when the image's
/// chains are refused.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the chain starts; each field's refusal sits beside the field"
)]
fn chained_fixups(bytes: &[u8], img: &Image) -> Result<(RelativeEncoding, Vec<Fixup>), String> {
    let Some(cf) = img.chained else {
        return Ok((RelativeEncoding::FileWord, Vec::new()));
    };
    let start = usize_of(cf.dataoff)?;
    let blob = start
        .checked_add(usize_of(cf.datasize)?)
        .and_then(|end| bytes.get(start..end))
        .ok_or("LC_DYLD_CHAINED_FIXUPS lies past the end of the file")?;
    let hdr = |d: usize| -> Result<u32, String> {
        u32_at(blob, d).ok_or_else(|| "truncated chained fixups header".to_owned())
    };
    if hdr(0)? != 0 {
        return Err("ChainInvalid: unknown chained fixups version".to_owned());
    }
    let starts_offset = usize_of(u64::from(hdr(4)?))?;
    let imports = Imports {
        blob,
        dylibs: &img.dylibs,
        offset: usize_of(u64::from(hdr(8)?))?,
        symbols: usize_of(u64::from(hdr(12)?))?,
        count: hdr(16)?,
        format: hdr(20)?,
    };
    if !matches!(imports.format, IMPORT | IMPORT_ADDEND | IMPORT_ADDEND64) {
        return Err(format!(
            "ChainInvalid: import format {} is not DYLD_CHAINED_IMPORT, _ADDEND or _ADDEND64",
            imports.format
        ));
    }
    if hdr(24)? != 0 {
        return Err("ChainInvalid: compressed chained fixup symbols are not read".to_owned());
    }
    let seg_count = u32_at(blob, starts_offset).ok_or("truncated chained starts")?;
    if usize::try_from(seg_count).ok() != Some(img.segments.len()) {
        return Err(format!(
            "ChainInvalid: the chain starts name {seg_count} segments, the image has {}",
            img.segments.len()
        ));
    }

    let mut format: Option<u16> = None;
    let mut out: Vec<Fixup> = Vec::new();
    for (i, seg) in img.segments.iter().enumerate() {
        let entry = i
            .checked_mul(4)
            .and_then(|o| o.checked_add(4))
            .and_then(|o| o.checked_add(starts_offset))
            .ok_or("chained starts overflow")?;
        let seg_info = u32_at(blob, entry).ok_or("truncated chained starts")?;
        if seg_info == 0 {
            continue;
        }
        let sis = starts_offset
            .checked_add(usize_of(u64::from(seg_info))?)
            .ok_or("chained starts overflow")?;
        let field = |d: usize| sis.checked_add(d).ok_or("chained starts overflow");
        let size = u32_at(blob, field(0)?).ok_or("truncated segment starts")?;
        let page_size = u16_at(blob, field(4)?).ok_or("truncated segment starts")?;
        let pointer_format = u16_at(blob, field(6)?).ok_or("truncated segment starts")?;
        let segment_offset = u64_at(blob, field(8)?).ok_or("truncated segment starts")?;
        let page_count = u16_at(blob, field(20)?).ok_or("truncated segment starts")?;
        if ARM64E_FORMATS.contains(&pointer_format) {
            return Err(format!(
                "Arm64e: segment {} uses the pointer-authenticated chain format {pointer_format}, \
                 whose loaded words are a function of where they load",
                seg.name
            ));
        }
        if pointer_format != DYLD_CHAINED_PTR_64 && pointer_format != DYLD_CHAINED_PTR_64_OFFSET {
            return Err(format!(
                "PointerFormat: segment {} uses chain format {pointer_format}; only \
                 DYLD_CHAINED_PTR_64 and DYLD_CHAINED_PTR_64_OFFSET are typed",
                seg.name
            ));
        }
        if format.is_some_and(|f| f != pointer_format) {
            return Err("PointerFormat: segments use different chain formats".to_owned());
        }
        format = Some(pointer_format);
        if segment_offset != seg.vmaddr.wrapping_sub(img.image_base) {
            return Err(format!(
                "ChainInvalid: segment {}'s chain starts give it offset {segment_offset:#x}, its \
                 load command {:#x}",
                seg.name,
                seg.vmaddr.wrapping_sub(img.image_base)
            ));
        }
        if page_size != 0x1000 && page_size != 0x4000 {
            return Err(format!(
                "ChainInvalid: segment {} has chain page size {page_size:#x}",
                seg.name
            ));
        }
        let table_end = usize::from(page_count)
            .checked_mul(2)
            .and_then(|t| t.checked_add(22))
            .ok_or("segment starts overflow")?;
        if usize_of(u64::from(size))? < table_end || field(table_end)? > blob.len() {
            return Err(format!(
                "ChainInvalid: segment {}'s page table runs past its starts",
                seg.name
            ));
        }
        for page in 0..page_count {
            let at = field(22)?
                .checked_add(usize::from(page).saturating_mul(2))
                .ok_or("segment starts overflow")?;
            let first = u16_at(blob, at).ok_or("truncated page starts")?;
            if first == PTR_START_NONE {
                continue;
            }
            if first & PTR_START_MULTI != 0 {
                return Err(format!(
                    "ChainInvalid: segment {} page {page} uses a multi-start page, a 32-bit form",
                    seg.name
                ));
            }
            let page_start = u64::from(page)
                .checked_mul(u64::from(page_size))
                .ok_or("chain offset overflows")?;
            let page_end = page_start
                .checked_add(u64::from(page_size))
                .ok_or("chain offset overflows")?;
            walk(
                bytes,
                seg,
                &imports,
                page_start.saturating_add(u64::from(first)),
                page_end,
                &mut out,
            )?;
        }
    }
    let encoding = match format {
        Some(DYLD_CHAINED_PTR_64_OFFSET) => RelativeEncoding::ChainedPtr64Offset,
        _ => RelativeEncoding::ChainedPtr64,
    };
    out.sort_by_key(|f| f.va);
    for (a, b) in out.iter().zip(out.iter().skip(1)) {
        if a.va.saturating_add(WORD) > b.va {
            return Err(format!(
                "ChainInvalid: the chains visit the word at {:#x} twice, or it overlaps the one \
                 at {:#x}",
                a.va, b.va
            ));
        }
    }
    Ok((encoding, out))
}

/// Follows one page's chain from `offset` in `seg`, appending each fixup.
fn walk(
    bytes: &[u8],
    seg: &Segment,
    imports: &Imports<'_>,
    mut offset: u64,
    page_end: u64,
    out: &mut Vec<Fixup>,
) -> Result<(), String> {
    loop {
        if offset >= page_end {
            return Err(format!(
                "ChainInvalid: a chain in segment {} leaves its page at offset {offset:#x}",
                seg.name
            ));
        }
        if offset.saturating_add(WORD) > seg.filesize {
            return Err(format!(
                "ChainInvalid: a chain in segment {} reaches offset {offset:#x}, outside the \
                 segment's file bytes",
                seg.name
            ));
        }
        let va = seg
            .vmaddr
            .checked_add(offset)
            .ok_or("fixup address overflows")?;
        let file_at = seg
            .fileoff
            .checked_add(offset)
            .ok_or("fixup offset overflows")?;
        let raw = u64_at(bytes, usize_of(file_at)?)
            .ok_or("a chain word lies past the end of the file")?;
        let bind = if raw >> 63 == 0 {
            if (raw >> 44) & 0x7f != 0 {
                return Err(format!(
                    "ChainInvalid: the rebase at {va:#x} sets reserved bits"
                ));
            }
            None
        } else {
            if (raw >> 32) & 0x7_ffff != 0 {
                return Err(format!(
                    "ChainInvalid: the bind at {va:#x} sets reserved bits"
                ));
            }
            let index = u32::try_from(raw & 0xff_ffff).map_err(|_| "bind ordinal overflows")?;
            let in_word = i64::try_from((raw >> 24) & 0xff).map_err(|_| "addend overflows")?;
            let mut record = imports.get(index, va)?;
            record.addend = record
                .addend
                .checked_add(in_word)
                .ok_or("a bind's addend overflows")?;
            Some(record)
        };
        out.push(Fixup { va, bind });
        let next = (raw >> 51) & 0xfff;
        if next == 0 {
            return Ok(());
        }
        offset = offset
            .checked_add(next.saturating_mul(CHAIN_STRIDE))
            .ok_or("chain offset overflows")?;
    }
}

/// The chained import table.
struct Imports<'a> {
    blob: &'a [u8],
    dylibs: &'a [Dylib],
    offset: usize,
    symbols: usize,
    count: u32,
    format: u32,
}

impl Imports<'_> {
    /// The record of import `index`, which the bind at `va` names.
    fn get(&self, index: u32, va: u64) -> Result<BindRecord, String> {
        if index >= self.count {
            return Err(format!(
                "ChainInvalid: the bind at {va:#x} names import {index} of {}",
                self.count
            ));
        }
        let width: usize = match self.format {
            IMPORT => 4,
            IMPORT_ADDEND => 8,
            _ => 16,
        };
        let at = usize_of(u64::from(index))?
            .checked_mul(width)
            .and_then(|o| o.checked_add(self.offset))
            .ok_or("import offset overflows")?;
        let (ordinal, special, weak, name_off, addend) = if self.format == IMPORT_ADDEND64 {
            let raw = u64_at(self.blob, at).ok_or("truncated import table")?;
            let addend = u64_at(self.blob, at.saturating_add(8)).ok_or("truncated import table")?;
            let ordinal = raw & 0xffff;
            (
                ordinal,
                ordinal == 0 || ordinal >= 0xfff0,
                (raw >> 16) & 1 != 0,
                raw >> 32,
                i64::from_le_bytes(addend.to_le_bytes()),
            )
        } else {
            let raw = u64::from(u32_at(self.blob, at).ok_or("truncated import table")?);
            let addend = if self.format == IMPORT_ADDEND {
                i64::from(i32::from_le_bytes(
                    u32_at(self.blob, at.saturating_add(4))
                        .ok_or("truncated import table")?
                        .to_le_bytes(),
                ))
            } else {
                0
            };
            let ordinal = raw & 0xff;
            (
                ordinal,
                ordinal == 0 || ordinal >= 0xf0,
                (raw >> 8) & 1 != 0,
                raw >> 9,
                addend,
            )
        };
        let name_at = self
            .symbols
            .checked_add(usize_of(name_off)?)
            .ok_or("import name offset overflows")?;
        let name = c_string(self.blob, name_at, self.blob.len())?;
        if special {
            return Err(format!(
                "SpecialOrdinal: the bind at {va:#x} imports {name} through special ordinal \
                 {ordinal:#x} (this image, the main executable, flat or weak lookup), which the \
                 module cannot resolve by library"
            ));
        }
        let dylib = usize_of(ordinal)
            .ok()
            .and_then(|o| o.checked_sub(1))
            .and_then(|o| self.dylibs.get(o))
            .ok_or_else(|| {
                format!(
                    "ChainInvalid: the bind at {va:#x} names library ordinal {ordinal}, of {}",
                    self.dylibs.len()
                )
            })?;
        let symbol = name.strip_prefix('_').ok_or_else(|| {
            format!(
                "ChainInvalid: the bind at {va:#x} imports {name}, which has no leading `_` for \
                 the resolver to remove"
            )
        })?;
        Ok(BindRecord {
            library: dylib.path.clone(),
            symbol: symbol.to_owned(),
            ordinal: 0,
            addend,
            weak: weak || dylib.weak,
        })
    }
}

/// The chain encoding an image's `Relative` words use: the one thing the
/// offline check needs before it has authenticated the image.
///
/// # Errors
///
/// A description when the image or its chains are malformed.
pub fn relative_encoding(bytes: &[u8]) -> Result<RelativeEncoding, String> {
    let img = parse(bytes)?;
    Ok(chained_fixups(bytes, &img)?.0)
}

/// Derives the typed extent of a Mach-O 64-bit image, with the four
/// envelope locator fields `Plain`.
///
/// # Errors
///
/// Returns a description, beginning with the refusal's name where one
/// applies, when the image is malformed, uses a structure the typing does
/// not describe, or the slot is missing or ambiguous.
pub fn classify(bytes: &[u8]) -> Result<Layout, String> {
    classify_with(bytes, None)
}

/// [`classify`], with each envelope locator field that differs between
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

/// The regions every file-backed byte of `img` falls in, ascending, and
/// where the signed image ends.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the segments; each segment kind's typing sits beside its refusal"
)]
fn regions(bytes: &[u8], img: &Image) -> Result<(Vec<Region>, u64), String> {
    let file_end = bytes.len() as u64;
    let linkedit = img.segments.iter().find(|s| s.name == "__LINKEDIT");
    let signed_end = match (img.code_signature, linkedit) {
        (Some(cs), Some(le)) => {
            let le_end = le.file_end().ok_or("__LINKEDIT's file extent overflows")?;
            if cs.dataoff < le.fileoff || cs.dataoff.saturating_add(cs.datasize) > le_end {
                return Err(
                    "the code signature does not lie inside __LINKEDIT's file extent".to_owned(),
                );
            }
            cs.dataoff
        }
        (Some(_), None) => {
            return Err("the image has a code signature but no __LINKEDIT".to_owned());
        }
        (None, _) => file_end,
    };
    for &(name, off, len) in &img.tables {
        if len == 0 {
            continue;
        }
        let inside = linkedit.is_some_and(|le| {
            off >= le.fileoff && off.checked_add(len).is_some_and(|end| end <= signed_end)
        });
        if !inside {
            return Err(format!(
                "TableNotCovered: {name} at file offset {off:#x} does not lie in __LINKEDIT's \
                 Plain bytes"
            ));
        }
    }

    let mut out = Vec::new();
    for seg in img.segments.iter().filter(|s| s.filesize > 0) {
        let end = seg.file_end().ok_or("a segment's file extent overflows")?;
        if end > file_end {
            return Err(format!(
                "segment {}'s file extent runs past the end of the file",
                seg.name
            ));
        }
        if seg.filesize > seg.vmsize {
            return Err(format!(
                "segment {} has more file bytes than memory",
                seg.name
            ));
        }
        for s in &seg.sections {
            if s.name == "__la_symbol_ptr"
                || s.name == "__nl_symbol_ptr"
                || matches!(
                    s.kind,
                    S_LAZY_SYMBOL_POINTERS | S_LAZY_DYLIB_SYMBOL_POINTERS
                )
            {
                return Err(format!(
                    "LazyPointers: {},{} holds lazily bound pointers, which the loader rewrites \
                     on first call; link with -Wl,-fixup_chains and without lazy binding",
                    seg.name, s.name
                ));
            }
        }
        let mut push = |from_va: u64, to_va: u64, kind: EntryKind| {
            if to_va > from_va {
                out.push(Region {
                    va: from_va,
                    len: to_va.saturating_sub(from_va),
                    file_off: seg
                        .fileoff
                        .saturating_add(from_va.saturating_sub(seg.vmaddr)),
                    kind,
                    writable: seg.writable(),
                });
            }
        };
        let seg_end_va = seg.vmaddr.saturating_add(seg.filesize);
        if !seg.writable() {
            let end_va = if seg.name == "__LINKEDIT" {
                seg.vmaddr
                    .saturating_add(signed_end.saturating_sub(seg.fileoff).min(seg.filesize))
            } else {
                seg_end_va
            };
            push(seg.vmaddr, end_va, EntryKind::Plain);
        } else if seg.constant() {
            push(seg.vmaddr, seg_end_va, EntryKind::Plain);
        } else if seg.name == "__DATA" {
            // FileOnly, except the thread-local template, which the module
            // never writes.
            let mut cursor = seg.vmaddr;
            let mut tdata: Vec<&Section> = seg
                .sections
                .iter()
                .filter(|s| s.kind == S_THREAD_LOCAL_REGULAR && s.size > 0)
                .collect();
            tdata.sort_by_key(|s| s.addr);
            for s in tdata {
                let lo = s.addr.clamp(cursor, seg_end_va);
                let hi = s.addr.saturating_add(s.size).clamp(lo, seg_end_va);
                push(cursor, lo, EntryKind::FileOnly);
                push(lo, hi, EntryKind::Plain);
                cursor = hi;
            }
            push(cursor, seg_end_va, EntryKind::FileOnly);
        } else {
            return Err(format!(
                "WritableSegment: {} is writable and is neither __DATA_CONST nor __DATA, so no \
                 typing describes it",
                seg.name
            ));
        }
    }
    out.sort_by_key(|r| r.va);
    Ok((out, signed_end))
}

/// The typed extent, with `holes` among the locator fields.
#[allow(
    clippy::too_many_lines,
    reason = "one linear derivation; each refusal sits beside the structure it reads"
)]
fn typed(bytes: &[u8], holes: &[LocatorField]) -> Result<Layout, String> {
    let img = parse(bytes)?;
    let header_seg = img
        .segments
        .iter()
        .find(|s| s.fileoff == 0 && s.filesize > 0)
        .ok_or("no file-backed segment maps the start of the file")?;
    if header_seg.writable() || header_seg.filesize < img.cmds_end as u64 {
        return Err(
            "the header and load commands do not lie in a read-only segment mapping the file's \
             start"
                .to_owned(),
        );
    }
    let (regions, signed_end) = regions(bytes, &img)?;
    let (relative, fixups) = chained_fixups(bytes, &img)?;

    // Place each fixup: kept in Plain bytes of a writable segment, dropped
    // in FileOnly bytes, refused anywhere else.
    let mut words: Vec<(u64, EntryKind, Option<BindRecord>)> = Vec::new();
    for f in fixups {
        let end = f.va.checked_add(WORD).ok_or("a fixup address overflows")?;
        let region = regions
            .iter()
            .find(|r| f.va >= r.va && f.va < r.end())
            .ok_or_else(|| {
                format!(
                    "FixupTarget: the fixup at {:#x} lies outside the image's typed bytes",
                    f.va
                )
            })?;
        if end > region.end() {
            return Err(format!(
                "FixupTarget: the fixup at {:#x} straddles the end of its region",
                f.va
            ));
        }
        if !region.writable {
            return Err(format!(
                "FixupTarget: the fixup at {:#x} writes a read-only segment",
                f.va
            ));
        }
        if region.kind == EntryKind::FileOnly {
            continue;
        }
        let kind = if f.bind.is_some() {
            EntryKind::Bind
        } else {
            EntryKind::Relative
        };
        words.push((f.va, kind, f.bind));
    }
    // The locator fields measured to vary, as holes; adjacent ones are one
    // hole, so the table stays canonical.
    let mut hole_spans: Vec<(u64, u64)> = Vec::new();
    for (field, at, len) in locator_fields(&img) {
        if !holes.contains(&field) {
            continue;
        }
        let va = header_seg
            .vmaddr
            .checked_add(at as u64)
            .ok_or("a locator field overflows")?;
        match hole_spans.last_mut() {
            Some((start, n)) if start.saturating_add(*n) == va => {
                *n = n.saturating_add(len as u64);
            }
            _ => hole_spans.push((va, len as u64)),
        }
    }

    // Records in order of first use, one per distinct import.
    let mut records: Vec<BindRecord> = Vec::new();
    let mut placed: Vec<Placed> = Vec::new();
    for (va, kind, bind) in words {
        let meta = match bind {
            Some(record) => {
                let index = if let Some(i) = records.iter().position(|r| *r == record) {
                    i
                } else {
                    records.push(record);
                    records.len().saturating_sub(1)
                };
                u16::try_from(index).map_err(|_| "TooManyImports: more than 65,536 imports")?
            }
            None => 0,
        };
        placed.push(Placed {
            va,
            len: WORD,
            kind,
            meta,
        });
    }
    for (va, len) in hole_spans {
        placed.push(Placed {
            va,
            len,
            kind: EntryKind::Hole,
            meta: 0,
        });
    }
    placed.sort_by_key(|p| p.va);
    for (a, b) in placed.iter().zip(placed.iter().skip(1)) {
        if a.va.saturating_add(a.len) > b.va {
            return Err(format!(
                "FixupTarget: the words at {:#x} and {:#x} overlap",
                a.va, b.va
            ));
        }
    }

    let entries = entries_of(&regions, &placed, img.image_base)?;
    let typed_len: u64 = regions.iter().map(|r| r.len).sum();
    let candidate_len: u64 = entries.iter().map(|e| u64::from(e.len)).sum();
    if candidate_len != typed_len {
        return Err(format!(
            "the typed entries cover {candidate_len} of {typed_len} file-backed bytes"
        ));
    }
    let ranges: Vec<Range> = regions
        .iter()
        .map(|r| -> Result<Range, String> {
            Ok(Range {
                rva: u32::try_from(r.va.wrapping_sub(img.image_base))
                    .map_err(|_| "an RVA exceeds 32 bits")?,
                file_off: u32::try_from(r.file_off).map_err(|_| "a file offset exceeds 32 bits")?,
                len: u32::try_from(r.len).map_err(|_| "a region exceeds 32 bits")?,
            })
        })
        .collect::<Result<_, _>>()?;
    ensure_disjoint(&ranges)?;

    // The slot, in both coordinate spaces; it must sit in a read-only
    // segment's Plain bytes.
    let slot_file_off = find_slot(bytes)?;
    let slot_seg = img
        .segments
        .iter()
        .find(|s| {
            let start = usize::try_from(s.fileoff).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(s.filesize).unwrap_or(0));
            slot_fits(slot_file_off, start, end)
        })
        .ok_or("no single segment contains the whole integrity slot")?;
    if slot_seg.writable() {
        return Err(
            "the integrity slot is in a writable segment; the loader may modify it".to_owned(),
        );
    }
    let slot_rva_u64 = slot_seg
        .vmaddr
        .checked_sub(img.image_base)
        .and_then(|v| v.checked_add((slot_file_off as u64).checked_sub(slot_seg.fileoff)?))
        .ok_or("slot RVA overflows")?;
    let slot_rva = u32::try_from(slot_rva_u64).map_err(|_| "slot RVA exceeds 32 bits")?;
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
    let file_len = if signed_end == bytes.len() as u64 {
        file_len_of(bytes)?
    } else {
        u32::try_from(signed_end).map_err(|_| "dataoff exceeds 32 bits")?
    };

    Ok(Layout {
        ranges: plain,
        entries,
        flags: 0,
        slot_file_off,
        slot_rva,
        invariant_len: typed_len,
        mapped_len: img.segments.iter().map(|s| s.filesize).sum(),
        link_base: img.image_base,
        file_len,
        relative,
        records,
    })
}

/// Checks a signed image's slot against the image's own chained fixups:
/// the table and records it records must be exactly the typing of this
/// file, with the locator fields the slot types as holes.
///
/// This is the offline check of every `Bind` and `Relative` word's
/// encoding. A `Bind` word's ordinal and addend, a chain's `next` and a
/// word's bind bit are not signature input; they are checked here by
/// decoding each chain word against the record and kind the signed table
/// gives it, and requiring the words the chains visit outside `FileOnly`
/// bytes to be exactly the `Relative` and `Bind` entries.
///
/// # Errors
///
/// `FixupMismatch` naming the first difference, or the refusal the
/// classifier gives the file.
pub fn check_signed(bytes: &[u8], fields: &SlotFields) -> Result<(), String> {
    let img = parse(bytes)?;
    let holes: Vec<LocatorField> = locator_fields(&img)
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
    if layout.entries.len() != fields.entries.len() {
        return Err(format!(
            "FixupMismatch: the slot records {} entries, the file's chained fixups give {}",
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
             the file's chained fixups",
            want.kind, want.rva, got.kind, got.rva
        ));
    }
    if layout.records != fields.records {
        return Err(
            "FixupMismatch: the slot's bound imports are not the ones the file's chain words \
             name"
                .to_owned(),
        );
    }
    if layout.link_base != fields.link_base || layout.file_len != fields.file_len {
        return Err(
            "FixupMismatch: the slot's link base or file length is not this file's".to_owned(),
        );
    }
    Ok(())
}

/// `LC_UUID`.
const LC_UUID: u32 = 0x1b;

/// The `LC_UUID` and `LC_SYMTAB` of a Mach-O file read only for its
/// symbols, such as a dSYM, whose segments carry no file bytes.
fn symbol_source(bytes: &[u8]) -> Result<(Option<[u8; 16]>, Option<Symtab>), String> {
    if !is_macho64_le(bytes) {
        return Err("StaticsUnchecked: the dSYM is not a 64-bit Mach-O file".to_owned());
    }
    let ncmds = u32_at(bytes, 16).ok_or("truncated Mach-O header")?;
    let mut uuid = None;
    let mut symtab = None;
    let mut off = MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        let cmd = u32_at(bytes, off).ok_or("truncated load command")?;
        let cmdsize = u32_at(bytes, off.saturating_add(4)).ok_or("truncated load command")?;
        let field = |d: usize| -> Result<u64, String> {
            u32_at(bytes, off.saturating_add(d))
                .map(u64::from)
                .ok_or_else(|| "truncated load command".to_owned())
        };
        match cmd {
            LC_UUID => {
                let raw = bytes
                    .get(off.saturating_add(8)..off.saturating_add(24))
                    .ok_or("truncated LC_UUID")?;
                let mut id = [0u8; 16];
                id.copy_from_slice(raw);
                uuid = Some(id);
            }
            LC_SYMTAB => {
                symtab = Some(Symtab {
                    symoff: field(8)?,
                    nsyms: field(12)?,
                    stroff: field(16)?,
                    strsize: field(20)?,
                });
            }
            _ => {}
        }
        if cmdsize < 8 {
            return Err("a load command has an implausible size".to_owned());
        }
        off = off
            .checked_add(usize::try_from(cmdsize).map_err(|_| "load command size exceeds usize")?)
            .ok_or("load command overflows")?;
    }
    Ok((uuid, symtab))
}

/// The image's `LC_UUID`, which its dSYM carries too.
///
/// # Errors
///
/// A description when the image is malformed.
pub fn image_uuid(bytes: &[u8]) -> Result<Option<[u8; 16]>, String> {
    Ok(symbol_source(bytes)?.0)
}

/// Names every zero-initialised module static the image's file holds.
///
/// The pre-operational tests run inside module initialisation, which the
/// service gates skip once the module state says the tests have run. A
/// zero-initialised static that the loader maps from the file rather than
/// from zero-fill could be preset by an edit of the file, so an image with
/// one must not be signed.
///
/// A module static is a symbol defined in a section, whose name contains
/// `oxicrypt`, in a writable segment that is not constant after fixups.
/// Mach-O symbols carry no size: one extends to the next symbol in its
/// section, or to the section's end. It is file-backed when any of its
/// bytes lie below its segment's file size, and zero-initialised when its
/// section is zero-fill, or every such byte is zero and no fixup writes into
/// it. The statics [`REQUIRED_STATICS`] pins are rows whenever any byte is
/// file-backed.
///
/// # Errors
///
/// `StaticsUnchecked` when the image has no symbol table, or a description
/// when it is malformed.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the symbol table; each condition sits beside the field it reads"
)]
pub fn module_statics(bytes: &[u8], symbols: Option<&[u8]>) -> Result<Statics, String> {
    let img = parse(bytes)?;
    let (_, fixups) = chained_fixups(bytes, &img)?;
    // The symbol table is the image's own, or that of a dSYM whose UUID is
    // the image's.
    let (src, symtab) = match symbols {
        None => (bytes, img.symtab),
        Some(dsym) => {
            let (uuid, symtab) = symbol_source(dsym)?;
            if uuid.is_none() || uuid != image_uuid(bytes)? {
                return Err(
                    "StaticsUnchecked: the dSYM's LC_UUID is not the artifact's, so its symbols \
                     describe another build"
                        .to_owned(),
                );
            }
            (dsym, symtab)
        }
    };
    let symtab = symtab.filter(|s| s.nsyms > 0).ok_or(
        "StaticsUnchecked: the symbol source has no symbol table; keep the dSYM cargo writes \
         with split-debuginfo beside the artifact",
    )?;
    let sections: Vec<(&Segment, &Section)> = img
        .segments
        .iter()
        .flat_map(|seg| seg.sections.iter().map(move |s| (seg, s)))
        .collect();
    let bytes_of_symbols = src;
    let str_start = usize_of(symtab.stroff)?;
    let str_end = str_start
        .checked_add(usize_of(symtab.strsize)?)
        .filter(|&e| e <= bytes_of_symbols.len())
        .ok_or("the string table runs past the end of the file")?;
    let mut syms: Vec<(u64, usize, String)> = Vec::new();
    for i in 0..symtab.nsyms {
        let at = i
            .checked_mul(NLIST_64_SIZE as u64)
            .and_then(|o| o.checked_add(symtab.symoff))
            .ok_or("the symbol table overflows")?;
        let at = usize_of(at)?;
        let src = bytes_of_symbols;
        let strx = u32_at(src, at).ok_or("truncated symbol table")?;
        let n_type = *src
            .get(at.saturating_add(4))
            .ok_or("truncated symbol table")?;
        let n_sect = *src
            .get(at.saturating_add(5))
            .ok_or("truncated symbol table")?;
        let value = u64_at(src, at.saturating_add(8)).ok_or("truncated symbol table")?;
        // A symbol defined in a section, or the debug map's record of a
        // static (`N_STSYM`), which is how a dSYM names a local static.
        let defined = n_type & N_STAB == 0 && n_type & N_TYPE == N_SECT;
        if !(defined || n_type == N_STSYM) || n_sect == 0 {
            continue;
        }
        let name_at = str_start
            .checked_add(usize_of(u64::from(strx))?)
            .ok_or("a symbol name offset overflows")?;
        let name = c_string(src, name_at, str_end).unwrap_or_default();
        // The section by address in the image, which a dSYM's section
        // numbering need not follow.
        let Some(index) = sections
            .iter()
            .position(|(_, s)| value >= s.addr && value < s.addr.saturating_add(s.size))
        else {
            continue;
        };
        syms.push((value, index.saturating_add(1), name));
    }
    // The debug map and the symbol table may both name a static.
    syms.sort_by(|a, b| (a.0, &a.2).cmp(&(b.0, &b.2)));
    syms.dedup_by(|a, b| a.0 == b.0 && a.2 == b.2);

    let mut matched = 0usize;
    let mut initialised = 0usize;
    let mut rows = Vec::new();
    let mut found = [false; REQUIRED_STATICS.len()];
    for (idx, (value, n_sect, name)) in syms.iter().enumerate() {
        if !name.contains("oxicrypt") {
            continue;
        }
        let Some(&(seg, sect)) = n_sect.checked_sub(1).and_then(|i| sections.get(i)) else {
            continue;
        };
        if !seg.writable() || seg.constant() {
            continue;
        }
        matched = matched.saturating_add(1);
        let mut pinned = false;
        for (seen, (_, ident, _)) in found.iter_mut().zip(REQUIRED_STATICS) {
            let is = name.contains(ident);
            *seen |= is;
            pinned |= is;
        }
        let sect_end = sect.addr.saturating_add(sect.size);
        let next = syms
            .iter()
            .skip(idx.saturating_add(1))
            .find(|(v, s, _)| s == n_sect && v > value)
            .map_or(sect_end, |(v, _, _)| *v);
        let size = next.saturating_sub(*value).max(1);
        let file_end = seg.vmaddr.saturating_add(seg.filesize);
        let backed = value
            .saturating_add(size)
            .min(file_end)
            .saturating_sub(*value);
        if backed == 0 {
            continue;
        }
        let off = seg.fileoff.saturating_add(value.saturating_sub(seg.vmaddr));
        let file = usize::try_from(off)
            .ok()
            .zip(usize::try_from(backed).ok())
            .and_then(|(o, n)| bytes.get(o..o.checked_add(n)?))
            .ok_or("a module static's file bytes lie past the end of the file")?;
        let relocated = fixups
            .iter()
            .any(|f| f.va < value.saturating_add(size) && f.va.saturating_add(WORD) > *value);
        let nonzero = !sect.zero_fill() && file.iter().any(|&b| b != 0);
        if !pinned && (relocated || nonzero) {
            initialised = initialised.saturating_add(1);
            continue;
        }
        rows.push(StaticRow {
            name: name.clone(),
            addr: *value,
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
    clippy::cast_sign_loss,
    clippy::integer_division,
    // One knob per shape the fixture can take, and one builder laying
    // the whole image out in file order.
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]
pub(crate) mod tests;
