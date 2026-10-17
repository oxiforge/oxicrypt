//! ELF64 classification: the typed extent of an image loaded by glibc or
//! bionic.
//!
//! This is the *signer's* half of the design, and it is deliberately
//! outside the cryptographic boundary. Format knowledge (what a program
//! header is, which words a loader writes) lives here and nowhere else. The
//! module itself reads only the typed table this module produces.
//!
//! # The rule
//!
//! Every file-backed byte of every `PT_LOAD`, `[p_offset, p_offset +
//! p_filesz)`, is covered by exactly one entry, except the integrity slot.
//! Bytes past `p_filesz` are zero-fill, not file bytes, and are not covered.
//! The kinds are assigned from the loader's own structures, `PT_DYNAMIC` and
//! the relocation tables it names, never from section headers:
//!
//! | Bytes | Kind |
//! |---|---|
//! | read-only `PT_LOAD`s, including the ELF and program headers | `Plain` |
//! | `PT_GNU_RELRO`'s file-backed bytes | `Plain`, except the words below |
//! | `RELA` and `JMPREL` destinations in RELRO | `Hole` (16 bytes for `TLSDESC`) |
//! | `RELR` destinations in RELRO (glibc only) | `Relative` |
//! | `.dynamic` `d_val` of `DT_DEBUG` | `Hole` |
//! | `.dynamic` pointer `d_val`s glibc adjusts in place | `Relative` |
//! | every other file-backed byte of a writable `PT_LOAD` | `FileOnly` |
//!
//! A `RELA` destination's file word is not what the loader writes: the value
//! is the addend, and the word itself is commonly zero. Such a word is a
//! `Hole`, and the relocation table that produces it is `Plain`, so the
//! word's value is covered by effect. `Relative` is used only where the file
//! word is the unslid address the loader adds the load bias to: a `RELR`
//! destination and an adjusted `.dynamic` pointer. The verifier subtracts
//! the slide from the loaded word, which then equals the file word.
//!
//! glibc adds the load bias to the `d_val` of `DT_HASH`, `DT_PLTGOT`,
//! `DT_STRTAB`, `DT_SYMTAB`, `DT_RELA`, `DT_REL`, `DT_JMPREL`, `DT_VERSYM`,
//! `DT_GNU_HASH` and `DT_RELR` when `PT_DYNAMIC` is writable; bionic adjusts
//! none. The loader is inferred from the `.note.android.ident` note (bionic
//! when present) and may be overridden, and is recorded in the slot's flags.
//!
//! Inside a `FileOnly` range no other entry is emitted: the verifier hashes
//! the image file's bytes there, whatever the loader or the module has since
//! written.
//!
//! # Refusals
//!
//! Each refusal begins with its name. An artifact is refused when it uses a
//! structure the typing above does not describe: `UnsupportedType` (an ELF
//! type that is not a loadable image), `UnsupportedMachine` (a machine other
//! than x86-64 and AArch64), `WritableExecutable` (a `PT_LOAD` both writable
//! and executable), `NoDynamic` (no `PT_DYNAMIC`), `PackedRelocations`
//! (APS2, `DT_ANDROID_REL`/`DT_ANDROID_RELA`), `RelrOnBionic` (any `RELR`
//! table when the loader is bionic), `AndroidRelr` (`DT_ANDROID_RELR` under
//! glibc), `PltRewrite` (the x86-64 PLT-rewrite tags `-z mark-plt` emits),
//! `LazyBinding` (no `BIND_NOW`), `TextRelocations`, `RelForm` (`REL`-form
//! relocations), `RelocationType` (a type outside the accepted set),
//! `CopyRelocation`, `RelocationTarget` (a destination in read-only bytes, in
//! `.dynamic`, or outside the image), `RelocationOverlap`, `DynamicPlacement`
//! (`PT_DYNAMIC` outside typed bytes, or its `PF_W` disagreeing with its
//! segment's), `DynamicStrtab` (the `SHT_DYNAMIC` section's string table is
//! not exactly `[DT_STRTAB, DT_STRTAB + DT_STRSZ)`; bionic reads it),
//! `WeakTlsRelocation` (under glibc, a TLS relocation whose symbol is
//! undefined and weak, which glibc may leave unwritten), and `TableNotCovered` (a table
//! `.dynamic` names lies outside `Plain` bytes).
//!
//! The file-backed module statics check ([`module_statics`]) is separate,
//! because it needs a symbol table that a stripped artifact no longer has.

use oxicrypt_integrity::SLOT_SIZE;
use oxicrypt_integrity::slot::{Entry, EntryKind, FLAG_LOADER_BIONIC, Range};

use crate::image::{
    Layout, Placed, Region, RelativeEncoding, ensure_disjoint, ensure_non_empty, entries_of,
    file_len_of, find_slot, slot_fits, subtract_slot, u16_at, u32_at, u64_at,
};

/// `p_type` of a loadable segment.
const PT_LOAD: u32 = 1;
/// `p_type` of the dynamic segment.
const PT_DYNAMIC: u32 = 2;
/// `p_type` of a note segment.
const PT_NOTE: u32 = 4;
/// `p_type` of the region made read-only after relocation.
const PT_GNU_RELRO: u32 = 0x6474_e552;
/// `p_flags` bit marking a segment writable.
const PF_W: u32 = 0x2;

/// `e_type` of an executable.
const ET_EXEC: u16 = 2;
/// `e_type` of a shared object or position-independent executable.
const ET_DYN: u16 = 3;
/// `e_machine` of x86-64.
const EM_X86_64: u16 = 62;
/// `e_machine` of AArch64.
const EM_AARCH64: u16 = 183;

const DT_NULL: u64 = 0;
const DT_PLTRELSZ: u64 = 2;
const DT_PLTGOT: u64 = 3;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_STRSZ: u64 = 10;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_RELENT: u64 = 19;
const DT_PLTREL: u64 = 20;
const DT_DEBUG: u64 = 21;
const DT_TEXTREL: u64 = 22;
const DT_JMPREL: u64 = 23;
const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_RELRENT: u64 = 37;
const DT_ANDROID_REL: u64 = 0x6000_000f;
const DT_ANDROID_RELSZ: u64 = 0x6000_0010;
const DT_ANDROID_RELA: u64 = 0x6000_0011;
const DT_ANDROID_RELASZ: u64 = 0x6000_0012;
const DT_ANDROID_RELR: u64 = 0x6fff_e000;
const DT_ANDROID_RELRSZ: u64 = 0x6fff_e001;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_VERSYM: u64 = 0x6fff_fff0;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// `DT_FLAGS` bit: the object has text relocations.
const DF_TEXTREL: u64 = 0x4;
/// `DT_FLAGS` bit: bind every symbol at load.
const DF_BIND_NOW: u64 = 0x8;
/// `DT_FLAGS_1` bit: bind every symbol at load.
const DF_1_NOW: u64 = 0x1;
/// `DT_FLAGS_1` bit: the object is a position-independent executable.
const DF_1_PIE: u64 = 0x0800_0000;
/// The x86-64 PLT-rewrite tags `-z mark-plt` emits (binutils
/// `include/elf/x86-64.h`: `DT_LOPROC + 0`, `+ 1` and `+ 3`). The same values
/// mean other things on AArch64.
const DT_X86_64_PLT: u64 = 0x7000_0000;
const DT_X86_64_PLTSZ: u64 = 0x7000_0001;
const DT_X86_64_PLTENT: u64 = 0x7000_0003;
/// `p_flags` bit marking a segment executable.
const PF_X: u32 = 0x1;

/// Section type of a symbol table.
const SHT_SYMTAB: u32 = 2;
/// Section type of the dynamic section.
const SHT_DYNAMIC: u32 = 6;

/// One `Elf64_Rela` record.
const RELA_SIZE: u64 = 24;
/// One `Elf64_Dyn` record.
const DYN_SIZE: usize = 16;
/// One `Elf64_Sym` record.
const SYM_SIZE: usize = 24;

/// The `.dynamic` tags whose `d_val` glibc adds the load bias to in place
/// whenever the tag is present, zero or not (`elf/get-dynamic-info.h`,
/// the first `ADJUST_DYN_INFO`, which tests only `info[tag] != NULL`).
const GLIBC_ADJUSTED: [u64; 8] = [
    DT_HASH,
    DT_PLTGOT,
    DT_STRTAB,
    DT_SYMTAB,
    DT_RELR,
    DT_JMPREL,
    DT_VERSYM,
    DT_GNU_HASH,
];

/// The `.dynamic` tags glibc adjusts only when their value is non-zero (the
/// second `ADJUST_DYN_INFO`, which also tests `d_ptr != 0`).
const GLIBC_ADJUSTED_NONZERO: [u64; 2] = [DT_RELA, DT_REL];

/// `p_type` of the program interpreter: present in an executable, which
/// glibc treats as its main program.
const PT_INTERP: u32 = 3;

/// The `.dynamic` tags the classifier or a loader reads one value of; a
/// second occurrence would leave two readings of the same table.
const SINGLE_TAGS: [u64; 28] = [
    DT_PLTRELSZ,
    DT_PLTGOT,
    DT_HASH,
    DT_STRTAB,
    DT_SYMTAB,
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_STRSZ,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_PLTREL,
    DT_DEBUG,
    DT_JMPREL,
    DT_FLAGS,
    DT_RELRSZ,
    DT_RELR,
    DT_RELRENT,
    DT_ANDROID_REL,
    DT_ANDROID_RELSZ,
    DT_ANDROID_RELA,
    DT_ANDROID_RELASZ,
    DT_ANDROID_RELR,
    DT_ANDROID_RELRSZ,
    DT_GNU_HASH,
    DT_VERSYM,
    DT_FLAGS_1,
];

/// The dynamic loader an image is typed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    /// GNU C library: adjusts `.dynamic` pointers in place, applies `RELR`.
    Glibc,
    /// Android's bionic: adjusts no `.dynamic` word.
    Bionic,
}

impl Loader {
    /// The loader a command-line name selects.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "glibc" => Some(Self::Glibc),
            "bionic" => Some(Self::Bionic),
            _ => None,
        }
    }

    /// The slot flags that record this loader.
    #[must_use]
    pub const fn slot_flags(self) -> u32 {
        match self {
            Self::Glibc => 0,
            Self::Bionic => FLAG_LOADER_BIONIC,
        }
    }
}

/// True when `bytes` looks like a little-endian 64-bit ELF image.
#[must_use]
pub fn is_elf64_le(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(b"\x7fELF".as_slice())
        && bytes.get(4) == Some(&2)
        && bytes.get(5) == Some(&1)
}

/// One program header, reduced to what classification needs.
#[derive(Debug, Clone, Copy)]
struct Phdr {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

impl Phdr {
    const fn writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    fn file_end(&self) -> Option<u64> {
        self.vaddr.checked_add(self.filesz)
    }

    fn mem_end(&self) -> Option<u64> {
        self.vaddr.checked_add(self.memsz)
    }
}

/// The program headers of an image and what they imply.
struct Headers {
    machine: u16,
    /// The image is an executable (`ET_EXEC`, or a `PT_INTERP` naming its
    /// loader), the main program rather than a library.
    executable: bool,
    phdrs: Vec<Phdr>,
    /// The `PT_LOAD`s, ascending by address.
    loads: Vec<Phdr>,
    image_base: u64,
}

fn headers(bytes: &[u8]) -> Result<Headers, String> {
    if !is_elf64_le(bytes) {
        return Err("not a little-endian 64-bit ELF image".to_owned());
    }
    let e_type = u16_at(bytes, 0x10).ok_or("truncated ELF header")?;
    if e_type != ET_DYN && e_type != ET_EXEC {
        return Err(format!(
            "UnsupportedType: ELF type {e_type} is not a loadable image"
        ));
    }
    let machine = u16_at(bytes, 0x12).ok_or("truncated ELF header")?;
    if machine != EM_X86_64 && machine != EM_AARCH64 {
        return Err(format!(
            "UnsupportedMachine: ELF machine {machine} is not x86-64 or AArch64"
        ));
    }
    let phoff = u64_at(bytes, 0x20).ok_or("truncated ELF header")?;
    let phentsize = usize::from(u16_at(bytes, 0x36).ok_or("truncated ELF header")?);
    let phnum = usize::from(u16_at(bytes, 0x38).ok_or("truncated ELF header")?);
    if phentsize < 56 {
        return Err(format!(
            "program header entry size {phentsize} is too small"
        ));
    }
    let phoff = usize::try_from(phoff).map_err(|_| "program header offset out of range")?;
    let mut phdrs = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let base = i
            .checked_mul(phentsize)
            .and_then(|o| o.checked_add(phoff))
            .ok_or("program header table overflows")?;
        let field = |off: usize| u64_at(bytes, base.saturating_add(off));
        phdrs.push(Phdr {
            p_type: u32_at(bytes, base).ok_or("truncated program header")?,
            flags: u32_at(bytes, base.saturating_add(4)).ok_or("truncated program header")?,
            offset: field(8).ok_or("truncated program header")?,
            vaddr: field(16).ok_or("truncated program header")?,
            filesz: field(32).ok_or("truncated program header")?,
            memsz: field(40).ok_or("truncated program header")?,
            align: field(48).ok_or("truncated program header")?,
        });
    }
    let mut loads: Vec<Phdr> = phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .copied()
        .collect();
    if loads.is_empty() {
        return Err("image has no PT_LOAD segments".to_owned());
    }
    loads.sort_by_key(|p| p.vaddr);
    for p in &loads {
        let end = p
            .offset
            .checked_add(p.filesz)
            .ok_or("segment file extent overflows")?;
        if usize::try_from(end).map_or(true, |e| e > bytes.len()) {
            return Err("segment extends past the end of the file".to_owned());
        }
        if p.filesz > p.memsz {
            return Err("a segment's file size exceeds its memory size".to_owned());
        }
        p.mem_end().ok_or("segment address range overflows")?;
    }
    for (a, b) in loads.iter().zip(loads.iter().skip(1)) {
        if a.mem_end().unwrap_or(u64::MAX) > b.vaddr {
            return Err(format!(
                "two PT_LOAD segments overlap in address space at {:#x}",
                b.vaddr
            ));
        }
    }
    let image_base = loads.first().map_or(0, |p| p.vaddr);
    let executable = e_type == ET_EXEC || phdrs.iter().any(|p| p.p_type == PT_INTERP);
    Ok(Headers {
        machine,
        executable,
        phdrs,
        loads,
        image_base,
    })
}

impl Headers {
    /// The file offset of `[va, va + len)`, when one `PT_LOAD` holds it in
    /// its file-backed bytes.
    fn file_offset(&self, va: u64, len: u64) -> Option<u64> {
        let end = va.checked_add(len)?;
        self.loads
            .iter()
            .find(|p| va >= p.vaddr && p.file_end().is_some_and(|e| end <= e))
            .and_then(|p| p.offset.checked_add(va.wrapping_sub(p.vaddr)))
    }

    fn one(&self, p_type: u32) -> Result<Option<Phdr>, String> {
        let mut found = self.phdrs.iter().filter(|p| p.p_type == p_type);
        let first = found.next().copied();
        if found.next().is_some() {
            return Err(format!(
                "the image has more than one segment of type {p_type:#x}"
            ));
        }
        Ok(first)
    }
}

/// The loader an image declares: bionic when a note segment carries the
/// `Android` ident note, glibc otherwise.
///
/// # Errors
///
/// Returns a description when the image or a note segment is malformed.
pub fn inferred_loader(bytes: &[u8]) -> Result<Loader, String> {
    let h = headers(bytes)?;
    for p in h.phdrs.iter().filter(|p| p.p_type == PT_NOTE) {
        let start = usize::try_from(p.offset).map_err(|_| "note segment out of range")?;
        let len = usize::try_from(p.filesz).map_err(|_| "note segment out of range")?;
        let end = start.checked_add(len).ok_or("note segment overflows")?;
        let notes = bytes
            .get(start..end)
            .ok_or("note segment past end of file")?;
        let align = if p.align == 8 { 8 } else { 4 };
        let mut at = 0usize;
        while at.saturating_add(12) <= notes.len() {
            let namesz = u32_at(notes, at).ok_or("truncated note")? as usize;
            let descsz = u32_at(notes, at.saturating_add(4)).ok_or("truncated note")? as usize;
            let n_type = u32_at(notes, at.saturating_add(8)).ok_or("truncated note")?;
            let name_at = at.saturating_add(12);
            let name = notes
                .get(name_at..name_at.saturating_add(namesz))
                .ok_or("a note's name runs past its segment")?;
            if n_type == 1 && name == b"Android\0" {
                return Ok(Loader::Bionic);
            }
            let desc_at = name_at
                .checked_add(namesz)
                .and_then(|v| v.checked_next_multiple_of(align))
                .ok_or("note overflows")?;
            at = desc_at
                .checked_add(descsz)
                .and_then(|v| v.checked_next_multiple_of(align))
                .ok_or("note overflows")?;
        }
    }
    Ok(Loader::Glibc)
}

/// `.dynamic`, parsed from the file.
struct Dynamic {
    phdr: Phdr,
    /// `(tag, value)` up to, not including, `DT_NULL`.
    entries: Vec<(u64, u64)>,
    /// Byte offset of the `DT_NULL` entry within the segment.
    null_at: u64,
}

impl Dynamic {
    fn get(&self, tag: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, v)| *v)
    }

    fn has(&self, tag: u64) -> bool {
        self.entries.iter().any(|(t, _)| *t == tag)
    }
}

fn dynamic(bytes: &[u8], h: &Headers) -> Result<Dynamic, String> {
    let phdr = h
        .one(PT_DYNAMIC)?
        .ok_or("NoDynamic: the image has no PT_DYNAMIC segment")?;
    let start = usize::try_from(phdr.offset).map_err(|_| "PT_DYNAMIC out of range")?;
    let len = usize::try_from(phdr.filesz).map_err(|_| "PT_DYNAMIC out of range")?;
    let seg = start
        .checked_add(len)
        .and_then(|end| bytes.get(start..end))
        .ok_or("PT_DYNAMIC runs past the end of the file")?;
    if h.file_offset(phdr.vaddr, phdr.filesz) != Some(phdr.offset) {
        return Err(
            "DynamicPlacement: PT_DYNAMIC's file bytes are not where its PT_LOAD maps them"
                .to_owned(),
        );
    }
    let mut entries = Vec::new();
    let mut null_at = None;
    for (i, record) in seg.chunks_exact(DYN_SIZE).enumerate() {
        let tag = u64_at(record, 0).ok_or("truncated .dynamic")?;
        let val = u64_at(record, 8).ok_or("truncated .dynamic")?;
        if tag == DT_NULL {
            null_at = Some(i.saturating_mul(DYN_SIZE) as u64);
            break;
        }
        if SINGLE_TAGS.contains(&tag) && entries.iter().any(|(t, _)| *t == tag) {
            return Err(format!(".dynamic carries tag {tag:#x} twice"));
        }
        entries.push((tag, val));
    }
    let null_at = null_at.ok_or(".dynamic has no DT_NULL entry")?;
    Ok(Dynamic {
        phdr,
        entries,
        null_at,
    })
}

/// The accepted relocation types and the width each writes.
fn relocation_width(machine: u16, r_type: u32) -> Result<u64, String> {
    let (copy, accepted, tlsdesc): (u32, &[u32], u32) = if machine == EM_X86_64 {
        (5, &[1, 6, 7, 8, 16, 17, 18, 37], 36)
    } else {
        (1024, &[257, 1025, 1026, 1027, 1028, 1029, 1030, 1032], 1031)
    };
    if r_type == tlsdesc {
        Ok(16)
    } else if accepted.contains(&r_type) {
        Ok(8)
    } else if r_type == copy {
        Err("CopyRelocation: a copy relocation reached the width table".to_owned())
    } else {
        Err(format!(
            "RelocationType: relocation type {r_type} is outside the accepted set"
        ))
    }
}

/// Whether `r_type` is the machine's copy relocation.
fn is_copy(machine: u16, r_type: u32) -> bool {
    r_type == if machine == EM_X86_64 { 5 } else { 1024 }
}

/// Dynamic symbol `index`'s record, from the table `DT_SYMTAB` names.
fn dyn_symbol<'a>(
    bytes: &'a [u8],
    h: &Headers,
    d: &Dynamic,
    index: u64,
) -> Result<&'a [u8], String> {
    let symtab = d
        .get(DT_SYMTAB)
        .ok_or("a relocation names a symbol, and .dynamic has no DT_SYMTAB")?;
    let at = index
        .checked_mul(SYM_SIZE as u64)
        .and_then(|o| symtab.checked_add(o))
        .ok_or("a relocation's symbol index overflows")?;
    table(bytes, h, "a dynamic symbol", at, SYM_SIZE as u64)
}

/// Whether the loader leaves a relocation's destination unwritten when its
/// symbol does not resolve: glibc's `DTPMOD64`, `DTPOFF64` and `TPOFF64`
/// (and the AArch64 `TLS_DTPMOD`, `TLS_DTPREL`, `TLS_TPREL`) write only
/// `if (sym != NULL)` or `if (sym_map != NULL)` (`sysdeps/x86_64/dl-machine.h`,
/// `sysdeps/aarch64/dl-machine.h`). Every other accepted type writes a value
/// whether or not the symbol resolved.
fn skipped_without_symbol(machine: u16, r_type: u32) -> bool {
    if machine == EM_X86_64 {
        matches!(r_type, 16..=18)
    } else {
        matches!(r_type, 1028..=1030)
    }
}

/// Refuses a relocation glibc may skip whose symbol is undefined and weak:
/// when the symbol does not resolve, the file's word stays in memory, so the
/// word is neither a hole nor reliably the file's value. Called for glibc
/// only.
fn refuse_weak_undefined(
    bytes: &[u8],
    h: &Headers,
    d: &Dynamic,
    index: u64,
    r_offset: u64,
) -> Result<(), String> {
    if index == 0 {
        return Ok(());
    }
    let sym = dyn_symbol(bytes, h, d, index)?;
    let st_info = *sym.get(4).ok_or("truncated dynamic symbol")?;
    let st_shndx = u16_at(sym, 6).ok_or("truncated dynamic symbol")?;
    if st_shndx == 0 && st_info >> 4 == 2 {
        return Err(format!(
            "WeakTlsRelocation: the TLS relocation at {r_offset:#x} names an undefined weak \
             symbol, so the loader leaves its word unwritten when the symbol is absent"
        ));
    }
    Ok(())
}

/// A word the loader writes, and how it is typed.
#[derive(Debug, Clone, Copy)]
struct Word {
    va: u64,
    len: u64,
    kind: EntryKind,
    /// A relocation destination, as opposed to a `.dynamic` value.
    relocation: bool,
    /// A copy relocation's destination, `len` being the symbol's size.
    copy: bool,
}

/// The bytes of the table `.dynamic` names at `tag`, `size` bytes long.
fn table<'a>(
    bytes: &'a [u8],
    h: &Headers,
    name: &str,
    va: u64,
    size: u64,
) -> Result<&'a [u8], String> {
    let off = h
        .file_offset(va, size)
        .ok_or_else(|| format!("TableNotCovered: {name} at {va:#x} is not in the file's bytes"))?;
    let start = usize::try_from(off).map_err(|_| "table offset out of range")?;
    let end = start
        .checked_add(usize::try_from(size).map_err(|_| "table size out of range")?)
        .ok_or("table overflows")?;
    bytes
        .get(start..end)
        .ok_or_else(|| format!("{name} runs past the end of the file"))
}

/// The refusals `.dynamic` alone decides.
fn refuse_unsupported(d: &Dynamic, loader: Loader, machine: u16) -> Result<(), String> {
    if machine == EM_X86_64
        && (d.has(DT_X86_64_PLT) || d.has(DT_X86_64_PLTSZ) || d.has(DT_X86_64_PLTENT))
    {
        return Err(
            "PltRewrite: the image carries the x86-64 PLT-rewrite tags (DT_X86_64_PLT), which \
             let glibc rewrite the PLT's code at load; link without -z mark-plt"
                .to_owned(),
        );
    }
    if d.has(DT_ANDROID_REL) || d.has(DT_ANDROID_RELA) {
        return Err(
            "PackedRelocations: the image uses APS2 packed relocations (DT_ANDROID_REL or \
             DT_ANDROID_RELA); link without --pack-dyn-relocs=android"
                .to_owned(),
        );
    }
    let relr = d.has(DT_RELR) || d.has(DT_ANDROID_RELR);
    if loader == Loader::Bionic && relr {
        return Err(
            "RelrOnBionic: the image packs relative relocations as RELR, which the Android \
             typing does not accept; link without --pack-dyn-relocs=relr"
                .to_owned(),
        );
    }
    if d.has(DT_ANDROID_RELR) {
        return Err(
            "AndroidRelr: DT_ANDROID_RELR is applied only by bionic, and the image is typed for \
             glibc"
                .to_owned(),
        );
    }
    let flags = d.get(DT_FLAGS).unwrap_or(0);
    let flags_1 = d.get(DT_FLAGS_1).unwrap_or(0);
    if d.has(DT_TEXTREL) || flags & DF_TEXTREL != 0 {
        return Err("TextRelocations: the image relocates its read-only text".to_owned());
    }
    if !(d.has(DT_BIND_NOW) || flags & DF_BIND_NOW != 0 || flags_1 & DF_1_NOW != 0) {
        return Err(
            "LazyBinding: the image is not linked with BIND_NOW (-z now), so the loader would \
             write lazy-binding words at first call"
                .to_owned(),
        );
    }
    let pltrel_not_rela = d.get(DT_JMPREL).is_some() && d.get(DT_PLTREL) != Some(DT_RELA);
    if d.has(DT_REL) || d.has(DT_RELSZ) || d.has(DT_RELENT) || pltrel_not_rela {
        return Err("RelForm: the image uses REL-form relocations".to_owned());
    }
    if d.get(DT_RELAENT).is_some_and(|e| e != RELA_SIZE) {
        return Err("DT_RELAENT is not the size of an Elf64_Rela".to_owned());
    }
    if d.get(DT_RELRENT).is_some_and(|e| e != 8) {
        return Err("DT_RELRENT is not 8".to_owned());
    }
    Ok(())
}

/// Every word the loader writes, from the relocation tables and `.dynamic`.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the loader's structures; each word's typing sits beside its source"
)]
fn loader_words(
    bytes: &[u8],
    h: &Headers,
    d: &Dynamic,
    loader: Loader,
) -> Result<Vec<Word>, String> {
    let mut words = Vec::new();
    for (name, tab_tag, size_tag) in [
        ("DT_RELA", DT_RELA, DT_RELASZ),
        ("DT_JMPREL", DT_JMPREL, DT_PLTRELSZ),
    ] {
        let Some(va) = d.get(tab_tag) else { continue };
        let size = d
            .get(size_tag)
            .ok_or_else(|| format!("{name} has no size tag"))?;
        if size % RELA_SIZE != 0 {
            return Err(format!("{name} ends in a partial record"));
        }
        for record in table(bytes, h, name, va, size)?.chunks_exact(24) {
            let r_offset = u64_at(record, 0).ok_or("truncated relocation")?;
            let r_info = u64_at(record, 8).ok_or("truncated relocation")?;
            let r_type = (r_info & 0xffff_ffff) as u32;
            if is_copy(h.machine, r_type) {
                // glibc copies MIN (sym->st_size, refsym->st_size) bytes, and
                // nothing when the symbol is absent (`dl-machine.h`, case
                // R_X86_64_COPY / R_AARCH64_COPY); bionic refuses to load an
                // object with one. A destination in zero-fill is no file
                // byte and needs no entry; one in file bytes is refused.
                if loader == Loader::Bionic {
                    return Err(
                        "CopyRelocation: the image carries a copy relocation, which bionic \
                         refuses to load"
                            .to_owned(),
                    );
                }
                let size = dyn_symbol(bytes, h, d, r_info >> 32)
                    .and_then(|sym| u64_at(sym, 16).ok_or_else(|| "truncated symbol".to_owned()))?;
                words.push(Word {
                    va: r_offset,
                    len: size.max(1),
                    kind: EntryKind::Hole,
                    relocation: true,
                    copy: true,
                });
                continue;
            }
            let len = relocation_width(h.machine, r_type)?;
            // bionic writes the destination whether or not the symbol
            // resolves (zero when it does not), so there it is a hole.
            if loader == Loader::Glibc && skipped_without_symbol(h.machine, r_type) {
                refuse_weak_undefined(bytes, h, d, r_info >> 32, r_offset)?;
            }
            words.push(Word {
                va: r_offset,
                len,
                kind: EntryKind::Hole,
                relocation: true,
                copy: false,
            });
        }
    }
    if let Some(va) = d.get(DT_RELR) {
        let size = d.get(DT_RELRSZ).ok_or("DT_RELR has no DT_RELRSZ")?;
        if size % 8 != 0 {
            return Err("DT_RELR ends in a partial entry".to_owned());
        }
        let mut next = 0u64;
        for entry in table(bytes, h, "DT_RELR", va, size)?.chunks_exact(8) {
            let v = u64_at(entry, 0).ok_or("truncated RELR entry")?;
            if v & 1 == 0 {
                words.push(Word {
                    va: v,
                    len: 8,
                    kind: EntryKind::Relative,
                    relocation: true,
                    copy: false,
                });
                next = v.checked_add(8).ok_or("a RELR address overflows")?;
            } else {
                for bit in 1..64u64 {
                    if (v >> bit) & 1 != 0 {
                        let at = next
                            .checked_add(bit.saturating_sub(1).saturating_mul(8))
                            .ok_or("a RELR bitmap address overflows")?;
                        words.push(Word {
                            va: at,
                            len: 8,
                            kind: EntryKind::Relative,
                            relocation: true,
                            copy: false,
                        });
                    }
                }
                next = next
                    .checked_add(63 * 8)
                    .ok_or("a RELR bitmap address overflows")?;
            }
        }
    }
    // `.dynamic` values. DT_DEBUG is overwritten without being read, but
    // only where the loader writes it: glibc for its main program alone
    // (`elf/rtld.c`, `elf_setup_debug_entry (main_map, r)`, and the same call
    // in `elf/dl-reloc-static-pie.c` for a static PIE, which `DF_1_PIE` marks
    // as an executable without a `PT_INTERP`), bionic for any object whose
    // PT_DYNAMIC is writable (`linker.cpp`, `case DT_DEBUG`).
    // The pointer values glibc adjusts are the unslid address plus the bias.
    let adjusts = loader == Loader::Glibc && d.phdr.writable();
    let debug_written = match loader {
        Loader::Glibc => h.executable || d.get(DT_FLAGS_1).unwrap_or(0) & DF_1_PIE != 0,
        Loader::Bionic => d.phdr.writable(),
    };
    for (i, (tag, val)) in d.entries.iter().enumerate() {
        let va = d
            .phdr
            .vaddr
            .checked_add((i as u64).saturating_mul(DYN_SIZE as u64))
            .and_then(|v| v.checked_add(8))
            .ok_or(".dynamic address overflows")?;
        let adjusted =
            GLIBC_ADJUSTED.contains(tag) || (*val != 0 && GLIBC_ADJUSTED_NONZERO.contains(tag));
        let kind = if *tag == DT_DEBUG && debug_written {
            EntryKind::Hole
        } else if adjusts && adjusted {
            EntryKind::Relative
        } else {
            continue;
        };
        words.push(Word {
            va,
            len: 8,
            kind,
            relocation: false,
            copy: false,
        });
    }
    words.sort_by_key(|w| w.va);
    Ok(words)
}

/// Splits every `PT_LOAD`'s file-backed bytes into `Plain` and `FileOnly`
/// regions: read-only segments and RELRO are `Plain`, the rest of a writable
/// segment is `FileOnly`.
fn regions(h: &Headers, relro: Option<(u64, u64)>) -> Vec<Region> {
    let mut out = Vec::new();
    for p in h.loads.iter().filter(|p| p.filesz > 0) {
        let end = p.vaddr.saturating_add(p.filesz);
        let mut push = |from: u64, to: u64, kind: EntryKind| {
            if to > from {
                out.push(Region {
                    va: from,
                    len: to.saturating_sub(from),
                    file_off: p.offset.saturating_add(from.saturating_sub(p.vaddr)),
                    kind,
                    writable: p.writable(),
                });
            }
        };
        if !p.writable() {
            push(p.vaddr, end, EntryKind::Plain);
            continue;
        }
        let (rs, re) = relro.unwrap_or((0, 0));
        let lo = rs.clamp(p.vaddr, end);
        let hi = re.clamp(lo, end);
        push(p.vaddr, lo, EntryKind::FileOnly);
        push(lo, hi, EntryKind::Plain);
        push(hi, end, EntryKind::FileOnly);
    }
    out
}

/// Places each word in its region: kept in a `Plain` region, dropped in a
/// `FileOnly` region or in zero-fill, refused anywhere else.
fn place_words(
    h: &Headers,
    d: &Dynamic,
    regions: &[Region],
    words: Vec<Word>,
) -> Result<Vec<Word>, String> {
    let dyn_lo = d.phdr.vaddr;
    let dyn_hi = d.phdr.vaddr.saturating_add(d.phdr.filesz);
    let mut kept: Vec<Word> = Vec::with_capacity(words.len());
    for w in words {
        let end =
            w.va.checked_add(w.len)
                .ok_or("a relocation address overflows")?;
        if w.relocation && w.va < dyn_hi && end > dyn_lo {
            return Err(format!(
                "RelocationTarget: a relocation at {:#x} writes inside .dynamic",
                w.va
            ));
        }
        match regions.iter().find(|r| w.va >= r.va && w.va < r.end()) {
            Some(_) if w.copy => {
                return Err(format!(
                    "CopyRelocation: the copy relocation at {:#x} writes file-backed bytes, of \
                     which the loader overwrites only as many as the library's symbol holds",
                    w.va
                ));
            }
            Some(r) if end > r.end() => {
                return Err(format!(
                    "RelocationTarget: the word at {:#x} straddles the end of its region",
                    w.va
                ));
            }
            Some(r) if r.kind == EntryKind::FileOnly => {}
            Some(r) if w.relocation && !r.writable => {
                return Err(format!(
                    "RelocationTarget: a relocation at {:#x} writes a read-only segment",
                    w.va
                ));
            }
            Some(_) => kept.push(w),
            None => {
                let zero_fill = h.loads.iter().any(|p| {
                    p.writable()
                        && w.va >= p.vaddr.saturating_add(p.filesz)
                        && p.mem_end().is_some_and(|e| end <= e)
                });
                if !zero_fill {
                    return Err(format!(
                        "RelocationTarget: the word at {:#x} lies outside the image",
                        w.va
                    ));
                }
            }
        }
    }
    for (a, b) in kept.iter().zip(kept.iter().skip(1)) {
        if a.va.saturating_add(a.len) > b.va {
            return Err(format!(
                "RelocationOverlap: two words the loader writes overlap at {:#x}",
                b.va
            ));
        }
    }
    Ok(kept)
}

/// Whether `[rva, rva + len)` is wholly covered by `Plain` entries.
fn plain_covers(entries: &[Entry], rva: u64, len: u64) -> bool {
    let end = rva.saturating_add(len.max(1));
    let mut cursor = rva;
    for e in entries.iter().filter(|e| e.kind == EntryKind::Plain) {
        let (lo, hi) = (
            u64::from(e.rva),
            u64::from(e.rva).saturating_add(u64::from(e.len)),
        );
        if lo <= cursor && hi > cursor {
            cursor = hi;
        }
        if cursor >= end {
            return true;
        }
    }
    false
}

/// The section headers, as `(sh_type, sh_addr, sh_offset, sh_size, sh_link,
/// sh_name)`; empty when the image has none.
type Section = (u32, u64, u64, u64, u32, u32);

fn sections(bytes: &[u8]) -> Result<Vec<Section>, String> {
    let shoff = u64_at(bytes, 0x28).ok_or("truncated ELF header")?;
    let shentsize = usize::from(u16_at(bytes, 0x3a).ok_or("truncated ELF header")?);
    let shnum = usize::from(u16_at(bytes, 0x3c).ok_or("truncated ELF header")?);
    if shoff == 0 {
        return Ok(Vec::new());
    }
    if shnum == 0 || shentsize < 64 {
        return Err("the section-header table is extended or malformed".to_owned());
    }
    let shoff = usize::try_from(shoff).map_err(|_| "section header offset out of range")?;
    let mut out = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let at = i
            .checked_mul(shentsize)
            .and_then(|o| o.checked_add(shoff))
            .ok_or("section header table overflows")?;
        let field = |o: usize| u64_at(bytes, at.saturating_add(o));
        out.push((
            u32_at(bytes, at.saturating_add(4)).ok_or("truncated section header")?,
            field(16).ok_or("truncated section header")?,
            field(24).ok_or("truncated section header")?,
            field(32).ok_or("truncated section header")?,
            u32_at(bytes, at.saturating_add(40)).ok_or("truncated section header")?,
            u32_at(bytes, at).ok_or("truncated section header")?,
        ));
    }
    Ok(out)
}

/// Requires the `SHT_DYNAMIC` section's string table to be exactly the one
/// `.dynamic` names, so the table bionic reads for names is the covered one.
fn check_dynamic_strtab(bytes: &[u8], h: &Headers, d: &Dynamic) -> Result<(), String> {
    let secs = sections(bytes)?;
    let mut dynamic = secs.iter().filter(|s| s.0 == SHT_DYNAMIC);
    let (Some(dyn_sec), None) = (dynamic.next(), dynamic.next()) else {
        return Err(
            "DynamicStrtab: the image has no section-header table with exactly one SHT_DYNAMIC \
             section"
                .to_owned(),
        );
    };
    let linked = secs
        .get(dyn_sec.4 as usize)
        .ok_or("DynamicStrtab: SHT_DYNAMIC's sh_link names no section")?;
    let strtab = d
        .get(DT_STRTAB)
        .ok_or("DynamicStrtab: .dynamic has no DT_STRTAB")?;
    let strsz = d
        .get(DT_STRSZ)
        .ok_or("DynamicStrtab: .dynamic has no DT_STRSZ")?;
    if linked.1 != strtab || linked.3 != strsz || Some(linked.2) != h.file_offset(strtab, strsz) {
        return Err(format!(
            "DynamicStrtab: SHT_DYNAMIC's string section ({:#x}, {} bytes) is not the table \
             .dynamic names ({strtab:#x}, {strsz} bytes)",
            linked.1, linked.3
        ));
    }
    Ok(())
}

/// Derives the typed extent of an ELF64 image, with the loader inferred from
/// the image.
///
/// # Errors
///
/// Returns a description, beginning with the refusal's name where one
/// applies, when the image is malformed, uses a structure the typing does
/// not describe, or the slot is missing or ambiguous.
pub fn classify(bytes: &[u8]) -> Result<Layout, String> {
    classify_for(bytes, None)
}

/// [`classify`], typed for `loader` when it is given rather than for the
/// loader the image declares.
///
/// # Errors
///
/// As [`classify`].
pub fn classify_for(bytes: &[u8], loader: Option<Loader>) -> Result<Layout, String> {
    typed(bytes, loader)
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear derivation; each refusal sits beside the structure it reads"
)]
fn typed(bytes: &[u8], loader: Option<Loader>) -> Result<Layout, String> {
    let h = headers(bytes)?;
    let loader = match loader {
        Some(l) => l,
        None => inferred_loader(bytes)?,
    };
    if let Some(p) = h.loads.iter().find(|p| p.writable() && p.flags & PF_X != 0) {
        return Err(format!(
            "WritableExecutable: the PT_LOAD at {:#x} is both writable and executable, so its \
             code would be checked only against the file; link so that no loadable segment \
             is both",
            p.vaddr
        ));
    }
    let d = dynamic(bytes, &h)?;
    refuse_unsupported(&d, loader, h.machine)?;

    let relro = h
        .one(PT_GNU_RELRO)?
        .map(|p| (p.vaddr, p.vaddr.saturating_add(p.memsz)));
    let regions = regions(&h, relro);

    // PT_DYNAMIC lies in typed bytes, and its own PF_W agrees with its
    // segment's: glibc decides whether to adjust .dynamic from the former.
    let dyn_end = d.phdr.vaddr.saturating_add(d.phdr.filesz);
    let in_plain = regions
        .iter()
        .any(|r| r.kind == EntryKind::Plain && d.phdr.vaddr >= r.va && dyn_end <= r.end());
    let seg_writable = h
        .loads
        .iter()
        .find(|p| d.phdr.vaddr >= p.vaddr && p.file_end().is_some_and(|e| dyn_end <= e))
        .map(Phdr::writable);
    if !in_plain {
        return Err(
            "DynamicPlacement: PT_DYNAMIC lies outside RELRO and outside every read-only \
             segment"
                .to_owned(),
        );
    }
    if seg_writable != Some(d.phdr.writable()) {
        return Err(
            "DynamicPlacement: PT_DYNAMIC's PF_W disagrees with the segment that holds it"
                .to_owned(),
        );
    }
    if d.null_at.saturating_add(DYN_SIZE as u64) > d.phdr.filesz {
        return Err(".dynamic has no DT_NULL entry".to_owned());
    }

    let words = loader_words(bytes, &h, &d, loader)?;
    let words = place_words(&h, &d, &regions, words)?;
    let placed: Vec<Placed> = words
        .iter()
        .map(|w| Placed {
            va: w.va,
            len: w.len,
            kind: w.kind,
            meta: 0,
        })
        .collect();
    let entries = entries_of(&regions, &placed, h.image_base)?;
    let candidate_len: u64 = entries.iter().map(|e| u64::from(e.len)).sum();
    let mapped_len: u64 = h.loads.iter().map(|p| p.filesz).sum();
    if candidate_len != mapped_len {
        return Err(format!(
            "the typed entries cover {candidate_len} of {mapped_len} file-backed bytes"
        ));
    }
    let ranges: Vec<Range> = entries
        .iter()
        .map(|e| Range {
            rva: e.rva,
            file_off: e.file_off,
            len: e.len,
        })
        .collect();
    ensure_disjoint(&ranges)?;

    // The slot's position, in both coordinate spaces; it must sit in a
    // read-only segment.
    let slot_file_off = find_slot(bytes)?;
    let slot_seg = h
        .loads
        .iter()
        .find(|p| {
            let start = usize::try_from(p.offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(p.filesz).unwrap_or(0));
            slot_fits(slot_file_off, start, end)
        })
        .ok_or("no single PT_LOAD segment contains the whole integrity slot")?;
    if slot_seg.writable() {
        return Err(
            "the integrity slot is in a writable segment; the loader may modify it".to_owned(),
        );
    }
    let slot_rva_u64 = slot_seg
        .vaddr
        .checked_sub(h.image_base)
        .and_then(|v| v.checked_add((slot_file_off as u64).checked_sub(slot_seg.offset)?))
        .ok_or("slot RVA overflows")?;
    let slot_rva = u32::try_from(slot_rva_u64).map_err(|_| "slot RVA exceeds 32 bits")?;

    let entries = oxicrypt_integrity::slot::merge(&subtract_slot(&entries, slot_rva)?);
    let covered = oxicrypt_integrity::slot::extent_len(&entries).ok_or("an entry overflows")?;
    if covered.saturating_add(SLOT_SIZE as u64) != mapped_len {
        return Err(format!(
            "the typed entries and the slot cover {} of {mapped_len} file-backed bytes",
            covered.saturating_add(SLOT_SIZE as u64)
        ));
    }

    // Every table .dynamic names is read by the loader: it must be Plain.
    // The tables .dynamic gives a size for are checked over that size. The
    // symbol, hash and version tables have no size tag, and deriving one
    // means trusting the very table being checked; they are required to
    // start in a read-only segment instead, every byte of which from there
    // to the segment's end is Plain (the slot aside), so the whole table is
    // covered whatever its length.
    let rva_of = |va: u64| va.checked_sub(h.image_base);
    for (name, tag, len) in [
        ("DT_RELA", DT_RELA, d.get(DT_RELASZ)),
        ("DT_JMPREL", DT_JMPREL, d.get(DT_PLTRELSZ)),
        ("DT_RELR", DT_RELR, d.get(DT_RELRSZ)),
        ("DT_STRTAB", DT_STRTAB, d.get(DT_STRSZ)),
        ("DT_SYMTAB", DT_SYMTAB, None),
        ("DT_HASH", DT_HASH, None),
        ("DT_GNU_HASH", DT_GNU_HASH, None),
        ("DT_VERSYM", DT_VERSYM, None),
    ] {
        let Some(va) = d.get(tag) else { continue };
        let covered = match len {
            Some(len) => rva_of(va).is_some_and(|rva| plain_covers(&entries, rva, len)),
            None => h
                .loads
                .iter()
                .any(|p| !p.writable() && va >= p.vaddr && p.file_end().is_some_and(|e| va < e)),
        };
        if !covered {
            return Err(format!(
                "TableNotCovered: {name} at {va:#x} does not lie in Plain bytes"
            ));
        }
    }
    check_dynamic_strtab(bytes, &h, &d)?;

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

    Ok(Layout {
        ranges: plain,
        entries,
        flags: loader.slot_flags(),
        slot_file_off,
        slot_rva,
        invariant_len: candidate_len,
        mapped_len,
        link_base: h.image_base,
        file_len: file_len_of(bytes)?,
        relative: RelativeEncoding::FileWord,
        records: Vec::new(),
    })
}

/// The ranges the loader may write to: every writable `PT_LOAD`'s
/// file-backed bytes.
///
/// Exposed for the control that proves the runtime test can fail: an
/// extent that hashes one of these as `Plain` must be rejected at runtime,
/// because the loader has rewritten some of those bytes and they no longer
/// match the file.
///
/// # Errors
///
/// Returns a description when the image is malformed.
pub fn writable_ranges(bytes: &[u8]) -> Result<Vec<Range>, String> {
    let h = headers(bytes)?;
    h.loads
        .iter()
        .filter(|p| p.writable() && p.filesz > 0)
        .map(|p| {
            Ok(Range {
                rva: u32::try_from(p.vaddr.saturating_sub(h.image_base))
                    .map_err(|_| "segment RVA exceeds 32 bits")?,
                file_off: u32::try_from(p.offset).map_err(|_| "segment offset exceeds 32 bits")?,
                len: u32::try_from(p.filesz).map_err(|_| "segment length exceeds 32 bits")?,
            })
        })
        .collect()
}

/// A module static the module must start from zero-fill whose bytes the
/// file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticRow {
    /// The symbol's name, as the symbol table spells it.
    pub name: String,
    /// The symbol's address.
    pub addr: u64,
    /// The symbol's size in bytes.
    pub size: u64,
    /// How many of its bytes lie inside the segment's file extent.
    pub file_backed: u64,
}

/// The file-backed module statics of an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statics {
    /// Module statics found in writable, non-RELRO memory.
    pub matched: usize,
    /// Of those, the file-backed ones holding initialised data.
    pub initialised: usize,
    /// The file-backed ones an edit of the file could preset: every
    /// zero-initialised one, and each pinned static whatever it holds.
    pub rows: Vec<StaticRow>,
    /// The module statics that hold its state and must be in the symbol
    /// table, of which none was found in writable, non-RELRO memory: an empty
    /// list means each was found and checked.
    pub missing: Vec<&'static str>,
}

/// The module statics the check must find by name, each as the
/// length-prefixed path both Rust manglings spell, and whether it is owned
/// by the boot sequence's integrity test rather than by the integrity test
/// itself.
///
/// The module's state and the records that the algorithm tests of the
/// integrity group (ML-DSA-87 and SHA-256) passed are read by the integrity
/// test itself, which is
/// what keeps the slot in a linked artifact. The integrity status is
/// written only by the boot sequence's test, whose name in the test
/// inventory is in the image's read-only bytes exactly when that test is
/// linked; an artifact that calls the integrity test without the boot
/// sequence does not link the status at all. Neither the slot nor that name
/// can be removed by stripping symbols.
pub const REQUIRED_STATICS: [(&str, &str, bool); 4] = [
    ("oxicrypt_module::STATE", "15oxicrypt_module5STATE", false),
    (
        "oxicrypt_integrity::LAST_STATUS",
        "18oxicrypt_integrity11LAST_STATUS",
        true,
    ),
    (
        "oxicrypt_integrity::ML_DSA_CAST_PASSED",
        "18oxicrypt_integrity18ML_DSA_CAST_PASSED",
        false,
    ),
    (
        "oxicrypt_integrity::SHA256_CAST_PASSED",
        "18oxicrypt_integrity18SHA256_CAST_PASSED",
        false,
    ),
];

/// The length of the boot integrity test's name.
const BOOT_TEST_NAME_LEN: usize = oxicrypt_integrity::INTEGRITY_TEST_NAME.len();

/// The boot integrity test's name, masked at compile time; the indexing is
/// bounded by the array's own length, checked by the compiler. The signer
/// links `oxicrypt-integrity` too, and keeping only this copy means its own
/// image never carries the name it looks for.
#[allow(
    clippy::indexing_slicing,
    reason = "constant evaluation over a fixed length; an out-of-range index fails the build"
)]
const BOOT_TEST_NAME_MASKED: [u8; BOOT_TEST_NAME_LEN] = {
    let name = oxicrypt_integrity::INTEGRITY_TEST_NAME.as_bytes();
    let mut out = [0u8; BOOT_TEST_NAME_LEN];
    let mut i = 0;
    while i < BOOT_TEST_NAME_LEN {
        out[i] = name[i] ^ 0xa5;
        i += 1;
    }
    out
};

/// Whether the image links the boot sequence's integrity test: its name in
/// the test inventory is in the image's read-only bytes.
#[must_use]
pub fn links_boot_test(image: &[u8]) -> bool {
    image.windows(BOOT_TEST_NAME_LEN).any(|w| {
        w.iter()
            .zip(BOOT_TEST_NAME_MASKED)
            .all(|(&b, m)| b ^ 0xa5 == m)
    })
}

/// Whether the image's symbol table holds any local data object, which a
/// strip that keeps only global symbols removes along with the module's
/// statics.
#[must_use]
pub fn has_local_objects(bytes: &[u8]) -> bool {
    let Ok(secs) = sections(bytes) else {
        return false;
    };
    secs.iter()
        .filter(|s| s.0 == SHT_SYMTAB)
        .filter_map(|s| {
            let start = usize::try_from(s.2).ok()?;
            let len = usize::try_from(s.3).ok()?;
            bytes.get(start..start.checked_add(len)?)
        })
        .any(|syms| {
            syms.chunks_exact(SYM_SIZE)
                .any(|sym| sym.get(4).is_some_and(|&info| info == 1))
        })
}

/// Whether the image carries a symbol table.
#[must_use]
pub fn has_symtab(bytes: &[u8]) -> bool {
    sections(bytes).is_ok_and(|s| s.iter().any(|sec| sec.0 == SHT_SYMTAB && sec.3 > 0))
}

/// The `.gnu_debuglink` name and CRC, when the image names a debug file.
///
/// # Errors
///
/// Returns a description when the section headers or the link are
/// malformed.
pub fn debuglink(bytes: &[u8]) -> Result<Option<(String, u32)>, String> {
    let secs = sections(bytes)?;
    let shstrndx = usize::from(u16_at(bytes, 0x3e).ok_or("truncated ELF header")?);
    let Some(names) = secs.get(shstrndx) else {
        return Ok(None);
    };
    for s in &secs {
        let name_at = usize::try_from(names.2.saturating_add(u64::from(s.5)))
            .map_err(|_| "section name out of range")?;
        let tail = bytes.get(name_at..).unwrap_or(&[]);
        let name = tail.split(|&b| b == 0).next().unwrap_or(&[]);
        if name != b".gnu_debuglink" {
            continue;
        }
        let start = usize::try_from(s.2).map_err(|_| "debuglink out of range")?;
        let len = usize::try_from(s.3).map_err(|_| "debuglink out of range")?;
        let body = start
            .checked_add(len)
            .and_then(|end| bytes.get(start..end))
            .ok_or("the debuglink runs past the end of the file")?;
        let file = body.split(|&b| b == 0).next().unwrap_or(&[]);
        let crc_at = file
            .len()
            .checked_add(1)
            .and_then(|v| v.checked_next_multiple_of(4))
            .ok_or("debuglink overflows")?;
        let crc = u32_at(body, crc_at).ok_or("the debuglink has no CRC")?;
        let file = std::str::from_utf8(file)
            .map_err(|_| "the debuglink name is not UTF-8")?
            .to_owned();
        if file.is_empty() || file.contains('/') {
            return Err("the debuglink does not name a file".to_owned());
        }
        return Ok(Some((file, crc)));
    }
    Ok(None)
}

/// The CRC-32 a `.gnu_debuglink` records for its debug file.
#[must_use]
pub fn debuglink_crc(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Names every zero-initialised module static the image's file holds.
///
/// The pre-operational tests run inside module initialisation, which the
/// service gates skip once the module state says the tests have run. A
/// zero-initialised static that the loader maps from the file rather than
/// from zero-fill could be preset by an edit of the file, so an image with
/// one must not be signed.
///
/// The statics [`REQUIRED_STATICS`] pins are rows whenever any byte is
/// file-backed, whatever the file holds there: the module reads them before
/// deciding whether to run its tests.
///
/// A module static is a defined `STT_OBJECT` symbol whose name contains
/// `oxicrypt` (every boundary crate's mangled names do), in a writable
/// segment outside RELRO. It is file-backed when any of its bytes lie below
/// the segment's file size, and zero-initialised when every such byte is
/// zero and no relocation writes into it. `symbols` is the image itself or
/// its separated debug file: the table is read from it, the bytes and
/// relocations from `image`, read as `loader` reads them (the loader the
/// image declares when `None`).
///
/// # Errors
///
/// Returns a description when either input is malformed or `symbols`
/// carries no symbol table.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the symbol table; each condition sits beside the field it reads"
)]
pub fn module_statics(
    image: &[u8],
    symbols: &[u8],
    loader: Option<Loader>,
) -> Result<Statics, String> {
    let h = headers(image)?;
    let d = dynamic(image, &h)?;
    let relro = h
        .one(PT_GNU_RELRO)?
        .map(|p| (p.vaddr, p.vaddr.saturating_add(p.memsz)));
    // Every word a relocation writes, whatever its region.
    let loader = match loader {
        Some(l) => l,
        None => inferred_loader(image)?,
    };
    let written = loader_words(image, &h, &d, loader)?;

    let secs = sections(symbols)?;
    let symtab = secs
        .iter()
        .find(|s| s.0 == SHT_SYMTAB && s.3 > 0)
        .ok_or("StaticsUnchecked: the symbol source has no symbol table")?;
    let strtab = secs
        .get(symtab.4 as usize)
        .ok_or("the symbol table's string table is missing")?;
    let slice = |off: u64, len: u64| -> Result<&[u8], String> {
        let start = usize::try_from(off).map_err(|_| "symbol table out of range")?;
        let len = usize::try_from(len).map_err(|_| "symbol table out of range")?;
        start
            .checked_add(len)
            .and_then(|end| symbols.get(start..end))
            .ok_or_else(|| "the symbol table runs past the end of its file".to_owned())
    };
    let syms = slice(symtab.2, symtab.3)?;
    let strs = slice(strtab.2, strtab.3)?;

    let mut matched = 0usize;
    let mut initialised = 0usize;
    let mut rows = Vec::new();
    let mut found = [false; REQUIRED_STATICS.len()];
    for sym in syms.chunks_exact(SYM_SIZE) {
        let st_name = u32_at(sym, 0).ok_or("truncated symbol")? as usize;
        let st_info = *sym.get(4).ok_or("truncated symbol")?;
        let st_shndx = u16_at(sym, 6).ok_or("truncated symbol")?;
        let value = u64_at(sym, 8).ok_or("truncated symbol")?;
        let size = u64_at(sym, 16).ok_or("truncated symbol")?.max(1);
        if st_info & 0xf != 1 || st_shndx == 0 || st_shndx >= 0xff00 {
            continue;
        }
        let name = strs
            .get(st_name..)
            .and_then(|t| t.split(|&b| b == 0).next())
            .unwrap_or(&[]);
        if !name.windows(8).any(|w| w == b"oxicrypt") {
            continue;
        }
        let Some(seg) = h
            .loads
            .iter()
            .find(|p| value >= p.vaddr && p.mem_end().is_some_and(|e| value < e))
        else {
            continue;
        };
        if !seg.writable() || relro.is_some_and(|(s, e)| value >= s && value < e) {
            continue;
        }
        matched = matched.saturating_add(1);
        let mut pinned = false;
        for (seen, (_, ident, _)) in found.iter_mut().zip(REQUIRED_STATICS) {
            let is = name.windows(ident.len()).any(|w| w == ident.as_bytes());
            *seen |= is;
            pinned |= is;
        }
        let file_end = seg.vaddr.saturating_add(seg.filesz);
        let backed = value
            .saturating_add(size)
            .min(file_end)
            .saturating_sub(value);
        if backed == 0 {
            continue;
        }
        let off = seg.offset.saturating_add(value.saturating_sub(seg.vaddr));
        let bytes = usize::try_from(off)
            .ok()
            .zip(usize::try_from(backed).ok())
            .and_then(|(o, n)| image.get(o..o.checked_add(n)?))
            .ok_or("a module static's file bytes lie past the end of the file")?;
        let relocated = written
            .iter()
            .any(|w| w.va < value.saturating_add(size) && w.va.saturating_add(w.len) > value);
        // A gate static the module reads before deciding to run its tests
        // must come from zero-fill whatever the file holds: an edit could set
        // any value, not only a zero one.
        if !pinned && (relocated || bytes.iter().any(|&b| b != 0)) {
            initialised = initialised.saturating_add(1);
            continue;
        }
        rows.push(StaticRow {
            name: String::from_utf8_lossy(name).into_owned(),
            addr: value,
            size,
            file_backed: backed,
        });
    }
    let boot = links_boot_test(image);
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
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
pub(crate) mod tests {
    use oxicrypt_integrity::slot::{Entry, EntryKind, FLAG_LOADER_BIONIC};
    use oxicrypt_integrity::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE};

    use super::{
        DF_1_NOW, DF_1_PIE, DT_ANDROID_REL, DT_ANDROID_RELA, DT_ANDROID_RELR, DT_BIND_NOW,
        DT_DEBUG, DT_FLAGS, DT_FLAGS_1, DT_GNU_HASH, DT_JMPREL, DT_PLTREL, DT_PLTRELSZ, DT_REL,
        DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELR, DT_RELRSZ, DT_STRSZ, DT_STRTAB, DT_SYMTAB,
        DT_TEXTREL, DT_X86_64_PLT, DT_X86_64_PLTENT, DT_X86_64_PLTSZ, Loader, classify,
        classify_for, debuglink, debuglink_crc, inferred_loader, module_statics,
    };

    // The fixture's layout. Everything is at file offset equal to its
    // address except the writable segment, which sits one page higher in
    // memory than in the file, as ld places it.
    const TEXT: u64 = 0x1000;
    const SLOT: u64 = 0x3000;
    const RO_END: u64 = SLOT + SLOT_SIZE as u64 + 0x1000;
    /// The writable segment: RELRO, then `.data`.
    const RW_FILE: u64 = RO_END;
    const RW_VA: u64 = RO_END + 0x1000;
    const RELRO_LEN: u64 = 0x1000;
    const DATA_LEN: u64 = 0x200;
    const BSS_LEN: u64 = 0x100;
    const DYN_VA: u64 = RW_VA;
    const RELA_VA: u64 = TEXT + 0x100;
    const RELR_VA: u64 = TEXT + 0x400;
    const DYNSTR_VA: u64 = TEXT + 0x500;
    const DYNSYM_VA: u64 = TEXT + 0x600;
    const HASH_VA: u64 = TEXT + 0x700;
    /// The words in RELRO a RELA record writes.
    const RELA_DEST: [u64; 2] = [RW_VA + 0x400, RW_VA + 0x420];
    /// A TLS descriptor destination, 16 bytes.
    const TLSDESC_DEST: u64 = RW_VA + 0x440;
    /// A RELR destination.
    const RELR_DEST: u64 = RW_VA + 0x500;
    /// A RELA destination in `.data`, inside the FileOnly region.
    const DATA_RELA_DEST: u64 = RW_VA + RELRO_LEN + 0x10;
    /// A module static address inside `.data`'s file bytes.
    pub(crate) const STATIC_VA: u64 = RW_VA + RELRO_LEN + 0x100;

    #[allow(
        clippy::struct_excessive_bools,
        reason = "each switch is one fixture variant"
    )]
    pub(crate) struct Fixture {
        pub(crate) loader_note: bool,
        pub(crate) dynamic: Vec<(u64, u64)>,
        pub(crate) relocs: Vec<(u64, u32)>,
        pub(crate) relr: Vec<u64>,
        pub(crate) dyn_writable: bool,
        pub(crate) relro: bool,
        /// Write a non-zero byte under the module static.
        pub(crate) static_initialised: bool,
        /// The static's address; past `p_filesz` makes it zero-fill.
        pub(crate) static_va: u64,
        /// Section headers; `None` builds an image without them.
        pub(crate) sections: bool,
        /// A section string table that disagrees with DT_STRTAB.
        /// Offsets added to the `SHT_DYNAMIC` string section's address, file
        /// offset and size, so each can disagree with `.dynamic` alone.
        pub(crate) strtab_skew: (u64, u64, u64),
        /// A `PT_INTERP`, which makes the image an executable.
        pub(crate) interp: bool,
        /// A `TPOFF64` relocation against dynamic symbol 1, which is
        /// undefined and weak when this is `Some(true)`.
        pub(crate) tls_weak: Option<bool>,
        /// The unslid address written at each RELR destination.
        pub(crate) relr_target: u64,
        /// Whether `.symtab` is present, as strip would leave it.
        pub(crate) symtab: bool,
        /// Rename one of the required statics, by its index in
        /// `REQUIRED_STATICS`, as a strip of that symbol would leave the
        /// table.
        pub(crate) drop_symbol: Option<usize>,
        /// A `.gnu_debuglink` section's file name and CRC.
        pub(crate) debuglink: Option<(String, u32)>,
        /// The boot integrity test's name in read-only data, as an artifact
        /// that links the boot sequence carries it.
        pub(crate) boot_test: bool,
        /// Mark the writable `PT_LOAD` executable as well (`PF_W | PF_X`).
        pub(crate) rw_exec: bool,
        /// An AArch64 image (`EM_AARCH64`) rather than x86-64; `relocs`
        /// must then carry AArch64 relocation types.
        pub(crate) aarch64: bool,
    }

    /// The fixture's name for the module state.
    pub(crate) const STATE_NAME: &str = "_RNvCs1_15oxicrypt_module5STATE";

    pub(crate) fn rela_type(machine_x86: bool, name: &str) -> u32 {
        match (machine_x86, name) {
            (true, "relative") => 8,
            (true, "glob_dat") => 6,
            (true, "tlsdesc") => 36,
            (true, "copy") => 5,
            _ => unreachable!(),
        }
    }

    impl Fixture {
        pub(crate) fn new() -> Self {
            Self {
                loader_note: false,
                dynamic: vec![
                    (DT_STRTAB, DYNSTR_VA),
                    (DT_STRSZ, 0x20),
                    (DT_SYMTAB, DYNSYM_VA),
                    (DT_GNU_HASH, HASH_VA),
                    (DT_RELA, RELA_VA),
                    (DT_RELASZ, 0),
                    (DT_RELAENT, 24),
                    (DT_DEBUG, 0),
                    (DT_FLAGS, 0x8),
                ],
                relocs: vec![
                    (RELA_DEST[0], 8),
                    (RELA_DEST[1], 6),
                    (TLSDESC_DEST, 36),
                    (DATA_RELA_DEST, 8),
                ],
                relr: vec![RELR_DEST],
                dyn_writable: true,
                relro: true,
                static_initialised: false,
                static_va: RW_VA + RELRO_LEN + DATA_LEN + 0x10,
                sections: true,
                strtab_skew: (0, 0, 0),
                interp: false,
                tls_weak: None,
                relr_target: RW_VA + 0x600,
                symtab: true,
                drop_symbol: None,
                debuglink: None,
                boot_test: true,
                rw_exec: false,
                aarch64: false,
            }
        }

        fn set(&mut self, tag: u64, val: u64) {
            match self.dynamic.iter_mut().find(|(t, _)| *t == tag) {
                Some(e) => e.1 = val,
                None => self.dynamic.push((tag, val)),
            }
        }

        fn remove(&mut self, tag: u64) {
            self.dynamic.retain(|(t, _)| *t != tag);
        }

        #[allow(clippy::too_many_lines, reason = "one fixture, laid out in file order")]
        pub(crate) fn build(&self) -> Vec<u8> {
            let rw_filesz = RELRO_LEN + DATA_LEN;
            let shoff = RW_FILE + rw_filesz;
            let symtab_off = shoff + 0x400;
            let strtab_off = symtab_off + 0x100;
            let shstr_off = strtab_off + 0x100;
            let len = shstr_off + 0x100;
            let mut img = vec![0u8; len as usize];
            let put = |img: &mut Vec<u8>, at: u64, b: &[u8]| {
                img[at as usize..at as usize + b.len()].copy_from_slice(b);
            };
            // ELF header.
            put(&mut img, 0, b"\x7fELF\x02\x01\x01");
            put(&mut img, 0x10, &3u16.to_le_bytes());
            put(
                &mut img,
                0x12,
                &(if self.aarch64 { 183u16 } else { 62 }).to_le_bytes(),
            );
            put(&mut img, 0x20, &64u64.to_le_bytes());
            put(&mut img, 0x36, &56u16.to_le_bytes());
            let mut phdrs: Vec<[u64; 7]> = vec![
                // type|flags, offset, vaddr, paddr, filesz, memsz, align
                [1 | (5 << 32), 0, 0, 0, RO_END, RO_END, 0x1000],
                [
                    1 | (u64::from(if self.rw_exec { 7u32 } else { 6 }) << 32),
                    RW_FILE,
                    RW_VA,
                    RW_VA,
                    rw_filesz,
                    rw_filesz + BSS_LEN,
                    0x1000,
                ],
                [
                    2 | (u64::from(if self.dyn_writable { 6u32 } else { 4 }) << 32),
                    RW_FILE,
                    DYN_VA,
                    DYN_VA,
                    0x200,
                    0x200,
                    8,
                ],
            ];
            if self.relro {
                phdrs.push([
                    0x6474_e552 | (4 << 32),
                    RW_FILE,
                    RW_VA,
                    RW_VA,
                    RELRO_LEN,
                    RELRO_LEN,
                    1,
                ]);
            }
            if self.interp {
                phdrs.push([3 | (4 << 32), 0x900, 0x900, 0x900, 0x10, 0x10, 1]);
            }
            if self.loader_note {
                phdrs.push([4 | (4 << 32), 0x800, 0x800, 0x800, 0x20, 0x20, 4]);
                put(&mut img, 0x800, &8u32.to_le_bytes());
                put(&mut img, 0x804, &4u32.to_le_bytes());
                put(&mut img, 0x808, &1u32.to_le_bytes());
                put(&mut img, 0x80c, b"Android\0");
                put(&mut img, 0x814, &24u32.to_le_bytes());
            }
            put(&mut img, 0x38, &(phdrs.len() as u16).to_le_bytes());
            for (i, p) in phdrs.iter().enumerate() {
                let at = 64 + 56 * i as u64;
                for (k, v) in p.iter().enumerate() {
                    put(&mut img, at + 8 * k as u64, &v.to_le_bytes());
                }
            }
            // The relocation tables, in the read-only segment.
            let mut rela = Vec::new();
            let mut relocs: Vec<(u64, u64)> = self
                .relocs
                .iter()
                .map(|(o, t)| (*o, u64::from(*t)))
                .collect();
            if let Some(weak) = self.tls_weak {
                relocs.push((RW_VA + 0x700, 0x12 | (1 << 32)));
                // Dynamic symbol 1: a TLS object, undefined and weak, or
                // defined in section 2.
                let mut sym = [0u8; 24];
                sym[4] = if weak { (2 << 4) | 6 } else { (1 << 4) | 6 };
                sym[6..8].copy_from_slice(&(if weak { 0u16 } else { 2 }).to_le_bytes());
                put(&mut img, DYNSYM_VA + 24, &sym);
            }
            for (off, info) in &relocs {
                rela.extend_from_slice(&off.to_le_bytes());
                rela.extend_from_slice(&info.to_le_bytes());
                rela.extend_from_slice(&0u64.to_le_bytes());
            }
            put(&mut img, RELA_VA, &rela);
            let mut dynamic = self.dynamic.clone();
            if let Some(e) = dynamic.iter_mut().find(|(t, _)| *t == DT_RELASZ) {
                e.1 = rela.len() as u64;
            }
            if !self.relr.is_empty() {
                let mut packed = Vec::new();
                let mut next = 0;
                for v in &self.relr {
                    packed.extend_from_slice(&v.to_le_bytes());
                    // The file word at each RELR destination is the unslid
                    // address it holds.
                    let mut dests = Vec::new();
                    if v & 1 == 0 {
                        dests.push(*v);
                        next = v + 8;
                    } else {
                        dests.extend(
                            (1..64)
                                .filter(|b| v >> b & 1 != 0)
                                .map(|b| next + (b - 1) * 8),
                        );
                        next += 63 * 8;
                    }
                    for d in dests {
                        put(
                            &mut img,
                            RW_FILE + (d - RW_VA),
                            &self.relr_target.to_le_bytes(),
                        );
                    }
                }
                put(&mut img, RELR_VA, &packed);
                if !dynamic.iter().any(|(t, _)| *t == DT_RELR) {
                    dynamic.push((DT_RELR, RELR_VA));
                    dynamic.push((DT_RELRSZ, packed.len() as u64));
                }
            }
            // .dynamic, at the start of RELRO.
            for (i, (t, v)) in dynamic.iter().enumerate() {
                put(&mut img, RW_FILE + 16 * i as u64, &t.to_le_bytes());
                put(&mut img, RW_FILE + 16 * i as u64 + 8, &v.to_le_bytes());
            }
            // The slot.
            put(&mut img, SLOT, &SLOT_HEADER_MAGIC);
            put(&mut img, SLOT + SLOT_SIZE as u64 - 16, &SLOT_FOOTER_MAGIC);
            crate::test_support::put_key_record(&mut img, (TEXT + 0x800) as usize);
            if self.boot_test {
                put(
                    &mut img,
                    TEXT + 0x1300,
                    oxicrypt_integrity::INTEGRITY_TEST_NAME.as_bytes(),
                );
            }
            // The module static's file bytes.
            if self.static_initialised && self.static_va < RW_VA + rw_filesz {
                put(&mut img, RW_FILE + (self.static_va - RW_VA), &[7]);
            }
            if !self.sections {
                return img;
            }
            // Sections: null, .dynstr, .dynamic, .symtab, .strtab, .shstrtab,
            // .gnu_debuglink.
            put(
                &mut img,
                shstr_off,
                b"\0.dynstr\0.dynamic\0.symtab\0.strtab\0.shstrtab\0.gnu_debuglink\0",
            );
            // The four statics the check requires, each a local object:
            // the state where the fixture puts it, the others in zero-fill.
            let bss = RW_VA + RELRO_LEN + DATA_LEN;
            let symbols = [
                (STATE_NAME, self.static_va, 8u64),
                ("_RNvCs1_18oxicrypt_integrity11LAST_STATUS", bss + 0x20, 1),
                (
                    "_RNvCs1_18oxicrypt_integrity18ML_DSA_CAST_PASSED.0",
                    bss + 0x28,
                    1,
                ),
                (
                    "_RNvCs1_18oxicrypt_integrity18SHA256_CAST_PASSED.0",
                    bss + 0x30,
                    1,
                ),
            ];
            let mut names = vec![0u8];
            for (i, (name, va, size)) in symbols.iter().enumerate() {
                let name = if self.drop_symbol == Some(i) {
                    "_RNvCs1_8oxicrypt5OTHER"
                } else {
                    name
                };
                let mut sym = [0u8; 24];
                sym[0..4].copy_from_slice(&(names.len() as u32).to_le_bytes());
                sym[4] = 1; // STT_OBJECT, STB_LOCAL
                sym[6..8].copy_from_slice(&2u16.to_le_bytes());
                sym[8..16].copy_from_slice(&va.to_le_bytes());
                sym[16..24].copy_from_slice(&size.to_le_bytes());
                put(&mut img, symtab_off + 24 * (i as u64 + 1), &sym);
                names.extend_from_slice(name.as_bytes());
                names.push(0);
            }
            put(&mut img, strtab_off, &names);
            let mut link = Vec::new();
            if let Some((name, crc)) = &self.debuglink {
                link.extend_from_slice(name.as_bytes());
                link.push(0);
                link.resize(link.len().next_multiple_of(4), 0);
                link.extend_from_slice(&crc.to_le_bytes());
            }
            let link_off = shstr_off + 0x80;
            put(&mut img, link_off, &link);
            let (addr_skew, off_skew, size_skew) = self.strtab_skew;
            let shdr = |name: u32, ty: u32, addr: u64, off: u64, size: u64, link: u32| {
                let mut s = [0u8; 64];
                s[0..4].copy_from_slice(&name.to_le_bytes());
                s[4..8].copy_from_slice(&ty.to_le_bytes());
                s[16..24].copy_from_slice(&addr.to_le_bytes());
                s[24..32].copy_from_slice(&off.to_le_bytes());
                s[32..40].copy_from_slice(&size.to_le_bytes());
                s[40..44].copy_from_slice(&link.to_le_bytes());
                s
            };
            let table = [
                [0u8; 64],
                shdr(
                    1,
                    3,
                    DYNSTR_VA + addr_skew,
                    DYNSTR_VA + off_skew,
                    0x20 + size_skew,
                    0,
                ),
                shdr(9, 6, DYN_VA, RW_FILE, 0x200, 1),
                shdr(
                    18,
                    if self.symtab { 2 } else { 1 },
                    0,
                    symtab_off,
                    24 * (symbols.len() as u64 + 1),
                    4,
                ),
                shdr(26, 3, 0, strtab_off, 0x100, 0),
                shdr(34, 3, 0, shstr_off, 0x40, 0),
                // Unnamed unless the fixture carries a debuglink.
                shdr(
                    if self.debuglink.is_some() { 44 } else { 0 },
                    1,
                    0,
                    link_off,
                    link.len() as u64,
                    0,
                ),
            ];
            for (i, s) in table.iter().enumerate() {
                put(&mut img, shoff + 64 * i as u64, s);
            }
            put(&mut img, 0x28, &shoff.to_le_bytes());
            put(&mut img, 0x3a, &64u16.to_le_bytes());
            put(&mut img, 0x3c, &(table.len() as u16).to_le_bytes());
            put(&mut img, 0x3e, &5u16.to_le_bytes());
            img
        }
    }

    /// The kind the table gives `rva`: a `Plain` entry's carried hole is a
    /// `Hole`.
    fn kind_at(entries: &[Entry], rva: u64) -> Option<EntryKind> {
        entries.iter().find_map(|e| {
            let start = u64::from(e.rva);
            let hashed = start + u64::from(e.len);
            if rva < start || rva >= hashed + u64::from(e.hole_len()) {
                None
            } else if rva < hashed {
                Some(e.kind)
            } else {
                Some(EntryKind::Hole)
            }
        })
    }

    fn refused(f: &Fixture, name: &str) {
        match classify(&f.build()) {
            Err(e) => assert!(e.starts_with(name), "expected {name}, got: {e}"),
            Ok(_) => panic!("expected {name}, but the image classified"),
        }
    }

    /// The glibc typing: RELA destinations in RELRO are holes (16 bytes for
    /// a TLS descriptor), RELR destinations and the adjusted `.dynamic`
    /// pointers are `Relative`, `DT_DEBUG`'s value is a hole, the rest of
    /// RELRO is `Plain`, `.data` is `FileOnly` with nothing inside it, and
    /// every file-backed byte but the slot is covered once.
    #[test]
    fn glibc_typing_covers_every_file_backed_byte_once() {
        let img = Fixture::new().build();
        let layout = classify(&img).unwrap();
        let e = &layout.entries;
        assert_eq!(layout.flags, 0, "glibc is recorded as flag 0");
        assert_eq!(kind_at(e, RELA_DEST[0]), Some(EntryKind::Hole));
        assert_eq!(kind_at(e, RELA_DEST[1]), Some(EntryKind::Hole));
        assert_eq!(kind_at(e, TLSDESC_DEST + 8), Some(EntryKind::Hole));
        assert_eq!(kind_at(e, RELR_DEST), Some(EntryKind::Relative));
        assert_eq!(
            kind_at(e, RW_VA + 8),
            Some(EntryKind::Relative),
            "DT_STRTAB's d_val"
        );
        assert_eq!(kind_at(e, RW_VA), Some(EntryKind::Plain), "a d_tag");
        assert_eq!(
            kind_at(e, RW_VA + 16 + 8),
            Some(EntryKind::Plain),
            "DT_STRSZ's d_val"
        );
        assert_eq!(
            kind_at(e, RW_VA + 7 * 16 + 8),
            Some(EntryKind::Plain),
            "glibc writes DT_DEBUG only in its main program"
        );
        assert_eq!(kind_at(e, RW_VA + 0x600), Some(EntryKind::Plain));
        assert_eq!(kind_at(e, DATA_RELA_DEST), Some(EntryKind::FileOnly));
        assert_eq!(kind_at(e, 0), Some(EntryKind::Plain), "the ELF header");
        assert_eq!(kind_at(e, SLOT), None, "the slot is subtracted");
        assert_eq!(
            kind_at(e, RW_VA + RELRO_LEN + DATA_LEN),
            None,
            "zero-fill is not covered"
        );
        let file_only: Vec<_> = e.iter().filter(|x| x.kind == EntryKind::FileOnly).collect();
        assert_eq!(file_only.len(), 1);
        assert_eq!(u64::from(file_only[0].len), DATA_LEN);
        assert_eq!(u64::from(file_only[0].file_off), RW_FILE + RELRO_LEN);
        let covered = oxicrypt_integrity::slot::extent_len(e).unwrap();
        assert_eq!(covered + SLOT_SIZE as u64, layout.mapped_len);
        // Ascending and canonical, as the slot decoder requires, with every
        // hole carried by the Plain entry before it.
        assert_eq!(oxicrypt_integrity::slot::merge(e), *e);
        assert!(e.windows(2).all(|w| w[0].rva_end().unwrap() <= w[1].rva));
        assert!(e.iter().all(|x| x.kind != EntryKind::Hole));
    }

    /// glibc writes `DT_DEBUG` only for its main program, so it is a hole in
    /// an executable and `Plain` in a library; bionic writes it in any object
    /// whose `PT_DYNAMIC` is writable.
    #[test]
    fn dt_debug_is_a_hole_only_where_the_loader_writes_it() {
        let debug = RW_VA + 7 * 16 + 8;
        let mut f = Fixture::new();
        f.interp = true;
        let layout = classify(&f.build()).unwrap();
        assert_eq!(kind_at(&layout.entries, debug), Some(EntryKind::Hole));
        f.interp = false;
        let layout = classify(&f.build()).unwrap();
        assert_eq!(kind_at(&layout.entries, debug), Some(EntryKind::Plain));
        f.relr.clear();
        let layout = classify_for(&f.build(), Some(Loader::Bionic)).unwrap();
        assert_eq!(kind_at(&layout.entries, debug), Some(EntryKind::Hole));
    }

    /// A static PIE (`ET_DYN`, `DF_1_PIE`, no `PT_INTERP`) is glibc's main
    /// program, so its `DT_DEBUG` value is a hole; without `DF_1_PIE` the
    /// same image is a library and the value is `Plain`.
    #[test]
    fn dt_debug_is_a_hole_in_a_static_pie() {
        let debug = RW_VA + 7 * 16 + 8;
        let mut f = Fixture::new();
        f.set(DT_FLAGS_1, DF_1_NOW | DF_1_PIE);
        let layout = classify(&f.build()).unwrap();
        assert_eq!(kind_at(&layout.entries, debug), Some(EntryKind::Hole));
        f.set(DT_FLAGS_1, DF_1_NOW);
        let layout = classify(&f.build()).unwrap();
        assert_eq!(kind_at(&layout.entries, debug), Some(EntryKind::Plain));
    }

    /// A loadable segment both writable and executable is refused: its code
    /// would be `FileOnly`, checked against the file and never in memory.
    #[test]
    fn a_writable_executable_segment_is_refused() {
        let mut f = Fixture::new();
        f.rw_exec = true;
        refused(&f, "WritableExecutable");
        f.rw_exec = false;
        classify(&f.build()).unwrap();
    }

    /// A second `DT_FLAGS_1` is refused in either order: glibc reads the
    /// last one, the classifier the first, so the two could disagree about
    /// `DF_1_NOW`.
    #[test]
    fn a_duplicate_dt_flags_1_is_refused_in_either_order() {
        for pair in [[DF_1_NOW, 0], [0, DF_1_NOW]] {
            let mut f = Fixture::new();
            f.dynamic.push((DT_FLAGS_1, pair[0]));
            f.dynamic.push((DT_FLAGS_1, pair[1]));
            refused(&f, ".dynamic carries tag 0x6ffffffb twice");
        }
        let mut f = Fixture::new();
        f.dynamic.push((DT_FLAGS_1, DF_1_NOW));
        classify(&f.build()).unwrap();
    }

    /// Each x86-64 PLT-rewrite tag, which `-z mark-plt` emits so that glibc
    /// may rewrite the PLT at load, is refused.
    #[test]
    fn the_x86_64_plt_rewrite_tags_are_refused() {
        for tag in [DT_X86_64_PLT, DT_X86_64_PLTSZ, DT_X86_64_PLTENT] {
            let mut f = Fixture::new();
            f.set(tag, 0x10);
            refused(&f, "PltRewrite");
        }
    }

    /// On AArch64 the PLT-rewrite tag values are other tags (`0x70000001` is
    /// `DT_AARCH64_BTI_PLT`), so an image carrying one classifies.
    #[test]
    fn on_aarch64_the_plt_rewrite_values_classify() {
        let mut f = Fixture::new();
        f.aarch64 = true;
        f.relocs = f
            .relocs
            .iter()
            .map(|&(o, t)| {
                let t = match t {
                    8 => 1027,
                    6 => 1025,
                    36 => 1031,
                    _ => unreachable!(),
                };
                (o, t)
            })
            .collect();
        classify(&f.build()).unwrap();
        f.set(0x7000_0001, 0);
        classify(&f.build()).unwrap();
    }

    /// The `Relative` words are exactly the RELR destinations, an address
    /// entry and a bitmap with bits 1, 2 and 63 set, and the `.dynamic`
    /// pointers glibc adjusts.
    #[test]
    fn relr_bitmaps_and_adjusted_pointers_are_exactly_the_relative_words() {
        let mut f = Fixture::new();
        f.relr = vec![RELR_DEST, 1 | (1 << 1) | (1 << 2) | (1 << 63)];
        let layout = classify(&f.build()).unwrap();
        let mut words: Vec<u64> = layout
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::Relative)
            .flat_map(|e| (u64::from(e.rva)..u64::from(e.rva) + u64::from(e.len)).step_by(8))
            .collect();
        words.sort_unstable();
        // DT_STRTAB, DT_SYMTAB, DT_GNU_HASH, DT_RELA and DT_RELR's values
        // (entries 0, 2, 3, 4 and 9), then the four RELR destinations.
        let mut want: Vec<u64> = [0, 2, 3, 4, 9].iter().map(|i| RW_VA + 16 * i + 8).collect();
        want.extend([
            RELR_DEST,
            RELR_DEST + 8,
            RELR_DEST + 16,
            RELR_DEST + 8 + 62 * 8,
        ]);
        want.sort_unstable();
        assert_eq!(words, want);
    }

    /// bionic adjusts no `.dynamic` word, and is recorded in the slot flags;
    /// the loader is inferred from the Android ident note and can be
    /// overridden either way.
    #[test]
    fn bionic_is_inferred_from_the_note_and_types_dynamic_plain() {
        let mut f = Fixture::new();
        f.relr.clear();
        f.loader_note = true;
        let img = f.build();
        assert_eq!(inferred_loader(&img).unwrap(), Loader::Bionic);
        let layout = classify(&img).unwrap();
        assert_eq!(layout.flags, FLAG_LOADER_BIONIC);
        assert_eq!(kind_at(&layout.entries, RW_VA + 8), Some(EntryKind::Plain));
        assert_eq!(
            kind_at(&layout.entries, RW_VA + 7 * 16 + 8),
            Some(EntryKind::Hole)
        );
        let glibc = classify_for(&img, Some(Loader::Glibc)).unwrap();
        assert_eq!(glibc.flags, 0);
        assert_eq!(
            kind_at(&glibc.entries, RW_VA + 8),
            Some(EntryKind::Relative)
        );
        // Without the note the same image is glibc, and the override makes
        // it bionic.
        f.loader_note = false;
        let img = f.build();
        assert_eq!(inferred_loader(&img).unwrap(), Loader::Glibc);
        assert_eq!(
            classify_for(&img, Some(Loader::Bionic)).unwrap().flags,
            FLAG_LOADER_BIONIC
        );
    }

    /// A read-only `.dynamic` is not adjusted by glibc, so its pointers are
    /// `Plain`; a `PT_DYNAMIC` whose `PF_W` disagrees with its segment is
    /// refused.
    #[test]
    fn dynamic_flags_decide_its_typing_and_a_disagreement_is_refused() {
        let mut f = Fixture::new();
        f.dyn_writable = false;
        refused(&f, "DynamicPlacement");
        // glibc adjusts a present DT_GNU_HASH even when it is zero, so a zero
        // value is Relative; it adjusts DT_RELA only when non-zero, so a zero
        // DT_RELA is Plain.
        let mut f = Fixture::new();
        f.set(DT_GNU_HASH, 0);
        let layout = classify(&f.build()).unwrap();
        assert_eq!(
            kind_at(&layout.entries, RW_VA + 3 * 16 + 8),
            Some(EntryKind::Relative)
        );
        let mut f = Fixture::new();
        f.relocs.clear();
        f.set(DT_RELA, 0);
        let layout = classify(&f.build()).unwrap();
        assert_eq!(
            kind_at(&layout.entries, RW_VA + 4 * 16 + 8),
            Some(EntryKind::Plain)
        );
    }

    /// A TLS relocation the loader skips when its symbol does not resolve is
    /// refused against an undefined weak symbol, and accepted as a hole
    /// against a defined one.
    #[test]
    fn a_tls_relocation_against_an_undefined_weak_symbol_is_refused() {
        let mut f = Fixture::new();
        f.tls_weak = Some(true);
        refused(&f, "WeakTlsRelocation");
        f.tls_weak = Some(false);
        let layout = classify(&f.build()).unwrap();
        assert_eq!(
            kind_at(&layout.entries, RW_VA + 0x700),
            Some(EntryKind::Hole)
        );
    }

    /// bionic writes an unresolved weak TLS relocation's destination (zero,
    /// or the computed value), so under bionic the word is a hole.
    #[test]
    fn under_bionic_a_weak_tls_relocation_is_a_hole() {
        let mut f = Fixture::new();
        f.tls_weak = Some(true);
        f.relr.clear();
        let layout = classify_for(&f.build(), Some(Loader::Bionic)).unwrap();
        assert_eq!(
            kind_at(&layout.entries, RW_VA + 0x700),
            Some(EntryKind::Hole)
        );
    }

    #[test]
    fn aps2_packing_is_refused() {
        let mut f = Fixture::new();
        f.set(DT_ANDROID_RELA, RELA_VA);
        refused(&f, "PackedRelocations");
        let mut f = Fixture::new();
        f.set(DT_ANDROID_REL, RELA_VA);
        refused(&f, "PackedRelocations");
    }

    #[test]
    fn relr_is_refused_on_bionic_and_android_relr_on_glibc() {
        let mut f = Fixture::new();
        f.loader_note = true;
        refused(&f, "RelrOnBionic");
        let mut f = Fixture::new();
        f.relr.clear();
        f.set(DT_ANDROID_RELR, RELR_VA);
        refused(&f, "AndroidRelr");
    }

    #[test]
    fn lazy_binding_text_relocations_and_rel_form_are_refused() {
        let mut f = Fixture::new();
        f.remove(DT_FLAGS);
        refused(&f, "LazyBinding");
        f.set(DT_BIND_NOW, 0);
        assert!(classify(&f.build()).is_ok(), "DT_BIND_NOW is BIND_NOW");
        let mut f = Fixture::new();
        f.set(DT_TEXTREL, 0);
        refused(&f, "TextRelocations");
        let mut f = Fixture::new();
        f.set(DT_REL, RELA_VA);
        refused(&f, "RelForm");
        let mut f = Fixture::new();
        f.set(DT_JMPREL, RELA_VA);
        f.set(DT_PLTRELSZ, 0);
        f.set(DT_PLTREL, DT_REL);
        refused(&f, "RelForm");
        // Control: a JMPREL in RELA form is accepted.
        f.set(DT_PLTREL, DT_RELA);
        assert!(classify(&f.build()).is_ok());
    }

    #[test]
    fn copy_and_unknown_relocations_are_refused() {
        // A copy into file bytes is refused: glibc copies only as many bytes
        // as the library's symbol holds, so the rest would stay the file's.
        let mut f = Fixture::new();
        f.relocs.push((RW_VA + 0x700, rela_type(true, "copy")));
        refused(&f, "CopyRelocation");
        // A copy into zero-fill writes no file byte and is accepted, with no
        // entry for it; bionic refuses to load any copy relocation.
        let bss = RW_VA + RELRO_LEN + DATA_LEN + 0x40;
        let mut f = Fixture::new();
        f.relr.clear();
        f.relocs.push((bss, rela_type(true, "copy")));
        let layout = classify(&f.build()).unwrap();
        assert_eq!(kind_at(&layout.entries, bss), None);
        match classify_for(&f.build(), Some(Loader::Bionic)) {
            Err(e) => assert!(e.starts_with("CopyRelocation"), "{e}"),
            Ok(_) => panic!("bionic must refuse a copy relocation"),
        }
        let mut f = Fixture::new();
        f.relocs.push((RW_VA + 0x700, 2));
        refused(&f, "RelocationType");
    }

    /// A relocation into read-only bytes or into `.dynamic`, or two that
    /// write overlapping words, is refused; one into zero-fill is accepted
    /// and covers nothing.
    #[test]
    fn relocation_targets_are_checked() {
        let mut f = Fixture::new();
        f.relocs.push((TEXT + 0x10, 8));
        refused(&f, "RelocationTarget");
        let mut f = Fixture::new();
        f.relocs.push((DYN_VA + 0x10, 8));
        refused(&f, "RelocationTarget");
        let mut f = Fixture::new();
        f.relocs.push((RELA_DEST[0] + 4, 8));
        refused(&f, "RelocationOverlap");
        let mut f = Fixture::new();
        f.relocs.push((RW_VA + RELRO_LEN + DATA_LEN + 0x20, 8));
        assert!(classify(&f.build()).is_ok());
    }

    /// bionic reads the `SHT_DYNAMIC` section's string table for names, so
    /// it must be exactly the covered `.dynstr`.
    #[test]
    fn a_dynamic_string_section_other_than_dt_strtab_is_refused() {
        let mut f = Fixture::new();
        for skew in [(8, 0, 0), (0, 8, 0), (0, 0, 8)] {
            f.strtab_skew = skew;
            refused(&f, "DynamicStrtab");
        }
        let mut f = Fixture::new();
        f.sections = false;
        refused(&f, "DynamicStrtab");
    }

    /// Every table `.dynamic` names must lie in `Plain` bytes.
    #[test]
    fn a_table_outside_plain_bytes_is_refused() {
        let mut f = Fixture::new();
        f.set(DT_SYMTAB, RW_VA + RELRO_LEN + 0x40);
        refused(&f, "TableNotCovered");
    }

    /// Without RELRO, `.dynamic` would sit in `FileOnly` bytes, which the
    /// typing does not describe.
    #[test]
    fn a_dynamic_outside_relro_is_refused() {
        let mut f = Fixture::new();
        f.relro = false;
        refused(&f, "DynamicPlacement");
    }

    /// The statics row: a zero static in the file's bytes is a row, an
    /// initialised one or one in zero-fill is not, and a static written by a
    /// relocation is initialised.
    #[test]
    fn the_file_backed_statics_row_names_zero_statics_and_every_pinned_one() {
        let mut f = Fixture::new();
        let zero_fill = f.build();
        let s = module_statics(&zero_fill, &zero_fill, None).unwrap();
        assert_eq!((s.matched, s.rows.len()), (4, 0));
        assert!(s.missing.is_empty());

        f.static_va = STATIC_VA;
        let img = f.build();
        let s = module_statics(&img, &img, None).unwrap();
        assert_eq!(s.rows.len(), 1);
        assert_eq!(s.rows[0].name, STATE_NAME);
        assert_eq!(s.rows[0].file_backed, 8);

        // The module state is pinned: a file-backed byte is a row whatever
        // its value, and whether or not a relocation writes it.
        f.static_initialised = true;
        let img = f.build();
        let s = module_statics(&img, &img, None).unwrap();
        assert_eq!((s.initialised, s.rows.len()), (0, 1));
        let mut f = Fixture::new();
        f.static_va = DATA_RELA_DEST;
        let img = f.build();
        assert_eq!(module_statics(&img, &img, None).unwrap().rows.len(), 1);

        // Any other module static is a row only when zero and unrelocated:
        // the same bytes under another name are initialised data.
        let mut f = Fixture::new();
        f.static_va = STATIC_VA;
        f.static_initialised = true;
        f.drop_symbol = Some(0);
        let img = f.build();
        let s = module_statics(&img, &img, None).unwrap();
        assert_eq!((s.initialised, s.rows.len()), (1, 0));
        f.static_va = DATA_RELA_DEST;
        f.static_initialised = false;
        let img = f.build();
        assert!(module_statics(&img, &img, None).unwrap().rows.is_empty());

        let mut f = Fixture::new();
        f.sections = false;
        let img = f.build();
        let e = module_statics(&img, &img, None).unwrap_err();
        assert!(e.starts_with("StaticsUnchecked"), "{e}");
    }

    /// The debuglink is read by name and its CRC is the standard CRC-32.
    #[test]
    fn the_debuglink_and_its_crc_are_read() {
        assert_eq!(debuglink_crc(b"123456789"), 0xcbf4_3926);
        assert_eq!(debuglink(&Fixture::new().build()).unwrap(), None);
        let mut f = Fixture::new();
        f.debuglink = Some(("libx.debug".to_owned(), 0x1234_5678));
        assert_eq!(
            debuglink(&f.build()).unwrap(),
            Some(("libx.debug".to_owned(), 0x1234_5678))
        );
        f.debuglink = Some(("../libx.debug".to_owned(), 1));
        assert!(
            debuglink(&f.build()).is_err(),
            "a name with a path is refused"
        );
    }
}
