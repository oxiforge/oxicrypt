//! Synthetic chained-fixup images: one per shape the classifier must type
//! or refuse.

use oxicrypt_integrity::slot::{BindRecord, EntryKind};
use oxicrypt_integrity::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE};

use super::{
    LocatorField, classify, classify_with, is_macho64_le, module_statics, reservation_holes,
};
use crate::image::RelativeEncoding;
use crate::test_support::{put_key_record, test_key};
use crate::{SignOptions, sign_image, sign_image_with, verify_image};

/// `VM_PROT_READ`, `_WRITE`, `_EXECUTE`.
const R: u32 = 1;
const W: u32 = 2;
const X: u32 = 4;

/// Where the fixture's pieces lie. Segment addresses differ from their
/// file offsets, so reading one where the other is meant fails a test.
const SLOT_AT: usize = 0x8000;
const KEY_AT: usize = 0x1800;
const CONST_VA: u64 = 0x24000;
const CONST_OFF: u64 = 0x20000;
/// Two pages, so a chain runs on more than one and the capacity test has
/// room to exceed the table.
const CONST_SIZE: u64 = 0x8000;
const DATA_VA: u64 = 0x2c000;
const DATA_OFF: u64 = 0x28000;
const LINKEDIT_VA: u64 = 0x34000;
const LINKEDIT_OFF: u64 = 0x2c000;
const CHAINS_AT: usize = 0x2c000;
const SYMS_AT: usize = 0x2d000;
/// Symbols the fixture's symbol table holds: the four statics the signer
/// requires and one initialised static.
const SYMBOLS: usize = 5;
const STRS_AT: usize = 0x2e000;
const SIG_AT: u64 = 0x2f000;
const FILE_LEN: usize = 0x30000;
const PAGE: u64 = 0x4000;

/// One chained fixup the fixture writes.
#[derive(Clone, Copy)]
enum Fix {
    /// A rebase to `target`, with `high8`.
    Rebase(u64, u8),
    /// A bind of import `index` with an in-word addend.
    Bind(u32, u8),
}

/// One chained import: library ordinal, weak, name, addend.
#[derive(Clone)]
struct Import(u16, bool, &'static str, i64);

/// A synthetic dylib: `__TEXT` (header, code, the key record and the slot),
/// `__DATA_CONST`, `__DATA` and `__LINKEDIT` holding the chains, the
/// symbol table and, optionally, a code signature.
#[derive(Clone)]
pub(super) struct Fixture {
    cpusubtype: u32,
    pointer_format: u16,
    imports_format: u32,
    imports: Vec<Import>,
    /// Fixups as (segment index, offset in segment, fixup).
    fixups: Vec<(usize, u64, Fix)>,
    code_signature: bool,
    dyld_info: bool,
    lazy_pointers: bool,
    /// Put the module's state in a zero-fill section inside `__DATA`'s
    /// file extent.
    state_in_file: bool,
    symtab: bool,
    data_name: &'static str,
    /// The image's `LC_UUID`, when it has one.
    uuid: Option<[u8; 16]>,
    /// A dSYM rather than an image (`MH_DSYM`), its statics named by
    /// `N_STSYM` debug-map entries.
    dsym: bool,
    /// Overrides the `next` field of the chain word at (segment, offset).
    next_override: Option<(usize, u64, u64)>,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self {
            cpusubtype: 0,
            pointer_format: super::DYLD_CHAINED_PTR_64,
            imports_format: super::IMPORT,
            imports: vec![
                Import(1, false, "_malloc", 0),
                Import(2, false, "_weakfn", 0),
            ],
            fixups: vec![
                (1, 0x0, Fix::Bind(0, 0)),
                (1, 0x8, Fix::Bind(1, 0)),
                (1, 0x20, Fix::Rebase(0x1000, 0)),
                (1, 0x28, Fix::Rebase(0x1010, 0x5a)),
                // In __data, FileOnly: traversed, no entry.
                (2, 0x0, Fix::Rebase(0x1020, 0)),
                (2, 0x10, Fix::Bind(0, 0)),
                // In __thread_data, Plain: a Relative entry.
                (2, 0x1000, Fix::Rebase(0x1030, 0)),
            ],
            code_signature: true,
            dyld_info: false,
            lazy_pointers: false,
            state_in_file: false,
            symtab: true,
            data_name: "__DATA",
            uuid: None,
            dsym: false,
            next_override: None,
        }
    }

    pub(super) fn build(&self) -> Vec<u8> {
        let mut out = vec![0u8; FILE_LEN];
        // __TEXT content, so a flipped byte anywhere in it is visible.
        for (i, b) in out[0x1000..0x20000].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        // Initialised __data, and its module static.
        out[DATA_OFF as usize + 0x100..DATA_OFF as usize + 0x108].copy_from_slice(&[7; 8]);

        let mut cmds: Vec<Vec<u8>> = Vec::new();
        let sect = |seg: &str, name: &str, addr: u64, size: u64, off: u64, kind: u32| {
            let mut s = vec![0u8; super::SECTION_64_SIZE];
            s[..name.len()].copy_from_slice(name.as_bytes());
            s[16..16 + seg.len()].copy_from_slice(seg.as_bytes());
            s[32..40].copy_from_slice(&addr.to_le_bytes());
            s[40..48].copy_from_slice(&size.to_le_bytes());
            s[48..52].copy_from_slice(&(off as u32).to_le_bytes());
            s[64..68].copy_from_slice(&kind.to_le_bytes());
            s
        };
        let seg = |name: &str,
                   vm: u64,
                   vmsize: u64,
                   off: u64,
                   filesize: u64,
                   prot: u32,
                   flags: u32,
                   sects: Vec<Vec<u8>>| {
            let mut c = vec![0u8; super::SEGMENT_COMMAND_64_SIZE];
            c[..4].copy_from_slice(&super::LC_SEGMENT_64.to_le_bytes());
            let size = super::SEGMENT_COMMAND_64_SIZE + sects.len() * super::SECTION_64_SIZE;
            c[4..8].copy_from_slice(&(size as u32).to_le_bytes());
            c[8..8 + name.len()].copy_from_slice(name.as_bytes());
            c[24..32].copy_from_slice(&vm.to_le_bytes());
            c[32..40].copy_from_slice(&vmsize.to_le_bytes());
            c[40..48].copy_from_slice(&off.to_le_bytes());
            c[48..56].copy_from_slice(&filesize.to_le_bytes());
            c[56..60].copy_from_slice(&(R | W | X).to_le_bytes());
            c[60..64].copy_from_slice(&prot.to_le_bytes());
            c[64..68].copy_from_slice(&(sects.len() as u32).to_le_bytes());
            c[68..72].copy_from_slice(&flags.to_le_bytes());
            for s in sects {
                c.extend_from_slice(&s);
            }
            c
        };
        cmds.push(seg(
            "__TEXT",
            0,
            0x20000,
            0,
            0x20000,
            R | X,
            0,
            vec![sect("__TEXT", "__text", 0x1000, 0x1f000, 0x1000, 0)],
        ));
        cmds.push(seg(
            "__DATA_CONST",
            CONST_VA,
            CONST_SIZE,
            CONST_OFF,
            CONST_SIZE,
            R | W,
            super::SG_READ_ONLY,
            vec![
                sect("__DATA_CONST", "__got", CONST_VA, 0x10, CONST_OFF, 6),
                sect(
                    "__DATA_CONST",
                    "__const",
                    CONST_VA + 0x10,
                    CONST_SIZE - 0x10,
                    CONST_OFF + 0x10,
                    0,
                ),
            ],
        ));
        let mut data_sects = vec![
            sect(self.data_name, "__data", DATA_VA, 0x1000, DATA_OFF, 0),
            sect(
                self.data_name,
                "__thread_data",
                DATA_VA + 0x1000,
                0x100,
                DATA_OFF + 0x1000,
                super::S_THREAD_LOCAL_REGULAR,
            ),
            sect(self.data_name, "__bss", DATA_VA + 0x4000, 0x100, 0, 1),
        ];
        if self.state_in_file {
            data_sects.push(sect(
                self.data_name,
                "__bss_in",
                DATA_VA + 0x2000,
                0x40,
                0,
                1,
            ));
        }
        if self.lazy_pointers {
            data_sects.push(sect(
                self.data_name,
                "__la_symbol_ptr",
                DATA_VA + 0x3000,
                0x10,
                DATA_OFF + 0x3000,
                super::S_LAZY_SYMBOL_POINTERS,
            ));
        }
        cmds.push(seg(
            self.data_name,
            DATA_VA,
            0x8000,
            DATA_OFF,
            0x4000,
            R | W,
            0,
            data_sects,
        ));
        cmds.push(seg(
            "__LINKEDIT",
            LINKEDIT_VA,
            0x4000,
            LINKEDIT_OFF,
            0x4000,
            R,
            0,
            Vec::new(),
        ));
        let linkedit_data = |cmd: u32, off: u64, size: u64| {
            let mut c = vec![0u8; 16];
            c[..4].copy_from_slice(&cmd.to_le_bytes());
            c[4..8].copy_from_slice(&16u32.to_le_bytes());
            c[8..12].copy_from_slice(&(off as u32).to_le_bytes());
            c[12..16].copy_from_slice(&(size as u32).to_le_bytes());
            c
        };
        cmds.push(linkedit_data(
            super::LC_DYLD_CHAINED_FIXUPS,
            CHAINS_AT as u64,
            0x800,
        ));
        if self.symtab {
            let mut c = vec![0u8; 24];
            c[..4].copy_from_slice(&super::LC_SYMTAB.to_le_bytes());
            c[4..8].copy_from_slice(&24u32.to_le_bytes());
            c[8..12].copy_from_slice(&(SYMS_AT as u32).to_le_bytes());
            c[12..16].copy_from_slice(&(SYMBOLS as u32).to_le_bytes());
            c[16..20].copy_from_slice(&(STRS_AT as u32).to_le_bytes());
            c[20..24].copy_from_slice(&0x400u32.to_le_bytes());
            cmds.push(c);
        }
        for (cmd, path) in [
            (super::LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
            (super::LC_LOAD_WEAK_DYLIB, "/usr/lib/libweak.dylib"),
        ] {
            let size = (24 + path.len() + 1).next_multiple_of(8);
            let mut c = vec![0u8; size];
            c[..4].copy_from_slice(&cmd.to_le_bytes());
            c[4..8].copy_from_slice(&(size as u32).to_le_bytes());
            c[8..12].copy_from_slice(&24u32.to_le_bytes());
            c[24..24 + path.len()].copy_from_slice(path.as_bytes());
            cmds.push(c);
        }
        if self.code_signature {
            cmds.push(linkedit_data(
                super::LC_CODE_SIGNATURE,
                SIG_AT,
                FILE_LEN as u64 - SIG_AT,
            ));
            for b in &mut out[SIG_AT as usize..] {
                *b = 0xfa;
            }
        }
        if let Some(uuid) = self.uuid {
            let mut c = vec![0u8; 24];
            c[..4].copy_from_slice(&super::LC_UUID.to_le_bytes());
            c[4..8].copy_from_slice(&24u32.to_le_bytes());
            c[8..24].copy_from_slice(&uuid);
            cmds.push(c);
        }
        if self.dyld_info {
            let mut c = vec![0u8; 48];
            c[..4].copy_from_slice(&super::LC_DYLD_INFO_ONLY.to_le_bytes());
            c[4..8].copy_from_slice(&48u32.to_le_bytes());
            cmds.push(c);
        }
        let sizeofcmds: usize = cmds.iter().map(Vec::len).sum();
        out[0..4].copy_from_slice(&super::MH_MAGIC_64.to_le_bytes());
        out[4..8].copy_from_slice(&super::CPU_TYPE_ARM64.to_le_bytes());
        out[8..12].copy_from_slice(&self.cpusubtype.to_le_bytes());
        let filetype: u32 = if self.dsym { 0xa } else { 6 };
        out[12..16].copy_from_slice(&filetype.to_le_bytes());
        out[16..20].copy_from_slice(&(cmds.len() as u32).to_le_bytes());
        out[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());
        let mut at = super::MACH_HEADER_64_SIZE;
        for c in &cmds {
            out[at..at + c.len()].copy_from_slice(c);
            at += c.len();
        }

        self.write_chains(&mut out);
        if self.symtab {
            self.write_symbols(&mut out);
        }
        out[SLOT_AT..SLOT_AT + 16].copy_from_slice(&SLOT_HEADER_MAGIC);
        out[SLOT_AT + SLOT_SIZE - 16..SLOT_AT + SLOT_SIZE].copy_from_slice(&SLOT_FOOTER_MAGIC);
        for b in &mut out[SLOT_AT + 16..SLOT_AT + SLOT_SIZE - 16] {
            *b = 0;
        }
        put_key_record(&mut out, KEY_AT);
        out
    }

    /// Segment index to (vmaddr, fileoff).
    fn seg_at(index: usize) -> (u64, u64) {
        match index {
            0 => (0, 0),
            1 => (CONST_VA, CONST_OFF),
            2 => (DATA_VA, DATA_OFF),
            _ => (LINKEDIT_VA, LINKEDIT_OFF),
        }
    }

    fn write_chains(&self, out: &mut [u8]) {
        let blob = &mut out[CHAINS_AT..CHAINS_AT + 0x800];
        let put32 =
            |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let starts = 32usize;
        let imports_at = 0x200usize;
        let symbols_at = 0x400usize;
        put32(blob, 0, 0);
        put32(blob, 4, starts as u32);
        put32(blob, 8, imports_at as u32);
        put32(blob, 12, symbols_at as u32);
        put32(blob, 16, self.imports.len() as u32);
        put32(blob, 20, self.imports_format);
        put32(blob, 24, 0);
        put32(blob, starts, 4);
        let mut next_info = 24usize;
        for seg in 0..4usize {
            let mut fixes: Vec<(u64, Fix)> = self
                .fixups
                .iter()
                .filter(|f| f.0 == seg)
                .map(|f| (f.1, f.2))
                .collect();
            if fixes.is_empty() {
                put32(blob, starts + 4 + 4 * seg, 0);
                continue;
            }
            fixes.sort_by_key(|f| f.0);
            let pages = (fixes.iter().map(|f| f.0).max().unwrap() / PAGE + 1) as usize;
            put32(blob, starts + 4 + 4 * seg, next_info as u32);
            let sis = starts + next_info;
            let size = 22 + 2 * pages;
            put32(blob, sis, size as u32);
            blob[sis + 4..sis + 6].copy_from_slice(&(PAGE as u16).to_le_bytes());
            blob[sis + 6..sis + 8].copy_from_slice(&self.pointer_format.to_le_bytes());
            let (vm, _) = Self::seg_at(seg);
            blob[sis + 8..sis + 16].copy_from_slice(&vm.to_le_bytes());
            blob[sis + 20..sis + 22].copy_from_slice(&(pages as u16).to_le_bytes());
            for p in 0..pages {
                let first = fixes.iter().find(|f| f.0 / PAGE == p as u64);
                let start = first.map_or(0xffff, |f| (f.0 - p as u64 * PAGE) as u16);
                blob[sis + 22 + 2 * p..sis + 24 + 2 * p].copy_from_slice(&start.to_le_bytes());
            }
            next_info += size.next_multiple_of(8);
        }
        // The chain words go into the image after the blob is complete.
        let mut words: Vec<(usize, u64)> = Vec::new();
        for seg in 0..4usize {
            let mut fixes: Vec<(u64, Fix)> = self
                .fixups
                .iter()
                .filter(|f| f.0 == seg)
                .map(|f| (f.1, f.2))
                .collect();
            fixes.sort_by_key(|f| f.0);
            let (_, fileoff) = Self::seg_at(seg);
            for (i, (off, fix)) in fixes.iter().enumerate() {
                let mut next = fixes
                    .get(i + 1)
                    .filter(|n| n.0 / PAGE == off / PAGE)
                    .map_or(0, |n| (n.0 - off) / 4);
                if let Some((s, o, n)) = self.next_override
                    && s == seg
                    && o == *off
                {
                    next = n;
                }
                let raw = match *fix {
                    Fix::Rebase(target, high8) => target | (u64::from(high8) << 36) | (next << 51),
                    Fix::Bind(index, addend) => {
                        u64::from(index) | (u64::from(addend) << 24) | (next << 51) | (1 << 63)
                    }
                };
                words.push(((fileoff + off) as usize, raw));
            }
        }
        // Imports and their names.
        let mut names = vec![0u8];
        for (i, Import(ordinal, weak, name, addend)) in self.imports.iter().enumerate() {
            let name_off = names.len() as u64;
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            match self.imports_format {
                super::IMPORT => {
                    let raw =
                        u64::from(*ordinal & 0xff) | (u64::from(*weak) << 8) | (name_off << 9);
                    put32(blob, imports_at + 4 * i, raw as u32);
                }
                super::IMPORT_ADDEND => {
                    let raw =
                        u64::from(*ordinal & 0xff) | (u64::from(*weak) << 8) | (name_off << 9);
                    put32(blob, imports_at + 8 * i, raw as u32);
                    put32(blob, imports_at + 8 * i + 4, (*addend as i32) as u32);
                }
                _ => {
                    let raw = u64::from(*ordinal) | (u64::from(*weak) << 16) | (name_off << 32);
                    blob[imports_at + 16 * i..imports_at + 16 * i + 8]
                        .copy_from_slice(&raw.to_le_bytes());
                    blob[imports_at + 16 * i + 8..imports_at + 16 * i + 16]
                        .copy_from_slice(&addend.to_le_bytes());
                }
            }
        }
        blob[symbols_at..symbols_at + names.len()].copy_from_slice(&names);
        for (at, raw) in words {
            out[at..at + 8].copy_from_slice(&raw.to_le_bytes());
        }
    }

    fn write_symbols(&self, out: &mut [u8]) {
        let state_sect = if self.state_in_file { 7u8 } else { 6 };
        let state_va = if self.state_in_file {
            DATA_VA + 0x2000
        } else {
            DATA_VA + 0x4000
        };
        let syms: [(&str, u8, u64); SYMBOLS] = [
            ("__RNvCs1_15oxicrypt_module5STATE", state_sect, state_va),
            (
                "__RNvCs1_18oxicrypt_integrity11LAST_STATUS",
                state_sect,
                state_va + 8,
            ),
            (
                "__RNvCs1_18oxicrypt_integrity18ML_DSA_CAST_PASSED",
                state_sect,
                state_va + 0x10,
            ),
            (
                "__RNvCs1_18oxicrypt_integrity18SHA256_CAST_PASSED",
                state_sect,
                state_va + 0x18,
            ),
            ("__RNvCs1_15oxicrypt_module4INIT", 4, DATA_VA + 0x100),
        ];
        let mut strs = vec![0u8];
        for (i, (name, n_sect, value)) in syms.iter().enumerate() {
            let at = SYMS_AT + i * super::NLIST_64_SIZE;
            out[at..at + 4].copy_from_slice(&(strs.len() as u32).to_le_bytes());
            out[at + 4] = if self.dsym {
                super::N_STSYM
            } else {
                super::N_SECT
            };
            out[at + 5] = *n_sect;
            out[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
            strs.extend_from_slice(name.as_bytes());
            strs.push(0);
        }
        out[STRS_AT..STRS_AT + strs.len()].copy_from_slice(&strs);
    }
}

fn record(library: &str, symbol: &str, weak: bool) -> BindRecord {
    BindRecord {
        library: library.to_owned(),
        symbol: symbol.to_owned(),
        ordinal: 0,
        addend: 0,
        weak,
    }
}

/// The kind of the entry covering `rva`, and its `meta`.
fn kind_at(layout: &crate::image::Layout, rva: u64) -> (EntryKind, u16) {
    let rva = u32::try_from(rva).unwrap();
    let e = layout
        .entries
        .iter()
        .find(|e| rva >= e.rva && rva < e.rva + e.len)
        .unwrap_or_else(|| panic!("no entry covers {rva:#x}"));
    (e.kind, e.meta)
}

#[test]
fn a_chained_dylib_types_every_file_backed_byte() {
    let img = Fixture::new().build();
    assert!(is_macho64_le(&img));
    let layout = classify(&img).unwrap();
    assert_eq!(layout.relative, RelativeEncoding::ChainedPtr64);
    assert_eq!(layout.link_base, 0);
    assert_eq!(layout.file_len, SIG_AT as u32, "file_len stops at dataoff");
    // The header and load commands are typed, as Plain.
    assert_eq!(kind_at(&layout, 0), (EntryKind::Plain, 0));
    assert_eq!(kind_at(&layout, 0x40), (EntryKind::Plain, 0));
    // __DATA_CONST: binds to two records, rebases Relative, the rest Plain.
    assert_eq!(kind_at(&layout, CONST_VA), (EntryKind::Bind, 0));
    assert_eq!(kind_at(&layout, CONST_VA + 8), (EntryKind::Bind, 1));
    assert_eq!(kind_at(&layout, CONST_VA + 0x20).0, EntryKind::Relative);
    assert_eq!(kind_at(&layout, CONST_VA + 0x28).0, EntryKind::Relative);
    assert_eq!(kind_at(&layout, CONST_VA + 0x30).0, EntryKind::Plain);
    assert_eq!(
        layout.records,
        vec![
            record("/usr/lib/libSystem.B.dylib", "malloc", false),
            record("/usr/lib/libweak.dylib", "weakfn", true),
        ],
        "the `_` is removed and a weak-linked library makes the import weak"
    );
    // __DATA: FileOnly, with no entry for the fixups inside it, and the
    // thread-local template Plain with its rebase Relative.
    assert_eq!(kind_at(&layout, DATA_VA).0, EntryKind::FileOnly);
    assert_eq!(kind_at(&layout, DATA_VA + 0x10).0, EntryKind::FileOnly);
    assert_eq!(kind_at(&layout, DATA_VA + 0x1000).0, EntryKind::Relative);
    assert_eq!(kind_at(&layout, DATA_VA + 0x1008).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, DATA_VA + 0x1100).0, EntryKind::FileOnly);
    assert_eq!(
        kind_at(&layout, DATA_VA + 0x3fff).0,
        EntryKind::FileOnly,
        "a file byte under zero-fill sections is FileOnly"
    );
    // __LINKEDIT up to dataoff Plain, nothing past it.
    assert_eq!(kind_at(&layout, LINKEDIT_VA).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, LINKEDIT_VA + 0x2fff).0, EntryKind::Plain);
    assert!(
        !layout
            .entries
            .iter()
            .any(|e| u64::from(e.rva) + u64::from(e.len) > LINKEDIT_VA + 0x3000),
        "the code-signature blob is outside the extent"
    );
    // No entry covers the slot, and nothing else is left untyped.
    let covered: u64 = layout
        .entries
        .iter()
        .map(|e| u64::from(e.len) + u64::from(e.hole_len()))
        .sum();
    assert_eq!(
        covered + SLOT_SIZE as u64,
        0x20000 + CONST_SIZE + 0x4000 + 0x3000
    );
}

#[test]
fn the_offset_format_and_addend_imports_decode() {
    let mut f = Fixture::new();
    f.pointer_format = super::DYLD_CHAINED_PTR_64_OFFSET;
    f.imports_format = super::IMPORT_ADDEND64;
    f.imports[0].3 = -16;
    f.fixups[0].2 = Fix::Bind(0, 4);
    let layout = classify(&f.build()).unwrap();
    assert_eq!(layout.relative, RelativeEncoding::ChainedPtr64Offset);
    assert_eq!(
        layout.records[0].addend, -12,
        "the import's addend plus the word's"
    );
    let mut f = Fixture::new();
    f.imports_format = super::IMPORT_ADDEND;
    f.imports[1].3 = 0x20;
    assert_eq!(classify(&f.build()).unwrap().records[1].addend, 0x20);
}

/// The slot budget `--show` prints is what signing writes: the stored
/// entry count and the string table of the signed slot, for a dylib whose
/// binds carry records.
#[test]
fn the_slot_budget_is_what_signing_writes() {
    use oxicrypt_integrity::slot::{OFF_COUNT, OFF_STRTAB_LEN};
    let mut img = Fixture::new().build();
    let budget = crate::slot_budget(&classify(&img).unwrap()).unwrap();
    assert!(budget.fits());
    assert!(
        budget.string_table > 0,
        "premise: the fixture binds imports"
    );
    sign_image(&mut img, test_key()).unwrap();
    let at = crate::image::find_slot(&img).unwrap();
    let word = |off: usize| u32::from_le_bytes(img[at + off..at + off + 4].try_into().unwrap());
    assert_eq!(word(OFF_COUNT) as usize, budget.stored);
    assert_eq!(word(OFF_STRTAB_LEN) as usize, budget.string_table);
}

#[test]
fn a_chained_dylib_signs_verifies_and_localises_tampering() {
    let mut img = Fixture::new().build();
    sign_image(&mut img, test_key()).unwrap();
    assert!(verify_image(&img).is_ok());
    for (what, at) in [
        ("a header byte", 0x10usize),
        ("a load command byte", 0x40),
        ("a __TEXT byte", 0x4000),
        ("a Plain __DATA_CONST byte", (CONST_OFF + 0x100) as usize),
        ("a FileOnly __data byte", (DATA_OFF + 0x100) as usize),
        ("an import table byte", CHAINS_AT + 0x200),
        ("a symbol string", STRS_AT + 4),
    ] {
        let mut t = img.clone();
        t[at] ^= 0x01;
        assert!(
            verify_image(&t).is_err(),
            "{what} at {at:#x} must be covered"
        );
    }
    // The code-signature blob is outside the signed image.
    let mut blob = img.clone();
    blob[SIG_AT as usize + 0x10] ^= 0xff;
    assert!(verify_image(&blob).is_ok());
}

/// The offline check of the words the signature does not cover: a bind
/// word's ordinal, a chain's `next` and a word's bind bit.
#[test]
fn verify_decodes_every_chain_word_against_its_record_and_kind() {
    let mut img = Fixture::new().build();
    sign_image(&mut img, test_key()).unwrap();
    let word_at = (CONST_OFF) as usize;

    // The ordinal: the first bind now names import 1.
    let mut ordinal = img.clone();
    ordinal[word_at] ^= 1;
    let err = verify_image(&ordinal).unwrap_err();
    assert!(err.starts_with("FixupMismatch"), "{err}");

    // `next`: the chain now skips a word.
    let mut next = img.clone();
    let rebase = word_at + 0x20;
    let raw = u64::from_le_bytes(next[rebase..rebase + 8].try_into().unwrap());
    let raw = (raw & !(0xfff << 51)) | (4 << 51);
    next[rebase..rebase + 8].copy_from_slice(&raw.to_le_bytes());
    let err = verify_image(&next).unwrap_err();
    assert!(
        err.starts_with("FixupMismatch") || err.starts_with("ChainInvalid"),
        "{err}"
    );

    // The bind bit, on a bind word: it becomes a rebase.
    let mut bit = img.clone();
    bit[word_at + 7] ^= 0x80;
    assert!(verify_image(&bit).is_err());
    // And on a rebase: it becomes a bind.
    let mut bit = img.clone();
    bit[word_at + 0x27] ^= 0x80;
    assert!(verify_image(&bit).is_err());

    // Control: the same image unchanged verifies.
    assert!(verify_image(&img).is_ok());
}

#[test]
fn refusals_are_named() {
    let refused = |f: &Fixture, name: &str| {
        let err = classify(&f.build()).unwrap_err();
        assert!(err.starts_with(name), "expected {name}, got: {err}");
    };
    let mut f = Fixture::new();
    f.dyld_info = true;
    refused(&f, "OpcodeFixups");
    let mut f = Fixture::new();
    f.lazy_pointers = true;
    refused(&f, "LazyPointers");
    let mut f = Fixture::new();
    f.cpusubtype = super::CPU_SUBTYPE_ARM64E;
    refused(&f, "Arm64e");
    for format in super::ARM64E_FORMATS {
        let mut f = Fixture::new();
        f.pointer_format = format;
        refused(&f, "Arm64e");
    }
    let mut f = Fixture::new();
    f.pointer_format = 3;
    refused(&f, "PointerFormat");
    for ordinal in [0u16, 0xff, 0xfe, 0xfd] {
        let mut f = Fixture::new();
        f.imports[0].0 = ordinal;
        refused(&f, "SpecialOrdinal");
    }
    let mut f = Fixture::new();
    f.imports[0].2 = "malloc";
    refused(&f, "ChainInvalid");
    let mut f = Fixture::new();
    f.data_name = "__MYDATA";
    refused(&f, "WritableSegment");
    // A fixup in __TEXT.
    let mut f = Fixture::new();
    f.fixups.push((0, 0x3000, Fix::Rebase(0x1000, 0)));
    refused(&f, "FixupTarget");
    // A chain that leaves its page.
    let mut f = Fixture::new();
    f.next_override = Some((1, 0x28, 0x1000));
    refused(&f, "ChainInvalid");
    // A chain that runs past the segment's file bytes into zero-fill.
    let mut f = Fixture::new();
    f.fixups.push((2, 0x3ffc, Fix::Rebase(0x1000, 0)));
    refused(&f, "ChainInvalid");
    // Two words four bytes apart overlap.
    let mut f = Fixture::new();
    f.fixups.push((1, 0x2c, Fix::Rebase(0x1000, 0)));
    refused(&f, "ChainInvalid");
    // A rebase with a reserved bit set.
    let mut f = Fixture::new();
    f.fixups[2].2 = Fix::Rebase(0x1000 | (1 << 44), 0);
    refused(&f, "ChainInvalid");
    // Control: the unmodified fixture is accepted.
    assert!(classify(&Fixture::new().build()).is_ok());
}

#[test]
fn reservation_types_exactly_the_fields_that_differ() {
    let a = Fixture::new().build();
    assert!(reservation_holes(&a, &a).unwrap().is_empty());
    // The fixture's LC_CODE_SIGNATURE is the ninth command: find it.
    let cs = locate(&a, super::LC_CODE_SIGNATURE);
    let linkedit = locate_segment(&a, "__LINKEDIT");
    let mut b = a.clone();
    b[cs + 12] ^= 0x10;
    assert_eq!(
        reservation_holes(&a, &b).unwrap(),
        vec![LocatorField::DataSize]
    );
    b[linkedit + 32] ^= 0x10;
    b[linkedit + 48] ^= 0x10;
    b[cs + 8] ^= 0x10;
    assert_eq!(
        reservation_holes(&a, &b).unwrap(),
        vec![
            LocatorField::DataOff,
            LocatorField::DataSize,
            LocatorField::VmSize,
            LocatorField::FileSize
        ]
    );
    let mut other = a.clone();
    other[8] ^= 1;
    let err = reservation_holes(&a, &other).unwrap_err();
    assert!(err.starts_with("ReservationDiff"), "{err}");

    // datasize alone: a 4-byte hole there, the rest of the header Plain.
    // (0x1000 becomes 0x800: the blob still lies inside __LINKEDIT.)
    let mut b = a.clone();
    b[cs + 13] ^= 0x18;
    let layout = classify_with(&b, Some(&a)).unwrap();
    let holes: Vec<_> = layout
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Hole)
        .collect();
    assert_eq!(holes.len(), 1);
    assert_eq!((holes[0].file_off as usize, holes[0].len), (cs + 12, 4));
}

/// Signed against a reference, an artifact tolerates the next `codesign`
/// rewriting the measured fields, and nothing else.
#[test]
fn a_reserved_field_may_change_after_signing_and_no_other_header_byte() {
    let a = Fixture::new().build();
    let cs = locate(&a, super::LC_CODE_SIGNATURE);
    let linkedit = locate_segment(&a, "__LINKEDIT");
    // datasize 0x1000 becomes 0x800 and filesize 0x4000 becomes 0x3800,
    // the blob still inside __LINKEDIT.
    let mut b = a.clone();
    b[cs + 13] ^= 0x18;
    b[linkedit + 49] ^= 0x78;
    let options = SignOptions {
        loader: None,
        symbols: None,
        reserved_against: Some(&a),
    };
    sign_image_with(&mut b, test_key(), &options).unwrap();
    assert!(verify_image(&b).is_ok());
    let mut d = b.clone();
    d[cs + 12] ^= 0x01;
    d[linkedit + 48] ^= 0x01;
    assert!(verify_image(&d).is_ok(), "the measured fields are holes");
    let mut d = b.clone();
    d[cs + 8] ^= 0x01;
    assert!(
        verify_image(&d).is_err(),
        "dataoff did not differ, so it stays covered"
    );
    let mut d = b.clone();
    d[linkedit + 32] ^= 0x01;
    assert!(verify_image(&d).is_err(), "vmsize stays covered");
}

#[test]
fn file_backed_module_state_is_refused_and_zero_fill_state_is_not() {
    let s = module_statics(&Fixture::new().build(), None).unwrap();
    assert!(s.missing.is_empty(), "{:?}", s.missing);
    assert!(s.rows.is_empty(), "{:?}", s.rows);
    assert_eq!(
        s.initialised, 1,
        "the initialised __data static is FileOnly"
    );

    let mut f = Fixture::new();
    f.state_in_file = true;
    let s = module_statics(&f.build(), None).unwrap();
    assert!(
        s.rows
            .iter()
            .any(|r| r.name.contains("15oxicrypt_module5STATE")),
        "{:?}",
        s.rows
    );
    let mut img = f.build();
    let pristine = img.clone();
    let err = sign_image(&mut img, test_key()).unwrap_err();
    assert!(err.starts_with("FileBackedStatic"), "{err}");
    assert!(err.contains("rename_section"), "{err}");
    assert_eq!(img, pristine, "a refused image is not written");

    let mut f = Fixture::new();
    f.symtab = false;
    let err = sign_image(&mut f.build(), test_key()).unwrap_err();
    assert!(err.starts_with("StaticsUnchecked"), "{err}");
}

#[test]
fn an_extent_beyond_the_table_is_too_many_entries() {
    let mut f = Fixture::new();
    // Every word of __DATA_CONST from 0x40 a fixup, rebases and binds
    // alternating: no run repeats, so each word is a stored entry, past
    // the table's `MAX_ENTRIES`.
    for i in 0..(CONST_SIZE - 0x40) / 8 {
        let fix = if i % 2 == 0 {
            Fix::Rebase(0x1000, 0)
        } else {
            Fix::Bind(0, 0)
        };
        f.fixups.push((1, 0x40 + 8 * i, fix));
    }
    let err = sign_image(&mut f.build(), test_key()).unwrap_err();
    assert!(err.contains("more than the table can hold"), "{err}");
}

#[test]
fn a_universal_or_big_endian_file_is_named() {
    let fat = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
    assert!(!is_macho64_le(&fat));
    assert!(super::unsupported_reason(&fat).is_some_and(|r| r.contains("thin slice")));
    let fat64 = [0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 2];
    assert!(super::unsupported_reason(&fat64).is_some_and(|r| r.contains("universal")));
    let cigam = 0xcffa_edfeu32.to_le_bytes();
    assert!(super::unsupported_reason(&cigam).is_some_and(|r| r.contains("big-endian")));
    assert!(super::unsupported_reason(&Fixture::new().build()).is_none());
}

/// File offset of the first load command `cmd`.
fn locate(img: &[u8], cmd: u32) -> usize {
    let ncmds = u32::from_le_bytes(img[16..20].try_into().unwrap());
    let mut at = 32;
    for _ in 0..ncmds {
        let c = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        if c == cmd {
            return at;
        }
        at += u32::from_le_bytes(img[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    panic!("no load command {cmd:#x}");
}

/// File offset of the segment command named `name`.
fn locate_segment(img: &[u8], name: &str) -> usize {
    let ncmds = u32::from_le_bytes(img[16..20].try_into().unwrap());
    let mut at = 32;
    for _ in 0..ncmds {
        let c = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        if c == super::LC_SEGMENT_64 && img[at + 8..at + 8 + name.len()] == *name.as_bytes() {
            return at;
        }
        at += u32::from_le_bytes(img[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    panic!("no segment {name}");
}

/// Signing options supplying `symbols` as the image's dSYM.
fn with_symbols(symbols: &[u8]) -> SignOptions<'_> {
    SignOptions {
        loader: None,
        symbols: Some(symbols),
        reserved_against: None,
    }
}

/// A stripped image is checked from its dSYM, matched by `LC_UUID`; a
/// dSYM of another build is refused, and a file-backed static it names is
/// refused as from the image's own table.
#[test]
fn the_statics_come_from_a_dsym_with_the_images_uuid() {
    let uuid = [7u8; 16];
    let mut image = Fixture::new();
    image.symtab = false;
    image.uuid = Some(uuid);
    let mut dsym = Fixture::new();
    dsym.uuid = Some(uuid);
    dsym.dsym = true;
    let symbols = dsym.build();
    // Control: without the dSYM the stripped image is refused.
    let err = sign_image(&mut image.build(), test_key()).unwrap_err();
    assert!(err.starts_with("StaticsUnchecked"), "{err}");
    let s = module_statics(&image.build(), Some(&symbols)).unwrap();
    assert!(s.missing.is_empty() && s.rows.is_empty(), "{s:?}");
    let mut img = image.build();
    sign_image_with(&mut img, test_key(), &with_symbols(&symbols)).unwrap();
    assert!(verify_image(&img).is_ok());

    let mut other = dsym.clone();
    other.uuid = Some([8u8; 16]);
    let err = sign_image_with(
        &mut image.build(),
        test_key(),
        &with_symbols(&other.build()),
    )
    .unwrap_err();
    assert!(
        err.starts_with("StaticsUnchecked") && err.contains("LC_UUID"),
        "{err}"
    );

    let mut image = image.clone();
    image.state_in_file = true;
    let mut dsym = dsym.clone();
    dsym.state_in_file = true;
    let err =
        sign_image_with(&mut image.build(), test_key(), &with_symbols(&dsym.build())).unwrap_err();
    assert!(err.starts_with("FileBackedStatic"), "{err}");
}

/// The dSYM is found beside the artifact as `<artifact>.dSYM`, by UUID.
#[test]
fn the_dsym_is_found_beside_the_artifact_by_uuid() {
    let dir = std::env::temp_dir().join(format!("oxicrypt-dsym-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let dwarf = dir.join("lib.dylib.dSYM/Contents/Resources/DWARF");
    std::fs::create_dir_all(&dwarf).unwrap();
    let mut image = Fixture::new();
    image.uuid = Some([7u8; 16]);
    let img = image.build();
    let artifact = dir.join("lib.dylib");
    let mut dsym = image.clone();
    dsym.dsym = true;
    dsym.uuid = Some([9u8; 16]);
    std::fs::write(dwarf.join("lib.dylib"), dsym.build()).unwrap();
    let err = crate::debug_symbols(&artifact, &img).unwrap_err();
    assert!(err.starts_with("StaticsUnchecked"), "{err}");
    dsym.uuid = Some([7u8; 16]);
    let matching = dsym.build();
    std::fs::write(dwarf.join("lib.dylib"), &matching).unwrap();
    assert_eq!(
        crate::debug_symbols(&artifact, &img).unwrap(),
        Some(matching)
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(crate::debug_symbols(&artifact, &img).unwrap(), None);
}

/// The dSYM refusal names its cause: an artifact with no `LC_UUID`, which no
/// dSYM can match; a candidate that is not a Mach-O file; and a candidate of
/// another build.
#[test]
fn the_dsym_refusal_names_its_cause() {
    let dir = std::env::temp_dir().join(format!("oxicrypt-dsym-cause-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let dwarf = dir.join("lib.dylib.dSYM/Contents/Resources/DWARF");
    std::fs::create_dir_all(&dwarf).unwrap();
    let artifact = dir.join("lib.dylib");
    let mut dsym = Fixture::new();
    dsym.dsym = true;
    dsym.uuid = Some([7u8; 16]);
    std::fs::write(dwarf.join("lib.dylib"), dsym.build()).unwrap();
    let no_uuid = Fixture::new().build();
    let err = crate::debug_symbols(&artifact, &no_uuid).unwrap_err();
    assert!(err.starts_with("StaticsUnchecked"), "{err}");
    assert!(err.contains("no LC_UUID"), "{err}");
    let mut image = Fixture::new();
    image.uuid = Some([7u8; 16]);
    let img = image.build();
    std::fs::write(dwarf.join("lib.dylib"), b"not a Mach-O file").unwrap();
    let err = crate::debug_symbols(&artifact, &img).unwrap_err();
    assert!(err.starts_with("StaticsUnchecked"), "{err}");
    assert!(err.contains("cannot be read as a dSYM"), "{err}");
    dsym.uuid = Some([9u8; 16]);
    std::fs::write(dwarf.join("lib.dylib"), dsym.build()).unwrap();
    let err = crate::debug_symbols(&artifact, &img).unwrap_err();
    assert!(err.contains("LC_UUID differs"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A header byte that changes nothing the classifier reads (the
/// `LC_UUID`), a rebase's target and a bind's in-word addend are each
/// refused by `--verify`: the first two by the signature, the third by the
/// chain-word check.
#[test]
fn a_uuid_byte_a_relative_target_and_a_bind_addend_are_refused() {
    let mut f = Fixture::new();
    f.uuid = Some([7u8; 16]);
    let mut img = f.build();
    sign_image(&mut img, test_key()).unwrap();
    assert!(verify_image(&img).is_ok());
    let uuid = locate(&img, super::LC_UUID) + 8;
    let mut t = img.clone();
    t[uuid] ^= 1;
    let err = verify_image(&t).unwrap_err();
    assert!(err.starts_with("SignatureInvalid"), "{err}");
    let rebase = (CONST_OFF + 0x20) as usize;
    let mut t = img.clone();
    t[rebase] ^= 0x10;
    let err = verify_image(&t).unwrap_err();
    assert!(err.starts_with("SignatureInvalid"), "{err}");
    let bind = CONST_OFF as usize;
    let mut t = img.clone();
    t[bind + 3] ^= 0x10;
    let err = verify_image(&t).unwrap_err();
    assert!(err.starts_with("FixupMismatch"), "{err}");
}

/// `--loader` names an ELF loader, so a Mach-O image is refused with one
/// rather than signed as if it were not given.
#[test]
fn a_loader_option_is_refused_for_a_mach_o_image() {
    let img = Fixture::new().build();
    let options = SignOptions {
        loader: Some(crate::elf::Loader::Glibc),
        ..SignOptions::default()
    };
    let err = crate::classify_with(&img, &options).unwrap_err();
    assert!(err.starts_with("--loader applies to ELF images"), "{err}");
    assert!(crate::classify_with(&img, &SignOptions::default()).is_ok());
    let mut signed = img.clone();
    sign_image(&mut signed, test_key()).unwrap();
    let err = crate::verify_image_for(&signed, options.loader).unwrap_err();
    assert!(err.starts_with("--loader applies to ELF images"), "{err}");
    assert!(crate::verify_image_for(&signed, None).is_ok());
}
