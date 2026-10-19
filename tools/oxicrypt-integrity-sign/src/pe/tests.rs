//! Synthetic PE32+ images: one per shape the classifier must type or
//! refuse.
//!
//! Synthetic because the shapes that decide this classifier (a bound
//! descriptor, an XFG-enabled image, a zero-initialised static inside
//! `.data`'s raw data) cannot be produced by asking a linker nicely.

use oxicrypt_integrity::slot::{BindRecord, EntryKind};
use oxicrypt_integrity::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE};

use super::dwarf::tests::{Loc, Shape, Split, Static, dwarf};
use super::pdb::tests::{pdb, record};
use super::pdb::{S_GDATA32, S_LDATA32, S_PUB32};
use super::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, ReservedField, classify, classify_with,
    is_pe32plus, module_statics, reservation_holes, writable_ranges,
};
use crate::image::{Layout, RelativeEncoding};
use crate::test_support::{put_key_record, test_key};
use crate::{
    SignOptions, after_signing_note, sign_image, sign_image_with, verify_image, write_entries,
};

const IMAGE_BASE: u64 = 0x1_8000_0000;
const PE_OFF: usize = 0x80;
const OPT: usize = PE_OFF + 24;
const OPT_SIZE: usize = 240;
const HEADERS: u32 = 0x400;
/// `IMAGE_SCN_MEM_READ`.
const READ: u32 = 0x4000_0000;

/// Sections: name, RVA, virtual size, raw offset, raw size, characteristics.
const TEXT: (u32, u32, u32, u32) = (0x1000, 0x3000, 0x400, 0x3000);
const RDATA: (u32, u32, u32, u32) = (0x4000, 0x14000, 0x3400, 0x14000);
const DATA: (u32, u32, u32, u32) = (0x18000, 0x1000, 0x17400, 0x200);
const TLS: (u32, u32, u32, u32) = (0x19000, 0x40, 0x17600, 0x200);
const RELOC: (u32, u32, u32, u32) = (0x1a000, 0x100, 0x17800, 0x200);
/// Zero-initialised data in a section of its own, with no file bytes.
const ZBSS: (u32, u32, u32, u32) = (0x1b000, 0x1000, 0, 0);
const FILE_LEN: usize = 0x17a00;
const SIZE_OF_IMAGE: u32 = 0x1c000;
/// Where the boot sequence's integrity test name lies, which makes
/// `LAST_STATUS` a required static.
const BOOT_NAME: u32 = 0x4f80;

/// Where `.rdata`'s tables lie, by RVA.
const KEY_AT: u32 = 0x16100;
const IAT_A: u32 = 0x4200;
const IAT_B: u32 = 0x4218;
const LOAD_CONFIG: u32 = 0x4300;
const CFG_STORAGE: u32 = 0x4500;
const POINTERS: u32 = 0x4600;
const IMPORTS: u32 = 0x4800;
const ILT_A: u32 = 0x4900;
const ILT_B: u32 = 0x4918;
const HINT_A: u32 = 0x4a00;
const HINT_B: u32 = 0x4a20;
const DLL_A: u32 = 0x4b00;
const DLL_B: u32 = 0x4b20;
const DEBUG: u32 = 0x4c00;
const RSDS: u32 = 0x4c40;
const TLS_DIR: u32 = 0x4d00;
const DELAY: u32 = 0x4e00;
const DELAY_NAMES: u32 = 0x4e80;
const BOUND: u32 = 0x4f00;
const SLOT_AT: u32 = 0x6000;

/// `.data` offsets: an initialised module static, a relocated word, and the
/// two pinned statics, past the raw data unless `state_in_file`.
const DATA_INIT: u32 = 0x18020;
const DATA_RELOCATED: u32 = 0x18010;

const GUID: [u8; 16] = [0x5a; 16];
const AGE: u32 = 3;

/// A synthetic DLL: `.text`, `.rdata` (the slot, the key record and every
/// table), `.data`, `.tls` and `.reloc`.
#[derive(Clone)]
struct Fixture {
    machine: u16,
    guard_flags: u32,
    /// Base relocations beyond the standard set: (RVA, type).
    extra_relocs: Vec<(u32, u16)>,
    /// Only the relocations whose destinations are FileOnly: the storage
    /// words and the `.data` word.
    file_only_relocs: bool,
    bound_directory: bool,
    stamped: bool,
    no_lookup_table: bool,
    /// The delay-load IAT's RVA, when the image has one.
    delay_iat: Option<u32>,
    tls_directory: bool,
    /// The certificate table, appended at the end of the file.
    certificate: bool,
    /// `STATE` inside `.data`'s raw data rather than past it.
    state_in_file: bool,
    /// The import descriptors in the reverse of their thunk arrays'
    /// address order, as an MSVC link lays them out.
    descriptors_reversed: bool,
}

impl Fixture {
    fn new() -> Self {
        Self {
            machine: super::MACHINE_AMD64,
            guard_flags: super::GUARD_CF_INSTRUMENTED,
            extra_relocs: Vec::new(),
            file_only_relocs: false,
            bound_directory: false,
            stamped: false,
            no_lookup_table: false,
            delay_iat: None,
            tls_directory: true,
            certificate: false,
            state_in_file: false,
            descriptors_reversed: false,
        }
    }

    /// Every `DIR64` destination the fixture relocates.
    fn relocs() -> Vec<u32> {
        let mut out = vec![
            LOAD_CONFIG + 0x58,
            LOAD_CONFIG + 0x70,
            LOAD_CONFIG + 0x78,
            LOAD_CONFIG + 0x118,
            LOAD_CONFIG + 0x120,
            LOAD_CONFIG + 0x128,
            LOAD_CONFIG + 0x130,
            LOAD_CONFIG + 0x138,
            TLS_DIR,
            TLS_DIR + 8,
            TLS_DIR + 0x10,
            DATA_RELOCATED,
            TLS.0 + 8,
        ];
        out.extend((0..8).map(|i| POINTERS + 8 * i));
        // The storage words themselves, each a relocated code address.
        out.extend((0..7).map(|k| CFG_STORAGE + 8 * k));
        out
    }

    /// `STATE`'s section, numbered from one, and its offset there: inside
    /// `.data`'s raw data, or in `.zbss`.
    fn state_at(&self) -> (u16, u32) {
        if self.state_in_file {
            (3, 0x180)
        } else {
            (6, 0)
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut out = vec![0u8; FILE_LEN];
        let file = |rva: u32| -> usize {
            for (va, vs, ro, _) in [TEXT, RDATA, DATA, TLS, RELOC] {
                if rva >= va && rva < va + vs {
                    return (ro + rva - va) as usize;
                }
            }
            assert!(rva < HEADERS, "no section holds {rva:#x}");
            rva as usize
        };
        let put = |out: &mut Vec<u8>, rva: u32, bytes: &[u8]| {
            let at = file(rva);
            out[at..at + bytes.len()].copy_from_slice(bytes);
        };
        let put64 = |out: &mut Vec<u8>, rva: u32, v: u64| put(out, rva, &v.to_le_bytes());
        let put32 = |out: &mut Vec<u8>, rva: u32, v: u32| put(out, rva, &v.to_le_bytes());
        let va = |rva: u32| IMAGE_BASE + u64::from(rva);

        // Headers.
        out[0..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
        out[0x40..0x80].fill(0x0e);
        out[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
        out[PE_OFF + 4..PE_OFF + 6].copy_from_slice(&self.machine.to_le_bytes());
        out[PE_OFF + 6..PE_OFF + 8].copy_from_slice(&6u16.to_le_bytes());
        out[PE_OFF + 20..PE_OFF + 22].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
        out[PE_OFF + 22..PE_OFF + 24].copy_from_slice(&0x2022u16.to_le_bytes());
        out[OPT..OPT + 2].copy_from_slice(&super::PE32_PLUS_MAGIC.to_le_bytes());
        out[OPT + 24..OPT + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        out[OPT + 32..OPT + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        out[OPT + 36..OPT + 40].copy_from_slice(&0x200u32.to_le_bytes());
        out[OPT + 56..OPT + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
        out[OPT + 60..OPT + 64].copy_from_slice(&HEADERS.to_le_bytes());
        out[OPT + 64..OPT + 68].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        out[OPT + 70..OPT + 72].copy_from_slice(&0x160u16.to_le_bytes());
        out[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = |out: &mut Vec<u8>, i: usize, rva: u32, size: u32| {
            let at = OPT + 112 + 8 * i;
            out[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        };
        let table = OPT + OPT_SIZE;
        for (i, (name, (rva, vs, ro, rs), chars)) in [
            (".text", TEXT, IMAGE_SCN_MEM_EXECUTE | READ | 0x20),
            (".rdata", RDATA, READ | 0x40),
            (".data", DATA, READ | IMAGE_SCN_MEM_WRITE | 0x40),
            (".tls", TLS, READ | IMAGE_SCN_MEM_WRITE | 0x40),
            (".reloc", RELOC, READ | 0x0200_0040),
            (".zbss", ZBSS, READ | IMAGE_SCN_MEM_WRITE | 0x80),
        ]
        .into_iter()
        .enumerate()
        {
            let o = table + 40 * i;
            out[o..o + name.len()].copy_from_slice(name.as_bytes());
            out[o + 8..o + 12].copy_from_slice(&vs.to_le_bytes());
            out[o + 12..o + 16].copy_from_slice(&rva.to_le_bytes());
            out[o + 16..o + 20].copy_from_slice(&rs.to_le_bytes());
            out[o + 20..o + 24].copy_from_slice(&ro.to_le_bytes());
            out[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        }

        // .text: a pattern, so a flipped byte anywhere is visible.
        for (i, b) in out[TEXT.2 as usize..(TEXT.2 + TEXT.3) as usize]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 251) as u8;
        }
        // .rdata: a pattern under the tables, then the tables.
        for (i, b) in out[RDATA.2 as usize + 0x5000..RDATA.2 as usize + 0x6000]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 239) as u8;
        }
        put_key_record(&mut out, file(KEY_AT));
        put(
            &mut out,
            BOOT_NAME,
            oxicrypt_integrity::INTEGRITY_TEST_NAME.as_bytes(),
        );
        let slot = file(SLOT_AT);
        out[slot..slot + 16].copy_from_slice(&SLOT_HEADER_MAGIC);
        out[slot + SLOT_SIZE - 16..slot + SLOT_SIZE].copy_from_slice(&SLOT_FOOTER_MAGIC);

        // Imports: KERNEL32.dll by name and ordinal, bcryptprimitives.dll
        // by name. The thunks on disk repeat the lookup tables.
        put(&mut out, HINT_A + 2, b"GetLastError\0");
        put(&mut out, HINT_B + 2, b"ProcessPrng\0");
        put(&mut out, DLL_A, b"KERNEL32.dll\0");
        put(&mut out, DLL_B, b"bcryptprimitives.dll\0");
        for (at, entries) in [
            (ILT_A, vec![u64::from(HINT_A), (1 << 63) | 5]),
            (ILT_B, vec![u64::from(HINT_B)]),
            (IAT_A, vec![u64::from(HINT_A), (1 << 63) | 5]),
            (IAT_B, vec![u64::from(HINT_B)]),
        ] {
            for (k, e) in entries.iter().enumerate() {
                put64(&mut out, at + 8 * k as u32, *e);
            }
        }
        let lookup_a = if self.no_lookup_table { 0 } else { ILT_A };
        let mut descriptors = [(lookup_a, DLL_A, IAT_A), (ILT_B, DLL_B, IAT_B)];
        if self.descriptors_reversed {
            descriptors.reverse();
        }
        for (k, (lookup, name, thunks)) in descriptors.into_iter().enumerate() {
            let d = IMPORTS + 20 * k as u32;
            put32(&mut out, d, lookup);
            put32(&mut out, d + 4, u32::from(self.stamped && k == 0));
            put32(&mut out, d + 12, name);
            put32(&mut out, d + 16, thunks);
        }
        dir(&mut out, 1, IMPORTS, 60);
        dir(&mut out, 12, IAT_A, 0x28);
        if self.bound_directory {
            dir(&mut out, 11, BOUND, 8);
        }

        // Load configuration: the cookie, the CFG pointers and the XFG
        // pointers are addresses, each relocated.
        put32(&mut out, LOAD_CONFIG, 0x140);
        put64(&mut out, LOAD_CONFIG + 0x58, va(0x18030));
        put64(&mut out, LOAD_CONFIG + 0x70, va(CFG_STORAGE));
        put64(&mut out, LOAD_CONFIG + 0x78, va(CFG_STORAGE + 8));
        put32(&mut out, LOAD_CONFIG + 0x90, self.guard_flags);
        // The XFG, CastGuard and GuardMemcpy fields name storage after the
        // CFG pair; each storage word holds a code address.
        for (k, off) in [0x118u32, 0x120, 0x128, 0x130, 0x138]
            .into_iter()
            .enumerate()
        {
            put64(
                &mut out,
                LOAD_CONFIG + off,
                va(CFG_STORAGE + 0x10 + 8 * k as u32),
            );
        }
        for k in 0..7u32 {
            put64(&mut out, CFG_STORAGE + 8 * k, va(0x1200 + 0x10 * k));
        }
        dir(&mut out, 10, LOAD_CONFIG, 0x140);
        for i in 0..8 {
            put64(&mut out, POINTERS + 8 * i, va(0x1000 + 0x10 * i));
        }

        // CodeView record naming the program database.
        let mut rsds = b"RSDS".to_vec();
        rsds.extend_from_slice(&GUID);
        rsds.extend_from_slice(&AGE.to_le_bytes());
        rsds.extend_from_slice(b"C:\\build\\fixture.pdb\0");
        put(&mut out, RSDS, &rsds);
        put32(&mut out, DEBUG + 12, super::DEBUG_TYPE_CODEVIEW);
        put32(&mut out, DEBUG + 16, rsds.len() as u32);
        put32(&mut out, DEBUG + 20, RSDS);
        put32(&mut out, DEBUG + 24, file(RSDS) as u32);
        dir(&mut out, 6, DEBUG, 28);

        // TLS: the template is .tls's first 0x20 bytes, one word relocated.
        put64(&mut out, TLS_DIR, va(TLS.0));
        put64(&mut out, TLS_DIR + 8, va(TLS.0 + 0x20));
        put64(&mut out, TLS_DIR + 0x10, va(0x18040));
        put(&mut out, TLS.0, &[0x33; 8]);
        put64(&mut out, TLS.0 + 8, va(POINTERS));
        put(&mut out, TLS.0 + 0x20, &[0x44; 0x20]);
        if self.tls_directory {
            dir(&mut out, 9, TLS_DIR, 0x28);
        }

        // .data: initialised bytes, a relocated word, an initialised static.
        put(&mut out, 0x18000, &[0x11; 0x10]);
        put64(&mut out, DATA_RELOCATED, va(POINTERS));
        put(&mut out, DATA_INIT, &[0x22; 8]);

        if let Some(iat) = self.delay_iat {
            put32(&mut out, DELAY, 1);
            put32(&mut out, DELAY + 4, DLL_B);
            // The module handle the delay-load helper stores, in .data.
            put32(&mut out, DELAY + 8, 0x18110);
            put32(&mut out, DELAY + 12, iat);
            put32(&mut out, DELAY + 16, DELAY_NAMES);
            put64(&mut out, DELAY_NAMES, u64::from(HINT_B));
            dir(&mut out, 13, DELAY, 64);
        }

        // Base relocations, one block per page.
        let mut relocs: Vec<(u32, u16)> = Self::relocs()
            .into_iter()
            .filter(|r| {
                !self.file_only_relocs
                    || (CFG_STORAGE..CFG_STORAGE + 0x38).contains(r)
                    || *r == DATA_RELOCATED
            })
            .map(|r| (r, super::REL_DIR64))
            .collect();
        relocs.extend(self.extra_relocs.iter().copied());
        relocs.sort_unstable();
        let mut blocks = Vec::new();
        let mut i = 0;
        while i < relocs.len() {
            let page = relocs[i].0 & !0xfff;
            let mut entries: Vec<u16> = Vec::new();
            while i < relocs.len() && relocs[i].0 & !0xfff == page {
                entries.push((relocs[i].1 << 12) | (relocs[i].0 & 0xfff) as u16);
                i += 1;
            }
            if !entries.len().is_multiple_of(2) {
                entries.push(0);
            }
            blocks.extend_from_slice(&page.to_le_bytes());
            blocks.extend_from_slice(&(8 + 2 * entries.len() as u32).to_le_bytes());
            for e in entries {
                blocks.extend_from_slice(&e.to_le_bytes());
            }
        }
        assert!(blocks.len() <= RELOC.1 as usize);
        put(&mut out, RELOC.0, &blocks);
        dir(&mut out, 5, RELOC.0, blocks.len() as u32);

        if self.certificate {
            out.resize(FILE_LEN + 0x100, 0xcc);
            dir(&mut out, 4, FILE_LEN as u32, 0x100);
        }
        out
    }

    /// The program database in production's shape: each module static an
    /// `S_LDATA32` record under its qualified name, once in the global
    /// records and once in its module's stream; and a code symbol.
    fn pdb(&self, guid: [u8; 16], age: u32) -> Vec<u8> {
        let (seg, off) = self.state_at();
        let statics = [
            (seg, off, "oxicrypt_module::STATE"),
            (6, 0x10, "oxicrypt_integrity::LAST_STATUS"),
            (6, 0x18, "oxicrypt_integrity::ML_DSA_CAST_PASSED"),
            (6, 0x20, "oxicrypt_integrity::SHA256_CAST_PASSED"),
            (3, DATA_INIT - DATA.0, "oxicrypt_thing::INIT"),
        ];
        let mut globals = record(S_PUB32, 1, 0x10, "oxicrypt_ffi_entry");
        let mut module = Vec::new();
        for (seg, off, name) in statics {
            globals.extend(record(S_LDATA32, seg, off, name));
            module.extend(record(S_LDATA32, seg, off, name));
        }
        pdb(guid, age, &globals, &module)
    }

    /// The same statics as a global and as public symbols under their
    /// mangled names, the other shapes a PDB may name them in.
    fn pdb_global_and_public(&self, guid: [u8; 16], age: u32) -> Vec<u8> {
        let (seg, off) = self.state_at();
        let mut globals = record(S_GDATA32, seg, off, "oxicrypt_module::STATE");
        globals.extend(record(
            S_PUB32,
            6,
            0x10,
            "_ZN18oxicrypt_integrity11LAST_STATUS17h0123456789abcdefE",
        ));
        globals.extend(record(
            S_PUB32,
            6,
            0x18,
            "_RNvCs1_18oxicrypt_integrity18ML_DSA_CAST_PASSED",
        ));
        globals.extend(record(
            S_PUB32,
            6,
            0x20,
            "_RNvCs1_18oxicrypt_integrity18SHA256_CAST_PASSED",
        ));
        let module = record(S_LDATA32, 3, DATA_INIT - DATA.0, "oxicrypt_thing::INIT");
        pdb(guid, age, &globals, &module)
    }
}

fn file_of(rva: u32) -> usize {
    for (va, vs, ro, _) in [TEXT, RDATA, DATA, TLS, RELOC] {
        if rva >= va && rva < va + vs {
            return (ro + rva - va) as usize;
        }
    }
    rva as usize
}

fn options(symbols: &[u8]) -> SignOptions<'_> {
    SignOptions {
        loader: None,
        symbols: Some(symbols),
        reserved_against: None,
    }
}

/// The fixture, signed with its program database.
fn signed(f: &Fixture) -> Vec<u8> {
    let mut img = f.build();
    let symbols = f.pdb(GUID, AGE);
    sign_image_with(&mut img, test_key(), &options(&symbols)).unwrap();
    img
}

/// The kind of the entry covering `rva`, counting a `Plain` entry's hole.
fn kind_at(layout: &Layout, rva: u32) -> (EntryKind, u16) {
    let e = layout
        .entries
        .iter()
        .find(|e| rva >= e.rva && rva < e.rva + e.len + e.hole_len())
        .unwrap_or_else(|| panic!("no entry covers {rva:#x}"));
    if rva >= e.rva + e.len {
        return (EntryKind::Hole, 0);
    }
    (e.kind, e.meta)
}

fn import(library: &str, symbol: &str, ordinal: u16) -> BindRecord {
    BindRecord {
        library: library.to_owned(),
        symbol: symbol.to_owned(),
        ordinal,
        addend: 0,
        weak: false,
    }
}

#[test]
fn every_file_backed_byte_is_typed() {
    let img = Fixture::new().build();
    assert!(is_pe32plus(&img));
    let layout = classify(&img).unwrap();
    assert_eq!(layout.relative, RelativeEncoding::FileWord);
    assert_eq!(layout.link_base, IMAGE_BASE, "the link base is ImageBase");
    assert_eq!(layout.file_len, FILE_LEN as u32);
    // Headers Plain, ImageBase Relative, CheckSum Plain without a reference.
    assert_eq!(kind_at(&layout, 0).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, (OPT + 24) as u32).0, EntryKind::Relative);
    assert_eq!(kind_at(&layout, (OPT + 64) as u32).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, HEADERS - 1).0, EntryKind::Plain);
    // Load Config pointers Relative; the storage each loader-written field
    // names FileOnly, its file value signed, though each is also relocated.
    for off in [0x58, 0x70, 0x78, 0x118, 0x120, 0x128, 0x130, 0x138] {
        assert_eq!(
            kind_at(&layout, LOAD_CONFIG + off).0,
            EntryKind::Relative,
            "load config +{off:#x}"
        );
    }
    for k in 0..7 {
        assert_eq!(
            kind_at(&layout, CFG_STORAGE + 8 * k).0,
            EntryKind::FileOnly,
            "storage word {k}"
        );
    }
    assert_eq!(kind_at(&layout, CFG_STORAGE + 0x38).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, POINTERS + 0x38).0, EntryKind::Relative);
    assert_eq!(kind_at(&layout, POINTERS + 0x40).0, EntryKind::Plain);
    // Thunks Bind, one record each; the terminators and the lookup tables
    // Plain.
    assert_eq!(kind_at(&layout, IAT_A), (EntryKind::Bind, 0));
    assert_eq!(kind_at(&layout, IAT_A + 8), (EntryKind::Bind, 1));
    assert_eq!(kind_at(&layout, IAT_A + 16).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, IAT_B), (EntryKind::Bind, 2));
    assert_eq!(kind_at(&layout, ILT_A).0, EntryKind::Plain);
    assert_eq!(
        layout.records,
        vec![
            import("KERNEL32.dll", "GetLastError", 0),
            import("KERNEL32.dll", "", 5),
            import("bcryptprimitives.dll", "ProcessPrng", 0),
        ]
    );
    // .text, .rdata and .reloc Plain; .data FileOnly with no entry for its
    // relocated word; the TLS template Plain with its word Relative, the
    // rest of .tls FileOnly.
    assert_eq!(kind_at(&layout, TEXT.0).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, RELOC.0).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, DATA.0).0, EntryKind::FileOnly);
    assert_eq!(kind_at(&layout, DATA_RELOCATED).0, EntryKind::FileOnly);
    assert_eq!(kind_at(&layout, DATA.0 + DATA.3 - 1).0, EntryKind::FileOnly);
    assert_eq!(kind_at(&layout, TLS.0).0, EntryKind::Plain);
    assert_eq!(kind_at(&layout, TLS.0 + 8).0, EntryKind::Relative);
    assert_eq!(kind_at(&layout, TLS.0 + 0x20).0, EntryKind::FileOnly);
    // File alignment padding past VirtualSize FileOnly, in a read-only
    // section too.
    assert_eq!(kind_at(&layout, RELOC.0 + RELOC.1).0, EntryKind::FileOnly);
    assert_eq!(
        kind_at(&layout, RELOC.0 + RELOC.3 - 1).0,
        EntryKind::FileOnly
    );
    // Nothing past the raw data, nothing in a section with none, nothing
    // left untyped but the slot.
    assert!(
        !layout
            .entries
            .iter()
            .any(|e| (e.rva >= DATA.0 + DATA.3 && e.rva < TLS.0) || e.rva >= ZBSS.0),
        "zero-fill is not file bytes"
    );
    let covered: u64 = layout
        .entries
        .iter()
        .map(|e| u64::from(e.len) + u64::from(e.hole_len()))
        .sum();
    let file_backed = u64::from(HEADERS + TEXT.3 + RDATA.3 + DATA.3 + TLS.3 + RELOC.3);
    assert_eq!(covered + SLOT_SIZE as u64, file_backed);
    assert!(!writable_ranges(&img).unwrap().is_empty());
}

/// Descriptors listed in another order than their thunk arrays lie in: the
/// records are numbered by first use in the table, which is address order,
/// so the slot is canonical and the image signs.
#[test]
fn records_follow_the_thunks_not_the_descriptors() {
    let mut f = Fixture::new();
    f.descriptors_reversed = true;
    let layout = classify(&f.build()).unwrap();
    assert_eq!(kind_at(&layout, IAT_A), (EntryKind::Bind, 0));
    assert_eq!(kind_at(&layout, IAT_B), (EntryKind::Bind, 2));
    assert_eq!(layout.records[0], import("KERNEL32.dll", "GetLastError", 0));
    let img = signed(&f);
    assert!(verify_image(&img).is_ok());
}

#[test]
fn the_storage_is_file_only_whatever_the_guard_flags() {
    let mut f = Fixture::new();
    f.guard_flags = 0;
    let layout = classify(&f.build()).unwrap();
    assert_eq!(kind_at(&layout, CFG_STORAGE).0, EntryKind::FileOnly);
    assert_eq!(kind_at(&layout, CFG_STORAGE + 0x30).0, EntryKind::FileOnly);
    // Without a TLS directory, all of .tls is FileOnly.
    let mut f = Fixture::new();
    f.tls_directory = false;
    let layout = classify(&f.build()).unwrap();
    assert_eq!(kind_at(&layout, TLS.0 + 8).0, EntryKind::FileOnly);
}

#[test]
fn refusals_are_named() {
    let refused = |f: &Fixture, name: &str| {
        let err = classify(&f.build()).unwrap_err();
        assert!(err.starts_with(name), "expected {name}, got: {err}");
    };
    let mut f = Fixture::new();
    f.machine = 0xaa64;
    refused(&f, "Machine");
    // SectionAlignment below a page, and a FileAlignment larger than it.
    for (section, file) in [(0x200u32, 0x200u32), (0x1000, 0x2000), (0x1000, 0x300)] {
        let mut img = Fixture::new().build();
        img[OPT + 32..OPT + 36].copy_from_slice(&section.to_le_bytes());
        img[OPT + 36..OPT + 40].copy_from_slice(&file.to_le_bytes());
        let err = classify(&img).unwrap_err();
        assert!(
            err.starts_with("Alignment"),
            "{section:#x}/{file:#x}: {err}"
        );
    }
    for t in [super::REL_HIGHLOW, super::REL_HIGH, super::REL_LOW, 5] {
        let mut f = Fixture::new();
        f.extra_relocs.push((POINTERS + 0x40, t));
        refused(&f, "RelocationType");
    }
    let mut f = Fixture::new();
    f.extra_relocs.push((DATA.0 + 0x400, super::REL_DIR64));
    refused(&f, "RelocTarget");
    let mut f = Fixture::new();
    f.bound_directory = true;
    refused(&f, "BoundImports");
    let mut f = Fixture::new();
    f.stamped = true;
    refused(&f, "BoundImports");
    let mut f = Fixture::new();
    f.no_lookup_table = true;
    refused(&f, "MissingLookupTable");
    // A relocated word inside a lookup table.
    let mut f = Fixture::new();
    f.extra_relocs.push((ILT_B, super::REL_DIR64));
    refused(&f, "ImportTable");
    // A relocated thunk overlaps its Bind word.
    let mut f = Fixture::new();
    f.extra_relocs.push((IAT_B, super::REL_DIR64));
    refused(&f, "WordOverlap");
    let mut f = Fixture::new();
    f.delay_iat = Some(POINTERS + 0x100);
    refused(&f, "DelayLoadIat");
    let mut f = Fixture::new();
    f.guard_flags |= super::GUARD_XFG_ENABLED;
    refused(&f, "Xfg");
    // Relocated words only in FileOnly bytes: nothing checks a relocated
    // word as loaded, so an edited ImageBase would pass.
    let mut f = Fixture::new();
    f.file_only_relocs = true;
    refused(&f, "UncheckedRelocation");
    // Control: one relocated word in Plain bytes besides.
    f.extra_relocs.push((POINTERS, super::REL_DIR64));
    assert!(classify(&f.build()).is_ok());
    // Controls: a delay-load IAT in .data, which is FileOnly, and the
    // unmodified fixture, are accepted.
    let mut f = Fixture::new();
    f.delay_iat = Some(0x18100);
    assert!(classify(&f.build()).is_ok());
    assert!(classify(&Fixture::new().build()).is_ok());
}

/// The image is refused when an edit of `at` to `value` (little-endian,
/// its width) is refused with `name`; the control is the unedited image.
fn refused_with(img: &[u8], at: usize, value: &[u8], name: &str) {
    let mut t = img.to_vec();
    t[at..at + value.len()].copy_from_slice(value);
    let err = classify(&t).unwrap_err();
    assert!(
        err.starts_with(name),
        "edit at {at:#x}: expected {name}, got: {err}"
    );
}

/// The PE format's alignment rules for the image and each section, and
/// raw data in order without overlap.
#[test]
fn geometry_off_the_format_rules_is_refused() {
    let img = Fixture::new().build();
    assert!(classify(&img).is_ok());
    let sec = |i: usize, d: usize| OPT + OPT_SIZE + 40 * i + d;
    let edits: [(usize, Vec<u8>); 8] = [
        // ImageBase not 64 KiB aligned.
        (OPT + 24, (IMAGE_BASE + 0x1000).to_le_bytes().to_vec()),
        // SizeOfImage not a multiple of SectionAlignment.
        (OPT + 56, (SIZE_OF_IMAGE + 0x10).to_le_bytes().to_vec()),
        // SizeOfHeaders not a multiple of FileAlignment.
        (OPT + 60, (HEADERS + 0x10).to_le_bytes().to_vec()),
        // A section RVA off SectionAlignment.
        (sec(4, 12), (RELOC.0 + 0x10).to_le_bytes().to_vec()),
        // A raw offset and a raw size off FileAlignment.
        (sec(4, 20), (RELOC.2 + 0x10).to_le_bytes().to_vec()),
        (sec(4, 16), (RELOC.3 - 0x10).to_le_bytes().to_vec()),
        // Raw data with no offset.
        (sec(4, 20), 0u32.to_le_bytes().to_vec()),
        // .rdata's raw data over .text's.
        (sec(1, 20), TEXT.2.to_le_bytes().to_vec()),
    ];
    for (at, value) in edits {
        refused_with(&img, at, &value, "Geometry");
    }
}

/// Relocation blocks are 4-byte multiples, each for a 4 KiB page.
#[test]
fn relocation_blocks_off_their_alignment_are_refused() {
    let img = Fixture::new().build();
    let table = file_of(RELOC.0);
    // The first block's page RVA, off its page.
    refused_with(&img, table, &0x4010u32.to_le_bytes(), "RelocationBlock");
    // Its size, a 2-byte multiple only.
    let size = u32::from_le_bytes(img[table + 4..table + 8].try_into().unwrap());
    refused_with(
        &img,
        table + 4,
        &(size - 2).to_le_bytes(),
        "RelocationBlock",
    );
}

/// XFG enabled is refused on the flag alone: with its fields zero, and with
/// them past the structure's Size, where they are absent, never zero.
#[test]
fn xfg_is_refused_on_the_flag_alone() {
    let mut f = Fixture::new();
    f.guard_flags |= super::GUARD_XFG_ENABLED;
    let img = f.build();
    let mut zeroed = img.clone();
    let at = file_of(LOAD_CONFIG + 0x118);
    zeroed[at..at + 24].fill(0);
    assert!(classify(&zeroed).unwrap_err().starts_with("Xfg"));
    // Size 0x118: GuardFlags present, the XFG fields absent.
    refused_with(&img, file_of(LOAD_CONFIG), &0x118u32.to_le_bytes(), "Xfg");
    // Control: the same Size without the flag is accepted, and the storage
    // the absent fields would name is not typed from them.
    let mut short = Fixture::new().build();
    short[file_of(LOAD_CONFIG)..file_of(LOAD_CONFIG) + 4].copy_from_slice(&0x118u32.to_le_bytes());
    let layout = classify(&short).unwrap();
    assert_eq!(kind_at(&layout, CFG_STORAGE).0, EntryKind::FileOnly);
    assert_eq!(
        kind_at(&layout, CFG_STORAGE + 0x10).0,
        EntryKind::Relative,
        "a word no present field names is typed by its relocation alone"
    );
}

/// The delay-load walk stays inside its directory, needs the terminator
/// there, and reads only RVA-based descriptors.
#[test]
fn delay_load_descriptors_are_bounded_and_rva_based() {
    let mut f = Fixture::new();
    f.delay_iat = Some(0x18100);
    let img = f.build();
    assert!(classify(&img).is_ok());
    // The directory's Size covering the descriptor but not the terminator.
    refused_with(
        &img,
        OPT + 112 + 8 * 13 + 4,
        &32u32.to_le_bytes(),
        "DelayLoadDescriptor",
    );
    // A legacy, address-based descriptor; reserved attribute bits.
    for attributes in [0u32, 3, 0x8000_0001] {
        refused_with(
            &img,
            file_of(DELAY),
            &attributes.to_le_bytes(),
            "DelayLoadDescriptor",
        );
    }
}

/// Words the loader writes at load, the TLS index `AddressOfIndex` names and
/// each delay-load descriptor's module handle, are refused in `Plain` bytes
/// and accepted in `.data`, which is `FileOnly`.
#[test]
fn loader_written_words_in_plain_bytes_are_refused() {
    let mut f = Fixture::new();
    f.delay_iat = Some(0x18100);
    let img = f.build();
    assert!(classify(&img).is_ok());
    refused_with(
        &img,
        file_of(TLS_DIR + 0x10),
        &(IMAGE_BASE + u64::from(POINTERS + 0x100)).to_le_bytes(),
        "TlsIndex",
    );
    refused_with(
        &img,
        file_of(DELAY + 8),
        &(POINTERS + 0x100).to_le_bytes(),
        "DelayLoadHandle",
    );
}

/// An image carrying a certificate table is told that `signtool` must sign
/// it again; one without, which is never Authenticode-signed, is told
/// nothing.
#[test]
fn a_certificate_bearing_image_is_told_to_run_signtool_afterwards() {
    let mut f = Fixture::new();
    f.certificate = true;
    let note = after_signing_note(&f.build()).expect("a signed PE image must get the note");
    assert!(note.starts_with("PE:"), "{note}");
    assert!(note.contains("signtool"), "{note}");
    assert!(note.contains("--reserved-against"), "{note}");
    assert_eq!(after_signing_note(&Fixture::new().build()), None);
}

#[test]
fn the_certificate_table_ends_the_signed_image() {
    let mut f = Fixture::new();
    f.certificate = true;
    let img = f.build();
    let layout = classify(&img).unwrap();
    assert_eq!(layout.file_len, FILE_LEN as u32);
    // A certificate table that starts inside the sections is refused.
    let mut bad = img.clone();
    let at = OPT + 112 + 8 * 4;
    bad[at..at + 4].copy_from_slice(&(RELOC.2).to_le_bytes());
    let err = classify(&bad).unwrap_err();
    assert!(err.starts_with("CertificateTable"), "{err}");
}

#[test]
fn a_synthetic_image_signs_verifies_and_localises_tampering() {
    let img = signed(&Fixture::new());
    assert!(verify_image(&img).is_ok());
    for (what, at) in [
        ("a DOS stub byte", 0x40usize),
        ("a section header byte", OPT + OPT_SIZE + 8),
        ("a .text byte", 0x1000),
        ("a Plain .rdata byte", file_of(0x9000)),
        ("a Relative word", file_of(POINTERS)),
        ("a load config pointer", file_of(LOAD_CONFIG + 0x70)),
        ("a .reloc entry", file_of(RELOC.0 + 8)),
        ("a FileOnly .data byte", file_of(DATA.0 + 4)),
        ("a TLS template byte", file_of(TLS.0)),
        ("the ImageBase field", OPT + 25),
        ("CheckSum, with no reference", OPT + 64),
    ] {
        let mut t = img.clone();
        t[at] ^= 0x01;
        assert!(
            verify_image(&t).is_err(),
            "{what} at {at:#x} must be covered"
        );
    }
    // A thunk on disk is overwritten at load: changing it changes nothing.
    let mut t = img.clone();
    t[file_of(IAT_A)] ^= 0x01;
    assert!(verify_image(&t).is_ok(), "a disk thunk is not signed input");
    // The loader-written storage and the alignment padding past
    // VirtualSize are signed from the file.
    for (what, at) in [
        ("the CFG check storage", file_of(CFG_STORAGE)),
        ("the GuardMemcpy storage", file_of(CFG_STORAGE + 0x30)),
        ("alignment padding", file_of(RELOC.0) + RELOC.1 as usize + 4),
    ] {
        let mut t = img.clone();
        t[at] ^= 0x01;
        let err = verify_image(&t).unwrap_err();
        assert!(err.starts_with("SignatureInvalid"), "{what}: {err}");
    }
}

/// The offline check of the imports: an edit of a lookup-table entry, a
/// name or a descriptor is refused, by the signature and, when the slot is
/// re-signed over the old table, by decoding the imports again.
#[test]
fn verify_decodes_the_lookup_tables_against_the_records() {
    let f = Fixture::new();
    let original = f.build();
    let layout = classify(&original).unwrap();
    let img = signed(&f);
    for (what, at, mask) in [
        ("an ordinal lookup entry", file_of(ILT_A + 8), 0x01u8),
        ("an import name", file_of(HINT_B + 3), 0x20),
        (
            "a descriptor's DLL name RVA",
            file_of(IMPORTS + 20 + 12),
            0x20,
        ),
    ] {
        let mut t = img.clone();
        t[at] ^= mask;
        let err = verify_image(&t).unwrap_err();
        assert!(err.starts_with("SignatureInvalid"), "{what}: {err}");
        // The same edit with the slot re-signed over the original table and
        // records: the signature holds, and the import decoding refuses.
        let mut t = original.clone();
        t[at] ^= mask;
        let before = t.clone();
        let err = write_entries(&mut t, &layout, &layout.entries, test_key()).unwrap_err();
        assert!(err.contains("ImportMismatch"), "{what}: {err}");
        // A failed self-check leaves the caller's buffer as it was.
        assert!(
            t == before,
            "{what}: write_entries changed the buffer and failed"
        );
    }
    // Control: re-signing the unedited image over its own table verifies.
    let mut t = original.clone();
    write_entries(&mut t, &layout, &layout.entries, test_key()).unwrap();
    assert!(verify_image(&t).is_ok());
}

#[test]
fn reservation_types_exactly_the_fields_signtool_rewrote() {
    let linked = Fixture::new().build();
    assert!(reservation_holes(&linked, &linked).unwrap().is_empty());
    let mut f = Fixture::new();
    f.certificate = true;
    let mut signed_by_tool = f.build();
    // signtool's CheckSum.
    signed_by_tool[OPT + 64] ^= 0x5a;
    assert_eq!(
        reservation_holes(&linked, &signed_by_tool).unwrap(),
        vec![ReservedField::CheckSum, ReservedField::SecurityDirectory]
    );
    // Against a reference already signed the same way, only CheckSum.
    let mut again = signed_by_tool.clone();
    again[OPT + 65] ^= 0x01;
    assert_eq!(
        reservation_holes(&signed_by_tool, &again).unwrap(),
        vec![ReservedField::CheckSum]
    );
    let mut other = signed_by_tool.clone();
    other[0x40] ^= 1;
    let err = reservation_holes(&linked, &other).unwrap_err();
    assert!(err.starts_with("ReservationDiff"), "{err}");
    let mut other = signed_by_tool.clone();
    other[file_of(0x9000)] ^= 1;
    let err = reservation_holes(&linked, &other).unwrap_err();
    assert!(err.starts_with("ReservationDiff"), "{err}");

    let layout = classify_with(&signed_by_tool, Some(&linked)).unwrap();
    assert_eq!(kind_at(&layout, (OPT + 64) as u32).0, EntryKind::Hole);
    assert_eq!(kind_at(&layout, (OPT + 112 + 32) as u32).0, EntryKind::Hole);
    assert_eq!(
        kind_at(&layout, (OPT + 112 + 40) as u32).0,
        EntryKind::Plain
    );
}

/// Signed against the image as linked, an artifact tolerates the next
/// `signtool` rewriting CheckSum and the certificate table, and nothing
/// else.
#[test]
fn the_reserved_fields_may_change_after_signing_and_no_other_byte() {
    let f = Fixture::new();
    let linked = f.build();
    let symbols = f.pdb(GUID, AGE);
    let mut cert = f.clone();
    cert.certificate = true;
    let mut b = cert.build();
    b[OPT + 64] ^= 0x5a;
    let opts = SignOptions {
        loader: None,
        symbols: Some(&symbols),
        reserved_against: Some(&linked),
    };
    sign_image_with(&mut b, test_key(), &opts).unwrap();
    assert!(verify_image(&b).is_ok());
    // The next signtool: a new CheckSum and a larger certificate table.
    let mut d = b.clone();
    d[OPT + 64] ^= 0x33;
    d[OPT + 112 + 36] = 0x80;
    d.resize(FILE_LEN + 0x180, 0xdd);
    assert!(verify_image(&d).is_ok(), "the measured fields are holes");
    let mut d = b.clone();
    d[OPT + 60] ^= 0x01;
    assert!(verify_image(&d).is_err(), "SizeOfHeaders stays covered");
    // Without the reference CheckSum is covered.
    let mut plain = cert.build();
    sign_image_with(&mut plain, test_key(), &options(&symbols)).unwrap();
    let mut d = plain.clone();
    d[OPT + 64] ^= 0x01;
    assert!(verify_image(&d).is_err());
}

#[test]
fn file_backed_module_state_is_refused_and_zero_fill_state_is_not() {
    let f = Fixture::new();
    let s = module_statics(&f.build(), Some(&f.pdb(GUID, AGE))).unwrap();
    assert!(s.missing.is_empty(), "{:?}", s.missing);
    assert!(s.rows.is_empty(), "{:?}", s.rows);
    assert_eq!(s.initialised, 1, "the initialised .data static is FileOnly");
    // Each static is named twice, in the global records and its module's
    // stream: counted once. The code symbol is not a static.
    assert_eq!(
        s.matched, 5,
        "duplicate records must collapse to one static each"
    );
    // The other shapes a PDB names statics in: a global, and publics under
    // both manglings.
    let s = module_statics(&f.build(), Some(&f.pdb_global_and_public(GUID, AGE))).unwrap();
    assert!(s.missing.is_empty() && s.rows.is_empty(), "{s:?}");
    assert_eq!(s.matched, 5);

    let mut f = Fixture::new();
    f.state_in_file = true;
    let symbols = f.pdb(GUID, AGE);
    let s = module_statics(&f.build(), Some(&symbols)).unwrap();
    assert_eq!(s.rows.len(), 1, "{:?}", s.rows);
    assert_eq!(s.rows[0].name, "oxicrypt_module::STATE");
    let mut img = f.build();
    let pristine = img.clone();
    let err = sign_image_with(&mut img, test_key(), &options(&symbols)).unwrap_err();
    assert!(err.starts_with("FileBackedStatic"), "{err}");
    assert!(err.contains("/MERGE:.bss="), "{err}");
    assert_eq!(img, pristine, "a refused image is not written");
}

#[test]
fn the_statics_come_from_the_pdb_the_image_names() {
    let f = Fixture::new();
    let mut img = f.build();
    let err = sign_image(&mut img, test_key()).unwrap_err();
    assert!(
        err.starts_with("StaticsUnchecked") && err.contains("fixture.pdb"),
        "{err}"
    );
    for (guid, age) in [([0x5b; 16], AGE), (GUID, AGE + 1)] {
        let err = sign_image_with(&mut img, test_key(), &options(&f.pdb(guid, age))).unwrap_err();
        assert!(
            err.starts_with("StaticsUnchecked") && err.contains("GUID and age"),
            "{err}"
        );
    }
    // A PDB that names none of the pinned statics proves nothing.
    let bare = pdb(GUID, AGE, &record(S_PUB32, 1, 0, "oxicrypt_ffi_entry"), &[]);
    let err = sign_image_with(&mut img, test_key(), &options(&bare)).unwrap_err();
    assert!(
        err.starts_with("StaticsUnchecked") && err.contains("STATE"),
        "{err}"
    );
    // A pinned static whose offset lies past its section names no byte the
    // check reads, so it is not found.
    let mut outside = record(S_LDATA32, 6, 0, "oxicrypt_integrity::LAST_STATUS");
    outside.extend(record(
        S_LDATA32,
        6,
        8,
        "oxicrypt_integrity::ML_DSA_CAST_PASSED",
    ));
    outside.extend(record(
        S_LDATA32,
        6,
        0x10,
        "oxicrypt_integrity::SHA256_CAST_PASSED",
    ));
    outside.extend(record(S_LDATA32, 6, ZBSS.1, "oxicrypt_module::STATE"));
    let err = sign_image_with(
        &mut img,
        test_key(),
        &options(&pdb(GUID, AGE, &outside, &[])),
    )
    .unwrap_err();
    assert!(
        err.starts_with("StaticsUnchecked") && err.contains("oxicrypt_module::STATE"),
        "{err}"
    );
    // Control: the same records one byte inside the section are found.
    let mut inside = record(S_LDATA32, 6, 0, "oxicrypt_integrity::LAST_STATUS");
    inside.extend(record(
        S_LDATA32,
        6,
        8,
        "oxicrypt_integrity::ML_DSA_CAST_PASSED",
    ));
    inside.extend(record(
        S_LDATA32,
        6,
        0x10,
        "oxicrypt_integrity::SHA256_CAST_PASSED",
    ));
    inside.extend(record(S_LDATA32, 6, ZBSS.1 - 8, "oxicrypt_module::STATE"));
    let s = module_statics(&img, Some(&pdb(GUID, AGE, &inside, &[]))).unwrap();
    assert!(s.missing.is_empty(), "{:?}", s.missing);

    // Found beside the artifact by the file name the CodeView record ends
    // in.
    let dir = std::env::temp_dir().join(format!("oxicrypt-pdb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let artifact = dir.join("lib.dll");
    assert_eq!(crate::debug_symbols(&artifact, &img).unwrap(), None);
    std::fs::write(dir.join("fixture.pdb"), f.pdb(GUID, AGE + 1)).unwrap();
    let err = crate::debug_symbols(&artifact, &img).unwrap_err();
    assert!(err.starts_with("StaticsUnchecked"), "{err}");
    let matching = f.pdb(GUID, AGE);
    std::fs::write(dir.join("fixture.pdb"), &matching).unwrap();
    assert_eq!(
        crate::debug_symbols(&artifact, &img).unwrap(),
        Some(matching)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_thirty_two_bit_image_is_named_rather_than_lumped_in() {
    let mut img = Fixture::new().build();
    img[OPT..OPT + 2].copy_from_slice(&super::PE32_MAGIC.to_le_bytes());
    assert!(!is_pe32plus(&img));
    assert!(super::unsupported_reason(&img).is_some_and(|r| r.contains("32-bit")));
    assert!(super::unsupported_reason(&Fixture::new().build()).is_none());
    assert!(super::unsupported_reason(b"not a pe at all").is_none());
}

#[test]
fn a_truncated_header_is_refused_rather_than_guessed() {
    let img = Fixture::new().build();
    for (cut, expected) in [
        (1, "not a PE image"),
        (0x3f, "not a PE image"),
        (0x82, "not a PE image"),
        (PE_OFF + 24, "not a PE32+ image"),
    ] {
        let err = classify(&img[..cut]).expect_err("a truncated image must be refused");
        assert_eq!(err, expected, "cut {cut}");
    }
}

/// `--loader` names an ELF loader, so a PE image is refused with one
/// rather than signed as if it were not given.
#[test]
fn a_loader_option_is_refused_for_a_pe_image() {
    let img = Fixture::new().build();
    let options = SignOptions {
        loader: Some(crate::elf::Loader::Glibc),
        ..SignOptions::default()
    };
    let err = crate::classify_with(&img, &options).unwrap_err();
    assert!(err.starts_with("--loader applies to ELF images"), "{err}");
    assert!(crate::classify_with(&img, &SignOptions::default()).is_ok());
}

/// How [`with_sections_as`] lays out the appended sections and the COFF
/// string table that names them.
#[derive(Clone, Copy, Default)]
struct SectionLayout {
    /// COFF symbols written ahead of the string table, so its offset
    /// counts eighteen bytes for each.
    symbols: u32,
    /// The string table's declared length, when not its true one.
    strings_len: Option<u32>,
    /// Each section's `VirtualSize` written as zero.
    no_virtual_size: bool,
}

/// `img` with `sections` appended, each a discardable read-only section
/// with a long name in a COFF string table, as a GNU toolchain links its
/// DWARF.
fn with_sections(img: &[u8], sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
    with_sections_as(img, sections, SectionLayout::default())
}

/// As [`with_sections`], laid out as `layout` says.
fn with_sections_as(img: &[u8], sections: &[(&str, Vec<u8>)], layout: SectionLayout) -> Vec<u8> {
    let mut out = img.to_vec();
    let count = u16::from_le_bytes([out[PE_OFF + 6], out[PE_OFF + 7]]) as usize;
    let mut strings = vec![0u8; 4];
    let mut rva = SIZE_OF_IMAGE;
    for (i, (name, data)) in sections.iter().enumerate() {
        let o = OPT + OPT_SIZE + 40 * (count + i);
        assert!(
            o + 40 <= HEADERS as usize,
            "the headers hold no more sections"
        );
        let field = format!("/{}", strings.len());
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let raw_at = out.len() as u32;
        let raw_len = data.len().next_multiple_of(0x200) as u32;
        out.extend_from_slice(data);
        out.resize((raw_at + raw_len) as usize, 0);
        let virtual_size = if layout.no_virtual_size {
            0
        } else {
            data.len() as u32
        };
        out[o..o + 8].fill(0);
        out[o..o + field.len()].copy_from_slice(field.as_bytes());
        out[o + 8..o + 12].copy_from_slice(&virtual_size.to_le_bytes());
        out[o + 12..o + 16].copy_from_slice(&rva.to_le_bytes());
        out[o + 16..o + 20].copy_from_slice(&raw_len.to_le_bytes());
        out[o + 20..o + 24].copy_from_slice(&raw_at.to_le_bytes());
        out[o + 36..o + 40].copy_from_slice(&(READ | 0x0200_0040).to_le_bytes());
        rva += raw_len.next_multiple_of(0x1000);
    }
    let len = layout.strings_len.unwrap_or(strings.len() as u32);
    strings[..4].copy_from_slice(&len.to_le_bytes());
    let table = out.len() as u32;
    // Symbols the signer does not read: a pattern, so a string table
    // looked for at the symbol table's start reads no name.
    out.extend((0..18 * layout.symbols).map(|i| (i % 7) as u8 + 1));
    out.extend_from_slice(&strings);
    out[PE_OFF + 6..PE_OFF + 8].copy_from_slice(&((count + sections.len()) as u16).to_le_bytes());
    out[PE_OFF + 12..PE_OFF + 16].copy_from_slice(&table.to_le_bytes());
    out[PE_OFF + 16..PE_OFF + 20].copy_from_slice(&layout.symbols.to_le_bytes());
    out[OPT + 56..OPT + 60].copy_from_slice(&rva.to_le_bytes());
    out
}

/// The address of `rva` in the fixture.
const fn va(rva: u32) -> u64 {
    IMAGE_BASE + rva as u64
}

/// The fixture's statics as DWARF describes them: the PDB fixture's, at the
/// same addresses, under their namespaces and mangled names, two of them in
/// the second unit.
fn fixture_statics(f: &Fixture) -> Vec<Static> {
    let (seg, off) = f.state_at();
    let state = if seg == 6 { ZBSS.0 + off } else { DATA.0 + off };
    vec![
        Static::new(
            "oxicrypt_module::STATE",
            Some("_ZN15oxicrypt_module5STATE17h0123456789abcdefE"),
            Loc::Addr(va(state)),
            Some(8),
        ),
        Static::new(
            "oxicrypt_integrity::LAST_STATUS",
            Some("_RNvCs1_18oxicrypt_integrity11LAST_STATUS"),
            Loc::Addr(va(ZBSS.0 + 0x10)),
            Some(1),
        )
        .in_unit(1),
        Static::new(
            "oxicrypt_integrity::ML_DSA_CAST_PASSED",
            Some("_RNvCs1_18oxicrypt_integrity18ML_DSA_CAST_PASSED"),
            Loc::Addr(va(ZBSS.0 + 0x18)),
            Some(1),
        ),
        Static::new(
            "oxicrypt_integrity::SHA256_CAST_PASSED",
            Some("_RNvCs1_18oxicrypt_integrity18SHA256_CAST_PASSED"),
            Loc::Addr(va(ZBSS.0 + 0x20)),
            Some(1),
        )
        .in_unit(1),
        Static::new(
            "oxicrypt_thing::INIT",
            Some("_RNvCs1_14oxicrypt_thing4INIT"),
            Loc::Addr(va(DATA_INIT)),
            Some(8),
        ),
    ]
}

/// The DWARF sections describing `statics`.
fn dwarf_sections_of(statics: &[Static]) -> Vec<(&'static str, Vec<u8>)> {
    let [info, abbrev, strs] = dwarf(statics);
    vec![
        (".debug_abbrev", abbrev),
        (".debug_info", info),
        (".debug_str", strs),
    ]
}

/// The fixture image carrying `statics` as DWARF.
fn dwarf_image(f: &Fixture, statics: &[Static]) -> Vec<u8> {
    with_sections(&f.build(), &dwarf_sections_of(statics))
}

/// The refusal the DWARF route draws for `statics`, the same from
/// [`module_statics`] and from signing.
fn dwarf_refusal(f: &Fixture, statics: &[Static]) -> String {
    let mut img = dwarf_image(f, statics);
    let err = module_statics(&img, None).unwrap_err();
    let signed = sign_image(&mut img, test_key()).unwrap_err();
    assert_eq!(signed, err);
    err
}

/// Without a program database, the DWARF in the image gives the same
/// statics, rows and pinned set as the PDB does, and the image signs.
#[test]
fn the_statics_come_from_dwarf_when_no_pdb_is_given() {
    for state_in_file in [false, true] {
        let mut f = Fixture::new();
        f.state_in_file = state_in_file;
        let img = dwarf_image(&f, &fixture_statics(&f));
        let from_dwarf = module_statics(&img, None).unwrap();
        let from_pdb = module_statics(&img, Some(&f.pdb(GUID, AGE))).unwrap();
        // The PDB names each static by its path, the DWARF by its mangled
        // name, and the DWARF sizes each by its type, the PDB to the next
        // symbol; the rest agrees.
        let shape = |s: &crate::elf::Statics| {
            let rows: Vec<u64> = s.rows.iter().map(|r| r.addr).collect();
            (s.matched, s.initialised, s.missing.clone(), rows)
        };
        assert_eq!(
            shape(&from_dwarf),
            shape(&from_pdb),
            "state in file: {state_in_file}"
        );
        assert_eq!(from_dwarf.matched, 5);
        assert_eq!(from_dwarf.initialised, 1);
        assert!(from_dwarf.missing.is_empty());
        let mut signed = img.clone();
        let result = sign_image(&mut signed, test_key());
        if state_in_file {
            assert_eq!(from_dwarf.rows.len(), 1, "{:?}", from_dwarf.rows);
            assert_eq!(from_dwarf.rows[0].addr, va(DATA.0 + 0x180));
            assert_eq!(from_dwarf.rows[0].size, 8, "STATE's type is 8 bytes");
            let err = result.unwrap_err();
            assert!(err.starts_with("FileBackedStatic"), "{err}");
            assert!(err.contains("LINK=/MERGE:.bss=.zbss"), "{err}");
        } else {
            assert!(from_dwarf.rows.is_empty(), "{:?}", from_dwarf.rows);
            result.unwrap();
            assert!(verify_image(&signed).is_ok());
        }
    }
}

/// Each way the DWARF can fail to name the statics exactly is refused by
/// its own name.
#[test]
fn dwarf_that_does_not_locate_each_pinned_static_once_is_refused() {
    let f = Fixture::new();
    let good = fixture_statics(&f);
    let refusal = |statics: &[Static]| dwarf_refusal(&f, statics);

    let mut twice = good.clone();
    twice.push(good[0].clone().in_unit(1));
    let err = refusal(&twice);
    assert!(
        err.starts_with("DuplicateStatic") && err.contains("oxicrypt_module::STATE"),
        "{err}"
    );

    let mut outside = good.clone();
    outside[0].loc = Loc::Addr(IMAGE_BASE + 0x10_0000);
    let err = refusal(&outside);
    assert!(err.starts_with("StaticOutsideImage"), "{err}");
    let mut below = good.clone();
    below[1].loc = Loc::Addr(0);
    assert!(refusal(&below).starts_with("StaticOutsideImage"));
    // An unpinned module static outside the image, by its linkage name or
    // by its path alone.
    let mut unpinned = good.clone();
    unpinned[4].loc = Loc::Addr(IMAGE_BASE + 0x10_0000);
    let err = refusal(&unpinned);
    assert!(
        err.starts_with("StaticOutsideImage") && err.contains("INIT"),
        "{err}"
    );
    let mut exported = good.clone();
    exported.push(Static::new(
        "oxicrypt_thing::EXPORTED",
        Some("fips_exported"),
        Loc::Addr(IMAGE_BASE + 0x10_0000),
        Some(8),
    ));
    assert!(refusal(&exported).starts_with("StaticOutsideImage"));

    let mut unlocated = good.clone();
    unlocated[2].loc = Loc::Absent;
    let err = refusal(&unlocated);
    assert!(
        err.starts_with("StaticUnlocated") && err.contains("ML_DSA_CAST_PASSED"),
        "{err}"
    );
    // Located, but in a read-only section.
    let mut read_only = good.clone();
    read_only[3].loc = Loc::Addr(va(RDATA.0 + 0x10));
    let err = refusal(&read_only);
    assert!(
        err.starts_with("StaticUnlocated") && err.contains("SHA256_CAST_PASSED"),
        "{err}"
    );
    let mut absent = good.clone();
    absent.remove(0);
    assert!(refusal(&absent).starts_with("StaticUnlocated"));
}

/// A module static is located only by a lone `DW_OP_addr`: any other
/// expression, for a pinned static or not, is refused, and a static with
/// no location at all, which the compiler emitted no storage for, is not
/// a module static.
#[test]
fn a_static_located_by_any_other_expression_is_refused() {
    let f = Fixture::new();
    let good = fixture_statics(&f);
    let mut addr = vec![super::dwarf::OP_ADDR];
    addr.extend(va(ZBSS.0).to_le_bytes());
    // `DW_OP_const8u`: nine bytes, an operand that is not an address.
    let mut constant = addr.clone();
    constant[0] = 0x0e;
    // `DW_OP_addr` then `DW_OP_plus_uconst 0`.
    let mut longer = addr.clone();
    longer.extend([0x23, 0]);
    for (which, expr) in [(0, constant.clone()), (0, longer.clone()), (4, longer)] {
        let mut s = good.clone();
        s[which].loc = Loc::Expr(expr.clone());
        let err = dwarf_refusal(&f, &s);
        assert!(
            err.starts_with("StaticUnlocated"),
            "{which} {expr:02x?}: {err}"
        );
    }
    let mut unemitted = good.clone();
    unemitted.push(Static::new(
        "oxicrypt_thing::KAT",
        Some("_RNvCs1_14oxicrypt_thing3KAT"),
        Loc::Absent,
        Some(8),
    ));
    let s = module_statics(&dwarf_image(&f, &unemitted), None).unwrap();
    assert_eq!(s.matched, 5, "{s:?}");
}

/// A zero, file-backed module static in `.data`: at `.data + 0x180`, past
/// every initialised byte the fixture writes.
fn zero_in_data(path: &str, linkage: Option<&str>) -> Static {
    Static::new(path, linkage, Loc::Addr(va(DATA.0 + 0x180)), Some(8))
}

/// A module static is one by its path or by its linkage name, as the PDB
/// names a static by its path; and a pinned static is named twice whether
/// the second entry with storage repeats its path or its linkage name. A
/// declaration with no location is not a second static.
#[test]
fn a_static_is_matched_by_its_path_or_its_linkage_name() {
    let f = Fixture::new();
    let good = fixture_statics(&f);
    for (linkage, why) in [
        (Some("fips_zero"), "an exported name outside the crate"),
        (None, "no linkage name"),
    ] {
        let mut s = good.clone();
        s.push(zero_in_data("oxicrypt_thing::ZERO", linkage));
        let mut img = dwarf_image(&f, &s);
        let statics = module_statics(&img, None).unwrap();
        assert_eq!(statics.rows.len(), 1, "{why}: {statics:?}");
        assert_eq!(statics.rows[0].addr, va(DATA.0 + 0x180), "{why}");
        let err = sign_image(&mut img, test_key()).unwrap_err();
        assert!(err.starts_with("FileBackedStatic"), "{why}: {err}");
    }

    let state = &good[0];
    let mut by_linkage = good.clone();
    by_linkage.push(Static::new(
        "elsewhere::COPY",
        state.linkage.as_deref(),
        Loc::Addr(va(ZBSS.0 + 0x40)),
        Some(8),
    ));
    let mut by_path = good.clone();
    by_path.push(Static::new(
        "oxicrypt_module::STATE",
        Some("fips_state"),
        Loc::Addr(va(ZBSS.0 + 0x40)),
        Some(8),
    ));
    let mut declared_too = good.clone();
    let mut declaration = state.clone().in_unit(1);
    declaration.loc = Loc::Absent;
    declared_too.push(declaration);
    let mut img = dwarf_image(&f, &declared_too);
    sign_image(&mut img, test_key()).unwrap();
    let mut nested_copy = good.clone();
    nested_copy.push(state.clone().nested());
    for (statics, why) in [
        (by_linkage, "the same linkage name"),
        (by_path, "the same path"),
        (nested_copy, "a copy under a function"),
    ] {
        let err = dwarf_refusal(&f, &statics);
        assert!(
            err.starts_with("DuplicateStatic") && err.contains("oxicrypt_module::STATE"),
            "{why}: {err}"
        );
    }
}

/// A static extends as far as its type's size, not to the next static the
/// DWARF happens to describe; a file-backed module static whose type gives
/// no size is refused.
#[test]
fn a_static_extends_as_far_as_its_type() {
    let f = Fixture::new();
    // INIT left out: nothing is described between ZERO and `.data`'s end,
    // where the fixture writes non-zero bytes in its raw data.
    let mut s: Vec<Static> = fixture_statics(&f).into_iter().take(4).collect();
    let mut img = f.build();
    let at = file_of(DATA.0 + 0x188);
    img[at..at + 8].fill(0x77);
    s.push(zero_in_data(
        "oxicrypt_thing::ZERO",
        Some("_RNvCs1_14oxicrypt_thing4ZERO"),
    ));
    let image = with_sections(&img, &dwarf_sections_of(&s));
    let statics = module_statics(&image, None).unwrap();
    assert_eq!(statics.rows.len(), 1, "{statics:?}");
    assert_eq!((statics.rows[0].size, statics.rows[0].file_backed), (8, 8));

    let last = s.len() - 1;
    s[last].size = None;
    let image = with_sections(&img, &dwarf_sections_of(&s));
    let err = module_statics(&image, None).unwrap_err();
    assert!(
        err.starts_with("StaticUnsized") && err.contains("ZERO"),
        "{err}"
    );
}

/// A static lies in the section whose extent, the larger of its virtual
/// and raw sizes, holds its first byte: at a section's end it is in the
/// next, and past `VirtualSize` inside the raw data it is still inside.
#[test]
fn a_static_lies_in_the_section_that_holds_its_first_byte() {
    let f = Fixture::new();
    let mut s = fixture_statics(&f);
    // `.data` ends where `.tls` begins; `.tls`'s first bytes are its
    // template, which the fixture fills.
    s.push(Static::new(
        "oxicrypt_thing::EDGE",
        Some("_RNvCs1_14oxicrypt_thing4EDGE"),
        Loc::Addr(va(DATA.0 + DATA.1)),
        Some(8),
    ));
    // Inside `.tls`'s raw data, past its virtual size.
    s.push(Static::new(
        "oxicrypt_thing::TAIL",
        Some("_RNvCs1_14oxicrypt_thing4TAIL"),
        Loc::Addr(va(TLS.0 + 0x100)),
        Some(8),
    ));
    let statics = module_statics(&dwarf_image(&f, &s), None).unwrap();
    assert_eq!(
        (statics.matched, statics.initialised),
        (7, 2),
        "{statics:?}"
    );
}

/// A static described under a function, as a C compiler may place a
/// function's `static`, is a static like any other: checked for file
/// backing, location and section by its path or its linkage name.
#[test]
fn a_static_under_a_function_is_checked_as_any_other() {
    let f = Fixture::new();
    let good = fixture_statics(&f);
    let zero = zero_in_data(
        "oxicrypt_thing::ZERO",
        Some("_RNvCs1_14oxicrypt_thing4ZERO"),
    )
    .nested();
    let mut s = good.clone();
    s.push(zero.clone());
    let mut img = dwarf_image(&f, &s);
    let statics = module_statics(&img, None).unwrap();
    assert_eq!(statics.rows.len(), 1, "{statics:?}");
    let err = sign_image(&mut img, test_key()).unwrap_err();
    assert!(err.starts_with("FileBackedStatic"), "{err}");

    let mut addr_then_more = vec![super::dwarf::OP_ADDR];
    addr_then_more.extend(va(DATA.0 + 0x180).to_le_bytes());
    addr_then_more.extend([0x23, 0]);
    let mut s = good.clone();
    let mut other = zero.clone();
    other.loc = Loc::Expr(addr_then_more);
    s.push(other);
    assert!(dwarf_refusal(&f, &s).starts_with("StaticUnlocated"));
    let mut s = good.clone();
    let mut outside = zero;
    outside.loc = Loc::Addr(IMAGE_BASE + 0x10_0000);
    s.push(outside);
    assert!(dwarf_refusal(&f, &s).starts_with("StaticOutsideImage"));

    // A pinned static described only under a function is located there.
    let mut s = good;
    s[0] = s[0].clone().nested();
    let mut img = dwarf_image(&f, &s);
    sign_image(&mut img, test_key()).unwrap();
}

/// A definition that names no static itself takes its name, linkage name
/// and type from the declaration its `DW_AT_specification` or
/// `DW_AT_abstract_origin` names, a static member's included; a
/// declaration with no definition has no storage.
#[test]
fn a_definition_takes_its_identity_from_its_declaration() {
    let f = Fixture::new();
    let good = fixture_statics(&f);
    for split in [Split::Specification, Split::Origin, Split::Member] {
        let mut s = good.clone();
        s[0] = s[0].clone().split(split);
        let mut img = dwarf_image(&f, &s);
        sign_image(&mut img, test_key()).unwrap_or_else(|e| panic!("{split:?}: {e}"));

        let mut s = good.clone();
        s.push(
            zero_in_data(
                "oxicrypt_thing::ZERO",
                Some("_RNvCs1_14oxicrypt_thing4ZERO"),
            )
            .split(split),
        );
        let statics = module_statics(&dwarf_image(&f, &s), None).unwrap();
        assert_eq!(statics.rows.len(), 1, "{split:?}: {statics:?}");
        assert_eq!(statics.rows[0].size, 8, "{split:?}: the declaration's type");
    }
    let mut s = good;
    let mut declared = zero_in_data(
        "oxicrypt_thing::ZERO",
        Some("_RNvCs1_14oxicrypt_thing4ZERO"),
    )
    .split(Split::Specification);
    declared.loc = Loc::Absent;
    s.push(declared);
    let statics = module_statics(&dwarf_image(&f, &s), None).unwrap();
    assert_eq!(statics.matched, 5, "{statics:?}");
}

/// A definition that repeats its name outside the declaration's
/// namespaces still lies in them: a static whose linkage name is no module
/// crate's is a module static by the declaration's path.
#[test]
fn a_named_definition_takes_its_declarations_scope() {
    let f = Fixture::new();
    let mut s = fixture_statics(&f);
    s.push(
        zero_in_data("oxicrypt_thing::COUNTER", Some("fips_counter"))
            .split(Split::NamedSpecification),
    );
    let statics = module_statics(&dwarf_image(&f, &s), None).unwrap();
    assert_eq!(statics.rows.len(), 1, "{statics:?}");
}

/// The shapes the other identity and location rules turn on: a function's
/// static with a linkage name but not external is a static; a declaration
/// with a path and no linkage name names its definition; and an entry both
/// located and marked a declaration is refused.
#[test]
fn identity_rules_hold_for_each_shape_they_name() {
    let f = Fixture::new();
    let good = fixture_statics(&f);
    let mut addr_then_more = vec![super::dwarf::OP_ADDR];
    addr_then_more.extend(va(DATA.0 + 0x180).to_le_bytes());
    addr_then_more.extend([0x23, 0]);
    let mut s = good.clone();
    s.push(
        Static::new(
            "oxicrypt_thing::ZERO",
            Some("_RNvCs1_14oxicrypt_thing4ZERO"),
            Loc::Expr(addr_then_more),
            Some(8),
        )
        .nested()
        .internal(),
    );
    let err = dwarf_refusal(&f, &s);
    assert!(
        err.starts_with("StaticUnlocated") && err.contains("ZERO"),
        "{err}"
    );

    let mut s = good.clone();
    s.push(zero_in_data("oxicrypt_thing::ZERO", None).split(Split::Specification));
    let statics = module_statics(&dwarf_image(&f, &s), None).unwrap();
    assert_eq!(statics.rows.len(), 1, "{statics:?}");

    let mut s = good;
    s.push(
        zero_in_data(
            "oxicrypt_thing::ZERO",
            Some("_RNvCs1_14oxicrypt_thing4ZERO"),
        )
        .declared(),
    );
    let err = dwarf_refusal(&f, &s);
    assert!(
        err.starts_with("NoDwarf") && err.contains("both a declaration and located"),
        "{err}"
    );
}

/// One entry stands for at most one pinned static: an entry whose path is
/// one pinned static's and whose linkage name is another's is refused.
#[test]
fn one_entry_cannot_stand_for_two_pinned_statics() {
    let f = Fixture::new();
    let mut s = fixture_statics(&f);
    s.remove(2);
    s[0].linkage = Some("_RNvCs1_18oxicrypt_integrity18ML_DSA_CAST_PASSED".to_owned());
    let err = dwarf_refusal(&f, &s);
    assert!(
        err.starts_with("DuplicateStatic")
            && err.contains("oxicrypt_module::STATE")
            && err.contains("ML_DSA_CAST_PASSED"),
        "{err}"
    );
}

/// An array's size is its element's times its count, or its bounds'
/// span; a module static whose type gives no size is refused wherever it
/// lies in writable memory.
#[test]
fn an_array_static_is_sized_by_its_elements() {
    let f = Fixture::new();
    let good = fixture_statics(&f);
    for shape in [Shape::Count(4), Shape::Bounds(0, 3)] {
        let mut s = good.clone();
        s.push(
            zero_in_data(
                "oxicrypt_thing::TABLE",
                Some("_RNvCs1_14oxicrypt_thing5TABLE"),
            )
            .shaped(shape),
        );
        let statics = module_statics(&dwarf_image(&f, &s), None).unwrap();
        assert_eq!(statics.rows.len(), 1, "{shape:?}: {statics:?}");
        assert_eq!(statics.rows[0].size, 32, "{shape:?}");
    }
    let mut s = good;
    s.push(Static::new(
        "oxicrypt_thing::OPAQUE",
        Some("_RNvCs1_14oxicrypt_thing6OPAQUE"),
        Loc::Addr(va(ZBSS.0 + 0x80)),
        None,
    ));
    let err = dwarf_refusal(&f, &s);
    assert!(
        err.starts_with("StaticUnsized") && err.contains("OPAQUE"),
        "{err}"
    );
}

/// The COFF string table lies after the symbol table, and a long name must
/// lie inside the length it declares.
#[test]
fn long_section_names_come_from_the_declared_string_table() {
    let f = Fixture::new();
    let statics = fixture_statics(&f);
    let sections = dwarf_sections_of(&statics);
    for layout in [
        SectionLayout {
            symbols: 3,
            ..SectionLayout::default()
        },
        SectionLayout {
            no_virtual_size: true,
            ..SectionLayout::default()
        },
    ] {
        let img = with_sections_as(&f.build(), &sections, layout);
        let s = module_statics(&img, None).unwrap();
        assert_eq!(s.matched, 5);
    }
    // A table declaring only its length field holds no name; one declaring
    // ten bytes cuts the first name short.
    for (declared, why) in [(4, "the 4 bytes"), (10, "not terminated")] {
        let img = with_sections_as(
            &f.build(),
            &sections,
            SectionLayout {
                strings_len: Some(declared),
                ..SectionLayout::default()
            },
        );
        let err = module_statics(&img, None).unwrap_err();
        assert!(
            err.starts_with("NoDwarf") && err.contains(why),
            "{declared}: {err}"
        );
    }
}

/// An image with no DWARF and no program database named, or DWARF the
/// reader cannot use, is refused as `NoDwarf`. One that names a program
/// database not beside it keeps the PDB route's `StaticsUnchecked`, with a
/// remedy for either toolchain.
#[test]
fn an_image_without_usable_dwarf_is_refused() {
    let f = Fixture::new();
    let mut bare = f.build();
    bare[OPT + 112 + 8 * 6..OPT + 112 + 8 * 7].fill(0);
    let err = module_statics(&bare, None).unwrap_err();
    assert!(err.starts_with("NoDwarf"), "{err}");
    let err = module_statics(&f.build(), None).unwrap_err();
    assert!(err.starts_with("StaticsUnchecked"), "{err}");
    assert!(
        err.contains("fixture.pdb") && err.contains("GNU toolchain") && err.contains("DWARF"),
        "{err}"
    );

    let statics = fixture_statics(&f);
    let [mut info, abbrev, strs] = dwarf(&statics);
    info[4] = 5;
    let img = with_sections(
        &f.build(),
        &[
            (".debug_abbrev", abbrev.clone()),
            (".debug_info", info),
            (".debug_str", strs.clone()),
        ],
    );
    let err = module_statics(&img, None).unwrap_err();
    assert!(
        err.starts_with("NoDwarf") && err.contains("version 5"),
        "{err}"
    );
    // `.debug_info` with no `.debug_abbrev`.
    let [info, ..] = dwarf(&statics);
    let img = with_sections(&f.build(), &[(".debug_info", info), (".debug_str", strs)]);
    let err = module_statics(&img, None).unwrap_err();
    assert!(err.starts_with("NoDwarf"), "{err}");
}

/// The file range of the section named `name`.
fn section_bytes(img: &[u8], name: &str) -> std::ops::Range<usize> {
    let parsed = super::parse(img).unwrap();
    let s = parsed
        .sections
        .iter()
        .find(|s| super::section_name(img, &parsed, s).unwrap() == name)
        .unwrap_or_else(|| panic!("no {name} section"));
    let start = s.raw_offset as usize;
    start..start + s.virtual_size.min(s.raw_size) as usize
}

/// An edit of an image's bytes, and the refusal it must draw.
type Edit<'a> = (&'a str, Box<dyn Fn(&mut Vec<u8>) + 'a>);

/// The one offset in `hay` where `needle` lies.
fn only(hay: &[u8], needle: &[u8]) -> usize {
    let at: Vec<usize> = hay
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, w)| (w == needle).then_some(i))
        .collect();
    assert_eq!(at.len(), 1, "{needle:02x?} occurs {} times", at.len());
    at[0]
}

/// A DLL of `oxicrypt-ffi` linked by `cargo zigbuild --target
/// x86_64-pc-windows-gnu` with full debug information and zero-initialised
/// data in `.zbss`, named by `OXICRYPT_GNU_FFI_DLL` (`docs/integrity-signing.md`
/// gives the build): it signs with its statics read from its DWARF, each
/// pinned static located once in `.zbss`, and each edit of its DWARF that
/// leaves a pinned static unnamed, twice named, outside the image, or
/// unreadable is refused by name.
#[test]
#[ignore = "needs a GNU-toolchain oxicrypt-ffi DLL named by OXICRYPT_GNU_FFI_DLL"]
fn a_gnu_toolchain_dll_signs_from_its_dwarf() {
    let path = std::env::var_os("OXICRYPT_GNU_FFI_DLL")
        .expect("OXICRYPT_GNU_FFI_DLL names the DLL this test signs");
    let mut img = std::fs::read(path).unwrap();
    crate::embed_verify_key(&mut img, test_key().public_key()).unwrap();

    let parsed = super::parse(&img).unwrap();
    let sections = super::dwarf_sections(&img, &parsed).unwrap().unwrap();
    let vars = super::dwarf::variables(&sections).unwrap();
    let zbss = parsed
        .sections
        .iter()
        .find(|s| super::section_name(&img, &parsed, s).unwrap() == ".zbss")
        .expect("the DLL is linked with zero-initialised data in .zbss");
    assert_eq!(zbss.raw_size, 0, ".zbss has no file bytes");
    let zbss_va = parsed.image_base + u64::from(zbss.virtual_address);
    let mut state = 0u64;
    for (path, ident, _) in crate::elf::REQUIRED_STATICS {
        let hits: Vec<&super::dwarf::Variable> = vars
            .iter()
            .filter(|v| {
                v.linkage
                    .iter()
                    .chain([&v.path])
                    .any(|n| super::pins(n, path, ident))
            })
            .collect();
        assert_eq!(hits.len(), 1, "{path}: {hits:?}");
        let addr = hits[0]
            .addr()
            .unwrap_or_else(|| panic!("{path} is not located"));
        assert!(
            (zbss_va..zbss_va + u64::from(zbss.virtual_size)).contains(&addr),
            "{path} at {addr:#x} is not in .zbss"
        );
        if path == "oxicrypt_module::STATE" {
            state = addr;
        }
    }
    let statics = module_statics(&img, None).unwrap();
    assert!(
        statics.missing.is_empty() && statics.rows.is_empty(),
        "{statics:?}"
    );
    assert!(statics.matched >= crate::elf::REQUIRED_STATICS.len());
    let mut signed = img.clone();
    sign_image(&mut signed, test_key()).unwrap();
    verify_image(&signed).unwrap();

    let info = section_bytes(&img, ".debug_info");
    let abbrev = section_bytes(&img, ".debug_abbrev");
    let strs = section_bytes(&img, ".debug_str");
    let mut location = vec![super::dwarf::OP_ADDR];
    location.extend_from_slice(&state.to_le_bytes());
    let state_at = info.start + only(&img[info.clone()], &location);
    let edits: Vec<Edit<'_>> = vec![
        // The first unit declares version 5.
        ("NoDwarf", Box::new(|b: &mut Vec<u8>| b[info.start + 4] = 5)),
        // The first abbreviation's first attribute given DW_FORM_strx1.
        (
            "DwarfForm",
            Box::new(|b: &mut Vec<u8>| {
                assert_eq!(b[abbrev.start..abbrev.start + 5], [1, 0x11, 1, 0x25, 0x0e]);
                b[abbrev.start + 4] = 0x25;
            }),
        ),
        // ML_DSA_CAST_PASSED's mangled name respelled as SHA256's.
        (
            "DuplicateStatic",
            Box::new(|b: &mut Vec<u8>| {
                let from = b"18oxicrypt_integrity18ML_DSA_CAST_PASSED";
                let at = strs.start + only(&b[strs.clone()], from);
                b[at..at + from.len()].copy_from_slice(b"18oxicrypt_integrity18SHA256_CAST_PASSED");
            }),
        ),
        // STATE located 256 MiB further on.
        (
            "StaticOutsideImage",
            Box::new(move |b: &mut Vec<u8>| {
                b[state_at + 1..state_at + 9].copy_from_slice(&(state + (1 << 28)).to_le_bytes());
            }),
        ),
        // STATE's location a constant rather than an address.
        (
            "StaticUnlocated",
            Box::new(move |b: &mut Vec<u8>| b[state_at] = 0x0e),
        ),
    ];
    for (name, edit) in &edits {
        let mut b = img.clone();
        edit(&mut b);
        let err = module_statics(&b, None).unwrap_err();
        assert!(err.starts_with(name), "{name}: {err}");
        let err = sign_image(&mut b, test_key()).unwrap_err();
        assert!(err.starts_with(name), "{name}: {err}");
    }
}
