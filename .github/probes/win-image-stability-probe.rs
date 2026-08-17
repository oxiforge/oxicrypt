//! Windows/PE loaded-image stability probe — a DESIGN MEASUREMENT, not production code.
//!
//! Same question as `image-stability-probe.c` on ELF and Mach-O: which parts of a
//! loaded DLL are identical across runs despite ASLR, and do those parts equal the
//! bytes of the file on disk?
//!
//! PE needs its own probe for a structural reason. ELF position-independent code and
//! Mach-O chained fixups route address-dependent references through GOT and
//! `__DATA_CONST`, leaving the code untouched — which is why `r-xp` and `__TEXT` came
//! back stable. PE instead carries a base relocation table and the loader patches the
//! image wherever it lands, and PE relocations **can target `.text` directly**. If they
//! do, "hash the code segment" does not generalise to Windows.
//!
//! So this probe does two things the others do not need to:
//!   1. reads its own memory through `ReadProcessMemory` — the kernel-mediated copy that
//!      is the actual candidate mechanism on Windows, so the measurement exercises the
//!      design rather than a stand-in; and
//!   2. parses the `.reloc` table and reports which sections the fixups land in, which
//!      answers the structural question outright instead of inferring it from 20 runs.
//!
//! The hash is FNV-1a 64. It measures INVARIANCE, not integrity.
//!
//! Build: rustc -O -o win-probe.exe win-image-stability-probe.rs
//! Run:   win-probe.exe <path-to-dll>

use std::fs;

type Handle = *mut u8;

extern "system" {
    fn LoadLibraryA(name: *const u8) -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn ReadProcessMemory(
        process: Handle,
        base: *const u8,
        buffer: *mut u8,
        size: usize,
        read: *mut usize,
    ) -> i32;
}

const FNV_INIT: u64 = 14695981039346656037;

fn fnv1a(data: &[u8], mut h: u64) -> u64 {
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// Kernel-mediated read of our own memory. A wrong address returns `None` rather
/// than invoking undefined behaviour — the property that makes this mechanism
/// acceptable in a boundary crate at all.
fn read_own(addr: usize, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut got: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            addr as *const u8,
            buf.as_mut_ptr(),
            len,
            &mut got,
        )
    };
    if ok == 0 || got != len {
        return None;
    }
    Some(buf)
}

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

struct Section {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw: u32,
    ptr_to_raw: u32,
    characteristics: u32,
}

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: win-probe.exe <dll>");
            std::process::exit(2);
        }
    };

    let mut cpath: Vec<u8> = path.clone().into_bytes();
    cpath.push(0);
    let base = unsafe { LoadLibraryA(cpath.as_ptr()) } as usize;
    if base == 0 {
        eprintln!("LoadLibraryA failed for {path}");
        std::process::exit(2);
    }

    let file = match fs::read(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot read own file: {e}");
            std::process::exit(2);
        }
    };

    // DOS header → e_lfanew at 0x3C → NT headers.
    let dos = read_own(base, 0x40).expect("read DOS header");
    let e_lfanew = u32le(&dos, 0x3c) as usize;
    let nt = read_own(base + e_lfanew, 24).expect("read NT headers");
    assert_eq!(&nt[0..4], b"PE\0\0", "not a PE image");
    let n_sections = u16le(&nt, 6) as usize;
    let size_opt_hdr = u16le(&nt, 20) as usize;
    let sec_table = base + e_lfanew + 24 + size_opt_hdr;

    // The ImageBase field as it appears in the LOADED header.
    //
    // INFORMATIONAL ONLY — do not build a control on this. It was tried as one
    // and it cannot fire: the loader rewrites this field in memory to the actual
    // load address, so `preferred` and `actual` are always equal and the image
    // always appears not to have moved. Measured 2026-08-17: the field read back
    // as an ASLR-shaped `0x7ff9_4079_0000` rather than a link-time base, while
    // 472 fixups existed and `.rdata` differed from the file — i.e. relocations
    // demonstrably had been applied.
    //
    // The control that does work is below, and the analyser applies it: fixups
    // exist AND a fixup-bearing section differs from the file. That pair proves
    // the loader applied relocations, without asking the image where it thinks
    // it was loaded.
    //
    // ImageBase sits at optional-header offset 24 for PE32+ (magic 0x20b).
    let opt = read_own(base + e_lfanew + 24, size_opt_hdr).expect("read optional header");
    let magic = u16le(&opt, 0);
    let image_base: u64 = if magic == 0x20b {
        u64::from_le_bytes([
            opt[24], opt[25], opt[26], opt[27], opt[28], opt[29], opt[30], opt[31],
        ])
    } else {
        u32le(&opt, 28) as u64
    };
    println!(
        "IMAGEBASE informational header_field=0x{:x} actual=0x{:x} \
         note=loader-rewrites-this-field-so-it-is-not-a-control",
        image_base, base
    );

    let raw = read_own(sec_table, 40 * n_sections).expect("read section table");
    let mut sections = Vec::new();
    for i in 0..n_sections {
        let s = &raw[i * 40..(i + 1) * 40];
        let name = String::from_utf8_lossy(&s[0..8])
            .trim_end_matches('\0')
            .to_string();
        sections.push(Section {
            name,
            virtual_size: u32le(s, 8),
            virtual_address: u32le(s, 12),
            size_of_raw: u32le(s, 16),
            ptr_to_raw: u32le(s, 20),
            characteristics: u32le(s, 36),
        });
    }

    // Per-section content hashes: memory vs file, over the bytes that exist in both.
    let mut regions = 0;
    for s in &sections {
        let len = std::cmp::min(s.virtual_size, s.size_of_raw) as usize;
        if len == 0 {
            continue;
        }
        let perms = format!(
            "{}{}{}",
            if s.characteristics & 0x4000_0000 != 0 { 'r' } else { '-' },
            if s.characteristics & 0x8000_0000 != 0 { 'w' } else { '-' },
            if s.characteristics & 0x2000_0000 != 0 { 'x' } else { '-' },
        );
        let mem = read_own(base + s.virtual_address as usize, len);
        let fstart = s.ptr_to_raw as usize;
        let fend = std::cmp::min(fstart + len, file.len());
        let mut fbytes = vec![0u8; len];
        if fstart < file.len() {
            let avail = fend - fstart;
            fbytes[..avail].copy_from_slice(&file[fstart..fend]);
        }
        let hm = match &mem {
            Some(b) => fnv1a(b, FNV_INIT),
            None => 0,
        };
        let hf = fnv1a(&fbytes, FNV_INIT);
        let cmp = match &mem {
            None => "UNKNOWN",
            Some(_) if hm == hf => "MATCH",
            Some(_) => "DIFFER",
        };
        println!(
            "REGION name={} perms={} fileoff=0x{:x} size={} mem={}{:016x} file={:016x} cmp={}",
            s.name,
            perms,
            s.ptr_to_raw,
            len,
            if mem.is_some() { "" } else { "ERR:" },
            hm,
            hf,
            cmp
        );
        regions += 1;
    }
    println!("LOADBASE 0x{base:x} REGIONS {regions}");

    // The structural question: parse .reloc and report which sections the fixups
    // land in. This is a direct answer, not an inference from hash stability.
    match sections.iter().find(|s| s.name == ".reloc") {
        None => println!("RELOC none — image carries no base relocation table"),
        Some(rs) => {
            let len = std::cmp::min(rs.virtual_size, rs.size_of_raw) as usize;
            let data = read_own(base + rs.virtual_address as usize, len)
                .expect("read .reloc");
            let mut counts: Vec<(String, usize)> =
                sections.iter().map(|s| (s.name.clone(), 0)).collect();
            let mut unattributed = 0usize;
            let mut total = 0usize;
            let mut off = 0usize;
            while off + 8 <= data.len() {
                let page_rva = u32le(&data, off);
                let block = u32le(&data, off + 4) as usize;
                if block < 8 || off + block > data.len() {
                    break;
                }
                let entries = (block - 8) / 2;
                for e in 0..entries {
                    let ent = u16le(&data, off + 8 + e * 2);
                    let typ = ent >> 12;
                    if typ == 0 {
                        continue; // IMAGE_REL_BASED_ABSOLUTE — padding
                    }
                    let rva = page_rva + (ent & 0x0fff) as u32;
                    total += 1;
                    match sections.iter().position(|s| {
                        rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size
                    }) {
                        Some(i) => counts[i].1 += 1,
                        None => unattributed += 1,
                    }
                }
                off += block;
            }
            println!("RELOC total={total} unattributed={unattributed}");
            for (name, n) in counts.iter().filter(|(_, n)| *n > 0) {
                println!("RELOC section={name} fixups={n}");
            }
            let text_fixups = counts
                .iter()
                .find(|(n, _)| n == ".text")
                .map(|(_, c)| *c)
                .unwrap_or(0);
            println!(
                "RELOC verdict: .text carries {text_fixups} fixups — {}",
                if text_fixups == 0 {
                    "code segment is NOT relocated, so hashing it generalises from ELF/Mach-O"
                } else {
                    "code segment IS relocated, so hashing it does NOT generalise"
                }
            );
        }
    }
}
