//! Typed loaded-image probe for PE32+ DLLs (Windows x64).
//!
//! A DESIGN MEASUREMENT of what the Windows loader does to a DLL, not the
//! integrity oracle: the oracle is the signed module at initialisation. The
//! probe loads the DLL, reads the headers and every section back through
//! `ReadProcessMemory`, the kernel-mediated route the verifier uses, and
//! applies the second extent's entry kinds:
//!
//! * `Plain`: every byte of the headers, of each read-only section's
//!   file-backed bytes (`min(VirtualSize, SizeOfRawData)`) outside the typed
//!   words: loaded value equals the file value.
//! * `Relative`: each `DIR64` base-relocation destination in a read-only
//!   section: loaded value minus the load delta equals the file value. The
//!   optional header's `ImageBase` passes either as the file holds it or as
//!   moved by the delta, and each run logs which (`IMAGEBASE_FIELD`).
//! * `Bind`: each IAT thunk the import directory enumerates: loaded value
//!   equals `GetProcAddress` of its name or ordinal in the module it names.
//! * `Hole`: the CFG check and dispatch pointer storage, only when the image
//!   is `IMAGE_GUARD_CF_INSTRUMENTED`.
//! * `FileOnly`: every file-backed byte of a writable section, read from the
//!   file `GetModuleFileNameA` reports.
//!
//! Every required condition sets a bit; 0 is the pass. The probe always ends
//! with one `RESULT status=N` line.
//!
//! * bit 0 (1): typing, every Plain byte equals the file
//! * bit 1 (2): length, the file holds every section's raw data and the
//!   certificate table lies inside it
//! * bit 2 (4): refusal, a bound import directory, a delay-load directory, an
//!   import descriptor with a non-zero TimeDateStamp or no lookup table, a
//!   base relocation other than `DIR64` or padding, an XFG-enabled image
//! * bit 3 (8): Bind thunks equal their resolution
//! * bit 4 (16): FileOnly sections present and readable from the file
//! * bit 5 (32): control, the load delta is non-zero and at least one
//!   `DIR64` destination moved, so the run says something (the header's
//!   ImageBase never counts)
//! * bit 6 (64): setup, the DLL loaded and every region read back
//! * bit 7 (128): Relative words normalise
//!
//! Options:
//!
//! * `--simulate DELTA`: load nothing; build the loaded image from the file
//!   the way the loader would (Relative words moved by DELTA, thunks set to a
//!   stand-in resolution) and type that. It drives the parser, the typing and
//!   every mutation on a host without the Windows loader and proves nothing
//!   about the loader itself.
//! * `--imagebase-rewritten`: with `--simulate`, also move the header's
//!   ImageBase by DELTA, as the Windows loader was observed to do.
//! * `--mutate NAME`: change one value a check consumes, after loading and
//!   parsing, so that check and only that check fails.
//! * `--list-mutations`: print each mutation name and the bit it must set.
//!
//! Build: rustc -O -o pe-typed-probe.exe pe-typed-probe.rs

use std::collections::HashMap;

const B_TYPING: u32 = 1;
const B_LENGTH: u32 = 2;
const B_REFUSE: u32 = 4;
const B_BIND: u32 = 8;
const B_FILEONLY: u32 = 16;
const B_CONTROL: u32 = 32;
const B_SETUP: u32 = 64;
const B_RELATIVE: u32 = 128;

const MUTATIONS: &[(&str, u32)] = &[
    ("header-plain", B_TYPING), // a byte of the DOS stub
    ("text-plain", B_TYPING),   // a byte in the middle of .text
    ("rdata-plain", B_TYPING),  // a Plain word of another read-only section
    ("length", B_LENGTH),       // the opened length, one byte short
    ("refuse", B_REFUSE),       // a bound import directory, parsed
    ("bind", B_BIND),           // the first thunk's resolution, +8
    ("fileonly", B_FILEONLY),   // the FileOnly bytes, unreadable
    ("no-slide", B_CONTROL),    // every Relative word reads unmoved
    ("relative", B_RELATIVE),   // a Plain .text word typed Relative
    ("xfg", B_REFUSE),          // IMAGE_GUARD_XFG_ENABLED, set in the parsed GuardFlags
];

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Relative,
    /// The optional header's ImageBase. Whether the loader rewrites it in the
    /// mapped header when it relocates is not settled by a primary source
    /// this probe can cite, so either value passes: the file's, or the file's
    /// plus the load delta. Each run logs which it saw (`IMAGEBASE_FIELD`),
    /// and the field never counts as a word the delta moved.
    ImageBaseField,
    Hole,
    Bind(String, Import),
}

#[derive(Clone, Debug, PartialEq)]
enum Import {
    Name(String),
    Ordinal(u16),
}

struct Section {
    name: String,
    va: u32,
    vsize: u32,
    rawptr: u32,
    rawsize: u32,
    chars: u32,
    /// Why no loader would map this section as described, if so: its RVA
    /// range wraps 32 bits, runs past SizeOfImage, or starts inside the
    /// headers. Such a section is refused and never read.
    bad: Option<String>,
}

impl Section {
    fn backed(&self) -> u32 {
        std::cmp::min(self.vsize, self.rawsize)
    }
}

struct Pe {
    image_base: u64,
    size_of_headers: u32,
    opt: usize,
    secs: Vec<Section>,
    dirs: Vec<(u32, u32)>,
}

struct Ctx {
    status: u32,
    mutate: Option<String>,
}

impl Ctx {
    fn fail(&mut self, bit: u32, msg: &str) {
        println!("FAIL[{bit}] {msg}");
        self.status |= bit;
    }
    fn mutating(&self, n: &str) -> bool {
        self.mutate.as_ref().map(|m| m == n).unwrap_or(false)
    }
    fn finish(&self) -> ! {
        println!("RESULT status={} {}", self.status, if self.status == 0 { "PASS" } else { "FAIL" });
        std::process::exit(self.status as i32)
    }
}

fn get(b: &[u8], off: usize, n: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(n)?)?;
    let mut v = 0u64;
    for (i, x) in s.iter().enumerate() {
        v |= (*x as u64) << (8 * i);
    }
    Some(v)
}

fn cstr(b: &[u8], off: usize) -> Option<String> {
    let s = b.get(off..)?;
    let end = s.iter().position(|c| *c == 0)?;
    Some(String::from_utf8_lossy(&s[..end]).into_owned())
}

fn parse(f: &[u8]) -> Result<Pe, String> {
    if f.get(0..2) != Some(b"MZ".as_ref()) {
        return Err("not a PE image".into());
    }
    let pe = get(f, 0x3c, 4).ok_or("truncated")? as usize;
    if f.get(pe..pe + 4) != Some(b"PE\0\0".as_ref()) {
        return Err("no PE signature".into());
    }
    let nsec = get(f, pe + 6, 2).ok_or("truncated")? as usize;
    let optsize = get(f, pe + 20, 2).ok_or("truncated")? as usize;
    let opt = pe + 24;
    if get(f, opt, 2) != Some(0x20b) {
        return Err("not PE32+".into());
    }
    let image_base = get(f, opt + 24, 8).ok_or("truncated")?;
    let size_of_image = get(f, opt + 56, 4).ok_or("truncated")? as u32;
    let size_of_headers = get(f, opt + 60, 4).ok_or("truncated")? as u32;
    let ndirs = get(f, opt + 108, 4).ok_or("truncated")? as usize;
    if ndirs > 16 || 112 + 8 * ndirs > optsize {
        return Err(format!("{ndirs} data directories do not fit the optional header"));
    }
    let mut dirs = Vec::new();
    for i in 0..ndirs {
        let rva = get(f, opt + 112 + 8 * i, 4).ok_or("truncated")? as u32;
        let size = get(f, opt + 116 + 8 * i, 4).ok_or("truncated")? as u32;
        dirs.push((rva, size));
    }
    while dirs.len() < 16 {
        dirs.push((0, 0));
    }
    let mut secs = Vec::new();
    for i in 0..nsec {
        let e = opt + optsize + 40 * i;
        let raw = f.get(e..e + 8).ok_or("truncated section table")?;
        let name = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
        let vsize = get(f, e + 8, 4).ok_or("truncated")? as u32;
        let va = get(f, e + 12, 4).ok_or("truncated")? as u32;
        let rawsize = get(f, e + 16, 4).ok_or("truncated")? as u32;
        let bad = match va.checked_add(std::cmp::max(vsize, rawsize)) {
            None => Some(format!("RVA range 0x{va:x}+0x{:x} wraps 32 bits", std::cmp::max(vsize, rawsize))),
            Some(end) if end > size_of_image => Some(format!("RVA range ends at 0x{end:x}, past SizeOfImage 0x{size_of_image:x}")),
            Some(_) if va < size_of_headers => Some(format!("RVA 0x{va:x} lies inside the headers")),
            Some(_) => None,
        };
        secs.push(Section {
            name,
            vsize,
            va,
            rawsize,
            rawptr: get(f, e + 20, 4).ok_or("truncated")? as u32,
            chars: get(f, e + 36, 4).ok_or("truncated")? as u32,
            bad,
        });
    }
    Ok(Pe { image_base, size_of_headers, opt, secs, dirs })
}

fn rva_off(pe: &Pe, rva: u32) -> Option<usize> {
    if rva < pe.size_of_headers {
        return Some(rva as usize);
    }
    for s in pe.secs.iter().filter(|s| s.bad.is_none()) {
        if rva >= s.va && rva - s.va < s.backed() {
            return (s.rawptr as usize).checked_add((rva - s.va) as usize);
        }
    }
    None
}

/// The typed words, by RVA. Refusals are reported through `ctx`.
fn classify(f: &[u8], pe: &Pe, ctx: &mut Ctx) -> HashMap<u32, Kind> {
    let mut kinds = HashMap::new();
    kinds.insert((pe.opt + 24) as u32, Kind::ImageBaseField);
    // base relocations
    let (rva, size) = pe.dirs[5];
    if size != 0 {
        match rva_off(pe, rva).filter(|o| o.checked_add(size as usize).map(|e| e <= f.len()).unwrap_or(false)) {
            None => ctx.fail(B_REFUSE, "base relocation table runs past the file"),
            Some(start) => {
                let mut o = start;
                while o + 8 <= start + size as usize {
                    let page = get(f, o, 4).unwrap_or(0) as u32;
                    let block = get(f, o + 4, 4).unwrap_or(0) as usize;
                    if block < 8 || o + block > start + size as usize {
                        ctx.fail(B_REFUSE, &format!("base relocation block at 0x{o:x} has size {block}"));
                        break;
                    }
                    for k in 0..(block - 8) / 2 {
                        let ent = get(f, o + 8 + 2 * k, 2).unwrap_or(0) as u32;
                        match ent >> 12 {
                            0 => {}
                            10 => {
                                kinds.insert(page.wrapping_add(ent & 0xfff), Kind::Relative);
                            }
                            t => ctx.fail(B_REFUSE, &format!("base relocation type {t} at 0x{:x}", page.wrapping_add(ent & 0xfff))),
                        }
                    }
                    o += block;
                }
            }
        }
    }
    if pe.dirs[11].1 != 0 {
        ctx.fail(B_REFUSE, "bound import directory present");
    }
    if pe.dirs[13].1 != 0 {
        ctx.fail(B_REFUSE, "delay-load import directory present");
    }
    // imports: the descriptors lie inside the directory's own extent, which
    // must hold the terminating all-zero descriptor; every read is checked
    let (rva, size) = pe.dirs[1];
    if size != 0 {
        let start = match rva_off(pe, rva) {
            Some(o) if o.checked_add(size as usize).map(|e| e <= f.len()).unwrap_or(false) => o,
            _ => {
                ctx.fail(B_LENGTH, "import directory runs past the file");
                return kinds;
            }
        };
        let end = start + size as usize;
        let mut d = start;
        loop {
            if d + 20 > end {
                ctx.fail(B_LENGTH, "import directory ends before its terminating descriptor");
                break;
            }
            let (oft, tds, fwd, name, ft) =
                match (get(f, d, 4), get(f, d + 4, 4), get(f, d + 8, 4), get(f, d + 12, 4), get(f, d + 16, 4)) {
                    (Some(a), Some(b), Some(c), Some(n), Some(e)) => (a as u32, b as u32, c as u32, n as u32, e as u32),
                    _ => {
                        ctx.fail(B_LENGTH, "import descriptor runs past the file");
                        break;
                    }
                };
            // the terminator is the all-zero descriptor: all five fields
            if oft == 0 && tds == 0 && fwd == 0 && name == 0 && ft == 0 {
                break;
            }
            let dll = match rva_off(pe, name).and_then(|o| cstr(f, o)) {
                Some(n) => n,
                None => {
                    ctx.fail(B_LENGTH, &format!("import descriptor at 0x{d:x} names no readable library"));
                    break;
                }
            };
            if tds != 0 {
                ctx.fail(B_REFUSE, &format!("import descriptor for {dll} is bound (TimeDateStamp 0x{tds:x})"));
            }
            if oft == 0 {
                ctx.fail(B_REFUSE, &format!("import descriptor for {dll} has no lookup table"));
                d += 20;
                continue;
            }
            let ilt = match rva_off(pe, oft) {
                Some(o) => o,
                None => {
                    ctx.fail(B_LENGTH, &format!("lookup table for {dll} outside the file"));
                    d += 20;
                    continue;
                }
            };
            let mut i = 0usize;
            loop {
                let e = match get(f, ilt + 8 * i, 8) {
                    Some(e) => e,
                    None => {
                        ctx.fail(B_LENGTH, &format!("lookup table for {dll} runs past the file"));
                        break;
                    }
                };
                if e == 0 {
                    break;
                }
                let imp = if e >> 63 == 1 {
                    Import::Ordinal((e & 0xffff) as u16)
                } else {
                    match rva_off(pe, (e & 0x7fff_ffff) as u32).and_then(|o| cstr(f, o + 2)) {
                        Some(n) => Import::Name(n),
                        None => {
                            ctx.fail(B_LENGTH, &format!("an import name for {dll} lies outside the file"));
                            break;
                        }
                    }
                };
                match (8u32.checked_mul(i as u32)).and_then(|o| ft.checked_add(o)) {
                    Some(at) => {
                        kinds.insert(at, Kind::Bind(dll.clone(), imp));
                    }
                    None => {
                        ctx.fail(B_LENGTH, &format!("the import address table for {dll} runs past 32-bit RVAs"));
                        break;
                    }
                }
                i += 1;
            }
            d += 20;
        }
    }
    if ctx.mutating("xfg") && pe.dirs[10].1 == 0 {
        println!("MUTATE xfg not applicable to this image");
    }
    // load configuration: CFG storage and XFG. The structure's own Size field
    // says how long it is; a structure that does not fit the file, or is too
    // short to hold its Size, is a failure, not a structure to skip.
    let (rva, size) = pe.dirs[10];
    if size != 0 {
        let lc = match rva_off(pe, rva) {
            Some(o) => o,
            None => {
                ctx.fail(B_LENGTH, "load configuration outside the file");
                return kinds;
            }
        };
        let struct_size = match get(f, lc, 4) {
            Some(n) if n >= 4 => n as usize,
            _ => {
                ctx.fail(B_LENGTH, "load configuration truncated before its Size field");
                return kinds;
            }
        };
        if lc.checked_add(struct_size).map(|e| e > f.len()).unwrap_or(true) {
            ctx.fail(B_LENGTH, &format!("load configuration of {struct_size} bytes runs past the file"));
            return kinds;
        }
        // bounded by its own directory entry, not only by the file
        if struct_size > size as usize {
            ctx.fail(B_LENGTH, &format!("load configuration Size {struct_size} exceeds its directory's {size}"));
            return kinds;
        }
        // a directory long enough for GuardFlags with a Size too short to
        // include them would silently drop the CFG typing
        if struct_size < 0x94 && size as usize >= 0x94 {
            ctx.fail(B_REFUSE, &format!("load configuration Size 0x{struct_size:x} omits GuardFlags its directory covers"));
            return kinds;
        }
        let field = |off: usize| if off + 8 <= struct_size { get(f, lc + off, 8).unwrap_or(0) } else { 0 };
        let mut guard_flags = if 0x94 <= struct_size { get(f, lc + 0x90, 4).unwrap_or(0) } else { 0 };
        if ctx.mutating("xfg") && 0x94 <= struct_size {
            guard_flags |= 0x0080_0000;
            println!("MUTATE xfg at 0x{:x}", rva + 0x90);
        }
        if guard_flags & 0x100 != 0 {
            for off in [0x70usize, 0x78].iter() {
                let va = field(*off);
                if va != 0 {
                    kinds.insert(va.wrapping_sub(pe.image_base) as u32, Kind::Hole);
                }
            }
        }
        // XFG: refused when the image is XFG-enabled
        // (IMAGE_GUARD_XFG_ENABLED). An MSVC-linked image without it still
        // carries non-zero XFG pointer fields; they are recorded, and the
        // storage they point at stays typed Plain, so a loader write there
        // would show as a Plain difference.
        let xfg: Vec<u64> = [0x118usize, 0x120, 0x128].iter().map(|o| field(*o)).collect();
        let xfg_enabled = guard_flags & 0x0080_0000 != 0;
        println!("XFG enabled={} pointers={:x?}", if xfg_enabled { "yes" } else { "no" }, xfg);
        if xfg_enabled {
            ctx.fail(B_REFUSE, "the image is XFG-enabled (IMAGE_GUARD_XFG_ENABLED)");
        }
    }
    kinds
}

fn stand_in(dll: &str, imp: &Import) -> u64 {
    let mut h: u64 = 1469598103934665603;
    let key = format!("{}!{:?}", dll.to_ascii_lowercase(), imp);
    for c in key.bytes() {
        h = (h ^ c as u64).wrapping_mul(1099511628211);
    }
    0x7ff0_0000_0000 + ((h & 0xffff_ffff) << 4)
}

#[cfg(windows)]
mod os {
    use super::Import;
    type H = *mut u8;
    extern "system" {
        fn LoadLibraryA(name: *const u8) -> H;
        fn GetModuleHandleA(name: *const u8) -> H;
        fn GetProcAddress(h: H, name: *const u8) -> H;
        fn GetModuleFileNameA(h: H, buf: *mut u8, n: u32) -> u32;
        fn GetCurrentProcess() -> H;
        fn ReadProcessMemory(p: H, base: *const u8, buf: *mut u8, n: usize, got: *mut usize) -> i32;
    }
    fn z(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }
    pub fn load(path: &str) -> Option<u64> {
        let p = z(path);
        let h = unsafe { LoadLibraryA(p.as_ptr()) };
        if h.is_null() { None } else { Some(h as u64) }
    }
    pub fn file_of(base: u64) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        let n = unsafe { GetModuleFileNameA(base as H, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() { return None; }
        Some(String::from_utf8_lossy(&buf[..n]).into_owned())
    }
    pub fn read(addr: u64, n: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let mut got = 0usize;
        let ok = unsafe { ReadProcessMemory(GetCurrentProcess(), addr as *const u8, buf.as_mut_ptr(), n, &mut got) };
        if ok == 0 || got != n { None } else { Some(buf) }
    }
    pub fn resolve(dll: &str, imp: &Import) -> u64 {
        let d = z(dll);
        let h = unsafe { GetModuleHandleA(d.as_ptr()) };
        if h.is_null() { return 0; }
        let p = match imp {
            Import::Name(n) => { let n = z(n); unsafe { GetProcAddress(h, n.as_ptr()) } }
            Import::Ordinal(o) => unsafe { GetProcAddress(h, *o as usize as *const u8) },
        };
        p as u64
    }
}

#[cfg(not(windows))]
mod os {
    use super::Import;
    pub fn load(_: &str) -> Option<u64> { None }
    pub fn file_of(_: u64) -> Option<String> { None }
    pub fn read(_: u64, _: usize) -> Option<Vec<u8>> { None }
    pub fn resolve(_: &str, _: &Import) -> u64 { 0 }
}

fn main() {
    // Every offset is bounds-checked; this only turns a parse path that was
    // missed into a setup failure instead of a crash.
    if std::panic::catch_unwind(probe).is_err() {
        println!("FAIL[{B_SETUP}] the probe panicked on input it does not handle");
        println!("RESULT status={B_SETUP} FAIL");
        std::process::exit(B_SETUP as i32);
    }
}

fn probe() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut ctx = Ctx { status: 0, mutate: None };
    let mut simulate: Option<u64> = None;
    let mut imagebase_rewritten = false;
    while !args.is_empty() && args[0].starts_with("--") {
        if args[0] == "--imagebase-rewritten" {
            imagebase_rewritten = true;
            args.remove(0);
            continue;
        }
        if args[0] == "--list-mutations" {
            for (n, b) in MUTATIONS {
                println!("{n} {b}");
            }
            return;
        }
        if args.len() < 2 {
            break;
        }
        let v = args[1].clone();
        match args[0].as_str() {
            "--simulate" => {
                let t = v.trim_start_matches("0x");
                simulate = Some(u64::from_str_radix(t, if v.starts_with("0x") { 16 } else { 10 }).unwrap_or(0));
            }
            "--mutate" => {
                if !MUTATIONS.iter().any(|(n, _)| *n == v) {
                    eprintln!("unknown mutation {v}");
                    std::process::exit(2);
                }
                ctx.mutate = Some(v);
            }
            _ => break,
        }
        args.drain(0..2);
    }
    if args.len() != 1 {
        eprintln!("usage: pe-typed-probe [--simulate DELTA] [--mutate NAME] <dll>\n       pe-typed-probe --list-mutations");
        std::process::exit(2);
    }
    let lib = args[0].clone();
    println!("PROC route={}", if simulate.is_some() { "simulated" } else { "ReadProcessMemory" });

    // -- load, and the file the loader reports --
    let (base, path) = match simulate {
        Some(_) => (0u64, lib.clone()),
        None => match os::load(&lib) {
            None => {
                ctx.fail(B_SETUP, &format!("LoadLibraryA {lib} failed"));
                ctx.finish()
            }
            Some(b) => match os::file_of(b) {
                Some(p) => (b, p),
                None => {
                    ctx.fail(B_SETUP, "GetModuleFileNameA failed");
                    ctx.finish()
                }
            },
        },
    };
    let mut f = match std::fs::read(&path) {
        Ok(f) => f,
        Err(e) => {
            ctx.fail(B_SETUP, &format!("read {path}: {e}"));
            ctx.finish()
        }
    };
    println!("FILE path={path} size={}", f.len());
    let mut pe = match parse(&f) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(B_SETUP, &e);
            ctx.finish()
        }
    };
    let mut delta = match simulate {
        Some(d) => d,
        None => base.wrapping_sub(pe.image_base),
    };
    // The refuse mutation gives the parsed headers a bound import directory,
    // which is what the refusal reads.
    if ctx.mutating("refuse") {
        pe.dirs[11] = (pe.dirs[1].0, 8);
        println!("MUTATE refuse at 0x0");
    }
    println!("IMAGE base=0x{:x} image_base=0x{:x} bias=0x{delta:x}", pe.image_base.wrapping_add(delta), pe.image_base);
    let kinds = classify(&f, &pe, &mut ctx);
    let (nrel, nbind, nhole) = kinds.values().fold((0, 0, 0), |a, k| match k {
        Kind::Relative => (a.0 + 1, a.1, a.2),
        Kind::ImageBaseField => a,
        Kind::Bind(..) => (a.0, a.1 + 1, a.2),
        Kind::Hole => (a.0, a.1, a.2 + 1),
    });
    println!("TYPES relative={nrel} bind={nbind} hole={nhole} sections={}", pe.secs.len());

    // -- the regions, as loaded: the headers, then each section's file-backed bytes --
    // (name, rva, length, writable, file offset); a region whose RVA maps to
    // no file bytes, or whose bytes run past the file, is a setup failure and
    // is not typed
    let mut regions: Vec<(String, u32, u32, bool, usize)> = Vec::new();
    let mut candidates = vec![("headers".to_string(), 0u32, pe.size_of_headers, false, 0x4000_0000u32)];
    for s in &pe.secs {
        if let Some(why) = &s.bad {
            ctx.fail(B_REFUSE, &format!("section {}: {why}", s.name));
            continue;
        }
        if s.backed() != 0 {
            candidates.push((s.name.clone(), s.va, s.backed(), s.chars & 0x8000_0000 != 0, s.chars));
        }
    }
    for (name, va, n, writable, chars) in candidates {
        if chars & 0x4000_0000 == 0 {
            println!("SECTION name={name} not readable: skipped");
            continue;
        }
        let foff = if va == 0 { Some(0) } else { rva_off(&pe, va) };
        match foff {
            Some(o) if o.checked_add(n as usize).map(|e| e <= f.len()).unwrap_or(false) => {
                regions.push((name, va, n, writable, o))
            }
            _ => ctx.fail(B_SETUP, &format!("{name} at RVA 0x{va:x} maps to no file bytes: not typed")),
        }
    }
    let mut mem: Vec<Vec<u8>> = Vec::new();
    for (name, va, n, _, foff) in &regions {
        let m = match simulate {
            Some(_) => f[*foff..*foff + *n as usize].to_vec(),
            None => match os::read(base + *va as u64, *n as usize) {
                Some(b) => b,
                None => {
                    ctx.fail(B_SETUP, &format!("{name} unreadable through ReadProcessMemory"));
                    ctx.finish()
                }
            },
        };
        mem.push(m);
    }
    let resolve = |dll: &str, imp: &Import| -> u64 {
        if simulate.is_some() { stand_in(dll, imp) } else { os::resolve(dll, imp) }
    };
    if simulate.is_some() {
        // what the loader would write
        // (ImageBase is left as the file holds it: the simulation does not
        // assume the loader rewrites it)
        for (i, (_, va, n, _, _)) in regions.iter().enumerate() {
            for o in 0..*n as usize {
                let rva = *va + o as u32;
                let w = match kinds.get(&rva) {
                    Some(Kind::Relative) => get(&mem[i], o, 8).map(|v| v.wrapping_add(delta)),
                    Some(Kind::ImageBaseField) if imagebase_rewritten => get(&mem[i], o, 8).map(|v| v.wrapping_add(delta)),
                    Some(Kind::ImageBaseField) => None,
                    Some(Kind::Bind(d, imp)) => Some(resolve(d, imp)),
                    Some(Kind::Hole) => Some(0x5a5a_5a5a_5a5a_5a5a),
                    None => None,
                };
                if let (Some(w), true) = (w, o + 8 <= *n as usize) {
                    mem[i][o..o + 8].copy_from_slice(&w.to_le_bytes());
                }
            }
        }
    }

    // The no-slide mutation: the image as if the loader had not moved it.
    // Every Relative word in the loaded copy holds its file value and the
    // delta the checks subtract is 0; only the control may notice.
    if ctx.mutating("no-slide") {
        for (i, (_, va, n, _, foff)) in regions.iter().enumerate() {
            for o in 0..(*n as usize).saturating_sub(7) {
                // the ImageBase field too: a loader that rewrites it on
                // relocation would have left it as the file holds it
                let k = kinds.get(&(*va + o as u32));
                if k == Some(&Kind::Relative) || k == Some(&Kind::ImageBaseField) {
                    let fv = f[*foff + o..*foff + o + 8].to_vec();
                    mem[i][o..o + 8].copy_from_slice(&fv);
                }
            }
        }
        delta = 0;
        println!("MUTATE no-slide at 0x0");
    }

    // -- length --
    let (cert_off, cert_len) = pe.dirs[4];
    let mut opened = f.len();
    let need = pe.secs.iter().map(|s| s.rawptr as usize + s.rawsize as usize).max().unwrap_or(0);
    if ctx.mutating("length") {
        opened = need.saturating_sub(1);
        println!("MUTATE length at 0x{opened:x}");
    }
    let file_len = if cert_len != 0 { cert_off as usize } else { opened };
    if need > file_len {
        ctx.fail(B_LENGTH, &format!("the sections need {need} file bytes, the image has {file_len}"));
    }
    if cert_len != 0 && cert_off as usize + cert_len as usize > opened {
        ctx.fail(B_LENGTH, "the certificate table runs past the file");
    }
    println!("SIZE image_len={need} file_len={file_len} opened_len={opened}");

    // -- mutations of file values, after parsing --
    let mut relative_at = None;
    if ctx.mutating("header-plain") {
        f[0x4e] ^= 1; // inside the DOS stub: parse() read past 0x40 already
        println!("MUTATE header-plain at 0x4e");
    }
    if let Some(t) = pe.secs.iter().find(|s| s.name == ".text") {
        let mid = (t.backed() / 2) & !7;
        if ctx.mutating("text-plain") {
            if let Some(b) = f.get_mut(t.rawptr as usize + mid as usize) {
                *b ^= 1;
                println!("MUTATE text-plain at 0x{:x}", t.va + mid);
            }
        }
        if ctx.mutating("relative") {
            relative_at = Some(t.va + mid);
            println!("MUTATE relative at 0x{:x}", t.va + mid);
        }
    }
    if ctx.mutating("rdata-plain") {
        let mut done = false;
        'outer: for s in pe.secs.iter().filter(|s| s.name != ".text" && s.chars & 0x8000_0000 == 0 && s.chars & 0x4000_0000 != 0) {
            for o in (0..s.backed()).step_by(8) {
                let rva = s.va + o;
                if (0..8).all(|k| !kinds.contains_key(&(rva + k)) && (k == 0 || !kinds.contains_key(&(rva - k)))) && o + 8 <= s.backed() {
                    match f.get_mut(s.rawptr as usize + o as usize) {
                        Some(b) => *b ^= 1,
                        None => break 'outer,
                    }
                    println!("MUTATE rdata-plain at 0x{rva:x} in {}", s.name);
                    done = true;
                    break 'outer;
                }
            }
        }
        if !done {
            println!("MUTATE rdata-plain not applicable to this image");
        }
    }

    // -- typing --
    let (mut plain, mut plain_bad, mut rel_ok, mut rel_bad, mut moved) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let (mut bind_ok, mut bind_bad, mut holes, mut fileonly_bytes) = (0usize, 0usize, 0usize, 0usize);
    let mut bind_mutated = false;
    let mut consumed: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for (i, (name, va, n, writable, foff)) in regions.iter().enumerate() {
        let n = *n as usize;
        let foff = *foff;
        if *writable {
            // the file offset the FileOnly read uses; the mutation moves it
            // past the image so the read itself has to fail
            let fo = if ctx.mutating("fileonly") {
                println!("MUTATE fileonly at 0x{va:x}");
                file_len
            } else {
                foff
            };
            let fbytes = if fo.checked_add(n).map(|e| e <= file_len).unwrap_or(false) { f.get(fo..fo + n) } else { None };
            match fbytes {
                None => ctx.fail(B_FILEONLY, &format!("FileOnly section {name} unreadable from the file")),
                Some(fb) => {
                    fileonly_bytes += n;
                    let diff = (0..n / 8).filter(|w| fb[w * 8..w * 8 + 8] != mem[i][w * 8..w * 8 + 8]).count();
                    println!("FILEONLY section={name} file_backed={n} words_written_by_loader_or_module={diff}");
                }
            }
            continue;
        }
        let mut region_plain = 0usize;
        let mut o = 0usize;
        while o < n {
            let rva = *va + o as u32;
            let kind = if relative_at == Some(rva) { Some(Kind::Relative) } else { kinds.get(&rva).cloned() };
            if let (Some(k), true) = (kind, o + 8 <= n) {
                consumed.insert(rva);
                let mv = get(&mem[i], o, 8).unwrap_or(0);
                let fv = get(&f, foff + o, 8).unwrap_or(0);
                match k {
                    Kind::Relative => {
                        if mv.wrapping_sub(delta) == fv { rel_ok += 1 } else {
                            rel_bad += 1;
                            if rel_bad <= 5 { println!("RELATIVE_BAD rva=0x{rva:x} mem=0x{mv:x} file=0x{fv:x}"); }
                        }
                        if mv != fv { moved += 1; }
                    }
                    Kind::ImageBaseField => {
                        // either behaviour passes; the run records which
                        let seen = if mv == fv { "unchanged" } else if mv == fv.wrapping_add(delta) { "rewritten" } else { "other" };
                        println!("IMAGEBASE_FIELD {seen} file=0x{fv:x} mem=0x{mv:x}");
                        if seen == "other" {
                            rel_bad += 1;
                        }
                    }
                    Kind::Hole => holes += 1,
                    Kind::Bind(d, imp) => {
                        let mut r = resolve(&d, &imp);
                        if r != 0 && ctx.mutating("bind") && !bind_mutated {
                            r += 8;
                            bind_mutated = true;
                            println!("MUTATE bind at 0x{rva:x}");
                        }
                        if r != 0 && mv == r { bind_ok += 1 } else {
                            bind_bad += 1;
                            if bind_bad <= 5 { println!("BIND_BAD rva=0x{rva:x} {d}!{imp:?} mem=0x{mv:x} resolved=0x{r:x}"); }
                        }
                    }
                }
                o += 8;
                continue;
            }
            region_plain += 1;
            let fb = f.get(foff + o).cloned();
            if fb != Some(mem[i][o]) {
                if plain_bad < 5 { println!("PLAIN_DIFF region={name} rva=0x{rva:x} file={fb:?} mem={:02x}", mem[i][o]); }
                plain_bad += 1;
            }
            o += 1;
        }
        plain += region_plain;
        println!("REGION name={name} plain_bytes={region_plain}");
    }
    println!("PE_SUMMARY plain_bytes={plain} plain_differing={plain_bad} relative_ok={rel_ok} relative_bad={rel_bad} bind_ok={bind_ok} bind_bad={bind_bad} holes={holes}");
    if plain_bad != 0 { ctx.fail(B_TYPING, &format!("{plain_bad} Plain bytes differ from the file")); }
    if rel_bad != 0 { ctx.fail(B_RELATIVE, &format!("{rel_bad} Relative words do not normalise")); }
    if bind_bad != 0 { ctx.fail(B_BIND, &format!("{bind_bad} thunks disagree with their resolution")); }
    // Every classified word was examined above, or (a Relative word or a
    // Hole) lies in a FileOnly section whose file bytes are hashed instead. A
    // thunk is never FileOnly. Any other classified word was never looked at.
    let in_fileonly = |rva: u32| {
        regions.iter().any(|(_, va, n, w, _)| *w && rva >= *va && ((rva - *va) as u64) + 8 <= *n as u64)
    };
    let mut unexamined = 0usize;
    for (rva, k) in kinds.iter() {
        if consumed.contains(rva) || (!matches!(k, Kind::Bind(..)) && in_fileonly(*rva)) {
            continue;
        }
        if unexamined < 5 {
            println!("UNEXAMINED {k:?} rva=0x{rva:x}");
        }
        unexamined += 1;
    }
    if unexamined != 0 {
        ctx.fail(B_REFUSE, &format!("{unexamined} classified words lie outside every typed region and were never examined"));
    }
    if nbind != 0 && bind_ok == 0 {
        ctx.fail(B_BIND, &format!("{nbind} thunks classified and none verified"));
    }
    // ImageBase is not a moved word: only a DIR64 destination shows relocation
    if delta == 0 || moved == 0 { ctx.fail(B_CONTROL, &format!("no DIR64 word moved (delta 0x{delta:x}): the run is void")); }
    if plain == 0 { ctx.fail(B_TYPING, "no Plain byte was compared"); }
    if fileonly_bytes == 0 { ctx.fail(B_FILEONLY, "no FileOnly byte was read from the file"); }
    ctx.finish()
}
