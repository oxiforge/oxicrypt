//! Loads the C library on Windows and reports what the module inside it did.
//!
//!   pe-ffi-operational <dll>
//!       Calls `oxi_init`, then asks whether the module became operational,
//!       with the contract of ffi-operational.c:
//!         0  operational: oxi_init returned 0, oxi_is_operational returned 1
//!            and the integrity test reported Passed (1);
//!         1  refused by the module's power-up tests: oxi_init returned
//!            non-zero and the module is not operational;
//!         2  the library could not be loaded or a symbol is missing;
//!         3  any other combination.
//!       It prints `oxi_init=R oxi_is_operational=O oxi_integrity_status=S`.
//!
//!   pe-ffi-operational --binds <show.txt> <dll>
//!       Loads the DLL without initialising the module and checks every
//!       bound word the signer's `--show` listing names (`[i] Bind rva ..
//!       len N .. record R` and `record [R] <dll> <symbol or #ordinal>`
//!       lines) the way the integrity test does: the loaded thunk must equal
//!       GetProcAddress of the record's symbol or ordinal in the module
//!       GetModuleHandleExW returns for the record's DLL name. One line per
//!       word: `BIND rva=.. dll=.. symbol=.. word=.. resolved=..
//!       named=<module the name gives> bound=<module holding the word>
//!       EQUAL|OTHER|UNRESOLVED`, and for an API-set name (`api-ms-*`,
//!       `ext-ms-*`) `apiset=SAME` when the module its name gives is the one
//!       holding the word, else `apiset=DIFFERENT`. Ends with `RESULT
//!       binds=N other=M unresolved=U apiset=A apiset_same=S`.
//!         0  every word EQUAL, at least one word;
//!         1  any word OTHER or UNRESOLVED, or none listed;
//!         2  the DLL could not be loaded or the listing could not be read.
//!
//!   pe-ffi-operational --word <dll> <rva>
//!       Loads the DLL without initialising the module and prints `WORD
//!       base=.. rva=.. loaded=..`, the 8-byte word at `rva` as loaded.
//!
//! Build: rustc -O -o pe-ffi-operational.exe pe-ffi-operational.rs

#[cfg(windows)]
mod os {
    pub type H = *mut core::ffi::c_void;
    extern "system" {
        pub fn LoadLibraryW(name: *const u16) -> H;
        pub fn GetProcAddress(h: H, name: *const u8) -> H;
        pub fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut H) -> i32;
        pub fn GetModuleFileNameW(h: H, buf: *mut u16, n: u32) -> u32;
        pub fn GetLastError() -> u32;
    }
    pub const UNCHANGED_REFCOUNT: u32 = 0x2;
    pub const FROM_ADDRESS: u32 = 0x4;

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn load(path: &str) -> Result<H, u32> {
        let w = wide(path);
        let h = unsafe { LoadLibraryW(w.as_ptr()) };
        if h.is_null() {
            Err(unsafe { GetLastError() })
        } else {
            Ok(h)
        }
    }

    pub fn symbol(h: H, name: &str) -> H {
        let mut n = name.as_bytes().to_vec();
        n.push(0);
        unsafe { GetProcAddress(h, n.as_ptr()) }
    }

    pub fn ordinal(h: H, ordinal: u16) -> H {
        unsafe { GetProcAddress(h, usize::from(ordinal) as *const u8) }
    }

    pub fn by_name(dll: &str) -> H {
        let w = wide(dll);
        let mut m: H = core::ptr::null_mut();
        if unsafe { GetModuleHandleExW(UNCHANGED_REFCOUNT, w.as_ptr(), &mut m) } == 0 {
            core::ptr::null_mut()
        } else {
            m
        }
    }

    pub fn by_address(addr: usize) -> H {
        let mut m: H = core::ptr::null_mut();
        if unsafe { GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT, addr as *const u16, &mut m) } == 0 {
            core::ptr::null_mut()
        } else {
            m
        }
    }

    pub fn path_of(h: H) -> String {
        if h.is_null() {
            return "-".to_owned();
        }
        let mut buf = vec![0u16; 32768];
        let n = unsafe { GetModuleFileNameW(h, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            return "?".to_owned();
        }
        String::from_utf16_lossy(&buf[..n]).replace(' ', "%20")
    }
}

/// One bound word: its RVA, the DLL and the symbol or `#ordinal`.
struct Word {
    rva: u64,
    dll: String,
    symbol: String,
}

/// The bound words the signer's listing names.
fn listing(text: &str) -> Result<Vec<Word>, String> {
    let mut records = std::collections::HashMap::new();
    let mut binds = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() == Some(&"record") && f.len() >= 4 {
            let i: usize = f[1].trim_matches(|c| c == '[' || c == ']').parse().map_err(|_| line.to_owned())?;
            records.insert(i, (f[2].to_owned(), f[3].to_owned()));
        } else if f.len() >= 12 && f[1] == "Bind" && f[2] == "rva" {
            let rva = u64::from_str_radix(f[3].trim_start_matches("0x"), 16).map_err(|_| line.to_owned())?;
            let len: u64 = f[7].parse().map_err(|_| line.to_owned())?;
            let record: usize = f[11].parse().map_err(|_| line.to_owned())?;
            binds.push((rva, len, record));
        }
    }
    let mut out = Vec::new();
    for (rva, len, record) in binds {
        let (dll, symbol) = records.get(&record).ok_or(format!("no record {record}"))?;
        for k in 0..len / 8 {
            out.push(Word { rva: rva + 8 * k, dll: dll.clone(), symbol: symbol.clone() });
        }
    }
    Ok(out)
}

#[cfg(windows)]
fn binds(show: &str, dll: &str) -> i32 {
    let text = match std::fs::read_to_string(show) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {show}: {e}");
            return 2;
        }
    };
    let words = match listing(&text) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot parse the listing at: {e}");
            return 2;
        }
    };
    let base = match os::load(dll) {
        Ok(h) => h as usize,
        Err(e) => {
            eprintln!("LoadLibraryW failed: {e}");
            return 2;
        }
    };
    let (mut other, mut unresolved, mut apiset, mut same) = (0, 0, 0, 0);
    for w in &words {
        // The thunk lies in this process's image of the DLL.
        let word = unsafe { core::ptr::read_volatile((base + w.rva as usize) as *const u64) } as usize;
        let named = os::by_name(&w.dll);
        let resolved = if named.is_null() {
            0
        } else if let Some(n) = w.symbol.strip_prefix('#') {
            os::ordinal(named, n.parse().unwrap_or(0)) as usize
        } else {
            os::symbol(named, &w.symbol) as usize
        };
        let bound = os::by_address(word);
        let verdict = if resolved == 0 {
            unresolved += 1;
            "UNRESOLVED"
        } else if resolved == word {
            "EQUAL"
        } else {
            other += 1;
            "OTHER"
        };
        let lower = w.dll.to_ascii_lowercase();
        let host = if lower.starts_with("api-ms-") || lower.starts_with("ext-ms-") {
            apiset += 1;
            if !named.is_null() && named == bound {
                same += 1;
                " apiset=SAME"
            } else {
                " apiset=DIFFERENT"
            }
        } else {
            ""
        };
        println!(
            "BIND rva={:#x} dll={} symbol={} word={word:#x} resolved={resolved:#x} named={} bound={} {verdict}{host}",
            w.rva,
            w.dll,
            w.symbol,
            os::path_of(named),
            os::path_of(bound)
        );
    }
    println!(
        "RESULT binds={} other={other} unresolved={unresolved} apiset={apiset} apiset_same={same}",
        words.len()
    );
    i32::from(words.is_empty() || other != 0 || unresolved != 0)
}

/// Loads the DLL without initialising the module and prints the 8-byte word
/// at `rva` in the loaded image, with the load base.
#[cfg(windows)]
fn word(dll: &str, rva: &str) -> i32 {
    let Ok(rva) = usize::from_str_radix(rva.trim_start_matches("0x"), 16) else {
        eprintln!("not a hexadecimal RVA: {rva}");
        return 2;
    };
    let base = match os::load(dll) {
        Ok(h) => h as usize,
        Err(e) => {
            eprintln!("LoadLibraryW failed: {e}");
            return 2;
        }
    };
    let loaded = unsafe { core::ptr::read_volatile((base + rva) as *const u64) };
    println!("WORD base={base:#x} rva={rva:#x} loaded={loaded:#x}");
    0
}

#[cfg(windows)]
fn operational(dll: &str) -> i32 {
    let h = match os::load(dll) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("LoadLibraryW failed: {e}");
            return 2;
        }
    };
    let (init, op, st) = (
        os::symbol(h, "oxi_init"),
        os::symbol(h, "oxi_is_operational"),
        os::symbol(h, "oxi_integrity_status"),
    );
    if init.is_null() || op.is_null() || st.is_null() {
        eprintln!("missing symbol");
        return 2;
    }
    type Init = extern "C" fn(i32) -> i32;
    type Query = extern "C" fn() -> i32;
    let (init, op, st): (Init, Query, Query) = unsafe {
        (core::mem::transmute(init), core::mem::transmute(op), core::mem::transmute(st))
    };
    let rc = init(0);
    let (o, s) = (op(), st());
    println!("oxi_init={rc} oxi_is_operational={o} oxi_integrity_status={s}");
    if rc == 0 && o == 1 && s == 1 {
        println!("library: operational");
        0
    } else if rc != 0 && o == 0 {
        println!("library: refused by the module's power-up tests");
        1
    } else {
        println!("library: neither operational nor refused");
        3
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(windows)]
    let code = match args.as_slice() {
        [flag, show, dll] if flag == "--binds" => binds(show, dll),
        [flag, dll, rva] if flag == "--word" => word(dll, rva),
        [dll] => operational(dll),
        _ => {
            eprintln!("usage: pe-ffi-operational [--binds <show.txt>] <dll> | --word <dll> <rva>");
            2
        }
    };
    #[cfg(not(windows))]
    let code = {
        // Off Windows only the listing parser runs, for the self-test.
        match args.as_slice() {
            [flag, show] if flag == "--parse" => match std::fs::read_to_string(show).map_err(|e| e.to_string()).and_then(|t| listing(&t)) {
                Ok(words) => {
                    for w in &words {
                        println!("{:#x} {} {}", w.rva, w.dll, w.symbol);
                    }
                    i32::from(words.is_empty())
                }
                Err(e) => {
                    eprintln!("cannot parse: {e}");
                    2
                }
            },
            _ => {
                eprintln!("the library harness runs on Windows; --parse <show.txt> checks a listing");
                2
            }
        }
    };
    std::process::exit(code);
}
