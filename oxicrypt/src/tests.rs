//! Unit tests: the pins against the workspace sources, the build script's
//! file selection, the manifest parser, the zeroing primitive and the secret
//! types' destructors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use crate::error::{Error, Site};
use crate::module::{Fingerprint, IntegrityStatus, Profile, manifest_library_version};
use crate::secret::{
    HkdfPrk, MlDsa87KeySeed, MlDsa87SecretKey, MlKem1024DecapsulationKey, Okm, SharedSecret, wipe,
};

#[path = "../build/select.rs"]
mod select;

fn workspace_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} (this test runs in the workspace)",
            path.display()
        )
    })
}

fn crate_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ----- provisioning -----

/// Fails when the crate was built without a library, so a run that tested
/// nothing against the library cannot pass, unless the run says so.
#[test]
fn library_is_provisioned() {
    let optional = std::env::var("OXICRYPT_LIB_OPTIONAL").is_ok_and(|v| v == "1");
    assert!(
        cfg!(oxicrypt_lib) || optional,
        "built without OXICRYPT_LIB_DIR, so no test ran against the library. Build and sign \
         one with `scripts/bindings-fixture.sh <empty dir>` and set the variables it prints, or \
         set OXICRYPT_LIB_OPTIONAL=1 to withdraw the claim that the library was tested"
    );
}

// ----- status codes -----

/// The `OxiResult` discriminants of the C ABI, as `(name, code)`.
///
/// Read from the `oxicrypt-ffi` source, which is where they are defined; this
/// function is the one place that knows where the table lives.
fn ffi_status_codes() -> Vec<(String, i32)> {
    let src = workspace_file("crates/oxicrypt-ffi/src/error.rs");
    let start = src
        .find("pub enum OxiResult {")
        .expect("OxiResult in error.rs");
    let body = &src[start..];
    let body = &body[..body.find("\n}").expect("end of OxiResult")];
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if let Some((name, rest)) = line.split_once(" = ") {
            let code = rest.trim_end_matches(',').trim();
            if let Ok(code) = code.parse::<i32>() {
                out.push((name.trim().to_owned(), code));
            }
        }
    }
    out
}

const SITES: [Site; 3] = [Site::AeadDecrypt, Site::SignatureVerify, Site::Other];

fn variant_name(e: &Error) -> String {
    let debug = format!("{e:?}");
    debug
        .split(|c: char| !c.is_alphanumeric())
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn every_ffi_status_code_maps_to_its_named_variant_at_every_site() {
    let codes = ffi_status_codes();
    assert!(
        codes.len() >= 20,
        "parsed only {} codes from error.rs; the parser is broken",
        codes.len()
    );
    assert!(codes.iter().any(|(n, c)| n == "TagMismatch" && *c == 22));
    for (name, code) in &codes {
        if *code == 0 {
            assert_eq!(name, "Ok");
            continue;
        }
        for site in SITES {
            let mapped = Error::from_code(*code, site);
            if *code == 22 && site == Site::SignatureVerify {
                assert_eq!(mapped, Error::SignatureInvalid);
                continue;
            }
            assert_eq!(
                variant_name(&mapped),
                *name,
                "code {code} at {site:?} maps to {mapped:?}, error.rs names it {name}"
            );
        }
    }
}

#[test]
fn codes_the_ffi_does_not_assign_are_unknown() {
    let assigned: BTreeSet<i32> = ffi_status_codes().into_iter().map(|(_, c)| c).collect();
    for code in -3..=300 {
        if assigned.contains(&code) {
            continue;
        }
        for site in SITES {
            assert_eq!(Error::from_code(code, site), Error::Unknown(code));
        }
    }
}

#[test]
fn code_22_depends_on_the_site() {
    assert_eq!(Error::from_code(22, Site::AeadDecrypt), Error::TagMismatch);
    assert_eq!(Error::from_code(22, Site::Other), Error::TagMismatch);
    assert_eq!(
        Error::from_code(22, Site::SignatureVerify),
        Error::SignatureInvalid
    );
}

#[test]
fn profile_and_integrity_codes_round_trip() {
    for code in -2..=12 {
        assert_eq!(Profile::from_code(code).code(), code);
    }
    assert_eq!(Profile::from_code(1), Profile::Cnsa2);
    assert_eq!(Profile::from_code(4), Profile::Unknown(4));
    let named = (0..=10)
        .filter(|c| !matches!(IntegrityStatus::from_code(*c), IntegrityStatus::Unknown(_)))
        .count();
    assert_eq!(named, 11);
    assert_eq!(IntegrityStatus::from_code(3), IntegrityStatus::SlotInvalid);
    assert_eq!(IntegrityStatus::from_code(11), IntegrityStatus::Unknown(11));
}

// ----- the sys module against the header -----

type Signature = (Vec<String>, String);

fn header_type(c: &str) -> String {
    let c = c.trim();
    let (is_const, rest) = match c.strip_prefix("const ") {
        Some(rest) => (true, rest.trim()),
        None => (false, c),
    };
    let stars = rest.matches('*').count();
    let base = rest.replace('*', "");
    let base = match base.trim() {
        "int" => "c_int".to_owned(),
        "uintptr_t" => "usize".to_owned(),
        "uint64_t" => "u64".to_owned(),
        "uint8_t" => "u8".to_owned(),
        "char" => "c_char".to_owned(),
        "void" => "()".to_owned(),
        other => other.to_owned(),
    };
    if stars == 0 {
        return base;
    }
    let mut out = format!("{} {base}", if is_const { "*const" } else { "*mut" });
    for _ in 1..stars {
        out = format!("*mut {out}");
    }
    out
}

fn strip_c_comments(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find("*/").expect("closed comment");
        rest = &rest[start + end + 2..];
    }
    out.push_str(rest);
    out.lines()
        .map(|l| l.split("//").next().unwrap())
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ")
}

fn header_functions() -> BTreeMap<String, Signature> {
    let src = workspace_file("crates/oxicrypt-ffi/include/oxicrypt.h");
    let text = strip_c_comments(&src);
    let start = text.find("extern \"C\" {").expect("extern block") + "extern \"C\" {".len();
    let mut out = BTreeMap::new();
    for decl in text[start..].split(';') {
        let decl = decl.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(open) = decl.find('(') else { continue };
        let head = &decl[..open];
        let name_start = head
            .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let name = head[name_start..].to_owned();
        let ret = header_type(&head[..name_start]);
        let params = decl[open + 1..decl.rfind(')').unwrap()].trim();
        let params = if params == "void" {
            Vec::new()
        } else {
            params
                .split(',')
                .map(|p| {
                    let p = p.trim();
                    let cut = p
                        .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .unwrap();
                    header_type(&p[..=cut])
                })
                .collect()
        };
        assert!(
            out.insert(name, (params, ret)).is_none(),
            "duplicate in header"
        );
    }
    out
}

fn sys_functions() -> BTreeMap<String, Signature> {
    let src = crate_file("src/sys.rs");
    let start = src
        .find("unsafe extern \"C\" {")
        .expect("extern block in sys.rs");
    let body = &src[start + "unsafe extern \"C\" {".len()..];
    let body = &body[..body.find("\n}").expect("end of extern block")];
    let mut out = BTreeMap::new();
    for decl in body.split(';') {
        let decl = decl.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(item) = decl.strip_prefix("pub(crate) fn ") else {
            assert!(decl.is_empty(), "unexpected item in sys: {decl}");
            continue;
        };
        let open = item.find('(').unwrap();
        let close = item.rfind(')').unwrap();
        let name = item[..open].to_owned();
        let params = item[open + 1..close].trim();
        let params = if params.is_empty() {
            Vec::new()
        } else {
            // rustfmt leaves a trailing comma after the last parameter of a
            // wrapped declaration.
            params
                .split(',')
                .filter(|p| !p.trim().is_empty())
                .map(|p| p.split_once(':').unwrap().1.trim().to_owned())
                .collect()
        };
        let ret = item[close + 1..]
            .trim()
            .strip_prefix("->")
            .map_or("()".to_owned(), |r| r.trim().to_owned());
        assert!(
            out.insert(name, (params, ret)).is_none(),
            "duplicate in sys"
        );
    }
    out
}

#[test]
fn sys_declares_exactly_the_header() {
    let header = header_functions();
    let sys = sys_functions();
    assert_eq!(header.len(), 292, "the header's export count changed");
    assert!(header.contains_key("lama_manifest"));
    assert_eq!(
        header["oxi_aes256_new"],
        (
            vec!["*mut *mut OxiAes256Key".to_owned(), "*const u8".to_owned()],
            "c_int".to_owned()
        ),
        "the header parser's positive control"
    );
    let missing: Vec<_> = header.keys().filter(|k| !sys.contains_key(*k)).collect();
    let extra: Vec<_> = sys.keys().filter(|k| !header.contains_key(*k)).collect();
    assert!(
        missing.is_empty(),
        "declared in the header, not in sys: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "declared in sys, not in the header: {extra:?}"
    );
    for (name, sig) in &header {
        assert_eq!(
            &sys[name], sig,
            "signature of {name} differs from the header"
        );
    }
}

// ----- the documented coverage list -----

#[test]
fn documented_wrapped_list_is_what_the_safe_layer_calls() {
    let lib = crate_file("src/lib.rs");
    let begin = lib.find("<!-- wrapped:begin -->").unwrap();
    let end = lib.find("<!-- wrapped:end -->").unwrap();
    let documented: BTreeSet<String> = lib[begin..end]
        .lines()
        .filter_map(|l| l.trim_start_matches("//!").trim().strip_prefix("- `"))
        .map(|l| l.trim_end_matches('`').to_owned())
        .collect();
    let mut called = BTreeSet::new();
    for file in [
        "error.rs",
        "module.rs",
        "ops.rs",
        "platform.rs",
        "secret.rs",
        "lib.rs",
    ] {
        let src = crate_file(&format!("src/{file}"));
        for (i, _) in src.match_indices("sys::") {
            let name: String = src[i + 5..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.starts_with("oxi_") || name == "lama_manifest" {
                called.insert(name);
            }
        }
    }
    assert!(called.contains("oxi_sha384"), "the scan's positive control");
    assert_eq!(documented, called);
    let header = header_functions();
    assert!(documented.iter().all(|n| header.contains_key(n)));
}

// ----- the manifest version parser -----

#[test]
fn manifest_version_is_read_only_under_library() {
    let real = "lama: \"0.1\"\n# comment\nlibrary:\n  name: oxicrypt\n  version: \"9.8.7\"\n  \
                languages:\n    - rust\nmodules:\n  - name: x\n    version: \"9.9.9\"\n";
    assert_eq!(manifest_library_version(real), Some("9.8.7"));

    // Positive control: a decoy `version:` before the library mapping, and
    // one nested deeper inside it, are not read.
    let decoy = "version: \"1.0.0\"\nmeta:\n  version: \"2.0.0\"\nlibrary:\n  name: oxicrypt\n  \
                 nested:\n    version: \"3.0.0\"\n  version: \"9.8.7\"\n";
    assert_eq!(manifest_library_version(decoy), Some("9.8.7"));

    assert_eq!(
        manifest_library_version("library:\n  name: oxicrypt\nversion: 1\n"),
        None
    );
    assert_eq!(manifest_library_version("../llm-api.yaml"), None);
    assert_eq!(manifest_library_version(""), None);
    assert_eq!(
        manifest_library_version("library:\n  version: 9.8.7 # unquoted\n"),
        Some("9.8.7")
    );
}

#[test]
fn the_workspace_manifest_states_the_crate_version() {
    let manifest = workspace_file("docs/llm-api-manifest/llm-api.yaml");
    assert_eq!(
        manifest_library_version(&manifest),
        Some(env!("CARGO_PKG_VERSION"))
    );
}

// ----- the build script's file selection -----

#[test]
fn linux_links_the_shared_library_by_exact_name() {
    let c = select::choice("linux", "gnu").unwrap();
    assert_eq!(select::link_lib(&c), "dylib:+verbatim=liboxicrypt_ffi.so");
    let archive_only = select::check_dir(&c, |n| n == "liboxicrypt_ffi.a");
    assert!(archive_only.unwrap_err().contains("liboxicrypt_ffi.so"));
    assert!(select::check_dir(&c, |n| n.starts_with("liboxicrypt_ffi.")).is_ok());
    assert!(select::check_no_dir(&c).is_ok());
}

#[test]
fn windows_links_the_import_library_never_the_archive() {
    let msvc = select::choice("windows", "msvc").unwrap();
    assert_eq!(
        select::link_lib(&msvc),
        "dylib:+verbatim=oxicrypt_ffi.dll.lib"
    );
    assert!(select::check_dir(&msvc, |n| n == "oxicrypt_ffi.lib").is_err());
    let gnu = select::choice("windows", "gnu").unwrap();
    assert_eq!(
        select::link_lib(&gnu),
        "dylib:+verbatim=liboxicrypt_ffi.dll.a"
    );
    assert!(select::check_dir(&gnu, |n| n == "liboxicrypt_ffi.a").is_err());
}

#[test]
fn macos_refuses_an_ambiguous_or_unset_directory() {
    let c = select::choice("macos", "").unwrap();
    assert!(select::check_dir(&c, |n| n == "liboxicrypt_ffi.dylib").is_ok());
    assert!(select::check_dir(&c, |n| n.starts_with("liboxicrypt_ffi.")).is_err());
    assert!(select::check_no_dir(&c).is_err());
    assert!(select::choice("freebsd", "").is_err());
}

#[test]
fn fingerprint_values_are_validated() {
    let hex = "2fdda00fd1fb3fb167d76e67c7136cf0ac266f7881c4e2b930e4fb7e42d4b6dd";
    assert_eq!(
        select::parse_fingerprint(&format!("sha256:{hex}")).unwrap(),
        hex
    );
    assert!(select::parse_fingerprint(hex).is_err());
    assert!(select::parse_fingerprint(&format!("sha256:{}", &hex[1..])).is_err());
    assert!(select::parse_fingerprint(&format!("sha256:{}g", &hex[1..])).is_err());
}

// ----- fingerprint parsing -----

#[test]
fn fingerprint_from_hex_takes_exactly_64_hex_digits() {
    let hex = "2fdda00fd1fb3fb167d76e67c7136cf0ac266f7881c4e2b930e4fb7e42d4b6dd";
    let fp = Fingerprint::from_hex(&format!("sha256:{hex}")).unwrap();
    assert_eq!(fp.to_string(), format!("sha256:{hex}"));
    assert_eq!(Fingerprint::from_hex(hex), Some(fp));
    assert_eq!(Fingerprint::from_hex(&"+f".repeat(32)), None);
    assert_eq!(
        Fingerprint::from_hex(&format!("sha256:{}", "+0".repeat(32))),
        None
    );
    assert_eq!(Fingerprint::from_hex(&hex[1..]), None);
    assert_eq!(Fingerprint::from_hex(&format!("{hex}0")), None);
    assert_eq!(Fingerprint::from_hex(&format!(" {}", &hex[1..])), None);
    assert_eq!(Fingerprint::from_hex(&format!("{}g", &hex[1..])), None);
}

// ----- zeroization -----

#[test]
fn wipe_zeroes_a_live_buffer() {
    let mut buf = [0xA5u8; 61];
    assert!(buf.iter().all(|b| *b == 0xA5), "positive control");
    wipe(&mut buf);
    assert!(buf.iter().all(|b| *b == 0));
}

/// Drops a value in place through a raw pointer taken before any reference
/// to it, and returns its byte array read through that pointer before and
/// after the drop. The storage stays live, so both reads are defined.
macro_rules! observe_drop {
    ($ty:ty, $value:expr, $len:expr) => {{
        let mut slot = core::mem::ManuallyDrop::new($value);
        // `ManuallyDrop<T>` is `repr(transparent)` over `T`.
        let p: *mut $ty = (&raw mut slot).cast();
        let read = |p: *mut $ty| -> [u8; $len] {
            // SAFETY: `p` points to the live, initialised value; `bytes` is a
            // fully initialised array field.
            unsafe { core::ptr::read_volatile(&raw const (*p).bytes) }
        };
        let before = read(p);
        // SAFETY: the value is dropped once, here, and never used again.
        unsafe { core::ptr::drop_in_place(p) };
        (before, read(p))
    }};
}

#[test]
fn stack_secrets_zero_themselves_on_drop() {
    let (before, after) = observe_drop!(HkdfPrk, HkdfPrk::from_bytes(&[0x5A; 48]), 48);
    assert!(before.iter().all(|b| *b == 0x5A), "positive control");
    assert!(after.iter().all(|b| *b == 0));

    let (before, after) = observe_drop!(SharedSecret, SharedSecret::from_bytes(&[0x3C; 32]), 32);
    assert!(before.iter().all(|b| *b == 0x3C), "positive control");
    assert!(after.iter().all(|b| *b == 0));

    let (before, after) =
        observe_drop!(MlDsa87KeySeed, MlDsa87KeySeed::from_bytes(&[0x7E; 32]), 32);
    assert!(before.iter().all(|b| *b == 0x7E), "positive control");
    assert!(after.iter().all(|b| *b == 0));
}

/// A global allocator for the unit-test binary that, for one watched block,
/// records whether its bytes were all zero when it was freed.
mod watch {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(super) struct Watching;

    static WATCHED: AtomicUsize = AtomicUsize::new(0);
    /// `Some(all_zero)` once the watched block was freed.
    pub(super) static RESULT: Mutex<Option<bool>> = Mutex::new(None);
    /// Serialises the tests that watch a block.
    pub(super) static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    // SAFETY: forwards every call to `System` unchanged; `dealloc` only reads
    // the block, which is still allocated, before forwarding.
    unsafe impl GlobalAlloc for Watching {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: forwarded with the caller's guarantees.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if ptr as usize == WATCHED.load(Ordering::SeqCst) {
                WATCHED.store(0, Ordering::SeqCst);
                let mut zero = true;
                for i in 0..layout.size() {
                    // SAFETY: the block is still allocated and `i` is within it.
                    zero &= unsafe { core::ptr::read_volatile(ptr.add(i)) } == 0;
                }
                if let Ok(mut r) = RESULT.try_lock() {
                    *r = Some(zero);
                }
            }
            // SAFETY: forwarded with the caller's guarantees.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    pub(super) fn watch(ptr: *const u8) {
        *RESULT.lock().unwrap() = None;
        WATCHED.store(ptr as usize, Ordering::SeqCst);
    }

    pub(super) fn result() -> Option<bool> {
        *RESULT.lock().unwrap()
    }
}

#[global_allocator]
static ALLOCATOR: watch::Watching = watch::Watching;

#[test]
fn heap_secrets_are_zero_when_their_block_is_freed() {
    let _serial = watch::ONE_AT_A_TIME.lock().unwrap();

    // Positive control: a plain vector of non-zero bytes is freed non-zero.
    let plain = vec![0xC3u8; 4896];
    watch::watch(plain.as_ptr());
    drop(plain);
    assert_eq!(
        watch::result(),
        Some(false),
        "the allocator does not see frees"
    );

    let sk = MlDsa87SecretKey::from_bytes(&[0xC3; 4896]);
    watch::watch(sk.bytes.as_ptr());
    drop(sk);
    assert_eq!(watch::result(), Some(true));

    let dk = MlKem1024DecapsulationKey::from_bytes(&[0x96; 3168]);
    watch::watch(dk.bytes.as_ptr());
    drop(dk);
    assert_eq!(watch::result(), Some(true));

    let mut okm = Okm::zeroed(100);
    okm.bytes.fill(0x69);
    watch::watch(okm.bytes.as_ptr());
    drop(okm);
    assert_eq!(watch::result(), Some(true));
}

#[test]
fn secret_debug_prints_only_the_type_name() {
    use crate::secret::{
        MlDsa87KeySeed, MlKem1024EncapsSeed, MlKem1024KeySeedD, MlKem1024KeySeedZ,
    };
    let shown = [
        format!("{:?}", HkdfPrk::from_bytes(&[1; 48])),
        format!("{:?}", SharedSecret::from_bytes(&[1; 32])),
        format!("{:?}", MlDsa87KeySeed::from_bytes(&[1; 32])),
        format!("{:?}", MlKem1024KeySeedD::from_bytes(&[1; 32])),
        format!("{:?}", MlKem1024KeySeedZ::from_bytes(&[1; 32])),
        format!("{:?}", MlKem1024EncapsSeed::from_bytes(&[1; 32])),
        format!("{:?}", MlDsa87SecretKey::from_bytes(&[1; 4896])),
        format!("{:?}", MlKem1024DecapsulationKey::from_bytes(&[1; 3168])),
        format!("{:?}", {
            let mut okm = Okm::zeroed(4);
            okm.bytes.fill(1);
            okm
        }),
    ];
    assert_eq!(
        shown,
        [
            "HkdfPrk",
            "SharedSecret",
            "MlDsa87KeySeed",
            "MlKem1024KeySeedD",
            "MlKem1024KeySeedZ",
            "MlKem1024EncapsSeed",
            "MlDsa87SecretKey",
            "MlKem1024DecapsulationKey",
            "Okm",
        ]
    );
}

/// Fails to compile if `$ty` implements any of the listed traits: with an
/// implementation, `AmbiguousIfImpl<_>` has two candidates and inference
/// cannot pick one.
macro_rules! assert_not_impl {
    ($ty:ty: $($tr:path),+ $(,)?) => {$(
        const _: () = {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            #[allow(dead_code)]
            struct Invalid;
            impl<T: ?Sized + $tr> AmbiguousIfImpl<Invalid> for T {}
            let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
        };
    )+};
}

mod forbidden_traits {
    use crate::secret::{
        HkdfPrk, MlDsa87KeySeed, MlDsa87SecretKey, MlKem1024DecapsulationKey, MlKem1024EncapsSeed,
        MlKem1024KeySeedD, MlKem1024KeySeedZ, Okm, SharedSecret,
    };
    use crate::{Aes256Key, HmacDrbgSha256};
    use core::hash::Hash;

    assert_not_impl!(Aes256Key: Clone, Copy);
    assert_not_impl!(HmacDrbgSha256: Clone, Copy, Sync);
    assert_not_impl!(HkdfPrk: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(Okm: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(SharedSecret: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(MlDsa87KeySeed: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(MlKem1024KeySeedD: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(MlKem1024KeySeedZ: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(MlKem1024EncapsSeed: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(MlDsa87SecretKey: Clone, Copy, PartialEq, Hash, core::fmt::Display);
    assert_not_impl!(MlKem1024DecapsulationKey: Clone, Copy, PartialEq, Hash, core::fmt::Display);
}

// ----- the integrity detail text -----

#[test]
fn integrity_detail_reports_each_way_it_can_fail() {
    use crate::error::DetailError;
    use crate::module::{DETAIL_MAX, detail_from};
    let text = |bytes: &'static [u8]| {
        move |buf: &mut [u8]| {
            buf[..bytes.len()].copy_from_slice(bytes);
            (0, bytes.len())
        }
    };
    let unused =
        |_: &mut [u8]| -> (core::ffi::c_int, usize) { panic!("read after sizing said none") };

    assert_eq!(detail_from((1, 0), unused), Ok(None), "no failure, no text");
    assert_eq!(
        detail_from((11, 6), text(b"abcde\0")),
        Ok(Some("abcde".to_owned()))
    );
    assert_eq!(
        detail_from((10, 0), unused),
        Err(DetailError::Sizing(Error::NullPointer))
    );
    assert_eq!(
        detail_from((11, DETAIL_MAX + 1), unused),
        Err(DetailError::TooLong {
            needed: DETAIL_MAX + 1
        })
    );
    assert_eq!(
        detail_from((11, 6), |_: &mut [u8]| (11, 6)),
        Err(DetailError::Read(Error::BufferTooSmall))
    );
    assert_eq!(
        detail_from((11, 6), |_: &mut [u8]| (0, 7)),
        Err(DetailError::Overrun {
            written: 7,
            capacity: 6
        })
    );
}

// ----- the unit-test binary against the library -----

/// The unit-test binary can call the library: it carries the run-time search
/// path the integration tests carry.
#[cfg(oxicrypt_lib)]
#[test]
fn the_unit_test_binary_reaches_the_library() {
    // SAFETY: U1; no pointers in. U5 for the result.
    let manifest = unsafe { crate::sys::lama_manifest() };
    assert!(!manifest.is_null());
}

// ----- AES-256-GCM length limits -----

/// SP 800-38D §5.2.1.1: a plaintext of at most 2^39 − 256 bits and
/// additional data of at most 2^64 − 1 bits, in whole bytes.
#[cfg(target_pointer_width = "64")]
#[test]
fn gcm_length_limits_are_sp_800_38d() {
    use crate::ops::gcm_lengths;
    let payload_max: u64 = (1 << 36) - 32;
    let aad_max: u64 = (1 << 61) - 1;
    let n = |v: u64| usize::try_from(v).unwrap();
    assert_eq!(gcm_lengths(0, 0), Ok(()));
    assert_eq!(gcm_lengths(n(payload_max), n(aad_max)), Ok(()));
    assert_eq!(
        gcm_lengths(n(payload_max + 1), 0),
        Err(Error::InvalidPayloadLength)
    );
    assert_eq!(gcm_lengths(0, n(aad_max + 1)), Err(Error::InvalidAadLength));
    assert_eq!(gcm_lengths(usize::MAX, 0), Err(Error::InvalidPayloadLength));
    assert_eq!(gcm_lengths(0, usize::MAX), Err(Error::InvalidAadLength));
}
