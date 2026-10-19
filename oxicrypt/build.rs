//! Links the program to the signed shared library `liboxicrypt_ffi`.
//!
//! Reads, at build time only:
//!
//! - `OXICRYPT_LIB_DIR`: the directory holding the shared library (and on
//!   Windows its import library). The file is chosen by name; a static
//!   archive is never linked.
//! - `OXICRYPT_LIB_FINGERPRINT=sha256:<64 hex digits>`: the fingerprint of the
//!   verifying key the library embeds. `Module::init` refuses a library that
//!   reports another.
//! - `OXICRYPT_LIB_UNPINNED=1`: the explicit opt-out from the fingerprint pin,
//!   which enables `Module::init_unpinned` instead of `Module::init`.
//! - `OXICRYPT_LIB_OPTIONAL=1`: with no `OXICRYPT_LIB_DIR`, build without
//!   linking the library at all, for a run of the crate's own unit tests that
//!   withdraws the claim that the library was tested.
//!
//! A build that links the library requires exactly one of the fingerprint
//! and the opt-out.

#![allow(clippy::print_stdout, clippy::print_stderr)] // a build script talks to cargo on stdout

#[path = "build/select.rs"]
mod select;

use std::env;
use std::path::Path;
use std::process::exit;

fn refuse(message: &str) -> ! {
    eprintln!("{message}");
    exit(1);
}

/// The value of `name` as UTF-8, `None` when unset or empty; a value that is
/// not UTF-8 is refused, never read as unset.
fn text(name: &str) -> Option<String> {
    let value = env::var_os(name)?;
    if value.is_empty() {
        return None;
    }
    match value.into_string() {
        Ok(v) => Some(v),
        Err(_) => refuse(&format!("oxicrypt: {name} is not valid UTF-8")),
    }
}

fn flag(name: &str) -> bool {
    text(name).is_some_and(|v| v == "1")
}

fn main() {
    for var in [
        "OXICRYPT_LIB_DIR",
        "OXICRYPT_LIB_FINGERPRINT",
        "OXICRYPT_LIB_UNPINNED",
        "OXICRYPT_LIB_OPTIONAL",
        "DOCS_RS",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-changed=build/select.rs");
    println!("cargo:rustc-check-cfg=cfg(oxicrypt_lib)");
    println!("cargo:rustc-check-cfg=cfg(oxicrypt_pinned)");
    println!("cargo:rustc-check-cfg=cfg(oxicrypt_unpinned)");

    let dir = text("OXICRYPT_LIB_DIR");
    if dir.is_none() && (flag("OXICRYPT_LIB_OPTIONAL") || env::var_os("DOCS_RS").is_some()) {
        return;
    }

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let choice = select::choice(&os, &target_env).unwrap_or_else(|e| refuse(&e));

    let pin = text("OXICRYPT_LIB_FINGERPRINT");
    match (pin, flag("OXICRYPT_LIB_UNPINNED")) {
        (Some(value), false) => {
            let hex = select::parse_fingerprint(&value).unwrap_or_else(|e| refuse(&e));
            println!("cargo:rustc-env=OXICRYPT_BINDINGS_PIN={hex}");
            println!("cargo:rustc-cfg=oxicrypt_pinned");
        }
        (None, true) => println!("cargo:rustc-cfg=oxicrypt_unpinned"),
        (Some(_), true) => refuse(
            "oxicrypt: OXICRYPT_LIB_FINGERPRINT and OXICRYPT_LIB_UNPINNED=1 are both \
             set; choose one",
        ),
        (None, false) => refuse(
            "oxicrypt: set OXICRYPT_LIB_FINGERPRINT=sha256:<64 hex digits> to the \
             fingerprint `oxicrypt-integrity-sign --show <library>` prints, or \
             OXICRYPT_LIB_UNPINNED=1 to accept any honestly signed library, or, with no \
             OXICRYPT_LIB_DIR, OXICRYPT_LIB_OPTIONAL=1 to build this crate without linking \
             the library (its unit tests only)",
        ),
    }

    match dir {
        Some(dir) => {
            let path = Path::new(&dir);
            select::check_dir(&choice, |name| path.join(name).is_file())
                .unwrap_or_else(|e| refuse(&e));
            let shown = path.display();
            // Run again when the directory's contents change: the choice
            // above depends on which files it holds.
            println!("cargo:rerun-if-changed={shown}");
            println!("cargo:rustc-link-search=native={shown}");
            println!("cargo:rustc-cfg=oxicrypt_lib");
            println!("cargo:rustc-env=OXICRYPT_BINDINGS_LIB_DIR={shown}");
            // A run-time search path for this package's own linked targets:
            // the unit-test binary, the integration tests and the examples.
            // It never reaches a dependent program, whose link arguments are
            // its own. RUNPATH rather than RPATH, so the loader's environment
            // still overrides it, which the control tests rely on.
            if matches!(os.as_str(), "linux" | "android") {
                println!("cargo:rustc-link-arg=-Wl,--enable-new-dtags");
                println!("cargo:rustc-link-arg=-Wl,-rpath,{shown}");
            } else if matches!(os.as_str(), "macos" | "ios") {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{shown}");
            }
        }
        None => select::check_no_dir(&choice).unwrap_or_else(|e| refuse(&e)),
    }
    println!("cargo:rustc-link-lib={}", select::link_lib(&choice));
}
