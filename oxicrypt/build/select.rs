//! Which library file the build script links, by name, per target.
//!
//! Shared by `build.rs` and the crate's unit tests, so the rule the tests
//! check is the rule the build runs.

/// The shared library to link for one target, and the static archive that a
/// linker search could pick in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Choice {
    /// The file the linker must be given: the shared library, or on Windows
    /// its import library.
    pub(crate) file: &'static str,
    /// The static archive of the same library, which must never be linked.
    pub(crate) archive: &'static str,
    /// Whether the toolchain honours `+verbatim`, so that the file is named
    /// exactly and a static archive beside it cannot be chosen.
    pub(crate) verbatim: bool,
}

/// The choice for `target_os` / `target_env` (cargo's `CARGO_CFG_TARGET_OS`
/// and `CARGO_CFG_TARGET_ENV`), or the reason the target is refused.
pub(crate) fn choice(target_os: &str, target_env: &str) -> Result<Choice, String> {
    match (target_os, target_env) {
        ("linux" | "android", _) => Ok(Choice {
            file: "liboxicrypt_ffi.so",
            archive: "liboxicrypt_ffi.a",
            verbatim: true,
        }),
        ("macos" | "ios", _) => Ok(Choice {
            file: "liboxicrypt_ffi.dylib",
            archive: "liboxicrypt_ffi.a",
            verbatim: false,
        }),
        ("windows", "msvc") => Ok(Choice {
            file: "oxicrypt_ffi.dll.lib",
            archive: "oxicrypt_ffi.lib",
            verbatim: true,
        }),
        ("windows", "gnu") => Ok(Choice {
            file: "liboxicrypt_ffi.dll.a",
            archive: "liboxicrypt_ffi.a",
            verbatim: true,
        }),
        _ => Err(format!(
            "oxicrypt: no shared-library rule for target_os={target_os} \
             target_env={target_env}"
        )),
    }
}

/// The `cargo:rustc-link-lib` value for a choice.
pub(crate) fn link_lib(choice: &Choice) -> String {
    if choice.verbatim {
        format!("dylib:+verbatim={}", choice.file)
    } else {
        "dylib=oxicrypt_ffi".to_owned()
    }
}

/// Checks a configured library directory, given whether each file name is
/// present in it.
pub(crate) fn check_dir(choice: &Choice, present: impl Fn(&str) -> bool) -> Result<(), String> {
    if !present(choice.file) {
        return Err(format!(
            "oxicrypt: OXICRYPT_LIB_DIR does not hold {}, the shared library this \
             crate links; it never links the static archive {}",
            choice.file, choice.archive
        ));
    }
    if !choice.verbatim && present(choice.archive) {
        return Err(format!(
            "oxicrypt: OXICRYPT_LIB_DIR holds both {} and the static archive {}; on \
             this target the linker could choose the archive, so point OXICRYPT_LIB_DIR at a \
             directory holding the shared library alone",
            choice.file, choice.archive
        ));
    }
    Ok(())
}

/// Checks the absence of a configured directory: allowed only where verbatim
/// naming means the linker's search cannot resolve to a static archive.
pub(crate) fn check_no_dir(choice: &Choice) -> Result<(), String> {
    if choice.verbatim {
        Ok(())
    } else {
        Err(format!(
            "oxicrypt: set OXICRYPT_LIB_DIR to the directory holding {}; on this target \
             a search of the linker's default paths could choose a static archive",
            choice.file
        ))
    }
}

/// Validates an `OXICRYPT_LIB_FINGERPRINT` value and returns its 64 hex
/// digits, lower case.
pub(crate) fn parse_fingerprint(value: &str) -> Result<String, String> {
    let hex = value.strip_prefix("sha256:").unwrap_or("");
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex.to_ascii_lowercase())
    } else {
        Err(format!(
            "oxicrypt: OXICRYPT_LIB_FINGERPRINT must be sha256:<64 hex digits>, as \
             `oxicrypt-integrity-sign --show <library>` prints it; got {value:?}"
        ))
    }
}
