//! Shared by the integration tests: initialisation for either build mode,
//! the fixture's directories, and reading published vectors from the
//! repository's vendored ACVP slices.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use oxicrypt::{InitError, Module, Profile};

/// `Module::init`, or `Module::init_unpinned` in a crate built unpinned.
#[allow(clippy::result_large_err)]
pub(crate) fn init(profile: Profile) -> Result<Module, InitError> {
    #[cfg(oxicrypt_pinned)]
    let result = Module::init(profile);
    #[cfg(not(oxicrypt_pinned))]
    let result = Module::init_unpinned(profile);
    result
}

/// The directory the crate was linked against (the fixture's `signed/`).
pub(crate) fn lib_dir() -> PathBuf {
    PathBuf::from(env!("OXICRYPT_BINDINGS_LIB_DIR"))
}

/// The fixture's root: the parent of `signed/`, holding `unsigned/` and
/// `second-key/` beside it.
pub(crate) fn fixture_dir() -> PathBuf {
    lib_dir().parent().unwrap().to_path_buf()
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub(crate) fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes, got {}", bytes.len()))
}

/// The hex field `field` of test case `tc_id` in a vendored ACVP slice,
/// `vendor/nist/acvp-server/gen-val/json-files/<dir>/<file>`. Each slice
/// records its upstream commit and path in its `_source` header.
pub(crate) fn acvp(dir: &str, file: &str, tc_id: u32, field: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vendor/nist/acvp-server/gen-val/json-files")
        .join(dir)
        .join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} (this test runs in the workspace)",
            path.display()
        )
    });
    let groups = text.find("\"testGroups\"").expect("testGroups");
    let text = &text[groups..];
    let case = format!("\"tcId\": {tc_id},");
    let start = text
        .find(&case)
        .unwrap_or_else(|| panic!("tcId {tc_id} not in {}", path.display()));
    let rest = &text[start + case.len()..];
    let end = rest.find("\"tcId\"").unwrap_or(rest.len());
    let rest = &rest[..end];
    let key = format!("\"{field}\": \"");
    let at = rest
        .find(&key)
        .unwrap_or_else(|| panic!("{field} not in tcId {tc_id} of {}", path.display()));
    let value = &rest[at + key.len()..];
    unhex(&value[..value.find('"').unwrap()])
}

/// The fingerprint of the signed fixture library's verifying key, as the
/// fixture's signer reports it with `--show`.
pub(crate) fn fixture_fingerprint() -> String {
    let signer = fixture_dir().join("bin/oxicrypt-integrity-sign");
    let out = std::process::Command::new(&signer)
        .arg("--show")
        .arg(lib_dir().join("liboxicrypt_ffi.so"))
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", signer.display()));
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("verify key: "))
        .expect("--show reports the verify key")
        .to_owned()
}
