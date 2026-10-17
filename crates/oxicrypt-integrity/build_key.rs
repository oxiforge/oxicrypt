//! Reading and checking the verifying key `build.rs` embeds.
//!
//! A separate file so the crate's own tests compile the same functions
//! `build.rs` runs and pin each refusal; a build script has no test
//! harness of its own.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::Path;

/// Length of an encoded ML-DSA-87 public key (FIPS 204 `pkEncode`).
pub(crate) const KEY_LEN: usize = 2_592;

/// The two build variables, read as OS strings so a value that is not
/// valid UTF-8 is refused rather than read as unset.
///
/// `read` reads the file the path variable names.
pub(crate) fn resolve_key(
    file: Option<&OsStr>,
    hex: Option<&OsStr>,
    read: &dyn Fn(&Path) -> std::io::Result<Vec<u8>>,
) -> Result<Option<[u8; KEY_LEN]>, String> {
    match (file, hex) {
        (Some(_), Some(_)) => Err(
            "set OXICRYPT_INTEGRITY_VERIFY_KEY or OXICRYPT_INTEGRITY_VERIFY_KEY_HEX, not both"
                .to_owned(),
        ),
        (Some(path), None) => {
            let bytes = read(Path::new(path)).map_err(|e| {
                format!(
                    "OXICRYPT_INTEGRITY_VERIFY_KEY names {}, which cannot be read: {e}",
                    path.to_string_lossy()
                )
            })?;
            checked(&bytes, "the file OXICRYPT_INTEGRITY_VERIFY_KEY names").map(Some)
        }
        (None, Some(hex)) => {
            let hex = hex.to_str().ok_or(
                "OXICRYPT_INTEGRITY_VERIFY_KEY_HEX is not valid UTF-8; it must be 5184 hex digits",
            )?;
            checked(
                &decode_hex(hex.trim())?,
                "OXICRYPT_INTEGRITY_VERIFY_KEY_HEX",
            )
            .map(Some)
        }
        (None, None) => Ok(None),
    }
}

/// Requires exactly [`KEY_LEN`] bytes, not all zero (the encoding of "no
/// key").
///
/// Every byte string of that length decodes as an ML-DSA-87 public key
/// (FIPS 204 `pkDecode` has no invalid input), so the length is the whole
/// structural check; a key that is not the signer's is refused at power-up
/// as a key mismatch.
pub(crate) fn checked(bytes: &[u8], source: &str) -> Result<[u8; KEY_LEN], String> {
    let key: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
        format!(
            "{source} must hold a {KEY_LEN}-byte ML-DSA-87 public key, not {} bytes",
            bytes.len()
        )
    })?;
    if key.iter().all(|&b| b == 0) {
        return Err(format!(
            "{source} holds an all-zero key, which is how a build with no key is encoded"
        ));
    }
    Ok(key)
}

/// Decodes an even number of hex digits.
pub(crate) fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "OXICRYPT_INTEGRITY_VERIFY_KEY_HEX must be an even number of hex digits".to_owned(),
        );
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|d| u8::from_str_radix(d, 16).ok())
                .ok_or_else(|| "OXICRYPT_INTEGRITY_VERIFY_KEY_HEX holds a non-hex digit".to_owned())
        })
        .collect()
}

/// The Rust source `build.rs` writes for `key`, all zero when there is
/// none.
pub(crate) fn emit(key: Option<&[u8; KEY_LEN]>) -> String {
    let mut src = String::from(
        "/// The verifying key this build embeds: all zero when the build had none.\n\
         const VERIFY_KEY_BYTES: [u8; VERIFY_KEY_LEN] = [",
    );
    for b in key.unwrap_or(&[0u8; KEY_LEN]) {
        let _ = write!(src, "{b:#04x}, ");
    }
    src.push_str("];\n");
    src
}
