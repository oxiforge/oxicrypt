//! The embedded verifying key.
//!
//! The integrity test verifies an ML-DSA-87 signature with a public key
//! compiled into the module. `build.rs` reads the key from the build
//! environment and this module places it in a [`KeyRecord`]: a fixed
//! structure between two magics, so the signer can find it in the file and
//! confirm it is signing for the key the artifact will verify with.
//!
//! The record is ordinary read-only data, inside the signed extent, so
//! replacing the key changes signed bytes and invalidates the signature.
//! The verifier reads the record through the same byte-acquisition
//! mechanism as the slot rather than through the static, so the key it
//! uses is the key the loaded image holds, and the fingerprint it reports
//! is the fingerprint `oxicrypt-integrity-sign --show` prints for the file.

use crate::slot::SlotDefect;

include!(concat!(env!("OUT_DIR"), "/verify_key.rs"));

/// Length of an encoded ML-DSA-87 public key (FIPS 204 `pkEncode`).
pub const VERIFY_KEY_LEN: usize = oxicrypt_ml_dsa::ml_dsa_87::PK_LEN;

/// Header magic of the key record. 16 bytes, led by a non-ASCII sentinel
/// like the slot's.
pub const KEY_RECORD_HEADER_MAGIC: [u8; 16] = [
    0xfa, b'O', b'X', b'I', b'C', b'R', b'Y', b'P', b'T', b'_', b'V', b'K', b'E', b'Y', b'_', b'H',
];

/// Footer magic of the key record. A candidate record is accepted only
/// when both magics sit at their offsets.
pub const KEY_RECORD_FOOTER_MAGIC: [u8; 16] = [
    0xfb, b'O', b'X', b'I', b'C', b'R', b'Y', b'P', b'T', b'_', b'V', b'K', b'E', b'Y', b'_', b'F',
];

/// Size of a [`KeyRecord`] in bytes.
pub const KEY_RECORD_SIZE: usize = 16 + VERIFY_KEY_LEN + 16;

/// Offset of the key within a [`KeyRecord`].
pub const KEY_RECORD_KEY_OFFSET: usize = 16;

/// Layout of the embedded verifying-key record.
#[repr(C)]
pub struct KeyRecord {
    /// Header magic, equal to [`KEY_RECORD_HEADER_MAGIC`].
    pub hdr: [u8; 16],
    /// The encoded ML-DSA-87 public key; all zero when the build had none.
    pub key: [u8; VERIFY_KEY_LEN],
    /// Footer magic, equal to [`KEY_RECORD_FOOTER_MAGIC`].
    pub ftr: [u8; 16],
}

/// The verifying key this module was built with.
///
/// `#[used]` keeps the record in the object file; the verifier takes its
/// address, which keeps it in every artifact that runs the test.
#[used]
pub static FIPS_INTEGRITY_VERIFY_KEY: KeyRecord = KeyRecord {
    hdr: KEY_RECORD_HEADER_MAGIC,
    key: VERIFY_KEY_BYTES,
    ftr: KEY_RECORD_FOOTER_MAGIC,
};

/// Runtime address of the embedded key record.
#[must_use]
pub fn key_record_address() -> usize {
    core::ptr::from_ref(&FIPS_INTEGRITY_VERIFY_KEY) as usize
}

/// Decodes a key record's bytes.
///
/// `Ok(None)` is a record holding the all-zero key: a build with no
/// verifying key.
///
/// # Errors
///
/// [`SlotDefect::KeyRecord`] when `bytes` is not [`KEY_RECORD_SIZE`] long
/// or either magic is absent.
pub fn parse_key_record(bytes: &[u8]) -> Result<Option<[u8; VERIFY_KEY_LEN]>, SlotDefect> {
    if bytes.len() != KEY_RECORD_SIZE
        || bytes.get(..16) != Some(KEY_RECORD_HEADER_MAGIC.as_slice())
        || bytes.get(KEY_RECORD_SIZE.saturating_sub(16)..)
            != Some(KEY_RECORD_FOOTER_MAGIC.as_slice())
    {
        return Err(SlotDefect::KeyRecord);
    }
    let mut key = [0u8; VERIFY_KEY_LEN];
    key.copy_from_slice(
        bytes
            .get(KEY_RECORD_KEY_OFFSET..KEY_RECORD_KEY_OFFSET.saturating_add(VERIFY_KEY_LEN))
            .ok_or(SlotDefect::KeyRecord)?,
    );
    if key.iter().all(|&b| b == 0) {
        Ok(None)
    } else {
        Ok(Some(key))
    }
}

/// Locates the key record in an artifact's file bytes.
///
/// Exactly one record must be present, identified by both magics at their
/// offsets.
///
/// # Errors
///
/// A description when no record or several are found.
pub fn find_key_record(bytes: &[u8]) -> Result<usize, String> {
    let Some(last) = bytes.len().checked_sub(KEY_RECORD_SIZE) else {
        return Err("artifact is smaller than one key record".to_owned());
    };
    let footer_at = KEY_RECORD_SIZE.saturating_sub(16);
    let mut found = Vec::new();
    for i in 0..=last {
        if bytes.get(i..i.saturating_add(16)) != Some(KEY_RECORD_HEADER_MAGIC.as_slice()) {
            continue;
        }
        let f = i.saturating_add(footer_at);
        if bytes.get(f..f.saturating_add(16)) == Some(KEY_RECORD_FOOTER_MAGIC.as_slice()) {
            found.push(i);
        }
    }
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(
            "no verifying-key record found: the artifact was not linked against \
             oxicrypt-integrity"
                .to_owned(),
        ),
        many => Err(format!(
            "{} verifying-key records found; exactly one is required",
            many.len()
        )),
    }
}
