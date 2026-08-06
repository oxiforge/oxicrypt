//! Software integrity self-test for the oxicrypt FIPS module.
//!
//! # Approved service
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | Module binary integrity check | FIPS 140-3 §7.10 / IG 10.3.A | [`integrity_self_test`] |
//!
//! This crate implements the power-up integrity check required by
//! FIPS 140-3 IG 10.3.A (as of March 2026). The check verifies that
//! the module binary on disk has not been modified since it was
//! signed by recomputing an HMAC-SHA-256 over the exact file bytes of
//! the currently-running executable and comparing against a
//! reference MAC embedded **inside** the binary at a reserved slot.
//!
//! # Sensitive security parameters
//!
//! None. The integrity HMAC key is public build-time material (see
//! "HMAC key policy" below); the MAC itself is public, and the
//! module binary bytes are public. No CSPs pass through this
//! crate's API.
//!
//! # Design: embedded slot
//!
//! The module binary embeds a 64-byte reserved slot at link time via
//! [`FIPS_INTEGRITY_SLOT`], an `#[used] pub static` with the layout
//!
//! ```text
//! [ HDR (16 bytes) | MAC (32 bytes) | FTR (16 bytes) ]
//! ```
//!
//! The HDR and FTR are fixed byte patterns chosen to be
//! cryptographically unlikely to appear elsewhere in the binary. The
//! MAC field is zero in an unsigned binary. At sign time, the
//! companion tool `fips-integrity-sign --sign <exe>`:
//!
//! 1. reads the module binary into a buffer,
//! 2. locates the slot by scanning for HDR and verifying that FTR
//!    appears at offset +48 from the match,
//! 3. zeroes the 32 MAC bytes in the buffer (idempotent re-sign),
//! 4. computes HMAC-SHA-256 over the entire buffer with the fixed
//!    public integrity key [`FIPS_INTEGRITY_KEY`], and
//! 5. writes the modified buffer — with the computed MAC spliced into
//!    the slot — back to disk.
//!
//! At runtime, the power-up KAT reads the on-disk bytes of
//! `env::current_exe()`, finds the slot, extracts the expected MAC,
//! zeroes the slot in its in-memory copy, recomputes the HMAC, and
//! compares against the extracted MAC in constant time.
//!
//! # Why embedded instead of a sidecar file
//!
//! An earlier version of this crate used a `<exe>.fipshmac` sidecar
//! written next to the executable. The sidecar pattern is simple on
//! Linux, macOS, and Windows command-line tools but breaks on
//! code-signed mobile bundles:
//!
//! - iOS `.app` bundles are signed as a unit; writing a sidecar at
//!   install time invalidates Apple's code signature and writing one
//!   at runtime is blocked by bundle immutability.
//! - Android APKs are zip archives; individual files inside an APK
//!   are not writable post-install.
//!
//! An embedded MAC travels with the binary across the signing
//! boundary on all three mobile OSes, so a single mechanism covers
//! every target this module intends to support.
//!
//! # Why scan for a magic, not parse ELF/Mach-O/PE
//!
//! Looking up the slot by the address of [`FIPS_INTEGRITY_SLOT`] and
//! converting that address to a file offset would require per-platform
//! ELF, Mach-O, and PE parsers. Scanning the on-disk bytes for a
//! 16-byte header magic plus a 16-byte footer magic 32 bytes later is
//! portable, pure Rust, no `unsafe`, and robust to any dedup choice
//! the linker might make: even if the scanner itself references the
//! header pattern somewhere in the code, the footer-at-+48 check
//! rejects any occurrence that isn't a real slot.
//!
//! # HMAC key policy
//!
//! The HMAC key is a fixed, publicly known 32-byte constant. IG
//! 10.3.A permits a known key here because the integrity check is an
//! **authenticity** check, not a secrecy check: the property that
//! matters is that an attacker who rewrites the module binary cannot
//! also predict the corresponding reference MAC without knowing the
//! key embedded in the module source. The key is therefore a
//! build-time constant, not a runtime secret. Rotating the key
//! requires re-validation per IG 10.3.A.
//!
//! # Boot flow
//!
//! The `integrity_self_test` function is registered in [`KATS`] as a
//! power-up KAT. During module boot the `fips-module` runner calls it
//! while the module is in `SelfTest` state, meaning the standard
//! `HmacSha256::new` entry point is still gated by
//! `require_operational()` and would return `NotOperational`. This
//! crate therefore routes through `HmacSha256::new_internal`, the
//! gateless constructor that exists for exactly this reason.
//!
//! # Failure modes
//!
//! Any of the following counts as an integrity failure and causes the
//! runner to latch the module into the terminal `Error` state:
//!
//! - The current executable path cannot be resolved.
//! - The executable cannot be read.
//! - No valid slot is found in the binary (missing header/footer, or
//!   header/footer not aligned).
//! - More than one valid slot is found (ambiguous binary, treated as
//!   tampering).
//! - The computed MAC does not equal the MAC stored in the slot in
//!   constant time.
//!
//! # Signing workflow (development)
//!
//! ```text
//! cargo build -p fips-integrity --bin fips-integrity-sign
//! cargo build -p acvp-harness
//! ./target/debug/fips-integrity-sign --sign ./target/debug/acvp-harness
//! ./target/debug/acvp-harness
//! ```
//!
//! A production build would run the signer as a post-link step in
//! the build pipeline and ship the signed binary; the runtime boot
//! path never calls [`sign_exe`].

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io;
use std::path::Path;

use oxicrypt_hmac::HmacSha256;
use oxicrypt_module::{KatEntry, SelfTestFailure};

/// Fixed, publicly known HMAC key used for the software integrity
/// self-test.
///
/// The key material is the UTF-8 bytes of the ASCII literal
/// `"oxicrypt-fips140-3-integrity-key"` (32 bytes) — not a secret,
/// just a stable value that is trivially auditable from the source
/// tree.
///
/// The literal is exactly 32 bytes, which is what fixes its spelling:
/// `"oxicrypt-fips-140-3-integrity-key!"` would read more naturally
/// but is 34. `integrity_key_matches_its_documented_literal` asserts
/// the constant against the text above, so the two cannot drift.
pub const FIPS_INTEGRITY_KEY: [u8; 32] = *b"oxicrypt-fips140-3-integrity-key";

/// Header magic for the embedded integrity slot. 16 bytes.
///
/// The leading `0xfc` byte is a deliberately non-ASCII sentinel: it
/// makes the pattern unlikely to appear in a string table and lets
/// the scanner short-circuit on a byte that rarely occurs in text
/// sections.
pub const SLOT_HEADER_MAGIC: [u8; 16] = [
    0xfc, b'O', b'X', b'I', b'C', b'R', b'Y', b'P', b'T', b'_', b'F', b'I', b'P', b'S', b'_', b'H',
];

/// Footer magic for the embedded integrity slot. 16 bytes. Paired
/// with [`SLOT_HEADER_MAGIC`]; the scanner requires both to appear at
/// the correct relative offsets before accepting a candidate slot.
pub const SLOT_FOOTER_MAGIC: [u8; 16] = [
    0xfd, b'O', b'X', b'I', b'C', b'R', b'Y', b'P', b'T', b'_', b'F', b'I', b'P', b'S', b'_', b'F',
];

/// Size in bytes of the embedded integrity slot.
pub const SLOT_SIZE: usize = 64;

/// Offset of the MAC field within the slot (after the 16-byte
/// header).
pub const MAC_OFFSET_IN_SLOT: usize = 16;

/// Length in bytes of the MAC field.
pub const MAC_SIZE: usize = 32;

/// Offset of the footer within the slot (header + MAC).
pub const FOOTER_OFFSET_IN_SLOT: usize = 48;

/// Reserved 64-byte integrity slot layout.
///
/// `#[repr(C)]` pins field order so the on-disk byte layout matches
/// the source declaration exactly, which is what the signer and
/// verifier both scan for.
#[repr(C)]
pub struct IntegritySlot {
    /// Header magic, must equal [`SLOT_HEADER_MAGIC`].
    pub hdr: [u8; 16],
    /// HMAC-SHA-256 over the module binary with this field zeroed.
    /// All zeros in an unsigned binary.
    pub mac: [u8; 32],
    /// Footer magic, must equal [`SLOT_FOOTER_MAGIC`].
    pub ftr: [u8; 16],
}

/// The module-binary integrity slot.
///
/// `#[used]` prevents the linker from discarding the static even
/// though it is never read from Rust code (the runtime check reads it
/// back through the on-disk file bytes, not the in-memory symbol).
/// Because the slot is a regular `pub static` with inline byte-array
/// fields, the linker places its 64 bytes contiguously in `.rodata`
/// exactly as declared. Signing and verification both find this
/// region by scanning the on-disk file for the header/footer pair.
#[used]
pub static FIPS_INTEGRITY_SLOT: IntegritySlot = IntegritySlot {
    hdr: SLOT_HEADER_MAGIC,
    mac: [0u8; 32],
    ftr: SLOT_FOOTER_MAGIC,
};

/// Errors surfaced by the standalone integrity-check helpers.
///
/// The power-up KAT itself returns only [`SelfTestFailure`] — the
/// runner has no use for richer error information at boot time — but
/// the signer tool uses these variants to give operators actionable
/// diagnostics.
#[derive(Debug)]
pub enum IntegrityError {
    /// Resolving `env::current_exe()` failed.
    CurrentExeUnresolved(io::Error),
    /// The executable could not be read.
    ExeReadFailed(io::Error),
    /// The signed buffer could not be written back to the executable
    /// path.
    ExeWriteFailed(io::Error),
    /// No `[HDR | 32 bytes | FTR]` slot was found in the binary.
    /// Usually means the binary was not linked against this crate,
    /// or the slot was stripped by a hostile post-processing step.
    SlotNotFound,
    /// More than one valid slot was found. Treated as tampering: a
    /// benign binary contains exactly one slot.
    MultipleSlotsFound,
    /// The HMAC computed over the slot-zeroed buffer did not match
    /// the MAC stored in the slot.
    MacMismatch,
}

impl core::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CurrentExeUnresolved(e) => {
                write!(f, "could not resolve current executable path: {e}")
            }
            Self::ExeReadFailed(e) => write!(f, "could not read module binary: {e}"),
            Self::ExeWriteFailed(e) => write!(f, "could not write signed module binary: {e}"),
            Self::SlotNotFound => f.write_str(
                "embedded integrity slot not found; binary was not linked against fips-integrity or the slot was stripped",
            ),
            Self::MultipleSlotsFound => f.write_str(
                "multiple integrity slots found; module binary has been tampered with",
            ),
            Self::MacMismatch => f.write_str(
                "module binary integrity MAC mismatch — the binary has been modified since signing",
            ),
        }
    }
}

impl std::error::Error for IntegrityError {}

/// Scans a module buffer for the embedded integrity slot.
///
/// Returns the absolute byte offset of the slot's header. A slot is
/// counted as valid only if [`SLOT_HEADER_MAGIC`] appears at offset
/// `i` **and** [`SLOT_FOOTER_MAGIC`] appears at offset
/// `i + FOOTER_OFFSET_IN_SLOT`; this rejects spurious occurrences of
/// the header pattern that might show up because the linker placed a
/// standalone copy of the constant somewhere in `.rodata`.
///
/// Returns `SlotNotFound` if zero valid slots are present, and
/// `MultipleSlotsFound` if more than one is present.
pub fn find_slot_offset(bytes: &[u8]) -> Result<usize, IntegrityError> {
    let mut valid: Option<usize> = None;
    let len = bytes.len();
    if len < SLOT_SIZE {
        return Err(IntegrityError::SlotNotFound);
    }
    // Last index at which a full 64-byte window still fits.
    let last = len.saturating_sub(SLOT_SIZE);
    for i in 0..=last {
        let Some(window_end) = i.checked_add(SLOT_SIZE) else {
            break;
        };
        let Some(window) = bytes.get(i..window_end) else {
            continue;
        };
        let Some(hdr) = window.get(..16) else {
            continue;
        };
        let Some(ftr) = window.get(FOOTER_OFFSET_IN_SLOT..SLOT_SIZE) else {
            continue;
        };
        if hdr == SLOT_HEADER_MAGIC.as_slice() && ftr == SLOT_FOOTER_MAGIC.as_slice() {
            if valid.is_some() {
                return Err(IntegrityError::MultipleSlotsFound);
            }
            valid = Some(i);
        }
    }
    valid.ok_or(IntegrityError::SlotNotFound)
}

/// Zeros the MAC bytes of the slot at `slot_offset` in `bytes` and
/// computes HMAC-SHA-256 over the whole buffer.
///
/// Shared by [`sign_exe`] and [`verify_exe`] so the two paths cannot
/// disagree on what "HMAC over the module binary" means.
fn hmac_with_slot_zeroed(bytes: &mut [u8], slot_offset: usize) -> Result<[u8; 32], IntegrityError> {
    let mac_start = slot_offset
        .checked_add(MAC_OFFSET_IN_SLOT)
        .ok_or(IntegrityError::SlotNotFound)?;
    let mac_end = mac_start
        .checked_add(MAC_SIZE)
        .ok_or(IntegrityError::SlotNotFound)?;
    let slot_mac = bytes
        .get_mut(mac_start..mac_end)
        .ok_or(IntegrityError::SlotNotFound)?;
    for b in slot_mac.iter_mut() {
        *b = 0;
    }
    let mut mac = HmacSha256::new_internal(&FIPS_INTEGRITY_KEY);
    mac.update(bytes);
    Ok(mac.finalize())
}

/// Extracts the 32-byte MAC stored in the slot at `slot_offset`.
fn extract_slot_mac(bytes: &[u8], slot_offset: usize) -> Result<[u8; 32], IntegrityError> {
    let mac_start = slot_offset
        .checked_add(MAC_OFFSET_IN_SLOT)
        .ok_or(IntegrityError::SlotNotFound)?;
    let mac_end = mac_start
        .checked_add(MAC_SIZE)
        .ok_or(IntegrityError::SlotNotFound)?;
    let slice = bytes
        .get(mac_start..mac_end)
        .ok_or(IntegrityError::SlotNotFound)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Writes the 32-byte MAC into the slot at `slot_offset` in `bytes`.
fn splice_slot_mac(
    bytes: &mut [u8],
    slot_offset: usize,
    mac: &[u8; 32],
) -> Result<(), IntegrityError> {
    let mac_start = slot_offset
        .checked_add(MAC_OFFSET_IN_SLOT)
        .ok_or(IntegrityError::SlotNotFound)?;
    let mac_end = mac_start
        .checked_add(MAC_SIZE)
        .ok_or(IntegrityError::SlotNotFound)?;
    let slot_mac = bytes
        .get_mut(mac_start..mac_end)
        .ok_or(IntegrityError::SlotNotFound)?;
    slot_mac.copy_from_slice(mac);
    Ok(())
}

/// Formats a 32-byte MAC as 64 lowercase hex characters. Used by the
/// signer tool when printing the MAC to stdout.
#[must_use]
pub fn encode_hmac_hex(mac: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (pair, &byte) in out.chunks_exact_mut(2).zip(mac.iter()) {
        let high = HEX.get((byte >> 4) as usize).copied().unwrap_or(b'0');
        let low = HEX.get((byte & 0x0f) as usize).copied().unwrap_or(b'0');
        if let Some(slot) = pair.first_mut() {
            *slot = high;
        }
        if let Some(slot) = pair.get_mut(1) {
            *slot = low;
        }
    }
    out
}

/// Compares two 32-byte MACs in constant time.
///
/// Short-circuiting comparison would let a timing attacker brute
/// force the expected MAC one byte at a time; the integrity check
/// happens against untrusted on-disk bytes, so we take the same care
/// here that we would for any secret MAC verification.
#[must_use]
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (ai, bi) in a.iter().zip(b.iter()) {
        diff |= ai ^ bi;
    }
    diff == 0
}

/// Computes the expected MAC for `exe_path` and writes it back into
/// the embedded slot, returning the computed MAC.
///
/// Used by `fips-integrity-sign --sign`. This function reads the
/// entire module binary into memory, zeroes the slot MAC bytes,
/// computes HMAC-SHA-256, and writes the modified buffer back over
/// the original file. Existing file permissions are preserved by
/// `std::fs::write`'s truncate-then-write semantics.
///
/// Must not be called against a running executable on Linux: the
/// kernel rejects writes to a file that currently backs any process
/// image with `ETXTBSY`. The standard development workflow is to run
/// the signer between `cargo build` and execution.
///
/// # Errors
///
/// Returns [`IntegrityError`] on I/O failure, missing slot, or
/// multiple-slot detection.
pub fn sign_exe(exe_path: &Path) -> Result<[u8; 32], IntegrityError> {
    let mut bytes = fs::read(exe_path).map_err(IntegrityError::ExeReadFailed)?;
    let slot_offset = find_slot_offset(&bytes)?;
    let mac = hmac_with_slot_zeroed(&mut bytes, slot_offset)?;
    splice_slot_mac(&mut bytes, slot_offset, &mac)?;
    fs::write(exe_path, &bytes).map_err(IntegrityError::ExeWriteFailed)?;
    Ok(mac)
}

/// Verifies the integrity of `exe_path` against its embedded slot.
///
/// Reads the file, locates the slot, extracts the expected MAC,
/// zeroes the slot MAC bytes in the in-memory copy, recomputes
/// HMAC-SHA-256, and compares in constant time.
///
/// # Errors
///
/// Returns [`IntegrityError::MacMismatch`] if the MAC differs from
/// the slot, or an appropriate I/O / slot-lookup error on other
/// failure modes.
pub fn verify_exe(exe_path: &Path) -> Result<(), IntegrityError> {
    let mut bytes = fs::read(exe_path).map_err(IntegrityError::ExeReadFailed)?;
    let slot_offset = find_slot_offset(&bytes)?;
    let expected = extract_slot_mac(&bytes, slot_offset)?;
    let computed = hmac_with_slot_zeroed(&mut bytes, slot_offset)?;
    if constant_time_eq(&expected, &computed) {
        Ok(())
    } else {
        Err(IntegrityError::MacMismatch)
    }
}

/// Power-up integrity KAT.
///
/// Resolves the current executable via `env::current_exe()`, reads
/// the on-disk bytes, and runs [`verify_exe`]. Returns
/// [`SelfTestFailure`] on any error so the `fips-module` runner can
/// latch the module into the terminal `Error` state.
///
/// Do not call this directly from application code — it is wired
/// into [`KATS`] and runs as part of
/// `oxicrypt_module::initialize_with_tests`.
///
/// # Errors
///
/// Returns [`SelfTestFailure`] if the executable path cannot be
/// resolved, the binary cannot be read, the embedded slot cannot be
/// found, or the computed MAC does not match the slot's MAC.
pub fn integrity_self_test() -> Result<(), SelfTestFailure> {
    let exe = env::current_exe().map_err(|_| SelfTestFailure)?;
    verify_exe(&exe).map_err(|_| SelfTestFailure)
}

/// Power-up KAT inventory for the software integrity self-test.
///
/// Merged into the acvp-harness boot sequence via
/// `oxicrypt_module::initialize_with_tests`. Per FIPS 140-3 IG 10.3.A the
/// integrity check is a mandatory power-up KAT and must run on every
/// module startup.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "Module binary integrity (HMAC-SHA-256 over embedded slot in current_exe())",
    run: integrity_self_test,
}];

// ----------------------------------------------------------------------
// Unit tests
// ----------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{
        FIPS_INTEGRITY_KEY, IntegrityError, MAC_SIZE, SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC,
        SLOT_SIZE, constant_time_eq, encode_hmac_hex, find_slot_offset, hmac_with_slot_zeroed,
        sign_exe, verify_exe,
    };
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    /// The doc comment on `FIPS_INTEGRITY_KEY` names the key's literal.
    /// Before this test existed the two disagreed twice over: the doc named
    /// an `oxicrypt-` prefix while the constant carried `pqclib-`, and the
    /// literal it named was 34 bytes, which could not have compiled as
    /// `[u8; 32]`. A doc naming the wrong key for the IG 10.3.A integrity
    /// check is the kind of discrepancy a CST lab reads.
    ///
    /// Asserting the constant against a literal repeated in the test would
    /// prove nothing about the prose, so this reads the doc comment out of
    /// the source and compares what it *claims* against what is compiled.
    #[test]
    fn integrity_key_matches_its_documented_literal() {
        let src = include_str!("lib.rs");
        let Some(doc_start) =
            src.find("/// Fixed, publicly known HMAC key used for the software integrity")
        else {
            panic!("key doc comment not found — was it reworded?");
        };
        let Some(decl) = src[doc_start..].find("pub const FIPS_INTEGRITY_KEY") else {
            panic!("key declaration not found after its doc comment");
        };
        let doc = &src[doc_start..doc_start + decl];

        // The doc states the literal in backticks and its length in parens.
        let Some(quoted_start) = doc.find("`\"") else {
            panic!("doc states no quoted literal");
        };
        let rest = &doc[quoted_start + 2..];
        let Some(quote_end) = rest.find('"') else {
            panic!("unterminated literal in doc");
        };
        let quoted = &rest[..quote_end];
        assert_eq!(
            quoted.as_bytes(),
            &FIPS_INTEGRITY_KEY[..],
            "doc comment names {quoted:?} but the constant is {:?}",
            core::str::from_utf8(&FIPS_INTEGRITY_KEY).unwrap()
        );

        let Some(len_end) = doc.find(" bytes)") else {
            panic!("doc states no byte count");
        };
        let head = &doc[..len_end];
        let Some(paren) = head.rfind('(') else {
            panic!("stated length has no opening paren");
        };
        let Ok(stated_len) = head[paren + 1..].trim().parse::<usize>() else {
            panic!("stated length is not a number");
        };
        assert_eq!(
            stated_len,
            FIPS_INTEGRITY_KEY.len(),
            "doc claims {stated_len} bytes; the constant is {}",
            FIPS_INTEGRITY_KEY.len()
        );
    }

    /// The slot magics are matched against on-disk bytes of signed binaries,
    /// so their length is load-bearing: a 15-byte tail plus the sentinel is
    /// what makes the slot 16 bytes wide. Rotating the project name through
    /// them is only safe while the lengths hold.
    #[test]
    fn slot_magics_are_sixteen_bytes_and_distinctly_sentinelled() {
        assert_eq!(SLOT_HEADER_MAGIC.len(), 16);
        assert_eq!(SLOT_FOOTER_MAGIC.len(), 16);
        assert_eq!(SLOT_HEADER_MAGIC[0], 0xfc);
        assert_eq!(SLOT_FOOTER_MAGIC[0], 0xfd);
        assert_ne!(
            SLOT_HEADER_MAGIC, SLOT_FOOTER_MAGIC,
            "header and footer must differ or the scanner cannot orient a slot"
        );
        for (name, m) in [
            ("header", &SLOT_HEADER_MAGIC),
            ("footer", &SLOT_FOOTER_MAGIC),
        ] {
            assert!(
                m[1..].iter().all(u8::is_ascii_graphic),
                "{name} magic tail must stay ASCII so it is greppable in a binary"
            );
        }
    }

    /// Builds a fake "binary" blob containing exactly one integrity
    /// slot with the MAC field zeroed, surrounded by filler bytes.
    fn make_fake_exe(prefix_len: usize, suffix_len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(prefix_len + SLOT_SIZE + suffix_len);
        buf.extend(std::iter::repeat_n(0xAAu8, prefix_len));
        buf.extend_from_slice(&SLOT_HEADER_MAGIC);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&SLOT_FOOTER_MAGIC);
        buf.extend(std::iter::repeat_n(0xBBu8, suffix_len));
        buf
    }

    fn unique_tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        p.push(format!("fips-integrity-test-{tag}-{pid}-{ts}.bin"));
        p
    }

    fn write_file(path: &Path, body: &[u8]) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn oxicrypt_integrity_key_is_32_bytes_ascii() {
        assert_eq!(FIPS_INTEGRITY_KEY.len(), 32);
        for b in FIPS_INTEGRITY_KEY {
            assert!(b.is_ascii() && !b.is_ascii_control());
        }
    }

    #[test]
    fn slot_magics_are_distinct_16_byte_patterns() {
        assert_eq!(SLOT_HEADER_MAGIC.len(), 16);
        assert_eq!(SLOT_FOOTER_MAGIC.len(), 16);
        assert_ne!(SLOT_HEADER_MAGIC, SLOT_FOOTER_MAGIC);
    }

    #[test]
    fn find_slot_offset_locates_single_slot_in_middle_of_buffer() {
        let buf = make_fake_exe(1024, 2048);
        let off = find_slot_offset(&buf).unwrap();
        assert_eq!(off, 1024);
    }

    #[test]
    fn find_slot_offset_rejects_buffer_with_no_slot() {
        let buf = vec![0xAAu8; 4096];
        match find_slot_offset(&buf) {
            Err(IntegrityError::SlotNotFound) => {}
            other => panic!("expected SlotNotFound, got {other:?}"),
        }
    }

    #[test]
    fn find_slot_offset_rejects_buffer_shorter_than_slot() {
        let buf = vec![0u8; SLOT_SIZE - 1];
        match find_slot_offset(&buf) {
            Err(IntegrityError::SlotNotFound) => {}
            other => panic!("expected SlotNotFound, got {other:?}"),
        }
    }

    #[test]
    fn find_slot_offset_rejects_header_without_footer() {
        // Header present but followed by garbage, not the footer.
        let mut buf = vec![0xAAu8; 100];
        buf.extend_from_slice(&SLOT_HEADER_MAGIC);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0xCDu8; 16]);
        buf.extend(std::iter::repeat_n(0xBBu8, 100));
        match find_slot_offset(&buf) {
            Err(IntegrityError::SlotNotFound) => {}
            other => panic!("expected SlotNotFound, got {other:?}"),
        }
    }

    #[test]
    fn find_slot_offset_rejects_two_valid_slots() {
        let mut buf = make_fake_exe(100, 100);
        // Append another full slot.
        buf.extend_from_slice(&SLOT_HEADER_MAGIC);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&SLOT_FOOTER_MAGIC);
        match find_slot_offset(&buf) {
            Err(IntegrityError::MultipleSlotsFound) => {}
            other => panic!("expected MultipleSlotsFound, got {other:?}"),
        }
    }

    #[test]
    fn encode_hmac_hex_is_lowercase_and_64_chars() {
        let mac = [0xabu8; 32];
        let hex = encode_hmac_hex(&mac);
        assert_eq!(hex.len(), 64);
        let expected: Vec<u8> = std::iter::repeat_n(b'a', 1)
            .chain(std::iter::repeat_n(b'b', 1))
            .cycle()
            .take(64)
            .collect();
        assert_eq!(hex.as_slice(), expected.as_slice());
    }

    #[test]
    fn constant_time_eq_detects_differences() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[31] = 1;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn hmac_with_slot_zeroed_is_independent_of_prior_slot_bytes() {
        // Two buffers identical except in the MAC region — since
        // that region is zeroed before HMAC, the computed MAC must
        // be equal.
        let mut a = make_fake_exe(200, 200);
        let mut b = a.clone();
        let slot_offset = find_slot_offset(&a).unwrap();
        // Corrupt the MAC field in `b` only.
        for i in 0..MAC_SIZE {
            let idx = slot_offset + 16 + i;
            b[idx] = 0xFF;
        }
        let mac_a = hmac_with_slot_zeroed(&mut a, slot_offset).unwrap();
        let mac_b = hmac_with_slot_zeroed(&mut b, slot_offset).unwrap();
        assert_eq!(mac_a, mac_b);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let exe = unique_tmp_path("signverify");
        let body = make_fake_exe(300, 300);
        write_file(&exe, &body);
        let signed_mac = sign_exe(&exe).unwrap();
        // Verify from on-disk.
        verify_exe(&exe).unwrap();
        // The on-disk bytes differ from the original only in the MAC
        // region, and the diff equals the signed MAC.
        let after = fs::read(&exe).unwrap();
        let slot_offset = find_slot_offset(&after).unwrap();
        let on_disk_mac = &after[slot_offset + 16..slot_offset + 16 + MAC_SIZE];
        assert_eq!(on_disk_mac, signed_mac.as_slice());
        let _ = fs::remove_file(&exe);
    }

    #[test]
    fn sign_is_idempotent_across_repeat_calls() {
        let exe = unique_tmp_path("idempotent");
        let body = make_fake_exe(500, 500);
        write_file(&exe, &body);
        let first = sign_exe(&exe).unwrap();
        let second = sign_exe(&exe).unwrap();
        assert_eq!(first, second);
        verify_exe(&exe).unwrap();
        let _ = fs::remove_file(&exe);
    }

    #[test]
    fn verify_detects_tampered_payload_byte() {
        let exe = unique_tmp_path("tamperpayload");
        let body = make_fake_exe(400, 400);
        write_file(&exe, &body);
        sign_exe(&exe).unwrap();
        // Flip a byte somewhere in the prefix (outside the slot).
        let mut buf = fs::read(&exe).unwrap();
        buf[10] ^= 0xff;
        fs::write(&exe, &buf).unwrap();
        match verify_exe(&exe) {
            Err(IntegrityError::MacMismatch) => {}
            other => panic!("expected MacMismatch, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
    }

    #[test]
    fn verify_detects_tampered_mac_byte() {
        let exe = unique_tmp_path("tampermac");
        let body = make_fake_exe(400, 400);
        write_file(&exe, &body);
        sign_exe(&exe).unwrap();
        let mut buf = fs::read(&exe).unwrap();
        let slot_offset = find_slot_offset(&buf).unwrap();
        buf[slot_offset + 16] ^= 0x01;
        fs::write(&exe, &buf).unwrap();
        match verify_exe(&exe) {
            Err(IntegrityError::MacMismatch) => {}
            other => panic!("expected MacMismatch, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
    }

    #[test]
    fn verify_rejects_binary_without_slot() {
        let exe = unique_tmp_path("noslot");
        let body = vec![0xAAu8; 4096];
        write_file(&exe, &body);
        match verify_exe(&exe) {
            Err(IntegrityError::SlotNotFound) => {}
            other => panic!("expected SlotNotFound, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
    }

    #[test]
    fn verify_rejects_binary_with_multiple_slots() {
        let exe = unique_tmp_path("twoslots");
        let mut body = make_fake_exe(100, 100);
        body.extend_from_slice(&SLOT_HEADER_MAGIC);
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&SLOT_FOOTER_MAGIC);
        write_file(&exe, &body);
        match verify_exe(&exe) {
            Err(IntegrityError::MultipleSlotsFound) => {}
            other => panic!("expected MultipleSlotsFound, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
    }
}
