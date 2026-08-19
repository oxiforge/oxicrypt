//! Build-time signing for the module's pre-operational integrity test.
//!
//! Exposed as a library so the format classifiers can be exercised
//! directly by tests — including the negative controls that must build a
//! deliberately wrong extent, which the command-line tool has no business
//! being able to produce.
//!
//! Everything here is **outside the cryptographic boundary**. It parses
//! executable formats, which the module deliberately does not.

#![forbid(unsafe_code)]

pub mod elf;
pub mod image;
pub mod macho;
pub mod pe;

use oxicrypt_integrity::{SLOT_SIZE, mac_over_file_ranges, slot};

/// Derives an image's loader-invariant extent, choosing the classifier from
/// the image's own magic.
///
/// The three formats do not share a rule, only an output. ELF takes every
/// non-writable load segment; Mach-O and PE take only what the loader maps
/// executable, because each has a non-writable region that is nonetheless not
/// reproducible from the file — `__LINKEDIT`, where `codesign` writes, and
/// `.rdata`, where the loader applies base relocations. Each module states its
/// own reasoning.
///
/// # Errors
///
/// Returns a description when the format is unrecognised or out of scope, or
/// when the chosen classifier rejects the image.
pub fn classify(image: &[u8]) -> Result<image::Layout, String> {
    if elf::is_elf64_le(image) {
        return elf::classify(image);
    }
    if macho::is_macho64_le(image) {
        return macho::classify(image);
    }
    if pe::is_pe32plus(image) {
        return pe::classify(image);
    }
    // Recognised but out of scope, so the refusal can say which rather than
    // reporting every unclassifiable file the same way.
    if let Some(reason) = macho::unsupported_reason(image) {
        return Err(reason.to_owned());
    }
    if let Some(reason) = pe::unsupported_reason(image) {
        return Err(reason.to_owned());
    }
    Err("unrecognised executable format".to_owned())
}

/// Signs `image` in place: derives its loader-invariant extent, computes
/// the reference MAC over that extent's file bytes, and writes the range
/// table and MAC into the embedded slot.
///
/// # Errors
///
/// Returns a description when the image cannot be classified, the slot is
/// missing or ambiguous, or the extent does not fit the slot's table.
pub fn sign_image(image: &mut [u8]) -> Result<[u8; 32], String> {
    let layout = classify(image)?;
    write_extent(image, &layout.ranges, layout.slot_rva, layout.slot_file_off)
}

/// Writes an arbitrary extent into an image's slot.
///
/// Separate from [`sign_image`] so a test can sign an image against an
/// extent the classifier would never emit. That is the only way to build
/// the control which proves the stability probe can actually fail: an
/// extent widened to cover a region the loader rewrites must be rejected
/// at runtime, and a probe that cannot be made to fail is not a probe.
///
/// # Errors
///
/// Returns a description when the ranges do not fit the table, fall
/// outside the image, or produce a slot the verifier would refuse.
pub fn write_extent(
    image: &mut [u8],
    ranges: &[slot::Range],
    slot_rva: u32,
    slot_file_off: usize,
) -> Result<[u8; 32], String> {
    let mac =
        mac_over_file_ranges(image, ranges).map_err(|d| format!("cannot hash the extent: {d}"))?;
    let encoded =
        slot::encode(ranges, slot_rva, &mac).map_err(|d| format!("cannot encode the slot: {d}"))?;
    let end = slot_file_off
        .checked_add(SLOT_SIZE)
        .ok_or("slot offset overflows")?;
    let window = image
        .get_mut(slot_file_off..end)
        .ok_or("slot extends past the end of the file")?;
    window.copy_from_slice(&encoded);
    Ok(mac)
}
