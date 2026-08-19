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

use oxicrypt_integrity::{SLOT_SIZE, constant_time_eq, mac_over_file_ranges, slot};

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

/// Checks an image against the slot it carries: locates the slot, parses the
/// range table out of it, recomputes the MAC over those file bytes and
/// compares without short-circuiting.
///
/// This is the offline check. It proves the file is internally consistent —
/// the extent's bytes match the MAC beside them — and says nothing about the
/// loaded image, which is what the runtime test exercises.
///
/// Lives here rather than in either caller because two of them now exist: the
/// command-line tool's `--verify`, and a binary verifying the slot it has just
/// written into itself. A second implementation is a second opinion about what
/// "verified" means, and the two would drift.
///
/// # Errors
///
/// Returns a description when the slot is absent, unparsable, or disagrees
/// with the bytes around it.
pub fn verify_image(image: &[u8]) -> Result<(), String> {
    let off = image::find_slot(image)?;
    let end = off.checked_add(SLOT_SIZE).ok_or("slot offset overflows")?;
    let window = image
        .get(off..end)
        .ok_or("slot extends past the end of the file")?;
    let parsed = slot::parse(window).map_err(|d| format!("slot invalid: {d}"))?;
    let computed = mac_over_file_ranges(image, &parsed.ranges)
        .map_err(|d| format!("cannot hash the extent: {d}"))?;
    if constant_time_eq(&computed, &parsed.mac) {
        Ok(())
    } else {
        Err("MAC mismatch — the file does not match its slot".to_owned())
    }
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]
mod tests {
    use super::*;

    /// This test binary's own bytes. It links `oxicrypt-integrity`, so it
    /// carries a slot, and it is a real image of the host's own format —
    /// which is what makes this exercise the classifier rather than a
    /// hand-built fixture that only ever resembles one.
    fn own_image() -> Vec<u8> {
        std::fs::read(std::env::current_exe().expect("current_exe")).expect("read self")
    }

    /// `verify_image` accepts what `sign_image` produced, and rejects the
    /// same bytes with one changed inside the extent.
    ///
    /// Both directions, because either alone is worthless: a function that
    /// always returned `Ok` would pass the first, and one that always
    /// returned `Err` would pass the second.
    #[test]
    fn verify_image_accepts_a_signed_image_and_rejects_a_changed_one() {
        let mut image = own_image();
        let layout = classify(&image).expect("classify this test binary");
        sign_image(&mut image).expect("sign");

        verify_image(&image).expect("a freshly signed image must verify");

        let last = layout.ranges.last().expect("extent has ranges");
        // Kept in the range table's own width until the premise is checked, so
        // the check is about the extent rather than about a conversion.
        let off_rva = last.file_off + last.len / 2;

        // The premise is checked against the range table PARSED BACK OUT OF THE
        // SIGNED IMAGE, not against the layout this test computed. Testing
        // `off_rva` for membership in the same `layout.ranges` it was derived
        // from is very nearly a tautology — it rules out a zero-length final
        // range and nothing else — and would read as a premise check while
        // being none. The slot's own table is what `verify_image` will hash, so
        // it is the table the offset must be inside.
        let slot_off = image::find_slot(&image).expect("the signed image has a slot");
        let parsed = slot::parse(
            image
                .get(slot_off..slot_off + SLOT_SIZE)
                .expect("slot window"),
        )
        .expect("the slot parses");
        assert!(
            parsed
                .ranges
                .iter()
                .any(|r| off_rva >= r.file_off && off_rva < r.file_off + r.len),
            "premise failed: {off_rva:#x} is not inside the extent the slot records"
        );
        // And the mirror: an offset in the slot's own body is NOT in that table,
        // so the membership test above can distinguish inside from outside.
        let in_slot = u32::try_from(slot_off + SLOT_SIZE / 2).expect("fits u32");
        assert!(
            !parsed
                .ranges
                .iter()
                .any(|r| in_slot >= r.file_off && in_slot < r.file_off + r.len),
            "premise failed: the membership test cannot tell inside from outside"
        );
        let off = usize::try_from(off_rva).expect("a file offset fits usize");
        let mut tampered = image.clone();
        tampered[off] ^= 0xff;
        assert!(
            verify_image(&tampered).is_err(),
            "a byte changed inside the extent must fail verification"
        );

        // The mirror control that a byte outside the extent is ignored is NOT
        // written here. The only region outside the extent in a signed image
        // is the slot itself, and the codec reads it — so a flip there changes
        // the verdict for a different reason and would prove nothing. That
        // property is covered where it can be driven honestly, on synthetic
        // images with a writable segment: see `macho::tests::
        // a_byte_changed_in_the_load_commands_does_not_break_the_mac`.
    }

    /// An image with no slot is refused, and says so rather than reporting a
    /// mismatch — the two call for different responses.
    #[test]
    fn verify_image_refuses_an_image_with_no_slot() {
        let err = verify_image(b"not an executable at all").expect_err("must refuse");
        assert!(
            !err.contains("MAC mismatch"),
            "a missing slot must not be reported as a mismatch, got: {err}"
        );
    }
}
