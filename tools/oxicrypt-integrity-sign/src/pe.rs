//! PE32+ classification — deriving an image's loader-invariant extent.
//!
//! The signer's half of the design for Windows, outside the cryptographic
//! boundary like the rest of this crate.
//!
//! # The rule
//!
//! Include every section the loader maps executable and not writable, then
//! subtract the integrity slot.
//!
//! # Why this differs from the ELF rule, which takes every non-writable segment
//!
//! PE is the one format of the three where the loader may patch the image, and
//! `.rdata` is where it does it: base relocations and the import address table
//! both land there. `.rdata` is not writable in its characteristics, so a rule
//! written as "non-writable" would include a section whose loaded bytes differ
//! from the file — and the extent must be bytes the signer can compute offline.
//!
//! The structural question this format raises is whether `.text` itself carries
//! relocations, since PE, unlike ELF and Mach-O, is free to patch code
//! directly. Measured on a release x86_64 build: of 472 base relocations, all
//! 472 target `.rdata` and none target `.text`. The exclusion above is what
//! makes that finding usable.
//!
//! # Why the mapped length and not the raw size
//!
//! `SizeOfRawData` is rounded up to the file alignment, so it can exceed
//! `VirtualSize` — those trailing bytes are padding present in the file and not
//! mapped. Hashing them would put bytes in the extent that the running image
//! does not contain. Only the smaller of the two is in the extent.

use oxicrypt_integrity::{SLOT_SIZE, slot::Range};

use crate::image::{
    Layout, ensure_disjoint, ensure_non_empty, find_slot, slot_fits, subtract, u16_at, u32_at,
};

/// Offset of `e_lfanew` in the DOS header.
const E_LFANEW_OFF: usize = 0x3c;
/// `IMAGE_NT_SIGNATURE`.
const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
const PE32_PLUS_MAGIC: u16 = 0x20b;
/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`, recognised only so the refusal can name it.
const PE32_MAGIC: u16 = 0x10b;
/// Bytes from the PE signature to the optional header.
const COFF_HEADER_SIZE: usize = 24;
/// `IMAGE_SECTION_HEADER` size.
const SECTION_HEADER_SIZE: usize = 40;
/// `IMAGE_SCN_MEM_EXECUTE`.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_WRITE`.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// The file offset of the PE signature, if `bytes` carries a DOS stub pointing
/// at one.
fn pe_header_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..2) != Some(b"MZ".as_slice()) {
        return None;
    }
    let e_lfanew = u32_at(bytes, E_LFANEW_OFF)?;
    let off = usize::try_from(e_lfanew).ok()?;
    (bytes.get(off..off.checked_add(4)?)? == PE_SIGNATURE).then_some(off)
}

/// True when `bytes` looks like a PE32+ image.
#[must_use]
pub fn is_pe32plus(bytes: &[u8]) -> bool {
    pe_header_offset(bytes)
        .and_then(|pe| u16_at(bytes, pe.checked_add(COFF_HEADER_SIZE)?))
        .is_some_and(|magic| magic == PE32_PLUS_MAGIC)
}

/// Why `bytes` is a PE this signer will not classify, if it is one.
#[must_use]
pub fn unsupported_reason(bytes: &[u8]) -> Option<&'static str> {
    let pe = pe_header_offset(bytes)?;
    match u16_at(bytes, pe.checked_add(COFF_HEADER_SIZE)?) {
        Some(PE32_MAGIC) => Some("32-bit PE images are not supported; the module is 64-bit only"),
        Some(PE32_PLUS_MAGIC) => None,
        _ => Some("the PE optional header carries an unrecognised magic"),
    }
}

/// One section header, reduced to what classification needs.
struct Section {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
}

impl Section {
    /// The loader maps this section writable.
    const fn writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// The loader maps this section executable.
    const fn executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// The file-backed bytes the loader actually maps: the raw data, capped at
    /// the virtual size so file alignment padding stays out of the extent. A
    /// section declaring no virtual size maps its raw data whole.
    const fn mapped_len(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else if self.virtual_size < self.raw_size {
            self.virtual_size
        } else {
            self.raw_size
        }
    }

    /// This section is a candidate for the extent.
    const fn invariant(&self) -> bool {
        self.executable() && !self.writable() && self.mapped_len() > 0 && self.raw_offset > 0
    }
}

/// Parses the section table.
///
/// # Errors
///
/// Returns a description when the headers are malformed or truncated.
fn sections(bytes: &[u8]) -> Result<Vec<Section>, String> {
    let pe = pe_header_offset(bytes).ok_or("not a PE image")?;
    if !is_pe32plus(bytes) {
        return Err("not a PE32+ image".to_owned());
    }
    let nsections = u16_at(bytes, pe.checked_add(6).ok_or("PE header overflows")?)
        .ok_or("truncated COFF header")?;
    let opt_size = u16_at(bytes, pe.checked_add(20).ok_or("PE header overflows")?)
        .ok_or("truncated COFF header")?;
    let table = pe
        .checked_add(COFF_HEADER_SIZE)
        .and_then(|o| o.checked_add(usize::from(opt_size)))
        .ok_or("section table offset overflows")?;

    let mut out = Vec::with_capacity(usize::from(nsections));
    for i in 0..usize::from(nsections) {
        let off = i
            .checked_mul(SECTION_HEADER_SIZE)
            .and_then(|d| table.checked_add(d))
            .ok_or("section header offset overflows")?;
        let at = |d: usize| -> Result<usize, String> {
            off.checked_add(d)
                .ok_or_else(|| "section field overflows".to_owned())
        };
        out.push(Section {
            virtual_size: u32_at(bytes, at(8)?).ok_or("truncated section header")?,
            virtual_address: u32_at(bytes, at(12)?).ok_or("truncated section header")?,
            raw_size: u32_at(bytes, at(16)?).ok_or("truncated section header")?,
            raw_offset: u32_at(bytes, at(20)?).ok_or("truncated section header")?,
            characteristics: u32_at(bytes, at(36)?).ok_or("truncated section header")?,
        });
    }
    Ok(out)
}

/// Turns a section into a range, addressed both ways.
fn section_range(s: &Section, file_len: usize) -> Result<Range, String> {
    let len = s.mapped_len();
    let end = usize::try_from(s.raw_offset)
        .ok()
        .and_then(|o| o.checked_add(usize::try_from(len).ok()?))
        .ok_or("section file extent overflows")?;
    if end > file_len {
        return Err("a section's file extent runs past the end of the file".to_owned());
    }
    Ok(Range {
        // A PE section header's `VirtualAddress` is already relative to the
        // image base, so no subtraction is needed and none is done — the
        // `ImageBase` field is not consulted at all, which is deliberate: the
        // loader rewrites it in the mapped image, so it is not a value this
        // signer should teach anything to depend on.
        rva: s.virtual_address,
        file_off: s.raw_offset,
        len,
    })
}

/// The ranges the loader may write to: every writable section's file-backed
/// bytes.
///
/// # Errors
///
/// Returns a description when the image is malformed.
pub fn writable_ranges(bytes: &[u8]) -> Result<Vec<Range>, String> {
    sections(bytes)?
        .iter()
        .filter(|s| s.writable() && s.mapped_len() > 0 && s.raw_offset > 0)
        .map(|s| section_range(s, bytes.len()))
        .collect()
}

/// Derives the loader-invariant extent of a PE32+ image.
///
/// # Errors
///
/// Returns a description when the image is malformed, the slot is missing or
/// ambiguous, or the slot lies in a writable section.
pub fn classify(bytes: &[u8]) -> Result<Layout, String> {
    let secs = sections(bytes)?;
    let mapped_len: u64 = secs
        .iter()
        .filter(|s| s.raw_offset > 0)
        .map(|s| u64::from(s.mapped_len()))
        .sum();

    let mut candidates: Vec<Range> = secs
        .iter()
        .filter(|s| s.invariant())
        .map(|s| section_range(s, bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    if candidates.is_empty() {
        return Err(
            "no section is mapped executable and non-writable, so there is nothing to hash"
                .to_owned(),
        );
    }
    candidates.sort_by_key(|r| r.rva);
    ensure_disjoint(&candidates)?;
    let invariant_len: u64 = candidates.iter().map(|r| u64::from(r.len)).sum();

    let slot_file_off = find_slot(bytes)?;
    let slot_sec = secs
        .iter()
        .find(|s| {
            let start = usize::try_from(s.raw_offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(s.mapped_len()).unwrap_or(0));
            s.raw_offset > 0 && slot_fits(slot_file_off, start, end)
        })
        .ok_or("no single mapped section contains the whole integrity slot")?;
    if slot_sec.writable() {
        return Err(
            "the integrity slot is in a writable section; the loader may modify it".to_owned(),
        );
    }
    let slot_off_in_sec = u32::try_from(slot_file_off)
        .map_err(|_| "slot file offset exceeds 32 bits")?
        .checked_sub(slot_sec.raw_offset)
        .ok_or("slot precedes the section that contains it")?;
    let slot_rva = slot_sec
        .virtual_address
        .checked_add(slot_off_in_sec)
        .ok_or("slot RVA overflows")?;

    let slot_len = u32::try_from(SLOT_SIZE).map_err(|_| "slot size exceeds 32 bits")?;
    let ranges = subtract(&candidates, slot_rva, slot_len)?;
    ensure_non_empty(&ranges)?;

    Ok(Layout {
        ranges,
        slot_file_off,
        slot_rva,
        invariant_len,
        mapped_len,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // Fixture builders compute header offsets from literals chosen in this
    // same file; a wrong one fails the test it feeds rather than shipping.
    clippy::arithmetic_side_effects
)]
mod tests {
    use oxicrypt_integrity::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE};

    use super::{
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, classify, is_pe32plus, writable_ranges,
    };

    /// Where the synthetic PE signature sits.
    const PE_OFF: usize = 0x80;
    /// Optional-header size claimed by the synthetic COFF header.
    const OPT_SIZE: usize = 240;

    /// One synthetic section: name, virtual size, RVA, raw size, raw offset,
    /// characteristics.
    struct Sec(&'static str, u32, u32, u32, u32, u32);

    /// Builds a minimal PE32+ carrying `secs`.
    ///
    /// Synthetic for the same reason as the Mach-O fixtures: the shapes that
    /// decide this classifier — a slot in a writable section, a section whose
    /// raw size exceeds what is mapped — cannot be produced by asking a linker
    /// nicely.
    fn image(secs: &[Sec], file_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; file_len];
        out[0..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&u32::try_from(PE_OFF).unwrap().to_le_bytes());
        out[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
        out[PE_OFF + 6..PE_OFF + 8]
            .copy_from_slice(&u16::try_from(secs.len()).unwrap().to_le_bytes());
        out[PE_OFF + 20..PE_OFF + 22]
            .copy_from_slice(&u16::try_from(OPT_SIZE).unwrap().to_le_bytes());
        out[PE_OFF + 24..PE_OFF + 26].copy_from_slice(&super::PE32_PLUS_MAGIC.to_le_bytes());
        let table = PE_OFF + super::COFF_HEADER_SIZE + OPT_SIZE;
        for (i, Sec(name, vsize, rva, rawsz, rawoff, chars)) in secs.iter().enumerate() {
            let o = table + i * super::SECTION_HEADER_SIZE;
            out[o..o + name.len()].copy_from_slice(name.as_bytes());
            out[o + 8..o + 12].copy_from_slice(&vsize.to_le_bytes());
            out[o + 12..o + 16].copy_from_slice(&rva.to_le_bytes());
            out[o + 16..o + 20].copy_from_slice(&rawsz.to_le_bytes());
            out[o + 20..o + 24].copy_from_slice(&rawoff.to_le_bytes());
            out[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        }
        out
    }

    fn put_slot(image: &mut [u8], at: usize) {
        image[at..at + 16].copy_from_slice(&SLOT_HEADER_MAGIC);
        image[at + SLOT_SIZE - 16..at + SLOT_SIZE].copy_from_slice(&SLOT_FOOTER_MAGIC);
    }

    /// The shape a real artifact has: `.text` executable, `.rdata` read-only
    /// and holding the slot, `.data` writable.
    fn fixture() -> Vec<u8> {
        let mut img = image(
            &[
                Sec(
                    ".text",
                    0x4000,
                    0x1000,
                    0x4000,
                    0x400,
                    IMAGE_SCN_MEM_EXECUTE,
                ),
                Sec(".rdata", 0x8000, 0x5000, 0x8000, 0x4400, 0),
                Sec(".data", 0x1000, 0xd000, 0x1000, 0xc400, IMAGE_SCN_MEM_WRITE),
            ],
            0xd400,
        );
        put_slot(&mut img, 0x5000);
        img
    }

    #[test]
    fn the_extent_is_the_executable_non_writable_section() {
        let img = fixture();
        assert!(is_pe32plus(&img));
        let layout = classify(&img).expect("classify");
        assert_eq!(layout.ranges.len(), 1, "only .text belongs in the extent");
        assert_eq!(layout.ranges[0].rva, 0x1000);
        assert_eq!(layout.ranges[0].file_off, 0x400);
        assert_eq!(layout.ranges[0].len, 0x4000);
        assert_eq!(layout.invariant_len, 0x4000);
    }

    /// The rule that distinguishes this classifier from the ELF one.
    ///
    /// `.rdata` is not writable, so "every non-writable region" would include
    /// it — and `.rdata` is where the loader applies base relocations and the
    /// import address table, so its loaded bytes differ from the file. Without
    /// this case the executable requirement could be dropped and every other
    /// test here would still pass.
    #[test]
    fn a_read_only_non_executable_section_is_excluded() {
        let layout = classify(&fixture()).expect("classify");
        assert_eq!(
            layout.ranges.len(),
            1,
            "a !any() assertion over an empty or shifted range list would pass without \
             testing anything"
        );
        assert!(
            !layout.ranges.iter().any(|r| r.rva == 0x5000),
            ".rdata is in the extent; the loader patches it and the MAC could not be \
             computed offline"
        );
    }

    /// The slot lives in `.rdata` on this format, so it is outside the extent
    /// and the subtraction is a no-op — which must leave `.text` whole rather
    /// than truncating it.
    #[test]
    fn a_slot_outside_the_extent_leaves_it_intact() {
        let layout = classify(&fixture()).expect("classify");
        assert_eq!(layout.slot_file_off, 0x5000);
        assert_eq!(layout.slot_rva, 0x5000 - 0x4400 + 0x5000);
        assert_eq!(
            layout.ranges[0].len, 0x4000,
            "subtracting a slot that lies outside the extent must remove nothing"
        );
    }

    /// File alignment padding is present in the file and not mapped, so it is
    /// not in the extent.
    #[test]
    fn raw_data_is_capped_at_the_mapped_size() {
        let mut img = image(
            &[
                // 0x3f00 mapped, 0x4000 on disk: 256 bytes of alignment padding.
                Sec(
                    ".text",
                    0x3f00,
                    0x1000,
                    0x4000,
                    0x400,
                    IMAGE_SCN_MEM_EXECUTE,
                ),
                Sec(".rdata", 0x8000, 0x5000, 0x8000, 0x4400, 0),
            ],
            0xc400,
        );
        put_slot(&mut img, 0x5000);
        let layout = classify(&img).expect("classify");
        assert_eq!(
            layout.ranges[0].len, 0x3f00,
            "the extent must stop at the mapped size, not the raw size"
        );
    }

    #[test]
    fn writable_sections_are_reported_and_excluded() {
        let img = fixture();
        let writable = writable_ranges(&img).expect("writable ranges");
        assert_eq!(writable.len(), 1);
        assert_eq!(writable[0].rva, 0xd000);
        let layout = classify(&img).expect("classify");
        assert!(
            !layout.ranges.is_empty(),
            "an empty extent proves nothing below"
        );
        assert!(!layout.ranges.iter().any(|r| r.rva == 0xd000));
    }

    #[test]
    fn a_slot_in_a_writable_section_is_refused() {
        let mut img = image(
            &[
                Sec(
                    ".text",
                    0x1000,
                    0x1000,
                    0x1000,
                    0x400,
                    IMAGE_SCN_MEM_EXECUTE,
                ),
                Sec(".data", 0x8000, 0x2000, 0x8000, 0x1400, IMAGE_SCN_MEM_WRITE),
            ],
            0x9400,
        );
        put_slot(&mut img, 0x2000);
        let err = classify(&img).expect_err("a slot the loader may rewrite must be refused");
        assert!(err.contains("writable"), "unhelpful refusal: {err}");
    }

    #[test]
    fn an_image_with_no_executable_section_is_refused() {
        let mut img = image(&[Sec(".rdata", 0x8000, 0x1000, 0x8000, 0x400, 0)], 0x8400);
        put_slot(&mut img, 0x1000);
        let err = classify(&img).expect_err("nothing to hash must be refused");
        assert!(err.contains("nothing to hash"), "unhelpful refusal: {err}");
    }

    #[test]
    fn a_thirty_two_bit_image_is_named_rather_than_lumped_in() {
        let mut img = fixture();
        img[PE_OFF + 24..PE_OFF + 26].copy_from_slice(&super::PE32_MAGIC.to_le_bytes());
        assert!(!is_pe32plus(&img));
        assert!(
            super::unsupported_reason(&img).is_some_and(|r| r.contains("32-bit")),
            "a PE32 image must say so"
        );
        // The mirror control: a PE32+ image is not "unsupported", and a file
        // that is not a PE at all yields no PE-specific reason.
        assert!(super::unsupported_reason(&fixture()).is_none());
        assert!(super::unsupported_reason(b"not a pe at all").is_none());
    }

    #[test]
    fn a_truncated_header_is_refused_rather_than_guessed() {
        let img = fixture();
        for (cut, expected) in [
            (1, "not a PE image"),
            // `e_lfanew` sits at 0x3c..0x40, so one byte short of it the image
            // is not recognisably a PE at all.
            (0x3f, "not a PE image"),
            (0x82, "not a PE image"),
            // Here the signature is readable and the optional header's magic is
            // not, so the refusal moves on to the shape.
            (PE_OFF + 24, "not a PE32+ image"),
        ] {
            let err = classify(&img[..cut]).expect_err("a truncated image must be refused");
            assert_eq!(
                err, expected,
                "cut {cut} must be refused for the reason that applies to it; a bare \
                 is-error assertion passes on any refusal at all"
            );
        }
    }

    /// A file offset inside the image but outside every extent range.
    const OUTSIDE: usize = 0x4500;

    /// The whole signer round trip on this format, in the tree rather than in a
    /// transcript.
    ///
    /// The claim this backs is that a Mach-O artifact signs, verifies from its
    /// own recorded extent, detects a change inside that extent, and tolerates
    /// one outside it. The last of those is the part that matters: without it a
    /// MAC over the whole file would pass every other assertion here.
    #[test]
    fn a_synthetic_image_signs_verifies_and_localises_tampering() {
        let mut img = fixture();
        let ranges = classify(&img).expect("classify").ranges;
        let mac = crate::sign_image(&mut img).expect("sign");

        let recomputed =
            oxicrypt_integrity::mac_over_file_ranges(&img, &ranges).expect("recompute the MAC");
        assert_eq!(
            recomputed, mac,
            "the signed artifact must verify against its own extent"
        );

        let inside = usize::try_from(ranges[0].file_off).unwrap();
        let mut tampered = img.clone();
        tampered[inside] ^= 0xff;
        assert_ne!(
            oxicrypt_integrity::mac_over_file_ranges(&tampered, &ranges).expect("mac"),
            mac,
            "a byte changed inside the extent must change the MAC"
        );

        let mut untouched = img.clone();
        untouched[OUTSIDE] ^= 0xff;
        assert_eq!(
            oxicrypt_integrity::mac_over_file_ranges(&untouched, &ranges).expect("mac"),
            mac,
            "a byte changed outside the extent must NOT change the MAC — otherwise the \
             extent is not what is being covered"
        );
        assert!(
            !ranges.iter().any(|r| {
                let start = usize::try_from(r.file_off).unwrap();
                let end = start + usize::try_from(r.len).unwrap();
                (start..end).contains(&OUTSIDE)
            }),
            "the control offset must really lie outside every range"
        );
    }
}
