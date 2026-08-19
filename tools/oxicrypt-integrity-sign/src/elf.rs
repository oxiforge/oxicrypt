//! ELF64 classification — deriving an image's loader-invariant extent.
//!
//! This is the *signer's* half of the design, and it is deliberately
//! outside the cryptographic boundary. Format knowledge — what a
//! program header is, which segments the loader writes to — lives here
//! and nowhere else. The module itself understands only a table of
//! `(rva, file_off, len)` triples.
//!
//! # The rule
//!
//! Include every `PT_LOAD` segment that lacks `PF_W`, then subtract the
//! integrity slot.
//!
//! Non-writable load segments are the bytes the loader maps and never
//! modifies. Everything address-dependent goes through the GOT, which
//! lives in a writable segment — including `.data.rel.ro`, which becomes
//! read-only only *after* relocation via `PT_GNU_RELRO` and whose
//! `PT_LOAD` therefore carries `PF_W`. Selecting on the load segment's
//! own flags excludes it for free, without special-casing RELRO.
//!
//! # Why `p_filesz` and not `p_memsz`
//!
//! `p_memsz` may exceed `p_filesz`, the excess being zero-filled by the
//! loader rather than read from the file. Those bytes have no file
//! counterpart, so the signer could not compute them offline and the
//! two sides would disagree. Only the file-backed prefix is in the
//! extent.

use oxicrypt_integrity::{SLOT_SIZE, slot::Range};

use crate::image::{
    Layout, ensure_disjoint, ensure_non_empty, find_slot, slot_fits, subtract, u16_at, u32_at,
    u64_at,
};

/// `p_type` value for a loadable segment.
const PT_LOAD: u32 = 1;
/// `p_flags` bit marking a segment writable.
const PF_W: u32 = 0x2;

/// True when `bytes` looks like a little-endian 64-bit ELF image.
#[must_use]
pub fn is_elf64_le(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(b"\x7fELF".as_slice())
        && bytes.get(4) == Some(&2)
        && bytes.get(5) == Some(&1)
}

/// One `PT_LOAD` segment, reduced to what classification needs.
struct Segment {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    writable: bool,
}

/// Parses every `PT_LOAD` segment and the image base they imply.
fn load_segments(bytes: &[u8]) -> Result<(Vec<Segment>, u64), String> {
    if !is_elf64_le(bytes) {
        return Err("not a little-endian 64-bit ELF image".to_owned());
    }
    let phoff = u64_at(bytes, 0x20).ok_or("truncated ELF header")?;
    let phentsize = u16_at(bytes, 0x36).ok_or("truncated ELF header")? as usize;
    let phnum = u16_at(bytes, 0x38).ok_or("truncated ELF header")? as usize;
    if phentsize < 56 {
        return Err(format!(
            "program header entry size {phentsize} is too small"
        ));
    }
    let phoff = usize::try_from(phoff).map_err(|_| "program header offset out of range")?;

    let mut segments: Vec<Segment> = Vec::new();
    for i in 0..phnum {
        let base = phoff
            .checked_add(
                i.checked_mul(phentsize)
                    .ok_or("program header table overflows")?,
            )
            .ok_or("program header table overflows")?;
        let p_type = u32_at(bytes, base).ok_or("truncated program header")?;
        if p_type != PT_LOAD {
            continue;
        }
        let p_flags = u32_at(bytes, base.saturating_add(4)).ok_or("truncated program header")?;
        let p_offset = u64_at(bytes, base.saturating_add(8)).ok_or("truncated program header")?;
        let p_vaddr = u64_at(bytes, base.saturating_add(16)).ok_or("truncated program header")?;
        let p_filesz = u64_at(bytes, base.saturating_add(32)).ok_or("truncated program header")?;
        segments.push(Segment {
            vaddr: p_vaddr,
            offset: p_offset,
            filesz: p_filesz,
            writable: p_flags & PF_W != 0,
        });
    }
    if segments.is_empty() {
        return Err("image has no PT_LOAD segments".to_owned());
    }

    let image_base = segments
        .iter()
        .map(|s| s.vaddr)
        .min()
        .ok_or("image has no PT_LOAD segments")?;
    Ok((segments, image_base))
}

/// Turns a segment into a range, addressed both ways.
fn segment_range(s: &Segment, image_base: u64, file_len: usize) -> Result<Range, String> {
    let end = s
        .offset
        .checked_add(s.filesz)
        .ok_or("segment file extent overflows")?;
    if usize::try_from(end).is_ok_and(|e| e > file_len) {
        return Err("segment extends past the end of the file".to_owned());
    }
    let rva = s
        .vaddr
        .checked_sub(image_base)
        .ok_or("segment address below the image base")?;
    Ok(Range {
        rva: u32::try_from(rva).map_err(|_| "segment RVA exceeds 32 bits")?,
        file_off: u32::try_from(s.offset).map_err(|_| "segment file offset exceeds 32 bits")?,
        len: u32::try_from(s.filesz).map_err(|_| "segment length exceeds 32 bits")?,
    })
}

/// The ranges the loader may write to: every writable `PT_LOAD`'s
/// file-backed bytes.
///
/// The complement of the extent, and never part of it. Exposed for two
/// uses that are really one: reporting what was excluded, and building
/// the control that proves the stability probe can fail. An extent
/// widened to include one of these must be rejected at runtime, because
/// the loader has rewritten those bytes and they no longer match the
/// file — and a probe that cannot be made to fail is not a probe.
///
/// # Errors
///
/// Returns a description when the image is malformed.
pub fn writable_ranges(bytes: &[u8]) -> Result<Vec<Range>, String> {
    let (segments, image_base) = load_segments(bytes)?;
    segments
        .iter()
        .filter(|s| s.writable && s.filesz > 0)
        .map(|s| segment_range(s, image_base, bytes.len()))
        .collect()
}

/// Derives the loader-invariant extent of an ELF64 image.
///
/// # Errors
///
/// Returns a description when the image is malformed, the slot is
/// missing or ambiguous, or a segment is too large for the slot format's
/// 32-bit fields.
pub fn classify(bytes: &[u8]) -> Result<Layout, String> {
    let (segments, image_base) = load_segments(bytes)?;
    let mapped_len: u64 = segments.iter().map(|s| s.filesz).sum();

    // Candidate ranges: every non-writable load segment's file-backed
    // bytes, addressed both ways.
    let mut candidates: Vec<Range> = segments
        .iter()
        .filter(|s| !s.writable && s.filesz > 0)
        .map(|s| segment_range(s, image_base, bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort_by_key(|r| r.rva);
    ensure_disjoint(&candidates)?;
    let invariant_len: u64 = candidates.iter().map(|r| u64::from(r.len)).sum();

    // The slot's position, in both coordinate spaces.
    let slot_file_off = find_slot(bytes)?;
    let slot_seg = segments
        .iter()
        .find(|s| {
            let start = usize::try_from(s.offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(s.filesz).unwrap_or(0));
            slot_fits(slot_file_off, start, end)
        })
        .ok_or("no single PT_LOAD segment contains the whole integrity slot")?;
    // Offset of the slot within its segment. `find` above established
    // that the slot lies inside this segment, so the subtraction holds —
    // checked anyway, because the invariant lives in a different
    // expression from the arithmetic that relies on it.
    let slot_off_in_seg = (slot_file_off as u64)
        .checked_sub(slot_seg.offset)
        .ok_or("slot precedes the segment that contains it")?;
    let slot_rva_u64 = slot_seg
        .vaddr
        .checked_sub(image_base)
        .ok_or("segment address below the image base")?
        .checked_add(slot_off_in_seg)
        .ok_or("slot RVA overflows")?;
    let slot_rva = u32::try_from(slot_rva_u64).map_err(|_| "slot RVA exceeds 32 bits")?;
    if slot_seg.writable {
        return Err(
            "the integrity slot is in a writable segment; the loader may modify it".to_owned(),
        );
    }

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
