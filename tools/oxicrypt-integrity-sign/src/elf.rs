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

use oxicrypt_integrity::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE, slot::Range};

/// `p_type` value for a loadable segment.
const PT_LOAD: u32 = 1;
/// `p_flags` bit marking a segment writable.
const PF_W: u32 = 0x2;

/// What the signer needs to know about an artifact.
pub struct Layout {
    /// The loader-invariant extent, slot already subtracted, ascending.
    pub ranges: Vec<Range>,
    /// File offset of the integrity slot.
    pub slot_file_off: usize,
    /// Offset of the integrity slot from the image base.
    pub slot_rva: u32,
    /// Total file-backed bytes across all non-writable load segments,
    /// before the slot was subtracted. Reported so an operator can see
    /// what fraction of the mapped image the extent covers.
    pub invariant_len: u64,
    /// Total file-backed bytes across every load segment.
    pub mapped_len: u64,
}

fn u16_at(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let arr: [u8; 2] = bytes.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

fn u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let arr: [u8; 4] = bytes.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn u64_at(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let arr: [u8; 8] = bytes.get(off..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

/// True when `bytes` looks like a little-endian 64-bit ELF image.
#[must_use]
pub fn is_elf64_le(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(b"\x7fELF".as_slice())
        && bytes.get(4) == Some(&2)
        && bytes.get(5) == Some(&1)
}

/// Locates the integrity slot in an artifact's file bytes.
///
/// A candidate is accepted only when the footer magic sits at exactly
/// `SLOT_SIZE - 16` past the header, which rejects an incidental
/// occurrence of the header pattern. Exactly one slot must be present:
/// zero means the artifact was never linked against the module, and
/// more than one means the verifier could not tell which is
/// authoritative.
///
/// # Errors
///
/// Returns a description when zero or several slots are found.
pub fn find_slot(bytes: &[u8]) -> Result<usize, String> {
    let mut found: Vec<usize> = Vec::new();
    let Some(last) = bytes.len().checked_sub(SLOT_SIZE) else {
        return Err("artifact is smaller than one integrity slot".to_owned());
    };
    let footer_at = SLOT_SIZE.saturating_sub(16);
    for i in 0..=last {
        if bytes.get(i..i.saturating_add(16)) != Some(SLOT_HEADER_MAGIC.as_slice()) {
            continue;
        }
        let f = i.saturating_add(footer_at);
        if bytes.get(f..f.saturating_add(16)) == Some(SLOT_FOOTER_MAGIC.as_slice()) {
            found.push(i);
        }
    }
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(
            "no integrity slot found — the artifact was not linked against oxicrypt-integrity, \
             or the slot was stripped"
                .to_owned(),
        ),
        many => Err(format!(
            "{} integrity slots found; exactly one is required",
            many.len()
        )),
    }
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
    let invariant_len: u64 = candidates.iter().map(|r| u64::from(r.len)).sum();

    // The slot's position, in both coordinate spaces.
    let slot_file_off = find_slot(bytes)?;
    let slot_seg = segments
        .iter()
        .find(|s| {
            let start = usize::try_from(s.offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(s.filesz).unwrap_or(0));
            slot_file_off >= start && slot_file_off < end
        })
        .ok_or("the integrity slot lies outside every PT_LOAD segment")?;
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

    Ok(Layout {
        ranges,
        slot_file_off,
        slot_rva,
        invariant_len,
        mapped_len,
    })
}

/// Removes `[cut_rva, cut_rva + cut_len)` from an ascending range list,
/// splitting any range that straddles it.
///
/// Subtractive rather than masking: the excluded bytes are simply absent
/// from the extent, so signer and verifier share one semantic — hash the
/// listed ranges in order — with no zero-substitution on either side.
///
/// # Errors
///
/// Returns a description on arithmetic overflow.
fn subtract(ranges: &[Range], cut_rva: u32, cut_len: u32) -> Result<Vec<Range>, String> {
    let cut_end = cut_rva
        .checked_add(cut_len)
        .ok_or("subtracted region overflows")?;
    let mut out: Vec<Range> = Vec::new();
    for r in ranges {
        let r_end = r.rva_end().ok_or("range overflows")?;
        if r_end <= cut_rva || r.rva >= cut_end {
            out.push(*r);
            continue;
        }
        // Head: the part before the cut.
        if r.rva < cut_rva {
            let len = cut_rva.saturating_sub(r.rva);
            out.push(Range {
                rva: r.rva,
                file_off: r.file_off,
                len,
            });
        }
        // Tail: the part after the cut.
        if r_end > cut_end {
            let skipped = cut_end.saturating_sub(r.rva);
            out.push(Range {
                rva: cut_end,
                file_off: r
                    .file_off
                    .checked_add(skipped)
                    .ok_or("range file offset overflows")?,
                len: r_end.saturating_sub(cut_end),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{Range, subtract};

    fn r(rva: u32, file_off: u32, len: u32) -> Range {
        Range { rva, file_off, len }
    }

    #[test]
    fn subtract_splits_a_straddling_range_and_tracks_the_file_offset() {
        // A 4 KiB range at RVA 0x1000 / file 0x2000, cut in the middle.
        let out = subtract(&[r(0x1000, 0x2000, 0x1000)], 0x1400, 0x400).unwrap();
        assert_eq!(
            out,
            vec![r(0x1000, 0x2000, 0x400), r(0x1800, 0x2800, 0x800)],
            "the tail's file offset must advance by the same amount as its RVA"
        );
    }

    #[test]
    fn subtract_leaves_disjoint_ranges_untouched() {
        let input = vec![r(0, 0, 0x100), r(0x8000, 0x8000, 0x100)];
        assert_eq!(subtract(&input, 0x4000, 0x1000).unwrap(), input);
    }

    #[test]
    fn subtract_drops_a_range_wholly_inside_the_cut() {
        let out = subtract(&[r(0x1100, 0x1100, 0x100)], 0x1000, 0x1000).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn subtract_trims_a_range_starting_inside_the_cut() {
        let out = subtract(&[r(0x1800, 0x1800, 0x1000)], 0x1000, 0x1000).unwrap();
        assert_eq!(out, vec![r(0x2000, 0x2000, 0x800)]);
    }

    /// A cut abutting a range exactly must remove nothing — the boundary
    /// case that decides whether the slot's neighbours survive intact.
    #[test]
    fn subtract_at_an_exact_boundary_removes_nothing() {
        let input = vec![r(0x1000, 0x1000, 0x1000)];
        assert_eq!(subtract(&input, 0x2000, 0x1000).unwrap(), input);
        assert_eq!(subtract(&input, 0x0, 0x1000).unwrap(), input);
    }
}
