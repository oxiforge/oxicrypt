//! Format-independent pieces of classification.
//!
//! Three executable formats share one output — a table of
//! `(rva, file_off, len)` triples with the integrity slot removed — and
//! the parts of that shared shape live here so no format module depends
//! on another. What differs between formats is only *which* regions are
//! candidates; everything downstream of that choice is common.

use oxicrypt_integrity::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE, slot::Range};

/// What the signer needs to know about an artifact.
#[derive(Debug)]
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

pub(crate) fn u16_at(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let arr: [u8; 2] = bytes.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

pub(crate) fn u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let arr: [u8; 4] = bytes.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

pub(crate) fn u64_at(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let arr: [u8; 8] = bytes.get(off..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
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
pub(crate) fn subtract(ranges: &[Range], cut_rva: u32, cut_len: u32) -> Result<Vec<Range>, String> {
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

/// Rejects an extent that covers nothing.
///
/// A MAC over zero bytes verifies against any file, so an artifact signed with
/// an empty extent passes its own integrity test while proving nothing. The
/// classifiers already refuse an image with no candidate region; this is the
/// other way in — a candidate that the slot subtraction consumes entirely.
///
/// # Errors
///
/// Returns a description when `ranges` is empty.
pub(crate) fn ensure_non_empty(ranges: &[Range]) -> Result<(), String> {
    if ranges.is_empty() {
        return Err(
            "the extent is empty once the integrity slot is removed; a MAC over no bytes              would verify against any file"
                .to_owned(),
        );
    }
    Ok(())
}

/// Rejects candidate regions that overlap in address space.
///
/// The slot decoder refuses an unordered or overlapping table, so an image like
/// this is caught eventually — but at the verifier, on an artifact the signer
/// reported as signed. Refusing here names the cause instead.
///
/// `ranges` must be sorted ascending by RVA.
///
/// # Errors
///
/// Returns a description naming the first overlapping pair.
pub(crate) fn ensure_disjoint(ranges: &[Range]) -> Result<(), String> {
    for (a, b) in ranges.iter().zip(ranges.iter().skip(1)) {
        let a_end = a.rva_end().ok_or("range overflows")?;
        if a_end > b.rva {
            return Err(format!(
                "two mapped regions overlap in address space: rva {:#x}..{:#x} and rva {:#x}",
                a.rva, a_end, b.rva
            ));
        }
    }
    Ok(())
}

/// Whether the whole slot lies inside the file range `start..end`.
///
/// Testing only where the slot *begins* would accept one that starts in a
/// read-only region and runs on into the next — leaving the tail outside every
/// check the classifier makes about where a slot may live, including the one
/// that keeps it out of writable memory.
pub(crate) fn slot_fits(slot_file_off: usize, start: usize, end: usize) -> bool {
    slot_file_off >= start
        && slot_file_off
            .checked_add(SLOT_SIZE)
            .is_some_and(|slot_end| slot_end <= end)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::{Range, ensure_disjoint, ensure_non_empty, slot_fits, subtract};

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

    /// A MAC over nothing verifies against anything, so an extent the slot
    /// subtraction has emptied must be refused rather than signed.
    #[test]
    fn an_emptied_extent_is_refused() {
        assert!(ensure_non_empty(&[]).is_err());
        // The mirror control: an extent with anything in it is accepted.
        assert!(ensure_non_empty(&[r(0, 0, 1)]).is_ok());
    }

    /// Overlapping regions would double-cover an address, and the slot decoder
    /// refuses the resulting table — so the signer must refuse it first, with a
    /// message naming the cause.
    #[test]
    fn overlapping_regions_are_refused_and_abutting_ones_are_not() {
        let err = ensure_disjoint(&[r(0x1000, 0, 0x1000), r(0x1800, 0x1800, 0x800)])
            .expect_err("overlapping regions must be refused");
        assert!(err.contains("overlap"), "unhelpful refusal: {err}");
        // The mirror control, and it is the case that actually occurs: two
        // regions meeting exactly at a boundary do not overlap.
        assert!(ensure_disjoint(&[r(0x1000, 0, 0x1000), r(0x2000, 0x1000, 0x800)]).is_ok());
        assert!(ensure_disjoint(&[]).is_ok());
        assert!(ensure_disjoint(&[r(0, 0, 1)]).is_ok());
    }

    /// The slot must lie wholly inside one region. Testing only where it begins
    /// would accept a slot whose tail runs into the next region — past every
    /// check the classifier makes about where a slot may live.
    #[test]
    fn a_slot_must_fit_whole_inside_its_region() {
        let size = super::SLOT_SIZE;
        assert!(
            slot_fits(0x1000, 0x1000, 0x1000 + size),
            "an exact fit must be accepted"
        );
        assert!(slot_fits(0x1000, 0, 0x9000));
        assert!(
            !slot_fits(0x1000, 0x1000, 0x1000 + size - 1),
            "a slot one byte too long for its region must be refused"
        );
        assert!(
            !slot_fits(0x100, 0x1000, 0x9000),
            "a slot before its region must be refused"
        );
        assert!(
            !slot_fits(usize::MAX, 0, usize::MAX),
            "the addition must not wrap"
        );
    }
}
