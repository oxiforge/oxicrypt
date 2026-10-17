//! Format-independent pieces of classification.
//!
//! Three executable formats share one output — a table of typed
//! `(rva, file_off, len)` entries with the integrity slot removed — and
//! the parts of that shared shape live here so no format module depends
//! on another. What differs between formats is only *which* regions are
//! candidates and how they are typed; everything downstream is common.

use oxicrypt_integrity::{
    SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE,
    slot::{BindRecord, Entry, EntryKind, Range},
};

/// What the signer needs to know about an artifact.
#[derive(Debug)]
pub struct Layout {
    /// The `Plain` entries of the extent, slot already subtracted,
    /// ascending: the bytes hashed exactly as the file holds them.
    pub ranges: Vec<Range>,
    /// The whole typed extent the slot records, slot already subtracted,
    /// ascending and merged.
    pub entries: Vec<Entry>,
    /// The slot's flags: the loader an ELF image is typed for.
    pub flags: u32,
    /// File offset of the integrity slot.
    pub slot_file_off: usize,
    /// Offset of the integrity slot from the image base.
    pub slot_rva: u32,
    /// Total file-backed bytes the extent types, of every kind, before the
    /// slot was subtracted. Reported so an operator can see what fraction
    /// of the mapped image the extent covers.
    pub invariant_len: u64,
    /// Total file-backed bytes across every load segment.
    pub mapped_len: u64,
    /// The image base the file was linked at, which a `Relative` word's
    /// unslid value is relative to. Zero where the classifier emits no
    /// `Relative` entry and does not read it.
    pub link_base: u64,
    /// Length of the file image the slot describes. It stops before the
    /// operating system's code-signature envelope: at a Mach-O
    /// `LC_CODE_SIGNATURE`'s `dataoff`, or a PE certificate table's file
    /// offset. Beyond it, `codesign` and `signtool` may grow or rewrite
    /// anything; before it they rewrite only the header and load-command
    /// fields `--reserved-against` measures.
    pub file_len: u32,
    /// How the file holds a `Relative` word, which decides the unslid value
    /// the signature covers.
    pub relative: RelativeEncoding,
    /// The imports the `Bind` entries name, in order of first use; a
    /// `Bind` entry's `meta` indexes this list.
    pub records: Vec<BindRecord>,
}

/// A run of file-backed bytes of one segment, with its base kind.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Region {
    /// Address of the run's first byte, as linked.
    pub(crate) va: u64,
    /// Length of the run.
    pub(crate) len: u64,
    /// File offset of the run's first byte.
    pub(crate) file_off: u64,
    /// `Plain` or `FileOnly`: the kind of every byte no word overrides.
    pub(crate) kind: EntryKind,
    /// The run lies in a segment the loader maps writable.
    pub(crate) writable: bool,
}

impl Region {
    /// One past the run's last address.
    pub(crate) fn end(&self) -> u64 {
        self.va.saturating_add(self.len)
    }
}

/// A word the loader writes, placed in a `Plain` region and typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Placed {
    /// Address of the word, as linked.
    pub(crate) va: u64,
    /// Length of the word.
    pub(crate) len: u64,
    /// `Relative`, `Bind` or `Hole`.
    pub(crate) kind: EntryKind,
    /// A `Bind` word's record index; zero otherwise.
    pub(crate) meta: u16,
}

/// Turns regions, ascending, and the words placed in their `Plain` runs,
/// ascending and disjoint, into ascending entries. A `FileOnly` region is
/// one entry, and no word is emitted inside it.
pub(crate) fn entries_of(
    regions: &[Region],
    words: &[Placed],
    image_base: u64,
) -> Result<Vec<Entry>, String> {
    let entry = |va: u64, len: u64, r: &Region, kind: EntryKind, meta: u16| {
        let rva = va
            .checked_sub(image_base)
            .ok_or("address below the image base")?;
        let file_off = r.file_off.saturating_add(va.saturating_sub(r.va));
        Ok::<Entry, String>(Entry {
            rva: u32::try_from(rva).map_err(|_| "an RVA exceeds 32 bits")?,
            file_off: u32::try_from(file_off).map_err(|_| "a file offset exceeds 32 bits")?,
            len: u32::try_from(len).map_err(|_| "an entry exceeds 32 bits")?,
            kind,
            meta,
        })
    };
    let mut out = Vec::new();
    let mut words = words.iter().peekable();
    for r in regions {
        if r.kind == EntryKind::FileOnly {
            out.push(entry(r.va, r.len, r, EntryKind::FileOnly, 0)?);
            continue;
        }
        let mut cursor = r.va;
        while let Some(w) = words.next_if(|w| w.va < r.end()) {
            if w.va > cursor {
                out.push(entry(
                    cursor,
                    w.va.saturating_sub(cursor),
                    r,
                    EntryKind::Plain,
                    0,
                )?);
            }
            out.push(entry(w.va, w.len, r, w.kind, w.meta)?);
            cursor = w.va.saturating_add(w.len);
        }
        if r.end() > cursor {
            out.push(entry(
                cursor,
                r.end().saturating_sub(cursor),
                r,
                EntryKind::Plain,
                0,
            )?);
        }
    }
    Ok(out)
}

/// Removes the slot from the entries. The slot must lie in `Plain` bytes.
pub(crate) fn subtract_slot(entries: &[Entry], slot_rva: u32) -> Result<Vec<Entry>, String> {
    let slot_len = u32::try_from(SLOT_SIZE).map_err(|_| "slot size exceeds 32 bits")?;
    let slot_end = slot_rva.checked_add(slot_len).ok_or("slot RVA overflows")?;
    let mut out = Vec::with_capacity(entries.len().saturating_add(1));
    for e in entries {
        let end = e.rva_end().ok_or("entry overflows")?;
        if end <= slot_rva || e.rva >= slot_end {
            out.push(*e);
            continue;
        }
        if e.kind != EntryKind::Plain {
            return Err(format!(
                "the integrity slot overlaps a {:?} entry at RVA {:#x}",
                e.kind, e.rva
            ));
        }
        let parts = subtract(
            &[Range {
                rva: e.rva,
                file_off: e.file_off,
                len: e.len,
            }],
            slot_rva,
            slot_len,
        )?;
        out.extend(parts.into_iter().map(Entry::plain));
    }
    Ok(out)
}

/// How a format stores a word the loader rebases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativeEncoding {
    /// The file word is the unslid address (ELF `RELR`, PE `DIR64`).
    FileWord,
    /// A Mach-O `DYLD_CHAINED_PTR_64` rebase: `target` in bits 0..36 is the
    /// unslid address, `high8` in bits 36..44 its top byte.
    ChainedPtr64,
    /// A Mach-O `DYLD_CHAINED_PTR_64_OFFSET` rebase: `target` is an offset
    /// from the image's link base.
    ChainedPtr64Offset,
}

impl RelativeEncoding {
    /// The unslid value a rebased word contributes to the signature input:
    /// the value the loader writes, less the slide. `None` for a chained
    /// word that is a bind rather than a rebase.
    #[must_use]
    pub fn unslid(self, raw: u64, link_base: u64) -> Option<u64> {
        const TARGET: u64 = 0xf_ffff_ffff;
        let chained = |base: u64| {
            if raw >> 63 != 0 {
                return None;
            }
            let high8 = (raw >> 36) & 0xff;
            Some(base.wrapping_add(raw & TARGET) | (high8 << 56))
        };
        match self {
            Self::FileWord => Some(raw),
            Self::ChainedPtr64 => chained(0),
            Self::ChainedPtr64Offset => chained(link_base),
        }
    }
}

/// The length a slot records for `bytes`, refused past the format's 32 bits.
pub(crate) fn file_len_of(bytes: &[u8]) -> Result<u32, String> {
    u32::try_from(bytes.len())
        .map_err(|_| "the file is larger than the slot format's 4 GiB".to_owned())
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
/// A signature over no image bytes says nothing about the image, so an
/// artifact signed with an empty extent passes its own integrity test while
/// proving nothing. The
/// classifiers already refuse an image with no candidate region; this is the
/// other way in — a candidate that the slot subtraction consumes entirely.
///
/// # Errors
///
/// Returns a description when `ranges` is empty.
pub(crate) fn ensure_non_empty(ranges: &[Range]) -> Result<(), String> {
    if ranges.is_empty() {
        return Err(
            "the extent is empty once the integrity slot is removed; a signature over no \
             image bytes proves nothing about the image"
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
    use super::{Range, RelativeEncoding, ensure_disjoint, ensure_non_empty, slot_fits, subtract};

    /// A chained rebase decodes to its target with `high8` restored, and
    /// the offset form adds the link base; a bind is not a rebase.
    #[test]
    fn chained_rebases_decode_to_the_address_the_loader_writes() {
        let raw = 0x1234 | (0x5au64 << 36) | (3u64 << 51);
        assert_eq!(
            RelativeEncoding::ChainedPtr64.unslid(raw, 0x1_0000_0000),
            Some(0x5a00_0000_0000_1234)
        );
        assert_eq!(
            RelativeEncoding::ChainedPtr64Offset.unslid(0x1234 | (3u64 << 51), 0x1_0000_0000),
            Some(0x1_0000_1234)
        );
        assert_eq!(RelativeEncoding::ChainedPtr64.unslid(1u64 << 63, 0), None);
        assert_eq!(RelativeEncoding::FileWord.unslid(raw, 0), Some(raw));
    }

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

    /// A signature over no image bytes proves nothing, so an extent the slot
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
        assert!(slot_fits(0x1000, 0, 0x1000 + size));
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
