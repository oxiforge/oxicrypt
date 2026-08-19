//! Mach-O 64-bit classification — deriving an image's loader-invariant extent.
//!
//! The signer's half of the design for Darwin, outside the cryptographic
//! boundary like the rest of this crate.
//!
//! # The rule
//!
//! Include every file-backed segment the loader maps executable and not
//! writable, then subtract the Mach header and load-command table, then the
//! integrity slot.
//!
//! # Why the header and load commands come out
//!
//! Mach-O puts them at the start of the segment that maps file offset zero —
//! `__TEXT` in every artifact seen — so a rule stated only in terms of segments
//! would cover them. Two independent reasons say it must not.
//!
//! The first is what they are. `AS10.17` obliges the integrity test to cover
//! *all software and firmware components within the cryptographic boundary*.
//! The header and the load-command table are neither: they are container
//! metadata the linker writes to tell the loader where the module's code and
//! constants live. Those sections are the software components, and they are
//! covered in full — the exclusion is of the envelope, not of anything the
//! module executes or reads.
//!
//! The second is what happens to them. `codesign` grows `__LINKEDIT` to hold
//! the signature, and the load command recording `__LINKEDIT`'s size lives in
//! the table inside `__TEXT`. So signing rewrites bytes the MAC covers without
//! moving or resizing anything the extent is defined by. Measured on both
//! architectures: 5 bytes changed on arm64 and 14 on x86_64, every one of them
//! ahead of the first section, none at or after it. An extent covering them
//! verifies on the artifact that was signed and fails on the next signing, and
//! that recurs for the life of the module.
//!
//! The bytes are not left unprotected by their absence here. Apple's own Code
//! Directory hashes the file from offset 0 to `codeLimit` — the offset of the
//! signature blob — so the header and the whole load-command table are inside
//! what `codesign` authenticates, and macOS validates it at load time. The two
//! mechanisms partition the file rather than leaving a gap in it.
//!
//! # Why this differs from the ELF rule, which takes every non-writable segment
//!
//! `__LINKEDIT` is non-writable, and in an unsigned or ad-hoc signed artifact
//! it is stable and byte-identical to the file — so a measurement alone would
//! invite including it. It is also exactly where `codesign` writes the
//! signature, which means an extent covering it verifies on the artifact that
//! was measured and fails on the first properly signed build. No measurement of
//! an unsigned binary can see that; the exclusion comes from what the format
//! does, not from what the bytes did.
//!
//! Requiring execute rather than merely non-writable excludes `__LINKEDIT`
//! without naming it, which matters because the segment set is
//! architecture-dependent: arm64 carries a `__DATA_CONST` that x86_64 may not,
//! and a rule written as a name list breaks when Apple changes one. Selecting on
//! the protection the loader applies is stable across both.
//!
//! # Why `filesize` and not `vmsize`
//!
//! As on ELF, `vmsize` may exceed `filesize`, the excess being zero-filled
//! rather than read from the file. Those bytes have no file counterpart, so the
//! signer could not compute them offline. Only the file-backed prefix is in the
//! extent.

use oxicrypt_integrity::{SLOT_SIZE, slot::Range};

use crate::image::{
    Layout, ensure_disjoint, ensure_non_empty, find_slot, slot_fits, subtract, u32_at, u64_at,
};

/// 64-bit Mach-O, host-endian little.
const MH_MAGIC_64: u32 = 0xfeed_facf;
/// 64-bit Mach-O with the opposite byte order. Recognised only so the
/// refusal can name it; a big-endian image is not classified.
const MH_CIGAM_64: u32 = 0xcffa_edfe;
/// A universal ("fat") archive, either byte order.
const FAT_MAGIC: u32 = 0xcafe_babe;
/// The same, byte-swapped.
const FAT_CIGAM: u32 = 0xbeba_feca;
/// `LC_SEGMENT_64`.
const LC_SEGMENT_64: u32 = 0x19;
/// Size of the fixed part of a `segment_command_64`, before its sections.
const SEGMENT_COMMAND_64_SIZE: usize = 72;
/// `mach_header_64` size.
const MACH_HEADER_64_SIZE: usize = 32;
/// `section_64` size.
const SECTION_64_SIZE: usize = 80;
/// `VM_PROT_WRITE`.
const VM_PROT_WRITE: u32 = 0x2;
/// `VM_PROT_EXECUTE`.
const VM_PROT_EXECUTE: u32 = 0x4;

/// True when `bytes` looks like a little-endian 64-bit Mach-O image.
#[must_use]
pub fn is_macho64_le(bytes: &[u8]) -> bool {
    u32_at(bytes, 0) == Some(MH_MAGIC_64)
}

/// Why `bytes` is a Mach-O this signer will not classify, if it is one.
///
/// Separated from [`is_macho64_le`] so the caller can tell "not a Mach-O at
/// all" from "a Mach-O whose shape is out of scope", and say which.
#[must_use]
pub fn unsupported_reason(bytes: &[u8]) -> Option<&'static str> {
    match u32_at(bytes, 0) {
        Some(MH_CIGAM_64) => Some("big-endian Mach-O images are not supported"),
        Some(FAT_MAGIC | FAT_CIGAM) => {
            Some("Mach-O universal binaries are not supported; sign each architecture slice")
        }
        _ => None,
    }
}

/// One `LC_SEGMENT_64`, reduced to what classification needs.
struct Segment {
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u32,
    /// The first file-backed section this segment carries, as
    /// `(addr, file offset)`, or `None` when it carries none.
    ///
    /// Only the segment mapping the start of the file uses it, and only to
    /// find where its content begins — see [`content_start`].
    first_section: Option<(u64, u64)>,
}

impl Segment {
    /// The loader maps this segment writable.
    const fn writable(&self) -> bool {
        self.initprot & VM_PROT_WRITE != 0
    }

    /// The loader maps this segment executable.
    const fn executable(&self) -> bool {
        self.initprot & VM_PROT_EXECUTE != 0
    }

    /// This segment is a candidate for the extent.
    const fn invariant(&self) -> bool {
        self.executable() && !self.writable() && self.filesize > 0
    }
}

/// The first file-backed section of the `LC_SEGMENT_64` at `cmd_off`, as
/// `(addr, file offset)`.
///
/// "First" is by file offset, not by table order — nothing in the format
/// obliges a linker to emit sections in ascending order, and the caller needs
/// the lowest offset rather than the earliest entry.
///
/// A section with a zero file offset is not file-backed: that is how
/// `S_ZEROFILL` and its relatives are spelled, and their bytes come from the
/// loader rather than from the file. Including one would put the header at the
/// start of the extent again, which is the whole thing this exists to avoid.
///
/// # Errors
///
/// Returns a description when the section table does not fit inside the load
/// command that declares it.
fn first_section(
    bytes: &[u8],
    cmd_off: usize,
    cmdsize: usize,
    nsects: u32,
) -> Result<Option<(u64, u64)>, String> {
    let nsects = usize::try_from(nsects).map_err(|_| "section count exceeds usize")?;
    let table = nsects
        .checked_mul(SECTION_64_SIZE)
        .ok_or("section table overflows")?;
    let needed = SEGMENT_COMMAND_64_SIZE
        .checked_add(table)
        .ok_or("section table overflows")?;
    if needed > cmdsize {
        return Err(format!(
            "LC_SEGMENT_64 declares {nsects} sections but is only {cmdsize} bytes"
        ));
    }
    let mut best: Option<(u64, u64)> = None;
    for i in 0..nsects {
        let base = cmd_off
            .checked_add(SEGMENT_COMMAND_64_SIZE)
            .and_then(|o| o.checked_add(i.checked_mul(SECTION_64_SIZE)?))
            .ok_or("section offset overflows")?;
        let at = |d: usize| -> Result<usize, String> {
            base.checked_add(d)
                .ok_or_else(|| "section field overflows".to_owned())
        };
        let addr = u64_at(bytes, at(32)?).ok_or("truncated section")?;
        let size = u64_at(bytes, at(40)?).ok_or("truncated section")?;
        let offset = u64::from(u32_at(bytes, at(48)?).ok_or("truncated section")?);
        if offset == 0 || size == 0 {
            continue;
        }
        if best.is_none_or(|(_, b)| offset < b) {
            best = Some((addr, offset));
        }
    }
    Ok(best)
}

/// Where a segment's content begins, relative to the segment's own start.
///
/// For every segment but one this is zero. The exception is the segment that
/// maps file offset zero, which on Mach-O carries the `mach_header_64` and the
/// whole load-command table ahead of its first section — see the module
/// documentation for why those bytes cannot be in the extent.
///
/// # Errors
///
/// Returns a description when the segment carries no file-backed section, or
/// when its first section's address and file offset disagree about where in the
/// segment it sits. The second is not a formality: the extent is recorded twice
/// over, once as an RVA for the verifier and once as a file offset for the
/// signer, and a segment whose two mappings are skewed would give the two sides
/// different bytes.
fn content_start(seg: &Segment, image_base: u64) -> Result<u64, String> {
    let (addr, offset) = seg.first_section.ok_or(
        "the segment mapping the start of the file carries no file-backed section, so there \
         is no point at which its content begins and the header ends",
    )?;
    let sect_rva = addr
        .checked_sub(image_base)
        .ok_or("a section's address is below the image base")?;
    let seg_rva = seg
        .vmaddr
        .checked_sub(image_base)
        .ok_or("segment address below the image base")?;
    let from_addr = sect_rva
        .checked_sub(seg_rva)
        .ok_or("a section's address is below the segment that contains it")?;
    let from_file = offset
        .checked_sub(seg.fileoff)
        .ok_or("a section's file offset is below the segment that contains it")?;
    if from_addr != from_file {
        return Err(format!(
            "the first section sits {from_addr:#x} into the segment by address but \
             {from_file:#x} by file offset; the extent could not be recorded both ways"
        ));
    }
    Ok(from_file)
}

/// Parses every `LC_SEGMENT_64` and the image base they imply.
///
/// # Errors
///
/// Returns a description when the header or a load command is malformed, or
/// when no segment maps the file's start — without which there is no image
/// base and every RVA would be a guess.
fn segments(bytes: &[u8]) -> Result<(Vec<Segment>, u64), String> {
    if !is_macho64_le(bytes) {
        return Err("not a little-endian 64-bit Mach-O image".to_owned());
    }
    let ncmds = u32_at(bytes, 16).ok_or("truncated Mach-O header")?;
    let sizeofcmds = u32_at(bytes, 20).ok_or("truncated Mach-O header")?;
    let cmds_end = MACH_HEADER_64_SIZE
        .checked_add(usize::try_from(sizeofcmds).map_err(|_| "load commands exceed usize")?)
        .ok_or("load command region overflows")?;
    if cmds_end > bytes.len() {
        return Err("load commands extend past the end of the file".to_owned());
    }

    let mut out = Vec::new();
    let mut off = MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        let cmd = u32_at(bytes, off).ok_or("truncated load command")?;
        let cmdsize = u32_at(bytes, off.checked_add(4).ok_or("load command overflows")?)
            .ok_or("truncated load command")?;
        let cmdsize = usize::try_from(cmdsize).map_err(|_| "load command size exceeds usize")?;
        // A zero or unaligned size would loop forever or walk off the end.
        if cmdsize < 8 || cmdsize % 8 != 0 {
            return Err(format!("load command has an implausible size of {cmdsize}"));
        }
        let next = off.checked_add(cmdsize).ok_or("load command overflows")?;
        if next > cmds_end {
            return Err("a load command extends past the load command region".to_owned());
        }
        if cmd == LC_SEGMENT_64 {
            if cmdsize < SEGMENT_COMMAND_64_SIZE {
                return Err("LC_SEGMENT_64 is shorter than its fixed fields".to_owned());
            }
            let at = |d: usize| -> Result<usize, String> {
                off.checked_add(d)
                    .ok_or_else(|| "segment field overflows".to_owned())
            };
            let nsects = u32_at(bytes, at(64)?).ok_or("truncated segment command")?;
            out.push(Segment {
                vmaddr: u64_at(bytes, at(24)?).ok_or("truncated segment command")?,
                fileoff: u64_at(bytes, at(40)?).ok_or("truncated segment command")?,
                filesize: u64_at(bytes, at(48)?).ok_or("truncated segment command")?,
                initprot: u32_at(bytes, at(60)?).ok_or("truncated segment command")?,
                first_section: first_section(bytes, off, cmdsize, nsects)?,
            });
        }
        off = next;
    }

    // The image base is the address of the segment that maps the file's
    // start — the one carrying the Mach header. Derived rather than named:
    // it is `__TEXT` in every artifact seen, but nothing in the format says
    // it must be called that.
    let base = out
        .iter()
        .find(|s| s.fileoff == 0 && s.filesize > 0)
        .map(|s| s.vmaddr)
        .ok_or("no file-backed segment maps the start of the file, so there is no image base")?;
    Ok((out, base))
}

/// Turns a segment into a range, addressed both ways.
fn segment_range(s: &Segment, image_base: u64, file_len: usize) -> Result<Range, String> {
    let rva = s
        .vmaddr
        .checked_sub(image_base)
        .ok_or("segment address below the image base")?;
    let rva = u32::try_from(rva).map_err(|_| "segment RVA exceeds 32 bits")?;
    let len = u32::try_from(s.filesize).map_err(|_| "segment exceeds 32 bits")?;
    let file_off = u32::try_from(s.fileoff).map_err(|_| "segment file offset exceeds 32 bits")?;
    let end = usize::try_from(s.fileoff)
        .ok()
        .and_then(|o| o.checked_add(usize::try_from(s.filesize).ok()?))
        .ok_or("segment file extent overflows")?;
    if end > file_len {
        return Err("a segment's file extent runs past the end of the file".to_owned());
    }
    Ok(Range { rva, file_off, len })
}

/// The ranges the loader may write to: every writable segment's file-backed
/// bytes.
///
/// The complement of the extent, and never part of it. Exposed for the same
/// reason as its ELF counterpart — building the control that proves the
/// stability probe can fail.
///
/// # Errors
///
/// Returns a description when the image is malformed.
pub fn writable_ranges(bytes: &[u8]) -> Result<Vec<Range>, String> {
    let (segs, base) = segments(bytes)?;
    segs.iter()
        .filter(|s| s.writable() && s.filesize > 0)
        .map(|s| segment_range(s, base, bytes.len()))
        .collect()
}

/// Derives the loader-invariant extent of a Mach-O 64-bit image.
///
/// # Errors
///
/// Returns a description when the image is malformed, the slot is missing or
/// ambiguous, the slot lies in a writable segment, or a segment is too large
/// for the slot format's 32-bit fields.
pub fn classify(bytes: &[u8]) -> Result<Layout, String> {
    let (segs, base) = segments(bytes)?;
    let mapped_len: u64 = segs.iter().map(|s| s.filesize).sum();

    let mut candidates: Vec<Range> = segs
        .iter()
        .filter(|s| s.invariant())
        .map(|s| segment_range(s, base, bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    if candidates.is_empty() {
        return Err(
            "no segment is mapped executable and non-writable, so there is nothing to hash"
                .to_owned(),
        );
    }
    candidates.sort_by_key(|r| r.rva);
    ensure_disjoint(&candidates)?;

    // Take the header and load-command table out of the extent. They sit at
    // the start of the segment that maps file offset zero, ahead of its first
    // section, and the module's own code and constants begin where they end.
    let header_seg = segs
        .iter()
        .find(|s| s.fileoff == 0 && s.filesize > 0)
        .ok_or("no file-backed segment maps the start of the file")?;
    if header_seg.invariant() {
        let header_rva = header_seg
            .vmaddr
            .checked_sub(base)
            .ok_or("segment address below the image base")?;
        let header_rva = u32::try_from(header_rva).map_err(|_| "segment RVA exceeds 32 bits")?;
        let cut = u32::try_from(content_start(header_seg, base)?)
            .map_err(|_| "the header and load commands exceed 32 bits")?;
        candidates = subtract(&candidates, header_rva, cut)?;
        ensure_non_empty(&candidates)?;
    }

    let invariant_len: u64 = candidates.iter().map(|r| u64::from(r.len)).sum();

    let slot_file_off = find_slot(bytes)?;
    let slot_seg = segs
        .iter()
        .find(|s| {
            let start = usize::try_from(s.fileoff).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(s.filesize).unwrap_or(0));
            slot_fits(slot_file_off, start, end)
        })
        .ok_or("no single segment contains the whole integrity slot")?;
    if slot_seg.writable() {
        return Err(
            "the integrity slot is in a writable segment; the loader may modify it".to_owned(),
        );
    }
    let slot_off_in_seg = (slot_file_off as u64)
        .checked_sub(slot_seg.fileoff)
        .ok_or("slot precedes the segment that contains it")?;
    let slot_rva_u64 = slot_seg
        .vmaddr
        .checked_sub(base)
        .ok_or("segment address below the image base")?
        .checked_add(slot_off_in_seg)
        .ok_or("slot RVA overflows")?;
    let slot_rva = u32::try_from(slot_rva_u64).map_err(|_| "slot RVA exceeds 32 bits")?;

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

    use super::{VM_PROT_EXECUTE, VM_PROT_WRITE, classify, is_macho64_le, writable_ranges};

    /// `VM_PROT_READ`.
    const R: u32 = 0x1;
    /// The image base every fixture uses.
    const BASE: u64 = 0x1_0000_0000;

    /// One synthetic segment: name, RVA, file offset, file size, virtual size,
    /// protection, and its sections.
    ///
    /// RVA is given separately from the file offset, and the fixtures below keep
    /// the two deliberately different. Deriving one from the other would let
    /// `segment_range` read `fileoff` where it means `vmaddr - base`, or the
    /// reverse, and every test in this file would still pass.
    struct Seg(&'static str, u64, u64, u64, u64, u32, &'static [Sect]);

    /// One synthetic section: RVA, file offset, size.
    ///
    /// A file offset of zero marks a section the loader fills rather than
    /// reads, which is how `S_ZEROFILL` is spelled in a real image.
    #[derive(Clone, Copy)]
    struct Sect(u64, u64, u64);

    /// Builds a minimal little-endian 64-bit Mach-O carrying `segs`.
    ///
    /// Synthetic rather than a checked-in binary: a real artifact is half a
    /// megabyte, and — more to the point — a real one cannot be made to hold
    /// the shapes that matter here, such as a slot in a writable segment.
    fn image(segs: &[Seg], file_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; file_len];
        let cmdsize = |s: &Seg| super::SEGMENT_COMMAND_64_SIZE + s.6.len() * super::SECTION_64_SIZE;
        let cmds_size: usize = segs.iter().map(cmdsize).sum();
        out[0..4].copy_from_slice(&super::MH_MAGIC_64.to_le_bytes());
        out[16..20].copy_from_slice(&u32::try_from(segs.len()).unwrap().to_le_bytes());
        out[20..24].copy_from_slice(&u32::try_from(cmds_size).unwrap().to_le_bytes());
        let mut off = super::MACH_HEADER_64_SIZE;
        for seg in segs {
            let Seg(name, rva, fileoff, filesize, vmsize, prot, sects) = seg;
            out[off..off + 4].copy_from_slice(&super::LC_SEGMENT_64.to_le_bytes());
            out[off + 4..off + 8]
                .copy_from_slice(&u32::try_from(cmdsize(seg)).unwrap().to_le_bytes());
            out[off + 8..off + 8 + name.len()].copy_from_slice(name.as_bytes());
            out[off + 24..off + 32].copy_from_slice(&(BASE + rva).to_le_bytes());
            out[off + 32..off + 40].copy_from_slice(&vmsize.to_le_bytes());
            out[off + 40..off + 48].copy_from_slice(&fileoff.to_le_bytes());
            out[off + 48..off + 56].copy_from_slice(&filesize.to_le_bytes());
            out[off + 60..off + 64].copy_from_slice(&prot.to_le_bytes());
            out[off + 64..off + 68]
                .copy_from_slice(&u32::try_from(sects.len()).unwrap().to_le_bytes());
            let mut soff = off + super::SEGMENT_COMMAND_64_SIZE;
            for Sect(sect_rva, sect_off, size) in *sects {
                out[soff + 32..soff + 40].copy_from_slice(&(BASE + sect_rva).to_le_bytes());
                out[soff + 40..soff + 48].copy_from_slice(&size.to_le_bytes());
                out[soff + 48..soff + 52]
                    .copy_from_slice(&u32::try_from(*sect_off).unwrap().to_le_bytes());
                soff += super::SECTION_64_SIZE;
            }
            off += cmdsize(seg);
        }
        out
    }

    /// Writes a well-formed slot at `at`.
    fn put_slot(image: &mut [u8], at: usize) {
        image[at..at + 16].copy_from_slice(&SLOT_HEADER_MAGIC);
        image[at + SLOT_SIZE - 16..at + SLOT_SIZE].copy_from_slice(&SLOT_FOOTER_MAGIC);
    }

    /// A text-shaped fixture: `__TEXT` r-x holding the slot, plus a writable
    /// segment and a read-only non-executable one.
    fn fixture() -> Vec<u8> {
        let mut img = image(
            &[
                Seg(
                    "__TEXT",
                    TEXT_RVA,
                    0,
                    0x8000,
                    0x8000,
                    R | VM_PROT_EXECUTE,
                    // The header and load commands occupy the segment ahead of
                    // this; `CONTENT` is where the module's own bytes begin.
                    &[Sect(CONTENT, CONTENT, 0x8000 - CONTENT)],
                ),
                // vmsize exceeds filesize: the excess is zero-filled by the
                // loader and has no file counterpart, so it must stay out of
                // every range this crate emits.
                Seg(
                    "__DATA",
                    DATA_RVA,
                    0x8000,
                    0x1000,
                    0x4000,
                    R | VM_PROT_WRITE,
                    &[Sect(DATA_RVA, 0x8000, 0x1000)],
                ),
                Seg("__LINKEDIT", LINKEDIT_RVA, 0x9000, 0x1000, 0x1000, R, &[]),
            ],
            0xa000,
        );
        put_slot(&mut img, 0x2000);
        img
    }

    /// Where the fixture's segments sit in address space — deliberately not
    /// equal to their file offsets.
    /// `__TEXT` maps the start of the file, so it *is* the image base and its
    /// RVA is zero by construction — that much cannot be decoupled. The other
    /// two are given addresses that do not match their file offsets, which is
    /// what makes `segment_range` reading `fileoff` where it means
    /// `vmaddr - base` a failing test rather than an invisible one.
    const TEXT_RVA: u64 = 0;
    const DATA_RVA: u64 = 0x20000;
    const LINKEDIT_RVA: u64 = 0x30000;

    /// Where `__TEXT`'s first section begins — the boundary between the header
    /// and load-command table and the module's own bytes.
    const CONTENT: u64 = 0x200;

    #[test]
    fn the_extent_is_the_executable_segment_less_the_header_and_the_slot() {
        let img = fixture();
        assert!(is_macho64_le(&img));
        let layout = classify(&img).expect("classify");
        assert_eq!(layout.slot_file_off, 0x2000);
        assert_eq!(
            layout.slot_rva,
            u32::try_from(TEXT_RVA).unwrap() + 0x2000,
            "the slot RVA must come from the segment address, not the file offset"
        );
        // `__TEXT` is 0x8000 bytes, of which the first CONTENT are header and
        // load commands; the slot splits what remains in two.
        assert_eq!(layout.invariant_len, 0x8000 - CONTENT);
        assert_eq!(layout.ranges.len(), 2, "the slot must split __TEXT");
        assert_eq!(
            layout.ranges[0].rva,
            u32::try_from(TEXT_RVA + CONTENT).unwrap(),
            "the extent must begin at the first section, not at the segment"
        );
        assert_eq!(layout.ranges[0].file_off, u32::try_from(CONTENT).unwrap());
        assert_eq!(
            layout.ranges[0].len,
            u32::try_from(0x2000 - CONTENT).unwrap()
        );
        assert_eq!(
            layout.ranges[1].rva,
            u32::try_from(TEXT_RVA).unwrap() + 0x2000 + u32::try_from(SLOT_SIZE).unwrap()
        );
        assert_eq!(
            layout.ranges[1].file_off,
            0x2000 + u32::try_from(SLOT_SIZE).unwrap(),
            "the file offset must advance with the RVA, not equal it"
        );
        let covered: u64 = layout.ranges.iter().map(|r| u64::from(r.len)).sum();
        assert_eq!(
            covered,
            0x8000 - CONTENT - u64::try_from(SLOT_SIZE).unwrap()
        );
    }

    /// The rule this module exists to get right, stated as the mechanism that
    /// forced it rather than as a range arithmetic check.
    ///
    /// `codesign` rewrites bytes in the load-command table — the command
    /// recording `__LINKEDIT`'s size — and nothing else inside `__TEXT`. This
    /// reproduces that shape: a byte changed in the load commands must leave
    /// the MAC alone, while a byte changed in the first section must break it.
    /// Without the second half the first passes on an empty extent.
    #[test]
    fn a_byte_changed_in_the_load_commands_does_not_break_the_mac() {
        let mut img = fixture();
        let ranges = classify(&img).expect("classify").ranges;
        let mac = crate::sign_image(&mut img).expect("sign");

        // Inside the load-command table: past the 32-byte header, well short of
        // the first section. This is where codesign writes.
        let in_load_commands = super::MACH_HEADER_64_SIZE + 8;
        assert!(
            (in_load_commands as u64) < CONTENT,
            "the probe offset must really be ahead of the first section"
        );
        let mut signed = img.clone();
        signed[in_load_commands] ^= 0xff;
        assert_eq!(
            oxicrypt_integrity::mac_over_file_ranges(&signed, &ranges).expect("mac"),
            mac,
            "a byte in the load commands is in the extent; every codesign would break the MAC"
        );

        // The mirror control. Without it the assertion above passes on an
        // extent that covers nothing at all.
        let mut content = img.clone();
        content[usize::try_from(CONTENT).unwrap()] ^= 0xff;
        assert_ne!(
            oxicrypt_integrity::mac_over_file_ranges(&content, &ranges).expect("mac"),
            mac,
            "the first section's bytes must be covered, or the exclusion has eaten the module"
        );
    }

    /// The header region is subtracted, not merely skipped by ordering.
    #[test]
    fn no_range_covers_the_header_or_the_load_commands() {
        let layout = classify(&fixture()).expect("classify");
        assert!(
            !layout.ranges.is_empty(),
            "an all() over an empty list is trivially true"
        );
        assert!(
            layout
                .ranges
                .iter()
                .all(|r| u64::from(r.file_off) >= CONTENT),
            "a range begins inside the header or load commands: {:?}",
            layout.ranges
        );
    }

    /// A segment mapping the file's start with nothing file-backed in it gives
    /// no boundary between metadata and content, and guessing one would put the
    /// header back in the extent.
    #[test]
    fn a_file_start_segment_with_no_file_backed_section_is_refused() {
        let mut img = image(
            &[
                Seg(
                    "__TEXT",
                    TEXT_RVA,
                    0,
                    0x8000,
                    0x8000,
                    R | VM_PROT_EXECUTE,
                    &[],
                ),
                Seg("__LINKEDIT", LINKEDIT_RVA, 0x8000, 0x1000, 0x1000, R, &[]),
            ],
            0x9000,
        );
        put_slot(&mut img, 0x2000);
        let err = classify(&img).expect_err("no boundary means no extent");
        assert!(
            err.contains("no file-backed section"),
            "unhelpful refusal: {err}"
        );
    }

    /// `S_ZEROFILL` and its relatives carry a file offset of zero. Treating one
    /// as the content boundary would set the cut to zero and quietly restore
    /// the bug this module was changed to fix.
    #[test]
    fn a_zero_filled_section_does_not_set_the_content_boundary() {
        let mut img = image(
            &[
                Seg(
                    "__TEXT",
                    TEXT_RVA,
                    0,
                    0x8000,
                    0x8000,
                    R | VM_PROT_EXECUTE,
                    &[Sect(0x7000, 0, 0x100), Sect(CONTENT, CONTENT, 0x100)],
                ),
                Seg("__LINKEDIT", LINKEDIT_RVA, 0x8000, 0x1000, 0x1000, R, &[]),
            ],
            0x9000,
        );
        put_slot(&mut img, 0x2000);
        let layout = classify(&img).expect("classify");
        assert_eq!(
            layout.ranges[0].file_off,
            u32::try_from(CONTENT).unwrap(),
            "a section with no file bytes must not set the boundary"
        );
    }

    /// Nothing obliges a linker to emit sections in ascending file order, and
    /// taking the first entry rather than the lowest offset would cut too much.
    #[test]
    fn the_boundary_is_the_lowest_file_offset_not_the_first_entry() {
        let mut img = image(
            &[
                Seg(
                    "__TEXT",
                    TEXT_RVA,
                    0,
                    0x8000,
                    0x8000,
                    R | VM_PROT_EXECUTE,
                    &[Sect(0x1000, 0x1000, 0x100), Sect(CONTENT, CONTENT, 0x100)],
                ),
                Seg("__LINKEDIT", LINKEDIT_RVA, 0x8000, 0x1000, 0x1000, R, &[]),
            ],
            0x9000,
        );
        put_slot(&mut img, 0x2000);
        let layout = classify(&img).expect("classify");
        assert_eq!(layout.ranges[0].file_off, u32::try_from(CONTENT).unwrap());
    }

    /// The extent is recorded twice over — as an RVA for the verifier and as a
    /// file offset for the signer. A section whose two positions disagree would
    /// give the two sides different bytes, so it is refused rather than
    /// resolved in favour of one of them.
    #[test]
    fn a_section_whose_address_and_file_offset_disagree_is_refused() {
        let mut img = image(
            &[
                Seg(
                    "__TEXT",
                    TEXT_RVA,
                    0,
                    0x8000,
                    0x8000,
                    R | VM_PROT_EXECUTE,
                    &[Sect(0x300, CONTENT, 0x100)],
                ),
                Seg("__LINKEDIT", LINKEDIT_RVA, 0x8000, 0x1000, 0x1000, R, &[]),
            ],
            0x9000,
        );
        put_slot(&mut img, 0x2000);
        let err = classify(&img).expect_err("a skewed section must be refused");
        assert!(
            err.contains("could not be recorded both ways"),
            "unhelpful refusal: {err}"
        );
    }

    /// A section table declared larger than the load command holding it must be
    /// refused rather than read out of bounds into the next command.
    #[test]
    fn a_section_table_that_does_not_fit_its_load_command_is_refused() {
        let mut img = fixture();
        // `__TEXT` is the first load command; overstate its section count.
        let nsects_at = super::MACH_HEADER_64_SIZE + 64;
        img[nsects_at..nsects_at + 4].copy_from_slice(&99u32.to_le_bytes());
        let err = classify(&img).expect_err("an oversized section table must be refused");
        assert!(err.contains("99 sections"), "unhelpful refusal: {err}");
    }

    /// The rule that distinguishes this classifier from the ELF one.
    ///
    /// `__LINKEDIT` is read-only and would be included by "every non-writable
    /// segment". It must not be: it is where `codesign` writes. Without this
    /// case the executable requirement could be dropped and every other test
    /// here would still pass.
    #[test]
    fn a_read_only_non_executable_segment_is_excluded() {
        let img = fixture();
        let layout = classify(&img).expect("classify");
        assert!(
            !layout.ranges.is_empty(),
            "a !any() assertion over an empty list is trivially true"
        );
        let linkedit_rva = u32::try_from(LINKEDIT_RVA).unwrap();
        assert!(
            !layout.ranges.iter().any(|r| r.rva == linkedit_rva),
            "__LINKEDIT is in the extent; codesign writes there and the MAC would break \
             on the first signed build"
        );
        assert!(
            layout.mapped_len > layout.invariant_len,
            "the fixture must contain segments outside the extent, or this proves nothing"
        );
    }

    #[test]
    fn writable_segments_are_reported_and_excluded() {
        let img = fixture();
        let writable = writable_ranges(&img).expect("writable ranges");
        assert_eq!(writable.len(), 1);
        assert_eq!(writable[0].rva, u32::try_from(DATA_RVA).unwrap());
        assert_eq!(
            writable[0].len, 0x1000,
            "the writable range must be the file-backed size, not the larger vmsize"
        );
        let layout = classify(&img).expect("classify");
        assert!(
            !layout.ranges.is_empty(),
            "an empty extent proves nothing below"
        );
        assert!(
            !layout
                .ranges
                .iter()
                .any(|r| r.rva == u32::try_from(DATA_RVA).unwrap())
        );
    }

    #[test]
    fn a_slot_in_a_writable_segment_is_refused() {
        let mut img = image(
            &[
                Seg(
                    "__TEXT",
                    TEXT_RVA,
                    0,
                    0x1000,
                    0x1000,
                    R | VM_PROT_EXECUTE,
                    &[Sect(CONTENT, CONTENT, 0x1000 - CONTENT)],
                ),
                Seg(
                    "__DATA",
                    DATA_RVA,
                    0x1000,
                    0x8000,
                    0x8000,
                    R | VM_PROT_WRITE,
                    &[Sect(DATA_RVA, 0x1000, 0x8000)],
                ),
            ],
            0x9000,
        );
        put_slot(&mut img, 0x2000);
        let err = classify(&img).expect_err("a slot the loader may rewrite must be refused");
        assert!(err.contains("writable"), "unhelpful refusal: {err}");
    }

    #[test]
    fn an_image_with_no_executable_segment_is_refused() {
        let mut img = image(
            &[Seg(
                "__DATA",
                DATA_RVA,
                0,
                0x8000,
                0x8000,
                R | VM_PROT_WRITE,
                &[Sect(DATA_RVA, 0x400, 0x7c00)],
            )],
            0x8000,
        );
        put_slot(&mut img, 0x1000);
        let err = classify(&img).expect_err("nothing to hash must be refused");
        assert!(err.contains("nothing to hash"), "unhelpful refusal: {err}");
    }

    #[test]
    fn a_truncated_header_is_refused_rather_than_guessed() {
        let img = fixture();
        for (cut, expected) in [
            // Four bytes is enough for the magic, so the refusal comes from
            // the header fields beyond it rather than from the magic.
            (4, "truncated Mach-O header"),
            (16, "truncated Mach-O header"),
            // At 31 bytes both header counts are readable, so the refusal
            // moves to the region they describe.
            (31, "load commands extend past the end of the file"),
            (40, "load commands extend past the end of the file"),
        ] {
            let err = classify(&img[..cut]).expect_err("a truncated image must be refused");
            assert_eq!(
                err, expected,
                "cut {cut} must be refused for the reason that applies to it, not merely \
                 refused — a bare is-error assertion passes on \"no integrity slot found\""
            );
        }
    }

    #[test]
    fn universal_and_big_endian_images_are_named_rather_than_lumped_in() {
        let fat = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0];
        assert!(!is_macho64_le(&fat));
        assert!(
            super::unsupported_reason(&fat).is_some_and(|r| r.contains("universal")),
            "a fat binary must say so"
        );
        let cigam = 0xcffa_edfeu32.to_le_bytes();
        assert!(
            super::unsupported_reason(&cigam).is_some_and(|r| r.contains("big-endian")),
            "a byte-swapped image must say so"
        );
        // The mirror control: an ordinary image is not "unsupported".
        assert!(super::unsupported_reason(&fixture()).is_none());
    }

    /// A file offset inside the image but outside every extent range.
    const OUTSIDE: usize = 0x8000;

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
