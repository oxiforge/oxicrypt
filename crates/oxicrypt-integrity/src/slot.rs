//! Wire format of the reserved integrity slot.
//!
//! The slot is the whole contract between the build-time signer and the
//! runtime verifier. It is a fixed-size byte structure rather than a
//! Rust type read through field access, because the verifier acquires
//! its bytes through the platform's byte-acquisition mechanism and never
//! dereferences the linked static (see the crate documentation for why).
//!
//! ```text
//! offset  size          field
//! 0       16            header magic
//! 16      4             version   (u32 LE)
//! 20      4             flags     (u32 LE, reserved, must be zero)
//! 24      4             count     (u32 LE, number of range entries)
//! 28      4             slot_rva  (u32 LE, slot offset from image base)
//! 32      32            reference MAC (HMAC-SHA-256)
//! 64      count * 12    range table
//! …       …             zero padding
//! 16368   16            footer magic
//! ```
//!
//! Each range entry is three little-endian `u32`s: `rva`, `file_off`,
//! `len`. `rva` is what the verifier adds to the load base; `file_off`
//! is what the signer hashed and what the file-read fallback uses. They
//! differ whenever a segment's file offset and virtual address diverge,
//! which is ordinary.
//!
//! Every field is little-endian regardless of target byte order. The
//! format travels between a signer and a verifier that may be different
//! builds, so a byte order that follows the host would make the slot's
//! meaning depend on who wrote it.

use crate::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE, SLOT_VERSION};

/// Offset of the header magic.
pub const OFF_HDR: usize = 0;
/// Offset of the format version.
pub const OFF_VERSION: usize = 16;
/// Offset of the reserved flags word.
pub const OFF_FLAGS: usize = 20;
/// Offset of the range count.
pub const OFF_COUNT: usize = 24;
/// Offset of the slot's own RVA.
pub const OFF_SLOT_RVA: usize = 28;
/// Offset of the reference MAC.
pub const OFF_MAC: usize = 32;
/// Offset of the first range entry.
pub const OFF_TABLE: usize = 64;
/// Offset of the footer magic.
pub const OFF_FTR: usize = SLOT_SIZE - 16;

/// Size of one range entry: three little-endian `u32`s.
pub const RANGE_ENTRY_SIZE: usize = 12;

/// Number of range entries the table can hold.
///
/// The truncation is the point: whatever space is left between the table
/// and the footer, only whole entries fit in it. Any remainder is
/// padding, which is why the workspace's integer-division lint is
/// silenced here rather than the expression reshaped.
#[allow(
    clippy::integer_division,
    reason = "capacity in whole entries; the remainder is padding by design"
)]
pub const MAX_RANGES: usize = (OFF_FTR - OFF_TABLE) / RANGE_ENTRY_SIZE;

/// One contiguous run of loader-invariant bytes.
///
/// The same bytes are addressed two ways: by `rva` for the verifier
/// reading the loaded image, and by `file_off` for the signer computing
/// the reference MAC — and for the file-read fallback. That the two
/// yield identical bytes is the measured property the whole design rests
/// on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// Offset of the run from the image base, as loaded.
    pub rva: u32,
    /// Offset of the same run in the signed file.
    pub file_off: u32,
    /// Length of the run in bytes. Never zero.
    pub len: u32,
}

impl Range {
    /// One past the last RVA covered by this range, or `None` on
    /// overflow.
    #[must_use]
    pub fn rva_end(&self) -> Option<u32> {
        self.rva.checked_add(self.len)
    }
}

/// A parsed, validated slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotImage {
    /// Format version. Always [`SLOT_VERSION`] once parsed.
    pub version: u32,
    /// Reserved flags word.
    pub flags: u32,
    /// Offset of the slot itself from the image base.
    pub slot_rva: u32,
    /// Reference MAC over the listed ranges, in order.
    pub mac: [u8; 32],
    /// The loader-invariant extent.
    pub ranges: Vec<Range>,
}

/// Why a slot was refused.
///
/// Each variant names a distinct defect rather than collapsing to "bad
/// slot", because they mean different things: a wrong magic says the
/// artifact was never linked against this crate, an unsupported version
/// says it was signed by an incompatible tool, and a structural defect
/// says the signer produced an extent that cannot be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotDefect {
    /// The acquired bytes are not [`SLOT_SIZE`] long.
    WrongSize(usize),
    /// The header magic is absent.
    HeaderMagic,
    /// The footer magic is absent.
    FooterMagic,
    /// The version is not [`SLOT_VERSION`]. Zero means the artifact was
    /// never signed.
    UnsupportedVersion(u32),
    /// The reserved flags word is non-zero, so the slot was written by a
    /// tool asserting a feature this verifier does not implement.
    UnknownFlags(u32),
    /// The range count is zero: an extent covering nothing would make
    /// the test vacuous.
    NoRanges,
    /// The range count exceeds [`MAX_RANGES`].
    TooManyRanges(u32),
    /// The range at this index has zero length.
    EmptyRange(u32),
    /// The range at this index overflows the RVA space.
    RangeOverflow(u32),
    /// The range at this index starts before the previous range ends, so
    /// the table is unordered or self-overlapping.
    Unordered(u32),
    /// The range at this index covers part of the slot. The slot must be
    /// outside the extent or signer and verifier hash different bytes.
    OverlapsSlot(u32),
    /// The range at this index falls outside the image being hashed.
    RangeOutOfBounds(u32),
    /// The slot's recorded RVA exceeds the address the slot was found
    /// at, so no load base can be derived from the pair.
    SlotRvaTooLarge,
}

impl core::fmt::Display for SlotDefect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongSize(n) => write!(f, "slot is {n} bytes, expected {SLOT_SIZE}"),
            Self::HeaderMagic => f.write_str(
                "header magic absent — the artifact was not linked against oxicrypt-integrity, \
                 or the slot was stripped",
            ),
            Self::FooterMagic => {
                f.write_str("footer magic absent — the slot is truncated or overwritten")
            }
            Self::UnsupportedVersion(0) => {
                f.write_str("slot version 0 — the artifact was never signed")
            }
            Self::UnsupportedVersion(v) => write!(
                f,
                "slot version {v} is not supported (this module requires version {SLOT_VERSION})"
            ),
            Self::UnknownFlags(x) => write!(f, "slot declares unknown flags {x:#010x}"),
            Self::NoRanges => f.write_str("slot lists no ranges — the extent covers nothing"),
            Self::TooManyRanges(n) => write!(f, "slot lists {n} ranges, table holds {MAX_RANGES}"),
            Self::EmptyRange(i) => write!(f, "range {i} has zero length"),
            Self::RangeOverflow(i) => write!(f, "range {i} overflows the RVA space"),
            Self::Unordered(i) => write!(
                f,
                "range {i} starts before range {} ends",
                i.saturating_sub(1)
            ),
            Self::OverlapsSlot(i) => write!(f, "range {i} covers the integrity slot"),
            Self::RangeOutOfBounds(i) => write!(f, "range {i} falls outside the image"),
            Self::SlotRvaTooLarge => {
                f.write_str("the slot's recorded RVA exceeds its own address; no load base follows")
            }
        }
    }
}

impl std::error::Error for SlotDefect {}

/// Reads a little-endian `u32` at `off`, or `None` if it does not fit.
fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let slice = bytes.get(off..end)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

/// Writes a little-endian `u32` at `off`. Silently does nothing if the
/// buffer is too short, which [`encode`] makes impossible by allocating
/// [`SLOT_SIZE`] up front.
fn write_u32(bytes: &mut [u8], off: usize, value: u32) {
    if let Some(end) = off.checked_add(4)
        && let Some(slice) = bytes.get_mut(off..end)
    {
        slice.copy_from_slice(&value.to_le_bytes());
    }
}

/// Serialises a slot.
///
/// Checks only that the table fits: full structural validation lives in
/// [`parse`], and the signer runs `parse` over its own output as a
/// self-check, so there is one implementation of what "valid" means
/// rather than two that can drift.
///
/// # Errors
///
/// Returns [`SlotDefect::TooManyRanges`] when `ranges` exceeds
/// [`MAX_RANGES`].
pub fn encode(ranges: &[Range], slot_rva: u32, mac: &[u8; 32]) -> Result<Vec<u8>, SlotDefect> {
    if ranges.len() > MAX_RANGES {
        return Err(SlotDefect::TooManyRanges(
            u32::try_from(ranges.len()).unwrap_or(u32::MAX),
        ));
    }
    let mut out = vec![0u8; SLOT_SIZE];
    if let Some(slice) = out.get_mut(OFF_HDR..OFF_HDR.saturating_add(16)) {
        slice.copy_from_slice(&SLOT_HEADER_MAGIC);
    }
    if let Some(slice) = out.get_mut(OFF_FTR..SLOT_SIZE) {
        slice.copy_from_slice(&SLOT_FOOTER_MAGIC);
    }
    write_u32(&mut out, OFF_VERSION, SLOT_VERSION);
    write_u32(&mut out, OFF_FLAGS, 0);
    write_u32(
        &mut out,
        OFF_COUNT,
        u32::try_from(ranges.len()).unwrap_or(u32::MAX),
    );
    write_u32(&mut out, OFF_SLOT_RVA, slot_rva);
    if let Some(slice) = out.get_mut(OFF_MAC..OFF_MAC.saturating_add(32)) {
        slice.copy_from_slice(mac);
    }
    for (i, r) in ranges.iter().enumerate() {
        let base = OFF_TABLE.saturating_add(i.saturating_mul(RANGE_ENTRY_SIZE));
        write_u32(&mut out, base, r.rva);
        write_u32(&mut out, base.saturating_add(4), r.file_off);
        write_u32(&mut out, base.saturating_add(8), r.len);
    }
    Ok(out)
}

/// Parses and fully validates a slot.
///
/// # Errors
///
/// Returns the [`SlotDefect`] describing the first problem found.
pub fn parse(bytes: &[u8]) -> Result<SlotImage, SlotDefect> {
    if bytes.len() != SLOT_SIZE {
        return Err(SlotDefect::WrongSize(bytes.len()));
    }
    if bytes.get(OFF_HDR..OFF_HDR.saturating_add(16)) != Some(SLOT_HEADER_MAGIC.as_slice()) {
        return Err(SlotDefect::HeaderMagic);
    }
    if bytes.get(OFF_FTR..SLOT_SIZE) != Some(SLOT_FOOTER_MAGIC.as_slice()) {
        return Err(SlotDefect::FooterMagic);
    }
    let version = read_u32(bytes, OFF_VERSION).ok_or(SlotDefect::WrongSize(bytes.len()))?;
    if version != SLOT_VERSION {
        return Err(SlotDefect::UnsupportedVersion(version));
    }
    let flags = read_u32(bytes, OFF_FLAGS).ok_or(SlotDefect::WrongSize(bytes.len()))?;
    if flags != 0 {
        return Err(SlotDefect::UnknownFlags(flags));
    }
    let count = read_u32(bytes, OFF_COUNT).ok_or(SlotDefect::WrongSize(bytes.len()))?;
    if count == 0 {
        return Err(SlotDefect::NoRanges);
    }
    let count_usize = usize::try_from(count).unwrap_or(usize::MAX);
    if count_usize > MAX_RANGES {
        return Err(SlotDefect::TooManyRanges(count));
    }
    let slot_rva = read_u32(bytes, OFF_SLOT_RVA).ok_or(SlotDefect::WrongSize(bytes.len()))?;

    let mut mac = [0u8; 32];
    let mac_bytes = bytes
        .get(OFF_MAC..OFF_MAC.saturating_add(32))
        .ok_or(SlotDefect::WrongSize(bytes.len()))?;
    mac.copy_from_slice(mac_bytes);

    let slot_end = slot_rva
        .checked_add(u32::try_from(SLOT_SIZE).unwrap_or(u32::MAX))
        .ok_or(SlotDefect::RangeOverflow(0))?;

    let mut ranges = Vec::with_capacity(count_usize);
    let mut previous_end: u32 = 0;
    for i in 0..count_usize {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let base = OFF_TABLE.saturating_add(i.saturating_mul(RANGE_ENTRY_SIZE));
        let rva = read_u32(bytes, base).ok_or(SlotDefect::WrongSize(bytes.len()))?;
        let file_off =
            read_u32(bytes, base.saturating_add(4)).ok_or(SlotDefect::WrongSize(bytes.len()))?;
        let len =
            read_u32(bytes, base.saturating_add(8)).ok_or(SlotDefect::WrongSize(bytes.len()))?;
        let range = Range { rva, file_off, len };

        if len == 0 {
            return Err(SlotDefect::EmptyRange(index));
        }
        let end = range.rva_end().ok_or(SlotDefect::RangeOverflow(index))?;
        if rva < slot_end && end > slot_rva {
            return Err(SlotDefect::OverlapsSlot(index));
        }
        if i > 0 && rva < previous_end {
            return Err(SlotDefect::Unordered(index));
        }
        previous_end = end;
        ranges.push(range);
    }

    Ok(SlotImage {
        version,
        flags,
        slot_rva,
        mac,
        ranges,
    })
}

/// Total number of bytes an extent covers, or `None` on overflow.
#[must_use]
pub fn extent_len(ranges: &[Range]) -> Option<u64> {
    ranges
        .iter()
        .try_fold(0u64, |acc, r| acc.checked_add(u64::from(r.len)))
}
