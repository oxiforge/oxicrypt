//! Wire format of the reserved integrity slot, version 4.
//!
//! The slot is the whole contract between the build-time signer and the
//! runtime verifier. It is a fixed-size byte structure rather than a Rust
//! type read through field access, because the verifier acquires its bytes
//! through the platform's byte-acquisition mechanism and never
//! dereferences the linked static (see the crate documentation for why).
//!
//! ```text
//! offset  size          field
//! 0       16            header magic
//! 16      4             version        (u32, 4)
//! 20      4             flags          (u32, bit 0: the loader is bionic)
//! 24      4             count          (u32, number of entries)
//! 28      4             slot_rva       (u32, slot offset from the image base)
//! 32      4627          signature      (ML-DSA-87, FIPS 204 sigEncode)
//! 4659    32            key_id         (SHA-256 of the verifying key)
//! 4691    8             link_base      (u64, the image base the file was linked at)
//! 4699    4             strtab_off     (u32, offset of the string table in the slot)
//! 4703    4             strtab_len     (u32, length of the string table)
//! 4707    4             slot_file_off  (u32, file offset of the slot)
//! 4711    4             file_len       (u32, length of the signed file image)
//! 4715    count * 16    entry table
//! …       …             zero bytes, the string table, zero bytes
//! 65520   16            footer magic
//! ```
//!
//! Each entry is `rva u32 | file_off u32 | len u32 | kind u8 | run u8
//! | meta u16`, little-endian. `rva` is what the verifier adds to the load
//! base; `file_off` is the same bytes in the signed file. The kinds:
//!
//! | Kind | Value | Signature input | Runtime check |
//! |---|---|---|---|
//! | [`EntryKind::Plain`] | 0 | the bytes | the loaded bytes |
//! | [`EntryKind::Hole`] | 1 | nothing | nothing |
//! | [`EntryKind::Relative`] | 2 | each 8-byte word's unslid value | `word - slide` |
//! | [`EntryKind::Bind`] | 3 | nothing | `word == resolved + addend` |
//! | [`EntryKind::FileOnly`] | 4 | the bytes of the image file | the file the loader reports |
//!
//! `meta` is zero except on a `Bind` entry, where it indexes the
//! [`BindRecord`] in the string table, and on a `Plain` entry, where it is
//! the number of 8-byte `Hole` words that follow its `len` hashed bytes
//! inside the same entry. A loader writes a relocated word between runs of
//! bytes it leaves alone, so nearly every hole follows `Plain` bytes, and
//! carrying it in that entry halves the table without leaving any byte
//! untyped: the hole is as explicit, and as signed, as a `Hole` entry.
//!
//! `run` is zero except on a `Plain` entry that carries words. Its bit 7
//! makes those words `Relative` rather than `Hole`, so a rebased word after
//! `Plain` bytes is carried the same way, each word still hashed as its
//! unslid value. Its bits 0–6 count further periods, 0 to 127, each the same `len`
//! bytes and `meta` words, that follow the first contiguously: a table of
//! pointers into constant data stores as one entry per run of identical
//! periods. The stored table is the one deterministic packing of the
//! canonical entries ([`parse`] expands it and requires it to repack
//! exactly), [`MAX_ENTRIES`] bounds the stored entries, and
//! [`MAX_EXPANDED`] the entries they expand to. A slot past [`MAX_ENTRIES`]
//! is refused as soon as its count is read, and one past [`MAX_EXPANDED`]
//! while its table is expanded, before any expanded entry is checked.
//! Only a `Relative` run of
//! whole words with no `meta` is carried; any other entry is stored as
//! given, and refused if malformed.
//! Every field is little-endian
//! regardless of target byte order, so the slot means the same thing
//! whichever build wrote it.
//!
//! # Canonical form
//!
//! [`parse`] accepts exactly one encoding of any table: entries ascending
//! and disjoint, adjacent entries that could merge already merged, every
//! unused byte zero. A slot has one signature input, and a format that
//! admitted two spellings of the same extent would let bytes outside the
//! described structure vary without the verifier noticing.

use crate::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE, SLOT_VERSION};

/// Offset of the header magic.
pub const OFF_HDR: usize = 0;
/// Offset of the format version.
pub const OFF_VERSION: usize = 16;
/// Offset of the flags word.
pub const OFF_FLAGS: usize = 20;
/// Offset of the entry count.
pub const OFF_COUNT: usize = 24;
/// Offset of the slot's own RVA.
pub const OFF_SLOT_RVA: usize = 28;
/// Offset of the ML-DSA-87 signature.
pub const OFF_SIG: usize = 32;
/// Length of the signature field: an encoded ML-DSA-87 signature.
pub const SIG_LEN: usize = oxicrypt_ml_dsa::ml_dsa_87::SIG_LEN;
/// Offset of the verifying key's fingerprint.
pub const OFF_KEY_ID: usize = OFF_SIG + SIG_LEN;
/// Offset of the image base the file was linked at.
pub const OFF_LINK_BASE: usize = OFF_KEY_ID + 32;
/// Offset of the string table's offset.
pub const OFF_STRTAB_OFF: usize = OFF_LINK_BASE + 8;
/// Offset of the string table's length.
pub const OFF_STRTAB_LEN: usize = OFF_STRTAB_OFF + 4;
/// Offset of the slot's own file offset.
pub const OFF_SLOT_FILE_OFF: usize = OFF_STRTAB_LEN + 4;
/// Offset of the signed file image's length.
pub const OFF_FILE_LEN: usize = OFF_SLOT_FILE_OFF + 4;
/// Offset of the first entry.
pub const OFF_TABLE: usize = OFF_FILE_LEN + 4;
/// Offset of the footer magic.
pub const OFF_FTR: usize = SLOT_SIZE - 16;

/// Size of one entry.
pub const ENTRY_SIZE: usize = 16;

/// Size of a [`BindRecord`]'s fixed header in the string table.
pub const BIND_RECORD_HEADER: usize = 16;

/// The loader flag: the artifact is loaded by bionic rather than glibc.
pub const FLAG_LOADER_BIONIC: u32 = 1;

/// Every flag this verifier understands.
const KNOWN_FLAGS: u32 = FLAG_LOADER_BIONIC;

/// Number of entries the table can hold.
///
/// Whatever space lies between the table's start and the footer, only
/// whole entries fit in it; any remainder is padding, which is why the
/// workspace's integer-division lint is silenced here rather than the
/// expression reshaped.
#[allow(
    clippy::integer_division,
    reason = "capacity in whole entries; the remainder is padding by design"
)]
pub const MAX_ENTRIES: usize = (OFF_FTR - OFF_TABLE) / ENTRY_SIZE;

/// How the verifier treats the bytes an entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    /// The loaded bytes equal the file bytes, and are hashed.
    Plain = 0,
    /// The loader overwrites these bytes without reading them; nothing is
    /// hashed.
    Hole = 1,
    /// 8-byte words the loader rebases; each is hashed as its unslid value.
    Relative = 2,
    /// 8-byte words the loader binds to an import; each must equal the
    /// recorded import's resolution plus its addend, except a Darwin x86_64
    /// resolver stub the export tries lead to.
    Bind = 3,
    /// Initialised writable data, hashed from the image file the loader
    /// reports.
    FileOnly = 4,
}

impl EntryKind {
    /// The kind a wire byte stands for.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Plain),
            1 => Some(Self::Hole),
            2 => Some(Self::Relative),
            3 => Some(Self::Bind),
            4 => Some(Self::FileOnly),
            _ => None,
        }
    }
}

/// One contiguous run of the extent, with its kind, and for a `Plain` run
/// the `Hole` words that follow it.
///
/// The same bytes are addressed two ways: by `rva` for the verifier
/// reading the loaded image, and by `file_off` for the signer reading the
/// file and for the file route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Offset of the run from the image base, as loaded.
    pub rva: u32,
    /// Offset of the same run in the signed file.
    pub file_off: u32,
    /// Length of the run in bytes. Never zero.
    pub len: u32,
    /// How the verifier treats the run.
    pub kind: EntryKind,
    /// Index of the [`BindRecord`] for a `Bind` entry; for a `Plain` entry,
    /// the number of 8-byte `Hole` words after its `len` bytes; zero
    /// otherwise.
    pub meta: u16,
}

impl Entry {
    /// A `Plain` entry over `range`.
    #[must_use]
    pub const fn plain(range: Range) -> Self {
        Self {
            rva: range.rva,
            file_off: range.file_off,
            len: range.len,
            kind: EntryKind::Plain,
            meta: 0,
        }
    }

    /// The bytes of `Hole` words a `Plain` entry carries after its `len`
    /// hashed bytes; zero for every other kind.
    #[must_use]
    pub const fn hole_len(&self) -> u32 {
        match self.kind {
            EntryKind::Plain => (self.meta as u32).saturating_mul(8),
            _ => 0,
        }
    }

    /// The bytes the entry covers: its `len`, and a `Plain` entry's hole.
    #[must_use]
    pub const fn span(&self) -> Option<u32> {
        self.len.checked_add(self.hole_len())
    }

    /// One past the last RVA covered by this entry, or `None` on overflow.
    #[must_use]
    pub const fn rva_end(&self) -> Option<u32> {
        match self.span() {
            Some(span) => self.rva.checked_add(span),
            None => None,
        }
    }

    /// One past the last file offset covered by this entry, or `None` on
    /// overflow.
    #[must_use]
    pub const fn file_end(&self) -> Option<u32> {
        match self.span() {
            Some(span) => self.file_off.checked_add(span),
            None => None,
        }
    }

    /// What `self` and `next` are in canonical form, when `next` continues
    /// `self` in both coordinates and they are not already canonical: two
    /// runs of one kind and `meta` become one; `Plain` bytes and the `Plain`
    /// run after them become one (its hole carried over); `Plain` bytes and
    /// the `Hole` words after them become the `Plain` entry's hole.
    ///
    /// A `Plain` entry carries at most `u16::MAX` hole words. The canonical
    /// form of a longer run is saturated: the `Plain` entry carries exactly
    /// `u16::MAX` words and one `Hole` entry holds the rest, returned as the
    /// second value.
    #[must_use]
    pub fn combined(&self, next: &Self) -> Option<(Self, Option<Self>)> {
        if self.rva_end() != Some(next.rva) || self.file_end() != Some(next.file_off) {
            return None;
        }
        let mut out = *self;
        match (self.kind, next.kind) {
            (EntryKind::Plain, EntryKind::Plain) if self.meta == 0 => {
                out.len = self.len.checked_add(next.len)?;
                out.meta = next.meta;
            }
            (EntryKind::Plain, EntryKind::Hole)
                if next.len.is_multiple_of(8) && self.meta < u16::MAX =>
            {
                let words = next.len >> 3;
                let room = u32::from(u16::MAX.saturating_sub(self.meta));
                if words <= room {
                    out.meta = self.meta.saturating_add(u16::try_from(words).ok()?);
                    return Some((out, None));
                }
                out.meta = u16::MAX;
                let taken = room.checked_mul(8)?;
                let rest = Self {
                    rva: next.rva.checked_add(taken)?,
                    file_off: next.file_off.checked_add(taken)?,
                    len: next.len.checked_sub(taken)?,
                    kind: EntryKind::Hole,
                    meta: 0,
                };
                return Some((out, Some(rest)));
            }
            (EntryKind::Plain, _) => return None,
            (kind, next_kind) if kind == next_kind && self.meta == next.meta => {
                out.len = self.len.checked_add(next.len)?;
            }
            _ => return None,
        }
        Some((out, None))
    }

    /// Whether `self` followed by `next` is not canonical, because
    /// [`Entry::combined`] would rewrite them.
    #[must_use]
    pub fn merges_with(&self, next: &Self) -> bool {
        self.combined(next).is_some()
    }
}

/// A run of bytes addressed both ways, before a kind is assigned.
///
/// The shape a format classifier produces; [`Entry::plain`] turns one into
/// a `Plain` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// Offset of the run from the image base, as loaded.
    pub rva: u32,
    /// Offset of the same run in the signed file.
    pub file_off: u32,
    /// Length of the run in bytes.
    pub len: u32,
}

impl Range {
    /// One past the last RVA covered by this range, or `None` on overflow.
    #[must_use]
    pub fn rva_end(&self) -> Option<u32> {
        self.rva.checked_add(self.len)
    }
}

/// The import a `Bind` entry's words are bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRecord {
    /// The library or DLL the import comes from, as the loader names it.
    pub library: String,
    /// The symbol name with any platform prefix removed; empty for an
    /// ordinal import.
    pub symbol: String,
    /// The PE ordinal for an import by ordinal; zero otherwise.
    pub ordinal: u16,
    /// The value added to the resolved address.
    pub addend: i64,
    /// A weak import, which may legitimately fail to resolve.
    pub weak: bool,
}

/// Record flag: the import is weak.
const RECORD_WEAK: u8 = 1;
/// Record flag: the import is by ordinal.
const RECORD_ORDINAL: u8 = 2;

impl BindRecord {
    /// Appends this record's encoding to `out`.
    ///
    /// `flags u8 | reserved u8 | lib_len u16 | sym_len u16 | ordinal u16 |
    /// addend i64 | library | symbol`.
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SlotDefect> {
        let lib_len = u16::try_from(self.library.len()).map_err(|_| SlotDefect::StringTable)?;
        let sym_len = u16::try_from(self.symbol.len()).map_err(|_| SlotDefect::StringTable)?;
        let mut flags = 0u8;
        if self.weak {
            flags |= RECORD_WEAK;
        }
        if self.symbol.is_empty() {
            flags |= RECORD_ORDINAL;
        }
        out.push(flags);
        out.push(0);
        out.extend_from_slice(&lib_len.to_le_bytes());
        out.extend_from_slice(&sym_len.to_le_bytes());
        out.extend_from_slice(&self.ordinal.to_le_bytes());
        out.extend_from_slice(&self.addend.to_le_bytes());
        out.extend_from_slice(self.library.as_bytes());
        out.extend_from_slice(self.symbol.as_bytes());
        Ok(())
    }
}

/// Decodes a string table into its records, refusing anything that is not
/// exactly a sequence of well-formed records.
fn decode_records(table: &[u8]) -> Result<Vec<BindRecord>, SlotDefect> {
    let mut records = Vec::new();
    let mut at = 0usize;
    while at < table.len() {
        let header = at
            .checked_add(BIND_RECORD_HEADER)
            .and_then(|end| table.get(at..end))
            .ok_or(SlotDefect::StringTable)?;
        let flags = header.first().copied().ok_or(SlotDefect::StringTable)?;
        let reserved = header.get(1).copied().ok_or(SlotDefect::StringTable)?;
        if reserved != 0 || flags & !(RECORD_WEAK | RECORD_ORDINAL) != 0 {
            return Err(SlotDefect::StringTable);
        }
        let lib_len = usize::from(read_u16(header, 2).ok_or(SlotDefect::StringTable)?);
        let sym_len = usize::from(read_u16(header, 4).ok_or(SlotDefect::StringTable)?);
        let ordinal = read_u16(header, 6).ok_or(SlotDefect::StringTable)?;
        let addend = read_u64(header, 8).ok_or(SlotDefect::StringTable)?;
        let lib_start = at
            .checked_add(BIND_RECORD_HEADER)
            .ok_or(SlotDefect::StringTable)?;
        let sym_start = lib_start
            .checked_add(lib_len)
            .ok_or(SlotDefect::StringTable)?;
        let end = sym_start
            .checked_add(sym_len)
            .ok_or(SlotDefect::StringTable)?;
        let library = table
            .get(lib_start..sym_start)
            .and_then(|b| core::str::from_utf8(b).ok())
            .ok_or(SlotDefect::StringTable)?;
        let symbol = table
            .get(sym_start..end)
            .and_then(|b| core::str::from_utf8(b).ok())
            .ok_or(SlotDefect::StringTable)?;
        // No loader accepts a name with an interior NUL, so a record holding
        // one is not one the signer wrote.
        if library.contains('\0') || symbol.contains('\0') {
            return Err(SlotDefect::StringTable);
        }
        let by_ordinal = flags & RECORD_ORDINAL != 0;
        // An import is by name or by ordinal, never both and never neither,
        // and it always names its library.
        if library.is_empty() || by_ordinal != symbol.is_empty() || (!by_ordinal && ordinal != 0) {
            return Err(SlotDefect::StringTable);
        }
        records.push(BindRecord {
            library: library.to_owned(),
            symbol: symbol.to_owned(),
            ordinal,
            addend: i64::from_le_bytes(addend.to_le_bytes()),
            weak: flags & RECORD_WEAK != 0,
        });
        at = end;
    }
    Ok(records)
}

/// Everything the signer writes into a slot except the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotFields {
    /// Loader flags ([`FLAG_LOADER_BIONIC`]).
    pub flags: u32,
    /// Offset of the slot from the image base.
    pub slot_rva: u32,
    /// SHA-256 of the verifying key the signature was made for.
    pub key_id: [u8; 32],
    /// The image base the file was linked at; the slide is the load base
    /// minus this.
    pub link_base: u64,
    /// File offset of the slot.
    pub slot_file_off: u32,
    /// Length of the signed file image.
    pub file_len: u32,
    /// The extent, in canonical form.
    pub entries: Vec<Entry>,
    /// The imports the `Bind` entries index.
    pub records: Vec<BindRecord>,
}

/// A parsed, validated slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotImage {
    /// Format version. Always [`SLOT_VERSION`] once parsed.
    pub version: u32,
    /// Everything the signature covers in the slot, decoded.
    pub fields: SlotFields,
    /// The ML-DSA-87 signature, as FIPS 204 `sigEncode` writes it.
    pub signature: [u8; SIG_LEN],
}

/// Why a slot was refused.
///
/// Each variant names a distinct defect rather than collapsing to "bad
/// slot", because they mean different things: a missing magic says the
/// slot was overwritten or truncated, an unsupported version says the slot
/// is not in the one format this verifier checks (version 0 is what the
/// unsigned template and a slot zeroed in place carry), a key mismatch says
/// it was signed for a different verifying key, and a structural defect
/// says the extent cannot be honoured.
///
/// An index counts the expanded entries, except in [`SlotDefect::EmptyEntry`],
/// in [`SlotDefect::MalformedEntry`] for an unknown kind or a misplaced
/// `run` byte, in [`SlotDefect::EntryOverflow`] from expanding a stored
/// entry, and in [`SlotDefect::NonMaximal`] when the stored table is not
/// the one packing of its entries, which count the entries as the table
/// stores them. [`SlotDefect::RecordOrder`] for a record no entry uses
/// carries the stored entry count rather than an index.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotDefect {
    /// The acquired bytes are not [`SLOT_SIZE`] long.
    WrongSize(usize),
    /// The header magic is absent.
    HeaderMagic,
    /// The footer magic is absent.
    FooterMagic,
    /// The version is not [`SLOT_VERSION`]. Zero is what the unsigned
    /// template carries, and what a signed slot zeroed in place carries
    /// too, so it does not show that the artifact was never signed.
    UnsupportedVersion(u32),
    /// The flags word sets a bit this verifier does not implement.
    UnknownFlags(u32),
    /// The entry count is zero: an extent covering nothing would make the
    /// test vacuous.
    NoEntries,
    /// The entry count exceeds [`MAX_ENTRIES`], the entries expand past
    /// [`MAX_EXPANDED`], or the entry table runs past the footer. [`encode`]
    /// also returns it when the entry table and the string table together
    /// do not fit before the footer; [`parse`] reports a string table past
    /// the footer as [`SlotDefect::StringTable`].
    TooManyEntries(u32),
    /// The entry at this index has zero length.
    EmptyEntry(u32),
    /// The entry at this index overflows the RVA or file-offset space.
    EntryOverflow(u32),
    /// The entry at this index starts before the previous entry ends, so
    /// the table is unordered or self-overlapping.
    Unordered(u32),
    /// The entry at this index covers part of the slot. The slot is
    /// signed through its own header, never as an entry.
    OverlapsSlot(u32),
    /// The entry at this index falls outside the image being hashed.
    EntryOutOfBounds(u32),
    /// The entry at this index has an unknown kind, a `run` byte on an
    /// entry that carries no words, a `meta` value its kind does not use,
    /// or a length its kind does not allow.
    MalformedEntry(u32),
    /// The entry at this index continues the previous one with the same
    /// kind and `meta`, or the stored table is not the one packing of its
    /// entries; the canonical table merges them.
    NonMaximal(u32),
    /// The `Bind` entry at this index names a record the string table does
    /// not hold.
    BindRecordOutOfRange(u32),
    /// The string table is misplaced or is not a sequence of well-formed
    /// records.
    StringTable,
    /// A byte outside every field, the table and the string table is not
    /// zero.
    NonZeroPadding,
    /// The entry at this index ends past `file_len`.
    FileLenTooShort(u32),
    /// The slot's `key_id` is not the fingerprint of the key this module
    /// embeds: the artifact was signed for a different verifying key.
    KeyMismatch,
    /// The `Bind` entry at this index names an import that did not resolve
    /// and is not weak.
    UnresolvedImport(u32),
    /// The slot is exactly the unsigned template the build emits. Whether
    /// the artifact was never signed or a signed slot was overwritten with
    /// the template cannot be told from the slot, so this says only what
    /// the bytes are.
    Unsigned,
    /// The `Bind` entry at this index records an import this platform
    /// cannot resolve the way its loader binds. The signer writes bound
    /// imports only for platforms whose loader binds that way.
    BindUnsupported(u32),
    /// The image file is not the length the slot records, which is checked
    /// before the slot's signature can be.
    FileLenMismatch,
    /// The slot's recorded RVA exceeds the address the slot was found at,
    /// so no load base can be derived from the pair.
    SlotRvaTooLarge,
    /// The embedded verifying-key record is absent or its magics are
    /// wrong.
    KeyRecord,
    /// The entries' payload is larger than the file image the slot
    /// describes.
    ExtentTooLarge,
    /// The slot itself does not lie inside the image it describes: it ends
    /// past `[0, file_len)` of the file, or its address range overflows the
    /// address space.
    SlotOutsideImage,
    /// The `Bind` entry at this index uses a record before an earlier one
    /// was first used, or a record is left unused: the string table is not
    /// in its one canonical order.
    RecordOrder(u32),
}

impl SlotDefect {
    /// Whether the slot is byte-identical to the unsigned template the
    /// build emits. That is what an unsigned build carries, and also what an
    /// attacker writes over a signed slot, so it does not establish that the
    /// artifact was never signed. The slot is the module's own static, so a
    /// missing magic or an earlier version is damage, and every other defect is damage to a signed slot or to the
    /// image it describes.
    #[must_use]
    pub const fn is_unsigned(&self) -> bool {
        matches!(self, Self::Unsigned)
    }
}

/// Whether `bytes` is the unsigned template a build emits: the two magics
/// and zeros between them.
pub(crate) fn is_unsigned_template(bytes: &[u8]) -> bool {
    bytes.len() == SLOT_SIZE
        && bytes.get(..16) == Some(SLOT_HEADER_MAGIC.as_slice())
        && bytes.get(OFF_FTR..) == Some(SLOT_FOOTER_MAGIC.as_slice())
        && bytes
            .get(16..OFF_FTR)
            .is_some_and(|body| body.iter().all(|&b| b == 0))
}

impl core::fmt::Display for SlotDefect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongSize(n) => write!(f, "slot is {n} bytes, expected {SLOT_SIZE}"),
            Self::HeaderMagic => f.write_str("header magic absent: the slot was overwritten"),
            Self::FooterMagic => {
                f.write_str("footer magic absent: the slot is truncated or overwritten")
            }
            Self::UnsupportedVersion(0) => {
                f.write_str("slot version 0: the slot holds no signature")
            }
            Self::UnsupportedVersion(v) => write!(
                f,
                "slot version {v} is not supported (this module requires version {SLOT_VERSION})"
            ),
            Self::UnknownFlags(x) => write!(f, "slot declares unknown flags {x:#010x}"),
            Self::NoEntries => f.write_str("slot lists no entries: the extent covers nothing"),
            Self::TooManyEntries(n) => {
                write!(
                    f,
                    "slot lists {n} entries, more than the table can hold or expand to"
                )
            }
            Self::EmptyEntry(i) => write!(f, "entry {i} has zero length"),
            Self::EntryOverflow(i) => write!(f, "entry {i} overflows the address space"),
            Self::Unordered(i) => write!(
                f,
                "entry {i} starts before entry {} ends",
                i.saturating_sub(1)
            ),
            Self::OverlapsSlot(i) => write!(f, "entry {i} covers the integrity slot"),
            Self::EntryOutOfBounds(i) => write!(f, "entry {i} falls outside the image"),
            Self::MalformedEntry(i) => write!(f, "entry {i} is malformed for its kind"),
            Self::NonMaximal(i) => {
                write!(
                    f,
                    "entry {i} continues the previous entry and should be merged with it"
                )
            }
            Self::BindRecordOutOfRange(i) => {
                write!(
                    f,
                    "entry {i} names an import the string table does not hold"
                )
            }
            Self::StringTable => f.write_str("the string table is misplaced or malformed"),
            Self::NonZeroPadding => f.write_str("an unused slot byte is not zero"),
            Self::FileLenTooShort(i) => {
                write!(f, "entry {i} ends past the recorded file length")
            }
            Self::KeyMismatch => f.write_str(
                "the slot was signed for a different verifying key than the one this module embeds",
            ),
            Self::UnresolvedImport(i) => {
                write!(
                    f,
                    "entry {i} binds an import that did not resolve and is not weak"
                )
            }
            Self::Unsigned => f.write_str("the slot is the unsigned template the build emits"),
            Self::BindUnsupported(i) => write!(
                f,
                "entry {i} records a bound import this platform's loader never binds"
            ),
            Self::FileLenMismatch => {
                f.write_str("the image file is not the length the slot records")
            }
            Self::SlotRvaTooLarge => {
                f.write_str("the slot's recorded RVA exceeds its own address; no load base follows")
            }
            Self::KeyRecord => {
                f.write_str("the embedded verifying-key record is absent or malformed")
            }
            Self::ExtentTooLarge => {
                f.write_str("the entries cover more bytes than the file image the slot describes")
            }
            Self::SlotOutsideImage => {
                f.write_str("the slot does not lie inside the image it describes")
            }
            Self::RecordOrder(i) => write!(
                f,
                "entry {i} breaks the canonical order of the string table's import records"
            ),
        }
    }
}

impl std::error::Error for SlotDefect {}

fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let arr: [u8; 2] = bytes.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let arr: [u8; 4] = bytes.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn read_u64(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let arr: [u8; 8] = bytes.get(off..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

/// Copies `src` to `out[off..]`. Silently does nothing if it does not fit,
/// which [`encode`] rules out by checking capacity first.
fn put(out: &mut [u8], off: usize, src: &[u8]) {
    if let Some(end) = off.checked_add(src.len())
        && let Some(slice) = out.get_mut(off..end)
    {
        slice.copy_from_slice(src);
    }
}

/// Merges adjacent entries that continue each other into canonical form.
///
/// `entries` must be ascending. Classifiers emit one entry per region; two
/// regions that abut in both coordinates with the same kind are one entry
/// on the wire.
#[must_use]
pub fn merge(entries: &[Entry]) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::with_capacity(entries.len());
    for e in entries {
        if let Some(last) = out.last_mut()
            && let Some((merged, rest)) = last.combined(e)
        {
            *last = merged;
            out.extend(rest);
            continue;
        }
        out.push(*e);
    }
    out
}

/// Wire byte 13 of a `Plain` entry: set when the words its `meta` counts
/// are `Relative` rather than `Hole`.
const RUN_RELATIVE: u8 = 0x80;
/// The low seven bits of wire byte 13: how many further periods repeat
/// the entry's first.
const RUN_REPEATS: u8 = 0x7f;

/// The most entries a table may expand to. A slot that expands to more is
/// refused while its table is expanded, before any expanded entry is
/// checked.
pub const MAX_EXPANDED: usize = 1 << 16;

/// One entry as the table stores it.
///
/// Every kind but `Plain` is stored as its [`Entry`], byte 13 zero. A
/// `Plain` entry stores one period, `len` bytes then `meta` words, and
/// byte 13: bit 7 makes those words `Relative` (otherwise `Hole`), and
/// bits 0–6 count further identical periods, 0 to 127, that follow it
/// contiguously, so one stored entry stands for at most 128 periods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Wire {
    rva: u32,
    file_off: u32,
    len: u32,
    kind: EntryKind,
    run: u8,
    meta: u16,
}

impl Wire {
    const fn stored(e: &Entry) -> Self {
        Self {
            rva: e.rva,
            file_off: e.file_off,
            len: e.len,
            kind: e.kind,
            run: 0,
            meta: e.meta,
        }
    }

    /// Bytes one period covers.
    fn period(&self) -> Option<u32> {
        self.len.checked_add(u32::from(self.meta).checked_mul(8)?)
    }

    /// Where the entry's last period ends, in both coordinates.
    fn ends(&self) -> Option<(u32, u32)> {
        let all = self
            .period()?
            .checked_mul(u32::from(self.run & RUN_REPEATS).checked_add(1)?)?;
        Some((self.rva.checked_add(all)?, self.file_off.checked_add(all)?))
    }
}

/// Packs a canonical table into the stored form, deterministically: a
/// `Plain` entry with no hole words takes the `Relative` run directly after
/// it as its words, and each period identical to the stored entry before it
/// and contiguous with it becomes one of that entry's repeats. A table with
/// no such runs is stored entry for entry.
fn pack(entries: &[Entry]) -> Vec<Wire> {
    let mut out: Vec<Wire> = Vec::with_capacity(entries.len());
    let mut i = 0usize;
    while let Some(e) = entries.get(i) {
        i = i.saturating_add(1);
        let mut unit = Wire::stored(e);
        if e.kind == EntryKind::Plain
            && e.meta == 0
            && let Some(next) = entries.get(i)
            && next.kind == EntryKind::Relative
            && next.meta == 0
            && next.len != 0
            && next.len % 8 == 0
            && e.rva.checked_add(e.len) == Some(next.rva)
            && e.file_off.checked_add(e.len) == Some(next.file_off)
            && let Ok(words) = u16::try_from(next.len >> 3)
        {
            unit.meta = words;
            unit.run = RUN_RELATIVE;
            i = i.saturating_add(1);
        }
        if let Some(last) = out.last_mut()
            && unit.kind == EntryKind::Plain
            && unit.meta != 0
            && last.kind == EntryKind::Plain
            && (last.len, last.meta, last.run & RUN_RELATIVE)
                == (unit.len, unit.meta, unit.run & RUN_RELATIVE)
            && last.run & RUN_REPEATS < RUN_REPEATS
            && last.ends() == Some((unit.rva, unit.file_off))
        {
            last.run = last.run.saturating_add(1);
            continue;
        }
        out.push(unit);
    }
    out
}

/// Appends the entries a stored entry stands for; `None` on overflow.
fn expand(wire: &Wire, out: &mut Vec<Entry>) -> Option<()> {
    if wire.kind != EntryKind::Plain || wire.run == 0 {
        out.push(Entry {
            rva: wire.rva,
            file_off: wire.file_off,
            len: wire.len,
            kind: wire.kind,
            meta: wire.meta,
        });
        return Some(());
    }
    let relative = wire.run & RUN_RELATIVE != 0;
    let period = wire.period()?;
    for k in 0..=u32::from(wire.run & RUN_REPEATS) {
        let step = period.checked_mul(k)?;
        let rva = wire.rva.checked_add(step)?;
        let file_off = wire.file_off.checked_add(step)?;
        out.push(Entry {
            rva,
            file_off,
            len: wire.len,
            kind: EntryKind::Plain,
            meta: if relative { 0 } else { wire.meta },
        });
        if relative {
            out.push(Entry {
                rva: rva.checked_add(wire.len)?,
                file_off: file_off.checked_add(wire.len)?,
                len: u32::from(wire.meta).checked_mul(8)?,
                kind: EntryKind::Relative,
                meta: 0,
            });
        }
    }
    Some(())
}

/// How many bytes `records` take as a slot's string table, encoded exactly
/// as [`encode`] writes them.
///
/// # Errors
///
/// [`SlotDefect::StringTable`] when a record's name is too long to encode.
pub fn string_table_len(records: &[BindRecord]) -> Result<usize, SlotDefect> {
    let mut table = Vec::new();
    for record in records {
        record.encode_into(&mut table)?;
    }
    Ok(table.len())
}

/// How many stored entries `entries`, a canonical table, takes in a slot:
/// the number the table's capacity, [`MAX_ENTRIES`], bounds.
#[must_use]
pub fn table_len(entries: &[Entry]) -> usize {
    pack(entries).len()
}

/// Serialises a slot, with `signature` in its field.
///
/// Checks only that the table and the string table fit: full structural
/// validation lives in [`parse`], and the signer runs `parse` over its own
/// output as a self-check, so there is one implementation of what "valid"
/// means rather than two that can drift.
///
/// # Errors
///
/// Returns [`SlotDefect::TooManyEntries`] when the entries and the string
/// table do not fit between the header and the footer, and
/// [`SlotDefect::StringTable`] when a record's name is too long to encode.
pub fn encode(fields: &SlotFields, signature: &[u8; SIG_LEN]) -> Result<Vec<u8>, SlotDefect> {
    let wires = pack(&fields.entries);
    let count = wires.len();
    let too_many = || SlotDefect::TooManyEntries(u32::try_from(count).unwrap_or(u32::MAX));
    let mut strtab = Vec::new();
    for record in &fields.records {
        record.encode_into(&mut strtab)?;
    }
    let table_end = count
        .checked_mul(ENTRY_SIZE)
        .and_then(|n| n.checked_add(OFF_TABLE))
        .ok_or_else(too_many)?;
    let strtab_end = table_end.checked_add(strtab.len()).ok_or_else(too_many)?;
    if strtab_end > OFF_FTR {
        return Err(too_many());
    }
    let (strtab_off, strtab_len) = if strtab.is_empty() {
        (0u32, 0u32)
    } else {
        (
            u32::try_from(table_end).map_err(|_| too_many())?,
            u32::try_from(strtab.len()).map_err(|_| too_many())?,
        )
    };

    let mut out = vec![0u8; SLOT_SIZE];
    put(&mut out, OFF_HDR, &SLOT_HEADER_MAGIC);
    put(&mut out, OFF_FTR, &SLOT_FOOTER_MAGIC);
    put(&mut out, OFF_VERSION, &SLOT_VERSION.to_le_bytes());
    put(&mut out, OFF_FLAGS, &fields.flags.to_le_bytes());
    put(
        &mut out,
        OFF_COUNT,
        &u32::try_from(count).map_err(|_| too_many())?.to_le_bytes(),
    );
    put(&mut out, OFF_SLOT_RVA, &fields.slot_rva.to_le_bytes());
    put(&mut out, OFF_SIG, signature);
    put(&mut out, OFF_KEY_ID, &fields.key_id);
    put(&mut out, OFF_LINK_BASE, &fields.link_base.to_le_bytes());
    put(&mut out, OFF_STRTAB_OFF, &strtab_off.to_le_bytes());
    put(&mut out, OFF_STRTAB_LEN, &strtab_len.to_le_bytes());
    put(
        &mut out,
        OFF_SLOT_FILE_OFF,
        &fields.slot_file_off.to_le_bytes(),
    );
    put(&mut out, OFF_FILE_LEN, &fields.file_len.to_le_bytes());
    for (i, e) in wires.iter().enumerate() {
        let base = i
            .checked_mul(ENTRY_SIZE)
            .and_then(|n| n.checked_add(OFF_TABLE))
            .ok_or_else(too_many)?;
        let mut raw = [0u8; ENTRY_SIZE];
        put(&mut raw, 0, &e.rva.to_le_bytes());
        put(&mut raw, 4, &e.file_off.to_le_bytes());
        put(&mut raw, 8, &e.len.to_le_bytes());
        put(&mut raw, 12, &[e.kind as u8, e.run]);
        put(&mut raw, 14, &e.meta.to_le_bytes());
        put(&mut out, base, &raw);
    }
    put(&mut out, table_end, &strtab);
    Ok(out)
}

/// Whether every byte of `bytes[start..end]` is zero. An empty or
/// out-of-range span is vacuously zero only when empty.
fn zero(bytes: &[u8], start: usize, end: usize) -> bool {
    if start >= end {
        return true;
    }
    bytes
        .get(start..end)
        .is_some_and(|s| s.iter().all(|&b| b == 0))
}

/// Parses and fully validates a slot.
///
/// Structural only: whether the slot's `key_id` matches the module's key,
/// and whether the signature verifies, are the verifier's checks.
///
/// # Errors
///
/// Returns the [`SlotDefect`] describing the first problem found.
#[allow(
    clippy::too_many_lines,
    reason = "one linear pass over the wire format, each check beside the field it reads"
)]
pub fn parse(bytes: &[u8]) -> Result<SlotImage, SlotDefect> {
    let wrong = || SlotDefect::WrongSize(bytes.len());
    if bytes.len() != SLOT_SIZE {
        return Err(wrong());
    }
    if bytes.get(OFF_HDR..OFF_HDR.saturating_add(16)) != Some(SLOT_HEADER_MAGIC.as_slice()) {
        return Err(SlotDefect::HeaderMagic);
    }
    if bytes.get(OFF_FTR..SLOT_SIZE) != Some(SLOT_FOOTER_MAGIC.as_slice()) {
        return Err(SlotDefect::FooterMagic);
    }
    let version = read_u32(bytes, OFF_VERSION).ok_or_else(wrong)?;
    if version != SLOT_VERSION {
        return Err(SlotDefect::UnsupportedVersion(version));
    }
    let flags = read_u32(bytes, OFF_FLAGS).ok_or_else(wrong)?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(SlotDefect::UnknownFlags(flags));
    }
    let count = read_u32(bytes, OFF_COUNT).ok_or_else(wrong)?;
    if count == 0 {
        return Err(SlotDefect::NoEntries);
    }
    let count_usize = usize::try_from(count).unwrap_or(usize::MAX);
    if count_usize > MAX_ENTRIES {
        return Err(SlotDefect::TooManyEntries(count));
    }
    let slot_rva = read_u32(bytes, OFF_SLOT_RVA).ok_or_else(wrong)?;
    let mut signature = [0u8; SIG_LEN];
    signature.copy_from_slice(
        bytes
            .get(OFF_SIG..OFF_SIG.saturating_add(SIG_LEN))
            .ok_or_else(wrong)?,
    );
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(
        bytes
            .get(OFF_KEY_ID..OFF_KEY_ID.saturating_add(32))
            .ok_or_else(wrong)?,
    );
    let link_base = read_u64(bytes, OFF_LINK_BASE).ok_or_else(wrong)?;
    let strtab_off = read_u32(bytes, OFF_STRTAB_OFF).ok_or_else(wrong)?;
    let strtab_len = read_u32(bytes, OFF_STRTAB_LEN).ok_or_else(wrong)?;
    let slot_file_off = read_u32(bytes, OFF_SLOT_FILE_OFF).ok_or_else(wrong)?;
    let file_len = read_u32(bytes, OFF_FILE_LEN).ok_or_else(wrong)?;

    // The table, then the string table, then zeros, then the footer.
    let table_end = count_usize
        .checked_mul(ENTRY_SIZE)
        .and_then(|n| n.checked_add(OFF_TABLE))
        .ok_or(SlotDefect::TooManyEntries(count))?;
    let strtab_off = usize::try_from(strtab_off).map_err(|_| SlotDefect::StringTable)?;
    let strtab_len = usize::try_from(strtab_len).map_err(|_| SlotDefect::StringTable)?;
    let (strtab_start, strtab_end) = if strtab_len == 0 {
        if strtab_off != 0 {
            return Err(SlotDefect::StringTable);
        }
        (table_end, table_end)
    } else {
        let end = strtab_off
            .checked_add(strtab_len)
            .ok_or(SlotDefect::StringTable)?;
        // The string table sits immediately after the entry table, so a
        // slot has one placement of its records.
        if strtab_off != table_end || end > OFF_FTR {
            return Err(SlotDefect::StringTable);
        }
        (strtab_off, end)
    };
    if table_end > OFF_FTR {
        return Err(SlotDefect::TooManyEntries(count));
    }
    if !zero(bytes, table_end, strtab_start) || !zero(bytes, strtab_end, OFF_FTR) {
        return Err(SlotDefect::NonZeroPadding);
    }
    let records = decode_records(
        bytes
            .get(strtab_start..strtab_end)
            .ok_or(SlotDefect::StringTable)?,
    )?;
    if records
        .iter()
        .enumerate()
        .any(|(i, r)| records.iter().skip(i.saturating_add(1)).any(|q| q == r))
    {
        return Err(SlotDefect::StringTable);
    }
    let slot_file_end = slot_file_off
        .checked_add(u32::try_from(SLOT_SIZE).unwrap_or(u32::MAX))
        .ok_or(SlotDefect::SlotOutsideImage)?;
    if slot_file_end > file_len {
        return Err(SlotDefect::SlotOutsideImage);
    }
    let mut next_record = 0usize;
    let mut payload = 0u64;

    let slot_end = slot_rva
        .checked_add(u32::try_from(SLOT_SIZE).unwrap_or(u32::MAX))
        .ok_or(SlotDefect::SlotOutsideImage)?;

    // The table as stored, and the entries it expands to.
    let mut wires: Vec<Wire> = Vec::with_capacity(count_usize);
    let mut expanded: Vec<Entry> = Vec::with_capacity(count_usize);
    for i in 0..count_usize {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let base = i
            .checked_mul(ENTRY_SIZE)
            .and_then(|n| n.checked_add(OFF_TABLE))
            .ok_or_else(wrong)?;
        let raw = base
            .checked_add(ENTRY_SIZE)
            .and_then(|end| bytes.get(base..end))
            .ok_or_else(wrong)?;
        let len = read_u32(raw, 8).ok_or_else(wrong)?;
        let kind_byte = raw.get(12).copied().ok_or_else(wrong)?;
        let run = raw.get(13).copied().ok_or_else(wrong)?;
        let meta = read_u16(raw, 14).ok_or_else(wrong)?;
        let kind = EntryKind::from_byte(kind_byte).ok_or(SlotDefect::MalformedEntry(index))?;
        if len == 0 {
            return Err(SlotDefect::EmptyEntry(index));
        }
        // Only a `Plain` entry carrying words has a run byte.
        if run != 0 && (kind != EntryKind::Plain || meta == 0) {
            return Err(SlotDefect::MalformedEntry(index));
        }
        let wire = Wire {
            rva: read_u32(raw, 0).ok_or_else(wrong)?,
            file_off: read_u32(raw, 4).ok_or_else(wrong)?,
            len,
            kind,
            run,
            meta,
        };
        expand(&wire, &mut expanded).ok_or(SlotDefect::EntryOverflow(index))?;
        if expanded.len() > MAX_EXPANDED {
            return Err(SlotDefect::TooManyEntries(count));
        }
        wires.push(wire);
    }

    let mut entries: Vec<Entry> = Vec::with_capacity(expanded.len());
    for (i, entry) in expanded.into_iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let Entry {
            rva,
            file_off,
            len,
            kind,
            meta,
        } = entry;
        let word_aligned = len % 8 == 0;
        let shape_ok = match kind {
            EntryKind::Plain => true,
            EntryKind::Hole | EntryKind::FileOnly => meta == 0,
            EntryKind::Relative => meta == 0 && word_aligned,
            EntryKind::Bind => word_aligned,
        };
        if !shape_ok {
            return Err(SlotDefect::MalformedEntry(index));
        }
        if kind == EntryKind::Bind {
            let used = usize::from(meta);
            if used >= records.len() {
                return Err(SlotDefect::BindRecordOutOfRange(index));
            }
            // Records appear in the order of their first use.
            if used == next_record {
                next_record = next_record.saturating_add(1);
            } else if used > next_record {
                return Err(SlotDefect::RecordOrder(index));
            }
        }
        if matches!(
            kind,
            EntryKind::Plain | EntryKind::Relative | EntryKind::FileOnly
        ) {
            payload = payload.saturating_add(u64::from(len));
            if payload > u64::from(file_len) {
                return Err(SlotDefect::ExtentTooLarge);
            }
        }
        let end = entry.rva_end().ok_or(SlotDefect::EntryOverflow(index))?;
        let file_end = entry.file_end().ok_or(SlotDefect::EntryOverflow(index))?;
        if file_end > file_len {
            return Err(SlotDefect::FileLenTooShort(index));
        }
        if (rva < slot_end && end > slot_rva)
            || (file_off < slot_file_end && file_end > slot_file_off)
        {
            return Err(SlotDefect::OverlapsSlot(index));
        }
        if let Some(prev) = entries.last() {
            if rva < prev.rva_end().unwrap_or(u32::MAX) {
                return Err(SlotDefect::Unordered(index));
            }
            if prev.merges_with(&entry) {
                return Err(SlotDefect::NonMaximal(index));
            }
        }
        entries.push(entry);
    }
    if next_record != records.len() {
        return Err(SlotDefect::RecordOrder(
            u32::try_from(count_usize).unwrap_or(u32::MAX),
        ));
    }
    // One stored spelling of the expanded table: the one `encode` packs.
    let packed = pack(&entries);
    if packed != wires {
        let at = packed
            .iter()
            .zip(&wires)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| packed.len().min(wires.len()));
        return Err(SlotDefect::NonMaximal(
            u32::try_from(at).unwrap_or(u32::MAX),
        ));
    }

    Ok(SlotImage {
        version,
        fields: SlotFields {
            flags,
            slot_rva,
            key_id,
            link_base,
            slot_file_off,
            file_len,
            entries,
            records,
        },
        signature,
    })
}

/// The slot bytes the signature covers: everything but the signature
/// field.
///
/// # Errors
///
/// Returns [`SlotDefect::WrongSize`] when `slot` is not [`SLOT_SIZE`]
/// bytes.
pub fn signed_header(slot: &[u8]) -> Result<Vec<u8>, SlotDefect> {
    if slot.len() != SLOT_SIZE {
        return Err(SlotDefect::WrongSize(slot.len()));
    }
    let head = slot
        .get(..OFF_SIG)
        .ok_or(SlotDefect::WrongSize(slot.len()))?;
    let tail = slot
        .get(OFF_SIG.saturating_add(SIG_LEN)..)
        .ok_or(SlotDefect::WrongSize(slot.len()))?;
    let mut out = Vec::with_capacity(SLOT_SIZE.saturating_sub(SIG_LEN));
    out.extend_from_slice(head);
    out.extend_from_slice(tail);
    Ok(out)
}

/// Total number of bytes the entries cover, of every kind and including
/// the holes `Plain` entries carry, or `None` on overflow.
#[must_use]
pub fn extent_len(entries: &[Entry]) -> Option<u64> {
    entries
        .iter()
        .try_fold(0u64, |acc, e| acc.checked_add(u64::from(e.span()?)))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::{
        BindRecord, Entry, EntryKind, MAX_ENTRIES, OFF_FLAGS, OFF_FTR, OFF_KEY_ID, OFF_SIG,
        OFF_TABLE, OFF_VERSION, SIG_LEN, SlotDefect, SlotFields, encode, merge, parse,
        signed_header,
    };
    use crate::{SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE, SLOT_VERSION};

    fn entry(rva: u32, len: u32, kind: EntryKind, meta: u16) -> Entry {
        Entry {
            rva,
            file_off: rva,
            len,
            kind,
            meta,
        }
    }

    fn sample() -> SlotFields {
        SlotFields {
            flags: 0,
            slot_rva: 0x9_0000,
            key_id: [0x11; 32],
            link_base: 0x1000,
            slot_file_off: 0x9_0000,
            file_len: 0x20_0000,
            entries: vec![
                entry(0, 64, EntryKind::Plain, 0),
                entry(64, 16, EntryKind::Relative, 0),
                entry(80, 8, EntryKind::Bind, 0),
                entry(88, 8, EntryKind::Hole, 0),
                entry(0x1000, 0x100, EntryKind::FileOnly, 0),
            ],
            records: vec![BindRecord {
                library: "libSystem.B.dylib".to_owned(),
                symbol: "malloc".to_owned(),
                ordinal: 0,
                addend: -16,
                weak: true,
            }],
        }
    }

    #[test]
    fn a_slot_round_trips_through_encode_and_parse() {
        let fields = sample();
        let sig = [0x5a; SIG_LEN];
        let bytes = encode(&fields, &sig).unwrap();
        assert_eq!(bytes.len(), SLOT_SIZE);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.version, SLOT_VERSION);
        assert_eq!(parsed.signature, sig);
        assert_eq!(parsed.fields, fields);
    }

    /// The signed header is the whole slot except the signature field, so a
    /// change to the signature does not move it and a change anywhere else
    /// does.
    #[test]
    fn the_signed_header_omits_exactly_the_signature() {
        let bytes = encode(&sample(), &[0; SIG_LEN]).unwrap();
        let header = signed_header(&bytes).unwrap();
        assert_eq!(header.len(), SLOT_SIZE - SIG_LEN);
        let mut resigned = bytes.clone();
        resigned[OFF_SIG] ^= 1;
        assert_eq!(signed_header(&resigned).unwrap(), header);
        let mut edited = bytes.clone();
        edited[OFF_KEY_ID] ^= 1;
        assert_ne!(signed_header(&edited).unwrap(), header);
    }

    /// Versions 1 to 3, and an unsigned slot, are refused by number.
    #[test]
    fn earlier_versions_and_unsigned_slots_are_refused() {
        for v in [0u32, 1, 2, 3] {
            let mut bytes = encode(&sample(), &[0; SIG_LEN]).unwrap();
            bytes[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&v.to_le_bytes());
            assert_eq!(parse(&bytes), Err(SlotDefect::UnsupportedVersion(v)));
        }
        let mut unsigned = vec![0u8; SLOT_SIZE];
        unsigned[..16].copy_from_slice(&SLOT_HEADER_MAGIC);
        unsigned[OFF_FTR..].copy_from_slice(&SLOT_FOOTER_MAGIC);
        assert_eq!(parse(&unsigned), Err(SlotDefect::UnsupportedVersion(0)));
    }

    /// A scanner that expects a 16 KiB slot finds no slot in this one:
    /// nothing places the footer magic 16,368 bytes after the header.
    #[test]
    fn a_scanner_for_a_16_kib_slot_finds_none() {
        const SMALL_SLOT_SIZE: usize = 16_384;
        let bytes = encode(&sample(), &[0; SIG_LEN]).unwrap();
        let found = (0..=bytes.len() - SMALL_SLOT_SIZE).any(|i| {
            bytes[i..i + 16] == SLOT_HEADER_MAGIC
                && bytes[i + SMALL_SLOT_SIZE - 16..i + SMALL_SLOT_SIZE] == SLOT_FOOTER_MAGIC
        });
        assert!(!found);
        // Control: the footer magic is where this slot's own size puts it.
        assert_eq!(bytes[OFF_FTR..], SLOT_FOOTER_MAGIC);
    }

    #[test]
    fn unknown_flags_are_refused_and_the_loader_flag_is_not() {
        let mut fields = sample();
        fields.flags = super::FLAG_LOADER_BIONIC;
        assert!(parse(&encode(&fields, &[0; SIG_LEN]).unwrap()).is_ok());
        let mut bytes = encode(&sample(), &[0; SIG_LEN]).unwrap();
        bytes[OFF_FLAGS] = 0x02;
        assert_eq!(parse(&bytes), Err(SlotDefect::UnknownFlags(2)));
    }

    /// Two entries that continue each other must be one entry; the
    /// signer's merge produces that form.
    #[test]
    fn a_non_maximal_table_is_refused_and_merge_makes_it_maximal() {
        let mut fields = sample();
        fields.entries = vec![
            entry(0, 32, EntryKind::Plain, 0),
            entry(32, 32, EntryKind::Plain, 0),
        ];
        let bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        assert_eq!(parse(&bytes), Err(SlotDefect::NonMaximal(1)));
        let merged = merge(&fields.entries);
        assert_eq!(merged, vec![entry(0, 64, EntryKind::Plain, 0)]);
        // Control: contiguous entries of different kinds are not merged.
        let mixed = [
            entry(0, 32, EntryKind::Plain, 0),
            entry(32, 8, EntryKind::Relative, 0),
        ];
        assert_eq!(merge(&mixed).len(), 2);
    }

    #[test]
    fn unordered_and_overlapping_entries_are_refused() {
        let mut fields = sample();
        fields.entries = vec![
            entry(0, 64, EntryKind::Plain, 0),
            entry(32, 8, EntryKind::Relative, 0),
        ];
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::Unordered(1))
        );
    }

    /// The slot is signed through its header, never as an entry.
    #[test]
    fn an_entry_covering_the_slot_is_refused() {
        let mut fields = sample();
        fields.entries = vec![entry(fields.slot_rva - 8, 16, EntryKind::Plain, 0)];
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::OverlapsSlot(0))
        );
    }

    #[test]
    fn malformed_entries_are_refused() {
        // A Relative entry that is not whole words.
        let mut fields = sample();
        fields.entries = vec![entry(0, 12, EntryKind::Relative, 0)];
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::MalformedEntry(0))
        );
        // A Hole entry carrying meta: only Plain carries a hole, and only
        // Bind an index.
        fields.entries = vec![entry(0, 16, EntryKind::Hole, 1)];
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::MalformedEntry(0))
        );
        // An unknown kind byte, and a run byte on an entry that carries no words.
        fields.entries = vec![entry(0, 16, EntryKind::Plain, 0)];
        let good = encode(&fields, &[0; SIG_LEN]).unwrap();
        let mut bad_kind = good.clone();
        bad_kind[OFF_TABLE + 12] = 9;
        assert_eq!(parse(&bad_kind), Err(SlotDefect::MalformedEntry(0)));
        let mut bad_run = good;
        bad_run[OFF_TABLE + 13] = 1;
        assert_eq!(parse(&bad_run), Err(SlotDefect::MalformedEntry(0)));
    }

    #[test]
    fn a_bind_entry_naming_a_missing_record_is_refused() {
        let mut fields = sample();
        fields.entries = vec![entry(0, 8, EntryKind::Bind, 1)];
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::BindRecordOutOfRange(0))
        );
    }

    #[test]
    fn a_non_zero_unused_byte_is_refused() {
        let mut bytes = encode(&sample(), &[0; SIG_LEN]).unwrap();
        bytes[OFF_FTR - 1] = 1;
        assert_eq!(parse(&bytes), Err(SlotDefect::NonZeroPadding));
    }

    #[test]
    fn a_file_len_shorter_than_an_entry_is_refused() {
        let mut fields = sample();
        fields
            .entries
            .push(entry(0x30_0000, 8, EntryKind::Plain, 0));
        let bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        assert_eq!(parse(&bytes), Err(SlotDefect::FileLenTooShort(5)));
    }

    /// The slot itself must lie inside the file image it describes.
    #[test]
    fn a_slot_outside_its_file_image_is_refused() {
        let mut fields = sample();
        fields.file_len = fields.slot_file_off + 0x100;
        fields.entries.truncate(4);
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::SlotOutsideImage)
        );
    }

    /// A slot whose address range overflows the address space lies in no
    /// image, and no entry is blamed for it.
    #[test]
    fn a_slot_whose_address_range_overflows_is_outside_its_image() {
        let mut fields = sample();
        fields.slot_rva = u32::MAX - 0x100;
        fields.entries.truncate(4);
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::SlotOutsideImage)
        );
    }

    /// An entry covering the slot by file offset is refused like one
    /// covering it by RVA.
    #[test]
    fn an_entry_covering_the_slot_by_file_offset_is_refused() {
        let mut fields = sample();
        fields.entries = vec![Entry {
            rva: 0x10_0000,
            file_off: fields.slot_file_off + 8,
            len: 16,
            kind: EntryKind::Plain,
            meta: 0,
        }];
        fields.records.clear();
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::OverlapsSlot(0))
        );
    }

    /// The entries' payload cannot exceed the file image.
    #[test]
    fn a_payload_larger_than_the_file_is_refused() {
        let mut fields = sample();
        fields.file_len = 0xa_0000;
        fields.entries = vec![
            entry(0, 0x8_0000, EntryKind::Plain, 0),
            entry(0x10_0000, 0x8_0000, EntryKind::FileOnly, 0),
        ];
        fields.entries[1].file_off = 0;
        fields.records.clear();
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::ExtentTooLarge)
        );
    }

    /// A version above 4 is not this format, and is refused by number.
    #[test]
    fn a_later_version_is_refused() {
        let mut bytes = encode(&sample(), &[0; SIG_LEN]).unwrap();
        bytes[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(SlotDefect::UnsupportedVersion(5)));
    }

    /// The string table's length is the one `encode` records.
    #[test]
    fn the_string_table_length_is_the_encoded_one() {
        let fields = sample();
        assert!(
            !fields.records.is_empty(),
            "premise: the sample has records"
        );
        let bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        let recorded = u32::from_le_bytes(
            bytes[super::OFF_STRTAB_LEN..super::OFF_STRTAB_LEN + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            super::string_table_len(&fields.records).unwrap(),
            recorded as usize
        );
        assert_eq!(super::string_table_len(&[]).unwrap(), 0);
    }

    /// The version-4 layout: an ML-DSA-87 signature field, the header
    /// fields after it, and the table capacity that leaves. Each offset is
    /// derived from the one before, so a field resized without the others
    /// moving shows here.
    #[test]
    fn the_v4_layout_holds() {
        assert_eq!(SLOT_VERSION, 4);
        assert_eq!(SLOT_SIZE, 65_536);
        assert_eq!(SIG_LEN, 4_627);
        assert_eq!(OFF_SIG, 32);
        assert_eq!(OFF_KEY_ID, 4_659);
        assert_eq!(super::OFF_LINK_BASE, 4_691);
        assert_eq!(super::OFF_FILE_LEN, 4_711);
        assert_eq!(OFF_TABLE, 4_715);
        assert_eq!(MAX_ENTRIES, 3_800);
        // A table of exactly MAX_ENTRIES entries ends inside the slot, and
        // one more would not.
        const {
            assert!(OFF_TABLE + MAX_ENTRIES * super::ENTRY_SIZE <= OFF_FTR);
            assert!(OFF_TABLE + (MAX_ENTRIES + 1) * super::ENTRY_SIZE > OFF_FTR);
        }
    }

    /// The string table follows the entry table directly; a zero gap before
    /// it, or an offset with no table, is a second spelling and is refused.
    #[test]
    fn the_string_table_has_one_placement() {
        let fields = sample();
        let mut bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        let table_end = OFF_TABLE + fields.entries.len() * super::ENTRY_SIZE;
        let len = u32::from_le_bytes(
            bytes[super::OFF_STRTAB_LEN..super::OFF_STRTAB_LEN + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        // Move the records 16 bytes later, zeroing where they were.
        let records = bytes[table_end..table_end + len].to_vec();
        oxicrypt_zeroize::zeroize(&mut bytes[table_end..table_end + len]);
        bytes[table_end + 16..table_end + 16 + len].copy_from_slice(&records);
        bytes[super::OFF_STRTAB_OFF..super::OFF_STRTAB_OFF + 4]
            .copy_from_slice(&u32::try_from(table_end + 16).unwrap().to_le_bytes());
        assert_eq!(parse(&bytes), Err(SlotDefect::StringTable));

        let mut no_table = sample();
        no_table.records.clear();
        no_table.entries.retain(|e| e.kind != EntryKind::Bind);
        let mut bytes = encode(&no_table, &[0; SIG_LEN]).unwrap();
        bytes[super::OFF_STRTAB_OFF] = 1;
        assert_eq!(parse(&bytes), Err(SlotDefect::StringTable));
    }

    /// A non-zero byte between the entry table and the string table is
    /// refused, like one after it.
    #[test]
    fn a_non_zero_byte_before_the_string_table_is_refused() {
        let mut fields = sample();
        fields.records.clear();
        fields.entries.retain(|e| e.kind != EntryKind::Bind);
        let mut bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        bytes[OFF_TABLE + fields.entries.len() * super::ENTRY_SIZE] = 1;
        assert_eq!(parse(&bytes), Err(SlotDefect::NonZeroPadding));
    }

    /// Records are unique, each used, and in the order of first use.
    #[test]
    fn bind_records_are_canonical() {
        let second = BindRecord {
            library: "libc.so".to_owned(),
            symbol: "free".to_owned(),
            ordinal: 0,
            addend: 0,
            weak: false,
        };
        let mut fields = sample();
        fields.entries = vec![
            entry(0, 8, EntryKind::Bind, 1),
            entry(16, 8, EntryKind::Bind, 0),
        ];
        fields.records.push(second.clone());
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::RecordOrder(0)),
            "the record used first must come first"
        );
        fields.entries = vec![entry(0, 8, EntryKind::Bind, 0)];
        assert!(
            matches!(
                parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
                Err(SlotDefect::RecordOrder(_))
            ),
            "an unused record is refused"
        );
        fields.records = vec![second.clone(), second];
        fields.entries = vec![
            entry(0, 8, EntryKind::Bind, 0),
            entry(16, 8, EntryKind::Bind, 1),
        ];
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::StringTable),
            "a repeated record is refused"
        );
        // Control: two distinct records used in order are accepted.
        let mut ok = sample();
        ok.records.push(BindRecord {
            library: "libc.so".to_owned(),
            symbol: "free".to_owned(),
            ordinal: 0,
            addend: 0,
            weak: false,
        });
        ok.entries = vec![
            entry(0, 8, EntryKind::Bind, 0),
            entry(16, 8, EntryKind::Bind, 1),
            entry(32, 8, EntryKind::Bind, 0),
        ];
        assert!(parse(&encode(&ok, &[0; SIG_LEN]).unwrap()).is_ok());
    }

    /// Entries continuing each other merge only when both coordinates and
    /// `meta` agree.
    #[test]
    fn merging_needs_both_coordinates_and_meta() {
        let a = entry(0, 32, EntryKind::Plain, 0);
        let mut b = entry(32, 32, EntryKind::Plain, 0);
        assert!(a.merges_with(&b));
        b.file_off = 40;
        assert!(!a.merges_with(&b), "file offsets must continue too");
        let c = entry(0, 8, EntryKind::Bind, 0);
        let d = entry(8, 8, EntryKind::Bind, 1);
        assert!(!c.merges_with(&d), "meta must agree");
        assert!(c.merges_with(&entry(8, 8, EntryKind::Bind, 0)));
    }

    /// A hole run longer than a `Plain` entry can carry has one canonical
    /// form, the saturated split: `meta` at `u16::MAX`, then one `Hole`
    /// entry with the rest. Every other split is refused.
    #[test]
    fn a_hole_run_past_the_meta_limit_has_one_canonical_split() {
        let max = u32::from(u16::MAX);
        let plain = entry(0, 8, EntryKind::Plain, 0);
        let hole = |at: u32, words: u32| Entry {
            rva: at,
            file_off: at,
            len: words * 8,
            kind: EntryKind::Hole,
            meta: 0,
        };
        let canonical = vec![
            entry(0, 8, EntryKind::Plain, u16::MAX),
            hole(8 + max * 8, 3),
        ];
        assert_eq!(merge(&[plain, hole(8, max + 3)]), canonical);
        assert_eq!(merge(&canonical), canonical);
        let mut fields = sample();
        fields.records.clear();
        fields.file_len = 0x80_0000;
        let check = |entries: Vec<Entry>| {
            let mut f = fields.clone();
            f.entries = entries;
            parse(&encode(&f, &[0; SIG_LEN]).unwrap()).map(|_| ())
        };
        assert_eq!(check(canonical.clone()), Ok(()));
        // The unsaturated Plain entry, the unfolded run and a remainder
        // split in two are each refused.
        let short = vec![
            entry(0, 8, EntryKind::Plain, u16::MAX - 1),
            hole(8 + (max - 1) * 8, 4),
        ];
        assert_eq!(check(short), Err(SlotDefect::NonMaximal(1)));
        assert_eq!(
            check(vec![plain, hole(8, max + 3)]),
            Err(SlotDefect::NonMaximal(1))
        );
        let split = vec![
            entry(0, 8, EntryKind::Plain, u16::MAX),
            hole(8 + max * 8, 1),
            hole(16 + max * 8, 2),
        ];
        assert_eq!(check(split), Err(SlotDefect::NonMaximal(2)));
    }

    /// The `Hole` words after `Plain` bytes become that entry's hole, and a
    /// table that spells them as a separate entry is not canonical. The hole
    /// is covered, and an entry after it starts where it ends.
    #[test]
    fn a_hole_after_plain_bytes_is_carried_by_the_plain_entry() {
        let plain = entry(0, 32, EntryKind::Plain, 0);
        let hole = entry(32, 16, EntryKind::Hole, 0);
        let after = entry(48, 8, EntryKind::Plain, 0);
        let merged = merge(&[plain, hole, after]);
        assert_eq!(merged, vec![entry(0, 32, EntryKind::Plain, 2), after]);
        assert_eq!(merged[0].rva_end(), Some(48));
        assert_eq!(super::extent_len(&merged), Some(56));
        // Plain bytes after a hole start a new entry; a hole not a whole
        // number of words, or after another kind, stays its own entry.
        assert!(!merged[0].merges_with(&after));
        assert!(!plain.merges_with(&entry(32, 4, EntryKind::Hole, 0)));
        assert!(!entry(0, 8, EntryKind::Relative, 0).merges_with(&entry(8, 8, EntryKind::Hole, 0)));
        // Encoded unfolded, the table is refused as not maximal.
        let mut fields = sample();
        fields.records.clear();
        fields.entries = vec![plain, hole];
        assert!(matches!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::NonMaximal(1))
        ));
        fields.entries = merge(&[plain, hole]);
        assert!(parse(&encode(&fields, &[0; SIG_LEN]).unwrap()).is_ok());
    }

    /// `bytes` with its table replaced by `rows`, each `(rva, file_off,
    /// len, kind, run, meta)`; the slot must carry no records.
    fn with_table(bytes: &[u8], rows: &[(u32, u32, u32, EntryKind, u8, u16)]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for b in &mut out[OFF_TABLE..OFF_FTR] {
            *b = 0;
        }
        out[super::OFF_COUNT..super::OFF_COUNT + 4]
            .copy_from_slice(&(rows.len() as u32).to_le_bytes());
        for (i, &(rva, file_off, len, kind, run, meta)) in rows.iter().enumerate() {
            let at = OFF_TABLE + i * super::ENTRY_SIZE;
            out[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&file_off.to_le_bytes());
            out[at + 8..at + 12].copy_from_slice(&len.to_le_bytes());
            out[at + 12] = kind as u8;
            out[at + 13] = run;
            out[at + 14..at + 16].copy_from_slice(&meta.to_le_bytes());
        }
        out
    }

    /// A run of identical periods is stored as one entry and expands back
    /// to the same entries, each `Relative` word its own; every other
    /// spelling of the same table is refused.
    #[test]
    fn identical_periods_store_as_one_entry_and_no_other_spelling_parses() {
        use EntryKind::{Plain, Relative};
        let mut entries = Vec::new();
        for k in 0..20u32 {
            entries.push(entry(k * 24, 16, Plain, 0));
            entries.push(entry(k * 24 + 16, 8, Relative, 0));
        }
        for k in 0..3u32 {
            entries.push(entry(480 + k * 24, 16, Plain, 1));
        }
        assert_eq!(merge(&entries), entries, "the fixture is canonical");
        assert_eq!(super::table_len(&entries), 2);
        let mut fields = sample();
        fields.records.clear();
        fields.entries = entries.clone();
        let bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        assert_eq!(bytes[OFF_TABLE + 13], 0x80 | 0x13);
        assert_eq!(bytes[OFF_TABLE + super::ENTRY_SIZE + 13], 2);
        assert_eq!(parse(&bytes).unwrap().fields.entries, entries);
        assert_eq!(
            parse(&with_table(
                &bytes,
                &[
                    (0, 0, 16, Plain, 0x80 | 0x13, 1),
                    (480, 480, 16, Plain, 2, 1)
                ]
            ))
            .unwrap()
            .fields
            .entries,
            entries,
            "control: the table written by hand as encode writes it parses"
        );
        // The first period stored apart from the rest.
        let split = [
            (0, 0, 16, Plain, 0x80, 1),
            (24, 24, 16, Plain, 0x80 | 0x12, 1),
            (480, 480, 16, Plain, 2, 1),
        ];
        assert_eq!(
            parse(&with_table(&bytes, &split)),
            Err(SlotDefect::NonMaximal(0))
        );
        // A period's Plain bytes and its Relative word stored apart.
        let apart = [
            (0, 0, 16, Plain, 0, 0),
            (16, 16, 8, Relative, 0, 0),
            (24, 24, 16, Plain, 0x80 | 0x12, 1),
            (480, 480, 16, Plain, 2, 1),
        ];
        assert_eq!(
            parse(&with_table(&bytes, &apart)),
            Err(SlotDefect::NonMaximal(0))
        );
        // A run byte on an entry that carries no words.
        for row in [(0, 0, 16, Relative, 1, 0), (0, 0, 16, Plain, 1, 0)] {
            assert_eq!(
                parse(&with_table(&bytes, &[row])),
                Err(SlotDefect::MalformedEntry(0))
            );
        }
        // A table that expands past MAX_EXPANDED is refused before it is
        // checked further.
        let many: Vec<_> = (0..300u32)
            .map(|k| (k * 0x1000, k * 0x1000, 16, Plain, 0x80 | 0x7f, 1))
            .collect();
        assert!(matches!(
            parse(&with_table(&bytes, &many)),
            Err(SlotDefect::TooManyEntries(_))
        ));
    }

    /// A `Relative` entry that is not whole words, or that carries `meta`,
    /// is never folded into the `Plain` entry before it: it is stored as
    /// given and refused, so no byte leaves the extent and no `meta` is
    /// dropped.
    #[test]
    fn a_malformed_relative_after_plain_bytes_is_stored_as_given_and_refused() {
        let mut fields = sample();
        fields.records.clear();
        for (len, meta) in [(12, 0), (9, 0), (8, 1)] {
            fields.entries = vec![
                entry(0, 8, EntryKind::Plain, 0),
                entry(8, len, EntryKind::Relative, meta),
            ];
            assert_eq!(
                super::table_len(&fields.entries),
                2,
                "len {len} meta {meta}"
            );
            assert_eq!(
                parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
                Err(SlotDefect::MalformedEntry(1)),
                "len {len} meta {meta}"
            );
        }
        // Control: whole words with no meta fold and parse back.
        fields.entries = vec![
            entry(0, 8, EntryKind::Plain, 0),
            entry(8, 16, EntryKind::Relative, 0),
        ];
        assert_eq!(super::table_len(&fields.entries), 1);
        let parsed = parse(&encode(&fields, &[0; SIG_LEN]).unwrap()).unwrap();
        assert_eq!(parsed.fields.entries, fields.entries);
    }

    /// The expansion cap is exact, and a run longer than one stored entry's
    /// 128 periods continues in the next.
    #[test]
    fn the_expansion_cap_is_exact_and_long_runs_round_trip() {
        use EntryKind::{Plain, Relative};
        let mut entries = Vec::new();
        for k in 0..200u32 {
            entries.push(entry(k * 24, 16, Plain, 0));
            entries.push(entry(k * 24 + 16, 8, Relative, 0));
        }
        assert_eq!(super::table_len(&entries), 2);
        let mut fields = sample();
        fields.records.clear();
        fields.entries = entries.clone();
        let bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        assert_eq!(parse(&bytes).unwrap().fields.entries, entries);
        // 256 stored entries of 128 periods of two entries each expand to
        // exactly MAX_EXPANDED; one more Plain entry exceeds it.
        let at = |k: u32| k * 0x2000;
        let mut rows: Vec<_> = (0..256u32)
            .map(|k| (at(k), at(k), 16, Plain, 0x80 | 0x7f, 1))
            .collect();
        assert_eq!(rows.len() * 256, super::MAX_EXPANDED);
        assert!(!matches!(
            parse(&with_table(&bytes, &rows)),
            Err(SlotDefect::TooManyEntries(_))
        ));
        rows.push((at(256), at(256), 16, Plain, 0, 0));
        assert!(matches!(
            parse(&with_table(&bytes, &rows)),
            Err(SlotDefect::TooManyEntries(_))
        ));
    }

    #[test]
    fn a_malformed_string_table_is_refused() {
        let fields = sample();
        let bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        // The record's reserved byte sits one past its flags byte, which is
        // the first byte after the table.
        let strtab = OFF_TABLE + super::table_len(&fields.entries) * super::ENTRY_SIZE;
        let mut bad = bytes;
        bad[strtab + 1] = 1;
        assert_eq!(parse(&bad), Err(SlotDefect::StringTable));
    }

    #[test]
    fn a_name_with_an_interior_nul_is_refused() {
        let fields = sample();
        assert!(!fields.records.is_empty());
        let bytes = encode(&fields, &[0; SIG_LEN]).unwrap();
        assert!(parse(&bytes).is_ok(), "control: the sample parses");
        // The first byte of the first record's library name.
        let name = OFF_TABLE + fields.entries.len() * super::ENTRY_SIZE + super::BIND_RECORD_HEADER;
        let mut bad = bytes;
        assert_ne!(bad[name], 0);
        bad[name] = 0;
        assert_eq!(parse(&bad), Err(SlotDefect::StringTable));
    }

    #[test]
    fn an_empty_table_and_an_overfull_one_are_refused() {
        let mut fields = sample();
        fields.entries.clear();
        assert_eq!(
            parse(&encode(&fields, &[0; SIG_LEN]).unwrap()),
            Err(SlotDefect::NoEntries)
        );
        fields.records.clear();
        fields.entries = (0..=MAX_ENTRIES as u32)
            .map(|i| entry(i * 16, 8, EntryKind::Plain, 0))
            .collect();
        assert!(matches!(
            encode(&fields, &[0; SIG_LEN]),
            Err(SlotDefect::TooManyEntries(_))
        ));
    }
}
