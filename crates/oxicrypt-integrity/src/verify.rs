//! The integrity test itself, independent of how bytes are acquired.
//!
//! [`verify`] runs the whole test against a [`Process`]: the platform glue
//! in `acquire` in production, a stub in the unit tests. Keeping the
//! algorithm here and the system calls there is what lets every branch of
//! the test (a slid word, a bound import, a file route of the wrong length,
//! a signature made with another key) be driven by a fixture, which a test
//! that can only run the real process could never reach.
//!
//! The signature input is the slot without its signature field, followed
//! by each entry's payload in table order: `Plain` bytes as loaded,
//! `Relative` words unslid, `FileOnly` bytes from the image file, and
//! nothing for `Hole` and `Bind`. The signer builds the same input from the
//! file with [`file_signature_input`], so the two sides share one
//! definition of what is signed.
//!
//! The signature is ML-DSA-87 (FIPS 204) over that input framed as FIPS
//! 204's external interface frames a message under a context string:
//! `M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M`, with `ctx` = [`SIGNATURE_CONTEXT`].
//! Both sides start the buffer with [`MESSAGE_PREFIX`] and then append
//! `M`, and the module verifies `M′` with `ML-DSA.Verify_internal`
//! because the gated external `verify` requires the operational state the
//! test precedes. The context separates integrity signatures from
//! signatures the same key makes under any other context string.

use std::path::PathBuf;

use oxicrypt_imageread::Symbol;
use oxicrypt_ml_dsa::ml_dsa_87;

use crate::key::{KEY_RECORD_SIZE, parse_key_record};
use crate::slot::{self, BindRecord, Entry, EntryKind, SlotDefect, SlotFields, SlotImage};
use crate::{IntegrityError, SLOT_SIZE, Unreadable, key_fingerprint};

/// Width of a `Relative` or `Bind` word.
const WORD: usize = 8;

/// The FIPS 204 context string every integrity signature is made under.
pub const SIGNATURE_CONTEXT: &[u8] = b"oxicrypt-integrity";

/// What FIPS 204's external interface puts before the message for pure
/// ML-DSA under [`SIGNATURE_CONTEXT`]: the domain separator `0x00`, the
/// context's length, then the context (FIPS 204 Algorithms 2 and 3).
///
/// The signed message `M′` is this prefix followed by the signature input
/// `M`. The verifier writes it first into the buffer it fills with `M`,
/// and [`file_signature_input`] starts with it, so the two sides share one
/// definition of the framing.
pub const MESSAGE_PREFIX: [u8; 20] = *b"\x00\x12oxicrypt-integrity";

/// Bytes read per request. Payload is appended a chunk at a time, so the
/// buffer only ever holds bytes that were actually read.
const CHUNK: usize = 64 * 1024;

/// Where the file route reads, once located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Located {
    /// The image file.
    pub(crate) path: PathBuf,
    /// `image_base`: the image's offset inside the file. Zero for a library
    /// loaded from its own file.
    pub(crate) base: u64,
    /// The file may continue past `file_len` with the operating system's
    /// code-signature envelope (a Mach-O code signature or a PE certificate
    /// table), which is outside the signed image.
    pub(crate) envelope: bool,
}

/// What the test needs from the process it runs in. Every method is a
/// system call or a file read; the decisions made on their results (where
/// the file route reads, how long the file must be, how a failed read is
/// classified) are made in this module, once, for production and tests
/// alike.
pub(crate) trait Process {
    /// Copies `out.len()` bytes of the loaded image at `addr`.
    fn read(&mut self, addr: u64, out: &mut [u8]) -> Result<(), Unreadable>;

    /// Finds the image file the loader mapped the slot from.
    fn locate_file(
        &mut self,
        slot: &SlotFields,
        slot_addr: u64,
        base: u64,
        span: u64,
    ) -> Result<Located, Unreadable>;

    /// The image file's length.
    fn file_size(&mut self, path: &std::path::Path) -> Result<u64, Unreadable>;

    /// Copies `out.len()` bytes of the image file at `pos`.
    fn read_file(
        &mut self,
        path: &std::path::Path,
        pos: u64,
        out: &mut [u8],
    ) -> Result<(), Unreadable>;

    /// Resolves an import the way the loader bound it. `Ok(None)` is a
    /// failed resolution; `Err(None)` means this platform cannot resolve
    /// this import the way its loader binds.
    fn resolve(&mut self, record: &BindRecord) -> Result<Option<u64>, Option<Unreadable>>;

    /// The Mach header of the loaded image whose path is `path`, or `None`
    /// when no image of that path is loaded. Darwin only; `None` wherever
    /// the platform cannot say, so the exception it opens in
    /// [`check_bind_word`] is never taken there.
    fn loaded_image(&mut self, path: &[u8]) -> Result<Option<u64>, Unreadable>;

    /// Whether the loader binds an import whose export is a resolver
    /// function to an indirect-jump stub: Darwin on x86_64. Elsewhere a
    /// bound word must equal its resolution exactly.
    fn indirect_stubs(&self) -> bool;

    /// Whether `[addr, addr + len)` is mapped, where the platform can say;
    /// `None` where it cannot. On Linux and Android that is any readable or
    /// executable mapping in the process, not only the image's own; on
    /// Windows it is committed, readable memory of the module the slot at
    /// `slot_addr` lies in. Tells a read the slot sent to unmapped memory
    /// from one the environment refused.
    fn mapped(&mut self, addr: u64, len: u64, slot_addr: u64) -> Option<bool>;

    /// An upper bound on the bytes the image can contribute, measured from
    /// the environment rather than taken from the slot: the readable
    /// mappings of the image file inside `[base, base + span)`, the range the
    /// slot's entries describe (Linux, Android), or the image file's physical
    /// size (Darwin, Windows). Caps the signature input before anything the
    /// slot records is authenticated. A bound that cannot be measured is an
    /// error, so nothing is allocated on the slot's word alone.
    ///
    /// `file_len` is the length the slot records; a bound measured from a
    /// file the environment names but which is shorter than that is the
    /// environment's fault, never the slot's.
    fn payload_cap(
        &mut self,
        slot_addr: u64,
        base: u64,
        span: u64,
        file_len: u64,
    ) -> Result<u64, Unreadable>;
}

/// The symbol a record names.
pub(crate) fn symbol_of(record: &BindRecord) -> Symbol<'_> {
    if record.symbol.is_empty() {
        Symbol::Ordinal(record.ordinal)
    } else {
        Symbol::Name(&record.symbol)
    }
}

/// A byte buffer the integrity test computed, wiped when it is dropped on
/// every path (ISO/IEC 19790 §7.5 `[05.10]`).
///
/// Its capacity is reserved once, before anything is written, so the
/// buffer never reallocates and leaves no unwiped copy behind.
pub(crate) struct Wiped(pub(crate) Vec<u8>);

impl Wiped {
    /// An empty buffer that can hold `capacity` bytes without moving.
    fn with_capacity(capacity: usize) -> Option<Self> {
        let mut v = Vec::new();
        v.try_reserve_exact(capacity).ok()?;
        Some(Self(v))
    }
}

impl Drop for Wiped {
    fn drop(&mut self) {
        // Every byte the buffer ever held, not just its current length: a
        // buffer cleared and refilled shorter keeps the earlier bytes past
        // its length. Growing to the capacity never reallocates.
        let capacity = self.0.capacity();
        self.0.resize(capacity, 0);
        oxicrypt_zeroize::zeroize(&mut self.0);
        #[cfg(test)]
        wipe_witness::record(self.0.len() == capacity && self.0.iter().all(|&b| b == 0));
    }
}

/// A fixed-size value the integrity test computed, wiped when dropped.
pub(crate) struct Secret<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.0);
        #[cfg(test)]
        wipe_witness::record(self.0.iter().all(|&b| b == 0));
    }
}

/// What the last `Drop` of a [`Wiped`] or [`Secret`] on this thread left in
/// its buffer, read by the drop itself while the buffer is still owned.
#[cfg(test)]
mod wipe_witness {
    std::thread_local! {
        static LAST: core::cell::Cell<Option<bool>> = const { core::cell::Cell::new(None) };
    }

    pub(super) fn record(zeroed: bool) {
        LAST.with(|c| c.set(Some(zeroed)));
    }

    /// `Some(true)` when the last drop left its whole buffer zero.
    pub(super) fn take() -> Option<bool> {
        LAST.with(core::cell::Cell::take)
    }
}

/// The highest RVA any entry or the slot occupies: the image span every
/// mapping of the image lies within.
fn image_span(fields: &SlotFields) -> u64 {
    let slot_end = u64::from(fields.slot_rva).saturating_add(SLOT_SIZE as u64);
    fields
        .entries
        .iter()
        .map(|e| e.rva_end().map_or(u64::MAX, u64::from))
        .fold(slot_end, u64::max)
}

/// The file route: located on first use, then read at
/// `image_base + file_off`.
struct FileRoute {
    located: Option<Located>,
}

impl FileRoute {
    fn read(
        &mut self,
        process: &mut impl Process,
        fields: &SlotFields,
        slot_addr: u64,
        base: u64,
        file_off: u64,
        out: &mut [u8],
    ) -> Result<(), Unreadable> {
        if self.located.is_none() {
            let located = process.locate_file(fields, slot_addr, base, image_span(fields))?;
            let size = process.file_size(&located.path)?;
            check_file_length(&located, u64::from(fields.file_len), size)?;
            self.located = Some(located);
        }
        let located = self.located.as_ref().ok_or(Unreadable::NoBackingFile)?;
        let pos = located
            .base
            .checked_add(file_off)
            .ok_or(Unreadable::SlotUnmapped)?;
        process.read_file(&located.path, pos, out)
    }
}

/// The file route's length rule.
///
/// A library loaded from its own file is exactly the signed length, and
/// one mapped out of an archive must fit inside it. An image whose file
/// carries the operating system's code-signature envelope after the signed
/// image is at least the signed length: the envelope is outside the
/// image, and `codesign` or `signtool` may grow it.
pub(crate) fn check_file_length(
    located: &Located,
    file_len: u64,
    size: u64,
) -> Result<(), Unreadable> {
    let end = located.base.checked_add(file_len);
    let fits = match end {
        Some(end) if located.base != 0 => end <= size,
        Some(end) if located.envelope => end <= size,
        Some(end) => end == size,
        None => false,
    };
    if fits {
        Ok(())
    } else {
        Err(Unreadable::FileLength {
            expected: file_len,
            actual: size,
        })
    }
}

/// Runs the test against `process`.
///
/// `fingerprint` receives the embedded key's fingerprint as soon as it is
/// known, so the caller can report which key a failed run was checking
/// against.
///
/// Classification of read failures: a failure reading the key record or
/// the slot means the environment could not supply the module's bytes
/// (`Unreadable`). Once both have been read through a working route, a
/// failed read of an entry is classified by its cause (`classify_memory`):
/// memory the slot names that is not mapped is damage to the slot
/// (`EntryOutOfBounds`); a refused read of mapped memory is the
/// environment's (`Unreadable`).
///
/// Order of checks: each `Bind` entry's import is resolved and its word
/// checked while the signature input is assembled, before the signature is
/// verified. The slot is not yet authenticated then, so its contents choose
/// which failure is reported: a slot edited to name an import that does not
/// resolve reports slot damage (`UnresolvedImport`, `BindUnsupported`), or
/// `Unreadable` when the resolver itself fails, rather than
/// `SignatureInvalid`. On Darwin x86_64 a bind word that does not match its
/// resolution, where the export-trie walk that could accept it as a
/// resolver stub fails, reports `Unreadable`. Every such path
/// fails the test.
#[allow(
    clippy::too_many_lines,
    reason = "the test's one linear sequence; each step's classification sits beside it"
)]
pub(crate) fn verify(
    process: &mut impl Process,
    slot_addr: u64,
    key_addr: u64,
    fingerprint: &mut Option<[u8; 32]>,
) -> Result<(), IntegrityError> {
    // The key first: a build without one has nothing to verify against,
    // and that is the finding whatever the slot holds.
    let mut record = Secret([0u8; KEY_RECORD_SIZE]);
    process
        .read(key_addr, &mut record.0)
        .map_err(IntegrityError::Unreadable)?;
    let key = Secret(
        parse_key_record(&record.0)
            .map_err(IntegrityError::SlotInvalid)?
            .ok_or(IntegrityError::NoVerifyKey)?,
    );
    let fp = key_fingerprint(&key.0).map_err(IntegrityError::Module)?;
    *fingerprint = Some(fp);

    let mut slot_bytes = Wiped(vec![0u8; SLOT_SIZE]);
    process
        .read(slot_addr, &mut slot_bytes.0)
        .map_err(IntegrityError::Unreadable)?;
    // The slot is the module's own static, so the only slot a correct
    // artifact can fail to parse is the unsigned template the build emits. Every other refusal is damage, and is reported so
    // that nobody is told to sign it.
    let mut parsed = slot::parse(&slot_bytes.0).map_err(|d| {
        if slot::is_unsigned_template(&slot_bytes.0) {
            IntegrityError::SlotInvalid(SlotDefect::Unsigned)
        } else {
            IntegrityError::SlotInvalid(d)
        }
    })?;
    let signature = Secret(parsed.signature);
    oxicrypt_zeroize::zeroize(&mut parsed.signature);
    if parsed.fields.key_id != fp {
        return Err(IntegrityError::SlotInvalid(SlotDefect::KeyMismatch));
    }
    let base = slot_addr
        .checked_sub(u64::from(parsed.fields.slot_rva))
        .ok_or(IntegrityError::SlotInvalid(SlotDefect::SlotRvaTooLarge))?;
    let slide = base.wrapping_sub(parsed.fields.link_base);

    let header = slot::signed_header(&slot_bytes.0).map_err(IntegrityError::SlotInvalid)?;
    let header = Wiped(header);
    let cap = process
        .payload_cap(
            slot_addr,
            base,
            image_span(&parsed.fields),
            u64::from(parsed.fields.file_len),
        )
        .map_err(IntegrityError::Unreadable)?;
    let payload = payload_len(&parsed.fields, cap)?;
    let total = header
        .0
        .len()
        .checked_add(MESSAGE_PREFIX.len())
        .and_then(|n| n.checked_add(payload))
        .ok_or(IntegrityError::SlotInvalid(SlotDefect::ExtentTooLarge))?;
    let mut message =
        Wiped::with_capacity(total).ok_or(IntegrityError::Unreadable(Unreadable::OutOfMemory))?;
    message.0.extend_from_slice(&MESSAGE_PREFIX);
    message.0.extend_from_slice(&header.0);
    let mut scratch =
        Wiped::with_capacity(CHUNK).ok_or(IntegrityError::Unreadable(Unreadable::OutOfMemory))?;
    let mut file = FileRoute { located: None };

    for (index, entry) in parsed.fields.entries.iter().enumerate() {
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        let damaged = || IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(index));
        let addr = base.checked_add(u64::from(entry.rva)).ok_or_else(damaged)?;
        let record = if entry.kind == EntryKind::Bind {
            let record = parsed.fields.records.get(usize::from(entry.meta)).ok_or(
                IntegrityError::SlotInvalid(SlotDefect::BindRecordOutOfRange(index)),
            )?;
            Some((record, resolve(process, index, record)?))
        } else {
            None
        };
        let mut done: u64 = 0;
        let len = u64::from(entry.len);
        while done < len {
            let take = usize::try_from(len.saturating_sub(done).min(CHUNK as u64)).unwrap_or(CHUNK);
            let at = addr.checked_add(done).ok_or_else(damaged)?;
            match entry.kind {
                EntryKind::Hole => break,
                EntryKind::Plain => {
                    let start = message.0.len();
                    message.0.resize(start.saturating_add(take), 0);
                    let window = message.0.get_mut(start..).ok_or_else(damaged)?;
                    if let Err(failure) = process.read(at, window) {
                        return Err(classify_memory(
                            process, failure, at, take, index, slot_addr,
                        ));
                    }
                }
                EntryKind::FileOnly => {
                    let start = message.0.len();
                    message.0.resize(start.saturating_add(take), 0);
                    let window = message.0.get_mut(start..).ok_or_else(damaged)?;
                    let off = u64::from(entry.file_off).saturating_add(done);
                    file.read(process, &parsed.fields, slot_addr, base, off, window)
                        .map_err(|u| classify_file_failure(u, index))?;
                }
                EntryKind::Relative | EntryKind::Bind => {
                    scratch.0.clear();
                    scratch.0.resize(take, 0);
                    if let Err(failure) = process.read(at, &mut scratch.0) {
                        return Err(classify_memory(
                            process, failure, at, take, index, slot_addr,
                        ));
                    }
                    for word in scratch.0.chunks_exact(WORD) {
                        let loaded = word_value(word);
                        match record {
                            Some((record, resolved)) => {
                                check_bind_word(process, record, resolved, loaded)?;
                            }
                            None => message
                                .0
                                .extend_from_slice(&loaded.wrapping_sub(slide).to_le_bytes()),
                        }
                    }
                }
            }
            done = done.saturating_add(take as u64);
        }
    }

    if ml_dsa_87::verify_internal(&key.0, &message.0, &signature.0)
        .map_err(IntegrityError::Module)?
    {
        Ok(())
    } else {
        Err(IntegrityError::SignatureInvalid)
    }
}

/// What a file-route failure says.
///
/// The environment can fail to supply the image file: no maps, no file, a
/// file that cannot be opened or read. Those are `Unreadable`, the test not
/// performed. A failure the slot's own fields cause (a file that is not the
/// recorded length, a mapping of the file the slot does not place, a read
/// past the bytes the length check admitted) is damage to the slot.
fn classify_file_failure(failure: Unreadable, index: u32) -> IntegrityError {
    match failure {
        // The slot has parsed, so a file mapped outside the range its
        // entries describe, or not where they place it, is the slot's word
        // against the loader's.
        Unreadable::SlotUnmapped
        | Unreadable::ArchiveBaseUnaligned(_)
        | Unreadable::ForeignArchiveMapping
        | Unreadable::MappingMisplaced => {
            IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(index))
        }
        // `file_len` is not yet authenticated when the length is checked, so
        // a mismatch is the slot's word against the file's.
        Unreadable::FileLength { .. } => IntegrityError::SlotInvalid(SlotDefect::FileLenMismatch),
        Unreadable::FileRead(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(index))
        }
        other => IntegrityError::Unreadable(other),
    }
}

/// Whether an operating-system status from a memory read means the address
/// is not mapped at all, which only a slot naming memory outside the image
/// causes. `EFAULT` from `process_vm_readv`, `KERN_INVALID_ADDRESS` from
/// `mach_vm_read_overwrite`, and `ERROR_INVALID_ADDRESS` or
/// `ERROR_NOACCESS` from `ReadProcessMemory`. Other statuses (`ENOMEM`,
/// `EIO`, `ERROR_PARTIAL_COPY` on a page another component guards) are the
/// environment's.
const fn unmapped_status(code: i64) -> bool {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        code == 14
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        code == 1
    } else if cfg!(windows) {
        code == 487 || code == 998
    } else {
        false
    }
}

/// What a failed read of an entry says, classified by its cause.
///
/// Memory the slot names that is not mapped is damage to the slot. A read
/// of mapped memory that the environment refused (memory pressure, an I/O
/// error, execute-only text a kernel will not copy) is `Unreadable`: the
/// test was not performed. Only when `mapped` cannot tell does the read's
/// own status decide: a status that means "not mapped", or a short read, is
/// damage.
fn classify_memory(
    process: &mut impl Process,
    failure: Unreadable,
    addr: u64,
    len: usize,
    index: u32,
    slot_addr: u64,
) -> IntegrityError {
    let damaged = IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(index));
    match process.mapped(addr, len as u64, slot_addr) {
        Some(false) => return damaged,
        Some(true) => return IntegrityError::Unreadable(failure),
        None => {}
    }
    match &failure {
        Unreadable::SelfReadFailed(oxicrypt_imageread::ReadError::Os(code))
            if unmapped_status(*code) =>
        {
            damaged
        }
        Unreadable::SelfReadFailed(oxicrypt_imageread::ReadError::Short { .. }) => damaged,
        _ => IntegrityError::Unreadable(failure),
    }
}

/// Total payload the entries contribute to the signature input. Every
/// payload byte is a byte of the image, so it is bounded by what the
/// environment measures the image to hold (`cap`) and by the slot's
/// `file_len`. A slot naming more is damaged.
fn payload_len(fields: &SlotFields, cap: u64) -> Result<usize, IntegrityError> {
    let too_large = || IntegrityError::SlotInvalid(SlotDefect::ExtentTooLarge);
    let total = fields
        .entries
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EntryKind::Plain | EntryKind::Relative | EntryKind::FileOnly
            )
        })
        .try_fold(0u64, |acc, e| acc.checked_add(u64::from(e.len)))
        .ok_or_else(too_large)?;
    // Bounded by the slot's own extent and file length, and by what the
    // environment says the image actually holds.
    if total > u64::from(fields.file_len) || total > image_span(fields) || total > cap {
        return Err(too_large());
    }
    usize::try_from(total).map_err(|_| too_large())
}

/// A little-endian 8-byte word. Every target this module supports is
/// little-endian, so this is also the loaded word's native value.
fn word_value(word: &[u8]) -> u64 {
    let mut arr = [0u8; WORD];
    arr.copy_from_slice(word.get(..WORD).unwrap_or(&[0u8; WORD]));
    u64::from_le_bytes(arr)
}

/// Resolves a `Bind` entry's import.
///
/// A non-weak import that does not resolve means the import the artifact
/// was signed against is not the one present. A platform that cannot
/// resolve the import the way its loader binds refuses the entry.
fn resolve(
    process: &mut impl Process,
    index: u32,
    record: &BindRecord,
) -> Result<Option<u64>, IntegrityError> {
    match process.resolve(record) {
        Ok(None) if !record.weak => Err(IntegrityError::SlotInvalid(SlotDefect::UnresolvedImport(
            index,
        ))),
        Ok(resolved) => Ok(resolved),
        // The signer writes a bound import only for a platform whose
        // loader binds that way, so a record this platform cannot resolve
        // was not written by the signer for this image.
        Err(None) => Err(IntegrityError::SlotInvalid(SlotDefect::BindUnsupported(
            index,
        ))),
        Err(Some(unreadable)) => Err(IntegrityError::Unreadable(unreadable)),
    }
}

/// Checks one word of a `Bind` entry: exactly the resolved address plus
/// the addend, or zero for a weak import that did not resolve.
///
/// One exception, on Darwin x86_64 alone, for an export that is a resolver
/// function: the loader binds such an import to a stub, `jmp
/// *disp32(%rip)`, in the exporting image, while the resolver lookup
/// returns the implementation the resolver chose. The stub's pointer is
/// bound lazily, on the first call through it, so what it holds when the
/// test runs proves nothing; the export tries tie the stub to the name.
/// The import is resolved the way dyld resolves it: `_<symbol>` is looked
/// up in the export trie of the library the record names, and a re-export
/// is followed to the dependent library its ordinal names, under its new
/// name when it renames, and on a miss each library the image re-exports
/// whole (`LC_REEXPORT_DYLIB`) is searched in order, as libSystem reaches
/// libsystem_platform's `_memcmp`; at most eight deep, 256 images in all,
/// and never twice through the same library and name on one path. The word is accepted
/// when all of these hold: the record names a symbol and has no addend;
/// the chain ends at a stub-and-resolver export whose stub is at the word;
/// and the bytes at the word are `FF 25`. The tries are read from each
/// image's `__LINKEDIT` as loaded, through the memory route; a library that
/// is not loaded, a cycle, an over-long chain, a failed read or a
/// malformed trie refuses the image (`Unreadable`). Any other word is
/// refused, and so is every word on arm64 that is not exactly its
/// resolution.
///
/// Two imports exported through the same stub cannot be told apart this
/// way: `memcpy` and `memmove` share one on x86_64, so an edit of the
/// ordinal from one to the other leaves the loaded word bit for bit the
/// same, and passes. It changes nothing the loader does.
fn check_bind_word(
    process: &mut impl Process,
    record: &BindRecord,
    resolved: Option<u64>,
    value: u64,
) -> Result<(), IntegrityError> {
    let expected = match resolved {
        Some(address) => address.wrapping_add_signed(record.addend),
        None => 0,
    };
    if value == expected {
        return Ok(());
    }
    if resolved.is_some() && record.addend == 0 && stub_reaches(process, record, value)? {
        return Ok(());
    }
    Err(IntegrityError::SignatureInvalid)
}

/// The x86_64 indirect-jump opcode, `jmp *disp32(%rip)`.
const JMP_RIP_INDIRECT: [u8; 2] = [0xff, 0x25];

/// Whether `word` is the x86_64 stub `record`'s import resolves to through
/// the export tries (see [`check_bind_word`]).
fn stub_reaches(
    process: &mut impl Process,
    record: &BindRecord,
    word: u64,
) -> Result<bool, IntegrityError> {
    if !process.indirect_stubs() || record.symbol.is_empty() {
        return Ok(false);
    }
    let mut name = Vec::with_capacity(record.symbol.len().saturating_add(1));
    name.push(b'_');
    name.extend_from_slice(record.symbol.as_bytes());
    let mut hops = Vec::new();
    let Some((base, stub)) =
        crate::trie::resolve_stub(process, record.library.as_bytes(), &name, &mut hops)
            .map_err(IntegrityError::Unreadable)?
    else {
        return Ok(false);
    };
    if base.checked_add(stub) != Some(word) {
        return Ok(false);
    }
    let mut code = [0u8; 2];
    process
        .read(word, &mut code)
        .map_err(IntegrityError::Unreadable)?;
    Ok(code == JMP_RIP_INDIRECT)
}

/// Builds a slot's signed message `M′` from the **file** bytes of `image`:
/// [`MESSAGE_PREFIX`], then the signature input.
///
/// The signer's half of the identity the test rests on: `Plain` and
/// `FileOnly` bytes are the file's, and each `Relative` word contributes
/// its unslid value, which `unslid` derives from the word as the file holds
/// it. For a format whose file word is already the unslid address (ELF
/// `RELR`, PE `DIR64`) that is the identity; a Mach-O chained rebase
/// encodes the target, `high8` and the chain's `next` field, which the
/// format's own decoder turns into the address the loader writes less the
/// slide. `Hole` and `Bind` contribute nothing, as on the verifier's side.
///
/// # Errors
///
/// [`IntegrityError::SlotInvalid`] with [`SlotDefect::EntryOutOfBounds`]
/// when an entry falls outside `image`, [`SlotDefect::MalformedEntry`]
/// when `unslid` refuses a `Relative` word, or [`SlotDefect::WrongSize`]
/// when `slot_bytes` is not a slot.
pub fn file_signature_input(
    image: &[u8],
    slot_bytes: &[u8],
    slot: &SlotImage,
    unslid: &dyn Fn(u64) -> Option<u64>,
) -> Result<Vec<u8>, IntegrityError> {
    let header = slot::signed_header(slot_bytes).map_err(IntegrityError::SlotInvalid)?;
    let mut message = Vec::with_capacity(MESSAGE_PREFIX.len().saturating_add(header.len()));
    message.extend_from_slice(&MESSAGE_PREFIX);
    message.extend_from_slice(&header);
    for (index, entry) in slot.fields.entries.iter().enumerate() {
        match entry.kind {
            EntryKind::Hole | EntryKind::Bind => {}
            EntryKind::Plain | EntryKind::FileOnly => {
                message.extend_from_slice(file_bytes(image, entry, index)?);
            }
            EntryKind::Relative => {
                for word in file_bytes(image, entry, index)?.chunks_exact(WORD) {
                    let value = unslid(word_value(word)).ok_or(IntegrityError::SlotInvalid(
                        SlotDefect::MalformedEntry(u32::try_from(index).unwrap_or(u32::MAX)),
                    ))?;
                    message.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
    }
    Ok(message)
}

/// The file bytes an entry names.
fn file_bytes<'a>(
    image: &'a [u8],
    entry: &Entry,
    index: usize,
) -> Result<&'a [u8], IntegrityError> {
    let out_of_bounds = || {
        IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(
            u32::try_from(index).unwrap_or(u32::MAX),
        ))
    };
    let start = usize::try_from(entry.file_off).map_err(|_| out_of_bounds())?;
    let end = start
        .checked_add(usize::try_from(entry.len).map_err(|_| out_of_bounds())?)
        .ok_or_else(out_of_bounds)?;
    image.get(start..end).ok_or_else(out_of_bounds)
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
    use std::collections::HashMap;
    use std::path::Path;

    use oxicrypt_ml_dsa::ml_dsa_87;

    use super::{
        Located, MESSAGE_PREFIX, Process, SIGNATURE_CONTEXT, file_signature_input, symbol_of,
        verify,
    };
    use crate::key::{
        KEY_RECORD_FOOTER_MAGIC, KEY_RECORD_HEADER_MAGIC, KEY_RECORD_SIZE, VERIFY_KEY_LEN,
    };
    use crate::slot::{self, BindRecord, Entry, EntryKind, SlotDefect, SlotFields};
    use crate::{IntegrityError, SLOT_SIZE, Unreadable, key_fingerprint};

    /// Where the fixture is linked; its load base is a parameter.
    const LINK_BASE: u64 = 0x1000;
    /// Layout of the fixture, as RVAs. Everything below `SHIFT_FROM` has
    /// file offset equal to RVA; the last segment is one page higher in
    /// memory than in the file, as real ELF segments often are.
    const CODE: u32 = 0;
    const KEY_RVA: u32 = 0x100;
    const RELATIVE: u32 = 0xc00;
    const BIND: u32 = 0xc10;
    const HOLE: u32 = 0xc20;
    const SLOT_RVA: u32 = 0x1000;
    const SHIFT_FROM: u32 = 0x1_2000;
    const SHIFT: u32 = 0x1000;
    /// The `FileOnly` entry, in the shifted segment.
    const FILE_ONLY: u32 = 0x1_2040;
    const FILE_LEN: usize = 0x1_2000;
    const MEMORY_LEN: usize = 0x1_3000;
    /// Two unslid addresses the `Relative` words hold.
    const UNSLID: [u64; 2] = [0x1234, 0x5678];
    /// The address the stub resolver returns for the import.
    const MALLOC: u64 = 0x7fff_0000_1000;
    const IMAGE: &str = "/fixture/libsubject.so";

    /// A fixed ML-DSA-87 key-generation seed ξ.
    fn d(seed: u8) -> [u8; 32] {
        let mut d = [seed; 32];
        d[0] = 0x01;
        d
    }

    /// The public key ξ derives.
    fn public_raw(xi: &[u8; 32]) -> [u8; VERIFY_KEY_LEN] {
        crate::test_support::start_module();
        ml_dsa_87::keygen_internal(xi).unwrap().0
    }

    /// `message` signed with the private key ξ derives, as the signer signs
    /// `M′`.
    fn sign(xi: &[u8; 32], message: &[u8]) -> [u8; slot::SIG_LEN] {
        crate::test_support::start_module();
        let (_, sk) = ml_dsa_87::keygen_internal(xi).unwrap();
        ml_dsa_87::sign_internal(&sk, message).unwrap()
    }

    #[allow(
        clippy::struct_excessive_bools,
        reason = "one switch per failure the stub can be told to produce"
    )]
    /// The test process. Memory is indexed by address from `base`; the file
    /// route goes through the production `locate_image` over `maps`, the
    /// production length rule and `image_base`, so only the bytes are stubbed.
    struct Stub {
        base: u64,
        memory: Vec<u8>,
        /// The whole file the loader mapped from: the image itself, or an
        /// archive holding it at `image_base`.
        file: Vec<u8>,
        maps: String,
        imports: HashMap<String, Option<u64>>,
        /// Other loaded images, each its path and Mach header address.
        loaded: Vec<(&'static str, u64)>,
        /// Bytes of other images the stub can read, each at its address.
        foreign: Vec<(u64, Vec<u8>)>,
        /// The platform binds resolver functions through x86_64 stubs.
        indirect: bool,
        binds: bool,
        resolver_fails: bool,
        unreadable: bool,
        /// Addresses, relative to `base`, the stub cannot read because
        /// nothing is mapped there.
        unmapped: Option<std::ops::Range<usize>>,
        /// Addresses, relative to `base`, that are mapped but whose read
        /// the environment refuses (`ENOMEM`).
        refused: Option<std::ops::Range<usize>>,
        /// Addresses, relative to `base`, that are mapped but whose read
        /// fails as execute-only text does: with this kernel status, or
        /// short when there is none.
        faulting: Option<(std::ops::Range<usize>, Option<i64>)>,
        /// Whether `mapped` cannot tell, as on a platform with no map query.
        mapping_unknown: bool,
    }

    impl Process for Stub {
        fn read(&mut self, addr: u64, out: &mut [u8]) -> Result<(), Unreadable> {
            if self.unreadable {
                return Err(Unreadable::NoMechanism);
            }
            for (at, bytes) in &self.foreign {
                let Some(from) = addr.checked_sub(*at).and_then(|o| usize::try_from(o).ok()) else {
                    continue;
                };
                if let Some(src) = bytes.get(from..from + out.len()) {
                    out.copy_from_slice(src);
                    return Ok(());
                }
            }
            let start = addr
                .checked_sub(self.base)
                .and_then(|o| usize::try_from(o).ok())
                .ok_or(Unreadable::SlotUnmapped)?;
            if let Some(hole) = &self.unmapped
                && start < hole.end
                && start + out.len() > hole.start
            {
                return Err(Unreadable::MemoryRead(std::io::Error::from_raw_os_error(5)));
            }
            if let Some((range, status)) = &self.faulting
                && start < range.end
                && start + out.len() > range.start
            {
                return Err(Unreadable::SelfReadFailed(status.map_or(
                    oxicrypt_imageread::ReadError::Short {
                        wanted: out.len(),
                        got: 0,
                    },
                    oxicrypt_imageread::ReadError::Os,
                )));
            }
            if let Some(busy) = &self.refused
                && start < busy.end
                && start + out.len() > busy.start
            {
                return Err(Unreadable::MemoryRead(std::io::Error::from_raw_os_error(
                    12,
                )));
            }
            let src = self
                .memory
                .get(start..start + out.len())
                .ok_or(Unreadable::SlotUnmapped)?;
            out.copy_from_slice(src);
            Ok(())
        }

        fn locate_file(
            &mut self,
            slot: &SlotFields,
            slot_addr: u64,
            base: u64,
            span: u64,
        ) -> Result<Located, Unreadable> {
            crate::acquire::locate_image(&self.maps, slot, slot_addr, base, span)
        }

        fn file_size(&mut self, path: &Path) -> Result<u64, Unreadable> {
            assert_eq!(path, Path::new(IMAGE));
            Ok(self.file.len() as u64)
        }

        fn read_file(&mut self, _path: &Path, pos: u64, out: &mut [u8]) -> Result<(), Unreadable> {
            let pos = pos as usize;
            let src = self
                .file
                .get(pos..pos + out.len())
                .ok_or_else(|| Unreadable::FileRead(std::io::ErrorKind::UnexpectedEof.into()))?;
            out.copy_from_slice(src);
            Ok(())
        }

        fn resolve(&mut self, record: &BindRecord) -> Result<Option<u64>, Option<Unreadable>> {
            if !self.binds {
                return Err(None);
            }
            if self.resolver_fails {
                return Err(Some(Unreadable::Resolver(
                    oxicrypt_imageread::ReadError::Os(5),
                )));
            }
            let key = match symbol_of(record) {
                oxicrypt_imageread::Symbol::Name(n) => n.to_owned(),
                oxicrypt_imageread::Symbol::Ordinal(o) => format!("#{o}"),
            };
            Ok(self.imports.get(&key).copied().flatten())
        }

        fn loaded_image(&mut self, path: &[u8]) -> Result<Option<u64>, Unreadable> {
            Ok(self
                .loaded
                .iter()
                .find(|(p, _)| p.as_bytes() == path)
                .map(|&(_, base)| base))
        }

        fn indirect_stubs(&self) -> bool {
            self.indirect
        }

        fn mapped(&mut self, addr: u64, len: u64, _slot_addr: u64) -> Option<bool> {
            if self.mapping_unknown {
                return None;
            }
            let start = usize::try_from(addr.checked_sub(self.base)?).ok()?;
            let end = start + usize::try_from(len).ok()?;
            let unmapped = self
                .unmapped
                .as_ref()
                .is_some_and(|h| start < h.end && end > h.start);
            Some(end <= self.memory.len() && !unmapped)
        }

        fn payload_cap(
            &mut self,
            slot_addr: u64,
            base: u64,
            span: u64,
            _file_len: u64,
        ) -> Result<u64, Unreadable> {
            Ok(crate::acquire::mapped_bytes_in(
                &self.maps, slot_addr, base, span,
            ))
        }
    }

    fn put(buf: &mut [u8], at: u32, bytes: &[u8]) {
        let at = at as usize;
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn record(weak: bool, addend: i64) -> BindRecord {
        BindRecord {
            library: "/usr/lib/libSystem.B.dylib".to_owned(),
            symbol: "malloc".to_owned(),
            ordinal: 0,
            addend,
            weak,
        }
    }

    /// How a fixture differs from the ordinary one.
    struct Spec {
        signer: [u8; 32],
        embedded: [u8; VERIFY_KEY_LEN],
        bind: BindRecord,
        bind_word: u64,
        base: u64,
        image_base: u64,
        /// The file's raw `Relative` words, and how the signer unslides them.
        relative_file: [u64; 2],
        unslid: fn(u64) -> Option<u64>,
    }

    fn spec() -> Spec {
        crate::test_support::start_module();
        let me = d(0x42);
        Spec {
            signer: me,
            embedded: public_raw(&me),
            bind: record(false, 0),
            bind_word: MALLOC,
            base: 0x5555_0000_0000,
            image_base: 0,
            relative_file: UNSLID,
            unslid: Some,
        }
    }

    fn entries() -> Vec<Entry> {
        let plain_end = KEY_RVA + KEY_RECORD_SIZE as u32;
        let e = |rva, file_off, len, kind, meta| Entry {
            rva,
            file_off,
            len,
            kind,
            meta,
        };
        vec![
            e(CODE, CODE, plain_end, EntryKind::Plain, 0),
            e(RELATIVE, RELATIVE, 16, EntryKind::Relative, 0),
            e(BIND, BIND, 8, EntryKind::Bind, 0),
            e(HOLE, HOLE, 8, EntryKind::Hole, 0),
            e(FILE_ONLY, FILE_ONLY - SHIFT, 32, EntryKind::FileOnly, 0),
        ]
    }

    /// Builds a signed fixture from `spec`: the file, the loaded image, the
    /// maps line set, and the stub.
    fn build(spec: &Spec) -> Stub {
        crate::test_support::start_module();
        let mut file = vec![0u8; FILE_LEN];
        for (i, b) in file[..KEY_RVA as usize].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&KEY_RECORD_HEADER_MAGIC);
        record_bytes.extend_from_slice(&spec.embedded);
        record_bytes.extend_from_slice(&KEY_RECORD_FOOTER_MAGIC);
        put(&mut file, KEY_RVA, &record_bytes);
        for (i, v) in spec.relative_file.iter().enumerate() {
            put(&mut file, RELATIVE + 8 * i as u32, &v.to_le_bytes());
        }
        put(
            &mut file,
            FILE_ONLY - SHIFT,
            b"initial value of a writable word",
        );

        let fields = SlotFields {
            flags: 0,
            slot_rva: SLOT_RVA,
            key_id: key_fingerprint(&spec.embedded).unwrap(),
            link_base: LINK_BASE,
            slot_file_off: SLOT_RVA,
            file_len: FILE_LEN as u32,
            entries: entries(),
            records: vec![spec.bind.clone()],
        };
        let unsigned = slot::encode(&fields, &[0; slot::SIG_LEN]).unwrap();
        put(&mut file, SLOT_RVA, &unsigned);
        let parsed = slot::parse(&unsigned).unwrap();
        let message = file_signature_input(&file, &unsigned, &parsed, &spec.unslid).unwrap();
        let sig = sign(&spec.signer, &message);
        put(&mut file, SLOT_RVA, &slot::encode(&fields, &sig).unwrap());

        // The loaded image: the shifted segment one page up, then the
        // loader's and the module's writes.
        let slide = spec.base - LINK_BASE;
        let mut memory = vec![0u8; MEMORY_LEN];
        memory[..SHIFT_FROM as usize - SHIFT as usize]
            .copy_from_slice(&file[..SHIFT_FROM as usize - SHIFT as usize]);
        memory[SHIFT_FROM as usize..].copy_from_slice(&file[(SHIFT_FROM - SHIFT) as usize..]);
        for (i, v) in UNSLID.iter().enumerate() {
            put(
                &mut memory,
                RELATIVE + 8 * i as u32,
                &(v + slide).to_le_bytes(),
            );
        }
        put(&mut memory, BIND, &spec.bind_word.to_le_bytes());
        put(&mut memory, HOLE, &[0xee; 8]);
        put(&mut memory, FILE_ONLY, &[0xcc; 32]);

        let mut archive = vec![0u8; spec.image_base as usize];
        archive.extend_from_slice(&file);
        let maps = format!(
            "{:x}-{:x} r-xp {:08x} fd:01 9 {IMAGE}\n{:x}-{:x} rw-p {:08x} fd:01 9 {IMAGE}\n",
            spec.base,
            spec.base + u64::from(SHIFT_FROM - SHIFT),
            spec.image_base,
            spec.base + u64::from(SHIFT_FROM),
            spec.base + MEMORY_LEN as u64,
            spec.image_base + u64::from(SHIFT_FROM - SHIFT),
        );
        Stub {
            base: spec.base,
            memory,
            file: archive,
            maps,
            imports: HashMap::from([
                ("malloc".to_owned(), Some(MALLOC)),
                ("#7".to_owned(), Some(MALLOC + 0x40)),
            ]),
            loaded: Vec::new(),
            foreign: Vec::new(),
            indirect: false,
            binds: true,
            resolver_fails: false,
            unreadable: false,
            unmapped: None,
            refused: None,
            faulting: None,
            mapping_unknown: false,
        }
    }

    fn run(stub: &mut Stub) -> Result<(), IntegrityError> {
        let mut fp = None;
        verify(
            stub,
            stub.base + u64::from(SLOT_RVA),
            stub.base + u64::from(KEY_RVA),
            &mut fp,
        )
    }

    fn good() -> Stub {
        build(&spec())
    }

    #[test]
    fn a_signed_image_verifies_and_reports_its_key() {
        let mut stub = good();
        let mut fp = None;
        verify(
            &mut stub,
            0x5555_0000_0000 + u64::from(SLOT_RVA),
            0x5555_0000_0000 + u64::from(KEY_RVA),
            &mut fp,
        )
        .unwrap();
        assert_eq!(fp, Some(key_fingerprint(&public_raw(&d(0x42))).unwrap()));
    }

    /// Every slot byte but the signature is signed, and each change is
    /// refused for the reason that applies to it.
    #[test]
    fn non_signature_slot_byte_changes_are_refused_with_their_cause() {
        type Expect = fn(&IntegrityError) -> bool;
        let slot_at = SLOT_RVA as usize;
        let cases: &[(usize, Expect)] = &[
            (slot::OFF_VERSION, |e| {
                matches!(
                    e,
                    IntegrityError::SlotInvalid(SlotDefect::UnsupportedVersion(_))
                )
            }),
            (slot::OFF_FLAGS, |e| {
                matches!(e, IntegrityError::SignatureInvalid)
            }),
            (slot::OFF_COUNT, |e| {
                matches!(e, IntegrityError::SlotInvalid(_))
            }),
            (slot::OFF_KEY_ID, |e| {
                matches!(e, IntegrityError::SlotInvalid(SlotDefect::KeyMismatch))
            }),
            (slot::OFF_LINK_BASE, |e| {
                matches!(e, IntegrityError::SignatureInvalid)
            }),
            (slot::OFF_FILE_LEN + 2, |e| {
                matches!(e, IntegrityError::SlotInvalid(SlotDefect::SlotOutsideImage))
            }),
            (slot::OFF_SLOT_FILE_OFF, |e| {
                matches!(
                    e,
                    IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(4))
                )
            }),
            (slot::OFF_TABLE + 1, |e| {
                matches!(e, IntegrityError::SlotInvalid(_))
            }),
            (slot::OFF_FTR - 1, |e| {
                matches!(e, IntegrityError::SlotInvalid(SlotDefect::NonZeroPadding))
            }),
        ];
        for (off, expected) in cases {
            let mut stub = good();
            stub.memory[slot_at + off] ^= 0x01;
            let outcome = run(&mut stub);
            assert!(
                outcome.as_ref().is_err_and(expected),
                "a change at slot offset {off} gave {outcome:?}"
            );
        }
        assert!(run(&mut good()).is_ok(), "control: the fixture passes");
    }

    #[test]
    fn a_flipped_signature_fails() {
        let mut stub = good();
        stub.memory[SLOT_RVA as usize + slot::OFF_SIG] ^= 1;
        assert!(matches!(
            run(&mut stub),
            Err(IntegrityError::SignatureInvalid)
        ));
    }

    /// The signed slot of the [`good`] fixture and its signature input `M`,
    /// without the framing, rebuilt from the file.
    fn slot_and_unframed_input(stub: &Stub) -> (Vec<u8>, Vec<u8>) {
        let slot_bytes = stub.file[SLOT_RVA as usize..SLOT_RVA as usize + SLOT_SIZE].to_vec();
        let parsed = slot::parse(&slot_bytes).unwrap();
        let framed = file_signature_input(&stub.file, &slot_bytes, &parsed, &Some).unwrap();
        assert_eq!(framed[..MESSAGE_PREFIX.len()], MESSAGE_PREFIX);
        (slot_bytes, framed[MESSAGE_PREFIX.len()..].to_vec())
    }

    /// Writes `sig` into the loaded slot's signature field.
    fn resign(stub: &mut Stub, sig: &[u8; slot::SIG_LEN]) {
        let at = SLOT_RVA as usize + slot::OFF_SIG;
        stub.memory[at..at + slot::SIG_LEN].copy_from_slice(sig);
    }

    /// The prefix is FIPS 204's external framing of [`SIGNATURE_CONTEXT`],
    /// and a signature the module accepts is one the gated external
    /// interface accepts over `M` under that context.
    #[test]
    fn the_framing_is_fips_204_external_framing_under_the_context() {
        assert_eq!(SIGNATURE_CONTEXT, b"oxicrypt-integrity");
        assert_eq!(MESSAGE_PREFIX[0], 0x00);
        assert_eq!(usize::from(MESSAGE_PREFIX[1]), SIGNATURE_CONTEXT.len());
        assert_eq!(&MESSAGE_PREFIX[2..], SIGNATURE_CONTEXT);

        let stub = good();
        let (slot_bytes, unframed) = slot_and_unframed_input(&stub);
        let sig: [u8; slot::SIG_LEN] = slot_bytes[slot::OFF_SIG..slot::OFF_SIG + slot::SIG_LEN]
            .try_into()
            .unwrap();
        let pk = public_raw(&d(0x42));
        let mut framed = MESSAGE_PREFIX.to_vec();
        framed.extend_from_slice(&unframed);
        assert!(ml_dsa_87::verify_internal(&pk, &framed, &sig).unwrap());
        // Control: the same signature does not verify over `M` alone.
        assert!(!ml_dsa_87::verify_internal(&pk, &unframed, &sig).unwrap());

        // The gated external interface, which frames `M` itself, agrees
        // once the module is operational.
        assert!(oxicrypt_module::is_operational());
        assert!(ml_dsa_87::verify(&pk, &unframed, SIGNATURE_CONTEXT, &sig).is_ok());
        // Control: under another context it refuses the same signature.
        assert!(ml_dsa_87::verify(&pk, &unframed, b"oxicrypt-integritz", &sig).is_err());
    }

    /// The gated external `sign(sk, M, SIGNATURE_CONTEXT)` the signer uses
    /// writes exactly the signature `sign_internal(sk, MESSAGE_PREFIX ‖ M)`
    /// writes, and that signature is a fixed one, for a fixed seed and
    /// message.
    #[test]
    fn the_external_signature_is_the_internal_one_over_the_framed_message() {
        crate::test_support::start_module();
        assert!(oxicrypt_module::is_operational());
        let (_, sk) = ml_dsa_87::keygen_internal(&d(0x42)).unwrap();
        let message = b"oxicrypt integrity golden message";
        let external = ml_dsa_87::sign(&sk, message, SIGNATURE_CONTEXT).unwrap();
        let mut framed = MESSAGE_PREFIX.to_vec();
        framed.extend_from_slice(message);
        let internal = ml_dsa_87::sign_internal(&sk, &framed).unwrap();
        assert_eq!(external, internal, "the two signatures differ");
        // The fixed answer: SHA-256 of the signature, for this seed and
        // message, so a change to the framing or to signing that moves both
        // sides together is still caught.
        let digest = oxicrypt_sha::sha256::sha256(&external).unwrap();
        assert_eq!(
            crate::format_fingerprint(&digest),
            "sha256:a777a3bcbb21a824810a11a91aeff6342cef8a7e2c88c9c86d11412aa7bb05f5"
        );
        // Control: the unframed message gives a different signature.
        let unframed = ml_dsa_87::sign_internal(&sk, message).unwrap();
        assert_ne!(external, unframed);
    }

    /// A signature over the signature input `M` without the framing, made
    /// with the right key, is refused.
    #[test]
    fn a_signature_over_the_unframed_input_is_refused() {
        let mut stub = good();
        let (_, unframed) = slot_and_unframed_input(&stub);
        resign(&mut stub, &sign(&d(0x42), &unframed));
        assert!(matches!(
            run(&mut stub),
            Err(IntegrityError::SignatureInvalid)
        ));
        // Control: the framed message, signed the same way, verifies.
        let mut framed = MESSAGE_PREFIX.to_vec();
        framed.extend_from_slice(&unframed);
        resign(&mut stub, &sign(&d(0x42), &framed));
        assert!(run(&mut stub).is_ok());
    }

    /// A signature over `M` under another context string, made with the
    /// right key, is refused.
    #[test]
    fn a_signature_under_another_context_is_refused() {
        let mut stub = good();
        let (_, unframed) = slot_and_unframed_input(&stub);
        for ctx in [&b"oxicrypt-integritz"[..], b"", b"oxicrypt"] {
            let mut framed = vec![0x00, u8::try_from(ctx.len()).unwrap()];
            framed.extend_from_slice(ctx);
            framed.extend_from_slice(&unframed);
            resign(&mut stub, &sign(&d(0x42), &framed));
            assert!(
                matches!(run(&mut stub), Err(IntegrityError::SignatureInvalid)),
                "context {ctx:?} was accepted"
            );
        }
    }

    /// A flip of any one bit of the signature is refused, wherever it falls:
    /// the challenge, the response or the hint.
    #[test]
    fn a_one_bit_signature_flip_is_refused_anywhere_in_the_field() {
        for (byte, bit) in [(0, 0), (63, 7), (64, 0), (2_000, 3), (slot::SIG_LEN - 1, 7)] {
            let mut stub = good();
            stub.memory[SLOT_RVA as usize + slot::OFF_SIG + byte] ^= 1 << bit;
            assert!(
                matches!(run(&mut stub), Err(IntegrityError::SignatureInvalid)),
                "a flip of bit {bit} of signature byte {byte} was accepted"
            );
        }
    }

    /// A version-3 slot is refused by its version as damage, never read
    /// under the version-4 layout.
    #[test]
    fn a_version_3_slot_is_refused() {
        use crate::IntegrityStatus;
        let mut stub = good();
        let at = SLOT_RVA as usize + slot::OFF_VERSION;
        stub.memory[at..at + 4].copy_from_slice(&3u32.to_le_bytes());
        let outcome = run(&mut stub);
        assert!(
            matches!(
                outcome,
                Err(IntegrityError::SlotInvalid(SlotDefect::UnsupportedVersion(
                    3
                )))
            ),
            "{outcome:?}"
        );
        assert_eq!(IntegrityStatus::of(&outcome), IntegrityStatus::SlotDamaged);
    }

    #[test]
    fn a_signature_made_with_another_key_fails() {
        let mut s = spec();
        s.signer = d(0x24);
        assert!(matches!(
            run(&mut build(&s)),
            Err(IntegrityError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_key_id_for_another_key_is_a_key_mismatch() {
        let mut stub = good();
        put(&mut stub.memory, KEY_RVA + 16, &public_raw(&d(0x24)));
        assert!(matches!(
            run(&mut stub),
            Err(IntegrityError::SlotInvalid(SlotDefect::KeyMismatch))
        ));
    }

    #[test]
    fn an_all_zero_key_record_is_no_verify_key() {
        let mut stub = good();
        put(&mut stub.memory, KEY_RVA + 16, &[0u8; VERIFY_KEY_LEN]);
        assert!(matches!(run(&mut stub), Err(IntegrityError::NoVerifyKey)));
    }

    #[test]
    fn a_damaged_key_record_magic_is_a_key_record_defect() {
        for off in [KEY_RVA, KEY_RVA + KEY_RECORD_SIZE as u32 - 1] {
            let mut stub = good();
            stub.memory[off as usize] ^= 1;
            assert!(matches!(
                run(&mut stub),
                Err(IntegrityError::SlotInvalid(SlotDefect::KeyRecord))
            ));
        }
    }

    /// The fixture loads at a slide of `base - LINK_BASE`; the words pass
    /// only because the verifier subtracts it, and a changed word fails.
    #[test]
    fn relative_words_are_checked_after_the_slide_is_removed() {
        assert!(run(&mut good()).is_ok());
        let slide = 0x5555_0000_0000 - LINK_BASE;
        let mut stub = good();
        put(
            &mut stub.memory,
            RELATIVE,
            &(UNSLID[0] + slide + 8).to_le_bytes(),
        );
        assert!(matches!(
            run(&mut stub),
            Err(IntegrityError::SignatureInvalid)
        ));
        let mut unslid = good();
        put(&mut unslid.memory, RELATIVE, &UNSLID[0].to_le_bytes());
        assert!(run(&mut unslid).is_err());
    }

    /// A Mach-O chained rebase: the file holds the target, `high8` and the
    /// chain's `next` field, not the address. The signer unslides it with
    /// the format's decoder into the value the loader writes less the slide,
    /// which is what the verifier computes; signing the raw file word
    /// instead fails.
    #[test]
    fn a_chained_rebase_verifies_when_signed_in_canonical_form() {
        // DYLD_CHAINED_PTR_64: target in bits 0..36, next in bits 51..63.
        let chained = |target: u64| target | (2u64 << 51);
        let decode = |raw: u64| -> Option<u64> {
            if raw >> 63 != 0 {
                return None;
            }
            Some((raw & 0xf_ffff_ffff) | (((raw >> 36) & 0xff) << 56))
        };
        let mut s = spec();
        s.relative_file = [chained(UNSLID[0]), chained(UNSLID[1])];
        s.unslid = decode;
        assert!(run(&mut build(&s)).is_ok());
        // Control: the raw file words, signed as they are, do not verify.
        s.unslid = Some;
        assert!(matches!(
            run(&mut build(&s)),
            Err(IntegrityError::SignatureInvalid)
        ));
    }

    #[test]
    fn bind_words_are_checked_against_the_resolver() {
        let with = |bind: BindRecord, word: u64| {
            let mut s = spec();
            s.bind = bind;
            s.bind_word = word;
            build(&s)
        };
        assert!(run(&mut with(record(false, 0), MALLOC)).is_ok());
        assert!(run(&mut with(record(false, -16), MALLOC - 16)).is_ok());
        assert!(matches!(
            run(&mut with(record(false, 0), MALLOC + 16)),
            Err(IntegrityError::SignatureInvalid)
        ));
        let mut swapped = with(record(false, 0), MALLOC);
        swapped
            .imports
            .insert("malloc".to_owned(), Some(MALLOC + 0x1000));
        assert!(matches!(
            run(&mut swapped),
            Err(IntegrityError::SignatureInvalid)
        ));
        let mut weak_zero = with(record(true, 0), 0);
        weak_zero.imports.insert("malloc".to_owned(), None);
        assert!(run(&mut weak_zero).is_ok());
        let mut weak_wrong = with(record(true, 0), 0x40);
        weak_wrong.imports.insert("malloc".to_owned(), None);
        assert!(matches!(
            run(&mut weak_wrong),
            Err(IntegrityError::SignatureInvalid)
        ));
        let mut missing = with(record(false, 0), MALLOC);
        missing.imports.insert("malloc".to_owned(), None);
        assert!(matches!(
            run(&mut missing),
            Err(IntegrityError::SlotInvalid(SlotDefect::UnresolvedImport(2)))
        ));
        let mut unsupported = with(record(false, 0), MALLOC);
        unsupported.binds = false;
        assert!(matches!(
            run(&mut unsupported),
            Err(IntegrityError::SlotInvalid(SlotDefect::BindUnsupported(2)))
        ));
        let mut failing = with(record(false, 0), MALLOC);
        failing.resolver_fails = true;
        assert!(matches!(
            run(&mut failing),
            Err(IntegrityError::Unreadable(Unreadable::Resolver(_)))
        ));
    }

    /// Where the foreign images' `__TEXT` was linked, and their
    /// `__LINKEDIT`'s address and file offset: deliberately not 0, and not
    /// equal, so the trie's address takes the slide and the offset both.
    const TEXT_LINK: u64 = 0x7000_0000;
    const LINKEDIT_VM: u64 = TEXT_LINK + 0xa000;
    const LINKEDIT_OFF: u32 = 0x9000;
    const TRIE_OFF: u32 = 0x9100;

    /// The Mach header, load commands and export trie of a foreign image
    /// whose header is at `base`, listing `dylibs` as its dependents, each
    /// an `LC_REEXPORT_DYLIB` when marked; the trie's recorded length is
    /// `declared`.
    fn foreign_image(
        base: u64,
        trie: &[u8],
        declared: u32,
        dylibs: &[(&str, bool)],
    ) -> Vec<(u64, Vec<u8>)> {
        let seg = |name: &[u8], vmaddr: u64, fileoff: u64, filesize: u64| {
            let mut c = vec![0u8; 72];
            c[..4].copy_from_slice(&0x19u32.to_le_bytes());
            c[4..8].copy_from_slice(&72u32.to_le_bytes());
            c[8..8 + name.len()].copy_from_slice(name);
            c[24..32].copy_from_slice(&vmaddr.to_le_bytes());
            c[40..48].copy_from_slice(&fileoff.to_le_bytes());
            c[48..56].copy_from_slice(&filesize.to_le_bytes());
            c
        };
        let mut cmds = seg(b"__TEXT", TEXT_LINK, 0, 0x9000);
        cmds.extend(seg(
            b"__LINKEDIT",
            LINKEDIT_VM,
            u64::from(LINKEDIT_OFF),
            0x1000,
        ));
        let mut et = vec![0u8; 16];
        et[..4].copy_from_slice(&0x8000_0033u32.to_le_bytes());
        et[4..8].copy_from_slice(&16u32.to_le_bytes());
        et[8..12].copy_from_slice(&TRIE_OFF.to_le_bytes());
        et[12..16].copy_from_slice(&declared.to_le_bytes());
        cmds.extend(et);
        for (path, whole) in dylibs {
            let size = (24 + path.len() + 1).next_multiple_of(8);
            let mut c = vec![0u8; size];
            let cmd: u32 = if *whole { 0x8000_001f } else { 0xc };
            c[..4].copy_from_slice(&cmd.to_le_bytes());
            c[4..8].copy_from_slice(&(size as u32).to_le_bytes());
            c[8..12].copy_from_slice(&24u32.to_le_bytes());
            c[24..24 + path.len()].copy_from_slice(path.as_bytes());
            cmds.extend(c);
        }
        let mut header = vec![0u8; 32];
        header[..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        header[16..20].copy_from_slice(&(3 + dylibs.len() as u32).to_le_bytes());
        header[20..24].copy_from_slice(&(cmds.len() as u32).to_le_bytes());
        header.extend(cmds);
        let trie_at = LINKEDIT_VM + (base - TEXT_LINK) + u64::from(TRIE_OFF - LINKEDIT_OFF);
        vec![(base, header), (trie_at, trie.to_vec())]
    }

    /// A word bound to an x86_64 resolver stub: accepted only when the
    /// import, resolved by name from the record's library through its
    /// re-exports as dyld resolves it, ends at a stub-and-resolver export
    /// whose stub is the word, the word is `FF 25`, there is no addend, and
    /// the platform binds through such stubs. The stub's pointer is not
    /// read: it is bound lazily.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture and every case it must refuse, side by side"
    )]
    fn a_resolver_stub_bind_is_accepted_only_where_the_export_tries_lead() {
        use crate::trie::tests::{plain, reexport, stub, trie};
        const SYSTEM: &str = "/usr/lib/libSystem.B.dylib";
        const PLATFORM: &str = "/usr/lib/system/libsystem_platform.dylib";
        const SYSTEM_AT: u64 = 0x7fff_7000_0000;
        const PLATFORM_AT: u64 = MALLOC - 0x1000;
        const STUB: u64 = MALLOC + 0x6000;
        const OFF: u64 = STUB - PLATFORM_AT;
        let jmp = vec![0xff, 0x25, 0x10, 0x20, 0, 0];
        // libSystem's trie, libsystem_platform's trie, the bytes at the word.
        let place = |bind: BindRecord,
                     system: Vec<u8>,
                     platform: Vec<u8>,
                     platform_deps: &[(&str, bool)],
                     code: Vec<u8>,
                     indirect: bool| {
            let mut s = spec();
            s.bind = bind;
            s.bind_word = STUB;
            let mut st = build(&s);
            st.loaded = vec![(SYSTEM, SYSTEM_AT), (PLATFORM, PLATFORM_AT)];
            st.foreign = foreign_image(
                SYSTEM_AT,
                &system,
                system.len() as u32,
                &[(PLATFORM, false)],
            );
            st.foreign.extend(foreign_image(
                PLATFORM_AT,
                &platform,
                platform.len() as u32,
                platform_deps,
            ));
            st.foreign.push((STUB, code));
            st.indirect = indirect;
            st.imports.insert("m0".to_owned(), Some(MALLOC));
            st
        };
        let renamed = || {
            trie(&[
                ("_free", plain(0x100)),
                ("_malloc", reexport(1, "__platform_malloc")),
            ])
        };
        let platform = || trie(&[("__platform_malloc", stub(OFF, 0x7da4))]);
        let ok = |st: Stub| {
            let mut st = st;
            assert!(run(&mut st).is_ok());
        };
        let refused = |mut st: Stub| {
            assert!(matches!(
                run(&mut st),
                Err(IntegrityError::SignatureInvalid)
            ));
        };
        let unreadable = |mut st: Stub| {
            assert!(matches!(run(&mut st), Err(IntegrityError::Unreadable(_))));
        };
        // A renamed re-export, for a strong and a weak import, and a
        // re-export that keeps its name.
        ok(place(
            record(false, 0),
            renamed(),
            platform(),
            &[],
            jmp.clone(),
            true,
        ));
        ok(place(
            record(true, 0),
            renamed(),
            platform(),
            &[],
            jmp.clone(),
            true,
        ));
        ok(place(
            record(false, 0),
            trie(&[("_malloc", reexport(1, ""))]),
            trie(&[("_malloc", stub(OFF, 0x7da4))]),
            &[],
            jmp.clone(),
            true,
        ));
        // The stub is reached only under another name.
        refused(place(
            record(false, 0),
            trie(&[
                ("_free", reexport(1, "__platform_malloc")),
                ("_malloc", plain(0x100)),
            ]),
            platform(),
            &[],
            jmp.clone(),
            true,
        ));
        // The chain ends at a plain export, or at no entry.
        refused(place(
            record(false, 0),
            renamed(),
            trie(&[("__platform_malloc", plain(OFF))]),
            &[],
            jmp.clone(),
            true,
        ));
        refused(place(
            record(false, 0),
            renamed(),
            trie(&[("__platform_free", stub(OFF, 0))]),
            &[],
            jmp.clone(),
            true,
        ));
        // The stub one byte away, `call *disp32(%rip)`, an addend, arm64.
        refused(place(
            record(false, 0),
            renamed(),
            trie(&[("__platform_malloc", stub(OFF + 1, 0))]),
            &[],
            jmp.clone(),
            true,
        ));
        refused(place(
            record(false, 0),
            renamed(),
            platform(),
            &[],
            vec![0xff, 0x15, 0, 0, 0, 0],
            true,
        ));
        refused(place(
            record(false, 16),
            renamed(),
            platform(),
            &[],
            jmp.clone(),
            true,
        ));
        refused(place(
            record(false, 0),
            renamed(),
            platform(),
            &[],
            jmp.clone(),
            false,
        ));
        // A cycle back to libSystem's `_malloc`.
        unreadable(place(
            record(false, 0),
            renamed(),
            trie(&[("__platform_malloc", reexport(1, "_malloc"))]),
            &[(SYSTEM, false)],
            jmp.clone(),
            true,
        ));
        // A chain of nine re-exports inside libsystem_platform.
        let long: Vec<(String, Vec<u8>)> = (b'a'..=b'i')
            .map(|c| {
                let next = format!("_{}", char::from(c + 1));
                (format!("_{}", char::from(c)), reexport(1, &next))
            })
            .collect();
        let long_ref: Vec<(&str, Vec<u8>)> =
            long.iter().map(|(n, p)| (n.as_str(), p.clone())).collect();
        let deep = BindRecord {
            symbol: "m0".to_owned(),
            ..record(false, 0)
        };
        unreadable(place(
            deep,
            trie(&[("_m0", reexport(1, "_a"))]),
            trie(&long_ref),
            &[(PLATFORM, false)],
            jmp.clone(),
            true,
        ));
        // The bound exactly: eight nested re-exports reach the stub, nine
        // do not.
        let nested = |n: u8| {
            let mut entries: Vec<(String, Vec<u8>)> = (1..n)
                .map(|i| (format!("_c{i}"), reexport(1, &format!("_c{}", i + 1))))
                .collect();
            entries.push((format!("_c{n}"), stub(OFF, 0x7da4)));
            let entries: Vec<(&str, Vec<u8>)> = entries
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect();
            place(
                BindRecord {
                    symbol: "m0".to_owned(),
                    ..record(false, 0)
                },
                trie(&[("_m0", reexport(1, "_c1"))]),
                trie(&entries),
                &[(PLATFORM, false)],
                jmp.clone(),
                true,
            )
        };
        ok(nested(8));
        unreadable(nested(9));
        // The cycle is refused where it closes, at the third image looked
        // in, not when the depth bound would stop it.
        let mut cycle = place(
            record(false, 0),
            renamed(),
            trie(&[("__platform_malloc", reexport(1, "_malloc"))]),
            &[(SYSTEM, false)],
            jmp.clone(),
            true,
        );
        let mut hops = Vec::new();
        assert!(
            crate::trie::resolve_stub(&mut cycle, SYSTEM.as_bytes(), b"_malloc", &mut hops)
                .is_err()
        );
        assert_eq!(hops.len(), 2);
        // A library that is not loaded.
        let mut absent = place(
            record(false, 0),
            renamed(),
            platform(),
            &[],
            jmp.clone(),
            true,
        );
        absent.loaded.truncate(1);
        unreadable(absent);
        // A truncated trie, and a ULEB past 64 bits.
        let mut cut = platform();
        cut.truncate(cut.len() - 3);
        unreadable(place(
            record(false, 0),
            renamed(),
            cut,
            &[],
            jmp.clone(),
            true,
        ));
        let mut over = vec![0u8, 1, b'_', 0, 5];
        over.extend([0xff; 11]);
        unreadable(place(
            record(false, 0),
            renamed(),
            over,
            &[],
            jmp.clone(),
            true,
        ));
        // A header that cannot be read.
        let mut no_header = place(
            record(false, 0),
            renamed(),
            platform(),
            &[],
            jmp.clone(),
            true,
        );
        no_header.foreign.retain(|(at, _)| *at != PLATFORM_AT);
        unreadable(no_header);
        // An export range past __LINKEDIT's file bytes.
        let mut outside = place(
            record(false, 0),
            renamed(),
            platform(),
            &[],
            jmp.clone(),
            true,
        );
        outside.foreign = foreign_image(SYSTEM_AT, &renamed(), 0x2000, &[(PLATFORM, false)]);
        unreadable(outside);
    }

    /// An umbrella library exports a name through the libraries it
    /// re-exports whole: on a miss in its own trie each `LC_REEXPORT_DYLIB`
    /// dependent is searched in order, and the first that exports the name
    /// decides. Here the umbrella's trie is empty, the first dependent lacks
    /// the name, and the second re-exports it, renamed, to the stub.
    #[test]
    fn an_umbrella_resolves_through_the_libraries_it_re_exports_whole() {
        use crate::trie::tests::{plain, reexport, stub, trie};
        const SYSTEM: &str = "/usr/lib/libSystem.B.dylib";
        const C: &str = "/usr/lib/system/libsystem_c.dylib";
        const MALLOC_LIB: &str = "/usr/lib/system/libsystem_malloc.dylib";
        const PLATFORM: &str = "/usr/lib/system/libsystem_platform.dylib";
        const SYSTEM_AT: u64 = 0x7fff_7000_0000;
        const C_AT: u64 = 0x7fff_7100_0000;
        const MALLOC_AT: u64 = 0x7fff_7200_0000;
        const PLATFORM_AT: u64 = MALLOC - 0x1000;
        const STUB: u64 = MALLOC + 0x6000;
        let umbrella_with = |c: Vec<u8>, deps: &[(&str, bool)]| {
            let mut s = spec();
            s.bind_word = STUB;
            let mut st = build(&s);
            st.indirect = true;
            st.loaded = vec![
                (SYSTEM, SYSTEM_AT),
                (C, C_AT),
                (MALLOC_LIB, MALLOC_AT),
                (PLATFORM, PLATFORM_AT),
            ];
            let empty = trie(&[]);
            let malloc = trie(&[("_malloc", reexport(1, "__platform_malloc"))]);
            let platform = trie(&[("__platform_malloc", stub(STUB - PLATFORM_AT, 0x7da4))]);
            st.foreign = foreign_image(SYSTEM_AT, &empty, empty.len() as u32, deps);
            st.foreign
                .extend(foreign_image(C_AT, &c, c.len() as u32, &[]));
            st.foreign.extend(foreign_image(
                MALLOC_AT,
                &malloc,
                malloc.len() as u32,
                &[(PLATFORM, false)],
            ));
            st.foreign.extend(foreign_image(
                PLATFORM_AT,
                &platform,
                platform.len() as u32,
                &[],
            ));
            st.foreign.push((STUB, vec![0xff, 0x25, 0x10, 0x20, 0, 0]));
            st
        };
        let umbrella =
            |deps: &[(&str, bool)]| umbrella_with(trie(&[("_free", plain(0x100))]), deps);
        assert!(run(&mut umbrella(&[(C, true), (MALLOC_LIB, true)])).is_ok());
        // A dependent that exports the name as anything else decides:
        // the search stops there and the stub behind it is not reached.
        assert!(matches!(
            run(&mut umbrella_with(
                trie(&[("_malloc", plain(0x100))]),
                &[(C, true), (MALLOC_LIB, true)]
            )),
            Err(IntegrityError::SignatureInvalid)
        ));
        // Dependents loaded but not re-exported whole are not searched.
        assert!(matches!(
            run(&mut umbrella(&[(C, true), (MALLOC_LIB, false)])),
            Err(IntegrityError::SignatureInvalid)
        ));
        // The name is in none of the dependents.
        assert!(matches!(
            run(&mut umbrella(&[(C, true)])),
            Err(IntegrityError::SignatureInvalid)
        ));
        // The name behind forty-five dependents that lack it, as libSystem
        // holds about forty: still within the cap.
        let mut late = vec![(C, true); 45];
        late.push((MALLOC_LIB, true));
        assert!(run(&mut umbrella(&late)).is_ok());
        // More images than one resolution may look in.
        let many = vec![(C, true); 300];
        assert!(matches!(
            run(&mut umbrella(&many)),
            Err(IntegrityError::Unreadable(_))
        ));
        // A dependent re-exported whole that is not loaded.
        let mut absent = umbrella(&[(C, true), (MALLOC_LIB, true)]);
        absent.loaded.retain(|(path, _)| *path != C);
        assert!(matches!(
            run(&mut absent),
            Err(IntegrityError::Unreadable(_))
        ));
    }

    /// An import by ordinal resolves by its ordinal, not by a name.
    #[test]
    fn an_ordinal_import_resolves_by_ordinal() {
        let ordinal = BindRecord {
            library: "KERNEL32.dll".to_owned(),
            symbol: String::new(),
            ordinal: 7,
            addend: 0,
            weak: false,
        };
        let mut s = spec();
        s.bind = ordinal.clone();
        s.bind_word = MALLOC + 0x40;
        assert!(run(&mut build(&s)).is_ok());
        s.bind_word = MALLOC;
        assert!(matches!(
            run(&mut build(&s)),
            Err(IntegrityError::SignatureInvalid)
        ));
    }

    /// `FileOnly` bytes come from the file, at `image_base + file_off`, in a
    /// segment one page higher in memory than in the file.
    #[test]
    fn file_only_bytes_come_from_the_file_route() {
        assert!(run(&mut good()).is_ok());
        let mut edited = good();
        edited.file[(FILE_ONLY - SHIFT) as usize] ^= 1;
        assert!(matches!(
            run(&mut edited),
            Err(IntegrityError::SignatureInvalid)
        ));
        let mut longer = good();
        longer.file.push(0);
        // `file_len` is unauthenticated when the length is checked, so the
        // mismatch is reported as the slot's, never as the environment's.
        assert!(matches!(
            run(&mut longer),
            Err(IntegrityError::SlotInvalid(SlotDefect::FileLenMismatch))
        ));
    }

    /// The same image mapped out of an archive at `image_base` 0x40000
    /// verifies, reading `FileOnly` from the archive at that offset; the
    /// archive may be longer than the image.
    #[test]
    fn an_archive_mapped_image_reads_at_its_image_base() {
        let mut s = spec();
        s.image_base = 0x4_0000;
        let mut stub = build(&s);
        stub.file.extend_from_slice(&[0u8; 0x2000]);
        assert!(run(&mut stub).is_ok());
        // Control: the FileOnly bytes at the archive's start are not ours.
        let mut wrong = build(&s);
        let at = (FILE_ONLY - SHIFT) as usize;
        wrong.file[at] ^= 1;
        assert!(
            run(&mut wrong).is_ok(),
            "bytes before image_base are not read"
        );
        wrong.file[0x4_0000 + at] ^= 1;
        assert!(matches!(
            run(&mut wrong),
            Err(IntegrityError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_hole_is_not_hashed() {
        let mut stub = good();
        put(&mut stub.memory, HOLE, &[0x11; 8]);
        assert!(run(&mut stub).is_ok());
    }

    #[test]
    fn an_image_that_cannot_be_read_is_unreadable() {
        let mut stub = good();
        stub.unreadable = true;
        assert!(matches!(run(&mut stub), Err(IntegrityError::Unreadable(_))));
    }

    #[test]
    fn a_changed_plain_byte_fails() {
        let mut stub = good();
        stub.memory[CODE as usize + 5] ^= 0x80;
        assert!(matches!(
            run(&mut stub),
            Err(IntegrityError::SignatureInvalid)
        ));
    }

    /// Once the key and slot have been read, a read the slot sends past the
    /// image is damage to the slot, not an unreadable environment.
    #[test]
    fn an_entry_beyond_the_image_is_out_of_bounds() {
        let mut stub = good();
        stub.unmapped = Some(RELATIVE as usize..RELATIVE as usize + 16);
        let outcome = run(&mut stub);
        assert!(matches!(
            outcome,
            Err(IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(1)))
        ));
        assert_eq!(
            crate::IntegrityStatus::of(&outcome),
            crate::IntegrityStatus::SlotDamaged
        );
    }

    /// Dropping a [`Wiped`] buffer zeroes every byte it ever held, including
    /// bytes past a shortened length, and dropping a [`Secret`] zeroes it.
    #[test]
    fn dropping_a_wiped_buffer_or_secret_zeroes_it() {
        let _ = super::wipe_witness::take();
        let mut w = super::Wiped::with_capacity(64).unwrap();
        w.0.extend_from_slice(&[0xa5; 64]);
        w.0.truncate(8);
        drop(w);
        assert_eq!(super::wipe_witness::take(), Some(true));
        drop(super::Secret([0x5a; 32]));
        assert_eq!(super::wipe_witness::take(), Some(true));
        // Control: nothing dropped, nothing recorded.
        assert_eq!(super::wipe_witness::take(), None);
    }

    /// A read the kernel faults on memory `mapped` reports as mapped, such
    /// as execute-only text read through `process_vm_readv`, is the
    /// environment's refusal, whatever its errno: `Unreadable`, not damage.
    /// Only when `mapped` cannot tell do the errno and a short read decide.
    #[test]
    fn a_fault_reading_mapped_memory_is_unreadable() {
        // The platform's "not mapped" status, then a short read.
        let unmapped_code = [14, 1, 487]
            .into_iter()
            .find(|&c| super::unmapped_status(c));
        let range = RELATIVE as usize..RELATIVE as usize + 16;
        for error in [unmapped_code, None] {
            let mut stub = good();
            stub.faulting = Some((range.clone(), error));
            let outcome = run(&mut stub);
            assert!(
                matches!(
                    outcome,
                    Err(IntegrityError::Unreadable(Unreadable::SelfReadFailed(_)))
                ),
                "{error:?}: {outcome:?}"
            );
            assert_eq!(
                crate::IntegrityStatus::of(&outcome),
                crate::IntegrityStatus::Unreadable
            );
            // Control: when `mapped` cannot tell, the same failure is read
            // as an address outside the image.
            let mut unknown = good();
            unknown.faulting = Some((range.clone(), error));
            unknown.mapping_unknown = true;
            assert!(
                matches!(
                    run(&mut unknown),
                    Err(IntegrityError::SlotInvalid(SlotDefect::EntryOutOfBounds(1)))
                ),
                "{error:?} with no map query"
            );
        }
    }

    /// A read of mapped memory the environment refuses (memory pressure,
    /// an I/O error, a guarded page) is the environment's fault: the test
    /// was not performed, and the module is not called damaged.
    #[test]
    fn an_environment_fault_reading_an_entry_is_unreadable() {
        let mut stub = good();
        stub.refused = Some(RELATIVE as usize..RELATIVE as usize + 16);
        let outcome = run(&mut stub);
        assert!(
            matches!(
                outcome,
                Err(IntegrityError::Unreadable(Unreadable::MemoryRead(_)))
            ),
            "{outcome:?}"
        );
        assert_eq!(
            crate::IntegrityStatus::of(&outcome),
            crate::IntegrityStatus::Unreadable
        );
        // A bound import this platform cannot resolve was not written by
        // the signer for this platform: damage, not the environment.
        let mut limited = good();
        limited.binds = false;
        assert_eq!(
            crate::IntegrityStatus::of(&run(&mut limited)),
            crate::IntegrityStatus::SlotDamaged
        );
    }

    /// The unsigned template is the one slot reported as unsigned rather
    /// than damaged. The same slot with a single byte changed, a signed
    /// slot's version set to 3 or 2, or a damaged magic, is damage.
    #[test]
    fn only_the_unsigned_template_is_reported_as_unsigned() {
        use crate::IntegrityStatus;
        let template = |stub: &mut Stub| {
            let at = SLOT_RVA as usize;
            oxicrypt_zeroize::zeroize(&mut stub.memory[at..at + SLOT_SIZE]);
            stub.memory[at..at + 16].copy_from_slice(&crate::SLOT_HEADER_MAGIC);
            stub.memory[at + slot::OFF_FTR..at + SLOT_SIZE]
                .copy_from_slice(&crate::SLOT_FOOTER_MAGIC);
        };
        let mut unsigned = good();
        template(&mut unsigned);
        let outcome = run(&mut unsigned);
        assert!(matches!(
            outcome,
            Err(IntegrityError::SlotInvalid(SlotDefect::Unsigned))
        ));
        assert_eq!(IntegrityStatus::of(&outcome), IntegrityStatus::SlotInvalid);

        let mut touched = good();
        template(&mut touched);
        touched.memory[SLOT_RVA as usize + 100] = 1;
        assert_eq!(
            IntegrityStatus::of(&run(&mut touched)),
            IntegrityStatus::SlotDamaged
        );

        for (off, value) in [
            (slot::OFF_VERSION, 3u8),
            (slot::OFF_VERSION, 2u8),
            (slot::OFF_VERSION, 0u8),
            (0, 0u8),
            (slot::OFF_FTR, 0u8),
        ] {
            let mut stub = good();
            stub.memory[SLOT_RVA as usize + off] = value;
            assert_eq!(
                IntegrityStatus::of(&run(&mut stub)),
                IntegrityStatus::SlotDamaged,
                "a signed slot with byte {off} set to {value} must be damage, never 'sign it'"
            );
        }
    }

    /// A slot whose recorded RVA exceeds its own address yields no load
    /// base. Reachable only for an image loaded below 4 GiB.
    #[test]
    fn a_slot_rva_past_its_address_is_refused() {
        let mut s = spec();
        s.base = 0x1000_0000;
        let mut stub = build(&s);
        let at = SLOT_RVA as usize + slot::OFF_SLOT_RVA;
        stub.memory[at..at + 4].copy_from_slice(&0xf000_0000u32.to_le_bytes());
        assert!(matches!(
            run(&mut stub),
            Err(IntegrityError::SlotInvalid(SlotDefect::SlotRvaTooLarge))
        ));
    }

    #[test]
    fn a_low_slot_rva_still_verifies() {
        let mut s = spec();
        s.base = 0x1000_0000;
        assert!(run(&mut build(&s)).is_ok());
    }

    #[test]
    fn file_and_memory_input_cover_the_same_table() {
        let stub = good();
        let slot_bytes = &stub.file[SLOT_RVA as usize..SLOT_RVA as usize + SLOT_SIZE];
        let parsed = slot::parse(slot_bytes).unwrap();
        assert!(file_signature_input(&stub.file, slot_bytes, &parsed, &Some).is_ok());
    }
}
