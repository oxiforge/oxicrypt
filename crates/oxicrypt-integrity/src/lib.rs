//! Pre-operational software integrity test for the oxicrypt FIPS module.
//!
//! # Approved service
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | Module image integrity check | ISO/IEC 19790:2012 §7.10.2.2 (`AS10.17`–`AS10.18`), §7.5 `[05.17]` | [`integrity_self_test`] |
//!
//! This crate implements the pre-operational software integrity test
//! required by ISO/IEC 19790:2012 §7.10.2.2. The technique is an approved
//! digital signature, ML-DSA-87 (FIPS 204), which §7.5 `[05.17]` requires
//! at Security Level 2: the signature can be produced only by the holder
//! of the private key, and the module verifies it with a public key
//! compiled into it. The signature algorithm's own self-test runs first
//! (see "Boot order").
//!
//! # What the test detects
//!
//! Accidental or unauthorised modification of the module's executable
//! image after it was signed: corruption at rest or in transit, a partial
//! or mismatched install, a faulty build step, or an edit by someone who
//! does not hold the signing key. It does not resist an adversary who
//! controls both the file and the launch, nor modification of process
//! memory after load. It does not detect an edit that keeps it from
//! running: an edit to the code that runs it, or to the image's layout so
//! that the module state starts already set, such as widening the file size
//! of the segment that holds the state word. No test a module runs on itself
//! can detect a change to whether it runs. Origin, meaning that an artifact
//! is the one a particular vendor produced, is not established by this test:
//! it rests on the distribution channel, and the fingerprint of the embedded
//! verifying key ([`verify_key_fingerprint`]) says which signer a build
//! trusts.
//!
//! # The verifying key is a build-time input
//!
//! `build.rs` reads `OXICRYPT_INTEGRITY_VERIFY_KEY` (the path of a
//! 2,592-byte encoded ML-DSA-87 public key) or
//! `OXICRYPT_INTEGRITY_VERIFY_KEY_HEX` and embeds it in
//! [`key::FIPS_INTEGRITY_VERIFY_KEY`]. A project release embeds the
//! project's key; a source builder generates a pair with
//! `oxicrypt-integrity-sign --keygen`, builds with the public half and
//! signs with the private half. A build with neither variable set compiles,
//! embeds an all-zero key, and reports [`IntegrityStatus::NoVerifyKey`] at
//! power-up: it never becomes operational, and there is no default key.
//!
//! The key record is read-only data inside the signed extent, so replacing
//! the key changes signed bytes. The slot also carries `key_id`, the
//! SHA-256 of the key the signature was made for; a slot whose `key_id` is
//! not the embedded key's fingerprint is refused as
//! [`IntegrityStatus::KeyMismatch`] before any signature is checked.
//!
//! # What is signed
//!
//! The signer, a build-time tool outside the cryptographic boundary, parses
//! the executable format and writes a typed extent into the slot: a table
//! of entries, each a run of the image with a kind (see [`slot`]). The
//! verifier performs no format parsing; it reads the entries it is given.
//! The signature input is the slot without its signature field, followed
//! by each entry's payload in table order: `Plain` bytes as loaded,
//! `Relative` words with the load slide subtracted, `FileOnly` bytes read
//! from the image file the loader reports, nothing for a `Hole`. A `Bind`
//! word contributes no payload; it must equal its recorded import's
//! resolution plus the addend, except on Darwin x86_64, where a resolver
//! stub the import's name leads to through the export tries is accepted.
//! Bind words are checked while the input is assembled, before the
//! signature is verified, so a slot edited to name an import that does not
//! resolve reports [`IntegrityStatus::SlotDamaged`], or
//! [`IntegrityStatus::Unreadable`] when the resolver fails, rather than
//! [`IntegrityStatus::SignatureInvalid`]. On Darwin x86_64 a bind word that
//! does not match its resolution, where the walk of the export tries that
//! could accept it as a resolver stub fails, reports
//! [`IntegrityStatus::Unreadable`] too.
//!
//! The signed message is that input framed as FIPS 204's external
//! interface frames a message under a context string,
//! `0x00 ‖ len(ctx) ‖ ctx ‖ M` with `ctx` = [`SIGNATURE_CONTEXT`], so an
//! integrity signature does not verify as a signature the same key makes
//! under any other context string, nor one of those as it. The module verifies it with `ML-DSA.Verify_internal`
//! (FIPS 204 Algorithm 8), which runs while the module is in `SelfTest`.
//!
//! Because every byte of the slot except the signature is signed, the
//! table, the key fingerprint and every header field are covered, and the
//! signature is the one exclusion ISO/IEC 19790:2012 §7.5 permits, as the
//! integrity technique's expected output.
//!
//! # The slot, and why it is read rather than dereferenced
//!
//! [`FIPS_INTEGRITY_SLOT`] is a [`SLOT_SIZE`]-byte `#[used] pub static`
//! reserved at link time. The verifier takes only its *address* from the
//! static and reads its bytes through the acquisition mechanism, the same
//! way it reads everything else. The signer patches the slot after
//! compilation, so the compiler's view of the static is stale for every
//! signed artifact, and reading it in Rust is a read of an immutable value
//! with a known initialiser that the compiler may constant-fold. Taking the
//! address and acquiring the bytes removes the question. The key record is
//! read the same way, so the key the test uses is the one the loaded image
//! holds.
//!
//! `slot_rva` records where the slot sits relative to the image base; the
//! slot's runtime address minus `slot_rva` is the load base, and the load
//! base minus the slot's `link_base` is the slide a `Relative` word is
//! corrected by.
//!
//! # Byte acquisition
//!
//! | Operational environment | Memory route | File route (`FileOnly`) |
//! |---|---|---|
//! | Linux, Android | `/proc/self/mem`, then `process_vm_readv` | the `/proc/self/maps` line holding the slot |
//! | Darwin | `mach_vm_read_overwrite` | `dladdr` |
//! | Windows | `ReadProcessMemory` | `GetModuleFileNameW` |
//!
//! When no memory route can read the image, the result is [`Unreadable`]:
//! the test was not performed and the module does not become operational.
//! The image file is never read in place of the loaded image. This crate
//! carries `#![forbid(unsafe_code)]`; every system call that is not a file
//! read is in `oxicrypt-imageread`.
//!
//! # Sensitive security parameters
//!
//! None. The verifying key is a public key, the signature is public, and
//! the module image bytes are public. No CSP passes through this crate.
//!
//! # Boot order
//!
//! [`KATS`] lists the ML-DSA-87 signature-verification CAST
//! ([`ml_dsa_cast`]), then the SHA-256 CAST ([`sha256_cast`]) for the
//! key fingerprint the test computes, then the integrity test
//! ([`integrity_self_test`]); `AS10.20` and IG 10.2.A require an
//! algorithm's self-test to pass before the algorithm is used. The order is
//! also enforced: [`verify_loaded_image`] refuses with
//! [`IntegrityError::CastNotRun`] unless both CASTs have passed in this
//! process. All three run while the module is in `SelfTest`, through the
//! `*_internal` primitives that admit that state.
//!
//! # Failure modes
//!
//! Every failure is terminal: the runner latches the module into the
//! `Error` state and no service is available. [`status`] distinguishes the
//! causes, because "the module is corrupt", "it was signed for another
//! key", "it was built without a key" and "this environment cannot supply
//! the module's own bytes" call for different responses.
//!
//! # Signing workflow
//!
//! ```text
//! oxicrypt-integrity-sign --keygen <dir outside the tree>
//! OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo build --release -p oxicrypt-cli
//! oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key target/release/oxi
//! ```
//!
//! A production build runs the signer as a post-link step and ships the
//! signed artifact; the runtime path never signs.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

use oxicrypt_module::{KatEntry, SelfTestFailure};

mod acquire;
pub mod key;
pub mod slot;
mod trie;
mod verify;

pub use key::{FIPS_INTEGRITY_VERIFY_KEY, KeyRecord};
pub use slot::{Entry, EntryKind, Range, SlotDefect, SlotImage};
pub use verify::{MESSAGE_PREFIX, SIGNATURE_CONTEXT, file_signature_input};

/// Header magic for the embedded integrity slot. 16 bytes.
///
/// The leading `0xfc` byte is a deliberately non-ASCII sentinel: it makes
/// the pattern unlikely to appear in a string table and lets the signer's
/// scanner short-circuit on a byte that rarely occurs in text sections.
pub const SLOT_HEADER_MAGIC: [u8; 16] = [
    0xfc, b'O', b'X', b'I', b'C', b'R', b'Y', b'P', b'T', b'_', b'F', b'I', b'P', b'S', b'_', b'H',
];

/// Footer magic for the embedded integrity slot. 16 bytes. Paired with
/// [`SLOT_HEADER_MAGIC`]; a candidate slot is accepted only when both
/// appear at their correct relative offsets.
pub const SLOT_FOOTER_MAGIC: [u8; 16] = [
    0xfd, b'O', b'X', b'I', b'C', b'R', b'Y', b'P', b'T', b'_', b'F', b'I', b'P', b'S', b'_', b'F',
];

/// Size in bytes of the embedded integrity slot.
///
/// 64 KiB. The size is what the entry table and the string table grow
/// into: at [`slot::ENTRY_SIZE`] bytes per entry the table admits
/// [`slot::MAX_ENTRIES`] entries when no string table is present.
pub const SLOT_SIZE: usize = 65_536;

/// Format version written by the signer and required by the verifier.
///
/// Every other version is refused, so a slot is accepted only in the one
/// format whose signature this module checks.
pub const SLOT_VERSION: u32 = 4;

/// Reserved integrity slot.
///
/// `#[used]` keeps the static in this crate's object file even though no
/// Rust code reads its contents: the verifier takes its *address* and
/// reads the bytes through the byte-acquisition mechanism, for the reason
/// given in the crate documentation. The attribute binds the compiler, not
/// the linker, so the slot's presence in a linked artifact is established
/// by the signer finding it, not by the attribute.
///
/// `#[repr(C)]` pins field order so the bytes appear in the artifact
/// exactly as declared, which is what the signer scans for and what the
/// field offsets in [`slot`] index into.
#[used]
pub static FIPS_INTEGRITY_SLOT: IntegritySlot = IntegritySlot {
    hdr: SLOT_HEADER_MAGIC,
    body: [0u8; SLOT_BODY_SIZE],
    ftr: SLOT_FOOTER_MAGIC,
};

/// Size of the slot's body: everything between the two magics.
pub const SLOT_BODY_SIZE: usize = SLOT_SIZE - 32;

/// Layout of the reserved integrity slot.
///
/// The body is deliberately opaque here: its interior structure is defined
/// by the field offsets in [`slot`] and parsed from bytes, not by Rust
/// field access, because the verifier never reads the static directly.
#[repr(C)]
pub struct IntegritySlot {
    /// Header magic, equal to [`SLOT_HEADER_MAGIC`].
    pub hdr: [u8; 16],
    /// Version, header fields, entry table, string table, padding.
    pub body: [u8; SLOT_BODY_SIZE],
    /// Footer magic, equal to [`SLOT_FOOTER_MAGIC`].
    pub ftr: [u8; 16],
}

/// Why the module's own bytes could not be obtained.
///
/// Distinguished from a failed verification because the two mean opposite
/// things to an operator: a failed signature says the module is wrong, an
/// acquisition failure says the environment cannot answer the question.
///
/// On the file route, once the slot has parsed, [`Unreadable::SlotUnmapped`],
/// [`Unreadable::ArchiveBaseUnaligned`], [`Unreadable::ForeignArchiveMapping`],
/// [`Unreadable::MappingMisplaced`], [`Unreadable::FileLength`] and a
/// [`Unreadable::FileRead`] that ends early are reported as slot damage
/// ([`IntegrityStatus::SlotDamaged`]) instead, because the slot's own
/// fields disagree with the file.
#[derive(Debug)]
#[non_exhaustive]
pub enum Unreadable {
    /// This target has no implemented byte-acquisition mechanism.
    NoMechanism,
    /// Linux and Android: `/proc/self/mem` and `process_vm_readv` both
    /// failed, so the loaded image cannot be read. Typical of a
    /// non-dumpable process under a seccomp filter that denies
    /// `process_vm_readv`.
    MemoryRoutesFailed {
        /// The first route's error.
        proc_self_mem: std::io::Error,
        /// The second route's error.
        process_vm_readv: oxicrypt_imageread::ReadError,
    },
    /// A read through the memory route chosen by the first read failed later.
    MemoryRead(std::io::Error),
    /// The kernel refused to copy the module's own image.
    SelfReadFailed(oxicrypt_imageread::ReadError),
    /// `/proc/self/maps` could not be read, so the image file cannot be
    /// located.
    MapsUnavailable(std::io::Error),
    /// The mapping holding the slot was found but a field of it did not
    /// parse, so its file offset cannot be trusted.
    MapsUnparseable,
    /// The slot's address falls in no reported mapping, or an address
    /// computed from it overflows.
    SlotUnmapped,
    /// The mapping holding the slot names no image file.
    NoBackingFile,
    /// The operating system named no image file for the slot's address.
    ImagePath(oxicrypt_imageread::ReadError),
    /// Linux and Android: `/proc/self/maps` does not exist, and the loader
    /// named no image file for the slot's address either, so the image
    /// cannot be measured.
    ImagePathWithoutMaps {
        /// Why `/proc/self/maps` could not be read.
        maps: std::io::Error,
        /// Why the loader named no image file.
        image_path: oxicrypt_imageread::ReadError,
    },
    /// Linux and Android: without `/proc/self/maps` the loader names the
    /// image only by the relative path it was loaded by, which depends on
    /// the working directory and so does not identify the file.
    ImagePathRelative(std::path::PathBuf),
    /// The image file could not be opened or its length read.
    FileOpen(std::io::Error),
    /// A read of the image file failed.
    FileRead(std::io::Error),
    /// The image file is not the length the slot records: a plain file
    /// must be exactly `file_len` bytes, an archive must hold the image.
    FileLength {
        /// The length the slot records.
        expected: u64,
        /// The file's length.
        actual: u64,
    },
    /// The image's offset inside the archive that maps it is not
    /// page-aligned, so the mapping cannot be one of its entries.
    ArchiveBaseUnaligned(u64),
    /// A mapping of the image file overlaps the file range the slot gives
    /// the image and meets the address range the slot's entries describe,
    /// but runs outside that range or maps archive bytes from before the
    /// image. A mapping of the file wholly outside the range, such as a
    /// second load of it, is not.
    ForeignArchiveMapping,
    /// The operating system's resolver failed on a bound import's names.
    Resolver(oxicrypt_imageread::ReadError),
    /// A mapping of the image file inside the image's address range moves
    /// a file range by a different amount than the slot's entry for it:
    /// the slot places its entries where the image is not.
    MappingMisplaced,
    /// Darwin: the image file the loader names holds no image whose Mach
    /// header and integrity slot are the loaded image's: neither the file
    /// itself nor any architecture slice of a universal file.
    SliceNotFound,
    /// Darwin: the image file is universal, and its architecture table
    /// runs past the limits dyld reads it within (the first 4 KiB and the
    /// file), or is followed by an arm64 entry dyld loads although the
    /// table does not count it.
    UniversalTable,
    /// Darwin x86_64: a library a bound import resolves through is not
    /// loaded, the chain of re-exports cycles or runs past eight hops, or an
    /// export trie cannot be found through its image's load commands as
    /// loaded or is malformed, so a resolver stub cannot be checked.
    ExportTrie,
    /// The signature input could not be allocated.
    OutOfMemory,
}

/// Failure of the pre-operational software integrity test.
///
/// Together with a pass, the variants are the module's status indicator
/// for this test (`AS10.18`); see [`IntegrityStatus`].
#[derive(Debug)]
#[non_exhaustive]
pub enum IntegrityError {
    /// A self-test of an algorithm the integrity test uses, ML-DSA-87 or
    /// SHA-256, has not passed in this process, so the test may not use it.
    ///
    /// A sequencing fault in the front end rather than a finding about the
    /// module image: something called the integrity test without first
    /// running [`ml_dsa_cast`] and [`sha256_cast`].
    CastNotRun,
    /// The module carries no verifying key, so it has nothing to verify
    /// its image against: built without one, or signed and then had its key
    /// record zeroed, which the module cannot tell apart.
    NoVerifyKey,
    /// The signature over the image does not verify under the embedded
    /// key, or a bound import does not hold its recorded value: the image
    /// is not the one that was signed.
    SignatureInvalid,
    /// The slot or the embedded key record is malformed, the slot is the
    /// unsigned template, it was signed for a different key, or it describes
    /// an impossible extent; [`IntegrityStatus`] tells these apart.
    SlotInvalid(SlotDefect),
    /// The module's own bytes could not be obtained, so the test was not
    /// performed.
    Unreadable(Unreadable),
    /// The module refused a primitive the test uses because its self-tests
    /// have not started or it has failed.
    Module(oxicrypt_module::Error),
}

impl core::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CastNotRun => f.write_str(
                "the ML-DSA-87 or SHA-256 self-test has not passed, so the integrity test may \
                 not use them",
            ),
            Self::NoVerifyKey => f.write_str(
                "this module was built without a verifying key (OXICRYPT_INTEGRITY_VERIFY_KEY)",
            ),
            Self::SignatureInvalid => {
                f.write_str("the module image does not match the signature recorded in it")
            }
            Self::SlotInvalid(d) => write!(f, "integrity slot invalid: {d}"),
            Self::Unreadable(u) => write!(f, "module image unreadable: {u}"),
            Self::Module(e) => write!(f, "the module refused a primitive the test uses: {e}"),
        }
    }
}

impl core::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMechanism => f.write_str(
                "no byte-acquisition mechanism is implemented for this operational environment",
            ),
            Self::MemoryRoutesFailed {
                proc_self_mem,
                process_vm_readv,
            } => write!(
                f,
                "/proc/self/mem failed ({proc_self_mem}) and process_vm_readv failed \
                 ({process_vm_readv})"
            ),
            Self::MemoryRead(e) => write!(f, "a read of the loaded image failed: {e}"),
            Self::SelfReadFailed(e) => write!(f, "the module's own image could not be read: {e}"),
            Self::MapsUnavailable(e) => write!(
                f,
                "/proc/self/maps unreadable ({e}), so the image file cannot be located and its \
                 initialised data cannot be checked; this is the environment, not damage"
            ),
            Self::MapsUnparseable => {
                f.write_str("the mapping holding the integrity slot could not be parsed")
            }
            Self::SlotUnmapped => f.write_str("the integrity slot lies in no reported mapping"),
            Self::NoBackingFile => {
                f.write_str("the mapping holding the integrity slot names no image file")
            }
            Self::ImagePath(e) => write!(f, "the image file could not be located: {e}"),
            Self::ImagePathWithoutMaps { maps, image_path } => write!(
                f,
                "/proc/self/maps unreadable ({maps}) and the loader named no image file \
                 ({image_path}); this is the environment, not damage"
            ),
            Self::ImagePathRelative(p) => write!(
                f,
                "/proc/self/maps unreadable and the image was loaded by the relative path {}, \
                 which does not identify the file; load it by an absolute path or provide /proc",
                p.display()
            ),
            Self::FileOpen(e) => write!(f, "the image file could not be opened: {e}"),
            Self::FileRead(e) => write!(f, "the image file could not be read: {e}"),
            Self::FileLength { expected, actual } => write!(
                f,
                "the image file is {actual} bytes where the slot records {expected}"
            ),
            Self::ArchiveBaseUnaligned(b) => {
                write!(
                    f,
                    "the image's offset {b:#x} in its archive is not page-aligned"
                )
            }
            Self::ForeignArchiveMapping => {
                f.write_str("a mapping of the image file runs outside the range the slot describes")
            }
            Self::Resolver(e) => write!(f, "a bound import could not be looked up: {e}"),
            Self::MappingMisplaced => f.write_str(
                "a mapping of the image file is placed unlike the slot's entry for its bytes",
            ),
            Self::ExportTrie => f.write_str(
                "an import's chain of export tries is missing, cyclic, too long or malformed",
            ),
            Self::UniversalTable => f.write_str(
                "the universal file's architecture table is outside dyld's limits or carries a \
                 hidden arm64 entry",
            ),
            Self::SliceNotFound => f.write_str(
                "the image file holds no image, or universal-file slice, that is the loaded image",
            ),
            Self::OutOfMemory => f.write_str("the signature input could not be allocated"),
        }
    }
}

impl std::error::Error for IntegrityError {}

/// SHA-256 of a raw verifying key: the `key_id` a slot carries and the
/// fingerprint an operator reads.
///
/// # Errors
///
/// [`oxicrypt_module::Error::NotOperational`] unless
/// [`oxicrypt_module::require_self_test_started`] admits the call: in
/// `Operational`, or in `SelfTest` on the thread running the power-up
/// self-tests.
pub fn key_fingerprint(
    key: &[u8; key::VERIFY_KEY_LEN],
) -> Result<[u8; 32], oxicrypt_module::Error> {
    let mut hash = oxicrypt_sha::sha256::Sha256::new_internal()?;
    hash.update(key);
    hash.finalize()
}

/// Formats a fingerprint as `sha256:` and 64 lowercase hex digits.
#[must_use]
pub fn format_fingerprint(fingerprint: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(71);
    out.push_str("sha256:");
    for &byte in fingerprint {
        for nibble in [byte >> 4, byte & 0x0f] {
            out.push(char::from(
                HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

/// Runtime address of the integrity slot.
///
/// Taking the address of the static is safe and says nothing about its
/// contents. Exposed because it is also the diagnostic an operator needs:
/// across runs it shows whether the image moved, which is what makes a
/// stable verdict meaningful rather than vacuous.
#[must_use]
pub fn slot_address() -> usize {
    core::ptr::from_ref(&FIPS_INTEGRITY_SLOT) as usize
}

/// Runs the pre-operational integrity test against the loaded module
/// image.
///
/// Reads the embedded key record and the slot through the platform
/// mechanism, validates the slot, builds the signature input from the
/// loaded image, and verifies the signature.
///
/// The test runs only inside the power-up self-tests, on the thread running
/// them. The module tests itself on demand by restarting: the process
/// starts again and initialises, which runs this test before any service
/// is offered. A call at any other time runs nothing, changes no state, and
/// returns [`IntegrityError::Module`]: [`oxicrypt_module::Error::AlreadyInitialized`]
/// once the module is operational, and otherwise the refusal the module's
/// guard gives, such as `NotOperational` naming `PowerOff`, `Error`, or
/// `SelfTest` on another thread.
///
/// # Errors
///
/// Returns [`IntegrityError`]; see [`IntegrityStatus`] for what each
/// outcome means to an operator.
///
/// A failure of a test that ran, including [`IntegrityError::CastNotRun`]
/// when the self-tests reach this one before [`ml_dsa_cast`] and
/// [`sha256_cast`] have passed, latches the
/// module into its terminal `Error` state.
///
/// Only the boot sequence's own entry ([`integrity_self_test`], run from
/// [`KATS`]) records the outcome for [`status`] and [`status_detail`]. A
/// call from another self-test records no outcome, so it cannot replace
/// the boot's verdict. Either records the embedded key's fingerprint for
/// [`verify_key_fingerprint`] the first time it reads the key; the key is
/// the same bytes whichever call reads it.
pub fn verify_loaded_image() -> Result<(), IntegrityError> {
    admit()?;
    run_admitted(acquire::verify_at)
}

/// The test's admission: only inside the power-up self-tests, on the thread
/// running them. A refusal runs nothing and changes nothing.
fn admit() -> Result<(), IntegrityError> {
    oxicrypt_module::require_self_test_started().map_err(IntegrityError::Module)?;
    if oxicrypt_module::is_operational() {
        return Err(IntegrityError::Module(
            oxicrypt_module::Error::AlreadyInitialized,
        ));
    }
    Ok(())
}

/// How an admitted run verifies the image at a slot and key-record address,
/// recording the key's fingerprint as soon as it is read.
type Verifier = fn(usize, usize, &mut Option<[u8; 32]>) -> Result<(), IntegrityError>;

/// The test once admitted. Every failure, including one the module reports
/// while the test runs (a concurrent transition to `Error`), is a failure of
/// a test that ran, and latches `Error`.
fn run_admitted(verify: Verifier) -> Result<(), IntegrityError> {
    let outcome = if casts_passed() {
        let mut fingerprint = None;
        let outcome = verify(slot_address(), key::key_record_address(), &mut fingerprint);
        if let Some(fp) = fingerprint {
            let _ = FINGERPRINT.set(fp);
        }
        outcome
    } else {
        Err(IntegrityError::CastNotRun)
    };
    if outcome.is_err() {
        oxicrypt_module::enter_error_state("software integrity test failed");
    }
    outcome
}

/// The fingerprint of the verifying key this module embeds.
static FINGERPRINT: OnceLock<[u8; 32]> = OnceLock::new();

/// The fingerprint, SHA-256 of the raw public key, of the verifying key
/// this module was built with.
///
/// Recorded by the integrity test from the key record it read, so it is
/// the key the loaded image holds and equals the fingerprint
/// `oxicrypt-integrity-sign --show` prints for the file. `None` until the
/// test has read the key in this process, and for a module built without
/// one.
#[must_use]
pub fn verify_key_fingerprint() -> Option<[u8; 32]> {
    FINGERPRINT.get().copied()
}

/// Records the boot sequence's outcome for [`status`].
///
/// The record LATCHES, mirroring the module's own state machine: a later
/// outcome must not overwrite the one the operator needs.
fn record_boot_outcome(outcome: &Result<(), IntegrityError>) {
    latch_outcome(&LAST_STATUS, outcome);
}

/// Writes `outcome` into `cell` only if `cell` still reads `NotRun`, so the
/// first recorded outcome wins.
fn latch_outcome(cell: &AtomicU8, outcome: &Result<(), IntegrityError>) {
    let _ = cell.compare_exchange(
        IntegrityStatus::NotRun as u8,
        IntegrityStatus::of(outcome) as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

/// The pre-operational integrity test's status indicator.
///
/// An operator and a test laboratory must be able to tell a corrupt
/// module from one signed for another key, one built without a key, and
/// an environment that could not supply the module's own bytes. The
/// module runner's `SelfTestFailure` carries no payload, so that
/// distinction cannot travel out through
/// `initialize_with_tests`; this indicator is how it is retrieved instead,
/// and [`status`] is the retrieval.
///
/// The discriminants are stable and are what the C ABI reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum IntegrityStatus {
    /// The test has not run in this process.
    NotRun = 0,
    /// The test ran and the signature over the image verified.
    Passed = 1,
    /// The signature over the image does not verify under the embedded
    /// key, or a bound import's word does not hold its recorded value: the
    /// image is not the one that was signed. Bind words are checked before
    /// the signature, so a slot naming an import that does not resolve is
    /// [`IntegrityStatus::SlotDamaged`] or [`IntegrityStatus::Unreadable`]
    /// instead, whatever the signature would have said. On Darwin x86_64 a
    /// mismatched bind word whose export-trie walk fails is
    /// [`IntegrityStatus::Unreadable`] for the same reason.
    SignatureInvalid = 2,
    /// The slot is byte for byte the unsigned template the build emits. A
    /// build that was never signed carries it, and so does a signed one
    /// whose slot was overwritten with it; the module cannot tell them
    /// apart, so this status is never on its own a reason to sign. Any
    /// other slot that does not parse, including a missing magic or an
    /// earlier version, is [`IntegrityStatus::SlotDamaged`].
    SlotInvalid = 3,
    /// The module's own bytes could not be obtained, so the test was
    /// **not performed**. This says nothing about the image.
    Unreadable = 4,
    /// The test was reached before the ML-DSA-87 and SHA-256 CASTs it
    /// depends on had both passed.
    CastNotRun = 5,
    /// The recorded indicator is not a value this module writes.
    ///
    /// Unreachable by construction. Reported rather than folded into
    /// [`IntegrityStatus::NotRun`] because reading an impossible value as
    /// the most benign one would hide the very condition worth seeing.
    Unknown = 6,
    /// The module refused a primitive the test uses after the test had been
    /// admitted, so the test was **not performed**.
    Refused = 7,
    /// The module carries no verifying key: built without
    /// `OXICRYPT_INTEGRITY_VERIFY_KEY`, or signed and then had its key
    /// record zeroed, which the module cannot tell apart. Never on its own
    /// a reason to sign.
    NoVerifyKey = 8,
    /// The slot was signed for a different verifying key than the one this
    /// module embeds.
    KeyMismatch = 9,
    /// A signed slot or the key record is damaged: the slot does not parse
    /// and is not the unsigned template, its fields disagree with the image
    /// or its file, or a bound import record names an import that does not
    /// resolve or that this platform cannot bind.
    /// The module is corrupt; signing it again would bless the damage.
    SlotDamaged = 10,
}

impl IntegrityStatus {
    /// The indicator corresponding to one run's outcome.
    pub(crate) const fn of(outcome: &Result<(), IntegrityError>) -> Self {
        match outcome {
            Ok(()) => Self::Passed,
            Err(IntegrityError::SignatureInvalid) => Self::SignatureInvalid,
            Err(IntegrityError::SlotInvalid(SlotDefect::KeyMismatch)) => Self::KeyMismatch,
            Err(IntegrityError::SlotInvalid(d)) if d.is_unsigned() => Self::SlotInvalid,
            Err(IntegrityError::SlotInvalid(_)) => Self::SlotDamaged,
            Err(IntegrityError::Unreadable(_)) => Self::Unreadable,
            Err(IntegrityError::CastNotRun) => Self::CastNotRun,
            Err(IntegrityError::NoVerifyKey) => Self::NoVerifyKey,
            Err(IntegrityError::Module(_)) => Self::Refused,
        }
    }
}

/// The text of the boot sequence's first failure.
static DETAIL: OnceLock<String> = OnceLock::new();

/// The boot sequence's integrity failure in words, including the cause the
/// status value cannot carry: which slot defect, which route's errno, which
/// lengths disagreed.
///
/// `None` until the boot sequence's integrity test has failed in this
/// process. Latched with [`status`], so it describes the same run.
#[must_use]
pub fn status_detail() -> Option<&'static str> {
    DETAIL.get().map(String::as_str)
}

/// The first outcome recorded by the boot sequence.
static LAST_STATUS: AtomicU8 = AtomicU8::new(IntegrityStatus::NotRun as u8);

/// Returns the pre-operational integrity test's status indicator.
///
/// [`IntegrityStatus::NotRun`] until the test has run in this process. The
/// value latches on the first run; the test is not re-run here, so this is
/// safe to call from an error state and cannot change it.
#[must_use]
pub fn status() -> IntegrityStatus {
    decode_status(LAST_STATUS.load(Ordering::Acquire))
}

/// The indicator a recorded byte stands for.
const fn decode_status(raw: u8) -> IntegrityStatus {
    match raw {
        0 => IntegrityStatus::NotRun,
        1 => IntegrityStatus::Passed,
        2 => IntegrityStatus::SignatureInvalid,
        3 => IntegrityStatus::SlotInvalid,
        4 => IntegrityStatus::Unreadable,
        5 => IntegrityStatus::CastNotRun,
        7 => IntegrityStatus::Refused,
        8 => IntegrityStatus::NoVerifyKey,
        9 => IntegrityStatus::KeyMismatch,
        10 => IntegrityStatus::SlotDamaged,
        _ => IntegrityStatus::Unknown,
    }
}

/// Records that the integrity technique's algorithm self-test passed in
/// this process.
static ML_DSA_CAST_PASSED: AtomicBool = AtomicBool::new(false);

/// Records that the SHA-256 algorithm self-test, which the test's key
/// fingerprint uses, passed in this process.
static SHA256_CAST_PASSED: AtomicBool = AtomicBool::new(false);

/// Whether both algorithm self-tests the integrity test depends on have
/// passed in this process.
fn casts_passed() -> bool {
    ML_DSA_CAST_PASSED.load(Ordering::Acquire) && SHA256_CAST_PASSED.load(Ordering::Acquire)
}

/// A known-answer test.
type Kat = fn() -> Result<(), SelfTestFailure>;

/// Where a CAST finds the known-answer test it runs. The CAST reads it
/// through [`KatCell::get`] on every call; the unit tests replace it with a
/// failing test, which is how they observe that the CAST runs it.
#[cfg(not(test))]
struct KatCell(Kat);

#[cfg(not(test))]
impl KatCell {
    const fn new(kat: Kat) -> Self {
        Self(kat)
    }

    fn get(&self) -> Kat {
        self.0
    }
}

#[cfg(test)]
struct KatCell(std::sync::RwLock<Kat>);

#[cfg(test)]
impl KatCell {
    const fn new(kat: Kat) -> Self {
        Self(std::sync::RwLock::new(kat))
    }

    fn get(&self) -> Kat {
        *self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set(&self, kat: Kat) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = kat;
    }
}

/// The known-answer test [`ml_dsa_cast`] runs.
static ML_DSA_KAT: KatCell = KatCell::new(oxicrypt_ml_dsa::verify_cast);

/// The known-answer test [`sha256_cast`] runs.
static SHA256_KAT: KatCell = KatCell::new(oxicrypt_sha::sha256::self_test);

/// The integrity technique's own cryptographic algorithm self-test: the
/// ML-DSA-87 signature-verification CAST
/// ([`oxicrypt_ml_dsa::verify_cast`]), which must accept a NIST vector's
/// valid signature and reject it with one bit flipped.
///
/// `AS10.20` and IG 10.2.A require an approved algorithm's CAST to precede
/// any use of that algorithm, so this runs first and the module's image is
/// verified only once signature verification has been proven against a
/// known answer, including the rejection of a tampered signature.
///
/// The ordering is not left to convention: [`KATS`] lists this entry
/// first, and [`verify_loaded_image`] refuses with
/// [`IntegrityError::CastNotRun`] unless it and [`sha256_cast`] have
/// passed.
///
/// # Errors
///
/// Returns [`SelfTestFailure`] if the known-answer test fails. A failure
/// latches the module into its terminal `Error` state and withdraws the
/// CAST's pass, whichever path called it: the boot sequence, or a direct
/// call after initialisation. A call the module refuses, before
/// initialisation or from another thread while the self-tests run, also
/// returns [`SelfTestFailure`], having run nothing and changed nothing.
pub fn ml_dsa_cast() -> Result<(), SelfTestFailure> {
    run_cast(
        &ML_DSA_CAST_PASSED,
        ML_DSA_KAT.get(),
        "ML-DSA-87 signature-verification CAST failed",
    )
}

/// The SHA-256 known-answer test (`oxicrypt_sha::sha256::self_test`), run
/// as part of the integrity group because the integrity test computes the
/// SHA-256 fingerprint of the embedded key before the algorithm
/// self-tests run.
///
/// `AS10.20` requires SHA-256's CAST to precede that use, so [`KATS`]
/// lists this entry before the integrity test, and
/// [`verify_loaded_image`] refuses with [`IntegrityError::CastNotRun`]
/// unless it and [`ml_dsa_cast`] have passed.
///
/// # Errors
///
/// As [`ml_dsa_cast`]: a failure latches `Error` and withdraws the pass,
/// and a call the module refuses runs nothing and changes nothing.
pub fn sha256_cast() -> Result<(), SelfTestFailure> {
    run_cast(&SHA256_CAST_PASSED, SHA256_KAT.get(), "SHA-256 CAST failed")
}

/// A CAST with its known-answer test and pass flag passed in, so a test can
/// make it fail.
fn run_cast(passed: &AtomicBool, kat: Kat, failure: &'static str) -> Result<(), SelfTestFailure> {
    // A caller the module refuses, before initialisation or on another
    // thread while the self-tests run, runs nothing and changes nothing.
    // Only a CAST that ran and failed latches `Error`.
    oxicrypt_module::require_self_test_started().map_err(|_| SelfTestFailure)?;
    if kat().is_err() {
        passed.store(false, Ordering::Release);
        oxicrypt_module::enter_error_state(failure);
        return Err(SelfTestFailure);
    }
    passed.store(true, Ordering::Release);
    Ok(())
}

/// The HMAC-SHA-256 known-answer test.
///
/// Not part of [`KATS`]: the integrity technique is ML-DSA-87. Kept for
/// out-of-boundary tools that start their own copy of the module without
/// the image check and need a self-test to stand in the integrity group's
/// place; the HMAC service runs its own CAST in its crate's `KATS`.
///
/// # Errors
///
/// Returns [`SelfTestFailure`] if the known-answer test fails.
pub fn hmac_cast() -> Result<(), SelfTestFailure> {
    oxicrypt_hmac::self_test_sha256()
}

/// The integrity test's name in [`KATS`].
///
/// Present in an artifact's read-only data exactly when the boot sequence's
/// integrity test, and with it the status it records, is linked; the signer
/// reads it to know which module statics the artifact must name.
pub const INTEGRITY_TEST_NAME: &str =
    "Module image integrity (ML-DSA-87 signature over the typed extent)";

/// The integrity technique's CAST name, the one every inventory and the
/// Security Policy use. Distinct from the name `oxicrypt_ml_dsa::KATS`
/// gives the same vector, so an inventory that lists both tells them
/// apart.
pub const ML_DSA_CAST_NAME: &str =
    "ML-DSA-87 CAST (signature verification, FIPS 204, integrity technique)";

/// The integrity group's SHA-256 CAST name. Distinct from the name
/// `oxicrypt_sha::KATS` gives the same test, so an inventory that lists
/// both tells them apart.
pub const SHA256_CAST_NAME: &str =
    "SHA-256 CAST (NIST CAVP SHA256ShortMsg Len=8, integrity key fingerprint)";

/// Pre-operational integrity test, in the shape the module runner wants.
///
/// Do not call this directly from application code: it is wired into
/// [`KATS`] and runs as part of `oxicrypt_module::initialize_with_tests`.
///
/// # Errors
///
/// Returns [`SelfTestFailure`] on any integrity failure, so the runner
/// latches the module into the terminal `Error` state. The cause is
/// available from [`status`]. A call from outside the power-up self-tests
/// is refused, as [`verify_loaded_image`] describes, also returns
/// [`SelfTestFailure`], and records nothing for [`status`].
pub fn integrity_self_test() -> Result<(), SelfTestFailure> {
    boot_test(acquire::verify_at)
}

/// [`integrity_self_test`] with its verifier passed in, so a test can make
/// an admitted run fail as the module would.
fn boot_test(verify: Verifier) -> Result<(), SelfTestFailure> {
    // A refusal at admission means the call came from outside the power-up
    // self-tests and ran nothing, so it is not the boot's verdict and records
    // nothing: the indicator stays free for the boot that does run. Once
    // admitted, every outcome is the boot's verdict and is recorded.
    if admit().is_err() {
        return Err(SelfTestFailure);
    }
    let outcome = run_admitted(verify);
    // The detail first, so a reader that sees a failed status always finds
    // its text.
    if let Err(e) = &outcome {
        let _ = DETAIL.set(e.to_string());
    }
    record_boot_outcome(&outcome);
    outcome.map_err(|_| SelfTestFailure)
}

/// Pre-operational test inventory for the software integrity test.
///
/// Merged into a front end's boot sequence via
/// `oxicrypt_module::initialize_with_tests`, which runs entries **in
/// order**. The order here is the requirement, not a convenience: the
/// technique's CAST first (`AS10.20`, IG 10.2.A), then the CAST of the
/// SHA-256 the key fingerprint uses, then the integrity test they enable
/// (ISO/IEC 19790:2012 §7.10.2.2, `AS10.17`).
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: ML_DSA_CAST_NAME,
        run: ml_dsa_cast,
    },
    KatEntry {
        name: SHA256_CAST_NAME,
        run: sha256_cast,
    },
    KatEntry {
        name: INTEGRITY_TEST_NAME,
        run: integrity_self_test,
    },
];

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{
        IntegrityError, IntegrityStatus, KATS, SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE,
        SlotDefect, Unreadable, decode_status, format_fingerprint, latch_outcome, ml_dsa_cast,
        slot,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    /// The slot magics are matched against artifact bytes by the signer,
    /// so each must be 16 bytes with a distinct sentinel.
    #[test]
    fn slot_magics_are_sixteen_bytes_and_distinctly_sentinelled() {
        assert_eq!(SLOT_HEADER_MAGIC[0], 0xfc);
        assert_eq!(SLOT_FOOTER_MAGIC[0], 0xfd);
        assert_ne!(SLOT_HEADER_MAGIC, SLOT_FOOTER_MAGIC);
        for m in [&SLOT_HEADER_MAGIC, &SLOT_FOOTER_MAGIC] {
            assert!(m[1..].iter().all(u8::is_ascii_graphic));
        }
    }

    /// The static must be exactly `SLOT_SIZE` bytes, or the signer's
    /// footer-at-a-fixed-offset check and the field offsets disagree with
    /// what is linked in.
    #[test]
    fn the_linked_slot_is_slot_size_bytes() {
        assert_eq!(core::mem::size_of::<super::IntegritySlot>(), SLOT_SIZE);
        assert_eq!(slot::OFF_FTR + 16, SLOT_SIZE);
        assert_eq!(
            core::mem::size_of::<super::KeyRecord>(),
            super::key::KEY_RECORD_SIZE
        );
    }

    /// The ML-DSA-87 CAST is the first entry, the SHA-256 CAST the second
    /// and the integrity test the third.
    #[test]
    fn the_casts_precede_the_integrity_test_in_kats() {
        type Run = fn() -> Result<(), oxicrypt_module::SelfTestFailure>;
        assert_eq!(KATS.len(), 3);
        assert!(KATS[0].name.contains("ML-DSA-87"));
        assert_ne!(KATS[0].name, oxicrypt_ml_dsa::VERIFY_CAST_NAME);
        assert!(core::ptr::fn_addr_eq(KATS[0].run, ml_dsa_cast as Run));
        assert!(KATS[1].name.contains("SHA-256"));
        assert!(!oxicrypt_sha::KATS.iter().any(|k| k.name == KATS[1].name));
        assert!(core::ptr::fn_addr_eq(
            KATS[1].run,
            super::sha256_cast as Run
        ));
        assert_eq!(KATS[2].name, super::INTEGRITY_TEST_NAME);
        assert!(core::ptr::fn_addr_eq(
            KATS[2].run,
            super::integrity_self_test as Run
        ));
    }

    /// Each CAST runs, end to end, the algorithm crate's own known-answer
    /// test: its cell holds that test, and the CAST's verdict follows what
    /// the cell holds. A CAST that ignored its cell (one that returned
    /// `Ok(())`, or ran a fixed test) passes with a failing test in the cell.
    /// Each case runs in a process of its own, because a failing CAST latches
    /// the process-global module state.
    #[test]
    fn each_cast_runs_the_known_answer_test_its_cell_holds() {
        use oxicrypt_module::{KatEntry, SelfTestFailure, State, initialize_with_tests, state};
        type Run = fn() -> Result<(), SelfTestFailure>;
        const CHILD: &str = "OXICRYPT_INTEGRITY_KAT_CELL_CHILD";
        const NAME: &str = "tests::each_cast_runs_the_known_answer_test_its_cell_holds";
        if std::env::var_os(CHILD).is_none() {
            // The cells hold the algorithm crates' tests.
            assert!(core::ptr::fn_addr_eq(
                super::ML_DSA_KAT.get(),
                oxicrypt_ml_dsa::verify_cast as Run
            ));
            assert!(core::ptr::fn_addr_eq(
                super::SHA256_KAT.get(),
                oxicrypt_sha::sha256::self_test as Run
            ));
            // Control: the comparison tells the two apart.
            assert!(!core::ptr::fn_addr_eq(
                super::ML_DSA_KAT.get(),
                oxicrypt_sha::sha256::self_test as Run
            ));
            for case in ["ml-dsa", "sha256"] {
                let out = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([NAME, "--exact", "--test-threads=1"])
                    .env(CHILD, case)
                    .output()
                    .unwrap();
                let stdout = std::string::String::from_utf8_lossy(&out.stdout);
                assert!(
                    out.status.success() && stdout.contains("test result: ok. 1 passed"),
                    "{NAME} ({case}) did not pass in its own process:\n{stdout}{}",
                    std::string::String::from_utf8_lossy(&out.stderr)
                );
            }
            return;
        }
        let stand_in = [KatEntry {
            name: "integrity not verifiable in an unsigned test binary",
            run: || Ok(()),
        }];
        initialize_with_tests(&stand_in, &[]).unwrap();
        let (cell, cast): (&super::KatCell, Run) =
            if std::env::var(CHILD).as_deref() == Ok("sha256") {
                (&super::SHA256_KAT, super::sha256_cast)
            } else {
                (&super::ML_DSA_KAT, ml_dsa_cast)
            };
        // Control: with the real test in the cell the CAST passes.
        assert!(cast().is_ok());
        assert_eq!(state(), State::Operational);
        cell.set(|| Err(SelfTestFailure));
        assert!(cast().is_err(), "the CAST did not run the test in its cell");
        assert_eq!(state(), State::Error);
    }

    /// A failing ML-DSA-87 or SHA-256 CAST latches `Error` and withdraws its
    /// pass even when it is called directly on an operational module. Each
    /// case runs in a process of its own, because it changes the
    /// process-global module state.
    #[test]
    fn a_failing_cast_latches_error_on_any_path() {
        use oxicrypt_module::{KatEntry, SelfTestFailure, State, initialize_with_tests, state};
        const CHILD: &str = "OXICRYPT_INTEGRITY_CAST_CHILD";
        const NAME: &str = "tests::a_failing_cast_latches_error_on_any_path";
        if std::env::var_os(CHILD).is_none() {
            for case in ["ml-dsa", "sha256"] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([NAME, "--exact", "--test-threads=1"])
                    .env(CHILD, case)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let start = std::time::Instant::now();
                while child.try_wait().unwrap().is_none() {
                    if start.elapsed() > std::time::Duration::from_mins(1) {
                        child.kill().unwrap();
                        panic!("{NAME} ({case}) did not finish in its own process");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                let out = child.wait_with_output().unwrap();
                let stdout = std::string::String::from_utf8_lossy(&out.stdout);
                assert!(
                    out.status.success() && stdout.contains("test result: ok. 1 passed"),
                    "{NAME} ({case}) did not pass in its own process:\n{stdout}{}",
                    std::string::String::from_utf8_lossy(&out.stderr)
                );
            }
            return;
        }
        let pass: fn() -> Result<(), SelfTestFailure> = || Ok(());
        let stand_in = [KatEntry {
            name: "integrity not verifiable in an unsigned test binary",
            run: pass,
        }];
        initialize_with_tests(&stand_in, &[]).unwrap();
        // Which CAST's flag this process exercises: the ML-DSA-87 one, or
        // with the variable set to `sha256`, the SHA-256 one.
        let (flag, other) = if std::env::var(CHILD).as_deref() == Ok("sha256") {
            (&super::SHA256_CAST_PASSED, &super::ML_DSA_CAST_PASSED)
        } else {
            (&super::ML_DSA_CAST_PASSED, &super::SHA256_CAST_PASSED)
        };
        // Control: a passing CAST on the operational module changes nothing.
        assert!(super::run_cast(flag, pass, "test").is_ok());
        assert!(flag.load(Ordering::Acquire));
        assert_eq!(state(), State::Operational);

        other.store(true, Ordering::Release);
        assert!(super::run_cast(flag, || Err(SelfTestFailure), "test").is_err());
        assert!(!flag.load(Ordering::Acquire));
        assert!(!super::casts_passed());
        assert_eq!(state(), State::Error);
        assert!(oxicrypt_sha::sha256::sha256(b"abc").is_err());
    }

    /// An admitted boot test that the module refuses part-way, as a
    /// concurrent transition to `Error` would, records its verdict and its
    /// detail rather than leaving the indicator at `NotRun`. Runs in a
    /// process of its own, because it changes the process-global state.
    #[test]
    fn a_module_refusal_after_admission_is_recorded() {
        use oxicrypt_module::{Error, KatEntry, SelfTestFailure, State, initialize_with_tests};
        fn refused(_: usize, _: usize, _: &mut Option<[u8; 32]>) -> Result<(), IntegrityError> {
            Err(IntegrityError::Module(Error::NotOperational {
                current: State::Error,
            }))
        }
        fn group() -> Result<(), SelfTestFailure> {
            super::ML_DSA_CAST_PASSED.store(true, Ordering::Release);
            super::SHA256_CAST_PASSED.store(true, Ordering::Release);
            super::boot_test(refused)
        }
        const CHILD: &str = "OXICRYPT_INTEGRITY_ADMITTED_CHILD";
        const NAME: &str = "tests::a_module_refusal_after_admission_is_recorded";
        if std::env::var_os(CHILD).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([NAME, "--exact", "--test-threads=1"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = std::string::String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("test result: ok. 1 passed"),
                "{NAME} did not pass in its own process:\n{stdout}{}",
                std::string::String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        // Control: a call outside the self-tests, here before initialisation,
        // is refused at admission and records nothing, so the boot that does
        // run still owns the indicator. Recording every outcome, admission's
        // refusal included, fails here.
        assert!(super::boot_test(refused).is_err());
        assert_eq!(super::status(), IntegrityStatus::NotRun);
        assert!(super::status_detail().is_none());
        // The admitted run refused part-way records its verdict. Treating
        // every `Module` error as a call that never started, as a check made
        // after the run rather than at admission does, fails here.
        let entries = [KatEntry {
            name: "integrity, refused part-way",
            run: group,
        }];
        assert!(initialize_with_tests(&entries, &[]).is_err());
        assert_eq!(super::status(), IntegrityStatus::Refused);
        assert!(super::status_detail().is_some());
    }

    #[test]
    fn fingerprints_format_as_sha256_and_lowercase_hex() {
        let text = format_fingerprint(&[0xab; 32]);
        assert_eq!(text.len(), 7 + 64);
        assert!(text.starts_with("sha256:abab"));
        assert!(text[7..].bytes().all(|b| b == b'a' || b == b'b'));
    }

    /// Each outcome maps to its own indicator, and a key mismatch is told
    /// apart from every other slot defect.
    #[test]
    fn outcomes_map_to_distinct_indicators() {
        let cases: [(Result<(), IntegrityError>, u8); 12] = [
            (Ok(()), 1),
            (Err(IntegrityError::SignatureInvalid), 2),
            (Err(IntegrityError::SlotInvalid(SlotDefect::Unsigned)), 3),
            (Err(IntegrityError::SlotInvalid(SlotDefect::NoEntries)), 10),
            (
                Err(IntegrityError::SlotInvalid(SlotDefect::HeaderMagic)),
                10,
            ),
            (
                Err(IntegrityError::SlotInvalid(SlotDefect::UnsupportedVersion(
                    2,
                ))),
                10,
            ),
            (Err(IntegrityError::Unreadable(Unreadable::OutOfMemory)), 4),
            (
                Err(IntegrityError::SlotInvalid(SlotDefect::BindUnsupported(0))),
                10,
            ),
            (Err(IntegrityError::CastNotRun), 5),
            (Err(IntegrityError::NoVerifyKey), 8),
            (Err(IntegrityError::SlotInvalid(SlotDefect::KeyMismatch)), 9),
            (
                Err(IntegrityError::Module(
                    oxicrypt_module::Error::NotOperational {
                        current: oxicrypt_module::State::Error,
                    },
                )),
                7,
            ),
        ];
        for (outcome, raw) in cases {
            assert_eq!(IntegrityStatus::of(&outcome) as u8, raw);
            assert_eq!(decode_status(raw) as u8, raw);
        }
        // Control: values the module never writes read as Unknown.
        assert_eq!(decode_status(6), IntegrityStatus::Unknown);
        assert_eq!(decode_status(11), IntegrityStatus::Unknown);
    }

    /// Every status, in discriminant order. The list is extended by hand.
    /// [`position`] matches on each variant with no wildcard, so a new
    /// variant does not compile until it is given a position there. The
    /// test below checks that each entry here sits at its position, so the
    /// list holds no variant twice and none out of place; a variant left
    /// out of the list is not caught.
    const ALL_STATUSES: [IntegrityStatus; 11] = [
        IntegrityStatus::NotRun,
        IntegrityStatus::Passed,
        IntegrityStatus::SignatureInvalid,
        IntegrityStatus::SlotInvalid,
        IntegrityStatus::Unreadable,
        IntegrityStatus::CastNotRun,
        IntegrityStatus::Unknown,
        IntegrityStatus::Refused,
        IntegrityStatus::NoVerifyKey,
        IntegrityStatus::KeyMismatch,
        IntegrityStatus::SlotDamaged,
    ];

    /// The index of `status` in [`ALL_STATUSES`].
    const fn position(status: IntegrityStatus) -> usize {
        match status {
            IntegrityStatus::NotRun => 0,
            IntegrityStatus::Passed => 1,
            IntegrityStatus::SignatureInvalid => 2,
            IntegrityStatus::SlotInvalid => 3,
            IntegrityStatus::Unreadable => 4,
            IntegrityStatus::CastNotRun => 5,
            IntegrityStatus::Unknown => 6,
            IntegrityStatus::Refused => 7,
            IntegrityStatus::NoVerifyKey => 8,
            IntegrityStatus::KeyMismatch => 9,
            IntegrityStatus::SlotDamaged => 10,
        }
    }

    /// Every status decodes back from the byte it is recorded and reported
    /// as.
    #[test]
    fn every_status_round_trips_through_its_byte() {
        assert_eq!(ALL_STATUSES.len(), 11);
        for (i, status) in ALL_STATUSES.into_iter().enumerate() {
            assert_eq!(position(status), i, "{status:?} is out of place");
            assert_eq!(decode_status(status as u8), status, "{status:?}");
        }
    }

    /// The status latch keeps the first recorded outcome.
    #[test]
    fn the_status_latch_keeps_the_first_outcome() {
        let cell = AtomicU8::new(IntegrityStatus::NotRun as u8);
        latch_outcome(&cell, &Err(IntegrityError::SignatureInvalid));
        latch_outcome(&cell, &Ok(()));
        assert_eq!(
            decode_status(cell.load(Ordering::Acquire)),
            IntegrityStatus::SignatureInvalid
        );
        let fresh = AtomicU8::new(IntegrityStatus::NotRun as u8);
        latch_outcome(&fresh, &Ok(()));
        assert_eq!(
            decode_status(fresh.load(Ordering::Acquire)),
            IntegrityStatus::Passed
        );
    }
}

/// The functions `build.rs` runs, compiled here so their refusals are
/// tested.
#[cfg(test)]
#[path = "../build_key.rs"]
mod build_key;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod build_key_tests {
    use std::ffi::OsStr;

    use super::build_key::{KEY_LEN, checked, emit, resolve_key};

    /// The ML-DSA-87 public key a fixed seed derives.
    fn public_key() -> [u8; KEY_LEN] {
        crate::test_support::start_module();
        oxicrypt_ml_dsa::ml_dsa_87::keygen_internal(&[0x5a; 32])
            .unwrap()
            .0
    }

    /// The build script's length is the module's.
    #[test]
    fn the_build_length_is_the_verify_key_length() {
        assert_eq!(KEY_LEN, crate::key::VERIFY_KEY_LEN);
        assert_eq!(KEY_LEN, 2_592);
    }

    /// A 64-byte key file stops the build with a message naming the length
    /// it needs.
    #[test]
    fn a_64_byte_key_file_stops_the_build() {
        let err =
            resolve_key(Some(OsStr::new("/k.pub")), None, &|_| Ok(vec![0x11; 64])).unwrap_err();
        assert!(err.contains("2592-byte ML-DSA-87"), "{err}");
        assert!(err.contains("not 64 bytes"), "{err}");
        let err = resolve_key(None, Some(OsStr::new(&"11".repeat(64))), &no_read).unwrap_err();
        assert!(err.contains("not 64 bytes"), "{err}");
        // Control: a key of the right length is accepted from both forms.
        let key = public_key();
        assert_eq!(
            resolve_key(Some(OsStr::new("/k.pub")), None, &|_| Ok(key.to_vec())).unwrap(),
            Some(key)
        );
        assert_eq!(
            resolve_key(None, Some(OsStr::new(&hex(&key))), &no_read).unwrap(),
            Some(key)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    fn no_read(_: &std::path::Path) -> std::io::Result<Vec<u8>> {
        panic!("the file form was not chosen")
    }

    #[test]
    fn the_file_form_reads_the_named_file() {
        let key = public_key();
        let got = resolve_key(Some(OsStr::new("/k.pub")), None, &|p| {
            assert_eq!(p, std::path::Path::new("/k.pub"));
            Ok(key.to_vec())
        })
        .unwrap();
        assert_eq!(got, Some(key));
    }

    #[test]
    fn the_hex_form_decodes_the_digits() {
        let key = public_key();
        let text = format!("  {}\n", hex(&key));
        assert_eq!(
            resolve_key(None, Some(OsStr::new(&text)), &no_read).unwrap(),
            Some(key)
        );
        assert!(resolve_key(None, Some(OsStr::new("abc")), &no_read).is_err());
        assert!(resolve_key(None, Some(OsStr::new(&"zz".repeat(KEY_LEN))), &no_read).is_err());
    }

    #[test]
    fn neither_variable_is_no_key_and_both_is_refused() {
        assert_eq!(resolve_key(None, None, &no_read).unwrap(), None);
        let err =
            resolve_key(Some(OsStr::new("/k")), Some(OsStr::new("00")), &no_read).unwrap_err();
        assert!(err.contains("not both"), "{err}");
    }

    /// A value that is not UTF-8 is refused, never read as unset.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_hex_value_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let err = resolve_key(None, Some(OsStr::from_bytes(&[0xff, 0xfe])), &no_read).unwrap_err();
        assert!(err.contains("UTF-8"), "{err}");
    }

    #[test]
    fn wrong_lengths_and_zero_keys_are_refused() {
        let key = public_key();
        assert!(
            checked(&key[..KEY_LEN - 1], "k")
                .unwrap_err()
                .contains("2591 bytes")
        );
        let mut long = key.to_vec();
        long.push(0);
        assert!(checked(&long, "k").unwrap_err().contains("2593 bytes"));
        assert!(
            checked(&[0u8; KEY_LEN], "k")
                .unwrap_err()
                .contains("all-zero")
        );
        // Control: the real key is accepted.
        assert_eq!(checked(&key, "k").unwrap(), key);
    }

    #[test]
    fn the_emitted_source_carries_the_key_bytes() {
        let key = public_key();
        let src = emit(Some(&key));
        assert!(src.contains(&format!("{:#04x}, ", key[0])));
        assert!(src.contains(&format!("{:#04x}, ];", key[KEY_LEN - 1])));
        assert!(src.contains("[u8; VERIFY_KEY_LEN]"));
        assert!(emit(None).contains("[0x00, "));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use oxicrypt_module::{KatEntry, initialize_with_tests, require_self_test_started};

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// Brings the module out of `PowerOff` so that a test can call the
    /// `*_internal` functions, which refuse until the self-tests have
    /// started. A second call in the same process is a no-op.
    pub(crate) fn start_module() {
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
        assert_eq!(require_self_test_started(), Ok(()));
    }
}
