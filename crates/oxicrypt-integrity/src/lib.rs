//! Pre-operational software integrity test for the oxicrypt FIPS module.
//!
//! # Approved service
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | Module image integrity check | ISO/IEC 19790:2012 §7.10.2.2 (`AS10.17`–`AS10.18`) | [`integrity_self_test`] |
//!
//! This crate implements the pre-operational software integrity test
//! required by ISO/IEC 19790:2012 §7.10.2.2, asserted by `AS10.17` and
//! `AS10.18`. The integrity technique itself is HMAC-SHA-256, whose
//! cryptographic algorithm self-test is governed by FIPS 140-3
//! IG 10.2.A and runs before this test (see "Boot order" below).
//!
//! # What is hashed: the loader-invariant image
//!
//! The test verifies the module's **runtime image** — the bytes the
//! operating-system loader mapped from the signed artifact and never
//! wrote to — rather than the bytes of a file on disk. Every loader
//! examined leaves the executable code alone and routes
//! address-dependent references through writable data (ELF through the
//! GOT, Mach-O through chained fixups into `__DATA_CONST`, PE through
//! base relocations landing in `.rdata`), so a region defined as *"every
//! byte the loader maps from the signed file and never modifies"* is
//! stable across runs and identical to the corresponding file bytes.
//!
//! Hashing the runtime image rather than the file is what makes one
//! technique reach every operational environment the module intends to
//! claim. A file-based hash cannot work where the platform rewrites the
//! delivered artifact — Apple's `codesign` edits `__LINKEDIT` and
//! FairPlay encrypts the code segment on disk while the kernel decrypts
//! it in memory — so the on-disk bytes of a shipped iOS binary are not
//! the bytes that execute. The runtime image is.
//!
//! The consequence that makes this practical: because the loader does
//! not modify the region, the **signer computes the reference MAC
//! offline from the file** while the **verifier reads memory**, and the
//! two agree by construction. No memory dump is needed in the build
//! pipeline and the module need not run at build time.
//!
//! # The extent is a list of ranges, not a rule
//!
//! The verifier performs **no classification**. The signer — a
//! build-time tool outside the cryptographic boundary, free to parse
//! ELF, Mach-O and PE — decides which ranges make up the
//! loader-invariant image for the artifact in front of it, and writes
//! that range list into the module. At runtime the module hashes the
//! ranges it is told to hash, in order. Format knowledge lives entirely
//! in the tool; the boundary crate understands one thing, a table of
//! `(rva, file_off, len)` triples.
//!
//! Ranges are **subtractive**: bytes the loader does patch are absent
//! from the extent rather than masked to zero, so both sides share a
//! single semantic — "HMAC the listed ranges in order" — with no
//! zero-substitution logic on either side and no cross-build assumption
//! about which words those are. The signer emits whatever ranges *this*
//! build produced.
//!
//! # The slot, and why it is not part of the extent
//!
//! [`FIPS_INTEGRITY_SLOT`] is a [`SLOT_SIZE`]-byte `#[used] pub static`
//! reserved at link time, carrying the format version, the range table,
//! and the reference MAC:
//!
//! ```text
//! HDR(16) | version(4) | flags(4) | count(4) | slot_rva(4) | MAC(32) | range table | pad | FTR(16)
//! ```
//!
//! **The slot's own range is never in the extent.** That is what
//! dissolves the circularity a reference MAC embedded inside the hashed
//! region would otherwise create: the signer hashes file bytes that
//! exclude the slot, then writes the MAC into the slot, and the verifier
//! hashes memory bytes that exclude the slot. Both sides hash identical
//! input by construction — there is no zeroing step on either side, and
//! no window in which the two disagree about what the slot contained.
//!
//! `slot_rva` records where the slot sits relative to the image base.
//! The verifier takes the slot's runtime address from the static and
//! subtracts `slot_rva` to recover the load base, which is all it needs
//! to turn every `rva` in the table into an address. No relocation
//! processing, no symbol lookup, no scanning.
//!
//! # Why the slot's bytes are read through the acquisition mechanism
//!
//! The verifier takes only the *address* of [`FIPS_INTEGRITY_SLOT`] from
//! the static and then reads its bytes the same way it reads every other
//! range. It never dereferences the static.
//!
//! The reason is that the signer patches the slot **after** compilation,
//! so the compiler's view of the static — all zeros in the MAC and table
//! — is stale for every signed artifact. Reading the static in Rust is a
//! read of an immutable value with a known initializer, which the
//! compiler is permitted to constant-fold; nothing in the source
//! prevents it, and the observed behaviour of any one compiler version
//! is not a guarantee. Folding would substitute the unsigned initializer
//! for the signed content, and the failure would be silent at compile
//! time. Taking the address and acquiring the bytes removes the question
//! entirely.
//!
//! # Byte acquisition
//!
//! One technique, a small platform-specific step to read the module's
//! own bytes:
//!
//! | Operational environment | Order | Mechanism | `unsafe` |
//! |---|---|---|---|
//! | Linux, Android | 1 | `pread` on `/proc/self/mem` | none |
//! | Linux, Android | 2 | `pread` the backing file at the recorded `file_off` | none |
//! | Darwin | only | `mach_vm_read_overwrite`, in `oxicrypt-imageread` | in that crate |
//! | Windows | only | `ReadProcessMemory`, in `oxicrypt-imageread` | in that crate |
//!
//! This crate carries `#![forbid(unsafe_code)]` and keeps it, on every
//! target. The Linux and Android mechanisms are file reads, so a wrong
//! offset is an error return or a short read rather than undefined
//! behaviour — a property worth preserving in the crate whose entire job
//! is integrity.
//!
//! Darwin and Windows expose no file-shaped route to a process's own
//! memory, so their reads are system calls and the `extern` declarations
//! live in `oxicrypt-imageread` rather than here. Both are
//! kernel-mediated copies, chosen so that an address named by a corrupt
//! range table returns a status instead of faulting. Those platforms
//! have **one** mechanism and no fallback, which is a property of the
//! platforms rather than an omission: a failed read is final and the
//! module enters its error state.
//!
//! A target with neither route still reports
//! [`Unreadable::NoMechanism`], and the module does not become
//! operational — an unverifiable module is an error state, not a pass.
//!
//! The second Linux mechanism verifies the **file image** rather than the
//! loaded image: a modification made to memory after loading would pass
//! it. That is consistent with the security property below, and it is
//! stated rather than left implicit. It exists because
//! `/proc/self/mem` becomes `root:root` for a non-dumpable process —
//! setuid, setcap, or privilege-dropping consumers — where reading the
//! backing file still works.
//!
//! # Security property
//!
//! This test detects **modification of the module after it was signed**.
//! An artifact whose loader-invariant image no longer matches the
//! reference MAC in its slot has changed since signing — corruption at
//! rest, corruption during loading, a faulty or partial installation, a
//! mismatched build — and the module refuses to become operational.
//!
//! The test is scoped to an artifact and the signature that artifact
//! carries. It does not establish *who* signed. The integrity key is
//! public build-time material, so any party able to write to an artifact
//! can also compute a valid reference MAC for it; an artifact modified
//! and then re-signed is internally consistent, and is a *different
//! module* rather than a defeated test. Establishing that an artifact is
//! the one a particular vendor produced is the job of the platform's
//! code signing and of the distribution channel, distinct from — and not
//! to be confused with — the module's own HMAC.
//!
//! Building this module from source and signing the result is not
//! modification-after-signing. The resulting artifact is the builder's
//! module, and this test protects it from the moment it is signed
//! exactly as it protects a vendor-signed one.
//!
//! # HMAC key policy
//!
//! The HMAC key is a fixed, publicly known 32-byte constant. The
//! integrity check is an authenticity check against accident and
//! substitution, not a secrecy check, so the key is a build-time
//! constant rather than a runtime secret. Rotating it after validation
//! is a module change and would require re-validation.
//!
//! # Sensitive security parameters
//!
//! None. The integrity HMAC key is public build-time material, the MAC
//! is public, and the module image bytes are public. No CSPs pass
//! through this crate's API.
//!
//! # Boot order
//!
//! [`integrity_self_test`] is registered in [`KATS`] as a pre-operational
//! test. The `oxicrypt-module` runner calls it while the module is in
//! `SelfTest` state, where the ordinary `HmacSha256::new` entry point is
//! still gated by `require_operational()`. This crate therefore routes
//! through `HmacSha256::new_internal`, the gateless constructor that
//! exists for exactly this reason. The HMAC-SHA-256 CAST runs before
//! the integrity test, satisfying `AS10.20`.
//!
//! # Failure modes
//!
//! Every failure is terminal — the runner latches the module into the
//! `Error` state and no service is available. The three top-level
//! variants of [`IntegrityError`] are distinguishable by design, because
//! a laboratory and an integrator need to tell "the module is corrupt"
//! from "this environment cannot supply the module's own bytes":
//!
//! - [`IntegrityError::Mismatch`] — the image does not match its
//!   reference MAC.
//! - [`IntegrityError::SlotInvalid`] — the slot is missing, malformed,
//!   or describes an extent that cannot be valid.
//! - [`IntegrityError::Unreadable`] — no byte-acquisition mechanism
//!   succeeded, so the test **was not performed**. An unverifiable
//!   module never becomes operational.
//!
//! # Signing workflow
//!
//! ```text
//! cargo build -p oxicrypt-integrity-sign
//! cargo build -p oxi
//! ./target/debug/oxicrypt-integrity-sign --sign ./target/debug/oxi
//! ./target/debug/oxi
//! ```
//!
//! A production build runs the signer as a post-link step and ships the
//! signed artifact; the runtime path never signs.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use oxicrypt_hmac::HmacSha256;
use oxicrypt_module::{KatEntry, SelfTestFailure};

mod acquire;
pub mod slot;

pub use slot::{Range, SlotDefect, SlotImage};

/// Fixed, publicly known HMAC key used for the software integrity
/// self-test.
///
/// The key material is the UTF-8 bytes of the ASCII literal
/// `"oxicrypt-fips140-3-integrity-key"` (32 bytes) — not a secret,
/// just a stable value that is trivially auditable from the source
/// tree.
///
/// The literal is exactly 32 bytes, which is what fixes its spelling:
/// `"oxicrypt-fips-140-3-integrity-key!"` would read more naturally
/// but is 34. `integrity_key_matches_its_documented_literal` asserts
/// the constant against the text above, so the two cannot drift.
pub const FIPS_INTEGRITY_KEY: [u8; 32] = *b"oxicrypt-fips140-3-integrity-key";

/// Header magic for the embedded integrity slot. 16 bytes.
///
/// The leading `0xfc` byte is a deliberately non-ASCII sentinel: it
/// makes the pattern unlikely to appear in a string table and lets the
/// signer's scanner short-circuit on a byte that rarely occurs in text
/// sections.
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
/// 16 KiB. The size is what the range table can grow into: at
/// [`slot::RANGE_ENTRY_SIZE`] bytes per entry it admits
/// [`slot::MAX_RANGES`] ranges, which is ample for a subtractive extent
/// on every format measured — the densest case observed is a PE image
/// whose 472 base relocations each split a range.
pub const SLOT_SIZE: usize = 16384;

/// Format version written by the signer and required by the verifier.
///
/// Version 1 was a 64-byte slot holding a whole-file MAC. It is not
/// accepted: the technique it encoded verifies the wrong bytes on every
/// platform that rewrites the delivered artifact, so accepting it would
/// mean the module could pass a test that does not hold.
pub const SLOT_VERSION: u32 = 2;

/// Reserved integrity slot.
///
/// `#[used]` keeps the static in this crate's object file even though no
/// Rust code reads its contents — the verifier takes its *address* and
/// reads the bytes through the byte-acquisition mechanism, for the reason
/// given in the crate documentation. The attribute binds the compiler,
/// not the linker: the Rust Reference states the linker remains free to
/// remove such an item, so the slot's presence in a linked artifact is
/// established by the signer finding it, not by the attribute.
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

/// Size of the slot's body — everything between the two magics.
pub const SLOT_BODY_SIZE: usize = SLOT_SIZE - 32;

/// Layout of the reserved integrity slot.
///
/// The body is deliberately opaque here: its interior structure is
/// defined by the field offsets in [`slot`] and parsed from bytes, not
/// by Rust field access, because the verifier never reads the static
/// directly.
#[repr(C)]
pub struct IntegritySlot {
    /// Header magic, equal to [`SLOT_HEADER_MAGIC`].
    pub hdr: [u8; 16],
    /// Version, flags, count, `slot_rva`, MAC, range table, padding.
    pub body: [u8; SLOT_BODY_SIZE],
    /// Footer magic, equal to [`SLOT_FOOTER_MAGIC`].
    pub ftr: [u8; 16],
}

/// Why no byte-acquisition mechanism could supply the module's bytes.
///
/// Distinguished from a MAC mismatch because the two mean opposite
/// things to an operator: a mismatch says the module is wrong, an
/// acquisition failure says the environment cannot answer the question.
#[derive(Debug)]
pub enum Unreadable {
    /// This target has no implemented byte-acquisition mechanism.
    NoMechanism,
    /// `/proc/self/maps` could not be read, so neither the load base nor
    /// the backing file could be established.
    MapsUnavailable(std::io::Error),
    /// The mapping holding the slot was found but a field of it did not
    /// parse, so its file offset cannot be trusted.
    MapsUnparseable,
    /// The slot's address falls in no mapping named by
    /// `/proc/self/maps`.
    SlotUnmapped,
    /// The mapping holding the slot names no backing file, so the
    /// file-read fallback has nothing to open.
    NoBackingFile,
    /// Every mechanism was tried and each failed. Carries the first
    /// error from each, in the order attempted.
    AllMechanismsFailed(Vec<std::io::Error>),
    /// The kernel refused to copy the module's own image.
    ///
    /// Darwin and Windows only. There is no second mechanism to fall
    /// back to on those platforms, so this is final rather than one
    /// failure among several — which is why it is its own variant
    /// instead of an entry in [`Unreadable::AllMechanismsFailed`].
    SelfReadFailed(oxicrypt_imageread::ReadError),
}

/// Failure of the pre-operational software integrity test.
///
/// The three variants are the module's status indicator for this test
/// (`AS10.18`); see the crate documentation.
#[derive(Debug)]
pub enum IntegrityError {
    /// The integrity technique's own algorithm self-test has not passed
    /// in this process, so the integrity test may not use it.
    ///
    /// A sequencing fault in the front end rather than a finding about
    /// the module image: it means something called the integrity test
    /// without first running [`hmac_cast`]. Reported distinctly because
    /// an error state a laboratory can reach must be one the Security
    /// Policy enumerates, and because reporting it as a mismatch would
    /// send an operator hunting for corruption that is not there.
    CastNotRun,
    /// The computed MAC over the loader-invariant image does not equal
    /// the reference MAC in the slot.
    Mismatch,
    /// The slot is absent, malformed, or describes an impossible extent.
    SlotInvalid(SlotDefect),
    /// The module's own bytes could not be obtained, so the test was not
    /// performed.
    Unreadable(Unreadable),
}

impl core::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CastNotRun => f.write_str(
                "the HMAC-SHA-256 algorithm self-test has not run, so the integrity test may not \
                 use it",
            ),
            Self::Mismatch => f.write_str(
                "module image integrity MAC mismatch — the image does not match its reference MAC",
            ),
            Self::SlotInvalid(d) => write!(f, "integrity slot invalid: {d}"),
            Self::Unreadable(u) => write!(f, "module image unreadable: {u}"),
        }
    }
}

impl core::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMechanism => f.write_str(
                "no byte-acquisition mechanism is implemented for this operational environment",
            ),
            Self::MapsUnavailable(e) => write!(f, "/proc/self/maps unreadable: {e}"),
            Self::MapsUnparseable => {
                f.write_str("the mapping holding the integrity slot could not be parsed")
            }
            Self::SlotUnmapped => f.write_str("the integrity slot lies in no reported mapping"),
            Self::NoBackingFile => {
                f.write_str("the mapping holding the integrity slot names no backing file")
            }
            Self::AllMechanismsFailed(errors) => {
                f.write_str("every byte-acquisition mechanism failed:")?;
                for e in errors {
                    write!(f, " [{e}]")?;
                }
                Ok(())
            }
            Self::SelfReadFailed(e) => {
                write!(f, "the module's own image could not be read: {e}")
            }
        }
    }
}

impl std::error::Error for IntegrityError {}

/// Formats a 32-byte MAC as 64 lowercase hex characters.
#[must_use]
pub fn encode_hmac_hex(mac: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (pair, &byte) in out.chunks_exact_mut(2).zip(mac.iter()) {
        let high = HEX.get((byte >> 4) as usize).copied().unwrap_or(b'0');
        let low = HEX.get((byte & 0x0f) as usize).copied().unwrap_or(b'0');
        if let Some(slot) = pair.first_mut() {
            *slot = high;
        }
        if let Some(slot) = pair.get_mut(1) {
            *slot = low;
        }
    }
    out
}

/// Compares two 32-byte MACs without short-circuiting: accumulates the
/// XOR of all 32 byte pairs and tests the accumulator once, so the
/// running time does not depend on where the first difference falls.
///
/// This MAC is public and sits in an artifact an attacker already holds,
/// so no secret depends on it. The compare is written this way because
/// it is the discipline this workspace applies to every MAC
/// verification.
#[must_use]
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (ai, bi) in a.iter().zip(b.iter()) {
        diff |= ai ^ bi;
    }
    diff == 0
}

/// Computes the reference MAC over `ranges` taken from the **file**
/// bytes in `image`, in table order.
///
/// This is the signer's half of the identity that makes the design work:
/// the MAC computed here from file bytes equals the MAC the verifier
/// computes from the loaded image, because the extent excludes every
/// byte the loader writes.
///
/// Shared with the signing tool so the two paths cannot disagree about
/// what "HMAC over the loader-invariant image" means.
///
/// # Errors
///
/// Returns [`SlotDefect::RangeOutOfBounds`] if any range falls outside
/// `image`.
pub fn mac_over_file_ranges(image: &[u8], ranges: &[Range]) -> Result<[u8; 32], SlotDefect> {
    let mut mac = HmacSha256::new_internal(&FIPS_INTEGRITY_KEY);
    for (index, range) in ranges.iter().enumerate() {
        let start = range.file_off as usize;
        let end = start
            .checked_add(range.len as usize)
            .ok_or(SlotDefect::RangeOutOfBounds(index_as_u32(index)))?;
        let bytes = image
            .get(start..end)
            .ok_or(SlotDefect::RangeOutOfBounds(index_as_u32(index)))?;
        mac.update(bytes);
    }
    Ok(mac.finalize())
}

/// Narrows a table index for a diagnostic. Indices are bounded by
/// [`slot::MAX_RANGES`], far below `u32::MAX`, so the saturating cast
/// cannot lose information in practice; it exists to keep the error type
/// free of `usize`.
fn index_as_u32(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

/// Runtime address of the integrity slot.
///
/// Taking the address of the static is safe and says nothing about its
/// contents: the address is the one thing the verifier takes from the
/// linked static, and the load base is derived from it. Exposed because
/// it is also the diagnostic an operator needs — across runs it shows
/// whether the image moved, which is what makes a stable verdict
/// meaningful rather than vacuous.
#[must_use]
pub fn slot_address() -> usize {
    core::ptr::from_ref(&FIPS_INTEGRITY_SLOT) as usize
}

/// Runs the pre-operational software integrity test against the loaded
/// module image.
///
/// Locates the slot by the address of [`FIPS_INTEGRITY_SLOT`], acquires
/// its bytes through the platform mechanism, validates the slot, derives
/// the load base, hashes the listed ranges from the loaded image, and
/// compares without short-circuiting.
///
/// # Errors
///
/// Returns [`IntegrityError`]; see the crate documentation for what each
/// variant means to an operator.
///
/// Records the outcome for [`status`] the first time it runs in this
/// process. The record latches, so calling this again cannot revise the
/// indicator an operator reads.
pub fn verify_loaded_image() -> Result<(), IntegrityError> {
    let outcome = if HMAC_CAST_PASSED.load(Ordering::Acquire) {
        let slot_addr = core::ptr::from_ref(&FIPS_INTEGRITY_SLOT) as usize;
        acquire::verify_at(slot_addr)
    } else {
        Err(IntegrityError::CastNotRun)
    };
    // Recorded HERE rather than in `integrity_self_test`, so the
    // indicator is set on every path that runs the test — including a
    // direct call — and not only on the one the module runner takes.
    //
    // The record LATCHES, mirroring the module's own state machine: this
    // function is public and may be called again after boot, and a later
    // benign run must not overwrite a failure the operator still needs.
    // Without the latch a transient `Unreadable` that subsequently clears
    // would rewrite the indicator to `Passed` while `oxicrypt_module`
    // stayed permanently in `Error` — the query would then contradict the
    // module state it exists to explain.
    let _ = LAST_STATUS.compare_exchange(
        IntegrityStatus::NotRun as u8,
        IntegrityStatus::of(&outcome) as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    outcome
}

/// The pre-operational integrity test's status indicator.
///
/// Security Policy §5.2 requires an operator and a test laboratory to be
/// able to tell a corrupt module from an environment that could not
/// supply the module's own bytes. The module runner's `SelfTestFailure`
/// carries no payload, so that distinction cannot travel out through
/// `initialize_with_tests`; this indicator is how it is retrieved
/// instead, and [`status`] is the retrieval.
///
/// The discriminants are stable and are what the C ABI reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum IntegrityStatus {
    /// The test has not run in this process.
    NotRun = 0,
    /// The test ran and the image matched its reference MAC.
    Passed = 1,
    /// The computed MAC does not equal the reference MAC in the slot.
    Mismatch = 2,
    /// The slot is absent, malformed, or describes an impossible extent.
    SlotInvalid = 3,
    /// The module's own bytes could not be obtained, so the test was
    /// **not performed**. This says nothing about the image.
    Unreadable = 4,
    /// The test was reached before the HMAC-SHA-256 CAST it depends on.
    CastNotRun = 5,
    /// The recorded indicator is not a value this module writes.
    ///
    /// Unreachable by construction — only [`verify_loaded_image`] writes
    /// the record, and only from the variants above. Reported rather than
    /// folded into [`IntegrityStatus::NotRun`] because this is a module
    /// whose purpose is detecting tampering: reading an impossible value
    /// as the most benign one would hide the very condition worth seeing.
    Unknown = 6,
}

impl IntegrityStatus {
    /// The indicator corresponding to one run's outcome.
    const fn of(outcome: &Result<(), IntegrityError>) -> Self {
        match outcome {
            Ok(()) => Self::Passed,
            Err(IntegrityError::Mismatch) => Self::Mismatch,
            Err(IntegrityError::SlotInvalid(_)) => Self::SlotInvalid,
            Err(IntegrityError::Unreadable(_)) => Self::Unreadable,
            Err(IntegrityError::CastNotRun) => Self::CastNotRun,
        }
    }
}

/// The last outcome recorded by [`verify_loaded_image`].
static LAST_STATUS: AtomicU8 = AtomicU8::new(IntegrityStatus::NotRun as u8);

/// Returns the pre-operational integrity test's status indicator.
///
/// [`IntegrityStatus::NotRun`] until the test has run in this process.
/// The value latches on the first run; the test is not re-run here, so
/// this is safe to call from an error state and cannot change it.
#[must_use]
pub fn status() -> IntegrityStatus {
    match LAST_STATUS.load(Ordering::Acquire) {
        1 => IntegrityStatus::Passed,
        2 => IntegrityStatus::Mismatch,
        3 => IntegrityStatus::SlotInvalid,
        4 => IntegrityStatus::Unreadable,
        5 => IntegrityStatus::CastNotRun,
        0 => IntegrityStatus::NotRun,
        _ => IntegrityStatus::Unknown,
    }
}

/// Records that the integrity technique's algorithm self-test passed in
/// this process.
static HMAC_CAST_PASSED: AtomicBool = AtomicBool::new(false);

/// The integrity technique's own cryptographic algorithm self-test.
///
/// `AS10.20` and IG 10.2.A require an approved algorithm's CAST to
/// precede any use of that algorithm, and the integrity test's technique
/// is HMAC-SHA-256 — so this runs first, and the module's own image is
/// hashed only once its hash function has been proven against a known
/// answer. SHA-256 needs no separate CAST here: IG 10.2.A permits a hash
/// to be covered implicitly by the HMAC self-test that exercises it.
///
/// The ordering is not left to convention. [`KATS`] lists this entry
/// first, so a front end passing `oxicrypt_integrity::KATS` gets the
/// sequence by construction; and [`verify_loaded_image`] refuses with
/// [`IntegrityError::CastNotRun`] if it is reached anyway. A rule that
/// cannot be violated is worth more than one every caller must remember.
///
/// # Errors
///
/// Returns [`SelfTestFailure`] if the known-answer test fails, which
/// latches the module into its terminal `Error` state.
pub fn hmac_cast() -> Result<(), SelfTestFailure> {
    oxicrypt_hmac::self_test_sha256()?;
    HMAC_CAST_PASSED.store(true, Ordering::Release);
    Ok(())
}

/// Pre-operational integrity test, in the shape the module runner wants.
///
/// Do not call this directly from application code — it is wired into
/// [`KATS`] and runs as part of `oxicrypt_module::initialize_with_tests`.
///
/// # Errors
///
/// Returns [`SelfTestFailure`] on any integrity failure, so the runner
/// latches the module into the terminal `Error` state. The richer
/// diagnosis is available from [`verify_loaded_image`], which this wraps.
pub fn integrity_self_test() -> Result<(), SelfTestFailure> {
    verify_loaded_image().map_err(|_| SelfTestFailure)
}

/// Pre-operational test inventory for the software integrity test.
///
/// Merged into a front end's boot sequence via
/// `oxicrypt_module::initialize_with_tests`, which runs entries **in
/// order**. The order here is the requirement, not a convenience: the
/// technique's CAST first (`AS10.20`, IG 10.2.A), then the integrity test
/// it enables (ISO/IEC 19790:2012 §7.10.2.2, `AS10.17`).
///
/// This slice is the module's own dependency and is self-contained. The
/// remaining approved-algorithm CASTs are a separate inventory and run
/// after these, once the module's image has been verified.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "HMAC-SHA-256 CAST (integrity technique, AS10.20)",
        run: hmac_cast,
    },
    KatEntry {
        name: "Module image integrity (HMAC-SHA-256 over the loader-invariant image)",
        run: integrity_self_test,
    },
];

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
        FIPS_INTEGRITY_KEY, Range, SLOT_FOOTER_MAGIC, SLOT_HEADER_MAGIC, SLOT_SIZE, SLOT_VERSION,
        SlotDefect, constant_time_eq, encode_hmac_hex, mac_over_file_ranges, slot,
    };

    /// The doc comment on `FIPS_INTEGRITY_KEY` names the key's literal.
    /// A doc naming the wrong key for the pre-operational integrity check
    /// is the kind of discrepancy a CST lab reads.
    ///
    /// Asserting the constant against a literal repeated in the test would
    /// prove nothing about the prose, so this reads the doc comment out of
    /// the source and compares what it *claims* against what is compiled.
    #[test]
    fn integrity_key_matches_its_documented_literal() {
        let src = include_str!("lib.rs");
        let Some(doc_start) =
            src.find("/// Fixed, publicly known HMAC key used for the software integrity")
        else {
            panic!("key doc comment not found — was it reworded?");
        };
        let Some(decl) = src[doc_start..].find("pub const FIPS_INTEGRITY_KEY") else {
            panic!("key declaration not found after its doc comment");
        };
        let doc = &src[doc_start..doc_start + decl];

        let Some(quoted_start) = doc.find("`\"") else {
            panic!("doc states no quoted literal");
        };
        let rest = &doc[quoted_start + 2..];
        let Some(quote_end) = rest.find('"') else {
            panic!("unterminated literal in doc");
        };
        let quoted = &rest[..quote_end];
        assert_eq!(
            quoted.as_bytes(),
            &FIPS_INTEGRITY_KEY[..],
            "doc comment names {quoted:?} but the constant is {:?}",
            core::str::from_utf8(&FIPS_INTEGRITY_KEY).unwrap()
        );

        let Some(len_end) = doc.find(" bytes)") else {
            panic!("doc states no byte count");
        };
        let head = &doc[..len_end];
        let Some(paren) = head.rfind('(') else {
            panic!("stated length has no opening paren");
        };
        let Ok(stated_len) = head[paren + 1..].trim().parse::<usize>() else {
            panic!("stated length is not a number");
        };
        assert_eq!(
            stated_len,
            FIPS_INTEGRITY_KEY.len(),
            "doc claims {stated_len} bytes; the constant is {}",
            FIPS_INTEGRITY_KEY.len()
        );
    }

    /// The slot magics are matched against artifact bytes by the signer,
    /// so their length is load-bearing: a 15-byte tail plus the sentinel
    /// is what makes each magic 16 bytes wide.
    #[test]
    fn slot_magics_are_sixteen_bytes_and_distinctly_sentinelled() {
        assert_eq!(SLOT_HEADER_MAGIC.len(), 16);
        assert_eq!(SLOT_FOOTER_MAGIC.len(), 16);
        assert_eq!(SLOT_HEADER_MAGIC[0], 0xfc);
        assert_eq!(SLOT_FOOTER_MAGIC[0], 0xfd);
        assert_ne!(
            SLOT_HEADER_MAGIC, SLOT_FOOTER_MAGIC,
            "header and footer must differ or the scanner cannot orient a slot"
        );
        for (name, m) in [
            ("header", &SLOT_HEADER_MAGIC),
            ("footer", &SLOT_FOOTER_MAGIC),
        ] {
            assert!(
                m[1..].iter().all(u8::is_ascii_graphic),
                "{name} magic tail must stay ASCII so it is greppable in an artifact"
            );
        }
    }

    /// The static must be exactly `SLOT_SIZE` bytes, or the signer's
    /// footer-at-a-fixed-offset check and the field offsets disagree with
    /// what is actually linked in.
    #[test]
    fn the_linked_slot_is_slot_size_bytes() {
        assert_eq!(core::mem::size_of::<super::IntegritySlot>(), SLOT_SIZE);
        assert_eq!(slot::OFF_FTR + 16, SLOT_SIZE);
    }

    fn sample_ranges() -> Vec<Range> {
        vec![
            Range {
                rva: 0,
                file_off: 0,
                len: 64,
            },
            Range {
                rva: 4096,
                file_off: 4096,
                len: 128,
            },
        ]
    }

    #[test]
    fn slot_round_trips_through_encode_and_parse() {
        let ranges = sample_ranges();
        let mac = [0x5au8; 32];
        let bytes = slot::encode(&ranges, 0x9000, &mac).unwrap();
        assert_eq!(bytes.len(), SLOT_SIZE);
        let parsed = slot::parse(&bytes).unwrap();
        assert_eq!(parsed.version, SLOT_VERSION);
        assert_eq!(parsed.slot_rva, 0x9000);
        assert_eq!(parsed.mac, mac);
        assert_eq!(parsed.ranges, ranges);
    }

    #[test]
    fn parse_rejects_a_wrong_header_magic() {
        let mut bytes = slot::encode(&sample_ranges(), 0x9000, &[0u8; 32]).unwrap();
        bytes[0] ^= 0xff;
        match slot::parse(&bytes) {
            Err(SlotDefect::HeaderMagic) => {}
            other => panic!("expected HeaderMagic, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_a_wrong_footer_magic() {
        let mut bytes = slot::encode(&sample_ranges(), 0x9000, &[0u8; 32]).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        match slot::parse(&bytes) {
            Err(SlotDefect::FooterMagic) => {}
            other => panic!("expected FooterMagic, got {other:?}"),
        }
    }

    /// An unsigned artifact carries the magics and nothing else, so its
    /// version field is zero. It must be refused as a distinct defect —
    /// "never signed" is a different operator problem from "corrupt".
    #[test]
    fn parse_rejects_an_unsigned_slot() {
        let mut bytes = vec![0u8; SLOT_SIZE];
        bytes[..16].copy_from_slice(&SLOT_HEADER_MAGIC);
        bytes[slot::OFF_FTR..].copy_from_slice(&SLOT_FOOTER_MAGIC);
        match slot::parse(&bytes) {
            Err(SlotDefect::UnsupportedVersion(0)) => {}
            other => panic!("expected UnsupportedVersion(0), got {other:?}"),
        }
    }

    /// Version 1 was the whole-file scheme. Accepting it would let the
    /// module pass a test that verifies the wrong bytes.
    #[test]
    fn parse_rejects_the_superseded_version_one() {
        let mut bytes = slot::encode(&sample_ranges(), 0x9000, &[0u8; 32]).unwrap();
        bytes[slot::OFF_VERSION..slot::OFF_VERSION + 4].copy_from_slice(&1u32.to_le_bytes());
        match slot::parse(&bytes) {
            Err(SlotDefect::UnsupportedVersion(1)) => {}
            other => panic!("expected UnsupportedVersion(1), got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_an_empty_range_table() {
        let bytes = slot::encode(&[], 0x9000, &[0u8; 32]).unwrap();
        match slot::parse(&bytes) {
            Err(SlotDefect::NoRanges) => {}
            other => panic!("expected NoRanges, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_a_zero_length_range() {
        let ranges = vec![Range {
            rva: 0,
            file_off: 0,
            len: 0,
        }];
        let bytes = slot::encode(&ranges, 0x9000, &[0u8; 32]).unwrap();
        match slot::parse(&bytes) {
            Err(SlotDefect::EmptyRange(0)) => {}
            other => panic!("expected EmptyRange(0), got {other:?}"),
        }
    }

    /// Ranges must be strictly ascending and non-overlapping. Overlap
    /// would let a signer double-count bytes, and unordered ranges would
    /// make "in table order" ambiguous between signer and verifier.
    #[test]
    fn parse_rejects_overlapping_ranges() {
        let ranges = vec![
            Range {
                rva: 0,
                file_off: 0,
                len: 4096,
            },
            Range {
                rva: 2048,
                file_off: 2048,
                len: 4096,
            },
        ];
        let bytes = slot::encode(&ranges, 0x9000, &[0u8; 32]).unwrap();
        match slot::parse(&bytes) {
            Err(SlotDefect::Unordered(1)) => {}
            other => panic!("expected Unordered(1), got {other:?}"),
        }
    }

    /// The whole circularity resolution rests on the slot being outside
    /// the extent. A signer that got that wrong must be refused loudly
    /// rather than producing a mismatch that reads like corruption.
    #[test]
    fn parse_rejects_a_range_covering_the_slot() {
        let slot_rva = 0x9000;
        let ranges = vec![Range {
            rva: 0x8000,
            file_off: 0x8000,
            len: 0x4000,
        }];
        let bytes = slot::encode(&ranges, slot_rva, &[0u8; 32]).unwrap();
        match slot::parse(&bytes) {
            Err(SlotDefect::OverlapsSlot(0)) => {}
            other => panic!("expected OverlapsSlot(0), got {other:?}"),
        }
    }

    /// A range abutting the slot on either side is legal — that is
    /// exactly what subtracting the slot from a larger segment produces,
    /// so the mirror control matters as much as the rejection above.
    #[test]
    fn parse_accepts_ranges_abutting_the_slot() {
        let slot_rva = 0x9000;
        let ranges = vec![
            Range {
                rva: 0x8000,
                file_off: 0x8000,
                len: 0x1000,
            },
            Range {
                rva: slot_rva + SLOT_SIZE as u32,
                file_off: slot_rva + SLOT_SIZE as u32,
                len: 0x1000,
            },
        ];
        let bytes = slot::encode(&ranges, slot_rva, &[0u8; 32]).unwrap();
        let parsed = slot::parse(&bytes).unwrap();
        assert_eq!(parsed.ranges.len(), 2);
    }

    #[test]
    fn encode_refuses_more_ranges_than_the_table_holds() {
        let ranges: Vec<Range> = (0..=slot::MAX_RANGES)
            .map(|i| Range {
                rva: (i as u32) * 16,
                file_off: (i as u32) * 16,
                len: 8,
            })
            .collect();
        match slot::encode(&ranges, 0, &[0u8; 32]) {
            Err(SlotDefect::TooManyRanges(_)) => {}
            other => panic!("expected TooManyRanges, got {other:?}"),
        }
    }

    #[test]
    fn mac_over_file_ranges_hashes_only_the_listed_bytes() {
        let mut image = vec![0u8; 8192];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let ranges = sample_ranges();
        let first = mac_over_file_ranges(&image, &ranges).unwrap();

        // A byte inside a listed range changes the MAC.
        let mut inside = image.clone();
        inside[10] ^= 0xff;
        assert_ne!(
            first,
            mac_over_file_ranges(&inside, &ranges).unwrap(),
            "a change inside the extent must change the MAC"
        );

        // A byte between the two ranges does not — this is the control
        // proving the extent is genuinely subtractive rather than a
        // whole-file hash wearing a range table.
        let mut outside = image.clone();
        outside[2048] ^= 0xff;
        assert_eq!(
            first,
            mac_over_file_ranges(&outside, &ranges).unwrap(),
            "a change outside the extent must not change the MAC"
        );
    }

    #[test]
    fn mac_over_file_ranges_rejects_a_range_past_the_image() {
        let image = vec![0u8; 64];
        let ranges = vec![Range {
            rva: 0,
            file_off: 0,
            len: 128,
        }];
        match mac_over_file_ranges(&image, &ranges) {
            Err(SlotDefect::RangeOutOfBounds(0)) => {}
            other => panic!("expected RangeOutOfBounds(0), got {other:?}"),
        }
    }

    #[test]
    fn encode_hmac_hex_is_lowercase_and_64_chars() {
        let mac = [0xabu8; 32];
        let hex = encode_hmac_hex(&mac);
        assert_eq!(hex.len(), 64);
        let expected: Vec<u8> = std::iter::repeat_n(b'a', 1)
            .chain(std::iter::repeat_n(b'b', 1))
            .cycle()
            .take(64)
            .collect();
        assert_eq!(hex.as_slice(), expected.as_slice());
    }

    #[test]
    fn constant_time_eq_detects_differences() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[31] = 1;
        assert!(!constant_time_eq(&a, &b));
    }
}
