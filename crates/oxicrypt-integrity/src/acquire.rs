//! Byte acquisition — reading the module's own image.
//!
//! One technique, one small platform-specific step. Every mechanism
//! implemented here is a **file read**, so a wrong offset produces an
//! error return or a short read rather than undefined behaviour. That is
//! what lets the crate keep `#![forbid(unsafe_code)]`, and it is the
//! reason the file-shaped route is preferred wherever a platform offers
//! one: the failure mode of a raw pointer read, in the crate whose whole
//! job is integrity, is the one failure mode worth spending effort to
//! avoid.
//!
//! Targets with no file-shaped route need a kernel-mediated copy and
//! therefore an `extern` declaration, which lives in
//! `oxicrypt-imageread` rather than here — that is what lets this crate
//! keep its `forbid`. Darwin and Windows take that route through
//! [`self_image`], with one mechanism and no fallback, because neither
//! platform offers a second.
//!
//! Android is served by the file-shaped route above rather than by an
//! exception: `/proc/self/mem` works for a dumpable process, and the
//! backing file covers the case where it does not.
//!
//! A target with neither route reports [`Unreadable::NoMechanism`] and
//! the module does not become operational. An unverifiable module is an
//! error state, not a pass.

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use imp::verify_at;
#[cfg(any(target_os = "macos", target_os = "ios", windows))]
pub(crate) use self_image::verify_at;

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
use crate::{IntegrityError, Unreadable};

/// Fallback for targets with no implemented mechanism.
///
/// Reporting "the test was not performed" is the honest answer and the
/// safe one: the runner latches the error state, so a target reaches
/// operational only once its mechanism exists.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
pub(crate) fn verify_at(_slot_addr: usize) -> Result<(), IntegrityError> {
    Err(IntegrityError::Unreadable(Unreadable::NoMechanism))
}

/// Darwin and Windows — one mechanism, the loaded image itself.
///
/// There is no second mechanism to fall back to, and that is a property
/// of the platforms rather than an omission: neither exposes a
/// file-shaped route to a process's own memory, which is the whole
/// reason `oxicrypt-imageread` exists. A read that fails here is
/// therefore final, and the module enters its error state.
#[cfg(any(target_os = "macos", target_os = "ios", windows))]
mod self_image {
    use oxicrypt_hmac::HmacSha256;
    use oxicrypt_imageread::read_self;

    use crate::slot::{self, SlotDefect};
    use crate::{FIPS_INTEGRITY_KEY, IntegrityError, SLOT_SIZE, Unreadable, constant_time_eq};

    /// Bytes hashed per read. Matches the Linux path's chunk for the
    /// same reason: a multi-megabyte extent costs a few dozen calls
    /// while the working buffer stays off the boot path's peak.
    const CHUNK: usize = 64 * 1024;

    /// Runs the pre-operational integrity test against the loaded image.
    ///
    /// The load base is derived from the slot rather than from any
    /// image-walking API: the signer recorded the slot's offset from the
    /// base, and the caller supplies the slot's address, so the
    /// subtraction is the base. That keeps every executable-format
    /// question on the signer's side of the boundary, where it belongs —
    /// this crate parses no headers.
    pub(crate) fn verify_at(slot_addr: usize) -> Result<(), IntegrityError> {
        let mut slot_bytes = vec![0u8; SLOT_SIZE];
        read_self(slot_addr, &mut slot_bytes)
            .map_err(|e| IntegrityError::Unreadable(Unreadable::SelfReadFailed(e)))?;

        let parsed = slot::parse(&slot_bytes).map_err(IntegrityError::SlotInvalid)?;
        let base = (slot_addr as u64)
            .checked_sub(u64::from(parsed.slot_rva))
            .ok_or(IntegrityError::SlotInvalid(SlotDefect::SlotRvaTooLarge))?;

        let mut mac = HmacSha256::new_internal(&FIPS_INTEGRITY_KEY);
        let mut buf = vec![0u8; CHUNK];
        for (index, range) in parsed.ranges.iter().enumerate() {
            // The real table index, so a diagnostic names the range that
            // actually failed rather than always naming the first.
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            let overflow = || IntegrityError::SlotInvalid(SlotDefect::RangeOverflow(index));
            let mut done: u32 = 0;
            while done < range.len {
                let remaining = range.len.saturating_sub(done);
                let take = usize::try_from(remaining).unwrap_or(CHUNK).min(CHUNK);
                let addr = base
                    .checked_add(u64::from(range.rva))
                    .and_then(|p| p.checked_add(u64::from(done)))
                    .and_then(|p| usize::try_from(p).ok())
                    .ok_or_else(overflow)?;
                let window = buf.get_mut(..take).ok_or_else(overflow)?;
                read_self(addr, window)
                    .map_err(|e| IntegrityError::Unreadable(Unreadable::SelfReadFailed(e)))?;
                mac.update(window);
                done = done.saturating_add(u32::try_from(take).unwrap_or(0));
            }
        }

        if constant_time_eq(&mac.finalize(), &parsed.mac) {
            Ok(())
        } else {
            Err(IntegrityError::Mismatch)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::FileExt;

    use oxicrypt_hmac::HmacSha256;

    use crate::slot::{self, Range, SlotImage};
    use crate::{FIPS_INTEGRITY_KEY, IntegrityError, SLOT_SIZE, Unreadable, constant_time_eq};

    /// Bytes read per `pread` while hashing. Large enough that a
    /// multi-megabyte code segment costs a few dozen syscalls, small
    /// enough to keep the working buffer off the boot path's peak.
    const CHUNK: usize = 64 * 1024;

    /// How an attempt ended.
    ///
    /// The distinction is load-bearing. An `Io` failure means *this
    /// mechanism* could not supply the bytes, so the next mechanism is
    /// tried. A `Verdict` is the test's answer — a mismatch or a
    /// malformed slot — and **must not** be retried against another
    /// source: falling through on a mismatch would let a second
    /// mechanism mask a real integrity failure found by the first.
    enum Attempt {
        Io(io::Error),
        Verdict(IntegrityError),
    }

    /// Which coordinate space a reader's positions are in.
    enum Coord {
        /// Positions are addresses in the loaded image.
        Memory { slot_addr: usize },
        /// Positions are offsets in the signed file.
        File { slot_file_off: u64 },
    }

    /// A positioned reader over one byte source.
    struct Reader {
        file: File,
        coord: Coord,
    }

    impl Reader {
        /// Position of the slot in this source's coordinate space.
        fn slot_pos(&self) -> u64 {
            match self.coord {
                Coord::Memory { slot_addr } => slot_addr as u64,
                Coord::File { slot_file_off } => slot_file_off,
            }
        }

        /// Position of `range[offset]` in this source's coordinate
        /// space. `base` is the load base and is unused for a file
        /// source, whose ranges carry their own file offsets.
        fn range_pos(&self, range: &Range, base: u64, offset: u32) -> Option<u64> {
            match self.coord {
                Coord::Memory { .. } => base
                    .checked_add(u64::from(range.rva))
                    .and_then(|p| p.checked_add(u64::from(offset))),
                Coord::File { .. } => u64::from(range.file_off).checked_add(u64::from(offset)),
            }
        }

        /// Load base implied by a parsed slot, for this coordinate
        /// space.
        fn base_for(&self, parsed: &SlotImage) -> Result<u64, IntegrityError> {
            match self.coord {
                Coord::Memory { slot_addr } => (slot_addr as u64)
                    .checked_sub(u64::from(parsed.slot_rva))
                    .ok_or(IntegrityError::SlotInvalid(
                        slot::SlotDefect::SlotRvaTooLarge,
                    )),
                Coord::File { .. } => Ok(0),
            }
        }
    }

    /// Runs the whole test against one byte source.
    fn attempt(reader: &Reader) -> Result<(), Attempt> {
        let mut slot_bytes = vec![0u8; SLOT_SIZE];
        reader
            .file
            .read_exact_at(&mut slot_bytes, reader.slot_pos())
            .map_err(Attempt::Io)?;

        let parsed = slot::parse(&slot_bytes)
            .map_err(|d| Attempt::Verdict(IntegrityError::SlotInvalid(d)))?;
        let base = reader.base_for(&parsed).map_err(Attempt::Verdict)?;

        let mut mac = HmacSha256::new_internal(&FIPS_INTEGRITY_KEY);
        let mut buf = vec![0u8; CHUNK];
        for (index, range) in parsed.ranges.iter().enumerate() {
            // The real table index, so a diagnostic names the range that
            // actually failed rather than always naming the first.
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            let overflow = || {
                Attempt::Verdict(IntegrityError::SlotInvalid(
                    slot::SlotDefect::RangeOverflow(index),
                ))
            };
            let mut done: u32 = 0;
            while done < range.len {
                let remaining = range.len.saturating_sub(done);
                let take = usize::try_from(remaining).unwrap_or(CHUNK).min(CHUNK);
                let pos = reader.range_pos(range, base, done).ok_or_else(overflow)?;
                let window = buf.get_mut(..take).ok_or_else(overflow)?;
                reader
                    .file
                    .read_exact_at(window, pos)
                    .map_err(Attempt::Io)?;
                mac.update(window);
                done = done.saturating_add(u32::try_from(take).unwrap_or(0));
            }
        }

        if constant_time_eq(&mac.finalize(), &parsed.mac) {
            Ok(())
        } else {
            Err(Attempt::Verdict(IntegrityError::Mismatch))
        }
    }

    /// One line of `/proc/self/maps`, reduced to what is needed here.
    struct Mapping {
        start: usize,
        end: usize,
        offset: u64,
        path: Option<String>,
    }

    /// Finds the mapping containing `addr`.
    ///
    /// This supplies two things the verifier cannot get otherwise: the
    /// backing file's path, for the file-read fallback, and that file's
    /// offset for the mapping, which turns the slot's address into a
    /// file offset without any format parsing.
    fn mapping_containing(addr: usize) -> Result<Mapping, Unreadable> {
        let maps =
            std::fs::read_to_string("/proc/self/maps").map_err(Unreadable::MapsUnavailable)?;
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let Some(range) = fields.next() else { continue };
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                continue;
            };
            if addr < start || addr >= end {
                continue;
            }
            // perms, then the file offset. A mapping whose offset will
            // not parse is refused rather than defaulted: this value is
            // added to the slot's address to locate it in the backing
            // file, so substituting zero would not fail — it would read
            // the wrong bytes and report a mismatch.
            let _perms = fields.next();
            let Some(Ok(offset)) = fields.next().map(|o| u64::from_str_radix(o, 16)) else {
                return Err(Unreadable::MapsUnparseable);
            };
            // dev, inode, then an optional path that may contain spaces.
            let _dev = fields.next();
            let _inode = fields.next();
            let rest = fields.collect::<Vec<_>>().join(" ");
            let path = if rest.is_empty() || rest.starts_with('[') {
                None
            } else {
                Some(rest)
            };
            return Ok(Mapping {
                start,
                end,
                offset,
                path,
            });
        }
        Err(Unreadable::SlotUnmapped)
    }

    /// Runs the pre-operational integrity test, given the slot's runtime
    /// address.
    ///
    /// Mechanism order is `/proc/self/mem` then the backing file. The
    /// second exists because `/proc/<pid>/mem` becomes `root:root` for a
    /// non-dumpable process — a setuid, setcap, or privilege-dropping
    /// consumer — where the mapped file is still readable. It verifies
    /// the *file* image rather than the loaded image; the two are
    /// identical for the loader-invariant extent by construction, and the
    /// difference is documented at the crate level rather than left
    /// implicit.
    ///
    /// Both mechanisms need `/proc/self/maps`, which supplies the backing
    /// path and the mapping's file offset. An environment with no `/proc`
    /// at all therefore has no mechanism here and is an error state, not
    /// a pass.
    pub(crate) fn verify_at(slot_addr: usize) -> Result<(), IntegrityError> {
        let mapping = mapping_containing(slot_addr).map_err(IntegrityError::Unreadable)?;
        let mut failures: Vec<io::Error> = Vec::new();

        // Mechanism 1 — the loaded image.
        match File::open("/proc/self/mem") {
            Ok(file) => {
                let reader = Reader {
                    file,
                    coord: Coord::Memory { slot_addr },
                };
                match attempt(&reader) {
                    Ok(()) => return Ok(()),
                    Err(Attempt::Verdict(v)) => return Err(v),
                    Err(Attempt::Io(e)) => failures.push(e),
                }
            }
            Err(e) => failures.push(e),
        }

        // Mechanism 2 — the backing file.
        let Some(path) = mapping.path else {
            return Err(IntegrityError::Unreadable(Unreadable::NoBackingFile));
        };
        let slot_file_off = mapping
            .offset
            .checked_add((slot_addr.saturating_sub(mapping.start)) as u64)
            .ok_or(IntegrityError::Unreadable(Unreadable::SlotUnmapped))?;
        debug_assert!(slot_addr < mapping.end, "slot address outside its mapping");
        match File::open(&path) {
            Ok(file) => {
                let reader = Reader {
                    file,
                    coord: Coord::File { slot_file_off },
                };
                match attempt(&reader) {
                    Ok(()) => return Ok(()),
                    Err(Attempt::Verdict(v)) => return Err(v),
                    Err(Attempt::Io(e)) => failures.push(e),
                }
            }
            Err(e) => failures.push(e),
        }

        Err(IntegrityError::Unreadable(Unreadable::AllMechanismsFailed(
            failures,
        )))
    }
}
