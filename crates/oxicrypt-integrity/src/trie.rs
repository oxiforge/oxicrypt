//! The Darwin export trie of a loaded image, read for the x86_64
//! resolver-stub rule (see `verify::check_bind_word`).
//!
//! On x86_64 the loader binds an import whose export is a resolver
//! function to a stub, `jmp *disp32(%rip)`, in the exporting image. The
//! stub's address is recorded in that image's export trie, under the
//! symbol's own name, by an entry flagged `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`.
//! This module finds the trie through the image's load commands as loaded
//! and looks one name up in it. Every read goes through the caller's memory
//! route, every length and offset is checked, and the walk is bounded by
//! the name's length; anything malformed is an error, never a match.

use crate::Unreadable;
use crate::verify::Process;

/// `EXPORT_SYMBOL_FLAGS_REEXPORT`.
const REEXPORT: u64 = 0x08;
/// `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`.
const STUB_AND_RESOLVER: u64 = 0x10;
/// 64-bit Mach-O, as the loaded header holds it.
const MH_MAGIC_64: u32 = 0xfeed_facf;
/// `LC_SEGMENT_64`.
const LC_SEGMENT_64: u32 = 0x19;
/// `LC_DYLD_INFO` and `LC_DYLD_INFO_ONLY`.
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
/// The dependent-library load commands, in the order dyld numbers them:
/// `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`,
/// `LC_LAZY_LOAD_DYLIB`, `LC_LOAD_UPWARD_DYLIB`.
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
/// `LC_DYLD_EXPORTS_TRIE`.
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
/// The load commands read, at most.
const MAX_COMMANDS: u32 = 64 * 1024;
/// The trie read, at most.
const MAX_TRIE: u64 = 16 * 1024 * 1024;

/// What the trie records for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Export {
    /// A stub-and-resolver entry: the stub's and the resolver's offsets
    /// from the image's Mach header.
    Stub {
        /// The stub's offset.
        stub: u64,
        /// The resolver's offset.
        resolver: u64,
    },
    /// A re-export: the 1-based ordinal of the dependent library that
    /// exports it, and its name there (empty when it keeps this one).
    Reexport {
        /// The library ordinal.
        ordinal: u64,
        /// The name in that library, or empty for the same name.
        name: Vec<u8>,
    },
    /// Any other export: a plain address, a thread-local or absolute
    /// symbol.
    Other,
}

/// A malformed trie or load-command table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// The ULEB128 at `*at`, which advances past it: at most ten bytes, and
/// refused when it does not fit 64 bits.
fn uleb(t: &[u8], at: &mut usize) -> Result<u64, Malformed> {
    let mut value: u64 = 0;
    for shift in (0..70).step_by(7) {
        let byte = *t.get(*at).ok_or(Malformed)?;
        *at = at.checked_add(1).ok_or(Malformed)?;
        let bits = u64::from(byte & 0x7f);
        if shift == 63 && bits > 1 {
            return Err(Malformed);
        }
        value |= bits.checked_shl(shift).ok_or(Malformed)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Malformed)
}

/// Looks `name` up in `trie`. `Ok(None)` when the trie holds no export of
/// that exact name.
///
/// Each step follows one edge, which consumes at least one byte of the
/// name, so the walk takes at most `name.len()` steps; an empty edge is
/// malformed.
pub(crate) fn lookup(trie: &[u8], name: &[u8]) -> Result<Option<Export>, Malformed> {
    let mut node = 0usize;
    let mut rest = name;
    let mut visited: Vec<usize> = Vec::new();
    // Each pass either returns or follows an edge, which consumes at least
    // one byte of `rest`, so the loop ends within `name.len() + 1` passes;
    // a node reached twice is a cycle, and malformed.
    loop {
        if visited.contains(&node) {
            return Err(Malformed);
        }
        visited.push(node);
        let mut at = node;
        let terminal = usize::try_from(uleb(trie, &mut at)?).map_err(|_| Malformed)?;
        let children = at.checked_add(terminal).ok_or(Malformed)?;
        // Every node's child list is read in full, whether or not the walk
        // goes on: a child that lies outside the trie is malformed.
        let count = *trie.get(children).ok_or(Malformed)?;
        let mut edge_at = children.checked_add(1).ok_or(Malformed)?;
        let mut next = None;
        for _ in 0..count {
            let tail = trie.get(edge_at..).ok_or(Malformed)?;
            let len = tail.iter().position(|&b| b == 0).ok_or(Malformed)?;
            if len == 0 {
                return Err(Malformed);
            }
            let edge = tail.get(..len).ok_or(Malformed)?;
            edge_at = edge_at
                .checked_add(len)
                .and_then(|a| a.checked_add(1))
                .ok_or(Malformed)?;
            let child = usize::try_from(uleb(trie, &mut edge_at)?).map_err(|_| Malformed)?;
            if child >= trie.len() {
                return Err(Malformed);
            }
            if next.is_none() && rest.starts_with(edge) {
                next = Some((child, len));
            }
        }
        if rest.is_empty() {
            if terminal == 0 {
                return Ok(None);
            }
            return terminal_export(trie, at, children).map(Some);
        }
        let Some((child, len)) = next else {
            return Ok(None);
        };
        rest = rest.get(len..).ok_or(Malformed)?;
        node = child;
    }
}

/// `EXPORT_SYMBOL_FLAGS_KIND_MASK`: regular 0, thread-local 1, absolute 2.
const KIND_MASK: u64 = 0x03;

/// The export a terminal node's payload, `[at, end)`, records.
fn terminal_export(trie: &[u8], mut at: usize, end: usize) -> Result<Export, Malformed> {
    let flags = uleb(trie, &mut at)?;
    let export = if flags & REEXPORT != 0 {
        let ordinal = uleb(trie, &mut at)?;
        let tail = trie.get(at..end).ok_or(Malformed)?;
        let len = tail.iter().position(|&b| b == 0).ok_or(Malformed)?;
        let name = tail.get(..len).ok_or(Malformed)?.to_vec();
        at = at
            .checked_add(len)
            .and_then(|a| a.checked_add(1))
            .ok_or(Malformed)?;
        Export::Reexport { ordinal, name }
    } else if flags & STUB_AND_RESOLVER != 0 {
        // A stub is code: a thread-local or absolute stub is malformed.
        if flags & KIND_MASK != 0 {
            return Err(Malformed);
        }
        let stub = uleb(trie, &mut at)?;
        let resolver = uleb(trie, &mut at)?;
        Export::Stub { stub, resolver }
    } else {
        uleb(trie, &mut at)?;
        Export::Other
    };
    if at > end {
        return Err(Malformed);
    }
    Ok(export)
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Malformed> {
    let raw = b
        .get(at..at.checked_add(4).ok_or(Malformed)?)
        .ok_or(Malformed)?;
    Ok(u32::from_le_bytes(raw.try_into().map_err(|_| Malformed)?))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, Malformed> {
    let raw = b
        .get(at..at.checked_add(8).ok_or(Malformed)?)
        .ok_or(Malformed)?;
    Ok(u64::from_le_bytes(raw.try_into().map_err(|_| Malformed)?))
}

/// What the resolver-stub rule reads of one loaded image.
pub(crate) struct Image {
    /// The export trie.
    pub(crate) trie: Vec<u8>,
    /// The dependent libraries' paths, in load-command order: ordinal 1 is
    /// the first. Each is marked when it is an `LC_REEXPORT_DYLIB`, whose
    /// whole export set this image re-exports.
    pub(crate) dylibs: Vec<(Vec<u8>, bool)>,
}

/// The export trie and dependent libraries of the loaded image whose Mach
/// header is at `base`, read through `process`'s memory route.
///
/// The trie is found where the loader finds it: `LC_DYLD_EXPORTS_TRIE`, or
/// `LC_DYLD_INFO`'s export range, a file offset in the image's
/// `__LINKEDIT`, which lies at `__LINKEDIT`'s address plus the image's
/// slide. The same holds for an image in the shared cache, whose
/// `__LINKEDIT` is the cache's.
///
/// # Errors
///
/// [`Unreadable::ExportTrie`] when the header, the load commands or the
/// trie cannot be read or do not describe a trie; any other failure as the
/// memory route reports it.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the load commands; each command's bounds sit beside it"
)]
pub(crate) fn read_image(process: &mut impl Process, base: u64) -> Result<Image, Unreadable> {
    let malformed = |_| Unreadable::ExportTrie;
    let mut header = [0u8; 32];
    process.read(base, &mut header)?;
    if u32_at(&header, 0).map_err(malformed)? != MH_MAGIC_64 {
        return Err(Unreadable::ExportTrie);
    }
    let ncmds = u32_at(&header, 16).map_err(malformed)?;
    let size = u32_at(&header, 20).map_err(malformed)?;
    if size > MAX_COMMANDS {
        return Err(Unreadable::ExportTrie);
    }
    let mut cmds = vec![0u8; usize::try_from(size).map_err(|_| Unreadable::ExportTrie)?];
    process.read(
        base.checked_add(32).ok_or(Unreadable::ExportTrie)?,
        &mut cmds,
    )?;
    let (mut text, mut linkedit, mut range) = (None, None, None);
    let mut dylibs: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut at = 0usize;
    for _ in 0..ncmds {
        let cmd = u32_at(&cmds, at).map_err(malformed)?;
        let cmdsize = usize::try_from(u32_at(&cmds, at.saturating_add(4)).map_err(malformed)?)
            .map_err(|_| Unreadable::ExportTrie)?;
        // Each command is read inside its own `cmdsize`, never past it.
        let end = at.checked_add(cmdsize).ok_or(Unreadable::ExportTrie)?;
        let c = cmds.get(at..end).ok_or(Unreadable::ExportTrie)?;
        let least = match cmd {
            LC_SEGMENT_64 => 72,
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => 48,
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => 24,
            LC_DYLD_EXPORTS_TRIE => 16,
            _ => 8,
        };
        if cmdsize < least {
            return Err(Unreadable::ExportTrie);
        }
        match cmd {
            LC_SEGMENT_64 => {
                let name = c.get(8..24).ok_or(Unreadable::ExportTrie)?;
                let vmaddr = u64_at(c, 24).map_err(malformed)?;
                let fileoff = u64_at(c, 40).map_err(malformed)?;
                let filesize = u64_at(c, 48).map_err(malformed)?;
                if name.starts_with(b"__TEXT\0") {
                    text = Some(vmaddr);
                } else if name.starts_with(b"__LINKEDIT\0") {
                    linkedit = Some((vmaddr, fileoff, filesize));
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                let name_off = usize::try_from(u32_at(c, 8).map_err(malformed)?)
                    .map_err(|_| Unreadable::ExportTrie)?;
                let tail = c.get(name_off..).ok_or(Unreadable::ExportTrie)?;
                let len = tail
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(Unreadable::ExportTrie)?;
                dylibs.push((
                    tail.get(..len).ok_or(Unreadable::ExportTrie)?.to_vec(),
                    cmd == LC_REEXPORT_DYLIB,
                ));
            }
            LC_DYLD_EXPORTS_TRIE => {
                range = Some((
                    u32_at(c, 8).map_err(malformed)?,
                    u32_at(c, 12).map_err(malformed)?,
                ));
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY if range.is_none() => {
                range = Some((
                    u32_at(c, 40).map_err(malformed)?,
                    u32_at(c, 44).map_err(malformed)?,
                ));
            }
            _ => {}
        }
        at = end;
    }
    let (Some(text), Some((le_vmaddr, le_fileoff, le_filesize)), Some((off, len))) =
        (text, linkedit, range)
    else {
        return Err(Unreadable::ExportTrie);
    };
    if len == 0 || u64::from(len) > MAX_TRIE {
        return Err(Unreadable::ExportTrie);
    }
    // The export range lies inside __LINKEDIT's file range.
    let inside = u64::from(off) >= le_fileoff
        && u64::from(off)
            .checked_add(u64::from(len))
            .zip(le_fileoff.checked_add(le_filesize))
            .is_some_and(|(end, le_end)| end <= le_end);
    if !inside {
        return Err(Unreadable::ExportTrie);
    }
    let slide = base.wrapping_sub(text);
    let address = u64::from(off)
        .checked_sub(le_fileoff)
        .and_then(|d| le_vmaddr.wrapping_add(slide).checked_add(d))
        .ok_or(Unreadable::ExportTrie)?;
    let mut trie = vec![0u8; usize::try_from(len).map_err(|_| Unreadable::ExportTrie)?];
    process.read(address, &mut trie)?;
    Ok(Image { trie, dylibs })
}

/// The deepest nesting of re-exports followed.
const MAX_DEPTH: usize = 8;
/// The most images one resolution looks in: libSystem alone re-exports
/// about forty libraries whole.
const MAX_VISITS: usize = 256;

/// One step of a resolution, for a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hop {
    /// The library looked in.
    pub(crate) library: Vec<u8>,
    /// The name looked up.
    pub(crate) name: Vec<u8>,
    /// What its trie records under that name.
    pub(crate) export: Option<Export>,
}

/// Where a lookup ended.
enum Found {
    /// A stub-and-resolver export: the image's Mach header and the stub's
    /// offset.
    Stub(u64, u64),
    /// Any other export.
    Other,
    /// No export of the name.
    Missing,
}

/// Resolves `name` the way dyld does, by name from `library`
/// (`dyld/common/MachOLoaded.cpp`, `MachOLoaded::findExportedSymbol`):
/// looked up in the library's own export trie; a per-symbol re-export
/// followed to the dependent library its ordinal names, under its new name
/// when it renames; and on a miss, each `LC_REEXPORT_DYLIB` dependent
/// searched in turn, in load-command order, the first that exports the
/// name deciding. Bounded at [`MAX_DEPTH`] nested re-exports and
/// [`MAX_VISITS`] images, never through the same library and name twice on
/// one path. Returns the image's Mach header and the stub offset when the
/// name ends at a stub-and-resolver export, and `None` when it ends at any
/// other export or at none.
///
/// # Errors
///
/// [`Unreadable::ExportTrie`] for a library that is not loaded, a cycle, a
/// resolution past either bound, an ordinal the image does not list, or a
/// trie that cannot be read or parsed; a memory-read failure as the route
/// reports it.
pub(crate) fn resolve_stub(
    process: &mut impl Process,
    library: &[u8],
    name: &[u8],
    hops: &mut Vec<Hop>,
) -> Result<Option<(u64, u64)>, Unreadable> {
    let mut path = Vec::new();
    match find(process, library, name, 0, &mut path, hops)? {
        Found::Stub(base, stub) => Ok(Some((base, stub))),
        Found::Other | Found::Missing => Ok(None),
    }
}

/// One step of [`resolve_stub`]; `path` holds the library and name pairs
/// on the way here, and `hops` every image looked in so far.
fn find(
    process: &mut impl Process,
    library: &[u8],
    name: &[u8],
    depth: usize,
    path: &mut Vec<(Vec<u8>, Vec<u8>)>,
    hops: &mut Vec<Hop>,
) -> Result<Found, Unreadable> {
    if depth > MAX_DEPTH
        || hops.len() >= MAX_VISITS
        || path
            .iter()
            .any(|(l, n)| l.as_slice() == library && n.as_slice() == name)
    {
        return Err(Unreadable::ExportTrie);
    }
    let base = process
        .loaded_image(library)?
        .ok_or(Unreadable::ExportTrie)?;
    let image = read_image(process, base)?;
    let export = lookup(&image.trie, name).map_err(|_| Unreadable::ExportTrie)?;
    hops.push(Hop {
        library: library.to_vec(),
        name: name.to_vec(),
        export: export.clone(),
    });
    path.push((library.to_vec(), name.to_vec()));
    let found = match export {
        Some(Export::Stub { stub, .. }) => Found::Stub(base, stub),
        Some(Export::Other) => Found::Other,
        Some(Export::Reexport {
            ordinal,
            name: renamed,
        }) => {
            let (dep, _) = usize::try_from(ordinal)
                .ok()
                .and_then(|o| o.checked_sub(1))
                .and_then(|o| image.dylibs.get(o))
                .ok_or(Unreadable::ExportTrie)?;
            let next = if renamed.is_empty() { name } else { &renamed };
            find(process, dep, next, depth.saturating_add(1), path, hops)?
        }
        None => {
            // Not exported here: the libraries this one re-exports whole,
            // in load-command order; the first that exports the name
            // decides.
            let mut found = Found::Missing;
            for (dep, _) in image.dylibs.iter().filter(|(_, whole)| *whole) {
                match find(process, dep, name, depth.saturating_add(1), path, hops)? {
                    Found::Missing => {}
                    decided => {
                        found = decided;
                        break;
                    }
                }
            }
            found
        }
    };
    path.pop();
    Ok(found)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
pub(crate) mod tests {
    use super::{Export, Malformed, lookup, uleb};

    /// ULEB128 encoding of `v`.
    pub(crate) fn enc(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// A stub-and-resolver payload.
    pub(crate) fn stub(stub: u64, resolver: u64) -> Vec<u8> {
        [enc(0x10), enc(stub), enc(resolver)].concat()
    }

    /// A plain export's payload.
    pub(crate) fn plain(address: u64) -> Vec<u8> {
        [enc(0), enc(address)].concat()
    }

    /// A re-export's payload: the library ordinal and the name there.
    pub(crate) fn reexport(ordinal: u64, name: &str) -> Vec<u8> {
        let mut out = [enc(0x08), enc(ordinal)].concat();
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out
    }

    /// A trie whose root has one child per entry, each a full name with its
    /// terminal payload.
    pub(crate) fn trie(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let terminals: Vec<Vec<u8>> = entries
            .iter()
            .map(|(_, payload)| {
                let mut node = enc(payload.len() as u64);
                node.extend_from_slice(payload);
                node.push(0);
                node
            })
            .collect();
        // Child offsets are single-byte ULEBs for these small tries.
        let edges_len: usize = entries.iter().map(|(n, _)| n.len() + 2).sum();
        let mut at = 2 + edges_len;
        let mut out = vec![0u8, entries.len() as u8];
        for ((name, _), node) in entries.iter().zip(&terminals) {
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            assert!(at < 0x80, "fixture trie too large");
            out.push(at as u8);
            at += node.len();
        }
        for node in terminals {
            out.extend(node);
        }
        out
    }

    #[test]
    fn entries_are_found_by_their_exact_name() {
        let t = trie(&[
            ("_malloc", plain(0x1000)),
            ("_memcmp", stub(0x2b88, 0x2da4)),
            ("_memset", reexport(1, "__platform_memset")),
            ("_bzero", reexport(2, "")),
        ]);
        assert_eq!(
            lookup(&t, b"_memcmp"),
            Ok(Some(Export::Stub {
                stub: 0x2b88,
                resolver: 0x2da4
            }))
        );
        assert_eq!(lookup(&t, b"_malloc"), Ok(Some(Export::Other)));
        assert_eq!(
            lookup(&t, b"_memset"),
            Ok(Some(Export::Reexport {
                ordinal: 1,
                name: b"__platform_memset".to_vec()
            }))
        );
        assert_eq!(
            lookup(&t, b"_bzero"),
            Ok(Some(Export::Reexport {
                ordinal: 2,
                name: Vec::new()
            }))
        );
        assert_eq!(lookup(&t, b"_memcm"), Ok(None));
        assert_eq!(lookup(&t, b"_memcmpx"), Ok(None));
        assert_eq!(lookup(&t, b"_opendir"), Ok(None));
    }

    #[test]
    fn a_malformed_trie_is_an_error() {
        let t = trie(&[("_memcmp", stub(0x2b88, 0x2da4))]);
        // Truncated anywhere, the entry is never found.
        let found = lookup(&t, b"_memcmp").unwrap();
        for cut in 0..t.len() {
            assert_ne!(
                lookup(&t[..cut], b"_memcmp"),
                Ok(found.clone()),
                "cut {cut}"
            );
        }
        assert_eq!(lookup(&t[..t.len() - 3], b"_memcmp"), Err(Malformed));
        // An empty edge.
        assert_eq!(lookup(&[0u8, 1, 0, 0], b"_memcmp"), Err(Malformed));
        // A child offset past the end.
        assert_eq!(lookup(&[0u8, 1, b'_', 0, 0x7f], b"_memcmp"), Err(Malformed));
        // A cycle: the root's only edge leads back to the root.
        assert_eq!(lookup(&[0u8, 1, b'_', 0, 0], b"_memcmp"), Err(Malformed));
        // A terminal node that declares a child it does not hold.
        let mut missing = trie(&[("_memcmp", stub(0x2b88, 0x2da4))]);
        let last = missing.len() - 1;
        missing[last] = 1;
        assert_eq!(lookup(&missing, b"_memcmp"), Err(Malformed));
        // A stub of the thread-local kind.
        let tlv = trie(&[("_memcmp", [enc(0x11), enc(0x2b88), enc(0x2da4)].concat())]);
        assert_eq!(lookup(&tlv, b"_memcmp"), Err(Malformed));
    }

    #[test]
    fn a_uleb_past_64_bits_is_refused() {
        let mut at = 0;
        assert_eq!(uleb(&[0xff; 11], &mut at), Err(Malformed));
        let mut at = 0;
        let mut over = vec![0xff; 9];
        over.push(0x02);
        assert_eq!(uleb(&over, &mut at), Err(Malformed));
        let mut at = 0;
        let mut max = vec![0xff; 9];
        max.push(0x01);
        assert_eq!(uleb(&max, &mut at), Ok(u64::MAX));
        // In the trie: a terminal size that overflows.
        let mut t = vec![0u8, 1, b'_', 0, 5];
        t.extend([0xff; 11]);
        assert_eq!(lookup(&t, b"_"), Err(Malformed));
    }
}
