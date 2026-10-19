//! Build-time signer for the module's pre-operational integrity test.
//!
//! ```text
//! oxicrypt-integrity-sign --keygen <dir>
//! oxicrypt-integrity-sign --sign --key <signing key> [--loader glibc|bionic] <artifact> [<artifact> ...]
//! oxicrypt-integrity-sign --sign --key <signing key> --reserved-against <reference> <Mach-O or PE artifact>
//! oxicrypt-integrity-sign --verify [--loader glibc|bionic] <artifact> [<artifact> ...]
//! oxicrypt-integrity-sign --show   [--loader glibc|bionic] <artifact> [<artifact> ...]
//! oxicrypt-integrity-sign --show   --reserved-against <reference> <Mach-O or PE artifact>
//! ```
//!
//! `--keygen` generates an ML-DSA-87 key pair and writes it to `<dir>`,
//! which must lie outside any source tree: `integrity-signing.key` (the
//! 32-byte key-generation seed, mode `0600`) and `integrity-verify.pub`
//! (the 2,592-byte public key a build embeds through
//! `OXICRYPT_INTEGRITY_VERIFY_KEY`).
//!
//! `--sign` derives the artifact's extent, writes it into the embedded
//! integrity slot with the fingerprint of the artifact's verifying key, and
//! signs the slot and the extent's **file** bytes with the key `--key`
//! names. It refuses with `SigningKeyAbsent` when `--key` is missing or
//! unreadable, or when the key's public half is not the key the artifact
//! embeds, and with `NoVerifyKey` when the artifact was built without one.
//!
//! An ELF artifact is typed for the loader its notes declare (bionic when it
//! carries the Android ident note, glibc otherwise); `--loader` overrides
//! that. `--sign` refuses an ELF artifact in which a module static the
//! module must start from zero-fill is file-backed, reading the symbol table
//! from the artifact or, when it has been stripped, from the debug file its
//! `.gnu_debuglink` names in the artifact's directory or its `.debug`
//! subdirectory.
//!
//! A Mach-O artifact is typed from its chained fixups, and `--sign` refuses
//! one in which a module static the module must start from zero-fill is
//! file-backed, reading its own symbol table or, when it has been stripped,
//! the dSYM beside it (`<artifact>.dSYM`) whose `LC_UUID` matches.
//! `--reserved-against <reference>` names the same build after one
//! `codesign` with the final identity and options, the artifact being the
//! result of the next: each `codesign` locator field (`LC_CODE_SIGNATURE`'s
//! `dataoff` and `datasize`, `__LINKEDIT`'s `vmsize` and `filesize`) that
//! differs between the two becomes a hole, and any other difference in the
//! header and load commands is refused.
//!
//! A PE artifact is typed from its headers, base relocations, import
//! directory and load configuration, and `--sign` refuses one in which a
//! module static the module must start from zero-fill is file-backed,
//! reading the symbols from the program database its CodeView record names,
//! beside the artifact, matched by GUID and age, or, when that file is not
//! there, from the DWARF the image carries. `--reserved-against <reference>` names the same
//! build as linked, the artifact being the result of `signtool` with the
//! final certificate and options: `CheckSum` and the Security directory
//! entry, where they differ, become holes, and any other difference before
//! the certificate table is refused.
//!
//! `--verify` rebuilds the signature input from the file and verifies the
//! signature with the embedded key; for a Mach-O artifact it then decodes
//! every chain word against the kind and import the signed table gives it,
//! and for a PE artifact every import lookup table against the records.
//! `--show` reports the typed extent, the file-backed module statics row
//! and both fingerprints without touching the artifact. For a PE artifact,
//! `--show` and `--sign` name where the statics were read from: the
//! program database beside it, or the DWARF in the image.
//!
//! This tool is **outside the cryptographic boundary**. It parses
//! executable formats, which the module deliberately does not: the module
//! reads the table the tool wrote. Both sides share the slot codec and the
//! signature-input builder, so the signer and the power-up test cannot
//! disagree about what is signed.
//!
//! # What `--verify` here does and does not prove
//!
//! It proves the file is internally consistent. It says nothing about the
//! loaded image, because it never loads the artifact; that is what the
//! runtime test exercises.
//!
//! Exit codes:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | success |
//! | 1 | usage error, including `--key` outside `--sign` or given twice, or an unreadable `--reserved-against` reference |
//! | 2 | at least one artifact failed to sign, verify or show |
//! | 3 | `--sign` was refused before any artifact was touched: `--key` missing, unreadable, not a 32-byte ML-DSA-87 seed, or failing its pairwise consistency test (`SigningKeyAbsent`) |
//! | 4 | `--keygen` failed |
//!
//! Every artifact is processed before exiting, so one bad input does not
//! mask diagnostics for the rest. `--sign` writes each artifact through a
//! temporary file that is synced and verified before it replaces the
//! original, so a failure before that replacement leaves the original
//! untouched. A directory that cannot be synced after it is a warning: the
//! signed file is already in place.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oxicrypt_integrity::{SLOT_SIZE, format_fingerprint, key_fingerprint, slot};
use oxicrypt_integrity_sign::{SignOptions, SigningKey, elf, image, macho, pe};

#[derive(Copy, Clone)]
enum Mode {
    Sign,
    Verify,
    Show,
    Keygen,
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear argument parse, each refusal beside the flag it concerns"
)]
fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode_arg) = argv.first() else {
        usage();
        return ExitCode::from(1);
    };
    let mode = match mode_arg.as_str() {
        "--sign" => Mode::Sign,
        "--verify" => Mode::Verify,
        "--show" => Mode::Show,
        "--keygen" => Mode::Keygen,
        _ => {
            usage();
            return ExitCode::from(1);
        }
    };

    let mut targets: Vec<PathBuf> = Vec::new();
    let mut key_path: Option<PathBuf> = None;
    let mut reserved_path: Option<PathBuf> = None;
    let mut loader: Option<elf::Loader> = None;
    let mut iter = argv.iter().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--loader" => {
                let chosen = iter.next().and_then(|name| elf::Loader::from_name(name));
                if loader.is_some() || chosen.is_none() {
                    eprintln!("error: --loader takes glibc or bionic, once");
                    return ExitCode::from(1);
                }
                loader = chosen;
            }
            "--target" | "--cdylib-target" | "--key" | "--reserved-against" => {
                let Some(path) = iter.next() else {
                    eprintln!("error: {a} requires a path argument");
                    return ExitCode::from(1);
                };
                if a == "--reserved-against" {
                    if reserved_path.is_some() {
                        eprintln!("error: --reserved-against given twice");
                        return ExitCode::from(1);
                    }
                    reserved_path = Some(PathBuf::from(path));
                } else if a == "--key" {
                    if key_path.is_some() {
                        eprintln!("error: --key given twice");
                        return ExitCode::from(1);
                    }
                    key_path = Some(PathBuf::from(path));
                } else {
                    targets.push(PathBuf::from(path));
                }
            }
            "--staticlib-target" => {
                // A static archive is a build input, not a loadable image.
                // The linker copies the slot object into the consumer's final
                // binary, so the consumer signs their own link.
                eprintln!(
                    "error: --staticlib-target is not supported. A static archive is not a \
                     loadable image: sign the final binary or shared library the archive is \
                     linked into."
                );
                return ExitCode::from(1);
            }
            _ if a.starts_with("--") => {
                eprintln!("error: unknown flag {a}");
                usage();
                return ExitCode::from(1);
            }
            _ => targets.push(PathBuf::from(a)),
        }
    }

    if loader.is_some() && matches!(mode, Mode::Keygen) {
        eprintln!("error: --loader applies to --sign, --verify and --show");
        return ExitCode::from(1);
    }
    if key_path.is_some() && !matches!(mode, Mode::Sign) {
        eprintln!(
            "error: --key applies to --sign only; --verify and --show use the key the \
             artifact embeds"
        );
        return ExitCode::from(1);
    }
    if reserved_path.is_some() && !matches!(mode, Mode::Sign | Mode::Show) {
        eprintln!(
            "error: --reserved-against applies to --sign and --show of one Mach-O or PE \
             artifact; --verify reads the holes from the slot"
        );
        return ExitCode::from(1);
    }
    if let Mode::Keygen = mode {
        return keygen(&targets);
    }
    if targets.is_empty() {
        eprintln!("error: no targets supplied");
        usage();
        return ExitCode::from(1);
    }
    let reserved = match reserved_path {
        None => None,
        Some(_) if matches!(mode, Mode::Verify) || targets.len() != 1 => {
            eprintln!("error: --reserved-against takes exactly one Mach-O or PE artifact");
            return ExitCode::from(1);
        }
        Some(path) => match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("error: cannot read {}: {e}", path.display());
                return ExitCode::from(1);
            }
        },
    };

    let key = if let Mode::Sign = mode {
        let Some(path) = key_path else {
            eprintln!(
                "SigningKeyAbsent: --sign requires --key <signing key>; generate a pair with \
                 --keygen <dir outside the tree>"
            );
            return ExitCode::from(3);
        };
        match SigningKey::read(&path) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(3);
            }
        }
    } else {
        None
    };

    let mut had_failure = false;
    for target in &targets {
        let outcome = match (mode, &key) {
            (Mode::Sign, Some(key)) => sign(target, key, loader, reserved.as_deref()),
            (Mode::Verify, _) => verify(target, loader),
            (Mode::Show, _) => show(target, loader, reserved.as_deref()),
            _ => Err("internal: no signing key".to_owned()),
        };
        if let Err(message) = outcome {
            eprintln!("{}: {message}", target.display());
            had_failure = true;
        }
    }

    if had_failure {
        ExitCode::from(2)
    } else {
        ExitCode::from(0)
    }
}

fn keygen(dirs: &[PathBuf]) -> ExitCode {
    let [dir] = dirs else {
        eprintln!("error: --keygen takes exactly one directory");
        usage();
        return ExitCode::from(1);
    };
    match oxicrypt_integrity_sign::key::keygen(dir) {
        Ok((private, public, fp)) => {
            println!("signing key: {}", private.display());
            println!("verify key:  {}", public.display());
            println!("fingerprint: {}", format_fingerprint(&fp));
            println!(
                "build with OXICRYPT_INTEGRITY_VERIFY_KEY={} and sign with --key {}",
                public.display(),
                private.display()
            );
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(4)
        }
    }
}

fn sign(
    named: &Path,
    key: &SigningKey,
    loader: Option<elf::Loader>,
    reserved_against: Option<&[u8]>,
) -> Result<(), String> {
    // A symbolic link is followed: the file it names is the artifact, and
    // replacing the link itself would leave that file unsigned.
    let target = std::fs::canonicalize(named).map_err(|e| format!("cannot resolve: {e}"))?;
    let path = target.as_path();
    let mut bytes = std::fs::read(path).map_err(|e| format!("cannot read: {e}"))?;
    let symbols = oxicrypt_integrity_sign::debug_symbols(path, &bytes)?;
    let options = SignOptions {
        loader,
        symbols: symbols.as_deref(),
        reserved_against,
    };
    let layout = oxicrypt_integrity_sign::classify_with(&bytes, &options)?;
    let signature = oxicrypt_integrity_sign::sign_image_with(&mut bytes, key, &options)?;
    let source = statics_source(&bytes, symbols.as_deref());
    // Everything that can fail is done before the artifact is replaced, so
    // a reported failure always means the original is untouched.
    let fingerprint = format_fingerprint(&key.fingerprint()?);
    // The 4,627-byte signature is named by its digest, so a log or release
    // note quoting this line stays one readable line.
    let signature_digest = oxicrypt_sha::sha256::sha256(&signature)
        .map_err(|e| format!("cannot hash the signature: {e}"))?;
    replace_verified(path, &bytes, loader)?;

    let extent = slot::extent_len(&layout.entries).unwrap_or(0);
    println!(
        "signed {} -> signature {}\n  verify key: {}\n  extent {extent} bytes in {} entries ({} of {} mapped bytes, {}%)",
        path.display(),
        format_fingerprint(&signature_digest),
        fingerprint,
        layout.entries.len(),
        extent,
        layout.mapped_len,
        percent(extent, layout.mapped_len),
    );
    println!(
        "  slot table: {} stored entries of {}",
        slot::table_len(&layout.entries),
        slot::MAX_ENTRIES
    );
    if let Some(source) = source {
        println!("  module statics read from: {source}");
    }
    if let Some(note) = oxicrypt_integrity_sign::after_signing_note(&bytes) {
        println!("  note: {note}");
    }
    Ok(())
}

/// Replaces `path` with `bytes` without ever leaving it half-written.
///
/// The new contents go to a temporary file beside it, with its
/// permissions, and are synced and verified from disk before a rename puts
/// them in place. A failure at any step removes the temporary file, if this
/// run created it, and leaves the original as it was.
fn replace_verified(path: &Path, bytes: &[u8], loader: Option<elf::Loader>) -> Result<(), String> {
    use std::io::Write as _;
    let name = path
        .file_name()
        .ok_or("the artifact path names no file")?
        .to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.signing-{}", std::process::id()));
    // Set once this run has created `tmp`: a name that already existed
    // belongs to someone else and is never removed here.
    let mut created = false;
    let outcome = (|| {
        let permissions = std::fs::metadata(path)
            .map_err(|e| format!("cannot read: {e}"))?
            .permissions();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
        created = true;
        file.write_all(bytes)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        file.set_permissions(permissions)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot finish {}: {e}", tmp.display()))?;
        // Self-check from disk: a signer that reported success without
        // reading back what it wrote would be asserting an outcome it never
        // observed.
        verify(&tmp, loader).map_err(|e| format!("signed, but the read-back check failed: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace the artifact: {e}"))
    })();
    if outcome.is_err() {
        if created {
            let _ = std::fs::remove_file(&tmp);
        }
        return outcome;
    }
    // The signed artifact is in place. A directory that cannot be synced
    // leaves the rename itself not yet durable, which is a warning about
    // that state, not a failure to sign.
    if let Err(e) = sync_parent(path) {
        eprintln!(
            "warning: {} is signed and in place, but its directory could not be synced ({e}); \
             until the system writes it back, a crash could restore the unsigned file",
            path.display()
        );
    }
    Ok(())
}

/// Makes the rename that replaced `path` durable by syncing its directory,
/// where the platform has a directory handle to sync.
#[cfg_attr(
    not(unix),
    allow(clippy::unnecessary_wraps, reason = "one signature; Unix can fail")
)]
fn sync_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let dir = path.parent().ok_or("the artifact path has no directory")?;
        std::fs::File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(|e| format!("replaced, but cannot sync {}: {e}", dir.display()))
    }
    #[cfg(not(unix))]
    {
        // Windows: `std::fs::rename` does not request write-through, so the
        // replacement is journaled but not forced to disk before this
        // returns. The signed contents were
        // synced; a crash immediately after can leave the original in place,
        // never a partial file.
        let _ = path;
        Ok(())
    }
}

fn verify(path: &Path, loader: Option<elf::Loader>) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read: {e}"))?;
    let fp = oxicrypt_integrity_sign::verify_image_for(&bytes, loader)?;
    println!(
        "verify ok: {} (verify key {})",
        path.display(),
        format_fingerprint(&fp)
    );
    Ok(())
}

fn show(
    path: &Path,
    loader: Option<elf::Loader>,
    reserved_against: Option<&[u8]>,
) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read: {e}"))?;
    let options = SignOptions {
        loader,
        symbols: None,
        reserved_against,
    };
    let layout = oxicrypt_integrity_sign::classify_with(&bytes, &options)?;
    oxicrypt_integrity_sign::start_module()?;
    println!("{}", path.display());
    let embedded = if let Some(key) = oxicrypt_integrity_sign::embedded_verify_key(&bytes)? {
        let fp = key_fingerprint(&key).map_err(|e| format!("cannot fingerprint: {e}"))?;
        println!("  verify key: {}", format_fingerprint(&fp));
        Some(fp)
    } else {
        println!(
            "  verify key: none (built without OXICRYPT_INTEGRITY_VERIFY_KEY; the module \
             will report NoVerifyKey)"
        );
        None
    };
    println!(
        "  slot at file offset {:#x}, RVA {:#x}",
        layout.slot_file_off, layout.slot_rva
    );
    println!(
        "  typed, slot included: {} bytes of {} mapped ({}%)",
        layout.invariant_len,
        layout.mapped_len,
        percent(layout.invariant_len, layout.mapped_len)
    );
    if elf::is_elf64_le(&bytes) {
        let typed_for = if layout.flags & slot::FLAG_LOADER_BIONIC == 0 {
            elf::Loader::Glibc
        } else {
            elf::Loader::Bionic
        };
        let name = if typed_for == elf::Loader::Glibc {
            "glibc"
        } else {
            "bionic"
        };
        println!("  loader: {name}");
        show_statics(path, &bytes, Some(typed_for));
    } else if macho::is_macho64_le(&bytes) {
        show_macho(path, &bytes, &layout, reserved_against)?;
    } else if pe::is_pe32plus(&bytes) {
        show_pe(path, &bytes, &layout, reserved_against)?;
    }
    let entries = layout.entries.clone();
    print_kinds(&entries);
    let extent = slot::extent_len(&entries).unwrap_or(0);
    println!(
        "  extent after subtracting the slot: {extent} bytes in {} entries ({}% of mapped, {}% of file)",
        entries.len(),
        percent(extent, layout.mapped_len),
        percent(extent, bytes.len() as u64),
    );
    println!(
        "  slot table: {} stored entries of {}",
        slot::table_len(&entries),
        slot::MAX_ENTRIES
    );
    print_slot_budget(&layout)?;
    print_entries(&entries);
    match read_slot(&bytes) {
        Ok(parsed) => {
            let signature_digest = oxicrypt_sha::sha256::sha256(&parsed.signature)
                .map_err(|e| format!("cannot hash the signature: {e}"))?;
            println!(
                "  slot: version {}, {} entries, key id {}, signature {}",
                parsed.version,
                parsed.fields.entries.len(),
                format_fingerprint(&parsed.fields.key_id),
                format_fingerprint(&signature_digest)
            );
            match embedded {
                Some(fp) if fp == parsed.fields.key_id => {
                    println!("  slot's key id matches the embedded verifying key");
                }
                Some(_) => println!(
                    "  KeyMismatch: the slot was signed for a different key than the one \
                     this artifact embeds"
                ),
                None => println!("  the artifact embeds no verifying key to match"),
            }
            if parsed.fields.entries == entries {
                println!("  slot's table matches the extent derived from this file");
            } else {
                println!("  WARNING: the slot's table differs from this file's extent");
            }
        }
        Err(e) => println!("  slot: {e}"),
    }
    Ok(())
}

/// The slot budget as one machine-readable line, for probes that check the
/// fit. `fits` is whether signing would accept the slot, by the same
/// encode-and-parse signing runs; when it would not, a second line gives the
/// reason.
fn print_slot_budget(layout: &oxicrypt_integrity_sign::image::Layout) -> Result<(), String> {
    let budget = oxicrypt_integrity_sign::slot_budget(layout)?;
    println!(
        "  slot budget: stored {} string-table {} capacity {} fits {}",
        budget.stored,
        budget.string_table,
        budget.capacity,
        if budget.fits() { "yes" } else { "no" }
    );
    if let Some(reason) = &budget.refused {
        println!("  slot budget refused: {reason}");
    }
    Ok(())
}

/// Prints a Mach-O image's statics row, its envelope locator holes when a
/// reference is given, its bound imports and its signed length.
fn show_macho(
    path: &Path,
    bytes: &[u8],
    layout: &image::Layout,
    reserved_against: Option<&[u8]>,
) -> Result<(), String> {
    show_statics(path, bytes, None);
    if let Some(reference) = reserved_against {
        let holes = macho::reservation_holes(reference, bytes)?;
        let names: Vec<&str> = holes.iter().map(|f| f.name()).collect();
        println!(
            "  envelope locator holes: {}",
            if names.is_empty() {
                "none".to_owned()
            } else {
                names.join(", ")
            }
        );
    }
    print_records(layout);
    Ok(())
}

/// Prints a PE image's program database, statics row, envelope holes when a
/// reference is given, its bound imports and its signed length.
fn show_pe(
    path: &Path,
    bytes: &[u8],
    layout: &image::Layout,
    reserved_against: Option<&[u8]>,
) -> Result<(), String> {
    match pe::codeview(bytes)? {
        Some(cv) => println!(
            "  program database: {} (GUID {}, age {})",
            cv.path,
            hex(&cv.guid),
            cv.age
        ),
        None => println!("  program database: none named"),
    }
    show_statics(path, bytes, None);
    if let Some(reference) = reserved_against {
        let holes = pe::reservation_holes(reference, bytes)?;
        let names: Vec<&str> = holes.iter().map(|f| f.name()).collect();
        println!(
            "  envelope holes: {}",
            if names.is_empty() {
                "none".to_owned()
            } else {
                names.join(", ")
            }
        );
    }
    println!("  link base (ImageBase) {:#x}", layout.link_base);
    print_records(layout);
    Ok(())
}

/// Prints the bound imports and the signed image's length.
fn print_records(layout: &image::Layout) {
    println!(
        "  bound imports: {} records; signed image length (file_len) {:#x}",
        layout.records.len(),
        layout.file_len
    );
    for (i, r) in layout.records.iter().enumerate() {
        let symbol = if r.symbol.is_empty() {
            format!("#{}", r.ordinal)
        } else {
            r.symbol.clone()
        };
        println!(
            "    record [{i}] {} {symbol} addend {} {}",
            r.library,
            r.addend,
            if r.weak { "weak" } else { "strong" }
        );
    }
}

/// Prints each entry, a `Bind` entry with the record its words are bound
/// to.
fn print_entries(entries: &[slot::Entry]) {
    for (i, e) in entries.iter().enumerate() {
        let record = if e.kind == slot::EntryKind::Bind {
            format!(" record {}", e.meta)
        } else {
            String::new()
        };
        println!(
            "    [{i}] {:?} rva {:#010x} file {:#010x} len {} hole {}{record}",
            e.kind,
            e.rva,
            e.file_off,
            e.len,
            e.hole_len()
        );
    }
}

/// Prints the entries and bytes of each kind, holes carried by `Plain`
/// entries counted as holes.
fn print_kinds(entries: &[slot::Entry]) {
    for kind in [
        slot::EntryKind::Plain,
        slot::EntryKind::Relative,
        slot::EntryKind::Bind,
        slot::EntryKind::Hole,
        slot::EntryKind::FileOnly,
    ] {
        let of_kind: Vec<&slot::Entry> = entries.iter().filter(|e| e.kind == kind).collect();
        let mut bytes_of: u64 = of_kind.iter().map(|e| u64::from(e.len)).sum();
        if kind == slot::EntryKind::Hole {
            let carried: Vec<u64> = entries.iter().map(|e| u64::from(e.hole_len())).collect();
            let words = carried.iter().filter(|&&h| h > 0).count();
            bytes_of = bytes_of.saturating_add(carried.iter().sum::<u64>());
            println!(
                "  {kind:?}: {} entries and {words} carried by Plain entries, {bytes_of} bytes",
                of_kind.len()
            );
            continue;
        }
        println!("  {kind:?}: {} entries, {bytes_of} bytes", of_kind.len());
    }
}

/// Where the signer reads a PE image's module statics from: the program
/// database `symbols` holds when one was found beside the artifact, else the
/// DWARF the image carries. `None` for any other format.
fn statics_source(bytes: &[u8], symbols: Option<&[u8]>) -> Option<&'static str> {
    pe::is_pe32plus(bytes).then_some(if symbols.is_some() {
        "the program database beside the artifact"
    } else {
        "the DWARF in the image"
    })
}

/// Prints the file-backed module statics row the signer refuses on.
fn show_statics(path: &Path, bytes: &[u8], loader: Option<elf::Loader>) {
    let statics = oxicrypt_integrity_sign::debug_symbols(path, bytes).and_then(|symbols| {
        if let Some(source) = statics_source(bytes, symbols.as_deref()) {
            println!("  module statics read from: {source}");
        }
        oxicrypt_integrity_sign::module_statics(bytes, symbols.as_deref(), loader)
    });
    match statics {
        Err(e) => println!("  file-backed module statics: not checked ({e})"),
        Ok(s) => {
            println!(
                "  module statics in writable memory: {}; file-backed initialised (FileOnly): {}",
                s.matched, s.initialised
            );
            if !s.missing.is_empty() {
                println!(
                    "  file-backed module statics: not checked (not in the symbol table: {})",
                    s.missing.join(", ")
                );
            } else if s.rows.is_empty() {
                println!("  file-backed module statics: none");
            } else {
                println!("  file-backed module statics:");
                for r in &s.rows {
                    println!(
                        "    STATIC addr={:#x} size={} file_backed={} name={}",
                        r.addr, r.size, r.file_backed, r.name
                    );
                }
            }
        }
    }
}

/// Locates and parses the slot in an artifact's file bytes.
fn read_slot(bytes: &[u8]) -> Result<slot::SlotImage, String> {
    let off = image::find_slot(bytes)?;
    let end = off.checked_add(SLOT_SIZE).ok_or("slot offset overflows")?;
    let window = bytes
        .get(off..end)
        .ok_or("slot extends past the end of the file")?;
    slot::parse(window).map_err(|d| format!("slot invalid: {d}"))
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Percentage to two decimal places, computed in integer arithmetic.
///
/// Floating point would be the obvious choice and is the wrong one here:
/// these are byte counts that can exceed an `f64` mantissa, and a report a
/// laboratory reads should not carry a rounding artefact from a conversion
/// it never needed. Zero denominator reports `0.00` rather than dividing.
#[allow(
    clippy::integer_division,
    reason = "splitting hundredths into whole and fractional parts for display"
)]
fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "0.00".to_owned();
    }
    let hundredths = part.saturating_mul(10_000).checked_div(whole).unwrap_or(0);
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  oxicrypt-integrity-sign --keygen <dir outside the source tree>");
    eprintln!(
        "  oxicrypt-integrity-sign --sign --key <signing key> [--loader glibc|bionic] <artifact> [<artifact> ...]"
    );
    eprintln!(
        "  oxicrypt-integrity-sign --sign --key <signing key> --reserved-against <reference> <Mach-O or PE artifact>"
    );
    eprintln!(
        "  oxicrypt-integrity-sign --verify [--loader glibc|bionic] <artifact> [<artifact> ...]"
    );
    eprintln!(
        "  oxicrypt-integrity-sign --show   [--loader glibc|bionic] <artifact> [<artifact> ...]"
    );
    eprintln!(
        "  oxicrypt-integrity-sign --show   --reserved-against <reference> <Mach-O or PE artifact>"
    );
    eprintln!();
    eprintln!("--target <path> and --cdylib-target <path> are the same as a positional <artifact>");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{replace_verified, statics_source};

    /// A PE32+ image says which route supplied its statics; an ELF image
    /// names none.
    #[test]
    fn the_statics_route_is_named_for_a_pe_image() {
        let mut pe = vec![0u8; 0x200];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        let pdb = b"a program database";
        assert_eq!(
            statics_source(&pe, Some(pdb)),
            Some("the program database beside the artifact")
        );
        assert_eq!(statics_source(&pe, None), Some("the DWARF in the image"));
        assert_eq!(statics_source(b"\x7fELF", None), None);
    }

    /// A temporary name this run did not create is left alone when the
    /// replacement fails: another process may own that file.
    #[test]
    fn a_failed_replacement_keeps_a_temporary_file_it_did_not_create() {
        let dir = std::env::temp_dir().join(format!("oxicrypt-replace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("artifact");
        std::fs::write(&artifact, b"original").unwrap();
        let tmp = dir.join(format!(".artifact.signing-{}", std::process::id()));
        std::fs::write(&tmp, b"someone else's").unwrap();
        let err = replace_verified(&artifact, b"signed", None).unwrap_err();
        assert!(err.starts_with("cannot create"), "{err}");
        assert_eq!(std::fs::read(&tmp).unwrap(), b"someone else's");
        assert_eq!(std::fs::read(&artifact).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
