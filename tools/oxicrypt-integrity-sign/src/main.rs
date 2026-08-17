//! Build-time signer for the module's pre-operational integrity test.
//!
//! ```text
//! oxicrypt-integrity-sign --sign   <artifact> [<artifact> ...]
//! oxicrypt-integrity-sign --verify <artifact> [<artifact> ...]
//! oxicrypt-integrity-sign --show   <artifact> [<artifact> ...]
//! ```
//!
//! `--sign` derives the artifact's loader-invariant extent, computes
//! HMAC-SHA-256 over that extent's **file** bytes, and writes the range
//! table and the resulting MAC into the artifact's embedded integrity
//! slot. `--verify` recomputes the same MAC from the file and compares
//! it against the slot without short-circuiting. `--show` reports the
//! extent without touching the artifact.
//!
//! This tool is **outside the cryptographic boundary**. It parses
//! executable formats, which the module deliberately does not: the
//! module reads the range table the tool wrote. Both sides share
//! `oxicrypt_integrity::mac_over_file_ranges` and the slot codec, so the
//! signer and the power-up test cannot disagree about what is hashed.
//!
//! # What `--verify` here does and does not prove
//!
//! It proves the file is internally consistent — the extent's file bytes
//! match the MAC in the slot. It says nothing about the loaded image,
//! because it never loads the artifact. The claim that memory equals
//! file over this extent is what the runtime test exercises; an offline
//! verify is a build-pipeline check, not a substitute.
//!
//! Exit codes: `0` success, `1` usage error, `2` at least one artifact
//! failed. Every artifact is processed before exiting, so one bad input
//! does not mask diagnostics for the rest.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use oxicrypt_integrity_sign::elf;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oxicrypt_integrity::{
    SLOT_SIZE, constant_time_eq, encode_hmac_hex, mac_over_file_ranges, slot,
};

#[derive(Copy, Clone)]
enum Mode {
    Sign,
    Verify,
    Show,
}

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
        _ => {
            usage();
            return ExitCode::from(1);
        }
    };

    let mut targets: Vec<PathBuf> = Vec::new();
    let mut iter = argv.iter().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--target" | "--cdylib-target" => {
                let Some(path) = iter.next() else {
                    eprintln!("error: {a} requires a path argument");
                    return ExitCode::from(1);
                };
                targets.push(PathBuf::from(path));
            }
            "--staticlib-target" => {
                // A static archive is a build input, not a loadable
                // image. The linker copies the slot object into the
                // consumer's final binary, so a MAC computed over the
                // archive can never be verified at runtime — and an
                // archive has no load segments to classify in the first
                // place. The consumer signs their own link.
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

    if targets.is_empty() {
        eprintln!("error: no targets supplied");
        usage();
        return ExitCode::from(1);
    }

    let mut had_failure = false;
    for target in &targets {
        let outcome = match mode {
            Mode::Sign => sign(target),
            Mode::Verify => verify(target),
            Mode::Show => show(target),
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

/// Reads an artifact and derives its extent, refusing formats whose
/// classifier is not implemented yet rather than guessing.
fn layout_of(path: &Path) -> Result<(Vec<u8>, elf::Layout), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read: {e}"))?;
    if elf::is_elf64_le(&bytes) {
        let layout = elf::classify(&bytes)?;
        return Ok((bytes, layout));
    }
    let hint = match bytes.get(..4) {
        Some([0xcf | 0xce, 0xfa, 0xed, 0xfe]) => "Mach-O classification is not implemented",
        Some([0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca]) => {
            "Mach-O universal binaries are not supported; sign each architecture slice"
        }
        _ if bytes.get(..2) == Some(b"MZ".as_slice()) => "PE classification is not implemented",
        _ => "unrecognised executable format",
    };
    Err(hint.to_owned())
}

fn sign(path: &Path) -> Result<(), String> {
    let (mut bytes, layout) = layout_of(path)?;
    let mac = mac_over_file_ranges(&bytes, &layout.ranges)
        .map_err(|d| format!("cannot hash the extent: {d}"))?;
    let encoded = slot::encode(&layout.ranges, layout.slot_rva, &mac)
        .map_err(|d| format!("cannot encode the slot: {d}"))?;

    let end = layout
        .slot_file_off
        .checked_add(SLOT_SIZE)
        .ok_or("slot offset overflows")?;
    let window = bytes
        .get_mut(layout.slot_file_off..end)
        .ok_or("slot extends past the end of the file")?;
    window.copy_from_slice(&encoded);
    std::fs::write(path, &bytes).map_err(|e| format!("cannot write: {e}"))?;

    // Self-check: re-read from disk and run the offline verify. A signer
    // that reported success without reading back what it wrote would be
    // asserting an outcome it never observed. This also exercises
    // `slot::parse`, so a structurally invalid table fails here rather
    // than at the consumer's boot.
    verify(path).map_err(|e| format!("signed, but the read-back check failed: {e}"))?;

    let hex = encode_hmac_hex(&mac);
    let hex = core::str::from_utf8(&hex).unwrap_or("<non-utf8>");
    let extent = slot::extent_len(&layout.ranges).unwrap_or(0);
    println!(
        "signed {} -> {hex}\n  extent {extent} bytes in {} ranges ({} of {} mapped bytes, {}%)",
        path.display(),
        layout.ranges.len(),
        extent,
        layout.mapped_len,
        percent(extent, layout.mapped_len),
    );
    Ok(())
}

fn verify(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read: {e}"))?;
    let (parsed, _) = read_slot(&bytes)?;
    let computed = mac_over_file_ranges(&bytes, &parsed.ranges)
        .map_err(|d| format!("cannot hash the extent: {d}"))?;
    if constant_time_eq(&computed, &parsed.mac) {
        println!("verify ok: {}", path.display());
        Ok(())
    } else {
        Err("MAC mismatch — the file does not match its slot".to_owned())
    }
}

fn show(path: &Path) -> Result<(), String> {
    let (bytes, layout) = layout_of(path)?;
    println!("{}", path.display());
    println!(
        "  slot at file offset {:#x}, RVA {:#x}",
        layout.slot_file_off, layout.slot_rva
    );
    println!(
        "  loader-invariant before subtraction: {} bytes of {} mapped ({}%)",
        layout.invariant_len,
        layout.mapped_len,
        percent(layout.invariant_len, layout.mapped_len)
    );
    let extent = slot::extent_len(&layout.ranges).unwrap_or(0);
    println!(
        "  extent after subtracting the slot: {extent} bytes in {} ranges ({}% of mapped, {}% of file)",
        layout.ranges.len(),
        percent(extent, layout.mapped_len),
        percent(extent, bytes.len() as u64),
    );
    for (i, r) in layout.ranges.iter().enumerate() {
        println!(
            "    [{i}] rva {:#010x} file {:#010x} len {}",
            r.rva, r.file_off, r.len
        );
    }
    if let Ok((parsed, _)) = read_slot(&bytes) {
        let hex = encode_hmac_hex(&parsed.mac);
        println!(
            "  slot: version {}, {} ranges, MAC {}",
            parsed.version,
            parsed.ranges.len(),
            core::str::from_utf8(&hex).unwrap_or("<non-utf8>")
        );
        if parsed.ranges == layout.ranges {
            println!("  slot's range table matches the extent derived from this file");
        } else {
            println!("  WARNING: the slot's range table differs from this file's extent");
        }
    } else {
        println!("  slot: unsigned or unreadable");
    }
    Ok(())
}

/// Locates and parses the slot in an artifact's file bytes.
fn read_slot(bytes: &[u8]) -> Result<(slot::SlotImage, usize), String> {
    let off = elf::find_slot(bytes)?;
    let end = off.checked_add(SLOT_SIZE).ok_or("slot offset overflows")?;
    let window = bytes
        .get(off..end)
        .ok_or("slot extends past the end of the file")?;
    let parsed = slot::parse(window).map_err(|d| format!("slot invalid: {d}"))?;
    Ok((parsed, off))
}

/// Percentage to two decimal places, computed in integer arithmetic.
///
/// Floating point would be the obvious choice and is the wrong one here:
/// these are byte counts that can exceed an `f64` mantissa, and a report
/// a laboratory reads should not carry a rounding artefact from a
/// conversion it never needed. Zero denominator reports `0.00` rather
/// than dividing.
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
    eprintln!("  oxicrypt-integrity-sign --sign   <artifact> [<artifact> ...]");
    eprintln!("  oxicrypt-integrity-sign --verify <artifact> [<artifact> ...]");
    eprintln!("  oxicrypt-integrity-sign --show   <artifact> [<artifact> ...]");
    eprintln!();
    eprintln!("named flag form (may be mixed with positional):");
    eprintln!("  --target        <path>");
    eprintln!("  --cdylib-target <path>");
}
