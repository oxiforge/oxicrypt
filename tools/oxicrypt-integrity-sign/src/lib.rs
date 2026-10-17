//! Build-time signing for the module's pre-operational integrity test.
//!
//! Exposed as a library so the format classifiers can be exercised
//! directly by tests, including the negative controls that must build a
//! deliberately wrong extent, which the command-line tool has no business
//! being able to produce.
//!
//! Everything here is **outside the cryptographic boundary**. It parses
//! executable formats, which the module deliberately does not. It is not the
//! module image, so it starts the module without the image check (see
//! [`start_module`]).
//!
//! Signing writes a version-4 slot: the artifact's typed extent, the
//! fingerprint of the verifying key the artifact embeds, and an ML-DSA-87
//! signature over the slot and the extent's bytes, framed under the
//! integrity context string ([`oxicrypt_integrity::SIGNATURE_CONTEXT`]). The signer refuses an
//! artifact built without a verifying key, and a signing key whose public
//! half is not the key the artifact embeds, because either would produce an
//! artifact that can never pass its own test.

// `forbid` everywhere but Windows, where the one call into the operating
// system's random number generator (`key::windows_rng`) is allowed by name
// under `deny`; nothing else in this crate uses `unsafe`.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

pub mod elf;
pub mod image;
pub mod key;
pub mod macho;
pub mod pe;

pub use key::SigningKey;

use oxicrypt_integrity::key::{
    KEY_RECORD_KEY_OFFSET, KEY_RECORD_SIZE, VERIFY_KEY_LEN, find_key_record, parse_key_record,
};
use oxicrypt_integrity::slot::{self, Entry, Range, SlotFields};
use oxicrypt_integrity::{SLOT_SIZE, file_signature_input, format_fingerprint, key_fingerprint};
use oxicrypt_module::{Error, KatEntry, initialize_with_tests};

/// The integrity group the signer starts the module with: the integrity
/// group's two CASTs, ML-DSA-87 and SHA-256, without the image check.
const SIGNER_INTEGRITY: &[KatEntry] = &[
    KatEntry {
        name: oxicrypt_integrity::ML_DSA_CAST_NAME,
        run: oxicrypt_integrity::ml_dsa_cast,
    },
    KatEntry {
        name: oxicrypt_integrity::SHA256_CAST_NAME,
        run: oxicrypt_integrity::sha256_cast,
    },
];

/// Starts this process's copy of the module so the signer can hash, sign and
/// verify, which the module refuses until its self-tests have run.
///
/// The signer is outside the module boundary and is not the module image, so
/// it initialises the module with the ML-DSA-87 and SHA-256 CASTs as its
/// integrity group and no image check, followed by the self-tests of every
/// algorithm it uses.
/// A module already operational in this process is left as it is.
///
/// # Errors
///
/// Returns a description when the module does not start.
pub fn start_module() -> Result<(), String> {
    let tests: Vec<KatEntry> = [
        oxicrypt_sha::KATS,
        oxicrypt_hmac::KATS,
        oxicrypt_drbg::KATS,
        oxicrypt_xof::KATS,
        oxicrypt_ml_dsa::KATS,
    ]
    .iter()
    .flat_map(|s| s.iter().copied())
    .collect();
    match initialize_with_tests(SIGNER_INTEGRITY, &tests) {
        Ok(()) | Err(Error::AlreadyInitialized) => Ok(()),
        Err(e) => Err(format!("the module did not start: {e}")),
    }
}

/// Choices a signing run may make that the artifact does not decide.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignOptions<'a> {
    /// The loader to type an ELF image for, instead of the one its notes
    /// declare. Refused for a Mach-O or PE image.
    pub loader: Option<elf::Loader>,
    /// The symbol table to read an ELF image's module statics from when the
    /// image itself has been stripped: the separated debug file its
    /// `.gnu_debuglink` names.
    pub symbols: Option<&'a [u8]>,
    /// The reference the operating system signer's writes are measured
    /// against. For a Mach-O image, the same build after one `codesign`
    /// with the final identity and options, where the image being signed
    /// is the result of the next; each envelope locator field that differs
    /// is typed as a hole (`macho::reservation_holes`). For a PE image, the
    /// same build as linked, where the image being signed is the result of
    /// `signtool` with the final certificate and options; `CheckSum` and the
    /// Security directory entry, where they differ, are typed as holes
    /// (`pe::reservation_holes`).
    pub reserved_against: Option<&'a [u8]>,
}

/// The refusal of `--loader` for a Mach-O or PE image.
const LOADER_NOT_ELF: &str = "--loader applies to ELF images, whose loader decides how they are \
                              typed; drop it for a Mach-O or PE image";

/// Derives an image's extent, choosing the classifier from the image's own
/// magic.
///
/// The three formats share a rule and an output: every file-backed byte the
/// loader maps is typed from the loader's own structures. Each module states
/// how its format's structures map to the kinds.
///
/// # Errors
///
/// Returns a description when the format is unrecognised or out of scope, or
/// when the chosen classifier rejects the image.
pub fn classify(image: &[u8]) -> Result<image::Layout, String> {
    classify_with(image, &SignOptions::default())
}

/// [`classify`], with an ELF image typed for `options.loader` when given.
///
/// # Errors
///
/// As [`classify`], and a refusal when `options.loader` is given for a
/// Mach-O or PE image, or `options.reserved_against` for any other.
pub fn classify_with(image: &[u8], options: &SignOptions<'_>) -> Result<image::Layout, String> {
    if options.loader.is_some() && (macho::is_macho64_le(image) || pe::is_pe32plus(image)) {
        return Err(LOADER_NOT_ELF.to_owned());
    }
    if macho::is_macho64_le(image) {
        return macho::classify_with(image, options.reserved_against);
    }
    if pe::is_pe32plus(image) {
        return pe::classify_with(image, options.reserved_against);
    }
    if options.reserved_against.is_some() {
        return Err(
            "--reserved-against applies to Mach-O and PE images, whose code signature rewrites \
             header fields"
                .to_owned(),
        );
    }
    if elf::is_elf64_le(image) {
        return elf::classify_for(image, options.loader);
    }
    // Recognised but out of scope, so the refusal can say which rather than
    // reporting every unclassifiable file the same way.
    if let Some(reason) = macho::unsupported_reason(image) {
        return Err(reason.to_owned());
    }
    if let Some(reason) = pe::unsupported_reason(image) {
        return Err(reason.to_owned());
    }
    Err("unrecognised executable format".to_owned())
}

/// What the person signing `image` still has to do before it will run, if
/// anything.
///
/// On Apple silicon the operating system refuses a binary whose code
/// signature is stale, and writing the slot changes bytes an existing
/// signature covers, so the code signature is renewed after this tool, not
/// before it. A PE image that carries a certificate table was
/// Authenticode-signed before this tool, and that signature is stale in the
/// same way. An ELF image, and a PE image without a certificate table, needs
/// no further step.
#[must_use]
pub fn after_signing_note(image: &[u8]) -> Option<&'static str> {
    if macho::is_macho64_le(image) {
        Some(
            "Mach-O: renew the code signature now with `codesign --force` and the same \
             identity and options as the --reserved-against reference (see \
             docs/integrity-signing.md)",
        )
    } else if pe::has_certificate_table(image) {
        Some(
            "PE: sign the image again now with `signtool sign` and the same certificate and \
             options as the --reserved-against reference (see docs/integrity-signing.md)",
        )
    } else {
        None
    }
}

/// The verifying key an artifact embeds, or `None` for an artifact built
/// without one.
///
/// # Errors
///
/// A description when the artifact holds no key record or several.
pub fn embedded_verify_key(image: &[u8]) -> Result<Option<[u8; VERIFY_KEY_LEN]>, String> {
    let off = find_key_record(image)?;
    let record = off
        .checked_add(KEY_RECORD_SIZE)
        .and_then(|end| image.get(off..end))
        .ok_or("the key record runs past the end of the file")?;
    parse_key_record(record).map_err(|d| d.to_string())
}

/// Writes `public` into an artifact's key record.
///
/// This is what a build does when `OXICRYPT_INTEGRITY_VERIFY_KEY` is set,
/// done after the link instead. It exists for test fixtures, which need a
/// key pair for an artifact cargo built without one; a release sets the key
/// at build time.
///
/// # Errors
///
/// A description when the artifact holds no key record or several.
pub fn embed_verify_key(image: &mut [u8], public: &[u8; VERIFY_KEY_LEN]) -> Result<(), String> {
    let off = find_key_record(image)?;
    let start = off
        .checked_add(KEY_RECORD_KEY_OFFSET)
        .ok_or("key record offset overflows")?;
    let end = start
        .checked_add(VERIFY_KEY_LEN)
        .ok_or("key record offset overflows")?;
    image
        .get_mut(start..end)
        .ok_or("the key record runs past the end of the file")?
        .copy_from_slice(public);
    Ok(())
}

/// Requires `key` to be the private half of the key `image` embeds.
fn check_key(image: &[u8], key: &SigningKey) -> Result<[u8; 32], String> {
    let embedded = embedded_verify_key(image)?.ok_or(
        "NoVerifyKey: the artifact was built without a verifying key; rebuild it with \
         OXICRYPT_INTEGRITY_VERIFY_KEY set to the public half of the signing key",
    )?;
    start_module()?;
    let signing = key.fingerprint()?;
    let expected = key_fingerprint(&embedded).map_err(|e| format!("cannot fingerprint: {e}"))?;
    if signing != expected {
        return Err(format!(
            "SigningKeyAbsent: the signing key ({}) is not the key the artifact embeds ({})",
            format_fingerprint(&signing),
            format_fingerprint(&expected)
        ));
    }
    Ok(signing)
}

/// Checks an image against the slot it carries: locates the slot and the
/// key record, requires the slot's `key_id` to name the embedded key,
/// rebuilds the signature input from the file and verifies the signature.
///
/// This is the offline check. It proves the file is internally consistent;
/// it says nothing about the loaded image, which is what the runtime test
/// exercises. Returns the embedded key's fingerprint.
///
/// # Errors
///
/// Returns a description when the slot or key record is absent, unparsable,
/// or disagrees with the bytes around it.
pub fn verify_image(image: &[u8]) -> Result<[u8; 32], String> {
    verify_for(image, None)
}

/// [`verify_image`], with an ELF slot's loader required to be `loader`
/// when it is given rather than the one the image declares: the check for
/// an artifact signed with `--loader`.
///
/// # Errors
///
/// As [`verify_image`], and a refusal when `loader` is given for a Mach-O
/// or PE image.
pub fn verify_image_for(image: &[u8], loader: Option<elf::Loader>) -> Result<[u8; 32], String> {
    verify_for(image, loader)
}

fn verify_for(image: &[u8], loader: Option<elf::Loader>) -> Result<[u8; 32], String> {
    if loader.is_some() && (macho::is_macho64_le(image) || pe::is_pe32plus(image)) {
        return Err(LOADER_NOT_ELF.to_owned());
    }
    start_module()?;
    let off = image::find_slot(image)?;
    let end = off.checked_add(SLOT_SIZE).ok_or("slot offset overflows")?;
    let window = image
        .get(off..end)
        .ok_or("slot extends past the end of the file")?;
    let parsed = match slot::parse(window) {
        Ok(parsed) => parsed,
        Err(d) => {
            // An unsigned artifact authenticates nothing, so what the signer
            // would refuse in it is the useful report; a damaged slot is
            // reported as damage, never as advice about the image.
            let template = window
                .get(16..SLOT_SIZE.saturating_sub(16))
                .is_some_and(|b| b.iter().all(|&x| x == 0));
            if template {
                classify_with(
                    image,
                    &SignOptions {
                        loader,
                        symbols: None,
                        reserved_against: None,
                    },
                )?;
            }
            return Err(format!("slot invalid: {d}"));
        }
    };
    let key = embedded_verify_key(image)?
        .ok_or("NoVerifyKey: the artifact was built without a verifying key")?;
    let fp = key_fingerprint(&key).map_err(|e| format!("cannot fingerprint: {e}"))?;
    if parsed.fields.key_id != fp {
        return Err(format!(
            "KeyMismatch: the slot was signed for {}, the artifact embeds {}",
            format_fingerprint(&parsed.fields.key_id),
            format_fingerprint(&fp)
        ));
    }
    // Authenticate first. Rebuilding the signed message needs only the
    // encoding of `Relative` words: an ELF or PE file word is its unslid
    // value, so nothing of the image is classified until the signature has
    // verified, and a changed byte is reported as `SignatureInvalid`, not as
    // whatever the classifier would make of it.
    let elf = elf::is_elf64_le(image);
    let macho = macho::is_macho64_le(image);
    let pe = pe::is_pe32plus(image);
    let relative = if macho {
        // The chain format alone: the typing is checked once the signature
        // has verified.
        macho::relative_encoding(image)?
    } else if elf || pe {
        image::RelativeEncoding::FileWord
    } else {
        classify(image)?.relative
    };
    let link_base = parsed.fields.link_base;
    let message = file_signature_input(image, window, &parsed, &|raw| {
        relative.unslid(raw, link_base)
    })
    .map_err(|d| format!("cannot rebuild the signature input: {d}"))?;
    // The external `ML-DSA.Verify` frames the input under the context
    // itself, so it is given `M`, the message without the prefix.
    let unframed = message
        .get(oxicrypt_integrity::MESSAGE_PREFIX.len()..)
        .ok_or("the signature input is shorter than its framing")?;
    match oxicrypt_ml_dsa::ml_dsa_87::verify(
        &key,
        unframed,
        oxicrypt_integrity::SIGNATURE_CONTEXT,
        &parsed.signature,
    ) {
        Ok(()) => {}
        // With a context of fixed, valid length, `InvalidInput` is a
        // signature that does not verify.
        Err(Error::InvalidInput) => {
            return Err("SignatureInvalid: the file does not match its signature".to_owned());
        }
        Err(e) => return Err(format!("the module refused the verification: {e}")),
    }
    if macho {
        // Signed: every chain word decodes to the kind and record the
        // signed table gives it.
        macho::check_signed(image, &parsed.fields)?;
    }
    if pe {
        // Signed: the lookup tables, names and descriptors decode to the
        // records the signed table gives the thunks.
        pe::check_signed(image, &parsed.fields)?;
    }
    if elf {
        // Signed: what the signer refuses in the image, typed as the slot
        // records, and the loader it was typed for.
        let slot_loader = if parsed.fields.flags & slot::FLAG_LOADER_BIONIC == 0 {
            elf::Loader::Glibc
        } else {
            elf::Loader::Bionic
        };
        elf::classify_for(image, Some(slot_loader))?;
        let declared = match loader {
            Some(l) => l,
            None => elf::inferred_loader(image)?,
        };
        if parsed.fields.flags != declared.slot_flags() {
            let name = |bionic: bool| if bionic { "bionic" } else { "glibc" };
            let slot_bionic = parsed.fields.flags & slot::FLAG_LOADER_BIONIC != 0;
            return Err(format!(
                "LoaderMismatch: the slot types this artifact for {}, but it declares {}; \
                 loaded by {}, its integrity test will fail. If you built it, sign it again \
                 for the loader that loads it; otherwise obtain a copy built for that loader",
                name(slot_bionic),
                name(declared == elf::Loader::Bionic),
                name(declared == elf::Loader::Bionic),
            ));
        }
    }
    Ok(fp)
}

/// Signs `image` in place: derives its extent, writes the slot and signs it.
///
/// # Errors
///
/// Returns a description when the image cannot be classified, embeds no
/// verifying key or a different one, the slot is missing or ambiguous, the
/// extent does not fit the slot, or the image has a file-backed module
/// static or no symbol table to check for one.
pub fn sign_image(image: &mut [u8], key: &SigningKey) -> Result<[u8; slot::SIG_LEN], String> {
    sign_image_with(image, key, &SignOptions::default())
}

/// [`sign_image`] with the choices `options` makes.
///
/// # Errors
///
/// As [`sign_image`].
pub fn sign_image_with(
    image: &mut [u8],
    key: &SigningKey,
    options: &SignOptions<'_>,
) -> Result<[u8; slot::SIG_LEN], String> {
    let layout = classify_with(image, options)?;
    if elf::is_elf64_le(image) || macho::is_macho64_le(image) || pe::is_pe32plus(image) {
        refuse_file_backed_statics(image, options.symbols, options.loader)?;
    }
    write_entries(image, &layout, &layout.entries, key)
}

/// The separated debug file an ELF artifact at `path` names through its
/// `.gnu_debuglink`, looked for beside the artifact and in its `.debug`
/// subdirectory, and required to match the link's CRC.
///
/// For an ELF artifact, `None` when it still holds local data objects in
/// its own symbol table, names no debug file, or neither location holds
/// one; `None` too for an artifact that is neither ELF, Mach-O nor PE. A
/// candidate whose CRC differs is passed over for the other; when
/// one was found and none matched, the refusal names it.
///
/// For a Mach-O artifact, the dSYM `dsymutil` wrote for it, beside it as
/// `<artifact>.dSYM`: the file under `Contents/Resources/DWARF/` whose
/// `LC_UUID` is the artifact's.
///
/// For a PE artifact, the program database its CodeView debug record names,
/// by file name beside the artifact, required to carry the record's GUID and
/// age.
///
/// # Errors
///
/// `StaticsUnchecked` when every debug file found fails the CRC, or the
/// UUID for a dSYM, or the GUID and age for a PDB, or a description when
/// the link is malformed or a candidate cannot be read for a reason other
/// than its absence.
pub fn debug_symbols(path: &std::path::Path, bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if macho::is_macho64_le(bytes) {
        return dsym_symbols(path, bytes);
    }
    if pe::is_pe32plus(bytes) {
        return pdb_symbols(path, bytes);
    }
    if !elf::is_elf64_le(bytes) || elf::has_local_objects(bytes) {
        return Ok(None);
    }
    let Some((name, crc)) = elf::debuglink(bytes)? else {
        return Ok(None);
    };
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut mismatched = None;
    for candidate in [dir.join(&name), dir.join(".debug").join(&name)] {
        let debug = match std::fs::read(&candidate) {
            Ok(debug) => debug,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("cannot read {}: {e}", candidate.display())),
        };
        if elf::debuglink_crc(&debug) == crc {
            return Ok(Some(debug));
        }
        mismatched.get_or_insert(candidate);
    }
    match mismatched {
        Some(candidate) => Err(format!(
            "StaticsUnchecked: {} does not match the CRC the artifact's .gnu_debuglink records",
            candidate.display()
        )),
        None => Ok(None),
    }
}

/// The dSYM beside a Mach-O artifact whose `LC_UUID` is the artifact's.
fn dsym_symbols(path: &std::path::Path, bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let Some(name) = path.file_name() else {
        return Ok(None);
    };
    let mut bundle = name.to_os_string();
    bundle.push(".dSYM");
    let dir = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(bundle)
        .join("Contents")
        .join("Resources")
        .join("DWARF");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", dir.display())),
    };
    let uuid = macho::image_uuid(bytes)?;
    let mut unreadable = None;
    let mut mismatched = None;
    for entry in entries {
        let candidate = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let Some(uuid) = uuid else {
            return Err(format!(
                "StaticsUnchecked: the artifact carries no LC_UUID, so {} cannot be matched to \
                 it; link without -no_uuid",
                candidate.display()
            ));
        };
        let debug = std::fs::read(&candidate)
            .map_err(|e| format!("cannot read {}: {e}", candidate.display()))?;
        match macho::image_uuid(&debug) {
            Ok(Some(found)) if found == uuid => return Ok(Some(debug)),
            Ok(_) => {
                mismatched.get_or_insert(candidate);
            }
            Err(e) => {
                unreadable.get_or_insert((candidate, e));
            }
        }
    }
    match (mismatched, unreadable) {
        (Some(candidate), _) => Err(format!(
            "StaticsUnchecked: {} is not the dSYM of this artifact: its LC_UUID differs; keep \
             the dSYM of this build beside it",
            candidate.display()
        )),
        (None, Some((candidate, e))) => Err(format!(
            "StaticsUnchecked: {} cannot be read as a dSYM: {e}",
            candidate.display()
        )),
        (None, None) => Ok(None),
    }
}

/// The PDB beside a PE artifact that its CodeView record names.
fn pdb_symbols(path: &std::path::Path, bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let Some(cv) = pe::codeview(bytes)? else {
        return Ok(None);
    };
    // The linker may record a full path, from either kind of system; the
    // PDB is looked for beside the artifact by its file name.
    let name = cv
        .path
        .rsplit(['\\', '/'])
        .next()
        .filter(|n| !n.is_empty())
        .ok_or("the CodeView record names no program database")?;
    let candidate = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(name);
    let pdb = match std::fs::read(&candidate) {
        Ok(pdb) => pdb,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", candidate.display())),
    };
    pe::matching_pdb(bytes, &pdb).map_err(|e| format!("{e} ({})", candidate.display()))?;
    Ok(Some(pdb))
}

/// The module statics of an ELF image, read from its own symbol table or,
/// when it has none, from `symbols`; of a Mach-O image, from `symbols`, its
/// dSYM, when given, else from its own symbol table; of a PE image, from
/// `symbols`, its program database.
///
/// # Errors
///
/// `StaticsUnchecked` when neither carries a symbol table, or a description
/// when either is malformed.
pub fn module_statics(
    image: &[u8],
    symbols: Option<&[u8]>,
    loader: Option<elf::Loader>,
) -> Result<elf::Statics, String> {
    if macho::is_macho64_le(image) {
        return macho::module_statics(image, symbols);
    }
    if pe::is_pe32plus(image) {
        return pe::module_statics(image, symbols);
    }
    // The image's own table serves only while it still holds local data
    // objects: a strip that keeps global symbols drops the module's statics,
    // which the debug file still names. A debug file is accepted only as
    // the one the image's `.gnu_debuglink` names, by its CRC.
    let source = match symbols {
        _ if elf::has_local_objects(image) => image,
        Some(debug) => {
            match elf::debuglink(image)? {
                Some((_, crc)) if elf::debuglink_crc(debug) == crc => {}
                _ => {
                    return Err(
                        "StaticsUnchecked: the symbols supplied are not the debug file the \
                         artifact's .gnu_debuglink names"
                            .to_owned(),
                    );
                }
            }
            debug
        }
        None if elf::has_symtab(image) => image,
        None => {
            return Err(
                "StaticsUnchecked: the artifact has no symbol table, and no debug file was \
                 found through its .gnu_debuglink; split the debug file off, add a matching \
                 .gnu_debuglink, keep the debug file beside the artifact, strip, and sign the \
                 stripped artifact"
                    .to_owned(),
            );
        }
    };
    elf::module_statics(image, source, loader)
}

/// Refuses an ELF, Mach-O or PE image in which a module static the module
/// must start from zero-fill is file-backed: an edit of the file could
/// preset the module's state.
fn refuse_file_backed_statics(
    image: &[u8],
    symbols: Option<&[u8]>,
    loader: Option<elf::Loader>,
) -> Result<(), String> {
    let statics = module_statics(image, symbols, loader)?;
    let macho = macho::is_macho64_le(image);
    let pe = pe::is_pe32plus(image);
    if !statics.missing.is_empty() {
        let remedy = if macho {
            "on arm64 build with -C llvm-args=-aarch64-enable-global-merge=false, which \
             otherwise merges the statics into one unnamed symbol; to strip, build with debug \
             info and split-debuginfo set to packed, strip, and sign with <artifact>.dSYM beside \
             it"
        } else if pe {
            "build with full debug information (CARGO_PROFILE_RELEASE_DEBUG=full), whose program \
             database names every static, and sign with that PDB beside the artifact"
        } else {
            "split the debug file off with a matching .gnu_debuglink, keep it beside the \
             artifact, strip, and sign the stripped artifact"
        };
        return Err(format!(
            "StaticsUnchecked: the symbol table does not name {} in writable memory, so an \
             empty file-backed statics row would prove nothing; {remedy}",
            statics.missing.join(", ")
        ));
    }
    if let Some(first) = statics.rows.first() {
        let remedy = if macho {
            "Link with the zero-fill sections in a segment of their own \
             (-Wl,-rename_section,__DATA,__bss,__ZEROFILL,__bss and the same for __common) \
             before signing"
        } else if pe {
            "Link with zero-initialised data in a section of its own, which has no file bytes \
             (-C link-arg=/MERGE:.bss=.zbss), before signing"
        } else {
            "Place module state in zero-fill (.bss) before signing"
        };
        return Err(format!(
            "FileBackedStatic: {} module static(s) the module must start from zero-fill lie in \
            the file's bytes, where an edit could preset them; the first is {} at {:#x} \
            ({} of {} bytes file-backed). {remedy}",
            statics.rows.len(),
            first.name,
            first.addr,
            first.file_backed,
            first.size
        ));
    }
    Ok(())
}

/// Writes an arbitrary extent, as `Plain` entries, into an image's slot and
/// signs it.
///
/// Separate from [`sign_image`] so a test can sign an image against an
/// extent the classifier would never emit. That is the only way to build the
/// control which proves the stability probe can fail: an extent widened to
/// cover a region the loader rewrites must be rejected at runtime.
///
/// # Errors
///
/// Returns a description when the key does not match the artifact, the
/// ranges do not fit the table, fall outside the image, or produce a slot the
/// verifier would refuse.
pub fn write_extent(
    image: &mut [u8],
    layout: &image::Layout,
    ranges: &[Range],
    key: &SigningKey,
) -> Result<[u8; slot::SIG_LEN], String> {
    let plain: Vec<Entry> = ranges.iter().copied().map(Entry::plain).collect();
    write_entries(image, layout, &plain, key)
}

/// What an image's extent takes of its slot, computed as signing encodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotBudget {
    /// Stored entries the merged table takes.
    pub stored: usize,
    /// Bytes the string table of bound-import records takes.
    pub string_table: usize,
    /// Stored entries that fit beside that string table.
    pub capacity: usize,
    /// Whether the slot signing would write encodes and parses back as
    /// given: the table and the string table fit, the expanded table is
    /// within `MAX_EXPANDED`, and every entry and the canonical form are
    /// accepted. `None` when it is not, with the reason.
    pub refused: Option<String>,
}

impl SlotBudget {
    /// Whether signing would accept the slot: [`SlotBudget::refused`] is
    /// `None`.
    #[must_use]
    pub const fn fits(&self) -> bool {
        self.refused.is_none()
    }
}

/// The slot budget of `layout`: the merged table and the records it names,
/// as [`write_entries`] would encode them, and whether signing would accept
/// the slot, decided by the same encode-and-parse [`write_entries`] runs.
///
/// # Errors
///
/// A description when a record's name is too long to encode.
#[allow(
    clippy::integer_division,
    reason = "capacity in whole entries; the remainder is padding"
)]
pub fn slot_budget(layout: &image::Layout) -> Result<SlotBudget, String> {
    let merged = slot::merge(&layout.entries);
    let string_table = if layout
        .entries
        .iter()
        .any(|e| e.kind == slot::EntryKind::Bind)
    {
        slot::string_table_len(&layout.records)
            .map_err(|d| format!("cannot encode the string table: {d}"))?
    } else {
        0
    };
    let room = (slot::OFF_FTR - slot::OFF_TABLE).saturating_sub(string_table);
    Ok(SlotBudget {
        stored: slot::table_len(&merged),
        string_table,
        capacity: room / slot::ENTRY_SIZE,
        refused: unsigned_slot(layout, &layout.entries, [0u8; 32]).err(),
    })
}

/// The slot signing writes for `entries` before the signature: its fields,
/// its encoding with a zero signature, and that encoding parsed back.
///
/// The one path both [`write_entries`] and [`slot_budget`] take, so the
/// budget's verdict is the signer's.
///
/// # Errors
///
/// A description when the table or the string table does not fit, the slot
/// would be refused (an expanded table past `MAX_EXPANDED`, a malformed
/// entry), or it would not record the extent as given.
fn unsigned_slot(
    layout: &image::Layout,
    entries: &[Entry],
    key_id: [u8; 32],
) -> Result<(SlotFields, Vec<u8>, slot::SlotImage), String> {
    let fields = SlotFields {
        flags: layout.flags,
        slot_rva: layout.slot_rva,
        key_id,
        link_base: layout.link_base,
        slot_file_off: u32::try_from(layout.slot_file_off)
            .map_err(|_| "slot file offset exceeds 32 bits")?,
        file_len: layout.file_len,
        entries: slot::merge(entries),
        // The records the entries name: a table of other kinds names none.
        records: if entries.iter().any(|e| e.kind == slot::EntryKind::Bind) {
            layout.records.clone()
        } else {
            Vec::new()
        },
    };
    let unsigned = slot::encode(&fields, &[0u8; slot::SIG_LEN])
        .map_err(|d| format!("cannot encode the slot: {d}"))?;
    let parsed = slot::parse(&unsigned).map_err(|d| format!("the slot would be refused: {d}"))?;
    // The slot must say exactly what was asked for: a table the encoding
    // could not hold as given is refused, never signed as something else.
    if parsed.fields != fields {
        return Err(
            "the slot would not record the extent as given; the table is not canonical".to_owned(),
        );
    }
    Ok((fields, unsigned, parsed))
}

/// Writes `entries` into an image's slot, merged into canonical form, and
/// signs it. `image` changes only once the signed copy has passed its
/// self-check; on any error it is left as it was.
///
/// # Errors
///
/// As [`write_extent`].
pub fn write_entries(
    image: &mut [u8],
    layout: &image::Layout,
    entries: &[Entry],
    key: &SigningKey,
) -> Result<[u8; slot::SIG_LEN], String> {
    let key_id = check_key(image, key)?;
    let (fields, unsigned, parsed) = unsigned_slot(layout, entries, key_id)?;
    let link_base = layout.link_base;
    let message = file_signature_input(image, &unsigned, &parsed, &|raw| {
        layout.relative.unslid(raw, link_base)
    })
    .map_err(|d| format!("cannot build the signature input: {d}"))?;
    // Signed through the external interface, which adds the framing the
    // module verifies, so it is given `M` without the prefix.
    let unframed = message
        .get(oxicrypt_integrity::MESSAGE_PREFIX.len()..)
        .ok_or("the signature input is shorter than its framing")?;
    let signature = key.sign(unframed)?;
    let encoded =
        slot::encode(&fields, &signature).map_err(|d| format!("cannot encode the slot: {d}"))?;
    let end = layout
        .slot_file_off
        .checked_add(SLOT_SIZE)
        .ok_or("slot offset overflows")?;
    // The self-check runs on a copy, so a failure leaves `image` untouched.
    let mut signed = image.to_vec();
    signed
        .get_mut(layout.slot_file_off..end)
        .ok_or("slot extends past the end of the file")?
        .copy_from_slice(&encoded);
    let loader =
        elf::is_elf64_le(&signed).then_some(if layout.flags & slot::FLAG_LOADER_BIONIC == 0 {
            elf::Loader::Glibc
        } else {
            elf::Loader::Bionic
        });
    verify_for(&signed, loader).map_err(|e| format!("signed, but the self-check failed: {e}"))?;
    image.copy_from_slice(&signed);
    Ok(signature)
}

#[cfg(test)]
#[allow(clippy::panic)]
pub(crate) mod test_support {
    use std::sync::OnceLock;

    use super::SigningKey;

    /// One key from a fixed seed for the whole test process; deriving one
    /// runs a pairwise consistency test, which there is no need to repeat.
    pub(crate) fn test_key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| {
            SigningKey::from_seed(&[0x42; 32]).unwrap_or_else(|e| panic!("keygen: {e}"))
        })
    }

    /// Writes a key record holding the test key's public half at `at`, the
    /// way the module's static lays it out.
    pub(crate) fn put_key_record(image: &mut [u8], at: usize) {
        use oxicrypt_integrity::key::{KEY_RECORD_FOOTER_MAGIC, KEY_RECORD_HEADER_MAGIC};
        let mut record = Vec::new();
        record.extend_from_slice(&KEY_RECORD_HEADER_MAGIC);
        record.extend_from_slice(test_key().public_key());
        record.extend_from_slice(&KEY_RECORD_FOOTER_MAGIC);
        let end = at.saturating_add(record.len());
        match image.get_mut(at..end) {
            Some(window) => window.copy_from_slice(&record),
            None => panic!("the key record does not fit the fixture at {at:#x}"),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]
mod tests {
    use super::test_support::test_key;
    use super::*;

    /// An image that a slot can describe: the ELF fixture, on every host.
    ///
    /// Not this test binary's own bytes: an unoptimised ELF test binary's
    /// RELRO interleaves more relocated words than the slot's table can
    /// list, a Mach-O test binary is linked with whatever fixup encoding its
    /// deployment target defaults to, and a PE test binary's statics are
    /// checked from a program database built for it (an optimised library or
    /// executable fits, and `integrity-probe` signs and runs one end to end).
    fn fixture_image() -> Vec<u8> {
        elf::tests::Fixture::new().build()
    }

    /// `verify_image` accepts what `sign_image` produced, and rejects the
    /// same bytes with one changed inside the extent.
    #[test]
    fn verify_image_accepts_a_signed_image_and_rejects_a_changed_one() {
        let mut image = fixture_image();
        embed_verify_key(&mut image, test_key().public_key()).unwrap();
        let layout = classify(&image).expect("classify the ELF fixture");
        sign_image(&mut image, test_key()).expect("sign");
        assert_eq!(
            verify_image(&image).unwrap(),
            test_key().fingerprint().unwrap()
        );

        let last = layout.ranges.last().expect("extent has ranges");
        let off = (last.file_off + last.len / 2) as usize;
        let mut tampered = image.clone();
        tampered[off] ^= 0xff;
        let err = verify_image(&tampered).expect_err("a changed byte must fail");
        assert!(err.starts_with("SignatureInvalid"), "{err}");

        // A changed signature byte fails the same way, and a changed key id
        // names the mismatch.
        let slot_off = image::find_slot(&image).unwrap();
        let mut resig = image.clone();
        resig[slot_off + slot::OFF_SIG] ^= 1;
        assert!(verify_image(&resig).is_err());
        let mut rekey = image.clone();
        rekey[slot_off + slot::OFF_KEY_ID] ^= 1;
        assert!(verify_image(&rekey).unwrap_err().starts_with("KeyMismatch"));
    }

    /// The budget's verdict is signing's: a layout signing accepts fits, and
    /// one whose last entry runs past the file length it records is refused
    /// by the same parse, with the reason.
    #[test]
    fn the_slot_budget_refuses_what_signing_refuses() {
        let image = fixture_image();
        let mut layout = classify(&image).unwrap();
        assert!(slot_budget(&layout).unwrap().fits(), "control");
        let last = *layout.entries.last().unwrap();
        layout.entries.push(Entry::plain(Range {
            rva: last.rva + last.len + 0x1000,
            file_off: layout.file_len + 0x1000,
            len: 8,
        }));
        let budget = slot_budget(&layout).unwrap();
        assert!(
            budget.stored <= budget.capacity,
            "premise: it is not a capacity refusal"
        );
        assert!(!budget.fits());
        assert!(budget.refused.unwrap().contains("refused"));
    }

    /// The slot carries a FIPS 204 external-interface ML-DSA-87 signature
    /// over the unframed signature input under the integrity context, as
    /// the gated `verify` checks it, and signing is deterministic: the same
    /// key over the same image gives the same signature.
    #[test]
    fn the_signature_is_deterministic_external_ml_dsa_87_under_the_context() {
        let mut image = fixture_image();
        embed_verify_key(&mut image, test_key().public_key()).unwrap();
        let mut again = image.clone();
        let sig = sign_image(&mut image, test_key()).unwrap();
        assert_eq!(sign_image(&mut again, test_key()).unwrap(), sig);
        assert_eq!(again, image);

        let at = image::find_slot(&image).unwrap();
        let window = &image[at..at + SLOT_SIZE];
        let parsed = slot::parse(window).unwrap();
        assert_eq!(parsed.signature, sig);
        let framed = file_signature_input(&image, window, &parsed, &Some).unwrap();
        let (prefix, unframed) = framed.split_at(oxicrypt_integrity::MESSAGE_PREFIX.len());
        assert_eq!(prefix, oxicrypt_integrity::MESSAGE_PREFIX);
        let pk = test_key().public_key();
        let ctx = oxicrypt_integrity::SIGNATURE_CONTEXT;
        assert!(oxicrypt_ml_dsa::ml_dsa_87::verify(pk, unframed, ctx, &sig).is_ok());
        // Control: another context, or none, is refused by the same check.
        assert!(oxicrypt_ml_dsa::ml_dsa_87::verify(pk, unframed, b"", &sig).is_err());
        assert!(oxicrypt_ml_dsa::ml_dsa_87::verify(pk, unframed, b"oxicrypt", &sig).is_err());
    }

    /// Signing refuses an artifact built without a verifying key, and a
    /// signing key that is not the one the artifact embeds.
    #[test]
    fn signing_refuses_a_missing_or_different_key() {
        let mut image = fixture_image();
        embed_verify_key(&mut image, &[0u8; VERIFY_KEY_LEN]).unwrap();
        let err = sign_image(&mut image, test_key()).unwrap_err();
        assert!(err.starts_with("NoVerifyKey"), "{err}");

        let other = SigningKey::from_seed(&[0x24; 32]).unwrap();
        embed_verify_key(&mut image, other.public_key()).unwrap();
        let err = sign_image(&mut image, test_key()).unwrap_err();
        assert!(err.starts_with("SigningKeyAbsent"), "{err}");
        assert!(
            err.contains("sha256:"),
            "the refusal names both fingerprints: {err}"
        );

        // Control: the matching key signs.
        assert!(sign_image(&mut image, &other).is_ok());
    }

    /// A key file that is absent or the wrong size is `SigningKeyAbsent`.
    #[test]
    fn an_unreadable_key_is_signing_key_absent() {
        let dir = std::env::temp_dir().join(format!("oxicrypt-sign-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let Err(missing) = SigningKey::read(&dir.join("absent.key")) else {
            panic!("an absent key must be refused");
        };
        assert!(missing.starts_with("SigningKeyAbsent"), "{missing}");
        let short = dir.join("short.key");
        std::fs::write(&short, [1u8; 31]).unwrap();
        let Err(err) = SigningKey::read(&short) else {
            panic!("a 31-byte key must be refused");
        };
        assert!(err.starts_with("SigningKeyAbsent"), "{err}");
        // A 64-byte file, or an expanded ML-DSA-87 private key, is not the
        // seed.
        for len in [64, oxicrypt_ml_dsa::ml_dsa_87::SK_LEN] {
            let wrong = dir.join(format!("{len}.key"));
            std::fs::write(&wrong, vec![1u8; len]).unwrap();
            let Err(err) = SigningKey::read(&wrong) else {
                panic!("a {len}-byte key must be refused");
            };
            assert!(err.contains("32-byte ML-DSA-87"), "{err}");
        }
        // Control: a 32-byte seed is read, and derives the pair from_seed
        // derives.
        let seed = dir.join("seed.key");
        std::fs::write(&seed, [0x42u8; 32]).unwrap();
        assert_eq!(
            SigningKey::read(&seed).unwrap().public_key(),
            test_key().public_key()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `keygen` writes a readable pair, the private half `0600`, and refuses
    /// a directory inside a git work tree.
    #[test]
    fn keygen_writes_a_usable_pair_outside_the_tree() {
        let dir = std::env::temp_dir().join(format!(
            "oxicrypt-keygen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let (private, public, fp) = key::keygen(&dir).unwrap();
        let read = SigningKey::read(&private).unwrap();
        assert_eq!(
            read.public_key().as_slice(),
            std::fs::read(&public).unwrap()
        );
        assert_eq!(read.fingerprint().unwrap(), fp);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&private).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(
            key::keygen(&dir).is_err(),
            "an existing pair is never overwritten"
        );

        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join(".git")).unwrap();
        let err = key::keygen(&tree.join("keys")).unwrap_err();
        assert!(err.contains("work tree"), "{err}");
        assert!(
            !tree.join("keys").exists(),
            "a refused directory must not be created"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Mach-O image gets the reminder to run `codesign` after signing; an
    /// ELF image, and a PE image without a certificate table, get none (the
    /// PE image with one is covered beside the PE fixture).
    #[test]
    fn only_a_macho_image_is_told_to_run_codesign_afterwards() {
        let macho = [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0];
        let note = after_signing_note(&macho).expect("a Mach-O image must get the note");
        assert!(note.contains("codesign"));
        assert_eq!(after_signing_note(b"\x7fELF\x02\x01\x01\x00"), None);
        assert_eq!(after_signing_note(b"MZ\x90\x00"), None);
        assert_eq!(after_signing_note(b""), None);
    }

    /// The loader an ELF image is typed for is recorded in the slot's flags,
    /// whether inferred from the Android note or chosen by override.
    #[test]
    fn the_loader_is_recorded_in_the_slot_flags() {
        let flags_of = |img: &[u8]| {
            let off = image::find_slot(img).unwrap();
            slot::parse(&img[off..off + SLOT_SIZE])
                .unwrap()
                .fields
                .flags
        };
        let mut f = elf::tests::Fixture::new();
        f.relr.clear();
        f.loader_note = true;
        let mut img = f.build();
        sign_image(&mut img, test_key()).unwrap();
        assert_eq!(flags_of(&img), slot::FLAG_LOADER_BIONIC);
        let mut img = f.build();
        let glibc = SignOptions {
            loader: Some(elf::Loader::Glibc),
            symbols: None,
            reserved_against: None,
        };
        sign_image_with(&mut img, test_key(), &glibc).unwrap();
        assert_eq!(flags_of(&img), 0);
        // The image declares bionic: `--verify` names the disagreement
        // rather than reporting a slot that would fail at load as sound.
        let err = verify_image(&img).unwrap_err();
        assert!(err.starts_with("LoaderMismatch"), "{err}");
        assert!(err.contains("If you built it"), "{err}");
        // Control: signed for the loader it declares, it verifies.
        let mut img = f.build();
        sign_image(&mut img, test_key()).unwrap();
        assert!(verify_image(&img).is_ok());
    }

    /// A loader override reaches every step: signing, the statics check, the
    /// read-back and `--verify`. A bionic-noted image using RELR, which the
    /// bionic typing refuses, signs for glibc when told to.
    #[test]
    fn a_loader_override_reaches_signing_and_verification() {
        let mut f = elf::tests::Fixture::new();
        f.loader_note = true;
        let mut img = f.build();
        let err = sign_image(&mut img.clone(), test_key()).unwrap_err();
        assert!(err.starts_with("RelrOnBionic"), "{err}");
        let glibc = SignOptions {
            loader: Some(elf::Loader::Glibc),
            symbols: None,
            reserved_against: None,
        };
        sign_image_with(&mut img, test_key(), &glibc).unwrap();
        assert!(verify_image_for(&img, Some(elf::Loader::Glibc)).is_ok());
        let err = verify_image(&img).unwrap_err();
        assert!(err.starts_with("LoaderMismatch"), "{err}");
    }

    /// `--verify` authenticates before it classifies: a changed program
    /// header is a signature failure, not the classifier's complaint about
    /// it; an unsigned image is reported as the signer would refuse it.
    #[test]
    fn verification_authenticates_before_it_classifies() {
        let mut img = elf::tests::Fixture::new().build();
        sign_image(&mut img, test_key()).unwrap();
        // PT_DYNAMIC is the third program header; clear its PF_W.
        img[64 + 2 * 56 + 4] &= !2;
        let err = verify_image(&img).unwrap_err();
        assert!(err.starts_with("SignatureInvalid"), "{err}");
        let mut f = elf::tests::Fixture::new();
        f.dyn_writable = false;
        let err = verify_image(&f.build()).unwrap_err();
        assert!(err.starts_with("DynamicPlacement"), "{err}");
    }

    /// Signing is the last step after strip: it writes the slot and nothing
    /// else, so the ELF header and every byte outside the slot are as the
    /// stripped file left them.
    #[test]
    fn signing_changes_only_the_slot() {
        let before = elf::tests::Fixture::new().build();
        let mut after = before.clone();
        sign_image(&mut after, test_key()).unwrap();
        let slot_off = image::find_slot(&after).unwrap();
        assert_eq!(before[..64], after[..64], "the ELF header is unchanged");
        let changed: Vec<usize> = (0..before.len())
            .filter(|&i| before[i] != after[i])
            .collect();
        assert!(!changed.is_empty(), "the slot must be written");
        assert!(
            changed
                .iter()
                .all(|&i| i >= slot_off && i < slot_off + SLOT_SIZE),
            "only slot bytes may change"
        );
    }

    /// A zero-initialised module static in the file's bytes is refused at
    /// signing; an image without a symbol table is refused unless the
    /// symbols come from its debug file.
    #[test]
    fn file_backed_statics_and_missing_symbols_are_refused_at_signing() {
        let mut f = elf::tests::Fixture::new();
        f.static_va = elf::tests::STATIC_VA;
        let mut img = f.build();
        let pristine = img.clone();
        let err = sign_image(&mut img, test_key()).unwrap_err();
        assert!(err.starts_with("FileBackedStatic"), "{err}");
        assert_eq!(img, pristine, "a refused image is not written");
        // Control: a non-zero file-backed module state is refused too, since
        // an edit could set it to any value.
        f.static_initialised = true;
        let err = sign_image(&mut f.build(), test_key()).unwrap_err();
        assert!(err.starts_with("FileBackedStatic"), "{err}");

        let symbols = elf::tests::Fixture::new().build();
        let mut f = elf::tests::Fixture::new();
        f.symtab = false;
        f.debuglink = Some(("x.debug".to_owned(), elf::debuglink_crc(&symbols)));
        let mut stripped = f.build();
        let err = sign_image(&mut stripped, test_key()).unwrap_err();
        assert!(err.starts_with("StaticsUnchecked"), "{err}");
        // Symbols that are not the debug file the link names are refused,
        // whoever supplies them.
        let mut other = symbols.clone();
        other[0x10] ^= 1;
        let wrong = SignOptions {
            loader: None,
            symbols: Some(&other),
            reserved_against: None,
        };
        let err = sign_image_with(&mut stripped.clone(), test_key(), &wrong).unwrap_err();
        assert!(err.starts_with("StaticsUnchecked"), "{err}");
        let with_debug = SignOptions {
            loader: None,
            symbols: Some(&symbols),
            reserved_against: None,
        };
        sign_image_with(&mut stripped, test_key(), &with_debug).unwrap();
        assert!(verify_image(&stripped).is_ok());

        // A symbol table naming no module static proves nothing.
        let mut f = elf::tests::Fixture::new();
        f.static_va = 0x10;
        let err = sign_image(&mut f.build(), test_key()).unwrap_err();
        assert!(err.starts_with("StaticsUnchecked"), "{err}");

        // A table that has lost one of the required statics is refused by
        // the name it lacks, whatever other module statics it still lists.
        for (i, path) in ["oxicrypt_module::STATE", "oxicrypt_integrity::LAST_STATUS"]
            .iter()
            .enumerate()
        {
            let mut f = elf::tests::Fixture::new();
            f.drop_symbol = Some(i);
            let err = sign_image(&mut f.build(), test_key()).unwrap_err();
            assert!(
                err.starts_with("StaticsUnchecked") && err.contains(path),
                "{err}"
            );
        }
        // The integrity status belongs to the boot sequence's test: an
        // artifact that does not link it does not link the status either,
        // and is not refused for lacking it. The state still is.
        let mut f = elf::tests::Fixture::new();
        f.boot_test = false;
        f.drop_symbol = Some(1);
        assert!(sign_image(&mut f.build(), test_key()).is_ok());
        f.drop_symbol = Some(0);
        let err = sign_image(&mut f.build(), test_key()).unwrap_err();
        assert!(err.contains("oxicrypt_module::STATE"), "{err}");
    }

    /// The debug file is found beside the artifact or in `.debug`, must match
    /// the link's CRC, and a mismatching one beside the artifact does not
    /// hide a matching one in `.debug`.
    #[test]
    fn the_debug_file_is_found_by_its_debuglink_and_crc() {
        let dir = std::env::temp_dir().join(format!("oxicrypt-debuglink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".debug")).unwrap();
        let debug = elf::tests::Fixture::new().build();
        let mut f = elf::tests::Fixture::new();
        f.symtab = false;
        f.debuglink = Some(("x.debug".to_owned(), elf::debuglink_crc(&debug)));
        let artifact = dir.join("x.so");
        let image = f.build();
        assert_eq!(
            debug_symbols(&artifact, &image).unwrap(),
            None,
            "no file yet"
        );
        std::fs::write(dir.join("x.debug"), b"not the debug file").unwrap();
        let err = debug_symbols(&artifact, &image).unwrap_err();
        assert!(err.starts_with("StaticsUnchecked"), "{err}");
        std::fs::write(dir.join(".debug").join("x.debug"), &debug).unwrap();
        assert_eq!(
            debug_symbols(&artifact, &image).unwrap(),
            Some(debug.clone())
        );
        std::fs::write(dir.join("x.debug"), &debug).unwrap();
        assert_eq!(debug_symbols(&artifact, &image).unwrap(), Some(debug));
        // An image whose own table still holds local objects needs no file.
        assert_eq!(
            debug_symbols(&artifact, &elf::tests::Fixture::new().build()).unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An image with no slot is refused, and says so rather than reporting a
    /// signature failure.
    #[test]
    fn verify_image_refuses_an_image_with_no_slot() {
        let err = verify_image(b"not an executable at all").expect_err("must refuse");
        assert!(!err.contains("SignatureInvalid"), "{err}");
    }
}
