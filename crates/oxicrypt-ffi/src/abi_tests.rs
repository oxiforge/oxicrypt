//! The ABI pin: the committed header must declare every function of
//! `abi/v<OXI_ABI_VERSION>.txt` with exactly the recorded parameter and
//! return types, and every recorded status code with its recorded value; the
//! file must list every function and status code the header declares; and
//! the file's frozen first lines must still have the count and digest
//! recorded here, so a recorded line cannot be edited to follow a break.
//!
//! A removed or changed function, or a renumbered status code, therefore
//! fails here until `OXI_ABI_VERSION` moves and a new inventory is started;
//! an addition fails until its line is appended. The header is generated
//! from this crate's source by cbindgen and checked for drift, so it is the
//! interface the library exports. Output sizes and the meaning of each
//! function are not in the inventory: the Rust binding's size and
//! known-answer tests pin the sizes it uses, and the rest rests on review.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::collections::BTreeSet;
use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn norm_type(t: &str) -> String {
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = t.replace(" *", "*").replace('*', " *");
    t.replace("* *", "**").trim().to_owned()
}

/// The frozen first lines of each inventory: their count, and the FNV-1a
/// 64-bit digest of those lines, each followed by a newline. The digest
/// guards against an accidental edit, not a deliberate one.
fn frozen(abi: i32) -> Option<(usize, u64)> {
    match abi {
        1 => Some((316, 0xe5b4_7830_6154_6473)),
        _ => None,
    }
}

fn fnv1a64(lines: &[String]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for line in lines {
        for byte in line.bytes().chain(core::iter::once(b'\n')) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// `name(type, …) -> ret` for each function the header declares, and
/// `OXI_RESULT_NAME = value` for each status code.
pub(crate) fn header_signatures(header: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = header
        .lines()
        .filter_map(|l| {
            let l = l.trim().trim_end_matches(',');
            let (name, value) = l.split_once(" = ")?;
            (name.starts_with("OXI_RESULT_") && value.parse::<i64>().is_ok())
                .then(|| format!("{name} = {value}"))
        })
        .collect();
    out.append(&mut function_signatures(header));
    out
}

/// `name(type, …) -> ret` for each function the header declares.
fn function_signatures(header: &str) -> BTreeSet<String> {
    let mut text = String::new();
    let mut rest = header;
    while let Some(start) = rest.find("/*") {
        text.push_str(&rest[..start]);
        let end = rest[start..].find("*/").expect("closed comment");
        rest = &rest[start + end + 2..];
    }
    text.push_str(rest);
    let text: String = text
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let open = "extern \"C\" {";
    let body = &text[text.find(open).expect("extern block") + open.len()..];
    let mut out = BTreeSet::new();
    for decl in body.split(';') {
        let decl = decl.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(paren) = decl.find('(') else {
            continue;
        };
        let head = &decl[..paren];
        let split = head
            .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let (returns, name) = head.split_at(split);
        let params = decl[paren + 1..decl.rfind(')').expect("closing paren")].trim();
        let params: Vec<String> = if params == "void" {
            Vec::new()
        } else {
            params
                .split(',')
                .map(|p| {
                    let p = p.trim();
                    let cut = p
                        .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .expect("a typed parameter");
                    norm_type(&p[..=cut])
                })
                .collect()
        };
        out.insert(format!(
            "{name}({}) -> {}",
            params.join(", "),
            norm_type(returns)
        ));
    }
    out
}

/// The recorded lines of `abi/v<n>.txt`, in file order.
fn inventory_lines(n: i32) -> Vec<String> {
    read(&format!("abi/v{n}.txt"))
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn inventory(n: i32) -> BTreeSet<String> {
    inventory_lines(n).into_iter().collect()
}

/// Whether the first lines of `lines` are the frozen ones of ABI `abi`.
fn frozen_prefix_holds(abi: i32, lines: &[String]) -> bool {
    let (count, digest) = frozen(abi).expect("a frozen record for this ABI");
    lines.len() >= count && fnv1a64(&lines[..count]) == digest
}

#[test]
fn the_frozen_lines_of_the_inventory_are_unchanged() {
    let lines = inventory_lines(crate::OXI_ABI_VERSION);
    assert!(
        frozen_prefix_holds(crate::OXI_ABI_VERSION, &lines),
        "the first {:?} lines of abi/v{}.txt were edited or removed; they are frozen. \
         A change that needs that raises OXI_ABI_VERSION and starts a new inventory",
        frozen(crate::OXI_ABI_VERSION).map(|f| f.0),
        crate::OXI_ABI_VERSION
    );

    // Positive controls: an edited line, a removed line and a reordering are
    // each caught; an appended line is not.
    let mut edited = lines.clone();
    edited[120] = edited[120].replace("-> int", "-> int64_t");
    assert_ne!(edited, lines, "the control edit changed nothing");
    assert!(!frozen_prefix_holds(crate::OXI_ABI_VERSION, &edited));
    let mut removed = lines.clone();
    removed.remove(5);
    assert!(!frozen_prefix_holds(crate::OXI_ABI_VERSION, &removed));
    let mut swapped = lines.clone();
    swapped.swap(0, 1);
    assert!(!frozen_prefix_holds(crate::OXI_ABI_VERSION, &swapped));
    let mut appended = lines.clone();
    appended.push("oxi_new_function() -> int".to_owned());
    assert!(frozen_prefix_holds(crate::OXI_ABI_VERSION, &appended));
}

/// The recorded signatures the header no longer declares as recorded.
fn broken(header: &BTreeSet<String>, recorded: &BTreeSet<String>) -> Vec<String> {
    recorded.difference(header).cloned().collect()
}

#[test]
fn the_header_keeps_every_recorded_signature_at_this_abi() {
    let header = header_signatures(&read("include/oxicrypt.h"));
    let recorded = inventory(crate::OXI_ABI_VERSION);
    assert!(
        recorded.len() > 200,
        "parsed only {} inventory lines",
        recorded.len()
    );

    // Positive control: one changed and one removed signature are found.
    let mut altered = header.clone();
    assert!(altered.remove("oxi_sha384(const uint8_t *, uintptr_t, uint8_t *) -> int"));
    altered.insert("oxi_sha384(const uint8_t *, uint32_t, uint8_t *) -> int".to_owned());
    assert!(altered.remove("oxi_abi_version() -> int"));
    assert!(altered.remove("OXI_RESULT_TAG_MISMATCH = 22"));
    altered.insert("OXI_RESULT_TAG_MISMATCH = 29".to_owned());
    assert_eq!(broken(&altered, &recorded).len(), 3);

    let broken = broken(&header, &recorded);
    assert!(
        broken.is_empty(),
        "functions removed or changed while OXI_ABI_VERSION is {}: {broken:#?}\n\
         A change that breaks compatibility raises OXI_ABI_VERSION and starts a new abi/v<n>.txt",
        crate::OXI_ABI_VERSION
    );
}

#[test]
fn every_header_function_is_recorded() {
    let header = header_signatures(&read("include/oxicrypt.h"));
    let recorded = inventory(crate::OXI_ABI_VERSION);
    let unrecorded: Vec<_> = header.difference(&recorded).collect();
    assert!(
        unrecorded.is_empty(),
        "append these to abi/v{}.txt (adding a function does not change the ABI): {unrecorded:#?}",
        crate::OXI_ABI_VERSION
    );
}

#[test]
fn the_signature_parser_reads_the_header_shapes() {
    let header = "extern \"C\" {\n/* doc */\nint oxi_x(OxiAes256Key **out_handle, const uint8_t *key);\n\
                  const char *lama_manifest(void);\nvoid oxi_f(OxiAes256Key *handle);\n}\n";
    let got = function_signatures(header);
    let want: BTreeSet<String> = [
        "oxi_x(OxiAes256Key **, const uint8_t *) -> int",
        "lama_manifest() -> const char *",
        "oxi_f(OxiAes256Key *) -> void",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(got, want);
}
