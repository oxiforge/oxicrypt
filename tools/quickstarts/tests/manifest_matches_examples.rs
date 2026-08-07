//! Asserts that every quickstart in `lama.yaml` is byte-identical to the
//! example file that gets compiled.
//!
//! The LAMA specification requires each quickstart to compile and run without
//! modification. A YAML file cannot make that true of itself — nothing
//! compiles it — so the requirement is met in two halves: the code lives in
//! `examples/`, where the ordinary `--all-targets` gate builds it, and this
//! test asserts the manifest carries exactly that text.
//!
//! Neither half is sufficient alone. Examples that compile prove nothing about
//! what the manifest says; a manifest checked only against itself proves
//! nothing about whether the code builds. The failure this prevents is the one
//! found upstream, where five of seven quickstarts in the specification's own
//! reference example no longer compiled against the API they described, and
//! nothing reported it.

use std::fs;
use std::path::{Path, PathBuf};

/// Categories in `lama.yaml` and the example file each corresponds to.
///
/// Not every capability carries a quickstart, so this list is the contract:
/// a category named here MUST have one, and its text MUST match the file.
const PAIRS: &[(&str, &str)] = &[
    ("Hashing", "hashing"),
    ("Extendable-output functions (XOF)", "xof"),
    ("Message authentication", "message_authentication"),
    ("Symmetric encryption", "symmetric_encryption"),
    ("Random number generation", "random_number_generation"),
    ("Digital signatures", "digital_signatures"),
    ("Key agreement", "key_agreement"),
    ("Key derivation", "key_derivation"),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

/// Pulls each `category` → `quickstart.code` pair out of the manifest by text.
///
/// Deliberately not a YAML parse: this crate carries no YAML dependency, and
/// the block-scalar shape here is fixed by the serialization rules the
/// conformance linter already enforces.
fn manifest_quickstarts(manifest: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut category: Option<String> = None;
    let mut lines = manifest.lines().peekable();

    while let Some(line) = lines.next() {
        if let Some(rest) = line.strip_prefix("  - category:") {
            category = Some(rest.trim().trim_matches('"').to_string());
            continue;
        }
        if line.trim_end() != "      code: |" {
            continue;
        }
        // The block scalar is indented 8 spaces; it ends at the first line
        // that is neither blank nor indented that far.
        let mut code = String::new();
        while let Some(next) = lines.peek() {
            if next.trim().is_empty() {
                code.push('\n');
                lines.next();
                continue;
            }
            match next.strip_prefix("        ") {
                Some(body) => {
                    code.push_str(body);
                    code.push('\n');
                    lines.next();
                }
                None => break,
            }
        }
        if let Some(cat) = category.clone() {
            found.push((cat, code));
        }
    }
    found
}

#[test]
fn every_declared_quickstart_matches_its_example_file() {
    let root = repo_root();
    let manifest = fs::read_to_string(root.join("lama.yaml")).expect("read lama.yaml");
    let found = manifest_quickstarts(&manifest);

    // Positive control. An extractor that matches nothing reports no
    // mismatches, which is indistinguishable from every quickstart agreeing.
    assert!(
        found.len() >= PAIRS.len(),
        "extracted {} quickstarts from lama.yaml but {} are declared below; \
         the extractor is not seeing the manifest rather than the manifest being clean",
        found.len(),
        PAIRS.len()
    );

    for (category, slug) in PAIRS {
        let (_, code) = found
            .iter()
            .find(|(c, _)| c == category)
            .unwrap_or_else(|| panic!("lama.yaml has no quickstart for capability {category:?}"));

        let path = root
            .join("tools/quickstarts/examples")
            .join(format!("{slug}.rs"));
        let disk =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        assert_eq!(
            code.trim_end(),
            disk.trim_end(),
            "the quickstart for {category:?} in lama.yaml differs from {slug}.rs.\n\
             The file is the canonical copy — it is what gets compiled. Re-copy it \
             into the manifest rather than editing the manifest's copy, or the \
             manifest will claim code that was never built."
        );
    }
}

#[test]
fn every_example_file_is_declared() {
    let root = repo_root();
    let dir = root.join("tools/quickstarts/examples");
    let mut on_disk: Vec<String> = fs::read_dir(&dir)
        .expect("read examples dir")
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.extension()? == "rs").then(|| p.file_stem()?.to_str().map(str::to_string))?
        })
        .collect();
    on_disk.sort();

    // Positive control: the directory is not empty, so an empty read cannot
    // pass as "every file is declared".
    assert!(
        !on_disk.is_empty(),
        "no example files found in {}; the check would pass vacuously",
        dir.display()
    );

    for slug in &on_disk {
        assert!(
            PAIRS.iter().any(|(_, s)| s == slug),
            "{slug}.rs is compiled as an example but no capability in lama.yaml claims it. \
             Either add it to PAIRS with its category, or remove the file — an example \
             that no manifest references is built for nobody."
        );
    }
}
