//! Drift guard for the repository's boundary / `unsafe` accounting.
//!
//! Three documentation surfaces state numerals that restate facts about the
//! workspace as built: `docs/security-policy/security-policy.md` (§1 boundary
//! accounting, §9.2 `forbid(unsafe_code)` accounting, §3.1 FFI surface size),
//! `AGENTS.md` (project-context paragraph), and `README.md` (architecture
//! header and crate tree). Hand-maintained numerals drift when crates are
//! added; the tests here recompute every numeral from the workspace on disk
//! and assert the documented values match, so the drift is caught by the
//! ordinary test gate instead of a reviewer.
//!
//! Frozen history — `CHANGELOG.md` entries, dated Appendix B rows, dated
//! `ISA.md` decision entries — records what was true at its date and is
//! deliberately not checked. Only current-state statements are asserted.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// The out-of-boundary crate set. The canonical statement of the module
    /// boundary is security-policy.md §1; `policy_states_the_as_built_accounting`
    /// asserts §1 still names exactly these crates, so this constant and the
    /// policy cannot drift apart silently.
    const OUT_OF_BOUNDARY: [&str; 2] = ["oxicrypt-ffi", "oxicrypt-maxwell"];

    /// The audited in-boundary `unsafe` exception crates. The canonical
    /// statement is security-policy.md §9.2. `accounting()` asserts this set
    /// equals the disk-derived set of in-boundary crates lacking the forbid
    /// attribute, so a `forbid(unsafe_code)` swap — attribute removed from one
    /// crate while another gains it — fails by name, not just by count.
    /// `deny(unsafe_code)` deliberately does not qualify: the policy's claim
    /// is the compiler-hard forbid level.
    const AUDITED_EXCEPTIONS: [&str; 5] = [
        "oxicrypt-aes-accel",
        "oxicrypt-keccak-accel",
        "oxicrypt-sha-accel",
        "oxicrypt-timer",
        "oxicrypt-zeroize",
    ];

    struct Accounting {
        total: usize,
        in_boundary: usize,
        forbid_in_boundary: usize,
        exceptions: BTreeSet<String>,
        ffi_fns: usize,
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root resolves")
    }

    fn read_doc(rel: &str) -> String {
        let path = repo_root().join(rel);
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// Every library crate under `crates/` (a directory holding a `Cargo.toml`).
    fn workspace_crates() -> BTreeSet<String> {
        let dir = repo_root().join("crates");
        fs::read_dir(&dir)
            .expect("crates/ directory exists")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().join("Cargo.toml").is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// A crate "carries the attribute" when its crate root (`src/lib.rs`,
    /// falling back to `src/main.rs`) has a `#![forbid(unsafe_code)]` line.
    fn has_forbid(name: &str) -> bool {
        ["src/lib.rs", "src/main.rs"].iter().any(|root| {
            let path = repo_root().join("crates").join(name).join(root);
            fs::read_to_string(path)
                .is_ok_and(|src| src.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"))
        })
    }

    /// Count `pub … extern "C" fn` declarations across `oxicrypt-ffi/src/`.
    ///
    /// Counting assumptions, pinned: a declaration's `pub … extern "C" fn`
    /// prefix stays on one line (rustfmt wraps after the parameter paren, and
    /// keeps `pub unsafe extern "C" fn` together), and every exported function
    /// in `oxicrypt-ffi` is declared literally — none are macro-generated. If
    /// either assumption changes, this counter undercounts and the §3.1 probe
    /// fails on the stale prose number, which is the safe direction.
    fn ffi_fn_count() -> usize {
        fn count_in(dir: &Path) -> usize {
            fs::read_dir(dir)
                .expect("ffi src dir")
                .filter_map(Result::ok)
                .map(|entry| {
                    let path = entry.path();
                    if path.is_dir() {
                        count_in(&path)
                    } else if path.extension().is_some_and(|ext| ext == "rs") {
                        fs::read_to_string(&path)
                            .expect("ffi source readable")
                            .lines()
                            .filter(|l| {
                                let l = l.trim_start();
                                l.starts_with("pub ") && l.contains("extern \"C\" fn")
                            })
                            .count()
                    } else {
                        0
                    }
                })
                .sum()
        }
        count_in(&repo_root().join("crates/oxicrypt-ffi/src"))
    }

    /// English word for the small counts the docs spell out in prose.
    fn word(n: usize) -> &'static str {
        [
            "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
        ][n]
    }

    fn accounting() -> Accounting {
        let crates = workspace_crates();
        for out in OUT_OF_BOUNDARY {
            assert!(
                crates.contains(out),
                "OUT_OF_BOUNDARY names `{out}`, which is not a crate on disk"
            );
        }
        let in_boundary: BTreeSet<String> = crates
            .iter()
            .filter(|name| !OUT_OF_BOUNDARY.contains(&name.as_str()))
            .cloned()
            .collect();
        let forbid_in_boundary = in_boundary.iter().filter(|name| has_forbid(name)).count();
        let exceptions: BTreeSet<String> = in_boundary
            .iter()
            .filter(|name| !has_forbid(name))
            .cloned()
            .collect();
        let declared: BTreeSet<String> =
            AUDITED_EXCEPTIONS.iter().map(ToString::to_string).collect();
        assert_eq!(
            exceptions, declared,
            "in-boundary crates without #![forbid(unsafe_code)] no longer match the declared \
             audited-exception set — update security-policy.md §9.2, AGENTS.md, and this guard \
             together"
        );
        Accounting {
            total: crates.len(),
            in_boundary: in_boundary.len(),
            forbid_in_boundary,
            exceptions,
            ffi_fns: ffi_fn_count(),
        }
    }

    #[test]
    fn policy_states_the_as_built_accounting() {
        let a = accounting();
        let policy = read_doc("docs/security-policy/security-policy.md");

        let boundary_sentence = format!("Of the {} library crates", a.total);
        assert!(
            policy.contains(&boundary_sentence),
            "policy §1: {boundary_sentence:?} missing"
        );
        let remaining = format!("the remaining {} are inside it", a.in_boundary);
        assert!(
            policy.contains(&remaining),
            "policy §1: {remaining:?} missing"
        );
        let out_word = format!("exactly {}", word(OUT_OF_BOUNDARY.len()));
        assert!(
            policy.contains(&out_word),
            "policy §1: {out_word:?} missing"
        );
        for out in OUT_OF_BOUNDARY {
            assert!(
                policy.contains(&format!("`{out}`")),
                "policy §1: `{out}` not named"
            );
        }

        let ratio = format!("({} of {})", a.forbid_in_boundary, a.in_boundary);
        assert!(policy.contains(&ratio), "policy §9.2: {ratio:?} missing");
        let unsafe_summary = format!(
            "{} carry `#![forbid(unsafe_code)]`, {} are the audited exception crates",
            a.forbid_in_boundary,
            word(a.exceptions.len())
        );
        assert!(
            policy.contains(&unsafe_summary),
            "policy §1: {unsafe_summary:?} missing"
        );
        for exception in &a.exceptions {
            assert!(
                policy.contains(&format!("`{exception}`")),
                "policy: audited exception `{exception}` not named"
            );
        }

        let ffi = format!("({} exported functions", a.ffi_fns);
        assert!(policy.contains(&ffi), "policy §3.1: {ffi:?} missing");
    }

    #[test]
    fn agents_md_states_the_as_built_accounting() {
        let a = accounting();
        let agents = read_doc("AGENTS.md");

        let workspace = format!("a {}-crate workspace", a.total);
        assert!(
            agents.contains(&workspace),
            "AGENTS.md: {workspace:?} missing"
        );
        let ratio = format!(
            "{} of the {} crates inside the cryptographic boundary",
            a.forbid_in_boundary, a.in_boundary
        );
        assert!(agents.contains(&ratio), "AGENTS.md: {ratio:?} missing");
        let exceptions = format!(
            "The {} audited in-boundary exceptions",
            word(a.exceptions.len())
        );
        assert!(
            agents.contains(&exceptions),
            "AGENTS.md: {exceptions:?} missing"
        );
        for exception in &a.exceptions {
            assert!(
                agents.contains(&format!("`{exception}`")),
                "AGENTS.md: audited exception `{exception}` not named"
            );
        }
    }

    #[test]
    fn readme_states_the_count_and_lists_every_crate() {
        let a = accounting();
        let readme = read_doc("README.md");

        let header = format!("with {} crates", a.total);
        assert!(
            readme.contains(&header),
            "README architecture header: {header:?} missing"
        );
        for name in workspace_crates() {
            let listed = readme.lines().any(|line| {
                line.starts_with("  ") && line.split_whitespace().next() == Some(name.as_str())
            });
            assert!(listed, "README crate tree: `{name}` row missing");
        }
    }

    /// Every `ISC-N` cited anywhere in the tree resolves to a criterion defined
    /// in `ISA.md`.
    ///
    /// The repository previously carried a placeholder ISA whose IDs collided
    /// with the numbering the code actually cited, so a citation resolved
    /// against the authoritative file to an unrelated criterion with nothing to
    /// signal the mismatch. Nothing checked, which is why it survived.
    ///
    /// Files are read as bytes and scanned lossily rather than as UTF-8 text: a
    /// committed `.pyc` once carried a leaked path, and a scan that skips binary
    /// content reports clean while the worst instance sits in history.
    #[test]
    fn every_cited_isc_resolves_in_the_isa() {
        fn collect(dir: &Path, out: &mut Vec<(String, u32)>) {
            for entry in fs::read_dir(dir)
                .expect("readable dir")
                .filter_map(Result::ok)
            {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name == ".git" || name == "target" || name == "vendor" {
                    continue;
                }
                if path.is_dir() {
                    collect(&path, out);
                } else if name != "ISA.md" {
                    let bytes = fs::read(&path).unwrap_or_default();
                    let text = String::from_utf8_lossy(&bytes);
                    let mut rest: &str = &text;
                    while let Some(i) = rest.find("ISC-") {
                        rest = &rest[i + 4..];
                        let digits: String =
                            rest.chars().take_while(char::is_ascii_digit).collect();
                        if let Ok(n) = digits.parse::<u32>() {
                            out.push((path.display().to_string(), n));
                        }
                    }
                }
            }
        }

        let isa = read_doc("ISA.md");
        let defined: BTreeSet<u32> = isa
            .lines()
            .filter_map(|l| {
                l.strip_prefix("- [x] ISC-")
                    .or_else(|| l.strip_prefix("- [ ] ISC-"))
            })
            .filter_map(|r| {
                let d: String = r.chars().take_while(char::is_ascii_digit).collect();
                d.parse().ok()
            })
            .collect();

        let mut cited = Vec::new();
        collect(&repo_root(), &mut cited);

        // Anti-vacuity: a walk that found nothing would make the assertion below
        // trivially true. These bounds are deliberately loose — they exist to
        // catch a broken walk, not to pin a count that legitimately moves.
        // A bolded ID makes PAI's `parseCriteriaList()` return zero criteria for
        // the WHOLE file, silently. A count threshold does not catch a single
        // bolded line, so assert the shape directly.
        let bolded: Vec<&str> = isa
            .lines()
            .filter(|l| l.starts_with("- [") && l.contains("] **ISC-"))
            .collect();
        assert!(
            bolded.is_empty(),
            "criterion IDs must be bare `- [ ] ISC-N:` — a bolded ID parses to \
             zero criteria for the whole file:\n  {}",
            bolded.join("\n  ")
        );

        assert!(
            defined.len() > 100,
            "ISA.md defines only {} criteria — the parser found almost nothing, \
             which usually means an ID was bolded",
            defined.len()
        );
        assert!(
            cited.len() > 50,
            "found only {} ISC citations in the tree — the walk is broken, so \
             `all cited resolve` would pass having checked nothing",
            cited.len()
        );

        let mut unresolved: Vec<String> = cited
            .iter()
            .filter(|(_, n)| !defined.contains(n))
            .map(|(f, n)| format!("ISC-{n} cited in {f}"))
            .collect();
        unresolved.sort();
        unresolved.dedup();
        assert!(
            unresolved.is_empty(),
            "these citations resolve to no criterion in ISA.md — add the criterion \
             or correct the citation:\n  {}",
            unresolved.join("\n  ")
        );
    }
}
