//! Drift guard for the repository's boundary / `unsafe` accounting.
//!
//! Three documentation surfaces state numerals that restate facts about the
//! workspace as built: the FIPS 140-3 Security Policy (§1 boundary accounting,
//! §9.2 `forbid(unsafe_code)` accounting, §3.1 FFI surface size), `AGENTS.md`
//! (project-context paragraph), and `README.md` (architecture header and crate
//! tree). Hand-maintained numerals drift when crates are added; the tests here
//! recompute every numeral from the workspace on disk and assert the documented
//! values match, so the drift is caught by the ordinary test gate instead of a
//! reviewer.
//!
//! Frozen history — `CHANGELOG.md` entries, dated Appendix B rows, dated
//! `ISA.md` decision entries — records what was true at its date and is
//! deliberately not checked. Only current-state statements are asserted.
//!
//! # The Security Policy is not in this repository
//!
//! The Security Policy is withheld from the public tree and lives in a separate
//! private repository; `docs/security-policy/README.md` explains why and how to
//! request access. The five guards that assert its content therefore resolve it
//! at runtime and **skip** when it is unreachable, so an ordinary clone runs
//! green with no configuration at all.
//!
//! A skip prints to stderr, which a passing test discards, so the skip alone
//! cannot be the safety net. `security_policy_is_provisioned` is — but it
//! keys on *claimed* provisioning rather than on absence, and that departure
//! from the EA-dataset precedent this otherwise mirrors is deliberate. The EA
//! datasets are public, so failing on absence is right there. This document is
//! not obtainable by an outside contributor at any price, and failing on its
//! absence would reintroduce as one failure exactly the hard failures that
//! removing it from the tree exists to prevent. See that test for the full
//! state table.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // A guard that could not run announces itself on stderr, and the
    // provisioning gate states that a run under the opt-out is not evidence —
    // the same convention, for the same reason, as the EA parity gate in
    // `oxicrypt-maxwell`.
    clippy::print_stderr
)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};

    /// The out-of-boundary crate set. The canonical statement of the module
    /// boundary is security-policy.md §1; `policy_states_the_as_built_accounting`
    /// asserts the policy still names exactly these crates and no more,
    /// anywhere in the document, so this constant and the policy cannot drift
    /// apart silently.
    const OUT_OF_BOUNDARY: [&str; 2] = ["oxicrypt-ffi", "oxicrypt-maxwell"];

    /// The in-boundary `unsafe` exception crates. The canonical
    /// statement is security-policy.md §9.2. `accounting()` asserts this set
    /// equals the disk-derived set of in-boundary crates lacking the forbid
    /// attribute, so a `forbid(unsafe_code)` swap — attribute removed from one
    /// crate while another gains it — fails by name, not just by count.
    /// `deny(unsafe_code)` deliberately does not qualify: the policy's claim
    /// is the compiler-hard forbid level.
    const UNSAFE_EXCEPTIONS: [&str; 6] = [
        "oxicrypt-aes-accel",
        "oxicrypt-imageread",
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

    // ----- the withheld Security Policy -----
    //
    // The policy is not tracked here. It is resolved at runtime from a private
    // sibling clone, exactly as `oxicrypt-maxwell` resolves the EA v1.1.8
    // dataset bundle, and every guard that asserts its content skips when it is
    // unreachable so a public clone runs green.

    /// The policy's file name inside its repository.
    const POLICY_FILE: &str = "security-policy.md";

    /// Every file withheld from this repository, by name. The Security Policy,
    /// and the jitter-entropy concept mapping — an annex whose columns cite the
    /// policy's own rule numbering, moved with it 2026-08-05. The containment
    /// sweep denies all of them; only `POLICY_FILE` is resolved at runtime,
    /// because only the policy has assertions that depend on its content.
    const WITHHELD_FILES: [&str; 2] = ["security-policy.md", "jent-concept-mapping.md"];

    /// The default sibling-clone location, relative to `$HOME`. Cloning
    /// `oxiforge/oxicrypt-policy` there needs no further configuration.
    const POLICY_REPO_REL: &str = "repos/oxicrypt-policy";

    /// The in-tree path the policy used to occupy. Retained so
    /// `policy_resolution_precedence_holds` can assert it is never a
    /// resolution target — deliberately **not** a fallback, since a fallback
    /// would make that failure mode reachable and silent at the same time.
    const POLICY_IN_TREE: &str = "docs/security-policy/security-policy.md";

    /// Resolve the Security Policy from an environment value and a home
    /// directory. Split out from [`security_policy_path`] so the precedence can
    /// be exercised against synthetic inputs rather than only against whatever
    /// this machine happens to have provisioned.
    ///
    /// `$OXICRYPT_SECURITY_POLICY` may name the file itself or a directory
    /// containing it: pointing it at the clone directory is the mistake a reader
    /// of the variable's name will make, and accepting both costs one branch.
    fn resolve_policy(env: Option<&str>, home: &str) -> PathBuf {
        if let Some(value) = env.filter(|v| !v.is_empty()) {
            let path = PathBuf::from(value);
            return if path.is_dir() {
                path.join(POLICY_FILE)
            } else {
                path
            };
        }
        Path::new(home).join(POLICY_REPO_REL).join(POLICY_FILE)
    }

    /// Where the Security Policy is expected on this machine.
    fn security_policy_path() -> PathBuf {
        let env = std::env::var("OXICRYPT_SECURITY_POLICY").ok();
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        resolve_policy(env.as_deref(), &home)
    }

    /// The Security Policy's text, or `None` when it is not provisioned.
    ///
    /// `read_to_string`, not `File::open`: opening a *directory* succeeds on
    /// Linux and fails only on read, so an `is_ok()` probe would report a
    /// mis-resolved directory path as provisioned and every guard would then
    /// fail on empty content instead of skipping.
    fn read_policy() -> Option<String> {
        fs::read_to_string(security_policy_path()).ok()
    }

    /// Whether the caller has accepted losing the policy assertions by setting
    /// `OXICRYPT_SECURITY_POLICY_OPTIONAL=1`.
    ///
    /// An opt-out rather than an opt-in, for the same reason as
    /// `OXICRYPT_EA_DATA_OPTIONAL`: the default must be that an unprovisioned
    /// checkout says so, or an environment without the document masquerades as
    /// a passing gate.
    fn policy_optional() -> bool {
        std::env::var("OXICRYPT_SECURITY_POLICY_OPTIONAL").is_ok_and(|v| v == "1")
    }

    /// Announce a guard that could not run. Stderr is discarded on a passing
    /// test, which is precisely why `security_policy_is_provisioned` exists —
    /// this line is for someone reading a `--nocapture` run, not the safety net.
    fn skip_without_policy(guard: &str) {
        eprintln!(
            "SKIP {guard}: the Security Policy is not provisioned at {}. It is withheld from \
             this repository — see docs/security-policy/README.md.",
            security_policy_path().display()
        );
    }

    /// The resolution precedence holds, checked against inputs whose shape is
    /// known rather than against this machine's provisioning.
    ///
    /// Without this, `resolve_policy` could quietly lose its directory branch or
    /// its environment branch and every other test here would be unaffected:
    /// they all pass when the policy is unreachable, so a resolver that resolved
    /// nothing would read exactly like a clean skip.
    #[test]
    fn policy_resolution_precedence_holds() {
        // A real directory and a real file, so the `is_dir` branch is exercised
        // rather than assumed.
        let dir = repo_root();
        let file = dir.join("README.md");
        assert!(dir.is_dir() && file.is_file(), "fixture paths must exist");

        assert_eq!(
            resolve_policy(Some(&dir.display().to_string()), "/nonexistent-home"),
            dir.join(POLICY_FILE),
            "a directory in $OXICRYPT_SECURITY_POLICY must gain the file name"
        );
        assert_eq!(
            resolve_policy(Some(&file.display().to_string()), "/nonexistent-home"),
            file,
            "a file in $OXICRYPT_SECURITY_POLICY must be used as given"
        );
        assert_eq!(
            resolve_policy(Some(""), "/home/example"),
            Path::new("/home/example")
                .join(POLICY_REPO_REL)
                .join(POLICY_FILE),
            "an empty $OXICRYPT_SECURITY_POLICY must fall through, not resolve to \"\""
        );
        assert_eq!(
            resolve_policy(None, "/home/example"),
            Path::new("/home/example")
                .join(POLICY_REPO_REL)
                .join(POLICY_FILE),
            "the default is the private sibling clone"
        );
        assert_ne!(
            resolve_policy(None, "/home/example"),
            repo_root().join(POLICY_IN_TREE),
            "the in-tree path must never be a resolution target"
        );
    }

    /// A checkout that *claims* the Security Policy must actually have it.
    ///
    /// This gate deliberately does **not** mirror `ea_dataset_suite_is_provisioned`
    /// in its default, and the difference is the whole design. The EA datasets are
    /// public and anyone can fetch them, so failing by default is right: absence is
    /// always a fixable mistake. The Security Policy is withheld — an outside
    /// contributor cannot obtain it at any price, and making a bare clone fail
    /// `cargo test --workspace` would simply reintroduce, as one failure, the five
    /// hard failures that removing the document from the tree exists to prevent.
    ///
    /// So the gate fires on *claimed* provisioning rather than on absence. A
    /// checkout asserts a relationship to the policy in exactly two ways: setting
    /// `$OXICRYPT_SECURITY_POLICY`, or having the sibling clone directory on disk.
    /// Either one, with the document unreadable, is a misconfiguration on a machine
    /// that is supposed to be running the full set — and that is worth failing over,
    /// because it is the maintainer's own checkout going quiet. Neither one is an
    /// ordinary public clone, which passes and says so.
    ///
    /// | State | Outcome |
    /// |---|---|
    /// | policy readable | pass, all five guards assert |
    /// | `$OXICRYPT_SECURITY_POLICY` set, unreadable | **fail** — a named path that is wrong |
    /// | env unset, clone directory present, file unreadable | **fail** — the clone is there, the document is not |
    /// | env unset, no clone directory | pass with a warning — no claim was made |
    /// | `OXICRYPT_SECURITY_POLICY_OPTIONAL=1` | pass with a warning — claim withdrawn explicitly |
    ///
    /// The residual is stated rather than hidden: deleting the clone directory
    /// outright silences the gate. That is the price of not failing every public
    /// clone, and it is the maintainer's own machine, not a contributor's.
    #[test]
    fn security_policy_is_provisioned() {
        // Internal positive control, and it has to be stronger than "the name
        // appears in this file". Deleting a `#[test]` attribute leaves the
        // function present and this control satisfied; the guard then never runs
        // while the gate reports the precondition met. So each name must carry
        // BOTH the attribute immediately above it and the skip call that makes it
        // a policy guard at all — a guard that stopped skipping-on-absence is no
        // longer one of the five this gate speaks for.
        //
        // `#[ignore]` on a guard is NOT caught here and cannot be: it is a
        // one-token edit that leaves the source shape intact. `cargo clippy
        // --all-targets -- -D warnings` catches an outright removed `#[test]`
        // via dead_code; nothing catches `#[ignore]` but review.
        const GUARDED: [&str; 7] = [
            "policy_states_the_alpha_values_the_code_implements",
            "alpha_means_the_same_thing_in_the_policy_and_the_crate_doc",
            "every_cited_resolution_is_named_somewhere_a_reviewer_can_reach",
            "policy_carries_no_new_unresolved_drafting_markers",
            "policy_states_the_as_built_accounting",
            "policy_defers_the_toolchain_versions_to_the_tree",
            "policy_service_table_matches_the_profile_definitions",
        ];
        let own_source = read_doc("tools/doc-guard/src/lib.rs");
        for guard in GUARDED {
            assert!(
                own_source.contains(&format!("#[test]\n    fn {guard}()")),
                "the guarded-test list names `{guard}`, which is not a `#[test]` in this file"
            );
            assert!(
                own_source.contains(&format!("skip_without_policy(\"{guard}\")")),
                "`{guard}` does not skip on an absent policy, so this gate no longer speaks \
                 for it — remove it from GUARDED or restore the skip"
            );
        }

        let path = security_policy_path();
        match fs::read_to_string(&path) {
            Ok(_) => return,
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                // Present but unreadable — permissions, a symlink loop, invalid
                // UTF-8. Reporting this as "not provisioned" would tell the
                // operator to clone a repository they already have.
                panic!(
                    "the Security Policy at {} exists but could not be read: {e}. The {} \
                     guards asserting its content did not run.",
                    path.display(),
                    GUARDED.len()
                );
            }
            Err(_) => {}
        }

        // Did this checkout claim to have the document?
        let env_set = std::env::var("OXICRYPT_SECURITY_POLICY").is_ok_and(|v| !v.is_empty());
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let clone_dir_present = Path::new(&home).join(POLICY_REPO_REL).is_dir();
        let claimed = env_set || clone_dir_present;

        assert!(
            !claimed || policy_optional(),
            "the Security Policy is missing from {}, but this checkout claims to have it ({}). \
             The {} guards that assert its content ({}) all skip silently without it, so this \
             run says nothing about the document a CST lab reads. Fix the path, or set \
             OXICRYPT_SECURITY_POLICY_OPTIONAL=1 to accept the loss. See \
             docs/security-policy/README.md.",
            path.display(),
            if env_set {
                "$OXICRYPT_SECURITY_POLICY is set"
            } else {
                "the sibling clone directory exists"
            },
            GUARDED.len(),
            GUARDED.join(", ")
        );
        eprintln!(
            "NOTE: the Security Policy was not found at {}. It is withheld from this repository \
             (docs/security-policy/README.md), so this is expected in an ordinary clone. The {} \
             guards asserting its content did not run; this run is not evidence about that \
             document.",
            path.display(),
            GUARDED.len()
        );
    }

    /// The Security Policy must not reappear in the public tree.
    ///
    /// The inverse of every other check here: those assert a document says what
    /// the code does, this asserts a document is absent. An accidental `cp` back
    /// into the tree is otherwise invisible until it is published, and
    /// publication is the one direction that cannot be undone.
    ///
    /// Two detectors, and the limit of both is stated rather than implied. The
    /// file-name sweep catches a copy restored at any path; the phrase sweep
    /// catches one restored under a different name. A copy that was *reflowed*
    /// as it was moved evades both — this guard is a backstop against accident,
    /// not an adversary. It also says nothing about git history; the document
    /// was excised from it, so only a new commit can reintroduce it.
    #[test]
    fn the_security_policy_is_not_in_the_public_tree() {
        /// A phrase the policy states on one line and nothing else in this tree
        /// does. Already present in this file (it is the clause
        /// `alpha_means_the_same_thing_in_the_policy_and_the_crate_doc` pins),
        /// so using it as a detector publishes nothing that was not already
        /// here. `health.rs` carries the same clause wrapped across `///` lines,
        /// which a literal scan does not match — deliberately, since markdown
        /// would not wrap it.
        const POLICY_PHRASE: &str =
            "the probability that a healthy source producing exactly its claimed min-entropy H";
        /// The files legitimately carrying the phrase literally: this guard, and
        /// the `pre-push` hook that duplicates it for pushes this test does not
        /// run on. Both are detectors, not policy prose. Kept as an exact
        /// expected set rather than a skip list — see the assertion below.
        const PHRASE_EXEMPT: [&str; 2] =
            ["scripts/git-hooks/pre-push", "tools/doc-guard/src/lib.rs"];

        // `vendor/` is NOT skipped. It is tracked, committed content that ships
        // on the public flip — unlike `target/`, which is build output. A copy
        // landing there would be published like any other.
        fn walk(
            dir: &Path,
            root: &Path,
            named: &mut Vec<String>,
            phrased: &mut Vec<String>,
            unreadable: &mut Vec<String>,
        ) {
            let rel_of = |p: &Path| p.strip_prefix(root).unwrap_or(p).display().to_string();
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(e) => {
                    // Never silent. An unreadable directory contributes nothing
                    // to either detector, which is the same clean-looking result
                    // as containment holding.
                    unreadable.push(format!("{} ({e})", rel_of(dir)));
                    return;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name == ".git" || name == "target" {
                    continue;
                }
                if path.is_dir() {
                    walk(&path, root, named, phrased, unreadable);
                    continue;
                }
                let rel = rel_of(&path);
                if WITHHELD_FILES.iter().any(|w| *w == name) {
                    named.push(rel.clone());
                }
                // Read every file, exempting nothing here: the exemption is an
                // expected-set assertion on the result, so that a walk which
                // reaches no files cannot look like a clean one.
                match fs::read(&path) {
                    Ok(bytes) => {
                        if String::from_utf8_lossy(&bytes).contains(POLICY_PHRASE) {
                            phrased.push(rel);
                        }
                    }
                    Err(e) => unreadable.push(format!("{rel} ({e})")),
                }
            }
        }

        let root = repo_root();
        let mut named = Vec::new();
        let mut phrased = Vec::new();
        let mut unreadable = Vec::new();
        walk(&root, &root, &mut named, &mut phrased, &mut unreadable);
        phrased.sort(); // readdir order is not stable across filesystems

        // Positive control — and it must be a property of THE WALK, not a
        // parallel read. A control that reads the exempt file independently
        // still passes when the walk itself reads nothing, so the expected set
        // is asserted against the walk's OWN output. A walk that read nothing
        // fails; so does a reworded phrase; so does one file too many.
        let expected: Vec<String> = PHRASE_EXEMPT.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            phrased, expected,
            "the phrase sweep must find exactly the files that legitimately carry the detector \
             phrase — the guards themselves — and nothing else. Anything EXTRA is Security \
             Policy prose in the public tree; move it back to the private policy repository. \
             Anything MISSING means the sweep is broken (a reworded phrase, a renamed guard, or \
             a walk reaching no files), and a broken sweep reports containment holding."
        );
        assert!(
            named.is_empty(),
            "these files are withheld from this repository ({WITHHELD_FILES:?}), but one is \
             present: {named:?}. If this is the real document, remove it — it belongs in the \
             private policy repository. See docs/security-policy/README.md."
        );
        assert!(
            unreadable.is_empty(),
            "these paths could not be read, so neither detector examined them and the sweep's \
             clean result does not cover them: {unreadable:?}"
        );
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
            UNSAFE_EXCEPTIONS.iter().map(ToString::to_string).collect();
        assert_eq!(
            exceptions, declared,
            "in-boundary crates without #![forbid(unsafe_code)] no longer match the declared \
             unsafe-exception set — update security-policy.md §9.2, AGENTS.md, and this guard \
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

    // ----- claim-versus-code: ISC-125, the α parameter (#157) -----
    //
    // A group of criteria are satisfied by a sentence in the policy and by
    // nothing else. A probe can confirm the sentence is present, but nothing
    // detects when the code drifts away from what the sentence asserts — the
    // claim and its enforcement are separate, and only the claim is checked.
    //
    // The guards below compare the two statements directly, so a policy
    // sentence and a crate doc that describe α differently cannot both pass.

    /// The integer ASSIGNED on the line containing `needle`.
    ///
    /// Deliberately not "the last digit run on the line": a trailing comment
    /// (`exp: 40 }; // was 30`) would then parse 30, and the guard would assert
    /// against a value nobody wrote — silently, because the mis-parsed value is
    /// the plausible old one. The comment is stripped first, only the text AFTER
    /// the needle is considered, and finding anything other than exactly one
    /// integer there is a failure rather than a guess.
    fn assigned_u32(src: &str, needle: &str) -> u32 {
        let line = src
            .lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no line containing {needle:?}"));
        let code = line.split("//").next().unwrap_or(line);
        let rhs = code
            .split_once(needle)
            .unwrap_or_else(|| panic!("needle vanished from {line:?}"))
            .1;
        let runs: Vec<String> = rhs
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            runs.len(),
            1,
            "expected exactly one integer after {needle:?} on {line:?}, found {runs:?} — \
             refusing to guess which one the code uses"
        );
        runs[0].parse().expect("integer")
    }

    /// Doc-comment markers stripped and whitespace collapsed.
    ///
    /// A claim wrapped across `///` lines is invisible to a literal `contains`,
    /// and rustfmt rewrapping a line would silently exempt it from the check —
    /// the same shape as a guard that parses its own source line-by-line and
    /// stops matching when the declaration moves. Comparing normalised text
    /// makes the assertion about the sentence, not its line breaks.
    fn normalized(text: &str) -> String {
        let stripped: String = text
            .lines()
            .map(|l| {
                let t = l.trim_start();
                t.strip_prefix("//!")
                    .or_else(|| t.strip_prefix("///"))
                    .or_else(|| t.strip_prefix("//"))
                    .unwrap_or(l)
            })
            .collect::<Vec<_>>()
            .join(" ");
        stripped.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The paragraph of `doc` containing `marker`.
    ///
    /// Claims must be asserted against CURRENT-STATE prose. This crate's module
    /// docs say frozen history — dated decision rows, changelog entries — is
    /// deliberately not checked, but a bare `policy.contains("2⁻²⁰")` is
    /// satisfied by any occurrence, including ones inside dated decision
    /// rows. Deleting the live sentence would then still pass.
    fn paragraph_containing<'a>(doc: &'a str, marker: &str) -> &'a str {
        doc.split("\n\n")
            .find(|p| p.contains(marker))
            .unwrap_or_else(|| panic!("no paragraph containing {marker:?}"))
    }

    /// ISC-125, the claim-versus-CODE half: α's default and permitted range are
    /// recomputed from the source and asserted against the policy's current-state
    /// paragraph. Changing `Alpha::DEFAULT` without touching the policy fails
    /// here rather than silently making the document wrong.
    #[test]
    fn policy_states_the_alpha_values_the_code_implements() {
        let Some(policy) = read_policy() else {
            skip_without_policy("policy_states_the_alpha_values_the_code_implements");
            return;
        };
        let health = read_doc("crates/oxicrypt-entropy/src/health.rs");
        let spec = read_doc("crates/oxicrypt-entropy/src/sp800_90b.rs");
        let claim_para = paragraph_containing(&policy, "cutoff-generating parameter");

        let default_exp = assigned_u32(&health, "pub const DEFAULT: Self = Self { exp:");
        let min_exp = assigned_u32(
            &spec,
            "pub const CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN: u32 =",
        );
        let max_exp = assigned_u32(
            &spec,
            "pub const CONTINUOUS_ALPHA_EXP_RECOMMENDED_MAX: u32 =",
        );

        // Plausibility, without restating the range this test exists to read from
        // disk: a hardcoded `20..=40` here would fail on a legitimate spec change
        // at the guard rather than at the claim.
        // Bound all three, not just their ordering. A mis-parsed `min_exp` of 3
        // ordered below max would otherwise sail through, and 2⁻³ is a security
        // parameter nobody intends. 64 is a generous ceiling on any α exponent a
        // spec revision could plausibly recommend — wide enough not to fight a
        // legitimate change, narrow enough to catch a parse that lost a digit.
        assert!(
            (20..=64).contains(&min_exp)
                && (min_exp..=64).contains(&max_exp)
                && (min_exp..=max_exp).contains(&default_exp),
            "parsed implausible α constants: default={default_exp}, range={min_exp}..={max_exp}"
        );

        let superscript = |n: u32| -> String {
            n.to_string()
                .chars()
                .map(|c| match c {
                    '0' => '⁰',
                    '1' => '¹',
                    '2' => '²',
                    '3' => '³',
                    '4' => '⁴',
                    '5' => '⁵',
                    '6' => '⁶',
                    '7' => '⁷',
                    '8' => '⁸',
                    '9' => '⁹',
                    other => other,
                })
                .collect()
        };

        // A bare `contains` is prefix-matchable: "2⁻³" is a substring of "2⁻³⁰",
        // so a code change to exp 3 would be "found" in a policy that says 30.
        // Require the match to end at a non-superscript-digit boundary.
        let states = |hay: &str, needle: &str| -> bool {
            hay.match_indices(needle).any(|(i, _)| {
                let rest = &hay[i.saturating_add(needle.len())..];
                rest.chars()
                    .next()
                    .is_none_or(|c| !"⁰¹²³⁴⁵⁶⁷⁸⁹".contains(c))
            })
        };

        let default_claim = format!("α = 2⁻{}", superscript(default_exp));
        assert!(
            states(claim_para, &default_claim),
            "the policy's α paragraph does not state the default the code implements \
             ({default_claim:?}); Alpha::DEFAULT is exp={default_exp}"
        );
        let min_claim = format!("2⁻{}", superscript(min_exp));
        assert!(
            states(claim_para, &min_claim),
            "the policy's α paragraph does not state the recommended minimum the code \
             enforces ({min_claim:?}); CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN is {min_exp}"
        );

        // The range's upper bound is asserted against the CRATE DOC only: the
        // policy does not state it anywhere, and inventing a policy sentence to
        // assert against would be the guard writing its own answer.
        let range_claim = format!("{min_exp}..={max_exp}");
        assert!(
            health.contains(&range_claim),
            "the crate doc no longer states the permitted α range {range_claim:?} that \
             CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN/MAX define"
        );
    }

    /// ISC-125, the meaning half. The policy draws a distinction — α is the
    /// cutoff-generating parameter, NOT the observed false-positive rate — and
    /// the crate doc must carry it rather than the reading the policy rules out.
    ///
    /// Asserted on BOTH surfaces, so drift in either direction fails; one surface
    /// alone would be a sentence matching itself. The whole clause is pinned
    /// rather than two fragments, and the ruled-out reading is asserted ABSENT as
    /// a standalone claim — a doc can contain both fragments while asserting the
    /// opposite, so fragment-presence alone would accept a contradiction.
    #[test]
    fn alpha_means_the_same_thing_in_the_policy_and_the_crate_doc() {
        /// The distinction itself, as the policy states it.
        const CLAUSE: &str = "the probability that a healthy source producing exactly its claimed min-entropy H \
             trips the test";
        /// The reading the policy explicitly rules out. Present as a bare
        /// description of α, it asserts what the policy denies.
        const RULED_OUT: &str = "False-positive probability for the continuous health tests";

        let Some(policy) = read_policy() else {
            skip_without_policy("alpha_means_the_same_thing_in_the_policy_and_the_crate_doc");
            return;
        };
        let health = read_doc("crates/oxicrypt-entropy/src/health.rs");
        let claim_para = paragraph_containing(&policy, "cutoff-generating parameter");

        assert!(
            normalized(claim_para).contains("not the observed false-positive rate"),
            "the policy's α paragraph no longer rules out the false-positive reading"
        );
        let claim_norm = normalized(claim_para);
        let health_norm = normalized(&health);
        assert!(
            claim_norm.contains(CLAUSE),
            "the policy no longer defines α as {CLAUSE:?}"
        );
        assert!(
            health_norm.contains("cutoff-generating") && health_norm.contains(CLAUSE),
            "crates/oxicrypt-entropy/src/health.rs no longer carries the ISC-125 α \
             distinction. The policy says α is the cutoff-generating parameter — {CLAUSE} — \
             and NOT the observed false-positive rate. Update both surfaces together."
        );
        assert!(
            !health_norm.contains(RULED_OUT),
            "crates/oxicrypt-entropy/src/health.rs describes α as {RULED_OUT:?}, the reading \
             the policy explicitly rules out"
        );
    }

    /// ISC-125 across **every** surface that documents α, not just the two the
    /// original divergence named.
    ///
    /// The ruled-out phrasing is denied repo-wide rather than corrected per
    /// file. A criterion reported as fixed while its own defect persists one
    /// file away is the thing this whole check family exists to prevent.
    #[test]
    fn no_source_surface_calls_alpha_a_false_positive_probability() {
        /// The ruled-out reading. The Security Policy says α is the
        /// cutoff-generating parameter and NOT the observed false-positive rate;
        /// any doc describing it as a false-positive probability asserts what the
        /// policy denies.
        const RULED_OUT: &str = "false-positive probability";

        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        for krate in workspace_crates() {
            let src = repo_root().join("crates").join(&krate).join("src");
            let Ok(entries) = fs::read_dir(&src) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                scanned = scanned.saturating_add(1);
                for (i, line) in text.lines().enumerate() {
                    // The one legitimate use is the sentence that names the
                    // reading in order to rule it out.
                    if line.to_lowercase().contains(RULED_OUT)
                        && !line.contains("would assert the reading")
                    {
                        offenders.push(format!(
                            "{krate}/src/{}:{}",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            i.saturating_add(1)
                        ));
                    }
                }
            }
        }

        // Positive control: a scan that read nothing would report clean.
        assert!(
            scanned > 20,
            "scanned only {scanned} source files — the sweep is not reaching the workspace"
        );
        assert!(
            offenders.is_empty(),
            "these surfaces describe α as a {RULED_OUT:?}, the reading the Security Policy \
             explicitly rules out (ISC-125). α is the cutoff-generating parameter — the \
             probability that a healthy source at exactly its claimed H trips the test — not \
             the observed false-positive rate:\n    {}",
            offenders.join("\n    ")
        );
    }

    // ----- citation-presence: the mechanism behind #158 (#157 family 2) -----
    //
    // Several criteria assert conformance to a specific normative resolution.
    // The claim's entire content is "we satisfy resolution X" — so if X is never
    // named in any document here, a reviewer cannot check the claim against the
    // resolution and the criterion cannot be falsified.
    //
    // WHICH resolutions the criteria should name is a normative judgment tracked
    // in #158, not a code change. This is only the mechanism that stops the set
    // growing, and it makes the current gap visible instead of leaving it to be
    // rediscovered.

    /// Resolutions cited by a criterion that are, as of #158, named nowhere in
    /// the repository. Listed rather than silently tolerated: the assertion below
    /// requires this set to be EXACT, so citing one of these fails the test until
    /// it is removed here — the list cannot quietly become permanent.
    ///
    /// `D.K R15` is cited by ISC-125, the criterion whose α claim the guards
    /// above assert. `D.K R1` is cited by ISC-123 in longhand
    /// ("IG D.K Resolution-1"): the parser normalises that form, which is one
    /// reflow away from a silent false negative.
    const KNOWN_UNCITED: &[&str] = &["D.J AC6", "D.K R1", "D.K R15", "D.K R22", "D.K R5"];

    /// How many distinct resolutions the criteria cite. Pinned rather than
    /// bounded: a threshold is cleared by a deletion, and a citation silently
    /// disappearing is one of the two failures this guard exists to catch.
    const EXPECTED_CITATIONS: usize = 7;

    /// Every `<letter>.<letter> R<n>` / `AC<n>` resolution cited in the ISA.
    ///
    /// The input is normalised first, because the shorthand is not the only
    /// form in use: ISC-123 cites "IG D.K Resolution-1" in longhand, whose
    /// token carries no digit. A comma or extra spacing between the section and
    /// the resolution is tolerated for the same reason: each is one reflow away
    /// from becoming a silent false negative.
    fn cited_resolutions(isa: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let normalised = isa
            .replace("Resolution-", "R")
            .replace("Resolution ", "R")
            .replace("Resolution", "R");
        let isa = normalised.replace(", R", " R").replace(",  R", " R");
        let isa = isa.as_str();
        for line in isa.lines() {
            let bytes: Vec<char> = line.chars().collect();
            for (i, w) in bytes.windows(3).enumerate() {
                // Shape: `X.Y ` where both are uppercase ASCII letters.
                if w[0].is_ascii_uppercase() && w[1] == '.' && w[2].is_ascii_uppercase() {
                    let rest: String = bytes.iter().skip(i.saturating_add(3)).collect();
                    let tail = rest.trim_start_matches(' ');
                    if tail.len() == rest.len() {
                        continue; // section and token must be separated
                    }
                    let token: String = tail
                        .chars()
                        .take_while(char::is_ascii_alphanumeric)
                        .collect();
                    let is_res = (token.starts_with('R') || token.starts_with("AC"))
                        && token.len() > 1
                        && token
                            .trim_start_matches(|c: char| c.is_ascii_alphabetic())
                            .chars()
                            .all(|c| c.is_ascii_digit())
                        && token.chars().any(|c| c.is_ascii_digit());
                    if is_res {
                        out.insert(format!("{}.{} {token}", w[0], w[2]));
                    }
                }
            }
        }
        out
    }

    /// Every `.rs` file under `dir`, recursively.
    fn collect_rs(dir: &Path, out: &mut String) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(t) = fs::read_to_string(&path)
            {
                out.push_str(&t);
            }
        }
    }

    /// A criterion citing a normative resolution must name it somewhere a
    /// reviewer can reach: the Security Policy, or a source file.
    #[test]
    fn every_cited_resolution_is_named_somewhere_a_reviewer_can_reach() {
        // Skipped wholesale rather than split. The parser fixture below is the
        // positive control FOR the unresolved-set assertion, and a control that
        // ran while the thing it controls did not would report a health this
        // guard had not established.
        let Some(policy) = read_policy() else {
            skip_without_policy("every_cited_resolution_is_named_somewhere_a_reviewer_can_reach");
            return;
        };
        let isa = read_doc("ISA.md");
        let cited = cited_resolutions(&isa);

        // Positive control on the extractor's SHAPE, against a synthetic fixture
        // rather than the live ISA. Asserting only "it matched something real"
        // cannot detect narrowing: every citation in the ISA today is `D.J`/`D.K`,
        // so restricting the parser to `D` would keep the live count identical
        // while making every other resolution family permanently invisible.
        let probe = cited_resolutions(
            "- [ ] X: per IG A.B R1 and Z.Y AC12 and D.K Resolution-7, but not D.KR5 or D.K Rx",
        );
        for expect in ["A.B R1", "Z.Y AC12", "D.K R7"] {
            assert!(
                probe.contains(expect),
                "citation parser missed {expect:?} in the shape fixture: {probe:?}"
            );
        }
        for reject in ["D.K R5", "D.K Rx"] {
            assert!(
                !probe.contains(reject),
                "citation parser accepted the near-miss {reject:?}: {probe:?}"
            );
        }

        // And the live extraction is pinned exactly, not by a threshold that one
        // deletion clears. A moving number is the whole point of this guard.
        assert_eq!(
            cited.len(),
            EXPECTED_CITATIONS,
            "the set of resolutions cited by criteria changed: {cited:?}. If a criterion \
             gained or lost a citation, update EXPECTED_CITATIONS and KNOWN_UNCITED together."
        );

        // Source text, so a resolution argued in a crate doc counts as named.
        // Recursive: a non-recursive read misses `src/bin/*.rs`.
        //
        // `tools/` is deliberately NOT in this corpus, and the exclusion is
        // load-bearing rather than incidental: this guard's own source names most
        // of the resolutions it checks, so including it would let every citation
        // resolve against the guard's own comments — a check certifying itself.
        let mut sources = String::new();
        for krate in workspace_crates() {
            collect_rs(
                &repo_root().join("crates").join(&krate).join("src"),
                &mut sources,
            );
        }

        // Boundary-checked, not a bare `contains`: "D.K R1" is a substring of
        // "D.K R14", so a single-digit resolution would false-PASS off an
        // unrelated one — turning a silently-missed citation into a silently
        // resolved one, which is worse. Same hazard as `2⁻³` inside `2⁻³⁰`.
        let names = |hay: &str, needle: &str| -> bool {
            hay.match_indices(needle).any(|(i, _)| {
                let rest = &hay[i.saturating_add(needle.len())..];
                rest.chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_alphanumeric())
            })
        };
        // The source half of the corpus resolves nothing today — every citation
        // that resolves does so from the policy — so without this it could be
        // permanently empty (a renamed `src`, a swallowed read error) and no
        // assertion would notice half the stated corpus had gone inert.
        assert!(
            sources.contains("SP 800-90B"),
            "the crate-source corpus is empty or unreadable ({} bytes) — half the \
             \"policy or a source file\" claim would be silently inert",
            sources.len()
        );

        let unresolved: BTreeSet<String> = cited
            .iter()
            .filter(|r| !names(&policy, r) && !names(&sources, r))
            .cloned()
            .collect();
        let known: BTreeSet<String> = KNOWN_UNCITED.iter().map(|r| (*r).to_owned()).collect();

        let newly_unresolved: Vec<&String> = unresolved.difference(&known).collect();
        assert!(
            newly_unresolved.is_empty(),
            "criteria cite normative resolutions that are named nowhere in this repository, \
             so the claims cannot be checked against the resolutions: {newly_unresolved:?}. \
             Either cite them in the Security Policy or amend the criteria (see #158)."
        );

        // The allow-list must be exact, and the two ways an entry can go stale are
        // reported separately — they call for opposite actions, and a single
        // message would state something false for one of them. Telling a
        // contributor a resolution is "now cited" when they in fact DELETED the
        // citation is the reverse of what happened, on exactly the remedy the
        // forward message recommends.
        let no_longer_cited: Vec<&String> = known.iter().filter(|r| !cited.contains(*r)).collect();
        assert!(
            no_longer_cited.is_empty(),
            "no criterion cites these any more, so the claim lost its normative content: \
             {no_longer_cited:?}. Confirm that was intended, then remove them from \
             KNOWN_UNCITED."
        );
        let now_resolved: Vec<&String> = known
            .iter()
            .filter(|r| cited.contains(*r) && !unresolved.contains(*r))
            .collect();
        assert!(
            now_resolved.is_empty(),
            "these resolutions are now named in the policy or a source, and must be \
             removed from KNOWN_UNCITED: {now_resolved:?}"
        );
    }

    // ----- banned-phrase: the mechanism behind #159 (#157 family 3) -----
    //
    // The Security Policy ships unresolved drafting text; the census below pins
    // how much, per marker. This is the document a CST lab and a CMVP reviewer
    // read.
    //
    // Resolving them is the content decision in #159, and one of the two blocks
    // on an external answer. This is the mechanism, and it pins the census PER
    // MARKER so the set cannot change shape quietly.

    /// Drafting markers that must not accumulate in current-state policy prose,
    /// with the number of occurrences currently open for each.
    ///
    /// Pinned per marker, not as a total. A bare total is satisfied by
    /// substitution — delete a `TODO`, add a `[design pending]`, and the sum is
    /// unchanged — which is the failure this crate already rejects elsewhere:
    /// `UNSAFE_EXCEPTIONS` exists so a `forbid(unsafe_code)` swap "fails by
    /// name, not just by count". The same standard applies here.
    ///
    /// `[MARK` is in the list because the policy uses a second convention for the
    /// same thing (`**[MARK: …confirm placement with the CST lab…]**`), which a
    /// `TODO`/`pending]` sweep does not see.
    const OPEN_MARKERS: &[(&str, usize)] = &[
        // 7 → 8 when §1.5 gained its vendor-affirmed environments. The new
        // marker is deliberate and is the honest state of that section: an
        // affirmation is relative to a tested environment, and §1.4 does not
        // yet name any, so §1.5 cannot be read on its own until it does. It
        // resolves when §1.4 is filled from the lab submission, and this pin
        // should drop back to 7 in the same change.
        ("TODO", 8),
        ("TBD", 0),
        ("FIXME", 0),
        ("XXX", 0),
        ("pending]", 8),
        ("[MARK", 1),
    ];

    /// A frozen-history line: a row whose first cell is an ISO date.
    ///
    /// This crate deliberately asserts current-state statements only, so a
    /// historical row quoting a past TODO must not trip the check. The shape is
    /// a real date, not "starts with 20" — the looser form also freezes
    /// `| 2048 | RSA legacy | TODO: … |`, and over-exemption is the exploitable
    /// direction: a marker hidden in a skipped row is invisible, while a row
    /// wrongly counted merely fails loudly.
    fn is_frozen_history(line: &str) -> bool {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix('|') else {
            return false;
        };
        let cell = rest.trim_start();
        let bytes: Vec<char> = cell.chars().take(10).collect();
        bytes.len() == 10
            && bytes[4] == '-'
            && bytes[7] == '-'
            && bytes
                .iter()
                .enumerate()
                .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    }

    /// The line with inline code spans removed.
    ///
    /// The policy's front matter documents what a `TODO` marker means, and that
    /// sentence must not count as an unresolved item — but skipping the whole
    /// LINE is far too broad. It exempts any line that merely cites the
    /// convention, anywhere in a 3,500-line document, including the other markers
    /// on it. Stripping the backticked span keeps the documentation exempt while
    /// leaving every bare marker on the same line visible.
    fn without_code_spans(line: &str) -> String {
        let mut out = String::new();
        let mut in_span = false;
        for c in line.chars() {
            if c == '`' {
                in_span = !in_span;
            } else if !in_span {
                out.push(c);
            }
        }
        out
    }

    /// The policy must not accumulate unresolved drafting text.
    #[test]
    fn policy_carries_no_new_unresolved_drafting_markers() {
        let Some(policy) = read_policy() else {
            skip_without_policy("policy_carries_no_new_unresolved_drafting_markers");
            return;
        };

        // Positive control on BOTH carve-outs, against a synthetic fixture rather
        // than the live document. Asserting only that the frozen predicate
        // "matched a lot of rows" cannot detect mis-scoping, so the predicate is
        // exercised on inputs that must and must not match.
        assert!(
            is_frozen_history("| 2026-07-03 | draft-N | resolved an earlier TODO |"),
            "frozen-history predicate no longer recognises a dated change-log row"
        );
        assert!(
            !is_frozen_history("| 2048 | RSA legacy | TODO: decide whether to claim this |"),
            "frozen-history predicate freezes a non-date table row — a marker hidden \
             there would be invisible"
        );
        assert!(
            !is_frozen_history("Ordinary prose mentioning 2026-07-03 and a TODO."),
            "frozen-history predicate matches prose"
        );
        assert_eq!(
            without_code_spans("the `TODO` convention; TODO: name the libc"),
            "the  convention; TODO: name the libc",
            "code-span stripping must exempt the documented convention while leaving \
             a bare marker on the same line visible"
        );

        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut sites: Vec<String> = Vec::new();
        for (i, line) in policy.lines().enumerate() {
            if is_frozen_history(line) {
                continue;
            }
            let scanned = without_code_spans(line);
            for (marker, _) in OPEN_MARKERS {
                // Every occurrence, not one per line: a line already carrying one
                // marker would otherwise make a second marker on it free.
                let n = scanned.matches(marker).count();
                if n > 0 {
                    *counts.entry(marker).or_insert(0) += n;
                    sites.push(format!("line {} [{marker}] x{n}", i.saturating_add(1)));
                }
            }
        }

        for (marker, expected) in OPEN_MARKERS {
            let found = counts.get(marker).copied().unwrap_or(0);
            assert_eq!(
                found,
                *expected,
                "the policy's `{marker}` census changed: found {found}, pinned {expected}.\n  \
                 An INCREASE is a regression — this document is read by a CST lab.\n  \
                 A DECREASE is only progress if the item was resolved: name the issue or \
                 decision that closed it when you lower the pin. Rewording a marker into \
                 unmarked prose, or moving it into a dated table row, lowers this number \
                 without resolving anything — and the item then becomes invisible to this \
                 check permanently. See #159.\n  Sites:\n    {}",
                sites.join("\n    ")
            );
        }
    }

    #[test]
    fn policy_states_the_as_built_accounting() {
        let Some(policy) = read_policy() else {
            skip_without_policy("policy_states_the_as_built_accounting");
            return;
        };
        let a = accounting();

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
            "{} carry `#![forbid(unsafe_code)]`, {} are the readily auditable exception crates",
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
                "policy: unsafe exception `{exception}` not named"
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
            "The {} readily auditable in-boundary exceptions",
            word(a.exceptions.len())
        );
        assert!(
            agents.contains(&exceptions),
            "AGENTS.md: {exceptions:?} missing"
        );
        for exception in &a.exceptions {
            assert!(
                agents.contains(&format!("`{exception}`")),
                "AGENTS.md: unsafe exception `{exception}` not named"
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
    /// A citation that resolves against the wrong file reaches an unrelated
    /// criterion with nothing to signal the mismatch, so resolution is pinned
    /// to `ISA.md` alone.
    ///
    /// Files are read as bytes and scanned lossily rather than as UTF-8 text:
    /// binary content can carry citations, and a scan that skips it reports
    /// clean.
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
        // Criterion IDs must be bare `- [ ] ISC-N:`; a bolded ID makes
        // downstream criterion parsers return nothing for the whole file,
        // silently. A count threshold does not catch a single bolded line,
        // so assert the shape directly.
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

    // ----- packaging: embedded files must live inside the package -----

    /// The crates that embed the LAMA manifest, each through a symlink in its
    /// own package root. Every one exposes a runtime `--lama` surface, so it
    /// needs the bytes embedded as well as the `[package.metadata.lama]`
    /// registry-discovery URL every crate carries.
    const LAMA_EMBEDDERS: [&str; 4] = ["crates/oxicrypt-ffi", "oxi", "acvp-harness", "esv-harness"];

    /// Every `.rs` file in the workspace, excluding build artefacts.
    fn workspace_rs_files() -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if path.is_dir() {
                    if !matches!(name.as_ref(), "target" | ".git") {
                        walk(&path, out);
                    }
                } else if name.ends_with(".rs") {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(&repo_root(), &mut out);
        out.sort();
        out
    }

    /// The package root owning `file` — the nearest ancestor with a Cargo.toml.
    fn owning_package_root(file: &Path) -> Option<PathBuf> {
        let mut dir = file.parent()?;
        let root = repo_root();
        loop {
            if dir.join("Cargo.toml").is_file() {
                return Some(dir.to_path_buf());
            }
            if dir == root {
                return None;
            }
            dir = dir.parent()?;
        }
    }

    /// `include_str!` and `include_bytes!` embed a file at compile time, and
    /// `cargo package` only ships what lies inside the package root. A path
    /// reaching outside it compiles here and fails for every consumer of the
    /// published crate — and because a published version is immutable, that
    /// failure cannot be corrected in place.
    ///
    /// The rule is deliberately unconditional rather than scoped to the crates
    /// currently destined for crates.io. A roster-conditional rule changes
    /// meaning when a `publish` flag moves.
    #[test]
    fn embedded_files_live_inside_their_package_root() {
        let files = workspace_rs_files();
        assert!(
            files.len() > 100,
            "walked only {} .rs files — the walk is broken and a clean result would mean nothing",
            files.len()
        );

        let mut escapes = Vec::new();
        let mut embeds = 0usize;
        for file in &files {
            let src = fs::read_to_string(file).unwrap_or_default();
            for (macro_name, rest) in src
                .match_indices("include_str!")
                .map(|(i, _)| ("include_str!", &src[i..]))
                .chain(
                    src.match_indices("include_bytes!")
                        .map(|(i, _)| ("include_bytes!", &src[i..])),
                )
            {
                let Some(open) = rest.find('"') else { continue };
                let Some(close) = rest[open + 1..].find('"') else {
                    continue;
                };
                let rel = &rest[open + 1..open + 1 + close];
                embeds += 1;
                let Some(pkg_root) = owning_package_root(file) else {
                    continue;
                };
                // Resolve textually: the target may not exist on a checkout
                // without symlink support, and that case belongs to the other
                // test rather than being silently skipped here.
                let mut resolved = file.parent().unwrap().to_path_buf();
                for part in Path::new(rel).components() {
                    match part {
                        std::path::Component::ParentDir => {
                            resolved.pop();
                        }
                        std::path::Component::Normal(p) => resolved.push(p),
                        _ => {}
                    }
                }
                if !resolved.starts_with(&pkg_root) {
                    escapes.push(format!(
                        "{}: {macro_name}(\"{rel}\") escapes {}",
                        file.strip_prefix(repo_root()).unwrap().display(),
                        pkg_root.strip_prefix(repo_root()).unwrap().display()
                    ));
                }
            }
        }
        assert!(
            embeds > 0,
            "found no include_str!/include_bytes! calls at all — the scan is broken"
        );
        assert!(
            escapes.is_empty(),
            "these embeds reach outside their package root, so `cargo package` ships a crate that \
             cannot build. Put a symlink in the package root and embed through it:\n  {}",
            escapes.join("\n  ")
        );
    }

    /// The embedded manifests must be the manifest.
    ///
    /// Each embedder reaches the canonical `docs/llm-api-manifest/llm-api.yaml`
    /// through a symlink in its own package root. Git on Windows checks a
    /// symlink out as a plain text file containing the target path unless
    /// `core.symlinks` is enabled — so `include_str!` would embed the string
    /// `../docs/llm-api-manifest/llm-api.yaml` as the manifest, and
    /// `cargo package` would publish that, immutably, with no error anywhere.
    /// Comparing bytes against the canonical file is what makes that loud.
    #[test]
    fn embedded_lama_manifests_are_the_manifest() {
        let canonical = read_doc("docs/llm-api-manifest/llm-api.yaml");
        assert!(
            canonical.starts_with("lama:"),
            "the canonical manifest does not start with `lama:` — this test's own reference is \
             wrong, so every comparison below is meaningless"
        );

        for crate_dir in LAMA_EMBEDDERS {
            let path = repo_root().join(crate_dir).join("llm-api.yaml");
            let embedded = fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "{crate_dir}/llm-api.yaml is unreadable ({e}). It should be a symlink to \
                     docs/llm-api-manifest/llm-api.yaml."
                )
            });
            assert!(
                embedded == canonical,
                "{crate_dir}/llm-api.yaml differs from the canonical manifest ({} bytes vs {}). \
                 On a checkout without symlink support this file holds the target path instead of \
                 the manifest, and publishing it would embed that string.",
                embedded.len(),
                canonical.len()
            );
        }
    }

    /// Crates whose keygen primitives hold temporary SSP material on the
    /// stack, and must clear it through the volatile path.
    const VOLATILE_SCRATCH_CRATES: [&str; 3] = [
        "crates/oxicrypt-ecdh",
        "crates/oxicrypt-dh",
        "crates/oxicrypt-ecdsa",
    ];

    /// FIPS 140-3 IG §7.9.7 AS09.32 requires temporary SSPs to be zeroised
    /// when they are no longer needed. Keygen scratch — rejection-sampler
    /// buffers, pairwise-consistency-test shared secrets — is temporary SSP
    /// material, and `fill(0)` on a local that is dead afterwards is an
    /// ordinary store the compiler is free to eliminate. The clear has to go
    /// through `oxicrypt-zeroize`'s `write_volatile` path.
    ///
    /// This is deliberately a source check rather than a behavioural one.
    /// Non-elision is a guarantee of `write_volatile`, not something a test
    /// can observe: reading the stack back would run under `opt-level=0`,
    /// where no dead-store elimination happens at all, so it would pass just
    /// as happily against the elidable version. A probe that cannot fail on
    /// the broken input is not a probe.
    ///
    /// Both halves matter. Banning `fill(0)` alone would be satisfied by
    /// deleting the clears outright, so each crate must also still call the
    /// volatile helper.
    #[test]
    fn keygen_scratch_is_cleared_through_the_volatile_path() {
        let root = repo_root();
        let mut elidable = Vec::new();
        for file in workspace_rs_files() {
            let Some(pkg) = owning_package_root(&file) else {
                continue;
            };
            if !pkg.starts_with(root.join("crates")) {
                continue;
            }
            let Ok(src) = fs::read_to_string(&file) else {
                continue;
            };
            for (i, line) in src.lines().enumerate() {
                if line.contains(".fill(0)") {
                    elidable.push(format!("{}:{}", file.display(), i + 1));
                }
            }
        }
        assert!(
            elidable.is_empty(),
            "in-boundary crates clear scratch with an elidable `fill(0)`; \
             use `oxicrypt_zeroize::zeroize` instead: {elidable:?}"
        );

        for crate_dir in VOLATILE_SCRATCH_CRATES {
            let dir = root.join(crate_dir).join("src");
            let calls: usize = workspace_rs_files()
                .iter()
                .filter(|f| f.starts_with(&dir))
                .filter_map(|f| fs::read_to_string(f).ok())
                .map(|s| s.matches("oxicrypt_zeroize::zeroize(").count())
                .sum();
            assert!(
                calls > 0,
                "{crate_dir} no longer clears its keygen scratch through the \
                 volatile path (AS09.32)"
            );
        }
    }
    // ----- reading the source without reading its commentary -----

    /// `src` with every `//` line comment removed.
    ///
    /// Every assertion below that pins a line of code must run against code. A
    /// bare `contains` over a source file is satisfied by a comment quoting the
    /// text it looks for, so `// was: <the arm this check pins>` left behind by
    /// the very edit the check exists to catch would keep it green. Neither of
    /// the regions this is applied to contains a string literal holding `//`,
    /// which is what makes stripping to end-of-line safe here rather than in
    /// general.
    fn code_only(src: &str) -> String {
        src.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body of the named free function, from its opening line to the first
    /// column-zero `}`.
    fn fn_body(name: &str, signature: &str) -> String {
        let src = read_doc("crates/oxicrypt-module/src/lib.rs");
        let start = src
            .find(signature)
            .unwrap_or_else(|| panic!("{name} is no longer declared as `{signature}`"));
        let rest = &src[start..];
        let end = rest
            .find("\n}\n")
            .unwrap_or_else(|| panic!("{name}'s body is unterminated"));
        rest[..end].to_string()
    }

    // ----- the toolchain versions: two authoritative files, several restatements -----

    /// Files whose Rust-version statements are frozen history rather than
    /// current-state claims, each with the reason it is exempt.
    ///
    /// This crate's module docs say frozen history is deliberately not checked.
    /// `CHANGELOG.md` is the dated-entry case that rule was written for. The
    /// benchmark page is not dated-entry shaped and so needs naming: it records
    /// the compiler a published measurement was taken under, which does not move
    /// when the MSRV moves, and rewriting it to track the MSRV would falsify the
    /// measurement.
    const FROZEN_RUST_VERSION_FILES: [(&str, &str); 2] = [
        (
            "CHANGELOG.md",
            "dated release entries record the MSRV of their release",
        ),
        (
            "docs/entropy-performance.md",
            "records the toolchain a published benchmark was measured under",
        ),
    ];

    /// Files that must contribute at least one Rust-version claim.
    ///
    /// The aggregate floor below catches a sweep that stops reading; it does not
    /// catch one that stops reading *one kind of file*. Dropping `md` from the
    /// extension list leaves the yaml and toml surfaces alone above the floor,
    /// green, with the two documents a newcomer actually reads unchecked — one
    /// of which is the file that was wrong.
    const RUST_VERSION_WITNESSES: [&str; 3] = ["README.md", "docs/building.md", "lama.yaml"];

    /// The markers that introduce a statement about the Rust version. Keying on
    /// these rather than on bare version-shaped numbers is deliberate: the tree
    /// is full of `1.NN` literals that are not toolchain versions at all — the
    /// entropy page's per-bit estimates among them — and a numeric sweep would
    /// need an allowlist long enough to hide a real defect inside it.
    const RUST_VERSION_MARKERS: [&str; 8] = [
        "minimum_toolchain",
        "toolchain",
        "rust-version",
        "Rust ",
        "rust ",
        "rustc ",
        "stable ",
        "MSRV",
    ];

    /// `.rs` files are deliberately not swept, and the cost is stated rather
    /// than hidden: a crate doc-comment saying "requires Rust 1.94" is invisible
    /// here. Sweeping them would read this file's own must-match fixtures —
    /// which contain a deliberately stale `1.94` — as claims about the tree, so
    /// the check would fail on its own test data.
    const SWEPT_EXTENSIONS: [&str; 4] = ["md", "yaml", "yml", "toml"];

    /// The unquoted value assigned to `key`, which must be assigned exactly once.
    ///
    /// Not a TOML parser, and it does not need to be: it is pointed at one key in
    /// one file whose shape is fixed. Requiring a single assignment is what makes
    /// that safe — a second `[package]` section gaining its own `rust-version`
    /// fails here rather than silently returning whichever came first. A trailing
    /// `#` comment is removed before the quotes are stripped, because leaving it
    /// in returns a value that is wrong rather than a parse that fails, and the
    /// build pin is restated nowhere in the tree, so a corrupted channel would
    /// never be contradicted.
    fn toml_value(src: &str, key: &str) -> String {
        let mut hits: Vec<String> = Vec::new();
        for line in src.lines() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix(key) else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim();
            let Some(open) = rest.strip_prefix('"') else {
                continue;
            };
            let Some(value) = open.split('"').next() else {
                continue;
            };
            hits.push(value.to_string());
        }
        assert_eq!(
            hits.len(),
            1,
            "expected exactly one quoted `{key}` assignment, found {}: {hits:?}",
            hits.len()
        );
        let value = hits.remove(0);
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "`{key}` parsed as {value:?}, which is not a version"
        );
        value
    }

    /// A version split into its numeric components.
    ///
    /// String ordering is not version ordering: `"1.100.0" < "1.95"`
    /// lexicographically, so a comparison done on the text would call a healthy
    /// tree broken three releases from now.
    fn version_components(version: &str) -> Vec<u32> {
        version
            .split('.')
            .map(|p| p.parse::<u32>().unwrap_or(u32::MAX))
            .collect()
    }

    /// Whether `claim` states `target` — equal, or a less precise prefix of it.
    ///
    /// A document writing `1.97` for a pin of `1.97.1` is substantively right and
    /// must not be reported stale; `1.94` against `1.95` is neither equal nor a
    /// prefix and is.
    fn version_states(claim: &str, target: &str) -> bool {
        let (c, t) = (version_components(claim), version_components(target));
        !c.is_empty() && c.len() <= t.len() && t.starts_with(&c)
    }

    /// The version token stated shortly after `marker`, if any.
    ///
    /// The token must be *near* the marker. `Rust 1.95`, `minimum_toolchain:
    /// "rust 1.95"`, `rust-version = "1.95"` and `Rust toolchain 1.95` all put
    /// it within twenty characters; widening further would start matching the
    /// next sentence, and a version pulled out of an unrelated clause is worse
    /// than no reading at all because it fails against a value nobody wrote.
    fn version_token_after(hay: &str, marker: &str) -> Option<String> {
        let idx = hay.find(marker)?;
        let rest: Vec<char> = hay[idx.saturating_add(marker.len())..].chars().collect();
        let start = rest.iter().take(20).position(char::is_ascii_digit)?;
        let mut end = start;
        while end < rest.len() && (rest[end].is_ascii_digit() || rest[end] == '.') {
            end = end.saturating_add(1);
        }
        while end > start && rest[end.saturating_sub(1)] == '.' {
            end = end.saturating_sub(1);
        }
        let token: String = rest[start..end].iter().collect();
        // A bare integer is a count, not a version.
        token.contains('.').then_some(token)
    }

    /// Every Rust-version claim made on `line`.
    fn rust_version_claims(line: &str) -> Vec<String> {
        let mut claims = Vec::new();
        for marker in RUST_VERSION_MARKERS {
            let mut cursor = line;
            while let Some(idx) = cursor.find(marker) {
                if let Some(token) = version_token_after(cursor, marker)
                    && !claims.contains(&token)
                {
                    claims.push(token);
                }
                cursor = &cursor[idx.saturating_add(marker.len())..];
            }
        }
        claims
    }

    /// Every documentation and manifest file that could carry a version claim.
    ///
    /// Only `target` and `.git` are skipped. Skipping dot-directories wholesale
    /// would exclude `.github/workflows`, where a pinned toolchain literal is
    /// exactly the drift this exists to find.
    fn docs_and_manifests() -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name == "target" || name == ".git" {
                    continue;
                }
                if path.is_dir() {
                    walk(&path, out);
                } else if path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| SWEPT_EXTENSIONS.contains(&e))
                {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(&repo_root(), &mut out);
        out.sort();
        out
    }

    /// The claim extractor catches the shapes the tree actually uses, and
    /// refuses the ones that would make it fire on prose.
    ///
    /// Without this the sweep below is unfalsifiable: an extractor that returned
    /// nothing would report every file clean, which reads exactly like a tree
    /// with no drift in it.
    #[test]
    fn the_rust_version_extractor_catches_what_it_must() {
        for (line, expected) in [
            ("- **Rust 1.95+** (MSRV enforced in `Cargo.toml`)", "1.95"),
            ("  minimum_toolchain: \"rust 1.95\"", "1.95"),
            ("  minimum_toolchain: rust 1.95", "1.95"),
            ("rust-version = \"1.95\"", "1.95"),
            ("oxicrypt requires **Rust 1.94 or later**.", "1.94"),
            (
                "| Ubuntu 22.04 | x86_64 | stable 1.94+ | Primary CI |",
                "1.94",
            ),
            (
                "| Toolchain | rustc 1.95.0 (2026-04-14), criterion |",
                "1.95.0",
            ),
            ("built with the Rust toolchain 1.95 or newer", "1.95"),
            ("this crate requires rust 1.95", "1.95"),
            ("the MSRV is 1.95 and moves deliberately", "1.95"),
            ("  toolchain: \"1.97.1\"", "1.97.1"),
        ] {
            let claims = rust_version_claims(line);
            assert!(
                claims.contains(&expected.to_string()),
                "extractor missed {expected} in {line:?}; it read {claims:?}"
            );
        }

        // Must NOT be read — the mirror control. Without it the extractor could
        // be widened until it fired on every number in the tree and this test
        // would still pass.
        for line in [
            "the shift is 1.5578 bits per sample",
            "CNSA 1.0 and CNSA 2.0 are both named",
            "TLS 1.2 KDF and TLS 1.3 KDF remain available",
            // A synthetic version, deliberately. A negative fixture carrying the
            // workspace's REAL current version collides with
            // `bump-version.sh`'s surviving-literal guard at every release —
            // the guard greps for the outgoing version across the tree, and a
            // fixture holding it reads as an incomplete bump. The control works
            // identically with a version that can never be ours.
            "version = \"1.2.3\"",
            "inherited via `rust-version.workspace = true`",
            "SP 800-56Cr2 and RFC 8446 §7.1 apply",
        ] {
            assert!(
                rust_version_claims(line).is_empty(),
                "extractor fired on {line:?}: {:?}",
                rust_version_claims(line)
            );
        }

        // Version ordering is numeric, not lexicographic.
        assert!(
            version_states("1.97", "1.97.1"),
            "a less precise claim states its target"
        );
        assert!(!version_states("1.94", "1.95"));
        assert!(
            !version_states("1.9", "1.95"),
            "1.9 is not a prefix of 1.95"
        );
        assert!(
            version_components("1.100.0") > version_components("1.95"),
            "component ordering must survive a three-digit minor"
        );
    }

    /// Every current-state Rust-version statement in the tree names one of the
    /// two values the authoritative files own.
    ///
    /// The MSRV is restated across a dozen documents and manifests and the build
    /// pin in none. Nothing held them in step: `docs/building.md` sat a full
    /// minor version behind the workspace for long enough that following it
    /// produced a build failure the document itself predicted would work.
    #[test]
    fn rust_version_statements_match_the_authoritative_files() {
        let msrv = workspace_msrv();
        let channel = toolchain_channel();
        let root = repo_root();

        assert!(
            version_components(&channel) >= version_components(&msrv),
            "the pinned build toolchain {channel} is below the workspace MSRV {msrv}"
        );

        let mut stale: Vec<String> = Vec::new();
        let mut read = 0usize;
        let mut witnessed: BTreeSet<&str> = BTreeSet::new();
        for path in docs_and_manifests() {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if FROZEN_RUST_VERSION_FILES
                .iter()
                .any(|(frozen, _)| rel == *frozen)
            {
                continue;
            }
            let Ok(src) = fs::read_to_string(&path) else {
                continue;
            };
            for (i, line) in src.lines().enumerate() {
                for claim in rust_version_claims(line) {
                    read = read.saturating_add(1);
                    if let Some(w) = RUST_VERSION_WITNESSES.iter().find(|w| **w == rel) {
                        witnessed.insert(w);
                    }
                    if !version_states(&claim, &msrv) && !version_states(&claim, &channel) {
                        stale.push(format!("{rel}:{} states Rust {claim}", i.saturating_add(1)));
                    }
                }
            }
        }

        // A sweep that read nothing would report a clean tree, and one that read
        // only the manifests would report a clean tree while the prose it exists
        // to check went unread. The floor is set from the measured population —
        // 15 distinct claims across 12 files, counted after de-duplicating the
        // several markers that match the same statement — and the witnesses pin
        // the file *kinds*, because dropping one extension leaves the aggregate
        // above any floor the others can carry.
        assert!(
            read >= 14,
            "the sweep read only {read} distinct Rust-version statements against a measured \
             15 — it is broken, not the tree"
        );
        for witness in RUST_VERSION_WITNESSES {
            assert!(
                witnessed.contains(witness),
                "{witness} contributed no Rust-version statement; the sweep is no longer \
                 reaching it"
            );
        }

        assert!(
            stale.is_empty(),
            "documents state a Rust version that is neither the workspace MSRV \
             ({msrv}) nor the pinned toolchain ({channel}): {stale:?}"
        );
    }

    /// The workspace MSRV — `[workspace.package] rust-version` in the root
    /// `Cargo.toml`. Authoritative; every current-state restatement in the tree
    /// is checked against it.
    fn workspace_msrv() -> String {
        toml_value(&read_doc("Cargo.toml"), "rust-version")
    }

    /// The pinned build toolchain — `channel` in `rust-toolchain.toml`.
    fn toolchain_channel() -> String {
        toml_value(&read_doc("rust-toolchain.toml"), "channel")
    }

    /// The Security Policy defers both toolchain values to the tree instead of
    /// restating them.
    ///
    /// §1.4 says in terms that version literals are deliberately absent from it
    /// so the paragraph cannot drift — and then, in the same paragraph, stated
    /// two of them. A sentence that describes its own discipline is not evidence
    /// that the discipline held.
    ///
    /// The detector reads any dotted literal, so these two paragraphs may not
    /// cite `CNSA 2.0` or `TLS 1.3` either. That is a constraint rather than a
    /// defect: a paragraph whose subject is where toolchain versions live has no
    /// occasion to name a cipher suite, and the alternative — teaching the
    /// detector which dotted numbers are innocent — is the allowlist that hides
    /// the next real one.
    #[test]
    fn policy_defers_the_toolchain_versions_to_the_tree() {
        let Some(policy) = read_policy() else {
            skip_without_policy("policy_defers_the_toolchain_versions_to_the_tree");
            return;
        };

        let deferral = paragraph_containing(&policy, "rust-toolchain.toml");
        assert!(
            deferral.contains("rust-toolchain.toml") && deferral.contains("rust-version"),
            "the toolchain paragraph no longer names both authoritative files"
        );
        assert!(
            deferral.contains("Cargo.toml"),
            "the toolchain paragraph no longer says which file owns the MSRV"
        );

        let claim = paragraph_containing(&policy, "Version literals are deliberately absent");
        for para in [deferral, claim] {
            let literals = version_literals(para);
            assert!(
                literals.is_empty(),
                "the toolchain paragraphs claim to carry no version literal and carry \
                 {literals:?}; the two authoritative files are the only place either \
                 value belongs"
            );
            for restatement in ["edition = \"", "rust-version = \""] {
                assert!(
                    !para.contains(restatement),
                    "the toolchain paragraphs restate `{restatement}...`, which is the \
                     drift this paragraph exists to avoid"
                );
            }
        }
    }

    /// Section references are not version literals, and a detector that could not
    /// tell them apart would fire on every cross-reference in the document.
    #[test]
    fn the_version_literal_detector_catches_what_it_must() {
        for text in [
            "the pin is 1.97.1 today",
            "declares `rust-version = \"1.95\"` in `[workspace.package]`",
            "tested against 1.94 and later",
            // Stated as a must-match rather than a must-miss: see the guard's
            // own docs for why these paragraphs may not cite a suite version.
            "CNSA 2.0 is named in Annex B",
        ] {
            assert!(
                !version_literals(text).is_empty(),
                "detector missed a literal in {text:?}"
            );
        }
        for text in [
            "see §1.4 and §9.2 for detail",
            "stated in §1.4. The pin is the floor",
            "inherited via `edition.workspace = true` / `rust-version.workspace = true`",
            "pinned by `rust-toolchain.toml` at the workspace root",
            "SP 800-38F and RFC 5869 are cited",
        ] {
            assert!(
                version_literals(text).is_empty(),
                "detector fired on {text:?}: {:?}",
                version_literals(text)
            );
        }
    }

    /// Version-shaped literals in `text`, section references removed first.
    ///
    /// A section reference is written `§1.4` and is not a version; a dot only
    /// continues the reference when a digit follows it, so a sentence-ending
    /// period survives. The detector reads dotted runs only — `edition = "2024"`
    /// is undotted and is caught by the separate restatement check above, which
    /// is stated rather than left as a silent gap.
    fn version_literals(text: &str) -> Vec<String> {
        let chars: Vec<char> = strip_section_refs(text).chars().collect();
        let mut found = Vec::new();
        let mut i = 0usize;
        while i < chars.len() {
            if !chars[i].is_ascii_digit() {
                i = i.saturating_add(1);
                continue;
            }
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i = i.saturating_add(1);
            }
            let mut end = i;
            let mut groups = 1usize;
            while groups < 3
                && end.saturating_add(1) < chars.len()
                && chars[end] == '.'
                && chars[end.saturating_add(1)].is_ascii_digit()
            {
                let mut j = end.saturating_add(1);
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j = j.saturating_add(1);
                }
                end = j;
                groups = groups.saturating_add(1);
            }
            if groups >= 2 {
                found.push(chars[start..end].iter().collect());
            }
            i = end.max(i);
        }
        found
    }

    /// `text` with every `§N.N` reference replaced by a space.
    fn strip_section_refs(text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut i = 0usize;
        while i < chars.len() {
            if chars[i] != '§' {
                out.push(chars[i]);
                i = i.saturating_add(1);
                continue;
            }
            i = i.saturating_add(1);
            while i < chars.len() && chars[i].is_ascii_digit() {
                i = i.saturating_add(1);
            }
            while i.saturating_add(1) < chars.len()
                && chars[i] == '.'
                && chars[i.saturating_add(1)].is_ascii_digit()
            {
                i = i.saturating_add(1);
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i = i.saturating_add(1);
                }
            }
            out.push(' ');
        }
        out
    }

    // ----- the algorithm profiles: three predicates, several descriptions -----

    /// The §4.2 abbreviation for each [`AlgorithmProfile`] variant.
    const PROFILE_ABBREVIATIONS: [(&str, &str); 4] = [
        ("U", "Unrestricted"),
        ("C1", "Cnsa1"),
        ("C2", "Cnsa2"),
        ("M", "Migration"),
    ];

    /// §4.2 rows that name a CNSA profile without being profile-gated at all,
    /// with the reason each is exempt. A row here is asserted to still exist, so
    /// the exemption cannot outlive the row it excuses.
    const UNGATED_SERVICE_ROWS: [(&str, &str); 1] = [(
        "Module integrity",
        "the integrity self-test runs before profile enforcement and has no `Service`, \
         so it is available under every profile rather than permitted by one",
    )];

    /// The shortest entry-point token allowed to select candidate services.
    ///
    /// Chosen by measurement, not by taste. At four characters the module
    /// segments `ctr`, `hash` and `hmac` select their whole crate's block —
    /// `oxicrypt_drbg::hash::HashDrbgSha256` pulls in `HashDrbgSha384` — and six
    /// rows are then reported as understating their profiles when they are
    /// correct. At five, both directions of the membership check run clean over
    /// the table as it stands.
    const MIN_ENTRY_TOKEN: usize = 5;

    /// Every `Service` variant, mapped to its owning crate and discriminant.
    ///
    /// The enum groups its variants under `// ----- oxicrypt-name: ... -----`
    /// banners, one per owning crate. The second return value is the number of
    /// variants *seen*, whether or not a banner claimed them, so the caller can
    /// assert the mapping is total rather than assume it: a banner that stops
    /// matching drops every variant beneath it silently, and a shrunken set only
    /// ever makes the checks below more permissive.
    fn service_owning_crates() -> (BTreeMap<String, (String, u32)>, usize) {
        let src = read_doc("crates/oxicrypt-module/src/lib.rs");
        let start = src
            .find("pub enum Service {")
            .expect("`Service` is no longer declared");
        let rest = &src[start..];
        let end = rest
            .find("\n}\n")
            .expect("`Service`'s body is unterminated");
        let mut owner = BTreeMap::new();
        let mut current: Option<String> = None;
        let mut seen = 0usize;
        for line in rest[..end].lines() {
            let t = line.trim();
            if let Some(banner) = t.strip_prefix("// -----") {
                current = banner
                    .trim()
                    .split(':')
                    .next()
                    .map(|c| c.trim().trim_end_matches(" -----").trim().to_string())
                    .filter(|c| c.starts_with("oxicrypt-"));
                continue;
            }
            let Some((name, tail)) = t.split_once(" = ") else {
                continue;
            };
            if !name.starts_with(char::is_uppercase) {
                continue;
            }
            let Ok(discriminant) = tail.trim_end_matches(',').parse::<u32>() else {
                continue;
            };
            seen = seen.saturating_add(1);
            if let Some(crate_name) = current.clone() {
                owner.insert(name.to_string(), (crate_name, discriminant));
            }
        }
        (owner, seen)
    }

    /// The services the named gate permits.
    ///
    /// The gate body is read with its commentary stripped. A gate scanned as raw
    /// text would keep admitting whatever its comments still mention — deleting
    /// `|| is_lms_service(service)` while leaving the LMS comment block above it
    /// would leave 160 services listed as permitted by a gate that refuses every
    /// one of them.
    fn gate_services(name: &str) -> BTreeSet<String> {
        let body = code_only(&fn_body(
            name,
            &format!("const fn {name}(service: Service) -> bool {{"),
        ));
        let (owner, _) = service_owning_crates();
        let mut services = BTreeSet::new();
        for token in body.split("Service::").skip(1) {
            let variant: String = token
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if owner.contains_key(&variant) {
                services.insert(variant);
            }
        }
        // The LMS block is admitted by a discriminant-range helper rather than by
        // arms. Its bounds are read from that helper, so a moved or resized block
        // follows instead of being restated here.
        if body.contains("is_lms_service(service)") {
            let range = code_only(&fn_body(
                "lms_block_contains",
                "const fn lms_block_contains(discriminant: u16) -> bool {",
            ));
            let bounds: Vec<u32> = range
                .split("Service::")
                .skip(1)
                .filter_map(|t| {
                    let v: String = t
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    owner.get(&v).map(|(_, d)| *d)
                })
                .collect();
            assert_eq!(
                bounds.len(),
                2,
                "`lms_block_contains` no longer names exactly two boundary variants"
            );
            let (lo, hi) = (bounds[0].min(bounds[1]), bounds[0].max(bounds[1]));
            for (variant, (_, d)) in &owner {
                if (lo..=hi).contains(d) {
                    services.insert(variant.clone());
                }
            }
        }
        services
    }

    /// The crates holding at least one service the named gate permits.
    fn gate_crates(name: &str) -> BTreeSet<String> {
        let (owner, _) = service_owning_crates();
        gate_services(name)
            .iter()
            .filter_map(|s| owner.get(s).map(|(c, _)| c.clone()))
            .collect()
    }

    /// The services a §4.2 entry-point cell plausibly names.
    ///
    /// The table is written per algorithm family and `Service` is per key size
    /// and mode, so no key relates them in general. What does relate many of
    /// them is that the entry point's own identifiers prefix the variant names:
    /// `oxicrypt_kdf::Pbkdf2Hmac*` selects the five `Pbkdf2Hmac…` variants,
    /// `oxicrypt_sha::sha384` selects `Sha384`. Where that resolves, membership
    /// is checked service by service; where it does not, the caller falls back to
    /// the coarser crate condition and says so.
    fn candidate_services(
        entry: &str,
        crates: &BTreeSet<String>,
        owner: &BTreeMap<String, (String, u32)>,
    ) -> BTreeSet<String> {
        let normalise = |s: &str| -> String {
            s.chars()
                .filter(char::is_ascii_alphanumeric)
                .flat_map(char::to_lowercase)
                .collect()
        };
        let mut tokens: Vec<String> = Vec::new();
        let mut current = String::new();
        for c in entry.chars() {
            if c.is_ascii_alphanumeric() || c == '_' {
                current.push(c);
            } else {
                if !current.starts_with("oxicrypt") {
                    let t = normalise(&current);
                    if t.len() >= MIN_ENTRY_TOKEN {
                        tokens.push(t);
                    }
                }
                current.clear();
            }
        }
        if !current.starts_with("oxicrypt") {
            let t = normalise(&current);
            if t.len() >= MIN_ENTRY_TOKEN {
                tokens.push(t);
            }
        }

        owner
            .iter()
            .filter(|(_, (c, _))| crates.contains(c))
            .filter(|(variant, _)| {
                let v = normalise(variant);
                tokens.iter().any(|t| v.starts_with(t.as_str()))
            })
            .map(|(variant, _)| variant.clone())
            .collect()
    }

    /// The crates named anywhere in a §4.2 entry-point cell.
    fn entry_point_crates(entry: &str) -> BTreeSet<String> {
        entry
            .split("oxicrypt_")
            .skip(1)
            .map(|t| {
                t.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect::<String>()
            })
            .filter(|t| !t.is_empty())
            .map(|t| format!("oxicrypt-{}", t.replace('_', "-")))
            .collect()
    }

    /// The profile tokens named by a §4.2 `Profiles` cell.
    ///
    /// Footnote markers ride on the letters (`C1†`), so matching the letters and
    /// ignoring what trails them is what makes the daggers harmless. The
    /// consequence is stated rather than hidden: `M` and `M†` are
    /// indistinguishable here, so a drift in what a dagger *means* is outside
    /// what any of these checks can see.
    fn profile_cell_tokens(cell: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (abbrev, _) in PROFILE_ABBREVIATIONS {
            let mut rest = cell;
            while let Some(i) = rest.find(abbrev) {
                let before = rest[..i].chars().next_back();
                let after = rest[i.saturating_add(abbrev.len())..].chars().next();
                let bounded = before.is_none_or(|c| !c.is_alphanumeric())
                    && after.is_none_or(|c| !c.is_alphanumeric());
                if bounded {
                    out.insert(abbrev.to_string());
                    break;
                }
                rest = &rest[i.saturating_add(abbrev.len())..];
            }
        }
        out
    }

    /// The data rows of the §4.2 service table: `(line, service, profiles, entry)`.
    fn service_table_rows(policy: &str) -> Vec<(usize, String, String, String)> {
        let mut rows = Vec::new();
        let mut inside = false;
        for (i, line) in policy.lines().enumerate() {
            if line.starts_with("### 4.2") {
                inside = true;
                continue;
            }
            if inside && line.starts_with("### ") {
                break;
            }
            if !inside || !line.starts_with('|') {
                continue;
            }
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            if cells.len() < 5 || cells[0] == "Service" {
                continue;
            }
            if cells.iter().all(|c| c.chars().all(|ch| ch == '-')) {
                continue;
            }
            rows.push((
                i.saturating_add(1),
                cells[0].to_string(),
                cells[3].to_string(),
                cells[4].to_string(),
            ));
        }
        rows
    }

    /// `is_allowed` still defines the two profiles whose membership the
    /// description checks derive rather than restate.
    ///
    /// Everything below rests on two structural facts: `Unrestricted` permits
    /// every service, and `Migration` is exactly the union of the two suites.
    /// Both are single arms in `is_allowed`. If either is rewritten, the
    /// invariants the documents are held to stop following from the code, and
    /// they would go on passing — describing a module that had changed
    /// underneath them.
    ///
    /// Asserted against `is_allowed`'s body with its commentary stripped. A pin
    /// that searches the file as text is satisfied by a comment quoting the line
    /// it looks for, so an edit narrowing the arm could leave `// was: <arm>`
    /// behind and keep this green while the invariants below stop following from
    /// anything.
    #[test]
    fn is_allowed_still_defines_the_profiles_these_checks_assume() {
        let body = code_only(&fn_body(
            "is_allowed",
            "const fn is_allowed(profile: AlgorithmProfile, service: Service) -> bool {",
        ));
        let collapsed = body.split_whitespace().collect::<Vec<_>>().join(" ");
        for arm in [
            "AlgorithmProfile::Unrestricted => true,",
            "AlgorithmProfile::Migration => is_cnsa1_allowed(service) || is_cnsa2_allowed(service),",
        ] {
            assert!(
                collapsed.contains(arm),
                "`is_allowed`'s code no longer contains `{arm}`. The profile checks in this \
                 file derive the documented memberships from that arm; revisit them before \
                 restoring the text."
            );
        }

        let raw = read_doc("crates/oxicrypt-module/src/lib.rs");
        let start = raw
            .find("pub enum AlgorithmProfile {")
            .expect("`AlgorithmProfile` is no longer declared");
        let rest = &raw[start..];
        let end = rest
            .find("\n}\n")
            .expect("`AlgorithmProfile` is unterminated");
        let variants: BTreeSet<String> = rest[..end]
            .lines()
            .filter_map(|l| l.trim().split_once(" = "))
            .filter(|(n, t)| {
                n.starts_with(char::is_uppercase) && t.trim_end_matches(',').parse::<u32>().is_ok()
            })
            .map(|(n, _)| n.to_string())
            .collect();
        let documented: BTreeSet<String> = PROFILE_ABBREVIATIONS
            .iter()
            .map(|(_, v)| (*v).to_string())
            .collect();
        assert_eq!(
            variants, documented,
            "`AlgorithmProfile`'s variants and the documented profile set have diverged"
        );
    }

    /// The derivation the description checks rest on is healthy, in every
    /// checkout.
    ///
    /// Deliberately not gated on the Security Policy. Every input here is in the
    /// public tree, and leaving the derivation reachable only from a
    /// policy-gated test meant an ordinary clone verified no relationship
    /// between the gates and any document at all — the machinery would go
    /// unexercised and its own liveness assertions unrun.
    #[test]
    fn the_profile_gate_derivation_is_healthy() {
        let (owner, seen) = service_owning_crates();
        assert_eq!(
            owner.len(),
            seen,
            "{} `Service` variants resolve to an owning crate out of {seen} seen; a banner \
             has stopped matching and the variants beneath it are being dropped",
            owner.len()
        );
        assert!(
            seen >= 300,
            "read only {seen} `Service` variants — the enum parser is broken, not the enum"
        );

        let c1 = gate_services("is_cnsa1_allowed");
        let c2 = gate_services("is_cnsa2_allowed");
        // Measured: 34 and 190 (the latter including the 160-service LMS block).
        assert!(
            c1.len() >= 30,
            "is_cnsa1_allowed resolved only {} services — the gate scan is broken",
            c1.len()
        );
        assert!(
            c2.len() >= 150,
            "is_cnsa2_allowed resolved only {} services; the LMS block alone is 160, so this \
             is the scan failing, not the gate",
            c2.len()
        );
        assert!(
            c2.iter().any(|s| s.starts_with("Lms")),
            "no LMS service is permitted by CNSA 2.0; the discriminant-range fold is broken"
        );
        assert!(
            !c1.iter().any(|s| s.starts_with("Pbkdf2"))
                && !c2.iter().any(|s| s.starts_with("Pbkdf2")),
            "a CNSA gate now permits PBKDF2; neither edition of CNSSP-15 names one, so this \
             is a gate change that the documents must follow"
        );

        let crates = gate_crates("is_cnsa2_allowed");
        assert!(
            crates.contains("oxicrypt-lms") && crates.contains("oxicrypt-sha"),
            "the gate-to-crate derivation lost a known crate: {crates:?}"
        );
    }

    /// The cell parser reads the shapes the table uses, and refuses the ones
    /// that would make it fire on prose.
    #[test]
    fn the_profile_cell_parser_catches_what_it_must() {
        for (cell, expected) in [
            ("U", vec!["U"]),
            ("U, C1, C2, M", vec!["C1", "C2", "M", "U"]),
            ("U, C2, M", vec!["C2", "M", "U"]),
            ("U, C1, M", vec!["C1", "M", "U"]),
            ("U, C1†, C2†, M", vec!["C1", "C2", "M", "U"]),
            ("U, C1‡, C2‡, M", vec!["C1", "C2", "M", "U"]),
        ] {
            let got = profile_cell_tokens(cell);
            let want: BTreeSet<String> = expected.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(got, want, "parser misread {cell:?}");
        }
        for cell in ["CMAC", "MU", "C10", "SHA-1", ""] {
            assert!(
                profile_cell_tokens(cell).is_empty(),
                "parser fired on {cell:?}: {:?}",
                profile_cell_tokens(cell)
            );
        }
    }

    /// Check every §4.2 row against the gates, accumulating faults.
    ///
    /// Split out of the test purely so the test reads as its three assertions
    /// rather than as a loop with assertions buried after it.
    fn audit_service_rows(
        rows: &[(usize, String, String, String)],
        owner: &BTreeMap<String, (String, u32)>,
        gates: &[(&str, &str, BTreeSet<String>); 2],
        faults: &mut Vec<String>,
        cnsa_rows: &mut usize,
        fine_rows: &mut usize,
    ) {
        for (line, service, cell, entry) in rows {
            let tokens = profile_cell_tokens(cell);
            if !tokens.contains("U") {
                faults.push(format!(
                    "{line}: {service} omits U, but `is_allowed` permits every service under \
                     Unrestricted"
                ));
            }
            let cnsa = tokens.contains("C1") || tokens.contains("C2");
            if cnsa != tokens.contains("M") {
                faults.push(format!(
                    "{line}: {service} states {cell:?}; Migration is the union of the two \
                     suites, so M belongs exactly where C1 or C2 does"
                ));
            }
            if UNGATED_SERVICE_ROWS.iter().any(|(s, _)| s == service) {
                continue;
            }
            if cnsa {
                *cnsa_rows = cnsa_rows.saturating_add(1);
            }

            let crates = entry_point_crates(entry);
            if crates.is_empty() {
                if cnsa {
                    faults.push(format!(
                        "{line}: {service} claims a CNSA profile but its entry point {entry:?} \
                         names no crate, so the claim cannot be checked against the gates"
                    ));
                }
                continue;
            }
            let candidates = candidate_services(entry, &crates, owner);
            if candidates.is_empty() {
                // Coarse fallback: the crate must be reachable by the profile.
                for (abbrev, gate, permitted) in gates {
                    if !tokens.contains(*abbrev) {
                        continue;
                    }
                    let reachable = permitted
                        .iter()
                        .filter_map(|s| owner.get(s).map(|(c, _)| c))
                        .any(|c| crates.contains(c));
                    if !reachable {
                        faults.push(format!(
                            "{line}: {service} claims {abbrev}, but {gate} permits no service \
                             in {crates:?}"
                        ));
                    }
                }
                continue;
            }
            *fine_rows = fine_rows.saturating_add(1);
            for (abbrev, gate, permitted) in gates {
                let any_permitted = candidates.iter().any(|c| permitted.contains(c));
                match (tokens.contains(*abbrev), any_permitted) {
                    (true, false) => faults.push(format!(
                        "{line}: {service} claims {abbrev}, but {gate} permits none of the \
                         services its entry point names ({candidates:?})"
                    )),
                    (false, true) => faults.push(format!(
                        "{line}: {service} omits {abbrev}, but {gate} permits {:?} — either \
                         the row understates the gate or the entry point names a service it \
                         does not provide",
                        candidates
                            .iter()
                            .filter(|c| permitted.contains(*c))
                            .take(3)
                            .collect::<Vec<_>>()
                    )),
                    _ => {}
                }
            }
        }
    }

    /// The §4.2 service table agrees with the three predicates that decide
    /// profile membership.
    ///
    /// Four assertions, each derived rather than restated. Every service is
    /// available under `Unrestricted`, because `is_allowed` returns `true` for
    /// it unconditionally. `Migration` appears exactly where a CNSA profile
    /// does, because it is defined as the union of the two. Where the entry
    /// point resolves to services — measured at 69 of 114 crate-bearing rows —
    /// the CNSA claims are checked against those services in both directions.
    /// Where it does not, a coarser condition applies: the row must name a crate
    /// the gate reaches at all.
    ///
    /// The coarse condition is genuinely weaker and the difference matters. A
    /// row for PBKDF2 promoted to `U, C1, C2, M` satisfies it, because
    /// `oxicrypt-kdf` holds HKDF-SHA-384, which CNSA 1.0 does permit — that is
    /// the whole reason the per-service check above exists, and PBKDF2 is one of
    /// the rows that was actually wrong.
    #[test]
    fn policy_service_table_matches_the_profile_definitions() {
        let Some(policy) = read_policy() else {
            skip_without_policy("policy_service_table_matches_the_profile_definitions");
            return;
        };

        let legend = paragraph_containing(&policy, "**Profiles** column");
        for (abbrev, variant) in PROFILE_ABBREVIATIONS {
            assert!(
                legend.contains(&format!("**{abbrev}**")),
                "the §4.2 legend no longer defines the abbreviation {abbrev} ({variant})"
            );
        }

        let rows = service_table_rows(&policy);
        assert!(
            rows.len() >= 110,
            "read only {} rows from §4.2 against a measured 119 — the table parser is broken, \
             not the table",
            rows.len()
        );

        let (owner, _) = service_owning_crates();
        let gates = [
            ("C1", "is_cnsa1_allowed", gate_services("is_cnsa1_allowed")),
            ("C2", "is_cnsa2_allowed", gate_services("is_cnsa2_allowed")),
        ];
        let mut faults: Vec<String> = Vec::new();
        let (mut cnsa_rows, mut fine_rows) = (0usize, 0usize);
        audit_service_rows(
            &rows,
            &owner,
            &gates,
            &mut faults,
            &mut cnsa_rows,
            &mut fine_rows,
        );

        assert!(
            cnsa_rows >= 40,
            "only {cnsa_rows} rows claim a CNSA profile against a measured 44 — the cell \
             parser is broken, not the table"
        );
        assert!(
            fine_rows >= 60,
            "only {fine_rows} rows resolved to services against a measured 69 — the entry-point \
             key is broken, and the rest of the table fell back to the weaker crate condition"
        );
        for (service, _) in UNGATED_SERVICE_ROWS {
            assert!(
                rows.iter().any(|(_, s, _, _)| s == service),
                "the ungated-row exemption names {service:?}, which is no longer in §4.2"
            );
        }
        assert!(
            faults.is_empty(),
            "the §4.2 service table disagrees with the profile gates:\n  {}",
            faults.join("\n  ")
        );
    }

    /// The two in-tree manifests agree with the same profile definitions.
    #[test]
    fn manifest_profile_lists_match_the_profile_definitions() {
        let variants: BTreeSet<String> = PROFILE_ABBREVIATIONS
            .iter()
            .map(|(_, v)| (*v).to_string())
            .collect();

        let manifest = read_doc("docs/llm-api-manifest/llm-api.yaml");
        let mut lists = 0usize;
        let mut faults: Vec<String> = Vec::new();
        for (i, line) in manifest.lines().enumerate() {
            let trimmed = line.trim();
            let entries: Vec<String> = if let Some(rest) = trimmed.strip_prefix("profiles:") {
                let rest = rest.trim();
                if rest.is_empty() {
                    manifest
                        .lines()
                        .skip(i.saturating_add(1))
                        .take_while(|l| l.trim().starts_with("- "))
                        .map(|l| l.trim().trim_start_matches("- ").trim().to_string())
                        .collect()
                } else {
                    rest.trim_matches(['[', ']'])
                        .split(',')
                        .map(|e| e.trim().to_string())
                        .filter(|e| !e.is_empty())
                        .collect()
                }
            } else {
                continue;
            };
            lists = lists.saturating_add(1);
            let set: BTreeSet<String> = entries.iter().cloned().collect();
            let line_no = i.saturating_add(1);
            for name in &set {
                if !variants.contains(name) {
                    faults.push(format!(
                        "llm-api.yaml:{line_no} names unknown profile {name:?}"
                    ));
                }
            }
            if !set.contains("Unrestricted") {
                faults.push(format!(
                    "llm-api.yaml:{line_no} omits Unrestricted, which permits every service"
                ));
            }
            let cnsa = set.contains("Cnsa1") || set.contains("Cnsa2");
            if cnsa != set.contains("Migration") {
                faults.push(format!(
                    "llm-api.yaml:{line_no} lists {entries:?}; Migration is the union of the two \
                     suites, so it belongs exactly where Cnsa1 or Cnsa2 does"
                ));
            }
        }
        assert!(
            lists >= 55,
            "read only {lists} profile lists from the LAMA manifest against a measured 61 — \
             the parser is broken, not the manifest"
        );

        let lama = read_doc("lama.yaml");
        let display = code_only(&fn_body(
            "AlgorithmProfile::fmt",
            "impl fmt::Display for AlgorithmProfile {",
        ));
        let mut named = 0usize;
        for line in display.lines() {
            let Some((_, tail)) = line.trim().split_once("=> \"") else {
                continue;
            };
            let Some(name) = tail.split('"').next() else {
                continue;
            };
            // `lama.yaml` carries the short name; Migration's display string
            // appends the union it stands for, which the manifest does not
            // repeat, so the leading word is what must appear.
            let short = name.split(" (").next().unwrap_or(name);
            named = named.saturating_add(1);
            if !lama.contains(&format!("name: \"{short}\"")) {
                faults.push(format!(
                    "lama.yaml does not enumerate the profile {short:?}, which \
                     `AlgorithmProfile`'s Display impl names"
                ));
            }
        }
        assert_eq!(
            named,
            PROFILE_ABBREVIATIONS.len(),
            "read {named} display names for {} profiles — the Display parser is broken",
            PROFILE_ABBREVIATIONS.len()
        );

        assert!(
            faults.is_empty(),
            "the manifests disagree with the profile gates:\n  {}",
            faults.join("\n  ")
        );
    }
}
