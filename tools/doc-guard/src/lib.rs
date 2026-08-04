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
    use std::collections::{BTreeMap, BTreeSet};
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

    // ----- claim-versus-code: ISC-125, the α parameter (#157) -----
    //
    // A group of criteria are satisfied by a sentence in the policy and by
    // nothing else. A probe can confirm the sentence is present, but nothing
    // detects when the code drifts away from what the sentence asserts — the
    // claim and its enforcement are separate, and only the claim is checked.
    //
    // ISC-125 had already diverged when this was written: the policy called α
    // "the cutoff-generating parameter … not the observed false-positive rate",
    // while the crate doc described it only as a "False-positive probability" —
    // the reading the policy explicitly rules out. Both documents were current
    // and nothing compared them.

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
    /// satisfied by any of its 6 occurrences, two of which sit in a dated
    /// decision table. Deleting the live sentence would then still pass.
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
        let health = read_doc("crates/oxicrypt-entropy/src/health.rs");
        let spec = read_doc("crates/oxicrypt-entropy/src/sp800_90b.rs");
        let policy = read_doc("docs/security-policy/security-policy.md");
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

        let policy = read_doc("docs/security-policy/security-policy.md");
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
    /// Fixing `health.rs` alone left the same reading live one file away — eight
    /// sites across three crates still called α a "false-positive probability",
    /// including `sp800_90b.rs`, the file the guard above parses. A criterion
    /// reported as fixed while its own defect persists next door is the thing
    /// this whole check family exists to prevent, so the phrasing is denied
    /// repo-wide rather than corrected once.
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
    /// #158 reported three cases. Sweeping every criterion found **five**:
    /// `D.K R5` and `D.K R15` are also cited and unresolved — `D.K R15` by
    /// ISC-125, the criterion whose α claim the guards above assert — and
    /// `D.K R1` is cited by ISC-123 in longhand ("IG D.K Resolution-1"), a form
    /// the first version of this parser dropped, so the very criterion the check
    /// exists to catch was invisible to it.
    const KNOWN_UNCITED: &[&str] = &["D.J AC6", "D.K R1", "D.K R15", "D.K R22", "D.K R5"];

    /// How many distinct resolutions the criteria cite. Pinned rather than
    /// bounded: a threshold is cleared by a deletion, and a citation silently
    /// disappearing is one of the two failures this guard exists to catch.
    const EXPECTED_CITATIONS: usize = 7;

    /// Every `<letter>.<letter> R<n>` / `AC<n>` resolution cited in the ISA.
    ///
    /// The input is normalised first, because the shorthand is not the only form
    /// in use: ISC-123 cites "IG D.K Resolution-1" in longhand, whose token
    /// carries no digit and was silently dropped — the criterion the check exists
    /// to catch, invisible to the check. A comma or extra spacing between the
    /// section and the resolution is tolerated for the same reason: each is one
    /// reflow away from becoming a silent false negative.
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
        let isa = read_doc("ISA.md");
        let policy = read_doc("docs/security-policy/security-policy.md");
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
    // The Security Policy ships unresolved drafting text — a forward reference to
    // wiring that has not landed, and a question not yet put to the CST lab. This
    // is the document a CST lab and a CMVP reviewer read.
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
    /// `AUDITED_EXCEPTIONS` exists so a `forbid(unsafe_code)` swap "fails by
    /// name, not just by count". The same standard applies here.
    ///
    /// `[MARK` is in the list because the policy uses a second convention for the
    /// same thing (`**[MARK: …confirm placement with the CST lab…]**`), which a
    /// `TODO`/`pending]` sweep does not see.
    const OPEN_MARKERS: &[(&str, usize)] = &[
        ("TODO", 7),
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
        let policy = read_doc("docs/security-policy/security-policy.md");

        // Positive control on BOTH carve-outs, against a synthetic fixture rather
        // than the live document. Asserting only that the frozen predicate
        // "matched a lot of rows" cannot detect mis-scoping: deleting the
        // carve-out entirely changes today's census by zero, because the one
        // dated row carrying a marker is exempt for another reason. So the
        // predicate is exercised on inputs that must and must not match.
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
                // Every occurrence, not one per line: line 2791 already carries
                // two `[seeding-integration pending]`, so a per-line count makes
                // a second marker on an already-marked line free.
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
