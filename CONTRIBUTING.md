# Contributing to oxicrypt

This document is the single source of truth for how work lands on `main`. It applies to maintainers, AI-pair commits, and external contributors equally.

## Branch model

oxicrypt uses **GitHub Flow + on-demand release branches**:

- `main` is always compilable, tested, and signed. Every commit on `main` is a candidate build.
- All work lands on `main` through pull requests. **No direct commits to `main`** — the project conventions document is the only file that ever lands directly, and only at the moment those conventions are first introduced.
- When stabilization is needed (CMVP validation, security audit, formal release window), cut a `release/X.Y` branch from `main`. Stabilize there. Merge fixes back to `main`. Drop the release branch when validation completes.

## One-time setup

After cloning, activate the doc-sync pre-commit hook:

```bash
git config core.hooksPath scripts/git-hooks
```

The hook enforces two checks on every commit (see `scripts/git-hooks/pre-commit` for full rationale):

1. **LAMA manifest sync** — if a commit changes `pub fn|struct|enum|const|type|trait|static|union|mod` lines under `crates/*/src/`, `docs/llm-api-manifest/llm-api.yaml` must also be staged.
2. **Security policy sync** — if any file under `crates/*/src/` is staged, the Security Policy must have been modified since the last commit. That document is withheld from this repository (see `docs/security-policy/README.md`), so git cannot stage it and the check is on mtime instead. **If you do not have the Security Policy, this check is skipped entirely** — it never blocks you on a document you cannot read.

The hook can be bypassed with `git commit --no-verify`. **Bypasses must be explained in the commit body** — either "internal change, no manifest delta" or "no security-policy gem surfaced, <reason>". Undocumented `--no-verify` is a contribution-flow violation.

## Branch naming

Flat namespace, three prefixes:

- `feat/<short-name>` — new functionality (algorithms, capabilities, features)
- `fix/<scope>` — bug fixes
- `chore/<scope>` — non-functional repo work (docs, tooling, CI)

Examples: `feat/ml-kem-768`, `fix/hmac-mac-len-per-group`, `chore/contribution-conventions`.

Avoid deep slash-nested names; the flat form keeps `gh pr` and tab-completion fast.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

- **Type:** `feat`, `fix`, `chore`, `refactor`, `docs`, `test`, `perf`
- **Scope:** the affected crate or area (`acvp-harness`, `oxicrypt-aes`, `oxicrypt-ml-kem`, `repo`, etc.)
- **Subject:** imperative mood, ≤72 chars, no trailing period
- **Body:** structured per the PR template — Why / What / Test plan / Anti-criteria

### Co-author trailer policy

Keep `Co-Authored-By: Claude <model-id> <noreply@anthropic.com>` (or whichever Anthropic model is in use) on **every commit that contains AI-generated code**. Strip the trailer only when the commit is purely human-authored.

For a FIPS-adjacent project where chain-of-trust matters, hiding the AI's role would be its own form of dishonesty. Honest disclosure of provenance is the brand.

## Local pre-PR gate stack

All of these must be clean before opening a PR. They run on your local machine until CI is in place.

| Gate | Command |
|---|---|
| Build | `cargo build --release --workspace` |
| Tests | `cargo test --workspace --all-features` |
| Clippy (strict) | `cargo clippy --all-targets --all-features --release -- -D warnings` |
| Rustdocs | `cargo doc --no-deps --workspace` (no warnings) |
| Doc-sync hook | Activated via `git config core.hooksPath scripts/git-hooks` (one-time setup above) |
| Integrity-sign (harness rebuilds) | `./target/release/fips-integrity-sign --sign ./target/release/acvp-harness` |

`-D warnings` promotes Clippy lints to errors. The project uses pedantic-tier lints; this gate is intentionally strict.

If a gate fails, fix the underlying issue rather than bypassing. The gate is the contract.

### How much of the nextest suite a push runs

The pre-push hook always runs fmt, Clippy, **doctests**, the **release construction guard** and the release build — together about seven seconds on a warm target directory. None of those are ever skipped. The one expensive gate is `cargo nextest run --workspace`, and only that gate is scoped to what the push can actually affect:

| Your push changes | `cargo nextest run` |
|---|---|
| no Rust at all (docs, hooks, CI config) | skipped — no test can observe it |
| Rust, but nothing `oxicrypt-maxwell` is built from | runs without that one package |
| `oxicrypt-maxwell`, or `oxicrypt-module` / `oxicrypt-sha` / `oxicrypt-test-vectors` / `oxicrypt-zeroize`, or `Cargo.lock` / `Cargo.toml` / the toolchain pin / `.cargo/` | runs in full |
| a crate the hook's inventory does not recognise | runs in full |

`oxicrypt-maxwell` carries the SP 800-90B estimator tests anchored to the NIST EA reference datasets. One of them exceeds 1140s of a ~1245s suite run, so excluding that package when nothing it is built from changed is most of the difference between a 21-minute push and a fast one. The scoping is conservative: it asks whether a test's verdict *could* change, never whether a push looks important, and anything it cannot resolve runs the full suite.

Only a full run records a pass in the stamp cache. A scoped run is a real pass over a smaller set, and must not be able to satisfy a later push that needs the full one.

To decide for yourself on a given push:

```bash
OXICRYPT_PUSH_NEXTEST=skip        git push    # skip the nextest suite (doctests + release guard still run)
OXICRYPT_PUSH_NEXTEST=no-maxwell  git push    # nextest without oxicrypt-maxwell
OXICRYPT_PUSH_NEXTEST=full        git push    # run all of nextest
```

The override is announced in the hook's output and writes no stamp unless it ran everything. Unlike the automatic scoping it does **not** check whether maxwell's inputs changed — `no-maxwell` excludes those tests whatever you touched, so use it knowing that, and let a full nextest run gate what lands on `main`.

### SP 800-90B reference datasets (required for a meaningful test run)

The `oxicrypt-maxwell` entropy-estimator tests compare against the NIST EA v1.1.8 reference outputs
and need that project's 11 `.bin` datasets:

```
git clone https://github.com/usnistgov/SP800-90B_EntropyAssessment ~/repos/SP800-90B_EntropyAssessment
```

They are looked up at `$OXICRYPT_EA_DATA`, falling back to
`~/repos/SP800-90B_EntropyAssessment/bin`. Without them the estimator tests **skip rather than
fail**, so the suite goes green having compared nothing — `parity::tests::ea_dataset_suite_is_provisioned`
fails fast to tell you that has happened, naming what is missing.

If you genuinely cannot provision them, `OXICRYPT_EA_DATA_OPTIONAL=1` downgrades that check to a
warning. A run under that flag forfeits the parity evidence claim and must not be offered as
tests-pass evidence on a PR touching the estimators.

### The Security Policy (you almost certainly do not have it — that is fine)

The FIPS 140-3 Security Policy is withheld from this repository and held privately;
[`docs/security-policy/README.md`](docs/security-policy/README.md) explains why and how to request
access. **You need it for nothing.** `cargo test --workspace` passes without it and without any
configuration: the five `doc-guard` tests that assert the document's stated numerals against the
workspace skip, and `doc_guard::tests::security_policy_is_provisioned` passes with a note saying so.

That gate only *fails* if your checkout claims to have the document — `$OXICRYPT_SECURITY_POLICY` is
set, or the sibling clone directory exists — and it is not readable. If you want it silent in a
scripted environment, set `OXICRYPT_SECURITY_POLICY_OPTIONAL=1`.

The pre-commit hook's gem-capture check works the same way: with no policy on disk it is skipped and
says so, and never blocks you on a document you cannot read.

## Private-name containment (opt-in)

Some strings must not reach a public repository and also cannot be written into one: an employer's name, a client path, an internal hostname. A pattern committed to the repo would publish the very name it exists to suppress, and would match its own source file, so it could never pass.

The `pre-push` hook therefore reads a deny-list that lives **outside version control**, in your own clone:

| | |
|---|---|
| Location | `$OXICRYPT_CONTAINMENT_DENY` if set, otherwise `.git/containment-deny` |
| Format | One extended regex per line; `#` comments and blank lines ignored |
| Absent | The check is **skipped**, loudly, and the push proceeds |

`.git/` is never tracked, so the file needs no `.gitignore` entry and cannot be committed by accident. Nobody adopts anyone else's list, and no list is ever shared.

Create it with your editor rather than a heredoc — typing the patterns at a shell prompt puts them in `~/.bash_history`, which is one of the channels this exists to protect:

```sh
$EDITOR "$(git rev-parse --git-dir)/containment-deny"
```

One extended regex per line, for example `/home/yourname/` or `internal\.example\.corp`.

If you use linked worktrees, note that `git rev-parse --git-dir` resolves to `.git/worktrees/<name>`, so each worktree has its own list and a new one starts empty.

Properties worth knowing, because each exists for a reason:

- **It scans binaries.** The leak that prompted this was found in a committed `.pyc`, where no text review would have surfaced it. A scanner that skips binary files reports clean while the worst instance sits in a compiled artefact.
- **It scans the commits being pushed, not your checked-out tree.** `git push origin other:main`, and a secret added in one commit and removed in the next, both reach the remote while `HEAD` is clean.
- **It scans paths as well as content.** A private name can appear only in a filename, which a content search never sees.
- **It runs before the tag short-circuit and the stamp cache.** Both of those skip the expensive cargo gates for states that cannot have changed the build — but a state gated before you wrote your deny-list has never been checked against it. A leak check that a cache can skip is not a leak check.
- **It never prints the pattern or the matched text** — only the deny-list *line number* and the files that matched. Echoing the string would write it into scrollback, CI logs, and shell history, reproducing the leak while reporting it. Note that a matching **filename** is printed, so a path that is itself sensitive will appear.
- **An invalid regex is a hard failure, not a skip.** `git grep` exits 128 on a bad pattern, which an ordinary `if` reads as "no match" — so a typo would disable that pattern for good while the hook reported success.

The hook runs a positive control, with the same flags as the real scan, before trusting a clean result: a string known to be present must match, so a broken scanner fails loudly instead of passing silently.

When a pattern matches, the hook names the deny-list line number. To find the content locally without the hook ever echoing the string:

```sh
git grep -n -E -f <(sed -n '<LINE>p' "$(git rev-parse --git-dir)/containment-deny")
```

This prevents **new** leaks in what you push. It says nothing about what is already in history; that is a separate sweep.

## Pull request flow

```
1. git checkout -b <type>/<scope>     # branch from main
2. <work>
3. git push -u origin <branch>
4. gh pr create --title "..." --body "..."   # use the template
5. Run requesting-code-review skill on the PR diff
6. Apply or note (with reasoning) each review finding
7. gh pr merge --squash --delete-branch
8. git pull --rebase origin main
9. bash scripts/tag-next-build.sh     # apply next vX.Y.Z.A tag
10. git push origin <next-tag>
```

The squash-merge takes the **PR title as the commit subject** and the **PR description as the commit body**. So the PR description is the historical record on `main`.

### PR description structure

Use `.github/PULL_REQUEST_TEMPLATE.md`. Sections:

1. **Summary** — one or two sentences capturing what this PR does
2. **Why** — motivation, prior art, the observation that drove this work
3. **What changed** — file-by-file or area-by-area
4. **Test plan** — checklist of gates passed (build / test / clippy / docs / sync hook / integrity-sign / live ACVTS if applicable)
5. **Anti-criteria** — what's deliberately NOT in this PR (deferrals, out-of-scope work)
6. **Code-review skill invocation** — findings and how each was actioned

### Code-review gate

Every PR must have the `requesting-code-review` skill invoked on its diff before squash-merge. Findings should be either applied or noted with reasoning in the PR thread. This is the third-party review that catches what the author is too close to see.

External contributors who don't have access to the skill can request maintainer review via standard `gh pr review` flow; maintainers run the skill on their behalf.

## Versioning and tagging

The workspace version lives in `Cargo.toml` under `[workspace.package].version`.

### Internal builds — retired

Per-merge `vX.Y.Z.A` tags are **no longer created**. Four exist (`v0.0.0.1` … `v0.1.0.1`), all from 2026-04-27, and none since; the convention was documented for three months after it stopped being practised.

It solved a problem the project no longer has. Its stated purpose was identifying which build is newest among several internal artifacts without parsing the commit log — `git describe` answers that better and for free:

```
$ git describe --tags HEAD
vX.Y.Z-18-gc7eaabd      # 18 commits past the vX.Y.Z tag, at commit c7eaabd
```

`Cargo.toml` never carried a fourth component and still does not; semver has no place for one.

### Releases

Releases are deliberate, separate acts. **Every version literal is bumped by `scripts/bump-version.sh`, not by hand** — there are three of them plus the changelog heading, and editing them individually is how they drift apart:

1. Decide the release version `X.Y.Z` per [semver](https://semver.org/). Note that `0.x` is not a lesser kind of version: cargo treats a `0.x` **minor** bump as incompatible, so the pre-1.0 track already carries the "may break you" contract that a major bump carries above 1.0.
2. On a `chore/release-X.Y.Z` branch, run `./scripts/bump-version.sh X.Y.Z`. It rewrites `Cargo.toml`, `docs/llm-api-manifest/llm-api.yaml` and `lama.yaml`, renames the changelog's `## [Unreleased]` heading to `## [X.Y.Z] - YYYY-MM-DD`, and refuses to finish if any stale literal survives.
3. Open the PR, merge it signature-preserving.
4. Tag the merge commit `vX.Y.Z` — annotated **and signed** — then `git push origin vX.Y.Z`.
5. Create the GitHub release from the tag.

When the project starts publishing to crates.io (currently `publish = false` in `Cargo.toml`), release tags become the publishing trigger. Note that crates.io reads the version from `Cargo.toml` at publish time and never sees a git tag.

### Tag scheme summary

| Kind | Format | Cargo.toml | Pushed to crates.io |
|---|---|---|---|
| Release | `vX.Y.Z` | matches | yes (when `publish = true`) |
| Release-stabilization branch | `release/X.Y` | unchanged on the branch | no |
| ~~Internal build~~ | ~~`vX.Y.Z.A`~~ | — | retired, see above |

## Rationale

Each rule in this document is here because it captures a discipline that compounds at the project boundaries: between commits, between PRs, between releases, between maintainers. If a rule seems to slow you down, that's usually the rule doing its job — discipline is friction with a payoff. If a rule is wrong, propose a `chore/contributing-update` PR that names what changed and why.
