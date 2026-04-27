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
2. **Security policy sync** — if any file under `crates/*/src/` is staged, `docs/security-policy/security-policy.md` must also be staged.

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

### Internal builds

After every PR squash-merge, the merged commit gets tagged `vX.Y.Z.A` where:

- `X.Y.Z` is the current value of `[workspace.package].version`
- `A` is one greater than the highest existing `.A` for this `X.Y.Z` (resets to `1` when `X.Y.Z` changes)

Use `scripts/tag-next-build.sh` to compute and apply the tag automatically.

The `.A` segment is git-tag-only; `Cargo.toml` does **not** carry a fourth version component (semver doesn't allow it). The `.A` exists so we can identify which build is newest among several internal artifacts without parsing commit log.

### Releases

Releases are deliberate, separate acts:

1. Decide the release version `vX.Y.Z` per [semver](https://semver.org/)
2. Bump `[workspace.package].version` in `Cargo.toml` on a `chore/release-X.Y.Z` PR if the value is stale
3. After the release PR squash-merges, tag the merge commit with `vX.Y.Z` (no `.A` suffix)
4. Push the tag: `git push origin vX.Y.Z`
5. Create the GitHub release from the tag
6. After the release lands, the next post-release internal build resets `.A` to `1`

When the project starts publishing to crates.io (currently `publish = false` in `Cargo.toml`), release tags become the publishing trigger.

### Tag scheme summary

| Kind | Format | Cargo.toml | Pushed to crates.io |
|---|---|---|---|
| Internal build | `vX.Y.Z.A` | unchanged | no |
| Release | `vX.Y.Z` | matches | yes (when `publish = true`) |
| Release-stabilization branch | `release/X.Y` | unchanged on the branch | no |

## Rationale

Each rule in this document is here because it captures a discipline that compounds at the project boundaries: between commits, between PRs, between releases, between maintainers. If a rule seems to slow you down, that's usually the rule doing its job — discipline is friction with a payoff. If a rule is wrong, propose a `chore/contributing-update` PR that names what changed and why.
