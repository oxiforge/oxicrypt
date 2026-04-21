# Project instructions — oxicrypt

These are the standing rules for Claude when working in this repository.
They are loaded automatically at the start of every session.

## Key paths

- **Repo:** `/home/rick/repos/oxicrypt`
- **LAMA spec repo:** `/home/rick/repos/lama` (remote: `github.com/lamaspec/lama`)
- **Project folder:** `~/carakastan/Projects/OxiCrypt/` — project plan,
  HN talking points, launch roadmap, and other planning docs that
  live outside the repo

## Session bootstrap

At the start of every session — or after a context reset —
read `llm-project-manifest.yaml` (repo root) before doing
anything else. The manifest records what exists right now:
repos, crates, tooling, docs, external dependencies, and their
status (`complete` / `partial` / `stub`). It contains no plans
and no priorities — just the current state of the world. Use it
to avoid re-proposing finished work or spending time on
reconnaissance that the manifest already answers.

The manifest lives **outside the repo** in the project folder
(`~/carakastan/Projects/OxiCrypt/llm-project-manifest.yaml`)
because it contains internal paths and references that should
not be committed to version control. Update it as part of the
doc-sync (step 6 below) whenever a commit changes the status
of anything it tracks — but do not commit it.

## Compliance target

Follow **FIPS 140-3 Implementation Guidance** as of the current IG release
(IG **D.G** as of March 2026). When the IG updates, reconcile any
affected decisions against the new text before shipping further work.

## Definition of done

Every task is incomplete until both of these pass:

1. `cargo fmt --all --check` (no unformatted code)
2. `cargo clippy --workspace --all-targets -- -D warnings`

Run both as the last step before handing control back to the user,
and re-run them after any post-review fix-ups. If `cargo fmt --all
--check` reports diffs, run `cargo fmt --all` to fix them before
the clippy step — clippy output is easier to read on formatted code.

## Documentation sync at every commit point

At each commit boundary, refresh documentation while the context is
fresh. For any commit that touches a crate — directly or by
reference — do all six of:

1. **Rustdoc.** Update the `lib.rs` header and any affected item
   docs of every crate changed or referenced so the "Approved
   services", SSP, self-test, and gating sections match the code
   as it stands at that commit. Run `cargo doc --workspace
   --no-deps` and resolve any new warnings in crates touched by
   the commit.
2. **Security Policy draft.** Update
   `docs/security-policy/security-policy.md` with whatever the
   commit changes: new approved services, new or reclassified
   SSPs, new self-tests, changed state-machine behavior, new
   disclosed side-channel posture, etc. The policy is currently
   an alpha draft and does not need formal revision numbers;
   internal versioning is the git history. Formal versioning
   will begin once human editing starts.
3. **README.** Update `README.md` if the commit changes the
   user-facing status of the crate — algorithm coverage, build
   instructions, workspace layout, or the project phase.
4. **LAMA manifests.** Update `lama.yaml` (root, quick-triage
   summary) and `docs/llm-api-manifest/llm-api.yaml` (full
   manifest) if the commit adds, removes, renames, or changes
   the signature of any public function, type, or entry point.
   The manifests are how AI agents discover the library, so
   they must stay in sync with the actual API surface. The
   pre-commit hook at `scripts/git-hooks/pre-commit` enforces
   `llm-api.yaml` mechanically on any change to a
   `pub fn|struct|enum|const|type|trait` line under
   `crates/*/src/`. If the hook fires on a change that is
   genuinely internal (rustdoc-only, signature-position reflow),
   bypass with `git commit --no-verify` and explain the bypass
   in the commit body so reviewers see the rationale.
5. **Project plan.** Update
   `~/carakastan/Projects/OxiCrypt/rust-fips-project-plan.md`
   current-status section and chunk checklists to reflect what
   the commit actually landed. This file lives outside the repo
   in the OxiCrypt project folder — do not commit it.
6. **Project manifest.** Update
   `~/carakastan/Projects/OxiCrypt/llm-project-manifest.yaml`
   if the commit changes the status of any tracked item — new
   crate, handler count change, doc completion, external
   dependency update, etc. The manifest is what IS, not what's
   planned; keep it factual and current. This file lives outside
   the repo in the OxiCrypt project folder — do not commit it.

Run `cargo fmt --all` before staging the commit so formatting
is always clean. These six doc updates ship **in the same
commit** as the code change — not as a follow-up — so reviewers
always see the code and its documentation evolve together.

## Insight capture at every commit (CMVP gem rule)

Before staging **any** commit — not only commits that touch the
security policy — pause and ask: *did this session surface any
mechanistic insight — about why a design choice is correct, how a
security property is guaranteed, what structural constraint prevents
a class of bug, or why a conformance property holds — that a NIST
auditor or CST lab reviewer would need to understand in order to
accept the claim?*

If yes, write it into `docs/security-policy/security-policy.md` as
a prose paragraph (not just a table row) in the same commit. Good
candidates:

- Language/compiler guarantees that enforce a security property
  (e.g. `Drop` ordering, `forbid(unsafe_code)` as a hard build-time
  control).
- Composition patterns that extend coverage transitively (e.g. a
  zeroization invariant inherited by every struct that embeds a
  zeroizing primitive).
- Rationale for why a zeroization, gating, or self-test approach is
  complete — especially when completeness is non-obvious.
- Conformance properties where two services intentionally diverge
  because they implement different specifications, and where the
  divergence would otherwise look like a bug.

Insights surface during code work, not during policy work. A
manifest-only commit or a refactor commit is just as likely to
expose a gem as a policy commit — so this check runs at **every**
commit gate, independent of which doc-sync steps apply. Capture
every gem while the context is warm; a gem deferred is usually a
gem lost.

The pre-commit hook at `scripts/git-hooks/pre-commit` enforces
this by requiring `docs/security-policy/security-policy.md` to be
staged alongside any change under `crates/*/src/`. That does not
mean every commit must add a gem — many changes legitimately
surface none. It means every commit must force the thought, which
is the only reliable way to avoid deferring a gem past the point
where the context is warm enough to write it. When no gem applies,
bypass with `git commit --no-verify` and say so in the commit body
("pure refactor, no new invariant surfaced" is a valid rationale).

## Working style — check in at batch boundaries

Claude Desktop is running on a laptop. Long work sessions are fine —
the user often works for hours — but check in **before starting a new
batch of work** so the user isn't forced to interrupt a running batch
with a shutdown.

A "batch" is any unit that will run for more than a few minutes without
a natural break. Before starting one, state what's in it and roughly
how long it'll take, so the user can say "go" or "not now".
