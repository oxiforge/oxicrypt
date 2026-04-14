# Project instructions — oxicrypt

These are the standing rules for Claude when working in this repository.
They are loaded automatically at the start of every session.

## Key paths

- **Repo:** `/home/rick/repos/oxicrypt`
- **LAMA spec repo:** `/home/rick/repos/lama-spec`
- **Project folder:** `~/carakastan/Projects/PQClib/` — project plan,
  HN talking points, launch roadmap, and other planning docs that
  live outside the repo

## Compliance target

Follow **FIPS 140-3 Implementation Guidance** as of the current IG release
(IG **D.G** as of March 2026). When the IG updates, reconcile any
affected decisions against the new text before shipping further work.

## Definition of done

Every task is incomplete until `cargo clippy --workspace --all-targets
-- -D warnings` passes. Run it as the last step before handing control
back to the user, and re-run it after any post-review fix-ups.

## Documentation sync at every commit point

At each commit boundary, refresh documentation while the context is
fresh. For any commit that touches a crate — directly or by
reference — do all five of:

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
   they must stay in sync with the actual API surface.
5. **Project plan.** Update
   `~/carakastan/Projects/PQClib/rust-fips-project-plan.md`
   current-status section and chunk checklists to reflect what
   the commit actually landed. This file lives outside the repo
   in the PQClib project folder — do not commit it.

These five doc updates ship **in the same commit** as the code
change — not as a follow-up — so reviewers always see the code
and its documentation evolve together.

## Working style — check in at batch boundaries

Claude Desktop is running on a laptop. Long work sessions are fine —
the user often works for hours — but check in **before starting a new
batch of work** so the user isn't forced to interrupt a running batch
with a shutdown.

A "batch" is any unit that will run for more than a few minutes without
a natural break. Before starting one, state what's in it and roughly
how long it'll take, so the user can say "go" or "not now".
