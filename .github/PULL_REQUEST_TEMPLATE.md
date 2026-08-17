<!--
  Squash-merge takes this body as the commit message body. Write it
  for the historical record on `main`, not just the reviewer in the
  moment. See CONTRIBUTING.md for the full PR flow.
-->

## Summary

<!-- One or two sentences capturing what this PR does. -->

## Why

<!--
  Motivation. What observation drove this work? Prior art / related
  issues / spec citations. If the work was queued in a memory file
  or earlier PRD, link it.
-->

## What changed

<!-- File-by-file or area-by-area. Be specific enough that a future
  reader can map the prose to the diff without reading every hunk. -->

## Test plan

<!-- Check each gate that applies. Mark N/A for any that don't. -->

- [ ] `cargo build --release --workspace` — clean
- [ ] `cargo test --workspace --all-features` — green (X/X passing)
- [ ] `cargo clippy --all-targets --all-features --release -- -D warnings` — clean
- [ ] `cargo doc --no-deps --workspace` — no warnings
- [ ] LAMA manifest updated (or `--no-verify` documented in commit body)
- [ ] Security policy updated — or no gem surfaced (bypass, no note needed), or policy not provisioned
- [ ] `oxicrypt-integrity-sign --sign` re-signed binary (harness rebuilds only) — HMAC `<paste>`
- [ ] Live ACVTS run (if applicable) — session `<id>`, vector set `<id>`, verdict `passed`

## Anti-criteria

<!--
  What's deliberately NOT in this PR. Out-of-scope items, deferrals,
  capability-builder bugs that surfaced but won't be fixed here.
  Anti-criteria prevent scope creep and document considered-and-
  declined alternatives.
-->

## Code-review skill invocation

<!--
  Per CONTRIBUTING.md, every PR must have the requesting-code-review
  skill invoked on the diff before squash-merge. Summarize the
  findings and how each was actioned (applied / noted-and-skipped
  with reason). Paste agent IDs or links if useful.
-->
