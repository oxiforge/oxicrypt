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

<!--
  A ticked box means DISPOSITIONED, not necessarily run. Tick an N/A row too,
  with "N/A —" leading the label and the reason after it, so a tick is never
  misread as "this ran". An unticked box means outstanding, so a PR ready for
  review has none: a lone unticked N/A reads as unfinished work at a glance,
  and the glance is what reviewers act on.
-->

- [ ] `cargo build --release --workspace` — clean
- [ ] `cargo test --workspace --all-features --exclude oxicrypt-ml-dsa --exclude oxicrypt-ml-kem`, then `cargo test -p oxicrypt-ml-dsa -p oxicrypt-ml-kem` with and without `--features testing-interfaces --tests` — green (X/X passing). Cargo unifies a feature across a workspace build, so the post-quantum crates' `compile_fail` doctests pass only per package.
- [ ] `cargo nextest run -p <package> --features fault-injection` for `oxicrypt-ml-dsa`, `oxicrypt-ml-kem`, `oxicrypt-drbg`, `oxicrypt-ffi` and `oxicrypt-cli` — green (X/X passing). A fault seam is process-wide, so these run under nextest.
- [ ] `cargo clippy --all-targets --all-features --release -- -D warnings` — clean
- [ ] `cargo doc --no-deps --workspace` — no warnings
- [ ] LAMA manifest updated (or `--no-verify` documented in commit body)
- [ ] Security policy updated — or no gem surfaced (bypass, no note needed), or policy not provisioned
- [ ] `oxicrypt-integrity-sign --sign --key <key>` re-signed binary (harness rebuilds only) — signature `<paste>`, verify key `sha256:<paste>`
- [ ] Live ACVTS run (if applicable) — session `<id>`, vector set `<id>`, verdict `passed`

## Code-review skill invocation

<!--
  Per CONTRIBUTING.md, every PR must have the requesting-code-review
  skill invoked on the diff before squash-merge. Summarize the
  findings and how each was actioned (applied / noted-and-skipped
  with reason). Paste agent IDs or links if useful.
-->
