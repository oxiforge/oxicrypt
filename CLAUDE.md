# Project instructions — pqclib

These are the standing rules for Claude when working in this repository.
They are loaded automatically at the start of every session.

## Compliance target

Follow **FIPS 140-3 Implementation Guidance** as of the current IG release
(IG **D.G** as of March 2026). When the IG updates, reconcile any
affected decisions against the new text before shipping further work.

## Definition of done

Every task is incomplete until `cargo clippy --workspace --all-targets
-- -D warnings` passes. Run it as the last step before handing control
back to the user, and re-run it after any post-review fix-ups.

## Working style — check in at batch boundaries

Claude Desktop is running on a laptop. Long work sessions are fine —
the user often works for hours — but check in **before starting a new
batch of work** so the user isn't forced to interrupt a running batch
with a shutdown.

A "batch" is any unit that will run for more than a few minutes without
a natural break. Before starting one, state what's in it and roughly
how long it'll take, so the user can say "go" or "not now".
