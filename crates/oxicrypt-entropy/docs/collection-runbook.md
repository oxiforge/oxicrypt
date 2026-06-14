# Raw-data collection runbook

Operator guide for the off-boundary `collect` binary. The binary captures
SP 800-90B raw and restart datasets for one operational environment (OE) per
invocation, writes them under a versioned per-OE layout with a top-level
sha256 manifest, and is resumable via a content-hash checkpoint.

> **Off-boundary tooling.** `collect` is built behind the default-off
> `collection` feature and is **outside** the validated module boundary. The
> default and library build graphs carry none of it, and the crate's
> `RawCollector` stays crate-private. Build it explicitly:
>
> ```sh
> cargo build -p oxicrypt-entropy --features collection --release
> ```
>
> Collection runs on **bare metal** only — VM-collected jitter is
> methodologically contested and taints the evidence package.

## One command per dataset type

A single `collect` invocation produces **both** dataset types for an OE,
across **both** boundaries. There is one command to remember per OE; the
dataset types it emits are:

| Dataset type | File | Count | Notes |
|--------------|------|-------|-------|
| Raw          | `raw.bin`     | 1,000,000 samples | Streamed, one byte per sample; certification posture (a mid-run health trip invalidates and signals re-collect). |
| Restart      | `restart.bin` | 1000 × 1000 samples | A **fresh source instance per restart round**, each re-running startup health gating. |

```sh
# Collect raw + restart, lower + upper boundary, for one OE:
collect --oe-id <oe-id> --datasets-dir <dir>
```

Preview the plan and resumable status without touching the noise source:

```sh
collect --oe-id <oe-id> --datasets-dir <dir> --dry-run
```

## Layout produced

```text
<dir>/<oe-id>/<timer>/<boundary>/
  raw.bin          1,000,000 one-byte samples
  restart.bin      1000 x 1000 one-byte samples (fresh source per round)
  metadata.json    versioned sidecar (validates against the vendored schema;
                   records sample_count, restart_total, timer, measured
                   counter frequency, CPU model, OS, and health-trip
                   annotations)
<dir>/manifest.sha256          sha256 of every dataset file (one per line)
<dir>/collection-session.json  resumable content-hash checkpoint
```

Two boundaries are always emitted per OE:

- `lower` — a tight measurement loop, the worst-case lower bound on
  per-sample entropy.
- `upper` — normal operation, the operating point.

## Resuming an interrupted collection

Collection is **resumable**. Every completed boundary dataset is recorded in
`collection-session.json` by a **content hash** of its full specification
(OE, timer, boundary, counts, claim, schema version). Re-running the exact
same command:

- **skips** any boundary whose content hash is already recorded — no source
  is rebuilt and no file is rewritten for it;
- **re-collects** any boundary whose spec changed (a different count, claim,
  or boundary hashes differently and is not skipped).

So an interrupted run is resumed simply by issuing the same command again —
already-completed datasets are skipped, and collection continues from the
first incomplete one. This mirrors the ACVP harness session-store discipline
(`acvp-harness/src/session.rs`): write durable progress, replay idempotently.

## Verifying the manifest

```sh
# From the datasets dir, re-verify every checksum:
sha256sum -c manifest.sha256
```

The manifest is rewritten after each boundary completes, so it always
reflects the files currently on disk.
