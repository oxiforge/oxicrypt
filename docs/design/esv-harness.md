# Design: `esv-harness` — the ESV submission client

Design-of-record for `esv-harness`, the out-of-boundary client that builds,
validates, and drives the NIST **Entropy Source Validation Protocol** (ESVP
1.0) flow for SP 800-90B entropy-source validation. It is the entropy-source
counterpart to `acvp-harness` (CAVP algorithm validation): both are
submission tooling that sits **outside** the cryptographic module boundary.

This document is RFC-lite — problem, constraints, approach, decisions, and the
questions deferred to the first attended demo-server run. It records the design
as built; the public API surface itself is catalogued in the LAMA manifest
(`docs/llm-api-manifest/llm-api.yaml`), and release history in `CHANGELOG.md`.

## Problem

An SP 800-90B entropy source is validated by submitting, over ESVP, a
registration describing the noise source and its conditioning, then uploading
the raw-noise and restart data files the server assesses, plus supporting
documentation, and finally requesting certification. The protocol is a
sequence of authenticated REST resources with a strict envelope, a 30-minute
bearer token, a bulk token-refresh step, multipart data-file uploads with an
interoperability-sensitive field spelling, a multi-status processing poll, and
several exactly-one cardinality constraints at certify time.

Two properties make a purpose-built client worthwhile over ad-hoc scripting:

1. **Credential cost.** Every live interaction consumes an attended,
   credentialed session (mutual TLS, a PIV-gated client certificate, a TOTP
   second factor). A malformed payload or an out-of-spec data file discovered
   *on the wire* wastes that session. The client must validate everything it
   can **offline, before any server contact**.
2. **Correctness under one lab review.** The values the client emits —
   principally the claimed per-sample min-entropy and the data-file
   dimensions — are what a validation lab and NIST review. They must be exact
   and internally consistent with the module's own measured entropy.

## Constraints and invariants

The design is bound by the ESVP wire contract (transcribed from the NIST
reference server and client, repository `usnistgov/ESV-Server`, commit
`59e0438`), the SP 800-90B data-file conventions, and the module's own
entropy-source scaffolding (`oxicrypt-entropy`). The verifiable invariants:

- **Attended credentials never enter the tooling.** The TOTP secret is read
  from standard input, never from `argv` (world-readable via `/proc`, and it
  lands in shell history) or the environment; the PIV PIN is handled entirely
  outside the client. The library computes and validates; the credentialed run
  is a separate attended step.
- **Zero third-party dependencies, zero new transport.** ESVP §2
  authentication is near-identical to ACVP: the same versioned-array envelope,
  mutual-TLS transport, RFC 6238 TOTP (30-second step, 8 digits, HMAC-SHA-256
  computed with the module's own HMAC), a 30-minute JWT, and bearer
  authorization on every non-login endpoint. `esv-harness` therefore builds
  *new resources over a proven transport*: it depends on `acvp-harness` as a
  library and reuses its `curl(1)`/mutual-TLS transport, TOTP generation, JSON
  codec, proactive-refresh margin, and reactive-retry decision. ESVP adds
  exactly one mechanism ACVP lacks — **bulk refresh**, one POST that refreshes
  an array of per-object tokens in a single TOTP touch, for certify-time
  freshness.
- **`DataFileSampleSize` is capitalized.** Server v1.8 expects the field
  capitalized; case-insensitivity begins only at server v2.0. The client never
  assumes case-insensitivity.
- **Data-file dimensions are fixed.** Each uploaded data file carries exactly
  1,000,000 one-byte-per-sample symbols, each symbol within the effective
  `min(bitsPerSample, 8)` width. The restart file is the SP 800-90B §3.1.4.1
  1000 × 1000 layout (1000 restarts × 1000 samples = 1,000,000). These are the
  same constants the module's dataset emitters produce against
  (`oxicrypt_entropy::sp800_90b::RAW_DATA_SAMPLE_COUNT`, `RESTART_ROUNDS`,
  `RESTART_SAMPLES_PER_ROUND`), so the validator and the emitter cannot drift.
  The reference client applies one 1,000,000-byte size check to raw-noise and
  restart files alike.
- **`hminEstimate` is exact, with no float on the claim path.** The module
  represents min-entropy as an exact fixed-point value in 1/256-bit steps
  (`oxicrypt_entropy::h::MinEntropy`). Every such step is a dyadic rational
  `n/256`, so it is finitely representable in decimal; the client serializes it
  with pure integer arithmetic — never through an `f64` — bounded by the schema
  rule `0 <= hminEstimate <= bitsPerSample`.
- **Vetted conditioning uploads no conditioned bits.** For a vetted
  conditioning component (the module's SHA2-256 hash), a conditioned-bits data
  file is neither expected nor uploadable; attempting one is a typed refusal,
  never a request placed on the wire.
- **Certify cardinality.** A certification carries exactly one EAR and exactly
  one PUD supporting document, at most one data-collection attestation, and the
  cross-program ACVTS `moduleId` and per-assessment `oeId` (a CAVP validation
  of the conditioning hash, and an ACVTS module/OE registration, both precede a
  real certify — hard external dependencies, surfaced as typed preconditions).

These invariants correspond to the entropy-source ISA's ESVP criteria: the
authentication and refresh flow, the registration payload and its offline
preflight, the multipart upload and status poll, the vetted-upload refusal, the
exact `hminEstimate` serialization, and the offline payload-and-file preflight.

## Approach

`esv-harness` is a workspace member with a thin binary over a library, so every
request builder and response parser is a pure function exercised against
fixtures with no network. The library modules mirror the ESVP resources:

- **Authentication** — the versioned login body, single-token refresh, and the
  bulk refresh, with a fail-closed access-token parser stricter than the ACVP
  one (ESV responses are always the versioned envelope) and a tunable proactive
  refresh margin so it can be aligned to the measured ESV token TTL.
- **Registration** — the entropy-source metadata payload builder (multi-OE via
  `numberOfOEs`, the vetted SHA2-256 conditioning entry with its CAVP
  validation number as required configuration, `iidClaim: false`,
  `physical: false`), the wire serializer, and the multi-OE response parser
  (one assessment object per operating environment, each with its data-file
  URLs and a scoped token).
- **Preflight** — offline validation, in two halves. The **payload** half
  transcribes the machine-checkable rules of the vendored NIST metadata schema
  and drift-guards every transcribed constant back against that vendored file,
  so a transcription mistake fails a test rather than shipping. The **file**
  half validates a data file against the dimension, symbol-width, restart-layout,
  and `DataFileSampleSize`-consistency constraints above, checked against the
  module's own cited constants. Both run before any server contact.
- **Data files** — the multipart upload builder (the `dataFile` binary part and
  the capitalized `DataFileSampleSize` field, in reference-client order), a
  provably non-colliding boundary generator, and the processing-status polling
  state machine over all seven documented statuses. The poll is bounded on the
  consecutive not-yet-processed count, a total-poll ceiling, and a
  consecutive-transient-failure budget; it captures NIST's returned assessment
  on success as a second, independent entropy-assessment oracle. Because that
  assessment carries fractional min-entropy numbers the integer-only shared
  codec cannot read, the status envelope is parsed by a small lossless
  JSON reader that captures every number as its exact source token, and the
  assessment body is retained verbatim.
- **Supporting documents** — the §6.2 upload with a fail-closed PDF-only guard
  and the supporting-document-type enumeration, over the shared multipart
  encoder so the two upload paths cannot drift.
- **Certify** — the full-submission, add-operating-environment, and update-PUD
  request builders, enforcing the cardinality and required-identifier
  constraints at construction.
- **Session store** — a per-submission directory with an append-only,
  intent-then-outcome log, so a fresh process can reload exactly where a
  submission stands (registered / files-uploaded / docs-uploaded / certified)
  and resume. Each server-facing step records **two** log lines: an *intent*
  carrying only locally-known data (what is about to be attempted) that
  genuinely persists *before* the network call, then an *outcome* built from
  the response, appended after. Both are single buffered newline-terminated
  writes, each fsync'd, so durability holds against power loss. On resume an
  outcome supersedes its preceding intent — a completed step reconstructs
  cleanly — while an intent with **no** following outcome is a *dangling
  intent*: the action may have taken effect on the server but was never
  confirmed, so it is surfaced as an **interrupted** state (verify before
  retrying) rather than blindly re-submitted, closing the response-to-record
  crash window that a single persist-before-submit event could not. A torn
  final line (the residue of a crashed append) is tolerated: it is dropped and
  recorded, the earlier records replay intact, and the next append heals it so
  a retry can never concatenate onto a partial record. A duplicated
  registration replay is deduplicated by assessment id, and every path
  component derived from outside input is validated so it cannot escape the
  submission directory.

Three state machines carry the judgment content and are frozen: the **token
lifecycle** (login → JWT → proactive margin refresh → one reactive
refresh-and-retry → bulk refresh before certify), the **data-file lifecycle**
(preflight → upload → poll to a terminal state, every result persisted), and
the **submission lifecycle** (register per OE → data files → supporting docs →
certify precondition check → certify or add-OE), resumable at every step.

Fixtures are shaped from the reference client's request code and the protocol's
example bodies; every unit check runs against fixtures or synthetic responses,
so no live server and no credentials are ever needed in an automated run. The
one vendored schema is carried in-tree with its source commit recorded. A live
demo-server run is a separate attended step with wrapper scripts built and
integrity-signed immediately before use, one submission per session.

## Decisions

- **D1 — crate placement.** `esv-harness` is a new workspace member depending
  on `acvp-harness` as a library, rather than an extracted shared transport
  crate or a subcommand family inside `acvp-harness`. It disturbs the proven
  CAVP path not at all, duplicates no code, and keeps the two ceremonies'
  blast radii apart. A shared-transport extraction is deferred until both
  harnesses are stable (revisit when a combined RBG track genuinely spans both
  servers). Being out-of-boundary, like `acvp-harness`, it needs no boundary
  accounting change.
- **D2 — the vetted conditioning validation number is required configuration.**
  A vetted conditioning component must supply the CAVP validation number of its
  algorithm's validation. The metadata schema does not carry that field, so it
  cannot police it; the builder makes it a typed construction requirement (no
  default), and the preflight independently catches its absence. The concrete
  value depends on the module's own CAVP validation of the conditioning hash — a
  known hard dependency that precedes any real certify.
- **D3 — the CLI mirrors the ACVP harness.** The subcommand shape follows the
  ACVP harness, with the same attended wrapper-script tradition for the live
  run. The offline builders are exposed as utilities that never touch the
  network.
- **D4 — public-item exposure over transport extraction.** Making the needed
  `acvp-harness` transport, TOTP, and JSON primitives public (with manifest
  entries) is cheaper and lower-risk than refactoring the proven transport into
  a shared crate now; the extraction is revisited only if a combined track
  requires it.

## Deferred — resolved at the attended demo run

Several details are wire-affecting or unproven against the current demo server
and are deliberately built as tunable or tolerant, flagged for empirical
confirmation at the first attended demo-server run:

- **Registration validation number for demo dry-runs.** What the demo server
  accepts in the conditioning `validationNumber` before a real CAVP number
  exists — a demo-issued number, an accepted placeholder, or deferring
  registration-with-conditioning — is resolved empirically; the field is
  required configuration with no default.
- **`numberOfOEs` on the wire.** The protocol digest has the client *set*
  `numberOfOEs`; the reference client instead omits it and registers per OE.
  The builder carries it as optional (present emits it, absent omits it) and the
  response parser handles the multi-OE array either way; which shape the demo
  server wants is confirmed at the smoke.
- **Poll and retry intervals.** The not-yet-processed and processing waits
  default to the digest's 30 seconds but are tunable, to align with whatever the
  upgraded demo server actually uses (the reference client uses shorter waits).
- **The restart data-file slot's presence.** The registration-response parser
  tolerates a missing `restartTestBits` slot rather than requiring it, because
  the exact per-OE slot set the demo server returns is unproven; it is tightened
  to required only if the server confirms it.
- **Envelope tolerance.** A trailing extra envelope element is tolerated as
  additive server variance rather than rejected.

## References

- NIST reference server and client: `usnistgov/ESV-Server`, commit `59e0438`
  (metadata schema, server-side rule scripts, reference client request code,
  the 1,000,000-byte data-file size check).
- SP 800-90B — entropy-source requirements, including the §3.1.4.1 restart
  test dimensions and the vetted-conditioning-component definition.
- SP 800-90C — the full-entropy input margin for the conditioning component.
- `oxicrypt-entropy` — the module's entropy-source scaffolding, whose
  fixed-point min-entropy type and SP 800-90B constants this client serializes
  and validates against.
