# Algorithm testing evidence

This directory publishes the record of oxicrypt's algorithm testing against NIST's **ACVP
demonstration server**.

## What this is, and what it is not

`acvp-demo-evidence.json` lists **every vector set submitted for grading — passing and failing
alike** — identified by the **test session ID** and **vector set ID** NIST itself issued, together
with the algorithm, mode, revision, verdict and grading date. Failures are published alongside
passes so the denominator is visible rather than implied: **154 vector sets graded, 141 passed, 13
failed.**

**It is not a certificate.** These results come from NIST's *demonstration* server. That server runs
the same protocol and the same test-vector generators as the certification path, but it issues no
certificate and confers no validation status.

**oxicrypt holds no CAVP algorithm certificate and no FIPS 140-3 module certificate.** Nothing here
should be read as claiming otherwise. The project is targeting validation; it has not been submitted
to a testing laboratory.

## Why the raw transcripts are not published

The harness writes a full transcript for every session. Those transcripts are **not** in this
repository and will not be: every session registration embeds an account access token whose payload
carries personal identifying data in cleartext. The file here is the derived, scrubbed record —
NIST's identifiers and verdicts, and nothing else.

## What these identifiers let a reader do

Being exact about this matters, because the obvious reading is wrong. These rows are **attestable,
not re-queryable by a third party.** ACVP test sessions expire thirty days after creation and most
of these are long past that; session URLs are also scoped to the account that created them, so
another party's demonstration-server credentials reach their own sessions, not these.

What the identifiers give a reader is the ability to put a specific, falsifiable question to NIST or
to a testing laboratory about a named session, and to hold this record against any future
certification submission. That is weaker than "re-run it yourself" and stronger than an unsourced
number.

## What is reproducible from this file, and what is not

A per-case count is recomputed from the retained verdict body where one exists, and **omitted rather
than estimated where it does not**. Two cuts of that limit, because the second is sharper and should
not have to be discovered:

- By vector set: 81 of 154 graded sets carry a reproducible count (76 of the 141 passing ones).
- **By algorithm: only 16 of 59 carry any reproducible count at all**, and the 43 that do not
  include the high-volume symmetric and hash families.

The `summary` block therefore reports what this file proves and nothing more. It does **not** restate
the project's overall test-case total, because that total is not reconstructible from this record.

Note also that the algorithm count here is *distinct ACVP algorithm registrations*, a finer unit than
the algorithm-family count quoted elsewhere in the project. Different units, not competing figures.

## Regenerating this record

After a graded ACVP session, three steps, in order:

```sh
scripts/extract-acvp-evidence.py <transcripts-dir>   # rebuild the JSON from raw transcripts
scripts/gen-acvp-evidence-md.py                      # re-render ACVP-EVIDENCE.md from the JSON
scripts/check-acvp-evidence.py                       # validate (also runs in CI)
```

The transcript directory is deliberately **not** in this repository and must never be added to it:
every session registration embeds an account access token whose payload carries personal identifying
data in cleartext. The extractor is the scrub — it reads those transcripts and emits only
NIST-issued identifiers, verdicts and counts. It refuses to write if anything credential-shaped
survives into its output, and it verifies that refusal against a planted string on every run.

Because the record is derived rather than transcribed, it cannot drift the way a hand-maintained
table does. The extractor is reproducible: re-running it against the same transcripts reproduces the
committed JSON byte for byte.

## Integrity checking

`scripts/check-acvp-evidence.py` runs in CI and does three things.

1. **It re-derives every published figure from the rows.** All eleven `summary` fields and the
   top-level `algorithms` list are recomputed from the `sessions` array; any disagreement fails the
   build, and nothing may appear in `summary` that is not derived this way.
2. **It rejects credential- and identity-shaped strings** — JWTs, token and key names, PEM blocks,
   e-mail addresses, POSIX and Windows user paths — against both the raw file *and* every decoded
   string in the parsed document. The second half matters: `\/home\/user` and `eyJ`
   are ordinary JSON escapes that many writers emit by default, and a raw-bytes scan never sees them.
3. **It pins the honesty statements** so the demonstration-server caveat and the no-certificate
   sentence cannot be removed, gutted, or inverted into an affirmative claim.

Each leak pattern is exercised against a planted string on every run, because a guard that has
silently stopped matching reads exactly like a clean file.

**What this cannot do.** These are consistency and hygiene checks, not attestation. A record whose
rows and summary agree can still be wrong — deleting rows and recomputing the summary produces a
file that passes every check here. No local check can close that gap; only NIST can confirm a
grading, which is why every row carries the identifiers needed to ask.
