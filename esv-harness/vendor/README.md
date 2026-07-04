# Vendored NIST ESV reference material

Files here are copied **verbatim** from the NIST reference ESV server so that
`esv-harness`'s offline preflight validates registration payloads against the
authoritative schema without a network fetch or a build-time dependency on an
external checkout. Do not edit them; re-vendor from upstream and update the
citation below when NIST publishes a new revision.

## `entropy-source-metadata-schema.json`

- **Upstream repo:** `usnistgov/ESV-Server` — <https://github.com/usnistgov/ESV-Server>
- **Upstream path:** `client/jsons/entropy-source-metadata-schema.json`
- **Pinned commit:** `59e0438` ("Update Entropy Source Validation Protocol.md")
- **SHA-256:** `7894e9edf5ade54e39b2bf69b2513c2d34b9940734e0c52eaa78fa890f137c15`
- **Schema dialect:** JSON Schema draft-07.

It describes the two-element versioned envelope of an entropy-source metadata
submission: element 0 is `{esvVersion:"1.0"}`; element 1 is the metadata object
(`primaryNoiseSource`, `iidClaim`, `bitsPerSample`, `hminEstimate`, `physical`,
`numberOfRestarts`, `samplesPerRestart`, `additionalNoiseSources`, and an
optional `conditioningComponent[]`).

`src/preflight.rs` transcribes this schema's machine-checkable constraints into
a Rust constant table and holds a drift-guard test that re-derives those
constraints from this vendored file — so a hand-transcription mistake fails the
test rather than shipping silently.

## Not vendored (deferred by design)

`validation_rules/` (NIST's server-side `RuleScript` / `ValidationTree` DSL) is
**not** vendored. The esv-harness preflight does not execute that DSL — it would
require a rule interpreter, and the file-checking half of preflight is a later
slice (S5). The two vetted-conditioning semantic constraints the metadata schema
does not itself carry — that a vetted component's `description` is a recognized
ACVTS algorithm name and that a vetted component supplies a CAVP
`validationNumber` — are transcribed with citations to the specific upstream rule
scripts (`RuleScripts/Rules/RegisterRequest/ConditioningComponent/Vetted/description.json`
and `.../Vetted/validationNumber.json`, same pinned commit) and to the ESVP
protocol digest, rather than by executing the DSL.
