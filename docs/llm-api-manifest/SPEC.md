# Library API Manifest for LLM Agents (LAMA) — Draft 0.1

A structured YAML format for documenting native library APIs in a way
that AI coding agents can consume without inference or ambiguity.

## Motivation

Human-readable documentation works well for human developers who bring
contextual understanding, domain knowledge, and the ability to infer
unstated constraints. AI coding agents lack these capabilities and
routinely hallucinate API calls, confuse parameter types, miss
preconditions, and generate code that compiles but violates invariants
the documentation assumed the reader would understand.

Existing standards do not address this gap. OpenAPI describes REST
endpoints. MCP describes tool-calling protocols. `llms.txt` provides
web-page discovery for LLM chatbots. None of these formats can describe
a native C, Rust, or C++ library's type system, state machines, memory
ownership rules, sequencing constraints, or security properties in a way
an LLM can parse deterministically.

LAMA fills this gap with a YAML schema designed to be both
machine-parseable by LLM agents *and* human-reviewable by library
authors. YAML was chosen over JSON for human readability (indentation,
comments, multi-line strings) while remaining trivially parseable by any
language or LLM.

## Design principles

1. **Explicit over implicit.** Every constraint that a human would infer
   from context must be stated. If a buffer must be exactly 32 bytes,
   say `size: 32`, not "a key." If a function must be called after
   initialization, list it in `preconditions`.

2. **Declarative, not narrative.** Facts are expressed as structured
   fields, not prose paragraphs. An LLM should never need to parse a
   sentence to extract a parameter type.

3. **Complete per-function.** Every function entry is self-contained.
   An agent should be able to generate a correct call site from a single
   function entry without reading any other part of the document.

4. **Layered detail.** The manifest is organized in layers of increasing
   detail: library metadata → modules → types → functions → parameters.
   An agent that only needs the function signature can stop early; one
   generating error-handling code can go deeper.

5. **Language-neutral.** The schema describes the API's *semantics*, not
   its syntax in any particular language. Bindings for C, Python, Go,
   and Rust can all be generated from the same manifest.

6. **Safety-aware.** Cryptographic and security-critical libraries have
   constraints that general-purpose libraries don't: constant-time
   requirements, zeroization obligations, approved-mode gating, key
   lifetime rules. The schema has first-class support for these.

## Top-level structure

```yaml
lama: "0.1"                    # Schema version (required)

library:
  name: string                 # Library name (required)
  version: string              # Semantic version or commit (required)
  description: string          # One-line purpose (required)
  repository: url              # Source code URL
  homepage: url                # Project website
  license: string              # SPDX identifier or custom
  languages:                   # Languages the library supports
    - rust
    - c
  minimum_toolchain: string    # e.g., "rust 1.94" or "gcc 12"

  # Library-wide constraints an agent must know
  constraints:
    - description: string      # What the constraint is
      enforcement: string      # "compile-time" | "runtime" | "convention"
      severity: string         # "error" | "undefined-behavior" | "warning"

  # Security properties (optional, for crypto/security libraries)
  security:
    certification: string      # e.g., "FIPS 140-3 Level 1 (targeting)"
    threat_model: string       # Brief threat model statement
    side_channel_posture: string  # "validated" | "disclosed" | "none"
    zeroization: string        # "automatic" | "manual" | "none"

state_machines:                # Named state machines (if any)
  - name: string
    description: string
    initial_state: string
    terminal_states: [string]
    states:
      - name: string
        description: string
    transitions:
      - from: string
        to: string
        trigger: string        # Function or event that causes transition
        condition: string      # What must be true (optional)

modules:                       # Logical groupings (crates, packages, headers)
  - name: string
    description: string
    no_std: bool               # Can run without OS (Rust/C embedded)
    depends_on: [string]       # Other modules this requires

types:                         # All types the API exposes
  - name: string
    module: string
    kind: string               # "struct" | "enum" | "alias" | "trait" | "opaque"
    description: string
    size_bytes: int            # Fixed size if known
    fields:                    # For structs
      - name: string
        type: string
        description: string
        constraints: string    # e.g., "must be 0x04 || X || Y"
    variants:                  # For enums
      - name: string
        description: string
    implements: [string]       # Traits/interfaces this type satisfies
    security:
      contains_secret: bool    # Does this hold CSP/key material?
      zeroize_on_drop: bool    # Is it wiped when freed?
      constant_time: bool      # Are operations on it constant-time?

functions:                     # Every public function
  - name: string
    module: string
    description: string        # One line: what it does

    # Full signature in the primary language
    signature: string

    parameters:
      - name: string
        type: string
        description: string
        direction: string      # "in" | "out" | "in-out"
        constraints:
          size: int | string   # Exact byte count or expression
          alignment: int       # Byte alignment if required
          encoding: string     # "big-endian" | "little-endian" | "hex" | "raw"
          valid_range: string  # e.g., "1..=65536" or "non-empty"
          nullability: string  # "required" | "optional" | "nullable"

    returns:
      type: string
      description: string
      error_variants:          # Every possible error and when it occurs
        - name: string
          condition: string    # Exact condition that triggers this error

    # What must be true BEFORE calling this function
    preconditions:
      - description: string
        check: string          # How to verify (function call or assertion)

    # What is guaranteed AFTER a successful return
    postconditions:
      - description: string

    # Functions that must/should be called in relation to this one
    sequencing:
      must_call_before: [string]   # Functions that must precede this call
      must_call_after: [string]    # Functions that must follow this call
      mutually_exclusive: [string] # Cannot be used with these functions

    # Threading and reentrancy
    thread_safety: string      # "thread-safe" | "not-thread-safe" | "send-not-sync"

    # Side effects beyond the return value
    side_effects:
      - description: string

    # Security-specific metadata
    security:
      constant_time: bool      # Is execution time independent of secret inputs?
      handles_secrets: bool    # Does this function touch CSP material?
      fips_approved: bool      # Is this an approved service?
      fips_gate: string        # State machine gate (e.g., "Operational")

    # Canonical usage example (compilable, not pseudocode)
    example:
      language: string
      code: string             # Complete, minimal, correct example

    # Common mistakes an agent should avoid
    pitfalls:
      - description: string
        wrong: string          # What the mistake looks like
        right: string          # What the correct approach is

error_types:                   # All error/result types
  - name: string
    module: string
    variants:
      - name: string
        description: string
        recoverable: bool      # Can the caller retry or work around this?
        user_action: string    # What the caller should do

constants:                     # Named constants the API exposes
  - name: string
    module: string
    type: string
    value: string
    description: string
```

## Key differences from human documentation

| Human docs assume... | LAMA states explicitly... |
|---|---|
| Reader knows what "a key" means | `size: 32`, `encoding: raw`, `contains_secret: true` |
| Reader infers initialization order | `preconditions: [module must be Operational]` |
| Reader notices that GCM needs a 12-byte IV | `constraints: { size: 12 }` on the `iv` parameter |
| Reader understands error handling idioms | Every `error_variant` with its exact trigger `condition` |
| Reader knows not to reuse a nonce | Listed in `pitfalls` with `wrong` and `right` examples |
| Reader reads the security policy | `security.constant_time`, `security.fips_approved` inline |

## Versioning

The `lama` field at the document root carries the schema version.
Breaking changes increment the minor version during the draft period
(0.x) and the major version after 1.0.

## File placement

The manifest should be placed at `docs/llm-api.yaml` (or a similar
well-known path) in the repository root. Libraries may also publish it
alongside their package metadata (e.g., in a crate's `docs/` directory
or as a PyPI package data file).

## Relationship to other standards

LAMA complements, rather than replaces, existing documentation:

- **Rustdoc / Doxygen / JSDoc** — Human-readable API reference. LAMA
  captures the same information in structured form.
- **llms.txt** — Web-page discovery for LLM chatbots. LAMA describes
  the API itself, not the documentation website.
- **OpenAPI** — REST endpoint description. LAMA covers native library
  APIs that OpenAPI cannot express.
- **MCP** — Tool-calling protocol for LLM agents. An MCP server could
  be *generated* from a LAMA manifest.

## Status

This is draft 0.1, developed alongside the oxicrypt cryptographic
library. Feedback and contributions are welcome.
