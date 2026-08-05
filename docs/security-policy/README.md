# Security Policy — withheld from this repository

Documentation elsewhere in this tree points at `security-policy.md` sections (§1 boundary
accounting, §3.1 FFI surface, §9.2 `forbid(unsafe_code)` accounting, and the IG conformance
judgments). **That document is not here, and its absence is deliberate.**

## Why

oxicrypt's source is open under Apache-2.0 OR MIT. The FIPS 140-3 Security Policy is not, because
the two are separable things. The code is standards-based mathematics that anyone can read,
reimplement, and check. The Security Policy is the artifact that turns a codebase into a
near-submission-ready certification package: the cryptographic boundary definition, the finite
state machine, the SSP lifecycle and zeroization points, the self-test completeness argument, the
side-channel posture, and the Implementation Guidance conformance judgments.

Non-publication is the right instrument for that and a license is the wrong one — a license cannot
protect a document whose value lies in being withheld, and a published document cannot be
un-published.

The bounds are worth stating honestly rather than overselling. The protection is **time-boxed**:
CMVP publishes every validated module's Security Policy, so this one becomes public at oxicrypt's
own validation. And it is **friction, not a wall**: validated Security Policies are a public corpus
that a competent CST lab already draws on. The durable protections are the certificate listing, the
trademark, relationships, and dated authorship — not this.

## Requesting access

The document is held in a private repository, and access is granted per person as a repository
collaborator — CST lab reviewers, CMVP contacts, and funders in a serious conversation. Open an
issue or contact the maintainer; being granted access there implies no access to anything else, and
requires no build tooling to read.

## For a provisioned checkout

The tests in `tools/doc-guard` assert that the Security Policy's stated numerals still match the
workspace as built. They resolve the document at runtime and **skip** when it is unreachable, so a
clone without it runs green with no configuration at all — you do not need to set anything to build
or test this repository. If you do have the document:

```sh
export OXICRYPT_SECURITY_POLICY=~/repos/oxicrypt-policy/security-policy.md
cargo test -p doc-guard
```

Resolution order:

1. `$OXICRYPT_SECURITY_POLICY` — the file itself, or a directory containing `security-policy.md`.
2. `~/repos/oxicrypt-policy/security-policy.md` — the default sibling-clone path.

This is the same shape as the SP 800-90B reference datasets (`$OXICRYPT_EA_DATA`, falling back to
`~/repos/SP800-90B_EntropyAssessment/bin`), because a skip that leaves no trace is indistinguishable
from a check that passed — `doc_guard::tests::security_policy_is_provisioned` exists to say the
difference out loud.

It differs from the dataset gate in one deliberate way. Those datasets are public, so failing when
they are absent is right: absence is always a fixable mistake. This document is not obtainable by an
outside contributor at any price, so failing on *its* absence would only put back, as a single
failure, the hard failures that removing it from the tree exists to prevent. The gate therefore
fires on a **claim**, not on absence:

| Your situation | What happens |
|---|---|
| You do not have the policy | Passes, with a note. Nothing to configure. |
| `$OXICRYPT_SECURITY_POLICY` is set but wrong | **Fails** — you named a path and it is not there |
| The clone directory exists but the file does not | **Fails** — you have the clone, something is wrong |
| You have it | Passes, and all five guards assert against it |

If you want to silence it explicitly — a scripted environment, say — set
`OXICRYPT_SECURITY_POLICY_OPTIONAL=1`. Nothing else in the workspace needs it: the five guards it
governs assert the *document's* prose, not the code's behaviour, and every claim about the module
itself is tested independently of them.

## What is not checked without it

For the record, so a green run is not read as more than it is. These skip when the policy is
absent:

| Guard | What it asserts |
|-------|-----------------|
| `policy_states_the_alpha_values_the_code_implements` | §9.x α default and recommended range match `Alpha::DEFAULT` and the SP 800-90B constants |
| `alpha_means_the_same_thing_in_the_policy_and_the_crate_doc` | The policy and `oxicrypt-entropy` agree on what α *is* |
| `every_cited_resolution_is_named_somewhere_a_reviewer_can_reach` | Every IG resolution cited by a criterion is named where a reviewer can find it |
| `policy_carries_no_new_unresolved_drafting_markers` | The document is not accumulating `TODO` / `[… pending]` text |
| `policy_states_the_as_built_accounting` | §1 / §3.1 / §9.2 crate counts match the workspace on disk |

The equivalent assertions against `AGENTS.md` and `README.md` — the same crate counts, the same
audited-exception set — run for everyone, so boundary-accounting drift is still caught in a public
clone.
