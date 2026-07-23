# Design: AVX2 acceleration of Keccak-f[1600]

**Status:** Proposed (design-first) — 2026-06-19. Not yet decomposed into issues.
**Author context:** optimization-arc scoping (`feat/oxicrypt-opt-arc`). This is the first
`docs/design/` epic; it exists because the optimization-arc "AVX2 Keccak for `oxicrypt-xof`"
item was assessed and found to need design, not a single-night build.

## Problem

SHAKE / SHA-3 has no x86 hardware instruction (unlike SHA-2 via SHA-NI or AES via AES-NI), and
Keccak-f[1600] dominates the wall-clock of SHAKE-heavy paths — notably SHAKE-LMS and the
lattice matrix-Â / sampling expansions, which issue large numbers of independent SHAKE streams.
The arc doc proposed an `accel-xof` path mirroring `oxicrypt-sha-accel` / `oxicrypt-aes-accel`.

## Key architectural facts (verified 2026-06-19)

1. **The permutation is shared, not in `oxicrypt-xof`.** The Keccak-f[1600] sponge lives in
   `oxicrypt-sha::keccak::Sponge<RATE>`. `oxicrypt-xof` (SHAKE128/256, cSHAKE, KMAC, TupleHash,
   ParallelHash) is a thin wrapper over it, and `oxicrypt-sha` uses the same sponge for SHA-3.
   So an accel path affects the SHA-3 path too, or must be dispatched from inside the shared
   sponge — it is not an `oxicrypt-xof`-local change.
2. **The API is strictly single-stream:** `new → update* → finalize → squeeze*`. There is no
   batched / x4 surface anywhere.
3. **The accel precedent does not transfer its *value model*.** `oxicrypt-sha-accel` (SHA-NI)
   and `oxicrypt-aes-accel` (AES-NI) wrap *dedicated single-stream hardware instructions* with
   large gains on the existing single-stream API. AVX2 has **no Keccak instruction** — AVX2
   Keccak is a *SIMD batching* technique whose gain is realized only when ≥4 independent
   permutations run together. The crate-quarantine *pattern* transfers; the "drop-in single-
   stream speedup" does not.

## Approach options

### Option A — single-state AVX2 permutation (drop-in, low value)
Vectorize one Keccak-f[1600] state across AVX2 registers behind a `#[target_feature(enable =
"avx2")]` boundary, dispatched from `oxicrypt-sha::keccak::Sponge` by runtime CPUID. Drop-in: no
API change, accelerates every existing SHAKE/SHA-3 caller.

**Problem:** single-state Keccak-f[1600] vectorizes poorly on AVX2. The 25-lane state does not
map onto 4×u64 SIMD without heavy cross-lane shuffles in θ/ρ/π; published single-state AVX2
implementations typically gain little over a good scalar (BMI-rotate) core and sometimes lose.
**Substantial, audited unsafe SIMD for a marginal and uncertain win — fails the reward/risk bar.**

### Option B — 4-way batched permutation `KeccakP1600times4` (high value, needs API)
Run 4 independent sponges in parallel, each of the 25 lanes a `__m256i` holding lane *i* of 4
states. This is the standard high-value AVX2 Keccak and gives near-4× on the permutation. It
maps directly onto the real hot paths: independent SHAKE streams in the LMS leaf sweep, the
lattice matrix-Â expansion, and FORS/WOTS sampling.

**Cost:** requires a **batched sponge API** (`Sponge4` / absorb-4 / squeeze-4 over 4 independent
inputs) in `oxicrypt-sha::keccak`, plus **caller rewiring** to feed it 4-at-a-time (the LMS leaf
sweep and `expand_a` would batch their independent XOFs). No speedup materializes until callers
batch — wiring it under the single-stream API alone gains nothing. This is a multi-component
epic, not a single-night build.

## Constraints / ISC invariants (any implementation must hold)

- **Default build unchanged:** `accel-*` feature default OFF, runtime CPUID, portable fallback
  when AVX2 absent; the CMVP validation-target configuration stays the portable single-threaded build.
- **Audited-unsafe quarantine:** all `unsafe` isolated in one dedicated crate, fenced behind a
  `#[target_feature]` boundary with a safe CPUID precondition — mirroring `oxicrypt-sha-accel`.
  This adds a 5th audited in-boundary exception crate; §9.2 of the security policy and the
  "N-of-26 `forbid(unsafe_code)`" accounting must be updated in the same change.
- **Byte-exact equivalence oracle:** every SHAKE128/256, cSHAKE, KMAC, SHA3-* KAT in
  `oxicrypt-xof` + `oxicrypt-sha` passes byte-identical with the feature ON and OFF; a
  cross-path equality test asserts accel == portable per permutation.
- **No claim-language change:** accel is a throughput option carrying no validation weight.

## Recommendation

Pursue **Option B** as a scoped epic when prioritized — it is the only form that justifies the
audited-unsafe surface — starting with the batched sponge API design, then one caller (LMS leaf
sweep) as the first beneficiary. **Do not ship Option A**: its gain does not justify the unsafe.
Until then, the portable scalar Keccak remains the path.

## Resolved

- **Batched API shape: a distinct concrete `Sponge4`** (not a generic `SpongeN<const LANES>`).
  The AVX2 primitive is `KeccakP1600times4` — exactly four lanes — so the concrete type is the
  hard-to-vary fit; a generic lane count has no caller until an AVX-512 8-way path exists.
- **First caller: lattice `expand_a`** (`oxicrypt-ml-dsa`), not the LMS leaf sweep. `expand_a`
  has ACVP keyGen/sigGen KATs that run feature-on and feature-off — a byte-exact Â oracle for
  the exact path — which the SHAKE-LMS keygen path lacks (sigVer-only KATs). Batching composes
  **with** the `parallel` (rayon) feature independently: `parallel` forks the outer row loop,
  `accel-keccak` batches the inner SHAKE-128 streams 4-at-a-time; all four of
  {`parallel`} × {`accel-keccak`} produce byte-identical Â.

## Open questions

- AVX-512 (`KeccakP1600times8`) as a later tier — shares this batched-API design and is the
  only future lane count that would reopen the `SpongeN<const LANES>` generalization question.
