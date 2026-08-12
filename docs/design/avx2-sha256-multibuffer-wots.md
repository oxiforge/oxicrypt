# Design: AVX2 8-way multi-buffer SHA-256 for SLH-DSA WOTS+ chains

**Status:** Decided 2026-06-25 — **wontfix.** #113 is closed as not-worth-the-unsafe on SHA-NI hosts (see Recommendation). This doc persists as the design-of-record for that decision. Revisit only on a measured SHA-NI-vs-multibuffer crossover on real WOTS+ traffic, or a validated AVX2-capable-but-SHA-NI-less target.
**Relation to siblings:** This mirrors `docs/design/avx2-keccak.md`, the design-of-record for
the AVX2 4-way Keccak epic (#110). That epic was given a design doc first because its
Option-A-vs-B analysis was load-bearing; #113 ("SLH-DSA batched WOTS+ hash chains via AVX2
lanes") is a build item with the same shape and needs the same treatment before anyone builds
it. Where `avx2-keccak.md` weighed a drop-in single-state path against a batched path, this doc
weighs an AVX2 *batching* path against an **already-shipped hardware single-stream path
(SHA-NI, `oxicrypt-sha-accel`)** — and that is the whole question.

## Problem

WOTS+ hash chains dominate the wall-clock of SLH-DSA keygen and signing. Each WOTS+ chain is a
sequence of up to `w − 1 = 15` applications of the tweakable hash `F`, there are `LEN` chains per
WOTS+ instance (35 for the 128-bit sets, more at higher levels), and SLH-DSA evaluates **many**
independent WOTS+ instances per signature (one per hyper-tree-layer node touched, `d` layers, plus
the FORS leaves). For the SHA-2 parameter family `F` is a single-block **SHA-256** compression
(verified below). SLH-DSA sign/keygen therefore issues *tens of thousands* of independent
single-block SHA-256 evaluations. Accelerating that one primitive is the obvious lever.

AVX2 8-way multi-buffer SHA-256 is the standard SIMD technique for this: run eight independent
SHA-256 message schedules + compression rounds in parallel, one per 32-bit element of a 256-bit
lane. The arc / roadmap item #113 proposes a new auditable-unsafe crate mirroring
`oxicrypt-sha-accel` / `oxicrypt-keccak-accel`, plus a batched WOTS+ caller that feeds it
8 chains at a time.

**The catch — and the reason this needs design, not a build:** this host (and every host the
module targets that has SHA-NI) *already* accelerates single-stream SHA-256 in hardware via
`oxicrypt-sha-accel`. AVX2 multi-buffer is a batching technique that competes directly against
SHA-NI on the same workload. So the load-bearing question is not "is AVX2 multi-buffer faster
than scalar SHA-256" (it is) but **"does AVX2 8-way multi-buffer SHA-256 beat SHA-NI
single-stream for WOTS+, by enough to justify a sixth auditable-unsafe SIMD crate?"** If SHA-NI
already saturates the chains, the multi-buffer surface does not pay for its unsafe.

## Key architectural facts (verified 2026-06-24)

1. **Where the chains live.** WOTS+ is in `oxicrypt_slh_dsa::slh_dsa_impl`, emitted per-variant by
   the `slh_dsa_impl!` macro. The chain primitive is `chain(pk_seed, adrs, x, start, steps)`
   (`slh_dsa_impl.rs:859`): a `for j in start..start+steps` loop, each iteration
   `tmp = f(pk_seed, adrs, &tmp)`. `wots_pk_chain` / `wots_sign_chain` compute one full chain;
   `wots_pkgen` / `wots_sign` sweep `LEN` chains into disjoint output slots.

2. **The chain step `F` is SHA-256 for *every* SHA-2 parameter set.** This is the crucial fact.
   `__emit_f!(sha2)` (`slh_dsa_impl.rs:221`) hashes `PK.seed ‖ pad256 ‖ ADRSc ‖ M₁` with a literal
   `Sha256` — **not** the `ShaLong` alias. Only `H`, `T_l`, `PRF_msg`, `H_msg` switch to SHA-512
   at `n ∈ {24, 32}` (the `__sha2_long_setup!` `ShaLong` alias, `slh_dsa_impl.rs:126`); `F` and
   `PRF` are always SHA-256 (`f` at :221, `prf` at :338, both literal `Sha256`). Since the WOTS+
   chains are built *entirely* from `F`, **a single 8-way SHA-256 multi-buffer kernel accelerates
   the WOTS+ chains of all six SHA-2 parameter sets** (128s/f, 192s/f, 256s/f) — `n` only changes
   the truncation length of the 32-byte digest, not the compression. A SHA-512 multi-buffer kernel
   would be needed only for the *non-WOTS+* hashes (`H`/`T`) at 192/256, which is out of scope for
   #113.

3. **`F` is exactly one SHA-256 block.** The input `PK.seed (n) ‖ pad256 (64−n) ‖ ADRSc (22) ‖
   M₁ (n)` is `n + (64−n) + 22 + n = 86 + n` bytes for `n=16` → 102 bytes... but note `pad256 =
   64 − N` (`slh_dsa_impl.rs:160`) pads `PK.seed` to a 64-byte block boundary, and ADRSc is the
   compressed 22-byte address; with SHA-256 padding this is a small fixed number of blocks per
   param set, identical across every `F` call within a set. The point for batching: every `F` call
   in a sweep has the **same input length and block count**, so 8-way lockstep multi-buffer (which
   requires equal-length inputs per batch) maps onto it cleanly — no ragged-tail handling.

4. **The batchable unit is *across independent chains*, not within a chain.** Inside one
   `chain`, step `j+1` consumes step `j`'s output — a hard serial data dependency (`tmp = f(.., &tmp)`,
   :870). So no parallelism exists *within* a chain. The independence is *across* the `LEN` chains of
   a WOTS+ instance (and across WOTS+ instances): `wots_pk_chain(.., i)` is documented as "a pure
   function of `(pk_seed, sk_seed, adrs, i)` with no cross-chain state" (:901), and the existing
   `parallel` (rayon) feature already exploits exactly this axis with `par_chunks_mut().enumerate()`
   (:935). **This is the same finding as tonight's LMS analysis (#108): the parallel axis is the
   independent siblings, not the internal chain.** A multi-buffer batch would group 8 chains and
   advance them in lockstep — but the chains have *different lengths* (`wots_sign_chain` runs
   `msg_i` steps, `msg_i ∈ 0..w−1`), so a naïve 8-lockstep wastes lanes on chains that finished
   early. (See open questions: lockstep-to-the-max-length vs work-queue refill.)

5. **The existing SHA-NI single-stream path.** `oxicrypt-sha-accel` wraps `_mm_sha256rnds2_epu32`
   + the message-schedule extensions behind a `#[target_feature]` + CPUID-probe boundary
   (`sha256_compress`, fail-portable, `AtomicU8`-cached detection). It is wired into `oxicrypt-sha`
   behind the default-off `accel-sha` feature. **On a SHA-NI host, every `F` call in a WOTS+ chain
   already runs on the SHA extension unit** when `accel-sha` is on — this is the incumbent the AVX2
   multi-buffer path must beat.

6. **The auditable-unsafe precedent + crate count.** Five readily auditable in-boundary `unsafe` crates exist
   today (`oxicrypt-zeroize`, `oxicrypt-sha-accel`, `oxicrypt-aes-accel`, `oxicrypt-keccak-accel`,
   `oxicrypt-timer`); the security-policy §9.2 accounting and the "22 of 27 `forbid(unsafe_code)`"
   line are stated in those exact terms (`security-policy.md:29`, :2616). A SHA-256 multi-buffer
   crate would be the **sixth**, and §9.2 + the N-of-27 accounting must be updated in the same
   change — exactly as `avx2-keccak.md` notes for its fifth crate.

## Oracle situation (the LMS lesson, applied to SLH-DSA SHA-2)

A multi-buffer kernel changes *how* the WOTS+ `F` evaluations are computed, so it needs a
byte-exact equivalence oracle. **A strong one exists:**

- **Deterministic sigGen.** The SLH-DSA sigGen handler signs deterministically with
  `opt_rand = PK.seed` (`handlers/slh_dsa.rs:14`, advertised `deterministic: [true]`). So for a
  fixed `(sk, msg, ctx)` the entire signature — every WOTS+ chain value in it — is **byte-exact
  reproducible**. Flipping the multi-buffer feature on/off must produce a bit-identical signature.
- **Per-variant power-up KAT.** Each SHA-2 variant module emits a deterministic
  keygen → sign → verify KAT (`slh_dsa_impl.rs:1562`, `kat_passes`), pinned to a fixed seed and
  message. This is a byte-exact ON/OFF oracle *per parameter set*, run by the default test suite.
- **NIST ACVP keyGen/sigGen vectors.** The harness advertises all 12 paramSets for keyGen/sigGen
  with deterministic sigGen; the SHA-2 sets' published ACVP vectors are byte-exact and exercise the
  WOTS+ path a batch would change.
- **Crate-local cross-path oracle (recommended, mirrors keccak-accel).** As in
  `oxicrypt-keccak-accel`'s `x4_matches_scalar_keccak_f1600_on_random_states`, the new crate should
  carry its own test asserting `multibuffer8(inputs) == [scalar SHA-256(inputs[i]); 8]` over
  thousands of random inputs, with the scalar reference being the real `oxicrypt-sha` compression
  (a dev-dependency), never a reimplementation.

**Finding, stated explicitly:** the SLH-DSA SHA-2 parameter sets DO have a real, byte-exact ON/OFF
oracle for the WOTS+ path — deterministic sigGen + per-variant KAT + NIST ACVP vectors. This is
*stronger* than the LMS situation that bit us tonight: there is no nondeterministic signing mode in
play, and the F-function the batch touches is on the critical path of every KAT. A wrong batch
cannot pass green.

## Approach options

### Option A — AVX2 8-way multi-buffer SHA-256, new auditable-unsafe crate + batched WOTS+ caller

A new `oxicrypt-sha-mb` (or `-sha256-mb`) crate exposing
`sha256_compress_x8(states: &mut [[u32; 8]; 8], blocks: &[[u8; 64]; 8]) -> bool` (the
multi-buffer analogue of `sha256_compress`), fail-portable, CPUID-gated on AVX2. Then a batched
WOTS+ caller in `slh_dsa_impl` that groups 8 independent chains and advances them in lockstep,
calling the kernel once per round of 8 chains instead of 8× scalar/SHA-NI `F` calls.

**Upside:** AVX2 8-way multi-buffer SHA-256 is a well-established technique (Intel's multi-buffer
crypto library, Gueron–Krasnov) with strong throughput on machines *without* SHA-NI.

**The problem — SHA-NI is the incumbent on the target host.** On a SHA-NI-capable CPU,
single-stream SHA-256 already runs ~1.5–2 cycles/byte on the SHA extension unit. Published
guidance and benchmarks consistently show that **multi-buffer AVX2 SHA-256 does *not* beat SHA-NI
single-stream on cores that have SHA-NI** — the SHA extensions were designed precisely to make the
multi-buffer trick unnecessary. Multi-buffer wins decisively over *scalar* SHA-256 and over AVX2
single-stream, but against the dedicated hardware instruction it is at best a wash and usually a
loss, because SHA-NI does in two instructions what multi-buffer spreads across many AVX2 ops.
(These are estimates from published multi-buffer-vs-SHA-NI comparisons; flagged as estimates — a
real bench on this host would confirm, but the architectural reason is robust.) So on exactly the
hosts that matter most (modern x86_64 with SHA-NI), Option A delivers **substantial auditable unsafe
for a likely-negative or wash result.** That is the `avx2-keccak.md` Option-A failure mode
repeated: unsafe SIMD for a marginal/uncertain win.

The *only* hosts where Option A could win are AVX2-capable CPUs **without** SHA-NI — a shrinking
population (pre-Goldmont Atom, Haswell/Broadwell/Skylake-without-SHA, older AMD pre-Zen). For those
hosts the CMVP validation-target default already provides correct (portable scalar) SHA-256; the question
is purely throughput on legacy silicon.

### Option B — rely on SHA-NI single-stream (current state + `parallel`); do not build the multi-buffer crate

Do nothing new in unsafe-land. The throughput levers for WOTS+ already exist and compose:

- **`accel-sha` (SHA-NI)** accelerates every `F` evaluation on the dominant host class, single-stream.
- **`parallel` (rayon)** already parallelizes the WOTS+ chain sweep and FORS sweep across cores
  (`slh_dsa_impl.rs:74`, R77), byte-identical to the sequential build.

The combination — SHA-NI per-`F` × rayon across chains/leaves — already captures both the hardware
acceleration and the cross-chain independence that Option A's multi-buffer would target, **without
any new unsafe and without a new crate.** SHA-NI gets the per-hash speed; rayon gets the throughput
across the thousands of independent chains.

### Honest reward/risk comparison on a SHA-NI host

| | Option A (AVX2 multi-buffer) | Option B (SHA-NI + rayon, current) |
|---|---|---|
| Per-`F` speed on SHA-NI host | likely ≤ SHA-NI single-stream (wash/loss, estimated) | full SHA-NI hardware speed |
| Cross-chain throughput | 8-way lockstep, lane waste on ragged chain lengths | rayon across all cores, no lane waste |
| New auditable unsafe | **yes — 6th crate**, §9.2 + N-of-27 update, new CPUID/quarantine/oracle | **none** |
| Caller rewiring | yes (batched WOTS+ sweep, ragged-length handling) | none (already shipped) |
| Win only on | AVX2-without-SHA-NI legacy CPUs | — |
| CMVP surface impact | grows the unsafe-audit footprint for a legacy-only gain | unchanged |

On the host class oxicrypt actually targets, Option B equals or beats Option A while carrying
**zero** new unsafe.

## Constraints / ISC invariants (any implementation must hold)

- **Default build unchanged.** Any `accel-*` feature default OFF, runtime CPUID, portable fallback
  when AVX2 absent; the CMVP validation-target configuration stays the portable single-threaded build.
- **Auditable-unsafe quarantine.** All `unsafe` isolated in one dedicated `no_std` crate, fenced
  behind a `#[target_feature(enable = "avx2")]` boundary with a safe CPUID precondition and an
  `AtomicU8`-cached probe — mirroring `oxicrypt-sha-accel` / `oxicrypt-keccak-accel` exactly. This
  would be the **sixth** readily auditable in-boundary exception; §9.2 of the security policy and the
  "22 of 27 `forbid(unsafe_code)`" accounting must be updated in the same change.
- **Byte-exact equivalence oracle.** Feature ON == feature OFF, bit-for-bit, on: every SHA-2-set
  power-up KAT, every SHA-2-set NIST ACVP keyGen/sigGen vector, and a crate-local
  `multibuffer8 == 8× scalar SHA-256` cross-path test over ≥1000 random inputs (scalar reference =
  real `oxicrypt-sha`, never a reimplementation).
- **No claim-language change.** Accel is a throughput option carrying no validation weight; the
  approved-services and SSP language is untouched.

## Recommendation

**Do not build Option A. Adopt Option B: SHA-NI single-stream + rayon is the WOTS+ acceleration
path, and #113 should be closed as not-worth-the-unsafe on SHA-NI hosts.**

This is the same call `avx2-keccak.md` made about its Option A, for the same reason — but here it
is *more* clear-cut, because Keccak has **no** hardware instruction (so its Option B / 4-way batch
was the only acceleration available and was worth building), whereas SHA-256 **does** have a
hardware instruction that the module already wraps. AVX2 multi-buffer is the technique you reach for
*because* there is no SHA-NI; spending a sixth auditable-unsafe crate to add it *alongside* SHA-NI
inverts that logic. The independent-chain throughput that multi-buffer would capture is already
captured, byte-identically and unsafe-free, by the `parallel` rayon sweep.

**If a future need overrides this** (e.g. a validated target platform that is AVX2-capable but
SHA-NI-less, or a benchmark on real WOTS+-heavy traffic that shows a material multi-buffer win even
*with* SHA-NI), the first slice would be the kernel crate + its cross-path oracle alone (no caller
rewiring), gated and benched against SHA-NI on representative hardware before any WOTS+ caller is
touched — and the build/ship decision made on that measured crossover, not on the multi-buffer
reputation in isolation. Until then, the portable+SHA-NI+rayon stack remains the path.

## Open questions

- **New crate vs extend `oxicrypt-sha-accel`.** If ever built, does the 8-way kernel live in a new
  `oxicrypt-sha-mb` crate (clean per-technique quarantine, matches the keccak-accel split) or as a
  second entry point in `oxicrypt-sha-accel` (one SHA-acceleration crate, two execution units —
  SHA-NI single-stream + AVX2 multi-buffer)? The latter keeps the auditable-crate count at five but
  mixes two unsafe techniques in one audit unit.
- **The SHA-NI-vs-AVX2 throughput crossover** on real WOTS+ traffic — the number that would
  actually justify or kill Option A. Needs a bench on SHA-NI hardware (this host has SHA-NI),
  comparing SHA-NI-per-`F` × rayon against AVX2-multi-buffer-batched, on a representative
  sign/keygen mix. Until measured, the recommendation rests on published multi-buffer-vs-SHA-NI
  guidance + the architectural argument.
- **Ragged chain lengths.** `wots_sign_chain` runs `msg_i ∈ 0..w−1` steps, so an 8-chain batch has
  unequal lengths — lockstep-to-the-max wastes lanes (worst case ~7/8 idle late in the batch),
  while a work-queue/refill scheme complicates the byte-exactness argument. This trade-off only
  matters if Option A is ever revisited.
- **SHAKE parameter sets ride #110, not this.** The six SHAKE SLH-DSA sets build WOTS+ from
  SHAKE-256 `F`, which would batch onto the #110 AVX2 4-way Keccak `Sponge4` once that epic lands a
  caller — a separate, already-justified path (Keccak has no hardware instruction). #113 is
  SHA-2-family only.
- **AVX-512 16-way multi-buffer** as a later tier shares this design and the same SHA-NI-incumbent
  problem (and harder: AVX-512 downclocking). No AVX-512 on this host; not in scope.
