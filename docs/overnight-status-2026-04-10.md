# Overnight status — 2026-04-10

## Summary

Full DRBG chapter closed out: CTR / Hash / HMAC mechanisms all land
under CAVP KATs, health tests, and the SP 800-90A §9.3
prediction-resistance API. Harness is at **113 power-up KATs green**,
clippy clean under `-D warnings` across the whole workspace.

No blockers encountered. No prod code was left in an uncompilable or
untested state at any point; every commit is independently green.

## What landed tonight

Commits (newest first):

- `6e521b8` — **docs: add CAVP traceability table for DRBG KATs** —
  new `docs/cavp-mapping/drbg.md` recording vendored source,
  section, COUNT, line number, and SHA-256 per KAT. Also enumerates
  gaps (prediction-resistance KATs, reseed-only KATs) so the list
  of "what's missing vs. full DRBGVS coverage" is explicit and
  actionable, not buried in source comments.
- `ce12706` — **docs: update plan for IG D.G — CRNGT deferred, PR
  API landed** — see decisions below.
- `f7e6ad4` — **fips-drbg: add SP 800-90A §9.3 prediction-resistance
  generate API** — `generate_pr` / `generate_df_pr` /
  `generate_no_df_pr` wrappers for all three mechanisms, each
  backed by a consistency unit test that asserts
  `generate_pr(e, ai, out) == reseed(e, ai); generate(None, out)`.
  Real CAVP KATs against `drbgvectors_pr_true` remain pending
  vendoring of those vectors.
- `f43e172` — **fips-drbg: add SP 800-90A §11.3 health tests +
  3 power-up KATs** — new `crates/oxicrypt-drbg/src/health.rs` drives
  the four error paths §11.3.2 requires (generate-before-
  instantiate, normal path, reseed-ceiling, post-uninstantiate) for
  CTR_DRBG / Hash_DRBG / HMAC_DRBG. Added `#[doc(hidden)]
  debug_force_reseed_ceiling()` helpers on each DRBG type so the
  ceiling check is deterministic under unit testing.
- `0b94889` — **fips-drbg: implement HMAC_DRBG per SP 800-90A +
  3 power-up KATs** — full §10.1.2 mechanism over HMAC-SHA-256/
  384/512, with the null-case distinction in the Update helper
  wired precisely per §10.1.2.2. CAVP Count=0 passes first try for
  all three digests.
- `220502c` — **fips-drbg: implement Hash_DRBG per SP 800-90A +
  3 power-up KATs** — §10.1.1 mechanism with §10.3.1 Hash_df,
  §10.1.1.4 Hashgen, and the big-endian modular V update. CAVP
  Count=0 passes first try for all three digests.

Harness self-report:

```
Power-up self-tests passed: 113 KAT(s).
```

Full harness KAT inventory is in the committed
`docs/cavp-mapping/drbg.md` for DRBG, and the top-of-crate
`kat.rs` in every other algorithm crate.

## Judgment calls to confirm in the morning

These are places where I exercised my own NIST/FIPS judgment per
your standing directive and want a sanity-check before they go
further.

1. **CRNGT on DRBG output deferred as not required.** The original
   plan listed "CRNGT on DRBG output" as a Phase 2 item with a note
   that it was "required under FIPS 140-3 IG". Reading IG D.G
   (March 2026) carefully, CRNGT-on-DRBG-output was removed as a
   conditional test requirement — SP 800-90A DRBGs don't emit
   duplicate output blocks by design, and the §11.3 error-path
   health tests (which I wired tonight) already cover the DRBG
   health-check line item. SP 800-90B §4.4 entropy-source health
   tests (Repetition Count Test, Adaptive Proportion Test) remain
   required for modules that bundle a noise source, but §4.4 of
   the plan is explicit that oxicrypt does **not** bundle an
   entropy source inside the cryptographic boundary — entropy is
   the caller's responsibility. So I marked the CRNGT item
   deferred with a justification note in §4.2 of the plan and
   updated the Phase 2 checklist. If your read of IG D.G
   disagrees, or if you want a belt-and-braces CRNGT wrapper in
   the code regardless, say the word and I'll implement it as a
   small `crngt` module in `oxicrypt-drbg`.

2. **Prediction-resistance KATs not wired — pending vector
   vendoring.** The §9.3 PR API landed and is covered by
   consistency unit tests (reseed+generate equivalence), but I
   intentionally did not wire any power-up KATs against the CAVP
   `drbgvectors_pr_true` files because those files aren't in
   `vendor/nist/cavp-drbg/` and I don't pull from arbitrary URLs.
   The gap is flagged in `docs/cavp-mapping/drbg.md`. Confirm: do
   you want me to go vendor those files (the usual slim-slice
   strategy, starting from `drbgtestvectors.zip`)? If so, is there
   a preferred way for you to drop them into the workspace, or
   should I plan to pull them from the pinned ACVP-Server commit
   the next time I have a vendoring session?

3. **113 KATs is the new `docs`/`README` number.** I updated
   `README.md`, `docs/rust-fips-project-plan.md`, and the harness
   description string to match, and I verified the harness prints
   "Power-up self-tests passed: 113 KAT(s)." Confirm: is the new
   `CtrDrbg::generate_*_pr` public API the right shape
   (three separate methods, one per variant) or would you prefer
   one unified entry-point that selects on a `df`/`no_df`
   enum/flag? I went with separate methods for clarity and to
   mirror the existing `generate_df` / `generate_no_df` split.

4. **`#[doc(hidden)] pub fn debug_force_reseed_ceiling(&mut
   self)`** is the mechanism I used to make the §11.3 health
   reseed-ceiling check deterministic without waiting 2^48 generate
   calls. It's behind `#[doc(hidden)]`, not gated behind
   `#[cfg(test)]` because the health test module needs it at
   runtime (not just under `cargo test`). A stricter alternative
   would be a crate-private `pub(crate)` method, but then the
   health tests would have to live inside each mechanism module
   instead of their own `health.rs`. Confirm this is acceptable
   for CST-lab eyes. If not, I'll either gate it behind a
   `test-helpers` feature flag or inline the three health
   functions into their respective mechanism modules.

## Next-up candidates (in priority order)

All P0 symmetric + DRBG work is done. The remaining Phase 2 and
Phase 3 items are chunkier and not overnight-bounded. I'd like your
pick before starting one.

- **Ed25519 (oxicrypt-eddsa).** Self-contained in one crate. Needs
  curve25519 field arithmetic (prime `2^255 - 19`, ~400 lines of
  constant-time code with careful 51-bit-limb reduction), Edwards
  point arithmetic with the standard cofactor-8 addition law, and
  SHA-512 already available. CAVP vectors for Ed25519 exist in
  `ACVP-Server/gen-val/json-files/EDDSA-SigGen-1.0`. Could
  realistically land a SigGen+SigVer KAT set in ~2-3 days of
  focused work. Risk: constant-time correctness on the field
  layer needs review.
- **ECDSA P-256 (oxicrypt-ecdsa).** Biggest bang for compliance buck
  (most CAVP-validated ECDSA submissions use P-256). Needs
  constant-time `GF(p256)` field arithmetic, short Weierstrass
  point arithmetic (Jacobian coordinates + scalar mul via
  wNAF or Montgomery ladder), RFC 6979 deterministic-k or §4.1.5
  random-k. ~5x the code of the DRBG chapter. P-384/P-521 follow
  the same skeleton once P-256 is done.
- **RSA PKCS#1 v1.5 / PSS (oxicrypt-rsa).** Needs a fixed-width
  big-integer implementation (2048/3072/4096-bit modular
  exponentiation, Barrett or Montgomery reduction, constant-time
  Miller-Rabin for key generation). This is the longest path —
  keygen in particular per FIPS 186-5 Appendix A is involved.
- **ACVP harness vector dispatch (Phase 3).** The `acvp-harness`
  binary today just runs power-up KATs and prints the inventory;
  it doesn't actually consume ACVP JSON request files. This is
  what eventually gets handed to the CST lab for algorithm
  validation. Could start with a small slice: SHA-256 SigGen
  dispatch only, as a proof-of-concept, then expand.
- **Vendoring additional DRBG vectors** (`drbgvectors_pr_true` and
  `drbgvectors_pr_false`) to tighten DRBG coverage with the API
  that already exists. Smallest of the five options — probably
  half a day.

My default pick if you don't answer before I'm back: vendor the
`pr_true` vectors and wire the 9 missing prediction-resistance
power-up KATs. It's the most bounded and directly closes a gap
I created tonight by landing the PR API without its KATs.

## Workspace state

- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test -p oxicrypt-drbg --lib` — 19 tests, all green
  (6 CTR CAVP, 3 Hash CAVP, 3 HMAC CAVP, 3 PR consistency,
  4 unit tests on internal helpers)
- `./target/debug/acvp-harness` — 113 KATs green + module
  integrity check green
- Branch: `main`, 8 commits ahead of `origin/main`, **not pushed**
  (per your standing no-push directive)
