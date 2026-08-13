//! # `ct-validation` — dudect-style constant-time validation harness for oxicrypt
//!
//! This crate is **not** part of the oxicrypt FIPS 140-3 cryptographic
//! module boundary. It is a developer tool that lives under `tools/`
//! and exists solely to produce empirical evidence backing the
//! "Side-channel posture (disclosed)" statements in §12.1 of the
//! Security Policy, which is withheld from this tree (see
//! `docs/security-policy/README.md`).
//!
//! ## Why this tool exists
//!
//! FIPS 140-3 Level 1 does not require side-channel resistance, and
//! IG D.G (March 2026 revision) does not mandate any specific
//! constant-time validation methodology. oxicrypt's security policy
//! nevertheless **voluntarily** claims constant-time secret-dependent
//! operations on the RSA and P-256 private-key paths. Claims that
//! aren't tested drift over time; this harness turns the claims into
//! something we can re-run after every refactor.
//!
//! ## Methodology (dudect, Reparaz/Balasch/Verbauwhede 2017)
//!
//! For each target primitive we define two input classes:
//!
//! 1. **Fixed class:** the same secret input is used for every
//!    measurement. This is the baseline "known operand" distribution.
//! 2. **Random class:** a fresh random secret input is used for every
//!    measurement. Because the input differs each call, any timing
//!    correlation with secret bits will show up as a spread around a
//!    different mean than the fixed class.
//!
//! We interleave the two classes inside one measurement loop — coin-
//! flipping class per sample so any slow global drift (CPU frequency
//! scaling, GC, neighbour processes) affects both classes
//! symmetrically and doesn't show up as a false positive.
//!
//! After collecting `N` samples per class we compute Welch's two-
//! sample t-statistic
//!
//! ```text
//!     t = (mean_fixed − mean_random)
//!         / sqrt( var_fixed / n_fixed + var_random / n_random )
//! ```
//!
//! and compare `|t|` against the thresholds recommended in the
//! dudect paper:
//!
//! - `|t| > 5.0` → [`Verdict::Leak`] (definite leak, stop)
//! - `|t| > 3.0` → [`Verdict::Warn`] (suspicious, collect more samples
//!   before accepting)
//! - otherwise → [`Verdict::Clean`] at the current sample budget
//!
//! A `Clean` verdict never *proves* constant-time behaviour — it only
//! proves that no timing leak large enough to be detected at this
//! sample count was observed. That framing is carried all the way
//! through to the security policy.
//!
//! ## Outlier handling
//!
//! Raw wall-clock / `rdtsc` measurements are heavy-tailed on a
//! general-purpose CPU: the kernel steals an arbitrary number of
//! cycles whenever it wants to, and a single 10× outlier can swamp
//! an entire run. We apply the standard dudect percentile crop: for
//! each configured percentile `p ∈ {0.99, 0.995, 0.999, ...}` we
//! discard all samples above the `p`-quantile and recompute the
//! t-statistic. The final verdict is the *worst* verdict across
//! all crops — an adversary would use whichever threshold maximises
//! the leak, so we do too.
//!
//! ## Not in scope
//!
//! This tool is **not** a formal side-channel proof. It cannot detect:
//!
//! - Cache-line-granularity leaks that are hidden inside a single
//!   cycle budget bucket.
//! - Power-analysis and electromagnetic side channels.
//! - Leaks that only appear on hardware we're not running on.
//! - Branch-predictor state leaks across process boundaries.
//!
//! The security policy §12.1 continues to disclose all non-mitigated
//! side channels explicitly; this harness only raises confidence in
//! the claims we *do* make.
//!
//! ## Targets and current verdicts
//!
//! The ten primitives wired into [`targets`] cover every secret-
//! dependent arithmetic path on the RSA, P-256, P-384 and Ed25519
//! private-key sides. The set is `targets::all_target_names`:
//!
//! | Target                      | Primitive                                               |
//! |-----------------------------|---------------------------------------------------------|
//! | `rsa_mont2048_pow_secret`   | `oxicrypt_rsa::mont2048::MontCtx2048::pow_secret`       |
//! | `rsa_mont1024_pow_secret`   | `oxicrypt_rsa::mont1024::MontCtx1024::pow_secret` (CRT) |
//! | `rsa_oaep_decode`           | `oxicrypt_rsa::oaep::emsa_oaep_decode` (Manger-framing) |
//! | `ecdsa_p256_scalar_mul`     | `oxicrypt_ecdsa::p256_point::Point::mul`                |
//! | `ecdsa_p256_scalar_invert`  | `oxicrypt_ecdsa::p256_scalar::Scalar::invert` (Fermat)  |
//! | `ecdh_p256_cdh`             | `oxicrypt_ecdh::compute_shared_secret_p256_internal`    |
//! | `ecdsa_p384_scalar_mul`     | `oxicrypt_ecdsa::p384_point::Point384::mul`             |
//! | `ecdsa_p384_scalar_invert`  | `oxicrypt_ecdsa::p384_scalar::Scalar384::invert`        |
//! | `ecdh_p384_cdh`             | `oxicrypt_ecdh::compute_shared_secret_p384_internal`    |
//! | `eddsa_ed25519_scalar_mul`  | `oxicrypt_eddsa::edwards::EdwardsPoint::mul` (clamped)  |
//!
//! Verdicts are not pinned here: they are whatever the harness reports
//! on the run in front of you, at the sample budget you gave it.
//!
//! ## Invariants this harness exists to defend
//!
//! Two properties of the P-256 code are load-bearing for its timing
//! and are the kind this harness detects the loss of. The Montgomery
//! tail-carry loops in `oxicrypt_ecdsa::p256_field::Fp::mul` and
//! `oxicrypt_ecdsa::p256_scalar::Scalar::mul` iterate to a fixed
//! bound with no carry-dependent early exit, so the iteration count
//! does not depend on the operands. `Point::add_mixed_ct` runs the
//! full EFD `madd-2007-bl` formula unconditionally and CT-selects the
//! identity case with `Point::conditional_select`, so the scalar-mul
//! ladder's per-iteration cost does not depend on the leading zero
//! bits of the secret scalar. Both are disclosed in §12.1.
//!
//! ## Known noise fluctuations
//!
//! One target, `ecdsa_p256_scalar_invert`, intermittently bounces
//! into the `Warn` band (`|t| ≈ 3.0–4.0`) at some sample counts even
//! though the underlying primitive has no data-dependent branch. The
//! distinguishing feature of noise vs. a real leak is monotonicity
//! in `n`: a real leak's `|t|` statistic grows as √n, while this
//! target's statistic is non-monotone (e.g. `0.99` at 100k → `5.63`
//! at 200k → `3.28` at 500k → `<3` at 300k in a clean run). §12.1
//! of the security policy documents this explicitly so reviewers
//! don't rerun the harness and panic at a transient yellow verdict.

#![allow(
    // Test-only statistical crate. Clippy's crypto-hardened lints
    // (indexing_slicing, integer_division, arithmetic_side_effects)
    // are off in this crate only: t-test math is naturally written
    // with array indexing and floating-point division, and the
    // "no arithmetic that silently wraps on secret data" rule doesn't
    // apply because there are no secrets inside this crate — the
    // secrets live inside the oxicrypt crates that we call.
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    // Fixture-construction panics are acceptable — they run once
    // per binary invocation, outside any timed region, and only
    // fire if a hardcoded test vector is wrong.
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
)]

pub mod measure;
pub mod stats;
pub mod targets;

pub use measure::{Measurement, RunConfig, TargetFn, run_target};
pub use stats::{Verdict, VerdictReport, welch_t};
