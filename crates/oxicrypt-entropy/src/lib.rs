//! SP 800-90B entropy-source scaffolding for the oxicrypt module.
//!
//! # Status — read this first
//!
//! **Phase-0 scaffolding.** This crate carries the noise-source abstraction,
//! the fixed-point min-entropy type, the cited SP 800-90B/90C constants
//! module, the approved continuous health tests (RCT + APT with startup
//! gating and permanent failure semantics), a CPU-jitter noise source, the
//! vetted SHA-256 conditioning component, and the pipeline lifecycle. It
//! makes **no entropy or conformance claims**. Nothing in this crate has
//! been assessed by any laboratory or validation program.
//!
//! # Approved services
//!
//! | Service | Standard | Entry point |
//! |---------|----------|-------------|
//! | *(none yet — scaffolding)* | — | — |
//!
//! # Architecture
//!
//! The crate is built around a three-stage pipeline:
//!
//! ```text
//!   NoiseSource  →  health tests (RCT + APT)  →  conditioner
//! ```
//!
//! Three load-bearing design rules, enforced by the types in this crate:
//!
//! 1. **Sources are dumb emitters.** [`source::NoiseSource`] yields
//!    digitized raw symbols plus self-description. Health tests sit
//!    *outside* the trait ([`health`]) so every present and future source
//!    inherits the same battery: RCT + APT on every sample, startup tests
//!    over ≥1024 samples gating first output, on-demand re-testing, and
//!    permanent poisoning on any failure.
//! 2. **Claimed min-entropy is injected at pipeline construction** — it is
//!    an assessment outcome, not a source attribute. The only entropy value
//!    a source declares is its design-anchored *ceiling*
//!    ([`source::NoiseSource::max_claimable_h`]); construction above the
//!    ceiling fails with a typed error ([`error::EntropyError`]).
//! 3. **No floats on the claim or cutoff path.** Min-entropy is exact
//!    fixed-point ([`h::MinEntropy`], 1/256-bit steps); every transcribed
//!    spec value is an integer or exact rational ([`sp800_90b`]).
//!
//! All SP 800-90B/90C numerics live in [`sp800_90b`] — one cited
//! transcription site, fetched-document provenance recorded in that
//! module's docs. Conditioned output is produced by the vetted SHA-256
//! component ([`conditioner`]) under the 90C full-entropy input margin.
//!
//! # Feature graph
//!
//! The crate is `#![no_std]` by default; every `std`-only surface sits
//! behind a named feature, and the default build graph carries no
//! optional dependency.
//!
//! - **`default = []`** — the validation-target configuration: `no_std` core,
//!   no optional dependency. The sealed [`source::NoiseSource`] trait,
//!   [`health`] tests, [`conditioner`], and the cited [`sp800_90b`]
//!   numerics are all available here.
//! - **`std`** — enables the OS monotonic-nanosecond-clock timer surface
//!   (pulls in `std`; brings no third-party dependency).
//! - **`raw-counter`** — enables the serialized raw CPU counter timer via
//!   the readily auditable `oxicrypt-timer` crate (`dep:oxicrypt-timer`), the only
//!   optional dependency.
//! - **`collection`** (= `std` + `raw-counter`) — the off-boundary
//!   raw-data `collection` module tooling backing the `collect` binary;
//!   never part of the validation-target surface.

#![forbid(unsafe_code)]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod conditioner;
pub mod error;
pub mod h;
pub mod health;
pub mod jitter;
pub mod pipeline;
pub(crate) mod raw;
pub mod source;
pub mod sp800_90b;
pub mod timer;

/// `rand_core` 0.9 compatibility shim (behind the default-off `rand-core`
/// feature). Exposes the pipeline's vetted conditioned output as a standard
/// fallible `rand_core::TryRngCore` generator. See
/// [`rand_core_compat::EntropyRng`].
#[cfg(feature = "rand-core")]
pub mod rand_core_compat;

/// Off-boundary raw-data collection tooling (behind the default-off
/// `collection` feature).
///
/// This module exists ONLY to back the off-boundary `collect` binary: it
/// drives [`crate::raw`]'s crate-private collector to write SP 800-90B
/// raw + restart datasets to disk under a versioned layout with a sha256
/// manifest, resumable via a content-hash session checkpoint. It is gated
/// behind the `collection` feature so the default build graph, the library's
/// validation-target surface, and its rustdoc carry **none** of the tooling — and
/// `RawCollector` itself remains crate-private (this module reaches it
/// in-crate; it is never re-exported). The single public entry point is
/// [`collection::run`], which the thin `collect` binary calls.
#[cfg(feature = "collection")]
pub mod collection;

#[cfg(test)]
mod kat_tests;
