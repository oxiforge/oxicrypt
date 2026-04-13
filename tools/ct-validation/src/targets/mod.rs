//! Wire-up of oxicrypt primitives into the paired-measurement harness.
//!
//! Every target module exposes a single `run(cfg)` function that
//! builds a [`crate::measure::TargetFn`] closure over a pre-allocated
//! piece of public context (e.g. a Montgomery `ctx`, a P-256 base
//! point), chooses a fixed secret, and calls [`crate::measure::run_target`].
//!
//! The "public context" is deliberately set up once before the loop
//! so its construction cost doesn't show up inside any measurement.

pub mod ecdh_cdh;
pub mod ecdsa_scalar_invert;
pub mod ecdsa_scalar_mul;
pub mod eddsa_scalar_mul;
pub mod oaep_decode;
pub mod rsa_mont1024_pow_secret;
pub mod rsa_mont2048_pow_secret;

use crate::measure::RunConfig;
use crate::stats::VerdictReport;

/// Canonically-ordered list of every target this harness knows
/// how to measure. Useful for `--help` output and for iterating
/// over all targets in the default binary run.
#[must_use]
pub fn all_target_names() -> &'static [&'static str] {
    &[
        "rsa_mont2048_pow_secret",
        "rsa_mont1024_pow_secret",
        "rsa_oaep_decode",
        "ecdsa_p256_scalar_mul",
        "ecdsa_p256_scalar_invert",
        "ecdh_p256_cdh",
        "eddsa_ed25519_scalar_mul",
    ]
}

/// Run a target by name, or return `None` if the name isn't known.
#[must_use]
pub fn run_by_name(name: &str, cfg: &RunConfig) -> Option<VerdictReport> {
    match name {
        "rsa_mont2048_pow_secret" => Some(rsa_mont2048_pow_secret::run(cfg)),
        "rsa_mont1024_pow_secret" => Some(rsa_mont1024_pow_secret::run(cfg)),
        "rsa_oaep_decode" => Some(oaep_decode::run(cfg)),
        "ecdsa_p256_scalar_mul" => Some(ecdsa_scalar_mul::run(cfg)),
        "ecdsa_p256_scalar_invert" => Some(ecdsa_scalar_invert::run(cfg)),
        "ecdh_p256_cdh" => Some(ecdh_cdh::run(cfg)),
        "eddsa_ed25519_scalar_mul" => Some(eddsa_scalar_mul::run(cfg)),
        _ => None,
    }
}
