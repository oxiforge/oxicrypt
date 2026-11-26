//! Wire-up of oxicrypt primitives into the paired-measurement harness.
//!
//! Every target module exposes a single `run(cfg)` function that
//! builds a [`crate::measure::TargetFn`] closure over a pre-allocated
//! piece of public context (e.g. a Montgomery `ctx`, a P-256 base
//! point), chooses a fixed secret, and calls [`crate::measure::run_target`].
//!
//! The "public context" is deliberately set up once before the loop
//! so its construction cost doesn't show up inside any measurement.

#[cfg(feature = "fixture")]
pub mod aa;
pub mod aes_gmul;
pub mod cmac_subkey;
pub mod cmac_verify;
#[cfg(feature = "fixture")]
pub mod cmac_verify_leaky;
pub mod ecdh_cdh;
pub mod ecdh_p384_cdh;
pub mod ecdsa_p384_scalar_invert;
pub mod ecdsa_p384_scalar_mul;
pub mod ecdsa_scalar_invert;
pub mod ecdsa_scalar_mul;
pub mod eddsa_scalar_mul;
pub mod ghash;
pub mod kwp_unwrap;
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
        "ecdsa_p384_scalar_mul",
        "ecdsa_p384_scalar_invert",
        "ecdh_p384_cdh",
        "eddsa_ed25519_scalar_mul",
        "ghash",
        "aes_gmul",
        "cmac_subkey",
        "kwp_unwrap",
        "cmac_verify",
    ]
}

/// Whether [`run_by_name`] knows `name`.
#[must_use]
pub fn is_known_target(name: &str) -> bool {
    all_target_names().contains(&name)
        || (cfg!(feature = "fixture") && FIXTURE_TARGET_NAMES.contains(&name))
}

/// The control targets built with the `fixture` feature, run by name
/// only: `cmac_verify_leaky` must report a leak, and `aa` gives both
/// classes the same work and data, the baseline for reading a `LEAK`.
pub const FIXTURE_TARGET_NAMES: &[&str] = &["cmac_verify_leaky", "aa"];

/// Brings the module to `Operational` for a test that calls a target's
/// preflight; a second call in the same process is a no-op.
#[cfg(test)]
pub(crate) fn start_module() {
    const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];
    let _ = oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
}

#[cfg(test)]
#[test]
fn fixture_targets_are_known_only_with_the_feature() {
    for name in FIXTURE_TARGET_NAMES {
        assert_eq!(is_known_target(name), cfg!(feature = "fixture"));
        assert!(!all_target_names().contains(name));
    }
}

/// Run a target by name, or return `None` if the name isn't known.
/// With the `fixture` feature this also knows the
/// [`FIXTURE_TARGET_NAMES`], which [`all_target_names`] does not list.
#[must_use]
pub fn run_by_name(name: &str, cfg: &RunConfig) -> Option<VerdictReport> {
    match name {
        "rsa_mont2048_pow_secret" => Some(rsa_mont2048_pow_secret::run(cfg)),
        "rsa_mont1024_pow_secret" => Some(rsa_mont1024_pow_secret::run(cfg)),
        "rsa_oaep_decode" => Some(oaep_decode::run(cfg)),
        "ecdsa_p256_scalar_mul" => Some(ecdsa_scalar_mul::run(cfg)),
        "ecdsa_p256_scalar_invert" => Some(ecdsa_scalar_invert::run(cfg)),
        "ecdh_p256_cdh" => Some(ecdh_cdh::run(cfg)),
        "ecdsa_p384_scalar_mul" => Some(ecdsa_p384_scalar_mul::run(cfg)),
        "ecdsa_p384_scalar_invert" => Some(ecdsa_p384_scalar_invert::run(cfg)),
        "ecdh_p384_cdh" => Some(ecdh_p384_cdh::run(cfg)),
        "eddsa_ed25519_scalar_mul" => Some(eddsa_scalar_mul::run(cfg)),
        "ghash" => Some(ghash::run(cfg)),
        "aes_gmul" => Some(aes_gmul::run(cfg)),
        "cmac_subkey" => Some(cmac_subkey::run(cfg)),
        "kwp_unwrap" => Some(kwp_unwrap::run(cfg)),
        "cmac_verify" => Some(cmac_verify::run(cfg)),
        #[cfg(feature = "fixture")]
        "cmac_verify_leaky" => Some(cmac_verify_leaky::run(cfg)),
        #[cfg(feature = "fixture")]
        "aa" => Some(aa::run(cfg)),
        _ => None,
    }
}
