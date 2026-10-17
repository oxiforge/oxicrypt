//! The algorithm self-tests `oxi` runs at power-up.
//!
//! `oxicrypt-bench`'s `power_up` benchmark compiles this file as well, so the
//! set it times is the set `oxi` runs.

use oxicrypt_module::KatEntry;

/// Pre-operational algorithm self-tests for the services this CLI offers:
/// SHA for `hash`, HMAC for `hmac`, and the DRBG — with the AES it is built
/// on — for `rand` — plus ML-DSA, which the integrity test links for its
/// signature, and the SHAKE it is built on. [`inventory`] flattened, in
/// order.
pub(crate) fn power_up_tests() -> Vec<KatEntry> {
    inventory()
        .iter()
        .flat_map(|(_, group)| group.iter().copied())
        .collect()
}

/// The power-up inventory, named by the crate that publishes each group.
///
/// One source with two readers: [`power_up_tests`] flattens it for
/// `oxicrypt_module::initialize_with_tests`, and `cmd_selftest` walks it to
/// show an operator each test in turn. Two lists would be two opinions about
/// what this binary self-tests, and the one the operator watched would be the
/// one that could drift from the one that ran.
///
/// The integrity group is deliberately absent: it is
/// `initialize_with_tests`' separate first argument, because the module
/// refuses to become operational without it. `cmd_selftest` prepends it for
/// display.
pub(crate) fn inventory() -> &'static [(&'static str, &'static [KatEntry])] {
    &[
        ("sha", oxicrypt_sha::KATS),
        ("hmac", oxicrypt_hmac::KATS),
        ("aes", oxicrypt_aes::KATS),
        ("drbg", oxicrypt_drbg::KATS),
        ("xof", oxicrypt_xof::KATS),
        ("ml-dsa", oxicrypt_ml_dsa::KATS),
    ]
}
