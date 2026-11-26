//! The algorithm self-tests `oxi` runs at power-up: the known-answer tests
//! and CASTs of every approved algorithm crate this binary links.
//!
//! `oxicrypt-bench`'s `power_up` benchmark and this crate's CLI tests compile
//! this file as well, so the set they time and count is the set `oxi` runs.

use oxicrypt_module::KatEntry;

/// Pre-operational algorithm self-tests for the algorithm crates this binary
/// links: SHA for `hash`, HMAC for `hmac`, and the DRBG, with the AES it is
/// built on, for `rand` and key generation. ML-DSA and the SHAKE it is built
/// on are linked by the integrity test and the `ml-dsa` commands, and ML-KEM
/// by the `ml-kem` commands. Each linked crate's `KATS` is here because
/// `the_inventory_covers_every_linked_algorithm_crate` requires it, and the
/// ML-KEM entries are the CASTs FIPS 140-3 IG 10.3.A item 14 requires.
/// [`inventory`] flattened, in order.
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
        ("ml-kem", oxicrypt_ml_kem::KATS),
    ]
}
