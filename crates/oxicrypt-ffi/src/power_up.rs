//! The algorithm self-tests `oxi_init` runs at power-up.
//!
//! `oxicrypt-bench`'s `power_up` benchmark compiles this file as well, so the
//! set it times is the set `oxi_init` runs.

use oxicrypt_module::KatEntry;

/// The `KATS` slice of every approved algorithm crate this library links,
/// directly or through another dependency, in the order `oxi_init` runs them.
///
/// `kat_tests` in `lib.rs` reads the library's resolved dependency graph and
/// fails if a linked algorithm crate is missing here.
pub(crate) const ALGORITHM_SELF_TESTS: &[&[KatEntry]] = &[
    oxicrypt_sha::KATS,
    oxicrypt_xof::KATS,
    oxicrypt_hmac::KATS,
    oxicrypt_kdf::KATS,
    oxicrypt_aes::KATS,
    oxicrypt_cmac::KATS,
    oxicrypt_drbg::KATS,
    oxicrypt_ecdsa::KATS,
    oxicrypt_eddsa::KATS,
    oxicrypt_ecdh::KATS,
    oxicrypt_tls_kdf::KATS,
    oxicrypt_dh::KATS,
    oxicrypt_rsa::KATS,
    oxicrypt_ml_kem::KATS,
    oxicrypt_ml_dsa::KATS,
    oxicrypt_slh_dsa::KATS,
    oxicrypt_lms::KATS,
    oxicrypt_xmss::KATS,
];

/// [`ALGORITHM_SELF_TESTS`] as one flat list.
pub(crate) fn algorithm_self_tests() -> Vec<KatEntry> {
    ALGORITHM_SELF_TESTS
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect()
}
