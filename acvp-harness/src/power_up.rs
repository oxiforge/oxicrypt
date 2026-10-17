//! The algorithm self-tests the harness runs at power-up.
//!
//! `oxicrypt-bench`'s `power_up` benchmark compiles this file as well, so the
//! set it times is the set the harness runs.

#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use oxicrypt_module::KatEntry;

/// Each approved algorithm crate the harness links, with its `KATS` slice, in
/// the order the harness runs them. `stringify!` takes each name from the
/// same path the slice is read through.
macro_rules! named_kats {
    ($($krate:ident),* $(,)?) => {
        &[$((stringify!($krate), $krate::KATS)),*]
    };
}

pub(crate) const ALGORITHM_SELF_TESTS: &[(&str, &[KatEntry])] = named_kats![
    oxicrypt_sha,
    oxicrypt_xof,
    oxicrypt_hmac,
    oxicrypt_kdf,
    oxicrypt_aes,
    oxicrypt_cmac,
    oxicrypt_drbg,
    oxicrypt_ecdsa,
    oxicrypt_eddsa,
    oxicrypt_rsa,
    oxicrypt_ecdh,
    oxicrypt_tls_kdf,
    oxicrypt_dh,
    oxicrypt_ml_kem,
    oxicrypt_ml_dsa,
    oxicrypt_slh_dsa,
    oxicrypt_lms,
    oxicrypt_xmss,
];

/// [`ALGORITHM_SELF_TESTS`] as one flat list, built at compile time.
///
/// Keeping this list in source (rather than assembling it via linker-section
/// magic) means the module's test inventory is auditable from a single
/// location, which is what a CST lab reviews against the Security Policy.
pub(crate) const POWER_UP_KATS: &[KatEntry] =
    &concat_kats::<{ total_len(ALGORITHM_SELF_TESTS) }>(ALGORITHM_SELF_TESTS);

/// The number of entries across every group.
const fn total_len(groups: &[(&str, &[KatEntry])]) -> usize {
    let mut n = 0usize;
    let mut g = 0usize;
    while g < groups.len() {
        n += groups[g].1.len();
        g += 1;
    }
    n
}

/// Concatenate the groups' `KatEntry` slices into a single fixed-size array
/// at compile time. `N` must equal the sum of the lengths of the slices; a
/// mismatch triggers a `const` panic.
const fn concat_kats<const N: usize>(groups: &[(&str, &[KatEntry])]) -> [KatEntry; N] {
    let mut out: [KatEntry; N] = [KatEntry {
        name: "",
        run: noop_kat,
    }; N];
    let mut out_idx = 0usize;
    let mut g = 0usize;
    while g < groups.len() {
        let part = groups[g].1;
        let mut i = 0usize;
        while i < part.len() {
            out[out_idx] = part[i];
            out_idx += 1;
            i += 1;
        }
        g += 1;
    }
    assert!(out_idx == N, "concat_kats: length mismatch");
    out
}

/// Placeholder used only to initialize the const array before the real
/// entries are copied in. Never invoked, because every slot is overwritten in
/// `concat_kats`. A `KatEntry` holds a `fn() -> Result<..>`, so the `Result`
/// is required even though this body cannot fail.
#[allow(clippy::unnecessary_wraps)]
fn noop_kat() -> Result<(), oxicrypt_module::SelfTestFailure> {
    Ok(())
}
