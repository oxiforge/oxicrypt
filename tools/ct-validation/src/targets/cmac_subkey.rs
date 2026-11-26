//! ct-validation target: the CMAC subkey derivation of SP 800-38B §6.1
//! steps 2 to 4, [`oxicrypt_cmac::cmac::subkeys_from_l_internal`].
//!
//! The secret is L = CIPH_K(0^128). K1 = L · x adds R_b when the top bit
//! of L is set, and K2 = K1 · x when the top bit of K1 is set. Each call
//! derives K1 and K2 from L and then from K2, `CHAIN` times.
//!
//! Fixed class = the L of the SP 800-38B §D.1 example, whose top bit is
//! clear, every call.
//! Random class = a fresh L per call, whose top bit is set in half the
//! calls.

use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_cmac::cmac::subkeys_from_l_internal;

/// Derivations per measured call.
const CHAIN: usize = 8;

/// L of SP 800-38B §D.1 (AES-128).
const FIXED_L: [u8; 16] = [
    0x7d, 0xf7, 0x6b, 0x0c, 0x1a, 0xb8, 0x99, 0xb3, 0x3e, 0x42, 0xf0, 0x47, 0xb9, 0x1b, 0x54, 0x6f,
];

/// K1 of SP 800-38B §D.1 (AES-128).
const D1_K1: [u8; 16] = [
    0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66, 0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde,
];

/// K2 of SP 800-38B §D.1 (AES-128).
const D1_K2: [u8; 16] = [
    0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc, 0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b,
];

/// Panics unless [`subkeys_from_l_internal`] accepts the call and
/// derives the §D.1 K1 and K2 from its L, so that a refused call, which
/// would take the same time in both classes, is never measured as clean.
pub(crate) fn preflight() {
    let mut k1 = [0u8; 16];
    let mut k2 = [0u8; 16];
    assert_eq!(
        subkeys_from_l_internal(&FIXED_L, &mut k1, &mut k2),
        Ok(()),
        "ct-validation: cmac_subkey refused the call"
    );
    assert_eq!(
        (k1, k2),
        (D1_K1, D1_K2),
        "ct-validation: cmac_subkey gave wrong subkeys"
    );
}

/// Measure [`subkeys_from_l_internal`] under the paired-class protocol
/// and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    preflight();
    let target = Box::new(|secret: &[u8]| {
        let mut l = [0u8; 16];
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        l.copy_from_slice(secret);
        for _ in 0..CHAIN {
            let r = subkeys_from_l_internal(&l, &mut k1, &mut k2);
            std::hint::black_box(&r);
            l = k2;
        }
        std::hint::black_box((k1, k2));
    });

    run_target("cmac_subkey", &FIXED_L, target, cfg)
}

#[cfg(test)]
#[test]
fn preflight_passes() {
    super::start_module();
    preflight();
}
