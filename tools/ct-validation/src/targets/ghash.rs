//! ct-validation target: the portable GHASH multiplication,
//! [`oxicrypt_aes::modes::ghash_mul_portable_internal`].
//!
//! H and the GHASH accumulator are secret (SP 800-38D §5.3). The secret
//! is 32 bytes: the accumulator, then H.
//!
//! Fixed class = one accumulator and one H, the same every call.
//! Random class = a fresh accumulator and a fresh H per call.
//!
//! A conditional step on a bit of either operand separates the classes.

use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_aes::modes::ghash_mul_portable_internal;

/// Fixed accumulator and H, each with few bits set, so that a multiply
/// that branched on their bits would take the conditional XORs rarely in
/// the fixed class and half the time in the random class.
const FIXED: [u8; 32] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// H of the GCM specification's Test Case 2 (SP 800-38D cites the
/// McGrew-Viega test cases).
const TC2_H: [u8; 16] = [
    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
];

/// The first ciphertext block C1 of Test Case 2, the accumulator before
/// the first multiplication.
const TC2_C1: [u8; 16] = [
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
];

/// X1 = C1 · H of Test Case 2.
const TC2_X1: [u8; 16] = [
    0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53, 0xde, 0xb7,
];

/// Panics unless [`ghash_mul_portable_internal`] accepts the call and
/// gives the Test Case 2 product, so that a refused call, which would
/// take the same time in both classes, is never measured as clean.
pub(crate) fn preflight() {
    let mut x = TC2_C1;
    assert_eq!(
        ghash_mul_portable_internal(&mut x, &TC2_H),
        Ok(()),
        "ct-validation: ghash refused the call"
    );
    assert_eq!(x, TC2_X1, "ct-validation: ghash gave a wrong product");
}

/// Measure [`ghash_mul_portable_internal`] under the paired-class
/// protocol and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    preflight();
    let target = Box::new(|secret: &[u8]| {
        let mut x = [0u8; 16];
        let mut h = [0u8; 16];
        x.copy_from_slice(&secret[..16]);
        h.copy_from_slice(&secret[16..32]);
        let r = ghash_mul_portable_internal(&mut x, &h);
        std::hint::black_box(&(r, x));
    });

    run_target("ghash", &FIXED, target, cfg)
}

#[cfg(test)]
#[test]
fn preflight_passes() {
    super::start_module();
    preflight();
}
