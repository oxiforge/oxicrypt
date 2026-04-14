//! ct-validation target: [`oxicrypt_ecdsa::p384_point::Point384::mul`].
//!
//! The P-384 scalar-multiplication ladder is used both in ECDSA
//! sign (via `k · G`) and in ECDH CDH (via `d · Q`). The claim in
//! §12.1 is that the ladder is constant-time in the scalar bits.
//! Structurally identical to the P-256 target but with 48-byte
//! scalars and 6×64-limb Montgomery arithmetic.
//!
//! Fixed class = one fixed scalar, same every call.
//! Random class = fresh 48-byte scalar per call.

use crate::measure::{run_target, RunConfig};
use crate::stats::VerdictReport;
use oxicrypt_ecdsa::p384_point::Point384;
use oxicrypt_ecdsa::p384_scalar::Scalar384;

/// Fixed scalar. Any non-zero canonical scalar works.
const FIXED_SCALAR: [u8; 48] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

/// Build a scalar via [`Scalar384::from_bytes_reduced`], which applies
/// a full `mod n` reduction and so takes the same code path for every
/// input. We deliberately avoid [`Scalar384::from_bytes`] here because
/// it has a rejection branch on `raw >= n` that would contribute
/// input-dependent timing to the harness wrapper (not to the
/// primitive we are actually measuring).
fn bytes_to_scalar(bytes: &[u8]) -> Scalar384 {
    let mut k = [0u8; 48];
    k.copy_from_slice(bytes);
    Scalar384::from_bytes_reduced(&k)
}

/// Measure [`Point384::mul`] under the paired-class protocol and
/// return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let g = Point384::generator();

    let target = Box::new(move |secret: &[u8]| {
        let k = bytes_to_scalar(secret);
        let r = g.mul(&k);
        std::hint::black_box(r);
    });

    run_target("ecdsa_p384_scalar_mul", &FIXED_SCALAR, target, cfg)
}
