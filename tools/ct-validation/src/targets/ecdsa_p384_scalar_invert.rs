//! ct-validation target: [`oxicrypt_ecdsa::p384_scalar::Scalar384::invert`].
//!
//! The Fermat-ladder modular inverse is the second secret-dependent
//! operation on the ECDSA sign hot path — it's used to compute
//! `k^(-1) mod n`. The ladder has a fixed number of squarings and
//! conditional multiplications driven by the bits of `n − 2`, which
//! is a **public** constant, so the *schedule* is data-independent.
//! What this harness checks is that the timing of the underlying
//! scalar multiplications doesn't depend on the limbs of the
//! operand being inverted.

use crate::measure::{run_target, RunConfig};
use crate::stats::VerdictReport;
use oxicrypt_ecdsa::p384_scalar::Scalar384;

const FIXED_SCALAR: [u8; 48] = [0x7e; 48];

/// Build a scalar via `from_bytes_reduced` — no rejection branch,
/// uniform code path regardless of the input's relation to `n`.
fn bytes_to_scalar(bytes: &[u8]) -> Scalar384 {
    let mut k = [0u8; 48];
    k.copy_from_slice(bytes);
    Scalar384::from_bytes_reduced(&k)
}

/// Measure [`Scalar384::invert`] under the paired-class protocol and
/// return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let target = Box::new(move |secret: &[u8]| {
        let s = bytes_to_scalar(secret);
        let inv = s.invert();
        std::hint::black_box(inv);
    });

    run_target("ecdsa_p384_scalar_invert", &FIXED_SCALAR, target, cfg)
}
