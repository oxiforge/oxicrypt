//! ct-validation target: Ed25519 secret-scalar mult on edwards25519.
//!
//! Ed25519 signing (RFC 8032 §5.1.6) feeds the clamped high-bits-of-
//! `SHA512(seed)` through [`EdwardsPoint::mul`] twice — once to
//! compute the public key component `A = [s]B` and once to compute
//! the per-signature commitment `R = [r]B`. Of these the first is
//! the more dangerous path: it is a scalar mult by the long-lived
//! secret signing key, executed on every sign. A side channel in
//! that ladder would recover the secret-key scalar directly.
//!
//! This target measures [`EdwardsPoint::mul`] on the base point
//! with a 32-byte secret that has been passed through the RFC 8032
//! §5.1.5 clamping mask (`h[0] &= 0xF8; h[31] &= 0x7F; h[31] |=
//! 0x40`). Clamping fixes bits 0..3 and bits 254..255, leaving 251
//! freely secret-varying bits — exactly the ladder budget the
//! constant-time claim covers. Without clamping the random class
//! would include scalars outside the Ed25519 operating regime and
//! the ladder's top-bit selector path would look structurally
//! different between the two classes for reasons that have nothing
//! to do with leakage.
//!
//! Fixed class = one fixed (clamped) 32-byte scalar, reused every call.
//! Random class = fresh 32-byte scalar clamped per call.
//!
//! [`EdwardsPoint::mul`]: oxicrypt_eddsa::edwards::EdwardsPoint::mul

use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_eddsa::edwards::EdwardsPoint;
use oxicrypt_eddsa::scalar::Scalar;

/// Fixed secret scalar. The 32 bytes are arbitrary; only the
/// clamping mask matters for the measurement's validity.
const FIXED_SECRET: [u8; 32] = [
    0x5e, 0xc4, 0x83, 0x71, 0x17, 0x22, 0xd4, 0x8f, 0x41, 0x3a, 0x9b, 0xcf, 0x4d, 0x20, 0x77, 0xe8,
    0x09, 0xbb, 0x12, 0x64, 0x9c, 0xa5, 0x30, 0x1e, 0xf6, 0x7d, 0x8c, 0x23, 0xba, 0x55, 0x91, 0x47,
];

/// RFC 8032 §5.1.5 clamping: lock the three low bits of `b[0]`, the
/// top bit of `b[31]`, and force bit 254 of `b[31]` on. This is
/// exactly what `ed25519::clamp` does inside the real signing path.
fn clamp_inplace(bytes: &mut [u8; 32]) {
    bytes[0] &= 0xF8;
    bytes[31] &= 0x7F;
    bytes[31] |= 0x40;
}

/// Measure [`EdwardsPoint::mul`] on the base point under the
/// paired-class protocol and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let base = EdwardsPoint::BASE;

    let target = Box::new(move |secret: &[u8]| {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(secret);
        clamp_inplace(&mut buf);
        let s = Scalar::from_bytes(&buf);
        let r = base.mul(&s);
        std::hint::black_box(r);
    });

    run_target("eddsa_ed25519_scalar_mul", &FIXED_SECRET, target, cfg)
}
