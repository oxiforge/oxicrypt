//! ct-validation target: [`oxicrypt_ecdh::compute_shared_secret_p256_internal`].
//!
//! ECDH-CDH shares its scalar-multiplication core with ECDSA sign;
//! this target exists mainly as a smoke check to make sure the
//! gated entry point and SP 800-56Ar3 §5.6.2.3.3 public-key
//! validation don't add data-dependent branches on top of the
//! already-validated scalar mul. We pre-validate the peer public
//! key by using RFC 5903's fixture (same one the ECDH P-256 power-up
//! KAT uses) so every measured call goes through the same success
//! path; only the private scalar `d` changes between fixed and
//! random classes.

use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_ecdh::{PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, compute_shared_secret_p256_internal};

/// RFC 5903 §8.1 responder public key `Q_r`.
const PEER_PK: [u8; PUBLIC_KEY_LEN] = [
    0x04, //
    0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c, 0x34,
    0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63,
    0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d, 0x6a,
    0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab,
];

/// Fixed private scalar — any canonical non-zero scalar works.
const FIXED_D: [u8; PRIVATE_KEY_LEN] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

/// Measure [`compute_shared_secret_p256_internal`] under the
/// paired-class protocol and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let target = Box::new(|secret: &[u8]| {
        let mut d = [0u8; PRIVATE_KEY_LEN];
        d.copy_from_slice(secret);
        // Canonicalize like the other ECDSA targets — keep top byte
        // zero so the scalar is < 2^248 < n, guaranteeing from_bytes
        // accepts it.
        d[0] = 0;
        d[31] |= 1;
        let r = compute_shared_secret_p256_internal(&d, &PEER_PK);
        std::hint::black_box(r);
    });

    run_target("ecdh_p256_cdh", &FIXED_D, target, cfg)
}
