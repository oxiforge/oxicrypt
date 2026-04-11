//! ct-validation target: [`fips_rsa::mont1024::MontCtx1024::pow_secret`].
//!
//! Mirror of the 2048 target one directory over, but at the CRT
//! half-ladder width. This is called twice per RSA-2048 sign (once
//! under `dP`, once under `dQ`) and twice per RSA-2048 OAEP decrypt.

use crate::measure::{run_target, RunConfig};
use crate::stats::VerdictReport;
use fips_rsa::bigint1024::U1024;
use fips_rsa::mont1024::MontCtx1024;

const N_BYTES: [u8; 128] = {
    let mut n = [0u8; 128];
    n[0] = 0x80;
    let mut i = 1;
    while i < 127 {
        n[i] = (i as u8).wrapping_mul(0x5f).wrapping_add(0x13);
        i += 1;
    }
    n[127] = 0x03;
    n
};

const FIXED_EXP: [u8; 128] = [0x5a; 128];

/// Measure [`MontCtx1024::pow_secret`] under the paired-class
/// protocol and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let n = U1024::from_be_bytes(&N_BYTES);
    let ctx = MontCtx1024::new(n).unwrap_or_else(|| {
        panic!("ct-validation: rsa_mont1024 N_BYTES produced invalid Montgomery context")
    });

    let base = {
        let mut b = [0u8; 128];
        b[127] = 0x05;
        U1024::from_be_bytes(&b)
    };

    let target = Box::new(move |secret: &[u8]| {
        let mut exp_bytes = [0u8; 128];
        exp_bytes.copy_from_slice(secret);
        let exp = U1024::from_be_bytes(&exp_bytes);
        let out = ctx.pow_secret(&base, &exp);
        std::hint::black_box(out);
    });

    run_target("rsa_mont1024_pow_secret", &FIXED_EXP, target, cfg)
}
