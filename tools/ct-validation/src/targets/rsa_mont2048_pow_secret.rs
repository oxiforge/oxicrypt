//! ct-validation target: [`oxicrypt_rsa::mont2048::MontCtx2048::pow_secret`].
//!
//! This is the non-CRT private-key exponentiation path used by
//! RSA-2048 sign (when CRT is unavailable) and by the OAEP decrypt
//! primitive. The claim in the security policy is that `pow_secret`
//! runs a fixed-schedule 4-bit window ladder — every one of the 512
//! nibbles in a 2048-bit exponent executes the same sequence of
//! Montgomery multiplications regardless of the nibble value, and
//! the table lookup is a constant-time scan over all 16 entries.
//!
//! The harness feeds the exponent bytes as the "secret" — the fixed
//! class reuses the same exponent every call, the random class draws
//! a fresh 256-byte exponent per call, and we measure the cycle
//! count of one `pow_secret` invocation.

use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_rsa::bigint2048::U2048;
use oxicrypt_rsa::mont2048::MontCtx2048;

/// 2048-bit odd modulus with the top bit set. This isn't the RSA
/// KAT modulus (which is module-private to `oxicrypt-rsa`) — we just
/// need *any* valid odd 2048-bit integer so `MontCtx2048::new`
/// succeeds. Correctness isn't being checked here; timing is.
const N_BYTES: [u8; 256] = {
    let mut n = [0u8; 256];
    // Top bit set ensures the top limb is non-zero as required by
    // `MontCtx2048::new`. Last byte odd ensures the modulus is odd.
    n[0] = 0x80;
    n[255] = 0x01;
    // Fill the middle with a deterministic pattern so it's a
    // "proper" integer and not just 2^2047 + 1 (which would be a
    // silly modulus to time, though still a valid Montgomery target).
    let mut i = 1;
    while i < 255 {
        n[i] = (i as u8).wrapping_mul(0x9d).wrapping_add(0x2b);
        i += 1;
    }
    // Make sure the last byte is odd even after the pattern fill.
    n[255] = 0x01;
    n
};

/// Fixed secret used by class 0. An arbitrary 2048-bit exponent —
/// any pattern is fine; the fixed class only needs to be *constant*,
/// not special.
const FIXED_EXP: [u8; 256] = [0xa5; 256];

/// Measure [`MontCtx2048::pow_secret`] under the paired-class
/// protocol and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let n = U2048::from_be_bytes(&N_BYTES);
    // If this `.unwrap()` ever trips, the N_BYTES constant above is
    // wrong (not odd or top limb zero) — this is harness setup, not
    // a timed call, so panic is acceptable.
    let ctx = MontCtx2048::new(n).unwrap_or_else(|| {
        panic!("ct-validation: rsa_mont2048 N_BYTES produced invalid Montgomery context")
    });

    // Fix a base for every call so the only input that varies
    // between classes is the secret exponent. The base value is
    // irrelevant — any non-zero `[0, n)` integer works.
    let base = {
        let mut b = [0u8; 256];
        b[255] = 0x03;
        U2048::from_be_bytes(&b)
    };

    let target = Box::new(move |secret: &[u8]| {
        // The secret buffer is 256 bytes of "exponent". Reinterpret
        // it as a U2048 and run the private-key ladder. We use
        // `black_box` on the return value so the compiler cannot
        // skip the call as dead code.
        let mut exp_bytes = [0u8; 256];
        exp_bytes.copy_from_slice(secret);
        let exp = U2048::from_be_bytes(&exp_bytes);
        let out = ctx.pow_secret(&base, &exp);
        std::hint::black_box(out);
    });

    run_target("rsa_mont2048_pow_secret", &FIXED_EXP, target, cfg)
}
