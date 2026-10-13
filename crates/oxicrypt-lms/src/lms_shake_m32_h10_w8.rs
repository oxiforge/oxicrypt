//! LMS_SHAKE_M32_H10 / LMOTS_SHAKE_N32_W8 instantiation.
//!
//! Parameters: hash = SHAKE-256, N = 32, H = 10 (1024
//! signatures), W = 8 (Winternitz). Derived (RFC 8554 Appendix B):
//! U = 32, V = 2, P = 34, LS = 0.
//!
//! Written by `scripts/lms_gen_pairs.py`; the `lms_impl!` invocation
//! below emits the verifier. External KAT grounding: the NIST ACVP
//! sigVer test group for this pair, from
//! `usnistgov/ACVP-Server @ 3611942e`, run by
//! `tests/acvp_sigver_all_pairs.rs`.

use oxicrypt_module::Service;

crate::lms_impl::lms_impl! {
    hasher = crate::hash::Shake256N32;
    n = 32;
    h = 10;
    w = 8;
    u = 32;
    v = 2;
    p = 34;
    ls = 0;
    lms_type = 0x0000_0010;
    lmots_type = 0x0000_000c;
    svc_verify = Service::LmsShakeM32H10W8Verify;
}
