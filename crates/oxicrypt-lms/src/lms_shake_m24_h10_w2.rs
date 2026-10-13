//! LMS_SHAKE_M24_H10 / LMOTS_SHAKE_N24_W2 instantiation.
//!
//! Parameters: hash = SHAKE-256, N = 24, H = 10 (1024
//! signatures), W = 2 (Winternitz). Derived (RFC 8554 Appendix B):
//! U = 96, V = 5, P = 101, LS = 6.
//!
//! Written by `scripts/lms_gen_pairs.py`; the `lms_impl!` invocation
//! below emits the verifier. External KAT grounding: the NIST ACVP
//! sigVer test group for this pair, from
//! `usnistgov/ACVP-Server @ 3611942e`, run by
//! `tests/acvp_sigver_all_pairs.rs`.

use oxicrypt_module::Service;

crate::lms_impl::lms_impl! {
    hasher = crate::hash::Shake256N24;
    n = 24;
    h = 10;
    w = 2;
    u = 96;
    v = 5;
    p = 101;
    ls = 6;
    lms_type = 0x0000_0015;
    lmots_type = 0x0000_000e;
    svc_verify = Service::LmsShakeM24H10W2Verify;
}
