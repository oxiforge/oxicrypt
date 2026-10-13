//! LMS_SHAKE_M24_H5 / LMOTS_SHAKE_N24_W4 instantiation.
//!
//! Parameters: hash = SHAKE-256, N = 24, H = 5 (32
//! signatures), W = 4 (Winternitz). Derived (RFC 8554 Appendix B):
//! U = 48, V = 3, P = 51, LS = 4.
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
    h = 5;
    w = 4;
    u = 48;
    v = 3;
    p = 51;
    ls = 4;
    lms_type = 0x0000_0014;
    lmots_type = 0x0000_000f;
    svc_verify = Service::LmsShakeM24H5W4Verify;
}
