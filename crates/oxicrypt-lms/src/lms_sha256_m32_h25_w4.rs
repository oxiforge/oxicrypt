//! LMS_SHA256_M32_H25 / LMOTS_SHA256_N32_W4 instantiation.
//!
//! Parameters: hash = SHA-256, N = 32, H = 25 (33554432
//! signatures), W = 4 (Winternitz). Derived (RFC 8554 Appendix B):
//! U = 64, V = 3, P = 67, LS = 4.
//!
//! Written by `scripts/lms_gen_pairs.py`; the `lms_impl!` invocation
//! below emits the verifier. External KAT grounding: the NIST ACVP
//! sigVer test group for this pair, from
//! `usnistgov/ACVP-Server @ 3611942e`, run by
//! `tests/acvp_sigver_all_pairs.rs`.

use oxicrypt_module::Service;

crate::lms_impl::lms_impl! {
    hasher = crate::hash::Sha256N32;
    n = 32;
    h = 25;
    w = 4;
    u = 64;
    v = 3;
    p = 67;
    ls = 4;
    lms_type = 0x0000_0009;
    lmots_type = 0x0000_0003;
    svc_verify = Service::LmsSha256M32H25W4Verify;
}
