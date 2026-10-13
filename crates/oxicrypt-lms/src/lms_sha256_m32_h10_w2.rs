//! LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W2 instantiation.
//!
//! Parameters: hash = SHA-256, N = 32, H = 10 (1024
//! signatures), W = 2 (Winternitz). Derived (RFC 8554 Appendix B):
//! U = 128, V = 5, P = 133, LS = 6.
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
    h = 10;
    w = 2;
    u = 128;
    v = 5;
    p = 133;
    ls = 6;
    lms_type = 0x0000_0006;
    lmots_type = 0x0000_0002;
    svc_verify = Service::LmsSha256M32H10W2Verify;
}
