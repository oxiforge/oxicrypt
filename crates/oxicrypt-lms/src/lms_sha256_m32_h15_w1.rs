//! LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W1 instantiation.
//!
//! Parameters: hash = SHA-256, N = 32, H = 15 (32768
//! signatures), W = 1 (Winternitz). Derived (RFC 8554 Appendix B):
//! U = 256, V = 9, P = 265, LS = 7.
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
    h = 15;
    w = 1;
    u = 256;
    v = 9;
    p = 265;
    ls = 7;
    lms_type = 0x0000_0007;
    lmots_type = 0x0000_0001;
    svc_verify = Service::LmsSha256M32H15W1Verify;
}
