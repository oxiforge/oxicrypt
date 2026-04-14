//! RSA-3072 key generation per FIPS 186-5 §A.1.1 / §B.3.1.
//!
//! Generates two 1536-bit probable primes `p`, `q` and computes the
//! 3072-bit modulus `n = p · q`, private exponent `d`, and the CRT
//! decomposition `(dP, dQ, qInv)`.
//!
//! This module is the RSA-3072 instantiation of the
//! `define_keygen` macro.
//! Shared constants and the `KeygenError` type live in
//! [`crate::keygen`].
//!
//! Miller-Rabin uses **4 rounds** per FIPS 186-5 Table B.1 (nlen =
//! 3072, error probability ≤ 2⁻¹⁰⁰).
//!
//! # Non-constant-time note
//!
//! Primality testing on candidate `p` is *not* constant time: we
//! return as soon as the sieve or an MR round fails. See
//! [`crate::keygen`]'s module doc for the rationale.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    clippy::manual_let_else
)]

use crate::bigint1536::{U1536, BYTES as BYTES1536, LIMBS as LIMBS1536};
use crate::bigint3072::{U3072, LIMBS as LIMBS3072};
use crate::mont1536::MontCtx1536;
use oxicrypt_drbg::HmacDrbgSha256;

// Silence unused-import warnings for the LIMBS/BYTES constants that
// the macro body references through the literal values passed in the
// invocation, while the test module (below) uses the named constants.
const _: () = {
    let _ = BYTES1536;
    let _ = LIMBS1536;
    let _ = LIMBS3072;
};

crate::keygen_impl::define_keygen! {
    /// RSA-3072 key material: modulus, private exponent, and CRT
    /// components. All CSPs are zeroized on `Drop`.
    pub struct KeyMaterial3072;
    half = U1536, limbs = 24, bytes = 192;
    full = U3072, limbs = 48;
    mont = MontCtx1536;
    pow_public = pow_public_u1536;
    mr_rounds = 4;
    nlen = 3072;
    generate = generate_3072;
    reduce = u3072_mod_u1536;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_drbg(seed: &[u8]) -> HmacDrbgSha256 {
        use oxicrypt_module::{initialize_with_tests, KatEntry};
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-3072-keygen-test-noop",
            run: || Ok(()),
        }]);
        let mut d = HmacDrbgSha256::default();
        d.instantiate(seed, b"pqclib-rsa3072-keygen-test", b"")
            .unwrap();
        d
    }

    #[test]
    fn small_primes_rejects_obvious_composites_1536() {
        let mut limbs = [0u64; LIMBS1536];
        limbs[0] = 15;
        let p = U1536 { limbs };
        assert!(has_small_factor(&p));
    }

    #[test]
    fn miller_rabin_does_not_panic_on_synthetic_input_1536() {
        let mut limbs = [0u64; LIMBS1536];
        limbs[0] = 7;
        limbs[LIMBS1536 - 1] = 1 << 63;
        let n_fake = U1536 { limbs };
        let mut drbg = make_drbg(b"mr-smoke-3072-seed-0000");
        let _ = miller_rabin(&n_fake, 2, &mut drbg);
    }

    #[test]
    fn u3072_mod_u1536_small_case() {
        // 15 mod 7 = 1
        let mut a_limbs = [0u64; LIMBS3072];
        a_limbs[0] = 15;
        let a = U3072 { limbs: a_limbs };
        // m must have top bit set for the debug assert.
        let mut m_limbs = [0u64; LIMBS1536];
        m_limbs[0] = 7;
        m_limbs[LIMBS1536 - 1] = 1 << 63;
        let m = U1536 { limbs: m_limbs };
        let r = u3072_mod_u1536(&a, &m);
        assert_eq!(r.limbs[0], 15); // 15 < m, so result is 15
    }

    /// Full keygen smoke test. Slow in debug (~seconds for 1536-bit
    /// primes) but exercises the complete pipeline.
    #[test]
    fn generate_3072_smoke() {
        use oxicrypt_module::{initialize_with_tests, KatEntry};
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-3072-keygen-smoke",
            run: crate::self_test,
        }]);
        let mut drbg = make_drbg(b"pqclib-rsa3072-keygen-smoke-entropy-0001");
        let km = generate_3072(&mut drbg, 65537).expect("keygen failed");
        // n must have its top bit set (full 3072 bits).
        assert_ne!(
            km.n.limbs[LIMBS3072 - 1] >> 63,
            0,
            "n is not 3072-bit"
        );
        // d must be less than n.
        assert_eq!(km.d.ct_lt(&km.n), 1, "d ≥ n");
        // p and q must be 1536-bit (top bit set).
        assert_ne!(km.p.limbs[LIMBS1536 - 1] >> 63, 0, "p is not 1536-bit");
        assert_ne!(km.q.limbs[LIMBS1536 - 1] >> 63, 0, "q is not 1536-bit");
    }

    #[test]
    fn generate_3072_rejects_even_exponent() {
        let mut drbg = make_drbg(b"even-exp-reject-3072");
        assert!(generate_3072(&mut drbg, 65538).is_err());
    }

    #[test]
    fn generate_3072_rejects_small_exponent() {
        let mut drbg = make_drbg(b"small-exp-reject-3072");
        assert!(generate_3072(&mut drbg, 3).is_err());
    }
}
