//! RSA-4096 key generation per FIPS 186-5 §A.1.1 / §B.3.1.
//!
//! Generates two 2048-bit probable primes `p`, `q` and computes the
//! 4096-bit modulus `n = p · q`, private exponent `d`, and the CRT
//! decomposition `(dP, dQ, qInv)`.
//!
//! This module is the RSA-4096 instantiation of the
//! `define_keygen` macro.
//! Shared constants and the `KeygenError` type live in
//! [`crate::keygen`].
//!
//! Miller-Rabin uses **4 rounds** per FIPS 186-5 Table B.1 (nlen =
//! 4096, error probability ≤ 2⁻¹⁰⁰).
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

use crate::bigint2048::{U2048, BYTES as BYTES2048, LIMBS as LIMBS2048};
use crate::bigint4096::{U4096, LIMBS as LIMBS4096};
use crate::mont2048::MontCtx2048;
use oxicrypt_drbg::HmacDrbgSha256;

// Silence unused-import warnings for the LIMBS/BYTES constants that
// the macro body references through the literal values passed in the
// invocation, while the test module (below) uses the named constants.
const _: () = {
    let _ = BYTES2048;
    let _ = LIMBS2048;
    let _ = LIMBS4096;
};

crate::keygen_impl::define_keygen! {
    /// RSA-4096 key material: modulus, private exponent, and CRT
    /// components. All CSPs are zeroized on `Drop`.
    pub struct KeyMaterial4096;
    half = U2048, limbs = 32, bytes = 256;
    full = U4096, limbs = 64;
    mont = MontCtx2048;
    pow_public = pow_public_u2048;
    mr_rounds = 4;
    nlen = 4096;
    generate = generate_4096;
    reduce = u4096_mod_u2048;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_drbg(seed: &[u8]) -> HmacDrbgSha256 {
        use oxicrypt_module::{initialize_with_tests, KatEntry};
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-4096-keygen-test-noop",
            run: || Ok(()),
        }]);
        let mut d = HmacDrbgSha256::default();
        d.instantiate(seed, b"pqclib-rsa4096-keygen-test", b"")
            .unwrap();
        d
    }

    #[test]
    fn small_primes_rejects_obvious_composites_2048() {
        let mut limbs = [0u64; LIMBS2048];
        limbs[0] = 15;
        let p = U2048 { limbs };
        assert!(has_small_factor(&p));
    }

    #[test]
    fn miller_rabin_does_not_panic_on_synthetic_input_2048() {
        let mut limbs = [0u64; LIMBS2048];
        limbs[0] = 7;
        limbs[LIMBS2048 - 1] = 1 << 63;
        let n_fake = U2048 { limbs };
        let mut drbg = make_drbg(b"mr-smoke-4096-seed-0000");
        let _ = miller_rabin(&n_fake, 2, &mut drbg);
    }

    #[test]
    fn u4096_mod_u2048_small_case() {
        let mut a_limbs = [0u64; LIMBS4096];
        a_limbs[0] = 15;
        let a = U4096 { limbs: a_limbs };
        let mut m_limbs = [0u64; LIMBS2048];
        m_limbs[0] = 7;
        m_limbs[LIMBS2048 - 1] = 1 << 63;
        let m = U2048 { limbs: m_limbs };
        let r = u4096_mod_u2048(&a, &m);
        assert_eq!(r.limbs[0], 15); // 15 < m, so result is 15
    }

    /// Full keygen smoke test. Very slow in debug (~tens of seconds
    /// for 2048-bit primes) but exercises the complete pipeline.
    #[test]
    fn generate_4096_smoke() {
        use oxicrypt_module::{initialize_with_tests, KatEntry};
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-4096-keygen-smoke",
            run: crate::self_test,
        }]);
        let mut drbg = make_drbg(b"pqclib-rsa4096-keygen-smoke-entropy-0001");
        let km = generate_4096(&mut drbg, 65537).expect("keygen failed");
        // n must have its top bit set (full 4096 bits).
        assert_ne!(
            km.n.limbs[LIMBS4096 - 1] >> 63,
            0,
            "n is not 4096-bit"
        );
        // d must be less than n.
        assert_eq!(km.d.ct_lt(&km.n), 1, "d ≥ n");
        // p and q must be 2048-bit (top bit set).
        assert_ne!(km.p.limbs[LIMBS2048 - 1] >> 63, 0, "p is not 2048-bit");
        assert_ne!(km.q.limbs[LIMBS2048 - 1] >> 63, 0, "q is not 2048-bit");
    }

    #[test]
    fn generate_4096_rejects_even_exponent() {
        let mut drbg = make_drbg(b"even-exp-reject-4096");
        assert!(generate_4096(&mut drbg, 65538).is_err());
    }

    #[test]
    fn generate_4096_rejects_small_exponent() {
        let mut drbg = make_drbg(b"small-exp-reject-4096");
        assert!(generate_4096(&mut drbg, 3).is_err());
    }
}
