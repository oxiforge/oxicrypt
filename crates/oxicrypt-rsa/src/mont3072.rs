//! Montgomery arithmetic for 3072-bit odd moduli.
//!
//! Full-width companion of [`crate::mont1536`]. Given an odd modulus
//! `n` with `2^3071 ≤ n < 2^3072`, we build a [`MontCtx3072`] for
//! CIOS Montgomery multiplication.
//!
//! # Constant-time contract
//!
//! `mont_mul`, `to_mont`, `from_mont`, and `pow_secret` are constant
//! time with respect to operand values. `pow_public_u64` is **not**
//! constant time in the exponent.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::return_self_not_must_use,
    clippy::needless_range_loop,
    clippy::many_single_char_names,
    clippy::assign_op_pattern,
    dead_code
)]

use crate::bigint3072::U3072;
use crate::mont_impl::define_mont_type;

define_mont_type! {
    /// Derived Montgomery constants for a specific 3072-bit odd modulus.
    pub struct MontCtx3072 for U3072;
    limbs = 48;
    bits = 3072;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::bigint3072::LIMBS;

    fn synthetic_modulus(seed: u64) -> U3072 {
        let mut limbs = [0u64; LIMBS];
        let mut x = seed | 1;
        for i in 0..LIMBS {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            limbs[i] = x;
        }
        limbs[0] |= 1;
        limbs[LIMBS - 1] |= 1 << 63;
        U3072 { limbs }
    }

    fn small(x: u64) -> U3072 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = x;
        U3072 { limbs }
    }

    #[test]
    fn mont_ctx_rejects_even_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[0] &= !1u64;
        assert!(MontCtx3072::new(n).is_none());
    }

    #[test]
    fn mont_ctx_rejects_short_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[LIMBS - 1] &= !(1 << 63);
        assert!(MontCtx3072::new(n).is_none());
    }

    #[test]
    fn mont_one_is_r_mod_n() {
        let n = synthetic_modulus(42);
        let ctx = MontCtx3072::new(n).unwrap();
        let back = ctx.from_mont(&ctx.one_mont);
        assert_eq!(back, small(1));
    }

    #[test]
    fn to_from_mont_roundtrip() {
        let n = synthetic_modulus(42);
        let ctx = MontCtx3072::new(n).unwrap();
        for v in [1u64, 2, 3, 65537, 0xdead_beef_u64] {
            let plain = small(v);
            let mont = ctx.to_mont(&plain);
            let back = ctx.from_mont(&mont);
            assert_eq!(back, plain);
        }
    }

    #[test]
    fn mont_mul_2_times_3_is_6() {
        let n = synthetic_modulus(123);
        let ctx = MontCtx3072::new(n).unwrap();
        let two = ctx.to_mont(&small(2));
        let three = ctx.to_mont(&small(3));
        let six = ctx.mont_mul(&two, &three);
        assert_eq!(ctx.from_mont(&six), small(6));
    }

    #[test]
    fn pow_public_small_numbers() {
        let n = synthetic_modulus(7);
        let ctx = MontCtx3072::new(n).unwrap();
        assert_eq!(ctx.pow_public_u64(&small(3), 7), small(2187));
        assert_eq!(ctx.pow_public_u64(&small(2), 16), small(65536));
        assert_eq!(ctx.pow_public_u64(&small(42), 0), small(1));
    }

    fn u3072_from_u64(x: u64) -> U3072 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = x;
        U3072 { limbs }
    }

    #[test]
    fn pow_secret_matches_pow_public_for_small_exps() {
        let n = synthetic_modulus(321);
        let ctx = MontCtx3072::new(n).unwrap();
        let base = small(7);
        for exp in [0u64, 1, 2, 3, 17, 65537, 0xdead_beef] {
            let want = ctx.pow_public_u64(&base, exp);
            let got = ctx.pow_secret(&base, &u3072_from_u64(exp));
            assert_eq!(want, got, "disagreed at exp={exp}");
        }
    }

    #[test]
    fn pow_secret_zero_base() {
        let n = synthetic_modulus(555);
        let ctx = MontCtx3072::new(n).unwrap();
        let big_exp = u3072_from_u64(12345);
        assert_eq!(ctx.pow_secret(&U3072::ZERO, &big_exp), U3072::ZERO);
    }

    #[test]
    fn pow_secret_one_base() {
        let n = synthetic_modulus(555);
        let ctx = MontCtx3072::new(n).unwrap();
        let big_exp = u3072_from_u64(12345);
        assert_eq!(ctx.pow_secret(&small(1), &big_exp), small(1));
    }

    #[test]
    fn pow_secret_exp_zero_is_one() {
        let n = synthetic_modulus(777);
        let ctx = MontCtx3072::new(n).unwrap();
        let r = ctx.pow_secret(&small(42), &U3072::ZERO);
        assert_eq!(r, small(1));
    }
}
