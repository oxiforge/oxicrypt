//! Montgomery arithmetic for 1536-bit odd moduli.
//!
//! CRT half-width companion of [`crate::mont3072`]. Two roles:
//!
//!   * **Key generation.** [`crate::keygen`] (once extended to 3072 bits)
//!     runs Miller-Rabin primality testing on 1536-bit prime candidates
//!     via [`MontCtx1536::pow_public_u1536`].
//!
//!   * **CRT sign path.** Each half-modulus `p`/`q` of an RSA-3072 key
//!     is used by [`MontCtx1536::pow_secret`] to raise the message
//!     representative to `dP`/`dQ` during CRT signing.
//!
//! # Constant-time contract
//!
//! `pow_public_u64` and `pow_public_u1536` are **not** constant time
//! in the exponent. `pow_secret` is constant-time in the exponent
//! (fixed schedule, constant-time table lookup).

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
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    dead_code
)]

use crate::bigint1536::{LIMBS, U1536};
use crate::mont_impl::define_mont_type;

define_mont_type! {
    /// Derived Montgomery constants for a specific 1536-bit odd modulus.
    pub struct MontCtx1536 for U1536;
    limbs = 24;
    bits = 1536;
}

// ---- Keygen-specific: wide public-exponent ladder for Miller-Rabin ----

impl MontCtx1536 {
    /// `base^exp mod n` for a 1536-bit public exponent (Miller-Rabin
    /// witness path). Left-to-right square-and-multiply.
    /// **Not** constant time in `exp`.
    pub fn pow_public_u1536(&self, base: &U1536, exp: &U1536) -> U1536 {
        let mut top: Option<usize> = None;
        for i in (0..LIMBS).rev() {
            let limb = exp.limbs[i];
            if limb != 0 {
                top = Some(i * 64 + (63 - limb.leading_zeros() as usize));
                break;
            }
        }
        let Some(top_bit) = top else {
            let mut one = [0u64; LIMBS];
            one[0] = 1;
            return U1536 { limbs: one };
        };

        let base_mont = self.to_mont(base);
        let mut acc = base_mont;
        if top_bit > 0 {
            for i in (0..top_bit).rev() {
                acc = self.mont_mul(&acc, &acc);
                let limb = exp.limbs[i / 64];
                if (limb >> (i % 64)) & 1 == 1 {
                    acc = self.mont_mul(&acc, &base_mont);
                }
            }
        }
        self.from_mont(&acc)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn synthetic_modulus(seed: u64) -> U1536 {
        let mut limbs = [0u64; LIMBS];
        let mut x = seed | 1;
        for i in 0..LIMBS {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            limbs[i] = x;
        }
        limbs[0] |= 1;
        limbs[LIMBS - 1] |= 1 << 63;
        U1536 { limbs }
    }

    fn small(x: u64) -> U1536 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = x;
        U1536 { limbs }
    }

    #[test]
    fn mont_ctx_rejects_even_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[0] &= !1u64;
        assert!(MontCtx1536::new(n).is_none());
    }

    #[test]
    fn mont_ctx_rejects_short_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[LIMBS - 1] &= !(1 << 63);
        assert!(MontCtx1536::new(n).is_none());
    }

    #[test]
    fn mont_roundtrip_small_values() {
        let n = synthetic_modulus(42);
        let ctx = MontCtx1536::new(n).unwrap();
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
        let ctx = MontCtx1536::new(n).unwrap();
        let two = ctx.to_mont(&small(2));
        let three = ctx.to_mont(&small(3));
        let six = ctx.mont_mul(&two, &three);
        assert_eq!(ctx.from_mont(&six), small(6));
    }

    #[test]
    fn pow_public_u64_small_cases() {
        let n = synthetic_modulus(7);
        let ctx = MontCtx1536::new(n).unwrap();
        assert_eq!(ctx.pow_public_u64(&small(3), 7), small(2187));
        assert_eq!(ctx.pow_public_u64(&small(2), 16), small(65536));
        assert_eq!(ctx.pow_public_u64(&small(5), 0), small(1));
    }

    #[test]
    fn pow_public_u1536_matches_u64_for_small_exps() {
        let n = synthetic_modulus(321);
        let ctx = MontCtx1536::new(n).unwrap();
        let base = small(7);
        for exp in [0u64, 1, 2, 3, 17, 65537, 0xdead_beef] {
            let want = ctx.pow_public_u64(&base, exp);
            let got = ctx.pow_public_u1536(&base, &small(exp));
            assert_eq!(want, got, "disagreed at exp={exp}");
        }
    }

    #[test]
    fn pow_secret_matches_pow_public_u64_for_small_exps() {
        let n = synthetic_modulus(4242);
        let ctx = MontCtx1536::new(n).unwrap();
        let base = small(7);
        for exp in [0u64, 1, 2, 3, 17, 65537, 0xdead_beef] {
            let want = ctx.pow_public_u64(&base, exp);
            let got = ctx.pow_secret(&base, &small(exp));
            assert_eq!(want, got, "disagreed at exp={exp}");
        }
    }

    #[test]
    fn pow_secret_matches_pow_public_u1536_on_wide_exp() {
        let n = synthetic_modulus(0xcafe_f00d);
        let ctx = MontCtx1536::new(n).unwrap();
        let base = small(5);
        let mut exp_limbs = [0u64; LIMBS];
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for limb in &mut exp_limbs {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *limb = x;
        }
        let exp = U1536 { limbs: exp_limbs };
        let want = ctx.pow_public_u1536(&base, &exp);
        let got = ctx.pow_secret(&base, &exp);
        assert_eq!(want, got);
    }
}
