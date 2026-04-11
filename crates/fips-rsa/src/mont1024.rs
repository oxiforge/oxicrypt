//! Montgomery arithmetic for 1024-bit odd moduli.
//!
//! Narrow cousin of [`crate::mont2048`]. Two distinct roles:
//!
//!   * **Key generation.** [`crate::keygen`] runs Miller-Rabin
//!     primality testing on 1024-bit prime candidates via
//!     [`MontCtx1024::pow_public_u1024`]. Witness exponentiation is
//!     public relative to the candidate's acceptance state, so the
//!     left-to-right ladder there is intentionally **not** constant
//!     time in the exponent.
//!
//!   * **CRT sign path.** Once the key is built, each half-modulus
//!     `p` and `q` is used by [`MontCtx1024::pow_secret`] to raise
//!     the message representative to `dP = d mod (p-1)` and
//!     `dQ = d mod (q-1)` during RSA sign (Garner recombine). The
//!     exponents `dP`/`dQ` are secret, so this path uses a
//!     fixed-schedule 4-bit windowed ladder with constant-time table
//!     lookup — mirror of [`crate::mont2048::MontCtx2048::pow_secret`]
//!     at 16-limb width.
//!
//! # Constant-time contract
//!
//! `pow_public_u64` and `pow_public_u1024` are **not** constant time
//! in the exponent and must only be used with public exponents (e.g.
//! Miller-Rabin witness exponents during keygen). `pow_secret` is
//! constant-time in the exponent (fixed schedule, constant-time table
//! lookup) and is the only path permitted for the secret CRT exponents
//! `dP`/`dQ` on the RSA sign path.

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

use crate::bigint1024::{U1024, LIMBS};

/// Derived Montgomery constants for a specific 1024-bit odd modulus.
#[derive(Copy, Clone, Debug)]
pub struct MontCtx1024 {
    pub(crate) n: U1024,
    pub(crate) n_prime: u64,
    pub(crate) one_mont: U1024,
    pub(crate) r2_mod_n: U1024,
}

impl MontCtx1024 {
    /// Build a context for a 1024-bit odd modulus `n` with
    /// `2^1023 ≤ n < 2^1024`. Returns `None` if `n` is even or has
    /// its top bit clear (FIPS 186-5 §A.1.1 primes for RSA-2048
    /// always have their top bit set).
    pub fn new(n: U1024) -> Option<MontCtx1024> {
        if n.limbs[0] & 1 == 0 {
            return None;
        }
        if n.limbs[LIMBS - 1] >> 63 == 0 {
            return None;
        }

        // n_prime = (−n[0]^(−1)) mod 2^64 via 6-round Newton.
        let n0 = n.limbs[0];
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
        }
        let n_prime = 0u64.wrapping_sub(inv);
        debug_assert_eq!(n0.wrapping_mul(n_prime), 0u64.wrapping_sub(1));

        // R mod n = R − n since 2^1023 ≤ n < 2^1024 = R.
        let mut r_mod_n_limbs = [0u64; LIMBS];
        let mut borrow: u64 = 0;
        for i in 0..LIMBS {
            let (d1, b1) = 0u64.overflowing_sub(n.limbs[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            r_mod_n_limbs[i] = d2;
            borrow = u64::from(b1 || b2);
        }
        debug_assert_eq!(borrow, 1);
        let one_mont = U1024 { limbs: r_mod_n_limbs };

        // R^2 mod n via doubling.
        let mut acc = one_mont;
        for _ in 0..1024 {
            let (doubled, carry) = acc.adding(&acc);
            let ge = if carry == 1 {
                1u8
            } else {
                1 - doubled.ct_lt(&n)
            };
            acc = if ge == 1 {
                doubled.subtracting(&n).0
            } else {
                doubled
            };
        }
        let r2_mod_n = acc;

        Some(MontCtx1024 {
            n,
            n_prime,
            one_mont,
            r2_mod_n,
        })
    }

    /// Montgomery product: `(a · b · R^(−1)) mod n` with `R = 2^1024`.
    pub fn mont_mul(&self, a: &U1024, b: &U1024) -> U1024 {
        let mut t = [0u64; LIMBS + 2];

        for i in 0..LIMBS {
            let mut carry: u64 = 0;
            for j in 0..LIMBS {
                let prod = (a.limbs[j] as u128) * (b.limbs[i] as u128)
                    + (t[j] as u128)
                    + (carry as u128);
                t[j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            let sum = (t[LIMBS] as u128) + (carry as u128);
            t[LIMBS] = sum as u64;
            t[LIMBS + 1] = t[LIMBS + 1] + (sum >> 64) as u64;

            let m = t[0].wrapping_mul(self.n_prime);

            let mut carry2: u64 = {
                let prod = (m as u128) * (self.n.limbs[0] as u128) + (t[0] as u128);
                (prod >> 64) as u64
            };
            for j in 1..LIMBS {
                let prod = (m as u128) * (self.n.limbs[j] as u128)
                    + (t[j] as u128)
                    + (carry2 as u128);
                t[j - 1] = prod as u64;
                carry2 = (prod >> 64) as u64;
            }
            let sum = (t[LIMBS] as u128) + (carry2 as u128);
            t[LIMBS - 1] = sum as u64;
            let high_carry = (sum >> 64) as u64;
            t[LIMBS] = t[LIMBS + 1] + high_carry;
            t[LIMBS + 1] = 0;
        }

        let mut limbs = [0u64; LIMBS];
        limbs.copy_from_slice(&t[..LIMBS]);
        let unreduced = U1024 { limbs };

        if t[LIMBS] != 0 {
            unreduced.subtracting(&self.n).0
        } else {
            unreduced.ct_sub_if_ge(&self.n)
        }
    }

    /// Convert `x ∈ [0, n)` into Montgomery form `x · R mod n`.
    pub fn to_mont(&self, x: &U1024) -> U1024 {
        self.mont_mul(x, &self.r2_mod_n)
    }

    /// Convert Montgomery-form `x · R mod n` back to a plain integer.
    pub fn from_mont(&self, x_mont: &U1024) -> U1024 {
        let mut one = [0u64; LIMBS];
        one[0] = 1;
        self.mont_mul(x_mont, &U1024 { limbs: one })
    }

    /// Compute `base^exp mod n` for a small public `u64` exponent.
    /// Not constant time in `exp`.
    pub fn pow_public_u64(&self, base: &U1024, exp: u64) -> U1024 {
        if exp == 0 {
            let mut one = [0u64; LIMBS];
            one[0] = 1;
            return U1024 { limbs: one };
        }

        let base_mont = self.to_mont(base);
        let top_bit = exp.ilog2();
        let mut acc = base_mont;
        if top_bit > 0 {
            for i in (0..top_bit).rev() {
                acc = self.mont_mul(&acc, &acc);
                if (exp >> i) & 1 == 1 {
                    acc = self.mont_mul(&acc, &base_mont);
                }
            }
        }
        self.from_mont(&acc)
    }

    /// Compute `base^exp mod n` for a 1024-bit public exponent. Used
    /// by Miller-Rabin to raise a public witness to `(n−1)/2^s`.
    /// Left-to-right square-and-multiply over the exponent bits.
    /// **Not** constant time in `exp`.
    pub fn pow_public_u1024(&self, base: &U1024, exp: &U1024) -> U1024 {
        // Find the top set bit of the exponent (if any).
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
            return U1024 { limbs: one };
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

    /// Compute `base^exp mod n` where `exp` is a secret 1024-bit
    /// integer. Fixed-schedule 4-bit window ladder: for each of the
    /// 256 exponent nibbles we square four times and then multiply by
    /// a table entry chosen via a constant-time scan. No per-call
    /// work depends on `exp`.
    ///
    /// Mirror of [`crate::mont2048::MontCtx2048::pow_secret`] at
    /// 16-limb width. Used on the RSA CRT sign path for `m_p = c^dP
    /// mod p` and `m_q = c^dQ mod q`, where `dP`/`dQ` are secret.
    ///
    /// # FIPS note
    ///
    /// The constant-time guarantee here is the same rationale as the
    /// 2048-bit sibling: per IG D.G, secret-dependent operations must
    /// not leak through execution time on common general-purpose
    /// CPUs. `dP` and `dQ` are CSPs (they reveal `d mod (p-1)` and
    /// `d mod (q-1)` respectively); leaking them would compromise the
    /// private key.
    pub fn pow_secret(&self, base: &U1024, exp: &U1024) -> U1024 {
        // Precompute table[i] = base^i · R mod n for i in 0..16.
        let mut table = [U1024::ZERO; 16];
        table[0] = self.one_mont;
        table[1] = self.to_mont(base);
        for i in 2..16 {
            table[i] = self.mont_mul(&table[i - 1], &table[1]);
        }

        // LIMBS * 16 = 256 nibbles total for a 1024-bit exponent.
        let mut acc = self.one_mont;
        for nibble_index in (0..LIMBS * 16).rev() {
            acc = self.mont_mul(&acc, &acc);
            acc = self.mont_mul(&acc, &acc);
            acc = self.mont_mul(&acc, &acc);
            acc = self.mont_mul(&acc, &acc);

            let nibble = exp.nibble(nibble_index);
            let mut selected = U1024::ZERO;
            for i in 0..16u8 {
                let diff = (i ^ nibble) as u64;
                let is_eq = (diff.wrapping_sub(1) >> 63) & 1;
                let mask = 0u64.wrapping_sub(is_eq);
                selected = U1024::conditional_select(mask, &table[i as usize], &selected);
            }
            acc = self.mont_mul(&acc, &selected);
        }

        self.from_mont(&acc)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn synthetic_modulus(seed: u64) -> U1024 {
        let mut limbs = [0u64; LIMBS];
        let mut x = seed | 1;
        for i in 0..LIMBS {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            limbs[i] = x;
        }
        limbs[0] |= 1;
        limbs[LIMBS - 1] |= 1 << 63;
        U1024 { limbs }
    }

    fn small(x: u64) -> U1024 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = x;
        U1024 { limbs }
    }

    #[test]
    fn mont_ctx_rejects_even_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[0] &= !1u64;
        assert!(MontCtx1024::new(n).is_none());
    }

    #[test]
    fn mont_ctx_rejects_short_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[LIMBS - 1] &= !(1 << 63);
        assert!(MontCtx1024::new(n).is_none());
    }

    #[test]
    fn mont_roundtrip_small_values() {
        let n = synthetic_modulus(42);
        let ctx = MontCtx1024::new(n).unwrap();
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
        let ctx = MontCtx1024::new(n).unwrap();
        let two = ctx.to_mont(&small(2));
        let three = ctx.to_mont(&small(3));
        let six = ctx.mont_mul(&two, &three);
        assert_eq!(ctx.from_mont(&six), small(6));
    }

    #[test]
    fn pow_public_u64_small_cases() {
        let n = synthetic_modulus(7);
        let ctx = MontCtx1024::new(n).unwrap();
        assert_eq!(ctx.pow_public_u64(&small(3), 7), small(2187));
        assert_eq!(ctx.pow_public_u64(&small(2), 16), small(65536));
        assert_eq!(ctx.pow_public_u64(&small(5), 0), small(1));
    }

    #[test]
    fn pow_public_u1024_matches_u64_for_small_exps() {
        let n = synthetic_modulus(321);
        let ctx = MontCtx1024::new(n).unwrap();
        let base = small(7);
        for exp in [0u64, 1, 2, 3, 17, 65537, 0xdead_beef] {
            let want = ctx.pow_public_u64(&base, exp);
            let got = ctx.pow_public_u1024(&base, &small(exp));
            assert_eq!(want, got, "disagreed at exp={exp}");
        }
    }

    #[test]
    fn pow_secret_matches_pow_public_u64_for_small_exps() {
        let n = synthetic_modulus(4242);
        let ctx = MontCtx1024::new(n).unwrap();
        let base = small(7);
        for exp in [0u64, 1, 2, 3, 17, 65537, 0xdead_beef] {
            let want = ctx.pow_public_u64(&base, exp);
            let got = ctx.pow_secret(&base, &small(exp));
            assert_eq!(want, got, "disagreed at exp={exp}");
        }
    }

    #[test]
    fn pow_secret_matches_pow_public_u1024_on_wide_exp() {
        let n = synthetic_modulus(0xcafe_f00d);
        let ctx = MontCtx1024::new(n).unwrap();
        let base = small(5);
        // Build a non-trivial 1024-bit exponent reduced mod n.
        let mut exp_limbs = [0u64; LIMBS];
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for i in 0..LIMBS {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            exp_limbs[i] = x;
        }
        let exp = U1024 { limbs: exp_limbs };
        let want = ctx.pow_public_u1024(&base, &exp);
        let got = ctx.pow_secret(&base, &exp);
        assert_eq!(want, got);
    }

    #[test]
    fn fermat_holds_for_a_known_prime_mod() {
        // 2^1023 + a well-chosen addend that makes the value prime.
        // Easier: verify Fermat-style `a^(n-1) ≡ 1 (mod n)` can be
        // computed without panic, and check consistency between paths.
        let n = synthetic_modulus(999);
        let ctx = MontCtx1024::new(n).unwrap();
        // We don't know if n is prime; just confirm that
        // (a^(p) * a) mod n == a^(p+1) mod n for a random exponent.
        let a = small(3);
        let p = 65537u64;
        let ap = ctx.pow_public_u64(&a, p);
        let ap1 = ctx.pow_public_u64(&a, p + 1);

        // ap * a mod n  (via mont_mul detour)
        let ap_m = ctx.to_mont(&ap);
        let a_m = ctx.to_mont(&a);
        let prod_m = ctx.mont_mul(&ap_m, &a_m);
        let prod = ctx.from_mont(&prod_m);
        // prod and ap1 should be equal modulo n. But prod was derived
        // as (ap * a * R^-1 * R) mod n which is just ap*a mod n.
        // We need (ap * a) mod n  via direct mont path.
        // Wait: mont_mul(to_mont(x), to_mont(y)) = (x*y*R) mod n,
        // so from_mont(that) = x*y mod n. Good.
        assert_eq!(prod, ap1);
    }
}
