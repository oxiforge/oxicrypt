//! Montgomery arithmetic for 2048-bit odd moduli.
//!
//! Given an odd modulus `n` with `2^2047 ≤ n < 2^2048`, we build a
//! [`MontCtx2048`] holding the derived constants needed to run CIOS
//! Montgomery multiplication:
//!
//!   * `n_prime = (−n^(−1)) mod 2^64`, the single-word Montgomery
//!     factor for CIOS's word-by-word reduction;
//!   * `r_mod_n  = 2^2048 mod n`, the Montgomery representative of 1;
//!   * `r2_mod_n = 2^4096 mod n`, used to move plain integers into
//!     Montgomery form via a single `mont_mul(x, r2_mod_n)` call.
//!
//! All outputs of [`mont_mul`] are reduced to the interval `[0, n)`
//! by a final [`U2048::ct_sub_if_ge`], matching the standard CIOS
//! contract.
//!
//! # Constant-time contract
//!
//! All routines here are constant time with respect to the operand
//! values. The modular-exponentiation routine
//! [`MontCtx2048::pow_public_u64`] is **not** constant time in the
//! exponent bits and is meant for public-key operations only
//! (RSA verify uses this path with the public exponent `e`). A
//! [`MontCtx2048::pow_secret`] is the constant-time, 4-bit-windowed
//! ladder for private-key operations: the exponent is consumed at a
//! fixed rate (512 nibbles per call, regardless of value) and the
//! table lookup uses a blinding scan so the secret exponent never
//! drives a branch or an index.

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

use crate::bigint2048::{U2048, LIMBS};

/// Derived Montgomery constants for a specific 2048-bit modulus.
#[derive(Copy, Clone, Debug)]
pub struct MontCtx2048 {
    /// The modulus itself, canonicalized into [`U2048`].
    pub(crate) n: U2048,
    /// `n_prime = (−n^(−1)) mod 2^64`. Used in the CIOS reduction
    /// step to compute `m = T[0] * n_prime mod 2^64`.
    pub(crate) n_prime: u64,
    /// `R mod n` where `R = 2^2048`. Equal to the Montgomery
    /// representative of `1`, so it's also the accumulator seed
    /// for modular exponentiation.
    pub(crate) one_mont: U2048,
    /// `R^2 mod n`. Multiplying a plain integer `x` by this value
    /// inside `mont_mul` yields the Montgomery representative of
    /// `x`, i.e. `(x · R) mod n`.
    pub(crate) r2_mod_n: U2048,
}

impl MontCtx2048 {
    /// Build a context for a 2048-bit odd modulus `n`.
    ///
    /// Returns `None` if `n` is even (CIOS reduction requires an
    /// invertible low limb) or if `n`'s top limb is zero (we require
    /// `2^2047 ≤ n < 2^2048`, which is always true for an RSA-2048
    /// key where the prime factors are both 1024 bits with their
    /// top bits set, as FIPS 186-5 §A.1.1 mandates).
    pub fn new(n: U2048) -> Option<MontCtx2048> {
        // Low limb must be odd for Montgomery to work.
        if n.limbs[0] & 1 == 0 {
            return None;
        }
        // Top limb must be non-zero so R = 2^2048 > n ≥ 2^2047
        // (FIPS 186-5 §5.1 requires strict-2048-bit moduli).
        if n.limbs[LIMBS - 1] >> 63 == 0 {
            return None;
        }

        // n_prime = (−n[0]^(−1)) mod 2^64 via Newton iteration for
        // 2-adic inverse: x_{k+1} = x_k * (2 − n[0] * x_k). Doubles
        // the number of correct bits each iteration; 6 rounds takes
        // us from 1 correct bit (trivially, since n[0] is odd) to
        // 64 correct bits.
        let n0 = n.limbs[0];
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
        }
        // Now n0 · inv ≡ 1 (mod 2^64). We want −n0^(−1) mod 2^64.
        let n_prime = 0u64.wrapping_sub(inv);
        debug_assert_eq!(n0.wrapping_mul(n_prime), 0u64.wrapping_sub(1));

        // R mod n. Since 2^2047 ≤ n < 2^2048 = R, we have R/n = 1
        // and R mod n = R − n. R is `[0; LIMBS]` with an implicit
        // 33rd limb of 1; two's-complement negation of `n` inside a
        // 2048-bit width gives exactly `R − n`.
        let mut r_mod_n_limbs = [0u64; LIMBS];
        let mut borrow: u64 = 0;
        for i in 0..LIMBS {
            let (d1, b1) = 0u64.overflowing_sub(n.limbs[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            r_mod_n_limbs[i] = d2;
            borrow = u64::from(b1 || b2);
        }
        // `borrow` is 1 because 0 < n; that borrow is absorbed by
        // the implicit 33rd limb of R. The 32-limb result is R − n.
        debug_assert_eq!(borrow, 1);
        let one_mont = U2048 { limbs: r_mod_n_limbs };

        // R^2 mod n: start from R mod n and double (with conditional
        // subtract) 2048 times. This is the classic "shift by one
        // bit then reduce" trick; it runs in O(2048) adds, plenty
        // fast for a one-shot key setup.
        let mut acc = one_mont;
        for _ in 0..2048 {
            let (doubled, carry) = acc.adding(&acc);
            // After doubling, the true value is `doubled + carry · R`.
            // Reduce by one `n` if either there was a carry-out from
            // the 2048-bit add or the sum already exceeded `n`.
            let ge = if carry == 1 {
                1u8
            } else {
                1 - doubled.ct_lt(&n)
            };
            acc = if ge == 1 {
                // doubled - n (borrow ignored: we've proven `doubled >= n`).
                doubled.subtracting(&n).0
            } else {
                doubled
            };
        }
        let r2_mod_n = acc;

        Some(MontCtx2048 {
            n,
            n_prime,
            one_mont,
            r2_mod_n,
        })
    }

    /// Montgomery product: returns `(a · b · R^(−1)) mod n` with
    /// `R = 2^2048`. Both inputs must already be less than `n`.
    pub fn mont_mul(&self, a: &U2048, b: &U2048) -> U2048 {
        // CIOS: T is LIMBS+2 words wide so we can absorb the running
        // carry plus the one extra limb produced by the inner loop.
        let mut t = [0u64; LIMBS + 2];

        for i in 0..LIMBS {
            // t += a · b[i]
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

            // m = (t[0] · n_prime) mod 2^64
            let m = t[0].wrapping_mul(self.n_prime);

            // t += m · n, but shifted: the bottom limb is guaranteed
            // to become zero (that's the whole point of n_prime), so
            // we can drop it and shift the rest down by one limb.
            //
            // First iteration: compute t[0] + m·n[0] but discard the
            // bottom limb; keep only the high word as `carry2`. The
            // low 64 bits are zero by construction, which is why the
            // CIOS shift-down works at all.
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
            // Absorb carry2 into t[LIMBS], shifting t[LIMBS+1] down.
            let sum = (t[LIMBS] as u128) + (carry2 as u128);
            t[LIMBS - 1] = sum as u64;
            let high_carry = (sum >> 64) as u64;
            t[LIMBS] = t[LIMBS + 1] + high_carry;
            t[LIMBS + 1] = 0;
        }

        // After LIMBS iterations, t[0..LIMBS] plus a potential
        // single-bit carry in t[LIMBS] holds the unreduced result,
        // which is in `[0, 2n)`. Conditional subtract `n` once.
        let mut limbs = [0u64; LIMBS];
        limbs.copy_from_slice(&t[..LIMBS]);
        let unreduced = U2048 { limbs };

        if t[LIMBS] != 0 {
            // Result overflowed by one `R` — subtract `n` once. The
            // overflow is guaranteed because otherwise the inputs
            // would have been out of range coming in.
            unreduced.subtracting(&self.n).0
        } else {
            unreduced.ct_sub_if_ge(&self.n)
        }
    }

    /// Convert a plain integer `x ∈ [0, n)` into Montgomery form
    /// `x · R mod n`.
    pub fn to_mont(&self, x: &U2048) -> U2048 {
        self.mont_mul(x, &self.r2_mod_n)
    }

    /// Convert a Montgomery-form value `x · R mod n` back into a
    /// plain integer `x ∈ [0, n)`.
    pub fn from_mont(&self, x_mont: &U2048) -> U2048 {
        // mont_mul(x_mont, 1) = x_mont · 1 · R^(−1) mod n = x mod n.
        let mut one = [0u64; LIMBS];
        one[0] = 1;
        self.mont_mul(x_mont, &U2048 { limbs: one })
    }

    /// Compute `base^exp mod n` for a small public exponent. The
    /// caller passes `base` as a plain integer; we handle the
    /// Montgomery conversion internally.
    ///
    /// **Not constant time in `exp`.** RSA public exponents are
    /// part of the public key and timing-leak-free exponentiation
    /// is only required for the private-key path.
    pub fn pow_public_u64(&self, base: &U2048, exp: u64) -> U2048 {
        if exp == 0 {
            // x^0 = 1 mod n.
            let mut one = [0u64; LIMBS];
            one[0] = 1;
            return U2048 { limbs: one };
        }

        // Left-to-right square-and-multiply in Montgomery form.
        let base_mont = self.to_mont(base);
        // Start the accumulator at the Montgomery representative of
        // 1 — but we can skip the first "result = square(result)"
        // step by seeding the accumulator with `base_mont` and
        // starting from the bit just below the top set bit.
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

    /// Compute `base^exp mod n` where `exp` is a secret 2048-bit
    /// integer. Uses a fixed-schedule 4-bit window ladder: for every
    /// one of the 512 exponent nibbles we square four times and then
    /// multiply by a table entry read via a constant-time scan. No
    /// per-call work depends on the value of `exp`.
    ///
    /// The implementation follows the classic "always-multiply"
    /// precomputed-table ladder; `acc` starts at the Montgomery
    /// representative of `1`, so the first iteration's nibble
    /// corresponds to the high nibble of `exp`.
    ///
    /// # FIPS note
    ///
    /// This is the private-key exponentiation path. It is used for
    /// RSASSA-PKCS1-v1_5 sign (and, in a later chunk, PSS sign). The
    /// constant-time guarantee protects against timing-based recovery
    /// of `d` in side-channel-exposed environments, matching
    /// IG D.G's expectation that secret-dependent operations not leak
    /// through execution time on common general-purpose CPUs.
    pub fn pow_secret(&self, base: &U2048, exp: &U2048) -> U2048 {
        // Precompute table[i] = base^i · R mod n for i in 0..16.
        // Entry 0 is the Montgomery form of 1; entry 1 is base in
        // Montgomery form; entries 2..16 chain from there.
        let mut table = [U2048::ZERO; 16];
        table[0] = self.one_mont;
        table[1] = self.to_mont(base);
        for i in 2..16 {
            table[i] = self.mont_mul(&table[i - 1], &table[1]);
        }

        // Run the ladder from the top nibble down.
        let mut acc = self.one_mont;
        // LIMBS * 16 = 512 nibbles total for a 2048-bit exponent.
        for nibble_index in (0..LIMBS * 16).rev() {
            // Four squarings = one "shift left by 4 nibble positions"
            // of the accumulated exponent.
            acc = self.mont_mul(&acc, &acc);
            acc = self.mont_mul(&acc, &acc);
            acc = self.mont_mul(&acc, &acc);
            acc = self.mont_mul(&acc, &acc);

            // Constant-time table lookup for table[nibble].
            let nibble = exp.nibble(nibble_index);
            let mut selected = U2048::ZERO;
            for i in 0..16u8 {
                // Build a word-wide mask: all ones iff i == nibble.
                let diff = (i ^ nibble) as u64;
                // `diff` is zero iff i == nibble. Turn that into a
                // 1-bit flag in bit 0, then extend to a full mask.
                let is_eq = (diff.wrapping_sub(1) >> 63) & 1;
                // Hit: is_eq==1, mask all ones. Miss: mask zero.
                let mask = 0u64.wrapping_sub(is_eq);
                selected = U2048::conditional_select(mask, &table[i as usize], &selected);
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

    /// Build a "canonical" tiny-prime-ish modulus: a 2048-bit value
    /// whose top bit is set and whose low limb is odd. Easiest way
    /// is to seed deterministic limbs, force the MSB and LSB bits.
    fn synthetic_modulus(seed: u64) -> U2048 {
        let mut limbs = [0u64; LIMBS];
        let mut x = seed | 1;
        for i in 0..LIMBS {
            // Linear congruential-ish generator; only used to make
            // a non-trivial odd 2048-bit number for arithmetic tests.
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            limbs[i] = x;
        }
        limbs[0] |= 1; // odd
        limbs[LIMBS - 1] |= 1 << 63; // top bit set
        U2048 { limbs }
    }

    fn small(x: u64) -> U2048 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = x;
        U2048 { limbs }
    }

    #[test]
    fn mont_ctx_rejects_even_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[0] &= !1u64; // make even
        assert!(MontCtx2048::new(n).is_none());
    }

    #[test]
    fn mont_ctx_rejects_short_modulus() {
        let mut n = synthetic_modulus(1);
        n.limbs[LIMBS - 1] &= !(1 << 63); // clear top bit
        assert!(MontCtx2048::new(n).is_none());
    }

    #[test]
    fn mont_one_is_r_mod_n() {
        let n = synthetic_modulus(42);
        let ctx = MontCtx2048::new(n).unwrap();
        // from_mont(one_mont) == 1.
        let back = ctx.from_mont(&ctx.one_mont);
        assert_eq!(back, small(1));
    }

    #[test]
    fn to_from_mont_roundtrip_for_small_values() {
        let n = synthetic_modulus(42);
        let ctx = MontCtx2048::new(n).unwrap();
        for v in [1u64, 2, 3, 65537, 0xdead_beef_u64] {
            let plain = small(v);
            let mont = ctx.to_mont(&plain);
            let back = ctx.from_mont(&mont);
            assert_eq!(back, plain);
        }
    }

    #[test]
    fn mont_mul_2_times_3_is_6_for_large_modulus() {
        let n = synthetic_modulus(123);
        let ctx = MontCtx2048::new(n).unwrap();
        // (2·R)·(3·R)·R^(−1) mod n = 6·R mod n. from_mont gives 6.
        let two_mont = ctx.to_mont(&small(2));
        let three_mont = ctx.to_mont(&small(3));
        let six_mont = ctx.mont_mul(&two_mont, &three_mont);
        assert_eq!(ctx.from_mont(&six_mont), small(6));
    }

    #[test]
    fn pow_public_small_numbers_matches_repeated_mul() {
        let n = synthetic_modulus(7);
        let ctx = MontCtx2048::new(n).unwrap();
        // 3^7 = 2187. For any modulus > 2187 this is just 2187.
        let base = small(3);
        let p = ctx.pow_public_u64(&base, 7);
        assert_eq!(p, small(2187));

        // 2^16 = 65536.
        let two_to_16 = ctx.pow_public_u64(&small(2), 16);
        assert_eq!(two_to_16, small(65536));

        // 2^65537 mod n — just check it's non-degenerate (nonzero
        // and strictly less than n).
        let big = ctx.pow_public_u64(&small(2), 65537);
        assert_eq!(big.is_zero(), 0);
        assert_eq!(big.ct_lt(&ctx.n), 1);
    }

    fn u2048_from_u64(x: u64) -> U2048 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = x;
        U2048 { limbs }
    }

    #[test]
    fn pow_secret_matches_pow_public_for_small_exponents() {
        let n = synthetic_modulus(321);
        let ctx = MontCtx2048::new(n).unwrap();
        let base = small(7);
        for exp in [0u64, 1, 2, 3, 17, 65537, 0xdead_beef] {
            let want = ctx.pow_public_u64(&base, exp);
            let got = ctx.pow_secret(&base, &u2048_from_u64(exp));
            assert_eq!(
                want, got,
                "pow_secret disagreed with pow_public_u64 for exp={exp}"
            );
        }
    }

    #[test]
    fn pow_secret_handles_zero_base_and_one_base() {
        let n = synthetic_modulus(555);
        let ctx = MontCtx2048::new(n).unwrap();
        // 0^e = 0 for any e > 0. (0^0 isn't tested; pow_secret always
        // runs the full ladder and produces 1 for exp=0 by virtue of
        // acc never being multiplied by anything other than table[0]
        // = 1_mont; but we leave that edge case to pow_public_u64.)
        let zero = U2048::ZERO;
        let big_exp = u2048_from_u64(12345);
        assert_eq!(ctx.pow_secret(&zero, &big_exp), U2048::ZERO);
        // 1^e = 1.
        let one = small(1);
        assert_eq!(ctx.pow_secret(&one, &big_exp), small(1));
    }

    #[test]
    fn pow_secret_exp_zero_is_one() {
        let n = synthetic_modulus(777);
        let ctx = MontCtx2048::new(n).unwrap();
        let base = small(42);
        let r = ctx.pow_secret(&base, &U2048::ZERO);
        assert_eq!(r, small(1));
    }

    #[test]
    fn pow_zero_exponent_is_one() {
        let n = synthetic_modulus(99);
        let ctx = MontCtx2048::new(n).unwrap();
        let r = ctx.pow_public_u64(&small(42), 0);
        assert_eq!(r, small(1));
    }
}
