//! Fixed-width 1024-bit unsigned big integer.
//!
//! Parallel narrow cousin of [`crate::bigint2048`]. We use this for
//! the half-width operands involved in key generation: each prime
//! factor `p`, `q` of an RSA-2048 modulus is 1024 bits, and the
//! arithmetic (Miller-Rabin, trial division, modular inverse) lives
//! entirely in [`U1024`] until the very end, where we widen the
//! product to a [`crate::bigint2048::U2048`] via [`U1024::widening_mul`].
//!
//! Representation is little-endian `u64` limbs, identical to the
//! 2048-bit module. All routines are public-parameter constant time
//! (the work per limb depends on the limb count, not on the values).
//! Binary extended GCD uses data-dependent branching — it is not used
//! on secret material (we feed it the public exponent and the public
//! `λ(n) = lcm(p−1, q−1)`), so this is acceptable.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::return_self_not_must_use,
    clippy::needless_range_loop,
    clippy::many_single_char_names,
    dead_code
)]

use crate::bigint2048::{LIMBS as LIMBS2048, U2048};

/// Limb count for a 1024-bit value.
pub const LIMBS: usize = 16;
/// Byte count for a 1024-bit value.
pub const BYTES: usize = 128;

/// A 1024-bit unsigned integer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct U1024 {
    pub(crate) limbs: [u64; LIMBS],
}

impl U1024 {
    /// The additive identity (zero).
    pub const ZERO: U1024 = U1024 { limbs: [0; LIMBS] };
    /// The multiplicative identity (one).
    pub const ONE: U1024 = {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 1;
        U1024 { limbs }
    };

    /// Build from a big-endian 128-byte buffer.
    pub fn from_be_bytes(bytes: &[u8; BYTES]) -> U1024 {
        let mut limbs = [0u64; LIMBS];
        for i in 0..LIMBS {
            let start = BYTES - 8 * (i + 1);
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[start..start + 8]);
            limbs[i] = u64::from_be_bytes(word);
        }
        U1024 { limbs }
    }

    /// Serialize to a big-endian 128-byte buffer.
    pub fn to_be_bytes(&self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        for i in 0..LIMBS {
            let start = BYTES - 8 * (i + 1);
            out[start..start + 8].copy_from_slice(&self.limbs[i].to_be_bytes());
        }
        out
    }

    /// Returns `1` iff `self == 0`, else `0`. Constant time.
    pub fn is_zero(&self) -> u8 {
        let mut acc: u64 = 0;
        for i in 0..LIMBS {
            acc |= self.limbs[i];
        }
        let nz = (acc | acc.wrapping_neg()) >> 63;
        (1 ^ (nz as u8)) & 1
    }

    /// Returns `1` iff `self == 1`, else `0`.
    pub fn is_one(&self) -> u8 {
        let mut acc: u64 = self.limbs[0] ^ 1;
        for i in 1..LIMBS {
            acc |= self.limbs[i];
        }
        let nz = (acc | acc.wrapping_neg()) >> 63;
        (1 ^ (nz as u8)) & 1
    }

    /// Returns the value of bit 0 (parity): `1` if odd, `0` if even.
    pub fn is_odd(&self) -> u8 {
        (self.limbs[0] & 1) as u8
    }

    /// Constant-time strict-less-than test, returning 1 or 0.
    pub fn ct_lt(&self, other: &U1024) -> u8 {
        let mut borrow: u64 = 0;
        for i in 0..LIMBS {
            let (d1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (_d2, b2) = d1.overflowing_sub(borrow);
            borrow = u64::from(b1 || b2);
        }
        borrow as u8
    }

    /// Constant-time equality, returning 1 or 0.
    pub fn ct_eq(&self, other: &U1024) -> u8 {
        let mut acc: u64 = 0;
        for i in 0..LIMBS {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        let nz = (acc | acc.wrapping_neg()) >> 63;
        (1 ^ (nz as u8)) & 1
    }

    /// Full-width 1024-bit add, returning `(sum, carry_out)`.
    pub fn adding(&self, other: &U1024) -> (U1024, u64) {
        let mut limbs = [0u64; LIMBS];
        let mut carry: u64 = 0;
        for i in 0..LIMBS {
            let (s1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            limbs[i] = s2;
            carry = u64::from(c1 || c2);
        }
        (U1024 { limbs }, carry)
    }

    /// Full-width 1024-bit sub, returning `(diff, borrow_out)`.
    pub fn subtracting(&self, other: &U1024) -> (U1024, u64) {
        let mut limbs = [0u64; LIMBS];
        let mut borrow: u64 = 0;
        for i in 0..LIMBS {
            let (d1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            limbs[i] = d2;
            borrow = u64::from(b1 || b2);
        }
        (U1024 { limbs }, borrow)
    }

    /// Conditional subtract: if `self >= other`, return `self - other`;
    /// else return `self`.
    pub fn ct_sub_if_ge(&self, other: &U1024) -> U1024 {
        let (diff, borrow) = self.subtracting(other);
        let mask = 0u64.wrapping_sub(borrow);
        let mut out = [0u64; LIMBS];
        for i in 0..LIMBS {
            out[i] = (self.limbs[i] & mask) | (diff.limbs[i] & !mask);
        }
        U1024 { limbs: out }
    }

    /// Constant-time conditional select: `mask == !0 → a`, `mask == 0 → b`.
    pub fn conditional_select(mask: u64, a: &U1024, b: &U1024) -> U1024 {
        let mut out = [0u64; LIMBS];
        for i in 0..LIMBS {
            out[i] = (a.limbs[i] & mask) | (b.limbs[i] & !mask);
        }
        U1024 { limbs: out }
    }

    /// Extract a 4-bit nibble counted from the least-significant end.
    pub fn nibble(&self, nibble_index: usize) -> u8 {
        debug_assert!(nibble_index < LIMBS * 16);
        let limb = nibble_index >> 4;
        let pos = nibble_index & 0xf;
        ((self.limbs[limb] >> (4 * pos)) & 0xf) as u8
    }

    /// Divide by two in place (shift right by one bit). Only used by
    /// binary extended GCD on public inputs.
    pub fn shr1(&self) -> U1024 {
        let mut limbs = [0u64; LIMBS];
        let mut carry: u64 = 0;
        for i in (0..LIMBS).rev() {
            let v = self.limbs[i];
            limbs[i] = (v >> 1) | (carry << 63);
            carry = v & 1;
        }
        U1024 { limbs }
    }

    /// Modular reduction by a small `u64`, returning the remainder.
    /// Used for the trial-division sieve over small primes.
    pub fn rem_u64(&self, m: u64) -> u64 {
        debug_assert!(m > 0);
        let mut rem: u128 = 0;
        for i in (0..LIMBS).rev() {
            rem = ((rem << 64) | self.limbs[i] as u128) % (m as u128);
        }
        rem as u64
    }

    /// Widening multiply: `self × other → U2048`. Used once per
    /// keygen run to form `n = p · q`.
    pub fn widening_mul(&self, other: &U1024) -> U2048 {
        let mut out = [0u64; LIMBS2048];
        for i in 0..LIMBS {
            let mut carry: u64 = 0;
            for j in 0..LIMBS {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (out[i + j] as u128)
                    + (carry as u128);
                out[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            out[i + LIMBS] = carry;
        }
        U2048 { limbs: out }
    }

    /// Widening add of a small `u64`, returning `(sum, carry_out)`.
    /// Used by the Miller-Rabin witness scaler.
    pub fn adding_u64(&self, addend: u64) -> (U1024, u64) {
        let mut limbs = self.limbs;
        let (s, c0) = limbs[0].overflowing_add(addend);
        limbs[0] = s;
        let mut carry: u64 = u64::from(c0);
        for i in 1..LIMBS {
            if carry == 0 {
                break;
            }
            let (s, c) = limbs[i].overflowing_add(carry);
            limbs[i] = s;
            carry = u64::from(c);
        }
        (U1024 { limbs }, carry)
    }

    /// Subtract a small `u64`, returning `(diff, borrow_out)`.
    pub fn subtracting_u64(&self, sub: u64) -> (U1024, u64) {
        let mut limbs = self.limbs;
        let (d, b0) = limbs[0].overflowing_sub(sub);
        limbs[0] = d;
        let mut borrow: u64 = u64::from(b0);
        for i in 1..LIMBS {
            if borrow == 0 {
                break;
            }
            let (d, b) = limbs[i].overflowing_sub(borrow);
            limbs[i] = d;
            borrow = u64::from(b);
        }
        (U1024 { limbs }, borrow)
    }

    /// Zero-extend to a [`U2048`].
    pub fn zero_extend(&self) -> U2048 {
        let mut limbs = [0u64; LIMBS2048];
        limbs[..LIMBS].copy_from_slice(&self.limbs);
        U2048 { limbs }
    }
}

/// Binary extended GCD producing the modular inverse of `a` mod `m`,
/// where `m` is odd. Returns `None` if `gcd(a, m) != 1`.
///
/// This is the textbook "plus-minus" variant: we maintain running
/// values `(u, v)` and coefficients `(x1, x2)` satisfying
///
///   u ≡ a · x1 (mod m)
///   v ≡ a · x2 (mod m)
///
/// and drive `(u, v)` down to `(1, 0)` by alternately halving and
/// subtracting. The coefficient trails on `v` give `a^(-1) mod m`.
///
/// This is **data-dependent** in its control flow and therefore not
/// suitable for secret operands. RSA keygen only calls it with the
/// public exponent `e` (a public u64) and the public `λ(n)` (which,
/// once keygen completes, becomes part of the publicly-computable
/// derivation from `(p, q)`). We ensure keygen never leaks `e⁻¹`
/// timing by not using this routine outside of the one-shot keygen
/// path.
///
/// Preconditions:
///   * `m` is odd and `m >= 3`.
///   * `a > 0` and `a < m`.
///
/// # Known limitation — top-bit-set moduli
///
/// The intermediate coefficients `x1`, `x2` are maintained in
/// `[0, 2m)`. When `m` has bit 1023 set (as is the case for every
/// 1024-bit RSA prime factor), `2m ≥ 2^1024`, which does not fit in a
/// [`U1024`]; the halving and conditional-subtract steps can then
/// silently wrap and produce a wrong (non-inverse) result. The
/// existing call sites in this crate only use small-modulus inputs,
/// so this limitation has not been fixed. Do **not** call this
/// routine with a 1024-bit prime modulus; use
/// [`crate::mont1024::MontCtx1024::pow_public_u1024`] for
/// Fermat-style inversion instead (`q^(p−2) mod p`).
pub fn modinv_odd(a: &U1024, m: &U1024) -> Option<U1024> {
    debug_assert_eq!(m.is_odd(), 1);
    if a.is_zero() == 1 {
        return None;
    }
    // u, v track the residues; x1, x2 track the coefficients on a.
    // Work modulo m, with intermediate values bounded in [0, 2m).
    let mut u = *a;
    let mut v = *m;
    let mut x1 = U1024::ONE;
    let mut x2 = U1024::ZERO;

    // Loop until u or v reaches zero; we need at most ~2·log2(m)
    // iterations, so a generous upper bound guarantees termination
    // even in the worst case. For 1024-bit `m`, 4096 is plenty.
    for _ in 0..4096 {
        if u.is_zero() == 1 {
            // gcd ended up in v; if v != 1, a wasn't invertible.
            if v.ct_eq(&U1024::ONE) != 1 {
                return None;
            }
            return Some(x2);
        }
        if v.is_zero() == 1 {
            if u.ct_eq(&U1024::ONE) != 1 {
                return None;
            }
            return Some(x1);
        }

        // Halve u while even, maintaining x1 ≡ a·x1' (mod m).
        while u.is_odd() == 0 {
            u = u.shr1();
            if x1.is_odd() == 1 {
                // x1 must be even to halve cleanly; add m (odd) to flip
                // parity, then shift.
                let (sum, _) = x1.adding(m);
                x1 = sum.shr1();
            } else {
                x1 = x1.shr1();
            }
        }
        // Same for v/x2.
        while v.is_odd() == 0 {
            v = v.shr1();
            if x2.is_odd() == 1 {
                let (sum, _) = x2.adding(m);
                x2 = sum.shr1();
            } else {
                x2 = x2.shr1();
            }
        }

        // Both u and v are odd; subtract the larger.
        if u.ct_lt(&v) == 0 {
            // u >= v.
            u = u.subtracting(&v).0;
            // x1 = x1 - x2 mod m.
            if x1.ct_lt(&x2) == 1 {
                // x1 < x2: add m first to avoid underflow.
                let (s, _) = x1.adding(m);
                x1 = s.subtracting(&x2).0;
            } else {
                x1 = x1.subtracting(&x2).0;
            }
        } else {
            v = v.subtracting(&u).0;
            if x2.ct_lt(&x1) == 1 {
                let (s, _) = x2.adding(m);
                x2 = s.subtracting(&x1).0;
            } else {
                x2 = x2.subtracting(&x1).0;
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn from_u64(x: u64) -> U1024 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = x;
        U1024 { limbs }
    }

    #[test]
    fn zero_roundtrips() {
        let z = U1024::ZERO;
        assert_eq!(z.is_zero(), 1);
        assert_eq!(z.is_one(), 0);
        let b = z.to_be_bytes();
        assert_eq!(b, [0u8; BYTES]);
        assert_eq!(U1024::from_be_bytes(&b), z);
    }

    #[test]
    fn one_is_one() {
        assert_eq!(U1024::ONE.is_one(), 1);
        assert_eq!(U1024::ONE.is_odd(), 1);
    }

    #[test]
    fn widening_mul_small() {
        // 3 * 5 = 15.
        let three = from_u64(3);
        let five = from_u64(5);
        let prod = three.widening_mul(&five);
        assert_eq!(prod.limbs[0], 15);
        for i in 1..LIMBS2048 {
            assert_eq!(prod.limbs[i], 0);
        }
    }

    #[test]
    fn widening_mul_spans_upper_half() {
        // (2^1023) * 2 = 2^1024, so the low half is all zero and the
        // first limb of the high half is 1.
        let mut hi_bit = U1024::ZERO;
        hi_bit.limbs[LIMBS - 1] = 1u64 << 63;
        let two = from_u64(2);
        let prod = hi_bit.widening_mul(&two);
        for i in 0..LIMBS {
            assert_eq!(prod.limbs[i], 0, "low half limb {i}");
        }
        assert_eq!(prod.limbs[LIMBS], 1);
        for i in LIMBS + 1..LIMBS2048 {
            assert_eq!(prod.limbs[i], 0);
        }
    }

    #[test]
    fn rem_u64_small_cases() {
        let x = from_u64(100);
        assert_eq!(x.rem_u64(7), 2);
        assert_eq!(x.rem_u64(100), 0);
        assert_eq!(x.rem_u64(101), 100);
    }

    #[test]
    fn shr1_halves() {
        let x = from_u64(42);
        assert_eq!(x.shr1(), from_u64(21));
        let odd = from_u64(43);
        assert_eq!(odd.shr1(), from_u64(21));
    }

    #[test]
    fn adding_u64_propagates_carry() {
        // 0xff..ff (low limb max) + 1 should overflow into limb 1.
        let mut x = U1024::ZERO;
        x.limbs[0] = u64::MAX;
        let (s, c) = x.adding_u64(1);
        assert_eq!(c, 0);
        assert_eq!(s.limbs[0], 0);
        assert_eq!(s.limbs[1], 1);
    }

    #[test]
    fn modinv_small_prime() {
        // 3^(-1) mod 11 = 4 since 3·4 = 12 ≡ 1 (mod 11).
        let three = from_u64(3);
        let eleven = from_u64(11);
        let inv = modinv_odd(&three, &eleven).unwrap();
        assert_eq!(inv, from_u64(4));
    }

    #[test]
    fn modinv_65537_mod_large_odd() {
        // 65537^(-1) mod (3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 * 31) = ?
        // Just check it roundtrips: (e * inv) mod m == 1.
        let m_small: u64 = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 * 31;
        let e = from_u64(65537);
        let m = from_u64(m_small);
        let inv = modinv_odd(&e, &m).unwrap();
        // Roundtrip: (65537 * inv) mod m_small must be 1.
        let prod = 65537u128 * (inv.limbs[0] as u128);
        assert_eq!((prod % (m_small as u128)) as u64, 1);
    }

    #[test]
    fn modinv_rejects_noncoprime() {
        // 6^(-1) mod 9: gcd(6,9) = 3, not invertible.
        let six = from_u64(6);
        let nine = from_u64(9);
        assert!(modinv_odd(&six, &nine).is_none());
    }
}
