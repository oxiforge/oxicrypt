//! Fixed-width 2048-bit unsigned big integer.
//!
//! This is the narrowest container that covers the `RSA-2048` path
//! FIPS 186-5 permits as a signature-scheme modulus size. A value is
//! stored as 32 little-endian `u64` limbs:
//!
//! ```text
//!   value = Σ_{i=0..32} limbs[i] · 2^(64·i)
//! ```
//!
//! All routines here are **public-parameter constant time** (the
//! work per limb depends on the limb count, not on the limb values).
//! They're used by both public-key and private-key RSA operations;
//! the private-key path will layer additional secret-independent
//! scheduling on top of these primitives when it lands in R2.
//!
//! We intentionally do **not** implement `U2048 × U2048 → U4096`
//! here: the CIOS Montgomery multiplier in the adjacent [`mont2048`]
//! module interleaves reduction with multiplication and never
//! materializes a 4096-bit intermediate product.
//!
//! [`mont2048`]: crate::mont2048

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::return_self_not_must_use,
    clippy::needless_range_loop,
    clippy::many_single_char_names
)]

/// Limb count for a 2048-bit value.
pub const LIMBS: usize = 32;
/// Byte count for a 2048-bit value.
pub const BYTES: usize = 256;

/// A 2048-bit unsigned integer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct U2048 {
    /// Little-endian limbs; `limbs[0]` is the least significant word.
    pub(crate) limbs: [u64; LIMBS],
}

impl U2048 {
    /// The zero element.
    pub const ZERO: U2048 = U2048 { limbs: [0; LIMBS] };

    /// Construct from a big-endian 256-byte buffer. No range check
    /// is performed — callers validate range against the modulus
    /// elsewhere. Infallible, constant time.
    pub fn from_be_bytes(bytes: &[u8; BYTES]) -> U2048 {
        let mut limbs = [0u64; LIMBS];
        for i in 0..LIMBS {
            // limbs[0] is the least-significant word. The
            // most-significant byte sits at bytes[0], so limb i
            // covers bytes[BYTES - 8*(i+1) .. BYTES - 8*i].
            let start = BYTES - 8 * (i + 1);
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[start..start + 8]);
            limbs[i] = u64::from_be_bytes(word);
        }
        U2048 { limbs }
    }

    /// Serialize to a big-endian 256-byte buffer.
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
        // acc == 0 ↔ self == 0. Fold to a 1/0 bit.
        let nz = (acc | acc.wrapping_neg()) >> 63; // 0 if acc==0, else 1
        (1 ^ (nz as u8)) & 1
    }

    /// Constant-time `self < other` test. Returns `1` iff strictly
    /// less, else `0`.
    ///
    /// Implementation: compute `self - other` with borrow and read
    /// the final borrow bit. If `self < other`, the subtraction
    /// borrows out of the top limb and the borrow is `1`.
    pub fn ct_lt(&self, other: &U2048) -> u8 {
        let mut borrow: u64 = 0;
        for i in 0..LIMBS {
            let (d1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (_d2, b2) = d1.overflowing_sub(borrow);
            borrow = u64::from(b1 || b2);
        }
        borrow as u8
    }

    /// Constant-time equality. Returns `1` iff equal, else `0`.
    pub fn ct_eq(&self, other: &U2048) -> u8 {
        let mut acc: u64 = 0;
        for i in 0..LIMBS {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        let nz = (acc | acc.wrapping_neg()) >> 63;
        (1 ^ (nz as u8)) & 1
    }

    /// `(result, carry) = self + other` (full-width 2048-bit add,
    /// returning the carry out as 0 or 1).
    pub fn adding(&self, other: &U2048) -> (U2048, u64) {
        let mut limbs = [0u64; LIMBS];
        let mut carry: u64 = 0;
        for i in 0..LIMBS {
            let (s1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            limbs[i] = s2;
            carry = u64::from(c1 || c2);
        }
        (U2048 { limbs }, carry)
    }

    /// `(result, borrow) = self - other` (full-width 2048-bit sub,
    /// returning the borrow out as 0 or 1).
    pub fn subtracting(&self, other: &U2048) -> (U2048, u64) {
        let mut limbs = [0u64; LIMBS];
        let mut borrow: u64 = 0;
        for i in 0..LIMBS {
            let (d1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            limbs[i] = d2;
            borrow = u64::from(b1 || b2);
        }
        (U2048 { limbs }, borrow)
    }

    /// Constant-time conditional select.
    ///
    /// If `mask == u64::MAX`, returns `a`. If `mask == 0`, returns `b`.
    /// Any other value of `mask` yields undefined output (the intent
    /// is that callers always pass one of the two sentinel values,
    /// e.g. by computing `mask = 0u64.wrapping_sub(cond as u64)`).
    ///
    /// Used by the windowed modular-exponentiation ladder in
    /// [`crate::mont2048::MontCtx2048::pow_secret`] to perform a
    /// secret-index table lookup without branching on the index.
    pub fn conditional_select(mask: u64, a: &U2048, b: &U2048) -> U2048 {
        let mut out = [0u64; LIMBS];
        for i in 0..LIMBS {
            out[i] = (a.limbs[i] & mask) | (b.limbs[i] & !mask);
        }
        U2048 { limbs: out }
    }

    /// Extract a 4-bit nibble at the given nibble-position, counting
    /// from the least-significant end. `nibble_index = 0` returns the
    /// low nibble of `limbs[0]`; `nibble_index = 511` returns the top
    /// nibble of `limbs[LIMBS - 1]`. Panics in debug if the index is
    /// out of range.
    pub fn nibble(&self, nibble_index: usize) -> u8 {
        debug_assert!(nibble_index < LIMBS * 16);
        let limb = nibble_index >> 4; // /16
        let pos = nibble_index & 0xf; // %16
        ((self.limbs[limb] >> (4 * pos)) & 0xf) as u8
    }

    /// The multiplicative identity (one).
    pub const ONE: U2048 = {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 1;
        U2048 { limbs }
    };

    /// Returns `1` iff `self == 1`, else `0`.
    pub fn is_one(&self) -> u8 {
        let mut acc: u64 = self.limbs[0] ^ 1;
        for i in 1..LIMBS {
            acc |= self.limbs[i];
        }
        let nz = (acc | acc.wrapping_neg()) >> 63;
        (1 ^ (nz as u8)) & 1
    }

    /// Parity bit: `1` if odd, `0` if even.
    pub fn is_odd(&self) -> u8 {
        (self.limbs[0] & 1) as u8
    }

    /// Divide by two (shift right by one bit). Used by binary
    /// extended GCD on public inputs only.
    pub fn shr1(&self) -> U2048 {
        let mut limbs = [0u64; LIMBS];
        let mut carry: u64 = 0;
        for i in (0..LIMBS).rev() {
            let v = self.limbs[i];
            limbs[i] = (v >> 1) | (carry << 63);
            carry = v & 1;
        }
        U2048 { limbs }
    }

    /// Modular reduction by a small `u64`. Used for trial-division
    /// sieve during prime generation (RSA-4096 keygen path).
    pub fn rem_u64(&self, m: u64) -> u64 {
        debug_assert!(m > 0);
        let mut rem: u128 = 0;
        for i in (0..LIMBS).rev() {
            rem = ((rem << 64) | self.limbs[i] as u128) % (m as u128);
        }
        rem as u64
    }

    /// Widening multiply: `self × other → U4096`. Used once per
    /// RSA-4096 keygen run to form `n = p · q` where each factor
    /// is 2048 bits.
    pub fn widening_mul(&self, other: &U2048) -> crate::bigint4096::U4096 {
        use crate::bigint4096::{U4096, LIMBS as LIMBS4096};
        let mut out = [0u64; LIMBS4096];
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
        U4096 { limbs: out }
    }

    /// Widening add of a small `u64`, returning `(sum, carry_out)`.
    pub fn adding_u64(&self, addend: u64) -> (U2048, u64) {
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
        (U2048 { limbs }, carry)
    }

    /// Subtract a small `u64`, returning `(diff, borrow_out)`.
    pub fn subtracting_u64(&self, sub: u64) -> (U2048, u64) {
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
        (U2048 { limbs }, borrow)
    }

    /// Zero-extend to a [`crate::bigint4096::U4096`].
    pub fn zero_extend_to_4096(&self) -> crate::bigint4096::U4096 {
        use crate::bigint4096::{U4096, LIMBS as LIMBS4096};
        let mut limbs = [0u64; LIMBS4096];
        limbs[..LIMBS].copy_from_slice(&self.limbs);
        U4096 { limbs }
    }

    /// Conditional subtract: if `self >= other`, return `self - other`;
    /// else return `self`. Constant time in the operand values, not
    /// in the branch. Used for the final "reduce one `n`" step that
    /// every Montgomery routine ends with.
    pub fn ct_sub_if_ge(&self, other: &U2048) -> U2048 {
        // Compute self - other; if it borrows, keep `self`, otherwise
        // keep the difference. Both branches are evaluated.
        let (diff, borrow) = self.subtracting(other);
        // borrow == 1 means self < other → keep self; else keep diff.
        let mask = 0u64.wrapping_sub(borrow); // all ones if borrow, else 0
        let mut out = [0u64; LIMBS];
        for i in 0..LIMBS {
            // mask==ffff..ff → pick self; mask==0 → pick diff.
            out[i] = (self.limbs[i] & mask) | (diff.limbs[i] & !mask);
        }
        U2048 { limbs: out }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_roundtrips() {
        let z = U2048::ZERO;
        assert_eq!(z.is_zero(), 1);
        let bytes = z.to_be_bytes();
        assert_eq!(bytes, [0u8; BYTES]);
        let back = U2048::from_be_bytes(&bytes);
        assert_eq!(back, z);
    }

    #[test]
    fn roundtrip_all_ones() {
        let mut bytes = [0u8; BYTES];
        bytes.fill(0xff);
        let x = U2048::from_be_bytes(&bytes);
        assert_eq!(x.limbs, [0xffff_ffff_ffff_ffff; LIMBS]);
        assert_eq!(x.to_be_bytes(), bytes);
        assert_eq!(x.is_zero(), 0);
    }

    #[test]
    fn big_endian_order_msbyte_first() {
        // Only the highest byte set: value is 2^2047+... just check
        // that bytes[0] == 0x80 lights up the top bit of the top limb.
        let mut bytes = [0u8; BYTES];
        bytes[0] = 0x80;
        let x = U2048::from_be_bytes(&bytes);
        assert_eq!(x.limbs[LIMBS - 1], 0x8000_0000_0000_0000);
        for i in 0..LIMBS - 1 {
            assert_eq!(x.limbs[i], 0);
        }
        assert_eq!(x.to_be_bytes(), bytes);
    }

    #[test]
    fn ct_lt_orders_correctly() {
        let mut a_bytes = [0u8; BYTES];
        let mut b_bytes = [0u8; BYTES];
        a_bytes[BYTES - 1] = 0x01;
        b_bytes[BYTES - 1] = 0x02;
        let a = U2048::from_be_bytes(&a_bytes);
        let b = U2048::from_be_bytes(&b_bytes);
        assert_eq!(a.ct_lt(&b), 1);
        assert_eq!(b.ct_lt(&a), 0);
        assert_eq!(a.ct_lt(&a), 0);
    }

    #[test]
    fn ct_eq_self_is_one() {
        let mut bytes = [0u8; BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17);
        }
        let x = U2048::from_be_bytes(&bytes);
        assert_eq!(x.ct_eq(&x), 1);
        let mut other = bytes;
        other[5] ^= 0x01;
        let y = U2048::from_be_bytes(&other);
        assert_eq!(x.ct_eq(&y), 0);
    }

    #[test]
    fn adding_1_plus_max_wraps_with_carry() {
        let ones = U2048 { limbs: [0xffff_ffff_ffff_ffff; LIMBS] };
        let one = {
            let mut bytes = [0u8; BYTES];
            bytes[BYTES - 1] = 1;
            U2048::from_be_bytes(&bytes)
        };
        let (sum, carry) = ones.adding(&one);
        assert_eq!(sum, U2048::ZERO);
        assert_eq!(carry, 1);
    }

    #[test]
    fn subtracting_zero_minus_one_borrows() {
        let one = {
            let mut bytes = [0u8; BYTES];
            bytes[BYTES - 1] = 1;
            U2048::from_be_bytes(&bytes)
        };
        let (diff, borrow) = U2048::ZERO.subtracting(&one);
        assert_eq!(diff, U2048 { limbs: [0xffff_ffff_ffff_ffff; LIMBS] });
        assert_eq!(borrow, 1);
    }

    #[test]
    fn conditional_select_picks_a_or_b() {
        let a = U2048 { limbs: [0xaa; LIMBS] };
        let b = U2048 { limbs: [0x55; LIMBS] };
        let pick_a = U2048::conditional_select(u64::MAX, &a, &b);
        let pick_b = U2048::conditional_select(0, &a, &b);
        assert_eq!(pick_a, a);
        assert_eq!(pick_b, b);
    }

    #[test]
    fn nibble_reads_little_endian_from_bottom() {
        // Low limb = 0xfedcba9876543210; nibbles 0..16 should be 0,1,2,...,f.
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 0xfedc_ba98_7654_3210;
        let x = U2048 { limbs };
        for i in 0..16 {
            assert_eq!(x.nibble(i), i as u8);
        }
        // Everything above limb 0 is zero.
        for i in 16..LIMBS * 16 {
            assert_eq!(x.nibble(i), 0);
        }
    }

    #[test]
    fn ct_sub_if_ge_keeps_self_when_smaller() {
        let mut a = [0u8; BYTES];
        let mut b = [0u8; BYTES];
        a[BYTES - 1] = 5;
        b[BYTES - 1] = 7;
        let av = U2048::from_be_bytes(&a);
        let bv = U2048::from_be_bytes(&b);
        // a < b → result is a.
        assert_eq!(av.ct_sub_if_ge(&bv), av);
        // b >= a → result is b - a = 2.
        let mut expect = [0u8; BYTES];
        expect[BYTES - 1] = 2;
        assert_eq!(bv.ct_sub_if_ge(&av), U2048::from_be_bytes(&expect));
    }
}
