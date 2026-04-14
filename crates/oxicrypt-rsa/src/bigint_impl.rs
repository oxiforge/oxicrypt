//! Declarative macro for generating fixed-width big-integer types.
//!
//! Every width shares the same core constant-time arithmetic: serialization,
//! comparison, add/sub, conditional select, nibble extraction, and
//! conditional-subtract-if-greater-or-equal. This macro generates all of
//! that from a single invocation, parameterized by the type name, limb
//! count, and byte count.
//!
//! Width-specific operations (widening multiply, modular reduction by
//! a small divisor, shift-right-by-one, etc.) are added in dedicated
//! `impl` blocks next to the macro invocation site — the macro only
//! covers what is truly identical across every width.
//!
//! # Design rationale (CNSA 2.0 forward-compatibility)
//!
//! RSA-3072/4096 and DH-3072 need three new widths (1536, 3072, 4096).
//! CNSA 2.0 post-quantum algorithms will need additional fixed-width
//! integer types for lattice coefficient vectors and hash-based tree
//! arithmetic. By centralizing the constant-time core in a single macro,
//! we ensure:
//!
//!   * Bug fixes propagate to every width at once.
//!   * Adding a new width is a one-line macro call plus any
//!     width-specific extras.
//!   * The constant-time contract is stated and audited in one place.

/// Generate a fixed-width unsigned big-integer type with constant-time
/// core arithmetic.
///
/// # Parameters
///
/// * `$name`  — the struct name, e.g. `U3072`.
/// * `$limbs` — number of `u64` limbs.
/// * `$bytes` — number of bytes (`$limbs * 8`).
/// * `$vis`   — visibility qualifier for the struct and its methods.
macro_rules! define_bigint_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
        limbs = $limbs:expr;
        bytes = $bytes:expr;
    ) => {
        /// Limb count for this width.
        pub const LIMBS: usize = $limbs;
        /// Byte count for this width.
        pub const BYTES: usize = $bytes;

        $(#[$meta])*
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        $vis struct $name {
            /// Little-endian limbs; `limbs[0]` is the least significant word.
            pub(crate) limbs: [u64; LIMBS],
        }

        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::cast_possible_truncation,
            clippy::cast_lossless,
            clippy::similar_names,
            clippy::return_self_not_must_use,
            clippy::needless_range_loop,
            clippy::many_single_char_names
        )]
        impl $name {
            /// The zero element.
            pub const ZERO: $name = $name { limbs: [0; LIMBS] };

            /// Construct from a big-endian byte buffer. No range check
            /// is performed — callers validate range against the modulus
            /// elsewhere. Infallible, constant time.
            pub fn from_be_bytes(bytes: &[u8; BYTES]) -> $name {
                let mut limbs = [0u64; LIMBS];
                for i in 0..LIMBS {
                    let start = BYTES - 8 * (i + 1);
                    let mut word = [0u8; 8];
                    word.copy_from_slice(&bytes[start..start + 8]);
                    limbs[i] = u64::from_be_bytes(word);
                }
                $name { limbs }
            }

            /// Serialize to a big-endian byte buffer.
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

            /// Constant-time `self < other` test. Returns `1` iff
            /// strictly less, else `0`.
            pub fn ct_lt(&self, other: &$name) -> u8 {
                let mut borrow: u64 = 0;
                for i in 0..LIMBS {
                    let (d1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
                    let (_d2, b2) = d1.overflowing_sub(borrow);
                    borrow = u64::from(b1 || b2);
                }
                borrow as u8
            }

            /// Constant-time equality. Returns `1` iff equal, else `0`.
            pub fn ct_eq(&self, other: &$name) -> u8 {
                let mut acc: u64 = 0;
                for i in 0..LIMBS {
                    acc |= self.limbs[i] ^ other.limbs[i];
                }
                let nz = (acc | acc.wrapping_neg()) >> 63;
                (1 ^ (nz as u8)) & 1
            }

            /// `(result, carry) = self + other`.
            pub fn adding(&self, other: &$name) -> ($name, u64) {
                let mut limbs = [0u64; LIMBS];
                let mut carry: u64 = 0;
                for i in 0..LIMBS {
                    let (s1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
                    let (s2, c2) = s1.overflowing_add(carry);
                    limbs[i] = s2;
                    carry = u64::from(c1 || c2);
                }
                ($name { limbs }, carry)
            }

            /// `(result, borrow) = self - other`.
            pub fn subtracting(&self, other: &$name) -> ($name, u64) {
                let mut limbs = [0u64; LIMBS];
                let mut borrow: u64 = 0;
                for i in 0..LIMBS {
                    let (d1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
                    let (d2, b2) = d1.overflowing_sub(borrow);
                    limbs[i] = d2;
                    borrow = u64::from(b1 || b2);
                }
                ($name { limbs }, borrow)
            }

            /// Constant-time conditional select.
            ///
            /// `mask == u64::MAX` → returns `a`.
            /// `mask == 0` → returns `b`.
            pub fn conditional_select(mask: u64, a: &$name, b: &$name) -> $name {
                let mut out = [0u64; LIMBS];
                for i in 0..LIMBS {
                    out[i] = (a.limbs[i] & mask) | (b.limbs[i] & !mask);
                }
                $name { limbs: out }
            }

            /// Extract a 4-bit nibble at position `nibble_index`,
            /// counting from the least-significant end.
            pub fn nibble(&self, nibble_index: usize) -> u8 {
                debug_assert!(nibble_index < LIMBS * 16);
                let limb = nibble_index >> 4;
                let pos = nibble_index & 0xf;
                ((self.limbs[limb] >> (4 * pos)) & 0xf) as u8
            }

            /// Conditional subtract: if `self >= other`, return
            /// `self - other`; else return `self`. Constant time.
            pub fn ct_sub_if_ge(&self, other: &$name) -> $name {
                let (diff, borrow) = self.subtracting(other);
                let mask = 0u64.wrapping_sub(borrow);
                let mut out = [0u64; LIMBS];
                for i in 0..LIMBS {
                    out[i] = (self.limbs[i] & mask) | (diff.limbs[i] & !mask);
                }
                $name { limbs: out }
            }
        }
    };
}

pub(crate) use define_bigint_type;
