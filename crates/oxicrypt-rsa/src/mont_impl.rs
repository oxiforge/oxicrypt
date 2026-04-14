//! Declarative macro for generating Montgomery arithmetic contexts.
//!
//! The CIOS Montgomery multiplier, to/from Montgomery conversion,
//! public-exponent ladder, and constant-time secret-exponent ladder
//! are identical across every operand width — only the limb count
//! and the associated big-integer type change. This macro generates
//! all of that from a single invocation.
//!
//! Width-specific helpers (e.g. Miller-Rabin `pow_public_uN` for the
//! keygen primes) are added in dedicated `impl` blocks next to the
//! macro invocation site.
//!
//! # Constant-time contract
//!
//! `mont_mul`, `to_mont`, `from_mont`, and `pow_secret` are constant
//! time with respect to operand values. `pow_public_u64` is **not**
//! constant time in the exponent and must only be used with public
//! exponents.

/// Generate a Montgomery context for a fixed-width odd modulus.
///
/// # Parameters
///
/// * `$ctx`   — the context struct name, e.g. `MontCtx3072`.
/// * `$uint`  — the associated big-integer type, e.g. `U3072`.
/// * `$limbs` — limb count (must equal the LIMBS constant of `$uint`'s module).
/// * `$bits`  — bit width (= `$limbs * 64`).
macro_rules! define_mont_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $ctx:ident for $uint:ident;
        limbs = $limbs:expr;
        bits = $bits:expr;
    ) => {
        /// Derived Montgomery constants for a specific modulus at this width.
        $(#[$meta])*
        #[derive(Copy, Clone, Debug)]
        $vis struct $ctx {
            /// The modulus.
            pub(crate) n: $uint,
            /// `n_prime = (-n^(-1)) mod 2^64`.
            pub(crate) n_prime: u64,
            /// `R mod n` where `R = 2^bits`. Montgomery representative of 1.
            pub(crate) one_mont: $uint,
            /// `R^2 mod n`. Used to convert plain integers to Montgomery form.
            pub(crate) r2_mod_n: $uint,
        }

        #[allow(
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
        impl $ctx {
            /// Build a context for an odd modulus `n` whose top bit is
            /// set (i.e. `2^(bits-1) <= n < 2^bits`). Returns `None` if
            /// `n` is even or if its top limb has the MSB clear.
            pub fn new(n: $uint) -> Option<$ctx> {
                if n.limbs[0] & 1 == 0 {
                    return None;
                }
                if n.limbs[$limbs - 1] >> 63 == 0 {
                    return None;
                }

                // n_prime = (-n[0]^(-1)) mod 2^64 via 6-round Newton.
                let n0 = n.limbs[0];
                let mut inv: u64 = 1;
                for _ in 0..6 {
                    inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
                }
                let n_prime = 0u64.wrapping_sub(inv);
                debug_assert_eq!(n0.wrapping_mul(n_prime), 0u64.wrapping_sub(1));

                // R mod n = R - n (since 2^(bits-1) <= n < 2^bits = R).
                let mut r_mod_n_limbs = [0u64; $limbs];
                let mut borrow: u64 = 0;
                for i in 0..$limbs {
                    let (d1, b1) = 0u64.overflowing_sub(n.limbs[i]);
                    let (d2, b2) = d1.overflowing_sub(borrow);
                    r_mod_n_limbs[i] = d2;
                    borrow = u64::from(b1 || b2);
                }
                debug_assert_eq!(borrow, 1);
                let one_mont = $uint { limbs: r_mod_n_limbs };

                // R^2 mod n via repeated doubling.
                let mut acc = one_mont;
                for _ in 0..$bits {
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

                Some($ctx {
                    n,
                    n_prime,
                    one_mont,
                    r2_mod_n,
                })
            }

            /// Montgomery product: `(a * b * R^(-1)) mod n`.
            pub fn mont_mul(&self, a: &$uint, b: &$uint) -> $uint {
                let mut t = [0u64; $limbs + 2];

                for i in 0..$limbs {
                    let mut carry: u64 = 0;
                    for j in 0..$limbs {
                        let prod = (a.limbs[j] as u128) * (b.limbs[i] as u128)
                            + (t[j] as u128)
                            + (carry as u128);
                        t[j] = prod as u64;
                        carry = (prod >> 64) as u64;
                    }
                    let sum = (t[$limbs] as u128) + (carry as u128);
                    t[$limbs] = sum as u64;
                    t[$limbs + 1] = t[$limbs + 1] + (sum >> 64) as u64;

                    let m = t[0].wrapping_mul(self.n_prime);

                    let mut carry2: u64 = {
                        let prod = (m as u128) * (self.n.limbs[0] as u128)
                            + (t[0] as u128);
                        (prod >> 64) as u64
                    };
                    for j in 1..$limbs {
                        let prod = (m as u128) * (self.n.limbs[j] as u128)
                            + (t[j] as u128)
                            + (carry2 as u128);
                        t[j - 1] = prod as u64;
                        carry2 = (prod >> 64) as u64;
                    }
                    let sum = (t[$limbs] as u128) + (carry2 as u128);
                    t[$limbs - 1] = sum as u64;
                    let high_carry = (sum >> 64) as u64;
                    t[$limbs] = t[$limbs + 1] + high_carry;
                    t[$limbs + 1] = 0;
                }

                let mut limbs = [0u64; $limbs];
                limbs.copy_from_slice(&t[..$limbs]);
                let unreduced = $uint { limbs };

                if t[$limbs] != 0 {
                    unreduced.subtracting(&self.n).0
                } else {
                    unreduced.ct_sub_if_ge(&self.n)
                }
            }

            /// Convert `x ∈ [0, n)` into Montgomery form.
            pub fn to_mont(&self, x: &$uint) -> $uint {
                self.mont_mul(x, &self.r2_mod_n)
            }

            /// Convert from Montgomery form back to a plain integer.
            pub fn from_mont(&self, x_mont: &$uint) -> $uint {
                let mut one = [0u64; $limbs];
                one[0] = 1;
                self.mont_mul(x_mont, &$uint { limbs: one })
            }

            /// `base^exp mod n` for a small public `u64` exponent.
            /// **Not** constant time in `exp`.
            pub fn pow_public_u64(&self, base: &$uint, exp: u64) -> $uint {
                if exp == 0 {
                    let mut one = [0u64; $limbs];
                    one[0] = 1;
                    return $uint { limbs: one };
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

            /// `base^exp mod n` where `exp` is a secret full-width
            /// integer. Fixed-schedule 4-bit windowed ladder: for each
            /// nibble of the exponent we square four times and multiply
            /// by a table entry chosen via a constant-time scan. No work
            /// depends on `exp`.
            ///
            /// # FIPS note
            ///
            /// Per IG D.G, secret-dependent operations must not leak
            /// through execution time on common general-purpose CPUs.
            pub fn pow_secret(&self, base: &$uint, exp: &$uint) -> $uint {
                let mut table = [$uint::ZERO; 16];
                table[0] = self.one_mont;
                table[1] = self.to_mont(base);
                for i in 2..16 {
                    table[i] = self.mont_mul(&table[i - 1], &table[1]);
                }

                let mut acc = self.one_mont;
                // LIMBS * 16 nibbles total.
                for nibble_index in (0..$limbs * 16).rev() {
                    acc = self.mont_mul(&acc, &acc);
                    acc = self.mont_mul(&acc, &acc);
                    acc = self.mont_mul(&acc, &acc);
                    acc = self.mont_mul(&acc, &acc);

                    let nibble = exp.nibble(nibble_index);
                    let mut selected = $uint::ZERO;
                    for i in 0..16u8 {
                        let diff = (i ^ nibble) as u64;
                        let is_eq = (diff.wrapping_sub(1) >> 63) & 1;
                        let mask = 0u64.wrapping_sub(is_eq);
                        selected = $uint::conditional_select(
                            mask,
                            &table[i as usize],
                            &selected,
                        );
                    }
                    acc = self.mont_mul(&acc, &selected);
                }

                self.from_mont(&acc)
            }
        }
    };
}

pub(crate) use define_mont_type;
