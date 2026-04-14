//! Declarative macro for RSA key generation at arbitrary operand widths.
//!
//! [`define_keygen`] generates the full keygen pipeline — Miller-Rabin
//! primality testing, trial-division sieve, DRBG-backed candidate
//! sampling, modular inverse of the small public exponent, CRT
//! decomposition, and the top-level generate function — parameterized
//! on the half-width (prime) and full-width (modulus) bigint types.
//!
//! The macro is invoked once for each target key size (RSA-3072 in
//! [`crate::keygen3072`], RSA-4096 in [`crate::keygen4096`]).  The
//! existing RSA-2048 keygen in [`crate::keygen`] predates the macro
//! and is left as-is; it may be migrated in a future cleanup pass.
//!
//! Shared constants (`SMALL_PRIMES`, `MAX_CANDIDATE_ATTEMPTS`) and
//! the `KeygenError` type live in [`crate::keygen`] and are
//! referenced by the macro body via `crate::keygen::*` paths.

#![allow(unused_macros)]

/// Generate RSA keygen functions for a specific key size.
///
/// # Generated items
///
/// | Item | Visibility | Description |
/// |------|-----------|-------------|
/// | `miller_rabin` | private | Miller-Rabin primality testing at half-width |
/// | `has_small_factor` | private | Trial division by primes < 2048 |
/// | `sample_candidate` | private | DRBG-backed odd candidate with top 2 bits set |
/// | `gen_probable_prime` | private | Prime-generation loop (FIPS 186-5 §A.1.1) |
/// | `$reduce` | `pub(crate)` | Bitwise shift-and-subtract full→half reduction |
/// | `modinv_small_e` | private | `e⁻¹ mod φ(n)` via divide-once-then-u64-EGCD |
/// | `$km` | `pub` | `KeyMaterial` struct with zeroizing `Drop` |
/// | `$gen` | `pub` | Top-level keygen entry point |
///
/// # Prerequisites at the call site
///
/// - `crate::keygen::{KeygenError, SMALL_PRIMES, MAX_CANDIDATE_ATTEMPTS}`
/// - `oxicrypt_drbg::HmacDrbgSha256`
/// - The half/full bigint types with keygen helpers (ONE, `subtracting_u64`,
///   `rem_u64`, `shr1`, `is_odd`, `is_one`, `widening_mul`, `ct_lt`,
///   `ct_sub_if_ge`)
/// - The half-width Montgomery context with `pow_public_<width>` method
macro_rules! define_keygen {
    (
        $(#[$km_meta:meta])*
        pub struct $km:ident;
        half = $half:ident, limbs = $hlimbs:expr, bytes = $hbytes:expr;
        full = $full:ident, limbs = $flimbs:expr;
        mont = $mont:ident;
        pow_public = $pow_pub:ident;
        mr_rounds = $mr:expr;
        nlen = $nlen:expr;
        generate = $gen:ident;
        reduce = $reduce:ident;
    ) => {
        // ---- Miller-Rabin primality testing ----

        /// Run Miller-Rabin with `rounds` random witnesses against
        /// candidate `n`. Returns `true` on "probably prime", `false`
        /// on "definitely composite".
        ///
        /// Precondition: `n` is odd and `n > 3`.
        fn miller_rabin(
            n: &$half,
            rounds: u32,
            drbg: &mut HmacDrbgSha256,
        ) -> Result<bool, crate::keygen::KeygenError> {
            let (n_minus_1, _) = n.subtracting_u64(1);
            let mut d = n_minus_1;
            let mut s: u32 = 0;
            while d.is_odd() == 0 && d.is_zero() == 0 {
                d = d.shr1();
                s += 1;
            }

            let ctx = match $mont::new(*n) {
                Some(c) => c,
                None => return Ok(false),
            };

            let n_minus_1_ct = n_minus_1;
            let one = $half::ONE;

            'witness: for _ in 0..rounds {
                // Sample a uniform witness `a ∈ [2, n − 2]`.
                let a = loop {
                    let mut buf = [0u8; $hbytes];
                    drbg.generate(None, &mut buf)?;
                    let cand = $half::from_be_bytes(&buf);
                    if cand.ct_lt(&n_minus_1_ct) == 1
                        && cand != $half::ZERO
                        && cand != one
                    {
                        break cand;
                    }
                };

                // x = a^d mod n
                let mut x = ctx.$pow_pub(&a, &d);
                if x == one || x == n_minus_1_ct {
                    continue 'witness;
                }

                for _ in 0..s.saturating_sub(1) {
                    let x_m = ctx.to_mont(&x);
                    let sq_m = ctx.mont_mul(&x_m, &x_m);
                    x = ctx.from_mont(&sq_m);
                    if x == n_minus_1_ct {
                        continue 'witness;
                    }
                    if x == one {
                        return Ok(false);
                    }
                }
                return Ok(false);
            }

            Ok(true)
        }

        // ---- Trial-division sieve ----

        /// Check whether candidate `p` is divisible by any small
        /// prime. Returns `true` if divisible (reject).
        fn has_small_factor(p: &$half) -> bool {
            for &sp in crate::keygen::SMALL_PRIMES {
                if p.rem_u64(sp as u64) == 0 {
                    return true;
                }
            }
            false
        }

        // ---- Candidate sampling ----

        /// Sample a half-width candidate from the DRBG: force top
        /// two bits set (so `p · q` spans the full nlen) and low
        /// bit set (odd).
        fn sample_candidate(
            drbg: &mut HmacDrbgSha256,
        ) -> Result<$half, crate::keygen::KeygenError> {
            let mut buf = [0u8; $hbytes];
            drbg.generate(None, &mut buf)?;
            buf[0] |= 0b1100_0000;
            buf[$hbytes - 1] |= 0b0000_0001;
            Ok($half::from_be_bytes(&buf))
        }

        // ---- Prime generation loop ----

        /// Generate a half-width probable prime from the DRBG,
        /// rejecting any candidate `p` for which `gcd(p − 1, e) ≠ 1`.
        /// FIPS 186-5 §A.1.1 steps 5.1–5.7.
        fn gen_probable_prime(
            drbg: &mut HmacDrbgSha256,
            e: u64,
        ) -> Result<$half, crate::keygen::KeygenError> {
            for _ in 0..crate::keygen::MAX_CANDIDATE_ATTEMPTS {
                let p = sample_candidate(drbg)?;
                if has_small_factor(&p) {
                    continue;
                }
                let (p_minus_1, _) = p.subtracting_u64(1);
                if p_minus_1.rem_u64(e) == 0 {
                    continue;
                }
                if miller_rabin(&p, $mr, drbg)? {
                    return Ok(p);
                }
            }
            Err(crate::keygen::KeygenError::TooManyAttempts)
        }

        // ---- Full-width mod half-width reduction ----

        /// Bitwise shift-and-subtract reduction of a full-width
        /// value modulo a half-width modulus.
        ///
        /// Called with public data (`d mod (p−1)` and `d mod (q−1)`)
        /// so constant-time behavior is not required.
        pub(crate) fn $reduce(a: &$full, m: &$half) -> $half {
            debug_assert!(
                m.limbs[$hlimbs - 1] >> 63 == 1,
                "m must have top bit set"
            );
            let mut acc = $half::ZERO;
            // Iterate over all bits of the full-width input.
            for bit in (0..($flimbs * 64_usize)).rev() {
                let carry_out = acc.limbs[$hlimbs - 1] >> 63;
                let mut new_limbs = [0u64; $hlimbs];
                let mut c: u64 = 0;
                for i in 0..$hlimbs {
                    new_limbs[i] = (acc.limbs[i] << 1) | c;
                    c = acc.limbs[i] >> 63;
                }
                let a_limb = a.limbs[bit / 64];
                let a_bit = (a_limb >> (bit % 64)) & 1;
                new_limbs[0] |= a_bit;
                let shifted = $half { limbs: new_limbs };
                let must_sub = carry_out == 1 || shifted.ct_lt(m) == 0;
                acc = if must_sub {
                    shifted.subtracting(m).0
                } else {
                    shifted
                };
            }
            acc
        }

        // ---- modinv_small_e helpers ----

        /// Divide a full-width value by a u64, returning (quotient,
        /// remainder).
        fn divmod_full_by_u64(x: &$full, divisor: u64) -> ($full, u64) {
            let mut q = [0u64; $flimbs];
            let mut rem: u128 = 0;
            for i in (0..$flimbs).rev() {
                let cur = (rem << 64) | (x.limbs[i] as u128);
                let qi = cur / (divisor as u128);
                rem = cur % (divisor as u128);
                q[i] = qi as u64;
            }
            ($full { limbs: q }, rem as u64)
        }

        /// Multiply a full-width value by a u64, returning the low
        /// bits (caller must verify the product fits).
        fn mul_full_by_u64(x: &$full, k: u64) -> $full {
            let mut out = [0u64; $flimbs];
            let mut carry: u64 = 0;
            for i in 0..$flimbs {
                let prod = (x.limbs[i] as u128) * (k as u128)
                    + (carry as u128);
                out[i] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            $full { limbs: out }
        }

        /// Wrap a u64 into a full-width value (low limb only).
        fn full_from_u64(x: u64) -> $full {
            let mut l = [0u64; $flimbs];
            l[0] = x;
            $full { limbs: l }
        }

        /// Two's-complement negate a full-width value.
        fn two_complement_full(x: &$full) -> $full {
            let mut inv = [0u64; $flimbs];
            for i in 0..$flimbs {
                inv[i] = !x.limbs[i];
            }
            let neg = $full { limbs: inv };
            let one = full_from_u64(1);
            let (r, _) = neg.adding(&one);
            r
        }

        /// Test the top bit as a signed-integer sign bit.
        fn is_full_negative(x: &$full) -> bool {
            (x.limbs[$flimbs - 1] >> 63) & 1 == 1
        }

        // ---- modinv_small_e ----

        /// Compute `e⁻¹ mod m` where `e` fits in a u64. Strategy:
        /// one big-int division `(q0, r0) = divmod(m, e)` reduces
        /// the problem to u64 EGCD on `(e, r0)`, then a single
        /// back-substitution recovers the full-width coefficient.
        fn modinv_small_e(e: u64, m: &$full) -> Option<$full> {
            if e == 0 || m.is_zero() == 1 {
                return None;
            }

            let (q0, r0) = divmod_full_by_u64(m, e);
            if r0 == 0 {
                return None;
            }

            // u64 Euclidean EGCD on (e, r0).
            let mut old_r: i128 = e as i128;
            let mut r: i128 = r0 as i128;
            let mut old_s: i128 = 1;
            let mut s: i128 = 0;
            let mut old_t: i128 = 0;
            let mut t: i128 = 1;
            while r != 0 {
                let q = old_r / r;
                let new_r = old_r - q * r;
                old_r = r;
                r = new_r;
                let new_s = old_s - q * s;
                old_s = s;
                s = new_s;
                let new_t = old_t - q * t;
                old_t = t;
                t = new_t;
            }
            if old_r != 1 {
                return None;
            }

            // Back-substitute r0 = m − q0·e to get
            // d ≡ (old_s − old_t·q0) (mod m).
            let (t_mag, t_neg): (u64, bool) = if old_t >= 0 {
                (old_t as u64, false)
            } else {
                ((-old_t) as u64, true)
            };
            let (s_mag, s_neg): (u64, bool) = if old_s >= 0 {
                (old_s as u64, false)
            } else {
                ((-old_s) as u64, true)
            };

            let tq = mul_full_by_u64(&q0, t_mag);
            let mut s_u = full_from_u64(s_mag);
            if s_neg {
                s_u = two_complement_full(&s_u);
            }

            let step = if t_neg {
                let (sum, _) = s_u.adding(&tq);
                sum
            } else {
                let (diff, _) = s_u.subtracting(&tq);
                diff
            };

            // Reduce signed result into [0, m).
            let is_negative = is_full_negative(&step);
            let reduced = if is_negative {
                let (plus_m, _) = step.adding(m);
                plus_m
            } else {
                step
            };
            let reduced = reduced.ct_sub_if_ge(m);
            Some(reduced)
        }

        // ---- KeyMaterial ----

        $(#[$km_meta])*
        #[derive(Clone, Debug)]
        pub struct $km {
            /// RSA modulus `n = p · q`.
            pub n: $full,
            /// Private exponent `d = e⁻¹ mod φ(n)`.
            pub d: $full,
            /// First prime factor.
            pub p: $half,
            /// Second prime factor.
            pub q: $half,
            /// CRT exponent `dP = d mod (p − 1)`.
            pub dp: $half,
            /// CRT exponent `dQ = d mod (q − 1)`.
            pub dq: $half,
            /// CRT coefficient `qInv = q⁻¹ mod p`.
            pub qinv: $half,
        }

        impl Drop for $km {
            fn drop(&mut self) {
                oxicrypt_zeroize::zeroize_u64(&mut self.d.limbs);
                oxicrypt_zeroize::zeroize_u64(&mut self.p.limbs);
                oxicrypt_zeroize::zeroize_u64(&mut self.q.limbs);
                oxicrypt_zeroize::zeroize_u64(&mut self.dp.limbs);
                oxicrypt_zeroize::zeroize_u64(&mut self.dq.limbs);
                oxicrypt_zeroize::zeroize_u64(&mut self.qinv.limbs);
            }
        }

        // ---- Top-level generate function ----

        /// Generate fresh RSA key material using `drbg` for all
        /// randomness. `e` must be an odd prime in `[65537, 2^64)`.
        pub fn $gen(
            drbg: &mut HmacDrbgSha256,
            e: u64,
        ) -> Result<$km, crate::keygen::KeygenError> {
            if e < 65537 || e & 1 == 0 {
                return Err(crate::keygen::KeygenError::InvalidExponent);
            }

            let p = gen_probable_prime(drbg, e)?;
            let q = loop {
                let q_try = gen_probable_prime(drbg, e)?;
                // FIPS 186-5 §A.1.1 step 5.4 — |p − q| distance.
                // We enforce p ≠ q; the full 2^(nlen/2−100) bound
                // is overwhelmingly satisfied in practice for primes
                // with the top two bits set.
                if q_try != p {
                    break q_try;
                }
            };

            // n = p · q.
            let n = p.widening_mul(&q);

            // φ(n) = (p − 1)(q − 1).
            let (p_minus_1, _) = p.subtracting_u64(1);
            let (q_minus_1, _) = q.subtracting_u64(1);
            let phi_n = p_minus_1.widening_mul(&q_minus_1);

            // d = e⁻¹ mod φ(n).
            let d = modinv_small_e(e, &phi_n)
                .ok_or(crate::keygen::KeygenError::InvalidExponent)?;

            // CRT decomposition.
            let dp = $reduce(&d, &p_minus_1);
            let dq = $reduce(&d, &q_minus_1);

            // qInv = q⁻¹ mod p via Fermat's little theorem:
            // q^(p − 2) ≡ q⁻¹ (mod p).
            let q_mod_p = if q.ct_lt(&p) == 1 {
                q
            } else {
                q.subtracting(&p).0
            };
            let ctx_p = $mont::new(p)
                .ok_or(crate::keygen::KeygenError::InvalidExponent)?;
            let (p_minus_2, _) = p.subtracting_u64(2);
            let qinv = ctx_p.$pow_pub(&q_mod_p, &p_minus_2);

            Ok($km { n, d, p, q, dp, dq, qinv })
        }
    };
}

pub(crate) use define_keygen;
