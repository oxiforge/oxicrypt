//! RSA-2048 key generation per FIPS 186-5 §A.1.1 / §B.3.1.
//!
//! Generates probable primes via:
//!   1. Draw 128 random bytes from the caller-supplied random bit
//!      generator.
//!   2. Force the top two bits and the bottom bit so the candidate is
//!      odd and `2^1023 ≤ p < 2^1024` (IG D.G rejects candidates that
//!      don't meet the full bit length — no "short" primes).
//!   3. Trial-divide by a sieve of small odd primes to cheaply reject
//!      obvious composites before the expensive MR rounds.
//!   4. Miller-Rabin with 5 rounds of random-witness testing per
//!      FIPS 186-5 Table B.1 row (nlen = 2048, error probability
//!      2^−100). Witnesses come from the same generator.
//!   5. Confirm `gcd(p − 1, e) = 1` (FIPS 186-5 §A.1.1 step 5.5).
//!
//! After `p` and `q` are both generated, compute `n = p · q`,
//! `φ(n) = (p − 1)(q − 1)`, the private exponent `d = e^(−1) mod φ(n)`
//! by a divide-once-then-u64 extended Euclidean step, and the CRT
//! components `(dP, dQ, qInv)`. The result is a [`KeyMaterial`];
//! [`crate::RsaPrivateKey2048::generate`] then runs the IG 10.3.A
//! pairwise consistency test before the key is usable.
//!
//! # Non-constant-time note
//!
//! Primality testing on candidate `p` is *not* constant time: it
//! returns as soon as the sieve or an MR round fails. That is
//! acceptable here because the candidate has not yet been accepted —
//! no attacker can correlate a rejection with any bit of a *final*
//! key, and the final key is protected by the constant-time
//! Montgomery ladder in [`crate::mont2048::MontCtx2048::pow_secret`].
//! The derivation of `d`, `dP`, `dQ` and `qInv` from the accepted
//! primes is also not constant time: the inverse runs over φ(n), the
//! CRT reductions branch on the running remainder, and `qInv` uses a
//! square-and-multiply with the exponent `p − 2`. Each site says so
//! where it occurs.

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

use crate::bigint1024::{self, BYTES as BYTES1024, LIMBS as LIMBS1024, U1024};
use crate::bigint2048::{LIMBS as LIMBS2048, U2048};
use crate::mont1024::MontCtx1024;
use oxicrypt_module::{Rbg, RbgError, require_self_test_started};

/// Errors that can arise during key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeygenError {
    /// The random bit generator produced no output; the [`RbgError`]
    /// states why.
    Rbg(RbgError),
    /// The public exponent was out of range or even. FIPS 186-5
    /// §A.1.1 requires `65537 ≤ e < 2^256` and `e` odd.
    InvalidExponent,
    /// A deterministic bound on the number of prime-candidate draws
    /// was exceeded. In practice this should never fire for 2048-bit
    /// RSA with 5 × (1024 bits) expected-cost MR; the bound exists
    /// purely to give the no_std control flow a hard stop.
    TooManyAttempts,
    /// The module refused key generation because its self-tests have not
    /// started or it has failed.
    Module(oxicrypt_module::Error),
}

impl core::fmt::Display for KeygenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rbg(e) => write!(f, "random bit generator error during keygen: {e}"),
            Self::InvalidExponent => write!(
                f,
                "public exponent must be odd and in range 65537 <= e < 2^256 \
                 (FIPS 186-5 §A.1.1); use e = 65537 (0x10001)"
            ),
            Self::TooManyAttempts => write!(
                f,
                "exceeded 20000 prime-candidate draws without finding a valid pair; \
                 this should never happen in practice — check your DRBG entropy source"
            ),
            Self::Module(e) => write!(f, "the module refused key generation: {e}"),
        }
    }
}

impl From<oxicrypt_module::Error> for KeygenError {
    fn from(e: oxicrypt_module::Error) -> KeygenError {
        KeygenError::Module(e)
    }
}

impl From<RbgError> for KeygenError {
    fn from(e: RbgError) -> KeygenError {
        KeygenError::Rbg(e)
    }
}

/// Upper bound on the number of candidate draws per prime. Appendix
/// F.4 of FIPS 186-5 gives an expected count around `ln(2^1024)/2 ≈
/// 355` and this figure is deterministic in expectation but not in
/// the worst case. 20 000 gives several orders of magnitude of slack.
pub(crate) const MAX_CANDIDATE_ATTEMPTS: u32 = 20_000;

/// Small odd primes < 2048, used by the trial-division sieve. This
/// list rejects ~85 % of uniformly random odd candidates cheaply.
pub(crate) const SMALL_PRIMES: &[u16] = &[
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873,
    1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999,
    2003, 2011, 2017, 2027, 2029, 2039,
];

/// FIPS 186-5 Table B.1 prescribes 5 Miller-Rabin rounds (error ≤
/// 2^−100) for generating 1024-bit primes in an nlen=2048 RSA key.
const MR_ROUNDS: u32 = 5;

/// Run Miller-Rabin with `rounds` random witnesses against candidate
/// `n`. Caller supplies the random bit generator for witness sampling.
/// Returns `true` on "probably prime", `false` on "definitely composite".
///
/// Precondition: `n` is odd and `n > 3`.
fn miller_rabin<R: Rbg>(n: &U1024, rounds: u32, drbg: &mut R) -> Result<bool, KeygenError> {
    // Write n − 1 = 2^s · d.
    let (n_minus_1, _) = n.subtracting_u64(1);
    let mut d = n_minus_1;
    let mut s: u32 = 0;
    while d.is_odd() == 0 && d.is_zero() == 0 {
        d = d.shr1();
        s += 1;
    }
    // s ≥ 1 because n is odd ⇒ n − 1 is even.

    let ctx = match MontCtx1024::new(*n) {
        Some(c) => c,
        None => return Ok(false),
    };

    let n_minus_1_ct = n_minus_1;
    let one = {
        let mut l = [0u64; LIMBS1024];
        l[0] = 1;
        U1024 { limbs: l }
    };

    'witness: for _ in 0..rounds {
        // Sample a uniform witness `a ∈ [2, n − 2]`. An out-of-range
        // 1024-bit draw is re-drawn; for a keygen candidate, whose top
        // two bits are set so `n ≥ 3·2^1022`, a draw is rejected with
        // probability of about 1/4 at most.
        let a = loop {
            let mut buf = [0u8; BYTES1024];
            drbg.fill(&mut buf)?;
            let cand = U1024::from_be_bytes(&buf);
            // Need 2 ≤ a ≤ n − 2, i.e. a > 1 and a < n − 1.
            if cand.ct_lt(&n_minus_1_ct) == 1 {
                // cand < n − 1; also need cand > 1.
                if cand != U1024::ZERO && cand != one {
                    break cand;
                }
            }
        };

        // x = a^d mod n
        let mut x = ctx.pow_public_u1024(&a, &d);
        if x == one || x == n_minus_1_ct {
            continue 'witness;
        }

        // Square `s − 1` times, looking for n − 1.
        for _ in 0..s.saturating_sub(1) {
            let x_m = ctx.to_mont(&x);
            let sq_m = ctx.mont_mul(&x_m, &x_m);
            x = ctx.from_mont(&sq_m);
            if x == n_minus_1_ct {
                continue 'witness;
            }
            if x == one {
                // Hit 1 without passing through n-1 ⇒ composite.
                return Ok(false);
            }
        }
        return Ok(false);
    }

    Ok(true)
}

/// Check whether candidate `p` is divisible by any small prime in
/// [`SMALL_PRIMES`]. Returns `true` if divisible (reject), `false`
/// if the sieve finds no small factor.
fn has_small_factor(p: &U1024) -> bool {
    for &sp in SMALL_PRIMES {
        if p.rem_u64(sp as u64) == 0 {
            return true;
        }
    }
    false
}

/// Sample a 1024-bit candidate from the random bit generator and
/// canonicalize: force the top two bits set (so `p · q ≥ 2^2047`,
/// giving a full 2048-bit modulus) and force the low bit set (so the
/// candidate is odd).
fn sample_candidate<R: Rbg>(drbg: &mut R) -> Result<U1024, KeygenError> {
    let mut buf = [0u8; BYTES1024];
    drbg.fill(&mut buf)?;
    // Top byte: set bits 7 and 6 so the top two bits of the 1024-bit
    // value are 1. This guarantees p ≥ 3·2^1022 so that p·q ≥ 9·2^2044
    // > 2^2047, ensuring the RSA modulus really is 2048 bits.
    buf[0] |= 0b1100_0000;
    // Low byte: set bit 0 so the value is odd.
    buf[BYTES1024 - 1] |= 0b0000_0001;
    Ok(U1024::from_be_bytes(&buf))
}

/// Generate a 1024-bit probable prime from the random bit generator,
/// rejecting any candidate `p` for which `gcd(p − 1, e) ≠ 1`. This is
/// FIPS 186-5 §A.1.1 steps 5.1–5.7 collapsed into a single loop for a
/// 1024-bit factor of a 2048-bit RSA modulus.
fn gen_probable_prime_1024<R: Rbg>(drbg: &mut R, e: u64) -> Result<U1024, KeygenError> {
    for _ in 0..MAX_CANDIDATE_ATTEMPTS {
        let p = sample_candidate(drbg)?;
        if has_small_factor(&p) {
            continue;
        }
        // FIPS 186-5 §A.1.1 step 5.5: gcd(p − 1, e) = 1.
        // For a prime `e` that holds iff `(p − 1) mod e ≠ 0`, which is
        // the test applied here. A composite `e` would need a full gcd,
        // so only a prime `e` is supported.
        let (p_minus_1, _) = p.subtracting_u64(1);
        if p_minus_1.rem_u64(e) == 0 {
            continue;
        }
        if miller_rabin(&p, MR_ROUNDS, drbg)? {
            return Ok(p);
        }
    }
    Err(KeygenError::TooManyAttempts)
}

/// Compute `a * b` as a 2048-bit product. Wraps `U1024::widening_mul`.
fn mul_1024(a: &U1024, b: &U1024) -> U2048 {
    a.widening_mul(b)
}

/// Reduce a 2048-bit `a` modulo a 1024-bit `m`, returning the 1024-bit
/// remainder. Uses a bitwise shift-and-subtract running-remainder
/// reduction: for each of the 2048 bits of `a` from MSB to LSB, shift
/// the 1024-bit accumulator left by one, inject the next bit of `a`,
/// and subtract `m` if the resulting value is `≥ m` (which is exactly
/// the case when the shift carried a bit out the top, since the
/// pre-shift accumulator is always in `[0, m)`).
///
/// Not constant time: the conditional subtract branches on the
/// running remainder. Keygen calls it on secret inputs (`d` mod
/// `p − 1` and `q − 1`); the CRT path calls it on the public input
/// representative.
pub(crate) fn u2048_mod_u1024(a: &U2048, m: &U1024) -> U1024 {
    debug_assert!(m.limbs[LIMBS1024 - 1] >> 63 == 1, "m must have top bit set");
    let mut acc = U1024::ZERO;
    for bit in (0..2048usize).rev() {
        // acc = acc << 1 ; capture the bit shifted out the top.
        let carry_out = acc.limbs[LIMBS1024 - 1] >> 63;
        let mut new_limbs = [0u64; LIMBS1024];
        let mut c: u64 = 0;
        for i in 0..LIMBS1024 {
            new_limbs[i] = (acc.limbs[i] << 1) | c;
            c = acc.limbs[i] >> 63;
        }
        let a_limb = a.limbs[bit / 64];
        let a_bit = (a_limb >> (bit % 64)) & 1;
        new_limbs[0] |= a_bit;
        let shifted = U1024 { limbs: new_limbs };
        // When carry_out == 1, m is subtracted: the real value is
        // `2^1024 + shifted`, which as a 1024-bit wrapping subtract
        // yields the correct `shifted + 2^1024 - m`. Otherwise m is
        // subtracted only if `shifted >= m`.
        let must_sub = carry_out == 1 || shifted.ct_lt(m) == 0;
        acc = if must_sub {
            shifted.subtracting(m).0
        } else {
            shifted
        };
    }
    acc
}

/// Result of a successful keygen: the public modulus, the private
/// exponent, and the full CRT decomposition. The caller feeds these
/// into [`crate::RsaPrivateKey2048::from_components`] (or the CRT
/// variant) along with `e`, which runs the IG 10.3.A pairwise
/// consistency test before the key is considered usable.
#[derive(Clone)]
pub struct KeyMaterial {
    /// RSA-2048 modulus `n = p · q`.
    pub n: U2048,
    /// Private exponent `d = e^(−1) mod φ(n)`.
    pub d: U2048,
    /// First prime factor, 1024 bits.
    pub p: U1024,
    /// Second prime factor, 1024 bits.
    pub q: U1024,
    /// CRT exponent `dP = d mod (p − 1)`.
    pub dp: U1024,
    /// CRT exponent `dQ = d mod (q − 1)`.
    pub dq: U1024,
    /// CRT coefficient `qInv = q^(−1) mod p`.
    pub qinv: U1024,
}

/// Shows the public modulus only; the private fields are not printed.
impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("n", &self.n)
            .finish_non_exhaustive()
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize_u64(&mut self.d.limbs);
        oxicrypt_zeroize::zeroize_u64(&mut self.p.limbs);
        oxicrypt_zeroize::zeroize_u64(&mut self.q.limbs);
        oxicrypt_zeroize::zeroize_u64(&mut self.dp.limbs);
        oxicrypt_zeroize::zeroize_u64(&mut self.dq.limbs);
        oxicrypt_zeroize::zeroize_u64(&mut self.qinv.limbs);
    }
}

/// Generate fresh RSA-2048 key material using `drbg`, a random bit
/// generator implementing [`Rbg`], for all randomness. `e` must be an
/// odd prime in `[65537, 2^64)`.
///
/// Skips the operational and profile gates; the approved service is
/// [`crate::RsaPrivateKey2048::generate`].
///
/// # Errors
///
/// Returns [`KeygenError::Module`] unless
/// [`oxicrypt_module::require_self_test_started`] admits the call: in
/// `Operational`, or in `SelfTest` on the thread running the power-up
/// self-tests, and [`KeygenError::Rbg`] when the random bit generator
/// produces no output.
pub fn generate_2048_internal<R: Rbg>(drbg: &mut R, e: u64) -> Result<KeyMaterial, KeygenError> {
    require_self_test_started()?;
    if e < 65537 || e & 1 == 0 {
        return Err(KeygenError::InvalidExponent);
    }

    let p = gen_probable_prime_1024(drbg, e)?;
    let q = loop {
        let q_try = gen_probable_prime_1024(drbg, e)?;
        // FIPS 186-5 §A.1.1 step 2(d): |p − q| > 2^(nlen/2 − 100), which
        // is 2^924 for a 2048-bit modulus. Only `p ≠ q` is checked here,
        // not that bound.
        if q_try != p {
            break q_try;
        }
    };

    // n = p · q as a 2048-bit product.
    let n = mul_1024(&p, &q);

    // φ(n) = (p−1)(q−1) is the modulus for the inverse. FIPS 186-5
    // §A.1.1 step 3 requires d = e^(−1) mod LCM(p−1, q−1) with
    // 2^(nlen/2) < d < LCM(p−1, q−1); the inverse modulo φ(n) is a valid
    // RSA private exponent but is not guaranteed to meet that bound, and
    // this code does not compute the LCM form.
    let (p_minus_1, _) = p.subtracting_u64(1);
    let (q_minus_1, _) = q.subtracting_u64(1);
    let phi_n = mul_1024(&p_minus_1, &q_minus_1);

    // d = e^(−1) mod φ(n). `e` fits in a u64, so this uses the
    // divide-once-then-finish-in-u64 extended Euclidean path in
    // [`modinv_small_e`]. φ(n) is even, which rules out a binary
    // EGCD over odd moduli.
    let d = modinv_small_e(e, &phi_n).ok_or(KeygenError::InvalidExponent)?;

    // CRT decomposition for the sign path:
    //   dP = d mod (p − 1)
    //   dQ = d mod (q − 1)
    //   qInv = q^(−1) mod p
    //
    // (p − 1) and (q − 1) are even, so `d` is reduced directly rather
    // than `e` inverted mod an even modulus. `q` may be greater than
    // `p`; it is reduced first with at most one subtraction since both
    // live in `[2^1023, 2^1024)`.
    let dp = u2048_mod_u1024(&d, &p_minus_1);
    let dq = u2048_mod_u1024(&d, &q_minus_1);

    let q_mod_p = if q.ct_lt(&p) == 1 {
        q
    } else {
        q.subtracting(&p).0
    };
    // Compute q^(−1) mod p via Fermat's little theorem: for prime p,
    // `q^(p − 2) ≡ q^(−1) (mod p)`. The binary EGCD in
    // [`bigint1024::modinv_odd`] is not used because its intermediate
    // coefficients can exceed `m` for top-bit-set moduli such as RSA
    // primes. [`MontCtx1024::pow_public_u1024`] is not constant time in
    // its exponent, and here the exponent `p − 2` is secret.
    let ctx_p_for_inv = MontCtx1024::new(p).ok_or(KeygenError::InvalidExponent)?;
    let (p_minus_2, _) = p.subtracting_u64(2);
    let qinv = ctx_p_for_inv.pow_public_u1024(&q_mod_p, &p_minus_2);

    Ok(KeyMaterial {
        n,
        d,
        p,
        q,
        dp,
        dq,
        qinv,
    })
}

// --------------------------------------------------------------------
// Extended Euclidean modular inverse for `u64 e` in U2048 modulus `m`.
//
// Computes `e^(−1) mod m`. The strategy exploits the fact that `e`
// fits in a u64: after one big-int division `(q, r) = divmod(m, e)`
// the remainder `r < e < 2^64` is small, and the whole rest of the
// Euclidean chain runs in i128 arithmetic. One back-substitution at
// the end recovers the coefficient of `e` in a Bezout identity
// `d · e + k · m = 1`.
//
// Not constant time. Keygen calls it once with `m = φ(n)`, which is
// secret.

fn modinv_small_e(e: u64, m: &U2048) -> Option<U2048> {
    if e == 0 || m.is_zero() == 1 {
        return None;
    }

    // Step 1: reduce m mod e to a u64, and capture the quotient q0 =
    // m / e as a U2048 for the final back-substitution.
    let (q0, r0) = divmod_u2048_by_u64(m, e);
    // gcd(e, m) = gcd(e, r0). If r0 is 0, gcd = e, which is ≠ 1 for
    // e ≥ 2 — no inverse exists.
    if r0 == 0 {
        return None;
    }

    // Step 2: u64 Euclidean EGCD on (e, r0).
    //   old_r · 1 + r · 0 = e  (but tracking "coefficient of e" only)
    // After the chain, s*e + t*r0 = gcd, tracked in i128.
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
    // Now old_r = gcd(e, r0), old_s·e + old_t·r0 = gcd.
    if old_r != 1 {
        return None;
    }

    // Step 3: back-substitute r0 = m − q0·e to rewrite the Bezout
    // identity as (old_s − old_t·q0)·e + old_t·m = 1. Thus
    // d ≡ (old_s − old_t·q0) (mod m).
    //
    // |old_s|, |old_t| < e < 2^64, and q0 < m/e < 2^2048, so
    // old_t·q0 < e · m/e = m < 2^2048 in magnitude. Everything fits
    // in U2048 once the signs are handled.
    //
    // Compute absolute-value product (|old_t| · q0) and track the
    // final sign manually.

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

    // tq = |old_t| * q0, a U2048.
    let tq = mul_u2048_by_u64(&q0, t_mag);

    // Compute (old_s - old_t * q0) reduced into [0, m).
    //
    // Case A: old_t ≥ 0 ⇒ subtract tq from old_s, potentially
    // borrowing copies of m.
    //   result = (old_s − tq) mod m.
    // Case B: old_t < 0 ⇒ add tq to old_s:
    //   result = (old_s + tq) mod m.
    //
    // And old_s itself can be negative; absorb its sign as a final
    // +m correction if needed.

    // s_as_u2048: either +s_mag or −s_mag (two's complement).
    let mut s_u = u2048_from_u64(s_mag);
    if s_neg {
        s_u = two_complement_u2048(&s_u);
    }

    let step = if t_neg {
        // result_before_mod = s_u + tq  (signed arithmetic)
        let (sum, _) = s_u.adding(&tq);
        sum
    } else {
        // result_before_mod = s_u − tq
        let (diff, _) = s_u.subtracting(&tq);
        diff
    };

    // `step` is a two's-complement U2048 in (−m, m). It is reduced
    // into [0, m):
    //   - If step's signed value is < 0, add m.
    //   - Then, if the result is ≥ m, subtract m.
    let is_negative = is_u2048_negative(&step);
    let reduced = if is_negative {
        let (plus_m, _) = step.adding(m);
        plus_m
    } else {
        step
    };
    let reduced = reduced.ct_sub_if_ge(m);

    Some(reduced)
}

/// Divide a U2048 by a u64, returning (quotient, remainder).
fn divmod_u2048_by_u64(x: &U2048, divisor: u64) -> (U2048, u64) {
    let mut q = [0u64; LIMBS2048];
    let mut rem: u128 = 0;
    for i in (0..LIMBS2048).rev() {
        let cur = (rem << 64) | (x.limbs[i] as u128);
        let qi = cur / (divisor as u128);
        rem = cur % (divisor as u128);
        q[i] = qi as u64;
    }
    (U2048 { limbs: q }, rem as u64)
}

/// Multiply a U2048 by a u64 and return the low 2048 bits (caller
/// must have verified the product fits).
fn mul_u2048_by_u64(x: &U2048, k: u64) -> U2048 {
    let mut out = [0u64; LIMBS2048];
    let mut carry: u64 = 0;
    for i in 0..LIMBS2048 {
        let prod = (x.limbs[i] as u128) * (k as u128) + (carry as u128);
        out[i] = prod as u64;
        carry = (prod >> 64) as u64;
    }
    U2048 { limbs: out }
}

/// Wrap a u64 into a U2048 (low limb).
fn u2048_from_u64(x: u64) -> U2048 {
    let mut l = [0u64; LIMBS2048];
    l[0] = x;
    U2048 { limbs: l }
}

/// Two's complement negate a U2048 (treat it as a signed 2048-bit).
fn two_complement_u2048(x: &U2048) -> U2048 {
    let mut inv = [0u64; LIMBS2048];
    for i in 0..LIMBS2048 {
        inv[i] = !x.limbs[i];
    }
    let neg = U2048 { limbs: inv };
    let one = u2048_from_u64(1);
    let (r, _) = neg.adding(&one);
    r
}

/// Test the high bit of a U2048 as a signed-integer sign bit.
fn is_u2048_negative(x: &U2048) -> bool {
    (x.limbs[LIMBS2048 - 1] >> 63) & 1 == 1
}

// Keeps the unused-import lint quiet by referencing the bigint1024
// module, of which only the types are used.
#[allow(dead_code)]
const _: () = {
    let _ = bigint1024::LIMBS;
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use oxicrypt_drbg::HmacDrbgSha256;

    /// Stands in for the pre-operational integrity test.
    ///
    /// A `cargo test` binary is never signed, so the real integrity test
    /// cannot pass inside one. The module requires an integrity group to
    /// initialise at all, so a test that needs a gated service declares
    /// this stub — visibly, at the call site — rather than the module
    /// offering any way to skip the requirement.
    const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    fn init_with_tests(tests: &[oxicrypt_module::KatEntry]) -> Result<(), oxicrypt_module::Error> {
        oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, tests)
    }

    fn make_drbg(personalization: &[u8]) -> HmacDrbgSha256 {
        // Bring the module to Operational so the module-seeded
        // instantiate (and any gated key construction it
        // triggers) succeeds.
        use oxicrypt_module::KatEntry;
        let _ = init_with_tests(&[KatEntry {
            name: "rsa-keygen-test-noop",
            run: || Ok(()),
        }]);
        HmacDrbgSha256::instantiate_from_module(personalization).unwrap()
    }

    #[test]
    fn small_primes_rejects_obvious_composites() {
        crate::test_support::start_module();
        // 15 = 3·5; rem by 3 is 0 ⇒ small-factor reject.
        let mut limbs = [0u64; LIMBS1024];
        limbs[0] = 15;
        let p = U1024 { limbs };
        assert!(has_small_factor(&p));
    }

    #[test]
    fn small_primes_does_not_panic_on_large_candidate() {
        crate::test_support::start_module();
        // `has_small_factor` on a large odd 1024-bit number must not
        // panic on the full operand width. The number is 2^1024 − 105.
        let mut limbs = [0u64; LIMBS1024];
        limbs.fill(!0u64);
        limbs[0] = !0u64 ^ 0x68;
        let p = U1024 { limbs };
        let _ = has_small_factor(&p);
    }

    #[test]
    fn miller_rabin_does_not_panic_on_synthetic_input() {
        crate::test_support::start_module();
        // Exercises the MR control flow on a synthetic composite
        // 1024-bit odd value. The accept/reject result is not checked;
        // end-to-end correctness is `generate_2048_smoke`'s job.
        let mut limbs = [0u64; LIMBS1024];
        limbs[0] = 7;
        limbs[LIMBS1024 - 1] = 1 << 63;
        let n_fake = U1024 { limbs };
        let mut drbg = make_drbg(b"oxicrypt-mr-smoke-test-seed-0000");
        let _ = miller_rabin(&n_fake, 2, &mut drbg);
    }

    // A full keygen is very slow in debug (can be 10+ seconds because
    // of the O(n^2) CIOS + O(1024) MR exponentiations). One keygen
    // still runs in tests so the path is exercised end-to-end.
    #[test]
    fn generate_2048_smoke() {
        // PCT inside from_components gates on the module being
        // operational, so bring the module up via the standard
        // initialization path first.
        use oxicrypt_module::KatEntry;
        let _ = init_with_tests(&[KatEntry {
            name: "rsa-2048-keygen-smoke",
            run: crate::self_test,
        }]);
        let mut drbg = make_drbg(b"oxicrypt-rsa-keygen-smoke-entropy-0001");
        let km = generate_2048_internal(&mut drbg, 65537).expect("keygen failed");
        assert_ne!(km.n.limbs[LIMBS2048 - 1] >> 63, 0, "n is not 2048-bit");
        assert_eq!(km.d.ct_lt(&km.n), 1, "d ≥ n");

        // `from_components` runs the pairwise consistency test; its
        // acceptance shows the key is self-consistent.
        let n_bytes = km.n.to_be_bytes();
        let d_bytes = km.d.to_be_bytes();
        let key = crate::RsaPrivateKey2048::from_components(&n_bytes, 65537, &d_bytes);
        assert!(
            key.is_ok(),
            "keygen produced a key that failed PCT: {:?}",
            key.err()
        );
    }

    /// Regression KAT: pins the `(n, d)` produced by a fixed HMAC_DRBG
    /// seed so accidental changes to the sieve order, MR witness
    /// sampling, or inverse algorithm are caught loudly. If this test
    /// breaks intentionally (e.g., the generator is re-ordered), just
    /// re-capture the expected bytes.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn generate_2048_pinned_kat() {
        use oxicrypt_module::KatEntry;
        let _ = init_with_tests(&[KatEntry {
            name: "rsa-2048-keygen-pinned-kat",
            run: crate::self_test,
        }]);
        let mut drbg = HmacDrbgSha256::default();
        drbg.instantiate(
            b"oxicrypt-rsa-keygen-kat-entropy-0001-pinned",
            b"oxicrypt-rsa-keygen-kat-nonce-0001",
            b"",
        )
        .unwrap();
        let km = generate_2048_internal(&mut drbg, 65537).expect("keygen failed");

        const EXPECTED_N: [u8; 256] = [
            0xca, 0x87, 0x4f, 0xb2, 0xe5, 0x6a, 0x08, 0xd0, 0xbb, 0x59, 0x23, 0xe1, 0xa0, 0xf5,
            0x9b, 0x48, 0xc9, 0x0a, 0xe9, 0x2b, 0x65, 0x34, 0x17, 0x7e, 0x1c, 0x49, 0x91, 0xbd,
            0x89, 0x15, 0x33, 0x1c, 0xaf, 0xef, 0x7e, 0xf8, 0xa8, 0x74, 0xe5, 0xc0, 0x40, 0xa1,
            0xd8, 0x04, 0x0c, 0x05, 0x70, 0xe9, 0xe5, 0x8c, 0x39, 0xf3, 0xd9, 0x5d, 0xce, 0xec,
            0x48, 0x42, 0x0c, 0xd9, 0x46, 0x0e, 0xeb, 0x36, 0xee, 0x27, 0x03, 0xb9, 0x42, 0x17,
            0xc1, 0x2e, 0xab, 0x92, 0x42, 0x13, 0xff, 0x7e, 0xd8, 0x9b, 0x5e, 0x70, 0xb6, 0xd3,
            0x08, 0xaa, 0xc5, 0x6f, 0x66, 0x64, 0x09, 0x63, 0x70, 0x9c, 0x73, 0x91, 0xb2, 0x8e,
            0x27, 0xf6, 0x26, 0x12, 0xad, 0xf2, 0x3a, 0x21, 0xf5, 0x5c, 0xf7, 0x1d, 0xfc, 0x9f,
            0xfc, 0xe4, 0x23, 0xc6, 0x09, 0xd9, 0xda, 0x3f, 0xc9, 0xac, 0x1f, 0x6c, 0x82, 0x7e,
            0x2d, 0x95, 0x73, 0xe0, 0x7f, 0xde, 0xe3, 0x4d, 0x2a, 0x7f, 0xb0, 0xcf, 0x5f, 0x84,
            0x3e, 0x6d, 0xb4, 0x58, 0x5a, 0xcd, 0xcd, 0xbe, 0x32, 0x5c, 0x05, 0x2a, 0xe6, 0x9d,
            0x81, 0xbe, 0x9b, 0xc1, 0xa8, 0x1a, 0x3b, 0x95, 0xaf, 0x33, 0x76, 0xd1, 0x0d, 0x00,
            0x78, 0x65, 0x25, 0xb9, 0x83, 0x39, 0xd0, 0x23, 0x2a, 0x07, 0xb0, 0x21, 0x8d, 0x8b,
            0x1c, 0xf0, 0x51, 0x53, 0x0d, 0x9c, 0x34, 0x89, 0x97, 0xd7, 0x96, 0x1c, 0xbf, 0xd9,
            0x31, 0x7e, 0x66, 0xbf, 0x7a, 0xc8, 0xe0, 0xf8, 0x69, 0xf8, 0x75, 0x2e, 0x4c, 0x90,
            0xe6, 0x19, 0x95, 0x14, 0x20, 0xa0, 0xaf, 0x1a, 0xd4, 0xdf, 0xa1, 0x70, 0x7e, 0xf6,
            0x4f, 0x26, 0xf3, 0x41, 0xee, 0x3a, 0xae, 0xf5, 0x96, 0x8c, 0x46, 0xe6, 0x6f, 0x2f,
            0x5c, 0xdc, 0xd3, 0x71, 0x56, 0xe5, 0xd9, 0x6c, 0x3f, 0x3f, 0xda, 0x0f, 0x8c, 0x92,
            0xd7, 0x68, 0x8e, 0x99,
        ];
        const EXPECTED_D: [u8; 256] = [
            0x18, 0x3c, 0xb7, 0x41, 0xfe, 0x88, 0x81, 0x03, 0x91, 0xd8, 0x2a, 0x1e, 0x1f, 0x68,
            0x25, 0x2c, 0x41, 0xbb, 0x07, 0x8a, 0x84, 0xf3, 0x05, 0xf8, 0xb6, 0xa3, 0xeb, 0x48,
            0x16, 0x76, 0xae, 0x06, 0x39, 0xdb, 0xdc, 0x83, 0x1f, 0x8d, 0xd5, 0xcc, 0xfb, 0x2f,
            0x23, 0x2d, 0xe0, 0xce, 0x69, 0xe3, 0xe3, 0xef, 0xb3, 0x23, 0xc6, 0x98, 0x9e, 0x61,
            0xd2, 0x87, 0xed, 0x07, 0xb7, 0x85, 0xa3, 0x8a, 0x90, 0x57, 0xa4, 0xef, 0x6f, 0xc4,
            0x6d, 0xff, 0x0a, 0xd3, 0x57, 0x0b, 0x13, 0xa1, 0x77, 0x84, 0xa8, 0x79, 0xae, 0xb7,
            0x74, 0xab, 0x13, 0x33, 0xb0, 0xba, 0x3a, 0x11, 0x67, 0x71, 0xa1, 0xb7, 0x06, 0xfa,
            0x52, 0x37, 0xf7, 0xf8, 0x76, 0x4e, 0xad, 0xbc, 0x50, 0xa3, 0xce, 0x83, 0x0d, 0x2f,
            0x8c, 0x51, 0x35, 0x22, 0xc7, 0x1d, 0x06, 0x2c, 0x6a, 0x13, 0x2a, 0x33, 0x8f, 0x2e,
            0x50, 0x80, 0x02, 0x76, 0xb8, 0x49, 0xfc, 0x24, 0x79, 0x27, 0x7a, 0xc2, 0x28, 0x72,
            0xfe, 0xbe, 0x0c, 0x26, 0x6e, 0xf7, 0xc5, 0x10, 0xa7, 0x0c, 0x90, 0x50, 0xc4, 0xe4,
            0x13, 0xce, 0x26, 0xdf, 0x98, 0x58, 0x17, 0x31, 0x22, 0x17, 0x1a, 0xa9, 0xf2, 0x2a,
            0x19, 0xb4, 0x45, 0xcc, 0x72, 0xb4, 0x36, 0x31, 0x0f, 0x72, 0x18, 0x6a, 0x29, 0xb9,
            0x87, 0x45, 0xf5, 0xab, 0x45, 0xbb, 0x2b, 0xff, 0x60, 0x32, 0x5b, 0x04, 0x4b, 0xe2,
            0xb2, 0x2d, 0xfd, 0x62, 0x2f, 0x84, 0x95, 0x77, 0xbb, 0x9e, 0xa7, 0xa2, 0x60, 0x0f,
            0xa1, 0x34, 0x13, 0x74, 0xaa, 0x1d, 0xfb, 0x89, 0x37, 0x1a, 0xfb, 0xfc, 0x89, 0x6d,
            0x94, 0xb3, 0xdf, 0x6a, 0x9a, 0xec, 0x32, 0x67, 0xd3, 0x96, 0x3b, 0x92, 0x55, 0xf6,
            0x77, 0x0b, 0x75, 0x01, 0x78, 0x84, 0x94, 0x4f, 0x4c, 0x63, 0x38, 0x19, 0x64, 0x23,
            0xc8, 0x89, 0x26, 0x9d,
        ];

        assert_eq!(km.n.to_be_bytes(), EXPECTED_N, "keygen n drift");
        assert_eq!(km.d.to_be_bytes(), EXPECTED_D, "keygen d drift");

        let key =
            crate::RsaPrivateKey2048::from_components(&EXPECTED_N, 65537, &EXPECTED_D).unwrap();
        let _ = key;
    }
}
