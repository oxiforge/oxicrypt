//! Declarative macro that generates a full ML-DSA parameter-set
//! implementation (FIPS 204 §6 internal primitives + §5.2 external
//! `ctx`-framing wrappers + power-up KAT) from a small parameter
//! tuple.
//!
//! This is the encoding/wiring single source of truth for ML-DSA-44,
//! ML-DSA-65, and ML-DSA-87. It mirrors the
//! [`ml_kem_impl!`](../../oxicrypt-ml-kem/src/ml_kem_impl.rs) macro
//! shipped in PR #74, which descends from the
//! [`define_rsa_wide!`](../../oxicrypt-rsa/src/rsa_wide_impl.rs)
//! pattern used by RSA-3072 / RSA-4096.
//!
//! # Macro inputs
//!
//! Per-variant parameters from FIPS 204 §4 Table 1:
//!
//! | Parameter | Meaning |
//! |-----------|---------|
//! | `lambda` | Security category bits (128, 192, or 256) |
//! | `tau` | Number of ±1 coefficients in the challenge polynomial c |
//! | `gamma1` | Mask range: y coefficients in [−γ₁+1, γ₁] |
//! | `gamma2` | Decomposition modulus for `Decompose` / `HighBits` / `LowBits` |
//! | `k` | Module rank for the public key (rows of A) |
//! | `l` | Module rank for the secret key (columns of A) |
//! | `eta` | Secret key coefficient range: s₁, s₂ ∈ [−η, η] (η ∈ {2, 4}) |
//! | `beta` | Norm bound β = τ · η |
//! | `omega` | Max hint weight (nonzero entries in h across k polys) |
//!
//! Derived constants emitted by the macro:
//!
//! | Constant | Derivation |
//! |----------|-----------|
//! | `CTILDE_LEN` | λ / 4 (challenge seed length in bytes: 32 / 48 / 64) |
//! | `ETA_PACKED` | 96 if η=2 (3 bits/coeff), 128 if η=4 (4 bits/coeff) |
//! | `Z_PACKED` | 576 if γ₁=2¹⁷ (18 bits/coeff), 640 if γ₁=2¹⁹ (20 bits/coeff) |
//! | `H_PACKED` | ω + k |
//! | `W1_PACKED` | 128 if γ₂=(q−1)/32 (4 bits/coeff), 192 if γ₂=(q−1)/88 (6 bits/coeff); ×k for whole vector |
//! | `PK_LEN` | 32 + k · 320 |
//! | `SK_LEN` | 32 + 32 + 64 + (ℓ + k) · ETA_PACKED + k · 416 |
//! | `SIG_LEN` | CTILDE_LEN + ℓ · Z_PACKED + ω + k |
//!
//! # Generated items
//!
//! | Item | Visibility | Purpose |
//! |------|-----------|---------|
//! | `LAMBDA`, `TAU`, `GAMMA1`, `GAMMA2`, `K`, `L`, `ETA`, `BETA`, `OMEGA` | `pub const` | Parameter constants |
//! | `CTILDE_LEN`, `ETA_PACKED`, `Z_PACKED`, `H_PACKED`, `W1_PACKED`, `W1_PACKED_TOTAL` | `pub const` | Derived size constants |
//! | `PK_LEN`, `SK_LEN`, `SIG_LEN`, `SEED_LEN` | `pub const` | Re-exported / derived sizes |
//! | `PolyVecK`, `PolyVecL` | `pub(crate)` | Fixed-length poly vectors |
//! | `expand_a`, `expand_s`, `expand_mask`, `sample_in_ball`, `rej_bounded_poly` | private | Per-variant sampling |
//! | `decompose`, `high_bits`, `low_bits`, `make_hint`, `use_hint`, `power2round` | private | Per-γ₂ rounding |
//! | `pack_eta`, `unpack_eta`, `pack_z`, `unpack_z`, `pack_t0`, `unpack_t0`, `pack_t1`, `unpack_t1`, `pack_hint`, `unpack_hint`, `pack_pk/sk/sig`, `unpack_pk/sk/sig`, `pack_w1` | private | Per-variant byte encoding |
//! | `ml_dsa_keygen`, `ml_dsa_sign`, `ml_dsa_verify` | private | FIPS 204 §6 internal primitives |
//! | `keygen`, `sign`, `verify` | `pub` | Module-gated FIPS 204 §5.2 external API (with `ctx` framing) |
//! | `keygen_internal`, `sign_internal`, `verify_internal` | `pub` (hidden) | Gate-free FIPS 204 §6 mirrors |
//! | `KATS`, `KAT_ENTRY`, `self_test` | `pub` | Power-up self-test |
//!
//! # Architectural note (CMVP gem)
//!
//! The macro is the **single source of truth for every parameter-set
//! divergence** in ML-DSA. There is no parallel hand-written
//! implementation per variant — every byte of `ExpandA`, `ExpandS`,
//! `ExpandMask`, `SampleInBall`, the rejection-sampling sign loop,
//! the `Decompose` / `MakeHint` / `UseHint` chain, and the byte
//! encodings is generated from one macro body. A bug fix in the macro
//! body fixes all three variants in lock-step, and the only way to
//! introduce a per-variant divergence is to add a conditional branch
//! on one of the macro parameters inside the macro body — which is
//! visible at the single audit site. The two intra-macro conditional
//! branches — η ∈ {2, 4} in `rej_bounded_poly` / `pack_eta` and
//! γ₂ ∈ {(q−1)/32, (q−1)/88} in `decompose` / `use_hint` /
//! `pack_w1` — are evaluated at instantiation time (each branch
//! reads `const` parameters), so the emitted code for each variant
//! is monomorphised down to one path.

#![allow(unused_macros)]

macro_rules! ml_dsa_impl {
    (
        // Per-variant parameters (FIPS 204 §4 Table 1).
        lambda = $lambda:expr;
        tau = $tau:expr;
        gamma1 = $gamma1:expr;
        gamma2 = $gamma2:expr;
        k = $k:expr;
        l = $l:expr;
        eta = $eta:expr;
        beta = $beta:expr;
        omega = $omega:expr;
        // Service variants for module gating.
        svc_keygen = $svc_keygen:expr;
        svc_sign = $svc_sign:expr;
        svc_verify = $svc_verify:expr;
        // KAT seeds.
        kat_xi = $kat_xi:expr;
        kat_msg = $kat_msg:expr;
        kat_name = $kat_name:expr;
    ) => {
        use oxicrypt_module::{Error, KatEntry, SelfTestFailure, Service};
        use oxicrypt_xof::{Shake128, Shake256};
        use $crate::field::reduce32;
        use $crate::params::{D, N, Q, SEED_LEN as SHARED_SEED_LEN, T0_PACKED, T1_PACKED};
        use $crate::poly::Poly;

        // ── Parameter constants ─────────────────────────────────────────

        /// Security category bits (128 / 192 / 256).
        pub const LAMBDA: usize = $lambda;

        /// Number of ±1 coefficients in challenge polynomial c.
        pub const TAU: usize = $tau;

        /// Mask range: y coefficients in [−γ₁+1, γ₁].
        pub const GAMMA1: i32 = $gamma1;

        /// Decomposition modulus γ₂ ∈ {(q−1)/32, (q−1)/88}.
        pub const GAMMA2: i32 = $gamma2;

        /// Module rank for public key (rows in A).
        pub const K: usize = $k;

        /// Module rank for secret key (columns in A).
        pub const L: usize = $l;

        /// Secret-vector coefficient range η ∈ {2, 4}.
        pub const ETA: i32 = $eta;

        /// Norm bound β = τ · η.
        pub const BETA: i32 = $beta;

        /// Max total hint weight (nonzero entries in h across k polys).
        pub const OMEGA: usize = $omega;

        /// Keygen seed length (32 bytes, FIPS 204 §6.1).
        pub use $crate::params::SEED_LEN;

        // ── Derived sizes ───────────────────────────────────────────────

        /// Challenge seed length c̃ in bytes = λ / 4 (= 2λ / 8).
        ///
        /// 32 for ML-DSA-44, 48 for ML-DSA-65, 64 for ML-DSA-87.
        pub const CTILDE_LEN: usize = LAMBDA / 4;

        /// Bytes per polynomial for η encoding. 3 bits/coeff if η=2,
        /// 4 bits/coeff if η=4. (256·3/8 = 96 or 256·4/8 = 128.)
        pub const ETA_PACKED: usize = if ETA == 2 { 96 } else { 128 };

        /// Bytes per polynomial for z encoding.
        ///
        /// γ₁=2¹⁷ → 18 bits/coeff → 576; γ₁=2¹⁹ → 20 bits/coeff → 640.
        pub const Z_PACKED: usize = if GAMMA1 == (1 << 17) { 576 } else { 640 };

        /// Bytes for hint encoding: ω + k.
        pub const H_PACKED: usize = OMEGA + K;

        /// Bytes per w₁ polynomial used in `pack_w1` (hashing).
        ///
        /// γ₂=(q−1)/32 → high coefficients in [0,15] → 4 bits/coeff → 128;
        /// γ₂=(q−1)/88 → high coefficients in [0,43] → 6 bits/coeff → 192.
        pub const W1_PACKED: usize = if GAMMA2 == (Q - 1) / 32 { 128 } else { 192 };

        /// Total `pack_w1` buffer length across the k components.
        pub const W1_PACKED_TOTAL: usize = K * W1_PACKED;

        /// Public key size in bytes: ρ (32) + k · t₁_packed (k · 320).
        pub const PK_LEN: usize = 32 + K * T1_PACKED;

        /// Secret key size in bytes:
        /// ρ(32) + K(32) + tr(64) + s₁(ℓ · ETA_PACKED) + s₂(K · ETA_PACKED) + t₀(K · 416).
        pub const SK_LEN: usize = 32 + 32 + 64 + L * ETA_PACKED + K * ETA_PACKED + K * T0_PACKED;

        /// Signature size in bytes: c̃ + z (ℓ · Z_PACKED) + hint (ω + k).
        pub const SIG_LEN: usize = CTILDE_LEN + L * Z_PACKED + H_PACKED;

        // ── PolyVec types (K/L-dependent) ───────────────────────────────

        /// A vector of `K` polynomials.
        #[derive(Clone)]
        #[allow(dead_code)]
        pub(crate) struct PolyVecK {
            pub(crate) polys: [Poly; K],
        }

        impl PolyVecK {
            /// Zero vector.
            pub(crate) fn zero() -> Self {
                Self {
                    polys: core::array::from_fn(|_| Poly::zero()),
                }
            }

            /// Forward NTT on every component.
            pub(crate) fn ntt(&mut self) {
                for p in &mut self.polys {
                    p.ntt();
                }
            }

            /// Inverse NTT on every component.
            pub(crate) fn inv_ntt(&mut self) {
                for p in &mut self.polys {
                    p.inv_ntt();
                }
            }

            /// Reduce all coefficients in every component.
            pub(crate) fn reduce(&mut self) {
                for p in &mut self.polys {
                    p.reduce();
                }
            }

            /// Add `other` to `self` component-wise.
            pub(crate) fn add_assign(&mut self, other: &Self) {
                for i in 0..K {
                    self.polys[i].add_assign(&other.polys[i]);
                }
            }

            /// Subtract `other` from `self` component-wise.
            pub(crate) fn sub_assign(&mut self, other: &Self) {
                for i in 0..K {
                    self.polys[i].sub_assign(&other.polys[i]);
                }
            }

            /// Check if any polynomial's infinity norm exceeds bound.
            pub(crate) fn check_norm(&self, bound: i32) -> bool {
                for p in &self.polys {
                    if p.check_norm(bound) {
                        return true;
                    }
                }
                false
            }
        }

        /// A vector of `L` polynomials.
        #[derive(Clone)]
        #[allow(dead_code)]
        pub(crate) struct PolyVecL {
            pub(crate) polys: [Poly; L],
        }

        impl PolyVecL {
            /// Zero vector.
            pub(crate) fn zero() -> Self {
                Self {
                    polys: core::array::from_fn(|_| Poly::zero()),
                }
            }

            /// Forward NTT on every component.
            pub(crate) fn ntt(&mut self) {
                for p in &mut self.polys {
                    p.ntt();
                }
            }

            /// Inverse NTT on every component.
            pub(crate) fn inv_ntt(&mut self) {
                for p in &mut self.polys {
                    p.inv_ntt();
                }
            }

            /// Reduce all coefficients in every component.
            pub(crate) fn reduce(&mut self) {
                for p in &mut self.polys {
                    p.reduce();
                }
            }

            /// Add `other` to `self` component-wise.
            pub(crate) fn add_assign(&mut self, other: &Self) {
                for i in 0..L {
                    self.polys[i].add_assign(&other.polys[i]);
                }
            }

            /// Check if any polynomial's infinity norm exceeds bound.
            pub(crate) fn check_norm(&self, bound: i32) -> bool {
                for p in &self.polys {
                    if p.check_norm(bound) {
                        return true;
                    }
                }
                false
            }
        }

        /// Pointwise multiply a k×l matrix by a length-l vector,
        /// accumulating into a length-k vector (in NTT domain).
        fn matrix_pointwise_mul(t: &mut PolyVecK, mat: &[[Poly; L]; K], s: &PolyVecL) {
            for i in 0..K {
                for c in &mut t.polys[i].coeffs {
                    *c = 0;
                }
                for j in 0..L {
                    $crate::ntt::pointwise_acc(
                        &mut t.polys[i].coeffs,
                        &mat[i][j].coeffs,
                        &s.polys[j].coeffs,
                    );
                }
                t.polys[i].reduce();
            }
        }

        /// Pointwise multiply: c = a ◦ b in NTT domain (single poly).
        fn poly_pointwise(c: &mut Poly, a: &Poly, b: &Poly) {
            $crate::ntt::pointwise_mul(&mut c.coeffs, &a.coeffs, &b.coeffs);
        }

        // ── Rounding (γ₂-dependent) ─────────────────────────────────────

        /// `Power2Round(r)`: decompose r ∈ [0, q) into (r₁, r₀) such
        /// that r ≡ r₁·2^d + r₀ (mod q) and r₀ ∈ (−2^(d−1), 2^(d−1)].
        #[inline]
        fn power2round(r: i32) -> (i32, i32) {
            let r1 = (r + (1 << (D - 1)) - 1) >> D;
            let r0 = r - (r1 << D);
            (r1, r0)
        }

        /// `Decompose(r)`: r ≡ r₁·2γ₂ + r₀ (mod q), r₀ centered.
        ///
        /// Two γ₂ regimes per FIPS 204 §7.4 / Dilithium reference:
        /// - γ₂ = (q−1)/32: r₁ ∈ [0, 15], constants tuned for q=8380417.
        /// - γ₂ = (q−1)/88: r₁ ∈ [0, 43], constants tuned for q=8380417.
        #[inline]
        fn decompose(r: i32) -> (i32, i32) {
            let two_gamma2 = 2 * GAMMA2;
            let mut r1;
            if GAMMA2 == (Q - 1) / 32 {
                // Dilithium ref: γ₂ = (q−1)/32, 2γ₂ = (q−1)/16
                r1 = (r + 127) >> 7;
                r1 = (r1 * 1025 + (1 << 21)) >> 22;
                r1 &= 15;
            } else {
                // Dilithium ref: γ₂ = (q−1)/88, 2γ₂ = (q−1)/44
                r1 = (r + 127) >> 7;
                r1 = (r1 * 11_275 + (1 << 23)) >> 24;
                r1 ^= ((43 - r1) >> 31) & r1;
            }
            let mut r0 = r - r1 * two_gamma2;
            r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;
            (r1, r0)
        }

        /// `HighBits(r)` = the high part of `Decompose(r)`.
        #[inline]
        fn high_bits(r: i32) -> i32 {
            decompose(r).0
        }

        /// `LowBits(r)` = the low part of `Decompose(r)`.
        #[inline]
        #[allow(dead_code)]
        fn low_bits(r: i32) -> i32 {
            decompose(r).1
        }

        /// `MakeHint` per FIPS 204 Algorithm 27, expressed in
        /// pq-crystals's shortcut form on centered low-bits `a0` and
        /// the corresponding high-bits `a1`.
        ///
        /// `a0` is the centered representative of `LowBits(w) − c·s₂ +
        /// c·t₀`, bounded by `(−2γ₂, 2γ₂)` after the c·t₀ norm check.
        /// `a1` is `w₁ = HighBits(w)` at the same coefficient position.
        ///
        /// Returns 1 iff applying the perturbation `c·t₀` would flip
        /// the high-bits bin — equivalent to
        /// `HighBits(r) ≠ HighBits(r + z)` in Algorithm 27, but with
        /// the `−γ₂` fence case made explicit so the `Decompose`
        /// top-bin wrap (where `r⁺ = q − γ₂` maps to `r₁ = 0,
        /// r₀ = −γ₂`) is still classified as a bin flip when
        /// `w₁ ≠ 0`.  The spec-form
        /// `HighBits(r) ≠ HighBits(r + z)` aliases this fence onto
        /// `r₁ = 0`, hiding the flip.  Matches
        /// pq-crystals/dilithium's `make_hint` in `rounding.c` so
        /// ACVP-grading produces byte-identical signatures across the
        /// centered/unsigned representation boundary.
        #[inline]
        fn make_hint(a0: i32, a1: i32) -> i32 {
            let outside = !(-GAMMA2..=GAMMA2).contains(&a0);
            let fence = a0 == -GAMMA2 && a1 != 0;
            i32::from(outside || fence)
        }

        /// `UseHint(h, r)`: if h=0 return `HighBits(r)`, else shift
        /// up/down by one mod m where m = (q−1)/(2γ₂).
        #[inline]
        fn use_hint(h: i32, r: i32) -> i32 {
            let (r1, r0) = decompose(r);
            if h == 0 {
                return r1;
            }
            let m: i32 = if GAMMA2 == (Q - 1) / 32 { 16 } else { 44 };
            if r0 > 0 {
                (r1 + 1) % m
            } else {
                (r1 + m - 1) % m
            }
        }

        fn polyveck_power2round(t: &PolyVecK, t1: &mut PolyVecK, t0: &mut PolyVecK) {
            for i in 0..K {
                for j in 0..N {
                    let (hi, lo) = power2round(t.polys[i].coeffs[j]);
                    t1.polys[i].coeffs[j] = hi;
                    t0.polys[i].coeffs[j] = lo;
                }
            }
        }

        fn polyveck_decompose(w: &PolyVecK, w1: &mut PolyVecK, w0: &mut PolyVecK) {
            for i in 0..K {
                for j in 0..N {
                    let (hi, lo) = decompose(w.polys[i].coeffs[j]);
                    w1.polys[i].coeffs[j] = hi;
                    w0.polys[i].coeffs[j] = lo;
                }
            }
        }

        /// Compute the hint vector h coefficient-wise from `(a0, a1)`
        /// and count the number of set bits.
        ///
        /// `a0` is the polynomial-vector of centered low-bits values
        /// `LowBits(w) − c·s₂ + c·t₀` (each coefficient bounded by
        /// `2γ₂`).  `a1` is the polynomial-vector of high-bits values
        /// `w₁`.
        ///
        /// Returns the count of 1-bits across all k polynomials.  If
        /// the count exceeds ω, the caller should reject.
        fn polyveck_make_hint(h: &mut PolyVecK, a0: &PolyVecK, a1: &PolyVecK) -> usize {
            let mut count = 0;
            for i in 0..K {
                for j in 0..N {
                    h.polys[i].coeffs[j] = make_hint(a0.polys[i].coeffs[j], a1.polys[i].coeffs[j]);
                    count += h.polys[i].coeffs[j] as usize;
                }
            }
            count
        }

        fn polyveck_use_hint(w1_prime: &mut PolyVecK, w: &PolyVecK, h: &PolyVecK) {
            for i in 0..K {
                for j in 0..N {
                    w1_prime.polys[i].coeffs[j] =
                        use_hint(h.polys[i].coeffs[j], w.polys[i].coeffs[j]);
                }
            }
        }

        fn reduce_polyveck(v: &mut PolyVecK) {
            for p in &mut v.polys {
                for c in &mut p.coeffs {
                    *c = reduce32(*c);
                }
            }
        }

        /// Pack w₁ into per-poly buffers for hashing.
        ///
        /// γ₂=(q−1)/32: coefficients in [0,15], 4 bits/coeff,
        /// 128 bytes/poly.
        /// γ₂=(q−1)/88: coefficients in [0,43], 6 bits/coeff,
        /// 192 bytes/poly (packed 4 coeffs per 3 bytes).
        fn pack_w1(w1: &PolyVecK, buf: &mut [u8]) {
            debug_assert!(buf.len() >= W1_PACKED_TOTAL);
            if GAMMA2 == (Q - 1) / 32 {
                let mut offset = 0;
                for i in 0..K {
                    for j in (0..N).step_by(2) {
                        buf[offset] = (w1.polys[i].coeffs[j] as u8)
                            | ((w1.polys[i].coeffs[j + 1] as u8) << 4);
                        offset += 1;
                    }
                }
            } else {
                // 6 bits per coefficient, 4 coefficients into 3 bytes.
                let mut offset = 0;
                for i in 0..K {
                    for j in (0..N).step_by(4) {
                        let c0 = w1.polys[i].coeffs[j] as u8;
                        let c1 = w1.polys[i].coeffs[j + 1] as u8;
                        let c2 = w1.polys[i].coeffs[j + 2] as u8;
                        let c3 = w1.polys[i].coeffs[j + 3] as u8;
                        buf[offset] = c0 | (c1 << 6);
                        buf[offset + 1] = (c1 >> 2) | (c2 << 4);
                        buf[offset + 2] = (c2 >> 4) | (c3 << 2);
                        offset += 3;
                    }
                }
            }
        }

        // ── Sampling (per-variant) ──────────────────────────────────────

        /// RejNTTPoly: rejection-sample a polynomial in NTT domain
        /// from a SHAKE-128 stream (FIPS 204 §8.3 Algorithm 32).
        fn rej_ntt_poly(xof: &mut Shake128) -> Poly {
            let mut poly = Poly::zero();
            let mut j: usize = 0;
            let mut buf = [0u8; 3];
            while j < N {
                xof.squeeze(&mut buf);
                let t = ((buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16))
                    & 0x7F_FFFF;
                if t < Q as u32 {
                    poly.coeffs[j] = t as i32;
                    j += 1;
                }
            }
            poly
        }

        /// ExpandA (FIPS 204 §8.3 Algorithm 30): A[i][j] ←
        /// RejNTTPoly(SHAKE-128(ρ ‖ IntegerToBits(j,8) ‖ IntegerToBits(i,8))).
        ///
        /// Sequential build (default, `no_std`): the rows are filled in
        /// order, each cell from its own fresh local XOF.
        #[cfg(not(feature = "parallel"))]
        fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
            let mut mat: [[Poly; L]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            for i in 0..K {
                for j in 0..L {
                    let mut xof = Shake128::new_internal();
                    xof.update(rho);
                    xof.update(&[j as u8, i as u8]);
                    xof.finalize();
                    mat[i][j] = rej_ntt_poly(&mut xof);
                }
            }
            mat
        }

        /// ExpandA (FIPS 204 §8.3 Algorithm 30): A[i][j] ←
        /// RejNTTPoly(SHAKE-128(ρ ‖ IntegerToBits(j,8) ‖ IntegerToBits(i,8))).
        ///
        /// Parallel build: the *outer* row loop is forked across a
        /// `rayon` parallel iterator. Each closure owns exactly its row
        /// `i` and writes only `row[j]`, sampling every cell from a
        /// fresh local SHAKE-128 XOF that is a pure function of ρ and
        /// `(i, j)` — there is no shared mutable state. Because each row
        /// is written into its fixed array slot, the matrix is
        /// recombined *by position*, never by completion order, so the
        /// output is byte-identical to the sequential build regardless
        /// of thread count.
        #[cfg(feature = "parallel")]
        fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
            use rayon::iter::{
                IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
            };

            let mut mat: [[Poly; L]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            (&mut mat[..])
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, row)| {
                    for j in 0..L {
                        let mut xof = Shake128::new_internal();
                        xof.update(rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        row[j] = rej_ntt_poly(&mut xof);
                    }
                });
            mat
        }

        /// RejBoundedPoly: rejection-sample coefficients in [−η, η]
        /// from SHAKE-256 (FIPS 204 §8.3 Algorithm 33, CoeffFromHalfByte).
        ///
        /// η=2: half-byte threshold 15; coefficient = 2 − (t mod 5).
        /// η=4: half-byte threshold 9;  coefficient = 4 − t.
        fn rej_bounded_poly(xof: &mut Shake256) -> Poly {
            let mut poly = Poly::zero();
            let mut j: usize = 0;
            let mut buf = [0u8; 1];
            while j < N {
                xof.squeeze(&mut buf);
                let b = buf[0];
                let t0 = b & 0x0F;
                let t1 = b >> 4;
                if ETA == 2 {
                    if t0 < 15 {
                        let a0 = t0 as i32;
                        let m0 = a0 - 5 * (a0 / 5);
                        poly.coeffs[j] = ETA - m0;
                        j += 1;
                    }
                    if j >= N {
                        break;
                    }
                    if t1 < 15 {
                        let a1 = t1 as i32;
                        let m1 = a1 - 5 * (a1 / 5);
                        poly.coeffs[j] = ETA - m1;
                        j += 1;
                    }
                } else {
                    // ETA == 4
                    if t0 < 9 {
                        poly.coeffs[j] = ETA - t0 as i32;
                        j += 1;
                    }
                    if j >= N {
                        break;
                    }
                    if t1 < 9 {
                        poly.coeffs[j] = ETA - t1 as i32;
                        j += 1;
                    }
                }
            }
            poly
        }

        /// ExpandS (FIPS 204 §8.3 Algorithm 31):
        /// s₁[r] ← RejBoundedPoly(SHAKE-256(σ ‖ r))   for r ∈ [0, ℓ)
        /// s₂[r] ← RejBoundedPoly(SHAKE-256(σ ‖ ℓ+r)) for r ∈ [0, k)
        fn expand_s(sigma: &[u8; 64]) -> (PolyVecL, PolyVecK) {
            let mut s1 = PolyVecL::zero();
            let mut s2 = PolyVecK::zero();
            for r in 0..L {
                let mut xof = Shake256::new_internal();
                xof.update(sigma);
                xof.update(&[r as u8, (r >> 8) as u8]);
                xof.finalize();
                s1.polys[r] = rej_bounded_poly(&mut xof);
            }
            for r in 0..K {
                let mut xof = Shake256::new_internal();
                xof.update(sigma);
                let idx = L + r;
                xof.update(&[idx as u8, (idx >> 8) as u8]);
                xof.finalize();
                s2.polys[r] = rej_bounded_poly(&mut xof);
            }
            (s1, s2)
        }

        /// Sample a single mask polynomial with coefficients in
        /// [−γ₁+1, γ₁] from SHAKE-256(seed ‖ counter).
        ///
        /// γ₁ = 2¹⁹: 20 bits/coeff, 640 bytes XOF output, 10 bytes →
        /// 4 coeffs.
        /// γ₁ = 2¹⁷: 18 bits/coeff, 576 bytes XOF output, 9 bytes →
        /// 4 coeffs.
        fn sample_mask_poly(seed: &[u8; 64], counter: u16) -> Poly {
            let mut poly = Poly::zero();
            let mut xof = Shake256::new_internal();
            xof.update(seed);
            xof.update(&counter.to_le_bytes());
            xof.finalize();

            if GAMMA1 == (1 << 19) {
                let mut buf = [0u8; 640];
                xof.squeeze(&mut buf);
                for i in 0..N / 4 {
                    let off = i * 10;
                    let b0 = buf[off] as u32;
                    let b1 = buf[off + 1] as u32;
                    let b2 = buf[off + 2] as u32;
                    let b3 = buf[off + 3] as u32;
                    let b4 = buf[off + 4] as u32;
                    let b5 = buf[off + 5] as u32;
                    let b6 = buf[off + 6] as u32;
                    let b7 = buf[off + 7] as u32;
                    let b8 = buf[off + 8] as u32;
                    let b9 = buf[off + 9] as u32;

                    let c0 = (b0 | (b1 << 8) | ((b2 & 0x0F) << 16)) & 0xFFFFF;
                    let c1 = ((b2 >> 4) | (b3 << 4) | (b4 << 12)) & 0xFFFFF;
                    let c2 = (b5 | (b6 << 8) | ((b7 & 0x0F) << 16)) & 0xFFFFF;
                    let c3 = ((b7 >> 4) | (b8 << 4) | (b9 << 12)) & 0xFFFFF;

                    poly.coeffs[4 * i] = GAMMA1 - c0 as i32;
                    poly.coeffs[4 * i + 1] = GAMMA1 - c1 as i32;
                    poly.coeffs[4 * i + 2] = GAMMA1 - c2 as i32;
                    poly.coeffs[4 * i + 3] = GAMMA1 - c3 as i32;
                }
            } else {
                // GAMMA1 == 1 << 17
                let mut buf = [0u8; 576];
                xof.squeeze(&mut buf);
                for i in 0..N / 4 {
                    let off = i * 9;
                    let b0 = buf[off] as u32;
                    let b1 = buf[off + 1] as u32;
                    let b2 = buf[off + 2] as u32;
                    let b3 = buf[off + 3] as u32;
                    let b4 = buf[off + 4] as u32;
                    let b5 = buf[off + 5] as u32;
                    let b6 = buf[off + 6] as u32;
                    let b7 = buf[off + 7] as u32;
                    let b8 = buf[off + 8] as u32;

                    let c0 = (b0 | (b1 << 8) | (b2 << 16)) & 0x3FFFF;
                    let c1 = ((b2 >> 2) | (b3 << 6) | (b4 << 14)) & 0x3FFFF;
                    let c2 = ((b4 >> 4) | (b5 << 4) | (b6 << 12)) & 0x3FFFF;
                    let c3 = ((b6 >> 6) | (b7 << 2) | (b8 << 10)) & 0x3FFFF;

                    poly.coeffs[4 * i] = GAMMA1 - c0 as i32;
                    poly.coeffs[4 * i + 1] = GAMMA1 - c1 as i32;
                    poly.coeffs[4 * i + 2] = GAMMA1 - c2 as i32;
                    poly.coeffs[4 * i + 3] = GAMMA1 - c3 as i32;
                }
            }
            poly
        }

        /// ExpandMask (FIPS 204 §8.3 Algorithm 34): y[r] ←
        /// SampleMaskPoly(ρ'', κ + r) for r ∈ [0, ℓ).
        fn expand_mask(seed: &[u8; 64], kappa: u16) -> PolyVecL {
            let mut y = PolyVecL::zero();
            for r in 0..L {
                y.polys[r] = sample_mask_poly(seed, kappa + r as u16);
            }
            y
        }

        /// SampleInBall (FIPS 204 §8.2 Algorithm 29).
        fn sample_in_ball(seed: &[u8]) -> Poly {
            let mut c = Poly::zero();
            let mut xof = Shake256::new_internal();
            xof.update(seed);
            xof.finalize();

            let mut sign_bytes = [0u8; 8];
            xof.squeeze(&mut sign_bytes);
            let mut signs = u64::from_le_bytes(sign_bytes);

            for i in (N - TAU)..N {
                let j = {
                    let mut buf = [0u8; 1];
                    loop {
                        xof.squeeze(&mut buf);
                        let val = buf[0] as usize;
                        if val <= i {
                            break val;
                        }
                    }
                };
                c.coeffs[i] = c.coeffs[j];
                let sign = signs & 1;
                signs >>= 1;
                c.coeffs[j] = if sign == 0 { 1 } else { Q - 1 };
            }
            c
        }

        // ── Byte encoding (per-variant) ─────────────────────────────────

        /// Pack a polynomial with coefficients in [−η, η].
        ///
        /// η=2: 3 bits/coeff (8 coeffs → 3 bytes), 96 bytes/poly.
        /// η=4: 4 bits/coeff (2 coeffs/byte),       128 bytes/poly.
        fn pack_eta(poly: &Poly, buf: &mut [u8]) {
            debug_assert!(buf.len() >= ETA_PACKED);
            if ETA == 2 {
                for i in 0..N / 8 {
                    let mut t = [0u8; 8];
                    for j in 0..8 {
                        t[j] = (ETA - poly.coeffs[8 * i + j]) as u8;
                    }
                    buf[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
                    buf[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                    buf[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
                }
            } else {
                // ETA == 4: 4-bit unsigned coefficients in [0, 8].
                for i in 0..N / 2 {
                    let a = (ETA - poly.coeffs[2 * i]) as u8;
                    let b = (ETA - poly.coeffs[2 * i + 1]) as u8;
                    buf[i] = (a & 0x0F) | ((b & 0x0F) << 4);
                }
            }
        }

        fn unpack_eta(buf: &[u8], poly: &mut Poly) {
            debug_assert!(buf.len() >= ETA_PACKED);
            if ETA == 2 {
                for i in 0..N / 8 {
                    let b0 = buf[3 * i] as u32;
                    let b1 = buf[3 * i + 1] as u32;
                    let b2 = buf[3 * i + 2] as u32;

                    poly.coeffs[8 * i] = ETA - (b0 & 7) as i32;
                    poly.coeffs[8 * i + 1] = ETA - ((b0 >> 3) & 7) as i32;
                    poly.coeffs[8 * i + 2] = ETA - (((b0 >> 6) | (b1 << 2)) & 7) as i32;
                    poly.coeffs[8 * i + 3] = ETA - ((b1 >> 1) & 7) as i32;
                    poly.coeffs[8 * i + 4] = ETA - ((b1 >> 4) & 7) as i32;
                    poly.coeffs[8 * i + 5] = ETA - (((b1 >> 7) | (b2 << 1)) & 7) as i32;
                    poly.coeffs[8 * i + 6] = ETA - ((b2 >> 2) & 7) as i32;
                    poly.coeffs[8 * i + 7] = ETA - ((b2 >> 5) & 7) as i32;
                }
            } else {
                for i in 0..N / 2 {
                    let v = buf[i];
                    poly.coeffs[2 * i] = ETA - (v & 0x0F) as i32;
                    poly.coeffs[2 * i + 1] = ETA - ((v >> 4) & 0x0F) as i32;
                }
            }
        }

        /// Pack t₁ polynomial (coefficients in [0, 2¹⁰)): 4 coeffs → 5 bytes.
        fn pack_t1(poly: &Poly, buf: &mut [u8]) {
            debug_assert!(buf.len() >= T1_PACKED);
            for i in 0..N / 4 {
                let c0 = poly.coeffs[4 * i] as u32;
                let c1 = poly.coeffs[4 * i + 1] as u32;
                let c2 = poly.coeffs[4 * i + 2] as u32;
                let c3 = poly.coeffs[4 * i + 3] as u32;

                buf[5 * i] = c0 as u8;
                buf[5 * i + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
                buf[5 * i + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
                buf[5 * i + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
                buf[5 * i + 4] = (c3 >> 2) as u8;
            }
        }

        fn unpack_t1(buf: &[u8], poly: &mut Poly) {
            debug_assert!(buf.len() >= T1_PACKED);
            for i in 0..N / 4 {
                let b0 = buf[5 * i] as u32;
                let b1 = buf[5 * i + 1] as u32;
                let b2 = buf[5 * i + 2] as u32;
                let b3 = buf[5 * i + 3] as u32;
                let b4 = buf[5 * i + 4] as u32;

                poly.coeffs[4 * i] = (b0 | (b1 << 8)) as i32 & 0x3FF;
                poly.coeffs[4 * i + 1] = ((b1 >> 2) | (b2 << 6)) as i32 & 0x3FF;
                poly.coeffs[4 * i + 2] = ((b2 >> 4) | (b3 << 4)) as i32 & 0x3FF;
                poly.coeffs[4 * i + 3] = ((b3 >> 6) | (b4 << 2)) as i32 & 0x3FF;
            }
        }

        /// Pack t₀ polynomial (coefficients in (−2^(d−1), 2^(d−1)]).
        /// 8 coefficients → 13 bytes.
        fn pack_t0(poly: &Poly, buf: &mut [u8]) {
            debug_assert!(buf.len() >= T0_PACKED);
            let half = 1i32 << (D - 1);
            for i in 0..N / 8 {
                let mut t = [0u32; 8];
                for j in 0..8 {
                    t[j] = (half - poly.coeffs[8 * i + j]) as u32;
                }
                buf[13 * i] = t[0] as u8;
                buf[13 * i + 1] = (t[0] >> 8) as u8 | (t[1] << 5) as u8;
                buf[13 * i + 2] = (t[1] >> 3) as u8;
                buf[13 * i + 3] = (t[1] >> 11) as u8 | (t[2] << 2) as u8;
                buf[13 * i + 4] = (t[2] >> 6) as u8 | (t[3] << 7) as u8;
                buf[13 * i + 5] = (t[3] >> 1) as u8;
                buf[13 * i + 6] = (t[3] >> 9) as u8 | (t[4] << 4) as u8;
                buf[13 * i + 7] = (t[4] >> 4) as u8;
                buf[13 * i + 8] = (t[4] >> 12) as u8 | (t[5] << 1) as u8;
                buf[13 * i + 9] = (t[5] >> 7) as u8 | (t[6] << 6) as u8;
                buf[13 * i + 10] = (t[6] >> 2) as u8;
                buf[13 * i + 11] = (t[6] >> 10) as u8 | (t[7] << 3) as u8;
                buf[13 * i + 12] = (t[7] >> 5) as u8;
            }
        }

        fn unpack_t0(buf: &[u8], poly: &mut Poly) {
            debug_assert!(buf.len() >= T0_PACKED);
            let half = 1i32 << (D - 1);
            for i in 0..N / 8 {
                let b = |idx: usize| buf[13 * i + idx] as u32;

                let t0 = b(0) | (b(1) << 8);
                let t1 = (b(1) >> 5) | (b(2) << 3) | (b(3) << 11);
                let t2 = (b(3) >> 2) | (b(4) << 6);
                let t3 = (b(4) >> 7) | (b(5) << 1) | (b(6) << 9);
                let t4 = (b(6) >> 4) | (b(7) << 4) | (b(8) << 12);
                let t5 = (b(8) >> 1) | (b(9) << 7);
                let t6 = (b(9) >> 6) | (b(10) << 2) | (b(11) << 10);
                let t7 = (b(11) >> 3) | (b(12) << 5);

                poly.coeffs[8 * i] = half - (t0 & 0x1FFF) as i32;
                poly.coeffs[8 * i + 1] = half - (t1 & 0x1FFF) as i32;
                poly.coeffs[8 * i + 2] = half - (t2 & 0x1FFF) as i32;
                poly.coeffs[8 * i + 3] = half - (t3 & 0x1FFF) as i32;
                poly.coeffs[8 * i + 4] = half - (t4 & 0x1FFF) as i32;
                poly.coeffs[8 * i + 5] = half - (t5 & 0x1FFF) as i32;
                poly.coeffs[8 * i + 6] = half - (t6 & 0x1FFF) as i32;
                poly.coeffs[8 * i + 7] = half - (t7 & 0x1FFF) as i32;
            }
        }

        /// Pack z polynomial.
        ///
        /// γ₁=2¹⁹: 20 bits/coeff, 4 coeffs → 10 bytes.
        /// γ₁=2¹⁷: 18 bits/coeff, 4 coeffs → 9 bytes.
        fn pack_z(poly: &Poly, buf: &mut [u8]) {
            debug_assert!(buf.len() >= Z_PACKED);
            if GAMMA1 == (1 << 19) {
                for i in 0..N / 4 {
                    let mut t = [0u32; 4];
                    for j in 0..4 {
                        let mut c = poly.coeffs[4 * i + j];
                        if c > (Q - 1) / 2 {
                            c -= Q;
                        }
                        t[j] = (GAMMA1 - c) as u32;
                    }
                    buf[10 * i] = t[0] as u8;
                    buf[10 * i + 1] = (t[0] >> 8) as u8;
                    buf[10 * i + 2] = (t[0] >> 16) as u8 | (t[1] << 4) as u8;
                    buf[10 * i + 3] = (t[1] >> 4) as u8;
                    buf[10 * i + 4] = (t[1] >> 12) as u8;
                    buf[10 * i + 5] = t[2] as u8;
                    buf[10 * i + 6] = (t[2] >> 8) as u8;
                    buf[10 * i + 7] = (t[2] >> 16) as u8 | (t[3] << 4) as u8;
                    buf[10 * i + 8] = (t[3] >> 4) as u8;
                    buf[10 * i + 9] = (t[3] >> 12) as u8;
                }
            } else {
                // γ₁ = 2¹⁷ → 18 bits per coefficient, 4 coeffs → 9 bytes
                for i in 0..N / 4 {
                    let mut t = [0u32; 4];
                    for j in 0..4 {
                        let mut c = poly.coeffs[4 * i + j];
                        if c > (Q - 1) / 2 {
                            c -= Q;
                        }
                        t[j] = (GAMMA1 - c) as u32;
                    }
                    buf[9 * i] = t[0] as u8;
                    buf[9 * i + 1] = (t[0] >> 8) as u8;
                    buf[9 * i + 2] = (t[0] >> 16) as u8 | (t[1] << 2) as u8;
                    buf[9 * i + 3] = (t[1] >> 6) as u8;
                    buf[9 * i + 4] = (t[1] >> 14) as u8 | (t[2] << 4) as u8;
                    buf[9 * i + 5] = (t[2] >> 4) as u8;
                    buf[9 * i + 6] = (t[2] >> 12) as u8 | (t[3] << 6) as u8;
                    buf[9 * i + 7] = (t[3] >> 2) as u8;
                    buf[9 * i + 8] = (t[3] >> 10) as u8;
                }
            }
        }

        fn unpack_z(buf: &[u8], poly: &mut Poly) {
            debug_assert!(buf.len() >= Z_PACKED);
            if GAMMA1 == (1 << 19) {
                for i in 0..N / 4 {
                    let b = |idx: usize| buf[10 * i + idx] as u32;
                    let t0 = b(0) | (b(1) << 8) | ((b(2) & 0x0F) << 16);
                    let t1 = (b(2) >> 4) | (b(3) << 4) | (b(4) << 12);
                    let t2 = b(5) | (b(6) << 8) | ((b(7) & 0x0F) << 16);
                    let t3 = (b(7) >> 4) | (b(8) << 4) | (b(9) << 12);

                    poly.coeffs[4 * i] = GAMMA1 - (t0 & 0xFFFFF) as i32;
                    poly.coeffs[4 * i + 1] = GAMMA1 - (t1 & 0xFFFFF) as i32;
                    poly.coeffs[4 * i + 2] = GAMMA1 - (t2 & 0xFFFFF) as i32;
                    poly.coeffs[4 * i + 3] = GAMMA1 - (t3 & 0xFFFFF) as i32;
                }
            } else {
                for i in 0..N / 4 {
                    let b = |idx: usize| buf[9 * i + idx] as u32;
                    let t0 = b(0) | (b(1) << 8) | ((b(2) & 0x03) << 16);
                    let t1 = (b(2) >> 2) | (b(3) << 6) | ((b(4) & 0x0F) << 14);
                    let t2 = (b(4) >> 4) | (b(5) << 4) | ((b(6) & 0x3F) << 12);
                    let t3 = (b(6) >> 6) | (b(7) << 2) | (b(8) << 10);

                    poly.coeffs[4 * i] = GAMMA1 - (t0 & 0x3FFFF) as i32;
                    poly.coeffs[4 * i + 1] = GAMMA1 - (t1 & 0x3FFFF) as i32;
                    poly.coeffs[4 * i + 2] = GAMMA1 - (t2 & 0x3FFFF) as i32;
                    poly.coeffs[4 * i + 3] = GAMMA1 - (t3 & 0x3FFFF) as i32;
                }
            }
        }

        /// Hint encoding — FIPS 204 §7.2.
        fn pack_hint(h: &PolyVecK, buf: &mut [u8]) -> bool {
            debug_assert!(buf.len() >= H_PACKED);
            for b in buf.iter_mut().take(H_PACKED) {
                *b = 0;
            }
            let mut offset = 0usize;
            for i in 0..K {
                for j in 0..N {
                    if h.polys[i].coeffs[j] != 0 {
                        if offset >= OMEGA {
                            return false;
                        }
                        buf[offset] = j as u8;
                        offset += 1;
                    }
                }
                buf[OMEGA + i] = offset as u8;
            }
            true
        }

        fn unpack_hint(buf: &[u8], h: &mut PolyVecK) -> bool {
            debug_assert!(buf.len() >= H_PACKED);
            for p in &mut h.polys {
                for c in &mut p.coeffs {
                    *c = 0;
                }
            }
            let mut prev_offset = 0u8;
            for i in 0..K {
                let cur_offset = buf[OMEGA + i];
                if cur_offset < prev_offset || cur_offset as usize > OMEGA {
                    return false;
                }
                let mut prev_idx: Option<u8> = None;
                for kk in (prev_offset as usize)..(cur_offset as usize) {
                    let idx = buf[kk];
                    if idx as usize >= N {
                        return false;
                    }
                    if let Some(p) = prev_idx
                        && idx <= p
                    {
                        return false;
                    }
                    h.polys[i].coeffs[idx as usize] = 1;
                    prev_idx = Some(idx);
                }
                prev_offset = cur_offset;
            }
            for kk in (prev_offset as usize)..OMEGA {
                if buf[kk] != 0 {
                    return false;
                }
            }
            true
        }

        fn pack_pk(rho: &[u8; 32], t1: &PolyVecK, pk: &mut [u8]) {
            debug_assert!(pk.len() >= PK_LEN);
            pk[..32].copy_from_slice(rho);
            for i in 0..K {
                let off = 32 + i * T1_PACKED;
                pack_t1(&t1.polys[i], &mut pk[off..off + T1_PACKED]);
            }
        }

        fn unpack_pk(pk: &[u8], rho: &mut [u8; 32], t1: &mut PolyVecK) {
            debug_assert!(pk.len() >= PK_LEN);
            rho.copy_from_slice(&pk[..32]);
            for i in 0..K {
                let off = 32 + i * T1_PACKED;
                unpack_t1(&pk[off..off + T1_PACKED], &mut t1.polys[i]);
            }
        }

        fn pack_sk(
            rho: &[u8; 32],
            key: &[u8; 32],
            tr: &[u8; 64],
            s1: &PolyVecL,
            s2: &PolyVecK,
            t0: &PolyVecK,
            sk: &mut [u8],
        ) {
            debug_assert!(sk.len() >= SK_LEN);
            let mut off = 0;
            sk[off..off + 32].copy_from_slice(rho);
            off += 32;
            sk[off..off + 32].copy_from_slice(key);
            off += 32;
            sk[off..off + 64].copy_from_slice(tr);
            off += 64;
            for i in 0..L {
                pack_eta(&s1.polys[i], &mut sk[off..off + ETA_PACKED]);
                off += ETA_PACKED;
            }
            for i in 0..K {
                pack_eta(&s2.polys[i], &mut sk[off..off + ETA_PACKED]);
                off += ETA_PACKED;
            }
            for i in 0..K {
                pack_t0(&t0.polys[i], &mut sk[off..off + T0_PACKED]);
                off += T0_PACKED;
            }
        }

        fn unpack_sk(
            sk: &[u8],
            rho: &mut [u8; 32],
            key: &mut [u8; 32],
            tr: &mut [u8; 64],
            s1: &mut PolyVecL,
            s2: &mut PolyVecK,
            t0: &mut PolyVecK,
        ) {
            debug_assert!(sk.len() >= SK_LEN);
            let mut off = 0;
            rho.copy_from_slice(&sk[off..off + 32]);
            off += 32;
            key.copy_from_slice(&sk[off..off + 32]);
            off += 32;
            tr.copy_from_slice(&sk[off..off + 64]);
            off += 64;
            for i in 0..L {
                unpack_eta(&sk[off..off + ETA_PACKED], &mut s1.polys[i]);
                off += ETA_PACKED;
            }
            for i in 0..K {
                unpack_eta(&sk[off..off + ETA_PACKED], &mut s2.polys[i]);
                off += ETA_PACKED;
            }
            for i in 0..K {
                unpack_t0(&sk[off..off + T0_PACKED], &mut t0.polys[i]);
                off += T0_PACKED;
            }
        }

        fn pack_sig(ctilde: &[u8], z: &PolyVecL, h: &PolyVecK, sig: &mut [u8]) -> bool {
            debug_assert!(sig.len() >= SIG_LEN);
            debug_assert!(ctilde.len() == CTILDE_LEN);
            sig[..CTILDE_LEN].copy_from_slice(ctilde);
            let mut off = CTILDE_LEN;
            for i in 0..L {
                pack_z(&z.polys[i], &mut sig[off..off + Z_PACKED]);
                off += Z_PACKED;
            }
            pack_hint(h, &mut sig[off..off + H_PACKED])
        }

        fn unpack_sig(sig: &[u8], ctilde: &mut [u8], z: &mut PolyVecL, h: &mut PolyVecK) -> bool {
            if sig.len() < SIG_LEN {
                return false;
            }
            debug_assert!(ctilde.len() == CTILDE_LEN);
            ctilde.copy_from_slice(&sig[..CTILDE_LEN]);
            let mut off = CTILDE_LEN;
            for i in 0..L {
                unpack_z(&sig[off..off + Z_PACKED], &mut z.polys[i]);
                off += Z_PACKED;
            }
            unpack_hint(&sig[off..off + H_PACKED], h)
        }

        // ── FIPS 204 §6 internal primitives ────────────────────────────

        /// ML-DSA.KeyGen (FIPS 204 §6.1 / Algorithm 1) per parameter set.
        fn ml_dsa_keygen(xi: &[u8; 32]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
            let mut h = Shake256::new_internal();
            h.update(xi);
            h.update(&[K as u8]);
            h.update(&[L as u8]);
            h.finalize();

            let mut rho = [0u8; 32];
            let mut sigma = [0u8; 64];
            let mut key = [0u8; 32];
            h.squeeze(&mut rho);
            h.squeeze(&mut sigma);
            h.squeeze(&mut key);

            let a_hat = expand_a(&rho);
            let (s1, s2) = expand_s(&sigma);

            let mut s1_hat = s1.clone();
            s1_hat.ntt();

            let mut t = PolyVecK::zero();
            matrix_pointwise_mul(&mut t, &a_hat, &s1_hat);
            t.inv_ntt();
            t.add_assign(&s2);
            t.reduce();

            let mut t1 = PolyVecK::zero();
            let mut t0 = PolyVecK::zero();
            polyveck_power2round(&t, &mut t1, &mut t0);

            let mut pk = [0u8; PK_LEN];
            pack_pk(&rho, &t1, &mut pk);

            let mut tr = [0u8; 64];
            let mut h_pk = Shake256::new_internal();
            h_pk.update(&pk);
            h_pk.finalize();
            h_pk.squeeze(&mut tr);

            let mut sk = [0u8; SK_LEN];
            pack_sk(&rho, &key, &tr, &s1, &s2, &t0, &mut sk);

            // Phase 3 zeroize (FIPS 140-3 IG 7.7 / SP 800-140B §7.9):
            // wipe the two stack-local secret seeds before the function
            // exits. `sigma` is the SHAKE-256 output that derives s1, s2;
            // `key` is the implicit-rejection / signing seed K embedded
            // in sk. Both are now persisted into sk (copy-discard scratch).
            oxicrypt_zeroize::zeroize(&mut sigma);
            oxicrypt_zeroize::zeroize(&mut key);

            (pk, sk)
        }

        /// ML-DSA.Sign (FIPS 204 §6.2 / Algorithm 7, deterministic).
        fn ml_dsa_sign(
            sk: &[u8; SK_LEN],
            m_prefix: &[u8],
            message: &[u8],
        ) -> Option<[u8; SIG_LEN]> {
            let mut rho = [0u8; 32];
            let mut key = [0u8; 32];
            let mut tr = [0u8; 64];
            let mut s1 = PolyVecL::zero();
            let mut s2 = PolyVecK::zero();
            let mut t0 = PolyVecK::zero();
            unpack_sk(sk, &mut rho, &mut key, &mut tr, &mut s1, &mut s2, &mut t0);

            let a_hat = expand_a(&rho);

            let mut mu = [0u8; 64];
            {
                let mut h = Shake256::new_internal();
                h.update(&tr);
                h.update(m_prefix);
                h.update(message);
                h.finalize();
                h.squeeze(&mut mu);
            }

            let rnd = [0u8; 32];
            let mut rho_pp = [0u8; 64];
            {
                let mut h = Shake256::new_internal();
                h.update(&key);
                h.update(&rnd);
                h.update(&mu);
                h.finalize();
                h.squeeze(&mut rho_pp);
            }

            let mut s1_hat = s1.clone();
            s1_hat.ntt();
            let mut s2_hat = s2.clone();
            s2_hat.ntt();
            let mut t0_hat = t0.clone();
            t0_hat.ntt();

            let mut kappa: u16 = 0;
            let max_iters = 1000u16;

            loop {
                if kappa >= max_iters {
                    // Phase 3 zeroize: wipe the unpacked signing seed K
                    // before the no-signature exit path.
                    oxicrypt_zeroize::zeroize(&mut key);
                    return None;
                }

                let y = expand_mask(&rho_pp, kappa * L as u16);

                let mut y_hat = y.clone();
                y_hat.ntt();
                let mut w = PolyVecK::zero();
                matrix_pointwise_mul(&mut w, &a_hat, &y_hat);
                w.inv_ntt();
                w.reduce();

                let mut w1 = PolyVecK::zero();
                let mut w0 = PolyVecK::zero();
                polyveck_decompose(&w, &mut w1, &mut w0);

                let mut ctilde = [0u8; CTILDE_LEN];
                {
                    let mut w1_packed = [0u8; W1_PACKED_TOTAL];
                    pack_w1(&w1, &mut w1_packed);
                    let mut h = Shake256::new_internal();
                    h.update(&mu);
                    h.update(&w1_packed);
                    h.finalize();
                    h.squeeze(&mut ctilde);
                }

                let c = sample_in_ball(&ctilde);
                let mut c_hat = c.clone();
                c_hat.ntt();

                let mut z = PolyVecL::zero();
                for i in 0..L {
                    poly_pointwise(&mut z.polys[i], &c_hat, &s1_hat.polys[i]);
                }
                z.inv_ntt();
                z.add_assign(&y);
                z.reduce();

                if z.check_norm(GAMMA1 - BETA) {
                    kappa += 1;
                    continue;
                }

                let mut cs2 = PolyVecK::zero();
                for i in 0..K {
                    poly_pointwise(&mut cs2.polys[i], &c_hat, &s2_hat.polys[i]);
                }
                cs2.inv_ntt();

                let mut r0 = w0.clone();
                r0.sub_assign(&cs2);
                reduce_polyveck(&mut r0);

                if r0.check_norm(GAMMA2 - BETA) {
                    kappa += 1;
                    continue;
                }

                let mut ct0 = PolyVecK::zero();
                for i in 0..K {
                    poly_pointwise(&mut ct0.polys[i], &c_hat, &t0_hat.polys[i]);
                }
                ct0.inv_ntt();
                ct0.reduce();

                if ct0.check_norm(GAMMA2) {
                    kappa += 1;
                    continue;
                }

                // 4j. Compute hint h per FIPS 204 §6.2 Algorithm 7 step 32:
                //   h = MakeHint(−c·t₀, w − c·s₂ + c·t₀)
                //
                // Use pq-crystals/dilithium's centered shortcut form so
                // the `a0 == −γ₂ && w₁ ≠ 0` fence case is handled
                // explicitly.  The spec-form
                // `HighBits(r) ≠ HighBits(r + z)` aliases this fence
                // onto `r₁ = 0 = v₁` via the Decompose top-bin wrap
                // (`r⁺ = q − γ₂ → r₁ = 0, r₀ = −γ₂`), silently flipping
                // the hint at rare inputs.  See R69 in
                // `docs/security-policy/security-policy.md` and ACVTS
                // session 730469 vsId 3859350 tcId 8.
                //
                // a0 = centered(LowBits(w) − c·s₂ + c·t₀)
                let mut a0 = r0.clone();
                a0.add_assign(&ct0);
                reduce_polyveck(&mut a0);
                for p in &mut a0.polys {
                    for c_val in &mut p.coeffs {
                        if *c_val > (Q - 1) / 2 {
                            *c_val -= Q;
                        }
                    }
                }

                // a1 = w₁ (high-bits of the original w, recorded above)
                let mut h_vec = PolyVecK::zero();
                let hint_count = polyveck_make_hint(&mut h_vec, &a0, &w1);

                if hint_count > OMEGA {
                    kappa += 1;
                    continue;
                }

                let mut sig = [0u8; SIG_LEN];
                if !pack_sig(&ctilde, &z, &h_vec, &mut sig) {
                    kappa += 1;
                    continue;
                }

                // Phase 3 zeroize: wipe the unpacked signing seed K
                // before the successful-signature exit path.
                oxicrypt_zeroize::zeroize(&mut key);
                return Some(sig);
            }
        }

        /// ML-DSA.Verify (FIPS 204 §6.3 / Algorithm 8).
        fn ml_dsa_verify(
            pk: &[u8; PK_LEN],
            m_prefix: &[u8],
            message: &[u8],
            sig: &[u8; SIG_LEN],
        ) -> bool {
            let mut rho = [0u8; 32];
            let mut t1 = PolyVecK::zero();
            unpack_pk(pk, &mut rho, &mut t1);

            let mut ctilde = [0u8; CTILDE_LEN];
            let mut z = PolyVecL::zero();
            let mut h_vec = PolyVecK::zero();
            if !unpack_sig(sig, &mut ctilde, &mut z, &mut h_vec) {
                return false;
            }

            if z.check_norm(GAMMA1 - BETA) {
                return false;
            }

            let a_hat = expand_a(&rho);

            let mut tr = [0u8; 64];
            {
                let mut h_pk = Shake256::new_internal();
                h_pk.update(pk);
                h_pk.finalize();
                h_pk.squeeze(&mut tr);
            }

            let mut mu = [0u8; 64];
            {
                let mut h_mu = Shake256::new_internal();
                h_mu.update(&tr);
                h_mu.update(m_prefix);
                h_mu.update(message);
                h_mu.finalize();
                h_mu.squeeze(&mut mu);
            }

            let c = sample_in_ball(&ctilde);
            let mut c_hat = c.clone();
            c_hat.ntt();

            let mut z_hat = z.clone();
            z_hat.ntt();

            let mut w_prime = PolyVecK::zero();
            matrix_pointwise_mul(&mut w_prime, &a_hat, &z_hat);

            let mut t1_scaled = t1.clone();
            for p in &mut t1_scaled.polys {
                for coeff in &mut p.coeffs {
                    *coeff <<= D;
                }
            }
            t1_scaled.ntt();

            let mut ct1 = PolyVecK::zero();
            for i in 0..K {
                poly_pointwise(&mut ct1.polys[i], &c_hat, &t1_scaled.polys[i]);
            }

            w_prime.sub_assign(&ct1);
            w_prime.inv_ntt();
            w_prime.reduce();

            let mut w1_prime = PolyVecK::zero();
            polyveck_use_hint(&mut w1_prime, &w_prime, &h_vec);

            let mut ctilde_prime = [0u8; CTILDE_LEN];
            {
                let mut w1_packed = [0u8; W1_PACKED_TOTAL];
                pack_w1(&w1_prime, &mut w1_packed);
                let mut h_final = Shake256::new_internal();
                h_final.update(&mu);
                h_final.update(&w1_packed);
                h_final.finalize();
                h_final.squeeze(&mut ctilde_prime);
            }

            ctilde == ctilde_prime
        }

        // ── Public gated API (FIPS 204 §5.2 external) ───────────────────

        /// Generate a key pair (FIPS 204 §6.1).
        pub fn keygen(xi: &[u8; SEED_LEN]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_keygen)?;
            Ok(keygen_internal(xi))
        }

        /// Sign a message (FIPS 204 §5.2 Algorithm 2, deterministic).
        ///
        /// Frames the message as M' = 0x00 || |ctx| || ctx || M before
        /// applying the internal §6.2 primitive. `ctx.len()` must be ≤
        /// 255 (FIPS 204 §5.2).
        pub fn sign(sk: &[u8; SK_LEN], message: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_sign)?;
            let prefix_buf = $crate::build_external_prefix(ctx)?;
            ml_dsa_sign(sk, prefix_buf.as_slice(), message).ok_or(Error::InvalidInput)
        }

        /// Verify a signature (FIPS 204 §5.2 Algorithm 3).
        pub fn verify(
            pk: &[u8; PK_LEN],
            message: &[u8],
            ctx: &[u8],
            sig: &[u8; SIG_LEN],
        ) -> Result<(), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_verify)?;
            let prefix_buf = $crate::build_external_prefix(ctx)?;
            if ml_dsa_verify(pk, prefix_buf.as_slice(), message, sig) {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            }
        }

        // ── Internal API (gate-free, for KATs and ACVP) ─────────────────

        /// Internal keygen — no module gate (FIPS 204 §6.1).
        #[doc(hidden)]
        pub fn keygen_internal(xi: &[u8; SEED_LEN]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
            ml_dsa_keygen(xi)
        }

        /// Internal sign — no module gate, no `ctx` framing
        /// (FIPS 204 §6.2 Algorithm 7).
        #[doc(hidden)]
        pub fn sign_internal(sk: &[u8; SK_LEN], message: &[u8]) -> Option<[u8; SIG_LEN]> {
            ml_dsa_sign(sk, &[], message)
        }

        /// Internal verify — no module gate, no `ctx` framing
        /// (FIPS 204 §6.3 Algorithm 8).
        #[doc(hidden)]
        pub fn verify_internal(pk: &[u8; PK_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
            ml_dsa_verify(pk, &[], message, sig)
        }

        // ── Power-up KATs ───────────────────────────────────────────────

        /// Deterministic KAT seed for keygen.
        const KAT_XI: [u8; 32] = $kat_xi;

        /// Test message for KAT.
        const KAT_MSG: &[u8] = $kat_msg;

        /// Self-test: deterministic keygen → sign → verify round-trip
        /// + negative (wrong-message + tampered-signature) tests.
        pub fn self_test() -> Result<(), SelfTestFailure> {
            let (pk, sk) = keygen_internal(&KAT_XI);
            let Some(sig) = sign_internal(&sk, KAT_MSG) else {
                return Err(SelfTestFailure);
            };
            if !verify_internal(&pk, KAT_MSG, &sig) {
                return Err(SelfTestFailure);
            }
            if verify_internal(&pk, b"wrong message", &sig) {
                return Err(SelfTestFailure);
            }
            let mut sig_bad = sig;
            sig_bad[100] ^= 0x01;
            if verify_internal(&pk, KAT_MSG, &sig_bad) {
                return Err(SelfTestFailure);
            }
            Ok(())
        }

        /// Single power-up KAT entry for this parameter set.
        pub const KAT_ENTRY: KatEntry = KatEntry {
            name: $kat_name,
            run: self_test,
        };

        /// Power-up KATs for this parameter set (one entry).
        pub const KATS: &[KatEntry] = &[KAT_ENTRY];

        // Compile-time sanity: the shared `SEED_LEN` constant from
        // `crate::params` matches the variant-local re-export.
        #[allow(dead_code)]
        const _ASSERT_SEED_LEN_MATCHES: usize = SHARED_SEED_LEN - SEED_LEN;

        // ── Determinism oracle (parallel feature only) ──────────────
        //
        // Oracle choice: `expand_a` is reachable in-crate (the per-variant
        // unit-test module reaches the macro-internal items via
        // `use super::*`), so we add a direct equality oracle rather than
        // relying only on the keygen-KAT-on/off check. We rebuild the
        // matrix with an always-sequential reference loop (which never
        // touches the rayon path) and assert it equals the feature-gated
        // `expand_a` cell-for-cell, for a few deterministic ρ values. The
        // keygen KATs (fixed ξ → fixed ρ → fixed A → fixed pk/sk) remain
        // the end-to-end oracle; this test pins `expand_a` itself.
        #[cfg(all(test, feature = "parallel"))]
        mod parallel_determinism {
            use super::*;

            /// Always-sequential reference: identical to the non-parallel
            /// `expand_a` body, never invoking the rayon path.
            fn expand_a_sequential_reference(rho: &[u8; 32]) -> [[Poly; L]; K] {
                let mut mat: [[Poly; L]; K] =
                    core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
                for i in 0..K {
                    for j in 0..L {
                        let mut xof = Shake128::new_internal();
                        xof.update(rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        mat[i][j] = rej_ntt_poly(&mut xof);
                    }
                }
                mat
            }

            #[test]
            fn parallel_expand_a_matches_sequential_reference() {
                for k in 0u8..4 {
                    let mut rho = [0u8; 32];
                    for (idx, b) in rho.iter_mut().enumerate() {
                        *b = k.wrapping_mul(7).wrapping_add(idx as u8).wrapping_add(0x5a);
                    }
                    let par = expand_a(&rho);
                    let seq = expand_a_sequential_reference(&rho);
                    for i in 0..K {
                        for j in 0..L {
                            assert_eq!(
                                par[i][j].coeffs, seq[i][j].coeffs,
                                "A cell mismatch at seed k={k}, i={i}, j={j}"
                            );
                        }
                    }
                }
            }
        }
    };
}

pub(crate) use ml_dsa_impl;
