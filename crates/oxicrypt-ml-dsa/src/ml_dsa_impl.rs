//! Declarative macro that generates a full ML-DSA parameter-set
//! implementation (FIPS 204 §6 internal primitives + §5.2 external
//! `ctx`-framing wrappers) from a small parameter tuple. The power-up
//! self-tests are in `cast`.
//!
//! This is the encoding/wiring single source of truth for ML-DSA-44,
//! ML-DSA-65, and ML-DSA-87.
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
//! Per-variant module inputs:
//!
//! | Input | Meaning |
//! |-------|---------|
//! | `svc_keygen`, `svc_expand_key`, `svc_sign`, `svc_verify` | The `Service` each public entry point is gated on |
//! | `rbg_strength_bits` | The RBG security strength key generation requires (FIPS 204 §3.6.1) |
//! | `pct_reason` | The `reason` of a failed pairwise consistency test |
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
//! | `ml_dsa_keygen`, `ml_dsa_keygen_into`, `ml_dsa_sign`, `ml_dsa_sign_into`, `ml_dsa_verify` | private | FIPS 204 §6 internal primitives |
//! | `keygen`, `keygen_with_seed`, `expand_key` | `pub` | Module-gated key generation from an RBG (FIPS 204 Algorithm 1) and expansion of a stored seed (§3.6.3), each with the pairwise consistency test |
//! | `draw_xi`, `expand_checked`, `pairwise_consistency`, `pairwise_consistency_failed` | private | The strength check and draw, and the expansion with the pairwise consistency test (FIPS 140-3 IG 10.3.A) |
//! | `sign`, `verify` | `pub` | Module-gated FIPS 204 §5.2 external API (with `ctx` framing) |
//! | `keygen_internal`, `sign_internal` | `pub` (hidden), `testing-interfaces` only | FIPS 204 §6 mirrors without the operational gate (CAVP testing only) |
//! | `verify_internal` | `pub` (hidden) | FIPS 204 §6 mirror without the operational gate |
//! | `keygen_internal_guarded`, `sign_internal_guarded` | `pub(crate)` | The same behind `require_self_test_started`, for the power-up self-tests, the unit tests and the `*_internal` wrappers |
//!
//! # Architectural note
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
        svc_keygen = $svc_keygen:expr;
        svc_expand_key = $svc_expand_key:expr;
        svc_sign = $svc_sign:expr;
        svc_verify = $svc_verify:expr;
        rbg_strength_bits = $rbg_strength_bits:expr;
        pct_reason = $pct_reason:expr;
    ) => {
        use oxicrypt_module::{Error, SelfTestStarted, Service};
        use oxicrypt_xof::{Shake128, Shake256};
        use $crate::field::reduce32;
        use $crate::params::{D, N, Q, T0_PACKED, T1_PACKED};
        use $crate::poly::Poly;

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
        /// γ₂=(q−1)/32 → high coefficients in `[0,15]` → 4 bits/coeff → 128;
        /// γ₂=(q−1)/88 → high coefficients in `[0,43]` → 6 bits/coeff → 192.
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

        /// `MakeHint` per FIPS 204 Algorithm 39, expressed in
        /// pq-crystals's shortcut form on centered low-bits `a0` and
        /// the corresponding high-bits `a1`.
        ///
        /// `a0` is the centered representative of `LowBits(w) − c·s₂ +
        /// c·t₀`, bounded by `(−2γ₂, 2γ₂)` after the c·t₀ norm check.
        /// `a1` is `w₁ = HighBits(w)` at the same coefficient position.
        ///
        /// Returns 1 iff applying the perturbation `c·t₀` would flip
        /// the high-bits bin, which is `HighBits(r) ≠ HighBits(r + z)`
        /// in Algorithm 39. At `a0 = −γ₂` with `w₁ ≠ 0`, Decompose keeps
        /// `r₀` in `(−γ₂, γ₂]`, so `r₁ = w₁ − 1` and the hint is 1; at
        /// `w₁ = 0` the top-bin wrap (`r⁺ = q − γ₂` maps to `r₁ = 0`)
        /// makes it 0. The explicit fence test gives both answers on the
        /// centered `a0`. Matches pq-crystals/dilithium's `make_hint` in
        /// `rounding.c`.
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
        /// γ₂=(q−1)/32: coefficients in `[0,15]`, 4 bits/coeff,
        /// 128 bytes/poly.
        /// γ₂=(q−1)/88: coefficients in `[0,43]`, 6 bits/coeff,
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

        /// RejNTTPoly: rejection-sample a polynomial in NTT domain
        /// from a SHAKE-128 stream (FIPS 204 §7.3 Algorithm 30).
        fn rej_ntt_poly(xof: &mut Shake128, started: &SelfTestStarted) -> Poly {
            let mut poly = Poly::zero();
            let mut j: usize = 0;
            let mut buf = $crate::Wiped([0u8; 3]);
            while j < N {
                xof.squeeze_with(started, &mut buf.0);
                let t = ((buf.0[0] as u32) | ((buf.0[1] as u32) << 8) | ((buf.0[2] as u32) << 16))
                    & 0x7F_FFFF;
                if t < Q as u32 {
                    poly.coeffs[j] = t as i32;
                    j += 1;
                }
            }
            poly
        }

        /// ExpandA (FIPS 204 §7.3 Algorithm 32): A[i][j] ←
        /// RejNTTPoly(SHAKE-128(ρ ‖ IntegerToBits(j,8) ‖ IntegerToBits(i,8))).
        ///
        /// Sequential build (default, `no_std`): the rows are filled in
        /// order, each cell from its own fresh local XOF.
        #[cfg(all(not(feature = "parallel"), not(feature = "accel-keccak")))]
        fn expand_a(rho: &[u8; 32]) -> Result<[[Poly; L]; K], Error> {
            let started = oxicrypt_module::require_self_test_started_token()?;
            let mut mat: [[Poly; L]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            for i in 0..K {
                for j in 0..L {
                    let mut xof = Shake128::new_internal()?;
                    xof.update(rho);
                    xof.update(&[j as u8, i as u8]);
                    xof.finalize();
                    mat[i][j] = rej_ntt_poly(&mut xof, &started);
                }
            }
            Ok(mat)
        }

        /// ExpandA (FIPS 204 §7.3 Algorithm 32): A[i][j] ←
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
        #[cfg(all(feature = "parallel", not(feature = "accel-keccak")))]
        fn expand_a(rho: &[u8; 32]) -> Result<[[Poly; L]; K], Error> {
            use rayon::iter::{
                IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
            };

            let started = oxicrypt_module::require_self_test_started_token()?;
            let mut mat: [[Poly; L]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            crate::sweep::run(|| {
                (&mut mat[..]).par_iter_mut().enumerate().try_for_each(
                    |(i, row)| -> Result<(), Error> {
                        for j in 0..L {
                            let mut xof = Shake128::new_with(&started);
                            xof.update(rho);
                            xof.update(&[j as u8, i as u8]);
                            xof.finalize();
                            row[j] = rej_ntt_poly(&mut xof, &started);
                        }
                        Ok(())
                    },
                )
            })??;
            Ok(mat)
        }

        /// `RejNTTPoly` batched four cells at a time over the AVX2 4-way
        /// Keccak path (`accel-keccak`). Fills `out[n]` with the matrix
        /// cell sampled from SHAKE-128(ρ ‖ \[j, i\]) for `cells[n] =
        /// (i, j)`, processing four independent cell streams together
        /// through [`oxicrypt_sha::keccak::Sponge4`] and falling back to
        /// the scalar [`rej_ntt_poly`] for a 1–3 cell tail.
        ///
        /// Byte-identical to the scalar build: each lane's SHAKE-128
        /// stream is consumed in the same 3-byte groups under the same
        /// `t < Q` accept rule, so the accepted coefficients — and thus
        /// every Â cell — match the per-cell single-sponge path exactly.
        /// Rejection sampling is probabilistic, so the four lanes are
        /// driven in lockstep and *re-squeezed* (never truncated) until
        /// all four reach `N` accepted coefficients.
        #[cfg(feature = "accel-keccak")]
        fn fill_cells_accel(
            rho: &[u8; 32],
            cells: &[(usize, usize)],
            out: &mut [Poly],
            started: &SelfTestStarted,
        ) {
            use oxicrypt_sha::keccak::Sponge4;

            // SHAKE-128 rate in bytes. It is a multiple of 3, so each
            // squeezed rate block yields exactly 56 complete 3-byte
            // candidate groups — no partial group is ever carried across
            // squeeze rounds, which keeps the lane bookkeeping simple.
            const SHAKE128_RATE: usize = 168;

            let total = cells.len();
            let mut base = 0;
            while base + 4 <= total {
                let mut inputs = [[0u8; 34]; 4];
                for lane in 0..4 {
                    let (i, j) = cells[base + lane];
                    inputs[lane][..32].copy_from_slice(rho);
                    inputs[lane][32] = j as u8;
                    inputs[lane][33] = i as u8;
                }
                let mut sponge = Sponge4::<SHAKE128_RATE>::new_with(started);
                sponge.absorb_4([
                    inputs[0].as_slice(),
                    inputs[1].as_slice(),
                    inputs[2].as_slice(),
                    inputs[3].as_slice(),
                ]);
                sponge.finalize_4(0x1f);

                let mut polys: [Poly; 4] = core::array::from_fn(|_| Poly::zero());
                let mut counts = [0usize; 4];
                let mut rounds = 0usize;
                while counts.iter().any(|&c| c < N) {
                    // One rate block per lane (equal length, as Sponge4
                    // requires). A lane already at N still squeezes to
                    // keep the four states synchronized, but consumes
                    // nothing — its surplus bytes are discarded.
                    let mut bufs = [[0u8; SHAKE128_RATE]; 4];
                    {
                        let [b0, b1, b2, b3] = &mut bufs;
                        sponge.squeeze_4([
                            b0.as_mut_slice(),
                            b1.as_mut_slice(),
                            b2.as_mut_slice(),
                            b3.as_mut_slice(),
                        ]);
                    }
                    for lane in 0..4 {
                        if counts[lane] >= N {
                            continue;
                        }
                        let buf = &bufs[lane];
                        let mut p = 0;
                        while p + 3 <= SHAKE128_RATE && counts[lane] < N {
                            let t = ((buf[p] as u32)
                                | ((buf[p + 1] as u32) << 8)
                                | ((buf[p + 2] as u32) << 16))
                                & 0x7F_FFFF;
                            if t < Q as u32 {
                                polys[lane].coeffs[counts[lane]] = t as i32;
                                counts[lane] += 1;
                            }
                            p += 3;
                        }
                    }
                    rounds += 1;
                    // Safety net only — never a real cap. The loop
                    // terminator is `all lanes reached N`; a lane short of
                    // N always forces another squeeze round, so nothing is
                    // ever truncated. Each round yields 56 candidates per
                    // lane at ~99.9% acceptance (N reached in ~5 rounds),
                    // so 4096 is unreachable in practice.
                    debug_assert!(
                        rounds < 4096,
                        "rej_ntt_poly batched: improbable squeeze-round count",
                    );
                }
                for lane in 0..4 {
                    out[base + lane] = polys[lane].clone();
                }
                base += 4;
            }

            // Tail: the final 1–3 cells when K·L is not a multiple of 4
            // (e.g. ML-DSA-65 with K·L = 30 → a tail of 2), sampled by the
            // scalar single-sponge path.
            while base < total {
                let (i, j) = cells[base];
                let mut xof = Shake128::new_with(started);
                xof.update(rho);
                xof.update(&[j as u8, i as u8]);
                xof.finalize();
                out[base] = rej_ntt_poly(&mut xof, started);
                base += 1;
            }
        }

        /// ExpandA — AVX2 batched build (`accel-keccak`, no `parallel`).
        /// Flattens the K×ℓ matrix row-major, batches the cells four at a
        /// time through [`fill_cells_accel`], and recombines by position.
        /// Each cell is a pure function of ρ and (i, j), so the output is
        /// byte-identical to the scalar build.
        #[cfg(all(feature = "accel-keccak", not(feature = "parallel")))]
        fn expand_a(rho: &[u8; 32]) -> Result<[[Poly; L]; K], Error> {
            let mut cells = [(0usize, 0usize); K * L];
            let mut n = 0;
            for i in 0..K {
                for j in 0..L {
                    cells[n] = (i, j);
                    n += 1;
                }
            }
            let started = oxicrypt_module::require_self_test_started_token()?;
            let mut out: [Poly; K * L] = core::array::from_fn(|_| Poly::zero());
            fill_cells_accel(rho, &cells, &mut out, &started);

            let mut mat: [[Poly; L]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            let mut n = 0;
            for i in 0..K {
                for j in 0..L {
                    mat[i][j] = out[n].clone();
                    n += 1;
                }
            }
            Ok(mat)
        }

        /// ExpandA — AVX2 batched build under `parallel`: the rayon row
        /// loop of the non-accel parallel build, where each row task
        /// batches its own ℓ cells through [`fill_cells_accel`] (a single
        /// 4-group plus a 0/1/3-cell tail). Rows are written into fixed
        /// slots and recombined by position, so the output is
        /// byte-identical regardless of thread count or batching.
        #[cfg(all(feature = "accel-keccak", feature = "parallel"))]
        fn expand_a(rho: &[u8; 32]) -> Result<[[Poly; L]; K], Error> {
            use rayon::iter::{
                IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
            };

            let started = oxicrypt_module::require_self_test_started_token()?;
            let mut mat: [[Poly; L]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            crate::sweep::run(|| {
                (&mut mat[..])
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, row)| {
                        let mut cells = [(0usize, 0usize); L];
                        for j in 0..L {
                            cells[j] = (i, j);
                        }
                        let mut out: [Poly; L] = core::array::from_fn(|_| Poly::zero());
                        fill_cells_accel(rho, &cells, &mut out, &started);
                        for j in 0..L {
                            row[j] = out[j].clone();
                        }
                    });
            })?;
            Ok(mat)
        }

        /// RejBoundedPoly: rejection-sample coefficients in [−η, η]
        /// from SHAKE-256 (FIPS 204 §7.3 Algorithm 31, using CoeffFromHalfByte,
        /// Algorithm 15).
        ///
        /// η=2: half-byte threshold 15; coefficient = 2 − (t mod 5).
        /// η=4: half-byte threshold 9;  coefficient = 4 − t.
        fn rej_bounded_poly(xof: &mut Shake256, started: &SelfTestStarted) -> Poly {
            let mut poly = Poly::zero();
            let mut j: usize = 0;
            let mut buf = $crate::Wiped([0u8; 1]);
            while j < N {
                xof.squeeze_with(started, &mut buf.0);
                let b = buf.0[0];
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

        /// ExpandS (FIPS 204 §7.3 Algorithm 33):
        /// s₁[r] ← RejBoundedPoly(SHAKE-256(σ ‖ r))   for r ∈ [0, ℓ)
        /// s₂[r] ← RejBoundedPoly(SHAKE-256(σ ‖ ℓ+r)) for r ∈ [0, k)
        fn expand_s(sigma: &[u8; 64]) -> Result<(PolyVecL, PolyVecK), Error> {
            let started = oxicrypt_module::require_self_test_started_token()?;
            let mut s1 = PolyVecL::zero();
            let mut s2 = PolyVecK::zero();
            for r in 0..L {
                let mut xof = Shake256::new_internal()?;
                xof.update(sigma);
                xof.update(&[r as u8, (r >> 8) as u8]);
                xof.finalize();
                s1.polys[r] = rej_bounded_poly(&mut xof, &started);
            }
            for r in 0..K {
                let mut xof = Shake256::new_internal()?;
                xof.update(sigma);
                let idx = L + r;
                xof.update(&[idx as u8, (idx >> 8) as u8]);
                xof.finalize();
                s2.polys[r] = rej_bounded_poly(&mut xof, &started);
            }
            Ok((s1, s2))
        }

        /// Sample a single mask polynomial with coefficients in
        /// [−γ₁+1, γ₁] from SHAKE-256(seed ‖ counter).
        ///
        /// γ₁ = 2¹⁹: 20 bits/coeff, 640 bytes XOF output, 10 bytes →
        /// 4 coeffs.
        /// γ₁ = 2¹⁷: 18 bits/coeff, 576 bytes XOF output, 9 bytes →
        /// 4 coeffs.
        fn sample_mask_poly(seed: &[u8; 64], counter: u16) -> Result<Poly, Error> {
            let mut poly = Poly::zero();
            let mut xof = Shake256::new_internal()?;
            xof.update(seed);
            xof.update(&counter.to_le_bytes());
            xof.finalize();

            if GAMMA1 == (1 << 19) {
                let mut wiped = $crate::Wiped([0u8; 640]);
                xof.squeeze(&mut wiped.0)?;
                let buf = &wiped.0;
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
                let mut wiped = $crate::Wiped([0u8; 576]);
                xof.squeeze(&mut wiped.0)?;
                let buf = &wiped.0;
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
            Ok(poly)
        }

        /// ExpandMask (FIPS 204 §7.3 Algorithm 34): y[r] ←
        /// SampleMaskPoly(ρ'', κ + r) for r ∈ [0, ℓ).
        fn expand_mask(seed: &[u8; 64], kappa: u16) -> Result<PolyVecL, Error> {
            let mut y = PolyVecL::zero();
            for r in 0..L {
                y.polys[r] = sample_mask_poly(seed, kappa + r as u16)?;
            }
            Ok(y)
        }

        /// SampleInBall (FIPS 204 §7.3 Algorithm 29).
        fn sample_in_ball(seed: &[u8]) -> Result<Poly, Error> {
            let mut c = Poly::zero();
            let mut xof = Shake256::new_internal()?;
            xof.update(seed);
            xof.finalize();

            let mut sign_bytes = $crate::Wiped([0u8; 8]);
            xof.squeeze(&mut sign_bytes.0)?;
            let mut signs = u64::from_le_bytes(sign_bytes.0);

            for i in (N - TAU)..N {
                let j = {
                    let mut buf = $crate::Wiped([0u8; 1]);
                    loop {
                        xof.squeeze(&mut buf.0)?;
                        let val = buf.0[0] as usize;
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
            Ok(c)
        }

        /// Pack a polynomial with coefficients in [−η, η].
        ///
        /// η=2: 3 bits/coeff (8 coeffs → 3 bytes), 96 bytes/poly.
        /// η=4: 4 bits/coeff (2 coeffs/byte),       128 bytes/poly.
        fn pack_eta(poly: &Poly, buf: &mut [u8]) {
            debug_assert!(buf.len() >= ETA_PACKED);
            if ETA == 2 {
                for i in 0..N / 8 {
                    let mut wiped = $crate::Wiped([0u8; 8]);
                    let t = &mut wiped.0;
                    for j in 0..8 {
                        t[j] = (ETA - poly.coeffs[8 * i + j]) as u8;
                    }
                    buf[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
                    buf[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                    buf[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
                }
            } else {
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
                let mut wiped = $crate::WipedWords([0u32; 8]);
                let t = &mut wiped.0;
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
                    let mut wiped = $crate::WipedWords([0u32; 4]);
                    let t = &mut wiped.0;
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
                for i in 0..N / 4 {
                    let mut wiped = $crate::WipedWords([0u32; 4]);
                    let t = &mut wiped.0;
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

        /// Hint encoding (HintBitPack) — FIPS 204 §7.1 Algorithm 20.
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

        /// ML-DSA.KeyGen_internal (FIPS 204 §6.1 / Algorithm 6) per parameter set.
        ///
        /// Every intermediate this function owns is wiped when it is dropped,
        /// on every return path (ISO/IEC 19790:2012 §7.9.7): byte
        /// buffers through `Wiped` and `wipe::Tagged`, polynomials through
        /// `Poly`'s `Drop`, the sponge through its own. What that does not
        /// reach: a value moved
        /// out of a frame can leave a bitwise copy in the dead frame, scalars
        /// held in registers or spilled are not wiped, and with
        /// `panic = "abort"` no destructor runs on a panic, which ends the
        /// process.
        fn ml_dsa_keygen(xi: &[u8; 32]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
            let mut pk = [0u8; PK_LEN];
            // The private key is assembled in a wiped buffer; the returned
            // array is a copy of it.
            let mut sk = $crate::Wiped([0u8; SK_LEN]);
            ml_dsa_keygen_into(xi, &mut pk, &mut sk.0)?;
            Ok((pk, sk.0))
        }

        fn ml_dsa_keygen_into(
            xi: &[u8; 32],
            pk: &mut [u8; PK_LEN],
            sk: &mut [u8; SK_LEN],
        ) -> Result<(), Error> {
            use $crate::wipe::{Tagged, WipedBuffer, observed};

            let mut h = Shake256::new_internal()?;
            h.update(xi);
            h.update(&[K as u8]);
            h.update(&[L as u8]);
            h.finalize();

            let mut rho = Tagged::<32>::new(WipedBuffer::Rho);
            let mut rho_prime = Tagged::<64>::new(WipedBuffer::RhoPrime);
            let mut key = Tagged::<32>::new(WipedBuffer::Key);
            h.squeeze(&mut rho.bytes)?;
            h.squeeze(&mut rho_prime.bytes)?;
            h.squeeze(&mut key.bytes)?;

            let a_hat = observed(WipedBuffer::KeygenA, expand_a(&rho.bytes)?);
            let (s1, s2) = expand_s(&rho_prime.bytes)?;
            let s1 = observed(WipedBuffer::KeygenS1, s1);
            let s2 = observed(WipedBuffer::KeygenS2, s2);

            let mut s1_hat = observed(WipedBuffer::KeygenS1Hat, s1.clone());
            s1_hat.ntt();

            let mut t = observed(WipedBuffer::KeygenT, PolyVecK::zero());
            matrix_pointwise_mul(&mut t, &a_hat, &s1_hat);
            t.inv_ntt();
            t.add_assign(&s2);
            t.reduce();

            let mut t1 = observed(WipedBuffer::KeygenT1, PolyVecK::zero());
            let mut t0 = observed(WipedBuffer::KeygenT0, PolyVecK::zero());
            polyveck_power2round(&t, &mut t1, &mut t0);

            pack_pk(&rho.bytes, &t1, pk);

            let mut tr = Tagged::<64>::new(WipedBuffer::Tr);
            let mut h_pk = Shake256::new_internal()?;
            h_pk.update(pk);
            h_pk.finalize();
            h_pk.squeeze(&mut tr.bytes)?;

            pack_sk(&rho.bytes, &key.bytes, &tr.bytes, &s1, &s2, &t0, sk);

            Ok(())
        }

        /// ML-DSA.Sign_internal (FIPS 204 §6.2 Algorithm 7).
        ///
        /// `rnd` is Algorithm 7's 32-byte randomizer. 32 zero bytes select the
        /// deterministic variant (FIPS 204 §3.4).
        ///
        /// Every intermediate this function owns is wiped when it is dropped,
        /// on every return path, with the limits `ml_dsa_keygen` states: the
        /// unpacked key (ρ, K, tr, s1, s2, t0 and their NTT forms), μ, ρ″,
        /// each candidate's y, w, c and their products.
        fn ml_dsa_sign(
            sk: &[u8; SK_LEN],
            m_prefix: &[u8],
            message: &[u8],
            rnd: &[u8; 32],
        ) -> Result<Option<[u8; SIG_LEN]>, Error> {
            let mut sig = [0u8; SIG_LEN];
            if ml_dsa_sign_into(sk, m_prefix, message, rnd, &mut sig)? {
                Ok(Some(sig))
            } else {
                Ok(None)
            }
        }

        /// `false`, with `out` zeroized, when the rejection loop is
        /// exhausted.
        fn ml_dsa_sign_into(
            sk: &[u8; SK_LEN],
            m_prefix: &[u8],
            message: &[u8],
            rnd: &[u8; 32],
            out: &mut [u8; SIG_LEN],
        ) -> Result<bool, Error> {
            use $crate::wipe::{Tagged, WipedBuffer as B, observed};

            let mut rho = $crate::Wiped([0u8; 32]);
            let mut key = Tagged::<32>::new(B::SignKey);
            let mut tr = $crate::Wiped([0u8; 64]);
            let mut s1 = observed(B::SignS1, PolyVecL::zero());
            let mut s2 = observed(B::SignS2, PolyVecK::zero());
            let mut t0 = observed(B::SignT0, PolyVecK::zero());
            unpack_sk(
                sk,
                &mut rho.0,
                &mut key.bytes,
                &mut tr.0,
                &mut s1,
                &mut s2,
                &mut t0,
            );

            let a_hat = observed(B::SignA, expand_a(&rho.0)?);

            let mut mu = Tagged::<64>::new(B::SignMu);
            {
                let mut h = Shake256::new_internal()?;
                h.update(&tr.0);
                h.update(m_prefix);
                h.update(message);
                h.finalize();
                h.squeeze(&mut mu.bytes)?;
            }

            let mut rho_pp = Tagged::<64>::new(B::SignRhoPrimePrime);
            {
                let mut h = Shake256::new_internal()?;
                h.update(&key.bytes);
                h.update(rnd);
                h.update(&mu.bytes);
                h.finalize();
                h.squeeze(&mut rho_pp.bytes)?;
            }

            let mut s1_hat = observed(B::SignS1Hat, s1.clone());
            s1_hat.ntt();
            let mut s2_hat = observed(B::SignS2Hat, s2.clone());
            s2_hat.ntt();
            let mut t0_hat = observed(B::SignT0Hat, t0.clone());
            t0_hat.ntt();

            let mut kappa: u16 = 0;
            let max_iters = 1000u16;

            loop {
                if kappa >= max_iters {
                    oxicrypt_zeroize::zeroize(out);
                    return Ok(false);
                }

                let y = observed(B::SignY, expand_mask(&rho_pp.bytes, kappa * L as u16)?);

                let mut y_hat = observed(B::SignYHat, y.clone());
                y_hat.ntt();
                let mut w = observed(B::SignW, PolyVecK::zero());
                matrix_pointwise_mul(&mut w, &a_hat, &y_hat);
                w.inv_ntt();
                w.reduce();

                let mut w1 = observed(B::SignW1, PolyVecK::zero());
                let mut w0 = observed(B::SignW0, PolyVecK::zero());
                polyveck_decompose(&w, &mut w1, &mut w0);

                let mut ctilde = $crate::Wiped([0u8; CTILDE_LEN]);
                {
                    let mut w1_packed = $crate::Wiped([0u8; W1_PACKED_TOTAL]);
                    pack_w1(&w1, &mut w1_packed.0);
                    let mut h = Shake256::new_internal()?;
                    h.update(&mu.bytes);
                    h.update(&w1_packed.0);
                    h.finalize();
                    h.squeeze(&mut ctilde.0)?;
                }

                let c = observed(B::SignC, sample_in_ball(&ctilde.0)?);
                let mut c_hat = observed(B::SignCHat, c.clone());
                c_hat.ntt();

                let mut z = observed(B::SignZ, PolyVecL::zero());
                for i in 0..L {
                    poly_pointwise(&mut z.polys[i], &c_hat, &s1_hat.polys[i]);
                }
                z.inv_ntt();
                z.add_assign(&y);
                z.reduce();

                if z.check_norm(GAMMA1 - BETA) {
                    #[cfg(test)]
                    crate::rejection_counts::record(crate::rejection_counts::Z);
                    kappa += 1;
                    continue;
                }

                let mut cs2 = observed(B::SignCs2, PolyVecK::zero());
                for i in 0..K {
                    poly_pointwise(&mut cs2.polys[i], &c_hat, &s2_hat.polys[i]);
                }
                cs2.inv_ntt();

                let mut r0 = observed(B::SignR0, w0.clone());
                r0.sub_assign(&cs2);
                reduce_polyveck(&mut r0);

                if r0.check_norm(GAMMA2 - BETA) {
                    #[cfg(test)]
                    crate::rejection_counts::record(crate::rejection_counts::R0);
                    kappa += 1;
                    continue;
                }

                let mut ct0 = observed(B::SignCt0, PolyVecK::zero());
                for i in 0..K {
                    poly_pointwise(&mut ct0.polys[i], &c_hat, &t0_hat.polys[i]);
                }
                ct0.inv_ntt();
                ct0.reduce();

                if ct0.check_norm(GAMMA2) {
                    #[cfg(test)]
                    crate::rejection_counts::record(crate::rejection_counts::CT0);
                    kappa += 1;
                    continue;
                }

                // FIPS 204 §6.2 Algorithm 7 step 26:
                //   h = MakeHint(−c·t₀, w − c·s₂ + c·t₀)
                //
                // Computed in pq-crystals/dilithium's centered shortcut form,
                // from a0 = centered(LowBits(w) − c·s₂ + c·t₀) and w₁. The
                // `a0 == −γ₂` fence must give 1 when `w₁ ≠ 0`, as Decompose's
                // `(−γ₂, γ₂]` convention makes Algorithm 39 return; the ACVP
                // regression in `tests/acvts_regressions.rs` exercises it.
                let mut a0 = observed(B::SignA0, r0.clone());
                a0.add_assign(&ct0);
                reduce_polyveck(&mut a0);
                for p in &mut a0.polys {
                    for c_val in &mut p.coeffs {
                        if *c_val > (Q - 1) / 2 {
                            *c_val -= Q;
                        }
                    }
                }

                let mut h_vec = observed(B::SignHint, PolyVecK::zero());
                let hint_count = polyveck_make_hint(&mut h_vec, &a0, &w1);

                if hint_count > OMEGA {
                    #[cfg(test)]
                    crate::rejection_counts::record(crate::rejection_counts::HINT);
                    kappa += 1;
                    continue;
                }

                if !pack_sig(&ctilde.0, &z, &h_vec, out) {
                    kappa += 1;
                    continue;
                }

                return Ok(true);
            }
        }

        /// ML-DSA.Verify_internal (FIPS 204 §6.3 Algorithm 8).
        ///
        /// Every intermediate this function owns (ρ, t1, c̃, z, h, tr, μ, c,
        /// w′, w1′, c̃′ and the packed w1′) is wiped when it is dropped, on
        /// every return path, with the limits `ml_dsa_keygen` states: the
        /// software integrity test runs through here, and
        /// ISO/IEC 19790:2012 §7.5 requires its temporary values zeroised.
        fn ml_dsa_verify(
            pk: &[u8; PK_LEN],
            m_prefix: &[u8],
            message: &[u8],
            sig: &[u8; SIG_LEN],
        ) -> Result<bool, Error> {
            use $crate::wipe::{WipedBuffer as B, observed};

            let mut rho = $crate::Wiped([0u8; 32]);
            let mut t1 = observed(B::VerifyT1, PolyVecK::zero());
            unpack_pk(pk, &mut rho.0, &mut t1);

            let mut ctilde = $crate::Wiped([0u8; CTILDE_LEN]);
            let mut z = observed(B::VerifyZ, PolyVecL::zero());
            let mut h_vec = observed(B::VerifyHint, PolyVecK::zero());
            if !unpack_sig(sig, &mut ctilde.0, &mut z, &mut h_vec) {
                return Ok(false);
            }

            if z.check_norm(GAMMA1 - BETA) {
                return Ok(false);
            }

            let a_hat = observed(B::VerifyA, expand_a(&rho.0)?);

            let mut tr = $crate::Wiped([0u8; 64]);
            {
                let mut h_pk = Shake256::new_internal()?;
                h_pk.update(pk);
                h_pk.finalize();
                h_pk.squeeze(&mut tr.0)?;
            }

            let mut mu = $crate::Wiped([0u8; 64]);
            {
                let mut h_mu = Shake256::new_internal()?;
                h_mu.update(&tr.0);
                h_mu.update(m_prefix);
                h_mu.update(message);
                h_mu.finalize();
                h_mu.squeeze(&mut mu.0)?;
            }

            let c = observed(B::VerifyC, sample_in_ball(&ctilde.0)?);
            let mut c_hat = observed(B::VerifyCHat, c.clone());
            c_hat.ntt();

            let mut z_hat = observed(B::VerifyZHat, z.clone());
            z_hat.ntt();

            let mut w_prime = observed(B::VerifyWPrime, PolyVecK::zero());
            matrix_pointwise_mul(&mut w_prime, &a_hat, &z_hat);

            let mut t1_scaled = observed(B::VerifyT1Scaled, t1.clone());
            for p in &mut t1_scaled.polys {
                for coeff in &mut p.coeffs {
                    *coeff <<= D;
                }
            }
            t1_scaled.ntt();

            let mut ct1 = observed(B::VerifyCt1, PolyVecK::zero());
            for i in 0..K {
                poly_pointwise(&mut ct1.polys[i], &c_hat, &t1_scaled.polys[i]);
            }

            w_prime.sub_assign(&ct1);
            w_prime.inv_ntt();
            w_prime.reduce();

            let mut w1_prime = observed(B::VerifyW1Prime, PolyVecK::zero());
            polyveck_use_hint(&mut w1_prime, &w_prime, &h_vec);

            let mut ctilde_prime = $crate::Wiped([0u8; CTILDE_LEN]);
            {
                let mut w1_packed = $crate::Wiped([0u8; W1_PACKED_TOTAL]);
                pack_w1(&w1_prime, &mut w1_packed.0);
                let mut h_final = Shake256::new_internal()?;
                h_final.update(&mu.0);
                h_final.update(&w1_packed.0);
                h_final.finalize();
                h_final.squeeze(&mut ctilde_prime.0)?;
            }

            Ok(ctilde.0 == ctilde_prime.0)
        }

        /// The RBG security strength key generation requires, in bits
        /// (FIPS 204 §3.6.1: 192 for ML-DSA-65, 256 for ML-DSA-87; for
        /// ML-DSA-44 the module requires 192, so the claim is never reduced
        /// to category 1).
        const RBG_STRENGTH_BITS: u32 = $rbg_strength_bits;

        const PCT_REASON: &str = $pct_reason;

        /// ML-DSA.KeyGen (FIPS 204 §5.1 Algorithm 1): checks the strength of
        /// `rbg`, draws ξ from it, expands the pair and runs the pairwise
        /// consistency test. ξ is wiped before the function returns.
        ///
        /// # Errors
        ///
        /// - [`Error::NotOperational`] unless the module is operational,
        ///   checked again after the pairwise consistency test so that no
        ///   pair is returned once another thread has put the module in its
        ///   error state.
        /// - [`Error::AlgorithmRestricted`] when the active profile does not
        ///   admit this parameter set's key generation.
        /// - [`Error::RbgTooWeak`] when `rbg.strength_bits()` is below the
        ///   requirement (192 bits for ML-DSA-44 and ML-DSA-65, 256 for
        ///   ML-DSA-87), before any draw.
        /// - [`Error::Rbg`] when the draw fails.
        /// - [`Error::ConditionalTestFailed`] when the pairwise consistency
        ///   test fails (FIPS 140-3 IG 10.3.A); the module has entered its
        ///   error state.
        pub fn keygen<R: oxicrypt_module::Rbg>(
            rbg: &mut R,
        ) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_keygen)?;
            let (_xi, pk, sk) = expand_checked(draw_xi(rbg)?)?;
            Ok((pk, sk))
        }

        /// As [`keygen`], and also returns ξ so that the caller can store it
        /// for later expansion with [`expand_key`] (FIPS 204 §3.6.3). ξ
        /// computes the private key and needs the same safeguards.
        ///
        /// # Errors
        ///
        /// As [`keygen`].
        pub fn keygen_with_seed<R: oxicrypt_module::Rbg>(
            rbg: &mut R,
        ) -> Result<
            (
                oxicrypt_zeroize::Zeroizing<[u8; SEED_LEN]>,
                [u8; PK_LEN],
                [u8; SK_LEN],
            ),
            Error,
        > {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_keygen)?;
            let (xi, pk, sk) = expand_checked(draw_xi(rbg)?)?;
            Ok((oxicrypt_zeroize::Zeroizing::new(xi.bytes), pk, sk))
        }

        /// Expands the key pair from a stored seed ξ (FIPS 204 §3.6.3) and
        /// runs the pairwise consistency test, on every call (FIPS 140-3
        /// IG 10.3.A). A seed that did not come from this module's
        /// [`keygen_with_seed`] is a private key imported from outside the
        /// boundary. `xi` is the caller's and is not modified.
        ///
        /// # Errors
        ///
        /// - [`Error::NotOperational`] unless the module is operational.
        /// - [`Error::AlgorithmRestricted`] when the active profile does not
        ///   admit this parameter set's key expansion.
        /// - [`Error::ConditionalTestFailed`] as for [`keygen`].
        pub fn expand_key(xi: &[u8; SEED_LEN]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_expand_key)?;
            let mut copy = $crate::wipe::Tagged::new($crate::wipe::WipedBuffer::Xi);
            copy.bytes = *xi;
            let (_copy, pk, sk) = expand_checked(copy)?;
            Ok((pk, sk))
        }

        /// Checks the strength of `rbg` against [`RBG_STRENGTH_BITS`], then
        /// draws ξ (FIPS 204 Algorithm 1 step 1).
        fn draw_xi<R: oxicrypt_module::Rbg>(
            rbg: &mut R,
        ) -> Result<$crate::wipe::Tagged<SEED_LEN>, Error> {
            if rbg.strength_bits() < RBG_STRENGTH_BITS {
                return Err(Error::RbgTooWeak);
            }
            let mut xi = $crate::wipe::Tagged::new($crate::wipe::WipedBuffer::Xi);
            rbg.fill(&mut xi.bytes).map_err(Error::Rbg)?;
            Ok(xi)
        }

        /// Expands the pair from the module's copy of ξ and runs the pairwise
        /// consistency test before either half is returned; returns ξ with
        /// the pair. The module state is checked again after the test, so a
        /// pair is not returned once another thread has put the module in
        /// its error state.
        fn expand_checked(
            xi: $crate::wipe::Tagged<SEED_LEN>,
        ) -> Result<($crate::wipe::Tagged<SEED_LEN>, [u8; PK_LEN], [u8; SK_LEN]), Error> {
            use $crate::wipe::{Tagged, WipedBuffer};

            let mut pk = Tagged::<PK_LEN>::new(WipedBuffer::PublicKey);
            let mut sk = Tagged::<SK_LEN>::new(WipedBuffer::SecretKey);
            ml_dsa_keygen_into(&xi.bytes, &mut pk.bytes, &mut sk.bytes)?;
            #[cfg(any(test, feature = "fault-injection"))]
            if $crate::seam::take_corrupt_next_pk() {
                pk.bytes[1] ^= 0xFF;
            }
            if !pairwise_consistency(&pk.bytes, &sk.bytes)? {
                return Err(pairwise_consistency_failed(xi, pk, sk));
            }
            oxicrypt_module::require_operational_for_output()?;
            Ok((xi, pk.bytes, sk.bytes))
        }

        /// Wipes ξ and both halves of a pair that failed the pairwise
        /// consistency test, then puts the module in its error state
        /// (FIPS 140-3 IG 10.3.A), and returns the error to report.
        fn pairwise_consistency_failed(
            xi: $crate::wipe::Tagged<SEED_LEN>,
            pk: $crate::wipe::Tagged<PK_LEN>,
            sk: $crate::wipe::Tagged<SK_LEN>,
        ) -> Error {
            drop(xi);
            drop(pk);
            drop(sk);
            oxicrypt_module::enter_error_state(PCT_REASON);
            Error::ConditionalTestFailed { reason: PCT_REASON }
        }

        /// The pairwise consistency test (FIPS 140-3 IG 10.3.A): signs
        /// [`oxicrypt_module::PCT_MESSAGE`] with the empty context and the
        /// deterministic randomizer, then verifies it under `pk`. `false`
        /// when the signature does not verify, or when signing exhausts its
        /// rejection loop.
        fn pairwise_consistency(pk: &[u8; PK_LEN], sk: &[u8; SK_LEN]) -> Result<bool, Error> {
            let prefix = $crate::build_external_prefix(&[])?;
            let mut sig =
                $crate::wipe::Tagged::<SIG_LEN>::new($crate::wipe::WipedBuffer::PctSignature);
            if !ml_dsa_sign_into(
                sk,
                prefix.as_slice(),
                &oxicrypt_module::PCT_MESSAGE,
                &[0u8; 32],
                &mut sig.bytes,
            )? {
                return Ok(false);
            }
            ml_dsa_verify(
                pk,
                prefix.as_slice(),
                &oxicrypt_module::PCT_MESSAGE,
                &sig.bytes,
            )
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
            ml_dsa_sign(sk, prefix_buf.as_slice(), message, &[0u8; 32])?.ok_or(Error::InvalidInput)
        }

        /// Verify a signature (FIPS 204 §5.3 Algorithm 3).
        pub fn verify(
            pk: &[u8; PK_LEN],
            message: &[u8],
            ctx: &[u8],
            sig: &[u8; SIG_LEN],
        ) -> Result<(), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_verify)?;
            let prefix_buf = $crate::build_external_prefix(ctx)?;
            if ml_dsa_verify(pk, prefix_buf.as_slice(), message, sig)? {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            }
        }

        /// Internal keygen — no operational gate (FIPS 204 §6.1).
        ///
        /// Compiled only with the `testing-interfaces` feature: FIPS 204 §6
        /// restricts this interface to CAVP testing.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[cfg(feature = "testing-interfaces")]
        #[doc(hidden)]
        pub fn keygen_internal(xi: &[u8; SEED_LEN]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
            oxicrypt_module::require_self_test_started()?;
            keygen_internal_guarded(xi)
        }

        /// Key generation behind the `require_self_test_started` guard. Called
        /// by the key-generation self-tests (ML-DSA-87, and ML-DSA-44 in its
        /// rejection CAST), the crate's unit tests and `keygen_internal`.
        pub(crate) fn keygen_internal_guarded(
            xi: &[u8; SEED_LEN],
        ) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
            oxicrypt_module::require_self_test_started()?;
            ml_dsa_keygen(xi)
        }

        /// Internal sign — no operational gate, no `ctx` framing
        /// (FIPS 204 §6.2 Algorithm 7).
        ///
        /// Compiled only with the `testing-interfaces` feature: FIPS 204 §6
        /// restricts this interface to CAVP testing.
        ///
        /// `rnd` is Algorithm 7's 32-byte randomizer. 32 zero bytes select the
        /// deterministic variant (FIPS 204 §3.4), which is what [`sign`] uses.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[cfg(feature = "testing-interfaces")]
        #[doc(hidden)]
        pub fn sign_internal(
            sk: &[u8; SK_LEN],
            message: &[u8],
            rnd: &[u8; 32],
        ) -> Result<[u8; SIG_LEN], Error> {
            oxicrypt_module::require_self_test_started()?;
            sign_internal_guarded(sk, message, rnd)
        }

        /// Signing behind the `require_self_test_started` guard. Called by the
        /// signing self-tests (ML-DSA-87 and ML-DSA-44), the crate's unit tests
        /// and `sign_internal`.
        pub(crate) fn sign_internal_guarded(
            sk: &[u8; SK_LEN],
            message: &[u8],
            rnd: &[u8; 32],
        ) -> Result<[u8; SIG_LEN], Error> {
            oxicrypt_module::require_self_test_started()?;
            ml_dsa_sign(sk, &[], message, rnd)?.ok_or(Error::InvalidInput)
        }

        /// Internal verify — no operational gate, no `ctx` framing
        /// (FIPS 204 §6.3 Algorithm 8).
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn verify_internal(
            pk: &[u8; PK_LEN],
            message: &[u8],
            sig: &[u8; SIG_LEN],
        ) -> Result<bool, Error> {
            oxicrypt_module::require_self_test_started()?;
            verify_internal_unguarded(pk, message, sig)
        }

        /// Body of [`verify_internal`], run once its guard has passed.
        fn verify_internal_unguarded(
            pk: &[u8; PK_LEN],
            message: &[u8],
            sig: &[u8; SIG_LEN],
        ) -> Result<bool, Error> {
            ml_dsa_verify(pk, &[], message, sig)
        }

        // The feature-gated `expand_a` must equal an always-sequential
        // reference loop, which never touches the rayon path, cell for cell
        // for a few fixed ρ. The key-generation vectors check `expand_a`
        // only through the whole key pair, and for ML-DSA-44 and ML-DSA-65
        // only through a digest, so this pins `expand_a` itself for every
        // parameter set.
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
                        let mut xof = Shake128::new_internal().unwrap();
                        xof.update(rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        mat[i][j] = rej_ntt_poly(
                            &mut xof,
                            &oxicrypt_module::require_self_test_started_token().unwrap(),
                        );
                    }
                }
                mat
            }

            #[test]
            fn parallel_expand_a_matches_sequential_reference() {
                crate::test_support::start_module();
                for k in 0u8..4 {
                    let mut rho = [0u8; 32];
                    for (idx, b) in rho.iter_mut().enumerate() {
                        *b = k.wrapping_mul(7).wrapping_add(idx as u8).wrapping_add(0x5a);
                    }
                    let par = expand_a(&rho).unwrap();
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

        /// Direct byte-exact oracle for the `accel-keccak` batched
        /// [`expand_a`]: compares it cell-for-cell against an
        /// always-scalar reference (one single SHAKE-128 sponge per
        /// cell, never the batched [`oxicrypt_sha::keccak::Sponge4`]
        /// path) over many random ρ. Generated once per parameter set,
        /// so it covers ML-DSA-44 / -65 / -87 — including the ML-DSA-65
        /// tail-of-2 batching. The reference shares only the scalar
        /// [`rej_ntt_poly`] with the batched sampler, which uses it for the
        /// 1–3 cell tail; the four-lane path is checked against it.
        #[cfg(all(test, feature = "accel-keccak"))]
        mod accel_keccak_determinism {
            use super::*;

            /// Always-scalar reference, independent of the batched path.
            fn expand_a_scalar_reference(rho: &[u8; 32]) -> [[Poly; L]; K] {
                let mut mat: [[Poly; L]; K] =
                    core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
                for i in 0..K {
                    for j in 0..L {
                        let mut xof = Shake128::new_internal().unwrap();
                        xof.update(rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        mat[i][j] = rej_ntt_poly(
                            &mut xof,
                            &oxicrypt_module::require_self_test_started_token().unwrap(),
                        );
                    }
                }
                mat
            }

            #[test]
            fn accel_expand_a_matches_scalar_reference() {
                crate::test_support::start_module();
                for seed in 0u8..16 {
                    let mut rho = [0u8; 32];
                    for (idx, b) in rho.iter_mut().enumerate() {
                        *b = seed
                            .wrapping_mul(31)
                            .wrapping_add(idx as u8)
                            .wrapping_add(0xa5);
                    }
                    let accel = expand_a(&rho).unwrap();
                    let scalar = expand_a_scalar_reference(&rho);
                    for i in 0..K {
                        for j in 0..L {
                            assert_eq!(
                                accel[i][j].coeffs, scalar[i][j].coeffs,
                                "A cell mismatch (accel vs scalar) at seed={seed}, i={i}, j={j}"
                            );
                        }
                    }
                }
            }

            /// Tail-boundary coverage for the batched fill: drives
            /// [`fill_cells_accel`] at cell counts whose remainder mod 4 is
            /// 1, 2, and 3, so the scalar tail and the batched→tail boundary
            /// are exercised at every remainder — not only the tail-of-2 that
            /// ML-DSA-65's K·ℓ = 30 happens to hit (44 and 87 have no tail).
            /// Each output cell must land byte-identical to an independent
            /// per-cell scalar single-sponge reference, which also pins that
            /// the batched groups and the tail write to the correct output
            /// positions (a boundary off-by-one at remainder 1 or 3 would
            /// misplace a cell and fail here).
            #[test]
            fn fill_cells_accel_tail_remainders_match_scalar() {
                const MAX: usize = 7;
                crate::test_support::start_module();
                let mut rho = [0u8; 32];
                for (idx, b) in rho.iter_mut().enumerate() {
                    *b = (idx as u8).wrapping_mul(53).wrapping_add(0x3c);
                }
                // 1 → pure tail (rem 1); 3 → pure tail (rem 3);
                // 5/6/7 → one full batched group then a tail of 1/2/3.
                for &n in &[1usize, 3, 5, 6, 7] {
                    let mut cells = [(0usize, 0usize); MAX];
                    for (k, c) in cells.iter_mut().enumerate().take(n) {
                        *c = (k % K, k % L);
                    }
                    let mut accel: [Poly; MAX] = core::array::from_fn(|_| Poly::zero());
                    fill_cells_accel(
                        &rho,
                        &cells[..n],
                        &mut accel[..n],
                        &oxicrypt_module::require_self_test_started_token().unwrap(),
                    );
                    for k in 0..n {
                        let (i, j) = cells[k];
                        let mut xof = Shake128::new_internal().unwrap();
                        xof.update(&rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        let want = rej_ntt_poly(
                            &mut xof,
                            &oxicrypt_module::require_self_test_started_token().unwrap(),
                        );
                        assert_eq!(
                            accel[k].coeffs,
                            want.coeffs,
                            "tail-boundary mismatch at n={n}, k={k} (rem {})",
                            n % 4
                        );
                    }
                }
            }
        }

        #[cfg(test)]
        mod rbg_services {
            use super::*;
            use oxicrypt_module::{Rbg, RbgError};

            /// An RBG that serves `stream` from its start on every draw, at a
            /// chosen strength, and counts its draws.
            pub(super) struct CountingRbg {
                pub(super) stream: [u8; SEED_LEN],
                pub(super) strength: u32,
                pub(super) draws: usize,
            }

            impl CountingRbg {
                pub(super) fn new(stream: [u8; SEED_LEN], strength: u32) -> Self {
                    Self {
                        stream,
                        strength,
                        draws: 0,
                    }
                }
            }

            impl Rbg for CountingRbg {
                fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
                    self.draws += 1;
                    let Some(source) = self.stream.get(..out.len()) else {
                        return Err(RbgError::RequestTooLong);
                    };
                    out.copy_from_slice(source);
                    Ok(())
                }

                fn strength_bits(&self) -> u32 {
                    self.strength
                }
            }

            /// `keygen` and `keygen_with_seed` draw ξ once, as one 32-byte
            /// request, and return what the internal core gives for that ξ.
            #[test]
            fn with_rbg_matches_internal_core() {
                crate::test_support::start_module();
                let stream = [0x3c; SEED_LEN];
                let expected = keygen_internal_guarded(&stream).unwrap();

                let mut rbg = CountingRbg::new(stream, RBG_STRENGTH_BITS);
                assert_eq!(keygen(&mut rbg).unwrap(), expected);
                assert_eq!(rbg.draws, 1);

                let mut rbg = CountingRbg::new(stream, RBG_STRENGTH_BITS);
                let (xi, pk, sk) = keygen_with_seed(&mut rbg).unwrap();
                assert_eq!((*xi, pk, sk), (stream, expected.0, expected.1));
                assert_eq!(rbg.draws, 1);
            }

            /// `keygen` and `keygen_with_seed` given an RBG of `bits`
            /// strength, and the number of draws the two made.
            pub(super) fn with_strength(
                bits: u32,
            ) -> (Result<(), Error>, Result<(), Error>, usize) {
                crate::test_support::start_module();
                let mut rbg = CountingRbg::new([0x3c; SEED_LEN], bits);
                let plain = keygen(&mut rbg).map(drop);
                let with_seed = keygen_with_seed(&mut rbg).map(drop);
                (plain, with_seed, rbg.draws)
            }

            /// A 128-bit RBG is refused before any draw by every set, and an
            /// uninstantiated DRBG of sufficient strength is refused by its
            /// draw. Each set's exact floor is pinned in its own module.
            #[test]
            fn with_rbg_refuses_weak_or_uninstantiated() {
                crate::test_support::start_module();
                let mut rbg = CountingRbg::new([0x3c; SEED_LEN], 128);
                assert_eq!(keygen(&mut rbg).map(drop), Err(Error::RbgTooWeak));
                assert_eq!(keygen_with_seed(&mut rbg).map(drop), Err(Error::RbgTooWeak));
                assert_eq!(rbg.draws, 0);

                // Uninstantiated, so any draw would fail with
                // `Uninstantiated`: `RbgTooWeak` shows no draw was made.
                let mut aes128 = oxicrypt_drbg::CtrDrbgAes128::new();
                assert_eq!(keygen(&mut aes128).map(drop), Err(Error::RbgTooWeak));
                assert_eq!(
                    keygen_with_seed(&mut aes128).map(drop),
                    Err(Error::RbgTooWeak)
                );

                let mut hmac = oxicrypt_drbg::HmacDrbgSha256::new();
                assert_eq!(
                    keygen(&mut hmac).map(drop),
                    Err(Error::Rbg(RbgError::Uninstantiated))
                );
                assert_eq!(
                    keygen_with_seed(&mut hmac).map(drop),
                    Err(Error::Rbg(RbgError::Uninstantiated))
                );
            }

            /// `expand_key` reproduces the pair `keygen_with_seed` returned
            /// from the seed it returned, and a seed with one byte changed
            /// does not.
            #[test]
            fn keygen_with_seed_round_trips() {
                crate::test_support::start_module();
                let mut rbg = CountingRbg::new([0x96; SEED_LEN], RBG_STRENGTH_BITS);
                let (xi, pk, sk) = keygen_with_seed(&mut rbg).unwrap();
                let seed: [u8; SEED_LEN] = *xi;
                assert_eq!(expand_key(&seed).unwrap(), (pk, sk));
                assert_eq!(
                    seed, [0x96; SEED_LEN],
                    "expand_key modified the caller's seed"
                );

                let mut mutated = seed;
                mutated[0] ^= 0x01;
                let (other_pk, other_sk) = expand_key(&mutated).unwrap();
                assert_ne!(other_pk, pk);
                assert_ne!(other_sk, sk);
            }
        }

        #[cfg(all(test, feature = "fault-injection"))]
        mod wipe_on_exit {
            extern crate std;

            use super::rbg_services::CountingRbg;
            use super::*;
            use oxicrypt_module::{Rbg, RbgError};
            use $crate::seam;
            use $crate::wipe::WipedBuffer::{self, *};

            /// Every buffer a key generation that reaches the pairwise
            /// consistency test holds.
            const KEY_GENERATION: &[WipedBuffer] = &[
                Xi,
                Rho,
                RhoPrime,
                Key,
                Tr,
                PublicKey,
                SecretKey,
                PctSignature,
                KeygenA,
                KeygenS1,
                KeygenS2,
                KeygenS1Hat,
                KeygenT,
                KeygenT1,
                KeygenT0,
                SignS1,
                SignS2,
                SignT0,
                SignA,
                SignS1Hat,
                SignS2Hat,
                SignT0Hat,
                SignY,
                SignYHat,
                SignW,
                SignW1,
                SignW0,
                SignC,
                SignCHat,
                SignZ,
                SignCs2,
                SignR0,
                SignCt0,
                SignA0,
                SignHint,
                VerifyT1,
                VerifyZ,
                VerifyHint,
                VerifyA,
                VerifyC,
                VerifyCHat,
                VerifyZHat,
                VerifyWPrime,
                VerifyT1Scaled,
                VerifyCt1,
                VerifyW1Prime,
                SignKey,
                SignMu,
                SignRhoPrimePrime,
            ];

            /// Set in a child process to `<entry point> <token>`.
            const CHILD: &str = "OXICRYPT_ML_DSA_WIPE_CHILD";

            /// Printed by a child, as a line of its own, once every
            /// assertion passed.
            const DONE: &str = "wipe child done:";

            /// The entry points whose pairwise consistency failure is faulted,
            /// each in a child process of its own.
            const FAULTED: [&str; 3] = ["keygen", "keygen_with_seed", "expand_key"];

            /// The entry point this process faults, when it is a child its
            /// parent started: [`CHILD`] holds the name and a token, and the
            /// token is also one of the process's arguments, so an inherited
            /// [`CHILD`] variable does not make a top-level run a child.
            fn child_entry() -> Option<std::string::String> {
                let value = std::env::var(CHILD).ok()?;
                let (name, token) = value.split_once(' ')?;
                std::env::args()
                    .any(|arg| arg == token)
                    .then(|| std::borrow::ToOwned::to_owned(name))
            }

            /// Runs `command` with both pipes drained, killing it after five
            /// minutes. Returns its success, stdout and stderr.
            fn run_child(
                mut command: std::process::Command,
            ) -> (bool, std::string::String, std::string::String) {
                use std::io::Read;

                let mut child = command
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let drain = |mut pipe: std::boxed::Box<dyn Read + Send>| {
                    std::thread::spawn(move || {
                        let mut bytes = std::vec::Vec::new();
                        pipe.read_to_end(&mut bytes).unwrap();
                        std::string::String::from_utf8_lossy(&bytes).into_owned()
                    })
                };
                let stdout = drain(std::boxed::Box::new(child.stdout.take().unwrap()));
                let stderr = drain(std::boxed::Box::new(child.stderr.take().unwrap()));
                let start = std::time::Instant::now();
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if start.elapsed() > std::time::Duration::from_mins(5) {
                        child.kill().unwrap();
                        panic!("a child did not finish");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                (
                    status.success(),
                    stdout.join().unwrap(),
                    stderr.join().unwrap(),
                )
            }

            struct FailingRbg;

            impl Rbg for FailingRbg {
                fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
                    oxicrypt_zeroize::zeroize(out);
                    Err(RbgError::Busy)
                }

                fn strength_bits(&self) -> u32 {
                    256
                }
            }

            /// Checks that, since the last reset, exactly the buffers in
            /// `held` were constructed, each was wiped as often as it was
            /// constructed and at least once, and every wipe left it zero.
            fn assert_wiped(exit: &str, held: &[WipedBuffer]) {
                for buffer in $crate::wipe::ALL {
                    let made = seam::temporaries(buffer);
                    let wiped = seam::wipes(buffer);
                    if held.contains(&buffer) {
                        assert!(wiped >= 1, "{exit}: {buffer:?} has no recorded wipe");
                        assert_eq!(wiped, made, "{exit}: {buffer:?} wiped {wiped} of {made}");
                    } else {
                        assert_eq!(made, 0, "{exit}: {buffer:?} is not in the list");
                    }
                }
                assert_eq!(seam::unwiped(), 0, "{exit}: a wipe left a nonzero byte");
                seam::reset();
            }

            /// Every identity in `wipe::ALL` that an exit of the
            /// key-generation services constructs is wiped on that exit, and
            /// no other identity is constructed. The exits: a strength
            /// refusal (which holds none) and a failed draw, each through
            /// `keygen` and `keygen_with_seed`; success through each entry
            /// point; and a failed pairwise consistency test through each
            /// entry point, each in a child process of its own because it
            /// puts the module in its error state.
            ///
            /// Limit: not observed are the bitwise copies a by-value move
            /// leaves, the returned `Zeroizing` ξ, the `Wiped` buffers that
            /// hold only values derived from public data (ρ, tr, c̃, packed
            /// w₁), and the `Wiped` and `WipedWords` scratch of the samplers
            /// and packers; not
            /// exercised are the expansion core's error exit, which the
            /// service's own gate excludes, signing exhausting its rejection
            /// loop, and the error exits inside `pairwise_consistency`.
            #[test]
            fn seeds_wiped_on_every_exit() {
                let refused = Err(Error::RbgTooWeak);
                let failed = Err(Error::ConditionalTestFailed { reason: PCT_REASON });

                crate::test_support::start_module();
                if let Some(entry) = child_entry() {
                    seam::reset();
                    seam::corrupt_next_pk();
                    let mut rbg = CountingRbg::new([0x11; SEED_LEN], 256);
                    let outcome = match entry.as_str() {
                        "keygen" => keygen(&mut rbg).map(drop),
                        "keygen_with_seed" => keygen_with_seed(&mut rbg).map(drop),
                        "expand_key" => expand_key(&[0x22; SEED_LEN]).map(drop),
                        other => panic!("no entry point named {other}"),
                    };
                    assert_eq!(outcome, failed);
                    assert!(!oxicrypt_module::is_operational());
                    assert_wiped(&entry, KEY_GENERATION);
                    std::eprintln!("{DONE} {entry}");
                    return;
                }

                seam::reset();
                let mut weak = CountingRbg::new([0x11; SEED_LEN], 128);
                assert_eq!(keygen(&mut weak).map(drop), refused);
                assert_wiped("keygen strength refusal", &[]);
                assert_eq!(keygen_with_seed(&mut weak).map(drop), refused);
                assert_wiped("keygen_with_seed strength refusal", &[]);

                let busy = Err(Error::Rbg(RbgError::Busy));
                assert_eq!(keygen(&mut FailingRbg).map(drop), busy);
                assert_wiped("keygen draw failure", &[Xi]);
                assert_eq!(keygen_with_seed(&mut FailingRbg).map(drop), busy);
                assert_wiped("keygen_with_seed draw failure", &[Xi]);

                let mut rbg = CountingRbg::new([0x11; SEED_LEN], 256);
                keygen(&mut rbg).unwrap();
                assert_wiped("keygen", KEY_GENERATION);
                let (xi, _, _) = keygen_with_seed(&mut rbg).unwrap();
                assert_wiped("keygen_with_seed", KEY_GENERATION);
                drop(xi);
                let seed = [0x22; SEED_LEN];
                expand_key(&seed).unwrap();
                assert_eq!(seed, [0x22; SEED_LEN]);
                assert_wiped("expand_key", KEY_GENERATION);

                let name = module_path!()
                    .split_once("::")
                    .map(|(_, path)| std::format!("{path}::seeds_wiped_on_every_exit"))
                    .unwrap();
                let token = std::format!(
                    "wipe-token-{:016x}",
                    std::hash::BuildHasher::hash_one(
                        &std::collections::hash_map::RandomState::new(),
                        std::process::id()
                    )
                );
                for entry in FAULTED {
                    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                    command
                        .args([
                            name.as_str(),
                            token.as_str(),
                            "--exact",
                            "--nocapture",
                            "--test-threads=1",
                        ])
                        .env(CHILD, std::format!("{entry} {token}"));
                    let (success, stdout, stderr) = run_child(command);
                    let done = std::format!("{DONE} {entry}");
                    assert!(
                        success
                            && stdout
                                .lines()
                                .any(|line| line.starts_with("test result: ok. 1 passed;"))
                            && stderr.lines().any(|line| line == done),
                        "the {entry} child failed:\n{stdout}{stderr}"
                    );
                }
            }
        }

        #[cfg(test)]
        mod randomizer {
            use super::*;

            /// FIPS 204 Algorithm 7 absorbs `rnd` into ρ″, so a non-zero `rnd`
            /// gives a signature other than the deterministic one, and both
            /// verify. Checked on the core and through `sign_internal_guarded`,
            /// so a guarded path that dropped `rnd` fails.
            #[test]
            fn a_nonzero_rnd_changes_the_signature_and_it_verifies() {
                crate::test_support::start_module();
                let (pk, sk) = ml_dsa_keygen(&[0x42u8; 32]).unwrap();
                let msg = b"randomizer test message";
                let zero = ml_dsa_sign(&sk, &[], msg, &[0u8; 32]).unwrap().unwrap();
                let hedged = ml_dsa_sign(&sk, &[], msg, &[0xA5u8; 32]).unwrap().unwrap();
                assert_ne!(hedged, zero, "rnd did not reach the signature");
                assert!(ml_dsa_verify(&pk, &[], msg, &hedged).unwrap());
                assert!(ml_dsa_verify(&pk, &[], msg, &zero).unwrap());
                let guarded_zero = sign_internal_guarded(&sk, msg, &[0u8; 32]).unwrap();
                let guarded_hedged = sign_internal_guarded(&sk, msg, &[0xA5u8; 32]).unwrap();
                assert_eq!(guarded_zero, zero);
                assert_eq!(guarded_hedged, hedged, "the guarded path dropped rnd");
            }
        }
    };
}

pub(crate) use ml_dsa_impl;
