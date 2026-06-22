//! Declarative macro that generates a full ML-KEM parameter-set
//! implementation (K-PKE inner scheme + Fujisaki–Okamoto KEM +
//! gated public wrappers + power-up KAT) from a small parameter
//! tuple.
//!
//! This is the encoding/wiring single source of truth for ML-KEM-512,
//! ML-KEM-768, and ML-KEM-1024. It mirrors the
//! [`define_rsa_wide!`](../../oxicrypt-rsa/src/rsa_wide_impl.rs)
//! pattern used by RSA-3072 / RSA-4096.
//!
//! # Macro inputs
//!
//! Per-variant parameters from FIPS 203 Table 2:
//!
//! | Parameter | Meaning |
//! |-----------|---------|
//! | `k` | Module rank (number of polynomials per vector) |
//! | `eta1` | CBD noise parameter for the secret vector and first error vector |
//! | `eta2` | CBD noise parameter for the second error polynomial |
//! | `du` | Compression parameter for u (ciphertext polynomial vector) |
//! | `dv` | Compression parameter for v (ciphertext polynomial) |
//!
//! Derived constants emitted by the macro:
//!
//! | Constant | Derivation |
//! |----------|-----------|
//! | `EK_LEN` | 384 · k + 32 |
//! | `DK_LEN` | 384 · k + EK_LEN + 64 |
//! | `CT_LEN` | du · k · 32 + dv · 32 |
//! | `POLY_COMPRESSED_DU` | du · 32 |
//! | `POLY_COMPRESSED_DV` | dv · 32 |
//! | `PRF_ETA1_BYTES` | 64 · eta1 |
//! | `PRF_ETA2_BYTES` | 64 · eta2 |
//!
//! # Generated items
//!
//! | Item | Visibility | Purpose |
//! |------|-----------|---------|
//! | `K`, `ETA1`, `ETA2`, `DU`, `DV` | `pub const` | Parameter constants |
//! | `EK_LEN`, `DK_LEN`, `CT_LEN`, `POLY_COMPRESSED_DU`, `POLY_COMPRESSED_DV`, `PRF_ETA1_BYTES`, `PRF_ETA2_BYTES` | `pub const` | Derived size constants |
//! | `SEED_LEN`, `SHARED_SECRET_LEN` | `pub const` | Re-exported common constants |
//! | `PolyVec` | `pub(crate)` | `[Poly; K]` with NTT / inner product |
//! | `PolyMatrix` | `pub(crate)` | `[[Poly; K]; K]` with mul_vec / transpose_mul_vec |
//! | `expand_a` | private | K-dependent matrix expansion from ρ |
//! | `sample_noise_vec` | private | K-component noise sampler |
//! | `kpke_keygen`, `kpke_encrypt`, `kpke_decrypt` | private | FIPS 203 §4.2 |
//! | `ml_kem_keygen`, `ml_kem_encaps`, `ml_kem_decaps` | private | FIPS 203 §4.3 |
//! | `keygen`, `encapsulate`, `decapsulate` | `pub` | Module-gated entry points |
//! | `keygen_internal`, `encaps_internal`, `decaps_internal` | `pub` (hidden) | Gate-free mirrors |
//! | `KATS`, `self_test` | `pub` | Power-up self-test |
//!
//! # Architectural note (CMVP gem)
//!
//! The macro is the **single source of truth for every parameter-set
//! divergence**. There is no parallel hand-written implementation
//! per variant — every byte of the K-PKE inner scheme and the FO
//! transform is generated from one macro body. This makes
//! cross-variant drift mechanically impossible: a bug fix in the
//! macro body fixes all three variants in lock-step, and a new
//! parameter set is a single macro invocation with no source-code
//! duplication. The `EK_LEN`/`DK_LEN`/`CT_LEN` derivation formulas
//! are also evaluated inside the macro, so the per-variant size
//! constants cannot drift from FIPS 203 Table 2 without the
//! parameter inputs themselves drifting.

#![allow(unused_macros)]

macro_rules! ml_kem_impl {
    (
        // Per-variant parameters (FIPS 203 Table 2).
        k = $k:expr;
        eta1 = $eta1:expr;
        eta2 = $eta2:expr;
        du = $du:expr;
        dv = $dv:expr;
        // Service variants.
        svc_keygen = $svc_keygen:expr;
        svc_encaps = $svc_encaps:expr;
        svc_decaps = $svc_decaps:expr;
        // KAT seeds (each variant carries its own deterministic
        // round-trip + implicit-rejection oracle).
        kat_d = $kat_d:expr;
        kat_z = $kat_z:expr;
        kat_m = $kat_m:expr;
        kat_name = $kat_name:expr;
    ) => {
        use oxicrypt_module::{Error, KatEntry, SelfTestFailure, Service};
        use oxicrypt_sha::sha3::{SHA3_256_DIGEST_SIZE, SHA3_512_DIGEST_SIZE, Sha3_256, Sha3_512};
        use oxicrypt_xof::{Shake128, Shake256};
        use $crate::encode::{byte_decode, byte_encode, compress_poly, decompress_poly};
        use $crate::field::{ct_bytes_eq, ct_select_32};
        use $crate::params::POLY_ENCODED_12;
        use $crate::poly::Poly;
        use $crate::sample::{sample_noise, sample_ntt};

        // ── Parameter constants ─────────────────────────────────────────

        /// Module rank (FIPS 203 Table 2).
        pub const K: usize = $k;

        /// CBD noise parameter for secret and first error vector.
        pub const ETA1: usize = $eta1;

        /// CBD noise parameter for second error polynomial.
        pub const ETA2: usize = $eta2;

        /// Compression parameter for u (ciphertext polynomial vector).
        pub const DU: usize = $du;

        /// Compression parameter for v (ciphertext polynomial).
        pub const DV: usize = $dv;

        /// Re-export of the shared seed length constant.
        pub use $crate::params::SEED_LEN;

        /// Re-export of the shared shared-secret length constant.
        pub use $crate::params::SHARED_SECRET_LEN;

        /// Encapsulation (public) key length in bytes: 384 · k + 32.
        pub const EK_LEN: usize = 384 * K + 32;

        /// Decapsulation (private) key length in bytes:
        /// dk_pke (384 · k) + ek + H(ek) (32) + z (32).
        pub const DK_LEN: usize = 384 * K + EK_LEN + 32 + 32;

        /// Ciphertext length in bytes: du · k · 32 + dv · 32.
        pub const CT_LEN: usize = DU * K * 32 + DV * 32;

        /// Byte length of one compressed polynomial at du bits.
        pub const POLY_COMPRESSED_DU: usize = DU * 32;

        /// Byte length of one compressed polynomial at dv bits.
        pub const POLY_COMPRESSED_DV: usize = DV * 32;

        /// PRF output bytes for CBD(η1) sampling: 64 · η1.
        pub const PRF_ETA1_BYTES: usize = 64 * ETA1;

        /// PRF output bytes for CBD(η2) sampling: 64 · η2.
        pub const PRF_ETA2_BYTES: usize = 64 * ETA2;

        // ── PolyVec ─────────────────────────────────────────────────────

        /// A vector of `K` polynomials.
        #[derive(Clone)]
        #[allow(dead_code)]
        pub(crate) struct PolyVec {
            /// The k polynomial components.
            pub(crate) polys: [Poly; K],
        }

        impl PolyVec {
            /// Zero vector.
            pub(crate) fn zero() -> Self {
                Self {
                    polys: core::array::from_fn(|_| Poly::zero()),
                }
            }

            /// Forward NTT on every component.
            pub(crate) fn ntt(&mut self) {
                for i in 0..K {
                    self.polys[i].ntt();
                }
            }

            /// Inverse NTT on every component.
            pub(crate) fn inv_ntt(&mut self) {
                for i in 0..K {
                    self.polys[i].inv_ntt();
                }
            }

            /// Add `other` to `self` component-wise.
            pub(crate) fn add_assign(&mut self, other: &Self) {
                for i in 0..K {
                    self.polys[i].add_assign(&other.polys[i]);
                }
            }

            /// Inner product in NTT domain: ⟨a, b⟩ = Σᵢ aᵢ ◦ bᵢ.
            pub(crate) fn inner_product_ntt(a: &Self, b: &Self) -> Poly {
                let mut r = Poly::zero();
                for i in 0..K {
                    r.pointwise_acc(&a.polys[i], &b.polys[i]);
                }
                r.reduce();
                r
            }
        }

        // ── PolyMatrix ──────────────────────────────────────────────────

        /// A k × k matrix of polynomials (in NTT domain).
        #[allow(dead_code)]
        pub(crate) struct PolyMatrix {
            /// Row-major: `rows[i][j]` is Â[i][j].
            pub(crate) rows: [[Poly; K]; K],
        }

        impl PolyMatrix {
            /// Multiply matrix by column vector: t̂ = Â · ŝ.
            pub(crate) fn mul_vec(&self, s: &PolyVec) -> PolyVec {
                let mut t = PolyVec::zero();
                for i in 0..K {
                    for j in 0..K {
                        t.polys[i].pointwise_acc(&self.rows[i][j], &s.polys[j]);
                    }
                    t.polys[i].reduce();
                }
                t
            }

            /// Multiply transpose of matrix by column vector: û = Âᵀ · r̂.
            pub(crate) fn transpose_mul_vec(&self, r: &PolyVec) -> PolyVec {
                let mut u = PolyVec::zero();
                for i in 0..K {
                    for j in 0..K {
                        u.polys[i].pointwise_acc(&self.rows[j][i], &r.polys[j]);
                    }
                    u.polys[i].reduce();
                }
                u
            }
        }

        // ── K-dependent sampling helpers ────────────────────────────────

        /// Expand the k × k public matrix Â from seed ρ.
        ///
        /// Â[i][j] = SampleNTT(XOF(ρ, j, i)) where XOF = SHAKE-128
        /// and the input is ρ ‖ j ‖ i (column index before row index,
        /// per FIPS 203 Algorithm 12 step 3).
        ///
        /// Sequential build (default, `no_std`): the rows are filled in
        /// order, each cell from its own fresh local XOF.
        #[cfg(not(feature = "parallel"))]
        #[allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]
        fn expand_a(rho: &[u8; SEED_LEN]) -> PolyMatrix {
            let mut rows: [[Poly; K]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            for i in 0..K {
                for j in 0..K {
                    let mut xof = Shake128::new_internal();
                    xof.update(rho);
                    xof.update(&[j as u8, i as u8]);
                    xof.finalize();
                    rows[i][j] = sample_ntt(&mut xof);
                }
            }
            PolyMatrix { rows }
        }

        /// Expand the k × k public matrix Â from seed ρ.
        ///
        /// Â[i][j] = SampleNTT(XOF(ρ, j, i)) where XOF = SHAKE-128
        /// and the input is ρ ‖ j ‖ i (column index before row index,
        /// per FIPS 203 Algorithm 12 step 3).
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
        #[allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]
        fn expand_a(rho: &[u8; SEED_LEN]) -> PolyMatrix {
            use rayon::iter::{
                IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
            };

            let mut rows: [[Poly; K]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            (&mut rows[..])
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, row)| {
                    for j in 0..K {
                        let mut xof = Shake128::new_internal();
                        xof.update(rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        row[j] = sample_ntt(&mut xof);
                    }
                });
            PolyMatrix { rows }
        }

        /// Sample a full noise vector (k polynomials) starting from
        /// counter `nonce`, incrementing after each polynomial.
        ///
        /// Returns the vector and the next nonce value.
        #[allow(clippy::needless_range_loop)]
        fn sample_noise_vec(sigma: &[u8; SEED_LEN], mut nonce: u8, eta: usize) -> (PolyVec, u8) {
            let mut vec = PolyVec::zero();
            for i in 0..K {
                vec.polys[i] = sample_noise(sigma, nonce, eta);
                nonce = nonce.wrapping_add(1);
            }
            (vec, nonce)
        }

        // ── K-PKE (FIPS 203 §4.2, Algorithms 12–14) ─────────────────────

        /// K-PKE.KeyGen (FIPS 203 Algorithm 12).
        ///
        /// - `d`: 32 bytes of randomness (caller-supplied from an
        ///   approved DRBG).
        /// - `ek_pke`: output encryption key (`EK_LEN` bytes).
        /// - `dk_pke`: output decryption key (`384 · k` bytes).
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::needless_range_loop,
            clippy::cast_possible_truncation,
            clippy::similar_names
        )]
        fn kpke_keygen(d: &[u8; SEED_LEN], ek_pke: &mut [u8], dk_pke: &mut [u8]) {
            debug_assert!(ek_pke.len() >= EK_LEN);
            debug_assert!(dk_pke.len() >= 384 * K);

            // 1. (ρ, σ) ← G(d ‖ k)  where G = SHA3-512
            let mut g_input = [0u8; 33];
            g_input[..32].copy_from_slice(d);
            g_input[32] = K as u8;

            let mut g = <Sha3_512>::new_internal();
            g.update(&g_input);
            let g_out: [u8; SHA3_512_DIGEST_SIZE] = g.finalize();

            let mut rho = [0u8; 32];
            let mut sigma = [0u8; 32];
            rho.copy_from_slice(&g_out[..32]);
            sigma.copy_from_slice(&g_out[32..64]);

            // 2. Expand matrix Â from ρ
            let a_hat = expand_a(&rho);

            // 3. Sample secret vector s and error vector e
            let (mut s, nonce) = sample_noise_vec(&sigma, 0, ETA1);
            let (mut e, _nonce) = sample_noise_vec(&sigma, nonce, ETA1);

            // 4. NTT(s), NTT(e)
            s.ntt();
            e.ntt();

            // 5. t̂ = Â ◦ ŝ + ê
            //    mul_vec produces results with an extra R⁻¹ Montgomery
            //    factor from basemul.  Convert back to normal form via
            //    to_mont (multiply by R) before adding ê which is in
            //    normal form.
            let mut t_hat = a_hat.mul_vec(&s);
            for i in 0..K {
                t_hat.polys[i].to_mont();
            }
            t_hat.add_assign(&e);

            // 6. Encode ek_PKE = ByteEncode_12(t̂) ‖ ρ
            for i in 0..K {
                t_hat.polys[i].reduce_full();
                byte_encode(
                    12,
                    &t_hat.polys[i].coeffs,
                    &mut ek_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                );
            }
            ek_pke[K * POLY_ENCODED_12..K * POLY_ENCODED_12 + 32].copy_from_slice(&rho);

            // 7. Encode dk_PKE = ByteEncode_12(ŝ)
            for i in 0..K {
                s.polys[i].reduce_full();
                byte_encode(
                    12,
                    &s.polys[i].coeffs,
                    &mut dk_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                );
            }
        }

        /// K-PKE encryption (FIPS 203 Algorithm 13).
        ///
        /// - `ek_pke`: encryption key (`EK_LEN` bytes).
        /// - `m`: 32-byte message (the shared-secret seed).
        /// - `r_seed`: 32-byte randomness for re-encryption.
        /// - `ct`: output ciphertext (`CT_LEN` bytes).
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::needless_range_loop,
            clippy::cast_possible_truncation,
            clippy::similar_names
        )]
        fn kpke_encrypt(ek_pke: &[u8], m: &[u8; 32], r_seed: &[u8; 32], ct: &mut [u8]) {
            debug_assert!(ek_pke.len() >= EK_LEN);
            debug_assert!(ct.len() >= CT_LEN);

            // 1. Decode t̂ from ek_PKE
            let mut t_hat = PolyVec::zero();
            for i in 0..K {
                byte_decode(
                    12,
                    &ek_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                    &mut t_hat.polys[i].coeffs,
                );
            }

            // 2. Extract ρ from ek_PKE
            let mut rho = [0u8; 32];
            rho.copy_from_slice(&ek_pke[K * POLY_ENCODED_12..K * POLY_ENCODED_12 + 32]);

            // 3. Expand Â from ρ
            let a_hat = expand_a(&rho);

            // 4. Sample r, e₁, e₂
            let (mut r_vec, nonce) = sample_noise_vec(r_seed, 0, ETA1);
            let (e1, nonce) = sample_noise_vec(r_seed, nonce, ETA2);
            let e2 = sample_noise(r_seed, nonce, ETA2);

            // 5. NTT(r)
            r_vec.ntt();

            // 6. u = NTT⁻¹(Âᵀ ◦ r̂) + e₁
            let mut u = a_hat.transpose_mul_vec(&r_vec);
            u.inv_ntt();
            u.add_assign(&e1);

            // 7. v = NTT⁻¹(t̂ᵀ ◦ r̂) + e₂ + Decompress₁(Decode₁(m))
            let mut v = PolyVec::inner_product_ntt(&t_hat, &r_vec);
            v.inv_ntt();
            v.add_assign(&e2);

            // Decode message and add Decompress_1(m)
            let mut m_poly = Poly::zero();
            byte_decode(1, m, &mut m_poly.coeffs);
            decompress_poly(1, &mut m_poly.coeffs);
            v.add_assign(&m_poly);

            // 8. Compress and encode ciphertext
            // c₁ = ByteEncode_{dᵤ}(Compress_{dᵤ}(u))
            for i in 0..K {
                u.polys[i].reduce_full();
                compress_poly(DU as u32, &mut u.polys[i].coeffs);
                byte_encode(
                    DU,
                    &u.polys[i].coeffs,
                    &mut ct[i * POLY_COMPRESSED_DU..(i + 1) * POLY_COMPRESSED_DU],
                );
            }

            // c₂ = ByteEncode_{dᵥ}(Compress_{dᵥ}(v))
            v.reduce_full();
            compress_poly(DV as u32, &mut v.coeffs);
            byte_encode(
                DV,
                &v.coeffs,
                &mut ct[K * POLY_COMPRESSED_DU..K * POLY_COMPRESSED_DU + POLY_COMPRESSED_DV],
            );
        }

        /// K-PKE decryption (FIPS 203 Algorithm 14).
        ///
        /// - `dk_pke`: decryption key (`384 · k` bytes).
        /// - `ct`: ciphertext (`CT_LEN` bytes).
        /// - `m`: output 32-byte message.
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::needless_range_loop,
            clippy::cast_possible_truncation,
            clippy::similar_names
        )]
        fn kpke_decrypt(dk_pke: &[u8], ct: &[u8], m: &mut [u8; 32]) {
            debug_assert!(dk_pke.len() >= 384 * K);
            debug_assert!(ct.len() >= CT_LEN);

            // 1. Decode u from ciphertext
            let mut u = PolyVec::zero();
            for i in 0..K {
                byte_decode(
                    DU,
                    &ct[i * POLY_COMPRESSED_DU..(i + 1) * POLY_COMPRESSED_DU],
                    &mut u.polys[i].coeffs,
                );
                decompress_poly(DU as u32, &mut u.polys[i].coeffs);
            }

            // 2. Decode v from ciphertext
            let mut v = Poly::zero();
            byte_decode(
                DV,
                &ct[K * POLY_COMPRESSED_DU..K * POLY_COMPRESSED_DU + POLY_COMPRESSED_DV],
                &mut v.coeffs,
            );
            decompress_poly(DV as u32, &mut v.coeffs);

            // 3. Decode ŝ from dk_PKE
            let mut s_hat = PolyVec::zero();
            for i in 0..K {
                byte_decode(
                    12,
                    &dk_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                    &mut s_hat.polys[i].coeffs,
                );
            }

            // 4. NTT(u)
            u.ntt();

            // 5. w = v − NTT⁻¹(ŝᵀ ◦ NTT(u))
            let mut w = PolyVec::inner_product_ntt(&s_hat, &u);
            w.inv_ntt();
            v.sub_assign(&w);

            // 6. m = ByteEncode₁(Compress₁(w))
            v.reduce_full();
            compress_poly(1, &mut v.coeffs);
            byte_encode(1, &v.coeffs, m);
        }

        // ── ML-KEM (FIPS 203 §4.3, Algorithms 15–17) ────────────────────

        /// ML-KEM.KeyGen (FIPS 203 Algorithm 15).
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::needless_range_loop,
            clippy::similar_names
        )]
        fn ml_kem_keygen(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
            ek: &mut [u8; EK_LEN],
            dk: &mut [u8; DK_LEN],
        ) {
            // 1. Run K-PKE.KeyGen to get (ek_PKE, dk_PKE)
            let dk_pke_len = 384 * K;
            kpke_keygen(d, ek, &mut dk[..dk_pke_len]);

            // 2. dk = dk_PKE ‖ ek ‖ H(ek) ‖ z
            dk[dk_pke_len..dk_pke_len + EK_LEN].copy_from_slice(ek);

            let mut h = <Sha3_256>::new_internal();
            h.update(ek);
            let h_ek: [u8; SHA3_256_DIGEST_SIZE] = h.finalize();
            dk[dk_pke_len + EK_LEN..dk_pke_len + EK_LEN + 32].copy_from_slice(&h_ek);

            dk[dk_pke_len + EK_LEN + 32..dk_pke_len + EK_LEN + 64].copy_from_slice(z);
        }

        /// ML-KEM.Encaps (FIPS 203 Algorithm 16).
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::similar_names,
            clippy::many_single_char_names
        )]
        fn ml_kem_encaps(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
        ) -> ([u8; SHARED_SECRET_LEN], [u8; CT_LEN]) {
            // 1. (K, r) ← G(m ‖ H(ek))
            let mut h = <Sha3_256>::new_internal();
            h.update(ek);
            let h_ek: [u8; SHA3_256_DIGEST_SIZE] = h.finalize();

            let mut g = <Sha3_512>::new_internal();
            g.update(m);
            g.update(&h_ek);
            let mut g_out: [u8; SHA3_512_DIGEST_SIZE] = g.finalize();

            let mut k = [0u8; 32];
            let mut r = [0u8; 32];
            k.copy_from_slice(&g_out[..32]);
            r.copy_from_slice(&g_out[32..64]);

            // 2. c ← K-PKE.Encrypt(ek, m, r)
            let mut ct = [0u8; CT_LEN];
            kpke_encrypt(ek, m, &r, &mut ct);

            // Phase 2 zeroize: `k` and `r` are CSPs derived from the
            // FO-transform's `G(m ‖ H(ek))` expansion. `k` is the
            // returned shared secret (the bitwise copy into the
            // returned tuple stays — the stack slot is what we
            // zeroize); `r` is the per-encapsulation re-encryption
            // randomness and must not outlive the function. `g_out`
            // is the concatenation `K ‖ r` and is zeroized alongside.
            // See FIPS 140-3 IG 7.7 / SP 800-140B §7.9.
            let result = (k, ct);
            oxicrypt_zeroize::zeroize(&mut k);
            oxicrypt_zeroize::zeroize(&mut r);
            oxicrypt_zeroize::zeroize(&mut g_out);
            result
        }

        /// ML-KEM.Decaps (FIPS 203 Algorithm 17).
        ///
        /// **Implicit rejection**: if the ciphertext is invalid, a
        /// pseudorandom key derived from the rejection seed `z` is
        /// returned (constant-time, no observable difference).
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::similar_names,
            clippy::many_single_char_names
        )]
        fn ml_kem_decaps(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> [u8; SHARED_SECRET_LEN] {
            let dk_pke_len = 384 * K;

            // Parse dk = dk_PKE ‖ ek ‖ H(ek) ‖ z
            let dk_pke = &dk[..dk_pke_len];
            let ek = &dk[dk_pke_len..dk_pke_len + EK_LEN];
            let h_ek = &dk[dk_pke_len + EK_LEN..dk_pke_len + EK_LEN + 32];
            let z = &dk[dk_pke_len + EK_LEN + 32..dk_pke_len + EK_LEN + 64];

            // 1. m' ← K-PKE.Decrypt(dk_PKE, c)
            let mut m_prime = [0u8; 32];
            kpke_decrypt(dk_pke, ct, &mut m_prime);

            // 2. (K', r') ← G(m' ‖ H(ek))
            let mut g = <Sha3_512>::new_internal();
            g.update(&m_prime);
            g.update(h_ek);
            let mut g_out: [u8; SHA3_512_DIGEST_SIZE] = g.finalize();

            let mut k_prime = [0u8; 32];
            let mut r_prime = [0u8; 32];
            k_prime.copy_from_slice(&g_out[..32]);
            r_prime.copy_from_slice(&g_out[32..64]);

            // 3. K̄ ← J(z ‖ c) where J = SHAKE-256, first 32 bytes
            let mut j = Shake256::new_internal();
            j.update(z);
            j.update(ct);
            j.finalize();
            let mut k_bar = [0u8; 32];
            j.squeeze(&mut k_bar);

            // 4. c' ← K-PKE.Encrypt(ek, m', r')
            let mut ct_prime = [0u8; CT_LEN];
            kpke_encrypt(ek, &m_prime, &r_prime, &mut ct_prime);

            // 5. Constant-time comparison: if c == c', return K'; else K̄
            //
            // `ct_select_32` reads `k_prime` and `k_bar` through `&[u8; 32]`
            // and constructs a new owned `[u8; 32]` — the input stack
            // slots are untouched by the call, so we can zeroize them
            // immediately afterward without disturbing the byte-exact
            // FIPS 203 §7.3 output that `implicit_rejection_matches_j_z_c`
            // pins against `J(z ‖ c)`.
            let diff = ct_bytes_eq(ct, &ct_prime);
            let result = ct_select_32(&k_prime, &k_bar, diff);

            // Phase 2 zeroize: every FO-transform intermediate that
            // carries shared-secret-derivable or candidate-shared-secret
            // material is wiped on exit (FIPS 140-3 IG 7.7 / SP 800-140B
            // §7.9):
            //   `m_prime` — re-encryption-input random (decrypted K-PKE
            //               output; secret-key-derived).
            //   `k_prime` — candidate shared secret in the success branch.
            //   `k_bar`   — implicit-rejection fallback shared secret.
            //   `r_prime` — re-encryption randomness (CSP-derived).
            //   `g_out`   — full 64-byte `G(m' ‖ H(ek))` expansion
            //               (concatenation of `K' ‖ r'`).
            //   `ct_prime`— recomputed ciphertext; not a CSP on its own,
            //               but its byte-equality with `ct` is the
            //               implicit-rejection oracle, and the bytes
            //               are derived from `m'` and `r'`.
            // Order of zeroize calls is immaterial — none alias and none
            // are reachable after `result` is constructed.
            oxicrypt_zeroize::zeroize(&mut m_prime);
            oxicrypt_zeroize::zeroize(&mut k_prime);
            oxicrypt_zeroize::zeroize(&mut k_bar);
            oxicrypt_zeroize::zeroize(&mut r_prime);
            oxicrypt_zeroize::zeroize(&mut g_out);
            oxicrypt_zeroize::zeroize(&mut ct_prime);
            result
        }

        // ── Public API (gated) ──────────────────────────────────────────

        /// Generate an ML-KEM key pair.
        ///
        /// Both `d` and `z` must be 32 bytes of fresh randomness from
        /// an approved DRBG (SP 800-90A).
        ///
        /// Returns `(ek, dk)`: the encapsulation key and decapsulation
        /// key.
        pub fn keygen(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
        ) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_keygen)?;
            keygen_internal(d, z).ok_or(Error::InvalidInput)
        }

        /// Encapsulate a shared secret against an encapsulation key.
        ///
        /// `m` must be 32 bytes of fresh randomness from an approved
        /// DRBG. Returns `(shared_secret, ciphertext)`.
        pub fn encapsulate(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
        ) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_encaps)?;
            Ok(encaps_internal(ek, m))
        }

        /// Decapsulate a shared secret from a ciphertext.
        ///
        /// Uses implicit rejection: if the ciphertext is invalid, a
        /// pseudorandom key is returned (constant-time, no observable
        /// difference).
        pub fn decapsulate(
            dk: &[u8; DK_LEN],
            ct: &[u8; CT_LEN],
        ) -> Result<[u8; SHARED_SECRET_LEN], Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_decaps)?;
            Ok(decaps_internal(dk, ct))
        }

        // ── Internal API (gate-free, for KATs and ACVP) ─────────────────

        /// Internal keygen — no module gate.
        #[doc(hidden)]
        pub fn keygen_internal(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
        ) -> Option<([u8; EK_LEN], [u8; DK_LEN])> {
            let mut ek = [0u8; EK_LEN];
            let mut dk = [0u8; DK_LEN];
            ml_kem_keygen(d, z, &mut ek, &mut dk);
            Some((ek, dk))
        }

        /// Internal encaps — no module gate.
        #[doc(hidden)]
        pub fn encaps_internal(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
        ) -> ([u8; SHARED_SECRET_LEN], [u8; CT_LEN]) {
            ml_kem_encaps(ek, m)
        }

        /// Internal decaps — no module gate.
        #[doc(hidden)]
        pub fn decaps_internal(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> [u8; SHARED_SECRET_LEN] {
            ml_kem_decaps(dk, ct)
        }

        // ── Power-up KATs ───────────────────────────────────────────────

        /// Deterministic KAT seed for keygen.
        const KAT_D: [u8; 32] = $kat_d;

        /// Deterministic KAT seed for implicit-rejection randomness z.
        const KAT_Z_SEED: [u8; 32] = $kat_z;

        /// Deterministic KAT seed for encapsulation.
        const KAT_M: [u8; 32] = $kat_m;

        /// Self-test: deterministic round-trip + negative (tamper) test.
        ///
        /// 1. KeyGen from fixed (d, z).
        /// 2. Encaps with fixed m → (K, c).
        /// 3. Decaps(dk, c) → K'.
        /// 4. Verify K == K' (positive test).
        /// 5. Tamper c, Decaps(dk, c_bad) → K''.
        /// 6. Verify K'' ≠ K (implicit rejection test).
        pub fn self_test() -> Result<(), SelfTestFailure> {
            // 1. KeyGen
            let Some((ek, dk)) = keygen_internal(&KAT_D, &KAT_Z_SEED) else {
                return Err(SelfTestFailure);
            };

            // 2. Encaps
            let (k, ct) = encaps_internal(&ek, &KAT_M);

            // 3. Decaps (positive)
            let k_prime = decaps_internal(&dk, &ct);

            // 4. K == K'
            if k != k_prime {
                return Err(SelfTestFailure);
            }

            // 5. Tamper ciphertext and decaps (negative — implicit rejection)
            let mut ct_bad = ct;
            ct_bad[0] ^= 0x01;
            let k_bad = decaps_internal(&dk, &ct_bad);

            // 6. K'' must differ from K (with overwhelming probability)
            if k_bad == k {
                return Err(SelfTestFailure);
            }

            Ok(())
        }

        /// Single power-up KAT entry for this parameter set.
        ///
        /// Aggregated into the crate-level [`KATS`](crate::KATS) slice
        /// by-value, avoiding the `indexing_slicing` clippy lint that
        /// fires on `slice[0]` even inside `const` blocks.
        pub const KAT_ENTRY: KatEntry = KatEntry {
            name: $kat_name,
            run: self_test,
        };

        /// Power-up KATs for this parameter set (single entry: round-trip
        /// + implicit-rejection).
        pub const KATS: &[KatEntry] = &[KAT_ENTRY];

        // Make `K`, `Q_U16`, `N`, `Poly`, `sample_*`, `Shake128`,
        // `Shake256`, etc. addressable from the unit-test module
        // without leaking them in public API.
        #[allow(dead_code)]
        const _ASSERT_K_GT_0: usize = K - 1;

        // ── Determinism oracle (parallel feature only) ──────────────
        //
        // Oracle choice: `expand_a` is reachable in-crate (the per-variant
        // unit-test module reaches the macro-internal items via
        // `use super::*`), so we add a direct equality oracle rather than
        // relying only on the keygen-KAT-on/off check. We rebuild the
        // matrix with an always-sequential reference loop (which never
        // touches the rayon path) and assert it equals the feature-gated
        // `expand_a` cell-for-cell, for a few deterministic ρ values. The
        // keygen KATs (fixed ρ → fixed Â → fixed ek/dk) remain the
        // end-to-end oracle; this test pins `expand_a` itself.
        #[cfg(all(test, feature = "parallel"))]
        #[allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]
        mod parallel_determinism {
            use super::*;

            /// Always-sequential reference: identical to the non-parallel
            /// `expand_a` body, never invoking the rayon path.
            fn expand_a_sequential_reference(rho: &[u8; SEED_LEN]) -> PolyMatrix {
                let mut rows: [[Poly; K]; K] =
                    core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
                for i in 0..K {
                    for j in 0..K {
                        let mut xof = Shake128::new_internal();
                        xof.update(rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        rows[i][j] = sample_ntt(&mut xof);
                    }
                }
                PolyMatrix { rows }
            }

            #[test]
            fn parallel_expand_a_matches_sequential_reference() {
                for k in 0u8..4 {
                    let mut rho = [0u8; SEED_LEN];
                    for (idx, b) in rho.iter_mut().enumerate() {
                        *b = k.wrapping_mul(7).wrapping_add(idx as u8).wrapping_add(0x5a);
                    }
                    let par = expand_a(&rho);
                    let seq = expand_a_sequential_reference(&rho);
                    for i in 0..K {
                        for j in 0..K {
                            assert_eq!(
                                par.rows[i][j].coeffs, seq.rows[i][j].coeffs,
                                "Â cell mismatch at seed k={k}, i={i}, j={j}"
                            );
                        }
                    }
                }
            }
        }
    };
}

pub(crate) use ml_kem_impl;
