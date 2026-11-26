//! Declarative macro that generates a full ML-KEM parameter-set
//! implementation (K-PKE inner scheme + Fujisaki–Okamoto KEM +
//! gated public wrappers) from a small parameter tuple. The power-up
//! self-tests are in `cast`.
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
//! Per-variant module inputs:
//!
//! | Input | Meaning |
//! |-------|---------|
//! | `svc_keygen`, `svc_expand_key`, `svc_encaps`, `svc_decaps` | The `Service` each public entry point is gated on |
//! | `rbg_strength_bits` | The RBG security strength key generation and encapsulation require (FIPS 203 §3.3) |
//! | `pct_reason` | The `reason` of a failed pairwise consistency test |
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
//! | `kpke_keygen`, `kpke_encrypt`, `kpke_decrypt` | private | FIPS 203 §5 |
//! | `ml_kem_keygen`, `ml_kem_encaps`, `ml_kem_encaps_into`, `ml_kem_decaps`, `ml_kem_decaps_into` | private | FIPS 203 §6 |
//! | `keygen`, `keygen_with_seed`, `expand_key` | `pub` | Module-gated key generation from an RBG (FIPS 203 Algorithm 19) and expansion of a stored seed, each with the pairwise consistency test |
//! | `encapsulate`, `decapsulate` | `pub` | Module-gated encapsulation from an RBG (Algorithm 20) and decapsulation (Algorithm 21) |
//! | `draw_d_z`, `draw_m`, `expand_checked`, `pairwise_consistency` | private | The strength checks and draws, and the expansion with the pairwise consistency test (FIPS 140-3 IG 10.3.A) |
//! | `keygen_internal`, `encaps_internal`, `decaps_internal` | `pub` (hidden), `testing-interfaces` only | Mirrors without the operational gate (FIPS 203 §3.3: CAVP testing only) |
//! | `keygen_internal_guarded`, `encaps_internal_guarded`, `decaps_internal_guarded` | `pub(crate)` | The same behind `require_self_test_started`, for the power-up self-tests, the unit tests and the `*_internal` wrappers |
//! | `keygen_internal_unguarded`, `encaps_internal_unguarded`, `decaps_internal_unguarded` | private | The shared bodies |

#![allow(unused_macros)]

macro_rules! ml_kem_impl {
    (
        // Per-variant parameters (FIPS 203 Table 2).
        k = $k:expr;
        eta1 = $eta1:expr;
        eta2 = $eta2:expr;
        du = $du:expr;
        dv = $dv:expr;
        // Per-variant module inputs: the services that gate the public
        // entry points, the RBG strength (FIPS 203 §3.3) and the reason a
        // failed pairwise consistency test reports.
        svc_keygen = $svc_keygen:expr;
        svc_expand_key = $svc_expand_key:expr;
        svc_encaps = $svc_encaps:expr;
        svc_decaps = $svc_decaps:expr;
        rbg_strength_bits = $rbg_strength_bits:expr;
        pct_reason = $pct_reason:expr;
    ) => {
        use oxicrypt_module::{Error, Service};
        use oxicrypt_sha::sha3::{SHA3_256_DIGEST_SIZE, SHA3_512_DIGEST_SIZE, Sha3_256, Sha3_512};
        use oxicrypt_xof::{Shake128, Shake256};
        use $crate::encode::{byte_decode, byte_encode, compress_poly, decompress_poly};
        use $crate::field::{ct_bytes_eq, ct_select_32};
        use $crate::params::POLY_ENCODED_12;
        use $crate::poly::Poly;
        use $crate::sample::{sample_noise, sample_ntt};
        use $crate::wipe::{Tagged, WipedBuffer, observed};

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

        #[derive(Clone)]
        #[allow(dead_code)]
        pub(crate) struct PolyVec {
            pub(crate) polys: [Poly; K],
        }

        impl PolyVec {
            pub(crate) fn zero() -> Self {
                Self {
                    polys: core::array::from_fn(|_| Poly::zero()),
                }
            }

            pub(crate) fn ntt(&mut self) {
                for i in 0..K {
                    self.polys[i].ntt();
                }
            }

            pub(crate) fn inv_ntt(&mut self) {
                for i in 0..K {
                    self.polys[i].inv_ntt();
                }
            }

            pub(crate) fn add_assign(&mut self, other: &Self) {
                for i in 0..K {
                    self.polys[i].add_assign(&other.polys[i]);
                }
            }

            pub(crate) fn inner_product_ntt(a: &Self, b: &Self) -> Poly {
                let mut r = Poly::zero();
                for i in 0..K {
                    r.pointwise_acc(&a.polys[i], &b.polys[i]);
                }
                r.reduce();
                r
            }
        }

        #[allow(dead_code)]
        pub(crate) struct PolyMatrix {
            pub(crate) rows: [[Poly; K]; K],
        }

        impl PolyMatrix {
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

        /// Â[i][j] = SampleNTT(ρ ‖ j ‖ i), column index before row index
        /// (FIPS 203 Algorithm 13 step 5).
        #[cfg(not(feature = "parallel"))]
        #[allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]
        fn expand_a(rho: &[u8; SEED_LEN]) -> Result<PolyMatrix, Error> {
            let started = oxicrypt_module::require_self_test_started_token()?;
            let mut rows: [[Poly; K]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            for i in 0..K {
                for j in 0..K {
                    let mut xof = Shake128::new_internal()?;
                    xof.update(rho);
                    xof.update(&[j as u8, i as u8]);
                    xof.finalize();
                    rows[i][j] = sample_ntt(&mut xof, &started);
                }
            }
            Ok(PolyMatrix { rows })
        }

        /// Â[i][j] = SampleNTT(ρ ‖ j ‖ i), column index before row index
        /// (FIPS 203 Algorithm 13 step 5).
        ///
        /// Each closure owns exactly its row `i` and samples every cell
        /// from a fresh local XOF that is a pure function of ρ and
        /// `(i, j)`, and each row is written into its fixed slot, so the
        /// matrix is byte-identical to the sequential build whatever the
        /// thread count.
        #[cfg(feature = "parallel")]
        #[allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]
        fn expand_a(rho: &[u8; SEED_LEN]) -> Result<PolyMatrix, Error> {
            use rayon::iter::{
                IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
            };

            let started = oxicrypt_module::require_self_test_started_token()?;
            let mut rows: [[Poly; K]; K] =
                core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
            crate::sweep::run(|| {
                (&mut rows[..]).par_iter_mut().enumerate().try_for_each(
                    |(i, row)| -> Result<(), Error> {
                        for j in 0..K {
                            let mut xof = Shake128::new_with(&started);
                            xof.update(rho);
                            xof.update(&[j as u8, i as u8]);
                            xof.finalize();
                            row[j] = sample_ntt(&mut xof, &started);
                        }
                        Ok(())
                    },
                )
            })??;
            Ok(PolyMatrix { rows })
        }

        /// K noise polynomials from PRF(σ, N) for N = `nonce`,
        /// `nonce` + 1, …, and the next N (FIPS 203 Algorithm 13 steps
        /// 8–15, Algorithm 14 steps 9–16).
        #[allow(clippy::needless_range_loop)]
        fn sample_noise_vec(
            sigma: &[u8; SEED_LEN],
            mut nonce: u8,
            eta: usize,
        ) -> Result<(PolyVec, u8), Error> {
            let mut vec = PolyVec::zero();
            for i in 0..K {
                vec.polys[i] = sample_noise(sigma, nonce, eta)?;
                nonce = nonce.wrapping_add(1);
            }
            Ok((vec, nonce))
        }

        /// K-PKE.KeyGen (FIPS 203 Algorithm 13), writing `ek_PKE` into the
        /// first `EK_LEN` bytes of `ek_pke` and `dk_PKE` into the first
        /// 384 · k bytes of `dk_pke`.
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::needless_range_loop,
            clippy::cast_possible_truncation,
            clippy::similar_names
        )]
        fn kpke_keygen(
            d: &[u8; SEED_LEN],
            ek_pke: &mut [u8],
            dk_pke: &mut [u8],
        ) -> Result<(), Error> {
            debug_assert!(ek_pke.len() >= EK_LEN);
            debug_assert!(dk_pke.len() >= 384 * K);

            // Step 1: (ρ, σ) ← G(d ‖ k), G = SHA3-512.
            let mut g_input = Tagged::<33>::new(WipedBuffer::KeygenGInput);
            g_input.bytes[..32].copy_from_slice(d);
            g_input.bytes[32] = K as u8;

            let mut g = <Sha3_512>::new_internal()?;
            g.update(&g_input.bytes);
            let mut g_out = Tagged::<SHA3_512_DIGEST_SIZE>::new(WipedBuffer::KeygenG);
            g_out.bytes = g.finalize()?;

            let mut rho = Tagged::<32>::new(WipedBuffer::KeygenRho);
            let mut sigma = Tagged::<32>::new(WipedBuffer::KeygenSigma);
            rho.bytes.copy_from_slice(&g_out.bytes[..32]);
            sigma.bytes.copy_from_slice(&g_out.bytes[32..64]);

            // Steps 3–7.
            let a_hat = observed(WipedBuffer::KeygenA, expand_a(&rho.bytes)?);

            // Steps 8–15.
            let (s, nonce) = sample_noise_vec(&sigma.bytes, 0, ETA1)?;
            let mut s = observed(WipedBuffer::KeygenS, s);
            let (e, _nonce) = sample_noise_vec(&sigma.bytes, nonce, ETA1)?;
            let mut e = observed(WipedBuffer::KeygenE, e);

            // Steps 16–17.
            s.ntt();
            e.ntt();

            // Step 18: t̂ = Â ◦ ŝ + ê. `mul_vec` leaves an extra R⁻¹
            // Montgomery factor from basemul, so its result is brought back
            // to normal form with `to_mont` before ê, which is in normal
            // form, is added.
            let mut t_hat = observed(WipedBuffer::KeygenTHat, a_hat.mul_vec(&s));
            for i in 0..K {
                t_hat.polys[i].to_mont();
            }
            t_hat.add_assign(&e);

            // Step 19: ek_PKE = ByteEncode_12(t̂) ‖ ρ.
            for i in 0..K {
                t_hat.polys[i].reduce_full();
                byte_encode(
                    12,
                    &t_hat.polys[i].coeffs,
                    &mut ek_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                );
            }
            ek_pke[K * POLY_ENCODED_12..K * POLY_ENCODED_12 + 32].copy_from_slice(&rho.bytes);

            // Step 20: dk_PKE = ByteEncode_12(ŝ).
            for i in 0..K {
                s.polys[i].reduce_full();
                byte_encode(
                    12,
                    &s.polys[i].coeffs,
                    &mut dk_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                );
            }
            Ok(())
        }

        /// K-PKE.Encrypt (FIPS 203 Algorithm 14) of the 32-byte message `m`
        /// under `ek_pke` with randomness `r_seed`, writing the `CT_LEN`-byte
        /// ciphertext into `ct`.
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::needless_range_loop,
            clippy::cast_possible_truncation,
            clippy::similar_names
        )]
        fn kpke_encrypt(
            ek_pke: &[u8],
            m: &[u8; 32],
            r_seed: &[u8; 32],
            ct: &mut [u8],
        ) -> Result<(), Error> {
            debug_assert!(ek_pke.len() >= EK_LEN);
            debug_assert!(ct.len() >= CT_LEN);

            // Step 2.
            let mut t_hat = observed(WipedBuffer::EncryptTHat, PolyVec::zero());
            for i in 0..K {
                byte_decode(
                    12,
                    &ek_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                    &mut t_hat.polys[i].coeffs,
                );
            }

            // Step 3.
            let mut rho = Tagged::<32>::new(WipedBuffer::EncryptRho);
            rho.bytes
                .copy_from_slice(&ek_pke[K * POLY_ENCODED_12..K * POLY_ENCODED_12 + 32]);

            // Steps 4–8.
            let a_hat = observed(WipedBuffer::EncryptA, expand_a(&rho.bytes)?);

            // Steps 9–17.
            let (r_vec, nonce) = sample_noise_vec(r_seed, 0, ETA1)?;
            let mut r_vec = observed(WipedBuffer::EncryptY, r_vec);
            let (e1, nonce) = sample_noise_vec(r_seed, nonce, ETA2)?;
            let e1 = observed(WipedBuffer::EncryptE1, e1);
            let e2 = observed(WipedBuffer::EncryptE2, sample_noise(r_seed, nonce, ETA2)?);

            // Step 18.
            r_vec.ntt();

            // Step 19: u = NTT⁻¹(Âᵀ ◦ ŷ) + e₁.
            let mut u = observed(WipedBuffer::EncryptU, a_hat.transpose_mul_vec(&r_vec));
            u.inv_ntt();
            u.add_assign(&e1);

            // Steps 20–21: v = NTT⁻¹(t̂ᵀ ◦ ŷ) + e₂ + Decompress₁(ByteDecode₁(m)).
            let mut v = observed(
                WipedBuffer::EncryptV,
                PolyVec::inner_product_ntt(&t_hat, &r_vec),
            );
            v.inv_ntt();
            v.add_assign(&e2);

            let mut m_poly = observed(WipedBuffer::EncryptMu, Poly::zero());
            byte_decode(1, m, &mut m_poly.coeffs);
            decompress_poly(1, &mut m_poly.coeffs);
            v.add_assign(&m_poly);

            // Step 22: c₁ = ByteEncode_{dᵤ}(Compress_{dᵤ}(u)).
            for i in 0..K {
                u.polys[i].reduce_full();
                compress_poly(DU as u32, &mut u.polys[i].coeffs);
                byte_encode(
                    DU,
                    &u.polys[i].coeffs,
                    &mut ct[i * POLY_COMPRESSED_DU..(i + 1) * POLY_COMPRESSED_DU],
                );
            }

            // Step 23: c₂ = ByteEncode_{dᵥ}(Compress_{dᵥ}(v)).
            v.reduce_full();
            compress_poly(DV as u32, &mut v.coeffs);
            byte_encode(
                DV,
                &v.coeffs,
                &mut ct[K * POLY_COMPRESSED_DU..K * POLY_COMPRESSED_DU + POLY_COMPRESSED_DV],
            );
            Ok(())
        }

        /// K-PKE.Decrypt (FIPS 203 Algorithm 15) of the `CT_LEN`-byte `ct`
        /// under the 384 · k-byte `dk_pke`, writing the message into `m`.
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

            // Steps 1 and 3.
            let mut u = observed(WipedBuffer::DecryptU, PolyVec::zero());
            for i in 0..K {
                byte_decode(
                    DU,
                    &ct[i * POLY_COMPRESSED_DU..(i + 1) * POLY_COMPRESSED_DU],
                    &mut u.polys[i].coeffs,
                );
                decompress_poly(DU as u32, &mut u.polys[i].coeffs);
            }

            // Steps 2 and 4.
            let mut v = observed(WipedBuffer::DecryptV, Poly::zero());
            byte_decode(
                DV,
                &ct[K * POLY_COMPRESSED_DU..K * POLY_COMPRESSED_DU + POLY_COMPRESSED_DV],
                &mut v.coeffs,
            );
            decompress_poly(DV as u32, &mut v.coeffs);

            // Step 5.
            let mut s_hat = observed(WipedBuffer::DecryptSHat, PolyVec::zero());
            for i in 0..K {
                byte_decode(
                    12,
                    &dk_pke[i * POLY_ENCODED_12..(i + 1) * POLY_ENCODED_12],
                    &mut s_hat.polys[i].coeffs,
                );
            }

            // Step 6: w = v′ − NTT⁻¹(ŝᵀ ◦ NTT(u′)).
            u.ntt();
            let mut w = observed(
                WipedBuffer::DecryptW,
                PolyVec::inner_product_ntt(&s_hat, &u),
            );
            w.inv_ntt();
            v.sub_assign(&w);

            // Step 7: m = ByteEncode₁(Compress₁(w)).
            v.reduce_full();
            compress_poly(1, &mut v.coeffs);
            byte_encode(1, &v.coeffs, m);
        }

        /// ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16).
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
        ) -> Result<(), Error> {
            // Step 1.
            let dk_pke_len = 384 * K;
            kpke_keygen(d, ek, &mut dk[..dk_pke_len])?;

            // Step 3: dk = dk_PKE ‖ ek ‖ H(ek) ‖ z.
            dk[dk_pke_len..dk_pke_len + EK_LEN].copy_from_slice(ek);

            let mut h = <Sha3_256>::new_internal()?;
            h.update(ek);
            let h_ek: [u8; SHA3_256_DIGEST_SIZE] = h.finalize()?;
            dk[dk_pke_len + EK_LEN..dk_pke_len + EK_LEN + 32].copy_from_slice(&h_ek);

            dk[dk_pke_len + EK_LEN + 32..dk_pke_len + EK_LEN + 64].copy_from_slice(z);
            Ok(())
        }

        /// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17), returning
        /// `(K, c)`.
        fn ml_kem_encaps(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
        ) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error> {
            let mut k = [0u8; SHARED_SECRET_LEN];
            let mut ct = [0u8; CT_LEN];
            ml_kem_encaps_into(ek, m, &mut k, &mut ct)?;
            Ok((k, ct))
        }

        /// [`ml_kem_encaps`] writing K into `k_out` and c into `ct_out`.
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::similar_names,
            clippy::many_single_char_names
        )]
        fn ml_kem_encaps_into(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
            k_out: &mut [u8; SHARED_SECRET_LEN],
            ct_out: &mut [u8; CT_LEN],
        ) -> Result<(), Error> {
            // Step 1: (K, r) ← G(m ‖ H(ek)).
            let mut h = <Sha3_256>::new_internal()?;
            h.update(ek);
            let h_ek: [u8; SHA3_256_DIGEST_SIZE] = h.finalize()?;

            let mut g = <Sha3_512>::new_internal()?;
            g.update(m);
            g.update(&h_ek);
            let mut g_out = Tagged::<SHA3_512_DIGEST_SIZE>::new(WipedBuffer::EncapsG);
            g_out.bytes = g.finalize()?;

            let mut k = Tagged::<32>::new(WipedBuffer::EncapsK);
            let mut r = Tagged::<32>::new(WipedBuffer::EncapsR);
            k.bytes.copy_from_slice(&g_out.bytes[..32]);
            r.bytes.copy_from_slice(&g_out.bytes[32..64]);

            // Step 2: c ← K-PKE.Encrypt(ek, m, r).
            kpke_encrypt(ek, m, &r.bytes, ct_out)?;
            *k_out = k.bytes;
            Ok(())
        }

        /// ML-KEM.Decaps_internal (FIPS 203 Algorithm 18), returning the
        /// shared secret: K′ when the re-encryption matches `ct`, the
        /// rejection secret K̄ otherwise, selected in constant time.
        fn ml_kem_decaps(
            dk: &[u8; DK_LEN],
            ct: &[u8; CT_LEN],
        ) -> Result<[u8; SHARED_SECRET_LEN], Error> {
            let mut k = [0u8; SHARED_SECRET_LEN];
            ml_kem_decaps_into(dk, ct, &mut k)?;
            Ok(k)
        }

        /// [`ml_kem_decaps`] writing the shared secret into `k_out`.
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::similar_names,
            clippy::many_single_char_names
        )]
        fn ml_kem_decaps_into(
            dk: &[u8; DK_LEN],
            ct: &[u8; CT_LEN],
            k_out: &mut [u8; SHARED_SECRET_LEN],
        ) -> Result<(), Error> {
            let dk_pke_len = 384 * K;

            // Steps 1–4: dk = dk_PKE ‖ ek ‖ H(ek) ‖ z.
            let dk_pke = &dk[..dk_pke_len];
            let ek = &dk[dk_pke_len..dk_pke_len + EK_LEN];
            let h_ek = &dk[dk_pke_len + EK_LEN..dk_pke_len + EK_LEN + 32];
            let z = &dk[dk_pke_len + EK_LEN + 32..dk_pke_len + EK_LEN + 64];

            let mut g = <Sha3_512>::new_internal()?;
            let mut j = Shake256::new_internal()?;

            // Step 5.
            let mut m_prime = Tagged::<32>::new(WipedBuffer::DecapsMPrime);
            kpke_decrypt(dk_pke, ct, &mut m_prime.bytes);

            // Step 6: (K′, r′) ← G(m′ ‖ h).
            g.update(&m_prime.bytes);
            g.update(h_ek);
            let mut g_out = Tagged::<SHA3_512_DIGEST_SIZE>::new(WipedBuffer::DecapsG);
            g_out.bytes = g.finalize()?;

            let mut k_prime = Tagged::<32>::new(WipedBuffer::DecapsKPrime);
            let mut r_prime = Tagged::<32>::new(WipedBuffer::DecapsRPrime);
            k_prime.bytes.copy_from_slice(&g_out.bytes[..32]);
            r_prime.bytes.copy_from_slice(&g_out.bytes[32..64]);

            // Step 7: K̄ ← J(z ‖ c), J = SHAKE-256 to 32 bytes.
            j.update(z);
            j.update(ct);
            j.finalize();
            let mut k_bar = Tagged::<32>::new(WipedBuffer::DecapsKBar);
            j.squeeze(&mut k_bar.bytes)?;

            // Step 8.
            let mut ct_prime = Tagged::<CT_LEN>::new(WipedBuffer::DecapsCtPrime);
            kpke_encrypt(ek, &m_prime.bytes, &r_prime.bytes, &mut ct_prime.bytes)?;

            // Steps 9–11, in constant time.
            let diff = ct_bytes_eq(ct, &ct_prime.bytes);
            *k_out = ct_select_32(&k_prime.bytes, &k_bar.bytes, diff);
            Ok(())
        }

        /// The RBG security strength key generation and encapsulation
        /// require, in bits (FIPS 203 §3.3).
        const RBG_STRENGTH_BITS: u32 = $rbg_strength_bits;

        /// The `reason` of the [`Error::ConditionalTestFailed`] a failed
        /// pairwise consistency test returns.
        const PCT_REASON: &str = $pct_reason;

        /// ML-KEM.KeyGen (FIPS 203 Algorithm 19): checks the strength of
        /// `rbg`, draws d and then z from it as two 32-byte requests,
        /// expands the pair and runs the pairwise consistency test. d and z
        /// are wiped before the function returns.
        ///
        /// Returns `(ek, dk)`.
        ///
        /// # Errors
        ///
        /// - [`Error::NotOperational`] unless the module is operational.
        /// - [`Error::AlgorithmRestricted`] when the active profile does not
        ///   admit this parameter set's key generation.
        /// - [`Error::RbgTooWeak`] when `rbg.strength_bits()` is below the
        ///   parameter set's requirement (128 bits for ML-KEM-512, 192 for
        ///   ML-KEM-768, 256 for ML-KEM-1024), before any draw.
        /// - [`Error::Rbg`] when a draw fails.
        /// - [`Error::ConditionalTestFailed`] when the pairwise consistency
        ///   test fails (FIPS 140-3 IG 10.3.A); the module has entered its
        ///   error state.
        pub fn keygen<R: oxicrypt_module::Rbg>(
            rbg: &mut R,
        ) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_keygen)?;
            let (d, z) = draw_d_z(rbg)?;
            expand_checked(&d.bytes, &z.bytes)
        }

        /// As [`keygen`], and also returns d ‖ z, d first, so that the
        /// caller can store the pair as its seed and expand it again with
        /// [`expand_key`]. The seed computes the decapsulation key and needs
        /// the same safeguards.
        ///
        /// # Errors
        ///
        /// As [`keygen`].
        pub fn keygen_with_seed<R: oxicrypt_module::Rbg>(
            rbg: &mut R,
        ) -> Result<
            (
                oxicrypt_zeroize::Zeroizing<[u8; 2 * SEED_LEN]>,
                [u8; EK_LEN],
                [u8; DK_LEN],
            ),
            Error,
        > {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_keygen)?;
            let (d, z) = draw_d_z(rbg)?;
            let (ek, dk) = expand_checked(&d.bytes, &z.bytes)?;
            let mut seed = oxicrypt_zeroize::Zeroizing::new([0u8; 2 * SEED_LEN]);
            seed[..SEED_LEN].copy_from_slice(&d.bytes);
            seed[SEED_LEN..].copy_from_slice(&z.bytes);
            Ok((seed, ek, dk))
        }

        /// Expands the key pair from a stored seed `(d, z)` (FIPS 203
        /// Algorithm 16) and runs the pairwise consistency test, on every
        /// call (FIPS 140-3 IG 10.3.A). A seed that did not come from this
        /// module's [`keygen_with_seed`] is a private key imported from
        /// outside the boundary. `d` and `z` are the caller's and are not
        /// modified.
        ///
        /// # Errors
        ///
        /// - [`Error::NotOperational`] unless the module is operational.
        /// - [`Error::AlgorithmRestricted`] when the active profile does not
        ///   admit this parameter set's key expansion.
        /// - [`Error::ConditionalTestFailed`] as for [`keygen`].
        pub fn expand_key(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
        ) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_expand_key)?;
            expand_checked(d, z)
        }

        /// ML-KEM.Encaps (FIPS 203 Algorithm 20): checks the strength of
        /// `rbg`, draws m from it as one 32-byte request and encapsulates
        /// against `ek`. m is wiped before the function returns.
        ///
        /// Returns `(shared_secret, ciphertext)`.
        ///
        /// # Errors
        ///
        /// - [`Error::NotOperational`] unless the module is operational.
        /// - [`Error::AlgorithmRestricted`] when the active profile does not
        ///   admit this parameter set's encapsulation.
        /// - [`Error::RbgTooWeak`] when `rbg.strength_bits()` is below the
        ///   requirement [`keygen`] states, before any draw.
        /// - [`Error::Rbg`] when the draw fails.
        pub fn encapsulate<R: oxicrypt_module::Rbg>(
            ek: &[u8; EK_LEN],
            rbg: &mut R,
        ) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_encaps)?;
            let m = draw_m(rbg)?;
            ml_kem_encaps(ek, &m.bytes)
        }

        /// ML-KEM.Decaps (FIPS 203 Algorithm 21) of `ct` under `dk`.
        ///
        /// Uses implicit rejection: a ciphertext that does not re-encrypt
        /// to itself yields the pseudorandom J(z ‖ c) rather than an error.
        /// The comparison and the selection are constant-time.
        ///
        /// # Errors
        ///
        /// - [`Error::NotOperational`] unless the module is operational.
        /// - [`Error::AlgorithmRestricted`] when the active profile does not
        ///   admit this parameter set's decapsulation.
        pub fn decapsulate(
            dk: &[u8; DK_LEN],
            ct: &[u8; CT_LEN],
        ) -> Result<[u8; SHARED_SECRET_LEN], Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_decaps)?;
            decaps_internal_unguarded(dk, ct)
        }

        /// Checks the strength of `rbg` against [`RBG_STRENGTH_BITS`], then
        /// draws d and then z (FIPS 203 Algorithm 19 steps 1 and 2). A
        /// failure of the second draw drops, and so wipes, d.
        fn draw_d_z<R: oxicrypt_module::Rbg>(
            rbg: &mut R,
        ) -> Result<(Tagged<SEED_LEN>, Tagged<SEED_LEN>), Error> {
            if rbg.strength_bits() < RBG_STRENGTH_BITS {
                return Err(Error::RbgTooWeak);
            }
            let mut d = Tagged::new(WipedBuffer::D);
            rbg.fill(&mut d.bytes).map_err(Error::Rbg)?;
            let mut z = Tagged::new(WipedBuffer::Z);
            rbg.fill(&mut z.bytes).map_err(Error::Rbg)?;
            Ok((d, z))
        }

        /// Checks the strength of `rbg` against [`RBG_STRENGTH_BITS`], then
        /// draws m (FIPS 203 Algorithm 20 step 1).
        fn draw_m<R: oxicrypt_module::Rbg>(rbg: &mut R) -> Result<Tagged<SEED_LEN>, Error> {
            if rbg.strength_bits() < RBG_STRENGTH_BITS {
                return Err(Error::RbgTooWeak);
            }
            let mut m = Tagged::new(WipedBuffer::M);
            rbg.fill(&mut m.bytes).map_err(Error::Rbg)?;
            Ok(m)
        }

        /// Expands the pair from `(d, z)` and runs the pairwise consistency
        /// test before either half is returned. On a failed test both halves
        /// are wiped, then the module enters its error state.
        fn expand_checked(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
        ) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
            let mut ek = Tagged::<EK_LEN>::new(WipedBuffer::PublicKey);
            let mut dk = Tagged::<DK_LEN>::new(WipedBuffer::SecretKey);
            ml_kem_keygen(d, z, &mut ek.bytes, &mut dk.bytes)?;
            #[cfg(any(test, feature = "fault-injection"))]
            if $crate::seam::take_corrupt_next_dk() {
                dk.bytes[0] ^= 0xFF;
            }
            if !pairwise_consistency(&ek.bytes, &dk.bytes)? {
                drop(ek);
                drop(dk);
                oxicrypt_module::enter_error_state(PCT_REASON);
                return Err(Error::ConditionalTestFailed { reason: PCT_REASON });
            }
            Ok((ek.bytes, dk.bytes))
        }

        /// The pairwise consistency test (FIPS 140-3 IG 10.3.A):
        /// encapsulates against `ek` with [`oxicrypt_module::PCT_M`],
        /// decapsulates the ciphertext with `dk`, and compares the two
        /// shared secrets with the constant-time `ct_bytes_eq`. `false`
        /// when they differ.
        fn pairwise_consistency(ek: &[u8; EK_LEN], dk: &[u8; DK_LEN]) -> Result<bool, Error> {
            let mut k = Tagged::<SHARED_SECRET_LEN>::new(WipedBuffer::PctEncapsK);
            let mut ct = Tagged::<CT_LEN>::new(WipedBuffer::PctCiphertext);
            ml_kem_encaps_into(ek, &oxicrypt_module::PCT_M, &mut k.bytes, &mut ct.bytes)?;
            let mut k_prime = Tagged::<SHARED_SECRET_LEN>::new(WipedBuffer::PctDecapsK);
            ml_kem_decaps_into(dk, &ct.bytes, &mut k_prime.bytes)?;
            Ok(ct_bytes_eq(&k.bytes, &k_prime.bytes) == 0)
        }

        /// Internal keygen — no operational gate.
        ///
        /// Compiled only with the `testing-interfaces` feature: FIPS 203 §3.3
        /// restricts this interface to CAVP testing.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[cfg(feature = "testing-interfaces")]
        #[doc(hidden)]
        pub fn keygen_internal(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
        ) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
            oxicrypt_module::require_self_test_started()?;
            keygen_internal_guarded(d, z)
        }

        /// Key generation behind the `require_self_test_started` guard, for
        /// the key-generation self-test (ML-KEM-1024), the crate's unit
        /// tests and `keygen_internal`.
        pub(crate) fn keygen_internal_guarded(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
        ) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
            oxicrypt_module::require_self_test_started()?;
            keygen_internal_unguarded(d, z)
        }

        fn keygen_internal_unguarded(
            d: &[u8; SEED_LEN],
            z: &[u8; SEED_LEN],
        ) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error> {
            let mut ek = [0u8; EK_LEN];
            let mut dk = [0u8; DK_LEN];
            ml_kem_keygen(d, z, &mut ek, &mut dk)?;
            Ok((ek, dk))
        }

        /// Internal encaps — no operational gate.
        ///
        /// Compiled only with the `testing-interfaces` feature: FIPS 203 §3.3
        /// restricts this interface to CAVP testing.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[cfg(feature = "testing-interfaces")]
        #[doc(hidden)]
        pub fn encaps_internal(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
        ) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error> {
            oxicrypt_module::require_self_test_started()?;
            encaps_internal_guarded(ek, m)
        }

        /// Encapsulation behind the `require_self_test_started` guard, for
        /// the encapsulation self-test (ML-KEM-1024), the crate's unit tests
        /// and `encaps_internal`.
        pub(crate) fn encaps_internal_guarded(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
        ) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error> {
            oxicrypt_module::require_self_test_started()?;
            encaps_internal_unguarded(ek, m)
        }

        fn encaps_internal_unguarded(
            ek: &[u8; EK_LEN],
            m: &[u8; SEED_LEN],
        ) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error> {
            ml_kem_encaps(ek, m)
        }

        /// Internal decaps — no operational gate.
        ///
        /// Compiled only with the `testing-interfaces` feature: FIPS 203 §3.3
        /// restricts this interface to CAVP testing.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[cfg(feature = "testing-interfaces")]
        #[doc(hidden)]
        pub fn decaps_internal(
            dk: &[u8; DK_LEN],
            ct: &[u8; CT_LEN],
        ) -> Result<[u8; SHARED_SECRET_LEN], Error> {
            oxicrypt_module::require_self_test_started()?;
            decaps_internal_guarded(dk, ct)
        }

        /// Decapsulation behind the `require_self_test_started` guard, for
        /// both decapsulation self-tests (ML-KEM-1024), the crate's unit
        /// tests and `decaps_internal`.
        pub(crate) fn decaps_internal_guarded(
            dk: &[u8; DK_LEN],
            ct: &[u8; CT_LEN],
        ) -> Result<[u8; SHARED_SECRET_LEN], Error> {
            oxicrypt_module::require_self_test_started()?;
            decaps_internal_unguarded(dk, ct)
        }

        fn decaps_internal_unguarded(
            dk: &[u8; DK_LEN],
            ct: &[u8; CT_LEN],
        ) -> Result<[u8; SHARED_SECRET_LEN], Error> {
            ml_kem_decaps(dk, ct)
        }

        // Fails to compile for K = 0.
        #[allow(dead_code)]
        const _ASSERT_K_GT_0: usize = K - 1;

        #[cfg(test)]
        mod rbg_services {
            extern crate std;

            use super::*;
            use oxicrypt_module::{Rbg, RbgError};

            /// An RBG that serves `stream` in order at a chosen strength and
            /// records the length of each draw.
            pub(super) struct CountingRbg {
                pub(super) stream: [u8; 2 * SEED_LEN],
                pub(super) strength: u32,
                pub(super) draws: std::vec::Vec<usize>,
                served: usize,
            }

            impl CountingRbg {
                pub(super) fn new(stream: [u8; 2 * SEED_LEN], strength: u32) -> Self {
                    Self {
                        stream,
                        strength,
                        draws: std::vec::Vec::new(),
                        served: 0,
                    }
                }
            }

            impl Rbg for CountingRbg {
                fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
                    self.draws.push(out.len());
                    let end = self.served + out.len();
                    let Some(source) = self.stream.get(self.served..end) else {
                        return Err(RbgError::RequestTooLong);
                    };
                    out.copy_from_slice(source);
                    self.served = end;
                    Ok(())
                }

                fn strength_bits(&self) -> u32 {
                    self.strength
                }
            }

            /// Bytes 0..64 of a stream whose two halves differ, so that
            /// swapping d and z changes the pair.
            fn stream() -> [u8; 2 * SEED_LEN] {
                core::array::from_fn(|i| i as u8 ^ 0x3c)
            }

            fn halves(s: &[u8; 2 * SEED_LEN]) -> ([u8; SEED_LEN], [u8; SEED_LEN]) {
                let mut d = [0u8; SEED_LEN];
                let mut z = [0u8; SEED_LEN];
                d.copy_from_slice(&s[..SEED_LEN]);
                z.copy_from_slice(&s[SEED_LEN..]);
                (d, z)
            }

            /// `keygen` and `keygen_with_seed` draw d and then z as two
            /// 32-byte requests and return what the internal core gives for
            /// that d and z.
            #[test]
            fn with_rbg_keygen_matches_internal_core() {
                crate::test_support::start_module();
                let stream = stream();
                let (d, z) = halves(&stream);
                let expected = keygen_internal_guarded(&d, &z).unwrap();
                assert_ne!(expected, keygen_internal_guarded(&z, &d).unwrap());

                let mut rbg = CountingRbg::new(stream, RBG_STRENGTH_BITS);
                assert_eq!(keygen(&mut rbg).unwrap(), expected);
                assert_eq!(rbg.draws, [SEED_LEN, SEED_LEN]);

                let mut rbg = CountingRbg::new(stream, RBG_STRENGTH_BITS);
                let (seed, ek, dk) = keygen_with_seed(&mut rbg).unwrap();
                assert_eq!((*seed, ek, dk), (stream, expected.0, expected.1));
                assert_eq!(rbg.draws, [SEED_LEN, SEED_LEN]);
            }

            /// `encapsulate` draws m as one 32-byte request and returns what
            /// the internal core gives for that m.
            #[test]
            fn with_rbg_encapsulate_matches_internal_core() {
                crate::test_support::start_module();
                let stream = stream();
                let (d, z) = halves(&stream);
                let (ek, dk) = keygen_internal_guarded(&d, &z).unwrap();
                let expected = encaps_internal_guarded(&ek, &d).unwrap();

                let mut rbg = CountingRbg::new(stream, RBG_STRENGTH_BITS);
                let (k, ct) = encapsulate(&ek, &mut rbg).unwrap();
                assert_eq!((k, ct), expected);
                assert_eq!(rbg.draws, [SEED_LEN]);
                assert_eq!(decapsulate(&dk, &ct).unwrap(), k);
            }

            /// An RBG below the set's strength is refused before any draw,
            /// and an uninstantiated DRBG of sufficient strength is refused
            /// by its draw.
            #[test]
            fn with_rbg_refuses_weak_or_uninstantiated() {
                crate::test_support::start_module();
                let (ek, _) =
                    keygen_internal_guarded(&[0x11; SEED_LEN], &[0x22; SEED_LEN]).unwrap();
                for strength in [128, 192, 256] {
                    let mut keygen_rbg = CountingRbg::new(stream(), strength);
                    let mut seed_rbg = CountingRbg::new(stream(), strength);
                    let mut encaps_rbg = CountingRbg::new(stream(), strength);
                    let outcomes = [
                        keygen(&mut keygen_rbg).map(drop),
                        keygen_with_seed(&mut seed_rbg).map(drop),
                        encapsulate(&ek, &mut encaps_rbg).map(drop),
                    ];
                    let draws = [keygen_rbg.draws, seed_rbg.draws, encaps_rbg.draws];
                    if strength < RBG_STRENGTH_BITS {
                        for outcome in outcomes {
                            assert_eq!(outcome, Err(Error::RbgTooWeak), "{strength}");
                        }
                        assert!(draws.iter().all(|d| d.is_empty()), "{strength}");
                    } else {
                        for outcome in outcomes {
                            assert_eq!(outcome, Ok(()), "{strength}");
                        }
                        assert_eq!(draws.map(|d| d.len()), [2, 2, 1], "{strength}");
                    }
                }

                // Uninstantiated, so any draw would fail with
                // `Uninstantiated`: `RbgTooWeak` shows no draw was made.
                let expected = |strength: u32| {
                    if strength < RBG_STRENGTH_BITS {
                        Error::RbgTooWeak
                    } else {
                        Error::Rbg(RbgError::Uninstantiated)
                    }
                };
                let mut aes128 = oxicrypt_drbg::CtrDrbgAes128::new();
                assert_eq!(keygen(&mut aes128).map(drop), Err(expected(128)));
                assert_eq!(keygen_with_seed(&mut aes128).map(drop), Err(expected(128)));
                assert_eq!(encapsulate(&ek, &mut aes128).map(drop), Err(expected(128)));
                let mut aes192 = oxicrypt_drbg::CtrDrbgAes192::new();
                assert_eq!(keygen(&mut aes192).map(drop), Err(expected(192)));
                assert_eq!(encapsulate(&ek, &mut aes192).map(drop), Err(expected(192)));

                let mut hmac = oxicrypt_drbg::HmacDrbgSha256::new();
                let uninstantiated = Err(Error::Rbg(RbgError::Uninstantiated));
                assert_eq!(keygen(&mut hmac).map(drop), uninstantiated);
                assert_eq!(keygen_with_seed(&mut hmac).map(drop), uninstantiated);
                assert_eq!(encapsulate(&ek, &mut hmac).map(drop), uninstantiated);
            }

            /// `expand_key` reproduces the pair `keygen_with_seed` returned
            /// from the seed it returned, and a seed with one byte changed
            /// does not.
            #[test]
            fn keygen_with_seed_round_trips() {
                crate::test_support::start_module();
                let mut rbg = CountingRbg::new([0x96; 2 * SEED_LEN], RBG_STRENGTH_BITS);
                let (seed, ek, dk) = keygen_with_seed(&mut rbg).unwrap();
                let (d, z) = halves(&seed);
                assert_eq!(expand_key(&d, &z).unwrap(), (ek, dk));
                assert_eq!(
                    (d, z),
                    ([0x96; SEED_LEN], [0x96; SEED_LEN]),
                    "expand_key modified the caller's seed"
                );

                let mut mutated = d;
                mutated[0] ^= 0x01;
                let (other_ek, other_dk) = expand_key(&mutated, &z).unwrap();
                assert_ne!(other_ek, ek);
                assert_ne!(other_dk, dk);
            }
        }

        #[cfg(all(test, feature = "fault-injection"))]
        mod wipe_on_exit {
            extern crate std;

            use super::rbg_services::CountingRbg;
            use super::*;
            use oxicrypt_module::{Rbg, RbgError};
            use $crate::seam;
            use $crate::wipe::WipedBuffer::*;

            /// Every buffer an encapsulation holds.
            const ENCAPSULATION: &[WipedBuffer] = &[
                M,
                NoisePrf,
                EncryptRho,
                EncapsG,
                EncapsK,
                EncapsR,
                EncryptTHat,
                EncryptA,
                EncryptY,
                EncryptE1,
                EncryptE2,
                EncryptU,
                EncryptV,
                EncryptMu,
            ];

            /// Every buffer a key generation that reaches the pairwise
            /// consistency test holds.
            const KEY_GENERATION: &[WipedBuffer] = &[
                D,
                Z,
                KeygenGInput,
                KeygenG,
                KeygenRho,
                KeygenSigma,
                NoisePrf,
                EncryptRho,
                EncapsG,
                EncapsK,
                EncapsR,
                DecapsMPrime,
                DecapsG,
                DecapsKPrime,
                DecapsRPrime,
                DecapsKBar,
                DecapsCtPrime,
                PublicKey,
                SecretKey,
                PctCiphertext,
                PctEncapsK,
                PctDecapsK,
                KeygenA,
                KeygenS,
                KeygenE,
                KeygenTHat,
                EncryptTHat,
                EncryptA,
                EncryptY,
                EncryptE1,
                EncryptE2,
                EncryptU,
                EncryptV,
                EncryptMu,
                DecryptU,
                DecryptV,
                DecryptSHat,
                DecryptW,
            ];

            /// Set in the child process this test runs its body in.
            const CHILD: &str = "OXICRYPT_ML_KEM_WIPE_CHILD";

            /// An RBG whose draws fail from the `fail_at`-th on, counting
            /// from 0.
            struct FailingRbg {
                fail_at: usize,
                draws: usize,
            }

            impl Rbg for FailingRbg {
                fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
                    self.draws += 1;
                    if self.draws > self.fail_at {
                        oxicrypt_zeroize::zeroize(out);
                        return Err(RbgError::Busy);
                    }
                    out.fill(0x5a);
                    Ok(())
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

            /// Every exit of the key-generation and encapsulation services
            /// wipes every buffer it holds: a strength refusal (which holds
            /// none), a failed first draw, a failed second draw, success
            /// through each entry point, and a failed pairwise consistency
            /// test. The last puts the module in its error state, so the
            /// body runs in a child process of its own.
            ///
            /// Limit: the expansion core's error exit is not exercised,
            /// because the core fails only on a module state that the
            /// service's own gate refuses first.
            #[test]
            fn seeds_wiped_on_every_exit() {
                let name = module_path!()
                    .split_once("::")
                    .map(|(_, path)| std::format!("{path}::seeds_wiped_on_every_exit"))
                    .unwrap();
                if std::env::var_os(CHILD).is_none() {
                    let out = std::process::Command::new(std::env::current_exe().unwrap())
                        .args([name.as_str(), "--exact", "--test-threads=1"])
                        .env(CHILD, "1")
                        .output()
                        .unwrap();
                    let stdout = std::string::String::from_utf8_lossy(&out.stdout);
                    assert!(
                        out.status.success() && stdout.contains("test result: ok. 1 passed"),
                        "{name} did not pass in its own process:\n{stdout}{}",
                        std::string::String::from_utf8_lossy(&out.stderr)
                    );
                    return;
                }

                crate::test_support::start_module();
                let (ek, _) =
                    keygen_internal_guarded(&[0x33; SEED_LEN], &[0x44; SEED_LEN]).unwrap();
                seam::reset();

                let mut weak = CountingRbg::new([0x11; 2 * SEED_LEN], RBG_STRENGTH_BITS - 64);
                assert_eq!(keygen(&mut weak).map(drop), Err(Error::RbgTooWeak));
                assert_eq!(
                    encapsulate(&ek, &mut weak).map(drop),
                    Err(Error::RbgTooWeak)
                );
                assert_wiped("strength refusal", &[]);

                let mut first = FailingRbg {
                    fail_at: 0,
                    draws: 0,
                };
                assert_eq!(
                    keygen_with_seed(&mut first).map(drop),
                    Err(Error::Rbg(RbgError::Busy))
                );
                assert_wiped("first draw failure", &[D]);

                let mut second = FailingRbg {
                    fail_at: 1,
                    draws: 0,
                };
                assert_eq!(
                    keygen(&mut second).map(drop),
                    Err(Error::Rbg(RbgError::Busy))
                );
                assert_eq!(second.draws, 2);
                assert_wiped("second draw failure", &[D, Z]);

                let mut first = FailingRbg {
                    fail_at: 0,
                    draws: 0,
                };
                assert_eq!(
                    encapsulate(&ek, &mut first).map(drop),
                    Err(Error::Rbg(RbgError::Busy))
                );
                assert_wiped("encapsulation draw failure", &[M]);

                let mut rbg = CountingRbg::new([0x11; 2 * SEED_LEN], RBG_STRENGTH_BITS);
                encapsulate(&ek, &mut rbg).unwrap();
                assert_wiped("encapsulate", ENCAPSULATION);

                let mut rbg = CountingRbg::new([0x11; 2 * SEED_LEN], RBG_STRENGTH_BITS);
                keygen(&mut rbg).unwrap();
                assert_wiped("keygen", KEY_GENERATION);

                let mut rbg = CountingRbg::new([0x11; 2 * SEED_LEN], RBG_STRENGTH_BITS);
                let (seed, _, _) = keygen_with_seed(&mut rbg).unwrap();
                assert_wiped("keygen_with_seed", KEY_GENERATION);
                drop(seed);

                let (d, z) = ([0x22; SEED_LEN], [0x23; SEED_LEN]);
                expand_key(&d, &z).unwrap();
                assert_eq!((d, z), ([0x22; SEED_LEN], [0x23; SEED_LEN]));
                let without_seed: std::vec::Vec<WipedBuffer> = KEY_GENERATION
                    .iter()
                    .copied()
                    .filter(|b| !matches!(b, D | Z))
                    .collect();
                assert_wiped("expand_key", &without_seed);

                seam::corrupt_next_dk();
                let mut rbg = CountingRbg::new([0x11; 2 * SEED_LEN], RBG_STRENGTH_BITS);
                assert_eq!(
                    keygen(&mut rbg).map(drop),
                    Err(Error::ConditionalTestFailed { reason: PCT_REASON })
                );
                assert!(!oxicrypt_module::is_operational());
                assert_wiped("pairwise consistency failure", KEY_GENERATION);
            }
        }

        // The feature-gated `expand_a` must equal an always-sequential
        // reference loop, which never touches the rayon path, cell for cell
        // for a few fixed ρ. Key-generation known-answer tests cover only
        // ML-KEM-1024, so this pins `expand_a` for every parameter set.
        #[cfg(all(test, feature = "parallel"))]
        #[allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]
        mod parallel_determinism {
            use super::*;

            fn expand_a_sequential_reference(rho: &[u8; SEED_LEN]) -> PolyMatrix {
                let mut rows: [[Poly; K]; K] =
                    core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
                for i in 0..K {
                    for j in 0..K {
                        let mut xof = Shake128::new_internal().unwrap();
                        xof.update(rho);
                        xof.update(&[j as u8, i as u8]);
                        xof.finalize();
                        rows[i][j] = sample_ntt(
                            &mut xof,
                            &oxicrypt_module::require_self_test_started_token().unwrap(),
                        );
                    }
                }
                PolyMatrix { rows }
            }

            #[test]
            fn parallel_expand_a_matches_sequential_reference() {
                crate::test_support::start_module();
                for k in 0u8..4 {
                    let mut rho = [0u8; SEED_LEN];
                    for (idx, b) in rho.iter_mut().enumerate() {
                        *b = k.wrapping_mul(7).wrapping_add(idx as u8).wrapping_add(0x5a);
                    }
                    let par = expand_a(&rho).unwrap();
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
