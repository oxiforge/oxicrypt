//! Declarative macro that generates the full RSA-3072 / RSA-4096 key
//! struct and all sign/verify/encrypt/decrypt internals, parameterized
//! on half-width and full-width big-integer types.
//!
//! This is the encoding/wiring counterpart to `keygen_impl.rs`, which
//! generates the keygen pipeline. Together the two macros cover the
//! entire RSA lifecycle from key generation through signature and
//! encryption operations.
//!
//! # Generated items
//!
//! | Item | Visibility | Purpose |
//! |------|-----------|---------|
//! | `CrtComponents$NLEN` | `pub(crate)` | CRT material with zeroizing Drop |
//! | `CrtComponentsRaw$NLEN` | `pub(crate)` | Borrowed CRT references |
//! | `rsa_crt_${nlen}_private_exp_internal` | `pub(crate)` | CRT sign/decrypt + Bellcore |
//! | `pairwise_consistency_test_${nlen}_internal` | `pub(crate)` | IG 10.3.A PCT |
//! | `RsaPrivateKey$NLEN` | `pub` | Validated private-key handle |
//! | Verify / sign / encrypt / decrypt internals | `#[doc(hidden)]` | Primitives without the operational gate |
//! | Public gated wrappers | `pub` | Module-gated entry points |
//!
//! # Architecture note
//!
//! The macro architecture here is designed for reuse: if a future
//! post-quantum algorithm (e.g., ML-DSA or SLH-DSA) needs a similar
//! parameterized sign/verify/encrypt flow over different key widths,
//! it can follow the same single-source-of-truth pattern.

#![allow(unused_macros)]

macro_rules! define_rsa_wide {
    (
        // Full-width types.
        full_type = $full:ident;
        full_bytes = $fbytes:expr;
        full_limbs = $flimbs:expr;
        full_mont = $fmont:ident;
        full_mod = $full_mod:path;
        // Half-width types.
        half_type = $half:ident;
        half_bytes = $hbytes:expr;
        half_limbs = $hlimbs:expr;
        half_mont = $hmont:ident;
        half_reduce = $half_reduce:path;
        // Key generation.
        keygen_fn = $keygen_fn:path;
        keygen_km = $keygen_km:ident;
        // Width parameters.
        nlen = $nlen:expr;
        em_bits = $embits:expr;
        em_len = $emlen:expr;
        oaep_k = $oaep_k:expr;
        oaep_max_msg = $oaep_max_msg:expr;
        // Names for generated items.
        key_struct = $key_struct:ident;
        crt_struct = $crt_struct:ident;
        crt_raw = $crt_raw:ident;
        // Service variants.
        svc_keygen = $svc_keygen:expr;
        svc_pkcs1_sign = $svc_pkcs1_sign:expr;
        svc_pkcs1_verify = $svc_pkcs1_verify:expr;
        svc_pss_sign = $svc_pss_sign:expr;
        svc_pss_verify = $svc_pss_verify:expr;
        svc_oaep = $svc_oaep:expr;
    ) => {
        use oxicrypt_module::{
            Error, Service, require_allowed, require_operational, require_self_test_started,
        };

        /// Fixed modulus byte length.
        pub const MODULUS_BYTES: usize = $fbytes;
        /// Fixed signature byte length (equal to modulus length per PKCS#1 §8.2).
        pub const SIGNATURE_BYTES: usize = $fbytes;
        /// Fixed byte length of each CRT half (`p`, `q`, `dP`, `dQ`, `qInv`).
        pub const CRT_HALF_BYTES: usize = $hbytes;

        /// OAEP `k` parameter (modulus byte length).
        pub const OAEP_K: usize = $oaep_k;
        /// Maximum OAEP plaintext length: `k − 2·hLen − 2`.
        pub const OAEP_MAX_MSG_LEN: usize = $oaep_max_msg;

        // ────────────────────── CRT types ──────────────────────

        /// CRT-form private-key material with zeroizing Drop.
        #[derive(Clone)]
        #[allow(clippy::struct_field_names)]
        pub(crate) struct $crt_struct {
            pub p_bytes: [u8; CRT_HALF_BYTES],
            pub q_bytes: [u8; CRT_HALF_BYTES],
            pub dp_bytes: [u8; CRT_HALF_BYTES],
            pub dq_bytes: [u8; CRT_HALF_BYTES],
            pub qinv_bytes: [u8; CRT_HALF_BYTES],
        }

        impl Drop for $crt_struct {
            fn drop(&mut self) {
                oxicrypt_zeroize::zeroize(&mut self.p_bytes);
                oxicrypt_zeroize::zeroize(&mut self.q_bytes);
                oxicrypt_zeroize::zeroize(&mut self.dp_bytes);
                oxicrypt_zeroize::zeroize(&mut self.dq_bytes);
                oxicrypt_zeroize::zeroize(&mut self.qinv_bytes);
            }
        }

        /// Borrowed CRT references for internal primitives.
        #[derive(Clone, Copy)]
        pub(crate) struct $crt_raw<'a> {
            pub p: &'a [u8; CRT_HALF_BYTES],
            pub q: &'a [u8; CRT_HALF_BYTES],
            pub dp: &'a [u8; CRT_HALF_BYTES],
            pub dq: &'a [u8; CRT_HALF_BYTES],
            pub qinv: &'a [u8; CRT_HALF_BYTES],
        }

        // ────────────────── Zero-extend helper ─────────────────

        /// Zero-extend a half-width value into the low half of a
        /// full-width value. Used by the CRT Garner recombine step.
        #[inline]
        fn half_into_full_low(x: &$half) -> $full {
            let mut limbs = [0u64; $flimbs];
            limbs[..$hlimbs].copy_from_slice(&x.limbs);
            $full { limbs }
        }

        // ────────── Core verify primitive (no operational gate) ────

        /// RSASSA-PKCS1-v1_5 verify, skipping the operational and profile gates.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn pkcs1_v15_verify_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            msg: &[u8],
            sig_bytes: &[u8; SIGNATURE_BYTES],
        ) -> Result<bool, Error> {
            require_self_test_started()?;
            pkcs1_v15_verify_internal_unguarded(n_bytes, e, msg, sig_bytes)
        }

        /// Body of [`pkcs1_v15_verify_internal`], run once its guard has passed.
        fn pkcs1_v15_verify_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            msg: &[u8],
            sig_bytes: &[u8; SIGNATURE_BYTES],
        ) -> Result<bool, Error> {
            let n = $full::from_be_bytes(n_bytes);
            let Some(ctx) = $fmont::new(n) else {
                return Ok(false);
            };
            let s = $full::from_be_bytes(sig_bytes);
            if s.ct_lt(&ctx.n) != 1 {
                return Ok(false);
            }
            let m = ctx.pow_public_u64(&s, e);
            let em_recovered = m.to_be_bytes();
            let digest = crate::pkcs1_v15::sha256_digest(msg)?;
            let mut em_expected = [0u8; MODULUS_BYTES];
            if crate::pkcs1_v15::encode_sha256(&digest, &mut em_expected).is_none() {
                return Ok(false);
            }
            Ok(crate::pkcs1_v15::ct_eq(&em_recovered, &em_expected) == 1)
        }

        // ────────── Core sign primitive (no operational gate) ──────

        /// RSASSA-PKCS1-v1_5 sign via direct `m^d mod n` ladder.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn pkcs1_v15_sign_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            d_bytes: &[u8; MODULUS_BYTES],
            msg: &[u8],
        ) -> Result<[u8; SIGNATURE_BYTES], Error> {
            require_self_test_started()?;
            pkcs1_v15_sign_internal_unguarded(n_bytes, d_bytes, msg)?.ok_or(Error::InvalidInput)
        }

        /// Body of [`pkcs1_v15_sign_internal`], run once its guard has passed.
        fn pkcs1_v15_sign_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            d_bytes: &[u8; MODULUS_BYTES],
            msg: &[u8],
        ) -> Result<Option<[u8; SIGNATURE_BYTES]>, Error> {
            let n = $full::from_be_bytes(n_bytes);
            let Some(ctx) = $fmont::new(n) else {
                return Ok(None);
            };
            let d = $full::from_be_bytes(d_bytes);
            if d.ct_lt(&ctx.n) != 1 {
                return Ok(None);
            }
            let digest = crate::pkcs1_v15::sha256_digest(msg)?;
            let mut em = [0u8; MODULUS_BYTES];
            if crate::pkcs1_v15::encode_sha256(&digest, &mut em).is_none() {
                return Ok(None);
            }
            let m = $full::from_be_bytes(&em);
            let s = ctx.pow_secret(&m, &d);
            Ok(Some(s.to_be_bytes()))
        }

        // ────────── Core PSS sign primitive ────────────────────

        /// RSASSA-PSS sign with caller-supplied salt.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn pss_sign_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            d_bytes: &[u8; MODULUS_BYTES],
            msg: &[u8],
            salt: &[u8; crate::pss::SLEN],
        ) -> Result<[u8; SIGNATURE_BYTES], Error> {
            require_self_test_started()?;
            pss_sign_internal_unguarded(n_bytes, d_bytes, msg, salt)?.ok_or(Error::InvalidInput)
        }

        /// Body of [`pss_sign_internal`], run once its guard has passed.
        fn pss_sign_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            d_bytes: &[u8; MODULUS_BYTES],
            msg: &[u8],
            salt: &[u8; crate::pss::SLEN],
        ) -> Result<Option<[u8; SIGNATURE_BYTES]>, Error> {
            let n = $full::from_be_bytes(n_bytes);
            let Some(ctx) = $fmont::new(n) else {
                return Ok(None);
            };
            let d = $full::from_be_bytes(d_bytes);
            if d.ct_lt(&ctx.n) != 1 {
                return Ok(None);
            }
            let digest = crate::pkcs1_v15::sha256_digest(msg)?;
            let mut em = [0u8; $emlen];
            if crate::pss::emsa_pss_encode_n(&digest, salt, $embits, &mut em)?.is_none() {
                return Ok(None);
            }
            let m = $full::from_be_bytes(&em);
            let s = ctx.pow_secret(&m, &d);
            Ok(Some(s.to_be_bytes()))
        }

        // ────────── PSS verify ─────────────────────────────────

        /// RSASSA-PSS verify.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn pss_verify_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            msg: &[u8],
            sig_bytes: &[u8; SIGNATURE_BYTES],
        ) -> Result<bool, Error> {
            require_self_test_started()?;
            pss_verify_internal_unguarded(n_bytes, e, msg, sig_bytes)
        }

        /// Body of [`pss_verify_internal`], run once its guard has passed.
        fn pss_verify_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            msg: &[u8],
            sig_bytes: &[u8; SIGNATURE_BYTES],
        ) -> Result<bool, Error> {
            let n = $full::from_be_bytes(n_bytes);
            let Some(ctx) = $fmont::new(n) else {
                return Ok(false);
            };
            let s = $full::from_be_bytes(sig_bytes);
            if s.ct_lt(&ctx.n) != 1 {
                return Ok(false);
            }
            let m = ctx.pow_public_u64(&s, e);
            let em = m.to_be_bytes();
            let digest = crate::pkcs1_v15::sha256_digest(msg)?;
            crate::pss::emsa_pss_verify_n(&digest, $embits, &em)
        }

        // ────────── CRT private exponent + Bellcore ────────────

        /// Core CRT private-exponent primitive with Bellcore verify.
        #[doc(hidden)]
        #[allow(
            clippy::many_single_char_names,
            clippy::similar_names,
            clippy::single_char_lifetime_names
        )]
        pub(crate) fn crt_private_exp_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            crt: $crt_raw<'_>,
            input: &[u8; MODULUS_BYTES],
        ) -> Option<[u8; MODULUS_BYTES]> {
            let n = $full::from_be_bytes(n_bytes);
            let ctx_n = $fmont::new(n)?;

            let p = $half::from_be_bytes(crt.p);
            let q = $half::from_be_bytes(crt.q);
            let ctx_p = $hmont::new(p)?;
            let ctx_q = $hmont::new(q)?;

            let dp = $half::from_be_bytes(crt.dp);
            let dq = $half::from_be_bytes(crt.dq);
            let qinv = $half::from_be_bytes(crt.qinv);

            let x = $full::from_be_bytes(input);
            if x.ct_lt(&ctx_n.n) != 1 {
                return None;
            }

            // Reduce x mod p and x mod q.
            let x_p = $half_reduce(&x, &p);
            let x_q = $half_reduce(&x, &q);

            // Secret-exponent exponentiations mod p and mod q.
            let y_p = ctx_p.pow_secret(&x_p, &dp);
            let y_q = ctx_q.pow_secret(&x_q, &dq);

            // Garner recombine.
            let y_q_mod_p = if y_q.ct_lt(&p) == 1 {
                y_q
            } else {
                y_q.subtracting(&p).0
            };

            let diff = if y_p.ct_lt(&y_q_mod_p) == 1 {
                let (sum, _) = y_p.adding(&p);
                sum.subtracting(&y_q_mod_p).0
            } else {
                y_p.subtracting(&y_q_mod_p).0
            };

            let diff_mont = ctx_p.to_mont(&diff);
            let qinv_mont = ctx_p.to_mont(&qinv);
            let h_mont = ctx_p.mont_mul(&qinv_mont, &diff_mont);
            let h = ctx_p.from_mont(&h_mont);

            let qh = q.widening_mul(&h);
            let yq_wide = half_into_full_low(&y_q);
            let (y, _carry) = qh.adding(&yq_wide);

            // Bellcore verify-after-exponent.
            let x_check = ctx_n.pow_public_u64(&y, e);
            if x_check.ct_eq(&x) != 1 {
                return None;
            }

            Some(y.to_be_bytes())
        }

        // ──── CRT sign wrappers ────────────────────────────────

        /// PKCS1v1.5 sign via CRT path.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        #[allow(clippy::too_many_arguments, clippy::similar_names)]
        pub fn pkcs1_v15_sign_crt_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            p_bytes: &[u8; CRT_HALF_BYTES],
            q_bytes: &[u8; CRT_HALF_BYTES],
            dp_bytes: &[u8; CRT_HALF_BYTES],
            dq_bytes: &[u8; CRT_HALF_BYTES],
            qinv_bytes: &[u8; CRT_HALF_BYTES],
            msg: &[u8],
        ) -> Result<[u8; SIGNATURE_BYTES], Error> {
            require_self_test_started()?;
            pkcs1_v15_sign_crt_internal_unguarded(
                n_bytes, e, p_bytes, q_bytes, dp_bytes, dq_bytes, qinv_bytes, msg,
            )?
            .ok_or(Error::InvalidInput)
        }

        /// Body of [`pkcs1_v15_sign_crt_internal`], run once its guard has passed.
        #[allow(clippy::too_many_arguments, clippy::similar_names)]
        fn pkcs1_v15_sign_crt_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            p_bytes: &[u8; CRT_HALF_BYTES],
            q_bytes: &[u8; CRT_HALF_BYTES],
            dp_bytes: &[u8; CRT_HALF_BYTES],
            dq_bytes: &[u8; CRT_HALF_BYTES],
            qinv_bytes: &[u8; CRT_HALF_BYTES],
            msg: &[u8],
        ) -> Result<Option<[u8; SIGNATURE_BYTES]>, Error> {
            let digest = crate::pkcs1_v15::sha256_digest(msg)?;
            let mut em = [0u8; MODULUS_BYTES];
            if crate::pkcs1_v15::encode_sha256(&digest, &mut em).is_none() {
                return Ok(None);
            }
            let crt = $crt_raw {
                p: p_bytes,
                q: q_bytes,
                dp: dp_bytes,
                dq: dq_bytes,
                qinv: qinv_bytes,
            };
            Ok(crt_private_exp_internal(n_bytes, e, crt, &em))
        }

        /// PSS sign via CRT path.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        #[allow(clippy::too_many_arguments, clippy::similar_names)]
        pub fn pss_sign_crt_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            p_bytes: &[u8; CRT_HALF_BYTES],
            q_bytes: &[u8; CRT_HALF_BYTES],
            dp_bytes: &[u8; CRT_HALF_BYTES],
            dq_bytes: &[u8; CRT_HALF_BYTES],
            qinv_bytes: &[u8; CRT_HALF_BYTES],
            msg: &[u8],
            salt: &[u8; crate::pss::SLEN],
        ) -> Result<[u8; SIGNATURE_BYTES], Error> {
            require_self_test_started()?;
            pss_sign_crt_internal_unguarded(
                n_bytes, e, p_bytes, q_bytes, dp_bytes, dq_bytes, qinv_bytes, msg, salt,
            )?
            .ok_or(Error::InvalidInput)
        }

        /// Body of [`pss_sign_crt_internal`], run once its guard has passed.
        #[allow(clippy::too_many_arguments, clippy::similar_names)]
        fn pss_sign_crt_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            p_bytes: &[u8; CRT_HALF_BYTES],
            q_bytes: &[u8; CRT_HALF_BYTES],
            dp_bytes: &[u8; CRT_HALF_BYTES],
            dq_bytes: &[u8; CRT_HALF_BYTES],
            qinv_bytes: &[u8; CRT_HALF_BYTES],
            msg: &[u8],
            salt: &[u8; crate::pss::SLEN],
        ) -> Result<Option<[u8; SIGNATURE_BYTES]>, Error> {
            let digest = crate::pkcs1_v15::sha256_digest(msg)?;
            let mut em = [0u8; $emlen];
            if crate::pss::emsa_pss_encode_n(&digest, salt, $embits, &mut em)?.is_none() {
                return Ok(None);
            }
            let crt = $crt_raw {
                p: p_bytes,
                q: q_bytes,
                dp: dp_bytes,
                dq: dq_bytes,
                qinv: qinv_bytes,
            };
            Ok(crt_private_exp_internal(n_bytes, e, crt, &em))
        }

        // ──── OAEP encrypt / decrypt ───────────────────────────

        /// RSAES-OAEP encrypt with caller-supplied seed.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn oaep_encrypt_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            label: &[u8],
            msg: &[u8],
            seed: &[u8; crate::oaep::HLEN],
        ) -> Result<[u8; MODULUS_BYTES], Error> {
            require_self_test_started()?;
            oaep_encrypt_internal_unguarded(n_bytes, e, label, msg, seed)?
                .ok_or(Error::InvalidInput)
        }

        /// Body of [`oaep_encrypt_internal`], run once its guard has passed.
        fn oaep_encrypt_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            label: &[u8],
            msg: &[u8],
            seed: &[u8; crate::oaep::HLEN],
        ) -> Result<Option<[u8; MODULUS_BYTES]>, Error> {
            let n = $full::from_be_bytes(n_bytes);
            let Some(ctx_n) = $fmont::new(n) else {
                return Ok(None);
            };
            let mut em = [0u8; OAEP_K];
            if crate::oaep::emsa_oaep_encode_n(label, msg, seed, &mut em)?.is_none() {
                return Ok(None);
            }
            let m = $full::from_be_bytes(&em);
            let c = ctx_n.pow_public_u64(&m, e);
            Ok(Some(c.to_be_bytes()))
        }

        /// RSAES-OAEP decrypt (non-CRT path).
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn oaep_decrypt_nocrt_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            d_bytes: &[u8; MODULUS_BYTES],
            label: &[u8],
            ct: &[u8; MODULUS_BYTES],
            out: &mut [u8],
        ) -> Result<usize, Error> {
            require_self_test_started()?;
            oaep_decrypt_nocrt_internal_unguarded(n_bytes, d_bytes, label, ct, out)?
                .ok_or(Error::InvalidInput)
        }

        /// Body of [`oaep_decrypt_nocrt_internal`], run once its guard has passed.
        fn oaep_decrypt_nocrt_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            d_bytes: &[u8; MODULUS_BYTES],
            label: &[u8],
            ct: &[u8; MODULUS_BYTES],
            out: &mut [u8],
        ) -> Result<Option<usize>, Error> {
            let n = $full::from_be_bytes(n_bytes);
            let Some(ctx_n) = $fmont::new(n) else {
                return Ok(None);
            };
            let d = $full::from_be_bytes(d_bytes);
            if d.ct_lt(&ctx_n.n) != 1 {
                return Ok(None);
            }
            let c = $full::from_be_bytes(ct);
            if c.ct_lt(&ctx_n.n) != 1 {
                return Ok(None);
            }
            let m = ctx_n.pow_secret(&c, &d);
            let em = m.to_be_bytes();
            crate::oaep::emsa_oaep_decode_n(label, &em, out)
        }

        /// RSAES-OAEP decrypt via CRT path with Bellcore.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        #[allow(clippy::too_many_arguments, clippy::similar_names)]
        pub fn oaep_decrypt_crt_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            p_bytes: &[u8; CRT_HALF_BYTES],
            q_bytes: &[u8; CRT_HALF_BYTES],
            dp_bytes: &[u8; CRT_HALF_BYTES],
            dq_bytes: &[u8; CRT_HALF_BYTES],
            qinv_bytes: &[u8; CRT_HALF_BYTES],
            label: &[u8],
            ct: &[u8; MODULUS_BYTES],
            out: &mut [u8],
        ) -> Result<usize, Error> {
            require_self_test_started()?;
            oaep_decrypt_crt_internal_unguarded(
                n_bytes, e, p_bytes, q_bytes, dp_bytes, dq_bytes, qinv_bytes, label, ct, out,
            )?
            .ok_or(Error::InvalidInput)
        }

        /// Body of [`oaep_decrypt_crt_internal`], run once its guard has passed.
        #[allow(clippy::too_many_arguments, clippy::similar_names)]
        fn oaep_decrypt_crt_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            p_bytes: &[u8; CRT_HALF_BYTES],
            q_bytes: &[u8; CRT_HALF_BYTES],
            dp_bytes: &[u8; CRT_HALF_BYTES],
            dq_bytes: &[u8; CRT_HALF_BYTES],
            qinv_bytes: &[u8; CRT_HALF_BYTES],
            label: &[u8],
            ct: &[u8; MODULUS_BYTES],
            out: &mut [u8],
        ) -> Result<Option<usize>, Error> {
            let crt = $crt_raw {
                p: p_bytes,
                q: q_bytes,
                dp: dp_bytes,
                dq: dq_bytes,
                qinv: qinv_bytes,
            };
            let Some(em) = crt_private_exp_internal(n_bytes, e, crt, ct) else {
                return Ok(None);
            };
            crate::oaep::emsa_oaep_decode_n(label, &em, out)
        }

        // ──── Pairwise Consistency Test ────────────────────────

        /// IG 10.3.A PCT: sign a probe, verify it back.
        ///
        /// Returns [`Error::NotOperational`] unless
        /// [`oxicrypt_module::require_self_test_started`] admits the call: in
        /// `Operational`, or in `SelfTest` on the thread running the power-up
        /// self-tests.
        #[doc(hidden)]
        pub fn pairwise_consistency_test_internal(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            d_bytes: &[u8; MODULUS_BYTES],
        ) -> Result<bool, Error> {
            require_self_test_started()?;
            pairwise_consistency_test_internal_unguarded(n_bytes, e, d_bytes)
        }

        /// Body of [`pairwise_consistency_test_internal`], run once its guard has passed.
        fn pairwise_consistency_test_internal_unguarded(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            d_bytes: &[u8; MODULUS_BYTES],
        ) -> Result<bool, Error> {
            const PROBE: &[u8] = concat!(
                "fips-rsa PCT probe / RSA-",
                stringify!($nlen),
                " / PKCS#1 v1.5 / SHA-256"
            )
            .as_bytes();
            let Some(sig) = pkcs1_v15_sign_internal_unguarded(n_bytes, d_bytes, PROBE)? else {
                return Ok(false);
            };
            pkcs1_v15_verify_internal_unguarded(n_bytes, e, PROBE, &sig)
        }

        // ──── Public gated wrappers ────────────────────────────

        /// Verify an RSASSA-PKCS1-v1_5 signature.
        pub fn pkcs1_v15_verify(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            msg: &[u8],
            sig_bytes: &[u8; SIGNATURE_BYTES],
        ) -> Result<(), Error> {
            require_operational()?;
            require_allowed($svc_pkcs1_verify)?;
            if pkcs1_v15_verify_internal_unguarded(n_bytes, e, msg, sig_bytes)? {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            }
        }

        /// Verify an RSASSA-PSS signature.
        pub fn pss_verify(
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            msg: &[u8],
            sig_bytes: &[u8; SIGNATURE_BYTES],
        ) -> Result<(), Error> {
            require_operational()?;
            require_allowed($svc_pss_verify)?;
            if pss_verify_internal_unguarded(n_bytes, e, msg, sig_bytes)? {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            }
        }

        /// Encrypt with RSAES-OAEP SHA-256, sampling the seed from a DRBG.
        pub fn oaep_encrypt(
            drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
            n_bytes: &[u8; MODULUS_BYTES],
            e: u64,
            label: &[u8],
            msg: &[u8],
        ) -> Result<[u8; MODULUS_BYTES], Error> {
            require_operational()?;
            require_allowed($svc_oaep)?;
            let mut seed = [0u8; crate::oaep::HLEN];
            drbg.generate(None, &mut seed).map_err(|e| match e {
                oxicrypt_drbg::DrbgError::Module(e) => e,
                _ => Error::InvalidInput,
            })?;
            oaep_encrypt_internal_unguarded(n_bytes, e, label, msg, &seed)?
                .ok_or(Error::InvalidInput)
        }

        // ──── Private-key handle ───────────────────────────────

        /// A validated RSA private key suitable for signing and decryption.
        ///
        /// Construction runs the FIPS 140-3 IG 10.3.A pairwise consistency
        /// test. When CRT components are present, signing uses the
        /// Garner-recombine path with Bellcore verify-after-sign per
        /// FIPS 140-3 IG D.G.
        #[derive(Clone)]
        pub struct $key_struct {
            n_bytes: [u8; MODULUS_BYTES],
            d_bytes: [u8; MODULUS_BYTES],
            e: u64,
            crt: Option<$crt_struct>,
        }

        impl Drop for $key_struct {
            fn drop(&mut self) {
                oxicrypt_zeroize::zeroize(&mut self.d_bytes);
            }
        }

        impl $key_struct {
            /// Build from raw `(n, e, d)` components. Runs PCT.
            pub fn from_components(
                n_bytes: &[u8; MODULUS_BYTES],
                e: u64,
                d_bytes: &[u8; MODULUS_BYTES],
            ) -> Result<Self, Error> {
                require_operational()?;
                require_allowed($svc_keygen)?;
                if !pairwise_consistency_test_internal_unguarded(n_bytes, e, d_bytes)? {
                    return Err(Error::InvalidInput);
                }
                Ok(Self {
                    n_bytes: *n_bytes,
                    d_bytes: *d_bytes,
                    e,
                    crt: None,
                })
            }

            /// Build from raw CRT components. PCT runs on the CRT path.
            #[allow(clippy::too_many_arguments, clippy::similar_names)]
            pub fn from_components_crt(
                n_bytes: &[u8; MODULUS_BYTES],
                e: u64,
                d_bytes: &[u8; MODULUS_BYTES],
                p_bytes: &[u8; CRT_HALF_BYTES],
                q_bytes: &[u8; CRT_HALF_BYTES],
                dp_bytes: &[u8; CRT_HALF_BYTES],
                dq_bytes: &[u8; CRT_HALF_BYTES],
                qinv_bytes: &[u8; CRT_HALF_BYTES],
            ) -> Result<Self, Error> {
                require_operational()?;
                require_allowed($svc_keygen)?;
                let probe: &[u8] = concat!(
                    "fips-rsa CRT PCT probe / RSA-",
                    stringify!($nlen),
                    " / PKCS#1 v1.5 / SHA-256"
                )
                .as_bytes();
                let Some(sig) = pkcs1_v15_sign_crt_internal_unguarded(
                    n_bytes, e, p_bytes, q_bytes, dp_bytes, dq_bytes, qinv_bytes, probe,
                )?
                else {
                    return Err(Error::InvalidInput);
                };
                if !pkcs1_v15_verify_internal_unguarded(n_bytes, e, probe, &sig)? {
                    return Err(Error::InvalidInput);
                }
                Ok(Self {
                    n_bytes: *n_bytes,
                    d_bytes: *d_bytes,
                    e,
                    crt: Some($crt_struct {
                        p_bytes: *p_bytes,
                        q_bytes: *q_bytes,
                        dp_bytes: *dp_bytes,
                        dq_bytes: *dq_bytes,
                        qinv_bytes: *qinv_bytes,
                    }),
                })
            }

            /// Public modulus, big-endian.
            ///
            /// # Errors
            ///
            /// Returns [`Error::NotOperational`] unless
            /// [`oxicrypt_module::require_self_test_started`] admits the call (in
            /// `Operational`, or in `SelfTest` on the thread running the power-up
            /// self-tests), so a key built before a failure outputs nothing after it.
            pub fn modulus_bytes(&self) -> Result<&[u8; MODULUS_BYTES], Error> {
                require_self_test_started()?;
                Ok(&self.n_bytes)
            }

            /// Public exponent.
            ///
            /// # Errors
            ///
            /// Returns [`Error::NotOperational`] unless
            /// [`oxicrypt_module::require_self_test_started`] admits the call (in
            /// `Operational`, or in `SelfTest` on the thread running the power-up
            /// self-tests), so a key built before a failure outputs nothing after it.
            pub fn public_exponent(&self) -> Result<u64, Error> {
                require_self_test_started()?;
                Ok(self.e)
            }

            /// Sign with RSASSA-PKCS1-v1_5 SHA-256.
            pub fn sign_pkcs1_v15_sha256(
                &self,
                msg: &[u8],
            ) -> Result<[u8; SIGNATURE_BYTES], Error> {
                require_operational()?;
                require_allowed($svc_pkcs1_sign)?;
                if let Some(crt) = self.crt.as_ref() {
                    pkcs1_v15_sign_crt_internal_unguarded(
                        &self.n_bytes,
                        self.e,
                        &crt.p_bytes,
                        &crt.q_bytes,
                        &crt.dp_bytes,
                        &crt.dq_bytes,
                        &crt.qinv_bytes,
                        msg,
                    )?
                    .ok_or(Error::InvalidInput)
                } else {
                    pkcs1_v15_sign_internal_unguarded(&self.n_bytes, &self.d_bytes, msg)?
                        .ok_or(Error::InvalidInput)
                }
            }

            /// Sign with RSASSA-PSS SHA-256, caller-supplied salt.
            pub fn sign_pss_sha256_with_salt(
                &self,
                msg: &[u8],
                salt: &[u8; crate::pss::SLEN],
            ) -> Result<[u8; SIGNATURE_BYTES], Error> {
                require_operational()?;
                require_allowed($svc_pss_sign)?;
                if let Some(crt) = self.crt.as_ref() {
                    pss_sign_crt_internal_unguarded(
                        &self.n_bytes,
                        self.e,
                        &crt.p_bytes,
                        &crt.q_bytes,
                        &crt.dp_bytes,
                        &crt.dq_bytes,
                        &crt.qinv_bytes,
                        msg,
                        salt,
                    )?
                    .ok_or(Error::InvalidInput)
                } else {
                    pss_sign_internal_unguarded(&self.n_bytes, &self.d_bytes, msg, salt)?
                        .ok_or(Error::InvalidInput)
                }
            }

            /// Sign with RSASSA-PSS SHA-256, DRBG-sampled salt.
            pub fn sign_pss_sha256(
                &self,
                drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
                msg: &[u8],
            ) -> Result<[u8; SIGNATURE_BYTES], Error> {
                require_operational()?;
                require_allowed($svc_pss_sign)?;
                let mut salt = [0u8; crate::pss::SLEN];
                drbg.generate(None, &mut salt).map_err(|e| match e {
                    oxicrypt_drbg::DrbgError::Module(e) => e,
                    _ => Error::InvalidInput,
                })?;
                if let Some(crt) = self.crt.as_ref() {
                    pss_sign_crt_internal_unguarded(
                        &self.n_bytes,
                        self.e,
                        &crt.p_bytes,
                        &crt.q_bytes,
                        &crt.dp_bytes,
                        &crt.dq_bytes,
                        &crt.qinv_bytes,
                        msg,
                        &salt,
                    )?
                    .ok_or(Error::InvalidInput)
                } else {
                    pss_sign_internal_unguarded(&self.n_bytes, &self.d_bytes, msg, &salt)?
                        .ok_or(Error::InvalidInput)
                }
            }

            /// Decrypt an RSAES-OAEP SHA-256 ciphertext.
            pub fn decrypt_oaep_sha256(
                &self,
                label: &[u8],
                ct: &[u8; MODULUS_BYTES],
                out: &mut [u8],
            ) -> Result<usize, Error> {
                require_operational()?;
                require_allowed($svc_oaep)?;
                if out.len() < OAEP_MAX_MSG_LEN {
                    return Err(Error::InvalidInput);
                }
                if let Some(crt) = self.crt.as_ref() {
                    oaep_decrypt_crt_internal_unguarded(
                        &self.n_bytes,
                        self.e,
                        &crt.p_bytes,
                        &crt.q_bytes,
                        &crt.dp_bytes,
                        &crt.dq_bytes,
                        &crt.qinv_bytes,
                        label,
                        ct,
                        out,
                    )?
                    .ok_or(Error::InvalidInput)
                } else {
                    oaep_decrypt_nocrt_internal_unguarded(
                        &self.n_bytes,
                        &self.d_bytes,
                        label,
                        ct,
                        out,
                    )?
                    .ok_or(Error::InvalidInput)
                }
            }

            /// Generate a fresh keypair from a DRBG.
            #[allow(clippy::similar_names)]
            pub fn generate(
                drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
                e: u64,
            ) -> Result<Self, Error> {
                require_operational()?;
                require_allowed($svc_keygen)?;
                let km = $keygen_fn(drbg, e).map_err(|e| match e {
                    crate::keygen::KeygenError::Drbg(oxicrypt_drbg::DrbgError::Module(e))
                    | crate::keygen::KeygenError::Module(e) => e,
                    _ => Error::InvalidInput,
                })?;
                let n_bytes = km.n.to_be_bytes();
                let d_bytes = km.d.to_be_bytes();
                let p_bytes = km.p.to_be_bytes();
                let q_bytes = km.q.to_be_bytes();
                let dp_bytes = km.dp.to_be_bytes();
                let dq_bytes = km.dq.to_be_bytes();
                let qinv_bytes = km.qinv.to_be_bytes();
                Self::from_components_crt(
                    &n_bytes,
                    e,
                    &d_bytes,
                    &p_bytes,
                    &q_bytes,
                    &dp_bytes,
                    &dq_bytes,
                    &qinv_bytes,
                )
            }
        }
    };
}

pub(crate) use define_rsa_wide;
