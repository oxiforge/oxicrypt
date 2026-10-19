//! HMAC_DRBG — NIST SP 800-90A Rev. 1 §10.1.2.
//!
//! Implements HMAC_DRBG over the approved SHA-2 digests covered by
//! this module: SHA-256, SHA-384, and SHA-512. The mechanism is
//! parameterised over a [`HmacAlg`] trait abstraction so that
//! different digests share a single `HmacDrbg<H>` state machine.
//!
//! The `HMAC_DRBG_Update` helper (§10.1.2.2) is implemented directly
//! and is the only place where the underlying HMAC primitive is
//! invoked during `instantiate`, `reseed`, and `generate`.
//!
//! Working state (`Key`, `V`) is stored in fixed-size buffers sized
//! to the largest supported digest (SHA-512 = 64 bytes). Each
//! variant only reads/writes the leftmost `OUTLEN` bytes.
//!
//! Power-up KATs reach HMAC through the `new_internal` constructors from
//! `oxicrypt-hmac`, which skip the operational gate and refuse unless
//! [`oxicrypt_module::require_self_test_started`] admits the call: in
//! `Operational`, or in `SelfTest` on the thread running the power-up
//! self-tests.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use core::marker::PhantomData;

use oxicrypt_hmac::{HmacSha256, HmacSha384, HmacSha512};
use oxicrypt_module::{Error, Service, require_allowed, require_operational};

use crate::ctr::DrbgError;

/// Maximum HMAC output length across supported algorithms (SHA-512).
const MAX_OUTLEN: usize = 64;
/// Upper bound on `provided_data` passed to `HMAC_DRBG_Update` for
/// power-up KATs and internal use. Bounds the stack scratch buffer that
/// instantiate / reseed / generate use to assemble `provided_data`
/// before calling `HMAC_DRBG_Update`.
pub const HMAC_DRBG_MAX_PROVIDED: usize = 768;
/// SP 800-90A Table 2 reseed interval for HMAC_DRBG: 2^48 requests.
const HMAC_DRBG_RESEED_INTERVAL: u64 = 1u64 << 48;
/// Maximum output bytes per single `generate` call.
const HMAC_DRBG_MAX_BITS_PER_REQ: usize = 1 << 16;
/// Instantiated security strength in bytes (256 bits): the highest
/// strength SP 800-57 Part 1 assigns HMAC over SHA-256, SHA-384 and
/// SHA-512, and the only strength this crate instantiates.
const SECURITY_STRENGTH: usize = 32;
/// Minimum entropy input length in bytes for instantiate and reseed:
/// the security strength (SP 800-90A Rev. 1 Table 2 `min_length`).
const MIN_ENTROPY_LEN: usize = SECURITY_STRENGTH;
/// Minimum nonce length in bytes for instantiate: half the security
/// strength. This floor is the module's nonce check, which SP 800-90A
/// Rev. 1 §9.1 step 8 permits; a nonce of this length can carry the
/// `security_strength / 2` bits of entropy that §8.6.7(a) asks for.
/// §8.6.7(b) also accepts a shorter value that repeats no more often
/// than a random string of that length would; the module refuses it.
/// The strength is even, so the division is exact.
#[allow(clippy::integer_division)]
const MIN_NONCE_LEN: usize = SECURITY_STRENGTH / 2;

/// Trait describing a concrete HMAC variant used by HMAC_DRBG.
///
/// An impl must provide a stateless one-shot HMAC:
/// `mac(key, parts)` computes `HMAC_H(key, parts[0] || parts[1] || ...)`
/// and writes exactly `OUTLEN` bytes to `out`.
pub trait HmacAlg {
    /// HMAC output length in bytes.
    const OUTLEN: usize;
    /// The FIPS module service gate associated with this HMAC algorithm.
    const DRBG_SERVICE: Service;
    /// Compute `HMAC(key, parts concatenated)` into `out[..OUTLEN]`.
    ///
    /// `out.len()` must be `>= OUTLEN`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call (in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests); the HMAC is built by `oxicrypt-hmac`'s `new_internal`.
    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error>;
}

/// `HmacAlg` over HMAC-SHA-256.
pub struct HmacSha256Alg;
/// `HmacAlg` over HMAC-SHA-384.
pub struct HmacSha384Alg;
/// `HmacAlg` over HMAC-SHA-512.
pub struct HmacSha512Alg;

impl HmacAlg for HmacSha256Alg {
    const OUTLEN: usize = 32;
    const DRBG_SERVICE: Service = Service::HmacDrbgSha256;
    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
        let mut h = HmacSha256::new_internal(key)?;
        for p in parts {
            h.update(p);
        }
        let tag = h.finalize()?;
        out[..32].copy_from_slice(&tag);
        Ok(())
    }
}

impl HmacAlg for HmacSha384Alg {
    const OUTLEN: usize = 48;
    const DRBG_SERVICE: Service = Service::HmacDrbgSha384;
    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
        let mut h = HmacSha384::new_internal(key)?;
        for p in parts {
            h.update(p);
        }
        let tag = h.finalize()?;
        out[..48].copy_from_slice(&tag);
        Ok(())
    }
}

impl HmacAlg for HmacSha512Alg {
    const OUTLEN: usize = 64;
    const DRBG_SERVICE: Service = Service::HmacDrbgSha512;
    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
        let mut h = HmacSha512::new_internal(key)?;
        for p in parts {
            h.update(p);
        }
        let tag = h.finalize()?;
        out[..64].copy_from_slice(&tag);
        Ok(())
    }
}

/// HMAC_DRBG instance parameterised by an [`HmacAlg`].
pub struct HmacDrbg<H: HmacAlg> {
    key: [u8; MAX_OUTLEN],
    v: [u8; MAX_OUTLEN],
    reseed_counter: u64,
    instantiated: bool,
    _marker: PhantomData<H>,
}

/// HMAC_DRBG over HMAC-SHA-256.
pub type HmacDrbgSha256 = HmacDrbg<HmacSha256Alg>;
/// HMAC_DRBG over HMAC-SHA-384.
pub type HmacDrbgSha384 = HmacDrbg<HmacSha384Alg>;
/// HMAC_DRBG over HMAC-SHA-512.
pub type HmacDrbgSha512 = HmacDrbg<HmacSha512Alg>;

impl<H: HmacAlg> HmacDrbg<H> {
    /// Create an empty, uninstantiated HMAC_DRBG slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            key: [0u8; MAX_OUTLEN],
            v: [0u8; MAX_OUTLEN],
            reseed_counter: 0,
            instantiated: false,
            _marker: PhantomData,
        }
    }

    /// `HMAC_DRBG_Update(provided_data, Key, V)` — SP 800-90A §10.1.2.2.
    ///
    /// `provided_data == None` corresponds to the "Null" case where
    /// only the first pair of HMAC calls runs.
    fn update(&mut self, provided_data: Option<&[u8]>) -> Result<(), Error> {
        let outlen = H::OUTLEN;
        // Step 1: K = HMAC(K, V || 0x00 || provided_data)
        let sep0 = [0x00u8];
        let mut new_key = [0u8; MAX_OUTLEN];
        let v_slice = {
            // Separate the &self field borrow into a stack copy so
            // we can mutate self.key below.
            let mut tmp = [0u8; MAX_OUTLEN];
            tmp[..outlen].copy_from_slice(&self.v[..outlen]);
            tmp
        };
        let pd_empty: &[u8] = &[];
        let pd = provided_data.unwrap_or(pd_empty);
        H::mac(
            &self.key[..outlen],
            &[&v_slice[..outlen], &sep0, pd],
            &mut new_key[..outlen],
        )?;
        self.key[..outlen].copy_from_slice(&new_key[..outlen]);

        // Step 2: V = HMAC(K, V)
        let mut new_v = [0u8; MAX_OUTLEN];
        H::mac(
            &self.key[..outlen],
            &[&v_slice[..outlen]],
            &mut new_v[..outlen],
        )?;
        self.v[..outlen].copy_from_slice(&new_v[..outlen]);

        // Step 3: If provided_data is Null, return.
        if provided_data.is_none() {
            return Ok(());
        }

        // Step 4: K = HMAC(K, V || 0x01 || provided_data)
        let sep1 = [0x01u8];
        let v_slice2 = {
            let mut tmp = [0u8; MAX_OUTLEN];
            tmp[..outlen].copy_from_slice(&self.v[..outlen]);
            tmp
        };
        H::mac(
            &self.key[..outlen],
            &[&v_slice2[..outlen], &sep1, pd],
            &mut new_key[..outlen],
        )?;
        self.key[..outlen].copy_from_slice(&new_key[..outlen]);

        // Step 5: V = HMAC(K, V)
        H::mac(
            &self.key[..outlen],
            &[&v_slice2[..outlen]],
            &mut new_v[..outlen],
        )?;
        self.v[..outlen].copy_from_slice(&new_v[..outlen]);
        Ok(())
    }

    /// HMAC_DRBG Instantiate — SP 800-90A §10.1.2.3.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EntropyInputTooShort`] when `entropy` is shorter
    /// than 32 bytes, the 256-bit security strength (SP 800-90A Rev. 1
    /// Table 2 `min_length`), and [`Error::NonceTooShort`] when `nonce`
    /// is shorter than 16 bytes, the module's nonce floor (see
    /// `MIN_NONCE_LEN`). Personalization never counts toward either
    /// minimum. An over-long combined input returns
    /// [`Error::InvalidInput`] even when one of them is also short. A
    /// refusal by any of these length checks leaves the DRBG
    /// uninstantiated.
    pub fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<(), Error> {
        require_operational()?;
        require_allowed(H::DRBG_SERVICE)?;
        self.instantiate_internal(entropy, nonce, personalization)
    }

    /// Internal instantiate function used by KAT runners.
    pub(crate) fn instantiate_internal(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<(), Error> {
        // Any refusal below leaves no instantiation behind: a failed
        // re-instantiate must not leave the earlier seed usable.
        self.uninstantiate();
        let total = entropy
            .len()
            .checked_add(nonce.len())
            .and_then(|n| n.checked_add(personalization.len()))
            .ok_or(Error::InvalidInput)?;
        if total > HMAC_DRBG_MAX_PROVIDED {
            return Err(Error::InvalidInput);
        }
        if entropy.len() < MIN_ENTROPY_LEN {
            return Err(Error::EntropyInputTooShort);
        }
        if nonce.len() < MIN_NONCE_LEN {
            return Err(Error::NonceTooShort);
        }
        let outlen = H::OUTLEN;
        // Key = 0x00^outlen, V = 0x01^outlen.
        self.key = [0u8; MAX_OUTLEN];
        self.v = [0u8; MAX_OUTLEN];
        for i in 0..outlen {
            self.v[i] = 0x01;
        }
        // seed_material = entropy || nonce || pers
        let mut seed_material = [0u8; HMAC_DRBG_MAX_PROVIDED];
        seed_material[..entropy.len()].copy_from_slice(entropy);
        seed_material[entropy.len()..entropy.len() + nonce.len()].copy_from_slice(nonce);
        let off = entropy.len() + nonce.len();
        seed_material[off..off + personalization.len()].copy_from_slice(personalization);
        // (Key, V) = Update(seed_material, Key, V)
        let seed = &seed_material[..total];
        // NB: provided_data is never Null for instantiate since seed
        // is always constructed (possibly length 0). Per the spec,
        // an empty-but-present provided_data still runs the full
        // two-round update; we reflect that by passing Some(&[]).
        self.update(Some(seed))?;
        self.reseed_counter = 1;
        self.instantiated = true;
        Ok(())
    }

    /// HMAC_DRBG Reseed — SP 800-90A §10.1.2.4.
    ///
    /// # Errors
    ///
    /// Returns [`DrbgError::Uninstantiated`] before any length check,
    /// [`DrbgError::InputTooLong`] when `entropy || additional_input` is
    /// over-long, and otherwise [`DrbgError::EntropyInputTooShort`] when
    /// `entropy` is shorter than 32 bytes, the 256-bit security strength
    /// (SP 800-90A Rev. 1 Table 2 `min_length`). Additional input never
    /// counts toward the minimum.
    pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        let total = entropy
            .len()
            .checked_add(additional_input.len())
            .ok_or(DrbgError::InputTooLong)?;
        if total > HMAC_DRBG_MAX_PROVIDED {
            return Err(DrbgError::InputTooLong);
        }
        if entropy.len() < MIN_ENTROPY_LEN {
            return Err(DrbgError::EntropyInputTooShort);
        }
        let mut seed_material = [0u8; HMAC_DRBG_MAX_PROVIDED];
        seed_material[..entropy.len()].copy_from_slice(entropy);
        seed_material[entropy.len()..entropy.len() + additional_input.len()]
            .copy_from_slice(additional_input);
        self.update(Some(&seed_material[..total]))?;
        self.reseed_counter = 1;
        Ok(())
    }

    /// HMAC_DRBG Generate — SP 800-90A §10.1.2.5.
    pub fn generate(
        &mut self,
        additional_input: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        let result = self.generate_unwiped(additional_input, out);
        if result.is_err() {
            // A failed call leaves no generated bytes in the caller's buffer.
            oxicrypt_zeroize::zeroize(out);
        }
        result
    }

    /// Body of [`Self::generate`]; the caller wipes `out` if it fails.
    fn generate_unwiped(
        &mut self,
        additional_input: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        if out.len() > HMAC_DRBG_MAX_BITS_PER_REQ {
            return Err(DrbgError::RequestTooLong);
        }
        if self.reseed_counter > HMAC_DRBG_RESEED_INTERVAL {
            return Err(DrbgError::ReseedRequired);
        }
        if let Some(ai) = additional_input {
            if ai.len() > HMAC_DRBG_MAX_PROVIDED {
                return Err(DrbgError::InputTooLong);
            }
            // Step 2: if additional_input != Null, Update.
            self.update(Some(ai))?;
        }

        // Step 3/4: produce bytes by V = HMAC(K, V).
        let outlen = H::OUTLEN;
        let mut produced = 0usize;
        let mut v_tmp = [0u8; MAX_OUTLEN];
        while produced < out.len() {
            v_tmp[..outlen].copy_from_slice(&self.v[..outlen]);
            let mut new_v = [0u8; MAX_OUTLEN];
            H::mac(
                &self.key[..outlen],
                &[&v_tmp[..outlen]],
                &mut new_v[..outlen],
            )?;
            self.v[..outlen].copy_from_slice(&new_v[..outlen]);
            let take = core::cmp::min(outlen, out.len() - produced);
            out[produced..produced + take].copy_from_slice(&self.v[..take]);
            produced += take;
        }

        // Step 6: (Key, V) = Update(additional_input, Key, V)
        self.update(additional_input)?;
        self.reseed_counter += 1;
        Ok(())
    }

    /// HMAC_DRBG Generate with prediction resistance —
    /// SP 800-90A §9.3.1 step 7.
    ///
    /// Equivalent to `reseed(entropy, additional_input)` followed by
    /// `generate(None, out)`.
    pub fn generate_pr(
        &mut self,
        entropy: &[u8],
        additional_input: &[u8],
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        self.reseed(entropy, additional_input)?;
        self.generate(None, out)
    }

    /// Zeroise the instance and mark it uninstantiated.
    ///
    /// `Key` and `V` are cleared with the volatile writes of
    /// `oxicrypt-zeroize`, as on drop (SP 800-90A §9.4).
    pub fn uninstantiate(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.key);
        oxicrypt_zeroize::zeroize(&mut self.v);
        self.reseed_counter = 0;
        self.instantiated = false;
    }

    /// Health-test helper: force the reseed counter above the
    /// SP 800-90A §10.1.2 ceiling so the next `generate` call
    /// returns [`DrbgError::ReseedRequired`]. Used only by the
    /// §11.3 power-up health tests.
    #[doc(hidden)]
    pub fn debug_force_reseed_ceiling(&mut self) {
        self.reseed_counter = HMAC_DRBG_RESEED_INTERVAL + 1;
    }
}

impl<H: HmacAlg> Default for HmacDrbg<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HmacAlg> Drop for HmacDrbg<H> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.key);
        oxicrypt_zeroize::zeroize(&mut self.v);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len(), N * 2, "hex length mismatch");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            let hi = hex_nib(bytes[2 * i]);
            let lo = hex_nib(bytes[2 * i + 1]);
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    const fn hex_nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0xff,
        }
    }

    // NIST CAVP HMAC_DRBG no-reseed SHA-256 Count=0.
    #[test]
    fn cavp_hmac_drbg_sha256_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 32] =
            hex_to_bytes("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
        let nonce: [u8; 16] = hex_to_bytes("659ba96c601dc69fc902940805ec0ca8");
        let expected: [u8; 128] = hex_to_bytes(
            "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
        );
        let mut drbg = HmacDrbgSha256::new();
        drbg.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 128];
        drbg.generate(None, &mut out).unwrap();
        drbg.generate(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn cavp_hmac_drbg_sha384_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 32] =
            hex_to_bytes("a1dc2dfeda4f3a1124e0e75ebfbe5f98cac11018221dda3fdcf8f9125d68447a");
        let nonce: [u8; 16] = hex_to_bytes("bae5ea27166540515268a493a96b5187");
        let expected: [u8; 192] = hex_to_bytes(
            "228293e59b1e4545a4ff9f232616fc5108a1128debd0f7c20ace837ca105cbf24c0dac1f9847dafd0d0500721ffad3c684a992d110a549a264d14a8911c50be8cd6a7e8fac783ad95b24f64fd8cc4c8b649eac2b15b363e30df79541a6b8a1caac238949b46643694c85e1d5fcbcd9aaae6260acee660b8a79bea48e079ceb6a5eaf4993a82c3f1b758d7c53e3094eeac63dc255be6dcdcc2b51e5ca45d2b20684a5a8fa5806b96f8461ebf51bc515a7dd8c5475c0e70f2fd0faf7869a99ab6c",
        );
        let mut drbg = HmacDrbgSha384::new();
        drbg.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 192];
        drbg.generate(None, &mut out).unwrap();
        drbg.generate(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // Consistency check for §9.3.1 prediction-resistance generate:
    // `generate_pr(e, ai, out)` must produce the same output as
    // explicit `reseed(e, ai)` followed by `generate(None, out)`.
    #[test]
    fn generate_pr_matches_reseed_then_generate() {
        crate::test_support::start_module();
        let entropy: [u8; 32] = [0x11u8; 32];
        let nonce: [u8; 16] = [0x22u8; 16];
        let reseed_e: [u8; 32] = [0x33u8; 32];
        let reseed_ai: [u8; 8] = [0x44u8; 8];

        let mut a = HmacDrbgSha256::new();
        a.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out_a = [0u8; 64];
        a.generate_pr(&reseed_e, &reseed_ai, &mut out_a).unwrap();

        let mut b = HmacDrbgSha256::new();
        b.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        b.reseed(&reseed_e, &reseed_ai).unwrap();
        let mut out_b = [0u8; 64];
        b.generate(None, &mut out_b).unwrap();

        assert_eq!(out_a, out_b);
    }

    #[test]
    fn cavp_hmac_drbg_sha512_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 32] =
            hex_to_bytes("35049f389a33c0ecb1293238fd951f8ffd517dfde06041d32945b3e26914ba15");
        let nonce: [u8; 16] = hex_to_bytes("f7328760be6168e6aa9fb54784989a11");
        let expected: [u8; 256] = hex_to_bytes(
            "e76491b0260aacfded01ad39fbf1a66a88284caa5123368a2ad9330ee48335e3c9c9ba90e6cbc9429962d60c1a6661edcfaa31d972b8264b9d4562cf18494128a092c17a8da6f3113e8a7edfcd4427082bd390675e9662408144971717303d8dc352c9e8b95e7f35fa2ac9f549b292bc7c4bc7f01ee0a577859ef6e82d79ef23892d167c140d22aac32b64ccdfeee2730528a38763b24227f91ac3ffe47fb11538e435307e77481802b0f613f370ffb0dbeab774fe1efbb1a80d01154a9459e73ad361108bbc86b0914f095136cbe634555ce0bb263618dc5c367291ce0825518987154fe9ecb052b3f0a256fcc30cc14572531c9628973639beda456f2bddf6",
        );
        let mut drbg = HmacDrbgSha512::new();
        drbg.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 256];
        drbg.generate(None, &mut out).unwrap();
        drbg.generate(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// Instantiates `drbg` with `entropy_len` bytes of entropy input and
    /// `nonce_len` bytes of nonce.
    fn instantiate_with<A: HmacAlg>(
        drbg: &mut HmacDrbg<A>,
        entropy_len: usize,
        nonce_len: usize,
    ) -> Result<(), Error> {
        let material = [0x5au8; 64];
        drbg.instantiate_internal(&material[..entropy_len], &material[..nonce_len], &[])
    }

    /// SP 800-90A Rev. 1 Table 2 `min_length` (32 bytes at the 256-bit
    /// security strength) and the module's nonce floor (16 bytes, half the
    /// strength; see `MIN_NONCE_LEN`), each
    /// checked one byte below, exactly at, and with an empty input.
    fn assert_minimums_enforced<A: HmacAlg>() {
        crate::test_support::start_module();
        let fresh = HmacDrbg::<A>::new;

        // Instantiate: entropy input.
        let mut d = fresh();
        assert_eq!(
            instantiate_with(&mut d, 31, 16),
            Err(Error::EntropyInputTooShort)
        );
        assert!(!d.instantiated);
        assert_eq!(
            instantiate_with(&mut d, 0, 16),
            Err(Error::EntropyInputTooShort)
        );
        assert!(!d.instantiated);
        assert_eq!(instantiate_with(&mut d, 32, 16), Ok(()));

        // Instantiate: nonce.
        let mut d = fresh();
        assert_eq!(instantiate_with(&mut d, 32, 15), Err(Error::NonceTooShort));
        assert!(!d.instantiated);
        assert_eq!(instantiate_with(&mut d, 32, 0), Err(Error::NonceTooShort));
        assert!(!d.instantiated);
        assert_eq!(instantiate_with(&mut d, 32, 16), Ok(()));

        // Reseed, directly and through prediction-resistance generate.
        let entropy = [0x6bu8; 32];
        assert_eq!(
            d.reseed(&entropy[..31], &[]),
            Err(DrbgError::EntropyInputTooShort)
        );
        assert_eq!(d.reseed(&[], &[]), Err(DrbgError::EntropyInputTooShort));
        assert_eq!(d.reseed(&entropy, &[]), Ok(()));
        let mut out = [0u8; 16];
        assert_eq!(
            d.generate_pr(&entropy[..31], &[], &mut out),
            Err(DrbgError::EntropyInputTooShort)
        );
        assert_eq!(d.generate_pr(&entropy, &[], &mut out), Ok(()));
    }

    /// Personalization and additional input never count toward the
    /// entropy or nonce minimum; an over-long input keeps its over-long
    /// error when the entropy input or nonce is also short; reseeding an
    /// uninstantiated DRBG reports `Uninstantiated` first; with both
    /// entropy input and nonce short, instantiate reports the entropy
    /// input; and an instantiate refused by a length check leaves the
    /// DRBG uninstantiated.
    fn assert_extras_and_precedence<A: HmacAlg>() {
        crate::test_support::start_module();
        let material = [0x5au8; 64];
        let extra = [0x7cu8; 64];
        let long = [0x3cu8; 800];
        let mut out = [0u8; 16];

        let mut d = HmacDrbg::<A>::new();
        assert_eq!(d.reseed(&[], &[]), Err(DrbgError::Uninstantiated));
        assert_eq!(
            d.reseed(&material[..32], &[]),
            Err(DrbgError::Uninstantiated)
        );
        assert_eq!(
            d.instantiate_internal(&material[..31], &material[..16], &extra),
            Err(Error::EntropyInputTooShort)
        );
        assert_eq!(
            d.instantiate_internal(&material[..32], &material[..15], &extra),
            Err(Error::NonceTooShort)
        );
        assert_eq!(
            d.instantiate_internal(&material[..31], &material[..15], &[]),
            Err(Error::EntropyInputTooShort)
        );
        // entropy || nonce || personalization one byte past the bound.
        let pers_len = HMAC_DRBG_MAX_PROVIDED + 1 - 31 - 16;
        assert_eq!(
            d.instantiate_internal(&material[..31], &material[..16], &long[..pers_len]),
            Err(Error::InvalidInput)
        );
        let pers_len = HMAC_DRBG_MAX_PROVIDED + 1 - 32 - 15;
        assert_eq!(
            d.instantiate_internal(&material[..32], &material[..15], &long[..pers_len]),
            Err(Error::InvalidInput)
        );
        assert!(!d.instantiated);

        d.instantiate_internal(&material[..32], &material[..16], &extra)
            .unwrap();
        assert_eq!(
            d.reseed(&material[..31], &extra),
            Err(DrbgError::EntropyInputTooShort)
        );
        assert_eq!(
            d.generate_pr(&material[..31], &extra, &mut out),
            Err(DrbgError::EntropyInputTooShort)
        );
        let ai_len = HMAC_DRBG_MAX_PROVIDED + 1 - 31;
        assert_eq!(
            d.reseed(&material[..31], &long[..ai_len]),
            Err(DrbgError::InputTooLong)
        );

        // A refused re-instantiate discards the earlier instantiation
        // and erases its working state.
        assert_eq!(
            d.instantiate_internal(&material[..31], &material[..16], &[]),
            Err(Error::EntropyInputTooShort)
        );
        assert!(!d.instantiated);
        assert!(d.key.iter().all(|&b| b == 0));
        assert!(d.v.iter().all(|&b| b == 0));
        assert_eq!(d.reseed_counter, 0);
        assert_eq!(d.generate(None, &mut out), Err(DrbgError::Uninstantiated));
        d.instantiate_internal(&material[..32], &material[..16], &[])
            .unwrap();
        let pers_len = HMAC_DRBG_MAX_PROVIDED + 1 - 32 - 16;
        assert_eq!(
            d.instantiate_internal(&material[..32], &material[..16], &long[..pers_len]),
            Err(Error::InvalidInput)
        );
        assert!(!d.instantiated);
        assert_eq!(d.generate(None, &mut out), Err(DrbgError::Uninstantiated));
    }

    #[test]
    fn hmac_drbg_sha256_enforces_minimum_entropy_and_nonce() {
        assert_minimums_enforced::<HmacSha256Alg>();
        assert_extras_and_precedence::<HmacSha256Alg>();
    }

    #[test]
    fn hmac_drbg_sha384_enforces_minimum_entropy_and_nonce() {
        assert_minimums_enforced::<HmacSha384Alg>();
        assert_extras_and_precedence::<HmacSha384Alg>();
    }

    #[test]
    fn hmac_drbg_sha512_enforces_minimum_entropy_and_nonce() {
        assert_minimums_enforced::<HmacSha512Alg>();
        assert_extras_and_precedence::<HmacSha512Alg>();
    }
}
