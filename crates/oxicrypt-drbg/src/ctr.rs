//! CTR_DRBG — NIST SP 800-90A Rev. 1 §10.2
//!
//! Implements the Counter mode DRBG with AES-128 / AES-192 / AES-256 as
//! the underlying block cipher. Both the "no derivation function" and
//! "use derivation function" variants are supported, as defined in
//! §10.2.1.3.1 and §10.2.1.3.2 respectively.
//!
//! The derivation function `Block_Cipher_df` from §10.3.2 (with BCC
//! from §10.3.3) is implemented internally; no other KDFs are used.
//!
//! # Design notes
//!
//! * State is held in fixed-size arrays sized to the largest approved
//!   variant (AES-256, `seedlen = 48`). This keeps the crate `no_std`
//!   and alloc-free.
//! * The DRBG state is parameterised over a [`CipherFactory`] trait,
//!   and three type aliases [`CtrDrbgAes128`], [`CtrDrbgAes192`], and
//!   [`CtrDrbgAes256`] are exposed for the concrete key sizes.
//! * The reseed interval is hardcoded at 2^48, the maximum permitted
//!   by SP 800-90A Table 3. Consumers are still free to reseed more
//!   often.
//! * This module does not talk to any entropy source. Callers must
//!   feed in entropy bytes of the correct length, as is standard for
//!   an ACVP-testable DRBG core.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of,
    clippy::unused_self,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use core::marker::PhantomData;

use oxicrypt_aes::modes::BlockCipher;
use oxicrypt_aes::{Aes128Key, Aes192Key, Aes256Key};
use oxicrypt_module::{
    Error, SelfTestStarted, Service, require_allowed, require_operational,
    require_self_test_started_token,
};

/// AES block size in bytes (`outlen` in SP 800-90A terminology).
const OUTLEN: usize = 16;
/// Maximum key length across all supported variants (AES-256).
const MAX_KEY_LEN: usize = 32;
/// Maximum `seedlen` (`keylen + outlen`) across supported variants.
const MAX_SEED_LEN: usize = MAX_KEY_LEN + OUTLEN; // 48
/// Upper bound on the length of any single byte string the DF is asked
/// to process (`entropy || nonce || personalization_string`).
///
/// Chosen to accommodate the largest ACVP instantiate payload:
/// AES-256 with `entropy(48) + nonce(48) + personalization(48) = 144`,
/// rounded up to 192.
pub const MAX_DF_INPUT: usize = 192;
/// Smallest working block that holds the IV, the `L || N` header, the
/// largest admissible input and the `0x80` separator.
const DF_SCRATCH_MIN: usize = OUTLEN + 8 + MAX_DF_INPUT + 1;
/// Scratch length for the `Block_Cipher_df` working block `IV || S`,
/// where `S = L || N || input_string || 0x80` zero-padded to a multiple
/// of `outlen` (SP 800-90A §10.3.2 steps 4 and 5).
///
/// Derived from [`MAX_DF_INPUT`] rather than written as a literal, so
/// a change to the bound carries the buffer with it. That the buffer is
/// large enough for every admissible input is established by
/// `df_accepts_every_length_up_to_max_df_input`, which walks the whole
/// range; the assertion below restates the requirement independently of
/// the derivation, so replacing either with a literal fails to compile.
const DF_SCRATCH_LEN: usize = DF_SCRATCH_MIN.div_ceil(OUTLEN) * OUTLEN;
// The `0x80` separator lands one past the last input byte, so the block
// must extend beyond `IV || L || N || input` at the largest admissible
// input. Written from the field widths rather than from
// `DF_SCRATCH_MIN`, so a mis-stated `DF_SCRATCH_MIN` does not satisfy it
// by construction.
const _: () = assert!(DF_SCRATCH_LEN > OUTLEN + 4 + 4 + MAX_DF_INPUT);
/// SP 800-90A Table 3: maximum reseed interval for CTR_DRBG is `2^48`.
const RESEED_INTERVAL: u64 = 1u64 << 48;

/// Errors returned by the CTR_DRBG API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgError {
    /// Generate was called before Instantiate, or after an error
    /// transitioned the state to an unusable condition.
    Uninstantiated,
    /// `reseed_counter` would exceed the 2^48 limit; caller must
    /// reseed before requesting more output.
    ReseedRequired,
    /// Caller passed more input bytes than this implementation
    /// is willing to buffer (see [`MAX_DF_INPUT`]).
    InputTooLong,
    /// `no_df` path: seed material was not exactly `seedlen` bytes.
    InvalidSeedLength,
    /// Reseed entropy input is shorter than the minimum entropy input
    /// length (`min_length`) for the instantiated security strength
    /// (SP 800-90A Rev. 1 §8.6.3, Tables 2 and 3). Distinct from
    /// [`DrbgError::InputTooLong`].
    EntropyInputTooShort,
    /// Requested output length exceeds `2^19` bits (SP 800-90A
    /// Table 3 `max_number_of_bits_per_request`).
    RequestTooLong,
    /// The module refused the call: it is not in a state in which the
    /// DRBG's underlying primitive may run (wraps
    /// [`oxicrypt_module::Error`]).
    Module(Error),
}

impl From<Error> for DrbgError {
    fn from(value: Error) -> Self {
        Self::Module(value)
    }
}

impl core::fmt::Display for DrbgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uninstantiated => write!(
                f,
                "DRBG has not been instantiated; call new() or instantiate() first"
            ),
            Self::ReseedRequired => write!(
                f,
                "DRBG reseed counter has reached the 2^48 limit (SP 800-90A Table 3); \
                 call reseed() with fresh entropy before generating more output"
            ),
            Self::InputTooLong => write!(
                f,
                "input exceeds the maximum derivation-function buffer ({MAX_DF_INPUT} bytes); \
                 reduce the combined length of entropy + nonce + personalization"
            ),
            Self::InvalidSeedLength => write!(
                f,
                "seed material length does not match the required seedlen for this \
                 DRBG instantiation; check CipherFactory::SEED_LEN for the expected size"
            ),
            Self::EntropyInputTooShort => write!(
                f,
                "entropy input is shorter than the minimum for the instantiated security \
                 strength (SP 800-90A Rev. 1 Tables 2 and 3)"
            ),
            Self::RequestTooLong => write!(
                f,
                "requested output exceeds 2^19 bits (65536 bytes) per call \
                 (SP 800-90A Table 3); split into multiple generate() calls"
            ),
            Self::Module(e) => write!(f, "{e}"),
        }
    }
}

/// Factory / constants bundle describing a concrete CTR_DRBG
/// parameterisation (which AES variant, which seedlen).
///
/// The instantiated security strength is `KEY_LEN * 8` bits: the
/// highest strength SP 800-57 Part 1 assigns the AES key size, which is
/// the only strength this crate instantiates (128, 192 or 256 bits).
pub trait CipherFactory {
    /// Key length in bytes (`keylen`).
    const KEY_LEN: usize;
    /// Seed length in bytes (`keylen + outlen`).
    const SEED_LEN: usize;
    /// The FIPS module service gate associated with this cipher factory.
    const DRBG_SERVICE: Service;
    /// Concrete `BlockCipher` implementation produced from a key.
    type Cipher: BlockCipher;
    /// Instantiate a block cipher from exactly `KEY_LEN` bytes of
    /// key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call (in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests); the cipher is built by the AES crate's
    /// `*_internal` constructor.
    ///
    /// # Panics
    ///
    /// Panics (via debug assert) if `key.len() != KEY_LEN`. Callers in
    /// this crate always pass the correct length.
    fn from_key(key: &[u8]) -> Result<Self::Cipher, Error>;
}

/// `CipherFactory` implementation for AES-128.
pub struct Aes128Factory;
/// `CipherFactory` implementation for AES-192.
pub struct Aes192Factory;
/// `CipherFactory` implementation for AES-256.
pub struct Aes256Factory;

impl CipherFactory for Aes128Factory {
    const KEY_LEN: usize = 16;
    const SEED_LEN: usize = 32;
    const DRBG_SERVICE: Service = Service::CtrDrbgAes128;
    type Cipher = Aes128Key;
    fn from_key(key: &[u8]) -> Result<Self::Cipher, Error> {
        debug_assert_eq!(key.len(), Self::KEY_LEN);
        let mut k = [0u8; 16];
        k.copy_from_slice(&key[..16]);
        Aes128Key::new_internal(&k)
    }
}

impl CipherFactory for Aes192Factory {
    const KEY_LEN: usize = 24;
    const SEED_LEN: usize = 40;
    const DRBG_SERVICE: Service = Service::CtrDrbgAes192;
    type Cipher = Aes192Key;
    fn from_key(key: &[u8]) -> Result<Self::Cipher, Error> {
        debug_assert_eq!(key.len(), Self::KEY_LEN);
        let mut k = [0u8; 24];
        k.copy_from_slice(&key[..24]);
        Aes192Key::new_internal(&k)
    }
}

impl CipherFactory for Aes256Factory {
    const KEY_LEN: usize = 32;
    const SEED_LEN: usize = 48;
    const DRBG_SERVICE: Service = Service::CtrDrbgAes256;
    type Cipher = Aes256Key;
    fn from_key(key: &[u8]) -> Result<Self::Cipher, Error> {
        debug_assert_eq!(key.len(), Self::KEY_LEN);
        let mut k = [0u8; 32];
        k.copy_from_slice(&key[..32]);
        Aes256Key::new_internal(&k)
    }
}

/// CTR_DRBG instance parameterised by a [`CipherFactory`].
///
/// The working state is (`Key`, `V`, `reseed_counter`) as defined in
/// SP 800-90A §10.2.1. Instances are not `Clone` because duplicating
/// DRBG state can cause catastrophic repetition of output.
pub struct CtrDrbg<F: CipherFactory> {
    /// Key material. Only the first `F::KEY_LEN` bytes are live.
    key: [u8; MAX_KEY_LEN],
    /// 16-byte counter value `V`.
    v: [u8; OUTLEN],
    /// SP 800-90A reseed counter, starting at 1 after Instantiate.
    reseed_counter: u64,
    /// Set to `true` after a successful Instantiate.
    instantiated: bool,
    _marker: PhantomData<F>,
}

/// CTR_DRBG with AES-128 as the underlying block cipher.
pub type CtrDrbgAes128 = CtrDrbg<Aes128Factory>;
/// CTR_DRBG with AES-192 as the underlying block cipher.
pub type CtrDrbgAes192 = CtrDrbg<Aes192Factory>;
/// CTR_DRBG with AES-256 as the underlying block cipher.
pub type CtrDrbgAes256 = CtrDrbg<Aes256Factory>;

impl<F: CipherFactory> CtrDrbg<F> {
    /// `use df` minimum entropy input length in bytes: the security
    /// strength (SP 800-90A Rev. 1 Table 3 `min_length`).
    const MIN_ENTROPY_LEN: usize = F::KEY_LEN;
    /// `use df` minimum nonce length in bytes for instantiate: half the
    /// security strength. This floor is the module's nonce check, which SP 800-90A
    /// Rev. 1 §9.1 step 8 permits; a nonce of this length can carry the
    /// `security_strength / 2` bits of entropy that §8.6.7(a) asks for.
    /// §8.6.7(b) also accepts a shorter value that repeats no more often
    /// than a random string of that length would; the module refuses it.
    /// Every AES key length is even, so the division is exact.
    #[allow(clippy::integer_division)]
    const MIN_NONCE_LEN: usize = F::KEY_LEN / 2;

    /// Create an empty, uninstantiated CTR_DRBG slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            key: [0u8; MAX_KEY_LEN],
            v: [0u8; OUTLEN],
            reseed_counter: 0,
            instantiated: false,
            _marker: PhantomData,
        }
    }

    /// CTR_DRBG Instantiate, `no df` variant (§10.2.1.3.1).
    ///
    /// `seed_material` must equal `entropy || personalization_string`
    /// and have length exactly `SEED_LEN` bytes. Callers using this
    /// variant are responsible for ensuring the entropy source
    /// provides full-entropy input of the required length.
    pub fn instantiate_no_df(&mut self, seed_material: &[u8]) -> Result<(), Error> {
        require_operational()?;
        require_allowed(F::DRBG_SERVICE)?;
        self.instantiate_no_df_internal(seed_material)
    }

    /// Internal instantiate function used by KAT runners.
    pub(crate) fn instantiate_no_df_internal(&mut self, seed_material: &[u8]) -> Result<(), Error> {
        // Any refusal below leaves no instantiation behind: a failed
        // re-instantiate must not leave the earlier seed usable.
        self.uninstantiate();
        if seed_material.len() != F::SEED_LEN {
            return Err(Error::InvalidInput);
        }
        // Key = 0, V = 0
        for b in &mut self.key[..F::KEY_LEN] {
            *b = 0;
        }
        self.v = [0u8; OUTLEN];
        // (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
        let mut provided = [0u8; MAX_SEED_LEN];
        provided[..F::SEED_LEN].copy_from_slice(seed_material);
        self.update(&provided[..F::SEED_LEN])?;
        self.reseed_counter = 1;
        self.instantiated = true;
        Ok(())
    }

    /// CTR_DRBG Instantiate, `use df` variant (§10.2.1.3.2).
    ///
    /// Runs `Block_Cipher_df(entropy || nonce || personalization, seedlen)`
    /// to derive the initial seed material. The concatenated input
    /// must fit in [`MAX_DF_INPUT`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::EntropyInputTooShort`] when `entropy` is shorter
    /// than `KEY_LEN` bytes, the security strength (SP 800-90A Rev. 1
    /// Table 3 `min_length`), and [`Error::NonceTooShort`] when `nonce`
    /// is shorter than `KEY_LEN / 2` bytes, the module's nonce floor
    /// (see `MIN_NONCE_LEN`). Personalization never counts toward either
    /// minimum. An over-long combined input returns
    /// [`Error::InvalidInput`] even when one of them is also short. A
    /// refusal by any of these length checks leaves the DRBG
    /// uninstantiated.
    pub fn instantiate_df(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<(), Error> {
        require_operational()?;
        require_allowed(F::DRBG_SERVICE)?;
        self.instantiate_df_internal(entropy, nonce, personalization)
    }

    /// Internal instantiate function used by KAT runners.
    pub(crate) fn instantiate_df_internal(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<(), Error> {
        // Any refusal below leaves no instantiation behind: a failed
        // re-instantiate must not leave the earlier seed usable.
        self.uninstantiate();
        // Build seed_material = entropy || nonce || personalization
        let total = entropy
            .len()
            .checked_add(nonce.len())
            .and_then(|n| n.checked_add(personalization.len()))
            .ok_or(Error::InvalidInput)?;
        if total > MAX_DF_INPUT {
            return Err(Error::InvalidInput);
        }
        if entropy.len() < Self::MIN_ENTROPY_LEN {
            return Err(Error::EntropyInputTooShort);
        }
        if nonce.len() < Self::MIN_NONCE_LEN {
            return Err(Error::NonceTooShort);
        }
        let mut seed_material = [0u8; MAX_DF_INPUT];
        seed_material[..entropy.len()].copy_from_slice(entropy);
        seed_material[entropy.len()..entropy.len() + nonce.len()].copy_from_slice(nonce);
        let offset = entropy.len() + nonce.len();
        seed_material[offset..offset + personalization.len()].copy_from_slice(personalization);

        let mut derived = [0u8; MAX_SEED_LEN];
        self.block_cipher_df(&seed_material[..total], &mut derived[..F::SEED_LEN])
            .map_err(|e| match e {
                DrbgError::Module(e) => e,
                _ => Error::InvalidInput,
            })?;

        for b in &mut self.key[..F::KEY_LEN] {
            *b = 0;
        }
        self.v = [0u8; OUTLEN];
        self.update(&derived[..F::SEED_LEN])?;
        self.reseed_counter = 1;
        self.instantiated = true;
        Ok(())
    }

    /// CTR_DRBG Reseed, `no df` variant (§10.2.1.4.1).
    pub fn reseed_no_df(&mut self, seed_material: &[u8]) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        if seed_material.len() != F::SEED_LEN {
            return Err(DrbgError::InvalidSeedLength);
        }
        let mut provided = [0u8; MAX_SEED_LEN];
        provided[..F::SEED_LEN].copy_from_slice(seed_material);
        self.update(&provided[..F::SEED_LEN])?;
        self.reseed_counter = 1;
        Ok(())
    }

    /// CTR_DRBG Reseed, `use df` variant (§10.2.1.4.2).
    ///
    /// # Errors
    ///
    /// Returns [`DrbgError::Uninstantiated`] before any length check,
    /// [`DrbgError::InputTooLong`] when `entropy || additional_input`
    /// exceeds [`MAX_DF_INPUT`], and otherwise
    /// [`DrbgError::EntropyInputTooShort`] when `entropy` is shorter than
    /// `KEY_LEN` bytes, the security strength (SP 800-90A Rev. 1 Table 3
    /// `min_length`). Additional input never counts toward the minimum.
    pub fn reseed_df(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        let total = entropy
            .len()
            .checked_add(additional_input.len())
            .ok_or(DrbgError::InputTooLong)?;
        if total > MAX_DF_INPUT {
            return Err(DrbgError::InputTooLong);
        }
        if entropy.len() < Self::MIN_ENTROPY_LEN {
            return Err(DrbgError::EntropyInputTooShort);
        }
        let mut seed_material = [0u8; MAX_DF_INPUT];
        seed_material[..entropy.len()].copy_from_slice(entropy);
        seed_material[entropy.len()..entropy.len() + additional_input.len()]
            .copy_from_slice(additional_input);

        let mut derived = [0u8; MAX_SEED_LEN];
        self.block_cipher_df(&seed_material[..total], &mut derived[..F::SEED_LEN])?;
        self.update(&derived[..F::SEED_LEN])?;
        self.reseed_counter = 1;
        Ok(())
    }

    /// CTR_DRBG Generate, `no df` variant (§10.2.1.5.1).
    ///
    /// If `additional_input` is present it must be exactly
    /// `SEED_LEN` bytes.
    pub fn generate_no_df(
        &mut self,
        additional_input: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        let result = self.generate_no_df_unwiped(additional_input, out);
        if result.is_err() {
            // A failed call leaves no generated bytes in the caller's buffer.
            oxicrypt_zeroize::zeroize(out);
        }
        result
    }

    /// Body of [`Self::generate_no_df`]; the caller wipes `out` if it fails.
    fn generate_no_df_unwiped(
        &mut self,
        additional_input: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        if out.len() > (1 << 16) {
            return Err(DrbgError::RequestTooLong);
        }
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(DrbgError::ReseedRequired);
        }

        let mut addl = [0u8; MAX_SEED_LEN];
        let have_addl = match additional_input {
            Some(ai) => {
                if ai.len() != F::SEED_LEN {
                    return Err(DrbgError::InvalidSeedLength);
                }
                addl[..F::SEED_LEN].copy_from_slice(ai);
                self.update(&addl[..F::SEED_LEN])?;
                true
            }
            None => false,
        };

        self.generate_blocks(out)?;

        // Final Update with additional_input (or zeros if not provided).
        if !have_addl {
            for b in &mut addl[..F::SEED_LEN] {
                *b = 0;
            }
        }
        self.update(&addl[..F::SEED_LEN])?;
        self.reseed_counter += 1;
        Ok(())
    }

    /// CTR_DRBG Generate, `use df` variant (§10.2.1.5.2).
    ///
    /// `additional_input` may be any length up to [`MAX_DF_INPUT`]; it
    /// is passed through `Block_Cipher_df` before being mixed in.
    pub fn generate_df(
        &mut self,
        additional_input: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        let result = self.generate_df_unwiped(additional_input, out);
        if result.is_err() {
            // A failed call leaves no generated bytes in the caller's buffer.
            oxicrypt_zeroize::zeroize(out);
        }
        result
    }

    /// Body of [`Self::generate_df`]; the caller wipes `out` if it fails.
    fn generate_df_unwiped(
        &mut self,
        additional_input: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        if out.len() > (1 << 16) {
            return Err(DrbgError::RequestTooLong);
        }
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(DrbgError::ReseedRequired);
        }

        let mut addl = [0u8; MAX_SEED_LEN];
        let have_addl = match additional_input {
            Some(ai) => {
                if ai.len() > MAX_DF_INPUT {
                    return Err(DrbgError::InputTooLong);
                }
                self.block_cipher_df(ai, &mut addl[..F::SEED_LEN])?;
                self.update(&addl[..F::SEED_LEN])?;
                true
            }
            None => false,
        };

        self.generate_blocks(out)?;

        if !have_addl {
            for b in &mut addl[..F::SEED_LEN] {
                *b = 0;
            }
        }
        self.update(&addl[..F::SEED_LEN])?;
        self.reseed_counter += 1;
        Ok(())
    }

    /// CTR_DRBG Generate with prediction resistance, `no df` variant —
    /// SP 800-90A §9.3.1 step 7 (`prediction_resistance_request = True`).
    ///
    /// Equivalent to `reseed_no_df(seed_material)` immediately
    /// followed by `generate_no_df(None, out)`, matching the
    /// §9.3.1 step 7.1/7.2 sequence where the additional input
    /// supplied by the caller is consumed by the reseed and the
    /// subsequent generate is invoked with a Null additional input.
    pub fn generate_no_df_pr(
        &mut self,
        seed_material: &[u8],
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        self.reseed_no_df(seed_material)?;
        self.generate_no_df(None, out)
    }

    /// CTR_DRBG Generate with prediction resistance, `use df` variant —
    /// SP 800-90A §9.3.1 step 7.
    ///
    /// Equivalent to `reseed_df(entropy, additional_input)` followed
    /// by `generate_df(None, out)`.
    pub fn generate_df_pr(
        &mut self,
        entropy: &[u8],
        additional_input: &[u8],
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        self.reseed_df(entropy, additional_input)?;
        self.generate_df(None, out)
    }

    /// Zeroise and mark the instance uninstantiated.
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
    /// SP 800-90A §10.2.1 ceiling so the next `generate*` call
    /// returns [`DrbgError::ReseedRequired`]. Used only by the
    /// §11.3 power-up health tests.
    #[doc(hidden)]
    pub fn debug_force_reseed_ceiling(&mut self) {
        self.reseed_counter = RESEED_INTERVAL + 1;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// CTR_DRBG_Update — SP 800-90A §10.2.1.2.
    ///
    /// `provided_data` must be exactly `SEED_LEN` bytes long.
    fn update(&mut self, provided_data: &[u8]) -> Result<(), Error> {
        debug_assert_eq!(provided_data.len(), F::SEED_LEN);
        let started = require_self_test_started_token()?;
        let cipher = F::from_key(&self.key[..F::KEY_LEN])?;
        let mut temp = [0u8; MAX_SEED_LEN];
        let mut produced = 0usize;
        while produced < F::SEED_LEN {
            increment_counter(&mut self.v);
            let mut block = self.v;
            cipher.encrypt_block_with(&started, &mut block);
            let take = core::cmp::min(OUTLEN, F::SEED_LEN - produced);
            temp[produced..produced + take].copy_from_slice(&block[..take]);
            produced += take;
        }
        // temp XOR= provided_data
        for i in 0..F::SEED_LEN {
            temp[i] ^= provided_data[i];
        }
        // Key = leftmost(temp, keylen)
        self.key[..F::KEY_LEN].copy_from_slice(&temp[..F::KEY_LEN]);
        // V = rightmost(temp, outlen)
        self.v
            .copy_from_slice(&temp[F::KEY_LEN..F::KEY_LEN + OUTLEN]);
        Ok(())
    }

    /// Core output-generation loop from §10.2.1.5.
    fn generate_blocks(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let started = require_self_test_started_token()?;
        let cipher = F::from_key(&self.key[..F::KEY_LEN])?;
        let mut produced = 0usize;
        while produced < out.len() {
            increment_counter(&mut self.v);
            let mut block = self.v;
            cipher.encrypt_block_with(&started, &mut block);
            let take = core::cmp::min(OUTLEN, out.len() - produced);
            out[produced..produced + take].copy_from_slice(&block[..take]);
            produced += take;
        }
        Ok(())
    }

    /// Block_Cipher_df — SP 800-90A §10.3.2.
    ///
    /// Writes exactly `out.len()` derived bytes. `out.len()` must be
    /// at most `F::SEED_LEN` in current use (and ≤ `MAX_SEED_LEN`).
    fn block_cipher_df(&self, input: &[u8], out: &mut [u8]) -> Result<(), DrbgError> {
        if input.len() > MAX_DF_INPUT {
            return Err(DrbgError::InputTooLong);
        }
        let started = require_self_test_started_token()?;
        let no_bits_return_bytes = out.len();
        debug_assert!(no_bits_return_bytes <= MAX_SEED_LEN);

        // S = L || N || input || 0x80, padded to outlen multiple.
        // Scratch: OUTLEN (IV) + header(8) + input(<=MAX_DF_INPUT)
        // + 1 (0x80) + pad(<OUTLEN), rounded to whole blocks.
        let mut s_buf = [0u8; DF_SCRATCH_LEN];
        // s_buf[0..16] is IV (filled later per iteration).
        let mut idx = OUTLEN;
        // L (4 bytes BE) = input length
        let l = input.len() as u32;
        s_buf[idx..idx + 4].copy_from_slice(&l.to_be_bytes());
        idx += 4;
        // N (4 bytes BE) = number_of_bits_to_return / 8
        let n = no_bits_return_bytes as u32;
        s_buf[idx..idx + 4].copy_from_slice(&n.to_be_bytes());
        idx += 4;
        s_buf[idx..idx + input.len()].copy_from_slice(input);
        idx += input.len();
        s_buf[idx] = 0x80;
        idx += 1;
        // Zero-pad to a multiple of OUTLEN (counting IV(16) + S).
        while (idx - OUTLEN) % OUTLEN != 0 {
            s_buf[idx] = 0;
            idx += 1;
        }
        let s_len = idx - OUTLEN;
        let total_bcc_in = OUTLEN + s_len;

        // K = 0x00 01 02 .. (keylen bytes)
        let mut k = [0u8; MAX_KEY_LEN];
        for i in 0..F::KEY_LEN {
            k[i] = i as u8;
        }
        let k_cipher = F::from_key(&k[..F::KEY_LEN])?;

        // temp = BCC outputs, length = keylen + outlen
        let mut temp = [0u8; MAX_SEED_LEN];
        let mut produced = 0usize;
        let mut i: u32 = 0;
        let target = F::SEED_LEN; // produce keylen + outlen
        while produced < target {
            // IV = i (4 bytes BE) || 00..00 (outlen - 4)
            s_buf[..4].copy_from_slice(&i.to_be_bytes());
            for b in &mut s_buf[4..OUTLEN] {
                *b = 0;
            }
            let block = bcc(&k_cipher, &started, &s_buf[..total_bcc_in]);
            let take = core::cmp::min(OUTLEN, target - produced);
            temp[produced..produced + take].copy_from_slice(&block[..take]);
            produced += take;
            i += 1;
        }

        // K' = leftmost(temp, keylen), X = select(temp, keylen, outlen)
        let k2_cipher = F::from_key(&temp[..F::KEY_LEN])?;
        let mut x = [0u8; OUTLEN];
        x.copy_from_slice(&temp[F::KEY_LEN..F::KEY_LEN + OUTLEN]);

        let mut out_produced = 0usize;
        while out_produced < no_bits_return_bytes {
            k2_cipher.encrypt_block_with(&started, &mut x);
            let take = core::cmp::min(OUTLEN, no_bits_return_bytes - out_produced);
            out[out_produced..out_produced + take].copy_from_slice(&x[..take]);
            out_produced += take;
        }
        Ok(())
    }
}

impl<F: CipherFactory> Default for CtrDrbg<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: CipherFactory> Drop for CtrDrbg<F> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.key);
        oxicrypt_zeroize::zeroize(&mut self.v);
    }
}

/// BCC — SP 800-90A §10.3.3. `data` length must be a multiple of 16.
fn bcc<B: BlockCipher>(cipher: &B, started: &SelfTestStarted, data: &[u8]) -> [u8; OUTLEN] {
    debug_assert_eq!(data.len() % OUTLEN, 0);
    let mut chaining = [0u8; OUTLEN];
    let mut i = 0usize;
    while i < data.len() {
        for j in 0..OUTLEN {
            chaining[j] ^= data[i + j];
        }
        cipher.encrypt_block_with(started, &mut chaining);
        i += OUTLEN;
    }
    chaining
}

/// Increment a 16-byte counter as a big-endian 128-bit integer,
/// wrapping at 2^128 (the `(V + 1) mod 2^outlen_bits` step in
/// §10.2.1.2).
fn increment_counter(v: &mut [u8; OUTLEN]) {
    let mut i = OUTLEN;
    while i > 0 {
        i -= 1;
        let (next, carry) = v[i].overflowing_add(1);
        v[i] = next;
        if !carry {
            return;
        }
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

    // ---------------- AES-128 no df CAVP Count=0 ----------------
    #[test]
    fn cavp_ctr_drbg_aes128_no_df_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 32] =
            hex_to_bytes("ce50f33da5d4c1d3d4004eb35244b7f2cd7f2e5076fbf6780a7ff634b249a5fc");
        let expected: [u8; 64] = hex_to_bytes(
            "6545c0529d372443b392ceb3ae3a99a30f963eaf313280f1d1a1e87f9db373d361e75d18018266499cccd64d9bbb8de0185f213383080faddec46bae1f784e5a",
        );
        let mut drbg = CtrDrbgAes128::new();
        drbg.instantiate_no_df_internal(&entropy).unwrap();
        let mut out = [0u8; 64];
        drbg.generate_no_df(None, &mut out).unwrap();
        drbg.generate_no_df(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // ---------------- AES-192 no df CAVP Count=0 ----------------
    #[test]
    fn cavp_ctr_drbg_aes192_no_df_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 40] = hex_to_bytes(
            "f1ef7eb311c850e189be229df7e6d68f1795aa8e21d93504e75abe78f041395873540386812a9a2a",
        );
        let expected: [u8; 64] = hex_to_bytes(
            "6bb0aa5b4b97ee83765736ad0e9068dfef0ccfc93b71c1d3425302ef7ba4635ffc09981d262177e208a7ec90a557b6d76112d56c40893892c3034835036d7a69",
        );
        let mut drbg = CtrDrbgAes192::new();
        drbg.instantiate_no_df_internal(&entropy).unwrap();
        let mut out = [0u8; 64];
        drbg.generate_no_df(None, &mut out).unwrap();
        drbg.generate_no_df(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // ---------------- AES-256 no df CAVP Count=0 ----------------
    #[test]
    fn cavp_ctr_drbg_aes256_no_df_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 48] = hex_to_bytes(
            "df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5531b51de16a30f769262474c73bec010",
        );
        let expected: [u8; 64] = hex_to_bytes(
            "d1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab2280b1dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5",
        );
        let mut drbg = CtrDrbgAes256::new();
        drbg.instantiate_no_df_internal(&entropy).unwrap();
        let mut out = [0u8; 64];
        drbg.generate_no_df(None, &mut out).unwrap();
        drbg.generate_no_df(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // ---------------- AES-128 use df CAVP Count=0 ----------------
    #[test]
    fn cavp_ctr_drbg_aes128_df_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 16] = hex_to_bytes("890eb067acf7382eff80b0c73bc872c6");
        let nonce: [u8; 8] = hex_to_bytes("aad471ef3ef1d203");
        let expected: [u8; 64] = hex_to_bytes(
            "a5514ed7095f64f3d0d3a5760394ab42062f373a25072a6ea6bcfd8489e94af6cf18659fea22ed1ca0a9e33f718b115ee536b12809c31b72b08ddd8be1910fa3",
        );
        let mut drbg = CtrDrbgAes128::new();
        drbg.instantiate_df_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 64];
        drbg.generate_df(None, &mut out).unwrap();
        drbg.generate_df(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // ---------------- AES-192 use df CAVP Count=0 ----------------
    #[test]
    fn cavp_ctr_drbg_aes192_df_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 24] = hex_to_bytes("c35c2fa2a89d52a11fa32aa96c95b8f1c9a8f9cb245a8b40");
        let nonce: [u8; 16] = hex_to_bytes("f3a6e5a7fbd9d3c68e277ba9ac9bbb00");
        let expected: [u8; 64] = hex_to_bytes(
            "8c2e72abfd9bb8284db79e17a43a3146cd7694e35249fc3383914a7117f41368e6d4f148ff49bf29076b5015c59f457945662e3d3503843f4aa5a3df9a9df10d",
        );
        let mut drbg = CtrDrbgAes192::new();
        drbg.instantiate_df_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 64];
        drbg.generate_df(None, &mut out).unwrap();
        drbg.generate_df(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // ---------------- AES-256 use df CAVP Count=0 ----------------
    #[test]
    fn cavp_ctr_drbg_aes256_df_count0() {
        crate::test_support::start_module();
        let entropy: [u8; 32] =
            hex_to_bytes("36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14");
        let nonce: [u8; 16] = hex_to_bytes("496f25b0f1301b4f501be30380a137eb");
        let expected: [u8; 64] = hex_to_bytes(
            "5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535a64912dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d",
        );
        let mut drbg = CtrDrbgAes256::new();
        drbg.instantiate_df_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 64];
        drbg.generate_df(None, &mut out).unwrap();
        drbg.generate_df(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // Consistency check for §9.3.1 prediction-resistance generate:
    // both `no df` and `use df` paths must satisfy
    // generate_pr(e, ai) == reseed(e, ai) + generate(None).
    #[test]
    fn generate_df_pr_matches_reseed_then_generate() {
        crate::test_support::start_module();
        let entropy: [u8; 16] = [0x11u8; 16];
        let nonce: [u8; 8] = [0x22u8; 8];
        let reseed_e: [u8; 16] = [0x33u8; 16];
        let reseed_ai: [u8; 8] = [0x44u8; 8];

        let mut a = CtrDrbgAes128::new();
        a.instantiate_df_internal(&entropy, &nonce, &[]).unwrap();
        let mut out_a = [0u8; 48];
        a.generate_df_pr(&reseed_e, &reseed_ai, &mut out_a).unwrap();

        let mut b = CtrDrbgAes128::new();
        b.instantiate_df_internal(&entropy, &nonce, &[]).unwrap();
        b.reseed_df(&reseed_e, &reseed_ai).unwrap();
        let mut out_b = [0u8; 48];
        b.generate_df(None, &mut out_b).unwrap();

        assert_eq!(out_a, out_b);
    }

    #[test]
    fn generate_no_df_pr_matches_reseed_then_generate() {
        crate::test_support::start_module();
        // AES-128 no df: seed_material must be exactly SEED_LEN = 32 bytes.
        let seed_init: [u8; 32] = [0xaau8; 32];
        let seed_reseed: [u8; 32] = [0xbbu8; 32];

        let mut a = CtrDrbgAes128::new();
        a.instantiate_no_df_internal(&seed_init).unwrap();
        let mut out_a = [0u8; 48];
        a.generate_no_df_pr(&seed_reseed, &mut out_a).unwrap();

        let mut b = CtrDrbgAes128::new();
        b.instantiate_no_df_internal(&seed_init).unwrap();
        b.reseed_no_df(&seed_reseed).unwrap();
        let mut out_b = [0u8; 48];
        b.generate_no_df(None, &mut out_b).unwrap();

        assert_eq!(out_a, out_b);
    }

    #[test]
    fn counter_increment_wraps_carry() {
        crate::test_support::start_module();
        let mut v = [0xffu8; OUTLEN];
        increment_counter(&mut v);
        assert_eq!(v, [0u8; OUTLEN]);
    }

    /// Every combined input length the public guard accepts must be
    /// processed, not panicked on. Covers the band from the minimum
    /// entropy input (and, for instantiate, nonce) up to `MAX_DF_INPUT`
    /// on all three entry points that reach `block_cipher_df`, and the
    /// whole `0..=MAX_DF_INPUT` band for generate.
    #[test]
    fn df_accepts_every_length_up_to_max_df_input() {
        crate::test_support::start_module();
        let material = [0x5au8; MAX_DF_INPUT];
        let nonce = [0xa5u8; 16];
        for len in 0..=MAX_DF_INPUT {
            // instantiate_df: entropy || nonce || personalization, with
            // the AES-256 minimums of 32 and 16 bytes.
            let mut a = CtrDrbgAes256::new();
            if len >= 32 + 16 {
                let r = a.instantiate_df_internal(&material[..len - 16], &nonce, &[]);
                assert!(r.is_ok(), "instantiate_df rejected len={len}");
            } else {
                a.instantiate_df_internal(&material[..32], &nonce, &[])
                    .unwrap();
            }

            // reseed_df: entropy || additional_input
            if len >= 32 {
                let r = a.reseed_df(&material[..len], &[]);
                assert!(r.is_ok(), "reseed_df rejected len={len}");
            }

            // generate_df: additional_input alone
            let mut out = [0u8; 32];
            let r = a.generate_df(Some(&material[..len]), &mut out);
            assert!(r.is_ok(), "generate_df rejected len={len}");
        }
    }

    /// One byte past the guard is refused by the length check on every
    /// path, before the derivation function is reached.
    #[test]
    fn df_rejects_one_byte_over_max_df_input() {
        crate::test_support::start_module();
        let material = [0x5au8; MAX_DF_INPUT + 1];

        let mut a = CtrDrbgAes256::new();
        assert_eq!(
            a.instantiate_df_internal(&material[..MAX_DF_INPUT + 1 - 16], &[0x22u8; 16], &[]),
            Err(Error::InvalidInput)
        );

        a.instantiate_df_internal(&[0x11u8; 48], &[0x22u8; 16], &[])
            .unwrap();
        assert_eq!(a.reseed_df(&material, &[]), Err(DrbgError::InputTooLong));

        let mut out = [0u8; 32];
        assert_eq!(
            a.generate_df(Some(&material), &mut out),
            Err(DrbgError::InputTooLong)
        );
    }

    /// Instantiates `drbg` (`use df`) with `entropy_len` bytes of
    /// entropy input and `nonce_len` bytes of nonce.
    fn instantiate_df_with<F: CipherFactory>(
        drbg: &mut CtrDrbg<F>,
        entropy_len: usize,
        nonce_len: usize,
    ) -> Result<(), Error> {
        let material = [0x5au8; 64];
        drbg.instantiate_df_internal(&material[..entropy_len], &material[..nonce_len], &[])
    }

    /// SP 800-90A Rev. 1 Table 3 `use df` `min_length` (`min_entropy`
    /// bytes, the security strength) and the module's nonce floor
    /// (`min_nonce` bytes, half the strength; see `MIN_NONCE_LEN`), each checked one byte below, exactly at,
    /// and with an empty input.
    fn assert_df_minimums_enforced<F: CipherFactory>(min_entropy: usize, min_nonce: usize) {
        crate::test_support::start_module();

        // Instantiate: entropy input.
        let mut d = CtrDrbg::<F>::new();
        assert_eq!(
            instantiate_df_with(&mut d, min_entropy - 1, min_nonce),
            Err(Error::EntropyInputTooShort)
        );
        assert!(!d.instantiated);
        assert_eq!(
            instantiate_df_with(&mut d, 0, min_nonce),
            Err(Error::EntropyInputTooShort)
        );
        assert!(!d.instantiated);
        assert_eq!(instantiate_df_with(&mut d, min_entropy, min_nonce), Ok(()));

        // Instantiate: nonce.
        let mut d = CtrDrbg::<F>::new();
        assert_eq!(
            instantiate_df_with(&mut d, min_entropy, min_nonce - 1),
            Err(Error::NonceTooShort)
        );
        assert!(!d.instantiated);
        assert_eq!(
            instantiate_df_with(&mut d, min_entropy, 0),
            Err(Error::NonceTooShort)
        );
        assert!(!d.instantiated);
        assert_eq!(instantiate_df_with(&mut d, min_entropy, min_nonce), Ok(()));

        // Reseed, directly and through prediction-resistance generate.
        let entropy = [0x6bu8; 32];
        assert_eq!(
            d.reseed_df(&entropy[..min_entropy - 1], &[]),
            Err(DrbgError::EntropyInputTooShort)
        );
        assert_eq!(d.reseed_df(&[], &[]), Err(DrbgError::EntropyInputTooShort));
        assert_eq!(d.reseed_df(&entropy[..min_entropy], &[]), Ok(()));
        let mut out = [0u8; 16];
        assert_eq!(
            d.generate_df_pr(&entropy[..min_entropy - 1], &[], &mut out),
            Err(DrbgError::EntropyInputTooShort)
        );
        assert_eq!(
            d.generate_df_pr(&entropy[..min_entropy], &[], &mut out),
            Ok(())
        );
    }

    /// The `use df` counterpart of the Hash_DRBG and HMAC_DRBG
    /// `assert_extras_and_precedence`: extras never count toward a
    /// minimum, over-long keeps its error, `Uninstantiated` is reported
    /// first on reseed, entropy is reported before nonce, and an
    /// instantiate refused by a length check leaves the DRBG
    /// uninstantiated.
    fn assert_df_extras_and_precedence<F: CipherFactory>(min_entropy: usize, min_nonce: usize) {
        crate::test_support::start_module();
        let material = [0x5au8; 64];
        let extra = [0x7cu8; 64];
        let long = [0x3cu8; MAX_DF_INPUT + 1];
        let mut out = [0u8; 16];
        let (e, n) = (min_entropy, min_nonce);

        let mut d = CtrDrbg::<F>::new();
        assert_eq!(d.reseed_df(&[], &[]), Err(DrbgError::Uninstantiated));
        assert_eq!(
            d.reseed_df(&material[..e], &[]),
            Err(DrbgError::Uninstantiated)
        );
        assert_eq!(
            d.instantiate_df_internal(&material[..e - 1], &material[..n], &extra),
            Err(Error::EntropyInputTooShort)
        );
        assert_eq!(
            d.instantiate_df_internal(&material[..e], &material[..n - 1], &extra),
            Err(Error::NonceTooShort)
        );
        assert_eq!(
            d.instantiate_df_internal(&material[..e - 1], &material[..n - 1], &[]),
            Err(Error::EntropyInputTooShort)
        );
        assert_eq!(
            d.instantiate_df_internal(
                &material[..e - 1],
                &material[..n],
                &long[..MAX_DF_INPUT + 1 - (e - 1) - n]
            ),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            d.instantiate_df_internal(
                &material[..e],
                &material[..n - 1],
                &long[..MAX_DF_INPUT + 1 - e - (n - 1)]
            ),
            Err(Error::InvalidInput)
        );
        assert!(!d.instantiated);

        d.instantiate_df_internal(&material[..e], &material[..n], &extra)
            .unwrap();
        assert_eq!(
            d.reseed_df(&material[..e - 1], &extra),
            Err(DrbgError::EntropyInputTooShort)
        );
        assert_eq!(
            d.generate_df_pr(&material[..e - 1], &extra, &mut out),
            Err(DrbgError::EntropyInputTooShort)
        );
        assert_eq!(
            d.reseed_df(&material[..e - 1], &long[..MAX_DF_INPUT + 1 - (e - 1)]),
            Err(DrbgError::InputTooLong)
        );

        // A refused re-instantiate discards the earlier instantiation
        // and erases its working state.
        assert_eq!(
            d.instantiate_df_internal(&material[..e - 1], &material[..n], &[]),
            Err(Error::EntropyInputTooShort)
        );
        assert!(!d.instantiated);
        assert!(d.key.iter().all(|&b| b == 0));
        assert!(d.v.iter().all(|&b| b == 0));
        assert_eq!(d.reseed_counter, 0);
        assert_eq!(
            d.generate_df(None, &mut out),
            Err(DrbgError::Uninstantiated)
        );
        d.instantiate_df_internal(&material[..e], &material[..n], &[])
            .unwrap();
        assert_eq!(
            d.instantiate_df_internal(&material[..e], &material[..n], &long),
            Err(Error::InvalidInput)
        );
        assert!(!d.instantiated);

        // The same holds for a refused `no df` re-instantiate.
        let mut d = CtrDrbg::<F>::new();
        d.instantiate_df_internal(&material[..e], &material[..n], &[])
            .unwrap();
        assert_eq!(
            d.instantiate_no_df_internal(&material[..F::SEED_LEN - 1]),
            Err(Error::InvalidInput)
        );
        assert!(!d.instantiated);
        assert_eq!(
            d.generate_no_df(None, &mut out),
            Err(DrbgError::Uninstantiated)
        );
    }

    /// Formats `value` into a fixed buffer; this crate is `no_std`
    /// without `alloc`.
    fn display_into<'a>(value: &dyn core::fmt::Display, buf: &'a mut [u8; 256]) -> &'a str {
        struct Writer<'b> {
            buf: &'b mut [u8; 256],
            len: usize,
        }
        impl core::fmt::Write for Writer<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.len + s.len();
                if end > self.buf.len() {
                    return Err(core::fmt::Error);
                }
                self.buf[self.len..end].copy_from_slice(s.as_bytes());
                self.len = end;
                Ok(())
            }
        }
        let mut w = Writer { buf, len: 0 };
        core::fmt::write(&mut w, format_args!("{value}")).unwrap();
        let len = w.len;
        core::str::from_utf8(&buf[..len]).unwrap()
    }

    #[test]
    fn drbg_error_entropy_too_short_display_names_the_minimum() {
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        let msg = display_into(&DrbgError::EntropyInputTooShort, &mut a);
        assert!(
            msg.contains("entropy input is shorter than the minimum"),
            "{msg}"
        );
        assert_ne!(msg, display_into(&DrbgError::InputTooLong, &mut b));
    }

    #[test]
    fn ctr_drbg_aes128_df_enforces_minimum_entropy_and_nonce() {
        assert_df_minimums_enforced::<Aes128Factory>(16, 8);
        assert_df_extras_and_precedence::<Aes128Factory>(16, 8);
    }

    #[test]
    fn ctr_drbg_aes192_df_enforces_minimum_entropy_and_nonce() {
        assert_df_minimums_enforced::<Aes192Factory>(24, 12);
        assert_df_extras_and_precedence::<Aes192Factory>(24, 12);
    }

    #[test]
    fn ctr_drbg_aes256_df_enforces_minimum_entropy_and_nonce() {
        assert_df_minimums_enforced::<Aes256Factory>(32, 16);
        assert_df_extras_and_precedence::<Aes256Factory>(32, 16);
    }

    /// `no df` keeps Table 3's `min_length = max_length = seedlen`:
    /// one byte short, one byte long and empty are refused, exactly
    /// `seedlen` is accepted, on instantiate and reseed.
    fn assert_no_df_seedlen_enforced<F: CipherFactory>(seedlen: usize) {
        crate::test_support::start_module();
        let material = [0x5au8; 49];
        let mut d = CtrDrbg::<F>::new();
        for len in [0, seedlen - 1, seedlen + 1] {
            assert_eq!(
                d.instantiate_no_df_internal(&material[..len]),
                Err(Error::InvalidInput)
            );
            assert!(!d.instantiated);
        }
        assert_eq!(d.instantiate_no_df_internal(&material[..seedlen]), Ok(()));
        for len in [0, seedlen - 1, seedlen + 1] {
            assert_eq!(
                d.reseed_no_df(&material[..len]),
                Err(DrbgError::InvalidSeedLength)
            );
        }
        assert_eq!(d.reseed_no_df(&material[..seedlen]), Ok(()));
    }

    #[test]
    fn ctr_drbg_no_df_requires_exactly_seedlen() {
        assert_no_df_seedlen_enforced::<Aes128Factory>(32);
        assert_no_df_seedlen_enforced::<Aes192Factory>(40);
        assert_no_df_seedlen_enforced::<Aes256Factory>(48);
    }
}
