//! AES modes of operation: ECB, CBC, CTR, GCM.
//!
//! # Scope
//!
//! Implements four modes over the raw AES block cipher
//! from [`crate::block`]:
//!
//!   * **ECB** — SP 800-38A §6.1. Encrypt / decrypt whole-block
//!     messages with no chaining. Primarily exposed to support the
//!     per-block CAVP KATs; not recommended for general use.
//!   * **CBC** — SP 800-38A §6.2. Requires a 16-byte IV, which the
//!     caller makes unpredictable to an adversary before the message is
//!     encrypted (SP 800-38A Appendix C), and a block-aligned plaintext
//!     (no padding mode baked in here).
//!   * **CTR** — SP 800-38A §6.5. Uses a 16-byte initial counter
//!     block and increments the whole 128-bit counter block as one
//!     big-endian integer (SP 800-38A Appendix B), unlike GCM, which
//!     increments only the low 32 bits (`inc32`).
//!   * **GCM** — SP 800-38D. 96-bit IV and 128-bit tag only; longer
//!     IV forms and shorter tags are not implemented.
//!
//! Each public mode function takes the key type bound to its mode and
//! is gated on that mode's service for the key's size; it then calls an
//! ungated core, parameterised over [`BlockCipher`], which the power-up
//! self-tests call directly. The same core runs over AES-128, AES-192
//! and AES-256.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::many_single_char_names
)]

use oxicrypt_module::{
    Error, Rbg, RbgError, SelfTestStarted, require_allowed, require_operational,
    require_self_test_started, require_self_test_started_token,
};
use oxicrypt_zeroize::Zeroizing;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::wipe::{WipedBlock, WipedBuffer, wipe_gcm_iv};

use crate::block::{
    BLOCK_SIZE, CBC_SERVICES, CTR_SERVICES, ECB_SERVICES, EcbKey, GCM_SERVICES, KeySchedule,
};

/// Minimal block-cipher primitive used by mode code.
///
/// Its methods are the per-block path for a mode function that checked
/// the module state once at its own entry point and holds the proof.
/// Each method checks the module state again on entry, so a proof held
/// across a transition to the error state drives no further blocks.
#[doc(hidden)]
pub trait BlockCipher {
    /// Block size in bytes. Always 16 for AES.
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    /// Encrypt a 16-byte block in place.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call: in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests.
    #[doc(hidden)]
    fn encrypt_block_with(
        &self,
        started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error>;
    /// Decrypt a 16-byte block in place.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call.
    #[doc(hidden)]
    fn decrypt_block_with(
        &self,
        started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error>;
}

impl BlockCipher for KeySchedule {
    fn encrypt_block_with(
        &self,
        started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error> {
        Self::encrypt_block_with(self, started, block)
    }
    fn decrypt_block_with(
        &self,
        started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error> {
        Self::decrypt_block_with(self, started, block)
    }
}

impl BlockCipher for EcbKey {
    fn encrypt_block_with(
        &self,
        started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error> {
        self.schedule.encrypt_block_with(started, block)
    }
    fn decrypt_block_with(
        &self,
        started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error> {
        self.schedule.decrypt_block_with(started, block)
    }
}

/// An AES key bound to CBC (SP 800-38A §6.2).
///
/// ```compile_fail,E0599
/// let k = oxicrypt_aes::CbcKey::new(&[0u8; 16]).unwrap();
/// let k2 = k.clone();
/// ```
pub struct CbcKey {
    pub(crate) schedule: KeySchedule,
}

impl CbcKey {
    /// Builds a CBC key from 16, 24 or 32 bytes of key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless the module is
    /// `Operational`, [`Error::InvalidInput`] unless `key` is 16, 24 or 32
    /// bytes, and [`Error::AlgorithmRestricted`] when the active profile
    /// does not permit AES-CBC at that key size.
    ///
    /// The key is returned by value; a copy of the schedule that the move
    /// leaves behind is not zeroized.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let mut k = Self {
            schedule: KeySchedule::admit(key.len(), CBC_SERVICES)?,
        };
        k.schedule.expand(key);
        Ok(k)
    }

    /// Builds the key as [`CbcKey::new`] does, in `slot`, and returns a
    /// reference to it there: the schedule is expanded where the key will
    /// stay, so the key is never moved.
    ///
    /// `slot` is treated as uninitialised; a value already in it is
    /// overwritten without being dropped. On success the caller owns the
    /// initialised value and must run its destructor in place, which
    /// zeroizes the schedule. A `MaybeUninit` runs no destructor of its
    /// own, so the caller embeds the slot in a type whose `Drop` runs the
    /// value's, as the C key handle does, or calls
    /// `MaybeUninit::assume_init_drop`; a slot left without its destructor
    /// run leaves the schedule unwiped. On an error `slot` has not been
    /// written.
    ///
    /// # Errors
    ///
    /// The errors of [`CbcKey::new`].
    #[doc(hidden)]
    pub fn new_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
    ) -> Result<&'a mut Self, Error> {
        let k = slot.write(Self {
            schedule: KeySchedule::admit(key.len(), CBC_SERVICES)?,
        });
        k.schedule.expand(key);
        Ok(k)
    }
}

/// An AES key bound to CTR (SP 800-38A §6.5).
///
/// ```compile_fail,E0599
/// let k = oxicrypt_aes::CtrKey::new(&[0u8; 16]).unwrap();
/// let k2 = k.clone();
/// ```
pub struct CtrKey {
    pub(crate) schedule: KeySchedule,
}

impl CtrKey {
    /// Builds a CTR key from 16, 24 or 32 bytes of key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless the module is
    /// `Operational`, [`Error::InvalidInput`] unless `key` is 16, 24 or 32
    /// bytes, and [`Error::AlgorithmRestricted`] when the active profile
    /// does not permit AES-CTR at that key size.
    ///
    /// The key is returned by value; a copy of the schedule that the move
    /// leaves behind is not zeroized.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let mut k = Self {
            schedule: KeySchedule::admit(key.len(), CTR_SERVICES)?,
        };
        k.schedule.expand(key);
        Ok(k)
    }

    /// Builds the key as [`CtrKey::new`] does, in `slot`, and returns a
    /// reference to it there: the schedule is expanded where the key will
    /// stay, so the key is never moved.
    ///
    /// `slot` is treated as uninitialised; a value already in it is
    /// overwritten without being dropped. On success the caller owns the
    /// initialised value and must run its destructor in place, which
    /// zeroizes the schedule. A `MaybeUninit` runs no destructor of its
    /// own, so the caller embeds the slot in a type whose `Drop` runs the
    /// value's, as the C key handle does, or calls
    /// `MaybeUninit::assume_init_drop`; a slot left without its destructor
    /// run leaves the schedule unwiped. On an error `slot` has not been
    /// written.
    ///
    /// # Errors
    ///
    /// The errors of [`CtrKey::new`].
    #[doc(hidden)]
    pub fn new_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
    ) -> Result<&'a mut Self, Error> {
        let k = slot.write(Self {
            schedule: KeySchedule::admit(key.len(), CTR_SERVICES)?,
        });
        k.schedule.expand(key);
        Ok(k)
    }
}

/// The number of encryptions SP 800-38D §8.3 permits under one key whose
/// IVs are generated by the RBG-based construction of §8.2.2.
const GCM_INVOCATION_LIMIT: u64 = 1 << 32;

/// An AES key bound to GCM (SP 800-38D).
///
/// The key counts its encryptions. [`gcm_encrypt`] reserves one invocation
/// before it draws an IV and returns [`ModeError::Module`] carrying
/// [`Error::KeyExhausted`] once the count has reached the key's limit, 2^32
/// (SP 800-38D §8.3) or the share set by [`GcmKey::new_with_limit`]. The
/// reservation is not released when the IV draw fails, and [`gcm_decrypt`]
/// does not count.
///
/// The limit applies to the key bytes, which the module sees only within
/// one instance. An operator who uses the same key in several processes or
/// across a restart sums their counts ([`GcmKey::invocations`],
/// [`GcmKey::new_with_count`]) and establishes a new key before the sum
/// reaches 2^32, or gives each instance a share with
/// [`GcmKey::new_with_limit`] whose sum is at most 2^32. The same key bytes
/// must never be constructed as a key of another mode.
///
/// ```compile_fail,E0599
/// let k = oxicrypt_aes::GcmKey::new(&[0u8; 16]).unwrap();
/// let k2 = k.clone();
/// ```
pub struct GcmKey {
    pub(crate) schedule: KeySchedule,
    pub(crate) invocations: AtomicU64,
    pub(crate) limit: u64,
}

impl GcmKey {
    /// Builds a GCM key from 16, 24 or 32 bytes of key material, with a
    /// count of 0 and a limit of 2^32 encryptions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless the module is
    /// `Operational`, [`Error::InvalidInput`] unless `key` is 16, 24 or 32
    /// bytes, and [`Error::AlgorithmRestricted`] when the active profile
    /// does not permit AES-GCM at that key size.
    ///
    /// The key is returned by value, as are those of
    /// [`GcmKey::new_with_count`] and [`GcmKey::new_with_limit`]; a copy of
    /// the schedule that the move leaves behind is not zeroized.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Self::build(key, 0, GCM_INVOCATION_LIMIT)
    }

    /// Builds the key as [`GcmKey::new`] does, in `slot`, and returns a
    /// reference to it there: the schedule is expanded where the key will
    /// stay, so the key is never moved.
    ///
    /// `slot` is treated as uninitialised; a value already in it is
    /// overwritten without being dropped. On success the caller owns the
    /// initialised value and must run its destructor in place, which
    /// zeroizes the schedule. A `MaybeUninit` runs no destructor of its
    /// own, so the caller embeds the slot in a type whose `Drop` runs the
    /// value's, as the C key handle does, or calls
    /// `MaybeUninit::assume_init_drop`; a slot left without its destructor
    /// run leaves the schedule unwiped. On an error `slot` has not been
    /// written.
    ///
    /// # Errors
    ///
    /// The errors of [`GcmKey::new`].
    #[doc(hidden)]
    pub fn new_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
    ) -> Result<&'a mut Self, Error> {
        Self::build_in_place(slot, key, 0, GCM_INVOCATION_LIMIT)
    }

    /// [`GcmKey::new_with_count`] in `slot`, as [`GcmKey::new_in_place`]
    /// is [`GcmKey::new`] there.
    ///
    /// # Errors
    ///
    /// The errors of [`GcmKey::new_with_count`].
    #[doc(hidden)]
    pub fn new_with_count_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
        used: u64,
    ) -> Result<&'a mut Self, Error> {
        Self::build_in_place(slot, key, used, GCM_INVOCATION_LIMIT)
    }

    /// [`GcmKey::new_with_limit`] in `slot`, as [`GcmKey::new_in_place`]
    /// is [`GcmKey::new`] there.
    ///
    /// # Errors
    ///
    /// The errors of [`GcmKey::new_with_limit`].
    #[doc(hidden)]
    pub fn new_with_limit_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
        limit: u64,
    ) -> Result<&'a mut Self, Error> {
        Self::build_in_place(slot, key, 0, limit)
    }

    /// Builds a GCM key as [`GcmKey::new`] does, with its count preloaded
    /// to `used`: the encryptions an earlier instance of the same key bytes
    /// performed, as read from [`GcmKey::invocations`].
    ///
    /// # Errors
    ///
    /// The errors of [`GcmKey::new`], checked first, then
    /// [`Error::InvalidInput`] when `used` is above 2^32.
    pub fn new_with_count(key: &[u8], used: u64) -> Result<Self, Error> {
        Self::build(key, used, GCM_INVOCATION_LIMIT)
    }

    /// Builds a GCM key as [`GcmKey::new`] does, with a count of 0 and a
    /// limit of `limit` encryptions: this instance's share of the 2^32
    /// permitted under the key bytes.
    ///
    /// # Errors
    ///
    /// The errors of [`GcmKey::new`], checked first, then
    /// [`Error::InvalidInput`] when `limit` is 0 or above 2^32.
    pub fn new_with_limit(key: &[u8], limit: u64) -> Result<Self, Error> {
        Self::build(key, 0, limit)
    }

    /// The number of encryptions reserved under this key, including any
    /// preloaded by [`GcmKey::new_with_count`].
    pub fn invocations(&self) -> u64 {
        self.invocations.load(Ordering::Relaxed)
    }

    /// The gates and argument checks of every constructor, returning the
    /// key with a zeroed schedule for `key` to be expanded into.
    fn admit(key: &[u8], used: u64, limit: u64) -> Result<Self, Error> {
        let schedule = KeySchedule::admit(key.len(), GCM_SERVICES)?;
        if used > GCM_INVOCATION_LIMIT || limit == 0 || limit > GCM_INVOCATION_LIMIT {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            schedule,
            invocations: AtomicU64::new(used),
            limit,
        })
    }

    fn build(key: &[u8], used: u64, limit: u64) -> Result<Self, Error> {
        let mut k = Self::admit(key, used, limit)?;
        k.schedule.expand(key);
        Ok(k)
    }

    fn build_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
        used: u64,
        limit: u64,
    ) -> Result<&'a mut Self, Error> {
        let k = slot.write(Self::admit(key, used, limit)?);
        k.schedule.expand(key);
        Ok(k)
    }

    /// Reserves one invocation, or refuses once the count has reached the
    /// limit. The compare-and-swap makes the check and the increment one
    /// step, so concurrent callers can never reserve past the limit.
    fn reserve_invocation(&self) -> Result<(), ModeError> {
        // The count guards no other memory, so the atomicity of the
        // read-modify-write is all the ordering it needs.
        let mut used = self.invocations.load(Ordering::Relaxed);
        loop {
            if used >= self.limit {
                return Err(ModeError::Module(Error::KeyExhausted));
            }
            match self.invocations.compare_exchange_weak(
                used,
                used + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => used = current,
            }
        }
    }
}

/// Errors returned by mode APIs.
///
/// The enum is non-exhaustive: a caller outside this crate matches it with
/// a wildcard arm, which a variant added in a later release reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModeError {
    /// Input length is not a multiple of the block size (ECB/CBC).
    NotBlockAligned,
    /// GCM: IV length is not 12 bytes (only the 96-bit IV form is
    /// implemented).
    InvalidIvLength,
    /// GCM/CCM: authentication tag did not verify.
    TagMismatch,
    /// GCM/CCM/CTR: buffer length mismatch between the input and the
    /// output. KW/KWP: a length the mode does not accept, below its
    /// minimum, not a multiple of 8, or an output of the wrong size.
    LengthMismatch,
    /// CCM: nonce length is outside the SP 800-38C range (7..=13).
    InvalidNonceLength,
    /// CCM: the tag buffer's length is not the key's tag length.
    InvalidTagLength,
    /// CCM: plaintext is too long for the chosen nonce length
    /// (`Plen >= 2^(8*(15 - Nlen))`). GCM: plaintext or ciphertext is
    /// longer than 2^36 − 32 bytes (SP 800-38D §5.2.1.1). ECB/CBC: the
    /// input is empty (SP 800-38A Appendix A). KW: a plaintext of 2^54
    /// semiblocks or more, or a ciphertext of more than 2^54 semiblocks
    /// (SP 800-38F §5.3.1 Table 1).
    InvalidPayloadLength,
    /// CCM: associated data exceeds the SP 800-38C §A.2.2 cap. GCM:
    /// associated data is longer than 2^61 − 1 bytes (SP 800-38D
    /// §5.2.1.1).
    InvalidAadLength,
    /// The random bit generator produced no output; its own error is
    /// carried unchanged.
    Rbg(RbgError),
    /// The random bit generator's security strength is below the 96 bits
    /// the GCM IV requires.
    RbgTooWeak,
    /// The module refused the operation, for example
    /// [`Error::NotOperational`] once it has entered the error state.
    Module(Error),
}

impl From<Error> for ModeError {
    fn from(e: Error) -> Self {
        Self::Module(e)
    }
}

/// One value of every [`ModeError`] variant, in declaration order, the
/// payload variants carrying [`RbgError::Busy`] and [`Error::InvalidInput`].
///
/// The successor of each value is an exhaustive `match` inside this crate,
/// so a variant added to the enum does not compile until the match inside
/// this function has an arm for it. A crate that maps the non-exhaustive enum iterates this to
/// cover every variant.
#[doc(hidden)]
pub fn mode_error_variants() -> impl Iterator<Item = ModeError> {
    core::iter::successors(Some(ModeError::NotBlockAligned), |e| match e {
        ModeError::NotBlockAligned => Some(ModeError::InvalidIvLength),
        ModeError::InvalidIvLength => Some(ModeError::TagMismatch),
        ModeError::TagMismatch => Some(ModeError::LengthMismatch),
        ModeError::LengthMismatch => Some(ModeError::InvalidNonceLength),
        ModeError::InvalidNonceLength => Some(ModeError::InvalidTagLength),
        ModeError::InvalidTagLength => Some(ModeError::InvalidPayloadLength),
        ModeError::InvalidPayloadLength => Some(ModeError::InvalidAadLength),
        ModeError::InvalidAadLength => Some(ModeError::Rbg(RbgError::Busy)),
        ModeError::Rbg(_) => Some(ModeError::RbgTooWeak),
        ModeError::RbgTooWeak => Some(ModeError::Module(Error::InvalidInput)),
        ModeError::Module(_) => None,
    })
}

impl core::fmt::Display for ModeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotBlockAligned => write!(
                f,
                "input length is not a multiple of 16 bytes (AES block size); \
                 pad or use a streaming mode (CTR/GCM/CCM)"
            ),
            Self::InvalidIvLength => write!(
                f,
                "GCM IV must be exactly 12 bytes (96 bits); \
                 pass a 12-byte nonce"
            ),
            Self::TagMismatch => write!(
                f,
                "authentication tag did not verify; \
                 the ciphertext or AAD was modified, or the key/nonce is wrong"
            ),
            Self::LengthMismatch => write!(
                f,
                "output buffer length does not match ciphertext length; \
                 allocate an output buffer of the same size as the ciphertext"
            ),
            Self::InvalidNonceLength => write!(
                f,
                "CCM nonce must be 7..=13 bytes (SP 800-38C §A.2.1); \
                 pass a nonce in that range"
            ),
            Self::InvalidTagLength => write!(
                f,
                "CCM tag buffer length must equal the key's tag length; \
                 pass a tag buffer of the length the key was built with"
            ),
            Self::InvalidPayloadLength => write!(
                f,
                "payload too long for the mode: CCM bounds it by the nonce \
                 length (use a shorter nonce or split the data), GCM by \
                 2^36 - 32 bytes (split the data)"
            ),
            Self::InvalidAadLength => write!(
                f,
                "associated data exceeds the mode's maximum \
                 (CCM: SP 800-38C §A.2.2; GCM: 2^61 - 1 bytes); \
                 reduce the AAD length"
            ),
            Self::Rbg(e) => write!(f, "the random bit generator produced no output: {e}"),
            Self::RbgTooWeak => write!(
                f,
                "random bit generator strength is below the 96 bits the GCM IV \
                 requires; pass one of the module's DRBGs"
            ),
            Self::Module(e) => write!(f, "the module refused the operation: {e}"),
        }
    }
}

/// ECB-encrypt `input` into `output`. Both buffers must have the
/// same length and that length must be a non-zero multiple of 16.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-ECB at the key's size.
/// Returns [`ModeError::InvalidPayloadLength`] when `input` is empty, and
/// [`ModeError::NotBlockAligned`] when the lengths differ or are not a
/// multiple of 16.
pub fn ecb_encrypt(key: &EcbKey, input: &[u8], output: &mut [u8]) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(ECB_SERVICES))?;
    ecb_encrypt_core(&key.schedule, input, output)
}

/// [`ecb_encrypt`] without the service gates, for the power-up self-tests.
pub(crate) fn ecb_encrypt_core<B: BlockCipher>(
    cipher: &B,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    if input.is_empty() {
        return Err(ModeError::InvalidPayloadLength);
    }
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut blk = WipedBlock::new(WipedBuffer::EcbBlock);
    let mut i = 0;
    while i < input.len() {
        blk.bytes.copy_from_slice(&input[i..i + 16]);
        cipher.encrypt_block_with(started, &mut blk.bytes)?;
        output[i..i + 16].copy_from_slice(&blk.bytes);
        i += 16;
    }
    Ok(())
}

/// ECB-decrypt `input` into `output`, under the length rules of
/// [`ecb_encrypt`].
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-ECB at the key's size.
/// Returns [`ModeError::InvalidPayloadLength`] when `input` is empty, and
/// [`ModeError::NotBlockAligned`] when the lengths differ or are not a
/// multiple of 16. A module that enters its error state while the
/// decryption runs stops it with [`ModeError::Module`], and `output` is
/// then zeroized, so no partial plaintext is left in it.
pub fn ecb_decrypt(key: &EcbKey, input: &[u8], output: &mut [u8]) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(ECB_SERVICES))?;
    ecb_decrypt_core(&key.schedule, input, output)
}

/// [`ecb_decrypt`] without the service gates, for the power-up self-tests.
pub(crate) fn ecb_decrypt_core<B: BlockCipher>(
    cipher: &B,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    if input.is_empty() {
        return Err(ModeError::InvalidPayloadLength);
    }
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut blk = WipedBlock::new(WipedBuffer::EcbBlock);
    let mut i = 0;
    while i < input.len() {
        blk.bytes.copy_from_slice(&input[i..i + 16]);
        if let Err(e) = cipher.decrypt_block_with(started, &mut blk.bytes) {
            oxicrypt_zeroize::zeroize(output);
            return Err(e.into());
        }
        output[i..i + 16].copy_from_slice(&blk.bytes);
        i += 16;
    }
    Ok(())
}

/// CBC-encrypt `plaintext` into `ciphertext_out` with a 16-byte IV.
/// Lengths must match and be a non-zero multiple of 16. No padding is
/// applied.
///
/// The IV must be unpredictable to an adversary before the message is
/// encrypted (SP 800-38A Appendix C). Choosing it so is the caller's
/// duty: this function encrypts under whatever IV it is given.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-CBC at the key's size.
/// Returns [`ModeError::InvalidPayloadLength`] when `plaintext` is empty,
/// and [`ModeError::NotBlockAligned`] when the lengths differ or are not
/// a multiple of 16.
pub fn cbc_encrypt(
    key: &CbcKey,
    iv: &[u8; 16],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(CBC_SERVICES))?;
    cbc_encrypt_core(&key.schedule, iv, plaintext, ciphertext_out)
}

/// [`cbc_encrypt`] without the service gates, for the power-up self-tests.
pub(crate) fn cbc_encrypt_core<B: BlockCipher>(
    cipher: &B,
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    if input.is_empty() {
        return Err(ModeError::InvalidPayloadLength);
    }
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut prev = *iv;
    let mut blk = WipedBlock::new(WipedBuffer::CbcBlock);
    let mut i = 0;
    while i < input.len() {
        for j in 0..16 {
            blk.bytes[j] = input[i + j] ^ prev[j];
        }
        cipher.encrypt_block_with(started, &mut blk.bytes)?;
        output[i..i + 16].copy_from_slice(&blk.bytes);
        prev = blk.bytes;
        i += 16;
    }
    Ok(())
}

/// CBC-decrypt `ciphertext` into `plaintext_out`, under the length rules
/// of [`cbc_encrypt`].
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-CBC at the key's size.
/// Returns [`ModeError::InvalidPayloadLength`] when `ciphertext` is empty,
/// and [`ModeError::NotBlockAligned`] when the lengths differ or are not
/// a multiple of 16. A module that enters its error state while the
/// decryption runs stops it with [`ModeError::Module`], and
/// `plaintext_out` is then zeroized, so no partial plaintext is left in
/// it.
pub fn cbc_decrypt(
    key: &CbcKey,
    iv: &[u8; 16],
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(CBC_SERVICES))?;
    cbc_decrypt_core(&key.schedule, iv, ciphertext, plaintext_out)
}

/// [`cbc_decrypt`] without the service gates, for the power-up self-tests.
pub(crate) fn cbc_decrypt_core<B: BlockCipher>(
    cipher: &B,
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    if input.is_empty() {
        return Err(ModeError::InvalidPayloadLength);
    }
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut prev = *iv;
    let mut blk = WipedBlock::new(WipedBuffer::CbcBlock);
    let mut i = 0;
    while i < input.len() {
        blk.bytes.copy_from_slice(&input[i..i + 16]);
        let cipher_in = blk.bytes;
        if let Err(e) = cipher.decrypt_block_with(started, &mut blk.bytes) {
            oxicrypt_zeroize::zeroize(output);
            return Err(e.into());
        }
        for j in 0..16 {
            blk.bytes[j] ^= prev[j];
        }
        output[i..i + 16].copy_from_slice(&blk.bytes);
        prev = cipher_in;
        i += 16;
    }
    Ok(())
}

/// Increment a 16-byte counter block by treating the final 4 bytes
/// as a big-endian counter. Matches the GCM convention.
#[inline]
fn inc32(ctr: &mut [u8; 16]) {
    let mut c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    c = c.wrapping_add(1);
    let b = c.to_be_bytes();
    ctr[12] = b[0];
    ctr[13] = b[1];
    ctr[14] = b[2];
    ctr[15] = b[3];
}

/// CTR encrypt/decrypt (the same operation) using `counter` as the
/// initial counter block (SP 800-38A §6.5).
///
/// Each successive counter block is the previous one plus one, the whole
/// 128-bit block taken as one big-endian integer, so a carry out of any
/// byte propagates into the next (SP 800-38A Appendix B.1, incrementing
/// all 128 bits).
/// GCM differs: its `inc32` increments only the low 32 bits.
///
/// The counter blocks must be distinct across every message encrypted
/// under one key (SP 800-38A Appendix B). Choosing initial counter
/// blocks whose ranges do not overlap is the caller's duty.
///
/// `output` must be exactly `input.len()` bytes.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-CTR at the key's size.
/// Returns [`ModeError::LengthMismatch`] when `output` is shorter or
/// longer than `input`. A module that enters its error state while the
/// operation runs stops it with [`ModeError::Module`], and `output` is
/// then zeroized, so a decryption leaves no partial plaintext in it.
pub fn ctr(
    key: &CtrKey,
    counter: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(CTR_SERVICES))?;
    ctr_core(&key.schedule, counter, input, output)
}

/// [`ctr`] without the service gates, for the power-up self-tests.
pub(crate) fn ctr_core<B: BlockCipher>(
    cipher: &B,
    counter: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    if input.len() != output.len() {
        return Err(ModeError::LengthMismatch);
    }
    let mut ctr = WipedBlock::new(WipedBuffer::CtrCounter);
    let mut ks = WipedBlock::new(WipedBuffer::CtrKeystream);
    ctr.bytes = *counter;
    let mut i = 0;
    while i < input.len() {
        ks.bytes = ctr.bytes;
        if let Err(e) = cipher.encrypt_block_with(started, &mut ks.bytes) {
            oxicrypt_zeroize::zeroize(output);
            return Err(e.into());
        }
        let take = core::cmp::min(16, input.len() - i);
        for j in 0..take {
            output[i + j] = input[i + j] ^ ks.bytes[j];
        }
        inc128_for_ctr(&mut ctr.bytes);
        i += 16;
    }
    Ok(())
}

/// Full 128-bit big-endian increment, used by CTR mode to follow the
/// SP 800-38A Appendix F.5 test-vector convention. The vectors only
/// wrap the low 32 bits within the length of the sample message.
/// GCM uses [`inc32`] instead.
fn inc128_for_ctr(ctr: &mut [u8; 16]) {
    let mut carry: u16 = 1;
    let mut i = 16;
    while i > 0 {
        i -= 1;
        let s = u16::from(ctr[i]) + carry;
        ctr[i] = (s & 0xff) as u8;
        carry = s >> 8;
        if carry == 0 {
            break;
        }
    }
}

/// GHASH multiplication in GF(2^128) with polynomial
/// `x^128 + x^7 + x^2 + x + 1` (SP 800-38D §6.3 Algorithm 1): `x`
/// becomes `x · h`.
///
/// Blocks are read in the GCM bit order, in which bit 0 of byte 0 is the
/// coefficient of `1`. This is the portable path and the correctness
/// oracle of the PCLMULQDQ path that [`gf_mul`] dispatches to.
///
/// H and the accumulator are secret (SP 800-38D §5.3), so each
/// conditional step of Algorithm 1, the XOR of V into Z on a bit of `x`
/// and the XOR of R into V on the bit shifted out of V, is applied under
/// a mask of all ones or all zeros taken from that bit rather than under
/// a branch. Both masks pass through [`core::hint::black_box`] because
/// without it the compiler turns the masked XOR of V into Z back into a
/// branch on the bit of `x`. V and Z are held in storage that wipes them,
/// and the product is written into `x`, which the caller holds as the
/// guarded accumulator.
fn gf_mul_portable(x: &mut [u8; 16], h: &[u8; 16]) {
    let mut z = WipedBlock::new(WipedBuffer::GcmGhashOperand);
    let mut v = WipedBlock::new(WipedBuffer::GcmGhashOperand);
    v.bytes.copy_from_slice(h);
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        let take = core::hint::black_box(0u8.wrapping_sub(bit));
        for k in 0..16 {
            z.bytes[k] ^= v.bytes[k] & take;
        }
        // SP 800-38D §6.3 Algorithm 1 step 3: V = V >> 1, then V ^= R
        // (R = 11100001 || 0^120) when the bit shifted out was 1.
        let lsb = v.bytes[15] & 1;
        let mut carry: u8 = 0;
        for k in 0..16 {
            let b = v.bytes[k];
            v.bytes[k] = (b >> 1) | carry;
            carry = (b & 1) << 7;
        }
        v.bytes[0] ^= 0xe1 & core::hint::black_box(0u8.wrapping_sub(lsb));
    }
    x.copy_from_slice(&z.bytes);
}

/// The portable GHASH multiplication, `x` becoming `x · h`, for the
/// constant-time harness.
///
/// Not a service of the module: it is reachable only so that the timing
/// of the portable multiplication can be measured directly, and it is
/// hidden from the documented API.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] unless
/// [`oxicrypt_module::require_self_test_started`] admits the call: in
/// `Operational`, or in `SelfTest` on the thread running the power-up
/// self-tests.
#[doc(hidden)]
pub fn ghash_mul_portable_internal(x: &mut [u8; 16], h: &[u8; 16]) -> Result<(), Error> {
    require_self_test_started()?;
    gf_mul_portable(x, h);
    Ok(())
}

/// GHASH multiply dispatcher, `x` becoming `x · h`: the PCLMULQDQ path
/// when the `accel-aes` feature is on and the running CPU supports it,
/// else [`gf_mul_portable`]. Both give the same product, which the
/// `accel-aes` differential oracle in this module's tests checks.
fn gf_mul(x: &mut [u8; 16], h: &[u8; 16]) {
    #[cfg(feature = "accel-aes")]
    {
        let mut out = WipedBlock::new(WipedBuffer::GcmGhashOperand);
        if oxicrypt_aes_accel::ghash_mul(x, h, &mut out.bytes) {
            x.copy_from_slice(&out.bytes);
            return;
        }
    }
    gf_mul_portable(x, h);
}

/// Accumulate `data` into `y` by XOR-then-multiply-by-H, padding the
/// final partial block with zero bytes on the right (SP 800-38D §6.4).
fn ghash_update(y: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    let mut i = 0;
    while i < data.len() {
        let take = core::cmp::min(16, data.len() - i);
        let mut blk = [0u8; 16];
        blk[..take].copy_from_slice(&data[i..i + take]);
        for k in 0..16 {
            y[k] ^= blk[k];
        }
        gf_mul(y, h);
        i += 16;
    }
}

/// Longest GCM plaintext or ciphertext, in bytes: 2^39 − 256 bits
/// (SP 800-38D §5.2.1.1), so the 32-bit block counter cannot wrap.
pub(crate) const GCM_MAX_TEXT_LEN: u64 = (1 << 36) - 32;

/// Longest GCM associated data, in bytes: the whole bytes within 2^64 − 1
/// bits (SP 800-38D §5.2.1.1), so the GHASH length block cannot overflow.
pub(crate) const GCM_MAX_AAD_LEN: u64 = (1 << 61) - 1;

/// Least security strength, in bits, of a generator that may produce a
/// 96-bit GCM IV.
const GCM_IV_MIN_STRENGTH_BITS: u32 = 96;

/// The SP 800-38D §5.2.1.1 input bounds, shared by encryption and
/// decryption and checked before any key material is used.
pub(crate) fn check_gcm_lengths(aad_len: u64, text_len: u64) -> Result<(), ModeError> {
    if text_len > GCM_MAX_TEXT_LEN {
        return Err(ModeError::InvalidPayloadLength);
    }
    if aad_len > GCM_MAX_AAD_LEN {
        return Err(ModeError::InvalidAadLength);
    }
    Ok(())
}

/// A buffer length as the `u64` [`check_gcm_lengths`] takes.
fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// The IV and tag of one GCM encryption, both public once the encryption
/// has run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcmSealed {
    /// The 96-bit IV drawn from the generator passed in for this encryption.
    pub iv: [u8; 12],
    /// The 128-bit authentication tag.
    pub tag: [u8; 16],
}

/// AES-GCM authenticated encryption (SP 800-38D §7.1) under an IV drawn
/// from `drbg`.
///
/// The 96-bit IV is one 12-byte draw from `drbg`, the whole IV being
/// random (SP 800-38D §8.2.2). It is held in zeroizing storage until the
/// encryption has consumed it and is then returned in [`GcmSealed`] with
/// the 128-bit tag. The approved sources for `drbg` are the DRBG types of
/// the `oxicrypt-drbg` crate; any other [`Rbg`] implementation is outside
/// the approved service. `ciphertext_out` must be as long as `plaintext`.
///
/// # Errors
///
/// Checked in this order, each before any output is written:
/// [`ModeError::Module`] carrying [`Error::NotOperational`] unless the
/// module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-GCM at the key's size;
/// [`ModeError::InvalidPayloadLength`] for a plaintext longer than
/// 2^36 − 32 bytes and [`ModeError::InvalidAadLength`] for associated data
/// longer than 2^61 − 1 bytes; [`ModeError::LengthMismatch`] when
/// `ciphertext_out` is not as long as `plaintext`;
/// [`ModeError::RbgTooWeak`] when `drbg`'s security strength is below
/// 96 bits; [`ModeError::Module`] carrying [`Error::KeyExhausted`], before
/// any IV is drawn, when the key's invocation count has reached its limit
/// (see [`GcmKey`]); and [`ModeError::Rbg`] carrying the generator's own
/// error when it produces no IV, for example [`RbgError::Uninstantiated`].
/// The invocation reserved before the draw is not released when the draw
/// fails. A module
/// that enters its error state while the encryption runs stops it with
/// [`ModeError::Module`], and `ciphertext_out` may then be partly written.
///
/// No public function encrypts under a caller-supplied IV; the fixed-IV
/// core the power-up self-test uses is private to this crate:
///
/// ```compile_fail,E0603
/// let key = oxicrypt_aes::EcbKey::new(&[0u8; 16]).unwrap();
/// let (mut ct, mut tag) = ([0u8; 16], [0u8; 16]);
/// let iv = [0u8; 12];
/// let _ = oxicrypt_aes::modes::gcm_encrypt_core(&key, &iv, b"", &[0u8; 16], &mut ct, &mut tag);
/// ```
pub fn gcm_encrypt<R: Rbg>(
    key: &GcmKey,
    drbg: &mut R,
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<GcmSealed, ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(GCM_SERVICES))?;
    check_gcm_lengths(len_u64(aad), len_u64(plaintext))?;
    if plaintext.len() != ciphertext_out.len() {
        return Err(ModeError::LengthMismatch);
    }
    if drbg.strength_bits() < GCM_IV_MIN_STRENGTH_BITS {
        return Err(ModeError::RbgTooWeak);
    }
    key.reserve_invocation()?;
    let mut iv = Zeroizing::new([0u8; 12]);
    let sealed = gcm_seal_under(&key.schedule, drbg, &mut iv, aad, plaintext, ciphertext_out);
    wipe_gcm_iv(&mut iv);
    sealed
}

/// Draws the IV into `iv` and encrypts under it. The caller wipes `iv`
/// after this returns, on success and on every error.
fn gcm_seal_under<B: BlockCipher, R: Rbg>(
    cipher: &B,
    drbg: &mut R,
    iv: &mut Zeroizing<[u8; 12]>,
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<GcmSealed, ModeError> {
    drbg.fill(&mut iv[..]).map_err(ModeError::Rbg)?;
    let mut tag = WipedBlock::new(WipedBuffer::GcmSealTag);
    gcm_encrypt_core(
        cipher,
        &iv[..],
        aad,
        plaintext,
        ciphertext_out,
        &mut tag.bytes,
    )?;
    Ok(GcmSealed {
        iv: **iv,
        tag: tag.bytes,
    })
}

/// GCM encryption under a caller-supplied IV, without the service gates,
/// for the power-up self-tests and [`gcm_encrypt`].
pub(crate) fn gcm_encrypt_core<B: BlockCipher>(
    cipher: &B,
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8; 16],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    if iv.len() != 12 {
        return Err(ModeError::InvalidIvLength);
    }
    if plaintext.len() != ciphertext_out.len() {
        return Err(ModeError::LengthMismatch);
    }

    // SP 800-38D §7.1 step 1: H = CIPH_K(0^128).
    let mut h = WipedBlock::new(WipedBuffer::GcmHashKey);
    cipher.encrypt_block_with(started, &mut h.bytes)?;

    // SP 800-38D §7.1 step 2, 96-bit IV: J0 = IV || 0^31 || 1.
    let mut j0 = WipedBlock::new(WipedBuffer::GcmPreCounterBlock);
    j0.bytes[..12].copy_from_slice(iv);
    j0.bytes[15] = 0x01;

    // SP 800-38D §7.1 step 3: C = GCTR_K(inc32(J0), P).
    let mut counter = WipedBlock::new(WipedBuffer::GcmCounter);
    let mut ks = WipedBlock::new(WipedBuffer::GcmKeystream);
    counter.bytes = j0.bytes;
    inc32(&mut counter.bytes);
    let mut i = 0;
    while i < plaintext.len() {
        ks.bytes = counter.bytes;
        cipher.encrypt_block_with(started, &mut ks.bytes)?;
        let take = core::cmp::min(16, plaintext.len() - i);
        for j in 0..take {
            ciphertext_out[i + j] = plaintext[i + j] ^ ks.bytes[j];
        }
        inc32(&mut counter.bytes);
        i += 16;
    }

    // SP 800-38D §7.1 steps 4 and 5: S = GHASH_H(A || 0^v || C || 0^u ||
    // [len(A)]_64 || [len(C)]_64).
    let mut y = WipedBlock::new(WipedBuffer::GcmGhashState);
    ghash_final(&mut y.bytes, &h.bytes, aad, ciphertext_out);

    // SP 800-38D §7.1 step 6: T = GCTR_K(J0, S), one block, so
    // CIPH_K(J0) XOR S.
    let mut ej0 = WipedBlock::new(WipedBuffer::GcmTagMask);
    let mut tag = WipedBlock::new(WipedBuffer::GcmTag);
    ej0.bytes = j0.bytes;
    cipher.encrypt_block_with(started, &mut ej0.bytes)?;
    for k in 0..16 {
        tag.bytes[k] = ej0.bytes[k] ^ y.bytes[k];
    }
    tag_out.copy_from_slice(&tag.bytes);
    Ok(())
}

/// S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
/// (SP 800-38D §7.1 step 5, §7.2 step 6), accumulated into `y`, which
/// starts at zero.
fn ghash_final(y: &mut [u8; 16], h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) {
    ghash_update(y, h, aad);
    ghash_update(y, h, ciphertext);
    let mut lenblk = [0u8; 16];
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    lenblk[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lenblk[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    for k in 0..16 {
        y[k] ^= lenblk[k];
    }
    gf_mul(y, h);
}

/// AES-GCM authenticated decryption, in which the tag is compared with no
/// early exit (SP 800-38D §7.2). Returns `Ok(())` only if the tag verifies.
///
/// The tag is verified before any plaintext is computed, so
/// `plaintext_out` is not written unless the tag verifies: on
/// [`ModeError::TagMismatch`] and on every other error returned before the
/// tag has verified it holds what the caller put there. `iv` is the IV the
/// encrypting party returned in [`GcmSealed`], and `plaintext_out` must be
/// as long as `ciphertext`.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-GCM at the key's size; then, before
/// any key material is used, [`ModeError::InvalidPayloadLength`] for a
/// ciphertext longer than 2^36 − 32 bytes and
/// [`ModeError::InvalidAadLength`] for associated data longer than
/// 2^61 − 1 bytes; [`ModeError::InvalidIvLength`] when `iv` is not 12
/// bytes; [`ModeError::LengthMismatch`] when `plaintext_out` is not as
/// long as `ciphertext`; and [`ModeError::TagMismatch`] when the tag does
/// not verify. A module that enters its error state after the tag has
/// verified stops the decryption with [`ModeError::Module`], and
/// `plaintext_out` is then zeroized, so no partial plaintext is left in
/// it.
pub fn gcm_decrypt(
    key: &GcmKey,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(GCM_SERVICES))?;
    check_gcm_lengths(len_u64(aad), len_u64(ciphertext))?;
    gcm_decrypt_core(&key.schedule, iv, aad, ciphertext, tag, plaintext_out)
}

/// [`gcm_decrypt`] without the service gates, for the power-up self-tests.
pub(crate) fn gcm_decrypt_core<B: BlockCipher>(
    cipher: &B,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    if iv.len() != 12 {
        return Err(ModeError::InvalidIvLength);
    }
    if ciphertext.len() != plaintext_out.len() {
        return Err(ModeError::LengthMismatch);
    }

    let mut h = WipedBlock::new(WipedBuffer::GcmHashKey);
    cipher.encrypt_block_with(started, &mut h.bytes)?;

    let mut j0 = WipedBlock::new(WipedBuffer::GcmPreCounterBlock);
    j0.bytes[..12].copy_from_slice(iv);
    j0.bytes[15] = 0x01;

    // SP 800-38D §7.2 computes P before comparing tags; the tag is
    // checked first here so that a forged message writes no plaintext.
    let mut y = WipedBlock::new(WipedBuffer::GcmGhashState);
    ghash_final(&mut y.bytes, &h.bytes, aad, ciphertext);

    let mut ej0 = WipedBlock::new(WipedBuffer::GcmTagMask);
    let mut computed_tag = WipedBlock::new(WipedBuffer::GcmTag);
    ej0.bytes = j0.bytes;
    cipher.encrypt_block_with(started, &mut ej0.bytes)?;
    for k in 0..16 {
        computed_tag.bytes[k] = ej0.bytes[k] ^ y.bytes[k];
    }

    // Every byte difference is accumulated with no early exit. That the
    // compiled comparison takes the same time wherever the tags differ is
    // unproven: no timing probe covers it.
    let mut diff: u8 = 0;
    for k in 0..16 {
        diff |= computed_tag.bytes[k] ^ tag[k];
    }
    if diff != 0 {
        return Err(ModeError::TagMismatch);
    }

    // SP 800-38D §7.2 step 4: P = GCTR_K(inc32(J0), C).
    let mut counter = WipedBlock::new(WipedBuffer::GcmCounter);
    let mut ks = WipedBlock::new(WipedBuffer::GcmKeystream);
    counter.bytes = j0.bytes;
    inc32(&mut counter.bytes);
    let mut i = 0;
    while i < ciphertext.len() {
        ks.bytes = counter.bytes;
        if let Err(e) = cipher.encrypt_block_with(started, &mut ks.bytes) {
            oxicrypt_zeroize::zeroize(plaintext_out);
            return Err(e.into());
        }
        let take = core::cmp::min(16, ciphertext.len() - i);
        for j in 0..take {
            plaintext_out[i + j] = ciphertext[i + j] ^ ks.bytes[j];
        }
        inc32(&mut counter.bytes);
        i += 16;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{
        CbcKey, CtrKey, GCM_MAX_AAD_LEN, GCM_MAX_TEXT_LEN, GcmKey, ModeError, cbc_decrypt,
        cbc_encrypt, check_gcm_lengths, ctr, ecb_decrypt, ecb_encrypt, gcm_decrypt, gcm_encrypt,
    };
    use crate::block::EcbKey;
    use oxicrypt_module::{Rbg, RbgError};

    /// A generator whose every output byte is one more than the last, so
    /// no two draws are equal.
    struct CountingRbg(u8);

    impl Rbg for CountingRbg {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
            for b in out {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }

        fn strength_bits(&self) -> u32 {
            256
        }
    }

    /// A generator that returns the same bytes on every draw.
    struct ConstantRbg;

    impl Rbg for ConstantRbg {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
            out.fill(0x5c);
            Ok(())
        }

        fn strength_bits(&self) -> u32 {
            256
        }
    }

    /// A generator that produces no output and returns its error.
    struct FailingRbg(RbgError);

    impl Rbg for FailingRbg {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
            out.fill(0x5a);
            Err(self.0)
        }

        fn strength_bits(&self) -> u32 {
            256
        }
    }

    /// A generator reporting a security strength of 80 bits.
    struct WeakRbg;

    impl Rbg for WeakRbg {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
            out.fill(0x5c);
            Ok(())
        }

        fn strength_bits(&self) -> u32 {
            80
        }
    }

    /// Output bytes no encryption of [`PT`] under [`KEY`] produces in the
    /// tests below, so an untouched buffer is recognisable.
    const SENTINEL: u8 = 0xa5;
    const KEY: [u8; 32] = [0x66; 32];
    const PT: [u8; 37] = [0x99; 37];

    /// Two encryptions of [`PT`] under one key, returning each IV and
    /// whether each decrypts back to [`PT`] under that key.
    fn two_encryptions<R: Rbg>(drbg: &mut R) -> ([[u8; 12]; 2], [bool; 2]) {
        let k = GcmKey::new(&KEY).unwrap();
        let aad = [0x88u8; 13];
        let mut ivs = [[0u8; 12]; 2];
        let mut round_trips = [false; 2];
        for i in 0..2 {
            let mut ct = [0u8; 37];
            let sealed = gcm_encrypt(&k, drbg, &aad, &PT, &mut ct).unwrap();
            let mut back = [0u8; 37];
            gcm_decrypt(&k, &sealed.iv, &aad, &ct, &sealed.tag, &mut back).unwrap();
            ivs[i] = sealed.iv;
            round_trips[i] = back == PT;
        }
        (ivs, round_trips)
    }

    /// The two GHASH multiplications of the GCM specification's Test Case 2
    /// (H, C, X1 and the final GHASH value), through the harness entry.
    #[test]
    fn ghash_mul_portable_matches_test_case_2() {
        crate::test_support::start_module();
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let mut y = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        super::ghash_mul_portable_internal(&mut y, &h).unwrap();
        let x1 = [
            0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53,
            0xde, 0xb7,
        ];
        assert_eq!(y, x1);
        y[15] ^= 0x80;
        super::ghash_mul_portable_internal(&mut y, &h).unwrap();
        let ghash = [
            0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0,
            0xf8, 0x85,
        ];
        assert_eq!(y, ghash);
    }

    /// Two encryptions under one key draw different 12-byte IVs, and each
    /// IV decrypts its own ciphertext. A generator with a constant output
    /// yields equal IVs, so the inequality is what the test checks.
    #[test]
    fn gcm_ivs_differ_and_decrypt() {
        crate::test_support::start_module();
        let (ivs, round_trips) = two_encryptions(&mut CountingRbg(1));
        assert_ne!(ivs[0], ivs[1]);
        assert_eq!(round_trips, [true, true]);
        assert_eq!(ivs[0], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        let (constant, _) = two_encryptions(&mut ConstantRbg);
        assert_eq!(constant[0], constant[1]);
    }

    /// The bounds are SP 800-38D §5.2.1.1's, in bytes, and the shared
    /// check admits each bound and refuses one byte past it.
    #[test]
    fn gcm_length_limits() {
        assert_eq!(GCM_MAX_TEXT_LEN * 8, (1u64 << 39) - 256);
        assert_eq!(GCM_MAX_AAD_LEN, u64::MAX / 8);
        assert_eq!(GCM_MAX_AAD_LEN, (1u64 << 61) - 1);

        assert_eq!(check_gcm_lengths(GCM_MAX_AAD_LEN, GCM_MAX_TEXT_LEN), Ok(()));
        assert_eq!(check_gcm_lengths(0, 0), Ok(()));
        assert_eq!(
            check_gcm_lengths(0, GCM_MAX_TEXT_LEN + 1),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(
            check_gcm_lengths(GCM_MAX_AAD_LEN + 1, 0),
            Err(ModeError::InvalidAadLength)
        );
        assert_eq!(
            check_gcm_lengths(u64::MAX, u64::MAX),
            Err(ModeError::InvalidPayloadLength)
        );

        crate::test_support::start_module();
        let k = GcmKey::new(&KEY).unwrap();
        let mut ct = [SENTINEL; 37];
        let sealed = gcm_encrypt(&k, &mut CountingRbg(0), b"aad", &PT, &mut ct).unwrap();
        let mut back = [0u8; 37];
        assert_eq!(
            gcm_decrypt(&k, &sealed.iv, b"aad", &ct, &sealed.tag, &mut back),
            Ok(())
        );
        assert_eq!(back, PT);
    }

    /// A generator that produces no output, or one too weak for a 96-bit
    /// IV, is refused with its error before anything is written; an
    /// instantiated generator succeeds.
    #[test]
    fn drbg_refusal_before_output() {
        crate::test_support::start_module();
        let k = GcmKey::new(&KEY).unwrap();
        for e in [
            RbgError::Uninstantiated,
            RbgError::EntropyUnavailable,
            RbgError::NotOperational,
        ] {
            let mut ct = [SENTINEL; 37];
            assert_eq!(
                gcm_encrypt(&k, &mut FailingRbg(e), b"", &PT, &mut ct),
                Err(ModeError::Rbg(e))
            );
            assert_eq!(ct, [SENTINEL; 37], "{e:?}");
        }

        let mut ct = [SENTINEL; 37];
        assert_eq!(
            gcm_encrypt(&k, &mut WeakRbg, b"", &PT, &mut ct),
            Err(ModeError::RbgTooWeak)
        );
        assert_eq!(ct, [SENTINEL; 37]);

        let mut ct = [SENTINEL; 37];
        assert!(gcm_encrypt(&k, &mut CountingRbg(0), b"", &PT, &mut ct).is_ok());
        assert_ne!(ct, [SENTINEL; 37]);
    }

    /// A generator that counts the draws made from it.
    #[derive(Default)]
    struct TallyRbg {
        draws: usize,
    }

    impl Rbg for TallyRbg {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
            self.draws += 1;
            out.fill(0x3c);
            Ok(())
        }

        fn strength_bits(&self) -> u32 {
            256
        }
    }

    const LIMIT: u64 = 1 << 32;
    const EXHAUSTED: ModeError = ModeError::Module(oxicrypt_module::Error::KeyExhausted);

    /// One encryption of [`PT`] under `k` into a sentinel-filled buffer,
    /// returning the result and whether the buffer is still untouched.
    fn encrypt_once<R: Rbg>(k: &GcmKey, drbg: &mut R) -> (Result<(), ModeError>, bool) {
        let mut ct = [SENTINEL; 37];
        let result = gcm_encrypt(k, drbg, b"", &PT, &mut ct).map(|_| ());
        (result, ct == [SENTINEL; 37])
    }

    /// A key preloaded to 2^32 − 1 encryptions performs the 2^32th and
    /// refuses every later one before drawing an IV or writing output. The
    /// exhausted key still decrypts, and decryption does not count.
    #[test]
    fn gcm_key_exhausts_at_2_32() {
        crate::test_support::start_module();
        let k = GcmKey::new_with_count(&KEY, LIMIT - 1).unwrap();
        let mut drbg = TallyRbg::default();
        let mut ct = [SENTINEL; 37];
        let sealed = gcm_encrypt(&k, &mut drbg, b"", &PT, &mut ct).unwrap();
        assert_eq!(drbg.draws, 1);
        assert_eq!(k.invocations(), LIMIT);

        for _ in 0..2 {
            assert_eq!(encrypt_once(&k, &mut drbg), (Err(EXHAUSTED), true));
            assert_eq!(drbg.draws, 1, "an IV was drawn under an exhausted key");
            assert_eq!(k.invocations(), LIMIT);
        }

        let mut back = [0u8; 37];
        gcm_decrypt(&k, &sealed.iv, b"", &ct, &sealed.tag, &mut back).unwrap();
        assert_eq!(back, PT);
        assert_eq!(k.invocations(), LIMIT);
    }

    /// Threads reserving under one key, each until it is refused, together
    /// take exactly the key's share and no more.
    #[test]
    fn gcm_count_is_atomic_under_threads() {
        const THREADS: usize = 16;
        const SHARE: u64 = 100_000;
        crate::test_support::start_module();
        let k = GcmKey::new_with_limit(&KEY, SHARE).unwrap();
        let start = std::sync::Barrier::new(THREADS);
        let taken: std::vec::Vec<u64> = std::thread::scope(|s| {
            let handles: std::vec::Vec<_> = (0..THREADS)
                .map(|_| {
                    s.spawn(|| {
                        let mut ok = 0u64;
                        start.wait();
                        loop {
                            match k.reserve_invocation() {
                                Ok(()) => ok += 1,
                                Err(e) => {
                                    assert_eq!(e, EXHAUSTED);
                                    break ok;
                                }
                            }
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(taken.len(), THREADS);
        assert_eq!(taken.iter().sum::<u64>(), SHARE);
        assert_eq!(k.invocations(), SHARE);
    }

    /// Threads encrypting through [`gcm_encrypt`] under one key with a
    /// share, each until it is refused, together perform exactly the share
    /// of encryptions, and the next encryption is refused with its output
    /// untouched.
    #[test]
    fn gcm_encrypt_share_is_exact_under_threads() {
        const THREADS: usize = 8;
        const SHARE: u64 = 256;
        crate::test_support::start_module();
        let k = GcmKey::new_with_limit(&KEY, SHARE).unwrap();
        let start = std::sync::Barrier::new(THREADS);
        let sealed: std::vec::Vec<u64> = std::thread::scope(|s| {
            let handles: std::vec::Vec<_> = (0..THREADS)
                .map(|_| {
                    s.spawn(|| {
                        let mut drbg = CountingRbg(0);
                        let mut ok = 0u64;
                        start.wait();
                        loop {
                            match encrypt_once(&k, &mut drbg).0 {
                                Ok(()) => ok += 1,
                                Err(e) => {
                                    assert_eq!(e, EXHAUSTED);
                                    break ok;
                                }
                            }
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(sealed.len(), THREADS);
        assert_eq!(sealed.iter().sum::<u64>(), SHARE);
        assert_eq!(k.invocations(), SHARE);
        assert_eq!(
            encrypt_once(&k, &mut CountingRbg(0)),
            (Err(EXHAUSTED), true)
        );
    }

    /// The ciphertext of [`PT`] padded with zeros to 48 bytes under ECB
    /// with [`KEY`], the key of [`crate::test_support::FailAt`].
    fn ecb_ciphertext() -> [u8; 48] {
        let key = EcbKey::new(&KEY).unwrap();
        let mut pt = [0u8; 48];
        pt[..37].copy_from_slice(&PT);
        let mut ct = [0u8; 48];
        super::ecb_encrypt_core(&key, &pt, &mut ct).unwrap();
        ct
    }

    /// A module error on the second block of an ECB decryption leaves the
    /// caller's buffer all zero, although the first block was written.
    #[test]
    fn ecb_decrypt_error_zeroizes_output() {
        use crate::test_support::{FAILED, FailAt};
        crate::test_support::start_module();
        let cipher = FailAt::new(2);
        let mut out = [SENTINEL; 48];
        let r = super::ecb_decrypt_core(&cipher, &ecb_ciphertext(), &mut out);
        assert_eq!(r, Err(ModeError::Module(FAILED)));
        assert_eq!(cipher.calls.get(), 2);
        assert_eq!(out, [0u8; 48]);
    }

    /// A module error on the second block of a CBC decryption leaves the
    /// caller's buffer all zero, although the first block was written.
    #[test]
    fn cbc_decrypt_error_zeroizes_output() {
        use crate::test_support::{FAILED, FailAt};
        crate::test_support::start_module();
        let cipher = FailAt::new(2);
        let mut out = [SENTINEL; 48];
        let r = super::cbc_decrypt_core(&cipher, &[0x0f; 16], &ecb_ciphertext(), &mut out);
        assert_eq!(r, Err(ModeError::Module(FAILED)));
        assert_eq!(cipher.calls.get(), 2);
        assert_eq!(out, [0u8; 48]);
    }

    /// A module error on the second keystream block of CTR leaves the
    /// caller's buffer all zero, although the first block was written.
    #[test]
    fn ctr_error_zeroizes_output() {
        use crate::test_support::{FAILED, FailAt};
        crate::test_support::start_module();
        let cipher = FailAt::new(2);
        let mut out = [SENTINEL; 37];
        let r = super::ctr_core(&cipher, &[0xf0; 16], &PT, &mut out);
        assert_eq!(r, Err(ModeError::Module(FAILED)));
        assert_eq!(cipher.calls.get(), 2);
        assert_eq!(out, [0u8; 37]);
    }

    /// A module error on the second GCTR block of a GCM decryption whose
    /// tag verified leaves the caller's buffer all zero, although the
    /// first block was written. Calls 1 and 2 compute H and CIPH_K(J0).
    #[test]
    fn gcm_decrypt_error_after_tag_zeroizes_output() {
        use crate::test_support::{FAILED, FailAt};
        crate::test_support::start_module();
        let key = EcbKey::new(&KEY).unwrap();
        let iv = [0x2d; 12];
        let mut ct = [0u8; 37];
        let mut tag = [0u8; 16];
        super::gcm_encrypt_core(&key, &iv, b"aad", &PT, &mut ct, &mut tag).unwrap();

        let cipher = FailAt::new(4);
        let mut out = [SENTINEL; 37];
        let r = super::gcm_decrypt_core(&cipher, &iv, b"aad", &ct, &tag, &mut out);
        assert_eq!(r, Err(ModeError::Module(FAILED)));
        assert_eq!(cipher.calls.get(), 4);
        assert_eq!(out, [0u8; 37]);

        let mut back = [0u8; 37];
        let r = super::gcm_decrypt_core(&key, &iv, b"aad", &ct, &tag, &mut back);
        assert_eq!((r, back), (Ok(()), PT));
    }

    /// The count starts at 0, rises by one per encryption, ignores
    /// decryption, and starts at the preloaded value when one is given.
    #[test]
    fn gcm_count_readable_and_preloadable() {
        crate::test_support::start_module();
        let k = GcmKey::new(&KEY).unwrap();
        assert_eq!(k.invocations(), 0);
        let mut drbg = CountingRbg(0);
        let mut ct = [0u8; 37];
        let mut last = None;
        for i in 1..=3 {
            last = Some(gcm_encrypt(&k, &mut drbg, b"", &PT, &mut ct).unwrap());
            assert_eq!(k.invocations(), i);
        }
        let sealed = last.unwrap();
        let mut back = [0u8; 37];
        gcm_decrypt(&k, &sealed.iv, b"", &ct, &sealed.tag, &mut back).unwrap();
        assert_eq!(k.invocations(), 3);

        let preloaded = GcmKey::new_with_count(&KEY, 7).unwrap();
        assert_eq!(preloaded.invocations(), 7);
        assert_eq!(encrypt_once(&preloaded, &mut drbg).0, Ok(()));
        assert_eq!(preloaded.invocations(), 8);
    }

    /// A limit above 2^32 or of 0 and a preload above 2^32 are refused; a
    /// key preloaded to 2^32 is built and refuses its first encryption; a
    /// key with a share of three performs three and refuses the fourth.
    #[test]
    fn gcm_key_limit_and_count() {
        crate::test_support::start_module();
        let refused = |r: Result<GcmKey, oxicrypt_module::Error>| {
            matches!(r, Err(oxicrypt_module::Error::InvalidInput))
        };
        assert!(refused(GcmKey::new_with_limit(&KEY, LIMIT + 1)));
        assert!(refused(GcmKey::new_with_limit(&KEY, 0)));
        assert!(refused(GcmKey::new_with_count(&KEY, LIMIT + 1)));
        assert!(refused(GcmKey::new_with_count(&KEY, u64::MAX)));
        assert!(GcmKey::new_with_limit(&KEY, LIMIT).is_ok());

        let mut drbg = TallyRbg::default();
        let full = GcmKey::new_with_count(&KEY, LIMIT).unwrap();
        assert_eq!(full.invocations(), LIMIT);
        assert_eq!(encrypt_once(&full, &mut drbg), (Err(EXHAUSTED), true));
        assert_eq!(drbg.draws, 0);

        let share = GcmKey::new_with_limit(&KEY, 3).unwrap();
        for _ in 0..3 {
            assert_eq!(encrypt_once(&share, &mut drbg).0, Ok(()));
        }
        assert_eq!(encrypt_once(&share, &mut drbg), (Err(EXHAUSTED), true));
        assert_eq!(drbg.draws, 3);
        assert_eq!(share.invocations(), 3);
    }

    /// An encryption that fails after its invocation is reserved leaves the
    /// invocation spent; one refused before the reservation (a buffer of
    /// the wrong length, a generator too weak) spends nothing.
    #[test]
    fn gcm_failed_encryption_spends_invocation() {
        crate::test_support::start_module();
        let k = GcmKey::new_with_limit(&KEY, 2).unwrap();

        let mut short = [SENTINEL; 36];
        assert_eq!(
            gcm_encrypt(&k, &mut CountingRbg(0), b"", &PT, &mut short),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(encrypt_once(&k, &mut WeakRbg).0, Err(ModeError::RbgTooWeak));
        assert_eq!(k.invocations(), 0);

        assert_eq!(
            encrypt_once(&k, &mut FailingRbg(RbgError::Uninstantiated)),
            (Err(ModeError::Rbg(RbgError::Uninstantiated)), true)
        );
        assert_eq!(k.invocations(), 1);

        assert_eq!(encrypt_once(&k, &mut CountingRbg(0)).0, Ok(()));
        assert_eq!(k.invocations(), 2);
        assert_eq!(
            encrypt_once(&k, &mut CountingRbg(0)),
            (Err(EXHAUSTED), true)
        );
    }

    #[test]
    fn ecb_roundtrip_aes128_single_block() {
        crate::test_support::start_module();
        let key = [0u8; 16];
        let k = EcbKey::new(&key).unwrap();
        let pt = [0x00; 16];
        let mut ct = [0u8; 16];
        let mut back = [0u8; 16];
        ecb_encrypt(&k, &pt, &mut ct).unwrap();
        ecb_decrypt(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn cbc_roundtrip_aes128() {
        crate::test_support::start_module();
        let key = [0x11u8; 16];
        let k = CbcKey::new(&key).unwrap();
        let iv = [0x22u8; 16];
        let pt = [0xaau8; 32];
        let mut ct = [0u8; 32];
        let mut back = [0u8; 32];
        cbc_encrypt(&k, &iv, &pt, &mut ct).unwrap();
        cbc_decrypt(&k, &iv, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn ctr_roundtrip_aes128() {
        crate::test_support::start_module();
        let key = [0x33u8; 16];
        let k = CtrKey::new(&key).unwrap();
        let icb = [0x44u8; 16];
        let pt = [0x55u8; 37];
        let mut ct = [0u8; 37];
        let mut back = [0u8; 37];
        ctr(&k, &icb, &pt, &mut ct).unwrap();
        ctr(&k, &icb, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    /// SP 800-38A Appendix A: ECB and CBC take a positive number of
    /// blocks, so an empty input is refused; one block is accepted.
    #[test]
    fn ecb_cbc_refuse_empty() {
        crate::test_support::start_module();
        let ecb = EcbKey::new(&[0x11u8; 16]).unwrap();
        let cbc = CbcKey::new(&[0x22u8; 16]).unwrap();
        let iv = [0x33u8; 16];
        let mut empty: [u8; 0] = [];
        assert_eq!(
            ecb_encrypt(&ecb, &[], &mut empty),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(
            ecb_decrypt(&ecb, &[], &mut empty),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(
            cbc_encrypt(&cbc, &iv, &[], &mut empty),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(
            cbc_decrypt(&cbc, &iv, &[], &mut empty),
            Err(ModeError::InvalidPayloadLength)
        );
        let block = [0x44u8; 16];
        let mut out = [0u8; 16];
        assert_eq!(ecb_encrypt(&ecb, &block, &mut out), Ok(()));
        assert_eq!(ecb_decrypt(&ecb, &block, &mut out), Ok(()));
        assert_eq!(cbc_encrypt(&cbc, &iv, &block, &mut out), Ok(()));
        assert_eq!(cbc_decrypt(&cbc, &iv, &block, &mut out), Ok(()));
    }

    /// An output shorter or longer than the input is refused before any
    /// byte is written; equal lengths succeed.
    #[test]
    fn ctr_short_output_is_length_mismatch() {
        crate::test_support::start_module();
        let k = CtrKey::new(&[0x33u8; 16]).unwrap();
        let icb = [0x44u8; 16];
        let pt = [0x55u8; 37];
        let mut short = [0xA5u8; 36];
        assert_eq!(
            ctr(&k, &icb, &pt, &mut short),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(short, [0xA5u8; 36]);
        let mut long = [0xA5u8; 38];
        assert_eq!(
            ctr(&k, &icb, &pt, &mut long),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(long, [0xA5u8; 38]);
        let mut exact = [0u8; 37];
        assert_eq!(ctr(&k, &icb, &pt, &mut exact), Ok(()));
        assert_ne!(exact, [0u8; 37]);
    }

    #[test]
    fn gcm_roundtrip_aes128() {
        crate::test_support::start_module();
        let key = [0x66u8; 16];
        let k = GcmKey::new(&key).unwrap();
        let aad = [0x88u8; 13];
        let pt = [0x99u8; 37];
        let mut ct = [0u8; 37];
        let mut back = [0u8; 37];
        let sealed = gcm_encrypt(&k, &mut CountingRbg(0x77), &aad, &pt, &mut ct).unwrap();
        gcm_decrypt(&k, &sealed.iv, &aad, &ct, &sealed.tag, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn gcm_detects_tag_tamper() {
        crate::test_support::start_module();
        let key = [0u8; 16];
        let k = GcmKey::new(&key).unwrap();
        let pt = [0u8; 16];
        let mut ct = [0u8; 16];
        let mut back = [0u8; 16];
        let mut sealed = gcm_encrypt(&k, &mut CountingRbg(0), &[], &pt, &mut ct).unwrap();
        sealed.tag[0] ^= 1;
        assert!(gcm_decrypt(&k, &sealed.iv, &[], &ct, &sealed.tag, &mut back).is_err());
    }

    /// The drawn IV is held in a `Zeroizing<[u8; 12]>` buffer that is
    /// wiped before return: the production code passes that buffer to this
    /// function, whose parameter type is fixed here, so a change of the
    /// buffer's storage type does not compile. The core also copies the IV
    /// into the pre-counter block, which the crate's intermediate
    /// zeroization covers.
    const _: fn(&mut oxicrypt_zeroize::Zeroizing<[u8; 12]>) = crate::wipe::wipe_gcm_iv;

    /// The IV buffer is wiped through the crate's wipe seam on the success
    /// path, when the generator fails, and when the module enters its
    /// error state after the IV is drawn and before it is used. Each case
    /// runs in a process of its own so that the counter it reads counts
    /// only its own encryption.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn iv_bytes_never_outside_zeroizing_storage() {
        use crate::wipe::{WipedBuffer, seam::wipes};
        use oxicrypt_module::{Error, State, enter_error_state};

        /// Draws a good IV, then puts the module into its error state, so
        /// the encryption fails after generation.
        struct ErrorAfterDraw;

        impl Rbg for ErrorAfterDraw {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
                out.fill(0x5c);
                enter_error_state("GCM IV wipe test");
                Ok(())
            }

            fn strength_bits(&self) -> u32 {
                256
            }
        }

        crate::test_support::isolated(
            "modes::tests::iv_bytes_never_outside_zeroizing_storage",
            &["success", "rbg-failure", "error-after-draw", "too-weak"],
            |setting| {
                crate::test_support::start_module();
                let k = GcmKey::new(&KEY).unwrap();
                let mut ct = [SENTINEL; 37];
                assert_eq!(wipes(WipedBuffer::GcmIv), 0);
                let (result, expected_wipes) = match setting {
                    "success" => (
                        gcm_encrypt(&k, &mut CountingRbg(0), b"", &PT, &mut ct).map(|_| ()),
                        1,
                    ),
                    "rbg-failure" => (
                        gcm_encrypt(
                            &k,
                            &mut FailingRbg(RbgError::Uninstantiated),
                            b"",
                            &PT,
                            &mut ct,
                        )
                        .map(|_| ()),
                        1,
                    ),
                    "error-after-draw" => (
                        gcm_encrypt(&k, &mut ErrorAfterDraw, b"", &PT, &mut ct).map(|_| ()),
                        1,
                    ),
                    _ => (
                        gcm_encrypt(&k, &mut WeakRbg, b"", &PT, &mut ct).map(|_| ()),
                        0,
                    ),
                };
                let expected = match setting {
                    "success" => Ok(()),
                    "rbg-failure" => Err(ModeError::Rbg(RbgError::Uninstantiated)),
                    "error-after-draw" => Err(ModeError::Module(Error::NotOperational {
                        current: State::Error,
                    })),
                    _ => Err(ModeError::RbgTooWeak),
                };
                assert_eq!(result, expected, "{setting}");
                assert_eq!(wipes(WipedBuffer::GcmIv), expected_wipes, "{setting}");
                if setting != "success" {
                    assert_eq!(ct, [SENTINEL; 37], "{setting}");
                }
            },
        );
    }

    #[cfg(feature = "fault-injection")]
    mod intermediates {
        use super::{
            CbcKey, CountingRbg, CtrKey, GcmKey, KEY, ModeError, PT, SENTINEL, cbc_decrypt,
            cbc_encrypt, ctr, ecb_decrypt, ecb_encrypt, gcm_decrypt, gcm_encrypt,
        };
        use crate::block::EcbKey;
        use crate::ccm::ccm_decrypt_core;
        use crate::kw::{kw_wrap_core, kw_wrap_inverse_core, kwp_wrap_core, kwp_wrap_inverse_core};
        use crate::modes::{ctr_core, ecb_decrypt_core, gcm_encrypt_core};
        use crate::test_support::{FAILED, FailAt};
        use crate::wipe::WipedBuffer::{self, *};
        use crate::wipe::seam::wipes;
        use crate::{
            CcmKey, KwKey, ccm_decrypt, ccm_encrypt, kw_unwrap, kw_unwrap_inverse, kw_wrap,
            kw_wrap_inverse, kwp_unwrap, kwp_unwrap_inverse, kwp_wrap, kwp_wrap_inverse,
        };
        use oxicrypt_module::{Rbg, RbgError, enter_error_state};
        use std::format;
        use std::vec::Vec;

        /// A new [`WipedBuffer`] variant does not compile until it has an
        /// arm here, which names its position in the list.
        fn design() -> [WipedBuffer; 27] {
            let design = [
                GcmIv,
                GcmHashKey,
                GcmPreCounterBlock,
                GcmCounter,
                GcmKeystream,
                GcmGhashState,
                GcmTagMask,
                GcmTag,
                CcmEncryptMacState,
                CcmEncryptTagMask,
                CcmEncryptKeystream,
                CcmMacState,
                CcmBlock,
                KwWrapBlock,
                KwBlock,
                KwUnwrapOutput,
                KwRegister,
                CtrCounter,
                CtrKeystream,
                KeyExpansionWord,
                GcmGhashOperand,
                KwWrapOutput,
                CcmPlaintextBlock,
                EcbBlock,
                CbcBlock,
                GcmSealTag,
                RoundKeys,
            ];
            for (i, buffer) in design.into_iter().enumerate() {
                let position = match buffer {
                    GcmIv => 0,
                    GcmHashKey => 1,
                    GcmPreCounterBlock => 2,
                    GcmCounter => 3,
                    GcmKeystream => 4,
                    GcmGhashState => 5,
                    GcmTagMask => 6,
                    GcmTag => 7,
                    CcmEncryptMacState => 8,
                    CcmEncryptTagMask => 9,
                    CcmEncryptKeystream => 10,
                    CcmMacState => 11,
                    CcmBlock => 12,
                    KwWrapBlock => 13,
                    KwBlock => 14,
                    KwUnwrapOutput => 15,
                    KwRegister => 16,
                    CtrCounter => 17,
                    CtrKeystream => 18,
                    KeyExpansionWord => 19,
                    GcmGhashOperand => 20,
                    KwWrapOutput => 21,
                    CcmPlaintextBlock => 22,
                    EcbBlock => 23,
                    CbcBlock => 24,
                    GcmSealTag => 25,
                    RoundKeys => 26,
                };
                assert_eq!(position, i, "{buffer:?}");
            }
            design
        }

        /// The wipes of one identity that a path must make.
        #[derive(Clone, Copy)]
        enum Expect {
            /// The path builds a known number of guards of the identity,
            /// one per guard, or none when it exits before building one.
            Exactly(u64),
            /// The count depends on how far the work ran (the key
            /// expansion wipes one word per expanded word).
            AtLeastOnce,
        }
        use Expect::{AtLeastOnce, Exactly};

        const GCM_SEAL: &[(WipedBuffer, Expect)] = &[
            (GcmIv, Exactly(1)),
            (GcmHashKey, Exactly(1)),
            (GcmPreCounterBlock, Exactly(1)),
            (GcmCounter, Exactly(1)),
            (GcmKeystream, Exactly(1)),
            (GcmGhashState, Exactly(1)),
            (GcmGhashOperand, AtLeastOnce),
            (GcmTagMask, Exactly(1)),
            (GcmTag, Exactly(1)),
            (GcmSealTag, Exactly(1)),
        ];
        const GCM_OPEN: &[(WipedBuffer, Expect)] = &[
            (GcmHashKey, Exactly(1)),
            (GcmPreCounterBlock, Exactly(1)),
            (GcmGhashState, Exactly(1)),
            (GcmGhashOperand, AtLeastOnce),
            (GcmTagMask, Exactly(1)),
            (GcmTag, Exactly(1)),
            (GcmCounter, Exactly(1)),
            (GcmKeystream, Exactly(1)),
        ];
        const GCM_MISMATCH: &[(WipedBuffer, Expect)] = &[
            (GcmHashKey, Exactly(1)),
            (GcmPreCounterBlock, Exactly(1)),
            (GcmGhashState, Exactly(1)),
            (GcmGhashOperand, AtLeastOnce),
            (GcmTagMask, Exactly(1)),
            (GcmTag, Exactly(1)),
            (GcmCounter, Exactly(0)),
            (GcmKeystream, Exactly(0)),
        ];
        const GCM_GCTR_ERROR: &[(WipedBuffer, Expect)] = &[
            (GcmHashKey, Exactly(1)),
            (GcmPreCounterBlock, Exactly(1)),
            (GcmCounter, Exactly(1)),
            (GcmKeystream, Exactly(1)),
            (GcmGhashState, Exactly(0)),
            (GcmGhashOperand, Exactly(0)),
            (GcmTagMask, Exactly(0)),
            (GcmTag, Exactly(0)),
            (GcmSealTag, Exactly(0)),
        ];
        const CCM_SEAL: &[(WipedBuffer, Expect)] = &[
            (CcmEncryptMacState, Exactly(1)),
            (CcmEncryptTagMask, Exactly(1)),
            (CcmEncryptKeystream, Exactly(1)),
            (CcmPlaintextBlock, Exactly(1)),
        ];
        /// `ccm_open` holds one MAC state and three 16-byte blocks.
        const CCM_OPEN: &[(WipedBuffer, Expect)] = &[
            (CcmMacState, Exactly(1)),
            (CcmBlock, Exactly(3)),
            (CcmPlaintextBlock, Exactly(0)),
        ];
        const CTR: &[(WipedBuffer, Expect)] =
            &[(CtrCounter, Exactly(1)), (CtrKeystream, Exactly(1))];
        const ECB: &[(WipedBuffer, Expect)] = &[(EcbBlock, Exactly(1))];
        const CBC: &[(WipedBuffer, Expect)] = &[(CbcBlock, Exactly(1))];
        const WRAP: &[(WipedBuffer, Expect)] = &[
            (KwWrapBlock, Exactly(1)),
            (KwRegister, Exactly(1)),
            (KwWrapOutput, Exactly(0)),
        ];
        const WRAP_REFUSED: &[(WipedBuffer, Expect)] = &[
            (KwWrapBlock, Exactly(1)),
            (KwRegister, Exactly(1)),
            (KwWrapOutput, Exactly(1)),
        ];
        /// A wrap length refusal returns before the wrap writes anything.
        const WRAP_LENGTH_REFUSED: &[(WipedBuffer, Expect)] = &[
            (KwWrapBlock, Exactly(0)),
            (KwRegister, Exactly(0)),
            (KwWrapOutput, Exactly(0)),
        ];
        const UNWRAP: &[(WipedBuffer, Expect)] = &[(KwBlock, Exactly(1)), (KwRegister, Exactly(1))];
        const UNWRAP_REFUSED: &[(WipedBuffer, Expect)] = &[
            (KwBlock, Exactly(1)),
            (KwRegister, Exactly(1)),
            (KwUnwrapOutput, Exactly(1)),
        ];
        /// The module error is detected on entry to the GCM core, before
        /// H or J0 is built.
        const GCM_MODULE_ERROR: &[(WipedBuffer, Expect)] = &[
            (GcmIv, Exactly(1)),
            (GcmSealTag, Exactly(1)),
            (GcmHashKey, Exactly(0)),
            (GcmPreCounterBlock, Exactly(0)),
        ];

        type Wrap = fn(&KwKey, &[u8], &mut [u8]) -> Result<usize, ModeError>;

        type CoreWrap = fn(&FailAt, &[u8], &mut [u8]) -> Result<(), ModeError>;

        struct ErrorAfterDraw;

        impl Rbg for ErrorAfterDraw {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
                out.fill(0x5c);
                enter_error_state("intermediate wipe test");
                Ok(())
            }

            fn strength_bits(&self) -> u32 {
                256
            }
        }

        fn path(name: &str, expected: &[(WipedBuffer, Expect)], body: impl FnOnce()) {
            let before: Vec<u64> = expected.iter().map(|(b, _)| wipes(*b)).collect();
            body();
            for (&(buffer, expect), before) in expected.iter().zip(before) {
                let made = wipes(buffer) - before;
                match expect {
                    Exactly(n) => assert_eq!(made, n, "{name}: {buffer:?} wiped {made} times"),
                    AtLeastOnce => assert!(made >= 1, "{name}: {buffer:?} was not wiped"),
                }
            }
        }

        fn gcm_paths(gcm: &GcmKey) {
            let mut ct = [0u8; 37];
            let mut sealed = None;
            path("GCM encrypt", GCM_SEAL, || {
                sealed = Some(gcm_encrypt(gcm, &mut CountingRbg(0), b"aad", &PT, &mut ct));
            });
            let sealed = sealed.unwrap().unwrap();
            path("GCM decrypt", GCM_OPEN, || {
                let mut back = [0u8; 37];
                let r = gcm_decrypt(gcm, &sealed.iv, b"aad", &ct, &sealed.tag, &mut back);
                assert_eq!((r, back), (Ok(()), PT));
            });
            path("GCM decrypt, tag mismatch", GCM_MISMATCH, || {
                let mut bad = sealed.tag;
                bad[0] ^= 1;
                let mut back = [0u8; 37];
                let r = gcm_decrypt(gcm, &sealed.iv, b"aad", &ct, &bad, &mut back);
                assert_eq!(r, Err(ModeError::TagMismatch));
            });
            // Call 1 computes H; call 3 is the second GCTR block.
            path("GCM encrypt, cipher error mid-GCTR", GCM_GCTR_ERROR, || {
                let cipher = FailAt::new(3);
                let mut ct = [0u8; 37];
                let mut tag = [0u8; 16];
                let r = gcm_encrypt_core(&cipher, &[0x2d; 12], b"aad", &PT, &mut ct, &mut tag);
                assert_eq!(r, Err(ModeError::Module(FAILED)));
            });
        }

        fn ccm_paths(ccm: &CcmKey) {
            let nonce = [0x1cu8; 13];
            let mut ct = [0u8; 37];
            let mut tag = [0u8; 16];
            path("CCM encrypt", CCM_SEAL, || {
                let r = ccm_encrypt(ccm, &nonce, b"aad", &PT, &mut ct, &mut tag);
                assert_eq!(r, Ok(()));
            });
            path("CCM decrypt", CCM_OPEN, || {
                let mut back = [0u8; 37];
                let r = ccm_decrypt(ccm, &nonce, b"aad", &ct, &tag, &mut back);
                assert_eq!((r, back), (Ok(()), PT));
            });
            path("CCM decrypt, tag mismatch", CCM_OPEN, || {
                let mut bad = tag;
                bad[0] ^= 1;
                let mut back = [0u8; 37];
                let r = ccm_decrypt(ccm, &nonce, b"aad", &ct, &bad, &mut back);
                assert_eq!(r, Err(ModeError::TagMismatch));
            });
            // Calls 1 and 2 MAC B0 and the associated data, call 3 is the
            // first keystream block and call 4 MACs the first payload
            // block.
            path("CCM decrypt, cipher error mid-CBC-MAC", CCM_OPEN, || {
                let cipher = FailAt::new(4);
                let mut back = [SENTINEL; 37];
                let r = ccm_decrypt_core(&cipher, &nonce, b"aad", &ct, &tag, &mut back);
                assert_eq!(r, Err(ModeError::Module(FAILED)));
                assert_eq!(cipher.calls.get(), 4);
                assert_eq!(back, [SENTINEL; 37]);
            });
        }

        fn ctr_paths(key: &CtrKey) {
            let counter = [0xf0u8; 16];
            path("CTR", CTR, || {
                let mut ct = [0u8; 37];
                assert_eq!(ctr(key, &counter, &PT, &mut ct), Ok(()));
            });
            path("CTR, cipher error mid-stream", CTR, || {
                let cipher = FailAt::new(2);
                let mut ct = [0u8; 37];
                let r = ctr_core(&cipher, &counter, &PT, &mut ct);
                assert_eq!(r, Err(ModeError::Module(FAILED)));
            });
        }

        fn ecb_cbc_paths(ecb: &EcbKey, cbc: &CbcKey) {
            let pt = [0x3eu8; 48];
            let iv = [0x0fu8; 16];
            let mut ct = [0u8; 48];
            path("ECB encrypt", ECB, || {
                assert_eq!(ecb_encrypt(ecb, &pt, &mut ct), Ok(()));
            });
            path("ECB decrypt", ECB, || {
                let mut back = [0u8; 48];
                assert_eq!((ecb_decrypt(ecb, &ct, &mut back), back), (Ok(()), pt));
            });
            path("ECB decrypt, cipher error mid-stream", ECB, || {
                let cipher = FailAt::new(2);
                let mut back = [SENTINEL; 48];
                let r = ecb_decrypt_core(&cipher, &ct, &mut back);
                assert_eq!(r, Err(ModeError::Module(FAILED)));
            });
            path("CBC encrypt", CBC, || {
                assert_eq!(cbc_encrypt(cbc, &iv, &pt, &mut ct), Ok(()));
            });
            path("CBC decrypt", CBC, || {
                let mut back = [0u8; 48];
                let r = cbc_decrypt(cbc, &iv, &ct, &mut back);
                assert_eq!((r, back), (Ok(()), pt));
            });
        }

        fn kw_paths(kw: &KwKey) {
            let wraps: [(&str, Wrap, Wrap, usize); 6] = [
                (
                    "KW",
                    |k, p, c| kw_wrap(k, p, c).map(|()| p.len() + 8),
                    |k, c, p| kw_unwrap(k, c, p).map(|()| p.len()),
                    24,
                ),
                (
                    "KW inverse",
                    |k, p, c| kw_wrap_inverse(k, p, c).map(|()| p.len() + 8),
                    |k, c, p| kw_unwrap_inverse(k, c, p).map(|()| p.len()),
                    24,
                ),
                ("KWP", kwp_wrap, kwp_unwrap, 24),
                ("KWP inverse", kwp_wrap_inverse, kwp_unwrap_inverse, 24),
                ("KWP one block", kwp_wrap, kwp_unwrap, 5),
                (
                    "KWP inverse one block",
                    kwp_wrap_inverse,
                    kwp_unwrap_inverse,
                    5,
                ),
            ];
            for (name, wrap, unwrap, len) in wraps {
                let key_data = [0xc3u8; 24];
                let mut wrapped = [0u8; 32];
                let mut n = 0;
                path(&format!("{name} wrap"), WRAP, || {
                    n = wrap(kw, &key_data[..len], &mut wrapped).unwrap();
                });
                let wrapped = &mut wrapped[..n];
                path(&format!("{name} unwrap"), UNWRAP, || {
                    let mut out = [0u8; 24];
                    let got = unwrap(kw, wrapped, &mut out[..n - 8]).unwrap();
                    assert_eq!(&out[..got], &key_data[..len], "{name}");
                });
                wrapped[0] ^= 1;
                path(
                    &format!("{name} unwrap, ICV failure"),
                    UNWRAP_REFUSED,
                    || {
                        let mut out = [0u8; 24];
                        let r = unwrap(kw, wrapped, &mut out[..n - 8]);
                        assert_eq!(r, Err(ModeError::TagMismatch), "{name}");
                    },
                );
            }

            let cores: [(&str, CoreWrap); 4] = [
                ("KW", kw_wrap_core::<FailAt>),
                ("KW inverse", kw_wrap_inverse_core::<FailAt>),
                ("KWP", kwp_wrap_core::<FailAt>),
                ("KWP inverse", kwp_wrap_inverse_core::<FailAt>),
            ];
            for (name, wrap) in cores {
                path(
                    &format!("{name} wrap, cipher error mid-W"),
                    WRAP_REFUSED,
                    || {
                        let cipher = FailAt::new(2);
                        let mut wrapped = [SENTINEL; 32];
                        let r = wrap(&cipher, &[0xc3u8; 24], &mut wrapped);
                        assert_eq!(r, Err(ModeError::Module(FAILED)), "{name}");
                    },
                );
            }

            // A 24-byte plaintext wraps to 32 bytes; a 31-byte output is
            // the wrong size for KW and too short for KWP.
            let refusals: [(&str, Wrap); 4] = [
                ("KW", |k, p, c| kw_wrap(k, p, c).map(|()| 0)),
                ("KW inverse", |k, p, c| kw_wrap_inverse(k, p, c).map(|()| 0)),
                ("KWP", kwp_wrap),
                ("KWP inverse", kwp_wrap_inverse),
            ];
            for (name, wrap) in refusals {
                path(
                    &format!("{name} wrap, output length refused"),
                    WRAP_LENGTH_REFUSED,
                    || {
                        let mut wrapped = [SENTINEL; 31];
                        let r = wrap(kw, &[0xc3u8; 24], &mut wrapped);
                        assert_eq!(r, Err(ModeError::LengthMismatch), "{name}");
                        assert_eq!(wrapped, [SENTINEL; 31], "{name}");
                    },
                );
            }
        }

        /// The secret intermediates of the ECB, CBC, CTR, GCM, CCM, KW and
        /// KWP paths are wiped through the seam (SP 800-38A §6.1, §6.2 and
        /// §6.5, SP 800-38D §5.3, SP 800-38C §6, SP 800-38F §6). The exits
        /// driven are: success of every operation; a GCM and a CCM tag
        /// mismatch; a KW and KWP ICV failure in each direction; a cipher
        /// error mid-stream in ECB decryption and CTR, mid-GCTR in GCM
        /// encryption, mid-CBC-MAC in CCM decryption and mid-W in each KW
        /// and KWP wrap; a KW and KWP wrap length refusal in each
        /// direction, which wipes nothing; the drop of a key, which wipes
        /// its round-key schedule once; and a module error after the GCM
        /// IV draw. Not driven: the other parameter and length refusals,
        /// which return before any guard is built; cipher errors in ECB
        /// encryption, CBC, GCM decryption, CCM encryption, the CCM
        /// verification pass, the GCM tag mask and KW and KWP unwrap. Each
        /// path is checked against the counters read just before it, for an
        /// exact count where the path's guards are known and at least one
        /// where the count depends on the work done. The paths run in
        /// sequence in one process of their own, the module error last
        /// because the error state is terminal. The run then fails naming
        /// any listed identity that no path wiped.
        #[test]
        fn intermediates_zeroized_on_all_paths() {
            crate::test_support::isolated(
                "modes::tests::intermediates::intermediates_zeroized_on_all_paths",
                &["all paths"],
                |_| {
                    crate::test_support::start_module();
                    let mut keys = None;
                    path("key expansion", &[(KeyExpansionWord, AtLeastOnce)], || {
                        keys = Some((
                            GcmKey::new(&KEY).unwrap(),
                            CcmKey::new(&KEY, 16).unwrap(),
                            KwKey::new(&KEY).unwrap(),
                            CtrKey::new(&KEY).unwrap(),
                        ));
                    });
                    let (gcm, ccm, kw, ctr_key) = keys.unwrap();
                    path("key drop", &[(RoundKeys, Exactly(1))], || {
                        let key = EcbKey::new(&KEY).unwrap();
                        drop(key);
                    });
                    gcm_paths(&gcm);
                    ccm_paths(&ccm);
                    ctr_paths(&ctr_key);
                    ecb_cbc_paths(&EcbKey::new(&KEY).unwrap(), &CbcKey::new(&KEY).unwrap());
                    kw_paths(&kw);
                    path(
                        "GCM encrypt, module error after the IV draw",
                        GCM_MODULE_ERROR,
                        || {
                            let mut ct = [SENTINEL; 37];
                            let r = gcm_encrypt(&gcm, &mut ErrorAfterDraw, b"aad", &PT, &mut ct);
                            assert_eq!(r.map(|_| ()), Err(ModeError::Module(FAILED)));
                            assert_eq!(ct, [SENTINEL; 37]);
                        },
                    );

                    let unwiped: Vec<WipedBuffer> =
                        design().into_iter().filter(|b| wipes(*b) == 0).collect();
                    assert!(unwiped.is_empty(), "never wiped: {unwiped:?}");
                },
            );
        }
    }
}

#[cfg(all(test, feature = "accel-aes"))]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod ghash_accel_oracle {
    use super::{gf_mul, gf_mul_portable};

    /// Tiny self-contained xorshift128+ PRNG — deterministic, no extra
    /// dependency, reproducible from a fixed seed. Good enough to spray
    /// the GF(2^128) input space for the oracle.
    struct XorShift128p {
        s0: u64,
        s1: u64,
    }

    impl XorShift128p {
        fn new(seed: u64) -> Self {
            // SplitMix64-style seeding so a single u64 seed yields a
            // well-mixed 128-bit state (avoids the all-zero fixed point).
            let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut next = || {
                z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut x = z;
                x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                x ^ (x >> 31)
            };
            Self {
                s0: next(),
                s1: next(),
            }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.s0;
            let y = self.s1;
            self.s0 = y;
            x ^= x << 23;
            self.s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
            self.s1.wrapping_add(y)
        }

        fn fill_block(&mut self) -> [u8; 16] {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&self.next_u64().to_le_bytes());
            b[8..].copy_from_slice(&self.next_u64().to_le_bytes());
            b
        }
    }

    const CASES: usize = 50_000;

    #[test]
    fn accel_ghash_matches_portable_byte_exact() {
        if !oxicrypt_aes_accel::ghash_available() {
            return;
        }

        let mut rng = XorShift128p::new(0x0C1C_8A54_6A45_5701);

        // A handful of structured edge cases up front, then the random
        // spray. Edge cases stress the reduction's lane-crossing and
        // high-bit handling.
        let edge: &[([u8; 16], [u8; 16])] = &[
            ([0u8; 16], [0u8; 16]),
            ([0xFFu8; 16], [0xFFu8; 16]),
            (
                [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
            (
                [0xFFu8; 16],
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
        ];
        for (x, y) in edge {
            let (mut want, mut got) = (*x, *x);
            gf_mul_portable(&mut want, y);
            gf_mul(&mut got, y);
            assert_eq!(
                got, want,
                "GHASH accel != portable on edge case x={x:02x?} y={y:02x?}"
            );
        }

        for i in 0..CASES {
            let x = rng.fill_block();
            let y = rng.fill_block();
            let (mut want, mut got) = (x, x);
            gf_mul_portable(&mut want, &y);
            gf_mul(&mut got, &y);
            assert_eq!(
                got, want,
                "GHASH accel != portable at random case {i}: x={x:02x?} y={y:02x?}"
            );
        }
    }
}
