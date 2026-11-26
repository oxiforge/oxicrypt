//! AES Key Wrap (KW) and Key Wrap with Padding (KWP) per
//! NIST SP 800-38F / RFC 3394 / RFC 5649.
//!
//! # Scope
//!
//! Implements the two wrapping modes in SP 800-38F:
//!
//!   * **KW** (§6.2, Algorithms 3/4 "KW-AE" / "KW-AD", over the W and
//!     W^-1 functions of §6.1) — the original
//!     RFC 3394 key wrap, with the default integrity check value
//!     `A6A6A6A6A6A6A6A6`. Lengths are multiples of 8 bytes. Wrap
//!     accepts a plaintext of 16 bytes or more and fewer than 2^54
//!     semiblocks, and unwrap accepts a ciphertext of 24 bytes or more
//!     and at most 2^54 semiblocks (SP 800-38F §5.3.1 Table 1).
//!   * **KWP** (§6.3, Algorithms 5/6 "KWP-AE" / "KWP-AD") — the
//!     padded variant from RFC 5649. Accepts any plaintext of length
//!     1..=2^32 - 1 bytes, prefixes the alternative IV
//!     `A65959A6 || [mli]_32`, zero-pads to a multiple of 8 bytes,
//!     and either runs a single AES block encrypt (when the padded
//!     input fits in 16 bytes) or feeds the result into the standard
//!     KW wrapping function.
//!
//! Each mode is exposed in two cipher directions, both defined by
//! SP 800-38F §5.1 / §6.2:
//!
//!   * **Forward cipher** (the default, ACVP `kwCipher = "cipher"`):
//!     the W function uses the AES forward cipher (encrypt) for wrap
//!     and the AES inverse cipher (decrypt) for unwrap. Exposed as
//!     [`kw_wrap`] / [`kw_unwrap`] / [`kwp_wrap`] / [`kwp_unwrap`].
//!   * **Inverse cipher** (ACVP `kwCipher = "inverse"`): the W
//!     function uses the AES inverse cipher (decrypt) for wrap and
//!     the AES forward cipher (encrypt) for unwrap. Exposed as
//!     [`kw_wrap_inverse`] / [`kw_unwrap_inverse`] /
//!     [`kwp_wrap_inverse`] / [`kwp_unwrap_inverse`].
//!
//! Every function takes a [`KwKey`]. KW and KWP, in both directions, are
//! gated on the KW and KWP services respectively for the key's size.
//!
//! The two directions are distinct algorithms — a wrap produced in
//! one direction is rejected by the other's ICV check with
//! overwhelming probability.
//!
//! The unwrap directions verify the published ICV: KW compares all
//! eight bytes against `A6A6A6A6A6A6A6A6`, KWP compares the four
//! `A65959A6` prefix bytes, the range of the declared length and the
//! zero padding together. The wrap directions write the ICV. Any mismatch
//! returns [`ModeError::TagMismatch`]. Length mismatches and invalid
//! inputs return dedicated variants of [`ModeError`]. Every unwrap error
//! after the service gates zeroizes the caller's output buffer before
//! return, and every wrap error after them zeroizes what the wrap wrote
//! there.
//!
//! # Ciphertext length
//!
//! For both KW and KWP, the wrapped output length equals the input
//! plaintext length rounded up to the next multiple of 8 **plus** 8
//! bytes for the prepended integrity-check semiblock.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::trivially_copy_pass_by_ref
)]

use core::mem::MaybeUninit;

use oxicrypt_module::{
    Error, SelfTestStarted, require_allowed, require_operational, require_self_test_started,
    require_self_test_started_token,
};

use crate::block::{KW_SERVICES, KWP_SERVICES, KeySchedule};
use crate::modes::{BlockCipher, ModeError};
use crate::wipe::{WipedBlock, WipedBuffer, WipedSemiblock, wipe};

/// Semiblock size in bytes. AES has a 128-bit block, so each
/// semiblock is 8 bytes (SP 800-38F §5.1).
const SEMI: usize = 8;

/// Default KW integrity check value (RFC 3394 §2.2.3.1,
/// SP 800-38F §6.2). Eight copies of the byte `0xA6`.
pub const KW_DEFAULT_IV: [u8; SEMI] = [0xA6; SEMI];

/// KWP alternative initial value prefix (RFC 5649 §3,
/// SP 800-38F §6.3). Four bytes; the remaining 4 bytes carry the
/// big-endian plaintext byte length (`mli`).
pub const KWP_IV_PREFIX: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// An AES key bound to key wrapping (SP 800-38F): KW and KWP, in the
/// forward- and inverse-cipher directions.
///
/// ```compile_fail,E0599
/// let k = oxicrypt_aes::KwKey::new(&[0u8; 16]).unwrap();
/// let k2 = k.clone();
/// ```
pub struct KwKey {
    pub(crate) schedule: KeySchedule,
}

impl KwKey {
    /// Builds a key-wrapping key from 16, 24 or 32 bytes of key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless the module is
    /// `Operational`, [`Error::InvalidInput`] unless `key` is 16, 24 or 32
    /// bytes, and [`Error::AlgorithmRestricted`] when the active profile
    /// does not permit AES-KW at that key size.
    ///
    /// The key is returned by value; a copy of the schedule that the move
    /// leaves behind is not zeroized.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let mut k = Self {
            schedule: KeySchedule::admit(key.len(), KW_SERVICES)?,
        };
        k.schedule.expand(key);
        Ok(k)
    }

    /// Builds the key as [`KwKey::new`] does, in `slot`, and returns a
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
    /// The errors of [`KwKey::new`].
    #[doc(hidden)]
    pub fn new_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
    ) -> Result<&'a mut Self, Error> {
        let k = slot.write(Self {
            schedule: KeySchedule::admit(key.len(), KW_SERVICES)?,
        });
        k.schedule.expand(key);
        Ok(k)
    }
}

/// The ciphertext length of a KWP wrap of `plaintext_len` bytes: the
/// plaintext padded to a multiple of 8, plus the 8-byte ICV semiblock.
/// `None` for an empty plaintext, one longer than `2^32 - 1` bytes, or one
/// whose wrapped length does not fit in a `usize`.
fn kwp_wrapped_len(plaintext_len: usize) -> Option<usize> {
    if plaintext_len == 0 || plaintext_len > u32::MAX as usize {
        return None;
    }
    plaintext_len
        .div_ceil(SEMI)
        .checked_mul(SEMI)?
        .checked_add(SEMI)
}

/// The largest KW-AE plaintext, in semiblocks: fewer than 2^54
/// (SP 800-38F §5.3.1 Table 1).
const KW_MAX_PLAINTEXT_SEMIBLOCKS: u64 = (1 << 54) - 1;

/// The largest KW-AD ciphertext, in semiblocks: at most 2^54, one more
/// than the largest plaintext for the ICV semiblock (SP 800-38F §5.3.1
/// Table 1).
const KW_MAX_CIPHERTEXT_SEMIBLOCKS: u64 = KW_MAX_PLAINTEXT_SEMIBLOCKS + 1;

/// The number of semiblocks in `len` bytes. [`ModeError::LengthMismatch`]
/// unless `len` is a multiple of 8.
fn semiblocks(len: usize) -> Result<u64, ModeError> {
    if len % SEMI != 0 {
        return Err(ModeError::LengthMismatch);
    }
    u64::try_from(len / SEMI).map_err(|_| ModeError::InvalidPayloadLength)
}

/// The KW-AE plaintext length check, on a length in semiblocks:
/// [`ModeError::LengthMismatch`] below 2 semiblocks and
/// [`ModeError::InvalidPayloadLength`] at 2^54 or more.
fn kw_wrap_semiblock_bound(plaintext_semiblocks: u64) -> Result<(), ModeError> {
    if plaintext_semiblocks < 2 {
        Err(ModeError::LengthMismatch)
    } else if plaintext_semiblocks > KW_MAX_PLAINTEXT_SEMIBLOCKS {
        Err(ModeError::InvalidPayloadLength)
    } else {
        Ok(())
    }
}

/// The KW-AD ciphertext length check, on a length in semiblocks:
/// [`ModeError::LengthMismatch`] below 3 semiblocks and
/// [`ModeError::InvalidPayloadLength`] above 2^54.
fn kw_unwrap_semiblock_bound(ciphertext_semiblocks: u64) -> Result<(), ModeError> {
    if ciphertext_semiblocks < 3 {
        Err(ModeError::LengthMismatch)
    } else if ciphertext_semiblocks > KW_MAX_CIPHERTEXT_SEMIBLOCKS {
        Err(ModeError::InvalidPayloadLength)
    } else {
        Ok(())
    }
}

/// Wipes `out`, recording it under `buffer`, when `result` is an error,
/// so a refused unwrap leaves no unverified plaintext and a failed wrap
/// no part of the key being wrapped.
fn wipe_on_error<T>(
    result: Result<T, ModeError>,
    buffer: WipedBuffer,
    out: &mut [u8],
) -> Result<T, ModeError> {
    if result.is_err() {
        wipe(buffer, out);
    }
    result
}

type WFunction<B> = fn(&B, &SelfTestStarted, &mut [u8; SEMI], &mut [u8]) -> Result<(), Error>;

type BlockFn<B> = fn(&B, &SelfTestStarted, &mut [u8; 16]) -> Result<(), Error>;

type WrapCore<B> = fn(&B, &[u8], &mut [u8]) -> Result<(), ModeError>;

/// `0xFF` when `a < b`, else `0`, taken from the borrow rather than a
/// comparison. Both operands are below 2^63, so the top bit of the
/// wrapping difference is the borrow.
fn mask_if_lt(a: u64, b: u64) -> u8 {
    ((a.wrapping_sub(b) >> 63) as u8).wrapping_neg()
}

/// The KWP-AD integrity check (SP 800-38F §6.3 Algorithm 6 steps 4, 7 and 8)
/// over the decrypted initial value `aiv` and padded plaintext `padded`.
///
/// Returns the length indicator `mli` and a fault mask that is zero only
/// when the ICV prefix matches, `8(n - 1) < mli <= 8n` for `padded` of
/// `n` semiblocks, and every padding octet is zero. Only the last seven
/// octets can be padding, so only they are scanned, each masked by its
/// position against `mli`; no index is derived from the indicator. That
/// the compiled code has no branch on the indicator is unproven.
fn kwp_icv_fault(aiv: &[u8; SEMI], padded: &[u8]) -> (u8, usize) {
    let mut fault: u8 = 0;
    for k in 0..KWP_IV_PREFIX.len() {
        fault |= aiv[k] ^ KWP_IV_PREFIX[k];
    }
    let mli = u64::from(u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]));
    let len = padded.len() as u64;
    fault |= mask_if_lt(len, mli) | mask_if_lt(mli + (SEMI as u64 - 1), len) | mask_if_lt(mli, 1);
    let start = padded.len().saturating_sub(SEMI - 1);
    for (position, octet) in padded.iter().enumerate().skip(start) {
        fault |= octet & !mask_if_lt(position as u64, mli);
    }
    (fault, mli as usize)
}

/// Core "W" wrapping function (SP 800-38F §6.1, Algorithm 1).
///
/// Takes an initial value `a` (8 bytes) and an `n`-semiblock input
/// `r` (n ≥ 2) stored as `n * 8` contiguous bytes in `r_out`, and
/// updates `r_out` in place so that the first 8 bytes become the
/// final A value and the remaining `n * 8` bytes become the wrapped
/// registers `R[1..n]`.
///
/// Laid out in this shape so both KW wrapping and the n ≥ 3 case of
/// KWP wrapping share the same core loop.
fn w_core<B: BlockCipher>(
    cipher: &B,
    started: &SelfTestStarted,
    a: &mut [u8; SEMI],
    r_out: &mut [u8],
) -> Result<(), Error> {
    let n = r_out.len() / SEMI;
    let mut blk = WipedBlock::new(WipedBuffer::KwWrapBlock);
    for j in 0..6u64 {
        for i in 1..=n {
            // B_in = A || R[i]
            blk.bytes[..SEMI].copy_from_slice(a);
            blk.bytes[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.encrypt_block_with(started, &mut blk.bytes)?;
            // A = MSB_64(B_out) XOR t, where t = n*j + i.
            a.copy_from_slice(&blk.bytes[..SEMI]);
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            for k in 0..SEMI {
                a[k] ^= tb[k];
            }
            // R[i] = LSB_64(B_out).
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk.bytes[SEMI..]);
        }
    }
    Ok(())
}

/// Core "W^-1" unwrapping function (SP 800-38F §6.1, Algorithm 2).
fn w_core_inv<B: BlockCipher>(
    cipher: &B,
    started: &SelfTestStarted,
    a: &mut [u8; SEMI],
    r_out: &mut [u8],
) -> Result<(), Error> {
    let n = r_out.len() / SEMI;
    let mut blk = WipedBlock::new(WipedBuffer::KwBlock);
    for j in (0..6u64).rev() {
        for i in (1..=n).rev() {
            // B_in = (A XOR t) || R[i]
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            for k in 0..SEMI {
                blk.bytes[k] = a[k] ^ tb[k];
            }
            blk.bytes[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.decrypt_block_with(started, &mut blk.bytes)?;
            a.copy_from_slice(&blk.bytes[..SEMI]);
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk.bytes[SEMI..]);
        }
    }
    Ok(())
}

/// Equality on 8 bytes, accumulated over every byte with no early exit.
fn ct_eq8(a: &[u8; SEMI], b: &[u8; SEMI]) -> bool {
    let mut diff: u8 = 0;
    for k in 0..SEMI {
        diff |= a[k] ^ b[k];
    }
    diff == 0
}

/// AES-KW wrap (SP 800-38F §6.2, Algorithm 3 "KW-AE").
///
/// `plaintext` length must be a multiple of 8, at least 16 bytes and
/// fewer than 2^54 semiblocks (SP 800-38F §5.3.1 Table 1).
/// `ciphertext_out` must be exactly `plaintext.len() + 8` bytes.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KW at the key's size.
/// Returns [`ModeError::InvalidPayloadLength`] when `plaintext` is 2^54
/// semiblocks or longer, and [`ModeError::LengthMismatch`] when it is
/// shorter than 16 bytes or not a multiple of 8, or `ciphertext_out` is
/// not `plaintext.len() + 8` bytes; a length refusal writes nothing to
/// `ciphertext_out`. A module that enters its error state while the wrap
/// runs stops it with [`ModeError::Module`]. On every error after the
/// service gates, every byte of `ciphertext_out` the wrap wrote is
/// zeroized before return, so no part of the key being wrapped is left in
/// it.
pub fn kw_wrap(key: &KwKey, plaintext: &[u8], ciphertext_out: &mut [u8]) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KW_SERVICES))?;
    kw_wrap_core(&key.schedule, plaintext, ciphertext_out)
}

/// [`kw_wrap`] without the service gates, for the power-up self-tests.
pub(crate) fn kw_wrap_core<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    kw_wrap_lengths(plaintext.len(), ciphertext_out.len())?;
    let result = kw_wrap_into(cipher, plaintext, ciphertext_out, w_core::<B>);
    wipe_on_error(result, WipedBuffer::KwWrapOutput, ciphertext_out)
}

/// The KW-AE length checks: the plaintext bound of SP 800-38F §5.3.1
/// Table 1 and an output of exactly `plaintext_len + 8` bytes. They run
/// before the wrap writes anything, so a length refusal leaves the output
/// as the caller passed it.
fn kw_wrap_lengths(plaintext_len: usize, out_len: usize) -> Result<(), ModeError> {
    kw_wrap_semiblock_bound(semiblocks(plaintext_len)?)?;
    if plaintext_len.checked_add(SEMI) != Some(out_len) {
        return Err(ModeError::LengthMismatch);
    }
    Ok(())
}

/// KW-AE (SP 800-38F §6.2 Algorithm 3) over the W function `w`, leaving
/// the output for the caller to wipe on an error. The lengths have passed
/// [`kw_wrap_lengths`].
fn kw_wrap_into<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    w: WFunction<B>,
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    let mut a = WipedSemiblock::new(WipedBuffer::KwRegister);
    a.bytes = KW_DEFAULT_IV;
    ciphertext_out[SEMI..].copy_from_slice(plaintext);
    w(cipher, started, &mut a.bytes, &mut ciphertext_out[SEMI..])?;
    ciphertext_out[..SEMI].copy_from_slice(&a.bytes);
    Ok(())
}

/// AES-KW unwrap (SP 800-38F §6.2, Algorithm 4 "KW-AD").
///
/// `ciphertext` length must be a multiple of 8, at least 24 bytes and
/// at most 2^54 semiblocks (SP 800-38F §5.3.1 Table 1). `plaintext_out`
/// must be exactly `ciphertext.len() - 8` bytes. On every error after
/// the service gates `plaintext_out` is zeroized before return, so no
/// unverified plaintext is left in it.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KW at the key's size.
/// Returns [`ModeError::TagMismatch`] if the ICV did not verify,
/// [`ModeError::InvalidPayloadLength`] when `ciphertext` is longer than
/// 2^54 semiblocks, and [`ModeError::LengthMismatch`] when it is shorter
/// than 24 bytes or not a multiple of 8, or `plaintext_out` is not
/// `ciphertext.len() - 8` bytes.
pub fn kw_unwrap(
    key: &KwKey,
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KW_SERVICES))?;
    kw_unwrap_core(&key.schedule, ciphertext, plaintext_out)
}

/// [`kw_unwrap`] without the service gates, for the power-up self-tests.
pub(crate) fn kw_unwrap_core<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    let result = kw_unwrap_into(cipher, ciphertext, plaintext_out, w_core_inv::<B>);
    wipe_on_error(result, WipedBuffer::KwUnwrapOutput, plaintext_out)
}

/// KW-AD (SP 800-38F §6.2 Algorithm 4) over the W⁻¹ function `w_inv`,
/// leaving the output for the caller to wipe on an error.
fn kw_unwrap_into<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
    w_inv: WFunction<B>,
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    kw_unwrap_semiblock_bound(semiblocks(ciphertext.len())?)?;
    if ciphertext.len().checked_sub(SEMI) != Some(plaintext_out.len()) {
        return Err(ModeError::LengthMismatch);
    }
    let mut a = WipedSemiblock::new(WipedBuffer::KwRegister);
    a.bytes.copy_from_slice(&ciphertext[..SEMI]);
    plaintext_out.copy_from_slice(&ciphertext[SEMI..]);
    w_inv(cipher, started, &mut a.bytes, plaintext_out)?;
    if ct_eq8(&a.bytes, &KW_DEFAULT_IV) {
        Ok(())
    } else {
        Err(ModeError::TagMismatch)
    }
}

/// AES-KWP wrap (SP 800-38F §6.3, Algorithm 5 "KWP-AE").
///
/// `plaintext` may be any length from 1 to 2^32 − 1 bytes.
///
/// Writes the wrapped key, `((plaintext.len() + 7) / 8) * 8 + 8` bytes,
/// to the front of `ciphertext_out`, which may be longer, and returns
/// that length.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KWP at the key's size.
/// Returns [`ModeError::LengthMismatch`] when `plaintext` is empty or
/// longer than `2^32 - 1` bytes, when its padded length plus 8 does not
/// fit in a `usize` (on 32-bit targets, the fifteen largest lengths), or
/// when `ciphertext_out` is shorter than the wrapped length. A module
/// that enters its error state while the wrap runs stops it with
/// [`ModeError::Module`]. On every error after the service gates, every
/// byte of `ciphertext_out` the wrap wrote is zeroized before return, so
/// no part of the key being wrapped is left in it.
pub fn kwp_wrap(
    key: &KwKey,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<usize, ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KWP_SERVICES))?;
    kwp_wrap_prefix(
        &key.schedule,
        plaintext,
        ciphertext_out,
        kwp_wrap_core::<KeySchedule>,
    )
}

/// Runs the KWP wrap `core` into the wrapped-length prefix of
/// `ciphertext_out` and returns that length. A plaintext length or an
/// output length it refuses is refused before anything is written.
fn kwp_wrap_prefix<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    core: WrapCore<B>,
) -> Result<usize, ModeError> {
    let total = kwp_wrapped_len(plaintext.len()).ok_or(ModeError::LengthMismatch)?;
    let out = ciphertext_out
        .get_mut(..total)
        .ok_or(ModeError::LengthMismatch)?;
    core(cipher, plaintext, out)?;
    Ok(total)
}

/// [`kwp_wrap`] without the service gates, for the power-up self-tests.
/// `ciphertext_out` is exactly the wrapped length.
pub(crate) fn kwp_wrap_core<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    let result = kwp_wrap_into(
        cipher,
        plaintext,
        ciphertext_out,
        B::encrypt_block_with,
        w_core::<B>,
    );
    wipe_on_error(result, WipedBuffer::KwWrapOutput, ciphertext_out)
}

/// KWP-AE (SP 800-38F §6.3 Algorithm 5), encrypting a one-semiblock
/// padded plaintext with `block` and a longer one with the W function
/// `w`, leaving the output for the caller to wipe on an error.
fn kwp_wrap_into<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    block: BlockFn<B>,
    w: WFunction<B>,
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    let mli = plaintext.len();
    let total = kwp_wrapped_len(mli).ok_or(ModeError::LengthMismatch)?;
    if ciphertext_out.len() != total {
        return Err(ModeError::LengthMismatch);
    }
    let padded_pt_len = total - SEMI;

    let mut a = WipedSemiblock::new(WipedBuffer::KwRegister);
    a.bytes[..4].copy_from_slice(&KWP_IV_PREFIX);
    let mli_be = (mli as u32).to_be_bytes();
    a.bytes[4..].copy_from_slice(&mli_be);

    if padded_pt_len == SEMI {
        // SP 800-38F §6.3 Algorithm 5 step 5: if len(P) <= 64, then
        // C = CIPH_K(S), S = AIV || padded_PT (RFC 5649 §4.1).
        let mut blk = WipedBlock::new(WipedBuffer::KwWrapBlock);
        blk.bytes[..SEMI].copy_from_slice(&a.bytes);
        blk.bytes[SEMI..SEMI + mli].copy_from_slice(plaintext);
        block(cipher, started, &mut blk.bytes)?;
        ciphertext_out.copy_from_slice(&blk.bytes);
    } else {
        // SP 800-38F §6.3 Algorithm 5 step 6: C = W(S), S = AIV || padded_PT.
        ciphertext_out[SEMI..SEMI + mli].copy_from_slice(plaintext);
        for b in &mut ciphertext_out[SEMI + mli..] {
            *b = 0;
        }
        w(cipher, started, &mut a.bytes, &mut ciphertext_out[SEMI..])?;
        ciphertext_out[..SEMI].copy_from_slice(&a.bytes);
    }
    Ok(())
}

/// AES-KWP unwrap (SP 800-38F §6.3, Algorithm 6 "KWP-AD").
///
/// Returns the unwrapped plaintext byte length `mli`.
/// `plaintext_out_scratch` must be exactly `ciphertext.len() - 8` bytes;
/// it receives the padded plaintext, of which the caller takes the first
/// `mli` bytes. On every error after the service gates it is zeroized
/// before return, so no unverified plaintext is left in it.
///
/// The ICV prefix, the range of the declared length and the zero padding
/// are checked together and refused with the one error
/// [`ModeError::TagMismatch`]; the padding check reads only the last
/// seven octets, whatever the declared length.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KWP at the key's size.
/// Returns [`ModeError::TagMismatch`] if the ICV prefix did not match,
/// the declared `mli` is outside `8(n - 1) < mli <= 8n` for a padded
/// plaintext of `n` semiblocks, or any padding octet is non-zero, and
/// [`ModeError::LengthMismatch`] when `ciphertext` is shorter than 16
/// bytes or not a multiple of 8, or `plaintext_out_scratch` is not
/// `ciphertext.len() - 8` bytes.
pub fn kwp_unwrap(
    key: &KwKey,
    ciphertext: &[u8],
    plaintext_out_scratch: &mut [u8],
) -> Result<usize, ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KWP_SERVICES))?;
    kwp_unwrap_core(&key.schedule, ciphertext, plaintext_out_scratch)
}

/// [`kwp_unwrap`] without the service gates, for the power-up self-tests.
pub(crate) fn kwp_unwrap_core<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out_scratch: &mut [u8],
) -> Result<usize, ModeError> {
    let result = kwp_unwrap_into(
        cipher,
        ciphertext,
        plaintext_out_scratch,
        B::decrypt_block_with,
        w_core_inv::<B>,
    );
    wipe_on_error(result, WipedBuffer::KwUnwrapOutput, plaintext_out_scratch)
}

/// KWP-AD (SP 800-38F §6.3 Algorithm 6), decrypting a two-semiblock
/// ciphertext with `block_inv` and a longer one with the W⁻¹ function
/// `w_inv`, leaving the output for the caller to wipe on an error. The
/// only exit after the inverse-cipher pass is the final expression.
fn kwp_unwrap_into<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out_scratch: &mut [u8],
    block_inv: BlockFn<B>,
    w_inv: WFunction<B>,
) -> Result<usize, ModeError> {
    let started = &require_self_test_started_token()?;
    if ciphertext.len() < 2 * SEMI
        || ciphertext.len() % SEMI != 0
        || ciphertext.len().checked_sub(SEMI) != Some(plaintext_out_scratch.len())
    {
        return Err(ModeError::LengthMismatch);
    }
    let mut aiv = WipedSemiblock::new(WipedBuffer::KwRegister);
    if ciphertext.len() == 2 * SEMI {
        let mut blk = WipedBlock::new(WipedBuffer::KwBlock);
        blk.bytes.copy_from_slice(ciphertext);
        block_inv(cipher, started, &mut blk.bytes)?;
        aiv.bytes.copy_from_slice(&blk.bytes[..SEMI]);
        plaintext_out_scratch.copy_from_slice(&blk.bytes[SEMI..]);
    } else {
        aiv.bytes.copy_from_slice(&ciphertext[..SEMI]);
        plaintext_out_scratch.copy_from_slice(&ciphertext[SEMI..]);
        w_inv(cipher, started, &mut aiv.bytes, plaintext_out_scratch)?;
    }
    kwp_check(&aiv.bytes, plaintext_out_scratch)
}

/// The result of KWP-AD (SP 800-38F §6.3 Algorithm 6 steps 4 to 9) for the
/// decrypted initial value `aiv` and padded plaintext `padded`: the
/// length indicator when [`kwp_icv_fault`] finds no fault, else
/// [`ModeError::TagMismatch`], from one exit whichever check failed.
fn kwp_check(aiv: &[u8; SEMI], padded: &[u8]) -> Result<usize, ModeError> {
    let (fault, mli) = kwp_icv_fault(aiv, padded);
    if fault == 0 {
        Ok(mli)
    } else {
        Err(ModeError::TagMismatch)
    }
}

/// The integrity check of a KWP unwrap after its inverse-cipher pass,
/// over a given decrypted initial value `aiv` and padded plaintext
/// `padded`, for the constant-time harness.
///
/// Not a service of the module: it takes the decrypted values directly,
/// so that the timing of the check can be measured without the AES
/// decryption, and it is hidden from the documented API.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// [`require_self_test_started`] admits the call: in `Operational`, or in
/// `SelfTest` on the thread running the power-up self-tests. Returns
/// [`ModeError::TagMismatch`] if the ICV prefix does not match, the
/// indicator is outside `8(n - 1) < mli <= 8n` for `padded` of `n`
/// semiblocks, or a padding octet is non-zero.
#[doc(hidden)]
pub fn kwp_check_internal(aiv: &[u8; SEMI], padded: &[u8]) -> Result<usize, ModeError> {
    require_self_test_started()?;
    kwp_check(aiv, padded)
}

// The inverse-cipher direction (SP 800-38F §6.2, ACVP kwCipher = "inverse")
// inverts only the AES block direction, so these copies of W and W^-1 differ
// from the forward ones in the block call alone.

/// [`w_core`] over the AES inverse cipher.
fn w_core_inverse_cipher<B: BlockCipher>(
    cipher: &B,
    started: &SelfTestStarted,
    a: &mut [u8; SEMI],
    r_out: &mut [u8],
) -> Result<(), Error> {
    let n = r_out.len() / SEMI;
    let mut blk = WipedBlock::new(WipedBuffer::KwWrapBlock);
    for j in 0..6u64 {
        for i in 1..=n {
            blk.bytes[..SEMI].copy_from_slice(a);
            blk.bytes[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.decrypt_block_with(started, &mut blk.bytes)?;
            a.copy_from_slice(&blk.bytes[..SEMI]);
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            for k in 0..SEMI {
                a[k] ^= tb[k];
            }
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk.bytes[SEMI..]);
        }
    }
    Ok(())
}

/// [`w_core_inv`] over the AES forward cipher.
fn w_core_inverse_cipher_inv<B: BlockCipher>(
    cipher: &B,
    started: &SelfTestStarted,
    a: &mut [u8; SEMI],
    r_out: &mut [u8],
) -> Result<(), Error> {
    let n = r_out.len() / SEMI;
    let mut blk = WipedBlock::new(WipedBuffer::KwBlock);
    for j in (0..6u64).rev() {
        for i in (1..=n).rev() {
            let t: u64 = (n as u64) * j + (i as u64);
            let tb = t.to_be_bytes();
            for k in 0..SEMI {
                blk.bytes[k] = a[k] ^ tb[k];
            }
            blk.bytes[SEMI..].copy_from_slice(&r_out[(i - 1) * SEMI..i * SEMI]);
            cipher.encrypt_block_with(started, &mut blk.bytes)?;
            a.copy_from_slice(&blk.bytes[..SEMI]);
            r_out[(i - 1) * SEMI..i * SEMI].copy_from_slice(&blk.bytes[SEMI..]);
        }
    }
    Ok(())
}

/// AES-KW wrap with the inverse cipher direction (SP 800-38F §6.2,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kw_wrap`], including its bound of
/// fewer than 2^54 plaintext semiblocks.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KW at the key's size.
/// Returns [`ModeError::InvalidPayloadLength`] and
/// [`ModeError::LengthMismatch`] as [`kw_wrap`] does, a length refusal
/// writing nothing to `ciphertext_out`. A module that enters its error
/// state while the wrap runs stops it with [`ModeError::Module`]. On every
/// error after the service gates, every byte of `ciphertext_out` the wrap
/// wrote is zeroized before return, so no part of the key being wrapped is
/// left in it.
pub fn kw_wrap_inverse(
    key: &KwKey,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KW_SERVICES))?;
    kw_wrap_inverse_core(&key.schedule, plaintext, ciphertext_out)
}

/// [`kw_wrap_inverse`] without the service gates, for the power-up self-tests.
pub(crate) fn kw_wrap_inverse_core<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    kw_wrap_lengths(plaintext.len(), ciphertext_out.len())?;
    let result = kw_wrap_into(
        cipher,
        plaintext,
        ciphertext_out,
        w_core_inverse_cipher::<B>,
    );
    wipe_on_error(result, WipedBuffer::KwWrapOutput, ciphertext_out)
}

/// AES-KW unwrap with the inverse cipher direction (SP 800-38F §6.2,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kw_unwrap`], including its bound of
/// at most 2^54 ciphertext semiblocks and the zeroized output on every
/// error after the service gates.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KW at the key's size.
/// Returns [`ModeError::TagMismatch`] on ICV mismatch, including the case
/// where the input was wrapped with the forward cipher direction, and
/// [`ModeError::InvalidPayloadLength`] and [`ModeError::LengthMismatch`]
/// as [`kw_unwrap`] does.
pub fn kw_unwrap_inverse(
    key: &KwKey,
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KW_SERVICES))?;
    kw_unwrap_inverse_core(&key.schedule, ciphertext, plaintext_out)
}

/// [`kw_unwrap_inverse`] without the service gates, for the power-up self-tests.
pub(crate) fn kw_unwrap_inverse_core<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    let result = kw_unwrap_into(
        cipher,
        ciphertext,
        plaintext_out,
        w_core_inverse_cipher_inv::<B>,
    );
    wipe_on_error(result, WipedBuffer::KwUnwrapOutput, plaintext_out)
}

/// AES-KWP wrap with the inverse cipher direction (SP 800-38F §6.3,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kwp_wrap`].
///
/// Writes the wrapped key, `((plaintext.len() + 7) / 8) * 8 + 8` bytes,
/// to the front of `ciphertext_out`, which may be longer, and returns
/// that length.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KWP at the key's size.
/// Returns [`ModeError::LengthMismatch`] when `plaintext` is empty or
/// longer than `2^32 - 1` bytes, when its padded length plus 8 does not
/// fit in a `usize` (on 32-bit targets, the fifteen largest lengths), or
/// when `ciphertext_out` is shorter than the wrapped length. A module
/// that enters its error state while the wrap runs stops it with
/// [`ModeError::Module`]. On every error after the service gates, every
/// byte of `ciphertext_out` the wrap wrote is zeroized before return, so
/// no part of the key being wrapped is left in it.
pub fn kwp_wrap_inverse(
    key: &KwKey,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<usize, ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KWP_SERVICES))?;
    kwp_wrap_prefix(
        &key.schedule,
        plaintext,
        ciphertext_out,
        kwp_wrap_inverse_core::<KeySchedule>,
    )
}

/// [`kwp_wrap_inverse`] without the service gates, for the power-up self-tests.
/// `ciphertext_out` is exactly the wrapped length.
pub(crate) fn kwp_wrap_inverse_core<B: BlockCipher>(
    cipher: &B,
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<(), ModeError> {
    let result = kwp_wrap_into(
        cipher,
        plaintext,
        ciphertext_out,
        B::decrypt_block_with,
        w_core_inverse_cipher::<B>,
    );
    wipe_on_error(result, WipedBuffer::KwWrapOutput, ciphertext_out)
}

/// AES-KWP unwrap with the inverse cipher direction (SP 800-38F §6.3,
/// ACVP `kwCipher = "inverse"`).
///
/// Same input/output contract as [`kwp_unwrap`], including the zeroized
/// output on every error after the service gates and the single
/// [`ModeError::TagMismatch`] for every integrity fault.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-KWP at the key's size.
/// Returns [`ModeError::TagMismatch`] on ICV-prefix mismatch, a declared
/// `mli` out of range, a non-zero padding octet, or input wrapped with the
/// forward cipher direction, and [`ModeError::LengthMismatch`] as
/// [`kwp_unwrap`] does.
pub fn kwp_unwrap_inverse(
    key: &KwKey,
    ciphertext: &[u8],
    plaintext_out_scratch: &mut [u8],
) -> Result<usize, ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(KWP_SERVICES))?;
    kwp_unwrap_inverse_core(&key.schedule, ciphertext, plaintext_out_scratch)
}

/// [`kwp_unwrap_inverse`] without the service gates, for the power-up self-tests.
pub(crate) fn kwp_unwrap_inverse_core<B: BlockCipher>(
    cipher: &B,
    ciphertext: &[u8],
    plaintext_out_scratch: &mut [u8],
) -> Result<usize, ModeError> {
    let result = kwp_unwrap_into(
        cipher,
        ciphertext,
        plaintext_out_scratch,
        B::encrypt_block_with,
        w_core_inverse_cipher_inv::<B>,
    );
    wipe_on_error(result, WipedBuffer::KwUnwrapOutput, plaintext_out_scratch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        KWP_IV_PREFIX, KwKey, kw_unwrap, kw_unwrap_inverse, kw_unwrap_semiblock_bound, kw_wrap,
        kw_wrap_inverse, kw_wrap_semiblock_bound, kwp_unwrap, kwp_unwrap_inverse, kwp_wrap,
        kwp_wrap_inverse, kwp_wrapped_len, semiblocks, w_core, w_core_inverse_cipher,
    };
    use crate::modes::ModeError;
    use oxicrypt_module::require_self_test_started_token;

    const SENTINEL: u8 = 0x5A;

    /// An unwrap under test, its result reduced to success or the error.
    type Unwrap = fn(&KwKey, &[u8], &mut [u8]) -> Result<(), ModeError>;

    /// After a refused unwrap the caller's buffer, pre-filled with a
    /// sentinel, is all zero, in all four unwraps and for each refusal: a
    /// failed ICV, an output of the wrong size, and a ciphertext below the
    /// minimum length. After a successful unwrap it holds the plaintext.
    /// Under `fault-injection` the seam records one wipe of the output on
    /// the refusal and none on the success. Each setting runs in a process
    /// of its own so that the counters count only its own unwraps.
    #[test]
    fn kw_unwrap_fail_leaves_buffer_wiped() {
        crate::test_support::isolated(
            "kw::tests::kw_unwrap_fail_leaves_buffer_wiped",
            &[
                "kw",
                "kw_inverse",
                "kwp",
                "kwp_inverse",
                "kw/wrong_size",
                "kw_inverse/wrong_size",
                "kwp/wrong_size",
                "kwp_inverse/wrong_size",
                "kw/short",
                "kw_inverse/short",
                "kwp/short",
                "kwp_inverse/short",
            ],
            |setting| {
                let (variant, case) = setting.split_once('/').unwrap_or((setting, "icv"));
                crate::test_support::start_module();
                let k = KwKey::new(&[0x42u8; 16]).unwrap();
                let pt = [0xC3u8; 24];
                let mut ct = [0u8; 32];
                let unwrap: Unwrap = match variant {
                    "kw" => {
                        kw_wrap(&k, &pt, &mut ct).unwrap();
                        kw_unwrap
                    }
                    "kw_inverse" => {
                        kw_wrap_inverse(&k, &pt, &mut ct).unwrap();
                        kw_unwrap_inverse
                    }
                    "kwp" => {
                        assert_eq!(kwp_wrap(&k, &pt, &mut ct), Ok(32));
                        |k, c, o| kwp_unwrap(k, c, o).map(|_| ())
                    }
                    _ => {
                        assert_eq!(kwp_wrap_inverse(&k, &pt, &mut ct), Ok(32));
                        |k, c, o| kwp_unwrap_inverse(k, c, o).map(|_| ())
                    }
                };

                let mut out = [SENTINEL; 24];
                assert_eq!(unwrap(&k, &ct, &mut out), Ok(()), "{variant}");
                assert_eq!(out, pt, "{variant}");
                #[cfg(feature = "fault-injection")]
                {
                    use crate::wipe::{WipedBuffer, seam::wipes};
                    assert_eq!(wipes(WipedBuffer::KwUnwrapOutput), 0, "{variant}");
                }

                // The 16-byte KW ciphertext and the 15-byte KWP ciphertext
                // each match their output length and fall short only of
                // the minimum (SP 800-38F §5.3.1 Table 1).
                let short = if variant.starts_with("kwp") { 15 } else { 16 };
                let (ciphertext, mut out, expected) = match case {
                    "wrong_size" => (&ct[..], std::vec![SENTINEL; 25], ModeError::LengthMismatch),
                    "short" => (
                        &ct[..short],
                        std::vec![SENTINEL; short - 8],
                        ModeError::LengthMismatch,
                    ),
                    _ => {
                        ct[0] ^= 1;
                        (&ct[..], std::vec![SENTINEL; 24], ModeError::TagMismatch)
                    }
                };
                assert!(!out.is_empty(), "{setting}");
                assert_eq!(unwrap(&k, ciphertext, &mut out), Err(expected), "{setting}");
                assert!(out.iter().all(|&b| b == 0), "{setting}");
                #[cfg(feature = "fault-injection")]
                {
                    use crate::wipe::{WipedBuffer, seam::wipes};
                    assert_eq!(wipes(WipedBuffer::KwUnwrapOutput), 1, "{setting}");
                    let blocks = if case == "icv" { 2 } else { 1 };
                    assert_eq!(wipes(WipedBuffer::KwBlock), blocks, "{setting}");
                }
            },
        );
    }

    /// A block failure in the middle of W leaves the caller's buffer of
    /// each of the four wraps, pre-filled with a sentinel, all zero, and
    /// the seam records exactly one wipe of it. The first block call
    /// succeeds and the second fails, so the buffer holds the key being
    /// wrapped and one transformed semiblock when the error is returned.
    /// A failure of the one block call of a KWP wrap of 8 bytes or fewer,
    /// in each cipher direction, leaves the buffer zero with one wipe
    /// recorded in the same way. Each wrap runs in a process of its own so
    /// that the counter counts only its own wipe.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn kw_wrap_fail_leaves_buffer_wiped() {
        use super::{kw_wrap_core, kw_wrap_inverse_core, kwp_wrap_core, kwp_wrap_inverse_core};
        use crate::test_support::{FAILED, FailAt};
        use crate::wipe::{WipedBuffer, seam::wipes};

        type Wrap = fn(&FailAt, &[u8], &mut [u8]) -> Result<(), ModeError>;

        crate::test_support::isolated(
            "kw::tests::kw_wrap_fail_leaves_buffer_wiped",
            &[
                "kw",
                "kw_inverse",
                "kwp",
                "kwp_inverse",
                "kwp_one_block",
                "kwp_inverse_one_block",
            ],
            |variant| {
                crate::test_support::start_module();
                let wrap: Wrap = match variant {
                    "kw" => kw_wrap_core::<FailAt>,
                    "kw_inverse" => kw_wrap_inverse_core::<FailAt>,
                    "kwp" | "kwp_one_block" => kwp_wrap_core::<FailAt>,
                    _ => kwp_wrap_inverse_core::<FailAt>,
                };
                // A plaintext of 8 bytes or fewer is wrapped by one block
                // call (SP 800-38F §6.3 Algorithm 5 step 5), which fails
                // before any byte of the output is written.
                let (pt_len, ct_len, fail_at) = if variant.ends_with("one_block") {
                    (5, 16, 1)
                } else {
                    (24, 32, 2)
                };
                let cipher = FailAt::new(fail_at);
                let pt = [0xC3u8; 24];
                let mut ct = [SENTINEL; 32];
                assert_eq!(
                    wrap(&cipher, &pt[..pt_len], &mut ct[..ct_len]),
                    Err(ModeError::Module(FAILED)),
                    "{variant}"
                );
                assert_eq!(cipher.calls.get(), fail_at, "{variant}");
                assert!(ct[..ct_len].iter().all(|&b| b == 0), "{variant}: {ct:02x?}");
                assert!(ct[ct_len..].iter().all(|&b| b == SENTINEL), "{variant}");
                assert_eq!(wipes(WipedBuffer::KwWrapOutput), 1, "{variant}");
            },
        );
    }

    /// The SP 800-38F §5.3.1 Table 1 bounds, checked on the semiblock
    /// counts the KW cores pass to `kw_wrap_semiblock_bound` and
    /// `kw_unwrap_semiblock_bound`: a buffer of 2^54 semiblocks (2^57
    /// bytes) cannot be allocated, so the public functions are driven only
    /// at the lower bound.
    #[test]
    fn kw_length_bounds() {
        let limit = 1u64 << 54;
        assert_eq!(kw_wrap_semiblock_bound(2), Ok(()));
        assert_eq!(kw_wrap_semiblock_bound(limit - 1), Ok(()));
        assert_eq!(
            kw_wrap_semiblock_bound(limit),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(kw_wrap_semiblock_bound(1), Err(ModeError::LengthMismatch));
        assert_eq!(kw_unwrap_semiblock_bound(3), Ok(()));
        assert_eq!(kw_unwrap_semiblock_bound(limit), Ok(()));
        assert_eq!(
            kw_unwrap_semiblock_bound(limit + 1),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(kw_unwrap_semiblock_bound(2), Err(ModeError::LengthMismatch));
        assert_eq!(semiblocks(24), Ok(3));
        assert_eq!(semiblocks(23), Err(ModeError::LengthMismatch));

        crate::test_support::start_module();
        let k = KwKey::new(&[0x42u8; 16]).unwrap();
        let mut ct = [0u8; 16];
        assert_eq!(
            kw_wrap(&k, &[0u8; 8], &mut ct),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(
            kw_wrap_inverse(&k, &[0u8; 8], &mut ct),
            Err(ModeError::LengthMismatch)
        );
        let mut pt = [0u8; 8];
        assert_eq!(
            kw_unwrap(&k, &[0u8; 16], &mut pt),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(
            kw_unwrap_inverse(&k, &[0u8; 16], &mut pt),
            Err(ModeError::LengthMismatch)
        );
    }

    /// `kwp_wrapped_len` agrees with checked `usize` arithmetic at the edge
    /// of `usize` on whatever target runs this test: for every length
    /// tried, both refuse or both give the same wrapped length. The
    /// reference applies the SP 800-38F §5.3.1 Table 1 range of 1 to
    /// 2^32 - 1 bytes and the §6.3 padded length, a multiple of 8, plus
    /// the 8-byte prefix.
    #[test]
    fn kwp_length_arithmetic_does_not_wrap() {
        fn checked(n: usize) -> Option<usize> {
            if n == 0 || u32::try_from(n).is_err() {
                return None;
            }
            let semiblocks = n.checked_add(7)? / 8;
            semiblocks.checked_mul(8)?.checked_add(8)
        }

        let largest = (u32::MAX as usize).min((usize::MAX - 8) / 8 * 8);
        assert!(kwp_wrapped_len(largest).is_some());
        assert_eq!(kwp_wrapped_len(largest + 1), None);

        let mut lengths = std::vec![0, 1, 7, 8, 9, largest, largest + 1];
        lengths.extend((0..=32).map(|k| usize::MAX - k));
        assert_eq!(lengths.len(), 40);
        for n in lengths {
            assert_eq!(kwp_wrapped_len(n), checked(n), "n={n}");
        }
    }

    /// Encrypts the chosen initial value `aiv` and padded plaintext into
    /// `ct` with the wrap primitive of one direction, so that the unwrap
    /// decrypts exactly that indicator and padding.
    fn seal(k: &KwKey, aiv: [u8; 8], padded: &[u8], inverse: bool, ct: &mut [u8]) {
        let started = require_self_test_started_token().unwrap();
        if padded.len() == 8 {
            let mut blk = [0u8; 16];
            blk[..8].copy_from_slice(&aiv);
            blk[8..].copy_from_slice(padded);
            if inverse {
                k.schedule.decrypt_block_with(&started, &mut blk).unwrap();
            } else {
                k.schedule.encrypt_block_with(&started, &mut blk).unwrap();
            }
            ct.copy_from_slice(&blk);
        } else {
            let mut a = aiv;
            ct[8..].copy_from_slice(padded);
            if inverse {
                w_core_inverse_cipher(&k.schedule, &started, &mut a, &mut ct[8..]).unwrap();
            } else {
                w_core(&k.schedule, &started, &mut a, &mut ct[8..]).unwrap();
            }
            ct[..8].copy_from_slice(&a);
        }
    }

    fn aiv(mli: u32) -> [u8; 8] {
        let mut aiv = [0u8; 8];
        aiv[..4].copy_from_slice(&KWP_IV_PREFIX);
        aiv[4..].copy_from_slice(&mli.to_be_bytes());
        aiv
    }

    /// Genuine ciphertexts whose decrypted length indicator is out of
    /// range (including `u32::MAX`, which would index far past the buffer)
    /// or whose padding is non-zero are refused with the same
    /// `TagMismatch` as an ICV failure, without a panic, in both
    /// directions on the multi-semiblock path, and the output is all zero
    /// after each refusal. A non-zero first octet of seven padding octets
    /// (length 17) is refused. Zero-padded plaintexts of 17, 20 and 24
    /// bytes are accepted.
    #[test]
    fn kwp_unwrap_single_exit_masked_padding() {
        crate::test_support::start_module();
        let k = KwKey::new(&[0x42u8; 24]).unwrap();
        for inverse in [false, true] {
            let unwrap = if inverse {
                kwp_unwrap_inverse
            } else {
                kwp_unwrap
            };

            let mut padded = [0xC3u8; 24];
            padded[20..].copy_from_slice(&[0; 4]);
            let mut ct = [0u8; 32];
            seal(&k, aiv(20), &padded, inverse, &mut ct);
            let mut reference = [0u8; 32];
            let wrap = if inverse { kwp_wrap_inverse } else { kwp_wrap };
            assert_eq!(wrap(&k, &padded[..20], &mut reference), Ok(32));
            assert_eq!(ct, reference, "inverse={inverse}");
            let mut out = [SENTINEL; 24];
            assert_eq!(unwrap(&k, &ct, &mut out), Ok(20), "inverse={inverse}");

            let mut refusals = std::vec::Vec::new();
            for mli in [0, 16, 25, 0x8000_0000, u32::MAX] {
                seal(&k, aiv(mli), &padded, inverse, &mut ct);
                let mut out = [SENTINEL; 24];
                refusals.push((mli, unwrap(&k, &ct, &mut out), out == [0u8; 24]));
            }
            for position in [20, 23] {
                let mut bad = padded;
                bad[position] = 1;
                seal(&k, aiv(20), &bad, inverse, &mut ct);
                let mut out = [SENTINEL; 24];
                refusals.push((20, unwrap(&k, &ct, &mut out), out == [0u8; 24]));
            }
            let mut wrong_prefix = aiv(20);
            wrong_prefix[0] ^= 1;
            seal(&k, wrong_prefix, &padded, inverse, &mut ct);
            let mut out = [SENTINEL; 24];
            refusals.push((20, unwrap(&k, &ct, &mut out), out == [0u8; 24]));
            seal(&k, aiv(20), &padded, inverse, &mut ct);
            ct[31] ^= 1;
            let mut out = [SENTINEL; 24];
            refusals.push((20, unwrap(&k, &ct, &mut out), out == [0u8; 24]));

            let mut seven = [0xC3u8; 24];
            seven[17..].copy_from_slice(&[0; 7]);
            for position in [17, 23] {
                let mut bad = seven;
                bad[position] = 1;
                seal(&k, aiv(17), &bad, inverse, &mut ct);
                let mut out = [SENTINEL; 24];
                refusals.push((17, unwrap(&k, &ct, &mut out), out == [0u8; 24]));
            }
            assert_eq!(refusals.len(), 11);
            for (mli, result, wiped) in refusals {
                assert_eq!(
                    result,
                    Err(ModeError::TagMismatch),
                    "mli={mli} inverse={inverse}"
                );
                assert!(wiped, "mli={mli} inverse={inverse}");
            }

            let full = [0xC3u8; 24];
            for (mli, padded) in [(17, &seven), (24, &full)] {
                seal(&k, aiv(mli), padded, inverse, &mut ct);
                let mut out = [SENTINEL; 24];
                assert_eq!(
                    unwrap(&k, &ct, &mut out),
                    Ok(mli as usize),
                    "mli={mli} inverse={inverse}"
                );
                assert_eq!(&out, padded, "mli={mli} inverse={inverse}");
            }
        }
    }

    /// The harness entry to the KWP integrity check accepts a matching ICV
    /// with zero padding, and refuses a wrong prefix, an indicator of 0 or
    /// 9 for one semiblock, and a non-zero padding octet.
    #[test]
    fn kwp_check_internal_refuses_each_fault() {
        crate::test_support::start_module();
        let key = [0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0];
        assert_eq!(super::kwp_check_internal(&aiv(5), &key), Ok(5));
        let mut prefix = aiv(5);
        prefix[0] ^= 1;
        let mut pad = key;
        pad[7] = 1;
        for (a, p) in [(prefix, key), (aiv(0), key), (aiv(9), key), (aiv(5), pad)] {
            assert_eq!(
                super::kwp_check_internal(&a, &p),
                Err(crate::ModeError::TagMismatch)
            );
        }
    }

    /// The single-block path of `kwp_unwrap_single_exit_masked_padding`:
    /// an out-of-range indicator or a non-zero padding octet, including the
    /// first of seven at length 1, is refused with `TagMismatch` and an
    /// all-zero output, and plaintexts of 1, 7 and 8 bytes are accepted.
    #[test]
    fn kwp_unwrap_single_block_masked_padding() {
        crate::test_support::start_module();
        let k = KwKey::new(&[0x42u8; 24]).unwrap();
        for inverse in [false, true] {
            let unwrap = if inverse {
                kwp_unwrap_inverse
            } else {
                kwp_unwrap
            };
            let single = [0x46u8, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69, 0x00];
            let mut ct = [0u8; 16];
            seal(&k, aiv(7), &single, inverse, &mut ct);
            let mut out = [SENTINEL; 8];
            assert_eq!(unwrap(&k, &ct, &mut out), Ok(7), "inverse={inverse}");
            for mli in [0, 9, u32::MAX] {
                seal(&k, aiv(mli), &single, inverse, &mut ct);
                let mut out = [SENTINEL; 8];
                assert_eq!(
                    unwrap(&k, &ct, &mut out),
                    Err(ModeError::TagMismatch),
                    "mli={mli} inverse={inverse}"
                );
                assert_eq!(out, [0u8; 8]);
            }
            let one = [0x46u8, 0, 0, 0, 0, 0, 0, 0];
            for (mli, bad_position, padded) in [(7, 7, single), (1, 1, one), (1, 7, one)] {
                let mut bad = padded;
                bad[bad_position] = 1;
                seal(&k, aiv(mli), &bad, inverse, &mut ct);
                let mut out = [SENTINEL; 8];
                assert_eq!(
                    unwrap(&k, &ct, &mut out),
                    Err(ModeError::TagMismatch),
                    "mli={mli} position={bad_position} inverse={inverse}"
                );
                assert_eq!(out, [0u8; 8], "mli={mli} inverse={inverse}");
            }
            let eight = [0x46u8, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69, 0x6e];
            for (mli, padded) in [(1, one), (8, eight)] {
                seal(&k, aiv(mli), &padded, inverse, &mut ct);
                let mut out = [SENTINEL; 8];
                assert_eq!(
                    unwrap(&k, &ct, &mut out),
                    Ok(mli as usize),
                    "mli={mli} inverse={inverse}"
                );
                assert_eq!(out, padded, "mli={mli} inverse={inverse}");
            }
        }
    }

    // RFC 3394 §4.1 — AES-128 wrap of 128-bit key.
    #[test]
    fn rfc3394_4_1_aes128_wrap_128() {
        crate::test_support::start_module();
        let kek: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected: [u8; 24] = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 24];
        kw_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut back = [0u8; 16];
        kw_unwrap(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    // RFC 3394 §4.6 — AES-256 wrap of 256-bit key.
    #[test]
    fn rfc3394_4_6_aes256_wrap_256() {
        crate::test_support::start_module();
        let kek: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let pt: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let expected: [u8; 40] = [
            0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
            0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
            0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
        ];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 40];
        kw_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut back = [0u8; 32];
        kw_unwrap(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    // RFC 5649 §6 — AES-192 KWP wrap of 7-byte key (single-block path).
    #[test]
    fn rfc5649_kwp_aes192_7_bytes() {
        crate::test_support::start_module();
        let kek: [u8; 24] = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt: [u8; 7] = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
        let expected: [u8; 16] = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b,
            0xb2, 0x4f,
        ];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 16];
        kwp_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut scratch = [0u8; 8];
        let mli = kwp_unwrap(&k, &ct, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);
    }

    // RFC 5649 §6 — AES-192 KWP wrap of 20-byte key (multi-semiblock path).
    #[test]
    fn rfc5649_kwp_aes192_20_bytes() {
        crate::test_support::start_module();
        let kek: [u8; 24] = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt: [u8; 20] = [
            0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89,
            0x41, 0x15, 0x50, 0x68, 0xf7, 0x38,
        ];
        let expected: [u8; 32] = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 32];
        kwp_wrap(&k, &pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut scratch = [0u8; 24];
        let mli = kwp_unwrap(&k, &ct, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);
    }

    #[test]
    fn kw_rejects_tampered_icv() {
        crate::test_support::start_module();
        let kek = [0u8; 16];
        let pt = [0xaau8; 16];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 24];
        kw_wrap(&k, &pt, &mut ct).unwrap();
        ct[0] ^= 1;
        let mut back = [0u8; 16];
        assert!(kw_unwrap(&k, &ct, &mut back).is_err());
    }

    #[test]
    fn kw_inverse_cipher_round_trip_aes128() {
        crate::test_support::start_module();
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let k = KwKey::new(&kek).unwrap();
        let mut ct_inv = [0u8; 24];
        kw_wrap_inverse(&k, &pt, &mut ct_inv).unwrap();
        let mut back = [0u8; 16];
        kw_unwrap_inverse(&k, &ct_inv, &mut back).unwrap();
        assert_eq!(back, pt);

        // Forward-cipher wrap of the same input must produce a different
        // ciphertext — the modes are distinct algorithms.
        let mut ct_fwd = [0u8; 24];
        kw_wrap(&k, &pt, &mut ct_fwd).unwrap();
        assert_ne!(ct_inv, ct_fwd);
    }

    #[test]
    fn kw_inverse_cipher_round_trip_aes192() {
        crate::test_support::start_module();
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = [0x5au8; 32];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 40];
        kw_wrap_inverse(&k, &pt, &mut ct).unwrap();
        let mut back = [0u8; 32];
        kw_unwrap_inverse(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn kw_inverse_cipher_round_trip_aes256() {
        crate::test_support::start_module();
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 40];
        kw_wrap_inverse(&k, &pt, &mut ct).unwrap();
        let mut back = [0u8; 32];
        kw_unwrap_inverse(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    // A wrap in one direction fails the other direction's ICV check with
    // overwhelming probability.
    #[test]
    fn kw_cross_direction_rejects() {
        crate::test_support::start_module();
        let kek = [0x42u8; 16];
        let pt = [0xa5u8; 24];
        let k = KwKey::new(&kek).unwrap();
        let mut ct_fwd = [0u8; 32];
        kw_wrap(&k, &pt, &mut ct_fwd).unwrap();
        let mut back = [0u8; 24];
        assert!(kw_unwrap_inverse(&k, &ct_fwd, &mut back).is_err());

        let mut ct_inv = [0u8; 32];
        kw_wrap_inverse(&k, &pt, &mut ct_inv).unwrap();
        assert!(kw_unwrap(&k, &ct_inv, &mut back).is_err());
    }

    // A 7-byte plaintext pads to one semiblock, the single-block path of
    // RFC 5649 §4.1.
    #[test]
    fn kwp_inverse_cipher_round_trip_single_block() {
        crate::test_support::start_module();
        let kek = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt = [0x46u8, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
        let k = KwKey::new(&kek).unwrap();
        let mut ct_inv = [0u8; 16];
        kwp_wrap_inverse(&k, &pt, &mut ct_inv).unwrap();
        let mut scratch = [0u8; 8];
        let mli = kwp_unwrap_inverse(&k, &ct_inv, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);

        // Forward-cipher KWP of the same input must differ.
        let mut ct_fwd = [0u8; 16];
        kwp_wrap(&k, &pt, &mut ct_fwd).unwrap();
        assert_ne!(ct_inv, ct_fwd);
    }

    #[test]
    fn kwp_inverse_cipher_round_trip_multi_block() {
        crate::test_support::start_module();
        let kek = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt = [
            0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89,
            0x41, 0x15, 0x50, 0x68, 0xf7, 0x38,
        ];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 32];
        kwp_wrap_inverse(&k, &pt, &mut ct).unwrap();
        let mut scratch = [0u8; 24];
        let mli = kwp_unwrap_inverse(&k, &ct, &mut scratch).unwrap();
        assert_eq!(mli, pt.len());
        assert_eq!(&scratch[..mli], &pt[..]);
    }

    #[test]
    fn kwp_inverse_cipher_rejects_tampered_icv() {
        crate::test_support::start_module();
        let kek = [0u8; 16];
        let pt = [0xc3u8; 24];
        let k = KwKey::new(&kek).unwrap();
        let mut ct = [0u8; 32];
        kwp_wrap_inverse(&k, &pt, &mut ct).unwrap();
        ct[0] ^= 1;
        let mut scratch = [0u8; 24];
        assert!(kwp_unwrap_inverse(&k, &ct, &mut scratch).is_err());
    }
}
