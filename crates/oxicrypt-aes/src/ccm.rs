//! AES Counter with CBC-MAC (CCM) per NIST SP 800-38C.
//!
//! # Scope
//!
//! Implements the full SP 800-38C authenticated encryption construction
//! (CCM-AE / CCM-AD) over the `BlockCipher` trait so the same code runs
//! across AES-128 / AES-192 / AES-256. The formatting and counter
//! generation functions follow Appendix A verbatim:
//!
//!   * **Formatting (`format_b0` + `format_associated_data`)** —
//!     Appendix A.2. The first formatting block `B0` packs the
//!     `Adata`/`Tlen`/`L` flags, the nonce `N`, and the plaintext
//!     length `Q = [Plen]_{8L}`. Associated data is prefixed with a
//!     length encoding that is 2 bytes, 6 bytes (`0xFFFE` prefix), or
//!     10 bytes (`0xFFFF` prefix) depending on its length.
//!   * **Counter block (`format_ctr`)** — Appendix A.3. The counter
//!     block has the same L/Nlen layout as `B0`, with the low L bytes
//!     holding the counter value i (starting at 0).
//!
//! Encryption proceeds in two passes per SP 800-38C §6.1 "CCM
//! Generation-Encryption Process":
//!
//!   1. Format the CBC-MAC input as
//!      `B0 || format(A) || zeropad(P)` and CBC-MAC it with IV = 0
//!      to obtain the raw tag `Y_r`.
//!   2. Derive the CTR keystream starting from block index 1 and XOR
//!      it with the plaintext. The tag output is
//!      `T = MSB_Tlen(Y_r XOR S_0)`, where `S_0 = CIPH_K(Ctr_0)`.
//!
//! Decryption (§6.2 "CCM Decryption-Verification Process") verifies
//! first. Each payload block is decrypted into a 16-byte local and
//! absorbed into the CBC-MAC there, the recomputed tag is compared with
//! the transmitted tag with no early exit (the comparison's timing is not
//! measured by the harness), and only when they are equal
//! does a second CTR pass write the plaintext to the caller's buffer.
//! Nothing is written to that buffer before the tag has verified, so an
//! unverified payload is never revealed (§6.2), and a module error during
//! the output pass leaves the buffer zeroised. The locals holding
//! decrypted payload or MAC state are wiped on every exit.
//!
//! Decryption returns the one error [`ModeError::TagMismatch`] for every
//! invalid input, so the returned error does not tell a tag that does not
//! verify from a malformed input (§6.2). A validity fault is detected
//! from the nonce, tag and ciphertext lengths, which the adversary already
//! knows, so its rejection time reveals nothing beyond those lengths. A
//! well-formed input runs the full MAC pass regardless of where the tag
//! differs.
//!
//! The tag length is fixed per key (SP 800-38C §5.3): [`CcmKey::new`]
//! takes it, and every call under the key produces or checks a tag of
//! that length.
//!
//! # Invocation limit
//!
//! SP 800-38C §5.1 limits the block-cipher invocations under one key to
//! 2^61. A [`CcmKey`] charges each encryption and decryption the
//! invocations its lengths fix, a failed decryption included, before any
//! work, and refuses an operation that would take the count past 2^61
//! with [`ModeError::Module`] carrying
//! [`Error::KeyExhausted`]. SP 800-38C Appendix B also bounds the number
//! of INVALID results under one key. The module does not count them: the
//! operator counts each [`ModeError::TagMismatch`] that [`ccm_decrypt`]
//! returns under a key and stops using the key at the bound the
//! application sets.
//!
//! # Parameter validation
//!
//! The call sites enforce the full SP 800-38C Appendix A.1 parameter matrix:
//!
//!   * Nonce length `Nlen` ∈ {7, 8, 9, 10, 11, 12, 13}.
//!   * Tag length `Tlen` ∈ {8, 10, 12, 14, 16}: 64 bits or more, since
//!     shorter tags need the analysis of SP 800-38C Appendix B.
//!   * Plaintext length `Plen` < `2^(8*(15 - Nlen))` (equivalently, `P`
//!     must be representable in the L-byte length field `Q`).
//!   * Associated-data length `Alen` at most [`CCM_MAX_AAD_LEN`],
//!     2^64 − 2^16 − 1 bytes, within the `Alen < 2^64` of SP 800-38C
//!     Appendix A.1; the 10-byte `0xFFFF`-prefixed encoding covers
//!     `Alen` from 2^32.
//!
//! On encryption, out-of-range values return dedicated [`ModeError`]
//! variants rather than panicking; on decryption they return
//! [`ModeError::TagMismatch`].

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop
)]

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};

use oxicrypt_module::{
    Error, SelfTestStarted, require_allowed, require_operational, require_self_test_started_token,
};

use crate::block::{CCM_SERVICES, KeySchedule};
use crate::modes::{BlockCipher, ModeError};
use crate::observe;
use crate::wipe::{WipedBlock, WipedBuffer};

/// AES block size in bytes. Always 16 for AES.
const B: usize = 16;

/// Valid nonce-length interval per SP 800-38C Appendix A.1.
const NLEN_MIN: usize = 7;
const NLEN_MAX: usize = 13;

/// Valid tag-length set (bytes, not bits): the SP 800-38C Appendix A.1
/// set less the 32- and 48-bit tags, which Appendix B admits only with
/// an analysis of the application.
const fn tlen_valid(tlen: usize) -> bool {
    matches!(tlen, 8 | 10 | 12 | 14 | 16)
}

/// The block-cipher invocations SP 800-38C §5.1 permits under one key.
const CCM_INVOCATION_LIMIT: u64 = 1 << 61;

/// An AES key bound to CCM (SP 800-38C), with its tag length.
///
/// The key charges every encryption and decryption under it the
/// block-cipher invocations that SP 800-38C's formatting fixes for its
/// lengths, a failed decryption charged in full, and refuses an
/// operation whose charge would take the total past 2^61
/// (SP 800-38C §5.1) with [`ModeError::Module`] carrying
/// [`Error::KeyExhausted`], before doing any of it.
///
/// The limit applies to the key bytes, which the module sees only within
/// one instance. An operator who uses the same key in several processes
/// or across a restart sums their counts ([`CcmKey::invocations`],
/// [`CcmKey::new_with_count`]) and establishes a new key before the sum
/// reaches 2^61.
///
/// ```compile_fail,E0599
/// let k = oxicrypt_aes::CcmKey::new(&[0u8; 16], 16).unwrap();
/// let k2 = k.clone();
/// ```
pub struct CcmKey {
    pub(crate) schedule: KeySchedule,
    pub(crate) tag_len: usize,
    pub(crate) invocations: AtomicU64,
}

impl CcmKey {
    /// Builds a CCM key from 16, 24 or 32 bytes of key material, with a
    /// tag length of `tag_len` bytes, one of 8, 10, 12, 14 or 16, and an
    /// invocation count of 0.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless the module is
    /// `Operational`, [`Error::InvalidInput`] unless `key` is 16, 24 or 32
    /// bytes and `tag_len` is in the set above, and
    /// [`Error::AlgorithmRestricted`] when the active profile does not
    /// permit AES-CCM at that key size.
    ///
    /// The key is returned by value, as is that of
    /// [`CcmKey::new_with_count`]; a copy of the schedule that the move
    /// leaves behind is not zeroized.
    pub fn new(key: &[u8], tag_len: usize) -> Result<Self, Error> {
        Self::build(key, tag_len, 0)
    }

    /// Builds the key as [`CcmKey::new`] does, in `slot`, and returns a
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
    /// The errors of [`CcmKey::new`].
    #[doc(hidden)]
    pub fn new_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
        tag_len: usize,
    ) -> Result<&'a mut Self, Error> {
        Self::build_in_place(slot, key, tag_len, 0)
    }

    /// [`CcmKey::new_with_count`] in `slot`, as [`CcmKey::new_in_place`]
    /// is [`CcmKey::new`] there.
    ///
    /// # Errors
    ///
    /// The errors of [`CcmKey::new_with_count`].
    #[doc(hidden)]
    pub fn new_with_count_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
        tag_len: usize,
        used: u64,
    ) -> Result<&'a mut Self, Error> {
        Self::build_in_place(slot, key, tag_len, used)
    }

    /// Builds a CCM key as [`CcmKey::new`] does, with its count preloaded
    /// to `used`: the block-cipher invocations an earlier instance of the
    /// same key bytes performed, as read from [`CcmKey::invocations`].
    ///
    /// # Errors
    ///
    /// The errors of [`CcmKey::new`], checked first, then
    /// [`Error::InvalidInput`] when `used` is above 2^61.
    pub fn new_with_count(key: &[u8], tag_len: usize, used: u64) -> Result<Self, Error> {
        Self::build(key, tag_len, used)
    }

    /// The number of block-cipher invocations reserved under this key,
    /// including any preloaded by [`CcmKey::new_with_count`].
    pub fn invocations(&self) -> u64 {
        self.invocations.load(Ordering::Relaxed)
    }

    /// The gates and argument checks of every constructor, returning the
    /// key with a zeroed schedule for `key` to be expanded into.
    fn admit(key: &[u8], tag_len: usize, used: u64) -> Result<Self, Error> {
        let schedule = KeySchedule::admit(key.len(), CCM_SERVICES)?;
        if !tlen_valid(tag_len) || used > CCM_INVOCATION_LIMIT {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            schedule,
            tag_len,
            invocations: AtomicU64::new(used),
        })
    }

    fn build(key: &[u8], tag_len: usize, used: u64) -> Result<Self, Error> {
        let mut k = Self::admit(key, tag_len, used)?;
        k.schedule.expand(key);
        Ok(k)
    }

    fn build_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
        tag_len: usize,
        used: u64,
    ) -> Result<&'a mut Self, Error> {
        let k = slot.write(Self::admit(key, tag_len, used)?);
        k.schedule.expand(key);
        Ok(k)
    }

    /// The tag length in bytes, one of 8, 10, 12, 14 or 16, fixed at
    /// construction: the length [`ccm_encrypt`] writes and [`ccm_decrypt`]
    /// verifies.
    pub const fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// Reserves `cost` invocations, or refuses when the count would pass
    /// the limit. The compare-and-swap makes the check and the addition
    /// one step, so concurrent callers can never reserve past the limit.
    fn reserve_invocations(&self, cost: u64) -> Result<(), ModeError> {
        // The count guards no other memory, so the atomicity of the
        // read-modify-write is all the ordering it needs.
        let mut used = self.invocations.load(Ordering::Relaxed);
        loop {
            let Some(total) = used
                .checked_add(cost)
                .filter(|&total| total <= CCM_INVOCATION_LIMIT)
            else {
                return Err(ModeError::Module(Error::KeyExhausted));
            };
            match self.invocations.compare_exchange_weak(
                used,
                total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => used = current,
            }
        }
    }
}

/// The direction of a CCM operation, which fixes its payload passes.
#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// The block-cipher invocations one CCM operation over `aad_len` bytes of
/// associated data and `payload_len` bytes of payload makes, the count
/// SP 800-38C §5.1 bounds per key, by the formatting of Appendix A.2 and
/// the steps of §6.1 and §6.2. A decryption costs one payload pass more
/// than an encryption because [`ccm_open`] verifies first: its MAC pass
/// computes the keystream of every payload block to decrypt that block
/// for the CBC-MAC, and its output pass computes that keystream again
/// once the tag has verified.
fn invocation_cost(aad_len: usize, payload_len: usize, direction: Direction) -> u64 {
    let aad_len = aad_len as u64;
    let a_enc: u64 = if aad_len == 0 {
        0
    } else if aad_len < (1 << 16) - (1 << 8) {
        2
    } else if aad_len < 1 << 32 {
        6
    } else {
        10
    };
    let aad_blocks = a_enc.saturating_add(aad_len).div_ceil(B as u64);
    let payload_blocks = (payload_len as u64).div_ceil(B as u64);
    let payload_passes: u64 = match direction {
        Direction::Encrypt => 2,
        Direction::Decrypt => 3,
    };
    1u64.saturating_add(aad_blocks)
        .saturating_add(payload_blocks.saturating_mul(payload_passes))
        .saturating_add(1)
}

/// Build the `B0` formatting block per SP 800-38C Appendix A.2.1.
///
/// Layout:
///
/// ```text
/// B0[0]   = flags
///         = (Adata?64:0)                // bit 6
///         | (((Tlen-2)/2) << 3)         // bits 3..5: (t-2)/2
///         | (L-1)                       // bits 0..2
/// B0[1..1+Nlen] = N
/// B0[1+Nlen..16] = Q  // Plen as L-byte big-endian
/// ```
fn format_b0(nonce: &[u8], adata_present: bool, tlen: usize, plen: u64) -> [u8; B] {
    let nlen = nonce.len();
    let l = B - 1 - nlen;
    let mut b0 = [0u8; B];
    let a_flag: u8 = if adata_present { 0x40 } else { 0 };
    let t_flag: u8 = (((tlen as u8) - 2) / 2) << 3;
    let l_flag: u8 = (l as u8) - 1;
    b0[0] = a_flag | t_flag | l_flag;
    b0[1..=nlen].copy_from_slice(nonce);
    // Encode plen into the trailing L bytes as big-endian. L ≤ 8 so
    // the length always fits in a u64.
    let mut q = plen;
    for i in 0..l {
        b0[B - 1 - i] = (q & 0xff) as u8;
        q >>= 8;
    }
    b0
}

/// Build the CTR_i counter block per SP 800-38C Appendix A.3.
///
/// ```text
/// Ctr_i[0]    = (L-1)        // bits 0..2 only; upper bits reserved=0
/// Ctr_i[1..1+Nlen] = N
/// Ctr_i[1+Nlen..16] = [i]_{8L}
/// ```
fn format_ctr(nonce: &[u8], i: u64) -> [u8; B] {
    let nlen = nonce.len();
    let l = B - 1 - nlen;
    let mut c = [0u8; B];
    c[0] = (l as u8) - 1;
    c[1..=nlen].copy_from_slice(nonce);
    let mut v = i;
    for k in 0..l {
        c[B - 1 - k] = (v & 0xff) as u8;
        v >>= 8;
    }
    c
}

/// XOR a single block into `acc` in place: `acc ^= other`.
fn xor_block(acc: &mut [u8; B], other: &[u8; B]) {
    for k in 0..B {
        acc[k] ^= other[k];
    }
}

/// Equality compare for two byte slices of identical length that reads
/// every byte and has no early exit on content. Returns `true` iff every
/// byte matches.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Absorb a single partial-or-full block (already zero-padded) into
/// the running CBC-MAC state.
fn cbc_mac_block<B2: BlockCipher>(
    cipher: &B2,
    started: &SelfTestStarted,
    y: &mut [u8; B],
    block: &[u8; B],
) -> Result<(), Error> {
    xor_block(y, block);
    cipher.encrypt_block_with(started, y)
}

/// Compute the raw CBC-MAC tag `Y_r` over `B0 || format(A) ||
/// zeropad(P)` into `y`, per SP 800-38C §6.1 steps 2 and 3.
fn ccm_mac<C: BlockCipher>(
    cipher: &C,
    started: &SelfTestStarted,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tlen: usize,
    y: &mut [u8; B],
) -> Result<(), Error> {
    ccm_mac_header(cipher, started, nonce, aad, plaintext.len(), tlen, y)?;

    // Absorb the plaintext, zero-padded to a block boundary.
    let mut blk = WipedBlock::new(WipedBuffer::CcmPlaintextBlock);
    let mut off = 0;
    while plaintext.len() - off >= B {
        blk.bytes.copy_from_slice(&plaintext[off..off + B]);
        cbc_mac_block(cipher, started, y, &blk.bytes)?;
        off += B;
    }
    let rem = plaintext.len() - off;
    if rem > 0 {
        blk.bytes = [0u8; B];
        blk.bytes[..rem].copy_from_slice(&plaintext[off..]);
        cbc_mac_block(cipher, started, y, &blk.bytes)?;
    }
    Ok(())
}

/// Run the CBC-MAC over `B0 || format(A)` into `y`, the part of the
/// SP 800-38C §6.1 step 2 input that precedes the payload, so that
/// encryption and decryption format it byte for byte identically.
fn ccm_mac_header<C: BlockCipher>(
    cipher: &C,
    started: &SelfTestStarted,
    nonce: &[u8],
    aad: &[u8],
    plen: usize,
    tlen: usize,
    y: &mut [u8; B],
) -> Result<(), Error> {
    // Y0 = B0
    *y = format_b0(nonce, !aad.is_empty(), tlen, plen as u64);
    cipher.encrypt_block_with(started, y)?;

    // Absorb associated data per §A.2.2.
    if !aad.is_empty() {
        // Length prefix: 2 bytes if Alen < 2^16 - 2^8, otherwise 6
        // bytes (0xFFFE||a_be32) if Alen < 2^32, otherwise 10 bytes
        // (0xFFFF||a_be64).
        let alen = aad.len() as u64;
        // First partial block: [length_prefix || leading AAD bytes].
        let mut first = [0u8; B];
        let prefix_len: usize;
        if alen < (1u64 << 16) - (1u64 << 8) {
            first[0] = ((alen >> 8) & 0xff) as u8;
            first[1] = (alen & 0xff) as u8;
            prefix_len = 2;
        } else if alen < (1u64 << 32) {
            first[0] = 0xff;
            first[1] = 0xfe;
            let a32 = (alen as u32).to_be_bytes();
            first[2..6].copy_from_slice(&a32);
            prefix_len = 6;
        } else {
            first[0] = 0xff;
            first[1] = 0xff;
            first[2..10].copy_from_slice(&alen.to_be_bytes());
            prefix_len = 10;
        }
        let take = core::cmp::min(B - prefix_len, aad.len());
        first[prefix_len..prefix_len + take].copy_from_slice(&aad[..take]);
        cbc_mac_block(cipher, started, y, &first)?;

        let mut off = take;
        while aad.len() - off >= B {
            let mut blk = [0u8; B];
            blk.copy_from_slice(&aad[off..off + B]);
            cbc_mac_block(cipher, started, y, &blk)?;
            off += B;
        }
        let rem = aad.len() - off;
        if rem > 0 {
            let mut blk = [0u8; B];
            blk[..rem].copy_from_slice(&aad[off..]);
            cbc_mac_block(cipher, started, y, &blk)?;
        }
    }
    Ok(())
}

/// Longest CCM associated data, in bytes: 2^64 − 2^16 − 1.
///
/// SP 800-38C Appendix A.1 allows any `Alen < 2^64`. The module accepts at
/// most this many bytes, so that the formatted associated data (a length
/// prefix of up to 10 octets, the data, and up to 15 octets of zero
/// padding) has a length that fits in a `u64`. The margin is deliberately
/// far larger than the 25 octets that needs. [`ccm_encrypt`] refuses a
/// longer AAD with [`ModeError::InvalidAadLength`] and [`ccm_decrypt`]
/// with [`ModeError::TagMismatch`].
///
/// ```
/// assert_eq!(oxicrypt_aes::ccm::CCM_MAX_AAD_LEN, u64::MAX - (1 << 16));
/// ```
pub const CCM_MAX_AAD_LEN: u64 = u64::MAX - (1 << 16);

/// Validate the parameter matrix from SP 800-38C Appendix A.1 and return the
/// corresponding `ModeError` variant on any failure.
fn validate_params(
    nonce_len: usize,
    aad_len: usize,
    plaintext_len: usize,
    tlen: usize,
) -> Result<(), ModeError> {
    if !(NLEN_MIN..=NLEN_MAX).contains(&nonce_len) {
        return Err(ModeError::InvalidNonceLength);
    }
    if !tlen_valid(tlen) {
        return Err(ModeError::InvalidTagLength);
    }
    // L = 15 - Nlen, Plen must be < 2^(8L).
    let l = B - 1 - nonce_len;
    if l < 8 {
        let max_plen: u64 = 1u64 << (8 * l as u32);
        if (plaintext_len as u64) >= max_plen {
            return Err(ModeError::InvalidPayloadLength);
        }
    }
    if (aad_len as u64) > CCM_MAX_AAD_LEN {
        return Err(ModeError::InvalidAadLength);
    }
    Ok(())
}

/// Encrypt and authenticate `plaintext` under CCM.
///
/// Writes the ciphertext, `plaintext.len()` bytes, into `ciphertext_out`
/// and the tag into `tag_out`, whose length must be the key's tag length.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-CCM at the key's size;
/// [`ModeError::InvalidTagLength`] when `tag_out` is not the key's tag
/// length; [`ModeError::LengthMismatch`] when `ciphertext_out` is not the
/// plaintext's length; [`ModeError::Module`] carrying
/// [`Error::KeyExhausted`] when the encryption's invocations would take
/// the key's count past 2^61; and the parameter errors of SP 800-38C
/// Appendix A.1. The buffer and parameter errors are returned before the
/// invocations are charged, so a refused call spends none of the key's
/// count. A module that enters its error state while the encryption runs
/// stops it with [`ModeError::Module`], with the charge spent.
pub fn ccm_encrypt(
    key: &CcmKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(CCM_SERVICES))?;
    if tag_out.len() != key.tag_len() {
        return Err(ModeError::InvalidTagLength);
    }
    if ciphertext_out.len() != plaintext.len() {
        return Err(ModeError::LengthMismatch);
    }
    validate_params(nonce.len(), aad.len(), plaintext.len(), key.tag_len())?;
    key.reserve_invocations(invocation_cost(
        aad.len(),
        plaintext.len(),
        Direction::Encrypt,
    ))?;
    ccm_encrypt_core(
        &key.schedule,
        nonce,
        aad,
        plaintext,
        ciphertext_out,
        tag_out,
    )
}

/// [`ccm_encrypt`] without the service gates, for the power-up
/// self-tests. The tag length is `tag_out.len()`.
pub(crate) fn ccm_encrypt_core<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8],
) -> Result<(), ModeError> {
    let started = &require_self_test_started_token()?;
    let tlen = tag_out.len();
    validate_params(nonce.len(), aad.len(), plaintext.len(), tlen)?;
    if ciphertext_out.len() != plaintext.len() {
        return Err(ModeError::LengthMismatch);
    }

    let mut y = WipedBlock::new(WipedBuffer::CcmEncryptMacState);
    let mut s0 = WipedBlock::new(WipedBuffer::CcmEncryptTagMask);
    let mut s = WipedBlock::new(WipedBuffer::CcmEncryptKeystream);
    ccm_mac(cipher, started, nonce, aad, plaintext, tlen, &mut y.bytes)?;

    // Keystream block 0 is used to mask the tag.
    s0.bytes = format_ctr(nonce, 0);
    cipher.encrypt_block_with(started, &mut s0.bytes)?;

    // CTR-encrypt plaintext into ciphertext_out starting from block 1.
    let mut off = 0usize;
    let mut i: u64 = 1;
    while off < plaintext.len() {
        s.bytes = format_ctr(nonce, i);
        cipher.encrypt_block_with(started, &mut s.bytes)?;
        let take = core::cmp::min(B, plaintext.len() - off);
        for k in 0..take {
            ciphertext_out[off + k] = plaintext[off + k] ^ s.bytes[k];
        }
        off += take;
        i += 1;
    }

    // T = MSB_Tlen(Y XOR S0).
    for k in 0..tlen {
        tag_out[k] = y.bytes[k] ^ s0.bytes[k];
    }
    Ok(())
}

/// Decrypt and verify a CCM ciphertext.
///
/// `ciphertext` is the payload ciphertext `C` and `tag` the transmitted
/// tag `T`, whose length must be the key's tag length. On success writes
/// the recovered plaintext, `ciphertext.len()` bytes, into
/// `plaintext_out`.
///
/// The tag is verified before any byte is written: the payload is
/// decrypted block by block into a local for the CBC-MAC, and only after
/// the recomputed tag has compared equal, with no early exit (the
/// comparison's timing is not measured by the harness), is it
/// decrypted again into `plaintext_out`. On any error `plaintext_out`
/// has not been written, except that a module error during that second
/// pass, after verification, leaves it zeroised.
///
/// Every invalid input returns the one error [`ModeError::TagMismatch`],
/// so the returned error does not tell apart a nonce length outside 7 to
/// 13, a payload length the nonce's length field cannot represent, and a
/// tag that does not verify (SP 800-38C §6.2). A validity fault is
/// detected from the nonce, tag and ciphertext lengths, which the
/// adversary already knows, so its rejection time reveals nothing beyond
/// those lengths. A well-formed input runs the full MAC pass regardless
/// of where the tag differs. An empty `ciphertext` with a tag
/// is accepted and decrypts to an empty payload once the tag verifies,
/// departing from §6.2 step 1, which rejects `Clen = Tlen`, because
/// this crate's encryption of an empty payload produces `C = T`.
///
/// The decryption is charged the invocations of [`ccm_encrypt`] for the
/// same lengths and one more per payload block, for the keystream of the
/// verification pass, whatever its result. Each [`ModeError::TagMismatch`] is
/// an INVALID result that the operator counts under SP 800-38C
/// Appendix B.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit AES-CCM at the key's size;
/// [`ModeError::InvalidTagLength`] when `tag` is not the key's tag
/// length; [`ModeError::LengthMismatch`] when `plaintext_out` is not the
/// ciphertext's length; [`ModeError::Module`] carrying
/// [`Error::KeyExhausted`] when the decryption's invocations would take
/// the key's count past 2^61; and [`ModeError::TagMismatch`] for every
/// invalid input. The buffer errors are returned before the invocations
/// are charged, and [`ModeError::TagMismatch`] after it.
pub fn ccm_decrypt(
    key: &CcmKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.schedule.service(CCM_SERVICES))?;
    if tag.len() != key.tag_len() {
        return Err(ModeError::InvalidTagLength);
    }
    if plaintext_out.len() != ciphertext.len() {
        return Err(ModeError::LengthMismatch);
    }
    key.reserve_invocations(invocation_cost(
        aad.len(),
        ciphertext.len(),
        Direction::Decrypt,
    ))?;
    ccm_decrypt_core(&key.schedule, nonce, aad, ciphertext, tag, plaintext_out)
}

/// [`ccm_decrypt`] without the service gates, for the power-up
/// self-tests. The tag length is `tag.len()`, and a tag length outside
/// the key set is one more invalid input.
pub(crate) fn ccm_decrypt_core<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    observe::decryption_started();
    let started = &require_self_test_started_token()?;
    if plaintext_out.len() != ciphertext.len() {
        return Err(ModeError::LengthMismatch);
    }
    // SP 800-38C §6.2: a malformed input returns the error of a tag that
    // does not verify.
    if validate_params(nonce.len(), aad.len(), ciphertext.len(), tag.len()).is_err() {
        return Err(ModeError::TagMismatch);
    }
    ccm_open(cipher, started, nonce, aad, ciphertext, tag, plaintext_out)
}

/// The verification and decryption of [`ccm_decrypt_core`], over
/// validated parameters: SP 800-38C §6.2 steps 3 to 10 with the payload
/// held block by block in a local, then the CTR pass into
/// `plaintext_out` once the tag has verified.
fn ccm_open<C: BlockCipher>(
    cipher: &C,
    started: &SelfTestStarted,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    let tlen = tag.len();
    let plen = ciphertext.len();
    let mut y = WipedBlock::new(WipedBuffer::CcmMacState);
    let mut keystream = WipedBlock::new(WipedBuffer::CcmBlock);
    let mut payload = WipedBlock::new(WipedBuffer::CcmBlock);
    let mut expected = WipedBlock::new(WipedBuffer::CcmBlock);

    ccm_mac_header(cipher, started, nonce, aad, plen, tlen, &mut y.bytes)?;
    let mut off = 0usize;
    let mut i: u64 = 1;
    while off < plen {
        keystream.bytes = format_ctr(nonce, i);
        cipher.encrypt_block_with(started, &mut keystream.bytes)?;
        let take = core::cmp::min(B, plen - off);
        payload.bytes = [0u8; B];
        for k in 0..take {
            payload.bytes[k] = ciphertext[off + k] ^ keystream.bytes[k];
        }
        cbc_mac_block(cipher, started, &mut y.bytes, &payload.bytes)?;
        off += take;
        i += 1;
    }

    expected.bytes = format_ctr(nonce, 0);
    cipher.encrypt_block_with(started, &mut expected.bytes)?;
    xor_block(&mut expected.bytes, &y.bytes);
    let verified = ct_eq(&expected.bytes[..tlen], tag);
    observe::tag_compared(verified);
    if !verified {
        return Err(ModeError::TagMismatch);
    }

    let mut off = 0usize;
    let mut i: u64 = 1;
    while off < plen {
        keystream.bytes = format_ctr(nonce, i);
        if let Err(e) = cipher.encrypt_block_with(started, &mut keystream.bytes) {
            // The blocks already written are verified, but the caller is
            // handed no partial payload.
            oxicrypt_zeroize::zeroize(plaintext_out);
            return Err(e.into());
        }
        let take = core::cmp::min(B, plen - off);
        for k in 0..take {
            plaintext_out[off + k] = ciphertext[off + k] ^ keystream.bytes[k];
        }
        observe::output_written(take);
        off += take;
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{CcmKey, ccm_decrypt, ccm_decrypt_core, ccm_encrypt, ccm_encrypt_core};
    use crate::block::KeySchedule;
    use crate::modes::{BlockCipher, ModeError};
    use core::cell::Cell;
    use oxicrypt_module::{Error, SelfTestStarted};
    use std::vec::Vec;

    // Shared CAVP parameters for all three keysize tests.
    // [Alen=32, Nlen=13, Tlen=16, Plen=16], Count=160.

    // CAVP CCMVS CCM-VPT, AES-128. Source: VPT128.rsp Count=160.
    #[test]
    fn cavp_vpt128_plen16_count160() {
        crate::test_support::start_module();
        let key: [u8; 16] = [
            0x70, 0x01, 0x0e, 0xd9, 0x0e, 0x61, 0x86, 0xec, 0xad, 0x41, 0xf0, 0xd3, 0xc7, 0xc4,
            0x2f, 0xf8,
        ];
        let nonce: [u8; 13] = [
            0xa5, 0xf4, 0xf4, 0x98, 0x6e, 0x98, 0x47, 0x29, 0x65, 0xf5, 0xab, 0xcc, 0x4b,
        ];
        let aad: [u8; 32] = [
            0x3f, 0xec, 0x0e, 0x5c, 0xc2, 0x4d, 0x67, 0x13, 0x94, 0x37, 0xcb, 0xc8, 0x11, 0x24,
            0x14, 0xfc, 0x8d, 0xac, 0xcd, 0x1a, 0x94, 0xb4, 0x9a, 0x4c, 0x76, 0xe2, 0xd3, 0x93,
            0x03, 0x54, 0x73, 0x17,
        ];
        let pt: [u8; 16] = [
            0xbe, 0x32, 0x2f, 0x58, 0xef, 0xa7, 0xf8, 0xc6, 0x8a, 0x63, 0x5e, 0x0b, 0x9c, 0xce,
            0x77, 0xf2,
        ];
        let expected_ct: [u8; 32] = [
            0x8e, 0x44, 0x25, 0xae, 0x57, 0x39, 0x74, 0xf0, 0xf0, 0x69, 0x3a, 0x18, 0x8b, 0x52,
            0x58, 0x12, 0xee, 0xf0, 0x8e, 0x3f, 0xb1, 0x5f, 0x42, 0x27, 0xe0, 0xd9, 0x89, 0xa4,
            0xd5, 0x87, 0xa8, 0xcf,
        ];
        let k = CcmKey::new(&key, 16).unwrap();
        let mut out = [0u8; 32];
        let (ct, tag) = out.split_at_mut(16);
        ccm_encrypt(&k, &nonce, &aad, &pt, ct, tag).unwrap();
        assert_eq!(out, expected_ct);
        let mut dec = [0u8; 16];
        let (ct, tag) = expected_ct.split_at(16);
        ccm_decrypt(&k, &nonce, &aad, ct, tag, &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    // CAVP CCMVS CCM-VPT, AES-192. Source: VPT192.rsp Count=160.
    #[test]
    fn cavp_vpt192_plen16_count160() {
        crate::test_support::start_module();
        let key: [u8; 24] = [
            0x68, 0x73, 0xf1, 0xc6, 0xc3, 0x09, 0x75, 0xaf, 0xf6, 0xf0, 0x84, 0x70, 0x26, 0x43,
            0x21, 0x13, 0x0a, 0x6e, 0x59, 0x84, 0xad, 0xe3, 0x24, 0xe9,
        ];
        let nonce: [u8; 13] = [
            0x7c, 0x4d, 0x2f, 0x7c, 0xec, 0x04, 0x36, 0x1f, 0x18, 0x7f, 0x07, 0x26, 0xd5,
        ];
        let aad: [u8; 32] = [
            0x77, 0x74, 0x3b, 0x5d, 0x83, 0xa0, 0x0d, 0x2c, 0x8d, 0x5f, 0x7e, 0x10, 0x78, 0x15,
            0x31, 0xb4, 0x96, 0xe0, 0x9f, 0x3b, 0xc9, 0x29, 0x5d, 0x7a, 0xe9, 0x79, 0x9e, 0x64,
            0x66, 0x8e, 0xf8, 0xc5,
        ];
        let pt: [u8; 16] = [
            0x50, 0x51, 0xa0, 0xb0, 0xb6, 0x76, 0x6c, 0xd6, 0xea, 0x29, 0xa6, 0x72, 0x76, 0x9d,
            0x40, 0xfe,
        ];
        let expected_ct: [u8; 32] = [
            0x0c, 0xe5, 0xac, 0x8d, 0x6b, 0x25, 0x6f, 0xb7, 0x58, 0x0b, 0xf6, 0xac, 0xc7, 0x64,
            0x26, 0xaf, 0x40, 0xbc, 0xe5, 0x8f, 0xd4, 0xcd, 0x65, 0x48, 0xdf, 0x90, 0xa0, 0x33,
            0x7c, 0x84, 0x20, 0x04,
        ];
        let k = CcmKey::new(&key, 16).unwrap();
        let mut out = [0u8; 32];
        let (ct, tag) = out.split_at_mut(16);
        ccm_encrypt(&k, &nonce, &aad, &pt, ct, tag).unwrap();
        assert_eq!(out, expected_ct);
        let mut dec = [0u8; 16];
        let (ct, tag) = expected_ct.split_at(16);
        ccm_decrypt(&k, &nonce, &aad, ct, tag, &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    // CAVP CCMVS CCM-VPT, AES-256. Source: VPT256.rsp Count=160.
    #[test]
    fn cavp_vpt256_plen16_count160() {
        crate::test_support::start_module();
        let key: [u8; 32] = [
            0xee, 0x8c, 0xe1, 0x87, 0x16, 0x97, 0x79, 0xd1, 0x3e, 0x44, 0x3d, 0x64, 0x28, 0xe3,
            0x8b, 0x38, 0xb5, 0x5d, 0xfb, 0x90, 0xf0, 0x22, 0x8a, 0x8a, 0x4e, 0x62, 0xf8, 0xf5,
            0x35, 0x80, 0x6e, 0x62,
        ];
        let nonce: [u8; 13] = [
            0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39, 0x1c, 0x98, 0xe6, 0x26, 0x9c, 0x8a,
        ];
        let aad: [u8; 32] = [
            0x71, 0x8d, 0x13, 0xe4, 0x75, 0x22, 0xac, 0x4c, 0xdf, 0x3f, 0x82, 0x80, 0x63, 0x98,
            0x0b, 0x6d, 0x45, 0x2f, 0xcd, 0xcd, 0x6e, 0x1a, 0x19, 0x04, 0xbf, 0x87, 0xf5, 0x48,
            0xa5, 0xfd, 0x5a, 0x05,
        ];
        let pt: [u8; 16] = [
            0xd1, 0x5f, 0x98, 0xf2, 0xc6, 0xd6, 0x70, 0xf5, 0x5c, 0x78, 0xa0, 0x66, 0x48, 0x33,
            0x2b, 0xc9,
        ];
        let expected_ct: [u8; 32] = [
            0xcc, 0x17, 0xbf, 0x87, 0x94, 0xc8, 0x43, 0x45, 0x7d, 0x89, 0x93, 0x91, 0x89, 0x8e,
            0xd2, 0x2a, 0x6f, 0x9d, 0x28, 0xfc, 0xb6, 0x42, 0x34, 0xe1, 0xcd, 0x79, 0x3c, 0x41,
            0x44, 0xf1, 0xda, 0x50,
        ];
        let k = CcmKey::new(&key, 16).unwrap();
        let mut out = [0u8; 32];
        let (ct, tag) = out.split_at_mut(16);
        ccm_encrypt(&k, &nonce, &aad, &pt, ct, tag).unwrap();
        assert_eq!(out, expected_ct);
        let mut dec = [0u8; 16];
        let (ct, tag) = expected_ct.split_at(16);
        ccm_decrypt(&k, &nonce, &aad, ct, tag, &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    // Tamper rejection: flipping a ciphertext bit must return
    // TagMismatch and leave the output buffer unwritten.
    #[test]
    fn ccm_rejects_bit_flip() {
        crate::test_support::start_module();
        let key: [u8; 16] = [
            0x70, 0x01, 0x0e, 0xd9, 0x0e, 0x61, 0x86, 0xec, 0xad, 0x41, 0xf0, 0xd3, 0xc7, 0xc4,
            0x2f, 0xf8,
        ];
        let nonce: [u8; 13] = [
            0xa5, 0xf4, 0xf4, 0x98, 0x6e, 0x98, 0x47, 0x29, 0x65, 0xf5, 0xab, 0xcc, 0x4b,
        ];
        let aad: [u8; 32] = [
            0x3f, 0xec, 0x0e, 0x5c, 0xc2, 0x4d, 0x67, 0x13, 0x94, 0x37, 0xcb, 0xc8, 0x11, 0x24,
            0x14, 0xfc, 0x8d, 0xac, 0xcd, 0x1a, 0x94, 0xb4, 0x9a, 0x4c, 0x76, 0xe2, 0xd3, 0x93,
            0x03, 0x54, 0x73, 0x17,
        ];
        let mut ct: [u8; 32] = [
            0x8e, 0x44, 0x25, 0xae, 0x57, 0x39, 0x74, 0xf0, 0xf0, 0x69, 0x3a, 0x18, 0x8b, 0x52,
            0x58, 0x12, 0xee, 0xf0, 0x8e, 0x3f, 0xb1, 0x5f, 0x42, 0x27, 0xe0, 0xd9, 0x89, 0xa4,
            0xd5, 0x87, 0xa8, 0xcf,
        ];
        ct[0] ^= 0x01;
        let k = CcmKey::new(&key, 16).unwrap();
        let mut dec = [0xA5u8; 16];
        let (ct, tag) = ct.split_at(16);
        let err = ccm_decrypt(&k, &nonce, &aad, ct, tag, &mut dec).unwrap_err();
        assert_eq!(err, ModeError::TagMismatch);
        assert_eq!(dec, [0xA5u8; 16]);
    }

    const KEY: [u8; 16] = [0x2b; 16];
    const NONCE: [u8; 13] = [0x1c; 13];
    const SENTINEL: u8 = 0xA5;
    const LIMIT: u64 = 1 << 61;
    const EXHAUSTED: ModeError = ModeError::Module(oxicrypt_module::Error::KeyExhausted);

    /// A key's cipher that counts the block-cipher calls made through it.
    struct Counting<'a> {
        inner: &'a KeySchedule,
        calls: Cell<u64>,
    }

    impl<'a> Counting<'a> {
        fn new(k: &'a CcmKey) -> Self {
            Self {
                inner: &k.schedule,
                calls: Cell::new(0),
            }
        }
    }

    impl BlockCipher for Counting<'_> {
        fn encrypt_block_with(
            &self,
            started: &SelfTestStarted,
            block: &mut [u8; 16],
        ) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            self.inner.encrypt_block_with(started, block)
        }
        fn decrypt_block_with(
            &self,
            started: &SelfTestStarted,
            block: &mut [u8; 16],
        ) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            self.inner.decrypt_block_with(started, block)
        }
    }

    /// The block-cipher calls a successful encryption of `pt` makes.
    fn encrypt_calls(k: &CcmKey, aad: &[u8], pt: &[u8]) -> u64 {
        let cipher = Counting::new(k);
        let mut ct = std::vec![0u8; pt.len()];
        let mut tag = std::vec![0u8; k.tag_len()];
        ccm_encrypt_core(&cipher, &NONCE, aad, pt, &mut ct, &mut tag).unwrap();
        cipher.calls.get()
    }

    /// The block-cipher calls a successful decryption of `ct` makes.
    fn decrypt_calls(k: &CcmKey, aad: &[u8], ct: &[u8], tag: &[u8]) -> u64 {
        let cipher = Counting::new(k);
        let mut out = std::vec![0u8; ct.len()];
        ccm_decrypt_core(&cipher, &NONCE, aad, ct, tag, &mut out).unwrap();
        cipher.calls.get()
    }

    /// Encrypts `pt` under `k`, returning the ciphertext and the tag.
    fn seal(k: &CcmKey, aad: &[u8], pt: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut ct = std::vec![0u8; pt.len()];
        let mut tag = std::vec![0u8; k.tag_len()];
        ccm_encrypt(k, &NONCE, aad, pt, &mut ct, &mut tag).unwrap();
        (ct, tag)
    }

    /// The decrypted payload reaches the caller's buffer only after the
    /// tag has compared equal, and never on a mismatch; the 16-byte locals
    /// holding MAC state or decrypted payload are wiped on both exits.
    /// Each case runs in a process of its own so that the counters it
    /// reads count only its own decryption.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn ccm_decrypt_writes_nothing_before_tag_check() {
        use crate::observe::seam::writes;
        use crate::wipe::{WipedBuffer, seam::wipes};

        crate::test_support::isolated(
            "ccm::tests::ccm_decrypt_writes_nothing_before_tag_check",
            &["matching", "mismatching"],
            |setting| {
                crate::test_support::start_module();
                let k = CcmKey::new(&KEY, 16).unwrap();
                let pt = [0x3cu8; 37];
                let (ct, mut tag) = seal(&k, b"header", &pt);
                if setting == "mismatching" {
                    tag[15] ^= 0x80;
                }
                assert_eq!(writes(), (0, 0));
                let mut out = [SENTINEL; 37];
                let result = ccm_decrypt(&k, &NONCE, b"header", &ct, &tag, &mut out);
                if setting == "matching" {
                    assert_eq!(result, Ok(()));
                    assert_eq!(writes(), (0, 37), "written before the tag check");
                    assert_eq!(out, pt);
                } else {
                    assert_eq!(result, Err(ModeError::TagMismatch));
                    assert_eq!(writes(), (0, 0), "written on a mismatch");
                    assert_eq!(out, [SENTINEL; 37]);
                }
                assert_eq!(wipes(WipedBuffer::CcmMacState), 1, "{setting}");
                assert_eq!(wipes(WipedBuffer::CcmBlock), 3, "{setting}");
            },
        );
    }

    /// Every validity fault of a decryption's input returns
    /// `TagMismatch` with the output unwritten, while the caller's buffer
    /// errors and encryption's errors stay distinct. A ciphertext shorter
    /// than the tag has no form here, since the tag is passed apart from
    /// the ciphertext and its length is checked against the key.
    #[test]
    fn ccm_decrypt_one_error_for_all_invalid_inputs() {
        crate::test_support::start_module();
        let k = CcmKey::new(&KEY, 16).unwrap();
        let (ct, tag) = seal(&k, b"aad", &[0x77u8; 20]);
        let mut out = [SENTINEL; 20];
        for nonce_len in [0, 6, 14, 16] {
            let nonce = [0x1cu8; 16];
            assert_eq!(
                ccm_decrypt(&k, &nonce[..nonce_len], b"aad", &ct, &tag, &mut out),
                Err(ModeError::TagMismatch),
                "nonce length {nonce_len}"
            );
        }
        // A 13-byte nonce leaves a 2-byte length field, so 2^16 bytes of
        // payload cannot be represented.
        let long = std::vec![0u8; 1 << 16];
        let mut long_out = std::vec![SENTINEL; 1 << 16];
        assert_eq!(
            ccm_decrypt(&k, &NONCE, b"aad", &long, &tag, &mut long_out),
            Err(ModeError::TagMismatch)
        );
        assert!(long_out.iter().all(|&b| b == SENTINEL));
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 1;
        assert_eq!(
            ccm_decrypt(&k, &NONCE, b"aad", &ct, &bad_tag, &mut out),
            Err(ModeError::TagMismatch)
        );
        assert_eq!(out, [SENTINEL; 20]);

        assert_eq!(
            ccm_decrypt(&k, &NONCE, b"aad", &ct, &tag, &mut out[..19]),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(
            ccm_decrypt(&k, &NONCE, b"aad", &ct, &tag[..15], &mut out),
            Err(ModeError::InvalidTagLength)
        );
        assert_eq!(out, [SENTINEL; 20]);
        assert_eq!(ccm_decrypt(&k, &NONCE, b"aad", &ct, &tag, &mut out), Ok(()));

        let pt = [0x77u8; 20];
        let mut ct_out = [0u8; 20];
        let mut tag_out = [0u8; 16];
        assert_eq!(
            ccm_encrypt(&k, &NONCE[..6], b"aad", &pt, &mut ct_out, &mut tag_out),
            Err(ModeError::InvalidNonceLength)
        );
        let mut long_ct = std::vec![0u8; 1 << 16];
        assert_eq!(
            ccm_encrypt(&k, &NONCE, b"aad", &long, &mut long_ct, &mut tag_out),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(
            ccm_encrypt(&k, &NONCE, b"aad", &pt, &mut ct_out[..19], &mut tag_out),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(
            ccm_encrypt(&k, &NONCE, b"aad", &pt, &mut ct_out, &mut tag_out[..15]),
            Err(ModeError::InvalidTagLength)
        );
    }

    /// Tags shorter than 64 bits are refused at construction, 64 bits
    /// being the shortest accepted.
    #[test]
    fn ccm_key_refuses_short_tag() {
        crate::test_support::start_module();
        for tag_len in [0, 2, 4, 6, 7] {
            assert!(
                matches!(
                    CcmKey::new(&KEY, tag_len),
                    Err(oxicrypt_module::Error::InvalidInput)
                ),
                "{tag_len}"
            );
            assert!(
                CcmKey::new_with_count(&KEY, tag_len, 0).is_err(),
                "{tag_len}"
            );
        }
        let k = CcmKey::new(&KEY, 8).unwrap();
        let (ct, tag) = seal(&k, b"", b"payload");
        assert_eq!(tag.len(), 8);
        let mut out = [0u8; 7];
        assert_eq!(ccm_decrypt(&k, &NONCE, b"", &ct, &tag, &mut out), Ok(()));
        assert_eq!(&out, b"payload");
    }

    /// An empty payload encrypts to the tag alone (`Clen = Tlen`), which
    /// decrypts to an empty payload once the tag verifies. A tag one byte
    /// short of the key's tag length is refused.
    #[test]
    fn ccm_empty_payload_round_trip() {
        crate::test_support::start_module();
        let k = CcmKey::new(&KEY, 16).unwrap();
        let (ct, tag) = seal(&k, b"aad", b"");
        assert!(ct.is_empty());
        assert_eq!(tag.len(), 16);
        assert_eq!(ccm_decrypt(&k, &NONCE, b"aad", &[], &tag, &mut []), Ok(()));
        let mut bad = tag.clone();
        bad[7] ^= 0x10;
        assert_eq!(
            ccm_decrypt(&k, &NONCE, b"aad", &[], &bad, &mut []),
            Err(ModeError::TagMismatch)
        );
        assert_eq!(
            ccm_decrypt(&k, &NONCE, b"aad", &[], &tag[..15], &mut []),
            Err(ModeError::InvalidTagLength)
        );
    }

    /// Each operation is charged the block-cipher calls that a successful
    /// operation of its direction and lengths makes, counted through
    /// [`Counting`]: with no AAD, with AAD under each length encoding,
    /// with an empty payload, with a partial block, on a failed
    /// decryption and on an invalid input. The caller's buffer errors
    /// spend nothing.
    #[test]
    fn ccm_invocation_accounting() {
        crate::test_support::start_module();
        let k = CcmKey::new(&KEY, 16).unwrap();
        let mut spent = 0u64;
        let mut charge = |k: &CcmKey| {
            let now = k.invocations();
            let delta = now - spent;
            spent = now;
            delta
        };

        let pt = [1u8; 32];
        let (ct, tag) = seal(&k, b"", &pt);
        assert_eq!(charge(&k), encrypt_calls(&k, b"", &pt), "encrypt, no AAD");
        let mut out = [0u8; 32];
        ccm_decrypt(&k, &NONCE, b"", &ct, &tag, &mut out).unwrap();
        assert_eq!(
            charge(&k),
            decrypt_calls(&k, b"", &ct, &tag),
            "decrypt, no AAD"
        );

        let aad2 = [2u8; 15];
        let pt = [3u8; 5];
        let (ct, tag) = seal(&k, &aad2, &pt);
        assert_eq!(
            charge(&k),
            encrypt_calls(&k, &aad2, &pt),
            "2-byte AAD encoding, partial block"
        );
        let mut out = [0u8; 5];
        ccm_decrypt(&k, &NONCE, &aad2, &ct, &tag, &mut out).unwrap();
        let full = decrypt_calls(&k, &aad2, &ct, &tag);
        assert_eq!(charge(&k), full, "decrypt, partial block");
        let mut bad = tag.clone();
        bad[3] ^= 4;
        assert_eq!(
            ccm_decrypt(&k, &NONCE, &aad2, &ct, &bad, &mut out),
            Err(ModeError::TagMismatch)
        );
        assert_eq!(charge(&k), full, "failed decryption");
        assert_eq!(
            ccm_decrypt(&k, &NONCE[..6], &aad2, &ct, &tag, &mut out),
            Err(ModeError::TagMismatch)
        );
        assert_eq!(charge(&k), full, "invalid input");

        let aad6 = std::vec![6u8; 0xff00];
        let (ct, tag) = seal(&k, &aad6, b"");
        assert_eq!(
            charge(&k),
            encrypt_calls(&k, &aad6, b""),
            "6-byte AAD encoding, empty payload"
        );
        ccm_decrypt(&k, &NONCE, &aad6, &ct, &tag, &mut []).unwrap();
        assert_eq!(
            charge(&k),
            decrypt_calls(&k, &aad6, &ct, &tag),
            "decrypt, empty payload"
        );

        // A 2^32-byte AAD is too large to pass, so the charge of the
        // 10-byte encoding is reserved directly; its length does not fit a
        // 32-bit `usize`, so the case runs on 64-bit targets only.
        #[cfg(target_pointer_width = "64")]
        {
            let cost = super::invocation_cost(1 << 32, 0, super::Direction::Encrypt);
            assert_eq!(cost, 268_435_459);
            k.reserve_invocations(cost).unwrap();
            assert_eq!(charge(&k), 268_435_459, "10-byte AAD encoding");
        }

        let before = k.invocations();
        let mut out = [0u8; 5];
        assert_eq!(
            ccm_decrypt(&k, &NONCE, &aad2, &ct, &tag, &mut out[..4]),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(
            ccm_decrypt(&k, &NONCE, &aad2, &ct, &tag[..8], &mut out),
            Err(ModeError::InvalidTagLength)
        );
        let mut tag_out = [0u8; 16];
        assert_eq!(
            ccm_encrypt(&k, &NONCE, &aad2, &[0u8; 5], &mut out[..4], &mut tag_out),
            Err(ModeError::LengthMismatch)
        );
        assert_eq!(k.invocations(), before);
    }

    /// A key preloaded to 2^61 less one operation's invocations performs
    /// that operation and refuses the next with its output untouched and
    /// its count unchanged, in each direction; a preload above 2^61 is
    /// refused.
    #[test]
    fn ccm_key_exhausts_at_2_61() {
        crate::test_support::start_module();
        let pt = [9u8; 16];
        let probe = CcmKey::new(&KEY, 16).unwrap();
        let cost = encrypt_calls(&probe, b"", &pt);
        let k = CcmKey::new_with_count(&KEY, 16, LIMIT - cost).unwrap();
        let (ct, tag) = seal(&k, b"", &pt);
        assert_eq!(k.invocations(), LIMIT);
        let decrypt_cost = decrypt_calls(&probe, b"", &ct, &tag);

        let mut ct_out = [SENTINEL; 16];
        let mut tag_out = [SENTINEL; 16];
        assert_eq!(
            ccm_encrypt(&k, &NONCE, b"", &pt, &mut ct_out, &mut tag_out),
            Err(EXHAUSTED)
        );
        assert_eq!((ct_out, tag_out), ([SENTINEL; 16], [SENTINEL; 16]));
        let mut out = [SENTINEL; 16];
        assert_eq!(
            ccm_decrypt(&k, &NONCE, b"", &ct, &tag, &mut out),
            Err(EXHAUSTED)
        );
        assert_eq!(out, [SENTINEL; 16]);
        assert_eq!(k.invocations(), LIMIT);

        let exact = CcmKey::new_with_count(&KEY, 16, LIMIT - decrypt_cost).unwrap();
        assert_eq!(
            ccm_decrypt(&exact, &NONCE, b"", &ct, &tag, &mut out),
            Ok(())
        );
        assert_eq!(out, pt);
        assert_eq!(exact.invocations(), LIMIT);

        let mut out = [SENTINEL; 16];
        let short = CcmKey::new_with_count(&KEY, 16, LIMIT - decrypt_cost + 1).unwrap();
        assert_eq!(
            ccm_decrypt(&short, &NONCE, b"", &ct, &tag, &mut out),
            Err(EXHAUSTED)
        );
        assert_eq!(out, [SENTINEL; 16]);
        assert_eq!(short.invocations(), LIMIT - decrypt_cost + 1);

        assert!(matches!(
            CcmKey::new_with_count(&KEY, 16, LIMIT + 1),
            Err(oxicrypt_module::Error::InvalidInput)
        ));
        assert_eq!(
            CcmKey::new_with_count(&KEY, 16, LIMIT)
                .unwrap()
                .invocations(),
            LIMIT
        );
    }

    /// A nonce length outside 7 to 13 and a payload too long for the
    /// nonce's length field are refused before the encryption is charged,
    /// so the key's count is unchanged.
    #[test]
    fn ccm_encrypt_parameter_error_spends_nothing() {
        crate::test_support::start_module();
        let k = CcmKey::new(&KEY, 16).unwrap();
        let pt = [0x77u8; 20];
        let mut ct = [0u8; 20];
        let mut tag = [0u8; 16];
        for nonce_len in [0, 6, 14] {
            let nonce = [0x1cu8; 14];
            assert_eq!(
                ccm_encrypt(&k, &nonce[..nonce_len], b"aad", &pt, &mut ct, &mut tag),
                Err(ModeError::InvalidNonceLength),
                "{nonce_len}"
            );
            assert_eq!(k.invocations(), 0, "{nonce_len}");
        }
        let long = std::vec![0u8; 1 << 16];
        let mut long_ct = std::vec![0u8; 1 << 16];
        assert_eq!(
            ccm_encrypt(&k, &NONCE, b"aad", &long, &mut long_ct, &mut tag),
            Err(ModeError::InvalidPayloadLength)
        );
        assert_eq!(k.invocations(), 0);
        assert_eq!(
            ccm_encrypt(&k, &NONCE, b"aad", &pt, &mut ct, &mut tag),
            Ok(())
        );
        assert_ne!(k.invocations(), 0);
    }

    /// The associated-data length encoding switches at 2^16 − 2^8 bytes
    /// (SP 800-38C Appendix A.2.2): 0xFEFF bytes take the two-octet
    /// encoding and 0xFF00 bytes the six-octet `0xFFFE` encoding. Each tag
    /// of an empty payload is checked against a CBC-MAC computed here over
    /// B0 and the associated data formatted with the expected encoding, the
    /// tag decrypts, and each direction is charged the invocations of that
    /// encoding's block count.
    #[test]
    fn ccm_aad_length_encoding_boundary() {
        crate::test_support::start_module();
        let started = oxicrypt_module::require_self_test_started_token().unwrap();
        let k = CcmKey::new(&KEY, 16).unwrap();
        let cases: [(usize, &[u8]); 2] = [
            (0xFEFF, &[0xFE, 0xFF]),
            (0xFF00, &[0xFF, 0xFE, 0x00, 0x00, 0xFF, 0x00]),
        ];
        for (aad_len, encoding) in cases {
            let aad = std::vec![0x5du8; aad_len];
            let mut formatted = encoding.to_vec();
            formatted.extend_from_slice(&aad);
            formatted.resize(formatted.len().div_ceil(16) * 16, 0);

            // B0: Adata, t = 16 and q = 2 give the flags 0x79; Q = 0.
            let mut y = [0u8; 16];
            y[0] = 0x79;
            y[1..14].copy_from_slice(&NONCE);
            k.schedule.encrypt_block_with(&started, &mut y).unwrap();
            for block in formatted.chunks_exact(16) {
                for (a, b) in y.iter_mut().zip(block) {
                    *a ^= b;
                }
                k.schedule.encrypt_block_with(&started, &mut y).unwrap();
            }
            let mut s0 = [0u8; 16];
            s0[0] = 0x01;
            s0[1..14].copy_from_slice(&NONCE);
            k.schedule.encrypt_block_with(&started, &mut s0).unwrap();
            let expected: Vec<u8> = y.iter().zip(&s0).map(|(a, b)| a ^ b).collect();

            let before = k.invocations();
            let (ct, tag) = seal(&k, &aad, b"");
            assert_eq!(tag, expected, "{aad_len:#x}");
            let blocks = (formatted.len() / 16) as u64;
            assert_eq!(k.invocations() - before, 1 + blocks + 1, "{aad_len:#x}");
            assert_eq!(
                ccm_decrypt(&k, &NONCE, &aad, &ct, &tag, &mut []),
                Ok(()),
                "{aad_len:#x}"
            );
            assert_eq!(
                k.invocations() - before,
                2 * (1 + blocks + 1),
                "{aad_len:#x}"
            );
        }
    }

    /// The AAD bound is inclusive: `CCM_MAX_AAD_LEN` bytes are accepted and
    /// one more is refused with `InvalidAadLength`.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn validate_params_aad_bound() {
        let max = usize::try_from(super::CCM_MAX_AAD_LEN).unwrap();
        assert_eq!(super::validate_params(13, max, 0, 16), Ok(()));
        assert_eq!(
            super::validate_params(13, max.checked_add(1).unwrap(), 0, 16),
            Err(ModeError::InvalidAadLength)
        );
    }
}
