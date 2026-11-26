//! AES-CMAC per NIST SP 800-38B.
//!
//! # Scope
//!
//! Implements CMAC with AES-128 / AES-192 / AES-256 as the underlying
//! block cipher. This is the MAC-only construction defined in
//! SP 800-38B; the CBC-MAC variants referenced from other NIST
//! documents are not in scope here.
//!
//! The implementation is a direct transcription of the algorithms in
//! SP 800-38B:
//!
//!   * **Subkey generation** (§6.1 "Subkey Generation Algorithm"):
//!     L = CIPH_K(0^128); K1 = L · x; K2 = L · x^2, with the left
//!     shift and the XOR of the block-size-specific constant
//!     R_b = 0x87 for 128-bit blocks, masked by the shifted-out bit.
//!   * **MAC generation** (§6.2 "MAC Generation Algorithm"):
//!     split the message into n 128-bit blocks (with zero-padding of
//!     the final block if needed, including for the empty message),
//!     XOR the final block with K1 (if the last block was complete)
//!     or K2 (if it was padded), and CBC-MAC with IV = 0^128. The
//!     tag is the final CBC output truncated to Tlen.
//!   * **MAC verification** (§6.3 "Verification Algorithm"): recompute
//!     the tag and compare its leftmost Tlen bits with the received MAC.
//!
//! SP 800-38B Appendix A recommends a Tlen of at least 64 bits, and
//! permits less only with a documented risk analysis. A [`CmacKey`]
//! fixes its MAC length at construction, between 8 and 16 bytes;
//! [`cmac()`] returns the full tag truncated to that length and
//! [`cmac_verify()`] accepts a MAC of exactly that length.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop
)]

use core::mem::MaybeUninit;

use oxicrypt_aes::{BlockCipher, EcbKey, ModeError};
use oxicrypt_module::{
    Error, SelfTestStarted, Service, require_allowed, require_operational,
    require_self_test_started, require_self_test_started_token,
};

use crate::wipe::{WipedBlock, WipedBuffer};

/// AES block size in bytes. Always 16 for AES.
pub const BLOCK_SIZE: usize = 16;

/// Rb constant for 128-bit blocks, SP 800-38B §5.3 (R128 = 0^120 10000111).
const RB_128: u8 = 0x87;

/// The shortest MAC length a key accepts, in bytes: the 64 bits
/// SP 800-38B Appendix A recommends as the minimum.
const MAC_LEN_MIN: usize = 8;

/// An AES key bound to CMAC (SP 800-38B), with its subkeys and its MAC
/// length.
///
/// SP 800-38B Appendix B recommends authenticating at most 2^48
/// messages under one key; the key does not count them, so the caller
/// keeps to that figure.
///
/// The AES schedule, K1 and K2 are wiped when the key is dropped, the
/// schedule by the `Drop` of the `oxicrypt-aes` round-key types
/// (`block.rs`). They are derived where the key holds them. The hidden
/// constructor `CmacKey::new_in_place` builds the key in a slot the
/// caller provides, so the key is never moved and the copy dropped is the
/// only one. A copy the compiler makes under optimisation is outside what
/// the module can observe, as the crate's Sensitive security parameters
/// section states.
///
/// ```compile_fail,E0599
/// let k = oxicrypt_cmac::CmacKey::new(&[0u8; 16], 16).unwrap();
/// let k2 = k.clone();
/// ```
pub struct CmacKey {
    cipher: EcbKey,
    k1: WipedBlock,
    k2: WipedBlock,
    mac_len: usize,
    service: Service,
}

impl CmacKey {
    /// Builds a CMAC key from 16, 24 or 32 bytes of key material, with a
    /// MAC length of `mac_len` bytes, from 8 to 16.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless the module is
    /// `Operational`, [`Error::InvalidInput`] unless `key` is 16, 24 or 32
    /// bytes and `mac_len` is in `8..=16`, and
    /// [`Error::AlgorithmRestricted`] when the active profile does not
    /// permit CMAC at that key size.
    ///
    /// The key is returned by value; a copy of the schedule, K1 and K2
    /// that the move leaves behind is not zeroized.
    pub fn new(key: &[u8], mac_len: usize) -> Result<Self, Error> {
        require_operational()?;
        require_allowed(service_for(key.len())?)?;
        Self::new_ungated(key, mac_len)
    }

    /// Builds the key as [`Self::new`] does, in `slot`, and returns a
    /// reference to it there: the schedule, K1 and K2 are derived where
    /// the key will stay, so the key is never moved.
    ///
    /// `slot` is treated as uninitialised; a value already in it is
    /// overwritten without being dropped. On success the caller owns the
    /// initialised value and must run its destructor in place, which
    /// zeroizes the schedule, K1 and K2. A `MaybeUninit` runs no destructor
    /// of its own, so the caller embeds the slot in a type whose `Drop`
    /// runs the value's, as the C key handle does, or calls
    /// `MaybeUninit::assume_init_drop`; a slot left without its destructor
    /// run leaves the schedule and subkeys unwiped. On an error the slot
    /// holds no key material: it is either unwritten or holds a key whose
    /// schedule and subkeys are zero, which needs no drop.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::new`].
    #[doc(hidden)]
    pub fn new_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
        mac_len: usize,
    ) -> Result<&'a mut Self, Error> {
        require_operational()?;
        require_allowed(service_for(key.len())?)?;
        let k = slot.write(Self::zeroed(key.len(), mac_len)?);
        k.derive_or_clear(key)?;
        Ok(k)
    }

    /// Derives the key from `key` where `self` lies, or, on an error,
    /// replaces `self` with a key whose schedule, K1 and K2 are zero.
    /// Assigning drops the partly derived key, which wipes it.
    fn derive_or_clear(&mut self, key: &[u8]) -> Result<(), Error> {
        if let Err(e) = self.derive(key) {
            if let Ok(blank) = Self::zeroed(key.len(), self.mac_len) {
                *self = blank;
            }
            return Err(e);
        }
        Ok(())
    }

    /// [`Self::new`] without the service gates, for the power-up
    /// self-tests.
    pub(crate) fn new_ungated(key: &[u8], mac_len: usize) -> Result<Self, Error> {
        let mut k = Self::zeroed(key.len(), mac_len)?;
        k.derive(key)?;
        Ok(k)
    }

    /// A key for `len` bytes of key material and a MAC length of
    /// `mac_len`, its schedule, K1 and K2 all zero.
    fn zeroed(len: usize, mac_len: usize) -> Result<Self, Error> {
        let service = service_for(len)?;
        if !(MAC_LEN_MIN..=BLOCK_SIZE).contains(&mac_len) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            cipher: EcbKey::zeroed(len)?,
            k1: WipedBlock::new(WipedBuffer::K1),
            k2: WipedBlock::new(WipedBuffer::K2),
            mac_len,
            service,
        })
    }

    /// Expands `key` into the schedule and derives K1 and K2 from it, all
    /// where `self` lies.
    fn derive(&mut self, key: &[u8]) -> Result<(), Error> {
        let started = require_self_test_started_token()?;
        self.cipher.expand_in_place(key)?;
        #[cfg(feature = "fault-injection")]
        crate::seam::after_expansion();
        derive_subkeys(
            &self.cipher,
            &started,
            &mut self.k1.bytes,
            &mut self.k2.bytes,
        )
    }

    /// The MAC length in bytes, from 8 to 16, fixed at construction: the
    /// length [`cmac()`] writes and [`cmac_verify()`] compares.
    pub const fn mac_len(&self) -> usize {
        self.mac_len
    }

    /// The subkeys K1 and K2.
    #[cfg(test)]
    pub(crate) const fn subkeys(&self) -> (&[u8; BLOCK_SIZE], &[u8; BLOCK_SIZE]) {
        (&self.k1.bytes, &self.k2.bytes)
    }
}

/// The CMAC service for a key of `len` bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] unless `len` is 16, 24 or 32.
const fn service_for(len: usize) -> Result<Service, Error> {
    match len {
        16 => Ok(Service::CmacAes128),
        24 => Ok(Service::CmacAes192),
        32 => Ok(Service::CmacAes256),
        _ => Err(Error::InvalidInput),
    }
}

/// Derive the CMAC subkeys K1 and K2 from a block cipher into `k1` and
/// `k2`.
///
/// Follows SP 800-38B §6.1 exactly: L = CIPH_K(0^128), then
/// K1 = L · x and K2 = L · x^2 in GF(2^128) with the polynomial
/// x^128 + x^7 + x^2 + x + 1 (so multiplication by x is a 1-bit left
/// shift, XOR'd with R_b = 0x87 if the high bit was set). L is a secret
/// of SP 800-38B §6.1, so it is held in storage that wipes it when the
/// function returns.
fn derive_subkeys<B: BlockCipher>(
    cipher: &B,
    started: &SelfTestStarted,
    k1: &mut [u8; BLOCK_SIZE],
    k2: &mut [u8; BLOCK_SIZE],
) -> Result<(), Error> {
    let mut l = WipedBlock::new(WipedBuffer::L);
    cipher.encrypt_block_with(started, &mut l.bytes)?;
    shift_with_rb(&l.bytes, k1);
    shift_with_rb(k1, k2);
    Ok(())
}

/// The subkeys K1 = L · x and K2 = K1 · x of SP 800-38B §6.1 steps 2 to
/// 4, from a given `l`, into `k1` and `k2`, for the constant-time harness.
///
/// Not a service of the module: it takes L directly, so that the timing
/// of the doubling can be measured on chosen values of L, and it is
/// hidden from the documented API.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] unless
/// [`oxicrypt_module::require_self_test_started`] admits the call: in
/// `Operational`, or in `SelfTest` on the thread running the power-up
/// self-tests.
#[doc(hidden)]
pub fn subkeys_from_l_internal(
    l: &[u8; BLOCK_SIZE],
    k1: &mut [u8; BLOCK_SIZE],
    k2: &mut [u8; BLOCK_SIZE],
) -> Result<(), Error> {
    require_self_test_started()?;
    shift_with_rb(l, k1);
    shift_with_rb(k1, k2);
    Ok(())
}

/// Multiply a 128-bit block by `x` in GF(2^128) with the GCM/CMAC
/// polynomial (big-endian bit order per SP 800-38B §5.3), writing the
/// product to `out`.
fn shift_with_rb(b: &[u8; BLOCK_SIZE], out: &mut [u8; BLOCK_SIZE]) {
    let msb = b[0] >> 7;
    let mut carry: u8 = 0;
    let mut i = BLOCK_SIZE;
    while i > 0 {
        i -= 1;
        out[i] = (b[i] << 1) | carry;
        carry = b[i] >> 7;
    }
    // R_b is applied under a mask of all ones or all zeros rather than a
    // branch, because the high bit is a bit of the secret L or K1. The
    // mask passes through `black_box` because without it the compiler can
    // turn the masked XOR back into a branch on the high bit.
    out[BLOCK_SIZE - 1] ^= RB_128 & core::hint::black_box(0u8.wrapping_sub(msb));
}

/// Compute an AES-CMAC tag over `message` (SP 800-38B §6.2) into
/// `mac_out`, which must be the key's MAC length: the full 128-bit tag
/// truncated to its leftmost `mac_out.len()` bytes.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit CMAC at the key's size; and
/// [`ModeError::LengthMismatch`] when `mac_out` is not the key's MAC
/// length.
pub fn cmac(key: &CmacKey, message: &[u8], mac_out: &mut [u8]) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.service)?;
    if mac_out.len() != key.mac_len {
        return Err(ModeError::LengthMismatch);
    }
    let mut state = WipedBlock::new(WipedBuffer::MacState);
    cmac_core(key, message, &mut state.bytes)?;
    mac_out.copy_from_slice(&state.bytes[..key.mac_len]);
    Ok(())
}

/// Verify `mac` as the AES-CMAC of `message` under `key` (SP 800-38B
/// §6.3): recompute the tag and compare its leftmost `mac.len()` bytes
/// with `mac`, which must be the key's MAC length.
///
/// The comparison reads every byte and does not stop at the first
/// difference. The `cmac_verify` target of the constant-time harness
/// `tools/ct-validation` measures that the time of a refused MAC does not
/// depend on where it differs from the tag; nothing else about the
/// comparison's timing is measured.
///
/// # Errors
///
/// Returns [`ModeError::Module`] carrying [`Error::NotOperational`] unless
/// the module is `Operational`, or [`Error::AlgorithmRestricted`] when the
/// active profile does not permit CMAC at the key's size;
/// [`ModeError::InvalidTagLength`] when `mac` is not the key's MAC length;
/// and [`ModeError::TagMismatch`] when `mac` is not the tag.
pub fn cmac_verify(key: &CmacKey, message: &[u8], mac: &[u8]) -> Result<(), ModeError> {
    require_operational()?;
    require_allowed(key.service)?;
    if mac.len() != key.mac_len {
        return Err(ModeError::InvalidTagLength);
    }
    let mut state = WipedBlock::new(WipedBuffer::MacState);
    cmac_core(key, message, &mut state.bytes)?;
    if ct_eq(&state.bytes[..key.mac_len], mac) {
        Ok(())
    } else {
        Err(ModeError::TagMismatch)
    }
}

/// Whether `a` and `b`, of equal length, are equal, accumulating the
/// difference of every byte with no early exit. The difference is the
/// XOR of the computed tag with the MAC, so it is held in storage that
/// wipes it.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = WipedBlock::new(WipedBuffer::TagDiff);
    for (x, y) in a.iter().zip(b) {
        diff.bytes[0] |= x ^ y;
    }
    diff.bytes[0] == 0
}

/// The full 128-bit CMAC tag of `msg` under `key` into `c`, the CBC-MAC
/// state, without the service gates. The caller holds `c` in storage
/// that wipes it.
fn cmac_core(key: &CmacKey, msg: &[u8], c: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
    let started = require_self_test_started_token()?;
    let cipher = &key.cipher;

    let complete_last = !msg.is_empty() && msg.len() % BLOCK_SIZE == 0;
    let n = if msg.is_empty() {
        1
    } else {
        msg.len().div_ceil(BLOCK_SIZE)
    };

    // CBC-MAC with IV = 0.
    *c = [0u8; BLOCK_SIZE];
    for i in 0..n - 1 {
        let start = i * BLOCK_SIZE;
        for k in 0..BLOCK_SIZE {
            c[k] ^= msg[start + k];
        }
        cipher.encrypt_block_with(&started, c)?;
    }

    // Final block M_n*: last 16 bytes of msg if complete_last, else
    // the trailing bytes padded with 0x80 0x00* to 16 bytes.
    let mut final_block = WipedBlock::new(WipedBuffer::FinalBlock);
    let m_n = &mut final_block.bytes;
    if complete_last {
        let start = (n - 1) * BLOCK_SIZE;
        m_n.copy_from_slice(&msg[start..start + BLOCK_SIZE]);
        for k in 0..BLOCK_SIZE {
            m_n[k] ^= key.k1.bytes[k];
        }
    } else {
        let start = (n - 1) * BLOCK_SIZE;
        let rem = msg.len() - start;
        m_n[..rem].copy_from_slice(&msg[start..]);
        m_n[rem] = 0x80;
        for k in 0..BLOCK_SIZE {
            m_n[k] ^= key.k2.bytes[k];
        }
    }

    for k in 0..BLOCK_SIZE {
        c[k] ^= m_n[k];
    }
    cipher.encrypt_block_with(&started, c)?;
    Ok(())
}

/// The full CMAC tag of `msg` under `key`, built and computed without
/// the service gates as the power-up self-tests run them.
pub(crate) fn full_tag(key: &[u8], msg: &[u8]) -> Result<[u8; BLOCK_SIZE], Error> {
    let k = CmacKey::new_ungated(key, BLOCK_SIZE)?;
    let mut state = WipedBlock::new(WipedBuffer::MacState);
    cmac_core(&k, msg, &mut state.bytes)?;
    Ok(state.bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{BLOCK_SIZE, CmacKey, full_tag, shift_with_rb, subkeys_from_l_internal};

    /// K1 and K2 of the SP 800-38B §D.1 AES-128 and §D.3 AES-256
    /// examples, both from the key and from the example's L. AES-128's L
    /// has its top bit clear and its K1 has it set; AES-256's L has it
    /// set, so each value of the shifted-out bit reaches the R_b mask.
    #[test]
    fn subkeys_match_sp800_38b_examples() {
        /// An example's name, key, L, K1 and K2.
        type Example = (&'static str, &'static [u8], [u8; 16], [u8; 16], [u8; 16]);

        crate::test_support::start_module();
        let cases: [Example; 2] = [
            (
                "D.1 AES-128",
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ],
                [
                    0x7d, 0xf7, 0x6b, 0x0c, 0x1a, 0xb8, 0x99, 0xb3, 0x3e, 0x42, 0xf0, 0x47, 0xb9,
                    0x1b, 0x54, 0x6f,
                ],
                [
                    0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66, 0x7c, 0x85, 0xe0, 0x8f, 0x72,
                    0x36, 0xa8, 0xde,
                ],
                [
                    0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc, 0xf9, 0x0b, 0xc1, 0x1e, 0xe4,
                    0x6d, 0x51, 0x3b,
                ],
            ),
            (
                "D.3 AES-256",
                &[
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                    0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
                    0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                ],
                [
                    0xe5, 0x68, 0xf6, 0x81, 0x94, 0xcf, 0x76, 0xd6, 0x17, 0x4d, 0x4c, 0xc0, 0x43,
                    0x10, 0xa8, 0x54,
                ],
                [
                    0xca, 0xd1, 0xed, 0x03, 0x29, 0x9e, 0xed, 0xac, 0x2e, 0x9a, 0x99, 0x80, 0x86,
                    0x21, 0x50, 0x2f,
                ],
                [
                    0x95, 0xa3, 0xda, 0x06, 0x53, 0x3d, 0xdb, 0x58, 0x5d, 0x35, 0x33, 0x01, 0x0c,
                    0x42, 0xa0, 0xd9,
                ],
            ),
        ];
        for (name, key, l, k1, k2) in cases {
            let mut from_l = [0u8; BLOCK_SIZE];
            shift_with_rb(&l, &mut from_l);
            assert_eq!(from_l, k1, "K1 from L, {name}");
            let mut from_k1 = [0u8; BLOCK_SIZE];
            shift_with_rb(&k1, &mut from_k1);
            assert_eq!(from_k1, k2, "K2 from K1, {name}");
            let (mut hook_k1, mut hook_k2) = ([0u8; BLOCK_SIZE], [0u8; BLOCK_SIZE]);
            subkeys_from_l_internal(&l, &mut hook_k1, &mut hook_k2).unwrap();
            assert_eq!((hook_k1, hook_k2), (k1, k2), "harness subkeys, {name}");
            let cmac_key = CmacKey::new(key, 16).unwrap();
            assert_eq!(cmac_key.subkeys(), (&k1, &k2), "subkeys of the key, {name}");
        }
    }

    /// The in-place constructor refuses a 15-byte key and a 7-byte MAC
    /// length. A key it builds is constructed, used and freed through the
    /// C key handle, whose free runs the key's destructor in place, so no
    /// test here leaves a built key in a slot without one.
    #[test]
    fn new_in_place_refuses_bad_lengths() {
        crate::test_support::start_module();
        let key = [0x2bu8; 16];
        let mut slot = core::mem::MaybeUninit::uninit();
        assert!(matches!(
            CmacKey::new_in_place(&mut slot, &key[..15], 16),
            Err(oxicrypt_module::Error::InvalidInput)
        ));
        assert!(matches!(
            CmacKey::new_in_place(&mut slot, &key, 7),
            Err(oxicrypt_module::Error::InvalidInput)
        ));
    }

    /// A derivation that fails after the schedule is expanded replaces the
    /// key with one whose K1 and K2 are zero, and the assignment wipes the
    /// partly derived key: its schedule once and K1 and K2 once each. The
    /// failure is a module error injected between the expansion and the
    /// subkey derivation, in a process of its own because the error state
    /// is permanent. `new_in_place` takes the same branch and records the
    /// same wipes.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn derive_failure_leaves_a_zeroed_key() {
        use crate::wipe::{WipedBuffer, seam::wipes};
        use oxicrypt_aes::seam::schedule_wipes;
        use oxicrypt_module::{Error, State};

        crate::test_support::isolated(
            "cmac::tests::derive_failure_leaves_a_zeroed_key",
            &["derive_or_clear", "new_in_place"],
            |setting| {
                crate::test_support::start_module();
                let key = [0x2bu8; 16];
                let mut k = CmacKey::zeroed(16, 12).unwrap();
                let before = (
                    schedule_wipes(),
                    wipes(WipedBuffer::K1),
                    wipes(WipedBuffer::K2),
                );
                crate::seam::error_after_next_expansion();
                let refused = Err(Error::NotOperational {
                    current: State::Error,
                });
                if setting == "derive_or_clear" {
                    assert_eq!(k.derive_or_clear(&key), refused);
                    assert_eq!(k.subkeys(), (&[0u8; 16], &[0u8; 16]));
                    assert_eq!(k.mac_len(), 12);
                } else {
                    let mut slot = core::mem::MaybeUninit::uninit();
                    assert!(matches!(
                        CmacKey::new_in_place(&mut slot, &key, 12),
                        Err(Error::NotOperational { .. })
                    ));
                }
                let after = (
                    schedule_wipes(),
                    wipes(WipedBuffer::K1),
                    wipes(WipedBuffer::K2),
                );
                assert_eq!(
                    (after.0 - before.0, after.1 - before.1, after.2 - before.2),
                    (1, 1, 1),
                    "{setting}"
                );
            },
        );
    }

    // NIST CMAC examples, AES-128 — Mlen = 0
    #[test]
    fn sp38b_d1_example1_aes128_empty() {
        crate::test_support::start_module();
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let expected: [u8; 16] = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ];
        assert_eq!(full_tag(&key, &[]).unwrap(), expected);
    }

    // NIST CMAC examples, AES-128 — Mlen = 128
    #[test]
    fn sp38b_d1_example2_aes128_one_block() {
        crate::test_support::start_module();
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let msg: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        assert_eq!(full_tag(&key, &msg).unwrap(), expected);
    }

    // NIST CMAC examples, AES-192 — Mlen = 512
    #[test]
    fn sp38b_d2_example4_aes192_four_blocks() {
        crate::test_support::start_module();
        let key: [u8; 24] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let msg: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected: [u8; 16] = [
            0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79, 0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3,
            0x9a, 0x11,
        ];
        assert_eq!(full_tag(&key, &msg).unwrap(), expected);
    }

    // NIST CMAC examples, AES-256 — Mlen = 320
    // (Partial final block — exercises the K2 subkey path.)
    #[test]
    fn sp38b_d3_example3_aes256_partial_block() {
        crate::test_support::start_module();
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let msg: [u8; 40] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let expected: [u8; 16] = [
            0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2, 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9,
            0x11, 0xe6,
        ];
        assert_eq!(full_tag(&key, &msg).unwrap(), expected);
    }

    /// L is wiped once at construction, K1 and K2 when the key is
    /// dropped, the CBC-MAC state and the masked final block on each
    /// call of [`crate::cmac()`] and [`crate::cmac_verify()`], a failing
    /// verification included, and the tag difference on each
    /// verification; a call refused for its MAC length wipes nothing. The
    /// test counts `wipe` calls per identity, not zeroed bytes.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn subkeys_zeroized_on_all_paths() {
        use crate::wipe::{WipedBuffer, seam::wipes};
        use crate::{CmacKey, cmac, cmac_verify};
        use oxicrypt_aes::ModeError;

        /// The secret intermediates of SP 800-38B §6.1 to §6.3.
        const IDENTITIES: [WipedBuffer; 6] = [
            WipedBuffer::L,
            WipedBuffer::K1,
            WipedBuffer::K2,
            WipedBuffer::MacState,
            WipedBuffer::FinalBlock,
            WipedBuffer::TagDiff,
        ];

        crate::test_support::isolated(
            "cmac::tests::subkeys_zeroized_on_all_paths",
            &["wipes"],
            |_| {
                crate::test_support::start_module();
                let counts = || IDENTITIES.map(wipes);
                let start = counts();
                let mut before = start;
                let mut step = |name: &str, expected: [u64; 6]| {
                    let after = counts();
                    for i in 0..IDENTITIES.len() {
                        assert_eq!(
                            after[i] - before[i],
                            expected[i],
                            "wipes of {:?} after {name}",
                            IDENTITIES[i]
                        );
                    }
                    before = after;
                };

                let key = CmacKey::new(&[0x2b; 16], 16).unwrap();
                step("construction", [1, 0, 0, 0, 0, 0]);
                let mut tag = [0u8; 16];
                cmac(&key, b"message", &mut tag).unwrap();
                step("cmac", [0, 0, 0, 1, 1, 0]);
                assert_eq!(cmac_verify(&key, b"message", &tag), Ok(()));
                step("a verification that passes", [0, 0, 0, 1, 1, 1]);
                let mut short = [0u8; 15];
                assert_eq!(
                    cmac(&key, b"message", &mut short),
                    Err(ModeError::LengthMismatch)
                );
                step("cmac with a wrong MAC length", [0, 0, 0, 0, 0, 0]);
                assert_eq!(
                    cmac_verify(&key, b"message", &tag[..15]),
                    Err(ModeError::InvalidTagLength)
                );
                step("a verification with a wrong MAC length", [0, 0, 0, 0, 0, 0]);
                tag[0] ^= 1;
                assert_eq!(
                    cmac_verify(&key, b"message", &tag),
                    Err(ModeError::TagMismatch)
                );
                step("a verification that fails", [0, 0, 0, 1, 1, 1]);
                drop(key);
                step("drop", [0, 1, 1, 0, 0, 0]);

                let end = counts();
                for i in 0..IDENTITIES.len() {
                    assert!(
                        end[i] > start[i],
                        "{:?} has no recorded wipe",
                        IDENTITIES[i]
                    );
                }
            },
        );
    }
}
