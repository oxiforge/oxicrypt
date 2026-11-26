//! AES block cipher core (FIPS 197).
//!
//! Pure Rust byte-wise S-box reference implementation (no T-tables) of
//! the Rijndael block cipher at the three approved key sizes:
//! AES-128 (Nk=4, Nr=10), AES-192 (Nk=6, Nr=12), AES-256
//! (Nk=8, Nr=14). The block size is fixed at 128 bits (Nb=4).
//!
//! # Scope
//!
//! This module implements only the raw block operation
//! (`encrypt_block` / `decrypt_block` on a single 16-byte state)
//! and the FIPS 197 key schedule. Modes of operation (ECB, CBC,
//! CTR, GCM) live in sibling modules and layer on top of this
//! primitive.
//!
//! # Side-channel posture
//!
//! A full table-based T-box implementation would be faster on
//! modern CPUs but is subject to well-known cache-timing attacks.
//! For a Level 1 software module we prefer the simple byte-wise
//! S-box implementation as the shipping default. The optional
//! `accel-aes` feature (default OFF) dispatches the single-block
//! boundary to `oxicrypt-aes-accel` — AES-NI, runtime-detected via
//! CPUID, fail-portable — whose rounds run in hardware with no table
//! lookups.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::many_single_char_names
)]

use core::mem::MaybeUninit;

use oxicrypt_module::{
    Error, SelfTestStarted, Service, require_allowed, require_operational,
    require_self_test_started, require_self_test_started_token,
};

use crate::wipe::{WipedBuffer, wipe};

/// The ECB services, indexed AES-128, AES-192, AES-256.
pub(crate) const ECB_SERVICES: [Service; 3] =
    [Service::Aes128Ecb, Service::Aes192Ecb, Service::Aes256Ecb];
/// The CBC services, indexed AES-128, AES-192, AES-256.
pub(crate) const CBC_SERVICES: [Service; 3] =
    [Service::Aes128Cbc, Service::Aes192Cbc, Service::Aes256Cbc];
/// The CTR services, indexed AES-128, AES-192, AES-256.
pub(crate) const CTR_SERVICES: [Service; 3] =
    [Service::Aes128Ctr, Service::Aes192Ctr, Service::Aes256Ctr];
/// The GCM services, indexed AES-128, AES-192, AES-256.
pub(crate) const GCM_SERVICES: [Service; 3] =
    [Service::Aes128Gcm, Service::Aes192Gcm, Service::Aes256Gcm];
/// The CCM services, indexed AES-128, AES-192, AES-256.
pub(crate) const CCM_SERVICES: [Service; 3] =
    [Service::Aes128Ccm, Service::Aes192Ccm, Service::Aes256Ccm];
/// The KW services, indexed AES-128, AES-192, AES-256.
pub(crate) const KW_SERVICES: [Service; 3] =
    [Service::Aes128Kw, Service::Aes192Kw, Service::Aes256Kw];
/// The KWP services, indexed AES-128, AES-192, AES-256.
pub(crate) const KWP_SERVICES: [Service; 3] =
    [Service::Aes128Kwp, Service::Aes192Kwp, Service::Aes256Kwp];

/// AES block size in bytes. Rijndael allows other sizes; AES fixes
/// `Nb = 4` (128-bit block).
pub const BLOCK_SIZE: usize = 16;

/// Forward S-box (FIPS 197 §5.1.1 figure 7).
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Inverse S-box (FIPS 197 §5.3.2 figure 14).
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Round constants for the key schedule (FIPS 197 §5.2). Rcon[i] is
/// the round constant for the i-th round of key expansion (1-indexed
/// in the spec; we store index 0 unused for cheap lookup).
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// Multiply `a` by `b` in GF(2^8) with the AES reduction polynomial
/// `0x11b` (FIPS 197 §4.2), for the MixColumns and InvMixColumns
/// constants.
///
/// `a` is a byte of the cipher state, so the XOR of `x` into the product
/// and the reduction of `xtime` on the high bit of `x` are applied under
/// masks of all ones or all zeros, so that no branch depends on the
/// state byte.
#[inline]
fn gmul(a: u8, b: u8) -> u8 {
    let mut r: u8 = 0;
    let mut x = a;
    let mut y = b;
    let mut i = 0;
    while i < 8 {
        r ^= x & 0u8.wrapping_sub(y & 1);
        let reduce = core::hint::black_box(0u8.wrapping_sub(x >> 7));
        x = x.wrapping_shl(1) ^ (0x1b & reduce);
        y >>= 1;
        i += 1;
    }
    r
}

// Round primitives, FIPS 197 §5.1.

#[inline]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

#[inline]
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

#[inline]
fn shift_rows(s: &mut [u8; 16]) {
    // Column-major layout: s[r + 4*c]. Rotate row r left by r.
    let (s1, s5, s9, s13) = (s[1], s[5], s[9], s[13]);
    s[1] = s5;
    s[5] = s9;
    s[9] = s13;
    s[13] = s1;
    let (s2, s6, s10, s14) = (s[2], s[6], s[10], s[14]);
    s[2] = s10;
    s[6] = s14;
    s[10] = s2;
    s[14] = s6;
    let (s3, s7, s11, s15) = (s[3], s[7], s[11], s[15]);
    s[3] = s15;
    s[7] = s3;
    s[11] = s7;
    s[15] = s11;
}

#[inline]
fn inv_shift_rows(s: &mut [u8; 16]) {
    // Inverse: rotate row r right by r.
    let (s1, s5, s9, s13) = (s[1], s[5], s[9], s[13]);
    s[1] = s13;
    s[5] = s1;
    s[9] = s5;
    s[13] = s9;
    let (s2, s6, s10, s14) = (s[2], s[6], s[10], s[14]);
    s[2] = s10;
    s[6] = s14;
    s[10] = s2;
    s[14] = s6;
    let (s3, s7, s11, s15) = (s[3], s[7], s[11], s[15]);
    s[3] = s7;
    s[7] = s11;
    s[11] = s15;
    s[15] = s3;
}

#[inline]
fn mix_columns(s: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        let a0 = s[i];
        let a1 = s[i + 1];
        let a2 = s[i + 2];
        let a3 = s[i + 3];
        s[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        s[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        i += 4;
    }
}

#[inline]
fn inv_mix_columns(s: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        let a0 = s[i];
        let a1 = s[i + 1];
        let a2 = s[i + 2];
        let a3 = s[i + 3];
        s[i] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        s[i + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        s[i + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        s[i + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
        i += 4;
    }
}

/// MixColumns (FIPS 197 §5.1.3) of `state`, for the constant-time
/// harness.
///
/// Not a service of the module: it is reachable only so that the timing
/// of the round step can be measured directly, and it is hidden from the
/// documented API.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
/// admits the call: in `Operational`, or in `SelfTest` on the thread
/// running the power-up self-tests.
#[doc(hidden)]
pub fn mix_columns_internal(state: &mut [u8; 16]) -> Result<(), Error> {
    require_self_test_started()?;
    mix_columns(state);
    Ok(())
}

/// InvMixColumns (FIPS 197 §5.3.3) of `state`, for the constant-time
/// harness.
///
/// Not a service of the module: it is reachable only so that the timing
/// of the round step can be measured directly, and it is hidden from the
/// documented API.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
/// admits the call: in `Operational`, or in `SelfTest` on the thread
/// running the power-up self-tests.
#[doc(hidden)]
pub fn inv_mix_columns_internal(state: &mut [u8; 16]) -> Result<(), Error> {
    require_self_test_started()?;
    inv_mix_columns(state);
    Ok(())
}

#[inline]
fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

// Key expansion, FIPS 197 §5.2.

/// Expand a key of `Nk` 32-bit words (`key`) into `(Nr+1)` round
/// keys of 16 bytes each, written into `out`. `out.len()` must equal
/// `16 * (nr + 1)`.
fn expand_key(key: &[u8], nk: usize, nr: usize, out: &mut [u8]) {
    let total_words = 4 * (nr + 1);
    let key_bytes = 4 * nk;
    out[..key_bytes].copy_from_slice(&key[..key_bytes]);

    let mut i = nk;
    while i < total_words {
        let off = (i - 1) * 4;
        let mut t = [out[off], out[off + 1], out[off + 2], out[off + 3]];

        if i % nk == 0 {
            // RotWord
            t.rotate_left(1);
            // SubWord
            t[0] = SBOX[t[0] as usize];
            t[1] = SBOX[t[1] as usize];
            t[2] = SBOX[t[2] as usize];
            t[3] = SBOX[t[3] as usize];
            // XOR Rcon
            t[0] ^= RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            // Extra SubWord for AES-256.
            t[0] = SBOX[t[0] as usize];
            t[1] = SBOX[t[1] as usize];
            t[2] = SBOX[t[2] as usize];
            t[3] = SBOX[t[3] as usize];
        }

        let prev = (i - nk) * 4;
        let cur = i * 4;
        out[cur] = out[prev] ^ t[0];
        out[cur + 1] = out[prev + 1] ^ t[1];
        out[cur + 2] = out[prev + 2] ^ t[2];
        out[cur + 3] = out[prev + 3] ^ t[3];
        wipe(WipedBuffer::KeyExpansionWord, &mut t);
        i += 1;
    }
}

/// AES-128 expanded key (11 round keys * 16 bytes).
pub(crate) struct Aes128Key {
    rk: [u8; 16 * 11],
}

/// AES-192 expanded key (13 round keys * 16 bytes).
pub(crate) struct Aes192Key {
    rk: [u8; 16 * 13],
}

/// AES-256 expanded key (15 round keys * 16 bytes).
pub(crate) struct Aes256Key {
    rk: [u8; 16 * 15],
}

/// The round-key schedule of one AES key, at one of the three approved
/// key sizes. Every mode-bound key type holds one.
pub(crate) enum KeySchedule {
    Aes128(Aes128Key),
    Aes192(Aes192Key),
    Aes256(Aes256Key),
}

impl KeySchedule {
    /// An all-zero schedule for a key of `len` bytes, which
    /// [`Self::expand`] then fills where it lies.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] unless `len` is 16, 24 or 32.
    pub(crate) const fn zeroed(len: usize) -> Result<Self, Error> {
        match len {
            16 => Ok(Self::Aes128(Aes128Key { rk: [0u8; 16 * 11] })),
            24 => Ok(Self::Aes192(Aes192Key { rk: [0u8; 16 * 13] })),
            32 => Ok(Self::Aes256(Aes256Key { rk: [0u8; 16 * 15] })),
            _ => Err(Error::InvalidInput),
        }
    }

    /// The gates of an approved service, followed by [`Self::zeroed`]:
    /// [`require_operational`], the key length, then [`require_allowed`]
    /// for the entry of `services` that matches the key size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless the module is
    /// `Operational`, [`Error::InvalidInput`] unless `len` is 16, 24 or
    /// 32, and [`Error::AlgorithmRestricted`] when the active profile does
    /// not permit the service.
    pub(crate) fn admit(len: usize, services: [Service; 3]) -> Result<Self, Error> {
        require_operational()?;
        let schedule = Self::zeroed(len)?;
        require_allowed(schedule.service(services))?;
        Ok(schedule)
    }

    /// Expands `key` into this schedule in place (FIPS 197 §5.2).
    ///
    /// `key` has the length the schedule was made for by [`Self::zeroed`].
    pub(crate) fn expand(&mut self, key: &[u8]) {
        match self {
            Self::Aes128(k) => expand_key(key, 4, 10, &mut k.rk),
            Self::Aes192(k) => expand_key(key, 6, 12, &mut k.rk),
            Self::Aes256(k) => expand_key(key, 8, 14, &mut k.rk),
        }
    }

    /// The entry of `services` (ordered AES-128, AES-192, AES-256) for
    /// this key's size.
    pub(crate) const fn service(&self, services: [Service; 3]) -> Service {
        match self {
            Self::Aes128(_) => services[0],
            Self::Aes192(_) => services[1],
            Self::Aes256(_) => services[2],
        }
    }

    /// The expanded round keys and the round count `Nr`.
    pub(crate) fn round_keys(&self) -> (&[u8], usize) {
        match self {
            Self::Aes128(k) => (&k.rk, 10),
            Self::Aes192(k) => (&k.rk, 12),
            Self::Aes256(k) => (&k.rk, 14),
        }
    }

    /// Encrypts a single 16-byte block in place.
    ///
    /// The module state is checked again on every call, so a proof
    /// obtained before the module entered the error state drives no
    /// further blocks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`require_self_test_started`] admits the call: in `Operational`, or
    /// in `SelfTest` on the thread running the power-up self-tests.
    pub(crate) fn encrypt_block_with(
        &self,
        _started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error> {
        require_self_test_started()?;
        let (rk, nr) = self.round_keys();
        #[cfg(feature = "accel-aes")]
        if oxicrypt_aes_accel::encrypt_block(rk, nr, block) {
            return Ok(());
        }
        encrypt_block_generic(block, rk, nr);
        Ok(())
    }

    /// Decrypts a single 16-byte block in place, with the state check of
    /// [`Self::encrypt_block_with`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`require_self_test_started`] admits the call.
    pub(crate) fn decrypt_block_with(
        &self,
        _started: &SelfTestStarted,
        block: &mut [u8; 16],
    ) -> Result<(), Error> {
        require_self_test_started()?;
        let (rk, nr) = self.round_keys();
        #[cfg(feature = "accel-aes")]
        if oxicrypt_aes_accel::decrypt_block(rk, nr, block) {
            return Ok(());
        }
        decrypt_block_generic(block, rk, nr);
        Ok(())
    }
}

/// An AES key for the raw block cipher (FIPS 197), with no mode.
///
/// This is the block cipher the power-up self-tests, CTR_DRBG and CMAC
/// run on, and the key of [`crate::ecb_encrypt`] and
/// [`crate::ecb_decrypt`]. Its constructor is a non-service interface: it
/// applies no algorithm-profile gate and admits the self-test state.
///
/// ```compile_fail,E0599
/// let k = oxicrypt_aes::EcbKey::new(&[0u8; 16]).unwrap();
/// let k2 = k.clone();
/// ```
#[doc(hidden)]
pub struct EcbKey {
    pub(crate) schedule: KeySchedule,
}

impl EcbKey {
    /// Builds the key schedule of a 16-, 24- or 32-byte AES key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call: in `Operational`, or in `SelfTest` on the thread
    /// running the power-up self-tests. Returns [`Error::InvalidInput`]
    /// unless `key` is 16, 24 or 32 bytes.
    ///
    /// The key is returned by value; a copy of the schedule that the move
    /// leaves behind is not zeroized.
    #[doc(hidden)]
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        require_self_test_started()?;
        let mut k = Self {
            schedule: KeySchedule::zeroed(key.len())?,
        };
        k.schedule.expand(key);
        Ok(k)
    }

    /// Builds the key as [`Self::new`] does, in `slot`, and returns a
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
    /// The errors of [`Self::new`].
    #[doc(hidden)]
    pub fn new_in_place<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
    ) -> Result<&'a mut Self, Error> {
        require_self_test_started()?;
        let k = slot.write(Self {
            schedule: KeySchedule::zeroed(key.len())?,
        });
        k.schedule.expand(key);
        Ok(k)
    }

    /// An all-zero schedule for a key of `len` bytes, which
    /// [`Self::expand_in_place`] then fills where it lies, so that a key
    /// held inside another value is expanded without being moved there.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] unless `len` is 16, 24 or 32.
    #[doc(hidden)]
    pub fn zeroed(len: usize) -> Result<Self, Error> {
        Ok(Self {
            schedule: KeySchedule::zeroed(len)?,
        })
    }

    /// Expands `key` into this schedule in place (FIPS 197 §5.2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call: in `Operational`, or in `SelfTest` on the thread
    /// running the power-up self-tests. Returns [`Error::InvalidInput`]
    /// unless `key` has the length [`Self::zeroed`] was given.
    #[doc(hidden)]
    pub fn expand_in_place(&mut self, key: &[u8]) -> Result<(), Error> {
        require_self_test_started()?;
        if !matches!(
            (&self.schedule, key.len()),
            (KeySchedule::Aes128(_), 16)
                | (KeySchedule::Aes192(_), 24)
                | (KeySchedule::Aes256(_), 32)
        ) {
            return Err(Error::InvalidInput);
        }
        self.schedule.expand(key);
        Ok(())
    }

    /// Encrypts a single 16-byte block in place (ECB on one block).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call.
    pub(crate) fn encrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Error> {
        let started = require_self_test_started_token()?;
        self.schedule.encrypt_block_with(&started, block)
    }

    /// Decrypts a single 16-byte block in place (ECB on one block).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call.
    pub(crate) fn decrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Error> {
        let started = require_self_test_started_token()?;
        self.schedule.decrypt_block_with(&started, block)
    }
}

/// Encrypt a single 16-byte AES block under `rk` (pre-expanded round
/// keys). `nr` selects the number of rounds (10/12/14).
fn encrypt_block_generic(state: &mut [u8; 16], rk: &[u8], nr: usize) {
    add_round_key(state, round_key(rk, 0));
    let mut round = 1;
    while round < nr {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key(rk, round));
        round += 1;
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key(rk, nr));
}

fn decrypt_block_generic(state: &mut [u8; 16], rk: &[u8], nr: usize) {
    add_round_key(state, round_key(rk, nr));
    let mut round = nr;
    while round > 1 {
        round -= 1;
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_key(rk, round));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_key(rk, 0));
}

#[inline]
fn round_key(rk: &[u8], round: usize) -> &[u8; 16] {
    let off = round * 16;
    let slice = &rk[off..off + 16];
    // `unwrap_used` is denied, so convert with a pattern match rather
    // than `try_into().unwrap()`.
    match <&[u8; 16]>::try_from(slice) {
        Ok(a) => a,
        // Unreachable by construction (slice length is always 16).
        // Return a static all-zero block to keep the type system
        // happy without `panic!`; this branch is dead code.
        Err(_) => &[0u8; 16],
    }
}

impl Drop for Aes128Key {
    fn drop(&mut self) {
        wipe(WipedBuffer::RoundKeys, &mut self.rk);
    }
}

impl Drop for Aes192Key {
    fn drop(&mut self) {
        wipe(WipedBuffer::RoundKeys, &mut self.rk);
    }
}

impl Drop for Aes256Key {
    fn drop(&mut self) {
        wipe(WipedBuffer::RoundKeys, &mut self.rk);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{EcbKey, inv_mix_columns_internal, mix_columns_internal};

    /// The MixColumns columns `db 13 53 45 -> 8e 4d a1 bc`,
    /// `f2 0a 22 5c -> 9f dc 58 9d`, `01 01 01 01` fixed and
    /// `d4 d4 d4 d5 -> d5 d5 d7 d6`, and InvMixColumns taking each back.
    #[test]
    fn mix_columns_known_columns_and_inverse() {
        crate::test_support::start_module();
        let input = [
            0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x01, 0x01, 0x01, 0x01, 0xd4, 0xd4,
            0xd4, 0xd5,
        ];
        let mixed = [
            0x8e, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x01, 0x01, 0x01, 0x01, 0xd5, 0xd5,
            0xd7, 0xd6,
        ];
        let mut state = input;
        mix_columns_internal(&mut state).unwrap();
        assert_eq!(state, mixed);
        inv_mix_columns_internal(&mut state).unwrap();
        assert_eq!(state, input);
    }

    #[test]
    fn fips197_appendix_c1_aes128() {
        crate::test_support::start_module();
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ct_expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let k = EcbKey::new(&key).unwrap();
        let mut buf = pt;
        k.encrypt_block(&mut buf).unwrap();
        assert_eq!(buf, ct_expected);
        k.decrypt_block(&mut buf).unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn fips197_appendix_c2_aes192() {
        crate::test_support::start_module();
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ct_expected = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ];
        let k = EcbKey::new(&key).unwrap();
        let mut buf = pt;
        k.encrypt_block(&mut buf).unwrap();
        assert_eq!(buf, ct_expected);
        k.decrypt_block(&mut buf).unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn fips197_appendix_c3_aes256() {
        crate::test_support::start_module();
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ct_expected = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let k = EcbKey::new(&key).unwrap();
        let mut buf = pt;
        k.encrypt_block(&mut buf).unwrap();
        assert_eq!(buf, ct_expected);
        k.decrypt_block(&mut buf).unwrap();
        assert_eq!(buf, pt);
    }
}

// The accel crate cannot host the FIPS 197 correctness KATs itself:
// an AES block KAT needs the expanded key schedule, which is private
// to this crate. With `accel-aes` enabled, the public block methods
// (which dispatch to AES-NI when CPUID allows) must agree byte-for-byte
// with the portable generic cipher and with the FIPS 197 Appendix C
// known answers.
#[cfg(all(test, feature = "accel-aes"))]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]
mod accel_cross_path_tests {
    use super::*;

    /// the NIST AES example vectors common plaintext.
    const PT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    #[test]
    fn fips197_appendix_c_through_dispatch() {
        crate::test_support::start_module();
        // C.1 — AES-128.
        let key128: [u8; 16] = core::array::from_fn(|i| i as u8);
        let expect128: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let k = EcbKey::new(&key128).unwrap();
        let mut b = PT;
        k.encrypt_block(&mut b).unwrap();
        assert_eq!(b, expect128, "AES-128 App C.1 ciphertext");
        k.decrypt_block(&mut b).unwrap();
        assert_eq!(b, PT, "AES-128 App C.1 round-trip");

        // C.2 — AES-192.
        let key192: [u8; 24] = core::array::from_fn(|i| i as u8);
        let expect192: [u8; 16] = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ];
        let k = EcbKey::new(&key192).unwrap();
        let mut b = PT;
        k.encrypt_block(&mut b).unwrap();
        assert_eq!(b, expect192, "AES-192 App C.2 ciphertext");
        k.decrypt_block(&mut b).unwrap();
        assert_eq!(b, PT, "AES-192 App C.2 round-trip");

        // C.3 — AES-256.
        let key256: [u8; 32] = core::array::from_fn(|i| i as u8);
        let expect256: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let k = EcbKey::new(&key256).unwrap();
        let mut b = PT;
        k.encrypt_block(&mut b).unwrap();
        assert_eq!(b, expect256, "AES-256 App C.3 ciphertext");
        k.decrypt_block(&mut b).unwrap();
        assert_eq!(b, PT, "AES-256 App C.3 round-trip");
    }

    #[test]
    fn dispatch_equals_portable_generic_across_many_blocks() {
        crate::test_support::start_module();
        let k128 = EcbKey::new(&[0x13; 16]).unwrap();
        let k192 = EcbKey::new(&[0x37; 24]).unwrap();
        let k256 = EcbKey::new(&[0x42; 32]).unwrap();
        let (rk128, _) = k128.schedule.round_keys();
        let (rk192, _) = k192.schedule.round_keys();
        let (rk256, _) = k256.schedule.round_keys();
        for i in 0..512u32 {
            let x: [u8; 16] =
                core::array::from_fn(|j| (i as usize).wrapping_mul(31).wrapping_add(j * 7) as u8);

            let (mut a, mut b) = (x, x);
            k128.encrypt_block(&mut a).unwrap();
            encrypt_block_generic(&mut b, rk128, 10);
            assert_eq!(a, b, "AES-128 dispatch≡portable encrypt, block {i}");
            let (mut da, mut db) = (a, b);
            k128.decrypt_block(&mut da).unwrap();
            decrypt_block_generic(&mut db, rk128, 10);
            assert_eq!(da, x, "AES-128 dispatch decrypt inverts, block {i}");
            assert_eq!(db, x, "AES-128 portable decrypt inverts, block {i}");

            let (mut a, mut b) = (x, x);
            k192.encrypt_block(&mut a).unwrap();
            encrypt_block_generic(&mut b, rk192, 12);
            assert_eq!(a, b, "AES-192 dispatch≡portable encrypt, block {i}");

            let (mut a, mut b) = (x, x);
            k256.encrypt_block(&mut a).unwrap();
            encrypt_block_generic(&mut b, rk256, 14);
            assert_eq!(a, b, "AES-256 dispatch≡portable encrypt, block {i}");
            let (mut da, mut db) = (a, b);
            k256.decrypt_block(&mut da).unwrap();
            decrypt_block_generic(&mut db, rk256, 14);
            assert_eq!(da, x, "AES-256 dispatch decrypt inverts, block {i}");
            assert_eq!(db, x, "AES-256 portable decrypt inverts, block {i}");
        }
    }
}
