//! The wrapped services.

use core::ffi::{CStr, c_char, c_int};
use core::ptr::{self, NonNull};

use crate::error::{Error, Site, status};
use crate::module::{Module, check};
use crate::secret::{
    HkdfPrk, MlDsa44SecretKey, MlDsa44Seed, MlDsa65SecretKey, MlDsa65Seed, MlDsa87SecretKey,
    MlDsa87Seed, MlKem512DecapsulationKey, MlKem512Seed, MlKem768DecapsulationKey, MlKem768Seed,
    MlKem1024DecapsulationKey, MlKem1024Seed, Okm, SharedSecret, wipe,
};
use crate::sys;
use crate::{
    AES_GCM_IV_LEN, AES_GCM_TAG_LEN, HKDF_SHA384_MAX_OKM_LEN, HMAC_DRBG_MAX_REQUEST_LEN,
    MlDsa44PublicKey, MlDsa44Signature, MlDsa65PublicKey, MlDsa65Signature, MlDsa87PublicKey,
    MlDsa87Signature, MlKem512Ciphertext, MlKem512EncapsulationKey, MlKem768Ciphertext,
    MlKem768EncapsulationKey, MlKem1024Ciphertext, MlKem1024EncapsulationKey, SHA384_LEN,
};

/// `Ok(())` for status 0. On any other status, zeroes `out`, which the
/// library may have written, and returns the mapped error.
fn status_or_wipe(code: core::ffi::c_int, site: Site, out: &mut [u8]) -> Result<(), Error> {
    let result = status(code, site);
    if result.is_err() {
        wipe(out);
    }
    result
}

/// The longest AES-GCM plaintext, 2^39 − 256 bits (SP 800-38D §5.2.1.1).
const GCM_MAX_PAYLOAD_LEN: u64 = (1 << 36) - 32;
/// The longest AES-GCM additional data, 2^64 − 1 bits, in whole bytes
/// (SP 800-38D §5.2.1.1).
const GCM_MAX_AAD_LEN: u64 = (1 << 61) - 1;

/// Refuses a GCM input over the SP 800-38D limits, which the crate checks
/// itself rather than relying on the library to: past them the 32-bit block
/// counter would wrap.
pub(crate) fn gcm_lengths(payload: usize, aad: usize) -> Result<(), Error> {
    if u64::try_from(payload).map_or(true, |n| n > GCM_MAX_PAYLOAD_LEN) {
        return Err(Error::InvalidPayloadLength);
    }
    if u64::try_from(aad).map_or(true, |n| n > GCM_MAX_AAD_LEN) {
        return Err(Error::InvalidAadLength);
    }
    Ok(())
}

/// The pointer for an input slice: NULL for an empty slice, which the header
/// permits wherever a length accompanies the pointer.
fn input(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fn owned<T>(code: c_int, handle: *mut T) -> Result<NonNull<T>, Error> {
    check(code)?;
    NonNull::new(handle).ok_or(Error::NullPointer)
}

/// `Ok(())` when `out` is `len` bytes; otherwise zeroes `out` and returns
/// [`Error::LengthMismatch`], so the library is not called.
fn same_len(out: &mut [u8], len: usize) -> Result<(), Error> {
    if out.len() == len {
        Ok(())
    } else {
        wipe(out);
        Err(Error::LengthMismatch)
    }
}

/// The signature the four KW functions share.
type KwFn = unsafe extern "C" fn(*const sys::OxiAesKwKey, *const u8, usize, *mut u8) -> c_int;

/// The signature the four KWP functions share.
type KwpFn = unsafe extern "C" fn(
    *const sys::OxiAesKwKey,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> c_int;

/// One call of the KW function `f`, whose output for `data` is `out_len`
/// bytes, `None` when no length fits. `out` is zeroed on every error.
fn kw_call(
    f: KwFn,
    key: &AesKwKey,
    data: &[u8],
    out: &mut [u8],
    out_len: Option<usize>,
) -> Result<(), Error> {
    if out_len != Some(out.len()) {
        wipe(out);
        return Err(Error::LengthMismatch);
    }
    // SAFETY: U1, `f` is a KW function of `sys`; U4 for `key`; U2 for
    // `data`; U9, `out` has the `out_len` writable bytes `f` writes, checked
    // above.
    let code = unsafe { f(key.ptr.as_ptr(), input(data), data.len(), out.as_mut_ptr()) };
    status_or_wipe(code, Site::Other, out)
}

/// One call of the KWP function `f` with `out`'s length as its capacity;
/// the length written. `out` is zeroed on every error.
fn kwp_call(f: KwpFn, key: &AesKwKey, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut written = 0usize;
    // SAFETY: U1, `f` is a KWP function of `sys`; U4 for `key`; U2 for
    // `data`; U9, `out` has `out.len()` writable bytes, the capacity passed;
    // `written` points to a live local.
    let code = unsafe {
        f(
            key.ptr.as_ptr(),
            input(data),
            data.len(),
            out.as_mut_ptr(),
            out.len(),
            &raw mut written,
        )
    };
    status_or_wipe(code, Site::Other, out)?;
    if written > out.len() {
        wipe(out);
        return Err(Error::Internal);
    }
    Ok(written)
}

impl Module {
    /// SHA-384 of `data`.
    pub fn sha384(self, data: &[u8]) -> Result<[u8; SHA384_LEN], Error> {
        let mut out = [0u8; SHA384_LEN];
        // SAFETY: U1; U2 for `data`; U3, `out` is SHA384_LEN writable bytes.
        let code = unsafe { sys::oxi_sha384(input(data), data.len(), out.as_mut_ptr()) };
        check(code)?;
        Ok(out)
    }

    /// HKDF-Extract with HMAC-SHA-384 (RFC 5869 §2.2). `None` and an empty
    /// salt both mean 48 zero bytes.
    pub fn hkdf_sha384_extract(self, salt: Option<&[u8]>, ikm: &[u8]) -> Result<HkdfPrk, Error> {
        let salt = salt.unwrap_or(&[]);
        let mut prk = HkdfPrk::zeroed();
        // SAFETY: U1; U2 for `salt` and `ikm`; U3, `prk.bytes` is
        // HKDF_SHA384_PRK_LEN writable bytes owned by the zeroing type.
        let code = unsafe {
            sys::oxi_hkdf_sha384_extract(
                input(salt),
                salt.len(),
                input(ikm),
                ikm.len(),
                prk.bytes.as_mut_ptr(),
            )
        };
        check(code)?;
        Ok(prk)
    }

    /// HKDF-Expand with HMAC-SHA-384 (RFC 5869 §2.3), `len` bytes.
    ///
    /// A `len` above [`HKDF_SHA384_MAX_OKM_LEN`] is refused with
    /// [`Error::OutputTooLong`] before anything is allocated or called.
    pub fn hkdf_sha384_expand(self, prk: &HkdfPrk, info: &[u8], len: usize) -> Result<Okm, Error> {
        if len > HKDF_SHA384_MAX_OKM_LEN {
            return Err(Error::OutputTooLong);
        }
        let mut okm = Okm::zeroed(len);
        // SAFETY: U1; U3, `prk.bytes` is the 48 bytes the function reads;
        // U2 for `info`; U9, `okm.bytes` is `len` writable bytes, bounded
        // above, owned by the zeroing type.
        let code = unsafe {
            sys::oxi_hkdf_sha384_expand(
                prk.bytes.as_ptr(),
                input(info),
                info.len(),
                okm.bytes.as_mut_ptr(),
                okm.bytes.len(),
            )
        };
        check(code)?;
        Ok(okm)
    }

    /// An AES-GCM key handle for a key of 16, 24 or 32 bytes, with a count of
    /// 0 and a limit of 2^32 encryptions (SP 800-38D §8.3). Calls
    /// `oxi_aes_gcm_key_new`; another key length is [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_gcm_key(self, key: &[u8]) -> Result<AesGcmKey, Error> {
        let mut handle: *mut sys::OxiAesGcmKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code = unsafe { sys::oxi_aes_gcm_key_new(input(key), key.len(), &raw mut handle) };
        owned(code, handle).map(|ptr| AesGcmKey { ptr })
    }

    /// An AES-GCM key handle as [`Module::aes_gcm_key`] builds it, with its
    /// count preloaded to `used`, the encryptions earlier instances of the
    /// same key bytes performed. Calls `oxi_aes_gcm_key_new_with_count`; a
    /// `used` above 2^32 is [`Error::InvalidInput`], and 2^32 builds a key
    /// that is already exhausted.
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_gcm_key_with_count(self, key: &[u8], used: u64) -> Result<AesGcmKey, Error> {
        let mut handle: *mut sys::OxiAesGcmKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code = unsafe {
            sys::oxi_aes_gcm_key_new_with_count(input(key), key.len(), used, &raw mut handle)
        };
        owned(code, handle).map(|ptr| AesGcmKey { ptr })
    }

    /// An AES-GCM key handle as [`Module::aes_gcm_key`] builds it, with a
    /// limit of `limit` encryptions: this instance's share of the 2^32
    /// permitted under the key bytes. Calls
    /// `oxi_aes_gcm_key_new_with_limit`; a `limit` of 0 or above 2^32 is
    /// [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_gcm_key_with_limit(self, key: &[u8], limit: u64) -> Result<AesGcmKey, Error> {
        let mut handle: *mut sys::OxiAesGcmKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code = unsafe {
            sys::oxi_aes_gcm_key_new_with_limit(input(key), key.len(), limit, &raw mut handle)
        };
        owned(code, handle).map(|ptr| AesGcmKey { ptr })
    }

    /// The number of encryptions reserved under `key`, including any
    /// preloaded by [`Module::aes_gcm_key_with_count`]. Calls
    /// `oxi_aes_gcm_key_invocations`.
    pub fn aes_gcm_invocations(self, key: &AesGcmKey) -> Result<u64, Error> {
        let mut n = 0u64;
        // SAFETY: U1; U4 for `key`; `out` points to a live local.
        let code = unsafe { sys::oxi_aes_gcm_key_invocations(key.ptr.as_ptr(), &raw mut n) };
        check(code)?;
        Ok(n)
    }

    /// AES-GCM encryption of `plaintext` into `ciphertext_out`, which must be
    /// the same length, under a 96-bit IV the module draws from `drbg`
    /// (SP 800-38D §8.2.2). Calls `oxi_aes_gcm_seal` and returns the IV and
    /// the tag.
    ///
    /// A length mismatch is refused with [`Error::LengthMismatch`], a
    /// plaintext over 2^36 − 32 bytes with [`Error::InvalidPayloadLength`]
    /// and additional data over 2^61 − 1 bytes with
    /// [`Error::InvalidAadLength`] (SP 800-38D §5.2.1.1), each before the
    /// library is called. A key at its limit is [`Error::KeyExhausted`],
    /// with no IV drawn, and the DRBG's own errors are those of
    /// [`Drbg::generate`]. `ciphertext_out` is zeroed on every error.
    pub fn aes_gcm_seal(
        self,
        key: &AesGcmKey,
        drbg: &mut Drbg,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
    ) -> Result<GcmSealed, Error> {
        if let Err(e) = gcm_lengths(plaintext.len(), aad.len()) {
            wipe(ciphertext_out);
            return Err(e);
        }
        same_len(ciphertext_out, plaintext.len())?;
        let mut sealed = GcmSealed {
            iv: [0; AES_GCM_IV_LEN],
            tag: [0; AES_GCM_TAG_LEN],
        };
        // SAFETY: U1; U4 for `key` and `drbg`; U2 for `aad` and `plaintext`;
        // U9, `ciphertext_out` has `plaintext.len()` writable bytes, checked
        // above; U3, `iv` and `tag` are AES_GCM_IV_LEN and AES_GCM_TAG_LEN
        // writable bytes.
        let code = unsafe {
            sys::oxi_aes_gcm_seal(
                key.ptr.as_ptr(),
                drbg.ptr.as_ptr(),
                input(aad),
                aad.len(),
                input(plaintext),
                plaintext.len(),
                ciphertext_out.as_mut_ptr(),
                sealed.iv.as_mut_ptr(),
                sealed.tag.as_mut_ptr(),
            )
        };
        // The header promises no output on a refusal; the wipes cover a
        // library that writes before refusing, as the control tests provoke
        // with an overriding shared object.
        if let Err(e) = status_or_wipe(code, Site::Other, ciphertext_out) {
            wipe(&mut sealed.iv);
            wipe(&mut sealed.tag);
            return Err(e);
        }
        Ok(sealed)
    }

    /// AES-GCM decryption of `ciphertext` into `plaintext_out`, which must be
    /// the same length. Calls `oxi_aes_gcm_open`.
    ///
    /// A tag that does not verify is [`Error::TagMismatch`]. A length
    /// mismatch is refused with [`Error::LengthMismatch`], and inputs over the
    /// SP 800-38D limits as for [`Module::aes_gcm_seal`], before the library
    /// is called. `plaintext_out` is zeroed on every error.
    pub fn aes_gcm_open(
        self,
        key: &AesGcmKey,
        iv: &[u8; AES_GCM_IV_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AES_GCM_TAG_LEN],
        plaintext_out: &mut [u8],
    ) -> Result<(), Error> {
        if let Err(e) = gcm_lengths(ciphertext.len(), aad.len()) {
            wipe(plaintext_out);
            return Err(e);
        }
        same_len(plaintext_out, ciphertext.len())?;
        // SAFETY: U1; U4 for `key`; U3 for `iv` and `tag`; U2 for `aad` and
        // `ciphertext`; U9, `plaintext_out` has `ciphertext.len()` writable
        // bytes, checked above.
        let code = unsafe {
            sys::oxi_aes_gcm_open(
                key.ptr.as_ptr(),
                iv.as_ptr(),
                input(aad),
                aad.len(),
                input(ciphertext),
                ciphertext.len(),
                tag.as_ptr(),
                plaintext_out.as_mut_ptr(),
            )
        };
        status_or_wipe(code, Site::AeadDecrypt, plaintext_out)
    }

    /// [`Module::aes_gcm_seal`] into a vector it allocates.
    pub fn aes_gcm_seal_vec(
        self,
        key: &AesGcmKey,
        drbg: &mut Drbg,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, GcmSealed), Error> {
        // Before the allocation, which an over-limit input would make huge.
        gcm_lengths(plaintext.len(), aad.len())?;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let sealed = self.aes_gcm_seal(key, drbg, aad, plaintext, &mut ciphertext)?;
        Ok((ciphertext, sealed))
    }

    /// [`Module::aes_gcm_open`] into a vector it allocates, zeroed before it
    /// is freed on an error.
    pub fn aes_gcm_open_vec(
        self,
        key: &AesGcmKey,
        iv: &[u8; AES_GCM_IV_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AES_GCM_TAG_LEN],
    ) -> Result<Vec<u8>, Error> {
        // Before the allocation, which an over-limit input would make huge.
        gcm_lengths(ciphertext.len(), aad.len())?;
        let mut plaintext = vec![0u8; ciphertext.len()];
        self.aes_gcm_open(key, iv, aad, ciphertext, tag, &mut plaintext)?;
        Ok(plaintext)
    }

    /// An AES-CCM key handle for a key of 16, 24 or 32 bytes with a tag
    /// length of `tag_len` bytes, fixed for the key (SP 800-38C §5.3), and an
    /// invocation count of 0. Calls `oxi_aes_ccm_key_new`; a key length
    /// other than 16, 24 or 32, or a `tag_len` other than 8, 10, 12, 14 or
    /// 16, is [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_ccm_key(self, key: &[u8], tag_len: usize) -> Result<AesCcmKey, Error> {
        let mut handle: *mut sys::OxiAesCcmKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code =
            unsafe { sys::oxi_aes_ccm_key_new(input(key), key.len(), tag_len, &raw mut handle) };
        owned(code, handle).map(|ptr| AesCcmKey { ptr, tag_len })
    }

    /// An AES-CCM key handle as [`Module::aes_ccm_key`] builds it, with its
    /// count preloaded to `used`, the block-cipher invocations earlier
    /// instances of the same key bytes performed. Calls
    /// `oxi_aes_ccm_key_new_with_count`; a `used` above 2^61 is
    /// [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_ccm_key_with_count(
        self,
        key: &[u8],
        tag_len: usize,
        used: u64,
    ) -> Result<AesCcmKey, Error> {
        let mut handle: *mut sys::OxiAesCcmKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code = unsafe {
            sys::oxi_aes_ccm_key_new_with_count(
                input(key),
                key.len(),
                tag_len,
                used,
                &raw mut handle,
            )
        };
        owned(code, handle).map(|ptr| AesCcmKey { ptr, tag_len })
    }

    /// The number of block-cipher invocations reserved under `key`,
    /// including any preloaded by [`Module::aes_ccm_key_with_count`]. Calls
    /// `oxi_aes_ccm_key_invocations`.
    pub fn aes_ccm_invocations(self, key: &AesCcmKey) -> Result<u64, Error> {
        let mut n = 0u64;
        // SAFETY: U1; U4 for `key`; `out` points to a live local.
        let code = unsafe { sys::oxi_aes_ccm_key_invocations(key.ptr.as_ptr(), &raw mut n) };
        check(code)?;
        Ok(n)
    }

    /// AES-CCM encryption (SP 800-38C §6.1) of `plaintext` into
    /// `ciphertext_out`, which must be the same length, and its tag into
    /// `tag_out`, which must be the key's [`tag_len`](AesCcmKey::tag_len),
    /// under `nonce`, which must be unique under the key. Calls
    /// `oxi_aes_ccm_seal`.
    ///
    /// An output of another length is refused with [`Error::LengthMismatch`]
    /// before the library is called. A nonce length outside 7 to 13 is
    /// [`Error::InvalidNonceLength`], a payload the nonce's length field
    /// cannot represent [`Error::InvalidPayloadLength`], AAD above the
    /// SP 800-38C bound [`Error::InvalidAadLength`], and an encryption that
    /// would take the key past 2^61 block-cipher invocations
    /// [`Error::KeyExhausted`]. Both outputs are zeroed on every error.
    pub fn aes_ccm_seal(
        self,
        key: &AesCcmKey,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), Error> {
        if ciphertext_out.len() != plaintext.len() || tag_out.len() != key.tag_len {
            wipe(ciphertext_out);
            wipe(tag_out);
            return Err(Error::LengthMismatch);
        }
        // SAFETY: U1; U4 for `key`; U2 for `nonce`, `aad` and `plaintext`;
        // U9, `ciphertext_out` has `plaintext.len()` writable bytes and
        // `tag_out` the key's tag length, checked above against `tag_len`:
        // the constructor cached it from the length the library accepted
        // for the handle, and it is the length the library writes.
        let code = unsafe {
            sys::oxi_aes_ccm_seal(
                key.ptr.as_ptr(),
                input(nonce),
                nonce.len(),
                input(aad),
                aad.len(),
                input(plaintext),
                plaintext.len(),
                ciphertext_out.as_mut_ptr(),
                tag_out.as_mut_ptr(),
            )
        };
        let result = status(code, Site::Other);
        if result.is_err() {
            wipe(ciphertext_out);
            wipe(tag_out);
        }
        result
    }

    /// AES-CCM decryption (SP 800-38C §6.2) of `ciphertext`, without its
    /// tag, into `plaintext_out`, which must be the same length. Calls
    /// `oxi_aes_ccm_open`.
    ///
    /// Every invalid input the library sees is [`Error::TagMismatch`], as the
    /// library reports it: a tag that does not verify, a nonce length outside
    /// 7 to 13, and a payload length the nonce's length field cannot
    /// represent. A `tag` that is not the key's
    /// [`tag_len`](AesCcmKey::tag_len) is refused with
    /// [`Error::InvalidTagLength`], and an output of another length with
    /// [`Error::LengthMismatch`], both before the call. A decryption that
    /// would take the key past 2^61 block-cipher invocations is
    /// [`Error::KeyExhausted`]. `plaintext_out` is zeroed on every error.
    pub fn aes_ccm_open(
        self,
        key: &AesCcmKey,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        plaintext_out: &mut [u8],
    ) -> Result<(), Error> {
        same_len(plaintext_out, ciphertext.len())?;
        if tag.len() != key.tag_len {
            wipe(plaintext_out);
            return Err(Error::InvalidTagLength);
        }
        // SAFETY: U1; U4 for `key`; U2 for `nonce`, `aad` and `ciphertext`,
        // and for `tag`, the key's tag length, checked above; U9,
        // `plaintext_out` has `ciphertext.len()` writable bytes, checked
        // above.
        let code = unsafe {
            sys::oxi_aes_ccm_open(
                key.ptr.as_ptr(),
                input(nonce),
                nonce.len(),
                input(aad),
                aad.len(),
                input(ciphertext),
                ciphertext.len(),
                tag.as_ptr(),
                plaintext_out.as_mut_ptr(),
            )
        };
        status_or_wipe(code, Site::AeadDecrypt, plaintext_out)
    }

    /// An AES-CBC key handle for a key of 16, 24 or 32 bytes. Calls
    /// `oxi_aes_cbc_key_new`; another key length is [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_cbc_key(self, key: &[u8]) -> Result<AesCbcKey, Error> {
        let mut handle: *mut sys::OxiAesCbcKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code = unsafe { sys::oxi_aes_cbc_key_new(input(key), key.len(), &raw mut handle) };
        owned(code, handle).map(|ptr| AesCbcKey { ptr })
    }

    /// AES-CBC encryption (SP 800-38A §6.2) of `data` into `out`, which must
    /// be the same length, under `iv`, which must be unpredictable
    /// (SP 800-38A Appendix C). Calls `oxi_aes_cbc_encrypt`.
    ///
    /// An output of another length is refused with [`Error::LengthMismatch`]
    /// before the call. A `data` that is not a multiple of 16 bytes is
    /// [`Error::NotBlockAligned`], an empty one
    /// [`Error::InvalidPayloadLength`]. `out` is zeroed on every error.
    pub fn aes_cbc_encrypt(
        self,
        key: &AesCbcKey,
        iv: &[u8; 16],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        same_len(out, data.len())?;
        // SAFETY: U1; U4 for `key`; U3 for `iv`; U2 for `data`; U9, `out`
        // has `data.len()` writable bytes, checked above.
        let code = unsafe {
            sys::oxi_aes_cbc_encrypt(
                key.ptr.as_ptr(),
                iv.as_ptr(),
                input(data),
                data.len(),
                out.as_mut_ptr(),
            )
        };
        status_or_wipe(code, Site::Other, out)
    }

    /// AES-CBC decryption (SP 800-38A §6.2) of `data` into `out`, with the
    /// lengths and errors of [`Module::aes_cbc_encrypt`]. Calls
    /// `oxi_aes_cbc_decrypt`.
    pub fn aes_cbc_decrypt(
        self,
        key: &AesCbcKey,
        iv: &[u8; 16],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        same_len(out, data.len())?;
        // SAFETY: U1; U4 for `key`; U3 for `iv`; U2 for `data`; U9, `out`
        // has `data.len()` writable bytes, checked above.
        let code = unsafe {
            sys::oxi_aes_cbc_decrypt(
                key.ptr.as_ptr(),
                iv.as_ptr(),
                input(data),
                data.len(),
                out.as_mut_ptr(),
            )
        };
        status_or_wipe(code, Site::Other, out)
    }

    /// An AES-CTR key handle for a key of 16, 24 or 32 bytes. Calls
    /// `oxi_aes_ctr_key_new`; another key length is [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_ctr_key(self, key: &[u8]) -> Result<AesCtrKey, Error> {
        let mut handle: *mut sys::OxiAesCtrKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code = unsafe { sys::oxi_aes_ctr_key_new(input(key), key.len(), &raw mut handle) };
        owned(code, handle).map(|ptr| AesCtrKey { ptr })
    }

    /// AES-CTR (SP 800-38A §6.5): `data` XORed into `out`, which must be the
    /// same length, with the keystream from the initial counter block
    /// `counter`, incremented as one 128-bit big-endian integer. Encryption
    /// and decryption are the same call; no counter block may repeat under
    /// one key. Calls `oxi_aes_ctr`.
    ///
    /// An output of another length is refused with [`Error::LengthMismatch`]
    /// before the call. `out` is zeroed on every error.
    pub fn aes_ctr(
        self,
        key: &AesCtrKey,
        counter: &[u8; 16],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        same_len(out, data.len())?;
        // SAFETY: U1; U4 for `key`; U3 for `counter`; U2 for `data`; U9,
        // `out` has `data.len()` writable bytes, checked above.
        let code = unsafe {
            sys::oxi_aes_ctr(
                key.ptr.as_ptr(),
                counter.as_ptr(),
                input(data),
                data.len(),
                out.as_mut_ptr(),
            )
        };
        status_or_wipe(code, Site::Other, out)
    }

    /// An AES key-wrap key handle for a key of 16, 24 or 32 bytes, for KW and
    /// KWP (SP 800-38F) in the forward and the inverse-cipher variants.
    /// Calls `oxi_aes_kw_key_new`; another key length is
    /// [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_kw_key(self, key: &[u8]) -> Result<AesKwKey, Error> {
        let mut handle: *mut sys::OxiAesKwKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code = unsafe { sys::oxi_aes_kw_key_new(input(key), key.len(), &raw mut handle) };
        owned(code, handle).map(|ptr| AesKwKey { ptr })
    }

    /// AES-KW wrap (SP 800-38F §6.2, KW-AE) of `plaintext` into `out`, which
    /// must be `plaintext.len() + 8` bytes. Calls `oxi_aes_kw_wrap`.
    ///
    /// An output of another length is refused with [`Error::LengthMismatch`]
    /// before the call. KW accepts a plaintext that is a multiple of 8 of at
    /// least 16 bytes and fewer than 2^54 semiblocks: one shorter than 16
    /// bytes or not a multiple of 8 is [`Error::LengthMismatch`], and one of
    /// 2^54 semiblocks or more [`Error::InvalidPayloadLength`]. `out` is
    /// zeroed on every error.
    pub fn aes_kw_wrap(
        self,
        key: &AesKwKey,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        kw_call(
            sys::oxi_aes_kw_wrap,
            key,
            plaintext,
            out,
            plaintext.len().checked_add(8),
        )
    }

    /// AES-KW unwrap (SP 800-38F §6.2, KW-AD) of `ciphertext` into `out`,
    /// which must be `ciphertext.len() - 8` bytes. Calls `oxi_aes_kw_unwrap`.
    ///
    /// An output of another length is refused with [`Error::LengthMismatch`]
    /// before the call. An integrity check value that does not verify is
    /// [`Error::TagMismatch`]. A ciphertext shorter than 24 bytes or not a
    /// multiple of 8 is [`Error::LengthMismatch`], and one longer than 2^54
    /// semiblocks [`Error::InvalidPayloadLength`]. `out` is zeroed on every
    /// error.
    pub fn aes_kw_unwrap(
        self,
        key: &AesKwKey,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        kw_call(
            sys::oxi_aes_kw_unwrap,
            key,
            ciphertext,
            out,
            ciphertext.len().checked_sub(8),
        )
    }

    /// AES-KW wrap with the inverse cipher (SP 800-38F §6.4), with the
    /// lengths and errors of [`Module::aes_kw_wrap`]. Calls
    /// `oxi_aes_kw_wrap_inverse`.
    pub fn aes_kw_wrap_inverse(
        self,
        key: &AesKwKey,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        kw_call(
            sys::oxi_aes_kw_wrap_inverse,
            key,
            plaintext,
            out,
            plaintext.len().checked_add(8),
        )
    }

    /// AES-KW unwrap with the forward cipher (SP 800-38F §6.4, the inverse of
    /// [`Module::aes_kw_wrap_inverse`]), with the lengths and errors of
    /// [`Module::aes_kw_unwrap`]. Calls `oxi_aes_kw_unwrap_inverse`.
    pub fn aes_kw_unwrap_inverse(
        self,
        key: &AesKwKey,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        kw_call(
            sys::oxi_aes_kw_unwrap_inverse,
            key,
            ciphertext,
            out,
            ciphertext.len().checked_sub(8),
        )
    }

    /// AES-KWP wrap (SP 800-38F §6.3, KWP-AE) of `plaintext`, 1 to 2^32 − 1
    /// bytes, into the front of `out`. Calls `oxi_aes_kwp_wrap` with `out`'s
    /// length as its capacity and returns the wrapped length,
    /// `((plaintext.len() + 7) / 8) * 8 + 8`.
    ///
    /// An `out` shorter than the wrapped length is [`Error::BufferTooSmall`],
    /// a plaintext length KWP does not accept [`Error::LengthMismatch`].
    /// `out` is zeroed on every error.
    pub fn aes_kwp_wrap(
        self,
        key: &AesKwKey,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        kwp_call(sys::oxi_aes_kwp_wrap, key, plaintext, out)
    }

    /// AES-KWP unwrap (SP 800-38F §6.3, KWP-AD) of `ciphertext` into the
    /// front of `out`. Calls `oxi_aes_kwp_unwrap` with `out`'s length as its
    /// capacity and returns the unwrapped length.
    ///
    /// An integrity check value or padding that does not verify is
    /// [`Error::TagMismatch`], which takes precedence over an `out` shorter
    /// than the unwrapped length, [`Error::BufferTooSmall`]; a length KWP
    /// does not accept is [`Error::LengthMismatch`]. `out` is zeroed on
    /// every error.
    pub fn aes_kwp_unwrap(
        self,
        key: &AesKwKey,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        kwp_call(sys::oxi_aes_kwp_unwrap, key, ciphertext, out)
    }

    /// AES-KWP wrap with the inverse cipher (SP 800-38F §6.4), with the
    /// lengths and errors of [`Module::aes_kwp_wrap`]. Calls
    /// `oxi_aes_kwp_wrap_inverse`.
    pub fn aes_kwp_wrap_inverse(
        self,
        key: &AesKwKey,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        kwp_call(sys::oxi_aes_kwp_wrap_inverse, key, plaintext, out)
    }

    /// AES-KWP unwrap with the forward cipher (SP 800-38F §6.4, the inverse
    /// of [`Module::aes_kwp_wrap_inverse`]), with the lengths and errors of
    /// [`Module::aes_kwp_unwrap`]. Calls `oxi_aes_kwp_unwrap_inverse`.
    pub fn aes_kwp_unwrap_inverse(
        self,
        key: &AesKwKey,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        kwp_call(sys::oxi_aes_kwp_unwrap_inverse, key, ciphertext, out)
    }

    /// A CMAC key handle (SP 800-38B) for a key of 16, 24 or 32 bytes with a
    /// MAC length of `mac_len` bytes, fixed for the key. Calls
    /// `oxi_aes_cmac_key_new`; a key length other than 16, 24 or 32, or a
    /// `mac_len` outside 8 to 16, is [`Error::InvalidInput`].
    /// A key size the active profile does not allow is
    /// [`Error::AlgorithmRestricted`].
    pub fn aes_cmac_key(self, key: &[u8], mac_len: usize) -> Result<AesCmacKey, Error> {
        let mut handle: *mut sys::OxiAesCmacKey = ptr::null_mut();
        // SAFETY: U1; U2 for `key`; `out` points to a live local.
        let code =
            unsafe { sys::oxi_aes_cmac_key_new(input(key), key.len(), mac_len, &raw mut handle) };
        owned(code, handle).map(|ptr| AesCmacKey { ptr, mac_len })
    }

    /// The CMAC (SP 800-38B §6.2) of `msg` into `mac_out`, which must be the
    /// key's [`mac_len`](AesCmacKey::mac_len). Calls `oxi_aes_cmac`.
    ///
    /// An output of another length is refused with [`Error::LengthMismatch`]
    /// before the call. `mac_out` is zeroed on every error.
    pub fn aes_cmac(self, key: &AesCmacKey, msg: &[u8], mac_out: &mut [u8]) -> Result<(), Error> {
        same_len(mac_out, key.mac_len)?;
        // SAFETY: U1; U4 for `key`; U2 for `msg`; U9, `mac_out` has the
        // key's MAC length in writable bytes, checked above.
        let code = unsafe {
            sys::oxi_aes_cmac(
                key.ptr.as_ptr(),
                input(msg),
                msg.len(),
                mac_out.as_mut_ptr(),
            )
        };
        status_or_wipe(code, Site::Other, mac_out)
    }

    /// Verifies `mac` as the CMAC of `msg` (SP 800-38B §6.3). Calls
    /// `oxi_aes_cmac_verify`. A MAC that does not verify is
    /// [`Error::TagMismatch`]. A `mac` that is not the key's
    /// [`mac_len`](AesCmacKey::mac_len) is refused with
    /// [`Error::InvalidTagLength`] before the call.
    pub fn aes_cmac_verify(self, key: &AesCmacKey, msg: &[u8], mac: &[u8]) -> Result<(), Error> {
        if mac.len() != key.mac_len {
            return Err(Error::InvalidTagLength);
        }
        // SAFETY: U1; U4 for `key`; U2 for `msg`, and for `mac`, the key's
        // MAC length, checked above.
        let code = unsafe {
            sys::oxi_aes_cmac_verify(key.ptr.as_ptr(), input(msg), msg.len(), mac.as_ptr())
        };
        check(code)
    }

    /// A new, uninstantiated DRBG of `kind`, seeded by the module when
    /// [`Drbg::instantiate`] is called.
    pub fn drbg(self, kind: DrbgKind) -> Result<Drbg, Error> {
        let new: unsafe extern "C" fn(*mut *mut sys::OxiDrbg) -> c_int = match kind {
            DrbgKind::HmacSha256 => sys::oxi_hmac_drbg_sha256_new_rbg,
            DrbgKind::HmacSha384 => sys::oxi_hmac_drbg_sha384_new_rbg,
            DrbgKind::HmacSha512 => sys::oxi_hmac_drbg_sha512_new_rbg,
            DrbgKind::HashSha256 => sys::oxi_hash_drbg_sha256_new_rbg,
            DrbgKind::HashSha384 => sys::oxi_hash_drbg_sha384_new_rbg,
            DrbgKind::HashSha512 => sys::oxi_hash_drbg_sha512_new_rbg,
            DrbgKind::CtrAes128 => sys::oxi_ctr_drbg_aes128_new_rbg,
            DrbgKind::CtrAes192 => sys::oxi_ctr_drbg_aes192_new_rbg,
            DrbgKind::CtrAes256 => sys::oxi_ctr_drbg_aes256_new_rbg,
        };
        let mut handle: *mut sys::OxiDrbg = ptr::null_mut();
        // SAFETY: U1; `out` points to a live local.
        let code = unsafe { new(&raw mut handle) };
        check(code)?;
        NonNull::new(handle)
            .map(|ptr| Drbg { ptr })
            .ok_or(Error::NullPointer)
    }

    /// Runs the entropy source's on-demand test on the module's seed path
    /// and returns the label naming that path.
    ///
    /// The first call in a process decides the seed path, as the first DRBG
    /// instantiation does. A failed test returns
    /// [`Error::EntropyUnavailable`], after which the module is in its error
    /// state; [`Error::Busy`] asks for a retry after a pause.
    pub fn entropy_on_demand_test(self) -> Result<&'static str, Error> {
        let mut label: *const c_char = ptr::null();
        // SAFETY: U1; `label_out` points to a live local.
        let code = unsafe { sys::oxi_entropy_on_demand_test(&raw mut label) };
        check(code)?;
        if label.is_null() {
            return Err(Error::NullPointer);
        }
        // SAFETY: U5, on status 0 the header sets `label` to a static
        // NUL-terminated string that lives as long as the library.
        let label = unsafe { CStr::from_ptr(label) };
        label.to_str().map_err(|_| Error::Internal)
    }
}

/// The length of `d`, the first part of an ML-KEM seed `d ‖ z`
/// (FIPS 203 Algorithm 16).
const ML_KEM_D_LEN: usize = 32;

macro_rules! rbg_errors_doc {
    () => {
        concat!(
            "A DRBG never instantiated is [`Error::Uninstantiated`], with nothing drawn, ",
            "and one instantiated in another process, as a handle inherited across ",
            "`fork` is, is [`Error::InvalidInput`] until [`Drbg::instantiate`] runs in ",
            "this process. A reseed the DRBG starts is [`Error::Busy`] when another ",
            "thread holds the module's seed path past its wait bound, which a retry ",
            "after a pause clears, and [`Error::EntropyUnavailable`] when the entropy ",
            "source fails, after which the module is in its error state."
        )
    };
}

macro_rules! keygen_errors_doc {
    () => {
        concat!(
            "A failed pairwise consistency test is [`Error::ConditionalTestFailed`], ",
            "after which the module is in its error state and every call returns ",
            "[`Error::NotOperational`]. A profile that does not admit the parameter ",
            "set or the DRBG is [`Error::AlgorithmRestricted`]."
        )
    };
}

#[rustfmt::skip]
macro_rules! ml_dsa_wrappers {
    (
        set: $set:literal,
        strength: $bits:literal,
        seed: $Seed:ident,
        public_key: $Pk:ident = $pk_len:ident,
        secret_key: $Sk:ident,
        signature: $Sig:ident = $sig_len:ident,
        keygen: $keygen:ident => $c_keygen:path,
        keygen_with_seed: $keygen_with_seed:ident,
        expand_key: $expand_key:ident => $c_expand_key:path,
        sign: $sign:ident => $c_sign:path,
        verify: $verify:ident => $c_verify:path $(,)?
    ) => {
        impl Module {
            #[doc = concat!(
                "ML-DSA-", $set, " key generation (FIPS 204 Algorithm 1): the module ",
                "draws the seed `ξ` from `rbg`, expands the key pair, runs the pairwise ",
                "consistency test on it (FIPS 140-3 IG 10.3.A) and wipes `ξ`. Calls `oxi_ml_dsa_",
                $set, "_keygen_rbg`.\n\n",
                "A DRBG below ", $bits, " bits of security strength is ",
                "[`Error::RbgTooWeak`], with nothing drawn."
            )]
            #[doc = rbg_errors_doc!()]
            #[doc = keygen_errors_doc!()]
            pub fn $keygen(self, rbg: &mut Drbg) -> Result<($Pk, $Sk), Error> {
                let mut pk = [0u8; crate::$pk_len];
                let mut sk = $Sk::zeroed();
                // SAFETY: U1; U4 for `rbg`; U3, `pk` and `sk.bytes` are the
                // documented writable lengths, `sk` owned by the zeroing
                // type; `seed_out` NULL, which the header permits.
                let code = unsafe {
                    $c_keygen(
                        rbg.ptr.as_ptr(),
                        pk.as_mut_ptr(),
                        sk.bytes.as_mut_ptr(),
                        ptr::null_mut(),
                    )
                };
                check(code)?;
                Ok((pk, sk))
            }

            #[doc = concat!(
                "ML-DSA-", $set, " key generation as [`Module::", stringify!($keygen),
                "`], also returning the seed `ξ`, from which [`Module::",
                stringify!($expand_key), "`] reproduces the pair. Errors as for [`Module::",
                stringify!($keygen), "`]."
            )]
            pub fn $keygen_with_seed(self, rbg: &mut Drbg) -> Result<($Pk, $Sk, $Seed), Error> {
                let mut pk = [0u8; crate::$pk_len];
                let mut sk = $Sk::zeroed();
                let mut seed = $Seed::zeroed();
                // SAFETY: U1; U4 for `rbg`; U3, `pk`, `sk.bytes` and
                // `seed.bytes` are the documented writable lengths, `sk` and
                // `seed` owned by the zeroing types.
                let code = unsafe {
                    $c_keygen(
                        rbg.ptr.as_ptr(),
                        pk.as_mut_ptr(),
                        sk.bytes.as_mut_ptr(),
                        seed.bytes.as_mut_ptr(),
                    )
                };
                check(code)?;
                Ok((pk, sk, seed))
            }

            #[doc = concat!(
                "ML-DSA-", $set, " key expansion from a stored seed `ξ` (FIPS 204 ",
                "Algorithm 6), with the pairwise consistency test run on the pair. Calls ",
                "`oxi_ml_dsa_", $set, "_expand_key`.\n\n",
                "A seed built with [`", stringify!($Seed), "::from_bytes`] rather than ",
                "returned by [`Module::", stringify!($keygen_with_seed), "`] is a private ",
                "key imported into the module. A failed pairwise consistency test is ",
                "[`Error::ConditionalTestFailed`], as for [`Module::", stringify!($keygen),
                "`]. A profile that does not admit the parameter set is ",
                "[`Error::AlgorithmRestricted`]."
            )]
            pub fn $expand_key(self, seed: &$Seed) -> Result<($Pk, $Sk), Error> {
                let mut pk = [0u8; crate::$pk_len];
                let mut sk = $Sk::zeroed();
                // SAFETY: U1; U3, `seed.bytes` is the 32 bytes read, `pk` and
                // `sk.bytes` the documented writable lengths, `sk` owned by
                // the zeroing type.
                let code = unsafe {
                    $c_expand_key(seed.bytes.as_ptr(), pk.as_mut_ptr(), sk.bytes.as_mut_ptr())
                };
                check(code)?;
                Ok((pk, sk))
            }

            #[doc = concat!(
                "Deterministic ML-DSA-", $set, " signature of `msg` under context `ctx` ",
                "(FIPS 204 §5.2). The library refuses a context over 255 bytes with ",
                "[`Error::InvalidInput`]."
            )]
            pub fn $sign(self, sk: &$Sk, msg: &[u8], ctx: &[u8]) -> Result<$Sig, Error> {
                let mut sig = [0u8; crate::$sig_len];
                // SAFETY: U1; U3, `sk.bytes` is the secret-key length read and
                // `sig` the signature length written, fixed by their types;
                // U2 for `msg` and `ctx`.
                let code = unsafe {
                    $c_sign(
                        sk.bytes.as_ptr(),
                        input(msg),
                        msg.len(),
                        input(ctx),
                        ctx.len(),
                        sig.as_mut_ptr(),
                    )
                };
                check(code)?;
                Ok(sig)
            }

            #[doc = concat!(
                "ML-DSA-", $set, " verification (FIPS 204 §5.3). A signature that does ",
                "not verify, and a signature or key that does not decode, are both ",
                "[`Error::SignatureInvalid`]."
            )]
            pub fn $verify(
                self,
                pk: &$Pk,
                msg: &[u8],
                ctx: &[u8],
                sig: &$Sig,
            ) -> Result<(), Error> {
                // SAFETY: U1; U3, `pk` and `sig` are the lengths the function
                // reads, fixed by their types; U2 for `msg` and `ctx`.
                let code = unsafe {
                    $c_verify(
                        pk.as_ptr(),
                        input(msg),
                        msg.len(),
                        input(ctx),
                        ctx.len(),
                        sig.as_ptr(),
                    )
                };
                status(code, Site::SignatureVerify)
            }
        }
    };
}

#[rustfmt::skip]
macro_rules! ml_kem_wrappers {
    (
        set: $set:literal,
        $(strength: $bits:literal,)?
        seed: $Seed:ident,
        encapsulation_key: $Ek:ident = $ek_len:ident,
        decapsulation_key: $Dk:ident,
        ciphertext: $Ct:ident = $ct_len:ident,
        keygen: $keygen:ident => $c_keygen:path,
        keygen_with_seed: $keygen_with_seed:ident,
        expand_key: $expand_key:ident => $c_expand_key:path,
        encapsulate: $encapsulate:ident => $c_encapsulate:path,
        decapsulate: $decapsulate:ident => $c_decapsulate:path $(,)?
    ) => {
        impl Module {
            #[doc = concat!(
                "ML-KEM-", $set, " key generation (FIPS 203 Algorithm 19): the module ",
                "draws the seeds `d` and `z` from `rbg`, expands the key pair, runs the ",
                "pairwise consistency test on it (FIPS 140-3 IG 10.3.A) and wipes the ",
                "seeds. Calls `oxi_ml_kem_", $set, "_keygen_rbg`.\n"
            )]
            $(#[doc = concat!(
                "A DRBG below ", $bits, " bits of security strength is ",
                "[`Error::RbgTooWeak`], with nothing drawn."
            )])?
            #[doc = rbg_errors_doc!()]
            #[doc = keygen_errors_doc!()]
            pub fn $keygen(self, rbg: &mut Drbg) -> Result<($Ek, $Dk), Error> {
                let mut ek = [0u8; crate::$ek_len];
                let mut dk = $Dk::zeroed();
                // SAFETY: U1; U4 for `rbg`; U3, `ek` and `dk.bytes` are the
                // documented writable lengths, `dk` owned by the zeroing
                // type; `seed_out` NULL, which the header permits.
                let code = unsafe {
                    $c_keygen(
                        rbg.ptr.as_ptr(),
                        ek.as_mut_ptr(),
                        dk.bytes.as_mut_ptr(),
                        ptr::null_mut(),
                    )
                };
                check(code)?;
                Ok((ek, dk))
            }

            #[doc = concat!(
                "ML-KEM-", $set, " key generation as [`Module::", stringify!($keygen),
                "`], also returning the seed `d ‖ z`, from which [`Module::",
                stringify!($expand_key), "`] reproduces the pair. Errors as for [`Module::",
                stringify!($keygen), "`]."
            )]
            pub fn $keygen_with_seed(self, rbg: &mut Drbg) -> Result<($Ek, $Dk, $Seed), Error> {
                let mut ek = [0u8; crate::$ek_len];
                let mut dk = $Dk::zeroed();
                let mut seed = $Seed::zeroed();
                // SAFETY: U1; U4 for `rbg`; U3, `ek`, `dk.bytes` and
                // `seed.bytes` are the documented writable lengths, `dk` and
                // `seed` owned by the zeroing types.
                let code = unsafe {
                    $c_keygen(
                        rbg.ptr.as_ptr(),
                        ek.as_mut_ptr(),
                        dk.bytes.as_mut_ptr(),
                        seed.bytes.as_mut_ptr(),
                    )
                };
                check(code)?;
                Ok((ek, dk, seed))
            }

            #[doc = concat!(
                "ML-KEM-", $set, " key expansion from a stored seed `d ‖ z` (FIPS 203 ",
                "Algorithm 16), with the pairwise consistency test run on the pair. Calls ",
                "`oxi_ml_kem_", $set, "_expand_key`.\n\n",
                "A seed built with [`", stringify!($Seed), "::from_bytes`] rather than ",
                "returned by [`Module::", stringify!($keygen_with_seed), "`] is a private ",
                "key imported into the module. A failed pairwise consistency test is ",
                "[`Error::ConditionalTestFailed`], as for [`Module::", stringify!($keygen),
                "`]. A profile that does not admit the parameter set is ",
                "[`Error::AlgorithmRestricted`]."
            )]
            pub fn $expand_key(self, seed: &$Seed) -> Result<($Ek, $Dk), Error> {
                let mut ek = [0u8; crate::$ek_len];
                let mut dk = $Dk::zeroed();
                let (d, z) = seed.bytes.split_at(ML_KEM_D_LEN);
                // SAFETY: U1; U3, `d` and `z` are the 32 bytes read each,
                // the two parts of the 64-byte seed; `ek` and `dk.bytes` the
                // documented writable lengths, `dk` owned by the zeroing type.
                let code = unsafe {
                    $c_expand_key(
                        d.as_ptr(),
                        z.as_ptr(),
                        ek.as_mut_ptr(),
                        dk.bytes.as_mut_ptr(),
                    )
                };
                check(code)?;
                Ok((ek, dk))
            }

            #[doc = concat!(
                "ML-KEM-", $set, " encapsulation against `ek` (FIPS 203 Algorithm 20): ",
                "the module checks `ek` (FIPS 203 §7.2) and draws `m` from `rbg`. Calls ",
                "`oxi_ml_kem_", $set, "_encapsulate_rbg`.\n\n",
                "An `ek` that fails the check is [`Error::InvalidInput`], with nothing ",
                "drawn."
            )]
            $(#[doc = concat!(
                "A DRBG below ", $bits, " bits of security strength is ",
                "[`Error::RbgTooWeak`], with nothing drawn."
            )])?
            #[doc = rbg_errors_doc!()]
            #[doc = concat!(
                "A profile that does not admit the parameter set or the DRBG is ",
                "[`Error::AlgorithmRestricted`]."
            )]
            pub fn $encapsulate(
                self,
                ek: &$Ek,
                rbg: &mut Drbg,
            ) -> Result<(SharedSecret, $Ct), Error> {
                let mut ss = SharedSecret::zeroed();
                let mut ct = [0u8; crate::$ct_len];
                // SAFETY: U1; U4 for `rbg`; U3, `ek` is the length read, fixed
                // by its type; `ss` and `ct` are the documented writable
                // lengths, `ss` owned by the zeroing type.
                let code = unsafe {
                    $c_encapsulate(
                        ek.as_ptr(),
                        rbg.ptr.as_ptr(),
                        ss.bytes.as_mut_ptr(),
                        ct.as_mut_ptr(),
                    )
                };
                check(code)?;
                Ok((ss, ct))
            }

            #[doc = concat!(
                "ML-KEM-", $set, " decapsulation (FIPS 203 Algorithm 21). The module ",
                "checks `dk` (FIPS 203 §7.3) and refuses one that fails with ",
                "[`Error::InvalidInput`]. A modified ciphertext is not an error: the ",
                "scheme returns an implicit-rejection secret (FIPS 203 §6.3)."
            )]
            pub fn $decapsulate(self, dk: &$Dk, ct: &$Ct) -> Result<SharedSecret, Error> {
                let mut ss = SharedSecret::zeroed();
                // SAFETY: U1; U3, `dk.bytes` and `ct` are the lengths read,
                // fixed by their types; `ss` the 32 written, owned by the
                // zeroing type.
                let code = unsafe {
                    $c_decapsulate(dk.bytes.as_ptr(), ct.as_ptr(), ss.bytes.as_mut_ptr())
                };
                check(code)?;
                Ok(ss)
            }
        }
    };
}

ml_dsa_wrappers! {
    set: "44",
    strength: "192",
    seed: MlDsa44Seed,
    public_key: MlDsa44PublicKey = ML_DSA_44_PUBLIC_KEY_LEN,
    secret_key: MlDsa44SecretKey,
    signature: MlDsa44Signature = ML_DSA_44_SIGNATURE_LEN,
    keygen: ml_dsa_44_keygen => sys::oxi_ml_dsa_44_keygen_rbg,
    keygen_with_seed: ml_dsa_44_keygen_with_seed,
    expand_key: ml_dsa_44_expand_key => sys::oxi_ml_dsa_44_expand_key,
    sign: ml_dsa_44_sign => sys::oxi_ml_dsa_44_sign,
    verify: ml_dsa_44_verify => sys::oxi_ml_dsa_44_verify,
}

ml_dsa_wrappers! {
    set: "65",
    strength: "192",
    seed: MlDsa65Seed,
    public_key: MlDsa65PublicKey = ML_DSA_65_PUBLIC_KEY_LEN,
    secret_key: MlDsa65SecretKey,
    signature: MlDsa65Signature = ML_DSA_65_SIGNATURE_LEN,
    keygen: ml_dsa_65_keygen => sys::oxi_ml_dsa_65_keygen_rbg,
    keygen_with_seed: ml_dsa_65_keygen_with_seed,
    expand_key: ml_dsa_65_expand_key => sys::oxi_ml_dsa_65_expand_key,
    sign: ml_dsa_65_sign => sys::oxi_ml_dsa_65_sign,
    verify: ml_dsa_65_verify => sys::oxi_ml_dsa_65_verify,
}

ml_dsa_wrappers! {
    set: "87",
    strength: "256",
    seed: MlDsa87Seed,
    public_key: MlDsa87PublicKey = ML_DSA_87_PUBLIC_KEY_LEN,
    secret_key: MlDsa87SecretKey,
    signature: MlDsa87Signature = ML_DSA_87_SIGNATURE_LEN,
    keygen: ml_dsa_87_keygen => sys::oxi_ml_dsa_87_keygen_rbg,
    keygen_with_seed: ml_dsa_87_keygen_with_seed,
    expand_key: ml_dsa_87_expand_key => sys::oxi_ml_dsa_87_expand_key,
    sign: ml_dsa_87_sign => sys::oxi_ml_dsa_87_sign,
    verify: ml_dsa_87_verify => sys::oxi_ml_dsa_87_verify,
}

ml_kem_wrappers! {
    set: "512",
    seed: MlKem512Seed,
    encapsulation_key: MlKem512EncapsulationKey = ML_KEM_512_ENCAPSULATION_KEY_LEN,
    decapsulation_key: MlKem512DecapsulationKey,
    ciphertext: MlKem512Ciphertext = ML_KEM_512_CIPHERTEXT_LEN,
    keygen: ml_kem_512_keygen => sys::oxi_ml_kem_512_keygen_rbg,
    keygen_with_seed: ml_kem_512_keygen_with_seed,
    expand_key: ml_kem_512_expand_key => sys::oxi_ml_kem_512_expand_key,
    encapsulate: ml_kem_512_encapsulate => sys::oxi_ml_kem_512_encapsulate_rbg,
    decapsulate: ml_kem_512_decapsulate => sys::oxi_ml_kem_512_decapsulate,
}

ml_kem_wrappers! {
    set: "768",
    strength: "192",
    seed: MlKem768Seed,
    encapsulation_key: MlKem768EncapsulationKey = ML_KEM_768_ENCAPSULATION_KEY_LEN,
    decapsulation_key: MlKem768DecapsulationKey,
    ciphertext: MlKem768Ciphertext = ML_KEM_768_CIPHERTEXT_LEN,
    keygen: ml_kem_768_keygen => sys::oxi_ml_kem_768_keygen_rbg,
    keygen_with_seed: ml_kem_768_keygen_with_seed,
    expand_key: ml_kem_768_expand_key => sys::oxi_ml_kem_768_expand_key,
    encapsulate: ml_kem_768_encapsulate => sys::oxi_ml_kem_768_encapsulate_rbg,
    decapsulate: ml_kem_768_decapsulate => sys::oxi_ml_kem_768_decapsulate,
}

ml_kem_wrappers! {
    set: "1024",
    strength: "256",
    seed: MlKem1024Seed,
    encapsulation_key: MlKem1024EncapsulationKey = ML_KEM_1024_ENCAPSULATION_KEY_LEN,
    decapsulation_key: MlKem1024DecapsulationKey,
    ciphertext: MlKem1024Ciphertext = ML_KEM_1024_CIPHERTEXT_LEN,
    keygen: ml_kem_1024_keygen => sys::oxi_ml_kem_1024_keygen_rbg,
    keygen_with_seed: ml_kem_1024_keygen_with_seed,
    expand_key: ml_kem_1024_expand_key => sys::oxi_ml_kem_1024_expand_key,
    encapsulate: ml_kem_1024_encapsulate => sys::oxi_ml_kem_1024_encapsulate_rbg,
    decapsulate: ml_kem_1024_decapsulate => sys::oxi_ml_kem_1024_decapsulate,
}

/// The IV and tag of one AES-GCM encryption, both public once the encryption
/// has run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcmSealed {
    /// The 96-bit IV the module drew from the DRBG for this encryption.
    pub iv: [u8; AES_GCM_IV_LEN],
    /// The 128-bit authentication tag.
    pub tag: [u8; AES_GCM_TAG_LEN],
}

/// An AES-GCM key held by the library with its count of encryptions,
/// built by [`Module::aes_gcm_key`] and its `_with_count` and `_with_limit`
/// forms.
///
/// Freed exactly once, when dropped; the library zeroes the key schedule.
pub struct AesGcmKey {
    ptr: NonNull<sys::OxiAesGcmKey>,
}

// SAFETY: U7, the header's contract on `OxiAesGcmKey`: any number of
// threads may use one handle at once, and only `_key_free`, called once from
// `Drop`, needs it unshared.
unsafe impl Send for AesGcmKey {}
// SAFETY: U7, as for `Send`.
unsafe impl Sync for AesGcmKey {}

impl Drop for AesGcmKey {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `_key_new` of this mode, is
        // private to this type and is freed only here.
        unsafe { sys::oxi_aes_gcm_key_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for AesGcmKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesGcmKey")
    }
}

/// An AES-CCM key held by the library with its tag length and its count
/// of block-cipher invocations, built by [`Module::aes_ccm_key`] and
/// [`Module::aes_ccm_key_with_count`].
///
/// Freed exactly once, when dropped; the library zeroes the key schedule.
pub struct AesCcmKey {
    ptr: NonNull<sys::OxiAesCcmKey>,
    tag_len: usize,
}

// SAFETY: U7, the header's contract on `OxiAesCcmKey`: any number of
// threads may use one handle at once, and only `_key_free`, called once from
// `Drop`, needs it unshared.
unsafe impl Send for AesCcmKey {}
// SAFETY: U7, as for `Send`.
unsafe impl Sync for AesCcmKey {}

impl Drop for AesCcmKey {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `_key_new` of this mode, is
        // private to this type and is freed only here.
        unsafe { sys::oxi_aes_ccm_key_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for AesCcmKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesCcmKey")
    }
}

impl AesCcmKey {
    /// The tag length fixed for the key, in bytes.
    #[must_use]
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
}

/// An AES-CBC key held by the library, built by [`Module::aes_cbc_key`].
///
/// Freed exactly once, when dropped; the library zeroes the key schedule.
pub struct AesCbcKey {
    ptr: NonNull<sys::OxiAesCbcKey>,
}

// SAFETY: U7, the header's contract on `OxiAesCbcKey`: any number of
// threads may use one handle at once, and only `_key_free`, called once from
// `Drop`, needs it unshared.
unsafe impl Send for AesCbcKey {}
// SAFETY: U7, as for `Send`.
unsafe impl Sync for AesCbcKey {}

impl Drop for AesCbcKey {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `_key_new` of this mode, is
        // private to this type and is freed only here.
        unsafe { sys::oxi_aes_cbc_key_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for AesCbcKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesCbcKey")
    }
}

/// An AES-CTR key held by the library, built by [`Module::aes_ctr_key`].
///
/// Freed exactly once, when dropped; the library zeroes the key schedule.
pub struct AesCtrKey {
    ptr: NonNull<sys::OxiAesCtrKey>,
}

// SAFETY: U7, the header's contract on `OxiAesCtrKey`: any number of
// threads may use one handle at once, and only `_key_free`, called once from
// `Drop`, needs it unshared.
unsafe impl Send for AesCtrKey {}
// SAFETY: U7, as for `Send`.
unsafe impl Sync for AesCtrKey {}

impl Drop for AesCtrKey {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `_key_new` of this mode, is
        // private to this type and is freed only here.
        unsafe { sys::oxi_aes_ctr_key_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for AesCtrKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesCtrKey")
    }
}

/// An AES key-wrap key held by the library, for KW and KWP with the
/// forward and the inverse cipher, built by [`Module::aes_kw_key`].
///
/// Freed exactly once, when dropped; the library zeroes the key schedule.
pub struct AesKwKey {
    ptr: NonNull<sys::OxiAesKwKey>,
}

// SAFETY: U7, the header's contract on `OxiAesKwKey`: any number of
// threads may use one handle at once, and only `_key_free`, called once from
// `Drop`, needs it unshared.
unsafe impl Send for AesKwKey {}
// SAFETY: U7, as for `Send`.
unsafe impl Sync for AesKwKey {}

impl Drop for AesKwKey {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `_key_new` of this mode, is
        // private to this type and is freed only here.
        unsafe { sys::oxi_aes_kw_key_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for AesKwKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesKwKey")
    }
}

/// A CMAC key held by the library with its MAC length, built by
/// [`Module::aes_cmac_key`].
///
/// Freed exactly once, when dropped; the library zeroes the key schedule.
pub struct AesCmacKey {
    ptr: NonNull<sys::OxiAesCmacKey>,
    mac_len: usize,
}

// SAFETY: U7, the header's contract on `OxiAesCmacKey`: any number of
// threads may use one handle at once, and only `_key_free`, called once from
// `Drop`, needs it unshared.
unsafe impl Send for AesCmacKey {}
// SAFETY: U7, as for `Send`.
unsafe impl Sync for AesCmacKey {}

impl Drop for AesCmacKey {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `_key_new` of this mode, is
        // private to this type and is freed only here.
        unsafe { sys::oxi_aes_cmac_key_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for AesCmacKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesCmacKey")
    }
}

impl AesCmacKey {
    /// The MAC length fixed for the key, in bytes.
    #[must_use]
    pub fn mac_len(&self) -> usize {
        self.mac_len
    }
}

/// The SP 800-90A mechanism and primitive a [`Drbg`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrbgKind {
    /// HMAC_DRBG with SHA-256.
    HmacSha256,
    /// HMAC_DRBG with SHA-384.
    HmacSha384,
    /// HMAC_DRBG with SHA-512.
    HmacSha512,
    /// Hash_DRBG with SHA-256.
    HashSha256,
    /// Hash_DRBG with SHA-384.
    HashSha384,
    /// Hash_DRBG with SHA-512.
    HashSha512,
    /// CTR_DRBG with AES-128 and the derivation function.
    CtrAes128,
    /// CTR_DRBG with AES-192 and the derivation function.
    CtrAes192,
    /// CTR_DRBG with AES-256 and the derivation function.
    CtrAes256,
}

/// One of the module's SP 800-90A DRBGs, held by the library and seeded by
/// the module from its own entropy source.
///
/// Created uninstantiated by [`Module::drbg`]; [`instantiate`](Self::instantiate)
/// draws its entropy input and nonce from the module's seed path. Freed
/// exactly once, when dropped; the library wipes the state.
///
/// A `Drbg` can move to another thread but not be shared between threads,
/// since every call that changes its state takes `&mut self`:
/// ```compile_fail,E0277
/// fn share(drbg: &oxicrypt::Drbg) {
///     std::thread::scope(|s| {
///         s.spawn(|| drbg.strength_bits());
///         s.spawn(|| drbg.strength_bits());
///     });
/// }
/// ```
pub struct Drbg {
    ptr: NonNull<sys::OxiDrbg>,
}

// SAFETY: U7, the library-side state is changed only through `&mut self`, so
// moving the handle to another thread moves its sole user.
unsafe impl Send for Drbg {}

impl Drbg {
    /// Instantiates from the module's seed path with the personalization
    /// string `perso`, replacing any earlier instantiation. An empty `perso`
    /// is passed as absent.
    ///
    /// A personalization string longer than the DRBG accepts returns
    /// [`Error::InvalidInput`]; a failed draw returns [`Error::Busy`] (retry
    /// after a pause) or [`Error::EntropyUnavailable`], and leaves the handle
    /// as it was. In a child process after `fork`, this is the call that
    /// makes an inherited handle usable again.
    pub fn instantiate(&mut self, perso: &[u8]) -> Result<(), Error> {
        // SAFETY: U1; U4 for the handle; U2 for `perso`.
        let code =
            unsafe { sys::oxi_drbg_instantiate(self.ptr.as_ptr(), input(perso), perso.len()) };
        check(code)
    }

    /// Reseeds from the module's seed path with the additional input
    /// `additional`. An empty `additional` is passed as absent.
    pub fn reseed(&mut self, additional: &[u8]) -> Result<(), Error> {
        // SAFETY: U1; U4 for the handle; U2 for `additional`.
        let code =
            unsafe { sys::oxi_drbg_reseed(self.ptr.as_ptr(), input(additional), additional.len()) };
        check(code)
    }

    /// Generates `out.len()` bytes into `out`, with the additional input
    /// `additional`. An empty `additional` is passed as absent. `out` is
    /// zeroed on every error. The DRBG reseeds itself from the module's seed
    /// path when it reaches its reseed interval.
    ///
    /// A request over [`HMAC_DRBG_MAX_REQUEST_LEN`] is refused with
    /// [`Error::OutputTooLong`] before the library is called.
    pub fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<(), Error> {
        if out.len() > HMAC_DRBG_MAX_REQUEST_LEN {
            wipe(out);
            return Err(Error::OutputTooLong);
        }
        // SAFETY: U1; U4 for the handle; U2 for `additional`; U9, `out` has
        // `out.len()` writable bytes, bounded above, and that is the length
        // passed.
        let code = unsafe {
            sys::oxi_drbg_generate(
                self.ptr.as_ptr(),
                input(additional),
                additional.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        status_or_wipe(code, Site::Other, out)
    }

    /// The security strength of the instantiated DRBG, in bits.
    /// [`Error::Uninstantiated`] before the first successful
    /// [`instantiate`](Self::instantiate).
    pub fn strength_bits(&self) -> Result<u32, Error> {
        let mut bits = 0u32;
        // SAFETY: U1; U4 for the handle; `out` points to a live local.
        let code = unsafe { sys::oxi_drbg_strength_bits(self.ptr.as_ptr(), &raw mut bits) };
        check(code)?;
        Ok(bits)
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `_new_rbg`, is private to
        // this type and is freed only here.
        unsafe { sys::oxi_drbg_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for Drbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Drbg")
    }
}
