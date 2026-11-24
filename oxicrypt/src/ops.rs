//! The wrapped services.

use core::ffi::{CStr, c_char, c_int};
use core::ptr::{self, NonNull};

use crate::error::{Error, Site, status};
use crate::module::{Module, check};
use crate::secret::{
    HkdfPrk, MlDsa87KeySeed, MlDsa87SecretKey, MlKem1024DecapsulationKey, MlKem1024EncapsSeed,
    MlKem1024KeySeedD, MlKem1024KeySeedZ, Okm, SharedSecret, wipe,
};
use crate::sys;
use crate::{
    AES256_GCM_NONCE_LEN, AES256_GCM_TAG_LEN, AES256_KEY_LEN, HKDF_SHA384_MAX_OKM_LEN,
    HMAC_DRBG_MAX_REQUEST_LEN, MlDsa87PublicKey, MlDsa87Signature, MlKem1024Ciphertext,
    MlKem1024EncapsulationKey, SHA384_LEN,
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

    /// An AES-256 key handle holding the library's key schedule for `key`.
    pub fn aes256_key(self, key: &[u8; AES256_KEY_LEN]) -> Result<Aes256Key, Error> {
        let mut handle: *mut sys::OxiAes256Key = ptr::null_mut();
        // SAFETY: U1; `out_handle` points to a live local; U2, `key` is
        // AES256_KEY_LEN readable bytes.
        let code = unsafe { sys::oxi_aes256_new(&raw mut handle, key.as_ptr()) };
        check(code)?;
        NonNull::new(handle)
            .map(|ptr| Aes256Key { ptr })
            .ok_or(Error::NullPointer)
    }

    /// AES-256-GCM encryption of `plaintext` into `ciphertext_out`, which must
    /// be the same length. Returns the tag.
    ///
    /// A length mismatch is refused with [`Error::LengthMismatch`], a plaintext
    /// over 2^36 − 32 bytes with [`Error::InvalidPayloadLength`] and additional
    /// data over 2^61 − 1 bytes with [`Error::InvalidAadLength`]
    /// (SP 800-38D §5.2.1.1), each before the library is called.
    /// `ciphertext_out` is zeroed on every error.
    pub fn aes256_gcm_encrypt(
        self,
        key: &Aes256Key,
        nonce: &[u8; AES256_GCM_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
    ) -> Result<[u8; AES256_GCM_TAG_LEN], Error> {
        if let Err(e) = gcm_lengths(plaintext.len(), aad.len()) {
            wipe(ciphertext_out);
            return Err(e);
        }
        if ciphertext_out.len() != plaintext.len() {
            wipe(ciphertext_out);
            return Err(Error::LengthMismatch);
        }
        let mut tag = [0u8; AES256_GCM_TAG_LEN];
        // SAFETY: U1; U4 for `key`; U2 for `nonce`, `aad` and `plaintext`;
        // U9, `ciphertext_out` has `plaintext.len()` writable bytes, checked
        // above; U3, `tag` is AES256_GCM_TAG_LEN writable bytes.
        let code = unsafe {
            sys::oxi_aes256_gcm_encrypt(
                key.ptr.as_ptr(),
                nonce.as_ptr(),
                input(aad),
                aad.len(),
                input(plaintext),
                plaintext.len(),
                ciphertext_out.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        // A correct library refuses an encryption only before writing to the
        // output; the wipe covers one that does not, as the control tests
        // provoke with an overriding shared object.
        status_or_wipe(code, Site::Other, ciphertext_out)?;
        Ok(tag)
    }

    /// AES-256-GCM decryption of `ciphertext` into `plaintext_out`, which
    /// must be the same length.
    ///
    /// A tag that does not verify is [`Error::TagMismatch`]. A length
    /// mismatch is refused with [`Error::LengthMismatch`], and inputs over the
    /// SP 800-38D limits as for encryption, before the library is called. `plaintext_out` is zeroed on every error, so nothing the
    /// library wrote before refusing the tag is left in it.
    pub fn aes256_gcm_decrypt(
        self,
        key: &Aes256Key,
        nonce: &[u8; AES256_GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext_out: &mut [u8],
        tag: &[u8; AES256_GCM_TAG_LEN],
    ) -> Result<(), Error> {
        if let Err(e) = gcm_lengths(ciphertext.len(), aad.len()) {
            wipe(plaintext_out);
            return Err(e);
        }
        if plaintext_out.len() != ciphertext.len() {
            wipe(plaintext_out);
            return Err(Error::LengthMismatch);
        }
        // SAFETY: U1; U4 for `key`; U2 for `nonce`, `aad`, `ciphertext` and
        // `tag`; U9, `plaintext_out` has `ciphertext.len()` writable bytes,
        // checked above.
        let code = unsafe {
            sys::oxi_aes256_gcm_decrypt(
                key.ptr.as_ptr(),
                nonce.as_ptr(),
                input(aad),
                aad.len(),
                input(ciphertext),
                ciphertext.len(),
                plaintext_out.as_mut_ptr(),
                tag.as_ptr(),
            )
        };
        status_or_wipe(code, Site::AeadDecrypt, plaintext_out)
    }

    /// [`Module::aes256_gcm_encrypt`] into a new vector.
    pub fn aes256_gcm_encrypt_vec(
        self,
        key: &Aes256Key,
        nonce: &[u8; AES256_GCM_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; AES256_GCM_TAG_LEN]), Error> {
        // Before the allocation, which an over-limit input would make huge.
        gcm_lengths(plaintext.len(), aad.len())?;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let tag = self.aes256_gcm_encrypt(key, nonce, aad, plaintext, &mut ciphertext)?;
        Ok((ciphertext, tag))
    }

    /// [`Module::aes256_gcm_decrypt`] into a new vector, which is zeroed
    /// before it is freed on an error.
    pub fn aes256_gcm_decrypt_vec(
        self,
        key: &Aes256Key,
        nonce: &[u8; AES256_GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AES256_GCM_TAG_LEN],
    ) -> Result<Vec<u8>, Error> {
        // Before the allocation, which an over-limit input would make huge.
        gcm_lengths(ciphertext.len(), aad.len())?;
        let mut plaintext = vec![0u8; ciphertext.len()];
        self.aes256_gcm_decrypt(key, nonce, aad, ciphertext, &mut plaintext, tag)?;
        Ok(plaintext)
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

    /// ML-DSA-87 key generation from a 32-byte seed (FIPS 204 §6.1).
    ///
    /// The key is generated inside the module. Its approved status depends
    /// on where the seed came from; a seed passed to
    /// [`MlDsa87KeySeed::from_bytes`] comes from outside the module. The seed
    /// is consumed and zeroed.
    pub fn ml_dsa_87_keygen(
        self,
        seed: MlDsa87KeySeed,
    ) -> Result<(MlDsa87PublicKey, MlDsa87SecretKey), Error> {
        let mut pk = [0u8; crate::ML_DSA_87_PUBLIC_KEY_LEN];
        let mut sk = MlDsa87SecretKey::zeroed();
        // SAFETY: U1; U3, `seed.bytes` is 32 readable bytes, `pk` and
        // `sk.bytes` are the documented writable lengths, `sk` owned by the
        // zeroing type.
        let code = unsafe {
            sys::oxi_ml_dsa_87_keygen(seed.bytes.as_ptr(), pk.as_mut_ptr(), sk.bytes.as_mut_ptr())
        };
        // The seed is used once: zeroed here, whatever the status.
        drop(seed);
        check(code)?;
        Ok((pk, sk))
    }

    /// Deterministic ML-DSA-87 signature of `msg` under context `ctx`
    /// (FIPS 204 §5.2). The library refuses a context over 255 bytes with
    /// [`Error::InvalidInput`].
    pub fn ml_dsa_87_sign(
        self,
        sk: &MlDsa87SecretKey,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<MlDsa87Signature, Error> {
        let mut sig = [0u8; crate::ML_DSA_87_SIGNATURE_LEN];
        // SAFETY: U1; U3, `sk.bytes` is the 4,896 bytes read and `sig` the
        // 4,627 written; U2 for `msg` and `ctx`.
        let code = unsafe {
            sys::oxi_ml_dsa_87_sign(
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

    /// ML-DSA-87 verification (FIPS 204 §5.3). A signature that does not
    /// verify, and a signature or key that does not decode, are both
    /// [`Error::SignatureInvalid`].
    pub fn ml_dsa_87_verify(
        self,
        pk: &MlDsa87PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &MlDsa87Signature,
    ) -> Result<(), Error> {
        // SAFETY: U1; U3, `pk` and `sig` are the 2,592 and 4,627 bytes the
        // function reads, fixed by their types; U2 for `msg` and `ctx`.
        let code = unsafe {
            sys::oxi_ml_dsa_87_verify(
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

    /// ML-KEM-1024 key generation from seeds `d` and `z` (FIPS 203 §6.1),
    /// with the same note on seed provenance as
    /// [`Module::ml_dsa_87_keygen`]. Both seeds are consumed and zeroed.
    pub fn ml_kem_1024_keygen(
        self,
        d: MlKem1024KeySeedD,
        z: MlKem1024KeySeedZ,
    ) -> Result<(MlKem1024EncapsulationKey, MlKem1024DecapsulationKey), Error> {
        let mut ek = [0u8; crate::ML_KEM_1024_ENCAPSULATION_KEY_LEN];
        let mut dk = MlKem1024DecapsulationKey::zeroed();
        // SAFETY: U1; U3, `d` and `z` are 32 readable bytes each, `ek` and
        // `dk.bytes` the documented writable lengths, `dk` owned by the
        // zeroing type.
        let code = unsafe {
            sys::oxi_ml_kem_1024_keygen(
                d.bytes.as_ptr(),
                z.bytes.as_ptr(),
                ek.as_mut_ptr(),
                dk.bytes.as_mut_ptr(),
            )
        };
        // The seeds are used once: zeroed here, whatever the status.
        drop((d, z));
        check(code)?;
        Ok((ek, dk))
    }

    /// ML-KEM-1024 encapsulation against `ek` with randomness `m`
    /// (FIPS 203 §6.2). `m` is consumed and zeroed, so one value cannot
    /// serve two encapsulations.
    pub fn ml_kem_1024_encapsulate(
        self,
        ek: &MlKem1024EncapsulationKey,
        m: MlKem1024EncapsSeed,
    ) -> Result<(SharedSecret, MlKem1024Ciphertext), Error> {
        let mut ss = SharedSecret::zeroed();
        let mut ct = [0u8; crate::ML_KEM_1024_CIPHERTEXT_LEN];
        // SAFETY: U1; U3, `ek` is the 1,568 bytes read and `m` the 32; `ss`
        // and `ct` are the documented writable lengths, `ss` owned by the
        // zeroing type.
        let code = unsafe {
            sys::oxi_ml_kem_1024_encapsulate(
                ek.as_ptr(),
                m.bytes.as_ptr(),
                ss.bytes.as_mut_ptr(),
                ct.as_mut_ptr(),
            )
        };
        // The seed is used once: zeroed here, whatever the status.
        drop(m);
        check(code)?;
        Ok((ss, ct))
    }

    /// ML-KEM-1024 decapsulation (FIPS 203 §6.3). A modified ciphertext is
    /// not an error: the scheme returns an implicit-rejection secret.
    pub fn ml_kem_1024_decapsulate(
        self,
        dk: &MlKem1024DecapsulationKey,
        ct: &MlKem1024Ciphertext,
    ) -> Result<SharedSecret, Error> {
        let mut ss = SharedSecret::zeroed();
        // SAFETY: U1; U3, `dk.bytes` and `ct` are the 3,168 and 1,568 bytes
        // read, `ss` the 32 written, owned by the zeroing type.
        let code = unsafe {
            sys::oxi_ml_kem_1024_decapsulate(dk.bytes.as_ptr(), ct.as_ptr(), ss.bytes.as_mut_ptr())
        };
        check(code)?;
        Ok(ss)
    }
}

/// An AES-256 key schedule held by the library.
///
/// Freed exactly once, when dropped; the library zeroes the schedule.
pub struct Aes256Key {
    ptr: NonNull<sys::OxiAes256Key>,
}

// SAFETY: U7, the handle holds only the key schedule, every mode function
// takes it by `const` pointer, and the library keeps no per-call state in it.
unsafe impl Send for Aes256Key {}
// SAFETY: U7, as for `Send`.
unsafe impl Sync for Aes256Key {}

impl Drop for Aes256Key {
    fn drop(&mut self) {
        // SAFETY: U4, `ptr` came from a successful `oxi_aes256_new`, is
        // private to this type and is freed only here.
        unsafe { sys::oxi_aes256_free(self.ptr.as_ptr()) };
    }
}

impl core::fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Aes256Key")
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
