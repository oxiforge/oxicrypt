//! Every wrapped service against the signed library under the CNSA 2.0
//! profile, with known answers from published vectors. Every test in this
//! binary initialises with `Profile::Cnsa2`; tests needing another profile
//! are in `unrestricted.rs`.

#![cfg(oxicrypt_lib)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{acvp, array, init};
use oxicrypt::{
    Drbg, DrbgKind, Error, HKDF_SHA384_MAX_OKM_LEN, IntegrityStatus, MlDsa44SecretKey, MlDsa44Seed,
    MlDsa65SecretKey, MlDsa65Seed, MlDsa87SecretKey, MlDsa87Seed, MlKem512DecapsulationKey,
    MlKem512Seed, MlKem768DecapsulationKey, MlKem768Seed, MlKem1024DecapsulationKey, MlKem1024Seed,
    Module, Profile,
};

fn module() -> Module {
    init(Profile::Cnsa2).expect("the signed fixture library initialises under CNSA 2.0")
}

// ----- initialisation -----

#[test]
fn the_signed_library_initialises_and_reports_itself() {
    let m = module();
    assert!(m.is_operational());
    assert_eq!(m.integrity_status(), IntegrityStatus::Passed);
    let found = m.key_fingerprint().unwrap().to_string();
    assert_eq!(found, common::fixture_fingerprint());
    let path = Module::library_path().expect("the loader names the library");
    assert_eq!(
        path.canonicalize().unwrap(),
        common::lib_dir()
            .join("liboxicrypt_ffi.so")
            .canonicalize()
            .unwrap()
    );
}

#[test]
fn init_is_idempotent_and_a_mismatch_poisons_nothing() {
    module();
    let refused = init(Profile::Unrestricted).unwrap_err();
    assert_eq!(
        refused.code,
        Error::ProfileMismatch {
            active: Profile::Cnsa2,
            requested: Profile::Unrestricted
        }
    );
    assert_eq!(refused.integrity, Some(IntegrityStatus::Passed));
    module();
}

// ----- SHA-384 -----

#[test]
fn sha384_known_answers() {
    let m = module();
    // NIST CAVP SHA384ShortMsg.rsp, Len = 8, via oxicrypt-test-vectors.
    assert_eq!(
        m.sha384(&oxicrypt_test_vectors::SHA_384_MSG).unwrap(),
        oxicrypt_test_vectors::SHA_384_MD
    );
    // The empty message, passed to the library as NULL with length 0, as
    // `printf '' | sha384sum` prints it.
    assert_eq!(
        m.sha384(b"").unwrap(),
        array::<48>(&common::unhex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
             4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        ))
    );
    // FIPS 180-4 example "abc", as `printf abc | sha384sum` prints it.
    assert_eq!(
        m.sha384(b"abc").unwrap(),
        array::<48>(&common::unhex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
             1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        ))
    );
}

// ----- HKDF-SHA384 -----

#[test]
fn hkdf_sha384_known_answer() {
    // NIST ACVP KDA-HKDF-Sp800-56Cr2, HMAC-SHA2-384, L = 1024 bits, via
    // oxicrypt-test-vectors (vendor/nist/acvp-server/.../KDA-HKDF-Sp800-56Cr2).
    use oxicrypt_test_vectors::{
        HKDF_SHA2_384_FIXED_INFO, HKDF_SHA2_384_IKM, HKDF_SHA2_384_KEY_OUT, HKDF_SHA2_384_SALT,
    };
    let m = module();
    let prk = m
        .hkdf_sha384_extract(Some(&HKDF_SHA2_384_SALT), &HKDF_SHA2_384_IKM)
        .unwrap();
    let okm = m
        .hkdf_sha384_expand(&prk, &HKDF_SHA2_384_FIXED_INFO, HKDF_SHA2_384_KEY_OUT.len())
        .unwrap();
    assert_eq!(okm.as_bytes(), HKDF_SHA2_384_KEY_OUT);
}

#[test]
fn hkdf_sha384_output_bound() {
    let m = module();
    let prk = m.hkdf_sha384_extract(None, b"ikm").unwrap();
    assert_eq!(
        m.hkdf_sha384_expand(&prk, b"", HKDF_SHA384_MAX_OKM_LEN)
            .unwrap()
            .as_bytes()
            .len(),
        HKDF_SHA384_MAX_OKM_LEN
    );
    assert_eq!(
        m.hkdf_sha384_expand(&prk, b"", HKDF_SHA384_MAX_OKM_LEN + 1)
            .unwrap_err(),
        Error::OutputTooLong
    );
    // The crate refuses before allocating: a request this large, allocated,
    // would abort the process rather than return.
    assert_eq!(
        m.hkdf_sha384_expand(&prk, b"", usize::MAX >> 2)
            .unwrap_err(),
        Error::OutputTooLong
    );
    assert_eq!(
        m.hkdf_sha384_expand(&prk, b"", usize::MAX).unwrap_err(),
        Error::OutputTooLong
    );
}

// ----- AES-GCM -----

// McGrew & Viega, "The Galois/Counter Mode of Operation", Appendix B, Test
// Case 15 (AES-256, 64-byte plaintext, no AAD); the same values are the
// module's GCM self-test in crates/oxicrypt-aes/src/kat.rs.
const GCM256_KEY: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const GCM_IV: &str = "cafebabefacedbaddecaf888";
const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                      1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const GCM256_CT: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
const GCM256_TAG: &str = "b094dac5d93471bdec1a502270e3cc6c";

type GcmCase = ([u8; 32], [u8; 12], Vec<u8>, Vec<u8>, [u8; 16]);

type CcmFault<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8]);

fn gcm_inputs() -> GcmCase {
    (
        array(&common::unhex(GCM256_KEY)),
        array(&common::unhex(GCM_IV)),
        common::unhex(GCM_PT),
        common::unhex(GCM256_CT),
        array(&common::unhex(GCM256_TAG)),
    )
}

fn cnsa2_drbg(m: Module) -> Drbg {
    let mut drbg = m.drbg(DrbgKind::HmacSha512).unwrap();
    drbg.instantiate(b"gcm").unwrap();
    drbg
}

#[test]
fn aes_gcm_open_known_answer() {
    let m = module();
    let (key, iv, pt, ct, tag) = gcm_inputs();
    let key = m.aes_gcm_key(&key).unwrap();
    let mut back = vec![0u8; ct.len()];
    m.aes_gcm_open(&key, &iv, &[], &ct, &tag, &mut back)
        .unwrap();
    assert_eq!(back, pt);
    assert_eq!(m.aes_gcm_open_vec(&key, &iv, &[], &ct, &tag).unwrap(), pt);
}

/// The module draws the IV, so encryption has no known answer: a sealed
/// message opens under the IV and tag returned, two seals of one plaintext
/// draw different IVs, and each seal counts once against the key.
#[test]
fn aes_gcm_seal_round_trips_under_a_drawn_iv() {
    let m = module();
    let (key, _, pt, _, _) = gcm_inputs();
    let key = m.aes_gcm_key(&key).unwrap();
    let mut drbg = cnsa2_drbg(m);
    assert_eq!(m.aes_gcm_invocations(&key), Ok(0));
    let mut ct = vec![0xAAu8; pt.len()];
    let sealed = m
        .aes_gcm_seal(&key, &mut drbg, b"aad", &pt, &mut ct)
        .unwrap();
    assert_ne!(ct, pt);
    assert_eq!(
        m.aes_gcm_open_vec(&key, &sealed.iv, b"aad", &ct, &sealed.tag)
            .unwrap(),
        pt
    );
    let (ct2, sealed2) = m.aes_gcm_seal_vec(&key, &mut drbg, b"aad", &pt).unwrap();
    assert_ne!(sealed.iv, sealed2.iv);
    assert_ne!(ct, ct2);
    assert_eq!(m.aes_gcm_invocations(&key), Ok(2));
}

/// A key at its limit refuses the next encryption with `KeyExhausted` and
/// zeroes the output, as does a key preloaded to 2^32. Whether the refusal
/// draws from the DRBG is not observable through the crate; the
/// `oxicrypt-aes` test `gcm_key_exhausts_at_2_32` pins that no IV is drawn.
#[test]
fn aes_gcm_key_at_its_limit_is_exhausted_and_zeroes_its_output() {
    let m = module();
    let mut drbg = cnsa2_drbg(m);
    let key = m.aes_gcm_key_with_limit(&[5; 32], 1).unwrap();
    let mut ct = [0u8; 4];
    m.aes_gcm_seal(&key, &mut drbg, &[], &[1; 4], &mut ct)
        .unwrap();
    let mut ct = [0xAAu8; 4];
    assert_eq!(
        m.aes_gcm_seal(&key, &mut drbg, &[], &[1; 4], &mut ct),
        Err(Error::KeyExhausted)
    );
    assert_eq!(ct, [0; 4]);
    assert_eq!(m.aes_gcm_invocations(&key), Ok(1));

    let full = m.aes_gcm_key_with_count(&[5; 32], 1 << 32).unwrap();
    assert_eq!(m.aes_gcm_invocations(&full), Ok(1 << 32));
    let mut ct = [0xAAu8; 4];
    assert_eq!(
        m.aes_gcm_seal(&full, &mut drbg, &[], &[1; 4], &mut ct),
        Err(Error::KeyExhausted)
    );
    assert_eq!(ct, [0; 4]);
    assert_eq!(
        m.aes_gcm_key_with_count(&[5; 32], (1 << 32) + 1)
            .unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        m.aes_gcm_key_with_limit(&[5; 32], 0).unwrap_err(),
        Error::InvalidInput
    );
}

/// A key built with a share of 3 encryptions seals three times and refuses
/// the fourth with `KeyExhausted`.
#[test]
fn aes_gcm_key_with_a_share_of_3_refuses_the_fourth_seal() {
    let m = module();
    let mut drbg = cnsa2_drbg(m);
    let key = m.aes_gcm_key_with_limit(&[6; 32], 3).unwrap();
    for n in 1..=3 {
        let mut ct = [0u8; 4];
        m.aes_gcm_seal(&key, &mut drbg, &[], &[1; 4], &mut ct)
            .unwrap_or_else(|e| panic!("seal {n}: {e:?}"));
        assert_eq!(m.aes_gcm_invocations(&key), Ok(n));
    }
    let mut ct = [0xAAu8; 4];
    assert_eq!(
        m.aes_gcm_seal(&key, &mut drbg, &[], &[1; 4], &mut ct),
        Err(Error::KeyExhausted)
    );
    assert_eq!(ct, [0; 4]);
    assert_eq!(m.aes_gcm_invocations(&key), Ok(3));
}

#[test]
fn aes_key_lengths_are_16_24_or_32_and_cnsa2_refuses_aes_128_and_192() {
    let m = module();
    assert_eq!(m.aes_gcm_key(&[1; 31]).unwrap_err(), Error::InvalidInput);
    assert_eq!(m.aes_gcm_key(&[]).unwrap_err(), Error::InvalidInput);
    for k in [&[1u8; 16][..], &[1u8; 24][..]] {
        let n = k.len();
        let restricted = Err(Error::AlgorithmRestricted);
        assert_eq!(m.aes_gcm_key(k).map(drop), restricted, "{n}");
        assert_eq!(m.aes_gcm_key_with_count(k, 0).map(drop), restricted, "{n}");
        assert_eq!(m.aes_gcm_key_with_limit(k, 1).map(drop), restricted, "{n}");
        assert_eq!(m.aes_ccm_key(k, 16).map(drop), restricted, "{n}");
        assert_eq!(
            m.aes_ccm_key_with_count(k, 16, 0).map(drop),
            restricted,
            "{n}"
        );
        assert_eq!(m.aes_cbc_key(k).map(drop), restricted, "{n}");
        assert_eq!(m.aes_ctr_key(k).map(drop), restricted, "{n}");
        assert_eq!(m.aes_kw_key(k).map(drop), restricted, "{n}");
        assert_eq!(m.aes_cmac_key(k, 16).map(drop), restricted, "{n}");
    }
}

#[test]
fn aes_gcm_seal_refuses_an_uninstantiated_drbg() {
    let m = module();
    let key = m.aes_gcm_key(&[1; 32]).unwrap();
    let mut never = m.drbg(DrbgKind::HmacSha512).unwrap();
    let mut ct = [0xAAu8; 4];
    assert_eq!(
        m.aes_gcm_seal(&key, &mut never, &[], &[1; 4], &mut ct),
        Err(Error::Uninstantiated)
    );
    assert_eq!(ct, [0; 4]);
}

#[test]
fn aes_gcm_tag_mismatch_wipes_the_output() {
    let m = module();
    let (key, iv, _, ct, mut tag) = gcm_inputs();
    let key = m.aes_gcm_key(&key).unwrap();
    tag[15] ^= 0x01;
    let mut out = vec![0xAAu8; ct.len()];
    assert_eq!(
        m.aes_gcm_open(&key, &iv, &[], &ct, &tag, &mut out),
        Err(Error::TagMismatch)
    );
    assert!(out.iter().all(|b| *b == 0), "plaintext_out not wiped");
}

#[test]
fn aes_gcm_length_mismatch_is_refused_before_the_call() {
    let m = module();
    let (key, iv, pt, ct, tag) = gcm_inputs();
    let key = m.aes_gcm_key(&key).unwrap();
    let mut drbg = cnsa2_drbg(m);
    let mut short = vec![0xAAu8; pt.len() - 1];
    assert_eq!(
        m.aes_gcm_seal(&key, &mut drbg, &[], &pt, &mut short),
        Err(Error::LengthMismatch)
    );
    assert!(short.iter().all(|b| *b == 0));
    assert_eq!(
        m.aes_gcm_invocations(&key),
        Ok(0),
        "refused before the call"
    );
    let mut long = vec![0xAAu8; ct.len() + 1];
    assert_eq!(
        m.aes_gcm_open(&key, &iv, &[], &ct, &tag, &mut long),
        Err(Error::LengthMismatch)
    );
    assert!(long.iter().all(|b| *b == 0));
}

/// The direction in which a missing check would let the library write past
/// the caller's slice: an output shorter than the input. A guard byte after
/// the sub-slice must be untouched.
#[test]
fn aes_gcm_short_output_is_refused_and_nothing_past_it_is_written() {
    let m = module();
    let (key, iv, pt, ct, tag) = gcm_inputs();
    let key = m.aes_gcm_key(&key).unwrap();
    let mut drbg = cnsa2_drbg(m);

    let mut buf = vec![0xAAu8; ct.len()];
    let (head, guard) = buf.split_at_mut(ct.len() - 1);
    assert_eq!(
        m.aes_gcm_open(&key, &iv, &[], &ct, &tag, head),
        Err(Error::LengthMismatch)
    );
    assert!(head.iter().all(|b| *b == 0));
    assert_eq!(guard, [0xAA]);

    let mut buf = vec![0xAAu8; pt.len()];
    let (head, guard) = buf.split_at_mut(pt.len() - 1);
    assert_eq!(
        m.aes_gcm_seal(&key, &mut drbg, &[], &pt, head),
        Err(Error::LengthMismatch)
    );
    assert_eq!(guard, [0xAA]);

    // The other direction: an output longer than the input.
    let mut long = vec![0xAAu8; pt.len() + 1];
    assert_eq!(
        m.aes_gcm_seal(&key, &mut drbg, &[], &pt, &mut long),
        Err(Error::LengthMismatch)
    );
}

/// A reserved, read-only mapping of `len` zero pages that is never touched,
/// so nothing is committed. Unmapped when dropped.
#[cfg(target_os = "linux")]
struct Reserved {
    base: *mut core::ffi::c_void,
    len: usize,
}

#[cfg(target_os = "linux")]
mod reserve {
    use core::ffi::{c_int, c_long, c_void};
    unsafe extern "C" {
        pub(crate) fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            off: c_long,
        ) -> *mut c_void;
        pub(crate) fn munmap(addr: *mut c_void, len: usize) -> c_int;
    }
}

#[cfg(target_os = "linux")]
impl Reserved {
    fn new(len: usize) -> Self {
        const PROT_READ: core::ffi::c_int = 1;
        const MAP_PRIVATE: core::ffi::c_int = 0x02;
        const MAP_ANONYMOUS: core::ffi::c_int = 0x20;
        const MAP_NORESERVE: core::ffi::c_int = 0x4000;
        // SAFETY: an anonymous private mapping; the result is checked below.
        let base = unsafe {
            reserve::mmap(
                core::ptr::null_mut(),
                len,
                PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(base as isize, -1, "mmap of a reserved region failed");
        Self { base, len }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping is `len` readable bytes and lives as long as
        // `self`.
        unsafe { core::slice::from_raw_parts(self.base.cast::<u8>(), self.len) }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Reserved {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the region `new` mapped, no longer borrowed.
        unsafe { reserve::munmap(self.base, self.len) };
    }
}

/// One byte over the SP 800-38D payload limit, 2^36 − 32 bytes.
#[cfg(target_os = "linux")]
const OVER_THE_LIMIT: usize = (1 << 36) - 31;

/// An input over the SP 800-38D payload limit is refused before anything is
/// read or the library is called. The output is one byte, so a length check
/// alone would answer `LengthMismatch`.
#[cfg(target_os = "linux")]
#[test]
fn aes_gcm_payload_over_the_limit_is_refused_by_the_crate() {
    let huge = Reserved::new(OVER_THE_LIMIT);
    let m = module();
    let key = m.aes_gcm_key(&[3; 32]).unwrap();
    let mut drbg = cnsa2_drbg(m);
    let mut out = [0xAAu8; 1];
    let seal = m.aes_gcm_seal(&key, &mut drbg, &[], huge.bytes(), &mut out);
    assert_eq!(seal, Err(Error::InvalidPayloadLength));
    assert_eq!(out, [0]);
    let mut out = [0xAAu8; 1];
    let open = m.aes_gcm_open(&key, &[1; 12], &[], huge.bytes(), &[0; 16], &mut out);
    assert_eq!(open, Err(Error::InvalidPayloadLength));
    assert_eq!(out, [0]);
}

/// The `Vec` forms refuse an over-limit input before allocating its output,
/// which would otherwise be a 64 GiB allocation.
#[cfg(target_os = "linux")]
#[test]
fn aes_gcm_vec_forms_refuse_over_the_limit_before_allocating() {
    let huge = Reserved::new(OVER_THE_LIMIT);
    let m = module();
    let key = m.aes_gcm_key(&[3; 32]).unwrap();
    let mut drbg = cnsa2_drbg(m);
    assert_eq!(
        m.aes_gcm_seal_vec(&key, &mut drbg, &[], huge.bytes()),
        Err(Error::InvalidPayloadLength)
    );
    assert_eq!(
        m.aes_gcm_open_vec(&key, &[1; 12], &[], huge.bytes(), &[0; 16]),
        Err(Error::InvalidPayloadLength)
    );
}

#[test]
fn handle_debug_prints_only_the_type_name() {
    let m = module();
    let k = [1u8; 32];
    assert_eq!(format!("{:?}", m.aes_gcm_key(&k).unwrap()), "AesGcmKey");
    assert_eq!(format!("{:?}", m.aes_ccm_key(&k, 16).unwrap()), "AesCcmKey");
    assert_eq!(format!("{:?}", m.aes_cbc_key(&k).unwrap()), "AesCbcKey");
    assert_eq!(format!("{:?}", m.aes_ctr_key(&k).unwrap()), "AesCtrKey");
    assert_eq!(format!("{:?}", m.aes_kw_key(&k).unwrap()), "AesKwKey");
    assert_eq!(
        format!("{:?}", m.aes_cmac_key(&k, 16).unwrap()),
        "AesCmacKey"
    );
    assert_eq!(
        format!("{:?}", m.drbg(DrbgKind::HmacSha512).unwrap()),
        "Drbg"
    );
}

/// One key on four threads, each with its own DRBG: every seal opens, and
/// the key's count is the number of seals.
#[test]
fn aes_gcm_key_is_shared_across_threads() {
    let m = module();
    let (key, _, pt, _, _) = gcm_inputs();
    let key = std::sync::Arc::new(m.aes_gcm_key(&key).unwrap());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (key, pt) = (key.clone(), pt.clone());
            std::thread::spawn(move || {
                let mut drbg = cnsa2_drbg(m);
                let (ct, sealed) = m.aes_gcm_seal_vec(&key, &mut drbg, &[], &pt).unwrap();
                m.aes_gcm_open_vec(&key, &sealed.iv, &[], &ct, &sealed.tag)
                    .unwrap()
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), pt);
    }
    assert_eq!(m.aes_gcm_invocations(&key), Ok(4));
}

// ----- the other AES modes, AES-256 -----

// SP 800-38A Appendix F: the plaintext of F.2.5 and F.5.5, the key of both,
// the CBC IV of F.2.5 and the initial counter block of F.5.5.
const SP38A_PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                        30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const SP38A_KEY256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CBC256_CT: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
                         39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b";
const CTR_ICB: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const CTR256_CT: &str = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5\
                         2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";

#[test]
fn aes_cbc_known_answer_both_ways() {
    let m = module();
    let key = m.aes_cbc_key(&common::unhex(SP38A_KEY256)).unwrap();
    let (iv, pt, ct) = (
        array(&common::unhex(CBC_IV)),
        common::unhex(SP38A_PT),
        common::unhex(CBC256_CT),
    );
    let mut out = vec![0u8; pt.len()];
    m.aes_cbc_encrypt(&key, &iv, &pt, &mut out).unwrap();
    assert_eq!(out, ct);
    m.aes_cbc_decrypt(&key, &iv, &ct, &mut out).unwrap();
    assert_eq!(out, pt);

    let mut short = vec![0xAAu8; pt.len() - 16];
    assert_eq!(
        m.aes_cbc_encrypt(&key, &iv, &pt, &mut short),
        Err(Error::LengthMismatch)
    );
    assert!(short.iter().all(|b| *b == 0));
    let mut out = [0xAAu8; 15];
    assert_eq!(
        m.aes_cbc_encrypt(&key, &iv, &[1; 15], &mut out),
        Err(Error::NotBlockAligned)
    );
    assert_eq!(out, [0; 15]);
    assert_eq!(
        m.aes_cbc_encrypt(&key, &iv, &[], &mut []),
        Err(Error::InvalidPayloadLength)
    );
    assert_eq!(
        m.aes_cbc_decrypt(&key, &iv, &[], &mut []),
        Err(Error::InvalidPayloadLength)
    );
}

#[test]
fn aes_ctr_known_answer_both_ways() {
    let m = module();
    let key = m.aes_ctr_key(&common::unhex(SP38A_KEY256)).unwrap();
    let (icb, pt, ct) = (
        array(&common::unhex(CTR_ICB)),
        common::unhex(SP38A_PT),
        common::unhex(CTR256_CT),
    );
    let mut out = vec![0u8; pt.len()];
    m.aes_ctr(&key, &icb, &pt, &mut out).unwrap();
    assert_eq!(out, ct);
    m.aes_ctr(&key, &icb, &ct, &mut out).unwrap();
    assert_eq!(out, pt);
    let mut long = vec![0xAAu8; pt.len() + 1];
    assert_eq!(
        m.aes_ctr(&key, &icb, &pt, &mut long),
        Err(Error::LengthMismatch)
    );
    assert!(long.iter().all(|b| *b == 0));
    let mut buf = vec![0xAAu8; pt.len()];
    let (head, guard) = buf.split_at_mut(pt.len() - 1);
    assert_eq!(m.aes_ctr(&key, &icb, &pt, head), Err(Error::LengthMismatch));
    assert!(head.iter().all(|b| *b == 0));
    assert_eq!(guard, [0xAA]);
}

// NIST CAVP CCMVS VPT256.rsp, [Alen = 32, Nlen = 13, Tlen = 16, Plen = 16],
// Count = 160; CT is the ciphertext followed by the tag. The same values are
// the module's CCM self-test in crates/oxicrypt-aes/src/kat.rs.
const CCM256_KEY: &str = "ee8ce187169779d13e443d6428e38b38b55dfb90f0228a8a4e62f8f535806e62";
const CCM256_NONCE: &str = "121642c4218b391c98e6269c8a";
const CCM256_AAD: &str = "718d13e47522ac4cdf3f828063980b6d452fcdcd6e1a1904bf87f548a5fd5a05";
const CCM256_PT: &str = "d15f98f2c6d670f55c78a06648332bc9";
const CCM256_CT: &str = "cc17bf8794c843457d899391898ed22a6f9d28fcb64234e1cd793c4144f1da50";

#[test]
fn aes_ccm_known_answer_both_ways() {
    let m = module();
    let key = m.aes_ccm_key(&common::unhex(CCM256_KEY), 16).unwrap();
    assert_eq!(key.tag_len(), 16);
    let (nonce, aad, pt) = (
        common::unhex(CCM256_NONCE),
        common::unhex(CCM256_AAD),
        common::unhex(CCM256_PT),
    );
    let expected = common::unhex(CCM256_CT);
    let (ct, tag) = expected.split_at(pt.len());
    let (mut ct_out, mut tag_out) = (vec![0u8; pt.len()], [0u8; 16]);
    m.aes_ccm_seal(&key, &nonce, &aad, &pt, &mut ct_out, &mut tag_out)
        .unwrap();
    assert_eq!(ct_out, ct);
    assert_eq!(tag_out, tag);
    let mut back = vec![0u8; ct.len()];
    m.aes_ccm_open(&key, &nonce, &aad, ct, tag, &mut back)
        .unwrap();
    assert_eq!(back, pt);
    assert!(m.aes_ccm_invocations(&key).unwrap() > 0);

    let mut flipped = tag.to_vec();
    flipped[0] ^= 1;
    let mut out = vec![0xAAu8; ct.len()];
    assert_eq!(
        m.aes_ccm_open(&key, &nonce, &aad, ct, &flipped, &mut out),
        Err(Error::TagMismatch)
    );
    assert!(out.iter().all(|b| *b == 0));
    let mut out = vec![0xAAu8; ct.len()];
    assert_eq!(
        m.aes_ccm_open(&key, &nonce, &aad, ct, &tag[..8], &mut out),
        Err(Error::InvalidTagLength)
    );
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(
        m.aes_ccm_open(&key, &nonce[..6], &aad, ct, tag, &mut out),
        Err(Error::TagMismatch)
    );
    let mut short_tag = [0xAAu8; 8];
    assert_eq!(
        m.aes_ccm_seal(&key, &nonce, &aad, &pt, &mut ct_out, &mut short_tag),
        Err(Error::LengthMismatch)
    );
    assert_eq!(short_tag, [0; 8]);
    assert_eq!(
        m.aes_ccm_seal(&key, &nonce[..6], &aad, &pt, &mut ct_out, &mut tag_out),
        Err(Error::InvalidNonceLength)
    );
    assert_eq!(tag_out, [0; 16]);
    assert_eq!(m.aes_ccm_key(&[1; 32], 9).unwrap_err(), Error::InvalidInput);
}

/// A CCM tag slice of another length than the key's is refused with
/// `InvalidTagLength`, shorter or longer, and the output is zeroed.
#[test]
fn aes_ccm_open_tag_of_another_length_is_invalid_tag_length() {
    let m = module();
    let key = m.aes_ccm_key(&common::unhex(CCM256_KEY), 16).unwrap();
    let (nonce, aad) = (common::unhex(CCM256_NONCE), common::unhex(CCM256_AAD));
    let expected = common::unhex(CCM256_CT);
    let (ct, tag) = expected.split_at(expected.len() - 16);
    for len in [0, 4, 15, 17] {
        let mut wrong = tag.to_vec();
        wrong.resize(len, 0);
        let mut out = vec![0xAAu8; ct.len()];
        assert_eq!(
            m.aes_ccm_open(&key, &nonce, &aad, ct, &wrong, &mut out),
            Err(Error::InvalidTagLength),
            "tag of {len} bytes"
        );
        assert!(out.iter().all(|b| *b == 0), "tag of {len} bytes");
    }
}

/// Each input the library refuses on a CCM decryption is reported as one
/// error, `TagMismatch`: a nonce length outside 7 to 13, a ciphertext one
/// byte short, and a tag with one bit flipped. The output is zeroed each
/// time, and the unaltered inputs open.
#[test]
fn aes_ccm_open_reports_each_refusal_as_tag_mismatch() {
    let m = module();
    let key = m.aes_ccm_key(&common::unhex(CCM256_KEY), 16).unwrap();
    let (nonce, aad, pt) = (
        common::unhex(CCM256_NONCE),
        common::unhex(CCM256_AAD),
        common::unhex(CCM256_PT),
    );
    let expected = common::unhex(CCM256_CT);
    let (ct, tag) = expected.split_at(pt.len());
    let mut flipped = tag.to_vec();
    flipped[15] ^= 0x80;
    let short = &ct[..ct.len() - 1];
    let cases: [CcmFault<'_>; 3] = [
        ("a 6-byte nonce", &nonce[..6], ct, tag),
        ("a short ciphertext", &nonce, short, tag),
        ("a flipped tag", &nonce, ct, &flipped),
    ];
    for (name, n, c, t) in cases {
        let mut out = vec![0xAAu8; c.len()];
        assert_eq!(
            m.aes_ccm_open(&key, n, &aad, c, t, &mut out),
            Err(Error::TagMismatch),
            "{name}"
        );
        assert!(out.iter().all(|b| *b == 0), "{name}");
    }
    let mut back = vec![0u8; ct.len()];
    m.aes_ccm_open(&key, &nonce, &aad, ct, tag, &mut back)
        .unwrap();
    assert_eq!(back, pt);
}

#[test]
fn aes_ccm_count_is_preloaded_and_bounded() {
    let m = module();
    let key = m.aes_ccm_key_with_count(&[2; 32], 8, 1 << 61).unwrap();
    assert_eq!(key.tag_len(), 8);
    assert_eq!(m.aes_ccm_invocations(&key), Ok(1 << 61));
    let (mut ct, mut tag) = ([0xAAu8; 4], [0xAAu8; 8]);
    assert_eq!(
        m.aes_ccm_seal(&key, &[0; 13], &[], &[1; 4], &mut ct, &mut tag),
        Err(Error::KeyExhausted)
    );
    assert_eq!((ct, tag), ([0; 4], [0; 8]));
    assert_eq!(
        m.aes_ccm_key_with_count(&[2; 32], 8, (1 << 61) + 1)
            .unwrap_err(),
        Error::InvalidInput
    );
}

// RFC 3394 §4.6: a 256-bit KEK wrapping 256 bits of key data.
const KW_KEK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KW_PT: &str = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f";
const KW_CT: &str =
    "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21";

#[test]
fn aes_kw_known_answer_both_ways() {
    let m = module();
    let key = m.aes_kw_key(&common::unhex(KW_KEK)).unwrap();
    let (pt, ct) = (common::unhex(KW_PT), common::unhex(KW_CT));
    let mut wrapped = vec![0u8; pt.len() + 8];
    m.aes_kw_wrap(&key, &pt, &mut wrapped).unwrap();
    assert_eq!(wrapped, ct);
    let mut unwrapped = vec![0u8; ct.len() - 8];
    m.aes_kw_unwrap(&key, &ct, &mut unwrapped).unwrap();
    assert_eq!(unwrapped, pt);

    let mut bad = ct.clone();
    bad[0] ^= 1;
    let mut out = vec![0xAAu8; ct.len() - 8];
    assert_eq!(
        m.aes_kw_unwrap(&key, &bad, &mut out),
        Err(Error::TagMismatch)
    );
    assert!(out.iter().all(|b| *b == 0));
    let mut out = vec![0xAAu8; pt.len()];
    assert_eq!(
        m.aes_kw_wrap(&key, &pt, &mut out),
        Err(Error::LengthMismatch)
    );
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(
        m.aes_kw_unwrap(&key, &[0; 4], &mut []),
        Err(Error::LengthMismatch)
    );
}

// NIST ACVP-Server ACVP-AES-KW-1.0, tgId 31, tcId 3001 (`kwCipher: inverse`,
// `keyLen: 256`, `payloadLen: 832`); the same values are the module's KW
// inverse-cipher self-test in crates/oxicrypt-aes/src/kat.rs.
const KW_INV_KEY: &str = "e66fd4b07c5a06e1200862cc8fddd8b0ca28eba5cab639891c8ac47597a1aa36";
const KW_INV_PT: &str = "96427f1babafdddc46125c9474757dae6896339c36185619f42730cd9c3630a4\
                         fd61bf1ce8920158d24b91747679517be721601d397133555f68adac08af28d8\
                         86d20dc5f165cfc9b46c0e696eb581a1d4387cc40eb6770b27b082b85bb5c4e0\
                         b50029f71b25b464";
const KW_INV_CT: &str = "ef71f30ebf5694ec2bd4bbe215ff77a0002bbb0e63b675f4ff83f3f93bb8f766\
                         3e89288560496130129b16c434ecee69b0710dbbff37ba86421c59c9bb780d3e\
                         2d4183b6fc5a820c96c319fbc775147f0055fd887a61f1a78d026ce31143714b\
                         d78432232158dc58b73df36341d8d726";

// NIST ACVP-Server ACVP-AES-KWP-1.0, tgId 21, tcId 2001 (`kwCipher: inverse`,
// `keyLen: 256`, `payloadLen: 656`); the same values are the module's KWP
// inverse-cipher self-test in crates/oxicrypt-aes/src/kat.rs.
const KWP_INV_KEY: &str = "63a9a46618a7d6f198c772764010a6fe9e1270e2469c98a115ca8467ec8e80f0";
const KWP_INV_PT: &str = "b5ef66688fa02bccdfa25cf273355985617bce110771056da0b57016cf3320cf\
                          6111450652154bbe210d91a2ec53517538eefcafb2dd90fbf5b97dda5f4cda71\
                          454946c5ab92745d2b81ee986cfb261d90d0";
const KWP_INV_CT: &str = "f1a5d99082f974de12c09de3c83aa3534e357fb891f74ced88e5b91e49f8b0f1\
                          346d64044b95bb55fe2d70c0c93b33b954d7ffd049585d69abe4cbc79138d106\
                          c8fcc98591fb4efe87edc9e82bfd6424cef1ffab8fc115deaaeb08d8621166e8";

#[test]
fn aes_kw_inverse_known_answer_both_ways() {
    let m = module();
    let key = m.aes_kw_key(&common::unhex(KW_INV_KEY)).unwrap();
    let (pt, ct) = (common::unhex(KW_INV_PT), common::unhex(KW_INV_CT));
    let mut wrapped = vec![0u8; pt.len() + 8];
    m.aes_kw_wrap_inverse(&key, &pt, &mut wrapped).unwrap();
    assert_eq!(wrapped, ct);
    let mut unwrapped = vec![0u8; ct.len() - 8];
    m.aes_kw_unwrap_inverse(&key, &ct, &mut unwrapped).unwrap();
    assert_eq!(unwrapped, pt);
}

#[test]
fn aes_kwp_inverse_known_answer_both_ways() {
    let m = module();
    let key = m.aes_kw_key(&common::unhex(KWP_INV_KEY)).unwrap();
    let (pt, ct) = (common::unhex(KWP_INV_PT), common::unhex(KWP_INV_CT));
    let mut wrapped = vec![0u8; ct.len()];
    let n = m.aes_kwp_wrap_inverse(&key, &pt, &mut wrapped).unwrap();
    assert_eq!(&wrapped[..n], ct.as_slice());
    let mut unwrapped = vec![0u8; ct.len()];
    let k = m.aes_kwp_unwrap_inverse(&key, &ct, &mut unwrapped).unwrap();
    assert_eq!(&unwrapped[..k], pt.as_slice());
}

/// The inverse-cipher variants round-trip, and differ from the forward
/// variants under one key.
#[test]
fn aes_kw_and_kwp_inverse_round_trip() {
    let m = module();
    let key = m.aes_kw_key(&common::unhex(KW_KEK)).unwrap();
    let pt = common::unhex(KW_PT);
    let (mut fwd, mut inv) = (vec![0u8; pt.len() + 8], vec![0u8; pt.len() + 8]);
    m.aes_kw_wrap(&key, &pt, &mut fwd).unwrap();
    m.aes_kw_wrap_inverse(&key, &pt, &mut inv).unwrap();
    assert_ne!(fwd, inv);
    let mut back = vec![0u8; pt.len()];
    m.aes_kw_unwrap_inverse(&key, &inv, &mut back).unwrap();
    assert_eq!(back, pt);
    assert_eq!(
        m.aes_kw_unwrap_inverse(&key, &fwd, &mut back),
        Err(Error::TagMismatch)
    );

    let mut wrapped = [0u8; 48];
    let n = m
        .aes_kwp_wrap_inverse(&key, &pt[..20], &mut wrapped)
        .unwrap();
    assert_eq!(n, 32);
    let mut back = [0u8; 32];
    let k = m
        .aes_kwp_unwrap_inverse(&key, &wrapped[..n], &mut back)
        .unwrap();
    assert_eq!(&back[..k], &pt[..20]);
}

// SP 800-38B Appendix D.3: AES-256, Mlen = 128 and Mlen = 320 over the
// SP 800-38A plaintext.
const CMAC256_TAG_128: &str = "28a7023f452e8f82bd4bf28d8c37c35c";
const CMAC256_TAG_320: &str = "aaf3d8f1de5640c232f5b169b9c911e6";

#[test]
fn aes_cmac_known_answers_and_verify() {
    let m = module();
    let key = m.aes_cmac_key(&common::unhex(SP38A_KEY256), 16).unwrap();
    assert_eq!(key.mac_len(), 16);
    let msg = common::unhex(SP38A_PT);
    for (len, tag) in [(16, CMAC256_TAG_128), (40, CMAC256_TAG_320)] {
        let mut mac = [0u8; 16];
        m.aes_cmac(&key, &msg[..len], &mut mac).unwrap();
        assert_eq!(mac.as_slice(), common::unhex(tag), "Mlen = {}", len * 8);
        assert_eq!(m.aes_cmac_verify(&key, &msg[..len], &mac), Ok(()));
        mac[15] ^= 1;
        assert_eq!(
            m.aes_cmac_verify(&key, &msg[..len], &mac),
            Err(Error::TagMismatch)
        );
    }
    let mut short = [0xAAu8; 8];
    assert_eq!(
        m.aes_cmac(&key, &msg, &mut short),
        Err(Error::LengthMismatch)
    );
    assert_eq!(short, [0; 8]);
    assert_eq!(
        m.aes_cmac_verify(&key, &msg[..16], &common::unhex(CMAC256_TAG_128)[..8]),
        Err(Error::InvalidTagLength)
    );
    // A truncated MAC is the leading bytes of the full one (SP 800-38B §6.2).
    let short_key = m.aes_cmac_key(&common::unhex(SP38A_KEY256), 8).unwrap();
    let mut mac = [0u8; 8];
    m.aes_cmac(&short_key, &msg[..16], &mut mac).unwrap();
    assert_eq!(mac.as_slice(), &common::unhex(CMAC256_TAG_128)[..8]);
}

// ----- the DRBGs under CNSA 2.0 -----

#[test]
fn drbgs_below_cnsa2_are_restricted() {
    let m = module();
    for kind in [
        DrbgKind::HmacSha256,
        DrbgKind::HashSha256,
        DrbgKind::CtrAes128,
        DrbgKind::CtrAes192,
    ] {
        let mut drbg = m.drbg(kind).unwrap();
        assert_eq!(
            drbg.instantiate(&[]),
            Err(Error::AlgorithmRestricted),
            "{kind:?}"
        );
        assert_eq!(
            drbg.strength_bits(),
            Err(Error::AlgorithmRestricted),
            "{kind:?}"
        );
    }
    for kind in [
        DrbgKind::HmacSha384,
        DrbgKind::HmacSha512,
        DrbgKind::HashSha384,
        DrbgKind::HashSha512,
        DrbgKind::CtrAes256,
    ] {
        let mut drbg = m.drbg(kind).unwrap();
        drbg.instantiate(b"cnsa2").unwrap();
        let mut out = [0u8; 48];
        drbg.generate(&[], &mut out).unwrap();
        assert_eq!(drbg.strength_bits(), Ok(256), "{kind:?}");
    }
}

// ----- ML-DSA-87 -----

const KEYGEN: (&str, &str) = ("ML-DSA-keyGen-FIPS204", "kat-slice.json");
const SIGGEN: (&str, &str) = ("ML-DSA-sigGen-FIPS204", "kat-slice.json");

/// ACVP ML-DSA-keyGen-FIPS204, ML-DSA-87, tgId 3, tcId 51.
fn dsa_keygen_vector() -> (MlDsa87Seed, Vec<u8>, Vec<u8>) {
    let seed = MlDsa87Seed::from_bytes(&array(&acvp(KEYGEN.0, KEYGEN.1, 51, "seed")));
    (
        seed,
        acvp(KEYGEN.0, KEYGEN.1, 51, "pk"),
        acvp(KEYGEN.0, KEYGEN.1, 51, "sk"),
    )
}

#[test]
fn ml_dsa_87_expand_key_known_answer() {
    let m = module();
    let (seed, expected_public, expected_secret) = dsa_keygen_vector();
    let (public, secret) = m.ml_dsa_87_expand_key(&seed).unwrap();
    assert_eq!(public.as_slice(), expected_public.as_slice());
    assert_eq!(secret.as_bytes().as_slice(), expected_secret.as_slice());
}

#[test]
fn ml_dsa_87_keygen_round_trips() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    let (pk, sk) = m.ml_dsa_87_keygen(&mut rbg).unwrap();
    let sig = m.ml_dsa_87_sign(&sk, b"message", b"ctx").unwrap();
    assert_eq!(m.ml_dsa_87_verify(&pk, b"message", b"ctx", &sig), Ok(()));

    let (other, _) = m.ml_dsa_87_keygen(&mut rbg).unwrap();
    assert_ne!(other, pk, "a second key generation draws a fresh seed");
    assert_eq!(
        m.ml_dsa_87_verify(&other, b"message", b"ctx", &sig),
        Err(Error::SignatureInvalid)
    );
}

#[test]
fn ml_dsa_87_keygen_with_seed_is_reproduced_by_expand_key() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    let (pk, sk, seed) = m.ml_dsa_87_keygen_with_seed(&mut rbg).unwrap();
    assert_ne!(seed.as_bytes(), &[0; 32]);
    let expanded = m.ml_dsa_87_expand_key(&seed).unwrap();
    assert_eq!(expanded.0, pk);
    assert_eq!(expanded.1.as_bytes(), sk.as_bytes());
}

#[test]
fn ml_dsa_87_keygen_refuses_an_uninstantiated_drbg() {
    let m = module();
    let mut rbg = m.drbg(DrbgKind::HmacSha384).unwrap();
    assert_eq!(
        m.ml_dsa_87_keygen(&mut rbg).unwrap_err(),
        Error::Uninstantiated
    );
}

#[test]
fn ml_kem_1024_keygen_and_encapsulate_refuse_an_uninstantiated_drbg() {
    let m = module();
    let mut rbg = m.drbg(DrbgKind::HmacSha384).unwrap();
    assert_eq!(
        m.ml_kem_1024_keygen(&mut rbg).unwrap_err(),
        Error::Uninstantiated
    );
    let ek: [u8; 1568] = array(&acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "ek"));
    assert_eq!(
        m.ml_kem_1024_encapsulate(&ek, &mut rbg).unwrap_err(),
        Error::Uninstantiated
    );
}

#[test]
fn ml_dsa_87_sign_known_answer() {
    let m = module();
    // ACVP ML-DSA-sigGen-FIPS204, ML-DSA-87, tgId 5 (external interface,
    // pure, deterministic), tcId 73, empty context.
    let sk = MlDsa87SecretKey::from_bytes(&array(&acvp(SIGGEN.0, SIGGEN.1, 73, "sk")));
    let msg = acvp(SIGGEN.0, SIGGEN.1, 73, "message");
    let expected = acvp(SIGGEN.0, SIGGEN.1, 73, "signature");
    let sig = m.ml_dsa_87_sign(&sk, &msg, &[]).unwrap();
    assert_eq!(sig.as_slice(), expected.as_slice());
}

#[test]
fn ml_dsa_87_verify_accepts_and_refuses() {
    let m = module();
    let (seed, pk, _) = dsa_keygen_vector();
    let pk: [u8; 2592] = array(&pk);
    let (_, sk) = m.ml_dsa_87_expand_key(&seed).unwrap();
    let sig = m.ml_dsa_87_sign(&sk, b"message", b"ctx").unwrap();
    assert_eq!(m.ml_dsa_87_verify(&pk, b"message", b"ctx", &sig), Ok(()));

    assert_eq!(
        m.ml_dsa_87_verify(&pk, b"messagf", b"ctx", &sig),
        Err(Error::SignatureInvalid)
    );
    assert_eq!(
        m.ml_dsa_87_verify(&pk, b"message", b"", &sig),
        Err(Error::SignatureInvalid)
    );
    let mut flipped = sig;
    flipped[100] ^= 0x01;
    assert_eq!(
        m.ml_dsa_87_verify(&pk, b"message", b"ctx", &flipped),
        Err(Error::SignatureInvalid)
    );

    // A full-length signature that does not decode: the hint section (the
    // last ω + k = 75 + 8 bytes) holds counts above ω, which FIPS 204
    // Algorithm 21 (HintBitUnpack) rejects.
    let mut malformed = sig;
    malformed[4627 - 83..].fill(0xFF);
    assert_eq!(
        m.ml_dsa_87_verify(&pk, b"message", b"ctx", &malformed),
        Err(Error::SignatureInvalid)
    );
}

#[test]
fn ml_dsa_87_context_bound_is_the_librarys() {
    let m = module();
    let (seed, _, _) = dsa_keygen_vector();
    let (_, sk) = m.ml_dsa_87_expand_key(&seed).unwrap();
    assert!(m.ml_dsa_87_sign(&sk, b"m", &[0; 255]).is_ok());
    assert_eq!(
        m.ml_dsa_87_sign(&sk, b"m", &[0; 256]).unwrap_err(),
        Error::InvalidInput
    );
}

// ----- ML-KEM-1024 -----

const KEM_KEYGEN: (&str, &str) = ("ML-KEM-keyGen-FIPS203", "kat-slice.json");
const KEM_ENCAP: (&str, &str) = ("ML-KEM-encapDecap-FIPS203", "kat-slice.json");
const KEM_DECAP: (&str, &str) = ("ML-KEM-encapDecap-FIPS203", "cast-slice.json");

#[test]
fn ml_kem_1024_expand_key_known_answer() {
    let m = module();
    // ACVP ML-KEM-keyGen-FIPS203, ML-KEM-1024, tgId 3, tcId 51.
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "d"));
    seed[32..].copy_from_slice(&acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "z"));
    let (ek, dk) = m
        .ml_kem_1024_expand_key(&MlKem1024Seed::from_bytes(&seed))
        .unwrap();
    assert_eq!(ek.as_slice(), acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "ek"));
    assert_eq!(
        dk.as_bytes().as_slice(),
        acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "dk")
    );
}

#[test]
fn ml_kem_1024_encapsulates_to_a_published_key_pair() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    // ACVP ML-KEM-encapDecap-FIPS203, ML-KEM-1024 encapsulation, tgId 3,
    // tcId 51; `m` is drawn by the module, so the vector gives the pair and
    // its decapsulation is the expected secret.
    let ek: [u8; 1568] = array(&acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "ek"));
    let dk =
        MlKem1024DecapsulationKey::from_bytes(&array(&acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "dk")));
    let (ss, ct) = m.ml_kem_1024_encapsulate(&ek, &mut rbg).unwrap();
    let received = m.ml_kem_1024_decapsulate(&dk, &ct).unwrap();
    assert_eq!(received.as_bytes(), ss.as_bytes());

    let (again, other) = m.ml_kem_1024_encapsulate(&ek, &mut rbg).unwrap();
    assert_ne!(ct, other, "each encapsulation draws a fresh m");
    assert_ne!(ss.as_bytes(), again.as_bytes());
}

#[test]
fn ml_kem_1024_decapsulate_refuses_a_key_failing_the_hash_check() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    let (ek, dk) = m.ml_kem_1024_keygen(&mut rbg).unwrap();
    let (_, ct) = m.ml_kem_1024_encapsulate(&ek, &mut rbg).unwrap();
    // FIPS 203 §7.3: dk = dk_PKE ‖ ek ‖ H(ek) ‖ z, so H(ek) starts 64 bytes
    // from the end.
    let mut bytes = *dk.as_bytes();
    bytes[3168 - 64] ^= 0x01;
    let broken = MlKem1024DecapsulationKey::from_bytes(&bytes);
    assert_eq!(
        m.ml_kem_1024_decapsulate(&broken, &ct).unwrap_err(),
        Error::InvalidInput
    );
    assert!(
        m.ml_kem_1024_decapsulate(&dk, &ct).is_ok(),
        "positive control"
    );
}

#[test]
fn ml_kem_1024_keygen_round_trips() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    let (ek, dk) = m.ml_kem_1024_keygen(&mut rbg).unwrap();
    let (sent, ct) = m.ml_kem_1024_encapsulate(&ek, &mut rbg).unwrap();
    let received = m.ml_kem_1024_decapsulate(&dk, &ct).unwrap();
    assert_eq!(received.as_bytes(), sent.as_bytes());

    let (_, other) = m.ml_kem_1024_keygen(&mut rbg).unwrap();
    let rejected = m.ml_kem_1024_decapsulate(&other, &ct).unwrap();
    assert_ne!(rejected.as_bytes(), sent.as_bytes());
}

#[test]
fn ml_kem_1024_keygen_with_seed_is_reproduced_by_expand_key() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    let (ek, dk, seed) = m.ml_kem_1024_keygen_with_seed(&mut rbg).unwrap();
    assert_ne!(seed.as_bytes(), &[0; 64]);
    let expanded = m.ml_kem_1024_expand_key(&seed).unwrap();
    assert_eq!(expanded.0, ek);
    assert_eq!(expanded.1.as_bytes(), dk.as_bytes());
}

#[test]
fn ml_kem_1024_encapsulate_refuses_a_key_failing_the_modulus_check() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    // FIPS 203 §7.2: every 12-bit coefficient of ek must be below q = 3329;
    // 0xFF bytes encode 4095.
    let mut ek: [u8; 1568] = array(&acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "ek"));
    ek[..3].fill(0xFF);
    assert_eq!(
        m.ml_kem_1024_encapsulate(&ek, &mut rbg).unwrap_err(),
        Error::InvalidInput
    );
}

#[test]
fn ml_kem_1024_decapsulate_known_answers() {
    let m = module();
    // ACVP ML-KEM-encapDecap-FIPS203, ML-KEM-1024 decapsulation, tgId 6:
    // tcId 96 a valid ciphertext, tcId 97 a modified one, whose answer is
    // the implicit-rejection secret, not an error.
    for tc in [96, 97] {
        let dk = MlKem1024DecapsulationKey::from_bytes(&array(&acvp(
            KEM_DECAP.0,
            KEM_DECAP.1,
            tc,
            "dk",
        )));
        let ct: [u8; 1568] = array(&acvp(KEM_DECAP.0, KEM_DECAP.1, tc, "c"));
        let ss = m.ml_kem_1024_decapsulate(&dk, &ct).unwrap();
        assert_eq!(
            ss.as_bytes().as_slice(),
            acvp(KEM_DECAP.0, KEM_DECAP.1, tc, "k"),
            "tcId {tc}"
        );
    }
}

// ----- the parameter sets CNSA 2.0 does not admit -----

#[test]
fn ml_dsa_44_and_65_are_restricted_under_cnsa2() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    let restricted = Err(Error::AlgorithmRestricted);

    assert_eq!(m.ml_dsa_44_keygen(&mut rbg).map(drop), restricted);
    assert_eq!(m.ml_dsa_44_keygen_with_seed(&mut rbg).map(drop), restricted);
    let seed = MlDsa44Seed::from_bytes(&[1; 32]);
    assert_eq!(m.ml_dsa_44_expand_key(&seed).map(drop), restricted);
    let sk = MlDsa44SecretKey::from_bytes(&[0; 2560]);
    assert_eq!(m.ml_dsa_44_sign(&sk, b"m", b"").map(drop), restricted);
    assert_eq!(
        m.ml_dsa_44_verify(&[0; 1312], b"m", b"", &[0; 2420]),
        restricted
    );

    assert_eq!(m.ml_dsa_65_keygen(&mut rbg).map(drop), restricted);
    assert_eq!(m.ml_dsa_65_keygen_with_seed(&mut rbg).map(drop), restricted);
    let seed = MlDsa65Seed::from_bytes(&[1; 32]);
    assert_eq!(m.ml_dsa_65_expand_key(&seed).map(drop), restricted);
    let sk = MlDsa65SecretKey::from_bytes(&[0; 4032]);
    assert_eq!(m.ml_dsa_65_sign(&sk, b"m", b"").map(drop), restricted);
    assert_eq!(
        m.ml_dsa_65_verify(&[0; 1952], b"m", b"", &[0; 3309]),
        restricted
    );
}

#[test]
fn ml_kem_512_and_768_are_restricted_under_cnsa2() {
    let m = module();
    let mut rbg = cnsa2_drbg(m);
    let restricted = Err(Error::AlgorithmRestricted);

    assert_eq!(m.ml_kem_512_keygen(&mut rbg).map(drop), restricted);
    assert_eq!(
        m.ml_kem_512_keygen_with_seed(&mut rbg).map(drop),
        restricted
    );
    let seed = MlKem512Seed::from_bytes(&[1; 64]);
    assert_eq!(m.ml_kem_512_expand_key(&seed).map(drop), restricted);
    assert_eq!(
        m.ml_kem_512_encapsulate(&[0; 800], &mut rbg).map(drop),
        restricted
    );
    let dk = MlKem512DecapsulationKey::from_bytes(&[0; 1632]);
    assert_eq!(
        m.ml_kem_512_decapsulate(&dk, &[0; 768]).map(drop),
        restricted
    );

    assert_eq!(m.ml_kem_768_keygen(&mut rbg).map(drop), restricted);
    assert_eq!(
        m.ml_kem_768_keygen_with_seed(&mut rbg).map(drop),
        restricted
    );
    let seed = MlKem768Seed::from_bytes(&[1; 64]);
    assert_eq!(m.ml_kem_768_expand_key(&seed).map(drop), restricted);
    assert_eq!(
        m.ml_kem_768_encapsulate(&[0; 1184], &mut rbg).map(drop),
        restricted
    );
    let dk = MlKem768DecapsulationKey::from_bytes(&[0; 2400]);
    assert_eq!(
        m.ml_kem_768_decapsulate(&dk, &[0; 1088]).map(drop),
        restricted
    );
}
