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
    Error, HKDF_SHA384_MAX_OKM_LEN, IntegrityStatus, MlDsa87KeySeed, MlDsa87SecretKey,
    MlKem1024DecapsulationKey, MlKem1024EncapsSeed, MlKem1024KeySeedD, MlKem1024KeySeedZ, Module,
    Profile,
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

// ----- AES-256-GCM -----

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

/// Key, IV, plaintext, ciphertext and tag.
type GcmCase = ([u8; 32], [u8; 12], Vec<u8>, Vec<u8>, [u8; 16]);

fn gcm_inputs() -> GcmCase {
    (
        array(&common::unhex(GCM256_KEY)),
        array(&common::unhex(GCM_IV)),
        common::unhex(GCM_PT),
        common::unhex(GCM256_CT),
        array(&common::unhex(GCM256_TAG)),
    )
}

#[test]
fn aes256_gcm_known_answer_both_ways() {
    let m = module();
    let (key, iv, pt, ct, tag) = gcm_inputs();
    let key = m.aes256_key(&key).unwrap();
    let mut out = vec![0u8; pt.len()];
    assert_eq!(
        m.aes256_gcm_encrypt(&key, &iv, &[], &pt, &mut out).unwrap(),
        tag
    );
    assert_eq!(out, ct);
    let mut back = vec![0u8; ct.len()];
    m.aes256_gcm_decrypt(&key, &iv, &[], &ct, &mut back, &tag)
        .unwrap();
    assert_eq!(back, pt);
    assert_eq!(
        m.aes256_gcm_decrypt_vec(&key, &iv, &[], &ct, &tag).unwrap(),
        pt
    );
}

#[test]
fn aes256_gcm_tag_mismatch_wipes_the_output() {
    let m = module();
    let (key, iv, _, ct, mut tag) = gcm_inputs();
    let key = m.aes256_key(&key).unwrap();
    tag[15] ^= 0x01;
    let mut out = vec![0xAAu8; ct.len()];
    assert_eq!(
        m.aes256_gcm_decrypt(&key, &iv, &[], &ct, &mut out, &tag),
        Err(Error::TagMismatch)
    );
    assert!(out.iter().all(|b| *b == 0), "plaintext_out not wiped");
}

#[test]
fn aes256_gcm_length_mismatch_is_refused_before_the_call() {
    let m = module();
    let (key, iv, pt, ct, tag) = gcm_inputs();
    let key = m.aes256_key(&key).unwrap();
    let mut short = vec![0xAAu8; pt.len() - 1];
    assert_eq!(
        m.aes256_gcm_encrypt(&key, &iv, &[], &pt, &mut short),
        Err(Error::LengthMismatch)
    );
    assert!(short.iter().all(|b| *b == 0));
    let mut long = vec![0xAAu8; ct.len() + 1];
    assert_eq!(
        m.aes256_gcm_decrypt(&key, &iv, &[], &ct, &mut long, &tag),
        Err(Error::LengthMismatch)
    );
    assert!(long.iter().all(|b| *b == 0));
}

/// The direction in which a missing check would let the library write past
/// the caller's slice: an output shorter than the input. A guard byte after
/// the sub-slice must be untouched.
#[test]
fn aes256_gcm_short_output_is_refused_and_nothing_past_it_is_written() {
    let m = module();
    let (key, iv, pt, ct, tag) = gcm_inputs();
    let key = m.aes256_key(&key).unwrap();

    let mut buf = vec![0xAAu8; ct.len()];
    let (head, guard) = buf.split_at_mut(ct.len() - 1);
    assert_eq!(
        m.aes256_gcm_decrypt(&key, &iv, &[], &ct, head, &tag),
        Err(Error::LengthMismatch)
    );
    assert!(head.iter().all(|b| *b == 0));
    assert_eq!(guard, [0xAA]);

    let mut buf = vec![0xAAu8; pt.len()];
    let (head, guard) = buf.split_at_mut(pt.len() - 1);
    assert_eq!(
        m.aes256_gcm_encrypt(&key, &iv, &[], &pt, head),
        Err(Error::LengthMismatch)
    );
    assert_eq!(guard, [0xAA]);

    // The other direction: an output longer than the input.
    let mut long = vec![0xAAu8; pt.len() + 1];
    assert_eq!(
        m.aes256_gcm_encrypt(&key, &iv, &[], &pt, &mut long),
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
fn aes256_gcm_payload_over_the_limit_is_refused_by_the_crate() {
    let huge = Reserved::new(OVER_THE_LIMIT);
    let m = module();
    let key = m.aes256_key(&[3; 32]).unwrap();
    let mut out = [0xAAu8; 1];
    let encrypt = m.aes256_gcm_encrypt(&key, &[1; 12], &[], huge.bytes(), &mut out);
    let decrypt = m.aes256_gcm_decrypt(&key, &[1; 12], &[], huge.bytes(), &mut out, &[0; 16]);
    assert_eq!(encrypt, Err(Error::InvalidPayloadLength));
    assert_eq!(decrypt, Err(Error::InvalidPayloadLength));
    assert_eq!(out, [0]);
}

/// The `Vec` forms refuse an over-limit input before allocating its output,
/// which would otherwise be a 64 GiB allocation.
#[cfg(target_os = "linux")]
#[test]
fn aes256_gcm_vec_forms_refuse_over_the_limit_before_allocating() {
    let huge = Reserved::new(OVER_THE_LIMIT);
    let m = module();
    let key = m.aes256_key(&[3; 32]).unwrap();
    assert_eq!(
        m.aes256_gcm_encrypt_vec(&key, &[1; 12], &[], huge.bytes()),
        Err(Error::InvalidPayloadLength)
    );
    assert_eq!(
        m.aes256_gcm_decrypt_vec(&key, &[1; 12], &[], huge.bytes(), &[0; 16]),
        Err(Error::InvalidPayloadLength)
    );
}

#[test]
fn handle_debug_prints_only_the_type_name() {
    let m = module();
    assert_eq!(
        format!("{:?}", m.aes256_key(&[1; 32]).unwrap()),
        "Aes256Key"
    );
    assert_eq!(
        format!("{:?}", m.hmac_drbg_sha256().unwrap()),
        "HmacDrbgSha256"
    );
}

#[test]
fn aes256_key_is_shared_across_threads() {
    let m = module();
    let (key, iv, pt, ct, tag) = gcm_inputs();
    let key = std::sync::Arc::new(m.aes256_key(&key).unwrap());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (key, pt) = (key.clone(), pt.clone());
            std::thread::spawn(move || m.aes256_gcm_encrypt_vec(&key, &iv, &[], &pt).unwrap())
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), (ct.clone(), tag));
    }
}

// ----- HMAC_DRBG-SHA-256 under a profile that forbids it -----

#[test]
fn hmac_drbg_sha256_is_restricted_under_cnsa2() {
    let m = module();
    let result = m
        .hmac_drbg_sha256()
        .and_then(|mut drbg| drbg.instantiate(&[1; 32], &[2; 16], &[]));
    assert_eq!(result, Err(Error::AlgorithmRestricted));
}

// ----- ML-DSA-87 -----

const KEYGEN: (&str, &str) = ("ML-DSA-keyGen-FIPS204", "kat-slice.json");
const SIGGEN: (&str, &str) = ("ML-DSA-sigGen-FIPS204", "kat-slice.json");

/// ACVP ML-DSA-keyGen-FIPS204, ML-DSA-87, tgId 3, tcId 51.
fn dsa_keygen_vector() -> (MlDsa87KeySeed, Vec<u8>, Vec<u8>) {
    let seed = MlDsa87KeySeed::from_bytes(&array(&acvp(KEYGEN.0, KEYGEN.1, 51, "seed")));
    (
        seed,
        acvp(KEYGEN.0, KEYGEN.1, 51, "pk"),
        acvp(KEYGEN.0, KEYGEN.1, 51, "sk"),
    )
}

#[test]
fn ml_dsa_87_keygen_known_answer() {
    let m = module();
    let (seed, expected_public, expected_secret) = dsa_keygen_vector();
    let (public, secret) = m.ml_dsa_87_keygen(seed).unwrap();
    assert_eq!(public.as_slice(), expected_public.as_slice());
    assert_eq!(secret.as_bytes().as_slice(), expected_secret.as_slice());
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
    let (_, sk) = m.ml_dsa_87_keygen(seed).unwrap();
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
    let (_, sk) = m.ml_dsa_87_keygen(seed).unwrap();
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
fn ml_kem_1024_keygen_known_answer() {
    let m = module();
    // ACVP ML-KEM-keyGen-FIPS203, ML-KEM-1024, tgId 3, tcId 51.
    let d = MlKem1024KeySeedD::from_bytes(&array(&acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "d")));
    let z = MlKem1024KeySeedZ::from_bytes(&array(&acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "z")));
    let (ek, dk) = m.ml_kem_1024_keygen(d, z).unwrap();
    assert_eq!(ek.as_slice(), acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "ek"));
    assert_eq!(
        dk.as_bytes().as_slice(),
        acvp(KEM_KEYGEN.0, KEM_KEYGEN.1, 51, "dk")
    );
}

#[test]
fn ml_kem_1024_encapsulate_known_answer() {
    let m = module();
    // ACVP ML-KEM-encapDecap-FIPS203, ML-KEM-1024 encapsulation, tgId 3, tcId 51.
    let ek: [u8; 1568] = array(&acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "ek"));
    let msg = MlKem1024EncapsSeed::from_bytes(&array(&acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "m")));
    let (ss, ct) = m.ml_kem_1024_encapsulate(&ek, msg).unwrap();
    assert_eq!(ct.as_slice(), acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "c"));
    assert_eq!(
        ss.as_bytes().as_slice(),
        acvp(KEM_ENCAP.0, KEM_ENCAP.1, 51, "k")
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
