//! The services the CNSA 2.0 profile does not permit, under
//! `Profile::Unrestricted`. Every test in this binary initialises with that
//! profile.

#![cfg(oxicrypt_lib)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::init;
use oxicrypt::{
    Drbg, DrbgKind, Error, HMAC_DRBG_MAX_PROVIDED_LEN, HMAC_DRBG_MAX_REQUEST_LEN, MlDsa44Seed,
    MlDsa65Seed, MlKem512DecapsulationKey, MlKem512Seed, MlKem768DecapsulationKey, MlKem768Seed,
    MlKem1024DecapsulationKey, Module, Profile,
};

fn module() -> Module {
    init(Profile::Unrestricted).expect("the signed fixture library initialises unrestricted")
}

/// Each kind with the security strength SP 800-90A gives it: 256 bits for
/// every HMAC_DRBG and Hash_DRBG here, the AES key length for CTR_DRBG.
const KINDS: [(DrbgKind, u32); 9] = [
    (DrbgKind::HmacSha256, 256),
    (DrbgKind::HmacSha384, 256),
    (DrbgKind::HmacSha512, 256),
    (DrbgKind::HashSha256, 256),
    (DrbgKind::HashSha384, 256),
    (DrbgKind::HashSha512, 256),
    (DrbgKind::CtrAes128, 128),
    (DrbgKind::CtrAes192, 192),
    (DrbgKind::CtrAes256, 256),
];

#[test]
fn drbg_generates_and_reseeds() {
    let m = module();
    for (kind, strength) in KINDS {
        let mut first = m.drbg(kind).unwrap();
        let mut second = m.drbg(kind).unwrap();
        first.instantiate(&[]).unwrap();
        second.instantiate(&[]).unwrap();
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        first.generate(&[], &mut a).unwrap();
        second.generate(&[], &mut b).unwrap();
        assert_ne!(a, [0u8; 64], "{kind:?} wrote nothing");
        assert_ne!(
            a, b,
            "two instantiations of {kind:?} produced the same output"
        );

        first.reseed(b"additional").unwrap();
        let mut c = [0u8; 64];
        first.generate(b"more", &mut c).unwrap();
        assert_ne!(a, c, "{kind:?} repeated its output after a reseed");
        assert_eq!(first.strength_bits(), Ok(strength), "{kind:?}");
        assert_eq!(second.strength_bits(), Ok(strength), "{kind:?}");
    }
}

#[test]
fn drbg_states_and_bounds() {
    let m = module();
    let mut drbg = m.drbg(DrbgKind::HmacSha256).unwrap();
    let mut out = [0xAAu8; 16];
    assert_eq!(drbg.generate(&[], &mut out), Err(Error::Uninstantiated));
    assert!(out.iter().all(|b| *b == 0), "output not wiped on error");
    assert_eq!(drbg.reseed(&[]), Err(Error::Uninstantiated));
    assert_eq!(drbg.strength_bits(), Err(Error::Uninstantiated));

    drbg.instantiate(b"p").unwrap();
    drbg.reseed(b"additional").unwrap();
    let mut big = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN + 1];
    assert_eq!(drbg.generate(&[], &mut big), Err(Error::OutputTooLong));
    assert!(big.iter().all(|b| *b == 0), "output not wiped on error");
    big.truncate(HMAC_DRBG_MAX_REQUEST_LEN);
    drbg.generate(b"more", &mut big).unwrap();

    assert_eq!(
        drbg.instantiate(&[0; HMAC_DRBG_MAX_PROVIDED_LEN]),
        Err(Error::InvalidInput),
        "a personalization string as long as everything HMAC_DRBG accepts"
    );
    assert_eq!(
        drbg.strength_bits(),
        Ok(256),
        "a refused instantiation leaves the handle as it was"
    );
}

/// A request over the bound is refused by the crate before the library is
/// called: on an uninstantiated handle the library would answer
/// `Uninstantiated` first.
#[test]
fn drbg_request_bound_is_checked_before_the_call() {
    let m = module();
    let mut drbg = m.drbg(DrbgKind::HmacSha256).unwrap();
    let mut big = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN + 1];
    assert_eq!(drbg.generate(&[], &mut big), Err(Error::OutputTooLong));
    let mut max = vec![0xAAu8; HMAC_DRBG_MAX_REQUEST_LEN];
    assert_eq!(drbg.generate(&[], &mut max), Err(Error::Uninstantiated));
}

fn instantiated(m: Module, kind: DrbgKind) -> Drbg {
    let mut rbg = m.drbg(kind).unwrap();
    rbg.instantiate(b"oxicrypt test").unwrap();
    rbg
}

macro_rules! ml_dsa_round_trip {
    ($name:ident, $keygen:ident, $with_seed:ident, $expand:ident, $sign:ident, $verify:ident) => {
        #[test]
        fn $name() {
            let m = module();
            let mut rbg = instantiated(m, DrbgKind::HmacSha256);
            let (pk, sk) = m.$keygen(&mut rbg).unwrap();
            let sig = m.$sign(&sk, b"message", b"ctx").unwrap();
            assert_eq!(m.$verify(&pk, b"message", b"ctx", &sig), Ok(()));
            assert_eq!(
                m.$verify(&pk, b"messagf", b"ctx", &sig),
                Err(Error::SignatureInvalid)
            );

            let (pk, sk, seed) = m.$with_seed(&mut rbg).unwrap();
            let expanded = m.$expand(&seed).unwrap();
            assert_eq!(expanded.0, pk);
            assert_eq!(expanded.1.as_bytes(), sk.as_bytes());
        }
    };
}

macro_rules! ml_kem_round_trip {
    (
        $name:ident,
        $Dk:ident,
        $keygen:ident,
        $with_seed:ident,
        $expand:ident,
        $encaps:ident,
        $decaps:ident
    ) => {
        #[test]
        fn $name() {
            let m = module();
            let mut rbg = instantiated(m, DrbgKind::HmacSha256);
            let (ek, dk) = m.$keygen(&mut rbg).unwrap();
            let (sent, ct) = m.$encaps(&ek, &mut rbg).unwrap();
            let received = m.$decaps(&dk, &ct).unwrap();
            assert_eq!(received.as_bytes(), sent.as_bytes());

            let (_, other) = m.$keygen(&mut rbg).unwrap();
            let rejected = m.$decaps(&other, &ct).unwrap();
            assert_ne!(rejected.as_bytes(), sent.as_bytes());

            // FIPS 203 §7.2: a 12-bit coefficient of ek at or above
            // q = 3329; 0xFF bytes encode 4095.
            let mut bad_ek = ek;
            bad_ek[..3].fill(0xFF);
            assert_eq!(
                m.$encaps(&bad_ek, &mut rbg).map(drop),
                Err(Error::InvalidInput)
            );

            // FIPS 203 §7.3: dk = dk_PKE ‖ ek ‖ H(ek) ‖ z, so H(ek) starts
            // 64 bytes from the end.
            let mut bytes = *dk.as_bytes();
            let at = bytes.len() - 64;
            bytes[at] ^= 0x01;
            assert_eq!(
                m.$decaps(&$Dk::from_bytes(&bytes), &ct).map(drop),
                Err(Error::InvalidInput)
            );

            let (ek, dk, seed) = m.$with_seed(&mut rbg).unwrap();
            let expanded = m.$expand(&seed).unwrap();
            assert_eq!(expanded.0, ek);
            assert_eq!(expanded.1.as_bytes(), dk.as_bytes());
        }
    };
}

ml_dsa_round_trip!(
    ml_dsa_44_round_trips,
    ml_dsa_44_keygen,
    ml_dsa_44_keygen_with_seed,
    ml_dsa_44_expand_key,
    ml_dsa_44_sign,
    ml_dsa_44_verify
);
ml_dsa_round_trip!(
    ml_dsa_65_round_trips,
    ml_dsa_65_keygen,
    ml_dsa_65_keygen_with_seed,
    ml_dsa_65_expand_key,
    ml_dsa_65_sign,
    ml_dsa_65_verify
);
ml_dsa_round_trip!(
    ml_dsa_87_round_trips,
    ml_dsa_87_keygen,
    ml_dsa_87_keygen_with_seed,
    ml_dsa_87_expand_key,
    ml_dsa_87_sign,
    ml_dsa_87_verify
);
ml_kem_round_trip!(
    ml_kem_512_round_trips,
    MlKem512DecapsulationKey,
    ml_kem_512_keygen,
    ml_kem_512_keygen_with_seed,
    ml_kem_512_expand_key,
    ml_kem_512_encapsulate,
    ml_kem_512_decapsulate
);
ml_kem_round_trip!(
    ml_kem_768_round_trips,
    MlKem768DecapsulationKey,
    ml_kem_768_keygen,
    ml_kem_768_keygen_with_seed,
    ml_kem_768_expand_key,
    ml_kem_768_encapsulate,
    ml_kem_768_decapsulate
);
ml_kem_round_trip!(
    ml_kem_1024_round_trips,
    MlKem1024DecapsulationKey,
    ml_kem_1024_keygen,
    ml_kem_1024_keygen_with_seed,
    ml_kem_1024_expand_key,
    ml_kem_1024_encapsulate,
    ml_kem_1024_decapsulate
);

#[test]
fn a_drbg_weaker_than_the_set_is_refused() {
    let m = module();
    let mut aes128 = instantiated(m, DrbgKind::CtrAes128);
    let mut aes192 = instantiated(m, DrbgKind::CtrAes192);

    assert_eq!(
        m.ml_kem_1024_keygen(&mut aes128).unwrap_err(),
        Error::RbgTooWeak
    );
    assert_eq!(
        m.ml_kem_1024_keygen(&mut aes192).unwrap_err(),
        Error::RbgTooWeak
    );
    assert_eq!(
        m.ml_kem_1024_keygen_with_seed(&mut aes192).unwrap_err(),
        Error::RbgTooWeak
    );
    assert_eq!(
        m.ml_dsa_87_keygen(&mut aes192).unwrap_err(),
        Error::RbgTooWeak
    );
    assert_eq!(
        m.ml_kem_768_keygen(&mut aes128).unwrap_err(),
        Error::RbgTooWeak
    );
    assert_eq!(
        m.ml_dsa_44_keygen(&mut aes128).unwrap_err(),
        Error::RbgTooWeak
    );
    assert_eq!(
        m.ml_dsa_65_keygen(&mut aes128).unwrap_err(),
        Error::RbgTooWeak
    );
    assert_eq!(
        m.ml_dsa_44_keygen_with_seed(&mut aes128).unwrap_err(),
        Error::RbgTooWeak
    );

    let (ek, _) = m
        .ml_kem_1024_keygen(&mut instantiated(m, DrbgKind::CtrAes256))
        .unwrap();
    assert_eq!(
        m.ml_kem_1024_encapsulate(&ek, &mut aes128).unwrap_err(),
        Error::RbgTooWeak
    );
    let (ek768, _) = m.ml_kem_768_keygen(&mut aes192).unwrap();
    assert_eq!(
        m.ml_kem_768_encapsulate(&ek768, &mut aes128).unwrap_err(),
        Error::RbgTooWeak
    );

    // Positive controls: each refused handle serves a set it is strong
    // enough for.
    let (ek, _) = m.ml_kem_512_keygen(&mut aes128).unwrap();
    m.ml_kem_512_encapsulate(&ek, &mut aes128).unwrap();
    m.ml_kem_768_encapsulate(&ek768, &mut aes192).unwrap();
    m.ml_dsa_44_keygen(&mut aes192).unwrap();
    m.ml_dsa_65_keygen(&mut aes192).unwrap();
}

// ACVP ML-DSA specification (draft-celi-acvp-ml-dsa-01) §6.1.2 Table 1,
// rows 1 and 6: seed ξ and SHA2-256(pk ‖ sk), as `oxicrypt-ml-dsa` holds them
// in `seam::ML_DSA_44_ACVP_SEED`, `ML_DSA_44_ACVP_KEY_HASH`,
// `ML_DSA_65_ACVP_SEED` and `ML_DSA_65_ACVP_KEY_HASH`.
const ML_DSA_44_SEED: &str = "5c624fcc1862452452d0c665840d8237f43108e5499edcdc108fbc49d596e4b7";
const ML_DSA_44_KEY_HASH: &str = "ac825c59d8a4c453a2c4efea8395741ca404f3000e28d56b25d03bb402e5cb2f";
const ML_DSA_65_SEED: &str = "464756a985e5df03739d95dd309c1ed9c5b04254cc294e7e7eb9b9365ee15117";
const ML_DSA_65_KEY_HASH: &str = "ae95ea0daa80199e7b4a74eb5a1b1dc6c3805bd01d2fa78d7c4fba8c255aa13d";

#[test]
fn sha256_known_answers() {
    // FIPS 180-4 examples (NIST CSRC "SHA256.pdf", "SHA256_2.pdf") and the
    // empty message, as `sha256sum` prints them.
    for (msg, digest) in [
        (
            &b""[..],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ] {
        assert_eq!(common::sha256(msg).as_slice(), common::unhex(digest));
    }
}

#[test]
fn ml_dsa_44_expand_key_known_answer() {
    let m = module();
    let seed = MlDsa44Seed::from_bytes(&common::array(&common::unhex(ML_DSA_44_SEED)));
    let (pk, sk) = m.ml_dsa_44_expand_key(&seed).unwrap();
    let digest = common::sha256(&[pk.as_slice(), sk.as_bytes()].concat());
    assert_eq!(digest.as_slice(), common::unhex(ML_DSA_44_KEY_HASH));
}

#[test]
fn ml_dsa_65_expand_key_known_answer() {
    let m = module();
    let seed = MlDsa65Seed::from_bytes(&common::array(&common::unhex(ML_DSA_65_SEED)));
    let (pk, sk) = m.ml_dsa_65_expand_key(&seed).unwrap();
    let digest = common::sha256(&[pk.as_slice(), sk.as_bytes()].concat());
    assert_eq!(digest.as_slice(), common::unhex(ML_DSA_65_KEY_HASH));
}

// NIST ACVP-Server ML-KEM-keyGen-FIPS203 `internalProjection.json` at commit
// 112690e8484dba7077709a05b1f3af58ddefdd5d, tgId 1 tcId 1 (ML-KEM-512) and
// tgId 2 tcId 26 (ML-KEM-768), as `oxicrypt-ml-kem` holds them in
// `tests/data/` for its `seam::ML_KEM_*_KEYGEN_*` constants.
const KEM_DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../crates/oxicrypt-ml-kem/tests/data"
);

fn kem_vector(name: &str) -> Vec<u8> {
    let path = format!("{KEM_DATA}/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn kem_seed<const N: usize>(prefix: &str) -> [u8; N] {
    common::array(
        &[
            kem_vector(&format!("{prefix}_d.bin")),
            kem_vector(&format!("{prefix}_z.bin")),
        ]
        .concat(),
    )
}

#[test]
fn ml_kem_512_expand_key_known_answer() {
    let m = module();
    let prefix = "mlkem512_nist_keygen_tg1_tc1";
    let seed = MlKem512Seed::from_bytes(&kem_seed(prefix));
    let (ek, dk) = m.ml_kem_512_expand_key(&seed).unwrap();
    assert_eq!(ek.as_slice(), kem_vector(&format!("{prefix}_ek.bin")));
    assert_eq!(
        dk.as_bytes().as_slice(),
        kem_vector(&format!("{prefix}_dk.bin"))
    );
}

#[test]
fn ml_kem_768_expand_key_known_answer() {
    let m = module();
    let prefix = "mlkem768_nist_keygen_tg2_tc26";
    let seed = MlKem768Seed::from_bytes(&kem_seed(prefix));
    let (ek, dk) = m.ml_kem_768_expand_key(&seed).unwrap();
    assert_eq!(ek.as_slice(), kem_vector(&format!("{prefix}_ek.bin")));
    assert_eq!(
        dk.as_bytes().as_slice(),
        kem_vector(&format!("{prefix}_dk.bin"))
    );
}

#[test]
fn entropy_on_demand_test_names_the_seed_path() {
    let label = module().entropy_on_demand_test().unwrap();
    assert!(!label.is_empty());
    assert_ne!(label, "undecided");
}

#[test]
fn a_cnsa2_request_after_unrestricted_is_a_mismatch() {
    module();
    assert_eq!(
        init(Profile::Cnsa2).unwrap_err().code,
        Error::ProfileMismatch {
            active: Profile::Unrestricted,
            requested: Profile::Cnsa2
        }
    );
}

// ----- AES-128 and AES-192 -----

// McGrew & Viega, "The Galois/Counter Mode of Operation", Appendix B, Test
// Case 3 (AES-128, 64-byte plaintext, no AAD), the module's AES-128 GCM
// self-test.
const GCM128_KEY: &str = "feffe9928665731c6d6a8f9467308308";
const GCM_IV: &str = "cafebabefacedbaddecaf888";
const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                      1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const GCM128_CT: &str = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
const GCM128_TAG: &str = "4d5c2af327cd64a62cf35abd2ba6fab4";

#[test]
fn aes_128_gcm_opens_its_known_answer_and_seals_under_a_ctr_drbg() {
    let m = module();
    let key = m.aes_gcm_key(&common::unhex(GCM128_KEY)).unwrap();
    let pt = common::unhex(GCM_PT);
    let opened = m
        .aes_gcm_open_vec(
            &key,
            &common::array(&common::unhex(GCM_IV)),
            &[],
            &common::unhex(GCM128_CT),
            &common::array(&common::unhex(GCM128_TAG)),
        )
        .unwrap();
    assert_eq!(opened, pt);

    let mut drbg = m.drbg(DrbgKind::CtrAes128).unwrap();
    drbg.instantiate(&[]).unwrap();
    let (ct, sealed) = m.aes_gcm_seal_vec(&key, &mut drbg, b"a", &pt).unwrap();
    assert_eq!(
        m.aes_gcm_open_vec(&key, &sealed.iv, b"a", &ct, &sealed.tag)
            .unwrap(),
        pt
    );
}

// RFC 5649 §6: a 192-bit KEK wrapping 20 bytes of key data.
const KWP_KEK: &str = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";
const KWP_PT: &str = "c37b7e6492584340bed12207808941155068f738";
const KWP_CT: &str = "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a";

#[test]
fn aes_192_kwp_known_answer_both_ways() {
    let m = module();
    let key = m.aes_kw_key(&common::unhex(KWP_KEK)).unwrap();
    let (pt, ct) = (common::unhex(KWP_PT), common::unhex(KWP_CT));
    let mut out = [0u8; 40];
    let n = m.aes_kwp_wrap(&key, &pt, &mut out).unwrap();
    assert_eq!(&out[..n], ct.as_slice());
    let mut back = [0u8; 32];
    let k = m.aes_kwp_unwrap(&key, &ct, &mut back).unwrap();
    assert_eq!(&back[..k], pt.as_slice());

    let mut small = [0xAAu8; 31];
    assert_eq!(
        m.aes_kwp_wrap(&key, &pt, &mut small),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(small, [0; 31]);
    let mut bad = ct.clone();
    bad[0] ^= 1;
    let mut tiny = [0xAAu8; 1];
    assert_eq!(
        m.aes_kwp_unwrap(&key, &bad, &mut tiny),
        Err(Error::TagMismatch),
        "TagMismatch takes precedence over BufferTooSmall"
    );
    assert_eq!(tiny, [0]);
}

// SP 800-38A Appendix F: the F.2 and F.5 plaintext, the CBC IV of F.2 and
// the initial counter block of F.5, with the AES-128 key of F.2.1 and F.5.1
// and the AES-192 key of F.2.3 and F.5.3. The same values are the module's
// CBC and CTR self-tests in crates/oxicrypt-aes/src/kat.rs.
const SP38A_PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                        30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const SP38A_KEY128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const SP38A_KEY192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CTR_ICB: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
// F.2.1 and F.2.3.
const CBC128_CT: &str = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
                         73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7";
const CBC192_CT: &str = "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a\
                         571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd";
// F.5.1 and F.5.3.
const CTR128_CT: &str = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff\
                         5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";
const CTR192_CT: &str = "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94\
                         1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050";

#[test]
fn aes_128_and_192_cbc_known_answers_both_ways() {
    let m = module();
    let (iv, pt) = (
        common::array(&common::unhex(CBC_IV)),
        common::unhex(SP38A_PT),
    );
    for (key, ct) in [(SP38A_KEY128, CBC128_CT), (SP38A_KEY192, CBC192_CT)] {
        let key = m.aes_cbc_key(&common::unhex(key)).unwrap();
        let ct = common::unhex(ct);
        let mut out = vec![0u8; pt.len()];
        m.aes_cbc_encrypt(&key, &iv, &pt, &mut out).unwrap();
        assert_eq!(out, ct);
        m.aes_cbc_decrypt(&key, &iv, &ct, &mut out).unwrap();
        assert_eq!(out, pt);
    }
}

#[test]
fn aes_128_and_192_ctr_known_answers_both_ways() {
    let m = module();
    let (icb, pt) = (
        common::array(&common::unhex(CTR_ICB)),
        common::unhex(SP38A_PT),
    );
    for (key, ct) in [(SP38A_KEY128, CTR128_CT), (SP38A_KEY192, CTR192_CT)] {
        let key = m.aes_ctr_key(&common::unhex(key)).unwrap();
        let ct = common::unhex(ct);
        let mut out = vec![0u8; pt.len()];
        m.aes_ctr(&key, &icb, &pt, &mut out).unwrap();
        assert_eq!(out, ct);
        m.aes_ctr(&key, &icb, &ct, &mut out).unwrap();
        assert_eq!(out, pt);
    }
}

/// Key, nonce, AAD, plaintext, and the ciphertext followed by the tag.
type CcmCase = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

// NIST CAVP CCMVS VPT128.rsp and VPT192.rsp, [Alen = 32, Nlen = 13,
// Tlen = 16, Plen = 16], Count = 160. The same values are the module's CCM
// self-tests in crates/oxicrypt-aes/src/kat.rs.
const CCM_CASES: [CcmCase; 2] = [
    (
        "70010ed90e6186ecad41f0d3c7c42ff8",
        "a5f4f4986e98472965f5abcc4b",
        "3fec0e5cc24d67139437cbc8112414fc8daccd1a94b49a4c76e2d39303547317",
        "be322f58efa7f8c68a635e0b9cce77f2",
        "8e4425ae573974f0f0693a188b525812eef08e3fb15f4227e0d989a4d587a8cf",
    ),
    (
        "6873f1c6c30975aff6f08470264321130a6e5984ade324e9",
        "7c4d2f7cec04361f187f0726d5",
        "77743b5d83a00d2c8d5f7e10781531b496e09f3bc9295d7ae9799e64668ef8c5",
        "5051a0b0b6766cd6ea29a672769d40fe",
        "0ce5ac8d6b256fb7580bf6acc76426af40bce58fd4cd6548df90a0337c842004",
    ),
];

#[test]
fn aes_128_and_192_ccm_known_answers_both_ways() {
    let m = module();
    for (key, nonce, aad, pt, expected) in CCM_CASES {
        let key = m.aes_ccm_key(&common::unhex(key), 16).unwrap();
        let (nonce, aad, pt) = (common::unhex(nonce), common::unhex(aad), common::unhex(pt));
        let expected = common::unhex(expected);
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
    }
}

/// SP 800-38B Appendix D.1, Example 2: AES-128, Mlen = 128.
const CMAC128_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const CMAC128_MSG: &str = "6bc1bee22e409f96e93d7e117393172a";
const CMAC128_TAG: &str = "070a16b46b4d4144f79bdd9dd04a287c";

/// A CMAC key fixes its MAC length: a 16-byte key built for 12-byte MACs
/// produces the leading 12 bytes of the full MAC (SP 800-38B §6.2) and
/// verifies only a 12-byte tag. The full 16-byte MAC, correct as it is, is
/// refused with `InvalidTagLength`, and a 12-byte tag with one bit flipped
/// with `TagMismatch`.
#[test]
fn aes_cmac_key_fixes_its_mac_length() {
    let m = module();
    let key = m.aes_cmac_key(&common::unhex(CMAC128_KEY), 12).unwrap();
    assert_eq!(key.mac_len(), 12);
    let (msg, full) = (common::unhex(CMAC128_MSG), common::unhex(CMAC128_TAG));
    let mut mac = [0u8; 12];
    m.aes_cmac(&key, &msg, &mut mac).unwrap();
    assert_eq!(mac.as_slice(), &full[..12]);
    assert_eq!(m.aes_cmac_verify(&key, &msg, &full[..12]), Ok(()));
    assert_eq!(
        m.aes_cmac_verify(&key, &msg, &full),
        Err(Error::InvalidTagLength)
    );
    assert_eq!(
        m.aes_cmac_verify(&key, &msg, &full[..8]),
        Err(Error::InvalidTagLength)
    );
    mac[11] ^= 1;
    assert_eq!(m.aes_cmac_verify(&key, &msg, &mac), Err(Error::TagMismatch));
}
