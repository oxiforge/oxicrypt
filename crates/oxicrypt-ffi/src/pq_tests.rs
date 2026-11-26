//! The ML-DSA and ML-KEM key generation, key expansion and encapsulation
//! symbols, driven through the C interface. Initialising the module is
//! process-global, so these tests rely on the test runner, nextest, running
//! each test in its own process.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::*;
use core::ptr;
use core::sync::atomic::Ordering;
use oxicrypt_module::{AlgorithmProfile, Error, KatEntry};

/// Stands in for the pre-operational integrity test, which cannot pass in
/// an unsigned test binary.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// The byte every output buffer is filled with before a call, so a failed
/// call that wrote nothing leaves only this byte.
const SENTINEL: u8 = 0xA5;

fn init(profile: AlgorithmProfile) {
    match oxicrypt_module::initialize_with_profile(UNSIGNED_TEST_BINARY, &[], profile) {
        Ok(()) | Err(Error::AlreadyInitialized) => {}
        Err(e) => panic!("module failed to initialise: {e:?}"),
    }
}

type New = unsafe extern "C" fn(*mut *mut OxiDrbg) -> c_int;

fn uninstantiated(new: New) -> *mut OxiDrbg {
    let mut h = ptr::null_mut();
    // SAFETY: `h` is a writable local.
    assert_eq!(unsafe { new(&raw mut h) }, 0);
    h
}

fn instantiated(new: New) -> *mut OxiDrbg {
    let h = uninstantiated(new);
    // SAFETY: `h` is a live handle.
    assert_eq!(unsafe { oxi_drbg_instantiate(h, b"pq".as_ptr(), 2) }, 0);
    h
}

fn free(h: *mut OxiDrbg) {
    // SAFETY: `h` is a live handle no other thread uses.
    unsafe { oxi_drbg_free(h) };
}

fn untouched(buffers: &[&[u8]]) -> bool {
    buffers.iter().all(|b| b.iter().all(|&x| x == SENTINEL))
}

type KeygenRbg = unsafe extern "C" fn(*mut OxiDrbg, *mut u8, *mut u8, *mut u8) -> c_int;
type KemExpand = unsafe extern "C" fn(*const u8, *const u8, *mut u8, *mut u8) -> c_int;
type DsaExpand = unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int;
type Encaps = unsafe extern "C" fn(*const u8, *mut OxiDrbg, *mut u8, *mut u8) -> c_int;
type Decaps = unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int;
type Sign = unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int;
type Verify =
    unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int;

struct Kem {
    name: &'static str,
    ek: usize,
    dk: usize,
    ct: usize,
    strength: u32,
    keygen: KeygenRbg,
    expand: KemExpand,
    encaps: Encaps,
    decaps: Decaps,
}

const KEMS: [Kem; 3] = [
    Kem {
        name: "ML-KEM-512",
        ek: 800,
        dk: 1632,
        ct: 768,
        strength: 128,
        keygen: oxi_ml_kem_512_keygen_rbg,
        expand: oxi_ml_kem_512_expand_key,
        encaps: oxi_ml_kem_512_encapsulate_rbg,
        decaps: oxi_ml_kem_512_decapsulate,
    },
    Kem {
        name: "ML-KEM-768",
        ek: 1184,
        dk: 2400,
        ct: 1088,
        strength: 192,
        keygen: oxi_ml_kem_768_keygen_rbg,
        expand: oxi_ml_kem_768_expand_key,
        encaps: oxi_ml_kem_768_encapsulate_rbg,
        decaps: oxi_ml_kem_768_decapsulate,
    },
    Kem {
        name: "ML-KEM-1024",
        ek: 1568,
        dk: 3168,
        ct: 1568,
        strength: 256,
        keygen: oxi_ml_kem_1024_keygen_rbg,
        expand: oxi_ml_kem_1024_expand_key,
        encaps: oxi_ml_kem_1024_encapsulate_rbg,
        decaps: oxi_ml_kem_1024_decapsulate,
    },
];

struct Dsa {
    name: &'static str,
    pk: usize,
    sk: usize,
    sig: usize,
    strength: u32,
    keygen: KeygenRbg,
    expand: DsaExpand,
    sign: Sign,
    verify: Verify,
}

const DSAS: [Dsa; 3] = [
    Dsa {
        name: "ML-DSA-44",
        pk: 1312,
        sk: 2560,
        sig: 2420,
        strength: 192,
        keygen: oxi_ml_dsa_44_keygen_rbg,
        expand: oxi_ml_dsa_44_expand_key,
        sign: oxi_ml_dsa_44_sign,
        verify: oxi_ml_dsa_44_verify,
    },
    Dsa {
        name: "ML-DSA-65",
        pk: 1952,
        sk: 4032,
        sig: 3309,
        strength: 192,
        keygen: oxi_ml_dsa_65_keygen_rbg,
        expand: oxi_ml_dsa_65_expand_key,
        sign: oxi_ml_dsa_65_sign,
        verify: oxi_ml_dsa_65_verify,
    },
    Dsa {
        name: "ML-DSA-87",
        pk: 2592,
        sk: 4896,
        sig: 4627,
        strength: 256,
        keygen: oxi_ml_dsa_87_keygen_rbg,
        expand: oxi_ml_dsa_87_expand_key,
        sign: oxi_ml_dsa_87_sign,
        verify: oxi_ml_dsa_87_verify,
    },
];

/// One key generation call with sentinel-filled outputs: the code, the two
/// halves and the seed (empty when `seed_len` is 0, which passes NULL).
fn keygen(
    f: KeygenRbg,
    h: *mut OxiDrbg,
    pk_len: usize,
    sk_len: usize,
    seed_len: usize,
) -> (c_int, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut pk = vec![SENTINEL; pk_len];
    let mut sk = vec![SENTINEL; sk_len];
    let mut seed = vec![SENTINEL; seed_len];
    let seed_ptr = if seed_len == 0 {
        ptr::null_mut()
    } else {
        seed.as_mut_ptr()
    };
    // SAFETY: every buffer is a local of its stated length; `h` is NULL or
    // a live handle.
    let rc = unsafe { f(h, pk.as_mut_ptr(), sk.as_mut_ptr(), seed_ptr) };
    (rc, pk, sk, seed)
}

/// One encapsulation with sentinel-filled outputs.
fn encaps(kem: &Kem, ek: &[u8], h: *mut OxiDrbg) -> (c_int, Vec<u8>, Vec<u8>) {
    let mut ss = vec![SENTINEL; 32];
    let mut ct = vec![SENTINEL; kem.ct];
    // SAFETY: `ek` holds `kem.ek` bytes and each output is a local of its
    // stated length; `h` is NULL or a live handle.
    let rc = unsafe { (kem.encaps)(ek.as_ptr(), h, ss.as_mut_ptr(), ct.as_mut_ptr()) };
    (rc, ss, ct)
}

/// SHA2-256(pk ‖ sk), the form the ACVP ML-DSA key-generation vectors pin.
#[cfg(feature = "fault-injection")]
fn key_hash(pk: &[u8], sk: &[u8]) -> [u8; 32] {
    let joined = [pk, sk].concat();
    let mut out = [0u8; 32];
    // SAFETY: `joined` and `out` are locals of the stated lengths.
    assert_eq!(
        unsafe { oxi_sha256(joined.as_ptr(), joined.len(), out.as_mut_ptr()) },
        0
    );
    out
}

#[test]
fn null_handle_returns_10_and_writes_nothing() {
    init(AlgorithmProfile::Unrestricted);
    for dsa in &DSAS {
        let (rc, pk, sk, seed) = keygen(dsa.keygen, ptr::null_mut(), dsa.pk, dsa.sk, 32);
        assert_eq!(rc, 10, "{}", dsa.name);
        assert!(untouched(&[&pk, &sk, &seed]), "{}", dsa.name);
    }
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for kem in &KEMS {
        let (rc, ek, dk, seed) = keygen(kem.keygen, ptr::null_mut(), kem.ek, kem.dk, 64);
        assert_eq!(rc, 10, "{}", kem.name);
        assert!(untouched(&[&ek, &dk, &seed]), "{}", kem.name);
        let (rc, ek, _, _) = keygen(kem.keygen, h, kem.ek, kem.dk, 0);
        assert_eq!(rc, 0, "{}", kem.name);
        let (rc, ss, ct) = encaps(kem, &ek, ptr::null_mut());
        assert_eq!(rc, 10, "{}", kem.name);
        assert!(untouched(&[&ss, &ct]), "{}", kem.name);
        let mut ss = vec![SENTINEL; 32];
        let mut ct = vec![SENTINEL; kem.ct];
        // SAFETY: the outputs are locals of the stated lengths.
        let rc = unsafe { (kem.encaps)(ptr::null(), h, ss.as_mut_ptr(), ct.as_mut_ptr()) };
        assert_eq!(rc, 10, "{} NULL ek", kem.name);
        assert!(untouched(&[&ss, &ct]), "{}", kem.name);
    }
    free(h);
}

#[test]
fn too_weak_handle_returns_31_and_writes_nothing() {
    init(AlgorithmProfile::Unrestricted);
    let strong = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    let weak = instantiated(oxi_ctr_drbg_aes128_new_rbg);
    let mut checked = 0;
    for dsa in DSAS.iter().filter(|d| d.strength > 128) {
        let (rc, pk, sk, seed) = keygen(dsa.keygen, weak, dsa.pk, dsa.sk, 32);
        assert_eq!(rc, 31, "{}", dsa.name);
        assert!(untouched(&[&pk, &sk, &seed]), "{}", dsa.name);
        checked += 1;
    }
    for kem in KEMS.iter().filter(|k| k.strength > 128) {
        let (rc, ek, dk, seed) = keygen(kem.keygen, weak, kem.ek, kem.dk, 64);
        assert_eq!(rc, 31, "{}", kem.name);
        assert!(untouched(&[&ek, &dk, &seed]), "{}", kem.name);
        let (rc, ek, _, _) = keygen(kem.keygen, strong, kem.ek, kem.dk, 0);
        assert_eq!(rc, 0, "{}", kem.name);
        let (rc, ss, ct) = encaps(kem, &ek, weak);
        assert_eq!(rc, 31, "{}", kem.name);
        assert!(untouched(&[&ss, &ct]), "{}", kem.name);
        checked += 1;
    }
    assert_eq!(checked, 5);
    // Positive control: the 128-bit handle meets ML-KEM-512's requirement.
    let (rc, ..) = keygen(KEMS[0].keygen, weak, KEMS[0].ek, KEMS[0].dk, 0);
    assert_eq!(rc, 0);
    free(weak);
    free(strong);
}

#[test]
fn kem_round_trip_through_a_module_seeded_handle() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for kem in &KEMS {
        let (rc, ek, dk, _) = keygen(kem.keygen, h, kem.ek, kem.dk, 0);
        assert_eq!(rc, 0, "{}", kem.name);
        assert!(!untouched(&[&ek]) && !untouched(&[&dk]), "{}", kem.name);
        let (rc, ss, ct) = encaps(kem, &ek, h);
        assert_eq!(rc, 0, "{}", kem.name);
        let mut ss2 = [SENTINEL; 32];
        // SAFETY: `dk`, `ct` and `ss2` are locals of the stated lengths.
        let rc = unsafe { (kem.decaps)(dk.as_ptr(), ct.as_ptr(), ss2.as_mut_ptr()) };
        assert_eq!(rc, 0, "{}", kem.name);
        assert_eq!(ss2.as_slice(), ss.as_slice(), "{}", kem.name);
    }
    free(h);
}

#[test]
fn kem_seed_out_expands_to_the_same_pair() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for kem in &KEMS {
        let (rc, ek, dk, seed) = keygen(kem.keygen, h, kem.ek, kem.dk, 64);
        assert_eq!(rc, 0, "{}", kem.name);
        assert!(!untouched(&[&seed]), "{}: the seed was written", kem.name);
        let mut ek2 = vec![SENTINEL; kem.ek];
        let mut dk2 = vec![SENTINEL; kem.dk];
        // SAFETY: `seed` holds 64 bytes, d then z; the outputs are locals.
        let rc = unsafe {
            (kem.expand)(
                seed.as_ptr(),
                seed[32..].as_ptr(),
                ek2.as_mut_ptr(),
                dk2.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "{}", kem.name);
        assert_eq!((ek2, dk2), (ek, dk), "{}", kem.name);
    }
    free(h);
}

#[test]
fn dsa_round_trip_and_seed_out_expands_to_the_same_pair() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for dsa in &DSAS {
        let (rc, pk, sk, _) = keygen(dsa.keygen, h, dsa.pk, dsa.sk, 0);
        assert_eq!(rc, 0, "{}", dsa.name);
        let mut sig = vec![SENTINEL; dsa.sig];
        let (m, n) = (b"message".as_ptr(), 7);
        // SAFETY: every buffer is a local of its stated length.
        unsafe {
            let rc = (dsa.sign)(sk.as_ptr(), m, n, ptr::null(), 0, sig.as_mut_ptr());
            assert_eq!(rc, 0, "{}", dsa.name);
            let rc = (dsa.verify)(pk.as_ptr(), m, n, ptr::null(), 0, sig.as_ptr());
            assert_eq!(rc, 0, "{}", dsa.name);
        }
        let (rc, pk, sk, seed) = keygen(dsa.keygen, h, dsa.pk, dsa.sk, 32);
        assert_eq!(rc, 0, "{}", dsa.name);
        assert!(!untouched(&[&seed]), "{}: the seed was written", dsa.name);
        let mut pk2 = vec![SENTINEL; dsa.pk];
        let mut sk2 = vec![SENTINEL; dsa.sk];
        // SAFETY: `seed` holds 32 bytes; the outputs are locals.
        let rc = unsafe { (dsa.expand)(seed.as_ptr(), pk2.as_mut_ptr(), sk2.as_mut_ptr()) };
        assert_eq!(rc, 0, "{}", dsa.name);
        assert_eq!((pk2, sk2), (pk, sk), "{}", dsa.name);
    }
    free(h);
}

#[test]
fn overlapping_ranges_return_5_and_write_nothing() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for dsa in &DSAS {
        let mut buf = vec![SENTINEL; dsa.pk + dsa.sk + 64];
        let p = buf.as_mut_ptr();
        // SAFETY: `buf` covers every range passed.
        unsafe {
            assert_eq!((dsa.keygen)(h, p, p, ptr::null_mut()), 5, "{}", dsa.name);
            assert_eq!((dsa.keygen)(h, p, p.add(dsa.pk), h.cast()), 5);
            assert_eq!((dsa.expand)(p, p.add(16), p.add(dsa.pk + 16)), 5);
        }
        assert!(untouched(&[&buf]), "{}", dsa.name);
    }
    for kem in &KEMS {
        let (rc, ek, _, _) = keygen(kem.keygen, h, kem.ek, kem.dk, 0);
        assert_eq!(rc, 0);
        let mut buf = vec![SENTINEL; kem.ek + kem.dk + 64];
        let p = buf.as_mut_ptr();
        // SAFETY: `buf` covers every range passed; `ek` is a local.
        unsafe {
            assert_eq!((kem.keygen)(h, p, p.add(kem.ek - 1), ptr::null_mut()), 5);
            assert_eq!((kem.expand)(p, p.add(32), p.add(16), p.add(16 + kem.ek)), 5);
            assert_eq!((kem.encaps)(ek.as_ptr(), h, p, p.add(31)), 5);
            assert_eq!((kem.encaps)(ek.as_ptr(), h, h.cast(), p), 5);
        }
        assert!(untouched(&[&buf]), "{}", kem.name);
        // Positive control: the same buffers, disjoint, succeed.
        // SAFETY: as above.
        assert_eq!(unsafe { (kem.encaps)(ek.as_ptr(), h, p, p.add(32)) }, 0);
    }
    free(h);
}

#[test]
fn noncanonical_ek_returns_5_before_any_draw() {
    init(AlgorithmProfile::Unrestricted);
    let never = uninstantiated(oxi_hmac_drbg_sha512_new_rbg);
    let good = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for kem in &KEMS {
        let (rc, ek, _, _) = keygen(kem.keygen, good, kem.ek, kem.dk, 0);
        assert_eq!(rc, 0);
        let bad = vec![0xFF; kem.ek];
        let (rc, ss, ct) = encaps(kem, &bad, never);
        assert_eq!(rc, 5, "{}", kem.name);
        assert!(untouched(&[&ss, &ct]), "{}", kem.name);
        // Control: a valid key reaches the draw, which the never
        // instantiated handle refuses.
        let (rc, ss, ct) = encaps(kem, &ek, never);
        assert_eq!(rc, 8, "{}", kem.name);
        assert!(untouched(&[&ss, &ct]), "{}", kem.name);
    }
    free(never);
    free(good);
}

#[test]
fn never_instantiated_handle_returns_8_and_writes_nothing() {
    init(AlgorithmProfile::Unrestricted);
    let never = uninstantiated(oxi_hmac_drbg_sha512_new_rbg);
    for dsa in &DSAS {
        let (rc, pk, sk, seed) = keygen(dsa.keygen, never, dsa.pk, dsa.sk, 32);
        assert_eq!(rc, 8, "{}", dsa.name);
        assert!(untouched(&[&pk, &sk, &seed]), "{}", dsa.name);
    }
    for kem in &KEMS {
        let (rc, ek, dk, seed) = keygen(kem.keygen, never, kem.ek, kem.dk, 64);
        assert_eq!(rc, 8, "{}", kem.name);
        assert!(untouched(&[&ek, &dk, &seed]), "{}", kem.name);
    }
    free(never);
}

#[test]
fn decapsulate_with_a_bad_dk_hash_returns_5() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for kem in &KEMS {
        let (rc, ek, mut dk, _) = keygen(kem.keygen, h, kem.ek, kem.dk, 0);
        assert_eq!(rc, 0);
        let (rc, _, ct) = encaps(kem, &ek, h);
        assert_eq!(rc, 0);
        // dk = dk_PKE ‖ ek ‖ H(ek) ‖ z (FIPS 203 Algorithm 16): the stored
        // hash starts 64 bytes from the end.
        dk[kem.dk - 64] ^= 1;
        let mut ss = [SENTINEL; 32];
        // SAFETY: `dk`, `ct` and `ss` are locals of the stated lengths.
        let rc = unsafe { (kem.decaps)(dk.as_ptr(), ct.as_ptr(), ss.as_mut_ptr()) };
        assert_eq!(rc, 5, "{}", kem.name);
        assert!(untouched(&[&ss]), "{}", kem.name);
    }
    free(h);
}

#[test]
fn busy_handle_returns_32_and_writes_nothing() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    let (rc, ek, _, _) = keygen(KEMS[2].keygen, h, KEMS[2].ek, KEMS[2].dk, 0);
    assert_eq!(rc, 0);
    // SAFETY: `h` is a live handle; only its atomics are touched.
    let drbg = unsafe { &*h };
    drbg.holder
        .store(crate::rbg::current_process(), Ordering::SeqCst);
    for dsa in &DSAS {
        let (rc, pk, sk, seed) = keygen(dsa.keygen, h, dsa.pk, dsa.sk, 32);
        assert_eq!(rc, 32, "{}", dsa.name);
        assert!(untouched(&[&pk, &sk, &seed]), "{}", dsa.name);
    }
    let (rc, ss, ct) = encaps(&KEMS[2], &ek, h);
    assert_eq!(rc, 32);
    assert!(untouched(&[&ss, &ct]));
    drbg.holder.store(0, Ordering::SeqCst);
    assert_eq!(encaps(&KEMS[2], &ek, h).0, 0);
    free(h);
}

#[test]
fn handle_of_another_process_returns_5() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    // SAFETY: `h` is a live handle; only its atomics are touched.
    let drbg = unsafe { &*h };
    let own = drbg.pid.load(Ordering::SeqCst);
    drbg.pid.store(own + 1, Ordering::SeqCst);
    let (rc, pk, sk, seed) = keygen(DSAS[2].keygen, h, DSAS[2].pk, DSAS[2].sk, 32);
    assert_eq!(rc, 5);
    assert!(untouched(&[&pk, &sk, &seed]));
    drbg.pid.store(own, Ordering::SeqCst);
    assert_eq!(keygen(DSAS[2].keygen, h, DSAS[2].pk, DSAS[2].sk, 32).0, 0);
    free(h);
}

/// The module state is checked before the profile: in the error state, a
/// service the profile refuses returns `NotOperational`, not
/// `AlgorithmRestricted`.
#[test]
fn error_state_is_reported_before_the_profile() {
    init(AlgorithmProfile::Cnsa2);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    let kem = &KEMS[0];
    let (rc, ..) = keygen(kem.keygen, h, kem.ek, kem.dk, 0);
    assert_eq!(rc, 6, "control: CNSA 2.0 refuses ML-KEM-512");
    oxicrypt_module::enter_error_state("pq_tests: error state");
    let (rc, ek, dk, _) = keygen(kem.keygen, h, kem.ek, kem.dk, 0);
    assert_eq!(rc, 1);
    assert!(untouched(&[&ek, &dk]));
    let (rc, ..) = keygen(DSAS[0].keygen, h, DSAS[0].pk, DSAS[0].sk, 0);
    assert_eq!(rc, 1);
    free(h);
}

/// The profile is checked before the handle: a busy handle under a profile
/// that refuses the service returns `AlgorithmRestricted`.
#[test]
fn profile_is_checked_before_the_handle() {
    init(AlgorithmProfile::Cnsa2);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    // SAFETY: `h` is a live handle; only its atomics are touched.
    let drbg = unsafe { &*h };
    drbg.holder
        .store(crate::rbg::current_process(), Ordering::SeqCst);
    for (keygen_fn, pk, sk) in [
        (KEMS[0].keygen, KEMS[0].ek, KEMS[0].dk),
        (DSAS[0].keygen, DSAS[0].pk, DSAS[0].sk),
    ] {
        assert_eq!(keygen(keygen_fn, h, pk, sk, 0).0, 6);
    }
    // Control: a service the profile admits reaches the hold.
    assert_eq!(keygen(KEMS[2].keygen, h, KEMS[2].ek, KEMS[2].dk, 0).0, 32);
    drbg.holder.store(0, Ordering::SeqCst);
    assert_eq!(keygen(KEMS[2].keygen, h, KEMS[2].ek, KEMS[2].dk, 0).0, 0);
    free(h);
}

/// `seed_out` overlapping either key output returns 5; `ss_out`
/// overlapping `dk` or `ct` on decapsulation returns 5. Nothing is written.
#[test]
fn overlapping_seed_and_shared_secret_outputs_return_5() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for dsa in &DSAS {
        let mut buf = vec![SENTINEL; dsa.pk + dsa.sk];
        let p = buf.as_mut_ptr();
        // SAFETY: `buf` covers every range passed.
        unsafe {
            assert_eq!((dsa.keygen)(h, p, p.add(dsa.pk), p), 5, "{}", dsa.name);
            let seed_in_sk = p.add(dsa.pk + 8);
            assert_eq!((dsa.keygen)(h, p, p.add(dsa.pk), seed_in_sk), 5);
        }
        assert!(untouched(&[&buf]), "{}", dsa.name);
    }
    for kem in &KEMS {
        let (rc, ek, mut dk, _) = keygen(kem.keygen, h, kem.ek, kem.dk, 0);
        assert_eq!(rc, 0);
        let (rc, _, mut ct) = encaps(kem, &ek, h);
        assert_eq!(rc, 0);
        // SAFETY: `dk` and `ct` are locals of their stated lengths, and every
        // `ss_out` passed lies inside one of them.
        let (dp, cp) = (dk.as_mut_ptr(), ct.as_mut_ptr());
        unsafe {
            assert_eq!((kem.decaps)(dp.cast_const(), cp.cast_const(), dp), 5);
            assert_eq!((kem.decaps)(dp.cast_const(), cp.cast_const(), cp), 5);
        }
        let mut ss = [SENTINEL; 32];
        // Control: a disjoint `ss_out` succeeds on the unchanged inputs.
        // SAFETY: as above, with `ss` a 32-byte local.
        let rc = unsafe { (kem.decaps)(dp.cast_const(), cp.cast_const(), ss.as_mut_ptr()) };
        assert_eq!(rc, 0, "{}", kem.name);
    }
    free(h);
}

/// A copy refused after the first two of three outputs zeroes those two
/// and leaves the third unwritten.
#[test]
fn a_refused_copy_zeroes_the_outputs_already_copied() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    for dsa in &DSAS {
        crate::rbg::WRITES_BEFORE_REFUSAL.set(Some(2));
        let (rc, pk, sk, seed) = keygen(dsa.keygen, h, dsa.pk, dsa.sk, 32);
        assert_eq!(rc, 1, "{}", dsa.name);
        assert!(pk.iter().chain(&sk).all(|&b| b == 0), "{}", dsa.name);
        assert!(untouched(&[&seed]), "{}", dsa.name);
    }
    crate::rbg::WRITES_BEFORE_REFUSAL.set(None);
    free(h);
}

/// The strength check comes before the draw: a never-instantiated 128-bit
/// handle on a set that needs more returns 31, not the 8 a draw would.
#[test]
fn a_weak_never_instantiated_handle_returns_31_before_any_draw() {
    init(AlgorithmProfile::Unrestricted);
    let weak = uninstantiated(oxi_ctr_drbg_aes128_new_rbg);
    for dsa in DSAS.iter().filter(|d| d.strength > 128) {
        let rc = keygen(dsa.keygen, weak, dsa.pk, dsa.sk, 0).0;
        assert_eq!(rc, 31, "{}", dsa.name);
    }
    for kem in KEMS.iter().filter(|k| k.strength > 128) {
        let rc = keygen(kem.keygen, weak, kem.ek, kem.dk, 0).0;
        assert_eq!(rc, 31, "{}", kem.name);
    }
    // Control: on ML-KEM-512, which needs 128 bits, the draw is reached.
    assert_eq!(keygen(KEMS[0].keygen, weak, KEMS[0].ek, KEMS[0].dk, 0).0, 8);
    free(weak);
}

/// Each required pointer of each function, set to NULL in turn, returns 10.
#[test]
fn every_null_required_pointer_returns_10() {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    let mut buf = vec![SENTINEL; 4 * 4896];
    let base = buf.as_mut_ptr();
    // SAFETY: each pointer lies in `buf`, whose quarters are each at least
    // as long as any range passed, so the ranges are disjoint.
    let q = |i: usize| unsafe { base.add(i * 4896) };
    let null = |ptrs: &[*mut u8], i: usize| {
        let mut v = ptrs.to_vec();
        v[i] = ptr::null_mut();
        v
    };
    let mut checked = 0;
    for dsa in &DSAS {
        let ptrs = [h.cast::<u8>(), q(0), q(1)];
        for i in 0..3 {
            let v = null(&ptrs, i);
            // SAFETY: as above; `h` is live.
            let rc = unsafe { (dsa.keygen)(v[0].cast(), v[1], v[2], ptr::null_mut()) };
            assert_eq!(rc, 10, "{} keygen_rbg position {i}", dsa.name);
            checked += 1;
        }
        let ptrs = [q(0), q(1), q(2)];
        for i in 0..3 {
            let v = null(&ptrs, i);
            // SAFETY: as above.
            let rc = unsafe { (dsa.expand)(v[0], v[1], v[2]) };
            assert_eq!(rc, 10, "{} expand_key position {i}", dsa.name);
            checked += 1;
        }
    }
    for kem in &KEMS {
        let ptrs = [h.cast::<u8>(), q(0), q(1)];
        for i in 0..3 {
            let v = null(&ptrs, i);
            // SAFETY: as above; `h` is live.
            let rc = unsafe { (kem.keygen)(v[0].cast(), v[1], v[2], ptr::null_mut()) };
            assert_eq!(rc, 10, "{} keygen_rbg position {i}", kem.name);
            checked += 1;
        }
        let ptrs = [q(0), q(1), q(2), q(3)];
        for i in 0..4 {
            let v = null(&ptrs, i);
            // SAFETY: as above.
            let rc = unsafe { (kem.expand)(v[0], v[1], v[2], v[3]) };
            assert_eq!(rc, 10, "{} expand_key position {i}", kem.name);
            checked += 1;
        }
        let ptrs = [q(0), h.cast::<u8>(), q(1), q(2)];
        for i in 0..4 {
            let v = null(&ptrs, i);
            // SAFETY: as above; `h` is live.
            let rc = unsafe { (kem.encaps)(v[0], v[1].cast(), v[2], v[3]) };
            assert_eq!(rc, 10, "{} encapsulate_rbg position {i}", kem.name);
            checked += 1;
        }
        let ptrs = [q(0), q(1), q(2)];
        for i in 0..3 {
            let v = null(&ptrs, i);
            // SAFETY: as above.
            let rc = unsafe { (kem.decaps)(v[0], v[1], v[2]) };
            assert_eq!(rc, 10, "{} decapsulate position {i}", kem.name);
            checked += 1;
        }
    }
    assert_eq!(checked, 3 * 6 + 3 * 14);
    assert!(untouched(&[&buf]));
    free(h);
}

/// The order around the §7.2 check: a busy handle is reported before a bad
/// `ek`, and a bad `ek` before a weak handle.
#[test]
fn bad_ek_is_checked_after_the_hold_and_before_the_strength() {
    init(AlgorithmProfile::Unrestricted);
    let kem = &KEMS[2];
    let bad = vec![0xFF; kem.ek];
    let busy = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    // SAFETY: `busy` is a live handle; only its atomics are touched.
    let drbg = unsafe { &*busy };
    drbg.holder
        .store(crate::rbg::current_process(), Ordering::SeqCst);
    assert_eq!(encaps(kem, &bad, busy).0, 32);
    drbg.holder.store(0, Ordering::SeqCst);
    let weak = instantiated(oxi_ctr_drbg_aes128_new_rbg);
    assert_eq!(encaps(kem, &bad, weak).0, 5);
    // Control: a valid key on the weak handle reaches the strength check.
    let (rc, ek, _, _) = keygen(kem.keygen, busy, kem.ek, kem.dk, 0);
    assert_eq!(rc, 0);
    assert_eq!(encaps(kem, &ek, weak).0, 31);
    free(weak);
    free(busy);
}

/// Every parameter set's `expand_key` through the C interface against its
/// ACVP key-generation vector. The vectors are exported from each crate's
/// `seam` module, which only a build with `fault-injection` compiles, so the
/// test runs only with the feature.
#[cfg(feature = "fault-injection")]
#[test]
fn expand_key_reproduces_the_acvp_vectors() {
    use oxicrypt_ml_dsa::seam::{
        ML_DSA_44_ACVP_KEY_HASH as HASH_44, ML_DSA_44_ACVP_SEED as SEED_44,
        ML_DSA_65_ACVP_KEY_HASH as HASH_65, ML_DSA_65_ACVP_SEED as SEED_65,
        ML_DSA_87_ACVP_KEY_HASH as HASH_87, ML_DSA_87_ACVP_SEED as SEED_87,
    };
    use oxicrypt_ml_kem::seam as kem;
    type KemVector<'a> = (&'a Kem, &'a [u8; 32], &'a [u8; 32], &'a [u8], &'a [u8]);
    init(AlgorithmProfile::Unrestricted);
    let vectors: [KemVector<'_>; 3] = [
        (
            &KEMS[0],
            kem::ML_KEM_512_KEYGEN_D,
            kem::ML_KEM_512_KEYGEN_Z,
            kem::ML_KEM_512_KEYGEN_EK,
            kem::ML_KEM_512_KEYGEN_DK,
        ),
        (
            &KEMS[1],
            kem::ML_KEM_768_KEYGEN_D,
            kem::ML_KEM_768_KEYGEN_Z,
            kem::ML_KEM_768_KEYGEN_EK,
            kem::ML_KEM_768_KEYGEN_DK,
        ),
        (
            &KEMS[2],
            kem::ML_KEM_1024_KEYGEN_D,
            kem::ML_KEM_1024_KEYGEN_Z,
            kem::ML_KEM_1024_KEYGEN_EK,
            kem::ML_KEM_1024_KEYGEN_DK,
        ),
    ];
    for (set, d, z, want_ek, want_dk) in vectors {
        let mut ek = vec![SENTINEL; set.ek];
        let mut dk = vec![SENTINEL; set.dk];
        // SAFETY: the seeds are 32-byte constants; the outputs are locals.
        let rc = unsafe { (set.expand)(d.as_ptr(), z.as_ptr(), ek.as_mut_ptr(), dk.as_mut_ptr()) };
        assert_eq!(rc, 0, "{}", set.name);
        assert_eq!(ek.as_slice(), want_ek, "{}", set.name);
        assert_eq!(dk.as_slice(), want_dk, "{}", set.name);
    }
    let dsa_vectors = [
        (&DSAS[0], SEED_44, HASH_44),
        (&DSAS[1], SEED_65, HASH_65),
        (&DSAS[2], SEED_87, HASH_87),
    ];
    for (set, seed, hash) in dsa_vectors {
        let mut pk = vec![SENTINEL; set.pk];
        let mut sk = vec![SENTINEL; set.sk];
        // SAFETY: `seed` is a 32-byte constant; the outputs are locals.
        let rc = unsafe { (set.expand)(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) };
        assert_eq!(rc, 0, "{}", set.name);
        assert_eq!(key_hash(&pk, &sk), hash, "{}", set.name);
    }
}

/// An exported arming function of `test_api`.
#[cfg(feature = "fault-injection")]
type Arm = extern "C" fn();

/// Arms every family at once, through the exported all-families function.
#[cfg(feature = "fault-injection")]
extern "C" fn arm_all() {
    crate::test_api::oxi_test_corrupt_next_key(1);
}

/// An ML-DSA-87 key generation from `h`, with the seed returned.
#[cfg(feature = "fault-injection")]
fn ml_dsa_keygen(h: *mut OxiDrbg) -> (c_int, Vec<u8>, Vec<u8>, Vec<u8>) {
    let dsa = &DSAS[2];
    keygen(dsa.keygen, h, dsa.pk, dsa.sk, 32)
}

/// An ML-KEM-1024 key generation from `h`, with the seed returned.
#[cfg(feature = "fault-injection")]
fn ml_kem_keygen(h: *mut OxiDrbg) -> (c_int, Vec<u8>, Vec<u8>, Vec<u8>) {
    let kem = &KEMS[2];
    keygen(kem.keygen, h, kem.ek, kem.dk, 64)
}

/// ML-DSA-87 key expansion of the ACVP seed: the code and both outputs.
#[cfg(feature = "fault-injection")]
fn ml_dsa_expand() -> (c_int, Vec<u8>, Vec<u8>) {
    let set = &DSAS[2];
    let seed = oxicrypt_ml_dsa::seam::ML_DSA_87_ACVP_SEED;
    let (mut pk, mut sk) = (vec![SENTINEL; set.pk], vec![SENTINEL; set.sk]);
    // SAFETY: `seed` is a 32-byte constant; the outputs are locals.
    let rc = unsafe { (set.expand)(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) };
    (rc, pk, sk)
}

/// ML-KEM-1024 key expansion of the ACVP seed: the code and both outputs.
#[cfg(feature = "fault-injection")]
fn ml_kem_expand() -> (c_int, Vec<u8>, Vec<u8>) {
    use oxicrypt_ml_kem::seam as kem;
    let set = &KEMS[2];
    let (d, z) = (kem::ML_KEM_1024_KEYGEN_D, kem::ML_KEM_1024_KEYGEN_Z);
    let (mut ek, mut dk) = (vec![SENTINEL; set.ek], vec![SENTINEL; set.dk]);
    // SAFETY: the seeds are 32-byte constants; the outputs are locals.
    let rc = unsafe { (set.expand)(d.as_ptr(), z.as_ptr(), ek.as_mut_ptr(), dk.as_mut_ptr()) };
    (rc, ek, dk)
}

#[cfg(feature = "fault-injection")]
fn ml_dsa_keygen_pct_failure(arm: Arm) {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    assert_eq!(ml_dsa_keygen(h).0, 0, "control");
    arm();
    let (rc, pk, sk, seed) = ml_dsa_keygen(h);
    assert_eq!(rc, 3);
    assert!(untouched(&[&pk, &sk, &seed]));
    assert_eq!(ml_dsa_keygen(h).0, 1);
    free(h);
}

#[cfg(feature = "fault-injection")]
fn ml_dsa_expand_key_pct_failure(arm: Arm) {
    init(AlgorithmProfile::Unrestricted);
    assert_eq!(ml_dsa_expand().0, 0, "control");
    arm();
    let (rc, pk, sk) = ml_dsa_expand();
    assert_eq!(rc, 3);
    assert!(untouched(&[&pk, &sk]));
    assert_eq!(ml_dsa_expand().0, 1);
}

#[cfg(feature = "fault-injection")]
fn ml_kem_keygen_pct_failure(arm: Arm) {
    init(AlgorithmProfile::Unrestricted);
    let h = instantiated(oxi_hmac_drbg_sha512_new_rbg);
    let kem = &KEMS[2];
    let (rc, public, private, _) = ml_kem_keygen(h);
    assert_eq!(rc, 0, "control");
    let (rc, _, sealed) = encaps(kem, &public, h);
    assert_eq!(rc, 0, "control");
    arm();
    let (rc, ek, dk, seed) = ml_kem_keygen(h);
    assert_eq!(rc, 3);
    assert!(untouched(&[&ek, &dk, &seed]));
    assert_eq!(ml_kem_keygen(h).0, 1);
    let (rc, ss, ct) = encaps(kem, &public, h);
    assert_eq!(rc, 1, "encapsulate_rbg in the error state");
    assert!(untouched(&[&ss, &ct]));
    let mut ss = vec![SENTINEL; 32];
    // SAFETY: `private` and `sealed` hold `kem.dk` and `kem.ct` bytes and
    // `ss` is a local of 32.
    let rc = unsafe { (kem.decaps)(private.as_ptr(), sealed.as_ptr(), ss.as_mut_ptr()) };
    assert_eq!(rc, 1, "decapsulate in the error state");
    assert!(untouched(&[&ss]));
    free(h);
}

#[cfg(feature = "fault-injection")]
fn ml_kem_expand_key_pct_failure(arm: Arm) {
    init(AlgorithmProfile::Unrestricted);
    assert_eq!(ml_kem_expand().0, 0, "control");
    arm();
    let (rc, ek, dk) = ml_kem_expand();
    assert_eq!(rc, 3);
    assert!(untouched(&[&ek, &dk]));
    assert_eq!(ml_kem_expand().0, 1);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ml_dsa_pct_failure_returns_3_then_1() {
    ml_dsa_keygen_pct_failure(crate::test_api::oxi_test_corrupt_next_pk_ml_dsa);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ml_dsa_pct_failure_under_the_all_families_arm() {
    ml_dsa_keygen_pct_failure(arm_all);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ml_dsa_expand_key_pct_failure_returns_3_then_1() {
    ml_dsa_expand_key_pct_failure(crate::test_api::oxi_test_corrupt_next_pk_ml_dsa);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ml_kem_pct_failure_returns_3_then_1() {
    ml_kem_keygen_pct_failure(crate::test_api::oxi_test_corrupt_next_dk_ml_kem);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ml_kem_pct_failure_under_the_all_families_arm() {
    ml_kem_keygen_pct_failure(arm_all);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ml_kem_expand_key_pct_failure_returns_3_then_1() {
    ml_kem_expand_key_pct_failure(crate::test_api::oxi_test_corrupt_next_dk_ml_kem);
}

/// `oxi_test_corrupt_next_key(0)` after arming leaves every family's next
/// key generation on its production path.
#[cfg(feature = "fault-injection")]
#[test]
fn disarming_every_family_restores_key_generation() {
    init(AlgorithmProfile::Unrestricted);
    let (h, typed) = (instantiated(oxi_hmac_drbg_sha512_new_rbg), typed_drbg());
    arm_all();
    crate::test_api::oxi_test_corrupt_next_key(0);
    assert_eq!(ml_dsa_keygen(h).0, 0);
    assert_eq!(ml_kem_keygen(h).0, 0);
    assert_eq!(ecdsa_generate(typed), 0);
    assert_eq!(ecdh_generate(typed).0, 0);
    assert_eq!(rsa_generate(typed), 0);
    free(h);
    // SAFETY: `typed` is live and no other thread uses it.
    unsafe { oxi_hmac_drbg_sha256_free(typed) };
}

/// A typed HMAC_DRBG-SHA-256 handle seeded by the module, as the classical
/// key generation functions take.
#[cfg(feature = "fault-injection")]
fn typed_drbg() -> *mut OxiHmacDrbgSha256 {
    let mut h = ptr::null_mut();
    // SAFETY: `h` is a writable local; the handle is live after `_new`.
    unsafe {
        assert_eq!(oxi_hmac_drbg_sha256_new(&raw mut h), 0);
        let rc = oxi_hmac_drbg_sha256_instantiate_from_module(h, b"pq".as_ptr(), 2);
        assert_eq!(rc, 0);
    }
    h
}

/// An ECDSA P-256 key generation from `h`; a key it returns is freed.
#[cfg(feature = "fault-injection")]
fn ecdsa_generate(h: *mut OxiHmacDrbgSha256) -> c_int {
    let mut key = ptr::null_mut();
    // SAFETY: `h` is live and `key` a writable local; a returned key is
    // live until freed here.
    unsafe {
        let rc = oxi_ecdsa_p256_private_key_new_generate(h, &raw mut key);
        if rc != 0 {
            assert!(key.is_null());
        }
        oxi_ecdsa_p256_private_key_free(key);
        rc
    }
}

/// An ECDH P-256 key pair generation from `h`: the code and whether both
/// outputs are untouched.
#[cfg(feature = "fault-injection")]
fn ecdh_generate(h: *mut OxiHmacDrbgSha256) -> (c_int, bool) {
    let (mut d, mut q) = ([SENTINEL; 32], [SENTINEL; 65]);
    // SAFETY: `h` is live and the outputs are locals of the stated lengths.
    let rc = unsafe { oxi_ecdh_p256_generate_keypair(h, d.as_mut_ptr(), q.as_mut_ptr()) };
    (rc, untouched(&[&d, &q]))
}

/// An RSA-2048 key generation from `h`; a key it returns is freed.
#[cfg(feature = "fault-injection")]
fn rsa_generate(h: *mut OxiHmacDrbgSha256) -> c_int {
    let mut key = ptr::null_mut();
    // SAFETY: `h` is live and `key` a writable local; a returned key is
    // live until freed here.
    unsafe {
        let rc = oxi_rsa_2048_private_key_new_generate(h, 65537, &raw mut key);
        if rc != 0 {
            assert!(key.is_null());
        }
        oxi_rsa_2048_private_key_free(key);
        rc
    }
}

/// Expects 0 from `generate`, then arms through `arm` and expects 3 from
/// `generate` and 1 from the call after it, on one typed handle made before
/// the fault.
#[cfg(feature = "fault-injection")]
fn classical_pct_failure(arm: Arm, generate: fn(*mut OxiHmacDrbgSha256) -> c_int) {
    init(AlgorithmProfile::Unrestricted);
    let h = typed_drbg();
    assert_eq!(generate(h), 0, "control");
    arm();
    assert_eq!(generate(h), 3);
    assert_eq!(generate(h), 1);
    // SAFETY: `h` is live and no other thread uses it.
    unsafe { oxi_hmac_drbg_sha256_free(h) };
}

#[cfg(feature = "fault-injection")]
fn ecdsa_pct_failure(arm: Arm) {
    classical_pct_failure(arm, ecdsa_generate);
}

#[cfg(feature = "fault-injection")]
fn ecdh_pct_failure(arm: Arm) {
    classical_pct_failure(arm, |h| {
        let (rc, untouched) = ecdh_generate(h);
        assert!(rc == 0 || untouched, "nothing is written on a failure");
        rc
    });
}

#[cfg(feature = "fault-injection")]
fn rsa_pct_failure(arm: Arm) {
    classical_pct_failure(arm, rsa_generate);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ecdsa_pct_failure_returns_3_then_1() {
    ecdsa_pct_failure(crate::test_api::oxi_test_corrupt_next_pk_ecdsa);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ecdsa_pct_failure_under_the_all_families_arm() {
    ecdsa_pct_failure(arm_all);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ecdh_pct_failure_returns_3_then_1() {
    ecdh_pct_failure(crate::test_api::oxi_test_corrupt_next_pk_ecdh);
}

#[cfg(feature = "fault-injection")]
#[test]
fn ecdh_pct_failure_under_the_all_families_arm() {
    ecdh_pct_failure(arm_all);
}

#[cfg(feature = "fault-injection")]
#[test]
fn rsa_pct_failure_returns_3_then_1() {
    rsa_pct_failure(crate::test_api::oxi_test_corrupt_next_pk_rsa);
}

#[cfg(feature = "fault-injection")]
#[test]
fn rsa_pct_failure_under_the_all_families_arm() {
    rsa_pct_failure(arm_all);
}
