//! The crate's size constants against the algorithm crates' own constants,
//! where those crates export one. The others are pinned by the known-answer
//! tests in `operational.rs` and `unrestricted.rs`, which no wrong length
//! passes. Also the DRBG functions the C header declares: the module-seeded
//! ones present and no caller-seeded one; the AES functions: the per-mode
//! key handle ones present and none of the `oxi_aes256_` family; and the ABI
//! number the crate is built against.

#![allow(clippy::unwrap_used)]

use oxicrypt as b;

#[test]
fn sizes_match_the_algorithm_crates() {
    assert_eq!(b::SHA384_LEN, oxicrypt_sha::SHA384_DIGEST_SIZE);
    assert_eq!(b::HKDF_SHA384_PRK_LEN, oxicrypt_sha::SHA384_DIGEST_SIZE);
    assert_eq!(
        b::HKDF_SHA384_MAX_OKM_LEN,
        255 * oxicrypt_sha::SHA384_DIGEST_SIZE
    );
    assert_eq!(
        b::HMAC_DRBG_MAX_PROVIDED_LEN,
        oxicrypt_drbg::hmac::HMAC_DRBG_MAX_PROVIDED
    );

    assert_eq!(b::ML_DSA_87_SEED_LEN, oxicrypt_ml_dsa::params::SEED_LEN);
    assert_eq!(b::ML_DSA_87_PUBLIC_KEY_LEN, oxicrypt_ml_dsa::PK_LEN);
    assert_eq!(b::ML_DSA_87_SECRET_KEY_LEN, oxicrypt_ml_dsa::SK_LEN);
    assert_eq!(b::ML_DSA_87_SIGNATURE_LEN, oxicrypt_ml_dsa::SIG_LEN);

    assert_eq!(b::ML_KEM_1024_SEED_LEN, oxicrypt_ml_kem::SEED_LEN);
    assert_eq!(
        b::ML_KEM_1024_ENCAPSULATION_KEY_LEN,
        oxicrypt_ml_kem::EK_LEN
    );
    assert_eq!(
        b::ML_KEM_1024_DECAPSULATION_KEY_LEN,
        oxicrypt_ml_kem::DK_LEN
    );
    assert_eq!(b::ML_KEM_1024_CIPHERTEXT_LEN, oxicrypt_ml_kem::CT_LEN);
    assert_eq!(
        b::ML_KEM_1024_SHARED_SECRET_LEN,
        oxicrypt_ml_kem::SHARED_SECRET_LEN
    );
}

/// The DRBG functions of the C interface: the nine constructors and five
/// calls of the module-seeded handle, the entropy source's on-demand test,
/// and each typed handle's module-seeded instantiate and reseed.
const DRBG_SYMBOLS: [&str; 33] = [
    "oxi_hmac_drbg_sha256_new_rbg",
    "oxi_hmac_drbg_sha384_new_rbg",
    "oxi_hmac_drbg_sha512_new_rbg",
    "oxi_hash_drbg_sha256_new_rbg",
    "oxi_hash_drbg_sha384_new_rbg",
    "oxi_hash_drbg_sha512_new_rbg",
    "oxi_ctr_drbg_aes128_new_rbg",
    "oxi_ctr_drbg_aes192_new_rbg",
    "oxi_ctr_drbg_aes256_new_rbg",
    "oxi_drbg_instantiate",
    "oxi_drbg_reseed",
    "oxi_drbg_generate",
    "oxi_drbg_strength_bits",
    "oxi_drbg_free",
    "oxi_entropy_on_demand_test",
    "oxi_hmac_drbg_sha256_instantiate_from_module",
    "oxi_hmac_drbg_sha256_reseed_from_module",
    "oxi_hmac_drbg_sha384_instantiate_from_module",
    "oxi_hmac_drbg_sha384_reseed_from_module",
    "oxi_hmac_drbg_sha512_instantiate_from_module",
    "oxi_hmac_drbg_sha512_reseed_from_module",
    "oxi_hash_drbg_sha256_instantiate_from_module",
    "oxi_hash_drbg_sha256_reseed_from_module",
    "oxi_hash_drbg_sha384_instantiate_from_module",
    "oxi_hash_drbg_sha384_reseed_from_module",
    "oxi_hash_drbg_sha512_instantiate_from_module",
    "oxi_hash_drbg_sha512_reseed_from_module",
    "oxi_ctr_drbg_aes128_instantiate_from_module",
    "oxi_ctr_drbg_aes128_reseed_from_module",
    "oxi_ctr_drbg_aes192_instantiate_from_module",
    "oxi_ctr_drbg_aes192_reseed_from_module",
    "oxi_ctr_drbg_aes256_instantiate_from_module",
    "oxi_ctr_drbg_aes256_reseed_from_module",
];

/// The AES functions of the C interface: the constructor, free and
/// operations of each mode's key handle.
const AES_SYMBOLS: [&str; 34] = [
    "oxi_aes_gcm_key_new",
    "oxi_aes_gcm_key_new_with_count",
    "oxi_aes_gcm_key_new_with_limit",
    "oxi_aes_gcm_key_invocations",
    "oxi_aes_gcm_key_free",
    "oxi_aes_gcm_seal",
    "oxi_aes_gcm_open",
    "oxi_aes_ccm_key_new",
    "oxi_aes_ccm_key_new_with_count",
    "oxi_aes_ccm_key_invocations",
    "oxi_aes_ccm_key_free",
    "oxi_aes_ccm_seal",
    "oxi_aes_ccm_open",
    "oxi_aes_cbc_key_new",
    "oxi_aes_cbc_key_free",
    "oxi_aes_cbc_encrypt",
    "oxi_aes_cbc_decrypt",
    "oxi_aes_ctr_key_new",
    "oxi_aes_ctr_key_free",
    "oxi_aes_ctr",
    "oxi_aes_kw_key_new",
    "oxi_aes_kw_key_free",
    "oxi_aes_kw_wrap",
    "oxi_aes_kw_unwrap",
    "oxi_aes_kwp_wrap",
    "oxi_aes_kwp_unwrap",
    "oxi_aes_kw_wrap_inverse",
    "oxi_aes_kw_unwrap_inverse",
    "oxi_aes_kwp_wrap_inverse",
    "oxi_aes_kwp_unwrap_inverse",
    "oxi_aes_cmac_key_new",
    "oxi_aes_cmac_key_free",
    "oxi_aes_cmac",
    "oxi_aes_cmac_verify",
];

/// The text of the C header.
fn header_text() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crates/oxicrypt-ffi/include/oxicrypt.h"
    );
    std::fs::read_to_string(path).unwrap()
}

/// The number of `oxi_` functions the header declares: its 319 exports less
/// `lama_manifest`.
const HEADER_OXI_FUNCTIONS: usize = 318;

/// The names of every `oxi_` function the header declares, each followed by
/// `(`.
fn header_function_names() -> Vec<String> {
    header_text()
        .lines()
        .filter(|l| !l.starts_with(' ') && !l.starts_with('#') && l.contains('('))
        .filter_map(|l| {
            let name = l[..l.find('(').unwrap()].rsplit([' ', '*']).next()?;
            name.starts_with("oxi_").then(|| name.to_owned())
        })
        .collect()
}

#[test]
fn the_header_declares_the_drbg_symbols() {
    let names = header_function_names();
    assert!(
        names.iter().any(|n| n == "oxi_sha384"),
        "the scan's positive control"
    );
    for symbol in DRBG_SYMBOLS {
        assert_eq!(
            names.iter().filter(|n| *n == symbol).count(),
            1,
            "{symbol} is not declared exactly once in the header"
        );
    }
}

#[test]
fn the_header_declares_no_caller_seeded_drbg_function() {
    let names = header_function_names();
    assert_eq!(names.len(), HEADER_OXI_FUNCTIONS, "parsed {names:?}");
    let caller_seeded: Vec<_> = names
        .iter()
        // A typed handle's function, `oxi_<mechanism>_drbg_<primitive>_…`.
        .filter(|n| n.find("_drbg_").is_some_and(|at| at > "oxi".len()))
        .filter(|n| {
            ["_instantiate", "_reseed", "_instantiate_df", "_reseed_df"]
                .iter()
                .chain(&["_instantiate_no_df", "_reseed_no_df", "_generate_no_df"])
                .any(|suffix| n.ends_with(suffix))
        })
        .collect();
    assert!(
        caller_seeded.is_empty(),
        "caller-seeded DRBG functions in the header: {caller_seeded:?}"
    );
}

#[test]
fn the_header_declares_the_aes_symbols() {
    let names = header_function_names();
    assert!(
        names.iter().any(|n| n == "oxi_sha384"),
        "the scan's positive control"
    );
    for symbol in AES_SYMBOLS {
        assert_eq!(
            names.iter().filter(|n| *n == symbol).count(),
            1,
            "{symbol} is not declared exactly once in the header"
        );
    }
    let aes: Vec<_> = names.iter().filter(|n| n.starts_with("oxi_aes_")).collect();
    assert_eq!(
        aes.len(),
        AES_SYMBOLS.len(),
        "AES functions in the header: {aes:?}"
    );
}

#[test]
fn the_header_declares_no_aes256_function() {
    let names = header_function_names();
    assert_eq!(names.len(), HEADER_OXI_FUNCTIONS, "parsed {names:?}");
    let aes256: Vec<_> = names
        .iter()
        .filter(|n| n.starts_with("oxi_aes256_"))
        .collect();
    assert!(
        aes256.is_empty(),
        "oxi_aes256_ functions in the header: {aes256:?}"
    );
    let header = header_text();
    assert!(
        header.contains("OxiAesGcmKey"),
        "the scan's positive control"
    );
    assert!(
        !header.contains("OxiAes256"),
        "an OxiAes256 type in the header"
    );
}

#[test]
fn the_crate_is_built_against_abi_3() {
    assert_eq!(b::OXI_ABI_VERSION, 3);
}
