//! The crate's size constants against the algorithm crates' own constants,
//! where those crates export one. The others are pinned by the known-answer
//! tests in `operational.rs` and `unrestricted.rs`, which no wrong length
//! passes. Also the DRBG functions the C header declares: the module-seeded
//! ones present and no caller-seeded one; the AES functions: the per-mode
//! key handle ones present and none of the `oxi_aes256_` family; the ML-DSA
//! and ML-KEM functions, each one named by the safe layer; and the ABI
//! number the crate is built against.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use oxicrypt as b;
use oxicrypt_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use oxicrypt_ml_kem::{ml_kem_512, ml_kem_768, ml_kem_1024};

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

    for seed in [
        b::ML_DSA_44_SEED_LEN,
        b::ML_DSA_65_SEED_LEN,
        b::ML_DSA_87_SEED_LEN,
    ] {
        assert_eq!(seed, oxicrypt_ml_dsa::params::SEED_LEN);
    }
    assert_eq!(b::ML_DSA_44_PUBLIC_KEY_LEN, ml_dsa_44::PK_LEN);
    assert_eq!(b::ML_DSA_44_SECRET_KEY_LEN, ml_dsa_44::SK_LEN);
    assert_eq!(b::ML_DSA_44_SIGNATURE_LEN, ml_dsa_44::SIG_LEN);
    assert_eq!(b::ML_DSA_65_PUBLIC_KEY_LEN, ml_dsa_65::PK_LEN);
    assert_eq!(b::ML_DSA_65_SECRET_KEY_LEN, ml_dsa_65::SK_LEN);
    assert_eq!(b::ML_DSA_65_SIGNATURE_LEN, ml_dsa_65::SIG_LEN);
    assert_eq!(b::ML_DSA_87_PUBLIC_KEY_LEN, ml_dsa_87::PK_LEN);
    assert_eq!(b::ML_DSA_87_SECRET_KEY_LEN, ml_dsa_87::SK_LEN);
    assert_eq!(b::ML_DSA_87_SIGNATURE_LEN, ml_dsa_87::SIG_LEN);

    // d ‖ z, FIPS 203 Algorithm 16.
    for seed in [
        b::ML_KEM_512_SEED_LEN,
        b::ML_KEM_768_SEED_LEN,
        b::ML_KEM_1024_SEED_LEN,
    ] {
        assert_eq!(seed, 2 * oxicrypt_ml_kem::SEED_LEN);
    }
    assert_eq!(b::ML_KEM_512_ENCAPSULATION_KEY_LEN, ml_kem_512::EK_LEN);
    assert_eq!(b::ML_KEM_512_DECAPSULATION_KEY_LEN, ml_kem_512::DK_LEN);
    assert_eq!(b::ML_KEM_512_CIPHERTEXT_LEN, ml_kem_512::CT_LEN);
    assert_eq!(b::ML_KEM_768_ENCAPSULATION_KEY_LEN, ml_kem_768::EK_LEN);
    assert_eq!(b::ML_KEM_768_DECAPSULATION_KEY_LEN, ml_kem_768::DK_LEN);
    assert_eq!(b::ML_KEM_768_CIPHERTEXT_LEN, ml_kem_768::CT_LEN);
    assert_eq!(b::ML_KEM_1024_ENCAPSULATION_KEY_LEN, ml_kem_1024::EK_LEN);
    assert_eq!(b::ML_KEM_1024_DECAPSULATION_KEY_LEN, ml_kem_1024::DK_LEN);
    assert_eq!(b::ML_KEM_1024_CIPHERTEXT_LEN, ml_kem_1024::CT_LEN);
    assert_eq!(
        b::ML_KEM_SHARED_SECRET_LEN,
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

fn header_text() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crates/oxicrypt-ffi/include/oxicrypt.h"
    );
    std::fs::read_to_string(path).unwrap()
}

const HEADER_OXI_FUNCTIONS: usize = 324;

const PQ_SYMBOLS: [&str; 24] = [
    "oxi_ml_dsa_44_keygen_rbg",
    "oxi_ml_dsa_44_expand_key",
    "oxi_ml_dsa_44_sign",
    "oxi_ml_dsa_44_verify",
    "oxi_ml_dsa_65_keygen_rbg",
    "oxi_ml_dsa_65_expand_key",
    "oxi_ml_dsa_65_sign",
    "oxi_ml_dsa_65_verify",
    "oxi_ml_dsa_87_keygen_rbg",
    "oxi_ml_dsa_87_expand_key",
    "oxi_ml_dsa_87_sign",
    "oxi_ml_dsa_87_verify",
    "oxi_ml_kem_512_keygen_rbg",
    "oxi_ml_kem_512_expand_key",
    "oxi_ml_kem_512_encapsulate_rbg",
    "oxi_ml_kem_512_decapsulate",
    "oxi_ml_kem_768_keygen_rbg",
    "oxi_ml_kem_768_expand_key",
    "oxi_ml_kem_768_encapsulate_rbg",
    "oxi_ml_kem_768_decapsulate",
    "oxi_ml_kem_1024_keygen_rbg",
    "oxi_ml_kem_1024_expand_key",
    "oxi_ml_kem_1024_encapsulate_rbg",
    "oxi_ml_kem_1024_decapsulate",
];

fn is_pq(name: &str) -> bool {
    name.starts_with("oxi_ml_dsa_") || name.starts_with("oxi_ml_kem_")
}

fn ops_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ops.rs");
    std::fs::read_to_string(path).unwrap()
}

/// `src` with every line comment and every block comment, nested or not,
/// removed.
fn without_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut depth = 0usize;
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        let next = chars.peek().copied();
        if c == '/' && next == Some('*') {
            chars.next();
            depth = depth.saturating_add(1);
        } else if depth > 0 && c == '*' && next == Some('/') {
            chars.next();
            depth = depth.saturating_sub(1);
        } else if depth == 0 && c == '/' && next == Some('/') {
            for skipped in chars.by_ref() {
                if skipped == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if depth == 0 {
            out.push(c);
        }
    }
    out
}

/// Every `sys::oxi_…` path in `src` outside a comment.
fn named_functions(src: &str) -> BTreeSet<String> {
    let code = without_comments(src);
    code.match_indices("sys::oxi_")
        .map(|(at, _)| {
            code[at..]
                .trim_start_matches("sys::")
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        })
        .collect()
}

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

/// Every ML-DSA and ML-KEM function the header declares is named by the safe
/// layer outside a comment, and no other function of those families is. A
/// name is not a call: that each wrapper calls its function with the right
/// buffers is shown by the linked round trips and known answers in
/// `operational.rs` and `unrestricted.rs`.
///
/// Positive controls: the ML-KEM-768 invocation in `src/ops.rs`, put inside
/// a block comment and then behind line comments, leaves its four functions
/// unnamed.
#[test]
fn pq_symbols() {
    let listed: BTreeSet<String> = PQ_SYMBOLS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(listed.len(), PQ_SYMBOLS.len(), "a symbol listed twice");

    let names = header_function_names();
    assert_eq!(names.len(), HEADER_OXI_FUNCTIONS, "parsed {names:?}");
    let declared: BTreeSet<String> = names.into_iter().filter(|n| is_pq(n)).collect();
    assert_eq!(
        declared, listed,
        "the header's ML-DSA and ML-KEM functions differ from the list"
    );

    let src = ops_source();
    let in_ops = named_functions(&src);
    assert!(
        in_ops.contains("oxi_aes_gcm_seal"),
        "the scan's positive control"
    );
    let wrapped: BTreeSet<String> = in_ops.into_iter().filter(|n| is_pq(n)).collect();
    let unwrapped: Vec<_> = listed.difference(&wrapped).collect();
    let extra: Vec<_> = wrapped.difference(&listed).collect();
    assert!(unwrapped.is_empty(), "not wrapped: {unwrapped:?}");
    assert!(extra.is_empty(), "wrapped, not in the list: {extra:?}");

    let anchor = "ml_kem_wrappers! {\n    set: \"768\",";
    assert_eq!(src.matches(anchor).count(), 1, "the control's anchor");
    let start = src.find(anchor).unwrap();
    let end = start + src[start..].find("\n}\n").unwrap() + "\n}".len();
    let invocation = &src[start..end];
    let block = src.replacen(invocation, &format!("/* {invocation} */"), 1);
    let lines = src.replacen(
        invocation,
        &invocation
            .lines()
            .map(|l| format!("// {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
        1,
    );
    let missing = BTreeSet::from(
        [
            "oxi_ml_kem_768_keygen_rbg",
            "oxi_ml_kem_768_expand_key",
            "oxi_ml_kem_768_encapsulate_rbg",
            "oxi_ml_kem_768_decapsulate",
        ]
        .map(str::to_owned),
    );
    for (how, commented) in [("block", block), ("line", lines)] {
        let still: BTreeSet<String> = named_functions(&commented)
            .into_iter()
            .filter(|n| is_pq(n))
            .collect();
        assert_eq!(
            listed.difference(&still).cloned().collect::<BTreeSet<_>>(),
            missing,
            "a {how}-commented invocation"
        );
    }
}

#[test]
fn the_crate_is_built_against_abi_4() {
    assert_eq!(b::OXI_ABI_VERSION, 4);
}
