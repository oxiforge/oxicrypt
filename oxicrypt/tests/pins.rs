//! The crate's size constants against the algorithm crates' own constants,
//! where those crates export one. The others are pinned by the known-answer
//! tests in `operational.rs` and `unrestricted.rs`, which no wrong length
//! passes.

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
