//! One function pointer per declaration of `sys.rs`, each with the
//! declaration's exact type. Included only by the `inventory` test binary,
//! next to `sys.rs` itself; never part of the library.

#![allow(clippy::struct_field_names, clippy::too_many_lines)]

use super::sys::*;
use core::ffi::{c_char, c_int};

/// One function pointer per declaration of `sys.rs`, each with the
/// declaration's exact type.
pub(crate) struct Inventory {
    pub(crate) lama_manifest: unsafe extern "C" fn() -> *const c_char,
    pub(crate) oxi_init: unsafe extern "C" fn(c_int) -> c_int,
    pub(crate) oxi_active_profile: unsafe extern "C" fn() -> c_int,
    pub(crate) oxi_is_operational: unsafe extern "C" fn() -> c_int,
    pub(crate) oxi_integrity_status: unsafe extern "C" fn() -> c_int,
    pub(crate) oxi_integrity_key_fingerprint: unsafe extern "C" fn(*mut u8, usize) -> c_int,
    pub(crate) oxi_integrity_status_detail:
        unsafe extern "C" fn(*mut u8, usize, *mut usize) -> c_int,
    pub(crate) oxi_sha256: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha512: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha224: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha384: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha512_224: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha512_256: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha3_224: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha3_256: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha3_384: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_sha3_512: unsafe extern "C" fn(*const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hmac_sha256:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hmac_sha384:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hmac_sha512:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hmac_sha3_224:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hmac_sha3_256:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hmac_sha3_384:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hmac_sha3_512:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_ecdsa_p256_derive_public_key: unsafe extern "C" fn(*const u8, *mut u8) -> c_int,
    pub(crate) oxi_ecdsa_p256_sign_with_k:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_ecdsa_p256_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_ecdsa_p384_derive_public_key: unsafe extern "C" fn(*const u8, *mut u8) -> c_int,
    pub(crate) oxi_ecdsa_p384_sign_with_k:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_ecdsa_p384_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_hkdf_sha256_extract:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hkdf_sha256_expand:
        unsafe extern "C" fn(*const u8, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_hkdf_sha384_extract:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hkdf_sha384_expand:
        unsafe extern "C" fn(*const u8, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_hkdf_sha512_extract:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_hkdf_sha512_expand:
        unsafe extern "C" fn(*const u8, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_tls13_hkdf_expand_label_sha256: unsafe extern "C" fn(
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_tls13_hkdf_expand_label_sha384: unsafe extern "C" fn(
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_tls13_derive_secret_sha256: unsafe extern "C" fn(
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_tls13_derive_secret_sha384: unsafe extern "C" fn(
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_ed25519_keygen: unsafe extern "C" fn(*const u8, *mut u8) -> c_int,
    pub(crate) oxi_ed25519_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_ed25519_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_ecdh_p256_compute_shared_secret:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_ecdh_p384_compute_shared_secret:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_ecdh_p256_generate_keypair:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ecdh_p384_generate_keypair:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_dh3072_compute_shared_secret:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_dh3072_generate_keypair:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_rsa_pkcs1_v15_verify_2048_sha256:
        unsafe extern "C" fn(*const u8, u64, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_rsa_pss_verify_2048_sha256:
        unsafe extern "C" fn(*const u8, u64, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_rsa_pkcs1_v15_verify_3072_sha256:
        unsafe extern "C" fn(*const u8, u64, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_rsa_pss_verify_3072_sha256:
        unsafe extern "C" fn(*const u8, u64, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_rsa_pkcs1_v15_verify_4096_sha256:
        unsafe extern "C" fn(*const u8, u64, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_rsa_pss_verify_4096_sha256:
        unsafe extern "C" fn(*const u8, u64, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_ml_dsa_87_keygen: unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_dsa_87_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_ml_dsa_87_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_ml_dsa_44_keygen: unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_dsa_44_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_ml_dsa_44_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_ml_dsa_65_keygen: unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_dsa_65_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_ml_dsa_65_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_ml_kem_1024_keygen:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_1024_encapsulate:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_1024_decapsulate:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_512_keygen:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_512_encapsulate:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_512_decapsulate:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_768_keygen:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_768_encapsulate:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_ml_kem_768_decapsulate:
        unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_256s_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_256s_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_256s_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_128s_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_128s_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_128s_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_128f_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_128f_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_128f_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_192s_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_192s_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_192s_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_192f_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_192f_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_192f_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_256f_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_256f_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_sha2_256f_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_128s_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_128s_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_128s_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_128f_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_128f_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_128f_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_192s_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_192s_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_192s_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_192f_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_192f_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_192f_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_256s_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_256s_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_256s_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_256f_keygen:
        unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_256f_sign:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_slh_dsa_shake_256f_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_verify_any:
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h5_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h5_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h5_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h5_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h10_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h10_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h10_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h10_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h15_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h15_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h15_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h15_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h20_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h20_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h20_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h20_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h25_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h25_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h25_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m32_h25_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h5_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h5_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h5_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h5_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h10_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h10_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h10_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h10_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h15_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h15_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h15_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h15_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h20_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h20_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h20_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h20_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h25_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h25_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h25_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_sha256_m24_h25_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h5_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h5_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h5_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h5_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h10_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h10_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h10_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h10_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h15_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h15_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h15_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h15_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h20_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h20_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h20_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h20_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h25_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h25_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h25_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m32_h25_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h5_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h5_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h5_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h5_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h10_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h10_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h10_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h10_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h15_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h15_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h15_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h15_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h20_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h20_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h20_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h20_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h25_w1_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h25_w2_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h25_w4_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_lms_shake_m24_h25_w8_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_xmss_verify:
        unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int,
    pub(crate) oxi_ecdsa_p256_private_key_new_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, *mut *mut OxiEcdsaP256PrivateKey) -> c_int,
    pub(crate) oxi_ecdsa_p256_private_key_free: unsafe extern "C" fn(*mut OxiEcdsaP256PrivateKey),
    pub(crate) oxi_ecdsa_p256_private_key_public_key:
        unsafe extern "C" fn(*const OxiEcdsaP256PrivateKey, *mut u8) -> c_int,
    pub(crate) oxi_ecdsa_p256_private_key_sign_sha256: unsafe extern "C" fn(
        *const OxiEcdsaP256PrivateKey,
        *mut OxiHmacDrbgSha256,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_ecdsa_p384_private_key_new_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, *mut *mut OxiEcdsaP384PrivateKey) -> c_int,
    pub(crate) oxi_ecdsa_p384_private_key_free: unsafe extern "C" fn(*mut OxiEcdsaP384PrivateKey),
    pub(crate) oxi_ecdsa_p384_private_key_public_key:
        unsafe extern "C" fn(*const OxiEcdsaP384PrivateKey, *mut u8) -> c_int,
    pub(crate) oxi_ecdsa_p384_private_key_sign_sha384: unsafe extern "C" fn(
        *const OxiEcdsaP384PrivateKey,
        *mut OxiHmacDrbgSha256,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_rsa_2048_private_key_new_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, u64, *mut *mut OxiRsaPrivateKey2048) -> c_int,
    pub(crate) oxi_rsa_2048_private_key_free: unsafe extern "C" fn(*mut OxiRsaPrivateKey2048),
    pub(crate) oxi_rsa_2048_modulus:
        unsafe extern "C" fn(*const OxiRsaPrivateKey2048, *mut u8) -> c_int,
    pub(crate) oxi_rsa_2048_public_exponent:
        unsafe extern "C" fn(*const OxiRsaPrivateKey2048, *mut u64) -> c_int,
    pub(crate) oxi_rsa_2048_sign_pkcs1_v15_sha256:
        unsafe extern "C" fn(*const OxiRsaPrivateKey2048, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_rsa_2048_sign_pss_sha256: unsafe extern "C" fn(
        *const OxiRsaPrivateKey2048,
        *mut OxiHmacDrbgSha256,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_rsa_2048_oaep_encrypt_sha256: unsafe extern "C" fn(
        *mut OxiHmacDrbgSha256,
        *const u8,
        u64,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_rsa_2048_oaep_decrypt_sha256: unsafe extern "C" fn(
        *const OxiRsaPrivateKey2048,
        *const u8,
        usize,
        *const u8,
        *mut u8,
        usize,
        *mut usize,
    ) -> c_int,
    pub(crate) oxi_rsa_3072_private_key_new_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, u64, *mut *mut OxiRsaPrivateKey3072) -> c_int,
    pub(crate) oxi_rsa_3072_private_key_free: unsafe extern "C" fn(*mut OxiRsaPrivateKey3072),
    pub(crate) oxi_rsa_3072_modulus:
        unsafe extern "C" fn(*const OxiRsaPrivateKey3072, *mut u8) -> c_int,
    pub(crate) oxi_rsa_3072_public_exponent:
        unsafe extern "C" fn(*const OxiRsaPrivateKey3072, *mut u64) -> c_int,
    pub(crate) oxi_rsa_3072_sign_pkcs1_v15_sha256:
        unsafe extern "C" fn(*const OxiRsaPrivateKey3072, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_rsa_3072_sign_pss_sha256: unsafe extern "C" fn(
        *const OxiRsaPrivateKey3072,
        *mut OxiHmacDrbgSha256,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_rsa_3072_oaep_encrypt_sha256: unsafe extern "C" fn(
        *mut OxiHmacDrbgSha256,
        *const u8,
        u64,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_rsa_3072_oaep_decrypt_sha256: unsafe extern "C" fn(
        *const OxiRsaPrivateKey3072,
        *const u8,
        usize,
        *const u8,
        *mut u8,
        usize,
        *mut usize,
    ) -> c_int,
    pub(crate) oxi_rsa_4096_private_key_new_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, u64, *mut *mut OxiRsaPrivateKey4096) -> c_int,
    pub(crate) oxi_rsa_4096_private_key_free: unsafe extern "C" fn(*mut OxiRsaPrivateKey4096),
    pub(crate) oxi_rsa_4096_modulus:
        unsafe extern "C" fn(*const OxiRsaPrivateKey4096, *mut u8) -> c_int,
    pub(crate) oxi_rsa_4096_public_exponent:
        unsafe extern "C" fn(*const OxiRsaPrivateKey4096, *mut u64) -> c_int,
    pub(crate) oxi_rsa_4096_sign_pkcs1_v15_sha256:
        unsafe extern "C" fn(*const OxiRsaPrivateKey4096, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_rsa_4096_sign_pss_sha256: unsafe extern "C" fn(
        *const OxiRsaPrivateKey4096,
        *mut OxiHmacDrbgSha256,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_rsa_4096_oaep_encrypt_sha256: unsafe extern "C" fn(
        *mut OxiHmacDrbgSha256,
        *const u8,
        u64,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_rsa_4096_oaep_decrypt_sha256: unsafe extern "C" fn(
        *const OxiRsaPrivateKey4096,
        *const u8,
        usize,
        *const u8,
        *mut u8,
        usize,
        *mut usize,
    ) -> c_int,
    pub(crate) oxi_aes256_new: unsafe extern "C" fn(*mut *mut OxiAes256Key, *const u8) -> c_int,
    pub(crate) oxi_aes256_free: unsafe extern "C" fn(*mut OxiAes256Key),
    pub(crate) oxi_aes256_gcm_encrypt: unsafe extern "C" fn(
        *const OxiAes256Key,
        *const u8,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_aes256_gcm_decrypt: unsafe extern "C" fn(
        *const OxiAes256Key,
        *const u8,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        *const u8,
    ) -> c_int,
    pub(crate) oxi_aes256_cbc_encrypt:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_aes256_cbc_decrypt:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_aes256_ctr:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_aes256_ccm_encrypt: unsafe extern "C" fn(
        *const OxiAes256Key,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_aes256_ccm_decrypt: unsafe extern "C" fn(
        *const OxiAes256Key,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        usize,
        *mut u8,
    ) -> c_int,
    pub(crate) oxi_aes256_cmac:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_aes256_kw_wrap:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_aes256_kw_unwrap:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_aes256_kwp_wrap:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, usize, *mut u8) -> c_int,
    pub(crate) oxi_aes256_kwp_unwrap:
        unsafe extern "C" fn(*const OxiAes256Key, *const u8, usize, *mut u8, *mut usize) -> c_int,
    pub(crate) oxi_hmac_drbg_sha256_new: unsafe extern "C" fn(*mut *mut OxiHmacDrbgSha256) -> c_int,
    pub(crate) oxi_hmac_drbg_sha256_free: unsafe extern "C" fn(*mut OxiHmacDrbgSha256),
    pub(crate) oxi_hmac_drbg_sha256_instantiate: unsafe extern "C" fn(
        *mut OxiHmacDrbgSha256,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_hmac_drbg_sha256_reseed:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_hmac_drbg_sha256_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha256, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_hmac_drbg_sha384_new: unsafe extern "C" fn(*mut *mut OxiHmacDrbgSha384) -> c_int,
    pub(crate) oxi_hmac_drbg_sha384_free: unsafe extern "C" fn(*mut OxiHmacDrbgSha384),
    pub(crate) oxi_hmac_drbg_sha384_instantiate: unsafe extern "C" fn(
        *mut OxiHmacDrbgSha384,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_hmac_drbg_sha384_reseed:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha384, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_hmac_drbg_sha384_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha384, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_hmac_drbg_sha512_new: unsafe extern "C" fn(*mut *mut OxiHmacDrbgSha512) -> c_int,
    pub(crate) oxi_hmac_drbg_sha512_free: unsafe extern "C" fn(*mut OxiHmacDrbgSha512),
    pub(crate) oxi_hmac_drbg_sha512_instantiate: unsafe extern "C" fn(
        *mut OxiHmacDrbgSha512,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_hmac_drbg_sha512_reseed:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha512, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_hmac_drbg_sha512_generate:
        unsafe extern "C" fn(*mut OxiHmacDrbgSha512, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_hash_drbg_sha256_new: unsafe extern "C" fn(*mut *mut OxiHashDrbgSha256) -> c_int,
    pub(crate) oxi_hash_drbg_sha256_free: unsafe extern "C" fn(*mut OxiHashDrbgSha256),
    pub(crate) oxi_hash_drbg_sha256_instantiate: unsafe extern "C" fn(
        *mut OxiHashDrbgSha256,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_hash_drbg_sha256_reseed:
        unsafe extern "C" fn(*mut OxiHashDrbgSha256, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_hash_drbg_sha256_generate:
        unsafe extern "C" fn(*mut OxiHashDrbgSha256, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_hash_drbg_sha384_new: unsafe extern "C" fn(*mut *mut OxiHashDrbgSha384) -> c_int,
    pub(crate) oxi_hash_drbg_sha384_free: unsafe extern "C" fn(*mut OxiHashDrbgSha384),
    pub(crate) oxi_hash_drbg_sha384_instantiate: unsafe extern "C" fn(
        *mut OxiHashDrbgSha384,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_hash_drbg_sha384_reseed:
        unsafe extern "C" fn(*mut OxiHashDrbgSha384, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_hash_drbg_sha384_generate:
        unsafe extern "C" fn(*mut OxiHashDrbgSha384, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_hash_drbg_sha512_new: unsafe extern "C" fn(*mut *mut OxiHashDrbgSha512) -> c_int,
    pub(crate) oxi_hash_drbg_sha512_free: unsafe extern "C" fn(*mut OxiHashDrbgSha512),
    pub(crate) oxi_hash_drbg_sha512_instantiate: unsafe extern "C" fn(
        *mut OxiHashDrbgSha512,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_hash_drbg_sha512_reseed:
        unsafe extern "C" fn(*mut OxiHashDrbgSha512, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_hash_drbg_sha512_generate:
        unsafe extern "C" fn(*mut OxiHashDrbgSha512, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes128_new: unsafe extern "C" fn(*mut *mut OxiCtrDrbgAes128) -> c_int,
    pub(crate) oxi_ctr_drbg_aes128_free: unsafe extern "C" fn(*mut OxiCtrDrbgAes128),
    pub(crate) oxi_ctr_drbg_aes128_instantiate_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes128, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes128_instantiate_df: unsafe extern "C" fn(
        *mut OxiCtrDrbgAes128,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_ctr_drbg_aes128_reseed_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes128, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes128_reseed_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes128, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes128_generate_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes128, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes128_generate_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes128, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes192_new: unsafe extern "C" fn(*mut *mut OxiCtrDrbgAes192) -> c_int,
    pub(crate) oxi_ctr_drbg_aes192_free: unsafe extern "C" fn(*mut OxiCtrDrbgAes192),
    pub(crate) oxi_ctr_drbg_aes192_instantiate_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes192, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes192_instantiate_df: unsafe extern "C" fn(
        *mut OxiCtrDrbgAes192,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_ctr_drbg_aes192_reseed_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes192, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes192_reseed_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes192, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes192_generate_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes192, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes192_generate_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes192, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes256_new: unsafe extern "C" fn(*mut *mut OxiCtrDrbgAes256) -> c_int,
    pub(crate) oxi_ctr_drbg_aes256_free: unsafe extern "C" fn(*mut OxiCtrDrbgAes256),
    pub(crate) oxi_ctr_drbg_aes256_instantiate_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes256, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes256_instantiate_df: unsafe extern "C" fn(
        *mut OxiCtrDrbgAes256,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int,
    pub(crate) oxi_ctr_drbg_aes256_reseed_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes256, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes256_reseed_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes256, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes256_generate_no_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes256, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) oxi_ctr_drbg_aes256_generate_df:
        unsafe extern "C" fn(*mut OxiCtrDrbgAes256, *const u8, usize, *mut u8, usize) -> c_int,
}

/// Kept by `#[used]` so the final link records an import of every declared
/// function, and read by a test so that its use is executed.
#[used]
pub(crate) static INVENTORY: Inventory = Inventory {
    lama_manifest,
    oxi_init,
    oxi_active_profile,
    oxi_is_operational,
    oxi_integrity_status,
    oxi_integrity_key_fingerprint,
    oxi_integrity_status_detail,
    oxi_sha256,
    oxi_sha512,
    oxi_sha224,
    oxi_sha384,
    oxi_sha512_224,
    oxi_sha512_256,
    oxi_sha3_224,
    oxi_sha3_256,
    oxi_sha3_384,
    oxi_sha3_512,
    oxi_hmac_sha256,
    oxi_hmac_sha384,
    oxi_hmac_sha512,
    oxi_hmac_sha3_224,
    oxi_hmac_sha3_256,
    oxi_hmac_sha3_384,
    oxi_hmac_sha3_512,
    oxi_ecdsa_p256_derive_public_key,
    oxi_ecdsa_p256_sign_with_k,
    oxi_ecdsa_p256_verify,
    oxi_ecdsa_p384_derive_public_key,
    oxi_ecdsa_p384_sign_with_k,
    oxi_ecdsa_p384_verify,
    oxi_hkdf_sha256_extract,
    oxi_hkdf_sha256_expand,
    oxi_hkdf_sha384_extract,
    oxi_hkdf_sha384_expand,
    oxi_hkdf_sha512_extract,
    oxi_hkdf_sha512_expand,
    oxi_tls13_hkdf_expand_label_sha256,
    oxi_tls13_hkdf_expand_label_sha384,
    oxi_tls13_derive_secret_sha256,
    oxi_tls13_derive_secret_sha384,
    oxi_ed25519_keygen,
    oxi_ed25519_sign,
    oxi_ed25519_verify,
    oxi_ecdh_p256_compute_shared_secret,
    oxi_ecdh_p384_compute_shared_secret,
    oxi_ecdh_p256_generate_keypair,
    oxi_ecdh_p384_generate_keypair,
    oxi_dh3072_compute_shared_secret,
    oxi_dh3072_generate_keypair,
    oxi_rsa_pkcs1_v15_verify_2048_sha256,
    oxi_rsa_pss_verify_2048_sha256,
    oxi_rsa_pkcs1_v15_verify_3072_sha256,
    oxi_rsa_pss_verify_3072_sha256,
    oxi_rsa_pkcs1_v15_verify_4096_sha256,
    oxi_rsa_pss_verify_4096_sha256,
    oxi_ml_dsa_87_keygen,
    oxi_ml_dsa_87_sign,
    oxi_ml_dsa_87_verify,
    oxi_ml_dsa_44_keygen,
    oxi_ml_dsa_44_sign,
    oxi_ml_dsa_44_verify,
    oxi_ml_dsa_65_keygen,
    oxi_ml_dsa_65_sign,
    oxi_ml_dsa_65_verify,
    oxi_ml_kem_1024_keygen,
    oxi_ml_kem_1024_encapsulate,
    oxi_ml_kem_1024_decapsulate,
    oxi_ml_kem_512_keygen,
    oxi_ml_kem_512_encapsulate,
    oxi_ml_kem_512_decapsulate,
    oxi_ml_kem_768_keygen,
    oxi_ml_kem_768_encapsulate,
    oxi_ml_kem_768_decapsulate,
    oxi_slh_dsa_sha2_256s_keygen,
    oxi_slh_dsa_sha2_256s_sign,
    oxi_slh_dsa_sha2_256s_verify,
    oxi_slh_dsa_sha2_128s_keygen,
    oxi_slh_dsa_sha2_128s_sign,
    oxi_slh_dsa_sha2_128s_verify,
    oxi_slh_dsa_sha2_128f_keygen,
    oxi_slh_dsa_sha2_128f_sign,
    oxi_slh_dsa_sha2_128f_verify,
    oxi_slh_dsa_sha2_192s_keygen,
    oxi_slh_dsa_sha2_192s_sign,
    oxi_slh_dsa_sha2_192s_verify,
    oxi_slh_dsa_sha2_192f_keygen,
    oxi_slh_dsa_sha2_192f_sign,
    oxi_slh_dsa_sha2_192f_verify,
    oxi_slh_dsa_sha2_256f_keygen,
    oxi_slh_dsa_sha2_256f_sign,
    oxi_slh_dsa_sha2_256f_verify,
    oxi_slh_dsa_shake_128s_keygen,
    oxi_slh_dsa_shake_128s_sign,
    oxi_slh_dsa_shake_128s_verify,
    oxi_slh_dsa_shake_128f_keygen,
    oxi_slh_dsa_shake_128f_sign,
    oxi_slh_dsa_shake_128f_verify,
    oxi_slh_dsa_shake_192s_keygen,
    oxi_slh_dsa_shake_192s_sign,
    oxi_slh_dsa_shake_192s_verify,
    oxi_slh_dsa_shake_192f_keygen,
    oxi_slh_dsa_shake_192f_sign,
    oxi_slh_dsa_shake_192f_verify,
    oxi_slh_dsa_shake_256s_keygen,
    oxi_slh_dsa_shake_256s_sign,
    oxi_slh_dsa_shake_256s_verify,
    oxi_slh_dsa_shake_256f_keygen,
    oxi_slh_dsa_shake_256f_sign,
    oxi_slh_dsa_shake_256f_verify,
    oxi_lms_verify,
    oxi_lms_verify_any,
    oxi_lms_sha256_m32_h5_w1_verify,
    oxi_lms_sha256_m32_h5_w2_verify,
    oxi_lms_sha256_m32_h5_w4_verify,
    oxi_lms_sha256_m32_h5_w8_verify,
    oxi_lms_sha256_m32_h10_w1_verify,
    oxi_lms_sha256_m32_h10_w2_verify,
    oxi_lms_sha256_m32_h10_w4_verify,
    oxi_lms_sha256_m32_h10_w8_verify,
    oxi_lms_sha256_m32_h15_w1_verify,
    oxi_lms_sha256_m32_h15_w2_verify,
    oxi_lms_sha256_m32_h15_w4_verify,
    oxi_lms_sha256_m32_h15_w8_verify,
    oxi_lms_sha256_m32_h20_w1_verify,
    oxi_lms_sha256_m32_h20_w2_verify,
    oxi_lms_sha256_m32_h20_w4_verify,
    oxi_lms_sha256_m32_h20_w8_verify,
    oxi_lms_sha256_m32_h25_w1_verify,
    oxi_lms_sha256_m32_h25_w2_verify,
    oxi_lms_sha256_m32_h25_w4_verify,
    oxi_lms_sha256_m32_h25_w8_verify,
    oxi_lms_sha256_m24_h5_w1_verify,
    oxi_lms_sha256_m24_h5_w2_verify,
    oxi_lms_sha256_m24_h5_w4_verify,
    oxi_lms_sha256_m24_h5_w8_verify,
    oxi_lms_sha256_m24_h10_w1_verify,
    oxi_lms_sha256_m24_h10_w2_verify,
    oxi_lms_sha256_m24_h10_w4_verify,
    oxi_lms_sha256_m24_h10_w8_verify,
    oxi_lms_sha256_m24_h15_w1_verify,
    oxi_lms_sha256_m24_h15_w2_verify,
    oxi_lms_sha256_m24_h15_w4_verify,
    oxi_lms_sha256_m24_h15_w8_verify,
    oxi_lms_sha256_m24_h20_w1_verify,
    oxi_lms_sha256_m24_h20_w2_verify,
    oxi_lms_sha256_m24_h20_w4_verify,
    oxi_lms_sha256_m24_h20_w8_verify,
    oxi_lms_sha256_m24_h25_w1_verify,
    oxi_lms_sha256_m24_h25_w2_verify,
    oxi_lms_sha256_m24_h25_w4_verify,
    oxi_lms_sha256_m24_h25_w8_verify,
    oxi_lms_shake_m32_h5_w1_verify,
    oxi_lms_shake_m32_h5_w2_verify,
    oxi_lms_shake_m32_h5_w4_verify,
    oxi_lms_shake_m32_h5_w8_verify,
    oxi_lms_shake_m32_h10_w1_verify,
    oxi_lms_shake_m32_h10_w2_verify,
    oxi_lms_shake_m32_h10_w4_verify,
    oxi_lms_shake_m32_h10_w8_verify,
    oxi_lms_shake_m32_h15_w1_verify,
    oxi_lms_shake_m32_h15_w2_verify,
    oxi_lms_shake_m32_h15_w4_verify,
    oxi_lms_shake_m32_h15_w8_verify,
    oxi_lms_shake_m32_h20_w1_verify,
    oxi_lms_shake_m32_h20_w2_verify,
    oxi_lms_shake_m32_h20_w4_verify,
    oxi_lms_shake_m32_h20_w8_verify,
    oxi_lms_shake_m32_h25_w1_verify,
    oxi_lms_shake_m32_h25_w2_verify,
    oxi_lms_shake_m32_h25_w4_verify,
    oxi_lms_shake_m32_h25_w8_verify,
    oxi_lms_shake_m24_h5_w1_verify,
    oxi_lms_shake_m24_h5_w2_verify,
    oxi_lms_shake_m24_h5_w4_verify,
    oxi_lms_shake_m24_h5_w8_verify,
    oxi_lms_shake_m24_h10_w1_verify,
    oxi_lms_shake_m24_h10_w2_verify,
    oxi_lms_shake_m24_h10_w4_verify,
    oxi_lms_shake_m24_h10_w8_verify,
    oxi_lms_shake_m24_h15_w1_verify,
    oxi_lms_shake_m24_h15_w2_verify,
    oxi_lms_shake_m24_h15_w4_verify,
    oxi_lms_shake_m24_h15_w8_verify,
    oxi_lms_shake_m24_h20_w1_verify,
    oxi_lms_shake_m24_h20_w2_verify,
    oxi_lms_shake_m24_h20_w4_verify,
    oxi_lms_shake_m24_h20_w8_verify,
    oxi_lms_shake_m24_h25_w1_verify,
    oxi_lms_shake_m24_h25_w2_verify,
    oxi_lms_shake_m24_h25_w4_verify,
    oxi_lms_shake_m24_h25_w8_verify,
    oxi_xmss_verify,
    oxi_ecdsa_p256_private_key_new_generate,
    oxi_ecdsa_p256_private_key_free,
    oxi_ecdsa_p256_private_key_public_key,
    oxi_ecdsa_p256_private_key_sign_sha256,
    oxi_ecdsa_p384_private_key_new_generate,
    oxi_ecdsa_p384_private_key_free,
    oxi_ecdsa_p384_private_key_public_key,
    oxi_ecdsa_p384_private_key_sign_sha384,
    oxi_rsa_2048_private_key_new_generate,
    oxi_rsa_2048_private_key_free,
    oxi_rsa_2048_modulus,
    oxi_rsa_2048_public_exponent,
    oxi_rsa_2048_sign_pkcs1_v15_sha256,
    oxi_rsa_2048_sign_pss_sha256,
    oxi_rsa_2048_oaep_encrypt_sha256,
    oxi_rsa_2048_oaep_decrypt_sha256,
    oxi_rsa_3072_private_key_new_generate,
    oxi_rsa_3072_private_key_free,
    oxi_rsa_3072_modulus,
    oxi_rsa_3072_public_exponent,
    oxi_rsa_3072_sign_pkcs1_v15_sha256,
    oxi_rsa_3072_sign_pss_sha256,
    oxi_rsa_3072_oaep_encrypt_sha256,
    oxi_rsa_3072_oaep_decrypt_sha256,
    oxi_rsa_4096_private_key_new_generate,
    oxi_rsa_4096_private_key_free,
    oxi_rsa_4096_modulus,
    oxi_rsa_4096_public_exponent,
    oxi_rsa_4096_sign_pkcs1_v15_sha256,
    oxi_rsa_4096_sign_pss_sha256,
    oxi_rsa_4096_oaep_encrypt_sha256,
    oxi_rsa_4096_oaep_decrypt_sha256,
    oxi_aes256_new,
    oxi_aes256_free,
    oxi_aes256_gcm_encrypt,
    oxi_aes256_gcm_decrypt,
    oxi_aes256_cbc_encrypt,
    oxi_aes256_cbc_decrypt,
    oxi_aes256_ctr,
    oxi_aes256_ccm_encrypt,
    oxi_aes256_ccm_decrypt,
    oxi_aes256_cmac,
    oxi_aes256_kw_wrap,
    oxi_aes256_kw_unwrap,
    oxi_aes256_kwp_wrap,
    oxi_aes256_kwp_unwrap,
    oxi_hmac_drbg_sha256_new,
    oxi_hmac_drbg_sha256_free,
    oxi_hmac_drbg_sha256_instantiate,
    oxi_hmac_drbg_sha256_reseed,
    oxi_hmac_drbg_sha256_generate,
    oxi_hmac_drbg_sha384_new,
    oxi_hmac_drbg_sha384_free,
    oxi_hmac_drbg_sha384_instantiate,
    oxi_hmac_drbg_sha384_reseed,
    oxi_hmac_drbg_sha384_generate,
    oxi_hmac_drbg_sha512_new,
    oxi_hmac_drbg_sha512_free,
    oxi_hmac_drbg_sha512_instantiate,
    oxi_hmac_drbg_sha512_reseed,
    oxi_hmac_drbg_sha512_generate,
    oxi_hash_drbg_sha256_new,
    oxi_hash_drbg_sha256_free,
    oxi_hash_drbg_sha256_instantiate,
    oxi_hash_drbg_sha256_reseed,
    oxi_hash_drbg_sha256_generate,
    oxi_hash_drbg_sha384_new,
    oxi_hash_drbg_sha384_free,
    oxi_hash_drbg_sha384_instantiate,
    oxi_hash_drbg_sha384_reseed,
    oxi_hash_drbg_sha384_generate,
    oxi_hash_drbg_sha512_new,
    oxi_hash_drbg_sha512_free,
    oxi_hash_drbg_sha512_instantiate,
    oxi_hash_drbg_sha512_reseed,
    oxi_hash_drbg_sha512_generate,
    oxi_ctr_drbg_aes128_new,
    oxi_ctr_drbg_aes128_free,
    oxi_ctr_drbg_aes128_instantiate_no_df,
    oxi_ctr_drbg_aes128_instantiate_df,
    oxi_ctr_drbg_aes128_reseed_no_df,
    oxi_ctr_drbg_aes128_reseed_df,
    oxi_ctr_drbg_aes128_generate_no_df,
    oxi_ctr_drbg_aes128_generate_df,
    oxi_ctr_drbg_aes192_new,
    oxi_ctr_drbg_aes192_free,
    oxi_ctr_drbg_aes192_instantiate_no_df,
    oxi_ctr_drbg_aes192_instantiate_df,
    oxi_ctr_drbg_aes192_reseed_no_df,
    oxi_ctr_drbg_aes192_reseed_df,
    oxi_ctr_drbg_aes192_generate_no_df,
    oxi_ctr_drbg_aes192_generate_df,
    oxi_ctr_drbg_aes256_new,
    oxi_ctr_drbg_aes256_free,
    oxi_ctr_drbg_aes256_instantiate_no_df,
    oxi_ctr_drbg_aes256_instantiate_df,
    oxi_ctr_drbg_aes256_reseed_no_df,
    oxi_ctr_drbg_aes256_reseed_df,
    oxi_ctr_drbg_aes256_generate_no_df,
    oxi_ctr_drbg_aes256_generate_df,
};

impl Inventory {
    /// The address of every function in the table, in declaration order.
    pub(crate) fn addresses(&self) -> [usize; 292] {
        [
            self.lama_manifest as usize,
            self.oxi_init as usize,
            self.oxi_active_profile as usize,
            self.oxi_is_operational as usize,
            self.oxi_integrity_status as usize,
            self.oxi_integrity_key_fingerprint as usize,
            self.oxi_integrity_status_detail as usize,
            self.oxi_sha256 as usize,
            self.oxi_sha512 as usize,
            self.oxi_sha224 as usize,
            self.oxi_sha384 as usize,
            self.oxi_sha512_224 as usize,
            self.oxi_sha512_256 as usize,
            self.oxi_sha3_224 as usize,
            self.oxi_sha3_256 as usize,
            self.oxi_sha3_384 as usize,
            self.oxi_sha3_512 as usize,
            self.oxi_hmac_sha256 as usize,
            self.oxi_hmac_sha384 as usize,
            self.oxi_hmac_sha512 as usize,
            self.oxi_hmac_sha3_224 as usize,
            self.oxi_hmac_sha3_256 as usize,
            self.oxi_hmac_sha3_384 as usize,
            self.oxi_hmac_sha3_512 as usize,
            self.oxi_ecdsa_p256_derive_public_key as usize,
            self.oxi_ecdsa_p256_sign_with_k as usize,
            self.oxi_ecdsa_p256_verify as usize,
            self.oxi_ecdsa_p384_derive_public_key as usize,
            self.oxi_ecdsa_p384_sign_with_k as usize,
            self.oxi_ecdsa_p384_verify as usize,
            self.oxi_hkdf_sha256_extract as usize,
            self.oxi_hkdf_sha256_expand as usize,
            self.oxi_hkdf_sha384_extract as usize,
            self.oxi_hkdf_sha384_expand as usize,
            self.oxi_hkdf_sha512_extract as usize,
            self.oxi_hkdf_sha512_expand as usize,
            self.oxi_tls13_hkdf_expand_label_sha256 as usize,
            self.oxi_tls13_hkdf_expand_label_sha384 as usize,
            self.oxi_tls13_derive_secret_sha256 as usize,
            self.oxi_tls13_derive_secret_sha384 as usize,
            self.oxi_ed25519_keygen as usize,
            self.oxi_ed25519_sign as usize,
            self.oxi_ed25519_verify as usize,
            self.oxi_ecdh_p256_compute_shared_secret as usize,
            self.oxi_ecdh_p384_compute_shared_secret as usize,
            self.oxi_ecdh_p256_generate_keypair as usize,
            self.oxi_ecdh_p384_generate_keypair as usize,
            self.oxi_dh3072_compute_shared_secret as usize,
            self.oxi_dh3072_generate_keypair as usize,
            self.oxi_rsa_pkcs1_v15_verify_2048_sha256 as usize,
            self.oxi_rsa_pss_verify_2048_sha256 as usize,
            self.oxi_rsa_pkcs1_v15_verify_3072_sha256 as usize,
            self.oxi_rsa_pss_verify_3072_sha256 as usize,
            self.oxi_rsa_pkcs1_v15_verify_4096_sha256 as usize,
            self.oxi_rsa_pss_verify_4096_sha256 as usize,
            self.oxi_ml_dsa_87_keygen as usize,
            self.oxi_ml_dsa_87_sign as usize,
            self.oxi_ml_dsa_87_verify as usize,
            self.oxi_ml_dsa_44_keygen as usize,
            self.oxi_ml_dsa_44_sign as usize,
            self.oxi_ml_dsa_44_verify as usize,
            self.oxi_ml_dsa_65_keygen as usize,
            self.oxi_ml_dsa_65_sign as usize,
            self.oxi_ml_dsa_65_verify as usize,
            self.oxi_ml_kem_1024_keygen as usize,
            self.oxi_ml_kem_1024_encapsulate as usize,
            self.oxi_ml_kem_1024_decapsulate as usize,
            self.oxi_ml_kem_512_keygen as usize,
            self.oxi_ml_kem_512_encapsulate as usize,
            self.oxi_ml_kem_512_decapsulate as usize,
            self.oxi_ml_kem_768_keygen as usize,
            self.oxi_ml_kem_768_encapsulate as usize,
            self.oxi_ml_kem_768_decapsulate as usize,
            self.oxi_slh_dsa_sha2_256s_keygen as usize,
            self.oxi_slh_dsa_sha2_256s_sign as usize,
            self.oxi_slh_dsa_sha2_256s_verify as usize,
            self.oxi_slh_dsa_sha2_128s_keygen as usize,
            self.oxi_slh_dsa_sha2_128s_sign as usize,
            self.oxi_slh_dsa_sha2_128s_verify as usize,
            self.oxi_slh_dsa_sha2_128f_keygen as usize,
            self.oxi_slh_dsa_sha2_128f_sign as usize,
            self.oxi_slh_dsa_sha2_128f_verify as usize,
            self.oxi_slh_dsa_sha2_192s_keygen as usize,
            self.oxi_slh_dsa_sha2_192s_sign as usize,
            self.oxi_slh_dsa_sha2_192s_verify as usize,
            self.oxi_slh_dsa_sha2_192f_keygen as usize,
            self.oxi_slh_dsa_sha2_192f_sign as usize,
            self.oxi_slh_dsa_sha2_192f_verify as usize,
            self.oxi_slh_dsa_sha2_256f_keygen as usize,
            self.oxi_slh_dsa_sha2_256f_sign as usize,
            self.oxi_slh_dsa_sha2_256f_verify as usize,
            self.oxi_slh_dsa_shake_128s_keygen as usize,
            self.oxi_slh_dsa_shake_128s_sign as usize,
            self.oxi_slh_dsa_shake_128s_verify as usize,
            self.oxi_slh_dsa_shake_128f_keygen as usize,
            self.oxi_slh_dsa_shake_128f_sign as usize,
            self.oxi_slh_dsa_shake_128f_verify as usize,
            self.oxi_slh_dsa_shake_192s_keygen as usize,
            self.oxi_slh_dsa_shake_192s_sign as usize,
            self.oxi_slh_dsa_shake_192s_verify as usize,
            self.oxi_slh_dsa_shake_192f_keygen as usize,
            self.oxi_slh_dsa_shake_192f_sign as usize,
            self.oxi_slh_dsa_shake_192f_verify as usize,
            self.oxi_slh_dsa_shake_256s_keygen as usize,
            self.oxi_slh_dsa_shake_256s_sign as usize,
            self.oxi_slh_dsa_shake_256s_verify as usize,
            self.oxi_slh_dsa_shake_256f_keygen as usize,
            self.oxi_slh_dsa_shake_256f_sign as usize,
            self.oxi_slh_dsa_shake_256f_verify as usize,
            self.oxi_lms_verify as usize,
            self.oxi_lms_verify_any as usize,
            self.oxi_lms_sha256_m32_h5_w1_verify as usize,
            self.oxi_lms_sha256_m32_h5_w2_verify as usize,
            self.oxi_lms_sha256_m32_h5_w4_verify as usize,
            self.oxi_lms_sha256_m32_h5_w8_verify as usize,
            self.oxi_lms_sha256_m32_h10_w1_verify as usize,
            self.oxi_lms_sha256_m32_h10_w2_verify as usize,
            self.oxi_lms_sha256_m32_h10_w4_verify as usize,
            self.oxi_lms_sha256_m32_h10_w8_verify as usize,
            self.oxi_lms_sha256_m32_h15_w1_verify as usize,
            self.oxi_lms_sha256_m32_h15_w2_verify as usize,
            self.oxi_lms_sha256_m32_h15_w4_verify as usize,
            self.oxi_lms_sha256_m32_h15_w8_verify as usize,
            self.oxi_lms_sha256_m32_h20_w1_verify as usize,
            self.oxi_lms_sha256_m32_h20_w2_verify as usize,
            self.oxi_lms_sha256_m32_h20_w4_verify as usize,
            self.oxi_lms_sha256_m32_h20_w8_verify as usize,
            self.oxi_lms_sha256_m32_h25_w1_verify as usize,
            self.oxi_lms_sha256_m32_h25_w2_verify as usize,
            self.oxi_lms_sha256_m32_h25_w4_verify as usize,
            self.oxi_lms_sha256_m32_h25_w8_verify as usize,
            self.oxi_lms_sha256_m24_h5_w1_verify as usize,
            self.oxi_lms_sha256_m24_h5_w2_verify as usize,
            self.oxi_lms_sha256_m24_h5_w4_verify as usize,
            self.oxi_lms_sha256_m24_h5_w8_verify as usize,
            self.oxi_lms_sha256_m24_h10_w1_verify as usize,
            self.oxi_lms_sha256_m24_h10_w2_verify as usize,
            self.oxi_lms_sha256_m24_h10_w4_verify as usize,
            self.oxi_lms_sha256_m24_h10_w8_verify as usize,
            self.oxi_lms_sha256_m24_h15_w1_verify as usize,
            self.oxi_lms_sha256_m24_h15_w2_verify as usize,
            self.oxi_lms_sha256_m24_h15_w4_verify as usize,
            self.oxi_lms_sha256_m24_h15_w8_verify as usize,
            self.oxi_lms_sha256_m24_h20_w1_verify as usize,
            self.oxi_lms_sha256_m24_h20_w2_verify as usize,
            self.oxi_lms_sha256_m24_h20_w4_verify as usize,
            self.oxi_lms_sha256_m24_h20_w8_verify as usize,
            self.oxi_lms_sha256_m24_h25_w1_verify as usize,
            self.oxi_lms_sha256_m24_h25_w2_verify as usize,
            self.oxi_lms_sha256_m24_h25_w4_verify as usize,
            self.oxi_lms_sha256_m24_h25_w8_verify as usize,
            self.oxi_lms_shake_m32_h5_w1_verify as usize,
            self.oxi_lms_shake_m32_h5_w2_verify as usize,
            self.oxi_lms_shake_m32_h5_w4_verify as usize,
            self.oxi_lms_shake_m32_h5_w8_verify as usize,
            self.oxi_lms_shake_m32_h10_w1_verify as usize,
            self.oxi_lms_shake_m32_h10_w2_verify as usize,
            self.oxi_lms_shake_m32_h10_w4_verify as usize,
            self.oxi_lms_shake_m32_h10_w8_verify as usize,
            self.oxi_lms_shake_m32_h15_w1_verify as usize,
            self.oxi_lms_shake_m32_h15_w2_verify as usize,
            self.oxi_lms_shake_m32_h15_w4_verify as usize,
            self.oxi_lms_shake_m32_h15_w8_verify as usize,
            self.oxi_lms_shake_m32_h20_w1_verify as usize,
            self.oxi_lms_shake_m32_h20_w2_verify as usize,
            self.oxi_lms_shake_m32_h20_w4_verify as usize,
            self.oxi_lms_shake_m32_h20_w8_verify as usize,
            self.oxi_lms_shake_m32_h25_w1_verify as usize,
            self.oxi_lms_shake_m32_h25_w2_verify as usize,
            self.oxi_lms_shake_m32_h25_w4_verify as usize,
            self.oxi_lms_shake_m32_h25_w8_verify as usize,
            self.oxi_lms_shake_m24_h5_w1_verify as usize,
            self.oxi_lms_shake_m24_h5_w2_verify as usize,
            self.oxi_lms_shake_m24_h5_w4_verify as usize,
            self.oxi_lms_shake_m24_h5_w8_verify as usize,
            self.oxi_lms_shake_m24_h10_w1_verify as usize,
            self.oxi_lms_shake_m24_h10_w2_verify as usize,
            self.oxi_lms_shake_m24_h10_w4_verify as usize,
            self.oxi_lms_shake_m24_h10_w8_verify as usize,
            self.oxi_lms_shake_m24_h15_w1_verify as usize,
            self.oxi_lms_shake_m24_h15_w2_verify as usize,
            self.oxi_lms_shake_m24_h15_w4_verify as usize,
            self.oxi_lms_shake_m24_h15_w8_verify as usize,
            self.oxi_lms_shake_m24_h20_w1_verify as usize,
            self.oxi_lms_shake_m24_h20_w2_verify as usize,
            self.oxi_lms_shake_m24_h20_w4_verify as usize,
            self.oxi_lms_shake_m24_h20_w8_verify as usize,
            self.oxi_lms_shake_m24_h25_w1_verify as usize,
            self.oxi_lms_shake_m24_h25_w2_verify as usize,
            self.oxi_lms_shake_m24_h25_w4_verify as usize,
            self.oxi_lms_shake_m24_h25_w8_verify as usize,
            self.oxi_xmss_verify as usize,
            self.oxi_ecdsa_p256_private_key_new_generate as usize,
            self.oxi_ecdsa_p256_private_key_free as usize,
            self.oxi_ecdsa_p256_private_key_public_key as usize,
            self.oxi_ecdsa_p256_private_key_sign_sha256 as usize,
            self.oxi_ecdsa_p384_private_key_new_generate as usize,
            self.oxi_ecdsa_p384_private_key_free as usize,
            self.oxi_ecdsa_p384_private_key_public_key as usize,
            self.oxi_ecdsa_p384_private_key_sign_sha384 as usize,
            self.oxi_rsa_2048_private_key_new_generate as usize,
            self.oxi_rsa_2048_private_key_free as usize,
            self.oxi_rsa_2048_modulus as usize,
            self.oxi_rsa_2048_public_exponent as usize,
            self.oxi_rsa_2048_sign_pkcs1_v15_sha256 as usize,
            self.oxi_rsa_2048_sign_pss_sha256 as usize,
            self.oxi_rsa_2048_oaep_encrypt_sha256 as usize,
            self.oxi_rsa_2048_oaep_decrypt_sha256 as usize,
            self.oxi_rsa_3072_private_key_new_generate as usize,
            self.oxi_rsa_3072_private_key_free as usize,
            self.oxi_rsa_3072_modulus as usize,
            self.oxi_rsa_3072_public_exponent as usize,
            self.oxi_rsa_3072_sign_pkcs1_v15_sha256 as usize,
            self.oxi_rsa_3072_sign_pss_sha256 as usize,
            self.oxi_rsa_3072_oaep_encrypt_sha256 as usize,
            self.oxi_rsa_3072_oaep_decrypt_sha256 as usize,
            self.oxi_rsa_4096_private_key_new_generate as usize,
            self.oxi_rsa_4096_private_key_free as usize,
            self.oxi_rsa_4096_modulus as usize,
            self.oxi_rsa_4096_public_exponent as usize,
            self.oxi_rsa_4096_sign_pkcs1_v15_sha256 as usize,
            self.oxi_rsa_4096_sign_pss_sha256 as usize,
            self.oxi_rsa_4096_oaep_encrypt_sha256 as usize,
            self.oxi_rsa_4096_oaep_decrypt_sha256 as usize,
            self.oxi_aes256_new as usize,
            self.oxi_aes256_free as usize,
            self.oxi_aes256_gcm_encrypt as usize,
            self.oxi_aes256_gcm_decrypt as usize,
            self.oxi_aes256_cbc_encrypt as usize,
            self.oxi_aes256_cbc_decrypt as usize,
            self.oxi_aes256_ctr as usize,
            self.oxi_aes256_ccm_encrypt as usize,
            self.oxi_aes256_ccm_decrypt as usize,
            self.oxi_aes256_cmac as usize,
            self.oxi_aes256_kw_wrap as usize,
            self.oxi_aes256_kw_unwrap as usize,
            self.oxi_aes256_kwp_wrap as usize,
            self.oxi_aes256_kwp_unwrap as usize,
            self.oxi_hmac_drbg_sha256_new as usize,
            self.oxi_hmac_drbg_sha256_free as usize,
            self.oxi_hmac_drbg_sha256_instantiate as usize,
            self.oxi_hmac_drbg_sha256_reseed as usize,
            self.oxi_hmac_drbg_sha256_generate as usize,
            self.oxi_hmac_drbg_sha384_new as usize,
            self.oxi_hmac_drbg_sha384_free as usize,
            self.oxi_hmac_drbg_sha384_instantiate as usize,
            self.oxi_hmac_drbg_sha384_reseed as usize,
            self.oxi_hmac_drbg_sha384_generate as usize,
            self.oxi_hmac_drbg_sha512_new as usize,
            self.oxi_hmac_drbg_sha512_free as usize,
            self.oxi_hmac_drbg_sha512_instantiate as usize,
            self.oxi_hmac_drbg_sha512_reseed as usize,
            self.oxi_hmac_drbg_sha512_generate as usize,
            self.oxi_hash_drbg_sha256_new as usize,
            self.oxi_hash_drbg_sha256_free as usize,
            self.oxi_hash_drbg_sha256_instantiate as usize,
            self.oxi_hash_drbg_sha256_reseed as usize,
            self.oxi_hash_drbg_sha256_generate as usize,
            self.oxi_hash_drbg_sha384_new as usize,
            self.oxi_hash_drbg_sha384_free as usize,
            self.oxi_hash_drbg_sha384_instantiate as usize,
            self.oxi_hash_drbg_sha384_reseed as usize,
            self.oxi_hash_drbg_sha384_generate as usize,
            self.oxi_hash_drbg_sha512_new as usize,
            self.oxi_hash_drbg_sha512_free as usize,
            self.oxi_hash_drbg_sha512_instantiate as usize,
            self.oxi_hash_drbg_sha512_reseed as usize,
            self.oxi_hash_drbg_sha512_generate as usize,
            self.oxi_ctr_drbg_aes128_new as usize,
            self.oxi_ctr_drbg_aes128_free as usize,
            self.oxi_ctr_drbg_aes128_instantiate_no_df as usize,
            self.oxi_ctr_drbg_aes128_instantiate_df as usize,
            self.oxi_ctr_drbg_aes128_reseed_no_df as usize,
            self.oxi_ctr_drbg_aes128_reseed_df as usize,
            self.oxi_ctr_drbg_aes128_generate_no_df as usize,
            self.oxi_ctr_drbg_aes128_generate_df as usize,
            self.oxi_ctr_drbg_aes192_new as usize,
            self.oxi_ctr_drbg_aes192_free as usize,
            self.oxi_ctr_drbg_aes192_instantiate_no_df as usize,
            self.oxi_ctr_drbg_aes192_instantiate_df as usize,
            self.oxi_ctr_drbg_aes192_reseed_no_df as usize,
            self.oxi_ctr_drbg_aes192_reseed_df as usize,
            self.oxi_ctr_drbg_aes192_generate_no_df as usize,
            self.oxi_ctr_drbg_aes192_generate_df as usize,
            self.oxi_ctr_drbg_aes256_new as usize,
            self.oxi_ctr_drbg_aes256_free as usize,
            self.oxi_ctr_drbg_aes256_instantiate_no_df as usize,
            self.oxi_ctr_drbg_aes256_instantiate_df as usize,
            self.oxi_ctr_drbg_aes256_reseed_no_df as usize,
            self.oxi_ctr_drbg_aes256_reseed_df as usize,
            self.oxi_ctr_drbg_aes256_generate_no_df as usize,
            self.oxi_ctr_drbg_aes256_generate_df as usize,
        ]
    }
}
