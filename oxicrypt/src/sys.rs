//! Declarations of every function the C ABI exports, as `include/oxicrypt.h`
//! in `oxicrypt-ffi` declares them.
//!
//! No generator runs at build time. The header-pinning test compares the
//! name, parameter types and return type of every declaration here with the
//! header, in both directions. Header types map as: `uint8_t` to `u8`,
//! `uintptr_t` to `usize`, `uint64_t` to `u64`, `int` to `c_int`, `char` to
//! `c_char`, a pointer to `const T` to `*const T`, any other pointer to
//! `*mut T`, and each opaque handle `typedef` to a zero-sized `#[repr(C)]`
//! struct of the same name.
//!
//! Every `unsafe` block in the crate cites, in its `// SAFETY:` comment, the
//! obligations it discharges, numbered U1 to U10 as in the table *Every
//! `unsafe` obligation and its discharge* of `docs/design/rust-bindings.md`
//! in the repository.
//!
//! Most declarations are not called by the safe layer yet. They are declared
//! so that the inventory is complete and checked: the `inventory` test binary
//! holds one function pointer per declaration (`src/sys_inventory.rs`), so
//! loading it requires the library to export every one.

#![allow(dead_code)]

use core::ffi::{c_char, c_int};
use core::marker::{PhantomData, PhantomPinned};

macro_rules! opaque {
    ($($name:ident),* $(,)?) => {$(
        /// An opaque handle type of the C ABI; only ever used behind a pointer.
        #[repr(C)]
        pub(crate) struct $name {
            _private: [u8; 0],
            _marker: PhantomData<(*mut u8, PhantomPinned)>,
        }
    )*};
}

opaque!(
    OxiAes256Key,
    OxiCtrDrbgAes128,
    OxiCtrDrbgAes192,
    OxiCtrDrbgAes256,
    OxiEcdsaP256PrivateKey,
    OxiEcdsaP384PrivateKey,
    OxiHashDrbgSha256,
    OxiHashDrbgSha384,
    OxiHashDrbgSha512,
    OxiHmacDrbgSha256,
    OxiHmacDrbgSha384,
    OxiHmacDrbgSha512,
    OxiRsaPrivateKey2048,
    OxiRsaPrivateKey3072,
    OxiRsaPrivateKey4096,
);

unsafe extern "C" {
    pub(crate) fn lama_manifest() -> *const c_char;
    pub(crate) fn oxi_init(profile: c_int) -> c_int;
    pub(crate) fn oxi_active_profile() -> c_int;
    pub(crate) fn oxi_is_operational() -> c_int;
    pub(crate) fn oxi_integrity_status() -> c_int;
    pub(crate) fn oxi_integrity_key_fingerprint(out: *mut u8, out_len: usize) -> c_int;
    pub(crate) fn oxi_integrity_status_detail(
        out: *mut u8,
        out_len: usize,
        written: *mut usize,
    ) -> c_int;
    pub(crate) fn oxi_sha256(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha512(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha224(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha384(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha512_224(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha512_256(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha3_224(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha3_256(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha3_384(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_sha3_512(data_ptr: *const u8, data_len: usize, out: *mut u8) -> c_int;
    pub(crate) fn oxi_hmac_sha256(
        key_ptr: *const u8,
        key_len: usize,
        data_ptr: *const u8,
        data_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hmac_sha384(
        key_ptr: *const u8,
        key_len: usize,
        data_ptr: *const u8,
        data_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hmac_sha512(
        key_ptr: *const u8,
        key_len: usize,
        data_ptr: *const u8,
        data_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hmac_sha3_224(
        key_ptr: *const u8,
        key_len: usize,
        data_ptr: *const u8,
        data_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hmac_sha3_256(
        key_ptr: *const u8,
        key_len: usize,
        data_ptr: *const u8,
        data_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hmac_sha3_384(
        key_ptr: *const u8,
        key_len: usize,
        data_ptr: *const u8,
        data_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hmac_sha3_512(
        key_ptr: *const u8,
        key_len: usize,
        data_ptr: *const u8,
        data_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p256_derive_public_key(
        d_ptr: *const u8,
        public_key_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p256_sign_with_k(
        d_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        k_ptr: *const u8,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p256_verify(
        public_key_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p384_derive_public_key(
        d_ptr: *const u8,
        public_key_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p384_sign_with_k(
        d_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        k_ptr: *const u8,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p384_verify(
        public_key_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_hkdf_sha256_extract(
        salt_ptr: *const u8,
        salt_len: usize,
        ikm_ptr: *const u8,
        ikm_len: usize,
        prk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hkdf_sha256_expand(
        prk_ptr: *const u8,
        info_ptr: *const u8,
        info_len: usize,
        okm_out: *mut u8,
        okm_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hkdf_sha384_extract(
        salt_ptr: *const u8,
        salt_len: usize,
        ikm_ptr: *const u8,
        ikm_len: usize,
        prk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hkdf_sha384_expand(
        prk_ptr: *const u8,
        info_ptr: *const u8,
        info_len: usize,
        okm_out: *mut u8,
        okm_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hkdf_sha512_extract(
        salt_ptr: *const u8,
        salt_len: usize,
        ikm_ptr: *const u8,
        ikm_len: usize,
        prk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_hkdf_sha512_expand(
        prk_ptr: *const u8,
        info_ptr: *const u8,
        info_len: usize,
        okm_out: *mut u8,
        okm_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_tls13_hkdf_expand_label_sha256(
        secret_ptr: *const u8,
        secret_len: usize,
        label_ptr: *const u8,
        label_len: usize,
        context_ptr: *const u8,
        context_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_tls13_hkdf_expand_label_sha384(
        secret_ptr: *const u8,
        secret_len: usize,
        label_ptr: *const u8,
        label_len: usize,
        context_ptr: *const u8,
        context_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_tls13_derive_secret_sha256(
        secret_ptr: *const u8,
        secret_len: usize,
        label_ptr: *const u8,
        label_len: usize,
        transcript_hash_ptr: *const u8,
        transcript_hash_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_tls13_derive_secret_sha384(
        secret_ptr: *const u8,
        secret_len: usize,
        label_ptr: *const u8,
        label_len: usize,
        transcript_hash_ptr: *const u8,
        transcript_hash_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ed25519_keygen(seed_ptr: *const u8, public_key_out: *mut u8) -> c_int;
    pub(crate) fn oxi_ed25519_sign(
        seed_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ed25519_verify(
        public_key_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdh_p256_compute_shared_secret(
        d_ptr: *const u8,
        peer_public_key_ptr: *const u8,
        shared_secret_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdh_p384_compute_shared_secret(
        d_ptr: *const u8,
        peer_public_key_ptr: *const u8,
        shared_secret_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdh_p256_generate_keypair(
        drbg: *mut OxiHmacDrbgSha256,
        private_out: *mut u8,
        public_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdh_p384_generate_keypair(
        drbg: *mut OxiHmacDrbgSha256,
        private_out: *mut u8,
        public_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_dh3072_compute_shared_secret(
        x_ptr: *const u8,
        peer_public_key_ptr: *const u8,
        shared_secret_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_dh3072_generate_keypair(
        drbg: *mut OxiHmacDrbgSha256,
        private_out: *mut u8,
        public_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_pkcs1_v15_verify_2048_sha256(
        n_ptr: *const u8,
        e: u64,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_pss_verify_2048_sha256(
        n_ptr: *const u8,
        e: u64,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_pkcs1_v15_verify_3072_sha256(
        n_ptr: *const u8,
        e: u64,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_pss_verify_3072_sha256(
        n_ptr: *const u8,
        e: u64,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_pkcs1_v15_verify_4096_sha256(
        n_ptr: *const u8,
        e: u64,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_pss_verify_4096_sha256(
        n_ptr: *const u8,
        e: u64,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_87_keygen(
        seed_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_87_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_87_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_44_keygen(
        seed_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_44_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_44_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_65_keygen(
        seed_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_65_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_dsa_65_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_1024_keygen(
        d_ptr: *const u8,
        z_ptr: *const u8,
        ek_out: *mut u8,
        dk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_1024_encapsulate(
        ek_ptr: *const u8,
        m_ptr: *const u8,
        ss_out: *mut u8,
        ct_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_1024_decapsulate(
        dk_ptr: *const u8,
        ct_ptr: *const u8,
        ss_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_512_keygen(
        d_ptr: *const u8,
        z_ptr: *const u8,
        ek_out: *mut u8,
        dk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_512_encapsulate(
        ek_ptr: *const u8,
        m_ptr: *const u8,
        ss_out: *mut u8,
        ct_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_512_decapsulate(
        dk_ptr: *const u8,
        ct_ptr: *const u8,
        ss_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_768_keygen(
        d_ptr: *const u8,
        z_ptr: *const u8,
        ek_out: *mut u8,
        dk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_768_encapsulate(
        ek_ptr: *const u8,
        m_ptr: *const u8,
        ss_out: *mut u8,
        ct_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ml_kem_768_decapsulate(
        dk_ptr: *const u8,
        ct_ptr: *const u8,
        ss_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_256s_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_256s_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_256s_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_128s_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_128s_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_128s_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_128f_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_128f_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_128f_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_192s_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_192s_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_192s_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_192f_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_192f_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_192f_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_256f_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_256f_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_sha2_256f_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_128s_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_128s_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_128s_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_128f_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_128f_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_128f_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_192s_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_192s_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_192s_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_192f_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_192f_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_192f_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_256s_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_256s_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_256s_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_256f_keygen(
        xi_ptr: *const u8,
        pk_out: *mut u8,
        sk_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_256f_sign(
        sk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_slh_dsa_shake_256f_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        ctx_ptr: *const u8,
        ctx_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_verify_any(
        pk_ptr: *const u8,
        pk_len: usize,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
        sig_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h5_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h5_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h5_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h5_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h10_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h10_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h10_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h10_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h15_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h15_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h15_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h15_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h20_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h20_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h20_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h20_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h25_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h25_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h25_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m32_h25_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h5_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h5_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h5_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h5_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h10_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h10_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h10_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h10_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h15_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h15_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h15_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h15_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h20_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h20_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h20_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h20_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h25_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h25_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h25_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_sha256_m24_h25_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h5_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h5_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h5_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h5_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h10_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h10_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h10_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h10_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h15_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h15_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h15_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h15_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h20_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h20_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h20_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h20_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h25_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h25_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h25_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m32_h25_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h5_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h5_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h5_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h5_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h10_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h10_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h10_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h10_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h15_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h15_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h15_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h15_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h20_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h20_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h20_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h20_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h25_w1_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h25_w2_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h25_w4_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_lms_shake_m24_h25_w8_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_xmss_verify(
        pk_ptr: *const u8,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_ptr: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p256_private_key_new_generate(
        drbg: *mut OxiHmacDrbgSha256,
        out_key: *mut *mut OxiEcdsaP256PrivateKey,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p256_private_key_free(key: *mut OxiEcdsaP256PrivateKey);
    pub(crate) fn oxi_ecdsa_p256_private_key_public_key(
        key: *const OxiEcdsaP256PrivateKey,
        public_key_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p256_private_key_sign_sha256(
        key: *const OxiEcdsaP256PrivateKey,
        drbg: *mut OxiHmacDrbgSha256,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p384_private_key_new_generate(
        drbg: *mut OxiHmacDrbgSha256,
        out_key: *mut *mut OxiEcdsaP384PrivateKey,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p384_private_key_free(key: *mut OxiEcdsaP384PrivateKey);
    pub(crate) fn oxi_ecdsa_p384_private_key_public_key(
        key: *const OxiEcdsaP384PrivateKey,
        public_key_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_ecdsa_p384_private_key_sign_sha384(
        key: *const OxiEcdsaP384PrivateKey,
        drbg: *mut OxiHmacDrbgSha256,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_2048_private_key_new_generate(
        drbg: *mut OxiHmacDrbgSha256,
        e: u64,
        out_key: *mut *mut OxiRsaPrivateKey2048,
    ) -> c_int;
    pub(crate) fn oxi_rsa_2048_private_key_free(key: *mut OxiRsaPrivateKey2048);
    pub(crate) fn oxi_rsa_2048_modulus(
        key: *const OxiRsaPrivateKey2048,
        modulus_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_2048_public_exponent(
        key: *const OxiRsaPrivateKey2048,
        e_out: *mut u64,
    ) -> c_int;
    pub(crate) fn oxi_rsa_2048_sign_pkcs1_v15_sha256(
        key: *const OxiRsaPrivateKey2048,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_2048_sign_pss_sha256(
        key: *const OxiRsaPrivateKey2048,
        drbg: *mut OxiHmacDrbgSha256,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_2048_oaep_encrypt_sha256(
        drbg: *mut OxiHmacDrbgSha256,
        n_ptr: *const u8,
        e: u64,
        label_ptr: *const u8,
        label_len: usize,
        msg_ptr: *const u8,
        msg_len: usize,
        ct_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_2048_oaep_decrypt_sha256(
        key: *const OxiRsaPrivateKey2048,
        label_ptr: *const u8,
        label_len: usize,
        ct_ptr: *const u8,
        out_ptr: *mut u8,
        out_max_len: usize,
        out_actual_len: *mut usize,
    ) -> c_int;
    pub(crate) fn oxi_rsa_3072_private_key_new_generate(
        drbg: *mut OxiHmacDrbgSha256,
        e: u64,
        out_key: *mut *mut OxiRsaPrivateKey3072,
    ) -> c_int;
    pub(crate) fn oxi_rsa_3072_private_key_free(key: *mut OxiRsaPrivateKey3072);
    pub(crate) fn oxi_rsa_3072_modulus(
        key: *const OxiRsaPrivateKey3072,
        modulus_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_3072_public_exponent(
        key: *const OxiRsaPrivateKey3072,
        e_out: *mut u64,
    ) -> c_int;
    pub(crate) fn oxi_rsa_3072_sign_pkcs1_v15_sha256(
        key: *const OxiRsaPrivateKey3072,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_3072_sign_pss_sha256(
        key: *const OxiRsaPrivateKey3072,
        drbg: *mut OxiHmacDrbgSha256,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_3072_oaep_encrypt_sha256(
        drbg: *mut OxiHmacDrbgSha256,
        n_ptr: *const u8,
        e: u64,
        label_ptr: *const u8,
        label_len: usize,
        msg_ptr: *const u8,
        msg_len: usize,
        ct_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_3072_oaep_decrypt_sha256(
        key: *const OxiRsaPrivateKey3072,
        label_ptr: *const u8,
        label_len: usize,
        ct_ptr: *const u8,
        out_ptr: *mut u8,
        out_max_len: usize,
        out_actual_len: *mut usize,
    ) -> c_int;
    pub(crate) fn oxi_rsa_4096_private_key_new_generate(
        drbg: *mut OxiHmacDrbgSha256,
        e: u64,
        out_key: *mut *mut OxiRsaPrivateKey4096,
    ) -> c_int;
    pub(crate) fn oxi_rsa_4096_private_key_free(key: *mut OxiRsaPrivateKey4096);
    pub(crate) fn oxi_rsa_4096_modulus(
        key: *const OxiRsaPrivateKey4096,
        modulus_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_4096_public_exponent(
        key: *const OxiRsaPrivateKey4096,
        e_out: *mut u64,
    ) -> c_int;
    pub(crate) fn oxi_rsa_4096_sign_pkcs1_v15_sha256(
        key: *const OxiRsaPrivateKey4096,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_4096_sign_pss_sha256(
        key: *const OxiRsaPrivateKey4096,
        drbg: *mut OxiHmacDrbgSha256,
        msg_ptr: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_4096_oaep_encrypt_sha256(
        drbg: *mut OxiHmacDrbgSha256,
        n_ptr: *const u8,
        e: u64,
        label_ptr: *const u8,
        label_len: usize,
        msg_ptr: *const u8,
        msg_len: usize,
        ct_out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_rsa_4096_oaep_decrypt_sha256(
        key: *const OxiRsaPrivateKey4096,
        label_ptr: *const u8,
        label_len: usize,
        ct_ptr: *const u8,
        out_ptr: *mut u8,
        out_max_len: usize,
        out_actual_len: *mut usize,
    ) -> c_int;
    pub(crate) fn oxi_aes256_new(out_handle: *mut *mut OxiAes256Key, key: *const u8) -> c_int;
    pub(crate) fn oxi_aes256_free(handle: *mut OxiAes256Key);
    pub(crate) fn oxi_aes256_gcm_encrypt(
        key: *const OxiAes256Key,
        iv: *const u8,
        aad: *const u8,
        aad_len: usize,
        plaintext: *const u8,
        pt_len: usize,
        ciphertext: *mut u8,
        tag: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_gcm_decrypt(
        key: *const OxiAes256Key,
        iv: *const u8,
        aad: *const u8,
        aad_len: usize,
        ciphertext: *const u8,
        ct_len: usize,
        plaintext: *mut u8,
        tag: *const u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_cbc_encrypt(
        key: *const OxiAes256Key,
        iv: *const u8,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_cbc_decrypt(
        key: *const OxiAes256Key,
        iv: *const u8,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_ctr(
        key: *const OxiAes256Key,
        icb: *const u8,
        input: *const u8,
        len: usize,
        output: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_ccm_encrypt(
        key: *const OxiAes256Key,
        nonce: *const u8,
        nonce_len: usize,
        aad: *const u8,
        aad_len: usize,
        plaintext: *const u8,
        pt_len: usize,
        tlen: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_ccm_decrypt(
        key: *const OxiAes256Key,
        nonce: *const u8,
        nonce_len: usize,
        aad: *const u8,
        aad_len: usize,
        ciphertext: *const u8,
        ct_len: usize,
        tlen: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_cmac(
        key: *const OxiAes256Key,
        msg: *const u8,
        msg_len: usize,
        tag: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_kw_wrap(
        key: *const OxiAes256Key,
        plaintext: *const u8,
        pt_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_kw_unwrap(
        key: *const OxiAes256Key,
        ciphertext: *const u8,
        ct_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_kwp_wrap(
        key: *const OxiAes256Key,
        plaintext: *const u8,
        pt_len: usize,
        out: *mut u8,
    ) -> c_int;
    pub(crate) fn oxi_aes256_kwp_unwrap(
        key: *const OxiAes256Key,
        ciphertext: *const u8,
        ct_len: usize,
        out_scratch: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha256_new(out_handle: *mut *mut OxiHmacDrbgSha256) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha256_free(handle: *mut OxiHmacDrbgSha256);
    pub(crate) fn oxi_hmac_drbg_sha256_instantiate(
        handle: *mut OxiHmacDrbgSha256,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha256_reseed(
        handle: *mut OxiHmacDrbgSha256,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha256_generate(
        handle: *mut OxiHmacDrbgSha256,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha384_new(out_handle: *mut *mut OxiHmacDrbgSha384) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha384_free(handle: *mut OxiHmacDrbgSha384);
    pub(crate) fn oxi_hmac_drbg_sha384_instantiate(
        handle: *mut OxiHmacDrbgSha384,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha384_reseed(
        handle: *mut OxiHmacDrbgSha384,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha384_generate(
        handle: *mut OxiHmacDrbgSha384,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha512_new(out_handle: *mut *mut OxiHmacDrbgSha512) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha512_free(handle: *mut OxiHmacDrbgSha512);
    pub(crate) fn oxi_hmac_drbg_sha512_instantiate(
        handle: *mut OxiHmacDrbgSha512,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha512_reseed(
        handle: *mut OxiHmacDrbgSha512,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hmac_drbg_sha512_generate(
        handle: *mut OxiHmacDrbgSha512,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha256_new(out_handle: *mut *mut OxiHashDrbgSha256) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha256_free(handle: *mut OxiHashDrbgSha256);
    pub(crate) fn oxi_hash_drbg_sha256_instantiate(
        handle: *mut OxiHashDrbgSha256,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha256_reseed(
        handle: *mut OxiHashDrbgSha256,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha256_generate(
        handle: *mut OxiHashDrbgSha256,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha384_new(out_handle: *mut *mut OxiHashDrbgSha384) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha384_free(handle: *mut OxiHashDrbgSha384);
    pub(crate) fn oxi_hash_drbg_sha384_instantiate(
        handle: *mut OxiHashDrbgSha384,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha384_reseed(
        handle: *mut OxiHashDrbgSha384,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha384_generate(
        handle: *mut OxiHashDrbgSha384,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha512_new(out_handle: *mut *mut OxiHashDrbgSha512) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha512_free(handle: *mut OxiHashDrbgSha512);
    pub(crate) fn oxi_hash_drbg_sha512_instantiate(
        handle: *mut OxiHashDrbgSha512,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha512_reseed(
        handle: *mut OxiHashDrbgSha512,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_hash_drbg_sha512_generate(
        handle: *mut OxiHashDrbgSha512,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes128_new(out_handle: *mut *mut OxiCtrDrbgAes128) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes128_free(handle: *mut OxiCtrDrbgAes128);
    pub(crate) fn oxi_ctr_drbg_aes128_instantiate_no_df(
        handle: *mut OxiCtrDrbgAes128,
        seed_material: *const u8,
        seed_material_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes128_instantiate_df(
        handle: *mut OxiCtrDrbgAes128,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes128_reseed_no_df(
        handle: *mut OxiCtrDrbgAes128,
        seed_material: *const u8,
        seed_material_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes128_reseed_df(
        handle: *mut OxiCtrDrbgAes128,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes128_generate_no_df(
        handle: *mut OxiCtrDrbgAes128,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes128_generate_df(
        handle: *mut OxiCtrDrbgAes128,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes192_new(out_handle: *mut *mut OxiCtrDrbgAes192) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes192_free(handle: *mut OxiCtrDrbgAes192);
    pub(crate) fn oxi_ctr_drbg_aes192_instantiate_no_df(
        handle: *mut OxiCtrDrbgAes192,
        seed_material: *const u8,
        seed_material_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes192_instantiate_df(
        handle: *mut OxiCtrDrbgAes192,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes192_reseed_no_df(
        handle: *mut OxiCtrDrbgAes192,
        seed_material: *const u8,
        seed_material_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes192_reseed_df(
        handle: *mut OxiCtrDrbgAes192,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes192_generate_no_df(
        handle: *mut OxiCtrDrbgAes192,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes192_generate_df(
        handle: *mut OxiCtrDrbgAes192,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes256_new(out_handle: *mut *mut OxiCtrDrbgAes256) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes256_free(handle: *mut OxiCtrDrbgAes256);
    pub(crate) fn oxi_ctr_drbg_aes256_instantiate_no_df(
        handle: *mut OxiCtrDrbgAes256,
        seed_material: *const u8,
        seed_material_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes256_instantiate_df(
        handle: *mut OxiCtrDrbgAes256,
        entropy: *const u8,
        entropy_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        personalization: *const u8,
        personalization_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes256_reseed_no_df(
        handle: *mut OxiCtrDrbgAes256,
        seed_material: *const u8,
        seed_material_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes256_reseed_df(
        handle: *mut OxiCtrDrbgAes256,
        entropy: *const u8,
        entropy_len: usize,
        additional_input: *const u8,
        additional_input_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes256_generate_no_df(
        handle: *mut OxiCtrDrbgAes256,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    pub(crate) fn oxi_ctr_drbg_aes256_generate_df(
        handle: *mut OxiCtrDrbgAes256,
        additional_input: *const u8,
        additional_input_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
}
