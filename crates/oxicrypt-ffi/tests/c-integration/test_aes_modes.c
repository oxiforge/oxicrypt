/* AES CBC, CTR, CCM, CMAC, KW and KWP through the per-mode key handles.
 *
 * Vectors:
 *   - CBC-AES-256:  NIST SP 800-38A Appendix F.2.5
 *   - CTR-AES-256:  NIST SP 800-38A Appendix F.5.5
 *   - CCM-AES-256:  NIST CAVP CCMVS, vendor/nist/cavp-ccm/VPT256.rsp,
 *                   [Plen = 16], Count = 160 (16-byte tag, 13-byte nonce,
 *                   32-byte AAD, 16-byte plaintext)
 *   - CMAC-AES-256: Examples 1, 2 and 4 (Mlen 0, 128 and 512 bits) of NIST's
 *                   CMAC-AES256 worked examples, the Appendix D set that
 *                   SP 800-38B's 2016 update moved to the NIST examples page;
 *                   Example 3 is the 320-bit message of the revised Appendix
 *                   D.3 (the message lengths RFC 4493 uses)
 *   - KW-AES-256:   RFC 3394 §4.3 (128-bit key data) and §4.6 (256-bit)
 *   - KWP-AES-256:  round trip only; the RFC 5649 examples are AES-192
 *
 * A modified tag, MAC or integrity check value returns
 * TagMismatch = 22 (SP 800-38C §6.2, SP 800-38B §6.3, SP 800-38F §6.2
 * and §6.3).
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "test_aes_modes, %s: rc=%d, expected %d\n", check, rc, want);
        failures++;
    }
}

static void expect_bytes(const char *check, const uint8_t *got, const uint8_t *want, size_t n) {
    if (memcmp(got, want, n) != 0) {
        fprintf(stderr, "test_aes_modes, %s: bytes differ\n", check);
        failures++;
    }
}

/* SP 800-38A Appendix F plaintext, also the SP 800-38B Appendix D message. */
static const uint8_t MSG64[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/* The AES-256 key of the SP 800-38A F tables and SP 800-38B D.3. */
static const uint8_t KEY256_SP38[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

static const uint8_t CBC_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t CBC_EXPECTED_CT[64] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
    0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
    0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
    0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
};

static void test_cbc(void) {
    OxiAesCbcKey *key = NULL;
    expect("cbc key", oxi_aes_cbc_key_new(KEY256_SP38, sizeof(KEY256_SP38), &key), 0);
    uint8_t ct[64], back[64];
    expect("cbc encrypt", oxi_aes_cbc_encrypt(key, CBC_IV, MSG64, sizeof(MSG64), ct), 0);
    expect_bytes("cbc ciphertext, SP 800-38A F.2.5", ct, CBC_EXPECTED_CT, sizeof(ct));
    expect("cbc decrypt",
           oxi_aes_cbc_decrypt(key, CBC_IV, CBC_EXPECTED_CT, sizeof(CBC_EXPECTED_CT), back), 0);
    expect_bytes("cbc plaintext, SP 800-38A F.2.6", back, MSG64, sizeof(back));
    oxi_aes_cbc_key_free(key);
}

static const uint8_t CTR_ICB[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const uint8_t CTR_EXPECTED_CT[64] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
    0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
    0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
    0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
    0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
    0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
    0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
    0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
};

/* CTR encryption and decryption are the same operation (SP 800-38A §6.5). */
static void test_ctr(void) {
    OxiAesCtrKey *key = NULL;
    expect("ctr key", oxi_aes_ctr_key_new(KEY256_SP38, sizeof(KEY256_SP38), &key), 0);
    uint8_t ct[64], back[64];
    expect("ctr encrypt", oxi_aes_ctr(key, CTR_ICB, MSG64, sizeof(MSG64), ct), 0);
    expect_bytes("ctr ciphertext, SP 800-38A F.5.5", ct, CTR_EXPECTED_CT, sizeof(ct));
    expect("ctr decrypt", oxi_aes_ctr(key, CTR_ICB, CTR_EXPECTED_CT, sizeof(CTR_EXPECTED_CT), back),
           0);
    expect_bytes("ctr plaintext, SP 800-38A F.5.6", back, MSG64, sizeof(back));
    oxi_aes_ctr_key_free(key);
}

static const uint8_t CCM_KEY[32] = {
    0xee, 0x8c, 0xe1, 0x87, 0x16, 0x97, 0x79, 0xd1,
    0x3e, 0x44, 0x3d, 0x64, 0x28, 0xe3, 0x8b, 0x38,
    0xb5, 0x5d, 0xfb, 0x90, 0xf0, 0x22, 0x8a, 0x8a,
    0x4e, 0x62, 0xf8, 0xf5, 0x35, 0x80, 0x6e, 0x62,
};
static const uint8_t CCM_NONCE[13] = {
    0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39, 0x1c,
    0x98, 0xe6, 0x26, 0x9c, 0x8a,
};
static const uint8_t CCM_AAD[32] = {
    0x71, 0x8d, 0x13, 0xe4, 0x75, 0x22, 0xac, 0x4c,
    0xdf, 0x3f, 0x82, 0x80, 0x63, 0x98, 0x0b, 0x6d,
    0x45, 0x2f, 0xcd, 0xcd, 0x6e, 0x1a, 0x19, 0x04,
    0xbf, 0x87, 0xf5, 0x48, 0xa5, 0xfd, 0x5a, 0x05,
};
static const uint8_t CCM_PT[16] = {
    0xd1, 0x5f, 0x98, 0xf2, 0xc6, 0xd6, 0x70, 0xf5,
    0x5c, 0x78, 0xa0, 0x66, 0x48, 0x33, 0x2b, 0xc9,
};
static const uint8_t CCM_EXPECTED_PACKED[32] = { /* C || T */
    0xcc, 0x17, 0xbf, 0x87, 0x94, 0xc8, 0x43, 0x45,
    0x7d, 0x89, 0x93, 0x91, 0x89, 0x8e, 0xd2, 0x2a,
    0x6f, 0x9d, 0x28, 0xfc, 0xb6, 0x42, 0x34, 0xe1,
    0xcd, 0x79, 0x3c, 0x41, 0x44, 0xf1, 0xda, 0x50,
};

static void test_ccm(void) {
    OxiAesCcmKey *key = NULL;
    expect("ccm key", oxi_aes_ccm_key_new(CCM_KEY, sizeof(CCM_KEY), 16, &key), 0);
    uint8_t ct[16], tag[16], back[16];
    expect("ccm seal",
           oxi_aes_ccm_seal(key, CCM_NONCE, sizeof(CCM_NONCE), CCM_AAD, sizeof(CCM_AAD), CCM_PT,
                            sizeof(CCM_PT), ct, tag),
           0);
    expect_bytes("ccm ciphertext", ct, CCM_EXPECTED_PACKED, 16);
    expect_bytes("ccm tag", tag, CCM_EXPECTED_PACKED + 16, 16);
    expect("ccm open",
           oxi_aes_ccm_open(key, CCM_NONCE, sizeof(CCM_NONCE), CCM_AAD, sizeof(CCM_AAD),
                            CCM_EXPECTED_PACKED, 16, CCM_EXPECTED_PACKED + 16, back),
           0);
    expect_bytes("ccm plaintext", back, CCM_PT, sizeof(back));

    uint8_t bad_tag[16];
    memcpy(bad_tag, CCM_EXPECTED_PACKED + 16, sizeof(bad_tag));
    bad_tag[0] ^= 0x01;
    expect("ccm open under a flipped tag",
           oxi_aes_ccm_open(key, CCM_NONCE, sizeof(CCM_NONCE), CCM_AAD, sizeof(CCM_AAD),
                            CCM_EXPECTED_PACKED, 16, bad_tag, back),
           OXI_RESULT_TAG_MISMATCH);
    oxi_aes_ccm_key_free(key);
}

static const uint8_t CMAC_EX1_TAG[16] = { /* Mlen = 0 */
    0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
    0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83,
};
static const uint8_t CMAC_EX2_TAG[16] = { /* Mlen = 128 */
    0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
    0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c,
};
static const uint8_t CMAC_EX3_TAG[16] = { /* Mlen = 320 */
    0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
    0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6,
};
static const uint8_t CMAC_EX4_TAG[16] = { /* Mlen = 512 */
    0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
    0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10,
};

static void test_cmac(void) {
    OxiAesCmacKey *key = NULL;
    expect("cmac key", oxi_aes_cmac_key_new(KEY256_SP38, sizeof(KEY256_SP38), 16, &key), 0);
    uint8_t mac[16];

    /* Example 1, the empty message: subkey K2 over the padded block. */
    expect("cmac Example 1", oxi_aes_cmac(key, NULL, 0, mac), 0);
    expect_bytes("cmac Example 1 MAC", mac, CMAC_EX1_TAG, sizeof(mac));
    expect("cmac_verify Example 1", oxi_aes_cmac_verify(key, NULL, 0, CMAC_EX1_TAG), 0);

    /* Example 2, a one-block message: subkey K1. */
    expect("cmac Example 2", oxi_aes_cmac(key, MSG64, 16, mac), 0);
    expect_bytes("cmac Example 2 MAC", mac, CMAC_EX2_TAG, sizeof(mac));
    expect("cmac_verify Example 2", oxi_aes_cmac_verify(key, MSG64, 16, CMAC_EX2_TAG), 0);

    /* Example 3, a partial last block: subkey K2. */
    expect("cmac Example 3", oxi_aes_cmac(key, MSG64, 40, mac), 0);
    expect_bytes("cmac Example 3 MAC", mac, CMAC_EX3_TAG, sizeof(mac));
    expect("cmac_verify Example 3", oxi_aes_cmac_verify(key, MSG64, 40, CMAC_EX3_TAG), 0);

    /* Example 4, four full blocks: subkey K1. */
    expect("cmac Example 4", oxi_aes_cmac(key, MSG64, 64, mac), 0);
    expect_bytes("cmac Example 4 MAC", mac, CMAC_EX4_TAG, sizeof(mac));
    expect("cmac_verify Example 4", oxi_aes_cmac_verify(key, MSG64, 64, CMAC_EX4_TAG), 0);

    uint8_t bad[16];
    memcpy(bad, CMAC_EX3_TAG, sizeof(bad));
    bad[15] ^= 0x01;
    expect("cmac_verify under a flipped MAC", oxi_aes_cmac_verify(key, MSG64, 40, bad),
           OXI_RESULT_TAG_MISMATCH);
    oxi_aes_cmac_key_free(key);
}

static const uint8_t KW_KEK[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static const uint8_t KW_PT_128[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
};
static const uint8_t KW_CT_43[24] = { /* §4.3 expected ciphertext */
    0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
    0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
    0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7,
};
static const uint8_t KW_PT_256[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};
static const uint8_t KW_CT_46[40] = { /* §4.6 expected ciphertext */
    0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
    0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
    0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
    0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
    0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
};

static void test_kw(void) {
    OxiAesKwKey *key = NULL;
    expect("kw key", oxi_aes_kw_key_new(KW_KEK, sizeof(KW_KEK), &key), 0);
    uint8_t ct24[24], back16[16], ct40[40], back32[32];

    expect("kw wrap §4.3", oxi_aes_kw_wrap(key, KW_PT_128, sizeof(KW_PT_128), ct24), 0);
    expect_bytes("kw ciphertext §4.3", ct24, KW_CT_43, sizeof(ct24));
    expect("kw unwrap §4.3", oxi_aes_kw_unwrap(key, KW_CT_43, sizeof(KW_CT_43), back16), 0);
    expect_bytes("kw key data §4.3", back16, KW_PT_128, sizeof(back16));

    expect("kw wrap §4.6", oxi_aes_kw_wrap(key, KW_PT_256, sizeof(KW_PT_256), ct40), 0);
    expect_bytes("kw ciphertext §4.6", ct40, KW_CT_46, sizeof(ct40));
    expect("kw unwrap §4.6", oxi_aes_kw_unwrap(key, KW_CT_46, sizeof(KW_CT_46), back32), 0);
    expect_bytes("kw key data §4.6", back32, KW_PT_256, sizeof(back32));

    uint8_t bad[24];
    memcpy(bad, KW_CT_43, sizeof(bad));
    bad[0] ^= 0x01;
    expect("kw unwrap under a flipped ICV", oxi_aes_kw_unwrap(key, bad, sizeof(bad), back16),
           OXI_RESULT_TAG_MISMATCH);
    oxi_aes_kw_key_free(key);
}

/* KWP round trips at plaintext lengths 1 (seven padding bytes), 7, 8 (no
 * padding), 17 and 32. */
static void test_kwp(void) {
    static const size_t pt_lens[] = { 1, 7, 8, 17, 32 };
    static const uint8_t pt_seed[32] = {
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
    };
    OxiAesKwKey *key = NULL;
    expect("kwp key", oxi_aes_kw_key_new(KEY256_SP38, sizeof(KEY256_SP38), &key), 0);

    for (size_t i = 0; i < sizeof(pt_lens) / sizeof(pt_lens[0]); ++i) {
        size_t pt_len = pt_lens[i];
        size_t ct_len = ((pt_len + 7) / 8) * 8 + 8;
        uint8_t ct[64], back[64];
        uintptr_t written = 0;
        uintptr_t recovered = 0;
        char check[64];

        snprintf(check, sizeof(check), "kwp wrap, %zu bytes", pt_len);
        expect(check, oxi_aes_kwp_wrap(key, pt_seed, pt_len, ct, sizeof(ct), &written), 0);
        if (written != ct_len) {
            fprintf(stderr, "test_aes_modes, %s: written=%zu, expected %zu\n", check,
                    (size_t)written, ct_len);
            failures++;
        }
        snprintf(check, sizeof(check), "kwp unwrap, %zu bytes", pt_len);
        expect(check, oxi_aes_kwp_unwrap(key, ct, ct_len, back, sizeof(back), &recovered), 0);
        if (recovered != pt_len) {
            fprintf(stderr, "test_aes_modes, %s: written=%zu, expected %zu\n", check,
                    (size_t)recovered, pt_len);
            failures++;
        }
        expect_bytes(check, back, pt_seed, pt_len);
    }

    uint8_t ct16[16], back8[8];
    uintptr_t written = 0;
    expect("kwp wrap, 8 bytes, for the ICV check",
           oxi_aes_kwp_wrap(key, pt_seed, 8, ct16, sizeof(ct16), &written), 0);
    ct16[0] ^= 0x01;
    expect("kwp unwrap under a flipped ICV",
           oxi_aes_kwp_unwrap(key, ct16, sizeof(ct16), back8, sizeof(back8), &written),
           OXI_RESULT_TAG_MISMATCH);
    oxi_aes_kw_key_free(key);
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    test_cbc();
    test_ctr();
    test_ccm();
    test_cmac();
    test_kw();
    test_kwp();
    if (failures != 0) {
        fprintf(stderr, "test_aes_modes: %d checks failed\n", failures);
        return 2;
    }
    printf("test_aes_modes: OK\n");
    return 0;
}
