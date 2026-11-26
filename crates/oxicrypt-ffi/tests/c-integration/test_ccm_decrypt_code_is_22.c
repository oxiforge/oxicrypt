/* oxi_aes_ccm_open returns TagMismatch = 22 for every invalid input of the
 * formatted ciphertext (SP 800-38C §6.2: a failure of the parameter check
 * is indistinguishable from a failure of the tag check), writes nothing to
 * `pt` when it does, and the caller's own buffer-contract faults keep their
 * codes.
 *
 * Every refusal runs twice, with `pt` filled 0xA5 and then 0x5A: a written
 * byte equal to one fill cannot equal both.
 *
 * Vector: NIST CAVP CCMVS, vendor/nist/cavp-ccm/VPT256.rsp, [Plen = 16],
 * Count = 160 (16-byte tag, 13-byte nonce, 32-byte AAD, 16-byte payload).
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t KEY[32] = {
    0xee, 0x8c, 0xe1, 0x87, 0x16, 0x97, 0x79, 0xd1,
    0x3e, 0x44, 0x3d, 0x64, 0x28, 0xe3, 0x8b, 0x38,
    0xb5, 0x5d, 0xfb, 0x90, 0xf0, 0x22, 0x8a, 0x8a,
    0x4e, 0x62, 0xf8, 0xf5, 0x35, 0x80, 0x6e, 0x62,
};
/* The vector's 13-byte nonce, then one byte more for the 14-byte arm. */
static const uint8_t NONCE[14] = {
    0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39, 0x1c,
    0x98, 0xe6, 0x26, 0x9c, 0x8a, 0x00,
};
#define NONCE_LEN 13
static const uint8_t AAD[32] = {
    0x71, 0x8d, 0x13, 0xe4, 0x75, 0x22, 0xac, 0x4c,
    0xdf, 0x3f, 0x82, 0x80, 0x63, 0x98, 0x0b, 0x6d,
    0x45, 0x2f, 0xcd, 0xcd, 0x6e, 0x1a, 0x19, 0x04,
    0xbf, 0x87, 0xf5, 0x48, 0xa5, 0xfd, 0x5a, 0x05,
};
static const uint8_t CT[16] = {
    0xcc, 0x17, 0xbf, 0x87, 0x94, 0xc8, 0x43, 0x45,
    0x7d, 0x89, 0x93, 0x91, 0x89, 0x8e, 0xd2, 0x2a,
};
static const uint8_t TAG[16] = {
    0x6f, 0x9d, 0x28, 0xfc, 0xb6, 0x42, 0x34, 0xe1,
    0xcd, 0x79, 0x3c, 0x41, 0x44, 0xf1, 0xda, 0x50,
};

static const uint8_t FILLS[2] = { 0xA5, 0x5A };

/* A 13-byte nonce leaves a 2-byte length field (SP 800-38C A.2.1), so a
 * payload of 2^16 bytes cannot be represented. The arm that uses these is
 * the length fault itself, refused whatever the tag. */
static uint8_t big_ct[1u << 16];
static uint8_t big_pt[1u << 16];

static int failures;

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "test_ccm_decrypt_code_is_22, %s: rc=%d, expected %d\n", check, rc,
                want);
        failures++;
    }
}

/* An open that must return TagMismatch = 22 and leave `pt` unwritten. */
static void refused_open(const char *check, const OxiAesCcmKey *key, uintptr_t nonce_len,
                         const uint8_t *ct, uintptr_t ct_len, const uint8_t *tag, uint8_t *pt) {
    for (size_t f = 0; f < sizeof(FILLS); f++) {
        memset(pt, FILLS[f], ct_len);
        expect(check,
               oxi_aes_ccm_open(key, NONCE, nonce_len, AAD, sizeof(AAD), ct, ct_len, tag, pt),
               OXI_RESULT_TAG_MISMATCH);
        for (size_t i = 0; i < ct_len; i++) {
            if (pt[i] != FILLS[f]) {
                fprintf(stderr, "test_ccm_decrypt_code_is_22, %s (fill 0x%02X): pt[%zu] written\n",
                        check, FILLS[f], i);
                failures++;
                break;
            }
        }
    }
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiAesCcmKey *key = NULL;
    if (oxi_aes_ccm_key_new(KEY, sizeof(KEY), 16, &key) != 0) {
        fprintf(stderr, "test_ccm_decrypt_code_is_22: setup failed\n");
        return 1;
    }
    uint8_t pt[16];

    expect("valid ciphertext",
           oxi_aes_ccm_open(key, NONCE, NONCE_LEN, AAD, sizeof(AAD), CT, sizeof(CT), TAG, pt), 0);

    refused_open("6-byte nonce", key, 6, CT, sizeof(CT), TAG, pt);
    refused_open("14-byte nonce", key, 14, CT, sizeof(CT), TAG, pt);
    refused_open("the 16-byte payload's tag over its first 8 bytes", key, NONCE_LEN, CT, 8, TAG,
                 pt);
    refused_open("payload the length field cannot represent", key, NONCE_LEN, big_ct,
                 sizeof(big_ct), TAG, big_pt);

    uint8_t bad_tag[16];
    memcpy(bad_tag, TAG, sizeof(bad_tag));
    bad_tag[0] ^= 0x01;
    refused_open("flipped tag", key, NONCE_LEN, CT, sizeof(CT), bad_tag, pt);

    expect("NULL pt (control)",
           oxi_aes_ccm_open(key, NONCE, NONCE_LEN, AAD, sizeof(AAD), CT, sizeof(CT), TAG, NULL),
           OXI_RESULT_NULL_POINTER);

    /* Encryption keeps its distinct codes. */
    uint8_t ct[16], tag[16];
    expect("seal under a 6-byte nonce",
           oxi_aes_ccm_seal(key, NONCE, 6, AAD, sizeof(AAD), pt, sizeof(pt), ct, tag),
           OXI_RESULT_INVALID_NONCE_LENGTH);

    oxi_aes_ccm_key_free(key);
    if (failures != 0) {
        fprintf(stderr, "test_ccm_decrypt_code_is_22: %d checks failed\n", failures);
        return 2;
    }
    printf("test_ccm_decrypt_code_is_22: OK\n");
    return 0;
}
