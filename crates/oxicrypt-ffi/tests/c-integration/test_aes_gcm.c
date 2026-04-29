/* AES-256-GCM C ABI test — verifiable KAT + decrypt roundtrip + tag tamper.
 *
 * Vector source: McGrew & Viega "The Galois/Counter Mode of Operation
 *   (GCM)" reference document, Test Case 15 (AES-256, no AAD).
 *   Same vector used by `oxicrypt-aes::kat::self_test_gcm_aes256`,
 *   so this test exercises the C ABI against a value the underlying
 *   primitive's power-up KAT already validates.
 *
 * - K:  fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08
 *       fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08
 * - IV: ca fe ba be fa ce db ad de ca f8 88
 * - P:  64 bytes (see GCM_PT below)
 * - C:  64 bytes (see GCM256_CT below)
 * - T:  b0 94 da c5 d9 34 71 bd ec 1a 50 22 70 e3 cc 6c
 * - AAD: empty
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t KEY[32] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
};
static const uint8_t IV[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88,
};
static const uint8_t PT[64] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
};
static const uint8_t EXPECTED_CT[64] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
};
static const uint8_t EXPECTED_TAG[16] = {
    0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
    0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c,
};

/* OxiResult::TagMismatch (per crates/oxicrypt-ffi/src/error.rs). */
#define OXI_TAG_MISMATCH 22

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }

    OxiAes256Key *key = NULL;
    if (oxi_aes256_new(&key, KEY) != 0) {
        fprintf(stderr, "oxi_aes256_new failed\n");
        return 2;
    }

    uint8_t ct[64];
    uint8_t tag[16];
    int rc = oxi_aes256_gcm_encrypt(key, IV, NULL, 0, PT, sizeof(PT), ct, tag);
    if (rc != 0) {
        fprintf(stderr, "encrypt failed: rc=%d\n", rc);
        oxi_aes256_free(key);
        return 3;
    }
    if (memcmp(ct, EXPECTED_CT, sizeof(EXPECTED_CT)) != 0) {
        fprintf(stderr, "ciphertext mismatch vs McGrew/Viega Case 15\n");
        oxi_aes256_free(key);
        return 4;
    }
    if (memcmp(tag, EXPECTED_TAG, sizeof(EXPECTED_TAG)) != 0) {
        fprintf(stderr, "tag mismatch vs McGrew/Viega Case 15\n");
        oxi_aes256_free(key);
        return 5;
    }

    /* Decrypt round-trip recovers the plaintext. */
    uint8_t pt_back[64];
    rc = oxi_aes256_gcm_decrypt(key, IV, NULL, 0, ct, sizeof(ct), pt_back, tag);
    if (rc != 0) {
        fprintf(stderr, "decrypt failed: rc=%d\n", rc);
        oxi_aes256_free(key);
        return 6;
    }
    if (memcmp(pt_back, PT, sizeof(PT)) != 0) {
        fprintf(stderr, "decrypt roundtrip plaintext mismatch\n");
        oxi_aes256_free(key);
        return 7;
    }

    /* Tamper with the tag: must return OxiResult::TagMismatch=22. */
    uint8_t bad_tag[16];
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[0] ^= 0x01;
    rc = oxi_aes256_gcm_decrypt(key, IV, NULL, 0, ct, sizeof(ct), pt_back, bad_tag);
    if (rc != OXI_TAG_MISMATCH) {
        fprintf(stderr, "tag tamper not rejected as TagMismatch: rc=%d (expected %d)\n",
                rc, OXI_TAG_MISMATCH);
        oxi_aes256_free(key);
        return 8;
    }

    oxi_aes256_free(key);
    printf("test_aes_gcm: OK (McGrew/Viega Case 15 + roundtrip + tag-tamper)\n");
    return 0;
}
