/* AES-256-GCM through oxi_aes_gcm_key_new, oxi_aes_gcm_seal and
 * oxi_aes_gcm_open.
 *
 * Vector: McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)",
 * Test Case 15 (AES-256, empty AAD).
 *
 * The seal draws its IV from the caller's DRBG (SP 800-38D §8.2.2), so the
 * vector's ciphertext is checked through decryption only: opening the
 * vector's ciphertext under its IV and tag yields its plaintext. The seal
 * is checked by round trip.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
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

static int failures;

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "test_aes_gcm, %s: rc=%d, expected %d\n", check, rc, want);
        failures++;
    }
}

static void expect_bytes(const char *check, const uint8_t *got, const uint8_t *want, size_t n) {
    if (memcmp(got, want, n) != 0) {
        fprintf(stderr, "test_aes_gcm, %s: bytes differ\n", check);
        failures++;
    }
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiDrbg *drbg = NULL;
    OxiAesGcmKey *key = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&drbg) != 0 || oxi_drbg_instantiate(drbg, NULL, 0) != 0 ||
        oxi_aes_gcm_key_new(KEY, sizeof(KEY), &key) != 0) {
        fprintf(stderr, "test_aes_gcm: setup failed\n");
        return 1;
    }

    uint8_t back[64];
    memset(back, 0xA5, sizeof(back));
    expect("open the Case 15 ciphertext",
           oxi_aes_gcm_open(key, IV, NULL, 0, EXPECTED_CT, sizeof(EXPECTED_CT), EXPECTED_TAG,
                            back),
           0);
    expect_bytes("Case 15 plaintext", back, PT, sizeof(PT));

    uint8_t bad_tag[16];
    memcpy(bad_tag, EXPECTED_TAG, sizeof(bad_tag));
    bad_tag[0] ^= 0x01;
    /* Under each fill, so that a written byte equal to one fill is caught
     * by the other. */
    static const uint8_t FILLS[2] = { 0xA5, 0x5A };
    for (size_t f = 0; f < sizeof(FILLS); f++) {
        memset(back, FILLS[f], sizeof(back));
        expect("open under a flipped tag is TagMismatch",
               oxi_aes_gcm_open(key, IV, NULL, 0, EXPECTED_CT, sizeof(EXPECTED_CT), bad_tag,
                                back),
               OXI_RESULT_TAG_MISMATCH);
        for (size_t i = 0; i < sizeof(back); i++) {
            if (back[i] != FILLS[f]) {
                fprintf(stderr, "test_aes_gcm, flipped tag (fill 0x%02X): byte %zu written\n",
                        FILLS[f], i);
                failures++;
                break;
            }
        }
    }

    uint8_t ct[64], iv[12], tag[16];
    uint8_t ct2[64], iv2[12], tag2[16];
    expect("seal", oxi_aes_gcm_seal(key, drbg, NULL, 0, PT, sizeof(PT), ct, iv, tag), 0);
    expect("second seal", oxi_aes_gcm_seal(key, drbg, NULL, 0, PT, sizeof(PT), ct2, iv2, tag2),
           0);
    if (memcmp(iv, iv2, sizeof(iv)) == 0) {
        fprintf(stderr, "test_aes_gcm, two seals: the same IV twice\n");
        failures++;
    }
    memset(back, 0, sizeof(back));
    expect("open the sealed ciphertext under the returned IV",
           oxi_aes_gcm_open(key, iv, NULL, 0, ct, sizeof(ct), tag, back), 0);
    expect_bytes("round trip plaintext", back, PT, sizeof(PT));

    oxi_aes_gcm_key_free(key);
    oxi_drbg_free(drbg);
    if (failures != 0) {
        fprintf(stderr, "test_aes_gcm: %d checks failed\n", failures);
        return 2;
    }
    printf("test_aes_gcm: OK\n");
    return 0;
}
