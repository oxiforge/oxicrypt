/* The GCM key's encryption count (SP 800-38D §8.3): a share set by
 * oxi_aes_gcm_key_new_with_limit, a count preloaded by
 * oxi_aes_gcm_key_new_with_count and read back by
 * oxi_aes_gcm_key_invocations, and the KeyExhausted = 34 refusal, which
 * leaves the caller's output buffers and the count unchanged.
 *
 * Every refusal runs twice, with the outputs filled 0xA5 and then 0x5A:
 * a written byte equal to one fill cannot equal both.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TWO_POW_32 ((uint64_t)1 << 32)

static const uint8_t FILLS[2] = { 0xA5, 0x5A };

static const uint8_t KEY[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static const uint8_t PT[32] = { 0x6b, 0xc1, 0xbe, 0xe2 };

static int failures;
static OxiDrbg *drbg;

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "test_gcm_key_count_ops, %s: rc=%d, expected %d\n", check, rc, want);
        failures++;
    }
}

static void expect_count(const char *check, const OxiAesGcmKey *key, uint64_t want) {
    uint64_t got = 0;
    expect(check, oxi_aes_gcm_key_invocations(key, &got), 0);
    if (got != want) {
        fprintf(stderr, "test_gcm_key_count_ops, %s: count=%llu, expected %llu\n", check,
                (unsigned long long)got, (unsigned long long)want);
        failures++;
    }
}

static int seal(const OxiAesGcmKey *key, uint8_t *ct, uint8_t *iv, uint8_t *tag) {
    return oxi_aes_gcm_seal(key, drbg, NULL, 0, PT, sizeof(PT), ct, iv, tag);
}

static void expect_untouched(const char *check, const char *what, uint8_t fill,
                             const void *buf, size_t n) {
    const uint8_t *b = buf;
    for (size_t i = 0; i < n; i++) {
        if (b[i] != fill) {
            fprintf(stderr, "test_gcm_key_count_ops, %s (fill 0x%02X): %s byte %zu written\n",
                    check, fill, what, i);
            failures++;
            return;
        }
    }
}

/* A seal that must return KeyExhausted = 34, write nothing and leave the
 * count at `count`. */
static void refused_seal(const char *check, const OxiAesGcmKey *key, uint64_t count) {
    uint8_t ct[32], iv[12], tag[16];
    for (size_t f = 0; f < sizeof(FILLS); f++) {
        memset(ct, FILLS[f], sizeof(ct));
        memset(iv, FILLS[f], sizeof(iv));
        memset(tag, FILLS[f], sizeof(tag));
        expect(check, seal(key, ct, iv, tag), OXI_RESULT_KEY_EXHAUSTED);
        expect_untouched(check, "ciphertext", FILLS[f], ct, sizeof(ct));
        expect_untouched(check, "iv_out", FILLS[f], iv, sizeof(iv));
        expect_untouched(check, "tag_out", FILLS[f], tag, sizeof(tag));
        expect_count(check, key, count);
    }
}

typedef int (*GcmKeyNewWith)(const uint8_t *, uintptr_t, uint64_t, OxiAesGcmKey **);

/* A construction that must return InvalidInput = 5 and leave `*out`
 * unchanged. */
static void refused_new(const char *check, GcmKeyNewWith new_with, uint64_t arg) {
    for (size_t f = 0; f < sizeof(FILLS); f++) {
        OxiAesGcmKey *out;
        memset(&out, FILLS[f], sizeof(out));
        expect(check, new_with(KEY, sizeof(KEY), arg, &out), OXI_RESULT_INVALID_INPUT);
        expect_untouched(check, "*out", FILLS[f], &out, sizeof(out));
    }
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    if (oxi_hmac_drbg_sha256_new_rbg(&drbg) != 0 || oxi_drbg_instantiate(drbg, NULL, 0) != 0) {
        fprintf(stderr, "test_gcm_key_count_ops: DRBG setup failed\n");
        return 1;
    }
    uint8_t ct[32], iv[12], tag[16];
    OxiAesGcmKey *key = NULL;

    /* A share of one encryption: the second is refused. */
    expect("new_with_limit 1", oxi_aes_gcm_key_new_with_limit(KEY, sizeof(KEY), 1, &key), 0);
    expect("first seal under a limit of 1", seal(key, ct, iv, tag), 0);
    refused_seal("second seal under a limit of 1", key, 1);
    oxi_aes_gcm_key_free(key);

    /* The largest share, 2^32, is accepted. */
    key = NULL;
    expect("new_with_limit 2^32",
           oxi_aes_gcm_key_new_with_limit(KEY, sizeof(KEY), TWO_POW_32, &key), 0);
    expect("seal under a limit of 2^32", seal(key, ct, iv, tag), 0);
    expect_count("count after one seal under a limit of 2^32", key, 1);
    oxi_aes_gcm_key_free(key);

    /* A preloaded count reads back and advances by one per seal. */
    key = NULL;
    expect("new_with_count 5", oxi_aes_gcm_key_new_with_count(KEY, sizeof(KEY), 5, &key), 0);
    expect_count("count preloaded to 5", key, 5);
    expect("seal after a preload of 5", seal(key, ct, iv, tag), 0);
    expect_count("count after one seal from 5", key, 6);
    oxi_aes_gcm_key_free(key);

    key = NULL;
    expect("new_with_count 0", oxi_aes_gcm_key_new_with_count(KEY, sizeof(KEY), 0, &key), 0);
    expect_count("count preloaded to 0", key, 0);
    expect("seal after a preload of 0", seal(key, ct, iv, tag), 0);
    expect_count("count after one seal from 0", key, 1);
    oxi_aes_gcm_key_free(key);

    /* A preload of 2^32 builds an exhausted key. */
    key = NULL;
    expect("new_with_count 2^32",
           oxi_aes_gcm_key_new_with_count(KEY, sizeof(KEY), TWO_POW_32, &key), 0);
    expect_count("count preloaded to 2^32", key, TWO_POW_32);
    refused_seal("seal after a preload of 2^32", key, TWO_POW_32);
    oxi_aes_gcm_key_free(key);

    refused_new("new_with_limit 0", oxi_aes_gcm_key_new_with_limit, 0);
    refused_new("new_with_limit 2^32 + 1", oxi_aes_gcm_key_new_with_limit, TWO_POW_32 + 1);
    refused_new("new_with_count 2^32 + 1", oxi_aes_gcm_key_new_with_count, TWO_POW_32 + 1);

    /* Control: a key without a share seals twice. */
    key = NULL;
    expect("new", oxi_aes_gcm_key_new(KEY, sizeof(KEY), &key), 0);
    expect("first seal, no share (control)", seal(key, ct, iv, tag), 0);
    expect("second seal, no share (control)", seal(key, ct, iv, tag), 0);
    oxi_aes_gcm_key_free(key);

    oxi_drbg_free(drbg);
    if (failures != 0) {
        fprintf(stderr, "test_gcm_key_count_ops: %d checks failed\n", failures);
        return 2;
    }
    printf("test_gcm_key_count_ops: OK\n");
    return 0;
}
