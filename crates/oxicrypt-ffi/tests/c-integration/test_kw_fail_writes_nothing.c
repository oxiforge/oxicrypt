/* KW and KWP unwrap write nothing on a refused call (SP 800-38F §6.2
 * Algorithm 4 step 3, §6.3 Algorithm 6: "return FAIL and stop"), in the
 * forward and the inverse-cipher variants.
 *
 * Before each refused call `out` is filled with a sentinel and `written`
 * set to a sentinel; both must be unchanged after it returns. The arms:
 *
 *   - a ciphertext whose byte 0 is flipped, and for KWP one whose last
 *     semiblock is flipped, return TagMismatch = 22;
 *   - a ciphertext below the minimum length, 16 bytes for KW and 8 for
 *     KWP, returns LengthMismatch = 23;
 *   - a KWP wrap or unwrap whose `out_cap` is one byte below the result
 *     returns BufferTooSmall = 11.
 *
 * The unwrap of the unmodified ciphertext must replace the sentinel with
 * the key data.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SENTINEL 0xA5
#define WRITTEN_SENTINEL ((uintptr_t)0xA5A5A5A5u)
/* Applied to byte 0 of the wrapped ciphertext; unwrap recovers the
 * integrity check value from it and the check fails. */
#define ICV_FLIP 0x01
/* 13 bytes wrap to 24 with three padding bytes (SP 800-38F §6.3), so the
 * padding check has bytes to check. */
#define KWP_PT_LEN 13
#define KWP_CT_LEN 24

/* RFC 3394 §4.3: KEK and key data. */
static const uint8_t KEK[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static const uint8_t KEY_DATA[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
};

static int failures;

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "test_kw_fail_writes_nothing, %s: rc=%d, expected %d\n", check, rc,
                want);
        failures++;
    }
}

static void expect_sentinel(const char *check, const uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (out[i] != SENTINEL) {
            fprintf(stderr, "test_kw_fail_writes_nothing, %s: out[%zu] written\n", check, i);
            failures++;
            return;
        }
    }
}

static void expect_written_sentinel(const char *check, uintptr_t written) {
    if (written != WRITTEN_SENTINEL) {
        fprintf(stderr, "test_kw_fail_writes_nothing, %s: written changed\n", check);
        failures++;
    }
}

static void expect_written(const char *check, uintptr_t written, size_t want) {
    if (written != want) {
        fprintf(stderr, "test_kw_fail_writes_nothing, %s: written=%zu, expected %zu\n", check,
                (size_t)written, want);
        failures++;
    }
}

static void expect_key_data(const char *check, const uint8_t *out, size_t n) {
    if (memcmp(out, KEY_DATA, n) != 0) {
        fprintf(stderr, "test_kw_fail_writes_nothing, %s: out is not the key data\n", check);
        failures++;
    }
}

typedef int (*KwWrap)(const OxiAesKwKey *, const uint8_t *, uintptr_t, uint8_t *);
typedef int (*KwUnwrap)(const OxiAesKwKey *, const uint8_t *, uintptr_t, uint8_t *);
typedef int (*KwpWrap)(const OxiAesKwKey *, const uint8_t *, uintptr_t, uint8_t *, uintptr_t,
                       uintptr_t *);
typedef int (*KwpUnwrap)(const OxiAesKwKey *, const uint8_t *, uintptr_t, uint8_t *, uintptr_t,
                         uintptr_t *);

static void kw_case(const char *name, const OxiAesKwKey *key, KwWrap wrap, KwUnwrap unwrap) {
    uint8_t ct[24], bad[24], out[16];
    char check[96];

    snprintf(check, sizeof(check), "%s wrap", name);
    expect(check, wrap(key, KEY_DATA, sizeof(KEY_DATA), ct), 0);

    snprintf(check, sizeof(check), "%s unwrap, valid (control)", name);
    memset(out, SENTINEL, sizeof(out));
    expect(check, unwrap(key, ct, sizeof(ct), out), 0);
    expect_key_data(check, out, sizeof(out));

    snprintf(check, sizeof(check), "%s unwrap, 16-byte ciphertext", name);
    memset(out, SENTINEL, sizeof(out));
    expect(check, unwrap(key, ct, 16, out), OXI_RESULT_LENGTH_MISMATCH);
    expect_sentinel(check, out, sizeof(out));

    snprintf(check, sizeof(check), "%s unwrap, flipped ICV", name);
    memcpy(bad, ct, sizeof(ct));
    bad[0] ^= ICV_FLIP;
    memset(out, SENTINEL, sizeof(out));
    expect(check, unwrap(key, bad, sizeof(bad), out), OXI_RESULT_TAG_MISMATCH);
    expect_sentinel(check, out, sizeof(out));
}

/* Runs a KWP unwrap that must be refused with `want`, and checks that
 * nothing of `out` or `written` changed. */
static void kwp_refused_unwrap(const char *check, const OxiAesKwKey *key, KwpUnwrap unwrap,
                               const uint8_t *ct, size_t ct_len, size_t out_cap, int want) {
    uint8_t out[KWP_CT_LEN];
    uintptr_t written = WRITTEN_SENTINEL;
    memset(out, SENTINEL, sizeof(out));
    expect(check, unwrap(key, ct, ct_len, out, out_cap, &written), want);
    expect_sentinel(check, out, sizeof(out));
    expect_written_sentinel(check, written);
}

static void kwp_case(const char *name, const OxiAesKwKey *key, KwpWrap wrap, KwpUnwrap unwrap) {
    uint8_t ct[KWP_CT_LEN], bad[KWP_CT_LEN], out[KWP_CT_LEN];
    uintptr_t written = 0;
    char check[96];

    snprintf(check, sizeof(check), "%s wrap", name);
    expect(check, wrap(key, KEY_DATA, KWP_PT_LEN, ct, sizeof(ct), &written), 0);
    expect_written(check, written, KWP_CT_LEN);

    snprintf(check, sizeof(check), "%s wrap, out_cap one byte short", name);
    memset(out, SENTINEL, sizeof(out));
    written = WRITTEN_SENTINEL;
    expect(check, wrap(key, KEY_DATA, KWP_PT_LEN, out, KWP_CT_LEN - 1, &written),
           OXI_RESULT_BUFFER_TOO_SMALL);
    expect_sentinel(check, out, sizeof(out));
    expect_written_sentinel(check, written);

    snprintf(check, sizeof(check), "%s unwrap, valid (control)", name);
    memset(out, SENTINEL, sizeof(out));
    written = WRITTEN_SENTINEL;
    expect(check, unwrap(key, ct, sizeof(ct), out, sizeof(out), &written), 0);
    expect_key_data(check, out, KWP_PT_LEN);
    expect_written(check, written, KWP_PT_LEN);

    snprintf(check, sizeof(check), "%s unwrap, out_cap one byte short", name);
    kwp_refused_unwrap(check, key, unwrap, ct, sizeof(ct), KWP_PT_LEN - 1,
                       OXI_RESULT_BUFFER_TOO_SMALL);

    snprintf(check, sizeof(check), "%s unwrap, 8-byte ciphertext", name);
    kwp_refused_unwrap(check, key, unwrap, ct, 8, sizeof(out), OXI_RESULT_LENGTH_MISMATCH);

    /* The last semiblock of the ciphertext unwraps to the semiblock that
     * holds the padding. */
    snprintf(check, sizeof(check), "%s unwrap, flipped last semiblock", name);
    memcpy(bad, ct, sizeof(ct));
    bad[KWP_CT_LEN - 1] ^= 0x01;
    kwp_refused_unwrap(check, key, unwrap, bad, sizeof(bad), sizeof(out),
                       OXI_RESULT_TAG_MISMATCH);

    snprintf(check, sizeof(check), "%s unwrap, flipped ICV", name);
    memcpy(bad, ct, sizeof(ct));
    bad[0] ^= ICV_FLIP;
    kwp_refused_unwrap(check, key, unwrap, bad, sizeof(bad), sizeof(out),
                       OXI_RESULT_TAG_MISMATCH);
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiAesKwKey *key = NULL;
    if (oxi_aes_kw_key_new(KEK, sizeof(KEK), &key) != 0) {
        fprintf(stderr, "test_kw_fail_writes_nothing: setup failed\n");
        return 1;
    }
    kw_case("kw", key, oxi_aes_kw_wrap, oxi_aes_kw_unwrap);
    kw_case("kw inverse", key, oxi_aes_kw_wrap_inverse, oxi_aes_kw_unwrap_inverse);
    kwp_case("kwp", key, oxi_aes_kwp_wrap, oxi_aes_kwp_unwrap);
    kwp_case("kwp inverse", key, oxi_aes_kwp_wrap_inverse, oxi_aes_kwp_unwrap_inverse);
    oxi_aes_kw_key_free(key);

    if (failures != 0) {
        fprintf(stderr, "test_kw_fail_writes_nothing: %d checks failed\n", failures);
        return 2;
    }
    printf("test_kw_fail_writes_nothing: OK\n");
    return 0;
}
