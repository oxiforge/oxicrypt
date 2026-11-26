/* Pointer and length contract of every oxi_aes_* function in oxicrypt.h
 * that returns int.
 *
 * The table at the end names each one by hand. Each row drives the
 * refusals oxicrypt.h states for its signature, in the buffer contract
 * that opens its AES functions (the documentation of
 * oxi_aes_gcm_key_new) and in the function's own documentation:
 *
 *   - a NULL key handle, or a NULL `out` on a _key_new, returns
 *     NullPointer = 10;
 *   - a NULL pointer with a non-zero length, or a NULL fixed-size pointer
 *     (an IV, counter, tag, MAC, `written`, the DRBG handle), returns 10;
 *   - a length above SIZE_MAX / 2 (isize::MAX), or a range that runs past
 *     the top of the address space, returns InvalidInput = 5;
 *   - an output that shares a byte with an input, with another output or
 *     with a handle, and an input that shares a byte with a handle, return
 *     InvalidInput = 5;
 *   - a _key_new given a 15-byte key, or a tag, MAC, count or limit its
 *     documentation refuses, returns InvalidInput = 5.
 *
 * Every refusal runs twice, with the outputs filled 0xA5 and then 0x5A,
 * and fails if any byte of an output, of an input or of the first 16 bytes
 * of a handle changed: a written byte equal to one fill cannot equal both.
 *
 * Each row ends with the same call on valid arguments, which returns 0,
 * and prints row=<function name>. The Makefile compares the sorted list of
 * those names with the oxi_aes_* functions oxicrypt.h declares, so a
 * function without a row, a row run twice or a row for a function the
 * header does not declare fails the run.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ISIZE_MAX ((uintptr_t)(SIZE_MAX / 2))
#define HUGE_LEN (ISIZE_MAX + 1)
/* A range of 8 or more bytes from here ends past the top of the address
 * space. */
#define WRAP_PTR ((uint8_t *)(uintptr_t)(UINTPTR_MAX - 7))
/* The same for a pointer-sized or 8-byte output, on 32- and 64-bit
 * targets. */
#define WRAP_WORD_PTR ((void *)(uintptr_t)(UINTPTR_MAX - 3))
/* A range of ISIZE_MAX bytes from here ends at UINTPTR_MAX, above every
 * buffer and handle of this process on a 64-bit target. */
#define TOP_HALF_PTR ((const uint8_t *)(uintptr_t)(UINTPTR_MAX - ISIZE_MAX))

static const uint8_t KEY[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static const uint8_t NONCE[13] = { 0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39 };
static const uint8_t SETUP_PT[32] = { 0xd1, 0x5f, 0x98, 0xf2 };

/* Inputs are read from `in` and outputs written to `out`; an overlap is
 * built by moving one pointer into another's range. The unions keep
 * `written`, a count and the handle pointer of a _key_new aligned. */
static union {
    uint8_t b[128];
    uint64_t q[16];
    void *p[16];
} in, out;

#define I_DATA (in.b)
#define I_NONCE (in.b + 48)
#define I_AAD (in.b + 64)
#define I_IV (in.b + 80)
#define I_TAG (in.b + 96)
#define I_TAG2 (in.b + 112)
#define O_DATA (out.b)
#define O_IV (out.b + 64)
#define O_TAG (out.b + 80)
#define O_WORD ((void *)(out.b + 112))

static OxiDrbg *drbg;
static OxiAesGcmKey *gcm;
static OxiAesCcmKey *ccm;
static OxiAesCbcKey *cbc;
static OxiAesCtrKey *ctr;
static OxiAesKwKey *kw;
static OxiAesCmacKey *cmac;

static int failures;

static void expect(const char *name, const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "%s, %s: rc=%d, expected %d\n", name, check, rc, want);
        failures++;
    }
}

#define HANDLES 7
#define HANDLE_PREFIX 16
static const uint8_t FILLS[2] = { 0xA5, 0x5A };
static uint8_t in_before[sizeof(in.b)];
static uint8_t handles_before[HANDLES][HANDLE_PREFIX];

static const uint8_t *handle_bytes(size_t i) {
    const void *h[HANDLES] = { gcm, ccm, cbc, ctr, kw, cmac, drbg };
    return h[i];
}

static void arm_begin(uint8_t fill) {
    memset(out.b, fill, sizeof(out.b));
    memcpy(in_before, in.b, sizeof(in.b));
    for (size_t i = 0; i < HANDLES; i++) {
        memcpy(handles_before[i], handle_bytes(i), HANDLE_PREFIX);
    }
}

static void arm_end(const char *name, const char *check, uint8_t fill) {
    for (size_t i = 0; i < sizeof(out.b); i++) {
        if (out.b[i] != fill) {
            fprintf(stderr, "%s, %s (fill 0x%02X): out byte %zu written\n", name, check, fill, i);
            failures++;
            break;
        }
    }
    if (memcmp(in.b, in_before, sizeof(in.b)) != 0) {
        fprintf(stderr, "%s, %s (fill 0x%02X): an input changed\n", name, check, fill);
        failures++;
    }
    for (size_t i = 0; i < HANDLES; i++) {
        if (memcmp(handle_bytes(i), handles_before[i], HANDLE_PREFIX) != 0) {
            fprintf(stderr, "%s, %s (fill 0x%02X): handle %zu changed\n", name, check, fill, i);
            failures++;
        }
    }
}

/* Runs `call` under each fill and checks its code and that nothing was
 * written. */
#define CHECK(check, want, call)                                                         \
    do {                                                                                 \
        for (size_t f_ = 0; f_ < sizeof(FILLS); f_++) {                                  \
            arm_begin(FILLS[f_]);                                                        \
            expect(n, check, (call), (want));                                            \
            arm_end(n, check, FILLS[f_]);                                                \
        }                                                                                \
    } while (0)

static int row_done(const char *name) {
    printf("row=%s\n", name);
    return 1;
}

#define NUL OXI_RESULT_NULL_POINTER
#define INV OXI_RESULT_INVALID_INPUT
#define LEN OXI_RESULT_LENGTH_MISMATCH
#define SMALL OXI_RESULT_BUFFER_TOO_SMALL

#define KEY_OUT(type) ((type **)O_WORD)

/* The arms every _key_new takes. The variable arguments are those between
 * `key_len` and `out`, with a trailing comma, or empty. */
#define KEY_NEW_ARMS(sym, type, ...)                                                     \
    CHECK("NULL out", NUL, sym(KEY, 32, __VA_ARGS__ NULL));                              \
    CHECK("NULL key, length 32", NUL, sym(NULL, 32, __VA_ARGS__ KEY_OUT(type)));         \
    CHECK("15-byte key", INV, sym(KEY, 15, __VA_ARGS__ KEY_OUT(type)));                  \
    CHECK("key wraps the address space", INV, sym(WRAP_PTR, 16, __VA_ARGS__ KEY_OUT(type))); \
    CHECK("out wraps the address space", INV, sym(KEY, 32, __VA_ARGS__ WRAP_WORD_PTR));  \
    CHECK("key length SIZE_MAX / 2 + 1", INV, sym(KEY, HUGE_LEN, __VA_ARGS__ KEY_OUT(type))); \
    CHECK("out over key", INV, sym(I_DATA, 32, __VA_ARGS__ (type **)(void *)I_DATA))

#define KEY_NEW_CONTROL(sym, type, free_fn, ...)                                         \
    do {                                                                                 \
        expect(n, "valid (control)", sym(KEY, 32, __VA_ARGS__ KEY_OUT(type)), 0);        \
        free_fn(*KEY_OUT(type));                                                         \
    } while (0)

static int row_oxi_aes_gcm_key_new(void) {
    const char *n = "oxi_aes_gcm_key_new";
    KEY_NEW_ARMS(oxi_aes_gcm_key_new, OxiAesGcmKey, );
    KEY_NEW_CONTROL(oxi_aes_gcm_key_new, OxiAesGcmKey, oxi_aes_gcm_key_free, );
    return row_done(n);
}

static int row_oxi_aes_gcm_key_new_with_count(void) {
    const char *n = "oxi_aes_gcm_key_new_with_count";
    KEY_NEW_ARMS(oxi_aes_gcm_key_new_with_count, OxiAesGcmKey, 0,);
    CHECK("count 2^32 + 1", INV,
          oxi_aes_gcm_key_new_with_count(KEY, 32, ((uint64_t)1 << 32) + 1, KEY_OUT(OxiAesGcmKey)));
    KEY_NEW_CONTROL(oxi_aes_gcm_key_new_with_count, OxiAesGcmKey, oxi_aes_gcm_key_free, 0,);
    return row_done(n);
}

static int row_oxi_aes_gcm_key_new_with_limit(void) {
    const char *n = "oxi_aes_gcm_key_new_with_limit";
    KEY_NEW_ARMS(oxi_aes_gcm_key_new_with_limit, OxiAesGcmKey, 1,);
    CHECK("limit 0", INV, oxi_aes_gcm_key_new_with_limit(KEY, 32, 0, KEY_OUT(OxiAesGcmKey)));
    CHECK("limit 2^32 + 1", INV,
          oxi_aes_gcm_key_new_with_limit(KEY, 32, ((uint64_t)1 << 32) + 1, KEY_OUT(OxiAesGcmKey)));
    KEY_NEW_CONTROL(oxi_aes_gcm_key_new_with_limit, OxiAesGcmKey, oxi_aes_gcm_key_free, 1,);
    return row_done(n);
}

static int row_oxi_aes_ccm_key_new(void) {
    const char *n = "oxi_aes_ccm_key_new";
    KEY_NEW_ARMS(oxi_aes_ccm_key_new, OxiAesCcmKey, 16,);
    CHECK("tag_len 7", INV, oxi_aes_ccm_key_new(KEY, 32, 7, KEY_OUT(OxiAesCcmKey)));
    CHECK("tag_len 17", INV, oxi_aes_ccm_key_new(KEY, 32, 17, KEY_OUT(OxiAesCcmKey)));
    KEY_NEW_CONTROL(oxi_aes_ccm_key_new, OxiAesCcmKey, oxi_aes_ccm_key_free, 16,);
    return row_done(n);
}

static int row_oxi_aes_ccm_key_new_with_count(void) {
    const char *n = "oxi_aes_ccm_key_new_with_count";
    KEY_NEW_ARMS(oxi_aes_ccm_key_new_with_count, OxiAesCcmKey, 16, 0,);
    CHECK("tag_len 7", INV, oxi_aes_ccm_key_new_with_count(KEY, 32, 7, 0, KEY_OUT(OxiAesCcmKey)));
    CHECK("tag_len 17", INV,
          oxi_aes_ccm_key_new_with_count(KEY, 32, 17, 0, KEY_OUT(OxiAesCcmKey)));
    CHECK("count 2^61 + 1", INV,
          oxi_aes_ccm_key_new_with_count(KEY, 32, 16, ((uint64_t)1 << 61) + 1,
                                         KEY_OUT(OxiAesCcmKey)));
    KEY_NEW_CONTROL(oxi_aes_ccm_key_new_with_count, OxiAesCcmKey, oxi_aes_ccm_key_free, 16, 0,);
    return row_done(n);
}

static int row_oxi_aes_cbc_key_new(void) {
    const char *n = "oxi_aes_cbc_key_new";
    KEY_NEW_ARMS(oxi_aes_cbc_key_new, OxiAesCbcKey, );
    KEY_NEW_CONTROL(oxi_aes_cbc_key_new, OxiAesCbcKey, oxi_aes_cbc_key_free, );
    return row_done(n);
}

static int row_oxi_aes_ctr_key_new(void) {
    const char *n = "oxi_aes_ctr_key_new";
    KEY_NEW_ARMS(oxi_aes_ctr_key_new, OxiAesCtrKey, );
    KEY_NEW_CONTROL(oxi_aes_ctr_key_new, OxiAesCtrKey, oxi_aes_ctr_key_free, );
    return row_done(n);
}

static int row_oxi_aes_kw_key_new(void) {
    const char *n = "oxi_aes_kw_key_new";
    KEY_NEW_ARMS(oxi_aes_kw_key_new, OxiAesKwKey, );
    KEY_NEW_CONTROL(oxi_aes_kw_key_new, OxiAesKwKey, oxi_aes_kw_key_free, );
    return row_done(n);
}

static int row_oxi_aes_cmac_key_new(void) {
    const char *n = "oxi_aes_cmac_key_new";
    KEY_NEW_ARMS(oxi_aes_cmac_key_new, OxiAesCmacKey, 16,);
    CHECK("mac_len 7", INV, oxi_aes_cmac_key_new(KEY, 32, 7, KEY_OUT(OxiAesCmacKey)));
    CHECK("mac_len 17", INV, oxi_aes_cmac_key_new(KEY, 32, 17, KEY_OUT(OxiAesCmacKey)));
    KEY_NEW_CONTROL(oxi_aes_cmac_key_new, OxiAesCmacKey, oxi_aes_cmac_key_free, 16,);
    return row_done(n);
}

/* A _key_invocations symbol. */
#define INVOCATIONS_ROW(sym, handle)                                                     \
    static int row_##sym(void) {                                                         \
        const char *n = #sym;                                                            \
        uint64_t *count = O_WORD;                                                        \
        CHECK("NULL handle", NUL, sym(NULL, count));                                     \
        CHECK("NULL out", NUL, sym(handle, NULL));                                       \
        CHECK("out wraps the address space", INV, sym(handle, WRAP_WORD_PTR));           \
        CHECK("out over the handle", INV, sym(handle, (uint64_t *)(void *)handle));      \
        expect(n, "valid (control)", sym(handle, count), 0);                             \
        return row_done(n);                                                              \
    }

INVOCATIONS_ROW(oxi_aes_gcm_key_invocations, gcm)
INVOCATIONS_ROW(oxi_aes_ccm_key_invocations, ccm)

static int row_oxi_aes_gcm_seal(void) {
    const char *n = "oxi_aes_gcm_seal";
    const uint8_t *a = I_AAD, *p = I_DATA;
    uint8_t *c = O_DATA, *v = O_IV, *t = O_TAG;
    uint8_t *k = (uint8_t *)(void *)gcm, *d = (uint8_t *)(void *)drbg;
    CHECK("NULL handle", NUL, oxi_aes_gcm_seal(NULL, drbg, a, 16, p, 16, c, v, t));
    CHECK("NULL DRBG", NUL, oxi_aes_gcm_seal(gcm, NULL, a, 16, p, 16, c, v, t));
    CHECK("NULL aad, length 16", NUL, oxi_aes_gcm_seal(gcm, drbg, NULL, 16, p, 16, c, v, t));
    CHECK("NULL plaintext, length 16", NUL,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, NULL, 16, c, v, t));
    CHECK("NULL ciphertext", NUL, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, NULL, v, t));
    CHECK("NULL iv_out", NUL, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, NULL, t));
    CHECK("NULL tag_out", NUL, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, NULL));
    CHECK("DRBG wraps the address space", INV,
          oxi_aes_gcm_seal(gcm, (OxiDrbg *)WRAP_WORD_PTR, a, 16, p, 16, c, v, t));
    CHECK("aad wraps the address space", INV,
          oxi_aes_gcm_seal(gcm, drbg, WRAP_PTR, 16, p, 16, c, v, t));
    CHECK("plaintext wraps the address space", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, WRAP_PTR, 16, c, v, t));
    CHECK("ciphertext wraps the address space", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, WRAP_PTR, v, t));
    CHECK("iv_out wraps the address space", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, WRAP_PTR, t));
    CHECK("tag_out wraps the address space", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, WRAP_PTR));
    CHECK("aad length SIZE_MAX / 2 + 1", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, HUGE_LEN, p, 16, c, v, t));
    CHECK("plaintext length SIZE_MAX / 2 + 1", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, HUGE_LEN, c, v, t));
    CHECK("ciphertext over plaintext", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, I_DATA + 8, v, t));
    CHECK("ciphertext over aad", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, I_AAD + 8, v, t));
    CHECK("iv_out over plaintext", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, I_DATA + 4, t));
    CHECK("iv_out over aad", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, I_AAD + 4, t));
    CHECK("tag_out over plaintext", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, I_DATA + 8));
    CHECK("tag_out over aad", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, I_AAD));
    CHECK("iv_out over ciphertext", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, c + 4, t));
    CHECK("tag_out over ciphertext", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, c + 8));
    CHECK("tag_out over iv_out", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, v + 4));
    CHECK("ciphertext over the key handle", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, k, v, t));
    CHECK("iv_out over the key handle", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, k, t));
    CHECK("tag_out over the key handle", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, k));
    CHECK("ciphertext over the DRBG handle", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, d, v, t));
    CHECK("iv_out over the DRBG handle", INV, oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, d, t));
    CHECK("tag_out over the DRBG handle", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, d));
    CHECK("aad over the key handle", INV, oxi_aes_gcm_seal(gcm, drbg, k, 16, p, 16, c, v, t));
    CHECK("plaintext over the key handle", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, k, 16, c, v, t));
    CHECK("aad over the DRBG handle", INV, oxi_aes_gcm_seal(gcm, drbg, d, 16, p, 16, c, v, t));
    CHECK("plaintext over the DRBG handle", INV,
          oxi_aes_gcm_seal(gcm, drbg, a, 16, d, 16, c, v, t));
    CHECK("DRBG handle is the key handle", INV,
          oxi_aes_gcm_seal(gcm, (OxiDrbg *)(void *)gcm, a, 16, p, 16, c, v, t));
    expect(n, "valid (control)", oxi_aes_gcm_seal(gcm, drbg, a, 16, p, 16, c, v, t), 0);
    return row_done(n);
}

static int row_oxi_aes_gcm_open(void) {
    const char *n = "oxi_aes_gcm_open";
    const uint8_t *v = I_IV, *a = I_AAD, *c = I_DATA, *t = I_TAG;
    uint8_t *p = O_DATA;
    const uint8_t *k = (const uint8_t *)(void *)gcm;
    if (oxi_aes_gcm_seal(gcm, drbg, a, 16, SETUP_PT, 16, I_DATA, I_IV, I_TAG) != 0) {
        fprintf(stderr, "%s: setup seal failed\n", n);
        failures++;
    }
    CHECK("NULL handle", NUL, oxi_aes_gcm_open(NULL, v, a, 16, c, 16, t, p));
    CHECK("NULL iv", NUL, oxi_aes_gcm_open(gcm, NULL, a, 16, c, 16, t, p));
    CHECK("NULL aad, length 16", NUL, oxi_aes_gcm_open(gcm, v, NULL, 16, c, 16, t, p));
    CHECK("NULL ciphertext, length 16", NUL, oxi_aes_gcm_open(gcm, v, a, 16, NULL, 16, t, p));
    CHECK("NULL tag", NUL, oxi_aes_gcm_open(gcm, v, a, 16, c, 16, NULL, p));
    CHECK("NULL plaintext", NUL, oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, NULL));
    CHECK("iv wraps the address space", INV, oxi_aes_gcm_open(gcm, WRAP_PTR, a, 16, c, 16, t, p));
    CHECK("aad wraps the address space", INV,
          oxi_aes_gcm_open(gcm, v, WRAP_PTR, 16, c, 16, t, p));
    CHECK("ciphertext wraps the address space", INV,
          oxi_aes_gcm_open(gcm, v, a, 16, WRAP_PTR, 16, t, p));
    CHECK("tag wraps the address space", INV,
          oxi_aes_gcm_open(gcm, v, a, 16, c, 16, WRAP_PTR, p));
    CHECK("plaintext wraps the address space", INV,
          oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, WRAP_PTR));
    CHECK("aad length SIZE_MAX / 2 + 1", INV, oxi_aes_gcm_open(gcm, v, a, HUGE_LEN, c, 16, t, p));
    CHECK("ciphertext length SIZE_MAX / 2 + 1", INV,
          oxi_aes_gcm_open(gcm, v, a, 16, c, HUGE_LEN, t, p));
    CHECK("plaintext over iv", INV, oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, I_IV));
    CHECK("plaintext over aad", INV, oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, I_AAD));
    CHECK("plaintext over ciphertext", INV, oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, I_DATA + 8));
    CHECK("plaintext over tag", INV, oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, I_TAG));
    CHECK("plaintext over the handle", INV,
          oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, (uint8_t *)(void *)gcm));
    CHECK("iv over the handle", INV, oxi_aes_gcm_open(gcm, k, a, 16, c, 16, t, p));
    CHECK("aad over the handle", INV, oxi_aes_gcm_open(gcm, v, k, 16, c, 16, t, p));
    CHECK("ciphertext over the handle", INV, oxi_aes_gcm_open(gcm, v, a, 16, k, 16, t, p));
    CHECK("tag over the handle", INV, oxi_aes_gcm_open(gcm, v, a, 16, c, 16, k, p));
    expect(n, "valid (control)", oxi_aes_gcm_open(gcm, v, a, 16, c, 16, t, p), 0);
    return row_done(n);
}

static int row_oxi_aes_ccm_seal(void) {
    const char *n = "oxi_aes_ccm_seal";
    const size_t nl = sizeof(NONCE);
    const uint8_t *nn = I_NONCE, *a = I_AAD, *p = I_DATA;
    uint8_t *c = O_DATA, *t = O_TAG;
    uint8_t *k = (uint8_t *)(void *)ccm;
    CHECK("NULL handle", NUL, oxi_aes_ccm_seal(NULL, nn, nl, a, 16, p, 16, c, t));
    CHECK("NULL nonce, length 13", NUL, oxi_aes_ccm_seal(ccm, NULL, nl, a, 16, p, 16, c, t));
    CHECK("NULL aad, length 16", NUL, oxi_aes_ccm_seal(ccm, nn, nl, NULL, 16, p, 16, c, t));
    CHECK("NULL pt, length 16", NUL, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, NULL, 16, c, t));
    CHECK("NULL ct", NUL, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, NULL, t));
    CHECK("NULL tag", NUL, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, NULL));
    CHECK("nonce wraps the address space", INV,
          oxi_aes_ccm_seal(ccm, WRAP_PTR, nl, a, 16, p, 16, c, t));
    CHECK("aad wraps the address space", INV,
          oxi_aes_ccm_seal(ccm, nn, nl, WRAP_PTR, 16, p, 16, c, t));
    CHECK("pt wraps the address space", INV,
          oxi_aes_ccm_seal(ccm, nn, nl, a, 16, WRAP_PTR, 16, c, t));
    CHECK("ct wraps the address space", INV,
          oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, WRAP_PTR, t));
    CHECK("tag wraps the address space", INV,
          oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, WRAP_PTR));
    CHECK("nonce length SIZE_MAX / 2 + 1", INV,
          oxi_aes_ccm_seal(ccm, nn, HUGE_LEN, a, 16, p, 16, c, t));
    CHECK("aad length SIZE_MAX / 2 + 1", INV,
          oxi_aes_ccm_seal(ccm, nn, nl, a, HUGE_LEN, p, 16, c, t));
    CHECK("pt length SIZE_MAX / 2 + 1", INV,
          oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, HUGE_LEN, c, t));
    CHECK("ct over nonce", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, I_NONCE, t));
    CHECK("ct over aad", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, I_AAD, t));
    CHECK("ct over pt", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, I_DATA + 8, t));
    CHECK("tag over nonce", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, I_NONCE));
    CHECK("tag over aad", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, I_AAD));
    CHECK("tag over pt", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, I_DATA + 8));
    CHECK("tag over ct", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, c + 8));
    CHECK("ct over the handle", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, k, t));
    CHECK("tag over the handle", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, k));
    CHECK("nonce over the handle", INV, oxi_aes_ccm_seal(ccm, k, nl, a, 16, p, 16, c, t));
    CHECK("aad over the handle", INV, oxi_aes_ccm_seal(ccm, nn, nl, k, 16, p, 16, c, t));
    CHECK("pt over the handle", INV, oxi_aes_ccm_seal(ccm, nn, nl, a, 16, k, 16, c, t));
    expect(n, "valid (control)", oxi_aes_ccm_seal(ccm, nn, nl, a, 16, p, 16, c, t), 0);
    return row_done(n);
}

static int row_oxi_aes_ccm_open(void) {
    const char *n = "oxi_aes_ccm_open";
    const size_t nl = sizeof(NONCE);
    const uint8_t *nn = I_NONCE, *a = I_AAD, *c = I_DATA, *t = I_TAG;
    uint8_t *p = O_DATA;
    const uint8_t *k = (const uint8_t *)(void *)ccm;
    if (oxi_aes_ccm_seal(ccm, nn, nl, a, 16, SETUP_PT, 16, I_DATA, I_TAG) != 0) {
        fprintf(stderr, "%s: setup seal failed\n", n);
        failures++;
    }
    CHECK("NULL handle", NUL, oxi_aes_ccm_open(NULL, nn, nl, a, 16, c, 16, t, p));
    CHECK("NULL nonce, length 13", NUL, oxi_aes_ccm_open(ccm, NULL, nl, a, 16, c, 16, t, p));
    CHECK("NULL aad, length 16", NUL, oxi_aes_ccm_open(ccm, nn, nl, NULL, 16, c, 16, t, p));
    CHECK("NULL ct, length 16", NUL, oxi_aes_ccm_open(ccm, nn, nl, a, 16, NULL, 16, t, p));
    CHECK("NULL tag", NUL, oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, NULL, p));
    CHECK("NULL pt", NUL, oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, NULL));
    CHECK("nonce wraps the address space", INV,
          oxi_aes_ccm_open(ccm, WRAP_PTR, nl, a, 16, c, 16, t, p));
    CHECK("aad wraps the address space", INV,
          oxi_aes_ccm_open(ccm, nn, nl, WRAP_PTR, 16, c, 16, t, p));
    CHECK("ct wraps the address space", INV,
          oxi_aes_ccm_open(ccm, nn, nl, a, 16, WRAP_PTR, 16, t, p));
    CHECK("tag wraps the address space", INV,
          oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, WRAP_PTR, p));
    CHECK("pt wraps the address space", INV,
          oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, WRAP_PTR));
    CHECK("nonce length SIZE_MAX / 2 + 1", INV,
          oxi_aes_ccm_open(ccm, nn, HUGE_LEN, a, 16, c, 16, t, p));
    CHECK("aad length SIZE_MAX / 2 + 1", INV,
          oxi_aes_ccm_open(ccm, nn, nl, a, HUGE_LEN, c, 16, t, p));
    CHECK("ct length SIZE_MAX / 2 + 1", INV,
          oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, HUGE_LEN, t, p));
    CHECK("pt over nonce", INV, oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, I_NONCE));
    CHECK("pt over aad", INV, oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, I_AAD));
    CHECK("pt over ct", INV, oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, I_DATA + 8));
    CHECK("pt over tag", INV, oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, I_TAG));
    CHECK("pt over the handle", INV,
          oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, (uint8_t *)(void *)ccm));
    CHECK("nonce over the handle", INV, oxi_aes_ccm_open(ccm, k, nl, a, 16, c, 16, t, p));
    CHECK("aad over the handle", INV, oxi_aes_ccm_open(ccm, nn, nl, k, 16, c, 16, t, p));
    CHECK("ct over the handle", INV, oxi_aes_ccm_open(ccm, nn, nl, a, 16, k, 16, t, p));
    CHECK("tag over the handle", INV, oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, k, p));
    expect(n, "valid (control)", oxi_aes_ccm_open(ccm, nn, nl, a, 16, c, 16, t, p), 0);
    return row_done(n);
}

/* oxi_aes_cbc_encrypt, oxi_aes_cbc_decrypt and oxi_aes_ctr: a 16-byte IV
 * or counter block, an input and an output of the input's length. A
 * (NULL, 0) input returns ZERO_RC: InvalidPayloadLength = 26 for CBC,
 * whose length must be positive, and 0 for CTR, which takes any length. */
#define BLOCK_ROW(sym, handle, ZERO_RC)                                                  \
    static int row_##sym(void) {                                                         \
        const char *n = #sym;                                                            \
        const uint8_t *k = (const uint8_t *)(void *)handle;                              \
        CHECK("NULL handle", NUL, sym(NULL, I_IV, I_DATA, 32, O_DATA));                  \
        CHECK("NULL iv", NUL, sym(handle, NULL, I_DATA, 32, O_DATA));                    \
        CHECK("NULL in, length 32", NUL, sym(handle, I_IV, NULL, 32, O_DATA));           \
        CHECK("NULL out", NUL, sym(handle, I_IV, I_DATA, 32, NULL));                     \
        CHECK("iv wraps the address space", INV, sym(handle, WRAP_PTR, I_DATA, 32, O_DATA)); \
        CHECK("in wraps the address space", INV, sym(handle, I_IV, WRAP_PTR, 16, O_DATA)); \
        CHECK("out wraps the address space", INV, sym(handle, I_IV, I_DATA, 16, WRAP_PTR)); \
        CHECK("length SIZE_MAX / 2 + 1", INV, sym(handle, I_IV, I_DATA, HUGE_LEN, O_DATA)); \
        CHECK("in NULL, length 0", ZERO_RC, sym(handle, I_IV, NULL, 0, O_DATA));         \
        CHECK("out over in", INV, sym(handle, I_IV, I_DATA, 32, I_DATA + 16));           \
        CHECK("out over iv", INV, sym(handle, I_IV, I_DATA, 32, I_IV));                  \
        CHECK("out over the handle", INV,                                                \
              sym(handle, I_IV, I_DATA, 32, (uint8_t *)(void *)handle));                 \
        CHECK("in over the handle", INV, sym(handle, I_IV, k, 32, O_DATA));              \
        CHECK("iv over the handle", INV, sym(handle, k, I_DATA, 32, O_DATA));            \
        expect(n, "valid (control)", sym(handle, I_IV, I_DATA, 32, O_DATA), 0);          \
        return row_done(n);                                                              \
    }

BLOCK_ROW(oxi_aes_cbc_encrypt, cbc, OXI_RESULT_INVALID_PAYLOAD_LENGTH)
BLOCK_ROW(oxi_aes_cbc_decrypt, cbc, OXI_RESULT_INVALID_PAYLOAD_LENGTH)
BLOCK_ROW(oxi_aes_ctr, ctr, 0)

/* KW wrap and unwrap, forward and inverse cipher. PREP leaves a valid input
 * of IN_LEN bytes at I_DATA. A KW input is at least 16 bytes to wrap and 24
 * to unwrap, so a (NULL, 0) input returns LengthMismatch = 23. */
#define KW_ROW(sym, IN_LEN, PREP)                                                        \
    static int row_##sym(void) {                                                         \
        const char *n = #sym;                                                            \
        const uint8_t *k = (const uint8_t *)(void *)kw;                                  \
        PREP;                                                                            \
        CHECK("NULL handle", NUL, sym(NULL, I_DATA, IN_LEN, O_DATA));                    \
        CHECK("NULL in, non-zero length", NUL, sym(kw, NULL, IN_LEN, O_DATA));           \
        CHECK("NULL out", NUL, sym(kw, I_DATA, IN_LEN, NULL));                           \
        CHECK("in wraps the address space", INV, sym(kw, WRAP_PTR, IN_LEN, O_DATA));     \
        CHECK("out wraps the address space", INV, sym(kw, I_DATA, IN_LEN, WRAP_PTR));    \
        CHECK("length SIZE_MAX / 2 + 1", INV, sym(kw, I_DATA, HUGE_LEN, O_DATA));        \
        CHECK("in NULL, length 0", LEN, sym(kw, NULL, 0, O_DATA));                       \
        CHECK("out over in", INV, sym(kw, I_DATA, IN_LEN, I_DATA + 8));                  \
        CHECK("out over the handle", INV, sym(kw, I_DATA, IN_LEN, (uint8_t *)(void *)kw)); \
        CHECK("in over the handle", INV, sym(kw, k, IN_LEN, O_DATA));                    \
        expect(n, "valid (control)", sym(kw, I_DATA, IN_LEN, O_DATA), 0);                \
        return row_done(n);                                                              \
    }

/* A wrap of SIZE_MAX / 2 bytes has an output 8 bytes longer, above
 * SIZE_MAX / 2, so the output's range is refused. The input starts where
 * that length still fits the address space. */
#define KW_WRAP_BOUNDARY(sym)                                                            \
    CHECK("length SIZE_MAX / 2, output past SIZE_MAX / 2", INV,                          \
          sym(kw, TOP_HALF_PTR, ISIZE_MAX, O_DATA))

KW_ROW(oxi_aes_kw_wrap, 16, memcpy(I_DATA, KEY, 16); KW_WRAP_BOUNDARY(oxi_aes_kw_wrap))
KW_ROW(oxi_aes_kw_wrap_inverse, 16,
       memcpy(I_DATA, KEY, 16); KW_WRAP_BOUNDARY(oxi_aes_kw_wrap_inverse))
KW_ROW(oxi_aes_kw_unwrap, 24, oxi_aes_kw_wrap(kw, KEY, 16, I_DATA))
KW_ROW(oxi_aes_kw_unwrap_inverse, 24, oxi_aes_kw_wrap_inverse(kw, KEY, 16, I_DATA))

/* KWP wrap and unwrap, forward and inverse cipher, with `out_cap` and
 * `written`. PREP leaves a valid input of IN_LEN bytes at I_DATA, whose
 * result is one byte longer than SHORT_CAP. A KWP plaintext is 1 byte or
 * more and a KWP ciphertext 16 or more, so a (NULL, 0) input returns
 * LengthMismatch = 23. */
#define KWP_ROW(sym, IN_LEN, SHORT_CAP, PREP)                                            \
    static int row_##sym(void) {                                                         \
        const char *n = #sym;                                                            \
        const uint8_t *k = (const uint8_t *)(void *)kw;                                  \
        uintptr_t *w = O_WORD;                                                           \
        PREP;                                                                            \
        CHECK("NULL handle", NUL, sym(NULL, I_DATA, IN_LEN, O_DATA, 32, w));             \
        CHECK("NULL in, non-zero length", NUL, sym(kw, NULL, IN_LEN, O_DATA, 32, w));    \
        CHECK("NULL out, out_cap 32", NUL, sym(kw, I_DATA, IN_LEN, NULL, 32, w));        \
        CHECK("NULL written", NUL, sym(kw, I_DATA, IN_LEN, O_DATA, 32, NULL));           \
        CHECK("in wraps the address space", INV, sym(kw, WRAP_PTR, IN_LEN, O_DATA, 32, w)); \
        CHECK("out wraps the address space", INV, sym(kw, I_DATA, IN_LEN, WRAP_PTR, 32, w)); \
        CHECK("written wraps the address space", INV,                                    \
              sym(kw, I_DATA, IN_LEN, O_DATA, 32, WRAP_WORD_PTR));                       \
        CHECK("in length SIZE_MAX / 2 + 1", INV, sym(kw, I_DATA, HUGE_LEN, O_DATA, 32, w)); \
        CHECK("out_cap SIZE_MAX / 2 + 1", INV, sym(kw, I_DATA, IN_LEN, O_DATA, HUGE_LEN, w)); \
        CHECK("in NULL, length 0", LEN, sym(kw, NULL, 0, O_DATA, 32, w));                \
        CHECK("out_cap one byte short", SMALL, sym(kw, I_DATA, IN_LEN, O_DATA, SHORT_CAP, w)); \
        CHECK("out over in", INV, sym(kw, I_DATA, IN_LEN, I_DATA + 8, 32, w));           \
        CHECK("written over in", INV,                                                    \
              sym(kw, I_DATA, IN_LEN, O_DATA, 32, (uintptr_t *)(void *)(I_DATA + 8)));   \
        CHECK("written over out", INV,                                                   \
              sym(kw, I_DATA, IN_LEN, O_DATA, 32, (uintptr_t *)(void *)(O_DATA + 8)));   \
        CHECK("out over the handle", INV,                                                \
              sym(kw, I_DATA, IN_LEN, (uint8_t *)(void *)kw, 32, w));                    \
        CHECK("written over the handle", INV,                                            \
              sym(kw, I_DATA, IN_LEN, O_DATA, 32, (uintptr_t *)(void *)kw));             \
        CHECK("in over the handle", INV, sym(kw, k, IN_LEN, O_DATA, 32, w));             \
        expect(n, "valid (control)", sym(kw, I_DATA, IN_LEN, O_DATA, 32, w), 0);         \
        return row_done(n);                                                              \
    }

/* An unwrap input of SIZE_MAX / 2 bytes passes the range check and is
 * refused by the length bound of a KWP ciphertext, the wrap of 2^32 - 1
 * bytes, with LengthMismatch = 23 because it is not a multiple of 8. On a
 * 32-bit target SIZE_MAX / 2 is within that bound. */
#if SIZE_MAX > 0xFFFFFFFFu
#define KWP_UNWRAP_BOUNDARY(sym)                                                         \
    CHECK("in length SIZE_MAX / 2", LEN, sym(kw, TOP_HALF_PTR, ISIZE_MAX, O_DATA, 32, w))
#else
#define KWP_UNWRAP_BOUNDARY(sym) ((void)0)
#endif

KWP_ROW(oxi_aes_kwp_wrap, 16, 23, memcpy(I_DATA, KEY, 16))
KWP_ROW(oxi_aes_kwp_wrap_inverse, 16, 23, memcpy(I_DATA, KEY, 16))
KWP_ROW(oxi_aes_kwp_unwrap, 24, 15,
        oxi_aes_kwp_wrap(kw, KEY, 16, I_DATA, 24, w); KWP_UNWRAP_BOUNDARY(oxi_aes_kwp_unwrap))
KWP_ROW(oxi_aes_kwp_unwrap_inverse, 24, 15,
        oxi_aes_kwp_wrap_inverse(kw, KEY, 16, I_DATA, 24, w);
        KWP_UNWRAP_BOUNDARY(oxi_aes_kwp_unwrap_inverse))

static int row_oxi_aes_cmac(void) {
    const char *n = "oxi_aes_cmac";
    const uint8_t *k = (const uint8_t *)(void *)cmac;
    CHECK("NULL handle", NUL, oxi_aes_cmac(NULL, I_DATA, 16, O_DATA));
    CHECK("NULL msg, length 16", NUL, oxi_aes_cmac(cmac, NULL, 16, O_DATA));
    CHECK("NULL mac", NUL, oxi_aes_cmac(cmac, I_DATA, 16, NULL));
    CHECK("msg wraps the address space", INV, oxi_aes_cmac(cmac, WRAP_PTR, 16, O_DATA));
    CHECK("mac wraps the address space", INV, oxi_aes_cmac(cmac, I_DATA, 16, WRAP_PTR));
    CHECK("length SIZE_MAX / 2 + 1", INV, oxi_aes_cmac(cmac, I_DATA, HUGE_LEN, O_DATA));
    CHECK("mac over msg", INV, oxi_aes_cmac(cmac, I_DATA, 16, I_DATA + 8));
    CHECK("mac over the handle", INV, oxi_aes_cmac(cmac, I_DATA, 16, (uint8_t *)(void *)cmac));
    CHECK("msg over the handle", INV, oxi_aes_cmac(cmac, k, 16, O_DATA));
    expect(n, "msg NULL, length 0", oxi_aes_cmac(cmac, NULL, 0, O_DATA), 0);
    expect(n, "valid (control)", oxi_aes_cmac(cmac, I_DATA, 16, O_DATA), 0);
    return row_done(n);
}

static int row_oxi_aes_cmac_verify(void) {
    const char *n = "oxi_aes_cmac_verify";
    const uint8_t *k = (const uint8_t *)(void *)cmac;
    if (oxi_aes_cmac(cmac, I_DATA, 16, I_TAG) != 0 || oxi_aes_cmac(cmac, NULL, 0, I_TAG2) != 0) {
        fprintf(stderr, "%s: setup MAC failed\n", n);
        failures++;
    }
    CHECK("NULL handle", NUL, oxi_aes_cmac_verify(NULL, I_DATA, 16, I_TAG));
    CHECK("NULL msg, length 16", NUL, oxi_aes_cmac_verify(cmac, NULL, 16, I_TAG));
    CHECK("NULL mac", NUL, oxi_aes_cmac_verify(cmac, I_DATA, 16, NULL));
    CHECK("msg wraps the address space", INV, oxi_aes_cmac_verify(cmac, WRAP_PTR, 16, I_TAG));
    CHECK("mac wraps the address space", INV, oxi_aes_cmac_verify(cmac, I_DATA, 16, WRAP_PTR));
    CHECK("length SIZE_MAX / 2 + 1", INV, oxi_aes_cmac_verify(cmac, I_DATA, HUGE_LEN, I_TAG));
    CHECK("msg over the handle", INV, oxi_aes_cmac_verify(cmac, k, 16, I_TAG));
    CHECK("mac over the handle", INV, oxi_aes_cmac_verify(cmac, I_DATA, 16, k));
    CHECK("msg NULL, length 0", 0, oxi_aes_cmac_verify(cmac, NULL, 0, I_TAG2));
    expect(n, "valid (control)", oxi_aes_cmac_verify(cmac, I_DATA, 16, I_TAG), 0);
    return row_done(n);
}

static int (*const ROWS[])(void) = {
    row_oxi_aes_gcm_key_new,
    row_oxi_aes_gcm_key_new_with_count,
    row_oxi_aes_gcm_key_new_with_limit,
    row_oxi_aes_gcm_key_invocations,
    row_oxi_aes_gcm_seal,
    row_oxi_aes_gcm_open,
    row_oxi_aes_ccm_key_new,
    row_oxi_aes_ccm_key_new_with_count,
    row_oxi_aes_ccm_key_invocations,
    row_oxi_aes_ccm_seal,
    row_oxi_aes_ccm_open,
    row_oxi_aes_cbc_key_new,
    row_oxi_aes_cbc_encrypt,
    row_oxi_aes_cbc_decrypt,
    row_oxi_aes_ctr_key_new,
    row_oxi_aes_ctr,
    row_oxi_aes_kw_key_new,
    row_oxi_aes_kw_wrap,
    row_oxi_aes_kw_unwrap,
    row_oxi_aes_kwp_wrap,
    row_oxi_aes_kwp_unwrap,
    row_oxi_aes_kw_wrap_inverse,
    row_oxi_aes_kw_unwrap_inverse,
    row_oxi_aes_kwp_wrap_inverse,
    row_oxi_aes_kwp_unwrap_inverse,
    row_oxi_aes_cmac_key_new,
    row_oxi_aes_cmac,
    row_oxi_aes_cmac_verify,
};

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    if (oxi_hmac_drbg_sha256_new_rbg(&drbg) != 0 || oxi_drbg_instantiate(drbg, NULL, 0) != 0 ||
        oxi_aes_gcm_key_new(KEY, sizeof(KEY), &gcm) != 0 ||
        oxi_aes_ccm_key_new(KEY, sizeof(KEY), 16, &ccm) != 0 ||
        oxi_aes_cbc_key_new(KEY, sizeof(KEY), &cbc) != 0 ||
        oxi_aes_ctr_key_new(KEY, sizeof(KEY), &ctr) != 0 ||
        oxi_aes_kw_key_new(KEY, sizeof(KEY), &kw) != 0 ||
        oxi_aes_cmac_key_new(KEY, sizeof(KEY), 16, &cmac) != 0) {
        fprintf(stderr, "test_buffer_contract: setup failed\n");
        return 1;
    }
    memset(in.b, 0x3C, sizeof(in.b));
    memcpy(I_NONCE, NONCE, sizeof(NONCE));
    int enumerated = 0;
    for (size_t i = 0; i < sizeof(ROWS) / sizeof(ROWS[0]); i++) {
        enumerated += ROWS[i]();
    }
    oxi_aes_gcm_key_free(gcm);
    oxi_aes_ccm_key_free(ccm);
    oxi_aes_cbc_key_free(cbc);
    oxi_aes_ctr_key_free(ctr);
    oxi_aes_kw_key_free(kw);
    oxi_aes_cmac_key_free(cmac);
    oxi_drbg_free(drbg);
    if (failures != 0) {
        fprintf(stderr, "test_buffer_contract: %d checks failed\n", failures);
        return 2;
    }
    printf("test_buffer_contract: OK enumerated=%d\n", enumerated);
    return 0;
}
