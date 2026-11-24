/* Pointer and length contract of every DRBG symbol in oxicrypt.h.
 *
 * Runs against a library built with the fault-injection feature.
 *
 * The table below names, by hand, each function in oxicrypt.h whose name
 * contains "drbg" and that returns int: the nine typed _new, the eighteen
 * typed _instantiate_from_module and _reseed_from_module, the nine typed
 * _generate, the nine _new_rbg and the four oxi_drbg_* functions. Each row
 * runs the refusals that apply to its signature:
 *
 *   - a NULL handle, or a NULL required output, returns NullPointer = 10;
 *   - a NULL optional input with a non-zero length returns
 *     InvalidInput = 5, except the typed _generate, whose header documents
 *     NullPointer = 10 for a NULL additional input;
 *   - an input length above SIZE_MAX / 2 returns InvalidInput = 5;
 *   - a typed _generate output length above 65536, the largest request,
 *     returns OutputTooLong = 12 before any allocation of that length;
 *   - oxi_drbg_generate with `out` and `additional` the same buffer
 *     returns InvalidInput = 5.
 *
 * The success line prints the row count as enumerated=<n>. The Makefile
 * compares it with the number of such functions declared in oxicrypt.h, so
 * a DRBG symbol added to the header without a row here fails the run.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HUGE_LEN ((uintptr_t)(SIZE_MAX / 2 + 1))

static uint8_t buf[64];
static int failures;

static void expect(const char *name, const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "%s, %s: rc=%d, expected %d\n", name, check, rc, want);
        failures++;
    }
}

/* One typed DRBG kind: its _new, _instantiate_from_module,
 * _reseed_from_module and _generate, run on an instantiated handle. */
#define TYPED_ROWS(prefix, type, gen)                                                    \
    static int row_##prefix##_new(void) {                                                \
        expect("oxi_" #prefix "_new", "NULL out", oxi_##prefix##_new(NULL),              \
               OXI_RESULT_NULL_POINTER);                                                 \
        return 1;                                                                        \
    }                                                                                    \
    static type *handle_##prefix(void) {                                                 \
        type *h = NULL;                                                                  \
        if (oxi_##prefix##_new(&h) != 0 ||                                               \
            oxi_##prefix##_instantiate_from_module(h, NULL, 0) != 0) {                   \
            fprintf(stderr, "oxi_" #prefix ": setup failed\n");                          \
            failures++;                                                                  \
        }                                                                                \
        return h;                                                                        \
    }                                                                                    \
    static int row_##prefix##_instantiate(void) {                                        \
        const char *n = "oxi_" #prefix "_instantiate_from_module";                       \
        type *h = handle_##prefix();                                                     \
        expect(n, "NULL handle", oxi_##prefix##_instantiate_from_module(NULL, NULL, 0),  \
               OXI_RESULT_NULL_POINTER);                                                 \
        expect(n, "NULL perso, length 1",                                                \
               oxi_##prefix##_instantiate_from_module(h, NULL, 1),                       \
               OXI_RESULT_INVALID_INPUT);                                                \
        expect(n, "huge perso length",                                                   \
               oxi_##prefix##_instantiate_from_module(h, buf, HUGE_LEN),                 \
               OXI_RESULT_INVALID_INPUT);                                                \
        oxi_##prefix##_free(h);                                                          \
        return 1;                                                                        \
    }                                                                                    \
    static int row_##prefix##_reseed(void) {                                             \
        const char *n = "oxi_" #prefix "_reseed_from_module";                            \
        type *h = handle_##prefix();                                                     \
        expect(n, "NULL handle", oxi_##prefix##_reseed_from_module(NULL, NULL, 0),       \
               OXI_RESULT_NULL_POINTER);                                                 \
        expect(n, "NULL additional, length 1",                                           \
               oxi_##prefix##_reseed_from_module(h, NULL, 1), OXI_RESULT_INVALID_INPUT); \
        expect(n, "huge additional length",                                              \
               oxi_##prefix##_reseed_from_module(h, buf, HUGE_LEN),                      \
               OXI_RESULT_INVALID_INPUT);                                                \
        oxi_##prefix##_free(h);                                                          \
        return 1;                                                                        \
    }                                                                                    \
    static int row_##prefix##_generate(void) {                                           \
        const char *n = "oxi_" #prefix "_" #gen;                                         \
        type *h = handle_##prefix();                                                     \
        expect(n, "NULL handle", oxi_##prefix##_##gen(NULL, NULL, 0, buf, 16),           \
               OXI_RESULT_NULL_POINTER);                                                 \
        expect(n, "NULL out", oxi_##prefix##_##gen(h, NULL, 0, NULL, 16),                \
               OXI_RESULT_NULL_POINTER);                                                 \
        expect(n, "NULL additional, length 1", oxi_##prefix##_##gen(h, NULL, 1, buf, 16), \
               OXI_RESULT_NULL_POINTER);                                                 \
        expect(n, "huge additional length", oxi_##prefix##_##gen(h, buf, HUGE_LEN, buf, 16), \
               OXI_RESULT_INVALID_INPUT);                                                \
        expect(n, "out length 65537", oxi_##prefix##_##gen(h, NULL, 0, buf, 65537),     \
               OXI_RESULT_OUTPUT_TOO_LONG);                                              \
        expect(n, "huge out length", oxi_##prefix##_##gen(h, NULL, 0, buf, HUGE_LEN),   \
               OXI_RESULT_OUTPUT_TOO_LONG);                                              \
        oxi_##prefix##_free(h);                                                          \
        return 1;                                                                        \
    }

TYPED_ROWS(hmac_drbg_sha256, OxiHmacDrbgSha256, generate)
TYPED_ROWS(hmac_drbg_sha384, OxiHmacDrbgSha384, generate)
TYPED_ROWS(hmac_drbg_sha512, OxiHmacDrbgSha512, generate)
TYPED_ROWS(hash_drbg_sha256, OxiHashDrbgSha256, generate)
TYPED_ROWS(hash_drbg_sha384, OxiHashDrbgSha384, generate)
TYPED_ROWS(hash_drbg_sha512, OxiHashDrbgSha512, generate)
TYPED_ROWS(ctr_drbg_aes128, OxiCtrDrbgAes128, generate_df)
TYPED_ROWS(ctr_drbg_aes192, OxiCtrDrbgAes192, generate_df)
TYPED_ROWS(ctr_drbg_aes256, OxiCtrDrbgAes256, generate_df)

#define NEW_RBG_ROW(prefix)                                                              \
    static int row_##prefix##_new_rbg(void) {                                            \
        expect("oxi_" #prefix "_new_rbg", "NULL out", oxi_##prefix##_new_rbg(NULL),      \
               OXI_RESULT_NULL_POINTER);                                                 \
        return 1;                                                                        \
    }

NEW_RBG_ROW(hmac_drbg_sha256)
NEW_RBG_ROW(hmac_drbg_sha384)
NEW_RBG_ROW(hmac_drbg_sha512)
NEW_RBG_ROW(hash_drbg_sha256)
NEW_RBG_ROW(hash_drbg_sha384)
NEW_RBG_ROW(hash_drbg_sha512)
NEW_RBG_ROW(ctr_drbg_aes128)
NEW_RBG_ROW(ctr_drbg_aes192)
NEW_RBG_ROW(ctr_drbg_aes256)

static OxiDrbg *shared_handle(void) {
    OxiDrbg *h = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&h) != 0 || oxi_drbg_instantiate(h, NULL, 0) != 0) {
        fprintf(stderr, "OxiDrbg setup failed\n");
        failures++;
    }
    return h;
}

static int row_drbg_instantiate(void) {
    const char *n = "oxi_drbg_instantiate";
    OxiDrbg *h = shared_handle();
    expect(n, "NULL handle", oxi_drbg_instantiate(NULL, NULL, 0), OXI_RESULT_NULL_POINTER);
    expect(n, "NULL perso, length 1", oxi_drbg_instantiate(h, NULL, 1),
           OXI_RESULT_INVALID_INPUT);
    expect(n, "huge perso length", oxi_drbg_instantiate(h, buf, HUGE_LEN),
           OXI_RESULT_INVALID_INPUT);
    oxi_drbg_free(h);
    return 1;
}

static int row_drbg_reseed(void) {
    const char *n = "oxi_drbg_reseed";
    OxiDrbg *h = shared_handle();
    expect(n, "NULL handle", oxi_drbg_reseed(NULL, NULL, 0), OXI_RESULT_NULL_POINTER);
    expect(n, "NULL additional, length 1", oxi_drbg_reseed(h, NULL, 1),
           OXI_RESULT_INVALID_INPUT);
    expect(n, "huge additional length", oxi_drbg_reseed(h, buf, HUGE_LEN),
           OXI_RESULT_INVALID_INPUT);
    oxi_drbg_free(h);
    return 1;
}

static int row_drbg_generate(void) {
    const char *n = "oxi_drbg_generate";
    OxiDrbg *h = shared_handle();
    expect(n, "NULL handle", oxi_drbg_generate(NULL, NULL, 0, buf, 16),
           OXI_RESULT_NULL_POINTER);
    expect(n, "NULL out", oxi_drbg_generate(h, NULL, 0, NULL, 16), OXI_RESULT_NULL_POINTER);
    expect(n, "NULL additional, length 1", oxi_drbg_generate(h, NULL, 1, buf, 16),
           OXI_RESULT_INVALID_INPUT);
    expect(n, "huge additional length", oxi_drbg_generate(h, buf + 32, HUGE_LEN, buf, 16),
           OXI_RESULT_INVALID_INPUT);
    expect(n, "huge out length", oxi_drbg_generate(h, NULL, 0, buf, HUGE_LEN),
           OXI_RESULT_INVALID_INPUT);
    expect(n, "out is additional", oxi_drbg_generate(h, buf, 16, buf, 16),
           OXI_RESULT_INVALID_INPUT);
    /* Control: the same call with separate buffers succeeds. */
    expect(n, "separate buffers (control)", oxi_drbg_generate(h, buf + 32, 16, buf, 16), 0);
    oxi_drbg_free(h);
    return 1;
}

static int row_drbg_strength_bits(void) {
    const char *n = "oxi_drbg_strength_bits";
    OxiDrbg *h = shared_handle();
    uint32_t bits = 0;
    expect(n, "NULL handle", oxi_drbg_strength_bits(NULL, &bits), OXI_RESULT_NULL_POINTER);
    expect(n, "NULL out", oxi_drbg_strength_bits(h, NULL), OXI_RESULT_NULL_POINTER);
    oxi_drbg_free(h);
    return 1;
}

#define TYPED_TABLE(prefix)                                                              \
    row_##prefix##_new, row_##prefix##_instantiate, row_##prefix##_reseed,               \
        row_##prefix##_generate

static int (*const ROWS[])(void) = {
    TYPED_TABLE(hmac_drbg_sha256),
    TYPED_TABLE(hmac_drbg_sha384),
    TYPED_TABLE(hmac_drbg_sha512),
    TYPED_TABLE(hash_drbg_sha256),
    TYPED_TABLE(hash_drbg_sha384),
    TYPED_TABLE(hash_drbg_sha512),
    TYPED_TABLE(ctr_drbg_aes128),
    TYPED_TABLE(ctr_drbg_aes192),
    TYPED_TABLE(ctr_drbg_aes256),
    row_hmac_drbg_sha256_new_rbg,
    row_hmac_drbg_sha384_new_rbg,
    row_hmac_drbg_sha512_new_rbg,
    row_hash_drbg_sha256_new_rbg,
    row_hash_drbg_sha384_new_rbg,
    row_hash_drbg_sha512_new_rbg,
    row_ctr_drbg_aes128_new_rbg,
    row_ctr_drbg_aes192_new_rbg,
    row_ctr_drbg_aes256_new_rbg,
    row_drbg_instantiate,
    row_drbg_reseed,
    row_drbg_generate,
    row_drbg_strength_bits,
};

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    memset(buf, 0x5A, sizeof(buf));
    int enumerated = 0;
    for (size_t i = 0; i < sizeof(ROWS) / sizeof(ROWS[0]); i++) {
        enumerated += ROWS[i]();
    }
    if (failures != 0) {
        fprintf(stderr, "test_drbg_buffer_contract: %d checks failed\n", failures);
        return 2;
    }
    printf("test_drbg_buffer_contract: OK enumerated=%d\n", enumerated);
    return 0;
}
