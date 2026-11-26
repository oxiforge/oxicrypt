/* Each key handle carries its mode, and every oxi_aes_* function in
 * oxicrypt.h that takes a key handle refuses a handle of another mode.
 *
 * One row per such function. A row passes the function a handle of
 * another mode and requires InvalidInput = 5 with every output byte
 * unwritten; a _key_free row requires that nothing is freed, so the
 * handle still works in a call of its own mode afterwards. Each row then
 * makes the same call, or that call of the handle's own mode, on a handle
 * of the matching mode, which returns 0.
 *
 * Every refusal runs twice, with the outputs filled 0xA5 and then 0x5A:
 * a written byte equal to one fill cannot equal both.
 *
 * Each row prints kind_row=<function name>. The Makefile compares the
 * sorted list of those names with the oxi_aes_* functions oxicrypt.h
 * declares whose first parameter is a key handle, so a function without a
 * row, a row run twice or a row for a function the header does not
 * declare fails the run.
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
static const uint8_t NONCE[13] = { 0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39 };
static const uint8_t BLOCK16[16] = { 0xf0, 0xf1, 0xf2, 0xf3 };
static const uint8_t PT[32] = { 0xd1, 0x5f, 0x98, 0xf2 };

static const uint8_t FILLS[2] = { 0xA5, 0x5A };

/* Every output of the calls below points into `out`; the union keeps the
 * count of a _key_invocations and the `written` of a KWP call aligned. */
static union {
    uint8_t b[64];
    uint64_t q[8];
    uintptr_t w[64 / sizeof(uintptr_t)];
} out;

#define O_DATA (out.b)
#define O_DATA_CAP ((uintptr_t)32)
#define O_TAG (out.b + 32)
#define O_IV (out.b + 48)
#define O_COUNT (&out.q[6])
#define O_WRITTEN (&out.w[56 / sizeof(uintptr_t)])

static int failures;

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "test_key_handle_kind_checked, %s: rc=%d, expected %d\n", check, rc,
                want);
        failures++;
    }
}

static void expect_unwritten(const char *check, uint8_t fill) {
    for (size_t i = 0; i < sizeof(out.b); i++) {
        if (out.b[i] != fill) {
            fprintf(stderr, "test_key_handle_kind_checked, %s (fill 0x%02X): byte %zu written\n",
                    check, fill, i);
            failures++;
            return;
        }
    }
}

/* A function returning int: `foreign` passes it a handle of another mode,
 * `control` the same call on a handle of its own mode. */
#define ROW(name, foreign, control)                                                      \
    do {                                                                                 \
        printf("kind_row=%s\n", name);                                                   \
        for (size_t f_ = 0; f_ < sizeof(FILLS); f_++) {                                  \
            memset(out.b, FILLS[f_], sizeof(out.b));                                     \
            expect(name " given a handle of another mode", (foreign),                    \
                   OXI_RESULT_INVALID_INPUT);                                            \
            expect_unwritten(name " given a handle of another mode", FILLS[f_]);         \
        }                                                                                \
        expect(name " (control)", (control), 0);                                         \
    } while (0)

/* A _key_free: `foreign` frees a handle of another mode, `still_live` is a
 * call of that handle's own mode, which must still succeed. */
#define FREE_ROW(name, foreign, still_live)                                              \
    do {                                                                                 \
        printf("kind_row=%s\n", name);                                                   \
        for (size_t f_ = 0; f_ < sizeof(FILLS); f_++) {                                  \
            memset(out.b, FILLS[f_], sizeof(out.b));                                     \
            foreign;                                                                     \
            expect_unwritten(name " given a handle of another mode", FILLS[f_]);         \
        }                                                                                \
        expect(name " left the handle of another mode live", (still_live), 0);           \
    } while (0)

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiDrbg *drbg = NULL;
    OxiAesGcmKey *gcm = NULL;
    OxiAesCcmKey *ccm = NULL;
    OxiAesCbcKey *cbc = NULL;
    OxiAesCtrKey *ctr = NULL;
    OxiAesKwKey *kw = NULL;
    OxiAesCmacKey *cmac = NULL;
    uint8_t gcm_ct[32], gcm_iv[12], gcm_tag[16], ccm_ct[32], ccm_tag[16], cmac_mac[16];
    uint8_t kw_ct[24], kwi_ct[24], kwp_ct[24], kwpi_ct[24];
    uintptr_t kwp_len = 0, kwpi_len = 0;
    if (oxi_hmac_drbg_sha256_new_rbg(&drbg) != 0 || oxi_drbg_instantiate(drbg, NULL, 0) != 0 ||
        oxi_aes_gcm_key_new(KEY, sizeof(KEY), &gcm) != 0 ||
        oxi_aes_ccm_key_new(KEY, sizeof(KEY), 16, &ccm) != 0 ||
        oxi_aes_cbc_key_new(KEY, sizeof(KEY), &cbc) != 0 ||
        oxi_aes_ctr_key_new(KEY, sizeof(KEY), &ctr) != 0 ||
        oxi_aes_kw_key_new(KEY, sizeof(KEY), &kw) != 0 ||
        oxi_aes_cmac_key_new(KEY, sizeof(KEY), 16, &cmac) != 0 ||
        oxi_aes_gcm_seal(gcm, drbg, NULL, 0, PT, sizeof(PT), gcm_ct, gcm_iv, gcm_tag) != 0 ||
        oxi_aes_ccm_seal(ccm, NONCE, sizeof(NONCE), NULL, 0, PT, sizeof(PT), ccm_ct, ccm_tag) !=
            0 ||
        oxi_aes_cmac(cmac, PT, sizeof(PT), cmac_mac) != 0 ||
        oxi_aes_kw_wrap(kw, PT, 16, kw_ct) != 0 ||
        oxi_aes_kw_wrap_inverse(kw, PT, 16, kwi_ct) != 0 ||
        oxi_aes_kwp_wrap(kw, PT, 16, kwp_ct, sizeof(kwp_ct), &kwp_len) != 0 ||
        oxi_aes_kwp_wrap_inverse(kw, PT, 16, kwpi_ct, sizeof(kwpi_ct), &kwpi_len) != 0 ||
        kwp_len != sizeof(kwp_ct) || kwpi_len != sizeof(kwpi_ct)) {
        fprintf(stderr, "test_key_handle_kind_checked: setup failed\n");
        return 1;
    }

    /* GCM */
    ROW("oxi_aes_gcm_key_invocations",
        oxi_aes_gcm_key_invocations((const OxiAesGcmKey *)cbc, O_COUNT),
        oxi_aes_gcm_key_invocations(gcm, O_COUNT));
    ROW("oxi_aes_gcm_seal",
        oxi_aes_gcm_seal((const OxiAesGcmKey *)ctr, drbg, NULL, 0, PT, sizeof(PT), O_DATA, O_IV,
                         O_TAG),
        oxi_aes_gcm_seal(gcm, drbg, NULL, 0, PT, sizeof(PT), O_DATA, O_IV, O_TAG));
    ROW("oxi_aes_gcm_open",
        oxi_aes_gcm_open((const OxiAesGcmKey *)ccm, gcm_iv, NULL, 0, gcm_ct, sizeof(gcm_ct),
                         gcm_tag, O_DATA),
        oxi_aes_gcm_open(gcm, gcm_iv, NULL, 0, gcm_ct, sizeof(gcm_ct), gcm_tag, O_DATA));
    FREE_ROW("oxi_aes_gcm_key_free", oxi_aes_gcm_key_free((OxiAesGcmKey *)ccm),
             oxi_aes_ccm_key_invocations(ccm, O_COUNT));

    /* CCM */
    ROW("oxi_aes_ccm_key_invocations",
        oxi_aes_ccm_key_invocations((const OxiAesCcmKey *)gcm, O_COUNT),
        oxi_aes_ccm_key_invocations(ccm, O_COUNT));
    ROW("oxi_aes_ccm_seal",
        oxi_aes_ccm_seal((const OxiAesCcmKey *)gcm, NONCE, sizeof(NONCE), NULL, 0, PT,
                         sizeof(PT), O_DATA, O_TAG),
        oxi_aes_ccm_seal(ccm, NONCE, sizeof(NONCE), NULL, 0, PT, sizeof(PT), O_DATA, O_TAG));
    ROW("oxi_aes_ccm_open",
        oxi_aes_ccm_open((const OxiAesCcmKey *)kw, NONCE, sizeof(NONCE), NULL, 0, ccm_ct,
                         sizeof(ccm_ct), ccm_tag, O_DATA),
        oxi_aes_ccm_open(ccm, NONCE, sizeof(NONCE), NULL, 0, ccm_ct, sizeof(ccm_ct), ccm_tag,
                         O_DATA));
    FREE_ROW("oxi_aes_ccm_key_free", oxi_aes_ccm_key_free((OxiAesCcmKey *)gcm),
             oxi_aes_gcm_key_invocations(gcm, O_COUNT));

    /* CBC */
    ROW("oxi_aes_cbc_encrypt",
        oxi_aes_cbc_encrypt((const OxiAesCbcKey *)ctr, BLOCK16, PT, sizeof(PT), O_DATA),
        oxi_aes_cbc_encrypt(cbc, BLOCK16, PT, sizeof(PT), O_DATA));
    ROW("oxi_aes_cbc_decrypt",
        oxi_aes_cbc_decrypt((const OxiAesCbcKey *)gcm, BLOCK16, PT, sizeof(PT), O_DATA),
        oxi_aes_cbc_decrypt(cbc, BLOCK16, PT, sizeof(PT), O_DATA));
    FREE_ROW("oxi_aes_cbc_key_free", oxi_aes_cbc_key_free((OxiAesCbcKey *)ctr),
             oxi_aes_ctr(ctr, BLOCK16, PT, sizeof(PT), O_DATA));

    /* CTR */
    ROW("oxi_aes_ctr", oxi_aes_ctr((const OxiAesCtrKey *)cbc, BLOCK16, PT, sizeof(PT), O_DATA),
        oxi_aes_ctr(ctr, BLOCK16, PT, sizeof(PT), O_DATA));
    FREE_ROW("oxi_aes_ctr_key_free", oxi_aes_ctr_key_free((OxiAesCtrKey *)cbc),
             oxi_aes_cbc_encrypt(cbc, BLOCK16, PT, sizeof(PT), O_DATA));

    /* KW and KWP, forward and inverse cipher */
    ROW("oxi_aes_kw_wrap", oxi_aes_kw_wrap((const OxiAesKwKey *)cmac, PT, 16, O_DATA),
        oxi_aes_kw_wrap(kw, PT, 16, O_DATA));
    ROW("oxi_aes_kw_unwrap",
        oxi_aes_kw_unwrap((const OxiAesKwKey *)ccm, kw_ct, sizeof(kw_ct), O_DATA),
        oxi_aes_kw_unwrap(kw, kw_ct, sizeof(kw_ct), O_DATA));
    ROW("oxi_aes_kwp_wrap",
        oxi_aes_kwp_wrap((const OxiAesKwKey *)gcm, PT, 16, O_DATA, O_DATA_CAP, O_WRITTEN),
        oxi_aes_kwp_wrap(kw, PT, 16, O_DATA, O_DATA_CAP, O_WRITTEN));
    ROW("oxi_aes_kwp_unwrap",
        oxi_aes_kwp_unwrap((const OxiAesKwKey *)cbc, kwp_ct, sizeof(kwp_ct), O_DATA, O_DATA_CAP,
                           O_WRITTEN),
        oxi_aes_kwp_unwrap(kw, kwp_ct, sizeof(kwp_ct), O_DATA, O_DATA_CAP, O_WRITTEN));
    ROW("oxi_aes_kw_wrap_inverse",
        oxi_aes_kw_wrap_inverse((const OxiAesKwKey *)ctr, PT, 16, O_DATA),
        oxi_aes_kw_wrap_inverse(kw, PT, 16, O_DATA));
    ROW("oxi_aes_kw_unwrap_inverse",
        oxi_aes_kw_unwrap_inverse((const OxiAesKwKey *)cmac, kwi_ct, sizeof(kwi_ct), O_DATA),
        oxi_aes_kw_unwrap_inverse(kw, kwi_ct, sizeof(kwi_ct), O_DATA));
    ROW("oxi_aes_kwp_wrap_inverse",
        oxi_aes_kwp_wrap_inverse((const OxiAesKwKey *)ccm, PT, 16, O_DATA, O_DATA_CAP,
                                 O_WRITTEN),
        oxi_aes_kwp_wrap_inverse(kw, PT, 16, O_DATA, O_DATA_CAP, O_WRITTEN));
    ROW("oxi_aes_kwp_unwrap_inverse",
        oxi_aes_kwp_unwrap_inverse((const OxiAesKwKey *)gcm, kwpi_ct, sizeof(kwpi_ct), O_DATA,
                                   O_DATA_CAP, O_WRITTEN),
        oxi_aes_kwp_unwrap_inverse(kw, kwpi_ct, sizeof(kwpi_ct), O_DATA, O_DATA_CAP,
                                   O_WRITTEN));
    FREE_ROW("oxi_aes_kw_key_free", oxi_aes_kw_key_free((OxiAesKwKey *)cmac),
             oxi_aes_cmac(cmac, PT, sizeof(PT), O_TAG));

    /* CMAC */
    ROW("oxi_aes_cmac", oxi_aes_cmac((const OxiAesCmacKey *)kw, PT, sizeof(PT), O_TAG),
        oxi_aes_cmac(cmac, PT, sizeof(PT), O_TAG));
    ROW("oxi_aes_cmac_verify",
        oxi_aes_cmac_verify((const OxiAesCmacKey *)gcm, PT, sizeof(PT), cmac_mac),
        oxi_aes_cmac_verify(cmac, PT, sizeof(PT), cmac_mac));
    FREE_ROW("oxi_aes_cmac_key_free", oxi_aes_cmac_key_free((OxiAesCmacKey *)kw),
             oxi_aes_kw_wrap(kw, PT, 16, O_DATA));

    oxi_aes_gcm_key_free(gcm);
    oxi_aes_ccm_key_free(ccm);
    oxi_aes_cbc_key_free(cbc);
    oxi_aes_ctr_key_free(ctr);
    oxi_aes_kw_key_free(kw);
    oxi_aes_cmac_key_free(cmac);
    oxi_drbg_free(drbg);
    if (failures != 0) {
        fprintf(stderr, "test_key_handle_kind_checked: %d checks failed\n", failures);
        return 2;
    }
    printf("test_key_handle_kind_checked: OK\n");
    return 0;
}
