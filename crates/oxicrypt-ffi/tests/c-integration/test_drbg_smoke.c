/* SP 800-90A DRBG C ABI smoke test — one representative per family.
 *
 * Exercises the caller lifecycle
 *   _new → _instantiate_from_module → _generate → _reseed_from_module
 *        → _generate → _free
 * for one typed DRBG handle from each of the three families:
 *
 *   - HMAC_DRBG-SHA-256  (SP 800-90A §10.1.2)
 *   - Hash_DRBG-SHA-256  (SP 800-90A §10.1.1)
 *   - CTR_DRBG-AES-256   (SP 800-90A §10.2.1, derivation-function form)
 *
 * and one round trip of the shared OxiDrbg handle through
 * oxi_hmac_drbg_sha256_new_rbg and the oxi_drbg_* functions.
 *
 * Every handle is seeded by the module: the caller supplies no entropy,
 * only an optional personalization string. Every rc is asserted == 0;
 * after the first generate the output buffer is asserted non-trivial
 * (not all-zero). Distinct return codes per failure keep a failure
 * diagnosable from the process exit code alone.
 *
 * Negative checks: generate on a handle never instantiated returns
 * OxiResult::Uninstantiated = 8, and generate on a NULL handle returns
 * OxiResult::NullPointer = 10. Neither passes a NULL out-pointer with a
 * non-zero length.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DRBG_OUT_LEN     64

#define OXI_UNINSTANTIATED 8 /* OxiResult::Uninstantiated */
#define OXI_NULL_POINTER 10  /* OxiResult::NullPointer    */

static const uint8_t PERSO[] = "test_drbg_smoke";

/* Returns 1 if buf is entirely zero (trivial/uninitialized output). */
static int all_zero(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }

    uint8_t out[DRBG_OUT_LEN];
    int rc;

    /* ---- HMAC_DRBG-SHA-256 (return codes 10-19) ---- */
    {
        OxiHmacDrbgSha256 *drbg = NULL;
        rc = oxi_hmac_drbg_sha256_new(&drbg);
        if (rc != 0 || drbg == NULL) {
            fprintf(stderr, "hmac_drbg_sha256_new failed: rc=%d\n", rc);
            return 10;
        }

        /* Negative: generate before instantiation → Uninstantiated = 8. */
        rc = oxi_hmac_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != OXI_UNINSTANTIATED) {
            fprintf(stderr, "hmac_drbg_sha256_generate(uninstantiated) rc=%d (expected %d)\n",
                    rc, OXI_UNINSTANTIATED);
            return 17;
        }

        rc = oxi_hmac_drbg_sha256_instantiate_from_module(drbg, PERSO, sizeof(PERSO) - 1);
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_instantiate_from_module failed: rc=%d\n", rc);
            return 11;
        }
        memset(out, 0, sizeof(out));
        rc = oxi_hmac_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_generate(1) failed: rc=%d\n", rc);
            return 12;
        }
        if (all_zero(out, sizeof(out))) {
            fprintf(stderr, "hmac_drbg_sha256_generate(1) produced all-zero output\n");
            return 13;
        }
        rc = oxi_hmac_drbg_sha256_reseed_from_module(drbg, NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_reseed_from_module failed: rc=%d\n", rc);
            return 14;
        }
        rc = oxi_hmac_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_generate(2) failed: rc=%d\n", rc);
            return 15;
        }

        /* Negative: NULL handle to generate → NullPointer = 10. */
        rc = oxi_hmac_drbg_sha256_generate(NULL, NULL, 0, out, sizeof(out));
        if (rc != OXI_NULL_POINTER) {
            fprintf(stderr, "hmac_drbg_sha256_generate(NULL) rc=%d (expected %d NullPointer)\n",
                    rc, OXI_NULL_POINTER);
            return 16;
        }

        oxi_hmac_drbg_sha256_free(drbg);
    }

    /* ---- Hash_DRBG-SHA-256 (return codes 20-29) ---- */
    {
        OxiHashDrbgSha256 *drbg = NULL;
        rc = oxi_hash_drbg_sha256_new(&drbg);
        if (rc != 0 || drbg == NULL) {
            fprintf(stderr, "hash_drbg_sha256_new failed: rc=%d\n", rc);
            return 20;
        }
        rc = oxi_hash_drbg_sha256_instantiate_from_module(drbg, PERSO, sizeof(PERSO) - 1);
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_instantiate_from_module failed: rc=%d\n", rc);
            return 21;
        }
        memset(out, 0, sizeof(out));
        rc = oxi_hash_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_generate(1) failed: rc=%d\n", rc);
            return 22;
        }
        if (all_zero(out, sizeof(out))) {
            fprintf(stderr, "hash_drbg_sha256_generate(1) produced all-zero output\n");
            return 23;
        }
        rc = oxi_hash_drbg_sha256_reseed_from_module(drbg, NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_reseed_from_module failed: rc=%d\n", rc);
            return 24;
        }
        rc = oxi_hash_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_generate(2) failed: rc=%d\n", rc);
            return 25;
        }
        oxi_hash_drbg_sha256_free(drbg);
    }

    /* ---- CTR_DRBG-AES-256 (df form) (return codes 30-39) ---- */
    {
        OxiCtrDrbgAes256 *drbg = NULL;
        rc = oxi_ctr_drbg_aes256_new(&drbg);
        if (rc != 0 || drbg == NULL) {
            fprintf(stderr, "ctr_drbg_aes256_new failed: rc=%d\n", rc);
            return 30;
        }
        rc = oxi_ctr_drbg_aes256_instantiate_from_module(drbg, PERSO, sizeof(PERSO) - 1);
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_instantiate_from_module failed: rc=%d\n", rc);
            return 31;
        }
        memset(out, 0, sizeof(out));
        rc = oxi_ctr_drbg_aes256_generate_df(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_generate_df(1) failed: rc=%d\n", rc);
            return 32;
        }
        if (all_zero(out, sizeof(out))) {
            fprintf(stderr, "ctr_drbg_aes256_generate_df(1) produced all-zero output\n");
            return 33;
        }
        rc = oxi_ctr_drbg_aes256_reseed_from_module(drbg, NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_reseed_from_module failed: rc=%d\n", rc);
            return 34;
        }
        rc = oxi_ctr_drbg_aes256_generate_df(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_generate_df(2) failed: rc=%d\n", rc);
            return 35;
        }
        oxi_ctr_drbg_aes256_free(drbg);
    }

    /* ---- Shared OxiDrbg handle, HMAC_DRBG-SHA-256 (return codes 40-49) ---- */
    {
        OxiDrbg *drbg = NULL;
        rc = oxi_hmac_drbg_sha256_new_rbg(&drbg);
        if (rc != 0 || drbg == NULL) {
            fprintf(stderr, "hmac_drbg_sha256_new_rbg failed: rc=%d\n", rc);
            return 40;
        }
        rc = oxi_drbg_instantiate(drbg, PERSO, sizeof(PERSO) - 1);
        if (rc != 0) {
            fprintf(stderr, "drbg_instantiate failed: rc=%d\n", rc);
            return 41;
        }
        memset(out, 0, sizeof(out));
        rc = oxi_drbg_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "drbg_generate failed: rc=%d\n", rc);
            return 42;
        }
        if (all_zero(out, sizeof(out))) {
            fprintf(stderr, "drbg_generate produced all-zero output\n");
            return 43;
        }
        oxi_drbg_free(drbg);
    }

    printf("test_drbg_smoke: OK (HMAC/Hash/CTR new+instantiate_from_module+generate+"
           "reseed_from_module+generate+free; shared OxiDrbg round trip; non-trivial output; "
           "uninstantiated rejects with 8, NULL handle with 10)\n");
    return 0;
}
