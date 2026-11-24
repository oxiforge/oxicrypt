/* _reseed_from_module and _generate on a typed handle never instantiated
 * return Uninstantiated = 8, for each of the nine typed DRBGs.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>

#define EXPECTED OXI_RESULT_UNINSTANTIATED

static int failures;

#define CHECK_KIND(prefix, type, gen)                                                  \
    do {                                                                               \
        type *h = NULL;                                                                \
        uint8_t out[16];                                                               \
        if (oxi_##prefix##_new(&h) != 0) {                                             \
            fprintf(stderr, "oxi_" #prefix "_new failed\n");                           \
            failures++;                                                                \
            break;                                                                     \
        }                                                                              \
        int rc = oxi_##prefix##_reseed_from_module(h, NULL, 0);                        \
        if (rc != EXPECTED) {                                                          \
            fprintf(stderr, "oxi_" #prefix "_reseed_from_module: rc=%d, expected %d\n", \
                    rc, EXPECTED);                                                     \
            failures++;                                                                \
        }                                                                              \
        rc = oxi_##prefix##_##gen(h, NULL, 0, out, sizeof(out));                       \
        if (rc != EXPECTED) {                                                          \
            fprintf(stderr, "oxi_" #prefix "_" #gen ": rc=%d, expected %d\n", rc,      \
                    EXPECTED);                                                         \
            failures++;                                                                \
        }                                                                              \
        oxi_##prefix##_free(h);                                                        \
    } while (0)

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    CHECK_KIND(hmac_drbg_sha256, OxiHmacDrbgSha256, generate);
    CHECK_KIND(hmac_drbg_sha384, OxiHmacDrbgSha384, generate);
    CHECK_KIND(hmac_drbg_sha512, OxiHmacDrbgSha512, generate);
    CHECK_KIND(hash_drbg_sha256, OxiHashDrbgSha256, generate);
    CHECK_KIND(hash_drbg_sha384, OxiHashDrbgSha384, generate);
    CHECK_KIND(hash_drbg_sha512, OxiHashDrbgSha512, generate);
    CHECK_KIND(ctr_drbg_aes128, OxiCtrDrbgAes128, generate_df);
    CHECK_KIND(ctr_drbg_aes192, OxiCtrDrbgAes192, generate_df);
    CHECK_KIND(ctr_drbg_aes256, OxiCtrDrbgAes256, generate_df);
    if (failures != 0) {
        fprintf(stderr, "test_typed_uninstantiated_codes: %d checks failed\n", failures);
        return 2;
    }
    printf("test_typed_uninstantiated_codes: OK (nine kinds, reseed and generate return 8)\n");
    return 0;
}
