/* oxi_drbg_generate accepts additional input up to each DRBG's limit and
 * refuses one byte more with InvalidInput = 5, for each of the nine kinds.
 *
 * The limit is the additional input the DRBG accepts from a module reseed,
 * its input bound less the 32-byte entropy input the module draws: 736
 * bytes for HMAC_DRBG, 680 for Hash_DRBG-SHA-256, 624 for Hash_DRBG-SHA-384
 * and -SHA-512, and 160 for CTR_DRBG.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct kind {
    const char *name;
    int (*new_rbg)(OxiDrbg **);
    uintptr_t limit;
};

static const struct kind KINDS[] = {
    {"HMAC_DRBG-SHA-256", oxi_hmac_drbg_sha256_new_rbg, 736},
    {"HMAC_DRBG-SHA-384", oxi_hmac_drbg_sha384_new_rbg, 736},
    {"HMAC_DRBG-SHA-512", oxi_hmac_drbg_sha512_new_rbg, 736},
    {"Hash_DRBG-SHA-256", oxi_hash_drbg_sha256_new_rbg, 680},
    {"Hash_DRBG-SHA-384", oxi_hash_drbg_sha384_new_rbg, 624},
    {"Hash_DRBG-SHA-512", oxi_hash_drbg_sha512_new_rbg, 624},
    {"CTR_DRBG-AES-128", oxi_ctr_drbg_aes128_new_rbg, 160},
    {"CTR_DRBG-AES-192", oxi_ctr_drbg_aes192_new_rbg, 160},
    {"CTR_DRBG-AES-256", oxi_ctr_drbg_aes256_new_rbg, 160},
};

static uint8_t additional[737];

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    memset(additional, 0x3C, sizeof(additional));
    int failures = 0;
    for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
        const struct kind *k = &KINDS[i];
        OxiDrbg *h = NULL;
        if (k->new_rbg(&h) != 0 || oxi_drbg_instantiate(h, NULL, 0) != 0) {
            fprintf(stderr, "%s: setup failed\n", k->name);
            failures++;
            continue;
        }
        uint8_t out[16];
        int over = oxi_drbg_generate(h, additional, k->limit + 1, out, sizeof(out));
        int at = oxi_drbg_generate(h, additional, k->limit, out, sizeof(out));
        if (over != OXI_RESULT_INVALID_INPUT) {
            fprintf(stderr, "%s: %lu bytes of additional input: rc=%d, expected 5\n", k->name,
                    (unsigned long)(k->limit + 1), over);
            failures++;
        }
        if (at != 0) {
            fprintf(stderr, "%s: %lu bytes of additional input: rc=%d, expected 0\n", k->name,
                    (unsigned long)k->limit, at);
            failures++;
        }
        oxi_drbg_free(h);
    }
    if (failures != 0) {
        fprintf(stderr, "test_drbg_generate_additional_bounds: %d checks failed\n", failures);
        return 2;
    }
    printf("test_drbg_generate_additional_bounds: OK (nine kinds, limit 0, limit + 1 refused 5)\n");
    return 0;
}
