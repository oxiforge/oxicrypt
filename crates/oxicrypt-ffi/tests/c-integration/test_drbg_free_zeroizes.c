/* oxi_drbg_free and every typed DRBG _free wipe every byte of the handle
 * before releasing it.
 *
 * Runs against a library built with the fault-injection feature, which
 * records whether the last freed handle read as all zero after its wipe and
 * before its memory was released, and clears the record when it is read.
 * One handle of each of the nine typed kinds and one OxiDrbg is
 * instantiated, used and freed, and the record is read after every free, so
 * a _free that releases its handle without the wipe reads -1, not 1.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <stdint.h>
#include <stdio.h>

/* Returns 0 when the record reads 1 after the free just made. */
static int expect_wiped(const char *name) {
    int zero = oxi_test_last_freed_bytes_zero();
    if (zero != 1) {
        fprintf(stderr, "freed %s handle read as all zero: %d, expected 1\n", name, zero);
        return 1;
    }
    if (oxi_test_last_freed_bytes_zero() != -1) {
        fprintf(stderr, "reading the record after %s did not clear it\n", name);
        return 1;
    }
    return 0;
}

/* Constructs, instantiates and generates from one typed handle, frees it
 * and checks the record, counting a handle not wiped in `failed`. A setup
 * failure returns 3 from main. */
#define TYPED_CASE(type, prefix, gen)                                                   \
    do {                                                                                \
        type *t = NULL;                                                                 \
        uint8_t t_out[32] = {0};                                                        \
        if (prefix##_new(&t) != 0 || prefix##_instantiate_from_module(t, NULL, 0) != 0 || \
            prefix##gen(t, NULL, 0, t_out, sizeof(t_out)) != 0) {                       \
            fprintf(stderr, "%s setup failed\n", #prefix);                             \
            return 3;                                                                   \
        }                                                                               \
        prefix##_free(t);                                                               \
        failed += expect_wiped(#prefix);                                                \
    } while (0)

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    if (oxi_test_last_freed_bytes_zero() != -1) {
        fprintf(stderr, "a freed handle was reported before any free\n");
        return 2;
    }
    int failed = 0;
    TYPED_CASE(OxiHmacDrbgSha256, oxi_hmac_drbg_sha256, _generate);
    TYPED_CASE(OxiHmacDrbgSha384, oxi_hmac_drbg_sha384, _generate);
    TYPED_CASE(OxiHmacDrbgSha512, oxi_hmac_drbg_sha512, _generate);
    TYPED_CASE(OxiHashDrbgSha256, oxi_hash_drbg_sha256, _generate);
    TYPED_CASE(OxiHashDrbgSha384, oxi_hash_drbg_sha384, _generate);
    TYPED_CASE(OxiHashDrbgSha512, oxi_hash_drbg_sha512, _generate);
    TYPED_CASE(OxiCtrDrbgAes128, oxi_ctr_drbg_aes128, _generate_df);
    TYPED_CASE(OxiCtrDrbgAes192, oxi_ctr_drbg_aes192, _generate_df);
    TYPED_CASE(OxiCtrDrbgAes256, oxi_ctr_drbg_aes256, _generate_df);

    OxiDrbg *h = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&h) != 0 || oxi_drbg_instantiate(h, NULL, 0) != 0) {
        fprintf(stderr, "OxiDrbg setup failed\n");
        return 4;
    }
    uint8_t out[32] = {0};
    if (oxi_drbg_generate(h, NULL, 0, out, sizeof(out)) != 0) {
        fprintf(stderr, "drbg_generate failed\n");
        return 5;
    }
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(out); i++) {
        nonzero |= out[i];
    }
    if (nonzero == 0) {
        fprintf(stderr, "drbg_generate produced all-zero output\n");
        return 6;
    }
    oxi_drbg_free(h);
    failed += expect_wiped("OxiDrbg");
    if (failed != 0) {
        fprintf(stderr, "%d of 10 freed handles did not read as all zero\n", failed);
        return 7;
    }
    printf("test_drbg_free_zeroizes: OK (10 freed handles all zero: 9 typed kinds and OxiDrbg)\n");
    return 0;
}
