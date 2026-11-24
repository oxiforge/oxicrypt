/* _instantiate_from_module on a typed handle already instantiated replaces
 * the instantiation, and the handle then generates.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiHmacDrbgSha256 *drbg = NULL;
    if (oxi_hmac_drbg_sha256_new(&drbg) != 0) {
        fprintf(stderr, "hmac_drbg_sha256_new failed\n");
        return 2;
    }
    static const uint8_t first[] = "first instantiation";
    static const uint8_t second[] = "second instantiation";
    int rc = oxi_hmac_drbg_sha256_instantiate_from_module(drbg, first, sizeof(first) - 1);
    if (rc != 0) {
        fprintf(stderr, "first instantiate_from_module: rc=%d\n", rc);
        return 3;
    }
    rc = oxi_hmac_drbg_sha256_instantiate_from_module(drbg, second, sizeof(second) - 1);
    if (rc != 0) {
        fprintf(stderr, "second instantiate_from_module: rc=%d\n", rc);
        return 4;
    }
    uint8_t out[32];
    memset(out, 0, sizeof(out));
    rc = oxi_hmac_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
    if (rc != 0) {
        fprintf(stderr, "generate after the replacement: rc=%d\n", rc);
        return 5;
    }
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(out); i++) {
        nonzero |= out[i];
    }
    if (nonzero == 0) {
        fprintf(stderr, "generate after the replacement produced all-zero output\n");
        return 6;
    }
    oxi_hmac_drbg_sha256_free(drbg);
    printf("test_typed_from_module_replace: OK (instantiate twice, then generate)\n");
    return 0;
}
