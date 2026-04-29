/* Handle lifecycle test — NULL-free is a safe no-op, basic alloc/free path. */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }

    /* NULL-free must be a no-op (no crash). */
    oxi_aes256_free(NULL);

    /* alloc + free on a zero-key handle must succeed (the key value is
     * not validated for being non-trivial — that's a key-generation
     * concern, not a cipher-construction concern). */
    static const uint8_t zero_key[32] = {0};
    OxiAes256Key *handle = NULL;
    if (oxi_aes256_new(&handle, zero_key) != 0) {
        fprintf(stderr, "oxi_aes256_new(zero_key) failed\n");
        return 2;
    }
    if (handle == NULL) {
        fprintf(stderr, "oxi_aes256_new returned 0 but did not write a handle\n");
        return 3;
    }
    oxi_aes256_free(handle);

    /* NULL-out_handle is rejected (NullPointer = 10). */
    OxiAes256Key *unused = NULL;
    int rc = oxi_aes256_new(NULL, zero_key);
    if (rc != 10) {
        fprintf(stderr, "oxi_aes256_new(NULL,...) returned %d, expected NullPointer=10\n", rc);
        return 4;
    }
    /* NULL-key is rejected (NullPointer = 10). */
    rc = oxi_aes256_new(&unused, NULL);
    if (rc != 10) {
        fprintf(stderr, "oxi_aes256_new(...,NULL) returned %d, expected NullPointer=10\n", rc);
        return 5;
    }

    printf("test_handles: OK (NULL-free + alloc/free + NULL-arg rejection)\n");
    return 0;
}
