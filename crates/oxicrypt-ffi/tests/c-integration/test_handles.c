/* Key handle lifecycle: oxi_aes_cbc_key_new and oxi_aes_cbc_key_free. */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>

static int failures;

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "test_handles, %s: rc=%d, expected %d\n", check, rc, want);
        failures++;
    }
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }

    /* NULL frees nothing. */
    oxi_aes_cbc_key_free(NULL);

    /* Key construction does not judge the key's value. */
    static const uint8_t zero_key[32] = {0};
    OxiAesCbcKey *handle = NULL;
    expect("new from an all-zero key", oxi_aes_cbc_key_new(zero_key, sizeof(zero_key), &handle),
           0);
    if (handle == NULL) {
        fprintf(stderr, "test_handles, new from an all-zero key: no handle written\n");
        failures++;
    }
    oxi_aes_cbc_key_free(handle);

    expect("NULL out", oxi_aes_cbc_key_new(zero_key, sizeof(zero_key), NULL),
           OXI_RESULT_NULL_POINTER);

    OxiAesCbcKey *unused = NULL;
    expect("NULL key, length 32", oxi_aes_cbc_key_new(NULL, 32, &unused),
           OXI_RESULT_NULL_POINTER);
    if (unused != NULL) {
        fprintf(stderr, "test_handles, NULL key: *out written on failure\n");
        failures++;
    }

    if (failures != 0) {
        fprintf(stderr, "test_handles: %d checks failed\n", failures);
        return 2;
    }
    printf("test_handles: OK\n");
    return 0;
}
