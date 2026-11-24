/* A _new_rbg whose allocation fails returns Internal = 255 and leaves
 * *out unchanged.
 *
 * Runs against a library built with the fault-injection feature, which can
 * make the next _new_rbg fail as an allocation failure does.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiDrbg *const sentinel = (OxiDrbg *)(uintptr_t)0x5a5a5a50u;
    OxiDrbg *out = sentinel;
    oxi_test_fail_next_alloc();
    int rc = oxi_hmac_drbg_sha256_new_rbg(&out);
    if (rc != OXI_RESULT_INTERNAL) {
        fprintf(stderr, "new_rbg after a failed allocation: rc=%d, expected 255\n", rc);
        return 2;
    }
    if (out != sentinel) {
        fprintf(stderr, "new_rbg wrote *out on a failed allocation\n");
        return 3;
    }
    /* Control: the failure is one-shot, so the next call succeeds. */
    rc = oxi_hmac_drbg_sha256_new_rbg(&out);
    if (rc != 0 || out == sentinel || out == NULL) {
        fprintf(stderr, "new_rbg after the failure: rc=%d\n", rc);
        return 4;
    }
    oxi_drbg_free(out);
    printf("test_new_rbg_alloc_failure: OK (255, *out unchanged)\n");
    return 0;
}
