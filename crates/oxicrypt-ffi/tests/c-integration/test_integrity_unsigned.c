/* Refusal test: run against a library (or a static executable) built with
 * a verifying key whose integrity slot has NOT been written by
 * `oxicrypt-integrity-sign`.
 *
 * The pre-operational integrity test must find no valid slot, so
 * `oxi_init` must fail with SelfTestFailed = 2, `oxi_integrity_status`
 * must report SlotInvalid = 3, the module must not be operational, and a
 * cryptographic service must refuse. The library still reports the
 * fingerprint of the key it embeds, which the test reads.
 *
 * Against a signed library this test fails, because `oxi_init` succeeds.
 * The Makefile runs it both ways, so a pass on the unsigned copy is known
 * to come from the refusal and not from a test that cannot fail.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RC_NOT_OPERATIONAL 1
#define RC_SELF_TEST_FAILED 2
#define INTEGRITY_NOT_RUN 0
#define INTEGRITY_SLOT_INVALID 3
#define RC_BUFFER_TOO_SMALL 11

int main(void) {
    int status = oxi_integrity_status();
    if (status != INTEGRITY_NOT_RUN) {
        fprintf(stderr, "integrity status before oxi_init: %d (expected %d NotRun)\n", status,
                INTEGRITY_NOT_RUN);
        return 1;
    }

    int rc = oxi_init(0);
    if (rc == 0) {
        fprintf(stderr, "oxi_init(0) succeeded: the library is signed\n");
        return 2;
    }
    if (rc != RC_SELF_TEST_FAILED) {
        fprintf(stderr, "oxi_init(0) rc=%d (expected %d SelfTestFailed)\n", rc,
                RC_SELF_TEST_FAILED);
        return 3;
    }

    status = oxi_integrity_status();
    if (status != INTEGRITY_SLOT_INVALID) {
        fprintf(stderr, "integrity status after oxi_init: %d (expected %d SlotInvalid)\n", status,
                INTEGRITY_SLOT_INVALID);
        return 4;
    }

    if (oxi_is_operational()) {
        fprintf(stderr, "module reports operational after a failed integrity test\n");
        return 5;
    }

    uint8_t fingerprint[32] = {0};
    rc = oxi_integrity_key_fingerprint(fingerprint, 31);
    if (rc != RC_BUFFER_TOO_SMALL) {
        fprintf(stderr, "oxi_integrity_key_fingerprint(31) rc=%d (expected %d BufferTooSmall)\n",
                rc, RC_BUFFER_TOO_SMALL);
        return 8;
    }
    rc = oxi_integrity_key_fingerprint(fingerprint, sizeof fingerprint);
    if (rc != 0) {
        fprintf(stderr, "oxi_integrity_key_fingerprint rc=%d (expected 0 Ok)\n", rc);
        return 9;
    }
    /* The value is the SHA-256 of the verifying key the library was built
     * with; the Makefile passes it as hex. */
    const char *expected = getenv("INTEGRITY_FINGERPRINT");
    if (expected == NULL || strlen(expected) != 64) {
        fprintf(stderr, "INTEGRITY_FINGERPRINT must hold the expected fingerprint as 64 hex digits\n");
        return 10;
    }
    for (int i = 0; i < 32; i++) {
        char pair[3] = {expected[2 * i], expected[2 * i + 1], 0};
        if ((uint8_t)strtoul(pair, NULL, 16) != fingerprint[i]) {
            fprintf(stderr, "fingerprint byte %d is %02x, expected %s\n", i, fingerprint[i], pair);
            return 11;
        }
    }

    size_t needed = 0;
    rc = oxi_integrity_status_detail(NULL, 0, &needed);
    if (rc != RC_BUFFER_TOO_SMALL || needed < 2) {
        fprintf(stderr, "oxi_integrity_status_detail sizing rc=%d needed=%zu\n", rc, needed);
        return 12;
    }
    char detail[512];
    if (needed > sizeof detail ||
        oxi_integrity_status_detail((uint8_t *)detail, sizeof detail, &needed) != 0 ||
        detail[needed - 1] != 0) {
        fprintf(stderr, "oxi_integrity_status_detail did not return its text\n");
        return 13;
    }

    /* A second call must not turn the failure into success. */
    if (oxi_init(0) == 0) {
        fprintf(stderr, "second oxi_init(0) succeeded after a failed integrity test\n");
        return 6;
    }

    /* A service call must refuse before looking at its inputs. An
     * operational module would grade these all-zero inputs TagMismatch = 22;
     * this one must answer NotOperational = 1. */
    static const uint8_t pk[56] = {0};
    static const uint8_t sig[2508] = {0};
    rc = oxi_lms_verify(pk, NULL, 0, sig);
    if (rc != RC_NOT_OPERATIONAL) {
        fprintf(stderr, "oxi_lms_verify rc=%d (expected %d NotOperational)\n", rc,
                RC_NOT_OPERATIONAL);
        return 7;
    }

    printf("test_integrity_unsigned: OK (oxi_init rc=%d, integrity status=%d)\n", RC_SELF_TEST_FAILED,
           INTEGRITY_SLOT_INVALID);
    return 0;
}
