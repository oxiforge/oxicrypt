/* C return codes of ECDH key generation on a pairwise consistency test
 * failure (FIPS 140-3 IG 10.3.A).
 *
 * Runs against a library built with the fault-injection feature.
 *
 * For each of P-256 and P-384, in its own child process, because the error
 * state lasts until the process ends: an unfaulted
 * oxi_ecdh_pNNN_generate_keypair returns 0 and writes both outputs; with
 * oxi_test_corrupt_next_pk_ecdh armed it returns ConditionalTestFailed = 3,
 * and then it and oxi_sha256 return NotOperational = 1. Every refusal
 * leaves both outputs holding their 0xA5 fill.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FILL 0xA5

static int failures;

static void expect(const char *name, const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "%s, %s: rc=%d, expected %d\n", name, check, rc, want);
        failures++;
    }
}

static int all_fill(const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (b[i] != FILL) return 0;
    return 1;
}

#define CURVE_CHILD(curve, priv_len, pub_len)                                                 \
    static int child_##curve(void) {                                                          \
        const char *n = "ECDH " #curve;                                                      \
        uint8_t priv[priv_len], pub[pub_len];                                                 \
        if (oxi_init(0) != 0) return 1;                                                       \
        OxiHmacDrbgSha256 *drbg = NULL;                                                       \
        if (oxi_hmac_drbg_sha256_new(&drbg) != 0 ||                                           \
            oxi_hmac_drbg_sha256_instantiate_from_module(drbg, NULL, 0) != 0)                 \
            return 1;                                                                         \
        memset(priv, FILL, sizeof priv);                                                      \
        memset(pub, FILL, sizeof pub);                                                        \
        expect(n, "unfaulted", oxi_ecdh_##curve##_generate_keypair(drbg, priv, pub),          \
               OXI_RESULT_OK);                                                                \
        if (all_fill(priv, sizeof priv) || all_fill(pub, sizeof pub)) {                       \
            fprintf(stderr, "%s: the unfaulted call left an output unwritten\n", n);          \
            failures++;                                                                       \
        }                                                                                     \
        oxi_test_corrupt_next_pk_ecdh();                                                      \
        memset(priv, FILL, sizeof priv);                                                      \
        memset(pub, FILL, sizeof pub);                                                        \
        expect(n, "PCT armed", oxi_ecdh_##curve##_generate_keypair(drbg, priv, pub),          \
               OXI_RESULT_CONDITIONAL_TEST_FAILED);                                           \
        expect(n, "next key generation", oxi_ecdh_##curve##_generate_keypair(drbg, priv, pub), \
               OXI_RESULT_NOT_OPERATIONAL);                                                   \
        uint8_t digest[32];                                                                   \
        expect(n, "next oxi_sha256", oxi_sha256((const uint8_t *)"abc", 3, digest),          \
               OXI_RESULT_NOT_OPERATIONAL);                                                   \
        if (!all_fill(priv, sizeof priv) || !all_fill(pub, sizeof pub)) {                     \
            fprintf(stderr, "%s: an output changed on a refusal\n", n);                       \
            failures++;                                                                       \
        }                                                                                     \
        return failures != 0;                                                                 \
    }

CURVE_CHILD(p256, 32, 65)
CURVE_CHILD(p384, 48, 97)

/* The alarm fails a child that hangs instead of hanging the run. */
static void in_child(const char *name, int (*body)(void)) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork failed\n", name);
        failures++;
        return;
    }
    if (pid == 0) {
        failures = 0;
        alarm(600);
        _exit(body());
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: child failed (status %d)\n", name, status);
        failures++;
    }
}

int main(void) {
    in_child("ECDH P-256", child_p256);
    in_child("ECDH P-384", child_p384);
    if (failures != 0) {
        fprintf(stderr, "test_pct_failure_code_ecdh: %d failures\n", failures);
        return 1;
    }
    printf("test_pct_failure_code_ecdh: OK (P-256, P-384: 0 unfaulted, 3 on PCT failure, then 1)\n");
    return 0;
}
