/* C return codes of ECDSA key generation on a pairwise consistency test
 * failure (FIPS 140-3 IG 10.3.A).
 *
 * Runs against a library built with the fault-injection feature.
 *
 * For each of P-256 and P-384, in its own child process, because the error
 * state lasts until the process ends: an unfaulted
 * oxi_ecdsa_pNNN_private_key_new_generate returns 0 with a handle; with
 * oxi_test_corrupt_next_pk_ecdsa armed it returns ConditionalTestFailed = 3,
 * and then it and oxi_sha256 return NotOperational = 1. Every refusal
 * leaves *out_key as it was.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void expect(const char *name, const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "%s, %s: rc=%d, expected %d\n", name, check, rc, want);
        failures++;
    }
}

#define CURVE_CHILD(curve, Type)                                                              \
    static int child_##curve(void) {                                                          \
        const char *n = "ECDSA " #curve;                                                     \
        static char marker;                                                                   \
        Type *const unset = (Type *)(void *)&marker;                                          \
        if (oxi_init(0) != 0) return 1;                                                       \
        OxiHmacDrbgSha256 *drbg = NULL;                                                       \
        if (oxi_hmac_drbg_sha256_new(&drbg) != 0 ||                                           \
            oxi_hmac_drbg_sha256_instantiate_from_module(drbg, NULL, 0) != 0)                 \
            return 1;                                                                         \
        Type *key = NULL;                                                                     \
        expect(n, "unfaulted", oxi_ecdsa_##curve##_private_key_new_generate(drbg, &key),      \
               OXI_RESULT_OK);                                                                \
        if (key == NULL) {                                                                    \
            fprintf(stderr, "%s: the unfaulted call returned no handle\n", n);                \
            failures++;                                                                       \
        }                                                                                     \
        oxi_ecdsa_##curve##_private_key_free(key);                                            \
        oxi_test_corrupt_next_pk_ecdsa();                                                     \
        key = unset;                                                                          \
        expect(n, "PCT armed", oxi_ecdsa_##curve##_private_key_new_generate(drbg, &key),      \
               OXI_RESULT_CONDITIONAL_TEST_FAILED);                                           \
        expect(n, "next key generation",                                                      \
               oxi_ecdsa_##curve##_private_key_new_generate(drbg, &key),                      \
               OXI_RESULT_NOT_OPERATIONAL);                                                   \
        uint8_t digest[32];                                                                   \
        expect(n, "next oxi_sha256", oxi_sha256((const uint8_t *)"abc", 3, digest),          \
               OXI_RESULT_NOT_OPERATIONAL);                                                   \
        if (key != unset) {                                                                   \
            fprintf(stderr, "%s: *out_key changed on a refusal\n", n);                        \
            failures++;                                                                       \
        }                                                                                     \
        return failures != 0;                                                                 \
    }

CURVE_CHILD(p256, OxiEcdsaP256PrivateKey)
CURVE_CHILD(p384, OxiEcdsaP384PrivateKey)

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
    in_child("ECDSA P-256", child_p256);
    in_child("ECDSA P-384", child_p384);
    if (failures != 0) {
        fprintf(stderr, "test_pct_failure_code_ecdsa: %d failures\n", failures);
        return 1;
    }
    printf("test_pct_failure_code_ecdsa: OK (P-256, P-384: 0 unfaulted, 3 on PCT failure, then 1)\n");
    return 0;
}
