/* C return codes of RSA key generation on a pairwise consistency test
 * failure (FIPS 140-3 IG 10.3.A).
 *
 * Runs against a library built with the fault-injection feature.
 *
 * For each of RSA-2048, RSA-3072 and RSA-4096, in its own child process,
 * the three running at once, because the error state lasts until the
 * process ends: an unfaulted
 * oxi_rsa_NNNN_private_key_new_generate with e = 65537 returns 0 with a
 * handle; with oxi_test_corrupt_next_pk_rsa armed it returns
 * ConditionalTestFailed = 3, and then it and oxi_sha256 return
 * NotOperational = 1. Every refusal leaves *out_key as it was.
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

#define SIZE_CHILD(bits)                                                                      \
    static int child_##bits(void) {                                                           \
        const char *n = "RSA-" #bits;                                                        \
        static char marker;                                                                   \
        OxiRsaPrivateKey##bits *const unset = (OxiRsaPrivateKey##bits *)(void *)&marker;      \
        if (oxi_init(0) != 0) return 1;                                                       \
        OxiHmacDrbgSha256 *drbg = NULL;                                                       \
        if (oxi_hmac_drbg_sha256_new(&drbg) != 0 ||                                           \
            oxi_hmac_drbg_sha256_instantiate_from_module(drbg, NULL, 0) != 0)                 \
            return 1;                                                                         \
        OxiRsaPrivateKey##bits *key = NULL;                                                   \
        expect(n, "unfaulted", oxi_rsa_##bits##_private_key_new_generate(drbg, 65537, &key),  \
               OXI_RESULT_OK);                                                                \
        if (key == NULL) {                                                                    \
            fprintf(stderr, "%s: the unfaulted call returned no handle\n", n);                \
            failures++;                                                                       \
        }                                                                                     \
        oxi_rsa_##bits##_private_key_free(key);                                               \
        oxi_test_corrupt_next_pk_rsa();                                                       \
        key = unset;                                                                          \
        expect(n, "PCT armed", oxi_rsa_##bits##_private_key_new_generate(drbg, 65537, &key),  \
               OXI_RESULT_CONDITIONAL_TEST_FAILED);                                           \
        expect(n, "next key generation",                                                      \
               oxi_rsa_##bits##_private_key_new_generate(drbg, 65537, &key),                  \
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

SIZE_CHILD(2048)
SIZE_CHILD(3072)
SIZE_CHILD(4096)

/* Forks a child running `body` and returns its pid, or -1. The alarm
 * fails a child that hangs instead of hanging the run. */
static pid_t start_child(const char *name, int (*body)(void)) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork failed\n", name);
        failures++;
        return -1;
    }
    if (pid == 0) {
        failures = 0;
        alarm(600);
        _exit(body());
    }
    return pid;
}

static void wait_child(const char *name, pid_t pid) {
    if (pid < 0) return;
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: child failed (status %d)\n", name, status);
        failures++;
    }
}

int main(void) {
    static const char *const names[] = {"RSA-2048", "RSA-3072", "RSA-4096"};
    int (*const bodies[])(void) = {child_2048, child_3072, child_4096};
    pid_t pids[3];
    for (int i = 0; i < 3; i++) pids[i] = start_child(names[i], bodies[i]);
    for (int i = 0; i < 3; i++) wait_child(names[i], pids[i]);
    if (failures != 0) {
        fprintf(stderr, "test_pct_failure_code_rsa: %d failures\n", failures);
        return 1;
    }
    printf("test_pct_failure_code_rsa: OK (2048, 3072, 4096: 0 unfaulted, 3 on PCT failure, "
           "then 1)\n");
    return 0;
}
