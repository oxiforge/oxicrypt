/* The shared OxiDrbg handle: output, hold, fork refusal and check order.
 *
 * Runs against a library built with the fault-injection feature.
 *
 *   - Seeded from the same fixed stream, an OxiDrbg holding HMAC_DRBG-SHA-256
 *     and a typed OxiHmacDrbgSha256 handle produce the same 64 bytes.
 *   - A call while another holds the handle returns Busy = 32.
 *   - A forked child's generate on an inherited handle returns
 *     InvalidInput = 5; the parent still generates.
 *   - oxi_drbg_free(NULL) is a no-op; generate on a handle never
 *     instantiated returns Uninstantiated = 8.
 *   - oxi_drbg_instantiate on an inherited handle that the parent held at
 *     the fork succeeds in the child, which then generates.
 *   - The check order, each pair shown by violating both checks at once:
 *     NullPointer = 10 over NotOperational = 1, NotOperational = 1 over
 *     AlgorithmRestricted = 6, AlgorithmRestricted = 6 over Busy = 32, and
 *     InvalidInput = 5 (another process's handle) over Busy = 32.
 *
 * A child reports through its exit status; the parent checks it.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define OUT_LEN 64
#define PROFILE_UNRESTRICTED 0
#define PROFILE_CNSA2 1

/* The exit status of child `pid`, or -1 when it did not exit normally. */
static int child_status(pid_t pid) {
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

static int generate(OxiDrbg *h, uint8_t *out) {
    return oxi_drbg_generate(h, NULL, 0, out, OUT_LEN);
}

static void *generate_thread(void *arg) {
    uint8_t out[OUT_LEN];
    static int rc;
    rc = generate((OxiDrbg *)arg, out);
    return &rc;
}

/* Child of the equality check: both handles drawn from the same stream. */
static int same_output_child(void) {
    uint8_t stream[96];
    for (size_t i = 0; i < sizeof(stream); i++) {
        stream[i] = (uint8_t)(i * 7 + 3);
    }
    uint8_t typed_out[OUT_LEN];
    uint8_t shared_out[OUT_LEN];

    OxiHmacDrbgSha256 *typed = NULL;
    if (oxi_hmac_drbg_sha256_new(&typed) != 0) {
        return 31;
    }
    oxi_test_set_seed_stream(stream, sizeof(stream));
    if (oxi_hmac_drbg_sha256_instantiate_from_module(typed, NULL, 0) != 0) {
        return 32;
    }
    if (oxi_hmac_drbg_sha256_generate(typed, NULL, 0, typed_out, OUT_LEN) != 0) {
        return 33;
    }
    oxi_hmac_drbg_sha256_free(typed);

    OxiDrbg *shared = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&shared) != 0) {
        return 34;
    }
    oxi_test_set_seed_stream(stream, sizeof(stream));
    if (oxi_drbg_instantiate(shared, NULL, 0) != 0) {
        return 35;
    }
    if (generate(shared, shared_out) != 0) {
        return 36;
    }
    oxi_drbg_free(shared);
    return memcmp(typed_out, shared_out, OUT_LEN) == 0 ? 0 : 37;
}

int main(void) {
    uint8_t out[OUT_LEN];
    int rc;
    pid_t pid;

    /* ---- Before oxi_init: check order 10 over 1, and 1 over 6 ---- */
    OxiDrbg *restricted = NULL;
    if (oxi_ctr_drbg_aes128_new_rbg(&restricted) != 0 || restricted == NULL) {
        fprintf(stderr, "ctr_drbg_aes128_new_rbg before oxi_init failed\n");
        return 10;
    }
    pid = fork();
    if (pid == 0) {
        _exit(oxi_drbg_generate(NULL, NULL, 0, out, OUT_LEN));
    }
    rc = child_status(pid);
    if (rc != OXI_RESULT_NULL_POINTER) {
        fprintf(stderr, "NULL handle, module not operational: status %d, expected 10\n", rc);
        return 11;
    }
    /* CTR_DRBG-AES-128 is a kind the CNSA 2.0 profile restricts. */
    pid = fork();
    if (pid == 0) {
        _exit(generate(restricted, out));
    }
    rc = child_status(pid);
    if (rc != OXI_RESULT_NOT_OPERATIONAL) {
        fprintf(stderr, "restricted kind, module not operational: status %d, expected 1\n", rc);
        return 12;
    }
    /* 6 over 32: a CNSA 2.0 child holds a restricted kind's handle. */
    pid = fork();
    if (pid == 0) {
        if (oxi_init(PROFILE_CNSA2) != 0 || oxi_active_profile() != PROFILE_CNSA2) {
            _exit(100);
        }
        oxi_test_hold_busy(restricted, 1);
        _exit(generate(restricted, out));
    }
    rc = child_status(pid);
    if (rc != OXI_RESULT_ALGORITHM_RESTRICTED) {
        fprintf(stderr, "restricted kind, busy, CNSA 2.0: status %d, expected 6\n", rc);
        return 13;
    }
    oxi_drbg_free(restricted);

    if (oxi_init(PROFILE_UNRESTRICTED) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }

    /* ---- Same seed, same output as the typed handle ---- */
    pid = fork();
    if (pid == 0) {
        _exit(same_output_child());
    }
    rc = child_status(pid);
    if (rc != 0) {
        fprintf(stderr, "typed and shared handles from one seed stream: child status %d\n", rc);
        return 20;
    }

    OxiDrbg *h = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&h) != 0 || h == NULL) {
        fprintf(stderr, "hmac_drbg_sha256_new_rbg failed\n");
        return 40;
    }
    rc = oxi_drbg_instantiate(h, NULL, 0);
    if (rc != 0) {
        fprintf(stderr, "drbg_instantiate failed: rc=%d\n", rc);
        return 41;
    }
    rc = generate(h, out);
    if (rc != 0) {
        fprintf(stderr, "drbg_generate failed: rc=%d\n", rc);
        return 42;
    }

    /* ---- Busy: a second thread's call while the handle is held ---- */
    oxi_test_hold_busy(h, 1);
    pthread_t thread;
    void *result = NULL;
    if (pthread_create(&thread, NULL, generate_thread, h) != 0 ||
        pthread_join(thread, &result) != 0) {
        fprintf(stderr, "thread start or join failed\n");
        return 50;
    }
    oxi_test_hold_busy(h, 0);
    if (*(int *)result != OXI_RESULT_BUSY) {
        fprintf(stderr, "generate on a busy handle: rc=%d, expected 32\n", *(int *)result);
        return 51;
    }
    rc = generate(h, out);
    if (rc != 0) {
        fprintf(stderr, "generate after the hold was released: rc=%d\n", rc);
        return 52;
    }

    /* ---- Fork: the child is refused, the parent is not ---- */
    pid = fork();
    if (pid == 0) {
        _exit(generate(h, out));
    }
    rc = child_status(pid);
    if (rc != OXI_RESULT_INVALID_INPUT) {
        fprintf(stderr, "child generate on an inherited handle: status %d, expected 5\n", rc);
        return 60;
    }
    rc = generate(h, out);
    if (rc != 0) {
        fprintf(stderr, "parent generate after fork: rc=%d\n", rc);
        return 61;
    }

    /* ---- NULL free, never-instantiated handle ---- */
    oxi_drbg_free(NULL);
    OxiDrbg *fresh = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&fresh) != 0) {
        fprintf(stderr, "second hmac_drbg_sha256_new_rbg failed\n");
        return 70;
    }
    rc = generate(fresh, out);
    if (rc != OXI_RESULT_UNINSTANTIATED) {
        fprintf(stderr, "generate on a never-instantiated handle: rc=%d, expected 8\n", rc);
        return 71;
    }
    oxi_drbg_free(fresh);

    /* ---- Inherited handle that the parent held ---- */
    oxi_test_hold_busy(h, 1);
    pid = fork();
    if (pid == 0) {
        int child_rc = oxi_drbg_instantiate(h, NULL, 0);
        if (child_rc != 0) {
            _exit(child_rc);
        }
        _exit(generate(h, out) == 0 ? 0 : 99);
    }
    rc = child_status(pid);
    if (rc != 0) {
        fprintf(stderr, "child re-instantiate of a held inherited handle: status %d\n", rc);
        return 80;
    }

    /* ---- 5 over 32: the parent's handle, busy, in a child ---- */
    pid = fork();
    if (pid == 0) {
        _exit(generate(h, out));
    }
    rc = child_status(pid);
    oxi_test_hold_busy(h, 0);
    if (rc != OXI_RESULT_INVALID_INPUT) {
        fprintf(stderr, "busy inherited handle in a child: status %d, expected 5\n", rc);
        return 81;
    }

    oxi_drbg_free(h);
    printf("test_oxi_drbg_handle: OK (same output as the typed handle; busy 32; fork 5; "
           "free(NULL); uninstantiated 8; inherited busy re-instantiate; order 10>1, 1>6, "
           "6>32, 5>32)\n");
    return 0;
}
