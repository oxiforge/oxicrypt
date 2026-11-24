/* A forked child re-instantiates an inherited OxiDrbg that the parent held
 * at the fork, and then generates.
 *
 * Runs against a library built with the fault-injection feature, which can
 * hold a handle as a call on another thread would. In the
 * child, generate on the inherited handle is first refused with
 * InvalidInput = 5; oxi_drbg_instantiate then takes over the hold the
 * parent held, resets the parent's instance, instantiates afresh and records
 * the child's process id, and the next generate succeeds. The child reports through its exit status.
 *
 * A second case forks while a handle that was never instantiated is
 * held, as it is while a parent thread runs the handle's
 * first instantiate. The child sees the same refusal and the same takeover.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define OUT_LEN 32

static int child(OxiDrbg *h) {
    uint8_t out[OUT_LEN];
    if (oxi_drbg_generate(h, NULL, 0, out, OUT_LEN) != OXI_RESULT_INVALID_INPUT) {
        return 20;
    }
    if (oxi_drbg_instantiate(h, NULL, 0) != 0) {
        return 21;
    }
    if (oxi_drbg_generate(h, NULL, 0, out, OUT_LEN) != 0) {
        return 22;
    }
    return 0;
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiDrbg *h = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&h) != 0 || oxi_drbg_instantiate(h, NULL, 0) != 0) {
        fprintf(stderr, "OxiDrbg setup failed\n");
        return 2;
    }
    oxi_test_hold_busy(h, 1);
    pid_t pid = fork();
    if (pid == 0) {
        _exit(child(h));
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        fprintf(stderr, "child did not exit normally\n");
        return 3;
    }
    if (WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child: status %d (20 first generate not refused with 5, "
                "21 instantiate failed, 22 generate after instantiate failed)\n",
                WEXITSTATUS(status));
        return 4;
    }
    uint8_t out[OUT_LEN];
    int rc = oxi_drbg_generate(h, NULL, 0, out, OUT_LEN);
    if (rc != OXI_RESULT_BUSY) {
        fprintf(stderr, "parent generate with its handle still held: rc=%d, expected 32\n", rc);
        return 5;
    }
    oxi_test_hold_busy(h, 0);
    rc = oxi_drbg_generate(h, NULL, 0, out, OUT_LEN);
    if (rc != 0) {
        fprintf(stderr, "parent generate after clearing the flag: rc=%d\n", rc);
        return 6;
    }
    oxi_drbg_free(h);

    OxiDrbg *first = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&first) != 0) {
        fprintf(stderr, "second OxiDrbg setup failed\n");
        return 7;
    }
    oxi_test_hold_busy(first, 1);
    pid = fork();
    if (pid == 0) {
        _exit(child(first));
    }
    status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        fprintf(stderr, "second child did not exit normally\n");
        return 8;
    }
    if (WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child of a first instantiate held at the fork: status %d (20 first "
                "generate not refused with 5, 21 instantiate failed, 22 generate after "
                "instantiate failed)\n", WEXITSTATUS(status));
        return 9;
    }
    oxi_test_hold_busy(first, 0);
    oxi_drbg_free(first);
    printf("test_inherited_handle_reinstantiate: OK (child 5, re-instantiate, generate; "
           "also for a first instantiate held at the fork)\n");
    return 0;
}
