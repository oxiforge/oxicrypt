/* Two threads of a forked child re-instantiate one inherited OxiDrbg at
 * the same time.
 *
 * Runs against a library built with the fault-injection feature, which can
 * hold a handle as a call on another thread would. The parent
 * instantiates a handle and holds it across the fork. In each
 * child, two threads released together by a barrier both call
 * oxi_drbg_instantiate on the inherited handle. Each call returns 0 or
 * Busy = 32, and at least one returns 0: one thread takes the handle over,
 * and the other is refused while it does or instantiates after it. A
 * generate then succeeds in the child, and its output differs from the
 * parent's next output, so the child holds none of the parent's state.
 * The child reports through its exit status; the run repeats ROUNDS times.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define OUT_LEN 32
#define ROUNDS 64

static OxiDrbg *handle;
static pthread_barrier_t barrier;

static void *instantiate_thread(void *arg) {
    int *rc = arg;
    pthread_barrier_wait(&barrier);
    *rc = oxi_drbg_instantiate(handle, NULL, 0);
    return NULL;
}

/* 0 when both calls returned 0, 1 when one returned 32, or a failure
 * status of 20 and above. */
static int child(const uint8_t parent_next[OUT_LEN]) {
    int rc[2] = {-1, -1};
    pthread_t threads[2];
    if (pthread_barrier_init(&barrier, NULL, 2) != 0) {
        return 20;
    }
    for (int i = 0; i < 2; i++) {
        if (pthread_create(&threads[i], NULL, instantiate_thread, &rc[i]) != 0) {
            return 21;
        }
    }
    for (int i = 0; i < 2; i++) {
        pthread_join(threads[i], NULL);
    }
    for (int i = 0; i < 2; i++) {
        if (rc[i] != 0 && rc[i] != OXI_RESULT_BUSY) {
            fprintf(stderr, "child thread %d: instantiate returned %d\n", i, rc[i]);
            return 22;
        }
    }
    if (rc[0] != 0 && rc[1] != 0) {
        return 23;
    }
    uint8_t out[OUT_LEN];
    if (oxi_drbg_generate(handle, NULL, 0, out, OUT_LEN) != 0) {
        return 24;
    }
    if (memcmp(out, parent_next, OUT_LEN) == 0) {
        return 25;
    }
    return rc[0] == 0 && rc[1] == 0 ? 0 : 1;
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    int one_refused = 0;
    int both_ok = 0;
    for (int round = 0; round < ROUNDS; round++) {
        if (oxi_hmac_drbg_sha256_new_rbg(&handle) != 0 ||
            oxi_drbg_instantiate(handle, NULL, 0) != 0) {
            fprintf(stderr, "OxiDrbg setup failed\n");
            return 2;
        }
        oxi_test_hold_busy(handle, 1);
        int fds[2];
        if (pipe(fds) != 0) {
            return 3;
        }
        pid_t pid = fork();
        if (pid == 0) {
            uint8_t parent_next[OUT_LEN];
            close(fds[1]);
            ssize_t got = read(fds[0], parent_next, OUT_LEN);
            _exit(got == OUT_LEN ? child(parent_next) : 26);
        }
        close(fds[0]);
        oxi_test_hold_busy(handle, 0);
        uint8_t parent_next[OUT_LEN];
        int rc = oxi_drbg_generate(handle, NULL, 0, parent_next, OUT_LEN);
        ssize_t sent = write(fds[1], parent_next, OUT_LEN);
        close(fds[1]);
        int status = 0;
        if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
            fprintf(stderr, "round %d: child did not exit normally\n", round);
            return 4;
        }
        if (rc != 0 || sent != OUT_LEN) {
            fprintf(stderr, "round %d: parent generate rc=%d, sent %zd bytes\n", round, rc, sent);
            return 5;
        }
        int child_status = WEXITSTATUS(status);
        if (child_status == 0) {
            both_ok++;
        } else if (child_status == 1) {
            one_refused++;
        } else {
            fprintf(stderr, "round %d: child status %d (20/21 thread setup failed, 22 a code "
                    "other than 0 or 32, 23 neither returned 0, 24 generate after "
                    "instantiate failed, 25 output equal to the parent's, 26 no parent "
                    "output)\n", round, child_status);
            return 6;
        }
        oxi_drbg_free(handle);
    }
    printf("test_drbg_fork_two_threads: OK (%d rounds: %d with one call refused with 32, "
           "%d with both calls succeeding in turn)\n", ROUNDS, one_refused, both_ok);
    return 0;
}
