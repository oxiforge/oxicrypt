/* A generate in progress when the module enters its error state writes
 * nothing to the caller's buffer and returns NotOperational = 1.
 *
 * Runs against a library built with the fault-injection feature.
 *
 * The handle is instantiated from a fixed seed stream, so the process's
 * seed path is still unconstructed. The test arms a hold with
 * oxi_test_park_before_output, and a second thread generates into a buffer
 * filled with 0xA5. The hold sits at the DRBG's re-check of the module
 * state, made before it produces any output bytes, and lasts until
 * oxi_test_release_parked or until it has spun 2^32 times. Once
 * oxi_test_is_parked reports that generate held there, the main thread
 * arms a startup health test failure with oxi_test_poison_entropy
 * (its own draw is served by the stream, so the failure stays armed) and
 * runs the entropy source's on-demand test, which constructs the seed
 * path, fails that test and puts the module into its error state. It then
 * releases the held generate, which must return 1 and leave every byte of
 * the buffer at 0xA5.
 *
 * The failure is reachable only where the seed path is the jitter source;
 * on the operating-system generator path the on-demand test returns 0 and
 * the run reports that.
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define OUT_LEN 64
/* How many times the main thread yields while waiting for the generate to
 * hold or return before it reports a hang. */
#define MAX_PARK_WAITS 100000000UL

static uint8_t out[OUT_LEN];
static int generate_rc = -1;
static atomic_int generate_done;

static void *generate_thread(void *arg) {
    generate_rc = oxi_drbg_generate((OxiDrbg *)arg, NULL, 0, out, OUT_LEN);
    atomic_store(&generate_done, 1);
    return NULL;
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    uint8_t stream[96];
    for (size_t i = 0; i < sizeof(stream); i++) {
        stream[i] = (uint8_t)(i * 13 + 1);
    }
    oxi_test_set_seed_stream(stream, sizeof(stream));
    OxiDrbg *h = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&h) != 0 || oxi_drbg_instantiate(h, NULL, 0) != 0) {
        fprintf(stderr, "OxiDrbg setup from the seed stream failed\n");
        return 2;
    }
    memset(out, 0xA5, sizeof(out));

    oxi_test_park_before_output(1);
    pthread_t thread;
    if (pthread_create(&thread, NULL, generate_thread, h) != 0) {
        fprintf(stderr, "thread start failed\n");
        return 3;
    }
    unsigned long waits = 0;
    while (!oxi_test_is_parked() && !atomic_load(&generate_done)) {
        if (++waits > MAX_PARK_WAITS) {
            fprintf(stderr, "generate neither held at its output check nor returned after %lu waits\n",
                    MAX_PARK_WAITS);
            return 11;
        }
        sched_yield();
    }
    if (!oxi_test_is_parked()) {
        pthread_join(thread, NULL);
        fprintf(stderr, "generate returned rc=%d without holding at its output check\n",
                generate_rc);
        return 9;
    }
    oxi_test_poison_entropy();
    const char *label = NULL;
    int test_rc = oxi_entropy_on_demand_test(&label);
    int held_until_release = oxi_test_is_parked();
    oxi_test_release_parked();
    if (pthread_join(thread, NULL) != 0) {
        fprintf(stderr, "thread join failed\n");
        return 4;
    }
    if (!held_until_release) {
        fprintf(stderr, "the hold at the output check ended before it was released\n");
        return 10;
    }
    if (test_rc != OXI_RESULT_ENTROPY_UNAVAILABLE) {
        fprintf(stderr, "on-demand test after poisoning: rc=%d (label %s), expected 33; "
                "the module did not enter its error state\n", test_rc, label ? label : "none");
        return 5;
    }
    if (oxi_is_operational() != 0) {
        fprintf(stderr, "module still operational after the failure\n");
        return 6;
    }
    if (generate_rc != OXI_RESULT_NOT_OPERATIONAL) {
        fprintf(stderr, "generate across the failure: rc=%d, expected 1\n", generate_rc);
        return 7;
    }
    for (size_t i = 0; i < sizeof(out); i++) {
        if (out[i] != 0xA5) {
            fprintf(stderr, "byte %zu of the output buffer was written\n", i);
            return 8;
        }
    }
    printf("test_output_inhibited_after_failure: OK (generate 1, buffer untouched)\n");
    return 0;
}
