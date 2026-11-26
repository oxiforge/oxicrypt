/* oxi_sha256 and oxi_ml_kem_512_keygen_rbg called concurrently from two
 * threads after one oxi_init.
 *
 * The threads start together. One runs 1000 iterations of
 * oxi_ml_kem_512_keygen_rbg on its own handle, checking that
 * oxi_ml_kem_512_expand_key of the returned seed reproduces the pair. The
 * other calls oxi_sha256 on "abc" and compares the FIPS 180-4 example
 * digest until the first has finished, and at least 1000 times. Every call
 * returns 0, and both iteration counts are asserted.
 *
 * Overlap witness: both threads take a ticket from one shared atomic
 * counter at the top of each iteration. The ticket ranges of the two
 * threads must overlap, and at least 1000 hash iterations must complete
 * between the key generation thread's first iteration and its last.
 *
 * Built with OXICRYPT_FAULT_INJECTION defined (the Makefile's test-fault):
 * while oxi_test_hold_busy holds a handle, a second thread's
 * oxi_ml_kem_512_keygen_rbg and oxi_ml_kem_512_encapsulate_rbg on it each
 * return Busy = 32 and write nothing; once the hold is released the same
 * calls from a second thread return 0.
 */

#include "oxicrypt.h"
#ifdef OXICRYPT_FAULT_INJECTION
#include "oxicrypt-test.h"
#endif
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ITERATIONS 1000
#define EK_LEN 800
#define DK_LEN 1632
#define CT_LEN 768
#define FILL 0xA5

static const uint8_t ABC_SHA256[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static pthread_barrier_t start;
static atomic_long tickets;
static atomic_int keygen_running, keygen_done;

typedef struct {
    OxiDrbg *rbg;
    long completed, during, first_ticket, last_ticket;
    int failures;
} Worker;

static void *hash_worker(void *arg) {
    Worker *w = arg;
    uint8_t digest[32];
    pthread_barrier_wait(&start);
    w->first_ticket = -1;
    while (w->completed < ITERATIONS || !atomic_load(&keygen_done)) {
        long ticket = atomic_fetch_add(&tickets, 1);
        if (w->first_ticket < 0) w->first_ticket = ticket;
        w->last_ticket = ticket;
        int running = atomic_load(&keygen_running);
        memset(digest, 0, sizeof digest);
        int rc = oxi_sha256((const uint8_t *)"abc", 3, digest);
        if (rc != 0 || memcmp(digest, ABC_SHA256, 32) != 0) {
            if (w->failures++ == 0)
                fprintf(stderr, "oxi_sha256 iteration %ld: rc=%d\n", w->completed, rc);
            if (w->failures > ITERATIONS) break;
            continue;
        }
        w->completed++;
        if (running && atomic_load(&keygen_running)) w->during++;
    }
    return NULL;
}

static void *keygen_worker(void *arg) {
    Worker *w = arg;
    static uint8_t ek[EK_LEN], dk[DK_LEN], ek2[EK_LEN], dk2[DK_LEN];
    uint8_t seed[64];
    pthread_barrier_wait(&start);
    atomic_store(&keygen_running, 1);
    for (int i = 0; i < ITERATIONS; i++) {
        long ticket = atomic_fetch_add(&tickets, 1);
        if (i == 0) w->first_ticket = ticket;
        w->last_ticket = ticket;
        int rc = oxi_ml_kem_512_keygen_rbg(w->rbg, ek, dk, seed);
        if (rc == 0) rc = oxi_ml_kem_512_expand_key(seed, seed + 32, ek2, dk2);
        if (rc != 0 || memcmp(ek, ek2, EK_LEN) != 0 || memcmp(dk, dk2, DK_LEN) != 0) {
            if (w->failures++ == 0)
                fprintf(stderr, "ML-KEM-512 iteration %d: rc=%d or the pair differs\n", i, rc);
            continue;
        }
        w->completed++;
    }
    atomic_store(&keygen_running, 0);
    atomic_store(&keygen_done, 1);
    return NULL;
}

static OxiDrbg *handle(void) {
    OxiDrbg *h = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&h) != 0 || oxi_drbg_instantiate(h, NULL, 0) != 0) {
        fprintf(stderr, "DRBG handle setup failed\n");
        oxi_drbg_free(h);
        return NULL;
    }
    return h;
}

#ifdef OXICRYPT_FAULT_INJECTION
static uint8_t key_ek[EK_LEN], key_dk[DK_LEN];
static uint8_t out_a[DK_LEN], out_b[DK_LEN];

typedef struct {
    OxiDrbg *rbg;
    int keygen_rc, encaps_rc;
} Call;

static void *held_calls(void *arg) {
    Call *c = arg;
    memset(out_a, FILL, sizeof out_a);
    memset(out_b, FILL, sizeof out_b);
    c->keygen_rc = oxi_ml_kem_512_keygen_rbg(c->rbg, out_a, out_b, NULL);
    if (c->keygen_rc != 0) {
        memset(out_a, FILL, sizeof out_a);
        memset(out_b, FILL, sizeof out_b);
    }
    c->encaps_rc = oxi_ml_kem_512_encapsulate_rbg(key_ek, c->rbg, out_a, out_b);
    return NULL;
}

static int all_fill(const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (b[i] != FILL) return 0;
    return 1;
}

static int run_held_calls(Call *c) {
    pthread_t t;
    if (pthread_create(&t, NULL, held_calls, c) != 0) {
        fprintf(stderr, "busy handle: pthread_create failed\n");
        return 0;
    }
    if (pthread_join(t, NULL) != 0) {
        fprintf(stderr, "busy handle: pthread_join failed\n");
        return 0;
    }
    return 1;
}

static int busy_handle(void) {
    int failures = 0;
    OxiDrbg *h = handle();
    if (h == NULL) return 1;
    Call c = {h, -1, -1};
    if (oxi_ml_kem_512_keygen_rbg(h, key_ek, key_dk, NULL) != 0) {
        fprintf(stderr, "busy handle: key pair setup failed\n");
        failures++;
        goto out;
    }

    oxi_test_hold_busy(h, 1);
    if (!run_held_calls(&c)) {
        failures++;
        goto release;
    }
    if (c.keygen_rc != OXI_RESULT_BUSY || c.encaps_rc != OXI_RESULT_BUSY ||
        !all_fill(out_a, sizeof out_a) || !all_fill(out_b, sizeof out_b)) {
        fprintf(stderr,
                "held handle: keygen rc=%d, encapsulate rc=%d, expected 32 and 32 with the "
                "outputs untouched\n",
                c.keygen_rc, c.encaps_rc);
        failures++;
    }

release:
    oxi_test_hold_busy(h, 0);
    if (failures == 0) {
        c.keygen_rc = c.encaps_rc = -1;
        if (!run_held_calls(&c)) {
            failures++;
        } else if (c.keygen_rc != OXI_RESULT_OK || c.encaps_rc != OXI_RESULT_OK) {
            fprintf(stderr, "released handle: keygen rc=%d, encapsulate rc=%d, expected 0 and 0\n",
                    c.keygen_rc, c.encaps_rc);
            failures++;
        }
    }
out:
    oxi_drbg_free(h);
    return failures;
}
#endif

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }
    OxiDrbg *h = handle();
    if (h == NULL) return 1;

    int failures = 0;
    Worker hasher = {0}, keygen = {0};
    keygen.rbg = h;
    pthread_t a, b;
    if (pthread_barrier_init(&start, NULL, 2) != 0) {
        fprintf(stderr, "pthread_barrier_init failed\n");
        failures++;
        goto out;
    }
    if (pthread_create(&a, NULL, hash_worker, &hasher) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        failures++;
        goto out;
    }
    if (pthread_create(&b, NULL, keygen_worker, &keygen) != 0) {
        fprintf(stderr, "pthread_create failed; the hash thread is left waiting\n");
        return 1;
    }
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_barrier_destroy(&start);

    failures += hasher.failures + keygen.failures;
    if (hasher.completed < ITERATIONS || keygen.completed != ITERATIONS) {
        fprintf(stderr, "completed %ld hash and %ld key generation iterations, expected at least "
                        "%d and exactly %d\n",
                hasher.completed, keygen.completed, ITERATIONS, ITERATIONS);
        failures++;
    }
    if (!(hasher.first_ticket < keygen.last_ticket && keygen.first_ticket < hasher.last_ticket)) {
        fprintf(stderr, "no overlap: hash tickets %ld-%ld, key generation tickets %ld-%ld\n",
                hasher.first_ticket, hasher.last_ticket, keygen.first_ticket, keygen.last_ticket);
        failures++;
    }
    if (hasher.during < ITERATIONS) {
        fprintf(stderr, "%ld hash iterations completed while key generation ran, expected at "
                        "least %d\n",
                hasher.during, ITERATIONS);
        failures++;
    }
#ifdef OXICRYPT_FAULT_INJECTION
    failures += busy_handle();
#endif
out:
    oxi_drbg_free(h);
    if (failures != 0) {
        fprintf(stderr, "test_concurrent_services: %d failures\n", failures);
        return 1;
    }
    printf("test_concurrent_services: OK (%ld hash iterations, %ld during %ld key generations)\n",
           hasher.completed, hasher.during, keygen.completed);
    return 0;
}
