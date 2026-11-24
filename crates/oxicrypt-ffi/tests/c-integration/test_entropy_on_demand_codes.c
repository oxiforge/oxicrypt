/* oxi_entropy_on_demand_test return codes and labels.
 *
 * Runs against a library built with the fault-injection feature.
 *
 *   - In a child forked before oxi_init, the module is not operational:
 *     NotOperational = 1.
 *   - After oxi_init, the test passes with 0 and a label naming the seed
 *     path, starting "jitter source" or "operating-system generator".
 *   - In a child that arms a startup health test failure, the test returns
 *     EntropyUnavailable = 33 with a label. A forked child starts with an
 *     unconstructed seed path. Its oxi_test_poison_entropy draw is served
 *     by a fixed seed stream, so the failure stays armed until the
 *     on-demand test constructs the jitter source and fails it. On the
 *     operating-system generator path there is no startup test to fail.
 *   - In a child that instantiates a handle, deciding the seed path, and
 *     then arms an on-demand test failure, the test returns 33 with the
 *     decided path's label: the jitter source or the operating-system
 *     generator, never "undecided".
 */

#include "oxicrypt.h"
#include "oxicrypt-test.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define JITTER "jitter source"
#define OS_GENERATOR "operating-system generator"

static int child_status(pid_t pid) {
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

static int poisoned_child(void) {
    uint8_t stream[64] = {0};
    oxi_test_set_seed_stream(stream, sizeof(stream));
    oxi_test_poison_entropy();
    const char *label = NULL;
    int rc = oxi_entropy_on_demand_test(&label);
    if (rc != OXI_RESULT_ENTROPY_UNAVAILABLE) {
        return rc == 0 ? 90 : rc;
    }
    return label != NULL && label[0] != '\0' ? 0 : 91;
}

static int decided_child(void) {
    OxiDrbg *h = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&h) != 0) {
        return 92;
    }
    int rc = oxi_drbg_instantiate(h, NULL, 0);
    if (rc != 0) {
        oxi_drbg_free(h);
        return 93;
    }
    oxi_test_fail_next_on_demand();
    const char *label = NULL;
    rc = oxi_entropy_on_demand_test(&label);
    oxi_drbg_free(h);
    if (rc != OXI_RESULT_ENTROPY_UNAVAILABLE) {
        return rc == 0 ? 90 : rc;
    }
    if (label == NULL) {
        return 91;
    }
    if (strncmp(label, JITTER, strlen(JITTER)) != 0 &&
        strncmp(label, OS_GENERATOR, strlen(OS_GENERATOR)) != 0) {
        fprintf(stderr, "on-demand failure after instantiate: label \"%s\"\n", label);
        return 94;
    }
    return 0;
}

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        _exit(oxi_entropy_on_demand_test(NULL));
    }
    int rc = child_status(pid);
    if (rc != OXI_RESULT_NOT_OPERATIONAL) {
        fprintf(stderr, "on-demand test before oxi_init: status %d, expected 1\n", rc);
        return 10;
    }

    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    const char *label = NULL;
    rc = oxi_entropy_on_demand_test(&label);
    if (rc != 0 || label == NULL) {
        fprintf(stderr, "healthy on-demand test: rc=%d, label %s\n", rc, label ? label : "NULL");
        return 20;
    }
    if (strncmp(label, JITTER, strlen(JITTER)) != 0 &&
        strncmp(label, OS_GENERATOR, strlen(OS_GENERATOR)) != 0) {
        fprintf(stderr, "healthy on-demand test: unexpected label \"%s\"\n", label);
        return 21;
    }

    pid = fork();
    if (pid == 0) {
        _exit(poisoned_child());
    }
    rc = child_status(pid);
    if (rc != 0) {
        fprintf(stderr, "on-demand test after poisoning: child status %d (90: returned 0, "
                "91: no label; other: the code returned), expected 33 with a label; "
                "seed path \"%s\"\n", rc, label);
        return 30;
    }

    pid = fork();
    if (pid == 0) {
        _exit(decided_child());
    }
    rc = child_status(pid);
    if (rc != 0) {
        fprintf(stderr, "on-demand failure after instantiate: child status %d (90: returned 0, "
                "91: no label, 92: construction failed, 93: instantiate failed, 94: label "
                "names no seed path; other: the code returned), expected 33 with the decided "
                "path's label\n", rc);
        return 40;
    }
    printf("test_entropy_on_demand_codes: OK (1 before init; 0 \"%s\"; 33 after poisoning; "
           "33 with the decided path's label)\n", label);
    return 0;
}
