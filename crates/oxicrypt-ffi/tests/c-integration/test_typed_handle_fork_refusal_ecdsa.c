/* ECDSA P-256 key generation refuses a typed DRBG handle inherited across fork.
 *
 * Runs against a library built with the fault-injection feature.
 *
 * The parent instantiates an HMAC_DRBG-SHA-256 handle from the module's
 * seed path and forks. In the child the inherited handle was instantiated
 * by another process, so key generation with it returns InvalidInput = 5.
 * The child reports the code through its exit status. The parent then
 * generates a key with the same handle, which succeeds.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int keygen(OxiHmacDrbgSha256 *drbg) {
    OxiEcdsaP256PrivateKey *key = NULL;
    int rc = oxi_ecdsa_p256_private_key_new_generate(drbg, &key);
    oxi_ecdsa_p256_private_key_free(key);
    return rc;
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }
    OxiHmacDrbgSha256 *drbg = NULL;
    if (oxi_hmac_drbg_sha256_new(&drbg) != 0 ||
        oxi_hmac_drbg_sha256_instantiate_from_module(drbg, NULL, 0) != 0) {
        fprintf(stderr, "HMAC_DRBG-SHA-256 setup failed\n");
        return 2;
    }
    pid_t pid = fork();
    if (pid == 0) {
        _exit(keygen(drbg));
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        fprintf(stderr, "child did not exit normally\n");
        return 3;
    }
    if (WEXITSTATUS(status) != OXI_RESULT_INVALID_INPUT) {
        fprintf(stderr, "child key generation with an inherited handle: status %d, expected 5\n",
                WEXITSTATUS(status));
        return 4;
    }
    int rc = keygen(drbg);
    if (rc != 0) {
        fprintf(stderr, "parent key generation after fork: rc=%d\n", rc);
        return 5;
    }
    oxi_hmac_drbg_sha256_free(drbg);
    printf("test_typed_handle_fork_refusal_ecdsa: OK (child 5, parent 0)\n");
    return 0;
}
