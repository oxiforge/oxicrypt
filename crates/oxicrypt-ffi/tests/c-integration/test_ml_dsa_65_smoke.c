/* ML-DSA-65 C ABI smoke test: key generation from a DRBG handle with the
 * seed returned, key expansion of that seed, signing and verification,
 * and a tampered signature refused with TagMismatch = 22.
 *
 * Sizes (FIPS 204 Table 2): seed 32 bytes, pk 1952, sk 4032, sig 3309.
 * ML-DSA-65 is admitted under the unrestricted profile (0) only.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PK_LEN 1952
#define SK_LEN 4032
#define SIG_LEN 3309

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }
    OxiDrbg *drbg = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&drbg) != 0 ||
        oxi_drbg_instantiate(drbg, (const uint8_t *)"smoke", 5) != 0) {
        fprintf(stderr, "DRBG handle setup failed\n");
        return 1;
    }

    static uint8_t pk[PK_LEN], sk[SK_LEN], pk2[PK_LEN], sk2[SK_LEN];
    uint8_t seed[32];
    int rc = oxi_ml_dsa_65_keygen_rbg(drbg, pk, sk, seed);
    if (rc != 0) {
        fprintf(stderr, "keygen_rbg failed: rc=%d\n", rc);
        return 2;
    }
    rc = oxi_ml_dsa_65_expand_key(seed, pk2, sk2);
    if (rc != 0 || memcmp(pk, pk2, PK_LEN) != 0 || memcmp(sk, sk2, SK_LEN) != 0) {
        fprintf(stderr, "expand_key did not reproduce the pair: rc=%d\n", rc);
        return 3;
    }

    const uint8_t msg[] = "ml-dsa-65 smoke test message";
    const size_t msg_len = sizeof(msg) - 1;
    static uint8_t sig[SIG_LEN];
    rc = oxi_ml_dsa_65_sign(sk, msg, msg_len, NULL, 0, sig);
    if (rc != 0) {
        fprintf(stderr, "sign failed: rc=%d\n", rc);
        return 4;
    }
    rc = oxi_ml_dsa_65_verify(pk, msg, msg_len, NULL, 0, sig);
    if (rc != 0) {
        fprintf(stderr, "verify failed: rc=%d\n", rc);
        return 5;
    }
    sig[0] ^= 0xFF;
    rc = oxi_ml_dsa_65_verify(pk, msg, msg_len, NULL, 0, sig);
    if (rc != OXI_RESULT_TAG_MISMATCH) {
        fprintf(stderr, "verify(tampered) rc=%d, expected %d\n", rc, OXI_RESULT_TAG_MISMATCH);
        return 6;
    }

    oxi_drbg_free(drbg);
    printf("test_ml_dsa_65_smoke: OK (keygen_rbg + expand_key + sign + verify + tamper refused)\n");
    return 0;
}
