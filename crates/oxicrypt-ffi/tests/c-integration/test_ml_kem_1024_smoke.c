/* ML-KEM-1024 C ABI smoke test: key generation from a DRBG handle with the
 * seed returned, key expansion of that seed, encapsulation with m drawn
 * from the handle, and decapsulation, including implicit rejection of a
 * tampered ciphertext (FIPS 203 Algorithm 21).
 *
 * Sizes (FIPS 203 Table 3): seed d || z 64 bytes, ek 1568, dk 3168,
 * ct 1568, shared secret 32.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define EK_LEN 1568
#define DK_LEN 3168
#define CT_LEN 1568

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

    static uint8_t ek[EK_LEN], dk[DK_LEN], ek2[EK_LEN], dk2[DK_LEN];
    uint8_t seed[64];
    int rc = oxi_ml_kem_1024_keygen_rbg(drbg, ek, dk, seed);
    if (rc != 0) {
        fprintf(stderr, "keygen_rbg failed: rc=%d\n", rc);
        return 2;
    }
    rc = oxi_ml_kem_1024_expand_key(seed, seed + 32, ek2, dk2);
    if (rc != 0 || memcmp(ek, ek2, EK_LEN) != 0 || memcmp(dk, dk2, DK_LEN) != 0) {
        fprintf(stderr, "expand_key did not reproduce the pair: rc=%d\n", rc);
        return 3;
    }

    static uint8_t ct[CT_LEN];
    uint8_t ss_a[32], ss_b[32], ss_bad[32];
    rc = oxi_ml_kem_1024_encapsulate_rbg(ek, drbg, ss_a, ct);
    if (rc != 0) {
        fprintf(stderr, "encapsulate_rbg failed: rc=%d\n", rc);
        return 4;
    }
    rc = oxi_ml_kem_1024_decapsulate(dk, ct, ss_b);
    if (rc != 0 || memcmp(ss_a, ss_b, 32) != 0) {
        fprintf(stderr, "decapsulate did not recover the shared secret: rc=%d\n", rc);
        return 5;
    }

    ct[0] ^= 0xFF;
    rc = oxi_ml_kem_1024_decapsulate(dk, ct, ss_bad);
    if (rc != 0) {
        fprintf(stderr, "decapsulate(tampered) returned rc=%d, expected 0\n", rc);
        return 6;
    }
    if (memcmp(ss_a, ss_bad, 32) == 0) {
        fprintf(stderr, "a tampered ciphertext gave the same shared secret\n");
        return 7;
    }

    oxi_drbg_free(drbg);
    printf("test_ml_kem_1024_smoke: OK (keygen_rbg + expand_key + encapsulate_rbg + decapsulate + implicit rejection)\n");
    return 0;
}
