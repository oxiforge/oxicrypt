/* ML-KEM-768 C ABI smoke test — keygen / encapsulate / decapsulate
 * round-trip with implicit-rejection oracle on tamper.
 *
 * FIPS 203 §6.1–§6.3, parameter set k=3. Byte counts: d=z=m=32,
 * ek=1184, dk=2400, ct=1088, ss=32.
 *
 * Profile must be Unrestricted (0): ML-KEM-768 is NOT in either the
 * CNSA 1.0 transition allow-list or the CNSA 2.0 mandate (which pins
 * ML-KEM-1024). See lib.rs ml_kem_768 section comment.
 *
 * Decapsulate tamper-detection follows the FIPS 203 §6.3 implicit-
 * rejection contract: tampered ciphertext does NOT surface as an
 * error discriminant, but the resulting shared secret IS distinct
 * from the encapsulated `ss_a` with overwhelming probability — the
 * test asserts non-equality, not error code.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }

    uint8_t d[32], z[32], m[32];
    memset(d, 0x42, sizeof(d));
    memset(z, 0x77, sizeof(z));
    memset(m, 0xAB, sizeof(m));

    uint8_t ek[1184];
    uint8_t dk[2400];
    int rc = oxi_ml_kem_768_keygen(d, z, ek, dk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    uint8_t ss_a[32];
    uint8_t ct[1088];
    rc = oxi_ml_kem_768_encapsulate(ek, m, ss_a, ct);
    if (rc != 0) {
        fprintf(stderr, "encapsulate failed: rc=%d\n", rc);
        return 3;
    }

    uint8_t ss_b[32];
    rc = oxi_ml_kem_768_decapsulate(dk, ct, ss_b);
    if (rc != 0) {
        fprintf(stderr, "decapsulate failed: rc=%d\n", rc);
        return 4;
    }
    if (memcmp(ss_a, ss_b, 32) != 0) {
        fprintf(stderr, "shared-secret mismatch on clean round-trip\n");
        return 5;
    }

    /* Tamper ct[0] and decapsulate again. FIPS 203 §6.3 implicit
     * rejection returns a deterministic-but-pseudorandom ss without
     * surfacing any error discriminant. The shared secret MUST be
     * distinct from ss_a (with overwhelming probability — collision
     * would require a near-zero-probability internal state hit). */
    uint8_t ct_bad[1088];
    memcpy(ct_bad, ct, sizeof(ct_bad));
    ct_bad[0] ^= 0xFF;
    uint8_t ss_bad[32];
    rc = oxi_ml_kem_768_decapsulate(dk, ct_bad, ss_bad);
    if (rc != 0) {
        fprintf(stderr, "decapsulate(tampered) returned rc=%d (expected 0; tamper does NOT surface as error)\n", rc);
        return 6;
    }
    if (memcmp(ss_a, ss_bad, 32) == 0) {
        fprintf(stderr, "implicit rejection failed: tampered ct produced matching shared secret\n");
        return 7;
    }

    printf("test_ml_kem_768_smoke: OK (keygen + encaps + decaps + implicit-rejection)\n");
    return 0;
}
