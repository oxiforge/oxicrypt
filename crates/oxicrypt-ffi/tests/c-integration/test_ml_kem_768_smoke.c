/* ML-KEM-768 C ABI smoke test — keygen, the refused caller-m
 * encapsulate, and decapsulate with its implicit-rejection oracle.
 *
 * Parameter set k=3. Byte counts: d=z=m=32, ek=1184, dk=2400, ct=1088,
 * ss=32.
 *
 * Profile must be Unrestricted (0): ML-KEM-768 is NOT in either the
 * CNSA 1.0 transition allow-list or the CNSA 2.0 mandate (which pins
 * ML-KEM-1024).
 *
 * oxi_ml_kem_768_encapsulate takes a caller-supplied m, which is not a
 * module service (FIPS 203 §3.3: the module performs the sampling), so it
 * returns OXI_RESULT_NOT_IMPLEMENTED and writes nothing. Decapsulation is
 * therefore checked on a fixed ciphertext rather than on a round trip:
 * implicit rejection (FIPS 203 Algorithm 18) returns a shared secret
 * without an error discriminant, the same one for the same ciphertext and,
 * with overwhelming probability, a different one when a byte is flipped.
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
    memset(ss_a, 0xC3, sizeof(ss_a));
    memset(ct, 0xC3, sizeof(ct));
    rc = oxi_ml_kem_768_encapsulate(ek, m, ss_a, ct);
    if (rc != OXI_RESULT_NOT_IMPLEMENTED) {
        fprintf(stderr, "encapsulate returned rc=%d, expected %d\n", rc,
                OXI_RESULT_NOT_IMPLEMENTED);
        return 3;
    }
    for (size_t i = 0; i < sizeof(ct); i++) {
        if (ct[i] != 0xC3 || (i < sizeof(ss_a) && ss_a[i] != 0xC3)) {
            fprintf(stderr, "encapsulate wrote to an output\n");
            return 4;
        }
    }

    memset(ct, 0x5A, sizeof(ct));
    uint8_t ss_b[32], ss_c[32];
    rc = oxi_ml_kem_768_decapsulate(dk, ct, ss_b);
    if (rc != 0) {
        fprintf(stderr, "decapsulate failed: rc=%d\n", rc);
        return 5;
    }
    rc = oxi_ml_kem_768_decapsulate(dk, ct, ss_c);
    if (rc != 0 || memcmp(ss_b, ss_c, 32) != 0) {
        fprintf(stderr, "decapsulate is not deterministic: rc=%d\n", rc);
        return 6;
    }

    uint8_t ct_bad[1088];
    memcpy(ct_bad, ct, sizeof(ct_bad));
    ct_bad[0] ^= 0xFF;
    uint8_t ss_bad[32];
    rc = oxi_ml_kem_768_decapsulate(dk, ct_bad, ss_bad);
    if (rc != 0) {
        fprintf(stderr, "decapsulate(tampered) returned rc=%d (expected 0; tamper does NOT surface as error)\n", rc);
        return 7;
    }
    if (memcmp(ss_b, ss_bad, 32) == 0) {
        fprintf(stderr, "implicit rejection failed: tampered ct produced matching shared secret\n");
        return 8;
    }

    printf("test_ml_kem_768_smoke: OK (keygen + encapsulate refused + decaps + implicit-rejection)\n");
    return 0;
}
