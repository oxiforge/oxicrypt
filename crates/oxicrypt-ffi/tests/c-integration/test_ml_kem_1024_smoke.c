/* ML-KEM-1024 C ABI smoke test — keygen / encapsulate / decapsulate
 * round-trip with implicit-rejection oracle on tamper.
 *
 * FIPS 203 §6.1–§6.3, parameter set k=4. Byte counts: d=z=m=32,
 * ek=1568, dk=3168, ct=1568, ss=32.
 *
 * Backfill: ML-KEM-1024 shipped in the original C ABI round without
 * a C smoke test. Per the PQ-family C-smoke-test precedent established
 * with this commit (see security-policy §4.7 "ML-KEM C ABI smoke-test
 * precedent for PQ families"), all three ML-KEM parameter sets carry
 * a parallel C round-trip exercise.
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
    /* profile=0 = Unrestricted (per oxi_active_profile mapping):
     * ML-KEM-1024 is also allowed under CNSA2=1, but we pin to
     * Unrestricted=0 to match the 512/768 tests in this round
     * (those variants are NOT in CNSA1/CNSA2 allow-lists). */
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }

    uint8_t d[32], z[32], m[32];
    memset(d, 0x42, sizeof(d));
    memset(z, 0x77, sizeof(z));
    memset(m, 0xAB, sizeof(m));

    uint8_t ek[1568];
    uint8_t dk[3168];
    int rc = oxi_ml_kem_1024_keygen(d, z, ek, dk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    uint8_t ss_a[32];
    uint8_t ct[1568];
    rc = oxi_ml_kem_1024_encapsulate(ek, m, ss_a, ct);
    if (rc != 0) {
        fprintf(stderr, "encapsulate failed: rc=%d\n", rc);
        return 3;
    }

    uint8_t ss_b[32];
    rc = oxi_ml_kem_1024_decapsulate(dk, ct, ss_b);
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
    uint8_t ct_bad[1568];
    memcpy(ct_bad, ct, sizeof(ct_bad));
    ct_bad[0] ^= 0xFF;
    uint8_t ss_bad[32];
    rc = oxi_ml_kem_1024_decapsulate(dk, ct_bad, ss_bad);
    if (rc != 0) {
        fprintf(stderr, "decapsulate(tampered) returned rc=%d (expected 0; tamper does NOT surface as error)\n", rc);
        return 6;
    }
    if (memcmp(ss_a, ss_bad, 32) == 0) {
        fprintf(stderr, "implicit rejection failed: tampered ct produced matching shared secret\n");
        return 7;
    }

    printf("test_ml_kem_1024_smoke: OK (keygen + encaps + decaps + implicit-rejection)\n");
    return 0;
}
