/* ML-DSA-87 C ABI smoke test — keygen / sign / verify round-trip
 * with TagMismatch oracle on tamper.
 *
 * FIPS 204 §5.2 + §6.1, parameter set k=8, ℓ=7. Byte counts: xi=32,
 * pk=2592, sk=4896, sig=4627.
 *
 * Profile may be Unrestricted (0), Cnsa2 (2), or Cnsa1Transition (1):
 * ML-DSA-87 is the CNSA 2.0 digital-signature mandate (CNSSP 15) and
 * is permitted under every profile. This test uses profile 0 for
 * uniformity with the ML-DSA-44/65 smoke tests.
 *
 * Verify tamper-detection: a flipped signature byte must surface as
 * `TagMismatch = 22` (FIPS 204 §5.2 Algorithm 3 collapses both the
 * upstream decode-fail and verification-fail paths into a single
 * `Err(InvalidInput)` which the FFI maps to `TagMismatch = 22`,
 * matching RSA-verify's PR #17 convention).
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

    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));

    uint8_t pk[2592];
    uint8_t sk[4896];
    int rc = oxi_ml_dsa_87_keygen(seed, pk, sk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    const uint8_t msg[] = "ml-dsa-87 smoke test message";
    const size_t msg_len = sizeof(msg) - 1;
    const uint8_t ctx[1] = {0};
    const size_t ctx_len = 0;

    uint8_t sig[4627];
    rc = oxi_ml_dsa_87_sign(sk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "sign failed: rc=%d\n", rc);
        return 3;
    }

    rc = oxi_ml_dsa_87_verify(pk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "verify(clean) failed: rc=%d (expected 0)\n", rc);
        return 4;
    }

    uint8_t sig_bad[4627];
    memcpy(sig_bad, sig, sizeof(sig_bad));
    sig_bad[0] ^= 0xFF;
    rc = oxi_ml_dsa_87_verify(pk, msg, msg_len, ctx, ctx_len, sig_bad);
    if (rc != 22) {
        fprintf(stderr, "verify(tampered) rc=%d (expected 22 TagMismatch)\n", rc);
        return 5;
    }

    printf("test_ml_dsa_87_smoke: OK (keygen + sign + verify + tamper-rejects)\n");
    return 0;
}
