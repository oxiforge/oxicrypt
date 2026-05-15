/* ML-DSA-65 C ABI smoke test — keygen / sign / verify round-trip
 * with TagMismatch oracle on tamper.
 *
 * FIPS 204 §5.2 + §6.1, parameter set k=6, ℓ=5. Byte counts: xi=32,
 * pk=1952, sk=4032, sig=3309.
 *
 * Profile must be Unrestricted (0): ML-DSA-65 is NOT in either the
 * CNSA 1.0 transition allow-list or the CNSA 2.0 mandate (which pins
 * ML-DSA-87). See lib.rs ml_dsa_65 section comment.
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

    uint8_t pk[1952];
    uint8_t sk[4032];
    int rc = oxi_ml_dsa_65_keygen(seed, pk, sk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    const uint8_t msg[] = "ml-dsa-65 smoke test message";
    const size_t msg_len = sizeof(msg) - 1;
    const uint8_t ctx[1] = {0};
    const size_t ctx_len = 0;

    uint8_t sig[3309];
    rc = oxi_ml_dsa_65_sign(sk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "sign failed: rc=%d\n", rc);
        return 3;
    }

    rc = oxi_ml_dsa_65_verify(pk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "verify(clean) failed: rc=%d (expected 0)\n", rc);
        return 4;
    }

    uint8_t sig_bad[3309];
    memcpy(sig_bad, sig, sizeof(sig_bad));
    sig_bad[0] ^= 0xFF;
    rc = oxi_ml_dsa_65_verify(pk, msg, msg_len, ctx, ctx_len, sig_bad);
    if (rc != 22) {
        fprintf(stderr, "verify(tampered) rc=%d (expected 22 TagMismatch)\n", rc);
        return 5;
    }

    printf("test_ml_dsa_65_smoke: OK (keygen + sign + verify + tamper-rejects)\n");
    return 0;
}
