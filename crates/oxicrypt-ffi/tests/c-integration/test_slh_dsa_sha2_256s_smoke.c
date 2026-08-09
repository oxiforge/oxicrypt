/* SLH-DSA-SHA2-256s C ABI smoke test — keygen / sign / verify
 * round-trip with TagMismatch oracle on tamper.
 *
 * FIPS 205 §9.1–§9.3, parameter set n=32, h=64, d=8, a=14, k=22, w=16.
 * Byte counts: xi=96 (SK.seed||SK.prf||PK.seed, 3×32), pk=64, sk=128,
 * sig=29 792.
 *
 * Profile must be Unrestricted (0). CNSSP-15 lists no SLH-DSA
 * parameter set, so SHA2-256s — like every other SLH-DSA parameter
 * set — is denied under both CNSA profiles.
 *
 * Signing is deterministic (opt_rand = PK.seed): re-running with the
 * same (sk, msg, ctx) triple gives a bit-identical signature.
 *
 * Verify tamper-detection: a flipped signature byte must surface as
 * `TagMismatch = 22` (FIPS 205 §9.3 Algorithm 24 collapses both the
 * upstream decode-fail and verification-fail paths into a single
 * `Err(InvalidInput)` which the FFI maps to `TagMismatch = 22`,
 * matching RSA-verify (PR #17), ML-DSA-verify (PR #18), and the
 * existing SLH-DSA-256s convention from the round-1 single-variant
 * FFI PR).
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

    /* xi = SK.seed || SK.prf || PK.seed (3×32 bytes, role-segregated
     * — see lib.rs SLH-DSA section comment). */
    uint8_t xi[96];
    memset(xi, 0x42, sizeof(xi));

    uint8_t pk[64];
    uint8_t sk[128];
    int rc = oxi_slh_dsa_sha2_256s_keygen(xi, pk, sk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    const uint8_t msg[] = "slh-dsa-sha2-256s smoke test message";
    const size_t msg_len = sizeof(msg) - 1;
    /* Empty ctx (X.509 / CMS / LAMPS convention). */
    const uint8_t ctx[1] = {0};
    const size_t ctx_len = 0;

    uint8_t sig[29792];
    rc = oxi_slh_dsa_sha2_256s_sign(sk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "sign failed: rc=%d\n", rc);
        return 3;
    }

    rc = oxi_slh_dsa_sha2_256s_verify(pk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "verify(clean) failed: rc=%d (expected 0)\n", rc);
        return 4;
    }

    /* Tamper sig[0] and verify again. FIPS 205 §9.3 Algorithm 24
     * surfaces this as `Err(InvalidInput)` upstream; FFI collapses
     * to `TagMismatch = 22`. */
    uint8_t sig_bad[29792];
    memcpy(sig_bad, sig, sizeof(sig_bad));
    sig_bad[0] ^= 0xFF;
    rc = oxi_slh_dsa_sha2_256s_verify(pk, msg, msg_len, ctx, ctx_len, sig_bad);
    if (rc != 22) {
        fprintf(stderr, "verify(tampered) rc=%d (expected 22 TagMismatch)\n", rc);
        return 5;
    }

    printf("test_slh_dsa_sha2_256s_smoke: OK (keygen + sign + verify + tamper-rejects)\n");
    return 0;
}
