/* SLH-DSA-SHAKE-128f C ABI smoke test — keygen / sign / verify
 * round-trip with TagMismatch oracle on tamper.
 *
 * FIPS 205 §9.1–§9.3 over §10.2 SHAKE family, parameter set n=16,
 * h=66, d=22, a=6, k=33, w=16. Byte counts: xi=48 (SK.seed||SK.prf||
 * PK.seed, 3×16), pk=32, sk=64, sig=17 088.
 *
 * SHAKE family + fast variant — chosen as a structurally distinct
 * representative from `test_slh_dsa_sha2_256s_smoke.c`: different
 * hash family (SHAKE-256 one-shot XOF replaces every SHA-256/512
 * tweakable hash call), different security category, different
 * speed/size trade-off (smaller key/sig but more hash evaluations
 * per signature). Per `project_c_abi_backfill_c_tests_per_complexity.md`
 * the 12-variant marshalling matrix qualifies as "High" complexity —
 * the SHA-2 and SHAKE representatives together exercise the two
 * structurally-divergent code paths the macro hash-family dispatch
 * emits at expansion time.
 *
 * Profile must be Unrestricted (0): CNSSP-15 lists no SLH-DSA
 * parameter set, so SHAKE-128f is permitted only under
 * `AlgorithmProfile::Unrestricted`. See lib.rs SLH-DSA section
 * comment.
 *
 * Verify tamper-detection: same `TagMismatch = 22` mapping as
 * SHA2-256s (cross-family convention).
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

    uint8_t xi[48];
    memset(xi, 0x42, sizeof(xi));

    uint8_t pk[32];
    uint8_t sk[64];
    int rc = oxi_slh_dsa_shake_128f_keygen(xi, pk, sk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    const uint8_t msg[] = "slh-dsa-shake-128f smoke test message";
    const size_t msg_len = sizeof(msg) - 1;
    /* Empty ctx (X.509 / CMS / LAMPS convention). */
    const uint8_t ctx[1] = {0};
    const size_t ctx_len = 0;

    uint8_t sig[17088];
    rc = oxi_slh_dsa_shake_128f_sign(sk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "sign failed: rc=%d\n", rc);
        return 3;
    }

    rc = oxi_slh_dsa_shake_128f_verify(pk, msg, msg_len, ctx, ctx_len, sig);
    if (rc != 0) {
        fprintf(stderr, "verify(clean) failed: rc=%d (expected 0)\n", rc);
        return 4;
    }

    /* Tamper sig[0] and verify again. */
    uint8_t sig_bad[17088];
    memcpy(sig_bad, sig, sizeof(sig_bad));
    sig_bad[0] ^= 0xFF;
    rc = oxi_slh_dsa_shake_128f_verify(pk, msg, msg_len, ctx, ctx_len, sig_bad);
    if (rc != 22) {
        fprintf(stderr, "verify(tampered) rc=%d (expected 22 TagMismatch)\n", rc);
        return 5;
    }

    printf("test_slh_dsa_shake_128f_smoke: OK (keygen + sign + verify + tamper-rejects)\n");
    return 0;
}
