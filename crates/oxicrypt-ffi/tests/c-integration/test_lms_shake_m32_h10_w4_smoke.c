/* LMS SHAKE-256 M=32 H=10 W=4 C ABI smoke test — keygen / sign /
 * verify round-trip with TagMismatch oracle on tamper.
 *
 * Parameter set: LMS_SHAKE_M32_H10 / LMOTS_SHAKE_N32_W4 (RFC 8708
 * §3.1). Byte counts: xi=32, pk=56, sk=52, sig=2508. Byte layout is
 * the same as the SHA-256/M=32/H=10/W=4 baseline (identical
 * dimensions); the structural divergence is in the hash family —
 * the SHAKE-256 XOF squeeze-to-32-bytes adapter replaces every
 * `SHA-256(...)` call at the LM-OTS and Merkle tree layers (RFC 8708
 * §3.1).
 *
 * Pair selection rationale per `project_c_abi_backfill_c_tests_per_complexity.md`:
 * the 80-pair LMS grid divides into four hash families × five
 * heights × four Winternitz parameters. Picking one SHA-256 family
 * pair (H5/W4) and one SHAKE-256 family pair (H10/W4) exercises both
 * structurally-divergent hash-adapter code paths emitted by
 * `lms_impl!`. The remaining 78 pairs differ in numeric parameter
 * substitution only — identical macro shape, distinct constants.
 *
 * The test runs under `AlgorithmProfile::Unrestricted` (= 0); the
 * SHAKE family is permitted under the CNSA profiles too, since
 * CNSSP-15 Annex B places no subset restriction on LMS.
 *
 * Verify-tamper-detection: `TagMismatch = 22` per cross-family
 * verify convention.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LMS_SHAKE_M32_H10_W4_SK_LEN 52
#define LMS_SHAKE_M32_H10_W4_PK_LEN 56
#define LMS_SHAKE_M32_H10_W4_SIG_LEN 2508

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }

    uint8_t xi[32];
    memset(xi, 0x42, sizeof(xi));

    uint8_t sk[LMS_SHAKE_M32_H10_W4_SK_LEN];
    uint8_t pk[LMS_SHAKE_M32_H10_W4_PK_LEN];
    int rc = oxi_lms_shake_m32_h10_w4_keygen(xi, sk, pk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    const uint8_t msg[] = "lms shake m32 h10 w4 smoke test message";
    const size_t msg_len = sizeof(msg) - 1;

    uint8_t sk_after[LMS_SHAKE_M32_H10_W4_SK_LEN];
    uint8_t sig[LMS_SHAKE_M32_H10_W4_SIG_LEN];
    rc = oxi_lms_shake_m32_h10_w4_sign(sk, msg, msg_len, sk_after, sig);
    if (rc != 0) {
        fprintf(stderr, "sign failed: rc=%d\n", rc);
        return 3;
    }

    if (memcmp(sk, sk_after, LMS_SHAKE_M32_H10_W4_SK_LEN) == 0) {
        fprintf(stderr, "sk_after equals sk (leaf index did not advance)\n");
        return 4;
    }

    rc = oxi_lms_shake_m32_h10_w4_verify(pk, msg, msg_len, sig);
    if (rc != 0) {
        fprintf(stderr, "verify(clean) failed: rc=%d (expected 0)\n", rc);
        return 5;
    }

    uint8_t sig_bad[LMS_SHAKE_M32_H10_W4_SIG_LEN];
    memcpy(sig_bad, sig, sizeof(sig_bad));
    sig_bad[0] ^= 0xFF;
    rc = oxi_lms_shake_m32_h10_w4_verify(pk, msg, msg_len, sig_bad);
    if (rc != 22) {
        fprintf(stderr, "verify(tampered) rc=%d (expected 22 TagMismatch)\n", rc);
        return 6;
    }

    printf("test_lms_shake_m32_h10_w4_smoke: OK (keygen + sign + verify + tamper-rejects)\n");
    return 0;
}
