/* LMS SHA-256 M=32 H=5 W=4 C ABI smoke test — keygen / sign / verify
 * round-trip with TagMismatch oracle on tamper.
 *
 * Parameter set: LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W4 (RFC 8554
 * §A.1+§A.2). Byte counts: xi=32, pk=56, sk=52, sig=2348. The
 * exact buffer sizes are wired through
 * `oxicrypt_lms::lms_sha256_m32_h5_w4::{PUBLIC_KEY_LEN,
 * PRIVATE_KEY_LEN, SIGNATURE_LEN}`; the C-side `#define`s below must
 * match.
 *
 * H=5 (32 leaves per key) — chosen as the short-tree representative
 * of the 80-pair grid: keygen completes in a fraction of a second
 * (vs. several seconds at H ≥ 15), and the structural code path
 * (RFC 8554 §5 Merkle traversal, RFC 8554 §4 LM-OTS hash chains)
 * is identical to every other pair — only the heights and Winternitz
 * parameter vary. Pair name slug aligns with the per-pair module:
 * `oxicrypt_lms::lms_sha256_m32_h5_w4`.
 *
 * H=5 with W=4 falls outside the CNSA 2.0 / CNSA 1.0 permitted set
 * (CNSA limits to H ∈ {10,15,20,25}); the test runs under
 * `AlgorithmProfile::Unrestricted` (= 0). The 80-pair grid is
 * available under Unrestricted; the 16-service subset is enforced
 * under CNSA-{1,2}.
 *
 * Verify-tamper-detection: `TagMismatch = 22` per cross-family verify
 * convention (RSA / ML-DSA / SLH-DSA / LMS / XMSS all share this
 * mapping; see oxi_lms_verify rustdoc).
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LMS_SHA256_M32_H5_W4_SK_LEN 52
#define LMS_SHA256_M32_H5_W4_PK_LEN 56
#define LMS_SHA256_M32_H5_W4_SIG_LEN 2348

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }

    uint8_t xi[32];
    memset(xi, 0x42, sizeof(xi));

    uint8_t sk[LMS_SHA256_M32_H5_W4_SK_LEN];
    uint8_t pk[LMS_SHA256_M32_H5_W4_PK_LEN];
    int rc = oxi_lms_sha256_m32_h5_w4_keygen(xi, sk, pk);
    if (rc != 0) {
        fprintf(stderr, "keygen failed: rc=%d\n", rc);
        return 2;
    }

    const uint8_t msg[] = "lms sha256 m32 h5 w4 smoke test message";
    const size_t msg_len = sizeof(msg) - 1;

    uint8_t sk_after[LMS_SHA256_M32_H5_W4_SK_LEN];
    uint8_t sig[LMS_SHA256_M32_H5_W4_SIG_LEN];
    rc = oxi_lms_sha256_m32_h5_w4_sign(sk, msg, msg_len, sk_after, sig);
    if (rc != 0) {
        fprintf(stderr, "sign failed: rc=%d\n", rc);
        return 3;
    }

    /* Persistence-of-record check: sk_after differs from sk (leaf
     * index advanced from 0 to 1). The last 4 bytes carry the
     * big-endian leaf_index per the opaque blob layout. */
    if (memcmp(sk, sk_after, LMS_SHA256_M32_H5_W4_SK_LEN) == 0) {
        fprintf(stderr, "sk_after equals sk (leaf index did not advance)\n");
        return 4;
    }

    rc = oxi_lms_sha256_m32_h5_w4_verify(pk, msg, msg_len, sig);
    if (rc != 0) {
        fprintf(stderr, "verify(clean) failed: rc=%d (expected 0)\n", rc);
        return 5;
    }

    /* Tamper sig[0] and verify again. */
    uint8_t sig_bad[LMS_SHA256_M32_H5_W4_SIG_LEN];
    memcpy(sig_bad, sig, sizeof(sig_bad));
    sig_bad[0] ^= 0xFF;
    rc = oxi_lms_sha256_m32_h5_w4_verify(pk, msg, msg_len, sig_bad);
    if (rc != 22) {
        fprintf(stderr, "verify(tampered) rc=%d (expected 22 TagMismatch)\n", rc);
        return 6;
    }

    printf("test_lms_sha256_m32_h5_w4_smoke: OK (keygen + sign + verify + tamper-rejects)\n");
    return 0;
}
