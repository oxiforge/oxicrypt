/* SP 800-90A DRBG C ABI smoke test — one representative per family.
 *
 * Exercises the full caller lifecycle
 *   _new → _instantiate → _generate → _reseed → _generate → _free
 * for one DRBG from each of the three families:
 *
 *   - HMAC_DRBG-SHA-256  (SP 800-90A §10.1.2)
 *   - Hash_DRBG-SHA-256  (SP 800-90A §10.1.1)
 *   - CTR_DRBG-AES-256   (SP 800-90A §10.2.1, derivation-function form)
 *
 * Every rc is asserted == 0; after the first generate the output
 * buffer is asserted non-trivial (not all-zero). Distinct return
 * codes per failure (mirroring the LMS smoke test) keep a failure
 * diagnosable from the process exit code alone.
 *
 * Entropy plumbing: the FFI does NOT bundle an entropy source — every
 * entropy-consuming call takes a caller-supplied buffer (drbg.rs
 * "Entropy plumbing"). Test entropy is a fixed 0x42-filled buffer
 * (deterministic, like the LMS test's xi seed) sized to the SP 800-90A
 * Table 2 / Table 3 minimums for the 256-bit security strength of each
 * representative:
 *   entropy ≥ 256 bits = 32 bytes; nonce ≥ 128 bits = 16 bytes.
 * We use 32-byte entropy + 16-byte nonce throughout. The CTR_DRBG _df
 * instantiate accepts variable-length entropy/nonce (it runs the
 * Block_Cipher_df), so the same sizes apply.
 *   (Sources: oxicrypt.h docs — HMAC §10.1.2.3 "entropy ≥ 256 bits,
 *   nonce ≥ 128 bits"; Hash §10.1.1.2 same; CTR-AES-256 _df §10.2.1
 *   "entropy ≥ 256 bits, nonce ≥ 128 bits".)
 *
 * Negative check: oxi_hmac_drbg_sha256_generate(NULL, ...) returns the
 * FFI-layer guard OxiResult::NullPointer = 10 (documented in
 * crates/oxicrypt-ffi/src/error.rs:62 and the drbg.rs error table
 * "NULL handle / NULL output | NullPointer = 10 | all three"; the guard
 * is `if handle.is_null() { return R::NullPointer }` at the top of the
 * generate fn — a defined, non-UB return). We do NOT double-free or
 * pass a NULL out-pointer with non-zero length triggering UB.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DRBG_ENTROPY_LEN 32 /* 256-bit security strength */
#define DRBG_NONCE_LEN   16 /* ≥ 128 bits                */
#define DRBG_OUT_LEN     64

#define OXI_NULL_POINTER 10 /* OxiResult::NullPointer (error.rs:62) */

/* Returns 1 if buf is entirely zero (trivial/uninitialized output). */
static int all_zero(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }

    uint8_t entropy[DRBG_ENTROPY_LEN];
    uint8_t nonce[DRBG_NONCE_LEN];
    memset(entropy, 0x42, sizeof(entropy));
    memset(nonce, 0x42, sizeof(nonce));

    uint8_t out[DRBG_OUT_LEN];
    int rc;

    /* ---- HMAC_DRBG-SHA-256 (return codes 10-19) ---- */
    {
        OxiHmacDrbgSha256 *drbg = NULL;
        rc = oxi_hmac_drbg_sha256_new(&drbg);
        if (rc != 0 || drbg == NULL) {
            fprintf(stderr, "hmac_drbg_sha256_new failed: rc=%d\n", rc);
            return 10;
        }
        rc = oxi_hmac_drbg_sha256_instantiate(drbg, entropy, sizeof(entropy),
                                              nonce, sizeof(nonce), NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_instantiate failed: rc=%d\n", rc);
            return 11;
        }
        memset(out, 0, sizeof(out));
        rc = oxi_hmac_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_generate(1) failed: rc=%d\n", rc);
            return 12;
        }
        if (all_zero(out, sizeof(out))) {
            fprintf(stderr, "hmac_drbg_sha256_generate(1) produced all-zero output\n");
            return 13;
        }
        rc = oxi_hmac_drbg_sha256_reseed(drbg, entropy, sizeof(entropy), NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_reseed failed: rc=%d\n", rc);
            return 14;
        }
        rc = oxi_hmac_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hmac_drbg_sha256_generate(2) failed: rc=%d\n", rc);
            return 15;
        }

        /* Negative: NULL handle to generate → NullPointer = 10. */
        rc = oxi_hmac_drbg_sha256_generate(NULL, NULL, 0, out, sizeof(out));
        if (rc != OXI_NULL_POINTER) {
            fprintf(stderr, "hmac_drbg_sha256_generate(NULL) rc=%d (expected %d NullPointer)\n",
                    rc, OXI_NULL_POINTER);
            return 16;
        }

        oxi_hmac_drbg_sha256_free(drbg);
    }

    /* ---- Hash_DRBG-SHA-256 (return codes 20-29) ---- */
    {
        OxiHashDrbgSha256 *drbg = NULL;
        rc = oxi_hash_drbg_sha256_new(&drbg);
        if (rc != 0 || drbg == NULL) {
            fprintf(stderr, "hash_drbg_sha256_new failed: rc=%d\n", rc);
            return 20;
        }
        rc = oxi_hash_drbg_sha256_instantiate(drbg, entropy, sizeof(entropy),
                                              nonce, sizeof(nonce), NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_instantiate failed: rc=%d\n", rc);
            return 21;
        }
        memset(out, 0, sizeof(out));
        rc = oxi_hash_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_generate(1) failed: rc=%d\n", rc);
            return 22;
        }
        if (all_zero(out, sizeof(out))) {
            fprintf(stderr, "hash_drbg_sha256_generate(1) produced all-zero output\n");
            return 23;
        }
        rc = oxi_hash_drbg_sha256_reseed(drbg, entropy, sizeof(entropy), NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_reseed failed: rc=%d\n", rc);
            return 24;
        }
        rc = oxi_hash_drbg_sha256_generate(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "hash_drbg_sha256_generate(2) failed: rc=%d\n", rc);
            return 25;
        }
        oxi_hash_drbg_sha256_free(drbg);
    }

    /* ---- CTR_DRBG-AES-256 (df form) (return codes 30-39) ---- */
    {
        OxiCtrDrbgAes256 *drbg = NULL;
        rc = oxi_ctr_drbg_aes256_new(&drbg);
        if (rc != 0 || drbg == NULL) {
            fprintf(stderr, "ctr_drbg_aes256_new failed: rc=%d\n", rc);
            return 30;
        }
        rc = oxi_ctr_drbg_aes256_instantiate_df(drbg, entropy, sizeof(entropy),
                                                nonce, sizeof(nonce), NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_instantiate_df failed: rc=%d\n", rc);
            return 31;
        }
        memset(out, 0, sizeof(out));
        rc = oxi_ctr_drbg_aes256_generate_df(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_generate_df(1) failed: rc=%d\n", rc);
            return 32;
        }
        if (all_zero(out, sizeof(out))) {
            fprintf(stderr, "ctr_drbg_aes256_generate_df(1) produced all-zero output\n");
            return 33;
        }
        rc = oxi_ctr_drbg_aes256_reseed_df(drbg, entropy, sizeof(entropy), NULL, 0);
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_reseed_df failed: rc=%d\n", rc);
            return 34;
        }
        rc = oxi_ctr_drbg_aes256_generate_df(drbg, NULL, 0, out, sizeof(out));
        if (rc != 0) {
            fprintf(stderr, "ctr_drbg_aes256_generate_df(2) failed: rc=%d\n", rc);
            return 35;
        }
        oxi_ctr_drbg_aes256_free(drbg);
    }

    printf("test_drbg_smoke: OK (HMAC/Hash/CTR new+instantiate+generate+reseed+generate+free; "
           "non-trivial output; NULL-handle rejects with NullPointer=10)\n");
    return 0;
}
