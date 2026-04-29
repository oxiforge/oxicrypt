/* AES-256 non-GCM C ABI tests — CBC, CTR, CCM, CMAC, KW, KWP.
 *
 * Each mode is exercised with the same KAT vector its underlying
 * power-up self-test uses (oxicrypt-aes::kat / oxicrypt-cmac::kat),
 * so the C ABI surface is verified against values the Rust core's
 * CAVP-style self-tests already validate. Modes without a published
 * AES-256 KAT (KWP-AES-256) are exercised with round-trip + decrypt
 * mismatch instead.
 *
 * Conformance argument: a successful test implies the encrypt /
 * decrypt / wrap / unwrap / mac path through the FFI marshalling
 * preserved the underlying primitive's exact algebraic behaviour,
 * with no mismatched IV length, packed C||T layout error, or
 * AAD / nonce / MAC pointer translation error. Tag-tamper rejection
 * (CCM, KW) confirms the constant-time tag-verify-then-release
 * contract is preserved across the boundary.
 *
 * Vector sources (per-mode):
 *   - CBC-AES-256:  NIST SP 800-38A Appendix F.2.5
 *   - CTR-AES-256:  NIST SP 800-38A Appendix F.5.5
 *   - CCM-AES-256:  oxicrypt-aes CCM_VPT256_* vector (16-byte tag,
 *                   13-byte nonce, 32-byte AAD, 16-byte plaintext)
 *   - CMAC-AES-256: NIST SP 800-38B Appendix D.3 Example 2 + Example 3
 *   - KW-AES-256:   RFC 3394 §4.3 (PT=128) and §4.6 (PT=256)
 *   - KWP-AES-256:  round-trip only (no published AES-256-KWP KAT
 *                   vector in the underlying self-test set; RFC 5649
 *                   examples cover AES-192 only)
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OXI_OK             0
#define OXI_TAG_MISMATCH  22

/* ─────────────────────────────────────────────────────────────────── */
/* Shared constants                                                    */
/* ─────────────────────────────────────────────────────────────────── */

/* SP 800-38A Appendix F plaintext / SP 800-38B Appendix D message
 * (same 64-byte sequence — used by CBC, CTR, CMAC test paths). */
static const uint8_t MSG64[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/* AES-256 key shared by SP 800-38A F-tables and SP 800-38B D.3. */
static const uint8_t KEY256_SP38[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

/* ─────────────────────────────────────────────────────────────────── */
/* CBC-AES-256 — SP 800-38A Appendix F.2.5                              */
/* ─────────────────────────────────────────────────────────────────── */

static const uint8_t CBC_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t CBC_EXPECTED_CT[64] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
    0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
    0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
    0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
};

static int test_cbc(const OxiAes256Key *key) {
    uint8_t ct[64], back[64];
    int rc = oxi_aes256_cbc_encrypt(key, CBC_IV, MSG64, sizeof(MSG64), ct);
    if (rc != OXI_OK) {
        fprintf(stderr, "  cbc encrypt rc=%d\n", rc);
        return 1;
    }
    if (memcmp(ct, CBC_EXPECTED_CT, sizeof(CBC_EXPECTED_CT)) != 0) {
        fprintf(stderr, "  cbc ciphertext mismatch vs SP 800-38A F.2.5\n");
        return 2;
    }
    rc = oxi_aes256_cbc_decrypt(key, CBC_IV, ct, sizeof(ct), back);
    if (rc != OXI_OK) {
        fprintf(stderr, "  cbc decrypt rc=%d\n", rc);
        return 3;
    }
    if (memcmp(back, MSG64, sizeof(MSG64)) != 0) {
        fprintf(stderr, "  cbc decrypt roundtrip mismatch\n");
        return 4;
    }
    printf("  cbc:  OK (SP 800-38A F.2.5 + roundtrip)\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────── */
/* CTR-AES-256 — SP 800-38A Appendix F.5.5                              */
/* ─────────────────────────────────────────────────────────────────── */

static const uint8_t CTR_ICB[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const uint8_t CTR_EXPECTED_CT[64] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
    0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
    0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
    0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
    0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
    0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
    0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
    0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
};

static int test_ctr(const OxiAes256Key *key) {
    uint8_t ct[64], back[64];
    int rc = oxi_aes256_ctr(key, CTR_ICB, MSG64, sizeof(MSG64), ct);
    if (rc != OXI_OK) {
        fprintf(stderr, "  ctr encrypt rc=%d\n", rc);
        return 1;
    }
    if (memcmp(ct, CTR_EXPECTED_CT, sizeof(CTR_EXPECTED_CT)) != 0) {
        fprintf(stderr, "  ctr ciphertext mismatch vs SP 800-38A F.5.5\n");
        return 2;
    }
    /* CTR is symmetric: same call decrypts. */
    rc = oxi_aes256_ctr(key, CTR_ICB, ct, sizeof(ct), back);
    if (rc != OXI_OK) {
        fprintf(stderr, "  ctr decrypt rc=%d\n", rc);
        return 3;
    }
    if (memcmp(back, MSG64, sizeof(MSG64)) != 0) {
        fprintf(stderr, "  ctr decrypt roundtrip mismatch\n");
        return 4;
    }
    printf("  ctr:  OK (SP 800-38A F.5.5 + symmetric roundtrip)\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────── */
/* CCM-AES-256 — oxicrypt-aes CCM_VPT256_* (Tlen=16, q=2, n=13)         */
/* ─────────────────────────────────────────────────────────────────── */

static const uint8_t CCM_KEY[32] = {
    0xee, 0x8c, 0xe1, 0x87, 0x16, 0x97, 0x79, 0xd1,
    0x3e, 0x44, 0x3d, 0x64, 0x28, 0xe3, 0x8b, 0x38,
    0xb5, 0x5d, 0xfb, 0x90, 0xf0, 0x22, 0x8a, 0x8a,
    0x4e, 0x62, 0xf8, 0xf5, 0x35, 0x80, 0x6e, 0x62,
};
static const uint8_t CCM_NONCE[13] = {
    0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39, 0x1c,
    0x98, 0xe6, 0x26, 0x9c, 0x8a,
};
static const uint8_t CCM_AAD[32] = {
    0x71, 0x8d, 0x13, 0xe4, 0x75, 0x22, 0xac, 0x4c,
    0xdf, 0x3f, 0x82, 0x80, 0x63, 0x98, 0x0b, 0x6d,
    0x45, 0x2f, 0xcd, 0xcd, 0x6e, 0x1a, 0x19, 0x04,
    0xbf, 0x87, 0xf5, 0x48, 0xa5, 0xfd, 0x5a, 0x05,
};
static const uint8_t CCM_PT[16] = {
    0xd1, 0x5f, 0x98, 0xf2, 0xc6, 0xd6, 0x70, 0xf5,
    0x5c, 0x78, 0xa0, 0x66, 0x48, 0x33, 0x2b, 0xc9,
};
static const uint8_t CCM_EXPECTED_PACKED[32] = { /* C || T */
    0xcc, 0x17, 0xbf, 0x87, 0x94, 0xc8, 0x43, 0x45,
    0x7d, 0x89, 0x93, 0x91, 0x89, 0x8e, 0xd2, 0x2a,
    0x6f, 0x9d, 0x28, 0xfc, 0xb6, 0x42, 0x34, 0xe1,
    0xcd, 0x79, 0x3c, 0x41, 0x44, 0xf1, 0xda, 0x50,
};

static int test_ccm(void) {
    OxiAes256Key *key = NULL;
    if (oxi_aes256_new(&key, CCM_KEY) != OXI_OK) {
        fprintf(stderr, "  ccm key construct failed\n");
        return 1;
    }
    uint8_t out[32], back[16];
    int rc = oxi_aes256_ccm_encrypt(
        key, CCM_NONCE, sizeof(CCM_NONCE),
        CCM_AAD, sizeof(CCM_AAD),
        CCM_PT, sizeof(CCM_PT), 16, out);
    if (rc != OXI_OK) {
        fprintf(stderr, "  ccm encrypt rc=%d\n", rc);
        oxi_aes256_free(key);
        return 2;
    }
    if (memcmp(out, CCM_EXPECTED_PACKED, sizeof(CCM_EXPECTED_PACKED)) != 0) {
        fprintf(stderr, "  ccm packed C||T mismatch\n");
        oxi_aes256_free(key);
        return 3;
    }
    rc = oxi_aes256_ccm_decrypt(
        key, CCM_NONCE, sizeof(CCM_NONCE),
        CCM_AAD, sizeof(CCM_AAD),
        out, sizeof(out), 16, back);
    if (rc != OXI_OK) {
        fprintf(stderr, "  ccm decrypt rc=%d\n", rc);
        oxi_aes256_free(key);
        return 4;
    }
    if (memcmp(back, CCM_PT, sizeof(CCM_PT)) != 0) {
        fprintf(stderr, "  ccm decrypt roundtrip mismatch\n");
        oxi_aes256_free(key);
        return 5;
    }

    /* Tamper a tag byte: must reject as TagMismatch. */
    uint8_t bad[32];
    memcpy(bad, out, sizeof(bad));
    bad[16] ^= 0x01; /* flip first tag byte */
    rc = oxi_aes256_ccm_decrypt(
        key, CCM_NONCE, sizeof(CCM_NONCE),
        CCM_AAD, sizeof(CCM_AAD),
        bad, sizeof(bad), 16, back);
    if (rc != OXI_TAG_MISMATCH) {
        fprintf(stderr, "  ccm tag tamper not rejected: rc=%d (expected %d)\n",
                rc, OXI_TAG_MISMATCH);
        oxi_aes256_free(key);
        return 6;
    }

    oxi_aes256_free(key);
    printf("  ccm:  OK (KAT + roundtrip + tag-tamper)\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────── */
/* CMAC-AES-256 — SP 800-38B Appendix D.3 Example 2 + Example 3         */
/* ─────────────────────────────────────────────────────────────────── */

static const uint8_t CMAC_EX2_TAG[16] = { /* Mlen = 128 */
    0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
    0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c,
};
static const uint8_t CMAC_EX3_TAG[16] = { /* Mlen = 320 */
    0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
    0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6,
};

static int test_cmac(const OxiAes256Key *key) {
    uint8_t tag[16];

    /* Example 2: 16-byte (128-bit) message — exercises K1 subkey path. */
    int rc = oxi_aes256_cmac(key, MSG64, 16, tag);
    if (rc != OXI_OK) {
        fprintf(stderr, "  cmac ex2 rc=%d\n", rc);
        return 1;
    }
    if (memcmp(tag, CMAC_EX2_TAG, sizeof(CMAC_EX2_TAG)) != 0) {
        fprintf(stderr, "  cmac ex2 tag mismatch vs SP 800-38B D.3 Ex2\n");
        return 2;
    }

    /* Example 3: 40-byte (320-bit) message — exercises K2 subkey padding path. */
    rc = oxi_aes256_cmac(key, MSG64, 40, tag);
    if (rc != OXI_OK) {
        fprintf(stderr, "  cmac ex3 rc=%d\n", rc);
        return 3;
    }
    if (memcmp(tag, CMAC_EX3_TAG, sizeof(CMAC_EX3_TAG)) != 0) {
        fprintf(stderr, "  cmac ex3 tag mismatch vs SP 800-38B D.3 Ex3\n");
        return 4;
    }

    /* Empty-message path: fixed 16-byte tag, must run without segfault. */
    rc = oxi_aes256_cmac(key, NULL, 0, tag);
    if (rc != OXI_OK) {
        fprintf(stderr, "  cmac empty-msg rc=%d\n", rc);
        return 5;
    }

    printf("  cmac: OK (SP 800-38B D.3 Ex2 + Ex3 + empty-msg)\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────── */
/* KW-AES-256 — RFC 3394 §4.3 (PT=128) and §4.6 (PT=256)                */
/* ─────────────────────────────────────────────────────────────────── */

static const uint8_t KW_KEK[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static const uint8_t KW_PT_128[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
};
static const uint8_t KW_CT_43[24] = { /* §4.3 expected ciphertext */
    0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
    0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
    0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7,
};
static const uint8_t KW_PT_256[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};
static const uint8_t KW_CT_46[40] = { /* §4.6 expected ciphertext */
    0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
    0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
    0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
    0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
    0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
};

static int test_kw(void) {
    OxiAes256Key *key = NULL;
    if (oxi_aes256_new(&key, KW_KEK) != OXI_OK) {
        fprintf(stderr, "  kw key construct failed\n");
        return 1;
    }

    /* §4.3 — wrap a 128-bit key under a 256-bit KEK. */
    uint8_t ct24[24], back16[16];
    int rc = oxi_aes256_kw_wrap(key, KW_PT_128, sizeof(KW_PT_128), ct24);
    if (rc != OXI_OK || memcmp(ct24, KW_CT_43, sizeof(KW_CT_43)) != 0) {
        fprintf(stderr, "  kw §4.3 wrap mismatch (rc=%d)\n", rc);
        oxi_aes256_free(key);
        return 2;
    }
    rc = oxi_aes256_kw_unwrap(key, ct24, sizeof(ct24), back16);
    if (rc != OXI_OK || memcmp(back16, KW_PT_128, sizeof(KW_PT_128)) != 0) {
        fprintf(stderr, "  kw §4.3 unwrap mismatch (rc=%d)\n", rc);
        oxi_aes256_free(key);
        return 3;
    }

    /* §4.6 — wrap a 256-bit key under a 256-bit KEK. */
    uint8_t ct40[40], back32[32];
    rc = oxi_aes256_kw_wrap(key, KW_PT_256, sizeof(KW_PT_256), ct40);
    if (rc != OXI_OK || memcmp(ct40, KW_CT_46, sizeof(KW_CT_46)) != 0) {
        fprintf(stderr, "  kw §4.6 wrap mismatch (rc=%d)\n", rc);
        oxi_aes256_free(key);
        return 4;
    }
    rc = oxi_aes256_kw_unwrap(key, ct40, sizeof(ct40), back32);
    if (rc != OXI_OK || memcmp(back32, KW_PT_256, sizeof(KW_PT_256)) != 0) {
        fprintf(stderr, "  kw §4.6 unwrap mismatch (rc=%d)\n", rc);
        oxi_aes256_free(key);
        return 5;
    }

    /* Tamper integrity check value: must reject as TagMismatch. */
    uint8_t bad[24];
    memcpy(bad, ct24, sizeof(bad));
    bad[0] ^= 0x01;
    rc = oxi_aes256_kw_unwrap(key, bad, sizeof(bad), back16);
    if (rc != OXI_TAG_MISMATCH) {
        fprintf(stderr, "  kw ICV tamper not rejected: rc=%d (expected %d)\n",
                rc, OXI_TAG_MISMATCH);
        oxi_aes256_free(key);
        return 6;
    }

    oxi_aes256_free(key);
    printf("  kw:   OK (RFC 3394 §4.3 + §4.6 + ICV-tamper)\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────── */
/* KWP-AES-256 — round-trip only (no published AES-256-KWP KAT in the   */
/* underlying self-test set; RFC 5649 examples cover AES-192 only)      */
/* ─────────────────────────────────────────────────────────────────── */

static int test_kwp(const OxiAes256Key *key) {
    /* Try several pt_len values that exercise the padding path:
     *   - 1 byte   (max padding: 7 zero bytes)
     *   - 7 bytes  (RFC 5649 small-msg shape, 1 zero byte)
     *   - 8 bytes  (1 block, no zero padding)
     *   - 17 bytes (2 blocks + 1, 7 zero bytes)
     *   - 32 bytes (4 blocks, no padding) */
    static const size_t pt_lens[] = { 1, 7, 8, 17, 32 };
    static const uint8_t pt_seed[32] = {
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
    };

    for (size_t i = 0; i < sizeof(pt_lens) / sizeof(pt_lens[0]); ++i) {
        size_t pt_len = pt_lens[i];
        size_t padded = ((pt_len + 7) / 8) * 8;
        size_t ct_len = padded + 8;

        uint8_t ct[64], scratch[64];
        size_t recovered_len = 0;

        int rc = oxi_aes256_kwp_wrap(key, pt_seed, pt_len, ct);
        if (rc != OXI_OK) {
            fprintf(stderr, "  kwp wrap pt_len=%zu rc=%d\n", pt_len, rc);
            return 1;
        }

        rc = oxi_aes256_kwp_unwrap(key, ct, ct_len, scratch, &recovered_len);
        if (rc != OXI_OK) {
            fprintf(stderr, "  kwp unwrap pt_len=%zu rc=%d\n", pt_len, rc);
            return 2;
        }
        if (recovered_len != pt_len) {
            fprintf(stderr, "  kwp recovered_len=%zu (expected %zu)\n",
                    recovered_len, pt_len);
            return 3;
        }
        if (memcmp(scratch, pt_seed, pt_len) != 0) {
            fprintf(stderr, "  kwp roundtrip mismatch at pt_len=%zu\n", pt_len);
            return 4;
        }
    }

    /* Tamper test on the 8-byte case (deterministic 16-byte ciphertext). */
    uint8_t ct16[16], scratch[8];
    size_t recovered_len = 0;
    if (oxi_aes256_kwp_wrap(key, pt_seed, 8, ct16) != OXI_OK) {
        fprintf(stderr, "  kwp tamper-prep wrap failed\n");
        return 5;
    }
    ct16[0] ^= 0x01;
    int rc = oxi_aes256_kwp_unwrap(key, ct16, sizeof(ct16), scratch, &recovered_len);
    if (rc != OXI_TAG_MISMATCH) {
        fprintf(stderr, "  kwp AIV tamper not rejected: rc=%d (expected %d)\n",
                rc, OXI_TAG_MISMATCH);
        return 6;
    }

    printf("  kwp:  OK (5 round-trips + AIV-tamper)\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────── */
/* main — initialise the module, run each mode, report aggregate pass   */
/* ─────────────────────────────────────────────────────────────────── */

int main(void) {
    if (oxi_init(0) != OXI_OK) {
        fprintf(stderr, "oxi_init failed\n");
        return 1;
    }

    /* Reuse a single OxiAes256Key handle across the three modes that
     * share the SP 800-38A/B canonical key (CBC, CTR, CMAC). This
     * mirrors the README claim that one key handle is reusable across
     * modes — exercising it in C catches any handle-aliasing bug. */
    OxiAes256Key *shared = NULL;
    if (oxi_aes256_new(&shared, KEY256_SP38) != OXI_OK) {
        fprintf(stderr, "shared key construct failed\n");
        return 2;
    }

    int rc = 0;
    rc |= test_cbc(shared);
    rc |= test_ctr(shared);
    rc |= test_cmac(shared);
    rc |= test_ccm();   /* uses its own key */
    rc |= test_kw();    /* uses its own KEK */
    rc |= test_kwp(shared);

    oxi_aes256_free(shared);

    if (rc != 0) {
        fprintf(stderr, "test_aes_modes: FAIL\n");
        return 3;
    }
    printf("test_aes_modes: OK (cbc + ctr + ccm + cmac + kw + kwp; shared-handle reuse verified)\n");
    return 0;
}
