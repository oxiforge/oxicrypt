/* Input checks and key-generation vectors of ML-KEM-1024 and ML-DSA-87
 * through the C interface.
 *
 *   - oxi_ml_kem_1024_encapsulate_rbg on an ek with one 12-bit coefficient
 *     out of range (the first set to q = 3329, the last set to 3329, or the
 *     first set to 4095) fails the modulus check (FIPS 203 §7.2) and
 *     returns InvalidInput = 5 through a 256-bit handle, through a
 *     CTR_DRBG-AES-128 handle and through a handle never instantiated. The
 *     same call on the valid ek returns RbgTooWeak = 31 and
 *     Uninstantiated = 8 through the last two, so the check runs before the
 *     handle is drawn from.
 *   - oxi_ml_kem_1024_decapsulate on a dk whose stored H(ek) has one byte
 *     flipped fails the hash check (FIPS 203 §7.3) and returns 5; the
 *     valid dk recovers the shared secret.
 *   - oxi_ml_kem_1024_expand_key reproduces, to its documented lengths and
 *     not past them, the ek and dk of NIST ACVP-Server
 *     gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
 *     tgId 3 tcId 51 (commit 112690e8484dba7077709a05b1f3af58ddefdd5d) from
 *     its d and z, read at run time from the .bin files in ML_KEM_DATA_DIR,
 *     which the Makefile sets.
 *   - oxi_ml_dsa_87_expand_key from the seed of ACVP ML-DSA specification
 *     (draft-celi-acvp-ml-dsa-01) §6.1.2 Table 1, row 13, gives a pair whose
 *     SHA2-256(pk || sk) is that row's.
 *
 * Every refusal leaves its outputs and the 16 bytes past them holding their
 * 0xA5 fill.
 */

#include "oxicrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef ML_KEM_DATA_DIR
#error "ML_KEM_DATA_DIR must name the oxicrypt-ml-kem test data directory"
#endif

#define FILL 0xA5
#define GUARD 16
#define EK_LEN 1568
#define DK_LEN 3168
#define CT_LEN 1568
/* dk = dk_PKE (384k bytes) || ek (384k + 32) || H(ek) (32) || z (32), k = 4
 * (FIPS 203 Algorithm 16). */
#define DK_HASH_OFFSET (1536 + EK_LEN)
#define DSA_PK_LEN 2592
#define DSA_SK_LEN 4896

static const uint8_t ML_DSA_87_SEED[32] = {
    0x04, 0x9d, 0x9b, 0x0b, 0x64, 0x6a, 0x2a, 0xc7, 0xf5, 0x0b, 0x63, 0xce, 0x5e, 0x4b, 0xfe, 0x44,
    0xc9, 0xb8, 0x76, 0x34, 0xf4, 0xff, 0x6c, 0x14, 0xc5, 0x13, 0xe3, 0x88, 0xb8, 0xa1, 0xf8, 0x08,
};
static const uint8_t ML_DSA_87_KEY_HASH[32] = {
    0xac, 0x8f, 0xe6, 0xb2, 0xfe, 0x26, 0x59, 0x1b, 0x12, 0x9e, 0xa5, 0x36, 0xa9, 0xa0, 0x01, 0xc7,
    0x85, 0xd8, 0xac, 0xbd, 0xd9, 0x48, 0x9f, 0x6e, 0x51, 0x46, 0x9a, 0x15, 0x6e, 0x9e, 0x63, 0x5d,
};

static int failures;

static uint8_t d[32], z[32], want_ek[EK_LEN], want_dk[DK_LEN];
static uint8_t ek[EK_LEN + GUARD], dk[DK_LEN + GUARD], bad[DK_LEN];
static uint8_t ct[CT_LEN + GUARD], ss[32 + GUARD], ss2[32 + GUARD];
static uint8_t pk_sk[DSA_PK_LEN + DSA_SK_LEN];

static void fill(uint8_t *b, size_t len) { memset(b, FILL, len + GUARD); }

static int untouched(const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len + GUARD; i++)
        if (b[i] != FILL) return 0;
    return 1;
}

static void expect(const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "%s: rc=%d, expected %d\n", check, rc, want);
        failures++;
    }
}

static void expect_true(const char *check, int ok) {
    if (!ok) {
        fprintf(stderr, "%s: failed\n", check);
        failures++;
    }
}

/* Reads exactly `len` bytes; a shorter or longer file fails. */
static int read_vector(const char *name, uint8_t *out, size_t len) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", ML_KEM_DATA_DIR, name);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return 0;
    }
    size_t got = fread(out, 1, len, f);
    int extra = fgetc(f) != EOF;
    fclose(f);
    if (got != len || extra) {
        fprintf(stderr, "%s is not %zu bytes\n", path, len);
        return 0;
    }
    return 1;
}

/* Written to the end of its length and not past it: the last 16 bytes are
 * not all the fill, and the guard after them is. */
static int written(const uint8_t *b, size_t len) {
    int tail_is_fill = 1;
    for (size_t i = len - 16; i < len; i++)
        if (b[i] != FILL) tail_is_fill = 0;
    return !tail_is_fill && untouched(b + len, 0);
}

/* Coefficient i of the encoded t-hat takes the 12 bits starting at bit 12i,
 * least significant first (FIPS 203 Algorithm 5). */
static void set_coefficient(uint8_t *e, size_t i, unsigned v) {
    size_t byte = 3 * (i / 2);
    if (i % 2 == 0) {
        e[byte] = (uint8_t)(v & 0xFF);
        e[byte + 1] = (uint8_t)((e[byte + 1] & 0xF0) | (v >> 8));
    } else {
        e[byte + 1] = (uint8_t)((e[byte + 1] & 0x0F) | ((v & 0x0F) << 4));
        e[byte + 2] = (uint8_t)(v >> 4);
    }
}

static void encaps_refused(const char *check, const uint8_t *key, OxiDrbg *h, int want) {
    fill(ss, 32);
    fill(ct, CT_LEN);
    expect(check, oxi_ml_kem_1024_encapsulate_rbg(key, h, ss, ct), want);
    expect_true(check, untouched(ss, 32) && untouched(ct, CT_LEN));
}

int main(void) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }
    if (!read_vector("mlkem1024_nist_keygen_d.bin", d, 32) ||
        !read_vector("mlkem1024_nist_keygen_z.bin", z, 32) ||
        !read_vector("mlkem1024_nist_keygen_ek.bin", want_ek, EK_LEN) ||
        !read_vector("mlkem1024_nist_keygen_dk.bin", want_dk, DK_LEN))
        return 1;

    OxiDrbg *strong = NULL, *weak = NULL, *never = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&strong) != 0 || oxi_drbg_instantiate(strong, NULL, 0) != 0 ||
        oxi_ctr_drbg_aes128_new_rbg(&weak) != 0 || oxi_drbg_instantiate(weak, NULL, 0) != 0 ||
        oxi_hmac_drbg_sha256_new_rbg(&never) != 0) {
        fprintf(stderr, "DRBG handle setup failed\n");
        return 1;
    }

    fill(ek, EK_LEN);
    fill(dk, DK_LEN);
    expect("ML-KEM-1024 expand_key of the vector seeds",
           oxi_ml_kem_1024_expand_key(d, z, ek, dk), OXI_RESULT_OK);
    expect_true("ML-KEM-1024 expand_key output written to its lengths",
                written(ek, EK_LEN) && written(dk, DK_LEN));
    expect_true("ML-KEM-1024 expand_key reproduces the vector ek and dk",
                memcmp(ek, want_ek, EK_LEN) == 0 && memcmp(dk, want_dk, DK_LEN) == 0);

    static const struct {
        size_t index;
        unsigned value;
        const char *name;
    } NON_CANONICAL[] = {
        {0, 3329, "coefficient 0 = 3329"},
        {1023, 3329, "coefficient 1023 = 3329"},
        {0, 4095, "coefficient 0 = 4095"},
    };
    for (size_t i = 0; i < sizeof NON_CANONICAL / sizeof NON_CANONICAL[0]; i++) {
        char check[128];
        memcpy(bad, ek, EK_LEN);
        set_coefficient(bad, NON_CANONICAL[i].index, NON_CANONICAL[i].value);
        snprintf(check, sizeof check, "encapsulate_rbg, ek %s", NON_CANONICAL[i].name);
        encaps_refused(check, bad, strong, OXI_RESULT_INVALID_INPUT);
        snprintf(check, sizeof check, "encapsulate_rbg, ek %s, CTR_DRBG-AES-128",
                 NON_CANONICAL[i].name);
        encaps_refused(check, bad, weak, OXI_RESULT_INVALID_INPUT);
        snprintf(check, sizeof check, "encapsulate_rbg, ek %s, uninstantiated handle",
                 NON_CANONICAL[i].name);
        encaps_refused(check, bad, never, OXI_RESULT_INVALID_INPUT);
    }
    encaps_refused("encapsulate_rbg, valid ek, CTR_DRBG-AES-128", ek, weak,
                   OXI_RESULT_RBG_TOO_WEAK);
    encaps_refused("encapsulate_rbg, valid ek, uninstantiated handle", ek, never,
                   OXI_RESULT_UNINSTANTIATED);

    fill(ss, 32);
    expect("encapsulate_rbg, valid ek", oxi_ml_kem_1024_encapsulate_rbg(ek, strong, ss, ct),
           OXI_RESULT_OK);

    memcpy(bad, dk, DK_LEN);
    bad[DK_HASH_OFFSET] ^= 0x01;
    fill(ss2, 32);
    expect("decapsulate, dk with a flipped H(ek) byte", oxi_ml_kem_1024_decapsulate(bad, ct, ss2),
           OXI_RESULT_INVALID_INPUT);
    expect_true("decapsulate, ss untouched after the hash check", untouched(ss2, 32));
    expect("decapsulate, valid dk", oxi_ml_kem_1024_decapsulate(dk, ct, ss2), OXI_RESULT_OK);
    expect_true("decapsulate recovers the shared secret", memcmp(ss, ss2, 32) == 0);

    expect("ML-DSA-87 expand_key of the vector seed",
           oxi_ml_dsa_87_expand_key(ML_DSA_87_SEED, pk_sk, pk_sk + DSA_PK_LEN), OXI_RESULT_OK);
    uint8_t digest[32];
    expect("SHA2-256 of pk || sk", oxi_sha256(pk_sk, sizeof pk_sk, digest), OXI_RESULT_OK);
    expect_true("ML-DSA-87 expand_key reproduces the vector key hash",
                memcmp(digest, ML_DSA_87_KEY_HASH, 32) == 0);

    oxi_drbg_free(strong);
    oxi_drbg_free(weak);
    oxi_drbg_free(never);
    if (failures != 0) {
        fprintf(stderr, "test_pq_input_checks: %d failures\n", failures);
        return 1;
    }
    printf("test_pq_input_checks: OK (FIPS 203 §7.2 and §7.3 checks, ML-KEM-1024 and ML-DSA-87 "
           "key-generation vectors)\n");
    return 0;
}
