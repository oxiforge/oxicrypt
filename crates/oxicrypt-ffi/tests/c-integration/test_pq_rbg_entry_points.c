/* Contract of the fifteen ML-DSA and ML-KEM functions that take an OxiDrbg
 * handle or a stored seed: oxi_ml_dsa_NN_keygen_rbg and _expand_key for
 * NN = 44, 65, 87, and oxi_ml_kem_NNN_keygen_rbg, _expand_key and
 * _encapsulate_rbg for NNN = 512, 768, 1024.
 *
 * Under profile 0, through a handle of each of HMAC_DRBG-SHA-256,
 * Hash_DRBG-SHA-256, CTR_DRBG-AES-256, CTR_DRBG-AES-192 and
 * CTR_DRBG-AES-128:
 *
 *   - a handle at or above the set's strength floor in oxicrypt.h (256
 *     bits for ML-DSA-87 and ML-KEM-1024, 192 for ML-DSA-44, ML-DSA-65 and
 *     ML-KEM-768, 128 for ML-KEM-512) returns 0 from key generation, with
 *     and without seed_out, and from encapsulation; each output is written
 *     to its documented length and not one byte past it; key expansion of
 *     the returned seed reproduces the pair; decapsulation recovers the
 *     shared secret; and a pair generated with seed_out NULL signs and
 *     verifies, or encapsulates and decapsulates;
 *   - a handle below the floor returns RbgTooWeak = 31.
 *
 * Every function returns NullPointer = 10 for each required pointer passed
 * NULL, and InvalidInput = 5 for two outputs at the same address, an output
 * over a seed or over ek, an output or ek over the handle, and two outputs
 * sharing one byte. Each function driven prints row=<name>; the Makefile
 * compares the sorted rows with the functions oxicrypt.h declares.
 *
 * In a child process initialised with profile 1 (CNSA 2.0),
 * oxi_ml_dsa_87_keygen_rbg, oxi_ml_kem_1024_keygen_rbg and
 * oxi_ml_kem_1024_encapsulate_rbg return 0 through a CTR_DRBG-AES-256
 * handle, and oxi_ml_kem_1024_keygen_rbg returns AlgorithmRestricted = 6
 * through an HMAC_DRBG-SHA-256 handle, which that profile does not admit.
 * The refused handle is never instantiated: the profile check precedes
 * Uninstantiated = 8 in the documented order.
 *
 * Built with OXICRYPT_FAULT_INJECTION defined (the Makefile's test-fault),
 * one child process per function of the six key generations and six key
 * expansions arms its family's pairwise consistency fault: the call returns
 * ConditionalTestFailed = 3 (FIPS 140-3 IG 10.3.A), then the same call and
 * oxi_sha256 return NotOperational = 1. Each runs in its own process
 * because the error state lasts until the process ends.
 *
 * Every refusal leaves every output and the 16 bytes past it holding their
 * 0xA5 fill, and the first 16 bytes of the handle unchanged.
 */

#include "oxicrypt.h"
#ifdef OXICRYPT_FAULT_INJECTION
#include "oxicrypt-test.h"
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FILL 0xA5
#define GUARD 16
#define MAX_PK 2592
#define MAX_SK 4896
#define MAX_CT 1568
#define MAX_SIG 4627
#define BOTH_LEN (MAX_PK + MAX_SK + 64)

static int failures;

static uint8_t pk[MAX_PK + GUARD], sk[MAX_SK + GUARD], seed[64 + GUARD];
static uint8_t pk2[MAX_PK + GUARD], sk2[MAX_SK + GUARD];
static uint8_t ct[MAX_CT + GUARD], ss[32 + GUARD], ss2[32 + GUARD], sig[MAX_SIG];
/* The argument rows place every output in this one region, so an overlap
 * row can point one argument into another. */
static uint8_t both[BOTH_LEN + GUARD];
#define P both
#define S (both + MAX_PK)
#define SEED (both + MAX_PK + MAX_SK)

static const uint8_t fixed_seed[64] = {1};
static const uint8_t msg[3] = {'a', 'b', 'c'};

static void fill(uint8_t *b, size_t len) { memset(b, FILL, len + GUARD); }

static int untouched(const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len + GUARD; i++)
        if (b[i] != FILL) return 0;
    return 1;
}

/* Written to the end of its length and not past it: the last 16 bytes are
 * not all the fill, and the guard after them is. */
static int written(const uint8_t *b, size_t len) {
    size_t tail = len < 16 ? len : 16;
    int tail_is_fill = 1;
    for (size_t i = len - tail; i < len; i++)
        if (b[i] != FILL) tail_is_fill = 0;
    if (tail_is_fill) return 0;
    for (size_t i = len; i < len + GUARD; i++)
        if (b[i] != FILL) return 0;
    return 1;
}

static const char *family = "";

static void expect(const char *name, const char *check, int rc, int want) {
    if (rc != want) {
        fprintf(stderr, "%s%s, %s: rc=%d, expected %d\n", family, name, check, rc, want);
        failures++;
    }
}

static void expect_true(const char *name, const char *check, int ok) {
    if (!ok) {
        fprintf(stderr, "%s%s, %s: failed\n", family, name, check);
        failures++;
    }
}

typedef struct {
    const char *name;
    int (*new_rbg)(OxiDrbg **);
    uint32_t strength;
} Family;

static const Family FAMILIES[] = {
    {"HMAC_DRBG-SHA-256", oxi_hmac_drbg_sha256_new_rbg, 256},
    {"Hash_DRBG-SHA-256", oxi_hash_drbg_sha256_new_rbg, 256},
    {"CTR_DRBG-AES-256", oxi_ctr_drbg_aes256_new_rbg, 256},
    {"CTR_DRBG-AES-192", oxi_ctr_drbg_aes192_new_rbg, 192},
    {"CTR_DRBG-AES-128", oxi_ctr_drbg_aes128_new_rbg, 128},
};
#define N_FAMILIES (sizeof FAMILIES / sizeof FAMILIES[0])

typedef struct {
    const char *name, *keygen_name, *expand_name;
    size_t pk_len, sk_len, sig_len;
    uint32_t floor;
    int (*keygen)(OxiDrbg *, uint8_t *, uint8_t *, uint8_t *);
    int (*expand)(const uint8_t *, uint8_t *, uint8_t *);
    int (*sign)(const uint8_t *, const uint8_t *, uintptr_t, const uint8_t *, uintptr_t,
                uint8_t *);
    int (*verify)(const uint8_t *, const uint8_t *, uintptr_t, const uint8_t *, uintptr_t,
                  const uint8_t *);
} DsaSet;

#define DSA_SET(nn, pk_len, sk_len, sig_len, floor)                                             \
    {"ML-DSA-" #nn, "oxi_ml_dsa_" #nn "_keygen_rbg", "oxi_ml_dsa_" #nn "_expand_key", pk_len, \
     sk_len, sig_len, floor, oxi_ml_dsa_##nn##_keygen_rbg, oxi_ml_dsa_##nn##_expand_key,       \
     oxi_ml_dsa_##nn##_sign, oxi_ml_dsa_##nn##_verify}

static const DsaSet DSA[] = {
    DSA_SET(44, 1312, 2560, 2420, 192),
    DSA_SET(65, 1952, 4032, 3309, 192),
    DSA_SET(87, 2592, 4896, 4627, 256),
};

typedef struct {
    const char *name, *keygen_name, *expand_name, *encaps_name;
    size_t ek_len, dk_len, ct_len;
    uint32_t floor;
    int (*keygen)(OxiDrbg *, uint8_t *, uint8_t *, uint8_t *);
    int (*expand)(const uint8_t *, const uint8_t *, uint8_t *, uint8_t *);
    int (*encaps)(const uint8_t *, OxiDrbg *, uint8_t *, uint8_t *);
    int (*decaps)(const uint8_t *, const uint8_t *, uint8_t *);
} KemSet;

#define KEM_SET(nnn, ek_len, dk_len, ct_len, floor)                                           \
    {"ML-KEM-" #nnn, "oxi_ml_kem_" #nnn "_keygen_rbg", "oxi_ml_kem_" #nnn "_expand_key",    \
     "oxi_ml_kem_" #nnn "_encapsulate_rbg", ek_len, dk_len, ct_len, floor,                    \
     oxi_ml_kem_##nnn##_keygen_rbg, oxi_ml_kem_##nnn##_expand_key,                            \
     oxi_ml_kem_##nnn##_encapsulate_rbg, oxi_ml_kem_##nnn##_decapsulate}

static const KemSet KEM[] = {
    KEM_SET(512, 800, 1632, 768, 128),
    KEM_SET(768, 1184, 2400, 1088, 192),
    KEM_SET(1024, 1568, 3168, 1568, 256),
};

static OxiDrbg *handle(int (*new_rbg)(OxiDrbg **), const char *name) {
    OxiDrbg *h = NULL;
    if (new_rbg(&h) != 0 || oxi_drbg_instantiate(h, NULL, 0) != 0) {
        fprintf(stderr, "%s: handle setup failed\n", name);
        failures++;
        oxi_drbg_free(h);
        return NULL;
    }
    return h;
}

static void dsa_through(const DsaSet *s, const Family *f, OxiDrbg *h) {
    fill(pk, s->pk_len);
    fill(sk, s->sk_len);
    fill(seed, 32);
    int rc = s->keygen(h, pk, sk, seed);
    if (f->strength < s->floor) {
        expect(s->name, f->name, rc, OXI_RESULT_RBG_TOO_WEAK);
        expect_true(s->name, "outputs untouched after RbgTooWeak",
                    untouched(pk, s->pk_len) && untouched(sk, s->sk_len) && untouched(seed, 32));
        return;
    }
    expect(s->name, f->name, rc, OXI_RESULT_OK);
    expect_true(s->name, "pk, sk and seed written to their lengths",
                written(pk, s->pk_len) && written(sk, s->sk_len) && written(seed, 32));
    fill(pk2, s->pk_len);
    fill(sk2, s->sk_len);
    expect(s->name, "expand_key of the returned seed", s->expand(seed, pk2, sk2), OXI_RESULT_OK);
    expect_true(s->name, "expand_key output written to its lengths",
                written(pk2, s->pk_len) && written(sk2, s->sk_len));
    expect_true(s->name, "expand_key reproduces the pair",
                memcmp(pk, pk2, s->pk_len) == 0 && memcmp(sk, sk2, s->sk_len) == 0);
    fill(pk, s->pk_len);
    fill(sk, s->sk_len);
    expect(s->name, "keygen_rbg, seed_out NULL", s->keygen(h, pk, sk, NULL), OXI_RESULT_OK);
    expect_true(s->name, "pk and sk written with seed_out NULL",
                written(pk, s->pk_len) && written(sk, s->sk_len));
    expect(s->name, "sign with the seed_out NULL pair", s->sign(sk, msg, 3, msg, 0, sig),
           OXI_RESULT_OK);
    expect(s->name, "verify with the seed_out NULL pair", s->verify(pk, msg, 3, msg, 0, sig),
           OXI_RESULT_OK);
}

static void kem_through(const KemSet *s, const Family *f, OxiDrbg *h, OxiDrbg *strong) {
    fill(pk, s->ek_len);
    fill(sk, s->dk_len);
    fill(seed, 64);
    int rc = s->keygen(h, pk, sk, seed);
    if (f->strength < s->floor) {
        expect(s->name, f->name, rc, OXI_RESULT_RBG_TOO_WEAK);
        expect_true(s->name, "outputs untouched after RbgTooWeak",
                    untouched(pk, s->ek_len) && untouched(sk, s->dk_len) && untouched(seed, 64));
        if (s->keygen(strong, pk, sk, NULL) != 0) {
            fprintf(stderr, "%s: key pair setup failed\n", s->name);
            failures++;
            return;
        }
        fill(ss, 32);
        fill(ct, s->ct_len);
        expect(s->name, "encapsulate_rbg through a weak handle", s->encaps(pk, h, ss, ct),
               OXI_RESULT_RBG_TOO_WEAK);
        expect_true(s->name, "ss and ct untouched after RbgTooWeak",
                    untouched(ss, 32) && untouched(ct, s->ct_len));
        return;
    }
    expect(s->name, f->name, rc, OXI_RESULT_OK);
    expect_true(s->name, "ek, dk and seed written to their lengths",
                written(pk, s->ek_len) && written(sk, s->dk_len) && written(seed, 64));
    fill(pk2, s->ek_len);
    fill(sk2, s->dk_len);
    expect(s->name, "expand_key of the returned seed", s->expand(seed, seed + 32, pk2, sk2),
           OXI_RESULT_OK);
    expect_true(s->name, "expand_key output written to its lengths",
                written(pk2, s->ek_len) && written(sk2, s->dk_len));
    expect_true(s->name, "expand_key reproduces the pair",
                memcmp(pk, pk2, s->ek_len) == 0 && memcmp(sk, sk2, s->dk_len) == 0);
    fill(ss, 32);
    fill(ct, s->ct_len);
    expect(s->name, "encapsulate_rbg", s->encaps(pk, h, ss, ct), OXI_RESULT_OK);
    expect_true(s->name, "ss and ct written to their lengths",
                written(ss, 32) && written(ct, s->ct_len));
    fill(ss2, 32);
    expect(s->name, "decapsulate", s->decaps(sk, ct, ss2), OXI_RESULT_OK);
    expect_true(s->name, "decapsulate output written to its length", written(ss2, 32));
    expect_true(s->name, "decapsulate recovers the shared secret", memcmp(ss, ss2, 32) == 0);
    fill(pk, s->ek_len);
    fill(sk, s->dk_len);
    expect(s->name, "keygen_rbg, seed_out NULL", s->keygen(h, pk, sk, NULL), OXI_RESULT_OK);
    expect_true(s->name, "ek and dk written with seed_out NULL",
                written(pk, s->ek_len) && written(sk, s->dk_len));
    fill(ss, 32);
    fill(ss2, 32);
    expect(s->name, "encapsulate_rbg to the seed_out NULL pair", s->encaps(pk, h, ss, ct),
           OXI_RESULT_OK);
    expect(s->name, "decapsulate with the seed_out NULL pair", s->decaps(sk, ct, ss2),
           OXI_RESULT_OK);
    expect_true(s->name, "the seed_out NULL pair agrees on the shared secret",
                memcmp(ss, ss2, 32) == 0);
}

static uint8_t handle_snapshot[16];

/* One refusal: `both` is filled before the call and must hold its fill
 * after it, and the first 16 bytes of the handle must not change. */
#define REFUSE(fn, check, call, want)                                                         \
    do {                                                                                      \
        memset(both, FILL, sizeof both);                                                      \
        memcpy(handle_snapshot, (const void *)h, sizeof handle_snapshot);                     \
        expect(fn, check, (call), (want));                                                    \
        expect_true(fn, check,                                                                \
                    untouched(both, BOTH_LEN) &&                                              \
                        memcmp(handle_snapshot, (const void *)h, sizeof handle_snapshot) == 0); \
    } while (0)

#define HP ((uint8_t *)(void *)h)

static void dsa_rows(const DsaSet *s, OxiDrbg *h) {
    const char *n = s->keygen_name;
    REFUSE(n, "NULL rbg", s->keygen(NULL, P, S, SEED), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL pk_out", s->keygen(h, NULL, S, SEED), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL sk_out", s->keygen(h, P, NULL, SEED), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "pk_out == sk_out", s->keygen(h, P, P, NULL), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "seed_out inside pk_out", s->keygen(h, P, S, P + 8), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "sk_out sharing pk_out's last byte", s->keygen(h, P, P + s->pk_len - 1, NULL),
           OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "pk_out over the handle", s->keygen(h, HP, S, NULL), OXI_RESULT_INVALID_INPUT);
    printf("row=%s\n", n);

    n = s->expand_name;
    REFUSE(n, "NULL seed", s->expand(NULL, P, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL pk_out", s->expand(fixed_seed, NULL, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL sk_out", s->expand(fixed_seed, P, NULL), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "pk_out == sk_out", s->expand(fixed_seed, P, P), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "pk_out over the seed", s->expand(P + 8, P, S), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "sk_out sharing pk_out's last byte", s->expand(fixed_seed, P, P + s->pk_len - 1),
           OXI_RESULT_INVALID_INPUT);
    printf("row=%s\n", n);
}

static void kem_rows(const KemSet *s, OxiDrbg *h) {
    const char *n = s->keygen_name;
    REFUSE(n, "NULL rbg", s->keygen(NULL, P, S, SEED), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL ek_out", s->keygen(h, NULL, S, SEED), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL dk_out", s->keygen(h, P, NULL, SEED), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "ek_out == dk_out", s->keygen(h, P, P, NULL), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "seed_out inside ek_out", s->keygen(h, P, S, P + 8), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "dk_out sharing ek_out's last byte", s->keygen(h, P, P + s->ek_len - 1, NULL),
           OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "ek_out over the handle", s->keygen(h, HP, S, NULL), OXI_RESULT_INVALID_INPUT);
    printf("row=%s\n", n);

    n = s->expand_name;
    const uint8_t *d = fixed_seed, *z = fixed_seed + 32;
    REFUSE(n, "NULL d", s->expand(NULL, z, P, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL z", s->expand(d, NULL, P, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL ek_out", s->expand(d, z, NULL, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL dk_out", s->expand(d, z, P, NULL), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "ek_out == dk_out", s->expand(d, z, P, P), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "ek_out over d", s->expand(P + 8, z, P, S), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "dk_out over z", s->expand(d, S + 8, P, S), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "dk_out sharing ek_out's last byte", s->expand(d, z, P, P + s->ek_len - 1),
           OXI_RESULT_INVALID_INPUT);
    printf("row=%s\n", n);

    n = s->encaps_name;
    static uint8_t key[MAX_PK];
    if (s->expand(d, z, key, sk2) != 0) {
        fprintf(stderr, "%s: key pair setup failed\n", n);
        failures++;
        return;
    }
    REFUSE(n, "NULL ek", s->encaps(NULL, h, SEED, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL rbg", s->encaps(key, NULL, SEED, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL ss_out", s->encaps(key, h, NULL, S), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "NULL ct_out", s->encaps(key, h, SEED, NULL), OXI_RESULT_NULL_POINTER);
    REFUSE(n, "ss_out == ct_out", s->encaps(key, h, S, S), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "ct_out over ek", s->encaps(P, h, SEED, P), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "ss_out over the handle", s->encaps(key, h, HP, S), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "ek over the handle", s->encaps(HP, h, SEED, S), OXI_RESULT_INVALID_INPUT);
    REFUSE(n, "ss_out sharing ct_out's last byte", s->encaps(key, h, S + s->ct_len - 1, S),
           OXI_RESULT_INVALID_INPUT);
    printf("row=%s\n", n);
}

static int profile_1_child(int unused) {
    (void)unused;
    if (oxi_init(1) != 0 || oxi_active_profile() != 1) {
        fprintf(stderr, "profile 1: oxi_init(1) did not activate CNSA 2.0\n");
        return 1;
    }
    OxiDrbg *aes256 = handle(oxi_ctr_drbg_aes256_new_rbg, "profile 1, CTR_DRBG-AES-256");
    if (aes256 == NULL) return 1;
    fill(pk, 2592);
    fill(sk, 4896);
    expect("profile 1", "ML-DSA-87 keygen_rbg through CTR_DRBG-AES-256",
           oxi_ml_dsa_87_keygen_rbg(aes256, pk, sk, NULL), OXI_RESULT_OK);
    expect_true("profile 1", "pk and sk written", written(pk, 2592) && written(sk, 4896));
    fill(pk, 1568);
    fill(sk, 3168);
    expect("profile 1", "ML-KEM-1024 keygen_rbg through CTR_DRBG-AES-256",
           oxi_ml_kem_1024_keygen_rbg(aes256, pk, sk, NULL), OXI_RESULT_OK);
    expect_true("profile 1", "ek and dk written", written(pk, 1568) && written(sk, 3168));
    fill(ss, 32);
    fill(ct, 1568);
    expect("profile 1", "ML-KEM-1024 encapsulate_rbg through CTR_DRBG-AES-256",
           oxi_ml_kem_1024_encapsulate_rbg(pk, aes256, ss, ct), OXI_RESULT_OK);
    expect_true("profile 1", "ss and ct written", written(ss, 32) && written(ct, 1568));
    oxi_drbg_free(aes256);

    OxiDrbg *sha256 = NULL;
    if (oxi_hmac_drbg_sha256_new_rbg(&sha256) != 0) {
        fprintf(stderr, "profile 1: HMAC_DRBG-SHA-256 handle construction failed\n");
        return 1;
    }
    fill(pk, 1568);
    fill(sk, 3168);
    expect("profile 1", "ML-KEM-1024 keygen_rbg through HMAC_DRBG-SHA-256",
           oxi_ml_kem_1024_keygen_rbg(sha256, pk, sk, NULL), OXI_RESULT_ALGORITHM_RESTRICTED);
    expect_true("profile 1", "outputs untouched after AlgorithmRestricted",
                untouched(pk, 1568) && untouched(sk, 3168));
    oxi_drbg_free(sha256);
    return failures != 0;
}

#ifdef OXICRYPT_FAULT_INJECTION
/* Fault child `which`: 0-2 the ML-DSA key generations, 3-5 the ML-DSA key
 * expansions, 6-8 the ML-KEM key generations, 9-11 the ML-KEM key
 * expansions, each in set order. */
static int pct_child(int which) {
    if (oxi_init(0) != 0) {
        fprintf(stderr, "fault child %d: oxi_init failed\n", which);
        return 1;
    }
    OxiDrbg *h = handle(oxi_hmac_drbg_sha256_new_rbg, "fault child");
    if (h == NULL) return 1;
    const DsaSet *dsa = which < 6 ? &DSA[which % 3] : NULL;
    const KemSet *kem = which < 6 ? NULL : &KEM[which % 3];
    int expansion = (which / 3) % 2;
    const char *n = dsa != NULL ? (expansion ? dsa->expand_name : dsa->keygen_name)
                                : (expansion ? kem->expand_name : kem->keygen_name);
    int want = OXI_RESULT_CONDITIONAL_TEST_FAILED;
    for (int call = 0; call < 2; call++) {
        if (call == 0 && dsa != NULL) oxi_test_corrupt_next_pk_ml_dsa();
        if (call == 0 && kem != NULL) oxi_test_corrupt_next_dk_ml_kem();
        int rc;
        memset(both, FILL, sizeof both);
        if (dsa != NULL)
            rc = expansion ? dsa->expand(fixed_seed, P, S) : dsa->keygen(h, P, S, SEED);
        else
            rc = expansion ? kem->expand(fixed_seed, fixed_seed + 32, P, S)
                           : kem->keygen(h, P, S, SEED);
        expect(n, call == 0 ? "with the PCT armed" : "the next call", rc, want);
        expect_true(n, "outputs untouched", untouched(both, BOTH_LEN));
        want = OXI_RESULT_NOT_OPERATIONAL;
    }
    uint8_t digest[32];
    expect(n, "the next oxi_sha256", oxi_sha256(msg, 3, digest), OXI_RESULT_NOT_OPERATIONAL);
    return failures != 0;
}
#define PCT_CHILDREN 12
#endif

/* Runs `body` in a child forked before this process initialises the
 * module, so the child's oxi_init is the first in its process. The alarm
 * fails a child that hangs instead of hanging the run. */
static void in_child(const char *name, int (*body)(int), int arg) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork failed\n", name);
        failures++;
        return;
    }
    if (pid == 0) {
        failures = 0;
        alarm(600);
        _exit(body(arg));
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: child failed (status %d)\n", name, status);
        failures++;
    }
}

int main(void) {
    in_child("profile 1", profile_1_child, 0);
#ifdef OXICRYPT_FAULT_INJECTION
    for (int i = 0; i < PCT_CHILDREN; i++) in_child("pairwise consistency fault", pct_child, i);
#endif

    if (oxi_init(0) != 0) {
        fprintf(stderr, "oxi_init(Unrestricted) failed\n");
        return 1;
    }
    OxiDrbg *strong = handle(oxi_hmac_drbg_sha256_new_rbg, "HMAC_DRBG-SHA-256");
    if (strong == NULL) return 1;

    for (size_t f = 0; f < N_FAMILIES; f++) {
        OxiDrbg *h = handle(FAMILIES[f].new_rbg, FAMILIES[f].name);
        if (h == NULL) continue;
        char prefix[64];
        snprintf(prefix, sizeof prefix, "%s: ", FAMILIES[f].name);
        family = prefix;
        uint32_t bits = 0;
        expect(FAMILIES[f].name, "strength_bits", oxi_drbg_strength_bits(h, &bits), OXI_RESULT_OK);
        expect(FAMILIES[f].name, "strength", (int)bits, (int)FAMILIES[f].strength);
        for (size_t i = 0; i < 3; i++) dsa_through(&DSA[i], &FAMILIES[f], h);
        for (size_t i = 0; i < 3; i++) kem_through(&KEM[i], &FAMILIES[f], h, strong);
        oxi_drbg_free(h);
    }
    family = "";
    for (size_t i = 0; i < 3; i++) dsa_rows(&DSA[i], strong);
    for (size_t i = 0; i < 3; i++) kem_rows(&KEM[i], strong);
    oxi_drbg_free(strong);

    if (failures != 0) {
        fprintf(stderr, "test_pq_rbg_entry_points: %d failures\n", failures);
        return 1;
    }
    printf("test_pq_rbg_entry_points: OK (through %zu DRBG families)\n", N_FAMILIES);
    return 0;
}
