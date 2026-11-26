/*
 * Hashes, signs and establishes a shared secret through the oxicrypt C
 * library, checking each result against the line examples/README.md expects.
 *
 *   example <bundle-dir> <out-dir>
 *   example <bundle-dir> decaps <dk-file> <ct-file>
 *
 * The library is linked when the program is built, so <bundle-dir> is not
 * read; it is taken so that every example has the same arguments.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "oxicrypt.h"

static const char MESSAGE[] = "The quick brown fox jumps over the lazy dog";
static const size_t SIG_FLIP_BYTE = 0;
static const size_t CT_FLIP_BYTE = 0;
static const char PERSONALIZATION[] = "oxicrypt example";
static const char SHA256_ABC[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

enum {
    PK_LEN = 2592,
    SK_LEN = 4896,
    SIG_LEN = 4627,
    EK_LEN = 1568,
    DK_LEN = 3168,
    CT_LEN = 1568,
    SS_LEN = 32,
};

static OxiDrbg *rbg;
static uint8_t sk[SK_LEN], dk[DK_LEN], ss[SS_LEN], ss2[SS_LEN];
static char ss_hex[2 * SS_LEN + 1];

/* A store through a volatile pointer is one the compiler may not remove as
 * dead, which a memset just before exit would be. */
static void wipe(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) {
        *v++ = 0;
    }
}

/* Frees the DRBG handle, which wipes its state, and wipes every secret. */
static void release(void) {
    oxi_drbg_free(rbg);
    rbg = NULL;
    wipe(sk, sizeof sk);
    wipe(dk, sizeof dk);
    wipe(ss, sizeof ss);
    wipe(ss2, sizeof ss2);
    wipe(ss_hex, sizeof ss_hex);
}

static void fail(void) {
    release();
    exit(1);
}

static void hex(const uint8_t *p, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        snprintf(out + 2 * i, 3, "%02x", p[i]);
    }
}

/* Prints `got` when it equals `want`; otherwise prints both and exits 1. */
static void expect(const char *want, const char *got) {
    if (strcmp(want, got) != 0) {
        fprintf(stderr, "expected: %s\n     got: %s\n", want, got);
        fail();
    }
    printf("%s\n", got);
}

/* Expects `<what> ok`, printing `<what> returned <rc>` against it otherwise. */
static void expect_ok(const char *what, int rc) {
    char want[128], got[128];
    snprintf(want, sizeof want, "%s ok", what);
    if (rc == OXI_RESULT_OK) {
        snprintf(got, sizeof got, "%s ok", what);
    } else {
        snprintf(got, sizeof got, "%s returned %d", what, rc);
    }
    expect(want, got);
}

/* Exits 1 naming the call when it returned other than Ok. */
static void check(const char *call, int rc) {
    if (rc != OXI_RESULT_OK) {
        fprintf(stderr, "%s returned %d\n", call, rc);
        fail();
    }
}

/* Writes the file, readable and writable by its owner only when `owner_only`
 * is set, as the decapsulation key is. On Windows the file takes the access
 * control list of its directory. */
static void write_file(const char *dir, const char *name, const void *p, size_t n, int owner_only) {
    char path[4096];
    int len = snprintf(path, sizeof path, "%s/%s", dir, name);
    if (len < 0 || (size_t)len >= sizeof path) {
        fprintf(stderr, "%s/%s: the path is longer than %zu bytes\n", dir, name, sizeof path - 1);
        fail();
    }
    FILE *f;
#ifdef _WIN32
    (void)owner_only;
    f = fopen(path, "wb");
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, owner_only ? 0600 : 0644);
    /* An existing file keeps its mode through O_TRUNC, so it is set here. */
    if (fd >= 0 && owner_only && fchmod(fd, 0600) != 0) {
        close(fd);
        fd = -1;
    }
    f = fd < 0 ? NULL : fdopen(fd, "wb");
    if (f == NULL && fd >= 0) {
        close(fd);
    }
#endif
    if (f == NULL) {
        perror(path);
        fail();
    }
    if (fwrite(p, 1, n, f) != n) {
        perror(path);
        fclose(f);
        fail();
    }
    if (fclose(f) != 0) {
        perror(path);
        fail();
    }
}

static void read_file(const char *path, uint8_t *p, size_t n) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        fail();
    }
    size_t got = fread(p, 1, n, f);
    int extra = fgetc(f);
    fclose(f);
    if (got != n || extra != EOF) {
        fprintf(stderr, "%s: expected %zu bytes\n", path, n);
        fail();
    }
}

/* Starts the module and reads its integrity result. Prints the fingerprint
 * of the key the library trusts to stderr, and exits 1 unless the module is
 * operational with its integrity test passed (status 1), leading with the
 * condition that failed. */
static void init(void) {
    int rc = oxi_init(0);
    int status = oxi_integrity_status();
    uint8_t fp[32];
    char fp_hex[65] = "";
    int fp_rc = oxi_integrity_key_fingerprint(fp, sizeof fp);
    if (fp_rc == OXI_RESULT_OK) {
        hex(fp, sizeof fp, fp_hex);
    }
    if (rc == OXI_RESULT_OK && status == 1 && fp_rc == OXI_RESULT_OK) {
        fprintf(stderr, "verify key sha256:%s\n", fp_hex);
        return;
    }
    if (rc != OXI_RESULT_OK) {
        fprintf(stderr, "oxi_init returned %d: the module refused to start\n", rc);
    } else if (status != 1) {
        fprintf(stderr, "oxi_init returned 0 but the integrity test reported status %d, not 1 (passed)\n", status);
    } else {
        fprintf(stderr, "oxi_integrity_key_fingerprint returned %d after the integrity test passed\n", fp_rc);
        exit(1);
    }
    fprintf(stderr, "integrity status %d\n", status);
    if (fp_rc == OXI_RESULT_OK) {
        fprintf(stderr, "verify key sha256:%s\n", fp_hex);
    } else {
        fprintf(stderr, "oxi_integrity_key_fingerprint returned %d\n", fp_rc);
    }
    exit(1);
}

/* Compares two shared secrets in time independent of where they differ. */
static int same_secret(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < SS_LEN; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

static void decaps_mode(const char *dk_path, const char *ct_path) {
    static uint8_t ct[CT_LEN];
    init();
    read_file(dk_path, dk, sizeof dk);
    read_file(ct_path, ct, sizeof ct);
    check("oxi_ml_kem_1024_decapsulate", oxi_ml_kem_1024_decapsulate(dk, ct, ss));
    hex(ss, sizeof ss, ss_hex);
    printf("ml-kem-1024 ss %s\n", ss_hex);
}

static void run(const char *out) {
    static uint8_t pk[PK_LEN], sig[SIG_LEN], tampered_sig[SIG_LEN];
    static uint8_t ek[EK_LEN], ct[CT_LEN], tampered_ct[CT_LEN];
    const size_t message_len = sizeof MESSAGE - 1;
    char want[128], got[128];
    int rc;

    init();

    uint8_t digest[32];
    char digest_hex[65];
    check("oxi_sha256", oxi_sha256((const uint8_t *)"abc", 3, digest));
    hex(digest, sizeof digest, digest_hex);
    snprintf(want, sizeof want, "sha256 abc %s", SHA256_ABC);
    snprintf(got, sizeof got, "sha256 abc %s", digest_hex);
    expect(want, got);

    check("oxi_hmac_drbg_sha256_new_rbg", oxi_hmac_drbg_sha256_new_rbg(&rbg));
    check("oxi_drbg_instantiate",
          oxi_drbg_instantiate(rbg, (const uint8_t *)PERSONALIZATION, sizeof PERSONALIZATION - 1));
    printf("drbg instantiated\n");

    expect_ok("ml-dsa-87 keygen", oxi_ml_dsa_87_keygen_rbg(rbg, pk, sk, NULL));
    check("oxi_ml_dsa_87_sign", oxi_ml_dsa_87_sign(sk, (const uint8_t *)MESSAGE, message_len, NULL, 0, sig));
    write_file(out, "pk.bin", pk, sizeof pk, 0);
    write_file(out, "message.txt", MESSAGE, message_len, 0);
    write_file(out, "sig.bin", sig, sizeof sig, 0);
    expect_ok("ml-dsa-87 verify", oxi_ml_dsa_87_verify(pk, (const uint8_t *)MESSAGE, message_len, NULL, 0, sig));
    memcpy(tampered_sig, sig, sizeof sig);
    tampered_sig[SIG_FLIP_BYTE] ^= 0x01;
    rc = oxi_ml_dsa_87_verify(pk, (const uint8_t *)MESSAGE, message_len, NULL, 0, tampered_sig);
    if (rc == OXI_RESULT_OK) {
        snprintf(got, sizeof got, "ml-dsa-87 verify-tampered accepted");
    } else {
        snprintf(got, sizeof got, "ml-dsa-87 verify-tampered rejected %d", rc);
    }
    expect("ml-dsa-87 verify-tampered rejected 22", got);

    expect_ok("ml-kem-1024 keygen", oxi_ml_kem_1024_keygen_rbg(rbg, ek, dk, NULL));
    check("oxi_ml_kem_1024_encapsulate_rbg", oxi_ml_kem_1024_encapsulate_rbg(ek, rbg, ss, ct));
    write_file(out, "ek.bin", ek, sizeof ek, 0);
    write_file(out, "dk.bin", dk, sizeof dk, 1);
    write_file(out, "ct.bin", ct, sizeof ct, 0);
    rc = oxi_ml_kem_1024_decapsulate(dk, ct, ss2);
    if (rc == OXI_RESULT_OK) {
        snprintf(got, sizeof got, "ml-kem-1024 decaps %s", same_secret(ss, ss2) ? "match" : "differs");
    } else {
        snprintf(got, sizeof got, "ml-kem-1024 decaps returned %d", rc);
    }
    expect("ml-kem-1024 decaps match", got);
    memcpy(tampered_ct, ct, sizeof ct);
    tampered_ct[CT_FLIP_BYTE] ^= 0x01;
    rc = oxi_ml_kem_1024_decapsulate(dk, tampered_ct, ss2);
    if (rc == OXI_RESULT_OK) {
        snprintf(got, sizeof got, "ml-kem-1024 decaps-tampered %s",
                 same_secret(ss, ss2) ? "match" : "differs");
    } else {
        snprintf(got, sizeof got, "ml-kem-1024 decaps-tampered returned %d", rc);
    }
    expect("ml-kem-1024 decaps-tampered differs", got);

    hex(ss, sizeof ss, ss_hex);
    printf("ml-kem-1024 ss %s\n", ss_hex);
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[2], "decaps") == 0) {
        decaps_mode(argv[3], argv[4]);
    } else if (argc == 3) {
        run(argv[2]);
    } else {
        fprintf(stderr, "usage: example <bundle-dir> <out-dir>\n"
                        "       example <bundle-dir> decaps <dk-file> <ct-file>\n");
        return 2;
    }
    release();
    /* A line lost to a full disk or a closed pipe surfaces here, and a
     * program that printed fewer than nine lines must not exit 0. */
    if (fflush(stdout) != 0 || ferror(stdout)) {
        perror("stdout");
        return 1;
    }
    return 0;
}
