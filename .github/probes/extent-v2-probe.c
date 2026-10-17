/* Typed loaded-image probe for ELF shared objects (glibc on Linux, bionic on
 * Android).
 *
 * A DESIGN MEASUREMENT of loader behaviour and of the file route. It is not the
 * integrity oracle: the oracle is the signed module at launch, whose
 * integrity status the `ffi-operational` harness reads. The probe dlopen()s a
 * shared object, reads the loaded image back through the kernel, and applies
 * the extent v2 entry kinds to it:
 *
 *   Plain     loaded value equals the file value
 *   Relative  an 8-byte word whose loaded value is the file value plus the
 *             load bias (RELR destinations; on glibc, the pointer-valued
 *             `.dynamic` entries when PT_DYNAMIC is writable)
 *   Hole      a word the loader overwrites without reading (RELA destinations,
 *             DT_DEBUG's value)
 *   FileOnly  initialised writable data, read from the file
 *
 * Every required condition sets a bit in the result; 0 is the pass. The probe
 * always ends with one `RESULT status=N` line, so a runner that cannot see the
 * process exit status (an adb shell on an old device) reads the same answer.
 *
 *   bit 0 (1)   typing: every Plain byte of the read-only PT_LOADs, of
 *               PT_DYNAMIC (each d_tag, each non-pointer d_val, the DT_NULL
 *               entry and every byte after it) and of the file-backed RELRO
 *               equals the file; pointer entries of `.dynamic` behave as the
 *               selected loader predicts; DT_DEBUG is its only Hole, and only
 *               where the loader writes it (bionic with a writable
 *               PT_DYNAMIC; never glibc, which writes it in the main
 *               program alone and this probe loads a library);
 *               the read-only PT_LOADs and RELRO each contributed Plain bytes
 *   bit 1 (2)   length: the mapped image lies inside the opened file, the base
 *               is page-aligned and is 0 unless the library is inside an
 *               archive, and for a version-4 slot the signed file_len
 *               and slot_file_off agree with the file and the ELF headers
 *   bit 2 (4)   refusal: APS2 packing, not BIND_NOW, DT_TEXTREL, REL-form
 *               relocations, a relocation type outside the accepted set, RELR
 *               on bionic
 *   bit 3 (8)   GOT[0..3] present and unchanged by the loader
 *   bit 4 (16)  FileOnly regions present and readable from file and memory
 *   bit 5 (32)  control: at least one RELA destination differed from the file,
 *               so the image was relocated and the run says something; on
 *               glibc an image with no RELA destination at all fails it
 *   bit 6 (64)  setup: the library loaded, a memory route exists, a slot was
 *               found (with --also: the decoy was mapped)
 *   bit 7 (128) Relative words normalise: loaded value minus the bias equals
 *               the file value
 *
 * Options:
 *   --loader glibc|bionic   the loader whose `.dynamic` behaviour to expect
 *   --also <lib>            dlopen a second entry of the same archive first,
 *                           and require mappings of the archive outside the
 *                           subject's image (Android, library inside an APK)
 *   --non-dumpable          clear the dumpable flag before choosing a memory
 *                           route
 *   --seccomp-deny-pvr      also install a seccomp filter that fails
 *                           process_vm_readv with EPERM; with both routes
 *                           closed the probe must report `route=unreadable`
 *   --relocs                print every relocation and `.dynamic` entry, for
 *                           the fixup cross-check
 *   --list-mutations        print each mutation name and the bit it must set
 *   --file <path>           read this file as the file route instead of the
 *                           one the loader reports; the self-tests use it to
 *                           feed truncated and malformed copies, which must
 *                           end in a RESULT failure and never a crash
 *   --mutate <name>         change one value the named check consumes, after
 *                           the image is loaded and parsed, so that check and
 *                           only that check must fail. The names are listed in
 *                           `mutations[]` below; `extent-v2-mutations.sh` runs
 *                           each one and requires exactly its bit.
 *
 * A library inside an APK is named `<archive>!/<entry>`, as bionic accepts it.
 * Every offset and size read from the file is bounds- and overflow-checked
 * before use.
 *
 * The image base inside the archive is the verifier's formula for a version-4
 * slot (slot archive offset minus slot_file_off) with the ELF-header search as
 * a control that must agree; for a version-2 slot the search is the only
 * source.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef DT_RELR
#define DT_RELR 36
#define DT_RELRSZ 35
#endif
#define DT_ANDROID_REL 0x6000000f
#define DT_ANDROID_RELA 0x60000011
#define DT_ANDROID_RELR 0x6fffe000
#define DT_ANDROID_RELRSZ 0x6fffe001
#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

enum {
    B_TYPING = 1, B_LENGTH = 2, B_REFUSE = 4, B_GOT = 8,
    B_FILEONLY = 16, B_CONTROL = 32, B_SETUP = 64, B_RELATIVE = 128,
};

static int status;

#define FAIL(bit, ...)                                                         \
    do {                                                                       \
        printf("FAIL[%d] ", (bit));                                            \
        printf(__VA_ARGS__);                                                   \
        printf("\n");                                                          \
        status |= (bit);                                                       \
    } while (0)

static int finish(void) {
    printf("RESULT status=%d %s\n", status, status ? "FAIL" : "PASS");
    fflush(stdout);
    return status;
}

/* ---- mutations --------------------------------------------------------- */

/* Each mutation names the bit it must set and nothing else. */
static const struct { const char *name; int bit; } mutations[] = {
    { "ro-plain", B_TYPING },     /* a byte of a read-only PT_LOAD          */
    { "dyn-tag", B_TYPING },      /* a byte of a d_tag                      */
    { "dyn-val", B_TYPING },      /* a byte of a non-pointer d_val          */
    { "dyn-ptr", B_TYPING },      /* a byte of a pointer-valued d_val       */
    { "dyn-null", B_TYPING },     /* a byte of the DT_NULL entry            */
    { "dyn-postnull", B_TYPING }, /* the first byte after the DT_NULL entry */
    { "relro-plain", B_TYPING },  /* a Plain word of the file-backed RELRO  */
    { "length", B_LENGTH },       /* the opened length, one byte short      */
    { "reloc-type", B_REFUSE },   /* a relocation type outside the set      */
    { "aps2", B_REFUSE },         /* DT_ANDROID_RELA, as parsed             */
    { "lazy", B_REFUSE },         /* BIND_NOW cleared, as parsed            */
    { "textrel", B_REFUSE },      /* DT_TEXTREL, as parsed                  */
    { "rel-form", B_REFUSE },     /* DT_REL, as parsed                      */
    { "relr-bionic", B_REFUSE },  /* RELR present, judged as bionic         */
    { "got", B_GOT },             /* a byte of GOT[0..3]                    */
    { "fileonly", B_FILEONLY },   /* the FileOnly region, unreadable        */
    { "no-slide", B_CONTROL },    /* every RELA destination reads unslid    */
    { "relative", B_RELATIVE },   /* a Plain RELRO word typed Relative      */
};
static const char *mutate;

static int mutating(const char *name) { return mutate && !strcmp(mutate, name); }

static void mutated(const char *name, uint64_t where) {
    printf("MUTATE %s at 0x%" PRIx64 "\n", name, where);
}

/* ---- memory routes ------------------------------------------------------ */

static int memfd = -1, use_pvr;

static int read_mem(uint64_t addr, void *buf, size_t n) {
    if (!use_pvr) {
        ssize_t got = pread(memfd, buf, n, (off_t)addr);
        return got == (ssize_t)n ? 0 : -1;
    }
    struct iovec l = { buf, n }, r = { (void *)(uintptr_t)addr, n };
    return process_vm_readv(getpid(), &l, 1, &r, 1, 0) == (ssize_t)n ? 0 : -1;
}

static int deny_process_vm_readv(void) {
#if defined(__x86_64__)
    const uint32_t arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    const uint32_t arch = AUDIT_ARCH_AARCH64;
#else
    return -1;
#endif
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { (unsigned short)(sizeof f / sizeof f[0]), f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

/* ---- the file ----------------------------------------------------------- */

static uint8_t *file_bytes;
static size_t file_len_opened;
static uint64_t apk_base, pagesz;

/* `n` bytes of the image at image-relative offset `off`, or NULL. Every
 * sum is checked: offsets and sizes come from the file and may be hostile. */
static uint8_t *F(uint64_t off, uint64_t n) {
    uint64_t len = file_len_opened;
    if (apk_base > len || off > len - apk_base || n > len - apk_base - off) return NULL;
    return file_bytes + apk_base + off;
}

/* *out = a + b, or 0 when the sum wraps. */
static int add_ok(uint64_t a, uint64_t b, uint64_t *out) {
    if (a > UINT64_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static const Elf64_Ehdr *eh;
static const Elf64_Phdr *ph;

static uint64_t v2o(uint64_t va) {
    uint64_t o;
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD && va >= ph[i].p_vaddr && va - ph[i].p_vaddr < ph[i].p_filesz)
            return add_ok(ph[i].p_offset, va - ph[i].p_vaddr, &o) ? o : UINT64_MAX;
    return UINT64_MAX;
}

/* Parses the ELF at archive offset `b`; returns the file offset `slot_rva`
 * maps to, or UINT64_MAX. */
/* The ELF and program headers are copied out of the file buffer rather than
 * read through cast pointers: an image base inside an archive need not be
 * aligned for them. */
static Elf64_Ehdr eh_copy;
static Elf64_Phdr *ph_copy;

static uint64_t try_base(uint64_t b, uint32_t slot_rva) {
    apk_base = b;
    eh = NULL;
    ph = NULL;
    const uint8_t *e = F(0, sizeof eh_copy);
    if (!e) return UINT64_MAX;
    memcpy(&eh_copy, e, sizeof eh_copy);
    if (memcmp(eh_copy.e_ident, ELFMAG, SELFMAG) || eh_copy.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh_copy.e_phentsize != sizeof(Elf64_Phdr))
        return UINT64_MAX;
    size_t n = (size_t)eh_copy.e_phnum * sizeof(Elf64_Phdr);
    const uint8_t *p = F(eh_copy.e_phoff, n);
    if (!p) return UINT64_MAX;
    Elf64_Phdr *c = realloc(ph_copy, n ? n : 1);
    if (!c) return UINT64_MAX;
    ph_copy = c;
    memcpy(ph_copy, p, n);
    eh = &eh_copy;
    ph = ph_copy;
    return v2o(slot_rva);
}

/* ---- relocation destinations ------------------------------------------- */

enum { D_HOLE = 1, D_RELATIVE = 2 };
typedef struct { uint64_t addr; int kind; int width; } Dest;
static Dest *dests;
static size_t ndests, capd;

static void add_dest(uint64_t a, int kind, int width) {
    if (ndests == capd) {
        capd = capd ? capd * 2 : 4096;
        dests = realloc(dests, capd * sizeof *dests);
        if (!dests) { perror("realloc"); exit(64); }
    }
    dests[ndests++] = (Dest){ a, kind, width };
}

static int dest_cmp(const void *a, const void *b) {
    uint64_t x = ((const Dest *)a)->addr, y = ((const Dest *)b)->addr;
    return x < y ? -1 : x > y;
}

static const Dest *find_dest(uint64_t a) {
    size_t lo = 0, hi = ndests;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (dests[mid].addr <= a) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return NULL;
    const Dest *d = &dests[lo - 1];
    return a - d->addr < (uint64_t)d->width ? d : NULL;
}

static int accepted_type(unsigned t, int *width) {
    *width = 8;
#if defined(__x86_64__)
    switch (t) {
    case 1: case 6: case 7: case 8: case 16: case 17: case 18: case 37: return 1;
    case 36: *width = 16; return 1;
    default: return 0;
    }
#elif defined(__aarch64__)
    switch (t) {
    case 257: case 1025: case 1026: case 1027: case 1028: case 1029: case 1030: case 1032:
        return 1;
    case 1031: *width = 16; return 1;
    default: return 0;
    }
#else
    (void)t;
    return 0;
#endif
}

/* The `.dynamic` tags whose d_val glibc adjusts in place when PT_DYNAMIC is
 * writable. bionic adjusts none of them. */
static int is_pointer_tag(uint64_t t) {
    return t == DT_HASH || t == DT_PLTGOT || t == DT_STRTAB || t == DT_SYMTAB ||
           t == DT_RELA || t == DT_REL || t == DT_JMPREL || t == DT_VERSYM ||
           t == DT_GNU_HASH || t == DT_RELR;
}

/* ---- /proc/self/maps ---------------------------------------------------- */

typedef struct { uint64_t lo, hi, off; char perms[8]; } Map;
static Map maps[256];
static int nmaps;

static int read_maps(const char *rp) {
    nmaps = 0;
    FILE *mf = fopen("/proc/self/maps", "r");
    if (!mf) return -1;
    char line[4096];
    while (fgets(line, sizeof line, mf) && nmaps < 256) {
        Map m;
        char path[PATH_MAX];
        unsigned maj, min;
        uint64_t ino;
        path[0] = 0;
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %x:%x %" SCNu64 " %4095s",
                   &m.lo, &m.hi, m.perms, &m.off, &maj, &min, &ino, path) < 8)
            continue;
        if (strcmp(path, rp)) continue;
        maps[nmaps++] = m;
    }
    fclose(mf);
    return nmaps;
}

static const uint8_t SLOT_HDR[16] = { 0xfc, 'O','X','I','C','R','Y','P','T','_','F','I','P','S','_','H' };
static const uint8_t SLOT_FTR[16] = { 0xfd, 'O','X','I','C','R','Y','P','T','_','F','I','P','S','_','F' };

/* The integrity slot's layout, version 4 (oxicrypt-integrity's slot
 * module). tools/integrity-probe/tests/probe_offsets.rs checks each value. */
#define SLOT_MAGIC_LEN 16
#define SLOT_VERSION 4
#define SLOT_SIZE 65536
#define OFF_VERSION 16
#define OFF_SLOT_RVA 28
#define OFF_KEY_ID 4659
#define OFF_SLOT_FILE_OFF 4707
#define OFF_FILE_LEN 4711

/* Counts the bytes of `n` that differ between the file and memory views. */
static size_t compare_plain(const char *what, uint64_t va0, const uint8_t *f,
                            const uint8_t *m, size_t n) {
    size_t bad = 0;
    for (size_t i = 0; i < n; i++)
        if (f[i] != m[i]) {
            if (bad < 5)
                printf("PLAIN_DIFF %s va=0x%" PRIx64 " file=%02x mem=%02x\n", what,
                       va0 + i, f[i], m[i]);
            bad++;
        }
    return bad;
}

int main(int argc, char **argv) {
    const char *loader = "glibc", *also = NULL, *file_override = NULL;
    int non_dumpable = 0, deny_pvr = 0, relocs = 0, ai = 1;
    setvbuf(stdout, NULL, _IOLBF, 0);
    while (ai < argc && argv[ai][0] == '-') {
        if (!strcmp(argv[ai], "--non-dumpable")) { non_dumpable = 1; ai++; continue; }
        if (!strcmp(argv[ai], "--seccomp-deny-pvr")) { non_dumpable = deny_pvr = 1; ai++; continue; }
        if (!strcmp(argv[ai], "--relocs")) { relocs = 1; ai++; continue; }
        if (!strcmp(argv[ai], "--list-mutations")) {
            for (size_t i = 0; i < sizeof mutations / sizeof mutations[0]; i++)
                printf("%s %d\n", mutations[i].name, mutations[i].bit);
            return 0;
        }
        if (ai + 1 >= argc) break;
        if (!strcmp(argv[ai], "--loader")) loader = argv[ai + 1];
        else if (!strcmp(argv[ai], "--also")) also = argv[ai + 1];
        else if (!strcmp(argv[ai], "--mutate")) mutate = argv[ai + 1];
        else if (!strcmp(argv[ai], "--file")) file_override = argv[ai + 1];
        else break;
        ai += 2;
    }
    if (ai + 1 != argc || (strcmp(loader, "glibc") && strcmp(loader, "bionic"))) {
        fprintf(stderr,
                "usage: %s [--loader glibc|bionic] [--also <lib>] [--non-dumpable]\n"
                "          [--seccomp-deny-pvr] [--relocs] [--mutate <name>] [--file <path>] <lib>\n"
                "       %s --list-mutations\n",
                argv[0], argv[0]);
        return 2;
    }
    if (mutate) {
        int known = 0;
        for (size_t i = 0; i < sizeof mutations / sizeof mutations[0]; i++)
            if (!strcmp(mutate, mutations[i].name)) known = 1;
        if (!known) { fprintf(stderr, "unknown mutation %s\n", mutate); return 2; }
    }
    const char *lib = argv[ai];
    int bionic = !strcmp(loader, "bionic");
    pagesz = (uint64_t)sysconf(_SC_PAGESIZE);

    /* -- process facts and the memory route -- */
    if (non_dumpable && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
        FAIL(B_SETUP, "PR_SET_DUMPABLE: %s", strerror(errno));
    if (deny_pvr && deny_process_vm_readv())
        FAIL(B_SETUP, "seccomp filter not installed: %s", strerror(errno));
    printf("PROC loader_expected=%s uid=%d dumpable=%d pagesize=%" PRIu64 "\n", loader,
           (int)getuid(), prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), pagesz);
    {
        FILE *s = fopen("/proc/self/status", "r");
        char l[256];
        while (s && fgets(l, sizeof l, s))
            if (!strncmp(l, "Seccomp", 7)) {
                l[strcspn(l, "\n")] = 0;
                for (char *c = l; *c; c++) if (*c == '\t') *c = ' ';
                printf("PROC %s\n", l);
            }
        if (s) fclose(s);
        int a = open("/proc/self/attr/current", O_RDONLY);
        char c[128] = { 0 };
        if (a >= 0) {
            ssize_t g = read(a, c, sizeof c - 1);
            (void)g;
            close(a);
            c[strcspn(c, "\n")] = 0;
        }
        printf("PROC selinux=%s\n", c[0] ? c : "(none)");
    }
    memfd = open("/proc/self/mem", O_RDONLY);
    int mem_errno = memfd < 0 ? errno : 0;
    char probe_src[8] = "probe!!", probe_dst[8] = { 0 };
    struct iovec pl = { probe_dst, 8 }, pr = { probe_src, 8 };
    ssize_t pg = process_vm_readv(getpid(), &pl, 1, &pr, 1, 0);
    int pvr_ok = pg == 8 && !memcmp(probe_dst, probe_src, 8);
    int pvr_errno = pvr_ok ? 0 : errno;
    printf("PROC proc_self_mem=%s process_vm_readv_self=%s\n",
           memfd >= 0 ? "ok" : strerror(mem_errno), pvr_ok ? "ok" : strerror(pvr_errno));
    if (memfd < 0 && pvr_ok) use_pvr = 1;
    printf("PROC route=%s\n", memfd >= 0 ? "proc_self_mem" : pvr_ok ? "process_vm_readv" : "unreadable");
    if (memfd < 0 && !pvr_ok) {
        FAIL(B_SETUP, "no memory route: Unreadable");
        return finish();
    }

    /* -- load -- */
    if (also && !dlopen(also, RTLD_NOW)) {
        FAIL(B_SETUP, "dlopen %s: %s", also, dlerror());
        return finish();
    }
    if (!dlopen(lib, RTLD_NOW)) {
        FAIL(B_SETUP, "dlopen %s: %s", lib, dlerror());
        return finish();
    }
    char want[PATH_MAX];
    const char *bang = strstr(lib, "!/");
    int in_apk = bang != NULL;
    size_t wl = in_apk ? (size_t)(bang - lib) : strlen(lib);
    if (wl >= sizeof want) { FAIL(B_SETUP, "path too long"); return finish(); }
    memcpy(want, lib, wl);
    want[wl] = 0;
    char rp[PATH_MAX];
    if (!realpath(want, rp)) { FAIL(B_SETUP, "realpath %s: %s", want, strerror(errno)); return finish(); }
    if (read_maps(rp) <= 0) { FAIL(B_SETUP, "no mapping of %s", rp); return finish(); }
    for (int i = 0; i < nmaps; i++)
        printf("MAP %s start=0x%" PRIx64 " off=0x%" PRIx64 " size=%" PRIu64 "\n", maps[i].perms,
               maps[i].lo, maps[i].off, maps[i].hi - maps[i].lo);

    /* -- the file the loader reports -- */
    if (file_override) snprintf(rp, sizeof rp, "%s", file_override);
    int fd = open(rp, O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0) { FAIL(B_SETUP, "open %s: %s", rp, strerror(errno)); return finish(); }
    file_len_opened = (size_t)st.st_size;
    file_bytes = malloc(file_len_opened ? file_len_opened : 1);
    if (!file_bytes) { FAIL(B_SETUP, "malloc for the file"); return finish(); }
    for (size_t done = 0; done < file_len_opened;) {
        ssize_t g = pread(fd, file_bytes + done, file_len_opened - done, (off_t)done);
        if (g <= 0) { FAIL(B_SETUP, "read %s", rp); return finish(); }
        done += (size_t)g;
    }
    close(fd);
    printf("FILE path=%s size=%zu\n", rp, file_len_opened);

    /* -- a valid slot in mapped memory -- */
    uint64_t slot_mem = 0;
    int slot_map = -1;
    uint32_t ver = 0, slot_rva = 0, slot_file_off = 0, file_len_signed = 0;
    uint8_t key_id[32] = { 0 }; /* version 4: SHA-256 of the verifying key the slot was signed for */
    for (int i = 0; i < nmaps && !slot_mem; i++) {
        if (maps[i].perms[0] != 'r') continue;
        size_t n = (size_t)(maps[i].hi - maps[i].lo);
        uint8_t *buf = n <= (1u << 30) ? malloc(n) : NULL;
        if (!buf || read_mem(maps[i].lo, buf, n)) {
            FAIL(B_SETUP, "mapping at 0x%" PRIx64 " unreadable", maps[i].lo);
            free(buf);
            continue;
        }
        for (size_t k = 0; k + SLOT_MAGIC_LEN <= n; k++) {
            if (buf[k] != 0xfc || memcmp(buf + k, SLOT_HDR, SLOT_MAGIC_LEN)) continue;
            uint32_t v = 0;
            uint8_t ftr[SLOT_MAGIC_LEN];
            if (read_mem(maps[i].lo + k + OFF_VERSION, &v, 4)) continue;
            size_t sz = v == 2 ? 16384 : v == SLOT_VERSION ? SLOT_SIZE : 0;
            if (!sz) { printf("SLOT candidate rejected: version %u\n", v); continue; }
            if (read_mem(maps[i].lo + k + sz - SLOT_MAGIC_LEN, ftr, SLOT_MAGIC_LEN) ||
                memcmp(ftr, SLOT_FTR, SLOT_MAGIC_LEN)) {
                printf("SLOT candidate rejected: no version-%u footer\n", v);
                continue;
            }
            slot_mem = maps[i].lo + k;
            slot_map = i;
            ver = v;
            if (read_mem(slot_mem + OFF_SLOT_RVA, &slot_rva, 4) ||
                (v == SLOT_VERSION &&
                 (read_mem(slot_mem + OFF_SLOT_FILE_OFF, &slot_file_off, 4) ||
                  read_mem(slot_mem + OFF_FILE_LEN, &file_len_signed, 4) ||
                  read_mem(slot_mem + OFF_KEY_ID, key_id, 32)))) {
                FAIL(B_SETUP, "slot header unreadable");
                slot_mem = 0;
            }
            break;
        }
        free(buf);
    }
    if (!slot_mem) { FAIL(B_SETUP, "no valid integrity slot in the mapped image"); return finish(); }
    uint64_t slot_arch_off;
    if (!add_ok(maps[slot_map].off, slot_mem - maps[slot_map].lo, &slot_arch_off)) {
        FAIL(B_SETUP, "the slot's archive offset wraps");
        return finish();
    }
    printf("SLOT version=%u slot_rva=0x%x archive_off=0x%" PRIx64 "\n", ver, slot_rva, slot_arch_off);
    if (ver == SLOT_VERSION) {
        printf("SLOT slot_file_off=0x%x file_len=%u verify_key=sha256:", slot_file_off, file_len_signed);
        for (int k = 0; k < 32; k++) printf("%02x", key_id[k]);
        printf("\n");
    }

    /* -- the image base inside the opened file -- */
    uint64_t base_formula = UINT64_MAX, base_search = UINT64_MAX;
    if (ver == SLOT_VERSION) {
        if (slot_arch_off >= slot_file_off &&
            try_base(slot_arch_off - slot_file_off, slot_rva) == (uint64_t)slot_file_off)
            base_formula = slot_arch_off - slot_file_off;
        else
            FAIL(B_LENGTH, "the formula base does not place slot_rva at slot_file_off");
    }
    for (uint64_t p = slot_arch_off & ~(pagesz - 1);; p -= pagesz) {
        uint64_t so = try_base(p, slot_rva);
        uint64_t at;
        if (so != UINT64_MAX && add_ok(p, so, &at) && at == slot_arch_off) { base_search = p; break; }
        if (p == 0) break;
    }
    if (base_search == UINT64_MAX) FAIL(B_SETUP, "no ELF header whose program headers place the slot");
    if (base_formula != UINT64_MAX && base_search != UINT64_MAX && base_formula != base_search)
        FAIL(B_LENGTH, "formula base 0x%" PRIx64 " != ELF-search base 0x%" PRIx64, base_formula, base_search);
    uint64_t base = base_formula != UINT64_MAX ? base_formula : base_search;
    if (base == UINT64_MAX || try_base(base, slot_rva) == UINT64_MAX) return finish();

    uint64_t link_base = UINT64_MAX, image_len = 0;
    const Elf64_Phdr *dyn = NULL, *relro = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            if (ph[i].p_vaddr < link_base) link_base = ph[i].p_vaddr;
            uint64_t end;
            if (!add_ok(ph[i].p_offset, ph[i].p_filesz, &end)) { FAIL(B_LENGTH, "PT_LOAD %d's file extent wraps", i); return finish(); }
            if (end > image_len) image_len = end;
        }
        if (ph[i].p_type == PT_DYNAMIC) dyn = &ph[i];
        if (ph[i].p_type == PT_GNU_RELRO) relro = &ph[i];
    }
    if (!dyn) { FAIL(B_SETUP, "no PT_DYNAMIC"); return finish(); }
    uint64_t img_end;
    if (!add_ok(apk_base, image_len, &img_end)) { FAIL(B_LENGTH, "image base + image length wraps"); return finish(); }
    uint64_t lo_min = UINT64_MAX;
    int nimg = 0;
    for (int i = 0; i < nmaps; i++) {
        if (maps[i].off < apk_base || maps[i].off >= img_end) continue;
        nimg++;
        if (maps[i].lo < lo_min) lo_min = maps[i].lo;
        uint64_t rel = maps[i].off - apk_base;
        int ok = 0;
        for (int j = 0; j < eh->e_phnum; j++)
            if (ph[j].p_type == PT_LOAD && rel >= (ph[j].p_offset & ~(pagesz - 1)) &&
                rel - ph[j].p_offset < ph[j].p_filesz)
                ok = 1;
        if (!ok) FAIL(B_SETUP, "mapping at archive offset 0x%" PRIx64 " belongs to no PT_LOAD", maps[i].off);
    }
    if (lo_min == UINT64_MAX || lo_min < (link_base & ~(pagesz - 1))) {
        FAIL(B_SETUP, "the lowest mapping lies below the lowest PT_LOAD address");
        return finish();
    }
    uint64_t bias = lo_min - (link_base & ~(pagesz - 1));
    printf("IMAGE apk_base=0x%" PRIx64 " (%s) image_len=%" PRIu64 " opened_len=%zu image_mappings=%d/%d bias=0x%" PRIx64 "\n",
           apk_base, ver == SLOT_VERSION ? "formula; search agrees" : "search", image_len, file_len_opened, nimg, nmaps, bias);
    if (also && nimg >= nmaps) FAIL(B_SETUP, "--also given but no mapping of the archive lies outside the subject: the decoy was not mapped");

    /* -- length -- */
    size_t opened_len = file_len_opened;
    if (mutating("length")) { opened_len = (size_t)(img_end - 1); mutated("length", opened_len); }
    if (apk_base % pagesz) FAIL(B_LENGTH, "image base 0x%" PRIx64 " not page-aligned", apk_base);
    if (!in_apk && apk_base) FAIL(B_LENGTH, "a library outside an archive has its ELF header at 0x%" PRIx64 ", not 0", apk_base);
    if (img_end > opened_len) FAIL(B_LENGTH, "the mapped image exceeds the opened file");
    if (ver == SLOT_VERSION) {
        if (!in_apk && opened_len != file_len_signed)
            FAIL(B_LENGTH, "st_size %zu != signed file_len %u", opened_len, file_len_signed);
        if (in_apk && (uint64_t)file_len_signed > opened_len - (apk_base < opened_len ? apk_base : opened_len))
            FAIL(B_LENGTH, "image base + signed file_len exceeds the archive");
        if (file_len_signed < image_len)
            FAIL(B_LENGTH, "signed file_len %u is smaller than the mapped image %" PRIu64, file_len_signed, image_len);
    }
    printf("SIZE image_len=%" PRIu64 " opened_len=%zu signed_len=%s non_mapped_tail=%" PRId64 "\n", image_len,
           opened_len, ver == SLOT_VERSION ? "checked" : "absent(version 2)",
           (int64_t)opened_len - (int64_t)img_end);

    /* -- .dynamic, parsed from the file -- */
    size_t dyn_n = (size_t)dyn->p_filesz;
    uint8_t *dynf = F(dyn->p_offset, dyn_n);
    if (!dynf || dyn_n < sizeof(Elf64_Dyn)) { FAIL(B_SETUP, "PT_DYNAMIC outside the file"); return finish(); }
    uint64_t rela = 0, relasz = 0, jmprel = 0, pltrelsz = 0, pltrel = 0, relr = 0, relrsz = 0, pltgot = 0, symtab = 0;
    uint64_t flags = 0, flags1 = 0;
    int aps2 = 0, android_relr = 0, textrel = 0, rel_form = 0;
    size_t null_at = SIZE_MAX; /* byte offset of the DT_NULL entry */
    for (size_t o = 0; o + sizeof(Elf64_Dyn) <= dyn_n; o += sizeof(Elf64_Dyn)) {
        Elf64_Dyn e;
        memcpy(&e, dynf + o, sizeof e);
        uint64_t v = e.d_un.d_val;
        if (e.d_tag == DT_NULL) { null_at = o; break; }
        if (relocs) printf("DYNENT tag=0x%" PRIx64 " val=0x%" PRIx64 "\n", (uint64_t)e.d_tag, v);
        switch (e.d_tag) {
        case DT_RELA: rela = v; break;
        case DT_RELASZ: relasz = v; break;
        case DT_JMPREL: jmprel = v; break;
        case DT_PLTRELSZ: pltrelsz = v; break;
        case DT_PLTREL: pltrel = v; break;
        case DT_RELR: relr = v; break;
        case DT_RELRSZ: relrsz = v; break;
        case DT_ANDROID_RELR: relr = v; android_relr = 1; break;
        case DT_ANDROID_RELRSZ: relrsz = v; break;
        case DT_ANDROID_RELA: case DT_ANDROID_REL: aps2 = 1; break;
        case DT_PLTGOT: pltgot = v; break;
        case DT_SYMTAB: symtab = v; break;
        case DT_FLAGS: flags = v; if (v & DF_TEXTREL) textrel = 1; break;
        case DT_FLAGS_1: flags1 = v; break;
        case DT_TEXTREL: textrel = 1; break;
        case DT_REL: case DT_RELSZ: rel_form = 1; break;
        default: break;
        }
    }
    if (null_at == SIZE_MAX) { FAIL(B_TYPING, "PT_DYNAMIC has no DT_NULL entry"); return finish(); }
    int bind_now = (flags & DF_BIND_NOW) || (flags1 & DF_1_NOW);
    int dyn_w = (dyn->p_flags & PF_W) != 0;
    printf("DYNAMIC entries=%zu bytes=%zu post_null_bytes=%zu rela=0x%" PRIx64 "+%" PRIu64 " jmprel=0x%" PRIx64 "+%" PRIu64
           " relr=0x%" PRIx64 "+%" PRIu64 "%s aps2=%s bind_now=%s PT_DYNAMIC_PF_W=%d\n",
           null_at / sizeof(Elf64_Dyn), dyn_n, dyn_n - null_at - sizeof(Elf64_Dyn), rela, relasz, jmprel, pltrelsz,
           relr, relrsz, android_relr ? "(ANDROID_RELR)" : "", aps2 ? "PRESENT" : "absent",
           bind_now ? "yes" : "NO", dyn_w);

    /* -- refusals; each mutation sets the parsed condition its check reads -- */
    int relr_present = relr != 0, judge_bionic = bionic;
    if (mutating("aps2")) { aps2 = 1; mutated(mutate, 0); }
    if (mutating("lazy")) { bind_now = 0; mutated(mutate, 0); }
    if (mutating("textrel")) { textrel = 1; mutated(mutate, 0); }
    if (mutating("rel-form")) { rel_form = 1; mutated(mutate, 0); }
    if (mutating("relr-bionic")) { relr_present = judge_bionic = 1; mutated(mutate, 0); }
    if (aps2) FAIL(B_REFUSE, "APS2 packed relocations");
    if (!bind_now) FAIL(B_REFUSE, "not BIND_NOW");
    if (textrel) FAIL(B_REFUSE, "DT_TEXTREL");
    if (rel_form || (jmprel && pltrel != DT_RELA)) FAIL(B_REFUSE, "REL-form relocations");
    if (judge_bionic && relr_present) FAIL(B_REFUSE, "RELR packing on bionic");

    /* -- relocation destinations -- */
    for (int pass = 0; pass < 2; pass++) {
        uint64_t tab = pass ? jmprel : rela, sz = pass ? pltrelsz : relasz;
        if (!tab) continue;
        uint64_t o = v2o(tab);
        const uint8_t *tb = o == UINT64_MAX ? NULL : F(o, sz);
        if (!tb) { FAIL(B_SETUP, "relocation table outside the file"); return finish(); }
        if (sz % sizeof(Elf64_Rela)) { FAIL(B_REFUSE, "a relocation table of %" PRIu64 " bytes ends in a partial record", sz); return finish(); }
        for (uint64_t i = 0; i < sz / sizeof(Elf64_Rela); i++) {
            Elf64_Rela r; /* copied: the table need not be aligned in the buffer */
            memcpy(&r, tb + i * sizeof r, sizeof r);
            int w;
            unsigned t = (unsigned)ELF64_R_TYPE(r.r_info);
            /* the parsed type only: the table's bytes stay as loaded */
            if (pass == 0 && i == 0 && mutating("reloc-type")) { t = 0xfffe; mutated("reloc-type", r.r_offset); }
            if (relocs) printf("FIXUP off=0x%" PRIx64 " type=%u kind=hole\n", (uint64_t)r.r_offset, t);
            if (!accepted_type(t, &w)) { FAIL(B_REFUSE, "relocation type %u outside the accepted set", t); w = 8; }
            /* The loader skips these TLS types when the symbol does not
             * resolve, leaving the file word: an undefined weak symbol is
             * refused rather than typed as a hole. */
            unsigned sym = (unsigned)ELF64_R_SYM(r.r_info);
#if defined(__x86_64__)
            int skippable = t == 16 || t == 17 || t == 18;
#else
            int skippable = t == 1028 || t == 1029 || t == 1030;
#endif
            if (skippable && sym) {
                uint64_t so = symtab ? v2o(symtab + (uint64_t)sym * sizeof(Elf64_Sym)) : UINT64_MAX;
                const uint8_t *sb = so == UINT64_MAX ? NULL : F(so, sizeof(Elf64_Sym));
                Elf64_Sym es;
                if (!sb) { FAIL(B_REFUSE, "TLS relocation symbol %u outside the file", sym); continue; }
                memcpy(&es, sb, sizeof es);
                if (es.st_shndx == SHN_UNDEF && ELF64_ST_BIND(es.st_info) == STB_WEAK) {
                    FAIL(B_REFUSE, "TLS relocation at 0x%" PRIx64 " against an undefined weak symbol", (uint64_t)r.r_offset);
                    continue;
                }
            }
            add_dest(r.r_offset, D_HOLE, w);
        }
    }
    if (relr) {
        uint64_t o = v2o(relr);
        const uint8_t *eb = o == UINT64_MAX ? NULL : F(o, relrsz);
        if (!eb) { FAIL(B_SETUP, "RELR table outside the file"); return finish(); }
        if (relrsz % 8) { FAIL(B_REFUSE, "a RELR table of %" PRIu64 " bytes ends in a partial entry", relrsz); return finish(); }
        uint64_t where = 0;
        for (uint64_t i = 0; i < relrsz / 8; i++) {
            uint64_t v;
            memcpy(&v, eb + i * 8, 8);
            if (!(v & 1)) {
                add_dest(v, D_RELATIVE, 8);
                if (relocs) printf("FIXUP off=0x%" PRIx64 " type=relr kind=relative\n", v);
                if (!add_ok(v, 8, &where)) { FAIL(B_REFUSE, "a RELR address wraps"); return finish(); }
            } else {
                for (int b = 0; (v >>= 1) != 0; b++)
                    if (v & 1) {
                        uint64_t a;
                        if (!add_ok(where, (uint64_t)b * 8, &a)) { FAIL(B_REFUSE, "a RELR bitmap address wraps"); return finish(); }
                        add_dest(a, D_RELATIVE, 8);
                        if (relocs) printf("FIXUP off=0x%" PRIx64 " type=relr kind=relative\n", a);
                    }
                if (!add_ok(where, 63 * 8, &where)) { FAIL(B_REFUSE, "a RELR bitmap address wraps"); return finish(); }
            }
        }
    }
    qsort(dests, ndests, sizeof *dests, dest_cmp);
    size_t nh = 0, nr = 0, hole_words = 0;
    for (size_t i = 0; i < ndests; i++) {
        if (dests[i].kind == D_HOLE) { nh++; hole_words += (size_t)dests[i].width / 8; } else nr++;
    }
    /* a TLS descriptor destination is one record covering two 8-byte words */
    printf("DESTS holes=%zu hole_words=%zu relative=%zu\n", nh, hole_words, nr);

    /* -- mutations of file values, after parsing -- */
    if (mutating("ro-plain")) {
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD && !(ph[i].p_flags & PF_W) && ph[i].p_filesz > 0x2000 &&
                F(ph[i].p_offset + ph[i].p_filesz / 2, 1)) {
                uint64_t o = ph[i].p_offset + ph[i].p_filesz / 2;
                F(o, 1)[0] ^= 0x01;
                mutated("ro-plain", o);
                break;
            }
    }
    {
        size_t first_val = SIZE_MAX, first_ptr = SIZE_MAX;
        for (size_t o = 0; o < null_at; o += sizeof(Elf64_Dyn)) {
            Elf64_Dyn e;
            memcpy(&e, dynf + o, sizeof e);
            int ptr = is_pointer_tag((uint64_t)e.d_tag) && e.d_un.d_val;
            if (ptr && first_ptr == SIZE_MAX) first_ptr = o;
            if (!ptr && e.d_tag != DT_DEBUG && first_val == SIZE_MAX) first_val = o;
        }
        size_t at = SIZE_MAX;
        if (mutating("dyn-tag")) at = 0 + 1;
        if (mutating("dyn-val") && first_val != SIZE_MAX) at = first_val + 8;
        if (mutating("dyn-ptr") && first_ptr != SIZE_MAX) at = first_ptr + 8 + 1;
        if (mutating("dyn-null")) at = null_at + 8;
        if (mutating("dyn-postnull") && null_at + sizeof(Elf64_Dyn) < dyn_n) at = null_at + sizeof(Elf64_Dyn);
        if (at != SIZE_MAX) { dynf[at] ^= 0x01; mutated(mutate, dyn->p_vaddr + at); }
        else if (mutate && !strncmp(mutate, "dyn-", 4)) printf("MUTATE %s not applicable to this image\n", mutate);
    }

    /* -- the read-only PT_LOADs, and the headers they carry: Plain -- */
    {
        size_t compared = 0, bad = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD || (ph[i].p_flags & PF_W) || !ph[i].p_filesz) continue;
            size_t n = (size_t)ph[i].p_filesz;
            const uint8_t *f = F(ph[i].p_offset, n);
            uint8_t *m = f ? malloc(n) : NULL;
            uint64_t at;
            if (!m || !f || !add_ok(bias, ph[i].p_vaddr, &at) || read_mem(at, m, n)) {
                FAIL(B_SETUP, "read-only PT_LOAD at 0x%" PRIx64 " unreadable", (uint64_t)ph[i].p_vaddr);
                free(m);
                continue;
            }
            bad += compare_plain("load", ph[i].p_vaddr, f, m, n);
            compared += n;
            free(m);
        }
        printf("LOAD_SUMMARY plain_bytes=%zu differing=%zu\n", compared, bad);
        if (bad) FAIL(B_TYPING, "%zu bytes of read-only PT_LOADs differ from the file", bad);
        if (!compared) FAIL(B_TYPING, "no read-only PT_LOAD byte was compared");
    }

    /* -- PT_DYNAMIC: every byte typed -- */
    {
        uint8_t *m = malloc(dyn_n);
        uint64_t at;
        if (!m || !add_ok(bias, dyn->p_vaddr, &at) || read_mem(at, m, dyn_n)) { FAIL(B_SETUP, "PT_DYNAMIC unreadable"); return finish(); }
        size_t plain = 0, plain_bad = 0, adjusted = 0, unchanged_ptr = 0, holes = 0, rel_bad = 0;
        for (size_t o = 0; o < dyn_n; o += sizeof(Elf64_Dyn)) {
            size_t len = dyn_n - o < sizeof(Elf64_Dyn) ? dyn_n - o : sizeof(Elf64_Dyn);
            int before_null = o < null_at;
            uint64_t tag = 0, fv = 0, mv = 0;
            if (len == sizeof(Elf64_Dyn)) {
                memcpy(&tag, m + o, 8); /* the loaded tag: a changed tag must not retype its value */
                memcpy(&fv, dynf + o + 8, 8);
                memcpy(&mv, m + o + 8, 8);
            }
            /* the tag, and everything at or after DT_NULL, is Plain */
            if (!before_null || len < sizeof(Elf64_Dyn)) {
                plain += len;
                plain_bad += compare_plain("dynamic", dyn->p_vaddr + o, dynf + o, m + o, len);
                continue;
            }
            plain += 8;
            plain_bad += compare_plain("dynamic.d_tag", dyn->p_vaddr + o, dynf + o, m + o, 8);
            uint64_t ftag;
            memcpy(&ftag, dynf + o, 8);
            if (ftag != tag) continue; /* counted above; the value's kind is undefined */
            if (tag == DT_DEBUG && bionic && dyn_w) { holes++; continue; }
            if (is_pointer_tag(tag) && fv && dyn_w && !bionic) {
                if (mv == fv) { unchanged_ptr++; FAIL(B_TYPING, "glibc was expected to adjust tag 0x%" PRIx64 " but did not", tag); }
                else if (mv - bias == fv) adjusted++;
                else { rel_bad++; printf("DYN_RELATIVE_BAD tag=0x%" PRIx64 " file=0x%" PRIx64 " mem=0x%" PRIx64 "\n", tag, fv, mv); }
                continue;
            }
            plain += 8;
            plain_bad += compare_plain("dynamic.d_val", dyn->p_vaddr + o + 8, dynf + o + 8, m + o + 8, 8);
        }
        printf("DYNAMIC_SUMMARY plain_bytes=%zu plain_differing=%zu relative_ok=%zu relative_bad=%zu "
               "relative_unadjusted=%zu holes=%zu\n", plain, plain_bad, adjusted, rel_bad, unchanged_ptr, holes);
        if (plain_bad) FAIL(B_TYPING, "%zu Plain bytes of PT_DYNAMIC differ from the file", plain_bad);
        if (rel_bad) FAIL(B_TYPING, "%zu pointer entries of PT_DYNAMIC are neither Plain nor Relative", rel_bad);
        free(m);
    }

    /* -- the file-backed RELRO, outside PT_DYNAMIC -- */
    if (!relro) {
        FAIL(B_TYPING, "PT_GNU_RELRO absent");
    } else {
        uint64_t rs = relro->p_vaddr, re, seg_file_end, fo, dhi;
        const Elf64_Phdr *seg = NULL;
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD && rs >= ph[i].p_vaddr && rs - ph[i].p_vaddr < ph[i].p_memsz) seg = &ph[i];
        if (!seg) { FAIL(B_SETUP, "RELRO outside every PT_LOAD"); return finish(); }
        if (!add_ok(rs, relro->p_memsz, &re) || !add_ok(seg->p_vaddr, seg->p_filesz, &seg_file_end) ||
            !add_ok(seg->p_offset, rs - seg->p_vaddr, &fo) || !add_ok(dyn->p_vaddr, dyn->p_filesz, &dhi)) {
            FAIL(B_SETUP, "RELRO or PT_DYNAMIC extent wraps");
            return finish();
        }
        if (re > seg_file_end) re = seg_file_end;
        if (re < rs) re = rs;
        size_t n = (size_t)(re - rs);
        uint8_t *f = F(fo, n);
        uint8_t *m = f ? malloc(n ? n : 1) : NULL;
        uint64_t at;
        if (!m || !f || !add_ok(bias, rs, &at) || read_mem(at, m, n)) { FAIL(B_SETUP, "RELRO unreadable"); return finish(); }
        uint64_t dlo = dyn->p_vaddr;
        int relro_mutated = 0;
        if (mutating("relro-plain") || mutating("relative")) {
            for (size_t w = 0; w + 8 <= n; w += 8) {
                uint64_t va = rs + w;
                /* not .dynamic, not a typed word, not GOT[0..3]: those have checks of their own */
                if ((va >= dlo && va < dhi) || find_dest(va) || memcmp(f + w, m + w, 8) ||
                    (pltgot && (va >= pltgot ? va - pltgot < 24 : pltgot - va < 8)))
                    continue;
                if (mutating("relro-plain")) f[w] ^= 0x01;
                else { add_dest(va, D_RELATIVE, 8); qsort(dests, ndests, sizeof *dests, dest_cmp); }
                mutated(mutate, va);
                relro_mutated = 1;
                break;
            }
            if (!relro_mutated) printf("MUTATE %s not applicable to this image\n", mutate);
        }
        size_t hole_diff = 0, rel_ok = 0, rel_bad = 0, plain = 0, plain_bad = 0;
        for (size_t w = 0; w < n;) {
            uint64_t va = rs + w;
            if (va >= dlo && va < dhi) { w = (size_t)(dhi - rs); continue; }
            const Dest *k = find_dest(va);
            if (k && w + (size_t)k->width <= n && k->addr == va) {
                if (k->kind == D_HOLE) {
                    /* the no-slide mutation writes the unslid file value into
                     * the loaded copy of every destination it reaches */
                    if (mutating("no-slide")) memcpy(m + w, f + w, (size_t)k->width);
                    if (memcmp(f + w, m + w, (size_t)k->width)) hole_diff++;
                } else {
                    uint64_t fv, mv;
                    memcpy(&fv, f + w, 8);
                    memcpy(&mv, m + w, 8);
                    if (mv - bias == fv) rel_ok++;
                    else { rel_bad++; if (rel_bad <= 5) printf("RELATIVE_BAD va=0x%" PRIx64 "\n", va); }
                }
                w += (size_t)k->width;
                continue;
            }
            plain++;
            if (f[w] != m[w]) {
                if (plain_bad < 5) printf("PLAIN_DIFF relro va=0x%" PRIx64 " file=%02x mem=%02x\n", va, f[w], m[w]);
                plain_bad++;
            }
            w++;
        }
        if (mutating("no-slide")) mutated("no-slide", rs);
        printf("RELRO vaddr=0x%" PRIx64 " memsz=%" PRIu64 " file_backed=%zu\n", rs, (uint64_t)relro->p_memsz, n);
        printf("RELRO_SUMMARY hole_words_differing=%zu relative_ok=%zu relative_bad=%zu plain_bytes=%zu plain_differing=%zu\n",
               hole_diff, rel_ok, rel_bad, plain, plain_bad);
        if (plain_bad) FAIL(B_TYPING, "%zu Plain RELRO bytes differ from the file", plain_bad);
        if (rel_bad) FAIL(B_RELATIVE, "%zu Relative words do not normalise", rel_bad);
        if (nh && !hole_diff) FAIL(B_CONTROL, "no RELA destination differed: the image was not relocated, the run is void");
        if (!nh && !bionic) FAIL(B_CONTROL, "no RELA destination at all: nothing shows the image was relocated");
        if (!plain) FAIL(B_TYPING, "no Plain RELRO byte was compared");
        free(m);
    }

    /* -- GOT[0..3] -- */
    if (!pltgot) {
        FAIL(B_GOT, "DT_PLTGOT absent");
    } else {
        uint64_t fo = v2o(pltgot);
        uint8_t *fw = fo == UINT64_MAX ? NULL : F(fo, 24);
        uint8_t mw[24];
        if (fw && mutating("got")) { fw[0] ^= 0x01; mutated("got", pltgot); }
        uint64_t at;
        if (!fw || !add_ok(bias, pltgot, &at) || read_mem(at, mw, 24)) {
            FAIL(B_GOT, "GOT unreadable");
        } else {
            printf("GOT unchanged=%s\n", memcmp(fw, mw, 24) ? "NO" : "yes");
            if (memcmp(fw, mw, 24)) FAIL(B_GOT, "GOT[0..3] written by the loader");
        }
    }

    /* -- FileOnly: every other file-backed byte of the writable PT_LOADs -- */
    {
        int regions = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_W)) continue;
            uint64_t s = ph[i].p_vaddr, e, relro_end = 0;
            if (!add_ok(s, ph[i].p_filesz, &e) || (relro && !add_ok(relro->p_vaddr, relro->p_memsz, &relro_end))) {
                FAIL(B_FILEONLY, "writable PT_LOAD %d's extent wraps", i);
                continue;
            }
            if (relro && s >= relro->p_vaddr && s < relro_end) s = relro_end;
            if (e <= s) continue;
            regions++;
            size_t n = (size_t)(e - s);
            uint64_t fo;
            if (!add_ok(ph[i].p_offset, s - ph[i].p_vaddr, &fo)) fo = UINT64_MAX;
            const uint8_t *f = mutating("fileonly") ? NULL : F(fo, n);
            uint8_t *m = f ? malloc(n) : NULL;
            if (mutating("fileonly")) mutated("fileonly", s);
            uint64_t at;
            if (!m || !f || !add_ok(bias, s, &at) || read_mem(at, m, n)) {
                FAIL(B_FILEONLY, "FileOnly region at 0x%" PRIx64 " unreadable", s);
            } else {
                size_t diff = 0;
                for (size_t w = 0; w + 8 <= n; w += 8) if (memcmp(f + w, m + w, 8)) diff++;
                printf("FILEONLY vaddr=0x%" PRIx64 " file_off=0x%" PRIx64 " file_backed=%zu words_written_by_loader_or_module=%zu\n",
                       s, fo, n, diff);
            }
            free(m);
        }
        if (!regions) FAIL(B_FILEONLY, "no writable file-backed region: expected at least .data");
    }
    return finish();
}
