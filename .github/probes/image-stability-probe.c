/* Loaded-image stability probe — a DESIGN MEASUREMENT, not production code.
 *
 * Question it answers, per ISC-2 of the integrity-platform workstream:
 * which parts of a loaded shared library are identical across runs despite
 * ASLR, and do those parts equal the corresponding bytes of the file on disk?
 * A region satisfying both can be hashed at build time from the file and
 * re-hashed at runtime from memory — which is how a pre-operational integrity
 * test survives a platform that rewrites or encrypts the file after signing.
 *
 * The hash is FNV-1a 64. It measures INVARIANCE, not integrity; it is not a
 * stand-in for HMAC and must never be read as one.
 *
 * Output is one `REGION` line per mapped/loaded region plus a `LOADBASE` line,
 * in the same format on every platform so one analyser handles all of them.
 *
 * Build:  cc -O1 -o probe image-stability-probe.c        (macOS)
 *         cc -O1 -o probe image-stability-probe.c -ldl   (Linux)
 * Run:    ./probe <path-to-shared-library>
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#endif

static uint64_t fnv1a(const unsigned char *d, size_t n, uint64_t h) {
    for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= 1099511628211ULL; }
    return h;
}
#define FNV_INIT 14695981039346656037ULL

/* Hash `len` bytes of the file at `off`, zero-filling past EOF so a
 * memory region larger than its file backing still compares meaningfully. */
static uint64_t hash_file(int fd, off_t off, size_t len, int *ok) {
    uint64_t h = FNV_INIT;
    unsigned char buf[65536];
    size_t done = 0;
    *ok = 1;
    while (done < len) {
        size_t want = len - done;
        if (want > sizeof buf) want = sizeof buf;
        ssize_t got = pread(fd, buf, want, off + (off_t)done);
        if (got < 0) { *ok = 0; return h; }
        if ((size_t)got < want) memset(buf + got, 0, want - (size_t)got);
        h = fnv1a(buf, want, h);
        done += want;
    }
    return h;
}

#ifdef __APPLE__
static const char *base_name(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}
#endif

static void emit(const char *name, const char *perms, unsigned long fileoff,
                 size_t size, uint64_t mem, uint64_t file, int memok, int fileok) {
    printf("REGION name=%s perms=%s fileoff=0x%lx size=%zu mem=%s%016" PRIx64
           " file=%s%016" PRIx64 " cmp=%s\n",
           name, perms, fileoff, size,
           memok ? "" : "ERR:", mem,
           fileok ? "" : "ERR:", file,
           (memok && fileok) ? (mem == file ? "MATCH" : "DIFFER") : "UNKNOWN");
}

#ifdef __APPLE__
static int run_macho(const char *lib) {
    const char *want = base_name(lib);
    int idx = -1;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strcmp(base_name(nm), want) == 0) { idx = (int)i; break; }
    }
    if (idx < 0) { fprintf(stderr, "image not found among %u loaded\n", n); return 2; }

    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)idx);
    const char *nm = _dyld_get_image_name((uint32_t)idx);

    int fd = open(nm, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open(%s): cannot read own image file\n", nm); }

    const uint8_t *p = (const uint8_t *)mh + sizeof *mh;
    int regions = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
            /* filesize, not vmsize: vmsize includes zero-fill with no file backing. */
            if (sc->filesize > 0 && (sc->initprot & 1)) {
                const unsigned char *addr =
                    (const unsigned char *)(uintptr_t)(sc->vmaddr + (uint64_t)slide);
                uint64_t hm = fnv1a(addr, (size_t)sc->filesize, FNV_INIT);
                int fok = 0;
                uint64_t hf = (fd >= 0)
                    ? hash_file(fd, (off_t)sc->fileoff, (size_t)sc->filesize, &fok)
                    : 0;
                char nb[17]; snprintf(nb, sizeof nb, "%.16s", sc->segname);
                char perms[8];
                snprintf(perms, sizeof perms, "%c%c%c",
                         (sc->initprot & 1) ? 'r' : '-',
                         (sc->initprot & 2) ? 'w' : '-',
                         (sc->initprot & 4) ? 'x' : '-');
                emit(nb, perms, (unsigned long)sc->fileoff, (size_t)sc->filesize,
                     hm, hf, 1, fok);
                regions++;
            }
        }
        p += lc->cmdsize;
    }
    printf("LOADBASE 0x%lx REGIONS %d\n", (unsigned long)(uintptr_t)mh, regions);
    if (fd >= 0) close(fd);
    return regions ? 0 : 1;
}
#else
static int run_elf(const char *lib) {
    char rp[PATH_MAX];
    if (!realpath(lib, rp)) { perror("realpath"); return 2; }

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) { perror("/proc/self/maps"); return 2; }
    int memfd = open("/proc/self/mem", O_RDONLY);
    int filefd = open(rp, O_RDONLY);
    if (memfd < 0) { perror("/proc/self/mem"); return 2; }

    char line[4096];
    unsigned long first = 0;
    int regions = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long lo, hi, off;
        char perms[16], path[PATH_MAX];
        path[0] = '\0';
        if (sscanf(line, "%lx-%lx %15s %lx %*s %*s %4095s",
                   &lo, &hi, perms, &off, path) < 5) continue;
        if (strcmp(path, rp) != 0) continue;
        if (!first) first = lo;
        if (perms[0] != 'r') continue;

        size_t len = hi - lo, done = 0;
        uint64_t hm = FNV_INIT;
        unsigned char buf[65536];
        int memok = 1;
        while (done < len) {
            size_t want = len - done;
            if (want > sizeof buf) want = sizeof buf;
            ssize_t got = pread(memfd, buf, want, (off_t)(lo + done));
            if (got <= 0) { memok = 0; break; }
            hm = fnv1a(buf, (size_t)got, hm);
            done += (size_t)got;
        }
        int fok = 0;
        uint64_t hf = (filefd >= 0) ? hash_file(filefd, (off_t)off, len, &fok) : 0;
        emit("-", perms, off, len, hm, hf, memok, fok);
        regions++;
    }
    printf("LOADBASE 0x%lx REGIONS %d\n", first, regions);
    return regions ? 0 : 1;
}
#endif

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <shared-library>\n", argv[0]); return 2; }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 2; }
#ifdef __APPLE__
    return run_macho(argv[1]);
#else
    return run_elf(argv[1]);
#endif
}
