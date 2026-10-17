/*
 * Reports, for each bound word of a loaded dylib, what the integrity test's
 * resolver check sees.
 *
 *   macho-bind-report <dylib> < binds.txt
 *
 * binds.txt holds one line per bound word, `rva library symbol` (the
 * symbol without the leading `_`), as macho-bind-list.py writes it from the
 * signer's --show listing. The dylib is loaded with dlopen and never
 * initialised. For each word it prints the loaded value, the address
 * dlsym gives the symbol through the named library's handle (RTLD_FIRST),
 * and what dladdr says of the word: image, symbol name and symbol address.
 * The verdict is EQUAL (word is the resolution), STUB (the integrity
 * test's x86_64 rule: `_<symbol>`, resolved by name from the record's
 * library through its re-exports as dyld resolves it, ends at a
 * stub-and-resolver export whose stub is the word, and the word is
 * `FF 25`) or OTHER. For every word that is not EQUAL it prints each hop of
 * that chain: library, name, flags, and the re-export's target or the
 * stub's and resolver's offsets. For every word that is not EQUAL
 * it also prints the six bytes at the word and, for `FF 25`, the pointer's
 * address and value, what dladdr says of the pointer's value and of the
 * resolution (image, symbol name, symbol address), and, for the five
 * libSystem functions it knows how to call harmlessly, the pointer's value
 * again after one call through the stub.
 *
 * Exit status: 0 every word EQUAL or STUB, 1 any OTHER, 2 the dylib or a
 * library could not be opened.
 */
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stddef.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* The ULEB128 at *p, below `end`; sets *ok to 0 on overrun or overflow. */
static uint64_t uleb(const uint8_t **p, const uint8_t *end, int *ok) {
    uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (*p >= end) break;
        uint8_t b = *(*p)++;
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) return v;
    }
    *ok = 0;
    return 0;
}

/* The Mach header of the loaded image whose path is `path`, or 0. */
static uintptr_t loaded_image(const char *path) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strcmp(name, path) == 0) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

/* One trie entry: flags, and for a stub its offsets, for a re-export its
 * ordinal and name. */
struct entry {
    uint64_t flags, stub, resolver, ordinal;
    char name[512];
};

/* Looks `name` up in the export trie of the image at `base`, and copies
 * its dependent library `ordinal` (1-based) into `dep` when asked; returns
 * 1 with the entry, 0 when there is none, -1 when no trie is found or it
 * is malformed. */
static int trie_lookup(uintptr_t base, const char *name, struct entry *e, uint64_t ordinal,
                       char *dep, size_t dep_size) {
    const uint8_t *h = (const uint8_t *)base;
    uint32_t magic, ncmds;
    memcpy(&magic, h, 4);
    memcpy(&ncmds, h + 16, 4);
    if (magic != 0xfeedfacf) return -1;
    const uint8_t *c = h + 32;
    uint64_t text = 0, le_vm = 0, le_off = 0, k = 0;
    uint32_t off = 0, size = 0;
    int have_text = 0, have_le = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd, cmdsize;
        memcpy(&cmd, c, 4);
        memcpy(&cmdsize, c + 4, 4);
        if (cmd == 0x19) {
            if (strncmp((const char *)c + 8, "__TEXT", 16) == 0) {
                memcpy(&text, c + 24, 8);
                have_text = 1;
            } else if (strncmp((const char *)c + 8, "__LINKEDIT", 16) == 0) {
                memcpy(&le_vm, c + 24, 8);
                memcpy(&le_off, c + 40, 8);
                have_le = 1;
            }
        } else if (cmd == 0xc || cmd == 0x80000018 || cmd == 0x8000001f || cmd == 0x20 ||
                   cmd == 0x80000023) {
            if (++k == ordinal && dep) {
                uint32_t name_off;
                memcpy(&name_off, c + 8, 4);
                snprintf(dep, dep_size, "%s", (const char *)c + name_off);
            }
        } else if (cmd == 0x80000033) {
            memcpy(&off, c + 8, 4);
            memcpy(&size, c + 12, 4);
        } else if ((cmd == 0x22 || cmd == 0x80000022) && size == 0) {
            memcpy(&off, c + 40, 4);
            memcpy(&size, c + 44, 4);
        }
        if (cmdsize < 8) return -1;
        c += cmdsize;
    }
    if (!have_text || !have_le || size == 0 || off < le_off) return -1;
    const uint8_t *t = (const uint8_t *)(uintptr_t)(le_vm + (base - text) + (off - le_off));
    const uint8_t *end = t + size, *node = t;
    const char *rest = name;
    for (size_t step = 0; step <= strlen(name); step++) {
        int ok = 1;
        const uint8_t *p = node;
        uint64_t term = uleb(&p, end, &ok);
        if (!ok || term > (uint64_t)(end - p)) return -1;
        const uint8_t *children = p + term;
        if (*rest == 0) {
            if (term == 0) return 0;
            memset(e, 0, sizeof *e);
            e->flags = uleb(&p, end, &ok);
            if (e->flags & 0x08) {
                e->ordinal = uleb(&p, end, &ok);
                snprintf(e->name, sizeof e->name, "%s", (const char *)p);
            } else if (e->flags & 0x10) {
                e->stub = uleb(&p, end, &ok);
                e->resolver = uleb(&p, end, &ok);
            }
            return ok ? 1 : -1;
        }
        if (children >= end) return -1;
        uint8_t count = *children;
        p = children + 1;
        const uint8_t *next = NULL;
        size_t used = 0;
        for (uint8_t i = 0; i < count; i++) {
            size_t len = strnlen((const char *)p, (size_t)(end - p));
            if (len == 0 || p + len >= end) return -1;
            const char *edge = (const char *)p;
            p += len + 1;
            uint64_t child = uleb(&p, end, &ok);
            if (!ok || child >= size) return -1;
            if (!next && strncmp(rest, edge, len) == 0) {
                next = t + child;
                used = len;
            }
        }
        if (!next) return 0;
        rest += used;
        node = next;
    }
    return -1;
}

/* The dependent libraries of the image at `base`, in load-command order,
 * each marked when it is an LC_REEXPORT_DYLIB; returns how many. */
static int dependents(uintptr_t base, char paths[][1024], int whole[], int max) {
    const uint8_t *h = (const uint8_t *)base, *c = h + 32;
    uint32_t ncmds;
    memcpy(&ncmds, h + 16, 4);
    int n = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd, cmdsize, name_off;
        memcpy(&cmd, c, 4);
        memcpy(&cmdsize, c + 4, 4);
        if (cmd == 0xc || cmd == 0x80000018 || cmd == 0x8000001f || cmd == 0x20 ||
            cmd == 0x80000023) {
            if (n < max) {
                memcpy(&name_off, c + 8, 4);
                snprintf(paths[n], 1024, "%s", (const char *)c + name_off);
                whole[n] = cmd == 0x8000001f;
            }
            n++;
        }
        if (cmdsize < 8) break;
        c += cmdsize;
    }
    return n < max ? n : max;
}

/* One step of dyld's lookup (MachOLoaded::findExportedSymbol): `name` in
 * `lib`'s own trie, a per-symbol re-export followed, and on a miss each
 * LC_REEXPORT_DYLIB dependent in order. Appends each image looked in to
 * `out`. Returns 1 with the stub's address at a stub-and-resolver export,
 * 0 at any other export, 2 when no image exports the name, -1 when a
 * library is not loaded, a trie cannot be read, or a bound is passed (the
 * visit cap, 256 images, prints `cap`). */
static int find(const char *lib, const char *name, int depth, int *visits, uint64_t *stub,
                char *out, size_t size) {
    size_t used = strlen(out);
    if (depth > 8 || ++*visits > 256) {
        snprintf(out + used, size - used, " hop%d=%s:%s:cap", *visits - 1, lib, name);
        return -1;
    }
    uintptr_t base = loaded_image(lib);
    if (!base) {
        snprintf(out + used, size - used, " hop%d=%s:not-loaded", *visits - 1, lib);
        return -1;
    }
    struct entry e;
    int r = trie_lookup(base, name, &e, 0, NULL, 0);
    snprintf(out + used, size - used, " hop%d=%s:%s:", *visits - 1, lib, name);
    used = strlen(out);
    if (r < 0) {
        snprintf(out + used, size - used, "unreadable");
        return -1;
    }
    if (r == 0) {
        snprintf(out + used, size - used, "none");
        char (*paths)[1024] = calloc(512, 1024);
        int *whole = calloc(512, sizeof *whole);
        if (!paths || !whole) {
            free(paths);
            free(whole);
            return -1;
        }
        int n = dependents(base, paths, whole, 512);
        int f = 2;
        for (int i = 0; i < n && f == 2; i++) {
            if (whole[i]) f = find(paths[i], name, depth + 1, visits, stub, out, size);
        }
        free(paths);
        free(whole);
        return f;
    }
    snprintf(out + used, size - used, "flags=0x%" PRIx64, e.flags);
    if (e.flags & 0x08) {
        char dep[1024] = "";
        struct entry ignored;
        trie_lookup(base, "", &ignored, e.ordinal, dep, sizeof dep);
        used = strlen(out);
        snprintf(out + used, size - used, ":reexport=%" PRIu64 ":%s", e.ordinal,
                 e.name[0] ? e.name : name);
        if (!dep[0]) return -1;
        char next[512];
        snprintf(next, sizeof next, "%s", e.name[0] ? e.name : name);
        return find(dep, next, depth + 1, visits, stub, out, size);
    }
    if (e.flags & 0x10) {
        used = strlen(out);
        snprintf(out + used, size - used, ":stub=0x%" PRIx64 ":resolver=0x%" PRIx64, e.stub,
                 e.resolver);
        *stub = base + e.stub;
        return 1;
    }
    return 0;
}

/* Resolves `_<sym>` from `library` as dyld does; see find. */
static int resolve_chain(const char *library, const char *sym, uint64_t *stub, char *out,
                         size_t size) {
    char name[520];
    snprintf(name, sizeof name, "_%s", sym);
    int visits = 0;
    int r = find(library, name, 0, &visits, stub, out, size);
    return r == 2 ? 0 : r;
}

/* What dladdr says of `p`, appended to `out`. */
static void describe(char *out, size_t size, const char *label, uint64_t p) {
    Dl_info i;
    size_t used = strlen(out);
    if (used >= size) return;
    if (dladdr((const void *)(uintptr_t)p, &i)) {
        snprintf(out + used, size - used, " %s_image=%s %s_sname=%s %s_saddr=%p", label,
                 i.dli_fname, label, i.dli_sname ? i.dli_sname : "-", label, i.dli_saddr);
    } else {
        snprintf(out + used, size - used, " %s_image=- %s_sname=- %s_saddr=0x0", label, label,
                 label);
    }
}

/* Calls the stub at `word` once, harmlessly, when `sym` is one of the five
 * functions it knows; returns 1 when it called. */
static int call_through(const char *sym, uint64_t word) {
    unsigned char a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 4};
    void *f = (void *)(uintptr_t)word;
    if (strcmp(sym, "memcmp") == 0) {
        (void)((int (*)(const void *, const void *, size_t))f)(a, b, sizeof a);
        return 1;
    }
    if (strcmp(sym, "memcpy") == 0 || strcmp(sym, "memmove") == 0) {
        ((void *(*)(void *, const void *, size_t))f)(a, b, sizeof a);
        return 1;
    }
    if (strcmp(sym, "memset") == 0) {
        ((void *(*)(void *, int, size_t))f)(a, 0, sizeof a);
        return 1;
    }
    if (strcmp(sym, "__bzero") == 0) {
        ((void (*)(void *, size_t))f)(a, sizeof a);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: macho-bind-report <dylib> < binds.txt\n");
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }
    void *anchor = dlsym(h, "oxi_init");
    Dl_info self;
    if (!anchor || !dladdr(anchor, &self)) {
        fprintf(stderr, "cannot find the dylib's base\n");
        return 2;
    }
    uintptr_t base = (uintptr_t)self.dli_fbase;
    unsigned long rva;
    char lib[1024], sym[512];
    int other = 0, n = 0;
    while (scanf("%lx %1023s %511s", &rva, lib, sym) == 3) {
        n++;
        uint64_t word;
        memcpy(&word, (const void *)(base + rva), sizeof word);
        void *lh = dlopen(lib, RTLD_NOLOAD | RTLD_LAZY | RTLD_FIRST);
        void *res = lh ? dlsym(lh, sym) : NULL;
        Dl_info w, r;
        int wok = dladdr((const void *)(uintptr_t)word, &w);
        int rok = res && dladdr(res, &r);
        const char *verdict = "OTHER";
        char detail[4096] = "";
        if (res && word == (uint64_t)(uintptr_t)res) {
            verdict = "EQUAL";
        } else if (wok && rok && w.dli_fbase == r.dli_fbase) {
            const unsigned char *code = (const unsigned char *)(uintptr_t)word;
            snprintf(detail, sizeof detail, " bytes=%02x%02x%02x%02x%02x%02x", code[0],
                             code[1], code[2], code[3], code[4], code[5]);
            uint64_t chain_stub = 0;
            int found = resolve_chain(lib, sym, &chain_stub, detail, sizeof detail);
            size_t used0 = strlen(detail);
            snprintf(detail + used0, sizeof detail - used0, " chain_stub_is_word=%d",
                     found == 1 && chain_stub == word);
            if (found == 1 && chain_stub == word && code[0] == 0xff && code[1] == 0x25)
                verdict = "STUB";
            if (code[0] == 0xff && code[1] == 0x25) {
                int32_t disp;
                memcpy(&disp, code + 2, sizeof disp);
                uint64_t at = word + 6 + (int64_t)disp;
                Dl_info p;
                uint64_t value = 0;
                int pok = dladdr((const void *)(uintptr_t)at, &p) && p.dli_fbase == r.dli_fbase;
                if (pok) memcpy(&value, (const void *)(uintptr_t)at, sizeof value);
                size_t at_end = strlen(detail);
                snprintf(detail + at_end, sizeof detail - at_end,
                         " pointer=0x%" PRIx64 " pointer_in_image=%d value=0x%" PRIx64, at, pok,
                         value);
                describe(detail, sizeof detail, "value", value);
                describe(detail, sizeof detail, "resolved", (uint64_t)(uintptr_t)res);
                if (pok && call_through(sym, word)) {
                    uint64_t after;
                    memcpy(&after, (const void *)(uintptr_t)at, sizeof after);
                    size_t used = strlen(detail);
                    snprintf(detail + used, sizeof detail - used,
                             " value_after_call=0x%" PRIx64 " after_equals_resolved=%d", after,
                             after == (uint64_t)(uintptr_t)res);
                    describe(detail, sizeof detail, "after", after);
                }
            }
        }
        if (strcmp(verdict, "OTHER") == 0) other++;
        printf("BIND rva=0x%lx %s %s word=0x%" PRIx64 " resolved=%p word_image=%s "
               "word_sname=%s word_saddr=%p resolved_image=%s%s %s\n",
               rva, lib, sym, word, res, wok ? w.dli_fname : "-",
               wok && w.dli_sname ? w.dli_sname : "-", wok ? w.dli_saddr : NULL,
               rok ? r.dli_fname : "-", detail, verdict);
    }
    printf("RESULT binds=%d other=%d\n", n, other);
    if (n == 0) return 2;
    return other ? 1 : 0;
}
