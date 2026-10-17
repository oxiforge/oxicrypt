/* Typed loaded-image probe for Mach-O dylibs (macOS, arm64 and x86_64).
 *
 * A DESIGN MEASUREMENT of what dyld does to a dylib, not the integrity oracle:
 * the oracle is the signed module at initialisation, which `ffi-operational`
 * reads. The probe dlopen()s the dylib, reads each segment back through
 * mach_vm_read_overwrite, the kernel-mediated route the verifier uses, and
 * applies the second extent's entry kinds:
 *
 *   Plain     every byte of the header, the load commands and the pad, of
 *             each read-only segment, of `__DATA_CONST` outside its fixup
 *             words, and of `__LINKEDIT` up to the code signature: loaded
 *             value equals the file value
 *   Relative  a rebase word: loaded value minus the slide equals the unslid
 *             target the file encodes
 *   Bind      a bind word: loaded value equals the symbol the record names,
 *             resolved in the library its ordinal names, plus the addend; an
 *             unresolved weak import must read zero; a symbol exported with
 *             a resolver may instead hold its resolver stub in the named
 *             library or a re-export (resolver_stub())
 *   FileOnly  every other file-backed byte of a writable segment, read from
 *             the file dladdr() reports
 *
 * Fixups are parsed from LC_DYLD_CHAINED_FIXUPS (DYLD_CHAINED_PTR_64 and
 * _64_OFFSET) or from the LC_DYLD_INFO rebase and bind opcode streams. The
 * opcode form is typed too, so a shipped artifact can be measured, but it is
 * a refusal: the extent requires chained fixups.
 *
 * Every required condition sets a bit; 0 is the pass. The probe always ends
 * with one `RESULT status=N` line.
 *
 *   bit 0 (1)   typing: every Plain byte equals the file
 *   bit 1 (2)   length: the reported file opens and holds every segment's
 *               file extent and the code signature's offset
 *   bit 2 (4)   refusal: opcode-encoded fixups, no fixup information at all,
 *               an unsupported chained pointer format, a special library
 *               ordinal, a fixup outside its segment's file bytes, a broken
 *               chain, `__la_symbol_ptr` or `__nl_symbol_ptr`
 *   bit 3 (8)   Bind words equal their resolution plus addend
 *   bit 4 (16)  FileOnly regions present and readable from the file
 *   bit 5 (32)  control: the slide is non-zero and at least one rebase word
 *               differs from its unslid value, so the run says something; an
 *               image with no rebase at all fails it
 *   bit 6 (64)  setup: the dylib loaded, was found among dyld's images, and
 *               every segment read back
 *   bit 7 (128) Relative words normalise
 *
 * Options:
 *   --simulate SLIDE   do not load anything: build the loaded image from the
 *                      file the way dyld would (rebase words slid, bind words
 *                      set to a stand-in resolution) and type that. It drives
 *                      the parser, the typing and every mutation on a host
 *                      without dyld; it proves nothing about dyld itself.
 *   --mutate NAME      change one value a check consumes, after loading and
 *                      parsing, so that check and only that check fails
 *   --list-mutations   print each mutation name and the bit it must set
 *
 * Every offset and size read from the file is checked against the file length
 * before use; a segment whose file extent does not fit sets the length bit
 * and is never read or typed; zero Plain or FileOnly bytes is a failure.
 *
 * Builds with no SDK headers beyond the C library: the few dyld and Mach
 * entry points it calls are declared here.
 */
#define _GNU_SOURCE /* Dl_info on glibc, for the declarations check */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(DARWIN_DECLARATIONS_CHECK)
#define HAVE_DYLD 1
extern uint32_t _dyld_image_count(void);
extern const char *_dyld_get_image_name(uint32_t);
extern const void *_dyld_get_image_header(uint32_t);
extern intptr_t _dyld_get_image_vmaddr_slide(uint32_t);
extern unsigned int mach_task_self_;
extern int mach_vm_read_overwrite(unsigned int task, uint64_t addr, uint64_t size, uint64_t data, uint64_t *outsize);
#ifndef RTLD_FIRST
#define RTLD_FIRST 0x100
#endif
#endif

enum {
    B_TYPING = 1, B_LENGTH = 2, B_REFUSE = 4, B_BIND = 8,
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

static const struct { const char *name; int bit; } mutations[] = {
    { "header-plain", B_TYPING },    /* a byte of the load commands          */
    { "text-plain", B_TYPING },      /* a byte in the middle of __TEXT       */
    { "linkedit-plain", B_TYPING },  /* the first byte of __LINKEDIT         */
    { "dataconst-plain", B_TYPING }, /* a Plain word of __DATA_CONST         */
    { "length", B_LENGTH },          /* the opened length, one byte short    */
    { "form-none", B_REFUSE },       /* no fixup information, as parsed      */
    { "lazy-section", B_REFUSE },    /* a parsed section renamed lazy          */
    { "bind", B_BIND },              /* the first bind's resolution, +8      */
    { "fileonly", B_FILEONLY },      /* the FileOnly file range, past the end */
    { "no-slide", B_CONTROL },       /* the image as if dyld never moved it  */
    { "relative", B_RELATIVE },      /* a Plain __TEXT word typed Relative   */
};
static const char *mutate;
static int mutating(const char *n) { return mutate && !strcmp(mutate, n); }
static void mutated(const char *n, uint64_t where) { printf("MUTATE %s at 0x%" PRIx64 "\n", n, where); }

/* ---- the file ------------------------------------------------------------ */

static uint8_t *F;
static size_t flen;
static int bad_read;

static int add_ok(uint64_t a, uint64_t b, uint64_t *out) {
    if (a > UINT64_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static uint64_t rd(uint64_t off, int n) {
    uint64_t v = 0;
    if (off + (uint64_t)n > flen || off + (uint64_t)n < off) { bad_read = 1; return 0; }
    for (int i = n - 1; i >= 0; i--) v = (v << 8) | F[off + (uint64_t)i];
    return v;
}
static uint64_t uleb(uint64_t *p, uint64_t end) {
    uint64_t v = 0;
    int s = 0;
    while (*p < end) {
        uint8_t b = F[(*p)++];
        if (s < 64) v |= (uint64_t)(b & 0x7f) << s;
        s += 7;
        if (!(b & 0x80)) return v;
    }
    bad_read = 1;
    return v;
}
/* Accumulated unsigned, sign-extended at the end: no signed shift. */
static int64_t sleb(uint64_t *p, uint64_t end) {
    uint64_t v = 0;
    int s = 0;
    uint8_t b = 0;
    while (*p < end) {
        b = F[(*p)++];
        if (s < 64) v |= (uint64_t)(b & 0x7f) << s;
        s += 7;
        if (!(b & 0x80)) break;
    }
    if (s < 64 && (b & 0x40)) v |= ~(uint64_t)0 << s;
    return (int64_t)v;
}
static const char *cstr(uint64_t off) {
    if (off >= flen || !memchr(F + off, 0, flen - off)) { bad_read = 1; return ""; }
    return (const char *)F + off;
}

typedef struct {
    char name[17];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t initprot, flags;
    int bad;      /* the file extent does not fit the file: never read or typed */
    uint8_t *mem; /* the loaded bytes of the file extent */
} Seg;
static Seg segs[32];
static int nsegs;
static const char *dylibs[256];
static int ndylibs;
static uint64_t sizeofcmds, codesig_off = UINT64_MAX;
typedef struct { char name[17]; uint32_t type; } Sect;
static Sect sects[512];
static int nsects_all;
static uint64_t fixup_cap; /* one fixup per 8 file-backed bytes at most */

typedef struct {
    uint64_t addr; /* vmaddr, for reporting and the cross-check */
    int seg;       /* the segment the record placed it in, by index */
    uint64_t off;  /* its offset in that segment's file bytes */
    int consumed;  /* examined by the typing, or covered by FileOnly */
    int bind, ord, weak;
    uint64_t target; /* rebase: the unslid value */
    const char *sym;
    int64_t addend;
} Fixup;
static Fixup *fx;
static size_t nfx, capfx;
static int opcode_form, chained_form;

static int finish(void);

/* Records a fixup at `off` in segment `seg`. Returns 0, and refuses, when the
 * word does not lie inside the segment's file extent or the table is already
 * as large as the file allows; the caller then stops its stream, so a hostile
 * repeat count ends here. */
static int emit(int seg, uint64_t off, Fixup f) {
    if (seg < 0 || seg >= nsegs || segs[seg].bad || segs[seg].filesize < 8 || off > segs[seg].filesize - 8) {
        FAIL(B_REFUSE, "a fixup at segment %d offset 0x%" PRIx64 " lies outside the segment's file bytes", seg, off);
        return 0;
    }
    if (nfx >= fixup_cap) { FAIL(B_REFUSE, "more fixups than the file has words"); return 0; }
    if (nfx == capfx) {
        size_t cap = capfx ? capfx * 2 : 1024;
        Fixup *n = realloc(fx, cap * sizeof *fx);
        if (!n) { FAIL(B_SETUP, "out of memory for the fixup table"); finish(); exit(B_SETUP); }
        fx = n;
        capfx = cap;
    }
    f.addr = segs[seg].vmaddr + off;
    f.seg = seg;
    f.off = off;
    f.consumed = 0;
    fx[nfx++] = f;
    return 1;
}
/* Fixups are keyed by (segment index, offset), never by vmaddr: a hostile
 * image with overlapping segments must not let one segment's record be read
 * against another's bytes. */
static int fx_cmp(const void *a, const void *b) {
    const Fixup *x = a, *y = b;
    if (x->seg != y->seg) return x->seg < y->seg ? -1 : 1;
    return x->off < y->off ? -1 : x->off > y->off;
}
static Fixup *find_fixup(int seg, uint64_t off) {
    size_t lo = 0, hi = nfx;
    while (lo < hi) {
        size_t m = (lo + hi) / 2;
        if (fx[m].seg < seg || (fx[m].seg == seg && fx[m].off < off)) lo = m + 1; else hi = m;
    }
    return lo < nfx && fx[lo].seg == seg && fx[lo].off == off ? &fx[lo] : NULL;
}
static int special_ord(int ord) { return ord <= 0 || ord > ndylibs; }

static void parse_rebase(uint64_t p, uint64_t end) {
    int seg = 0;
    uint64_t off = 0;
#define EMIT_REBASE                                                                       \
    do {                                                                                  \
        if (!emit(seg, off, (Fixup){ .target = seg < nsegs ? rd(segs[seg].fileoff + off, 8) : 0 })) \
            return;                                                                       \
    } while (0)
    while (p < end) {
        uint8_t op = F[p] & 0xf0, imm = F[p] & 0x0f;
        p++;
        uint64_t n, skip;
        switch (op) {
        case 0x00: return;
        case 0x10: break;
        case 0x20: seg = imm; off = uleb(&p, end); break;
        case 0x30: off += uleb(&p, end); break;
        case 0x40: off += (uint64_t)imm * 8; break;
        case 0x50: for (int i = 0; i < imm; i++) { EMIT_REBASE; off += 8; } break;
        case 0x60: n = uleb(&p, end); for (uint64_t i = 0; i < n; i++) { EMIT_REBASE; off += 8; } break;
        case 0x70: n = uleb(&p, end); EMIT_REBASE; off += n + 8; break;
        case 0x80: n = uleb(&p, end); skip = uleb(&p, end);
            for (uint64_t i = 0; i < n; i++) { EMIT_REBASE; off += skip + 8; } break;
        default: FAIL(B_REFUSE, "rebase opcode 0x%x", op); return;
        }
    }
#undef EMIT_REBASE
}

static void parse_bind(uint64_t p, uint64_t end) {
    int seg = 0, ord = 0, weak = 0;
    uint64_t off = 0;
    int64_t addend = 0;
    const char *sym = "";
#define EMIT_BIND                                                                         \
    do {                                                                                  \
        if (!emit(seg, off, (Fixup){ .bind = 1, .ord = ord, .weak = weak, .sym = sym, .addend = addend })) return;         \
    } while (0)
    while (p < end) {
        uint8_t op = F[p] & 0xf0, imm = F[p] & 0x0f;
        p++;
        uint64_t n, skip;
        switch (op) {
        case 0x00: return;
        case 0x10: ord = imm; break;
        case 0x20: ord = (int)uleb(&p, end); break;
        case 0x30: ord = imm ? (int)(int8_t)(0xf0 | imm) : 0; break;
        case 0x40: sym = cstr(p); weak = imm & 1; p += strlen(sym) + 1; break;
        case 0x50: break;
        case 0x60: addend = sleb(&p, end); break;
        case 0x70: seg = imm; off = uleb(&p, end); break;
        case 0x80: off += uleb(&p, end); break;
        case 0x90: EMIT_BIND; off += 8; break;
        case 0xa0: n = uleb(&p, end); EMIT_BIND; off += n + 8; break;
        case 0xb0: EMIT_BIND; off += (uint64_t)imm * 8 + 8; break;
        case 0xc0: n = uleb(&p, end); skip = uleb(&p, end);
            for (uint64_t i = 0; i < n; i++) { EMIT_BIND; off += skip + 8; } break;
        default: FAIL(B_REFUSE, "bind opcode 0x%x", op); return;
        }
    }
#undef EMIT_BIND
}

/* The blob's own fields are 32-bit offsets into a blob whose extent was
 * checked against the file, so every sum below stays far from wrapping; each
 * structure is still checked to lie inside the blob before it is read. */
static void parse_chained(uint64_t blob, uint64_t size) {
    uint64_t end = blob + size;
    if (size < 28) { FAIL(B_REFUSE, "chained fixups header shorter than its fields"); return; }
    uint64_t starts = blob + rd(blob + 4, 4), imports = blob + rd(blob + 8, 4), symbols = blob + rd(blob + 12, 4);
    uint32_t nimports = (uint32_t)rd(blob + 16, 4), ifmt = (uint32_t)rd(blob + 20, 4);
    uint64_t link_base = nsegs ? segs[0].vmaddr : 0;
    for (int i = 0; i < nsegs; i++)
        if (!strcmp(segs[i].name, "__TEXT")) link_base = segs[i].vmaddr;
    if (starts + 4 > end) { FAIL(B_REFUSE, "chained starts table outside the blob"); return; }
    uint32_t seg_count = (uint32_t)rd(starts, 4);
    if (bad_read || starts + 4 + 4 * (uint64_t)seg_count > end) { FAIL(B_REFUSE, "chained fixups header out of range"); return; }
    uint64_t iwidth = ifmt == 1 ? 4 : ifmt == 2 ? 8 : ifmt == 3 ? 16 : 0;
    if (!iwidth) { FAIL(B_REFUSE, "import format %u", ifmt); return; }
    if (imports + iwidth * (uint64_t)nimports > end || symbols > end) { FAIL(B_REFUSE, "chained import table outside the blob"); return; }
    for (uint32_t s = 0; s < seg_count && s < (uint32_t)nsegs; s++) {
        uint64_t info = rd(starts + 4 + 4 * (uint64_t)s, 4);
        if (!info) continue;
        uint64_t b = starts + info;
        if (b + 22 > end) { FAIL(B_REFUSE, "chained segment %u's starts lie outside the blob", s); continue; }
        uint32_t page_size = (uint32_t)rd(b + 4, 2), fmt = (uint32_t)rd(b + 6, 2), pages = (uint32_t)rd(b + 20, 2);
        if (b + 22 + 2 * (uint64_t)pages > end) { FAIL(B_REFUSE, "chained segment %u's page table lies outside the blob", s); continue; }
        if (fmt != 2 && fmt != 6) { FAIL(B_REFUSE, "chained pointer format %u", fmt); continue; }
        Seg *sg = &segs[s];
        if (sg->bad) continue;
        /* the page size dyld walks with, and the segment's own offset from
         * the image start, must be the segment's: anything else is a table
         * describing some other layout */
        if (page_size != 0x1000 && page_size != 0x4000) { FAIL(B_REFUSE, "chained page size %u", page_size); continue; }
        if (rd(b + 8, 8) != sg->vmaddr - link_base) {
            FAIL(B_REFUSE, "chained segment %u's offset 0x%" PRIx64 " is not its segment's 0x%" PRIx64, s, rd(b + 8, 8),
                 sg->vmaddr - link_base);
            continue;
        }
        for (uint32_t pg = 0; pg < pages; pg++) {
            uint32_t start = (uint32_t)rd(b + 22 + 2 * (uint64_t)pg, 2);
            if (start == 0xffff) continue;
            if (start & 0x8000) { FAIL(B_REFUSE, "multi-start chain page"); continue; }
            uint64_t o = (uint64_t)pg * page_size + start;
            for (int steps = 0;; steps++) {
                if (o + 8 > sg->filesize || steps > 1 << 20) { FAIL(B_REFUSE, "chain leaves its segment"); break; }
                uint64_t v = rd(sg->fileoff + o, 8);
                Fixup f = { .bind = (int)(v >> 63) };
                if (f.bind) {
                    uint32_t k = (uint32_t)(v & 0xffffff);
                    f.addend = (int64_t)((v >> 24) & 0xff);
                    if (k >= nimports) { FAIL(B_REFUSE, "bind ordinal %u beyond %u imports", k, nimports); break; }
                    uint64_t name_off;
                    if (ifmt == 1 || ifmt == 2) {
                        uint64_t w = rd(imports + (uint64_t)k * (ifmt == 1 ? 4 : 8), 4);
                        uint32_t lo = (uint32_t)(w & 0xff);
                        f.ord = lo > 0xf0 ? (int)(int8_t)lo : (int)lo;
                        f.weak = (int)((w >> 8) & 1);
                        name_off = w >> 9;
                        if (ifmt == 2 && __builtin_add_overflow(f.addend, (int64_t)(int32_t)rd(imports + (uint64_t)k * 8 + 4, 4), &f.addend)) {
                            FAIL(B_REFUSE, "a bind addend overflows");
                            break;
                        }
                    } else if (ifmt == 3) {
                        uint64_t w = rd(imports + (uint64_t)k * 16, 8);
                        uint32_t lo = (uint32_t)(w & 0xffff);
                        f.ord = lo > 0xfff0 ? (int)(int16_t)lo : (int)lo;
                        f.weak = (int)((w >> 16) & 1);
                        name_off = w >> 32;
                        if (__builtin_add_overflow(f.addend, (int64_t)rd(imports + (uint64_t)k * 16 + 8, 8), &f.addend)) {
                            FAIL(B_REFUSE, "a bind addend overflows");
                            break;
                        }
                    } else break;
                    f.sym = cstr(symbols + name_off);
                } else {
                    uint64_t target = v & 0xfffffffffULL, high8 = (v >> 36) & 0xff;
                    f.target = (fmt == 6 ? link_base + target : target) | (high8 << 56);
                }
                if (!emit((int)s, o, f)) break;
                uint64_t next = (v >> 51) & 0xfff;
                if (!next) break;
                o += next * 4;
            }
        }
    }
}

static void parse(void) {
    if (rd(0, 4) != 0xfeedfacf) { FAIL(B_SETUP, "not a thin 64-bit Mach-O"); return; }
    uint32_t ncmds = (uint32_t)rd(16, 4);
    sizeofcmds = rd(20, 4);
    if (32 + sizeofcmds > flen) { FAIL(B_SETUP, "load commands (%" PRIu64 " bytes) run past the file", sizeofcmds); return; }
    uint64_t off = 32, chained = 0, chained_size = 0;
    uint32_t info[10] = { 0 };
    int have_info = 0;
    for (uint32_t i = 0; i < ncmds && !bad_read; i++) {
        uint32_t cmd = (uint32_t)rd(off, 4), size = (uint32_t)rd(off + 4, 4);
        if (size < 8 || off + size > 32 + sizeofcmds) {
            FAIL(B_SETUP, "load command %u (size %u) does not fit the load-command area", i, size);
            return;
        }
        if (cmd == 0x19 && nsegs < 32) {
            if (size < 72 || (size - 72) / 80 < rd(off + 64, 4)) {
                FAIL(B_SETUP, "segment command %u is too small for its sections", i);
                return;
            }
            Seg *s = &segs[nsegs++];
            memset(s, 0, sizeof *s);
            memcpy(s->name, F + off + 8, 16);
            s->vmaddr = rd(off + 24, 8);
            s->vmsize = rd(off + 32, 8);
            s->fileoff = rd(off + 40, 8);
            s->filesize = rd(off + 48, 8);
            s->initprot = (uint32_t)rd(off + 60, 4);
            uint32_t nsects = (uint32_t)rd(off + 64, 4);
            s->flags = (uint32_t)rd(off + 68, 4);
            uint64_t send;
            if (s->fileoff > flen || s->filesize > flen - s->fileoff || !add_ok(s->fileoff, s->filesize, &send)) {
                FAIL(B_LENGTH, "segment %.16s's file extent 0x%" PRIx64 "+0x%" PRIx64 " does not fit the file", s->name,
                     s->fileoff, s->filesize);
                s->bad = 1;
            }
            for (uint32_t k = 0; k < nsects && nsects_all < 512; k++) {
                Sect *t = &sects[nsects_all++];
                memset(t, 0, sizeof *t);
                memcpy(t->name, F + off + 72 + 80 * (uint64_t)k, 16);
                t->type = (uint32_t)rd(off + 72 + 80 * (uint64_t)k + 64, 4) & 0xff;
            }
        } else if ((cmd == 0xc || cmd == 0x80000018 || cmd == 0x8000001f || cmd == 0x20 || cmd == 0x80000023) && ndylibs < 256) {
            dylibs[ndylibs++] = cstr(off + rd(off + 8, 4));
        } else if (cmd == 0x22 || cmd == 0x80000022) {
            have_info = 1;
            for (int k = 0; k < 10; k++) info[k] = (uint32_t)rd(off + 8 + 4 * (uint64_t)k, 4);
        } else if (cmd == 0x80000034) {
            chained = rd(off + 8, 4);
            chained_size = rd(off + 12, 4);
        } else if (cmd == 0x1d) {
            codesig_off = rd(off + 8, 4);
        }
        off += size;
    }
    if (bad_read) { FAIL(B_SETUP, "load commands run past the file"); return; }
    for (int i = 0; i < nsegs; i++)
        if (!segs[i].bad) fixup_cap += segs[i].filesize / 8;
    if (chained) {
        chained_form = 1;
        if (chained > flen || chained_size > flen - chained) FAIL(B_LENGTH, "LC_DYLD_CHAINED_FIXUPS runs past the file");
        else parse_chained(chained, chained_size);
    }
    if (have_info) {
        opcode_form = 1;
        /* (offset, size) pairs: rebase, bind, weak bind, lazy bind, export */
        for (int k = 0; k < 10; k += 2)
            if (info[k] > flen || info[k + 1] > flen - info[k]) {
                FAIL(B_LENGTH, "LC_DYLD_INFO range %d (0x%x+0x%x) runs past the file", k / 2, info[k], info[k + 1]);
                info[k] = info[k + 1] = 0;
            }
        if (info[1]) parse_rebase(info[0], (uint64_t)info[0] + info[1]);
        if (info[3]) parse_bind(info[2], (uint64_t)info[2] + info[3]);
    }
    if (bad_read) FAIL(B_REFUSE, "a fixup record runs past the file");
    if (nfx) qsort(fx, nfx, sizeof *fx, fx_cmp);
    /* Segments whose VM ranges wrap or overlap describe no image a loader
     * would map: refused, and the overlap is never resolved by address. */
    for (int i = 0; i < nsegs; i++) {
        uint64_t ei;
        if (!segs[i].vmsize) continue;
        if (!add_ok(segs[i].vmaddr, segs[i].vmsize, &ei)) { FAIL(B_REFUSE, "segment %s's VM range wraps", segs[i].name); continue; }
        for (int j = i + 1; j < nsegs; j++) {
            uint64_t ej;
            if (!segs[j].vmsize || !add_ok(segs[j].vmaddr, segs[j].vmsize, &ej)) continue;
            if (segs[i].vmaddr < ej && segs[j].vmaddr < ei) FAIL(B_REFUSE, "segments %s and %s overlap in memory", segs[i].name, segs[j].name);
        }
    }
    for (size_t i = 1; i < nfx; i++)
        if (fx[i].addr < fx[i - 1].addr + 8) FAIL(B_REFUSE, "fixups overlap at 0x%" PRIx64, fx[i].addr);
}

/* ---- resolution ---------------------------------------------------------- */

static int simulate;
static int64_t slide;
static size_t route_first, route_unresolved;

static uint64_t stand_in(const char *sym) {
    uint64_t h = 1469598103934665603ULL;
    for (const char *c = sym; *c; c++) h = (h ^ (uint8_t)*c) * 1099511628211ULL;
    return 0x7f0000000000ULL + ((h & 0xffffffffULL) << 4);
}

/* 0 when the symbol does not resolve */
static uint64_t resolve(const Fixup *f) {
    if (simulate) return stand_in(f->sym);
#ifdef HAVE_DYLD
    /* Resolved only in the library the ordinal names: RTLD_FIRST keeps dlsym
     * from searching that library's dependents, so a same-named symbol from
     * another library is a mismatch, never a match. No retry without it. */
    const char *name = f->sym[0] == '_' ? f->sym + 1 : f->sym;
    void *h = dlopen(dylibs[f->ord - 1], RTLD_NOLOAD | RTLD_LAZY | RTLD_FIRST);
    void *p = h ? dlsym(h, name) : NULL;
    if (p) route_first++;
    else route_unresolved++;
    return (uint64_t)(uintptr_t)p;
#else
    (void)f;
    return 0;
#endif
}

/* A symbol exported with a resolver (EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
 * as libSystem's memcpy and friends are on x86_64) is bound by dyld to a
 * resolver stub that carries no exported name, while dlsym runs the resolver
 * and returns a CPU-variant implementation in the same image. Such a word is
 * accepted only when all of these hold:
 *   (1) the record has no addend;
 *   (2) the dlsym result is not the word itself;
 *   (3) dladdr places the word and the dlsym result in the same image;
 *   (4) that image is the library the ordinal names, or one that library
 *       re-exports (LC_REEXPORT_DYLIB), so the binding went to the right
 *       library;
 *   (5) the word lies inside that image's __TEXT segment.
 * A same-named symbol in an unrelated library, or a word outside that
 * image's __TEXT, still fails. Never in simulation. When the word is not
 * accepted, `stub_why` names the first condition that failed and
 * `stub_detail` carries both dladdr results. */
static char stub_why[64], stub_detail[1024];

#ifdef HAVE_DYLD
static const uint8_t *image_header(const char *path, intptr_t *slide_out) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && !strcmp(nm, path)) {
            *slide_out = _dyld_get_image_vmaddr_slide(i);
            return _dyld_get_image_header(i);
        }
    }
    return NULL;
}

/* Whether `path` is the library `lib` or a library it re-exports, read from
 * the load commands of `lib` as dyld mapped it. */
static int named_or_reexported(const char *lib, const char *path) {
    if (!strcmp(lib, path)) return 1;
    intptr_t slide_unused;
    const uint8_t *mh = image_header(lib, &slide_unused);
    if (!mh) return 0;
    uint32_t ncmds, cmd, size;
    memcpy(&ncmds, mh + 16, 4);
    const uint8_t *p = mh + 32;
    for (uint32_t k = 0; k < ncmds && k < 4096; k++, p += size) {
        memcpy(&cmd, p, 4);
        memcpy(&size, p + 4, 4);
        if (size < 8) break;
        if (cmd == 0x8000001f) { /* LC_REEXPORT_DYLIB */
            uint32_t name_off;
            memcpy(&name_off, p + 8, 4);
            if (name_off < size && !strncmp((const char *)p + name_off, path, size - name_off)) return 1;
        }
    }
    return 0;
}

/* Whether the loaded address `a` lies inside the __TEXT segment of the image
 * mapped from `path`. */
static int in_text_of(const char *path, uint64_t a) {
    intptr_t sl;
    const uint8_t *mh = image_header(path, &sl);
    if (!mh) return 0;
    uint32_t ncmds, cmd, size;
    memcpy(&ncmds, mh + 16, 4);
    const uint8_t *p = mh + 32;
    for (uint32_t k = 0; k < ncmds && k < 4096; k++, p += size) {
        memcpy(&cmd, p, 4);
        memcpy(&size, p + 4, 4);
        if (size < 8) break;
        if (cmd == 0x19 && !strncmp((const char *)p + 8, "__TEXT", 16)) {
            uint64_t vmaddr, vmsize;
            memcpy(&vmaddr, p + 24, 8);
            memcpy(&vmsize, p + 32, 8);
            uint64_t lo = vmaddr + (uint64_t)sl;
            return a >= lo && a - lo < vmsize;
        }
    }
    return 0;
}
#endif

static int resolver_stub(const Fixup *f, uint64_t mv, uint64_t r) {
    snprintf(stub_why, sizeof stub_why, "not checked");
    stub_detail[0] = 0;
#ifdef HAVE_DYLD
    if (simulate || !r) return 0;
    Dl_info w, m;
    int have_w = dladdr((const void *)(uintptr_t)mv, &w), have_m = dladdr((const void *)(uintptr_t)r, &m);
    snprintf(stub_detail, sizeof stub_detail,
             "word: fname=%s sname=%s saddr=0x%" PRIx64 "; dlsym: fname=%s sname=%s saddr=0x%" PRIx64,
             have_w && w.dli_fname ? w.dli_fname : "-", have_w && w.dli_sname ? w.dli_sname : "-",
             have_w ? (uint64_t)(uintptr_t)w.dli_saddr : 0, have_m && m.dli_fname ? m.dli_fname : "-",
             have_m && m.dli_sname ? m.dli_sname : "-", have_m ? (uint64_t)(uintptr_t)m.dli_saddr : 0);
    if (f->addend) { snprintf(stub_why, sizeof stub_why, "(1) the record has an addend"); return 0; }
    if (r == mv) { snprintf(stub_why, sizeof stub_why, "(2) the dlsym result is the word"); return 0; }
    if (!have_w || !have_m || !w.dli_fname || !m.dli_fname || strcmp(w.dli_fname, m.dli_fname)) {
        snprintf(stub_why, sizeof stub_why, "(3) the word and the dlsym result are not in one image");
        return 0;
    }
    if (!named_or_reexported(dylibs[f->ord - 1], w.dli_fname)) {
        snprintf(stub_why, sizeof stub_why, "(4) the image is not the named library or a re-export");
        return 0;
    }
    if (!in_text_of(w.dli_fname, mv)) {
        snprintf(stub_why, sizeof stub_why, "(5) the word is not inside that image's __TEXT");
        return 0;
    }
    return 1;
#else
    (void)f; (void)mv; (void)r;
    return 0;
#endif
}

/* ---- loading -------------------------------------------------------------- */

static const char *base_name(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static int load_memory(const char *lib, char *path, size_t pathsz) {
    if (simulate) {
        snprintf(path, pathsz, "%s", lib);
        return 0;
    }
#ifdef HAVE_DYLD
    if (!dlopen(lib, RTLD_NOW)) { FAIL(B_SETUP, "dlopen %s: %s", lib, dlerror()); return -1; }
    int idx = -1;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && !strcmp(base_name(nm), base_name(lib))) { idx = (int)i; break; }
    }
    if (idx < 0) { FAIL(B_SETUP, "%s not among dyld's images", lib); return -1; }
    slide = (int64_t)_dyld_get_image_vmaddr_slide((uint32_t)idx);
    const void *mh = _dyld_get_image_header((uint32_t)idx);
    Dl_info di;
    if (!dladdr(mh, &di) || !di.dli_fname) { FAIL(B_SETUP, "dladdr on the image header"); return -1; }
    snprintf(path, pathsz, "%s", di.dli_fname);
    printf("IMAGE name=%s header=0x%" PRIx64 " bias=0x%" PRIx64 "\n", base_name(path),
           (uint64_t)(uintptr_t)mh, (uint64_t)slide);
    return 0;
#else
    (void)lib; (void)base_name;
    FAIL(B_SETUP, "no dyld on this host: use --simulate");
    return -1;
#endif
}

static int read_segments(void) {
    for (int i = 0; i < nsegs; i++) {
        Seg *s = &segs[i];
        if (!s->filesize || s->bad) continue; /* a bad extent was failed at parse */
        s->mem = malloc((size_t)s->filesize);
        if (!s->mem) { FAIL(B_SETUP, "malloc for segment %s", s->name); return -1; }
        if (simulate) {
            memcpy(s->mem, F + s->fileoff, (size_t)s->filesize);
            continue;
        }
#ifdef HAVE_DYLD
        uint64_t got = 0;
        int kr = mach_vm_read_overwrite(mach_task_self_, s->vmaddr + (uint64_t)slide, s->filesize,
                                        (uint64_t)(uintptr_t)s->mem, &got);
        if (kr || got != s->filesize) { FAIL(B_SETUP, "segment %s unreadable (kr=%d)", s->name, kr); return -1; }
#endif
    }
    if (simulate) { /* what dyld would write */
        for (size_t i = 0; i < nfx; i++) {
            Seg *s = &segs[fx[i].seg];
            if (!s->mem) continue;
            uint64_t v = 0;
            if (!fx[i].bind) v = fx[i].target + (uint64_t)slide;
            else if (!special_ord(fx[i].ord) && (v = resolve(&fx[i])) != 0) v += (uint64_t)fx[i].addend;
            memcpy(s->mem + fx[i].off, &v, 8);
        }
    }
    return 0;
}

static int is_const(const Seg *s) { return !strcmp(s->name, "__DATA_CONST") || (s->flags & 0x10); }

int main(int argc, char **argv) {
    int ai = 1;
    setvbuf(stdout, NULL, _IOLBF, 0);
    while (ai < argc && argv[ai][0] == '-') {
        if (!strcmp(argv[ai], "--list-mutations")) {
            for (size_t i = 0; i < sizeof mutations / sizeof mutations[0]; i++) printf("%s %d\n", mutations[i].name, mutations[i].bit);
            return 0;
        }
        if (ai + 1 >= argc) break;
        if (!strcmp(argv[ai], "--simulate")) { simulate = 1; slide = (int64_t)strtoull(argv[ai + 1], NULL, 0); }
        else if (!strcmp(argv[ai], "--mutate")) mutate = argv[ai + 1];
        else break;
        ai += 2;
    }
    if (ai + 1 != argc) {
        fprintf(stderr, "usage: %s [--simulate SLIDE] [--mutate NAME] <dylib>\n       %s --list-mutations\n", argv[0], argv[0]);
        return 2;
    }
    if (mutate) {
        int known = 0;
        for (size_t i = 0; i < sizeof mutations / sizeof mutations[0]; i++) if (!strcmp(mutate, mutations[i].name)) known = 1;
        if (!known) { fprintf(stderr, "unknown mutation %s\n", mutate); return 2; }
    }
    printf("PROC route=%s\n", simulate ? "simulated" : "mach_vm_read_overwrite");

    char path[4096];
    if (load_memory(argv[ai], path, sizeof path)) return finish();
    int fd = open(path, O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st)) { FAIL(B_SETUP, "open %s: %s", path, strerror(errno)); return finish(); }
    flen = (size_t)st.st_size;
    F = malloc(flen ? flen : 1);
    if (!F) { FAIL(B_SETUP, "malloc for the file"); return finish(); }
    for (size_t d = 0; d < flen;) {
        ssize_t g = pread(fd, F + d, flen - d, (off_t)d);
        if (g <= 0) { FAIL(B_SETUP, "read %s", path); return finish(); }
        d += (size_t)g;
    }
    close(fd);
    printf("FILE path=%s size=%zu\n", path, flen);
    if (simulate) printf("IMAGE name=%s bias=0x%" PRIx64 " (simulated)\n", base_name(path), (uint64_t)slide);

    parse();
    if (status & B_SETUP) return finish();
    size_t nreb = 0, nbind = 0;
    for (size_t i = 0; i < nfx; i++) (void)(fx[i].bind ? nbind++ : nreb++);
    printf("FIXUPS form=%s rebase=%zu bind=%zu dylibs=%d\n", chained_form ? (opcode_form ? "chained+opcodes" : "chained") : opcode_form ? "opcodes" : "none", nreb, nbind, ndylibs);
    if (opcode_form) FAIL(B_REFUSE, "opcode-encoded fixups (LC_DYLD_INFO): chained fixups are required");
    if (mutating("form-none")) { opcode_form = chained_form = 0; mutated(mutate, 0); }
    if (!opcode_form && !chained_form) FAIL(B_REFUSE, "no fixup information at all (form=none)");
    /* refusal mutations change the parsed values the refusal checks read */
    if (mutating("lazy-section")) {
        if (nsects_all) { memcpy(sects[0].name, "__la_symbol_ptr", 16); mutated(mutate, 0); }
        else printf("MUTATE %s not applicable to this image\n", mutate);
    }

    {
        int lazy = 0; /* lazy pointers, by name or type; `__got` is non-lazy by type and allowed */
        for (int k = 0; k < nsects_all; k++)
            if (!memcmp(sects[k].name, "__la_symbol_ptr", 15) || !memcmp(sects[k].name, "__nl_symbol_ptr", 15) || sects[k].type == 7)
                lazy++;
        if (lazy) FAIL(B_REFUSE, "%d lazy or non-lazy symbol pointer section(s)", lazy);
    }
    for (size_t i = 0; i < nfx; i++)
        if (fx[i].bind && special_ord(fx[i].ord)) { FAIL(B_REFUSE, "special or out-of-range library ordinal %d for %s", fx[i].ord, fx[i].sym); break; }

    if (read_segments()) return finish();
    /* The no-slide mutation: the image as if dyld had not moved it. Every
     * rebase word in the loaded copy holds its unslid target, and the slide
     * the checks subtract is 0; only the control may notice. */
    if (mutating("no-slide")) {
        for (size_t i = 0; i < nfx; i++) {
            Seg *sg = &segs[fx[i].seg];
            if (!fx[i].bind && sg->mem) memcpy(sg->mem + fx[i].off, &fx[i].target, 8);
        }
        slide = 0;
        mutated(mutate, 0);
    }

    /* -- length -- */
    size_t opened = flen;
    uint64_t need = 0;
    for (int i = 0; i < nsegs; i++)
        if (!segs[i].bad && segs[i].fileoff + segs[i].filesize > need) need = segs[i].fileoff + segs[i].filesize;
    if (mutating("length")) { opened = need ? (size_t)need - 1 : 0; mutated("length", opened); }
    if (need > opened) FAIL(B_LENGTH, "the segments need %" PRIu64 " file bytes, the file has %zu", need, opened);
    if (codesig_off != UINT64_MAX && codesig_off > opened) FAIL(B_LENGTH, "the code signature lies beyond the file");
    printf("SIZE image_len=%" PRIu64 " opened_len=%zu codesig_off=%s\n", need, opened, codesig_off == UINT64_MAX ? "none" : "set");

    /* -- mutations of file values, after parsing -- */
    uint64_t relative_at = UINT64_MAX;
    int dataconst_done = 0;
    for (int i = 0; i < nsegs; i++) {
        Seg *s = &segs[i];
        if (!s->filesize) continue;
        if (!strcmp(s->name, "__TEXT")) {
            if (mutating("header-plain")) { F[s->fileoff + 32 + sizeofcmds - 4] ^= 1; mutated(mutate, s->vmaddr + 32 + sizeofcmds - 4); }
            if (mutating("text-plain")) { F[s->fileoff + s->filesize / 2] ^= 1; mutated(mutate, s->vmaddr + s->filesize / 2); }
            if (mutating("relative")) { relative_at = s->vmaddr + ((s->filesize / 2) & ~7ULL); mutated(mutate, relative_at); }
        }
        if (!strcmp(s->name, "__LINKEDIT") && mutating("linkedit-plain")) { F[s->fileoff] ^= 1; mutated(mutate, s->vmaddr); }
        if (is_const(s) && mutating("dataconst-plain")) {
            for (uint64_t o = 0; o + 8 <= s->filesize; o += 8)
                if (!find_fixup(i, o)) { F[s->fileoff + o] ^= 1; mutated(mutate, s->vmaddr + o); dataconst_done = 1; break; }
        }
    }
    if (mutating("dataconst-plain") && !dataconst_done) printf("MUTATE %s not applicable to this image\n", mutate);

    /* -- typing -- */
    size_t plain = 0, plain_bad = 0, rel_ok = 0, rel_bad = 0, rel_moved = 0, bind_ok = 0, bind_bad = 0, weak_zero = 0;
    size_t fileonly_bytes = 0, bind_stub = 0;
    int bind_mutated = 0;
    for (int i = 0; i < nsegs; i++) {
        Seg *s = &segs[i];
        if (!s->filesize || !s->mem) continue;
        if (s->fileoff + s->filesize > opened) { /* the length bit is set; nothing past it is typed */
            FAIL(B_LENGTH, "segment %s lies past the opened file: not typed", s->name);
            continue;
        }
        int writable = (s->initprot & 2) != 0, linkedit = !strcmp(s->name, "__LINKEDIT");
        uint64_t n = s->filesize;
        if (linkedit && codesig_off != UINT64_MAX && codesig_off >= s->fileoff && codesig_off < s->fileoff + n) n = codesig_off - s->fileoff;
        if (writable && !is_const(s)) { /* FileOnly: read from the file at the segment's offset */
            uint64_t fo = s->fileoff;
            if (mutating("fileonly")) { fo = opened; mutated("fileonly", s->vmaddr); }
            const uint8_t *f = fo <= opened && n <= opened - fo ? F + fo : NULL;
            if (!f) { FAIL(B_FILEONLY, "FileOnly segment %s unreadable from the file", s->name); continue; }
            fileonly_bytes += n;
            size_t diff = 0;
            for (uint64_t o = 0; o + 8 <= n; o += 8) if (memcmp(f + o, s->mem + o, 8)) diff++;
            printf("FILEONLY segment=%s file_backed=%" PRIu64 " words_written_by_loader_or_module=%zu\n", s->name, n, diff);
            continue;
        }
        size_t seg_plain = 0;
        for (uint64_t o = 0; o < n;) {
            uint64_t va = s->vmaddr + o;
            Fixup *f = o + 8 <= n ? find_fixup(i, o) : NULL;
            Fixup tmp;
            if (!f && va == relative_at) {
                memset(&tmp, 0, sizeof tmp);
                tmp.addr = va;
                tmp.seg = i;
                tmp.off = o;
                tmp.target = rd(s->fileoff + o, 8);
                f = &tmp;
            }
            if (f) {
                uint64_t mv;
                memcpy(&mv, s->mem + o, 8);
                f->consumed = 1;
                if (!f->bind) {
                    if (mv != f->target) rel_moved++;
                    if (mv - (uint64_t)slide == f->target) rel_ok++;
                    else { rel_bad++; if (rel_bad <= 5) printf("RELATIVE_BAD va=0x%" PRIx64 " mem=0x%" PRIx64 " unslid=0x%" PRIx64 "\n", va, mv, f->target); }
                } else if (!special_ord(f->ord)) { /* a refused ordinal is never resolved */
                    uint64_t r = resolve(f);
                    if (r && mutating("bind") && !bind_mutated) { r += 8; bind_mutated = 1; mutated("bind", va); }
                    uint64_t want = r ? r + (uint64_t)f->addend : 0;
                    snprintf(stub_why, sizeof stub_why, "not checked");
                    stub_detail[0] = 0;
                    if (!r && !f->weak) { bind_bad++; printf("BIND_UNRESOLVED va=0x%" PRIx64 " sym=%s\n", va, f->sym); }
                    else if (mv == want) { bind_ok++; if (!r) weak_zero++; }
                    else if (!bind_mutated && resolver_stub(f, mv, r)) {
                        bind_stub++;
                        printf("BIND_RESOLVER_STUB va=0x%" PRIx64 " sym=%s mem=0x%" PRIx64 " dlsym=0x%" PRIx64 " %s\n", va,
                               f->sym, mv, r, stub_detail);
                    }
                    else {
                        bind_bad++;
                        if (bind_bad <= 8)
                            printf("BIND_BAD va=0x%" PRIx64 " sym=%s mem=0x%" PRIx64 " want=0x%" PRIx64 " stub_check=%s %s\n", va,
                                   f->sym, mv, want, stub_why, stub_detail);
                    }
                }
                o += 8;
                continue;
            }
            seg_plain++;
            if (F[s->fileoff + o] != s->mem[o]) {
                if (plain_bad < 5) printf("PLAIN_DIFF segment=%s va=0x%" PRIx64 " file=%02x mem=%02x\n", s->name, va, F[s->fileoff + o], s->mem[o]);
                plain_bad++;
            }
            o++;
        }
        plain += seg_plain;
        printf("SEGMENT name=%s kind=%s plain_bytes=%zu\n", s->name, is_const(s) ? "typed" : "plain", seg_plain);
    }
    /* Every classified word was either examined above or lies in a FileOnly
     * segment, whose file bytes are hashed instead. Any other was never
     * looked at, and a pass would claim it. */
    size_t unexamined = 0;
    for (size_t i = 0; i < nfx; i++) {
        const Seg *s = &segs[fx[i].seg];
        int fileonly = (s->initprot & 2) && !is_const(s);
        if (!fx[i].consumed && !fileonly) {
            if (unexamined < 5) printf("UNEXAMINED %s va=0x%" PRIx64 " segment=%s\n", fx[i].bind ? "bind" : "rebase", fx[i].addr, s->name);
            unexamined++;
        }
    }
    if (unexamined) FAIL(B_REFUSE, "%zu classified words lie outside every typed region and were never examined", unexamined);
    printf("MACHO_SUMMARY plain_bytes=%zu plain_differing=%zu relative_ok=%zu relative_bad=%zu bind_ok=%zu bind_bad=%zu "
           "weak_zero=%zu resolver_stub=%zu\n", plain, plain_bad, rel_ok, rel_bad, bind_ok, bind_bad, weak_zero, bind_stub);
    printf("BIND_ROUTE resolved_in_named_library=%zu unresolved=%zu\n", route_first, route_unresolved);
    if (plain_bad) FAIL(B_TYPING, "%zu Plain bytes differ from the file", plain_bad);
    if (rel_bad) FAIL(B_RELATIVE, "%zu rebase words do not normalise", rel_bad);
    if (bind_bad) FAIL(B_BIND, "%zu bind words disagree with their resolution", bind_bad);
    /* the control counts only typed Relative words: a FileOnly rebase is not
     * examined, so it cannot show the image moved */
    /* An image already refused for its fixup encoding is typed only as far as
     * that encoding allows: its control and its none-verified check would
     * report on words the opcode form leaves in FileOnly data, not on the
     * probe. They stay strict on every image the probe accepts for typing. */
    if (opcode_form) {
        printf("CONTROLS not evaluated: the image is refused for its opcode-encoded fixups\n");
    } else {
        if (!slide || !rel_moved) FAIL(B_CONTROL, "no typed rebase word moved (slide 0x%" PRIx64 ", %zu rebases): the run is void", (uint64_t)slide, nreb);
        if (nbind && !bind_ok) FAIL(B_BIND, "%zu bind words classified and none verified", nbind);
    }
    if (!plain) FAIL(B_TYPING, "no Plain byte was compared");
    if (!fileonly_bytes) FAIL(B_FILEONLY, "no FileOnly byte was read from the file");
    return finish();
}
