/* A small shared library with the structures the extent v2 probes type: an
 * integrity slot, RELA destinations in RELRO, a GOT, `.data` and `.bss`.
 *
 * It exists so the probes and their mutation tests run against an image whose
 * shape is known, beside the real artifact: a linker that pads `.dynamic`
 * after DT_NULL gives the post-DT_NULL comparison something to compare, and
 * `-DFILE_BACKED_STATIC` puts a zero-initialised module static into initialised
 * data, which `file-backed-statics.py` must report, and `-DSTATE_INITIALISED`
 * gives it a non-zero initial value, which it must not. It needs no C library
 * headers, so the same source builds the Mach-O and PE fixtures that test the
 * statics report on those formats (`build-fixtures.sh`).
 *
 *   cc -shared -fPIC -O1 -Wl,-z,now -Wl,-z,relro -o fixture.so elf-fixture.c
 *   python3 slot-stamp.py fixture.so
 *
 * The slot is a version-2 slot with only its magic, version and footer set;
 * `slot-stamp.py` writes its slot_rva. Nothing here is signed.
 */
typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;
typedef __SIZE_TYPE__ size_t;
#if defined(_WIN32)
/* no C library on the PE side: a local strlen, and one import from
 * kernel32.dll so the import directory and the IAT exist */
static size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);

/* A load configuration directory that declares the image CFG-instrumented,
 * so the CFG check and dispatch pointer storage is typed Hole. Only the
 * fields the probe reads are set; the image is for --simulate, not for a
 * loader. */
static void guard_check(void) {}
const void *const oxicrypt_fixture_guard_check = (const void *)guard_check;
const void *const oxicrypt_fixture_guard_dispatch = (const void *)guard_check;
const struct {
    unsigned int size;
    unsigned char before_check[0x70 - 4];
    const void *const *check;
    const void *const *dispatch;
    unsigned char before_flags[0x90 - 0x80];
    unsigned int guard_flags;
    unsigned char rest[0x140 - 0x94];
} _load_config_used = { 0x140, { 0 }, &oxicrypt_fixture_guard_check, &oxicrypt_fixture_guard_dispatch, { 0 }, 0x100, { 0 } };
#else
size_t strlen(const char *);
#endif

#if defined(__APPLE__)
#define DATA_SECTION "__DATA,__data"
/* the module-state arrangement: a segment holding only zero-fill */
#define ZEROFILL __attribute__((used, section("__OXIZF,__state,zerofill")))
#else
#define DATA_SECTION ".data"
#define ZEROFILL __attribute__((used))
#endif

#define SLOT_SIZE 16384

__attribute__((used, aligned(16))) const uint8_t oxicrypt_fixture_slot[SLOT_SIZE] = {
    0xfc, 'O', 'X', 'I', 'C', 'R', 'Y', 'P', 'T', '_', 'F', 'I', 'P', 'S', '_', 'H',
    2, 0, 0, 0,
    [SLOT_SIZE - 16] = 0xfd, 'O', 'X', 'I', 'C', 'R', 'Y', 'P', 'T', '_', 'F', 'I', 'P', 'S', '_', 'F',
};

/* RELA destinations in `.data.rel.ro`, inside RELRO */
static const char *const names[] = { "alpha", "beta", "gamma", "delta" };
__attribute__((used)) const char *const *oxicrypt_fixture_names = names;

/* RELRO with Plain words beside a relocated one, so every RELRO check has a
 * word to work on whether the pointers are RELA or RELR destinations */
__attribute__((used)) const struct { const char *name; unsigned long long a, b; } oxicrypt_fixture_pair = {
    "pair", 0x1122334455667788ULL, 0x0102030405060708ULL,
};

/* `.data`: initialised writable data, FileOnly */
int oxicrypt_fixture_counter = 7;

#if defined(FILE_BACKED_STATIC)
/* a zero-initialised module static placed in the file */
__attribute__((used, section(DATA_SECTION))) uint64_t oxicrypt_fixture_state;
#elif defined(STATE_INITIALISED)
/* an initialised module static: FileOnly, never in the row */
__attribute__((used)) uint64_t oxicrypt_fixture_state = 1;
#else
/* zero-fill: ELF `.bss` lies beyond p_filesz and the Mach-O segment has no
 * file bytes; a PE linker merges `.bss` into `.data`, whose raw size is
 * rounded up to the file alignment, so there the static is file-backed */
ZEROFILL uint64_t oxicrypt_fixture_state;
#endif

/* a call through the PLT, so DT_PLTGOT and GOT[0..3] exist (ELF, Mach-O) */
size_t oxicrypt_fixture_len(int i) {
    oxicrypt_fixture_counter++;
    oxicrypt_fixture_state += (uint64_t)i;
#if defined(_WIN32)
    if (i < 0) return (size_t)GetTickCount();
#endif
    return strlen(names[i & 3]) + (size_t)oxicrypt_fixture_slot[16];
}
