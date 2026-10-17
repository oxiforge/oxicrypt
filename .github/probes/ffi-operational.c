/*
 * Loads the C library and asks whether the module inside it became
 * operational.
 *
 *   ffi-operational <path-to-library>
 *
 * Exit status:
 *   0  operational: oxi_init returned 0, oxi_is_operational returned 1 and the
 *      integrity test reported Passed (1).
 *   1  refused by the module's power-up tests: oxi_init returned non-zero and
 *      the module is not operational. The integrity status is printed so the
 *      caller can require a specific outcome.
 *   2  the library could not be loaded or a symbol is missing.
 *   3  any other combination.
 *
 * A library the operating system refuses to load exits 2, never 0 or 1.
 */
#include <dlfcn.h>
#include <stdio.h>

typedef int (*init_fn)(int);
typedef int (*query_fn)(void);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: ffi-operational <path-to-library>\n");
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }
    init_fn init = (init_fn)dlsym(h, "oxi_init");
    query_fn operational = (query_fn)dlsym(h, "oxi_is_operational");
    query_fn integrity = (query_fn)dlsym(h, "oxi_integrity_status");
    if (!init || !operational || !integrity) {
        fprintf(stderr, "missing symbol: %s\n", dlerror());
        return 2;
    }
    int rc = init(0);
    int op = operational();
    int st = integrity();
    printf("oxi_init=%d oxi_is_operational=%d oxi_integrity_status=%d\n", rc, op, st);
    if (rc == 0 && op == 1 && st == 1) {
        puts("library: operational");
        return 0;
    }
    if (rc != 0 && op == 0) {
        puts("library: refused by the module's power-up tests");
        return 1;
    }
    puts("library: neither operational nor refused");
    return 3;
}
