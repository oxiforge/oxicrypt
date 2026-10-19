/*
 * Links against a staged release directory the way a consumer does, by the
 * plain name (-loxicrypt_ffi), and runs from that directory alone: the
 * program records the library's delivered name (its SONAME or install name)
 * and the loader must find that file beside the link.
 *
 *   cc -o staged-link staged-link.c -L<dir> -loxicrypt_ffi -Wl,-rpath,<dir>
 *   ./staged-link <delivered file name>
 *
 * The ABI number in the delivered name (liboxicrypt_ffi.so.<N> or
 * liboxicrypt_ffi.<N>.dylib) must equal what oxi_abi_version() returns; a
 * name without one (liboxicrypt_ffi.so on Android) is not compared. Then the
 * library is initialised and must reach the operational state.
 *
 * Exit status 0 on success, 2 when the name's ABI and the library's differ
 * (checked before oxi_init), 1 when initialisation fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int oxi_abi_version(void);
int oxi_init(int profile);
int oxi_is_operational(void);

/* The ABI number a delivered name carries, or -1 when it carries none. */
static long name_abi(const char *name) {
    const char *so = "liboxicrypt_ffi.so.";
    const char *dy = "liboxicrypt_ffi.";
    char *end;
    long n;
    if (strncmp(name, so, strlen(so)) == 0) {
        n = strtol(name + strlen(so), &end, 10);
        return (*end == '\0' && end != name + strlen(so)) ? n : -1;
    }
    if (strncmp(name, dy, strlen(dy)) == 0) {
        n = strtol(name + strlen(dy), &end, 10);
        return (strcmp(end, ".dylib") == 0 && end != name + strlen(dy)) ? n : -1;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: staged-link <delivered file name>\n");
        return 1;
    }
    int abi = oxi_abi_version();
    long named = name_abi(argv[1]);
    if (named >= 0 && named != abi) {
        printf("name %s carries ABI %ld, oxi_abi_version() returns %d\n", argv[1], named, abi);
        return 2;
    }
    int rc = oxi_init(1);
    int operational = oxi_is_operational();
    printf("name=%s abi=%d oxi_init(1)=%d operational=%d\n", argv[1], abi, rc, operational);
    return (rc == 0 && operational == 1) ? 0 : 1;
}
