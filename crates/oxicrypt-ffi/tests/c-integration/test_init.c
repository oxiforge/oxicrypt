/* Init + state-query smoke test for the oxicrypt-ffi C ABI. */

#include "oxicrypt.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int rc = oxi_init(0);
    if (rc != 0) {
        fprintf(stderr, "oxi_init(0) failed: rc=%d\n", rc);
        return 1;
    }

    if (!oxi_is_operational()) {
        fprintf(stderr, "module not operational after init\n");
        return 2;
    }

    int profile = oxi_active_profile();
    if (profile < 0 || profile > 2) {
        fprintf(stderr, "active profile out of range: %d\n", profile);
        return 3;
    }

    /* oxi_init is idempotent — the second call must return 0 too. */
    if (oxi_init(0) != 0) {
        fprintf(stderr, "second oxi_init returned non-zero\n");
        return 4;
    }

    /* Unknown profile rejected per F4 reviewer-framing. */
    int rc_bad = oxi_init(999);

    /* Migration is profile 3 and must be in range; 4 is out of range. The
       range check runs before the idempotent already-operational path, so
       these hold whatever order the tests run in. They pin the accepted
       range only — that 3 maps to Migration rather than to another profile
       is pinned in the Rust suite, which can read the profile back. */
    int rc_migration = oxi_init(3);
    int rc_out_of_range = oxi_init(4);
    /* OxiResult::InvalidInput == 5 */
    if (rc_out_of_range != 5) {
        fprintf(stderr, "oxi_init(4) accepted an out-of-range profile: %d\n", rc_out_of_range);
        return 1;
    }
    if (rc_migration == 5) {
        fprintf(stderr, "oxi_init(3) rejected the Migration profile\n");
        return 1;
    }
    if (rc_bad != 5) {
        /* idempotent already-init path may return 0 first; if so the
         * existing module is operational and the profile-check
         * happens before init, so 5 is still expected. */
        fprintf(stderr, "oxi_init(999) returned %d, expected OxiResult::InvalidInput=5\n", rc_bad);
        return 5;
    }

    printf("test_init: OK (profile=%d)\n", profile);
    return 0;
}
