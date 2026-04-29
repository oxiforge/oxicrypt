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
    /* OxiResult::InvalidInput == 5 */
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
